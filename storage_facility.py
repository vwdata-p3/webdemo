import pep3_pb2_grpc
import pep3_pb2

import common
import xthreading
import xqueue

import traceback
import queue
import functools

import grpc

class StorageFacility(pep3_pb2_grpc.StorageFacilityServicer):
    def __init__(self, pep):
        self.pep = pep
        self.store_processor = StoreProcessor(self) 

    def shutdown(self):
        self.store_processor.shutdown()

    def Store(self, request_it, context):
        return self.store_processor.Store(request_it, context)

    def Query(self, query, context):
        common.authenticate(context,
                must_be_one_of=[b"PEP3 researcher", b"PEP3 investigator"])

        secret_local_key = self.pep.private_keys["pseudonym"]

        names = []

        # decrypt pseudonymizable parameters
        for parameter in query.parameters.values():
            if parameter.WhichOneof('kind')=='pseudonymizable_value':
                names.append(parameter.pseudonymizable_value)

        self.pep.decrypt(names, secret_local_key)

        for chunk in self.pep.connect_to("database").Query(query):

            # encrypt pseudonymizable cells
            names.clear() 
            for row in chunk.rows:
                for cell in row.cells:
                    if cell.WhichOneof('kind')=='pseudonymizable_value':
                        names.append(cell.pseudonymizable_value)

            self.pep.encrypt(names)

            yield chunk


# helper class that deals with the "Store" RPC method
class StoreProcessor:
    def __init__(self, sf):
        self.sf = sf
        self.cache = xthreading.Cache(
                self._process_raw_ips, sf.pep.global_config.batchsize)
        self.queue = xqueue.Queue()
        self.request_id_to_feedback_queue = {}

        self.process_queue_fut = \
                self.sf.pep._executor.submit(self._process_queue_try)
        self.feedback_queues = set()

    def shutdown(self):
        self.queue.stop()
        self.process_queue_fut.result() # wait
        feedback_queues = list(self.feedback_queues)
        for fbq in feedback_queues:
            fbq.stop()

    def _process_queue_try(self):
        try:
            self._process_queue()
        except Exception as e:
            print("StorageFacility: unexpected (and fatal)  error:")
            print("Exception on processing thread:")
            traceback.print_exc()
            print("Terminating StorageFacility")
            self.pep.grpc_server.stop(0)

    def _process_queue(self):
        try:
            # database has only one thread, so we don't want to hog it
            while True:
                request, stopped = self.queue.get()
                if stopped:
                    return
                for store_feedback in self.sf.pep.connect_to("database")\
                    .Store(iter([request])):
                    try:
                        feedback_queue = self.request_id_to_feedback_queue\
                                .pop(store_feedback.stored_id)
                    except KeyError:
                        print("storage facility: database returned "
                                "a request id not known to us; reraising "
                                "exception, but not sure if "
                                "it will register")
                        raise
                    feedback_queue.put(store_feedback)
        except grpc.RpcError as e:
            assert(isinstance(e, grpc.Call))
            if e.code() == grpc.StatusCode.INTERNAL \
                    and "RST_STREAM" in e.details():
                # Database is shutting down, so we'll shutdown as
                # well, quietly, unless we had still some work to do.
                if self.queue.qsize()>0:
                    raise Exception("Database seems to be shutting"
                        f" down, but we still got {self.queue.qsize()}"
                        " StoreRequests to send!")
                self.pep.grpc_server.stop(0)
                return
            # unknown RpcError, reraise
            raise e

    def _process_raw_ips(self, batch):
        pseudonymizables = []
        for raw_ip in batch:
            p = pep3_pb2.Pseudonymizable()
            p.data = raw_ip
            p.state = pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM
            pseudonymizables.append(p)
        self.sf.pep.decrypt(pseudonymizables,
                self.sf.pep.private_keys["pseudonym"])
        return pseudonymizables

    def _handle_request_with_cached_ips(self, request):
        for flowrecord in request.records:
            assert(flowrecord.source_ip.state
                    ==pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM)
            assert(flowrecord.destination_ip.state
                    ==pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM)
            flowrecord.source_ip.CopyFrom(self.cache[
                    flowrecord.source_ip.data])
            flowrecord.destination_ip.CopyFrom(self.cache[
                    flowrecord.destination_ip.data])
        self.queue.put(request)


    def Store(self, request_it, context):
        common.authenticate(context, 
                must_be_one_of=[b"PEP3 collector"])
        # the flowrecords are stored asynchronously, using the self.queue
        # the feedback is returned asynchronously too, via the following
        # feedback queue.  We use the expected_responses counter to
        # see when we all responses we expected.
        expected_responses = 0
        request_it_done = False
        feedback_queue = xqueue.Queue()
        self.feedback_queues.add(feedback_queue)

        fut = self.sf.pep._executor.submit(
                self.Store_process_request_it, request_it, context,
                    feedback_queue)

        while expected_responses > 0 or not request_it_done:
            store_feedback, stopped = feedback_queue.get()
            if stopped:
                return
            if store_feedback==None: 
                # Signal that Store_processs_request_it has completed
                request_it_done = True
                e = fut.exception()
                if e!=None:
                    raise e
                expected_responses += fut.result()
                continue
            expected_responses -= 1
            yield store_feedback

        self.feedback_queues.remove(feedback_queue)


    def Store_process_request_it(self, request_it, context, feedback_queue):
        requests_stored = 0

        for request in request_it:
            if request.id in self.request_id_to_feedback_queue:
                raise ValueError("request id already in use")

            self.request_id_to_feedback_queue[request.id] = feedback_queue
            requests_stored += 1

            raw_ips = []
            
            for flowrecord in request.records:
                common.check_is_encrypted_pseudonym(
                        flowrecord.source_ip, context)
                common.check_is_encrypted_pseudonym(
                        flowrecord.destination_ip, context)
                
                raw_ips.append(flowrecord.source_ip.data)
                raw_ips.append(flowrecord.destination_ip.data)

            self.cache.request(raw_ips,
                    functools.partial(
                        self._handle_request_with_cached_ips, request))

        self.cache.flush()
        feedback_queue.put(None) # signal we're almost done
        return requests_stored


