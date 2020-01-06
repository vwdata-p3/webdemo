import grpc

import pep3_pb2
import pep3_pb2_grpc

import common
import xthreading
import xqueue
import xos

import queue
import functools

class Collector(pep3_pb2_grpc.CollectorServicer):
    def __init__(self, pep):
        self.pep = pep
        self.cache = xthreading.Cache(
                self._process_raw_ips, pep.global_config.batchsize)
        self.queue = xqueue.Queue()
        self.shutdown_called = False
        self.request_id_to_feedback_queue = {}

        self.process_queue_fut \
                = self.pep._executor.submit(self._process_queue_try)

    def shutdown(self):
        self.shutdown_called = True
        self.queue.stop()
        self.process_queue_fut.result() # wait

    def _process_queue_try(self):
        with xos.terminate_on_exception("Collector: "
                "fatal error on processing thread:"):
            self._process_queue()

    def _process_queue(self):
        try:
            while True:
                if self.shutdown_called:
                    return
                for store_feedback in self.pep.connect_to("storage_facility")\
                        .Store(self._iter_queue()):
                    try:
                        feedback_queue = self.request_id_to_feedback_queue.pop(
                                store_feedback.stored_id)
                    except KeyError:
                        print("collector: storage facility returned "
                                "a request id not known to us; reraising "
                                "exception, but not sure if it will register")
                        raise
                    feedback_queue.put(store_feedback)
        except grpc.RpcError as e:
            assert(isinstance(e, grpc.Call))
            if e.code() == grpc.StatusCode.INTERNAL \
                    and "RST_STREAM" in e.details():
                # Storage facility is shutting down, so we'll shutdown as
                # well, quietly, unless we had still some work to do.
                if self.queue.qsize()>0:
                    raise Exception("Storage facility seems to be shutting"
                        f" down, but we still got {self.queue.qsize()}"
                        " StoreRequests to send!")
                self.pep.grpc_server.stop(0)
                return
            # unknown RpcError, reraise
            raise e

    def _iter_queue(self):
        while True:
            item, stopped = self.queue.get()
            if stopped:
                return
            if item==None: # flush
                return
            else:
                yield item

    def _process_raw_ips(self, batch):
        pseudonymizables = []
        for raw_ip in batch:
            p = pep3_pb2.Pseudonymizable()
            p.data = raw_ip
            p.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME
            pseudonymizables.append(p)
        self.pep.pseudonymize(pseudonymizables)
        self.pep.relocalize(pseudonymizables, 
                self.pep.config.warrants.to_sf)
        return [ p for p in pseudonymizables ]

    def _handle_request_with_cached_ips(self, request, results):
        for flowrecord in request.records:
            assert(flowrecord.source_ip.state
                    ==pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME)
            assert(flowrecord.destination_ip.state
                    ==pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME)
            flowrecord.source_ip.CopyFrom(results[flowrecord.source_ip.data])
            flowrecord.destination_ip.CopyFrom(results[
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
        feedback_queue = queue.SimpleQueue()

        for request in request_it:
            
            if request.id in self.request_id_to_feedback_queue:
                raise ValueError("request id already in use")

            self.request_id_to_feedback_queue[request.id] = feedback_queue
            expected_responses += 1

            raw_ips = []
            
            for flowrecord in request.records:
                common.check_is_plaintext(flowrecord.source_ip, context)
                common.check_is_plaintext(flowrecord.destination_ip, context)
                
                raw_ips.append(flowrecord.source_ip.data)
                raw_ips.append(flowrecord.destination_ip.data)

            self.cache.request(raw_ips,
                    functools.partial(
                        self._handle_request_with_cached_ips, request))
            
        self.cache.flush()
        self.queue.put(None) # flush storage facility too
        
        while expected_responses > 0:
            store_feedback = feedback_queue.get()
            
            expected_responses -= 1
            yield store_feedback


            



