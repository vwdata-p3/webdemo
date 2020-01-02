import socket
import contextlib
import threading
import common
import sys
import threading
import os

import pep3

import pep3_pb2

def collect(args):
    Collect(args).run()

class Collect:
    def __init__(self, args):
        self.args = args

    def run(self):
        self.pep = pep3.PepContext(self.args.config, 
                self.args.secrets, "collector", None)
        self.collector = self.pep.connect_to("collector")
        
        with contextlib.ExitStack() as stack:
            if self.args.keep_input_open:
                threading.Thread(target=lambda: stack.enter_context(
                    open(self.args.input, "w")
                )).start()

            self.inputf = open(self.args.input,'r')
            stack.enter_context(self.inputf)

            cell_index_to_handler = None

            # read header
            line = next(self.inputf)
            bits = tuple(map(lambda x: x.strip(),line.split(",")))

            # see if we've got a header
            header_name_count = len([bit for bit in bits 
                if bit in HEADER_NAME_TO_HANDLER]) 
            if header_name_count < len(bits):
                # we didn't recognise all fields of the header
                raise Exception(f"{self.args.input}:"
                        f" I think this '{line}' is a header, but do not"
                        " recognize these field(s): " 
                        + ", ".join(filter(lambda bit: 
                                bit not in HEADER_NAME_TO_HANDLER, 
                            bits)) + ".")
            # we've definitely got a header
            cell_index_to_handler = [ HEADER_NAME_TO_HANDLER[bit]
                    for bit in bits ]

            def batch_generator():
                request = pep3_pb2.StoreRequest()

                for linenr, line in enumerate(self.inputf):
                    linenr += 1 # the header was line nr. 0

                    bits = tuple(map(lambda x: x.strip(),line.split(",")))

                    record = request.records.add()

                    for index, bit in enumerate(bits):
                        cell_index_to_handler[index](record, bit)

                    if linenr % self.args.batchsize==0:
                        cpy = pep3_pb2.StoreRequest()
                        cpy.CopyFrom(request)
                        cpy.id = linenr.to_bytes(8, byteorder="big")
                        yield cpy
                        request.Clear()
            
                if request.records:
                    yield request

            queue = common.chuck(batch_generator())

            gens = [ self.collector.Store(queue)
                    for i in range(self.args.streamcount) ]

            all_done = threading.Event()

            def status_printer():
                counter = 0 
                while True:
                    counter += 1
                    if all_done.wait(.1):
                        break
                    sys.stdout.write(f"{counter/10} {queue.size()}\r")

            status_printer_thread = threading.Thread(target=status_printer)
            status_printer_thread.start()

            # wait for all streams to finish
            for gen in gens:
                for item in gen:
                    pass

            all_done.set()
            status_printer_thread.join()


class HandleIPAddress:
    def __init__(self, fieldname):
        self.fieldname = fieldname

    def __call__(self, record, cell):
        field = getattr(record, self.fieldname)
        field.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME
        if ":" not in cell:
            # we got an ipv4 address; convert to IPv6
            cell = "2002::" + cell
        field.data = socket.inet_pton(socket.AF_INET6, cell)

class HandleInt:
    def __init__(self, fieldname):
        self.fieldname = fieldname

    def __call__(self, record, cell):
        setattr(record.anonymous_part, self.fieldname, int(cell))


class HandleSerial:
    def __init__(self):
        self._last = None

    def __call__(self, record, cell):
        serial = int(cell)
        if self._last == None:
            self._last = serial
            return
        if self._last + 1 != serial:
            print(f"WARNING: jump from serial number {self._last} to {serial}")
        self._last = serial


def handle_ignored_field(record, cell):
    return
            
HEADER_NAME_TO_HANDLER = {
        "src_ip": HandleIPAddress("source_ip"),
        "dst_ip": HandleIPAddress("destination_ip"),
        "protocol": HandleInt("protocol"),
        "sport": HandleInt("source_port"),
        "dport": HandleInt("destination_port"),
        "tstart": HandleInt("start_time"),
        "tend": HandleInt("end_time"),
        "packets": HandleInt("number_of_packets"),
        "bytes": HandleInt("number_of_bytes"),
        "serial": HandleSerial(),
        "tcp_flags": handle_ignored_field,
        "last_updated_in_cache": handle_ignored_field,
        "no_of_partials": handle_ignored_field,
}
