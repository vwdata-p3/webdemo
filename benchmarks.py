import argparse
import os
import sys
import concurrent.futures
import pstats
import threading
from itertools import zip_longest, chain, islice
import contextlib
import queue

import grpc
from OpenSSL import crypto

import pep3_pb2

import pep3
import elgamal
import ed25519
import schnorr
import common
import cheats

class Benchmarks:
    def __init__(self, args):
        self.args = args

    def run(self):
        method_name = f"benchmark_{self.args.name}"

        if method_name not in dir(self):
            sys.stderr.write(f"unknown benchmark {self.args.name};\n")
            options = [ s[10:] for s in dir(self) 
                    if s.startswith("benchmark_") ]
            sys.stderr.write(f"please choose from {options}\n")
            return

        if self.args.config==None:
            assert(self.args.secrets==None)

            config = pep3_pb2.Configuration()
            secrets = pep3_pb2.Secrets()

            pep3.fill_local_config_messages(config, secrets)

            self.args.config = config
            self.args.secrets = secrets

        with contextlib.ExitStack() as exitstack:
            if self.args.run_servers:
                g = exitstack.enter_context(pep3.RunServers(self.args.config, 
                        self.args.secrets, 
                        executor_type=self.args.executor_type))

            self.investigator = pep3.PepContext(self.args.config, 
                    self.args.secrets, "investigator", None,
                    allow_enrollment=False)
            self.collector = pep3.PepContext(self.args.config, self.args.secrets, 
                    "collector",None, allow_enrollment=False)

            try:
                getattr(self, method_name)(self.args.benchmark_args)
            except grpc.RpcError as err:
                if err.code()==grpc.StatusCode.UNAVAILABLE \
                        and not self.args.run_servers:

                    raise Exception("One of the servers is unavailable; \n"
                            "did you forget to use --run-servers?")
                raise err


    def benchmark_enroll(self, args):
        pep3.PepContext(self.args.config, 
                self.args.secrets, "investigator", None,
                allow_enrollment=True).public_keys

    def benchmark_certified_component(self, args):
        for i in range(1):
            k = ed25519.scalar_random()
            e = ed25519.scalar_random()
            cc = schnorr.CertifiedComponent.create(k,e)
            assert(cc.is_valid_proof_for(e,
                    [ed25519.Point.B_times(pow(k,2**i,ed25519.l))
                        for i in range(253) ] ))
        




