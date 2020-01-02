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


    def benchmark_store_several(self, args):
        parser = argparse.ArgumentParser("... store_several")
        parser.add_argument("--streams",
                help="number of streams to use",
                type=int, default="10")
        parser.add_argument("--batchsize",
                help="number of flowrecords per batch",
                type=int, default="1024")
        parser.add_argument("--batches",
                help="number of batches per stream",
                type=int, default="10")
        args = parser.parse_args(args)

        it = common.iter_threadsafe(
                self._benchmark_store_several_generator(args))

        gens = []
        for i in range(args.streams):
            gens.append(self.collector.connect_to('collector')\
                    .Store(it))
        for gen in gens:
            for feedback in gen:
                pass

    def _benchmark_store_several_generator(self, args):
        for i in range(args.batches):
            request = pep3_pb2.StoreRequest()
            request.id = os.urandom(16)
            for j in range(args.batchsize):
                flowrecord = request.records.add()

                flowrecord.source_ip.data = os.urandom(16)
                flowrecord.source_ip.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME
                flowrecord.destination_ip.data = os.urandom(16)
                flowrecord.destination_ip.state = \
                        pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME
                flowrecord.anonymous_part.number_of_bytes = 123
                flowrecord.anonymous_part.number_of_packets = 456
        
            yield request

    def benchmark_depseudonymize(self, args):
        ip = os.urandom(16)

        # manually compute investigator-local pseudonym
        pseudonym_secrets = {}
        for peer_secrets in self.args.secrets.peers.values():
            for shard, shard_secrets in peer_secrets.by_shard.items():
                pseudonym_secrets[shard] \
                        = shard_secrets.pseudonym_component_secret

        s = 1
        e = ed25519.scalar_unpack(common.sha256(b"PEP3 investigator"))
        for secret in pseudonym_secrets.values():
            s *= pow(ed25519.scalar_unpack(secret),e,ed25519.l)
            s %= ed25519.l

        investigator_local_ip = ( ed25519.Point.lizard(ip)*s ).pack()

        # manually create warrant
        warrant = pep3_pb2.DepseudonymizationRequest.Warrant()
        warrant.act.actor = b"PEP3 investigator"
        warrant.act.name.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM
        warrant.act.name.data = investigator_local_ip

        self.investigator.encrypt([ warrant.act.name ], 
                cheats.public_key(self.args.secrets,
                    b"PEP3 investigator", 'pseudonym'))

        warrant.signature = crypto.sign(
                crypto.load_privatekey(crypto.FILETYPE_PEM,
                    self.args.secrets.root_certificate_keys.warrants),
                warrant.act.SerializeToString(), 'sha256')

        result = self.investigator.connect_to("investigator")\
                .Depseudonymize(warrant)

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
        




