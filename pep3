#!/usr/bin/env python3
import time
import sys
import argparse
import concurrent.futures
import grpc
import pep3_pb2
import pep3_pb2_grpc
import google.protobuf.json_format
import google.protobuf as pb
import os.path
import os
import importlib
import collections
import threading
import multiprocessing
import itertools
import random
import logging

import ed25519
import elgamal
import cryptopu
import common
import xprofile

from OpenSSL import crypto

import pep3_collect

def _configure_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
		'%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)
_configure_logging()


SERVER_TYPES = {} # will be { "peer": ServerTypeInfo(...), 
#                             "storage_facility": ServerTypeInfo(...), ... }

class ServerTypeInfo:
    def __init__(self, ServerTypeName, server_type_name, is_singleton):
        self.Name = ServerTypeName
        self.name = server_type_name
        self.is_singleton = is_singleton

def CamelCase2snake_case(s):
    return ''.join(map(lambda x: "_" + x.lower() if x.isupper() else x, s))[1:]

def set_SERVER_TYPES():
    conf_desc = pep3_pb2.DESCRIPTOR.message_types_by_name["Configuration"]

    for ServerTypeName in pep3_pb2.DESCRIPTOR.services_by_name.keys():
        server_type_name = CamelCase2snake_case(ServerTypeName)
        
        # We can tell there may be multiple peers but only one storage facility
        # by the facts that the Configuration message has the fields "peers"
        # and "storage_facility", respectively.
        if server_type_name in conf_desc.fields_by_name:
            is_singleton = True
        else:
            assert(server_type_name+"s" in conf_desc.fields_by_name)
            is_singleton = False

        SERVER_TYPES[server_type_name] = ServerTypeInfo(
                ServerTypeName,server_type_name, is_singleton)

set_SERVER_TYPES()
del set_SERVER_TYPES

def main():
    parser = argparse.ArgumentParser(
        description="Tool for the PEP3 system.")
    parser.set_defaults(parser=parser)
    parser.add_argument("--profile", action="store_true",
            help="run cProfile")
    parser.add_argument("--dump-stats", 
            help="run cProfile and dump stats to this file"
            "; implies --profile", type=str, metavar="FILE")
    subparsers = parser.add_subparsers()

    # . run 
    parser_run = subparsers.add_parser("run",
            description="Run specified servers")
    parser_run.set_defaults(parser=parser_run, func=run_servers)

    parser_run.add_argument("--config", 
            type=JsonMessageMaybeInFileArgument(pep3_pb2.Configuration),
            default="config.json",
            help="json file that stores the config of the PEP system. ")
    parser_run.add_argument("--secrets",
            type=JsonMessageMaybeInFileArgument(pep3_pb2.Secrets),
            default="secrets.json",
            help="json file that stores the secrets of the servers.")

    
    parser_run.add_argument("servers",
            type=str, nargs="+",
            metavar="server",
            help="either \"all\" or one of " + ', '.join([ 
                server_type.name if server_type.is_singleton 
                else server_type.name + ":{name}" 
                    for server_type in SERVER_TYPES.values() ]) )

    # . call
    parser_call = subparsers.add_parser("call")
    parser_call.set_defaults(parser=parser_call)
    parser_call.add_argument("--call-as", default="researcher")
    parser_call.add_argument("--config", 
            type=JsonMessageMaybeInFileArgument(pep3_pb2.Configuration),
            default="config.json")
    parser_call.add_argument("--secrets",
            type=JsonMessageMaybeInFileArgument(pep3_pb2.Secrets),
            default="secrets.json")


    subparsers_call = parser_call.add_subparsers()

    # . collect
    parser_collect = subparsers.add_parser("collect",
            description="Read plain flowrecords from specified file, "
                "and store them in PEP by sending them to the Collector.")
    parser_collect.set_defaults(parser=parser_collect)
    parser_collect.set_defaults(func=pep3_collect.collect)
    parser_collect.add_argument("--config", 
            type=JsonMessageMaybeInFileArgument(pep3_pb2.Configuration),
            default="config.json")
    parser_collect.add_argument("--secrets",
            type=JsonMessageMaybeInFileArgument(pep3_pb2.Secrets),
            default="secrets.json")
    parser_collect.add_argument("--batchsize",
            type=int,
            default="512")
    parser_collect.add_argument("--streamcount",
            type=int,
            default="5",
            help="Number of streams to open to the collector.")
    parser_collect.add_argument("--keep-input-open",
            action="store_true",
            help="Also open input file for writing (but don't write "
            "anything to it,) so that when the input file is a fifo "
            "it won't close when the actual writer is done.")
    parser_collect.add_argument("input")

    # .. <server_type_name>

    for server_type_name in SERVER_TYPES.keys():
        server_type = SERVER_TYPES[server_type_name]
        ServerTypeName = server_type.Name

        parser_server_type = subparsers_call.add_parser(server_type_name)
        parser_server_type.set_defaults(parser=parser_server_type)
        
        if not server_type.is_singleton:
            parser_server_type.add_argument("instance_name", type=str, 
                    default=None)
        else:
            parser_server_type.set_defaults(instance_name=None)

        subparsers_server_type = parser_server_type.add_subparsers()

        server_type_desc = pep3_pb2.DESCRIPTOR.services_by_name[ServerTypeName]

        for MethodName in server_type_desc.methods_by_name.keys():
            method_name = CamelCase2snake_case(MethodName)
            method_desc = server_type_desc.methods_by_name[MethodName]

            # ... <method>
            parser_method = subparsers_server_type.add_parser(method_name)
            parser_method.set_defaults(parser=parser_method)
            parser_method.set_defaults(func=call_method)
            parser_method.set_defaults(server_type_name=server_type_name)
            parser_method.set_defaults(MethodName=MethodName)
            
            input_type = common.pb_to_python_type(method_desc.input_type)
            parser_method.add_argument("input",
                    nargs="?",
                    default=input_type(),
                    type=JsonMessageMaybeInFileArgument(input_type),
                    help=method_desc.input_type.full_name)
    
    # . create
    parser_create = subparsers.add_parser("create")
    parser_create.set_defaults(parser=parser_create)
    subparsers_create = parser_create.add_subparsers()

    # .. local_config
    parser_local_config = subparsers_create.add_parser("local_config")

    parser_local_config.add_argument("--config", type=argparse.FileType("w+"),
            default="config.json")
    parser_local_config.add_argument("--secrets", type=argparse.FileType("w+"),
            default="secrets.json")

    parser_local_config.set_defaults(parser=parser_local_config)
    parser_local_config.set_defaults(func=create_local_config)

    # . benchmark
    parser_benchmark = subparsers.add_parser("benchmark")

    parser_benchmark.add_argument("--config", 
            type=JsonMessageMaybeInFileArgument(
                pep3_pb2.Configuration,
                dont_mind_not_set=True),
            default="config.json",
            help="configuration of the PEP system that is to be benchmarked; " 
            "if not set, a default configuration is used, and --run-servers "
            " is implied.")
    parser_benchmark.add_argument("--secrets",
            type=JsonMessageMaybeInFileArgument(
                pep3_pb2.Secrets,
                dont_mind_not_set=True),
            default="secrets.json",
            help="secrets to use to run the benchmark")
    parser_benchmark.add_argument("--run-servers",
            action="store_true",
            help="run servers locally")

    parser_benchmark.add_argument("name",
            help="name of the benchmark to run")
    parser_benchmark.add_argument("benchmark_args",
            nargs=argparse.REMAINDER)

    parser_benchmark.set_defaults(parser=parser_benchmark)
    parser_benchmark.set_defaults(func=benchmark)

    args = parser.parse_args()

    if 'func' not in args:
        args.parser.print_help()
        sys.exit(1)

    if args.dump_stats:
        args.profile = True

    if args.profile:
        importlib.import_module("enable_profiling")

    args.executor_type = concurrent.futures.ThreadPoolExecutor

    args.kill_command_event = threading.Event()

    try:
        args.func(args)
    except KeyboardInterrupt:
        args.kill_command_event.set()

    if not args.profile:
        return

    stats = xprofile.Stats()
    stats.sort_stats("cumulative") 

    if not args.dump_stats: 
        print("Press any key to print profiling stats (or Ctrl+C to exit.)")
        try: 
            sys.stdin.read(1) 
        except KeyboardInterrupt: 
            return 
     
    if args.dump_stats: 
        stats.dump_stats(args.dump_stats) 
    else: 
        stats.print_stats() 


class JsonMessageMaybeInFileArgument(object):
    def __init__(self, message_type, dont_mind_not_set=False):
        self._message_type = message_type
        self._dont_mind_not_set = dont_mind_not_set

    def __call__(self, string):
        if os.path.isfile(string):
            try:
                with open(string, "r") as f:
                    string = f.read()
            except OSError as e:
                raise argparse.ArgumentTypeError("can't open '%s': %s" \
                        % (string,e))
        try: 
            return pb.json_format.Parse(string, self._message_type())
        except pb.json_format.ParseError as e:
            if self._dont_mind_not_set:
                return None
            raise argparse.ArgumentTypeError("'%s' is neither the filename"
                    " of an existing file nor a valid JSON string: %s" 
                            % (string,e))

def parse_server_name(server_name):
    # converts "peer:A" to ("peer", "A") and 
    #          "key_server" to ("key_server", None), etc..
    parts = server_name.split(":", 1)
    server_type_name = parts[0]
    if SERVER_TYPES[server_type_name].is_singleton and len(parts)>1:
        raise ValueError(f"\"{server_type_name}:{parts[1]}\" makes no sense:"
                f" {server_type_name} has only one instance.")
    if not SERVER_TYPES[server_type_name].is_singleton and len(parts)==1:
        raise ValueError(f"please specify instance of {server_type_name}"
                f" via \"{server_type_name}:< instance name >\".")
    instance_name = None
    if len(parts)>1:
        instance_name = parts[1]
    return (server_type_name, instance_name)

def call_method(args):
    pep = PepContext(args.config, args.secrets, 
            *parse_server_name(args.call_as))
    server_stub = pep.connect_to(args.server_type_name, args.instance_name)

    method = getattr(server_stub, args.MethodName)
    inp = args.input

    if method.__class__.__name__.startswith("_Stream"):
        inp = iter( (inp,) )

    results = method(inp)

    if not isinstance(results, collections.Iterable):
        results = (results,)
    for result in results:
        print(pb.json_format.MessageToJson(result))


def run_servers(args, executor_type=None):
    servers = []

    if "all" in args.servers:
        servers = None
    else:
        for server_name in args.servers:
            servers.append(parse_server_name(server_name))

    with RunServers(args.config, args.secrets, servers, 
            executor_type=executor_type):
        args.kill_command_event.wait()


class RunServers:
    def __init__(self, config, secrets, server_names=None, executor_type=None):
        self.config = config
        self.secrets = secrets
        self.contexts = {}
        self.executor_type = executor_type
        
        if server_names==None:
            server_names = []
            # get all servers based on provided configuration
            for server_type in SERVER_TYPES.values():
                if server_type.is_singleton:
                    server_names.append( (server_type.name, None) )
                    # get all servers based on provided configuration
                    continue
                for instance_name in getattr(config, server_type.name+"s"):
                    server_names.append( (server_type.name, instance_name) )

        self.server_names = server_names

    def __enter__(self):
        for server_type_name, instance_name in self.server_names:
            pep_context = PepContext(self.config, self.secrets, 
                    server_type_name, instance_name,
                    executor_type=self.executor_type)
            pep_context.create_grpc_servicer()
            self.contexts[(server_type_name,instance_name)] = pep_context
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for context in self.contexts.values():
            context.shutdown_start()
        for context in self.contexts.values():
            context.shutdown_finish()
    

def create_local_config(args):
    config = pep3_pb2.Configuration()
    secrets = pep3_pb2.Secrets()

    fill_local_config_messages(config, secrets)

    args.config.write(pb.json_format.MessageToJson(config))
    args.secrets.write(pb.json_format.MessageToJson(secrets))


def benchmark(args):
    if (args.config==None)!=(args.secrets==None):
        sys.stderr.write("Error: either both --config and --secrets should "
                " be set, or neither.\n")
        sys.exit(-1)

    import benchmarks
    benchmarks.Benchmarks(args).run()


def fill_local_config_messages(config, secrets):
    config.domains.append("pseudonym")
    pu = cryptopu.CryptoPU()

    # configure peers
    peer_names = ('A', 'B', 'C', 'D', 'E')

    for letter in peer_names:
        config.peers.get_or_create(letter)
        secrets.peers.get_or_create(letter)
        secrets.peers[letter].reminders_hmac_secret = os.urandom(32)

    private_keys = {}
    for domain in config.domains:
        private_keys[domain] = 1  # will be set below

    peer_triples = tuple(itertools.combinations(peer_names,3))

    for name1, name2, name3 in peer_triples:
        shard = name1 + name2 + name3  # ABC, ADE, ...
        config.shards.append(shard)

        config.peers[name1].shards.append(shard)
        config.peers[name2].shards.append(shard)
        config.peers[name3].shards.append(shard)

        secrets.peers[name1].by_shard[shard].pseudonym_component_secret\
                = secrets.peers[name2].by_shard[shard]\
                        .pseudonym_component_secret\
                = secrets.peers[name3].by_shard[shard]\
                        .pseudonym_component_secret\
                = s_packed = os.urandom(32)
        s = ed25519.scalar_unpack(s_packed)

        config.components[shard].pseudonym.base_times_two_to_the_power_of\
                .extend(pu.component_public_part(s))

        for domain in config.domains:
            private_key_part = ed25519.scalar_random()

            secrets.peers[name1].by_shard[shard].by_domain[domain]\
                        .private_master_key\
                    = secrets.peers[name2].by_shard[shard].by_domain[domain]\
                            .private_master_key\
                    = secrets.peers[name3].by_shard[shard].by_domain[domain]\
                            .private_master_key\
                    = ed25519.scalar_pack(private_key_part)

            private_keys[domain] *= private_key_part
            private_keys[domain] %= ed25519.l

            secrets.peers[name1].by_shard[shard].by_domain[domain]\
                            .key_component_secret\
                    = secrets.peers[name2].by_shard[shard].by_domain[domain]\
                            .key_component_secret\
                    = secrets.peers[name3].by_shard[shard].by_domain[domain]\
                            .key_component_secret\
                    = k_packed = os.urandom(32)
            k = ed25519.scalar_unpack(k_packed)

            config.components[shard].keys[domain]\
                    .base_times_two_to_the_power_of\
                    .extend(pu.component_public_part(k))

    # generate certificates and port numbers for the servers
    root_key = crypto.PKey()
    root_key.generate_key(crypto.TYPE_RSA, 1024)
    secrets.root_certificate_keys.tls = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, root_key)
    root_crt = crypto.X509()
    root_crt.get_subject().CN = "PEP3 TLS Root"
    root_crt.set_serial_number(1)
    root_crt.gmtime_adj_notBefore(0)
    root_crt.gmtime_adj_notAfter(356*24*60*60)
    root_crt.set_issuer(root_crt.get_subject())
    root_crt.set_pubkey(root_key)
    root_crt.sign(root_key, 'sha256')

    config.root_certificates.tls = crypto.dump_certificate(
            crypto.FILETYPE_PEM, root_crt)

    port = 1234
    number_of_cpus = multiprocessing.cpu_count()

    for server_type_name, server_type in SERVER_TYPES.items():
        if server_type.is_singleton:
            server_configs = { None: getattr(config,server_type_name) }
        else:
            server_configs = getattr(config, server_type_name+"s")

        for name, server_config in server_configs.items():
            server_config.number_of_threads = number_of_cpus
        
            # set address and port
            server_config.location.address = \
                    server_config.location.listen_address = f"localhost:{port}"
            port += 1

            # set tls certificate
            server_key = crypto.PKey()
            server_key.generate_key(crypto.TYPE_RSA, 1024)
            server_crt = crypto.X509()
            server_crt.get_subject().CN = "PEP3 " + server_type_name
            server_crt.set_serial_number(1)
            server_crt.gmtime_adj_notBefore(0)
            server_crt.gmtime_adj_notAfter(356*24*60*60)
            server_crt.set_issuer(root_crt.get_subject())
            ext = crypto.X509Extension(b"subjectAltName",False, b"DNS:localhost")
            server_crt.add_extensions([ext])
            server_crt.set_pubkey(server_key)
            server_crt.sign(root_key, 'sha256')
        
            server_config.location.tls_certificate = crypto.dump_certificate(
                crypto.FILETYPE_PEM, server_crt)

            if name==None:
                server_secrets = getattr(secrets,server_type_name)
            else:
                server_secrets = getattr(secrets,server_type_name+"s")[name]

            server_secrets.tls_certificate_key = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, server_key)

    # The following uri makes sqlalchemy.create_engine use sqlite's :memory:
    # in-memory database.
    config.database.engine.uri = "sqlite://" 
    config.database.engine.connect_args['check_same_thread'] = False
    config.database.engine.poolclass = 'StaticPool'
    config.database.engine.create_tables = True
    config.database.number_of_threads = 1

    # generate keys for warrants
    warrant_key = crypto.PKey()
    warrant_key.generate_key(crypto.TYPE_RSA, 1024)
    secrets.root_certificate_keys.warrants = crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, warrant_key)
    warrant_crt = crypto.X509()
    warrant_crt.get_subject().CN = "PEP3 Warrant Root"
    warrant_crt.set_serial_number(1)
    warrant_crt.gmtime_adj_notBefore(0)
    warrant_crt.gmtime_adj_notAfter(356*24*60*60)
    warrant_crt.set_issuer(warrant_crt.get_subject())
    warrant_crt.set_pubkey(warrant_key)
    warrant_crt.sign(warrant_key, 'sha256')
    warrant_crt_data = crypto.dump_certificate(crypto.FILETYPE_PEM, 
            warrant_crt)

    config.root_certificates.warrants = warrant_crt_data

    # for Collector.Store
    warrant = config.collector.warrants.to_sf
    act = warrant.act
    act.target = b"PEP3 storage_facility"
    act.encrypt_for = b"PEP3 storage_facility"
    act.source = b"plaintext"
    act.actor = b"PEP3 collector"

    warrant.signature = crypto.sign(
            warrant_key, act.SerializeToString(), 'sha256')

    # for Researcher.Query
    warrant = config.researcher.warrants.from_me_to_sf
    act = warrant.act
    act.target = b"PEP3 storage_facility"
    act.encrypt_for = b"PEP3 storage_facility"
    act.source = b"PEP3 researcher"
    act.actor = b"PEP3 researcher"

    warrant.signature = crypto.sign(
            warrant_key, act.SerializeToString(), 'sha256')

    warrant = config.researcher.warrants.from_sf_to_me
    act = warrant.act
    act.target = b"PEP3 researcher"
    act.encrypt_for = b"PEP3 researcher"
    act.source = b"PEP3 storage_facility"
    act.actor = b"PEP3 researcher"

    warrant.signature = crypto.sign(
            warrant_key, act.SerializeToString(), 'sha256')

    # for Investigator.Query
    warrant = config.investigator.warrants.from_me_to_sf
    act = warrant.act
    act.target = b"PEP3 storage_facility"
    act.encrypt_for = b"PEP3 storage_facility"
    act.source = b"PEP3 investigator"
    act.actor = b"PEP3 investigator"

    warrant.signature = crypto.sign(
            warrant_key, act.SerializeToString(), 'sha256')

    warrant = config.investigator.warrants.from_sf_to_me
    act = warrant.act
    act.target = b"PEP3 investigator"
    act.encrypt_for = b"PEP3 investigator"
    act.source = b"PEP3 storage_facility"
    act.actor = b"PEP3 investigator"

    warrant.signature = crypto.sign(
            warrant_key, act.SerializeToString(), 'sha256')

    # describe tables used by the database
    columns = config.db_desc['peped_flows'].columns
    columns['p_src_ip'] = 'pseudonymized'
    columns['p_dst_ip'] = 'pseudonymized'

    for name in ('start_time', 'end_time', 'src_port', 'dst_port',
            'protocol', 'packets', 'bytes'):
        columns[name] = 'plain'

    #
    config.batchsize = 1024

        
class PepContext:
    def __init__(self, config, secrets, my_type_name, my_instance_name, 
            executor_type=None, allow_enrollment=True):

        self.global_config = config
        self.my_type_name = my_type_name
        self.my_instance_name = my_instance_name
        self.allow_enrollment = allow_enrollment
        
        if my_instance_name==None:
            self.config = getattr(config, my_type_name)
            self.secrets = getattr(secrets, my_type_name)
        else:
            if my_instance_name not in getattr(config, my_type_name+"s"):
                raise ValueError(f"there is no instance of \"{my_type_name}\""
                        f" named \"{my_instance_name}\"")
            self.config = getattr(config, my_type_name+"s")[my_instance_name]
            self.secrets = getattr(secrets, my_type_name+"s")[my_instance_name]

        if executor_type == None:
            executor_type = concurrent.futures.ThreadPoolExecutor

        self._executor_type = executor_type
        self._lock = threading.RLock()
        self._connections = {}
        self._private_keys = None
        self._public_keys = None
        self._certified_components = None
        self._reminders = None # to the peers that the components are correct
        self._cryptopu = cryptopu.CryptoPU()

    def shutdown_start(self):
        if not hasattr(self, "grpc_server"):
            return
        self.grpc_server.stop(None)
        servicer = self.grpc_servicer
        if hasattr(servicer, "shutdown"):
            servicer.shutdown()

    def shutdown_finish(self):
        if hasattr(self, "_executor"):
            self._executor.shutdown()

    @property
    def MyTypeName(self):
        return SERVER_TYPES[self.my_type_name].Name

    def __str__(self):
        return self.my_type_name + ("" if self.my_instance_name==None else
                "/" + self.my_instance_name)

    # connects to the specified server, and returns the grpc stub object
    def connect_to(self, server_type_name, instance_name=None):
        name = (server_type_name, instance_name)

        assert( SERVER_TYPES[server_type_name].is_singleton 
                == (instance_name==None) )

        if name in self._connections:
            return self._connections[name]

        with self._lock:
            if name in self._connections:
                return self._connections[name]

            # create self._connections[name]
            key = bytes(self.secrets.tls_certificate_key, 'utf-8')
            crt = bytes(self.config.location.tls_certificate, 'utf-8')
            root_crt = bytes(self.global_config.root_certificates.tls, 'utf-8')

            channel_credentials = grpc.ssl_channel_credentials(
                    root_certificates=root_crt, private_key=key,
                    certificate_chain=crt)
            
            if instance_name==None:
                server_config = getattr(self.global_config, server_type_name)
            else:
                server_config = getattr(self.global_config, 
                        server_type_name+"s")[instance_name]

            channel = grpc.secure_channel(server_config.location.address, 
                    channel_credentials)

            ServerTypeName = SERVER_TYPES[server_type_name].Name
            self._connections[name] \
                    = getattr(pep3_pb2_grpc, ServerTypeName + "Stub")(channel)

        return self._connections[name]

    def _create_grpc_server(self):
        host_key = bytes(self.secrets.tls_certificate_key, 'utf-8')
        host_crt = bytes(self.config.location.tls_certificate, 'utf-8')
        root_crt = bytes(self.global_config.root_certificates.tls, 'utf-8')

        server_credentials = grpc.ssl_server_credentials(
                private_key_certificate_chain_pairs=((host_key, host_crt),), 
                root_certificates=root_crt,
                require_client_auth=True)

        self._executor = self._executor_type(
                max_workers=self.config.number_of_threads,
                thread_name_prefix=str(self))
        server = grpc.server(self._executor)
        server.add_secure_port(self.config.location.listen_address, 
                server_credentials)

        server.start()

        self.grpc_server = server

    def create_grpc_servicer(self):
        self._create_grpc_server()
        
        if self.my_type_name not in globals():
            # import <self.my_type_name>
            globals()[self.my_type_name] = \
                    importlib.import_module(self.my_type_name)

        assert self.my_type_name in globals(), \
                "couldn't import module  '%s'" \
                % self.my_type_name

        server_module = globals()[self.my_type_name]

        ServerTypeName = self.MyTypeName
        assert ServerTypeName in dir(server_module), \
                "module '%s' contains no class named '%s'" \
                % (server_name,ServerTypeName)
        servicer_class = getattr(server_module, ServerTypeName)
        self.grpc_servicer = servicer_class(self)
        getattr( pep3_pb2_grpc, "add_" + ServerTypeName 
                + "Servicer_to_server" )(self.grpc_servicer, self.grpc_server)


    def _enroll(self):
        void = pep3_pb2.Void()

        key_parts = {}
        components = {} # by shard

        for domain in self.global_config.domains:
            key_parts[domain] = {}

        futs = []
        for peer_name in self.global_config.peers:
            futs.append(self.connect_to("peer", peer_name).Enroll.future(void))

        for fut in futs:
            resp = fut.result()
            for shard, by_shard in resp.by_shard.items():

                for domain, private_key_part in \
                        by_shard.private_local_keys.items():

                    if shard not in key_parts[domain]:
                        key_parts[domain][shard] = private_key_part
                    else:
                        # inconsistency?
                        assert(key_parts[domain][shard]
                                == private_key_part)

            for shard, by_shard in resp.components.items():
                assert(set(by_shard.keys.keys()) \
                        == set(self.global_config.domains))

                if shard not in components:
                    components[shard] = by_shard
                else:
                    other_by_shard = components[shard]
                    # check for consistency
                    assert(other_by_shard.pseudonym.component
                            == by_shard.pseudonym.component)
                    for domain in self.global_config.domains:
                        assert(other_by_shard.keys[domain].component 
                                == by_shard.keys[domain].component)


        # check if we have received everything
        if len(components)>0:
            for shard in self.global_config.shards:
                assert(shard in components)
        
        # compute private local keys
        private_local_keys = {}
        for domain in self.global_config.domains:
            private_local_keys[domain] = 1
            for shard in self.global_config.shards:
                private_local_keys[domain] *= ed25519.scalar_unpack(
                        key_parts[domain][shard])
                private_local_keys[domain] %= ed25519.l

        # compute public keys
        public_keys = {}
        for domain in self.global_config.domains:
            public_keys[domain] = ed25519.Point.B_times(
                    private_local_keys[domain])

        # register components if we got them
        reminders = None
        if len(components)>0:
            reminders = self._register_components(components)

        return (public_keys, private_local_keys, components, reminders)


    def _register_components(self, components):
        futs = {}
        shards_set = set(self.global_config.shards)

        # send registration requests to components
        for peer in self.global_config.peers:
            request = pep3_pb2.CertifiedComponents()
            for shard in shards_set \
                    - set(self.global_config.peers[peer].shards):
                request.components[shard].CopyFrom(components[shard])

            futs[peer] = (self.connect_to("peer", peer)\
                    .RegisterComponents.future(request))

        reminders = {}

        for peer, fut in futs.items():
            reminders[peer] = fut.result().reminders

        return reminders


    @property
    def private_keys(self):
        self._ensure_enrolled()
        return self._private_keys

    @property
    def public_keys(self):
        self._ensure_enrolled()
        return self._public_keys

    @property
    def certified_components(self):
        self._ensure_enrolled()
        return self._certified_components

    @property
    def reminders(self):
        self._ensure_enrolled()
        if len(self._certified_components)==0:
            raise ValueError("didn't get certified components")
        return self._reminders

    def _ensure_enrolled(self):
        assert(self.allow_enrollment)

        if self._private_keys!=None:
            return
        with self._lock:
            if self._private_keys!=None:
                return
            self._public_keys,\
                self._private_keys, \
                self._certified_components, \
                self._reminders = self._enroll()

    def pseudonymize(self, names):
        for name in names:
            assert(name.state==pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME)
            name.state = pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM
            name.data = ed25519.lizard_without_elligator(name.data)
        self._cryptopu.elligator(names)
        self._cryptopu.encrypt(names,
                self.public_keys['pseudonym'],
                [ed25519.scalar_random() for i in range(len(names))])

    def encrypt(self, names, key=None):
        if key==None:
            key = self.public_keys['pseudonym']
        for name in names:
            assert(name.state==pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM)
            name.state = pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM
        self._cryptopu.encrypt(names, key, [ed25519.scalar_random() 
            for i in range(len(names))])

    def decrypt(self, names, key):
        for name in names:
            assert(name.state==pep3_pb2.Pseudonymizable\
                    .ENCRYPTED_PSEUDONYM)
            name.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM
        self._cryptopu.decrypt(names, key)

    def relocalize(self, pseudonyms, warrant):
        if len(pseudonyms)==0:
            return

        for pseudonym in pseudonyms:
            assert(pseudonym.state in (
                pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM,
                pep3_pb2.Pseudonymizable.ENCRYPTED_NAME))

        request = pep3_pb2.RelocalizationRequest()
        request.warrant.CopyFrom(warrant)
        request.names.extend(pseudonyms)
        
        unused_peers = set(self.global_config.peers)
        unassigned_shards = set(self.global_config.shards)

        while len(unassigned_shards)>0:
            if len(unused_peers)==0:
                raise RuntimeError("Not enough working peers")

            peer = random.choice(list(unused_peers))
            unused_peers.remove(peer)
            
            shards = unassigned_shards \
                            & set(self.global_config.peers[peer].shards)

            request.ClearField('which_shards')
            request.which_shards.extend(shards)

            # TODO: random check of peers
            try:
                resp = self.connect_to("peer", peer).Relocalize(request)
                assert(len(resp.names)==len(pseudonyms))
            except grpc.RpcError as e:
                logging.warn(f"relocalization request to peer {peer}"
                        f" failed: {e.details()}")
                # TODO: differentiate between errors; was it our fault,
                # or did the peer fail?
                continue
            
            unassigned_shards -= shards
            request.ClearField('names')
            request.names.extend(resp.names)

        for i in range(len(pseudonyms)):
            pseudonyms[i].CopyFrom(resp.names[i])


    def depseudonymize(self, warrant, out):
        request = pep3_pb2.DepseudonymizationRequest()
        request.warrant.CopyFrom(warrant)
        
        # let's plan which peers to contact for which shards
        plan = []
        # will be [ (peer1, (shard1, shard2, ..., shard42)),
        #           (peer2, (sercret43, shard44, ..)), ... ]

        unused_peers = set(self.global_config.peers)
        unassigned_shards = set(self.global_config.shards)

        while len(unassigned_shards)>0:
            assert(len(unused_peers)>0)

            peer = random.choice(list(unused_peers))
            unused_peers.remove(peer)
            
            shards = unassigned_shards \
                            & set(self.global_config.peers[peer].shards)
            unassigned_shards -= shards

            plan.append( (peer, shards) )

        # keeps track of the shards in the chain
        shards_in_the_chain = set()  

        # execute the plan
        for peer, shards in plan:
            request.ClearField('which_shards')
            request.ClearField('reminders')
            request.which_shards.extend(shards)

            # set reminders
            for reminder in self.reminders[peer]:
                if reminder.shard in shards_in_the_chain and \
                        reminder.HasField("pseudonym"):
                    reminder_ = request.reminders.add()
                    reminder_.CopyFrom(reminder)

            resp = self.connect_to("peer", peer).Depseudonymize(request)

            # TODO: should we too check the proofs provided by the peer?
            
            link = request.chain.add()
            link.peer = peer
            link.peer_response.CopyFrom(resp)
            link.which_shards.extend(shards)
            shards_in_the_chain.update(shards)
            
        out.CopyFrom(resp.name)

        # decrypt the result
        self.decrypt([ out ], self.private_keys['pseudonym'])
        out.data = ed25519.Point.unpack(out.data).lizard_inv()
        out.state = pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME

def raise_nofile_limit(to=1024):
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < to and to < hard:
        soft = to
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

if __name__=="__main__":
    main()

