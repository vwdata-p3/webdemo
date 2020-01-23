#!/usr/bin/env python3

import pep3
import pep3_pb2
import threading
import urllib.request
import urllib.parse
import json
import base64
import xos
import traceback
import time

import google.protobuf as pb
import google.protobuf.json_format
import grpc

def _get_config_and_secrets():
    config = pep3_pb2.Configuration()
    secrets = pep3_pb2.Secrets()

    with open("config.json") as f:
        pb.json_format.Parse(f.read(), config)

    with open("secrets.json") as f:
        pb.json_format.Parse(f.read(), secrets)

    return config, secrets
config, secrets = _get_config_and_secrets()

starttime = time.time()

def emit_event(peer_name, msg):
    event = {
        'peer_name': peer_name,
        'message': pb.json_format.MessageToDict(msg),
        'uptime': int(time.time()-starttime)
    }
    
    request = urllib.request.Request('http://localhost:1612/trigger_event',
            urllib.parse.urlencode({
                'event-name': 'peer_message',
                'event-data': json.dumps(event)
            }).encode('utf-8'))
    urllib.request.urlopen(request).read()

def try_monitor_peer(peer_name):
    with xos.terminate_on_exception(f"error on monitor of {peer_name}"):
        monitor_peer(peer_name)

def monitor_peer(peer_name):
    peer_stub = pep3.PepContext(config, secrets, 'demonstrator', None)\
            .connect_to('peer', peer_name)

    tries = 0
    while True:
        try: 
            for msg in peer_stub.Demo_Monitor(pep3_pb2.Void()):
                emit_event(peer_name, msg)
        except grpc.RpcError as e:
            if e.code()==grpc.StatusCode.UNAVAILABLE:
                #emit_event(peer_name, pep3_pb2.Message(modePlusOne=4))
                if tries < 20:
                    time.sleep(.5)
                    tries += 1
                    continue
                print("webdemo_monitor: ERROR: "
                        f"couldn't connect to peer {peer_name}:")
                traceback.print_exc()
                return
            raise

def try_ping_peer(peer_name):
    with xos.terminate_on_exception(f"error on pinger of peer {peer_name}"):
        ping_peer(peer_name)

def ping_peer(peer_name):
    peer_stub = pep3.PepContext(config, secrets, 'demonstrator', None)\
            .connect_to('peer', peer_name)

    while True:
        time.sleep(5)
        try:
            peer_stub.Demo_Ping(pep3_pb2.PingRequest(
                cause_message=True))
        except grpc.RpcError as e:
            if e.code()==grpc.StatusCode.UNAVAILABLE:
                continue


def wait_for_webdemo():
    # wait for webdemo to come online
    tries = 0
    while True:
        request = urllib.request.Request('http://localhost:1612/blank')
        try: 
            urllib.request.urlopen(request).read()
        except urllib.error.URLError as e:
            if tries < 20:
                time.sleep(.5)
                tries += 1
                continue
            print("webdemo_monitor: ERROR: "
                    "failed to connect to webdemo.")
            return 
        return # Ok, no error

if __name__=="__main__":
    wait_for_webdemo()

    for peer_name in config.peers.keys():
        threading.Thread(name=f'monitoring-of-{peer_name}',
                target=try_monitor_peer, args=(peer_name,)).start()
        threading.Thread(name=f'pinger-of-{peer_name}',
                target=try_ping_peer, args=(peer_name,)).start()
    
