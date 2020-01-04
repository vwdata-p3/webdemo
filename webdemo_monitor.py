#!/usr/bin/env python3

import time
import pep3
import pep3_pb2
import threading
import urllib.request
import urllib.parse
import json
import base64

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

def emit_event(peer_name, msg):
    event = {
        'peer_name': peer_name,
        'message': pb.json_format.MessageToDict(msg)
    }
    
    request = urllib.request.Request('http://localhost:1612/trigger_event',
            urllib.parse.urlencode({
                'event-name': 'peer_message',
                'event-data': json.dumps(event)
            }).encode('utf-8'))
    urllib.request.urlopen(request).read()


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
                if tries < 10:
                    time.sleep(0.01 * 2**tries)
                    tries += 1
                    continue
                print("webdemo_monitor: ERROR: "
                        f"couldn't connect to peer {peer_name}")
                return
            raise

if __name__=="__main__":
    for peer_name in config.peers.keys():
        threading.Thread(name=f'monitoring-of-{peer_name}',
                target=monitor_peer, args=(peer_name,)).start()
    
