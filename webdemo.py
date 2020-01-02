#!/usr/bin/env python3

import os
import threading
import json

import flask
import flask_socketio
import traceback

app = flask.Flask(__name__)
app.secret_key = os.urandom(32) # sessions won't work accross restarts
socketio = flask_socketio.SocketIO(app)

import pep3
import pep3_pb2
import common
import sql
import database

import google.protobuf as pb
import google.protobuf.json_format
from OpenSSL import crypto

import socket

# get pep configuration
def _get_config_and_secrets():
    config = pep3_pb2.Configuration()
    secrets = pep3_pb2.Secrets()

    with app.open_resource("config.json") as f:
        pb.json_format.Parse(f.read(), config)

    with app.open_resource("secrets.json") as f:
        pb.json_format.Parse(f.read(), secrets)

    return config, secrets
config, secrets = _get_config_and_secrets()

@socketio.on('rpc')
def handle_rpc(server_type_name, instance_name, MethodName, messages, call_as):
    answer = {}
    try:
        answer["results"] = _handle_rpc(server_type_name, instance_name,
                MethodName, messages, call_as)
    except Exception as e:
        answer["error"] = traceback.format_exc()
    return answer

@socketio.on('check_query')
def handle_check_query(query_json):
    answer = {}

    db_desc = database.Database.load_db_desc_from(config)

    query = pep3_pb2.SqlQuery()
    pb.json_format.ParseDict(query_json, query)

    param_desc = {}
    for name, value in query.parameters.items():
        _, param_desc[name] = common.value_to_object_and_type(value)

    try:
        answer['columns'] = sql.check_query(db_desc, param_desc, 
                query.query)
    except sql.InvalidQuery as e:
        answer['invalid_query'] = traceback.format_exc()
    except Exception as e:
        answer['error'] = traceback.format_exc()
    return answer

@socketio.on('sign_warrant')
def handle_sign_warrant(act_json):
    answer = {}
    warrant = pep3_pb2.DepseudonymizationRequest.Warrant()
    pb.json_format.ParseDict(act_json, warrant.act)

    actor = warrant.act.actor.decode('ascii')
    assert(actor.startswith("PEP3 "))
    type_name = actor[len("PEP3 "):]

    ctx = pep3.PepContext(config, secrets, my_type_name=type_name, 
            my_instance_name=None)
    ctx.encrypt([warrant.act.name])

    try:
        warrant.signature = crypto.sign( 
            crypto.load_privatekey(crypto.FILETYPE_PEM, 
                secrets.root_certificate_keys.warrants), 
            warrant.act.SerializeToString(), 'sha256') 
        crypto.verify(crypto.load_certificate(crypto.FILETYPE_PEM,
                        ctx.global_config.root_certificates.warrants),
                    warrant.signature,
                    warrant.act.SerializeToString(),'sha256')
        answer['warrant'] = pb.json_format.MessageToDict(warrant)
        answer['actor'] = type_name
        answer['serialized_act'] = str(warrant.act.SerializeToString())
    except Exception:
        answer['error'] = traceback.format_exc()
    return answer

def _handle_rpc(server_type_name, instance_name, MethodName, messages, call_as):
    if call_as==None:
        call_as = server_type_name
    server_ctx = pep3.PepContext(config, secrets, call_as, None)
    server = server_ctx.connect_to(server_type_name, instance_name)
    method = getattr(server, MethodName)

    server_type_desc = pep3_pb2.DESCRIPTOR.services_by_name[
            pep3.SERVER_TYPES[server_type_name].Name]
    method_desc = server_type_desc.methods_by_name[MethodName]

    input_type = common.pb_to_python_type(method_desc.input_type)

    method = common.pb_method_to_stream_stream(method)

    pb_messages = []
    for message in messages:
        pb_message = input_type()
        pb.json_format.ParseDict(message, pb_message)
        pb_messages.append(pb_message)

    print(f"calling {MethodName} on {pb_messages}")
    output_it = method(iter(pb_messages))

    return [ pb.json_format.MessageToDict(pb_message) 
            for pb_message in output_it ]


@app.route('/')
def handle_root():
    return flask.render_template('index.html', config=config)


@app.route('/trigger_event', methods=['POST'])
def handle_trigger_event():
    # TODO: add authentication
    if 'event-name' not in flask.request.form \
            or 'event-data' not in flask.request.form:
        print(f"warning: invalid call to trigger_event")
        return
    socketio.emit(flask.request.form['event-name'],
            json.loads(flask.request.form['event-data']))
    return ""


if __name__ == "__main__":
    socketio.run(app)

