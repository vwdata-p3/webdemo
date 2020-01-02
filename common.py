import hashlib
import hmac
import threading
import concurrent.futures
import numbers
import functools
import queue
import sys
import collections
import contextlib

import pep3_pb2
import grpc
import grpc._channel

def sha256hmac(secret, msg):
    return hmac.new(secret, msg, hashlib.sha256).digest()

def sha256(data):
    return hashlib.sha256(data).digest()

def authenticate(context, must_be_one_of=None):
    common_names = context.auth_context().get("x509_common_name")
    if len(common_names)==0:
        context.abort(grpc.StatusCode.UNAUTHENTICATED,
                "no single common name was provided by the "
                f"tls certificate but instead: {common_names}")
    common_name = common_names[0]

    if must_be_one_of!=None and common_name not in must_be_one_of:
        context.abort(grpc.StatusCode.PERMISSION_DENIED,
                f"to call this method you must one of {must_be_one_of}, "
                f"but you are {common_name}")

    return common_name

def check_is_plaintext(p, context):
    if p.state != pep3_pb2.Pseudonymizable.UNENCRYPTED_NAME:
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                f"pseudonymizable should be UNENCRYPTED_NAME but is {p.state}")

def check_is_encrypted_pseudonym(p, context):
    if p.state != pep3_pb2.Pseudonymizable.ENCRYPTED_PSEUDONYM:
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                "pseudonymizable should be ENCRYPTED_PSEUDONYM"
                f" but is {p.state}")
    if len(p.data)!=96:
        context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                "the data of an encrypted local pseudonym consists "
                f"of 96 bytes, but {len(p.data)} were given")

class Failure(Exception):
    pass

class iter_threadsafe:
    def __init__(self, iterable):
        self._it = iter(iterable)
        self._lock = threading.Lock()

    def __next__(self):
        with self._lock:
            return next(self._it)

def pb_to_python_type(pb_type):
    # Given the type descriptor for, say, pep3_pb2.Pseudonymizable, returns
    # pep3_pb2.Pseudonymizable. The existence of nested types such as
    # pep3_pb2.RelocalizationRequest.Warrant makes this not entirely trivial.
    parent = pep3_pb2
    if pb_type.containing_type != None:
        parent = pb_to_python_type(pb_type.containing_type)
    return getattr(parent, pb_type.name)

def pb_method_to_stream_stream(method):
    # turns a {Stream,Unary}{Stream,Unary}MultiCallable to something
    # that takes an iterator and returns an iterator
    if isinstance(method,grpc.UnaryUnaryMultiCallable):
        return lambda it: iter( ( method(assert_singleton(it)), ) )
    if isinstance(method,grpc.UnaryStreamMultiCallable):
        return lambda it: method(assert_singleton(it))
    if isinstance(method,grpc.StreamUnaryMultiCallable):
        return lambda it: iter( ( method(it), ) )
    if isinstance(method,grpc.StreamStreamMultiCallable):
        return lambda it: method(it)
    assert(False)

def assert_singleton(it):
    """Checks that the given iterator contains exactly one element,
    and returns it."""
    try:
        result = next(it)
    except StopIteration:
        raise ValueError('expected exactly one element from iterator; got none')
    try:
        next(it)
    except StopIteration:
        return result
    raise ValueError('expected exactly one element from iterator; got more')




def verify_protobuf_signature(msg, hmac_secret, field="signature"):
    signature = getattr(msg,field)
    setattr(msg, field, b"")
    return signature == sha256hmac(hmac_secret, msg.SerializeToString())

def sign_protobuf(msg, hmac_secret, field="signature"):
    setattr(msg, field, sha256hmac(hmac_secret, msg.SerializeToString()))

def value_to_object_and_type(v):
    """Given pep3_pb.Value, returns the associated Python object
    and either 'plain' or 'pseudonymized'"""
    which = v.WhichOneof('kind')
    if which=='pseudonymizable_value':
        return v.pseudonymizable_value.data, 'pseudonymized'
    elif which=='number_value':
        return v.number_value, 'plain'
    elif which=='string_value':
        return v.string_value, 'plain'
    else:
        raise NotImplementedError(f"Unknown pep3_pb2.Value kind {kind}")

def object_and_type_to_value(value, obj, typ):
    if typ == 'pseudonymized':
        value.pseudonymizable_value.data = obj
        value.pseudonymizable_value.state \
                = pep3_pb2.Pseudonymizable.UNENCRYPTED_PSEUDONYM
    elif typ == 'plain':
        if isinstance(obj, numbers.Number):
            value.number_value = obj
        elif isinstance(obj, str):
            value.string_value = obj
        else:
            raise NotImplementedError(f"Unsupported value for cell: {obj}")
    else:
        raise NotImplementedError(f"Unknown type '{typ}'")


# decorator
class switch:
    def __init__(self, expr):
        self._expr = expr
        self._cases = dict()
        self._default_case = self.default_default_case

    def default_default_case(self, *args, **kwargs):
        raise ValueError(f"switch: no case for {self._expr(*args,**kwargs)}"
                " (and no default case.)")

    def case(self, val):
        return functools.partial(self._case_on, val)

    def default(self, f):
        self._default_case = f
        return self

    def _case_on(self, val, f):
        self._cases[val] = f
        return self

    def __call__(self, *args, **kwargs):
        case = self._cases.get(self._expr(*args, **kwargs), self._default_case)
        return case(*args, **kwargs)

    def __get__(self, obj, t=None):
        return functools.partial(self.__call__, obj)


# Given a queue, return an iterator that empties it
class iterqueue:
    def __init__(self, queue):
        self._queue = queue
    def __iter__(self):
        return self
    def __next__(self):
        return self._queue.get()

# Given an iterator, return basically the same iterator, but under the hood
# it uses a separate thread to get the next items as quickly as possible,
# storing them in an internal queue.
class chuck:
    def __init__(self, it):
        self._queue = queue.SimpleQueue()
        self._thread = threading.Thread(
                target=self._threads_work, 
                kwargs={
                    "it": iter(it), 
                    "queue": self._queue}
        ).start()

    def __iter__(self):
        return self

    def __next__(self):
        item, exception  = self._queue.get()
        if exception != None:
            self._queue.put_nowait( (None, exception) )
            raise exception
        return item

    def size(self):
        return self._queue.qsize()

    @staticmethod
    def _threads_work(it, queue):
        while True:
            try:
                item = next(it)
            except Exception as e:
                queue.put_nowait( (None, e) )
                break
            queue.put_nowait( (item, None) )

