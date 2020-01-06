import os
import contextlib
import traceback
import signal

@contextlib.contextmanager
def terminate_on_exception(msg):
    try:
        yield
    except Exception as e:
        print(msg)
        traceback.print_exc()
        terminate()

def terminate():
    pid = os.getpid()
    print(f"terminating..")
    os.kill(pid,signal.SIGTERM)

