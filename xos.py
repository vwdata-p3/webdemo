import os
import signal

def terminate():
    pid = os.getpid()
    print(f"terminating..")
    os.kill(pid,signal.SIGTERM)

