import queue

# like q=queue.SimpleQueue(), but allows unblocking of threads
# waiting on q.get().
class Queue:
    def __init__(self):
        self._simplequeue = queue.SimpleQueue()
        self._stopped = False

    def get(self):
        if self._stopped:
            return None, True
        item = self._simplequeue.get()
        if self._stopped:
            # wake the next waiter (if there is one)
            self._simplequeue.put(None) 
            return None, True
        return item, False

    def stop(self):
        if self._stopped: return
        self._stopped = True
        self._simplequeue.put(None) # wake a waiter (if there is one)

    def put(self, item):
        if not self._stopped:
            self._simplequeue.put(item)

    def qsize(self):
        qsize = self._simplequeue.qsize()
        if self._stopped:
            qsize -= 1 # the "None" intended for wakeups
        return qsize



