import threading
import collections
import os 
import xos
import traceback

import error

# A Tower is constructed by multiple threads floor-by-floor.
# Each thread may start construction of a floor by calling add_floor(),
# and 'store' some items on that floor by calling "store" on the returned Floor.
# These items are released only when the floor, and all floors below it
# are completed.  The thread that added the Floor may complete it by calling
# the "complete" method on Floor, and will receive all items (possibly from
# other floors) thereby released.
class Tower:
    def __init__(self):
        self._under_construction = collections.deque()
        self._lock = threading.Lock()
        self._floor_counter = 0

    def add_floor(self):
        floor = Tower.Floor(self, self._floor_counter)
        self._floor_counter += 1
        with self._lock:
            self._under_construction.append(floor)
        return floor

    def _update(self):
        released_items = []

        with self._lock:
            while len(self._under_construction)>0 \
                    and self._under_construction[0]._done:
                floor = self._under_construction.popleft()
                released_items.extend(floor._stored)

        return released_items

    def completion_diagram(self):
        result = ""
        first_under_construction = self._floor_counter
        if len(self._under_construction)>0:
            first_under_construction = self._under_construction[0]._number
        for i in range(self._floor_counter):
            if i<first_under_construction:
                result += "-"
            else:
                j = i-first_under_construction
                floor = self._under_construction[j]
                assert(floor._number == i)
                result += ("D" if floor._done else ".")
        return result

    class Floor:
        def __init__(self, tower, number):
            self._tower = tower
            self._done = False
            self._stored = []
            self._number = number

        def store(self, item):
            self._stored.append(item)

        def complete(self):
            assert(not self._done)
            self._done = True
            return self._tower._update()


class Cache:
    DEBUG_ENV_NAME = "PEP3_CACHE_DEBUG"

    def __init__(self, constructor, batchsize, maxsize=None):
        self._constructor = constructor
        assert(batchsize>0)
        self._batchsize = batchsize

        if maxsize==None:
            maxsize = batchsize*batchsize
        self._maxsize = maxsize

        self._on_hand = collections.OrderedDict()  # cached values
        self._in_progress = set() # items for which the values as currently computed
        self._in_line = [] # items that will soon go in a batch
        self._in_line_set = set() # TODO: use an "OrderedSet" datastructure

        self._in_line_callbacks = [] # callbacks for items in line, and before
        
        self._claimcount = collections.Counter() # number of requests for item

        self._lock = threading.RLock()
        self._tower = Tower()

        self._debug = Cache.DEBUG_ENV_NAME in os.environ
        if self._debug:
            self._debug_item_to_batch = {}


    def request(self, items, callback=None, flush=False):
        with self._lock:
            for item in items:
                self._claimcount[item] += 1
                if item in self._in_progress:
                    continue
                if item in self._on_hand:
                    self._on_hand.move_to_end(item)
                    continue
                if item not in self._in_line_set:
                    self._in_line_set.add(item)
                    self._in_line.append(item)
            batches = list(self._prepare_batches(flush))
            assert(len(self._in_line) < self._batchsize)
            self._in_line_callbacks.append( (callback, tuple(items)) ) 
        self._emit_batches(batches)
        self._prune()

    def flush(self, callback=None):
        self.request((), callback, flush=True)

    def _prepare_batches(self, flush=False):
        # assuming self._lock is held

        # only prepare a batch if there are enough items in line,
        # or if we're flushing, and there is at least one item or callback
        # to flush.
        while flush and (self._in_line or self._in_line_callbacks) \
                or len(self._in_line) >= self._batchsize:
            yield self._prepare_batch()

    def _prepare_batch(self):
        # assuming self._lock is held
        # assuming len(self._in_line) >= self._batchsize
        items = list(self._in_line[:self._batchsize])
        self._in_line = self._in_line[self._batchsize:]
        self._in_line_set = set(self._in_line)
        self._in_progress.update(items)
        floor = self._tower.add_floor()
        while(len(self._in_line_callbacks)>0):
            floor.store(self._in_line_callbacks.pop())
        batch = Cache._Batch(floor, items)
        if self._debug:
            for item in items:
                self._debug_item_to_batch[item] = batch
        return batch

    def _emit_batches(self, batches):
        for batch in batches:
            valuesOrError = error.catch(self._constructor, batch._items)
            with self._lock:
                for i, item in enumerate(batch._items):
                    self._on_hand[item] = valuesOrError.map(
                            lambda values: values[i])
                    self._in_progress.remove(item)
            callbacks = batch._floor.complete()
            for callback_no, (callback, items) in enumerate(callbacks):
                if self._debug:
                    for item in items:
                        if item not in self._on_hand:
                            with self._lock:
                                self._print_keyerror_debug_info(item,
                                        batches, callback_no, 
                                        callback, callbacks)
                                xos.terminate()
                results = {}
                for item in items:
                    if item not in self._on_hand:
                        self._print_keyerror_debug_info(ke.args[0], 
                                batches, callback_no, callback, callbacks)
                        xos.terminate()
                    results[item] = self._on_hand[item]
                try:
                    if callback != None:
                        callback(results)
                except Exception as e:
                    traceback.print_exc()
                    print("note: this unhandled exception in"
                            " a Cache.request callback causes termination")
                    xos.terminate()
                with self._lock:
                    for item in items:
                        cc = self._claimcount[item]-1
                        if cc==0:
                            del self._claimcount[item]
                        else:
                            self._claimcount[item] = cc

    def _prune(self):
        items_visited = 0
        with self._lock:
            while items_visited < len(self._on_hand) > self._maxsize:
                # get oldest item of cache, the one that was inserted first
                item = next(iter(self._on_hand))
                items_visited += 1
                if self._claimcount[item] == 0:
                    del self._on_hand[item]
                else:
                    self._on_hand.move_to_end(item)
            if len(self._on_hand) > self._maxsize:
                raise RuntimeError("cache overflow")

    def _print_keyerror_debug_info(self, key, batches, callback_no,
            callback, callbacks):

        print()
        print("INTERNAL ERROR in collector's Cache class - "
                "debug info follows")
        print()
        print(f"key: {key.hex()}") 
        if key in self._in_line_set:
            print(f"  in _in_line, among {len(self._in_line)}")
        if key in self._in_progress:
            print(f"  in _in_progress, among "
                    f"{len(self._in_progress)}")
        for batch_no, batch in enumerate(batches):
            if key in batch._items:
                print(f"  in batch #{batch_no} ")
        print()
        print(f"while emitting {len(batches)} batch(es)")
        for batch_no, batch in enumerate(batches):
            print(f"  batch {batch_no}: {len(batch._items)} items; "
                    f"floor #{batch._floor._number} "
                    f"({len(batch._floor._stored)} callbacks; "
                    f"completed: {batch._floor._done})")
        print()
        print(f"while calling callback {callback_no}"
                f" of {len(callbacks)}")
        print()
        print("tower completion diagram:")
        print(self._tower.completion_diagram())
        if not self._debug:
            print("Note: for more debug information,"
                    f" set {Cache.DEBUG_ENV_NAME}")
            return

        print()
        print("Extra {Cache.DEBUG_ENV_NAME} information:")
        print()
        
        batch = self._debug_item_to_batch.get(key, None)
        if batch==None:
            print("key has not been added to any batch")
        else:
            if key not in batch._items:
                print("key should be part of the following batch, *BUT ISN'T*:")
            else:
                print("key is part of the following batch "
                        f"(item #{batch._items.index(key)} of"
                        f" {len(batch._items)}):")
            print(f"  floor #{batch._floor._number}:")
            print(f"    completed: {batch._floor._done}")
            print(f"    stored callbacks: {len(batch._floor._stored)}")

                
    class _Batch:
        def __init__(self, floor, items):
            self._floor = floor
            self._items = items


    class KeyError(KeyError):
        @property
        def key(self):
            return self.args[0]
