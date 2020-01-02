import os

from cffi import FFI
import os.path, inspect

ffi = FFI()

curdir = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))

header = None
source = None

with open(os.path.join(curdir, "ristretto.h")) as f:
    header = f.read()
with open(os.path.join(curdir, "ristretto.c")) as f:
    source = header + f.read()
            
ffi.set_source("_ristretto",  source, extra_compile_args=["-O3", "-march=native", "-mavx2", "-fomit-frame-pointer", "-std=c99"])
ffi.cdef(header)

ffi.compile()
