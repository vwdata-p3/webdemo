import threading
import contextlib
import cProfile
import pstats
import queue

import xprofile

import grpc
import time
import grpc._cython.cygrpc

if threading.active_count() > 1:
    raise RuntimeError(f"{__name__} must be imported on the main thread"
            " before any (other) threads are created")


# we use threadlocal storage to get a profile for each thread
g_threadlocal = threading.local()
g_profiles = set()


def add_local_profile():
    g_threadlocal.profile = profile = cProfile.Profile(
            timer=time.thread_time_ns,
            timeunit=1.0/1000**3)
    g_profiles.add(profile)
    profile.enable()
add_local_profile()


def replace_thread_run():
    old_thread_run = threading.Thread.run

    def new_thread_run(thread):
        add_local_profile()
        old_thread_run(thread)

    threading.Thread.run = new_thread_run
replace_thread_run()


def replace_stats():
    def new_stats():
        stats = pstats.Stats()
        for profile in g_profiles:
            stats.add(profile)
        return stats

    xprofile.Stats = new_stats
replace_stats()


