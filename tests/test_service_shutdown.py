"""B5: `Service.shutdown()` used to close the databases while a maintenance
sweep was still running.

`run_maintenance` runs on the timer thread every minute and, forced, on
whatever HTTP thread called `apply_global_settings` (a settings save).
Before the fix, `shutdown()` never joined the timer thread and held no lock
around the stop/close sequence, so a sweep in flight on either thread could
call into a database `shutdown()` had just closed underneath it, raising
`sqlite3.ProgrammingError: Cannot operate on a closed database`.

This suite never starts the timer thread (`service.start()` is not needed to
exercise `run_maintenance`/`shutdown()` directly) and drives both from plain
threads instead."""
import os
import shutil
import sys
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.web import Service

TMPDIR = _paths.tmpdir("service_shutdown_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
           "alerts", "wireless", "configrx")


def new_service(subdir):
    data_dir = os.path.join(TMPDIR, subdir)
    os.makedirs(data_dir, exist_ok=True)
    return Service(*[os.path.join(data_dir, name + ".db") for name in DB_NAMES])


# ------------------------------------------------- 1. shutdown waits, doesn't crash

service = new_service("t1")

slow_calls = []


def slow_prune(*a, **k):
    slow_calls.append(time.time())
    time.sleep(2.0)
    return 0


service.flow_db.prune = slow_prune

errors = []


def run_forced():
    try:
        service.run_maintenance(force=True)
    except Exception:
        import sys as _sys
        errors.append(_sys.exc_info())


maint_thread = threading.Thread(target=run_forced, name="test-maintenance")
maint_thread.start()
time.sleep(0.3)   # let run_maintenance get well into the sweep

t0 = time.time()
service.shutdown()
elapsed = time.time() - t0

maint_thread.join(timeout=15.0)

check("run_maintenance actually got into the slow section before shutdown",
     len(slow_calls) == 1, slow_calls)
check("shutdown() returned in a bounded time (waited for the sweep, not stuck)",
     elapsed < 12.0, elapsed)
check("the maintenance thread finished",
     not maint_thread.is_alive())
check("no exception was raised on the maintenance thread "
     "(e.g. sqlite3.ProgrammingError from a closed database)",
     not errors, errors[0][1] if errors else None)

shutil.rmtree(os.path.join(TMPDIR, "t1"), ignore_errors=True)


# ------------------------------------------- 2. mutual exclusion between sweeps

service2 = new_service("t2")

call_log = []
call_lock = threading.Lock()


def counting_prune(*a, **k):
    with call_lock:
        call_log.append(time.time())
    time.sleep(0.5)
    return 0


service2.alerts_db.prune = counting_prune

# 2a. two concurrent non-forced calls: only one should run the body (the
# other loses the trylock and returns immediately because the interval
# check has not yet elapsed either).
service2._last_maintenance = 0.0
call_log.clear()
threads = [threading.Thread(target=service2.run_maintenance) for _ in range(2)]
for t in threads:
    t.start()
for t in threads:
    t.join(timeout=5.0)
check("two concurrent non-forced run_maintenance() calls only run the body once",
     len(call_log) == 1, call_log)

# 2b. a forced call while another forced call is running waits its turn
# rather than running concurrently.
call_log.clear()
first_started = threading.Event()

real_counting_prune = counting_prune


def marking_prune(*a, **k):
    first_started.set()
    return counting_prune(*a, **k)


service2.alerts_db.prune = marking_prune

t1 = threading.Thread(target=lambda: service2.run_maintenance(force=True))
t1.start()
first_started.wait(timeout=5.0)
t2 = threading.Thread(target=lambda: service2.run_maintenance(force=True))
t2.start()
t1.join(timeout=5.0)
t2.join(timeout=5.0)
check("two concurrent forced run_maintenance() calls both run, serialized",
     len(call_log) == 2, call_log)
check("...and did not overlap (the second waited for the lock)",
     len(call_log) < 2 or call_log[1] - call_log[0] >= 0.4, call_log)

service2.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t2"), ignore_errors=True)

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
