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
import io
import os
import shutil
import sqlite3
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


# --------------------------------------- 3. the trace scheduler, same bug class
# 4.48.1: the same "closed database under work still in flight" bug as
# sections 1/2 above, in Monitor (netpath/monitor.py)'s trace scheduler
# rather than the maintenance sweep — found from a stray traceback at the
# end of tests/test_web_gates.py, not from a report against a running
# instance.
#
# The failure mode is different from sections 1/2, though, and that
# difference is why this needs its own check rather than reusing theirs
# unchanged: _run_one runs on Monitor's own ThreadPoolExecutor with nothing
# waiting on the future, so the exception never reaches a caller's
# sys.exc_info() the way run_maintenance's did. Before the fix, the only
# sign was _run_one's own "must never die quietly" handler printing a raw
# traceback to stderr — indistinguishable, in a log an operator checks
# right after a service stop, from an actual crash. Caught on stderr here
# for that reason.
import netpath.monitor as monitor_mod
from netpath.tracer import TraceResult

service3 = new_service("t3")
target_id = service3.db.add_target("10.0.0.9", max_hops=2, probes=1, timeout_s=1.0)
real_record_trace = service3.db.record_trace
real_run_trace = monitor_mod.run_trace


def closed_db_record_trace(*a, **k):
    raise sqlite3.ProgrammingError("Cannot operate on a closed database.")


def instant_run_trace(host, **kwargs):
    return TraceResult(host=host, dest_ip=host, hops=[], reached=True,
                       started_ts=time.time(), duration_s=0.0)


service3.db.record_trace = closed_db_record_trace
# 3a/3b call _run_one directly rather than through a real trace, so they do
# not depend on this host actually having a working tracert/traceroute —
# see REVIEW-OPERATOR-4.49.md's W-1/W-2 on how little that can be assumed.
monitor_mod.run_trace = instant_run_trace

# 3a. Forced directly rather than by racing a real shutdown against a real
# trace, so this is deterministic instead of timing-dependent: _stop set
# first, exactly as Monitor.shutdown() would already have done before a
# trace still in flight could reach record_trace.
old_stderr = sys.stderr
sys.stderr = captured = io.StringIO()
service3.monitor._stop.set()
try:
    service3.monitor._run_one(target_id)
finally:
    sys.stderr = old_stderr
    service3.monitor._stop.clear()

check("a trace that hits a closed database DURING a stop prints no traceback",
     "Traceback" not in captured.getvalue(), captured.getvalue())
last_message = service3.log.all()[-1].message if service3.log.all() else ""
check("...and says so plainly in the event log instead of staying silent",
     "scheduler stopped" in last_message, last_message)

# 3b. The same exception NOT during a stop is still a real bug (some other
# thread closed the database out from under a scheduler that was not told
# to stop, which is its own problem worth knowing about) and must still get
# the loud treatment -- the guard is scoped to "we asked for this", not to
# every closed-database error, or a real one would go silent too.
sys.stderr = captured2 = io.StringIO()
try:
    service3.monitor._run_one(target_id)   # _stop is clear again here
finally:
    sys.stderr = old_stderr

check("the same error NOT during a stop still prints -- the guard did not "
     "swallow more than the one case it exists for",
     "Traceback" in captured2.getvalue())

service3.db.record_trace = real_record_trace

# 3c. End to end, through the real scheduler thread and a real (slowed)
# trace: shutdown()'s drain window is sized to the in-flight target's own
# settings (expected_budget), not a flat guess, so a trace that is merely
# slow -- not hung -- gets to finish and be recorded rather than losing its
# result to a drain window that gave up too early.
trace_started = threading.Event()


def slow_run_trace(host, **kwargs):
    trace_started.set()
    time.sleep(1.5)
    return TraceResult(host=host, dest_ip=host, hops=[], reached=True,
                       started_ts=time.time(), duration_s=1.5)


monitor_mod.run_trace = slow_run_trace
service3.monitor.start()
try:
    service3.monitor.trace_now(target_id)
    check("the (slowed) trace actually started before shutdown was asked for",
         trace_started.wait(timeout=5.0))
    sys.stderr = captured3 = io.StringIO()
    t0 = time.time()
    service3.shutdown()
    elapsed = time.time() - t0
    sys.stderr = old_stderr
finally:
    monitor_mod.run_trace = real_run_trace

check("shutdown() waited for the slow-but-not-hung trace rather than "
     "cutting it off at a flat few seconds", elapsed >= 1.5, elapsed)
check("shutdown() still returned in a bounded time, not an unlimited wait",
     elapsed < 20.0, elapsed)
check("...and printed no traceback while doing it",
     "Traceback" not in captured3.getvalue(), captured3.getvalue())

shutil.rmtree(os.path.join(TMPDIR, "t3"), ignore_errors=True)

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
