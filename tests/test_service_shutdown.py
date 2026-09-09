"""`Service.shutdown()` must not close the databases while a maintenance
sweep is still running: `run_maintenance` runs on the maintenance thread
every minute and, forced, when a settings save asks for one.
`shutdown()` joins the timer thread and holds a lock around the
stop/close sequence so a sweep in flight cannot touch a closed database.
This suite drives both from plain threads, without starting the timer."""
import io
import os
import shutil
import sqlite3
import sys
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.syslogdb import SyslogDatabase
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
# not depend on this host actually having a working tracert/traceroute.
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

# 3d. A different race in the same function, found as a byproduct of
# testing 3a/3b rather than reported: an operator deleting a NetPath target
# while it happens to be mid-trace is an ordinary action, not a bug, and
# record_trace's INSERT hitting a foreign key that no longer resolves used
# to reach the same "must never die quietly" handler as a genuine crash.
# Simulated deterministically by having the (stubbed) trace delete its own
# target as a side effect before returning, rather than racing two real
# threads against the clock.
def delete_then_return(host, **kwargs):
    service3.db.remove_target(target_id)
    return TraceResult(host=host, dest_ip=host, hops=[], reached=True,
                       started_ts=time.time(), duration_s=0.0)


monitor_mod.run_trace = delete_then_return
sys.stderr = captured_del = io.StringIO()
try:
    service3.monitor._run_one(target_id)
finally:
    sys.stderr = old_stderr
    monitor_mod.run_trace = instant_run_trace

check("a target deleted mid-trace prints no traceback",
     "Traceback" not in captured_del.getvalue(), captured_del.getvalue())
last_message = service3.log.all()[-1].message if service3.log.all() else ""
check("...and says so plainly in the event log instead",
     "deleted while its trace was running" in last_message, last_message)

# Put the target back for 3c, which needs one that still exists.
target_id = service3.db.add_target("10.0.0.9", max_hops=2, probes=1, timeout_s=1.0)

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


# --------------------------------------- 4. the node poller, same bug class
# Same shape as section 3, in NodePoller (netpath/nodepoll.py) rather than
# the trace scheduler. NodePoller.stop() alone never waited for a poll
# already running to finish, and tests/test_web_gates.py's own finally
# block used to paper over exactly this by polling worker_state() for up
# to 20 seconds before ever calling service.shutdown() -- a workaround at
# the test level for a bug at the source, now removed from that file since
# shutdown() does the waiting itself.
service4 = new_service("t4")
device_id = service4.nodes_db.add_device("10.0.0.9")
real_poll_device = service4.node_poller._poll_device


def closed_db_poll_device(device, config):
    raise sqlite3.ProgrammingError("Cannot operate on a closed database.")


service4.node_poller._poll_device = closed_db_poll_device

# 4a. Forced directly, same technique as 3a: _stop set first, exactly as
# NodePoller.shutdown() would already have done before a poll still in
# flight could reach a write.
sys.stderr = captured4 = io.StringIO()
service4.node_poller._stop.set()
try:
    service4.node_poller._run_one(device_id)
finally:
    sys.stderr = old_stderr
    service4.node_poller._stop.clear()

check("a poll that hits a closed database DURING a stop prints no traceback",
     "Traceback" not in captured4.getvalue(), captured4.getvalue())
last_message = service4.log.all()[-1].message if service4.log.all() else ""
check("...and says so plainly in the event log instead of staying silent",
     "poller stopped" in last_message, last_message)

# 4b. The same exception NOT during a stop is still a real bug.
sys.stderr = captured5 = io.StringIO()
try:
    service4.node_poller._run_one(device_id)   # _stop is clear again here
finally:
    sys.stderr = old_stderr

check("the same error NOT during a stop still prints for the node poller too",
     "Traceback" in captured5.getvalue())

service4.node_poller._poll_device = real_poll_device

# 4c. A device deleted mid-poll, same technique as 3d: the stubbed poll
# deletes its own device as a side effect before raising the foreign-key
# error that would really follow, rather than racing two real threads.
def delete_then_poll(device, config):
    service4.nodes_db.remove_device(device["id"])
    raise sqlite3.IntegrityError("FOREIGN KEY constraint failed")


service4.node_poller._poll_device = delete_then_poll
sys.stderr = captured6 = io.StringIO()
try:
    service4.node_poller._run_one(device_id)
finally:
    sys.stderr = old_stderr
    service4.node_poller._poll_device = real_poll_device

check("a device deleted mid-poll prints no traceback",
     "Traceback" not in captured6.getvalue(), captured6.getvalue())
last_message = service4.log.all()[-1].message if service4.log.all() else ""
check("...and says so plainly in the event log instead",
     "deleted while its poll was running" in last_message, last_message)

service4.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t4"), ignore_errors=True)


# --------------------------------------- 5. the syslog index backfill, a
# --------------------------------------- different kind of bug in the same family
# Sections 1-4 are all "closing a database under work still in flight raises
# a traceback that reads like a crash". This one, found while auditing
# Service.start()/shutdown() for the same asymmetry, is quieter and worse:
# SyslogDatabase.start_index_backfill() (netpath/syslogdb.py) span a thread
# whose local handle was discarded immediately, so nothing could ever wait
# for it, and its own `except sqlite3.Error` already caught a closed-
# database mid-backfill silently -- no traceback, but `finally` still
# unconditionally marked the index complete and disabled full-text search
# outright, regardless of whether the backfill had actually finished or was
# only cut short. An operator restarting during a large backfill (exactly
# when a big backlog means one is most likely running) got syslog search
# silently downgraded to table-scanning for the rest of that run, with no
# message anywhere, self-correcting only because self.fts is redetermined
# fresh on the next restart -- except the backfill never got a chance to
# resume either, since the schema already looked current by then.
TMPDIR5 = os.path.join(TMPDIR, "t5")
os.makedirs(TMPDIR5, exist_ok=True)
SYSLOG5 = os.path.join(TMPDIR5, "syslog.db")


class _LogSpy:
    """A minimal stand-in for EventLog: keeps every entry's message text so
    a check below can read exactly what was logged, without a whole
    Service's much larger log to search through."""

    def __init__(self):
        self.entries = []

    def add(self, category, message, target="", detail=""):
        self.entries.append(message)


class _Entry:
    def __init__(self, i):
        self.source = f"10.0.0.{i % 5}"
        self.host = self.source
        self.facility = 1
        self.severity = 6
        self.app = "test"
        self.procid = ""
        self.msgid = ""
        self.message = f"hello world message number {i}"
        self.raw = self.message
        self.ts = time.time()


N_MESSAGES = 500
log5a = _LogSpy()
syslog5a = SyslogDatabase(SYSLOG5, log=log5a)
syslog5a.insert([_Entry(i) for i in range(N_MESSAGES)])
syslog5a.close()

# Force an old-shape index (as an upgrade from before the trigram tokenizer
# would find on disk), so the next open decides a backfill is needed.
_conn = sqlite3.connect(SYSLOG5)
_conn.execute("DROP TABLE IF EXISTS logs_fts")
_conn.execute("CREATE VIRTUAL TABLE logs_fts USING fts5(message, app, host,"
             " content='logs', content_rowid='id', tokenize='unicode61')")
_conn.commit()
_conn.close()

log5b = _LogSpy()
syslog5b = SyslogDatabase(SYSLOG5, log=log5b)
check("the old-shaped index is recognised as needing a backfill",
     syslog5b._backfill_wanted)
syslog5b.BACKFILL_CHUNK = 50   # small enough to interrupt deterministically
syslog5b.start_index_backfill()
check("the backfill actually started", syslog5b._backfill_thread is not None)
time.sleep(0.05)   # let it land a couple of chunks
syslog5b.close()    # simulate shutdown mid-backfill

check("closing mid-backfill did not mark the index falsely complete",
     syslog5b.index_ready is False)
check("...and did not disable full-text search either",
     syslog5b.fts is True)
check("...and said so in the event log rather than nowhere",
     any("paused for shutdown" in m for m in log5b.entries), log5b.entries)

_conn = sqlite3.connect(SYSLOG5)
_conn.row_factory = sqlite3.Row
_row = _conn.execute(
    "SELECT value FROM settings WHERE key = '_fts_backfill_cursor'").fetchone()
_conn.close()
resume_cursor = int(_row["value"]) if _row else None
check("a resume point was persisted, partway through, not at the start or the end",
     resume_cursor is not None and 0 < resume_cursor < N_MESSAGES, resume_cursor)

log5c = _LogSpy()
syslog5c = SyslogDatabase(SYSLOG5, log=log5c)
check("reopening re-arms the backfill from the persisted point rather than "
     "believing the (already-created) table means it is done",
     syslog5c._backfill_wanted and syslog5c._backfill_start_cursor == resume_cursor,
     (syslog5c._backfill_wanted, syslog5c._backfill_start_cursor, resume_cursor))
syslog5c.start_index_backfill()
_deadline = time.time() + 10
while time.time() < _deadline and not syslog5c.index_ready:
    time.sleep(0.05)
check("the resumed backfill runs to completion", syslog5c.index_ready)
check("...without having disabled search along the way", syslog5c.fts)

_conn = sqlite3.connect(SYSLOG5)
_conn.row_factory = sqlite3.Row
_cleared = _conn.execute(
    "SELECT value FROM settings WHERE key = '_fts_backfill_cursor'").fetchone()
_indexed = _conn.execute("SELECT COUNT(*) AS n FROM logs_fts").fetchone()["n"]
_conn.close()
check("the resume marker is cleared once the backfill genuinely finishes",
     _cleared is None, _cleared)
check("every message landed in the index exactly once -- resuming from a "
     "persisted cursor neither skipped rows nor re-indexed them",
     _indexed == N_MESSAGES, _indexed)
syslog5c.close()

# A genuine failure (not a stop) still disables search and says so -- the
# guard above must not have gone the other way and swallowed a real one.
log5d = _LogSpy()
syslog5d = SyslogDatabase(SYSLOG5, log=log5d)
syslog5d._conn.execute("DROP TABLE logs_fts")   # the table _backfill expects
syslog5d._conn.commit()
syslog5d._backfill_stop.clear()
syslog5d._backfill(0, N_MESSAGES, N_MESSAGES)
check("a genuine (non-shutdown) failure still disables full-text search",
     syslog5d.fts is False)
check("...and still says so in the event log",
     any("Full-text search unavailable" in m for m in log5d.entries), log5d.entries)
syslog5d.close()

shutil.rmtree(TMPDIR5, ignore_errors=True)

# ---------------------------------------------- 6. shutdown is BOUNDED
#
# The regression this section exists for: Service.shutdown() used to ask each
# subsystem to stop and then wait for it, one after another, so about twenty
# independent timeouts summed. selfupdate.py's own module comment records the
# result -- "the before-restart hook alone measures 37-63s against a real
# fleet" -- and the console ran that on the Qt GUI thread, so Windows ghosted
# the window and operators ended the task. Nothing asserted the wall clock,
# which is why it could drift that far.
#
# Every wedge below is one that really happened: a maintenance sweep holding
# the lock shutdown() acquires, workers that never finish stopping, and a
# store lock held by a request thread that outlived WebServer.stop().

from netpath.web.service import SHUTDOWN_DB_GRACE_S, SHUTDOWN_DEADLINE_S  # noqa: E402


class Wedged:
    """A worker that is asked to stop and then never finishes. Records when
    each half was called, so the test can tell "signalled everything, then
    waited once" from "signalled and waited, one at a time"."""

    def __init__(self, name, phases):
        self.name = name
        self.phases = phases
        self.running = True

    def begin_stop(self):
        self.phases.append((self.name, "begin", time.monotonic()))

    def finish_stop(self, deadline):
        self.phases.append((self.name, "finish", time.monotonic()))
        # Burn the whole budget, the way a poll against unresponsive gear does.
        while time.monotonic() < deadline:
            time.sleep(0.02)


service6 = new_service("t6")
phases6 = []
WEDGED = ("ssh_sessions", "web_relays", "monitor", "hop_prober", "resolver",
         "asn_resolver", "collector", "syslog", "snmp", "ipam",
         "alert_engine", "node_poller", "wireless", "configrx")
for _name in WEDGED:
    setattr(service6, _name, Wedged(_name, phases6))

# A sweep in flight, holding the lock shutdown() has to take. Untimed, this
# alone was an unbounded wait however long the sweep ran.
service6._maintenance_lock.acquire()

# A request thread still mid-query when the databases close. The web server's
# handler threads are daemons and survive WebServer.stop(), so this is the
# real shape, not a contrived one.
_held = threading.Event()
_release6 = threading.Event()


def _hold_store_lock():
    with service6.db._lock:
        _held.set()
        _release6.wait(60)


threading.Thread(target=_hold_store_lock, daemon=True).start()
_held.wait(5)

_t0 = time.monotonic()
service6.shutdown()
_elapsed = time.monotonic() - _t0

# Generous slack: this asserts "bounded", not "fast". The old code took
# 37-63s on a real fleet and had no ceiling at all.
_ceiling = SHUTDOWN_DEADLINE_S + SHUTDOWN_DB_GRACE_S + 5.0
check("shutdown finishes inside its budget even with every worker wedged, "
     "the maintenance lock held and a store lock held by a live query",
     _elapsed < _ceiling, f"took {_elapsed:.1f}s, ceiling {_ceiling:.1f}s")

# The property that makes the budget shared rather than summed. If a future
# change puts a wait back inside the signalling loop, this is what catches it.
_begins = [t for _n, phase, t in phases6 if phase == "begin"]
_finishes = [t for _n, phase, t in phases6 if phase == "finish"]
check("every worker was asked to stop before any of them was waited for",
     _begins and _finishes and max(_begins) < min(_finishes),
     f"last begin {max(_begins) - _t0:.2f}s, first finish "
     f"{min(_finishes) - _t0:.2f}s" if _begins and _finishes else str(phases6))

# The ordering the comments in shutdown() call out, as an ordering of waits.
_order = [n for n, phase, _t in phases6 if phase == "finish"]
check("alerts stops waiting before the Nodes poller does (it reads Nodes' "
     "own data, so the reader must go quiet before the writer)",
     _order.index("alert_engine") < _order.index("node_poller"), _order)
check("the sessions and relays are waited out first, while the databases "
     "they write their closing events to are still open",
     _order.index("ssh_sessions") < 2 and _order.index("web_relays") < 2, _order)

check("...and the databases closed anyway rather than waiting on the query",
     service6.db._closed)
_release6.set()

# Idempotent: the self-update's before-restart hook and the console's own
# teardown both call this, and on the update path both do.
_t1 = time.monotonic()
service6.shutdown()
check("a second shutdown() is a fast no-op, not a second teardown",
     time.monotonic() - _t1 < 0.5, f"{time.monotonic() - _t1:.2f}s")

# And the healthy case is quick, not merely bounded: nothing is wedged here,
# so nothing should be waited out.
service6b = new_service("t6b")
_t2 = time.monotonic()
service6b.shutdown()
_idle_elapsed = time.monotonic() - _t2
check("an idle service shuts down promptly rather than sitting out its budget",
     _idle_elapsed < 5.0, f"took {_idle_elapsed:.1f}s")


# ------------- 6b. the second signal must not discard the first one's work
#
# shutdown() signals every subsystem, waits out any restart still queued, and
# then signals again -- the second pass is what stops a deferred restart from
# bringing a worker back up after the first. That makes begin_stop() have to
# be idempotent, and the session registries are the two that are not
# idempotent for free: each spawns a stopper thread per live session and hands
# them to finish_stop(). A second pass that re-snapshotted the sessions would
# replace those threads, and finish_stop() would then wait for nothing.

from netpath.webrelay import WebRelayRegistry  # noqa: E402


class _SlowSession:
    device_id = 1

    def __init__(self):
        self.stopped = threading.Event()

    def stop(self, reason=""):
        time.sleep(0.6)
        self.stopped.set()


registry = WebRelayRegistry(None)   # nothing here reaches the service
session = _SlowSession()
registry._sessions["s1"] = session
registry.begin_stop()
registry.begin_stop()          # the second pass shutdown() always makes
check("a repeated begin_stop keeps the stopper threads the first one started",
     len(registry._stoppers) == 1, str(len(registry._stoppers)))
registry.finish_stop(time.monotonic() + 5.0)
check("...so finish_stop actually waits for the sessions to close",
     session.stopped.is_set())


# ------------------------------------- 7. a store lock cannot hang close()
service7 = new_service("t7")
_held7 = threading.Event()
_release7 = threading.Event()


def _hold7():
    with service7.flow_db._lock:
        _held7.set()
        _release7.wait(30)


threading.Thread(target=_hold7, daemon=True).start()
_held7.wait(5)
_t3 = time.monotonic()
service7.flow_db.close(timeout_s=0.2)
_close_elapsed = time.monotonic() - _t3
check("close() gives up on the store lock rather than waiting for it",
     _close_elapsed < 1.5, f"took {_close_elapsed:.2f}s")
try:
    service7.flow_db._conn.execute("SELECT 1")
    _closed_for_real = False
except sqlite3.ProgrammingError:
    _closed_for_real = True
check("...and the connection really is closed, not merely marked so",
     _closed_for_real)
_release7.set()
service7.shutdown()


shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
