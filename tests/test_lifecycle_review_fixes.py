"""Regression suite for four lifecycle defects found in a review of the
service's start/stop/self-update path (REVIEW-OPERATOR-4.50.md and the task
that followed it):

1. Monitor._loop (netpath/monitor.py) had no exception guard around its
   tick body, unlike every sibling scheduler in the same file. One
   transient `sqlite3.OperationalError: database is locked` -- a failure
   RUNBOOK.md documents as expected under contention -- killed the trace
   scheduler thread permanently, silently: the web UI stayed up, every
   other collector kept running, and nothing said tracing itself had
   stopped.

2. run_headless (netpath/__main__.py) caught only KeyboardInterrupt, and
   nothing in the package installed a signal.signal handler. RUNBOOK.md's
   documented stop procedure -- `systemctl stop/restart sappiwhere`,
   `nssm stop SappiWhere` -- delivers SIGTERM, whose default disposition
   kills the process outright, skipping the `finally` that releases the
   port and drains in-flight work.

3. selfupdate.apply() (netpath/selfupdate.py) called _run_before_restart()
   -- which stops the listener and shuts down every worker and database --
   and only then attempted _swap_in(). A failure there (or in the
   write_meta() calls right after a successful swap) used to return
   {"ok": False, ...} with nothing scheduled to bring the service back,
   leaving the process alive but completely inert.

4. ipam_worker.py's stop() dropped cancel_futures=True (unlike every other
   pool-owning worker's stop()), and a genuinely inert `except
   (DhcpUnavailable, Exception)` named a subclass its own superclass
   already covers.

Sections 1-3 below drive the fixed code directly (a real Monitor/Database
for section 1, the real run_headless for section 2 with only its
database/socket work swapped for lightweight fakes, and the real apply()
for section 3 with only the network boundary and the restart itself
mocked away -- following test_security_fixes.py's own pattern for that).
Section 4 is a source-level check for the two ipam_worker.py one-liners,
since neither has any lifecycle behaviour worth spinning up a worker for.

Nothing here ever lets a real restart or process exit happen: _swap_in,
schedule_restart and the actual OS restart functions are monkeypatched out
in every test that reaches anywhere near them.
"""
import inspect
import io
import os
import shutil
import signal
import sqlite3
import sys
import tarfile
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("lifecycle_review_fixes_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


class LogSpy:
    """Keeps every entry's category/message, the same minimal EventLog
    stand-in test_service_shutdown.py uses, so a check can read exactly
    what was logged without a whole Service's log to search through."""

    def __init__(self):
        self.entries = []

    def add(self, category, message, target="", detail=""):
        self.entries.append((category, message))


# =====================================================================
# 1. Monitor._loop survives a db.targets() that raises
# =====================================================================
# Before the fix, this was the entire body of the failure: the first
# transient error reading db.targets() ended the scheduler thread, and
# nothing in the process noticed. A real Database (rather than a hand-
# built duck-typed stub) is used here, with only .targets() monkeypatched
# to fail once -- the same technique test_scheduler.py already uses
# against NodesDatabase.schedule_rows for the analogous bug in NodePoller.

import netpath.monitor as monitor_mod
from netpath.db import Database
from netpath.eventlog import ERROR
from netpath.tracer import TraceResult

DIR1 = os.path.join(TMPDIR, "t1")
os.makedirs(DIR1, exist_ok=True)
db1 = Database(os.path.join(DIR1, "netpath.db"))
target_id1 = db1.add_target("10.0.0.1", interval_s=1, max_hops=1, probes=1, timeout_s=1.0)

real_targets = db1.targets
targets_calls = {"n": 0}


def flaky_targets():
    targets_calls["n"] += 1
    if targets_calls["n"] == 1:
        raise sqlite3.OperationalError("database is locked")
    return real_targets()


db1.targets = flaky_targets

real_run_trace = monitor_mod.run_trace


def instant_run_trace(host, **kwargs):
    return TraceResult(host=host, dest_ip=host, hops=[], reached=True,
                       started_ts=time.time(), duration_s=0.0)


monitor_mod.run_trace = instant_run_trace

dispatched = threading.Event()


def on_complete(tid):
    dispatched.set()


log1 = LogSpy()
mon1 = monitor_mod.Monitor(db1, workers=2, on_complete=on_complete, log=log1)
try:
    mon1.start()
    check("1. a trace was dispatched despite the first tick's db.targets() raising",
         dispatched.wait(timeout=5.0))
    check("1. the loop actually retried db.targets() after the failure "
         "rather than only ever calling it once",
         targets_calls["n"] >= 2, targets_calls["n"])
    check("1. the scheduler thread is still alive after the failure", mon1.running)
    check("1. the failure was logged rather than swallowed",
         any(cat == ERROR and "Scheduler tick failed" in msg
             for cat, msg in log1.entries), log1.entries)
    check("1. ...and counted, the same bookkeeping convention collector.py's "
         "receive loop keeps for an identical guard",
         mon1._loop_errors >= 1, mon1._loop_errors)
finally:
    mon1.shutdown()
    monitor_mod.run_trace = real_run_trace
    db1.close()
shutil.rmtree(DIR1, ignore_errors=True)


# =====================================================================
# 2. SIGTERM (and SIGINT/SIGBREAK) reach run_headless's shutdown path
# =====================================================================
# RUNBOOK.md's documented stop procedure delivers SIGTERM, whose default
# disposition used to kill the process outright -- server.stop() and
# service.shutdown() in run_headless's `finally` never ran. This drives
# the real run_headless(), with build_service() and WebServer swapped for
# lightweight fakes so the test needs no real sockets or ten SQLite files.
#
# Delivering the signal itself is the part that cannot be done the obvious
# way, and it is worth recording why: a genuinely cross-thread signal --
# one thread calls signal.raise_signal()/os.kill() while the main thread
# blocks in stop_event.wait(), the way a real `systemctl stop`/`nssm stop`
# would arrive from outside the process entirely -- was tried first and
# measured, not assumed, before writing the version below:
#   * signal.raise_signal(SIGTERM) from a background thread while the main
#     thread sat in Event.wait() never woke it inside a 5s bound on this
#     platform -- Windows has no EINTR-style interruption of a blocked C
#     wait, unlike POSIX, so the pending Python-level handler is never
#     reached until the main thread next runs bytecode on its own.
#   * os.kill(os.getpid(), signal.SIGTERM) is worse, not merely
#     ineffective: on Windows it calls TerminateProcess() directly and
#     never reaches the registered Python handler at all -- it would have
#     killed this test process outright.
# Both were confirmed with a standalone repro before this section was
# written this way, so the suite does not carry a hang or a self-kill as
# "should be fine in CI".
#
# What *is* reliable, confirmed by the same repro: signal.raise_signal()
# on the SAME thread that installed the handler runs it synchronously,
# in-line, before raise_signal() returns -- which is also exactly the
# thread real signal delivery invokes a Python handler on (CPython only
# ever runs signal handlers on the main thread). So stop_event's class is
# swapped for a subclass whose wait() raises SIGTERM against itself, on
# this thread, the first time it is called, then defers to the real
# Event.wait(). run_headless's own code is entirely unmodified and
# unaware of this: it creates threading.Event() (this subclass, while
# patched), installs its real signal.signal() handlers for real, and
# calls the real stop_event.wait() -- which now triggers the real
# installed handler for real, synchronously, before returning True. Every
# step from handler installation through the `finally` cleanup below is
# the genuine run_headless code path; only the mechanics of *when* the
# signal gets raised are arranged, in place of an external `kill` this
# process cannot portably reproduce on itself.

import netpath.__main__ as main_mod
import netpath.web as web_mod


class FakeSettings(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


class FakeService:
    def __init__(self):
        self.settings = FakeSettings({"web_host": "127.0.0.1", "web_port": 0,
                                      "web_cert": "", "web_key": ""})
        self.shutdown_calls = 0

    def save_listener_settings(self, values):
        pass

    def shutdown(self):
        self.shutdown_calls += 1


created_webservers = []


class FakeWebServer:
    def __init__(self, service, host=None, port=None, certfile=None, keyfile=None):
        self.service = service
        self.url = "http://fake.example/"
        self.error = None
        self.stop_calls = 0
        created_webservers.append(self)

    def start(self, block=False):
        return True

    def stop(self):
        self.stop_calls += 1


class SelfSignalingEvent(threading.Event):
    """threading.Event, except the first wait() call raises SIGTERM
    against this same thread before actually waiting -- see the note
    above on why that is the only reliable way to land a real signal on
    a real, unmodified run_headless() from inside this test process."""

    def wait(self, timeout=None):
        if not self.is_set():
            signal.raise_signal(signal.SIGTERM)
        return super().wait(timeout=timeout)


real_webserver_cls = web_mod.WebServer
real_build_service = main_mod.build_service
real_event_cls = threading.Event

fake_service2 = FakeService()
web_mod.WebServer = FakeWebServer
main_mod.build_service = lambda args: fake_service2
threading.Event = SelfSignalingEvent

# Signal handlers this suite installs are cleared afterwards -- otherwise
# they would outlive this test and fire against the fakes above the next
# time something in this process sent SIGTERM/SIGINT.
_installed_signals = [s for s in ("SIGTERM", "SIGINT", "SIGBREAK")
                      if getattr(signal, s, None) is not None]
_prior_handlers = {name: signal.getsignal(getattr(signal, name))
                   for name in _installed_signals}

args2 = main_mod.build_parser().parse_args(["--headless"])

try:
    rc2 = main_mod.run_headless(args2)
finally:
    threading.Event = real_event_cls
    web_mod.WebServer = real_webserver_cls
    main_mod.build_service = real_build_service
    for name in _installed_signals:
        try:
            signal.signal(getattr(signal, name), _prior_handlers[name])
        except (ValueError, OSError):
            pass

check("2. run_headless installed a SIGTERM handler and returned normally "
     "once it fired, rather than the process being killed under it",
     rc2 == 0, rc2)
check("2. ...and the finally block actually ran: service.shutdown() was called",
     fake_service2.shutdown_calls == 1, fake_service2.shutdown_calls)
check("2. ...and server.stop() too, not just the service half of the cleanup",
     len(created_webservers) == 1 and created_webservers[0].stop_calls == 1,
     [w.stop_calls for w in created_webservers])
_source = inspect.getsource(main_mod.run_headless)
check("2. the source still calls both server.stop() and service.shutdown() "
     "in the finally that follows the wait",
     "server.stop()" in _source and "service.shutdown()" in _source
     and "except KeyboardInterrupt" in _source, "")
check("2. SIGINT is installed too, not just SIGTERM (RUNBOOK's `kill` default)",
     "SIGINT" in _source, "")
check("2. SIGBREAK is considered, guarded for platforms without it "
     "(what nssm actually delivers on a Windows console stop)",
     "SIGBREAK" in _source and "getattr(signal" in _source, "")
check("2. the wait loop waits on the stop event now, not a fixed time.sleep(1)",
     "stop_event.wait()" in _source and "time.sleep(1)" not in _source, "")


# =====================================================================
# 3 & 4. selfupdate.apply(): a post-teardown failure still restarts
# =====================================================================
# Reuses test_security_fixes.py's own pattern for driving apply() offline:
# _fetch_json/_fetch_bytes stand in for the network boundary, and a real
# AppDatabase provides .meta()/.settings()/.path. _swap_in and
# schedule_restart are always mocked here -- this suite must never let a
# real restart happen.

from netpath import selfupdate
from netpath.appdb import AppDatabase
import netpath.appdb as appdb_mod


def build_tarball(root: str) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        for name, text in ((f"{root}/netpath/__init__.py", "x = 1\n"),
                           (f"{root}/netpath/web/__init__.py", "y = 1\n")):
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def new_apply_fixture(tag_dir):
    """A fresh AppDatabase with updates_enabled on, and the network
    boundary + _run_before_restart's hook reset so this section's tests
    do not depend on section 2's leftover state."""
    d = os.path.join(TMPDIR, tag_dir)
    os.makedirs(d, exist_ok=True)
    app_db = AppDatabase(os.path.join(d, "app.db"))
    app_db.save_settings({"updates_enabled": True})
    selfupdate._before_restart_hook = None
    selfupdate._before_restart_done = False
    return app_db, d


SHA = "c" * 40
TARBALL = build_tarball(f"magicalbeans-{SHA}")


def fake_json(url, timeout=10.0):
    if url.endswith("/commits/main"):
        return {"sha": SHA, "commit": {"message": "a commit"}}
    raise AssertionError(url)


def fake_bytes(url, timeout=60.0, max_bytes=0):
    if "codeload" in url:
        return TARBALL
    raise AssertionError(url)


real_fetch_json = selfupdate._fetch_json
real_fetch_bytes = selfupdate._fetch_bytes
real_swap_in = selfupdate._swap_in
real_schedule_restart = selfupdate.schedule_restart
real_write_meta = appdb_mod.write_meta

selfupdate._fetch_json = fake_json
selfupdate._fetch_bytes = fake_bytes

try:
    # ---- 3. _swap_in raising OSError after teardown still restarts -----
    app_db3, dir3 = new_apply_fixture("t3")
    restart_calls3 = []
    selfupdate.schedule_restart = lambda delay=1.5: restart_calls3.append(delay)

    def raising_swap_in(new_netpath):
        raise OSError("The process cannot access the file because it is "
                      "being used by another process")

    selfupdate._swap_in = raising_swap_in
    result3 = selfupdate.apply(app_db3)
    check("3. apply() reports the failure rather than raising "
         "(its docstring promises it never does)",
         result3.get("ok") is False, result3)
    check("3. ...but still schedules a restart instead of returning with "
         "the service torn down and nothing left to bring it back",
         len(restart_calls3) == 1, restart_calls3)
    app_db3.close()

    # ---- 4. write_meta failing does not skip schedule_restart() --------
    app_db4, dir4 = new_apply_fixture("t4")
    restart_calls4 = []
    selfupdate.schedule_restart = lambda delay=1.5: restart_calls4.append(delay)
    selfupdate._swap_in = lambda new_netpath: None   # swap "succeeds"

    def raising_write_meta(path, key, value):
        raise sqlite3.OperationalError("database is locked")

    appdb_mod.write_meta = raising_write_meta
    result4 = selfupdate.apply(app_db4)
    check("4. apply() still returns ok even though every write_meta() call failed",
         result4.get("ok") is True, result4)
    check("4. ...and does not raise out of apply() (docstring: never raises)",
         True)  # reaching this line at all proves it, given the try/except above
    check("4. ...and still schedules the restart: the markers are "
         "bookkeeping, the restart is not optional",
         len(restart_calls4) == 1, restart_calls4)
    app_db4.close()
finally:
    selfupdate._fetch_json = real_fetch_json
    selfupdate._fetch_bytes = real_fetch_bytes
    selfupdate._swap_in = real_swap_in
    selfupdate.schedule_restart = real_schedule_restart
    appdb_mod.write_meta = real_write_meta
    selfupdate._before_restart_hook = None
    selfupdate._before_restart_done = False


# =====================================================================
# 5. ipam_worker.py: cancel_futures and the inert DhcpUnavailable name
# =====================================================================
# Neither is lifecycle behaviour worth spinning a worker up for -- (a) is
# a one-word argument to a stdlib call, and (b) removes a name from an
# except tuple that was never doing anything (DhcpUnavailable is-a
# Exception; git history shows no distinct handling was ever attached to
# it). Checked at the source level, the same way test_frontend_contracts.py
# and test_time_contracts.py check invariants that runtime behaviour
# cannot distinguish from the equivalent-but-worse alternative.

IPAM_SRC = open(os.path.join(_paths.REPO_ROOT, "netpath", "ipam_worker.py"),
                encoding="utf-8").read()

check("5a. stop()'s pool.shutdown() cancels queued-but-unstarted scans "
     "(cancel_futures=True), matching every other pool-owning worker's stop()",
     "pool.shutdown(wait=False, cancel_futures=True)" in IPAM_SRC, "")
check("5b. the resize path's pool.shutdown() is left alone -- queued work "
     "on the OLD pool during a resize is meant to still finish, unlike a "
     "real stop()",
     "old_pool.shutdown(wait=False)" in IPAM_SRC
     and "old_pool.shutdown(wait=False, cancel_futures=True)" not in IPAM_SRC, "")
check("5c. the DHCP poll's except clause no longer names DhcpUnavailable "
     "redundantly alongside its own superclass Exception",
     "except (DhcpUnavailable, Exception)" not in IPAM_SRC
     and "except Exception as exc:" in IPAM_SRC, "")
check("5d. ...and the now-unused import was removed with it",
     "from .ipam_dhcp import DhcpUnavailable" not in IPAM_SRC, "")


shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
