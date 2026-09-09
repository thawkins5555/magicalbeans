"""A settings save must not restart a collector on the HTTP thread.

`_restart` stops a worker and starts it again, and `Worker._join` waits up to
two seconds per worker thread — syslogd.stop() waits that long again for each
connected TCP client on top. Run inline from apply_settings, as it used to be,
a syslog save with a couple of devices holding TCP sessions open held the HTTP
response open for over four seconds.

apply_settings now persists, logs and bumps the config version on the request
thread — so the 200 is still truthful about what was stored — and hands the
restart to the single-threaded serial executor Service owns.

Nothing here decides pass or fail on a sleep. The restart is gated on an Event
the test holds shut, so "the response did not wait for the join" is a fact
about a join that provably had not finished, not about a chosen interval; and
"the worker came back" is read after await_restarts, not after a nap.

Style of test_settings_types.py: a real Service + WebServer on a free loopback
port, over a throwaway directory, driven with plain HTTP.
"""
import http.client
import json
import os
import shutil
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("settings_restart_async_")

from netpath.eventlog import ERROR  # noqa: E402
from netpath.web.server import WebServer  # noqa: E402
from netpath.web.service import Service  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def req(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    try:
        conn.request(method, path,
                     json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        data = response.read()
        head = {k.lower(): v for k, v in response.getheaders()}
        try:
            return response.status, head, json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return response.status, head, data
    finally:
        conn.close()


def admin_cookie(port):
    """Log in, clear must_change (the settings API is unreachable until it is
    cleared), and log in again for the session the checks use."""
    _s, head, _p = req(port, "POST", "/api/login",
                       {"username": "admin", "password": "admin"})
    cookie = head.get("set-cookie", "").split(";")[0]
    password = "correct horse battery staple 15"
    req(port, "POST", "/api/password",
        {"current_password": "admin", "new_password": password}, cookie=cookie)
    _s, head, _p = req(port, "POST", "/api/login",
                       {"username": "admin", "password": password})
    return head.get("set-cookie", "").split(";")[0]


def save_syslog(port, cookie, values):
    """POST one syslog settings save and return (status, seconds)."""
    started = time.perf_counter()
    status, _h, payload = req(port, "POST", "/api/settings",
                              {"scope": "syslog", "values": values},
                              cookie=cookie)
    return status, time.perf_counter() - started, payload


class GatedStop:
    """service.syslog.stop, held on a gate the test opens.

    `after=False` holds the restart *before* the real stop, which is what
    makes the latency check below decisive rather than a threshold: with the
    gate shut, an inline restart could not return at all, so a POST that
    comes back in milliseconds proves the restart is somewhere else.

    `after=True` holds it *after* the real stop, parking the worker in the
    down half of the transition for as long as the test wants to look at it.
    """

    def __init__(self, worker, after=False):
        self.worker = worker
        self.real = worker.stop
        self.after = after
        self.entered = threading.Event()
        self.stopped = threading.Event()
        self.gate = threading.Event()
        self.concurrent = 0
        self.max_concurrent = 0
        self.order = []
        self._lock = threading.Lock()

    def install(self):
        self.worker.stop = self

    def remove(self):
        self.gate.set()
        try:
            del self.worker.stop
        except AttributeError:  # pragma: no cover - only if never installed
            pass

    def __call__(self):
        with self._lock:
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
            self.order.append(self.worker._settings_tag())
        self.entered.set()
        try:
            if self.after:
                self.real()
                self.stopped.set()
                self.gate.wait(60)
            else:
                self.gate.wait(60)
                self.real()
                self.stopped.set()
        finally:
            with self._lock:
                self.concurrent -= 1


def main() -> int:
    data_dir = os.path.join(TMPDIR, "data")
    os.makedirs(data_dir, exist_ok=True)
    db_names = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps",
                "nodes", "alerts", "wireless", "configrx")
    service = Service(*[os.path.join(data_dir, name + ".db")
                        for name in db_names])
    # The tag the gated stop records, so the ordering check can say which
    # save's restart ran without reaching into the executor.
    service.syslog._settings_tag = lambda: service.syslog_settings.get(
        "max_message_chars")

    port = _paths.free_tcp_port()
    server = WebServer(service, host="127.0.0.1", port=port)
    if not server.start(block=False):
        print(f"SKIP: could not bind 127.0.0.1:{port}: {server.error}")
        return 77

    try:
        cookie = admin_cookie(port)
        check("logged in as the seeded admin", bool(cookie))

        syslog_port = _paths.free_udp_port()
        status, _elapsed, _p = save_syslog(port, cookie, {
            "enabled": True, "accept_udp": True, "accept_tcp": False,
            "port": syslog_port, "max_message_chars": 2048})
        check("enabling the syslog collector is accepted", status == 200)
        check("await_restarts reports the enable finished",
              service.await_restarts(30.0))
        check("the collector is up after await_restarts", service.syslog.running,
              service.syslog.status_text())

        # ----------------------------------------------- (a) the save returns
        # The restart is wedged inside stop() for as long as the gate is shut.
        # If apply_settings still ran it inline, the POST below could not
        # return at all until the gate opened -- which it does not, until
        # after every check in this section.
        gate = GatedStop(service.syslog)
        gate.install()
        version_before = service.config_version
        status, elapsed, payload = save_syslog(port, cookie,
                                               {"max_message_chars": 3000})
        check("the save is accepted", status == 200, f"{status} {payload}")
        check("the response does not wait for the join", elapsed < 2.0,
              f"{elapsed * 1000:.0f} ms")
        # Counted on the request thread, before apply_settings returns, so
        # this is not a race: a restart was outstanding at the moment the
        # response went out.
        check("a restart was still outstanding when the response landed",
              service.await_restarts(0.0) is False)

        # What the 200 answered for happened synchronously.
        check("the new value is already stored",
              service.syslog_db.settings()["max_message_chars"] == 3000)
        check("the returned settings carry the new value",
              isinstance(payload, dict)
              and payload.get("syslog_settings", {}).get("max_message_chars")
              == 3000)
        check("config_version was bumped before the response",
              service.config_version == version_before + 1)
        check("the event log already carries the applied line",
              any(event.message == "Syslog settings applied"
                  for event in service.log.all()))
        check("the restart really did reach stop()", gate.entered.wait(10))

        # ------------------------------------------- (b) await_restarts waits
        gate.remove()
        check("await_restarts observes the worker back up",
              service.await_restarts(30.0) and service.syslog.running,
              service.syslog.status_text())

        # ------------------------------- (b2) /api/state carries the transition
        # No frontend work is owed by this change because the poll every page
        # already makes reports both halves of it. Held in the down half on
        # purpose, so this reads a state that exists rather than one a sleep
        # happened to catch.
        gate = GatedStop(service.syslog, after=True)
        gate.install()
        status, _elapsed, _p = save_syslog(port, cookie,
                                           {"max_message_chars": 3050})
        check("the mid-transition save is accepted", status == 200)
        check("the restart got past the real stop", gate.stopped.wait(30))
        _s, _h, state = req(port, "GET", "/api/state", cookie=cookie)
        check("/api/state reports the syslog worker's running flag and status",
              isinstance(state, dict) and "running" in state.get("syslog", {})
              and "status" in state.get("syslog", {}))
        check("/api/state shows the worker down mid-restart",
              state["syslog"]["running"] is False, str(state.get("syslog")))
        check("status_text says so too",
              state["syslog"]["status"] == f"{service.syslog.NOUN} stopped",
              str(state["syslog"]["status"]))
        gate.remove()
        check("the restart finishes once the gate opens",
              service.await_restarts(30.0))
        _s, _h, state = req(port, "GET", "/api/state", cookie=cookie)
        check("/api/state shows it up again once the restart finished",
              state["syslog"]["running"] is True, str(state.get("syslog")))

        # ------------------------------------ (c) serial, and in the order asked
        # Two saves queued back to back. One thread means the second restart
        # cannot begin until the first has finished its stop and start, so a
        # save can never land between another save's stop() and its start()
        # and leave the collector down with settings that say it is up.
        gate = GatedStop(service.syslog)
        gate.gate.set()          # not held shut here; only counted
        gate.install()
        for value in (3100, 3200):
            status, elapsed, _p = save_syslog(port, cookie,
                                              {"max_message_chars": value})
            check(f"save of max_message_chars={value} is accepted", status == 200)
            check(f"save of max_message_chars={value} returns promptly",
                  elapsed < 2.0, f"{elapsed * 1000:.0f} ms")
        check("both restarts finish", service.await_restarts(60.0))
        check("restarts never overlap", gate.max_concurrent == 1,
              f"max_concurrent={gate.max_concurrent}")
        # More entries than saves: SyslogCollector.start() calls stop() itself
        # before it binds, so one restart passes through here twice. What is
        # being checked is that they never interleave (above) and that the
        # last word belongs to the last save (below) -- a queued restart reads
        # the module's live settings dict, so it brings the collector up on
        # what is stored now rather than on what was stored when it was queued.
        check("every queued restart ran", len(gate.order) >= 2, str(gate.order))
        check("the last restart used the newest stored settings",
              gate.order[-1] == 3200, str(gate.order))
        gate.remove()
        check("the collector is up after the pair", service.syslog.running,
              service.syslog.status_text())

        # ------------------------- (d) a failing restart does not kill the thread
        boom = {"n": 0}
        real_start = service.syslog.start

        def exploding_start(settings):
            boom["n"] += 1
            raise RuntimeError("simulated bind failure")

        service.syslog.start = exploding_start
        status, elapsed, _p = save_syslog(port, cookie,
                                          {"max_message_chars": 3300})
        check("a save whose restart will raise is still accepted", status == 200)
        check("the failing restart finishes", service.await_restarts(30.0))
        check("the failure reached start()", boom["n"] == 1)
        check("the failure is logged to the event log",
              any(event.category == ERROR
                  and "syslog settings were saved, but applying them failed"
                  in event.message
                  for event in service.log.all()),
              str([e.message for e in service.log.all()][-3:]))
        check("the stored value survived the failed restart",
              service.syslog_db.settings()["max_message_chars"] == 3300)

        del service.syslog.start
        check("start() is the real one again",
              service.syslog.start == real_start)
        status, _elapsed, _p = save_syslog(port, cookie,
                                           {"max_message_chars": 3400})
        check("a later save is still accepted", status == 200)
        check("the executor thread survived the failure and ran the next one",
              service.await_restarts(30.0) and service.syslog.running,
              service.syslog.status_text())

        # ------------------------------------------ (e) shutdown drains first
        # A restart in flight must not outlive the service: it starts a
        # collector that writes to databases shutdown() is about to close.
        server.stop()
        finished = threading.Event()
        real_stop = service.syslog.stop

        def slow_stop():
            time.sleep(0.5)
            real_stop()
            finished.set()

        service.syslog.stop = slow_stop
        service.apply_settings("syslog", {"max_message_chars": 3500})
        check("the deferred restart had not finished when shutdown began",
              not finished.is_set())
        service.shutdown()
        check("shutdown waited for the restart to finish", finished.is_set())
        check("nothing is outstanding after shutdown",
              service.await_restarts(0.0))
        server = service = None
    finally:
        if server is not None:
            try:
                server.stop()
            except Exception:
                pass
        if service is not None:
            try:
                service.shutdown()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"\n{len(FAILS)} check(s) failed: " + ", ".join(FAILS))
        code = 1
    else:
        print("\nall checks passed")
    raise SystemExit(code)
