"""The debug event log's cursor, its capacity, and the restart boundary.

The reported defect was "the Debug event log seems to randomly clear". It
never cleared: `_seq` restarts at 0 in a new process, so a page still asking
for `since=<a large seq from the previous process>` was handed nothing for
hours, and the operator's next reload showed an almost empty log. Two
smaller faults sat behind it -- the batch and the cursor were read under
separate lock holds, so an event appended between them was delivered to
nobody, and a 3,000-event ring is minutes of history on a large fleet.

First half is the log on its own; second half drives a real Service and
WebServer over loopback (the harness `test_alerts_api.py` uses).
"""
import http.client
import json
import os
import shutil
import sys
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import eventlog
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# =========================================================== 1. the log alone

check("the default ring is 10,000 events, not 3,000",
      eventlog.DEFAULT_CAPACITY == 10000, str(eventlog.DEFAULT_CAPACITY))
log = eventlog.EventLog()
check("a log built with no capacity argument takes that default",
      log.capacity == 10000, str(log.capacity))
check("an EventLog stamps an epoch identifying this process's log",
      isinstance(log.epoch, float) and log.epoch > 0, str(log.epoch))

# --------------------------------------------- the batch and its cursor agree
# The old code read since() and last_seq under separate lock holds: an event
# appended between the two was missing from the batch AND behind the cursor
# the caller was handed, so the next poll (asking for > that cursor) skipped
# it for good. A writer thread hammering add() makes that window wide.
stop = threading.Event()
busy = eventlog.EventLog()


def hammer():
    while not stop.is_set():
        busy.add(eventlog.TRACE, "tick", target="10.0.0.1")


writer = threading.Thread(target=hammer, daemon=True)
writer.start()
try:
    torn = 0
    empty_batches = 0
    cursor = 0
    deadline = time.time() + 2.0
    reads = 0
    while time.time() < deadline:
        events, last_seq = busy.since_with_seq(cursor)
        reads += 1
        if not events:
            empty_batches += 1
        else:
            if last_seq != max(e.seq for e in events):
                torn += 1
            cursor = last_seq
    check("since_with_seq hands back the cursor of the SAME snapshot under a "
          "concurrent writer (no event falls between the batch and the seq)",
          torn == 0 and reads > 50, f"{torn} torn reads of {reads}")
    check("...and the cursor never ran ahead of what was delivered",
          cursor <= busy.last_seq, f"{cursor} vs {busy.last_seq}")
    check("...with the writer actually producing work to race with",
          empty_batches < reads, f"{empty_batches} empty of {reads}")
finally:
    stop.set()
    writer.join(timeout=5)

# ------------------------------------------------------------- set_capacity
ring = eventlog.EventLog(capacity=100)
for i in range(50):
    ring.add(eventlog.SYSTEM, f"event {i}")
ring.set_capacity(10)
kept = ring.all()
check("shrinking the capacity keeps the NEWEST events",
      ring.capacity == 10 and len(kept) == 10
      and kept[0].message == "event 40" and kept[-1].message == "event 49",
      f"{ring.capacity} {[e.message for e in kept][:3]}")
ring.set_capacity(200)
check("growing it keeps everything already held",
      ring.capacity == 200 and len(ring.all()) == 10, str(len(ring.all())))
for i in range(100):
    ring.add(eventlog.SYSTEM, f"more {i}")
check("...and then genuinely grows past the old ceiling",
      len(ring.all()) == 110, str(len(ring.all())))

before = ring.all()
ring.set_capacity(200)
check("setting the capacity it already has is a no-op",
      [e.seq for e in ring.all()] == [e.seq for e in before])
ring.set_capacity(0)
check("a capacity of 0 is floored at 1 rather than making a log that "
      "cannot hold anything", ring.capacity == 1, str(ring.capacity))
ring.set_capacity("25")
check("a capacity arriving as a string is coerced", ring.capacity == 25,
      str(ring.capacity))

check("capacity reports the deque's own maxlen",
      eventlog.EventLog(capacity=4321).capacity == 4321)

# -------------------------------------------------------------------- NullLog
null = eventlog.NullLog()
check("NullLog answers since_with_seq", null.since_with_seq(17) == ([], 0),
      str(null.since_with_seq(17)))
check("NullLog answers set_capacity without raising",
      null.set_capacity(5000) is None)
check("NullLog reports capacity 0 and epoch 0.0",
      null.capacity == 0 and null.epoch == 0.0,
      f"{null.capacity} {null.epoch}")


# ============================================== 2. the service and the wire

TMPDIR = _paths.tmpdir("debug_log_cursor_")

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path,
                 body=json.dumps(body).encode() if body is not None else None,
                 headers=headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    try:
        return response.status, json.loads(raw)
    except ValueError:
        return response.status, raw


def login(username, password):
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    conn.request("POST", "/api/login",
                 body=json.dumps({"username": username,
                                  "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


try:
    first = service.log.all()[0]
    check("a fresh Service writes 'Event log started' as its very first event "
          "— the boundary that tells a restart apart from a cleared log",
          first.message == "Event log started"
          and first.category == eventlog.SYSTEM and first.seq == 1,
          f"{first.seq} {first.category} {first.message!r}")
    check("the service's log takes its capacity from the settings default",
          service.log.capacity == 10000, str(service.log.capacity))

    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # --------------------------------------- the setting's range, over HTTP
    status, payload = call("POST", "/api/settings",
                           {"scope": "global",
                            "values": {"debug_log_capacity": 500}},
                           token=admin)
    check("debug_log_capacity below its floor (500) -> 400", status == 400,
          f"{status} {payload}")
    status, payload = call("POST", "/api/settings",
                           {"scope": "global",
                            "values": {"debug_log_capacity": 60000}},
                           token=admin)
    check("debug_log_capacity above its ceiling (60000) -> 400", status == 400,
          f"{status} {payload}")
    check("neither refusal touched the live log",
          service.log.capacity == 10000, str(service.log.capacity))

    status, payload = call("POST", "/api/settings",
                           {"scope": "global",
                            "values": {"debug_log_capacity": 20000}},
                           token=admin)
    check("debug_log_capacity in range (20000) -> 200", status == 200,
          f"{status} {payload}")
    check("...and it resizes the running log, no restart needed",
          service.log.capacity == 20000, str(service.log.capacity))

    # ----------------------------------------------- what /api/debug carries
    service.log.add(eventlog.TRACE, "traced", target="router-a")
    service.log.add(eventlog.DNS, "resolved", target="192.0.2.9")

    status, payload = call("GET", "/api/debug?since=0", token=admin)
    check("GET /api/debug answers", status == 200, f"{status} {payload}")
    body = payload if status == 200 else {}
    check("...carrying last_seq", isinstance(body.get("last_seq"), int)
          and body["last_seq"] >= 3, str(body.get("last_seq")))
    check("...carrying log_epoch, so the page can tell one process's log "
          "from the next", body.get("log_epoch") == service.log.epoch,
          str(body.get("log_epoch")))
    check("...carrying capacity, so the page trims to what the server keeps",
          body.get("capacity") == 20000, str(body.get("capacity")))
    check("since=0 carries the log's FULL target list, not just the targets "
          "this batch happens to mention",
          body.get("targets") == service.log.targets(),
          f"{body.get('targets')} vs {service.log.targets()}")

    cursor = body["last_seq"]
    status, payload = call("GET", f"/api/debug?since={cursor}", token=admin)
    check("a delta poll returns no events and the same cursor",
          status == 200 and payload["events"] == []
          and payload["last_seq"] == cursor,
          f"{status} {payload.get('last_seq')}")
    check("...and its targets stay the delta-derived list (empty here), so an "
          "idle poll does not resend every target every second",
          payload.get("targets") == [], str(payload.get("targets")))

    service.log.add(eventlog.TRACE, "traced again", target="router-b")
    status, payload = call("GET", f"/api/debug?since={cursor}", token=admin)
    check("the next poll after that cursor delivers exactly the new event",
          status == 200 and [e["message"] for e in payload["events"]]
          == ["traced again"], str(payload.get("events")))
    check("...and its cursor advances", payload["last_seq"] == cursor + 1,
          f"{payload['last_seq']} vs {cursor + 1}")

    # A cursor from a previous process: the seq is far past anything this log
    # will reach, and the answer's last_seq being BELOW it is exactly what
    # debug.js keys the resync off.
    status, payload = call("GET", "/api/debug?since=9999999", token=admin)
    check("a cursor left over from an older process reads back a last_seq "
          "below it — the signal debug.js resyncs on",
          status == 200 and payload["last_seq"] < 9999999,
          str(payload.get("last_seq")))

    # ------------------------------- get_debug assembles per-section helpers
    # Each section is its own `_debug_<section>` function now; the response
    # must still carry every one of them, and a section whose module is not
    # granted must still come back empty rather than as a refusal.
    from netpath.web import api as api_mod

    status, payload = call("GET", "/api/debug?since=0", token=admin)
    expected = {"workers", "dns_workers", "ipam_workers", "node_workers",
                "node_counters", "discovery_scans", "events", "last_seq",
                "log_epoch", "capacity", "targets", "store_locks", "routes",
                "summary"}
    check("the assembled /api/debug response still carries every section",
          status == 200 and expected <= set(payload), sorted(expected - set(payload or {})))
    check("...and its summary still carries the header counters",
          {"scheduler", "workers_busy", "queued", "dns_pending", "ping_path"}
          <= set(payload.get("summary") or {}), sorted(payload.get("summary") or {}))

    empty = {"debug": "read"}
    check("_debug_netpath_workers is empty without `netpath` read",
          api_mod._debug_netpath_workers(service, {}, empty, time.time())
          == ([], 0, 0))
    check("...and the dns, ipam, nodes and discovery sections likewise",
          all(helper(service, {}, empty, time.time()) == []
              for helper in (api_mod._debug_dns_workers,
                             api_mod._debug_ipam_workers,
                             api_mod._debug_node_workers,
                             api_mod._debug_discovery_scans)))
    events, last_seq = api_mod._debug_events(service, {}, empty, 0)
    check("...and the event stream is filtered to nothing, cursor intact",
          events == [] and last_seq == service.log.last_seq,
          f"{len(events)} {last_seq}")
finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
