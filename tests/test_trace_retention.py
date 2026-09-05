"""O-6x: `netpath.db`'s age-based trace retention (`trace_retention_days`) was
never actually applied by the automatic maintenance sweep.

`Service._run_maintenance_body` (netpath/web/service.py) calls `.prune(...)`
on every other database it owns -- flow_db, syslog_db, snmp_db, ipam_db,
nodes_db, alerts_db, configrx_db -- passing each the matching *_retention_days
setting. For `self.db` (netpath.db, the trace store) it called only
`trim_to_size(cap)`, a *size* cap, and never `self.db.prune(days)`, the *age*
retention the Settings UI's "Keep traces for N days" field and
`trace_retention_days` promise. The only caller of `db.prune()` was the manual
`POST /api/maintenance {"action": "prune_traces"}` action in api.py -- so a
configured retention period did nothing unless an administrator clicked a
button. This suite proves the automatic path now applies it, using a real
`Service` and its real periodic sweep entry point (`run_maintenance`) rather
than calling `db.prune()` directly, since `db.prune()` working in isolation
(covered by test_collectors_hardening.py) was never in question -- only
whether anything automatic ever calls it.

Sections 3 and 4 cover a hazard that making prune() automatic exposed:
`trace_retention_days` had no server-side range check (only the Settings
page's own `min="1"` input, which an API client can skip). Before this
change that was nearly harmless -- prune() only ran when an admin clicked
"Prune traces now". Now it runs every maintenance interval, and `prune(0)`
computes `cutoff = time.time() - 0`, i.e. now, deleting every trace, every
interval, forever. `_GLOBAL_SETTINGS_RANGES` in api.py now carries
`"trace_retention_days": (1, 3650)`; section 3 proves that floor is actually
enforced over HTTP, and section 4 proves the automatic sweep, left at its
shipped 90-day default, prunes only what has actually aged out and nothing
still inside the window.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on
failure."""
import http.client
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.tracer import Hop, TraceResult
from netpath.web import Service
from netpath.web.server import WebServer

TMPDIR = _paths.tmpdir("trace_retention_")

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


def seed_traces(service, target_id, old_n, new_n, cutoff_days):
    now = time.time()
    for i in range(old_n):
        hop = Hop(ttl=1, addrs={"10.0.0.2": [1.0]}, sent=1, lost=0)
        result = TraceResult(host="10.0.0.1", dest_ip="10.0.0.1", hops=[hop],
                             reached=True,
                             started_ts=now - (cutoff_days + 5) * 86400 - i,
                             duration_s=1.0)
        service.db.record_trace(target_id, result, "ok")
    for i in range(new_n):
        hop = Hop(ttl=1, addrs={"10.0.0.2": [1.0]}, sent=1, lost=0)
        result = TraceResult(host="10.0.0.1", dest_ip="10.0.0.1", hops=[hop],
                             reached=True, started_ts=now - i, duration_s=1.0)
        service.db.record_trace(target_id, result, "ok")


def trace_count(service):
    return service.db._conn.execute("SELECT COUNT(*) FROM traces").fetchone()[0]


def req(port, method, path, body=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
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


def login(port, username, password):
    status, head, payload = req(port, "POST", "/api/login",
                                {"username": username, "password": password})
    cookie = head.get("set-cookie", "").split(";")[0]
    return (cookie if status == 200 else ""), status, payload


def admin_cookie_for(port):
    """Log in as the seeded admin and clear must_change, exactly the flow
    test_settings_types.py uses, so /api/settings is reachable."""
    cookie, status, _p = login(port, "admin", "admin")
    if status != 200:
        return cookie, status
    new_password = "correct horse battery staple 15"
    status, _h, _p = req(port, "POST", "/api/password",
                         {"current_password": "admin",
                          "new_password": new_password},
                         cookie=cookie)
    if status != 200:
        return cookie, status
    return login(port, "admin", new_password)[:2]


# ------------------------------ 1. the automatic sweep applies age retention

service = new_service("t1")
target_id = service.db.add_target("10.0.0.1")
CUTOFF_DAYS = 30
OLD_N, NEW_N = 12, 5
seed_traces(service, target_id, OLD_N, NEW_N, CUTOFF_DAYS)
service.settings["trace_retention_days"] = CUTOFF_DAYS
# No size cap: any removal below can only be the age-based prune, not
# trim_to_size taking a shortcut to the same answer.
service.settings["max_trace_db_mb"] = 0

check("traces are seeded before maintenance runs",
     trace_count(service) == OLD_N + NEW_N, trace_count(service))

service.run_maintenance(force=True)

check("run_maintenance() -- the real periodic sweep entry point, not "
     "db.prune() called directly -- removed the traces past the "
     "configured retention window",
     trace_count(service) == NEW_N,
     f"{trace_count(service)} traces remain, expected {NEW_N}")

service.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t1"), ignore_errors=True)


# --------------------- 2. the setting actually drives the cutoff (not a
# hardcoded default): a longer retention period keeps traces the first case
# would have dropped.

service2 = new_service("t2")
target_id2 = service2.db.add_target("10.0.0.1")
seed_traces(service2, target_id2, OLD_N, NEW_N, CUTOFF_DAYS)
service2.settings["trace_retention_days"] = CUTOFF_DAYS + 10
service2.settings["max_trace_db_mb"] = 0

service2.run_maintenance(force=True)

check("a longer trace_retention_days keeps traces a shorter one would have "
     "pruned -- the sweep reads the setting, not a fixed cutoff",
     trace_count(service2) == OLD_N + NEW_N, trace_count(service2))

service2.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t2"), ignore_errors=True)


# --------------------- 3. the API refuses a retention floor that would make
# the now-automatic prune delete everything, every interval, forever.
#
# trace_retention_days had no entry in _GLOBAL_SETTINGS_RANGES: only the
# Settings page's own min="1" input stood between an operator and this, and
# an API client skips the browser entirely. Before prune() ran automatically
# a bad value here was nearly harmless (it only bit whoever clicked "Prune
# traces now"); now it is posted straight into a sweep that runs every
# MAINTENANCE_INTERVAL_S forever, so the floor has to hold over HTTP, not
# just in the Settings page's <input min>.

service3 = new_service("t3")
port = _paths.free_tcp_port()
server3 = WebServer(service3, host="127.0.0.1", port=port)
if not server3.start(block=False):
    print(f"SKIP: could not bind 127.0.0.1:{port}: {server3.error}")
else:
    cookie, status = admin_cookie_for(port)
    check("admin login (and password change) succeeded, settings API reachable",
         status == 200 and bool(cookie), status)

    before = service3.settings.get("trace_retention_days")
    status, _h, payload = req(port, "POST", "/api/settings",
                              {"scope": "netpath",
                               "values": {"trace_retention_days": 0}},
                              cookie=cookie)
    check("HTTP trace_retention_days=0 -> 400 (the floor that keeps the "
         "automatic prune from ever being handed a cutoff of \"now\")",
         status == 400, f"{status} {payload}")
    check("...and the rejected value never reached service.settings",
         service3.settings.get("trace_retention_days") == before,
         str(service3.settings.get("trace_retention_days")))

    status, _h, payload = req(port, "POST", "/api/settings",
                              {"scope": "netpath",
                               "values": {"trace_retention_days": -5}},
                              cookie=cookie)
    check("HTTP trace_retention_days=-5 -> 400 too",
         status == 400, f"{status} {payload}")

    status, _h, payload = req(port, "POST", "/api/settings",
                              {"scope": "netpath",
                               "values": {"trace_retention_days": 45}},
                              cookie=cookie)
    check("HTTP a valid trace_retention_days is still accepted",
         status == 200 and service3.settings.get("trace_retention_days") == 45,
         f"{status} {payload}")

server3.stop()
service3.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t3"), ignore_errors=True)


# --------------------- 4. at the shipped 90-day default, the automatic sweep
# prunes what has aged out and leaves everything still inside the window --
# not a no-op, and not an over-eager one.

service4 = new_service("t4")
target_id4 = service4.db.add_target("10.0.0.1")
DEFAULT_RETENTION_DAYS = 90
check("the shipped default is what this section actually exercises",
     service4.settings.get("trace_retention_days") == DEFAULT_RETENTION_DAYS,
     service4.settings.get("trace_retention_days"))
# service4.settings is untouched -- trace_retention_days and max_trace_db_mb
# are both left at whatever a fresh install ships with.

now = time.time()
hop = Hop(ttl=1, addrs={"10.0.0.2": [1.0]}, sent=1, lost=0)
inside_id = service4.db.record_trace(
    target_id4,
    TraceResult(host="10.0.0.1", dest_ip="10.0.0.1", hops=[hop], reached=True,
               started_ts=now - 10 * 86400, duration_s=1.0),
    "ok")
outside_id = service4.db.record_trace(
    target_id4,
    TraceResult(host="10.0.0.1", dest_ip="10.0.0.1", hops=[hop], reached=True,
               started_ts=now - (DEFAULT_RETENTION_DAYS + 5) * 86400,
               duration_s=1.0),
    "ok")

service4.run_maintenance(force=True)

remaining = {row["id"] for row in
            service4.db._conn.execute("SELECT id FROM traces").fetchall()}
check("a trace well inside the 90-day default window survives the "
     "automatic sweep",
     inside_id in remaining, remaining)
check("a trace past the 90-day default window is removed by the automatic "
     "sweep -- this is a real prune, not a no-op that happens to leave "
     "everything alone",
     outside_id not in remaining, remaining)

service4.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t4"), ignore_errors=True)

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
