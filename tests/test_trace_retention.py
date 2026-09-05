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

Sections 5-7 cover a follow-on review finding: making prune() automatic
exposed a *different* way retention could destroy in-window data.
`Service._run_maintenance_body` ran `self.db.prune(...)` and then
`self.db.trim_to_size(cap)` back to back. trim_to_size decided how much to
delete from `size_bytes()` -- the raw file, which counts freelist pages and
the WAL as if they were live rows -- so a prune() that spent its whole
budget deleting and never reached reclaim (measured: zero pages freed after
a 30s delete pass on a 1.5M-row backlog) left a large freelist that
trim_to_size then read as "still over cap" and deleted real, in-retention
rows to correct -- measured at 22% of in-retention traces lost in one
maintenance pass on a synthetic 2M-trace database. Section 5 reproduces
that shape without needing millions of rows. Section 6 covers the same
review's second finding: a settings save now runs this same prune/trim pair
synchronously on the HTTP thread, and at the periodic sweep's 30s budget
that stalled the request by up to 30s per save. Section 7 closes the
loophole in section 3's HTTP-only floor: a `trace_retention_days` of 0
already sitting in the settings table (from before the floor existed, or
from a script) reaches coerce_settings(strict=False), which checks type but
never range, so it was never re-clamped on load.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on
failure."""
import http.client
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

import netpath.db as db_mod
import netpath.web.service as service_mod
from netpath.db import Database, MIN_TRACE_RETENTION_DAYS
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


def trace_count_db(db):
    return db._conn.execute("SELECT COUNT(*) FROM traces").fetchone()[0]


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


# --------------------- 5. trim_to_size must not delete in-retention rows
# just because freed-but-unreclaimed space (freelist pages, an
# un-checkpointed WAL) makes size_bytes() read the file as over cap.
#
# Reproduced without millions of rows: a raw DELETE run directly against
# the tables, bypassing prune()/reclaim() entirely, stands in for "prune()
# spent its whole budget deleting and never got to reclaim" -- same end
# state (freed pages sitting on the freelist, an un-checkpointed WAL), 4000
# rows and no HTTP server needed to reach it.

db5 = Database(os.path.join(TMPDIR, "t5-netpath.db"))
target5 = db5.add_target("10.0.0.1")

N_TOTAL = 4000
N_KEEP = 300   # stands in for "still inside the retention window"
now = time.time()
for i in range(N_TOTAL):
    hop = Hop(ttl=1, addrs={"10.0.0.2": [1.0], "10.0.0.3": [2.0]}, sent=1, lost=0)
    result = TraceResult(host="10.0.0.1", dest_ip="10.0.0.1", hops=[hop],
                         reached=True, started_ts=now - i, duration_s=1.0)
    db5.record_trace(target5, result, "ok")

check("seeded traces before the simulated partial prune",
     trace_count_db(db5) == N_TOTAL, trace_count_db(db5))

with db5._lock:
    bounds = db5._conn.execute(
        "SELECT MIN(id) AS lo, MAX(id) AS hi FROM traces").fetchone()
    cutoff_id = bounds["hi"] - N_KEEP + 1
    db5._conn.execute("DELETE FROM hops WHERE trace_id < ?", (cutoff_id,))
    db5._conn.execute("DELETE FROM traces WHERE id < ?", (cutoff_id,))
    db5._conn.commit()

check("the simulated partial prune left exactly the in-retention rows",
     trace_count_db(db5) == N_KEEP, trace_count_db(db5))

live5 = db5.live_size_bytes()
file5 = db5.size_bytes()
check("the unreclaimed freelist/WAL makes the raw file read larger than "
     "the live data -- the gap trim_to_size must not mistake for more rows "
     "to delete",
     file5 > live5, f"file={file5} live={live5}")

# Set the cap strictly between the two: the live data already fits: only
# the not-yet-reclaimed file does not. Exactly the shape a maintenance pass
# hits right after a time-limited prune.
cap5 = (live5 + file5) // 2
check("test cap sits strictly between live size and raw file size "
     "(otherwise this proves nothing)",
     live5 < cap5 < file5, f"live={live5} cap={cap5} file={file5}")

removed5 = db5.trim_to_size(cap5)
check("trim_to_size does not delete rows just because unreclaimed free "
     "space makes the file read as over cap -- live data was already "
     "under the cap",
     removed5 == 0, f"removed {removed5} of {N_KEEP} in-retention rows")
check("every in-retention row survives the trim",
     trace_count_db(db5) == N_KEEP, trace_count_db(db5))

db5.close()


# --------------------- 6. the forced/synchronous maintenance path (a
# settings save, on the HTTP thread) must not run netpath.db's prune/trim
# at the full periodic-timer budget -- unbounded there measured as a ~30s
# stall per save with a backlog. Checked at two levels: the mechanism
# (prune() actually stops at whatever budget_s it is given, rather than
# running until the backlog is exhausted) and the wiring (the forced path
# actually asks for the short budget instead of the long default).

db6 = Database(os.path.join(TMPDIR, "t6-netpath.db"))
target6 = db6.add_target("10.0.0.1")
N_OLD = 500
now = time.time()
for i in range(N_OLD):
    hop = Hop(ttl=1, addrs={"10.0.0.2": [1.0]}, sent=1, lost=0)
    result = TraceResult(host="10.0.0.1", dest_ip="10.0.0.1", hops=[hop],
                         reached=True, started_ts=now - 100 * 86400 - i,
                         duration_s=1.0)
    db6.record_trace(target6, result, "ok")

# budget_s=0.0: by the time the loop's first deadline check runs, real time
# has already moved past it, so this is a deterministic "stop immediately"
# rather than a timing race against how fast 500 deletes run on this
# machine.
removed6 = db6.prune(older_than_days=1, budget_s=0.0)
check("prune() given essentially no budget does not run until the whole "
     "backlog is gone -- the sweep is time-bounded, not just "
     "backlog-bounded",
     removed6 < N_OLD, f"removed {removed6} of {N_OLD}")
check("...and reports the sweep as incomplete rather than silently partial",
     db6.last_prune_incomplete is True, db6.last_prune_incomplete)
db6.close()

service6 = new_service("t6b")
service6.db.add_target("10.0.0.1")
service6.settings["max_trace_db_mb"] = 500   # so trim_to_size runs too
calls = []
real_prune, real_trim = service6.db.prune, service6.db.trim_to_size

def capturing_prune(days, budget_s=db_mod.TRIM_BUDGET_S):
    calls.append(("prune", budget_s))
    return real_prune(days, budget_s=0.0)   # keep the test itself fast

def capturing_trim(max_bytes, budget_s=db_mod.TRIM_BUDGET_S):
    calls.append(("trim", budget_s))
    return real_trim(max_bytes, budget_s=0.0)

service6.db.prune, service6.db.trim_to_size = capturing_prune, capturing_trim

service6.run_maintenance(force=True)
forced = [budget for name, budget in calls if name == "prune"]
check("a forced maintenance pass (settings save) asks netpath.db's prune "
     "for a short budget, not the full periodic-timer one",
     forced and forced[-1] == service_mod.FORCED_PRUNE_BUDGET_S, forced)
check("...and the size trim on the same forced pass gets the same short "
     "budget",
     [b for n, b in calls if n == "trim"][-1:] == [service_mod.FORCED_PRUNE_BUDGET_S],
     calls)

calls.clear()
service6._last_maintenance = 0.0   # make an unforced pass due again
service6.run_maintenance(force=False)
periodic = [budget for name, budget in calls if name == "prune"]
check("an unforced (periodic-timer) maintenance pass keeps the full "
     "budget -- only the forced/HTTP-thread path is shortened",
     periodic and periodic[-1] == service_mod.TRIM_BUDGET_S, periodic)

service6.db.prune, service6.db.trim_to_size = real_prune, real_trim
service6.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t6b"), ignore_errors=True)


# --------------------- 7. a trace_retention_days of 0 already sitting in
# the settings table -- written before the (1, 3650) floor existed (section
# 3 above), or by a script that bypassed the API entirely -- must not reach
# prune() unclamped. coerce_settings(strict=False) (settingsutil.py) checks
# only type, never range, so this floor has to be applied again right after
# it, on every load, not just on save.

db7 = Database(os.path.join(TMPDIR, "t7-netpath.db"))
target7 = db7.add_target("10.0.0.1")

with db7._lock:
    db7._conn.execute(
        "INSERT INTO settings(key, value) VALUES ('trace_retention_days', '0')"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    db7._conn.commit()

loaded7 = db7.settings()["trace_retention_days"]
check("a 0 already on disk is clamped on load, not handed to prune() as-is",
     loaded7 == MIN_TRACE_RETENTION_DAYS, loaded7)

recent_id7 = db7.record_trace(
    target7,
    TraceResult(host="10.0.0.1", dest_ip="10.0.0.1",
               hops=[Hop(ttl=1, addrs={"10.0.0.2": [1.0]}, sent=1, lost=0)],
               reached=True, started_ts=time.time() - 3600, duration_s=1.0),
    "ok")

db7.prune(db7.settings()["trace_retention_days"])
remaining7 = {row["id"] for row in
             db7._conn.execute("SELECT id FROM traces").fetchall()}
check("a recent trace survives prune() driven by the clamped value -- the "
     "fix actually prevents the wipe a stored 0 would otherwise cause "
     "every maintenance pass, not just the number settings() returns",
     recent_id7 in remaining7, remaining7)

db7.close()

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
