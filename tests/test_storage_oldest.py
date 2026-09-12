"""`SqliteStore.oldest_ts()` — how far back each database still reaches —
and the `{name}_oldest_ts` keys /api/state's storage block carries beside
the path and the byte count. Every store answers from its own history
table; the two that keep no history (the MIB file, the mapper file) answer
None, and so does any store that has never been written to.

Written against the real stores rather than a stub: the point of the hook
is that each one names the right column, which only the real schema can
show. Rows are inserted through the store's own connection where the API
would not let the test choose a timestamp -- the column the hook reads is
exactly what is being pinned."""
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.appdb import AppDatabase
from netpath.configrxdb import ConfigRxDatabase
from netpath.db import Database
from netpath.flowdb import FlowDatabase
from netpath.ipamdb import IpamDatabase
from netpath.mapperdb import MapperDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.web import api as api_mod
from netpath.web import Service
from netpath.wirelessdb import WirelessDatabase

TMPDIR = _paths.tmpdir("storage_oldest_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def write(db, sql, params=()):
    with db._lock:
        db._conn.execute(sql, params)
        db._conn.commit()


NOW = time.time()
OLD = NOW - 30 * 86400
OLDER = NOW - 90 * 86400


def path(name):
    return os.path.join(TMPDIR, name + ".db")


# ------------------------------------------------- 1. an empty store has no age

stores = {
    "app": AppDatabase(path("app")),
    "trace": Database(path("netpath")),
    "flow": FlowDatabase(path("flows")),
    "syslog": SyslogDatabase(path("syslog")),
    "snmp": SnmpTrapDatabase(path("snmptraps")),
    "ipam": IpamDatabase(path("ipam")),
    "nodes": NodesDatabase(path("nodes")),
    "alerts": AlertsDatabase(path("alerts")),
    "wireless": WirelessDatabase(path("wireless")),
    "configrx": ConfigRxDatabase(path("configrx")),
    "mapper": MapperDatabase(path("mapper")),
}
stores["nodes_series"] = stores["nodes"].series_db
stores["nodes_mibs"] = stores["nodes"].mib_db

empty = {name: db.oldest_ts() for name, db in stores.items()}
check("a store with nothing in it has no oldest record, rather than 0 or "
      "an exception",
      all(value is None for value in empty.values()),
      {k: v for k, v in empty.items() if v is not None})
check("...including the thirteenth store, so the UI has a key for every "
      "file it lists",
      len(empty) == 13, sorted(empty))


# --------------------------------------------- 2. each store finds its own oldest

trace_target = stores["trace"].add_target("10.0.0.1")
write(stores["trace"],
      "INSERT INTO traces(target_id, started_ts, status, reached)"
      " VALUES (?,?,'ok',1)", (trace_target, OLD))
write(stores["trace"],
      "INSERT INTO traces(target_id, started_ts, status, reached)"
      " VALUES (?,?,'ok',1)", (trace_target, NOW))
check("netpath.db reads traces.started_ts, and reports the oldest of two",
      stores["trace"].oldest_ts() == OLD, stores["trace"].oldest_ts())

write(stores["flow"],
      "INSERT INTO flows(exporter, version, ts_start, ts_end)"
      " VALUES ('10.0.0.1',9,?,?)", (OLD, OLD + 60))
check("flows.db reads flows.ts_start",
      stores["flow"].oldest_ts() == OLD, stores["flow"].oldest_ts())

write(stores["syslog"],
      "INSERT INTO logs(ts, source, message) VALUES (?,'10.0.0.1','x')", (OLD,))
check("syslog.db reads logs.ts", stores["syslog"].oldest_ts() == OLD,
      stores["syslog"].oldest_ts())

write(stores["snmp"],
      "INSERT INTO traps(ts, source, version, severity)"
      " VALUES (?,'10.0.0.1',1,5)", (OLD,))
check("snmptraps.db reads traps.ts", stores["snmp"].oldest_ts() == OLD,
      stores["snmp"].oldest_ts())

subnet = stores["ipam"].add_subnet("10.0.0.0/24")
write(stores["ipam"],
      "INSERT INTO scans(subnet_id, started_ts) VALUES (?,?)", (subnet, OLD))
check("ipam.db reads scans.started_ts -- the one table there that is a log",
      stores["ipam"].oldest_ts() == OLD, stores["ipam"].oldest_ts())

nodes = stores["nodes"]
group = nodes.ensure_default_group()
device = nodes.add_device("10.0.0.2", name="sw1", group_id=group)
write(nodes, "INSERT INTO device_events(device_id, ts, kind)"
             " VALUES (?,?,'down')", (device, OLD))
check("nodes.db reads the device event log", nodes.oldest_ts() == OLD,
      nodes.oldest_ts())
write(nodes, "INSERT INTO interfaces(device_id, if_index, last_seen_ts)"
             " VALUES (?,1,?)", (device, NOW))
with nodes._lock:
    interface = nodes._conn.execute(
        "SELECT id FROM interfaces WHERE device_id = ?", (device,)).fetchone()["id"]
write(nodes, "INSERT INTO interface_events(interface_id, ts, kind)"
             " VALUES (?,?,'link_down')", (interface, OLDER))
check("...and the interface event log too, so an older link flap moves the "
      "answer back",
      nodes.oldest_ts() == OLDER, nodes.oldest_ts())

series = stores["nodes_series"]
nodes.record_metric_samples(device, [("if.1", "if 1", "b/s", "gauge", OLD, 1.0)])
check("nodes_series.db falls back to the raw samples while nothing has "
      "been summarised yet",
      series.oldest_ts() == OLD, series.oldest_ts())
with series._lock:
    metric = series._conn.execute("SELECT id FROM metrics").fetchone()["id"]
write(series, "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
              " VALUES (?,?,1,1.0,1.0,1.0)", (metric, int(OLDER // 3600) * 3600))
check("...and reports the hourly rollups once they reach further back, "
      "which is what a wide chart actually reads",
      series.oldest_ts() == int(OLDER // 3600) * 3600, series.oldest_ts())

rule_id = stores["alerts"].rules()[0]["id"]
write(stores["alerts"],
      "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
      " entity_label, severity, message, opened_ts, last_ts)"
      " VALUES (?,'d','device','1','sw1',4,'m',?,?)", (rule_id, OLD, NOW))
check("alerts.db reads alerts.opened_ts", stores["alerts"].oldest_ts() == OLD,
      stores["alerts"].oldest_ts())

write(stores["wireless"],
      "INSERT INTO ap_events(ts, controller_id, wtp_id, kind)"
      " VALUES (?,1,'w1','up')", (OLD,))
check("wireless.db reads ap_events.ts", stores["wireless"].oldest_ts() == OLD,
      stores["wireless"].oldest_ts())

write(stores["configrx"],
      "INSERT INTO backups(device_id, ts, content_gz, sha256, size_bytes)"
      " VALUES (1,?,X'00','abc',1)", (OLD,))
check("configrx.db reads backups.ts", stores["configrx"].oldest_ts() == OLD,
      stores["configrx"].oldest_ts())

stores["app"].audit("admin", "127.0.0.1", "settings.save")
check("app.db reads the audit log, so the file worth backing up says how "
      "much history it holds",
      abs((stores["app"].oldest_ts() or 0) - time.time()) < 60,
      stores["app"].oldest_ts())

check("the MIB file has no history to report even after a store beside it "
      "does -- a MIB is not a log",
      stores["nodes_mibs"].oldest_ts() is None, stores["nodes_mibs"].oldest_ts())
check("...and neither has the mapper file",
      stores["mapper"].oldest_ts() is None, stores["mapper"].oldest_ts())

for name, db in list(stores.items()):
    if name not in ("nodes_series", "nodes_mibs"):
        db.close()


# ------------------------------------------ 3. /api/state carries the age

DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")
service_dir = os.path.join(TMPDIR, "service")
os.makedirs(service_dir, exist_ok=True)
service = Service(*[os.path.join(service_dir, name + ".db") for name in DB_NAMES])

storage = api_mod._storage(service)
byte_keys = {key[:-len("_bytes")] for key in storage if key.endswith("_bytes")}
age_keys = {key[:-len("_oldest_ts")] for key in storage if key.endswith("_oldest_ts")}
check("every store the storage block sizes also reports an age -- the two "
      "lists cannot drift",
      byte_keys == age_keys and len(byte_keys) == 13,
      sorted(byte_keys ^ age_keys) or len(byte_keys))
check("a fresh install reports None rather than an epoch of 0, so the page "
      "can say 'no history' instead of 1970",
      all(storage[f"{name}_oldest_ts"] is None for name in byte_keys),
      {n: storage[f"{n}_oldest_ts"] for n in byte_keys
       if storage[f"{n}_oldest_ts"] is not None})

target = service.db.add_target("10.0.0.1")
write(service.db, "INSERT INTO traces(target_id, started_ts, status, reached)"
                  " VALUES (?,?,'ok',1)", (target, OLD))
storage = api_mod._storage(service)
check("a seeded store reports its oldest record over the API",
      storage["trace_oldest_ts"] == OLD, storage["trace_oldest_ts"])
check("...and the stores that keep no history still report None there",
      storage["nodes_mibs_oldest_ts"] is None
      and storage["mapper_oldest_ts"] is None,
      (storage["nodes_mibs_oldest_ts"], storage["mapper_oldest_ts"]))

# --------------------------- 3b. app.db has a warning where others have a cap
# The audit trail is never trimmed, so app.db is the one store no sweep can
# bring back under a ceiling. The storage block says so once it is large,
# and names the setting that decides "large".
check("app_db_warn_mib defaults to 512 MiB",
      service.settings.get("app_db_warn_mib") == 512,
      service.settings.get("app_db_warn_mib"))
check("no warning while app.db is under the threshold",
      "app_db_warning" not in storage, storage.get("app_db_warning"))

real_size_bytes = service.app_db.size_bytes
service.app_db.size_bytes = lambda: 600 * 1024 * 1024
try:
    warned = api_mod._storage(service)
    service.settings["app_db_warn_mib"] = 1024
    raised = api_mod._storage(service)
finally:
    service.settings["app_db_warn_mib"] = 512
    service.app_db.size_bytes = real_size_bytes

check("app.db past the threshold carries a warning line, naming the size and "
      "the setting",
      "600" in str(warned.get("app_db_warning"))
      and "app_db_warn_mib" in str(warned.get("app_db_warning")),
      warned.get("app_db_warning"))
check("...and it is a warning only: the byte count and the store list are "
      "unchanged",
      warned["app_bytes"] == 600 * 1024 * 1024
      and {k for k in warned if k.endswith("_bytes")}
      == {k for k in storage if k.endswith("_bytes")},
      sorted(warned))
check("...and raising the threshold past the file clears it",
      "app_db_warning" not in raised, raised.get("app_db_warning"))

service.shutdown()


# ------------------------- 4. the flow store's age costs index probes, not a scan

# /api/state polls this every ten seconds, on the collector's write lock, for
# every open tab, and the desktop console has a timer of its own. What it
# costs is therefore part of what it means. Counted in SQLite VM steps rather
# than wall clock: the query plan is what has to stay right, and a stopwatch
# is a flaky way of asserting one.
def vm_steps(db, call):
    counted = [0]

    def tick():
        counted[0] += 1
        return 0

    db._conn.set_progress_handler(tick, 1000)
    try:
        return call(), counted[0]
    finally:
        db._conn.set_progress_handler(None, 0)


cost_db = FlowDatabase(path("flows_cost"))
BULK = 60_000
BULK_SPAN = 4 * 3600.0
with cost_db._lock:
    cost_db._conn.executemany(
        "INSERT INTO flows(exporter, version, ts_start, ts_end, bytes, packets,"
        " sampling) VALUES ('10.0.0.1',9,?,?,100,1,1)",
        [(NOW - BULK_SPAN + i * (BULK_SPAN / BULK),
          NOW - BULK_SPAN + i * (BULK_SPAN / BULK) + 1.0) for i in range(BULK)])
    cost_db._conn.commit()
for tier in (60, 3600):
    cost_db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
    while True:
        rows_written, walked = cost_db.backfill_rollup(tier, max_buckets=10_000,
                                                       budget_s=120)
        if walked or not rows_written:
            break

value, steps = vm_steps(cost_db, cost_db.oldest_ts)
raw_oldest = cost_db._conn.execute("SELECT MIN(ts_start) FROM flows").fetchone()[0]
check("flows.db still reports the oldest of its raw rows and its rollup "
      "buckets", value is not None and abs(value - raw_oldest) < 3600,
      (value, raw_oldest))
check(f"...and finds it in index probes rather than walking {BULK} rows and "
      f"every rollup bucket beside them ({steps * 1000} VM steps)",
      steps < 20, steps)

held = cost_db._conn.execute(
    "EXPLAIN QUERY PLAN " + FlowDatabase.OLDEST_TS_SQL).fetchall()
check("the plan never touches flow_rollup, whose index leads on tier and so "
      "cannot serve a MIN over buckets",
      not any("flow_rollup " in " ".join(str(c) for c in row) + " "
              for row in held),
      [tuple(row) for row in held])
cost_db.close()

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
