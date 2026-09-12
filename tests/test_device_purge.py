"""Deleting a device with a long history.

The delete used to be one transaction over nine child tables plus every
sample and rollup the device ever produced — millions of rows under the two
locks the poller and every chart read need. It is now a tombstone written in
one short transaction (`request_device_removal`) and a background purge that
deletes in batches (`purge_step`, run by the service's DevicePurger).

What is pinned here: the route answers at once, the device is invisible from
that moment, a reader of the series store never waits on a purge in flight,
the rows really do reach zero, a purge interrupted by a restart resumes from
its `device_purges` row, and the id the device gave up carries nothing of it
into whatever device is added next.
"""
import http.client
import json
import os
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.nodesdb import NodesDatabase
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("device_purge_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


SAMPLES = 200_000
HOURLY = 20_000


def seed_history(db, device_id, samples=SAMPLES, hourly=HOURLY):
    """One device's worth of series rows and walk rows, written the way a
    year of polling would leave them."""
    now = time.time()
    metric_ids = [db.series_db.record_metric_sample(
        device_id, f"bench.{i}", f"metric {i}", "u", "gauge", now, 0.0)
        for i in range(20)]
    series = db.series_db
    with series._lock:
        series._conn.executemany(
            "INSERT OR REPLACE INTO samples(metric_id, ts, value) VALUES (?,?,?)",
            [(metric_ids[i % len(metric_ids)], now - i, float(i % 100))
             for i in range(samples)])
        series._conn.executemany(
            "INSERT OR REPLACE INTO samples_hourly(metric_id, hour, n, vmin,"
            " vavg, vmax) VALUES (?,?,?,60,1.0,2.0)",
            [(metric_ids[i % len(metric_ids)], int(now) - i * 3600, 1.0)
             for i in range(hourly)])
        series._conn.commit()
    with db._lock:
        db._conn.executemany(
            "INSERT INTO interfaces(device_id, if_index, descr, last_seen_ts)"
            " VALUES (?,?,?,?)",
            [(device_id, i + 1, f"Gi0/{i + 1}", now) for i in range(48)])
        interface_ids = [r[0] for r in db._conn.execute(
            "SELECT id FROM interfaces WHERE device_id = ?", (device_id,)).fetchall()]
        db._conn.executemany(
            "INSERT INTO interface_events(interface_id, ts, kind, detail)"
            " VALUES (?,?,'link_down','x')",
            [(interface_ids[i % len(interface_ids)], now - i) for i in range(20_000)])
        db._conn.executemany(
            "INSERT INTO device_events(device_id, ts, kind, detail)"
            " VALUES (?,?,'down','x')",
            [(device_id, now - i) for i in range(20_000)])
        db._conn.executemany(
            "INSERT INTO mac_entries(device_id, if_index, mac, vlan, seen_ts,"
            " first_seen_ts, present) VALUES (?,?,?,'1',?,?,1)",
            [(device_id, i % 48 + 1, "aa:bb:%08x" % i, now, now)
             for i in range(20_000)])
        db._conn.executemany(
            "INSERT INTO vlans(device_id, vlan, name, seen_ts, first_seen_ts,"
            " present) VALUES (?,?,?,?,?,1)",
            [(device_id, i + 1, f"vlan{i}", now, now) for i in range(1_000)])
        db._conn.execute(
            "INSERT INTO device_addresses(device_id, ip, source, seen_ts)"
            " VALUES (?,?,'test',?)", (device_id, f"10.99.0.{device_id}", now))
        db._conn.commit()


def rows_left(db, device_id):
    counts = {}
    with db.series_db._lock:
        counts["metrics"] = db.series_db._conn.execute(
            "SELECT COUNT(*) FROM metrics WHERE device_id = ?",
            (device_id,)).fetchone()[0]
        counts["samples"] = db.series_db._conn.execute(
            "SELECT COUNT(*) FROM samples").fetchone()[0]
        counts["samples_hourly"] = db.series_db._conn.execute(
            "SELECT COUNT(*) FROM samples_hourly").fetchone()[0]
    with db._lock:
        for table in ("interfaces", "device_events", "mac_entries", "vlans",
                      "device_addresses"):
            counts[table] = db._conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE device_id = ?",
                (device_id,)).fetchone()[0]
        counts["interface_events"] = db._conn.execute(
            "SELECT COUNT(*) FROM interface_events").fetchone()[0]
        counts["devices"] = db._conn.execute(
            "SELECT COUNT(*) FROM devices WHERE id = ?", (device_id,)).fetchone()[0]
    return counts


# ----------------------------------------------------- 1. the store itself

store_dir = os.path.join(TMPDIR, "store")
os.makedirs(store_dir, exist_ok=True)
store_path = os.path.join(store_dir, "nodes.db")
db = NodesDatabase(store_path)
group_id = db.ensure_default_group()
device_id = db.add_device("10.90.0.1", "sw-purge", group_id=group_id)
keeper = db.add_device("10.90.0.2", "sw-keeper", group_id=group_id)
db.update_device(keeper, upstream_id=device_id)
seed_history(db, device_id)

started = time.monotonic()
queued = db.request_device_removal([device_id])
elapsed = time.monotonic() - started
check("requesting removal is one short transaction, whatever the history",
      queued == 1 and elapsed < 0.5, f"{queued} queued in {elapsed:.3f}s")

visible = [row["id"] for row in db.devices()]
check("the device is gone from devices() the moment it is requested",
      visible == [keeper], visible)
check("...and from devices_count()", db.devices_count() == 1, db.devices_count())
check("...and from device(), so every route that reads one answers 404",
      db.device(device_id) is None)
check("...and from the poll scheduler's rows",
      [row["id"] for row in db.schedule_rows()] == [keeper])
check("...while its rows are all still there",
      rows_left(db, device_id)["devices"] == 1)

status = db.purge_status()
check("the purge is pending, and says which device it is on",
      status["pending"] == 1 and status["current"]["ip"] == "10.90.0.1", status)

check("the address is free at once, so a device can be re-added to it",
      db.add_device("10.90.0.1", "sw-replacement", group_id=group_id)
      not in (None, device_id))
replacement = db.device_by_ip("10.90.0.1")["id"]
check("...and the replacement is a NEW id: the tombstone reserves the old "
      "one until every child row is gone",
      replacement != device_id, f"{replacement} vs {device_id}")


# ------------------------------------- 2. a reader never waits on the purge

class Probe(threading.Thread):
    """The Nodes page's own read pattern against the series lock: if a purge
    holds it for longer than half a second, this records it."""

    def __init__(self, store):
        super().__init__(daemon=True)
        self.store = store
        self.worst = 0.0
        self.blocked = 0
        self.reads = 0
        self._done = threading.Event()

    def run(self):
        while not self._done.is_set():
            began = time.monotonic()
            got = self.store._lock.acquire(timeout=0.5)
            waited = time.monotonic() - began
            if got:
                self.store._conn.execute("SELECT 1").fetchone()
                self.store._lock.release()
                self.reads += 1
            else:
                self.blocked += 1
            self.worst = max(self.worst, waited)
            self._done.wait(0.005)

    def stop(self):
        self._done.set()
        self.join(timeout=10)


probe = Probe(db.series_db)
probe.start()
time.sleep(0.05)
purge_started = time.monotonic()
removed = db.purge_all()
purge_seconds = time.monotonic() - purge_started
probe.stop()
check("a reader taking the series lock during the purge is never shut out "
      "for half a second",
      probe.blocked == 0 and probe.worst < 0.5,
      f"{probe.blocked} blocked, worst {probe.worst * 1000:.0f} ms over "
      f"{probe.reads} reads in {purge_seconds:.1f}s")

left = rows_left(db, device_id)
check("every row of the deleted device is gone, in both files",
      all(value == 0 for value in left.values()), left)
check("...including the rows of the three tables with no foreign key",
      left["vlans"] == 0 and left["mac_entries"] == 0)
check("and the purge queue is empty", db.purge_status()["pending"] == 0,
      db.purge_status())
check("the purge reports what it removed", removed > SAMPLES, removed)
check("the devices the purge was not asked about are untouched",
      sorted(row["id"] for row in db.devices()) == sorted([keeper, replacement]))
check("...except that nothing still points at the deleted device as its "
      "upstream, which the next holder of the id would have inherited",
      db.device(keeper)["upstream_id"] is None, db.device(keeper)["upstream_id"])


# ------------------------------------------ 3. interrupted, then resumed

second = db.add_device("10.90.0.9", "sw-interrupted", group_id=group_id)
seed_history(db, second, samples=60_000, hourly=2_000)
db.request_device_removal([second])
step = db.purge_step(budget_s=0.02)
check("a step bounded by its budget stops partway and says so",
      step["pending"] == 1 and step["rows_removed_now"] > 0, step)
partway = rows_left(db, second)
check("...with rows still to go",
      partway["samples"] + partway["samples_hourly"] > 0, partway)
db.close()

db = NodesDatabase(store_path)
check("the tombstone survives a restart, so the purge resumes rather than "
      "being forgotten",
      db.purge_status()["pending"] == 1, db.purge_status())
check("...and the half-purged device is still invisible",
      db.device(second) is None)
db.purge_all()
check("the resumed purge finishes the job",
      all(value == 0 for value in rows_left(db, second).values())
      and db.purge_status()["pending"] == 0, rows_left(db, second))
db.close()


# ------------------------------------------------- 4. through the routes

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
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=30)
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


row = service.app_db.user(DEFAULT_USER)
if row is not None and row["must_change"]:
    service.app_db.set_password(DEFAULT_USER, row["password"], must_change=False)
conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=30)
conn.request("POST", "/api/login",
             body=json.dumps({"username": DEFAULT_USER,
                              "password": DEFAULT_PASSWORD}).encode(),
             headers={"Content-Type": "application/json"})
response = conn.getresponse()
response.read()
cookie = dict(response.getheaders()).get("Set-Cookie", "")
conn.close()
assert "sw_session=" in cookie, cookie
TOKEN = cookie.split("sw_session=")[1].split(";")[0]

nodes = service.nodes_db
group = nodes.ensure_default_group()
target = nodes.add_device("10.91.0.1", "sw-route", group_id=group)
seed_history(nodes, target)

# The three stores whose rows would otherwise be inherited by the next
# device to be handed this id.
service.alerts_db.set_device_threshold(target, "cpu_high", threshold=95.0,
                                       clear_threshold=80.0)
service.alerts_db.mute("device", str(target), 2.0, by="test")
service.alerts_db.set_maintenance(target, by="test")
service.alerts_db.park_occurrence(target, time.time() + 600, "{}")
service.configrx_db.update_device_config(target, backup_enabled=1)
service.configrx_db.replace_search_lines(
    target, "\n".join(f"line {i}" for i in range(5_000)))
map_id = service.mapper_db.create_map("purge map")
service.mapper_db.add_node(map_id, device_id=target, label="sw-route")

started = time.monotonic()
status_code, payload = call("DELETE", f"/api/nodes/devices/{target}", token=TOKEN)
elapsed = time.monotonic() - started
check("DELETE answers in well under the browser's timeout, whatever the "
      "history behind it",
      status_code == 200 and payload.get("ok") and elapsed < 2.0,
      f"{status_code} {payload} in {elapsed:.2f}s")

status_code, payload = call("GET", f"/api/nodes/devices/{target}", token=TOKEN)
check("the device already reads as gone to every route that loads one",
      status_code == 404 and "No such device" in str(payload),
      f"{status_code} {payload}")
status_code, payload = call("GET", "/api/nodes/purges", token=TOKEN)
check("/api/nodes/purges reports the work still to do",
      status_code == 200 and payload["pending"] == 1
      and payload["current"]["ip"] == "10.91.0.1", payload)
status_code, payload = call("GET", "/api/state", token=TOKEN)
check("...and so does the status payload the Nodes strip already polls",
      payload["nodes"]["purges"]["pending"] == 1, payload["nodes"]["purges"])

check("the alert store forgets the device's thresholds",
      service.alerts_db.device_thresholds(target) == [])
check("...its mute", service.alerts_db.mute_row("device", str(target)) is None)
check("...its maintenance period",
      service.alerts_db.open_maintenance(target) is None)
with service.alerts_db._lock:
    parked = service.alerts_db._conn.execute(
        "SELECT COUNT(*) FROM pending_alerts WHERE device_id = ?",
        (target,)).fetchone()[0]
check("...and anything it had parked waiting out a delay", parked == 0, parked)
check("ConfigRX forgets its credential row",
      service.configrx_db.device_config(target) is None)
check("...and its indexed configuration lines",
      not service.configrx_db.has_search_lines(target))
check("the map forgets where it was placed",
      [n["device_id"] for n in service.mapper_db.nodes(map_id)] == [])

status_code, payload = call("POST", "/api/nodes/devices",
                            {"ip": "10.91.0.1", "name": "sw-route-2"},
                            token=TOKEN)
check("the address can be used again at once, while the purge runs",
      status_code == 200, payload)
fresh = service.nodes_db.device_by_ip("10.91.0.1")["id"]
check("...and the new device is a new id, with none of the old one's "
      "thresholds, mute or configuration",
      fresh != target and service.alerts_db.device_thresholds(fresh) == []
      and service.alerts_db.mute_row("device", str(fresh)) is None
      and service.configrx_db.device_config(fresh) is None,
      f"{fresh} vs {target}")

# The worker the service runs, driven by hand: start() would have it racing
# the assertions above.
service.device_purger.nodes_db.purge_all()
check("the purge drains to nothing",
      service.nodes_db.purge_status()["pending"] == 0
      and all(value == 0 for value in rows_left(service.nodes_db, target).values()),
      rows_left(service.nodes_db, target))
status_code, payload = call("GET", "/api/nodes/purges", token=TOKEN)
check("...and the route says so", payload["pending"] == 0, payload)

server.stop()
service.shutdown()

print()
print("FAILURES:", ", ".join(FAILS) if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
