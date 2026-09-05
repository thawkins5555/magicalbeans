"""A child alert that opened before its parent, or before an ancestor's
outage covered it, must not sit on the Alerts page for the rest of the
outage.

Two separate gaps this closes, both in alertengine.py:

  Gap 1 (alertengine.py's own _absorb_subordinates already closes this one
  for the SAME device, and this file's first section only proves it stays
  closed): a device's own device_down opens after packet_loss_high (say)
  already did — climbing loss is visible several polls before "down" is
  confirmed by consecutive failures, so the child always arrives first.
  _absorb_subordinates resolves it the moment device_down opens.

  Gap 2 (this file's real subject, and the one alertengine.py did not
  already close): a device whose OWN device_down alert never opens at all,
  because an ancestor's outage rolled it up first (_rollup_parent's
  upstream-outage case, or _absorb_downstream the other way round) — was
  still left with its OTHER already-open children on the page. The
  absorption every other child gets is hung off its OWN device_down
  opening (is_new in _apply), and a topology-covered device's device_down
  never does that, in either direction. _rollup_parent's case 4 and
  _absorb_children_of close it: a child rolls up exactly as far as
  device_down itself does, ancestor included.

Drives engine._tick() directly, the same harness shape test_alert_engine_
fixes.py uses, for the same reason: every fix here is about what one tick
does, and a real thread would make the assertions time-dependent.
"""
import os
import sqlite3
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_rollup_topology_")
_SEQ = [0]


def build(**settings):
    """(nodes, alerts, snmp, syslog, ipam, engine) on fresh temp databases.

    rollup_enabled defaults on here (unlike test_alert_engine_fixes.py's
    build(), which defaults it off) — every section in this file is about
    rollup behaviour specifically, so there is no case here that wants it
    off by default.
    """
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    values = {"email_enabled": False, "rollup_enabled": True,
              "new_device_grace_s": 0, "notify_rollup_delay_s": 0}
    values.update(settings)
    alerts.save_settings(values)
    snmp = SnmpTrapDatabase(os.path.join(folder, "traps.db"))
    syslog = SyslogDatabase(os.path.join(folder, "syslog.db"))
    ipam = IpamDatabase(os.path.join(folder, "ipam.db"))
    netpath_db = NetpathDatabase(os.path.join(folder, "netpath.db"))
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp,
                         syslog_db=syslog, ipam_db=ipam, netpath_db=netpath_db)
    return nodes, alerts, snmp, syslog, ipam, engine


def add_device(nodes, ip, name, **fields):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid, **fields)


def set_status(nodes, device_ids, status):
    """The status column a poll would have written — see
    test_alert_engine_fixes.py's identical helper for why this is written
    directly rather than through record_poll."""
    conn = sqlite3.connect(nodes.path)
    conn.executemany("UPDATE devices SET status = ? WHERE id = ?",
                     [(status, i) for i in device_ids])
    conn.commit()
    conn.close()


def go_down(nodes, device_ids, detail="stopped responding"):
    if isinstance(device_ids, int):
        device_ids = [device_ids]
    set_status(nodes, device_ids, "down")
    for device_id in device_ids:
        nodes.record_device_event(device_id, "down", detail)


def open_rows(alerts, rule_key, entity_id=None):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    if entity_id is not None:
        rows = [r for r in rows if r["entity_id"] == str(entity_id)]
    return rows


def open_loss(nodes, engine, did, base, offsets=(0, 65)):
    """Records ping_loss_pct high enough to breach packet_loss_high at each
    offset (seconds from `base`), ticking after each — the same two-sample
    pattern test_alert_engine_fixes.py's F11 section uses to get a child
    alert open before anything else has happened to the device."""
    for offset in offsets:
        nodes.record_metric_sample(did, "ping_loss_pct", "Loss", "%", "gauge",
                                   base + offset, 999.0)
        engine._tick()


PASSED = []


def ok(line):
    PASSED.append(line)
    print("  " + line + " OK")


# ============================================================ same device
print("1 — a child already open when its OWN parent opens is still absorbed")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
did = add_device(nodes, "10.40.0.1", "sw-1")
base = time.time()
open_loss(nodes, engine, did, base)
assert len(open_rows(alerts, "packet_loss_high", did)) == 1
ok("packet_loss_high opens on its own well before any device_down")

go_down(nodes, did)
engine._tick()
assert len(open_rows(alerts, "device_down", did)) == 1
assert open_rows(alerts, "packet_loss_high", did) == []
ok("device_down opening absorbs the already-open child immediately "
   "(this is the existing _absorb_subordinates path, unchanged)")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ================================================== parent-first, no child
print("\n2 — parent-first ordering is unaffected: nothing to absorb, "
     "nothing extra happens")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
did = add_device(nodes, "10.40.0.2", "sw-2")
go_down(nodes, did)
engine._tick()
assert len(open_rows(alerts, "device_down", did)) == 1
ok("device_down opens normally when nothing was open before it")

base = time.time()
open_loss(nodes, engine, did, base)
assert open_rows(alerts, "packet_loss_high", did) == [], (
    "a device_down-covered device must not open a fresh packet_loss_high "
    "while it is still down")
ok("packet_loss_high breaching while the device is still down stays "
   "suppressed rather than opening a second alert for the same outage")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ================================================ topology: ancestor first
print("\n3 — a downstream device's own already-open child is swept when an "
     "ancestor's outage covers it (ancestor goes down first)")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
a = add_device(nodes, "10.40.1.1", "core-a")
b = add_device(nodes, "10.40.1.2", "acc-b")
nodes.update_device(b, upstream_id=a)

base = time.time()
open_loss(nodes, engine, b, base)
assert len(open_rows(alerts, "packet_loss_high", b)) == 1
ok("B has its own packet_loss_high open before the site outage reaches it")

go_down(nodes, [a, b])
engine._tick()
assert len(open_rows(alerts, "device_down", a)) == 1
assert open_rows(alerts, "device_down", b) == [], (
    "B's own device_down must roll into A's, not open separately")
assert open_rows(alerts, "packet_loss_high", b) == [], (
    "B's pre-existing packet_loss_high must be swept too — this is the gap"
)
ok("B's device_down rolls into A's, and B's own already-open "
   "packet_loss_high is swept in the same tick")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ============================================== topology: downstream first
print("\n4 — the other order: downstream device's own device_down opened "
     "first, ancestor's outage catches up and absorbs it (_absorb_downstream)")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
a = add_device(nodes, "10.40.2.1", "core-a")
b = add_device(nodes, "10.40.2.2", "acc-b")
nodes.update_device(b, upstream_id=a)

base = time.time()
open_loss(nodes, engine, b, base)
assert len(open_rows(alerts, "packet_loss_high", b)) == 1

go_down(nodes, b)
engine._tick()
assert len(open_rows(alerts, "device_down", b)) == 1
ok("B goes down on its own first (the poller reached it before the core)")

go_down(nodes, a)
engine._tick()
assert len(open_rows(alerts, "device_down", a)) == 1
assert open_rows(alerts, "device_down", b) == [], (
    "_absorb_downstream must resolve B's own device_down into A's")
assert open_rows(alerts, "packet_loss_high", b) == [], (
    "and sweep B's other already-open children while it is at it")
ok("A's device_down absorbs B's device_down AND B's own packet_loss_high")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ==================================== operator resolves the ancestor by hand
print("\n5 — an operator resolving the ancestor's alert while it is still "
     "down must not resurrect what the topology sweep already absorbed")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
a = add_device(nodes, "10.40.3.1", "core-a")
b = add_device(nodes, "10.40.3.2", "acc-b")
nodes.update_device(b, upstream_id=a)

base = time.time()
open_loss(nodes, engine, b, base)
go_down(nodes, [a, b])
engine._tick()
assert open_rows(alerts, "packet_loss_high", b) == []
ok("setup: B's device_down rolled into A's, B's packet_loss_high absorbed")

outage = open_rows(alerts, "device_down", a)[0]
assert alerts.resolve_many([outage["id"]], "operator") == 1
for _ in range(3):
    engine._tick()
assert open_rows(alerts, "device_down", a) == [], \
    "resolving A by hand must not immediately re-open A's own outage"
assert open_rows(alerts, "device_down", b) == [], \
    "B must not re-open its own device_down while A (and B) are still down"
assert open_rows(alerts, "packet_loss_high", b) == [], \
    "B's packet_loss_high must not resurrect either, while B is still down"
ok("hand-resolving the ancestor while the outage is still real keeps "
   "everything behind it — including packet_loss_high — suppressed")

come_up_a = time.time() + 200
set_status(nodes, [a], "up")
nodes.record_device_event(a, "up", "responding again")
# B is still down on its own account.
engine._tick()
assert len(open_rows(alerts, "device_down", b)) == 1, (
    "once the ancestor recovers, a device still down on its own account "
    "opens its own outage again")
ok("A recovering re-opens B's own outage, which is still real")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# =========================================================== cost bounded
print("\n6 — the topology sweep is bounded by the outage, not by how large "
     "the alert table has grown")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()

# A large pile of unrelated, already-resolved history, inserted directly
# rather than through 4000 ticks of the engine: if any part of the sweep
# below ever scanned the alerts table rather than going straight at an
# indexed dedup_key, this is what would make it slow.
device_down_rule = alerts.rule_by_key("device_down")
now = time.time()
padding = [
    (device_down_rule["id"], f"padding:{i}", "device", str(-i - 1),
     f"padding-{i}", 5, "padding", "", "resolved", 1, now - 3600, now - 3600,
     now - 3500, "operator", "")
    for i in range(4000)
]
alerts._conn.executemany(
    "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
    " entity_label, severity, message, detail, state, count, opened_ts,"
    " last_ts, resolved_ts, resolved_by, extra_json)"
    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", padding)
alerts._conn.commit()
assert alerts._conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"] >= 4000
ok("padded the alert table with 4000 unrelated resolved rows")

DEVICES = 60
a = add_device(nodes, "10.40.4.2", "core-b")
kids = [add_device(nodes, f"10.40.5.{i}", f"acc-{i}") for i in range(DEVICES)]
for device_id in kids:
    nodes.update_device(device_id, upstream_id=a)

base = time.time()
for did in kids:
    open_loss(nodes, engine, did, base, offsets=(0,))
# One breach sample is not (by itself) enough to open the alert on every
# rule's hysteresis, so make sure every child is actually open before
# timing the sweep below - the cost claim is about the sweep, not about
# how many polls a threshold rule needs to trip.
open_loss(nodes, engine, kids[0], base, offsets=(65,))
for did in kids[1:]:
    nodes.record_metric_sample(did, "ping_loss_pct", "Loss", "%", "gauge",
                               base + 65, 999.0)
engine._tick()
opened_children = sum(1 for did in kids if open_rows(alerts, "packet_loss_high", did))
assert opened_children == DEVICES, opened_children
ok(f"{DEVICES} devices each have their own packet_loss_high open")

go_down(nodes, [a] + kids)
started = time.monotonic()
engine._tick()
elapsed = time.monotonic() - started
assert elapsed < 5.0, elapsed
assert len(open_rows(alerts, "device_down", a)) == 1
assert all(open_rows(alerts, "device_down", did) == [] for did in kids)
assert all(open_rows(alerts, "packet_loss_high", did) == [] for did in kids)
ok(f"{DEVICES} devices absorbed (device_down and packet_loss_high both) "
   f"in {elapsed:.2f}s despite 4000+ unrelated rows already in the table")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


print(f"\nALL {len(PASSED)} ROLLUP-TOPOLOGY-SWEEP ASSERTIONS PASSED")
