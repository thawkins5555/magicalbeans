"""device_events, interface_events, traps, syslog logs, ipam conflicts and
wireless ap_events are all INTEGER PRIMARY KEY with no AUTOINCREMENT, so
SQLite reuses ids after a delete drops a table's own max id. AlertEngine
reads each with `id > cursor`, which used to strand the cursor above that
new max forever. Two fixes, one section per source:

(a) AlertEngine._drain_from rewinds the cursor the moment a source's current
    max id falls below it (alertengine.py).
(b) each source's age-based prune keeps its own highest-id row, so a
    retention sweep can never cause that drop by itself (nodesdb.py,
    snmptrapdb.py, syslogdb.py, ipamdb.py, wirelessdb.py) -- but not the
    Settings "delete everything now" button, which empties the table on
    purpose and relies on (a) alone. syslog drains by the same cursor over
    the same kind of table, so it gets the same fix.

House style: a plain script, FAILS collects failed check() names, exit 1 if
anything failed.
"""
import os
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.wirelessdb import WirelessDatabase
from netpath import syslogparse

TMPDIR = _paths.tmpdir("alert_cursor_rewind_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def build(name):
    folder = os.path.join(TMPDIR, name)
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    alerts.save_settings({"email_enabled": False, "new_device_grace_s": 0})
    snmp = SnmpTrapDatabase(os.path.join(folder, "traps.db"))
    syslog = SyslogDatabase(os.path.join(folder, "syslog.db"))
    ipam = IpamDatabase(os.path.join(folder, "ipam.db"))
    wireless = WirelessDatabase(os.path.join(folder, "wireless.db"))
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp, syslog_db=syslog,
                         ipam_db=ipam, wireless_db=wireless)
    return nodes, alerts, snmp, syslog, ipam, wireless, engine


def add_device(nodes, ip, name):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid)


def evaluated(engine) -> int:
    return engine.counters["evaluated"]


# ==================================================================== device_events
print("device_events: delete-the-tail reuse, and prune-to-empty")

nodes, alerts, snmp, syslog, ipam, wireless, engine = build("device_events")
dev = add_device(nodes, "10.60.0.1", "dev-sw")
nodes.record_device_event(dev, "down", "seed")
engine._tick()   # seeds the cursor at the current max; seed row is not new
before = evaluated(engine)
nodes.record_device_event(dev, "up", "one")
engine._tick()
check("a plain new row is drained (sanity)", evaluated(engine) == before + 1,
      evaluated(engine))

# Simulate what a delete leaves behind: the table's own max id drops below
# the persisted cursor. The engine ticks every 5s regardless of activity, so
# it observes that dip (and rewinds) before the next row ever arrives.
max_id = nodes._conn.execute("SELECT MAX(id) FROM device_events").fetchone()[0]
nodes._conn.execute("DELETE FROM device_events WHERE id = ?", (max_id,))
nodes._conn.commit()
engine._tick()
before = evaluated(engine)
nodes.record_device_event(dev, "down", "reused id")
engine._tick()
check("device_events: a row that reused an id past the old cursor is still drained",
      evaluated(engine) == before + 1, evaluated(engine))

nodes.record_device_event(dev, "up", "before age prune")
engine._tick()
# Every row old enough to qualify under a real retention window -- proving
# the age prune would otherwise take them all, highest id included.
nodes._conn.execute("UPDATE device_events SET ts = ?", (time.time() - 200 * 86400,))
nodes._conn.commit()
nodes.prune(event_days=180)
remaining = nodes._conn.execute("SELECT COUNT(*) FROM device_events").fetchone()[0]
check("device_events: an age-based prune keeps exactly the highest-id row",
      remaining == 1, remaining)

# The Settings "delete everything now" button (event_days=0) empties the
# table completely instead -- a later insert relies on the cursor rewind
# alone, with no row left behind to lean on.
nodes.prune(event_days=0)
remaining = nodes._conn.execute("SELECT COUNT(*) FROM device_events").fetchone()[0]
check("device_events: the explicit purge empties the table completely",
      remaining == 0, remaining)
engine._tick()
before = evaluated(engine)
nodes.record_device_event(dev, "down", "after explicit purge")
engine._tick()
check("device_events: a row inserted right after an explicit purge to "
      "empty is still drained",
      evaluated(engine) == before + 1, evaluated(engine))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close(); wireless.close()


# ================================================================= interface_events
print("\ninterface_events: delete-the-tail reuse, and prune-to-empty")

nodes, alerts, snmp, syslog, ipam, wireless, engine = build("interface_events")
dev = add_device(nodes, "10.60.0.2", "if-sw")
result = nodes.replace_interfaces(dev, [{"if_index": 1, "descr": "Gi0/1"}])
iface_id = result["ids"][1]
nodes.record_interface_event(iface_id, "link_down", "seed")
engine._tick()
before = evaluated(engine)
nodes.record_interface_event(iface_id, "link_up", "one")
engine._tick()
check("a plain new row is drained (sanity)", evaluated(engine) == before + 1,
      evaluated(engine))

max_id = nodes._conn.execute("SELECT MAX(id) FROM interface_events").fetchone()[0]
nodes._conn.execute("DELETE FROM interface_events WHERE id = ?", (max_id,))
nodes._conn.commit()
engine._tick()
before = evaluated(engine)
nodes.record_interface_event(iface_id, "link_down", "reused id")
engine._tick()
check("interface_events: a row that reused an id past the old cursor is still drained",
      evaluated(engine) == before + 1, evaluated(engine))

nodes.record_interface_event(iface_id, "link_up", "before age prune")
engine._tick()
nodes._conn.execute("UPDATE interface_events SET ts = ?", (time.time() - 200 * 86400,))
nodes._conn.commit()
nodes.prune(event_days=180)
remaining = nodes._conn.execute("SELECT COUNT(*) FROM interface_events").fetchone()[0]
check("interface_events: an age-based prune keeps exactly the highest-id row",
      remaining == 1, remaining)

nodes.prune(event_days=0)   # the explicit purge: empties the table
remaining = nodes._conn.execute("SELECT COUNT(*) FROM interface_events").fetchone()[0]
check("interface_events: the explicit purge empties the table completely",
      remaining == 0, remaining)
engine._tick()
before = evaluated(engine)
nodes.record_interface_event(iface_id, "link_down", "after explicit purge")
engine._tick()
check("interface_events: a row inserted right after an explicit purge to "
      "empty is still drained",
      evaluated(engine) == before + 1, evaluated(engine))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close(); wireless.close()


# ============================================================================ traps
print("\ntraps: delete-the-tail reuse, and prune-to-empty")

nodes, alerts, snmp, syslog, ipam, wireless, engine = build("traps")


def seed_trap(ts=None):
    from netpath import trapdecode
    snmp.insert([trapdecode.Trap(
        ts=ts if ts is not None else time.time(), source="10.60.0.3", version=1,
        community="public", trap_oid="1.3.6.1.6.3.1.1.5.3", trap_name="linkDown",
        trap_kind="link_down", severity=5, generic=2, specific=0,
        enterprise="", agent_addr="10.60.0.3", uptime=0, is_inform=False,
        varbinds=[])])


seed_trap()
engine._tick()
before = evaluated(engine)
seed_trap()
engine._tick()
check("a plain new row is drained (sanity)", evaluated(engine) == before + 1,
      evaluated(engine))

max_id = snmp._conn.execute("SELECT MAX(id) FROM traps").fetchone()[0]
snmp._conn.execute("DELETE FROM traps WHERE id = ?", (max_id,))
snmp._conn.commit()
engine._tick()
before = evaluated(engine)
seed_trap()
engine._tick()
check("traps: a row that reused an id past the old cursor is still drained",
      evaluated(engine) == before + 1, evaluated(engine))

seed_trap()
engine._tick()
snmp._conn.execute("UPDATE traps SET ts = ?", (time.time() - 200 * 86400,))
snmp._conn.commit()
snmp.prune(retention_days=90, max_rows=0)   # a real retention window
remaining = snmp._conn.execute("SELECT COUNT(*) FROM traps").fetchone()[0]
check("traps: an age-based prune keeps exactly the highest-id row",
      remaining == 1, remaining)

snmp.prune(retention_days=0, max_rows=0)   # the explicit purge: empties the table
remaining = snmp._conn.execute("SELECT COUNT(*) FROM traps").fetchone()[0]
check("traps: the explicit purge empties the table completely",
      remaining == 0, remaining)
engine._tick()
before = evaluated(engine)
seed_trap()
engine._tick()
check("traps: a row inserted right after an explicit purge to empty is "
      "still drained",
      evaluated(engine) == before + 1, evaluated(engine))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close(); wireless.close()


# ========================================================================= logs
print("\nsyslog logs: delete-the-tail reuse, and prune-to-empty")

nodes, alerts, snmp, syslog, ipam, wireless, engine = build("logs")


def seed_log(ts=None, message="seed"):
    syslog.insert([syslogparse.LogEntry(
        ts=ts if ts is not None else time.time(), source="10.60.0.9",
        severity=1, app="sshd", message=message)])


seed_log(message="seed 1")
engine._tick()
before = evaluated(engine)
seed_log(message="one")
engine._tick()
check("a plain new row is drained (sanity)", evaluated(engine) == before + 1,
      evaluated(engine))

max_id = syslog._conn.execute("SELECT MAX(id) FROM logs").fetchone()[0]
syslog._conn.execute("DELETE FROM logs WHERE id = ?", (max_id,))
syslog._conn.commit()
engine._tick()
before = evaluated(engine)
seed_log(message="reused id")
engine._tick()
check("logs: a row that reused an id past the old cursor is still drained",
      evaluated(engine) == before + 1, evaluated(engine))

seed_log(message="before age prune")
engine._tick()
syslog._conn.execute("UPDATE logs SET ts = ?", (time.time() - 60 * 86400,))
syslog._conn.commit()
syslog.prune(retention_days=30, max_rows=0)   # a real retention window
remaining = syslog._conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
check("logs: an age-based prune keeps exactly the highest-id row",
      remaining == 1, remaining)

syslog.prune(retention_days=0, max_rows=0)   # the explicit purge: empties the table
remaining = syslog._conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
check("logs: the explicit purge empties the table completely",
      remaining == 0, remaining)
engine._tick()
before = evaluated(engine)
seed_log(message="after explicit purge")
engine._tick()
check("logs: a row inserted right after an explicit purge to empty is "
      "still drained",
      evaluated(engine) == before + 1, evaluated(engine))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close(); wireless.close()


# ======================================================================= conflicts
print("\nipam conflicts: delete-the-tail reuse, and prune-to-empty")

nodes, alerts, snmp, syslog, ipam, wireless, engine = build("conflicts")

ipam.record_conflict("10.60.0.4", "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", "scan")
engine._tick()
before = evaluated(engine)
ipam.record_conflict("10.60.0.5", "aa:aa:aa:aa:aa:03", "aa:aa:aa:aa:aa:04", "scan")
engine._tick()
check("a plain new row is drained (sanity)", evaluated(engine) == before + 1,
      evaluated(engine))

max_id = ipam._conn.execute("SELECT MAX(id) FROM conflicts").fetchone()[0]
ipam._conn.execute("DELETE FROM conflicts WHERE id = ?", (max_id,))
ipam._conn.commit()
engine._tick()
before = evaluated(engine)
ipam.record_conflict("10.60.0.6", "aa:aa:aa:aa:aa:05", "aa:aa:aa:aa:aa:06", "scan")
engine._tick()
check("conflicts: a row that reused an id past the old cursor is still drained",
      evaluated(engine) == before + 1, evaluated(engine))

# prune_conflicts only ever deletes RESOLVED rows -- resolve everything,
# backdated so a real retention window can reach them.
old_ts = time.time() - 200 * 86400
for row in ipam.conflicts():
    ipam.resolve_conflict(row["id"])
    ipam._conn.execute("UPDATE conflicts SET resolved_ts=? WHERE id=?",
                       (old_ts, row["id"]))
ipam._conn.commit()
ipam.prune_conflicts(older_than_days=180)   # a real retention window
remaining = ipam._conn.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0]
check("conflicts: an age-based prune keeps exactly the highest-id row",
      remaining == 1, remaining)

ipam.prune_conflicts(older_than_days=0)   # the explicit purge: empties the table
remaining = ipam._conn.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0]
check("conflicts: the explicit purge empties the table completely",
      remaining == 0, remaining)
engine._tick()
before = evaluated(engine)
ipam.record_conflict("10.60.0.7", "aa:aa:aa:aa:aa:07", "aa:aa:aa:aa:aa:08", "scan")
engine._tick()
check("conflicts: a row inserted right after an explicit purge to empty "
      "is still drained",
      evaluated(engine) == before + 1, evaluated(engine))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close(); wireless.close()


# ======================================================================= ap_events
print("\nwireless ap_events: delete-the-tail reuse, and prune-to-empty")

nodes, alerts, snmp, syslog, ipam, wireless, engine = build("ap_events")

wireless.add_ap_event(1, "wtp-1", "root", "ap-one", "removed", "seed")
engine._tick()
before = evaluated(engine)
wireless.add_ap_event(1, "wtp-2", "root", "ap-two", "removed", "one")
engine._tick()
check("a plain new row is drained (sanity)", evaluated(engine) == before + 1,
      evaluated(engine))

max_id = wireless._conn.execute("SELECT MAX(id) FROM ap_events").fetchone()[0]
wireless._conn.execute("DELETE FROM ap_events WHERE id = ?", (max_id,))
wireless._conn.commit()
engine._tick()
before = evaluated(engine)
wireless.add_ap_event(1, "wtp-3", "root", "ap-three", "removed", "reused id")
engine._tick()
check("ap_events: a row that reused an id past the old cursor is still drained",
      evaluated(engine) == before + 1, evaluated(engine))

wireless.add_ap_event(1, "wtp-4", "root", "ap-four", "removed", "before prune")
engine._tick()
time.sleep(0.05)
wireless.prune_ap_events(retention_days=0)
remaining = wireless._conn.execute("SELECT COUNT(*) FROM ap_events").fetchone()[0]
check("ap_events: prune-to-empty keeps exactly the highest-id row",
      remaining == 1, remaining)
before = evaluated(engine)
wireless.add_ap_event(1, "wtp-5", "root", "ap-five", "removed", "after prune")
engine._tick()
check("ap_events: a row inserted right after a full prune is drained",
      evaluated(engine) == before + 1, evaluated(engine))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close(); wireless.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
import sys
sys.exit(1 if FAILS else 0)
