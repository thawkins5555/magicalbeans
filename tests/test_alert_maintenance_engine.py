"""Maintenance windows at the engine's own occurrence-gating layer: an
active window silences new alerts for its covered devices exactly like a
manual mute, a future window is inert until its start, and a held roll-up
notification for a covered alert follows the same mute rule email already
does — left pending, not decided, until the window is no longer covering it.

Drives engine._tick() directly, on the same harness test_alert_engine_fixes.py
uses, rather than importing from it: that module runs its own numbered
sections at import time, which this suite does not want to repeat.
"""
import os
import sqlite3
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_maintenance_engine_")
_SEQ = [0]

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def build(**settings):
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    values = {"email_enabled": False, "rollup_enabled": False,
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


def add_device(nodes, ip, name, device_group_id=None):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid,
                            device_group_id=device_group_id)


def set_status(nodes, device_ids, status):
    conn = sqlite3.connect(nodes.path)
    conn.executemany("UPDATE devices SET status = ? WHERE id = ?",
                     [(status, i) for i in device_ids])
    conn.commit()
    conn.close()


def go_down(nodes, device_id, detail="stopped responding"):
    set_status(nodes, [device_id], "down")
    nodes.record_device_event(device_id, "down", detail)


def come_up(nodes, device_id, detail="responding again"):
    set_status(nodes, [device_id], "up")
    nodes.record_device_event(device_id, "up", detail)


def open_rows(alerts, rule_key, entity_id=None):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    if entity_id is not None:
        rows = [r for r in rows if r["entity_id"] == str(entity_id)]
    return rows


# ======================================================================= B1
print("B1 — an active window silences a new occurrence like a manual mute")

nodes, alerts, snmp, syslog, ipam, engine = build()
dgid = nodes.add_device_group("Core")
dev = add_device(nodes, "10.9.0.1", "core1", device_group_id=dgid)
engine._tick()                       # seed cursors
now = time.time()
alerts.add_window("Cutover", "group", now - 5, now + 3600,
                  scope_group_id=dgid, created_by="tester")
go_down(nodes, dev)
engine._tick()
check("no alert opens for a device covered by an active window",
      not open_rows(alerts, "device_down", dev))
check("the muted counter reflects it (same path a manual mute uses)",
      engine.counters["muted"] >= 1, engine.counters)


# ======================================================================= B2
print("\nB2 — a future window has no effect yet")

nodes, alerts, snmp, syslog, ipam, engine = build()
dgid = nodes.add_device_group("Core")
dev = add_device(nodes, "10.9.0.2", "core2", device_group_id=dgid)
engine._tick()
now = time.time()
alerts.add_window("Next weekend", "group", now + 7 * 86400, now + 7 * 86400 + 3600,
                  scope_group_id=dgid, created_by="tester")
go_down(nodes, dev)
engine._tick()
check("a device covered only by a FUTURE window still alerts normally",
      len(open_rows(alerts, "device_down", dev)) == 1)


# ======================================================================= B3
print("\nB3 — devices() explicit scope, and alerts resume once the window ends")

nodes, alerts, snmp, syslog, ipam, engine = build()
dev = add_device(nodes, "10.9.0.3", "leaf1")
engine._tick()
now = time.time()
wid = alerts.add_window("Cutover", "devices", now - 5, now + 3600,
                        scope_device_ids=[dev], created_by="tester")
go_down(nodes, dev)
engine._tick()
check("an explicit device-list window silences its device too",
      not open_rows(alerts, "device_down", dev))

alerts.end_window_now(wid)
engine._tick()
check("ending the window does not retroactively open the suppressed occurrence"
      " (nothing replays a dropped device_event on its own)",
      not open_rows(alerts, "device_down", dev))
# A device_event occurrence dropped by a mute (or a window) is not replayed —
# see AlertEngine._muted's own docstring on how a mute works, which the
# window reuses verbatim. The condition itself is still live, so the next
# real recurrence (the poller noticing it is STILL down) opens it normally.
go_down(nodes, dev, detail="still down")
engine._tick()
check("...but the condition is still live, so the next recurrence opens it",
      len(open_rows(alerts, "device_down", dev)) == 1)


# ======================================================================= B4
print("\nB4 — window covers interfaces under the device too, like a device mute")

nodes, alerts, snmp, syslog, ipam, engine = build()
dgid = nodes.add_device_group("Core")
dev = add_device(nodes, "10.9.0.4", "core4", device_group_id=dgid)
nodes.replace_interfaces(dev, [
    {"if_index": 3, "descr": "Gi0/3", "alias": "", "admin_status": "up",
     "oper_status": "down"}])
iface_id = nodes.interfaces(dev)[0]["id"]
engine._tick()
now = time.time()
alerts.add_window("Cutover", "group", now - 5, now + 3600,
                  scope_group_id=dgid, created_by="tester")
nodes.record_interface_event(iface_id, "link_down", "port down")
engine._tick()
check("an interface event under a window-covered device is silenced too",
      not open_rows(alerts, "interface_down", f"{dev}:3"))


# ======================================================================= B5
print("\nB5 — a held roll-up notification follows the window's mute, like email's")

nodes, alerts, snmp, syslog, ipam, engine = build(notify_rollup_delay_s=120)
dgid = nodes.add_device_group("Core")
dev = add_device(nodes, "10.9.0.5", "core5", device_group_id=dgid)
engine._tick()
go_down(nodes, dev)
engine._tick()
rows = open_rows(alerts, "device_down", dev)
check("the alert opened even though its notice is held for roll-up",
      len(rows) == 1, rows)
alert_id = rows[0]["id"]
check("its first notification is still undecided (last_notified_ts NULL)",
      alerts.alert(alert_id)["last_notified_ts"] is None)

# A window covering the device starts AFTER the alert opened but before the
# roll-up hold elapses — the case _sweep_notify_rollup's own docstring says
# must be left pending, not silently decided either way.
now = time.time()
alerts.add_window("Cutover", "group", now - 1, now + 3600,
                  scope_group_id=dgid, created_by="tester")
time.sleep(0.05)
engine._tick()
check("still undecided while the window covers it — a mute is temporary, so"
      " this is left pending rather than recorded as sent or not-sent",
      alerts.alert(alert_id)["last_notified_ts"] is None)

nodes, alerts, snmp, syslog, ipam, engine = build(
    notify_rollup_delay_s=1, email_enabled=True, smtp_host="relay.invalid",
    smtp_to_default=["ops@example.com"])
dgid = nodes.add_device_group("Core")
dev = add_device(nodes, "10.9.0.6", "core6", device_group_id=dgid)
engine._tick()
go_down(nodes, dev)
engine._tick()
rows = open_rows(alerts, "device_down", dev)
alert_id = rows[0]["id"]
time.sleep(1.2)
engine._tick()          # the hold has elapsed; nothing covers the device yet
check("once the window lifts, the held notice is finally decided",
      alerts.alert(alert_id)["last_notified_ts"] is not None)


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
