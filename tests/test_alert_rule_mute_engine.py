"""Muting ONE rule on ONE device, at every engine gate the device-wide mute
already covers: no new alert for that rule on that box, nothing silenced on
any other box or rule, no recovery mail, no renotify reminder, and alerting
back when it expires or is lifted. R7 re-runs a plain device mute unchanged
— the per-rule gate must not have moved the device one. Harness shape from
tests/test_device_maintenance_engine.py.
"""
import os
import sqlite3
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertmail
from netpath.alertsdb import DEVICE_RULE_KIND, AlertsDatabase, device_rule_entity
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_rule_mute_engine_")
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


def add_device(nodes, ip, name):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid)


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


def mute_rule(alerts, device_id, rule_key, hours=6.0):
    return alerts.mute(DEVICE_RULE_KIND,
                       device_rule_entity(device_id, rule_key), hours,
                       by="tester", reason="one noisy rule")


def expire_mute(alerts, device_id, rule_key):
    """Backdate a live mute rather than waiting seven days for it."""
    conn = sqlite3.connect(alerts.path)
    conn.execute("UPDATE alert_mutes SET until_ts = ? WHERE entity_kind = ?"
                 " AND entity_id = ?",
                 (time.time() - 60, DEVICE_RULE_KIND,
                  device_rule_entity(device_id, rule_key)))
    conn.commit()
    conn.close()


class FakeMail:
    """Stands in for alertmail.send; what went out is only observable here."""

    def __init__(self):
        self.attempts = []

    def __call__(self, settings, password, to_addrs, subject, body, is_html):
        self.attempts.append(subject)


MAIL = {"email_enabled": True, "smtp_host": "relay.invalid",
        "smtp_to_default": ["noc@example.invalid"]}

PORTS = [
    {"if_index": 7, "descr": "GigabitEthernet1/0/7", "alias": "uplink to core",
     "admin_status": "up", "oper_status": "up"},
]


# ======================================================================= R1
print("R1 — one rule on one device goes quiet, and nothing else does")

nodes, alerts, snmp, syslog, ipam, engine = build()
d1 = add_device(nodes, "10.9.0.1", "core1")
d2 = add_device(nodes, "10.9.0.2", "core2")
engine._tick()                       # seed cursors
mute_rule(alerts, d1, "device_down")
go_down(nodes, d1)
go_down(nodes, d2)
nodes.record_device_event(d1, "rebooted", "uptime went backwards")
engine._tick()

check("no device_down alert opens for the device whose device_down is muted",
      not open_rows(alerts, "device_down", d1))
check("...and the rule_muted counter says which gate dropped it",
      engine.counters["rule_muted"] >= 1, engine.counters)
check("the device-wide muted counter is NOT what fired — this device is not"
      " muted, one of its rules is",
      engine.counters["muted"] == 0, engine.counters)
check("the SAME rule on another device still opens",
      len(open_rows(alerts, "device_down", d2)) == 1,
      [dict(r) for r in open_rows(alerts, "device_down")])
check("ANOTHER rule on the same device still opens",
      len(open_rows(alerts, "device_rebooted", d1)) == 1,
      [dict(r) for r in open_rows(alerts, "device_rebooted")])


# ======================================================================= R2
print("\nR2 — a port's alert is silenced by a rule muted on its switch")

nodes, alerts, snmp, syslog, ipam, engine = build()
did = add_device(nodes, "10.9.1.1", "access-sw")
nodes.replace_interfaces(did, PORTS)
engine._tick()
port_id = [i for i in nodes.interfaces(did) if i["if_index"] == 7][0]["id"]
mute_rule(alerts, did, "interface_down")
nodes.record_interface_event(port_id, "link_down", "Gi1/0/7: up -> down")
engine._tick()
check("an INTERFACE occurrence is silenced by a rule muted on the switch the"
      " port is on — the same resolution a device mute uses",
      not open_rows(alerts, "interface_down"),
      [dict(r) for r in open_rows(alerts, "interface_down")])

alerts.unmute(DEVICE_RULE_KIND, device_rule_entity(did, "interface_down"))
nodes.record_interface_event(port_id, "link_down", "Gi1/0/7: up -> down again")
engine._tick()
check("...and the next link-down opens once the mute is lifted",
      len(open_rows(alerts, "interface_down")) == 1)


# ======================================================================= R3
print("\nR3 — an alert open before the mute still resolves, with no mail")

real_send = alertmail.send
nodes, alerts, snmp, syslog, ipam, engine = build(notify_on_clear=True, **MAIL)
sent = FakeMail()
alertmail.send = sent
try:
    dev = add_device(nodes, "10.9.2.1", "core3")
    engine._tick()
    go_down(nodes, dev)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    alert_id = open_rows(alerts, "device_down", dev)[0]["id"]
    check("the opening alert did send a message, so this case can tell"
          " 'silenced' from 'mail was never working'",
          len(sent.attempts) == 1, sent.attempts)
    before = len(sent.attempts)
    # Both halves: the open rule, and the one the recovery event raises.
    mute_rule(alerts, dev, "device_down")
    mute_rule(alerts, dev, "device_up")
    come_up(nodes, dev)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("the alert still RESOLVES — the list stays truthful whatever the"
          " mute says", alerts.alert(alert_id)["state"] == "resolved")
    check("...and NO recovery mail went out",
          len(sent.attempts) == before, sent.attempts)
    check("...with no 'clear' notification recorded either",
          not [n for n in alerts.notifications_for(alert_id) if n["kind"] == "clear"],
          [dict(n) for n in alerts.notifications_for(alert_id)])
finally:
    alertmail.send = real_send


# ======================================================================= R4
print("\nR4 — no renotify reminder while the rule is muted, one after")

nodes, alerts, snmp, syslog, ipam, engine = build(renotify_minutes=1, **MAIL)
sent = FakeMail()
alertmail.send = sent
try:
    dev = add_device(nodes, "10.9.3.1", "core4")
    engine._tick()
    go_down(nodes, dev)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    alert_id = open_rows(alerts, "device_down", dev)[0]["id"]
    stamp = time.time() - 7200
    alerts.mark_notified(alert_id, stamp)
    before = len(sent.attempts)
    mute_rule(alerts, dev, "device_down")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("no reminder is sent while this alert's rule is muted on this device",
          len(sent.attempts) == before, sent.attempts)
    check("...and last_notified_ts is untouched, so the reminder is still due"
          " the moment the mute lifts",
          abs(alerts.alert(alert_id)["last_notified_ts"] - stamp) < 1.0,
          alerts.alert(alert_id)["last_notified_ts"] - stamp)

    alerts.unmute(DEVICE_RULE_KIND, device_rule_entity(dev, "device_down"))
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("...and one reminder goes out once it is lifted",
          len(sent.attempts) == before + 1, sent.attempts)
finally:
    alertmail.send = real_send


# ======================================================================= R5
print("\nR5 — an expired mute alerts again, with nothing to un-suppress")

nodes, alerts, snmp, syslog, ipam, engine = build()
dev = add_device(nodes, "10.9.4.1", "core5")
engine._tick()
mute_rule(alerts, dev, "device_down")
go_down(nodes, dev)
engine._tick()
check("silenced while the mute is live", not open_rows(alerts, "device_down", dev))

expire_mute(alerts, dev, "device_down")
go_down(nodes, dev, detail="still down")
engine._tick()
check("**an expired mute reads as no mute — the next occurrence opens**",
      len(open_rows(alerts, "device_down", dev)) == 1,
      [dict(r) for r in open_rows(alerts, "device_down", dev)])


# ======================================================================= R6
print("\nR6 — unmute lifts it immediately")

nodes, alerts, snmp, syslog, ipam, engine = build()
dev = add_device(nodes, "10.9.5.1", "core6")
engine._tick()
mute_rule(alerts, dev, "device_down")
go_down(nodes, dev)
engine._tick()
check("silenced", not open_rows(alerts, "device_down", dev))
lifted = alerts.unmute(DEVICE_RULE_KIND, device_rule_entity(dev, "device_down"))
go_down(nodes, dev, detail="still down")
engine._tick()
check("unmute reports it lifted something", lifted)
check("...and the next occurrence opens",
      len(open_rows(alerts, "device_down", dev)) == 1)


# ======================================================================= R7
print("\nR7 — a plain device mute is unchanged by any of the above")

nodes, alerts, snmp, syslog, ipam, engine = build()
dev = add_device(nodes, "10.9.6.1", "core7")
other = add_device(nodes, "10.9.6.2", "core8")
engine._tick()
alerts.mute("device", str(dev), 6.0, by="tester")
go_down(nodes, dev)
nodes.record_device_event(dev, "rebooted", "uptime went backwards")
go_down(nodes, other)
engine._tick()
check("a device mute still silences EVERY rule on that device",
      not open_rows(alerts, "device_down", dev)
      and not open_rows(alerts, "device_rebooted", dev))
check("...through the device gate, not the new per-rule one",
      engine.counters["muted"] >= 1 and engine.counters["rule_muted"] == 0,
      engine.counters)
check("...and leaves other devices alone",
      len(open_rows(alerts, "device_down", other)) == 1)


print()
if FAILS:
    print("FAILURES: %d" % len(FAILS))
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("FAILURES: none")
