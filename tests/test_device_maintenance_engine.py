"""Indefinite maintenance mode at the engine's gates: no new alert, no mail
of any kind (the recovery message included), no renotify reminder, and a
held first notice DECIDED with a reason rather than left waiting for a
moment that never arrives. Open alerts stay open and listed, and polling —
occurrence draining — carries on regardless.

Every maintenance case is paired with its MUTE twin, because two of these
gates did not exist before this release and the mute is what they must not
have changed: _sweep_renotify had no suppression check at all, and the
first-notify sweep is deliberately left byte-for-byte as it was for a mute
(a mute ends, so its notice waits) while maintenance is decided (it does
not, so a waiting notice would wait for ever).

Same harness shape as tests/test_alert_maintenance_engine.py.
"""
import os
import sqlite3
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertmail
from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("device_maintenance_engine_")
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


def notes(alerts, alert_id):
    return [n["error"] or "" for n in alerts.notifications_for(alert_id)]


class FakeMail:
    """Stands in for alertmail.send, the same stub test_alert_engine.py
    uses: the relay is never reached in a test, so what actually went out is
    only observable here."""

    def __init__(self):
        self.attempts = []

    def __call__(self, settings, password, to_addrs, subject, body, is_html):
        self.attempts.append(subject)


MAIL = {"email_enabled": True, "smtp_host": "relay.invalid",
        "smtp_to_default": ["noc@example.invalid"]}


# ======================================================================= M1
print("M1 — a device in maintenance raises no new alert, and keeps polling")

nodes, alerts, snmp, syslog, ipam, engine = build()
dev = add_device(nodes, "10.8.0.1", "core1")
engine._tick()                       # seed cursors
alerts.set_maintenance(dev, by="tester", reason="rack rewire")
go_down(nodes, dev)
engine._tick()
check("no alert opens for a device in maintenance mode",
      not open_rows(alerts, "device_down", dev))
check("the muted counter reflects it — one gate, three mechanisms",
      engine.counters["muted"] >= 1, engine.counters)
check("occurrences are still DRAINED, not left to pile up: polling and its"
      " event stream carry on exactly as before",
      engine.counters["evaluated"] >= 1, engine.counters)

alerts.clear_maintenance(dev, by="tester")
go_down(nodes, dev, detail="still down")
engine._tick()
check("...and ending maintenance lets the next recurrence open normally",
      len(open_rows(alerts, "device_down", dev)) == 1)


# ======================================================================= M2
print("\nM2 — an alert open BEFORE maintenance stays open and listed")

nodes, alerts, snmp, syslog, ipam, engine = build()
dev = add_device(nodes, "10.8.0.2", "core2")
engine._tick()
go_down(nodes, dev)
engine._tick()
rows = open_rows(alerts, "device_down", dev)
check("the alert opened while nothing was suppressing it", len(rows) == 1, rows)
alert_id = rows[0]["id"]

alerts.set_maintenance(dev, by="tester")
engine._tick()
check("it is STILL open after maintenance started — maintenance stops what"
      " happens next, it never takes work off the operator's screen",
      alerts.alert(alert_id)["state"] == "open")
check("...and still in the unresolved list",
      any(r["id"] == alert_id for r in open_rows(alerts, "device_down", dev)))


# ======================================================================= M3
print("\nM3 — no mail of any kind, the recovery message included")

for label, silence in (("maintenance", "maintenance"), ("mute", "mute")):
    nodes, alerts, snmp, syslog, ipam, engine = build(notify_on_clear=True, **MAIL)
    sent = FakeMail()
    real_send = alertmail.send
    alertmail.send = sent
    try:
        dev = add_device(nodes, "10.8.1.1", "core3")
        engine._tick()
        go_down(nodes, dev)
        engine._tick()
        assert engine._mail.wait_idle(10.0)
        alert_id = open_rows(alerts, "device_down", dev)[0]["id"]
        check(f"[{label}] the opening alert did send a message, so this suite"
              " can tell 'silenced' from 'mail was never working'",
              len(sent.attempts) == 1, sent.attempts)
        before = len(sent.attempts)
        if silence == "maintenance":
            alerts.set_maintenance(dev, by="tester")
        else:
            alerts.mute("device", str(dev), 6.0, by="tester")
        come_up(nodes, dev)
        engine._tick()
        assert engine._mail.wait_idle(10.0)
        check(f"[{label}] the alert still RESOLVES — the list stays truthful",
              alerts.alert(alert_id)["state"] == "resolved")
        check(f"[{label}] ...and NO recovery mail went out",
              len(sent.attempts) == before, sent.attempts)
    finally:
        alertmail.send = real_send


# ======================================================================= M4
print("\nM4 — no renotify reminder while a device is silenced")

for label, silence in (("maintenance", "maintenance"), ("mute", "mute")):
    nodes, alerts, snmp, syslog, ipam, engine = build(renotify_minutes=1, **MAIL)
    sent = FakeMail()
    real_send = alertmail.send
    alertmail.send = sent
    try:
        dev = add_device(nodes, "10.8.2.1", "core4")
        engine._tick()
        go_down(nodes, dev)
        engine._tick()
        assert engine._mail.wait_idle(10.0)
        alert_id = open_rows(alerts, "device_down", dev)[0]["id"]
        # Backdate the last notice so the alert is unambiguously due for a
        # reminder on the very next tick.
        stamp = time.time() - 7200
        alerts.mark_notified(alert_id, stamp)
        before = len(sent.attempts)
        if silence == "maintenance":
            alerts.set_maintenance(dev, by="tester")
        else:
            alerts.mute("device", str(dev), 6.0, by="tester")
        engine._tick()
        assert engine._mail.wait_idle(10.0)
        check(f"[{label}] **no reminder is sent while the device is silenced**",
              len(sent.attempts) == before, sent.attempts)
        check(f"[{label}] ...and last_notified_ts is untouched, so nothing is"
              " stranded — the alert is still due the moment silence lifts",
              abs(alerts.alert(alert_id)["last_notified_ts"] - stamp) < 1.0,
              alerts.alert(alert_id)["last_notified_ts"] - stamp)

        if silence == "maintenance":
            alerts.clear_maintenance(dev)
        else:
            alerts.unmute("device", str(dev))
        engine._tick()
        assert engine._mail.wait_idle(10.0)
        check(f"[{label}] ...and one reminder does go out once it lifts",
              len(sent.attempts) == before + 1, sent.attempts)
    finally:
        alertmail.send = real_send


# ======================================================================= M5
print("\nM5 — the held first notice: maintenance is DECIDED, a mute still waits")

nodes, alerts, snmp, syslog, ipam, engine = build(
    notify_rollup_delay_s=1, email_enabled=True, smtp_host="relay.invalid",
    smtp_to_default=["ops@example.com"])
dev = add_device(nodes, "10.8.3.1", "core5")
engine._tick()
go_down(nodes, dev)
engine._tick()
alert_id = open_rows(alerts, "device_down", dev)[0]["id"]
check("its first notification is held, undecided (last_notified_ts NULL)",
      alerts.alert(alert_id)["last_notified_ts"] is None)
alerts.set_maintenance(dev, by="tester")
time.sleep(1.2)
engine._tick()
check("**the held notice is decided once the hold elapses, not left pending"
      " — maintenance mode has no deadline to wait for**",
      alerts.alert(alert_id)["last_notified_ts"] is not None)
check("...with a reason that names maintenance, so the pane does not read"
      " a bare 'None sent.' with nothing saying why",
      any("maintenance" in text for text in notes(alerts, alert_id)),
      notes(alerts, alert_id))

nodes, alerts, snmp, syslog, ipam, engine = build(
    notify_rollup_delay_s=1, email_enabled=True, smtp_host="relay.invalid",
    smtp_to_default=["ops@example.com"])
dev = add_device(nodes, "10.8.3.2", "core6")
engine._tick()
go_down(nodes, dev)
engine._tick()
alert_id = open_rows(alerts, "device_down", dev)[0]["id"]
alerts.mute("device", str(dev), 6.0, by="tester")
time.sleep(1.2)
engine._tick()
check("[mute] the held notice is STILL pending — a mute ends, so a device"
      " unmuted before anyone sees this should still get the notice",
      alerts.alert(alert_id)["last_notified_ts"] is None)

alerts.unmute("device", str(dev))
engine._tick()
check("[mute] ...and it is finally decided once the mute is lifted",
      alerts.alert(alert_id)["last_notified_ts"] is not None)


# ======================================================================= M6
print("\nM6 — clearing maintenance re-arms the notice it decided")

HOLD = {"notify_rollup_delay_s": 1, "renotify_minutes": 0}


def held_case(ip, name):
    """One device with one open alert whose first notice is held, mail
    stubbed. Re-notify is OFF — the default — which is the whole point:
    _sweep_renotify returns before it looks at anything, so the first-notify
    sweep is the only path that can ever send this notice."""
    nodes, alerts, snmp, syslog, ipam, engine = build(**HOLD, **MAIL)
    sent = FakeMail()
    alertmail.send = sent
    dev = add_device(nodes, ip, name)
    engine._tick()
    go_down(nodes, dev)
    engine._tick()
    alert_id = open_rows(alerts, "device_down", dev)[0]["id"]
    return alerts, engine, dev, alert_id, sent


real_send = alertmail.send
try:
    alerts, engine, dev, alert_id, sent = held_case("10.8.4.1", "core7")
    alerts.set_maintenance(dev, by="tester")
    time.sleep(1.2)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("the held notice is decided while maintenance is on, and nothing"
          " is mailed", alerts.alert(alert_id)["last_notified_ts"] is not None
          and not sent.attempts, sent.attempts)

    alerts.clear_maintenance(dev, by="tester")
    check("**clearing maintenance re-arms it — a notice skipped for a"
          " two-minute cable move is not lost for good**",
          alerts.alert(alert_id)["last_notified_ts"] is None)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("...and the next sweep sends it, EXACTLY once, with re-notify off",
          len(sent.attempts) == 1, sent.attempts)

    alerts.set_maintenance(dev, by="tester")
    alerts.clear_maintenance(dev, by="tester")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("...and a second maintenance toggle does not re-arm a notice that"
          " has already gone out", len(sent.attempts) == 1, sent.attempts)

    # Notified for real BEFORE maintenance: the clear must not repeat it.
    alerts, engine, dev, alert_id, sent = held_case("10.8.4.2", "core8")
    time.sleep(1.2)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    stamp = alerts.alert(alert_id)["last_notified_ts"]
    check("the notice went out before maintenance began",
          len(sent.attempts) == 1 and stamp is not None, sent.attempts)
    alerts.set_maintenance(dev, by="tester")
    engine._tick()
    alerts.clear_maintenance(dev, by="tester")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("**an alert genuinely notified before maintenance is not notified"
          " a second time when it clears**",
          len(sent.attempts) == 1
          and alerts.alert(alert_id)["last_notified_ts"] == stamp,
          sent.attempts)

    # The mute path, unchanged: still pending, and clearing a maintenance
    # the device was never in touches nothing.
    alerts, engine, dev, alert_id, sent = held_case("10.8.4.3", "core9")
    alerts.mute("device", str(dev), 6.0, by="tester")
    time.sleep(1.2)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("[mute] the held notice is still PENDING, exactly as before",
          alerts.alert(alert_id)["last_notified_ts"] is None and not sent.attempts,
          sent.attempts)
    check("[mute] clearing a maintenance the device was never in changes"
          " nothing", alerts.clear_maintenance(dev, by="tester") is False)
    alerts.unmute("device", str(dev))
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    check("[mute] ...and lifting the mute sends it once",
          len(sent.attempts) == 1, sent.attempts)
finally:
    alertmail.send = real_send

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
