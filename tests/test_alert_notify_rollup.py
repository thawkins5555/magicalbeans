"""notify_rollup_delay_s: an alert opens immediately, as always, but its
FIRST email is held for the configured window and re-checked at flush time —
see AlertEngine._sweep_notify_rollup and _skip_held_open_notify. This is the
fix for the review's 499-device outage: 377 device-down alerts each opening
within seconds of the next, faster than the poll cycle could reach the core
switch behind all of them, produced 1,355 emails in 241 seconds and burned
the whole hourly budget before anyone could read any of them.

Structured like test_alert_engine_fixes.py: numbered sections sharing one
harness, driving engine._tick() by hand rather than a real thread so nothing
here is timing-dependent — "the window elapsed" is simulated by back-dating
opened_ts directly, the same trick test_alert_engine_fixes.py's A6 section
uses for auto-resolve intervals.
"""
import os
import sqlite3
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath import alertmail
from netpath.alertsdb import AlertsDatabase, NOTIFY_ROLLUP_DELAY_MAX_S
from netpath.alertengine import AlertEngine, DIGEST_THRESHOLD
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_notify_rollup_")
_SEQ = [0]

MAIL_SETTINGS = {"email_enabled": True, "smtp_host": "relay.invalid",
                 "smtp_to_default": ["noc@example.invalid"]}


def build(**settings):
    """(nodes, alerts, snmp, syslog, ipam, engine, folder) on fresh temp
    databases, with email on and a 240 s roll-up hold by default — the
    opposite defaults from test_alert_engine_fixes.py's build(), because
    this suite is specifically about what happens during and after that
    hold. `folder` is returned so a section that wants a second engine
    against the same files (the restart section) does not have to
    reconstruct the paths by hand."""
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    values = {"rollup_enabled": False, "new_device_grace_s": 0,
              "notify_rollup_delay_s": 240, "max_emails_per_hour": 60}
    values.update(MAIL_SETTINGS)
    values.update(settings)
    alerts.save_settings(values)
    snmp = SnmpTrapDatabase(os.path.join(folder, "traps.db"))
    syslog = SyslogDatabase(os.path.join(folder, "syslog.db"))
    ipam = IpamDatabase(os.path.join(folder, "ipam.db"))
    netpath_db = NetpathDatabase(os.path.join(folder, "netpath.db"))
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp,
                         syslog_db=syslog, ipam_db=ipam, netpath_db=netpath_db)
    return nodes, alerts, snmp, syslog, ipam, engine, folder


def reopen_engine(folder):
    """A second AlertEngine (and its own NodesDatabase handle) against the
    SAME database files build() already wrote — what a process restart
    looks like: fresh Python objects, same rows on disk."""
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
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


def open_rows(alerts, rule_key, entity_id=None):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    if entity_id is not None:
        rows = [r for r in rows if r["entity_id"] == str(entity_id)]
    return rows


def backdate_opened(alerts, alert_id, seconds: float) -> None:
    """Make an alert look `seconds` older than it is, without a real sleep —
    exactly what elapsing the roll-up window means to alerts_due_first_notify,
    which reads opened_ts."""
    conn = sqlite3.connect(alerts.path)
    conn.execute("UPDATE alerts SET opened_ts = opened_ts - ? WHERE id = ?",
                 (seconds, alert_id))
    conn.commit()
    conn.close()


class FakeMail:
    """Stands in for alertmail.send. Records every attempt's (subject, body,
    to_addrs) rather than just counting, so a section can check a digest's
    contents, not only that exactly one was sent."""

    def __init__(self):
        self.attempts = []
        self.fail = False

    def __call__(self, settings, password, to_addrs, subject, body, is_html):
        self.attempts.append((subject, body, list(to_addrs)))
        if self.fail:
            raise OSError("relay refused the connection")


real_send = alertmail.send

PASSED = []


def ok(line):
    PASSED.append(line)
    print("  " + line + " OK")


def close_all(nodes, alerts, snmp, syslog, ipam, engine):
    engine.stop()
    nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ============================================================ 1: passthrough
print("1 — notify_rollup_delay_s=0 is an exact passthrough")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(notify_rollup_delay_s=0)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.20.0.1", "core-sw-a")
    nodes.record_device_event(did, "down", "stopped responding")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    down = open_rows(alerts, "device_down", did)
    assert len(down) == 1, [dict(a) for a in down]
    assert len(sent.attempts) == 1, sent.attempts
    kinds = [n["kind"] for n in alerts.notifications_for(down[0]["id"])]
    assert kinds == ["alert"], kinds
    assert down[0]["last_notified_ts"] is not None
    ok("at delay 0 the first email goes out on the very tick the alert opens")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ================================================= 2: held, then flushed
print("\n2 — a held alert emails nothing until the window elapses, then sends")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(notify_rollup_delay_s=240)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.20.1.1", "core-sw-b")
    nodes.record_device_event(did, "down", "stopped responding")
    engine._tick()
    down = open_rows(alerts, "device_down", did)
    assert len(down) == 1, [dict(a) for a in down]
    alert_id = down[0]["id"]
    assert engine._mail.wait_idle(10.0)
    assert sent.attempts == [], sent.attempts
    assert alerts.notifications_for(alert_id) == []
    assert alerts.alert(alert_id)["last_notified_ts"] is None
    ok("the alert opens immediately but its first email does not go out")

    engine._tick()          # still inside the window: nothing changes
    assert engine._mail.wait_idle(10.0)
    assert sent.attempts == []
    ok("ticking again inside the window still sends nothing")

    backdate_opened(alerts, alert_id, 241)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert len(sent.attempts) == 1, sent.attempts
    subject, body, to_addrs = sent.attempts[0]
    assert "core-sw-b" in subject, subject
    assert to_addrs == ["noc@example.invalid"], to_addrs
    kinds = [n["kind"] for n in alerts.notifications_for(alert_id)]
    assert kinds == ["alert"], kinds
    assert alerts.alert(alert_id)["last_notified_ts"] is not None
    ok("once the window has elapsed the flush sends exactly the held email")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ==================================================== 3: cleared in-window
print("\n3 — an alert that clears inside the window sends nothing at all")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(notify_rollup_delay_s=240)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.20.2.1", "edge-sw-c")
    nodes.record_device_event(did, "down", "stopped responding")
    engine._tick()
    down = open_rows(alerts, "device_down", did)
    alert_id = down[0]["id"]

    nodes.record_device_event(did, "up", "responding again")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert alerts.alert(alert_id)["state"] == "resolved"
    assert sent.attempts == [], sent.attempts
    ok("neither the open notice nor a recovery notice is ever mailed")

    notes = alerts.notifications_for(alert_id)
    assert len(notes) == 1, [dict(n) for n in notes]
    assert notes[0]["kind"] == "alert" and notes[0]["ok"] == 0
    assert "cleared within the roll-up window" in notes[0]["error"], dict(notes[0])
    ok("the alert's own history records why, exactly once")

    # And it must not be re-decided by a later flush sweep, now that it is
    # already resolved with its decision made.
    for _ in range(3):
        engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert len(alerts.notifications_for(alert_id)) == 1
    ok("the decision is not repeated on later ticks")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ============================================ 4: absorbed under a rollup parent
print("\n4 — an alert absorbed by a rollup parent inside the window sends nothing")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(
    notify_rollup_delay_s=240, rollup_enabled=True)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    core = add_device(nodes, "10.20.3.1", "core-sw-d")
    leaf = add_device(nodes, "10.20.3.2", "acc-sw-d")
    nodes.update_device(leaf, upstream_id=core)

    # The downstream device is noticed down first — the exact race the
    # review's 499-device outage hit: a poll cycle reaches the leaves before
    # it reaches the core that explains all of them.
    nodes.record_device_event(leaf, "down", "stopped responding")
    engine._tick()
    leaf_alert = open_rows(alerts, "device_down", leaf)
    assert len(leaf_alert) == 1, [dict(a) for a in leaf_alert]
    leaf_id = leaf_alert[0]["id"]
    assert alerts.alert(leaf_id)["last_notified_ts"] is None

    nodes.record_device_event(core, "down", "stopped responding")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    leaf_now = alerts.alert(leaf_id)
    assert leaf_now["state"] == "resolved" and leaf_now["resolved_by"] == "", \
        dict(leaf_now)
    assert sent.attempts == [], sent.attempts
    ok("the downstream alert is absorbed and its held email never goes out")

    notes = alerts.notifications_for(leaf_id)
    assert len(notes) == 1, [dict(n) for n in notes]
    assert notes[0]["ok"] == 0
    assert "rolled up under" in notes[0]["error"] and "core-sw-d" in notes[0]["error"], \
        dict(notes[0])
    ok(f"the reason names the outage it rolled up under: {notes[0]['error']!r}")

    # The core's own alert survived and is still waiting on its own window —
    # rollup absorbing the leaf must not also let the core jump the queue.
    core_alert = open_rows(alerts, "device_down", core)
    assert len(core_alert) == 1
    assert alerts.notifications_for(core_alert[0]["id"]) == []
    ok("the surviving parent alert's own held notice is unaffected")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ============================== 5: still open, covered by a parent at flush
print("\n5 — the flush sweep re-checks roll-up cover live, not just at open")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(
    notify_rollup_delay_s=240, rollup_enabled=False)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    core = add_device(nodes, "10.20.4.1", "core-sw-e")
    leaf = add_device(nodes, "10.20.4.2", "acc-sw-e")
    nodes.update_device(leaf, upstream_id=core)

    # Rollup is off while both come down, so both open as their own alerts —
    # nothing suppresses or absorbs the leaf at any point while it is off.
    nodes.record_device_event(core, "down", "stopped responding")
    nodes.record_device_event(leaf, "down", "stopped responding")
    engine._tick()
    leaf_id = open_rows(alerts, "device_down", leaf)[0]["id"]
    assert alerts.alert(leaf_id)["last_notified_ts"] is None

    # An operator turns rollup on mid-incident, before the leaf's window is
    # up. Nothing re-processed the already-open leaf alert when that
    # happened — the live check at flush time is what has to catch it.
    alerts.save_settings({"rollup_enabled": True})
    backdate_opened(alerts, leaf_id, 241)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert sent.attempts == [], sent.attempts
    notes = alerts.notifications_for(leaf_id)
    assert len(notes) == 1 and notes[0]["ok"] == 0, [dict(n) for n in notes]
    assert "rolled up under" in notes[0]["error"] and "core-sw-e" in notes[0]["error"], \
        dict(notes[0])
    assert alerts.alert(leaf_id)["state"] == "open", \
        "the flush sweep decides notification only, never alert state"
    ok("a still-open alert newly covered by a parent is caught at flush, "
       "and stays open — only its held email is cancelled")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ===================================================== 6: muted, left pending
print("\n6 — a device muted after its alert opened is left pending, not decided")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(notify_rollup_delay_s=240)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.20.5.1", "acc-sw-f")
    nodes.record_device_event(did, "down", "stopped responding")
    engine._tick()
    alert_id = open_rows(alerts, "device_down", did)[0]["id"]
    alerts.mute("device", did, 1.0, by="operator", reason="known maintenance")

    backdate_opened(alerts, alert_id, 241)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert sent.attempts == []
    assert alerts.notifications_for(alert_id) == []
    assert alerts.alert(alert_id)["last_notified_ts"] is None
    ok("a muted device's due alert sends nothing and is not marked decided")

    alerts.unmute("device", did)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert len(sent.attempts) == 1, sent.attempts
    kinds = [n["kind"] for n in alerts.notifications_for(alert_id)]
    assert kinds == ["alert"], kinds
    ok("once unmuted, the still-pending held notice is delivered")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ============================================== 7: coalesced into one digest
print("\n7 — more than DIGEST_THRESHOLD sendable alerts become one digest email")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(notify_rollup_delay_s=60)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    count = DIGEST_THRESHOLD + 2
    ids = [add_device(nodes, f"10.20.6.{i + 1}", f"acc-sw-g{i}")
          for i in range(count)]
    for device_id in ids:
        nodes.record_device_event(device_id, "down", "stopped responding")
    engine._tick()
    rows = {r["entity_id"]: r for r in open_rows(alerts, "device_down")}
    assert len(rows) == count, [dict(r) for r in rows.values()]
    for row in rows.values():
        backdate_opened(alerts, row["id"], 61)
    engine._tick()
    assert engine._mail.wait_idle(10.0)

    assert len(sent.attempts) == 1, sent.attempts
    subject, body, to_addrs = sent.attempts[0]
    assert str(count) in subject and "alerts opened in the last" in subject, subject
    for name in (f"acc-sw-g{i}" for i in range(count)):
        assert name in body, (name, body)
    ok(f"{count} alerts due at once produce exactly one digest email "
       f"({subject!r})")

    assert len(engine._sent_this_hour) == 1, engine._sent_this_hour
    ok("the digest counts once against max_emails_per_hour, not once per alert")

    per_alert = [alerts.notifications_for(r["id"]) for r in rows.values()]
    assert all(len(notes) == 1 and notes[0]["kind"] == "alert" and notes[0]["ok"] == 1
              for notes in per_alert), per_alert
    assert all(alerts.alert(r["id"])["last_notified_ts"] is not None
              for r in rows.values())
    ok("every alert in the digest gets its own sent notification row")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ---- DIGEST_THRESHOLD or fewer still send individually, unchanged
nodes, alerts, snmp, syslog, ipam, engine, folder = build(notify_rollup_delay_s=60)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    ids = [add_device(nodes, f"10.20.7.{i + 1}", f"acc-sw-h{i}")
          for i in range(DIGEST_THRESHOLD)]
    for device_id in ids:
        nodes.record_device_event(device_id, "down", "stopped responding")
    engine._tick()
    rows = list(open_rows(alerts, "device_down"))
    assert len(rows) == DIGEST_THRESHOLD
    for row in rows:
        backdate_opened(alerts, row["id"], 61)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert len(sent.attempts) == DIGEST_THRESHOLD, sent.attempts
    subjects = [subject for subject, _b, _t in sent.attempts]
    assert all("is not responding" in s for s in subjects), subjects
    ok(f"exactly {DIGEST_THRESHOLD} due alerts still send their own "
       f"individual, template-rendered emails")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# =================================================== 8: restart-safe hold
print("\n8 — a held alert survives an engine restart and still sends after "
      "the window")

nodes, alerts, snmp, syslog, ipam, engine, folder = build(notify_rollup_delay_s=240)
try:
    engine._tick()
    did = add_device(nodes, "10.20.8.1", "core-sw-i")
    nodes.record_device_event(did, "down", "stopped responding")
    engine._tick()
    alert_id = open_rows(alerts, "device_down", did)[0]["id"]
    assert alerts.alert(alert_id)["last_notified_ts"] is None
finally:
    engine.stop()
    nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()

# A brand new set of Python objects against the same files — what the
# process restarting mid-hold looks like.
nodes, alerts, snmp, syslog, ipam, engine = reopen_engine(folder)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()               # inside the window still: nothing to send
    assert engine._mail.wait_idle(10.0)
    assert sent.attempts == []
    ok("immediately after reopening, still inside the window, nothing sends")

    backdate_opened(alerts, alert_id, 241)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    assert len(sent.attempts) == 1, sent.attempts
    ok("the new engine instance finds the same due alert from the row "
       "itself — last_notified_ts IS NULL — and sends it, no in-memory "
       "queue required")
finally:
    alertmail.send = real_send
close_all(nodes, alerts, snmp, syslog, ipam, engine)


# ==================================================== 9: settings round-trip
print("\n9 — settings round-trip, defaults, and clamping")

nodes, alerts, snmp, syslog, ipam, engine, folder = build()
try:
    assert alerts.settings()["notify_rollup_delay_s"] == 240
    ok("the shipped default is 240 s (4 minutes)")

    alerts.save_settings({"notify_rollup_delay_s": 30})
    assert alerts.settings()["notify_rollup_delay_s"] == 30
    ok("an ordinary value round-trips")

    alerts.save_settings({"notify_rollup_delay_s": 999999})
    assert alerts.settings()["notify_rollup_delay_s"] == NOTIFY_ROLLUP_DELAY_MAX_S, \
        alerts.settings()["notify_rollup_delay_s"]
    ok(f"an oversized value clamps to {NOTIFY_ROLLUP_DELAY_MAX_S}")

    alerts.save_settings({"notify_rollup_delay_s": -50})
    assert alerts.settings()["notify_rollup_delay_s"] == 0
    ok("a negative value clamps to 0, the same as an explicit 0")

    alerts.save_settings({"notify_rollup_delay_s": 0})
    assert alerts.settings()["notify_rollup_delay_s"] == 0
    ok("0 round-trips as 0 (the disabled state), not back to the default")
finally:
    close_all(nodes, alerts, snmp, syslog, ipam, engine)


print(f"\n{len(PASSED)} checks passed")
