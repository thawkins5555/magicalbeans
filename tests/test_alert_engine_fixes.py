"""The alert-engine correctness fixes of 4.37.0, each section proving one
finding from the alerting review is closed.

Structured as numbered sections that share one harness (`build()` returns
the six objects the engine needs plus the engine) and are otherwise
independent — each builds its own temporary databases, so a failure in one
cannot cascade into the next. Drives `engine._tick()` directly rather than
starting the engine thread: every fix here is about what one tick does, and
a real thread would make the assertions time-dependent.
"""
import json
import os
import sqlite3
import threading
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath import alertmail
from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.alertrules import Occurrence
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase
from netpath import syslogparse
from netpath import trapdecode

TMPDIR = _paths.tmpdir("alert_engine_fixes_")
_SEQ = [0]


def build(**settings):
    """(nodes, alerts, snmp, syslog, ipam, engine) on fresh temp databases.

    Email is off and the new-device hold is disabled by default: both would
    give an occurrence a reason to be dropped that has nothing to do with
    what any section here is testing. A section that wants email says so.
    """
    _SEQ[0] += 1
    folder = os.path.join(TMPDIR, f"case{_SEQ[0]}")
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    values = {"email_enabled": False, "rollup_enabled": False,
              "new_device_grace_s": 0}
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


def open_rows(alerts, rule_key, entity_id=None):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    if entity_id is not None:
        rows = [r for r in rows if r["entity_id"] == str(entity_id)]
    return rows


def seed_trap(snmp, source, oid, name, severity=5, kind="", varbinds="",
              ts=None):
    """One trap row written the way the receiver writes them."""
    snmp.insert([trapdecode.Trap(
        ts=ts if ts is not None else time.time(), source=source, version=1,
        community="public", trap_oid=oid, trap_name=name, trap_kind=kind,
        severity=severity, varbind_text=varbinds)])


def seed_syslog(syslog, source, message, severity=2, host="", ts=None):
    syslog.insert([syslogparse.LogEntry(
        ts=ts if ts is not None else time.time(), source=source,
        facility=16, severity=severity, host=host or source,
        message=message, raw=message)])


PASSED = []


def ok(line):
    PASSED.append(line)
    print("  " + line + " OK")


# ==================================================================== A9
print("A9 — duration and clock text")

assert alertmail.duration_text(0.4) == "", alertmail.duration_text(0.4)
assert alertmail.duration_text(0.0) == ""
assert alertmail.duration_text(-3) == ""
ok("a sub-second outage renders as nothing, not \"0 s\"")

assert alertmail.duration_text(0.6) == "1 s", alertmail.duration_text(0.6)
assert alertmail.duration_text(59.6) == "1 m 00 s", alertmail.duration_text(59.6)
assert alertmail.duration_text(48) == "48 s"
ok("rounding happens before the units are chosen (0.6 -> 1 s, 59.6 -> 1 m 00 s)")

stamp = alertmail.clock_text(time.time())
offset = time.strftime("%z", time.localtime())
assert stamp.endswith(offset) and len(offset) == 5, (stamp, offset)
assert alertmail.clock_text(0) == ""
ok(f"every email timestamp carries its UTC offset ({stamp})")


# ==================================================================== A1
print("\nA1 — cursors advance only after the batch is applied")

nodes, alerts, snmp, syslog, ipam, engine = build()
# Three identical cold-start traps from three switches. Any occurrence would
# do; a trap is the cheapest source to seed and needs no device row.
engine._tick()                       # seeds every cursor, evaluates nothing
for ip in ("10.1.0.1", "10.1.0.2", "10.1.0.3"):
    seed_trap(snmp, ip, "1.3.6.1.6.3.1.1.5.1", "coldStart", severity=4,
              kind="coldStart")

trace = []
real_apply = engine._apply
real_set_cursor = alerts.set_cursor
boom = {"n": 0}


def apply_spy(rules, occurrence, settings):
    boom["n"] += 1
    trace.append(("apply", occurrence.entity_id))
    if boom["n"] == 2:
        raise RuntimeError("boom in _apply")
    return real_apply(rules, occurrence, settings)


def set_cursor_spy(source, value):
    trace.append(("set_cursor", source, value))
    return real_set_cursor(source, value)


engine._apply = apply_spy
alerts.set_cursor = set_cursor_spy
engine._tick()
engine._apply = real_apply
alerts.set_cursor = real_set_cursor

opened = [a for a in alerts.alerts(state="unresolved")
          if a["entity_kind"] == "trap"]
assert engine.counters["apply_errors"] == 1, engine.counters
assert len(opened) == 2, [dict(a) for a in opened]
ok("one poisoned occurrence is skipped; the other two still open alerts")

assert alerts.cursor("traps") == snmp.max_id() == 3, \
    (alerts.cursor("traps"), snmp.max_id())
ok("the cursor still reaches max_id, so the batch is never re-read")

applies = [i for i, e in enumerate(trace) if e[0] == "apply"]
cursors = [i for i, e in enumerate(trace) if e[0] == "set_cursor"]
assert applies and cursors, trace
assert max(applies) < min(cursors), trace
ok("every apply precedes the first set_cursor of the tick")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# A batch bigger than one read: the drain must page forward inside one tick
# rather than leaving the rest for later ticks.
nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
for i in range(2500):
    seed_trap(snmp, "10.2.0.9", "1.3.6.1.6.3.1.1.5.1", "coldStart",
              severity=4, kind="coldStart")
engine._tick()
assert alerts.cursor("traps") == snmp.max_id() == 2500, \
    (alerts.cursor("traps"), snmp.max_id())
assert engine.counters["backlog"] == 0, engine.counters
ok("2,500 rows behind the cursor are drained in one tick, backlog 0")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ==================================================================== A2
print("\nA2 — SMTP off the tick, with a breaker")


class FakeMail:
    """Stands in for alertmail.send. Counts attempts, fails on demand, and
    can block so a shutdown with a wedged relay can be timed."""

    def __init__(self):
        self.attempts = []
        self.fail = False
        self.block = threading.Event()

    def __call__(self, settings, password, to_addrs, subject, body, is_html):
        self.attempts.append(subject)
        if self.block.is_set():
            time.sleep(30)
        if self.fail:
            raise OSError("relay refused the connection")


MAIL_SETTINGS = {"email_enabled": True, "smtp_host": "relay.invalid",
                 "smtp_to_default": ["noc@example.invalid"]}

nodes, alerts, snmp, syslog, ipam, engine = build(**MAIL_SETTINGS)
fake = FakeMail()
fake.fail = True
real_send = alertmail.send
alertmail.send = fake
try:
    engine._mail.cooldown_s = 900.0
    engine._tick()
    did = add_device(nodes, "10.3.0.1", "core-sw-a")
    # Six separate outages, one per device: each opens its own alert and so
    # submits its own message.
    ids = [did] + [add_device(nodes, f"10.3.0.{i}", f"acc-sw-{i}")
                   for i in range(2, 8)]
    for device_id in ids:
        nodes.record_device_event(device_id, "down", "stopped responding")
    engine._tick()
    assert engine._mail.wait_idle(10.0), "mail queue never went idle"

    assert len(fake.attempts) == 5, len(fake.attempts)
    ok("the breaker stops attempting after 5 consecutive failures "
       f"({len(ids)} alerts, {len(fake.attempts)} attempts)")

    failed = [n for aid in [a["id"] for a in alerts.alerts(state="unresolved")]
              for n in alerts.notifications_for(aid) if not n["ok"]]
    assert len(failed) == len(ids), [dict(f) for f in failed]
    assert sum(1 for f in failed if "not attempted" in (f["error"] or "")) == 2, \
        [f["error"] for f in failed]
    ok("every alert carries its own failed-notification row, "
       "including the ones never attempted")

    assert len(engine._sent_this_hour) == len(ids), engine._sent_this_hour
    ok("the hourly quota counts attempts, so a dead relay is rationed")

    engine._tick()          # raises the queued smtp_failing occurrence
    smtp_rows = open_rows(alerts, "smtp_failing")
    assert len(smtp_rows) == 1, [dict(r) for r in smtp_rows]
    assert smtp_rows[0]["severity"] == 2, dict(smtp_rows[0])
    assert alerts.notifications_for(smtp_rows[0]["id"]) == [], \
        "a system alert must never try to email about email"
    ok("the mail path raises its own alert, and that alert sends no email")

    # The cooldown elapses and the relay comes back: the next job is the
    # half-open probe, and its success closes the breaker.
    fake.fail = False
    engine._mail.cooldown_s = 0.0
    nodes.record_device_event(ids[0], "up", "responding again")
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    engine._tick()          # drains the queued clear
    assert alerts.rule_by_key("smtp_failing") is not None
    resolved = [a for a in alerts.alerts(state="resolved")
                if a["entity_kind"] == "system"]
    assert len(resolved) == 1, [dict(r) for r in resolved]
    assert resolved[0]["resolved_by"] == "", dict(resolved[0])
    assert open_rows(alerts, "smtp_failing") == []
    ok("a successful half-open probe closes the breaker and resolves the "
       "alert with resolved_by ''")
finally:
    alertmail.send = real_send
engine.stop()
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# A wedged relay must not make shutdown look like a hang.
nodes, alerts, snmp, syslog, ipam, engine = build(**MAIL_SETTINGS)
blocker = FakeMail()
blocker.block.set()
alertmail.send = blocker
try:
    engine._tick()
    blocked_device = add_device(nodes, "10.3.9.9", "wedged-sw")
    nodes.record_device_event(blocked_device, "down", "stopped responding")
    engine._tick()
    for _ in range(200):                      # let the worker pick the job up
        if blocker.attempts:
            break
        time.sleep(0.01)
    assert blocker.attempts, "the worker never started the blocked send"
    started = time.monotonic()
    engine.stop()
    elapsed = time.monotonic() - started
    assert elapsed < 2.5, elapsed
    ok(f"stop() returns in {elapsed:.2f}s with a send blocked on a dead relay")
finally:
    alertmail.send = real_send
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ==================================================================== A3
print("\nA3 — renotify actually fires")

nodes, alerts, snmp, syslog, ipam, engine = build(
    renotify_minutes=1, **MAIL_SETTINGS)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.4.0.1", "core-sw-a")
    base = time.time()
    # cpu_high: threshold 90, clear 80, for_polls 2 — a threshold rule, so
    # the alert also has extras worth rendering in the renotify.
    for offset in (0, 65):
        nodes.record_metric_sample(did, "cpu_pct", "CPU", "%", "gauge",
                                   base + offset, 97.0)
        engine._tick()
    assert engine._mail.wait_idle(10.0)
    opened = open_rows(alerts, "cpu_high", did)
    assert len(opened) == 1, [dict(o) for o in opened]
    alert_id = opened[0]["id"]
    kinds = [n["kind"] for n in alerts.notifications_for(alert_id)]
    assert kinds == ["alert"], kinds
    ok("the first breach sends exactly one message")

    # Twenty more minutes of breaching polls: under the old code this was the
    # reproduction that produced one email and a count of 228.
    for i in range(1, 21):
        nodes.record_metric_sample(did, "cpu_pct", "CPU", "%", "gauge",
                                   base + 65 + i * 60, 97.0)
        engine._tick()
    assert engine._mail.wait_idle(10.0)
    kinds = [n["kind"] for n in alerts.notifications_for(alert_id)]
    assert kinds == ["alert"], kinds
    ok("nothing is re-sent while the renotify interval has not elapsed")

    alerts.mark_notified(alert_id, time.time() - 3600)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    notes = alerts.notifications_for(alert_id)
    renotifies = [n for n in notes if n["kind"] == "renotify"]
    assert len(renotifies) == 1, [dict(n) for n in notes]
    ok("once the interval has elapsed the sweep sends a renotify")

    assert "97.0" in renotifies[0]["subject"], renotifies[0]["subject"]
    ok("a threshold renotify still renders {{value}} from the stored extras")

    alerts.acknowledge(alert_id, "operator", "on it")
    alerts.mark_notified(alert_id, time.time() - 3600)
    engine._tick()
    assert engine._mail.wait_idle(10.0)
    after = [n for n in alerts.notifications_for(alert_id) if n["kind"] == "renotify"]
    assert len(after) == 1, [dict(n) for n in after]
    ok("an acknowledged alert is never re-notified about")
finally:
    alertmail.send = real_send
engine.stop()
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# The case the occurrence path could never serve: an event-driven rule that
# produces exactly one occurrence and then nothing at all.
nodes, alerts, snmp, syslog, ipam, engine = build(
    renotify_minutes=1, **MAIL_SETTINGS)
sent = FakeMail()
alertmail.send = sent
try:
    engine._tick()
    did = add_device(nodes, "10.4.1.1", "edge-sw-b")
    nodes.record_device_event(did, "down", "stopped responding")
    engine._tick()
    down = open_rows(alerts, "device_down", did)
    assert len(down) == 1, [dict(d) for d in down]
    alerts.mark_notified(down[0]["id"], time.time() - 3600)
    for _ in range(3):                 # no further events of any kind
        engine._tick()
    assert engine._mail.wait_idle(10.0)
    kinds = [n["kind"] for n in alerts.notifications_for(down[0]["id"])]
    assert kinds.count("renotify") == 1, kinds
    ok("a device that stays down is re-notified about with no new event")
finally:
    alertmail.send = real_send
engine.stop()
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()
