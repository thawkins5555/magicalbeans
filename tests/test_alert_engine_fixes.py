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


# ==================================================================== A5
print("\nA5 — traps and syslog name the device that sent them")

nodes, alerts, snmp, syslog, ipam, engine = build()
add_device(nodes, "10.5.0.1", "core-sw-a")
add_device(nodes, "10.5.0.2", "edge-sw-b")
engine._tick()

# Same rule, restricted to the core switch. Both sources send the same trap
# and the same message, so only the device identity can tell them apart.
trap_rule = alerts.rule_by_key("trap_cold_start")
alerts.update_rule(trap_rule["id"], device_filter="core")
syslog_rule = alerts.rule_by_key("syslog_critical")
alerts.update_rule(syslog_rule["id"], device_filter="core")

for ip in ("10.5.0.1", "10.5.0.2"):
    seed_trap(snmp, ip, "1.3.6.1.6.3.1.1.5.1", "coldStart", severity=4,
              kind="coldStart")
    seed_syslog(syslog, ip, "%SYS-2-MALLOCFAIL: Memory allocation failed",
                severity=2)
engine._tick()

trap_alerts = open_rows(alerts, "trap_cold_start")
assert len(trap_alerts) == 1, [dict(a) for a in trap_alerts]
assert "core-sw-a" in trap_alerts[0]["entity_label"], dict(trap_alerts[0])
ok(f"device_filter matches a trap by its sender ({trap_alerts[0]['entity_label']!r})")

syslog_alerts = open_rows(alerts, "syslog_critical")
assert len(syslog_alerts) == 1, [dict(a) for a in syslog_alerts]
assert "core-sw-a" in syslog_alerts[0]["entity_label"], dict(syslog_alerts[0])
ok("device_filter matches a syslog message by its sender, not the other one")

assert "coldStart" in trap_alerts[0]["entity_label"], dict(trap_alerts[0])
ok("a trap alert's label names both the sender and the trap")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ==================================================================== A4
print("\nA4 — trap and syslog alert identity, and the severity gate")

LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
for ip in ("10.6.0.1", "10.6.0.2"):
    seed_trap(snmp, ip, LINK_DOWN, "linkDown", severity=3, kind="linkDown",
              varbinds="ifIndex 7")
engine._tick()
unmanaged = open_rows(alerts, "trap_link_down_unmanaged")
assert len(unmanaged) == 2, [dict(a) for a in unmanaged]
assert {a["entity_id"] for a in unmanaged} == {f"10.6.0.{i}:{LINK_DOWN}"
                                               for i in (1, 2)}, \
    [a["entity_id"] for a in unmanaged]
ok("the same trap OID from two senders opens two alerts, each naming its source")

# trap_critical ships at severity 2 and matches every trap; the default trap
# severity is 5, so an informational vendor trap must no longer reach it.
seed_trap(snmp, "10.6.0.3", "1.3.6.1.4.1.9.9.43.2.0.1",
          "ciscoConfigManEvent", severity=6, kind="")
engine._tick()
assert open_rows(alerts, "trap_critical", "10.6.0.3:1.3.6.1.4.1.9.9.43.2.0.1") == []
ok("a severity-6 config-save trap no longer opens \"Critical SNMP trap received\"")

seed_trap(snmp, "10.6.0.4", "1.3.6.1.4.1.9.9.43.2.0.2", "vendorPanic",
          severity=1, kind="")
engine._tick()
assert len(open_rows(alerts, "trap_critical",
                     "10.6.0.4:1.3.6.1.4.1.9.9.43.2.0.2")) == 1
ok("a severity-1 trap still does")

# coldStart ships at severity 4 while an unmapped trap decodes as 5; the gate
# must not apply to a rule that already names one trap.
seed_trap(snmp, "10.6.0.5", "1.3.6.1.6.3.1.1.5.1", "coldStart", severity=5,
          kind="coldStart")
engine._tick()
assert len(open_rows(alerts, "trap_cold_start")) == 1
ok("a rule naming one trap is not subject to the severity gate")

# A managed sender must not raise the "unmanaged device" rule.
add_device(nodes, "10.6.1.1", "managed-sw")
seed_trap(snmp, "10.6.1.1", LINK_DOWN, "linkDown", severity=3,
          kind="linkDown", varbinds="ifIndex 3")
engine._tick()
assert open_rows(alerts, "trap_link_down_unmanaged", f"10.6.1.1:{LINK_DOWN}") == []
ok("a link-down trap from a device we poll raises no \"unmanaged\" alert")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ---- syslog identity
nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
host = "10.6.2.1"
for port in ("Gi0/1", "Gi0/9"):
    seed_syslog(syslog, host,
                f"%LINK-3-UPDOWN: Interface {port}, changed state to down",
                severity=2)
engine._tick()
link_rows = [a for a in open_rows(alerts, "syslog_critical")
             if a["entity_id"].endswith("%LINK-3-UPDOWN")]
assert len(link_rows) == 1, [dict(a) for a in link_rows]
assert link_rows[0]["count"] == 2, dict(link_rows[0])
ok("two ports bouncing on one switch are one alert with count 2")

seed_syslog(syslog, host,
            "%LINEPROTO-5-UPDOWN: Line protocol on Gi0/1 changed state to down",
            severity=2)
engine._tick()
assert len(open_rows(alerts, "syslog_critical")) == 2, \
    [a["entity_id"] for a in open_rows(alerts, "syslog_critical")]
ok("a different mnemonic on the same host opens its own alert")

for n in (123, 456):
    seed_syslog(syslog, host, f"session {n} failed to establish", severity=2)
engine._tick()
hashed = [a for a in open_rows(alerts, "syslog_critical")
          if ":h" in a["entity_id"]]
assert len(hashed) == 1 and hashed[0]["count"] == 2, [dict(a) for a in hashed]
ok("two messages that differ only in their digits share one alert")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ---- the upgrade migration, against a database written with the old keys
folder = os.path.join(TMPDIR, "rekey")
os.makedirs(folder, exist_ok=True)
legacy_path = os.path.join(folder, "alerts.db")
legacy = AlertsDatabase(legacy_path)
syslog_rule = legacy.rule_by_key("syslog_critical")
trap_rule = legacy.rule_by_key("trap_critical")
now = time.time()
conn = sqlite3.connect(legacy_path)
conn.execute(
    "UPDATE schema_migrations SET name = 'x_' || name")   # replay the migration
for dedup, kind, entity, message in (
        (f"{syslog_rule['key']}:syslog:10.7.0.1", "syslog", "10.7.0.1",
         "%SYS-2-MALLOCFAIL: Memory allocation of 1032 bytes failed"),
        (f"{syslog_rule['key']}:syslog:10.7.0.2", "syslog", "10.7.0.2",
         "%OSPF-4-ERRRCV: Received invalid packet"),
        (f"{trap_rule['key']}:trap:1.3.6.1.6.3.1.1.5.3", "trap",
         "1.3.6.1.6.3.1.1.5.3", "ifIndex 199")):
    conn.execute(
        "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
        " entity_label, severity, message, detail, opened_ts, last_ts)"
        " VALUES (?,?,?,?,?,2,?,'',?,?)",
        (syslog_rule["id"] if kind == "syslog" else trap_rule["id"], dedup,
         kind, entity, entity, message, now, now))
conn.commit(); conn.close()
legacy.close()

upgraded = AlertsDatabase(legacy_path)
open_now = upgraded.alerts(state="unresolved")
assert len(open_now) == 2, [dict(a) for a in open_now]
assert all(a["entity_kind"] == "syslog" for a in open_now), \
    [dict(a) for a in open_now]
for row in open_now:
    assert row["dedup_key"].count(":") >= 3, row["dedup_key"]
    assert row["entity_id"].startswith("10.7.0."), row["entity_id"]
ok("upgrading re-keys open syslog alerts in place, keeping their history")

trap_row = [a for a in upgraded.alerts(state="resolved")
            if a["entity_kind"] == "trap"]
assert len(trap_row) == 1 and trap_row[0]["resolved_by"] == "", \
    [dict(a) for a in trap_row]
assert "keyed per source device" in (trap_row[0]["rollup_note"] or "")
ok("an open trap alert whose source was never stored is resolved with an "
   "explanation")

upgraded.close()
again = AlertsDatabase(legacy_path)
assert len(again.alerts(state="unresolved")) == 2
ok("the migration is idempotent — reopening changes nothing")
again.close()


# ==================================================================== A6
print("\nA6 — momentary-event rules resolve themselves")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
did = add_device(nodes, "10.8.0.1", "core-sw-a")

up_rule = alerts.rule_by_key("device_up")
assert up_rule["auto_resolve_after_s"] == 3600, dict(up_rule)
down_rule = alerts.rule_by_key("device_down")
assert down_rule["auto_resolve_after_s"] is None, dict(down_rule)
ok("a recovery notice ships with a one-hour lifetime; an outage ships with none")

nodes.record_device_event(did, "up", "responding again")
nodes.record_device_event(did, "rebooted", "uptime went backwards")
engine._tick()
recovered = open_rows(alerts, "device_up", did)
rebooted = open_rows(alerts, "device_rebooted", did)
assert len(recovered) == 1 and len(rebooted) == 1
alerts.acknowledge(rebooted[0]["id"], "operator", "known maintenance")

engine._sweep_expired()
assert len(open_rows(alerts, "device_up", did)) == 1, "not due yet"

# Back-date both past their intervals (device_up 1 h, device_rebooted 24 h).
conn = sqlite3.connect(alerts.path)
conn.execute("UPDATE alerts SET last_ts = last_ts - 200000")
conn.commit(); conn.close()
engine._tick()
assert open_rows(alerts, "device_up", did) == []
ok("an open recovery notice expires once its interval has passed")

assert open_rows(alerts, "device_rebooted", did) == []
assert alerts.alert(rebooted[0]["id"])["state"] == "resolved"
assert alerts.alert(rebooted[0]["id"])["resolved_by"] == ""
ok("an acknowledged alert expires too, with resolved_by ''")

# A state rule with no interval must never expire, however old.
nodes.record_device_event(did, "down", "stopped responding")
engine._tick()
down = open_rows(alerts, "device_down", did)
assert len(down) == 1
conn = sqlite3.connect(alerts.path)
conn.execute("UPDATE alerts SET last_ts = last_ts - 5000000 WHERE id = ?",
             (down[0]["id"],))
conn.commit(); conn.close()
engine._tick()
assert len(open_rows(alerts, "device_down", did)) == 1
ok("a NULL interval never expires, so a device still down stays open")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ---- IPAM: resolving the conflict resolves its alert
nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
ipam.record_conflict("10.8.1.5", "aa:bb:cc:dd:ee:01",
                     "aa:bb:cc:dd:ee:02", "arp")
conflict_id = ipam.conflicts()[0]["id"]
engine._tick()
conflict_alerts = open_rows(alerts, "ipam_new_conflict", conflict_id)
assert len(conflict_alerts) == 1, [dict(a) for a in conflict_alerts]
ipam.resolve_conflict(conflict_id)
engine._tick()
assert open_rows(alerts, "ipam_new_conflict", conflict_id) == []
closed = alerts.alert(conflict_alerts[0]["id"])
assert closed["state"] == "resolved" and closed["resolved_by"] == "", dict(closed)
ok("marking an IPAM conflict resolved resolves its alert")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ---- an existing database gets the intervals on upgrade
folder = os.path.join(TMPDIR, "autoresolve")
os.makedirs(folder, exist_ok=True)
legacy_path = os.path.join(folder, "alerts.db")
legacy = AlertsDatabase(legacy_path)
legacy.close()
conn = sqlite3.connect(legacy_path)
conn.execute("UPDATE rules SET auto_resolve_after_s = NULL")
conn.execute("DELETE FROM schema_migrations WHERE name = 'seed_auto_resolve_1'")
# One rule an operator deliberately took the interval off.
conn.execute("UPDATE rules SET auto_resolve_after_s = 120 WHERE key = 'device_up'")
conn.commit(); conn.close()
upgraded = AlertsDatabase(legacy_path)
assert upgraded.rule_by_key("poll_overrun")["auto_resolve_after_s"] == 3600
assert upgraded.rule_by_key("device_up")["auto_resolve_after_s"] == 120
ok("upgrading seeds the shipped intervals and leaves an operator's own alone")
upgraded.close()


# ==================================================================== A7
print("\nA7 — one keyed metrics query, and stale samples read as absent")

nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
did = add_device(nodes, "10.9.0.1", "ap-bridge")
old_ts = time.time() - 45 * 86400
for _ in range(3):
    nodes.record_metric_sample(did, "cpu_pct", "CPU", "%", "gauge", old_ts, 97.0)
    engine._tick()
assert open_rows(alerts, "cpu_high", did) == [], \
    "a 45-day-old sample must not open an alert"
ok("a 45-day-old sample opens nothing, however long the engine runs")

# An alert already open must NOT be resolved by the device going quiet: that
# is device_down's job, and a silent recovery would be a lie.
base = time.time()
for offset in (0, 65):
    nodes.record_metric_sample(did, "cpu_pct", "CPU", "%", "gauge",
                               base + offset, 97.0)
    engine._tick()
live = open_rows(alerts, "cpu_high", did)
assert len(live) == 1, [dict(a) for a in live]
conn = sqlite3.connect(nodes.path)
conn.execute("UPDATE metrics SET last_ts = last_ts - 86400 WHERE device_id = ?",
             (did,))
conn.commit(); conn.close()
for _ in range(3):
    engine._tick()
still = open_rows(alerts, "cpu_high", did)
assert len(still) == 1 and still[0]["id"] == live[0]["id"], [dict(a) for a in still]
ok("an alert already open survives its metric going stale")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ---- one statement against `metrics` per tick, at 50 devices
nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
base = time.time()
for i in range(50):
    device_id = add_device(nodes, f"10.9.1.{i + 1}", f"acc-sw-{i:02d}")
    for key, label in (("cpu_pct", "CPU"), ("mem_pct", "Memory"),
                       ("ping_rtt_ms", "RTT"), ("ping_loss_pct", "Loss")):
        nodes.record_metric_sample(device_id, key, label, "%", "gauge", base, 5.0)

statements = []
nodes._conn.set_trace_callback(statements.append)   # the engine's own connection
try:
    engine._tick()
finally:
    nodes._conn.set_trace_callback(None)
from_metrics = [q for q in statements if "FROM metrics" in q]
assert len(from_metrics) == 1, from_metrics
ok(f"one FROM metrics statement per tick at 50 devices "
   f"(was 50; {len(statements)} statements in total)")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ---- streak state does not outlive the devices it is about
nodes, alerts, snmp, syslog, ipam, engine = build()
engine._tick()
base = time.time()
victims = [add_device(nodes, f"10.9.2.{i + 1}", f"tmp-sw-{i}") for i in range(5)]
for device_id in victims:
    nodes.record_metric_sample(device_id, "cpu_pct", "CPU", "%", "gauge",
                               base, 20.0)
engine._tick()
assert engine._breach_streaks, "the streaks were never built"
for device_id in victims:
    nodes.remove_device(device_id)
engine._tick()
assert engine._breach_streaks == {}, engine._breach_streaks
ok("streak state for a deleted device is dropped rather than leaked")

nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()
