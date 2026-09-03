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
