"""AlertEngine._evaluate_thresholds is change-driven -- a full, fleet-wide
pass runs on the first tick, every _THRESHOLD_FULL_PASS_S, and
immediately when a rule or a device_thresholds override changes; every
other tick evaluates only the devices a new sample or an alert resolve
touched since the last one. This file pins the four behaviours the change
must hold exactly:

1. a tick with nothing dirty and no full pass due issues no metrics query
2. a device with a new breaching sample opens its alert the same tick
3. resolving an alert marks its device dirty, so a still-breaching rollup
   child re-derives on the VERY NEXT tick, not up to 60s late
4. editing a rule (or a device override) forces a full pass on the next tick

House style: a plain script, FAILS collects failed check() names, exit 1 if
anything failed.
"""
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase

TMPDIR = _paths.tmpdir("threshold_change_driven_")
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
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp,
                         syslog_db=syslog, ipam_db=ipam)
    return nodes, alerts, snmp, syslog, ipam, engine


def add_device(nodes, ip, name):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid)


def open_rows(alerts, rule_key, entity_id=None):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    if entity_id is not None:
        rows = [r for r in rows if r["entity_id"] == str(entity_id)]
    return rows


def sample_temp(nodes, device_id, ts, value_c):
    nodes.record_metric_sample(device_id, "temp_chassis_c", "Chassis temp",
                               "C", "gauge", ts, value_c)


# ============================================================ 1: no dirty, no query
print("1: a tick with nothing dirty and no full pass due issues no metrics query")

nodes, alerts, snmp, syslog, ipam, engine = build("no_dirty")
dev = add_device(nodes, "10.80.0.1", "quiet-sw")
sample_temp(nodes, dev, time.time(), 40.0)
engine._tick()   # first tick: always a full pass (forces one via the 0.0 default)

calls = []
real_fleet = nodes.metrics_for_families
real_scoped = nodes.metrics_for_families_and_devices
nodes.metrics_for_families = lambda *a, **kw: (calls.append("fleet"), real_fleet(*a, **kw))[1]
nodes.metrics_for_families_and_devices = (
    lambda *a, **kw: (calls.append("scoped"), real_scoped(*a, **kw))[1])
try:
    engine._tick()   # nothing changed since the full pass above: 0 dirty, not due yet
finally:
    nodes.metrics_for_families = real_fleet
    nodes.metrics_for_families_and_devices = real_scoped
check("no metrics query at all on a tick with nothing dirty", calls == [], calls)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# =================================================== 2: new breaching sample
print("\n2: a device with a new breaching sample opens its alert the same tick")

# temp_chassis_high ships for_polls=2, so this also proves a dirty pass
# counts polls exactly like a full pass would: no extra tick of delay, and
# no early opening either.
nodes, alerts, snmp, syslog, ipam, engine = build("new_breach")
dev = add_device(nodes, "10.80.0.2", "fresh-sw")
sample_temp(nodes, dev, time.time(), 40.0)
engine._tick()   # full pass, nowhere near breaching

base = time.time()
sample_temp(nodes, dev, base, 80.0)          # >= temp_chassis_high's 75C, poll 1
engine._tick()                               # dirty pass: only this device's sample
check("one breaching poll is not yet open (for_polls=2)",
      not open_rows(alerts, "temp_chassis_high", dev), None)
sample_temp(nodes, dev, base + 65, 80.0)     # poll 2
engine._tick()
check("the alert opens on the very tick its second breaching poll landed",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 1,
      open_rows(alerts, "temp_chassis_high", dev))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ======================================================== 3: resolve re-raises
print("\n3: resolving an alert marks its device dirty -- re-derived next tick")

# Whether the RE-DERIVED occurrence goes on to open (it may legitimately
# stay covered -- see test_temp_thresholds.py's "resolving Critical by hand
# does not re-open Warning") is _apply's rollup logic, unrelated to this
# change. What this pins is that _evaluate_thresholds runs for this device
# at all on the very next tick -- proven by `evaluated` moving with no new
# sample -- rather than being skipped as a tick with nothing dirty.
nodes, alerts, snmp, syslog, ipam, engine = build("resolve_reraise")
engine._tick()
dev = add_device(nodes, "10.80.0.3", "hot-sw")

base = time.time()
for offset in (0, 65):   # both rules ship for_polls=2
    sample_temp(nodes, dev, base + offset, 90.0)
    engine._tick()
critical_open = open_rows(alerts, "temp_chassis_critical", dev)
check("a device at 90 C opens Critical", len(critical_open) == 1, critical_open)
check("...and Warning starts out suppressed under it",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0, None)

engine._tick()   # settle: confirm a quiet tick with nothing new evaluates nothing
before = engine.counters["evaluated"]
engine._tick()
check("a quiet tick (nothing dirty, no full pass due) evaluates nothing "
      "(sanity, mirrors pin 1)", engine.counters["evaluated"] == before, None)

alerts.resolve(critical_open[0]["id"], by="operator")
check("Critical is resolved by hand", not open_rows(alerts, "temp_chassis_critical", dev), None)

# No new sample at all -- only the resolve above should make this device
# dirty. If it didn't, this tick has nothing dirty and nothing due, and
# skips evaluating this device entirely (pin 1's own behaviour).
before = engine.counters["evaluated"]
engine._tick()
check("the device is re-derived on the very next tick, off the resolve "
      "alone (no new sample) -- not up to 60s later on the next full pass",
      engine.counters["evaluated"] > before,
      (before, engine.counters["evaluated"]))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# =================================================== 4: rule change forces full pass
print("\n4: editing a rule forces a full pass on the very next tick")

nodes, alerts, snmp, syslog, ipam, engine = build("rule_change")
dev = add_device(nodes, "10.80.0.4", "edit-sw")
sample_temp(nodes, dev, time.time(), 40.0)
engine._tick()   # full pass; settles the generation this engine has seen
engine._tick()   # idle: nothing dirty, not due -- confirms the baseline is quiet

rule = alerts.rule_by_key("temp_chassis_high")
alerts.update_rule(rule["id"], threshold=90.0)   # bumps alertsdb's generation counter

calls = []
real_fleet = nodes.metrics_for_families
nodes.metrics_for_families = lambda *a, **kw: (calls.append(1), real_fleet(*a, **kw))[1]
try:
    engine._tick()   # still nothing dirty, but the rule changed underneath it
finally:
    nodes.metrics_for_families = real_fleet
check("a rule edit alone -- no dirty devices -- still forces the fleet-wide "
      "(full-pass) query on the next tick",
      calls == [1], calls)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
import sys
sys.exit(1 if FAILS else 0)
