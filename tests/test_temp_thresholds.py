"""Configurable chassis-temperature alerting: the temp_chassis_high /
temp_chassis_critical built-in pair (alertsdb._BUILTIN_RULES), the generic
device_thresholds override table and its AlertsDatabase accessors, and
AlertEngine._evaluate_thresholds honouring an override — its own numbers,
its enabled flag, and its clear_threshold — without resurrecting a stale
streak or opening the wrong alert twice. House style: a plain script, FAILS
collects failed check() names, exit 1 if anything failed.
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

TMPDIR = _paths.tmpdir("temp_thresholds_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_alerts_db(name: str) -> tuple:
    path = os.path.join(TMPDIR, f"{name}.db")
    return AlertsDatabase(path), path


def build(name: str):
    """(nodes, alerts, snmp, syslog, ipam, engine) on fresh temp databases.

    rollup_enabled stays True (the default): the Critical/Warning suppression
    this suite exercises IS a rollup, via alertrules.ROLLED_UP_BY.
    """
    folder = os.path.join(TMPDIR, name)
    os.makedirs(folder, exist_ok=True)
    nodes = NodesDatabase(os.path.join(folder, "nodes.db"))
    alerts = AlertsDatabase(os.path.join(folder, "alerts.db"))
    alerts.save_settings({"email_enabled": False, "new_device_grace_s": 0,
                          "notify_rollup_delay_s": 0})
    snmp = SnmpTrapDatabase(os.path.join(folder, "traps.db"))
    syslog = SyslogDatabase(os.path.join(folder, "syslog.db"))
    ipam = IpamDatabase(os.path.join(folder, "ipam.db"))
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp,
                         syslog_db=syslog, ipam_db=ipam)
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


def sample_temp(nodes, device_id, ts, value_c):
    nodes.record_metric_sample(device_id, "temp_chassis_c", "Chassis temp",
                               "C", "gauge", ts, value_c)


# ============================================================ seeding & upgrade
print("temp_chassis_high / temp_chassis_critical seeding")

db, path = new_alerts_db("seed")
high = db.rule_by_key("temp_chassis_high")
critical = db.rule_by_key("temp_chassis_critical")
check("temp_chassis_high still exists with its original shipped numbers",
      high is not None and high["threshold"] == 75.0 and high["clear_threshold"] == 65.0,
      dict(high) if high else None)
check("temp_chassis_critical is seeded as a new built-in threshold rule on temp_chassis_c",
      critical is not None and critical["kind"] == "threshold"
      and critical["source_kind"] == "temp_chassis_c",
      dict(critical) if critical else None)
check("temp_chassis_critical sits above temp_chassis_high (85/78 vs 75/65)",
      critical is not None and critical["threshold"] == 85.0
      and critical["clear_threshold"] == 78.0,
      dict(critical) if critical else None)
check("temp_chassis_critical's severity is this scale's actual 'critical' (2), "
      "not temp_chassis_high's 'warning' (4) again",
      critical is not None and critical["severity"] == 2, critical["severity"] if critical else None)

# An operator tunes the existing rule, then the database re-opens — the
# upgrade case: _seed_rules (INSERT OR IGNORE) and _run_named_migrations run
# on every _after_open, and neither may touch a row already there.
db.update_rule(high["id"], threshold=72.0, clear_threshold=60.0)
db.close()

reopened = AlertsDatabase(path)
high2 = reopened.rule_by_key("temp_chassis_high")
matches = [r for r in reopened.rules() if r["key"] == "temp_chassis_critical"]
check("re-opening does not reset an operator's edited temp_chassis_high threshold",
      high2["threshold"] == 72.0 and high2["clear_threshold"] == 60.0, dict(high2))
check("re-opening does not duplicate temp_chassis_critical",
      len(matches) == 1, matches)
reopened.close()


# ==================================================================== accessors
print("\ndevice_thresholds accessors and validation")

db, _ = new_alerts_db("accessors")

db.set_device_threshold(101, "temp_chassis_high", threshold=65.0, clear_threshold=55.0)
row = db.device_thresholds(101)
check("device_thresholds(device_id) returns the override just set",
      len(row) == 1 and row[0]["threshold"] == 65.0 and row[0]["clear_threshold"] == 55.0
      and row[0]["enabled"] == 1, [dict(r) for r in row])

db.set_device_threshold(102, "temp_chassis_high", threshold=None, clear_threshold=None,
                        enabled=False)
fleet = db.device_thresholds()
check("device_thresholds() with no device_id returns every override, for the fleet view",
      len(fleet) == 2, [dict(r) for r in fleet])

by_device = db.device_threshold_map("temp_chassis_high")
check("device_threshold_map keys by device_id for one rule",
      set(by_device.keys()) == {101, 102} and by_device[101]["threshold"] == 65.0,
      {k: dict(v) for k, v in by_device.items()})
check("device_threshold_map for a rule with no overrides is empty, not an error",
      db.device_threshold_map("temp_chassis_critical") == {}, None)

raised = None
try:
    db.set_device_threshold(101, "not_a_real_rule", threshold=1.0, clear_threshold=0.0)
except ValueError as exc:
    raised = exc
check("an unknown rule_key raises ValueError", raised is not None, None)

raised = None
try:
    db.set_device_threshold(101, "device_down", threshold=1.0, clear_threshold=0.0)
except ValueError as exc:
    raised = exc
check("a non-threshold rule_key (device_down) raises too", raised is not None, None)

raised = None
try:
    db.set_device_threshold(101, "temp_chassis_high", threshold=70.0, clear_threshold=80.0)
except ValueError as exc:
    raised = exc
check("a clear_threshold on the wrong side of threshold raises",
      raised is not None, None)
check("...with a readable message naming both numbers and the rule",
      raised is not None and "clear_threshold" in str(raised)
      and "temp_chassis_high" in str(raised), str(raised) if raised else None)

removed = db.clear_device_threshold(101, "temp_chassis_high")
check("clear_device_threshold removes an existing override and reports True",
      removed is True, None)
check("...and it is actually gone", db.device_thresholds(101) == [], None)
check("clearing an override that is not there reports False",
      db.clear_device_threshold(101, "temp_chassis_high") is False, None)
db.close()


# ================================================================ engine: honours
print("\nengine: a per-device threshold override")

nodes, alerts, snmp, syslog, ipam, engine = build("override_engine")
engine._tick()
hot = add_device(nodes, "10.50.0.1", "closet-sw")
cool = add_device(nodes, "10.50.0.2", "server-room-sw")
alerts.set_device_threshold(hot, "temp_chassis_high", threshold=65.0, clear_threshold=55.0)

base = time.time()
for offset in (0, 65):   # temp_chassis_high ships for_polls=2
    sample_temp(nodes, hot, base + offset, 70.0)
    sample_temp(nodes, cool, base + offset, 70.0)
    engine._tick()

hot_open = open_rows(alerts, "temp_chassis_high", hot)
cool_open = open_rows(alerts, "temp_chassis_high", cool)
check("a device with a 65 override alerts at 70 C", len(hot_open) == 1, hot_open)
check("a device with no override does NOT alert at 70 C (the shipped default is 75)",
      len(cool_open) == 0, cool_open)

# enabled=0 suppresses the rule for THAT device only.
alerts.set_device_threshold(cool, "temp_chassis_high", threshold=None,
                            clear_threshold=None, enabled=False)
for offset in (130, 195):
    sample_temp(nodes, cool, base + offset, 80.0)   # over the shipped default too
    engine._tick()
cool_open2 = open_rows(alerts, "temp_chassis_high", cool)
hot_open2 = open_rows(alerts, "temp_chassis_high", hot)
check("enabled=0 suppresses the rule for that device even at 80 C (over the default)",
      len(cool_open2) == 0, cool_open2)
check("...and the OTHER device's own alert is unaffected",
      len(hot_open2) == 1 and hot_open2[0]["id"] == hot_open[0]["id"], hot_open2)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ============================================================ engine: clear drives
print("\nengine: the override's own clear_threshold drives the clear")

nodes, alerts, snmp, syslog, ipam, engine = build("override_clear")
engine._tick()
dev = add_device(nodes, "10.50.1.1", "closet-sw-2")
alerts.set_device_threshold(dev, "temp_chassis_high", threshold=65.0, clear_threshold=55.0)

base = time.time()
for offset in (0, 65):
    sample_temp(nodes, dev, base + offset, 70.0)
    engine._tick()
opened = open_rows(alerts, "temp_chassis_high", dev)
check("the override opens the alert at 70 C (>= override threshold 65)",
      len(opened) == 1, opened)

# 60 C is below the OVERRIDE threshold (65, so no longer breaching) but NOT
# below the OVERRIDE clear (55). The rule's OWN clear_threshold (65) would
# have cleared this; the override's (55) must not.
sample_temp(nodes, dev, base + 130, 60.0)
engine._tick()
still_open = open_rows(alerts, "temp_chassis_high", dev)
check("60 C stays open — the override's clear_threshold (55) drives the "
      "clear, not the rule's own shipped one (65)",
      len(still_open) == 1 and still_open[0]["id"] == opened[0]["id"], still_open)

sample_temp(nodes, dev, base + 195, 50.0)   # below the override's own clear
engine._tick()
cleared = open_rows(alerts, "temp_chassis_high", dev)
check("dropping below the override's own clear_threshold (55) clears it",
      len(cleared) == 0, cleared)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ============================================================ engine: Warning/Critical
print("\nengine: Critical suppresses Warning on the same metric")

nodes, alerts, snmp, syslog, ipam, engine = build("critical_rollup")
engine._tick()
dev = add_device(nodes, "10.50.2.1", "hot-core-sw")

base = time.time()
for offset in (0, 65):   # both rules ship for_polls=2
    sample_temp(nodes, dev, base + offset, 90.0)
    engine._tick()
warning = open_rows(alerts, "temp_chassis_high", dev)
critical = open_rows(alerts, "temp_chassis_critical", dev)
check("a device at 90 C opens Critical", len(critical) == 1, critical)
check("...and does NOT leave Warning open beside it", len(warning) == 0, warning)
check("Critical's count is 1 after 2 polls, not 2 — no cross-match double-increment "
      "from the Warning occurrence sharing the same source_kind",
      len(critical) == 1 and critical[0]["count"] == 1,
      critical[0]["count"] if critical else None)

for offset in (130, 195, 260):
    sample_temp(nodes, dev, base + offset, 90.0)
    engine._tick()
critical2 = open_rows(alerts, "temp_chassis_critical", dev)
warning2 = open_rows(alerts, "temp_chassis_high", dev)
check("staying at 90 C keeps exactly one Critical alert, correctly incremented "
      "(4 polls past the opening one, not 8 via cross-matching)",
      len(critical2) == 1 and critical2[0]["id"] == critical[0]["id"]
      and critical2[0]["count"] == 4, critical2)
check("...and Warning stays suppressed the whole time", len(warning2) == 0, warning2)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# =========================================================== engine: deleted device
print("\nengine: an override for a deleted device is harmless")

nodes, alerts, snmp, syslog, ipam, engine = build("deleted_device")
engine._tick()
ghost = add_device(nodes, "10.50.3.1", "ghost-sw")
alive = add_device(nodes, "10.50.3.2", "alive-sw")
nodes.remove_device(ghost)
alerts.set_device_threshold(ghost, "temp_chassis_high", threshold=1.0, clear_threshold=0.0)

base = time.time()
raised = None
try:
    for offset in (0, 65):
        sample_temp(nodes, alive, base + offset, 76.0)
        engine._tick()
except Exception as exc:   # pragma: no cover -- the whole point is that this can't happen
    raised = exc
check("a leftover override for a deleted device raises nothing", raised is None,
      repr(raised) if raised else None)
alive_open = open_rows(alerts, "temp_chassis_high", alive)
check("...and a real device's own evaluation is unaffected", len(alive_open) == 1, alive_open)
check("the leftover row itself is still visible (an operator can find and clean it up)",
      len(alerts.device_thresholds(ghost)) == 1, None)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ============================================================ engine: read once
print("\nengine: the override map is read once per rule per tick")

nodes, alerts, snmp, syslog, ipam, engine = build("read_once")
engine._tick()
base = time.time()
for i in range(20):
    device_id = add_device(nodes, f"10.50.4.{i + 1}", f"acc-sw-{i:02d}")
    sample_temp(nodes, device_id, base, 40.0)   # nowhere near breaching

threshold_rule_count = len([r for r in alerts.rules()
                            if r["enabled"] and r["kind"] == "threshold"])
statements = []
alerts._conn.set_trace_callback(statements.append)
try:
    engine._tick()
finally:
    alerts._conn.set_trace_callback(None)
device_threshold_reads = [s for s in statements if "device_thresholds" in s]
check("device_threshold_map runs exactly once per enabled threshold rule per "
      "tick, not once per device (20 devices, one query per rule either way)",
      len(device_threshold_reads) == threshold_rule_count,
      (len(device_threshold_reads), threshold_rule_count))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ================================================= engine: resolving Critical
print("\nengine: resolving Critical by hand does not re-open Warning")

# The reproduction from the review: a device sustained at 90 C opens
# Critical and correctly suppresses Warning underneath it (ROLLED_UP_BY).
# An operator resolves Critical by hand. The device is still at 90 C. Two
# more polls later, Warning must NOT open — that is exactly the duplicate
# noise ROLLED_UP_BY["temp_chassis_high"] = "temp_chassis_critical" exists
# to prevent, and it depends on _parent_operator_resolved finding Warning's
# OWN live breach streak (via _child_first_breach_ts) to confirm that
# streak began before the hand resolve.
nodes, alerts, snmp, syslog, ipam, engine = build("resolve_critical")
engine._tick()
dev = add_device(nodes, "10.50.5.1", "still-hot-sw")

base = time.time()
for offset in (0, 65):   # both rules ship for_polls=2
    sample_temp(nodes, dev, base + offset, 90.0)
    engine._tick()
critical_open = open_rows(alerts, "temp_chassis_critical", dev)
check("a device at 90 C opens Critical", len(critical_open) == 1, critical_open)
check("...and Warning starts out suppressed",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0,
      open_rows(alerts, "temp_chassis_high", dev))

alerts.resolve(critical_open[0]["id"], by="operator")
check("Critical is resolved by hand",
      len(open_rows(alerts, "temp_chassis_critical", dev)) == 0, None)

# The device never recovered: still 90 C, two more polls.
for offset in (130, 195):
    sample_temp(nodes, dev, base + offset, 90.0)
    engine._tick()

check("Critical stays resolved rather than re-opening on its own account "
      "(the same-alert operator-resolve gate, unrelated to this bug)",
      len(open_rows(alerts, "temp_chassis_critical", dev)) == 0,
      open_rows(alerts, "temp_chassis_critical", dev))
check("Warning does NOT open just because Critical was resolved by hand — "
      "_child_first_breach_ts must find Warning's live streak under the "
      "same (rule, device) key _evaluate_thresholds stores it under",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0,
      open_rows(alerts, "temp_chassis_high", dev))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ===================================================== engine: override change
print("\nengine: a changed override does not resume the old streak")

# The reason the streak key was widened to include the effective
# threshold/clear pair in the first place (4.54.0) still has to hold once
# that pair moves inside the entry instead of inside the key: a poll
# counted under the OLD numbers must not count toward for_polls under the
# NEW ones.
nodes, alerts, snmp, syslog, ipam, engine = build("override_change_streak")
engine._tick()
dev = add_device(nodes, "10.50.6.1", "retuned-sw")
alerts.set_device_threshold(dev, "temp_chassis_high", threshold=65.0, clear_threshold=55.0)

base = time.time()
sample_temp(nodes, dev, base, 70.0)   # over 65 -- one poll of two (for_polls=2)
engine._tick()
check("one poll over the override is not yet a breach (for_polls=2)",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0, None)

alerts.set_device_threshold(dev, "temp_chassis_high", threshold=60.0, clear_threshold=55.0)
sample_temp(nodes, dev, base + 65, 70.0)   # over the NEW 60 too
engine._tick()
check("changing the override starts a fresh streak — the one poll counted "
      "under the OLD threshold (65) does not carry over toward the NEW "
      "one's for_polls=2",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0,
      open_rows(alerts, "temp_chassis_high", dev))

sample_temp(nodes, dev, base + 130, 70.0)   # second poll under the NEW numbers
engine._tick()
check("...and two full polls under the new numbers does breach",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 1,
      open_rows(alerts, "temp_chassis_high", dev))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ===================================================== engine: override clear
print("\nengine: clearing an override likewise starts a fresh streak")

nodes, alerts, snmp, syslog, ipam, engine = build("override_clear_streak")
engine._tick()
dev = add_device(nodes, "10.50.6.2", "detuned-sw")
alerts.set_device_threshold(dev, "temp_chassis_high", threshold=65.0, clear_threshold=55.0)

base = time.time()
sample_temp(nodes, dev, base, 80.0)   # over the override (65) -- one poll of two
engine._tick()
check("one poll over the override is not yet a breach",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0, None)

alerts.clear_device_threshold(dev, "temp_chassis_high")   # back to the shipped 75/65
sample_temp(nodes, dev, base + 65, 80.0)   # still over the rule's own 75
engine._tick()
check("clearing the override starts a fresh streak — the poll counted "
      "under the override does not carry over toward the rule's own "
      "for_polls=2",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0,
      open_rows(alerts, "temp_chassis_high", dev))

sample_temp(nodes, dev, base + 130, 80.0)   # second poll under the rule's own numbers
engine._tick()
check("...and two full polls under the rule's own numbers does breach",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 1,
      open_rows(alerts, "temp_chassis_high", dev))
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()



# ============================================== engine: disabling an open override
print("\nengine: disabling an override for a device resolves an alert already open")

# The regression from the re-review: enabled=0 used to `continue` before
# ever touching an alert that was already open, freezing it — a device
# that later cooled back down stayed "alerting" forever, with no
# automatic path back to closed.
nodes, alerts, snmp, syslog, ipam, engine = build("override_disable_open")
engine._tick()
dev = add_device(nodes, "10.50.7.1", "cooling-sw")

base = time.time()
for offset in (0, 65):   # shipped default: threshold=75, for_polls=2
    sample_temp(nodes, dev, base + offset, 80.0)
    engine._tick()
opened = open_rows(alerts, "temp_chassis_high", dev)
check("a device at 80 C opens temp_chassis_high", len(opened) == 1, opened)

# Operator disables the rule for this device — FEATURES.md and the
# CHANGELOG both say this "turns the rule off entirely" for it.
alerts.set_device_threshold(dev, "temp_chassis_high", threshold=None,
                            clear_threshold=None, enabled=False)
sample_temp(nodes, dev, base + 130, 80.0)   # still hot
engine._tick()
disabled_open = open_rows(alerts, "temp_chassis_high", dev)
check("disabling the rule for this device resolves the alert that was "
      "already open, instead of freezing it", len(disabled_open) == 0,
      disabled_open)

rule_id = alerts.rule_by_key("temp_chassis_high")["id"]
resolved_rows = [r for r in alerts.alerts(state="resolved", rule_id=rule_id)
                if r["entity_id"] == str(dev)]
check("...resolved automatically (resolved_by=''), not as an operator's own "
      "hand resolve", len(resolved_rows) == 1 and resolved_rows[0]["resolved_by"] == "",
      [dict(r) for r in resolved_rows])

# The device cools down while still disabled: nothing left frozen, and
# nothing to reopen either.
sample_temp(nodes, dev, base + 195, 40.0)
engine._tick()
check("staying disabled through a cooldown leaves it resolved, not reopened",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0, None)

# Re-enabling the rule for this device and breaching again must open a
# FRESH alert — the auto-resolve above has to behave like
# _sweep_netpath_alerts's (by='', no clear email), not like an operator's
# hand resolve, or this device would be silenced forever.
alerts.clear_device_threshold(dev, "temp_chassis_high")
for offset in (260, 325):
    sample_temp(nodes, dev, base + offset, 80.0)
    engine._tick()
reopened_rows = open_rows(alerts, "temp_chassis_high", dev)
check("re-enabling the rule and breaching again opens a fresh alert",
      len(reopened_rows) == 1, reopened_rows)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


# ==================================================== engine: rule-edit resets streaks
print("\nengine: editing a RULE's own numbers resets every device's streak too")

# Finding 6 from the re-review: the streak-reset compares the EFFECTIVE
# threshold/clear pair, so editing a rule's own threshold now resets every
# device's streak and first_breach_ts exactly the way changing a per-device
# override already did — before 4.54.0 a streak survived a rule edit.
# Concluded correct and documented in alertengine._evaluate_thresholds: a
# streak counted against numbers that no longer apply is not evidence of
# anything, so a hand-resolved but still-breaching alert re-opens as a new
# run after any edit to that rule's numbers.
nodes, alerts, snmp, syslog, ipam, engine = build("rule_edit_resets_streak")
engine._tick()
dev = add_device(nodes, "10.50.7.2", "still-hot-sw-2")
rule_id = alerts.rule_by_key("temp_chassis_high")["id"]

base = time.time()
for offset in (0, 65):   # shipped default: threshold=75, for_polls=2
    sample_temp(nodes, dev, base + offset, 80.0)
    engine._tick()
opened = open_rows(alerts, "temp_chassis_high", dev)
check("a device at 80 C opens temp_chassis_high", len(opened) == 1, opened)

alerts.resolve(opened[0]["id"], by="operator")
check("an operator resolves it by hand",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0, None)

# Still breaching, untouched numbers: the operator-resolve gate keeps it
# closed (unrelated to this bug — see the "resolving Critical" case above).
sample_temp(nodes, dev, base + 130, 80.0)
engine._tick()
check("staying at 80 C under the SAME numbers keeps it resolved",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0, None)

# The rule's own threshold is edited — no override involved at all.
alerts.update_rule(rule_id, threshold=70.0, clear_threshold=60.0)
sample_temp(nodes, dev, base + 195, 80.0)   # one poll under the new numbers
engine._tick()
check("one poll after the rule edit is not yet a breach (for_polls=2) — the "
      "old streak did not carry over",
      len(open_rows(alerts, "temp_chassis_high", dev)) == 0, None)

sample_temp(nodes, dev, base + 260, 80.0)   # second poll under the new numbers
engine._tick()
reopened_rows = open_rows(alerts, "temp_chassis_high", dev)
check("...and a second poll re-opens it as a NEW run — the rule edit reset "
      "first_breach_ts, so the operator-resolve gate no longer recognizes "
      "this as the run that was resolved by hand",
      len(reopened_rows) == 1, reopened_rows)
nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
