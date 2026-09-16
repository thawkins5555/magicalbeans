"""5.16.0 per-sensor alerting: temp_sensor_c.<idx> is judged against the limit
the device published into interface_thresholds, temp_sensor_state.<idx> and
psu_state.<idx> against their fixed enum floors, all three as `sensor`
entities named from the metric's own label; and the chassis temperature
rules step aside for a device that has per-sensor coverage.

Metric keys and threshold rows are written by hand, exactly as
tests/test_alert_per_port.py does, so nothing here depends on the poller.
"""
import os
import sqlite3
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.alertrules import (BASELINE_FAMILIES, FALLBACK_OF, PUBLISHED_THRESHOLD_RULES,
                                ROLLED_UP_BY, SENSOR_FAMILIES, device_id_for)
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

TMPDIR = _paths.tmpdir("alert_sensor_")
_SEQ = [0]
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
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
    stores = (SnmpTrapDatabase(os.path.join(folder, "traps.db")),
              SyslogDatabase(os.path.join(folder, "syslog.db")),
              IpamDatabase(os.path.join(folder, "ipam.db")),
              NetpathDatabase(os.path.join(folder, "netpath.db")))
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=stores[0],
                         syslog_db=stores[1], ipam_db=stores[2], netpath_db=stores[3])
    return nodes, alerts, engine, stores


def open_rows(alerts, rule_key):
    rule = alerts.rule_by_key(rule_key)
    return alerts.alerts(state="unresolved", rule_id=rule["id"])


def sample(nodes, did, key, label, unit, ts, value):
    nodes.record_metric_sample(did, key, label, unit, "gauge", ts, value)


def go_down(nodes, device_id):
    """Same outage helper tests/test_alert_per_port.py uses: a status update
    the engine's own outage detector would make, plus the event it reads."""
    conn = sqlite3.connect(nodes.path)
    conn.execute("UPDATE devices SET status = 'down' WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    nodes.record_device_event(device_id, "down", "stopped responding")


def publish(nodes, did, idx, warn, alarm):
    nodes.replace_interface_thresholds(did, "CISCO-ENTITY-SENSOR-MIB", [
        {"if_index": idx, "metric_root": "temp_sensor_c", "low_alarm": None,
         "low_warn": None, "high_warn": warn, "high_alarm": alarm,
         "updated_ts": time.time()}])


# ------------------------------------------------------------- the contract
check("the two published temperature rules read the high bands",
      PUBLISHED_THRESHOLD_RULES["temp_sensor_high"] == ("temp_sensor_c", "high_warn")
      and PUBLISHED_THRESHOLD_RULES["temp_sensor_critical"] == ("temp_sensor_c", "high_alarm"))
check("the five sensor families are declared",
      SENSOR_FAMILIES == {"temp_sensor_c", "temp_sensor_state", "psu_state",
                          "stack_power_port", "fan_state"})
check("both chassis rules fall back to the sensor families",
      set(FALLBACK_OF) == {"temp_chassis_high", "temp_chassis_critical"})
check("each pair rolls warning under critical and critical under device_down",
      ROLLED_UP_BY["temp_sensor_high"] == "temp_sensor_critical"
      and ROLLED_UP_BY["psu_warning"] == "psu_failed"
      and ROLLED_UP_BY["psu_failed"] == "device_down")
check("stack_power_cable_down rolls up under device_down directly",
      ROLLED_UP_BY["stack_power_cable_down"] == "device_down")
check("a sensor entity resolves to its device for muting",
      device_id_for("sensor", "7:3") == 7)

# --------------------------------------------- S1 published temperature limit
nodes, alerts, engine, stores = build(rollup_enabled=True)
did = nodes.add_device("10.30.0.1", name="core-sw", group_id=nodes.ensure_default_group())
for key in ("temp_sensor_high", "temp_sensor_critical"):
    rule = alerts.rule_by_key(key)
    check(f"{key} ships with no threshold of its own",
          rule is not None and rule["threshold"] is None and rule["clear_threshold"] is None,
          dict(rule) if rule else None)
engine._tick()
publish(nodes, did, 3, 60.0, 75.0)
engine._published_cache = (0.0, None, None)
base = time.time()
for i in range(2):
    sample(nodes, did, "temp_sensor_c.3", "Supervisor inlet", "°C", base + i, 70.0)
    engine._tick()
rows = open_rows(alerts, "temp_sensor_high")
check("70 C against a published 60 C warning opens the sensor alert",
      len(rows) == 1 and rows[0]["entity_kind"] == "sensor"
      and rows[0]["entity_id"] == f"{did}:3", [dict(r) for r in rows])
check("...named after the sensor, not a port",
      rows and "Supervisor inlet" in rows[0]["entity_label"], rows and rows[0]["entity_label"])
check("...and the alert says the limit came from the device",
      rows and "published by the device" in (rows[0]["extra_json"] or ""), rows and rows[0]["extra_json"])
for i in range(2):
    sample(nodes, did, "temp_sensor_c.3", "Supervisor inlet", "°C", base + 10 + i, 80.0)
    engine._tick()
check("80 C opens critical and rolls the warning up",
      len(open_rows(alerts, "temp_sensor_critical")) == 1
      and open_rows(alerts, "temp_sensor_high") == [])
sample(nodes, did, "temp_sensor_c.3", "Supervisor inlet", "°C", base + 20, 50.0)
engine._tick()
check("50 C clears critical (2 C hysteresis below the published limit)",
      open_rows(alerts, "temp_sensor_critical") == [])

# ------------------------------------------------ S2 the chassis rule steps aside
for i in range(3):
    sample(nodes, did, "temp_chassis_c", "Chassis temperature", "°C", base + 30 + i, 90.0)
    engine._tick()
check("a device with a published sensor limit is not judged by temp_chassis_high",
      open_rows(alerts, "temp_chassis_high") == [] and open_rows(alerts, "temp_chassis_critical") == [])

other = nodes.add_device("10.30.0.2", name="old-sw", group_id=nodes.ensure_default_group())
for i in range(3):
    sample(nodes, other, "temp_chassis_c", "Chassis temperature", "°C", base + 40 + i, 90.0)
    engine._tick()
check("a device with no per-sensor coverage still gets the chassis rules",
      len(open_rows(alerts, "temp_chassis_critical")) == 1)
nodes.close(); alerts.close()
for store in stores:
    store.close()

# ------------------------------------------------------- S3 state enums and PSU
nodes, alerts, engine, stores = build()
did = nodes.add_device("10.30.0.3", name="edge-sw", group_id=nodes.ensure_default_group())
engine._tick()
base = time.time()
sample(nodes, did, "psu_state.2", "Power supply 2", "", base, 2.0)
engine._tick()
rows = open_rows(alerts, "psu_failed")
check("a supply reading 2 opens psu_failed on the first sample",
      len(rows) == 1 and rows[0]["entity_kind"] == "sensor"
      and "Power supply 2" in rows[0]["entity_label"], [dict(r) for r in rows])
sample(nodes, did, "psu_state.2", "Power supply 2", "", base + 1, 0.0)
engine._tick()
check("...and 0 clears it", open_rows(alerts, "psu_failed") == [])
sample(nodes, did, "psu_state.2", "Power supply 2", "", base + 2, 1.0)
engine._tick()
check("1 opens psu_warning only",
      len(open_rows(alerts, "psu_warning")) == 1 and open_rows(alerts, "psu_failed") == [])

sample(nodes, did, "psu_state.2", "Power supply 2", "", base + 2.5, 3.0)
engine._tick()
check("3 (not present) opens psu_failed, same as an outright failure",
      len(open_rows(alerts, "psu_failed")) == 1)
sample(nodes, did, "psu_state.2", "Power supply 2", "", base + 2.7, 0.0)
engine._tick()
check("...and 0 clears it", open_rows(alerts, "psu_failed") == [])

sample(nodes, did, "temp_sensor_state.1", "Board temperature", "", base + 3, 1.0)
engine._tick()
check("a vendor status enum of 1 opens the state warning",
      len(open_rows(alerts, "temp_sensor_state_warning")) == 1)
for i in range(3):
    sample(nodes, did, "temp_chassis_c", "Chassis temperature", "°C", base + 4 + i, 90.0)
    engine._tick()
check("a state-only device is also covered, so the chassis rule stays quiet",
      open_rows(alerts, "temp_chassis_critical") == [])
nodes.close(); alerts.close()
for store in stores:
    store.close()

# --------------------------------------------- S4 stack power cable down
nodes, alerts, engine, stores = build(rollup_enabled=True)
did = nodes.add_device("10.30.0.4", name="stack-sw", group_id=nodes.ensure_default_group())
engine._tick()
base = time.time()
sample(nodes, did, "stack_power_port.1001002",
      "Switch 1 stack power PORT-2 -> switch 2", "state", base, 2.0)
engine._tick()
rows = open_rows(alerts, "stack_power_cable_down")
check("a stack power port reading 2 opens stack_power_cable_down",
      len(rows) == 1 and rows[0]["entity_kind"] == "sensor"
      and rows[0]["entity_id"] == f"{did}:1001002", [dict(r) for r in rows])
check("...named after the port, not a generic sensor index",
      rows and "PORT-2" in rows[0]["entity_label"], rows and rows[0]["entity_label"])
sample(nodes, did, "stack_power_port.1001002",
      "Switch 1 stack power PORT-2 -> switch 2", "state", base + 1, 0.0)
engine._tick()
check("...and 0 clears it", open_rows(alerts, "stack_power_cable_down") == [])


# device_down first, THEN a fresh breach -- the order _rollup_parent (not
# the open-on-absorb sweep, which only covers "device"/"interface" entity
# children -- see alertengine._absorb_one) actually covers for a `sensor`
# family child: it is suppressed before ever opening, same as psu_failed.
did2 = nodes.add_device("10.30.0.5", name="stack-sw-down", group_id=nodes.ensure_default_group())
engine._tick()
go_down(nodes, did2)
engine._tick()
check("the device is down", len(open_rows(alerts, "device_down")) == 1)
sample(nodes, did2, "stack_power_port.1001002",
      "Switch 1 stack power PORT-2 -> switch 2", "state", base + 2, 2.0)
engine._tick()
check("a fresh cable-down breach while the device is already down is "
      "suppressed under the outage rather than opening its own alert",
      open_rows(alerts, "stack_power_cable_down") == [],
      [dict(r) for r in open_rows(alerts, "stack_power_cable_down")])
nodes.close(); alerts.close()
for store in stores:
    store.close()

# --------------------------------------------------------------- S5 fans
nodes, alerts, engine, stores = build()
did = nodes.add_device("10.30.0.6", name="fan-sw", group_id=nodes.ensure_default_group())
engine._tick()
base = time.time()
sample(nodes, did, "fan_state.1", "Fan 1", "", base, 2.0)
engine._tick()
check("a fan reading 2 opens fan_failed",
      len(open_rows(alerts, "fan_failed")) == 1)
sample(nodes, did, "fan_state.1", "Fan 1", "", base + 1, 1.0)
engine._tick()
check("1 opens fan_warning only",
      len(open_rows(alerts, "fan_warning")) == 1 and open_rows(alerts, "fan_failed") == [])
sample(nodes, did, "fan_state.1", "Fan 1", "", base + 2, 0.0)
engine._tick()
check("0 stays silent on both", open_rows(alerts, "fan_warning") == []
      and open_rows(alerts, "fan_failed") == [])
nodes.close(); alerts.close()
for store in stores:
    store.close()

# --------------------------------------------------- S6 Sensor Snapshot baseline
check("the three baseline-covered families are declared",
      BASELINE_FAMILIES == {"psu_state", "stack_power_port", "fan_state"})

nodes, alerts, engine, stores = build()
did = nodes.add_device("10.30.0.7", name="baseline-sw", group_id=nodes.ensure_default_group())
engine._tick()
base = time.time()
sample(nodes, did, "psu_state.2", "Power supply 2", "", base, 3.0)
engine._tick()
check("psu_state.2 == 3 (not present) opens psu_failed before any baseline exists",
      len(open_rows(alerts, "psu_failed")) == 1)
nodes.replace_sensor_baselines(did, [{"metric_key": "psu_state.2", "value": 3.0, "ts": base}])
sample(nodes, did, "psu_state.2", "Power supply 2", "", base + 1, 3.0)
engine._tick()
check("...and once 3 is the accepted baseline, a fresh sample still reading 3 "
      "does not keep it open (this tick's pass resolves it on the way past)",
      open_rows(alerts, "psu_failed") == [])
sample(nodes, did, "psu_state.2", "Power supply 2", "", base + 2, 2.0)
engine._tick()
check("...but a value WORSE than the baseline (2, an outright failure) still opens it",
      len(open_rows(alerts, "psu_failed")) == 1)
sample(nodes, did, "psu_state.2", "Power supply 2", "", base + 3, 3.0)
engine._tick()
check("...and back to exactly the baseline (3) is quiet again",
      open_rows(alerts, "psu_failed") == [])

sample(nodes, did, "stack_power_port.5", "Stack power port 5", "state", base + 4, 2.0)
engine._tick()
check("a stack power port with no baseline opens as normal",
      len(open_rows(alerts, "stack_power_cable_down")) == 1)
nodes.replace_sensor_baselines(did, [{"metric_key": "psu_state.2", "value": 3.0, "ts": base},
                                     {"metric_key": "stack_power_port.5", "value": 2.0, "ts": base}])
sample(nodes, did, "stack_power_port.5", "Stack power port 5", "state", base + 5, 2.0)
engine._tick()
check("...and with a baseline of 2, the same reading stays quiet",
      open_rows(alerts, "stack_power_cable_down") == [])
nodes.close(); alerts.close()
for store in stores:
    store.close()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
