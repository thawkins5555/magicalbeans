"""UPS-MIB battery/output health (RFC 1628) and the device-level
ENTITY-SENSOR-MIB environmental read (RFC 3433) -- the gap: a UPS's own
*traps* were already decoded (trapoids.py) and its enterprise arc already
named a vendor (enterprises.py, nodeoids.VENDOR_HEALTH's neighbours), but
nothing ever asked a UPS how it was doing, and an environmental monitor's
sensors were reachable only through read_dom()'s interface dialog, which
requires an ifIndex mapping a chassis sensor never has.

Four sections, matching the four things asked for:
  1. nodeoids.UPS_HEALTH decoded correctly off real BER wire responses,
     through the actual poll path (nodepoll._poll_snmp_scalars) --
     including the /10 voltage scale, the column_first/column_max table
     reductions, the "not a UPS" cost gate, and the APC TimeTicks runtime
     fallback.
  2. nodepoll._decode_entity_sensor's RFC 3433 arithmetic against synthetic
     scale/precision combinations, including a negative exponent.
  3. A sensor with no ifIndex mapping now visible at DEVICE level
     (_poll_environment) while read_dom()'s own, unchanged, port-only view
     still sees only what it always saw -- AND that a temperature reading
     lands in temp_optic_c/temp_ambient_c/temp_chassis_c correctly, the fix
     for a real false-positive incident this shipped with for about a day
     (one "temp_c" key covering a room, a chassis and an SFP's DOM at once
     read as ten false "Temperature high" alerts on a healthy fleet). The
     "cannot be determined" case (no humidity sensor anywhere on the
     device) must default to chassis, never ambient.
  4. Each new built-in alert rule (alertsdb._BUILTIN_RULES) opening and
     clearing against synthetic metric samples, through a real AlertEngine
     tick -- not evaluate_threshold alone.
  5. alertsdb's _retire_temp_high migration: an installation that already
     seeded the old single "temp_high" rule gets it disabled (not deleted
     -- that would cascade-delete its alert history) and its open alerts
     resolved with an explanatory note, on the next startup.
"""
import os
import socket
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("ups_env_")

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.db import Database as NetpathDatabase

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_nodes_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def stub_stat(port: int, command: bytes) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(command, ("127.0.0.1", port))
    try:
        return s.recv(256).decode("utf-8", "replace")
    finally:
        s.close()


def request_count(port: int) -> int:
    return int(stub_stat(port, b"STATS"))


def reset_count(port: int) -> None:
    stub_stat(port, b"RESET")


def device_against(db: NodesDatabase, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


# ============================================================== § 1 UPS-MIB

stub, port = spawn_stub("stub_agent_ups_env.py", "ups")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("ups")
    did = device_against(db, "ups-1")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity, uptime_ticks, metrics = poller._poll_snmp_scalars(device, config)
    values = {key: value for key, label, unit, kind, value in metrics}

    check("battery status is stored as its raw enum code (batteryLow=3)",
          values.get("ups_battery_status") == 3.0, values)
    check("seconds on battery",
          values.get("ups_on_battery_s") == 45.0, values)
    check("estimated runtime remaining, standard scalar",
          values.get("ups_runtime_min") == 12.0, values)
    check("battery charge percent",
          values.get("ups_battery_charge_pct") == 63.0, values)
    check("battery voltage scaled from decivolts (243 -> 24.3 V)",
          values.get("ups_battery_voltage") == 24.3, values)
    check("battery temperature, no scaling needed",
          values.get("ups_battery_temp_c") == 31.0, values)
    check("output source is stored as its raw enum code (battery=5)",
          values.get("ups_output_source") == 5.0, values)
    check("active alarm count",
          values.get("ups_alarms") == 2.0, values)
    check("input voltage takes the first line (column_first): 118, not 121",
          values.get("ups_input_voltage") == 118.0, values)
    check("output load takes the worst line (column_max): 72, not 55",
          values.get("ups_output_load_pct") == 72.0, values)
    db.close()
finally:
    stub.kill()

# ---------------------------------- not a UPS: the two table walks never run

stub, port = spawn_stub("stub_agent_ups_env.py", "no_ups")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("no_ups")
    did = device_against(db, "not-a-ups")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    reset_count(port)
    metrics = poller._poll_ups_health(device, config, identity={}, already=set())
    requests = request_count(port)
    check("a device that answers no UPS-MIB scalar produces no UPS metrics",
          metrics == [], metrics)
    check("...and cost exactly the one scalar GET, not a walk on top of it",
          requests == 1, requests)
    check("that first probe recorded ups_capable=False on the device row",
          db.device(did)["ups_capable"] == 0, db.device(did))

    reset_count(port)
    poller._poll_ups_health(db.device(did), config, identity={}, already=set())
    check("a device already known incapable is never probed again -- not "
          "even the one scalar GET -- so a fleet of non-UPS devices stops "
          "paying for this every poll, forever",
          request_count(port) == 0, request_count(port))
    db.close()
finally:
    stub.kill()

# --------------------------------------------------- APC TimeTicks fallback

stub, port = spawn_stub("stub_agent_ups_env.py", "apc_ups")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("apc_ups")
    did = device_against(db, "apc-ups-1")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    identity, uptime_ticks, metrics = poller._poll_snmp_scalars(device, config)
    values = {key: value for key, label, unit, kind, value in metrics}
    check("the vendor arc identified this device as APC (318)",
          identity.get("vendor_arc") == 318, identity)
    check("upsEstimatedMinutesRemaining absent, upsAdvBatteryRunTimeRemaining "
          "used instead (900000 TimeTicks / 100 / 60 = 150 min)",
          values.get("ups_runtime_min") == 150.0, values)
    db.close()
finally:
    stub.kill()

# ========================================================== § 2 sensor decode

db = new_nodes_db("decode")
poller = NodePoller(db)

reading = poller._decode_entity_sensor(
    "1", 451, types={"1": 8}, scales={"1": 9}, precisions={"1": 1},
    statuses={"1": 1}, units={}, descrs={"1": "Inlet"})
check("scale=units(9), precision=1: 451 -> 45.1 °C",
      reading is not None and reading["value"] == 45.1
      and reading["unit"] == "°C" and reading["status"] == "ok", reading)

reading = poller._decode_entity_sensor(
    "2", 65000, types={"2": 9}, scales={"2": 8}, precisions={"2": 0},
    statuses={"2": 1}, units={}, descrs={"2": "Chassis RH"})
check("negative exponent: scale=milli(8) is 10^-3, precision=0: "
      "65000 -> 65.0 %RH",
      reading is not None and reading["value"] == 65.0
      and reading["unit"] == "%RH", reading)

reading = poller._decode_entity_sensor(
    "3", 12345, types={"3": 6}, scales={"3": 10}, precisions={"3": 2},
    statuses={"3": 2}, units={}, descrs={"3": "PSU"})
check("positive exponent: scale=kilo(10) is 10^3, precision=2: "
      "12345 -> 123450.0, and status 2 decodes to \"unavailable\"",
      reading is not None and reading["value"] == 123450.0
      and reading["status"] == "unavailable", reading)

check("a non-numeric reading decodes to None rather than raising",
      poller._decode_entity_sensor("4", "not-a-number", {}, {}, {}, {}, {}, {}) is None)
check("an unparsable suffix decodes to None rather than raising",
      poller._decode_entity_sensor("x.y", 10, {}, {}, {}, {}, {}, {}) is None)
db.close()

# ============================================= § 3 device-level sensor visibility

stub, port = spawn_stub("stub_agent_ups_env.py", "sensors")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("sensors")
    did = device_against(db, "env-mon-1")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"}])
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    now = time.time()
    poller._poll_environment(did, device, config, set(), now)
    dev_metrics = {m["key"]: m for m in db.metrics(did)}
    # Entity 1 maps to ifIndex 1 -> temp_optic_c. Entity 3 (99, nonoperational)
    # is excluded. Entity 4 (52, unmapped) has no port, but this device DOES
    # answer a humidity sensor (entity 2), which is the positive evidence
    # that promotes an unmapped reading to temp_ambient_c rather than the
    # temp_chassis_c default -- see the "sensors_no_humidity" section below
    # for the opposite case.
    check("a port-mapped sensor becomes temp_optic_c (45.1, entity 1)",
          "temp_optic_c" in dev_metrics
          and dev_metrics["temp_optic_c"]["last_value"] == 45.1,
          dev_metrics.get("temp_optic_c"))
    check("an unmapped sensor on a device with a humidity sensor becomes "
          "temp_ambient_c (52, entity 4 -- not the excluded 99 nonoperational "
          "reading from entity 3)",
          "temp_ambient_c" in dev_metrics
          and dev_metrics["temp_ambient_c"]["last_value"] == 52.0,
          dev_metrics.get("temp_ambient_c"))
    check("no temp_chassis_c is produced here (nothing unmapped and "
          "'chassis-only' on this device)",
          "temp_chassis_c" not in dev_metrics, dev_metrics)
    check("...and the humidity reading itself, decoded through a negative "
          "scale exponent",
          "humidity_pct" in dev_metrics
          and dev_metrics["humidity_pct"]["last_value"] == 65.0,
          dev_metrics.get("humidity_pct"))

    sensors = poller.read_dom(did, 1)
    check("read_dom's own port-mapped view is unchanged by the device scan: "
          "exactly the one entity aliased to ifIndex 1, at its own reading",
          len(sensors) == 1 and sensors[0]["value"] == 45.1
          and sensors[0]["unit"] == "°C", sensors)

    reset_count(port)
    poller._poll_environment(did, device, config, set(), now + 1.0)
    check("a second call inside the cadence window does not re-walk the device",
          request_count(port) == 0, request_count(port))

    poller._poll_environment(
        did, device, config, set(), now + NodePoller._SENSOR_REFRESH_S + 1.0)
    check("...but one past the cadence window does",
          request_count(port) >= 1, request_count(port))
    db.close()
finally:
    stub.kill()

# ---------------------------- no humidity sensor: default is chassis, not ambient

stub, port = spawn_stub("stub_agent_ups_env.py", "sensors_no_humidity")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("sensors_no_humidity")
    did = device_against(db, "switch-with-a-sensor")
    db.replace_interfaces(did, [{"if_index": 1, "descr": "Gi0/1"}])
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_environment(did, device, config, set(), time.time())
    dev_metrics = {m["key"]: m for m in db.metrics(did)}
    check("a device whose sensor kind cannot be positively identified as "
          "ambient (no humidity sensor anywhere on it) defaults to "
          "temp_chassis_c, never temp_ambient_c",
          "temp_chassis_c" in dev_metrics
          and dev_metrics["temp_chassis_c"]["last_value"] == 52.0
          and "temp_ambient_c" not in dev_metrics,
          dev_metrics)
    check("the port-mapped entity is still temp_optic_c regardless",
          "temp_optic_c" in dev_metrics
          and dev_metrics["temp_optic_c"]["last_value"] == 45.1,
          dev_metrics.get("temp_optic_c"))
    check("no humidity_pct at all when nothing on the device reports one",
          "humidity_pct" not in dev_metrics, dev_metrics)
    db.close()
finally:
    stub.kill()

# ------------------------ no ENTITY-SENSOR-MIB at all: never probed again

stub, port = spawn_stub("stub_agent_ups_env.py", "no_ups")   # no sensor OIDs either
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_nodes_db("no_sensors")
    did = device_against(db, "plain-switch")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    now = time.time()
    poller._poll_environment(did, device, config, set(), now)
    check("a device with no ENTITY-SENSOR-MIB support records "
          "sensor_capable=False on its first (and only necessary) walk",
          db.device(did)["sensor_capable"] == 0, db.device(did))

    reset_count(port)
    # Well past the cadence window -- if capability memory were not
    # checked FIRST, this alone would re-walk the device.
    poller._poll_environment(did, db.device(did), config, set(),
                            now + NodePoller._SENSOR_REFRESH_S + 1.0)
    check("...and a confirmed-incapable device is never walked again, even "
          "once its cadence window has long since passed -- the fix for a "
          "switch that would otherwise cost one wasted GETBULK every "
          "_SENSOR_REFRESH_S, forever, across a fleet where most devices "
          "are not environmental monitors",
          request_count(port) == 0, request_count(port))
    db.close()
finally:
    stub.kill()

# ================================================================ § 4 rules


def build_alert_harness():
    folder = tmpdir("ups_env_alerts_")
    nodes = NodesDatabase(f"{folder}/nodes.db")
    alerts = AlertsDatabase(f"{folder}/alerts.db")
    alerts.save_settings({"email_enabled": False, "rollup_enabled": False,
                          "new_device_grace_s": 0, "notify_rollup_delay_s": 0})
    snmp = SnmpTrapDatabase(f"{folder}/traps.db")
    syslog = SyslogDatabase(f"{folder}/syslog.db")
    ipam = IpamDatabase(f"{folder}/ipam.db")
    netpath_db = NetpathDatabase(f"{folder}/netpath.db")
    engine = AlertEngine(alerts, nodes_db=nodes, snmp_db=snmp, syslog_db=syslog,
                         ipam_db=ipam, netpath_db=netpath_db)
    return nodes, alerts, snmp, syslog, ipam, engine


def add_device(nodes, ip, name):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid)


def open_rows(alerts, rule_key, device_id):
    rule = alerts.rule_by_key(rule_key)
    rows = alerts.alerts(state="unresolved", rule_id=rule["id"])
    return [r for r in rows if r["entity_id"] == str(device_id)]


# rule key, metric key, label, unit, a value that breaches, a value that clears
CASES = [
    ("ups_on_battery", "ups_on_battery_s", "Seconds on battery", "s", 45.0, 0.0),
    ("ups_battery_low", "ups_battery_status", "Battery status", "", 3.0, 2.0),
    ("ups_battery_replace", "ups_battery_status", "Battery status", "", 4.0, 2.0),
    ("ups_load_high", "ups_output_load_pct", "Output load", "%", 95.0, 40.0),
    ("temp_ambient_high", "temp_ambient_c", "Ambient temperature", "°C", 40.0, 20.0),
    ("temp_chassis_high", "temp_chassis_c", "Chassis temperature", "°C", 90.0, 60.0),
    ("temp_optic_high", "temp_optic_c", "Optic temperature", "°C", 95.0, 60.0),
    ("humidity_high", "humidity_pct", "Humidity", "%RH", 90.0, 50.0),
]

for rule_key, metric_key, label, unit, breach_value, clear_value in CASES:
    nodes, alerts, snmp, syslog, ipam, engine = build_alert_harness()
    try:
        engine._tick()   # seeds every cursor, evaluates nothing yet
        did = add_device(nodes, "10.9.0.1", f"{rule_key}-dev")
        base = time.time()
        for_polls = max(1, int(alerts.rule_by_key(rule_key)["for_polls"] or 1))
        for i in range(for_polls):
            nodes.record_metric_sample(did, metric_key, label, unit, "gauge",
                                       base + i, breach_value)
            engine._tick()
        opened = open_rows(alerts, rule_key, did)
        check(f"{rule_key} opens once its threshold is breached for "
              f"{for_polls} poll(s)",
              len(opened) == 1, opened)

        nodes.record_metric_sample(did, metric_key, label, unit, "gauge",
                                   base + for_polls + 1, clear_value)
        engine._tick()
        still_open = open_rows(alerts, rule_key, did)
        check(f"{rule_key} clears once the value drops back below the "
              f"clear threshold",
              still_open == [], still_open)
    finally:
        engine.stop()
        nodes.close(); alerts.close(); snmp.close(); syslog.close(); ipam.close()

# =================================================== § 5 the retirement migration

# Simulates an installation that already seeded 4.49.0's first cut of this
# feature -- one "temp_high" rule over one "temp_c" metric key -- before the
# fix landed. A fresh AlertsDatabase() never creates that row any more (it
# is gone from _BUILTIN_RULES), so it is inserted by hand here, exactly as
# it shipped, with one open alert against it.
migration_dir = tmpdir("ups_env_migration_")
alerts_path = os.path.join(migration_dir, "alerts.db")
alerts = AlertsDatabase(alerts_path)
now = time.time()
alerts._conn.execute(
    "INSERT INTO rules(key, name, kind, source_kind, severity, enabled,"
    " is_builtin, device_filter, notify, threshold, clear_threshold,"
    " for_polls, created_ts) VALUES ('temp_high', 'Temperature high',"
    " 'threshold', 'temp_c', 4, 1, 1, '', 1, 35.0, 30.0, 2, ?)", (now,))
old_rule = alerts._conn.execute(
    "SELECT id FROM rules WHERE key = 'temp_high'").fetchone()
alerts._conn.execute(
    "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
    " entity_label, severity, message, state, count, opened_ts, last_ts,"
    " extra_json) VALUES (?, 'temp_high:device:1', 'device', '1', 'sw1',"
    " 4, 'hot', 'open', 1, ?, ?, '{}')", (old_rule["id"], now, now))
# The FIRST AlertsDatabase(alerts_path) above already ran every named
# migration once, including retire_temp_high_1 -- as a no-op, since the
# temp_high row above did not exist yet. A real pre-fix install would have
# seeded that row BEFORE this migration's code ever existed, so its
# schema_migrations marker would not be there yet either; forgetting that
# marker here is what makes the row inserted above look like a genuine
# upgrade case to the next open, instead of a migration this database has
# (as far as it knows) already run.
alerts._conn.execute(
    "DELETE FROM schema_migrations WHERE name = 'retire_temp_high_1'")
alerts._conn.commit()
alerts.close()

# Reopening the same file is the "next startup" this migration runs on.
alerts = AlertsDatabase(alerts_path)
retired = alerts.rule_by_key("temp_high")
check("the pre-fix temp_high rule survives (not deleted -- deleting it "
      "would cascade-delete its alert history) but is disabled and "
      "relabelled so it reads as retired rather than merely broken",
      retired is not None and retired["enabled"] == 0
      and "retired" in retired["name"].lower(),
      dict(retired) if retired else None)
still_open = [r for r in alerts.alerts(state="unresolved")
             if retired and r["rule_id"] == retired["id"]]
check("its open alert is resolved on upgrade instead of staying open "
      "forever (temp_c will never arrive again to clear it on its own)",
      still_open == [], still_open)
alerts.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
