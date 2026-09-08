"""Optic power alerting from the limits the transceiver itself publishes.

The SFP receive/transmit power rules stopped carrying a global number in
5.3.0: a threshold that is right for an SR part is wrong for a ZR one, so
the poller learns each port's own alarm/warning bands out of
CISCO-ENTITY-SENSOR-MIB's entSensorThresholdTable and the engine alerts off
those alone — no rules.threshold, no device override, and therefore no
alert at all on a port whose switch publishes nothing.

Sections: the storage table and its accessors; the walk, its two-scale
decode and its sanity gates; cadence and gating; the eight rules; the
engine reading published limits only; the rollup pairing; the upgrade; and
the two silent-ignore refusals.

House style: a plain script, FAILS collects failed check() names, exit 1 if
anything failed.
"""
import json
import os
import socket
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

import netpath.nodepoll as nodepoll_mod
from netpath.alertrules import (PUBLISHED_HYSTERESIS, PUBLISHED_THRESHOLD_RULES,
                                ROLLED_UP_BY, breaches, same_metric_pair)
from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase
from netpath.web import api

TMPDIR = _paths.tmpdir("optic_published_thresholds_")

FAILS = []

PORT_DESCR = "TenGigabitEthernet1/1/1"
CISCO_SOURCE = "CISCO-ENTITY-SENSOR-MIB"


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def build(name: str):
    """(nodes, alerts, engine) on fresh temp databases."""
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
    return nodes, alerts, engine


def add_device(nodes, ip, name, **fields):
    gid = nodes.ensure_default_group()
    return nodes.add_device(ip, name=name, group_id=gid, **fields)


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


def cisco_device(db: NodesDatabase, name: str, ports=((1, PORT_DESCR),)) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    did = db.add_device("127.0.0.1", name=name, group_id=gid)
    db.replace_interfaces(did, [{"if_index": i, "descr": d} for i, d in ports])
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity={"vendor_detected": "cisco"},
                   uptime_ticks=None, status="up", reachable=True)
    return did


# ==================================================== § 1 the storage table
print("interface_thresholds: storage and its accessors")

nodes, _alerts, _engine = build("storage")
dev = add_device(nodes, "10.0.0.1", "sw-1")
other = add_device(nodes, "10.0.0.2", "sw-2")
nodes.replace_interfaces(dev, [{"if_index": 1, "descr": "Te1/1/1"},
                               {"if_index": 2, "descr": "Te1/1/2"}])
now = time.time()
nodes.replace_interface_thresholds(dev, CISCO_SOURCE, [
    {"if_index": 1, "metric_root": "sfp_rx_dbm", "low_alarm": -14.4,
     "low_warn": -11.4, "high_warn": 0.5, "high_alarm": 1.0,
     "updated_ts": now},
    {"if_index": 1, "metric_root": "sfp_tx_dbm", "low_alarm": -8.2,
     "low_warn": -7.3, "high_warn": 1.5, "high_alarm": 2.0,
     "updated_ts": now},
])

stored = nodes.interface_thresholds(dev)
check("a device's published limits come back keyed by (if_index, root)",
      set(stored) == {(1, "sfp_rx_dbm"), (1, "sfp_tx_dbm")}, sorted(stored))
check("every band round-trips as written",
      stored[(1, "sfp_rx_dbm")]["low_alarm"] == -14.4
      and stored[(1, "sfp_rx_dbm")]["high_alarm"] == 1.0
      and stored[(1, "sfp_tx_dbm")]["low_warn"] == -7.3,
      dict(stored[(1, "sfp_rx_dbm")]))
check("the publisher is recorded on the row, so a second vendor's walk can "
      "replace only its own",
      stored[(1, "sfp_rx_dbm")]["source"] == CISCO_SOURCE)

# --- a second write for the same source replaces, a different one does not
nodes.replace_interface_thresholds(dev, CISCO_SOURCE, [
    {"if_index": 2, "metric_root": "sfp_rx_dbm", "low_alarm": -20.0,
     "low_warn": None, "high_warn": None, "high_alarm": None,
     "updated_ts": now},
])
stored = nodes.interface_thresholds(dev)
check("re-publishing replaces this source's whole set: port 1's rows are "
      "gone and port 2's is there",
      set(stored) == {(2, "sfp_rx_dbm")}, sorted(stored))
check("a band the device does not publish is stored NULL, not guessed",
      stored[(2, "sfp_rx_dbm")]["low_warn"] is None,
      dict(stored[(2, "sfp_rx_dbm")]))
nodes.replace_interface_thresholds(dev, "OTHER-VENDOR-MIB", [
    {"if_index": 1, "metric_root": "sfp_tx_dbm", "low_alarm": -9.0,
     "low_warn": None, "high_warn": None, "high_alarm": None,
     "updated_ts": now},
])
check("a different publisher's rows sit alongside rather than replacing",
      set(nodes.interface_thresholds(dev)) == {(2, "sfp_rx_dbm"),
                                               (1, "sfp_tx_dbm")},
      sorted(nodes.interface_thresholds(dev)))

# --- the fleet-wide read the engine uses
nodes.replace_interface_thresholds(other, CISCO_SOURCE, [
    {"if_index": 7, "metric_root": "sfp_rx_dbm", "low_alarm": -30.0,
     "low_warn": None, "high_warn": None, "high_alarm": None,
     "updated_ts": now},
])
fleet = nodes.interface_thresholds_for_roots(["sfp_rx_dbm"])
check("the fleet read is keyed (device_id, root, if_index) and filtered to "
      "the roots asked for",
      set(fleet) == {(dev, "sfp_rx_dbm", 2), (other, "sfp_rx_dbm", 7)},
      sorted(fleet))
check("asking for no roots at all costs no query and returns nothing",
      nodes.interface_thresholds_for_roots([]) == {})
nodes.update_device(other, enabled=0)
check("a disabled device's limits are filtered out, the same way its "
      "metrics are",
      set(nodes.interface_thresholds_for_roots(["sfp_rx_dbm"]))
      == {(dev, "sfp_rx_dbm", 2)},
      sorted(nodes.interface_thresholds_for_roots(["sfp_rx_dbm"])))
nodes.update_device(other, enabled=1)

# --- the two lifecycle hazards the (device_id, if_index) key exists for
nodes.replace_interfaces(dev, [{"if_index": 2, "descr": "Te1/1/2 renamed"}])
check("an ordinary poll that drops and reindexes ports leaves the limits "
      "alone -- they are keyed by if_index, not interfaces.id",
      set(nodes.interface_thresholds(dev)) == {(2, "sfp_rx_dbm"),
                                               (1, "sfp_tx_dbm")},
      sorted(nodes.interface_thresholds(dev)))
nodes.remove_device(other)
check("removing a device cascades its published limits away with it",
      nodes.interface_thresholds(other) == {},
      nodes.interface_thresholds(other))
nodes.close()


# ============================================= § 2 the walk and its decode
print()
print("entSensorThresholdTable: the walk, the two-scale decode, the gates")

stub, port = _paths.spawn_stub("stub_agent_ups_env.py", "cisco_dom_thresholds")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    nodes, _alerts, _engine = build("walk")
    did = cisco_device(nodes, "cisco-sw")
    poller = NodePoller(nodes)
    device = nodes.device(did)
    config = nodes.effective_config(device)
    poller._poll_environment(did, device, config, set(), time.time())

    limits = nodes.interface_thresholds(did)
    check("the port's optic limits are learned, one row per DOM root the "
          "device publishes a usable level for",
          set(limits) == {(1, "sfp_rx_dbm"), (1, "sfp_tx_dbm"),
                          (1, "sfp_temp_c"), (1, "sfp_bias_ma")},
          sorted(limits))
    check("the chassis inlet probe publishes thresholds too, and maps to no "
          "port -- so it produces no row at all",
          all(if_index == 1 for if_index, _root in limits), sorted(limits))

    # --- the decode proof. Tx is quoted units(9)/precision 1 and Rx
    # milli(8)/precision 0, so a threshold decoded against anything but its
    # OWN entity's scale is out by a factor of a thousand -- and -14400 dBm
    # looks exactly as much like a number as -14.4 does.
    tx = limits[(1, "sfp_tx_dbm")]
    rx = limits[(1, "sfp_rx_dbm")]
    check("Tx: -82 at scale units(9), precision 1 decodes to -8.2 dBm",
          tx["low_alarm"] == -8.2, tx["low_alarm"])
    check("Rx: -14400 at scale milli(8), precision 0 decodes to -14.4 dBm "
          "-- the SAME entity's scale, not the Tx sensor's",
          rx["low_alarm"] == -14.4, rx["low_alarm"])
    check("every band of the Tx optic lands in its own column",
          (tx["low_alarm"], tx["low_warn"], tx["high_warn"], tx["high_alarm"])
          == (-8.2, -7.3, 1.5, 2.0), dict(tx))
    check("...and of the Rx optic",
          (rx["low_alarm"], rx["low_warn"], rx["high_warn"], rx["high_alarm"])
          == (-14.4, -11.4, 0.5, 1.0), dict(rx))
    check("critical(30) and major(20) are the alarm band, minor(10) the "
          "warning band",
          rx["low_alarm"] == -14.4 and rx["low_warn"] == -11.4, dict(rx))
    check("every row names the MIB that published it",
          all(row["source"] == CISCO_SOURCE for row in limits.values()))

    # --- the deliberate awkward cases in the fixture
    temp = limits[(1, "sfp_temp_c")]
    check("a device publishing ONE level stores that level and leaves the "
          "other three NULL -- partial publication is normal on older IOS",
          (temp["high_alarm"], temp["high_warn"], temp["low_alarm"],
           temp["low_warn"]) == (75.0, None, None, None), dict(temp))
    check("a row whose relation is equalTo, and one whose severity is "
          "other(1), name no band this app can act on and are dropped -- "
          "the supply-voltage sensor publishes only those two, so it gets "
          "no row",
          (1, "sfp_volt") not in limits, sorted(limits))
    bias = limits[(1, "sfp_bias_ma")]
    check("the same band quoted twice keeps the level that alerts EARLIER: "
          "0.002 A and 0.003 A both low_warn, the higher one wins",
          bias["low_warn"] == 3.0, dict(bias))
    check("...and a bias limit is converted into the milliamps its own "
          "metric is recorded in, not left in the MIB's amperes",
          bias["low_warn"] == 3.0, dict(bias))

    # --- store every DOM root, not only the two the rules read today
    check("temperature and bias limits are stored as well as the two dBm "
          "roots: the walk is the same walk, and widening the rule set "
          "later needs no poller change",
          {(1, "sfp_temp_c"), (1, "sfp_bias_ma")} <= set(limits),
          sorted(limits))

    # --- cadence: three walks an hour, not three every five minutes
    later = time.time() + NodePoller._SENSOR_REFRESH_S + 1.0
    reset_count(port)
    poller._poll_environment(did, nodes.device(did), config, set(), later)
    check("a second sensor pass inside the hour re-reads the readings and "
          "does NOT re-walk the three threshold columns",
          request_count(port) > 0
          and did in poller._sensor_threshold_read
          and poller._sensor_threshold_read[did] < later,
          (request_count(port), poller._sensor_threshold_read.get(did)))

    hour_on = time.time() + NodePoller._SENSOR_THRESHOLD_REFRESH_S + 1.0
    poller._poll_environment(did, nodes.device(did), config, set(), hour_on)
    check("an hour on the limits are read again -- an optic can be swapped",
          poller._sensor_threshold_read[did] == hour_on,
          poller._sensor_threshold_read.get(did))

    # --- poll_now drops both stamps, the existing contract
    poller._sensor_threshold_read[did] = time.time()
    poller.poll_now(did)
    check("poll_now clears the threshold cadence stamp alongside the sensor "
          "one, so an operator never waits out the hour",
          did not in poller._sensor_threshold_read,
          poller._sensor_threshold_read)
    nodes.close()
finally:
    stub.kill()

# --- a cut-short walk must KEEP what is stored ---------------------------
stub, port = _paths.spawn_stub("stub_agent_ups_env.py", "cisco_dom_thresholds")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    nodes, _alerts, _engine = build("cut_short")
    did = cisco_device(nodes, "cisco-sw")
    poller = NodePoller(nodes)
    config = nodes.effective_config(nodes.device(did))
    poller._poll_environment(did, nodes.device(did), config, set(), time.time())
    before = nodes.interface_thresholds(did)
    check("limits are stored on the first pass", len(before) == 4, sorted(before))

    incomplete = [(dict(), False)] * 3

    def cut_short(device, cfg, base_oid, **kwargs):
        if base_oid.startswith("1.3.6.1.4.1.9.9.91.1.2.1.1"):
            return {}, False
        return real_walk(device, cfg, base_oid, **kwargs)

    real_walk = poller._walk_column_status
    poller._walk_column_status = cut_short
    poller._sensor_threshold_read.clear()
    poller._sensor_read.clear()
    poller._poll_environment(did, nodes.device(did), config, set(), time.time())
    poller._walk_column_status = real_walk
    check("a walk cut short writes NOTHING: an empty answer would read as "
          "'this device publishes no limits', which switches optic power "
          "alerting off for every port on it",
          nodes.interface_thresholds(did).keys() == before.keys(),
          sorted(nodes.interface_thresholds(did)))
    nodes.close()
finally:
    stub.kill()

# --- gating: a Cisco device with no optics, and a non-Cisco device --------
stub, port = _paths.spawn_stub("stub_agent_ups_env.py", "sensors")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    nodes, _alerts, _engine = build("gate_no_optics")
    gid = nodes.ensure_default_group()
    nodes.update_group(gid, snmp_version=1, community="public",
                       snmp_timeout_s=1.0, snmp_retries=0)
    did = nodes.add_device("127.0.0.1", name="not-cisco", group_id=gid)
    nodes.replace_interfaces(did, [{"if_index": 1, "descr": "Gi1/0/1"}])
    poller = NodePoller(nodes)
    config = nodes.effective_config(nodes.device(did))
    poller._poll_environment(did, nodes.device(did), config, set(), time.time())
    check("a device that is not Cisco never walks the Cisco threshold table "
          "and stores nothing -- there is no vendor-neutral table to read, "
          "and a dead walk an hour per device is a cost with no answer",
          nodes.interface_thresholds(did) == {}
          and did not in poller._sensor_threshold_read,
          (nodes.interface_thresholds(did), poller._sensor_threshold_read))
    nodes.close()
finally:
    stub.kill()

# ================================================ § 3 the eight built-ins
print()
print("the eight rules")

nodes, alerts, engine = build("rules")
EIGHT = ("sfp_rx_power_low", "sfp_rx_power_low_alarm",
         "sfp_rx_power_high", "sfp_rx_power_high_alarm",
         "sfp_tx_power_low", "sfp_tx_power_low_alarm",
         "sfp_tx_power_high", "sfp_tx_power_high_alarm")
rules = {key: alerts.rule_by_key(key) for key in EIGHT}
check("all eight optic power rules are seeded",
      all(rules[key] is not None for key in EIGHT),
      [key for key in EIGHT if rules[key] is None])
check("none of them carries a threshold of its own -- there is no global "
      "number left to be wrong for most of the fleet's optics",
      all(rules[key]["threshold"] is None
          and rules[key]["clear_threshold"] is None for key in EIGHT),
      {key: (rules[key]["threshold"], rules[key]["clear_threshold"])
       for key in EIGHT})
check("each reads the DOM metric root of its own direction",
      all(rules[key]["source_kind"] == ("sfp_rx_dbm" if "_rx_" in key
                                        else "sfp_tx_dbm") for key in EIGHT),
      {key: rules[key]["source_kind"] for key in EIGHT})
check("the alarm halves are severity 2 (this scale's 'critical') and the "
      "warning halves severity 4",
      all(rules[key]["severity"] == (2 if key.endswith("_alarm") else 4)
          for key in EIGHT),
      {key: rules[key]["severity"] for key in EIGHT})
check("the four low keys compare 'below' and the four high keys 'above' -- "
      "too much light is a real fault, and the optic publishes a ceiling "
      "for it",
      all(rules[key]["comparison"] == ("below" if "_low" in key else "above")
          for key in EIGHT),
      {key: rules[key]["comparison"] for key in EIGHT})
check("the two keys that already existed keep their name, severity and "
      "for_polls, so an upgraded install's tuning of those survives",
      rules["sfp_rx_power_low"]["name"] == "Optic receive power low"
      and rules["sfp_tx_power_low"]["name"] == "Optic transmit power low"
      and rules["sfp_rx_power_low"]["for_polls"] == 2,
      dict(rules["sfp_rx_power_low"]))
check("each warning rolls up under its own alarm, and each alarm under "
      "device_down",
      all(ROLLED_UP_BY.get(key) == (f"{key}_alarm" if not key.endswith("_alarm")
                                    else "device_down") for key in EIGHT),
      {key: ROLLED_UP_BY.get(key) for key in EIGHT})
check("sfp_temp_high is untouched: only optical POWER moved to published "
      "limits",
      alerts.rule_by_key("sfp_temp_high")["threshold"] == 70.0
      and ROLLED_UP_BY["sfp_temp_high"] == "device_down",
      dict(alerts.rule_by_key("sfp_temp_high")))
check("every one of the eight is mapped to a (root, column) pair, and "
      "nothing else is",
      set(PUBLISHED_THRESHOLD_RULES) == set(EIGHT),
      sorted(PUBLISHED_THRESHOLD_RULES))
check("same_metric_pair recognises the new pairs and refuses an outage "
      "parent",
      same_metric_pair(rules["sfp_rx_power_low"],
                       rules["sfp_rx_power_low_alarm"])
      and not same_metric_pair(rules["sfp_rx_power_low_alarm"],
                               alerts.rule_by_key("device_down"))
      and not same_metric_pair(rules["sfp_rx_power_low"],
                               rules["sfp_tx_power_low_alarm"]))
check("...and reads a plain dict the same way a database row does",
      same_metric_pair({"kind": "threshold", "source_kind": "sfp_rx_dbm"},
                       {"kind": "threshold", "source_kind": "sfp_rx_dbm"})
      and not same_metric_pair({"kind": "threshold", "source_kind": ""},
                               {"kind": "threshold", "source_kind": ""}))

# --- the other six threshold rules must be exactly as they were
SIX = ("cpu_high", "mem_high", "if_in_util_high", "temp_chassis_high",
       "humidity_high", "packet_loss_high")
check("the threshold rules that are NOT optic power keep their own numbers "
      "and take exactly the path they always did",
      all(alerts.rule_by_key(key)["threshold"] is not None
          and key not in PUBLISHED_THRESHOLD_RULES for key in SIX),
      {key: alerts.rule_by_key(key)["threshold"] for key in SIX})
nodes.close()


# ================================= § 4 the engine reads published limits only
print()
print("the engine: published limits, and nothing else")


def optic_ports(nodes, did, if_indexes=(7,)):
    nodes.replace_interfaces(did, [
        {"if_index": i, "descr": f"GigabitEthernet1/0/{i}", "alias": "",
         "admin_status": "up", "oper_status": "up"} for i in if_indexes])


def publish(nodes, engine, did, if_index, root="sfp_rx_dbm", **bands):
    rows = [{"if_index": if_index, "metric_root": root,
             "low_alarm": bands.get("low_alarm"),
             "low_warn": bands.get("low_warn"),
             "high_warn": bands.get("high_warn"),
             "high_alarm": bands.get("high_alarm"),
             "updated_ts": time.time()}]
    nodes.replace_interface_thresholds(did, CISCO_SOURCE, rows)
    # The engine caches its fleet-wide read for _PUBLISHED_CACHE_S against
    # the poller's hourly write cadence; a test writes them mid-run.
    engine._published_cache = (0.0, None, None)


def sample(nodes, did, if_index, ts, value, root="sfp_rx_dbm"):
    nodes.record_metric_sample(did, f"{root}.{if_index}",
                               f"Gi1/0/{if_index} Rx power", "dBm", "gauge",
                               ts, value)


def open_rows(alerts, rule_key):
    rule = alerts.rule_by_key(rule_key)
    return alerts.alerts(state="unresolved", rule_id=rule["id"])


# --- no published limits means no alert, even with a number hand-set
nodes, alerts, engine = build("no_fallback")
engine._tick()
did = add_device(nodes, "10.1.0.1", "unpublished-sw")
optic_ports(nodes, did)
alerts._conn.execute(
    "UPDATE rules SET threshold = -22.0, clear_threshold = -20.0"
    " WHERE key = 'sfp_rx_power_low'")
alerts._conn.commit()
base = time.time()
for i in range(4):
    sample(nodes, did, 7, base + i, -30.0)
    engine._tick()
check("a port whose switch publishes NO limits raises no optic power alert, "
      "even with a threshold hand-written onto the rule row -- there is no "
      "global fallback left, which is the whole point",
      open_rows(alerts, "sfp_rx_power_low") == [],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")])
check("...and no streak was counted for it either, so a port that starts "
      "publishing tomorrow starts a fresh one",
      not [k for k in engine._breach_streaks
           if k[0] == alerts.rule_by_key("sfp_rx_power_low")["id"]],
      list(engine._breach_streaks))
nodes.close()

# --- each band fires, with the right dedup key and extras
nodes, alerts, engine = build("bands")
engine._tick()
did = add_device(nodes, "10.1.0.2", "publishing-sw")
optic_ports(nodes, did, (7, 8, 9, 10))
base = time.time()
for if_index in (7, 8, 9, 10):
    nodes.replace_interface_thresholds(did, CISCO_SOURCE, [
        {"if_index": i, "metric_root": "sfp_rx_dbm", "low_alarm": -24.0,
         "low_warn": -22.0, "high_warn": -1.0, "high_alarm": 1.0,
         "updated_ts": base} for i in (7, 8, 9, 10)])
engine._published_cache = (0.0, None, None)

for i in range(2):
    sample(nodes, did, 7, base + i, -22.5)      # warning band only
    sample(nodes, did, 8, base + i, -30.0)      # past the low alarm
    sample(nodes, did, 9, base + i, -0.5)       # high warning band only
    sample(nodes, did, 10, base + i, 5.0)       # past the high alarm
    engine._tick()

low_warn = open_rows(alerts, "sfp_rx_power_low")
check("a port under its published low WARNING opens the warning rule alone",
      [r["entity_id"] for r in low_warn] == [f"{did}:7"],
      [dict(r) for r in low_warn])
check("...keyed per port, so the dedup key names the interface",
      low_warn and low_warn[0]["dedup_key"]
      == f"sfp_rx_power_low:interface:{did}:7", dict(low_warn[0]))
extra = json.loads(low_warn[0]["extra_json"])
check("the alert's Threshold extra is the number THIS PORT was judged "
      "against, and says where it came from",
      extra["threshold"] == "-22.0"
      and extra["threshold_source"] == " (published by the optic)", extra)
check("a port past its published low ALARM opens the alarm rule",
      [r["entity_id"] for r in open_rows(alerts, "sfp_rx_power_low_alarm")]
      == [f"{did}:8"],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low_alarm")])
check("a port over its published high WARNING opens the high warning rule",
      [r["entity_id"] for r in open_rows(alerts, "sfp_rx_power_high")]
      == [f"{did}:9"],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_high")])
check("a port over its published high ALARM opens the high alarm rule",
      [r["entity_id"] for r in open_rows(alerts, "sfp_rx_power_high_alarm")]
      == [f"{did}:10"],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_high_alarm")])
check("the clear sits one dB back from the published level, since a "
      "transceiver publishes a level and no band (PUBLISHED_HYSTERESIS)",
      PUBLISHED_HYSTERESIS["sfp_rx_dbm"] == 1.0
      and PUBLISHED_HYSTERESIS["sfp_tx_dbm"] == 1.0, PUBLISHED_HYSTERESIS)
sample(nodes, did, 7, base + 10, -21.5)
engine._tick()
check("...so a reading back inside the published limit but not yet a whole "
      "dB past it holds the alert open",
      len(open_rows(alerts, "sfp_rx_power_low")) == 1,
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")])
sample(nodes, did, 7, base + 11, -20.5)
engine._tick()
check("...and a dB clear of it closes the alert",
      open_rows(alerts, "sfp_rx_power_low") == [],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")])
nodes.close()

# --- partial publication
nodes, alerts, engine = build("partial")
engine._tick()
did = add_device(nodes, "10.1.0.3", "partial-sw")
optic_ports(nodes, did)
base = time.time()
publish(nodes, engine, did, 7, low_alarm=-24.0)
for i in range(2):
    sample(nodes, did, 7, base + i, -30.0)
    engine._tick()
check("a device publishing only the alarm level alerts on it and stays "
      "silent on the warning it never published -- partial publication is "
      "normal on older IOS and needs no special handling",
      len(open_rows(alerts, "sfp_rx_power_low_alarm")) == 1
      and open_rows(alerts, "sfp_rx_power_low") == [],
      ([dict(r) for r in open_rows(alerts, "sfp_rx_power_low_alarm")],
       [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")]))
nodes.close()

# --- the dark optic, and the asymmetry that must stay
nodes, alerts, engine = build("dark")
engine._tick()
did = add_device(nodes, "10.1.0.4", "dark-sw")
optic_ports(nodes, did, (7, 8))
base = time.time()
nodes.replace_interface_thresholds(did, CISCO_SOURCE, [
    {"if_index": i, "metric_root": "sfp_rx_dbm", "low_alarm": -24.0,
     "low_warn": -22.0, "high_warn": -1.0, "high_alarm": 1.0,
     "updated_ts": base} for i in (7, 8)])
engine._published_cache = (0.0, None, None)
for i in range(4):
    sample(nodes, did, 7, base + i, -40.0)
    engine._tick()
check("a dark optic at -40 dBm opens NEITHER low rule, however many polls "
      "it stays dark -- a port with no light is interface_down's to report",
      open_rows(alerts, "sfp_rx_power_low") == []
      and open_rows(alerts, "sfp_rx_power_low_alarm") == [],
      ([dict(r) for r in open_rows(alerts, "sfp_rx_power_low")],
       [dict(r) for r in open_rows(alerts, "sfp_rx_power_low_alarm")]))
for i in range(2):
    sample(nodes, did, 8, base + 10 + i, -30.0)
    engine._tick()
check("(an alarm is open on port 8 to go dark on)",
      len(open_rows(alerts, "sfp_rx_power_low_alarm")) == 1)
sample(nodes, did, 8, base + 20, -40.0)
engine._tick()
check("a lit port going dark resolves the open alarm rather than leaving "
      "it on a stale reading",
      open_rows(alerts, "sfp_rx_power_low_alarm") == [],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low_alarm")])
# The asymmetry is deliberate and must not be "fixed": evaluate_threshold's
# dark -> clear branch is 'below'-only because -40 dBm is the bottom of the
# scale. It cannot be at or above any published high threshold, so breaches()
# never opened a high alert on it and there is never one there to close.
HIGH_KEYS = ("sfp_rx_power_high", "sfp_rx_power_high_alarm",
             "sfp_tx_power_high", "sfp_tx_power_high_alarm")
check("the four high keys compare 'above', and a -40 dBm reading breaches "
      "none of them at any published ceiling -- which is why the dark->clear "
      "branch is 'below'-only and widening it would add a dead branch",
      all(alerts.rule_by_key(key)["comparison"] == "above" for key in HIGH_KEYS)
      and not any(breaches({"threshold": ceiling, "comparison": "above",
                            "source_kind": "sfp_rx_dbm", "key": key},
                           -40.0)
                  for key in HIGH_KEYS for ceiling in (-30.0, -1.0, 1.0)),
      {key: alerts.rule_by_key(key)["comparison"] for key in HIGH_KEYS})
check("...and both high rules stayed shut on the dark port throughout",
      open_rows(alerts, "sfp_rx_power_high") == []
      and open_rows(alerts, "sfp_rx_power_high_alarm") == [])
nodes.close()

# --- an optic swap under a live streak
nodes, alerts, engine = build("swap")
engine._tick()
did = add_device(nodes, "10.1.0.5", "swap-sw")
optic_ports(nodes, did)
base = time.time()
publish(nodes, engine, did, 7, low_warn=-22.0)
sample(nodes, did, 7, base, -30.0)
engine._tick()
rule_id = alerts.rule_by_key("sfp_rx_power_low")["id"]
streak_key = (rule_id, f"{did}:7")
check("(one poll of breach is counted, one short of for_polls)",
      engine._breach_streaks[streak_key][1] == 1,
      engine._breach_streaks.get(streak_key))
publish(nodes, engine, did, 7, low_warn=-35.0)     # a longer-reach optic
sample(nodes, did, 7, base + 1, -30.0)
engine._tick()
check("swapping the optic moves the published limit, which resets the "
      "streak exactly as an override edit does -- a streak counted against "
      "a number that no longer applies is not evidence",
      engine._breach_streaks[streak_key][1] == 0
      and open_rows(alerts, "sfp_rx_power_low") == [],
      (engine._breach_streaks.get(streak_key),
       [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")]))
nodes.close()

# --- the override's enabled flag is still honoured
nodes, alerts, engine = build("override_off")
engine._tick()
did = add_device(nodes, "10.1.0.6", "muted-sw")
optic_ports(nodes, did)
base = time.time()
publish(nodes, engine, did, 7, low_warn=-22.0)
alerts.set_device_threshold(did, "sfp_rx_power_low", threshold=None,
                            clear_threshold=None, enabled=False)
for i in range(4):
    sample(nodes, did, 7, base + i, -30.0)
    engine._tick()
check("an override that turns the rule off for ONE switch still silences "
      "it -- that is a statement about the switch, not about physics",
      open_rows(alerts, "sfp_rx_power_low") == [],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")])
raised = None
try:
    alerts.set_device_threshold(did, "sfp_rx_power_low", threshold=-24.0,
                                clear_threshold=-21.0)
except ValueError as exc:
    raised = exc
check("...while a NUMBER on the same override is refused out loud rather "
      "than stored and silently ignored",
      raised is not None and "publishes" in str(raised), str(raised))

# The rules route refuses it too, and -- the reason it has its own check
# rather than leaning on alertsdb's -- a NULL threshold on one of these keys
# must NOT trip the generic "a threshold rule needs a threshold" guard, which
# every other threshold rule is right to have.
rule = alerts.rule_by_key("sfp_rx_power_high")
raised = None
try:
    api._validated_threshold_fields("threshold", rule, {"threshold": 1.0})
except ValueError as exc:
    raised = exc
check("the rules route refuses a number on a published-threshold key, "
      "naming the rule and why",
      raised is not None and "sfp_rx_power_high" in str(raised), str(raised))
check("...and an ordinary edit of the same rule passes straight through, "
      "rather than being refused for having no threshold",
      api._validated_threshold_fields(
          "threshold", rule, {"notify": False, "threshold": None})
      == {"notify": False})
raised = None
try:
    api._validated_threshold_fields("threshold", alerts.rule_by_key("cpu_high"),
                                    {"threshold": None})
except ValueError as exc:
    raised = exc
check("...while a rule that is NOT published-threshold still needs one",
      raised is not None and "needs a threshold" in str(raised), str(raised))
nodes.close()

# --- a limit that goes away must still resolve what it opened
nodes, alerts, engine = build("unpublished_resolve")
engine._tick()
did = add_device(nodes, "10.1.0.7", "stopped-publishing-sw")
optic_ports(nodes, did)
base = time.time()
publish(nodes, engine, did, 7, low_warn=-22.0)
for i in range(2):
    sample(nodes, did, 7, base + i, -30.0)
    engine._tick()
check("(an alert is open on a published limit, to take the limit away from)",
      len(open_rows(alerts, "sfp_rx_power_low")) == 1,
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")])
nodes.replace_interface_thresholds(did, CISCO_SOURCE, [])
engine._published_cache = (0.0, None, None)
sample(nodes, did, 7, base + 2, -30.0)
engine._tick()
check("a port whose published limit goes away -- swapped optic, a band that "
      "no longer passes the sanity gate, a switch that stopped answering -- "
      "has its open alert RESOLVED on the next tick: the evaluator never "
      "reaches that rule for that port again, so nothing else could ever "
      "clear it",
      open_rows(alerts, "sfp_rx_power_low") == [],
      [dict(r) for r in open_rows(alerts, "sfp_rx_power_low")])
resolved = alerts._conn.execute(
    "SELECT resolved_by FROM alerts WHERE dedup_key = ?",
    (f"sfp_rx_power_low:interface:{did}:7",)).fetchone()
check("...resolved_by='' like every other automatic resolve, so a port that "
      "starts publishing again and is still dark opens a fresh alert rather "
      "than finding itself permanently suppressed",
      resolved is not None and resolved["resolved_by"] == "",
      dict(resolved) if resolved else None)
nodes.close()

# --- and the branch that does it stays cheap on the path it dominates
nodes, alerts, engine = build("unpublished_cost")
engine._tick()
did = add_device(nodes, "10.1.0.8", "no-limits-sw")
optic_ports(nodes, did, (7, 8, 9, 10))
base = time.time()
resolve_calls = []
open_key_reads = []
real_resolve = alerts.resolve_by_dedup
real_open_keys = alerts.open_dedup_keys


def spy_resolve(dedup, *args, **kwargs):
    resolve_calls.append(dedup)
    return real_resolve(dedup, *args, **kwargs)


def spy_open_keys():
    open_key_reads.append(1)
    return real_open_keys()


alerts.resolve_by_dedup = spy_resolve
alerts.open_dedup_keys = spy_open_keys
for i in range(3):
    for if_index in (7, 8, 9, 10):
        sample(nodes, did, if_index, base + i, -30.0)
    engine._tick()
alerts.resolve_by_dedup = real_resolve
alerts.open_dedup_keys = real_open_keys
check("four unpublished ports over three ticks issue NO resolve query for "
      "the optic power rules -- with nothing open there is nothing to "
      "resolve, and this branch runs for most ports on most ticks",
      [k for k in resolve_calls if k.startswith("sfp_")] == [], resolve_calls)
check("...and the open dedup keys are read at most once per tick, not once "
      "per port per tick",
      len(open_key_reads) <= 3, len(open_key_reads))
nodes.close()

print()
if FAILS:
    print(f"{len(FAILS)} FAILED: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
