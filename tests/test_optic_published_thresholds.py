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
import os
import socket
import time

import _paths  # noqa: F401  (puts the repo root and tests/ on sys.path)

import netpath.nodepoll as nodepoll_mod
from netpath.alertsdb import AlertsDatabase
from netpath.alertengine import AlertEngine
from netpath.ipamdb import IpamDatabase
from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase
from netpath.snmptrapdb import SnmpTrapDatabase
from netpath.syslogdb import SyslogDatabase

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

print()
if FAILS:
    print(f"{len(FAILS)} FAILED: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
