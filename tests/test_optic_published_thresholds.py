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


print()
if FAILS:
    print(f"{len(FAILS)} FAILED: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
