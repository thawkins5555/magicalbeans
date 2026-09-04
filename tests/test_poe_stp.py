"""PoE and STP polling (Tier 1 #7): PSE budget/consumption and per-port
state stored via nodepoll._poll_poe, bridge state and per-port state via
_poll_stp, the topology-change counter recorded as an ordinary metric
sample, the capability probe remembered so a non-PoE/non-STP device is
probed exactly once, and poe_enabled/stp_enabled inheritance."""
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("poe_stp_")

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def stub_stat(port: int, command: bytes) -> str:
    import socket
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


def device_against(db: NodesDatabase, port: int, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


def two_ports(db: NodesDatabase, device_id: int) -> None:
    """The interfaces PoE/STP writes join onto — created directly, the same
    shortcut test_mac_tables.py's device_against takes, since these tests
    are about _poll_poe/_poll_stp, not the interface poll itself."""
    db.replace_interfaces(device_id, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"}])


# ------------------------------------------------------------------- PoE

stub, port = spawn_stub("stub_agent_l2.py", "poe")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("poe")
    did = device_against(db, port, "poe-sw")
    two_ports(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    check("poe_enabled defaults on", config.get("poe_enabled") == 1, config)
    poller._poll_poe(did, device, config)

    device = db.device(did)
    check("the capability probe records poe_capable=True on the first hit",
          device["poe_capable"] == 1, device["poe_capable"])

    metrics = {m["key"]: m for m in db.metrics(did)}
    check("the PSE budget is stored as an ordinary metric sample",
          "poe_budget_w" in metrics and metrics["poe_budget_w"]["last_value"] == 370.0,
          metrics.get("poe_budget_w"))
    check("...alongside the consumption figure",
          "poe_consumption_w" in metrics
          and metrics["poe_consumption_w"]["last_value"] == 214.0,
          metrics.get("poe_consumption_w"))

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("port 1 (delivering power) got its admin/detection/milliwatts stored",
          ifaces[1]["poe_admin"] == "enabled"
          and ifaces[1]["poe_detect_status"] == "deliveringPower"
          and ifaces[1]["poe_power_mw"] == 15400, ifaces[1])
    check("port 2 (disabled) got its state stored too",
          ifaces[2]["poe_admin"] == "disabled"
          and ifaces[2]["poe_detect_status"] == "disabled", ifaces[2])
    db.close()
finally:
    stub.kill()

# ------------------------------------------------ PoE: probed once, then skipped
stub, port = spawn_stub("stub_agent_l2.py", "no_poe")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("no_poe")
    did = device_against(db, port, "no-poe-sw")
    two_ports(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    reset_count(port)
    poller._poll_poe(did, device, config)
    first_requests = request_count(port)
    device = db.device(did)
    check("a device with no PSE table is probed once and marked incapable",
          device["poe_capable"] == 0, device["poe_capable"])
    check("...that first probe cost at least one request",
          first_requests >= 1, first_requests)

    reset_count(port)
    poller._poll_poe(did, device, config)     # second call: same device row
    second_requests = request_count(port)
    check("a device already known incapable is never walked again",
          second_requests == 0, second_requests)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------------------------- STP

stub, port = spawn_stub("stub_agent_l2.py", "stp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("stp")
    did = device_against(db, port, "stp-sw")
    two_ports(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    check("stp_enabled defaults on", config.get("stp_enabled") == 1, config)
    poller._poll_stp(did, device, config)

    device = db.device(did)
    check("the capability probe records stp_capable=True on the first hit",
          device["stp_capable"] == 1, device["stp_capable"])
    check("bridge-wide state is stored on the device row",
          device["stp_protocol_spec"] == "ieee8021d"
          and device["stp_priority"] == 32768
          and device["stp_root_cost"] == 4
          and device["stp_root_port"] == 1
          and device["stp_root_id"], dict(device))
    check("...including time-since-change converted from TimeTicks to seconds",
          device["stp_time_since_change_s"] == 120.0, device["stp_time_since_change_s"])

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("bridge port 5 (-> ifIndex 1 via the MAC table's own port map) is forwarding",
          ifaces[1]["stp_state"] == "forwarding", ifaces[1])
    check("bridge port 7 (-> ifIndex 2) is blocking",
          ifaces[2]["stp_state"] == "blocking", ifaces[2])

    metrics = {m["key"]: m for m in db.metrics(did)}
    check("the topology-change counter is stored as a metric sample",
          "stp_topology_changes" in metrics
          and metrics["stp_topology_changes"]["last_value"] == 5.0,
          metrics.get("stp_topology_changes"))

    stub_stat(port, b"BUMP_TOPO")
    stub_stat(port, b"BUMP_TOPO")
    time.sleep(0.05)
    poller._poll_stp(did, db.device(did), config)
    series_metric = db.metrics(did)
    topo = next(m for m in series_metric if m["key"] == "stp_topology_changes")
    check("...and increases when the device reports more changes",
          topo["last_value"] == 7.0, topo["last_value"])
    points = db.series(did, topo["id"], time.time() - 3600, time.time() + 60)
    check("...leaving a history a future rule/chart can read (series has 2 points)",
          len(points) >= 2, points)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------ STP: probed once, then skipped
stub, port = spawn_stub("stub_agent_l2.py", "no_stp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("no_stp")
    did = device_against(db, port, "no-stp-sw")
    two_ports(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    reset_count(port)
    poller._poll_stp(did, device, config)
    first_requests = request_count(port)
    device = db.device(did)
    check("a device with no dot1dStp is probed once and marked incapable",
          device["stp_capable"] == 0, device["stp_capable"])
    check("...that first probe cost at least one request", first_requests >= 1, first_requests)

    reset_count(port)
    poller._poll_stp(did, device, config)
    second_requests = request_count(port)
    check("a device already known incapable is never walked again",
          second_requests == 0, second_requests)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------------- settings inheritance
db = new_db("settings")
gid = db.ensure_default_group()
db.update_group(gid, poe_enabled=0, stp_enabled=0)
did_off = db.add_device("10.0.0.80", name="off-sw", group_id=gid)
did_on = db.add_device("10.0.0.81", name="on-sw", group_id=gid,
                       poe_enabled=1, stp_enabled=1)
config_off = db.effective_config(db.device(did_off))
config_on = db.effective_config(db.device(did_on))
check("a group can turn PoE/STP polling off, inherited by a device",
      config_off.get("poe_enabled") == 0 and config_off.get("stp_enabled") == 0,
      config_off)
check("a device override beats the group's off switch",
      config_on.get("poe_enabled") == 1 and config_on.get("stp_enabled") == 1,
      config_on)
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
