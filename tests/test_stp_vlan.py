"""Per-VLAN spanning-tree state (5.37.0): nodepoll._cisco_vlan_stp, the
merge into interfaces.stp_state/stp_blocking_vlans/stp_vlan_count in
_poll_stp, the devices.stp_vlan_capable latch and its hourly re-probe, and
the cut-short rule that keeps stored per-VLAN detail rather than write a
partial view."""
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("stp_vlan_")

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


def communities(port: int) -> set:
    text = stub_stat(port, b"COMMUNITIES")
    return set(text.split(",")) if text else set()


def device_against(db: NodesDatabase, port: int, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


def two_ports(db: NodesDatabase, device_id: int) -> None:
    db.replace_interfaces(device_id, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"}])


def mark_cisco(db: NodesDatabase, did: int) -> None:
    """Writes vendor_detected without a real identify walk -- the idiom
    tests/test_sfp_media.py's own mark_cisco uses."""
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity={"vendor_detected": "cisco"},
                   uptime_ticks=None, status="up", reachable=True)


# --------------------------------------------------------- the per-VLAN merge

stub, port = spawn_stub("stub_agent_l2.py", "pvst")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst")
    did = device_against(db, port, "pvst-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    reset_count(port)
    poller._poll_stp(did, device, config)

    device = db.device(did)
    check("the per-VLAN latch records stp_vlan_capable=True on the first hit",
          device["stp_vlan_capable"] == 1, device["stp_vlan_capable"])

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("port 7 (-> ifIndex 2), blocking only in VLAN 20, reads blocking",
          ifaces[2]["stp_state"] == "blocking", ifaces[2])
    check("...with the blocking VLAN named",
          ifaces[2]["stp_blocking_vlans"] == "20", ifaces[2])
    check("...and both VLAN contexts counted",
          ifaces[2]["stp_vlan_count"] == 2, ifaces[2])
    check("port 5 (-> ifIndex 1), forwarding in every VLAN, reads forwarding "
          "even though the DEFAULT context called it blocking",
          ifaces[1]["stp_state"] == "forwarding", ifaces[1])
    check("...blocked nowhere",
          ifaces[1]["stp_blocking_vlans"] == "", ifaces[1])

    seen = communities(port)
    check("VLAN 1002 (legacy, in the VTP table) is never asked",
          "public@1002" not in seen, seen)
    check("...but VLANs 20 and 30 both are",
          {"public@20", "public@30"} <= seen, seen)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------- non-Cisco device: no '@'

stub, port = spawn_stub("stub_agent_l2.py", "pvst")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_noncisco")
    did = device_against(db, port, "generic-sw")
    two_ports(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    reset_count(port)
    poller._poll_stp(did, device, config)

    device = db.device(did)
    check("a non-Cisco device's per-VLAN latch is never touched",
          device["stp_vlan_capable"] is None, device["stp_vlan_capable"])
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("...and its rows carry no per-VLAN detail",
          ifaces[2]["stp_blocking_vlans"] is None, ifaces[2])

    seen = communities(port)
    check("...because it never sends a community@vlan request at all",
          not any("@" in c for c in seen), seen)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------------------- v3: skipped

stub, port = spawn_stub("stub_agent_l2.py", "pvst")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_v3")
    did = device_against(db, port, "v3-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = {**db.effective_config(device), "snmp_version": 3}

    reset_count(port)
    rows, answered, complete = poller._cisco_vlan_stp(device, config, {})
    check("a v3 config skips the per-VLAN pass outright",
          rows == {} and answered is False and complete is True,
          (rows, answered, complete))
    check("...without sending a single request",
          request_count(port) == 0, request_count(port))
    db.close()
finally:
    stub.kill()

# ------------------------------------------ latch: no VTP table, re-probed

stub, port = spawn_stub("stub_agent_l2.py", "pvst_no_vtp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_no_vtp")
    did = device_against(db, port, "no-vtp-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    # A spy on _cisco_vlan_stp itself: the VTP-less device never sends a
    # community@vlan request either way (there is no VLAN to scope one to),
    # so whether the per-VLAN pass ran at all has to be read off the call
    # count rather than off the wire.
    calls = []
    real_cisco_vlan_stp = poller._cisco_vlan_stp

    def spy(device_arg, config_arg, port_map_arg):
        calls.append(1)
        return real_cisco_vlan_stp(device_arg, config_arg, port_map_arg)
    poller._cisco_vlan_stp = spy

    poller._poll_stp(did, device, config)
    device = db.device(did)
    check("a device with no VTP table latches stp_vlan_capable=False",
          device["stp_vlan_capable"] == 0, device["stp_vlan_capable"])
    check("...after one probe", len(calls) == 1, calls)

    poller._poll_stp(did, db.device(did), config)
    check("...and is not re-probed inside the hourly reprobe window",
          len(calls) == 1, calls)

    # Force the hourly reprobe window open, the same way a test of
    # _mau_read/_cage_read's own cadence would.
    poller._stp_vlan_read[did] = time.time() - poller._SENSOR_REPROBE_S - 1
    poller._poll_stp(did, db.device(did), config)
    check("...but is re-probed once the hour is up",
          len(calls) == 2, calls)
    db.close()
finally:
    stub.kill()

# --------------------------------------------- cut short: stored detail kept

stub, port = spawn_stub("stub_agent_l2.py", "pvst-slow")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_slow")
    did = device_against(db, port, "slow-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    # Pre-seed the per-VLAN detail a prior, complete poll would have
    # stored, so the cut-short poll below has something to keep.
    db.update_interface_stp(did, [{"if_index": 2, "stp_state": "blocking",
                                   "stp_blocking_vlans": "20", "stp_vlan_count": 2}])
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    device = db.device(did)
    check("a walk that answered anything still latches stp_vlan_capable=True",
          device["stp_vlan_capable"] == 1, device["stp_vlan_capable"])
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("a cut-short pass keeps the stored blocking-VLAN detail",
          ifaces[2]["stp_blocking_vlans"] == "20", ifaces[2])
    check("...and the stored VLAN count",
          ifaces[2]["stp_vlan_count"] == 2, ifaces[2])
    check("...and the seeded stp_state is left alone, not flapped to the "
          "global read's forwarding",
          ifaces[2]["stp_state"] == "blocking", ifaces[2])
    db.close()
finally:
    stub.kill()

# ------------------------------------------- F1: no VLAN-1 member ports

stub, port = spawn_stub("stub_agent_l2.py", "pvst-empty1")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_empty1")
    did = device_against(db, port, "empty1-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("VLAN 1 has no member ports, but the per-VLAN pass still runs "
          "and lands its detail",
          ifaces[2]["stp_state"] == "blocking", ifaces[2])
    check("...with the blocking VLAN named",
          ifaces[2]["stp_blocking_vlans"] == "20", ifaces[2])
    db.close()
finally:
    stub.kill()

# ------------------------- F1b: no scalars, but a VLAN context answers

stub, port = spawn_stub("stub_agent_l2.py", "pvst-no-scalars")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_no_scalars")
    did = device_against(db, port, "no-scalars-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    device = db.device(did)
    check("a per-VLAN answer stops the stp_capable=False latch even "
          "though the default context has no dot1dStp scalars at all",
          device["stp_capable"] is None, device["stp_capable"])
    db.close()
finally:
    stub.kill()

# --------------------------------------- F3: 50 VLANs, sliced to 48

stub, port = spawn_stub("stub_agent_l2.py", "pvst-50vlan")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_50vlan")
    did = device_against(db, port, "vlan50-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    reset_count(port)
    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("a 50-VLAN VTP table sliced to the first 48 still counts as a "
          "complete pass",
          ifaces[2]["stp_vlan_count"] == 48, ifaces[2])
    check("...port 7 forwards in all 48",
          ifaces[2]["stp_state"] == "forwarding", ifaces[2])
    check("...port 5 blocks in all 48",
          ifaces[1]["stp_state"] == "blocking" and ifaces[1]["stp_vlan_count"] == 48,
          ifaces[1])
    db.close()
finally:
    stub.kill()

# --------------------------- F4: non-forwarding states must not collapse

stub, port = spawn_stub("stub_agent_l2.py", "pvst-disabled")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_disabled")
    did = device_against(db, port, "disabled-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("disabled(1) in every VLAN context stays disabled, not "
          "forwarding",
          ifaces[2]["stp_state"] == "disabled", ifaces[2])
    db.close()
finally:
    stub.kill()

# ------------------------------- F5: global-only port keeps global state

stub, port = spawn_stub("stub_agent_l2.py", "pvst-orphan")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("pvst_orphan")
    did = device_against(db, port, "orphan-sw")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"},
        {"if_index": 3, "descr": "Gi0/3"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("a port answered only in the global read, never in any VLAN "
          "context, keeps its global state",
          ifaces[3]["stp_state"] == "forwarding", ifaces[3])
    check("...and carries no per-VLAN detail",
          ifaces[3]["stp_blocking_vlans"] is None, ifaces[3])
    db.close()
finally:
    stub.kill()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
