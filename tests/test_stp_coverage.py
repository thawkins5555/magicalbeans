"""5.62.0: one check per cause on Dora's list that could hide a spanning-
tree block on a Catalyst PVST+ estate -- against the six stub_agent_l2.py
modes tests/stubs/stub_agent_l2.py adds for this release, through a real
NodePoller, the same fixture shape tests/test_stp_vlan.py and
tests/test_stp_bundle.py already use."""
import time

import _paths
from _paths import spawn_stub, tmpdir

TMP = tmpdir("stp_coverage_")

import netpath.nodepoll.environment_mixin as environment_mixin_mod
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


def device_against(db: NodesDatabase, port: int, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


def mark_cisco(db: NodesDatabase, did: int) -> None:
    """test_stp_vlan.py's own mark_cisco idiom: writes vendor_detected
    without a real identify walk."""
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity={"vendor_detected": "cisco"},
                   uptime_ticks=None, status="up", reachable=True)


class CaptureLog:
    """Just enough of eventlog to read back what the poller wrote."""

    def __init__(self):
        self.lines = []

    def add(self, category, message, target="", detail=""):
        self.lines.append(message)


# ---------------------------------------------- 1. no-VLAN-1 trunk blocks

stub, port = spawn_stub("stub_agent_l2.py", "pvst-no-vlan1-trunk")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("no_vlan1_trunk")
    did = device_against(db, port, "no-vlan1-sw")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"},
        {"if_index": 12, "descr": "Gi0/12 trunk"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("a trunk absent from the DEFAULT context's own map/state reads "
          "blocking from its per-VLAN read alone",
          ifaces[12]["stp_state"] == "blocking", ifaces[12])
    check("...naming VLAN 30 as the blocking VLAN",
          ifaces[12]["stp_blocking_vlans"] == "30", ifaces[12])
    device = db.device(did)
    check("...and no bridge port is reported unmapped -- every context "
          "answered its own map for it",
          not device["stp_scan_unmapped"], device["stp_scan_unmapped"])
    db.close()
finally:
    stub.kill()

# ------------------------------------------------- 2. unmapped bridge port

stub, port = spawn_stub("stub_agent_l2.py", "pvst-unmapped")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("unmapped")
    did = device_against(db, port, "unmapped-sw")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    poller.log = CaptureLog()
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    device = db.device(did)
    unmapped = (device["stp_scan_unmapped"] or "").split(",")
    check("a bridge port seen in a VLAN's state table but mapped in no "
          "VLAN's port table lands in devices.stp_scan_unmapped",
          "9" in unmapped, device["stp_scan_unmapped"])
    check("...and the Events log carries the same fact",
          any("bridge port(s) 9 in no VLAN's port table" in line
              for line in poller.log.lines),
          poller.log.lines)
    db.close()
finally:
    stub.kill()

# --------------------------------------------- 3. truncated default map

stub, port = spawn_stub("stub_agent_l2.py", "pvst-map-truncated")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("map_truncated")
    did = device_against(db, port, "truncated-sw")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"},
        {"if_index": 3, "descr": "Gi0/3"}])
    mark_cisco(db, did)
    # One row per GETBULK request, so the walk's own cursor -- the last
    # accepted row's OID -- is what the next request carries; dropping
    # port 7's row times out the request that would have fetched port 9's.
    db.save_settings({"snmp_bulk_max_repetitions": 1})
    stub_stat(port, b"DROP_OID 1.3.6.1.2.1.17.1.4.1.2.7")
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    check("a default-context bridge-port map cut short by a dropped row "
          "is never cached",
          did not in poller._bridge_port_map_cache, poller._bridge_port_map_cache)
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("...yet every port still resolves a state, off the per-VLAN "
          "reads' own complete maps",
          all(ifaces[i]["stp_state"] is not None for i in (1, 2, 3)), ifaces)
    check("...port 7 (-> ifIndex 2) still reads blocking from VLAN 30",
          ifaces[2]["stp_state"] == "blocking", ifaces[2])
    stub_stat(port, b"CLEAR_DROPS")
    db.close()
finally:
    stub.kill()

# ------------------------------------------------ 4. VTP timeout keeps cache

stub, port = spawn_stub("stub_agent_l2.py", "pvst-vtp-timeout")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("vtp_timeout")
    did = device_against(db, port, "vtp-timeout-sw")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)   # first pass: full VLAN list, cached
    vlans_before = set(poller._stp_vlan_cache[did]["vlans"])
    check("the first pass caches all three operational VLANs",
          vlans_before == {"10", "20", "30"}, vlans_before)

    stub_stat(port, b"DROP_OID 1.3.6.1.4.1.9.9.46.1.3.1.1.2")
    poller._run_stp_vlan_pass(db.device(did), config)   # second pass: VTP times out

    vlans_after = set(poller._stp_vlan_cache[did]["vlans"])
    check("a VTP list timeout on the second pass keeps the first pass's "
          "cache untouched",
          vlans_after == vlans_before, vlans_after)
    device = db.device(did)
    check("...and the scan summary says why",
          device["stp_scan_note"] == "VLAN list unavailable", device["stp_scan_note"])
    stub_stat(port, b"CLEAR_DROPS")
    db.close()
finally:
    stub.kill()

# ------------------------------------------------------ 5. broken is blocked

stub, port = spawn_stub("stub_agent_l2.py", "pvst-broken")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("broken")
    did = device_against(db, port, "broken-sw")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("port 7 (-> ifIndex 2) reading broken(6) in VLAN 20 stores "
          "stp_state='broken', not 'blocking' or dropped",
          ifaces[2]["stp_state"] == "broken", ifaces[2])
    check("nodesdb's own blocked-state set treats broken as blocked, the "
          "same set web/api/mapper.py's blocking test mirrors",
          "broken" in NodesDatabase.STP_BLOCKED_STATES,
          NodesDatabase.STP_BLOCKED_STATES)
    db.close()
finally:
    stub.kill()

# ----------------------------------------- 6. Po outside VLAN 1 inherited

stub, port = spawn_stub("stub_agent_l2.py", "stp-po-outside-vlan1")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("po_outside_vlan1")
    did = device_against(db, port, "po-outside-sw")
    db.replace_interfaces(did, [
        {"if_index": 10, "descr": "Gi1/0/1"}, {"if_index": 11, "descr": "Gi1/0/2"},
        {"if_index": 5000, "descr": "Po1"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("the Port-channel, a bridge port only inside @20, still reads "
          "blocking",
          ifaces[5000]["stp_state"] == "blocking"
          and ifaces[5000]["stp_blocking_vlans"] == "20", ifaces[5000])
    check("member 10 inherits it, naming the Port-channel as via",
          ifaces[10]["stp_state"] == "blocking"
          and ifaces[10]["stp_via_if_index"] == 5000, ifaces[10])
    check("member 11 does too",
          ifaces[11]["stp_state"] == "blocking"
          and ifaces[11]["stp_via_if_index"] == 5000, ifaces[11])
    db.close()
finally:
    stub.kill()

# --------------------------------------------- 7. stop clears the in-flight set

db = new_db("stop_clears")
poller = NodePoller(db)
poller._stp_vlan_running.add(999)
poller.begin_stop()
check("begin_stop clears _stp_vlan_running",
      999 not in poller._stp_vlan_running, poller._stp_vlan_running)
db.close()

# --------------------------------------------- 8. stp_capable=0 re-probed

stub, port = spawn_stub("stub_agent_l2.py", "stp")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("reprobe")
    did = device_against(db, port, "reprobe-sw")
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "Gi0/1"}, {"if_index": 2, "descr": "Gi0/2"}])
    db.set_stp_capable(did, False)
    poller = NodePoller(db)
    poller._stp_capable_reprobe[did] = time.time()   # "just probed" -- inside the hour
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)
    device = db.device(did)
    check("a latched stp_capable=0 is not re-probed inside the hour",
          device["stp_capable"] == 0, device["stp_capable"])

    real_time = environment_mixin_mod.time.time
    environment_mixin_mod.time.time = lambda: real_time() + 3700
    try:
        poller._poll_stp(did, db.device(did), config)
    finally:
        environment_mixin_mod.time.time = real_time

    device = db.device(did)
    check("...but is re-probed and flipped to 1 once an hour has passed "
          "and the device answers",
          device["stp_capable"] == 1, device["stp_capable"])
    db.close()
finally:
    stub.kill()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
