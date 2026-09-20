"""Per-VLAN spanning-tree state (5.37.0): nodepoll._cisco_vlan_stp, the
merge into interfaces.stp_state/stp_blocking_vlans/stp_vlan_count in
_poll_stp, the devices.stp_vlan_capable latch, its own cadence off the poll
pool (5.50.0, _maybe_walk_stp_vlan/_run_stp_vlan_pass), and the cut-short
rule that keeps stored per-VLAN detail rather than write a partial view."""
import time

import _paths
from _paths import spawn_stub, tmpdir

TMP = tmpdir("stp_vlan_")

import netpath.nodepoll as nodepoll_mod
from netpath import nodeoids
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
    check("...and is not re-probed on a later poll with no topology change",
          len(calls) == 1, calls)

    # The negative verdict is now re-tried by the per-VLAN walk's own
    # cadence (_maybe_walk_stp_vlan), off the poll pool -- called directly
    # here the same way test_port_vlans.py exercises _run_vlan_table
    # directly, independent of when the scheduler judges it due.
    poller._run_stp_vlan_pass(db.device(did), config)
    check("...but is re-probed by the per-VLAN walk's own cadence",
          len(calls) == 2, calls)
    db.close()
finally:
    stub.kill()

# --------------------------------------------- cut short: stored detail kept

stub, port = spawn_stub("stub_agent_l2.py", "pvst-slow")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
    check("a per-VLAN answer latches stp_capable=True even though the "
          "default context has no dot1dStp scalars at all",
          device["stp_capable"] == 1, device["stp_capable"])
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("...and the VLAN-20-blocked port's state is written, not skipped",
          ifaces[2]["stp_state"] == "blocking", ifaces[2])
    check("...with the blocking VLAN named",
          ifaces[2]["stp_blocking_vlans"] == "20", ifaces[2])
    db.close()
finally:
    stub.kill()

# --------------------------------------- F3: 50 VLANs, sliced to 48

stub, port = spawn_stub("stub_agent_l2.py", "pvst-50vlan")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
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

# --------------------------- F6: 2+ non-forwarding states, no global value

stub, port = spawn_stub("stub_agent_l2.py", "pvst-mixed")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pvst_mixed")
    did = device_against(db, port, "mixed-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("a port listening in one VLAN and learning in another, absent "
          "from the global read, still gets a written stp_state",
          ifaces[2]["stp_state"] is not None, ifaces[2])
    check("...and blocks nowhere",
          ifaces[2]["stp_blocking_vlans"] == "", ifaces[2])
    db.close()
finally:
    stub.kill()

# --------------------------- v1: noSuchName at the column's last row

stub, port = spawn_stub("stub_agent_l2.py", "pvst")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pvst_v1")
    did = device_against(db, port, "v1-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = {**db.effective_config(device), "snmp_version": 0}

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("a v1 device's noSuchName at dot1dStpPortState's last row still "
          "lands the per-VLAN detail (RFC 1157, not a PAN-OS-style refusal)",
          ifaces[2]["stp_blocking_vlans"] == "20", ifaces[2])
    check("...and the VLAN count",
          ifaces[2]["stp_vlan_count"] == 2, ifaces[2])

    # Direct check of _walk_column_status itself, against the "@20" context
    # where dot1dStpPortState really is the view's last object: v1 rows
    # already accepted before noSuchName is the table end; none accepted
    # is still a real error (the PAN-OS case _error_status_reason covers).
    scoped = {**config, "community": f"{config['community']}@20"}
    values, complete = poller._walk_column_status(
        device, scoped, nodeoids.DOT1D_STP_PORT_STATE)
    check("v1, rows accepted before noSuchName: complete=True",
          complete is True and values, (complete, values))

    _, complete_empty = poller._walk_column_status(
        device, scoped, nodeoids.DOT1D_STP_PORT_STATE + ".7")
    check("v1, noSuchName with zero rows accepted: complete=False",
          complete_empty is False, complete_empty)
    db.close()
finally:
    stub.kill()

# ---------------------------------- 5.50.0: topology-change bypasses cadence

stub, port = spawn_stub("stub_agent_l2.py", "stp")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pvst_topo_trigger")
    did = device_against(db, port, "topo-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    calls = []
    real_cisco_vlan_stp = poller._cisco_vlan_stp

    def spy(device_arg, config_arg, port_map_arg):
        calls.append(1)
        return real_cisco_vlan_stp(device_arg, config_arg, port_map_arg)
    poller._cisco_vlan_stp = spy

    poller._poll_stp(did, device, config)
    check("the per-VLAN pass runs on a device's first sighting",
          len(calls) == 1, calls)

    poller._poll_stp(did, db.device(did), config)
    check("...but not on a later poll with no topology change",
          len(calls) == 1, calls)

    stub_stat(port, b"BUMP_TOPO")
    poller._poll_stp(did, db.device(did), config)
    check("...and runs again the moment dot1dStpTopChanges moves, without "
          "waiting for the cadence",
          len(calls) == 2, calls)
    db.close()
finally:
    stub.kill()

# ------------------------------ 5.50.0: _maybe_walk_stp_vlan's own cadence

db = new_db("stp_vlan_schedule")
gid = db.ensure_default_group()
db.update_group(gid, snmp_version=1, community="public")
did_on = db.add_device("10.1.0.1", name="cadence-sw", group_id=gid,
                       vlan_interval_s=900)
did_off = db.add_device("10.1.0.2", name="cadence-off-sw", group_id=gid,
                        vlan_interval_s=0)
did_noncisco = db.add_device("10.1.0.3", name="cadence-generic-sw",
                             group_id=gid, vlan_interval_s=900)
mark_cisco(db, did_on)
mark_cisco(db, did_off)
poller = NodePoller(db)
now = time.time()

did_not_bridge = db.add_device("10.1.0.4", name="not-a-bridge-sw",
                               group_id=gid, vlan_interval_s=900)
mark_cisco(db, did_not_bridge)
db.set_stp_capable(did_not_bridge, False)

# The scheduling loop (_loop -> _schedule_pass) hands _maybe_walk_stp_vlan
# schedule_rows()' narrow row -- no vendor, no stp_capable -- so vendor and
# stp_capable can only be checked once a walk is actually due, not on
# every pass. Exercised for real here rather than assumed: schedule_rows()
# itself, not a full db.device() row.
narrow_on = next(r for r in db.schedule_rows() if r["id"] == did_on)
config_on = db.effective_config(db.device(did_on))
poller._maybe_walk_stp_vlan(narrow_on, config_on, now)
check("the narrow scheduling-pass row (no vendor/stp_capable columns) "
      "does not crash the first-sighting stagger",
      did_on in poller._next_stp_vlan_walk, poller._next_stp_vlan_walk)
poller._next_stp_vlan_walk.pop(did_on, None)

for did in (did_on, did_off, did_noncisco, did_not_bridge):
    device_row = db.device(did)
    config_row = db.effective_config(device_row)
    poller._maybe_walk_stp_vlan(device_row, config_row, now)
check("every v1/v2c device with a community is staggered on first sighting, "
      "regardless of vendor or stp_capable -- both need a full row this "
      "call never had a reason to fetch yet",
      all(did in poller._next_stp_vlan_walk
          for did in (did_on, did_off, did_noncisco, did_not_bridge)),
      poller._next_stp_vlan_walk)
check("...off vlan_interval_s=0 still falls inside the hourly fallback",
      now <= poller._next_stp_vlan_walk[did_off] <= now + poller._SENSOR_REPROBE_S,
      poller._next_stp_vlan_walk)

# The due-firing path itself: a fake executor that only records what was
# submitted, so the flag/next-walk bookkeeping can be checked without
# racing a real background job to completion.
submitted = []


class _FakeExecutor:
    def submit(self, fn, device_id):
        submitted.append((fn, device_id))


poller._mac_executor = _FakeExecutor()
for did in (did_on, did_off, did_noncisco, did_not_bridge):
    poller._next_stp_vlan_walk[did] = now - 1
    poller._maybe_walk_stp_vlan(db.device(did), db.effective_config(db.device(did)), now)

check("a due, capable Cisco device takes the in-flight guard and submits",
      did_on in poller._stp_vlan_running
      and (poller._run_stp_vlan_walk_job, did_on) in submitted,
      (poller._stp_vlan_running, submitted))
check("...advancing next-walk by a full interval",
      poller._next_stp_vlan_walk[did_on] == now + 900, poller._next_stp_vlan_walk)
check("a due Cisco device with vlan_interval_s=0 also submits, on its "
      "hourly fallback cadence",
      (poller._run_stp_vlan_walk_job, did_off) in submitted, submitted)
check("a due non-Cisco device is checked once due but never submitted",
      did_noncisco not in poller._stp_vlan_running
      and not any(d == did_noncisco for _, d in submitted), submitted)
check("a due device already confirmed not a bridge is never submitted "
      "either -- it can't be a PVST+ one",
      did_not_bridge not in poller._stp_vlan_running
      and not any(d == did_not_bridge for _, d in submitted), submitted)
db.close()

# ------------------------------------ 5.50.0: a stale cache does not merge

stub, port = spawn_stub("stub_agent_l2.py", "pvst")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pvst_stale_cache")
    did = device_against(db, port, "stale-sw", vlan_interval_s=60)
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)   # first sighting: warms the cache
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("sanity: the fresh per-VLAN merge blocks ifIndex 2",
          ifaces[2]["stp_state"] == "blocking", ifaces[2])

    poller._stp_vlan_cache[did]["ts"] = time.time() - 2 * poller._stp_vlan_cadence_s(config) - 1
    poller._poll_stp(did, db.device(did), config)   # no trigger: cache would be reused if fresh
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("a cache older than 2x the cadence is not merged -- the fresh "
          "DEFAULT-context read (forwarding) stands instead of a stale "
          "'blocking' verdict",
          ifaces[2]["stp_state"] == "forwarding", ifaces[2])
    db.close()
finally:
    stub.kill()

# --------------------------------- 5.50.0: an empty answer clears the cache

stub, port = spawn_stub("stub_agent_l2.py", "pvst_no_vtp")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pvst_cache_clear")
    did = device_against(db, port, "clear-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._stp_vlan_cache[did] = {
        "rows": {2: {"blocking": ["20"], "vlans": 1, "states": {"blocking"}}},
        "ts": time.time()}
    rows, answered, complete = poller._run_stp_vlan_pass(device, config)
    check("a complete walk that answers no VLANs returns no rows",
          rows == {} and answered is False and complete is True,
          (rows, answered, complete))
    check("...and clears whatever was cached, rather than leaving it to "
          "override the fresh global read forever",
          did not in poller._stp_vlan_cache, poller._stp_vlan_cache)
    db.close()
finally:
    stub.kill()

# --------------------- 5.50.0: topology trigger reaches a scalarless device

stub, port = spawn_stub("stub_agent_l2.py", "pvst-no-scalars")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pvst_no_scalars_trigger")
    did = device_against(db, port, "no-scalars-topo-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    calls = []
    real_cisco_vlan_stp = poller._cisco_vlan_stp

    def spy(device_arg, config_arg, port_map_arg):
        calls.append(1)
        return real_cisco_vlan_stp(device_arg, config_arg, port_map_arg)
    poller._cisco_vlan_stp = spy

    poller._poll_stp(did, device, config)
    check("the per-VLAN pass runs on first sighting with no default-context "
          "scalars at all",
          len(calls) == 1, calls)

    # This device's dot1dStpProtocolSpec never answers, so the old
    # (unhoisted) topology check never even ran for it. Forcing it open
    # here proves the check itself now reaches a scalarless device -- the
    # exact case the trigger exists for -- rather than proving the stub can
    # move a counter it does not have.
    poller._stp_topology_changed = lambda *a, **k: True
    poller._poll_stp(did, db.device(did), config)
    check("...and a topology-change trigger still reaches it",
          len(calls) == 2, calls)
    db.close()
finally:
    stub.kill()

# --------------------- 5.50.0 review: guard already held, cache still merges
stub, port = spawn_stub("stub_agent_l2.py", "pvst")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pvst_guard_held")
    did = device_against(db, port, "guard-sw")
    two_ports(db, did)
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    calls = []
    real_cisco_vlan_stp = poller._cisco_vlan_stp

    def spy(device_arg, config_arg, port_map_arg):
        calls.append(1)
        return real_cisco_vlan_stp(device_arg, config_arg, port_map_arg)
    poller._cisco_vlan_stp = spy

    # Simulate a cadence walk already in flight on the mac executor: the
    # guard is held and a fresh cache entry already stored, so this poll's
    # own inline trigger (first sighting) must merge the cache rather than
    # race the in-flight walk with a second 48-context walk.
    poller._stp_vlan_running.add(did)
    poller._stp_vlan_cache[did] = {
        "rows": {2: {"blocking": ["20"], "vlans": 2, "states": {"blocking"}}},
        "ts": time.time()}

    poller._poll_stp(did, device, config)

    check("a poll that finds the guard already held does not run a second "
          "per-VLAN walk",
          calls == [], calls)
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("...but still merges the pre-seeded cache onto the interfaces",
          ifaces[2]["stp_blocking_vlans"] == "20"
          and ifaces[2]["stp_vlan_count"] == 2, ifaces[2])
    check("...and does not release a guard it never took",
          did in poller._stp_vlan_running, poller._stp_vlan_running)
    db.close()
finally:
    stub.kill()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
