"""Bundle members inherit the Port-channel's STP state (5.60.0):
nodepoll._cached_agg_map (IF-MIB ifStackStatus, with a CISCO-PAGP-MIB
pagpGroupIfIndex fallback), the merge in _poll_stp that copies a Port-
channel's row onto a member the switch never answers for directly, the
event suppression on a member's own row (the Port-channel's row raises the
one alert), and _bridge_port_map's bridge-port-equals-ifIndex fallback when
dot1dBasePortIfIndex answers nothing at all."""
import _paths
from _paths import spawn_stub, tmpdir

TMP = tmpdir("stp_bundle_")

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


def device_against(db: NodesDatabase, port: int, name: str, **overrides) -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    return db.add_device("127.0.0.1", name=name, group_id=gid, **overrides)


def mark_cisco(db: NodesDatabase, did: int) -> None:
    """Writes vendor_detected without a real identify walk -- test_stp_vlan.py's
    own mark_cisco idiom."""
    db.record_poll(did, ping_ok=None, ping_rtt_ms=None, snmp_ok=True,
                   snmp_error="", identity={"vendor_detected": "cisco"},
                   uptime_ticks=None, status="up", reachable=True)


class CapturingLog:
    """Enough of eventlog to check what _log_media_diag says -- the same
    shape test_arp_tables.py's own CapturingLog uses."""

    def __init__(self):
        self.lines = []

    def add(self, category, message, target="", detail=""):
        self.lines.append((category, message))


def blocking_events(db: NodesDatabase, did: int) -> list:
    return [dict(row) for row in db.interface_events_for_device(did)
           if row["kind"] == "stp_blocking"]


def unblocked_events(db: NodesDatabase, did: int) -> list:
    return [dict(row) for row in db.interface_events_for_device(did)
           if row["kind"] == "stp_unblocked"]


# ------------------------------------------- ifStackStatus: Po1 over 10, 11

stub, port = spawn_stub("stub_agent_l2.py", "stp-bundle")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("stack")
    did = device_against(db, port, "bundle-sw")
    db.replace_interfaces(did, [
        {"if_index": 10, "descr": "Gi1/0/1"}, {"if_index": 11, "descr": "Gi1/0/2"},
        {"if_index": 5000, "descr": "Po1"}])
    mark_cisco(db, did)
    # A forwarding baseline on all three, so the poll below is a real
    # transition an interface event can be raised from.
    db.update_interface_stp(did, [{"if_index": 10, "stp_state": "forwarding"},
                                  {"if_index": 11, "stp_state": "forwarding"},
                                  {"if_index": 5000, "stp_state": "forwarding"}])
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("member 10 (not a bridge port of its own) inherits the Po's "
          "blocking state",
          ifaces[10]["stp_state"] == "blocking", ifaces[10])
    check("...naming the Port-channel as the via ifIndex",
          ifaces[10]["stp_via_if_index"] == 5000, ifaces[10])
    check("member 11 does too",
          ifaces[11]["stp_state"] == "blocking"
          and ifaces[11]["stp_via_if_index"] == 5000, ifaces[11])
    check("the Port-channel's own row reads blocking with no via",
          ifaces[5000]["stp_state"] == "blocking"
          and ifaces[5000]["stp_via_if_index"] is None, ifaces[5000])

    events = blocking_events(db, did)
    check("exactly one stp_blocking event is raised, on the Port-channel's "
          "own row -- a member's inherited row raises none",
          len(events) == 1 and events[0]["if_index"] == 5000, events)

    # ---- second poll: member 11 leaves the stack table
    stub_stat(port, b"DROP_STACK_MEMBER 11")
    poller._agg_map_cache.pop(did, None)   # force a fresh stack-table walk
    poller._poll_stp(did, db.device(did), config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("member 11's via is cleared once it leaves the stack table",
          ifaces[11]["stp_via_if_index"] is None, ifaces[11])
    check("...and, since the switch answers no state for it directly, its "
          "inherited stp_state is cleared to NULL, not flapped or left "
          "as stale blocking",
          ifaces[11]["stp_state"] is None
          and ifaces[11]["stp_blocking_vlans"] is None
          and ifaces[11]["stp_vlan_count"] is None, ifaces[11])
    check("member 10, still in the stack table, is unaffected",
          ifaces[10]["stp_via_if_index"] == 5000
          and ifaces[10]["stp_state"] == "blocking", ifaces[10])
    check("no new stp_blocking or stp_unblocked event was raised for "
          "member 11 leaving -- a via clear is not a state transition",
          len(blocking_events(db, did)) == 1
          and len(unblocked_events(db, did)) == 0,
          (blocking_events(db, did), unblocked_events(db, did)))
    db.close()
finally:
    stub.kill()

# ------------------------------- ifStackStatus times out: via/state held

stub, port = spawn_stub("stub_agent_l2.py", "stp-bundle")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("stack_timeout")
    did = device_against(db, port, "bundle-timeout-sw")
    db.replace_interfaces(did, [
        {"if_index": 10, "descr": "Gi1/0/1"}, {"if_index": 11, "descr": "Gi1/0/2"},
        {"if_index": 5000, "descr": "Po1"}])
    mark_cisco(db, did)
    db.update_interface_stp(did, [{"if_index": 10, "stp_state": "forwarding"},
                                  {"if_index": 11, "stp_state": "forwarding"},
                                  {"if_index": 5000, "stp_state": "forwarding"}])
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)   # baseline: members inherit via 5000

    stub_stat(port, f"DROP_OID {nodeoids.IF_STACK_STATUS}".encode())
    poller._agg_map_cache.pop(did, None)   # force a fresh, now-timing-out walk
    poller._poll_stp(did, db.device(did), config)

    check("a timed-out ifStackStatus walk is not cached as \"no bundle\"",
          did not in poller._agg_map_cache, poller._agg_map_cache.get(did))
    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("member 10 keeps its inherited via and blocking state through a "
          "poll where the bundle table timed out",
          ifaces[10]["stp_via_if_index"] == 5000
          and ifaces[10]["stp_state"] == "blocking", ifaces[10])
    check("member 11 does too",
          ifaces[11]["stp_via_if_index"] == 5000
          and ifaces[11]["stp_state"] == "blocking", ifaces[11])
    check("no stp_unblocked event was raised for either member -- an "
          "unknown bundle table is not evidence they left it",
          len(unblocked_events(db, did)) == 0, unblocked_events(db, did))

    stub_stat(port, b"CLEAR_DROPS")
    poller._agg_map_cache.pop(did, None)
    poller._poll_stp(did, db.device(did), config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("once ifStackStatus answers again, the next poll behaves "
          "normally",
          ifaces[10]["stp_via_if_index"] == 5000
          and ifaces[10]["stp_state"] == "blocking"
          and ifaces[11]["stp_via_if_index"] == 5000
          and ifaces[11]["stp_state"] == "blocking", ifaces)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------------------- PAgP fallback

stub, port = spawn_stub("stub_agent_l2.py", "stp-pagp")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("pagp")
    did = device_against(db, port, "pagp-sw")
    db.replace_interfaces(did, [
        {"if_index": 10, "descr": "Gi1/0/1"}, {"if_index": 5000, "descr": "Po1"}])
    mark_cisco(db, did)
    poller = NodePoller(db)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("with no ifStackStatus at all, a Cisco device's own "
          "pagpGroupIfIndex gives the same result",
          ifaces[10]["stp_state"] == "blocking"
          and ifaces[10]["stp_via_if_index"] == 5000, ifaces[10])
    db.close()
finally:
    stub.kill()

# ------------------------------------------------------ bridge-port fallback

stub, port = spawn_stub("stub_agent_l2.py", "stp-bridge-fallback")
_paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
try:
    db = new_db("bridge_fallback")
    did = device_against(db, port, "fallback-sw")
    db.replace_interfaces(did, [{"if_index": 10, "descr": "Gi1/0/1"}])
    log = CapturingLog()
    poller = NodePoller(db, log=log)
    device = db.device(did)
    config = db.effective_config(device)

    poller._poll_stp(did, device, config)

    ifaces = {i["if_index"]: dict(i) for i in db.interfaces(did)}
    check("an empty dot1dBasePortIfIndex falls back to bridge port = "
          "ifIndex, confirmed against the device's own interface table",
          ifaces[10]["stp_state"] == "blocking", ifaces[10])
    said = [m for _, m in log.lines if "assuming bridge port = ifIndex" in m]
    check("...and logs it once via _log_media_diag",
          len(said) == 1, log.lines)
    db.close()
finally:
    stub.kill()

# -------------------------- 5.62.0: a Port-channel outside VLAN 1 inherits

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
    check("the Port-channel's bridge port answers only inside @20 (never "
          "the DEFAULT context), and still reads blocking",
          ifaces[5000]["stp_state"] == "blocking", ifaces[5000])
    check("member 10 inherits it anyway -- _cached_agg_map recognises "
          "ifIndex 5000 through the per-VLAN cache's own port union, not "
          "just the (here empty) DEFAULT-context bridge port map",
          ifaces[10]["stp_state"] == "blocking"
          and ifaces[10]["stp_via_if_index"] == 5000, ifaces[10])
    check("member 11 does too",
          ifaces[11]["stp_state"] == "blocking"
          and ifaces[11]["stp_via_if_index"] == 5000, ifaces[11])
    db.close()
finally:
    stub.kill()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
