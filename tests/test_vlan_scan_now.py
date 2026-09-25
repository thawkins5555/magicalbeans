"""walk_vlans_now (nodepoll.NodePoller) -- the fleet-wide "VLAN scan" button's
poller side. Same in-flight guard and executor as poll_now's per-device walks
(test_poll_now_walks.py), extracted into _queue_walk and exercised here with
one queued device, one interval-off device, one down device, one already
in-flight and one disabled device.
"""
from concurrent.futures import ThreadPoolExecutor

from _paths import tmpdir

TMP = tmpdir("vlan_scan_now_")

from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def new_poller(db: NodesDatabase) -> NodePoller:
    """A poller with a real _mac_executor but never .start()ed."""
    poller = NodePoller(db)
    poller._mac_executor = ThreadPoolExecutor(max_workers=2)
    poller._submit = lambda device_id: True
    return poller


def stub_walks(poller: NodePoller, calls: list) -> None:
    def make(label, running):
        def run(device_id):
            calls.append((label, device_id))
            running.discard(device_id)
        return run
    poller._run_mac_table = make("mac", poller._mac_running)
    poller._run_lldp_table = make("lldp", poller._lldp_running)
    poller._run_vlan_table = make("vlan", poller._vlan_running)
    poller._run_arp_table = make("arp", poller._arp_running)
    poller._run_stp_vlan_walk_job = make("stp_vlan", poller._stp_vlan_running)


def stub_vlan_pending(poller: NodePoller, calls: list) -> None:
    """A _run_vlan_table stand-in that records the call but does not clear
    _vlan_running, so a device stays "in flight" across two walk_vlans_now
    calls the way a real walk would while it is still running."""
    def run(device_id):
        calls.append(device_id)
    poller._run_vlan_table = run


# --------------------------------------------------------------- fixture
db = new_db("fleet")
gid_on = db.ensure_default_group()
db.update_group(gid_on, vlan_interval_s=3600)
gid_off = db.add_group("off-group", vlan_interval_s=0)

normal = db.add_device("10.1.0.1", name="normal", group_id=gid_on)
interval_off = db.add_device("10.1.0.2", name="interval-off", group_id=gid_off)
down = db.add_device("10.1.0.3", name="down", group_id=gid_on)
db.record_poll(down, ping_ok=False, ping_rtt_ms=None, snmp_ok=False,
               snmp_error="timeout", identity=None, uptime_ticks=None,
               status="down", reachable=False)
already = db.add_device("10.1.0.4", name="already-running", group_id=gid_on)
disabled = db.add_device("10.1.0.5", name="disabled", group_id=gid_on)
db.update_device(disabled, enabled=0)

poller = new_poller(db)
calls = []
stub_vlan_pending(poller, calls)
poller._vlan_running.add(already)

before = __import__("time").time()
result = poller.walk_vlans_now()
after = __import__("time").time()

check("one normal device is queued", result["queued"] == 1, result)
check("the interval-off and down devices are skipped",
      result["skipped"] == 2, result)
check("the already-running device is reported as already_running",
      result["already_running"] == 1, result)
check("running is reported true with a live executor", result["running"] is True, result)
check("the stub vlan walk was called for the normal device only",
      calls == [normal], calls)
check("_next_vlan_walk was stamped about now + 3600s for the normal device",
      normal in poller._next_vlan_walk
      and before + 3600 - 1 <= poller._next_vlan_walk[normal] <= after + 3600 + 1,
      poller._next_vlan_walk.get(normal))
check("the disabled device appears in no count",
      result["queued"] + result["already_running"] + result["skipped"] == 4,
      result)

# ------------------------------------------------- a second click right after
calls.clear()
result2 = poller.walk_vlans_now()
check("a second call queues nothing new (the normal device is still in flight)",
      result2["queued"] == 0, result2)
check("...and both the normal and already-running devices now read already_running",
      result2["already_running"] == 2, result2)
check("...and the still-skipped devices are unchanged",
      result2["skipped"] == 2, result2)
check("the vlan walk stub was not called again", calls == [], calls)

# ------------------------------------------------------- poller stopped
poller._mac_executor = None
result3 = poller.walk_vlans_now()
check("a stopped poller (_mac_executor is None) returns all zeros and running False",
      result3 == {"running": False, "queued": 0, "already_running": 0, "skipped": 0},
      result3)
db.close()

# ---------------------------------------- _walk_now still queues all five
db = new_db("walk_now_still_all_five")
gid = db.ensure_default_group()
db.update_group(gid, mac_table_interval_s=3600, lldp_interval_s=3600,
                vlan_interval_s=3600, arp_table_interval_s=3600)
did = db.add_device("10.1.0.9", name="sw", group_id=gid)
poller = new_poller(db)
calls = []
stub_walks(poller, calls)
poller.poll_now(did, walks=True)
poller._mac_executor.shutdown(wait=True)
check("_walk_now still queues mac, lldp, vlan, arp and stp_vlan for a normal "
      "device after the _queue_walk extraction",
      sorted(calls) == [("arp", did), ("lldp", did), ("mac", did),
                        ("stp_vlan", did), ("vlan", did)],
      calls)
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
