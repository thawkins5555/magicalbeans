"""poll_now also starts an immediate MAC-table, VLAN and ARP-table walk
(nodepoll.NodePoller.poll_now / _walk_now) -- the scheduled walks'
_maybe_walk_* trio applied without the random stagger and run promptly on a
manual poll, sharing the same in-flight guard and executor."""
from concurrent.futures import ThreadPoolExecutor

from _paths import tmpdir

TMP = tmpdir("poll_now_walks_")

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
    """A poller with a real _mac_executor but never .start()ed -- the base
    poll pool, the scheduler thread and live SNMP are all things this test
    must not touch."""
    poller = NodePoller(db)
    poller._mac_executor = ThreadPoolExecutor(max_workers=2)
    poller._submit = lambda device_id: True   # the base counters/status poll -- not under test here
    return poller


def stub_walks(poller: NodePoller, calls: list) -> None:
    """Stands in for _run_mac_table/_run_vlan_table/_run_arp_table without
    any SNMP, but still clears the in-flight set the real ones clear in
    their own `finally`, so the guard's round trip is exercised too."""
    def make(label, running):
        def run(device_id):
            calls.append((label, device_id))
            running.discard(device_id)
        return run
    poller._run_mac_table = make("mac", poller._mac_running)
    poller._run_vlan_table = make("vlan", poller._vlan_running)
    poller._run_arp_table = make("arp", poller._arp_running)


# --------------------------------------------------- 1. all three, enabled
db = new_db("enabled")
gid = db.ensure_default_group()
db.update_group(gid, mac_table_interval_s=3600, vlan_interval_s=3600,
                arp_table_interval_s=3600)
did = db.add_device("10.0.0.80", name="sw", group_id=gid)
poller = new_poller(db)
calls = []
stub_walks(poller, calls)
poller.poll_now(did, walks=True)
poller._mac_executor.shutdown(wait=True)
check("poll_now submits the MAC, VLAN and ARP walks for the device",
      sorted(calls) == [("arp", did), ("mac", did), ("vlan", did)], calls)
check("...and each walk's in-flight guard is left clear once it ran",
      did not in poller._mac_running and did not in poller._vlan_running
      and did not in poller._arp_running,
      (poller._mac_running, poller._vlan_running, poller._arp_running))
db.close()

# --------------------------------------------------------- 2. all opted out
db = new_db("disabled")
gid = db.ensure_default_group()
did = db.add_device("10.0.0.81", name="sw-off", group_id=gid,
                    mac_table_interval_s=0, vlan_interval_s=0,
                    arp_table_interval_s=0)
poller = new_poller(db)
calls = []
stub_walks(poller, calls)
poller.poll_now(did, walks=True)
poller._mac_executor.shutdown(wait=True)
check("a device with every walk interval explicitly 0 gets none of them",
      calls == [], calls)
db.close()

# ------------------------------------------------- 3. a down device is skipped
db = new_db("down")
gid = db.ensure_default_group()
db.update_group(gid, mac_table_interval_s=3600, vlan_interval_s=3600,
                arp_table_interval_s=3600)
did = db.add_device("10.0.0.82", name="sw-down", group_id=gid)
db.record_poll(did, ping_ok=False, ping_rtt_ms=None, snmp_ok=False,
               snmp_error="timeout", identity=None, uptime_ticks=None,
               status="down", reachable=False)
poller = new_poller(db)
calls = []
stub_walks(poller, calls)
poller.poll_now(did, walks=True)
poller._mac_executor.shutdown(wait=True)
check("a device already marked down/failing is not walked by poll_now",
      calls == [], calls)
db.close()

# ------------------------------------------- 4. an in-flight walk is not doubled
db = new_db("inflight")
gid = db.ensure_default_group()
db.update_group(gid, mac_table_interval_s=3600, vlan_interval_s=3600,
                arp_table_interval_s=3600)
did = db.add_device("10.0.0.83", name="sw-busy", group_id=gid)
poller = new_poller(db)
calls = []
stub_walks(poller, calls)
poller._mac_running.add(did)   # a MAC walk is already running for this device
poller.poll_now(did, walks=True)
poller._mac_executor.shutdown(wait=True)
check("a walk already in flight for this device is not started a second time",
      sorted(calls) == [("arp", did), ("vlan", did)], calls)
db.close()

# ------------------------------------------- 5. default (walks=False) walks none
db = new_db("default")
gid = db.ensure_default_group()
db.update_group(gid, mac_table_interval_s=3600, vlan_interval_s=3600,
                arp_table_interval_s=3600)
did = db.add_device("10.0.0.84", name="sw-default", group_id=gid)
poller = new_poller(db)
calls = []
stub_walks(poller, calls)
poller.poll_now(did)   # walks defaults to False -- the bulk-import/trap/fortipoll callers
poller._mac_executor.shutdown(wait=True)
check("poll_now with no walks argument starts no walks", calls == [], calls)
db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
