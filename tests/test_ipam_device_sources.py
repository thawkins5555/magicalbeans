"""5.16.0: IPAM folds the stored device tables in. A router's ARP row marks
a host up with its MAC and opens a conflict against a different MAC on
file or in a fresh DHCP lease; a managed device's own address counts as
seen; a learned MAC joined to the ARP map lands the switch port on the
host, skipping uplink ports; and static_in_scope lists addresses in use
inside a DHCP range that no lease or reservation covers.
"""
import os
import sys
import time

import _paths  # noqa: F401

from netpath.ipam_worker import IpamWorker
from netpath.ipamdb import IpamDatabase
from netpath.nodesdb import NodesDatabase

TMPDIR = _paths.tmpdir("ipam_device_sources_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


nodes = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
ipam = IpamDatabase(os.path.join(TMPDIR, "ipam.db"))
worker = IpamWorker(ipam, nodes_db=nodes)
settings = ipam.settings()
now = time.time()

subnet = ipam.add_subnet("10.50.0.0/24", "Plant A")
router = nodes.add_device("10.50.0.1", "core-rtr")
nodes.replace_interfaces(router, [{"if_index": 5, "descr": "Vlan50", "alias": "",
                                   "admin_status": "up", "oper_status": "up"}])
switch = nodes.add_device("10.50.0.2", "access-sw")
nodes.replace_interfaces(switch, [
    {"if_index": 7, "descr": "Gi1/0/7", "alias": "", "admin_status": "up", "oper_status": "up"},
    {"if_index": 24, "descr": "Gi1/0/24", "alias": "uplink", "admin_status": "up", "oper_status": "up"}])

# The sweep saw 10.50.0.20 as one MAC; the router's ARP says another.
ipam.record_host("10.50.0.20", subnet, True, "aa:bb:cc:00:00:20")
nodes.replace_arp_entries(router, [
    {"if_index": 5, "ip": "10.50.0.20", "mac": "aa:bb:cc:00:00:99"},
    {"if_index": 5, "ip": "10.50.0.30", "mac": "aa:bb:cc:00:00:30"},
    {"if_index": 5, "ip": "10.60.0.9", "mac": "aa:bb:cc:00:00:60"},   # outside every subnet
])
# The learned MAC of .30 sits on Gi1/0/7 and on the uplink Gi1/0/24.
nodes.replace_mac_entries(switch, [
    {"if_index": 7, "mac": "aa:bb:cc:00:00:30", "vlan": "50"},
    {"if_index": 24, "mac": "aa:bb:cc:00:00:30", "vlan": "50"},
])
nodes.replace_neighbors(switch, [
    {"if_index": 24, "protocol": "lldp", "rem_index": "1", "sys_name": "core-rtr"}])
nodes.record_device_addresses(router, ["10.50.0.1"], "ipAddrTable")

# A fresh DHCP lease for .30 that names a third MAC.
server = ipam.add_dhcp_server("dhcp.example.net", "DHCP")
ipam.replace_dhcp_scopes(server, [{"scope_id": "10.50.0.0", "name": "Plant A", "start_ip": "10.50.0.10",
                                   "end_ip": "10.50.0.200", "mask": "255.255.255.0", "state": "Active",
                                   "lease_duration_s": 86400, "description": "", "router": "10.50.0.1"}])
ipam.replace_dhcp_leases(server, [{"scope_id": "10.50.0.0", "ip": "10.50.0.30", "mac": "aa:bb:cc:00:00:31",
                                   "hostname": "pc30", "address_state": "Active",
                                   "lease_expires_ts": now + 3600, "is_reservation": False, "description": ""}])

import sqlite3
conn = sqlite3.connect(nodes.path)
conn.execute("UPDATE devices SET status = 'up', last_poll_ts = ? WHERE id = ?", (now, router))
conn.commit(); conn.close()

opened = worker._ingest_device_tables(settings)
check("the ingest opened two conflicts (ARP vs file, ARP vs lease)", opened == 2, opened)
conflicts = {(c["ip"], c["source"]): c for c in ipam.conflicts()}
check("a router ARP MAC that differs from the sweep's MAC is a device_arp conflict",
      ("10.50.0.20", "device_arp") in conflicts, sorted(conflicts))
check("...naming the router and interface that saw it",
      "core-rtr Vlan50" in (conflicts.get(("10.50.0.20", "device_arp")) or {"detail": ""})["detail"],
      dict(conflicts.get(("10.50.0.20", "device_arp")) or {}))
check("a router ARP MAC that differs from a fresh lease is a device_arp_dhcp conflict",
      ("10.50.0.30", "device_arp_dhcp") in conflicts, sorted(conflicts))

host30 = ipam.host("10.50.0.30")
check("an address only the router's ARP table knew is now a host, up, with its MAC and source",
      host30 is not None and host30["alive"] == 1 and host30["mac"] == "aa:bb:cc:00:00:30"
      and host30["seen_source"] == "device_arp" and host30["seen_detail"] == "core-rtr Vlan50",
      dict(host30) if host30 else None)
check("...carrying the access port its MAC was learned on, not the uplink",
      host30["switch_device_id"] == switch and host30["switch_if_index"] == 7
      and host30["switch_port"] == "Gi1/0/7", dict(host30))
check("an address outside every configured subnet is not recorded",
      ipam.host("10.60.0.9") is None)
host1 = ipam.host("10.50.0.1")
check("the router's own address counts as seen, with the device named",
      host1 is not None and host1["seen_source"] == "device_address"
      and host1["seen_detail"] == "core-rtr" and host1["alive"] == 1, dict(host1) if host1 else None)

again = worker._ingest_device_tables(settings)
check("a second ingest with nothing new opens nothing", again == 0 and len(ipam.conflicts()) == 2,
      (again, len(ipam.conflicts())))

# ---------------------------------------------------------- static in scope
static = ipam.static_in_scope(3600)
listed = {h["ip"] for h in static.get((server, "10.50.0.0"), [])}
check("an address in use inside the scope with no lease is listed as static",
      "10.50.0.20" in listed, listed)
check("...a leased address is not", "10.50.0.30" not in listed, listed)
check("...and the router's address below the range start is not", "10.50.0.1" not in listed, listed)
ipam.replace_dhcp_leases(server, [
    {"scope_id": "10.50.0.0", "ip": "10.50.0.20", "mac": "aa:bb:cc:00:00:20", "hostname": "printer",
     "address_state": "Active", "lease_expires_ts": None, "is_reservation": True, "description": ""}])
check("a reservation takes the address off the static list",
      "10.50.0.20" not in {h["ip"] for h in ipam.static_in_scope(3600).get((server, "10.50.0.0"), [])})

nodes.close()
ipam.close()
print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")
