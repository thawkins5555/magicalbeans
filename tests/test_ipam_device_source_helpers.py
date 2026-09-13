"""Storage helpers for Part B: arp_entries_present, mac_entries_present,
device_addresses_all, neighbor_ports from nodesdb; hosts columns and
subnet_for_ip from ipamdb.
"""
import sys
import time

import _paths  # noqa: F401

from netpath.nodesdb import NodesDatabase
from netpath.ipamdb import IpamDatabase

TMPDIR = _paths.tmpdir("ipam_device_source_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


nodes_db = NodesDatabase(f"{TMPDIR}/nodes.db")
ipam_db = IpamDatabase(f"{TMPDIR}/ipam.db")

now = time.time()

dev1 = nodes_db.add_device("10.0.0.1", "sw-01")
dev2 = nodes_db.add_device("10.0.0.2", "sw-02")

nodes_db.replace_arp_entries(dev1, [
    {"if_index": 1, "ip": "10.1.1.1", "mac": "aa:bb:cc:dd:ee:01"}
])
nodes_db.replace_arp_entries(dev2, [
    {"if_index": 1, "ip": "10.1.1.2", "mac": "aa:bb:cc:dd:ee:02"}
])

nodes_db.replace_mac_entries(dev1, [
    {"if_index": 1, "mac": "aa:bb:cc:dd:ee:03", "vlan": "10"}
])

nodes_db.record_device_addresses(dev1, ["10.0.0.100"], "snmp")

nodes_db.replace_neighbors(dev1, [
    {"if_index": 1, "protocol": "lldp", "rem_index": "1", "sys_name": "sw-02"}
])

arp_present = nodes_db.arp_entries_present(since_ts=0)
check("arp_entries_present returns rows", len(arp_present) > 0, f"got {len(arp_present)}")
check("arp_entries_present has device fields",
      len(arp_present) > 0 and arp_present[0]["device_name"] is not None,
      arp_present[0] if arp_present else None)

mac_present = nodes_db.mac_entries_present(since_ts=0)
check("mac_entries_present returns rows", len(mac_present) > 0, f"got {len(mac_present)}")
check("mac_entries_present has device fields",
      len(mac_present) > 0 and mac_present[0]["device_name"] is not None,
      mac_present[0] if mac_present else None)

dev_addr_rows = nodes_db.device_addresses(dev1)
check("device_addresses returns rows for device", len(dev_addr_rows) > 0, f"got {len(dev_addr_rows)}")
addrs_all = nodes_db.device_addresses_all()
check("device_addresses_all returns rows", len(addrs_all) > 0, f"got {len(addrs_all)}")
check("device_addresses_all has device fields",
      len(addrs_all) > 0 and addrs_all[0]["device_name"] is not None,
      addrs_all[0] if addrs_all else None)

neighbor_result = nodes_db.neighbor_ports()
check("neighbor_ports returns rows", len(neighbor_result) > 0, f"got {len(neighbor_result)}")
check("neighbor_ports has device_id and if_index",
      len(neighbor_result) > 0 and "device_id" in neighbor_result[0].keys()
      and "if_index" in neighbor_result[0].keys(),
      list(neighbor_result[0].keys()) if neighbor_result else None)

ipam_db.add_subnet("10.1.0.0/24", "test-subnet-1")
ipam_db.add_subnet("10.2.0.0/24", "test-subnet-2")

inside_result = ipam_db.subnet_for_ip("10.1.0.5")
check("subnet_for_ip finds address inside subnet", inside_result is not None,
      inside_result)

outside_result = ipam_db.subnet_for_ip("10.3.0.1")
check("subnet_for_ip returns None for address outside all subnets",
      outside_result is None, outside_result)

disabled_db = IpamDatabase(f"{TMPDIR}/ipam2.db")
disabled_subnet_id = disabled_db.add_subnet("10.4.0.0/24", "disabled-subnet")
disabled_db.update_subnet(disabled_subnet_id, enabled=0)
disabled_result = disabled_db.subnet_for_ip("10.4.0.1")
check("subnet_for_ip skips disabled subnets", disabled_result is None,
      disabled_result)

hosts_cols = disabled_db._conn.execute(
    "PRAGMA table_info(hosts)").fetchall()
col_names = [col["name"] for col in hosts_cols]
check("hosts has seen_source column", "seen_source" in col_names, col_names)
check("hosts has seen_detail column", "seen_detail" in col_names, col_names)
check("hosts has switch_device_id column", "switch_device_id" in col_names, col_names)
check("hosts has switch_if_index column", "switch_if_index" in col_names, col_names)
check("hosts has switch_port column", "switch_port" in col_names, col_names)
check("hosts has switch_seen_ts column", "switch_seen_ts" in col_names, col_names)

nodes_db.close()
ipam_db.close()
disabled_db.close()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")
