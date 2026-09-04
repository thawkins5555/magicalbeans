"""LLDP/CDP neighbour walk (Tier 1 #5): the live walk against stub_agent_l2,
CDP as a fallback/supplement on Cisco, present-flag ageing (mirroring
mac_entries), the best-effort device-match join, and lldp_interval_s
scheduling/inheritance (0 = off, mirroring mac_table_interval_s)."""
import os
import sqlite3
import time

from _paths import spawn_stub, tmpdir

TMP = tmpdir("lldp_topology_")

import netpath.nodepoll as nodepoll_mod
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.web import Service

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> NodesDatabase:
    return NodesDatabase(f"{TMP}/{name}.db")


def device_against(db: NodesDatabase, port: int, *, vendor: str = "",
                   name: str = "sw") -> int:
    gid = db.ensure_default_group()
    db.update_group(gid, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    did = db.add_device("127.0.0.1", name=name, group_id=gid)
    db.seed_identity(did, sys_descr="", sys_name=name,
                     sys_object_id="1.3.6.1.4.1.9.1.1208", vendor=vendor)
    return did


# ------------------------------------------------------- 1. plain LLDP walk
stub, port = spawn_stub("stub_agent_l2.py", "lldp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("lldp")
    did = device_against(db, port, vendor="", name="lldp-sw")
    poller = NodePoller(db)
    entries = poller.read_device_neighbors(did)
    check("a plain LLDP walk returns the one neighbour",
          entries is not None and len(entries) == 1, entries)
    if entries:
        row = entries[0]
        check("...on local port 1 (lldpRemLocalPortNum used as ifIndex)",
              row["if_index"] == 1, row)
        check("...with the chassis id decoded as a MAC (subtype 4)",
              row["chassis_id"] == "aa:bb:cc:dd:ee:ff" and row["chassis_id_subtype"] == 4,
              row)
        check("...and sysName/portId carried through",
              row["sys_name"] == "core-sw-1" and row["port_id"] == "Gi0/24", row)
        check("...tagged protocol 'lldp'", row["protocol"] == "lldp", row)
    check("a non-Cisco device never attempts CDP (one protocol only)",
          entries is not None and all(e["protocol"] == "lldp" for e in entries), entries)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------- 2. CDP-only fallback
stub, port = spawn_stub("stub_agent_l2.py", "cdp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("cdp")
    did = device_against(db, port, vendor="cisco", name="cdp-sw")
    poller = NodePoller(db)
    entries = poller.read_device_neighbors(did)
    check("a Cisco device with no LLDP table falls back to CDP",
          entries is not None and len(entries) == 1 and entries[0]["protocol"] == "cdp",
          entries)
    if entries:
        row = entries[0]
        check("...on ifIndex 3 (cdpCacheIfIndex is the ifIndex directly)",
              row["if_index"] == 3, row)
        check("...with device id/platform/port carried through",
              row["chassis_id"] == "access-sw-9"
              and row["platform"] == "cisco WS-C2960X"
              and row["port_id"] == "GigabitEthernet0/1", row)
        check("...and the address decoded from hex bytes to dotted-decimal",
              row["remote_address"] == "10.0.0.9", row)
    db.close()
finally:
    stub.kill()

# ---------------------------------------------- 3. CDP supplements LLDP
stub, port = spawn_stub("stub_agent_l2.py", "lldp_and_cdp")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("both")
    did = device_against(db, port, vendor="cisco", name="both-sw")
    poller = NodePoller(db)
    entries = poller.read_device_neighbors(did)
    protocols = sorted(e["protocol"] for e in entries) if entries else []
    check("a Cisco device answering both tables keeps BOTH rows",
          protocols == ["cdp", "lldp"], entries)
    db.close()
finally:
    stub.kill()

# ------------------------------------------- 4. neither table -> None
stub, port = spawn_stub("stub_agent_l2.py", "no_l2")
nodepoll_mod.DEFAULT_SNMP_PORT = port
try:
    db = new_db("none")
    did = device_against(db, port, vendor="cisco", name="none-sw")
    poller = NodePoller(db)
    entries = poller.read_device_neighbors(did)
    check("a device answering neither table returns None, not []",
          entries is None, entries)
    db.close()
finally:
    stub.kill()

# ------------------------------------------------ 5. present-flag ageing
db = new_db("ageing")
did = db.add_device("10.0.0.50", name="age-sw", group_id=db.ensure_default_group())
walk1_ts = time.time() - 3700.0
db.replace_neighbors(did, [
    {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
     "chassis_id": "aa:bb:cc:dd:ee:ff", "chassis_id_subtype": 4,
     "sys_name": "core-sw-1", "port_id": "Gi0/24"},
    {"if_index": 2, "protocol": "lldp", "rem_index": "0.2.1",
     "chassis_id": "11:22:33:44:55:66", "chassis_id_subtype": 4,
     "sys_name": "ap-lobby", "port_id": "eth0"},
], now=walk1_ts)
first_pass = {(r["if_index"], r["protocol"], r["rem_index"]): dict(r)
             for r in db.neighbours_of(did)}
check("first walk stores both neighbours, all present",
      len(first_pass) == 2 and all(r["present"] for r in first_pass.values()),
      first_pass)

walk2_ts = walk1_ts + 60.0
# The second walk only still sees the core switch — the AP dropped off.
db.replace_neighbors(did, [
    {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
     "chassis_id": "aa:bb:cc:dd:ee:ff", "chassis_id_subtype": 4,
     "sys_name": "core-sw-1", "port_id": "Gi0/24"},
], now=walk2_ts)
rows = {(r["if_index"], r["protocol"], r["rem_index"]): dict(r)
       for r in db.neighbours_of(did)}
check("the row count is unchanged — nothing deleted, just marked",
      len(rows) == len(first_pass), (len(rows), len(first_pass)))
vanished_key = (2, "lldp", "0.2.1")
still_key = (1, "lldp", "0.1.1")
check("the vanished neighbour is present=0 with its old seen_ts kept",
      not rows[vanished_key]["present"]
      and rows[vanished_key]["seen_ts"] == first_pass[vanished_key]["seen_ts"], rows)
check("the still-seen neighbour got a fresh seen_ts and stays present",
      rows[still_key]["present"] and rows[still_key]["seen_ts"] == walk2_ts, rows)

removed = db.prune_neighbors(60.0)   # both rows are well past a 1-minute window
check("prune_neighbors drops rows past the retention window",
      removed == len(rows), (removed, len(rows)))
db.close()

# ------------------------------------------------ 6. best-effort device match
db = new_db("match")
gid = db.ensure_default_group()
known_id = db.add_device("10.0.0.60", name="core-sw-1", group_id=gid)
db.replace_interfaces(known_id, [
    {"if_index": 1, "descr": "Gi0/1", "phys_addr": "aa:bb:cc:dd:ee:ff"}])
observer_id = db.add_device("10.0.0.61", name="observer", group_id=gid)
db.replace_neighbors(observer_id, [
    {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
     "chassis_id": "aa:bb:cc:dd:ee:ff", "chassis_id_subtype": 4,
     "sys_name": "core-sw-1", "port_id": "Gi0/24"},
])
rows = db.neighbours_of(observer_id)
check("a MAC-address chassis id joins to the interface's phys_addr",
      len(rows) == 1 and rows[0]["matched_device_id"] == known_id,
      [dict(r) for r in rows])
fleet = db.all_neighbours()
check("all_neighbours() carries the same join, fleet-wide",
      len(fleet) == 1 and fleet[0]["matched_device_id"] == known_id,
      [dict(r) for r in fleet])
db.close()

# --------------------------------------------- 7. scheduling / inheritance
db = new_db("schedule")
gid = db.ensure_default_group()
db.update_group(gid, lldp_interval_s=0)     # shipped default overridden off
did_off = db.add_device("10.0.0.70", name="off-sw", group_id=gid)
did_on = db.add_device("10.0.0.71", name="on-sw", group_id=gid, lldp_interval_s=900)
poller = NodePoller(db)
device_off = db.device(did_off)
config_off = db.effective_config(device_off)
check("a group set to 0 disables LLDP scheduling (inherited)",
      config_off.get("lldp_interval_s") == 0, config_off)
poller._maybe_walk_lldp(device_off, config_off, time.time())
check("...and _maybe_walk_lldp never schedules a due time for it",
      did_off not in poller._next_lldp_walk, poller._next_lldp_walk)

device_on = db.device(did_on)
config_on = db.effective_config(device_on)
check("a device override beats the group's 0",
      config_on.get("lldp_interval_s") == 900, config_on)
now = time.time()
poller._maybe_walk_lldp(device_on, config_on, now)
check("...and _maybe_walk_lldp schedules a first walk within one interval",
      did_on in poller._next_lldp_walk
      and now <= poller._next_lldp_walk[did_on] <= now + 900,
      poller._next_lldp_walk)

db2 = new_db("default_interval")
did_default = db2.add_device("10.0.0.72", name="default-sw",
                             group_id=db2.ensure_default_group())
config_default = db2.effective_config(db2.device(did_default))
check("the shipped default is 3600s, mirroring mac_table_interval_s",
      config_default.get("lldp_interval_s") == 3600, config_default)
db2.close()
db.close()

# ---------------------------- 8. prune_neighbors is wired into maintenance
# prune_neighbors has existed since the neighbours table shipped (the
# schema comment has promised it all along — "the same shape
# prune_mac_entries already has") but was never actually called from
# anywhere: a device dropped from the walk schedule kept its neighbour
# rows, present=1 forever, and the table only ever grew. This drives a
# real Service.run_maintenance(force=True), the same maintenance sweep
# that prunes mac_entries, rather than calling nodes_db.prune_neighbors
# directly — that already passes (see section 5 above) and would not have
# caught a missing wire-up.
DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
           "alerts", "wireless", "configrx")
svc_dir = os.path.join(TMP, "maintenance_svc")
os.makedirs(svc_dir, exist_ok=True)
service = Service(*[os.path.join(svc_dir, name + ".db") for name in DB_NAMES])
try:
    gid = service.nodes_db.ensure_default_group()
    stale_dev = service.nodes_db.add_device("10.0.0.80", name="stale-sw", group_id=gid)
    fresh_dev = service.nodes_db.add_device("10.0.0.81", name="fresh-sw", group_id=gid)
    service.nodes_db.replace_neighbors(stale_dev, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "aa:bb:cc:00:00:01", "chassis_id_subtype": 4,
         "sys_name": "old-neighbour", "port_id": "Gi0/1"},
    ])
    service.nodes_db.replace_neighbors(fresh_dev, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.2.1",
         "chassis_id": "aa:bb:cc:00:00:02", "chassis_id_subtype": 4,
         "sys_name": "current-neighbour", "port_id": "Gi0/2"},
    ])
    retention_days = float(service.nodes_settings.get("mac_table_retention_days", 7))
    # Back-date the stale device's row well past the retention window —
    # what "this device stopped being walked" looks like on disk, mirroring
    # test_mac_tables.py's own way of aging a row for prune_mac_entries.
    conn = sqlite3.connect(service.nodes_db.path)
    conn.execute("UPDATE neighbors SET seen_ts = ? WHERE device_id = ?",
                (time.time() - (retention_days + 1) * 86400, stale_dev))
    conn.commit()
    conn.close()

    service.run_maintenance(force=True)

    remaining = {r["device_id"] for r in service.nodes_db.all_neighbours()}
    check("run_maintenance prunes a stale device's neighbour rows",
          stale_dev not in remaining, remaining)
    check("...and leaves a freshly-seen device's neighbour rows alone",
          fresh_dev in remaining, remaining)
finally:
    service.shutdown()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
