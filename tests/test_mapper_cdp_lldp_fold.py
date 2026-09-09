"""One cable, one link — even when a Cisco switch answers BOTH neighbour
tables for it.

The existing protocol-merge pin in test_mapper_links.py cannot catch the real
double: its `row()` helper forces chassis_id_subtype=4 on every row, so both
rows resolve a matched_if_index and fold on the frozenset key. A CDP row never
has that shape. nodepoll's _walk_cdp writes no chassis_id_subtype at all and
puts the cdpCacheDeviceId NAME in chassis_id, so nodesdb's chassis-MAC join
(which requires subtype 4) cannot fire and only the sysName join does — no
matched_if_index, a per-row key, a second link straight on top of the first.

Also covers the other route to the same symptom: a chassis MAC that matches
several interfaces (a stack base MAC, an SVI beside its port-channel) used to
fan one neighbour row out into several links through nodesdb's join.
"""
import os

import _paths  # noqa: F401  (puts the repo root on sys.path)
from _paths import tmpdir

from netpath.mapper import LINK_CSV_HEADER, assemble_links, link_csv_rows
from netpath.nodesdb import NodesDatabase

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


NOW = 1_000_000.0


def lldp_row(device_id, if_index, *, chassis_mac, matched_device_id,
             matched_if_index, port_id="", rem_index="1"):
    """What nodepoll._walk_lldp writes (a MAC chassis id WITH subtype 4),
    matched the way _NEIGHBOR_MATCH_SQL matches it."""
    return _row(device_id, if_index, "lldp", rem_index=rem_index,
                chassis_id=chassis_mac, chassis_id_subtype=4, port_id=port_id,
                sys_name="", matched_device_id=matched_device_id,
                matched_if_index=matched_if_index)


def cdp_row(device_id, if_index, *, device_id_text, matched_device_id,
            port_id="", rem_index="1"):
    """What nodepoll._walk_cdp ACTUALLY writes: no chassis_id_subtype, and
    cdpCacheDeviceId (a name) in both chassis_id and sys_name. Only the
    sysName half of the match can fire, so matched_if_index stays NULL."""
    return _row(device_id, if_index, "cdp", rem_index=rem_index,
                chassis_id=device_id_text, chassis_id_subtype=None,
                port_id=port_id, sys_name=device_id_text,
                matched_device_id=matched_device_id, matched_if_index=None)


def _row(device_id, if_index, protocol, *, rem_index, chassis_id,
         chassis_id_subtype, port_id, sys_name, matched_device_id,
         matched_if_index):
    return {
        "device_id": device_id, "if_index": if_index, "protocol": protocol,
        "rem_index": rem_index, "chassis_id": chassis_id,
        "chassis_id_subtype": chassis_id_subtype, "port_id": port_id,
        "port_id_subtype": None, "port_descr": "", "sys_name": sys_name,
        "sys_descr": "", "platform": "", "remote_address": "",
        "seen_ts": NOW, "first_seen_ts": NOW, "present": 1,
        "matched_device_id": matched_device_id, "matched_device_name": "",
        "matched_if_index": matched_if_index,
    }


def label_of(device_id, if_index):
    return f"dev{device_id}/if{if_index}"


def all_on_map(_id):
    return True


# ------------------------------------------------- the CDP/LLDP double

# Device 1's port 10 faces device 2's port 20. Device 1 walks both tables and
# reports the cable twice; device 2 is not walked at all (only one of the two
# switches needs to answer for the doubling to appear).
PORT_VLANS = {(1, 10): [{"vlan": 10, "tagged": True},
                        {"vlan": 20, "tagged": True},
                        {"vlan": 1, "tagged": False}]}
rows_double = [
    lldp_row(1, 10, chassis_mac="aa:bb:cc:dd:ee:ff", matched_device_id=2,
             matched_if_index=20, port_id="0011.2233.4455", rem_index="0.10.1"),
    cdp_row(1, 10, device_id_text="edge-sw-2", matched_device_id=2,
            port_id="GigabitEthernet0/20", rem_index="10.1"),
]
links, peers = assemble_links(rows_double, port_vlans=PORT_VLANS,
                              port_label=label_of, on_map=all_on_map, now=NOW)
check("one cable seen by CDP and LLDP from the same port draws ONE link",
      len(links) == 1, links)
if len(links) == 1:
    link = links[0]
    check("...carrying BOTH protocols",
          link["protocols"] == ["cdp", "lldp"], link["protocols"])
    check("...with one port label at each end, both resolved",
          (link["a_port"], link["b_port"]) == ("dev1/if10", "dev2/if20"), link)
    check("...and one VLAN set, not two copies of it",
          link["vlans"] == [1, 10, 20], link["vlans"])
    check("...still naming the native VLAN", link["native_vlan"] == 1, link)
check("no phantom peer from the CDP half", peers == [], peers)

# The status bar and the VLAN table both count links; the fold has to make
# them agree that this is one cable on three VLANs, not two cables.
vlan_counts = {}
for one in links:
    for vlan in one["vlans"]:
        vlan_counts[vlan] = vlan_counts.get(vlan, 0) + 1
check("the VLAN table counts the cable once per VLAN",
      vlan_counts == {1: 1, 10: 1, 20: 1}, vlan_counts)
csv_rows = link_csv_rows(links, lambda device_id: f"Device-{device_id}")
check("the CSV export writes the cable as one row", len(csv_rows) == 1, csv_rows)
if csv_rows:
    protocols = csv_rows[0][LINK_CSV_HEADER.index("Protocols")]
    check("...naming both protocols on that row", protocols == "cdp,lldp", protocols)

# The far-end direction: only device 2 walked LLDP, so the MAC-matched link is
# keyed from ITS end, and device 1's CDP row has to find it from the other side.
rows_reverse = [
    cdp_row(1, 10, device_id_text="edge-sw-2", matched_device_id=2,
            port_id="GigabitEthernet0/20", rem_index="10.1"),
    lldp_row(2, 20, chassis_mac="11:22:33:44:55:66", matched_device_id=1,
             matched_if_index=10, port_id="0011.2233.4455", rem_index="0.20.1"),
]
links_rev, _ = assemble_links(rows_reverse, port_vlans={}, port_label=label_of,
                              on_map=all_on_map, now=NOW)
check("the fold works whichever end owns the MAC-matched row",
      len(links_rev) == 1, links_rev)
if len(links_rev) == 1:
    check("...with both protocols there too",
          links_rev[0]["protocols"] == ["cdp", "lldp"], links_rev[0])

# A CDP row naming a DIFFERENT device than the MAC-matched link faces must not
# be folded onto it: same local port, but that is two neighbours on one port
# (a hub, or a stale row), not one cable seen twice.
rows_other_far_end = [
    lldp_row(1, 10, chassis_mac="aa:bb:cc:dd:ee:ff", matched_device_id=2,
             matched_if_index=20, rem_index="0.10.1"),
    cdp_row(1, 10, device_id_text="somewhere-else", matched_device_id=3,
            rem_index="10.1"),
]
links_other, _ = assemble_links(rows_other_far_end, port_vlans={},
                                port_label=label_of, on_map=all_on_map, now=NOW)
check("a name-matched row facing a DIFFERENT device is not folded in",
      len(links_other) == 2, links_other)

# The reciprocal name-only case stays two links, exactly as
# test_mapper_links.py pins it: two rows, two local ports, and nothing saying
# they face each other.
rows_name_only = [
    cdp_row(1, 11, device_id_text="core-sw", matched_device_id=2, rem_index="11.1"),
    cdp_row(2, 21, device_id_text="edge-sw", matched_device_id=1, rem_index="21.1"),
]
links_nm, _ = assemble_links(rows_name_only, port_vlans={}, port_label=label_of,
                             on_map=all_on_map, now=NOW)
check("the reciprocal name-only case still draws two links",
      len(links_nm) == 2, links_nm)


# ------------------------------------------- one chassis MAC, many interfaces

def _fanout_rows():
    """A real nodesdb read: device 2 carries the same chassis MAC on three of
    its own interfaces (the stack base MAC on a member port, the SVI, and the
    port-channel), and device 1 reports one LLDP neighbour with that MAC."""
    tmp = tmpdir("mapper_fanout_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        a = db.add_device("10.0.0.1", "edge-sw-1", group_id=group_id)
        b = db.add_device("10.0.0.2", "edge-sw-2", group_id=group_id)
        mac = "00:11:22:33:44:55"
        db.replace_interfaces(b, [
            {"if_index": index, "descr": descr, "alias": "", "phys_addr": mac,
             "speed_bps": 1e9, "admin_status": "up", "oper_status": "up"}
            for index, descr in ((20, "Gi1/0/20"), (100, "Vlan100"),
                                 (900, "Port-channel1"))])
        db.replace_neighbors(a, [{
            "if_index": 10, "protocol": "lldp", "rem_index": "0.10.1",
            "chassis_id": mac, "chassis_id_subtype": 4, "port_id": "Gi1/0/20",
            "port_id_subtype": 5, "port_descr": "", "sys_name": "edge-sw-2",
            "sys_descr": "", "platform": "", "remote_address": "",
        }])
        return a, b, [dict(row) for row in db.all_neighbours()]
    finally:
        db.close()


device_a, device_b, fanout_rows = _fanout_rows()
check("a chassis MAC on three interfaces still reads back as ONE neighbour row",
      len(fanout_rows) == 1, fanout_rows)
check("...resolving a single matched_if_index",
      len({row["matched_if_index"] for row in fanout_rows}) == 1,
      [row["matched_if_index"] for row in fanout_rows])
check("...belonging to the device the match resolved to",
      all(row["matched_device_id"] == device_b for row in fanout_rows),
      [(row["matched_device_id"], row["matched_if_index"]) for row in fanout_rows])
links_fan, _ = assemble_links(fanout_rows, port_vlans={}, port_label=label_of,
                              on_map=all_on_map, now=NOW)
check("...and drawing ONE link, not one per interface sharing the MAC",
      len(links_fan) == 1, links_fan)


def _disagreeing_rows():
    """The two halves of the match resolving to DIFFERENT devices: the
    neighbour's sysName names one device, its chassis MAC sits on another's
    interface. matched_device_id is the sysName's (COALESCE puts byname
    first), so the MAC device's port index must not ride along with it."""
    tmp = tmpdir("mapper_disagree_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        observer = db.add_device("10.0.0.1", "edge-sw-1", group_id=group_id)
        named = db.add_device("10.0.0.2", "core-sw", group_id=group_id)
        mac_owner = db.add_device("10.0.0.3", "unrelated-sw", group_id=group_id)
        mac = "00:aa:bb:cc:dd:ee"
        db.replace_interfaces(mac_owner, [
            {"if_index": 7, "descr": "Gi1/0/7", "alias": "", "phys_addr": mac,
             "speed_bps": 1e9, "admin_status": "up", "oper_status": "up"}])
        db.replace_neighbors(observer, [{
            "if_index": 10, "protocol": "lldp", "rem_index": "0.10.1",
            "chassis_id": mac, "chassis_id_subtype": 4, "port_id": "Gi1/0/7",
            "port_id_subtype": 5, "port_descr": "", "sys_name": "core-sw",
            "sys_descr": "", "platform": "", "remote_address": "",
        }])
        return named, mac_owner, [dict(row) for row in db.all_neighbours()]
    finally:
        db.close()


named_id, mac_owner_id, disagreeing = _disagreeing_rows()
check("when the sysName and chassis-MAC joins disagree, the sysName's device wins",
      [row["matched_device_id"] for row in disagreeing] == [named_id], disagreeing)
check("...and no other device's port index rides along with it",
      all(row["matched_if_index"] is None for row in disagreeing),
      [(row["matched_device_id"], row["matched_if_index"]) for row in disagreeing])


def main():
    print()
    if FAILS:
        print(f"{len(FAILS)} FAILURE(S): " + "; ".join(FAILS))
        raise SystemExit(1)
    print("all mapper fold checks passed")


main()
