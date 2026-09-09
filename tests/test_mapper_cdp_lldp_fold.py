"""One cable, one link — even when a Cisco switch answers BOTH neighbour
tables for it.

The existing protocol-merge pin in test_mapper_links.py cannot catch the real
double: its `row()` helper forces chassis_id_subtype=4 on every row, so both
rows resolve a matched_if_index and fold on the frozenset key. A CDP row never
has that shape. nodepoll's _walk_cdp writes no chassis_id_subtype at all and
puts the cdpCacheDeviceId NAME in chassis_id, so nodesdb's chassis-MAC join
(which requires subtype 4) cannot fire and only the sysName join does — no
matched_if_index, a per-row key, a second link straight on top of the first.

The same doubling from the other direction: two switches speaking only CDP
to each other put a name-only row on EACH side and no MAC-matched link on
either, so nothing in the first fold can pair them. Where they are the only
two rows between that pair of devices the pairing is forced and they fold;
where either side reports more than one port (a LAG) they deliberately stay
apart, because nothing says which port faces which.

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

# ------------------------------------------- the reciprocal CDP-only double

# Two Cisco switches, one cable, CDP only: neither side writes a chassis
# subtype, so neither row resolves a matched_if_index and there is no
# MAC-matched link for either to fold onto. Both rows survive on per-row keys
# and draw on the same coordinates -- the doubling again, from the other
# direction. But these are the ONLY two rows between devices 1 and 2, one port
# each side, so the pairing is forced and the cable folds to one link. The
# fold also hands each end the OTHER switch's own port_label, in place of the
# raw cdpCachePortId string the cable carried across.
rows_name_only = [
    cdp_row(1, 11, device_id_text="core-sw", matched_device_id=2,
            port_id="GigabitEthernet0/21", rem_index="11.1"),
    cdp_row(2, 21, device_id_text="edge-sw", matched_device_id=1,
            port_id="GigabitEthernet0/11", rem_index="21.1"),
]
links_nm, _ = assemble_links(rows_name_only, port_vlans={}, port_label=label_of,
                             on_map=all_on_map, now=NOW)
check("the reciprocal CDP-only case (one row each side) draws ONE link",
      len(links_nm) == 1, links_nm)
if len(links_nm) == 1:
    check("...with both ends labelled from their own port_label, not the raw CDP string",
          (links_nm[0]["a_port"], links_nm[0]["b_port"]) == ("dev1/if11", "dev2/if21"),
          links_nm[0])
    check("...and the far-end if_index now known",
          (links_nm[0]["a_if_index"], links_nm[0]["b_if_index"]) == (11, 21),
          links_nm[0])
    check("...still carrying the protocol", links_nm[0]["protocols"] == ["cdp"], links_nm[0])

# Determinism: the same two rows in the other order must produce the SAME
# link -- same id, same a/b ends -- or the id would flip every time device 2
# happened to be walked before device 1, which the UI would read as the link
# itself having changed.
links_nm_rev, _ = assemble_links(list(reversed(rows_name_only)), port_vlans={},
                                 port_label=label_of, on_map=all_on_map, now=NOW)
check("...and folds to the same link whichever row arrives first",
      len(links_nm_rev) == 1 and len(links_nm) == 1
      and (links_nm_rev[0]["id"], links_nm_rev[0]["a_device_id"], links_nm_rev[0]["a_if_index"],
           links_nm_rev[0]["b_device_id"], links_nm_rev[0]["b_if_index"],
           links_nm_rev[0]["a_port"], links_nm_rev[0]["b_port"])
      == (links_nm[0]["id"], links_nm[0]["a_device_id"], links_nm[0]["a_if_index"],
          links_nm[0]["b_device_id"], links_nm[0]["b_if_index"],
          links_nm[0]["a_port"], links_nm[0]["b_port"]),
      (links_nm, links_nm_rev))

# The LAG case: two parallel cables between the same pair of switches, each
# side reporting two ports facing the other. Nothing in the rows says which
# of device 1's ports faces which of device 2's, so a fold would be the guess
# link_identity refuses to make -- and would collapse a real port-channel of
# two cables into one line. All four rows must stay exactly as they are.
rows_lag = [
    cdp_row(1, 11, device_id_text="core-sw", matched_device_id=2, rem_index="11.1"),
    cdp_row(1, 12, device_id_text="core-sw", matched_device_id=2, rem_index="12.1"),
    cdp_row(2, 21, device_id_text="edge-sw", matched_device_id=1, rem_index="21.1"),
    cdp_row(2, 22, device_id_text="edge-sw", matched_device_id=1, rem_index="22.1"),
]
links_lag, _ = assemble_links(rows_lag, port_vlans={}, port_label=label_of,
                              on_map=all_on_map, now=NOW)
check("two parallel cables between one pair (a LAG) do NOT fold -- four links stand",
      len(links_lag) == 4, links_lag)
if len(links_lag) == 4:
    check("...none of them given a guessed far-end if_index",
          all(one["b_if_index"] is None for one in links_lag), links_lag)

# Asymmetric: device 1 reports two ports facing device 2, device 2 reports
# one facing device 1 (the second cable's row not yet walked, or a port that
# went quiet). One-vs-two is still ambiguous -- which of device 1's two ports
# is the one device 2 named? -- so nothing folds.
rows_asym = [
    cdp_row(1, 11, device_id_text="core-sw", matched_device_id=2, rem_index="11.1"),
    cdp_row(1, 12, device_id_text="core-sw", matched_device_id=2, rem_index="12.1"),
    cdp_row(2, 21, device_id_text="edge-sw", matched_device_id=1, rem_index="21.1"),
]
links_asym, _ = assemble_links(rows_asym, port_vlans={}, port_label=label_of,
                               on_map=all_on_map, now=NOW)
check("a 1-vs-2 asymmetric pair does NOT fold either -- three links stand",
      len(links_asym) == 3, links_asym)

# Two name-only rows facing DIFFERENT devices are two cables, not a
# reciprocal pair: device 1 names device 2 and device 2 names device 3. The
# name-only twin of the frozenset case above -- nothing groups them, so
# nothing folds.
rows_nm_other = [
    cdp_row(1, 11, device_id_text="core-sw", matched_device_id=2, rem_index="11.1"),
    cdp_row(2, 21, device_id_text="dist-sw", matched_device_id=3, rem_index="21.1"),
]
links_nm_other, _ = assemble_links(rows_nm_other, port_vlans={}, port_label=label_of,
                                   on_map=all_on_map, now=NOW)
check("two name-only rows facing different devices are not folded together",
      len(links_nm_other) == 2, links_nm_other)


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


# ------------------------------------ a DISABLED device shares the chassis MAC

def _disabled_twin_rows():
    """One physical box carrying two device rows: a disabled duplicate an
    operator kept rather than deleted (the lower id), and the enabled row that
    is actually polled. Both carry the box's chassis MAC on an interface.
    Also the shape a shared virtual MAC has — VRRP/HSRP on a pair whose
    lower-id router is disabled."""
    tmp = tmpdir("mapper_disabled_twin_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    try:
        group_id = db.ensure_default_group()
        observer = db.add_device("10.0.0.1", "edge-sw-1", group_id=group_id)
        retired = db.add_device("10.0.0.9", "core-sw (old entry)", group_id=group_id)
        live = db.add_device("10.0.0.2", "core-sw", group_id=group_id)
        db.update_device(retired, enabled=0)
        mac = "00:11:22:33:44:55"
        for device_id in (retired, live):
            db.replace_interfaces(device_id, [
                {"if_index": 20, "descr": "Gi1/0/20", "alias": "",
                 "phys_addr": mac, "speed_bps": 1e9,
                 "admin_status": "up", "oper_status": "up"}])
        db.replace_neighbors(observer, [{
            "if_index": 10, "protocol": "lldp", "rem_index": "0.10.1",
            "chassis_id": mac, "chassis_id_subtype": 4, "port_id": "Gi1/0/20",
            "port_id_subtype": 5, "port_descr": "", "sys_name": "",
            "sys_descr": "", "platform": "", "remote_address": "",
        }])
        return live, [dict(row) for row in db.all_neighbours()]
    finally:
        db.close()


live_id, twin_rows = _disabled_twin_rows()
check("a chassis MAC shared with a DISABLED device still matches the enabled one",
      [row["matched_device_id"] for row in twin_rows] == [live_id],
      [(row["matched_device_id"], row["matched_if_index"]) for row in twin_rows])
check("...pointing at that device's own port",
      [row["matched_if_index"] for row in twin_rows] == [20],
      [row["matched_if_index"] for row in twin_rows])
check("...and matched_by_mac_id agrees, so the suggestion keeps its confidence",
      [row["matched_by_mac_id"] for row in twin_rows] == [live_id],
      [row["matched_by_mac_id"] for row in twin_rows])
links_twin, twin_peers = assemble_links(twin_rows, port_vlans={},
                                        port_label=label_of, on_map=all_on_map,
                                        now=NOW)
check("...drawing a link BETWEEN the two devices, not one dead-ending in an "
      "unmanaged peer",
      len(links_twin) == 1 and links_twin[0]["b_device_id"] == live_id
      and not links_twin[0]["unmanaged"], links_twin)
check("...and no phantom peer standing in for the device it failed to match",
      twin_peers == [], twin_peers)


def main():
    print()
    if FAILS:
        print(f"{len(FAILS)} FAILURE(S): " + "; ".join(FAILS))
        raise SystemExit(1)
    print("all mapper fold checks passed")


main()
