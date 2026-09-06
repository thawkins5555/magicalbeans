"""netpath/mapper.py: the pure link-assembly and render-plan layer MAPPER's
API and front-end both code against. No database, no SNMP, no HTTP -- every
row here is a hand-built dict standing in for a sqlite3.Row from
nodesdb.all_neighbours(), so this whole suite runs with nothing but the
stdlib.

Covers: link folding (both-ends-walked cables collapse; sysName-only
matches do not), unmanaged-peer identity and multiplicity, the on_map
placement gate, present/staleness filtering, protocol/VLAN merging,
render_plan's three modes, vlan_color_index's collision behaviour, and the
CSV export shape.
"""
from _paths import tmpdir  # noqa: F401  (registers repo root on sys.path)

from netpath import mapperdb
from netpath.mapper import (
    LINK_CSV_HEADER,
    LINK_PROTOCOLS,
    ROLES,
    VLAN_PALETTE_SIZE,
    assemble_links,
    detect_role,
    link_csv_rows,
    link_identity,
    peer_identity,
    render_plan,
    vlan_color_index,
)

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


NOW = 1_000_000.0


def row(device_id, if_index, protocol="lldp", *, rem_index="1",
        chassis_id="", sys_name="", port_id="", port_descr="", platform="",
        remote_address="", present=1, seen_ts=NOW, first_seen_ts=NOW,
        matched_device_id=None, matched_device_name=None, matched_if_index=None):
    """A hand-built stand-in for one nodesdb.all_neighbours() row -- a plain
    dict, since mapper.py only ever requires row["col"]."""
    return {
        "device_id": device_id, "if_index": if_index, "protocol": protocol,
        "rem_index": rem_index, "chassis_id": chassis_id,
        "chassis_id_subtype": 4 if chassis_id else None,
        "port_id": port_id, "port_id_subtype": None, "port_descr": port_descr,
        "sys_name": sys_name, "sys_descr": "", "platform": platform,
        "remote_address": remote_address, "seen_ts": seen_ts,
        "first_seen_ts": first_seen_ts, "present": present,
        "matched_device_id": matched_device_id,
        "matched_device_name": matched_device_name,
        "matched_if_index": matched_if_index,
    }


def label_of(device_id, if_index):
    return f"dev{device_id}/if{if_index}"


def all_on_map(_id):
    return True


# ----------------------------------------------------------------- folding

# A cable walked from both ends: device 1's port 10 sees device 2 (matched,
# its own port 20), and device 2's port 20 sees device 1 (matched, its own
# port 10) right back.
rows_both_ends = [
    row(1, 10, chassis_id="aa:bb", matched_device_id=2, matched_if_index=20),
    row(2, 20, chassis_id="cc:dd", matched_device_id=1, matched_if_index=10),
]
links, peers = assemble_links(rows_both_ends, port_vlans={}, port_label=label_of,
                              on_map=all_on_map, now=NOW)
check("a cable walked from both ends collapses to ONE link",
      len(links) == 1, links)
if links:
    link = links[0]
    ports = {link["a_port"], link["b_port"]}
    check("...with both ports labelled correctly",
          ports == {"dev1/if10", "dev2/if20"}, link)
check("no peers from a fully-matched cable", peers == [], peers)

# A sysName-only match: nodesdb resolved a device but has no matched
# if_index for either direction, so the two rows must NOT fold -- pairing
# them would be a guess at which port on the far end this cable lands on.
rows_name_only = [
    row(1, 11, sys_name="core-sw", matched_device_id=2, matched_if_index=None),
    row(2, 21, sys_name="edge-sw", matched_device_id=1, matched_if_index=None),
]
links_nm, _ = assemble_links(rows_name_only, port_vlans={}, port_label=label_of,
                             on_map=all_on_map, now=NOW)
check("a sysName-only match (no matched_if_index) does NOT fold -- two links",
      len(links_nm) == 2, links_nm)

# ------------------------------------------------------------- unmanaged peers

# The same unmanaged AP, seen from two different switches, must be one peer
# with two links -- not two disconnected "unknown" boxes.
rows_peer = [
    row(1, 12, chassis_id="ap:mac:1", sys_name="ap-lobby", port_id="Gi0/1"),
    row(2, 22, chassis_id="ap:mac:1", sys_name="ap-lobby", port_id="Gi0/2"),
]
links_p, peers_p = assemble_links(rows_peer, port_vlans={}, port_label=label_of,
                                  on_map=all_on_map, now=NOW)
check("the same unmanaged peer seen from two switches is ONE peer",
      len(peers_p) == 1, peers_p)
check("...with two links (one per observing switch)",
      len(links_p) == 2, links_p)
if peers_p:
    check("...and the peer records both devices it was seen via",
          {v["device_id"] for v in peers_p[0]["seen_via"]} == {1, 2}, peers_p)

# ------------------------------------------------------- on_map gating

def only_device_1(id_):
    return id_ == 1

rows_offmap_peer = [row(1, 13, chassis_id="phone:1", sys_name="phone")]
links_off, peers_off = assemble_links(rows_offmap_peer, port_vlans={}, port_label=label_of,
                                      on_map=only_device_1, now=NOW)
check("a link whose far end (an unplaced peer) is not on the map is not returned",
      links_off == [], links_off)
check("...but its peer IS returned, so 'add neighbours' can still offer it",
      len(peers_off) == 1, peers_off)

rows_offmap_device = [row(1, 14, chassis_id="x", matched_device_id=2, matched_if_index=24)]
links_off2, peers_off2 = assemble_links(rows_offmap_device, port_vlans={}, port_label=label_of,
                                        on_map=only_device_1, now=NOW)
check("a link to a real device that is not on the map is also not returned",
      links_off2 == [], links_off2)
check("...and produces no peer entry (it is a known device, not a peer)",
      peers_off2 == [], peers_off2)

# on_map's contract is wider than "callable(device_id) -> bool" reads in
# isolation: it is also asked about an unmanaged peer's str peer_key (there
# is no device id to ask about for a peer that has no device row at all).
# Pin that explicitly with an on_map that raises on anything else, so a
# future refactor that narrows the type by accident fails loudly here
# instead of silently miscounting a placed peer as off-map.
def typed_on_map(id_):
    if not isinstance(id_, (int, str)):
        raise TypeError(f"on_map got an unexpected type: {type(id_)!r}")
    return True

rows_typed = [
    row(1, 40, chassis_id="typed-a", matched_device_id=2, matched_if_index=41),
    row(2, 41, chassis_id="typed-b", matched_device_id=1, matched_if_index=40),
    row(3, 42, chassis_id="typed-peer", sys_name="typed-peer"),
]
try:
    links_typed, peers_typed = assemble_links(
        rows_typed, port_vlans={}, port_label=label_of, on_map=typed_on_map, now=NOW)
    typed_ok = len(links_typed) == 2 and len(peers_typed) == 1
    typed_detail = (links_typed, peers_typed)
except TypeError as exc:
    typed_ok = False
    typed_detail = str(exc)
check("on_map is called only with an int device id or a str peer key -- "
      "never anything else -- for both a matched-device link and an "
      "unmanaged-peer link",
      typed_ok, typed_detail)

# ------------------------------------------------------- presence / staleness

rows_stale = [
    row(1, 15, chassis_id="dead", present=0),
    row(1, 16, chassis_id="old", seen_ts=NOW - 500),
    row(1, 17, chassis_id="fresh", seen_ts=NOW - 5),
]
links_stale, peers_stale = assemble_links(rows_stale, port_vlans={}, port_label=label_of,
                                          on_map=all_on_map, now=NOW, stale_after_s=100)
check("present=0 rows do not draw",
      all(p["peer_key"] != "chassis:dead" for p in peers_stale), peers_stale)
check("stale-by-seen_ts rows do not draw",
      all(p["peer_key"] != "chassis:old" for p in peers_stale), peers_stale)
check("a fresh row still draws under a staleness cutoff",
      any(p["peer_key"] == "chassis:fresh" for p in peers_stale), peers_stale)

links_nocutoff, peers_nocutoff = assemble_links(rows_stale, port_vlans={}, port_label=label_of,
                                                on_map=all_on_map, now=NOW, stale_after_s=None)
check("stale_after_s=None disables the staleness cutoff (old row draws)",
      any(p["peer_key"] == "chassis:old" for p in peers_nocutoff), peers_nocutoff)
check("...but present=0 still excludes the dead row regardless of the cutoff",
      all(p["peer_key"] != "chassis:dead" for p in peers_nocutoff), peers_nocutoff)

# ------------------------------------------------------- protocol merge

rows_both_protocols = [
    row(1, 18, "lldp", chassis_id="bb:bb", matched_device_id=2, matched_if_index=28),
    row(2, 28, "cdp", chassis_id="cc:cc", matched_device_id=1, matched_if_index=18),
]
links_proto, _ = assemble_links(rows_both_protocols, port_vlans={}, port_label=label_of,
                                on_map=all_on_map, now=NOW)
check("the same cable seen by both CDP and LLDP folds to one link",
      len(links_proto) == 1, links_proto)
if links_proto:
    check("...with protocols merged and sorted",
          links_proto[0]["protocols"] == ["cdp", "lldp"], links_proto[0])

# ------------------------------------------------------------- VLAN union

port_vlans = {
    (1, 19): [{"vlan": 10, "tagged": True}, {"vlan": 1, "tagged": False}],
    (2, 29): [{"vlan": 20, "tagged": True}],
}
rows_vlan = [
    row(1, 19, chassis_id="v1", matched_device_id=2, matched_if_index=29),
    row(2, 29, chassis_id="v2", matched_device_id=1, matched_if_index=19),
]
links_vlan, _ = assemble_links(rows_vlan, port_vlans=port_vlans, port_label=label_of,
                               on_map=all_on_map, now=NOW)
check("VLANs union across the two ends of a link",
      links_vlan and links_vlan[0]["vlans"] == [1, 10, 20], links_vlan)
if links_vlan:
    check("...and the native (untagged) vlan from whichever end reports one",
          links_vlan[0]["native_vlan"] == 1, links_vlan[0])

# a link where only one end reports VLANs at all keeps them (no intersection)
port_vlans_one_sided = {(1, 30): [{"vlan": 50, "tagged": True}, {"vlan": 60, "tagged": True}]}
rows_one_sided = [
    row(1, 30, chassis_id="one-sided-a", matched_device_id=2, matched_if_index=31),
    row(2, 31, chassis_id="one-sided-b", matched_device_id=1, matched_if_index=30),
]
links_one_sided, _ = assemble_links(rows_one_sided, port_vlans=port_vlans_one_sided,
                                    port_label=label_of, on_map=all_on_map, now=NOW)
check("a link with VLAN data on only one end keeps that end's VLANs "
      "(union, not an intersection that would erase them)",
      links_one_sided and links_one_sided[0]["vlans"] == [50, 60], links_one_sided)

# ------------------------------------------------------------- link_identity

check("link_identity of matched, known-if_index rows is undirected (order-independent)",
      link_identity(1, 10, 2, 20) == link_identity(2, 20, 1, 10))
check("link_identity without a matched_if_index falls back to a per-row key",
      link_identity(1, 10, 2, None) != link_identity(2, 20, 1, None))


# ---------------------------------------------------------------- peer_identity

check("peer_identity prefers chassis_id",
      peer_identity(row(1, 1, chassis_id="AA:BB", sys_name="whatever"))
      == peer_identity(row(2, 2, chassis_id="aa:bb", sys_name="other")))
check("peer_identity falls back to sys_name when chassis_id is absent",
      peer_identity(row(1, 1, sys_name="Phone-1"))
      == peer_identity(row(2, 2, sys_name="phone-1")))
check("peer_identity falls back to a row-unique key when nothing else is reported",
      peer_identity(row(1, 1)) != peer_identity(row(1, 2)))


# ---------------------------------------------------------------- render_plan

RP_KW = dict(threshold=8, max_strands=64, width_min=2.0, width_max=12.0)

plan0 = render_plan({"vlans": []}, **RP_KW)
check("0 VLANs -> plain mode", plan0["mode"] == "plain", plan0)
check("...at width_min", plan0["width"] == 2.0, plan0)
check("...and known is False (never confused with a real 1-VLAN link)",
      plan0["known"] is False, plan0)

vlans_below = list(range(1, 8))  # threshold - 1 = 7 VLANs
plan_strands = render_plan({"vlans": vlans_below}, **RP_KW)
check("fewer than threshold VLANs -> strands mode", plan_strands["mode"] == "strands", plan_strands)
check("...with one strand per VLAN",
      len(plan_strands["strands"]) == len(vlans_below), plan_strands)
offsets = [s["offset"] for s in plan_strands["strands"]]
check("...offsets symmetric about the centre line (sum ~= 0)",
      abs(sum(offsets)) < 1e-9, offsets)
check("...offsets spaced by width_min * 2",
      all(abs((offsets[i + 1] - offsets[i]) - 4.0) < 1e-9 for i in range(len(offsets) - 1)),
      offsets)

plan_collapsed = render_plan({"vlans": list(range(1, 9))}, **RP_KW)  # exactly threshold
check("exactly `threshold` VLANs -> collapsed mode",
      plan_collapsed["mode"] == "collapsed", plan_collapsed)
check("...at width_min (no jump between strands and collapsed at the boundary)",
      abs(plan_collapsed["width"] - 2.0) < 1e-9, plan_collapsed)
check("...carrying vlan_count", plan_collapsed["vlan_count"] == 8, plan_collapsed)

plan_max = render_plan({"vlans": list(range(1, 65))}, **RP_KW)  # == max_strands
check("at max_strands VLANs, width reaches width_max",
      abs(plan_max["width"] - 12.0) < 1e-9, plan_max)

plan_over = render_plan({"vlans": list(range(1, 401))}, **RP_KW)  # way over max_strands
check("width is clamped at width_max even far beyond max_strands (a 400-VLAN misconfig)",
      abs(plan_over["width"] - 12.0) < 1e-9, plan_over)

widths = [render_plan({"vlans": list(range(1, n + 1))}, **RP_KW)["width"]
          for n in (8, 16, 32, 48, 64, 200)]
check("width is monotonically non-decreasing as VLAN count grows",
      all(widths[i] <= widths[i + 1] + 1e-9 for i in range(len(widths) - 1)), widths)
check("width never dips below width_min",
      all(w >= 2.0 - 1e-9 for w in widths), widths)

for count_in_plan in (plan_strands, plan_collapsed):
    check(f"render_plan always carries the full sorted vlans list ({count_in_plan['mode']})",
          count_in_plan["vlans"] == sorted(count_in_plan["vlans"]), count_in_plan)

# max_strand_vlans is a genuine cap (Finding 8): at or above it a link must
# collapse regardless of vlan_collapse_threshold, even for a misconfigured
# pair with max_strands <= threshold (_check_mapper_settings now refuses to
# store one, but render_plan itself must not depend on that having run --
# it is handed raw threshold/max_strands and has to enforce the cap itself).
# Reproduces the finding's own example: threshold=8, max_strand_vlans=5,
# count=7 used to draw 7 individual strands.
plan_capped = render_plan({"vlans": list(range(1, 8))},  # 7 VLANs
                          threshold=8, max_strands=5, width_min=1.5, width_max=14.0)
check("count under threshold but at/over max_strand_vlans still collapses",
      plan_capped["mode"] == "collapsed", plan_capped)
check("...never drawing more individual strands than max_strand_vlans allows",
      len(plan_capped["strands"]) == 0, plan_capped)

plan_at_cap = render_plan({"vlans": list(range(1, 6))},  # exactly max_strands (5)
                          threshold=8, max_strands=5, width_min=1.5, width_max=14.0)
check("count exactly at max_strand_vlans collapses too (the cap is inclusive)",
      plan_at_cap["mode"] == "collapsed", plan_at_cap)

plan_under_cap = render_plan({"vlans": list(range(1, 5))},  # under both bounds
                             threshold=8, max_strands=5, width_min=1.5, width_max=14.0)
check("count under both threshold and max_strand_vlans still draws strands",
      plan_under_cap["mode"] == "strands", plan_under_cap)


# ------------------------------------------------------------ vlan_color_index

check("vlan_color_index is deterministic",
      vlan_color_index(100) == vlan_color_index(100))
check("vlan_color_index overrides win",
      vlan_color_index(100, overrides={100: 3}) == 3)
check("...and are taken modulo the palette size, never out of range",
      vlan_color_index(100, overrides={100: 19}) == 3)

# A plain `vlan % 16` collapses every one of these round, evenly-spaced ids
# (all multiples of 10) into a handful of residues -- exactly the collision
# the multiplicative hash exists to avoid. Assert the actual property
# instead of the naive formula's score.
round_vlans = [1, 10, 20, 30, 40, 50, 100, 200, 300, 400, 500, 999, 1000, 2000]
indexes = [vlan_color_index(v) for v in round_vlans]
check("vlan_color_index scatters real-world round-number VLAN ids: "
      f">=12 of {VLAN_PALETTE_SIZE} colours used across {len(round_vlans)} ids",
      len(set(indexes)) >= 12, indexes)
check("...and every index is in range",
      all(0 <= i < VLAN_PALETTE_SIZE for i in indexes), indexes)


# ------------------------------------------------------------ link_csv_rows

def device_name(device_id):
    return f"Device-{device_id}"

csv_links = links + links_p  # a matched link and an unmanaged-peer link
csv_rows = link_csv_rows(csv_links, device_name)
check("link_csv_rows returns one row per link",
      len(csv_rows) == len(csv_links), csv_rows)
check("...and every row's shape matches LINK_CSV_HEADER's length",
      all(len(r) == len(LINK_CSV_HEADER) for r in csv_rows), csv_rows)
# Column positions come from LINK_CSV_HEADER, not from literal indexes: this
# check was pinned to r[4]/r[3] and broke the moment per-end port mode and
# native VLAN columns were added ahead of them, reporting a column shift as a
# missing peer name. Looking the names up means a new column moves this test
# rather than failing it.
B_ID = LINK_CSV_HEADER.index("B Device ID")
B_NAME = LINK_CSV_HEADER.index("B Device")
peer_rows = [r for r in csv_rows if r[B_ID] == ""]
check("...an unmanaged peer's row has no B device id but still names the peer",
      peer_rows and all(r[B_NAME] for r in peer_rows), peer_rows)
check("...and every end's port mode and native VLAN have their own columns",
      all(name in LINK_CSV_HEADER for name in
          ("A Port Mode", "A Native VLAN", "B Port Mode", "B Native VLAN")),
      LINK_CSV_HEADER)

check("LINK_PROTOCOLS is exactly lldp and cdp", LINK_PROTOCOLS == ("lldp", "cdp"))

# ------------------------------------------- a peer confirmed by both protocols

# A Cisco switch answers its LLDP table AND its CDP table for the same
# neighbour on the same cable, so the same peer arrives as two rows that both
# pass every filter. seen_via has to record that as one port confirmed twice,
# not two ports: "Add neighbours" showing the same AP on Gi0/1 twice reads as
# two cables that are not there.
rows_both_proto = [
    row(1, 12, "lldp", chassis_id="ap:mac:9", sys_name="ap-hall", port_id="Gi0/1"),
    row(1, 12, "cdp", chassis_id="ap:mac:9", sys_name="ap-hall", port_id="Gi0/1"),
]
_, peers_bp = assemble_links(rows_both_proto, port_vlans={}, port_label=label_of,
                             on_map=all_on_map, now=NOW)
check("a peer reported by both LLDP and CDP on one port is one peer",
      len(peers_bp) == 1, peers_bp)
if peers_bp:
    check("...seen_via records that port once, not once per protocol",
          len(peers_bp[0]["seen_via"]) == 1, peers_bp[0]["seen_via"])
    check("...and seen_via carries the if_index the dedupe keys on",
          peers_bp[0]["seen_via"][0].get("if_index") == 12, peers_bp[0]["seen_via"])

# ...but the same peer on two DIFFERENT ports of one switch is two cables and
# must still record both, or the dedupe would have thrown away a real link.
rows_two_ports = [
    row(1, 12, chassis_id="ap:mac:9", sys_name="ap-hall", port_id="Gi0/1"),
    row(1, 13, chassis_id="ap:mac:9", sys_name="ap-hall", port_id="Gi0/2"),
]
_, peers_tp = assemble_links(rows_two_ports, port_vlans={}, port_label=label_of,
                             on_map=all_on_map, now=NOW)
check("the same peer on two ports of one switch records both ports",
      peers_tp and len(peers_tp[0]["seen_via"]) == 2, peers_tp)

# --------------------------------------- vlan_count is present in every mode

# mapper.js reads plan.vlan_count to label a link; a key that exists in only
# one of the three modes would hand it undefined for the other two.
for mode_name, plan_link in (("plain", {"vlans": []}),
                             ("strands", {"vlans": [10, 20]}),
                             ("collapsed", {"vlans": list(range(1, 21))})):
    plan_any = render_plan(plan_link, threshold=8, max_strands=30,
                           width_min=1.5, width_max=14.0)
    check(f"render_plan's {mode_name} mode carries vlan_count",
          plan_any.get("vlan_count") == len(plan_link["vlans"]), plan_any)
    check(f"...and {mode_name} mode is the mode that ran",
          plan_any["mode"] == mode_name, plan_any)

# --------------------------------------------------------------- detect_role

check("mapper.ROLES is mapperdb.ROLES with the '' (auto) member dropped",
      ROLES == tuple(r for r in mapperdb.ROLES if r), (ROLES, mapperdb.ROLES))

def assert_role(name, role, **kw):
    got = detect_role(**kw)
    check(name, got == role, (kw, "got", got, "want", role))
    check(f"...and detect_role's return value ({got!r}) is a member of mapperdb.ROLES",
          got in mapperdb.ROLES, got)

# An unmanaged CDP/LLDP peer never gets a managed role, even when handed
# vendor/sysDescr fields that would otherwise scream "Catalyst switch" --
# unmanaged=True is checked first and wins unconditionally, because a peer
# has no sysDescr of its OWN: whatever text is passed here would really be
# describing the NEIGHBOUR that reported it, not this peer.
assert_role("an unmanaged peer is always 'unmanaged', regardless of other fields",
            "unmanaged", unmanaged=True, vendor="cisco",
            sys_descr="Cisco IOS Software, C2960X Software, ... Catalyst")

# Fortinet sells FortiGate (firewall), FortiSwitch (switch) and FortiAP (AP)
# all under the same "fortinet" vendor key -- this is the case worth
# pinning: vendor alone must NOT be enough to call either one.
assert_role("a Fortinet FortiGate is a firewall",
            "firewall", vendor="fortinet",
            sys_descr="FortiGate-100F v7.0.1,build0157 (GA)")
assert_role("a FortiAP -- same vendor key as the FortiGate above -- is an AP",
            "ap", vendor="fortinet", sys_descr="FortiAP-231F v6.2,build0179")
assert_role("a FortiSwitch -- same vendor key again -- is a switch",
            "switch", vendor="fortinet", sys_descr="FortiSwitch-124F v6.4")

# Cisco sells ASA/Firepower (firewall), Catalyst/Nexus (switch), ISR/ASR
# (router) and Aironet (AP) all under "cisco" -- the same vendor-sharing
# case as Fortinet above, so each needs its own sysDescr hint too.
assert_role("a Cisco ASA is a firewall despite the shared 'cisco' vendor key",
            "firewall", vendor="cisco",
            sys_descr="Cisco Adaptive Security Appliance Software Version 9.12")
assert_role("a Cisco Firepower is a firewall",
            "firewall", vendor="cisco", sys_descr="Cisco Firepower Threat Defense")
assert_role("a Cisco Aironet is an AP despite the shared 'cisco' vendor key",
            "ap", vendor="cisco", sys_descr="Cisco Aironet AIR-AP2802I")
assert_role("a Catalyst is a switch", "switch", vendor="cisco",
            sys_descr="Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M),"
                      " Version 15.2 -- Catalyst 2960X")
assert_role("an ISR is a router", "router", vendor="cisco",
            sys_descr="Cisco IOS-XE Software, ISR4321 Software")
assert_role("an ASR is a router, matched the same word-boundary way as ISR",
            "router", vendor="cisco", sys_descr="Cisco IOS-XR Software, ASR9006")

# Vendors whose whole catalog is a firewall/appliance -- the vendor key
# alone is enough, no sysDescr hint required.
for fw_vendor in ("paloAlto", "sonicwall", "checkPoint", "watchguard", "pfSense"):
    assert_role(f"vendor {fw_vendor!r} alone is enough to call it a firewall",
                "firewall", vendor=fw_vendor, sys_descr="")

# Meraki's own product letters share a vendor ("meraki" isn't even a
# canonical key here -- Meraki devices are keyed "cisco" or a dedicated
# arc, but the sysDescr always says "Meraki" plus a model letter) --
# MX (security appliance) must not fall through to the MX-router hint.
assert_role("a Meraki MX is a firewall, not a Juniper-style MX router",
            "firewall", sys_descr="Cisco Meraki MX68 cloud managed")
assert_role("a Meraki MR is an AP", "ap", sys_descr="Cisco Meraki MR36")

# Ubiquiti's airMAX/airOS radios: reuses nodeoids.SYSDESCR_VENDORS' own
# vocabulary (see mapper.py's _AP_HINTS comment) because on this hardware
# family the model name doubles as the role signal.
assert_role("a Ubiquiti airOS radio (NanoBeam) is an AP",
            "ap", vendor="ubiquiti", sys_descr="Linux NanoBeam 5AC 8.7.11")
assert_role("Ubiquiti's EdgeRouter/EdgeOS line is a router, not an AP -- "
            "the two product lines split the same vendor's sysDescr vocabulary",
            "router", vendor="ubiquiti", sys_descr="Linux EdgeOS ubnt 4.4.0")

# Juniper MX/EX -- the word-boundary-plus-digit guard on the short "mx"/"ex"
# tokens (bare "mx"/"ex" must not match, e.g. inside unrelated text).
assert_role("a Juniper MX is a router", "router", vendor="juniper",
            sys_descr="Juniper Networks, Inc. mx240 internet router")
assert_role("a Juniper EX is a switch", "switch", vendor="juniper",
            sys_descr="Juniper Networks, Inc. ex4300 Ethernet Switch")
# A naive bare-substring "mx"/"ex" check would misread "complex"/"maximum"
# as Juniper MX/EX gear and call this a router; the word-boundary + digit
# guard means neither model-number hint fires, so this managed device with
# no other signal just gets the ordinary switch default instead.
assert_role("bare 'mx'/'ex' inside unrelated words does not falsely trigger "
            "the router/switch model-number hints",
            "switch", vendor="juniper", sys_descr="juniper complex maximum uptime device")

# Aruba's vendor key is shared between its switch (ArubaOS-CX) and AP
# lines by canonical_key (arubaCx -> aruba), so only the sysDescr's own
# "CX" wording -- not the vendor key -- can tell the switch apart.
assert_role("an ArubaOS-CX switch is a switch despite the shared 'aruba' vendor key",
            "switch", vendor="aruba", sys_descr="ArubaOS-CX 10.08")

# A bare sysDescr naming an operating system, not a network appliance, with
# no switch/router/firewall/AP signal at all.
assert_role("a bare Linux sysDescr is a server",
            "server", sys_descr="Linux server01 5.4.0-100-generic #113-Ubuntu SMP")
assert_role("a Windows sysDescr is a server",
            "server", sys_descr="Hardware: x64 Family... Windows Server 2019")
assert_role("a FreeBSD sysDescr is a server", "server", sys_descr="FreeBSD host.example 13.1")
assert_role("a VMware ESXi sysDescr is a server", "server", sys_descr="VMware ESXi 7.0.3")

# A managed device (it has a sysObjectID, so it answered SNMP) with an
# empty sysDescr still falls back to switch -- "we know something is here
# and managed" is a real signal even with no text to classify by, and on
# an L2 map an unclassified managed box is far more often a switch than
# anything else.
assert_role("a managed device with an empty sysDescr falls back to switch",
            "switch", sys_object_id="1.3.6.1.4.1.9.1.1208", sys_descr="")

# Genuinely nothing to go on: no vendor, no sysDescr, no sysObjectID, no
# platform -- the honest "we looked and could not say" answer, distinct
# from an operator having actually picked "switch" (which is why the API
# layer carries role_auto alongside this).
assert_role("a device with no signal at all returns ''", "")


print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
