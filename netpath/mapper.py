"""Pure link-assembly and render-plan layer for MAPPER, the manually-built
L2 network map.

Nothing here touches sqlite3, SNMP, or HTTP: every function is a plain
transform over plain dicts/rows (an `assemble_links` caller hands over
`nodesdb.all_neighbours()` rows, a VLAN-per-port dict, and a couple of
closures) so the whole module is exhaustively unit-testable, and so the
drawing maths -- which VLANs collapse into which strand offsets, how wide
a collapsed trunk gets -- lives in ONE place (here) instead of being
duplicated in mapper.js. The API layer calls these and ships the result as
JSON; mapper.js only draws what it is handed.

This re-does, properly and with VLANs added, the reasoning
`_topology_dedup_key` / `_topology_unknown_identity` carried in
`netpath/web/api.py` before 4.53.0 deleted the fleet-wide L2 graph route
those helpers backed ("a separate module will replace the graph itself" --
this module).
"""

from __future__ import annotations

import re

from .mapperdb import ROLES as _MAP_NODE_ROLES

LINK_PROTOCOLS = ("lldp", "cdp")

# mapperdb.ROLES is map_nodes.role's own domain, and it leads with "" to mean
# "no operator override -- auto-detect" (a column-storage concern: the
# database has to store SOMETHING for "unset", and '' is that something).
# detect_role() below never returns that meaning -- it always tries to name
# a role -- but it reuses the very same "" string for its OWN "found no
# signal at all" answer, because the two are never compared to each other:
# the API layer only ever asks "is map_nodes.role non-empty" (operator
# override) OR calls detect_role() (auto), never both at once for the same
# question. Deriving ROLES from mapperdb's tuple rather than hand-copying it
# is what makes "detect_role's return value is always a member of
# mapperdb.ROLES" true by construction instead of by two lists agreeing.
ROLES = tuple(role for role in _MAP_NODE_ROLES if role)

VLAN_PALETTE_SIZE = 16

# Knuth-style multiplicative hashing constant: any odd 32-bit integer makes
# `(vlan * constant) mod 2**32` a bijection on the 32-bit ring (multiplying
# by an odd number is invertible mod a power of two), so no VLAN id is ever
# folded onto another one's product -- only the top bits kept afterward can
# collide. The textbook choice is the odd integer nearest 2**32 times the
# golden ratio (2654435761), but that constant's own bit pattern happens to
# alias several of the round decimal ids real networks use for VLANs (10,
# 20, ..., 100, 200, ...) onto the same top 4 bits. This constant was
# selected by searching odd 32-bit integers for one that keeps those
# specific round numbers scattered (see vlan_color_index and the
# round-number check in test_mapper_links.py) while remaining exactly the
# same construction otherwise.
_KNUTH_MULTIPLIER = 1248904971


# ------------------------------------------------------------- node role
#
# All vocabulary below is matched against a lower-cased sysDescr (and, for
# an unmanaged peer's platform string -- see detect_role -- that too), the
# same substring idiom nodeoids.SYSDESCR_VENDORS already uses for vendor
# identification. Vendor keys compared directly (never substring-matched)
# are the canonical keys enterprises.py/nodeoids.py already produce
# (identify_vendor / vendor_from_descr), so detect_role never invents its
# own vendor vocabulary -- it only decides what a vendor's PRODUCT LINE
# implies, given a vendor already resolved elsewhere.

# These vendors' entire catalog is a firewall/security appliance -- unlike
# Fortinet and Cisco below, none of them also sells switches or APs under
# the same vendor key, so the vendor key alone is enough.
_FIREWALL_ONLY_VENDORS = frozenset({
    "paloAlto", "sonicwall", "checkPoint", "watchguard", "pfSense",
})

# sysDescr substrings that mean "firewall" even when the vendor key alone
# would not: Fortinet sells FortiSwitch/FortiAP under the same "fortinet"
# vendor key as FortiGate, and Cisco sells ASA/Firepower alongside
# Catalyst/ISR/Aironet under "cisco" -- so for these two, only the
# model-line word in the text itself can tell a firewall apart from the
# rest of that vendor's catalog. "meraki mx" is Meraki's OWN security
# appliance line and is listed here, ahead of the router hints below,
# specifically because Juniper's MX router family would otherwise match
# the router hints' bare "mx" pattern -- Meraki's sysDescr always says
# "Meraki" too, so checking for the pair together resolves the clash.
_FIREWALL_HINTS = (
    "fortigate", "meraki mx", "asa", "adaptive security appliance",
    "firepower", "pan-os",
)

# FortiAP shares Fortinet's vendor key with FortiGate/FortiSwitch, so -- same
# reasoning as the firewall hints above -- it needs its own model-name
# substring rather than a vendor check. Aironet is Cisco's AP line (vendor
# key "cisco", shared with switches/routers/firewalls); "meraki mr" is Cisco
# Meraki's AP model prefix (MR), distinguished from its MX security
# appliances and MS switches by the letter after "meraki ". "unifi ap" is
# Ubiquiti's managed-AP product name. The rest -- nanobeam/nanostation/
# litebeam/powerbeam/airmax/airfiber/airos -- are the EXACT substrings
# nodeoids.SYSDESCR_VENDORS uses to identify Ubiquiti's airMAX/airOS radios
# from sysDescr alone (that table's own comment explains why: these PtP/
# PtMP radios rarely say "ubiquiti" anywhere in their sysDescr). Reused
# rather than re-typed here, because on this hardware family the model name
# IS the role signal too: an airOS/airMAX radio bridge is, functionally, an
# access point.
_AP_HINTS = (
    "fortiap", "aironet", "meraki mr", "unifi ap",
    "nanobeam", "nanostation", "litebeam", "powerbeam",
    "airmax", "airfiber", "airos",
)

# ISR/ASR (Cisco) and MX (Juniper) are edge/core router product families,
# short enough that a plain substring risks matching inside unrelated text
# (an "asr" could be a typo'd word fragment; "mx" is only two letters), so
# each is matched with a word boundary immediately followed by a digit --
# "isr4321", "asr9006", "mx480" all match; a stray "mx" elsewhere does not.
_ROUTER_MODEL_RE = re.compile(r"\b(?:isr|asr|mx)\d")
# EdgeRouter/EdgeOS are Ubiquiti's ROUTER line -- deliberately absent from
# _AP_HINTS above, which covers Ubiquiti's radio/AP families instead; the
# same vendor's sysDescr vocabulary splits cleanly by product line the same
# way Fortinet's and Cisco's do.
_ROUTER_HINTS = ("edgerouter", "edgeos")

# Catalyst/Nexus (Cisco), PowerConnect (Dell), ProCurve (HP's pre-Aruba
# switch branding) are switch-only product names and safe to match as plain
# substrings. EX (Juniper) and ICX (Ruckus/Brocade) are short the same way
# MX is above, so they get the same word-boundary-plus-digit guard.
# "arubaos-cx"/"aruba cx" needs its own sysDescr substring rather than a
# vendor check: Aruba's vendor key ("aruba") is shared with its AP line by
# canonical_key (enterprises.VENDOR_ALIASES folds "arubaCx" into "aruba"),
# so only ArubaOS-CX's own sysDescr text -- which says "CX" -- can tell the
# switch apart from an Aruba AP.
_SWITCH_MODEL_RE = re.compile(r"\b(?:ex|icx)\d")
_SWITCH_HINTS = (
    "catalyst", "nexus", "powerconnect", "procurve",
    "arubaos-cx", "aruba cx", "switch",
)

# A sysDescr naming an operating system, not a network appliance -- the
# openings net-snmp/Windows/BSD/ESXi agents actually use ("Linux <host>
# <kernel>...", "Hardware: ... Windows ...", "FreeBSD <host> ...", "VMware
# ESXi ...").
_SERVER_HINTS = ("linux", "windows", "freebsd", "vmware esxi", "esxi")


def detect_role(*, vendor="", sys_descr="", sys_object_id="", platform="",
                unmanaged=False) -> str:
    """A map node's role, auto-detected from what is already known about the
    device -- no new polling, no new storage, just a classification over
    fields nodesdb already has. Always one of `ROLES`, or "" when nothing
    here lets us say. Pure and side-effect free so it is unit-testable
    without a database, an SNMP agent, or an HTTP server (see
    test_mapper_links.py's detect_role section).

    The caller decides what an operator's manual override (map_nodes.role,
    where "" means "auto") means; this function only ever computes the
    AUTO half, and never sees the override -- see the ROLES comment above
    for how the two "" meanings relate without colliding.

    Rule order (each checked only if nothing earlier matched):

      1. `unmanaged=True` -> "unmanaged", unconditionally, before any other
         field is even read. An unmanaged CDP/LLDP peer has no device row
         and so no sysDescr of its own to classify by -- only whatever its
         NEIGHBOUR happened to report about it (platform, sys_name), which
         is far too thin a signal to guess switch/router/firewall/ap/server
         from, and guessing wrong here would be worse than the honest
         "we don't manage this one" the front end already draws distinctly.
      2. No signal at all (every field blank) -> "", the honest "we looked
         and could not say" -- distinct from an operator explicitly having
         picked "switch", which is why the API layer carries a separate
         `role_auto` flag rather than overloading this string.
      3. Firewall vendors/hints (see _FIREWALL_ONLY_VENDORS/_FIREWALL_HINTS).
      4. AP hints (see _AP_HINTS).
      5. Router hints (see _ROUTER_MODEL_RE/_ROUTER_HINTS), plus the literal
         word "router" anywhere in the text -- a catch-all for a sysDescr
         that names itself one in words rather than a model number.
      6. Switch hints (see _SWITCH_MODEL_RE/_SWITCH_HINTS) -- checked BEFORE
         the server rule below, not after, so a switch that happens to also
         run embedded Linux (some do, in their sysDescr banner) is still
         read as the switch it is.
      7. Server hints (see _SERVER_HINTS): a sysDescr naming an operating
         system, reached only once router/switch have already had their
         chance to claim it.
      8. Default: "switch". A managed device that answered SNMP (there IS a
         signal -- step 2 already ruled out "nothing at all") but matched
         none of the above is, on an L2 map, far more often an unclassified
         switch than anything else -- routers, firewalls and APs are a
         small minority of ports on a typical LLDP/CDP-walked network, so
         defaulting to the common case gives the operator's manual override
         less work to do than defaulting to "" (which would just make every
         plain switch draw as a generic box until someone classified it
         by hand).
    """
    if unmanaged:
        return "unmanaged"

    vendor = (vendor or "").strip()
    sys_object_id = (sys_object_id or "").strip()
    descr = (sys_descr or "").strip().lower()
    plat = (platform or "").strip().lower()

    if not (vendor or sys_object_id or descr or plat):
        return ""

    # sys_object_id is deliberately NOT searched below: it is a dotted OID,
    # not text a product line would name itself in, so every hint list
    # matches against sysDescr and platform only. It still counts toward
    # "is there a signal at all" above -- a device identified purely by
    # sysObjectID (sysDescr blank) is still a real, managed device.
    haystack = f"{descr} {plat}"

    if vendor in _FIREWALL_ONLY_VENDORS or any(h in haystack for h in _FIREWALL_HINTS):
        return "firewall"
    if any(h in haystack for h in _AP_HINTS):
        return "ap"
    if (_ROUTER_MODEL_RE.search(haystack) or any(h in haystack for h in _ROUTER_HINTS)
            or "router" in haystack):
        return "router"
    if _SWITCH_MODEL_RE.search(haystack) or any(h in haystack for h in _SWITCH_HINTS):
        return "switch"
    if any(h in haystack for h in _SERVER_HINTS):
        return "server"
    return "switch"


def _get(row, key, default=None):
    """`row[key]` when present, `default` otherwise -- the one guard every
    function in this module uses to read an optional column, because `row`
    is documented only to support `row["col"]` (a sqlite3.Row from
    nodesdb.all_neighbours(), or a hand-built dict in the tests) and neither
    type can be relied on to have `.get`. `sqlite3.Row` and `dict` both
    support `in row.keys()`, which is what api.py's own `_neighbor_json`
    already uses for the same reason."""
    return row[key] if key in row.keys() else default


def peer_identity(row) -> str:
    """What makes two unmatched neighbour rows the SAME unmanaged peer --
    an AP or phone with no SNMP of its own, seen from two switches, has to
    fold into one node with two links, not two disconnected boxes, or
    "add neighbours" would offer the operator the same device twice and a
    map built from it would draw it twice.

    Preference order mirrors the deleted `_topology_unknown_identity`:
    chassis_id first (LLDP/CDP chassis ids are supposed to be globally
    unique -- normally a MAC -- so two rows reporting the same one really
    are the same box), then sys_name (weaker: two sites can both name a
    phone "SEP001122334455", but it is still a better signal than nothing),
    then a fallback built from this row's own (device_id, if_index,
    protocol) -- the honest answer for "nothing here identifies this
    neighbour beyond the port it was seen on", which keeps the row from
    being silently merged into some unrelated peer just because both
    happened to report no identity at all.

    Each branch is prefixed (`chassis:`, `sysname:`, `row:`) so a chassis id
    that happens to look like a sys_name string, or vice versa, can never
    collide across branches; sys_name is lower-cased to match the
    case-insensitive comparison `_NEIGHBOR_MATCH_SQL` already uses for the
    same field."""
    chassis_id = _get(row, "chassis_id") or ""
    if chassis_id:
        return f"chassis:{chassis_id.strip().lower()}"
    sys_name = _get(row, "sys_name") or ""
    if sys_name:
        return f"sysname:{sys_name.strip().lower()}"
    return (f"row:{row['device_id']}:{row['if_index']}:{row['protocol']}:"
            f"{_get(row, 'rem_index') or ''}")


def link_identity(device_id, if_index, matched_id, matched_if_index) -> object:
    """The undirected identity of one physical link, so a cable walked from
    BOTH ends -- the switch that owns this port, and the device across the
    cable, if it also walks its own LLDP/CDP table -- folds into one line
    instead of drawing the same cable twice.

    `matched_if_index` (nodesdb's join of the remote chassis MAC to the
    remote device's OWN interface, see `_NEIGHBOR_MATCH_SQL`) is what makes
    the two rows -- (A, ifA) matched to (B, ifB), and separately (B, ifB)
    matched to (A, ifA) -- produce the identical frozenset key below, so
    the second row folds onto the first. A sysName-only match (no MAC, so
    no matched_if_index) cannot be paired this way: nodesdb only tells us
    "these sysNames match", not which of the matched device's ports faces
    this cable, so guessing would risk pairing this row against the WRONG
    port on a multi-homed device. It gets its own per-row key instead,
    which draws as a second, one-directional line rather than a wrong
    guess at which port to fold it onto."""
    if matched_if_index is not None:
        return frozenset({(device_id, if_index), (matched_id, matched_if_index)})
    return ("name-match", device_id, if_index)


def _link_id(key) -> str:
    """A stable string id for a link's identity key. A frozenset key is
    sorted before stringifying so the two rows that produce the SAME cable
    (walked from both ends) also produce the SAME id regardless of which
    row happened to be seen first -- an id that depended on insertion order
    would change every time a device re-walked its table before its peer
    did, which would look to the UI like the link itself had changed."""
    if isinstance(key, frozenset):
        pair_a, pair_b = sorted(key)
        return f"link:{pair_a[0]}:{pair_a[1]}~{pair_b[0]}:{pair_b[1]}"
    return "link:" + ":".join(str(part) for part in key)


def _port_vlans(port_vlans: dict, device_id, if_index):
    """The (vlan ids, native vlan) pair for one local port, from the
    port_vlans dict a caller built from Q-BRIDGE/VTP/mac_entries data.
    Native vlan is whichever entry is reported untagged -- a trunk normally
    has at most one, but if a caller's source ever disagrees we take the
    first and move on rather than raising, because a wrong native vlan on
    one strand is a cosmetic mislabel, not a reason to fail the whole map."""
    entries = port_vlans.get((device_id, if_index)) or []
    vlan_ids = sorted({int(entry["vlan"]) for entry in entries})
    native = next((int(entry["vlan"]) for entry in entries
                   if not entry.get("tagged", True)), None)
    return vlan_ids, native


def assemble_links(neighbour_rows, *, port_vlans, port_label, on_map, now,
                   stale_after_s=None) -> tuple[list[dict], list[dict]]:
    """Turn raw LLDP/CDP neighbour rows into the links and peers one map
    draws.

    Processing order per row matters and is deliberate:
      1. protocol / present / staleness filters drop rows that should not
         draw at all (see below).
      2. `on_map(device_id)` -- the reporting device must be placed on
         THIS map, or its neighbours are not this map's business (they
         belong to whichever map that device lives on).
      3. matched rows (nodesdb resolved chassis id or sysName to a real
         device) build a link keyed by `link_identity`; unmatched rows are
         an unmanaged peer, identified by `peer_identity`.
      4. the peer entry (if any) is recorded UNCONDITIONALLY at this
         point -- "neighbours you could add" has to list a peer whether or
         not it has been placed yet, or the "Add neighbours" helper could
         never discover a peer for the first time.
      5. only THEN is the far end's own placement checked
         (`on_map(b_device_id)` or `on_map(peer_key)`): a link draws only
         when BOTH ends are on the map, but that check must not gate step 4
         or a not-yet-placed peer would never be offered at all.

    `on_map` is called with TWO different argument types, and must answer
    for both: an `int` device id (every call at step 2, and step 5 for a
    matched row's far end), or a `str` peer key (step 5 for an unmanaged
    row's far end -- the same string `peer_identity` produced). This is
    wider than "callable(device_id) -> bool" reads in isolation, but a
    placed unmanaged peer has no device id to test with, only the peer_key
    it was placed under, so the caller's map-membership lookup has to be
    keyed on whichever of the two it is given.

    Presence and staleness: `present=0` is nodesdb's own record that the
    last walk of that device did not hear this row any more (see
    replace_neighbors), and a row older than `stale_after_s` (by seen_ts)
    is one no recent walk has refreshed either way. Both are treated the
    same: skip the row. A link is a claim about the CURRENT physical
    topology, not a history; drawing a cable that has since been
    unplugged (or a device that has stopped answering) would be worse than
    silence, because the operator has no way to tell "still there" from
    "last seen three weeks ago" apart on the map itself. `stale_after_s`
    is a separate knob from `present` because a device can be polled far
    less often than a map is refreshed -- disabling it (`None`) is for a
    caller that trusts `present` alone (e.g. lldp_interval_s already long
    enough that a stray staleness cutoff would just be a second, redundant
    clock racing the first one).

    VLANs on a link are the UNION of what each end's OWN port reports
    (`_port_vlans`, applied once per row to that row's local device/
    if_index), never the intersection. A trunk is only really usable for a
    VLAN both ends allow, so intersection looks like the "more correct"
    answer -- but in practice one end very often has NO VLAN data at all
    (an unmanaged peer has no VLAN MIB to ask; plenty of managed devices
    answer no VLAN MIB either), and intersecting anything with the empty
    set is the empty set. That would erase every VLAN on the link the
    moment either end is VLAN-blind, which is a strictly worse failure mode
    than occasionally showing a VLAN the far end happens not to carry.
    """
    port_vlans = port_vlans or {}
    links_by_key: dict = {}
    peers_by_key: dict = {}

    for row in neighbour_rows:
        protocol = row["protocol"]
        if protocol not in LINK_PROTOCOLS:
            continue
        if not row["present"]:
            continue
        seen_ts = row["seen_ts"]
        if stale_after_s is not None and seen_ts is not None \
                and (now - seen_ts) > stale_after_s:
            continue

        device_id = row["device_id"]
        if_index = row["if_index"]
        if not on_map(device_id):
            continue

        a_port = port_label(device_id, if_index)
        a_vlans, a_native = _port_vlans(port_vlans, device_id, if_index)

        matched_id = _get(row, "matched_device_id")
        matched_if_index = _get(row, "matched_if_index")

        if matched_id is not None:
            key = link_identity(device_id, if_index, matched_id, matched_if_index)
            b_device_id = matched_id
            b_if_index = matched_if_index
            if matched_if_index is not None:
                b_port = port_label(matched_id, matched_if_index)
            else:
                b_port = row["port_id"] or row["port_descr"] or ""
            b_peer_key = ""
            b_map_id = matched_id
            unmanaged = False
        else:
            peer_key = peer_identity(row)
            key = (device_id, if_index, "peer", peer_key)
            b_device_id = None
            b_if_index = None
            b_port = row["port_id"] or row["port_descr"] or ""
            b_peer_key = peer_key
            b_map_id = peer_key
            unmanaged = True

            peer = peers_by_key.get(peer_key)
            if peer is None:
                peer = {"peer_key": peer_key,
                        "name": row["sys_name"] or row["platform"]
                                or row["chassis_id"] or peer_key,
                        "platform": row["platform"] or "",
                        "address": row["remote_address"] or "",
                        "seen_via": [], "seen_ts": seen_ts}
                peers_by_key[peer_key] = peer
            # Deduped on the port, not appended blind: a Cisco switch answers
            # both the LLDP and the CDP table for the same neighbour on the
            # same cable, and those are two rows that both reach here. Without
            # this the "Add neighbours" list would say the peer was seen twice
            # on one port, which reads as two cables rather than one neighbour
            # confirmed by two protocols.
            if not any(via["device_id"] == device_id and via["if_index"] == if_index
                       for via in peer["seen_via"]):
                peer["seen_via"].append({"device_id": device_id,
                                         "if_index": if_index, "port": a_port})
            peer["seen_ts"] = max(peer["seen_ts"], seen_ts)

        if not on_map(b_map_id):
            continue    # far end not placed -- no link, but the peer above still stands

        link = links_by_key.get(key)
        if link is None:
            link = {"id": _link_id(key), "a_device_id": device_id, "a_port": a_port,
                    "a_if_index": if_index, "b_device_id": b_device_id,
                    "b_peer_key": b_peer_key, "b_port": b_port, "b_if_index": b_if_index,
                    "protocols": set(), "unmanaged": unmanaged, "vlans": set(),
                    "native_vlan": None, "seen_ts": seen_ts}
            links_by_key[key] = link
        link["protocols"].add(protocol)
        link["vlans"] |= set(a_vlans)
        if link["native_vlan"] is None and a_native is not None:
            link["native_vlan"] = a_native
        link["seen_ts"] = max(link["seen_ts"], seen_ts)

    links = []
    for link in links_by_key.values():
        link["protocols"] = sorted(link["protocols"])
        link["vlans"] = sorted(link["vlans"])
        links.append(link)
    return links, list(peers_by_key.values())


def vlan_color_index(vlan: int, overrides: dict[int, int] | None = None) -> int:
    """A deterministic 0..VLAN_PALETTE_SIZE-1 colour slot for a VLAN id.

    Deliberately NOT `vlan % 16`: real estates number VLANs in round,
    evenly-spaced blocks -- 10, 20, 30, ..., 100, 200, 300 -- and every one
    of those is a multiple of 10, so `% 16` walks the same handful of
    residues (10, 4, 14, 8, 2, 12, ...) over and over and collides most of
    a site's VLANs onto a few colours, which is exactly the "which colour
    is which VLAN" confusion the whole strand-colouring feature exists to
    avoid.

    Instead this is a Knuth-style multiplicative hash for a table of size
    2**4: multiply by the odd constant `_KNUTH_MULTIPLIER` (mod 2**32,
    picked by search -- see the constant's own comment) and keep the top 4
    bits. Multiplying by an odd constant is a bijection mod 2**32, and this
    particular constant was chosen so that round decimal VLAN ids land in
    scattered, unrelated slots instead of a repeating pattern -- see
    test_mapper_links.py, which asserts this over exactly the round-number
    VLAN ids a real network uses.

    `overrides` lets an operator pin a specific VLAN to a specific slot
    (e.g. matching an existing house colour convention) without changing
    the hash for every other VLAN."""
    if overrides and vlan in overrides:
        return overrides[vlan] % VLAN_PALETTE_SIZE
    hashed = (vlan * _KNUTH_MULTIPLIER) & 0xFFFFFFFF
    return hashed >> 28


def render_plan(link, *, threshold, max_strands, width_min, width_max,
                color_overrides=None) -> dict:
    """The drawing instruction for one link, computed once, server side, so
    mapper.js never has to re-derive strand offsets or collapsed widths
    (or, worse, derive them slightly differently on every browser).

    Three modes:
      - 0 VLANs known ("plain"): an L2 link we know exists (a neighbour row
        matched) but know no VLANs for -- because neither end answered a
        VLAN MIB, say -- is still a real link and still has to draw as
        something, so it draws as one neutral line at width_min. It carries
        "known": False specifically so the UI can distinguish "this link
        has exactly one VLAN" (a real, if unusual, fact) from "nobody knows
        this link's VLANs at all" (an absence) -- collapsing those two into
        the same look would misreport a trunk as a single-VLAN access link.
      - fewer than `threshold` VLANs, AND fewer than `max_strands`
        ("strands"): one strand per VLAN, drawn side by side. Offsets are
        spaced `width_min * 2` apart and centred on the link's centre line
        (symmetric: for N strands they run from -(N-1)*width_min to
        +(N-1)*width_min), so the whole strand bundle is centred wherever
        the single-line link would have been, rather than the bundle
        drifting to one side as VLAN count changes.
      - at or above `threshold`, OR at or above `max_strands`
        ("collapsed"): one thick line, width linearly interpolated between
        width_min (at `threshold`) and width_max (at `max_strands`),
        clamped at both ends -- so a 400-VLAN link (a misconfiguration, but
        it happens) still draws at width_max rather than a line half the
        screen wide, and a link sitting exactly at `threshold` draws at
        width_min, the same width the last strand mode would have used, so
        the transition between the two modes has no visible jump.
        `max_strand_vlans` is checked here independently of `threshold` --
        not folded into "count < threshold" -- because it is a genuine
        ceiling on how many strands are EVER drawn individually (see
        mapperdb.DEFAULTS' own comment): a misconfigured pair with
        max_strands at or below threshold must still collapse every link
        at or above max_strands, not draw threshold-1 strands regardless.
        `_check_mapper_settings` refuses to store such a pair going
        forward, but render_plan itself has no way to know its caller
        validated anything, so it enforces the cap unconditionally.

    "vlan_count" and "vlans" (the full sorted VLAN list) are present in
    every mode, not only the collapsed one where the label needs the
    number: a drawing routine that reads plan.vlan_count or plan.vlans
    unconditionally would otherwise get undefined for two of the three
    modes, and the keys cost nothing to carry -- "vlans" is what hover/
    click lists regardless of which mode won.
    """
    vlans = sorted(link.get("vlans") or [])
    count = len(vlans)

    if count == 0:
        return {"mode": "plain", "width": width_min, "strands": [],
                "known": False, "vlan_count": 0, "vlans": vlans}

    if count < threshold and count < max_strands:
        spacing = width_min * 2
        start = -spacing * (count - 1) / 2
        strands = [
            {"vlan": vlan, "color_index": vlan_color_index(vlan, color_overrides),
             "offset": start + i * spacing}
            for i, vlan in enumerate(vlans)
        ]
        return {"mode": "strands", "width": width_min, "strands": strands,
                "known": True, "vlan_count": count, "vlans": vlans}

    span = max_strands - threshold
    frac = (count - threshold) / span if span > 0 else 1.0
    frac = min(max(frac, 0.0), 1.0)
    width = width_min + (width_max - width_min) * frac
    return {"mode": "collapsed", "width": width, "strands": [], "known": True,
            "vlan_count": count, "vlans": vlans}


LINK_CSV_HEADER = ["A Device", "A Device ID", "A Port", "A Port Mode", "A Native VLAN",
                   "B Device", "B Device ID", "B Port", "B Port Mode", "B Native VLAN",
                   "Protocols", "VLAN Count", "VLANs", "Native VLAN", "Seen"]


def link_csv_rows(links, device_name) -> list[list]:
    """One row per link for the CSV export, in `LINK_CSV_HEADER` order. The
    B side is either a real device (name/id from `device_name`) or, for an
    unmanaged peer, its `peer_key` with no id -- an export exists to leave
    with the whole picture, so an unmanaged peer still gets a row rather
    than being silently dropped just because it has no device id.

    Each end carries its own port mode and native VLAN (from vlan_ports,
    what the device itself reports) alongside the older single "Native VLAN"
    column, which is the A side inferred from which VLAN crosses the port
    untagged. Both are kept rather than the weaker one replaced: a native
    VLAN that differs between the two ends of a trunk is a real
    misconfiguration, and an export that averaged it into one column would
    hide exactly the row somebody exported the file to find. The blank a
    column carries is "nothing reported it", not "zero"."""
    rows = []
    for link in links:
        if link["b_device_id"] is not None:
            b_name = device_name(link["b_device_id"])
            b_id = link["b_device_id"]
        else:
            b_name = link["b_peer_key"]
            b_id = ""

        def cell(key):
            value = link.get(key)
            return "" if value is None else value

        rows.append([
            device_name(link["a_device_id"]), link["a_device_id"], link["a_port"],
            cell("a_port_mode"), cell("a_native_vlan"),
            b_name, b_id, link["b_port"],
            cell("b_port_mode"), cell("b_native_vlan"),
            ",".join(link["protocols"]),
            len(link["vlans"]),
            ";".join(str(vlan) for vlan in link["vlans"]),
            link["native_vlan"] if link["native_vlan"] is not None else "",
            link["seen_ts"],
        ])
    return rows
