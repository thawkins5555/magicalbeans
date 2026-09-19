"""Handlers: the network map (Mapper) editor."""

from __future__ import annotations

import math
import time

from ... import namelookup
from ... import mapper
from ... import nodepoll
from ... import report as reportmod

from ._shared import Conflict, _audit, _csv_response, _mapper_port_index, _matched_device_names, _neighbor_local_port_labeler, _pick, _require


# ------------------------------------------------------------------- mapper
#
# MAPPER draws a manually-built map: mapperdb owns where a device or
# unmanaged peer was dropped and what an operator called it, and everything
# about what is actually cabled together (LLDP/CDP, VLAN membership) is read
# live from nodesdb through netpath/mapper.py's pure assembly functions —
# there is no MAPPER poller and nothing here caches a link across requests.

def _mapper_map_json(row) -> dict:
    return {"id": row["id"], "name": row["name"], "notes": row["notes"],
            "created_ts": row["created_ts"], "updated_ts": row["updated_ts"]}


def get_mapper_maps(service, params, body) -> dict:
    maps = []
    for row in service.mapper_db.maps():
        # One nodes() read per map, not per node: with maps numbering in the
        # tens at most (they are hand-built, never auto-created) this is a
        # handful of queries, not a fleet-scale cost.
        entry = _mapper_map_json(row)
        entry["node_count"] = len(service.mapper_db.nodes(row["id"]))
        maps.append(entry)
    return {"maps": maps, "settings": service.mapper_settings}


def post_mapper_map(service, params, body) -> dict:
    name = str(body.get("name", "") or "")
    notes = str(body.get("notes", "") or "")
    # create_map itself raises ValueError, with an operator-readable
    # message, for a blank or a case-insensitively duplicate name -- left to
    # surface unchanged rather than caught and reworded here.
    map_id = service.mapper_db.create_map(name, notes)
    _audit(service, params, "mapper.map.create", target=str(map_id),
          detail=f"name={name}")
    return {"id": map_id}


def put_mapper_map(service, params, body, map_id) -> dict:
    before = _require(service.mapper_db.map_row(map_id), "map")
    # A caller renaming only stays on its own name; one editing only notes
    # (notes omitted entirely) leaves them alone via rename_map's own
    # notes=None meaning "unchanged" -- not the same as notes="", which
    # clears them.
    name = str(body.get("name", before["name"]) or "")
    notes = body.get("notes")
    service.mapper_db.rename_map(map_id, name, notes=notes)
    _audit(service, params, "mapper.map.rename", target=str(map_id),
          detail=f"name={name}")
    return {"ok": True}


def delete_mapper_map(service, params, body, map_id) -> dict:
    before = service.mapper_db.map_row(map_id)
    ok = service.mapper_db.delete_map(map_id)
    if before is not None:
        _audit(service, params, "mapper.map.delete", target=str(map_id),
              detail=f"name={before['name']}")
    return {"ok": ok}


def _mapper_vlans_json(service, links, device_ids, color_overrides: dict) -> list[dict]:
    """{"vlan","name","color_index","link_count"} for every VLAN carried by
    at least one link on THIS map -- not the fleet-wide VLAN list, which
    would show entries for a switch nowhere near this drawing. `name` is
    whichever device happened to name that VLAN id first (nodesdb.
    vlans_for_devices is bounded to `device_ids` but still spans every
    device on the map, and VLAN naming is not guaranteed consistent across
    them, but showing no name at all when some device on the map clearly
    knows one would be a worse default).

    vlans_for_devices, not a fleet-wide read: every VLAN id that could
    possibly appear in `counts` was read off a link, and a link only exists
    between two devices this map places (assemble_links's on_map check), so
    a VLAN this map could ever need naming for was necessarily named by one
    of `device_ids` -- reading the fleet's whole `vlans` table to resolve a
    handful of ids was exactly the cost this route's report measured (87 ms
    at 2,000 devices x 50 VLANs)."""
    counts: dict[int, int] = {}
    for link in links:
        for vlan in link["vlans"]:
            counts[vlan] = counts.get(vlan, 0) + 1
    if not counts:
        return []
    names: dict[int, str] = {}
    for row in service.nodes_db.vlans_for_devices(device_ids):
        vlan = row["vlan"]
        if vlan in counts and row["name"] and vlan not in names:
            names[vlan] = row["name"]
    return [
        {"vlan": vlan, "name": names.get(vlan, ""),
         "color_index": mapper.vlan_color_index(vlan, color_overrides),
         "link_count": count}
        for vlan, count in sorted(counts.items())
    ]


def _mapper_port_vlans(service, device_ids, *, now: float,
                       stale_after_s: float | None) -> dict:
    """(device_id, if_index) -> [{"vlan","tagged"}], the shape
    mapper.assemble_links wants, built once from nodesdb's port_vlans table
    for just the devices this map places (port_vlans_for_devices) rather
    than one port_vlans_for() call per neighbour row -- or, before this,
    the whole fleet's port_vlans table for a map that might place six
    devices (see get_mapper_map's own report on that cost).

    present=0 and stale-by-seen_ts rows are dropped -- the same two checks
    mapper.assemble_links already applies to the neighbour rows themselves
    (see its docstring's Presence-and-staleness paragraph). Without this, a
    VLAN a trunk stopped carrying still drew on the map, unchanged, until
    prune_port_vlans eventually dropped the row after
    mac_table_retention_days (7 days by default) -- a removed VLAN reading
    as still-present for up to a week, when the link it rode already
    dropped a stale/removed neighbour at `stale_after_s`. `stale_after_s`
    is `None` for a caller that trusts `present` alone, the same meaning
    assemble_links gives it."""
    out: dict = {}
    for row in service.nodes_db.port_vlans_for_devices(device_ids):
        if not row["present"]:
            continue
        seen_ts = row["seen_ts"]
        if stale_after_s is not None and seen_ts is not None \
                and (now - seen_ts) > stale_after_s:
            continue
        out.setdefault((row["device_id"], row["if_index"]), []).append(
            {"vlan": row["vlan"], "tagged": bool(row["tagged"])})
    return out


def _mapper_vlan_ports(service, device_ids, *, now: float,
                       stale_after_s: float | None) -> dict:
    """(device_id, if_index) -> {"mode","native_vlan"}, built once from
    nodesdb's `vlan_ports` table for just the devices this map places
    (vlan_ports_for_devices) -- _mapper_port_vlans' own shape, applied to
    the sibling table so get_mapper_map can label each link end with the
    trunk/access mode and device-reported native VLAN an operator reading a
    trunk diagram expects, rather than leaving that table written every
    poll and read by nothing.

    present=0 and stale-by-seen_ts rows are dropped, the same two checks
    _mapper_port_vlans applies and for the same reason: a port that stopped
    reporting a mode should read as "unknown", not keep showing a mode from
    before it went stale."""
    out: dict = {}
    for row in service.nodes_db.vlan_ports_for_devices(device_ids):
        if not row["present"]:
            continue
        seen_ts = row["seen_ts"]
        if stale_after_s is not None and seen_ts is not None \
                and (now - seen_ts) > stale_after_s:
            continue
        out[(row["device_id"], row["if_index"])] = {
            "mode": row["mode"] or None, "native_vlan": row["native_vlan"]}
    return out


def _mapper_node_role(row, *, unmanaged: bool, device=None) -> tuple[str, bool]:
    """(role, role_auto) for one map node. The operator's own override
    (map_nodes.role, non-empty) always wins; otherwise the role comes from
    mapper.detect_role(), fed whatever identity this node actually has to
    detect from -- a peer has no device row of its own (only its
    neighbour's view of it), so it goes through detect_role(unmanaged=True)
    rather than being handed empty vendor/sysDescr fields that would
    otherwise read as "no signal" instead of "definitely unmanaged".
    `role_auto` is True whenever the override was empty, so the front end's
    role <select> can show "Auto (switch)" rather than pretending the
    operator chose it."""
    override = row["role"]
    if override:
        return override, False
    if device is None:
        return mapper.detect_role(unmanaged=unmanaged), True
    return mapper.detect_role(
        vendor=device["vendor"] or "", sys_descr=device["sys_descr"] or "",
        sys_object_id=device["sys_object_id"] or ""), True


def _mapper_node_name(label: str, resolved: str) -> tuple[str, str]:
    """(name, resolved_name) for one map node. `name` is what draws on the
    map AND what the CSV export reads (get_mapper_map_export builds its
    device_name callable straight from these nodes' own "name", so fixing
    it here fixes both consumers at once, per the operator's own report
    that a renamed node still showed its original name in the export).
    `resolved_name` -- named for "the identity resolved from live data",
    not "device_name", because this same function also names an unmanaged
    peer's resolved identity, which is not a device at all -- is kept
    alongside so the UI can still show "renamed from resolved_name" without
    losing that fact the moment an operator renames a node."""
    return (label or resolved), resolved


def _apply_ip_matches(service, rows) -> list[dict]:
    """Neighbour rows as dicts with the address match applied over the SQL
    join (matched_if_index stays None: no interface evidence) and every
    matched name replaced by the display-name chain."""
    out = [dict(row) for row in rows]
    if service.nodes_db is None:
        return out
    ip_matches = service.nodes_db.neighbour_device_matches(
        out, nodepoll.neighbor_ip_candidates)
    for index, device in ip_matches.items():
        row = out[index]
        row["matched_device_id"] = device["id"]
        row["matched_device_ip"] = device["ip"]
        row["matched_if_index"] = None

    names = _matched_device_names(service, (row["matched_device_id"] for row in out))
    for row in out:
        device_id = row.get("matched_device_id")
        if device_id in names:
            row["matched_device_name"] = names[device_id]
    return out


def _mapper_peer_name(service, rows):
    """peer_name callable for assemble_links: DNS cache (one batched read),
    then sys_name/platform/chassis_id, the same order as the candidates."""
    candidate_ips = set()
    for row in rows:
        if row.get("matched_device_id") is None:
            candidate_ips.update(nodepoll.neighbor_ip_candidates(row))
    names = (service.app_db.hostnames(candidate_ips)
            if candidate_ips and service.app_db is not None else {})

    def peer_name(row) -> str:
        for ip in nodepoll.neighbor_ip_candidates(row):
            if names.get(ip):
                return names[ip]
        return row["sys_name"] or row["platform"] or row["chassis_id"] or ""
    return peer_name


def _mapper_assemble(service, device_ids, node_rows, now: float, stale_after_s):
    """get_mapper_map's link-assembly phase: the per-port VLAN reads, the
    prefetched port labeller, the on-map predicate and the neighbour read
    that feed mapper.assemble_links. Returns (links, peers, vlan_ports) --
    vlan_ports is the only one of this phase's own reads the caller still
    needs afterwards, to carry each link's port mode/native VLAN."""
    port_vlans = _mapper_port_vlans(
        service, device_ids, now=now, stale_after_s=stale_after_s)
    vlan_ports = _mapper_vlan_ports(
        service, device_ids, now=now, stale_after_s=stale_after_s)
    # Prefetched: every label this map needs belongs to a device it
    # places, already known here, so one read serves them all.
    port_label = _neighbor_local_port_labeler(service, prefetch_ids=device_ids)
    placed_device_ids = set(device_ids)
    placed_peer_keys = {row["peer_key"] for row in node_rows if row["peer_key"]}

    def on_map(key) -> bool:
        return key in placed_device_ids or key in placed_peer_keys

    # neighbours_for_devices, not all_neighbours(): assemble_links only ever
    # uses a neighbour row whose OWN device_id is on_map (see its docstring's
    # processing-order paragraph, step 2), so a row observed by a device this
    # map does not place can never produce a link OR a peer on it -- reading
    # the whole fleet's neighbour table to draw a handful of placements was
    # exactly the cost this route's report measured (12.4s at 10k rows).
    neighbour_rows = _apply_ip_matches(
        service, service.nodes_db.neighbours_for_devices(device_ids))
    port_index = _mapper_port_index(service, device_ids)
    links, peers = mapper.assemble_links(
        neighbour_rows, port_vlans=port_vlans,
        port_label=port_label, on_map=on_map, now=now,
        stale_after_s=stale_after_s,
        peer_name=_mapper_peer_name(service, neighbour_rows),
        port_index=port_index)
    return links, peers, vlan_ports


def _mapper_add_manual_links(service, map_id, node_rows, links: list,
                             width_min: float) -> None:
    """get_mapper_map's D2 phase: manual lines the operator drew by hand,
    appended to `links` in place -- mapper.js's drawLink and friends see
    one list and branch on `manual`. Every key a discovered link carries is
    present here too (even where always None), so a code path that reads
    e.g. link.a_port_mode without checking `manual` first does not throw."""
    node_by_id = {row["id"]: row for row in node_rows}
    for row in service.mapper_db.links(map_id):
        a_node = node_by_id.get(row["a_node_id"])
        b_node = node_by_id.get(row["b_node_id"])
        if a_node is None or b_node is None:
            continue    # placement removed since; the FK cascade will catch up
        links.append({
            "id": f"m{row['id']}", "link_id": row["id"], "manual": True,
            "a_device_id": a_node["device_id"], "a_peer_key": a_node["peer_key"] or "",
            "b_device_id": b_node["device_id"], "b_peer_key": b_node["peer_key"] or "",
            "a_port": "", "b_port": "", "a_if_index": None, "b_if_index": None,
            "a_port_mode": None, "a_native_vlan": None,
            "b_port_mode": None, "b_native_vlan": None,
            "a_media": None, "b_media": None, "fiber": False,
            "a_optic_mode": None, "b_optic_mode": None, "fiber_mode": None,
            "a_stp": None, "b_stp": None, "a_stp_vlans": None, "b_stp_vlans": None,
            "blocking": False,
            "label": row["label"], "protocols": ["manual"], "vlans": [],
            "native_vlan": None,
            "unmanaged": a_node["device_id"] is None or b_node["device_id"] is None,
            "seen_ts": row["added_ts"],
            "plan": {"mode": "manual", "width": width_min, "strands": [],
                    "known": False, "vlan_count": 0, "vlans": [], "label_step": 0.0},
        })


def get_mapper_map(service, params, body, map_id) -> dict:
    """The whole drawing: this map's own placements, resolved against
    nodesdb's live device/neighbour/VLAN data through mapper.assemble_links
    and mapper.render_plan. Nothing here is cached across requests -- see
    the module comment above."""
    map_row = _require(service.mapper_db.map_row(map_id), "map")
    node_rows = service.mapper_db.nodes(map_id)

    device_ids = [row["device_id"] for row in node_rows if row["device_id"] is not None]
    # devices_by_ids, not devices(): this map's placements are a handful of
    # ids out of a fleet that can run to thousands, and devices_by_ids exists
    # for exactly this "many known ids, one indexed read" shape (see its own
    # docstring) rather than pulling every device in the fleet to resolve a
    # dozen placements.
    devices_by_id = {row["id"]: row for row in service.nodes_db.devices_by_ids(device_ids)}
    dns_names = service.app_db.hostnames(row["ip"] for row in devices_by_id.values())

    settings = service.mapper_settings
    badge_temp = bool(settings.get("badge_temp"))
    badge_cpu = bool(settings.get("badge_cpu"))
    badge_ports = bool(settings.get("badge_ports"))

    # metrics_for_devices, not metrics_for_keys (the alert engine's
    # fleet-wide read) -- bounded to devices this map places.
    temp_by_device: dict = {}
    cpu_by_device: dict = {}
    metric_keys = [key for key, on in
                   (("temp_chassis_c", badge_temp), ("cpu_pct", badge_cpu)) if on]
    if metric_keys:
        for row in service.nodes_db.metrics_for_devices(device_ids, metric_keys):
            target = temp_by_device if row["key"] == "temp_chassis_c" else cpu_by_device
            target[row["device_id"]] = row["last_value"]
    # One grouped COUNT for the map, not an interfaces() read per device.
    # Defaulted to 0, not absent: a device with no interfaces drew "0p".
    port_count_by_device: dict = {}
    if badge_ports:
        counted = service.nodes_db.interface_counts(device_ids)
        port_count_by_device = {device_id: counted.get(device_id, 0)
                                for device_id in device_ids}

    now = time.time()
    stale_hours = float(settings.get("stale_link_hours", 24.0))
    stale_after_s = (stale_hours * 3600.0) if stale_hours > 0 else None
    links, peers, vlan_ports = _mapper_assemble(
        service, device_ids, node_rows, now, stale_after_s)

    color_overrides = service.mapper_db.vlan_colors()
    threshold = int(settings.get("vlan_collapse_threshold", 8))
    max_strands = int(settings.get("max_strand_vlans", 30))
    width_min = float(settings.get("link_width_min", 1.5))
    width_max = float(settings.get("link_width_max", 14.0))
    # FiberView + STP: one read for every on-map device's per-port media,
    # optic mode and STP state, then a pure lookup per link -- neither
    # mapper.link_is_fiber nor mapper.fiber_mode ever touches the db.
    link_facts = service.nodes_db.interface_link_facts_for_devices(device_ids)
    for link in links:
        # Each end's own vlan_ports row (never the far end's -- same
        # locality rule _mapper_vlan_ports' docstring gives port_vlans):
        # the device-reported trunk/access mode and, for a trunk, its
        # native VLAN -- a stronger source than the link's own
        # `native_vlan`, which mapper.assemble_links only derives from
        # port_vlans.tagged and only ever from the a side. b_* stays None
        # for an unmanaged peer (no b_device_id) or a matched row with no
        # far-end if_index (see mapper.assemble_links).
        a_info = vlan_ports.get((link["a_device_id"], link["a_if_index"]))
        link["a_port_mode"] = a_info["mode"] if a_info else None
        link["a_native_vlan"] = a_info["native_vlan"] if a_info else None
        b_info = None
        if link["b_device_id"] is not None and link["b_if_index"] is not None:
            b_info = vlan_ports.get((link["b_device_id"], link["b_if_index"]))
        link["b_port_mode"] = b_info["mode"] if b_info else None
        link["b_native_vlan"] = b_info["native_vlan"] if b_info else None
        a_facts = link_facts.get((link["a_device_id"], link["a_if_index"])) \
            if link["a_if_index"] is not None else None
        b_facts = None
        if link["b_device_id"] is not None and link["b_if_index"] is not None:
            b_facts = link_facts.get((link["b_device_id"], link["b_if_index"]))
        a_media = a_facts["media"] if a_facts else None
        b_media = b_facts["media"] if b_facts else None
        link["a_media"] = a_media
        link["b_media"] = b_media
        link["fiber"] = mapper.link_is_fiber(a_media, b_media)
        a_optic_mode = a_facts["optic_mode"] if a_facts else None
        b_optic_mode = b_facts["optic_mode"] if b_facts else None
        link["a_optic_mode"] = a_optic_mode
        link["b_optic_mode"] = b_optic_mode
        link["fiber_mode"] = (mapper.fiber_mode(a_optic_mode, b_optic_mode)
                              if link["fiber"] else None)
        a_stp = a_facts["stp_state"] if a_facts else None
        b_stp = b_facts["stp_state"] if b_facts else None
        link["a_stp"] = a_stp
        link["b_stp"] = b_stp
        link["a_stp_vlans"] = a_facts["stp_blocking_vlans"] if a_facts else None
        link["b_stp_vlans"] = b_facts["stp_blocking_vlans"] if b_facts else None
        link["blocking"] = a_stp == "blocking" or b_stp == "blocking"
        link["plan"] = mapper.render_plan(
            link, threshold=threshold, max_strands=max_strands,
            width_min=width_min, width_max=width_max,
            color_overrides=color_overrides)

    peers_by_key = {peer["peer_key"]: peer for peer in peers}

    nodes = []
    for row in node_rows:
        device_id = row["device_id"]
        if device_id is None and mapper.is_placeholder(row["peer_key"]):
            # Operator-created logical box: never discovered, never polled,
            # never an unmanaged peer -- its name IS its label, always.
            nodes.append({
                "id": row["id"], "device_id": None, "peer_key": row["peer_key"],
                "label": row["label"], "name": row["label"],
                "resolved_name": row["label"],
                "role": row["role"], "role_auto": False, "x": row["x"], "y": row["y"],
                "status": None, "ip": None, "unmanaged": False, "missing": False,
                "placeholder": True,
                "temp_c": None, "cpu_pct": None, "port_count": None,
            })
            continue
        if device_id is None:
            peer = peers_by_key.get(row["peer_key"])
            name, resolved_name = _mapper_node_name(
                row["label"], peer["name"] if peer else row["peer_key"])
            role, role_auto = _mapper_node_role(row, unmanaged=True)
            nodes.append({
                "id": row["id"], "device_id": None, "peer_key": row["peer_key"],
                "label": row["label"], "name": name, "resolved_name": resolved_name,
                "role": role, "role_auto": role_auto, "x": row["x"], "y": row["y"],
                "status": None, "ip": (peer["address"] if peer else None),
                "unmanaged": True, "missing": False, "placeholder": False,
                "temp_c": None, "cpu_pct": None, "port_count": None,
            })
            continue
        device = devices_by_id.get(device_id)
        if device is None:
            # Placed, then deleted from Nodes entirely (from this device or
            # another browser tab). It must still draw -- silently dropping
            # a node an operator can see is worse than showing it with
            # nothing live left to say -- so it is marked two ways: a
            # `status` value no real device ever has, and a `missing` flag
            # for a client that would rather branch on that than compare
            # strings. There is no device row left to detect a role from,
            # so detect_role sees blanks and reports "" (role_auto True)
            # unless the operator had already overridden it before deletion.
            name, resolved_name = _mapper_node_name(
                row["label"], f"(deleted device #{device_id})")
            role, role_auto = _mapper_node_role(row, unmanaged=False, device=None)
            nodes.append({
                "id": row["id"], "device_id": device_id, "peer_key": "",
                "label": row["label"], "name": name, "resolved_name": resolved_name,
                "role": role, "role_auto": role_auto, "x": row["x"], "y": row["y"],
                "status": "missing", "ip": None, "unmanaged": False,
                "missing": True, "placeholder": False,
                "temp_c": None, "cpu_pct": None, "port_count": None,
            })
            continue
        resolved, name_source = reportmod.device_label(device, dns_names)
        name, resolved_name = _mapper_node_name(row["label"], resolved)
        role, role_auto = _mapper_node_role(row, unmanaged=False, device=device)
        nodes.append({
            "id": row["id"], "device_id": device_id, "peer_key": "",
            "label": row["label"], "name": name, "resolved_name": resolved_name,
            "name_source": name_source,
            "role": role, "role_auto": role_auto, "x": row["x"], "y": row["y"],
            "status": device["status"], "ip": device["ip"], "unmanaged": False,
            "missing": False, "placeholder": False,
            "temp_c": temp_by_device.get(device_id) if badge_temp else None,
            "cpu_pct": cpu_by_device.get(device_id) if badge_cpu else None,
            "port_count": port_count_by_device.get(device_id) if badge_ports else None,
        })

    _mapper_add_manual_links(service, map_id, node_rows, links, width_min)

    frames = [
        {"id": row["id"], "label": row["label"], "x": row["x"], "y": row["y"],
         "width": row["width"], "height": row["height"], "color": row["color"],
         "text_size": row["text_size"], "added_ts": row["added_ts"]}
        for row in service.mapper_db.frames(map_id)]

    # Canvas-only, like frames: never fed to mapper.link_csv_rows/the CSV export.
    notes = [
        {"id": row["id"], "node_id": row["node_id"], "text": row["text"],
         "x": row["x"], "y": row["y"], "width": row["width"], "height": row["height"],
         "color": row["color"], "text_size": row["text_size"], "added_ts": row["added_ts"]}
        for row in service.mapper_db.notes(map_id)]

    return {
        "map": _mapper_map_json(map_row),
        "nodes": nodes,
        "links": links,
        "peers": peers,
        "vlans": _mapper_vlans_json(service, links, device_ids, color_overrides),
        "frames": frames,
        "notes": notes,
        "settings": settings,
    }


def post_mapper_map_nodes(service, params, body, map_id) -> dict:
    """Add one device, one unmanaged peer, or one placeholder to the map.
    A placeholder (`"placeholder": true`) ignores device_id/peer_key and
    goes through mapperdb.add_placeholder instead -- otherwise exactly one
    of `device_id`/`peer_key`, exactly what mapperdb.add_node itself
    enforces, so a bad body is a 400 from there rather than a second check
    here that could disagree with it."""
    _require(service.mapper_db.map_row(map_id), "map")
    if body.get("placeholder"):
        label = str(body.get("label", "") or "")
        node_id = service.mapper_db.add_placeholder(
            map_id, label=label,
            x=float(body.get("x", 0.0) or 0.0), y=float(body.get("y", 0.0) or 0.0))
        _audit(service, params, "mapper.node.add", target=str(map_id),
              detail=f"placeholder={label.strip()[:120]}")
        return {"id": node_id}
    device_id = body.get("device_id")
    if device_id is not None:
        device_id = int(device_id)
        _require(service.nodes_db.device(device_id), "device")
    peer_key = str(body.get("peer_key", "") or "")
    node_id = service.mapper_db.add_node(
        map_id, device_id=device_id, peer_key=peer_key,
        label=str(body.get("label", "") or ""), role=str(body.get("role", "") or ""),
        x=float(body.get("x", 0.0) or 0.0), y=float(body.get("y", 0.0) or 0.0))
    _audit(service, params, "mapper.node.add", target=str(map_id),
          detail=(f"device_id={device_id}" if device_id is not None
                 else f"peer_key={peer_key}"))
    return {"id": node_id}


def put_mapper_map_nodes(service, params, body, map_id) -> dict:
    """Bulk position/label/role write -- one call per drag-end or
    align/distribute action, not one call per node moved. Not audited: a
    drag is UI state, not an accountability-worthy change the way adding or
    removing a node from the topology is (see post_mapper_map_nodes and
    delete_mapper_map_node), and an audit line per drag would drown the
    trail in noise nobody would ever want to read back."""
    _require(service.mapper_db.map_row(map_id), "map")
    updates = body.get("updates")
    if not isinstance(updates, list):
        raise ValueError("updates must be a list")
    clean = []
    for item in updates:
        if not isinstance(item, dict) or "id" not in item:
            continue
        entry = {"id": int(item["id"])}
        if "x" in item:
            entry["x"] = float(item["x"])
        if "y" in item:
            entry["y"] = float(item["y"])
        if "label" in item:
            entry["label"] = str(item["label"] or "")
        if "role" in item:
            entry["role"] = str(item["role"] or "")
        clean.append(entry)
    changed = service.mapper_db.update_nodes(map_id, clean)
    return {"changed": changed}


def delete_mapper_map_node(service, params, body, map_id, node_id) -> dict:
    ok = service.mapper_db.remove_node(map_id, node_id)
    if ok:
        _audit(service, params, "mapper.node.remove", target=str(map_id),
              detail=f"node_id={node_id}")
    return {"ok": ok}


def post_mapper_map_links(service, params, body, map_id) -> dict:
    """A manual line an operator draws between two placed nodes -- asserted,
    not learned from LLDP/CDP. Both ends must already be on this map (the
    same rule add_node enforces for device placement); the duplicate check
    runs here, ahead of mapperdb.add_link's own, so a repeat click reports
    409 with the existing pair rather than a generic 400."""
    _require(service.mapper_db.map_row(map_id), "map")
    try:
        a_node_id = int(body.get("a_node_id"))
        b_node_id = int(body.get("b_node_id"))
    except (TypeError, ValueError):
        raise ValueError("a_node_id and b_node_id are required")
    if a_node_id == b_node_id:
        raise ValueError("A manual line needs two different nodes.")
    label = str(body.get("label", "") or "").strip()
    if len(label) > 60:
        raise ValueError("Line label is limited to 60 characters.")
    for existing in service.mapper_db.links(map_id):
        pair = {existing["a_node_id"], existing["b_node_id"]}
        if pair == {a_node_id, b_node_id}:
            raise Conflict("A line already connects these two nodes.",
                          {"link_id": existing["id"]})
    link_id = service.mapper_db.add_link(map_id, a_node_id, b_node_id, label)
    _audit(service, params, "mapper.link", target=str(map_id),
          detail=f"a_node_id={a_node_id} b_node_id={b_node_id}")
    return {"id": link_id}


def delete_mapper_map_link(service, params, body, map_id, link_id) -> dict:
    ok = service.mapper_db.delete_link(map_id, link_id)
    if ok:
        _audit(service, params, "mapper.link.remove", target=str(map_id),
              detail=f"link_id={link_id}")
    return {"ok": ok}


_FRAME_UPDATE_FIELDS = ("label", "x", "y", "width", "height", "color", "text_size")


def post_mapper_map_frames(service, params, body, map_id) -> dict:
    """A labelled rectangle dropped on the map for visual grouping only --
    decoration, never a device placement, so this never touches map_nodes.
    add_frame itself raises ValueError, with an operator-readable message,
    for a bad size/color/label; left to surface unchanged."""
    _require(service.mapper_db.map_row(map_id), "map")
    label = body.get("label", "")
    if label is not None and not isinstance(label, str):
        raise ValueError("Frame label must be text.")
    try:
        x, y = float(body.get("x")), float(body.get("y"))
        width, height = float(body.get("width")), float(body.get("height"))
        color = body.get("color", 0) or 0
        if isinstance(color, bool) or not isinstance(color, (int, float)):
            raise ValueError  # not a number at all
        if isinstance(color, float):
            if not math.isfinite(color) or not color.is_integer():
                raise ValueError  # e.g. 2.9, nan, inf
            color = int(color)
    except (TypeError, ValueError):
        raise ValueError("x, y, width, height and color must be numbers.")
    frame_id = service.mapper_db.add_frame(
        map_id, x=x, y=y, width=width, height=height,
        label=(label or ""), color=color)
    _audit(service, params, "mapper.frame", target=str(map_id),
          detail=f"frame_id={frame_id}")
    return {"id": frame_id}


def put_mapper_map_frame(service, params, body, map_id, frame_id) -> dict:
    """Position/size writes happen on every drag and are not audited, same
    as put_mapper_map_nodes; a label, color or text_size change is an
    accountability-worthy edit an operator made on purpose, so that alone
    is audited."""
    _require(service.mapper_db.map_row(map_id), "map")
    fields = _pick(body, _FRAME_UPDATE_FIELDS)
    if not fields:
        raise ValueError("No frame fields to update.")
    ok = service.mapper_db.update_frame(map_id, frame_id, **fields)
    if ok and ("label" in fields or "color" in fields or "text_size" in fields):
        _audit(service, params, "mapper.frame.update", target=str(map_id),
              detail=f"frame_id={frame_id}")
    return {"ok": ok}


def delete_mapper_map_frame(service, params, body, map_id, frame_id) -> dict:
    ok = service.mapper_db.delete_frame(map_id, frame_id)
    if ok:
        _audit(service, params, "mapper.frame.remove", target=str(map_id),
              detail=f"frame_id={frame_id}")
    return {"ok": ok}


_NOTE_UPDATE_FIELDS = ("text", "x", "y", "width", "height", "color", "text_size")


def post_mapper_map_notes(service, params, body, map_id) -> dict:
    """A thought-bubble annotation dropped on the map for operator commentary
    only -- decoration, never a device placement, same as a frame -- with an
    optional node_id anchor: the operator's own choice at creation (exactly
    one node selected), never re-derived here. add_note itself raises
    ValueError, with an operator-readable message, for a bad size/color/
    text/anchor; left to surface unchanged."""
    _require(service.mapper_db.map_row(map_id), "map")
    text = body.get("text", "")
    if text is not None and not isinstance(text, str):
        raise ValueError("Note text must be text.")
    node_id = body.get("node_id")
    if node_id is not None:
        try:
            node_id = int(node_id)
        except (TypeError, ValueError):
            raise ValueError("node_id must be an integer.")
    try:
        x, y = float(body.get("x")), float(body.get("y"))
        width, height = float(body.get("width")), float(body.get("height"))
        color = body.get("color", 0) or 0
        if isinstance(color, bool) or not isinstance(color, (int, float)):
            raise ValueError  # not a number at all
        if isinstance(color, float):
            if not math.isfinite(color) or not color.is_integer():
                raise ValueError  # e.g. 2.9, nan, inf
            color = int(color)
    except (TypeError, ValueError):
        raise ValueError("x, y, width, height and color must be numbers.")
    note_id = service.mapper_db.add_note(
        map_id, x=x, y=y, width=width, height=height,
        text=(text or ""), color=color, node_id=node_id)
    _audit(service, params, "mapper.note", target=str(map_id),
          detail=f"note_id={note_id}")
    return {"id": note_id}


def put_mapper_map_note(service, params, body, map_id, note_id) -> dict:
    """Position/size writes happen on every drag and are not audited, same
    as put_mapper_map_frame; a text, color or text_size change is audited.
    The anchor itself is never accepted here -- see post_mapper_map_notes'
    docstring."""
    _require(service.mapper_db.map_row(map_id), "map")
    fields = _pick(body, _NOTE_UPDATE_FIELDS)
    if not fields:
        raise ValueError("No note fields to update.")
    ok = service.mapper_db.update_note(map_id, note_id, **fields)
    if ok and ("text" in fields or "color" in fields or "text_size" in fields):
        _audit(service, params, "mapper.note.update", target=str(map_id),
              detail=f"note_id={note_id}")
    return {"ok": ok}


def delete_mapper_map_note(service, params, body, map_id, note_id) -> dict:
    ok = service.mapper_db.delete_note(map_id, note_id)
    if ok:
        _audit(service, params, "mapper.note.remove", target=str(map_id),
              detail=f"note_id={note_id}")
    return {"ok": ok}


def get_mapper_map_candidates(service, params, body, map_id) -> dict:
    """What "Add device" and "Add neighbours" both offer: every device not
    already on this map, and separately -- for neighbours -- only what
    LLDP/CDP has actually seen adjacent to a device this map already has,
    each carrying which placed device saw it and on which of THAT device's
    own ports. A device or peer can appear in both lists; that is not a bug
    to dedupe away, it is the difference between browsing the whole fleet
    and being offered what is actually cabled to what is already here."""
    _require(service.mapper_db.map_row(map_id), "map")
    node_rows = service.mapper_db.nodes(map_id)
    placed_device_ids = {row["device_id"] for row in node_rows if row["device_id"] is not None}
    placed_peer_keys = {row["peer_key"] for row in node_rows if row["peer_key"]}

    # device_summaries(), not devices()'s SELECT * (forty-odd columns) for
    # every device in the fleet.
    devices = [
        {"id": d["id"], "name": namelookup.device_name(d), "ip": d["ip"],
         "status": d["status"], "vendor": d["vendor"]}
        for d in service.nodes_db.device_summaries() if d["id"] not in placed_device_ids]

    # Only placed devices' ports are ever labelled below, so this prefetch
    # set is exactly right.
    port_label = _neighbor_local_port_labeler(service, prefetch_ids=placed_device_ids)
    seen_devices: set = set()
    seen_peers: set = set()
    neighbours = []
    # neighbours_for_devices, not all_neighbours(): every row this loop can
    # possibly use has already been filtered to device_id in
    # placed_device_ids below, so asking nodesdb for exactly that set of
    # devices' rows -- not the whole fleet -- returns the same rows without
    # the fleet-wide join cost get_mapper_map's own report measured.
    #
    # _apply_ip_matches, the same helper get_mapper_map uses, so a
    # candidate LLDP/CDP only placed a Nodes device by address (not
    # sysName or chassis MAC) is offered as "kind": "device" here too.
    candidate_rows = _apply_ip_matches(
        service, service.nodes_db.neighbours_for_devices(placed_device_ids))
    peer_name = _mapper_peer_name(service, candidate_rows)
    for row in candidate_rows:
        if row["device_id"] not in placed_device_ids or not row["present"]:
            continue
        if row["protocol"] not in mapper.LINK_PROTOCOLS:
            continue
        local_port = port_label(row["device_id"], row["if_index"])
        matched_id = row["matched_device_id"]
        if matched_id is not None:
            if matched_id in placed_device_ids or matched_id in seen_devices:
                continue
            seen_devices.add(matched_id)
            neighbours.append({
                "kind": "device", "device_id": matched_id,
                "name": row["matched_device_name"] or "",
                "seen_from_device_id": row["device_id"], "seen_from_port": local_port,
            })
        else:
            peer_key = mapper.peer_identity(row)
            if peer_key in placed_peer_keys or peer_key in seen_peers:
                continue
            seen_peers.add(peer_key)
            neighbours.append({
                "kind": "peer", "peer_key": peer_key,
                "name": peer_name(row) or peer_key,
                "platform": row["platform"] or "", "address": row["remote_address"] or "",
                "seen_from_device_id": row["device_id"], "seen_from_port": local_port,
            })
    return {"devices": devices, "neighbours": neighbours}


def get_mapper_map_export(service, params, body, map_id) -> dict:
    """CSV of this map's links -- built on top of get_mapper_map rather than
    re-running link assembly a second way, so the export can never disagree
    with what the drawing itself shows."""
    payload = get_mapper_map(service, params, body, map_id)
    names = {node["device_id"]: node["name"] for node in payload["nodes"]
             if node["device_id"] is not None}
    peer_names = {node["peer_key"]: node["name"] for node in payload["nodes"]
                  if node["device_id"] is None}

    def device_name(device_id) -> str:
        return names.get(device_id) or f"Device {device_id}"

    def peer_name(peer_key) -> str:
        return peer_names.get(peer_key) or peer_key

    rows = mapper.link_csv_rows(payload["links"], device_name, peer_name)
    return _csv_response("mapper-links", mapper.LINK_CSV_HEADER, rows)


def post_mapper_vlan_color(service, params, body) -> dict:
    """Set (or, with color_index omitted/null, clear) one VLAN's colour
    override -- global, not per-map, see mapperdb.vlan_colors' own
    docstring for why."""
    if "vlan" not in body:
        raise ValueError("vlan is required")
    vlan = int(body["vlan"])
    color_index = body.get("color_index")
    if color_index is not None:
        color_index = int(color_index)
        if not (0 <= color_index < mapper.VLAN_PALETTE_SIZE):
            raise ValueError(
                f"color_index must be between 0 and {mapper.VLAN_PALETTE_SIZE - 1}")
    service.mapper_db.set_vlan_color(vlan, color_index)
    _audit(service, params, "mapper.vlan_color.set", target=str(vlan),
          detail=f"color_index={color_index}")
    return {"ok": True}
