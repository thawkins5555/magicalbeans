"""MAPPER: the manually-built L2 map's web API. Everything goes through a
real `Service` and `WebServer` over loopback HTTP with real sessions and
permission checks, the same shape test_alerts_api.py uses -- the questions
here are about the wire format, who may do what, and whether the link
assembly (netpath/mapper.py) reached the API the way the map itself expects.
"""
import csv
import http.client
import io
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import mapper as mapper_mod
from netpath import mapperdb
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("mapper_api_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path,
                 body=json.dumps(body).encode() if body is not None else None,
                 headers=headers)
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    try:
        return response.status, json.loads(raw)
    except ValueError:
        return response.status, raw


def login(username, password):
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    conn.request("POST", "/api/login",
                 body=json.dumps({"username": username,
                                  "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # A read-only account (mapper:read) and one with no mapper grant at all,
    # for the permission checks at the bottom.
    status, payload = call("POST", "/api/users",
                           {"username": "viewer",
                            "password": "Corr3ct-Horse-Battery",
                            "grants": {"mapper": "read", "alerts": "read"}},
                           token=admin)
    assert status == 200, (status, payload)
    viewer = login("viewer", "Corr3ct-Horse-Battery")

    status, payload = call("POST", "/api/users",
                           {"username": "outsider",
                            "password": "Corr3ct-Horse-Battery",
                            "grants": {"nodes": "read"}},
                           token=admin)
    assert status == 200, (status, payload)
    outsider = login("outsider", "Corr3ct-Horse-Battery")

    # -------------------------------------------------- fleet fixture
    #
    # Two real devices (A speaks LLDP to B, matched by sysName so no MAC
    # gymnastics are needed) plus a third the map never learns anything
    # about, and one CDP/LLDP row from A that matches no device at all --
    # the unmanaged-peer case.
    gid = service.nodes_db.ensure_default_group()
    dev_a = service.nodes_db.add_device("192.0.2.10", name="Switch A", group_id=gid)
    dev_b = service.nodes_db.add_device("192.0.2.11", name="Switch B", group_id=gid)
    dev_c = service.nodes_db.add_device("192.0.2.12", name="Switch C", group_id=gid)
    dev_ghost = service.nodes_db.add_device("192.0.2.13", name="Switch Ghost", group_id=gid)

    service.nodes_db.replace_interfaces(dev_a, [
        {"if_index": 1, "descr": "Gi0/1", "alias": "to-b",
         "admin_status": "up", "oper_status": "up"}])
    service.nodes_db.replace_interfaces(dev_b, [
        {"if_index": 2, "descr": "Gi0/2", "alias": "to-a",
         "admin_status": "up", "oper_status": "up"}])

    service.nodes_db.replace_port_vlans(dev_a, [
        {"if_index": 1, "vlan": 10, "tagged": True},
        {"if_index": 1, "vlan": 20, "tagged": True}])

    service.nodes_db.replace_neighbors(dev_a, [
        # Matched, by sysName, to Switch B -- a real device-to-device link.
        {"if_index": 1, "protocol": "lldp", "rem_index": "1",
         "chassis_id": "", "sys_name": "Switch B", "port_id": "Gi0/2",
         "port_descr": "Gi0/2"},
        # Matches nothing on file: an unmanaged peer.
        {"if_index": 1, "protocol": "lldp", "rem_index": "2",
         "chassis_id": "aa:bb:cc:00:11:22", "sys_name": "",
         "platform": "Some AP", "port_id": "eth0", "remote_address": "192.0.2.200"},
    ])
    # B's own neighbour row, matched to Switch C -- so once A and B are both
    # placed but C is not, "candidates" for this map has someone to offer
    # under "neighbours" (seen from B) that isn't already on it.
    service.nodes_db.replace_neighbors(dev_b, [
        {"if_index": 3, "protocol": "lldp", "rem_index": "1",
         "chassis_id": "", "sys_name": "Switch C", "port_id": "Gi0/1",
         "port_descr": "Gi0/1"},
    ])

    # dev_a gets a resolvable identity so MAPPER's role auto-detection
    # (Gap 1) has something to detect from. A FortiGate sysDescr is used
    # deliberately: Fortinet also sells FortiSwitch/FortiAP under the same
    # vendor key, so this pins the "vendor alone is not enough" case
    # test_mapper_links.py's detect_role section covers at the unit level.
    service.nodes_db.seed_identity(
        dev_a, sys_descr="FortiGate-100F v7.0.1,build0157 (GA)",
        sys_object_id="1.3.6.1.4.1.12356.101.1.2", vendor="fortinet")

    # ------------------------------------------------- 1. maps CRUD

    status, payload = call("GET", "/api/mapper/maps", token=admin)
    check("no maps yet", status == 200 and payload["maps"] == [], (status, payload))
    check("...and settings ride along", status == 200 and "settings" in payload, payload)

    status, payload = call("POST", "/api/mapper/maps", {"name": "Site A"}, token=admin)
    check("creating a map is accepted", status == 200 and "id" in payload, (status, payload))
    map_id = payload["id"]

    status, payload = call("POST", "/api/mapper/maps", {"name": "Site A"}, token=admin)
    check("a duplicate name is a 400 with a readable message",
          status == 400 and "Site A" in str(payload), (status, payload))

    status, payload = call("GET", "/api/mapper/maps", token=admin)
    check("the list now shows one map with a node_count",
          status == 200 and len(payload["maps"]) == 1
          and payload["maps"][0]["node_count"] == 0, (status, payload))

    status, payload = call("PUT", f"/api/mapper/maps/{map_id}",
                           {"name": "Site A - Main"}, token=admin)
    check("renaming a map is accepted", status == 200, (status, payload))
    status, payload = call("GET", "/api/mapper/maps", token=admin)
    check("...and it stuck", payload["maps"][0]["name"] == "Site A - Main", payload)

    # ------------------------------------------------- 2. an empty map is not an error

    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    check("a map with nothing on it returns 200 with empty lists",
          status == 200 and payload["nodes"] == [] and payload["links"] == []
          and payload["peers"] == [] and payload["vlans"] == [], (status, payload))

    # ------------------------------------------------- 3. add A alone first

    status, payload = call("POST", f"/api/mapper/maps/{map_id}/nodes",
                           {"device_id": dev_a, "x": 10, "y": 20}, token=admin)
    check("adding a device node is accepted", status == 200 and "id" in payload,
          (status, payload))
    node_a = payload["id"]

    # --------------------------------------- 4. link needs BOTH ends placed

    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    check("with only A placed, no link draws yet (neither B nor the peer is on the map)",
          status == 200 and payload["links"] == [], (status, payload))
    check("...but the unplaced peer A has seen still appears under peers",
          status == 200 and any(p["peer_key"] == "chassis:aa:bb:cc:00:11:22"
                                for p in payload["peers"]),
          (status, payload))

    status, payload = call("POST", f"/api/mapper/maps/{map_id}/nodes",
                           {"device_id": dev_b, "x": 100, "y": 20}, token=admin)
    check("adding the far end device is accepted", status == 200, (status, payload))
    node_b = payload["id"]

    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    check("now both ends are placed, the A-B link draws",
          status == 200 and len(payload["links"]) == 1, (status, payload))
    link = payload["links"][0] if status == 200 and payload["links"] else {}
    check("...carrying the VLANs A's port reported",
          sorted(link.get("vlans", [])) == [10, 20], link)
    check("...and a render plan from mapper.render_plan",
          link.get("plan", {}).get("mode") in ("strands", "collapsed", "plain"), link)
    check("the VLAN summary lists both VLANs with a link_count of 1 so far",
          status == 200 and {v["vlan"] for v in payload["vlans"]} == {10, 20}
          and all(v["link_count"] == 1 for v in payload["vlans"]), payload)
    check("nodes carry status/ip for a real device",
          status == 200 and next(n for n in payload["nodes"] if n["id"] == node_a)["ip"]
          == "192.0.2.10", payload)
    node_a_json = next(n for n in payload["nodes"] if n["id"] == node_a)
    check("a node with no role override reports a role detected from its "
          "vendor/sysDescr (Gap 1)", node_a_json.get("role") == "firewall", node_a_json)
    check("...and role_auto is True when the operator has not overridden it",
          node_a_json.get("role_auto") is True, node_a_json)
    check("every node's role is a member of mapperdb.ROLES",
          all(n["role"] in mapperdb.ROLES for n in payload["nodes"]), payload["nodes"])
    check("...and the still-unplaced peer keeps showing under peers, not as a node",
          status == 200 and all(n["device_id"] != dev_b or n["id"] == node_b
                                for n in payload["nodes"])
          and any(p["peer_key"] == "chassis:aa:bb:cc:00:11:22" for p in payload["peers"]),
          payload)

    # Now place the peer too: a SECOND link (A to the peer) appears, on top
    # of the A-B one above, and the node resolves its name from the same
    # peer info assemble_links already derived.
    status, payload = call("POST", f"/api/mapper/maps/{map_id}/nodes",
                           {"peer_key": "chassis:aa:bb:cc:00:11:22", "label": "AP by the door"},
                           token=admin)
    check("adding a peer node is accepted", status == 200 and "id" in payload,
          (status, payload))
    node_peer = payload["id"]

    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    check("placing the peer adds its own link without losing the A-B one",
          status == 200 and len(payload["links"]) == 2, (status, payload))
    node_peer_json = next(n for n in payload["nodes"] if n["id"] == node_peer)
    check("a node given a label (Gap 2) reports that label as its name, "
          "not the resolved peer identity", node_peer_json["name"] == "AP by the door",
          node_peer_json)
    check("...while still exposing the resolved identity separately, so the "
          "UI can say 'renamed from ...'",
          node_peer_json["resolved_name"] == "Some AP", node_peer_json)

    # -------------------------------------------- 5. bulk move + remove

    status, payload = call("PUT", f"/api/mapper/maps/{map_id}/nodes",
                           {"updates": [{"id": node_a, "x": 5, "y": 5,
                                        "label": "Core Switch A", "role": "server"},
                                       {"id": node_b, "x": 200, "y": 5}]},
                           token=admin)
    check("bulk position write is accepted", status == 200 and payload["changed"] == 2,
          (status, payload))

    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    moved = next(n for n in payload["nodes"] if n["id"] == node_a)
    check("...and the position actually moved", moved["x"] == 5 and moved["y"] == 5, moved)
    check("setting a role override (Gap 1) reports it back with role_auto False",
          moved["role"] == "server" and moved["role_auto"] is False, moved)
    check("...and a label (Gap 2) overrides the resolved name as `name`, "
          "while `resolved_name` still carries the original identity",
          moved["name"] == "Core Switch A" and moved["resolved_name"] == "Switch A", moved)

    # -------------------------------------------------- 5b. CSV honors a label
    #
    # export.csv must agree with the drawing: an operator-renamed node's
    # label, not its original Nodes name, should appear as the CSV's device
    # name -- Gap 2 again, this time through mapper.link_csv_rows's
    # device_name callable rather than the node dict directly.
    status, payload = call("GET", f"/api/mapper/maps/{map_id}/export.csv", token=admin)
    csv_rows_labeled = (list(csv.reader(io.StringIO(payload["csv"].lstrip("﻿"))))
                       if status == 200 else [])
    a_rows = [r for r in csv_rows_labeled if r and r[1] == str(dev_a)]
    check("the CSV export uses a node's label, not its original device name",
          bool(a_rows) and all(r[0] == "Core Switch A" for r in a_rows), csv_rows_labeled)

    status, payload = call("DELETE", f"/api/mapper/maps/{map_id}/nodes/{node_peer}",
                           token=admin)
    check("removing a node is accepted", status == 200 and payload["ok"], (status, payload))
    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    check("...and it is gone", status == 200 and
          all(n["id"] != node_peer for n in payload["nodes"]), payload)

    # -------------------------------------------------- 6. candidates

    status, payload = call("GET", f"/api/mapper/maps/{map_id}/candidates", token=admin)
    device_ids = {d["id"] for d in payload.get("devices", [])} if status == 200 else set()
    check("candidates excludes devices already on the map",
          status == 200 and dev_a not in device_ids and dev_b not in device_ids,
          (status, device_ids))
    check("...and includes an unplaced device", dev_c in device_ids, device_ids)
    neighbours = payload.get("neighbours", []) if status == 200 else []
    neighbour_device_ids = {n.get("device_id") for n in neighbours if n.get("kind") == "device"}
    check("candidates' neighbours include what a placed device has actually seen",
          dev_c in neighbour_device_ids, neighbours)
    check("...but not a neighbour that is already placed",
          dev_b not in neighbour_device_ids, neighbours)
    seen_from = next((n["seen_from_device_id"] for n in neighbours
                      if n.get("device_id") == dev_c), None)
    check("...and says which placed device saw it", seen_from == dev_b, neighbours)

    # ------------------------------------------------------ 7. export.csv

    status, payload = call("GET", f"/api/mapper/maps/{map_id}/export.csv", token=admin)
    csv_rows = (list(csv.reader(io.StringIO(payload["csv"].lstrip("﻿"))))
               if status == 200 else [])
    check("export.csv answers 200 with the mapper CSV header",
          status == 200 and csv_rows and csv_rows[0] == mapper_mod.LINK_CSV_HEADER,
          (status, csv_rows[:1] if csv_rows else payload))
    check("...with one data row per link", len(csv_rows) == 2, csv_rows)

    # ---------------------------------------- 8. a device deleted from Nodes

    status, payload = call("POST", f"/api/mapper/maps/{map_id}/nodes",
                           {"device_id": dev_ghost}, token=admin)
    check("placing the soon-to-be-deleted device works", status == 200, (status, payload))
    ghost_node_id = payload.get("id")
    service.nodes_db.remove_device(dev_ghost)

    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    ghost_node = (next((n for n in payload["nodes"] if n["id"] == ghost_node_id), None)
                 if status == 200 else None)
    check("a node whose device vanished from Nodes still returns, not a 500",
          status == 200 and ghost_node is not None, (status, payload))
    check("...clearly marked rather than looking like a live device",
          ghost_node is not None and ghost_node.get("missing") is True
          and ghost_node.get("status") != "up", ghost_node)
    check("...and, with no device row left to detect a role from, reports "
          "'' rather than guessing", ghost_node is not None
          and ghost_node.get("role") == "" and ghost_node.get("role_auto") is True,
          ghost_node)

    # -------------------------------------------------- 9. vlan colour

    status, payload = call("POST", "/api/mapper/vlan-color",
                           {"vlan": 10, "color_index": 3}, token=admin)
    check("setting a VLAN colour override is accepted", status == 200, (status, payload))
    status, payload = call("POST", "/api/mapper/vlan-color",
                           {"vlan": 10, "color_index": None}, token=admin)
    check("...and clearing it is accepted too", status == 200, (status, payload))
    status, payload = call("POST", "/api/mapper/vlan-color",
                           {"vlan": 10, "color_index": 999}, token=admin)
    check("an out-of-range colour index is a 400", status == 400, (status, payload))

    # ------------------------------------------------------ 10. delete map

    status, payload = call("POST", "/api/mapper/maps", {"name": "Throwaway"}, token=admin)
    throwaway_id = payload["id"]
    status, payload = call("DELETE", f"/api/mapper/maps/{throwaway_id}", token=admin)
    check("deleting a map is accepted", status == 200 and payload["ok"], (status, payload))
    status, payload = call("GET", f"/api/mapper/maps/{throwaway_id}", token=admin)
    check("...and it is really gone", status == 400, (status, payload))

    # -------------------------------------------------- 11. settings

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper", "values": {"vlan_collapse_threshold": 0}},
                           token=admin)
    check("vlan_collapse_threshold below 1 is a 400", status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper", "values": {"vlan_collapse_threshold": 31}},
                           token=admin)
    check("vlan_collapse_threshold above 30 is a 400", status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper", "values": {"map_style": "neon"}},
                           token=admin)
    check("an unknown map_style is a 400", status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper",
                            "values": {"vlan_collapse_threshold": 12, "map_style": "blueprint"}},
                           token=admin)
    check("a valid mapper settings write is accepted", status == 200, (status, payload))

    status, payload = call("GET", "/api/config", token=admin)
    check("...and round-trips through /api/config",
          status == 200
          and payload["mapper_settings"]["vlan_collapse_threshold"] == 12
          and payload["mapper_settings"]["map_style"] == "blueprint", (status, payload))

    # ---------------------------------------------------- 12. permissions

    status, payload = call("GET", "/api/mapper/maps", token=viewer)
    check("a read-only account can list maps", status == 200, (status, payload))
    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=viewer)
    check("...and read one", status == 200, (status, payload))

    status, payload = call("POST", "/api/mapper/maps", {"name": "Nope"}, token=viewer)
    check("...but not create one", status == 403, (status, payload))
    status, payload = call("PUT", f"/api/mapper/maps/{map_id}", {"name": "Nope"}, token=viewer)
    check("...nor rename one", status == 403, (status, payload))
    status, payload = call("DELETE", f"/api/mapper/maps/{map_id}", token=viewer)
    check("...nor delete one", status == 403, (status, payload))
    status, payload = call("POST", f"/api/mapper/maps/{map_id}/nodes",
                           {"device_id": dev_c}, token=viewer)
    check("...nor add a node", status == 403, (status, payload))

    status, payload = call("GET", "/api/mapper/maps", token=outsider)
    check("an account with no mapper grant is refused even a read",
          status == 403, (status, payload))
    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=outsider)
    check("...on the single-map route too", status == 403, (status, payload))

    # ------------------------------------------------- 13. device thresholds

    status, payload = call("POST", "/api/alerts/device-thresholds",
                           {"device_id": dev_a, "rule_key": "temp_chassis_high",
                            "threshold": 80.0, "clear_threshold": 70.0}, token=admin)
    check("setting a device threshold override is accepted", status == 200, (status, payload))

    status, payload = call("GET", f"/api/alerts/device-thresholds?device_id={dev_a}",
                           token=admin)
    rows = payload.get("device_thresholds", []) if status == 200 else []
    check("...and reads back with the numbers given",
          status == 200 and len(rows) == 1 and rows[0]["threshold"] == 80.0
          and rows[0]["rule_key"] == "temp_chassis_high", (status, payload))

    status, payload = call("POST", "/api/alerts/device-thresholds",
                           {"device_id": dev_a, "rule_key": "temp_chassis_high",
                            "clear": True}, token=admin)
    check("clearing it is accepted and reports it removed",
          status == 200 and payload.get("removed") is True, (status, payload))
    status, payload = call("GET", f"/api/alerts/device-thresholds?device_id={dev_a}",
                           token=admin)
    check("...and it is really gone",
          status == 200 and payload.get("device_thresholds") == [], (status, payload))

    status, payload = call("POST", "/api/alerts/device-thresholds",
                           {"device_id": dev_a, "rule_key": "not_a_real_rule",
                            "threshold": 1.0, "clear_threshold": 0.0}, token=admin)
    check("an unknown rule_key is a 400", status == 400, (status, payload))

    status, payload = call("GET", "/api/alerts/device-thresholds", token=viewer)
    check("a read-only alerts account can still read device thresholds",
          status == 200, (status, payload))

    # -------------------------------------------------- 14. bounded reads (Finding 4)
    #
    # get_mapper_map and get_mapper_map_candidates used to call
    # nodesdb.all_neighbours()/all_port_vlans()/all_vlans() -- the WHOLE
    # fleet -- to draw a map that might place two devices.
    # neighbours_for_devices/port_vlans_for_devices/vlans_for_devices/
    # vlan_ports_for_devices exist so the cost is bounded by what a map
    # actually places. First, directly: placing (asking for) two devices
    # must not read a third device's own rows. dev_c gets neighbour/VLAN
    # rows of its own here purely as that third device.
    service.nodes_db.replace_neighbors(dev_c, [
        {"if_index": 9, "protocol": "lldp", "rem_index": "1",
         "chassis_id": "", "sys_name": "Nobody Placed Me", "port_id": "Gi0/9",
         "port_descr": "Gi0/9"}])
    service.nodes_db.replace_port_vlans(dev_c, [{"if_index": 9, "vlan": 77, "tagged": True}])
    service.nodes_db.replace_vlans(dev_c, [{"vlan": 77, "name": "Should Not Appear On Map"}])
    service.nodes_db.replace_vlan_ports(
        dev_c, [{"if_index": 9, "mode": "trunk", "native_vlan": 77}])
    # dev_a/dev_b get vlans/vlan_ports rows of their own here too, purely so
    # the bounded-vs-fleet-wide checks below have something of THEIRS to
    # find; section 14b re-establishes (and extends) this same data for the
    # route-level checks further down.
    service.nodes_db.replace_vlans(dev_a, [{"vlan": 10, "name": "Printers"}])
    service.nodes_db.replace_vlan_ports(
        dev_a, [{"if_index": 1, "mode": "trunk", "native_vlan": 10}])

    bounded_neighbours = service.nodes_db.neighbours_for_devices([dev_a, dev_b])
    check("neighbours_for_devices for two devices excludes a third device's own rows",
          bool(bounded_neighbours)
          and all(r["device_id"] != dev_c for r in bounded_neighbours), bounded_neighbours)
    with_c_neighbours = service.nodes_db.neighbours_for_devices([dev_a, dev_b, dev_c])
    check("...but does include it once that third device is actually asked for",
          any(r["device_id"] == dev_c for r in with_c_neighbours), with_c_neighbours)
    check("neighbours_for_devices([]) returns [] without touching the database",
          service.nodes_db.neighbours_for_devices([]) == [])

    bounded_port_vlans = service.nodes_db.port_vlans_for_devices([dev_a, dev_b])
    check("port_vlans_for_devices for two devices excludes a third device's own rows",
          bool(bounded_port_vlans)
          and all(r["device_id"] != dev_c for r in bounded_port_vlans), bounded_port_vlans)
    with_c_port_vlans = service.nodes_db.port_vlans_for_devices([dev_a, dev_b, dev_c])
    check("...but does include it once that third device is actually asked for",
          any(r["device_id"] == dev_c for r in with_c_port_vlans), with_c_port_vlans)
    check("port_vlans_for_devices([]) returns [] without touching the database",
          service.nodes_db.port_vlans_for_devices([]) == [])

    # vlans_for_devices/vlan_ports_for_devices -- Finding 4(a)/(b)'s new
    # bounded accessors -- get the same two checks: excludes a third
    # device's own rows, includes them once that device is actually asked
    # for, and [] short-circuits without touching the database.
    bounded_vlans = service.nodes_db.vlans_for_devices([dev_a, dev_b])
    check("vlans_for_devices for two devices excludes a third device's own rows",
          bool(bounded_vlans) and all(r["device_id"] != dev_c for r in bounded_vlans),
          bounded_vlans)
    with_c_vlans = service.nodes_db.vlans_for_devices([dev_a, dev_b, dev_c])
    check("...but does include it once that third device is actually asked for",
          any(r["device_id"] == dev_c for r in with_c_vlans), with_c_vlans)
    check("vlans_for_devices([]) returns [] without touching the database",
          service.nodes_db.vlans_for_devices([]) == [])

    bounded_vlan_ports = service.nodes_db.vlan_ports_for_devices([dev_a, dev_b])
    check("vlan_ports_for_devices for two devices excludes a third device's own rows",
          bool(bounded_vlan_ports)
          and all(r["device_id"] != dev_c for r in bounded_vlan_ports), bounded_vlan_ports)
    with_c_vlan_ports = service.nodes_db.vlan_ports_for_devices([dev_a, dev_b, dev_c])
    check("...but does include it once that third device is actually asked for",
          any(r["device_id"] == dev_c for r in with_c_vlan_ports), with_c_vlan_ports)
    check("vlan_ports_for_devices([]) returns [] without touching the database",
          service.nodes_db.vlan_ports_for_devices([]) == [])

    # Second, through the route: disable EVERY fleet-wide nodesdb accessor
    # (every "all_*" method -- the naming convention this codebase's
    # fleet-wide readers all share, see nodesdb.all_neighbours/
    # all_known_oids) and confirm neither GET breaks -- proof the routes
    # never reach ANY of them, not merely the two Finding 4(a)'s reviewer
    # happened to name. Generic on purpose: naming two specific methods is
    # exactly what let a third fleet-wide read (all_vlans, in
    # _mapper_vlans_json) go uncaught last round.
    all_fleet_wide = [name for name in dir(service.nodes_db)
                      if name.startswith("all_") and callable(getattr(service.nodes_db, name))]
    check("at least one fleet-wide accessor exists to guard against",
          len(all_fleet_wide) >= 1, all_fleet_wide)

    def _boom(*_a, **_k):
        raise AssertionError("a map GET reached a fleet-wide nodesdb accessor")
    originals = {name: getattr(service.nodes_db, name) for name in all_fleet_wide}
    for name in all_fleet_wide:
        setattr(service.nodes_db, name, _boom)
    try:
        status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
        check("a map GET never calls any fleet-wide (all_*) nodesdb accessor",
              status == 200, (status, payload))
        status, payload = call("GET", f"/api/mapper/maps/{map_id}/candidates", token=admin)
        check("...and neither does its candidates route",
              status == 200, (status, payload))
    finally:
        for name, orig in originals.items():
            setattr(service.nodes_db, name, orig)

    # -------------------------------------------- 14b. VLAN naming + vlan_ports (Finding 4)
    #
    # _mapper_vlans_json's name comes from vlans_for_devices, bounded to the
    # devices this map places -- dev_c's "Should Not Appear On Map" name for
    # VLAN 77 must never surface here, both because dev_c is unplaced and
    # because VLAN 77 is not carried by any link on this map at all. dev_a's
    # own VLAN 10 name and vlan_ports row were already set up in section 14
    # above (Printers / trunk-native 10); dev_b gets its own vlan_ports row
    # here, independently, so the b_ side below is not dev_a's twice over.
    service.nodes_db.replace_vlan_ports(
        dev_b, [{"if_index": 2, "mode": "access", "native_vlan": 20}])

    # Give the far end (B) a resolvable if_index too: the original A-B
    # neighbour row matches by sysName alone (chassis_id ""), which
    # assemble_links can only label from the raw remote port_id string
    # (matched_if_index stays None -- see mapper.assemble_links) -- exactly
    # the "no b_if_index to look vlan_ports up by" case get_mapper_map's
    # b_port_mode/b_native_vlan legitimately reports as None for. Adding a
    # chassis-MAC match alongside the existing sysName one (both now agree
    # on dev_b, so matched_device_id/matched_device_name are unchanged) is
    # what lets the far end's OWN if_index resolve, so its vlan_ports row is
    # the one this checks. The still-unmatched peer row is repeated
    # unchanged so it does not age out from this same replace_neighbors call.
    service.nodes_db.replace_interfaces(dev_b, [
        {"if_index": 2, "descr": "Gi0/2", "alias": "to-a", "phys_addr": "aa:bb:cc:00:00:02",
         "admin_status": "up", "oper_status": "up"}])
    service.nodes_db.replace_neighbors(dev_a, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "1",
         "chassis_id": "aa:bb:cc:00:00:02", "chassis_id_subtype": 4, "sys_name": "Switch B",
         "port_id": "Gi0/2", "port_descr": "Gi0/2"},
        {"if_index": 1, "protocol": "lldp", "rem_index": "2",
         "chassis_id": "aa:bb:cc:00:11:22", "sys_name": "",
         "platform": "Some AP", "port_id": "eth0", "remote_address": "192.0.2.200"},
    ])

    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    vlan_10 = next((v for v in payload.get("vlans", []) if v["vlan"] == 10), None) \
        if status == 200 else None
    check("a VLAN named by a placed device shows that name on the map",
          vlan_10 is not None and vlan_10["name"] == "Printers", (status, vlan_10))
    check("VLAN 77 -- named only by the unplaced dev_c -- never appears on this map",
          status == 200 and all(v["vlan"] != 77 for v in payload.get("vlans", [])),
          payload.get("vlans"))

    ab_link = next((l for l in payload.get("links", [])
                    if l.get("a_device_id") == dev_a and l.get("b_device_id") == dev_b),
                   None) if status == 200 else None
    check("the A-B link now resolves a b_if_index (chassis-MAC match added)",
          ab_link is not None and ab_link.get("b_if_index") == 2, (status, ab_link))
    check("the A-B link carries A's own vlan_ports mode/native VLAN",
          ab_link is not None and ab_link.get("a_port_mode") == "trunk"
          and ab_link.get("a_native_vlan") == 10, (status, ab_link))
    check("...and B's own, independently, on the same link (b_ side)",
          ab_link is not None and ab_link.get("b_port_mode") == "access"
          and ab_link.get("b_native_vlan") == 20, (status, ab_link))

    # -------------------------------------------------- 15. VLAN present/staleness (Finding 6)
    #
    # A VLAN a trunk stops carrying must stop drawing at the same clock a
    # dropped/stale neighbour already does, not linger until
    # prune_port_vlans eventually drops the row (mac_table_retention_days,
    # 7 days by default). dev_a/if_index 1 currently reports VLANs 10 and 20
    # (the original fixture); re-walking with only VLAN 10 ages VLAN 20 to
    # present=0.
    service.nodes_db.replace_port_vlans(
        dev_a, [{"if_index": 1, "vlan": 10, "tagged": True}])
    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    ab_link = next((l for l in payload.get("links", [])
                    if l.get("a_device_id") == dev_a and l.get("b_device_id") == dev_b),
                   None) if status == 200 else None
    check("a VLAN aged to present=0 no longer draws on the A-B link",
          ab_link is not None and ab_link.get("vlans") == [10], (status, ab_link))

    # Now age VLAN 10 itself, not via present, but via staleness: seen_ts far
    # enough in the past to exceed stale_link_hours (24h default = 86400s),
    # the same cutoff assemble_links already applies to the neighbour rows.
    service.nodes_db.replace_port_vlans(
        dev_a, [{"if_index": 1, "vlan": 10, "tagged": True}], now=time.time() - 100000)
    status, payload = call("GET", f"/api/mapper/maps/{map_id}", token=admin)
    ab_link = next((l for l in payload.get("links", [])
                    if l.get("a_device_id") == dev_a and l.get("b_device_id") == dev_b),
                   None) if status == 200 else None
    check("a present=1 but stale-by-seen_ts VLAN also stops drawing",
          ab_link is not None and ab_link.get("vlans") == [], (status, ab_link))
    check("...and the link itself still draws (only its VLANs vanished, "
          "not the L2 link the neighbour row still confirms)",
          ab_link is not None, ab_link)

    # -------------------------------------------------- 16. mapper settings validation (Finding 8)
    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper", "values": {"max_strand_vlans": 0}},
                           token=admin)
    check("max_strand_vlans below 1 is a 400", status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper", "values": {"max_strand_vlans": 201}},
                           token=admin)
    check("max_strand_vlans above 200 is a 400", status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper", "values": {"link_width_min": 0}},
                           token=admin)
    check("link_width_min of 0 is a 400 (it would collapse every strand "
          "offset to zero)", status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper", "values": {"link_width_max": 0.5}},
                           token=admin)
    check("link_width_max below 1 is a 400", status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper",
                            "values": {"link_width_min": 10, "link_width_max": 5}},
                           token=admin)
    check("link_width_max less than link_width_min is a 400", status == 400, (status, payload))

    # Cross-field: max_strand_vlans <= vlan_collapse_threshold is refused
    # even when only ONE of the pair is named in this request -- the
    # currently-applied setting supplies the other side. Section 11 above
    # already set vlan_collapse_threshold to 12 and it is still in effect.
    status, payload = call("GET", "/api/config", token=admin)
    current_threshold = payload["mapper_settings"]["vlan_collapse_threshold"]
    check("...sanity: still 12 from section 11's write", current_threshold == 12, payload)
    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper",
                            "values": {"max_strand_vlans": current_threshold}},
                           token=admin)
    check("max_strand_vlans == the CURRENTLY-APPLIED vlan_collapse_threshold "
          "is a 400 even though this request does not name the threshold",
          status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper",
                            "values": {"vlan_collapse_threshold": 20, "max_strand_vlans": 20}},
                           token=admin)
    check("max_strand_vlans == vlan_collapse_threshold in the SAME request is a 400 too",
          status == 400, (status, payload))

    status, payload = call("POST", "/api/settings",
                           {"scope": "mapper",
                            "values": {"vlan_collapse_threshold": 5, "max_strand_vlans": 30}},
                           token=admin)
    check("a valid, consistent threshold/max_strand_vlans pair is accepted",
          status == 200, (status, payload))

    # ------------------------------------------- 17. vlan_interval_s editable (Finding 10)
    status, payload = call("GET", f"/api/nodes/devices/{dev_a}", token=admin)
    device_json = payload.get("device", {}) if status == 200 else {}
    check("device JSON carries vlan_interval_s (null until overridden)",
          status == 200 and "vlan_interval_s" in device_json
          and device_json["vlan_interval_s"] is None, (status, payload))

    status, payload = call("PUT", f"/api/nodes/devices/{dev_a}",
                           {"vlan_interval_s": 1800}, token=admin)
    check("vlan_interval_s is an editable device field", status == 200, (status, payload))
    status, payload = call("GET", f"/api/nodes/devices/{dev_a}", token=admin)
    device_json = payload.get("device", {}) if status == 200 else {}
    check("...and the device's own override reads back",
          status == 200 and device_json.get("vlan_interval_s") == 1800, (status, payload))
    check("...and effective_config resolves to that same override",
          status == 200
          and device_json.get("effective_config", {}).get("vlan_interval_s") == 1800, payload)

    status, payload = call("GET", "/api/nodes/groups", token=admin)
    group_row = (next((g for g in payload.get("groups", []) if g["id"] == gid), None)
                if status == 200 else None)
    check("group/profile JSON carries vlan_interval_s too",
          group_row is not None and "vlan_interval_s" in group_row, (status, payload))

    status, payload = call("PUT", f"/api/nodes/groups/{gid}",
                           {"vlan_interval_s": 900}, token=admin)
    check("vlan_interval_s is an editable group/profile field", status == 200, (status, payload))
    status, payload = call("GET", "/api/nodes/groups", token=admin)
    group_row = (next((g for g in payload.get("groups", []) if g["id"] == gid), None)
                if status == 200 else None)
    check("...and the profile's own value reads back",
          group_row is not None and group_row.get("vlan_interval_s") == 900, group_row)
finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
