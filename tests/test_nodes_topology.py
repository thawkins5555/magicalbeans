"""Wave 4, job 1/3: the API + gates surfacing Tier 1's already-committed
LLDP/CDP, PoE, STP and PtP RF polling — driven against a real Service and
WebServer over loopback, with the backend rows seeded directly through
nodesdb's own accessors (the same shortcut test_poe_stp.py's two_ports()
and test_lldp_topology.py's "best-effort device match" section take) rather
than a live SNMP walk, since this suite is about the routes on top of that
data, not the walk itself.

Covers:
  - GET /api/nodes/topology: nodes+edges shape, a matched pair of LLDP rows
    (each device reporting the other) deduplicated into ONE edge, and an
    unmatched neighbour drawn as its own synthetic "unknown" node.
  - GET /api/nodes/devices/<id>/neighbors: the detail-pane shape.
  - GET /api/nodes/devices/<id>/interfaces carries poe_admin/poe_detect_
    status/poe_power_mw/stp_state; GET .../<id> carries poe_capable/
    stp_capable/stp_root_id and friends.
  - RF metrics (recorded exactly as nodepoll._poll_rf_metrics would) are
    reachable through the ordinary /metrics and /series endpoints — nothing
    RF-specific needed on the wire, which is the point.
  - Every new route is gated ("nodes", read): a nodes:read account is let
    in, an account with no nodes grant at all is refused.
  - Both new CSV exports (topology, and one device's neighbours) round-trip
    through Python's own csv module.
"""
import csv
import http.client
import io
import json
import os
import time
from urllib.parse import urlencode

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("nodes_topology_")
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
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(method, path, body=None, token=None):
    # GET carries its arguments in the query string — the server never reads
    # a body for GET — while every other method sends `body` as JSON.
    data = None
    if method == "GET":
        if body:
            path = f"{path}?{urlencode(body)}"
    else:
        data = json.dumps(body).encode() if body is not None else None
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path, body=data, headers=headers)
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
                 body=json.dumps({"username": username, "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


def read_csv(text):
    # Strip the BOM the same way Excel would (see api._csv_text).
    return list(csv.reader(io.StringIO(text.lstrip("﻿"))))


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    db = service.nodes_db
    gid = db.ensure_default_group()

    # ------------------------------------------------------------- devices
    core_id = db.add_device("10.40.0.1", name="core-sw-1", group_id=gid)
    edge_id = db.add_device("10.40.0.2", name="edge-sw-1", group_id=gid)
    ap_id = db.add_device("10.40.0.3", name="radio", group_id=gid)

    # Each device's own port the reciprocal LLDP walk saw, so nodesdb's
    # chassis-MAC join can resolve BOTH directions to a real device id.
    db.replace_interfaces(core_id, [
        {"if_index": 1, "descr": "Gi0/1", "phys_addr": "aa:aa:aa:aa:aa:01"},
        {"if_index": 2, "descr": "Gi0/2"}])
    db.replace_interfaces(edge_id, [
        {"if_index": 1, "descr": "Gi0/1", "phys_addr": "bb:bb:bb:bb:bb:01"}])

    # The physical link, reported from BOTH ends — the ordinary case for two
    # devices that both walk LLDP. This must dedup to ONE edge.
    db.replace_neighbors(core_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "bb:bb:bb:bb:bb:01", "chassis_id_subtype": 4,
         "sys_name": "edge-sw-1", "port_id": "Gi0/1"},
    ])
    db.replace_neighbors(edge_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "aa:aa:aa:aa:aa:01", "chassis_id_subtype": 4,
         "sys_name": "core-sw-1", "port_id": "Gi0/1"},
    ])
    # An unmatched neighbour on the core switch's second port — nothing in
    # Nodes answers this chassis id or sysName (an unmanaged AP, say).
    db.replace_neighbors(core_id, [
        {"if_index": 2, "protocol": "lldp", "rem_index": "0.2.1",
         "chassis_id": "cc:cc:cc:cc:cc:02", "chassis_id_subtype": 4,
         "sys_name": "unmanaged-ap", "port_id": "eth0", "platform": "generic-ap"},
    ], now=time.time())
    # replace_neighbors marks every OTHER row for this device present=0 —
    # restore the first link's row (it was walked in a separate call above).
    db.replace_neighbors(core_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "bb:bb:bb:bb:bb:01", "chassis_id_subtype": 4,
         "sys_name": "edge-sw-1", "port_id": "Gi0/1"},
        {"if_index": 2, "protocol": "lldp", "rem_index": "0.2.1",
         "chassis_id": "cc:cc:cc:cc:cc:02", "chassis_id_subtype": 4,
         "sys_name": "unmanaged-ap", "port_id": "eth0", "platform": "generic-ap"},
    ])

    # ------------------------------------------------------------ topology
    print("GET /api/nodes/topology")
    status, payload = call("GET", "/api/nodes/topology", token=admin)
    check("200", status == 200, (status, payload))
    node_ids = {n["id"] for n in payload["nodes"]}
    check("every real device is a node", {core_id, edge_id, ap_id} <= node_ids, node_ids)
    real_edges = [e for e in payload["edges"] if not e["unknown"]]
    unk_edges = [e for e in payload["edges"] if e["unknown"]]
    check("the reciprocal core<->edge link dedups to exactly one edge",
          len(real_edges) == 1, payload["edges"])
    if real_edges:
        e = real_edges[0]
        check("...naming both device ids",
              {e["a_device_id"], e["b_device_id"]} == {core_id, edge_id}, e)
        check("...with both ports labelled from each device's own interfaces()",
              e["a_port"] in ("Gi0/1",) and e["b_port"] in ("Gi0/1",), e)
    check("the unmatched neighbour is exactly one edge, marked unknown",
          len(unk_edges) == 1, payload["edges"])
    unknown_node_ids = [n["id"] for n in payload["nodes"] if n.get("unknown")]
    check("...pointing at a synthetic node, not a real device id",
          len(unknown_node_ids) == 1 and isinstance(unknown_node_ids[0], str)
          and unknown_node_ids[0].startswith("unknown:"), unknown_node_ids)
    if unk_edges:
        check("...that edge's b_device_id is the synthetic node",
              unk_edges[0]["b_device_id"] == unknown_node_ids[0], unk_edges[0])

    status, csv_payload = call("GET", "/api/nodes/topology/export.csv", token=admin)
    check("topology export.csv", status == 200 and "csv" in csv_payload, (status, csv_payload))
    if status == 200:
        rows = read_csv(csv_payload["csv"])
        check("...header plus at least the 3 stored neighbour rows",
              len(rows) >= 4, len(rows))

    # ------------------------------------------------------ per-device view
    print("GET /api/nodes/devices/<id>/neighbors")
    status, payload = call("GET", f"/api/nodes/devices/{core_id}/neighbors", token=admin)
    check("200", status == 200, (status, payload))
    rows = payload.get("neighbors", [])
    check("both of core's neighbour rows come back", len(rows) == 2, rows)
    matched = next((r for r in rows if r["if_index"] == 1), None)
    check("the matched row carries matched_device_id/name and a local port label",
          matched is not None and matched["matched_device_id"] == edge_id
          and matched["matched_device_name"] == "edge-sw-1"
          and matched["local_port"] == "Gi0/1", matched)
    unmatched = next((r for r in rows if r["if_index"] == 2), None)
    check("the unmatched row has no device match",
          unmatched is not None and unmatched["matched_device_id"] is None, unmatched)

    status, csv_payload = call(
        "GET", f"/api/nodes/devices/{core_id}/neighbors/export.csv", token=admin)
    check("per-device neighbours export.csv",
          status == 200 and read_csv(csv_payload["csv"])[0][0] == "if_index",
          (status, csv_payload))

    # ----------------------------------------------------- PoE/STP surfaced
    print("PoE/STP fields on the device and interfaces responses")
    db.set_poe_capable(core_id, True)
    db.set_stp_capable(core_id, True)
    db.update_stp_bridge(core_id, protocol_spec="ieee8021d", priority=32768,
                         root_id="8000.aaaaaaaaaa01", root_cost=4, root_port=1,
                         time_since_change_s=120.0)
    db.update_interface_poe(core_id, [
        {"if_index": 1, "poe_admin": "enabled", "poe_detect_status": "deliveringPower",
         "poe_power_mw": 15400}])
    db.update_interface_stp(core_id, [{"if_index": 1, "stp_state": "forwarding"}])
    db.record_metric_samples(core_id, [
        ("poe_budget_w", "PoE power budget", "W", "gauge", time.time(), 370.0),
        ("poe_consumption_w", "PoE power in use", "W", "gauge", time.time(), 214.0),
        ("stp_topology_changes", "STP topology changes", "count", "counter_rate",
         time.time(), 5.0),
    ])

    status, payload = call("GET", f"/api/nodes/devices/{core_id}", token=admin)
    device = payload["device"]
    check("poe_capable/stp_capable surfaced on the device",
          device.get("poe_capable") is True and device.get("stp_capable") is True, device)
    check("STP root/topology fields surfaced",
          device.get("stp_root_id") == "8000.aaaaaaaaaa01"
          and device.get("stp_root_cost") == 4
          and device.get("stp_time_since_change_s") == 120.0, device)

    status, payload = call("GET", f"/api/nodes/devices/{core_id}/interfaces", token=admin)
    iface1 = next(i for i in payload["interfaces"] if i["if_index"] == 1)
    check("port 1 carries poe_admin/poe_detect_status/poe_power_mw/stp_state",
          iface1["poe_admin"] == "enabled" and iface1["poe_detect_status"] == "deliveringPower"
          and iface1["poe_power_mw"] == 15400 and iface1["stp_state"] == "forwarding", iface1)

    status, csv_payload = call(
        "GET", f"/api/nodes/devices/{core_id}/interfaces/export.csv", token=admin)
    header = read_csv(csv_payload["csv"])[0]
    check("interfaces export.csv gained the four PoE/STP columns",
          all(k in header for k in ("poe_admin", "poe_detect_status",
                                    "poe_power_mw", "stp_state")), header)

    status, payload = call("GET", f"/api/nodes/devices/{core_id}/metrics", token=admin)
    metrics = {m["key"]: m for m in payload["metrics"]}
    check("the PSE budget/consumption metrics are the ordinary metrics list",
          metrics.get("poe_budget_w", {}).get("last_value") == 370.0
          and metrics.get("poe_consumption_w", {}).get("last_value") == 214.0, metrics)
    check("...and the topology-change counter alongside them",
          metrics.get("stp_topology_changes", {}).get("last_value") == 5.0, metrics)

    # ---------------------------------------------------------- RF via series
    print("RF metrics reachable through the ordinary series endpoint")
    now = time.time()
    # Two separate calls, not two rows in one — record_metric_samples keys
    # its batch by metric key, so a second row for the same key in the same
    # call would only overwrite the first rather than leaving two points in
    # series() (test_poe_stp.py's own topology-change-counter history
    # section takes the same two-call shape for the same reason).
    db.record_metric_samples(ap_id, [
        ("rf_rssi_dbm", "RSSI", "dBm", "gauge", now - 60, -60.0)])
    db.record_metric_samples(ap_id, [
        ("rf_rssi_dbm", "RSSI", "dBm", "gauge", now, -58.0),
        ("rf_snr_db", "SNR", "dB", "gauge", now, 28.0),
        ("rf_capacity_bps", "Link capacity", "bps", "gauge", now, 700_000_000.0),
    ])
    status, payload = call("GET", f"/api/nodes/devices/{ap_id}/metrics", token=admin)
    rf_metrics = {m["key"]: m for m in payload["metrics"]}
    check("all three RF metrics show up in the plain metrics list",
          {"rf_rssi_dbm", "rf_snr_db", "rf_capacity_bps"} <= set(rf_metrics),
          rf_metrics)
    check("current RSSI reads back correctly",
          rf_metrics["rf_rssi_dbm"]["last_value"] == -58.0, rf_metrics["rf_rssi_dbm"])
    rssi_id = rf_metrics["rf_rssi_dbm"]["id"]
    status, payload = call("GET", f"/api/nodes/devices/{ap_id}/series",
                           {"metric_id": rssi_id, "t0": now - 3600, "t1": now + 60}, token=admin)
    check("series has RSSI history (2 points)", len(payload.get("points", [])) >= 2, payload)

    # -------------------------------------------------------------- gates
    print("gates: nodes:read allowed, no grant refused")
    service.app_db.add_user("topo-reader", hash_password("TopoReaderPW2026"), must_change=False)
    service.app_db.set_permissions("topo-reader", {"nodes": "read"})
    reader = login("topo-reader", "TopoReaderPW2026")
    service.app_db.add_user("topo-outsider", hash_password("TopoOutsiderPW2026"), must_change=False)
    service.app_db.set_permissions("topo-outsider", {"syslog": "read"})
    outsider = login("topo-outsider", "TopoOutsiderPW2026")

    for path in (
        "/api/nodes/topology",
        "/api/nodes/topology/export.csv",
        f"/api/nodes/devices/{core_id}/neighbors",
        f"/api/nodes/devices/{core_id}/neighbors/export.csv",
    ):
        status, payload = call("GET", path, token=reader)
        check(f"a nodes:read account may read {path}", status == 200, (status, payload))
        status, payload = call("GET", path, token=outsider)
        check(f"an account with no nodes grant is refused {path}",
              status == 403, (status, payload))

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)
