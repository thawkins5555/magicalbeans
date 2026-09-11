"""The API and gates over LLDP/CDP, PoE, STP and PtP RF polling, driven against
a real Service + WebServer over loopback with rows seeded through nodesdb's
own accessors rather than a live walk. Covers the per-device neighbours route
(the best-effort device match joined in as matched_device_id/name), PoE/STP
fields on interface and device routes, RF via plain /metrics and /series,
"nodes" read gating, and both CSVs."""
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

    # ----------------------------------------- neighbours identified by IP
    # Four ways a neighbour arrives with an address where a name should be:
    # an LLDP subtype-5 chassis id (dotted and raw), a CDP device id that is
    # an address, and a CDP cdpCacheAddress with nothing else to go on.
    print("IP-only neighbours named through the Nodes/DNS chain")
    mgmt_id = db.add_device("10.40.0.9", name="mgmt-sw", group_id=gid)
    db.record_device_addresses(edge_id, ["10.40.0.22"], "test")
    service.app_db.set_hostname("10.40.0.50", "printer-3.corp.example")

    db.replace_neighbors(core_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "bb:bb:bb:bb:bb:01", "chassis_id_subtype": 4,
         "sys_name": "edge-sw-1", "port_id": "Gi0/1"},
        {"if_index": 2, "protocol": "lldp", "rem_index": "0.2.1",
         "chassis_id": "cc:cc:cc:cc:cc:02", "chassis_id_subtype": 4,
         "sys_name": "unmanaged-ap", "port_id": "eth0", "platform": "generic-ap"},
        {"if_index": 3, "protocol": "lldp", "rem_index": "0.3.1",
         "chassis_id": "10.40.0.9", "chassis_id_subtype": 5, "port_id": "Gi1/1"},
        {"if_index": 4, "protocol": "cdp", "rem_index": "4.1",
         "chassis_id": "10.40.0.22", "chassis_id_subtype": 1,
         "sys_name": "10.40.0.22", "remote_address": "10.40.0.22", "port_id": "Gi0/24"},
        {"if_index": 5, "protocol": "cdp", "rem_index": "5.1",
         "remote_address": "10.40.0.50", "port_id": "eth0"},
        {"if_index": 6, "protocol": "lldp", "rem_index": "0.6.1",
         "chassis_id": "10.40.0.77", "chassis_id_subtype": 5, "port_id": "e1"},
        # The raw IANA address-family + octets form a real agent sends.
        {"if_index": 7, "protocol": "lldp", "rem_index": "0.7.1",
         "chassis_id": "01 0A 28 00 09", "chassis_id_subtype": 5, "port_id": "Gi1/2"},
    ])

    status, payload = call("GET", f"/api/nodes/devices/{core_id}/neighbors", token=admin)
    by_port = {r["if_index"]: r for r in payload.get("neighbors", [])}
    check("all seven neighbour rows come back", len(by_port) == 7, sorted(by_port))

    row = by_port.get(3)
    check("a subtype-5 chassis IP of a managed device resolves to that device",
          row is not None and row["matched_device_id"] == mgmt_id
          and row["matched_device_name"] == "mgmt-sw"
          and row["resolved_source"] == "nodes", row)

    row = by_port.get(4)
    check("a CDP address matching a device's alias resolves to that device",
          row is not None and row["matched_device_id"] == edge_id
          and row["matched_device_name"] == "edge-sw-1"
          and row["resolved_source"] == "nodes", row)

    row = by_port.get(5)
    check("an unmanaged address with a cached PTR shows the DNS name",
          row is not None and row["matched_device_id"] is None
          and row["resolved_name"] == "printer-3.corp.example"
          and row["resolved_source"] == "dns", row)

    row = by_port.get(6)
    check("an address nothing knows stays the address",
          row is not None and row["matched_device_id"] is None
          and row["resolved_name"] is None and row["resolved_source"] == ""
          and row["chassis_id"] == "10.40.0.77", row)

    row = by_port.get(7)
    check("a raw address-family + octets chassis id decodes and resolves",
          row is not None and row["matched_device_id"] == mgmt_id
          and row["resolved_source"] == "nodes", row)

    check("the MAC-matched row is untouched by the name chain",
          by_port[1]["matched_device_id"] == edge_id
          and by_port[1]["resolved_source"] == "", by_port[1])

    status, csv_payload = call(
        "GET", f"/api/nodes/devices/{core_id}/neighbors/export.csv", token=admin)
    csv_rows = read_csv(csv_payload["csv"])
    header = csv_rows[0]
    exported = next((r for r in csv_rows[1:] if r[0] == "5"), None)
    check("the export carries resolved_name/resolved_source, appended",
          status == 200 and header[-2:] == ["resolved_name", "resolved_source"]
          and exported is not None
          and exported[header.index("resolved_name")] == "printer-3.corp.example",
          (header, exported))

    check("the resolver is fed the neighbour addresses it must name",
          "10.40.0.77" in service._extra_resolve_targets(),
          [a for a in service._extra_resolve_targets() if a.startswith("10.40.0.")])

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
