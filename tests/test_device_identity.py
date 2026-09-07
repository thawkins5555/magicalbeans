"""One node per device, however many L3 addresses it answers on.

Covers the whole of item 3: the bounded ipAdEntAddr walk a discovery sweep
runs (and the setting that turns it off), the within-sweep fold, promote()
folding onto a device already on file, the 409 a manual add answers with
and the force that overrules it, the same disposition in bulk import, the
addresses route and the addresses that ride in the device JSON, the
duplicate listing, and a merge executed across all four databases with its
audit line and its permission gate.

Runs a real Service + WebServer over loopback and a real stub SNMP agent,
like test_bulk_import.py and test_nodediscover_e2e.py do.
"""
import http.client
import json
import os
import time
from urllib.parse import urlencode

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

import netpath.nodediscover as nodediscover
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.nodediscover import fold_target, register_addresses
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("device_identity_")
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

nodes = service.nodes_db
stub = None


def call(method, path, body=None, token=None):
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


def run_sweep(addresses_on):
    """One device-kind sweep of 127.0.0.1 against the stub, run to
    completion, returning its single result row."""
    job_id = service.node_poller.start_discovery(
        "device", "127.0.0.1",
        overrides={"default_snmp_timeout_s": 1.0, "discovery_communities": "public",
                   "discovery_arc_hop": False, "discovery_addresses": addresses_on})
    for _ in range(100):
        job = nodes.discovery_job(job_id)
        if job["state"] != "running":
            break
        time.sleep(0.1)
    return job_id, nodes.discovery_results(job_id)[0]


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    stub, stub_port = _paths.spawn_stub("stub_agent_multiip.py")
    nodediscover.DEFAULT_SNMP_PORT = stub_port

    # ------------------------------------------------ 1. the address walk
    print("1. discovery walks ipAdEntAddr, and the setting turns it off")
    job_on, result_on = run_sweep(True)
    walked = json.loads(result_on["ip_addresses"] or "[]")
    check("a sweep records every address the device answered on",
          sorted(walked) == ["10.7.7.7", "10.8.8.8"], walked)
    check("...and never the loopback every agent reports",
          "127.0.0.1" not in walked, walked)
    job_off, result_off = run_sweep(False)
    check("discovery_addresses off walks nothing",
          json.loads(result_off["ip_addresses"] or "[]") == [],
          result_off["ip_addresses"])

    # ------------------------------------------------------ 2. the fold rule
    print("2. fold_target / register_addresses")
    owners = {}
    register_addresses(owners, 11, ["10.7.7.7", "10.8.8.8"])
    check("the first result to reach an address keeps it",
          fold_target(["10.9.9.9", "10.8.8.8"], owners) == 11, owners)
    check("a result sharing nothing folds into nothing",
          fold_target(["10.9.9.9"], owners) is None)
    register_addresses(owners, 12, ["10.7.7.7"])
    check("a later result never steals an address already claimed",
          owners["10.7.7.7"] == 11, owners)

    # ------------------------------- 3. promote folds onto an existing device
    print("3. promote folds a result onto the device that already answers")
    existing_id = nodes.add_device("10.7.7.7")
    promoted = service.node_poller.promote(job_on, [result_on["id"]])
    check("promoting a result whose walked address is already a device folds onto it",
          promoted == [existing_id], (promoted, existing_id))
    check("...and creates no second device",
          nodes.device_by_ip("127.0.0.1") is None)
    aliases = {row["ip"] for row in nodes.device_addresses(existing_id)}
    check("...and records the addresses it walked on that device",
          "10.8.8.8" in aliases, aliases)

    forced = service.node_poller.promote(job_off, [result_off["id"]], force=True)
    check("force adds the device anyway", len(forced) == 1 and
          nodes.device_by_ip("127.0.0.1") is not None, forced)
    nodes.remove_device(forced[0])

    # ------------------------- 4. a folded row promotes as its primary instead
    print("4. a folded result promotes as the row it was folded into")
    fold_job = nodes.add_discovery_job("subnet", "10.30.0.0/30")
    primary_id = nodes.add_discovery_result(
        fold_job, ip="10.30.0.1", ping_ok=1, snmp_ok=1, sys_name="folder",
        sys_object_id="1.3.6.1.4.1.99999", community_or_user="public",
        snmp_version=1, ip_addresses=json.dumps(["10.30.0.2"]))
    folded_id = nodes.add_discovery_result(
        fold_job, ip="10.30.0.2", ping_ok=1, snmp_ok=1, sys_name="folder",
        sys_object_id="1.3.6.1.4.1.99999", community_or_user="public",
        snmp_version=1, folded_into_result_id=primary_id)
    fold_devices = service.node_poller.promote(fold_job, [folded_id])
    check("ticking the folded row promotes its primary, once",
          len(fold_devices) == 1 and
          nodes.device(fold_devices[0])["ip"] == "10.30.0.1", fold_devices)
    check("...and the folded sibling is marked promoted to the same device",
          nodes.discovery_result(folded_id)["promoted_device_id"] == fold_devices[0])
    folded_device = fold_devices[0]

    # ------------------------------------- 5. what the discovery listing says
    print("5. the discovery listing serves primaries and flags duplicates")
    status, listing = call("GET", f"/api/nodes/discovery/{fold_job}", token=admin)
    ips = [row["ip"] for row in listing["results"]]
    check("a folded row is not offered as a second device",
          status == 200 and ips == ["10.30.0.1"], (status, ips))
    check("...its address rides on the primary's row instead",
          "10.30.0.2" in listing["results"][0]["addresses"],
          listing["results"][0]["addresses"])

    dup_job = nodes.add_discovery_job("subnet", "10.31.0.0/30")
    high_id = nodes.add_discovery_result(
        dup_job, ip="10.31.0.1", ping_ok=1, snmp_ok=1, sys_name="whatever",
        sys_object_id="1.3.6.1.4.1.1", community_or_user="public", snmp_version=1,
        ip_addresses=json.dumps(["10.8.8.8"]))
    nodes.seed_identity(existing_id, sys_name="medium-twin",
                        sys_object_id="1.3.6.1.4.1.4242")
    medium_id = nodes.add_discovery_result(
        dup_job, ip="10.31.0.2", ping_ok=1, snmp_ok=1, sys_name="medium-twin",
        sys_object_id="1.3.6.1.4.1.4242", community_or_user="public", snmp_version=1)
    status, dup_listing = call("GET", f"/api/nodes/discovery/{dup_job}", token=admin)
    by_id = {row["id"]: row for row in dup_listing["results"]}
    check("an address a device already answers on is high confidence",
          by_id[high_id]["duplicate_confidence"] == "high"
          and by_id[high_id]["duplicate_of_device_id"] == existing_id,
          by_id.get(high_id))
    check("sysName plus sysObjectID alone is only a medium hint",
          by_id[medium_id]["duplicate_confidence"] == "medium",
          by_id.get(medium_id))

    medium_devices = service.node_poller.promote(dup_job, [medium_id])
    check("a medium hint never folds — it adds the device it was ticked for",
          len(medium_devices) == 1
          and nodes.device(medium_devices[0])["ip"] == "10.31.0.2", medium_devices)
    high_devices = service.node_poller.promote(dup_job, [high_id])
    check("a high (address) match folds instead of adding",
          high_devices == [existing_id], high_devices)

    # ---------------------------------------------------- 6. manual add 409
    print("6. adding an address another device already answers on")
    status, refusal = call("POST", "/api/nodes/devices", {"ip": "10.8.8.8"}, token=admin)
    check("a manual add of an alias address is refused with 409",
          status == 409, (status, refusal))
    check("...naming the device it belongs to",
          (refusal.get("duplicate_of") or {}).get("device_id") == existing_id, refusal)
    status, forced_add = call("POST", "/api/nodes/devices",
                              {"ip": "10.8.8.8", "force": True}, token=admin)
    check("...and force adds it anyway", status == 200 and forced_add.get("id"),
          (status, forced_add))
    forced_device_id = forced_add["id"]
    status, again = call("POST", "/api/nodes/devices",
                         {"ip": "10.8.8.8", "force": True}, token=admin)
    check("force still cannot create two devices on one primary address",
          status == 400, (status, again))
    # A primary-IP collision is never "Add anyway": the UNIQUE index behind
    # the insert refuses it either way, so a 409 only bought a second, less
    # informative refusal one click later.
    status, plain = call("POST", "/api/nodes/devices",
                         {"ip": "10.8.8.8"}, token=admin)
    check("...and without force it is the same plain 400, not a 409",
          status == 400 and "duplicate_of" not in plain, (status, plain))

    # --------------------------------------------------- 7. bulk import
    print("7. bulk import puts an alias-owned row in its duplicate disposition")
    nodes.record_device_addresses(existing_id, ["10.44.0.9"], "ipAddrTable")
    status, imported = call("POST", "/api/nodes/devices/bulk-import",
                            {"devices": [{"ip": "10.44.0.9"}]}, token=admin)
    duplicate = (imported.get("duplicate") or [{}])[0]
    check("an address another device answers on is a duplicate, not a create",
          status == 200 and not imported["created"]
          and duplicate.get("device_id") == existing_id, (status, imported))
    status, forced_import = call("POST", "/api/nodes/devices/bulk-import",
                                 {"devices": [{"ip": "10.44.0.9"}], "force": True},
                                 token=admin)
    check("...and force imports it", status == 200
          and len(forced_import["created"]) == 1, (status, forced_import))

    # -------------------------------------------------- 8. the addresses view
    print("8. the addresses route and the device JSON")
    status, addr = call("GET", f"/api/nodes/devices/{existing_id}/addresses", token=admin)
    listed = [row["ip"] for row in addr["addresses"]]
    check("the addresses route leads with the device's own primary address",
          status == 200 and listed[0] == "10.7.7.7" and addr["addresses"][0]["primary"],
          (status, addr))
    check("...and lists the aliases behind it", "10.8.8.8" in listed, listed)
    status, device_json = call("GET", f"/api/nodes/devices/{existing_id}", token=admin)
    check("the device JSON carries the same list, so the subtab needs no fetch",
          status == 200 and [r["ip"] for r in device_json["device"]["addresses"]] == listed,
          (status, device_json.get("device", {}).get("addresses")))

    # ---------------------------------------------- 9. duplicates and merge
    print("9. the duplicates listing")
    status, duplicates = call("GET", "/api/nodes/duplicates", token=admin)
    pair = next((d for d in duplicates["duplicates"]
                 if {d["a_id"], d["b_id"]} == {existing_id, forced_device_id}), None)
    check("two devices claiming one address are listed as a high-confidence pair",
          status == 200 and pair is not None and pair["confidence"] == "high",
          (status, duplicates))
    check("...with the lower id suggested as the winner",
          pair and pair["suggested_winner_id"] == min(existing_id, forced_device_id),
          pair)

    print("9b. merge preview, then merge, across all four databases")
    map_id = service.mapper_db.create_map("identity-map")
    service.mapper_db.add_node(map_id, device_id=forced_device_id, label="loser")
    service.mapper_db.add_node(map_id, device_id=folded_device, label="bystander")
    service.configrx_db.update_device_config(forced_device_id, backup_enabled=1)
    rule = service.alerts_db.rules()[0]
    service.alerts_db.open_or_increment(
        rule["id"], f"merge-test:{forced_device_id}", "device", str(forced_device_id),
        "loser", 3, "still open", "", time.time())
    service.alerts_db.mute("device", str(forced_device_id), 1.0, by="tester")
    service.alerts_db.park_occurrence(forced_device_id, time.time() + 600, "{}")
    window_id = service.alerts_db.add_window(
        "identity window", "devices", time.time(), time.time() + 3600,
        scope_device_ids=[forced_device_id])
    nodes.set_upstream_ids({folded_device: forced_device_id})

    status, preview = call("POST", f"/api/nodes/devices/{forced_device_id}/merge",
                           {"into": existing_id, "preview": True}, token=admin)
    check("a preview counts what would move and writes nothing",
          status == 200 and preview["preview"] is True
          and preview["plan"]["counts"]["upstream_children"] == 1
          and nodes.device(forced_device_id) is not None, (status, preview))

    status, merged = call("POST", f"/api/nodes/devices/{forced_device_id}/merge",
                          {"into": existing_id}, token=admin)
    check("the merge answers with the surviving device",
          status == 200 and merged["device_id"] == existing_id, (status, merged))
    check("the loser's row is gone", nodes.device(forced_device_id) is None)
    check("its address became an alias of the winner",
          "10.8.8.8" in {r["ip"] for r in nodes.device_addresses(existing_id)})
    check("an upstream pointing at the loser now points at the winner",
          nodes.device(folded_device)["upstream_id"] == existing_id,
          nodes.device(folded_device)["upstream_id"])
    map_devices = {row["device_id"] for row in service.mapper_db.nodes(map_id)}
    check("the map placement moved rather than being lost",
          existing_id in map_devices and forced_device_id not in map_devices,
          map_devices)
    check("the loser's open alert was resolved rather than left unnavigable",
          not [a for a in service.alerts_db.alerts(state="open")
               if a["entity_id"] == str(forced_device_id)])
    check("its mute moved to the winner",
          service.alerts_db.mute_row("device", str(existing_id)) is not None)
    check("its held occurrences moved to the winner",
          all(row["device_id"] == existing_id
              for row in service.alerts_db.due_occurrences(time.time() + 1200)))
    scope = json.loads(service.alerts_db.window(window_id)["scope_device_ids"])
    check("a maintenance window naming the loser now names the winner",
          scope == [existing_id], scope)
    audit = [row for row in service.app_db.audit_events(limit=500)
             if row["action"] == "device.merge"]
    check("the merge is in the audit trail", len(audit) == 1, audit)
    check("ConfigRX's half moved to the winner",
          service.configrx_db.device_config(existing_id) is not None
          and service.configrx_db.device_config(forced_device_id) is None,
          service.configrx_db.device_config(existing_id))

    print("9c. the merge needs nodes write")
    service.app_db.add_user("id-reader", hash_password("IdentityReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("id-reader", {"nodes": "read"})
    reader = login("id-reader", "IdentityReaderPW2026")
    status, refused = call("POST", f"/api/nodes/devices/{folded_device}/merge",
                           {"into": existing_id}, token=reader)
    check("a nodes:read-only account cannot merge", status == 403, (status, refused))
    status, readable = call("GET", "/api/nodes/duplicates", token=reader)
    check("...but may read the duplicates listing", status == 200, status)

finally:
    if stub is not None:
        stub.kill()
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
