"""One node per device, however many addresses it answers on — but only its
own interface table says so; a discovery sweep asserts nothing beyond the
address it actually probed.

Covers the 5.29.0 rule: a sweep records the probed address only, two
addresses of the same device are two independent results, promote() folds a
result onto a device whose own interfaces (ipAddrTable) already answer the
probed address unless forced, the 409 a manual add answers with and the
force that overrules it, the same disposition in bulk import, the addresses
route and the addresses that ride in the device JSON, the duplicate listing
and its reason text, and a merge executed across all four databases with its
audit line and its permission gate — without carrying the loser's primary
address over as a fresh alias.

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
import netpath.nodesdb as nodesdb
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
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


def run_sweep():
    """One device-kind sweep of 127.0.0.1 against the stub, run to
    completion, returning its single result row."""
    job_id = service.node_poller.start_discovery(
        "device", "127.0.0.1",
        overrides={"default_snmp_timeout_s": 1.0, "discovery_communities": "public",
                   "discovery_arc_hop": False})
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

    # ------------------------------------------- 1. the probed address only
    print("1. discovery records the probed address only, no address walk")
    job_on, result_on = run_sweep()
    check("no ip_addresses are recorded any more",
          not result_on["ip_addresses"], result_on["ip_addresses"])
    check("the result carries the address that was actually probed",
          result_on["ip"] == "127.0.0.1", result_on["ip"])

    # ------------------------------------------ 2. two addresses, two rows
    print("2. two addresses of the same device are two rows, not folded")
    twin_job = nodes.add_discovery_job("subnet", "10.33.0.0/30")
    twin_a = nodes.add_discovery_result(
        twin_job, ip="10.33.0.1", ping_ok=1, snmp_ok=1, sys_name="twin",
        sys_object_id="1.3.6.1.4.1.55555", community_or_user="public", snmp_version=1)
    twin_b = nodes.add_discovery_result(
        twin_job, ip="10.33.0.2", ping_ok=1, snmp_ok=1, sys_name="twin",
        sys_object_id="1.3.6.1.4.1.55555", community_or_user="public", snmp_version=1)
    status, twin_listing = call("GET", f"/api/nodes/discovery/{twin_job}", token=admin)
    check("both addresses are listed as separate rows",
          status == 200 and len(twin_listing["results"]) == 2, (status, twin_listing))
    twin_devices = service.node_poller.promote(twin_job, [twin_a, twin_b])
    check("promoting both adds two devices, not one",
          len(twin_devices) == 2 and len(set(twin_devices)) == 2, twin_devices)
    for device_id in twin_devices:
        nodes.remove_device(device_id)

    # --------- 3. a promoted device has no device_addresses rows until polled
    print("3. a promoted device has no device_addresses rows until it is polled")
    # 127.0.0.1 is never storable as interface evidence (alias_candidate
    # excludes it — every agent reports it, so it can never single out a
    # device), so this real sweep's result has no owner anywhere and
    # promotes as a plain new device; the fold rule itself is proven in
    # section 4 against a real, storable address.
    promoted = service.node_poller.promote(job_on, [result_on["id"]])
    check("promoting it adds a new device",
          len(promoted) == 1 and nodes.device_by_ip("127.0.0.1") is not None, promoted)
    check("...with no device_addresses rows recorded at promote time",
          nodes.device_addresses(promoted[0]) == [], nodes.device_addresses(promoted[0]))
    nodes.remove_device(promoted[0])

    existing_id = nodes.add_device("10.7.7.7")
    nodes.record_device_addresses(existing_id, ["10.8.8.8"], "ipAddrTable")

    # ------------------ 4. a duplicate result folds unless it is forced
    print("4. a duplicate result folds onto the existing device unless forced")
    fold_job = nodes.add_discovery_job("subnet", "10.30.0.0/30")
    fold_target_id = nodes.add_device("10.30.0.9")
    nodes.record_device_addresses(fold_target_id, ["10.30.0.1", "10.30.0.2"],
                                  "ipAddrTable")
    dup_a = nodes.add_discovery_result(
        fold_job, ip="10.30.0.1", ping_ok=1, snmp_ok=1, sys_name="folder",
        sys_object_id="1.3.6.1.4.1.99999", community_or_user="public", snmp_version=1)
    dup_b = nodes.add_discovery_result(
        fold_job, ip="10.30.0.2", ping_ok=1, snmp_ok=1, sys_name="folder",
        sys_object_id="1.3.6.1.4.1.99999", community_or_user="public", snmp_version=1)
    status, fold_listing = call("GET", f"/api/nodes/discovery/{fold_job}", token=admin)
    fold_row = next(r for r in fold_listing["results"] if r["id"] == dup_a)
    check("the listing flags the row high, with the interfaces reason",
          status == 200 and fold_row.get("duplicate_confidence") == "high"
          and fold_row.get("duplicate_of_device_id") == fold_target_id
          and fold_row.get("duplicate_reason")
          == "already added as 10.30.0.9: 10.30.0.1 is on its interfaces",
          fold_row)
    plain_devices = service.node_poller.promote(fold_job, [dup_a])
    check("ticking it plainly folds onto the existing device",
          plain_devices == [fold_target_id], plain_devices)

    # ------------------ 4b. force keeps a duplicate result as its own device
    print("4b. force keeps a duplicate result as its own device")
    forced_dup_devices = service.node_poller.promote(fold_job, [dup_b], force=True)
    check("force promotes the duplicate at its own probed address",
          len(forced_dup_devices) == 1
          and nodes.device(forced_dup_devices[0])["ip"] == "10.30.0.2",
          forced_dup_devices)
    folded_device = forced_dup_devices[0]

    # ---------------- 4c. the promote route: forced + plain, one call
    print("4c. force_result_ids and result_ids together, each its own device")

    def add_dup_pair(job, target_id, ip_a, ip_b, sys_name, sys_object_id):
        nodes.record_device_addresses(target_id, [ip_a, ip_b], "ipAddrTable")
        result_a = nodes.add_discovery_result(
            job, ip=ip_a, ping_ok=1, snmp_ok=1, sys_name=sys_name,
            sys_object_id=sys_object_id, community_or_user="public", snmp_version=1)
        result_b = nodes.add_discovery_result(
            job, ip=ip_b, ping_ok=1, snmp_ok=1, sys_name=sys_name,
            sys_object_id=sys_object_id, community_or_user="public", snmp_version=1)
        return result_a, result_b

    job_4c1 = nodes.add_discovery_job("subnet", "10.34.0.0/30")
    target_4c1 = nodes.add_device("10.34.0.9")
    dup_4c1a, dup_4c1b = add_dup_pair(job_4c1, target_4c1, "10.34.0.1", "10.34.0.2",
                                      "fold-pair", "1.3.6.1.4.1.77777")
    status, result_4c1 = call(
        "POST", f"/api/nodes/discovery/{job_4c1}/promote",
        {"result_ids": [dup_4c1a], "force_result_ids": [dup_4c1b]}, token=admin)
    ids_4c1 = result_4c1.get("device_ids") or []
    check("a plain-ticked duplicate and its forced twin become two devices",
          status == 200 and len(ids_4c1) == 2 and len(set(ids_4c1)) == 2
          and target_4c1 in ids_4c1, (status, result_4c1))
    ips_4c1 = sorted(nodes.device(d)["ip"] for d in ids_4c1) if len(ids_4c1) == 2 else []
    check("...the target device and a second device at the forced address",
          ips_4c1 == ["10.34.0.2", "10.34.0.9"], ips_4c1)
    for device_id in ids_4c1:
        if device_id != target_4c1:
            nodes.remove_device(device_id)

    job_4c2 = nodes.add_discovery_job("subnet", "10.35.0.0/30")
    target_4c2 = nodes.add_device("10.35.0.9")
    dup_4c2a, dup_4c2b = add_dup_pair(job_4c2, target_4c2, "10.35.0.1", "10.35.0.2",
                                      "fold-pair", "1.3.6.1.4.1.77778")
    status, result_4c2 = call(
        "POST", f"/api/nodes/discovery/{job_4c2}/promote",
        {"result_ids": [dup_4c2a, dup_4c2b], "force_result_ids": [dup_4c2b]},
        token=admin)
    ids_4c2 = result_4c2.get("device_ids") or []
    check("the forced id repeated in both lists still yields two devices, no dupes",
          status == 200 and len(ids_4c2) == 2 and len(set(ids_4c2)) == 2, (status, result_4c2))
    for device_id in ids_4c2:
        if device_id != target_4c2:
            nodes.remove_device(device_id)

    job_4c3 = nodes.add_discovery_job("subnet", "10.36.0.0/30")
    target_4c3 = nodes.add_device("10.36.0.9")
    dup_4c3a, dup_4c3b = add_dup_pair(job_4c3, target_4c3, "10.36.0.1", "10.36.0.2",
                                      "fold-pair", "1.3.6.1.4.1.77779")
    status, result_4c3 = call(
        "POST", f"/api/nodes/discovery/{job_4c3}/promote",
        {"force_result_ids": [dup_4c3b]}, token=admin)
    ids_4c3 = result_4c3.get("device_ids") or []
    check("forcing one duplicate alone adds one device at its own address",
          status == 200 and len(ids_4c3) == 1
          and nodes.device(ids_4c3[0])["ip"] == "10.36.0.2", (status, result_4c3))
    forced_only_device_4c3 = ids_4c3[0]
    status, listing_4c3 = call("GET", f"/api/nodes/discovery/{job_4c3}", token=admin)
    row_4c3 = next(r for r in listing_4c3["results"] if r["id"] == dup_4c3a)
    check("...and its twin still shows a high-confidence duplicate hint, unpromoted",
          status == 200 and row_4c3.get("duplicate_confidence") == "high"
          and row_4c3.get("duplicate_of_device_id") == target_4c3
          and not row_4c3.get("promoted_device_id"), row_4c3)
    status, result_4c3b = call(
        "POST", f"/api/nodes/discovery/{job_4c3}/promote",
        {"result_ids": [dup_4c3a]}, token=admin)
    ids_4c3b = result_4c3b.get("device_ids") or []
    check("plainly promoting the twin afterward folds onto the target",
          status == 200 and ids_4c3b == [target_4c3], (status, result_4c3b))
    nodes.remove_device(forced_only_device_4c3)
    nodes.remove_device(target_4c3)

    # ------- 4d. ordering: plain fold first, then a forced twin afterwards
    print("4d. a plain fold via the route, then its duplicate force-added after")
    job_4d = nodes.add_discovery_job("subnet", "10.37.0.0/30")
    target_4d = nodes.add_device("10.37.0.9")
    dup_4da, dup_4db = add_dup_pair(job_4d, target_4d, "10.37.0.1", "10.37.0.2",
                                    "fold-pair", "1.3.6.1.4.1.77780")
    status, result_4d1 = call(
        "POST", f"/api/nodes/discovery/{job_4d}/promote",
        {"result_ids": [dup_4da]}, token=admin)
    ids_4d1 = result_4d1.get("device_ids") or []
    check("plain approval alone folds onto the target",
          status == 200 and ids_4d1 == [target_4d], (status, result_4d1))
    status, result_4d2 = call(
        "POST", f"/api/nodes/discovery/{job_4d}/promote",
        {"force_result_ids": [dup_4db]}, token=admin)
    ids_4d2 = result_4d2.get("device_ids") or []
    check("force-adding the duplicate afterward still adds a second device",
          status == 200 and len(ids_4d2) == 1
          and nodes.device(ids_4d2[0])["ip"] == "10.37.0.2"
          and ids_4d2[0] != target_4d, (status, result_4d2))
    nodes.remove_device(ids_4d2[0])
    nodes.remove_device(target_4d)

    # ------------------------------------- 5. what the discovery listing says
    print("5. the discovery listing serves the duplicate verdict")
    dup_job = nodes.add_discovery_job("subnet", "10.31.0.0/30")
    high_id = nodes.add_discovery_result(
        dup_job, ip="10.8.8.8", ping_ok=1, snmp_ok=1, sys_name="whatever",
        sys_object_id="1.3.6.1.4.1.1", community_or_user="public", snmp_version=1)
    nodes.seed_identity(existing_id, sys_name="medium-twin",
                        sys_object_id="1.3.6.1.4.1.4242")
    medium_id = nodes.add_discovery_result(
        dup_job, ip="10.31.0.2", ping_ok=1, snmp_ok=1, sys_name="medium-twin",
        sys_object_id="1.3.6.1.4.1.4242", community_or_user="public", snmp_version=1)
    status, dup_listing = call("GET", f"/api/nodes/discovery/{dup_job}", token=admin)
    by_id = {row["id"]: row for row in dup_listing["results"]}
    check("the probed address alone is enough for a high match",
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

    # ------------- 5b. the promote route: force_result_ids vs result_ids
    print("5b. POST .../promote: force_result_ids adds anyway, result_ids folds")
    fresh_high_id = nodes.add_discovery_result(
        dup_job, ip="10.8.8.8", ping_ok=1, snmp_ok=1, sys_name="whatever",
        sys_object_id="1.3.6.1.4.1.1", community_or_user="public", snmp_version=1)
    status, forced_result = call(
        "POST", f"/api/nodes/discovery/{dup_job}/promote",
        {"result_ids": [], "force_result_ids": [fresh_high_id]}, token=admin)
    forced_new_device_id = (forced_result.get("device_ids") or [None])[0]
    check("force_result_ids on a flagged duplicate adds a new device instead of folding",
          status == 200 and forced_new_device_id and forced_new_device_id != existing_id,
          (status, forced_result))
    if forced_new_device_id and forced_new_device_id != existing_id:
        nodes.remove_device(forced_new_device_id)

    other_high_id = nodes.add_discovery_result(
        dup_job, ip="10.8.8.8", ping_ok=1, snmp_ok=1, sys_name="whatever",
        sys_object_id="1.3.6.1.4.1.1", community_or_user="public", snmp_version=1)
    status, folded_result = call(
        "POST", f"/api/nodes/discovery/{dup_job}/promote",
        {"result_ids": [other_high_id]}, token=admin)
    check("result_ids without force still folds a high match",
          status == 200 and folded_result.get("device_ids") == [existing_id],
          (status, folded_result))

    status, empty_body = call(
        "POST", f"/api/nodes/discovery/{dup_job}/promote", {}, token=admin)
    check("an empty promote body is refused", status == 400, (status, empty_body))


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

    # ---------------------------- 7b. a discovered address is not evidence
    print("7b. a discovered address is not duplicate evidence")
    nodes.record_device_addresses(existing_id, ["10.45.0.9"], "discovery")
    status, created = call("POST", "/api/nodes/devices", {"ip": "10.45.0.9"}, token=admin)
    check("a discovery-only alias never blocks a manual add",
          status == 200 and created.get("id"), (status, created))
    nodes.remove_device(created["id"])

    status, imported_fresh = call("POST", "/api/nodes/devices/bulk-import",
                                  {"devices": [{"ip": "10.45.0.9"}]}, token=admin)
    check("...nor a bulk import",
          status == 200 and len(imported_fresh.get("created") or []) == 1
          and not imported_fresh.get("duplicate"), (status, imported_fresh))
    nodes.remove_device(imported_fresh["created"][0]["id"])

    fresh_job = nodes.add_discovery_job("subnet", "10.45.0.0/30")
    fresh_id = nodes.add_discovery_result(
        fresh_job, ip="10.45.0.9", ping_ok=1, snmp_ok=1, sys_name="fresh",
        sys_object_id="1.3.6.1.4.1.5", community_or_user="public", snmp_version=1)
    status, fresh_listing = call("GET", f"/api/nodes/discovery/{fresh_job}", token=admin)
    fresh_row = next(r for r in fresh_listing["results"] if r["id"] == fresh_id)
    check("...nor the discovery listing's duplicate hint",
          not fresh_row.get("duplicate_of_device_id"), fresh_row)
    fresh_devices = service.node_poller.promote(fresh_job, [fresh_id])
    check("...and promote() adds a new device rather than folding",
          len(fresh_devices) == 1 and fresh_devices[0] != existing_id, fresh_devices)
    nodes.remove_device(fresh_devices[0])

    nodes.record_device_addresses(existing_id, ["10.45.0.9"], "ipAddrTable")
    status, refused_fresh = call("POST", "/api/nodes/devices", {"ip": "10.45.0.9"}, token=admin)
    check("a configured alias blocks a manual add with 409 naming the owner",
          status == 409
          and (refused_fresh.get("duplicate_of") or {}).get("device_id") == existing_id,
          (status, refused_fresh))
    status, imported_conf = call("POST", "/api/nodes/devices/bulk-import",
                                 {"devices": [{"ip": "10.45.0.9"}]}, token=admin)
    conf_dup = (imported_conf.get("duplicate") or [{}])[0]
    check("...and bulk import reports it as a duplicate of the same device",
          status == 200 and not imported_conf["created"]
          and conf_dup.get("device_id") == existing_id, (status, imported_conf))

    conf_job = nodes.add_discovery_job("subnet", "10.45.0.4/30")
    conf_id = nodes.add_discovery_result(
        conf_job, ip="10.45.0.9", ping_ok=1, snmp_ok=1, sys_name="fresh2",
        sys_object_id="1.3.6.1.4.1.6", community_or_user="public", snmp_version=1)
    status, conf_listing = call("GET", f"/api/nodes/discovery/{conf_job}", token=admin)
    conf_row = next(r for r in conf_listing["results"] if r["id"] == conf_id)
    check("...and the listing now shows a high-confidence duplicate hint",
          conf_row.get("duplicate_confidence") == "high"
          and conf_row.get("duplicate_of_device_id") == existing_id, conf_row)
    conf_devices = service.node_poller.promote(conf_job, [conf_id])
    check("...and promote() folds onto the existing device instead of adding",
          conf_devices == [existing_id], conf_devices)

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
    check("the loser's primary address is not carried over as a fresh alias",
          not any(row["source"] == "merge" for row in nodes.device_addresses(existing_id)),
          [dict(r) for r in nodes.device_addresses(existing_id)])
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

    # ------------------------------------------- 10. the profile is not an override
    print("10. promote() targets the sweep's own profile, not the suggestion")

    def run_sweep_under(group_id):
        job_id = service.node_poller.start_discovery(
            "device", "127.0.0.1", group_id=group_id,
            overrides={"default_snmp_timeout_s": 1.0, "discovery_communities": "public",
                      "discovery_arc_hop": False})
        for _ in range(100):
            job = nodes.discovery_job(job_id)
            if job["state"] != "running":
                break
            time.sleep(0.1)
        return job_id, nodes.discovery_results(job_id)[0]

    group_match = nodes.add_group("PartA-Match", community="public", snmp_version=1)
    group_diff = nodes.add_group("PartA-Diff", community="secretcomm", snmp_version=1)

    job_match, result_match = run_sweep_under(group_match)
    match_devices = service.node_poller.promote(job_match, [result_match["id"]])
    match_row = nodes.device(match_devices[0])
    check("a sweep under a non-default profile lands the device in that profile",
          match_row["group_id"] == group_match, match_row["group_id"])
    check("...and a discovered community the profile's own credential already "
          "covers is not pinned as an override",
          nodesdb.override_fields(match_row) == (), nodesdb.override_fields(match_row))
    nodes.remove_device(match_devices[0])

    job_diff, result_diff = run_sweep_under(group_diff)
    diff_devices = service.node_poller.promote(job_diff, [result_diff["id"]])
    diff_row = nodes.device(diff_devices[0])
    check("...still lands in the sweep's profile even when its community differs",
          diff_row["group_id"] == group_diff, diff_row["group_id"])
    check("...but a community outside that profile's own credentials is pinned",
          diff_row["community"] == "public" and "community" in nodesdb.override_fields(diff_row),
          (diff_row["community"], nodesdb.override_fields(diff_row)))
    nodes.remove_device(diff_devices[0])

    print("10b. the one-time repair")
    repair_fixed = nodes.add_device("10.50.50.1", group_id=group_match,
                                    community="public", snmp_version=1)
    repair_kept = nodes.add_device("10.50.50.2", group_id=group_diff,
                                   community="public", snmp_version=1)
    fixed_count = nodes.repair_profile_credential_overrides()
    check("the repair clears a community/version pin equal to the device's "
          "own profile", fixed_count == 1, fixed_count)
    repaired = nodes.device(repair_fixed)
    check("...leaving both columns unset on the row it fixed",
          repaired["community"] is None and repaired["snmp_version"] is None,
          (repaired["community"], repaired["snmp_version"]))
    kept = nodes.device(repair_kept)
    check("...and leaving a genuinely different community alone",
          kept["community"] == "public" and kept["snmp_version"] == 1,
          (kept["community"], kept["snmp_version"]))

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
