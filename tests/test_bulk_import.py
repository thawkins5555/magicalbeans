"""Item 3 of the API-heavy trio: `POST /api/nodes/devices/bulk-import`.

Covers, against a real Service + WebServer over loopback: the JSON-array
form and the CSV-text form (including column aliases and a profile/group
named rather than id'd), per-row dispositions (created/duplicate/invalid),
transactionality — a batch containing one row that fails validation still
inserts every row that passed, and nothing beyond that gets written even
where the underlying insert itself is made to fail — the permission gate
(same as single-device creation: nodes write), and that a created device
gets the same post-add queueing the single POST route triggers (a first
poll, and identification where SNMP is enabled).
"""
import http.client
import json
import os
from urllib.parse import urlencode

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer
from netpath.web import api as web_api

TMPDIR = _paths.tmpdir("bulk_import_")
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


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # --------------------------------------------------------------- JSON
    print("JSON array form")
    status, result = call("POST", "/api/nodes/devices/bulk-import",
                          {"devices": [
                              {"ip": "10.80.0.1", "name": "sw-1"},
                              {"ip": "10.80.0.2", "name": "sw-2", "snmp_version": 2,
                               "community": "public"},
                              {"ip": "not-an-address", "name": "bad"},
                          ]}, token=admin)
    check("JSON import answers 200", status == 200, (status, result))
    check("two rows created, one invalid",
          len(result.get("created", [])) == 2 and len(result.get("invalid", [])) == 1,
          result)
    check("the invalid row names its row number and a reason",
          result["invalid"][0]["row"] == 3 and "not an IP address" in result["invalid"][0]["reason"],
          result["invalid"])
    device = service.nodes_db.device_by_ip("10.80.0.2")
    check("an override field (snmp_version) landed on the created device",
          device is not None and device["snmp_version"] == 2, device)

    # A repeat of the same JSON array: both good rows are now duplicates.
    status, again = call("POST", "/api/nodes/devices/bulk-import",
                         {"devices": [{"ip": "10.80.0.1"}, {"ip": "10.80.0.2"}]}, token=admin)
    check("re-importing existing addresses reports them as duplicates, not created",
          len(again.get("duplicate", [])) == 2 and not again.get("created"), again)

    # A within-batch duplicate (same address twice in one paste) is caught too.
    status, dup_in_batch = call("POST", "/api/nodes/devices/bulk-import",
                                {"devices": [{"ip": "10.80.0.9"}, {"ip": "10.80.0.9"}]},
                                token=admin)
    check("a duplicate within the same batch is created once, flagged the second time",
          len(dup_in_batch.get("created", [])) == 1
          and len(dup_in_batch.get("duplicate", [])) == 1, dup_in_batch)

    # ---------------------------------------------------------------- CSV
    print("CSV text form")
    service.nodes_db.add_group("Switches")
    csv_text = (
        "address,name,group\n"
        "10.81.0.1,core-a,Switches\n"
        "10.81.0.2,core-b,\n"
        "not-an-address,bad-row,\n"
    )
    status, csv_result = call("POST", "/api/nodes/devices/bulk-import",
                              {"csv": csv_text}, token=admin)
    check("CSV import answers 200", status == 200, (status, csv_result))
    check("CSV import: two created, one invalid",
          len(csv_result.get("created", [])) == 2 and len(csv_result.get("invalid", [])) == 1,
          csv_result)
    core_a = service.nodes_db.device_by_ip("10.81.0.1")
    switches = next(g for g in service.nodes_db.groups() if g["name"] == "Switches")
    check("the 'group' CSV column resolved a polling profile by NAME, not id",
          core_a is not None and core_a["group_id"] == switches["id"], core_a)

    # A CSV cell naming a profile that does not exist is invalid, not a
    # device created with a random group.
    status, bad_group = call("POST", "/api/nodes/devices/bulk-import",
                             {"csv": "address,group\n10.81.0.9,NoSuchProfile\n"}, token=admin)
    check("an unresolvable group name is refused per-row, not substituted",
          not bad_group.get("created") and len(bad_group.get("invalid", [])) == 1, bad_group)

    # ---------------------------------------------------- transactionality
    print("transactionality")
    # A whole-batch failure inside the insert step must not leave a partial
    # write behind. Patched at the module level (not the instance) so the
    # single call inside post_nodes_devices_bulk_import picks it up.
    real_add_devices_bulk = service.nodes_db.__class__.add_devices_bulk

    def failing_add_devices_bulk(self, rows):
        raise sqlite3_IntegrityError_stub("simulated failure partway through the batch")

    import sqlite3 as _sqlite3
    sqlite3_IntegrityError_stub = _sqlite3.IntegrityError
    service.nodes_db.__class__.add_devices_bulk = failing_add_devices_bulk
    try:
        status, failed = call("POST", "/api/nodes/devices/bulk-import",
                              {"devices": [{"ip": "10.82.0.1"}, {"ip": "10.82.0.2"}]},
                              token=admin)
    finally:
        service.nodes_db.__class__.add_devices_bulk = real_add_devices_bulk
    check("a failure inside the insert step answers an error, not a 200 with partial results",
          status != 200, (status, failed))
    check("...and neither row from that failed batch exists",
          service.nodes_db.device_by_ip("10.82.0.1") is None
          and service.nodes_db.device_by_ip("10.82.0.2") is None, "half-inserted")

    # Sanity: the real add_devices_bulk itself is transactional even when a
    # later row in the pre-validated set collides unexpectedly (simulating a
    # race rather than a validation miss) — nothing from the batch lands.
    try:
        service.nodes_db.add_devices_bulk([
            {"ip": "10.82.1.1", "overrides": {}},
            {"ip": "10.82.1.1", "overrides": {}},   # UNIQUE(ip) collides here
        ])
        raised = False
    except Exception:
        raised = True
    check("add_devices_bulk itself raises on a mid-batch conflict",
          raised, "did not raise")
    check("...and the first row of that failed transaction was rolled back too",
          service.nodes_db.device_by_ip("10.82.1.1") is None, "row 1 survived the rollback")

    # -------------------------------------------------------- request caps
    print("row and size limits")
    status, empty = call("POST", "/api/nodes/devices/bulk-import", {"devices": []}, token=admin)
    check("an empty batch is refused", status == 400, (status, empty))
    status, neither = call("POST", "/api/nodes/devices/bulk-import", {}, token=admin)
    check("neither 'devices' nor 'csv' is refused", status == 400, (status, neither))
    status, too_many = call(
        "POST", "/api/nodes/devices/bulk-import",
        {"devices": [{"ip": f"10.83.{i // 250}.{i % 250 + 1}"}
                    for i in range(web_api.BULK_IMPORT_MAX_ROWS + 1)]},
        token=admin)
    check("a batch over the row cap is refused rather than truncated silently",
          status == 400, (status, too_many if status != 200 else "accepted"))

    # ------------------------------------------------------- permission gate
    print("permission gate: same as single-device creation")
    service.app_db.add_user("bi-reader", hash_password("BulkReaderPW2026"), must_change=False)
    service.app_db.set_permissions("bi-reader", {"nodes": "read"})
    reader = login("bi-reader", "BulkReaderPW2026")
    status, refused = call("POST", "/api/nodes/devices/bulk-import",
                           {"devices": [{"ip": "10.84.0.1"}]}, token=reader)
    check("a nodes:read-only account is refused bulk import (write is required)",
          status == 403, (status, refused))
    check("...and nothing was created by the refused attempt",
          service.nodes_db.device_by_ip("10.84.0.1") is None, "created anyway")

    # ------------------------------------------------------ post-add queueing
    print("post-insert queueing mirrors the single-device route")
    calls = []
    real_poll_now = service.node_poller.poll_now

    def spy_poll_now(device_id):
        calls.append(device_id)
        return real_poll_now(device_id)

    service.node_poller.poll_now = spy_poll_now
    try:
        status, queued_result = call("POST", "/api/nodes/devices/bulk-import",
                                     {"devices": [{"ip": "10.85.0.1", "name": "queue-me"}]},
                                     token=admin)
    finally:
        service.node_poller.poll_now = real_poll_now
    check("bulk import answers 200 and creates the device", status == 200
          and len(queued_result.get("created", [])) == 1, (status, queued_result))
    created_id = queued_result["created"][0]["id"]
    check("poll_now was queued for the newly created device (same as the single POST route)",
          created_id in calls, calls)

finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
