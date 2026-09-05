"""4.49.0: the upstream-suggestions review flow (nodesdb.upstream_suggestions/
set_upstream_ids, and the two /api/nodes/upstream-suggestions routes on top).

alertrules.py:250-266 explains why the LLDP/CDP neighbour match nodesdb
already computes may never drive alert rollup by itself — it is a
best-effort guess, and only an operator-confirmed devices.upstream_id may
be trusted there. What was missing was the means for an operator to turn
one of those guesses into an upstream_id at fleet scale instead of visiting
2,000 Edit dialogs one at a time. This suite is that means, driven against a
real Service and WebServer over loopback, with neighbour/interface rows
seeded directly through nodesdb's own accessors (test_nodes_topology.py's
own shortcut) rather than a live SNMP walk.

Covers:
  - A clean single-match suggestion (chassis-MAC match, both present and
    stale, plus a plain sysName-only match) carries the right match_kind
    and confidence, and is not `ambiguous`.
  - A device whose neighbour rows resolve to two different real devices
    comes back `ambiguous`, both candidates listed, neither picked.
  - A stale neighbour row (present=0) is marked `stale` and scored down
    rather than treated as equally trustworthy as a fresh one.
  - POST .../apply refuses a batch that would create a two-device cycle,
    and separately one that would create a three-device cycle — neither
    individual pair is invalid on its own, only the batch together.
  - A valid batch applies in one call and the assigned devices drop out of
    the suggestions list on the next read.
  - Both routes are gated ("nodes", read/write as appropriate): a
    nodes:read account may read but not apply; an account with no nodes
    grant at all is refused both.
"""
import http.client
import json
import os
import time

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("upstream_suggestions_")
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
    data = json.dumps(body).encode() if (method != "GET" and body is not None) else None
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
    db = service.nodes_db
    gid = db.ensure_default_group()

    # -------------------------------------------------------------- devices
    core_id = db.add_device("10.50.0.1", name="core-sw-1", group_id=gid)
    dist_id = db.add_device("10.50.0.2", name="dist-sw-1", group_id=gid)
    access_id = db.add_device("10.50.0.3", name="access-sw-1", group_id=gid)
    named_only_id = db.add_device("10.50.0.4", name="named-only-sw", group_id=gid)
    observer_id = db.add_device("10.50.0.5", name="observer-sw", group_id=gid)

    db.replace_interfaces(core_id, [
        {"if_index": 1, "descr": "Gi0/1", "phys_addr": "aa:aa:aa:aa:aa:01"}])
    db.replace_interfaces(dist_id, [
        {"if_index": 5, "descr": "Gi0/5", "phys_addr": "bb:bb:bb:bb:bb:05"}])

    # access-sw-1 sees only core-sw-1 (chassis-MAC match) -> clean suggestion.
    db.replace_neighbors(access_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "aa:aa:aa:aa:aa:01", "chassis_id_subtype": 4,
         "sys_name": "core-sw-1", "port_id": "Gi0/1"},
    ])
    # observer-sw sees only named-only-sw, which has no interfaces at all —
    # sysName is the only evidence a join can offer here.
    db.replace_neighbors(observer_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "", "chassis_id_subtype": None,
         "sys_name": "named-only-sw", "port_id": "Gi0/1"},
    ])

    print("GET /api/nodes/upstream-suggestions — clean single-match + sysName-only")
    status, payload = call("GET", "/api/nodes/upstream-suggestions", token=admin)
    check("200", status == 200, (status, payload))
    by_device = {s["device_id"]: s for s in payload.get("suggestions", [])}
    check("access-sw-1 got a suggestion", access_id in by_device, by_device)
    if access_id in by_device:
        s = by_device[access_id]
        check("...not ambiguous, one candidate naming core-sw-1",
              not s["ambiguous"] and len(s["candidates"]) == 1
              and s["candidates"][0]["matched_device_id"] == core_id, s)
        check("...match_kind is chassis_mac, confidence high, not stale",
              s["candidates"][0]["match_kind"] == "chassis_mac"
              and s["candidates"][0]["confidence"] == "high"
              and s["candidates"][0]["stale"] is False, s)
        check("...local_port labelled from access-sw-1's own interface",
              s["candidates"][0]["local_if_index"] == 1, s)
    check("observer-sw got a suggestion naming named-only-sw by sysName",
          observer_id in by_device
          and not by_device[observer_id]["ambiguous"]
          and by_device[observer_id]["candidates"][0]["matched_device_id"] == named_only_id
          and by_device[observer_id]["candidates"][0]["match_kind"] == "sys_name",
          by_device.get(observer_id))

    # ---------------------------------------------------------- ambiguous
    print("an ambiguous device (two distinct matched candidates)")
    db.replace_neighbors(access_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "aa:aa:aa:aa:aa:01", "chassis_id_subtype": 4,
         "sys_name": "core-sw-1", "port_id": "Gi0/1"},
        {"if_index": 2, "protocol": "lldp", "rem_index": "0.2.1",
         "chassis_id": "bb:bb:bb:bb:bb:05", "chassis_id_subtype": 4,
         "sys_name": "dist-sw-1", "port_id": "Gi0/5"},
    ])
    status, payload = call("GET", "/api/nodes/upstream-suggestions", token=admin)
    by_device = {s["device_id"]: s for s in payload.get("suggestions", [])}
    s = by_device.get(access_id)
    check("access-sw-1 is now ambiguous with both candidates listed",
          s is not None and s["ambiguous"]
          and {c["matched_device_id"] for c in s["candidates"]} == {core_id, dist_id},
          s)

    # -------------------------------------------------------------- stale
    print("a stale neighbour row is marked stale and scored down")
    db.replace_neighbors(access_id, [
        {"if_index": 2, "protocol": "lldp", "rem_index": "0.2.1",
         "chassis_id": "bb:bb:bb:bb:bb:05", "chassis_id_subtype": 4,
         "sys_name": "dist-sw-1", "port_id": "Gi0/5"},
    ])
    status, payload = call("GET", "/api/nodes/upstream-suggestions", token=admin)
    by_device = {s["device_id"]: s for s in payload.get("suggestions", [])}
    s = by_device.get(access_id)
    core_cand = next((c for c in (s or {}).get("candidates", [])
                      if c["matched_device_id"] == core_id), None)
    check("the core-sw-1 candidate is now marked stale",
          core_cand is not None and core_cand["stale"] is True
          and core_cand["present"] is False, core_cand)
    check("...and scored below the still-fresh dist-sw-1 candidate",
          core_cand is not None
          and core_cand["confidence_rank"] <
              next(c["confidence_rank"] for c in s["candidates"]
                   if c["matched_device_id"] == dist_id), s)

    # restore a single clean match on access-sw-1 for the apply tests below
    db.replace_neighbors(access_id, [
        {"if_index": 1, "protocol": "lldp", "rem_index": "0.1.1",
         "chassis_id": "aa:aa:aa:aa:aa:01", "chassis_id_subtype": 4,
         "sys_name": "core-sw-1", "port_id": "Gi0/1"},
    ])

    # ------------------------------------------------------ cycle rejection
    print("POST .../apply refuses a batch that would create a 2-device cycle")
    pair_a = db.add_device("10.50.1.1", name="pair-a", group_id=gid)
    pair_b = db.add_device("10.50.1.2", name="pair-b", group_id=gid)
    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [
            {"device_id": pair_a, "upstream_id": pair_b},
            {"device_id": pair_b, "upstream_id": pair_a},
        ]}, token=admin)
    check("400 refused", status == 400, (status, payload))
    check("...naming both devices in the cycle",
          str(pair_a) in str(payload.get("error", ""))
          and str(pair_b) in str(payload.get("error", "")), payload)
    check("...and neither assignment was actually applied",
          db.device(pair_a)["upstream_id"] is None
          and db.device(pair_b)["upstream_id"] is None,
          (db.device(pair_a)["upstream_id"], db.device(pair_b)["upstream_id"]))

    print("POST .../apply refuses a batch that would create a 3-device cycle")
    tri_a = db.add_device("10.50.1.3", name="tri-a", group_id=gid)
    tri_b = db.add_device("10.50.1.4", name="tri-b", group_id=gid)
    tri_c = db.add_device("10.50.1.5", name="tri-c", group_id=gid)
    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [
            {"device_id": tri_a, "upstream_id": tri_b},
            {"device_id": tri_b, "upstream_id": tri_c},
            {"device_id": tri_c, "upstream_id": tri_a},
        ]}, token=admin)
    check("400 refused", status == 400, (status, payload))
    error_text_ = str(payload.get("error", ""))
    check("...naming all three devices in the cycle",
          all(str(d) in error_text_ for d in (tri_a, tri_b, tri_c)), payload)
    check("...and none of the three were applied",
          all(db.device(d)["upstream_id"] is None for d in (tri_a, tri_b, tri_c)),
          [db.device(d)["upstream_id"] for d in (tri_a, tri_b, tri_c)])

    # A 3-cycle where only two of the three edges are in THIS batch (the
    # third comes from what is already on file) must be caught too — not
    # just cycles made entirely of new edges.
    print("...and a cycle completed by an edge already on file, not just new ones")
    chain_a = db.add_device("10.50.1.6", name="chain-a", group_id=gid)
    chain_b = db.add_device("10.50.1.7", name="chain-b", group_id=gid)
    chain_c = db.add_device("10.50.1.8", name="chain-c", group_id=gid)
    db.set_upstream_ids({chain_c: chain_a})   # already on file: C -> A
    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [
            {"device_id": chain_a, "upstream_id": chain_b},
            {"device_id": chain_b, "upstream_id": chain_c},
        ]}, token=admin)
    check("400 refused", status == 400, (status, payload))
    check("...and chain-a's upstream was not overwritten",
          db.device(chain_a)["upstream_id"] is None, db.device(chain_a))

    # --------------------------------------------------------- valid apply
    print("a valid batch applies, and assigned devices drop out of the list")
    status, payload = call("GET", "/api/nodes/upstream-suggestions", token=admin)
    before_ids = {s["device_id"] for s in payload.get("suggestions", [])}
    check("access-sw-1 is offered before the apply", access_id in before_ids, before_ids)

    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [{"device_id": access_id, "upstream_id": core_id}]}, token=admin)
    check("200 ok, one updated", status == 200 and payload == {"ok": True, "updated": 1},
          (status, payload))
    check("the device row itself now carries the upstream_id",
          db.device(access_id)["upstream_id"] == core_id, db.device(access_id))

    status, payload = call("GET", "/api/nodes/upstream-suggestions", token=admin)
    after_ids = {s["device_id"] for s in payload.get("suggestions", [])}
    check("access-sw-1 no longer appears once it has an upstream_id",
          access_id not in after_ids, after_ids)

    # ------------------------------------------------------- bad references
    print("basic validation: unknown device_id and self-reference are refused")
    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [{"device_id": 999999, "upstream_id": core_id}]}, token=admin)
    check("400 for an unknown device_id", status == 400, (status, payload))
    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [{"device_id": dist_id, "upstream_id": dist_id}]}, token=admin)
    check("400 for a device pointed at itself", status == 400, (status, payload))

    # -------------------------------------------------------------- gates
    print("gates: nodes:read may GET but not POST; no grant is refused both")
    service.app_db.add_user("upstream-reader", hash_password("UpstreamReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("upstream-reader", {"nodes": "read"})
    reader = login("upstream-reader", "UpstreamReaderPW2026")
    service.app_db.add_user("upstream-outsider", hash_password("UpstreamOutsiderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("upstream-outsider", {"syslog": "read"})
    outsider = login("upstream-outsider", "UpstreamOutsiderPW2026")

    status, payload = call("GET", "/api/nodes/upstream-suggestions", token=reader)
    check("a nodes:read account may GET the suggestions list", status == 200, (status, payload))
    status, payload = call("GET", "/api/nodes/upstream-suggestions", token=outsider)
    check("an account with no nodes grant is refused the GET",
          status == 403, (status, payload))

    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [{"device_id": dist_id, "upstream_id": core_id}]}, token=reader)
    check("a nodes:read account may NOT POST apply (needs write)",
          status == 403, (status, payload))
    status, payload = call("POST", "/api/nodes/upstream-suggestions/apply", {
        "assignments": [{"device_id": dist_id, "upstream_id": core_id}]}, token=outsider)
    check("an account with no nodes grant is refused the POST too",
          status == 403, (status, payload))

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)
