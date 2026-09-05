"""4.49.0: the routes on top of netpath/configrx_search.py (cross-device
config search) and netpath/configrx_compliance.py (compliance rule sets) —
both modules' own correctness, redaction and regex-safety guarantees are
covered by test_configrx_search_compliance.py; this suite is the thin
dispatch layer, driven against a real Service+WebServer: query-string
parsing, an UnsafeRegex reaching the ordinary ValueError->400 path
unchanged, rule-set/rule CRUD plus their audit lines, the manual evaluate
route, and both compliance-results read routes.

Search lines are seeded directly via replace_search_lines() — the same
shortcut every other suite in this repo takes for data a live poll would
otherwise produce (test_nodes_topology.py's neighbour rows, and so on) —
since populating them for real means a live SSH capture through
ConfigRxWorker, which is not what this suite is testing.
"""
import http.client
import json
import os
import time
from urllib.parse import urlencode

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("configrx_search_routes_")
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

    dev1 = db.add_device("10.95.0.1", name="cx-search-1", group_id=gid)
    dev2 = db.add_device("10.95.0.2", name="cx-search-2", group_id=gid)
    service.configrx_db.replace_search_lines(
        dev1, "hostname cx-search-1\nntp server 10.1.1.1\nsnmp-server community public RO\n")
    service.configrx_db.replace_search_lines(
        dev2, "hostname cx-search-2\nntp server 10.2.2.2\n")

    # -------------------------------------------------------------- search
    print("GET /api/configrx/search")
    status, payload = call("GET", "/api/configrx/search?query=ntp", token=admin)
    check("200", status == 200, (status, payload))
    check("both devices' ntp lines matched, with device_name/ip hydrated",
          status == 200 and len(payload["matches"]) == 2
          and all(m["device_name"] and m["device_ip"] for m in payload["matches"]),
          payload)

    status, payload = call("GET", f"/api/configrx/search?query=ntp&device={dev1}", token=admin)
    check("device= narrows the search to one device",
          status == 200 and len(payload["matches"]) == 1
          and payload["matches"][0]["device_id"] == dev1, payload)

    status, payload = call("GET", "/api/configrx/search", token=admin)
    check("missing query is a 400", status == 400, (status, payload))

    status, payload = call(
        "GET", "/api/configrx/search?" + urlencode({"query": "(a|aa)+", "mode": "regex"}),
        token=admin)
    check("an unsafe regex pattern reaches a plain 400, not a 500",
          status == 400 and "repeats a group" in str(payload.get("error", "")),
          (status, payload))

    status, payload = call(
        "GET", "/api/configrx/search?" + urlencode(
            {"query": r"ntp server \d+\.\d+\.\d+\.\d+", "mode": "regex"}),
        token=admin)
    check("a safe regex pattern runs and matches",
          status == 200 and len(payload["matches"]) == 2, (status, payload))

    # ---------------------------------------------------------- rule sets
    print("rule set create / read / update / delete")
    status, payload = call("POST", "/api/configrx/rule-sets",
                           {"name": "Baseline"}, token=admin)
    check("200", status == 200, (status, payload))
    rule_set_id = payload["id"]

    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}", token=admin)
    check("200, name round-trips",
          status == 200 and payload["rule_set"]["name"] == "Baseline", (status, payload))

    status, payload = call("GET", "/api/configrx/rule-sets", token=admin)
    check("the new rule set appears in the list",
          status == 200 and any(r["id"] == rule_set_id for r in payload["rule_sets"]),
          payload)

    status, payload = call("PUT", f"/api/configrx/rule-sets/{rule_set_id}",
                           {"enabled": False}, token=admin)
    check("200", status == 200, (status, payload))
    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}", token=admin)
    check("the update actually applied", payload["rule_set"]["enabled"] == 0, payload)
    rows = service.app_db.audit_query(0, time.time() + 60,
                                      action="configrx.rule_set.update", target="Baseline")
    check("rule_set.update audited", bool(rows), rows)

    # ------------------------------------------------------------- rules
    print("rule create (with safe pattern) / unsafe pattern refused / delete")
    status, payload = call("POST", f"/api/configrx/rule-sets/{rule_set_id}/rules",
                           {"description": "NTP must be configured",
                            "kind": "must_match", "pattern": "^ntp server "},
                           token=admin)
    check("200", status == 200, (status, payload))
    rule_id = payload["id"]

    status, payload = call("POST", f"/api/configrx/rule-sets/{rule_set_id}/rules",
                           {"description": "bad pattern", "kind": "must_match",
                            "pattern": "(a|aa)+"}, token=admin)
    check("an unsafe rule pattern is refused at creation, never stored",
          status == 400, (status, payload))

    status, payload = call("POST", f"/api/configrx/rule-sets/{rule_set_id}/rules",
                           {"description": "bad kind", "kind": "nonsense",
                            "pattern": "x"}, token=admin)
    check("an invalid kind is refused", status == 400, (status, payload))

    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}/rules", token=admin)
    check("exactly the one valid rule was stored",
          status == 200 and len(payload["rules"]) == 1
          and payload["rules"][0]["id"] == rule_id, payload)

    # --------------------------------------------------- evaluate + results
    print("evaluate + results")
    # Re-enable — evaluate_all only considers enabled rule sets.
    call("PUT", f"/api/configrx/rule-sets/{rule_set_id}", {"enabled": True}, token=admin)
    backup1_id, _ = service.configrx_db.add_backup(dev1, "hostname cx-search-1\nntp server 10.1.1.1\n")
    backup2_id, _ = service.configrx_db.add_backup(dev2, "hostname cx-search-2\nno ntp here\n")

    status, payload = call("POST", f"/api/configrx/rule-sets/{rule_set_id}/evaluate",
                           token=admin)
    check("200, both devices evaluated", status == 200 and payload["evaluated"] == 2,
          (status, payload))

    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}/results", token=admin)
    check("200", status == 200, (status, payload))
    results_by_device = {r["device_id"]: r for r in payload["results"]}
    check("dev1 (has the ntp line) passes",
          results_by_device.get(dev1, {}).get("status") == "pass", results_by_device.get(dev1))
    check("dev2 (missing it) fails, with the rule's description in failed_rules",
          results_by_device.get(dev2, {}).get("status") == "fail"
          and results_by_device[dev2]["failed_rules"]
          and results_by_device[dev2]["failed_rules"][0]["description"] == "NTP must be configured",
          results_by_device.get(dev2))

    status, payload = call(f"GET", f"/api/configrx/devices/{dev2}/compliance", token=admin)
    check("the per-device compliance view agrees with the per-rule-set one",
          status == 200 and len(payload["results"]) == 1
          and payload["results"][0]["status"] == "fail", payload)

    status, payload = call("DELETE",
                           f"/api/configrx/rule-sets/{rule_set_id}/rules/{rule_id}",
                           token=admin)
    check("rule delete: 200", status == 200, (status, payload))
    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}/rules", token=admin)
    check("...and it's actually gone", status == 200 and payload["rules"] == [], payload)

    status, payload = call("DELETE", f"/api/configrx/rule-sets/{rule_set_id}", token=admin)
    check("rule set delete: 200", status == 200, (status, payload))
    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}", token=admin)
    check("...and it's actually gone", status == 400, (status, payload))

    # -------------------------------------------------------------- gates
    print("gates: configrx:read may search/read, may not write; no grant refused both")
    service.app_db.add_user("cx-search-reader", hash_password("CxSearchReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("cx-search-reader", {"configrx": "read"})
    reader = login("cx-search-reader", "CxSearchReaderPW2026")
    service.app_db.add_user("cx-search-outsider", hash_password("CxSearchOutsiderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("cx-search-outsider", {"syslog": "read"})
    outsider = login("cx-search-outsider", "CxSearchOutsiderPW2026")

    status, payload = call("GET", "/api/configrx/search?query=ntp", token=reader)
    check("a configrx:read account may search", status == 200, (status, payload))
    status, payload = call("GET", "/api/configrx/search?query=ntp", token=outsider)
    check("an account with no configrx grant is refused search", status == 403, (status, payload))

    status, payload = call("POST", "/api/configrx/rule-sets", {"name": "reader-set"}, token=reader)
    check("a configrx:read account may NOT create a rule set (needs write)",
          status == 403, (status, payload))

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)
