"""4.50.0: a compliance rule's pattern can BE the secret it checks for — the
Add-rule dialog says so outright ("a rule can check a secret's actual
value") — so GET /api/configrx/rule-sets/{id}/rules must gate the `pattern`
field the same way get_configrx_backup already gates unredacted backup
content: a configrx:read account (no write) gets every other field but not
the pattern itself, while a configrx:write account round-trips it unchanged.
Before this fix the route returned `pattern` verbatim to any configrx read,
letting a reader pull the same secret out of the rule that checks for it
even though the equivalent backup route already refused them the value.

This suite is deliberately narrow (just the permission boundary on one
field) rather than duplicating test_configrx_search_routes.py's broader rule
CRUD coverage.
"""
import http.client
import json
import os

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("configrx_rule_pattern_permission_")
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

    service.app_db.add_user("cxrp-reader", hash_password("CxRpReaderPW2026"), must_change=False)
    service.app_db.set_permissions("cxrp-reader", {"configrx": "read"})
    reader = login("cxrp-reader", "CxRpReaderPW2026")

    service.app_db.add_user("cxrp-writer", hash_password("CxRpWriterPW2026"), must_change=False)
    service.app_db.set_permissions("cxrp-writer", {"configrx": "write"})
    writer = login("cxrp-writer", "CxRpWriterPW2026")

    status, payload = call("POST", "/api/configrx/rule-sets",
                           {"name": "Secret pattern check"}, token=admin)
    check("rule set created", status == 200, (status, payload))
    rule_set_id = payload["id"]

    secret_pattern = "snmp-server community S3cr3tRO"
    status, payload = call("POST", f"/api/configrx/rule-sets/{rule_set_id}/rules",
                           {"description": "No default SNMP community",
                            "kind": "must_match", "pattern": secret_pattern},
                           token=admin)
    check("rule created", status == 200, (status, payload))
    rule_id = payload["id"]
    check("rule creation response itself never echoes the pattern back",
          "pattern" not in payload, payload)

    # ------------------------------------------------- the boundary itself
    print("GET rules: configrx:read never sees the raw pattern")
    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}/rules", token=reader)
    check("200", status == 200, (status, payload))
    rules = payload.get("rules", [])
    check("exactly the one rule came back", len(rules) == 1, rules)
    row = rules[0] if rules else {}
    check("the secret pattern text is not present anywhere in the response",
          secret_pattern not in json.dumps(payload), payload)
    check("pattern is null, not the value, for a read-only account",
          row.get("pattern") is None, row)
    check("pattern_hidden says WHY, so an empty pattern doesn't read as "
          "\"this rule has no pattern\"",
          row.get("pattern_hidden") is True, row)
    check("identity and results-relevant fields still come through",
          row.get("id") == rule_id and row.get("kind") == "must_match"
          and row.get("description") == "No default SNMP community", row)

    print("GET rules: configrx:write still gets the pattern verbatim")
    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}/rules", token=writer)
    check("200", status == 200, (status, payload))
    row = payload["rules"][0]
    check("pattern round-trips unchanged for a write account",
          row.get("pattern") == secret_pattern, row)
    check("pattern_hidden is absent/false when the pattern is actually shown",
          not row.get("pattern_hidden"), row)

    print("GET rules: admin (write) matches the writer case")
    status, payload = call("GET", f"/api/configrx/rule-sets/{rule_set_id}/rules", token=admin)
    check("200 and pattern visible", status == 200
          and payload["rules"][0].get("pattern") == secret_pattern, payload)

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)
