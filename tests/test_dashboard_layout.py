"""The Dashboard's saved tile arrangement: GET/PUT/DELETE /api/dashboard/layout,
each self-service and per account (appdb.py's `dashboard_layout` column beside
`theme`), _validate_dashboard_layout's rules, and the fleet-wide
/api/nodes/events route the Recent events tile reads. HTTP-level through a
real Service + WebServer over loopback, test_api_helpers.py's own scaffolding.
"""
import http.client
import json
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import permissions
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer
from netpath.web import api as api_mod

TMPDIR = _paths.tmpdir("dashboard_layout_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps",
           "nodes", "alerts", "wireless", "configrx")


def db_paths():
    return [os.path.join(TMPDIR, name + ".db") for name in DB_NAMES]


service = Service(*db_paths())
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
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

    print("1. a fresh account gets the shipped default")
    status, payload = call("GET", "/api/dashboard/layout", token=admin)
    check("GET answers 200", status == 200, (status, payload))
    check("...default is True", payload.get("default") is True, payload)
    default_ids = [t["id"] for t in payload.get("layout", {}).get("tiles", [])]
    check("...the ten shipped tiles, in the documented order",
          default_ids == ["fleet", "open_alerts", "workers", "storage",
                          "top_events", "top_iface_events", "top_alerts",
                          "top_rtt", "top_loss", "top_cpu"], default_ids)

    print("2. PUT round-trips a layout with a note and an iface_traffic tile")
    audit_mark = service.app_db.audit_last_id()
    keep_device = service.nodes_db.add_device("10.60.0.1", name="core-a")
    custom_layout = {
        "version": 1,
        "tiles": [
            {"id": "n1", "type": "note", "w": 2, "h": 1,
             "config": {"title": "Heads up", "text": "line one\nline two"}},
            {"id": "t1", "type": "iface_traffic", "w": 1, "h": 2,
             "config": {"device_id": keep_device, "if_index": 3, "window_s": 21600}},
        ],
    }
    status, payload = call("PUT", "/api/dashboard/layout",
                           {"layout": custom_layout}, token=admin)
    check("PUT answers 200", status == 200, (status, payload))
    check("...default is False now", payload.get("default") is False, payload)
    check("...the layout round-trips exactly", payload.get("layout") == custom_layout,
          payload.get("layout"))

    status, payload = call("GET", "/api/dashboard/layout", token=admin)
    check("GET after PUT sees the saved layout, not the default",
          status == 200 and payload.get("default") is False
          and payload.get("layout") == custom_layout, payload)

    audit_rows = [(r["action"], r["username"])
                  for r in service.app_db.audit_events(audit_mark, 500)]
    check("the PUT wrote a dashboard.layout audit row",
          ("dashboard.layout", DEFAULT_USER) in audit_rows, audit_rows)

    print("3. a second account is isolated and still sees the default")
    service.app_db.add_user("dash-two", hash_password("DashTwoPW2026"), must_change=False)
    service.app_db.set_permissions("dash-two", {"nodes": permissions.READ})
    second = login("dash-two", "DashTwoPW2026")
    status, payload = call("GET", "/api/dashboard/layout", token=second)
    check("a second account's GET is unaffected by the first account's PUT",
          status == 200 and payload.get("default") is True, payload)

    print("4. validation refuses bad layouts with 400")
    bad_cases = [
        ("unknown tile type", {"version": 1, "tiles": [
            {"id": "x", "type": "not_a_type", "w": 1, "h": 1, "config": {}}]}),
        ("width out of range", {"version": 1, "tiles": [
            {"id": "x", "type": "note", "w": 4, "h": 1,
             "config": {"title": "t", "text": ""}}]}),
        ("note text past 2000 chars", {"version": 1, "tiles": [
            {"id": "x", "type": "note", "w": 1, "h": 1,
             "config": {"title": "t", "text": "a" * 2001}}]}),
        ("unknown config key", {"version": 1, "tiles": [
            {"id": "x", "type": "note", "w": 1, "h": 1,
             "config": {"title": "t", "text": "", "bogus": 1}}]}),
        ("duplicate tile ids", {"version": 1, "tiles": [
            {"id": "dup", "type": "note", "w": 1, "h": 1, "config": {"title": "a", "text": ""}},
            {"id": "dup", "type": "note", "w": 1, "h": 1, "config": {"title": "b", "text": ""}},
        ]}),
    ]
    for name, layout in bad_cases:
        status, payload = call("PUT", "/api/dashboard/layout",
                               {"layout": layout}, token=admin)
        check(f"PUT with {name} answers 400", status == 400, (status, payload))

    print("5. DELETE restores the default")
    status, payload = call("DELETE", "/api/dashboard/layout", token=admin)
    check("DELETE answers 200 with the default", status == 200
          and payload.get("default") is True, (status, payload))
    status, payload = call("GET", "/api/dashboard/layout", token=admin)
    check("...and a GET afterwards agrees", status == 200
          and payload.get("default") is True, payload)
    audit_rows = [r["action"] for r in service.app_db.audit_events(audit_mark, 500)]
    check("the DELETE also wrote an audit row",
          audit_rows.count("dashboard.layout") >= 2, audit_rows)

    print("6. the stored layout survives reopening the AppDatabase")
    status, payload = call("PUT", "/api/dashboard/layout",
                           {"layout": custom_layout}, token=admin)
    check("setup: saved a layout to persist", status == 200, (status, payload))
    reopened = Service(*db_paths())
    try:
        reread = api_mod.get_dashboard_layout(
            reopened, {"_username": DEFAULT_USER}, None)
        check("a fresh Service on the same files reads the stored layout back",
              reread.get("default") is False and reread.get("layout") == custom_layout,
              reread)
    finally:
        reopened.shutdown()

    print("7. unit: the shipped default validates unchanged")
    check("_validate_dashboard_layout accepts DEFAULT_DASHBOARD_LAYOUT as-is",
          api_mod._validate_dashboard_layout(api_mod.DEFAULT_DASHBOARD_LAYOUT)
          == api_mod.DEFAULT_DASHBOARD_LAYOUT, api_mod.DEFAULT_DASHBOARD_LAYOUT)

    print("8. GET /api/nodes/events")
    service.app_db.add_user("dash-none", hash_password("DashNonePW2026"), must_change=False)
    service.app_db.set_permissions("dash-none", {})
    no_nodes = login("dash-none", "DashNonePW2026")
    status, payload = call("GET", "/api/nodes/events", token=no_nodes)
    check("/api/nodes/events refuses an account without Nodes read",
          status == 403, (status, payload))

    events_device = service.nodes_db.add_device("10.60.0.2", name="events-sw")
    service.nodes_db.seed_identity(events_device, sys_name="events-sw-sys")
    service.nodes_db.record_device_event(events_device, "device_down", "test outage")
    status, payload = call("GET", "/api/nodes/events", token=admin)
    check("/api/nodes/events answers 200 for admin", status == 200, (status, payload))
    rows = [e for e in payload.get("events", []) if e.get("device_id") == events_device]
    check("...and names the device via namelookup and carries its ip",
          bool(rows) and rows[0].get("device_name") == "events-sw-sys"
          and rows[0].get("ip") == "10.60.0.2" and rows[0].get("kind") == "device_down",
          rows)

finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
