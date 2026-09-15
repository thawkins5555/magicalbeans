"""The Dashboard's saved tile arrangement: GET/PUT/DELETE /api/dashboard/layout,
each self-service and per account (appdb.py's `dashboard_layout` column beside
`theme`), _validate_dashboard_layout's rules, and the fleet-wide
/api/nodes/events route the Recent events tile reads. HTTP-level through a
real Service + WebServer over loopback, test_api_helpers.py's own scaffolding.
"""
import csv
import http.client
import io
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


def parse_csv(text):
    if text.startswith("﻿"):
        text = text[1:]
    return list(csv.reader(io.StringIO(text)))


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

    status, payload = call("PUT", "/api/dashboard/layout", {"layout": {
        "version": 1, "tiles": [{"id": "s1", "type": "note", "w": 1, "h": 1,
                                 "config": {"title": "second's own", "text": ""}}]}},
                           token=second)
    check("setup: the second account saves its own layout", status == 200, (status, payload))
    status, payload = call("GET", "/api/dashboard/layout", token=admin)
    check("...and the first account's own layout is unaffected by it either way",
          status == 200 and payload.get("layout") == custom_layout, payload)

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
        ("w: true (a bool, not the int 1)", {"version": 1, "tiles": [
            {"id": "x", "type": "note", "w": True, "h": 1,
             "config": {"title": "t", "text": ""}}]}),
        ("n: true for ipam_subnets (a bool, not an int)", {"version": 1, "tiles": [
            {"id": "x", "type": "ipam_subnets", "w": 1, "h": 1, "config": {"n": True}}]}),
        ("h out of range", {"version": 1, "tiles": [
            {"id": "x", "type": "note", "w": 1, "h": 3,
             "config": {"title": "t", "text": ""}}]}),
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

    print("9. a stored layout that will not parse degrades to the default")
    service.app_db.set_user_dashboard_layout(DEFAULT_USER, "{not json")
    status, payload = call("GET", "/api/dashboard/layout", token=admin)
    check("garbage stored JSON: GET still answers 200, never 500",
          status == 200, (status, payload))
    check("...reported as the default layout",
          payload.get("default") is True
          and payload.get("layout") == api_mod.DEFAULT_DASHBOARD_LAYOUT, payload)

    service.app_db.set_user_dashboard_layout(
        DEFAULT_USER, json.dumps({"version": 2, "tiles": []}))
    status, payload = call("GET", "/api/dashboard/layout", token=admin)
    check("a stored layout from a future version also degrades to the default",
          status == 200 and payload.get("default") is True, payload)

    print("10. iface_traffic tolerates a null device_id and an absent one")
    for label, config in (
            ("device_id: null", {"device_id": None, "if_index": 3, "window_s": 3600}),
            ("device_id absent", {"if_index": 3, "window_s": 3600})):
        layout = {"version": 1, "tiles": [
            {"id": "it1", "type": "iface_traffic", "w": 1, "h": 1, "config": config}]}
        status, payload = call("PUT", "/api/dashboard/layout",
                               {"layout": layout}, token=admin)
        check(f"iface_traffic with {label} is accepted, not a 400",
              status == 200
              and "device_id" not in payload["layout"]["tiles"][0]["config"],
              (status, payload))

    print("11. GET /api/nodes/events")
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

    print("12. iface_traffic: interfaces list, name, y_max, t0/t1, widened window_s")

    def put_tile(config, tile_type="iface_traffic"):
        layout = {"version": 1, "tiles": [
            {"id": "sch1", "type": tile_type, "w": 1, "h": 1, "config": config}]}
        return call("PUT", "/api/dashboard/layout", {"layout": layout}, token=admin)

    second_device = service.nodes_db.add_device("10.60.0.3", name="core-b")

    good_cases = [
        ("a legacy single-interface config",
         {"device_id": keep_device, "if_index": 3, "window_s": 3600}),
        ("an interfaces list of two",
         {"interfaces": [{"device_id": keep_device, "if_index": 1},
                         {"device_id": second_device, "if_index": 2}]}),
        ("a name at the 60-char limit", {"name": "x" * 60}),
        ("y_max 0 (auto)", {"y_max": 0}),
        ("y_max at the 10**13 ceiling", {"y_max": 10**13}),
        ("window_s 900 (new: 15 minutes)", {"window_s": 900}),
        ("window_s 2592000 (new: 30 days)", {"window_s": 2592000}),
        ("a pinned t0/t1 range", {"t0": 1000, "t1": 5000}),
    ]
    for name, config in good_cases:
        status, payload = put_tile(config)
        check(f"iface_traffic accepts {name}", status == 200, (status, payload))

    bad_iface_cases = [
        ("interfaces: empty list", {"interfaces": []}),
        ("interfaces: 9 entries (over the 8 max)",
         {"interfaces": [{"device_id": keep_device, "if_index": i} for i in range(9)]}),
        ("interfaces: a duplicate device/if_index pair",
         {"interfaces": [{"device_id": keep_device, "if_index": 1},
                         {"device_id": keep_device, "if_index": 1}]}),
        ("interfaces: wrong shape (missing if_index)",
         {"interfaces": [{"device_id": keep_device}]}),
        ("interfaces: an extra key beyond device_id/if_index",
         {"interfaces": [{"device_id": keep_device, "if_index": 1, "extra": 1}]}),
        ("interfaces: string ids instead of ints",
         {"interfaces": [{"device_id": str(keep_device), "if_index": "1"}]}),
        ("name over 60 chars", {"name": "x" * 61}),
        ("y_max negative", {"y_max": -1}),
        ("y_max above the 10**13 ceiling", {"y_max": 10**13 + 1}),
        ("y_max as a bool, not an int", {"y_max": True}),
        ("window_s not in the allowed set", {"window_s": 120}),
        ("t0 without t1", {"t0": 1000}),
        ("t1 without t0", {"t1": 5000}),
        ("t1 <= t0", {"t0": 5000, "t1": 5000}),
        ("a span over 120 days", {"t0": 0, "t1": 2592000 * 4 + 1}),
        ("an unknown config key", {"bogus_key": 1}),
        # Documents the contract dashboard.js's sanitizedLayout and app.js's
        # rangeDialog round for: _dash_int refuses a non-int t0/t1.
        ("t0 as a float", {"t0": 1000.5, "t1": 5000}),
    ]
    for name, config in bad_iface_cases:
        status, payload = put_tile(config)
        check(f"iface_traffic rejects {name}", status == 400, (status, payload))

    print("12b. device_metric: name, y_max, t0/t1 too")
    good_metric_cases = [
        ("name at the 60-char limit",
         {"device_id": keep_device, "metric_key": "cpu_pct", "name": "y" * 60}),
        ("y_max at the 10**15 ceiling",
         {"device_id": keep_device, "metric_key": "cpu_pct", "y_max": 10**15}),
        ("a pinned t0/t1 range",
         {"device_id": keep_device, "metric_key": "cpu_pct", "t0": 1000, "t1": 5000}),
        ("y_max 0.5 (a fractional unit)",
         {"device_id": keep_device, "metric_key": "cpu_pct", "y_max": 0.5}),
    ]
    for name, config in good_metric_cases:
        status, payload = put_tile(config, tile_type="device_metric")
        check(f"device_metric accepts {name}", status == 200, (status, payload))

    bad_metric_cases = [
        ("name over 60 chars", {"metric_key": "cpu_pct", "name": "y" * 61}),
        ("y_max above the 10**15 ceiling",
         {"metric_key": "cpu_pct", "y_max": 10**15 + 1}),
        ("t1 <= t0", {"metric_key": "cpu_pct", "t0": 5000, "t1": 5000}),
    ]
    for name, config in bad_metric_cases:
        status, payload = put_tile(config, tile_type="device_metric")
        check(f"device_metric rejects {name}", status == 400, (status, payload))

    print("13. GET /api/nodes/series/batch")
    batch_device = service.nodes_db.add_device("10.60.0.4", name="batch-sw")
    service.nodes_db.replace_interfaces(batch_device, [
        {"if_index": 1, "descr": "Gi0/1", "alias": "uplink"},
        {"if_index": 2, "descr": "", "alias": "srv-2"},
    ])
    service.nodes_db.record_metric_sample(
        batch_device, "if_in_bps.1", "Gi0/1 in_bps", "bps", "gauge",
        time.time() - 30, 1000.0)
    service.nodes_db.record_metric_sample(
        batch_device, "if_out_bps.1", "Gi0/1 out_bps", "bps", "gauge",
        time.time() - 30, 2000.0)
    service.nodes_db.record_metric_sample(
        batch_device, "cpu_pct", "CPU", "%", "gauge", time.time() - 30, 42.0)

    status, payload = call(
        "GET", f"/api/nodes/series/batch?q={batch_device}:if_in_bps.1,"
              f"{batch_device}:if_out_bps.1", token=admin)
    check("batch: two metrics for one device return two series",
          status == 200 and len(payload.get("series", [])) == 2, (status, payload))
    series_by_key = {s["metric_key"]: s for s in payload.get("series", [])}
    check("...ports are labelled from the interface's descr",
          series_by_key.get("if_in_bps.1", {}).get("label") == "Gi0/1", series_by_key)
    check("...each carries its device_name and unit",
          series_by_key.get("if_in_bps.1", {}).get("device_name") == "batch-sw"
          and series_by_key.get("if_in_bps.1", {}).get("unit") == "bps", series_by_key)
    check("...and actual points",
          len(series_by_key.get("if_in_bps.1", {}).get("points", [])) >= 1, series_by_key)

    status, payload = call(
        "GET", f"/api/nodes/series/batch?q={batch_device}:no_such_metric_key",
        token=admin)
    check("batch: an unknown metric key answers 200 with empty points, not 404",
          status == 200 and payload["series"][0]["points"] == []
          and payload["series"][0]["label"] == "no_such_metric_key", (status, payload))

    status, payload = call(
        "GET", "/api/nodes/series/batch?q=999999:cpu_pct", token=admin)
    check("batch: an unknown device also answers empty points, not 404",
          status == 200 and payload["series"][0]["points"] == []
          and payload["series"][0]["device_name"] == "", (status, payload))

    q17 = ",".join(f"{batch_device}:cpu_pct" for _ in range(17))
    status, payload = call("GET", f"/api/nodes/series/batch?q={q17}", token=admin)
    check("batch: 17 entries is refused (400), the cap is 16",
          status == 400, (status, payload))

    status, payload = call(
        "GET", "/api/nodes/series/batch?q=not-a-valid-entry", token=admin)
    check("batch: a malformed q entry is refused (400)", status == 400, (status, payload))

    status, payload = call("GET", "/api/nodes/series/batch", token=admin)
    check("batch: q is required", status == 400, (status, payload))

    status, payload = call(
        "GET", f"/api/nodes/series/batch?q={batch_device}:cpu_pct", token=no_nodes)
    check("batch: refuses an account without Nodes read", status == 403, (status, payload))

    print("14. GET /api/nodes/series/export.csv (E2)")
    status, exported = call(
        "GET", f"/api/nodes/series/export.csv?q={batch_device}:if_in_bps.1,"
              f"{batch_device}:if_out_bps.1", token=admin)
    check("export: answers 200", status == 200, (status, exported))
    rows = parse_csv(exported["csv"])
    check("export: long-format header",
          rows[0] == ["time", "ts", "device", "metric", "unit", "value", "min", "max"],
          rows[0])
    check("export: one row per point per series (both series have samples)",
          len(rows) - 1 == 2, rows)
    # In q= order (if_in_bps.1 then if_out_bps.1); both share the port's own
    # label ("Gi0/1", the batch route's own answer -- in/out are told apart
    # by column position there, not by the label text).
    in_row, out_row = rows[1], rows[2]
    check("export: device/metric/unit/value line up with the batch route's own answer",
          in_row[2] == "batch-sw" and in_row[3] == "Gi0/1" and in_row[4] == "bps"
          and float(in_row[5]) == 1000.0 and float(out_row[5]) == 2000.0,
          (in_row, out_row))
    import re as _re
    check("export: the readable time column parses as a local timestamp",
          _re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$", rows[1][0]) is not None, rows[1])
    check("export: cap is SERIES_EXPORT_CAP (200000)",
          exported.get("cap") == api_mod.SERIES_EXPORT_CAP, exported.get("cap"))
    check("export: not truncated for two points under the cap",
          exported.get("truncated") is False, exported)

    real_cap = api_mod.SERIES_EXPORT_CAP
    api_mod.SERIES_EXPORT_CAP = 1
    try:
        status, capped = call(
            "GET", f"/api/nodes/series/export.csv?q={batch_device}:if_in_bps.1,"
                  f"{batch_device}:if_out_bps.1", token=admin)
    finally:
        api_mod.SERIES_EXPORT_CAP = real_cap
    check("export: a cap of 1 truncates two points to one, and says so",
          status == 200 and capped.get("truncated") is True
          and capped.get("count") == 1, (status, capped))

    status, payload = call(
        "GET", f"/api/nodes/series/export.csv?q={batch_device}:cpu_pct", token=no_nodes)
    check("export: refuses an account without Nodes read", status == 403, (status, payload))

finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
