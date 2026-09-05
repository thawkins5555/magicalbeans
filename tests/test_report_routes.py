"""4.49.0: the two /api/nodes/reports/* routes on top of netpath/report.py's
device_availability_report and top_metric_ranking (report.py itself, and its
query correctness/cost at scale, is covered by test_report_availability.py
and test_report_topn.py — this suite is the thin dispatch layer: query-string
parsing, "no device_ids means the whole fleet", and the synchronous-request
refusal for a whole-fleet top-metrics ask spanning more than a week).

Covers:
  - GET /api/nodes/reports/availability with no device_ids reports on every
    device on file; device_ids narrows it; an explicit t0/t1 is honoured.
  - GET /api/nodes/reports/top-metrics: key is required; rank_by must be
    'peak' or 'mean'; ranks against samples_hourly (seeded directly, the
    same way test_report_topn.py's own fixture is built, since the hourly
    rollup runs on its own schedule, not synchronously with a live sample).
  - Ranking the WHOLE fleet (no device_ids) over more than 7 days is
    refused outright; the same window narrowed to specific device_ids is
    allowed — report.py's own docstring measured the whole-fleet, month-
    long shape at ~100s, too slow for a synchronous request.
  - Both routes are gated ("nodes", read): a nodes:read account may read
    both; an account with no nodes grant is refused both.
"""
import http.client
import json
import os
import time

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("report_routes_")
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


def seed_hourly_sample(db, device_id, key, label, unit, hour, n, vmin, vavg, vmax):
    """samples_hourly directly, the way test_report_topn.py's own fixture
    does — the hourly rollup runs on its own schedule, not synchronously
    with record_metric_samples, so a route test needs the same shortcut."""
    metric_id = db.record_metric_samples(
        device_id, [(key, label, unit, "gauge", time.time(), vavg)])[key]
    db._conn.execute(
        "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
        " VALUES (?,?,?,?,?,?)", (metric_id, hour, n, vmin, vavg, vmax))
    db._conn.commit()
    return metric_id


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    db = service.nodes_db
    gid = db.ensure_default_group()
    now = time.time()

    dev1 = db.add_device("10.85.0.1", name="dev-1", group_id=gid)
    dev2 = db.add_device("10.85.0.2", name="dev-2", group_id=gid)

    # -------------------------------------------------------- availability
    print("GET /api/nodes/reports/availability")
    status, payload = call("GET", "/api/nodes/reports/availability", token=admin)
    check("200", status == 200, (status, payload))
    check("no device_ids -> every device on file",
          {d["device_id"] for d in payload.get("devices", [])} == {dev1, dev2}, payload)

    status, payload = call(
        "GET", f"/api/nodes/reports/availability?device_ids={dev1}"
               f"&t0={now - 3600}&t1={now}", token=admin)
    check("device_ids narrows the report to just that device",
          status == 200 and [d["device_id"] for d in payload["devices"]] == [dev1],
          (status, payload))
    check("t0/t1 echoed back as requested_start/requested_end",
          payload["requested_start"] == now - 3600 and payload["requested_end"] == now,
          payload)

    status, payload = call(
        "GET", f"/api/nodes/reports/availability?device_ids=999999", token=admin)
    check("an unknown device id gets its own degenerate row, not an error",
          status == 200 and payload["devices"][0]["caveats"] == ["no such device"],
          (status, payload))

    # -------------------------------------------------------- top-metrics
    print("GET /api/nodes/reports/top-metrics")
    status, payload = call("GET", "/api/nodes/reports/top-metrics", token=admin)
    check("key is required", status == 400, (status, payload))

    status, payload = call(
        "GET", "/api/nodes/reports/top-metrics?key=cpu_pct&rank_by=bogus", token=admin)
    check("rank_by must be peak or mean", status == 400, (status, payload))

    hour = int(now // 3600) * 3600
    seed_hourly_sample(db, dev1, "cpu_pct", "CPU", "percent", hour, 5, 30.0, 40.0, 55.0)
    seed_hourly_sample(db, dev2, "cpu_pct", "CPU", "percent", hour, 5, 10.0, 15.0, 20.0)

    status, payload = call(
        "GET", f"/api/nodes/reports/top-metrics?key=cpu_pct&t0={now - 3600}&t1={now + 60}",
        token=admin)
    check("200, both devices ranked, hottest first (peak, default rank_by)",
          status == 200 and len(payload["rows"]) == 2
          and payload["rows"][0]["device_id"] == dev1
          and payload["rows"][0]["peak"] == 55.0, (status, payload))

    status, payload = call(
        "GET", f"/api/nodes/reports/top-metrics?key=cpu_pct&t0={now - 3600}&t1={now + 60}"
               f"&ascending=1", token=admin)
    check("ascending=1 flips the order (coolest first)",
          status == 200 and payload["rows"][0]["device_id"] == dev2, (status, payload))

    status, payload = call(
        "GET", f"/api/nodes/reports/top-metrics?key=cpu_pct&t0={now - 3600}&t1={now + 60}"
               f"&device_ids={dev1}", token=admin)
    check("device_ids narrows the ranking",
          status == 200 and [r["device_id"] for r in payload["rows"]] == [dev1],
          (status, payload))

    # ---------------------------------------------- whole-fleet cost cap
    print("whole-fleet-equivalent top-metrics over more than 7 days is refused")
    long_t0 = now - 40 * 86400
    status, payload = call(
        "GET", f"/api/nodes/reports/top-metrics?key=cpu_pct&t0={long_t0}&t1={now}", token=admin)
    check("400: whole fleet (device_ids omitted), >7 days is refused",
          status == 400, (status, payload))

    # The exact bypass this guard exists to close: explicitly naming every
    # device on file produces the identical query omitting device_ids
    # does, and must be refused identically rather than read as "narrowed"
    # just because the parameter was present.
    status, payload = call(
        "GET", f"/api/nodes/reports/top-metrics?key=cpu_pct&t0={long_t0}&t1={now}"
               f"&device_ids={dev1},{dev2}", token=admin)
    check("400: device_ids listing every device is refused exactly like omitting it",
          status == 400, (status, payload))

    # Genuinely narrowed (half the two-device fleet) over a window short
    # enough that the scaled-down cost falls back under the cap.
    short_t0 = now - 10 * 86400
    status, payload = call(
        "GET", f"/api/nodes/reports/top-metrics?key=cpu_pct&t0={short_t0}&t1={now}"
               f"&device_ids={dev1}", token=admin)
    check("...but a genuinely narrowed request over a shorter window is allowed",
          status == 200, (status, payload))
    # The default 7-day window with no device_ids must NOT be refused --
    # only a window actually longer than the cap should trip it.
    status, payload = call("GET", "/api/nodes/reports/top-metrics?key=cpu_pct", token=admin)
    check("...and the plain default-window whole-fleet call is unaffected",
          status == 200, (status, payload))

    # -------------------------------------------------------------- gates
    print("gates: nodes:read allowed, no grant refused")
    service.app_db.add_user("report-reader", hash_password("ReportReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("report-reader", {"nodes": "read"})
    reader = login("report-reader", "ReportReaderPW2026")
    service.app_db.add_user("report-outsider", hash_password("ReportOutsiderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("report-outsider", {"syslog": "read"})
    outsider = login("report-outsider", "ReportOutsiderPW2026")

    for path in ("/api/nodes/reports/availability",
                "/api/nodes/reports/top-metrics?key=cpu_pct"):
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
