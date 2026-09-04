"""Item 2 of the API-heavy trio: server-side paging for the Devices list
and the Alerts list.

Devices (nodesdb.devices/devices_count via GET /api/nodes/devices):
limit/offset math, a `total` that ignores the page, and the no-params call
still returning the whole matching set unpaged — the backward-compatible
form item 2 explicitly asked to keep for one release.

Alerts (alertsdb.alerts via GET /api/alerts): `offset` walking past
ALERTS_LIST_CAP, with `total` (from the existing count_alerts helper)
staying honest about how many pages there are.
"""
import http.client
import json
import os
import time
from urllib.parse import urlencode

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertrules import Occurrence, dedup_key
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("paging_")
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

    # -------------------------------------------------------- device paging
    print("device paging")
    DEVICE_N = 47
    created_ips = []
    for i in range(DEVICE_N):
        ip = f"10.70.{i // 250}.{i % 250 + 1}"
        status, row = call("POST", "/api/nodes/devices",
                           {"ip": ip, "name": f"dev-{i:03d}"}, token=admin)
        assert status == 200, (status, row)
        created_ips.append(ip)

    status, unpaged = call("GET", "/api/nodes/devices", token=admin)
    check("no limit/offset at all still returns the whole matching set (backward compat)",
          status == 200 and len(unpaged["devices"]) == DEVICE_N,
          (status, len(unpaged.get("devices", []))))
    check("...and now also carries a total alongside the full list",
          unpaged.get("total") == DEVICE_N, unpaged.get("total"))

    status, page1 = call("GET", "/api/nodes/devices", {"limit": 10, "offset": 0}, token=admin)
    check("page 1 of 10 returns exactly 10 rows", status == 200 and len(page1["devices"]) == 10,
          (status, len(page1.get("devices", []))))
    check("page 1 carries the overall total, not the page size",
          page1.get("total") == DEVICE_N, page1.get("total"))
    check("page 1 echoes back limit and offset",
          page1.get("limit") == 10 and page1.get("offset") == 0, page1)

    status, page2 = call("GET", "/api/nodes/devices", {"limit": 10, "offset": 10}, token=admin)
    check("page 2 returns the next 10 rows", status == 200 and len(page2["devices"]) == 10,
          (status, len(page2.get("devices", []))))
    page1_ids = {d["id"] for d in page1["devices"]}
    page2_ids = {d["id"] for d in page2["devices"]}
    check("page 1 and page 2 do not overlap", not (page1_ids & page2_ids),
          page1_ids & page2_ids)

    last_offset = (DEVICE_N // 10) * 10
    status, last_page = call("GET", "/api/nodes/devices",
                             {"limit": 10, "offset": last_offset}, token=admin)
    check("the final partial page returns the remainder, not a full page",
          status == 200 and len(last_page["devices"]) == DEVICE_N - last_offset,
          (status, len(last_page.get("devices", []))))

    status, past_end = call("GET", "/api/nodes/devices",
                            {"limit": 10, "offset": DEVICE_N + 50}, token=admin)
    check("an offset past the end returns zero rows, not an error",
          status == 200 and past_end["devices"] == [], (status, past_end))

    # A limit above DEVICE_LIST_MAX_LIMIT is clamped, not refused or honoured
    # verbatim — a caller cannot turn the paged route back into an unbounded
    # one just by asking for a huge page.
    status, clamped = call("GET", "/api/nodes/devices", {"limit": 999999, "offset": 0},
                           token=admin)
    check("an oversized limit is clamped rather than honoured or refused",
          status == 200 and clamped.get("limit", 0) <= 2000 and
          len(clamped["devices"]) == min(DEVICE_N, clamped.get("limit", 0)),
          (status, clamped.get("limit"), len(clamped.get("devices", []))))

    # Filters still apply under paging.
    status, filtered_page = call("GET", "/api/nodes/devices",
                                 {"q": "dev-000", "limit": 10, "offset": 0}, token=admin)
    check("a filter narrows the total under paging too",
          filtered_page.get("total") == 1, filtered_page)

    # -------------------------------------------------------- alert paging
    print("alert paging past the cap")
    rule = service.alerts_db.rules()[0]

    def raise_alert(n):
        occurrence = Occurrence(kind=rule["kind"], source_kind=rule["source_kind"] or "",
                                entity_kind="device", entity_id=str(n),
                                entity_label=f"a{n}", ts=time.time() + n, message="m")
        service.alerts_db.open_or_increment(
            rule["id"], dedup_key(rule, occurrence) + f":{n}", "device", str(n),
            f"a{n}", rule["severity"], "m", "", time.time() + n)

    ALERT_N = 2300
    for i in range(ALERT_N):
        raise_alert(i)

    status, first_page = call("GET", "/api/alerts", {"limit": 2000, "offset": 0}, token=admin)
    check("the first page is capped at 2,000 (ALERTS_LIST_CAP)",
          status == 200 and len(first_page["alerts"]) == 2000,
          (status, len(first_page.get("alerts", []))))
    check("the first page's total covers every matching alert, not just the page",
          first_page.get("total") == ALERT_N, first_page.get("total"))

    status, second_page = call("GET", "/api/alerts", {"limit": 2000, "offset": 2000},
                               token=admin)
    check("offset past the cap reaches the rest — the alerts_truncated bug this fixes",
          status == 200 and len(second_page["alerts"]) == ALERT_N - 2000,
          (status, len(second_page.get("alerts", []))))
    first_ids = {a["id"] for a in first_page["alerts"]}
    second_ids = {a["id"] for a in second_page["alerts"]}
    check("the two pages do not repeat a row", not (first_ids & second_ids),
          first_ids & second_ids)

finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
