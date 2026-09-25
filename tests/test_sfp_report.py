"""SFP inventory report: netpath/nodesdb.py's interfaces_with_media, the
report.sfp_inventory rows/counts, reportsched.py's "sfp" kind render, and
the /api/nodes/reports/sfp(+/export.csv) routes end to end. Modelled on
test_report_firmware.py and test_report_schedules.py -- run standalone as
`python3 tests/test_sfp_report.py`.
"""
import http.client
import json
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import report, reportsched
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.nodesdb import NodesDatabase
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("sfp_report_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


PORTS = [{"if_index": 1, "descr": "GigabitEthernet1/0/1"},
        {"if_index": 2, "descr": "GigabitEthernet1/0/2", "alias": "uplink-a"},
        {"if_index": 3, "descr": "GigabitEthernet1/0/3"},
        {"if_index": 4, "descr": "GigabitEthernet1/0/4"},
        {"if_index": 5, "descr": "TenGigabitEthernet1/0/5"}]

SFP_CSV_HEADER_ROW = ["device_id", "name", "ip", "if_index", "port", "alias",
                      "kind", "medium", "optic_mode", "media", "oper_status",
                      "admin_status", "speed_bps", "last_seen_ts", "device"]


# ============================================================ 1. report.py

print("1: report.sfp_inventory against a seeded nodesdb")

db = NodesDatabase(f"{TMPDIR}/nodes_unit.db")
gid = db.ensure_default_group()

sw1 = db.add_device("10.60.0.1", "acc-sw-01", group_id=gid)
db.replace_interfaces(sw1, PORTS)
db.update_interface_media(sw1, [
    {"if_index": 1, "media": "optic", "optic_mode": "sm"},
    {"if_index": 2, "media": "sfp", "optic_mode": "mm"},
    {"if_index": 3, "media": "sfp_empty"},
    # if_index 4 stays NULL -- a copper port, no cage at all.
    {"if_index": 5, "media": "copper"},
])

sw2 = db.add_device("10.60.0.2", "acc-sw-02", group_id=gid)
db.replace_interfaces(sw2, PORTS[:2])
db.update_interface_media(sw2, [{"if_index": 1, "media": "optic"}])

result = report.sfp_inventory(db)
by_key = {(r.device_id, r.if_index): r for r in result.rows}

check("empty cages are excluded by default",
      (sw1, 3) not in by_key, list(by_key))
check("a copper port with no media at all is excluded",
      (sw1, 4) not in by_key, list(by_key))
check("an optic port is a row",
      (sw1, 1) in by_key and by_key[(sw1, 1)].kind == "DOM", by_key.get((sw1, 1)))
check("a plain sfp port is a row",
      (sw1, 2) in by_key and by_key[(sw1, 2)].kind == "SFP", by_key.get((sw1, 2)))
check("a copper port is a row with kind 'COP'",
      (sw1, 5) in by_key and by_key[(sw1, 5)].kind == "COP", by_key.get((sw1, 5)))
check("medium spells out the optic mode when known, Copper for COP",
      by_key[(sw1, 1)].medium == "Laser · SM" and by_key[(sw1, 2)].medium == "Laser · MM"
      and by_key[(sw1, 5)].medium == "Copper",
      {k: r.medium for k, r in by_key.items()})
check("optic_mode is carried through as its own column",
      by_key[(sw1, 1)].optic_mode == "sm" and by_key[(sw1, 2)].optic_mode == "mm"
      and by_key[(sw1, 5)].optic_mode == "",
      {k: r.optic_mode for k, r in by_key.items()})
check("port label falls back to descr", by_key[(sw1, 1)].port == "GigabitEthernet1/0/1",
      by_key[(sw1, 1)].port)
check("alias is carried through separately from port",
      by_key[(sw1, 2)].alias == "uplink-a", by_key[(sw1, 2)])
check("device/ip carried through the same device_label chain firmware uses",
      by_key[(sw1, 1)].device == "acc-sw-01 (10.60.0.1)", by_key[(sw1, 1)])

check("port_count is every row, dom/sfp/copper counts split by kind",
      result.port_count == 4 and result.dom_count == 2 and result.sfp_count == 1
      and result.copper_count == 1 and result.empty_count == 0, result.to_dict())
check("device_count is devices with >=1 row, not the whole fleet",
      result.device_count == 2, result.device_count)

with_empty = report.sfp_inventory(db, include_empty=True)
check("include_empty adds the empty-cage row",
      (sw1, 3) in {(r.device_id, r.if_index) for r in with_empty.rows}, with_empty.to_dict())
check("...counted separately as empty_count, port_count grows by one",
      with_empty.empty_count == 1 and with_empty.port_count == 5, with_empty.to_dict())
check("an empty cage's kind reads 'Empty cage', medium is blank -- neither "
      "copper nor laser until something is proven in it",
      next(r for r in with_empty.rows if r.if_index == 3).kind == "Empty cage"
      and next(r for r in with_empty.rows if r.if_index == 3).medium == "",
      [(r.kind, r.medium) for r in with_empty.rows])

narrowed = report.sfp_inventory(db, device_ids=[sw2])
check("device_ids narrows the report to that device's ports only",
      {r.device_id for r in narrowed.rows} == {sw2} and narrowed.port_count == 1,
      narrowed.to_dict())

check("an empty device_ids list reports on nothing rather than the fleet",
      report.sfp_inventory(db, device_ids=[]).rows == [], "")
check("...same for interfaces_with_media directly",
      db.interfaces_with_media(device_ids=[]) == [], "")

sw3 = db.add_device("10.60.0.3", "acc-sw-03", group_id=gid)
db.replace_interfaces(sw3, PORTS[:1])
db.update_interface_media(sw3, [{"if_index": 1, "media": "dac"}])
dac_result = report.sfp_inventory(db)
dac_row = next(r for r in dac_result.rows if r.device_id == sw3)
check("a dac port is a row with kind 'DAC', medium 'Copper'",
      dac_row.kind == "DAC" and dac_row.medium == "Copper", dac_row)
check("dac_count counts it, copper_count is unaffected",
      dac_result.dac_count == 1 and dac_result.copper_count == result.copper_count,
      dac_result.to_dict())

sw4 = db.add_device("10.60.0.4", "acc-sw-04", group_id=gid)
db.replace_interfaces(sw4, PORTS[:1])
db.update_interface_media(sw4, [{"if_index": 1, "media": "daf"}])
daf_result = report.sfp_inventory(db)
daf_row = next(r for r in daf_result.rows if r.device_id == sw4)
check("a daf port is a row with kind 'DAF', medium 'Laser'",
      daf_row.kind == "DAF" and daf_row.medium == "Laser", daf_row)
check("daf_count counts it, dac_count is unaffected",
      daf_result.daf_count == 1 and daf_result.dac_count == dac_result.dac_count,
      daf_result.to_dict())

db.request_device_removal([sw1])
purged = report.sfp_inventory(db)
check("a purged device's ports drop out of the report",
      sw1 not in {r.device_id for r in purged.rows}, purged.to_dict())

payload = result.to_dict()
check("to_dict() is JSON-shaped all the way down",
      isinstance(payload["rows"], list) and isinstance(payload["rows"][0], dict)
      and set(payload["rows"][0]) == {
          "device_id", "name", "ip", "device", "if_index", "port", "alias",
          "kind", "medium", "optic_mode", "media", "oper_status", "admin_status",
          "speed_bps", "last_seen_ts"},
      payload["rows"][0])

db.close()


# ======================================================= 2. reportsched.py

print("\n2: reportsched.render() for kind 'sfp'")

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"), initial_admin_password="admin")
web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
assert server.start(block=False), server.error

nodes_db = service.nodes_db
gid2 = nodes_db.ensure_default_group()
rsw1 = nodes_db.add_device("10.61.0.1", "rep-sw-01", group_id=gid2)
nodes_db.replace_interfaces(rsw1, PORTS)
nodes_db.update_interface_media(rsw1, [
    {"if_index": 1, "media": "optic"}, {"if_index": 2, "media": "sfp"},
    {"if_index": 5, "media": "copper"}])
rsw2 = nodes_db.add_device("10.61.0.2", "rep-sw-02", group_id=gid2)
nodes_db.replace_interfaces(rsw2, PORTS[:1])
nodes_db.update_interface_media(rsw2, [{"if_index": 1, "media": "sfp_empty"}])

sfp_row = {"kind": "sfp", "name": "SFP audit", "params_json": "{}"}
now = time.time()
subject, body, csv_text, filename = reportsched.render(service, sfp_row, now)
check("kind 'sfp' is registered and renders without error",
      subject.startswith("SFP audit:"), subject)
check("subject carries the port/device/DOM/SFP/COP counts",
      "3 port(s) on 1 device(s)" in subject and "1 DOM" in subject
      and "1 SFP" in subject and "1 COP" in subject,
      subject)
check("body names the device with transceivers",
      "rep-sw-01" in body, body)
check("empty cages are excluded from the default schedule render",
      "rep-sw-02" not in body, body)
csv_lines = csv_text.lstrip("﻿").splitlines()
check("CSV header matches the Reports subtab's own export, medium after kind",
      csv_lines[0].split(",") == SFP_CSV_HEADER_ROW,
      csv_lines[0])
check("one CSV row per transceiver port",
      len(csv_lines) == 4, csv_lines)
check("filename is a .csv", filename.endswith(".csv"), filename)

empty_row = {"kind": "sfp", "name": "SFP audit (with empties)",
            "params_json": json.dumps({"include_empty": True})}
subject, body, csv_text, filename = reportsched.render(service, empty_row, now)
check("include_empty=True in a schedule's params reaches the render",
      "4 port(s) on 2 device(s)" in subject, subject)

dgid = nodes_db.add_device_group("Access switches")
nodes_db.update_device(rsw1, device_group_id=dgid)
group_row = {"kind": "sfp", "name": "Group only",
            "params_json": json.dumps({"device_group_id": dgid})}
subject, _, _, _ = reportsched.render(service, group_row, now)
check("device_group_id resolves through _device_ids_for_group like availability does",
      "3 port(s) on 1 device(s)" in subject, subject)


# ============================================================== 3. routes

print("\n3: /api/nodes/reports/sfp routes")


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


admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

status, payload = call("GET", "/api/nodes/reports/sfp", token=admin)
check("200, no device_ids -> the whole fleet's transceiver ports",
      status == 200 and payload["port_count"] == 3
      and payload["copper_count"] == 1, (status, payload))

status, payload = call("GET", "/api/nodes/reports/sfp?include_empty=1", token=admin)
check("include_empty=1 also counts the empty cage",
      status == 200 and payload["port_count"] == 4 and payload["empty_count"] == 1,
      (status, payload))

status, payload = call(
    "GET", f"/api/nodes/reports/sfp?device_ids={rsw2}&include_empty=1", token=admin)
check("device_ids narrows the route the same way as report.py",
      status == 200 and [r["device_id"] for r in payload["rows"]] == [rsw2],
      (status, payload))

status, payload = call("GET", "/api/nodes/reports/sfp/export.csv", token=admin)
check("the server-side CSV route answers a csv/filename/count payload",
      status == 200 and payload["count"] == 3
      and payload["filename"].endswith(".csv")
      and payload["csv"].splitlines()[0].lstrip("﻿") ==
      "device_id,name,ip,if_index,port,alias,kind,medium,optic_mode,media,"
      "oper_status,admin_status,speed_bps,last_seen_ts,device",
      (status, payload))
check("...and honours include_empty too",
      call("GET", "/api/nodes/reports/sfp/export.csv?include_empty=1",
          token=admin)[1]["count"] == 4, "")

# -------------------------------------------------------------- gates
print("gates: nodes:read allowed, no grant refused (viewer 403 pattern)")
service.app_db.add_user("sfp-reader", hash_password("SfpReaderPW2026"),
                        must_change=False)
service.app_db.set_permissions("sfp-reader", {"nodes": "read"})
reader = login("sfp-reader", "SfpReaderPW2026")
service.app_db.add_user("sfp-outsider", hash_password("SfpOutsiderPW2026"),
                        must_change=False)
service.app_db.set_permissions("sfp-outsider", {"syslog": "read"})
outsider = login("sfp-outsider", "SfpOutsiderPW2026")

for path in ("/api/nodes/reports/sfp", "/api/nodes/reports/sfp/export.csv"):
    status, payload = call("GET", path, token=reader)
    check(f"a nodes:read account may read {path}", status == 200, (status, payload))
    status, payload = call("GET", path, token=outsider)
    check(f"an account with no nodes grant is refused {path}", status == 403, (status, payload))

status, payload = call("GET", "/api/nodes/reports/sfp")
check("no session at all is refused with 401", status == 401, (status, payload))

# A schedule of kind 'sfp' round-trips through the CRUD routes, the same
# nodes-write gate every other schedule kind uses.
sched_body = {"name": "Weekly SFP", "kind": "sfp", "cadence": "weekly",
             "hour": 6, "minute": 0, "weekday": 1,
             "recipients": ["ops@example.invalid"],
             "params": {"include_empty": True}}
status, created = call("POST", "/api/nodes/reports/schedules", sched_body, token=admin)
check("a 'sfp' kind schedule can be created", status == 200 and created.get("id"),
      (status, created))
status, payload = call("POST", "/api/nodes/reports/schedules", sched_body, token=reader)
check("...but a nodes:read account may not create one", status == 403, (status, payload))

# device_group_id and include_empty round-trip through the params cleaner
# with the same typing every other schedule kind gets.
group_sched_body = {"name": "Group SFP", "kind": "sfp", "cadence": "weekly",
                    "hour": 6, "minute": 0, "weekday": 1,
                    "recipients": ["ops@example.invalid"],
                    "params": {"device_group_id": str(dgid), "include_empty": "false"}}
status, created = call("POST", "/api/nodes/reports/schedules", group_sched_body, token=admin)
check("a schedule may target one device group", status == 200 and created.get("id"),
      (status, created))
group_sched_id = created["id"]

status, listing = call("GET", "/api/nodes/reports/schedules", token=admin)
stored = next(s for s in listing["schedules"] if s["id"] == group_sched_id)
check("device_group_id is stored as an int, not the submitted string",
      stored["params"]["device_group_id"] == dgid
      and isinstance(stored["params"]["device_group_id"], int), stored["params"])
check("include_empty: \"false\" stores as the boolean False",
      stored["params"]["include_empty"] is False, stored["params"])

group_row = nodes_db.report_schedule(group_sched_id)
subject, _, _, _ = reportsched.render(service, group_row, now)
check("the stored schedule's own render narrows to its saved device group",
      "3 port(s) on 1 device(s)" in subject, subject)

status, payload = call(
    "POST", "/api/nodes/reports/schedules",
    {**group_sched_body, "params": {"device_group_id": "abc"}}, token=admin)
check("a non-integer device_group_id is refused with 400", status == 400, (status, payload))

server.stop()
service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
