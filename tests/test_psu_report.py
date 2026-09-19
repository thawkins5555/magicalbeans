"""Single-PSU report: report.single_psu_report's per-member judging (listed
vs excluded-and-covered), reportsched.py's "psu" kind render, and the
/api/nodes/reports/psu(+/export.csv) routes end to end. Modelled on
test_sfp_report.py -- run standalone as `python3 tests/test_psu_report.py`.
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

TMPDIR = _paths.tmpdir("psu_report_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


PSU_CSV_HEADER_ROW = ["device_id", "name", "ip", "member", "psu_total", "psu_present",
                      "psu_down", "supplies", "stack_power", "covered", "last_ts", "device"]


def seed_psu(db, device_id, rows, ts=None):
    """rows: list of (key, label, value) -- record_metric_samples wants the
    full (key, label, unit, kind, ts, value) tuple, always 'gauge'/'' here."""
    ts = ts or time.time()
    db.record_metric_samples(device_id, [
        (key, label, "", "gauge", ts, value) for key, label, value in rows])


# ============================================================ 1. report.py

print("1: report.single_psu_report against a seeded nodesdb")

db = NodesDatabase(f"{TMPDIR}/nodes_unit.db")
gid = db.ensure_default_group()

# A standalone switch with exactly one supply present.
standalone = db.add_device("10.62.0.1", "acc-sw-01", group_id=gid)
seed_psu(db, standalone, [
    ("psu_state.1", "Power Supply A", 0.0),
    ("psu_state.2", "Power Supply B", 3.0),
])

# A standalone switch with both supplies ok -- not a single-PSU switch.
both_ok = db.add_device("10.62.0.2", "acc-sw-02", group_id=gid)
seed_psu(db, both_ok, [
    ("psu_state.1", "Power Supply A", 0.0),
    ("psu_state.2", "Power Supply B", 0.0),
])

# A stack member whose dead supply is covered by StackPower up to a neighbour.
covered = db.add_device("10.62.0.3", "stk-sw-01", group_id=gid)
seed_psu(db, covered, [
    ("psu_state.1", "Switch 1 - Power Supply A", 0.0),
    ("psu_state.2", "Switch 1 - Power Supply B", 3.0),
    ("stack_power_port.1", "StackPort1/1", 0.0),
    ("stack_power_port_switch.1", "StackPort1/1", 1.0),
    ("stack_power_port_admin.1", "StackPort1/1", 1.0),
    ("stack_power_port_neighbour.1", "StackPort1/1", 2.0),
])

# The same shape, but the StackPower port itself is down -- not covered.
cable_down = db.add_device("10.62.0.4", "stk-sw-02", group_id=gid)
seed_psu(db, cable_down, [
    ("psu_state.1", "Switch 1 - Power Supply A", 0.0),
    ("psu_state.2", "Switch 1 - Power Supply B", 3.0),
    ("stack_power_port.1", "StackPort1/1", 2.0),
    ("stack_power_port_switch.1", "StackPort1/1", 1.0),
    ("stack_power_port_admin.1", "StackPort1/1", 1.0),
    ("stack_power_port_neighbour.1", "StackPort1/1", 0.0),
])

# Same shape again, port administratively disabled -- not covered either.
admin_off = db.add_device("10.62.0.5", "stk-sw-03", group_id=gid)
seed_psu(db, admin_off, [
    ("psu_state.1", "Switch 1 - Power Supply A", 0.0),
    ("psu_state.2", "Switch 1 - Power Supply B", 3.0),
    ("stack_power_port.1", "StackPort1/1", 0.0),
    ("stack_power_port_switch.1", "StackPort1/1", 1.0),
    ("stack_power_port_admin.1", "StackPort1/1", 2.0),
    ("stack_power_port_neighbour.1", "StackPort1/1", 2.0),
])

# Two members on one device, each with a single supply present.
two_members = db.add_device("10.62.0.6", "stk-sw-04", group_id=gid)
seed_psu(db, two_members, [
    ("psu_state.1", "Switch 1 - Power Supply A", 0.0),
    ("psu_state.2", "Switch 1 - Power Supply B", 3.0),
    ("psu_state.3", "Switch 2 - Power Supply A", 0.0),
    ("psu_state.4", "Switch 2 - Power Supply B", 3.0),
])

result = report.single_psu_report(db)
by_key = {(r.device_id, r.member): r for r in result.rows}

check("a standalone switch with one PSU present is listed with member ''",
      (standalone, "") in by_key, list(by_key))
check("...and its supplies text names both bays",
      by_key[(standalone, "")].supplies
      == "Power Supply A ok · Power Supply B not present",
      by_key[(standalone, "")].supplies)
check("a standalone switch with both PSUs ok is not listed",
      (both_ok, "") not in by_key, list(by_key))
check("a stack member covered by StackPower is excluded, not listed",
      (covered, "1") not in by_key, list(by_key))
check("...but a cable-down member is still listed",
      (cable_down, "1") in by_key
      and by_key[(cable_down, "1")].stack_power == "cable down", list(by_key))
check("...an admin-disabled StackPower port does not count as covered either "
      "(still listed, though its port is still reported up)",
      (admin_off, "1") in by_key
      and by_key[(admin_off, "1")].stack_power == "1 up", list(by_key))
check("two stack members on one device are two separate rows",
      (two_members, "1") in by_key and (two_members, "2") in by_key, list(by_key))

check("row_count/device_count/covered_count add up",
      result.row_count == 5 and result.device_count == 6 and result.covered_count == 1,
      result.to_dict())

narrowed = report.single_psu_report(db, device_ids=[standalone])
check("device_ids narrows the report to that device's rows only",
      {r.device_id for r in narrowed.rows} == {standalone} and narrowed.row_count == 1,
      narrowed.to_dict())
check("an empty device_ids list reports on nothing rather than the fleet",
      report.single_psu_report(db, device_ids=[]).rows == [], "")

check("CSV header length matches the row's own field count",
      len(report.PSU_CSV_HEADER) == len(report.PsuRow.__dataclass_fields__),
      (report.PSU_CSV_HEADER, list(report.PsuRow.__dataclass_fields__)))

payload = result.to_dict()
check("to_dict() is JSON-shaped all the way down",
      isinstance(payload["rows"], list) and isinstance(payload["rows"][0], dict)
      and set(payload["rows"][0]) == {
          "device_id", "name", "ip", "device", "member", "psu_total", "psu_present",
          "psu_down", "supplies", "stack_power", "covered", "last_ts"},
      payload["rows"][0])

db.close()


# ======================================================= 2. reportsched.py

print("\n2: reportsched.render() for kind 'psu'")

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
rsw1 = nodes_db.add_device("10.63.0.1", "rep-psu-01", group_id=gid2)
seed_psu(nodes_db, rsw1, [
    ("psu_state.1", "Power Supply A", 0.0),
    ("psu_state.2", "Power Supply B", 3.0),
])
rsw2 = nodes_db.add_device("10.63.0.2", "rep-psu-02", group_id=gid2)
seed_psu(nodes_db, rsw2, [
    ("psu_state.1", "Power Supply A", 0.0),
    ("psu_state.2", "Power Supply B", 0.0),
])

psu_row = {"kind": "psu", "name": "PSU audit", "params_json": "{}"}
now = time.time()
subject, body, csv_text, filename = reportsched.render(service, psu_row, now)
check("kind 'psu' is registered and renders without error",
      subject.startswith("PSU audit:"), subject)
check("subject carries the single-PSU row count",
      "1 switch(es)" in subject, subject)
check("body names the device with a single supply",
      "rep-psu-01" in body, body)
check("a device with both supplies ok is excluded from the render",
      "rep-psu-02" not in body, body)
csv_lines = csv_text.lstrip("﻿").splitlines()
check("CSV header matches the Reports subtab's own export",
      csv_lines[0].split(",") == PSU_CSV_HEADER_ROW, csv_lines[0])
check("one CSV row for the single-PSU switch",
      len(csv_lines) == 2, csv_lines)
check("filename is a .csv", filename.endswith(".csv"), filename)

dgid = nodes_db.add_device_group("Stack switches")
nodes_db.update_device(rsw1, device_group_id=dgid)
group_row = {"kind": "psu", "name": "Group only",
            "params_json": json.dumps({"device_group_id": dgid})}
subject, _, _, _ = reportsched.render(service, group_row, now)
check("device_group_id resolves through _device_ids_for_group like sfp/availability do",
      "1 switch(es)" in subject, subject)


# ============================================================== 3. routes

print("\n3: /api/nodes/reports/psu routes")


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

status, payload = call("GET", "/api/nodes/reports/psu", token=admin)
check("200, no device_ids -> the whole fleet's single-PSU switches",
      status == 200 and payload["row_count"] == 1, (status, payload))

status, payload = call(
    "GET", f"/api/nodes/reports/psu?device_ids={rsw2}", token=admin)
check("device_ids narrows the route the same way as report.py",
      status == 200 and payload["rows"] == [], (status, payload))

status, payload = call("GET", "/api/nodes/reports/psu/export.csv", token=admin)
check("the server-side CSV route answers a csv/filename/count payload",
      status == 200 and payload["count"] == 1
      and payload["filename"].endswith(".csv")
      and payload["csv"].splitlines()[0].lstrip("﻿") ==
      "device_id,name,ip,member,psu_total,psu_present,psu_down,supplies,"
      "stack_power,covered,last_ts,device",
      (status, payload))

# -------------------------------------------------------------- gates
print("gates: nodes:read allowed, no grant refused (viewer 403 pattern)")
service.app_db.add_user("psu-reader", hash_password("PsuReaderPW2026"),
                        must_change=False)
service.app_db.set_permissions("psu-reader", {"nodes": "read"})
reader = login("psu-reader", "PsuReaderPW2026")
service.app_db.add_user("psu-outsider", hash_password("PsuOutsiderPW2026"),
                        must_change=False)
service.app_db.set_permissions("psu-outsider", {"syslog": "read"})
outsider = login("psu-outsider", "PsuOutsiderPW2026")

for path in ("/api/nodes/reports/psu", "/api/nodes/reports/psu/export.csv"):
    status, payload = call("GET", path, token=reader)
    check(f"a nodes:read account may read {path}", status == 200, (status, payload))
    status, payload = call("GET", path, token=outsider)
    check(f"an account with no nodes grant is refused {path}", status == 403, (status, payload))

status, payload = call("GET", "/api/nodes/reports/psu")
check("no session at all is refused with 401", status == 401, (status, payload))

# A schedule of kind 'psu' round-trips through the CRUD routes, the same
# nodes-write gate every other schedule kind uses.
sched_body = {"name": "Weekly PSU", "kind": "psu", "cadence": "weekly",
             "hour": 6, "minute": 0, "weekday": 1,
             "recipients": ["ops@example.invalid"],
             "params": {"device_group_id": str(dgid)}}
status, created = call("POST", "/api/nodes/reports/schedules", sched_body, token=admin)
check("a 'psu' kind schedule can be created", status == 200 and created.get("id"),
      (status, created))
status, payload = call("POST", "/api/nodes/reports/schedules", sched_body, token=reader)
check("...but a nodes:read account may not create one", status == 403, (status, payload))

status, listing = call("GET", "/api/nodes/reports/schedules", token=admin)
stored = next(s for s in listing["schedules"] if s["id"] == created["id"])
check("device_group_id is stored as an int, not the submitted string",
      stored["params"]["device_group_id"] == dgid
      and isinstance(stored["params"]["device_group_id"], int), stored["params"])

status, payload = call(
    "POST", "/api/nodes/reports/schedules",
    {**sched_body, "params": {"device_group_id": "abc"}}, token=admin)
check("a non-integer device_group_id is refused with 400", status == 400, (status, payload))

server.stop()
service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
