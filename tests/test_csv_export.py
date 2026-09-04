"""Item 1 of the API-heavy trio: `GET /api/<module>/export.csv` on every
operator-facing table.

Covers, against a real Service + WebServer over loopback: the current
filter honoured (devices, syslog), RFC 4180 quoting of a value carrying a
comma, an embedded quote and a newline all at once, the permission gate
(read is enough, but only for the module the route belongs to — the same
semantics test_web_gates.py already pins for the JSON routes), the
Content-Disposition-style filename the JSON payload carries, and the
alerts export actually exceeding the old 2,000-row screen cap.

Every export route answers JSON — {csv, filename, count, truncated, cap}
— rather than a raw file (see api.py's `_csv_response` docstring for why);
this suite reads `csv` back with Python's own csv module rather than
string-matching it, so a quoting bug that still "looks right" eyeballed
would still fail here.
"""
import csv
import http.client
import io
import json
import os
import re
import time
from urllib.parse import urlencode

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import nfdecode, syslogparse, trapdecode
from netpath.alertrules import Occurrence, dedup_key
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("csv_export_")
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
    # GET carries its arguments in the query string, not a JSON body (the
    # server never reads one for GET) — a dict handed in for a GET call is
    # query params, everything else is the JSON body.
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


FILENAME_RE = re.compile(r"^sappiwhere-[a-z0-9-]+-\d{8}-\d{6}\.csv$")


def parse_csv(text):
    """Strip the BOM the same way Excel would and hand back csv.reader's
    own rows — the ground truth for whether the quoting was correct,
    rather than eyeballing the raw text."""
    if text.startswith("﻿"):
        text = text[1:]
    return list(csv.reader(io.StringIO(text)))


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # ---------------------------------------------------------- devices
    print("devices export")
    status, plain = call("POST", "/api/nodes/devices",
                         {"ip": "10.90.0.1", "name": "core-a"}, token=admin)
    check("setup: plain device created", status == 200, (status, plain))
    tricky_name = 'Core, "main" switch\nsecond line'
    status, tricky = call("POST", "/api/nodes/devices",
                          {"ip": "10.90.0.2", "name": tricky_name}, token=admin)
    check("setup: device with comma/quote/newline created", status == 200, (status, tricky))

    status, payload = call("GET", "/api/nodes/devices/export.csv", token=admin)
    check("devices export answers 200", status == 200, (status, payload))
    check("devices export filename matches the convention",
          bool(FILENAME_RE.match(payload.get("filename", ""))), payload.get("filename"))
    check("devices export count matches the two devices created",
          payload.get("count") == 2, payload)
    rows = parse_csv(payload["csv"])
    check("devices export has a header row plus one row per device",
          len(rows) == 3, rows)
    header = rows[0]
    check("devices export header names the id/name/ip columns",
          {"id", "name", "ip", "status"} <= set(header), header)
    name_col = header.index("name")
    names = {row[name_col] for row in rows[1:]}
    check("the comma/quote/newline in a device name round-trips exactly",
          tricky_name in names, names)

    # The current filter honoured: q=core-a should only match the plain device.
    status, filtered = call("GET", "/api/nodes/devices/export.csv", {"q": "core-a"}, token=admin)
    check("devices export honours the q filter", filtered.get("count") == 1, filtered)
    filtered_rows = parse_csv(filtered["csv"])
    check("...and the row it kept is the matching device",
          filtered_rows[1][header.index("ip")] == "10.90.0.1", filtered_rows)

    # ------------------------------------------------------- interfaces
    print("interfaces export")
    status, empty_if = call("GET", f"/api/nodes/devices/{plain['id']}/interfaces/export.csv",
                            token=admin)
    check("interfaces export answers 200 even with no polled interfaces yet",
          status == 200 and empty_if.get("count") == 0, (status, empty_if))
    status, missing = call("GET", "/api/nodes/devices/999999/interfaces/export.csv", token=admin)
    check("interfaces export 400s for a device that does not exist", status == 400, status)

    # ------------------------------------------------------------ alerts
    print("alerts export exceeds the 2,000-row screen cap")
    rule = service.alerts_db.rules()[0]

    def raise_alert(n):
        occurrence = Occurrence(kind=rule["kind"], source_kind=rule["source_kind"] or "",
                                entity_kind="device", entity_id=str(n),
                                entity_label=f"dev{n}", ts=time.time(), message="test")
        service.alerts_db.open_or_increment(
            rule["id"], dedup_key(rule, occurrence) + f":{n}", "device", str(n),
            f"dev{n}", rule["severity"], "test message", "", time.time())

    ALERT_N = 2500
    for i in range(ALERT_N):
        raise_alert(i)

    status, listed = call("GET", "/api/alerts", {"limit": 5000}, token=admin)
    check("the screen list is still capped at 2,000 even if a bigger limit is asked for",
          status == 200 and len(listed["alerts"]) == 2000, (status, len(listed.get("alerts", []))))
    check("...and now carries a total past the cap",
          listed.get("total") == ALERT_N, listed.get("total"))

    status, exported = call("GET", "/api/alerts/export.csv", token=admin)
    check("alerts export answers 200", status == 200, (status, type(exported)))
    check(f"alerts export returns all {ALERT_N} rows, past the old 2,000 cap",
          exported.get("count") == ALERT_N, exported.get("count"))
    check("alerts export is not marked truncated (comfortably under its own cap)",
          exported.get("truncated") is False, exported)
    exported_rows = parse_csv(exported["csv"])
    check("alerts export row count matches count + header",
          len(exported_rows) == ALERT_N + 1, len(exported_rows))

    # ------------------------------------------------------------ syslog
    print("syslog export: quoting + gate")
    tricky_message = 'line one, "quoted" bit\nline two'
    service.syslog_db.insert([syslogparse.LogEntry(
        ts=time.time(), source="10.9.9.9", host="switch-1", message=tricky_message)])
    status, syslog_export = call("GET", "/api/syslog/search/export.csv", token=admin)
    check("syslog export answers 200", status == 200, (status, syslog_export))
    check("syslog export sees the inserted row",
          syslog_export.get("count", 0) >= 1, syslog_export.get("count"))
    syslog_rows = parse_csv(syslog_export["csv"])
    syslog_header = syslog_rows[0]
    msg_col = syslog_header.index("message")
    check("the comma/quote/newline syslog message round-trips exactly",
          any(row[msg_col] == tricky_message for row in syslog_rows[1:]),
          [row[msg_col] for row in syslog_rows[1:]])

    # ---------------------------------------------------- snmp traps
    print("snmp traps export")
    service.snmp_db.insert([trapdecode.Trap(
        ts=time.time(), source="10.9.9.8", version=1, community="public",
        trap_name="linkDown", trap_kind="linkDown", severity=4)])
    status, trap_export = call("GET", "/api/snmp/traps/export.csv", token=admin)
    check("snmp traps export answers 200 and sees the inserted trap",
          status == 200 and trap_export.get("count", 0) >= 1, (status, trap_export))

    # --------------------------------------------------------- netflow
    print("netflow export")
    flow = nfdecode.Flow(exporter="10.9.9.7", version=9, ts_start=time.time(),
                         ts_end=time.time(), src_ip="10.1.1.1", dst_ip="10.1.1.2",
                         packets=10, bytes=1000)
    service.flow_db.insert_flows([flow])
    status, flow_export = call("GET", "/api/netflow/records/export.csv", token=admin)
    check("netflow export answers 200 and sees the inserted flow",
          status == 200 and flow_export.get("count", 0) >= 1, (status, flow_export))

    # ----------------------------------------------------------- ipam
    print("ipam hosts + dhcp leases export")
    service.ipam_db.record_host("10.9.9.6", None, True, "aa:bb:cc:dd:ee:ff")
    status, hosts_export = call("GET", "/api/ipam/hosts/export.csv", token=admin)
    check("ipam hosts export answers 200 and sees the inserted host",
          status == 200 and hosts_export.get("count", 0) >= 1, (status, hosts_export))

    dhcp_server_id = service.ipam_db.add_dhcp_server("10.9.9.5", "test-dhcp")
    service.ipam_db.replace_dhcp_leases(
        dhcp_server_id, [{"ip": "10.9.9.4", "mac": "11:22:33:44:55:66",
                          "hostname": "leased-host", "scope_id": "s1"}])
    status, leases_export = call("GET", "/api/ipam/dhcp/leases/export.csv", token=admin)
    check("dhcp leases export answers 200 and sees the inserted lease",
          status == 200 and leases_export.get("count", 0) >= 1, (status, leases_export))

    # ------------------------------------------------------- wireless
    print("wireless aps export")
    controller_id = service.wireless_db.add_controller("test-ctrl", "10.9.9.3")
    service.wireless_db.upsert_ap(controller_id, "ap-1", "root", name="Lobby AP",
                                  status="online", model="FAP-221E",
                                  mac_address="00:11:22:33:44:55")
    status, aps_export = call("GET", "/api/wireless/aps/export.csv", token=admin)
    check("wireless aps export answers 200 and sees the inserted AP",
          status == 200 and aps_export.get("count", 0) >= 1, (status, aps_export))

    # ---------------------------------------------------- permission gate
    # Mirrors test_web_gates.py's own semantics: read is enough for an
    # export (it is a read of the same data the JSON list already shows),
    # but only on the module the route belongs to — a syslog:read account
    # has no business exporting the device inventory.
    print("permission gate: read is enough, but only on the owning module")
    service.app_db.add_user("csv-reader", hash_password("CsvReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("csv-reader", {"syslog": "read"})
    reader = login("csv-reader", "CsvReaderPW2026")

    status, _payload = call("GET", "/api/syslog/search/export.csv", token=reader)
    check("a syslog:read account may export syslog", status == 200, status)

    for path in ("/api/nodes/devices/export.csv", "/api/alerts/export.csv",
                 "/api/netflow/records/export.csv", "/api/snmp/traps/export.csv",
                 "/api/ipam/hosts/export.csv", "/api/wireless/aps/export.csv"):
        status, payload = call("GET", path, token=reader)
        check(f"a syslog:read account is refused {path}", status == 403, (status, payload))

    status, payload = call("GET", "/api/nodes/devices/export.csv")
    check("no session at all is refused with 401", status == 401, (status, payload))

finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
