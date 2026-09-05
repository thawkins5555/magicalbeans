"""4.49.0: GET /api/nodes/devices/<id> surfaces devices.vendor_arc alongside
vendor_source/vendor_confidence — the enterprise arc a device's sysObjectID
actually sits under, or None. Needed because vendor_source/vendor_confidence
alone cannot distinguish a device with a real but unnamed arc from one that
only answers a generic net-snmp sysObjectID and therefore has NO arc at
all — the second case can never receive VENDOR_HEALTH (keyed by arc), and
a device pane needs vendor_arc to say why, rather than showing a blank
pane an operator reads as a fault.
"""
import http.client
import json
import os

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("vendor_arc_")
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


def set_vendor_arc(db, device_id, arc):
    with db._lock:
        db._conn.execute("UPDATE devices SET vendor_arc = ? WHERE id = ?", (arc, device_id))
        db._conn.commit()


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    db = service.nodes_db
    gid = db.ensure_default_group()

    with_arc = db.add_device("10.65.0.1", name="arc-device", group_id=gid)
    set_vendor_arc(db, with_arc, 9)   # Cisco's enterprise number

    without_arc = db.add_device("10.65.0.2", name="generic-device", group_id=gid)
    # vendor_arc left NULL: a generic net-snmp sysObjectID answers a
    # description but sits under no real enterprise arc at all.

    status, payload = call("GET", f"/api/nodes/devices/{with_arc}", token=admin)
    check("200", status == 200, (status, payload))
    check("vendor_arc surfaces for a device with a real arc",
          payload["device"].get("vendor_arc") == 9, payload["device"])

    status, payload = call("GET", f"/api/nodes/devices/{without_arc}", token=admin)
    check("200", status == 200, (status, payload))
    check("vendor_arc is None, not missing or 0, for a device with no arc at all",
          "vendor_arc" in payload["device"] and payload["device"]["vendor_arc"] is None,
          payload["device"])

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)
