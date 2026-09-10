"""The Host box, end to end through the API.

The stored `logs.host` is only what the device put in its own syslog header.
The name an operator reads in the Host column is usually resolved from Nodes
or DNS when the page is drawn, and was never written down -- so searching for
the name on screen used to return nothing for exactly the devices the
cross-reference exists to help with. These pin the resolution the API layer
now does before the query runs.
"""
import http.client
import json
import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.syslogparse import LogEntry
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("syslog_host_")
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
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error


def call(path, token):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    conn.request("GET", path, headers={"Cookie": f"sw_session={token}"})
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    return response.status, json.loads(raw)


def login():
    row = service.app_db.user(DEFAULT_USER)
    if row is not None and row["must_change"]:
        service.app_db.set_password(DEFAULT_USER, row["password"], must_change=False)
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    conn.request("POST", "/api/login",
                 body=json.dumps({"username": DEFAULT_USER,
                                  "password": DEFAULT_PASSWORD}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    return cookie.split("sw_session=")[1].split(";")[0]


try:
    token = login()
    now = time.time()

    # Two devices Nodes knows by name, and one address it does not.
    service.nodes_db.add_device("10.20.3.4", name="core-sw-01")
    service.nodes_db.add_device("10.20.3.5", name="edge-rtr-09")

    service.syslog_db.insert([
        # Self-reports nothing: the Host column is filled in from Nodes.
        LogEntry(ts=now - 60, source="10.20.3.4", host="", message="link down"),
        # Self-reports its own name.
        LogEntry(ts=now - 50, source="10.20.3.5", host="edge-rtr-09",
                 message="bgp neighbor reset"),
        # Nobody knows this one.
        LogEntry(ts=now - 40, source="10.20.9.9", host="", message="unrelated"),
    ])

    window = f"t0={int(now - 3600)}&t1={int(now + 60)}&limit=50"

    status, payload = call(f"/api/syslog/search?{window}&host=core-sw", token)
    messages = payload.get("messages", []) if status == 200 else []
    sources = [m.get("source") for m in messages]
    check("a blank self-reported host is found by the Nodes name",
          status == 200 and sources == ["10.20.3.4"], f"{status} {sources}")

    status, payload = call(f"/api/syslog/search?{window}&host=CORE-SW", token)
    sources = [m.get("source") for m in payload.get("messages", [])]
    check("the fragment is case-insensitive", sources == ["10.20.3.4"], sources)

    status, payload = call(f"/api/syslog/search?{window}&host=sw-01", token)
    sources = [m.get("source") for m in payload.get("messages", [])]
    check("a fragment from the middle of the name matches",
          sources == ["10.20.3.4"], sources)

    status, payload = call(f"/api/syslog/search?{window}&host=edge-rtr", token)
    sources = [m.get("source") for m in payload.get("messages", [])]
    check("a self-reported host still matches directly",
          sources == ["10.20.3.5"], sources)

    status, payload = call(f"/api/syslog/search?{window}&host=nothing-like-this", token)
    check("a fragment matching no device and no host returns nothing",
          payload.get("messages") == [], payload.get("messages"))

    status, payload = call(f"/api/syslog/search?{window}", token)
    check("an unfiltered search is unaffected",
          len(payload.get("messages", [])) == 3, payload.get("messages"))

    # The overrides contract the Nodes table reads.
    status, payload = call("/api/nodes/devices?limit=10", token)
    devices = payload.get("devices", []) if status == 200 else []
    check("every device carries an override count",
          bool(devices) and all("override_count" in d and "override_fields" in d
                                for d in devices),
          f"{status} {devices[:1]}")
    check("a device that overrides nothing reports zero",
          bool(devices) and all(d["override_count"] == 0 for d in devices),
          [d.get("override_count") for d in devices])

    device_id = devices[0]["id"]
    service.nodes_db.update_device(device_id, snmp_timeout_s=9)
    status, payload = call("/api/nodes/devices?overrides_only=1", token)
    devices = payload.get("devices", [])
    check("the overrides filter returns only the overriding device",
          [d["id"] for d in devices] == [device_id],
          [d.get("id") for d in devices])
    check("and it names the field",
          bool(devices) and devices[0]["override_fields"] == ["snmp_timeout_s"],
          devices[0].get("override_fields") if devices else None)
finally:
    server.stop()

print()
if FAILS:
    print(f"FAILURES: {len(FAILS)}")
    for name in FAILS:
        print("  - " + name)
    sys.exit(1)
print("FAILURES: none")
