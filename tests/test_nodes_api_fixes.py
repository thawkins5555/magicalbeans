"""Three findings from the full code review, driven against a real Service
and WebServer over loopback plus the discovery probe on its own:

- POST /api/nodes/devices used to drop `vendor_override` and `upstream_id`
  without a word (add_device's override filter never knew them), so a
  device created with a vendor pin or an upstream device got neither.
- POST /api/nodes/devices/<id>/test answered a socket() failure with a bare
  500 instead of the structured {"snmp": {"ok": false, "error": ...}}.
- nodediscover._snmp_identify took the first datagram that arrived, from
  any address with any request id, as the device's identity.
"""
import http.client
import json
import os
import socket
import sys
import threading

import _paths  # noqa: F401

from netpath import nodediscover, nodepoll
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.snmppoll import SnmpError, decode_response
from netpath.trapdecode import PDU_RESPONSE, T_SEQUENCE, _tlv, enc_int, enc_octets, enc_oid
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("nodes_api_fixes_")
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
                 body=json.dumps({"username": username,
                                  "password": password}).encode(),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    assert "sw_session=" in cookie, cookie
    return cookie.split("sw_session=")[1].split(";")[0]


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # ---------------------------------------------------- device creation
    status, core = call("POST", "/api/nodes/devices", {"ip": "10.9.0.1", "name": "core"},
                        token=admin)
    check("N1 a plain device is created", status == 200 and "id" in core, (status, core))
    status, edge = call("POST", "/api/nodes/devices",
                        {"ip": "10.9.0.2", "name": "edge", "upstream_id": core["id"],
                         "vendor_override": "Acme", "snmp_version": 1},
                        token=admin)
    check("N1 a device created with upstream_id and vendor_override is accepted",
          status == 200 and "id" in edge, (status, edge))
    status, row = call("GET", f"/api/nodes/devices/{edge['id']}", token=admin)
    device = row.get("device", row) if isinstance(row, dict) else {}
    check("N1 …its upstream_id is stored", device.get("upstream_id") == core["id"],
          (status, row))
    check("N1 …its vendor override is stored",
          (device.get("vendor_override") or "").lower() == "acme"
          and (device.get("vendor") or "").lower() == "acme", (status, row))
    check("N1 …and a profile column still lands too", device.get("snmp_version") == 1,
          (status, row))

    status, refused = call("POST", "/api/nodes/devices",
                           {"ip": "10.9.0.3", "upstream_id": 999999}, token=admin)
    check("N1 an unknown upstream is refused before the device exists",
          status == 400 and not service.nodes_db.device_by_ip("10.9.0.3"),
          (status, refused))
    status, refused = call("POST", "/api/nodes/devices",
                           {"ip": "10.9.0.4", "vendor_override": "x" * 65}, token=admin)
    check("N1 an over-long vendor name is refused before the device exists",
          status == 400 and not service.nodes_db.device_by_ip("10.9.0.4"),
          (status, refused))

    # ------------------------------------------------ device test on OSError
    real_init = nodepoll._Session.__init__

    def failing_init(self, *args, **kwargs):
        # What socket() raises under descriptor exhaustion, at the one
        # place in the handler that opens a socket.
        raise OSError(24, "Too many open files")

    nodepoll._Session.__init__ = failing_init
    try:
        status, result = call("POST", f"/api/nodes/devices/{core['id']}/test",
                              {}, token=admin)
    finally:
        nodepoll._Session.__init__ = real_init
    snmp = result.get("snmp", {}) if isinstance(result, dict) else {}
    check("N2 a socket() failure in the device test is a structured answer, not a 500",
          status == 200 and snmp.get("ok") is False
          and "Too many open files" in str(snmp.get("error", "")),
          (status, result))

    # --------------------------------------------------- discovery probe
    def snmp_response(request_id, oid, text):
        varbind = _tlv(T_SEQUENCE, enc_oid(oid) + enc_octets(text))
        pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0)
                   + _tlv(T_SEQUENCE, varbind))
        return _tlv(T_SEQUENCE, enc_int(1) + enc_octets("public") + pdu)

    sys_descr = "1.3.6.1.2.1.1.1.0"

    # An "agent" that answers correctly, and a "stranger" on another loopback
    # address that answers first, from the wrong address, with a bogus id.
    agent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    agent.bind(("127.0.0.1", 0))
    agent.settimeout(5)
    stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stranger.bind(("127.0.0.2", 0))
    nodediscover.DEFAULT_SNMP_PORT = agent.getsockname()[1]

    def agent_thread(honest: bool):
        data, addr = agent.recvfrom(65535)
        # decode_response reads a GetRequest's fields the same way the stub
        # agents do, which is all that is needed to learn its request id.
        rid = decode_response(data).request_id
        stranger.sendto(snmp_response(rid, sys_descr, "STRANGER"), addr)
        if honest:
            agent.sendto(snmp_response(rid + 1, sys_descr, "WRONG-ID"), addr)
            agent.sendto(snmp_response(rid, sys_descr, "GENUINE"), addr)

    worker = threading.Thread(target=agent_thread, args=(True,), daemon=True)
    worker.start()
    response = nodediscover._snmp_identify("127.0.0.1", 1, "public", 2.0, [sys_descr])
    worker.join(5)
    check("N3 the discovery probe ignores a datagram from another address and a wrong id",
          response.varbinds and response.varbinds[0]["value"] == "GENUINE",
          str(response.varbinds))

    worker = threading.Thread(target=agent_thread, args=(False,), daemon=True)
    worker.start()
    try:
        nodediscover._snmp_identify("127.0.0.1", 1, "public", 0.8, [sys_descr])
        outcome = "answered"
    except SnmpError as exc:
        outcome = type(exc).__name__
    worker.join(5)
    check("N3 …and with only the stranger answering, the probe times out",
          outcome == "SnmpTimeout", outcome)
    agent.close()
    stranger.close()
finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")
