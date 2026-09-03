import base64
import http.client
import json
import os
import sys
import time

from _paths import free_tcp_port, spawn_stub, tmpdir

TMPDIR = tmpdir("custom_mib_e2e_")

import netpath.nodepoll as nodepoll_mod
# The stub answers GET/GETNEXT for the system group, an empty ifTable and
# the custom MIB's scalar (testScalar = 42) on a free loopback port.
stub, STUB_PORT = spawn_stub("stub_agent_get_getnext.py")
nodepoll_mod.DEFAULT_SNMP_PORT = STUB_PORT

from netpath.web import Service, WebServer
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER


service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()

port = free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=port, certfile=None, keyfile=None)
assert server.start(block=False), server.error
print(f"server up on 127.0.0.1:{port}")

conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)


def call(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    return resp.status, payload, dict(resp.getheaders())


def login(username, password):
    status, payload, headers = call("POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return headers.get("Set-Cookie", "").split("sw_session=")[1].split(";")[0]


# The default account is created owing a password change, and the server now
# refuses everything except the change itself until it is done — so a test
# that wants to call the API has to do what an operator does on a fresh
# install. Changing it also destroys the session, hence the second sign-in.
FIRST_PASSWORD = "TestSuiteFirstPass2026"


def login_ready(username, password):
    token = login(username, password)
    status, payload, _ = call("POST", "/api/password",
                              {"current_password": password,
                               "new_password": FIRST_PASSWORD}, token=token)
    assert status == 200, (status, payload)
    return login(username, FIRST_PASSWORD)


TEST_MIB = """
TEST-MIB DEFINITIONS ::= BEGIN
testEnterprise OBJECT IDENTIFIER ::= { enterprises 99999 }
testScalar OBJECT-TYPE
    SYNTAX INTEGER
    ACCESS read-only
    STATUS mandatory
    DESCRIPTION "A test scalar for custom-MIB polling verification"
    ::= { testEnterprise 1 }
END
"""

try:
    admin_token = login_ready(DEFAULT_USER, DEFAULT_PASSWORD)

    content_b64 = base64.b64encode(TEST_MIB.encode()).decode()
    status, payload, _ = call("POST", "/api/nodes/mibs",
                              {"filename": "test.mib", "content": content_b64}, token=admin_token)
    assert status == 200, (status, payload)
    print("MIB upload result:", payload)
    # testEnterprise (OBJECT IDENTIFIER) + testScalar (OBJECT-TYPE), both
    # resolved -- only testScalar is a genuine polling target.
    assert payload["resolved_count"] == payload["object_count"] == 2, payload
    mib_file_id = payload["id"]

    status, payload, _ = call("POST", "/api/nodes/devices",
                              {"ip": "127.0.0.1", "name": "stub-device",
                               "snmp_version": 1, "community": "public"}, token=admin_token)
    assert status == 200, (status, payload)
    device_id = payload["id"]

    status, payload, _ = call("PUT", f"/api/nodes/devices/{device_id}",
                              {"mib_file_id": mib_file_id}, token=admin_token)
    assert status == 200, (status, payload)

    status, payload, _ = call("GET", f"/api/nodes/devices/{device_id}", token=admin_token)
    assert payload["device"]["mib_file_id"] == mib_file_id, payload["device"]
    print("device correctly shows assigned mib_file_id OK")

    status, payload, _ = call("POST", f"/api/nodes/devices/{device_id}/poll", {}, token=admin_token)
    assert status == 200, (status, payload)
    # Wait for the worker to finish rather than sleeping a fixed time:
    # shutting the service down under an in-flight poll closes the
    # database out from under it.
    deadline = time.time() + 15
    while time.time() < deadline and device_id in service.node_poller.worker_state():
        time.sleep(0.1)
    assert device_id not in service.node_poller.worker_state(), "poll never finished"

    status, payload, _ = call("GET", f"/api/nodes/devices/{device_id}", token=admin_token)
    print("device after poll: status=%r snmp_ok=%r snmp_error=%r" %
         (payload["device"]["status"], payload["device"]["snmp_ok"], payload["device"]["snmp_error"]))

    status, payload, _ = call("GET", f"/api/nodes/devices/{device_id}/metrics", token=admin_token)
    print("metrics:", payload)
    keys = [m["key"] for m in payload["metrics"]]
    assert "mib_testScalar" in keys, keys
    metric = next(m for m in payload["metrics"] if m["key"] == "mib_testScalar")
    assert metric["last_value"] == 42, metric
    assert metric["label"] == "testScalar", metric
    print("custom MIB scalar polled and stored under its own name with the right value OK")

    print("ALL CUSTOM-MIB E2E ASSERTIONS PASSED")
finally:
    server.stop()
    service.shutdown()
    stub.kill()
