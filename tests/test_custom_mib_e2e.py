import base64
import http.client
import json
import os
import socket
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
    # 4.37 refuses every API route for an account whose password must still
    # be changed, so clear the flag rather than re-password every account
    # this suite uses. The stored hash goes back unchanged.
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
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

finally:
    server.stop()
    service.shutdown()
    stub.kill()


# ------------------------------------------- a MIB too large for one GET
#
# _poll_custom_mib put every resolved object of the file into ONE GET:
# IP-MIB alone is 267 varbinds, and an agent that will not answer that many
# replies tooBig(1) with an empty varbind list (RFC 3416). Nothing raised,
# nothing was logged and no metric was ever produced -- for a MIB
# _auto_assign_mib had attached with no operator involvement.

from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase

big_stub, big_port = spawn_stub("stub_agent_toobig.py", "10")
nodepoll_mod.DEFAULT_SNMP_PORT = big_port
try:
    db = NodesDatabase(os.path.join(TMPDIR, "toobig.db"))
    group_id = db.ensure_default_group()
    db.update_group(group_id, snmp_version=1, community="public",
                    snmp_timeout_s=1.0, snmp_retries=0)
    mib_id = db.add_mib_file("big.mib", "BIG-MIB", 100, [], "")
    db.replace_mib_objects(mib_id, [
        {"name": f"bigScalar{n:03d}", "oid": f"1.3.6.1.4.1.99999.{n}",
         "description": "", "syntax": "INTEGER", "enums": None,
         "is_notification": False}
        for n in range(1, 101)])
    device_id = db.add_device("127.0.0.1", "toobig-device", group_id=group_id,
                              ping_enabled=0, mib_file_id=mib_id)
    poller = NodePoller(db)
    device = db.device(device_id)
    metrics = poller._poll_custom_mib(device, db.effective_config(device), mib_id)
    values = {key: value for key, _label, _unit, _kind, value in metrics}
    assert len(values) == 100, (len(values), sorted(values)[:5])
    assert values["mib_bigScalar001"] == 1 and values["mib_bigScalar100"] == 100, \
        (values.get("mib_bigScalar001"), values.get("mib_bigScalar100"))
    print(f"a 100-object MIB against an agent that refuses more than 10 "
          f"varbinds produced all {len(values)} metrics OK")

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.settimeout(2.0)
    probe.sendto(b"BIGGEST", ("127.0.0.1", big_port))
    biggest = int(probe.recv(64))
    probe.close()
    assert biggest <= 25, biggest
    learned = poller._get_batch.get(device_id)
    assert learned is not None and learned <= 10, learned
    print(f"the largest GET it ever sent was {biggest} varbinds, and the "
          f"batch size this agent takes ({learned}) is remembered OK")
    db.close()
finally:
    big_stub.kill()

print("ALL CUSTOM-MIB E2E ASSERTIONS PASSED")
