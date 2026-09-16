"""GET /api/nodes/devices/<id>/interfaces/<if_index>/config: the Interface
Detail dialog's RUNNING CONFIGURATION route, driven against a real
Service+WebServer -- the happy path, no backup, no matching stanza, and the
dual configrx-read + nodes-read gate."""
import http.client
import json
import os

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("configrx_stanza_route_")
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


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    db = service.nodes_db
    gid = db.ensure_default_group()

    did = db.add_device("10.96.0.1", name="cx-stanza-1", group_id=gid)
    db.replace_interfaces(did, [
        {"if_index": 1, "descr": "GigabitEthernet1/0/1", "name": "Gi1/0/1"},
        {"if_index": 3, "descr": "GigabitEthernet1/0/3", "name": "Gi1/0/3"},
    ])
    did_nobackup = db.add_device("10.96.0.2", name="cx-stanza-2", group_id=gid)
    db.replace_interfaces(did_nobackup, [
        {"if_index": 1, "descr": "GigabitEthernet1/0/1", "name": "Gi1/0/1"},
    ])

    service.configrx_db.add_backup(did, (
        "hostname cx-stanza-1\n!\n"
        "interface GigabitEthernet1/0/1\n description uplink\n!\n"
        "interface GigabitEthernet1/0/2\n shutdown\n!\n"))

    print("GET /api/nodes/devices/<id>/interfaces/<if_index>/config")
    status, payload = call(
        "GET", f"/api/nodes/devices/{did}/interfaces/1/config", token=admin)
    check("200, and the port's own stanza comes back",
          status == 200 and payload["text"] is not None
          and "description uplink" in payload["text"]
          and "GigabitEthernet1/0/2" not in payload["text"]
          and payload["backup_id"] is not None and payload["ts"] is not None,
          (status, payload))

    status, payload = call(
        "GET", f"/api/nodes/devices/{did}/interfaces/3/config", token=admin)
    check("a port that exists but has no stanza in the latest backup: text is null",
          status == 200 and payload["text"] is None and payload["backup_id"] is not None,
          (status, payload))

    status, payload = call(
        "GET", f"/api/nodes/devices/{did}/interfaces/2/config", token=admin)
    check("a port with no interface row at all: text is null",
          status == 200 and payload["text"] is None and payload["backup_id"] is not None,
          (status, payload))

    status, payload = call(
        "GET", f"/api/nodes/devices/{did_nobackup}/interfaces/1/config", token=admin)
    check("a device with no stored backup at all: everything null",
          status == 200 and payload == {"backup_id": None, "ts": None, "text": None,
                                        "searched": [], "headers": 0},
          (status, payload))

    status, payload = call(
        "GET", f"/api/nodes/devices/{did}/interfaces/3/config", token=admin)
    check("searched carries the candidate names in order name then descr, "
          "headers counts every 'interface' header in the backup",
          status == 200 and payload["searched"] == ["Gi1/0/3", "GigabitEthernet1/0/3"]
          and payload["headers"] == 2,
          (status, payload))

    # -------------------------------------------------------------- gates
    print("gates: needs BOTH configrx:read and nodes:read")
    service.app_db.add_user("cx-stanza-nodes-only", hash_password("CxStanzaNodesOnlyPW2026"),
                            must_change=False)
    service.app_db.set_permissions("cx-stanza-nodes-only", {"nodes": "read"})
    nodes_only = login("cx-stanza-nodes-only", "CxStanzaNodesOnlyPW2026")
    status, payload = call(
        "GET", f"/api/nodes/devices/{did}/interfaces/1/config", token=nodes_only)
    check("nodes:read alone (no configrx grant) is refused",
          status == 403, (status, payload))

    service.app_db.add_user("cx-stanza-configrx-only",
                            hash_password("CxStanzaConfigrxOnlyPW2026"), must_change=False)
    service.app_db.set_permissions("cx-stanza-configrx-only", {"configrx": "read"})
    configrx_only = login("cx-stanza-configrx-only", "CxStanzaConfigrxOnlyPW2026")
    status, payload = call(
        "GET", f"/api/nodes/devices/{did}/interfaces/1/config", token=configrx_only)
    check("configrx:read alone (no nodes grant) is refused",
          status == 403, (status, payload))
    status, payload = call(
        "GET", "/api/nodes/devices/999999/interfaces/1/config", token=configrx_only)
    check("configrx:read alone against a nonexistent device id: 403, not 404",
          status == 403, (status, payload))
finally:
    server.stop()
    service.shutdown()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
