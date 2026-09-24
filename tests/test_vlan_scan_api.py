"""`POST /api/nodes/vlan-scan` -- the Nodes toolbar's fleet-wide VLAN scan
button, driven against a real Service + WebServer over loopback: the
poller-stopped 400, the nodes-write permission gate, the Events log line and
the audit row. The poller's own walk_vlans_now is exercised in
test_vlan_scan_now.py; here it is a spy.
"""
import http.client
import json
import os

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.nodepoll import NodePoller
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("vlan_scan_api_")
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
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"), initial_admin_password="admin")
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


def last_audit(action, target=None):
    import time
    rows = service.app_db.audit_query(0, time.time() + 60, action=action,
                                      target=target or "", limit=50)
    return rows[0] if rows else None


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # `running` is read-only on Worker, so stubbed on the class for the
    # duration of the success/permission checks below -- the same pattern
    # test_poller_behaviour.py uses to reach a poller's "started" branches
    # without a real thread.
    real_running = NodePoller.running
    NodePoller.running = property(lambda self: True)

    spy_calls = []
    real_walk_vlans_now = service.node_poller.walk_vlans_now

    def spy_walk_vlans_now():
        spy_calls.append(True)
        return {"running": True, "queued": 3, "already_running": 1, "skipped": 2}

    service.node_poller.walk_vlans_now = spy_walk_vlans_now

    try:
        print("admin: 200 with counts, spy called once, logged, audited")
        status, result = call("POST", "/api/nodes/vlan-scan", {}, token=admin)
        check("200", status == 200, (status, result))
        check("body carries ok and the three counts",
              result.get("ok") is True and result.get("queued") == 3
              and result.get("already_running") == 1 and result.get("skipped") == 2,
              result)
        check("walk_vlans_now was called exactly once", len(spy_calls) == 1, spy_calls)
        check("the Events log has a line starting 'VLAN scan requested'",
              any(e.message.startswith("VLAN scan requested")
                  for e in service.log.all()),
              [e.message for e in service.log.all()][-5:])
        row = last_audit("device.vlan_scan", "3 devices")
        check("audit row device.vlan_scan targets '3 devices'",
              row is not None, row and dict(row))

        print("read-only account: 403")
        service.app_db.add_user("vs-reader", hash_password("VlanReaderPW2026"), must_change=False)
        service.app_db.set_permissions("vs-reader", {"nodes": "read"})
        reader = login("vs-reader", "VlanReaderPW2026")
        status, refused = call("POST", "/api/nodes/vlan-scan", {}, token=reader)
        check("a nodes:read-only account is refused (write is required)",
              status == 403, (status, refused))
        check("...and the spy was not called a second time", len(spy_calls) == 1, spy_calls)
    finally:
        service.node_poller.walk_vlans_now = real_walk_vlans_now
        NodePoller.running = real_running

    print("poller stopped: 400 naming the poller")
    status, stopped = call("POST", "/api/nodes/vlan-scan", {}, token=admin)
    check("poller not running answers 400", status == 400, (status, stopped))
    check("...and the error names the poller",
          "poller" in str(stopped.get("error", stopped)).lower(), stopped)

finally:
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
