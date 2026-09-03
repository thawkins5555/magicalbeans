"""The three server-side gates a browser must not be trusted to enforce.

Each covers a defect the UI review reproduced against a running instance:

  * an account that still owes a password change could use the whole API,
    because "must change" was only ever a dialog the browser raised and
    Escape dismissed;
  * a device could be created at `999.999.1.oops`, which then sat in the
    inventory looking exactly like a device that was merely down;
  * /api/state drops a module's block for an account that cannot read it,
    which is correct — this pins the shape so the next key added to a
    module's block cannot quietly become a required one for everybody.

There is no browser here on purpose: these are the halves that have to hold
whatever the page does.
"""

import http.client
import json
import os
import sys
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("web_gates_")

from netpath.web import Service, WebServer
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password

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

ADMIN_PASSWORD = "GatesSuiteAdmin2026"
READER_PASSWORD = "GatesSuiteReader2026"
failures = []


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
    status, payload, headers = call(
        "POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return headers.get("Set-Cookie", "").split("sw_session=")[1].split(";")[0]


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


try:
    # ---------------------------------------------------- must_change gate
    # The default account is seeded owing a change, so this is the state a
    # fresh install is actually in.
    print("must_change gate")
    token = login(DEFAULT_USER, DEFAULT_PASSWORD)

    status, payload, _ = call("GET", "/api/state", token=token)
    check("/api/state is reachable (it is what raises the prompt)", status == 200, status)

    status, payload, _ = call("POST", "/api/heartbeat", {}, token=token)
    check("/api/heartbeat is reachable (it keeps the session alive meanwhile)",
          status == 200, status)

    status, payload, _ = call("POST", "/api/nodes/devices", {"ip": "10.0.0.1"}, token=token)
    check("a normal write is refused", status == 403, f"{status} {payload}")

    status, payload, _ = call("GET", "/api/nodes/devices", token=token)
    check("a normal read is refused", status == 403, f"{status} {payload}")

    status, payload, _ = call("POST", "/api/password",
                              {"current_password": DEFAULT_PASSWORD,
                               "new_password": ADMIN_PASSWORD}, token=token)
    check("the change itself is allowed", status == 200, f"{status} {payload}")

    # Changing a password destroys every session for that account, so this
    # is a fresh sign-in rather than a reused token.
    token = login(DEFAULT_USER, ADMIN_PASSWORD)
    status, payload, _ = call("GET", "/api/nodes/devices", token=token)
    check("the API opens up once the password is replaced", status == 200, status)

    # ------------------------------------------------ device address checks
    print("device address validation")
    for bad, why in [("999.999.1.oops", "not an address at all"),
                     ("core-sw-01.example.com", "a hostname"),
                     ("10.20.3", "a truncated address"),
                     ("", "blank")]:
        status, payload, _ = call("POST", "/api/nodes/devices", {"ip": bad}, token=token)
        check(f"refuses {why}: {bad!r}", status != 200, f"{status} {payload}")

    for good in ["10.20.3.7", "2001:db8::1"]:
        status, payload, _ = call("POST", "/api/nodes/devices", {"ip": good}, token=token)
        check(f"accepts {good}", status == 200, f"{status} {payload}")

    status, payload, _ = call("POST", "/api/nodes/devices", {"ip": "10.20.3.7"}, token=token)
    check("still refuses a duplicate", status != 200, f"{status} {payload}")

    # ------------------------------------------------- /api/state per grant
    # The bug this pins: a module's block is omitted for an account that
    # cannot read it, and the page used to assume every block was present.
    print("/api/state shape per permission set")
    service.app_db.add_user("reader", hash_password(READER_PASSWORD), must_change=False)
    service.app_db.set_permissions("reader", {"nodes": "read", "syslog": "read"})
    reader_token = login("reader", READER_PASSWORD)

    # Since 4.43.0 the settings blocks live on /api/config and the live
    # blocks on /api/state; the same per-module gate applies to both.
    status, reader_state, _ = call("GET", "/api/config", token=reader_token)
    check("a limited account can read config at all", status == 200, status)
    check("its own modules' blocks are present",
          "nodes_settings" in reader_state and "syslog_settings" in reader_state,
          sorted(k for k in reader_state if k.endswith("_settings")))
    check("blocks it cannot read are absent",
          "dimensions" not in reader_state and "flow_settings" not in reader_state,
          "dimensions" in reader_state)
    check("permissions name exactly what was granted",
          sorted(reader_state["permissions"]) == ["nodes", "syslog"],
          reader_state["permissions"])

    status, admin_config, _ = call("GET", "/api/config", token=token)
    check("an account that can read NetFlow still gets its block",
          "dimensions" in admin_config and "flow_settings" in admin_config)
    status, reader_live, _ = call("GET", "/api/state", token=reader_token)
    check("live blocks it cannot read are absent too",
          "collector" not in reader_live and "nodes" in reader_live,
          sorted(k for k in reader_live if k in ("collector", "nodes", "syslog", "snmp")))
    check("both halves carry the same config_version",
          reader_live.get("config_version") == reader_state.get("config_version")
          and isinstance(reader_live.get("config_version"), int))
    status, admin_state, _ = call("GET", "/api/state", token=token)

    # Both session countdowns are sent, so the browser can warn before either
    # ends. The absolute one used to be missing entirely and arrived as a
    # sudden redirect to the sign-in page.
    session = admin_state["session"]
    check("session carries the idle countdown",
          session.get("idle_seconds_remaining") is not None, session)
    check("session carries the absolute countdown",
          session.get("max_seconds_remaining") is not None, session)

    # --------------------------------------------- 4.44.0: since, counts, toggle
    print("since when, honest counts, the IPAM toggle")
    status, payload, _ = call("GET", "/api/nodes/devices", token=token)
    devices = payload.get("devices") or payload if isinstance(payload, dict) else payload
    if isinstance(devices, dict):
        devices = devices.get("devices", [])
    device_id = devices[0]["id"] if devices else None
    check("a device exists to inspect", device_id is not None, str(payload)[:120])
    if device_id is not None:
        status, detail, _ = call("GET", f"/api/nodes/devices/{device_id}", token=token)
        d = detail.get("device", detail)
        check("the device carries status_since_ts and sys_uptime_s",
              "status_since_ts" in d and "sys_uptime_s" in d, sorted(d)[:8])
        if d.get("status") == "up":
            check("up since the last time it was seen down",
                  d["status_since_ts"] == (d.get("last_down_ts") or d.get("created_ts")))
        elif d.get("status") == "down":
            check("down since the last time it was seen up",
                  d["status_since_ts"] == (d.get("last_up_ts") or d.get("created_ts")))
        else:
            check("an unknown state has no since", d["status_since_ts"] is None, d.get("status"))
    for path in ("/api/syslog/search?limit=5", "/api/snmp/traps?limit=5"):
        status, payload, _ = call("GET", path, token=token)
        check(f"{path.split('?')[0]} says whether it was cut off",
              status == 200 and "truncated" in payload and payload.get("cap") == 2000
              and payload.get("limit") == 5, str(payload)[:100])
    status, before, _ = call("GET", "/api/state", token=token)
    status, payload, _ = call("POST", "/api/ipam/worker", {"action": "stop"}, token=token)
    check("the IPAM worker can be stopped from its strip", status == 200 and payload.get("enabled") is False,
          f"{status} {payload}")
    status, config, _ = call("GET", "/api/config", token=token)
    check("and the choice is persisted like the settings checkbox",
          config.get("ipam_settings", {}).get("enabled") is False
          and config["config_version"] > before["config_version"])
    status, payload, _ = call("POST", "/api/ipam/worker", {"action": "start"}, token=token)
    check("and started again", status == 200 and payload.get("enabled") is True, f"{status} {payload}")
    status, payload, _ = call("POST", "/api/ipam/worker", {"action": "dance"}, token=token)
    check("an unknown action is refused", status == 400, status)

    print("FAILED: " + ", ".join(failures) if failures else "ALL WEB GATE ASSERTIONS PASSED")
finally:
    server.stop()
    # Adding a device queues a first poll, and shutting the service down
    # under an in-flight one closes the database out from beneath the
    # worker. Wait it out rather than printing a traceback that looks like
    # a failure of the thing this suite is actually testing.
    deadline = time.time() + 20
    while time.time() < deadline and service.node_poller.worker_state():
        time.sleep(0.1)
    service.shutdown()

sys.exit(1 if failures else 0)
