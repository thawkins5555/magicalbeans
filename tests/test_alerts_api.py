"""The alert rows the web API hands the page, and the device mute that hangs
off them.

Everything here goes through a real `Service` and `WebServer` over loopback
HTTP with real sessions and real permission checks, because the questions are
about the wire format and about who is allowed to do what — neither of which
calling the handler functions directly would answer honestly.

The point of the device id on an alert row: Mute silences a *device*, and the
engine's suppression already resolves an interface alert to the switch the
port is on. The page cannot know that rule, so the API states it — a device
alert resolves to its own device, an interface alert to its parent, and
anything structurally outside Nodes (a syslog message, a DHCP scope) to
nothing at all, which is what makes the Mute control disable itself with a
reason instead of quietly vanishing.
"""
import http.client
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("alerts_api_")

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


def raise_alert(rule_key, entity_kind, entity_id, label, message):
    """One alert straight into the store, the way the engine's _apply would
    write it. No engine here on purpose: what is under test is the shape of
    the row the API returns, not what made it."""
    rule = service.alerts_db.rule_by_key(rule_key)
    assert rule is not None, rule_key
    row, _created = service.alerts_db.open_or_increment(
        rule["id"], f"{rule_key}:{entity_id}", entity_kind, str(entity_id),
        label, rule["severity"], message, "", time.time())
    return row["id"]


def alerts_by_id(token):
    status, payload = call("GET", "/api/alerts", token=token)
    assert status == 200, (status, payload)
    return {a["id"]: a for a in payload["alerts"]}


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # Read on alerts and nodes and nothing else: enough to see every alert
    # and every device, which is exactly the account that reported the Mute
    # button "missing" — it was hidden rather than disabled.
    status, payload = call("POST", "/api/users",
                           {"username": "viewer",
                            "password": "Corr3ct-Horse-Battery",
                            "grants": {"alerts": "read", "nodes": "read"}},
                           token=admin)
    assert status == 200, (status, payload)
    viewer = login("viewer", "Corr3ct-Horse-Battery")

    group_id = service.nodes_db.ensure_default_group()
    switch = service.nodes_db.add_device("192.0.2.20", name="Access Switch",
                                         group_id=group_id)
    service.nodes_db.replace_interfaces(switch, [
        {"if_index": 7, "descr": "GigabitEthernet0/7", "alias": "uplink",
         "admin_status": "up", "oper_status": "down"}])

    # ------------------------------------------------- 1. the device id

    device_alert = raise_alert("device_down", "device", switch,
                               "Access Switch (192.0.2.20)",
                               "Access Switch is not responding")
    iface_alert = raise_alert("interface_down", "interface", f"{switch}:7",
                              "Access Switch / GigabitEthernet0/7",
                              "GigabitEthernet0/7 is down")
    syslog_alert = raise_alert("syslog_critical", "syslog", "192.0.2.99",
                               "192.0.2.99", "kernel panic")

    rows = alerts_by_id(admin)
    check("a device alert carries its own device id",
          rows[device_alert]["device_id"] == switch,
          rows.get(device_alert))
    check("an interface alert resolves to the device the port is on",
          rows[iface_alert]["device_id"] == switch,
          rows.get(iface_alert))
    check("both carry the device's display name",
          rows[device_alert]["device_name"] == "Access Switch"
          and rows[iface_alert]["device_name"] == "Access Switch",
          (rows[device_alert]["device_name"], rows[iface_alert]["device_name"]))
    check("an alert about nothing in Nodes resolves to no device",
          rows[syslog_alert]["device_id"] is None
          and rows[syslog_alert]["device_name"] == "",
          rows.get(syslog_alert))

    status, payload = call("GET", f"/api/alerts/{iface_alert}", token=admin)
    check("the single-alert route carries the device id too",
          status == 200 and payload["alert"]["device_id"] == switch,
          (status, payload))

    # -------------------------------------- 2. muting from an interface alert

    # The device id the page would send for the interface alert above: this
    # is the whole point — the operator is looking at a port, and the mute
    # lands on the switch, which is what silences the port with it.
    mute_id = str(rows[iface_alert]["device_id"])
    status, payload = call("POST", "/api/alerts/mute",
                           {"entity_kind": "device", "entity_id": mute_id,
                            "hours": 2}, token=admin)
    check("muting the interface alert's device is accepted",
          status == 200 and payload["mute"]["entity_id"] == mute_id,
          (status, payload))
    until = payload["mute"]["until_ts"] if status == 200 else 0
    check("...for about the hours asked for",
          6000 < until - time.time() < 7400, until - time.time())

    status, payload = call("GET", "/api/alerts/mutes", token=viewer)
    listed = {m["entity_id"]: m for m in payload.get("mutes", [])} if status == 200 else {}
    check("the mute is listed, and a read-only account may see it",
          status == 200 and mute_id in listed
          and listed[mute_id]["entity_kind"] == "device", (status, payload))

    status, payload = call("GET", "/api/nodes/devices", token=viewer)
    devices = {d["id"]: d for d in payload.get("devices", [])} if status == 200 else {}
    check("the Nodes row for the parent device shows it as muted",
          status == 200 and devices.get(switch, {}).get("muted_until") == until,
          (status, devices.get(switch, {}).get("muted_until"), until))

    # ------------------------------------------------- 3. read-only is refused

    status, payload = call("POST", "/api/alerts/mute",
                           {"entity_kind": "device", "entity_id": mute_id,
                            "hours": 1}, token=viewer)
    check("a read-only account cannot mute", status == 403, (status, payload))

    status, payload = call("DELETE", "/api/alerts/mute",
                           {"entity_kind": "device", "entity_id": mute_id},
                           token=viewer)
    check("...nor lift one", status == 403, (status, payload))
    check("...and the mute is still standing afterwards",
          service.alerts_db.mute_row("device", mute_id) is not None)

    status, payload = call("POST", f"/api/alerts/{iface_alert}/resolve", {},
                           token=viewer)
    check("a read-only account cannot resolve an alert either",
          status == 403, (status, payload))

    # -------------------------------------------------------- 4. lifting it

    status, payload = call("DELETE", "/api/alerts/mute",
                           {"entity_kind": "device", "entity_id": mute_id},
                           token=admin)
    check("lifting the mute reports the row it removed",
          status == 200 and payload.get("lifted") is True, (status, payload))

    status, payload = call("GET", "/api/alerts/mutes", token=admin)
    check("...and the mute list is empty again",
          status == 200 and payload["mutes"] == [], (status, payload))

    status, payload = call("GET", "/api/nodes/devices", token=admin)
    devices = {d["id"]: d for d in payload.get("devices", [])} if status == 200 else {}
    check("...and the Nodes row no longer says muted",
          devices.get(switch, {}).get("muted_until") is None,
          devices.get(switch, {}).get("muted_until"))

    # ------------------------------- 5. a device that is gone is not muteable

    ghost = service.nodes_db.add_device("192.0.2.21", name="Removed Switch",
                                        group_id=group_id)
    ghost_alert = raise_alert("device_down", "device", ghost,
                              "Removed Switch (192.0.2.21)", "gone")
    service.nodes_db.remove_device(ghost)
    rows = alerts_by_id(admin)
    check("an alert whose device has been removed resolves to no device",
          rows[ghost_alert]["device_id"] is None, rows.get(ghost_alert))
finally:
    server.stop()
    service.shutdown()

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
