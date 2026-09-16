"""POST/GET /api/nodes/devices/<id>/sensor-snapshot, driven against a real
Service+WebServer: the snapshot stores a baseline row per psu_state/
stack_power_port/fan_state metric and resolves whatever is open on those
rules for the device, and the GET route reads the stored baseline back for
the dialog's 'Baseline taken ...' line."""
import http.client
import json
import os
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("sensor_snapshot_")
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
service.alerts_db.save_settings({"email_enabled": False, "rollup_enabled": False,
                                 "new_device_grace_s": 0, "notify_rollup_delay_s": 0})
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
    nodes_db = service.nodes_db
    engine = service.alert_engine
    gid = nodes_db.ensure_default_group()
    did = nodes_db.add_device("10.97.0.1", name="snapshot-sw", group_id=gid)
    engine._tick()

    base = time.time()
    nodes_db.record_metric_sample(did, "psu_state.2", "Power supply 2", "",
                                  "gauge", base, 2.0)
    nodes_db.record_metric_sample(did, "fan_state.1", "Fan 1", "", "gauge", base, 3.0)
    engine._tick()
    check("psu_state.2 == 2 opens psu_failed before any snapshot",
          len(service.alerts_db.alerts(state="unresolved",
                                       rule_id=service.alerts_db.rule_by_key("psu_failed")["id"])) == 1)
    check("fan_state.1 == 3 (not present) opens fan_failed too",
          len(service.alerts_db.alerts(state="unresolved",
                                       rule_id=service.alerts_db.rule_by_key("fan_failed")["id"])) == 1)

    print("GET /api/nodes/devices/<id>/sensor-snapshot before any snapshot")
    status, payload = call("GET", f"/api/nodes/devices/{did}/sensor-snapshot", token=admin)
    check("200, count 0, ts null", status == 200 and payload == {"count": 0, "ts": None}, payload)

    print("POST /api/nodes/devices/<id>/sensor-snapshot")
    status, payload = call("POST", f"/api/nodes/devices/{did}/sensor-snapshot", {}, token=admin)
    check("200, two sensors baselined (psu_state.2, fan_state.1)",
          status == 200 and payload["count"] == 2 and payload["ts"] is not None, payload)
    check("the baseline rows are actually stored",
          nodes_db.sensor_baselines(did) == {"psu_state.2": 2.0, "fan_state.1": 3.0},
          nodes_db.sensor_baselines(did))

    status, payload = call("GET", f"/api/nodes/devices/{did}/sensor-snapshot", token=admin)
    check("GET now reports the stored baseline",
          status == 200 and payload["count"] == 2 and payload["ts"] is not None, payload)

    check("the snapshot resolved the open psu_failed alert",
          service.alerts_db.alerts(
              state="unresolved", rule_id=service.alerts_db.rule_by_key("psu_failed")["id"]) == [])
    check("...and the open fan_failed alert",
          service.alerts_db.alerts(
              state="unresolved", rule_id=service.alerts_db.rule_by_key("fan_failed")["id"]) == [])
    resolved = service.alerts_db.alerts(state="resolved",
                                        rule_id=service.alerts_db.rule_by_key("psu_failed")["id"])
    check("...and left a 'Sensor snapshot' note on it",
          resolved and "Sensor snapshot" in (resolved[0]["rollup_note"] or ""),
          resolved and dict(resolved[0]))

    engine._tick()
    check("a later tick, same readings, does not re-open either alert",
          service.alerts_db.alerts(
              state="unresolved", rule_id=service.alerts_db.rule_by_key("psu_failed")["id"]) == []
          and service.alerts_db.alerts(
              state="unresolved", rule_id=service.alerts_db.rule_by_key("fan_failed")["id"]) == [])

    nodes_db.record_metric_sample(did, "psu_state.2", "Power supply 2", "",
                                  "gauge", time.time(), 3.0)
    engine._tick()
    check("a value WORSE than the baseline (3, not present) still opens the alert",
          len(service.alerts_db.alerts(
              state="unresolved", rule_id=service.alerts_db.rule_by_key("psu_failed")["id"])) == 1)

    # 5.35.0: a fan pulled AFTER a healthy snapshot. Baseline captures it
    # ok (0); nodepoll's own vanish detection (_mark_vendor_rows_absent)
    # later writes 3 (not present) for the same key when it drops out of a
    # complete walk entirely -- the engine compares against the BASELINE
    # value only (alertengine.py), so a genuinely new failure still opens
    # the alert even though a snapshot exists for this device.
    nodes_db.record_metric_sample(did, "fan_state.9", "Fan 9", "", "gauge",
                                  time.time(), 0.0)
    engine._tick()
    call("POST", f"/api/nodes/devices/{did}/sensor-snapshot", {}, token=admin)
    check("fan_state.9 baselined at 0 (ok)",
          nodes_db.sensor_baselines(did).get("fan_state.9") == 0.0,
          nodes_db.sensor_baselines(did))
    nodes_db.record_metric_sample(did, "fan_state.9", "Fan 9", "", "gauge",
                                  time.time(), 3.0)
    engine._tick()
    check("the tray vanishing after the snapshot (baseline 0, now 3) opens "
          "fan_failed -- baseline equality does not suppress a genuinely "
          "new not-present reading",
          len(service.alerts_db.alerts(
              state="unresolved", rule_id=service.alerts_db.rule_by_key("fan_failed")["id"])) == 1)

    print("gates: needs nodes write to POST, nodes read to GET")
    from netpath.auth import hash_password
    service.app_db.add_user("snapshot-reader", hash_password("SnapshotReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("snapshot-reader", {"nodes": "read"})
    reader = login("snapshot-reader", "SnapshotReaderPW2026")
    status, payload = call("POST", f"/api/nodes/devices/{did}/sensor-snapshot", {}, token=reader)
    check("nodes:read alone cannot POST the snapshot", status == 403, (status, payload))
    status, payload = call("GET", f"/api/nodes/devices/{did}/sensor-snapshot", token=reader)
    check("nodes:read may GET it", status == 200, (status, payload))
finally:
    server.stop()
    service.shutdown()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
