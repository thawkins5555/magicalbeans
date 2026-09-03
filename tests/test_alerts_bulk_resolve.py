"""Bulk Resolve, through the real HTTP route, resolves and stays resolved.

`tests/test_alert_operator_resolve.py` proves the engine rule that makes this
work by driving AlertEngine directly. This suite proves the operator's actual
path: three devices down, their outages ticked in the list, one
`POST /api/alerts/bulk-resolve` carrying all three ids, "Resolved 3 of 3" —
and then the next engine tick, which is where it used to go wrong. Within
five seconds of the click the engine re-opened one "Packet loss to device
high" per device (a device that answers nothing records 100 % loss on every
poll), each with its own email, because a rollup child is only suppressed
while its parent alert is OPEN.

Real `Service` and `WebServer` on a loopback port, the same shape as
`tests/test_ssh_hostkeys.py` section 10. Nothing is started that polls or
ticks on its own: the poll results are written the way nodepoll writes them
and the engine is ticked by hand, so the test is deterministic rather than
timing-dependent.
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

TMPDIR = _paths.tmpdir("alerts_bulk_resolve_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))

# Rollup on (the shipped default, and the whole point here); no new-device
# grace, because every device in this test is seconds old and would otherwise
# have its outage held back; email off so nothing needs SMTP.
service.alerts_db.save_settings({"rollup_enabled": True, "email_enabled": False,
                                 "new_device_grace_s": 0})

web_port = _paths.free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error

try:
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

    admin_token = login(DEFAULT_USER, DEFAULT_PASSWORD)
    status, payload = call("POST", "/api/users",
                           {"username": "viewer",
                            "password": "Corr3ct-Horse-Battery",
                            "grants": {"alerts": "read"}}, token=admin_token)
    assert status == 200, (status, payload)
    viewer_token = login("viewer", "Corr3ct-Horse-Battery")

    nodes_db = service.nodes_db
    engine = service.alert_engine
    group_id = nodes_db.ensure_default_group()
    devices = [nodes_db.add_device(f"10.30.0.{n}", name=f"branch-sw-{n}",
                                   group_id=group_id) for n in (1, 2, 3)]
    down_rule = service.alerts_db.rule_by_key("device_down")
    loss_rule = service.alerts_db.rule_by_key("packet_loss_high")

    def failed_poll(ts):
        """What nodepoll writes for a device that answers nothing: the live
        state (status "down") and 100 % packet loss, on every device."""
        for device_id in devices:
            nodes_db.record_poll(device_id, ping_ok=False, ping_rtt_ms=None,
                                 snmp_ok=None, snmp_error=None, identity=None,
                                 uptime_ticks=None, status="down",
                                 reachable=False)
            nodes_db.record_metric_sample(device_id, "ping_loss_pct",
                                          "Packet loss", "%", "gauge", ts, 100.0)

    def open_ids(rule):
        status, payload = call("GET", f"/api/alerts?state=open&rule_id={rule['id']}",
                               token=admin_token)
        assert status == 200, (status, payload)
        return [row["id"] for row in payload["alerts"]]

    engine._tick()                      # seeds the drain cursors
    base = time.time()
    failed_poll(base)
    for device_id in devices:
        nodes_db.record_device_event(device_id, "down", "not responding")
    engine._tick()
    outage_ids = open_ids(down_rule)
    check("three devices down: three outages in the list",
          len(outage_ids) == 3, outage_ids)

    # 70 s of sustained loss is what packet_loss_high asks for (for_seconds=60).
    # Every one of the three breaches, and every one is suppressed behind its
    # device's open outage — which is the state the operator presses Resolve in.
    failed_poll(base + 70)
    engine._tick()
    check("...and the packet loss they all report is rolled up under them",
          open_ids(loss_rule) == [] and engine.counters["rolled_up"] >= 3,
          (open_ids(loss_rule), engine.counters["rolled_up"]))

    status, payload = call("POST", "/api/alerts/bulk-resolve",
                           {"alert_ids": outage_ids}, token=viewer_token)
    check("bulk resolve is refused to a read-only account", status == 403,
          (status, payload))

    status, payload = call("POST", "/api/alerts/bulk-resolve",
                           {"alert_ids": outage_ids}, token=admin_token)
    check("the real route resolves all three at once",
          status == 200 and payload.get("resolved") == 3, (status, payload))
    check("...and none of the three is open any more", open_ids(down_rule) == [],
          open_ids(down_rule))

    # The tick that used to undo it. The devices are still down, so the loss
    # is still 100 %, so every child is still breaching — and every child is
    # still covered by the outage its operator resolved.
    opened_before = engine.counters["opened"]
    failed_poll(base + 140)
    engine._tick()
    check("the next engine tick opens nothing", open_ids(loss_rule) == [],
          open_ids(loss_rule))
    check("...and notifies about nothing",
          engine.counters["opened"] == opened_before,
          (engine.counters["opened"], opened_before))

    for _ in range(3):
        engine._tick()
    status, payload = call("GET", "/api/alerts?state=open", token=admin_token)
    check("...and after three more ticks the whole open list is still empty",
          status == 200 and payload["alerts"] == [],
          (status, [row.get("message") for row in payload.get("alerts", [])]))

    status, payload = call("GET", f"/api/alerts?rule_id={down_rule['id']}",
                           token=admin_token)
    resolved = [row for row in payload["alerts"] if row["state"] == "resolved"]
    check("the three outages stay resolved, by the account that resolved them",
          len(resolved) == 3
          and all(row.get("resolved_by") == DEFAULT_USER for row in resolved),
          [(row["state"], row.get("resolved_by")) for row in payload["alerts"]])
finally:
    server.stop()
    service.shutdown()
    # In the finally, not after it: a crash anywhere above used to leave a
    # whole temp tree of databases behind on every run.
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
