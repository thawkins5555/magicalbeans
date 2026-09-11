"""Maintenance windows, bulk mute and un-acknowledge, at the web API layer.

Same harness as test_alerts_api.py: a real Service + WebServer over loopback
HTTP with real sessions and real permission checks, because the questions
here are about the wire format and about who is allowed to do what.
"""
import http.client
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.alertrules import Occurrence, dedup_key
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("alert_maintenance_")

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


def raise_alert(rule_key, entity_kind, entity_id, label, message):
    rule = service.alerts_db.rule_by_key(rule_key)
    occurrence = Occurrence(kind=rule["kind"], source_kind=rule["source_kind"] or "",
                            entity_kind=entity_kind, entity_id=str(entity_id),
                            entity_label=label, ts=time.time(), message=message)
    row, _created = service.alerts_db.open_or_increment(
        rule["id"], dedup_key(rule, occurrence), entity_kind, str(entity_id),
        label, rule["severity"], message, "", time.time())
    return row["id"]


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)
    status, payload = call("POST", "/api/users",
                           {"username": "viewer",
                            "password": "Corr3ct-Horse-Battery",
                            "grants": {"alerts": "read", "nodes": "read"}},
                           token=admin)
    assert status == 200, (status, payload)
    viewer = login("viewer", "Corr3ct-Horse-Battery")

    gid = service.nodes_db.ensure_default_group()
    dgid = service.nodes_db.add_device_group("Core")
    other_dgid = service.nodes_db.add_device_group("Edge")
    d1 = service.nodes_db.add_device("192.0.2.40", name="core1", group_id=gid,
                                     device_group_id=dgid)
    d2 = service.nodes_db.add_device("192.0.2.41", name="core2", group_id=gid,
                                     device_group_id=dgid)
    d3 = service.nodes_db.add_device("192.0.2.42", name="edge1", group_id=gid,
                                     device_group_id=other_dgid)

    # -------------------------------------- 1. window creation, gated

    now = time.time()
    status, payload = call("POST", "/api/alerts/windows", {
        "name": "Cutover", "scope_kind": "group", "scope_group_id": dgid,
        "start_ts": now - 5, "end_ts": now + 3600}, token=viewer)
    check("a read-only account cannot create a window", status == 403, (status, payload))

    status, payload = call("POST", "/api/alerts/windows", {
        "name": "Cutover", "scope_kind": "group", "scope_group_id": dgid,
        "start_ts": now - 5, "end_ts": now + 3600, "reason": "core swap"},
        token=admin)
    check("admin creates a window", status == 200, (status, payload))
    wid = payload["window"]["id"]
    check("...active immediately, since start_ts is in the past",
          payload["window"]["active"] is True, payload["window"])

    status, payload = call("GET", "/api/alerts/windows", token=viewer)
    check("a read-only account can list windows",
          status == 200 and any(w["id"] == wid for w in payload["windows"]),
          (status, payload))

    # ------------------------------------------------------ 2. cap and shape

    status, payload = call("POST", "/api/alerts/windows", {
        "name": "Too long", "scope_kind": "devices", "scope_device_ids": [d1],
        "start_ts": now, "end_ts": now + 20 * 86400}, token=admin)
    check("a window longer than 14 days is refused", status == 400, (status, payload))

    status, payload = call("POST", "/api/alerts/windows", {
        "name": "Backwards", "scope_kind": "devices", "scope_device_ids": [d1],
        "start_ts": now, "end_ts": now - 10}, token=admin)
    check("a window ending before it starts is refused", status == 400, (status, payload))

    status, payload = call("POST", "/api/alerts/windows", {
        "name": "No such group", "scope_kind": "group", "scope_group_id": 999999,
        "start_ts": now, "end_ts": now + 60}, token=admin)
    check("a window naming an absent device group is refused",
          status == 400, (status, payload))

    # --------------------------------------------------- 3. device list flag

    status, payload = call("GET", "/api/nodes/devices", token=viewer)
    devices = {d["id"]: d for d in payload["devices"]}
    check("a device covered by the active window shows muted_until",
          devices[d1]["muted_until"] is not None
          and devices[d2]["muted_until"] is not None, devices)
    check("a device outside the window's group does not",
          devices[d3]["muted_until"] is None, devices[d3])

    status, payload = call("GET", f"/api/nodes/devices/{d1}", token=viewer)
    check("the single-device page shows the same thing",
          status == 200 and payload["device"]["muted_until"] is not None,
          (status, payload))

    # ------------------------------------------------------- 4. edit + end

    status, payload = call("PUT", f"/api/alerts/windows/{wid}",
                           {"reason": "core swap, extended"}, token=viewer)
    check("a read-only account cannot edit a window", status == 403, (status, payload))

    status, payload = call("PUT", f"/api/alerts/windows/{wid}",
                           {"reason": "core swap, extended"}, token=admin)
    check("admin edits a window", status == 200 and
          payload["window"]["reason"] == "core swap, extended", (status, payload))

    status, payload = call("POST", f"/api/alerts/windows/{wid}/end", {}, token=viewer)
    check("a read-only account cannot end a window", status == 403, (status, payload))

    status, payload = call("POST", f"/api/alerts/windows/{wid}/end", {}, token=admin)
    check("admin ends the window now", status == 200 and
          payload["window"]["active"] is False, (status, payload))

    status, payload = call("GET", "/api/nodes/devices", token=admin)
    devices = {d["id"]: d for d in payload["devices"]}
    check("...and the device list stops showing the device as muted",
          devices[d1]["muted_until"] is None, devices[d1])

    # ------------------------------------------------- 5. future window inert

    status, payload = call("POST", "/api/alerts/windows", {
        "name": "Next weekend", "scope_kind": "devices", "scope_device_ids": [d1],
        "start_ts": now + 7 * 86400, "end_ts": now + 7 * 86400 + 3600},
        token=admin)
    check("a future window is created inactive",
          status == 200 and payload["window"]["active"] is False, (status, payload))
    future_id = payload["window"]["id"]

    status, payload = call("GET", "/api/nodes/devices", token=admin)
    devices = {d["id"]: d for d in payload["devices"]}
    check("...and does not mute its device yet",
          devices[d1]["muted_until"] is None, devices[d1])

    # ---------------------------------------------------------- 6. delete

    status, payload = call("DELETE", f"/api/alerts/windows/{wid}", {}, token=viewer)
    check("a read-only account cannot delete a window", status == 403, (status, payload))

    status, payload = call("DELETE", f"/api/alerts/windows/{wid}", {}, token=admin)
    check("admin deletes the ended window",
          status == 200 and payload["removed"] is True, (status, payload))
    status, payload = call("DELETE", f"/api/alerts/windows/{future_id}", {}, token=admin)
    check("...and the future one too", status == 200 and payload["removed"] is True,
          (status, payload))

    # ----------------------------------------------------- 7. bulk mute

    status, payload = call("POST", "/api/alerts/bulk-mute",
                           {"device_ids": [d1, d2, d3], "hours": 2, "reason": "batch"},
                           token=viewer)
    check("a read-only account cannot bulk-mute", status == 403, (status, payload))

    status, payload = call("POST", "/api/alerts/bulk-mute",
                           {"device_ids": [d1, d2, d3], "hours": 2, "reason": "batch"},
                           token=admin)
    check("admin bulk-mutes three devices in one call",
          status == 200 and payload["muted"] == 3, (status, payload))
    for device_id in (d1, d2, d3):
        row = service.alerts_db.mute_row("device", str(device_id))
        check(f"...device {device_id} is actually muted", row is not None)

    status, payload = call("POST", "/api/alerts/bulk-mute",
                           {"group_id": dgid, "hours": 500}, token=admin)
    check("bulk mute respects the 7-day ad-hoc cap even for a group",
          status == 200, (status, payload))
    if status == 200:
        row = service.alerts_db.mute_row("device", str(d1))
        check("...capped at 168 hours, not 500",
              row is not None and 167.9 * 3600 < row["until_ts"] - time.time() < 168.1 * 3600,
              row["until_ts"] - time.time() if row else None)

    status, payload = call("POST", "/api/alerts/bulk-mute", {"hours": 1}, token=admin)
    check("bulk mute with neither device_ids nor group_id is refused",
          status == 400, (status, payload))

    for device_id in (d1, d2, d3):
        service.alerts_db.unmute("device", str(device_id))

    # -------------------------------------------------- 8. unacknowledge

    alert_id = raise_alert("device_down", "device", d1, "core1", "down")
    status, payload = call("POST", f"/api/alerts/{alert_id}/ack", {}, token=admin)
    check("ack the alert first", status == 200, (status, payload))

    status, payload = call("POST", f"/api/alerts/{alert_id}/unack", {}, token=viewer)
    check("a read-only account cannot unacknowledge", status == 403, (status, payload))

    status, payload = call("POST", f"/api/alerts/{alert_id}/unack", {}, token=admin)
    check("admin unacknowledges it", status == 200, (status, payload))
    row = service.alerts_db.alert(alert_id)
    check("...state is back to open with the ack fields cleared",
          row["state"] == "open" and row["acked_by"] is None
          and row["acked_ts"] is None, (row["state"], row["acked_by"]))

    status, payload = call("POST", f"/api/alerts/{alert_id}/ack", {}, token=admin)
    status, payload = call("POST", "/api/alerts/bulk-unack",
                           {"alert_ids": [alert_id]}, token=viewer)
    check("a read-only account cannot bulk-unacknowledge", status == 403, (status, payload))

    status, payload = call("POST", "/api/alerts/bulk-unack",
                           {"alert_ids": [alert_id]}, token=admin)
    check("admin bulk-unacknowledges it",
          status == 200 and payload["unacknowledged"] == 1, (status, payload))
    row = service.alerts_db.alert(alert_id)
    check("...and it is open again", row["state"] == "open", row["state"])

    # ----------------------------------------------------- 9. trap DB cap

    from netpath import appdb
    check("the trap database's default size cap matches Syslog and Nodes (1024 MB)",
          appdb.GLOBAL_DEFAULTS["max_snmp_db_mb"] == 1024,
          appdb.GLOBAL_DEFAULTS["max_snmp_db_mb"])

    # ------------------------------- 10. bulk maintenance, at the store
    #
    # A planned cutover puts a whole device group into maintenance from the
    # bulk bar. Done a device at a time that is two alerts.db lock
    # acquisitions and one commit per device, on the request thread, while
    # the alert engine ticks against the same file. These are the batch
    # forms: one lock hold, one commit, the same parameters and the same
    # per-device semantics as set_maintenance/clear_maintenance.

    alerts_db = service.alerts_db
    FLEET = list(range(9000, 9500))

    class CountingConn:
        """The store's connection, with commits counted."""

        def __init__(self, inner):
            self._inner = inner
            self.commits = 0

        def commit(self):
            self.commits += 1
            return self._inner.commit()

        def __getattr__(self, name):
            return getattr(self._inner, name)

    real_conn = alerts_db._conn
    alerts_db._conn = CountingConn(real_conn)
    try:
        opened = alerts_db.set_maintenance_many(FLEET, by=DEFAULT_USER,
                                                reason="core cutover")
        commits = alerts_db._conn.commits
    finally:
        alerts_db._conn = real_conn
    check(f"set_maintenance_many puts all {len(FLEET)} devices into"
          f" maintenance in one commit",
          opened == len(FLEET) and commits == 1, (opened, commits))
    row = alerts_db.open_maintenance(FLEET[0])
    check("...with the same row set_maintenance writes: who, when and why",
          row is not None and row["started_by"] == DEFAULT_USER
          and row["reason"] == "core cutover" and row["ended_ts"] is None,
          dict(row) if row else None)
    check("...and every device reads as in maintenance",
          len(alerts_db.maintenance_device_ids()) >= len(FLEET),
          len(alerts_db.maintenance_device_ids()))

    started = row["started_ts"]
    again = alerts_db.set_maintenance_many(FLEET, by="someone-else",
                                           reason="different reason")
    row = alerts_db.open_maintenance(FLEET[0])
    check("a second press changes nothing and reports nothing changed —"
          " the same idempotence set_maintenance has",
          again == 0 and row["started_ts"] == started
          and row["started_by"] == DEFAULT_USER, (again, dict(row)))

    mixed = alerts_db.set_maintenance_many([FLEET[0], 9999], by=DEFAULT_USER)
    check("a mixed selection counts only the devices it actually opened",
          mixed == 1, mixed)
    alerts_db.clear_maintenance_many([9999], by=DEFAULT_USER)

    # A first notice that maintenance mode swallowed must be handed back by
    # the batch clear, exactly as clear_maintenance hands it back.
    held_rule = alerts_db.rule_by_key("device_down")
    held_row, _opened = alerts_db.open_or_increment(
        held_rule["id"], "maint-held:9000", "device", str(FLEET[0]),
        "sw-9000", 2, "stopped answering", "", time.time())
    with alerts_db._lock:
        alerts_db._conn.execute(
            "UPDATE alerts SET last_notified_ts = ?, maint_held_notify_ts = ?"
            " WHERE id = ?", (time.time(), time.time(), held_row["id"]))
        alerts_db._conn.commit()

    alerts_db._conn = CountingConn(real_conn)
    try:
        cleared = alerts_db.clear_maintenance_many(FLEET, by=DEFAULT_USER)
        commits = alerts_db._conn.commits
    finally:
        alerts_db._conn = real_conn
    check(f"clear_maintenance_many takes all {len(FLEET)} back out in one"
          f" commit",
          cleared == len(FLEET) and commits == 1, (cleared, commits))
    check("...and none of them is in maintenance any more",
          alerts_db.open_maintenance(FLEET[0]) is None
          and alerts_db.open_maintenance(FLEET[-1]) is None)
    with alerts_db._lock:
        closed = alerts_db._conn.execute(
            "SELECT COUNT(*) FROM device_maintenance WHERE device_id = ?"
            " AND ended_ts IS NOT NULL", (FLEET[0],)).fetchone()[0]
    check("...the closed period is kept rather than deleted — it is the"
          " availability report's evidence those seconds were planned",
          closed == 1, closed)
    check("...and the held first notice is due again",
          alerts_db.alert(held_row["id"])["last_notified_ts"] is None,
          alerts_db.alert(held_row["id"])["last_notified_ts"])

    check("clearing devices that are not in maintenance reports nothing"
          " changed, as clear_maintenance's False does",
          alerts_db.clear_maintenance_many(FLEET, by=DEFAULT_USER) == 0)
    check("an empty selection is a no-op on both",
          alerts_db.set_maintenance_many([]) == 0
          and alerts_db.clear_maintenance_many([]) == 0)
    check("a duplicated id is one device, not two rows",
          alerts_db.set_maintenance_many([9001, 9001, 9001]) == 1)
    alerts_db.clear_maintenance_many([9001])
finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
