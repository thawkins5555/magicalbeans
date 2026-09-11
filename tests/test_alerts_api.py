"""The alert rows the web API hands the page, and the device mute that hangs
off them. Everything goes through a real `Service` and `WebServer` over
loopback HTTP with real sessions and permission checks, because the
questions are about the wire format and who may do what. The device id on an
alert row resolves a device alert to its own device, an interface alert to
its parent, and anything outside Nodes to nothing (Mute disables itself).
"""
import http.client
import json
import os
import shutil
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.alertrules import Occurrence, dedup_key
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
    # 4.39 refuses every API route for an account whose password must still be
    # changed (the forced first-run change is enforced by the server, not just
    # by the bundled UI), so clear the flag rather than re-password every
    # account this suite creates.
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
    """One alert straight into the store, the way the engine's _apply would
    write it. No engine here on purpose: what is under test is the shape of
    the row the API returns, not what made it — but the dedup key is built by
    the engine's own alertrules.dedup_key, so a row written here is a row the
    engine would recognise (it is "<key>:<entity_kind>:<entity_id>", not
    "<key>:<entity_id>")."""
    rule = service.alerts_db.rule_by_key(rule_key)
    assert rule is not None, rule_key
    occurrence = Occurrence(kind=rule["kind"], source_kind=rule["source_kind"] or "",
                            entity_kind=entity_kind, entity_id=str(entity_id),
                            entity_label=label, ts=time.time(), message=message)
    row, _created = service.alerts_db.open_or_increment(
        rule["id"], dedup_key(rule, occurrence), entity_kind, str(entity_id),
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
    check("...and neither carries a device_name the page never reads",
          "device_name" not in rows[device_alert]
          and "device_name" not in rows[iface_alert],
          sorted(rows[device_alert]))
    check("an alert about nothing in Nodes resolves to no device",
          rows[syslog_alert]["device_id"] is None,
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

    # ---------------------------- 4b. a per-port threshold alert on the wire

    port_alert = raise_alert(
        "if_in_util_high", "interface", f"{switch}:7",
        "Access Switch / GigabitEthernet0/7 (uplink)",
        "Access Switch / GigabitEthernet0/7 (uplink): Interface inbound "
        "utilization high (97.0 %)")
    rows = alerts_by_id(admin)
    check("a per-port threshold alert names the port in its label and "
          "resolves to the switch",
          rows[port_alert]["entity_kind"] == "interface"
          and rows[port_alert]["device_id"] == switch
          and "GigabitEthernet0/7 (uplink)" in rows[port_alert]["entity_label"],
          rows.get(port_alert))

    # ------------------------------------------- 4c. the comparison direction

    status, payload = call("GET", "/api/alerts/rules", token=admin)
    by_key = {r["key"]: r for r in payload.get("rules", [])} if status == 200 else {}
    check("every rule reports a comparison, defaulting to 'above'",
          by_key.get("cpu_high", {}).get("comparison") == "above",
          by_key.get("cpu_high"))
    check("...and the shipped optic power rules report 'below'",
          by_key.get("sfp_rx_power_low", {}).get("comparison") == "below",
          by_key.get("sfp_rx_power_low"))

    cpu_id = by_key["cpu_high"]["id"]
    status, payload = call("PUT", f"/api/alerts/rules/{cpu_id}",
                           {"comparison": "below", "threshold": 10.0,
                            "clear_threshold": 20.0}, token=admin)
    check("a rule can be flipped to 'below' with its numbers the right way "
          "round", status == 200, (status, payload))
    status, payload = call("GET", "/api/alerts/rules", token=admin)
    flipped = {r["key"]: r for r in payload.get("rules", [])}["cpu_high"]
    check("...and it round-trips",
          (flipped["comparison"], flipped["threshold"],
           flipped["clear_threshold"]) == ("below", 10.0, 20.0), flipped)

    status, payload = call("PUT", f"/api/alerts/rules/{cpu_id}",
                           {"comparison": "below", "threshold": 20.0,
                            "clear_threshold": 10.0}, token=admin)
    check("a clear on the wrong side of a 'below' threshold is a 400",
          status == 400, (status, payload))

    status, payload = call("PUT", f"/api/alerts/rules/{cpu_id}",
                           {"comparison": "sideways"}, token=admin)
    check("an unrecognised comparison is a 400", status == 400, (status, payload))

    call("PUT", f"/api/alerts/rules/{cpu_id}",
         {"comparison": "above", "threshold": 90.0, "clear_threshold": 80.0},
         token=admin)

    # ------------------------------- 5. a device that is gone is not muteable

    ghost = service.nodes_db.add_device("192.0.2.21", name="Removed Switch",
                                        group_id=group_id)
    ghost_alert = raise_alert("device_down", "device", ghost,
                              "Removed Switch (192.0.2.21)", "gone")
    service.nodes_db.remove_device(ghost)
    rows = alerts_by_id(admin)
    check("an alert whose device has been removed resolves to no device",
          rows[ghost_alert]["device_id"] is None, rows.get(ghost_alert))

    # ------------------------------- 6. indefinite maintenance mode

    audit_mark = service.app_db.audit_last_id()

    def audit_since_mark():
        return [dict(r) for r in service.app_db.audit_events(audit_mark, 500)]

    group = service.nodes_db.add_device_group("Cutover")
    spare = service.nodes_db.add_device("192.0.2.30", name="Spare Switch",
                                        group_id=group_id,
                                        device_group_id=group)
    service.nodes_db.update_device(switch, device_group_id=group)

    status, payload = call("POST", "/api/alerts/maintenance",
                           {"device_id": switch, "reason": "rack rewire"},
                           token=viewer)
    check("a read-only account cannot put a device into maintenance",
          status == 403, (status, payload))

    status, payload = call("POST", "/api/alerts/maintenance",
                           {"device_id": switch, "reason": "rack rewire"},
                           token=admin)
    check("an administrator can, and gets the period back",
          status == 200 and payload["maintenance"]["device_id"] == switch
          and payload["maintenance"]["ended_ts"] is None
          and payload["maintenance"]["reason"] == "rack rewire",
          (status, payload))
    started_ts = payload["maintenance"]["started_ts"] if status == 200 else 0

    status, payload = call("POST", "/api/alerts/maintenance",
                           {"device_id": switch, "reason": "something else"},
                           token=admin)
    check("a second POST is idempotent: the SAME period, untouched",
          status == 200 and payload["already"] is True
          and payload["maintenance"]["started_ts"] == started_ts
          and payload["maintenance"]["reason"] == "rack rewire",
          (status, payload))

    status, payload = call("POST", "/api/alerts/maintenance",
                           {"device_id": switch, "hours": 4}, token=admin)
    check("a body carrying `hours` is REFUSED, not silently obeyed with the "
          "hours dropped — that is how an operator believes in a 4-hour "
          "maintenance that does not exist",
          status == 400 and "mute" in str(payload).lower(), (status, payload))
    status, payload = call("POST", "/api/alerts/maintenance",
                           {"device_id": switch, "until_ts": time.time() + 60},
                           token=admin)
    check("...and `until_ts` likewise, naming maintenance windows instead",
          status == 400 and "window" in str(payload).lower(), (status, payload))

    status, payload = call("POST", "/api/alerts/maintenance",
                           {"device_id": 999999}, token=admin)
    check("a device Nodes does not have is refused, the same 'No such device' "
          "a mute answers with", status == 400 and "device" in str(payload),
          (status, payload))

    # The devices endpoint carries it, and leaves muted_until alone.
    status, listed = call("GET", "/api/nodes/devices", token=admin)
    devices = {d["id"]: d for d in listed.get("devices", [])} if status == 200 else {}
    check("the Nodes row carries a `maintenance` object",
          (devices.get(switch) or {}).get("maintenance", {}).get("device_id") == switch,
          (devices.get(switch) or {}).get("maintenance"))
    check("...and muted_until stays NULL for a maintenance-only device — "
          "anything rendering it would print a date that never arrives",
          (devices.get(switch) or {}).get("muted_until") is None,
          (devices.get(switch) or {}).get("muted_until"))
    check("...while a device in neither carries maintenance: null",
          (devices.get(spare) or {}).get("maintenance") is None,
          (devices.get(spare) or {}).get("maintenance"))

    status, payload = call("GET", "/api/alerts/maintenance", token=viewer)
    check("a read-only account may SEE what is in maintenance",
          status == 200 and any(m["device_id"] == switch
                                for m in payload.get("maintenance", [])),
          (status, payload))

    # maintenance_only, filtered server-side and paged.
    call("POST", "/api/alerts/maintenance", {"device_id": spare}, token=admin)
    totals, seen = set(), []
    for offset in (0, 1):
        status, payload = call(
            "GET", f"/api/nodes/devices?maintenance_only=1&limit=1&offset={offset}",
            token=admin)
        if status == 200:
            totals.add(payload["total"])
            seen += [d["id"] for d in payload["devices"]]
    check("maintenance_only=1 returns exactly the devices in maintenance, "
          "one per page, with a total that agrees across both pages",
          totals == {2} and sorted(seen) == sorted([switch, spare]),
          (totals, seen))

    status, payload = call("DELETE", "/api/alerts/maintenance",
                           {"device_id": spare}, token=viewer)
    check("a read-only account cannot end a maintenance either", status == 403,
          (status, payload))
    status, payload = call("DELETE", "/api/alerts/maintenance",
                           {"device_id": spare}, token=admin)
    check("DELETE reports the period it ended", status == 200
          and payload["cleared"] is True, (status, payload))
    status, payload = call("DELETE", "/api/alerts/maintenance",
                           {"device_id": spare}, token=admin)
    check("...and reports false the second time, having nothing to end",
          status == 200 and payload["cleared"] is False, (status, payload))

    status, payload = call("GET", "/api/nodes/devices?maintenance_only=1",
                           token=admin)
    check("the filter follows it out again",
          status == 200 and [d["id"] for d in payload["devices"]] == [switch],
          (status, payload))

    # Bulk, by group, both directions.
    status, payload = call("POST", "/api/alerts/bulk-maintenance",
                           {"group_id": group, "reason": "site cutover"},
                           token=admin)
    check("bulk maintenance by group_id covers the group's whole membership",
          status == 200 and payload["devices"] == 2, (status, payload))
    check("...and only the device not already in it counts as changed",
          status == 200 and payload["changed"] == 1, (status, payload))
    check("...so both devices are now in maintenance",
          service.alerts_db.open_maintenance(switch) is not None
          and service.alerts_db.open_maintenance(spare) is not None)

    status, payload = call("POST", "/api/alerts/bulk-maintenance",
                           {"group_id": group, "clear": True}, token=admin)
    check("`clear` takes the same group back out again",
          status == 200 and payload["cleared"] is True
          and payload["changed"] == 2, (status, payload))
    check("...and nothing in the group is in maintenance any more",
          service.alerts_db.open_maintenance(switch) is None
          and service.alerts_db.open_maintenance(spare) is None)

    status, payload = call("POST", "/api/alerts/bulk-maintenance",
                           {"group_id": group, "hours": 2}, token=admin)
    check("a bulk body carrying `hours` is refused too", status == 400,
          (status, payload))

    # Deleting a device must take its maintenance with it: devices.id is
    # reissued, so a leftover period would silence whoever inherits it.
    call("POST", "/api/alerts/maintenance", {"device_id": spare}, token=admin)
    call("DELETE", f"/api/nodes/devices/{spare}", token=admin)
    check("deleting a device leaves no maintenance period behind for the "
          "next device to inherit its rowid",
          service.alerts_db.open_maintenance(spare) is None)

    # ------------------------------- bulk maintenance is one batch, not a loop
    #
    # The scope resolution is the same as above; what is pinned here is that
    # the store is touched once for the whole selection rather than twice per
    # device (an open_maintenance read and a set_maintenance write, each its
    # own alerts.db lock and commit) on the request thread.
    bulk_ids = [service.nodes_db.add_device(f"198.51.100.{n}", name=f"bulk{n}",
                                            group_id=group_id)
                for n in range(1, 21)]
    singles = {"set": 0, "clear": 0, "open": 0}
    real_set = service.alerts_db.set_maintenance
    real_clear = service.alerts_db.clear_maintenance
    real_open = service.alerts_db.open_maintenance

    def counted_set(*a, **kw):
        singles["set"] += 1
        return real_set(*a, **kw)

    def counted_clear(*a, **kw):
        singles["clear"] += 1
        return real_clear(*a, **kw)

    def counted_open(*a, **kw):
        singles["open"] += 1
        return real_open(*a, **kw)

    service.alerts_db.set_maintenance = counted_set
    service.alerts_db.clear_maintenance = counted_clear
    service.alerts_db.open_maintenance = counted_open
    try:
        status, payload = call("POST", "/api/alerts/bulk-maintenance",
                               {"device_ids": bulk_ids, "reason": "cutover"},
                               token=admin)
        check("bulk maintenance puts the whole selection in at once",
              status == 200 and payload["changed"] == len(bulk_ids),
              (status, payload))
        check("...without one set_maintenance/open_maintenance pair per device",
              singles["set"] == 0 and singles["open"] == 0, singles)
        status, payload = call("POST", "/api/alerts/bulk-maintenance",
                               {"device_ids": bulk_ids, "reason": "cutover"},
                               token=admin)
        check("...and a device already in maintenance still does not count "
              "as changed", status == 200 and payload["changed"] == 0,
              (status, payload))
        status, payload = call("POST", "/api/alerts/bulk-maintenance",
                               {"device_ids": bulk_ids, "clear": True},
                               token=admin)
        check("clearing the selection is one batch too",
              status == 200 and payload["changed"] == len(bulk_ids)
              and singles["clear"] == 0, (status, payload, singles))
        check("...and every device is really out of maintenance",
              all(service.alerts_db.open_maintenance(i) is None
                  for i in bulk_ids))
    finally:
        service.alerts_db.set_maintenance = real_set
        service.alerts_db.clear_maintenance = real_clear
        service.alerts_db.open_maintenance = real_open

    status, payload = call("POST", "/api/alerts/bulk-maintenance",
                           {"device_ids": list(range(1, 50002))}, token=admin)
    check("an oversized bulk maintenance scope is a 400 naming the limit, "
          "not a fleet-sized loop", status == 400
          and "limit is" in str(payload.get("error", "")), (status, payload))

    # --------------------------------------------- a rule key is an identifier
    for bad, why in [('x" autofocus onfocus="alert(1)', "quotes and spaces"),
                     ("rule key", "a space"),
                     ("rule/key", "a slash"),
                     ("ruéle", "a non-ASCII letter"),
                     ("k" * 200, "length")]:
        status, payload = call("POST", "/api/alerts/rules",
                               {"key": bad, "name": "Bad key", "kind": "system"},
                               token=admin)
        check(f"a rule key with {why} is refused", status == 400,
              (bad[:40], status, payload))
        check("...and nothing was stored for it",
              service.alerts_db.rule_by_key(bad) is None)

    status, payload = call("POST", "/api/alerts/rules",
                           {"key": "site-a.custom_rule2", "name": "Fine key",
                            "kind": "system"}, token=admin)
    check("an ordinary key — letters, digits, dot, hyphen, underscore — is "
          "still accepted", status == 200, (status, payload))

    # ------------------------------- the webhook URL is a bearer credential
    service.apply_settings("alerts", {
        "webhook_url": "https://hooks.example.com/services/T000/B000/XXXsecret",
        "webhook_headers": ["Authorization: Bearer sekrit"]})
    status, payload = call("GET", "/api/config", token=viewer)
    settings = payload.get("alerts_settings", {}) if status == 200 else {}
    check("a read-only Alerts account is not handed the webhook URL",
          status == 200 and settings.get("webhook_url") == ""
          and "XXXsecret" not in json.dumps(payload), (status, settings))
    check("...nor the webhook headers", settings.get("webhook_headers") == []
          and "sekrit" not in json.dumps(payload), settings)
    check("...but is told both are set",
          settings.get("has_webhook_url") is True
          and settings.get("has_webhook_headers") is True, settings)
    status, payload = call("GET", "/api/config", token=admin)
    settings = payload.get("alerts_settings", {}) if status == 200 else {}
    check("an account that could change them still sees them",
          settings.get("webhook_url", "").endswith("XXXsecret")
          and settings.get("webhook_headers") == ["Authorization: Bearer sekrit"],
          settings)

    actions = [row["action"] for row in audit_since_mark()]
    check("the audit trail records maintenance being turned on",
          "alert.maintenance_on" in actions, actions)
    check("...off", "alert.maintenance_off" in actions, actions)
    check("...and in bulk", "alert.maintenance_bulk" in actions, actions)
    check("and NOT under any of the mute action names — a maintenance is not "
          "a mute, and an audit reader must be able to tell them apart",
          not any(a.startswith("alert.mute") or a == "alert.unmute"
                  for a in actions), actions)
finally:
    server.stop()
    service.shutdown()
    # In the finally, not after it: a crash anywhere above used to leave a
    # whole temp tree of databases behind on every run.
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
