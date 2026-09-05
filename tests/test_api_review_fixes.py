"""The API-layer defects a hostile full-codebase review of 4.50.0 found, each
one pinned by the request that used to produce the wrong answer.

Everything goes through a real `Service` and `WebServer` over loopback HTTP
with real sessions and real permission checks, the same way test_alerts_api.py
does — three of these findings are about who may do what, and calling the
handlers directly would answer that question dishonestly.

What is covered, and why each one mattered:

  1. A settings:write grant, deliberately weaker than admin, could rewrite the
     session lifetime for every account on the host and repoint the listener's
     TLS material. Those keys were classified as sensitive server internals
     but never added to ADMIN_ONLY_SETTINGS.
  2. A stored ConfigRX backup was served verbatim to a ConfigRX-read caller
     whenever the row's `redacted` flag was set — and that flag records "we
     ran the redactor", not "the redactor removed something".
  3. A threshold rule could be saved with a blank threshold or clear
     threshold, producing a rule that either never clears or breaches on
     every device at once.
  4. An oversized integer in a route or a query answered 500 rather than 400.
  5. An unbounded time window sized an allocation from t1 - t0.
  6. A CSV export wrote a cell beginning "=" as the spreadsheet's own formula.
  7. Deleting a device dropped its Nodes row before its ConfigRX credentials.
  8. ?limit=-1 on the discovery list read as SQLite's "no limit".
"""
import http.client
import json
import os
import shutil
import sqlite3
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import permissions
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_password
from netpath.web import Service, WebServer
from netpath.web.api import _csv_text, _flow_bucket, _window

TMPDIR = _paths.tmpdir("api_review_")

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


try:
    admin = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # ---------------------------------------------------------------------
    # 1. Settings write is not admin
    #
    # permissions.py carved "admin" out of "settings" precisely so a
    # settings grant would stop being all-powerful. Six keys never made the
    # ADMIN_ONLY_SETTINGS list: the two that decide how long a sign-in lasts
    # (which apply_global_settings hands straight to SessionStore.configure,
    # so the change lands immediately rather than at the next restart) and
    # the four that decide where the listener binds and which certificate it
    # presents.

    service.app_db.add_user("settingsonly", hash_password("SettingsOnlyPW2026"),
                            must_change=False)
    service.app_db.set_permissions("settingsonly", {"settings": permissions.WRITE})
    settings_only = login("settingsonly", "SettingsOnlyPW2026")

    for key, value in (("session_idle_minutes", 1440),
                       ("session_max_hours", 168),
                       ("web_host", "0.0.0.0"),
                       ("web_port", 9999),
                       ("web_cert", "/tmp/evil.pem"),
                       ("web_key", "/tmp/evil.key")):
        status, payload = call("POST", "/api/settings",
                               {"scope": "global", "values": {key: value}},
                               token=settings_only)
        check(f"settings:write alone cannot change {key}",
              status == 403, f"{status} {payload}")

    status, _ = call("POST", "/api/settings",
                     {"scope": "global", "values": {"session_idle_minutes": 45}},
                     token=admin)
    check("admin can still change session_idle_minutes", status == 200, status)

    # ---------------------------------------------------------------------
    # 2. A stored backup is redacted on the way out, whatever the flag says
    #
    # The row is written the way configrx._backup_device writes one when
    # store_secrets is off: redacted=True, meaning "the redactor ran". The
    # content here is a Juniper line no Cisco/FortiOS-anchored pattern ever
    # matched, so under the old read path the flag was believed and the key
    # went out in full to a caller holding only ConfigRX read.

    device_id = service.nodes_db.add_device("192.0.2.40", name="Edge Router")
    secret_line = 'set system radius-server 10.0.0.5 secret "R4diusKey"\n'
    backup_id, _digest = service.configrx_db.add_backup(
        device_id, secret_line, redacted=True)
    check("the backup fixture stored", backup_id is not None)

    service.app_db.add_user("cfgreader", hash_password("CfgReaderPW2026"),
                            must_change=False)
    service.app_db.set_permissions("cfgreader", {"configrx": permissions.READ,
                                                 "nodes": permissions.READ})
    reader = login("cfgreader", "CfgReaderPW2026")

    status, payload = call("GET", f"/api/configrx/backups/{backup_id}", token=reader)
    content = (payload or {}).get("content", "") if isinstance(payload, dict) else ""
    check("a ConfigRX reader never sees a stored secret, whatever the flag says",
          status == 200 and "R4diusKey" not in content,
          f"{status} {content!r}")

    # ---------------------------------------------------------------------
    # 3. A threshold rule that cannot raise, or cannot clear, is refused
    #
    # The Edit Rule dialog reached this route with Number(input.value), and
    # Number('') is 0 — so a cleared box produced clear_threshold 0 ("clear
    # when the value goes below zero", i.e. never) or threshold 0 ("breach on
    # every non-negative sample", i.e. the whole fleet at once). Blank now
    # arrives as null, and null is refused by name.

    cpu = service.alerts_db.rule_by_key("cpu_high")
    status, payload = call("PUT", f"/api/alerts/rules/{cpu['id']}",
                           {"threshold": None}, token=admin)
    check("a threshold rule cannot be saved with no threshold",
          status == 400 and "never raise" in str(payload), f"{status} {payload}")

    status, payload = call("PUT", f"/api/alerts/rules/{cpu['id']}",
                           {"threshold": float("nan")}, token=admin)
    check("a non-finite threshold is refused", status == 400, f"{status} {payload}")

    # Not required, on purpose. A rule with no clear threshold closes on
    # auto_resolve_after_s, on a paired CLEARS occurrence, or by hand — a
    # coherent choice this application has always accepted. What the blank
    # box used to send was 0, which on a metric that is never negative is a
    # clear test that can never be satisfied; the dialog now sends null,
    # which means the coherent thing.
    status, payload = call("PUT", f"/api/alerts/rules/{cpu['id']}",
                           {"threshold": 90.0, "clear_threshold": None},
                           token=admin)
    check("a threshold rule with no clear threshold is still allowed",
          status == 200, f"{status} {payload}")

    status, payload = call("PUT", f"/api/alerts/rules/{cpu['id']}",
                           {"threshold": 95.0, "clear_threshold": 85.0}, token=admin)
    check("a threshold rule with both values still saves", status == 200,
          f"{status} {payload}")

    # Zero is a legitimate threshold for a metric that can go negative — a
    # temperature sensor — so the check is "was it supplied", never "is it
    # nonzero". Refusing 0 outright would have been the wrong fix.
    status, payload = call("PUT", f"/api/alerts/rules/{cpu['id']}",
                           {"threshold": 0.0, "clear_threshold": 0.0}, token=admin)
    check("an explicit zero threshold is still allowed", status == 200,
          f"{status} {payload}")
    call("PUT", f"/api/alerts/rules/{cpu['id']}",
         {"threshold": 90.0, "clear_threshold": 80.0}, token=admin)

    status, payload = call("POST", "/api/alerts/rules",
                           {"key": "custom_no_threshold", "name": "Custom",
                            "kind": "threshold", "source_kind": "cpu_pct"},
                           token=admin)
    check("a new threshold rule with no threshold at all is refused",
          status == 400, f"{status} {payload}")

    status, payload = call("POST", "/api/alerts/rules",
                           {"key": "custom_with_threshold", "name": "Custom Two",
                            "kind": "threshold", "source_kind": "cpu_pct",
                            "severity": 3, "threshold": 90.0}, token=admin)
    check("a new threshold rule with only a threshold still saves",
          status == 200, f"{status} {payload}")

    # A non-threshold rule is unaffected — device_down ships with both
    # columns NULL and must stay saveable.
    down = service.alerts_db.rule_by_key("device_down")
    status, payload = call("PUT", f"/api/alerts/rules/{down['id']}",
                           {"severity": 1}, token=admin)
    check("a device_event rule is not subject to the threshold check",
          status == 200, f"{status} {payload}")

    # A rule stored with no threshold at all — which the create route used to
    # allow — must still be editable in every other respect. Requiring the
    # threshold on a PUT that never mentions it made the operator's likely
    # first move on a broken rule, disabling it, the one thing refused.
    legacy = service.alerts_db.add_rule(
        "legacy_no_threshold", "Legacy", "threshold", "cpu_pct", severity=3)
    status, payload = call("PUT", f"/api/alerts/rules/{legacy}",
                           {"enabled": False}, token=admin)
    check("a stored rule with no threshold can still be disabled",
          status == 200, f"{status} {payload}")
    row = service.alerts_db.rule(legacy)
    check("...and disabling it did not invent a threshold",
          row["threshold"] is None, row["threshold"])

    # ---------------------------------------------------------------------
    # 3b. Bulk device routes take a whole page of ids
    #
    # The Devices page offers a 1000-row page size with a select-all. An
    # earlier cap of 900 — set to stay under SQLite's oldest parameter limit
    # — turned that ordinary action into a 400. The parameter limit is now
    # handled by chunking the statement in nodesdb, where it belongs.

    bulk_ids = [service.nodes_db.add_device(f"10.9.{n // 256}.{n % 256}",
                                            name=f"bulk-{n}")
                for n in range(1000)]
    status, payload = call("POST", "/api/nodes/devices/bulk-delete",
                           {"device_ids": bulk_ids}, token=admin)
    check("a 1000-device bulk delete is accepted",
          status == 200, f"{status} {payload}")
    check("...and every one of them is gone",
          all(service.nodes_db.device(i) is None for i in bulk_ids))

    # ---------------------------------------------------------------------
    # 4. An oversized integer is a bad request, not a server fault
    #
    # Every `(\d+)` route arg becomes an int with a bare int(), which parses
    # thirty digits happily. sqlite3's parameter binding is what finds out,
    # and it raises OverflowError — not a ValueError, so the router used to
    # answer 500.

    huge = "9" * 30
    status, payload = call("GET", f"/api/nodes/devices/{huge}", token=admin)
    check("an oversized device id answers 4xx, not 500",
          400 <= status < 500, f"{status} {payload}")

    status, payload = call("GET", f"/api/netflow/records?port={huge}", token=admin)
    check("an oversized query filter answers 4xx, not 500",
          400 <= status < 500, f"{status} {payload}")

    # ---------------------------------------------------------------------
    # 5. A time window is bounded before anything is sized from it
    #
    # flowdb.overview allocates one float per bucket per series from
    # (t1 - t0) / bucket_s. _window used to hand it whatever the query string
    # said, and _num(..., float) parses "inf" and "1e18" without complaint.

    t0, t1 = _window({"t0": "0", "t1": "1e18"})
    check("a 1e18 window is clamped to a finite span",
          (t1 - t0) <= 10 * 366 * 24 * 3600.0 + 1, (t0, t1))
    t0, t1 = _window({"t0": "-inf", "t1": "inf"})
    check("a non-finite window is replaced, not propagated",
          t0 == t0 and t1 == t1 and (t1 - t0) < 1e12, (t0, t1))

    class _FlowSettings:
        flow_settings = {"bucket_seconds": 0}

    span = 10 * 366 * 24 * 3600.0
    bucket = _flow_bucket(_FlowSettings(), span)
    check("the bucket widens so a decade-wide chart stays bounded",
          span / bucket <= 5000 + 1, bucket)

    class _TinyBucket:
        flow_settings = {"bucket_seconds": 10}

    bucket = _flow_bucket(_TinyBucket(), span)
    check("a configured tiny bucket is widened for a wide span too",
          span / bucket <= 5000 + 1, bucket)

    # ---------------------------------------------------------------------
    # 6. A CSV cell is data, not a formula
    #
    # A syslog message is written by anything that can reach UDP/514 — no
    # account, no HTTP request. Excel and Sheets read a leading = + - or @ as
    # a formula, so an export opened by an analyst is the delivery vehicle.

    text = _csv_text(["message"], [['=cmd|\' /C calc\'!A0'], ["-2+3"],
                                   ["ordinary message"]])
    check("a formula-leading CSV cell is made inert",
          "'=cmd" in text and "'-2+3" in text, text)
    check("an ordinary CSV cell is untouched",
          "ordinary message" in text and "'ordinary" not in text, text)

    # ---------------------------------------------------------------------
    # 7. Deleting a device drops its ConfigRX credentials first
    #
    # devices.id is INTEGER PRIMARY KEY with no AUTOINCREMENT, so SQLite
    # reissues the highest freed rowid. If the Nodes row went first and the
    # ConfigRX call then failed, the next device added could land on the same
    # id and inherit the old device's stored SSH password.

    doomed = service.nodes_db.add_device("192.0.2.41", name="Doomed")
    service.configrx_db.update_device_config(doomed, backup_enabled=1,
                                             ssh_username="admin")
    status, _ = call("DELETE", f"/api/nodes/devices/{doomed}", token=admin)
    check("deleting a device answers ok", status == 200, status)
    check("its ConfigRX config is gone with it",
          service.configrx_db.device_config(doomed) is None,
          service.configrx_db.device_config(doomed))

    # The order is the whole fix, so the order is what this pins. Asserting
    # only that both rows are gone on the happy path would pass just as well
    # with the calls the wrong way round. Breaking the Nodes delete proves
    # which one already ran: with ConfigRX first, the credentials are gone
    # even though the request failed. With the old order they would still be
    # sitting there, keyed to an id SQLite is free to reissue.
    stubborn = service.nodes_db.add_device("192.0.2.42", name="Stubborn")
    service.configrx_db.update_device_config(stubborn, backup_enabled=1,
                                             ssh_username="admin")
    original_remove = service.nodes_db.remove_device

    def _fail_remove(device_id):
        raise sqlite3.OperationalError("database is locked")

    service.nodes_db.remove_device = _fail_remove
    try:
        status, _ = call("DELETE", f"/api/nodes/devices/{stubborn}", token=admin)
    finally:
        service.nodes_db.remove_device = original_remove
    check("a device delete that fails halfway has already dropped the "
          "ConfigRX credentials",
          service.configrx_db.device_config(stubborn) is None,
          service.configrx_db.device_config(stubborn))

    # ---------------------------------------------------------------------
    # 8. A negative limit is not "no limit"
    #
    # SQLite reads LIMIT -1 as unbounded. Every other paginated list route in
    # api.py clamps; this one did not.

    # Asserting only "200 and a dict" would have passed before the fix too —
    # the unclamped route answered 200 with every row in the table. The
    # count is the thing: with three jobs stored, limit=1 must return one,
    # and limit=-1 must not return more than limit=1 did.
    for ip in ("192.0.2.51", "192.0.2.52", "192.0.2.53"):
        service.nodes_db.add_discovery_job("single", ip)
    status, payload = call("GET", "/api/nodes/discovery?limit=1", token=admin)
    one = len(payload.get("jobs", [])) if isinstance(payload, dict) else -1
    check("a discovery limit of 1 returns one job", status == 200 and one == 1,
          f"{status} {one}")
    status, payload = call("GET", "/api/nodes/discovery?limit=-1", token=admin)
    negative = len(payload.get("jobs", [])) if isinstance(payload, dict) else -1
    check("a negative discovery limit is clamped, not read as 'no limit'",
          status == 200 and negative == 1, f"{status} {negative}")

finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
