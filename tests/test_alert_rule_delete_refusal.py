"""4.49.0: DELETE /api/alerts/rules/<id> refuses to delete a CUSTOM rule
that has raised real alert history, naming the count and offering the
alternative in the same sentence — rules.id is alerts.rule_id's own
ON DELETE CASCADE parent, so deleting a rule with history used to
silently destroy every alert it ever raised, resolved history included,
behind a confirmation dialog that only ever asked "Remove <name>?".

alertsdb.alert_count_for_rule/remove_rule (the storage-layer half of this
fix) are covered by test_alertsdb_rollup_and_rules.py; this suite is the
API layer: the actual HTTP refusal message, that nothing gets deleted
when it fires, and that a rule with no history still deletes normally.
"""
import http.client
import json
import os
import time

import _paths  # noqa: F401

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("rule_delete_refusal_")
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
    alerts_db = service.alerts_db

    status, payload = call("POST", "/api/alerts/rules",
                           {"key": "rule_with_history", "name": "Rule With History",
                            "kind": "threshold", "source_kind": "cpu_pct",
                            "severity": 3, "threshold": 90.0}, token=admin)
    check("200", status == 200, (status, payload))
    rule_id = payload["id"]

    # Two alerts, one still open, one resolved -- alert_count_for_rule
    # counts every state, so the refusal must too. Inserted directly, the
    # same shortcut test_alertsdb_rollup_and_rules.py's own open_alert()
    # takes, since building these through a live poll/threshold breach is
    # not what this suite is testing.
    now = time.time()
    with alerts_db._lock:
        alerts_db._conn.execute(
            "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
            " entity_label, severity, message, state, count, opened_ts,"
            " last_ts, extra_json) VALUES (?,?,'device','10.60.0.1','dev1',"
            "3,'m','open',1,?,?,'{}')", (rule_id, "open:device:10.60.0.1", now, now))
        alerts_db._conn.execute(
            "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
            " entity_label, severity, message, state, count, opened_ts,"
            " last_ts, extra_json) VALUES (?,?,'device','10.60.0.2','dev2',"
            "3,'m','open',1,?,?,'{}')", (rule_id, "resolved:device:10.60.0.2", now, now))
        alerts_db._conn.commit()
    alerts_db.resolve_by_dedup("resolved:device:10.60.0.2")

    status, payload = call("DELETE", f"/api/alerts/rules/{rule_id}", token=admin)
    check("400: refused rather than silently cascading",
          status == 400, (status, payload))
    error_text = str(payload.get("error", ""))
    check("...naming the actual count",
          "2 alert" in error_text, error_text)
    check("...offering disable in the same sentence",
          "disable" in error_text.lower(), error_text)

    status, payload = call("GET", "/api/alerts/rules", token=admin)
    check("the rule still exists — nothing was deleted",
          any(r["id"] == rule_id for r in payload["rules"]), payload)

    # Disabling instead of deleting must still work and must not itself
    # be refused -- the alternative the message offers has to actually work.
    status, payload = call("PUT", f"/api/alerts/rules/{rule_id}",
                           {"enabled": False}, token=admin)
    check("disabling the rule (the offered alternative) succeeds",
          status == 200, (status, payload))

    # A rule with no history at all still deletes normally -- the refusal
    # must not have become a blanket "custom rules can never be deleted".
    status, payload = call("POST", "/api/alerts/rules",
                           {"key": "rule_without_history", "name": "Rule Without History",
                            "kind": "threshold", "source_kind": "mem_pct",
                            "severity": 3, "threshold": 90.0}, token=admin)
    clean_rule_id = payload["id"]
    status, payload = call("DELETE", f"/api/alerts/rules/{clean_rule_id}", token=admin)
    check("a rule with no alert history deletes normally (200)",
          status == 200, (status, payload))
    status, payload = call("GET", "/api/alerts/rules", token=admin)
    check("...and is actually gone",
          not any(r["id"] == clean_rule_id for r in payload["rules"]), payload)

    # A built-in rule's own refusal is unchanged by this — still refused
    # for being built-in, not for having history.
    builtin = next((r for r in payload["rules"] if r["is_builtin"]), None)
    if builtin is not None:
        status, payload = call("DELETE", f"/api/alerts/rules/{builtin['id']}", token=admin)
        check("a built-in rule is still refused with its own message",
              status == 400 and "built-in" in str(payload.get("error", "")).lower(),
              (status, payload))

    print()
    print("FAILURES:", FAILS if FAILS else "none")
finally:
    server.stop()

raise SystemExit(1 if FAILS else 0)
