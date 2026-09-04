"""API tokens (Tier 1 #10): service-account credentials that authenticate a
request the same way a session cookie does, but never expire from idleness.

Driven the way test_web_gates.py and test_security_fixes.py drive their own
checks: a real Service + WebServer on a free loopback port, everything
through plain HTTP requests — the layer between the socket and the handler
(server.py's Bearer handling) is exactly what this is testing, so calling a
handler function directly would miss the point.

Covers: issue -> authenticate a real request with it -> revoke -> refused;
an expired token refused; the gate matrix (read allowed, write refused) for
a read-only account's token, matching what its session would get; the raw
token never appearing in any response body or the audit log; hash-only
storage in app.db; last_used_ts updating (and being rate-limited); no idle
timeout where a session would have one; and that a Bearer header does
nothing useful on the login and kiosk-heartbeat paths.
"""
import hashlib
import http.client
import json
import os
import sys
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("api_tokens_")

from netpath.web import Service, WebServer
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER, hash_api_token

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

ADMIN_PASSWORD = "TokenSuiteAdmin2026"
failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


def call(method, path, body=None, token=None, bearer=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    headers_out = dict(resp.getheaders())
    conn.close()
    return resp.status, payload, headers_out, raw


def login(username, password):
    status, payload, headers, _raw = call(
        "POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return headers.get("Set-Cookie", "").split("sw_session=")[1].split(";")[0]


try:
    # --------------------------------------------------------------- set up
    admin_token = login(DEFAULT_USER, DEFAULT_PASSWORD)
    status, payload, _h, _r = call(
        "POST", "/api/password",
        {"current_password": DEFAULT_PASSWORD, "new_password": ADMIN_PASSWORD},
        token=admin_token)
    check("admin password change", status == 200, f"{status} {payload}")
    admin_token = login(DEFAULT_USER, ADMIN_PASSWORD)

    def make_user(username, grants, password="Corr3ct-Horse-Battery"):
        status, payload, _h, _r = call(
            "POST", "/api/users",
            {"username": username, "password": password, "grants": grants},
            token=admin_token)
        assert status == 200, (username, status, payload)
        row = service.app_db.user(username)
        service.app_db.set_password(username, row["password"], must_change=False)
        return password

    reader_password = make_user("token-reader", {"nodes": "read"})
    writer_password = make_user("token-writer", {"nodes": "write"})

    # ----------------------------------------------- issue -> use -> revoke
    print("issue, authenticate, revoke")
    status, payload, _h, raw = call(
        "POST", "/api/tokens",
        {"username": "token-reader", "label": "monitoring script"},
        token=admin_token)
    check("a token is issued for an existing account", status == 200, f"{status} {payload}")
    reader_token = payload.get("token", "")
    token_id = payload.get("id")
    check("the plaintext token is returned exactly once, in this response",
          isinstance(reader_token, str) and reader_token.startswith("sw_api_"),
          reader_token[:12])

    status, payload, _h, _r = call(
        "GET", "/api/nodes/devices", bearer=reader_token)
    check("Bearer authenticates a real API request", status == 200, f"{status} {payload}")

    status, payload, _h, _r = call(
        "POST", "/api/nodes/devices", {"ip": "10.44.0.1"}, bearer=reader_token)
    check("a read-only account's token is refused a write, exactly like its "
          "session would be", status == 403, f"{status} {payload}")

    status, payload, _h, raw = call(
        "POST", "/api/tokens",
        {"username": "token-writer", "label": "poller"}, token=admin_token)
    writer_token = payload.get("token", "")
    status, payload, _h, _r = call(
        "POST", "/api/nodes/devices", {"ip": "10.44.0.2"}, bearer=writer_token)
    check("a write-granted account's token can write",
          status == 200, f"{status} {payload}")

    status, payload, _h, _r = call("DELETE", "/api/tokens", {"id": token_id},
                                   token=admin_token)
    check("revocation succeeds", status == 200 and payload.get("revoked") == token_id,
          f"{status} {payload}")
    status, payload, _h, _r = call("GET", "/api/nodes/devices", bearer=reader_token)
    check("a revoked token is refused immediately", status == 401, f"{status} {payload}")

    status, payload, _h, _r = call("DELETE", "/api/tokens", {"id": token_id},
                                   token=admin_token)
    check("revoking an already-revoked id is a clean error, not a 200",
          status == 400, f"{status} {payload}")

    # ------------------------------------------------------------- expiry
    print("expiry")
    status, payload, _h, _r = call(
        "POST", "/api/tokens",
        {"username": "token-reader", "label": "short-lived", "expires_days": 30},
        token=admin_token)
    check("a token can be issued with an expiry", status == 200, f"{status} {payload}")
    expiring_token = payload["token"]
    expiring_id = payload["id"]
    status, payload, _h, _r = call("GET", "/api/nodes/devices", bearer=expiring_token)
    check("not yet expired, it authenticates", status == 200, f"{status} {payload}")

    # Back-date it directly — the route only accepts a positive day count,
    # so the only way to exercise "already expired" without waiting 30 days
    # is to move the stored expiry into the past the same way a very old
    # token would eventually get there on its own.
    with service.app_db._lock:
        service.app_db._conn.execute(
            "UPDATE api_tokens SET expires_ts = ? WHERE id = ?",
            (time.time() - 60, expiring_id))
        service.app_db._conn.commit()
    status, payload, _h, _r = call("GET", "/api/nodes/devices", bearer=expiring_token)
    check("an expired token is refused", status == 401, f"{status} {payload}")

    status, payload, _h, _r = call("GET", "/api/audit?limit=5000", token=admin_token)
    actions = [e["action"] for e in payload.get("events", [])]
    check("the expired-use attempt is audited",
          "token.expired_use" in actions, str(sorted(set(actions))))
    check("token.issue and token.revoke are audited too",
          "token.issue" in actions and "token.revoke" in actions,
          str(sorted(set(actions))))

    # ---------------------------------------------------- no secret leaks
    print("the token itself never reappears anywhere")
    status, payload, _h, raw = call("GET", "/api/tokens", token=admin_token)
    check("the list route never carries a 'token' field",
          status == 200 and all("token" not in row for row in payload.get("tokens", [])),
          str(payload.get("tokens"))[:200])
    body_text = raw.decode("utf-8", "replace")
    check("the raw token string is not in the list response body",
          reader_token not in body_text and writer_token not in body_text
          and expiring_token not in body_text)

    status, payload, _h, raw = call("GET", "/api/audit?limit=5000", token=admin_token)
    audit_text = raw.decode("utf-8", "replace")
    check("the raw token string is not in the audit log",
          reader_token not in audit_text and writer_token not in audit_text
          and expiring_token not in audit_text)

    print("hash-only storage")
    row = service.app_db.api_token_by_hash(hash_api_token(writer_token))
    check("the token is found by the hash of what was issued",
          row is not None and row["username"] == "token-writer", row)
    with service.app_db._lock:
        stored = [r[0] for r in service.app_db._conn.execute(
            "SELECT token_hash FROM api_tokens").fetchall()]
    check("no stored value equals or contains the plaintext token",
          all(writer_token not in value for value in stored), stored)
    check("the stored value is exactly the sha256 hex of the token",
          hash_api_token(writer_token) in stored, hash_api_token(writer_token))

    # ----------------------------------------------------------- last_used
    print("last_used_ts")
    status, payload, _h, _r = call(
        "POST", "/api/tokens", {"username": "token-reader", "label": "last-used probe"},
        token=admin_token)
    fresh_token = payload["token"]
    fresh_token_id = payload["id"]
    row = service.app_db.api_token(fresh_token_id)
    check("a freshly issued token has never been used", row["last_used_ts"] is None, dict(row))

    call("GET", "/api/nodes/devices", bearer=fresh_token)
    row = service.app_db.api_token(fresh_token_id)
    first_seen = row["last_used_ts"]
    check("using it sets last_used_ts", first_seen is not None, dict(row))

    call("GET", "/api/nodes/devices", bearer=fresh_token)
    row = service.app_db.api_token(fresh_token_id)
    check("a second use inside the same minute does not move last_used_ts "
          "again (throttled to avoid a write per request)",
          row["last_used_ts"] == first_seen, (first_seen, row["last_used_ts"]))

    with service.app_db._lock:
        service.app_db._conn.execute(
            "UPDATE api_tokens SET last_used_ts = ? WHERE id = ?",
            (time.time() - 120, fresh_token_id))
        service.app_db._conn.commit()
    call("GET", "/api/nodes/devices", bearer=fresh_token)
    row = service.app_db.api_token(fresh_token_id)
    check("…but does move it once the throttle window has passed",
          row["last_used_ts"] > time.time() - 5, dict(row))

    # -------------------------------------------------------- no idle timeout
    print("no idle timeout for a token, where a session would have one")
    real_idle = service.sessions.idle_seconds
    try:
        service.sessions.idle_seconds = 1
        session_token = login("token-reader", reader_password)
        time.sleep(1.6)
        status, payload, _h, _r = call("GET", "/api/nodes/devices", token=session_token)
        check("a cookie session times out at the (shortened) idle limit",
              status == 401, f"{status} {payload}")
        status, payload, _h, _r = call("GET", "/api/nodes/devices", bearer=fresh_token)
        check("…but a Bearer token over the same window is unaffected",
              status == 200, f"{status} {payload}")
    finally:
        service.sessions.idle_seconds = real_idle

    # ----------------------------------------- must_change applies to tokens
    print("must_change gate applies the same way")
    status, payload, _h, _r = call(
        "POST", "/api/users",
        {"username": "fresh-account", "password": "Corr3ct-Horse-Battery",
         "grants": {"nodes": "read"}}, token=admin_token)
    check("a freshly created local account owes a password change",
          status == 200, f"{status} {payload}")
    status, payload, _h, _r = call(
        "POST", "/api/tokens",
        {"username": "fresh-account", "label": "issued before first login"},
        token=admin_token)
    fresh_account_token = payload["token"]
    status, payload, _h, _r = call("GET", "/api/nodes/devices", bearer=fresh_account_token)
    check("a token for an account that owes a password change is refused "
          "the same way a session would be", status == 403, f"{status} {payload}")

    # ------------------------------------------ Bearer does nothing on
    # ------------------------------------------ login/kiosk paths
    print("Bearer on the login and kiosk-heartbeat paths")
    status, payload, headers, _r = call(
        "POST", "/api/login", {"username": DEFAULT_USER, "password": "wrong"},
        bearer=writer_token)
    check("a Bearer header does not bypass or change /api/login",
          status == 401, f"{status} {payload}")

    status, payload, headers, _r = call("POST", "/api/heartbeat", {}, bearer=writer_token)
    check("a Bearer-only heartbeat is answered (authenticates the request) "
          "but sets no session cookie", status == 200 and "Set-Cookie" not in headers,
          f"{status} {headers}")
    status, payload, _h, _r = call("GET", "/api/session", bearer=writer_token)
    check("…and /api/session, which only knows the cookie store, reports "
          "no browser session exists", payload.get("authenticated") is False,
          payload)

    # ---------------------------------------------------- unknown/garbage
    print("garbage bearer values")
    status, payload, _h, _r = call("GET", "/api/nodes/devices",
                                   bearer="not-a-real-token-at-all")
    check("an unrecognised bearer value is refused, not a 500",
          status == 401, f"{status} {payload}")

    print("FAILED: " + ", ".join(failures) if failures else "ALL API TOKEN ASSERTIONS PASSED")
finally:
    server.stop()
    deadline = time.time() + 20
    while time.time() < deadline and service.node_poller.worker_state():
        time.sleep(0.1)
    service.shutdown()

sys.exit(1 if failures else 0)
