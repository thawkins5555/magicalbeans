"""Per-account SSH login: GET/PUT/DELETE /api/account/ssh, the app.db
user_ssh store, the sign-in-only gate (no module permission, viewer
included), and remove_user cleanup. This is the credential the SSH button
reads (sshterm.py) — never ConfigRX's own device-scoped one.
"""
import http.client
import json
import os
import shutil
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

import netpath.dpapi as dpapi_mod
dpapi_mod.available = lambda: True
dpapi_mod.protect = lambda p: b"FAKE:" + p
dpapi_mod.unprotect = lambda c: bytes(c)[5:]

from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

TMPDIR = _paths.tmpdir("account_ssh_")
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

    # A plain account with no grants at all — the SSH-login routes need
    # nothing but a signed-in session, same as SMS's.
    status, payload = call("POST", "/api/users",
                           {"username": "grunt", "password": "Corr3ct-Horse-Battery",
                            "grants": {}}, token=admin)
    assert status == 200, (status, payload)
    grunt = login("grunt", "Corr3ct-Horse-Battery")

    # ---------------------------------------------------------- 1. anonymous
    status, payload = call("GET", "/api/account/ssh")
    check("an unauthenticated GET is 401", status == 401, (status, payload))

    # ------------------------------------------------------ 2. before setup
    status, payload = call("GET", "/api/account/ssh", token=grunt)
    check("GET is 200 with no row", status == 200, (status, payload))
    check("...username is empty", payload.get("username") == "", payload)
    check("...has_password is False", payload.get("has_password") is False, payload)
    check("...stored_ts is None", payload.get("stored_ts") is None, payload)
    check("...available reflects dpapi.available()", payload.get("available") is True, payload)

    # -------------------------------------------------- 3. PUT validation
    status, payload = call("PUT", "/api/account/ssh", {"ssh_username": "netop"}, token=grunt)
    check("PUT with no password is a 400", status == 400, (status, payload))
    status, payload = call("PUT", "/api/account/ssh", {"ssh_password": "hunter2"}, token=grunt)
    check("PUT with no username is a 400", status == 400, (status, payload))

    # ------------------------------------------------------------- 4. PUT
    status, payload = call("PUT", "/api/account/ssh",
                           {"ssh_username": "netop", "ssh_password": "hunter2"}, token=grunt)
    check("PUT with both fields is 200", status == 200, (status, payload))
    check("...username comes back", payload.get("username") == "netop", payload)
    check("...has_password is now True", payload.get("has_password") is True, payload)
    check("...stored_ts is set", bool(payload.get("stored_ts")), payload)
    check("...the password itself is never in the response",
         "ssh_password" not in payload and "password" not in payload, payload)

    row = service.app_db.user_ssh("grunt")
    check("appdb.user_ssh holds the encrypted pair", row is not None
         and row["ssh_username"] == "netop", dict(row) if row else row)
    check("...the password is encrypted, not plaintext",
         bytes(row["ssh_password_enc"]) != b"hunter2", bytes(row["ssh_password_enc"]))
    check("...and decrypts back to what was sent",
         dpapi_mod.unprotect(bytes(row["ssh_password_enc"])) == b"hunter2", row)

    # ------------------------------------------------------ 5. GET after PUT
    status, payload = call("GET", "/api/account/ssh", token=grunt)
    check("GET after PUT reflects the stored login", status == 200
         and payload.get("username") == "netop" and payload.get("has_password") is True,
         payload)

    # --------------------------------------------------------- 6. overwrite
    status, payload = call("PUT", "/api/account/ssh",
                           {"ssh_username": "netop2", "ssh_password": "newpass"}, token=grunt)
    check("a second PUT overwrites the first", status == 200
         and payload.get("username") == "netop2", payload)
    row = service.app_db.user_ssh("grunt")
    check("...appdb reflects the overwrite", row["ssh_username"] == "netop2", dict(row))

    # ----------------------------------------------------------- 7. isolation
    admin_row = service.app_db.user_ssh(DEFAULT_USER)
    check("a second account's SSH login is independent (none stored)",
         admin_row is None, admin_row)

    # ------------------------------------------------------------ 8. DELETE
    status, payload = call("DELETE", "/api/account/ssh", token=grunt)
    check("DELETE is 200", status == 200, (status, payload))
    check("...has_password is now False", payload.get("has_password") is False, payload)
    check("...username is cleared", payload.get("username") == "", payload)
    check("appdb.user_ssh is gone after DELETE",
         service.app_db.user_ssh("grunt") is None)

    status, payload = call("DELETE", "/api/account/ssh", token=grunt)
    check("a second DELETE (nothing stored) is still 200", status == 200, (status, payload))

    # -------------------------------------------------------- 9. remove_user
    status, payload = call("PUT", "/api/account/ssh",
                           {"ssh_username": "netop", "ssh_password": "hunter2"}, token=grunt)
    assert status == 200, (status, payload)
    assert service.app_db.user_ssh("grunt") is not None
    service.app_db.remove_user("grunt")
    check("remove_user removes the user_ssh row too",
         service.app_db.user_ssh("grunt") is None)

    # --------------------------------------------------------------- 10. audit
    events = [e for e in service.app_db.audit_events(0)
             if e["username"] == "grunt" and e["action"] in
             ("account.ssh.store", "account.ssh.clear")]
    check("both PUT and DELETE are audited",
         any(e["action"] == "account.ssh.store" for e in events)
         and any(e["action"] == "account.ssh.clear" for e in events),
         [dict(e) for e in events])
finally:
    server.stop()
    service.shutdown()
    shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
