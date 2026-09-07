"""Theme, saved per account: AppDatabase.set_user_theme/migration, the
PUT /api/account/theme route (own account, unknown name rejected), and
get_session/get_state handing the stored theme back. A real Service +
WebServer on a loopback port, the idiom test_api_tokens.py uses.
"""
import http.client
import json
import os
import sys
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("account_theme_")

from netpath.web import Service, WebServer
from netpath.web.api import THEMES
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER

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

ADMIN_PASSWORD = "ThemeSuiteAdmin2026"
failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
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
    headers_out = dict(resp.getheaders())
    conn.close()
    return resp.status, payload, headers_out


def login(username, password):
    status, payload, headers = call(
        "POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return headers.get("Set-Cookie", "").split("sw_session=")[1].split(";")[0]


try:
    print("migration")
    row = service.app_db.user(DEFAULT_USER)
    check("a fresh install's default account has an empty theme column",
          row is not None and row["theme"] == "", dict(row) if row else row)

    admin_token = login(DEFAULT_USER, DEFAULT_PASSWORD)
    status, payload, _h = call(
        "POST", "/api/password",
        {"current_password": DEFAULT_PASSWORD, "new_password": ADMIN_PASSWORD},
        token=admin_token)
    check("admin password change", status == 200, f"{status} {payload}")
    admin_token = login(DEFAULT_USER, ADMIN_PASSWORD)

    print("put_account_theme")
    status, payload, _h = call(
        "PUT", "/api/account/theme", {"theme": "not-a-real-theme"}, token=admin_token)
    check("an unknown theme is rejected", status == 400, f"{status} {payload}")
    row = service.app_db.user(DEFAULT_USER)
    check("…and nothing was stored", row["theme"] == "", dict(row))

    chosen = "midnight"
    check("the chosen theme is one this suite actually validates against THEMES",
          chosen in THEMES, THEMES)
    status, payload, _h = call(
        "PUT", "/api/account/theme", {"theme": chosen}, token=admin_token)
    check("a known theme is accepted", status == 200 and payload.get("theme") == chosen,
          f"{status} {payload}")
    row = service.app_db.user(DEFAULT_USER)
    check("…and stored on the account", row["theme"] == chosen, dict(row))

    status, payload, _h = call("GET", "/api/audit?limit=5000", token=admin_token)
    actions = [e["action"] for e in payload.get("events", [])]
    check("the save is audited as account.theme", "account.theme" in actions,
          str(sorted(set(actions))))

    print("get_session / get_state hand the theme back")
    status, payload, _h = call("GET", "/api/session", token=admin_token)
    check("get_session returns the stored theme",
          status == 200 and payload.get("theme") == chosen, f"{status} {payload}")

    status, payload, _h = call("GET", "/api/state", token=admin_token)
    check("get_state's session block returns the stored theme too",
          status == 200 and payload.get("session", {}).get("theme") == chosen,
          f"{status} {payload}")

    print("PUT requires a session")
    status, payload, _h = call("PUT", "/api/account/theme", {"theme": "dark"})
    check("no cookie, no save", status == 401, f"{status} {payload}")

    print("FAILED: " + ", ".join(failures) if failures else "ALL ACCOUNT THEME ASSERTIONS PASSED")
finally:
    server.stop()
    deadline = time.time() + 20
    while time.time() < deadline and service.node_poller.worker_state():
        time.sleep(0.1)
    service.shutdown()

sys.exit(1 if failures else 0)
