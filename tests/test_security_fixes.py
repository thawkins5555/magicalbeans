"""The security fixes from the network-engineer review, probed against a
real server.

The application is started the way the security reviewer started it — a
`Service` over ten SQLite files in a throwaway directory and a `WebServer`
on a free loopback port — and every check below is an HTTP request against
that instance, not a call into a handler. That is deliberate: most of these
defects were in the layer between the socket and the handler (the route
table, the session gate, the headers), and a unit test that calls the
handler directly would have passed on every one of them.

Nothing here needs the network, paramiko or DPAPI: `netpath.dpapi` is
replaced with a reversible stand-in before anything that stores a
credential is imported, and the self-update checks mock `urllib` at the two
functions that use it.
"""
import base64
import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import ssl
import stat
import sys
import tarfile
import threading
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("security_fixes_")

# Before anything that stores a credential is imported: the real DPAPI is
# Windows-only and every "store a secret" path refuses without it.
import netpath.dpapi as dpapi_mod  # noqa: E402
dpapi_mod.available = lambda: True
dpapi_mod.protect = lambda plaintext: b"FAKE:" + bytes(plaintext)
dpapi_mod.unprotect = lambda ciphertext: bytes(ciphertext)[5:]

from netpath.web.server import WebServer  # noqa: E402
from netpath.web.service import Service  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# --------------------------------------------------------------- the server

DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")

DATA_DIR = os.path.join(TMPDIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

SERVICE = Service(*[os.path.join(DATA_DIR, name + ".db") for name in DB_NAMES])
PORT = _paths.free_tcp_port()
SERVER = WebServer(SERVICE, host="127.0.0.1", port=PORT)
if not SERVER.start(block=False):
    print(f"SKIP: could not bind 127.0.0.1:{PORT}: {SERVER.error}")
    raise SystemExit(77)


def stop_server():
    try:
        SERVER.stop()
        SERVICE.shutdown()
    except Exception:
        pass
    shutil.rmtree(TMPDIR, ignore_errors=True)


def req(method, path, body=None, cookie=None, headers=None,
        content_type="application/json", raw=None):
    """One request. Returns (status, headers dict, decoded body-or-text)."""
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    sent = {}
    if raw is not None or body is not None:
        sent["Content-Type"] = content_type
    if cookie:
        sent["Cookie"] = cookie
    sent.update(headers or {})
    payload = raw if raw is not None else (
        json.dumps(body) if body is not None else None)
    try:
        conn.request(method, path, payload, sent)
        response = conn.getresponse()
        data = response.read()
        head = {k.lower(): v for k, v in response.getheaders()}
        try:
            return response.status, head, json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return response.status, head, data
    finally:
        conn.close()


def login(username, password):
    """(cookie, payload). The cookie is the Set-Cookie name=value pair."""
    status, head, payload = req("POST", "/api/login",
                                {"username": username, "password": password})
    cookie = head.get("set-cookie", "").split(";")[0]
    return (cookie if status == 200 else ""), status, payload


def main() -> int:
    from netpath import permissions

    # ------------------------------------------------------- D1 must_change
    admin_cookie, status, _payload = login("admin", "admin")
    check("D1 the seeded admin can sign in", status == 200 and bool(admin_cookie))

    status, _h, payload = req("GET", "/api/users", cookie=admin_cookie)
    check("D1 must_change refuses /api/users",
          status == 403 and isinstance(payload, dict)
          and "password change" in str(payload.get("error", "")).lower(),
          f"{status} {payload}")

    status, _h, _p = req("GET", "/api/nodes/devices", cookie=admin_cookie)
    check("D1 must_change refuses a module read", status == 403, str(status))

    status, _h, _p = req("POST", "/api/maintenance", {"action": "redns"},
                         cookie=admin_cookie)
    check("D1 must_change refuses maintenance", status == 403, str(status))

    for allowed in ("/api/state", "/api/session"):
        status, _h, _p = req("GET", allowed, cookie=admin_cookie)
        check(f"D1 must_change still allows {allowed}", status == 200, str(status))

    status, _h, _p = req("GET", "/index.html", cookie=admin_cookie)
    check("D1 must_change leaves static files alone", status == 200, str(status))

    # Change it, and the gate lifts.
    ADMIN_PASSWORD = "correct horse battery staple"
    status, _h, payload = req("POST", "/api/password",
                              {"current_password": "admin",
                               "new_password": ADMIN_PASSWORD},
                              cookie=admin_cookie)
    check("D1 the password change itself is allowed", status == 200, f"{status} {payload}")
    admin_cookie, status, _p = login("admin", ADMIN_PASSWORD)
    check("D1 after the change the API opens up",
          status == 200 and req("GET", "/api/users", cookie=admin_cookie)[0] == 200)

    # ---------------------------------------------------- D2 settings scope
    def make_user(username, grants, password="Corr3ct-Horse-Battery"):
        """An account with exactly these grants, ready to use (the
        must_change flag D1 sets on every new account is cleared here the
        way an operator's first sign-in would clear it)."""
        status, _h, payload = req("POST", "/api/users",
                                  {"username": username, "password": password,
                                   "grants": grants}, cookie=admin_cookie)
        assert status == 200, (username, status, payload)
        row = SERVICE.app_db.user(username)
        SERVICE.app_db.set_password(username, row["password"], must_change=False)
        cookie, status, _p = login(username, password)
        assert status == 200, (username, status)
        return cookie

    debug_cookie = make_user("debugonly", {"debug": "write"})

    status, _h, payload = req("POST", "/api/settings",
                              {"scope": "debug",
                               "values": {"web_port": 31337, "dns_server": "10.6.6.6",
                                          "session_idle_minutes": 1}},
                              cookie=debug_cookie)
    check("D2 an unlisted scope needs Settings write", status == 403, f"{status} {payload}")
    check("D2 …and nothing was applied",
          SERVICE.settings.get("web_port") != 31337
          and SERVICE.settings.get("dns_server") != "10.6.6.6",
          str(SERVICE.settings.get("web_port")))

    status, _h, payload = req("POST", "/api/settings",
                              {"scope": "netpath", "values": {"web_cert": "/tmp/evil.pem"}},
                              cookie=debug_cookie)
    check("D2 a netpath scope still needs netpath write", status == 403, str(status))

    netpath_cookie = make_user("netpathonly", {"netpath": "write"})
    status, _h, payload = req("POST", "/api/settings",
                              {"scope": "netpath",
                               "values": {"trace_workers": 4, "web_cert": "/tmp/evil.pem",
                                          "session_idle_minutes": 1}},
                              cookie=netpath_cookie)
    check("D2 a netpath scope write is accepted", status == 200, f"{status} {payload}")
    check("D2 …but does not carry global keys into the shared settings",
          SERVICE.settings.get("web_cert") != "/tmp/evil.pem"
          and SERVICE.settings.get("session_idle_minutes") != 1,
          f"{SERVICE.settings.get('web_cert')!r} "
          f"{SERVICE.settings.get('session_idle_minutes')!r}")
    check("D2 …and the response hides the Settings-only keys",
          isinstance(payload, dict)
          and not (set(payload.get("settings", {}))
                   & {"web_cert", "web_key", "web_host", "web_port",
                      "session_idle_minutes", "dns_server", "asn_server"}),
          str(sorted(payload.get("settings", {}))[:12]))

    status, _h, payload = req("GET", "/api/state", cookie=netpath_cookie)
    check("D2 /api/state hides them too",
          status == 200 and not (set(payload.get("settings", {}))
                                 & {"web_cert", "session_idle_minutes", "dns_server"}),
          str(status))

    status, _h, payload = req("GET", "/api/state", cookie=admin_cookie)
    check("D2 a Settings reader still sees them",
          "web_cert" in payload.get("settings", {})
          and "session_idle_minutes" in payload.get("settings", {}))

    return 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    finally:
        stop_server()
    if FAILS:
        print(f"\n{len(FAILS)} check(s) failed: " + ", ".join(FAILS))
        code = 1
    else:
        print("\nall checks passed")
    raise SystemExit(code)
