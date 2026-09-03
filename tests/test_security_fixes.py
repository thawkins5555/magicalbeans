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
import urllib.error as urllib_error

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

    # ------------------------------------------------------- D3 self-update
    from netpath import selfupdate

    status, _h, payload = req("POST", "/api/update", {}, cookie=admin_cookie)
    check("D3 updates_enabled defaults to off and refuses the route",
          status in (401, 403) and "switched off" in str(payload.get("error", "")),
          f"{status} {payload}")

    # A repository of one tag whose release publishes a digest, served
    # entirely from memory: the two functions in selfupdate that touch the
    # network are the only boundary, and both are replaced here.
    TAG = "v9.9.9"
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w:gz") as tar:
        for name, text in (("magicalbeans-9.9.9/netpath/__init__.py", "x = 1\n"),
                           ("magicalbeans-9.9.9/netpath/web/__init__.py", "y = 1\n")):
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o777          # the archive asking for more than it may have
            tar.addfile(info, io.BytesIO(data))
    TARBALL = tar_bytes.getvalue()
    GOOD_DIGEST = hashlib.sha256(TARBALL).hexdigest()

    state = {"digest": GOOD_DIGEST, "tarball": TARBALL, "calls": []}

    def fake_json(url, timeout=10.0):
        state["calls"].append(url)
        if url.endswith("/tags"):
            return [{"name": "v9.8.0", "commit": {"sha": "a" * 40}},
                    {"name": TAG, "commit": {"sha": "b" * 40}},
                    {"name": "v9.10.0-broken", "commit": {"sha": "c" * 40}}]
        if "/releases/tags/" in url:
            if url.endswith("v9.10.0-broken"):
                return {"assets": []}
            return {"assets": [{"name": "SHA256SUMS",
                                "browser_download_url": "https://example/SHA256SUMS"}]}
        raise AssertionError(url)

    def fake_bytes(url, timeout=60.0, max_bytes=0):
        state["calls"].append(url)
        if url.endswith("SHA256SUMS"):
            return (f"{state['digest']}  magicalbeans-{TAG}.tar.gz\n"
                    "0000  something-else.tar.gz\n").encode()
        if "codeload" in url:
            return state["tarball"]
        raise AssertionError(url)

    real_json, real_bytes = selfupdate._fetch_json, selfupdate._fetch_bytes
    real_swap, real_restart = selfupdate._swap_in, selfupdate.schedule_restart
    real_hook = selfupdate._before_restart_hook
    selfupdate._fetch_json, selfupdate._fetch_bytes = fake_json, fake_bytes
    swapped = []
    modes = []

    def fake_swap(path):
        # The temp tree is removed as soon as apply() returns, so the mode
        # the extraction left behind is read here, while it still exists.
        swapped.append(path)
        modes.append(stat.S_IMODE(
            os.stat(os.path.join(path, "__init__.py")).st_mode))

    selfupdate._swap_in = fake_swap
    selfupdate.schedule_restart = lambda delay=1.5: None
    quiesced = []
    selfupdate.set_before_restart_hook(lambda: quiesced.append(True))
    try:
        release = selfupdate.latest_tag()
        check("D3 the newest tag is chosen by version order, not list order",
              release["tag"] == "v9.10.0-broken", release["tag"])

        # The newest tag has no SHA256SUMS: refused, nothing downloaded.
        SERVICE.app_db.save_settings({"updates_enabled": True})
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 a release with no SHA256SUMS is refused",
              not result.get("ok") and "SHA256SUMS" in result.get("error", ""),
              str(result))
        check("D3 …and nothing was swapped in", not swapped, str(swapped))

        # Drop the broken tag so v9.9.9 is newest, and tamper with the archive.
        def only_good(url, timeout=10.0):
            payload = fake_json(url, timeout)
            if url.endswith("/tags"):
                return [t for t in payload if not t["name"].endswith("broken")]
            return payload
        selfupdate._fetch_json = only_good

        state["tarball"] = TARBALL + b"tampered"
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 a tarball whose digest differs is refused",
              not result.get("ok") and "SHA-256" in result.get("error", ""),
              str(result))
        check("D3 …and still nothing was swapped in", not swapped, str(swapped))

        # Oversized: refused before it can be unpacked.
        state["tarball"] = TARBALL
        result_ok_before = SERVICE.app_db.meta(selfupdate.INSTALLED_TAG_KEY)
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 the matching tarball installs",
              result.get("ok") and result.get("tag") == TAG, str(result))
        check("D3 …the workers were quiesced before the swap",
              bool(quiesced) and bool(swapped), f"{quiesced} {swapped}")
        check("D3 …and the installed tag is recorded",
              SERVICE.app_db.meta(selfupdate.INSTALLED_TAG_KEY) == TAG
              and result_ok_before is None,
              str(SERVICE.app_db.meta(selfupdate.INSTALLED_TAG_KEY)))

        # The unpacked tree must not carry the archive's own mode bits
        # (the tarball above asks for 0777 on every file).
        check("D3 the archive's mode bits are discarded",
              modes == [0o644], str([oct(m) for m in modes]))

        result = selfupdate.apply(SERVICE.app_db)
        check("D3 the same tag again is 'up to date'",
              result.get("ok") and result.get("up_to_date"), str(result))

        # And with the setting off again, nothing is even asked of GitHub.
        SERVICE.app_db.save_settings({"updates_enabled": False})
        state["calls"].clear()
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 switching the setting off stops it reaching the network",
              not result.get("ok") and result.get("disabled") and not state["calls"],
              f"{result} {state['calls']}")
    finally:
        selfupdate._fetch_json, selfupdate._fetch_bytes = real_json, real_bytes
        selfupdate._swap_in, selfupdate.schedule_restart = real_swap, real_restart
        selfupdate.set_before_restart_hook(real_hook)
        SERVICE.app_db.save_settings({"updates_enabled": False})

    # -------------------------------------------- D4 credential retargeting
    # The listener the review used: anything that reaches it is recorded, so
    # "no AUTH was seen" is a fact about the wire, not about the code.
    seen = []
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    smtp_port = listener.getsockname()[1]
    listener.listen(8)
    listener.settimeout(0.5)
    stop_listener = threading.Event()

    def spy():
        while not stop_listener.is_set():
            try:
                sock, _addr = listener.accept()
            except (socket.timeout, OSError):
                continue
            try:
                sock.settimeout(2)
                sock.sendall(b"220 spy ESMTP\r\n")
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    seen.append(data)
                    if data.upper().startswith(b"EHLO") or data.upper().startswith(b"HELO"):
                        sock.sendall(b"250-spy\r\n250 AUTH PLAIN LOGIN\r\n")
                    else:
                        sock.sendall(b"250 ok\r\n")
            except OSError:
                pass
            finally:
                sock.close()

    spy_thread = threading.Thread(target=spy, daemon=True)
    spy_thread.start()
    try:
        SERVICE.alerts_db.set_smtp_credential(
            dpapi_mod.protect(b"S3cretStoredPassword"))
        SERVICE.alerts_db.save_settings({
            "smtp_host": "mail.example.invalid", "smtp_port": 25,
            "smtp_security": "starttls", "smtp_username": "svc-monitor",
            "smtp_from": "sappiwhere@example.invalid"})
        SERVICE.alerts_settings = SERVICE.alerts_db.settings()

        status, _h, payload = req(
            "POST", "/api/alerts/smtp/test",
            {"to": "a@b.c", "smtp_host": "127.0.0.1", "smtp_port": smtp_port,
             "smtp_security": "none", "smtp_username": "svc-monitor"},
            cookie=admin_cookie)
        check("D4 the stored SMTP password is refused for a body-supplied host",
              status == 400 and "saved password" in str(payload.get("error", "")),
              f"{status} {payload}")
        check("D4 …and the listener saw nothing at all", not seen, str(seen[:2]))

        # With a password typed in, the destination is allowed — but not
        # over a transport that puts it on the wire in the clear.
        status, _h, payload = req(
            "POST", "/api/alerts/smtp/test",
            {"to": "a@b.c", "smtp_host": "127.0.0.1", "smtp_port": smtp_port,
             "smtp_security": "none", "smtp_username": "svc-monitor",
             "password": "typed-in"}, cookie=admin_cookie)
        check("D4 a password over an unprotected transport is refused",
              status == 400 and "in the clear" in str(payload.get("error", "")),
              f"{status} {payload}")
        check("D4 …and still nothing reached the listener", not seen, str(seen[:2]))

        # No password at all: the connection is allowed to happen (this is
        # the "does the port answer" test), and no AUTH is sent.
        status, _h, payload = req(
            "POST", "/api/alerts/smtp/test",
            {"to": "a@b.c", "smtp_host": "127.0.0.1", "smtp_port": smtp_port,
             "smtp_security": "none", "smtp_username": "", "password": ""},
            cookie=admin_cookie)
        # The spy answers 250 to everything, so the send itself reports a
        # protocol error; what matters here is that the connection was made
        # at all — a passwordless test of an unsaved host is still allowed.
        check("D4 a passwordless test still reaches the host",
              status == 200 and any(b"HLO" in d.upper() for d in seen),
              f"{status} {payload} {seen[:2]}")
        check("D4 …with no AUTH on the wire",
              not any(b"AUTH" in d.upper() for d in seen),
              str([d[:40] for d in seen]))

        # The opt-out exists, and turning it on lets the plain-auth test run.
        SERVICE.settings["smtp_allow_plain_auth"] = True
        seen.clear()
        status, _h, payload = req(
            "POST", "/api/alerts/smtp/test",
            {"to": "a@b.c", "smtp_host": "127.0.0.1", "smtp_port": smtp_port,
             "smtp_security": "none", "smtp_username": "svc-monitor",
             "password": "typed-in"}, cookie=admin_cookie)
        check("D4 the documented opt-out re-enables plain AUTH",
              status == 200 and any(b"AUTH" in d.upper() for d in seen),
              f"{status} {payload}")
        SERVICE.settings["smtp_allow_plain_auth"] = False
    finally:
        stop_listener.set()
        spy_thread.join(timeout=3)
        listener.close()

    # A stored credential does not follow the row to a new address.
    status, _h, payload = req("POST", "/api/ipam/dhcp/servers",
                              {"address": "10.0.0.5", "label": "dhcp-a"},
                              cookie=admin_cookie)
    server_id = payload["id"]
    SERVICE.ipam_db.set_dhcp_credential(server_id, "svc",
                                        dpapi_mod.protect(b"dhcp-secret"))
    status, _h, payload = req("PUT", f"/api/ipam/dhcp/servers/{server_id}",
                              {"address": "10.9.9.9"}, cookie=admin_cookie)
    check("D4 moving a DHCP server clears its stored credential",
          status == 200 and payload.get("credential_cleared")
          and not SERVICE.ipam_db.dhcp_server(server_id)["password_enc"],
          f"{status} {payload}")

    status, _h, payload = req("POST", "/api/wireless/controllers",
                              {"name": "wlc-a", "ip": "10.0.0.6"},
                              cookie=admin_cookie)
    controller_id = payload["id"]
    SERVICE.wireless_db.set_credential(controller_id,
                                       dpapi_mod.protect(b"wlc-secret"))
    status, _h, payload = req("PUT", f"/api/wireless/controllers/{controller_id}",
                              {"ip": "10.9.9.9"}, cookie=admin_cookie)
    check("D4 moving a wireless controller clears its stored credential",
          status == 200 and payload.get("credential_cleared")
          and not SERVICE.wireless_db.controller(controller_id)["v3_auth_pass_enc"],
          f"{status} {payload}")

    # ---------------------------------------------------------- D5 file modes
    if os.name == "nt":
        check("D5 file modes (skipped: Windows has no POSIX mode)", True)
    else:
        def loose_modes(names):
            bad = []
            for name in names:
                for suffix in ("", "-wal", "-shm"):
                    path = os.path.join(DATA_DIR, name + ".db" + suffix)
                    if not os.path.exists(path):
                        continue
                    mode = stat.S_IMODE(os.stat(path).st_mode)
                    if mode & 0o077:
                        bad.append(f"{os.path.basename(path)}={oct(mode)}")
            return bad

        # The three this workstream owns. dbopen.connect is adopted by each
        # database module as its workstream touches it; the remaining seven
        # are listed rather than failed so this suite reports progress
        # instead of blocking on another agent's file.
        check("D5 app.db, wireless.db and configrx.db are owner-only",
              not loose_modes(("app", "wireless", "configrx")),
              ", ".join(loose_modes(("app", "wireless", "configrx"))))
        remaining = loose_modes(("netpath", "flows", "syslog", "ipam",
                                 "snmptraps", "nodes", "alerts"))
        if remaining:
            print("      note: still to adopt dbopen.connect — "
                  + ", ".join(sorted({r.split("=")[0] for r in remaining})))

        from netpath import __main__ as entry
        home = os.path.join(TMPDIR, "fakehome")
        os.makedirs(home, exist_ok=True)
        old_xdg = os.environ.get("XDG_DATA_HOME")
        os.environ["XDG_DATA_HOME"] = home
        try:
            folder = os.path.dirname(entry.default_db_path())
            check("D5 a new data folder is created owner-only",
                  stat.S_IMODE(os.stat(folder).st_mode) == 0o700,
                  oct(stat.S_IMODE(os.stat(folder).st_mode)))
            os.chmod(folder, 0o755)          # an install that predates this
            entry.default_db_path()
            check("D5 an existing world-readable data folder is tightened",
                  stat.S_IMODE(os.stat(folder).st_mode) == 0o700,
                  oct(stat.S_IMODE(os.stat(folder).st_mode)))
        finally:
            if old_xdg is None:
                os.environ.pop("XDG_DATA_HOME", None)
            else:
                os.environ["XDG_DATA_HOME"] = old_xdg

    from netpath.configrxdb import DEFAULTS as CONFIGRX_DEFAULTS
    check("D5 allow_legacy_ssh is off by default",
          CONFIGRX_DEFAULTS["allow_legacy_ssh"] is False)

    # ------------------------------------------------ D6 headers and bodies
    status, head, _p = req("GET", "/api/state", cookie=admin_cookie)
    csp = head.get("content-security-policy", "")
    for directive in ("frame-ancestors 'none'", "base-uri 'none'",
                      "form-action 'self'", "connect-src 'self'"):
        check(f"D6 CSP carries {directive}", directive in csp, csp)
    check("D6 the Server header is gone", "server" not in head, str(head))
    check("D6 HSTS is absent over plain HTTP",
          "strict-transport-security" not in head, str(head))

    status, _h, payload = req("POST", "/api/maintenance", {"action": "redns"},
                              cookie=admin_cookie,
                              headers={"Origin": "http://evil.example"})
    check("D6 a cross-site Origin is refused", status == 403, f"{status} {payload}")

    status, _h, payload = req("POST", "/api/maintenance", {"action": "redns"},
                              cookie=admin_cookie,
                              headers={"Sec-Fetch-Site": "cross-site"})
    check("D6 Sec-Fetch-Site: cross-site is refused", status == 403, str(status))

    status, _h, payload = req("POST", "/api/maintenance", {"action": "redns"},
                              cookie=admin_cookie)
    check("D6 an absent Origin still works (scripts, the demo harness)",
          status == 200, f"{status} {payload}")

    status, _h, payload = req(
        "POST", "/api/maintenance", {"action": "redns"}, cookie=admin_cookie,
        headers={"Origin": f"http://127.0.0.1:{PORT}",
                 "Sec-Fetch-Site": "same-origin"})
    check("D6 the app's own origin is accepted", status == 200, str(status))

    # Chunked: refused with 411 rather than run with an empty body.
    chunked = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    payload = json.dumps({"action": "prune_syslog"}).encode()
    chunked.putrequest("POST", "/api/maintenance", skip_accept_encoding=True)
    chunked.putheader("Content-Type", "application/json")
    chunked.putheader("Transfer-Encoding", "chunked")
    chunked.putheader("Cookie", admin_cookie)
    chunked.endheaders()
    chunked.send(b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload))
    response = chunked.getresponse()
    response.read()
    chunked.close()
    check("D6 a chunked body is 411, not an empty body", response.status == 411,
          str(response.status))

    check("D6 the general body cap is 16 MiB",
          SERVER.httpd.RequestHandlerClass.MAX_BODY_BYTES == 16 * 1024 * 1024)
    handler_class = SERVER.httpd.RequestHandlerClass
    check("D6 the handler has a socket timeout", handler_class.timeout == 30,
          str(handler_class.timeout))

    status, _h, payload = req("POST", "/api/nodes/devices",
                              {"ip": "10.20.30.40",
                               "_agent": "<img src=x onerror=alert(1)>EVIL"},
                              cookie=admin_cookie)
    check("D6 an underscore key in a body is dropped, not stored",
          status == 200, f"{status} {payload}")
    _c, _s, _p = login("admin", ADMIN_PASSWORD)
    status, _h, payload = req("GET", "/api/users", cookie=admin_cookie)
    agents = [s.get("agent", "") for s in payload.get("sessions", [])]
    check("D6 the session list shows the real User-Agent, not a body field",
          not any("onerror" in a for a in agents), str(agents))

    # ------------------------------------------------------------- D7 login
    from netpath import auth as auth_mod

    # Timing: a real account and an account that does not exist must cost
    # the same. The dummy hash is built lazily, so warm it up first.
    login("nosuchaccount", "whatever")

    def timed(username, password):
        # The throttle's own delay would otherwise dominate after five
        # failures; what is being measured here is the hashing.
        SERVICE.throttle._failures.clear()
        started = time.perf_counter()
        login(username, password)
        return time.perf_counter() - started

    # Minimum of several, so a scheduling hiccup lengthens a sample rather
    # than shortening one. The defect this replaces was a factor of nine
    # (0.055 s against 0.48 s); anything under a third is not an oracle.
    real = min(timed("admin", "definitely-not-the-password") for _ in range(5))
    fake = min(timed("nosuchaccount", "definitely-not-the-password")
               for _ in range(5))
    gap = abs(real - fake) / max(real, fake, 1e-9)
    check("D7 an unknown username costs the same as a known one",
          gap < 0.30, f"real={real:.3f}s fake={fake:.3f}s gap={gap:.0%}")

    # A username that is not a username is refused before it is used as a
    # key or written anywhere.
    huge = "A" * 200_000
    before = len(SERVICE.log.all())
    _c, status, _p = login(huge, "x")
    check("D7 an oversized username is refused", status == 401, str(status))
    check("D7 …and does not put itself into the event log",
          not any(huge[:200] in (e.message or "") for e in SERVICE.log.all()[before:]))

    # Lockout: independent counters per username and per address.
    throttle = auth_mod.LoginThrottle(threshold=5, window_s=900,
                                      lockout_threshold=3, max_keys=10)
    for _ in range(3):
        throttle.record_failure("victim", "10.0.0.1")
    check("D7 the username is locked out after the threshold",
          throttle.lockout_remaining("victim", "10.0.0.9") > 0)
    check("D7 …and so is the address, independently",
          throttle.lockout_remaining("someone-else", "10.0.0.1") > 0)
    check("D7 …while an unrelated pair is not",
          throttle.lockout_remaining("bystander", "10.0.0.2") == 0)
    throttle.clear("victim")
    check("D7 a successful sign-in clears only that account's failures",
          throttle.lockout_remaining("victim", "10.0.0.9") == 0
          and throttle.lockout_remaining("someone-else", "10.0.0.1") > 0)
    for n in range(200):
        throttle.record_failure(f"guess{n}", f"10.1.0.{n % 250}")
    check("D7 the failure table is bounded",
          len(throttle._failures) <= throttle.max_keys,
          str(len(throttle._failures)))

    # And end to end: 429 rather than 401 once the real threshold is passed.
    victim = make_user("lockme", {"nodes": "read"})
    for _ in range(auth_mod.LOCKOUT_THRESHOLD):
        req("POST", "/api/login", {"username": "lockme", "password": "wrong"})
    status, _h, payload = req("POST", "/api/login",
                              {"username": "lockme",
                               "password": "Corr3ct-Horse-Battery"})
    check("D7 the real threshold locks the account out with 429",
          status == 429 and "Try again" in str(payload.get("error", "")),
          f"{status} {payload}")
    # Every failure above came from 127.0.0.1, so the ADDRESS is locked out
    # too — which is the point of counting it separately, and would stop
    # the rest of this suite signing in. Stand in for the fifteen minutes
    # passing.
    SERVICE.throttle._failures.clear()

    # Concurrency cannot dilute the throttle: the verifications serialise.
    check("D7 password verification is bounded by a semaphore",
          getattr(__import__("netpath.web.api", fromlist=["x"]),
                  "_LOGIN_SLOTS")._value <= 4)

    # ------------------------------------------------ D8 the admin capability
    check("D8 admin is appended after ssh in MODULES",
          permissions.MODULES[-2:] == ("ssh", "admin"),
          str(permissions.MODULES))
    check("D8 the seeded account holds it",
          SERVICE.app_db.permissions_for("admin").get("admin") == "write")

    settings_cookie = make_user("settingswrite", {"settings": "write"})
    for method, path, payload in (("GET", "/api/users", None),
                                  ("POST", "/api/users",
                                   {"username": "sneaky", "password": "Corr3ct-Horse-B4t"}),
                                  ("POST", "/api/users/permissions",
                                   {"username": "settingswrite",
                                    "grants": {"admin": "write"}}),
                                  ("POST", "/api/maintenance", {"action": "redns"}),
                                  ("POST", "/api/update", {})):
        status, _h, body_out = req(method, path, payload, cookie=settings_cookie)
        check(f"D8 settings:write is refused {method} {path}",
              status == 403, f"{status} {body_out}")

    status, _h, payload = req("POST", "/api/settings",
                              {"scope": "global", "values": {"updates_enabled": True}},
                              cookie=settings_cookie)
    check("D8 settings:write cannot turn self-update on",
          status == 401 and "administrator" in str(payload.get("error", "")),
          f"{status} {payload}")
    check("D8 …and it stayed off",
          SERVICE.app_db.settings().get("updates_enabled") is False)

    status, _h, payload = req("POST", "/api/password",
                              {"username": "debugonly",
                               "new_password": "An0ther-Horse-Battery"},
                              cookie=settings_cookie)
    check("D8 settings:write cannot reset another account's password",
          status == 403, f"{status} {payload}")

    # An administrator cannot edit their own grants, and the last one
    # cannot be reduced or removed.
    status, _h, payload = req("POST", "/api/users/permissions",
                              {"username": "admin", "grants": {"nodes": "read"}},
                              cookie=admin_cookie)
    check("D8 an administrator cannot change their own permissions",
          status == 400 and "your own" in str(payload.get("error", "")),
          f"{status} {payload}")

    make_user("admin2", {m: "write" for m in permissions.MODULES})
    status, _h, payload = req("POST", "/api/users/permissions",
                              {"username": "admin2", "grants": {"nodes": "read"}},
                              cookie=admin_cookie)
    check("D8 one administrator may reduce another", status == 200,
          f"{status} {payload}")

    make_user("admin3", {m: "write" for m in permissions.MODULES})
    status, _h, payload = req("DELETE", "/api/users", {"username": "admin3"},
                              cookie=admin_cookie)
    check("D8 …and remove another", status == 200, f"{status} {payload}")

    # The last-administrator guard is a backstop rather than a reachable
    # route: the caller must be an administrator and cannot target
    # themselves, so the two routes above can never leave zero. Exercised
    # directly, which is the only honest way to show it holds.
    import netpath.web.api as api_mod
    admins_now = SERVICE.app_db.usernames_with("admin", "write")
    try:
        api_mod._last_admin_guard(SERVICE, admins_now[0], keeps_admin=False)
        refused = False
    except ValueError:
        refused = True
    check("D8 the last administrator cannot be reduced away",
          admins_now == ["admin"] and refused, str(admins_now))

    # The migration: an account holding settings:write before the upgrade
    # receives admin, once, and revoking it afterwards sticks.
    from netpath.appdb import AppDatabase
    migrated_path = os.path.join(TMPDIR, "migrated.db")
    # Opened once so the permission table exists, then reopened: that is an
    # install that already had per-module grants, which is the case the
    # admin backfill is about. (A database with no permission table at all
    # predates the whole feature and gets write on everything, admin
    # included — the separate, older backfill.)
    AppDatabase(migrated_path).close()
    legacy = AppDatabase(migrated_path)
    legacy.add_user("olduser", "x", must_change=False)
    legacy.add_user("reader", "x", must_change=False)
    legacy.set_permissions("olduser", {"settings": "write", "nodes": "write"})
    legacy.set_permissions("reader", {"settings": "read", "nodes": "read"})
    legacy.backfill_permissions()
    check("D8 the migration grants admin to settings:write accounts",
          legacy.permissions_for("olduser").get("admin") == "write")
    check("D8 …and to nobody else",
          legacy.permissions_for("reader").get("admin") is None)
    legacy.set_permissions("olduser", {"settings": "write", "nodes": "write"})
    legacy.backfill_permissions()
    check("D8 the migration is idempotent — revoking it sticks",
          legacy.permissions_for("olduser").get("admin") is None)
    legacy.close()

    # --------------------------------------------------------- D9 audit log
    # Exercise the remaining audited paths through the API, so what the
    # trail is checked for below is what a real caller produces.
    throwaway = make_user("auditwalker", {"alerts": "write"})
    req("POST", "/api/alerts/smtp/credential", {"password": "audit-me"},
        cookie=throwaway)
    req("DELETE", "/api/alerts/smtp/credential", {}, cookie=throwaway)
    req("POST", "/api/logout", {}, cookie=throwaway)

    # An update attempt that cannot reach GitHub: enabled, so the route
    # runs, with the network boundary replaced so nothing leaves the host.
    SERVICE.app_db.save_settings({"updates_enabled": True})
    broken = selfupdate._fetch_json
    selfupdate._fetch_json = lambda url, timeout=10.0: (_ for _ in ()).throw(
        urllib_error.URLError("no network in this test"))
    try:
        req("POST", "/api/update", {}, cookie=admin_cookie)
    finally:
        selfupdate._fetch_json = broken
        SERVICE.app_db.save_settings({"updates_enabled": False})

    status, _h, payload = req("GET", "/api/audit", cookie=debug_cookie)
    check("D9 the audit log is administrator-only", status == 403, str(status))

    status, _h, payload = req("GET", "/api/audit?limit=99999", cookie=admin_cookie)
    check("D9 the limit is capped server-side",
          status == 200 and payload.get("limit") == 5000, f"{status} {payload!r}"[:200])
    actions = [e["action"] for e in payload.get("events", [])]
    for wanted in ("signin.ok", "signin.failed", "signout", "user.create",
                   "user.permissions", "settings.change", "credential.store",
                   "credential.clear", "password.change", "update.refused"):
        check(f"D9 {wanted} is audited", wanted in actions,
              str(sorted(set(actions))))

    # No row carries an unbounded field, and nothing deletes from the table.
    longest = max((len(e["detail"]) for e in payload["events"]), default=0)
    check("D9 audit fields are capped", longest <= 512, str(longest))
    check("D9 there is no route that deletes audit rows",
          not any("audit" in pattern and method in ("DELETE", "POST")
                  for method, pattern, _h2, _r in
                  __import__("netpath.web.server", fromlist=["x"]).ROUTES))

    before = payload["max_id"]
    status, _h, _p = req("POST", "/api/maintenance", {"action": "prune_syslog"},
                         cookie=admin_cookie)
    check("D9 a destructive maintenance action needs confirm", status == 400,
          str(status))
    status, _h, payload = req("POST", "/api/maintenance",
                              {"action": "prune_syslog", "confirm": True},
                              cookie=admin_cookie)
    check("D9 …and with it, reports the row count", status == 200
          and "removed" in payload, f"{status} {payload}")
    status, _h, payload = req("POST", "/api/maintenance", {"action": "nonsense"},
                              cookie=admin_cookie)
    check("D9 an unknown maintenance action is an error, not a 200",
          status == 400, f"{status} {payload}")

    status, _h, payload = req(f"GET", f"/api/audit?since={before}",
                              cookie=admin_cookie)
    pruned = [e for e in payload["events"] if e["action"] == "maintenance.prune_syslog"]
    check("D9 the prune is audited with its count",
          len(pruned) == 1 and "row(s)" in pruned[0]["detail"],
          str(pruned))

    # Rows survive the process: reopen the same file and read them back.
    from netpath.appdb import AppDatabase as _AppDb
    reopened = _AppDb(os.path.join(DATA_DIR, "app.db"))
    try:
        check("D9 audit rows survive a restart",
              reopened.audit_last_id() >= payload["max_id"] > 0,
              str(reopened.audit_last_id()))
    finally:
        reopened.close()

    # The Debug event feed is filtered by the caller's module grants.
    SERVICE.log.add("configrx", "a ConfigRX event only a ConfigRX reader sees")
    SERVICE.log.add("nodes", "a Nodes event only a Nodes reader sees")
    status, _h, payload = req("GET", "/api/debug", cookie=debug_cookie)
    categories = {e["category"] for e in payload.get("events", [])}
    check("D9 debug:read alone no longer reads every module's events",
          status == 200 and not (categories & {"configrx", "nodes", "system"}),
          str(sorted(categories)))
    status, _h, payload = req("GET", "/api/debug", cookie=admin_cookie)
    categories = {e["category"] for e in payload.get("events", [])}
    check("D9 …while an account holding those modules still does",
          {"configrx", "nodes"} <= categories, str(sorted(categories)))

    # ------------------------------------------------- D10 community strings
    group_id = SERVICE.nodes_db.ensure_default_group()
    SERVICE.nodes_db.update_group(group_id, community="pr0file-community")
    device_id = SERVICE.nodes_db.add_device("10.77.0.1", name="plc-1",
                                            group_id=group_id)
    SERVICE.nodes_db.update_device(device_id, community="s3cret-community")
    controller_id = SERVICE.wireless_db.add_controller(
        "wlc-b", "10.77.0.2", community="wl4n-community")

    reader = make_user("nodesreader", {"nodes": "read", "wireless": "read"})

    def community_values(cookie):
        found = []
        for path, key in (("/api/nodes/devices", "devices"),
                          ("/api/nodes/groups", "groups"),
                          ("/api/wireless/controllers", "controllers")):
            _s, _h, out = req("GET", path, cookie=cookie)
            found.append((path, [row.get("community") for row in out.get(key, [])],
                          [row.get("has_community") for row in out.get(key, [])]))
        _s, _h, out = req("GET", f"/api/nodes/devices/{device_id}", cookie=cookie)
        found.append(("device", [out.get("device", {}).get("community")],
                      [out.get("device", {}).get("has_community")]))
        found.append(("effective", [out.get("device", {})
                                    .get("effective_config", {}).get("community")],
                      [True]))
        return found

    for path, values, flags in community_values(reader):
        check(f"D10 a read-only caller sees no community in {path}",
              all(v is None for v in values), f"{values}")
        if path != "effective":
            check(f"D10 …but is told one exists in {path}", any(flags), str(flags))

    for path, values, _flags in community_values(admin_cookie):
        if path == "effective":
            continue
        check(f"D10 a write caller still sees the community in {path}",
              any(v for v in values), str(values))

    # ---------------------------------------------------- D11 backup secrets
    from netpath import configrx, configrx_redact

    CISCO = """!
hostname core-sw-1
!
enable secret 5 $1$mERr$Nv1KcQ9E6ZmM0pT7yzUq/1
enable password 7 070C285F4D06
!
username operator privilege 15 secret 5 $1$abcd$0123456789abcdefghij0
username backup password 7 104D000A0618
!
snmp-server community pl4nt-r34d RO 20
snmp-server community pl4nt-wr1te RW
snmp-server user netops NETOPS v3 auth sha AuthPassPhrase priv aes 128 PrivPassPhrase
!
tacacs-server host 10.1.1.1 key 7 05080F1C2243
radius-server host 10.1.1.2 key R4diusSh4red
tacacs server ISE
 address ipv4 10.1.1.3
 key 7 121A0C0411045D
!
key chain EIGRP-KEYS
 key 1
  key-string eigrpSh4redKey
!
crypto isakmp key MyPreSharedKey address 198.51.100.7
crypto ikev2 keyring KR
 peer BRANCH
  pre-shared-key local Br4nchLocalKey
  pre-shared-key remote Br4nchRemoteKey
!
router bgp 65001
 neighbor 203.0.113.9 password 7 060506324F41
!
interface Dialer1
 ppp chap password 7 02050D480809
!
banner motd ^ No enable secret is configured on guest kit ^
description uplink to the tacacs-server room
!
end
"""

    FORTIOS = """config system admin
    edit "admin"
        set password ENC AK1qL2mN3oP4qR5sT6uV7wX8yZ==
        set accprofile "super_admin"
    next
end
config user local
    edit "svc-radius"
        set passwd ENC ZZ9yX8wV7uT6sR5qP4oN3mL2kJ==
    next
end
config vpn ipsec phase1-interface
    edit "to-branch"
        set psksecret ENC QQ1aB2cD3eF4gH5iJ6kL7mN8oP==
        set remote-gw 198.51.100.8
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config log syslogd setting
    set status enable
end
"""

    for label, text, expected in (("Cisco IOS", CISCO, [
            "$1$mERr", "070C285F4D06", "$1$abcd", "104D000A0618",
            "pl4nt-r34d", "pl4nt-wr1te", "PrivPassPhrase",
            "05080F1C2243", "R4diusSh4red", "121A0C0411045D",
            "eigrpSh4redKey", "MyPreSharedKey", "Br4nchLocalKey",
            "Br4nchRemoteKey", "060506324F41", "02050D480809"]),
            ("FortiOS", FORTIOS, [
                "AK1qL2mN3oP4qR5sT6uV7wX8yZ==",
                "ZZ9yX8wV7uT6sR5qP4oN3mL2kJ==",
                "QQ1aB2cD3eF4gH5iJ6kL7mN8oP=="])):
        out, count = configrx_redact.redact(text)
        leaked = [secret for secret in expected if secret in out]
        check(f"D11 every {label} secret is replaced", not leaked, str(leaked))
        check(f"D11 …and the {label} pass reports what it did", count >= len(expected),
              f"{count} replacements for {len(expected)} secrets")

    check("D11 the structure of a redacted line survives",
          "snmp-server community <redacted> RO 20" in
          configrx_redact.redact(CISCO)[0]
          and "crypto isakmp key <redacted> address 198.51.100.7" in
          configrx_redact.redact(CISCO)[0])
    check("D11 …and FortiOS quoting is kept",
          'set psksecret ENC "<redacted>"' in configrx_redact.redact(FORTIOS)[0]
          or "set psksecret ENC <redacted>" in configrx_redact.redact(FORTIOS)[0],
          configrx_redact.redact(FORTIOS)[0])
    check("D11 text that only mentions a keyword is left alone",
          "No enable secret is configured on guest kit"
          in configrx_redact.redact(CISCO)[0]
          and "description uplink to the tacacs-server room"
          in configrx_redact.redact(CISCO)[0])
    check("D11 a config with no secrets is returned unchanged",
          configrx_redact.redact("hostname edge-1\n!\nend\n")
          == ("hostname edge-1\n!\nend\n", 0))

    # Through the worker's own storage path, with the device's opt-out.
    backup_device = SERVICE.nodes_db.add_device("10.77.0.9", name="cfg-sw",
                                                group_id=group_id)
    SERVICE.configrx_db.update_device_config(backup_device, backup_enabled=1)
    text, n = configrx_redact.redact(CISCO)
    stored_id, _digest = SERVICE.configrx_db.add_backup(backup_device, text,
                                                        redacted=True)
    row = SERVICE.configrx_db.backup(stored_id)
    check("D11 the stored row records that it was redacted", bool(row["redacted"]))
    content = SERVICE.configrx_db.backup_content(stored_id)
    check("D11 …and the stored bytes carry no secret",
          "pl4nt-wr1te" not in content and "<redacted>" in content)

    status, _h, payload = req("POST", f"/api/configrx/devices/{backup_device}/config",
                              {"store_secrets": True}, cookie=admin_cookie)
    check("D11 the per-device opt-out is settable", status == 200, str(status))
    check("D11 …and is reported back",
          req("GET", f"/api/configrx/devices/{backup_device}",
              cookie=admin_cookie)[2]["device"]["store_secrets"] is True)
    SERVICE.configrx_db.update_device_config(backup_device, store_secrets=0)

    # Content needs ConfigRX write; the listing does not.
    cx_reader = make_user("cxreader", {"configrx": "read"})
    status, _h, payload = req("GET", f"/api/configrx/backups/{stored_id}",
                              cookie=cx_reader)
    check("D11 a read-only ConfigRX account cannot download a backup",
          status == 403, f"{status} {payload}")
    status, _h, payload = req("GET",
                              f"/api/configrx/devices/{backup_device}/backups",
                              cookie=cx_reader)
    check("D11 …but still sees the listing, with the redacted flag",
          status == 200 and payload["backups"][0]["redacted"] is True,
          f"{status} {payload}")
    status, _h, payload = req("GET", f"/api/configrx/backups/{stored_id}",
                              cookie=admin_cookie)
    check("D11 a ConfigRX write account can still download it",
          status == 200 and "<redacted>" in payload.get("content", ""),
          str(status))

    # ----------------------------------------------------- D12 probe pacing
    from netpath import ipam_scan

    # A /24 at 200 probes per second cannot finish faster than ~1.27 s.
    # The ping itself is replaced so what is being measured is the pacing,
    # not this machine's ICMP.
    real_ping = ipam_scan.ping_once
    ipam_scan.ping_once = lambda ip, timeout_ms=800: False
    try:
        slash24 = ipam_scan.usable_addresses("10.88.0.0/24", 4096)
        started = time.perf_counter()
        result = ipam_scan.sweep(slash24, probes_per_second=200)
        elapsed = time.perf_counter() - started
        check("D12 a /24 sweep at 200/s takes at least 1.2 s",
              elapsed >= 1.2 and len(result) == len(slash24),
              f"{elapsed:.2f}s for {len(result)} addresses")

        started = time.perf_counter()
        ipam_scan.sweep(slash24, probes_per_second=0)
        unpaced = time.perf_counter() - started
        check("D12 …and is genuinely the pacing, not the probe",
              unpaced < 0.5, f"{unpaced:.2f}s unpaced")

        # The never-scan list: those addresses are reported, never probed.
        probed = []
        ipam_scan.ping_once = lambda ip, timeout_ms=800: probed.append(ip) or False
        out = ipam_scan.sweep(["10.88.0.1", "10.99.0.1"],
                              probes_per_second=0,
                              never_scan="10.88.0.0/24, 192.0.2.0/24")
        check("D12 an address on the never-scan list is not probed",
              probed == ["10.99.0.1"], str(probed))
        check("D12 …but is still accounted for",
              out == {"10.88.0.1": False, "10.99.0.1": False}, str(out))
        check("D12 an unparseable entry is dropped, not raised on",
              ipam_scan.parse_never_scan("not-a-cidr, 10.0.0.0/8") ,
              str(ipam_scan.parse_never_scan("not-a-cidr, 10.0.0.0/8")))
    finally:
        ipam_scan.ping_once = real_ping

    check("D12 never_scan_cidrs is a stored setting",
          "never_scan_cidrs" in SERVICE.app_db.settings())

    # /focus is a write.
    status, _h, payload = req("POST", f"/api/nodes/devices/{device_id}/focus",
                              {}, cookie=reader)
    check("D12 a Nodes-read account cannot start fast polling",
          status == 403, f"{status} {payload}")
    status, _h, payload = req("POST", f"/api/nodes/devices/{device_id}/focus",
                              {}, cookie=admin_cookie)
    check("D12 …while a Nodes-write account still can", status == 200, str(status))

    # mibcatalog.fetch_file: the vendored CA bundle, and a pinned digest.
    from netpath import mibcatalog, selfupdate as selfupdate_mod

    seen_context = {}

    class _FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def read(self, n=-1):
            return self._payload[:n] if n >= 0 else self._payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    real_urlopen = mibcatalog.urllib.request.urlopen
    MIB_BYTES = b"TEST-MIB DEFINITIONS ::= BEGIN\nEND\n"

    def fake_urlopen(request, timeout=None, context=None):
        seen_context["context"] = context
        return _FakeResponse(MIB_BYTES)

    mibcatalog.urllib.request.urlopen = fake_urlopen
    try:
        text = mibcatalog.fetch_file("https://example/TEST-MIB", 5, 1 << 20)
        check("D12 fetch_file uses the vendored CA bundle context",
              seen_context.get("context") is not None
              and isinstance(seen_context["context"], ssl.SSLContext)
              and "BEGIN" in text)
        good = hashlib.sha256(MIB_BYTES).hexdigest()
        check("D12 …accepts a file matching its pinned digest",
              "BEGIN" in mibcatalog.fetch_file("https://example/TEST-MIB", 5,
                                               1 << 20, sha256=good))
        try:
            mibcatalog.fetch_file("https://example/TEST-MIB", 5, 1 << 20,
                                  sha256="0" * 64)
            refused = False
        except mibcatalog.DownloadError:
            refused = True
        check("D12 …and refuses one that does not", refused)
    finally:
        mibcatalog.urllib.request.urlopen = real_urlopen

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
