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
import sqlite3
import ssl
import stat
import sys
import tarfile
import tempfile
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

    status, _h, payload = req("GET", "/api/config", cookie=netpath_cookie)
    check("D2 /api/config hides them too",
          status == 200 and not (set(payload.get("settings", {}))
                                 & {"web_cert", "session_idle_minutes", "dns_server"}),
          str(status))

    status, _h, payload = req("GET", "/api/config", cookie=admin_cookie)
    check("D2 a Settings reader still sees them",
          "web_cert" in payload.get("settings", {})
          and "session_idle_minutes" in payload.get("settings", {}))

    # ------------------------------------------------------- D3 self-update
    from netpath import appdb as appdb_module
    from netpath import selfupdate

    # A setting the API guards but no page can set is a setting that can only
    # ever hold its default. updates_enabled shipped exactly like that: the
    # default, the admin-only guard, the enforcement in apply() and a refusal
    # naming a control ("Allow updates from GitHub in Settings") that did not
    # exist anywhere in the UI, so the update button could never work on any
    # install. Every administrator-only setting has to be reachable.
    from netpath.web import api as _api
    static_dir = os.path.join(_paths.REPO_ROOT, "netpath", "web", "static")
    with open(os.path.join(static_dir, "settings.js"), encoding="utf-8") as fh:
        settings_js = fh.read()
    with open(os.path.join(static_dir, "index.html"), encoding="utf-8") as fh:
        index_html = fh.read()
    # "Reachable" means a control exists somewhere an administrator can get
    # at, not specifically on the Settings page. The listener keys
    # (web_host/web_port/web_cert/web_key) joined ADMIN_ONLY_SETTINGS when a
    # review found that a plain settings:write grant — deliberately weaker
    # than admin — could repoint the TLS material and the bind address
    # through the API. They have never had a Settings-page control and
    # should not get one: the listener is changed from the service console
    # (console.py's Apply and restart), which needs a session on the host
    # itself, and from the command line. So the console counts as a control
    # surface here. What this check is really guarding against is the
    # updates_enabled case in the comment above — a key the API guards that
    # NOTHING anywhere can set, which can therefore only ever hold its
    # default — and that guarantee is unchanged.
    with open(os.path.join(_paths.REPO_ROOT, "netpath", "console.py"),
              encoding="utf-8") as fh:
        console_py = fh.read()
    unreachable = [key for key in _api.ADMIN_ONLY_SETTINGS
                   if key not in settings_js and key not in console_py]
    check("D3 every administrator-only setting has a control that sets it",
          not unreachable, str(unreachable))
    # And that control is gated on the grant the API actually demands, so it
    # is not offered to someone whose press can only ever be refused.
    check("D3 …the update controls are gated on admin, not settings",
          index_html.count('data-requires-write="admin"') >= 3
          and 'id="update-now" class="primary half" '
              'data-requires-write="settings"' not in index_html,
          str(index_html.count('data-requires-write="admin"')))

    status, _h, payload = req("POST", "/api/update", {}, cookie=admin_cookie)
    # 403 specifically, not "401 or 403": accepting either is what let a 401
    # ship here, and a 401 makes the browser replace the page with the
    # sign-in form instead of showing the operator which setting to turn on.
    check("D3 updates_enabled defaults to off and refuses the route",
          status == 403 and "switched off" in str(payload.get("error", "")),
          f"{status} {payload}")

    # A repository served entirely from memory: the two functions in
    # selfupdate that touch the network are the only boundary, and both are
    # replaced here.
    #
    # apply() follows the tip of main — see the SECURITY NOTE in
    # selfupdate.py for the exposure that carries and why it is accepted for
    # now. The tag-and-digest helpers it no longer calls are still exercised
    # directly further down, so the verified path stays covered and putting
    # it back stays a change to apply() rather than a rewrite.
    TAG = "v9.9.9"
    TIP = "b" * 40

    def build_tarball(root: str) -> bytes:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as tar:
            for name, text in ((f"{root}/netpath/__init__.py", "x = 1\n"),
                               (f"{root}/netpath/web/__init__.py", "y = 1\n")):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o777      # the archive asking for more than it may have
                tar.addfile(info, io.BytesIO(data))
        return raw.getvalue()

    TARBALL = build_tarball(f"magicalbeans-{TIP}")
    GOOD_DIGEST = hashlib.sha256(build_tarball("magicalbeans-9.9.9")).hexdigest()

    state = {"digest": GOOD_DIGEST, "tarball": TARBALL, "sha": TIP,
             "message": "The commit at the tip\n\nand its body", "calls": []}

    def fake_json(url, timeout=10.0):
        state["calls"].append(url)
        if url.endswith("/commits/main"):
            return {"sha": state["sha"],
                    "commit": {"message": state["message"]}}
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

    # NTFS has no POSIX mode concept, so os.stat().st_mode on Windows is
    # synthesized from the read-only attribute and file type rather than
    # reflecting what os.chmod was asked to set — reading it back cannot
    # prove the archive's mode bits were discarded there. tarfile's own
    # extraction calls os.chmod(path, member.mode) on every platform
    # (hasattr(os, "chmod") is true on Windows too), so recording those
    # calls proves the same property in a way both platforms can observe.
    chmod_calls = []
    real_chmod = os.chmod

    def spy_chmod(path, mode, *a, **kw):
        chmod_calls.append((path, mode))
        return real_chmod(path, mode, *a, **kw)

    os.chmod = spy_chmod

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
        SERVICE.app_db.save_settings({"updates_enabled": True})

        # The tip of main is what is installed, and it is reached without
        # asking about tags or releases at all.
        state["calls"].clear()
        commit_before = SERVICE.app_db.meta(selfupdate.INSTALLED_COMMIT_KEY)
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 the tip of main installs",
              result.get("ok") and not result.get("up_to_date")
              and result.get("commit") == TIP[:10], str(result))
        check("D3 …with the commit subject as its message, not its whole body",
              result.get("message") == "The commit at the tip", str(result))
        check("D3 …asking GitHub only for the branch tip and that tarball",
              not any("/tags" in url or "/releases" in url
                      for url in state["calls"]),
              str(state["calls"]))
        check("D3 …the workers were quiesced before the swap",
              bool(quiesced) and bool(swapped), f"{quiesced} {swapped}")
        check("D3 …and the installed commit is recorded",
              SERVICE.app_db.meta(selfupdate.INSTALLED_COMMIT_KEY) == TIP
              and commit_before is None,
              str(SERVICE.app_db.meta(selfupdate.INSTALLED_COMMIT_KEY)))
        # A branch pull cannot honestly claim a tag, so it must not leave one
        # behind for the Settings page to report as what is installed.
        check("D3 …and no tag is claimed for it",
              not SERVICE.app_db.meta(selfupdate.INSTALLED_TAG_KEY),
              repr(SERVICE.app_db.meta(selfupdate.INSTALLED_TAG_KEY)))

        # The unpacked tree must not carry the archive's own mode bits
        # (the tarball above asks for 0777 on every file). On POSIX this is
        # asked directly of the filesystem; on Windows, where st_mode is not
        # a real POSIX mode, it is asked of the chmod call tarfile itself
        # made, which is the only place the property is observable there.
        if sys.platform == "win32":
            init_calls = [mode for path, mode in chmod_calls
                         if os.path.basename(path) == "__init__.py"]
            check("D3 the archive's mode bits are discarded",
                  bool(init_calls) and all(m == 0o644 for m in init_calls),
                  str([oct(m) for m in init_calls]))
        else:
            check("D3 the archive's mode bits are discarded",
                  modes == [0o644], str([oct(m) for m in modes]))

        result = selfupdate.apply(SERVICE.app_db)
        check("D3 the same tip again is 'up to date'",
              result.get("ok") and result.get("up_to_date"), str(result))

        # A branch tip moves, and following it is the whole point of this
        # path: the next commit installs without anything being published.
        MOVED = "d" * 40
        state["sha"], state["message"] = MOVED, "A later commit"
        state["tarball"] = build_tarball(f"magicalbeans-{MOVED}")
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 a moved tip installs the new commit",
              result.get("ok") and not result.get("up_to_date")
              and result.get("commit") == MOVED[:10]
              and SERVICE.app_db.meta(selfupdate.INSTALLED_COMMIT_KEY) == MOVED,
              str(result))

        # An answer that arrived intact but carries no commit id is not a
        # connectivity problem, and must not be reported as one — that sent
        # an operator to the firewall for something no firewall would fix.
        state["sha"] = ""
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 an answer with no commit id is not 'could not reach GitHub'",
              not result.get("ok")
              and "commit id" in result.get("error", "")
              and "reach" not in result.get("error", ""), str(result))
        state["sha"], state["message"] = MOVED, "A later commit"

        # And with the setting off again, nothing is even asked of GitHub.
        SERVICE.app_db.save_settings({"updates_enabled": False})
        state["calls"].clear()
        result = selfupdate.apply(SERVICE.app_db)
        check("D3 switching the setting off stops it reaching the network",
              not result.get("ok") and result.get("disabled") and not state["calls"],
              f"{result} {state['calls']}")

        # "This host replaced its own code" is the audit entry that matters
        # most, and it was the one the log never kept: apply() closes app.db
        # before it swaps the package, so the service's own handle is gone
        # by the time there is an outcome to record, and audit() swallowed
        # the resulting ProgrammingError after logging a traceback. A
        # connection of the write's own is the same idiom write_meta uses.
        audit_probe = os.path.join(tempfile.mkdtemp(), "app.db")
        probe_db = appdb_module.AppDatabase(audit_probe)
        probe_db.audit("someone", "10.0.0.9", "update.requested")
        probe_db.close()                    # exactly what apply() leaves
        appdb_module.write_audit(audit_probe, "someone", "10.0.0.9",
                                 "update.installed", target="abc1234567")
        with sqlite3.connect(audit_probe) as probe:
            actions = [r[0] for r in
                       probe.execute("SELECT action FROM audit ORDER BY ts")]
        check("D3 a completed update is audited even though app.db is closed",
              actions == ["update.requested", "update.installed"], str(actions))

        # The verified path apply() no longer uses, still covered so that
        # restoring it stays a change to apply() rather than a rewrite.
        release = selfupdate.latest_tag()
        check("D3 (retained) the newest tag is chosen by version order",
              release["tag"] == "v9.10.0-broken", release["tag"])
        try:
            selfupdate.published_digest("v9.10.0-broken")
            refused = ""
        except ValueError as exc:
            refused = str(exc)
        check("D3 (retained) a release with no SHA256SUMS is refused",
              "SHA256SUMS" in refused, refused or "no refusal")
        check("D3 (retained) a published digest is read from the asset list",
              selfupdate.published_digest(TAG) == GOOD_DIGEST,
              selfupdate.published_digest(TAG))
    finally:
        selfupdate._fetch_json, selfupdate._fetch_bytes = real_json, real_bytes
        selfupdate._swap_in, selfupdate.schedule_restart = real_swap, real_restart
        selfupdate.set_before_restart_hook(real_hook)
        os.chmod = real_chmod
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
    # 403, not 401: the caller is signed in and stays signed in. A 401 sends
    # the browser to the sign-in page, which bounces straight back for a
    # valid session and loses the sentence saying what was refused and why.
    check("D8 settings:write cannot turn self-update on",
          status == 403 and "administrator" in str(payload.get("error", "")),
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
            "pl4nt-r34d", "pl4nt-wr1te", "AuthPassPhrase", "PrivPassPhrase",
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

    # The SNMPv3 user line carries two keys, and used to lose only the last
    # token on the line: the auth key stayed whenever a priv key followed,
    # and an `access` clause after them kept both.
    for label, line, secrets, keep in (
            ("auth only", "snmp-server user ro-user NETOPS v3 auth sha OnlyAuthKey999",
             ["OnlyAuthKey999"], "auth sha <redacted>"),
            ("auth+priv+acl",
             "snmp-server user netops NETOPS v3 auth sha AuthKeyA priv aes 128 PrivKeyB access 10",
             ["AuthKeyA", "PrivKeyB"], "priv aes 128 <redacted> access 10"),
            ("encrypted",
             "snmp-server user svc SVC v3 encrypted auth sha EncAuthHash priv aes 256 EncPrivHash",
             ["EncAuthHash", "EncPrivHash"], "auth sha <redacted> priv aes 256 <redacted>"),
            ("upper case",
             "SNMP-SERVER USER OPS OPS V3 AUTH SHA UpperAuthKey PRIV AES 192 UpperPrivKey",
             ["UpperAuthKey", "UpperPrivKey"], "PRIV AES 192 <redacted>")):
        out, count = configrx_redact.redact(line)
        leaked = [secret for secret in secrets if secret in out]
        check(f"D11 snmp-server user v3 ({label}): every key is replaced",
              not leaked and count == len(secrets), f"{out!r} ({count})")
        check(f"D11 snmp-server user v3 ({label}): the rest of the line survives",
              keep in out, out)

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

    # P1-8: reading a stored config is a read, not a write — a ConfigRX
    # reader gets the content, same as the listing beside it.
    cx_reader = make_user("cxreader", {"configrx": "read"})
    status, _h, payload = req("GET", f"/api/configrx/backups/{stored_id}",
                              cookie=cx_reader)
    check("D11 a read-only ConfigRX account can read an already-redacted backup",
          status == 200 and "<redacted>" in payload.get("content", ""),
          f"{status} {payload}")
    status, _h, payload = req("GET",
                              f"/api/configrx/devices/{backup_device}/backups",
                              cookie=cx_reader)
    check("D11 …and still sees the listing, with the redacted flag",
          status == 200 and payload["backups"][0]["redacted"] is True,
          f"{status} {payload}")
    status, _h, payload = req("GET", f"/api/configrx/backups/{stored_id}",
                              cookie=admin_cookie)
    check("D11 a ConfigRX write account can still download it",
          status == 200 and "<redacted>" in payload.get("content", ""),
          str(status))

    # The case the read-only route change actually has to guard: a backup
    # stored VERBATIM (store_secrets was on for the capture) still cannot
    # reach a caller without ConfigRX write — it comes back redacted on the
    # fly instead of 403ing, and the response says so.
    verbatim_id, _digest = SERVICE.configrx_db.add_backup(
        backup_device, CISCO, redacted=False)
    verbatim_row = SERVICE.configrx_db.backup(verbatim_id)
    check("D11 the verbatim row records that it was NOT redacted",
          not bool(verbatim_row["redacted"]))
    status, _h, payload = req("GET", f"/api/configrx/backups/{verbatim_id}",
                              cookie=cx_reader)
    check("D11 a read-only account reading a verbatim backup gets 200, not 403",
          status == 200, f"{status} {payload}")
    check("D11 …with the secret taken out",
          "pl4nt-wr1te" not in payload.get("content", "")
          and "<redacted>" in payload.get("content", ""),
          payload.get("content", ""))
    check("D11 …and the response says it was redacted for this caller",
          payload.get("backup", {}).get("redacted") is True, str(payload))
    status, _h, payload = req("GET", f"/api/configrx/backups/{verbatim_id}",
                              cookie=admin_cookie)
    check("D11 a ConfigRX write account reads the verbatim backup unredacted",
          status == 200 and "pl4nt-wr1te" in payload.get("content", ""),
          f"{status} {payload}")
    check("D11 …and the stored row's own flag is reported, still False",
          payload.get("backup", {}).get("redacted") is False, str(payload))

    # The diff route was ConfigRX write through 4.48.0 and is ConfigRX read
    # from 4.49.0. Refusing a comparison of two backups the same account may
    # already open one at a time was never a boundary — a read-only account
    # could diff them by eye — so the gate matched get_configrx_backup and
    # the protection moved to where it does work: get_configrx_diff redacts
    # unconditionally, ignoring each row's own `redacted` flag. That is
    # STRICTER than the single-backup route, which still hands a write
    # account the verbatim text of a store_secrets=True capture.
    #
    # `verbatim_id` below is exactly that capture — stored unredacted on
    # purpose — so this pair is the case that would leak if the second
    # redaction pass were ever dropped. The check is deliberately not
    # "status == 200": it is that the secret is absent from the whole
    # response, whatever shape it takes.
    status, _h, payload = req(
        "GET", f"/api/configrx/diff?device={backup_device}"
        f"&from={stored_id}&to={verbatim_id}", cookie=cx_reader)
    check("D11 a read-only ConfigRX account may now read a diff",
          status == 200, f"{status} {payload}")
    check("D11 …and the verbatim side's secret is redacted anyway, "
          "even though that row is flagged NOT redacted",
          "pl4nt-wr1te" not in json.dumps(payload), json.dumps(payload)[:400])
    # This pair is the degenerate case the second redaction pass creates, and
    # it is worth pinning rather than avoiding. The two rows have genuinely
    # different stored bytes — different sha256, which the response itself
    # reports — but one was stored redacted and the other verbatim, so after
    # get_configrx_diff redacts BOTH the secret reads as the identical
    # "<redacted>" token on each side and the visible diff comes back empty.
    #
    # Empty is the honest answer to "what changed in the text you are allowed
    # to see". It used to be a misleading answer to "did anything change",
    # which is what an operator clicking Diff is actually asking — O-57:
    # the response now distinguishes "identical" (the two rows genuinely are
    # the same) from "differs only in redacted material" (`identical` is
    # False and `redacted_only_change` is True), rather than reporting
    # hashes that differ alongside a diff that implied nothing did.
    check("D11 …the two rows really do differ on disk",
          payload["from"]["sha256"] != payload["to"]["sha256"],
          f'{payload["from"]["sha256"]} vs {payload["to"]["sha256"]}')
    check("D11 …the visible diff is empty (the secret change is invisible "
          "to it, same as before)",
          payload.get("diff") == "" and payload.get("additions") == 0
          and payload.get("removals") == 0, str(payload)[:300])
    check("D11 …but the response no longer calls this 'identical' (O-57)",
          payload.get("identical") is False, str(payload)[:300])
    check("D11 …and says plainly that the difference is entirely in "
          "redacted material (O-57)",
          payload.get("redacted_only_change") is True, str(payload)[:300])
    status, _h, payload = req(
        "GET", f"/api/configrx/diff?device={backup_device}"
        f"&from={stored_id}&to={verbatim_id}", cookie=admin_cookie)
    check("D11 …and a ConfigRX WRITE account gets the secret redacted too — "
          "the diff route never serves it to anyone",
          status == 200 and "pl4nt-wr1te" not in json.dumps(payload),
          f"{status} {json.dumps(payload)[:400]}")

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

    # ------------------------------------------------- D13 the origin scheme
    # This listener is plain HTTP, so an https:// origin naming the same
    # host and port is a different origin and must be refused. It used to
    # be accepted, on the state-changing methods and on the WebSocket
    # upgrade alike, because only the netloc was compared.
    status, _h, payload = req("POST", "/api/maintenance", {"action": "redns"},
                              cookie=admin_cookie,
                              headers={"Origin": f"https://127.0.0.1:{PORT}"})
    check("D13 an https origin against an http listener is refused",
          status == 403, f"{status} {payload}")
    status, _h, _p = req("POST", "/api/maintenance", {"action": "redns"},
                         cookie=admin_cookie,
                         headers={"Origin": f"HTTP://127.0.0.1:{PORT}"})
    check("D13 …while the scheme comparison stays case-insensitive",
          status == 200, str(status))

    def upgrade(origin):
        """A WebSocket upgrade, far enough to see the status line."""
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        headers = {"Upgrade": "websocket", "Connection": "Upgrade",
                   "Sec-WebSocket-Version": "13",
                   "Sec-WebSocket-Key": base64.b64encode(b"0123456789abcdef").decode(),
                   "Cookie": admin_cookie}
        if origin:
            headers["Origin"] = origin
        try:
            conn.request("GET", f"/api/ssh/devices/{device_id}/socket",
                         headers=headers)
            return conn.getresponse().status
        finally:
            conn.close()

    check("D13 an upgrade with no Origin is still refused",
          upgrade(None) == 403, str(upgrade(None)))
    check("D13 an upgrade with a mismatched scheme is refused",
          upgrade(f"https://127.0.0.1:{PORT}") == 403,
          str(upgrade(f"https://127.0.0.1:{PORT}")))
    check("D13 an upgrade from another host is refused",
          upgrade("http://evil.example") == 403,
          str(upgrade("http://evil.example")))
    check("D13 …and the app's own origin still upgrades",
          upgrade(f"http://127.0.0.1:{PORT}") == 101,
          str(upgrade(f"http://127.0.0.1:{PORT}")))

    # ------------------------------------------------- D14 the access log
    from netpath.web.server import AccessLog, MAX_TRACKED_CLIENTS

    check("D14 the live access log has a client ceiling",
          MAX_TRACKED_CLIENTS == 1000 and SERVER.access.max_clients == 1000,
          str(SERVER.access.max_clients))

    small = AccessLog(max_clients=10)
    for n in range(500):
        small.record(f"10.0.{n // 250}.{n % 250}", "GET", "/api/state", 200,
                     1.0, "scanner/1.0")
    check("D14 it stops growing one entry per source address",
          len(small.clients) == 10, str(len(small.clients)))
    check("D14 …and keeps the most recently seen",
          f"10.0.1.249" in small.clients and "10.0.0.0" not in small.clients,
          str(list(small.clients)[:3]))
    small.record("10.0.0.5", "GET", "/api/state", 200, 1.0, "operator")
    small.record("10.9.9.9", "GET", "/api/state", 200, 1.0, "operator")
    check("D14 …evicting the quietest, not the newest",
          "10.0.0.5" in small.clients and "10.9.9.9" in small.clients,
          str(list(small.clients)))
    check("D14 the snapshot still reads",
          isinstance(small.snapshot()["clients"], dict))

    # ------------------------------------------- D15 the stale "no auth" lines
    # Both of this workstream's copies went with D5, when the headless
    # banner was rewritten. This is the guard that keeps them gone: the
    # claim was false from 4.22 onward, and __main__'s copy printed on
    # every headless start, so an operator's last word before walking away
    # was that the application they had just secured was unauthenticated.
    # console.py's third copy belongs to another workstream.
    import netpath.web.server as server_mod
    import netpath.__main__ as main_mod

    stale = []
    for module in (server_mod, main_mod):
        with open(module.__file__, encoding="utf-8") as handle:
            text = handle.read().lower()
        for phrase in ("no authentication yet", "is no authentication"):
            if phrase in text:
                stale.append(f"{os.path.basename(module.__file__)}: {phrase}")
    check("D15 nothing in the server or the entry point claims there is no "
          "authentication", not stale, ", ".join(stale))
    check("D15 …and the headless banner says what is actually true",
          "must change its" in open(main_mod.__file__, encoding="utf-8").read())

    # ------------------------------------------ D16 ConfigRX SSH port range
    # 0, -5 and 99999 were all previously stored as a device's ssh_port,
    # after which every backup attempt failed with a bare socket error and
    # nothing pointed at the port being the reason. The route now refuses
    # anything outside 1-65535 with a 400, before it ever reaches the
    # database or a socket.
    print("configrx SSH port range")
    for bad_port in (0, -5, 99999):
        status, _h, payload = req(
            "POST", f"/api/configrx/devices/{backup_device}/config",
            {"ssh_port": bad_port}, cookie=admin_cookie)
        check(f"D16 ssh_port {bad_port} is refused", status == 400,
              f"{status} {payload}")
    stored_port = SERVICE.configrx_db.device_config(backup_device)["ssh_port"]
    check("D16 …and none of them were stored", stored_port not in (0, -5, 99999),
          stored_port)

    for good_port in (1, 65535):
        status, _h, payload = req(
            "POST", f"/api/configrx/devices/{backup_device}/config",
            {"ssh_port": good_port}, cookie=admin_cookie)
        check(f"D16 ssh_port {good_port} (boundary) is accepted",
              status == 200, f"{status} {payload}")
        check(f"D16 …and stored",
              SERVICE.configrx_db.device_config(backup_device)["ssh_port"] == good_port,
              SERVICE.configrx_db.device_config(backup_device)["ssh_port"])
    SERVICE.configrx_db.update_device_config(backup_device, ssh_port=22)

    # --------------------------- D17 the enable secret's three-way contract
    # POST .../credential: the key absent from the body leaves a stored
    # enable secret alone, present-and-empty clears it, present-and-non-empty
    # (re)encrypts and replaces it. clear_credential (the DELETE route) was
    # fixed this release to clear both secrets, not just the SSH password —
    # a device's decommission or a post-exposure credential wipe otherwise
    # left the enable secret sitting in configrx.db, unreachable but still
    # reported as present by has_enable_secret.
    print("configrx enable secret three-way contract")
    status, _h, payload = req(
        "POST", f"/api/configrx/devices/{backup_device}/credential",
        {"ssh_username": "netops", "ssh_password": "swpass1"}, cookie=admin_cookie)
    check("D17 a credential with no enable_secret key is accepted", status == 200,
          f"{status} {payload}")
    check("D17 …and the response never carries a secret",
          "ssh_password" not in payload and "enable_secret" not in payload
          and "ssh_password_enc" not in payload and "enable_secret_enc" not in payload,
          payload)
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D17 …absent enable_secret leaves none stored (still none to begin with)",
          config["enable_secret_enc"] is None)

    status, _h, payload = req(
        "POST", f"/api/configrx/devices/{backup_device}/credential",
        {"ssh_username": "netops", "ssh_password": "swpass2",
         "enable_secret": "en4ble-1"}, cookie=admin_cookie)
    check("D17 a non-empty enable_secret is accepted", status == 200,
          f"{status} {payload}")
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D17 …and stored encrypted, decrypting back to the plaintext",
          config["enable_secret_enc"] is not None
          and dpapi_mod.unprotect(config["enable_secret_enc"]) == b"en4ble-1")

    status, _h, payload = req(
        "GET", f"/api/configrx/devices/{backup_device}", cookie=admin_cookie)
    device_json = payload["device"]
    check("D17 has_enable_secret reports existence only",
          device_json.get("has_enable_secret") is True, device_json)
    check("D17 …never the secret itself, in this or any other field",
          "en4ble-1" not in json.dumps(device_json), device_json)

    status, _h, payload = req(
        "POST", f"/api/configrx/devices/{backup_device}/credential",
        {"ssh_username": "netops", "ssh_password": "swpass3", "enable_secret": ""},
        cookie=admin_cookie)
    check("D17 an empty (present) enable_secret is accepted", status == 200,
          f"{status} {payload}")
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D17 …and clears the stored enable secret",
          config["enable_secret_enc"] is None)
    status, _h, payload = req(
        "GET", f"/api/configrx/devices/{backup_device}", cookie=admin_cookie)
    check("D17 …has_enable_secret now says so",
          payload["device"].get("has_enable_secret") is False, payload["device"])

    # Set both secrets again, then DELETE the credential and confirm BOTH
    # are gone — the actual fix this release made after the security review.
    status, _h, payload = req(
        "POST", f"/api/configrx/devices/{backup_device}/credential",
        {"ssh_username": "netops", "ssh_password": "swpass4",
         "enable_secret": "en4ble-2"}, cookie=admin_cookie)
    check("D17 setup: both secrets stored ahead of the clear", status == 200,
          f"{status} {payload}")
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D17 setup: enable_secret_enc is present before the clear",
          config["enable_secret_enc"] is not None)
    check("D17 setup: ssh_password_enc is present before the clear",
          config["ssh_password_enc"] is not None)

    status, _h, payload = req(
        "DELETE", f"/api/configrx/devices/{backup_device}/credential",
        {}, cookie=admin_cookie)
    check("D17 the clear-credential route succeeds", status == 200, f"{status} {payload}")
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D17 clear_credential clears the SSH password",
          config["ssh_password_enc"] is None)
    check("D17 …AND the enable secret, which used to survive it",
          config["enable_secret_enc"] is None)
    status, _h, payload = req(
        "GET", f"/api/configrx/devices/{backup_device}", cookie=admin_cookie)
    check("D17 …has_credential and has_enable_secret both go false",
          payload["device"].get("has_credential") is False
          and payload["device"].get("has_enable_secret") is False,
          payload["device"])

    # ------------------------------------------------- D18 /api/session version
    # The version now goes to the sign-in page (the unauthenticated branch)
    # as well as to a signed-in one, because the page that most needs to
    # show a build number is the one nobody has signed in to yet.
    print("/api/session version on both branches")
    from netpath import __version__ as app_version
    conn_anon = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    conn_anon.request("GET", "/api/session")
    resp = conn_anon.getresponse()
    anon_payload = json.loads(resp.read().decode("utf-8"))
    conn_anon.close()
    check("D18 an unauthenticated /api/session says so",
          anon_payload.get("authenticated") is False, anon_payload)
    check("D18 …and carries the running version",
          anon_payload.get("version") == app_version, anon_payload)
    check("D18 …and nothing else beyond authenticated/first_run/version",
          set(anon_payload) <= {"authenticated", "first_run", "version"},
          sorted(anon_payload))

    status, _h, auth_payload = req("GET", "/api/session", cookie=admin_cookie)
    check("D18 an authenticated /api/session also carries the version",
          status == 200 and auth_payload.get("version") == app_version,
          auth_payload)
    check("D18 …and is still authenticated", auth_payload.get("authenticated") is True,
          auth_payload)

    # ------------------------------------------- D19 the served vendor list
    # configrx.js used to carry its own hand-typed copy of the eleven keys
    # in configrx_vendors.VENDORS — a second copy of the hard safety
    # boundary of ConfigRX's backup path, free to drift from the table it
    # was supposed to mirror. /api/config now serves it instead, built from
    # VENDORS in its own iteration order, and it is one of the configrx
    # module's config keys so it is dropped for an account without ConfigRX
    # read, same as configrx_settings beside it.
    print("configrx_vendors served, not mirrored")
    from netpath import configrx_vendors

    status, _h, payload = req("GET", "/api/config", cookie=admin_cookie)
    served_vendors = payload.get("configrx_vendors")
    expected_vendors = [{"key": key, "label": vendor.label}
                        for key, vendor in configrx_vendors.VENDORS.items()]
    check("D19 the served list matches configrx_vendors.VENDORS exactly "
          "(same keys, same labels, same order)",
          served_vendors == expected_vendors,
          f"{served_vendors!r} != {expected_vendors!r}")
    # Proven non-vacuous: reordering VENDORS' first two entries, or
    # truncating the expected list to ten, both make the equality above
    # fail — checked by hand against a deliberately wrong expectation
    # before this assertion was written the right way; see the report.
    check("D19 …every entry carries only key and label, nothing a client "
          "has no business knowing (no command, no pager-off lines)",
          served_vendors is not None
          and all(set(entry) == {"key", "label"} for entry in served_vendors),
          served_vendors)
    check("D19 …all eleven vendor keys are present",
          served_vendors is not None
          and {entry["key"] for entry in served_vendors} == set(configrx_vendors.VENDORS),
          served_vendors)

    status, _h, payload = req("GET", "/api/config", cookie=debug_cookie)
    check("D19 an account with no ConfigRX grant gets no configrx_vendors "
          "key at all — absent, not an empty list",
          "configrx_vendors" not in payload, payload.get("configrx_vendors", "<absent>"))

    # ------------------------------- D20 the enable-secret-only delete route
    # Previously the only way to remove an enable secret was clear_credential
    # (DELETE .../credential), which took the SSH password with it — so
    # removing a secret that turned out not to be needed meant retyping the
    # switch's SSH password too. This route clears only enable_secret_enc.
    print("configrx enable-secret-only delete route")
    status, _h, payload = req(
        "POST", f"/api/configrx/devices/{backup_device}/credential",
        {"ssh_username": "netops", "ssh_password": "swpass5",
         "enable_secret": "en4ble-3"}, cookie=admin_cookie)
    check("D20 setup: both secrets stored", status == 200, f"{status} {payload}")
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D20 setup: enable_secret_enc is present before the narrow clear",
          config["enable_secret_enc"] is not None)
    check("D20 setup: ssh_password_enc is present before the narrow clear",
          config["ssh_password_enc"] is not None)

    status, _h, payload = req(
        "DELETE", f"/api/configrx/devices/{backup_device}/credential/enable-secret",
        {}, cookie=admin_cookie)
    check("D20 the narrow clear succeeds", status == 200, f"{status} {payload}")
    check("D20 …and the response never carries a secret",
          "ssh_password" not in payload and "enable_secret" not in payload
          and "ssh_password_enc" not in payload and "enable_secret_enc" not in payload,
          payload)
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D20 it clears enable_secret_enc",
          config["enable_secret_enc"] is None)
    # "Left intact" means the SSH password still round-trips, not merely
    # that the column is non-NULL: decrypt it back to the plaintext just
    # set above. Proven non-vacuous by pointing this same assertion at the
    # both-secrets route instead (DELETE .../credential) and watching it
    # fail — see the report.
    check("D20 …AND leaves ssh_password_enc intact, still decrypting to the "
          "password set above",
          config["ssh_password_enc"] is not None
          and dpapi_mod.unprotect(config["ssh_password_enc"]) == b"swpass5",
          config)
    check("D20 …and leaves ssh_username intact",
          config["ssh_username"] == "netops", config["ssh_username"])

    status, _h, payload = req(
        "GET", f"/api/configrx/devices/{backup_device}", cookie=admin_cookie)
    check("D20 has_credential stays true, has_enable_secret goes false",
          payload["device"].get("has_credential") is True
          and payload["device"].get("has_enable_secret") is False,
          payload["device"])

    status, _h, payload = req(
        "DELETE", f"/api/configrx/devices/{backup_device}/credential/enable-secret",
        {}, cookie=cx_reader)
    check("D20 a ConfigRX read-only account is refused (needs write)",
          status == 403, f"{status} {payload}")

    status, _h, payload = req(
        "DELETE", "/api/configrx/devices/999999/credential/enable-secret",
        {}, cookie=admin_cookie)
    check("D20 an unknown device id is a clean error, not a traceback",
          status == 400 and payload.get("error") != "Internal Server Error",
          f"{status} {payload}")

    # And the wide route beside it still does what D17 already pinned:
    # clears both secrets, not just the password — this narrower route must
    # not have quietly undone that.
    status, _h, payload = req(
        "POST", f"/api/configrx/devices/{backup_device}/credential",
        {"ssh_username": "netops", "ssh_password": "swpass6",
         "enable_secret": "en4ble-4"}, cookie=admin_cookie)
    check("D20 setup 2: both secrets stored again", status == 200, f"{status} {payload}")
    status, _h, payload = req(
        "DELETE", f"/api/configrx/devices/{backup_device}/credential",
        {}, cookie=admin_cookie)
    check("D20 …the wide route still clears the password too", status == 200,
          f"{status} {payload}")
    config = SERVICE.configrx_db.device_config(backup_device)
    check("D20 …confirmed: both secrets gone via the wide route",
          config["ssh_password_enc"] is None and config["enable_secret_enc"] is None,
          config)

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
