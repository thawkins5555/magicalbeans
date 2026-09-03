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
