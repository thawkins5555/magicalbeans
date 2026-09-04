"""Item 4: `/api/platform`'s `secret_store` flag, wired to the real
`netpath.dpapi.available()` instead of the hard-coded `False` it carried
before this change — see CREDENTIAL-SECURITY.md's "A gap this workstream
did not close" for the defect this closes.

Drives a real Service + WebServer against the *real* dpapi/secretstore
modules (not the reversible stand-in most other suites install — see
test_secretstore.py's own note on why) so the two passphrase sources this
suite toggles are the exact ones an operator would configure. Fixtures
(`reset`, `passphrase_file`, the throwaway salt path) mirror
test_secretstore.py's own — this is the second suite exercising the real
implementation, not a copy of its unit tests.
"""
import http.client
import json
import os

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

TMPDIR = _paths.tmpdir("platform_secret_store_")

import netpath.secretstore as ss  # noqa: E402
import netpath.dpapi as dpapi  # noqa: E402
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER  # noqa: E402
from netpath.web import Service, WebServer  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


_SALT_FILE = os.path.join(TMPDIR, "install.salt")
ss._salt_path = lambda: _SALT_FILE


def reset():
    os.environ.pop(ss.ENV_PASSPHRASE_FILE, None)
    os.environ.pop(ss.ENV_PASSPHRASE, None)
    ss._key_cache.clear()
    try:
        os.unlink(_SALT_FILE)
    except OSError:
        pass


def passphrase_file(text, mode=0o600):
    path = os.path.join(TMPDIR, "pass.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)
    return path


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
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=20)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    conn.request(method, path, body=json.dumps(body).encode() if body is not None else None,
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

    print("nothing configured")
    reset()
    status, payload = call("GET", "/api/platform", token=admin)
    check("/api/platform answers 200", status == 200, (status, payload))
    platform = payload.get("platform", {})
    check("secret_store agrees with the real dpapi.available() (nothing configured)",
          platform.get("secret_store") is bool(dpapi.available()),
          (platform.get("secret_store"), dpapi.available()))
    if os.name != "nt":
        check("...which is False off Windows with no passphrase source",
              platform.get("secret_store") is False, platform)
        check("credential_store is None off Windows with nothing configured",
              platform.get("credential_store") is None, platform)

    if os.name != "nt":
        print("a passphrase FILE configured")
        path = passphrase_file("api-platform-suite passphrase, not typed anywhere else\n")
        os.environ[ss.ENV_PASSPHRASE_FILE] = path
        status, payload = call("GET", "/api/platform", token=admin)
        platform = payload.get("platform", {})
        check("secret_store is True once NETPATH_SECRET_PASSPHRASE_FILE is set",
              platform.get("secret_store") is True, platform)
        check("credential_store now names the portable store",
              platform.get("credential_store") == "Portable secret store", platform)

        print("a passphrase in the environment directly")
        reset()
        os.environ[ss.ENV_PASSPHRASE] = "api-platform-suite env passphrase"
        status, payload = call("GET", "/api/platform", token=admin)
        platform = payload.get("platform", {})
        check("secret_store is True with NETPATH_SECRET_PASSPHRASE alone too",
              platform.get("secret_store") is True, platform)

        print("removed again")
        reset()
        status, payload = call("GET", "/api/platform", token=admin)
        platform = payload.get("platform", {})
        check("secret_store goes back to False once the passphrase is removed",
              platform.get("secret_store") is False, platform)

        # The endpoint calls dpapi.available() fresh on every request (see
        # get_platform's own comment) rather than caching an answer from
        # process start-up — this is the behaviour CREDENTIAL-SECURITY.md
        # said the API layer already had while the flag stayed hard-coded;
        # confirming it stays true now that the flag reflects reality.
        print("credential routes already agreed with dpapi.available() before this fix")
        status, server_row = call("POST", "/api/ipam/dhcp/servers",
                                  {"address": "10.91.0.9", "label": "platform-suite"},
                                  token=admin)
        check("setup: a DHCP server can be created", status == 200, (status, server_row))
        status, refused = call(
            "POST", f"/api/ipam/dhcp/servers/{server_row['id']}/credential",
            {"username": "svc", "password": "whatever"}, token=admin)
        check("no passphrase configured: the credential route itself still refuses",
              status != 200, (status, refused))
        os.environ[ss.ENV_PASSPHRASE] = "api-platform-suite second passphrase"
        status, accepted = call(
            "POST", f"/api/ipam/dhcp/servers/{server_row['id']}/credential",
            {"username": "svc", "password": "whatever"}, token=admin)
        check("passphrase configured: the same credential route now accepts it",
              status == 200, (status, accepted))
        status, payload = call("GET", "/api/platform", token=admin)
        check("...and /api/platform's flag agrees with that at the same moment",
              payload["platform"]["secret_store"] is True, payload)
    else:
        print("      note: skipping the passphrase toggles -- this host IS "
              "Windows, where dpapi.available() is unconditionally True and "
              "the portable store is never consulted.")

finally:
    reset()
    server.stop()
    service.shutdown()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
