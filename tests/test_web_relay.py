"""The WEB button's device relay end to end: a real Service, a real
WebServer, and a stub "device" web server on loopback.

Proves what the relay promises. Bytes arrive at the device unaltered and come
back the same way; the destination comes from the device row and cannot be
named by the caller; the listening port admits one address; the relay closes
on idle, on nobody connecting, on sign-out and when the permission goes away;
the caps and the port range refuse rather than fail; another account cannot
close your tunnel; and every open and close leaves a device event and an
audit row carrying byte counts and no content.

Everything binds 127.0.0.1, which is what keeps Windows Firewall out of it.
"""
import http.client
import http.server
import json
import os
import socket
import threading
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("web_relay_")

from netpath import permissions, webrelay
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer

failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label
          + (f"  {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)


# ------------------------------------------------------------ a device, sort of

BODY = (b"<html><body>SappiWhere stub device management page. "
        + b"x" * 5000 + b"</body></html>")


class StubDeviceHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):                                     # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("X-Stub-Path", self.path)
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):                         # keep the run quiet
        pass


stub = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StubDeviceHandler)
stub.daemon_threads = True
stub_port = stub.server_address[1]
threading.Thread(target=stub.serve_forever, daemon=True).start()
print(f"stub device on 127.0.0.1:{stub_port}")

# ------------------------------------------------------------------- the app

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()
# Relays follow the UI's own bind address (webrelay.relay_bind_host), so
# pinning the UI here is what keeps every relay on loopback — and a loopback
# bind is the one Windows Firewall does not prompt for. The range is left
# ephemeral except in the exhaustion section, which sets its own.
service.settings["web_host"] = "127.0.0.1"
service.settings["web_relay_port_range"] = "0"

web_port = free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port,
                   certfile=None, keyfile=None)
assert server.start(block=False), server.error
print(f"server up on 127.0.0.1:{web_port}")

ADMIN_PASSWORD = "RelaySuiteAdmin2026"


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=15)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Cookie"] = f"sw_session={token}"
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    raw = response.read()
    status = response.status
    cookie = dict(response.getheaders()).get("Set-Cookie", "")
    conn.close()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    return status, payload, cookie


def login(username, password):
    row = service.app_db.user(username)
    if row is not None and row["must_change"]:
        service.app_db.set_password(username, row["password"], must_change=False)
    status, payload, cookie = call(
        "POST", "/api/login", {"username": username, "password": password})
    assert status == 200, (status, payload)
    return cookie.split("sw_session=")[1].split(";")[0]


def make_user(username, grants, password="RelaySuiteUser2026"):
    from netpath.auth import hash_password
    service.app_db.add_user(username, hash_password(password), must_change=False)
    service.app_db.set_permissions(username, grants)
    return login(username, password)


def fetch_through(port, path="/", timeout=15.0):
    """One raw HTTP/1.1 GET straight at a relay port, read to EOF. Deliberately
    not http.client: what is under test is that the bytes cross unaltered, so
    the test writes the request itself."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                     f"Connection: close\r\n\r\n".encode("ascii"))
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def wait_until(predicate, seconds):
    """True as soon as `predicate` holds, False when `seconds` run out. Every
    caller passes twice the patched constant it is waiting on, so a loaded
    machine does not fail a timing assertion that is really about ordering."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


device_id = None
try:
    token = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # ------------------------------------------------- the device's web fields
    print("device web fields")
    status, payload, _ = call("POST", "/api/nodes/devices",
                              {"ip": "127.0.0.1", "name": "stub-device",
                               "web_scheme": "http", "web_port": stub_port},
                              token=token)
    check("a device can be added with its web scheme and port", status == 200,
          (status, payload))
    device_id = payload.get("id")

    status, payload, _ = call("GET", f"/api/nodes/devices/{device_id}", token=token)
    device_json = payload.get("device", payload)
    check("the fields round-trip through the device JSON",
          device_json.get("web_scheme") == "http"
          and device_json.get("web_port") == stub_port,
          device_json)
    check("and the JSON says which port the relay will dial",
          device_json.get("web_port_effective") == stub_port,
          device_json.get("web_port_effective"))

    for bad in (0, 70000, "ftp"):
        field = "web_scheme" if bad == "ftp" else "web_port"
        # 0 is the one that is not a refusal: it is how a form clears the
        # override and puts the device back on its scheme's default port.
        status, payload, _ = call("PUT", f"/api/nodes/devices/{device_id}",
                                  {field: bad}, token=token)
        expected = 200 if bad == 0 else 400
        check(f"{field}={bad!r} is answered {expected}", status == expected,
              (status, payload))
    status, _payload, _ = call("PUT", f"/api/nodes/devices/{device_id}",
                               {"web_port": stub_port}, token=token)
    assert status == 200

    # ---------------------------------------------------------- opening one
    print("opening a relay")
    status, relay, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                            {}, token=token)
    check("POST /api/web/devices/<id>/relay is answered 200", status == 200,
          (status, relay))
    check("its URL names the host the browser reached this server on",
          str(relay.get("url", "")).startswith(f"http://127.0.0.1:"), relay.get("url"))
    check("the session id starts with 'r', so _route cannot turn it into an int",
          str(relay.get("session_id", "")).startswith("r"), relay.get("session_id"))
    check("the relay names the device's port, not the browser's",
          relay.get("device_port") == stub_port, relay.get("device_port"))
    check("and the one address it will admit",
          relay.get("client_ip") == "127.0.0.1", relay.get("client_ip"))
    relay_port = relay["port"]
    check("the URL's port is the relay's port",
          f":{relay_port}/" in relay["url"], relay["url"])

    # ------------------------------------------------------ bytes across it
    print("carrying bytes")
    answer = fetch_through(relay_port)
    check("a GET through the relay comes back byte for byte",
          BODY in answer and b"200 OK" in answer.split(b"\r\n")[0],
          answer[:80])
    check("and the device saw the path it was sent",
          b"X-Stub-Path: /" in answer, answer[:200])

    results = {}

    def concurrent(index):
        try:
            results[index] = fetch_through(relay_port, f"/page-{index}")
        except Exception as exc:                          # recorded, not raised
            results[index] = repr(exc).encode()

    threads = [threading.Thread(target=concurrent, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    check("six connections at once are all answered in full",
          len(results) == 6 and all(BODY in body for body in results.values()),
          {i: body[:60] for i, body in results.items()})
    check("each one reached its own path",
          all(f"X-Stub-Path: /page-{i}".encode() in body
              for i, body in results.items()))

    live = service.web_relays.get(relay["session_id"])
    check("the byte counters moved in both directions",
          live is not None and live.info()["bytes_to_device"] > 0
          and live.info()["bytes_from_device"] > len(BODY),
          live.info() if live else None)

    # ------------------------------------------------------------- listing
    status, payload, _ = call("GET", "/api/web/relays", token=token)
    check("GET /api/web/relays lists it", status == 200
          and any(row["session_id"] == relay["session_id"]
                  for row in payload.get("relays", [])),
          (status, payload))

    # ------------------------------------------------------- who is admitted
    print("the address gate")
    check("_admit takes the operator's own address",
          live._admit(("127.0.0.1", 51000)))
    check("_admit takes it through an IPv4-mapped IPv6 peer, like every other "
          "allow list here", live._admit(("::ffff:127.0.0.1", 51000)))
    check("_admit refuses any other address",
          not live._admit(("10.4.4.4", 51000)))
    before = len([row for row in service.nodes_db.device_events(
        device_id=device_id, kinds=["web"]) if "refused" in row["detail"]])
    live._audit_refusal(("10.4.4.4", 51000))
    live._audit_refusal(("10.4.4.5", 51000))
    after = [row for row in service.nodes_db.device_events(
        device_id=device_id, kinds=["web"]) if "refused" in row["detail"]]
    check("a refused source is audited once per relay, not once per attempt",
          len(after) - before == 1, [row["detail"] for row in after])

    # ------------------------------------------------------------- closing
    print("closing")
    status, payload, _ = call(
        "DELETE", f"/api/web/relays/{relay['session_id']}", {}, token=token)
    check("DELETE closes it", status == 200, (status, payload))
    check("and it is gone from the registry",
          service.web_relays.get(relay["session_id"]) is None)
    refused = None
    try:
        fetch_through(relay_port, timeout=3)
    except OSError as exc:
        refused = exc
    check("the port stops answering", refused is not None, refused)

    events = [row["detail"] for row in service.nodes_db.device_events(
        device_id=device_id, kinds=["web"])]
    check("the device's own event list carries the open and the close",
          any("opened" in detail for detail in events)
          and any("closed" in detail for detail in events), events)
    check("the close event carries byte counts and no content",
          any("bytes to the device" in detail for detail in events)
          and not any(b"SappiWhere stub" in detail.encode() for detail in events),
          events)

    # ----------------------------------------------------------- the audit log
    status, payload, _ = call("GET", "/api/audit?limit=500", token=token)
    actions = [row.get("action") for row in payload.get("events", [])]
    check("web.relay.open and web.relay.close are both in the audit log",
          "web.relay.open" in actions and "web.relay.close" in actions,
          sorted(set(a for a in actions if a and a.startswith("web."))))

    # ------------------------------------------------------------- the caps
    print("the caps")
    saved = (webrelay.MAX_SESSIONS, webrelay.MAX_SESSIONS_PER_USER)
    webrelay.MAX_SESSIONS_PER_USER = 2
    opened = []
    for _ in range(2):
        status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                                  {}, token=token)
        assert status == 200, (status, payload)
        opened.append(payload["session_id"])
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=token)
    check("a third relay for one account is refused 400", status == 400,
          (status, payload))
    check("and the refusal says which cap was reached",
          "2 web tunnels" in str(payload.get("error", "")), payload)

    webrelay.MAX_SESSIONS_PER_USER = 8
    webrelay.MAX_SESSIONS = len(opened)
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=token)
    check("the application-wide cap is refused 400 too", status == 400,
          (status, payload))
    webrelay.MAX_SESSIONS, webrelay.MAX_SESSIONS_PER_USER = saved
    for session_id in opened:
        service.web_relays.close(session_id, "test teardown")

    # --------------------------------------------------- a spent port range
    print("a spent port range")
    single = free_tcp_port()
    service.settings["web_relay_port_range"] = f"{single}-{single}"
    status, first, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                            {}, token=token)
    check("a one-port range still opens the first relay",
          status == 200 and first.get("port") == single, (status, first))
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=token)
    check("and refuses the second with 400, naming the range", status == 400
          and str(single) in str(payload.get("error", "")), (status, payload))
    service.web_relays.close(first["session_id"], "test teardown")
    service.settings["web_relay_port_range"] = "0"

    # -------------------------------------------------- what closes a relay
    print("what closes a relay")
    saved_window = webrelay.FIRST_CONNECT_WINDOW_S
    webrelay.FIRST_CONNECT_WINDOW_S = 1
    status, unused, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=token)
    assert status == 200, (status, unused)
    check("a relay nobody connects to closes inside its first-connect window",
          wait_until(lambda: service.web_relays.get(unused["session_id"]) is None,
                     2 * webrelay.FIRST_CONNECT_WINDOW_S + 2))
    webrelay.FIRST_CONNECT_WINDOW_S = saved_window

    saved_idle = webrelay.IDLE_TIMEOUT_S
    webrelay.IDLE_TIMEOUT_S = 1
    status, idler, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                            {}, token=token)
    assert status == 200, (status, idler)
    fetch_through(idler["port"])                 # so the idle clock, not the
    check("a relay with no traffic closes on the idle timeout",  # window, applies
          wait_until(lambda: service.web_relays.get(idler["session_id"]) is None,
                     2 * webrelay.IDLE_TIMEOUT_S + 3))
    webrelay.IDLE_TIMEOUT_S = saved_idle

    saved_ticks = webrelay.PERMISSION_EVERY_TICKS
    webrelay.PERMISSION_EVERY_TICKS = 1
    revoked_token = make_user("revokee", {"nodes": "read", "web": "write"})
    status, doomed, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=revoked_token)
    check("an account holding web:write can open one", status == 200,
          (status, doomed))
    service.app_db.set_permissions("revokee", {"nodes": "read"})
    check("revoking the permission closes the relay within a few ticks",
          wait_until(lambda: service.web_relays.get(doomed["session_id"]) is None,
                     2 * webrelay.PERMISSION_EVERY_TICKS + 4))
    webrelay.PERMISSION_EVERY_TICKS = saved_ticks

    signed_out = make_user("signout", {"nodes": "read", "web": "write"})
    status, orphan, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=signed_out)
    assert status == 200, (status, orphan)
    call("POST", "/api/logout", {}, token=signed_out)
    check("signing out takes the relay with it",
          wait_until(lambda: service.web_relays.get(orphan["session_id"]) is None, 6))

    # -------------------------------------------------------------- the gates
    print("the gates")
    nodes_only = make_user("nodesonly", {"nodes": "write"})
    status, payload, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                              {}, token=nodes_only)
    check("nodes:write with no web grant is refused 403", status == 403,
          (status, payload))
    status, payload, _ = call("GET", "/api/web/relays", token=nodes_only)
    check("and cannot list relays either", status == 403, (status, payload))

    other = make_user("otherweb", {"nodes": "read", "web": "write"})
    status, theirs, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                             {}, token=other)
    assert status == 200, (status, theirs)
    intruder = make_user("intruder", {"nodes": "read", "web": "write"})
    status, payload, _ = call(
        "DELETE", f"/api/web/relays/{theirs['session_id']}", {}, token=intruder)
    check("another account's DELETE is refused 403", status == 403,
          (status, payload))
    check("and the relay is still open",
          service.web_relays.get(theirs["session_id"]) is not None)
    status, payload, _ = call("GET", "/api/web/relays", token=intruder)
    check("a non-administrator's list shows only their own relays",
          all(row["username"] == "intruder"
              for row in payload.get("relays", [])), payload)
    status, payload, _ = call(
        "DELETE", f"/api/web/relays/{theirs['session_id']}", {}, token=token)
    check("an administrator may close it", status == 200, (status, payload))

    # --------------------------------------------------------------- shutdown
    print("shutdown")
    status, lingering, _ = call("POST", f"/api/web/devices/{device_id}/relay",
                                {}, token=token)
    assert status == 200, (status, lingering)
    held = socket.create_connection(("127.0.0.1", lingering["port"]), timeout=10)
    held.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    held.recv(64)                       # a connection still open and idle
    started = time.time()
    service.web_relays.shutdown()
    elapsed = time.time() - started
    check("shutdown() ends every relay inside its budget",
          elapsed <= 2 * webrelay.SHUTDOWN_BUDGET_S and service.web_relays.count == 0,
          f"{elapsed:.2f}s, {service.web_relays.count} left")
    try:
        held.close()
    except OSError:
        pass

    print("FAILED: " + ", ".join(failures) if failures
          else "ALL WEB RELAY ASSERTIONS PASSED")
finally:
    server.stop()
    stub.shutdown()
    service.shutdown()

if failures:
    raise SystemExit(1)
