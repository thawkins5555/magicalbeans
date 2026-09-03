"""The SSH terminal end to end: the real web server, the real session
registry, a real paramiko device.

Everything here is in one process on loopback — there is no `ssh` binary in
this environment and never will be, so the device is `tests/stubs/
stub_ssh_device.py`, a paramiko server, and the browser is the small
WebSocket client below. What is being proved is the protocol the terminal
page depends on: the upgrade goes through the same permission gate as any
other route, an open message reaches a shell, keystrokes arrive at the
device, output comes back as binary frames, a device with no stored
credential asks for one, and the session's limits and audit trail hold.

DPAPI is monkeypatched before anything imports it, exactly as the ConfigRX
suites do: this is not Windows, and what is under test is the plumbing
around the credential, not the encryption of it."""
import base64
import http.client
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("ssh_terminal_")

import netpath.dpapi as dpapi_mod
dpapi_mod.available = lambda: True
dpapi_mod.protect = lambda p: b"FAKE:" + p
dpapi_mod.unprotect = lambda c: bytes(c)[5:]

try:
    import paramiko
except ImportError:                       # run_all.py reports this as SKIP
    print("SKIP: paramiko is not installed, so there is nothing to speak SSH to")
    raise SystemExit(77)

from netpath import sshterm
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER
from netpath.web import Service, WebServer, wsock
from stubs.stub_ssh_device import StubDevice

PASSWORD = "stub-secret"


# --------------------------------------------------------- a browser, sort of

class WsClient:
    """A WebSocket client in a hundred lines of standard library: the
    handshake, masked client frames, unmasked server frames. Deliberately
    not built on wsock's reading side — the test speaks the wire format, so
    a bug in wsock cannot cancel itself out."""

    def __init__(self, port: int, path: str, token: str, timeout: float = 20.0,
                 origin: str | None = None, tls: bool = False,
                 pipeline: bytes = b""):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        if tls:
            # A self-signed certificate on loopback: what is under test is
            # that one TLS socket survives being read and written at once,
            # not who signed it.
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(self.sock)
        self.key = base64.b64encode(os.urandom(16)).decode("ascii")
        # A browser always sends Origin on an upgrade and the server refuses
        # a socket without one, so this is the default; `origin=""` leaves
        # the header out and any other string sends that instead.
        if origin is None:
            origin = f"{'https' if tls else 'http'}://127.0.0.1:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            + (f"Origin: {origin}\r\n" if origin else "")
            + f"Cookie: sw_session={token}\r\n"
            "\r\n")
        # `pipeline` rides out with the handshake, so those frames are
        # already in the server's HTTP read buffer when the upgrade is
        # answered — the case the transport has to drain rather than lose.
        self.sock.sendall(request.encode("ascii") + pipeline)
        self.rfile = self.sock.makefile("rb", -1)
        self.status, self.headers, self.body = self._read_response()
        self.close_code = None
        self.close_reason = ""
        self.output = b""

    def _read_response(self):
        line = self.rfile.readline().decode("latin-1").strip()
        status = int(line.split()[1])
        headers = {}
        while True:
            raw = self.rfile.readline().decode("latin-1").strip()
            if not raw:
                break
            name, _, value = raw.partition(":")
            headers[name.strip().lower()] = value.strip()
        body = b""
        if status != 101:
            length = int(headers.get("content-length", 0) or 0)
            body = self.rfile.read(length) if length else b""
        return status, headers, body

    @property
    def upgraded(self) -> bool:
        if self.status != 101:
            return False
        import hashlib
        expect = base64.b64encode(hashlib.sha1(
            (self.key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        ).digest()).decode()
        return self.headers.get("sec-websocket-accept") == expect

    # ------------------------------------------------------------- frames

    def send_json(self, payload: dict) -> None:
        self.sock.sendall(wsock.client_frame(
            wsock.OP_TEXT, json.dumps(payload).encode("utf-8")))

    def send_binary(self, data: bytes) -> None:
        self.sock.sendall(wsock.client_frame(wsock.OP_BINARY, data))

    def _frame(self):
        head = self.rfile.read(2)
        if not head or len(head) < 2:
            return None
        opcode = head[0] & 0x0F
        length = head[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.rfile.read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.rfile.read(8))[0]
        payload = self.rfile.read(length) if length else b""
        return opcode, payload

    def next_control(self, wanted: str = "", timeout: float = 20.0) -> dict | None:
        """The next JSON message (optionally, the next one of a given type).
        Binary frames are terminal output and pile up in `self.output`."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            frame = self._frame()
            if frame is None:
                return None
            opcode, payload = frame
            if opcode == wsock.OP_BINARY:
                self.output += payload
                continue
            if opcode == wsock.OP_CLOSE:
                if len(payload) >= 2:
                    self.close_code = struct.unpack("!H", payload[:2])[0]
                    self.close_reason = payload[2:].decode("utf-8", "replace")
                return None
            if opcode != wsock.OP_TEXT:
                continue
            message = json.loads(payload.decode("utf-8"))
            if not wanted or message.get("type") == wanted:
                return message
        raise AssertionError(f"no {wanted or 'control'} message within {timeout}s")

    def read_until(self, marker: bytes, timeout: float = 20.0) -> bytes:
        deadline = time.time() + timeout
        while marker not in self.output and time.time() < deadline:
            frame = self._frame()
            if frame is None:
                break
            opcode, payload = frame
            if opcode == wsock.OP_BINARY:
                self.output += payload
            elif opcode == wsock.OP_CLOSE:
                break
        assert marker in self.output, \
            f"{marker!r} never arrived; got {self.output[-300:]!r}"
        return self.output

    def wait_closed(self, timeout: float = 20.0) -> int | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            frame = self._frame()
            if frame is None:
                return self.close_code
            opcode, payload = frame
            if opcode == wsock.OP_BINARY:
                self.output += payload
            elif opcode == wsock.OP_CLOSE:
                if len(payload) >= 2:
                    self.close_code = struct.unpack("!H", payload[:2])[0]
                    self.close_reason = payload[2:].decode("utf-8", "replace")
                return self.close_code
        raise AssertionError(f"the socket did not close within {timeout}s")

    def close(self) -> None:
        try:
            self.sock.sendall(wsock.client_frame(
                wsock.OP_CLOSE, struct.pack("!H", 1000)))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def until_connected(client, timeout: float = 30.0) -> list:
    """Every control message up to and including `status connected`. The
    order is status(connecting) → hostkey (only when there is something to
    say about it) → status(connected)."""
    seen = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        message = client.next_control(timeout=timeout)
        assert message is not None, seen
        assert message.get("type") != "error", message
        seen.append(message)
        if message.get("type") == "status" and message.get("state") == "connected":
            return seen
    raise AssertionError(f"never reached 'connected': {seen}")


def wait_idle(timeout: float = 10.0) -> None:
    """Wait for the registry to be empty again. A client's close() returns
    as soon as its own frame is on the wire; the server thread lets its
    session go a moment later, and a cap counted before that is a cap
    already spent."""
    deadline = time.time() + timeout
    while time.time() < deadline and service.ssh_sessions.count:
        time.sleep(0.05)
    assert service.ssh_sessions.count == 0, service.ssh_sessions.count


# -------------------------------------------------------------- the service

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))

web_port = free_tcp_port()
server = WebServer(service, host="127.0.0.1", port=web_port, certfile=None, keyfile=None)
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


def login(username, password) -> str:
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


device = None
plain_device = None
try:
    token = login(DEFAULT_USER, DEFAULT_PASSWORD)

    # The default admin was seeded with every module, so it has ssh; the
    # backfill's other half (an upgrading install) is checked further down.
    grants = service.app_db.permissions_for(DEFAULT_USER)
    assert grants.get("ssh") == "write", grants
    print("PASS: the seeded administrator holds ssh write")

    stub = StubDevice(mode="slow", pause_s=0.05)
    group_id = service.nodes_db.ensure_default_group()
    device = service.nodes_db.add_device("127.0.0.1", name="stub-switch",
                                         group_id=group_id)
    service.configrx_db.update_device_config(device, ssh_port=stub.port,
                                             ssh_username="operator")
    service.configrx_db.set_credential(device, "operator",
                                       dpapi_mod.protect(PASSWORD.encode()))

    # -------------------------------------------------- the page's own GET

    status, payload = call("GET", f"/api/ssh/devices/{device}", token=token)
    assert status == 200, (status, payload)
    assert payload["device"]["ip"] == "127.0.0.1", payload
    assert payload["has_credential"] is True, payload
    assert payload["ssh_port"] == stub.port, payload
    assert payload["paramiko"]["available"] is True, payload
    assert payload["host_key"] is None, payload
    assert payload["device"] == {"id": device, "ip": "127.0.0.1",
                                 "name": "stub-switch"}, payload
    assert "ssh_username" not in payload, payload
    print("PASS: GET /api/ssh/devices/<id> describes the device, its credential "
          "and (not yet) its host key")
    print("PASS: it names the device once — no SSH username, and no fields for "
          "the page to recompute the name from")

    # ------------------------------------------------------ the permission

    status, payload = call("POST", "/api/users",
                           {"username": "viewer", "password": "Corr3ct-Horse-Battery",
                            "grants": {"nodes": "read", "configrx": "write"}},
                           token=token)
    assert status == 200, (status, payload)
    viewer_token = login("viewer", "Corr3ct-Horse-Battery")
    status, payload = call("GET", f"/api/ssh/devices/{device}", token=viewer_token)
    assert status == 403, (status, payload)
    refused = WsClient(web_port, f"/api/ssh/devices/{device}/socket", viewer_token)
    assert refused.status == 403, (refused.status, refused.body)
    assert not refused.upgraded
    refused.close()
    print("PASS: an account without ssh gets 403 on both routes — the upgrade "
          "is refused before the hijack, as an ordinary HTTP response")

    anonymous = WsClient(web_port, f"/api/ssh/devices/{device}/socket", "")
    assert anonymous.status == 401, (anonymous.status, anonymous.body)
    anonymous.close()
    print("PASS: an unsigned-in socket request is 401, not an upgrade")

    # The cookie is SameSite=Strict, which is site-scoped: another port on
    # this host counts as the same site and would carry the cookie. Origin
    # is what tells the two apart, and a browser always sends it here.
    for bad_origin, why in (
            (f"http://127.0.0.1:{web_port + 1}", "another port on this host"),
            ("http://evil.example", "a different site"),
            ("", "no Origin header at all")):
        refused = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token,
                           origin=bad_origin)
        assert refused.status == 403, (why, refused.status, refused.body)
        assert not refused.upgraded, why
        assert b"Cross-origin" in refused.body, (why, refused.body)
        refused.close()
    print("PASS: an upgrade from another origin — or with no Origin — is 403, "
          "before any hijack")

    # ------------------------------------------------------ a real session

    ws = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
    assert ws.upgraded, (ws.status, ws.headers)
    print("PASS: the socket route answers 101 with a valid accept digest")

    ws.send_json({"type": "open", "cols": 100, "rows": 30})
    seen = until_connected(ws)
    assert seen[0] == {"type": "status", "state": "connecting",
                       "message": seen[0]["message"]}, seen
    keys = [m for m in seen if m["type"] == "hostkey"]
    assert len(keys) == 1 and keys[0]["event"] == "new", seen
    assert keys[0]["fingerprint"].startswith("SHA256:"), keys[0]
    first_fingerprint = keys[0]["fingerprint"]
    print("PASS: the first connection stores the device's host key and says so")
    print("PASS: the session reaches 'connected' using ConfigRX's stored credential")

    ws.read_until(b"stub-switch#")
    print("PASS: the device's banner and prompt arrive as binary frames")

    ws.send_binary(b"show ver\n")
    ws.read_until(b"version 15.2")
    typed = b"".join(stub.sent_bytes)
    assert b"show ver\n" in typed or b"show ver\r" in typed, typed[-80:]
    print("PASS: keystrokes reach the device and its output comes back")

    ws.send_json({"type": "resize", "cols": 120, "rows": 40})
    ws.send_binary(b"terminal length 0\n")
    ws.read_until(b"terminal length 0")
    print("PASS: a resize does not disturb the session")

    events = service.nodes_db.device_events(device, kinds=["ssh"])
    opened = [e for e in events if "opened" in e["detail"]]
    assert opened, [dict(e) for e in events]
    assert DEFAULT_USER in opened[0]["detail"] and "127.0.0.1" in opened[0]["detail"], \
        opened[0]["detail"]
    assert PASSWORD not in opened[0]["detail"] and "show ver" not in opened[0]["detail"]
    print("PASS: opening the session is audited as a device event naming the "
          "user and the client, and nothing else")

    ws.close()
    deadline = time.time() + 10
    while time.time() < deadline and service.ssh_sessions.count:
        time.sleep(0.05)
    assert service.ssh_sessions.count == 0, service.ssh_sessions.count
    closed = [e for e in service.nodes_db.device_events(device, kinds=["ssh"])
              if "closed after" in e["detail"]]
    assert closed, [dict(e) for e in service.nodes_db.device_events(device, kinds=["ssh"])]
    print("PASS: closing the socket ends the session and is audited with its "
          "duration")

    # A second connection to the same device is not a first sighting.
    status, payload = call("GET", f"/api/ssh/devices/{device}", token=token)
    assert payload["host_key"], payload
    assert payload["host_key"]["fingerprint"] == first_fingerprint, payload
    seen_before = service.configrx_db.host_key("127.0.0.1", stub.port)["last_seen_ts"]
    ws = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
    ws.send_json({"type": "open", "cols": 80, "rows": 24})
    seen = until_connected(ws)
    assert not [m for m in seen if m["type"] == "hostkey"], seen
    print("PASS: a second connection to a known host key reports no hostkey "
          "event, and the page's GET shows the stored fingerprint")
    ws.close()

    # And the sighting is recorded: last_seen_ts is the only thing that says
    # a remembered key is still in use rather than left over from a device
    # that has gone. A terminal is a sighting exactly as a backup is.
    seen_after = service.configrx_db.host_key("127.0.0.1", stub.port)["last_seen_ts"]
    assert seen_after > seen_before, (seen_before, seen_after)
    print("PASS: connecting again advances the host key's last-seen time, so a "
          "device that is only ever SSHed to does not look unconfirmed")

    # -------------------------------------------------- a changed host key

    # The same address and port, a different identity: the device was
    # replaced, or something is sitting in front of it. Either way the
    # connection is refused until a person says otherwise.
    stub.close()
    new_key = paramiko.RSAKey.generate(2048)
    replacement = None
    for _attempt in range(50):
        try:
            replacement = StubDevice(mode="slow", pause_s=0.05, port=stub.port,
                                     host_key=new_key)
            break
        except OSError:            # the kernel has not released the port yet
            time.sleep(0.2)
    assert replacement is not None, "could not restart the stub on its own port"
    ws = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
    ws.send_json({"type": "open", "cols": 80, "rows": 24})
    message = ws.next_control("hostkey")
    assert message["event"] == "changed", message
    assert message["old_fingerprint"] == first_fingerprint, message
    assert message["fingerprint"] != first_fingerprint, message
    assert message["fingerprint"].startswith("SHA256:"), message
    print("PASS: a changed host key refuses the connection and names both "
          "fingerprints")

    ws.send_json({"type": "trust"})
    until_connected(ws)
    print("PASS: 'trust' replaces the stored key and reconnects, without "
          "asking for the password again")
    ws.close()

    status, payload = call("GET", f"/api/ssh/devices/{device}", token=token)
    assert payload["host_key"]["fingerprint"] != first_fingerprint, payload
    trusted = [e for e in service.nodes_db.device_events(device, kinds=["ssh"])
               if "host key replaced" in e["detail"]]
    assert trusted and DEFAULT_USER in trusted[0]["detail"], \
        [dict(e) for e in service.nodes_db.device_events(device, kinds=["ssh"])]
    print("PASS: trusting a new host key is audited as a device event")

    # ------------------------------------------- a device with no credential

    # Its own listener, on another loopback address, because the device row
    # is keyed by IP and this one must not have ConfigRX's credential.
    stub2 = StubDevice(mode="slow", pause_s=0.05, host="127.0.0.2")
    plain_device = service.nodes_db.add_device("127.0.0.2", name="no-credential",
                                               group_id=group_id)
    service.configrx_db.update_device_config(plain_device, ssh_port=stub2.port)
    status, payload = call("GET", f"/api/ssh/devices/{plain_device}", token=token)
    assert payload["has_credential"] is False, payload

    ws = WsClient(web_port, f"/api/ssh/devices/{plain_device}/socket", token)
    ws.send_json({"type": "open", "cols": 80, "rows": 24})
    message = ws.next_control()
    assert message["type"] == "need-credentials", message
    assert message["reason"] == "none-stored", message
    print("PASS: a device with no stored credential asks the page for one")

    ws.send_json({"type": "auth", "username": "typed-in", "password": "typed"})
    until_connected(ws)
    ws.read_until(b"stub-switch#")
    print("PASS: credentials typed into the page open the session")

    for event in service.nodes_db.device_events(plain_device, kinds=["ssh"]):
        assert "typed" not in event["detail"], event["detail"]
    print("PASS: the typed password appears in no device event")
    ws.close()

    # --------------------------------------------------------- the limits

    # ws.close() returns as soon as the client's close frame is on the wire;
    # the server thread releases its session a moment later. Wait for that,
    # or a cap of one is already spent on the session that is still going.
    for _ in range(200):
        if service.ssh_sessions.count == 0:
            break
        time.sleep(0.05)
    assert service.ssh_sessions.count == 0, service.ssh_sessions.count

    original_max = sshterm.MAX_SESSIONS
    sshterm.MAX_SESSIONS = 1
    try:
        first = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        first.send_json({"type": "open", "cols": 80, "rows": 24})
        until_connected(first)
        second = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        second.send_json({"type": "open", "cols": 80, "rows": 24})
        message = second.next_control("error")
        assert "already 1 SSH sessions" in message["message"], message
        assert second.wait_closed(10) == 4429, second.close_code
        print("PASS: past the concurrent-session cap the socket closes with 4429")
        second.close()
        first.close()
    finally:
        sshterm.MAX_SESSIONS = original_max

    deadline = time.time() + 10
    while time.time() < deadline and service.ssh_sessions.count:
        time.sleep(0.05)

    original_idle = sshterm.IDLE_TIMEOUT_S
    sshterm.IDLE_TIMEOUT_S = 2
    try:
        idle = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        idle.send_json({"type": "open", "cols": 80, "rows": 24})
        until_connected(idle)
        assert idle.wait_closed(30) == 4408, idle.close_code
        print("PASS: a session with no keystrokes is closed with 4408 once the "
              "idle timeout passes")
        idle.close()
        wait_idle()

        # Frames are not presence; keystrokes are. A page on a second
        # monitor that a window manager nudges sends `resize` and nothing
        # else, and that must not keep a root shell on a core switch alive.
        nudged = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        nudged.send_json({"type": "open", "cols": 80, "rows": 24})
        until_connected(nudged)
        stop_nudging = threading.Event()

        def nudge():
            while not stop_nudging.wait(0.4):
                try:
                    nudged.send_json({"type": "resize", "cols": 100, "rows": 30})
                except OSError:
                    return

        threading.Thread(target=nudge, daemon=True).start()
        assert nudged.wait_closed(20) == 4408, nudged.close_code
        stop_nudging.set()
        nudged.close()
        wait_idle()
        print("PASS: a stream of resize frames does not hold the session open "
              "— only keystrokes refresh the idle timer")

        # And the other way round: somebody typing is never idle.
        typed = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        typed.send_json({"type": "open", "cols": 80, "rows": 24})
        until_connected(typed)
        stop_typing = threading.Event()

        def keep_typing():
            while not stop_typing.wait(0.4):
                try:
                    typed.send_binary(b" ")     # a keystroke the stub buffers
                except OSError:
                    return

        threading.Thread(target=keep_typing, daemon=True).start()
        time.sleep(sshterm.IDLE_TIMEOUT_S * 2)
        assert service.ssh_sessions.count == 1, service.ssh_sessions.count
        stop_typing.set()
        assert typed.wait_closed(20) == 4408, typed.close_code
        typed.close()
        print("PASS: keystrokes hold it open past twice the idle timeout, and "
              "it closes once they stop")
    finally:
        sshterm.IDLE_TIMEOUT_S = original_idle

    # ------------------------------------------------ failed logins are capped

    def wait_for_event(device_id, needle: str, timeout: float = 10.0) -> list:
        """The device's `ssh` events matching `needle`. A close the client
        has already seen is a frame ahead of the audit line behind it, so
        this waits for the line rather than racing it."""
        deadline = time.time() + timeout
        while True:
            found = [e for e in service.nodes_db.device_events(
                device_id, kinds=["ssh"]) if needle in e["detail"]]
            if found or time.time() > deadline:
                return found
            time.sleep(0.05)

    wait_idle()
    import stubs.stub_ssh_device as stub_module
    accept_password = stub_module._Server.check_auth_password
    stub_module._Server.check_auth_password = \
        lambda self, username, password: paramiko.AUTH_FAILED
    try:
        before = len(service.nodes_db.device_events(plain_device, kinds=["ssh"]))
        ws = WsClient(web_port, f"/api/ssh/devices/{plain_device}/socket", token)
        ws.send_json({"type": "open", "cols": 80, "rows": 24})
        assert ws.next_control("need-credentials")["reason"] == "none-stored"
        ws.send_json({"type": "auth", "username": "wrong", "password": "guess"})
        refusals, capped = 0, None
        while capped is None:
            message = ws.next_control(timeout=30)
            assert message is not None, (refusals, capped)
            if message["type"] == "error":
                if "Too many failed logins" in message["message"]:
                    capped = message
                    continue
                refusals += 1
            elif message["type"] == "need-credentials":
                assert message["reason"] == "auth-failed", message
                ws.send_json({"type": "auth", "username": "wrong",
                              "password": "guess"})
        assert refusals == sshterm.MAX_AUTH_ATTEMPTS, refusals
        assert ws.wait_closed(10) == 1000, ws.close_code
        print("PASS: five refused logins end the session — the page is not an "
              "unthrottled password oracle")

        failures = wait_for_event(plain_device, "attempt 5 of 5")
        events = service.nodes_db.device_events(plain_device, kinds=["ssh"])[:]
        failures = [e for e in events if "refused (attempt" in e["detail"]]
        assert len(failures) == sshterm.MAX_AUTH_ATTEMPTS, \
            [dict(e) for e in events][:10]
        assert "attempt 5 of 5" in failures[0]["detail"], failures[0]["detail"]
        assert "wrong" in failures[0]["detail"] and DEFAULT_USER in \
            failures[0]["detail"], failures[0]["detail"]
        for event in events:
            assert "guess" not in event["detail"], event["detail"]
        assert len(events) > before
        print("PASS: every refused login is audited with its attempt number, "
              "the SSH user tried and who asked — and never the password")
        ws.close()
    finally:
        stub_module._Server.check_auth_password = accept_password
    wait_idle()

    # --------------------------- and the cap follows the account, not the socket

    # A socket is free to open, so a per-socket counter is no counter at
    # all: close the window, open another, and the guessing carries on. The
    # cap is per account and device, across sockets, with a cooling-off —
    # and the socket that runs into it never reaches the device.
    stub4 = StubDevice(mode="slow", pause_s=0.05, host="127.0.0.4")
    guessed = service.nodes_db.add_device("127.0.0.4", name="guess-target",
                                          group_id=group_id)
    service.configrx_db.update_device_config(guessed, ssh_port=stub4.port)
    tried = []
    stub_module._Server.check_auth_password = (
        lambda self, username, password: (tried.append(username),
                                          paramiko.AUTH_FAILED)[1])
    try:
        def guess(client, times: int) -> None:
            """Answer `need-credentials` `times` over. Each answer is sent
            only once the ask for it has arrived, so the failures are in
            order rather than raced."""
            for _ in range(times):
                assert client.next_control("need-credentials", timeout=30)
                client.send_json({"type": "auth", "username": "wrong",
                                  "password": "guess"})

        def error_saying(client, needle: str, timeout: float = 30.0) -> dict:
            """The next error frame that says `needle` — a refused login
            sends its own error first, and it is not the one being asserted."""
            deadline = time.time() + timeout
            while time.time() < deadline:
                message = client.next_control(timeout=timeout)
                assert message is not None, f"the socket closed before {needle!r}"
                if message["type"] == "error" and needle in message["message"]:
                    return message
            raise AssertionError(f"no error saying {needle!r}")

        first = WsClient(web_port, f"/api/ssh/devices/{guessed}/socket", token)
        first.send_json({"type": "open", "cols": 80, "rows": 24})
        guess(first, 3)
        assert first.next_control("need-credentials", timeout=30)
        first.close()
        wait_idle()
        assert len(tried) == 3, tried

        # A brand-new socket: the counter does not start again with it.
        second = WsClient(web_port, f"/api/ssh/devices/{guessed}/socket", token)
        second.send_json({"type": "open", "cols": 80, "rows": 24})
        guess(second, 2)
        error_saying(second, "Too many failed logins")
        assert second.wait_closed(10) == 1000, second.close_code
        second.close()
        wait_idle()
        assert len(tried) == sshterm.MAX_AUTH_ATTEMPTS, tried
        print("PASS: five refusals spread over two sockets spend the cap — "
              "reconnecting does not reset it")

        numbered = [e["detail"] for e in service.nodes_db.device_events(
            guessed, kinds=["ssh"]) if "refused (attempt" in e["detail"]]
        assert len(numbered) == sshterm.MAX_AUTH_ATTEMPTS, numbered
        assert any("attempt 4 of 5" in d for d in numbered), numbered
        assert any("attempt 5 of 5" in d for d in numbered), numbered
        print("PASS: the device events count 1..5 across both sockets, so the "
              "pattern is visible instead of reading as two fresh starts")

        # The sixth attempt: refused here, and the device never hears it.
        third = WsClient(web_port, f"/api/ssh/devices/{guessed}/socket", token)
        third.send_json({"type": "open", "cols": 80, "rows": 24})
        message = error_saying(third, "Too many failed logins for this device")
        assert "minute" in message["message"], message
        assert third.wait_closed(10) == 4429, third.close_code
        third.close()
        wait_idle()
        assert len(tried) == sshterm.MAX_AUTH_ATTEMPTS, tried
        print("PASS: the sixth attempt is refused with 4429 and a cooling-off "
              "period, without the device being contacted at all")

        refusals = [e["detail"] for e in service.nodes_db.device_events(
            guessed, kinds=["ssh"]) if "refused before it was attempted" in
            e["detail"]]
        assert len(refusals) == 1 and DEFAULT_USER in refusals[0], refusals
        print("PASS: the refusal to start is audited once, not once per socket")

        # A cooling-off that has passed lets the account try again, and a
        # login the device accepts clears what is standing against the pair.
        original_window = sshterm.AUTH_FAILURE_WINDOW_S
        sshterm.AUTH_FAILURE_WINDOW_S = 0.5
        try:
            time.sleep(0.6)
            stub_module._Server.check_auth_password = accept_password
            again = WsClient(web_port, f"/api/ssh/devices/{guessed}/socket", token)
            again.send_json({"type": "open", "cols": 80, "rows": 24})
            assert again.next_control("need-credentials", timeout=30)
            again.send_json({"type": "auth", "username": "operator",
                             "password": PASSWORD})
            until_connected(again)
            again.close()
            wait_idle()
        finally:
            sshterm.AUTH_FAILURE_WINDOW_S = original_window
        assert service.ssh_sessions.auth_cooldown(DEFAULT_USER, guessed) == (0.0, False)
        print("PASS: the count decays with its window, and a login the device "
              "accepts clears it")
    finally:
        stub_module._Server.check_auth_password = accept_password
        stub4.close()
    wait_idle()

    # ------------------------------------- a shell is only as live as its session

    status, payload = call("POST", "/api/users",
                           {"username": "shelluser", "password": "Corr3ct-Horse-B4t",
                            "grants": {"ssh": "write"}}, token=token)
    assert status == 200, (status, payload)
    shell_token = login("shelluser", "Corr3ct-Horse-B4t")
    signed_out = WsClient(web_port, f"/api/ssh/devices/{device}/socket", shell_token)
    signed_out.send_json({"type": "open", "cols": 80, "rows": 24})
    until_connected(signed_out)
    status, payload = call("POST", "/api/logout", {}, token=shell_token)
    assert status == 200, (status, payload)
    assert signed_out.wait_closed(15) == 4401, signed_out.close_code
    signed_out.close()
    notes = wait_for_event(device, "no longer signed in")
    assert notes and "shelluser" in notes[0]["detail"], \
        [dict(e) for e in service.nodes_db.device_events(device, kinds=["ssh"])][:5]
    print("PASS: signing out closes the shell that sign-in opened, with 4401, "
          "and says so in the device's events")
    wait_idle()

    revoked = WsClient(web_port, f"/api/ssh/devices/{device}/socket",
                       login("shelluser", "Corr3ct-Horse-B4t"))
    revoked.send_json({"type": "open", "cols": 80, "rows": 24})
    until_connected(revoked)
    status, payload = call("POST", "/api/users/permissions",
                           {"username": "shelluser", "grants": {"nodes": "read"}},
                           token=token)
    assert status == 200, (status, payload)
    assert revoked.wait_closed(20) == 4401, revoked.close_code
    revoked.close()
    print("PASS: taking the ssh permission away closes a shell that is already "
          "running")
    wait_idle()

    # ----------------------------------------------- one account's own ceiling

    original_per_user = sshterm.MAX_SESSIONS_PER_USER
    sshterm.MAX_SESSIONS_PER_USER = 2
    mine = []
    try:
        for _ in range(sshterm.MAX_SESSIONS_PER_USER):
            one = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
            one.send_json({"type": "open", "cols": 80, "rows": 24})
            until_connected(one)
            mine.append(one)
        extra = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        extra.send_json({"type": "open", "cols": 80, "rows": 24})
        message = extra.next_control("error")
        assert "You already have 2 SSH sessions" in message["message"], message
        assert extra.wait_closed(10) == 4429, extra.close_code
        extra.close()
        print("PASS: one account cannot spend the application-wide cap on its "
              "own — its own limit closes with 4429")
    finally:
        sshterm.MAX_SESSIONS_PER_USER = original_per_user
        for one in mine:
            one.close()
    wait_idle()

    # ------------------------------------------- the watchdog survives a fault

    # Every limit on a live shell — the idle timeout, the sign-out check,
    # the permission check — is that one loop in that one daemon thread. An
    # exception used to end the thread, silently, and the shell then ran on
    # with none of them. Here the session store raises for three ticks and
    # the watchdog has to still be enforcing afterwards.
    status, payload = call("POST", "/api/users",
                           {"username": "flakyuser", "password": "Corr3ct-Horse-B6t",
                            "grants": {"ssh": "write"}}, token=token)
    assert status == 200, (status, payload)
    flaky_token = login("flakyuser", "Corr3ct-Horse-B6t")
    flaky = WsClient(web_port, f"/api/ssh/devices/{device}/socket", flaky_token)
    flaky.send_json({"type": "open", "cols": 80, "rows": 24})
    until_connected(flaky)

    real_get = service.sessions.get
    raised = []

    def flaky_get(looked_up):
        """Raise for this one session's token, and only three times: every
        other caller — including the request that signs it out — sees the
        real store."""
        if looked_up == flaky_token and len(raised) < 3:
            raised.append(looked_up)
            raise RuntimeError("the session store is busy")
        return real_get(looked_up)

    service.sessions.get = flaky_get
    try:
        deadline = time.time() + 15
        while len(raised) < 3 and time.time() < deadline:
            time.sleep(0.1)
        assert len(raised) == 3, raised
    finally:
        service.sessions.get = real_get
    status, payload = call("POST", "/api/logout", {}, token=flaky_token)
    assert status == 200, (status, payload)
    assert flaky.wait_closed(15) == 4401, flaky.close_code
    flaky.close()
    print("PASS: a watchdog tick that raises is reported once — the traceback "
          "above is that report, for three raised ticks — and the next tick "
          "is still taken, so the shell's limits go on being enforced")
    wait_idle()

    # ------------------------------------ shutting down stops sessions at once

    # `stop()` takes the socket's I/O lock, which a write into a browser
    # that stopped reading holds for SEND_TIMEOUT_S. Serially that is
    # sixteen of those, one after another, ahead of a three-second budget.
    class StallingSession:
        """A session whose stop() is parked exactly where a real one is:
        waiting for a write that only a socket shutdown will release."""

        def __init__(self, registry):
            self.registry = registry
            self.device_id = 0
            self.released = threading.Event()
            self.stopped = threading.Event()

        def unblock(self):
            self.released.set()

        def stop(self, message=""):
            self.released.wait(30)          # wsock.SEND_TIMEOUT_S, or longer
            self.stopped.set()
            with self.registry._lock:
                self.registry._sessions.discard(self)

    registry = sshterm.SshSessionRegistry(service)
    stalled = [StallingSession(registry) for _ in range(sshterm.MAX_SESSIONS)]
    registry._sessions.update(stalled)
    started = time.time()
    registry.shutdown()
    elapsed = time.time() - started
    assert elapsed < sshterm.SHUTDOWN_BUDGET_S + 2, elapsed
    assert registry.count == 0, registry.count
    assert all(one.stopped.is_set() for one in stalled)
    print(f"PASS: {len(stalled)} stalled sessions are stopped together in "
          f"{elapsed:.1f}s, inside one budget, instead of one timeout each")

    # ------------------------------------ a socket that never sends `open`

    # The slot is taken at the 101, not at `connected`: a laptop that slept
    # with the terminal open, or a client that never intended to send
    # `open`, holds it against both caps. Everything that bounds a
    # terminal's life has to cover that window too.
    original_handshake = sshterm.HANDSHAKE_TIMEOUT_S
    original_per_user = sshterm.MAX_SESSIONS_PER_USER
    sshterm.HANDSHAKE_TIMEOUT_S = 2
    sshterm.MAX_SESSIONS_PER_USER = 1
    try:
        silent = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        assert silent.upgraded, (silent.status, silent.headers)
        # It really is holding the slot: this account's one session is spent.
        blocked = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        blocked.send_json({"type": "open", "cols": 80, "rows": 24})
        message = blocked.next_control("error")
        assert "You already have 1 SSH sessions" in message["message"], message
        blocked.close()
        assert silent.wait_closed(20) == 4408, silent.close_code
        silent.close()
        wait_idle()
        print("PASS: a socket that upgrades and sends no 'open' loses its slot "
              "with 4408 instead of holding it forever")

        # And the cap it was spending is free again.
        after = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
        after.send_json({"type": "open", "cols": 80, "rows": 24})
        until_connected(after)
        after.close()
        print("PASS: the per-account cap that socket was spending is released")
    finally:
        sshterm.HANDSHAKE_TIMEOUT_S = original_handshake
        sshterm.MAX_SESSIONS_PER_USER = original_per_user
    wait_idle()

    # The other half: the watchdog's sign-out check covers that window too,
    # so a socket parked before `open` does not outlive the sign-in behind
    # it while it waits.
    status, payload = call("POST", "/api/users",
                           {"username": "silentuser", "password": "Corr3ct-Horse-B5t",
                            "grants": {"ssh": "write"}}, token=token)
    assert status == 200, (status, payload)
    silent_token = login("silentuser", "Corr3ct-Horse-B5t")
    waiting = WsClient(web_port, f"/api/ssh/devices/{device}/socket", silent_token)
    assert waiting.upgraded, (waiting.status, waiting.headers)
    status, payload = call("POST", "/api/logout", {}, token=silent_token)
    assert status == 200, (status, payload)
    assert waiting.wait_closed(15) == 4401, waiting.close_code
    waiting.close()
    print("PASS: signing out closes a socket that is still waiting for its "
          "'open' message, with 4401")
    wait_idle()

    # ------------------------------------------------- the same thing over TLS

    # One SSLSocket read and written at the same time is what OpenSSL does
    # not support, and a terminal does exactly that: keystrokes going in
    # while a `show` scrolls out. The transport serialises both onto one
    # lock; this is the test that says so.
    if not shutil.which("openssl"):
        print("SKIP: no openssl binary here, so no certificate to serve TLS with")
    else:
        certfile = os.path.join(TMPDIR, "tls-cert.pem")
        keyfile = os.path.join(TMPDIR, "tls-key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-nodes", "-keyout", keyfile, "-out", certfile,
                        "-days", "2", "-subj", "/CN=127.0.0.1"],
                       check=True, capture_output=True)
        tls_port = free_tcp_port()
        tls_server = WebServer(service, host="127.0.0.1", port=tls_port,
                               certfile=certfile, keyfile=keyfile)
        assert tls_server.start(block=False), tls_server.error
        stub3 = StubDevice(mode="slow", pause_s=0.0, host="127.0.0.3")
        tls_device = service.nodes_db.add_device("127.0.0.3", name="tls-switch",
                                                 group_id=group_id)
        service.configrx_db.update_device_config(tls_device, ssh_port=stub3.port,
                                                 ssh_username="operator")
        service.configrx_db.set_credential(tls_device, "operator",
                                           dpapi_mod.protect(PASSWORD.encode()))
        secure = WsClient(tls_port, f"/api/ssh/devices/{tls_device}/socket",
                          token, tls=True)
        assert secure.upgraded, (secure.status, secure.headers)
        secure.send_json({"type": "open", "cols": 80, "rows": 24})
        until_connected(secure)
        secure.read_until(b"stub-switch#")
        print("PASS: the upgrade, the shell and its output all work over TLS")

        # Keystrokes go in while the answer to the last one is still coming
        # out: on the server that is its reader thread and its pump thread
        # on one SSLSocket at the same moment, which is the case that used
        # to be able to kill the connection. (The client stays
        # single-threaded — its own `ssl` socket is under no such lock.)
        target, typed = 300_000, 0
        deadline = time.time() + 60
        while len(secure.output) < target and time.time() < deadline:
            if typed < 200 and len(secure.output) > (typed - 3) * 4000:
                secure.send_binary(b"show ver\n")
                typed += 1
            frame = secure._frame()
            assert frame is not None, \
                f"the TLS socket ended after {len(secure.output):,} bytes"
            opcode, chunk = frame
            assert opcode != wsock.OP_CLOSE, (secure.close_code,
                                              len(secure.output))
            if opcode == wsock.OP_BINARY:
                secure.output += chunk
        assert len(secure.output) >= target, len(secure.output)
        print(f"PASS: {len(secure.output):,} bytes streamed back over TLS while "
              f"{typed} commands went the other way, without a record error")
        secure.close()
        wait_idle()
        stub3.close()
        tls_server.stop()

    # ----------------------------------------------- the open message's edges

    # A `resize` that overtakes the `open` is applied rather than treated as
    # a missing open: the page measures its terminal as it opens the socket,
    # and a notice appearing between the two changes that measurement.
    early = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
    early.send_json({"type": "resize", "cols": 132, "rows": 43})
    early.send_json({"type": "open", "cols": 132, "rows": 43})
    until_connected(early)
    early.read_until(b"stub-switch#")
    print("PASS: a resize arriving before the open is applied, and the session "
          "still opens")
    early.close()
    wait_idle()

    # And an `open` pipelined behind the handshake itself — sent before the
    # 101 came back, so it lands in the HTTP buffer the transport takes over
    # from — is not lost.
    piped = WsClient(
        web_port, f"/api/ssh/devices/{device}/socket", token,
        pipeline=wsock.client_frame(wsock.OP_TEXT, json.dumps(
            {"type": "open", "cols": 80, "rows": 24}).encode("utf-8")))
    assert piped.upgraded, (piped.status, piped.headers)
    until_connected(piped)
    print("PASS: an open message pipelined behind the handshake is picked up, "
          "not dropped with the buffer it arrived in")
    piped.close()
    wait_idle()

    # ------------------------------------------------- a device that is gone

    ws = WsClient(web_port, f"/api/ssh/devices/999999/socket", token)
    ws.send_json({"type": "open", "cols": 80, "rows": 24})
    message = ws.next_control("error")
    assert "No such device" in message["message"], message
    ws.close()
    print("PASS: opening a session on a device that does not exist is an error "
          "frame, not a traceback")

    # ------------------------------------------------ the permission backfill

    from netpath.appdb import SSH_BACKFILL_MARKER, AppDatabase
    from netpath import permissions as perms
    upgrade_path = os.path.join(TMPDIR, "upgrade.db")
    seed = AppDatabase(upgrade_path)
    seed.add_user("olduser", "x", must_change=False)
    seed.add_user("halfuser", "x", must_change=False)
    seed.set_permissions("olduser", {m: "write" for m in perms.MODULES if m != "ssh"})
    seed.set_permissions("halfuser", {m: "write" for m in perms.MODULES
                                      if m not in ("ssh", "settings")})
    seed._conn.execute("DELETE FROM meta WHERE key = ?", (SSH_BACKFILL_MARKER,))
    seed._conn.commit()
    seed.close()
    upgraded = AppDatabase(upgrade_path)
    upgraded.backfill_permissions()      # Service calls this after migrate_from
    assert upgraded.permissions_for("olduser").get("ssh") == "write", \
        upgraded.permissions_for("olduser")
    assert "ssh" not in upgraded.permissions_for("halfuser"), \
        upgraded.permissions_for("halfuser")
    print("PASS: the one-time backfill grants ssh to accounts that already "
          "held write on everything else, and to nobody else")

    # And exactly once: taking it away again survives a restart.
    upgraded.set_permissions("olduser", {m: "write" for m in perms.MODULES
                                         if m != "ssh"})
    upgraded.close()
    again = AppDatabase(upgrade_path)
    again.backfill_permissions()
    assert "ssh" not in again.permissions_for("olduser"), \
        again.permissions_for("olduser")
    again.close()
    print("PASS: revoking ssh afterwards is not undone on the next start")

finally:
    for listener in ("stub", "stub2", "replacement"):
        try:
            globals()[listener].close()
        except Exception:
            pass
    server.stop()
    service.shutdown()

print("ALL SSH TERMINAL ASSERTIONS PASSED")
