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
import socket
import struct
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

    def __init__(self, port: int, path: str, token: str, timeout: float = 20.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {self.key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Cookie: sw_session={token}\r\n"
            "\r\n")
        self.sock.sendall(request.encode("ascii"))
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
    print("PASS: GET /api/ssh/devices/<id> describes the device, its credential "
          "and (not yet) its host key")

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
    ws = WsClient(web_port, f"/api/ssh/devices/{device}/socket", token)
    ws.send_json({"type": "open", "cols": 80, "rows": 24})
    seen = until_connected(ws)
    assert not [m for m in seen if m["type"] == "hostkey"], seen
    print("PASS: a second connection to a known host key reports no hostkey "
          "event, and the page's GET shows the stored fingerprint")
    ws.close()

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
    finally:
        sshterm.IDLE_TIMEOUT_S = original_idle

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
