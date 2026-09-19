"""TACACS+ (RFC 8907) PAP authentication, three layers cheapest first: the
hand-rolled wire format against known-answer byte vectors, authenticate()
against a scripted fake TACACS+ server (PASS, FAIL, ERROR, GETPASS,
garbage, a wrong shared secret, a stalled server, a closed port, server
fallback), and the real login route end to end -- a tacacs-mapped account,
a wrong password, a server that is down, auto-create on and off, the
feature switched off, a local account, the settings write-gate, and the
tacacs-test route. Cloned in structure from test_ldap_auth.py.
"""
import hashlib
import http.client
import json
import os
import socket
import sys
import threading
import time

os.environ.setdefault("NETPATH_SECRET_PASSPHRASE", "tacacs-auth-suite")

from _paths import free_tcp_port, tmpdir  # noqa: E402  (env var set first)

TMPDIR = tmpdir("tacacs_auth_")

from netpath import permissions, tacacsclient  # noqa: E402
from netpath.web import Service, WebServer  # noqa: E402
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER  # noqa: E402

failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


# =========================================================================
# 1. Header, obfuscation and packet layout: known-answer vectors.
# =========================================================================
print("header encode/decode round-trips")

sid = b"\x11\x22\x33\x44"
header = tacacsclient.encode_header(session_id=sid, seq_no=1, length=17, flags=0)
check("encode_header produces exactly 12 bytes", len(header) == 12, header.hex())
check("...version byte is 0xC0", header[0] == 0xC0, hex(header[0]))
check("...type byte is AUTHEN (1)", header[1] == tacacsclient.TYPE_AUTHEN, header[1])
check("...seq_no/flags/session_id/length are in the right byte offsets",
      header[2] == 1 and header[3] == 0 and header[4:8] == sid
      and int.from_bytes(header[8:12], "big") == 17, header.hex())
decoded = tacacsclient.decode_header(header)
check("decode_header inverts encode_header",
      decoded == {"version": 0xC0, "type": tacacsclient.TYPE_AUTHEN, "seq_no": 1,
                  "flags": 0, "session_id": sid, "length": 17}, decoded)

try:
    tacacsclient.encode_header(session_id=b"\x01\x02\x03", seq_no=1, length=0)
    check("encode_header refuses a session_id that is not 4 bytes", False)
except tacacsclient.TacacsConfigError:
    check("encode_header refuses a session_id that is not 4 bytes", True)


print("obfuscation: chained-MD5 keystream, known-answer and round-trip")

key = b"tac-plus-shared-secret"
version, seq_no = tacacsclient.VERSION, tacacsclient.SEQ_NO_START

# RFC 8907 §4.5's MD5_1 by hand, checked against a zero body of the same
# length -- XORing a body of all-zero bytes against the pad reproduces the
# pad exactly, so this is a clean known-answer check of _pseudo_pad's first
# block without reaching into the private helper directly.
md5_1 = hashlib.md5(sid + key + bytes([version, seq_no])).digest()
zero_body = b"\x00" * len(md5_1)
pad_from_obfuscate = tacacsclient.obfuscate(zero_body, sid, key, version, seq_no)
check("obfuscate(zero body) reproduces RFC 8907's MD5_1 by hand",
      pad_from_obfuscate == md5_1, pad_from_obfuscate.hex())

# A body longer than one MD5 block exercises the chain (MD5_2, ...): the
# second 16-byte block of the keystream is MD5(header + MD5_1).
md5_2 = hashlib.md5(sid + key + bytes([version, seq_no]) + md5_1).digest()
long_zero_body = b"\x00" * 40
long_pad = tacacsclient.obfuscate(long_zero_body, sid, key, version, seq_no)
check("the chain's second MD5 block matches RFC 8907's construction",
      long_pad[16:32] == md5_2, long_pad.hex())

body = b"this body is long enough to span more than one MD5 block, easily"
encrypted = tacacsclient.obfuscate(body, sid, key, version, seq_no)
check("obfuscate actually changes the bytes", encrypted != body)
round_tripped = tacacsclient.obfuscate(encrypted, sid, key, version, seq_no)
check("obfuscate(obfuscate(x)) == x (XOR is its own inverse)",
      round_tripped == body, round_tripped)

different_key_result = tacacsclient.obfuscate(encrypted, sid, b"a different secret",
                                              version, seq_no)
check("de-obfuscating with the wrong key does not reproduce the body",
      different_key_result != body, different_key_result)


print("build_authen_start: field layout by byte offset")

started = tacacsclient.build_authen_start("alice", "s3cret", "10.20.30.40", "netpath")
check("action/priv_lvl/authen_type/authen_service are the first four bytes",
      started[0:4] == bytes([tacacsclient.ACTION_LOGIN, tacacsclient.PRIV_LVL_MIN,
                            tacacsclient.AUTHEN_TYPE_PAP,
                            tacacsclient.AUTHEN_SERVICE_LOGIN]), started[:4].hex())
u_len, p_len, r_len, d_len = started[4], started[5], started[6], started[7]
check("the four length bytes match the fields that follow",
      (u_len, p_len, r_len, d_len) == (5, len(b"netpath"), len(b"10.20.30.40"),
                                       len(b"s3cret")),
      (u_len, p_len, r_len, d_len))
pos = 8
check("...user is at the expected offset",
      started[pos:pos + u_len] == b"alice", started[pos:pos + u_len])
pos += u_len
check("...port is at the expected offset",
      started[pos:pos + p_len] == b"netpath", started[pos:pos + p_len])
pos += p_len
check("...rem_addr is at the expected offset",
      started[pos:pos + r_len] == b"10.20.30.40", started[pos:pos + r_len])
pos += r_len
check("...password (data) is at the expected offset",
      started[pos:pos + d_len] == b"s3cret", started[pos:pos + d_len])
check("...and there is nothing left over", pos + d_len == len(started), len(started))

for name, kwargs in (
        ("username", {"user": "x" * 256, "password": "pw"}),
        ("password", {"user": "u", "password": "x" * 256}),
        ("rem_addr", {"user": "u", "password": "pw", "rem_addr": "x" * 256})):
    try:
        tacacsclient.build_authen_start(**kwargs)
        check(f"a {name} over 255 bytes is refused", False)
    except tacacsclient.TacacsConfigError:
        check(f"a {name} over 255 bytes is refused", True)


print("parse_authen_reply")

reply_body = (bytes([tacacsclient.STATUS_PASS, 0]) + (5).to_bytes(2, "big")
             + (0).to_bytes(2, "big") + b"hello")
status, flags, server_msg, data = tacacsclient.parse_authen_reply(reply_body)
check("parse_authen_reply reads status/flags/server_msg/data correctly",
      (status, flags, server_msg, data) == (tacacsclient.STATUS_PASS, 0, "hello", b""),
      (status, flags, server_msg, data))

for bad, why in (
        (b"\x01\x00\x00", "shorter than the fixed 6-byte header"),
        (bytes([tacacsclient.STATUS_FAIL, 0]) + (10).to_bytes(2, "big")
         + (0).to_bytes(2, "big"), "server_msg_len longer than the body actually is")):
    try:
        tacacsclient.parse_authen_reply(bad)
        check(f"malformed AUTHEN REPLY body is refused ({why})", False)
    except tacacsclient.TacacsProtocolError:
        check(f"malformed AUTHEN REPLY body is refused ({why})", True)


# =========================================================================
# 2. parse_servers
# =========================================================================
print("parse_servers")

check("a single bare host gets the default port",
      tacacsclient.parse_servers("10.0.0.1") == [("10.0.0.1", 49)])
check("comma-separated hosts with explicit ports",
      tacacsclient.parse_servers("10.0.0.1:4949,10.0.0.2:100")
      == [("10.0.0.1", 4949), ("10.0.0.2", 100)])
check("whitespace-separated hosts work the same way",
      tacacsclient.parse_servers("10.0.0.1  10.0.0.2:100") ==
      [("10.0.0.1", 49), ("10.0.0.2", 100)])
check("mixed comma/whitespace/blank entries are tolerated",
      tacacsclient.parse_servers(" 10.0.0.1, ,10.0.0.2 ")
      == [("10.0.0.1", 49), ("10.0.0.2", 49)])
check("a bracketed IPv6 literal with a port",
      tacacsclient.parse_servers("[::1]:4949") == [("::1", 4949)])
check("a bracketed IPv6 literal with no port gets the default",
      tacacsclient.parse_servers("[2001:db8::1]") == [("2001:db8::1", 49)])
check("a bare (unbracketed) IPv6 literal gets the default port",
      tacacsclient.parse_servers("::1") == [("::1", 49)])

for bad, why in (
        ("", "empty"),
        ("   ", "whitespace only"),
        ("10.0.0.1:notaport", "non-numeric port"),
        ("10.0.0.1:99999", "port out of range"),
        ("10.0.0.1:0", "port zero"),
        ("[::1", "unmatched bracket"),
        (":49", "empty host with a port"),
        ("a,b,c,d,e", "more than 4 servers")):
    try:
        tacacsclient.parse_servers(bad)
        check(f"parse_servers rejects {why!r}", False, bad)
    except tacacsclient.TacacsConfigError:
        check(f"parse_servers rejects {why!r}", True)


# =========================================================================
# 3. authenticate() against a scripted fake TACACS+ server.
# =========================================================================

SHARED_SECRET = "netpath-suite-shared-secret"
CREDS = {"alice": "correct-horse"}


def _reply_bytes(session_id, secret, seq_no, status, *, flags=0, server_msg=b"",
                 data=b"", header_flags=0, key=None,
                 version=tacacsclient.VERSION, packet_type=tacacsclient.TYPE_AUTHEN):
    body = (bytes([status, flags]) + len(server_msg).to_bytes(2, "big")
           + len(data).to_bytes(2, "big") + server_msg + data)
    use_key = key if key is not None else secret.encode("utf-8")
    encrypted = tacacsclient.obfuscate(body, session_id, use_key, version, seq_no)
    head = tacacsclient.encode_header(session_id=session_id, seq_no=seq_no,
                                      length=len(encrypted), flags=header_flags,
                                      version=version, packet_type=packet_type)
    return head + encrypted


def _HANG_FOREVER(user, password, head):    # noqa: N802 - sentinel
    return None


class FakeTacacsServer:
    """Accepts a connection, reads exactly one AUTHEN START, de-obfuscates
    it with `secret`, hands (user, password, header) to `respond`, and
    writes back whatever bytes it returns (or holds the connection open
    forever if it returns None -- the "stalled server" case)."""

    def __init__(self, respond, secret=SHARED_SECRET, host="127.0.0.1"):
        self.respond = respond
        self.secret = secret
        self.host = host
        self.received: list[tuple[str, str]] = []
        self.received_versions: list[int] = []
        self.connections = 0
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def servers(self):
        return [(self.host, self.port)]

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            header_bytes = tacacsclient._recv_exact(conn, 12)
            head = tacacsclient.decode_header(header_bytes)
            body_enc = tacacsclient._recv_exact(conn, head["length"])
            body = tacacsclient.obfuscate(body_enc, head["session_id"],
                                          self.secret.encode("utf-8"),
                                          head["version"], head["seq_no"])
            u_len, p_len, r_len, d_len = body[4], body[5], body[6], body[7]
            pos = 8
            user = body[pos:pos + u_len].decode("utf-8"); pos += u_len
            pos += p_len   # port -- not needed by any responder here
            pos += r_len   # rem_addr -- ditto
            password = body[pos:pos + d_len].decode("utf-8")
            self.received.append((user, password))
            self.received_versions.append(head["version"])
            reply = self.respond(user, password, head)
            if reply is not None:
                conn.sendall(reply)
            # else: deliberately never answer (the stalled-server case) --
            # the connection is held open until the client's own timeout
            # gives up, or this thread exits with the process.
        except Exception:
            pass
        finally:
            if self.respond is not _HANG_FOREVER:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


print("scripted fake TACACS+ server -- the PASS/FAIL outcomes")


def credentialed(user, password, head):
    status = (tacacsclient.STATUS_PASS if CREDS.get(user) == password
             else tacacsclient.STATUS_FAIL)
    return _reply_bytes(head["session_id"], SHARED_SECRET, head["seq_no"] + 1, status,
                        version=head["version"])


server = FakeTacacsServer(credentialed)
try:
    ok = tacacsclient.authenticate(server.servers(), SHARED_SECRET, "alice",
                                   "correct-horse", timeout=3, rem_addr="10.1.1.1")
    check("PASS: the right username/password authenticates", ok is True, ok)
    check("...and the fake server actually received that exact user/password",
          server.received[-1] == ("alice", "correct-horse"), server.received[-1])

    ok = tacacsclient.authenticate(server.servers(), SHARED_SECRET, "alice",
                                   "wrong", timeout=3)
    check("FAIL: a wrong password returns False, does not raise", ok is False, ok)
    check("the PAP START carries minor_version 1 (0xC1), not 0xC0",
          server.received_versions[-1] == tacacsclient.VERSION_PAP,
          hex(server.received_versions[-1]))
finally:
    server.stop()

print("a reply that echoes 0xC0 instead of the client's own 0xC1 still decodes")
echo_c0_srv = FakeTacacsServer(lambda u, p, h: _reply_bytes(
    h["session_id"], SHARED_SECRET, h["seq_no"] + 1, tacacsclient.STATUS_PASS,
    version=tacacsclient.VERSION))
try:
    ok = tacacsclient.authenticate(echo_c0_srv.servers(), SHARED_SECRET, "alice",
                                   "correct-horse", timeout=3)
    check("a 0xC0 reply to a 0xC1 START is still accepted and decodes to PASS",
          ok is True, ok)
finally:
    echo_c0_srv.stop()

print("a reply whose packet type is not AUTHEN is a TacacsProtocolError")
wrong_type_srv = FakeTacacsServer(lambda u, p, h: _reply_bytes(
    h["session_id"], SHARED_SECRET, h["seq_no"] + 1, tacacsclient.STATUS_PASS,
    version=h["version"], packet_type=0x02))
try:
    try:
        tacacsclient.authenticate(wrong_type_srv.servers(), SHARED_SECRET, "alice",
                                  "correct-horse", timeout=3)
        check("a non-AUTHEN reply type: did not raise (unexpected)", False)
    except tacacsclient.TacacsProtocolError:
        check("a non-AUTHEN reply type raises TacacsProtocolError", True)
finally:
    wrong_type_srv.stop()

print("empty password refused before any I/O")
dead_port = free_tcp_port()
ok = tacacsclient.authenticate([("127.0.0.1", dead_port)], SHARED_SECRET, "alice", "",
                               timeout=1)
check("an empty password returns False without touching the network",
      ok is False, ok)

print("ERROR / GETPASS / RESTART / FOLLOW: not a credential answer")
for status_name, status in (("ERROR", tacacsclient.STATUS_ERROR),
                            ("GETPASS", tacacsclient.STATUS_GETPASS),
                            ("GETUSER", tacacsclient.STATUS_GETUSER),
                            ("GETDATA", tacacsclient.STATUS_GETDATA),
                            ("RESTART", tacacsclient.STATUS_RESTART),
                            ("FOLLOW", tacacsclient.STATUS_FOLLOW)):
    srv = FakeTacacsServer(lambda u, p, h, status=status: _reply_bytes(
        h["session_id"], SHARED_SECRET, h["seq_no"] + 1, status))
    try:
        try:
            tacacsclient.authenticate(srv.servers(), SHARED_SECRET, "alice",
                                      "correct-horse", timeout=3)
            check(f"{status_name}: did not raise (unexpected)", False)
        except tacacsclient.TacacsProtocolError:
            check(f"{status_name}: raises TacacsProtocolError, not a plain "
                  f"True/False", True)
    finally:
        srv.stop()

print("garbage / undecodable replies")
garbage_srv = FakeTacacsServer(lambda u, p, h: _reply_bytes(
    h["session_id"], SHARED_SECRET, h["seq_no"] + 1, tacacsclient.STATUS_PASS,
    server_msg=b"x" * 30, data=b"y" * 20)[:8] + b"\xff\xff\xff\xff")
try:
    try:
        tacacsclient.authenticate(garbage_srv.servers(), SHARED_SECRET, "alice",
                                  "correct-horse", timeout=3)
        check("a truncated/garbled reply body: did not raise (unexpected)", False)
    except tacacsclient.TacacsProtocolError:
        check("a truncated/garbled reply body raises TacacsProtocolError", True)
finally:
    garbage_srv.stop()

print("a wrong shared secret produces garbage, not a clean FAIL")
wrong_key_srv = FakeTacacsServer(lambda u, p, h: _reply_bytes(
    h["session_id"], SHARED_SECRET, h["seq_no"] + 1, tacacsclient.STATUS_PASS,
    server_msg=b"a genuine, reasonably long server message here",
    key=b"a completely different secret than the client has"))
try:
    try:
        tacacsclient.authenticate(wrong_key_srv.servers(), SHARED_SECRET, "alice",
                                  "correct-horse", timeout=3)
        check("wrong shared secret: did not raise (unexpected -- it must not "
              "read as a clean answer)", False)
    except tacacsclient.TacacsProtocolError:
        check("wrong shared secret raises TacacsProtocolError rather than "
              "silently deciding PASS or FAIL", True)
finally:
    wrong_key_srv.stop()

print("a reply with the header's unencrypted flag set is refused")
unencrypted_srv = FakeTacacsServer(lambda u, p, h: _reply_bytes(
    h["session_id"], SHARED_SECRET, h["seq_no"] + 1, tacacsclient.STATUS_PASS,
    header_flags=tacacsclient.FLAG_UNENCRYPTED))
try:
    try:
        tacacsclient.authenticate(unencrypted_srv.servers(), SHARED_SECRET, "alice",
                                  "correct-horse", timeout=3)
        check("FLAG_UNENCRYPTED reply: did not raise (unexpected)", False)
    except tacacsclient.TacacsProtocolError:
        check("a reply with FLAG_UNENCRYPTED set is refused as a "
              "TacacsProtocolError, never trusted", True)
finally:
    unencrypted_srv.stop()

print("a stalled server (read timeout) is TacacsConnectError")
hang_srv = FakeTacacsServer(_HANG_FOREVER)
started_at = time.time()
try:
    try:
        tacacsclient.authenticate(hang_srv.servers(), SHARED_SECRET, "alice",
                                  "correct-horse", timeout=0.5)
        check("a server that never answers: did not raise (unexpected)", False)
    except tacacsclient.TacacsConnectError:
        elapsed = time.time() - started_at
        check("a stalled server times out as TacacsConnectError within budget",
              elapsed < 3.0, f"{elapsed:.2f}s")
finally:
    hang_srv.stop()

print("a closed port is TacacsConnectError")
closed_port = free_tcp_port()
try:
    tacacsclient.authenticate([("127.0.0.1", closed_port)], SHARED_SECRET, "alice",
                              "correct-horse", timeout=2)
    check("connecting to a closed port: did not raise (unexpected)", False)
except tacacsclient.TacacsConnectError:
    check("connecting to a closed port raises TacacsConnectError", True)

print("server-list fallback: a closed first server, a working second one")
fallback_srv = FakeTacacsServer(credentialed)
try:
    servers = [("127.0.0.1", free_tcp_port())] + fallback_srv.servers()
    ok = tacacsclient.authenticate(servers, SHARED_SECRET, "alice", "correct-horse",
                                   timeout=2)
    check("the second, reachable server answers PASS after the first refuses "
          "the connection", ok is True, ok)
finally:
    fallback_srv.stop()

print("every server unreachable raises TacacsConnectError, not TacacsProtocolError")
try:
    tacacsclient.authenticate(
        [("127.0.0.1", free_tcp_port()), ("127.0.0.1", free_tcp_port())],
        SHARED_SECRET, "alice", "correct-horse", timeout=1)
    check("all servers unreachable: did not raise (unexpected)", False)
except tacacsclient.TacacsConnectError:
    check("all servers unreachable raises TacacsConnectError", True)

print("a TacacsProtocolError is raised immediately, never tried on a later server")
protocol_err_srv = FakeTacacsServer(lambda u, p, h: _reply_bytes(
    h["session_id"], SHARED_SECRET, h["seq_no"] + 1, tacacsclient.STATUS_ERROR))
never_reached_srv = FakeTacacsServer(credentialed)
try:
    try:
        tacacsclient.authenticate(
            protocol_err_srv.servers() + never_reached_srv.servers(),
            SHARED_SECRET, "alice", "correct-horse", timeout=3)
        check("did not raise (unexpected)", False)
    except tacacsclient.TacacsProtocolError:
        check("a protocol error from the first server raises immediately", True)
    check("...and the second (working) server was never even contacted",
          never_reached_srv.connections == 0, never_reached_srv.connections)
finally:
    protocol_err_srv.stop()
    never_reached_srv.stop()

print("no configured secret / no configured servers")
try:
    tacacsclient.authenticate([("127.0.0.1", 49)], "", "alice", "pw")
    check("an empty secret: did not raise (unexpected)", False)
except tacacsclient.TacacsConfigError:
    check("an empty secret raises TacacsConfigError", True)
try:
    tacacsclient.authenticate([], SHARED_SECRET, "alice", "pw")
    check("no servers at all: did not raise (unexpected)", False)
except tacacsclient.TacacsConnectError:
    check("no servers at all raises TacacsConnectError", True)


# =========================================================================
# 4. The real login route, end to end.
# =========================================================================
print()
print("the login route, end to end")

DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps",
           "nodes", "alerts", "wireless", "configrx")


def db_paths(tag):
    d = tmpdir(f"tacacs_route_{tag}_")
    return [os.path.join(d, name + ".db") for name in DB_NAMES]


service = Service(*db_paths("main"), initial_admin_password="admin")
service.start()

http_port = free_tcp_port()
web = WebServer(service, host="127.0.0.1", port=http_port, certfile=None, keyfile=None)
assert web.start(block=False), web.error
print(f"server up on 127.0.0.1:{http_port}")

ADMIN_PASSWORD = "TacacsSuiteAdmin2026"


def call(method, path, body=None, token=None):
    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
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
    heads = dict(resp.getheaders())
    conn.close()
    return resp.status, payload, heads


def login(username, password):
    status, payload, heads = call(
        "POST", "/api/login", {"username": username, "password": password})
    if status != 200:
        return "", status, payload
    return heads.get("Set-Cookie", "").split("sw_session=")[1].split(";")[0], status, payload


try:
    admin_cookie, status, _p = login(DEFAULT_USER, DEFAULT_PASSWORD)
    check("the seeded admin can sign in", status == 200 and bool(admin_cookie))
    status, payload, _h = call(
        "POST", "/api/password",
        {"current_password": DEFAULT_PASSWORD, "new_password": ADMIN_PASSWORD},
        token=admin_cookie)
    check("the seeded admin's password change succeeds", status == 200, payload)
    admin_cookie, status, _p = login(DEFAULT_USER, ADMIN_PASSWORD)
    check("...and can sign in again with the new one", status == 200)

    def enable_tacacs(server, *, auto_create=True, default_role="viewer",
                      extra_values=None):
        values = {"tacacs_enabled": True, "tacacs_servers": f"{server.host}:{server.port}",
                  "tacacs_secret": SHARED_SECRET, "tacacs_timeout_s": 3,
                  "tacacs_auto_create": auto_create, "tacacs_default_role": default_role}
        values.update(extra_values or {})
        return call("POST", "/api/settings", {"scope": "global", "values": values},
                    token=admin_cookie)

    directory = FakeTacacsServer(credentialed)
    try:
        status, payload, _h = enable_tacacs(directory)
        check("an administrator can turn TACACS+ sign-in on", status == 200,
              f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/settings",
            {"scope": "global", "values": {"tacacs_servers": "10.0.0.1:notaport"}},
            token=admin_cookie)
        check("a bad tacacs_servers port is refused (400), not silently stored",
              status == 400, f"{status} {payload}")
        status, payload, _h = call(
            "POST", "/api/settings",
            {"scope": "global", "values": {"tacacs_default_role": "root"}},
            token=admin_cookie)
        check("an unknown tacacs_default_role is refused (400) at save time",
              status == 400, f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/users",
            {"username": "alice", "auth_source": "tacacs",
             "grants": {"nodes": "read"}}, token=admin_cookie)
        check("a tacacs-mapped account can be created",
              status == 200 and payload.get("auth_source") == "tacacs",
              f"{status} {payload}")
        check("…and stores no local password hash",
              service.app_db.user("alice")["password"] == "")

        alice_cookie, status, payload = login("alice", "correct-horse")
        check("the tacacs account authenticates via the real login route "
              "through the fake AAA server", status == 200 and bool(alice_cookie),
              f"{status} {payload}")
        check("…with must_change already false (no local password to change)",
              payload.get("must_change") is False, payload)
        status, payload, _h = call("GET", "/api/nodes/devices", token=alice_cookie)
        check("…and its session carries its own grants",
              status == 200, f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/login", {"username": "alice", "password": "wrong"})
        check("a wrong password against the AAA server is refused",
              status == 401, f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/password",
            {"username": "alice", "new_password": "whatever"}, token=admin_cookie)
        check("changing a tacacs account's password is refused",
              status == 400 and "tacacs" in str(payload.get("error", "")).lower(),
              f"{status} {payload}")

        status, payload, _h = call("GET", "/api/audit?limit=5000", token=admin_cookie)
        actions_for_alice = [(e["action"], e["detail"]) for e in payload.get("events", [])
                             if e["target"] == "alice"]
        check("the failed AAA sign-in is audited, without a password",
              any(a == "signin.failed" and "wrong" not in d and "correct-horse" not in d
                  for a, d in actions_for_alice),
              actions_for_alice)
        audit_text = json.dumps(payload)
        check("no audited detail anywhere contains the real password or the shared secret",
              "correct-horse" not in audit_text and SHARED_SECRET not in audit_text,
              "leaked")

        directory.stop()
        status, payload, _h = call(
            "POST", "/api/login", {"username": "alice", "password": "correct-horse"})
        check("an AAA server that is down fails closed (401, not a 500)",
              status == 401, f"{status} {payload}")
        check("…with the distinct AAA-unreachable message, not 'wrong password'",
              "aaa server" in str(payload.get("error", "")).lower(), payload)

        status, payload, _h = call("GET", "/api/audit?limit=5000", token=admin_cookie)
        unreachable_events = [e for e in payload.get("events", [])
                              if e["action"] == "signin.tacacs_unreachable"]
        check("the AAA-unreachable case gets its own audit action, not "
              "signin.failed", bool(unreachable_events), unreachable_events)

        admin_cookie2, status, _p = login(DEFAULT_USER, ADMIN_PASSWORD)
        check("a local account signs in completely normally with "
              "tacacs_enabled on and the AAA server down",
              status == 200 and bool(admin_cookie2))
    finally:
        try:
            directory.stop()
        except Exception:
            pass

    # -------------------------------------------------------- auto-create
    print("auto-create: an unknown username, PASS, gets an account")
    auto_srv = FakeTacacsServer(lambda u, p, h: _reply_bytes(
        h["session_id"], SHARED_SECRET, h["seq_no"] + 1,
        tacacsclient.STATUS_PASS if p == "correct-horse" else tacacsclient.STATUS_FAIL))
    try:
        status, payload, _h = enable_tacacs(auto_srv, auto_create=True,
                                            default_role="operator")
        check("setup: tacacs re-enabled with auto-create on, role operator",
              status == 200, f"{status} {payload}")
        check("setup: the account does not exist yet",
              service.app_db.user("newguy") is None)

        newguy_cookie, status, payload = login("newguy", "correct-horse")
        check("an unknown username that PASSes is auto-created and signed in",
              status == 200 and bool(newguy_cookie), f"{status} {payload}")
        row = service.app_db.user("newguy")
        check("…with auth_source tacacs and no local password hash",
              row is not None and row["auth_source"] == "tacacs" and row["password"] == "",
              dict(row) if row else None)
        grants = service.app_db.permissions_for("newguy")
        check("…and the operator role's grants",
              grants == permissions.role_grants("operator"), grants)

        audit_rows = [e for e in
                     call("GET", "/api/audit?limit=5000", token=admin_cookie)[1]
                     .get("events", []) if e.get("target") == "newguy"]
        check("the auto-create is audited as user.autocreate",
              any(e["action"] == "user.autocreate" for e in audit_rows), audit_rows)

        newguy_cookie2, status, payload = login("newguy", "correct-horse")
        check("a second sign-in reuses the same (now-existing) account, "
              "does not try to create it again",
              status == 200 and bool(newguy_cookie2), f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/login", {"username": "nosuchperson", "password": "wrong"})
        check("an unknown username that FAILs is not created",
              status == 401 and service.app_db.user("nosuchperson") is None,
              f"{status} {payload}")

        print("auto-create off: an unknown username gets the plain 401")
        status, payload, _h = enable_tacacs(auto_srv, auto_create=False)
        check("setup: auto-create turned off", status == 200, f"{status} {payload}")
        status, payload, _h = call(
            "POST", "/api/login", {"username": "anotherperson", "password": "correct-horse"})
        check("with auto-create off, an unknown username is refused and no "
              "account is created",
              status == 401 and service.app_db.user("anotherperson") is None,
              f"{status} {payload}")
    finally:
        auto_srv.stop()

    # ------------------------------------------ auto-create + AAA outage
    print("auto-create + AAA outage: unknown username holds no login slot "
         "past the negative cache")
    stall_srv = FakeTacacsServer(_HANG_FOREVER)
    try:
        status, payload, _h = enable_tacacs(stall_srv, auto_create=True,
                                            default_role="viewer",
                                            extra_values={"tacacs_timeout_s": 1})
        check("setup: tacacs pointed at a server that never answers",
              status == 200, f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/login", {"username": "brandnewperson", "password": "whatever"})
        check("unknown username + AAA outage: refused, not a 500",
              status == 401, f"{status} {payload}")
        check("...with the distinct AAA-unreachable message, not 'wrong password'",
              "aaa server" in str(payload.get("error", "")).lower(), payload)
        check("...and no account was created",
              service.app_db.user("brandnewperson") is None)

        conns_after_first = stall_srv.connections
        check("...the first attempt actually reached the server",
              conns_after_first >= 1, conns_after_first)

        status, payload, _h = call(
            "POST", "/api/login", {"username": "brandnewperson", "password": "whatever"})
        check("a second immediate attempt also fails closed, not a 500",
              status == 401, f"{status} {payload}")
        check("...answered from the negative cache without opening a new "
              "socket to the AAA server",
              stall_srv.connections == conns_after_first,
              (stall_srv.connections, conns_after_first))

        from netpath.web.service import TacacsUnavailable
        try:
            service.authenticate_tacacs("brandnewperson", "whatever", "127.0.0.1")
            paused = ""
        except TacacsUnavailable as exc:
            paused = str(exc)
        check("the paused refusal carries the original cause and says it is paused",
              "(retry paused)" in paused and "reachable" in paused.lower(), paused)
        service.apply_global_settings({"tacacs_timeout_s": 1})
        check("a settings save clears the pause",
              service._tacacs_outage_until == 0.0, service._tacacs_outage_until)
        try:
            service.authenticate_tacacs("brandnewperson", "whatever", "127.0.0.1")
        except TacacsUnavailable:
            pass
        check("...so the next attempt reaches the server again",
              stall_srv.connections == conns_after_first + 1,
              (stall_srv.connections, conns_after_first))
    finally:
        stall_srv.stop()

    print("tacacs disabled: a tacacs account cannot sign in")
    status, payload, _h = call(
        "POST", "/api/settings", {"scope": "global", "values": {"tacacs_enabled": False}},
        token=admin_cookie)
    check("setup: tacacs turned off", status == 200, f"{status} {payload}")
    status, payload, _h = call(
        "POST", "/api/login", {"username": "alice", "password": "correct-horse"})
    check("a tacacs-mapped account cannot sign in while the feature is off",
          status == 401, f"{status} {payload}")

    # ----------------------------------------------------------- settings
    print("settings: tacacs_* keys are administrator-only")
    from netpath.auth import hash_password
    service.app_db.add_user("write-only", hash_password("WriteOnlyPW2026"), must_change=False)
    service.app_db.set_permissions("write-only", {"settings": permissions.WRITE})
    write_only_cookie, status, _p = login("write-only", "WriteOnlyPW2026")
    check("setup: the settings:write (non-admin) account can sign in",
          status == 200 and bool(write_only_cookie))

    status, payload, _h = call(
        "POST", "/api/settings",
        {"scope": "global", "values": {"tacacs_enabled": True}}, token=write_only_cookie)
    check("a settings:write (non-admin) account cannot change tacacs_enabled",
          status == 403, f"{status} {payload}")
    status, payload, _h = call(
        "POST", "/api/settings",
        {"scope": "global", "values": {"tacacs_secret": "whatever"}},
        token=write_only_cookie)
    check("…nor tacacs_secret", status == 403, f"{status} {payload}")

    print("GET settings: tacacs_secret_set, never the secret itself")
    status, payload, _h = call(
        "POST", "/api/settings",
        {"scope": "global", "values": {"tacacs_secret": SHARED_SECRET}},
        token=admin_cookie)
    check("setup: the admin saves a tacacs shared secret", status == 200,
          f"{status} {payload}")
    status, payload, _h = call("GET", "/api/config", token=admin_cookie)
    settings = payload.get("settings", {})
    check("tacacs_secret_set is true once a secret is saved",
          settings.get("tacacs_secret_set") is True, settings.get("tacacs_secret_set"))
    check("the raw secret is never present anywhere in the response",
          SHARED_SECRET not in json.dumps(payload), "leaked")
    check("tacacs_secret_enc itself is never returned either",
          "tacacs_secret_enc" not in settings, sorted(settings))

    print("GET /api/config for a caller with no settings:read hides tacacs_* "
         "the same way it hides ldap_*")
    status, payload, _h = call("GET", "/api/config", token=alice_cookie)
    check("an account without settings:read does not see tacacs_secret_set",
          "tacacs_secret_set" not in payload.get("settings", {}), payload.get("settings", {}))

    # ------------------------------------------------------- tacacs-test
    print("POST /api/settings/tacacs-test")
    test_srv = FakeTacacsServer(credentialed)
    try:
        status, payload, _h = call(
            "POST", "/api/settings/tacacs-test",
            {"username": "alice", "password": "correct-horse",
             "servers": f"{test_srv.host}:{test_srv.port}", "secret": SHARED_SECRET},
            token=admin_cookie)
        check("tacacs-test: a correct credential against explicit overrides answers ok",
              status == 200 and payload.get("ok") is True, f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/settings/tacacs-test",
            {"username": "alice", "password": "wrong",
             "servers": f"{test_srv.host}:{test_srv.port}", "secret": SHARED_SECRET},
            token=admin_cookie)
        check("tacacs-test: a wrong password answers ok=False, still 200",
              status == 200 and payload.get("ok") is False, f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/settings/tacacs-test",
            {"username": "alice", "password": "correct-horse",
             "servers": f"127.0.0.1:{free_tcp_port()}", "secret": SHARED_SECRET,
             "timeout_s": 1},
            token=admin_cookie)
        check("tacacs-test: an unreachable server answers ok=False with a "
              "reach-the-server message",
              status == 200 and payload.get("ok") is False
              and "reach" in str(payload.get("message", "")).lower(),
              f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/settings/tacacs-test",
            {"username": "alice", "password": "correct-horse"}, token=write_only_cookie)
        check("tacacs-test is refused (403) for a non-admin caller",
              status == 403, f"{status} {payload}")
    finally:
        test_srv.stop()

    # ------------------------------------------------- direct Service unit checks
    print("Service.authenticate_tacacs: over-long password, bad role, bad secret")

    long_password = "x" * 256
    ok = service.authenticate_tacacs("alice", long_password)
    check("a password over 255 bytes is a plain False reject, before any I/O",
          ok is False, ok)

    status, payload, _h = call(
        "POST", "/api/settings", {"scope": "global", "values": {
            "tacacs_enabled": True, "tacacs_servers": "127.0.0.1:1",
            "tacacs_auto_create": True, "tacacs_default_role": "viewer"}},
        token=admin_cookie)
    check("setup: tacacs re-enabled for the role/secret checks below",
          status == 200, f"{status} {payload}")
    # apply_global_settings bypasses post_global_settings' own validation --
    # simulates a role that was valid when stored and no longer is.
    service.apply_global_settings({"tacacs_default_role": "not-a-real-role"})
    status, payload, _h = call(
        "POST", "/api/login", {"username": "roleprobe", "password": "whatever"})
    check("an unknown tacacs_default_role is refused before add_user runs, "
         "not a 500", status == 401, f"{status} {payload}")
    check("...and no half-created account is left behind",
          service.app_db.user("roleprobe") is None)
    service.apply_global_settings({"tacacs_default_role": "viewer"})

    service.apply_global_settings({"tacacs_secret_enc": "not valid base64 at all!!"})
    try:
        service.authenticate_tacacs("alice", "correct-horse")
        check("an undecodable stored secret raises TacacsUnavailable, not "
              "an unhandled exception", False)
    except Exception as exc:
        from netpath.web.service import TacacsUnavailable
        check("an undecodable stored secret raises TacacsUnavailable, not "
              "an unhandled exception", isinstance(exc, TacacsUnavailable),
              type(exc))

    print("FAILED: " + ", ".join(failures) if failures else "ALL TACACS+ ASSERTIONS PASSED")
finally:
    web.stop()
    deadline = time.time() + 20
    while time.time() < deadline and service.node_poller.worker_state():
        time.sleep(0.1)
    service.shutdown()

sys.exit(1 if failures else 0)
