"""LDAP simple-bind directory authentication (Tier 1 #10).

Three layers, cheapest first:

  1. The hand-rolled BER encoder, against a known-good byte vector composed
     by hand and cited to RFC 4511 fields (no server involved at all).
  2. netpath.ldapclient.simple_bind against a scripted fake LDAP server on a
     local socket (a thread, the same shape test_security_fixes.py's SMTP
     spy already uses) — success, invalidCredentials, referral, a garbage
     response, a stalled directory (read timeout), and the cleartext
     refusal, each asserting both the client's behaviour and what the fake
     server actually received.
  3. The real login route end to end: an ldap-mapped account signs in
     through the fake server, a wrong password is refused, the directory
     being down fails closed with its own distinct error, a local account
     is unaffected by any of it, and the last-local-admin safeguard holds.
"""
import http.client
import json
import os
import socket
import sys
import threading
import time

from _paths import free_tcp_port, tmpdir

TMPDIR = tmpdir("ldap_auth_")

from netpath import ldapclient
from netpath.web import Service, WebServer
from netpath.auth import DEFAULT_PASSWORD, DEFAULT_USER

failures = []


def check(label, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + label + (f"  {detail}" if detail else ""))
    if not condition:
        failures.append(label)


# =========================================================================
# 1. BER encoding: a known-good vector, byte for byte.
# =========================================================================
print("BER encoding — known-good vectors")

# dn="cn=a" (4 bytes: 63 6e 3d 61), password="pw" (2 bytes: 70 77),
# messageID=1. Built by hand against RFC 4511:
#
#   LDAPMessage ::= SEQUENCE { messageID, protocolOp }             (§4.1.1)
#     30 12                              SEQUENCE, length 18
#       02 01 01                         INTEGER messageID = 1
#       60 0d                            [APPLICATION 0] BindRequest, len 13
#         02 01 03                       INTEGER version = 3
#         04 04 63 6e 3d 61               OCTET STRING name = "cn=a"
#         80 02 70 77                     [0] OCTET STRING simple = "pw"
KNOWN_BIND_REQUEST = bytes([
    0x30, 0x12,
    0x02, 0x01, 0x01,
    0x60, 0x0d,
    0x02, 0x01, 0x03,
    0x04, 0x04, 0x63, 0x6e, 0x3d, 0x61,
    0x80, 0x02, 0x70, 0x77,
])
got = ldapclient.encode_bind_request(1, "cn=a", "pw")
check("BindRequest for a known dn/password/messageID matches byte for byte",
      got == KNOWN_BIND_REQUEST, got.hex())

# UnbindRequest ::= [APPLICATION 2] NULL (§4.3): tag 0x42, zero-length,
# inside the same LDAPMessage envelope.
KNOWN_UNBIND = bytes([0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00])
check("UnbindRequest matches byte for byte",
      ldapclient.encode_unbind_request(1) == KNOWN_UNBIND,
      ldapclient.encode_unbind_request(1).hex())

# A longer dn/password exercises the long-form BER length (>= 128 bytes) on
# the OCTET STRING content — X.690 §8.1.3's other branch, untouched by the
# vector above.
long_password = "x" * 200
encoded = ldapclient.encode_bind_request(7, "cn=long", long_password)
# ...80 <len> for the simple-auth OCTET STRING: 200 needs one length-of-
# length byte (0x81) followed by the length itself (0xc8 = 200).
check("a >=128-byte value uses the BER long-length form",
      b"\x80\x81\xc8" + long_password.encode() in encoded, encoded[-5:].hex())

# Round-trips through the client's own request-side reader (used by the
# fake server below) prove decode agrees with encode independently of the
# hand-built vector above.


def _read_bind_request(data: bytes):
    tag, envelope, _end = ldapclient._read_tlv(data, 0)
    assert tag == 0x30
    tag, _mid, pos = ldapclient._read_tlv(envelope, 0)
    assert tag == 0x02
    tag, op, pos = ldapclient._read_tlv(envelope, pos)
    assert tag == 0x60
    tag, _version, p = ldapclient._read_tlv(op, 0)
    tag, dn_bytes, p = ldapclient._read_tlv(op, p)
    tag, pw_bytes, p = ldapclient._read_tlv(op, p)
    return dn_bytes.decode("utf-8"), pw_bytes.decode("utf-8")


dn, pw = _read_bind_request(KNOWN_BIND_REQUEST)
check("the known vector round-trips back to the same dn/password",
      (dn, pw) == ("cn=a", "pw"), (dn, pw))


def _bind_response(message_id: int, result_code: int, matched_dn: bytes = b"",
                   diagnostic: bytes = b"", referral: bytes | None = None) -> bytes:
    """A BindResponse built the same TLV-by-TLV way the client's own
    encoder is (RFC 4511 §4.1.9/§4.2), used to script the fake server's
    replies below without duplicating the production encoder verbatim."""
    result = ldapclient._ber_tlv(0x0A, bytes([result_code & 0xFF])) if result_code < 128 \
        else ldapclient._ber_tlv(0x0A, result_code.to_bytes(2, "big"))
    body = (result
            + ldapclient._ber_tlv(0x04, matched_dn)
            + ldapclient._ber_tlv(0x04, diagnostic))
    if referral is not None:
        body += ldapclient._ber_tlv(0xA3, ldapclient._ber_tlv(0x04, referral))
    op = ldapclient._ber_tlv(0x61, body)
    return ldapclient._ber_tlv(0x30, ldapclient._ber_integer(message_id) + op)


# Decoding the fixtures the fake server below sends is exercised implicitly
# by every simple_bind() call further down; this pins the decoder directly
# against one built independently of simple_bind's own request path.
success_bytes = _bind_response(1, 0)
decoded = ldapclient.decode_bind_response(success_bytes)
check("decode_bind_response reads a hand-built success response",
      decoded["result_code"] == 0 and decoded["referral"] is False, decoded)

invalid_bytes = _bind_response(1, 49, diagnostic=b"bad credentials")
decoded = ldapclient.decode_bind_response(invalid_bytes)
check("…and an invalidCredentials one, diagnostic message included",
      decoded["result_code"] == 49
      and decoded["diagnostic_message"] == "bad credentials", decoded)

referral_bytes = _bind_response(1, 10, referral=b"ldap://elsewhere/dc=x")
decoded = ldapclient.decode_bind_response(referral_bytes)
check("…and a referral, flagged as one",
      decoded["result_code"] == 10 and decoded["referral"] is True, decoded)

for garbage, why in [
        (b"\x30\x80", "an indefinite length, which this decoder refuses"),
        (b"\x02\x01\x01", "not even a SEQUENCE"),
        (b"\x30\x05\x02\x01\x01", "truncated mid-value"),
        (b"", "empty")]:
    try:
        ldapclient.decode_bind_response(garbage)
        raised = False
    except ldapclient.LDAPProtocolError:
        raised = True
    check(f"garbage input is refused as LDAPProtocolError ({why})", raised,
          garbage.hex())

# =========================================================================
# 2. safe_dn_username / render_bind_dn: reject, never escape.
# =========================================================================
print("DN-safe username validation")

for good in ("alice", "alice.smith", "alice-smith", "alice_2", "A1"):
    try:
        ldapclient.safe_dn_username(good)
        ok = True
    except ldapclient.LDAPConfigError:
        ok = False
    check(f"a legitimate username is accepted: {good!r}", ok)

for bad in ('alice,evil', 'alice+evil', 'alice"evil', "alice\\evil",
           "alice<evil", "alice>evil", "alice;evil", "alice=evil",
           "#alice", " alice", "alice ", "", "al ice"):
    try:
        ldapclient.safe_dn_username(bad)
        rejected = False
    except ldapclient.LDAPConfigError:
        rejected = True
    check(f"a DN-metacharacter-bearing username is rejected: {bad!r}", rejected)

try:
    ldapclient.render_bind_dn(
        "uid={username},ou=people,dc=example,dc=com", "alice,evil")
    injected = False
except ldapclient.LDAPConfigError:
    injected = True
check("a template substitution cannot inject an extra RDN", injected)

try:
    ldapclient.render_bind_dn("dc=example,dc=com", "alice")
    no_slot_refused = False
except ldapclient.LDAPConfigError:
    no_slot_refused = True
check("a template with no {username} slot is refused", no_slot_refused)

check("a valid template renders the expected dn",
      ldapclient.render_bind_dn("uid={username},ou=people,dc=example,dc=com", "alice")
      == "uid=alice,ou=people,dc=example,dc=com")


# =========================================================================
# 3. simple_bind() against a scripted fake LDAP server on a local socket.
# =========================================================================

class FakeLdapServer:
    """A minimal, single-purpose LDAP stand-in: accept a connection, read
    exactly one BindRequest, hand (dn, password) to `respond`, and write
    back whatever bytes it returns (or nothing at all, if it returns None
    — simulating a directory that accepts a connection and then hangs).

    Threaded, like the SMTP spy in test_security_fixes.py. `received`
    records every (dn, password) actually parsed off the wire, so a test
    can assert what the server saw, not just what the client claims it
    sent — the whole point of testing against a real socket instead of
    mocking simple_bind's internals.
    """

    def __init__(self, respond, host: str = "127.0.0.1"):
        # `host` is either bound literally (an IPv6 test passes "::1") — the
        # family follows from whether it parses as IPv6, same as any real
        # ldap_url would decide it via getaddrinfo.
        self.respond = respond
        self.host = host
        self.received: list[tuple[str, str]] = []
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

    def url(self, tls: bool = False) -> str:
        # A literal IPv6 host needs its own [brackets] in the URL, same as
        # any browser address bar — urlparse (and ldapclient._parse_url)
        # requires them to tell the host apart from a port's own colon.
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{'ldaps' if tls else 'ldap'}://{host}:{self.port}"

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
            raw = ldapclient._recv_message(conn)
            dn, password = _read_bind_request(raw)
            self.received.append((dn, password))
            reply = self.respond(dn, password)
            if reply is not None:
                conn.sendall(reply)
                # Best-effort drain of the client's UnbindRequest so its own
                # socket.close() is a clean FIN, not a reset.
                conn.settimeout(1)
                try:
                    conn.recv(4096)
                except OSError:
                    pass
            # else: deliberately never answer (the "stalled directory" case)
            # — the connection is simply held open until the client's own
            # timeout gives up on it or this thread exits with the process.
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


def _HANG_FOREVER(dn, password):    # noqa: N802 - sentinel, not a constant
    return None


print("scripted fake LDAP server — the four bind outcomes")

CREDS = {"uid=alice,ou=people,dc=example,dc=com": "correct-horse"}


def credentialed(dn, password):
    if dn in CREDS and CREDS[dn] == password:
        return _bind_response(1, 0)
    return _bind_response(1, 49, diagnostic=b"invalid credentials")


server = FakeLdapServer(credentialed)
try:
    ldapclient.simple_bind(server.url(), "uid=alice,ou=people,dc=example,dc=com",
                           "correct-horse", allow_cleartext=True)
    ok = True
except ldapclient.LDAPError:
    ok = False
check("success: the right dn/password binds without raising", ok)
check("…and the server actually received that exact dn/password",
      server.received[-1] == ("uid=alice,ou=people,dc=example,dc=com", "correct-horse"),
      server.received[-1])

try:
    ldapclient.simple_bind(server.url(), "uid=alice,ou=people,dc=example,dc=com",
                           "wrong", allow_cleartext=True)
    check("invalidCredentials: did not raise (unexpected)", False)
except ldapclient.LDAPInvalidCredentials:
    check("invalidCredentials: raises LDAPInvalidCredentials for a wrong password", True)
except ldapclient.LDAPError as exc:
    check("invalidCredentials: raises LDAPInvalidCredentials, not something else",
          False, repr(exc))
server.stop()

# Deterministic even where this host has no real IPv6 stack at all (the
# skippable end-to-end check just below needs one): simple_bind must go
# through socket.create_connection rather than a hard-coded AF_INET
# socket() + connect(), since create_connection is what resolves through
# getaddrinfo and can reach an AAAA-only host or an IPv6 literal at all —
# a bare AF_INET socket never could, whatever this test host supports.
real_create_connection = socket.create_connection
cc_calls = []


def spy_create_connection(*args, **kwargs):
    cc_calls.append((args, kwargs))
    return real_create_connection(*args, **kwargs)


socket.create_connection = spy_create_connection
cc_server = FakeLdapServer(credentialed)
try:
    ldapclient.simple_bind(cc_server.url(), "uid=alice,ou=people,dc=example,dc=com",
                           "correct-horse", allow_cleartext=True)
    check("simple_bind connects through socket.create_connection, not a "
          "hard-coded AF_INET socket", len(cc_calls) == 1, cc_calls)
finally:
    socket.create_connection = real_create_connection
    cc_server.stop()

print("IPv6: simple_bind reaches a directory on an IPv6 literal")
try:
    ipv6_server = FakeLdapServer(credentialed, host="::1")
except OSError as exc:
    # No IPv6 loopback on this host/container — every other check here
    # still ran and still matters, so this one check skips rather than
    # failing the whole suite.
    ipv6_server = None
    print(f"SKIP  IPv6 bind test: ::1 is not available here ({exc})")
if ipv6_server is not None:
    try:
        ldapclient.simple_bind(ipv6_server.url(),
                               "uid=alice,ou=people,dc=example,dc=com",
                               "correct-horse", allow_cleartext=True)
        ok = True
    except ldapclient.LDAPError:
        ok = False
    check("simple_bind connects to an ldap_url on an IPv6 literal ([::1])", ok)
    check("…and the fake server actually received the bind over that socket",
          ipv6_server.received[-1] ==
          ("uid=alice,ou=people,dc=example,dc=com", "correct-horse"),
          ipv6_server.received[-1] if ipv6_server.received else None)
    ipv6_server.stop()

referral_server = FakeLdapServer(lambda dn, pw: _bind_response(
    1, 10, referral=b"ldap://elsewhere.example.com/dc=x"))
try:
    ldapclient.simple_bind(referral_server.url(), "uid=alice,ou=people,dc=example,dc=com",
                           "anything", allow_cleartext=True)
    check("referral: did not raise (unexpected)", False)
except ldapclient.LDAPReferralError:
    check("referral: raises LDAPReferralError rather than following it", True)
except ldapclient.LDAPError as exc:
    check("referral: raises LDAPReferralError, not something else", False, repr(exc))
referral_server.stop()

garbage_server = FakeLdapServer(lambda dn, pw: b"\x30\x80")  # indefinite length
try:
    ldapclient.simple_bind(garbage_server.url(), "uid=alice,ou=people,dc=example,dc=com",
                           "anything", allow_cleartext=True)
    check("garbage response: did not raise (unexpected)", False)
except ldapclient.LDAPProtocolError:
    check("garbage response: raises LDAPProtocolError", True)
except ldapclient.LDAPError as exc:
    check("garbage response: raises LDAPProtocolError, not something else",
          False, repr(exc))
garbage_server.stop()

print("a stalled directory (read timeout)")
hang_server = FakeLdapServer(_HANG_FOREVER)
started = time.time()
try:
    ldapclient.simple_bind(hang_server.url(), "uid=alice,ou=people,dc=example,dc=com",
                           "anything", timeout=0.5, allow_cleartext=True)
    check("a directory that never answers: did not raise (unexpected)", False)
except ldapclient.LDAPConnectError:
    elapsed = time.time() - started
    check("a directory that never answers times out as LDAPConnectError, "
          "within the configured budget", elapsed < 3.0, f"{elapsed:.2f}s")
except ldapclient.LDAPError as exc:
    check("a directory that never answers raises LDAPConnectError, not "
          "something else", False, repr(exc))
hang_server.stop()

print("a directory that is not there at all")
dead_port = free_tcp_port()   # nothing is listening on it
try:
    ldapclient.simple_bind(f"ldap://127.0.0.1:{dead_port}",
                           "uid=alice,ou=people,dc=example,dc=com", "anything",
                           timeout=2, allow_cleartext=True)
    check("connecting to a closed port: did not raise (unexpected)", False)
except ldapclient.LDAPConnectError:
    check("connecting to a closed port raises LDAPConnectError", True)
except ldapclient.LDAPError as exc:
    check("connecting to a closed port raises LDAPConnectError, not "
          "something else", False, repr(exc))

print("cleartext refusal")
refusal_server = FakeLdapServer(lambda dn, pw: _bind_response(1, 0))
try:
    ldapclient.simple_bind(refusal_server.url(), "uid=alice,ou=people,dc=example,dc=com",
                           "anything")     # allow_cleartext defaults to False
    check("ldap:// without allow_cleartext: did not raise (unexpected)", False)
except ldapclient.LDAPConfigError:
    check("ldap:// without allow_cleartext raises LDAPConfigError", True)
except ldapclient.LDAPError as exc:
    check("ldap:// without allow_cleartext raises LDAPConfigError, not "
          "something else", False, repr(exc))
check("…and it never even opened a connection to try",
      refusal_server.connections == 0, refusal_server.connections)
refusal_server.stop()

try:
    ldapclient.simple_bind("ldaps://127.0.0.1:1", "uid=alice,ou=people,dc=example,dc=com",
                           "anything")     # ldaps:// needs no opt-in
    check("ldaps:// with no opt-in: refused before even trying to connect "
          "(unexpected — should have attempted TLS and failed to connect "
          "instead)", False)
except ldapclient.LDAPConfigError:
    check("ldaps:// with no opt-in is refused for cleartext (unexpected — "
          "ldaps:// needs no opt-in)", False)
except ldapclient.LDAPConnectError:
    check("ldaps:// needs no cleartext opt-in — it fails on the connection "
          "attempt itself, not the cleartext guard", True)


# =========================================================================
# 4. The real login route, end to end.
# =========================================================================
print()
print("the login route, end to end")

service = Service(
    os.path.join(TMPDIR, "netpath.db"), os.path.join(TMPDIR, "flows.db"),
    os.path.join(TMPDIR, "syslog.db"), os.path.join(TMPDIR, "app.db"),
    os.path.join(TMPDIR, "ipam.db"), os.path.join(TMPDIR, "snmptraps.db"),
    os.path.join(TMPDIR, "nodes.db"), os.path.join(TMPDIR, "alerts.db"),
    os.path.join(TMPDIR, "wireless.db"), os.path.join(TMPDIR, "configrx.db"))
service.start()

http_port = free_tcp_port()
web = WebServer(service, host="127.0.0.1", port=http_port, certfile=None, keyfile=None)
assert web.start(block=False), web.error
print(f"server up on 127.0.0.1:{http_port}")

ADMIN_PASSWORD = "LdapSuiteAdmin2026"


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
    check("…and can sign in again with the new one", status == 200)

    directory = FakeLdapServer(credentialed)   # reuses CREDS from part 3
    try:
        status, payload, _h = call(
            "POST", "/api/settings",
            {"scope": "global",
             "values": {"ldap_enabled": True, "ldap_url": directory.url(),
                        "ldap_bind_dn_template":
                            "uid={username},ou=people,dc=example,dc=com",
                        "ldap_allow_cleartext": True, "ldap_timeout_s": 3}},
            token=admin_cookie)
        check("an administrator can turn LDAP sign-in on", status == 200,
              f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/users",
            {"username": "alice", "auth_source": "ldap",
             "grants": {"nodes": "read"}}, token=admin_cookie)
        check("an ldap-mapped account can be created",
              status == 200 and payload.get("auth_source") == "ldap",
              f"{status} {payload}")
        check("…and stores no local password hash",
              service.app_db.user("alice")["password"] == "")

        alice_cookie, status, payload = login("alice", "correct-horse")
        check("the ldap account authenticates via the real login route "
              "through the fake directory", status == 200 and bool(alice_cookie),
              f"{status} {payload}")
        check("…with must_change already false (no local password to change)",
              payload.get("must_change") is False, payload)
        status, payload, _h = call("GET", "/api/nodes/devices", token=alice_cookie)
        check("…and its session carries its own grants",
              status == 200, f"{status} {payload}")

        status, payload, _h = call(
            "POST", "/api/login", {"username": "alice", "password": "wrong"})
        check("a wrong password against the directory is refused",
              status == 401, f"{status} {payload}")

        status, payload, _h = call("GET", "/api/audit?limit=5000", token=admin_cookie)
        actions_for_alice = [(e["action"], e["detail"]) for e in payload.get("events", [])
                             if e["target"] == "alice"]
        check("the failed directory bind is audited, without a password",
              any(a == "signin.failed" and "wrong" not in d and "correct-horse" not in d
                  for a, d in actions_for_alice),
              actions_for_alice)
        audit_text = json.dumps(payload)
        check("no audited detail anywhere contains the real password",
              "correct-horse" not in audit_text, "leaked")

        directory.stop()
        status, payload, _h = call(
            "POST", "/api/login", {"username": "alice", "password": "correct-horse"})
        check("a directory that is down fails closed (401, not a 500)",
              status == 401, f"{status} {payload}")
        check("…with a distinct, honest message rather than 'wrong password'",
              "reach" in str(payload.get("error", "")).lower(), payload)

        status, payload, _h = call("GET", "/api/audit?limit=5000", token=admin_cookie)
        unreachable_events = [e for e in payload.get("events", [])
                              if e["action"] == "signin.ldap_unreachable"]
        check("the directory-unreachable case gets its own audit action, "
              "not signin.failed", bool(unreachable_events), unreachable_events)

        admin_cookie2, status, _p = login(DEFAULT_USER, ADMIN_PASSWORD)
        check("a local account signs in completely normally with "
              "ldap_enabled on and the directory down",
              status == 200 and bool(admin_cookie2))
    finally:
        try:
            directory.stop()
        except Exception:
            pass

    # ------------------------------------------------- last-local-admin guard
    print("the last-local-admin safeguard")
    directory2 = FakeLdapServer(lambda dn, pw: _bind_response(1, 0))   # anything binds
    try:
        status, payload, _h = call(
            "POST", "/api/settings",
            {"scope": "global",
             "values": {"ldap_enabled": True, "ldap_url": directory2.url(),
                        "ldap_bind_dn_template":
                            "uid={username},ou=people,dc=example,dc=com",
                        "ldap_allow_cleartext": True, "ldap_timeout_s": 3}},
            token=admin_cookie)
        check("LDAP re-enabled against the second fake directory", status == 200)

        # Two local admins besides the seeded one is more accounts than the
        # guard needs, but sets up the realistic chain below without any
        # account ever having to edit its own grants (post_user_permissions
        # refuses that outright, on purpose).
        all_write = {}
        from netpath import permissions as _permissions_mod
        for module in _permissions_mod.MODULES:
            all_write[module] = "write"

        status, payload, _h = call(
            "POST", "/api/users",
            {"username": "admin2", "password": "Corr3ct-Horse-Battery",
             "auth_source": "local", "grants": all_write}, token=admin_cookie)
        check("a second local admin can be created", status == 200, payload)
        row = service.app_db.user("admin2")
        service.app_db.set_password("admin2", row["password"], must_change=False)

        status, payload, _h = call(
            "POST", "/api/users",
            {"username": "ldapadmin", "auth_source": "ldap", "grants": all_write},
            token=admin_cookie)
        check("an ldap-sourced administrator can be created", status == 200, payload)

        admin2_cookie, status, _p = login("admin2", "Corr3ct-Horse-Battery")
        check("admin2 can sign in", status == 200)

        # admin2 (a different, local, administrator) demotes the seeded
        # `admin` account — not self-edit, since the actor is admin2 and the
        # target is `admin`. Still safe: admin2 itself remains a local
        # admin, so this is expected to succeed.
        status, payload, _h = call(
            "POST", "/api/users/permissions",
            {"username": DEFAULT_USER, "grants": {"nodes": "read"}},
            token=admin2_cookie)
        check("demoting the seeded admin succeeds while another local "
              "admin (admin2) remains", status == 200, f"{status} {payload}")

        ldapadmin_cookie, status, payload = login("ldapadmin", "anything")
        check("the ldap administrator can sign in through the directory",
              status == 200 and bool(ldapadmin_cookie), f"{status} {payload}")

        # Now the only local administrator left is admin2. ldapadmin (itself
        # an ldap account) tries to take admin2's admin grant away — which
        # would leave administration entirely in directory accounts.
        status, payload, _h = call(
            "POST", "/api/users/permissions",
            {"username": "admin2", "grants": {"nodes": "read"}},
            token=ldapadmin_cookie)
        check("demoting the last LOCAL administrator is refused even though "
              "an ldap administrator would still remain",
              status == 400
              and "local" in str(payload.get("error", "")).lower(),
              f"{status} {payload}")
        check("…and admin2's grant is actually unchanged",
              service.app_db.permissions_for("admin2").get("admin") == "write")

        # The same guard, exercised directly (it is mostly a backstop: no
        # route ever lets an account edit its own grants or delete itself,
        # so this is the only way to see it fire with nothing else in the
        # way — the same approach test_security_fixes.py's D8 uses for the
        # plain "last administrator" guard this one extends).
        import netpath.web.api as api_mod
        try:
            api_mod._last_admin_guard(service, "admin2", keeps_admin=False)
            refused = False
        except ValueError as exc:
            refused = "local" in str(exc).lower()
        check("_last_admin_guard refuses directly, too, citing 'local'", refused)
    finally:
        try:
            directory2.stop()
        except Exception:
            pass

    print("FAILED: " + ", ".join(failures) if failures else "ALL LDAP ASSERTIONS PASSED")
finally:
    web.stop()
    deadline = time.time() + 20
    while time.time() < deadline and service.node_poller.worker_state():
        time.sleep(0.1)
    service.shutdown()

sys.exit(1 if failures else 0)

