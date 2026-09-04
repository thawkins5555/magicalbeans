"""A minimal LDAPv3 simple-bind client — enough to verify a username and
password against a directory, and nothing else.

The standard library ships no LDAP client, and this application runs on the
standard library alone by policy (see CREDENTIAL-SECURITY.md's own framing
of that constraint for the secret store). Pulling in python-ldap or ldap3
would mean shipping a C extension or a third-party dependency tree onto a
box whose job is watching a network, for a feature that needs exactly one
thing: send a BindRequest, read the BindResponse's resultCode. So this hand-
rolls the handful of ASN.1 BER structures RFC 4511 defines for that one
exchange and stops there.

What this deliberately does NOT do:
  * No search. There is nothing here to look an entry up by; the caller
    must already know (or be able to template) the bind DN.
  * No referrals. A BindResponse carrying a referral is treated as a
    failure with a clear message — following one would mean implementing
    LDAP URL parsing and a second connection, for a directory topology this
    application has no way to reason about safely.
  * No SASL, no StartTLS. Only two transports: `ldaps://` (TLS from the
    first byte, via ssl.create_default_context — the same trust store every
    other TLS client in this codebase uses) or `ldap://` with the
    password sent as plaintext, refused unless the caller explicitly opts
    in (`allow_cleartext=True`) — see simple_bind's docstring.
  * No connection pooling, no retries. One bind is one TCP (or TLS)
    connection, opened, used once, unbound and closed.

RFC 4511 §4.1.1 (LDAPMessage), §4.2 (BindRequest/BindResponse) and §4.1.9
(LDAPResult, which BindResponse's non-referral fields come from) are the
sections this file implements; each encoder/decoder below cites the field
it is building or reading.
"""

from __future__ import annotations

import hmac
import re
import socket
import ssl
from urllib.parse import urlparse

DEFAULT_LDAP_PORT = 389
DEFAULT_LDAPS_PORT = 636

# How long a connect() or a read may take before this gives up and reports
# the directory unreachable rather than hanging the login route (and the
# HTTP thread behind it) indefinitely. A login is a synchronous request a
# person or a script is waiting on, not a background poll, so this is
# short — long enough for a real directory on the same network, nowhere
# near long enough to make an operator wonder if the page has frozen.
DEFAULT_TIMEOUT_S = 10.0

# What a bind DN template's {username} slot may safely contain. RFC 4514
# gives `, + " \ < > ; =` (and a leading '#' or leading/trailing space) a
# syntactic meaning inside a DN string; substituting any of those into a
# template unescaped lets the value reshape which entry the bind targets —
# an extra RDN, or a jump to an entirely different (perhaps higher-
# privileged) one. Escaping instead of rejecting is the usual advice for a
# general-purpose DN builder, but this is a login form for one application
# with one username grammar: every legitimate username already matches
# auth.USERNAME_RE (letters, digits, dot, dash, underscore — deliberately
# mirrored here rather than imported, so this module has no dependency on
# the web layer's account model and stays reusable/testable on its own).
# There is no legitimate input this regex rejects, and no escaping scheme
# to get subtly wrong, so reject on sight instead of trying to neutralise.
_SAFE_DN_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class LDAPError(Exception):
    """Base of everything this module raises."""


class LDAPConfigError(LDAPError):
    """The caller's own setup is wrong: an unusable URL, an empty bind DN
    template, or a plaintext bind attempted without opting in. Never sent
    a byte over the network."""


class LDAPConnectError(LDAPError):
    """Could not open (or lost) the connection at all: DNS, TCP refusal, a
    TLS handshake failure, or a timeout on connect or read. This is the
    "directory unreachable" case callers should fail closed on and log
    distinctly from "wrong password" — see Service.authenticate_ldap."""


class LDAPProtocolError(LDAPError):
    """A response arrived but is not a well-formed BindResponse: truncated
    BER, an unexpected tag, a length that runs past the data actually
    read. Garbage on the wire is not a credential problem; it is treated
    the same as LDAPConnectError by callers, but kept as its own type so a
    test (or an administrator reading the log) can tell "nothing answered"
    from "something answered nonsense"."""


class LDAPReferralError(LDAPError):
    """The directory answered with a referral (resultCode 10, or a
    referral field on any other result) rather than a plain success or
    failure. This client does not follow referrals — see the module
    docstring — so this is reported as its own outcome rather than folded
    into "wrong password"."""


class LDAPInvalidCredentials(LDAPError):
    """resultCode 49: the bind DN exists (or the directory does not say
    otherwise) but the password was wrong."""


class LDAPBindError(LDAPError):
    """Any other non-zero resultCode: no such object, unwilling to
    perform, and so on. Carries the numeric code and the directory's own
    diagnostic message."""

    def __init__(self, result_code: int, diagnostic_message: str):
        self.result_code = result_code
        self.diagnostic_message = diagnostic_message
        super().__init__(
            f"bind refused: resultCode={result_code}"
            + (f" ({diagnostic_message})" if diagnostic_message else ""))


def safe_dn_username(username: str) -> str:
    """`username`, unchanged, if it cannot alter the shape of a DN built by
    substituting it into a bind_dn_template; raises LDAPConfigError
    otherwise. See the module-level comment on _SAFE_DN_USERNAME_RE for why
    this rejects rather than escapes."""
    if not username or not _SAFE_DN_USERNAME_RE.match(username):
        raise LDAPConfigError(
            "This username cannot be used with the configured directory "
            "template: only letters, digits, dot, dash and underscore are "
            "allowed.")
    return username


def render_bind_dn(template: str, username: str) -> str:
    """`template` with {username} replaced by a validated `username`.
    Raises LDAPConfigError for an empty template or an unsafe username —
    both are configuration/input problems, not directory failures."""
    if not template or "{username}" not in template:
        raise LDAPConfigError(
            "ldap_bind_dn_template is not set, or has no {username} slot")
    return template.replace("{username}", safe_dn_username(username))


# --------------------------------------------------------------- BER: encode
#
# X.690 BER, minimal DER-style encoding (shortest form of everything) —
# LDAP does not require DER, but there is no reason to write a longer form
# than necessary, and a decoder that only has to handle one form is a
# decoder with fewer places to get wrong.

def _ber_length(n: int) -> bytes:
    """X.690 §8.1.3. Short form (one byte, high bit clear) under 128;
    long form (a length-of-length byte with the high bit set, then that
    many big-endian bytes) otherwise. LDAP messages here are at most a DN,
    a password and a little envelope, so the long form is only ever
    exercised by the tests' deliberately oversized inputs."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def _ber_integer(n: int) -> bytes:
    """X.690 §8.3: INTEGER, two's-complement, minimal length. messageID
    and version are always small non-negative values in this module, so
    this only needs to handle n >= 0 — a leading 0x00 pad byte is added
    when the high bit of the first content byte would otherwise be read as
    a sign bit."""
    if n < 0:
        raise ValueError("negative INTEGER is not needed or supported here")
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _ber_tlv(0x02, body)


# LDAPMessage ::= SEQUENCE (RFC 4511 §4.1.1)                        tag 0x30
# BindRequest ::= [APPLICATION 0] SEQUENCE, constructed              -> 0x60
# BindResponse ::= [APPLICATION 1] SEQUENCE, constructed             -> 0x61
# UnbindRequest ::= [APPLICATION 2] NULL, primitive                  -> 0x42
# AuthenticationChoice.simple ::= [0] OCTET STRING, primitive        -> 0x80
# LDAPResult.resultCode ::= ENUMERATED, primitive                    -> 0x0A
# LDAPResult.referral ::= [3] SEQUENCE OF LDAPURL, constructed       -> 0xA3
TAG_SEQUENCE = 0x30
TAG_BIND_REQUEST = 0x60
TAG_BIND_RESPONSE = 0x61
TAG_UNBIND_REQUEST = 0x42
TAG_AUTH_SIMPLE = 0x80
TAG_ENUMERATED = 0x0A
TAG_OCTET_STRING = 0x04
TAG_REFERRAL = 0xA3


def encode_bind_request(message_id: int, dn: str, password: str) -> bytes:
    """RFC 4511 §4.2:

        BindRequest ::= [APPLICATION 0] SEQUENCE {
             version                 INTEGER (1..127),
             name                    LDAPDN,
             authentication          AuthenticationChoice }
        AuthenticationChoice ::= CHOICE {
             simple                  [0] OCTET STRING, ... }

    wrapped in the LDAPMessage envelope every LDAP PDU travels in:

        LDAPMessage ::= SEQUENCE {
             messageID       MessageID,
             protocolOp      CHOICE { bindRequest BindRequest, ... } }
    """
    version = _ber_integer(3)
    name = _ber_tlv(TAG_OCTET_STRING, dn.encode("utf-8"))
    authentication = _ber_tlv(TAG_AUTH_SIMPLE, password.encode("utf-8"))
    bind_request = _ber_tlv(TAG_BIND_REQUEST, version + name + authentication)
    return _ber_tlv(TAG_SEQUENCE, _ber_integer(message_id) + bind_request)


def encode_unbind_request(message_id: int) -> bytes:
    """RFC 4511 §4.3: UnbindRequest ::= [APPLICATION 2] NULL — no content,
    just the tag and a zero length, inside the usual envelope. Sent
    best-effort before closing the socket; the server never answers it."""
    unbind_request = bytes([TAG_UNBIND_REQUEST, 0x00])
    return _ber_tlv(TAG_SEQUENCE, _ber_integer(message_id) + unbind_request)


# --------------------------------------------------------------- BER: decode

def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise LDAPProtocolError("truncated BER length")
    first = data[pos]
    pos += 1
    if first & 0x80 == 0:
        return first, pos
    n = first & 0x7F
    if n == 0:
        # Indefinite-length BER (X.690 §8.1.3.6) needs an end-of-contents
        # marker to close it, which is a BER-over-CER concept this
        # decoder does not implement; a real LDAP server never sends it.
        raise LDAPProtocolError("indefinite-length BER is not supported")
    if pos + n > len(data):
        raise LDAPProtocolError("truncated BER length")
    return int.from_bytes(data[pos:pos + n], "big"), pos + n


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos >= len(data):
        raise LDAPProtocolError("truncated BER data")
    tag = data[pos]
    length, pos = _read_length(data, pos + 1)
    value = data[pos:pos + length]
    if len(value) != length:
        raise LDAPProtocolError("truncated BER value")
    return tag, value, pos + length


def decode_bind_response(data: bytes) -> dict:
    """Parses one complete LDAPMessage wrapping a BindResponse and returns
    {"message_id", "result_code", "matched_dn", "diagnostic_message",
    "referral"} (the last a bool: whether a referral field was present).
    Raises LDAPProtocolError for anything that is not that shape."""
    tag, envelope, end = _read_tlv(data, 0)
    if tag != TAG_SEQUENCE:
        raise LDAPProtocolError(f"expected LDAPMessage SEQUENCE, got tag 0x{tag:02x}")
    if end != len(data):
        raise LDAPProtocolError("trailing bytes after the LDAPMessage")

    tag, id_bytes, pos = _read_tlv(envelope, 0)
    if tag != 0x02:
        raise LDAPProtocolError("expected INTEGER messageID")
    message_id = int.from_bytes(id_bytes, "big", signed=True) if id_bytes else 0

    tag, op, pos = _read_tlv(envelope, pos)
    if tag != TAG_BIND_RESPONSE:
        raise LDAPProtocolError(
            f"expected BindResponse [APPLICATION 1], got tag 0x{tag:02x}")

    # LDAPResult ::= SEQUENCE { resultCode ENUMERATED, matchedDN LDAPDN,
    #   diagnosticMessage LDAPString, referral [3] Referral OPTIONAL }
    # (RFC 4511 §4.1.9); BindResponse adds an optional serverSaslCreds
    # after these, which this client never requests and so never reads.
    tag, code_bytes, rp = _read_tlv(op, 0)
    if tag != TAG_ENUMERATED:
        raise LDAPProtocolError("expected ENUMERATED resultCode")
    result_code = int.from_bytes(code_bytes, "big", signed=True) if code_bytes else 0

    tag, matched_dn, rp = _read_tlv(op, rp)
    if tag != TAG_OCTET_STRING:
        raise LDAPProtocolError("expected OCTET STRING matchedDN")

    tag, diagnostic, rp = _read_tlv(op, rp)
    if tag != TAG_OCTET_STRING:
        raise LDAPProtocolError("expected OCTET STRING diagnosticMessage")

    referral = False
    if rp < len(op):
        tag, _value, rp = _read_tlv(op, rp)
        if tag == TAG_REFERRAL:
            referral = True
        # Anything else trailing (e.g. serverSaslCreds) is simply not this
        # client's business; it is neither an error nor a referral.

    return {
        "message_id": message_id,
        "result_code": result_code,
        "matched_dn": matched_dn.decode("utf-8", "replace"),
        "diagnostic_message": diagnostic.decode("utf-8", "replace"),
        "referral": referral,
    }


# ------------------------------------------------------------------ network

def _parse_url(url: str) -> tuple[bool, str, int]:
    """(use_tls, host, port). Accepts "ldap://" and "ldaps://" only."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("ldap", "ldaps"):
        raise LDAPConfigError(
            f"ldap_url must start with ldap:// or ldaps://, got {url!r}")
    if not parsed.hostname:
        raise LDAPConfigError(f"ldap_url has no host: {url!r}")
    use_tls = parsed.scheme == "ldaps"
    port = parsed.port or (DEFAULT_LDAPS_PORT if use_tls else DEFAULT_LDAP_PORT)
    return use_tls, parsed.hostname, port


def _recv_exact(sock, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise LDAPConnectError("the directory closed the connection early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_message(sock) -> bytes:
    """One complete BER TLV read off `sock` — the tag byte, then the
    length (short or long form), then exactly that many content bytes.
    Reads in three small pieces rather than one big `recv()` because
    nothing here can assume a whole LDAPMessage lands in one TCP segment."""
    tag = _recv_exact(sock, 1)
    first_len = _recv_exact(sock, 1)
    if first_len[0] & 0x80 == 0:
        length = first_len[0]
        header = tag + first_len
    else:
        n = first_len[0] & 0x7F
        if n == 0:
            raise LDAPProtocolError("indefinite-length BER is not supported")
        rest = _recv_exact(sock, n)
        length = int.from_bytes(rest, "big")
        header = tag + first_len + rest
    # A garbage or malicious length must not be handed straight to a
    # blocking recv() loop as a memory/time bomb — a real BindResponse is a
    # DN and a short message, nowhere near this.
    if length > 1 << 20:
        raise LDAPProtocolError("BindResponse claims an implausible length")
    value = _recv_exact(sock, length)
    return header + value


def simple_bind(url: str, dn: str, password: str, *,
                timeout: float = DEFAULT_TIMEOUT_S,
                allow_cleartext: bool = False) -> None:
    """Verify `dn`/`password` against the directory at `url`. Returns
    (nothing) on success; raises LDAPInvalidCredentials, LDAPReferralError,
    LDAPBindError, LDAPConnectError, LDAPProtocolError or LDAPConfigError
    otherwise. Always unbinds and closes the connection before returning,
    on every path — success, failure or exception.

    `url` must be "ldaps://host[:port]" (TLS from the first byte, via
    ssl.create_default_context — the platform trust store, exactly like
    every other outbound TLS client in this codebase) or "ldap://host[:port]"
    (no transport security at all: refused with LDAPConfigError unless
    `allow_cleartext` is explicitly True, because a simple bind's password
    is sent as plaintext inside the BindRequest and without TLS that means
    on the wire in the clear). There is no StartTLS support — see the
    module docstring for what this client deliberately does not do.
    """
    use_tls, host, port = _parse_url(url)
    if not use_tls and not allow_cleartext:
        raise LDAPConfigError(
            "ldap_url uses ldap:// (no transport security) and "
            "ldap_allow_cleartext is off — a simple bind sends the password "
            "as plaintext, which this refuses to do without an explicit "
            "opt-in. Use ldaps:// instead, or set ldap_allow_cleartext.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect((host, port))
            if use_tls:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
        except (OSError, ssl.SSLError) as exc:
            raise LDAPConnectError(f"could not reach {host}:{port}: {exc}") from exc

        message_id = 1
        try:
            sock.sendall(encode_bind_request(message_id, dn, password))
            raw = _recv_message(sock)
        except socket.timeout as exc:
            raise LDAPConnectError(
                f"{host}:{port} did not answer within {timeout:.0f}s") from exc
        except OSError as exc:
            raise LDAPConnectError(f"connection to {host}:{port} failed: {exc}") from exc

        response = decode_bind_response(raw)
        # A best-effort UnbindRequest either way: RFC 4511 §4.3 says the
        # client should send one before closing, and there is no response
        # to wait for, so a failure here must not shadow the real outcome
        # decided below.
        try:
            sock.sendall(encode_unbind_request(message_id))
        except OSError:
            pass

        if response["referral"] or response["result_code"] == 10:
            raise LDAPReferralError(
                "the directory returned a referral; this client does not "
                "follow referrals")
        if response["result_code"] == 0:
            return
        if response["result_code"] == 49:
            raise LDAPInvalidCredentials("invalid credentials")
        raise LDAPBindError(response["result_code"], response["diagnostic_message"])
    finally:
        try:
            sock.close()
        except OSError:
            pass


# hmac is imported for the one call sites that want an explicit
# constant-time comparison rather than relying on `==`/dict lookup being
# "good enough" for a 256-bit random value — see auth.hash_api_token's
# docstring for why that is a documented choice, not an oversight, and
# server.py's Bearer handling for where this is actually used.
def constant_time_hash_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
