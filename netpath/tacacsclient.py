"""A minimal TACACS+ (RFC 8907) client for PAP login authentication over one
shared secret. No AUTHOR, no ACCT, no CHAP/MSCHAP, no session reuse: one TCP
connection per login attempt. Modelled on ldapclient.py's shape.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket

DEFAULT_PORT = 49
DEFAULT_TIMEOUT_S = 5.0
MAX_SERVERS = 4
# The wire format's user/port/rem_addr/data lengths are each one byte.
MAX_FIELD_LEN = 255
# Well above a real AUTHEN REPLY's size -- guards recv() against a garbage/malicious length.
MAX_BODY_LEN = 65535

# TAC_PLUS_MAJOR_VER << 4 | TAC_PLUS_MINOR_VER_DEFAULT (0); kept as the header default.
VERSION = 0xC0
# minor_version 1 -- RFC 8907 5.4.2.2 requires this on a PAP START; tac_plus rejects 0xC0.
VERSION_PAP = 0xC1
ACCEPTED_VERSIONS = (VERSION, VERSION_PAP)
TYPE_AUTHEN = 0x01

SEQ_NO_START = 1
SEQ_NO_REPLY = 2

# TAC_PLUS_UNENCRYPTED_FLAG (RFC 8907 §4.1) -- never set on a request; a reply setting it is refused.
FLAG_UNENCRYPTED = 0x01

ACTION_LOGIN = 0x01
PRIV_LVL_MIN = 1
AUTHEN_TYPE_PAP = 0x02
AUTHEN_SERVICE_LOGIN = 0x01

STATUS_PASS = 0x01
STATUS_FAIL = 0x02
STATUS_GETDATA = 0x03
STATUS_GETUSER = 0x04
STATUS_GETPASS = 0x05
STATUS_RESTART = 0x06
STATUS_ERROR = 0x07
STATUS_FOLLOW = 0x21

_STATUS_NAMES = {
    STATUS_PASS: "PASS", STATUS_FAIL: "FAIL", STATUS_GETDATA: "GETDATA",
    STATUS_GETUSER: "GETUSER", STATUS_GETPASS: "GETPASS",
    STATUS_RESTART: "RESTART", STATUS_ERROR: "ERROR", STATUS_FOLLOW: "FOLLOW",
}


class TacacsError(Exception):
    """Base of everything this module raises."""


class TacacsConfigError(TacacsError):
    """Bad caller-side setup (servers string, secret, or an oversized field) -- never sent a byte."""


class TacacsConnectError(TacacsError):
    """No server in the list could be reached; carries the last connect/read error."""


class TacacsProtocolError(TacacsError):
    """A reply arrived but isn't a usable PASS/FAIL -- includes a wrong shared secret, so it is
    raised immediately rather than tried against the next server."""


_SERVER_SPLIT_RE = re.compile(r"[,\s]+")


def parse_servers(text: str) -> list[tuple[str, int]]:
    """`tacacs_servers` as stored -> [(host, port)]: comma/whitespace-separated
    "host[:port]" entries, default port DEFAULT_PORT, at most MAX_SERVERS.
    Raises TacacsConfigError for anything that does not parse, or is empty."""
    pieces = [p for p in _SERVER_SPLIT_RE.split(str(text or "").strip()) if p]
    if not pieces:
        raise TacacsConfigError("at least one TACACS+ server is required")
    if len(pieces) > MAX_SERVERS:
        raise TacacsConfigError(
            f"at most {MAX_SERVERS} TACACS+ servers are supported")
    return [_parse_one_server(piece) for piece in pieces]


def _parse_port(port_s: str, piece: str) -> int:
    try:
        port = int(port_s)
    except ValueError:
        raise TacacsConfigError(f"bad port in server {piece!r}")
    if not (1 <= port <= 65535):
        raise TacacsConfigError(f"port out of range in server {piece!r}")
    return port


def _parse_one_server(piece: str) -> tuple[str, int]:
    if piece.startswith("["):
        end = piece.find("]")
        if end == -1:
            raise TacacsConfigError(f"unmatched '[' in server {piece!r}")
        host = piece[1:end]
        rest = piece[end + 1:]
        if rest.startswith(":"):
            port = _parse_port(rest[1:], piece)
        elif rest == "":
            port = DEFAULT_PORT
        else:
            raise TacacsConfigError(f"junk after ']' in server {piece!r}")
    elif piece.count(":") > 1:
        host, port = piece, DEFAULT_PORT
    elif ":" in piece:
        host, _, port_s = piece.partition(":")
        port = _parse_port(port_s, piece)
    else:
        host, port = piece, DEFAULT_PORT
    if not host:
        raise TacacsConfigError(f"empty host in server {piece!r}")
    return host, port


# ------------------------------------------------------------------ header

def encode_header(*, session_id: bytes, seq_no: int, length: int, flags: int = 0,
                  version: int = VERSION, packet_type: int = TYPE_AUTHEN) -> bytes:
    """The 12-byte TACACS+ header (RFC 8907 §4.1): version, packet type,
    seq_no, flags, the 4-byte session_id, and the length of the (obfuscated)
    body that follows. `flags` defaults to 0 -- this client never sets
    FLAG_UNENCRYPTED on a request; it always obfuscates the body."""
    if len(session_id) != 4:
        raise TacacsConfigError("session_id must be exactly 4 bytes")
    if not (0 <= length <= 0xFFFFFFFF):
        raise TacacsConfigError("length does not fit the header's 32-bit field")
    return (bytes([version & 0xFF, packet_type & 0xFF, seq_no & 0xFF, flags & 0xFF])
            + session_id + length.to_bytes(4, "big"))


def decode_header(data: bytes) -> dict:
    """The inverse of encode_header, for tests and the reply path."""
    if len(data) != 12:
        raise TacacsProtocolError("a TACACS+ header is exactly 12 bytes")
    return {
        "version": data[0], "type": data[1], "seq_no": data[2], "flags": data[3],
        "session_id": data[4:8], "length": int.from_bytes(data[8:12], "big"),
    }


# -------------------------------------------------------------- obfuscation

def _pseudo_pad(session_id: bytes, key: bytes, version: int, seq_no: int,
                length: int) -> bytes:
    """RFC 8907 §4.5's chained-MD5 keystream, truncated to `length`:
    MD5_1 = MD5(session_id + key + version + seq_no)
    MD5_n = MD5(session_id + key + version + seq_no + MD5_{n-1})
    concatenated until there is enough of it."""
    header = session_id + key + bytes([version & 0xFF, seq_no & 0xFF])
    pad = b""
    prev = b""
    while len(pad) < length:
        prev = hashlib.md5(header + prev).digest()
        pad += prev
    return pad[:length]


def obfuscate(body: bytes, session_id: bytes, key: bytes, version: int,
              seq_no: int) -> bytes:
    """XOR `body` against the pseudo_pad keystream -- symmetric, so this is
    also how a reply's body is de-obfuscated: obfuscate(obfuscate(x, ...),
    ...) == x for the same session_id/key/version/seq_no."""
    pad = _pseudo_pad(session_id, key, version, seq_no, len(body))
    return bytes(b ^ p for b, p in zip(body, pad))


# ------------------------------------------------------------ AUTHEN START

def _check_field_len(name: str, value: bytes) -> None:
    if len(value) > MAX_FIELD_LEN:
        raise TacacsConfigError(
            f"{name} is too long for TACACS+ (max {MAX_FIELD_LEN} bytes)")


def build_authen_start(user: str, password: str, rem_addr: str = "",
                       port: str = "netpath") -> bytes:
    """The AUTHEN START body for a PAP login (RFC 8907 §5.1/§5.4.2):
    action=LOGIN, priv_lvl=1, authen_type=PAP, authen_service=LOGIN, then
    the four length-prefixed fields. PAP carries the password in `data`
    right away -- unlike ASCII, it needs no CONTINUE round trip, so one
    START is the whole exchange."""
    user_b = user.encode("utf-8")
    port_b = port.encode("utf-8")
    rem_addr_b = rem_addr.encode("utf-8")
    data_b = password.encode("utf-8")
    _check_field_len("username", user_b)
    _check_field_len("port", port_b)
    _check_field_len("rem_addr", rem_addr_b)
    _check_field_len("password", data_b)
    return (bytes([ACTION_LOGIN, PRIV_LVL_MIN, AUTHEN_TYPE_PAP, AUTHEN_SERVICE_LOGIN,
                   len(user_b), len(port_b), len(rem_addr_b), len(data_b)])
            + user_b + port_b + rem_addr_b + data_b)


def parse_authen_reply(body: bytes) -> tuple[int, int, str, bytes]:
    """The AUTHEN REPLY body -> (status, flags, server_msg, data). Raises
    TacacsProtocolError for anything shorter than the fixed header or whose
    length fields do not add up to the body actually received -- which is
    exactly what a body de-obfuscated with the wrong shared secret looks
    like, as well as plain truncation."""
    if len(body) < 6:
        raise TacacsProtocolError("AUTHEN REPLY body is too short")
    status = body[0]
    flags = body[1]
    server_msg_len = int.from_bytes(body[2:4], "big")
    data_len = int.from_bytes(body[4:6], "big")
    if 6 + server_msg_len + data_len != len(body):
        raise TacacsProtocolError(
            "AUTHEN REPLY length fields do not match the body received")
    server_msg = body[6:6 + server_msg_len].decode("utf-8", "replace")
    data = body[6 + server_msg_len:6 + server_msg_len + data_len]
    return status, flags, server_msg, data


# ------------------------------------------------------------------ network

def _recv_exact(sock, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("the AAA server closed the connection early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def authenticate(servers, secret: str, username: str, password: str, *,
                 timeout: float = DEFAULT_TIMEOUT_S, rem_addr: str = "",
                 port_label: str = "netpath") -> bool:
    """True if `username`/`password` is accepted (PASS) by the first
    reachable server in `servers`; False for a definite FAIL. Raises
    TacacsConfigError for a bad secret/field before any I/O,
    TacacsConnectError when every server in the list is unreachable (named
    with the last connection error seen), and TacacsProtocolError
    immediately -- not tried against the next server -- for anything that
    answered but is not a well-formed PASS/FAIL, since that includes a
    wrong shared secret and must stay visible rather than reading as an
    ordinary wrong password or a network blip.

    Empty password refused before any socket is opened, the same defence
    Service.authenticate_ldap applies to LDAP: a TACACS+ server is under no
    obligation to reject an empty PAP password, so this must not rely on
    one to.
    """
    if password == "":
        return False
    if not secret:
        raise TacacsConfigError("a TACACS+ shared secret is required")
    if not servers:
        raise TacacsConnectError("no TACACS+ servers configured")
    key = secret.encode("utf-8")
    body_plain = build_authen_start(username, password, rem_addr, port_label)

    last_error: Exception | None = None
    for host, port in servers:
        sock = None
        try:
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
            except OSError as exc:
                last_error = exc
                continue

            session_id = os.urandom(4)
            encrypted = obfuscate(body_plain, session_id, key, VERSION_PAP, SEQ_NO_START)
            header = encode_header(session_id=session_id, seq_no=SEQ_NO_START,
                                   length=len(encrypted), version=VERSION_PAP)
            try:
                sock.sendall(header + encrypted)
                reply_header = _recv_exact(sock, 12)
            except socket.timeout as exc:
                last_error = exc
                continue
            except OSError as exc:
                last_error = exc
                continue

            head = decode_header(reply_header)
            if head["version"] not in ACCEPTED_VERSIONS:
                raise TacacsProtocolError(
                    f"{host}:{port} replied with an unsupported TACACS+ "
                    f"version (0x{head['version']:02x})")
            if head["type"] != TYPE_AUTHEN:
                raise TacacsProtocolError(
                    f"{host}:{port} replied with packet type "
                    f"0x{head['type']:02x}, expected AUTHEN")
            if head["length"] > MAX_BODY_LEN:
                raise TacacsProtocolError(
                    f"{host}:{port} claims an implausible reply length "
                    f"({head['length']} bytes)")

            try:
                r_body_enc = _recv_exact(sock, head["length"])
            except socket.timeout as exc:
                last_error = exc
                continue
            except OSError as exc:
                last_error = exc
                continue

            if head["flags"] & FLAG_UNENCRYPTED:
                raise TacacsProtocolError(
                    f"{host}:{port} sent an unencrypted reply body, which "
                    f"this client refuses to trust")
            if head["session_id"] != session_id:
                raise TacacsProtocolError(
                    f"{host}:{port} answered with a different session id "
                    f"than the one this request used")
            if head["seq_no"] != SEQ_NO_REPLY:
                raise TacacsProtocolError(
                    f"{host}:{port} answered out of sequence "
                    f"(seq_no={head['seq_no']}, expected {SEQ_NO_REPLY})")

            r_body = obfuscate(r_body_enc, session_id, key, head["version"], head["seq_no"])
            status, _reply_flags, _server_msg, _data = parse_authen_reply(r_body)
            if status == STATUS_PASS:
                return True
            if status == STATUS_FAIL:
                return False
            name = _STATUS_NAMES.get(status, f"0x{status:02x}")
            raise TacacsProtocolError(
                f"{host}:{port} answered {name} instead of PASS/FAIL -- an "
                f"undecodable reply from the wrong shared secret looks like "
                f"this too, so check the shared secret if this is unexpected")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    raise TacacsConnectError(f"no TACACS+ server reachable: {last_error}")
