"""netpath.web.wsock: the handshake and the framing, on a socketpair.

No HTTP server and no SSH here — this is the transport on its own, driven
by hand-built client frames, so that a framing bug is caught as a framing
bug rather than as a terminal that mysteriously stops echoing. The other
side of the same contract (a real upgrade over the real server, and a
session on top of it) is tests/test_ssh_terminal.py."""
import email
import socket
import struct
import threading
import time

import _paths  # noqa: F401  (repo root on sys.path)

from netpath.web import wsock

HANDSHAKE = {
    "Host": "127.0.0.1:8443",
    "Upgrade": "websocket",
    "Connection": "keep-alive, Upgrade",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
    "Sec-WebSocket-Version": "13",
}


class FakeHandler:
    """The three attributes wsock.accept() touches on a request handler."""

    def __init__(self, sock, headers: dict):
        self.connection = sock
        self.rfile = sock.makefile("rb", -1)
        self.wfile = sock.makefile("wb", 0)
        self.headers = email.message_from_string(
            "".join(f"{k}: {v}\n" for k, v in headers.items()))


def pair(headers: dict | None = None):
    """(client socket, accepted WebSocket) over a socketpair."""
    server_sock, client_sock = socket.socketpair()
    server_sock.settimeout(5)
    client_sock.settimeout(5)
    handler = FakeHandler(server_sock, headers if headers is not None else HANDSHAKE)
    websocket = wsock.accept(handler)
    read_http_response(client_sock)
    return client_sock, websocket


def read_http_response(sock) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def read_frame(sock):
    """(fin, opcode, payload) of one server frame. Server frames are never
    masked, which is itself part of what this asserts."""
    head = _exact(sock, 2)
    fin = bool(head[0] & 0x80)
    opcode = head[0] & 0x0F
    assert not head[1] & 0x80, "a server frame must not be masked"
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", _exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _exact(sock, 8))[0]
    return fin, opcode, _exact(sock, length) if length else b""


def _exact(sock, count: int) -> bytes:
    out = b""
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            raise AssertionError(f"stream ended after {len(out)} of {count} bytes")
        out += chunk
    return out


# ------------------------------------------------------------- handshake

sock, ws = pair()
# The RFC 6455 §1.3 worked example: this key must produce this accept value,
# so a browser's own check of it passes.
server_sock2, client_sock2 = socket.socketpair()
handler = FakeHandler(server_sock2, HANDSHAKE)
wsock.accept(handler)
response = read_http_response(client_sock2).decode("ascii")
assert response.startswith("HTTP/1.1 101 Switching Protocols\r\n"), response
assert "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" in response, response
assert "Upgrade: websocket\r\n" in response, response
assert "Connection: Upgrade\r\n" in response, response
print("PASS: the handshake answers 101 with the RFC's example accept digest")
# HTTP/1.1 specifically: the server's own protocol_version is HTTP/1.0, and a
# browser refuses a 101 announced as HTTP/1.0.
assert not response.startswith("HTTP/1.0"), response
print("PASS: the 101 status line is HTTP/1.1 even though the server is 1.0")

for broken, why in (
        ({**HANDSHAKE, "Upgrade": "h2c"}, "not a websocket upgrade"),
        ({**HANDSHAKE, "Connection": "keep-alive"}, "no Connection: Upgrade"),
        ({**HANDSHAKE, "Sec-WebSocket-Version": "8"}, "an old draft version"),
        ({k: v for k, v in HANDSHAKE.items() if k != "Sec-WebSocket-Key"},
         "no key at all"),
        ({**HANDSHAKE, "Sec-WebSocket-Key": "not-base64!"}, "a malformed key"),
        ({**HANDSHAKE, "Sec-WebSocket-Key": "c2hvcnQ="}, "a key of the wrong length"),
):
    a, b = socket.socketpair()
    try:
        wsock.accept(FakeHandler(a, broken))
        raise AssertionError(f"accept() allowed {why}")
    except wsock.WebSocketError:
        pass
    a.setblocking(False)
    b.setblocking(False)
    try:
        assert b.recv(1) == b"", f"accept() wrote bytes before refusing {why}"
    except BlockingIOError:
        pass                      # nothing written at all, which is the point
    a.close()
    b.close()
print("PASS: a handshake that is not a valid upgrade is refused, silently")

# ---------------------------------------------------------------- reading

sock.sendall(wsock.client_frame(wsock.OP_TEXT, b'{"type":"open"}'))
assert ws.recv() == (wsock.OP_TEXT, b'{"type":"open"}')
sock.sendall(wsock.client_frame(wsock.OP_BINARY, b"show version\r"))
assert ws.recv() == (wsock.OP_BINARY, b"show version\r")
print("PASS: masked client text and binary frames are unmasked and delivered")

# Fragmentation: one message, three frames, only the last with FIN.


def fragment(opcode: int, payload: bytes, fin: bool) -> bytes:
    frame = bytearray(wsock.client_frame(opcode, payload))
    if not fin:
        frame[0] &= 0x7F
    return bytes(frame)


sock.sendall(fragment(wsock.OP_TEXT, b"Hel", False))
sock.sendall(fragment(wsock.OP_CONT, b"lo, ", False))
sock.sendall(fragment(wsock.OP_CONT, b"world", True))
assert ws.recv() == (wsock.OP_TEXT, b"Hello, world")
print("PASS: a fragmented message is reassembled and delivered once, whole")

# A ping is answered with a pong carrying the same payload, and does not
# surface as a message.
sock.sendall(wsock.client_frame(wsock.OP_PING, b"are you there"))
sock.sendall(wsock.client_frame(wsock.OP_TEXT, b"after the ping"))
assert ws.recv() == (wsock.OP_TEXT, b"after the ping")
fin, opcode, payload = read_frame(sock)
assert (fin, opcode, payload) == (True, wsock.OP_PONG, b"are you there"), \
    (fin, opcode, payload)
print("PASS: a ping is answered with a pong and never reaches the application")

# ---------------------------------------------------------------- writing

ws.send_text("status: connected")
fin, opcode, payload = read_frame(sock)
assert (fin, opcode, payload) == (True, wsock.OP_TEXT, b"status: connected")
ws.send_binary(b"\x1b[2J")
fin, opcode, payload = read_frame(sock)
assert (fin, opcode, payload) == (True, wsock.OP_BINARY, b"\x1b[2J")
print("PASS: send_text and send_binary write single unmasked FIN frames")

# The two extended length encodings — 126 (16-bit) and 127 (64-bit) — on the
# way out, and the same on the way in.
for size in (200, 70000):
    ws.send_binary(b"x" * size)
    fin, opcode, payload = read_frame(sock)
    assert (fin, opcode, len(payload)) == (True, wsock.OP_BINARY, size), \
        (fin, opcode, len(payload))
    sock.sendall(wsock.client_frame(wsock.OP_BINARY, b"y" * size))
    opcode, payload = ws.recv()
    assert (opcode, len(payload)) == (wsock.OP_BINARY, size), (opcode, len(payload))
print("PASS: 16-bit and 64-bit length encodings round-trip in both directions")

# ------------------------------------------------------------ close paths

sock.sendall(wsock.client_frame(wsock.OP_CLOSE, struct.pack("!H", 1000) + b"bye"))
assert ws.recv() is None
assert ws.close_code == 1000 and ws.close_reason == "bye", \
    (ws.close_code, ws.close_reason)
fin, opcode, payload = read_frame(sock)
assert opcode == wsock.OP_CLOSE and struct.unpack("!H", payload[:2])[0] == 1000
assert ws.closed
assert ws.send_text("too late") is False, "sending after close must not raise"
print("PASS: a client close is echoed, ends recv(), and disarms further sends")
sock.close()

# An unmasked client frame is a protocol error, not something to accept.
sock, ws = pair()
unmasked = bytes([0x80 | wsock.OP_TEXT, 5]) + b"hello"
sock.sendall(unmasked)
assert ws.recv() is None
_, opcode, payload = read_frame(sock)
assert opcode == wsock.OP_CLOSE, opcode
assert struct.unpack("!H", payload[:2])[0] == wsock.CLOSE_PROTOCOL_ERROR
print("PASS: an unmasked client frame closes the connection with 1002")
sock.close()

# A reserved bit set means an extension nobody negotiated.
sock, ws = pair()
reserved = bytearray(wsock.client_frame(wsock.OP_TEXT, b"hi"))
reserved[0] |= 0x40
sock.sendall(bytes(reserved))
assert ws.recv() is None
_, opcode, payload = read_frame(sock)
assert struct.unpack("!H", payload[:2])[0] == wsock.CLOSE_PROTOCOL_ERROR
print("PASS: a reserved bit closes the connection with 1002")
sock.close()

# The size cap is enforced on the length field, before any payload is read:
# a header claiming 3 MB must never allocate 3 MB.
sock, ws = pair()
sock.sendall(bytes([0x80 | wsock.OP_BINARY, 0x80 | 127])
             + struct.pack("!Q", 3 * 1024 * 1024) + b"\x00\x00\x00\x00")
assert ws.recv() is None
_, opcode, payload = read_frame(sock)
assert struct.unpack("!H", payload[:2])[0] == wsock.CLOSE_TOO_BIG
print("PASS: a frame larger than the cap is refused on its header alone (1009)")
sock.close()

# The cap covers a reassembled message too, not only one frame. Sent from
# its own thread: two megabytes is far more than a socketpair will hold, so
# the writer has to be running while recv() drains.
sock, ws = pair()


def flood():
    chunk = b"z" * 100000
    sent = 0
    try:
        while sent <= wsock.MAX_MESSAGE_BYTES:
            opcode = wsock.OP_BINARY if sent == 0 else wsock.OP_CONT
            sock.sendall(fragment(opcode, chunk, False))
            sent += len(chunk)
    except OSError:
        pass                      # the far end closed on us, which is correct


writer = threading.Thread(target=flood, daemon=True)
writer.start()
assert ws.recv() is None
_, opcode, payload = read_frame(sock)
assert struct.unpack("!H", payload[:2])[0] == wsock.CLOSE_TOO_BIG
print("PASS: fragments that add up past the cap are refused too")
sock.close()

# A control frame may be neither fragmented nor oversized.
sock, ws = pair()
sock.sendall(fragment(wsock.OP_PING, b"x", False))
assert ws.recv() is None
_, opcode, payload = read_frame(sock)
assert struct.unpack("!H", payload[:2])[0] == wsock.CLOSE_PROTOCOL_ERROR
print("PASS: a fragmented control frame closes the connection with 1002")
sock.close()

# A message that arrives as thousands of small fragments must not be
# reassembled by concatenating onto one growing buffer: 2 MB in 125-byte
# frames is 16,777 of them, and copying the buffer each time is quadratic.
# What is asserted is the whole message and the fact that it lands in
# seconds rather than minutes.
sock, ws = pair()
PIECE = b"a" * 125
PIECES = wsock.MAX_MESSAGE_BYTES // len(PIECE)


def dribble():
    try:
        for index in range(PIECES):
            last = index == PIECES - 1
            opcode = wsock.OP_BINARY if index == 0 else wsock.OP_CONT
            sock.sendall(fragment(opcode, PIECE, last))
    except OSError:
        pass


started = time.time()
writer = threading.Thread(target=dribble, daemon=True)
writer.start()
opcode, payload = ws.recv()
elapsed = time.time() - started
assert (opcode, len(payload)) == (wsock.OP_BINARY, PIECES * len(PIECE)), \
    (opcode, len(payload))
assert payload == PIECE * PIECES
assert elapsed < 30, f"{PIECES} fragments took {elapsed:.1f}s"
print(f"PASS: a {len(payload) // 1024} KB message in {PIECES:,} fragments is "
      f"reassembled in {elapsed:.1f}s")
ws.close()
sock.close()

# ------------------------------------------------------- a peer that stops
#
# A browser that stops reading — a laptop shut mid-`show tech-support` —
# must not pin the socket forever, and the send lock must not be held while
# it does. The send fails within the timeout, the socket is marked closed,
# and that is what releases a recv() parked in another thread.
original_send_timeout = wsock.SEND_TIMEOUT_S
wsock.SEND_TIMEOUT_S = 1
try:
    sock, ws = pair()
    parked = []
    reader = threading.Thread(target=lambda: parked.append(ws.recv()), daemon=True)
    reader.start()
    time.sleep(0.3)                      # let it settle into the read
    started = time.time()
    blob = b"x" * 200000
    while ws.send_binary(blob):
        assert time.time() - started < 30, "the socketpair never filled up"
    elapsed = time.time() - started
    assert ws.closed
    assert elapsed < 20, elapsed
    print(f"PASS: a peer that stops reading fails the send in {elapsed:.1f}s "
          f"instead of blocking on it forever")
    reader.join(timeout=5)
    assert not reader.is_alive(), "recv() was left parked after the failed send"
    assert parked == [None], parked
    started = time.time()
    ws.close()
    assert time.time() - started < 5
    print("PASS: the failed send unblocks the reader, and close() still returns")
    sock.close()
finally:
    wsock.SEND_TIMEOUT_S = original_send_timeout

# A peer that simply vanishes ends recv() without an exception.
sock, ws = pair()
sock.close()
assert ws.recv() is None
assert ws.closed
print("PASS: an abruptly closed peer ends recv() cleanly")

print("ALL WSOCK ASSERTIONS PASSED")
