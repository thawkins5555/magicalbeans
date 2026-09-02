"""RFC 6455 WebSocket framing, server side, standard library only.

The app already owns its HTTP server (a threading `http.server` with one
daemon thread per connection), and that shape makes a WebSocket cheap: a
handler can answer the upgrade itself and then keep the socket for the life
of the conversation, because there is no keep-alive pipeline behind it to
unwind and no event loop whose thread it would be blocking. So rather than
add a dependency for one page, the ~200 lines of framing that page needs
live here.

What this implements, and what it deliberately does not:

* The handshake (`accept`), validating `Upgrade`, `Connection`,
  `Sec-WebSocket-Version: 13` and `Sec-WebSocket-Key`, and answering with
  the `Sec-WebSocket-Accept` digest. The status line is written by hand as
  HTTP/1.1: the server's `protocol_version` is HTTP/1.0 and a browser will
  not accept a 101 announced as HTTP/1.0.
* Text, binary and continuation frames, with masked payloads (a client
  frame that is not masked is a protocol error, per the RFC), ping answered
  with pong, and the close handshake echoed.
* One lock around sending, because a session has two writers: the thread
  pumping the SSH channel and the thread reading the socket.
* A frame/message ceiling (`MAX_MESSAGE_BYTES`). A terminal's keystrokes
  are tiny; anything near a megabyte is a bug or an attack, and without a
  cap the length field alone is an out-of-memory kill.

Not implemented, because nothing here needs it: extensions (the handshake
never negotiates one, so RSV bits must be zero), subprotocol selection, and
client-side masking — this end never masks, which is exactly what the RFC
requires of a server.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import threading

# The RFC's magic constant, appended to the client's key before the digest.
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

_CONTROL_OPS = (OP_CLOSE, OP_PING, OP_PONG)

# One frame, and one reassembled message, may not exceed this. Generous for
# a terminal by three orders of magnitude, small enough that a bad length
# cannot exhaust memory.
MAX_MESSAGE_BYTES = 2 * 1024 * 1024

# Close codes this module sends on its own behalf. The application's own
# codes (4401/4408/4429) are passed to close() by the caller.
CLOSE_NORMAL = 1000
CLOSE_PROTOCOL_ERROR = 1002
CLOSE_TOO_BIG = 1009


class WebSocketError(Exception):
    """A handshake that cannot be answered, or a frame that breaks the
    protocol. The first is reported to the client as a 400 before anything
    is hijacked; the second closes the socket."""


class WebSocketTooBig(WebSocketError):
    """A frame whose declared length is past the cap. Its own exception
    because it has its own close code (1009, not 1002) — and because it is
    raised from the length field alone, before a byte of that payload has
    been read into memory, which is the entire point of the cap."""


def accept(handler) -> "WebSocket":
    """Answer a WebSocket upgrade on `handler` (a BaseHTTPRequestHandler)
    and return the socket wrapper. Raises WebSocketError — before writing
    anything — when the request is not a valid upgrade, so the caller can
    still answer it as an ordinary HTTP error."""
    headers = handler.headers
    upgrade = (headers.get("Upgrade") or "").strip().lower()
    connection = (headers.get("Connection") or "").lower()
    key = (headers.get("Sec-WebSocket-Key") or "").strip()
    version = (headers.get("Sec-WebSocket-Version") or "").strip()
    if upgrade != "websocket":
        raise WebSocketError("Not a WebSocket upgrade request")
    if "upgrade" not in [part.strip() for part in connection.split(",")]:
        raise WebSocketError("Missing 'Connection: Upgrade'")
    if version != "13":
        raise WebSocketError("Only WebSocket version 13 is supported")
    if not key:
        raise WebSocketError("Missing Sec-WebSocket-Key")
    try:
        if len(base64.b64decode(key, validate=True)) != 16:
            raise ValueError
    except Exception as exc:
        raise WebSocketError("Malformed Sec-WebSocket-Key") from exc

    digest = base64.b64encode(
        hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {digest}\r\n"
        "\r\n"
    )
    handler.wfile.write(response.encode("ascii"))
    try:
        handler.wfile.flush()
    except (OSError, ValueError):
        pass
    return WebSocket(handler.rfile, handler.wfile,
                     sock=getattr(handler, "connection", None))


class WebSocket:
    """A hijacked connection, after the 101.

    `recv()` is single-reader: one thread owns it. `send_*` and `close()`
    are safe from any thread.
    """

    def __init__(self, rfile, wfile, sock=None):
        self.rfile = rfile
        self.wfile = wfile
        self.sock = sock
        self._send_lock = threading.Lock()
        self.closed = False
        # Filled in when the peer closes: the code and reason it gave.
        self.close_code: int | None = None
        self.close_reason: str = ""

    # ------------------------------------------------------------- reading

    def recv(self):
        """The next application message as `(opcode, payload)` — OP_TEXT or
        OP_BINARY, with fragments already reassembled — or None once the
        conversation is over (the peer closed, the socket died, or this end
        called close()). Pings are answered here and never surface."""
        buffer = b""
        message_op = None
        while True:
            try:
                frame = self._read_frame()
            except WebSocketTooBig as exc:
                self.close(CLOSE_TOO_BIG, str(exc)[:110])
                return None
            except WebSocketError as exc:
                self.close(CLOSE_PROTOCOL_ERROR, str(exc)[:110])
                return None
            except (OSError, ValueError):
                # Socket closed underneath us — including by our own close()
                # from another thread, which is how the idle timer and
                # shutdown unblock this loop.
                self.closed = True
                return None
            if frame is None:                    # clean EOF, no close frame
                self.closed = True
                return None
            fin, opcode, payload = frame

            if opcode in _CONTROL_OPS:
                if opcode == OP_CLOSE:
                    code, reason = _parse_close(payload)
                    self.close_code = code
                    self.close_reason = reason
                    self.close(code if code is not None else CLOSE_NORMAL)
                    return None
                if opcode == OP_PING:
                    self._send_frame(OP_PONG, payload)
                continue                          # a pong needs no answer

            if opcode == OP_CONT:
                if message_op is None:
                    self.close(CLOSE_PROTOCOL_ERROR, "Unexpected continuation")
                    return None
            elif message_op is not None:
                self.close(CLOSE_PROTOCOL_ERROR, "Interleaved message")
                return None
            else:
                message_op = opcode

            buffer += payload
            if len(buffer) > MAX_MESSAGE_BYTES:
                self.close(CLOSE_TOO_BIG, "Message too large")
                return None
            if fin:
                return message_op, buffer

    def _read_frame(self):
        head = self._read_exact(2)
        if head is None:
            return None
        first, second = head[0], head[1]
        fin = bool(first & 0x80)
        if first & 0x70:
            raise WebSocketError("Reserved bits set")
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if not masked:
            # "The server MUST close the connection upon receiving a frame
            # that is not masked" — RFC 6455 §5.1.
            raise WebSocketError("Client frame was not masked")
        if length == 126:
            extra = self._read_exact(2)
            if extra is None:
                return None
            length = struct.unpack("!H", extra)[0]
        elif length == 127:
            extra = self._read_exact(8)
            if extra is None:
                return None
            length = struct.unpack("!Q", extra)[0]
        if opcode in _CONTROL_OPS:
            if not fin:
                raise WebSocketError("Fragmented control frame")
            if length > 125:
                raise WebSocketError("Oversized control frame")
        if length > MAX_MESSAGE_BYTES:
            raise WebSocketTooBig("Frame exceeds the size limit")
        mask = self._read_exact(4)
        if mask is None:
            return None
        payload = self._read_exact(length) if length else b""
        if payload is None:
            return None
        return fin, opcode, _apply_mask(payload, mask)

    def _read_exact(self, count: int) -> bytes | None:
        """Exactly `count` bytes, or None at end of stream. `rfile` is a
        BufferedReader, whose read() can still come up short at EOF."""
        chunks = []
        remaining = count
        while remaining > 0:
            chunk = self.rfile.read(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    # ------------------------------------------------------------- writing

    def send_text(self, text: str) -> bool:
        return self._send_frame(OP_TEXT, text.encode("utf-8"))

    def send_binary(self, data: bytes) -> bool:
        return self._send_frame(OP_BINARY, bytes(data))

    def send_ping(self, data: bytes = b"") -> bool:
        return self._send_frame(OP_PING, data)

    def close(self, code: int = CLOSE_NORMAL, reason: str = "") -> None:
        """Send a close frame (best effort) and stop the socket.

        Idempotent and safe from any thread: whoever gets there first sends
        the frame, and shutting the socket down is what unblocks a `recv()`
        parked in another thread.
        """
        with self._send_lock:
            if self.closed:
                return
            self.closed = True
            payload = struct.pack("!H", int(code)) + reason.encode("utf-8")[:123]
            try:
                self.wfile.write(_frame(OP_CLOSE, payload))
                self.wfile.flush()
            except (OSError, ValueError):
                pass
        # No waiting for the peer's answering close: the handler thread is
        # about to let the connection go, and a half-closed socket is what
        # unblocks a recv() parked in another thread.
        try:
            if self.sock is not None:
                import socket as _socket
                self.sock.shutdown(_socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass

    def _send_frame(self, opcode: int, payload: bytes) -> bool:
        with self._send_lock:
            if self.closed:
                return False
            try:
                self.wfile.write(_frame(opcode, payload))
                self.wfile.flush()
                return True
            except (OSError, ValueError):
                self.closed = True
                return False


# ------------------------------------------------------------------ framing


def _frame(opcode: int, payload: bytes) -> bytes:
    """One unmasked server frame. Never fragmented: the caller already
    chunks terminal output to a size worth sending."""
    length = len(payload)
    head = bytes([0x80 | opcode])
    if length < 126:
        head += bytes([length])
    elif length < 65536:
        head += bytes([126]) + struct.pack("!H", length)
    else:
        head += bytes([127]) + struct.pack("!Q", length)
    return head + payload


def client_frame(opcode: int, payload: bytes, mask: bytes | None = None) -> bytes:
    """A masked *client* frame. Only the tests speak this direction, but it
    belongs with the framing it mirrors rather than being copied into them."""
    mask = mask or os.urandom(4)
    length = len(payload)
    head = bytes([0x80 | opcode])
    if length < 126:
        head += bytes([0x80 | length])
    elif length < 65536:
        head += bytes([0x80 | 126]) + struct.pack("!H", length)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", length)
    return head + mask + _apply_mask(payload, mask)


def _apply_mask(payload: bytes, mask: bytes) -> bytes:
    # Masking is its own inverse; int.from_bytes beats a per-byte loop by
    # enough to matter on a fast-scrolling `show tech-support`.
    if not payload:
        return payload
    repeats = len(payload) // 4 + 1
    long_mask = (mask * repeats)[:len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(long_mask, "big")
            ).to_bytes(len(payload), "big")


def _parse_close(payload: bytes) -> tuple[int | None, str]:
    if len(payload) < 2:
        return None, ""
    code = struct.unpack("!H", payload[:2])[0]
    return code, payload[2:].decode("utf-8", "replace")
