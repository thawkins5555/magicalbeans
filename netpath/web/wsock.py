"""RFC 6455 WebSocket framing, server side, standard library only.

The app already owns its HTTP server (a threading `http.server` with one
daemon thread per connection), and that shape makes a WebSocket cheap: a
handler can answer the upgrade itself and then keep the socket for the life
of the conversation, because there is no keep-alive pipeline behind it to
unwind and no event loop whose thread it would be blocking. So rather than
add a dependency for one page, the ~250 lines of framing that page needs
live here.

What this implements, and what it deliberately does not:

* The handshake (`accept`), validating `Upgrade`, `Connection`,
  `Sec-WebSocket-Version: 13` and `Sec-WebSocket-Key`, and answering with
  the `Sec-WebSocket-Accept` digest. The status line is written by hand as
  HTTP/1.1: the server's `protocol_version` is HTTP/1.0 and a browser will
  not accept a 101 announced as HTTP/1.0. Whether the *caller* is allowed
  to be here at all — the session cookie, the permission, and the `Origin`
  of the page asking — is settled in server.py before this is reached.
* Text, binary and continuation frames, with masked payloads (a client
  frame that is not masked is a protocol error, per the RFC), ping answered
  with pong, and the close handshake echoed. Every other opcode is
  reserved, and a reserved one fails the connection (§5.2) rather than
  being reassembled as though it were data.
* One lock around *all* socket I/O, not merely around sending. A session
  has two threads on one socket — the one reading it and the one pumping
  the SSH channel into it — and under TLS that would be a concurrent
  `SSL_read`/`SSL_write` on a single `SSLSocket`, which OpenSSL does not
  support: a post-handshake message arriving mid-`show tech-support` can
  kill the connection with a record error. So after the 101 this stops
  using the handler's `rfile`/`wfile` buffers and talks to the socket
  itself. The reader waits for readability *outside* the lock and then
  takes it only for a non-blocking read, so the thread that is idle 99% of
  the time cannot starve the one with output to send; the sender holds it
  under a real timeout (`SEND_TIMEOUT_S`). That timeout is the other half
  of the bargain: no thread can be parked in socket I/O holding the lock,
  so `close()`, the idle watchdog and the registry's shutdown are all
  bounded.
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
import logging
import os
import select
import selectors
import socket
import ssl
import struct
import threading
import time

log = logging.getLogger(__name__)

# The RFC's magic constant, appended to the client's key before the digest.
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

_CONTROL_OPS = (OP_CLOSE, OP_PING, OP_PONG)
# Every opcode the RFC defines. The rest — 0x3-0x7 (reserved non-control)
# and 0xB-0xF (reserved control) — "MUST fail the WebSocket connection"
# (§5.2). Without that they missed the control branch and the continuation
# branch alike and were reassembled as if they were text or binary, and a
# reserved *control* opcode also escaped the "fragmented control frame" and
# "oversized control frame" guards, since those ask whether the opcode is
# one of the three above.
_DEFINED_OPS = (OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG)

# One frame, and one reassembled message, may not exceed this. Generous for
# a terminal by three orders of magnitude, small enough that a bad length
# cannot exhaust memory.
MAX_MESSAGE_BYTES = 2 * 1024 * 1024

# How long the reader waits for the socket to become readable before
# looking around. The wait itself is outside the I/O lock and the read that
# follows it is non-blocking, so a reader parked on a terminal nobody is
# typing at never keeps the pump thread off the socket. A quarter of a
# second is short enough that a `close()` from another thread is noticed at
# once and long enough that an idle session is not spinning. A read that
# ends mid-TLS-record loses nothing — OpenSSL keeps its own state between
# calls, which is exactly why those calls must not overlap.
READ_SLICE_S = 0.25
# How long one write may block. A browser that stops reading (a laptop shut
# mid-`show tech-support`) must not pin the socket forever: past this the
# send fails, the socket is marked closed, and everything waiting on it —
# `stop()`, the idle watchdog, `SshSessionRegistry.shutdown()` — is released.
SEND_TIMEOUT_S = 15
# One `recv` from the socket. Independent of the message cap: this is the
# stream, not a frame.
_RECV_BYTES = 65536

# `poll()` where the platform has it (Linux, the BSDs), `selectors` — which
# is epoll/kqueue there and `select` on Windows — everywhere else. NOT
# `select.select`: it cannot express a descriptor at or above FD_SETSIZE
# (1024) and raises ValueError for one, and this application reaches that
# number on an ordinary busy appliance (ten databases with their WAL and
# SHM companions, three UDP listeners, the poller's worker sockets, one
# descriptor per open HTTP connection). Windows' select has no such ceiling
# on the descriptor's *value*, which is why the fallback is safe there.
_HAS_POLL = hasattr(select, "poll")

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


class _Eof(Exception):
    """The stream ended: the peer went away, or this end closed. Internal —
    `recv()` turns it into the None that ends the conversation."""


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
    sock = getattr(handler, "connection", None)
    if sock is None:
        raise WebSocketError("This connection cannot be hijacked")

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
    return WebSocket(sock, initial=_drain(handler.rfile, sock))


def _drain(rfile, sock) -> bytes:
    """Whatever a pipelined client sent behind its handshake and `rfile`
    has already buffered. From here on the socket is read directly, so
    anything still sitting in that buffer would simply be lost; this is the
    one moment it can be recovered. Non-blocking, so "nothing there" — the
    ordinary case — costs one failed read."""
    if rfile is None:
        return b""
    chunks = []
    try:
        sock.setblocking(False)
    except (OSError, AttributeError):
        return b""
    try:
        while True:
            try:
                chunk = rfile.read1(_RECV_BYTES)
            except (OSError, ValueError):
                break                     # BlockingIOError: nothing buffered
            if not chunk:                 # b"" at EOF, None when it would block
                break
            chunks.append(chunk)
    finally:
        try:
            sock.setblocking(True)
        except OSError:
            pass
    return b"".join(chunks)


class WebSocket:
    """A hijacked connection, after the 101.

    `recv()` is single-reader: one thread owns it. `send_*` and `close()`
    are safe from any thread. Everything touching the socket goes through
    `_io_lock`, so the two threads never overlap on it.
    """

    def __init__(self, sock, initial: bytes = b""):
        self.sock = sock
        self._io_lock = threading.Lock()
        # Bytes read from the socket but not yet consumed by a frame.
        self._buffer = bytearray(initial)
        self._used = 0
        self.closed = False
        # Filled in when the peer closes: the code and reason it gave.
        self.close_code: int | None = None
        self.close_reason: str = ""
        # Whether the readability wait has already been reported as broken;
        # one line per socket, not one per slice.
        self._wait_broken = False
        self._set_timeout(READ_SLICE_S)

    def _set_timeout(self, seconds: float) -> None:
        try:
            self.sock.settimeout(seconds)
        except (OSError, AttributeError):
            pass

    # ------------------------------------------------------------- reading

    def recv(self):
        """The next application message as `(opcode, payload)` — OP_TEXT or
        OP_BINARY, with fragments already reassembled — or None once the
        conversation is over (the peer closed, the socket died, or this end
        called close()). Pings are answered here and never surface."""
        fragments: list[bytes] = []
        pending = 0                       # running length, so no O(n²) concat
        message_op = None
        while True:
            try:
                fin, opcode, payload = self._read_frame()
            except WebSocketTooBig as exc:
                self.close(CLOSE_TOO_BIG, str(exc)[:110])
                return None
            except WebSocketError as exc:
                self.close(CLOSE_PROTOCOL_ERROR, str(exc)[:110])
                return None
            except _Eof:
                # The peer vanished, or our own close() from another thread
                # shut the socket down — which is how the idle timer and
                # shutdown unblock this loop.
                self.closed = True
                return None

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

            # Checked before the append, so the cap is a ceiling on what is
            # ever held, not on what has already been held.
            if pending + len(payload) > MAX_MESSAGE_BYTES:
                self.close(CLOSE_TOO_BIG, "Message too large")
                return None
            fragments.append(payload)
            pending += len(payload)
            if fin:
                return message_op, b"".join(fragments)

    def _read_frame(self):
        head = self._read_exact(2)
        first, second = head[0], head[1]
        fin = bool(first & 0x80)
        if first & 0x70:
            raise WebSocketError("Reserved bits set")
        opcode = first & 0x0F
        if opcode not in _DEFINED_OPS:
            raise WebSocketError("Reserved opcode")
        masked = bool(second & 0x80)
        length = second & 0x7F
        if not masked:
            # "The server MUST close the connection upon receiving a frame
            # that is not masked" — RFC 6455 §5.1.
            raise WebSocketError("Client frame was not masked")
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        if opcode in _CONTROL_OPS:
            if not fin:
                raise WebSocketError("Fragmented control frame")
            if length > 125:
                raise WebSocketError("Oversized control frame")
        if length > MAX_MESSAGE_BYTES:
            raise WebSocketTooBig("Frame exceeds the size limit")
        mask = self._read_exact(4)
        payload = self._read_exact(length) if length else b""
        return fin, opcode, _apply_mask(payload, mask)

    def _read_exact(self, count: int) -> bytes:
        """Exactly `count` bytes from the buffer, refilling it from the
        socket as needed. Raises `_Eof` when the stream ends first."""
        while len(self._buffer) - self._used < count:
            self._buffer += self._fill()
        start = self._used
        self._used += count
        out = bytes(self._buffer[start:self._used])
        if self._used >= _RECV_BYTES:            # keep the buffer from growing
            del self._buffer[:self._used]
            self._used = 0
        return out

    def _fill(self) -> bytes:
        """One read slice: whatever the socket has to give.

        The waiting happens *outside* the lock and the read itself is
        non-blocking, so the reader — which spends nearly all of its life
        waiting for the next keystroke — holds the socket for microseconds
        at a time and the pump thread is never kept out. (A blocking read
        under the lock would starve it: releasing a lock and immediately
        re-taking it hands it back to the same thread.)
        """
        while not self.closed:
            self._wait_readable()
            with self._io_lock:
                if self.closed:
                    break
                try:
                    self.sock.setblocking(False)
                    data = self.sock.recv(_RECV_BYTES)
                except (BlockingIOError, ssl.SSLWantReadError):
                    data = None           # nothing yet, or half a TLS record
                except (OSError, ValueError) as exc:
                    raise _Eof from exc
                finally:
                    self._set_timeout(READ_SLICE_S)
            if data is None:
                continue
            if not data:
                raise _Eof
            return data
        raise _Eof

    def _wait_readable(self) -> None:
        """Wait, without the lock, for the socket to have something — or for
        the slice to expire, which is what makes `closed` noticed promptly.
        Its answer is not trusted: the read that follows happens either way,
        because under TLS a whole record can already be decoded and waiting
        inside the SSL object with nothing left for the wait to see — which
        is also why a TLS socket that reports pending bytes is not made to
        wait out the slice first.

        What must never happen is *no* wait: the read behind this one is
        non-blocking, so a wait that returns immediately turns the reader
        into a loop that takes and releases the I/O lock millions of times
        a second, pinning a core and starving the pump thread on the same
        socket. That is why the wait uses `poll`/`epoll` rather than
        `select` (see `_HAS_POLL`), and why a wait that cannot be performed
        at all is slept out rather than skipped.
        """
        try:
            if isinstance(self.sock, ssl.SSLSocket) and self.sock.pending():
                return
        except (OSError, ValueError):
            pass                          # closed underneath us; the read says so
        try:
            self._poll_readable(READ_SLICE_S)
        except (OSError, ValueError) as exc:
            # Not evidence that the socket is gone — the read that follows
            # decides that — but the slice still has to pass, or this is a
            # spin. Said once per socket, because it is the kind of fault
            # that otherwise only shows up as an unexplained busy CPU.
            if not self._wait_broken:
                self._wait_broken = True
                log.warning("WebSocket reader cannot wait on its socket "
                            "(%s: %s); falling back to a timed sleep",
                            type(exc).__name__, exc)
            time.sleep(READ_SLICE_S)

    def _poll_readable(self, timeout: float) -> None:
        """One readability wait on this socket, with no ceiling on the
        descriptor's value. Both objects are per-call: `select.poll()` costs
        no descriptor at all, and a selector is only built on the platforms
        that have no `poll`."""
        if _HAS_POLL:
            poller = select.poll()
            poller.register(self.sock.fileno(), select.POLLIN | select.POLLPRI)
            poller.poll(timeout * 1000.0)
            return
        with selectors.DefaultSelector() as selector:
            selector.register(self.sock, selectors.EVENT_READ)
            selector.select(timeout)

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
        the frame, and the shutdown — which happens on *every* call, even
        one that finds the socket already marked closed by a failed write —
        is what unblocks a `recv()` parked in another thread.
        """
        payload = struct.pack("!H", int(code)) + reason.encode("utf-8")[:123]
        with self._io_lock:
            if not self.closed:
                self.closed = True
                self._write(_frame(OP_CLOSE, payload))
        # Windows resets a connection that is closed with data still unread in
        # its receive buffer, and a reset discards whatever WE last sent — so
        # the peer loses the close frame naming the reason, and reads a bare
        # ConnectionResetError instead of "There are already 16 SSH sessions".
        # Draining what the peer already sent turns that reset back into an
        # orderly FIN. Bounded, because the point is to empty a buffer, not to
        # keep reading a peer that is still talking, and best-effort because
        # every failure here ends the same way as success: shut the socket.
        self._drain()
        # No waiting for the peer's answering close: the handler thread is
        # about to let the connection go, and a half-closed socket is what
        # unblocks a recv() parked in another thread.
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass

    def _drain(self, rounds: int = 8) -> None:
        """Discard what is already in the receive buffer, without blocking."""
        try:
            for _ in range(rounds):
                if not select.select([self.sock], [], [], 0)[0]:
                    return
                if not self.sock.recv(65536):
                    return
        except (OSError, ValueError, AttributeError):
            pass

    def unblock(self) -> None:
        """Stop the socket without sending anything and without taking the
        I/O lock. `close()` cannot do this: it takes the lock to send its
        close frame, and the lock can be held for `SEND_TIMEOUT_S` by a
        write into a peer that stopped reading — which is exactly the case
        a caller in a hurry (`SshSessionRegistry.shutdown()`) needs to get
        past. The shutdown fails that write immediately and ends any
        `recv()` parked on the socket."""
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass

    def _send_frame(self, opcode: int, payload: bytes) -> bool:
        frame = _frame(opcode, payload)
        with self._io_lock:
            if self.closed:
                return False
            if not self._write(frame):
                self.closed = True
                return False
            return True

    def _write(self, frame: bytes) -> bool:
        """One frame onto the socket, under `_io_lock` and a real timeout.
        False when the peer stopped reading or the socket is gone."""
        self._set_timeout(SEND_TIMEOUT_S)
        try:
            self.sock.sendall(frame)
            return True
        except (socket.timeout, TimeoutError, OSError, ValueError):
            return False
        finally:
            self._set_timeout(READ_SLICE_S)


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
