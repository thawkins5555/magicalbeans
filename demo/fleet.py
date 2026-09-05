"""A whole SNMP fleet in one process.

Every simulated device gets its own loopback address and its own UDP
socket bound to the real SNMP port::

    127.0.0.2:161, 127.0.0.3:161, 127.0.0.4:161, ...

which is what lets the UNMODIFIED app poll them. netpath/nodeoids.py:12
hard-wires DEFAULT_SNMP_PORT = 161 and netpath/fortipoll.py:49 does the
same, so a stub on a random high port could never be reached by anything
but a test; a stub on 127.0.0.x:161 is indistinguishable from real gear.

    python3 demo/fleet.py --count 300 [--control-port 8099]
                          [--scenario demo/scenario.json] [--quiet]

One line containing "listening" is printed once every socket is bound —
the same banner contract tests/_paths.spawn_stub() waits for.

Design notes
------------
* The device sockets are sharded across selectors.DefaultSelector
  instances, MAX_SOCKETS_PER_SHARD each, one selector loop per shard
  running in its own thread. This exists because selectors.DefaultSelector
  on Windows is selectors.SelectSelector, and select() there is capped at
  FD_SETSIZE (512) file descriptors — a single selector simply cannot hold
  a 1000- or 2000-device fleet. Below that cap, though, each shard's loop
  is purely reactive exactly as a single selector would be: nothing is
  recomputed on a timer, and every time-varying value (uptime, counters,
  flapping ports, the scheduled outage and reboot devices) is derived from
  the clock at reply time. Idle CPU is therefore ~0 regardless of fleet
  size, and a device answers on whichever shard's thread holds its socket
  without the shards needing to know about each other.
* A slow device's reply is computed on arrival and parked on a due-time
  heap that its shard's selector loop drains, so one 2.6 s device cannot
  stall that loop (and, since the heap is per shard, cannot stall any
  other shard's loop either) and a hundred of them cannot queue behind
  each other. (A fixed-size thread pool was the obvious alternative and is
  wrong: with 87 devices at 400 ms and 8 workers, replies queue ~4 s deep
  and the poller sees timeouts no device actually caused.)
* A control HTTP server on 127.0.0.1:<control-port> exposes GET /state and
  POST /event, so a demo script can knock devices over and bring them back
  while the app watches.
"""

from __future__ import annotations

import argparse
import errno
import heapq
import hmac
import itertools
import json
import os
import selectors
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import personas                                   # noqa: E402
from demo.personas import DeviceState, build_device, fleet_plan   # noqa: E402
from netpath.snmppoll import decode_response, find_auth_span      # noqa: E402
from netpath.trapdecode import (                            # noqa: E402
    AUTH_PROTOCOLS, PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_REPORT,
    PDU_RESPONSE, Reader, T_COUNTER32, T_END_OF_MIB_VIEW, T_INTEGER, T_NULL,
    T_OCTET_STRING, T_SEQUENCE, V1, V2C, V3, _signed, _tlv, enc_int,
    enc_octets, enc_varbind, localized_key,
)

SNMP_PORT = 161
MAX_UDP = 65535
MAX_VARBINDS_PER_REPLY = 120        # keeps a GETBULK reply inside one datagram

# select.select()'s FD_SETSIZE limit is 512 on every platform CPython
# builds for, but on Windows selectors.DefaultSelector *is* SelectSelector
# (epoll/kqueue/poll do not exist there), so it is the only selector this
# process can use and 512 sockets is therefore a hard ceiling per selector,
# not just a soft default. Measured on this machine: 512 registered sockets
# selects fine (0.08 ms/call), 513 raises "ValueError: too many file
# descriptors in select()" — and it raises from inside serve_forever(),
# not from bind(), so an oversized shard binds all its sockets without
# complaint and only falls over on the very first poll, which looks at a
# glance like a fleet that started fine and then mysteriously died. 400
# rather than 512 leaves headroom for the handful of other descriptors a
# Python process already holds open (stdio, the interpreter's own
# housekeeping fds, the signal module's wakeup socket pair) so a shard
# that is otherwise full does not tip a select() call over FD_SETSIZE.
MAX_SOCKETS_PER_SHARD = 400

# usmStats counters, the objects a Report-PDU carries (RFC 3414 s5).
USM_UNKNOWN_ENGINE_IDS = "1.3.6.1.6.3.15.1.1.4.0"
USM_WRONG_DIGESTS = "1.3.6.1.6.3.15.1.1.5.0"
USM_UNKNOWN_USER_NAMES = "1.3.6.1.6.3.15.1.1.3.0"

FLAG_AUTH = 0x01
# RFC 3412 s6.4: the reportable bit is set on requests, never on a Response
# or a Report, so every message this module builds clears it. It is named
# here only so the zero is visibly deliberate.
FLAG_REPORTABLE = 0x04


# ------------------------------------------------------------ wire helpers

def read_community(data: bytes) -> str:
    """The community string off the wire.

    snmppoll.decode_response() skips it (it is not part of a Response),
    but a Cisco per-VLAN read carries the VLAN in it as `public@10`, so a
    fleet that wants to reproduce that path has to look. Same trick
    tests/stubs/stub_agent_fdb.py:read_community uses.
    """
    def length_at(i):
        first = data[i]
        if first < 0x80:
            return first, i + 1
        n = first & 0x7F
        return int.from_bytes(data[i + 1:i + 1 + n], "big"), i + 1 + n

    i = 1
    _outer, i = length_at(i)
    if data[i] != 0x02:
        raise ValueError("no version integer")
    vlen, i = length_at(i + 1)
    i += vlen
    if data[i] != 0x04:
        raise ValueError("no community string")
    clen, i = length_at(i + 1)
    return data[i:i + clen].decode("utf-8", "replace")


def _pdu(tag: int, request_id: int, error_status: int, error_index: int,
         body: bytes) -> bytes:
    return _tlv(tag, enc_int(request_id) + enc_int(error_status) +
                enc_int(error_index) + _tlv(T_SEQUENCE, body))


def reply_v1v2c(version: int, community: str, request_id: int, body: bytes,
                error_status: int = 0, error_index: int = 0) -> bytes:
    return _tlv(T_SEQUENCE, enc_int(version) + enc_octets(community) +
                _pdu(PDU_RESPONSE, request_id, error_status, error_index, body))


def null_varbinds(oids) -> bytes:
    """The request echoed back with null values — what a v1 agent returns
    alongside noSuchName, and what an authorizationError carries."""
    return b"".join(enc_varbind(oid, _tlv(T_NULL, b"")) for oid in oids)


def v3_meta(data: bytes) -> tuple[int, int]:
    """(msgID, msgFlags) out of an inbound v3 message. snmppoll._decode_v3
    reads past both, so they have to be re-read here to answer with the
    same msgID."""
    top = Reader(data)
    bs, be = top.expect(T_SEQUENCE)
    msg = Reader(data, bs, be)
    msg.expect(T_INTEGER)                       # msgVersion
    hs, he = msg.expect(T_SEQUENCE)
    header = Reader(data, hs, he)
    s, e = header.expect(T_INTEGER)
    msg_id = _signed(data, s, e)
    header.expect(T_INTEGER)                    # msgMaxSize
    fs, fe = header.expect(T_OCTET_STRING)
    flags = data[fs] if fe > fs else 0
    return msg_id, flags


def v3_message(msg_id: int, pdu_bytes: bytes, *, flags: int, engine_id: bytes,
               engine_boots: int, engine_time: int, user: str,
               auth_len: int) -> bytes:
    """The exact reverse of snmppoll._decode_v3 / _v3_message: msgGlobalData
    + USM security parameters + ScopedPDU, with the authentication field
    zero-filled ready to be signed."""
    header = _tlv(T_SEQUENCE, enc_int(msg_id) + enc_int(65507) +
                  _tlv(T_OCTET_STRING, bytes([flags])) + enc_int(3))
    usm = (enc_octets(engine_id) + enc_int(engine_boots) + enc_int(engine_time) +
           enc_octets(user) + _tlv(T_OCTET_STRING, bytes(auth_len)) +
           _tlv(T_OCTET_STRING, b""))
    sec_params = _tlv(T_OCTET_STRING, _tlv(T_SEQUENCE, usm))
    scoped = _tlv(T_SEQUENCE, enc_octets(engine_id) + enc_octets(b"") + pdu_bytes)
    return _tlv(T_SEQUENCE, enc_int(V3) + header + sec_params + scoped)


def sign_v3(message: bytes, key: bytes, proto: str = "SHA") -> bytes:
    """Blank-field HMAC, spliced in — the same operation
    trapdecode.Decoder._verify_v3 performs in reverse, so a message this
    signs verifies there."""
    ctor, digest_len = AUTH_PROTOCOLS[proto]
    start, end = find_auth_span(message)
    digest = hmac.new(key, message, ctor).digest()[:digest_len]
    return message[:start] + digest + message[end:]


def verify_v3(data: bytes, key: bytes, proto: str = "SHA") -> bool:
    ctor, digest_len = AUTH_PROTOCOLS[proto]
    try:
        start, end = find_auth_span(data)
    except Exception:
        return False
    sent = data[start:end]
    if len(sent) != digest_len:
        return False
    blanked = bytearray(data)
    blanked[start:end] = b"\x00" * digest_len
    computed = hmac.new(key, bytes(blanked), ctor).digest()[:digest_len]
    return hmac.compare_digest(computed, sent)


# ---------------------------------------------------------- PDU answering

def _get_body(table, dev: DeviceState, oids, now: float, version: int):
    """(body, error_status, error_index).

    SNMPv1 has no per-varbind exception markers: an object the agent does
    not implement spoils the WHOLE request with noSuchName and the varbind
    list echoed back as nulls. That is exactly the behaviour
    nodepoll._poll_snmp_scalars' long comment (nodepoll.py:1231-1265) says
    it splits its identity GET to survive, so the v1 persona reproduces it
    rather than answering the modern way.
    """
    body = b""
    for pos, oid in enumerate(oids, start=1):
        if table.has(oid):
            body += enc_varbind(oid, table.value_bytes(oid, dev, now))
        elif version == V1:
            return null_varbinds(oids), 2, pos          # noSuchName
        else:
            body += enc_varbind(oid, _tlv(0x80, b""))   # noSuchObject
    return body, 0, 0


def _getnext_body(table, dev: DeviceState, oids, now: float, version: int):
    body = b""
    for pos, oid in enumerate(oids, start=1):
        nxt = table.next_oid(oid)
        if nxt is None:
            if version == V1:
                return null_varbinds(oids), 2, pos      # v1 end of MIB
            body += enc_varbind(oid, _tlv(T_END_OF_MIB_VIEW, b""))
        else:
            body += enc_varbind(nxt, table.value_bytes(nxt, dev, now))
    return body, 0, 0


def _getbulk_body(table, dev: DeviceState, oids, now: float,
                  non_repeaters: int, max_repetitions: int) -> bytes:
    """RFC 3416 s4.2.3: the first `non_repeaters` bindings get one
    successor each, the rest get `max_repetitions` successors, emitted in
    repetition-major order."""
    non_repeaters = max(0, min(non_repeaters, len(oids)))
    body = b""
    count = 0

    def emit(request_oid: str, oid):
        nonlocal body, count
        if oid is None:
            body += enc_varbind(request_oid, _tlv(T_END_OF_MIB_VIEW, b""))
        else:
            body += enc_varbind(oid, table.value_bytes(oid, dev, now))
        count += 1

    for oid in oids[:non_repeaters]:
        emit(oid, table.next_oid(oid))

    cursors = list(oids[non_repeaters:])
    exhausted = [False] * len(cursors)
    for _ in range(max(1, max_repetitions)):
        if count >= MAX_VARBINDS_PER_REPLY or all(exhausted):
            break
        for i, cursor in enumerate(cursors):
            if exhausted[i]:
                continue
            nxt = table.next_oid(cursor)
            emit(cursor, nxt)
            if nxt is None:
                exhausted[i] = True
            else:
                cursors[i] = nxt
            if count >= MAX_VARBINDS_PER_REPLY:
                break
    return body


def handle_packet(dev: DeviceState, data: bytes, now: float | None = None) -> bytes | None:
    """The whole agent, as a pure function: request bytes in, reply bytes
    out (or None to drop the datagram, which is what a dead device, a wrong
    community and a wrong SNMP version all look like on the wire).

    Importable and callable with no socket bound, which is what
    demo/selftest.py exercises.
    """
    now = time.time() if now is None else now
    if not dev.is_alive(now):
        dev.drops += 1
        return None
    try:
        request = decode_response(data)
    except Exception:
        dev.drops += 1
        return None

    if request.version == V3:
        return _handle_v3(dev, data, request, now)

    if dev.v3:                      # a v3-only device ignores community traffic
        dev.drops += 1
        return None
    if dev.v1_only and request.version != V1:
        dev.drops += 1
        return None

    try:
        community = read_community(data)
    except Exception:
        dev.drops += 1
        return None
    ok, vlan = dev.accepts(community)
    if not ok:
        # Silence, not an error: a real agent that does not recognise the
        # community says nothing at all, which is why a wrong community
        # looks exactly like a dead device to the poller.
        dev.drops += 1
        return None

    oids = [vb["oid"] for vb in request.varbinds]
    dev.requests += 1
    dev.last_request_ts = now
    version = request.version

    if dev.auth_fail:
        dev.gets += 1
        return reply_v1v2c(version, community, request.request_id,
                           null_varbinds(oids), error_status=16, error_index=0)

    table = dev.table(vlan)

    if request.pdu_tag == PDU_GET:
        dev.gets += 1
        body, err, idx = _get_body(table, dev, oids, now, version)
        return reply_v1v2c(version, community, request.request_id, body, err, idx)

    if request.pdu_tag == PDU_GETNEXT:
        dev.getnexts += 1
        body, err, idx = _getnext_body(table, dev, oids, now, version)
        return reply_v1v2c(version, community, request.request_id, body, err, idx)

    if request.pdu_tag == PDU_GETBULK:
        dev.getbulks += 1
        if dev.v1_only:
            # v1 has no GetBulk-PDU at all; a v1 agent answers genErr.
            return reply_v1v2c(V1, community, request.request_id,
                               null_varbinds(oids), error_status=5, error_index=0)
        # non_repeaters and max_repetitions ride in the error_status /
        # error_index slots of the decoded request (snmppoll._pdu_bytes).
        non_repeaters = max(0, request.error_status)
        max_repetitions = max(1, request.error_index or 1)
        if dev.toobig and max_repetitions > 8:
            return reply_v1v2c(version, community, request.request_id, b"",
                               error_status=1, error_index=0)
        body = _getbulk_body(table, dev, oids, now, non_repeaters, max_repetitions)
        return reply_v1v2c(version, community, request.request_id, body)

    dev.drops += 1
    return None


def _report(dev: DeviceState, msg_id: int, request_id: int, now: float,
            oid: str) -> bytes:
    """A Report-PDU carrying this agent's engineID/boots/time — the answer
    to nodepoll._discover_engine's empty probe, and the reverse of
    snmppoll._decode_v3's engine fields."""
    body = enc_varbind(oid, _tlv(T_COUNTER32, b"\x01"))
    pdu = _pdu(PDU_REPORT, request_id, 0, 0, body)
    return v3_message(msg_id, pdu, flags=0, engine_id=dev.engine_id,
                      engine_boots=dev.engine_boots,
                      engine_time=int(now - dev.start_ts) + 1,
                      user="", auth_len=0)


def _handle_v3(dev: DeviceState, data: bytes, request, now: float) -> bytes | None:
    if not dev.v3:
        dev.drops += 1
        return None
    try:
        msg_id, flags = v3_meta(data)
    except Exception:
        dev.drops += 1
        return None

    dev.requests += 1
    dev.last_request_ts = now

    # Engine discovery: an empty engineID (and, in practice, an empty user)
    # is the RFC 3414 s4 probe. Answer with a Report naming this engine.
    if not request.engine_id or request.engine_id != dev.engine_id:
        return _report(dev, msg_id, request.request_id, now,
                       USM_UNKNOWN_ENGINE_IDS)
    if not request.user:
        return _report(dev, msg_id, request.request_id, now,
                       USM_UNKNOWN_ENGINE_IDS)
    if request.user != dev.v3_user:
        return _report(dev, msg_id, request.request_id, now,
                       USM_UNKNOWN_USER_NAMES)

    authenticated = False
    if dev.v3 == "sha":
        key = localized_key("SHA", dev.v3_password, dev.engine_id)
        if not (flags & FLAG_AUTH) or key is None or not verify_v3(data, key):
            return _report(dev, msg_id, request.request_id, now,
                           USM_WRONG_DIGESTS)
        authenticated = True
    elif flags & FLAG_AUTH:
        # noAuth device asked to authenticate: it has no key to check with.
        return _report(dev, msg_id, request.request_id, now, USM_WRONG_DIGESTS)

    oids = [vb["oid"] for vb in request.varbinds]
    table = dev.table(None)

    if dev.auth_fail:
        body, err, idx = null_varbinds(oids), 16, 0
    elif request.pdu_tag == PDU_GET:
        dev.gets += 1
        body, err, idx = _get_body(table, dev, oids, now, V2C)
    elif request.pdu_tag == PDU_GETNEXT:
        dev.getnexts += 1
        body, err, idx = _getnext_body(table, dev, oids, now, V2C)
    elif request.pdu_tag == PDU_GETBULK:
        dev.getbulks += 1
        non_repeaters = max(0, request.error_status)
        max_repetitions = max(1, request.error_index or 1)
        if dev.toobig and max_repetitions > 8:
            body, err, idx = b"", 1, 0
        else:
            body = _getbulk_body(table, dev, oids, now, non_repeaters,
                                 max_repetitions)
            err = idx = 0
    else:
        dev.drops += 1
        return None

    pdu = _pdu(PDU_RESPONSE, request.request_id, err, idx, body)
    digest_len = AUTH_PROTOCOLS["SHA"][1] if authenticated else 0
    message = v3_message(msg_id, pdu, flags=FLAG_AUTH if authenticated else 0,
                         engine_id=dev.engine_id,
                         engine_boots=dev.engine_boots,
                         engine_time=int(now - dev.start_ts) + 1,
                         user=dev.v3_user, auth_len=digest_len)
    if authenticated:
        key = localized_key("SHA", dev.v3_password, dev.engine_id)
        message = sign_v3(message, key)
    return message


# ------------------------------------------------------------- the fleet

class _Shard:
    """One selector's worth of device sockets, served by one thread.

    Everything a serve loop touches — the selector, the slow-responder
    due-time heap, the tie-breaking sequence counter — lives here rather
    than on Fleet, because it is precisely the state that must NOT be
    shared between shards: two threads pushing onto one heap or registering
    on one selector would need locking on every single packet, which is
    exactly the per-packet overhead sharding is meant to avoid. A device's
    socket is registered on exactly one shard for its whole life, so its
    deferred replies only ever need that shard's heap.
    """

    def __init__(self, index: int):
        self.index = index
        self.selector = selectors.DefaultSelector()
        self.sockets: list[socket.socket] = []
        # (due_ts, seq, sock, addr, reply) for devices with slow_ms set.
        self._deferred: list[tuple] = []
        self._seq = itertools.count()

    def register(self, sock: socket.socket, dev: DeviceState) -> None:
        self.sockets.append(sock)
        self.selector.register(sock, selectors.EVENT_READ, dev)

    def serve(self, stop: threading.Event) -> None:
        while not stop.is_set():
            timeout = 0.5
            if self._deferred:
                timeout = max(0.0, min(0.5, self._deferred[0][0] - time.time()))
            for key, _mask in self.selector.select(timeout=timeout):
                self._on_readable(key.fileobj, key.data)
            if self._deferred:
                self._flush_deferred()

    def _flush_deferred(self) -> None:
        now = time.time()
        while self._deferred and self._deferred[0][0] <= now:
            _due, _seq, sock, addr, reply = heapq.heappop(self._deferred)
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass

    def _on_readable(self, sock: socket.socket, dev: DeviceState) -> None:
        while True:
            try:
                data, addr = sock.recvfrom(MAX_UDP)
            except BlockingIOError:
                return
            except OSError:
                return
            # The answer is computed on arrival either way — that is when a
            # real agent reads its own counters — and only the send is
            # deferred for a slow device.
            reply = handle_packet(dev, data)
            if not reply:
                continue
            if dev.slow_ms > 0:
                heapq.heappush(self._deferred,
                               (time.time() + dev.slow_ms / 1000.0,
                                next(self._seq), sock, addr, reply))
                continue
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass

    def close(self) -> None:
        self._deferred.clear()
        for sock in self.sockets:
            try:
                self.selector.unregister(sock)
            except (KeyError, ValueError):
                pass
            sock.close()
        self.selector.close()


class Fleet:
    def __init__(self, count: int, quiet: bool = False):
        self.quiet = quiet
        self.plan = fleet_plan(count)
        self.devices: dict[str, DeviceState] = {}
        self.sockets: list[socket.socket] = []
        # Filled in by bind(), one shard per MAX_SOCKETS_PER_SHARD bound
        # devices; shard 0's loop runs on the main thread (see
        # serve_forever) and every other shard gets its own thread.
        self._shards: list[_Shard] = []
        self.started_ts = time.time()
        self._stop = threading.Event()

    def log(self, message: str) -> None:
        if not self.quiet:
            print(message, flush=True)

    def _shard_for(self, position: int) -> _Shard:
        """The shard that owns the `position`-th successfully bound socket,
        creating shards on demand so a device count that does not fill the
        last shard does not leave an empty one dangling."""
        index = position // MAX_SOCKETS_PER_SHARD
        while len(self._shards) <= index:
            self._shards.append(_Shard(len(self._shards)))
        return self._shards[index]

    def bind(self) -> None:
        failures = 0
        bound = 0
        for entry in self.plan:
            dev = build_device(entry)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # SO_REUSEADDR means "let me rebind a port stuck in TIME_WAIT"
            # on POSIX, which is exactly the harmless, useful thing a demo
            # that restarts a lot wants. On Windows it means something else
            # entirely: a second process can bind the SAME 127.0.0.x:161
            # that a first fleet already owns, and the OS then delivers
            # each inbound datagram to whichever of the two it feels like,
            # with no error raised anywhere — verified on this machine, and
            # exactly the kind of bug that only shows up as "the poller got
            # a reply from the wrong device" hours later. SO_EXCLUSIVEADDRUSE
            # is the Windows option that actually means "fail the bind if
            # anyone else already has this address," which is what every
            # other platform's default bind behaviour already gives you.
            # The two options are mutually exclusive and EXCLUSIVEADDRUSE
            # has to be set before bind(), same as REUSEADDR.
            if os.name == "nt":
                sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((dev.ip, SNMP_PORT))
            except OSError as exc:
                sock.close()
                failures += 1
                if failures <= 5:
                    hint = ""
                    if exc.errno == errno.EACCES:
                        # On POSIX this is unambiguous: binding 161 needs
                        # root. On Windows the same errno also covers a
                        # port RESERVED by another process (netsh
                        # excludedportrange, a Hyper-V NAT reservation) or
                        # simply another listener already sitting on that
                        # address — "needs root" would be actively
                        # misleading advice on that platform.
                        hint = (" (port 161 needs root)" if os.name != "nt"
                                else " (port reserved, or already in use "
                                     "by another listener)")
                    elif exc.errno == errno.EMFILE:
                        # ulimit -n only exists on POSIX; raising Windows'
                        # per-process handle ceiling is a registry change
                        # (USER Object/Handle quotas), not a shell command,
                        # so the two platforms need different hints for the
                        # same errno.
                        hint = (" (raise the open-file limit: ulimit -n 8192)"
                                if os.name != "nt" else
                                " (too many open handles for this process)")
                    print(f"bind {dev.ip}:{SNMP_PORT} failed: {exc}{hint}",
                          file=sys.stderr, flush=True)
                continue
            sock.setblocking(False)
            self.devices[dev.ip] = dev
            self.sockets.append(sock)
            self._shard_for(bound).register(sock, dev)
            bound += 1
        if failures:
            print(f"{failures} of {len(self.plan)} sockets failed to bind",
                  file=sys.stderr, flush=True)
        if not self.devices:
            raise SystemExit("no device sockets bound; nothing to serve")

    def serve_forever(self) -> None:
        # Shard 0 runs on the calling thread so Ctrl-C/SIGTERM keep working
        # exactly as before sharding existed (the signal handler sets
        # self._stop, and it is this thread's blocking select() call that
        # has to notice it and return); every other shard is driven from
        # its own thread and joined once shard 0's loop exits.
        threads = [threading.Thread(target=shard.serve, args=(self._stop,),
                                    name=f"shard-{shard.index}", daemon=True)
                  for shard in self._shards[1:]]
        for thread in threads:
            thread.start()
        if self._shards:
            self._shards[0].serve(self._stop)
        for thread in threads:
            thread.join()

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        for shard in self._shards:
            shard.close()

    # -------------------------------------------------------- control API

    def state(self) -> dict:
        return {"count": len(self.devices),
                "uptime_s": int(time.time() - self.started_ts),
                "devices": {ip: dev.snapshot()
                            for ip, dev in sorted(self.devices.items())}}

    def select_devices(self, body: dict) -> list[DeviceState]:
        if body.get("ip"):
            dev = self.devices.get(body["ip"])
            return [dev] if dev else []
        if body.get("ips"):
            return [self.devices[ip] for ip in body["ips"] if ip in self.devices]
        selector = body.get("select")
        if isinstance(selector, dict):
            picked = []
            for _ip, dev in sorted(self.devices.items()):
                if selector.get("persona") and dev.persona_key != selector["persona"]:
                    continue
                if selector.get("site") and dev.site != selector["site"]:
                    continue
                if selector.get("profile") and dev.profile != selector["profile"]:
                    continue
                picked.append(dev)
                if selector.get("limit") and len(picked) >= int(selector["limit"]):
                    break
            return picked
        return []

    def apply(self, dev: DeviceState, action: str, arg=None) -> bool:
        if action == "down":
            dev.alive = False
        elif action == "up":
            dev.alive = True
        elif action == "reboot":
            dev.reboot()
        elif action == "flap_start":
            if arg is None:
                return False
            dev.flapping.add(int(arg))
        elif action == "flap_stop":
            if arg is None:
                dev.flapping.clear()
            else:
                dev.flapping.discard(int(arg))
        elif action == "slow":
            dev.slow_ms = int(arg or 0)
        elif action == "community":
            dev.community = str(arg)
        elif action == "auth_fail_on":
            dev.auth_fail = True
        elif action == "auth_fail_off":
            dev.auth_fail = False
        elif action == "toobig_on":
            dev.toobig = True
        elif action == "toobig_off":
            dev.toobig = False
        elif action == "on_battery":
            # personas._build_apc_ups reads nothing but this one flag: every
            # upsBattery/PowerNet scalar (upsSecondsOnBattery, the charge and
            # runtime-remaining counters, upsOutputSource) is a pure function
            # of dev.on_battery and the clock, so flipping it is the whole
            # event — the charge is already seen to count down against real
            # elapsed time with no further action needed here.
            dev.on_battery = True
        elif action == "on_mains":
            dev.on_battery = False
        elif action == "temp_hot_on":
            # Same shape for personas._room_temp_c: a Room Alert has exactly
            # two states, not an arbitrary setpoint, so "over a threshold"
            # is this flag rather than a temperature value.
            dev.temp_hot = True
        elif action == "temp_hot_off":
            dev.temp_hot = False
        else:
            return False
        return True

    def event(self, body: dict) -> int:
        action = str(body.get("action") or "")
        arg = body.get("arg")
        applied = 0
        for dev in self.select_devices(body):
            if self.apply(dev, action, arg):
                applied += 1
        if applied:
            self.log(f"event {action}(arg={arg!r}) applied to {applied} device(s)")
        return applied


# --------------------------------------------------------- control server

class _ControlHandler(BaseHTTPRequestHandler):
    fleet: Fleet | None = None
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:        # quiet by default
        pass

    def _send(self, code: int, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in ("/state", "/"):
            self._send(200, self.fleet.state())
        elif path == "/alive":
            # A one-device liveness answer for demo/bin/ping, so a device
            # taken "down" stops answering ICMP as well as SNMP — loopback
            # would otherwise answer every ping and the app (correctly)
            # never marks a ping-answering device down.
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            ip = ""
            for part in query.split("&"):
                if part.startswith("ip="):
                    ip = part[3:]
            dev = self.fleet.devices.get(ip)
            self._send(200, {"ip": ip,
                             "alive": (bool(dev.alive) if dev is not None else None)})
        elif path == "/personas":
            self._send(200, {"personas": sorted(personas.PERSONAS)})
        elif path == "/specials":
            self._send(200, {"specials": {str(k): v
                                          for k, v in personas.SPECIALS.items()}})
        else:
            self._send(404, {"ok": False, "error": "no such path"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError as exc:
            self._send(400, {"ok": False, "error": f"bad JSON: {exc}"})
            return
        if path != "/event":
            self._send(404, {"ok": False, "error": "no such path"})
            return
        try:
            applied = self.fleet.event(body)
        except (TypeError, ValueError, KeyError) as exc:
            self._send(400, {"ok": False, "error": str(exc)})
            return
        self._send(200, {"ok": True, "applied": applied})


def start_control_server(fleet: Fleet, port: int) -> ThreadingHTTPServer:
    handler = type("ControlHandler", (_ControlHandler,), {"fleet": fleet})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="control",
                     daemon=True).start()
    return server


# -------------------------------------------------------------- scenarios

def load_scenario(path: str) -> list[dict]:
    """A JSON list of {"at_s": N, ...event}, applied relative to start."""
    with open(path, "r", encoding="utf-8") as handle:
        events = json.load(handle)
    if not isinstance(events, list):
        raise ValueError("a scenario file is a JSON list of events")
    return sorted(events, key=lambda e: float(e.get("at_s", 0)))


def start_scenario(fleet: Fleet, events: list[dict]) -> threading.Thread:
    """One 1 s ticker. The scheduled dark/reboot devices need no thread at
    all — DeviceState.is_alive()/boot() derive those from the clock at
    reply time — so this exists only for the scenario file."""
    pending = list(events)
    started = time.time()

    def run() -> None:
        while pending and not fleet._stop.is_set():
            elapsed = time.time() - started
            while pending and float(pending[0].get("at_s", 0)) <= elapsed:
                event = pending.pop(0)
                try:
                    applied = fleet.event(event)
                    fleet.log(f"t+{elapsed:.0f}s scenario "
                              f"{event.get('action')} -> {applied} device(s)")
                except Exception as exc:
                    fleet.log(f"scenario event failed: {exc}")
            time.sleep(1.0)

    thread = threading.Thread(target=run, name="scenario", daemon=True)
    thread.start()
    return thread


# ------------------------------------------------------------------- main

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--count", type=int, default=30,
                        help="how many devices to simulate (default 30)")
    parser.add_argument("--control-port", type=int, default=8099,
                        help="control HTTP port on 127.0.0.1 (default 8099)")
    parser.add_argument("--scenario", default="",
                        help="JSON file of time-scheduled events")
    parser.add_argument("--quiet", action="store_true",
                        help="only print the listening banner")
    args = parser.parse_args(argv)

    fleet = Fleet(args.count, quiet=args.quiet)
    events = load_scenario(args.scenario) if args.scenario else []
    fleet.bind()

    server = None
    try:
        server = start_control_server(fleet, args.control_port)
    except OSError as exc:
        print(f"control port {args.control_port} unavailable: {exc}",
              file=sys.stderr, flush=True)

    def shutdown(_signum, _frame):
        fleet.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    if events:
        start_scenario(fleet, events)

    first = fleet.plan[0]["ip"]
    last = fleet.plan[len(fleet.devices) - 1]["ip"]
    print(f"fleet listening on {len(fleet.devices)} devices "
          f"{first}:{SNMP_PORT}..{last}:{SNMP_PORT}, control "
          f"http://127.0.0.1:{args.control_port}/state", flush=True)

    try:
        fleet.serve_forever()
    finally:
        if server is not None:
            server.shutdown()
        fleet.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
