"""The syslog listener.

Same split as the flow collector: sockets are read on their own threads and a
writer drains a queue in batches. Syslog arrives in far heavier bursts than
NetFlow — a single misbehaving device can produce thousands of lines a second —
so the receive path does nothing but read, parse and enqueue.
"""

from __future__ import annotations

import collections
import queue
import socket
import threading
import time
import traceback

from . import udpsock
from .eventlog import ERROR, SYSTEM
from .syslogdb import SyslogDatabase
from .syslogparse import parse
from .worker import ago

BATCH = 500
FLUSH_S = 1.0
# The per-source rate buckets are keyed on a spoofable source address, so the
# dict is an LRU rather than an unbounded one.
MAX_RATE_SOURCES = 4096

# The most one TCP-framed message may be, either framing. RFC 6587 octet
# counting reads a length prefix of up to ten digits and the newline framing
# has no length prefix at all, so without this nothing bounds how large a
# single message can grow before it is even looked at: a connection declaring
# a 2 GB octet count and trickling bytes toward it grows the buffer without
# limit while every counter stays at zero. No real syslog message — even one
# carrying a sizeable RFC 5424 structured-data block — comes close to 1 MB.
MAX_TCP_MESSAGE_BYTES = 1_000_000


class SyslogCollector(udpsock.UdpReceiver):
    NOUN = "Collector"
    DROPS_PORT_NOUN = "syslog"
    LOG_CATEGORY = SYSTEM
    QUEUE_SIZE = 100_000
    COUNTERS = {"messages": 0, "stored": 0, "collapsed": 0,
                "dropped": 0, "rejected": 0, "filtered": 0,
                "errors": 0, "throttled": 0, "tcp_refused": 0,
                "tcp_oversized": 0, "tcp_clients": 0,
                "last_message": 0.0}

    def __init__(self, db: SyslogDatabase, log=None, on_batch=None):
        super().__init__(log)
        self.db = db
        self.on_batch = on_batch
        self._allowed: set[str] = set()
        self._auto_accept = True
        self._use_receive_time = False
        self._min_severity = 7
        self._max_chars = 2048
        # source -> [tokens, last refill]. One float pair per source, refilled
        # lazily on arrival, so throttling costs O(1) per message and cannot
        # grow past MAX_RATE_SOURCES entries however many addresses appear.
        self._buckets: collections.OrderedDict = collections.OrderedDict()
        self._rate = 0.0
        self._max_tcp_clients = 64
        self._clients: list[threading.Thread] = []

    # --------------------------------------------------------------- lifecycle

    def start(self, settings: dict) -> bool:
        self.stop()
        self._reset_for_start()

        allow = str(settings.get("allowed_sources", "") or "")
        self._allowed = {item.strip() for item in allow.replace(",", "\n").split("\n")
                         if item.strip()}
        self._auto_accept = bool(settings.get("auto_accept_sources", True))
        self._use_receive_time = bool(settings.get("use_receive_time", False))
        self._min_severity = int(settings.get("min_severity", 7))
        self._max_chars = max(int(settings.get("max_message_chars", 2048)), 80)
        self._rate = max(0.0, float(settings.get("per_source_rate", 200) or 0))
        self._max_tcp_clients = max(1, int(settings.get("max_tcp_clients", 64)))
        self._buckets.clear()
        self.db.collapse_repeats_s = max(
            0.0, float(settings.get("collapse_repeats_s", 5.0) or 0))

        address = settings.get("bind_address", "0.0.0.0")
        port = int(settings.get("port", 514))
        tcp_port = int(settings.get("tcp_port", 0)) or port
        buffer_bytes = int(settings.get("socket_buffer_kb", 4096)) * 1024
        self.ports = {}

        try:
            if settings.get("accept_udp", True):
                self._udp = self._bind(socket.SOCK_DGRAM, address, port,
                                       buffer_bytes)
                self.ports["UDP"] = port
            if settings.get("accept_tcp", False):
                self._tcp = self._bind(socket.SOCK_STREAM, address, tcp_port,
                                       buffer_bytes)
                self._tcp.listen(64)
                self.ports["TCP"] = tcp_port
        except OSError as exc:
            where = (f"{address}:{port}" if tcp_port == port
                     else f"{address} (UDP {port}, TCP {tcp_port})")
            hint = ""
            code = getattr(exc, "errno", None)
            if code in (13, 1):
                hint = (" — ports below 1024 need administrator or root "
                        "rights. Use 5140 and point devices at it instead.")
            elif code in (48, 98, 10048):
                hint = (" — another process already holds it. On Windows: "
                        "Get-NetUDPEndpoint -LocalPort " + str(port) +
                        " | Select OwningProcess. Another syslog daemon is the "
                        "usual answer; change the port in Settings if so.")
            self.error = f"Could not bind {where}: {exc}{hint}"
            self.log.add(ERROR, self.error)
            self.stop()
            return False

        if self._udp is None and self._tcp is None:
            self.error = "Neither UDP nor TCP is enabled"
            return False

        if self._udp is not None:
            self._arm_kernel_drops(port)
        else:
            self._drops = None
            self._drops_logged = False
            self.counters.pop("kernel_dropped", None)

        self.bound = (address, port)
        if self._udp is not None:
            self._spawn(self._receive_udp, "syslog-udp")
        if self._tcp is not None:
            self._spawn(self._receive_tcp, "syslog-tcp")
        self._spawn(self._write, "syslog-write")

        where = ", ".join(f"{name} {value}" for name, value in self.ports.items())
        self.log.add(SYSTEM, f"Syslog listening on {address} ({where})")
        return True

    def stop(self) -> None:
        super().stop()
        for thread in self._clients:
            if thread.is_alive():
                thread.join(timeout=2)
        self._clients = []
        self.counters["tcp_clients"] = 0

    # ------------------------------------------------------------------ errors

    def _note_error(self, exc: Exception) -> None:
        # The counters survive a restart, so errors are accumulated in the
        # counter itself rather than republished from a per-run total.
        self.counters["errors"] += 1
        self._log_throttled("receive", f"Receive error: {exc}",
                            detail=traceback.format_exc)

    # ------------------------------------------------------------------ access

    def _accepted(self, source: str) -> bool:
        if self._allowed:
            return source in self._allowed
        return self._auto_accept

    def _within_rate(self, source: str, now: float) -> bool:
        """A token bucket per source, refilled lazily.

        Without it one device in a debug loop consumed the whole queue and
        evicted every other device's messages, and `dropped` could not say
        whose. O(1) per message and bounded in memory.
        """
        if self._rate <= 0:
            return True
        bucket = self._buckets.get(source)
        if bucket is None:
            bucket = [self._rate, now]
            self._buckets[source] = bucket
            while len(self._buckets) > MAX_RATE_SOURCES:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(source)
            bucket[0] = min(self._rate, bucket[0] + (now - bucket[1]) * self._rate)
            bucket[1] = now
        if bucket[0] < 1.0:
            return False
        bucket[0] -= 1.0
        return True

    # ----------------------------------------------------------------- threads

    def _enqueue(self, data: bytes, source: str) -> None:
        # Counted after the access check, not before: a rejected source used
        # to refresh "last message just now", so the status strip read healthy
        # while every packet was being thrown away.
        if not self._accepted(source):
            self.counters["rejected"] += 1
            return
        now = time.time()
        if not self._within_rate(source, now):
            self.counters["throttled"] += 1
            self._log_throttled("throttle",
                                f"Throttling syslog from {source}: more than "
                                f"{self._rate:.0f} messages a second",
                                target=source,
                                detail="Messages above the per-source rate are "
                                       "discarded so one noisy device cannot "
                                       "evict everyone else's. Raise or clear "
                                       "the per-source rate in Settings to keep "
                                       "them all.")
            return
        self.counters["messages"] += 1
        self.counters["last_message"] = now
        if self._first_from(source):
            self.log.add(SYSTEM, f"First syslog message from {source}",
                         target=source)
        try:
            entry = parse(data, source)
            # Filter before the queue: a device stuck in a debug loop should
            # cost nothing beyond the parse.
            if entry.severity > self._min_severity:
                self.counters["filtered"] += 1
                return
            if len(entry.message) > self._max_chars:
                entry.message = entry.message[:self._max_chars] + "…"
            if self._use_receive_time:
                entry.ts = time.time()
            self._queue.put_nowait(entry)
        except queue.Full:
            self.counters["dropped"] += 1

    def _handle_datagram(self, data: bytes, address) -> None:
        self._enqueue(data, udpsock.normalise_source(address[0]))

    def _receive_tcp(self) -> None:
        sock = self._tcp
        while not self._stop.is_set() and sock is not None:
            try:
                client, address = sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                # A peer that reset between SYN and accept, or a brief EMFILE, is
                # not a reason to end the listener; a closed socket is.
                if self._stop.is_set() or self._tcp is None:
                    break
                self._note_error(exc)
                time.sleep(0.05)
                continue
            # One thread per connection with no cap and a list that only ever
            # grew: a device that reconnects per message, or a scanner,
            # exhausted threads and then memory. Dead ones are reaped on every
            # accept and the live ones are capped.
            address = (udpsock.normalise_source(address[0]),) + tuple(address[1:])
            self._clients = [t for t in self._clients if t.is_alive()]
            self.counters["tcp_clients"] = len(self._clients)
            if len(self._clients) >= self._max_tcp_clients:
                self.counters["tcp_refused"] += 1
                try:
                    client.close()
                except OSError:
                    pass
                continue
            thread = threading.Thread(
                target=lambda c=client, a=address[0]: self._read_stream(c, a),
                name="syslog-tcp-client", daemon=True)
            self._clients.append(thread)
            self.counters["tcp_clients"] = len(self._clients)
            thread.start()

    def _note_oversized(self, source: str, declared: int | None = None) -> None:
        """Count a TCP message that hit MAX_TCP_MESSAGE_BYTES, and log at most
        one line a minute so a sender doing this repeatedly cannot fill the
        event log."""
        self.counters["tcp_oversized"] += 1
        what = (f"a declared length of {declared:,} bytes" if declared is not None
                else f"no newline within {MAX_TCP_MESSAGE_BYTES:,} bytes")
        self._log_throttled("oversized",
                            f"Oversized TCP syslog message from {source} refused "
                            f"({what})",
                            target=source,
                            detail="No real syslog message approaches "
                                   f"{MAX_TCP_MESSAGE_BYTES:,} bytes. Without this "
                                   "cap the sender's own claimed size (octet "
                                   "counting) or an unterminated line (newline "
                                   "framing) would grow this connection's buffer "
                                   "without limit.")

    def _read_stream(self, client: socket.socket, source: str) -> None:
        """A TCP stream is a byte stream, so messages must be reassembled.

        Both framings are handled: RFC 6587 octet counting (`123 <13>...`) and
        the far more common newline separation. Neither may grow the buffer
        past MAX_TCP_MESSAGE_BYTES.

        The two framings are refused differently because they can be recovered
        from differently. Octet counting is refused the moment the *declared*
        length is read and the connection is then closed outright, because the
        only way to find where the next frame starts is to read past `length`
        bytes of this one — exactly the commitment being refused. Newline
        framing keeps the connection open and resumes from the next `\\n`.
        """
        client.settimeout(30)
        buffer = b""
        try:
            while not self._stop.is_set():
                chunk = client.recv(65536)
                if not chunk:
                    break
                buffer += chunk
                while buffer:
                    space = buffer.find(b" ")
                    # RFC 6587 octet counting: "<count> <message>", and the
                    # message always starts with a PRI. Without the "<" test a
                    # newline-framed line that merely starts with a number
                    # ("123 packets dropped") was read as a length prefix and
                    # the connection desynchronised from there on.
                    if (0 < space <= 10 and buffer[:space].isdigit()
                            and buffer[space + 1:space + 2] == b"<"):
                        length = int(buffer[:space])
                        if length > MAX_TCP_MESSAGE_BYTES:
                            self._note_oversized(source, declared=length)
                            return
                        if len(buffer) < space + 1 + length:
                            break
                        self._enqueue(buffer[space + 1:space + 1 + length], source)
                        buffer = buffer[space + 1 + length:]
                        continue
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        if len(buffer) > MAX_TCP_MESSAGE_BYTES:
                            self._note_oversized(source)
                            buffer = b""
                        break
                    self._enqueue(buffer[:newline], source)
                    buffer = buffer[newline + 1:]
        except (OSError, ValueError):
            pass
        except Exception as exc:
            # One malformed stream must not take the whole receiver down.
            self._note_error(exc)
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _write(self) -> None:
        pending: list = []
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                pending.append(self._queue.get(timeout=0.3))
            except queue.Empty:
                pass
            self._poll_kernel_drops()
            due = time.time() - last_flush >= FLUSH_S
            if pending and (due or len(pending) >= BATCH):
                try:
                    stored, collapsed = self.db.insert(pending)
                    self.counters["stored"] += stored
                    # A row's own repeat_count carries a collapsed message
                    # forward (see syslogdb._collapse), so nothing is lost —
                    # but "stored" alone undercounts "messages" by exactly
                    # this much, and reads as an unexplained gap without it.
                    self.counters["collapsed"] += collapsed
                except Exception:
                    traceback.print_exc()
                pending.clear()
                last_flush = time.time()
                if self.on_batch:
                    self.on_batch()
        if pending:
            try:
                self.db.insert(pending)
            except Exception:
                pass

    # ------------------------------------------------------------------ status

    def _listening_text(self) -> str:
        address, _ = self.bound or ("?", 0)
        where = ", ".join(f"{name} {value}" for name, value in self.ports.items())
        base = f"Listening on {address} ({where})"
        last = self.counters["last_message"]
        return (f"{base} · last message {ago(last)}" if last
                else f"{base} · waiting for messages")

    def _status_parts(self) -> list[str]:
        parts = []
        if self.counters["throttled"]:
            parts.append(f"{self.counters['throttled']} throttled")
        if self.counters["tcp_clients"]:
            parts.append(f"{self.counters['tcp_clients']} TCP clients")
        if self.counters["tcp_oversized"]:
            parts.append(f"{self.counters['tcp_oversized']} oversized TCP messages refused")
        return parts
