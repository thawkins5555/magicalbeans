"""The syslog listener.

Same split as the flow collector: sockets are read on their own threads and a
writer drains a queue in batches. Syslog arrives in far heavier bursts than
NetFlow — a single misbehaving device can produce thousands of lines a second —
so the receive path does nothing but read, parse and enqueue.
"""

from __future__ import annotations

import collections
import os
import queue
import socket
import threading
import time
import traceback

from . import kerneldrops
from .eventlog import ERROR, NullLog, SYSTEM
from .syslogdb import SyslogDatabase
from .syslogparse import parse

BATCH = 500
FLUSH_S = 1.0
# Cap on the "first message from ..." memory: the key is a spoofable source
# address, so it is an LRU rather than an unbounded set.
MAX_SEEN_SOURCES = 4096


def _ago(ts: float) -> str:
    if not ts:
        return "never"
    age = time.time() - ts
    if age < 5:
        return "just now"
    if age < 90:
        return f"{age:.0f}s ago"
    if age < 5400:
        return f"{age / 60:.0f}m ago"
    return f"{age / 3600:.1f}h ago"


class SyslogCollector:
    def __init__(self, db: SyslogDatabase, log=None, on_batch=None):
        self.db = db
        self.log = log or NullLog()
        self.on_batch = on_batch
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._queue: queue.Queue = queue.Queue(maxsize=100_000)
        self.error: str | None = None
        self.bound: tuple[str, int] | None = None
        self.counters = {"messages": 0, "stored": 0, "dropped": 0,
                         "rejected": 0, "filtered": 0, "errors": 0,
                         "last_message": 0.0}
        # A receive thread must never die on message content; failures are
        # counted here and _crash records a thread that ended anyway so the
        # status strip does not read like a deliberate stop.
        self._last_error_log = 0.0
        self._crash: str | None = None
        self._drops: kerneldrops.KernelDrops | None = None
        self._drops_logged = False
        self.ports: dict[str, int] = {}
        self._allowed: set[str] = set()
        self._auto_accept = True
        self._use_receive_time = False
        self._min_severity = 7
        self._max_chars = 2048
        self._seen: collections.OrderedDict = collections.OrderedDict()

    @property
    def running(self) -> bool:
        return any(thread.is_alive() for thread in self._threads)

    # --------------------------------------------------------------- lifecycle

    def start(self, settings: dict) -> bool:
        self.stop()
        self.error = None
        self._crash = None
        self._stop.clear()
        self._seen.clear()

        allow = str(settings.get("allowed_sources", "") or "")
        self._allowed = {item.strip() for item in allow.replace(",", "\n").split("\n")
                         if item.strip()}
        self._auto_accept = bool(settings.get("auto_accept_sources", True))
        self._use_receive_time = bool(settings.get("use_receive_time", False))
        self._min_severity = int(settings.get("min_severity", 7))
        self._max_chars = max(int(settings.get("max_message_chars", 2048)), 80)

        address = settings.get("bind_address", "0.0.0.0")
        port = int(settings.get("port", 514))
        tcp_port = int(settings.get("tcp_port", 0)) or port
        buffer_bytes = int(settings.get("socket_buffer_kb", 4096)) * 1024
        self.ports: dict[str, int] = {}

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
                hint = (" \u2014 ports below 1024 need administrator or root "
                        "rights. Use 5140 and point devices at it instead.")
            elif code in (48, 98, 10048):
                hint = (" \u2014 another process already holds it. On Windows: "
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

        self._drops = (kerneldrops.KernelDrops(port)
                       if self._udp is not None and kerneldrops.supported() else None)
        self._drops_logged = False
        if self._drops is not None:
            self.counters["kernel_dropped"] = 0
        else:
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

    def _bind(self, kind, address: str, port: int, buffer_bytes: int):
        sock = socket.socket(socket.AF_INET, kind)
        if os.name == "nt":
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except (AttributeError, OSError):
                pass
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            option = socket.SO_RCVBUF
            sock.setsockopt(socket.SOL_SOCKET, option, buffer_bytes)
            granted = sock.getsockopt(socket.SOL_SOCKET, option)
            if kind == socket.SOCK_DGRAM and granted < buffer_bytes:
                # Linux reports back twice what it granted, so a readback
                # below the request means net.core.rmem_max clamped it — the
                # commonest reason for kernel drops under load.
                self.log.add(ERROR,
                             f"The receive buffer was clamped to {granted} bytes "
                             f"(asked for {buffer_bytes})",
                             detail="Raise net.core.rmem_max on this host, or "
                                    "lower the buffer size in Settings so the "
                                    "two agree.")
        except OSError:
            pass
        sock.bind((address, port))
        sock.settimeout(0.5)
        return sock

    def _spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=lambda: self._guard(target, name),
                                  name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _guard(self, target, name: str) -> None:
        """Run a collector thread and remember how it ended, so a crash reads
        as "stopped unexpectedly" rather than as an operator stop."""
        try:
            target()
        except Exception as exc:
            self._crash = f"{name}: {exc}"
            self.log.add(ERROR, f"The {name} thread stopped unexpectedly: {exc}",
                         detail=traceback.format_exc())
        else:
            if not self._stop.is_set() and name != "syslog-tcp-client":
                self._crash = f"{name} ended unexpectedly"


    def _poll_kernel_drops(self) -> None:
        """Read back the kernel's own loss counter for the bound port.

        counters["dropped"] only counts a message the writer queue could not
        take, which is loss the application caused; datagrams the socket
        buffer discarded before anyone read them were invisible. The key is
        absent on platforms that do not publish the figure.
        """
        if self._drops is None:
            return
        value = self._drops.poll()
        if value is None:
            return
        previous = self.counters.get("kernel_dropped", 0)
        self.counters["kernel_dropped"] = value
        if value > previous and not self._drops_logged:
            self._drops_logged = True
            self.log.add(ERROR,
                         f"The kernel is dropping datagrams on syslog port "
                         f"{self._drops.port}: {value} lost before they could "
                         f"be read",
                         detail="The socket receive buffer is full: the sender "
                                "is faster than this host can drain it. Raise "
                                "the buffer size in Settings, and on Linux "
                                "raise net.core.rmem_max to at least that "
                                "value.")

    def _note_error(self, exc: Exception) -> None:
        """Count a message the receive path could not process; log at most one
        traceback a minute so a flood cannot fill the event log."""
        self.counters["errors"] += 1
        now = time.time()
        if now - self._last_error_log >= 60:
            self._last_error_log = now
            self.log.add(ERROR, f"Receive error: {exc}",
                         detail=traceback.format_exc())

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._udp, self._tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._udp = self._tcp = None
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2)
        self._threads = []
        self.bound = None

    # ----------------------------------------------------------------- threads


    def _first_from(self, source: str) -> bool:
        """True the first time a source is seen since the last start.

        The set is keyed on the datagram's source address, which anyone with
        network reach can vary, so it is bounded and least-recently-used
        rather than growing for the life of the process.
        """
        if source in self._seen:
            self._seen.move_to_end(source)
            return False
        self._seen[source] = None
        while len(self._seen) > MAX_SEEN_SOURCES:
            self._seen.popitem(last=False)
        return True

    def _accepted(self, source: str) -> bool:
        if self._allowed:
            return source in self._allowed
        return self._auto_accept

    def _enqueue(self, data: bytes, source: str) -> None:
        self.counters["messages"] += 1
        self.counters["last_message"] = time.time()
        if not self._accepted(source):
            self.counters["rejected"] += 1
            return
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

    def _receive_udp(self) -> None:
        sock = self._udp
        while not self._stop.is_set() and sock is not None:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._enqueue(data, address[0])
            except Exception as exc:
                self._note_error(exc)

    def _receive_tcp(self) -> None:
        sock = self._tcp
        while not self._stop.is_set() and sock is not None:
            try:
                client, address = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._spawn(lambda c=client, a=address[0]: self._read_stream(c, a),
                        "syslog-tcp-client")

    def _read_stream(self, client: socket.socket, source: str) -> None:
        """A TCP stream is a byte stream, so messages must be reassembled.

        Both framings are handled: RFC 6587 octet counting (`123 <13>...`) and
        the far more common newline separation.
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
                    if 0 < space <= 10 and buffer[:space].isdigit():
                        length = int(buffer[:space])
                        if len(buffer) < space + 1 + length:
                            break
                        self._enqueue(buffer[space + 1:space + 1 + length], source)
                        buffer = buffer[space + 1 + length:]
                        continue
                    newline = buffer.find(b"\n")
                    if newline < 0:
                        if len(buffer) > 1_000_000:      # runaway, drop it
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
                    self.counters["stored"] += self.db.insert(pending)
                except Exception:
                    import traceback
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

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            if self._crash:
                return f"Collector stopped unexpectedly: {self._crash}"
            return "Collector stopped"
        address, _ = self.bound or ("?", 0)
        where = ", ".join(f"{name} {value}" for name, value in self.ports.items())
        base = f"Listening on {address} ({where})"
        last = self.counters["last_message"]
        text = (f"{base} \u00b7 last message {_ago(last)}" if last
                else f"{base} \u00b7 waiting for messages")
        lost = self.counters.get("kernel_dropped", 0)
        return f"{text} \u00b7 {lost} dropped by the kernel" if lost else text
