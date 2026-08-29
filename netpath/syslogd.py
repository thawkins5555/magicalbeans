"""The syslog listener.

Same split as the flow collector: sockets are read on their own threads and a
writer drains a queue in batches. Syslog arrives in far heavier bursts than
NetFlow — a single misbehaving device can produce thousands of lines a second —
so the receive path does nothing but read, parse and enqueue.
"""

from __future__ import annotations

import os
import queue
import socket
import threading
import time

from .eventlog import ERROR, NullLog, SYSTEM
from .syslogdb import SyslogDatabase
from .syslogparse import parse

BATCH = 500
FLUSH_S = 1.0


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
                         "rejected": 0, "filtered": 0, "last_message": 0.0}
        self.ports: dict[str, int] = {}
        self._allowed: set[str] = set()
        self._auto_accept = True
        self._use_receive_time = False
        self._min_severity = 7
        self._max_chars = 2048
        self._seen: set[str] = set()

    @property
    def running(self) -> bool:
        return any(thread.is_alive() for thread in self._threads)

    # --------------------------------------------------------------- lifecycle

    def start(self, settings: dict) -> bool:
        self.stop()
        self.error = None
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
        except OSError:
            pass
        sock.bind((address, port))
        sock.settimeout(0.5)
        return sock

    def _spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

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
        if source not in self._seen:
            self._seen.add(source)
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
            self._enqueue(data, address[0])

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
            return "Collector stopped"
        address, _ = self.bound or ("?", 0)
        where = ", ".join(f"{name} {value}" for name, value in self.ports.items())
        base = f"Listening on {address} ({where})"
        last = self.counters["last_message"]
        return f"{base} \u00b7 last message {_ago(last)}" if last else \
            f"{base} \u00b7 waiting for messages"
