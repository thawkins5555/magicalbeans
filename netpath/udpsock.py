"""What the three UDP listeners share: dual-stack binds, source addresses,
kernel drop counts, and the UdpReceiver base they all subclass.

`bind` asks for a dual-stack socket and falls back to IPv4 where the platform
will not give one; `normalise_source` folds the `::ffff:a.b.c.d` form a
dual-stack socket reports back to the dotted quad the allow lists and the
device correlation are written in.

counters["dropped"] only ever counted a message the application itself threw
away, after it had been read off the socket. The real loss point under load
is the socket receive buffer, which Linux publishes as the last column of
``/proc/net/udp``/``udp6``, keyed on the local address and port in hex. No
other platform this runs on exposes anything comparable cheaply, so there the
counter is absent rather than guessed at.
"""

from __future__ import annotations

import collections
import logging
import os
import queue
import socket
import sys
import threading
import time
import traceback

from .eventlog import ERROR, NullLog

log = logging.getLogger(__name__)

PROC_FILES = ("/proc/net/udp", "/proc/net/udp6")
POLL_INTERVAL_S = 5.0

# Cap on the "first message from ..." memories: their keys are spoofable
# source addresses, so they are LRUs rather than unbounded sets.
MAX_SEEN_SOURCES = 4096


def bind(kind: int, address: str, port: int, buffer_bytes: int = 0,
         exclusive: bool = True):
    """A listening socket on (address, port), dual-stack where possible.

    Returns (socket, family). "0.0.0.0" and "" mean "everything", so they are
    bound as "::" on an AF_INET6 socket with IPV6_V6ONLY cleared, which
    accepts both families on every platform this runs on that supports it; a
    literal address is bound in its own family. A host with IPv6 disabled, or
    one that refuses to clear V6ONLY, falls back to AF_INET so nothing that
    worked before stops working.
    """
    wildcard = address in ("", "0.0.0.0", "::")
    family = socket.AF_INET
    bind_address = address
    if wildcard:
        family, bind_address = socket.AF_INET6, "::"
    elif ":" in address:
        family, bind_address = socket.AF_INET6, address

    try:
        sock = _make(family, kind, bind_address, port, buffer_bytes, exclusive)
    except OSError:
        if family != socket.AF_INET6 or not wildcard:
            raise
        # No IPv6 on this host. An IPv4-only listener is what shipped, so it
        # is the right thing to fall back to rather than refusing to start.
        sock = _make(socket.AF_INET, kind, "0.0.0.0", port, buffer_bytes,
                     exclusive)
        return sock, socket.AF_INET
    return sock, family


def _make(family: int, kind: int, address: str, port: int, buffer_bytes: int,
          exclusive: bool):
    sock = socket.socket(family, kind)
    try:
        if os.name == "nt" and exclusive:
            # Two processes can silently share a UDP port under SO_REUSEADDR
            # on Windows, and one of them swallows the datagrams while both
            # look healthy. SO_EXCLUSIVEADDRUSE makes a duplicate bind fail
            # loudly instead.
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except (AttributeError, OSError):
                pass
        elif os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (AttributeError, OSError):
                pass
        if buffer_bytes:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_bytes)
            except OSError:
                pass
        sock.bind((address, port))
        sock.settimeout(0.5)          # so a loop can notice its stop event
    except BaseException:
        sock.close()
        raise
    return sock


def normalise_source(address: str) -> str:
    """The dotted quad behind an IPv4-mapped IPv6 source address.

    A dual-stack socket reports an IPv4 sender as "::ffff:10.0.0.1". Allow
    lists, per-source rate buckets and device correlation are all written in
    dotted quads, so they would all silently stop matching without this.
    """
    if address.startswith("::ffff:") and "." in address:
        return address[7:]
    return address


def supported() -> bool:
    """True where the drops column can be read at all."""
    return sys.platform.startswith("linux") and os.path.exists(PROC_FILES[0])


def _read_port(port: int) -> int | None:
    """Cumulative drops across every UDP socket bound to `port`.

    Returns None when the figure cannot be read at all (not Linux, /proc not
    mounted, no row for the port yet), which the caller reports as "unknown"
    rather than as zero.
    """
    wanted = f"{port:04X}"
    total = None
    for path in PROC_FILES:
        try:
            with open(path, "r", encoding="ascii", errors="replace") as handle:
                handle.readline()                     # column headings
                for line in handle:
                    parts = line.split()
                    # sl, local_address, rem_address, ..., drops
                    if len(parts) < 13:
                        continue
                    local = parts[1]
                    if local.rsplit(":", 1)[-1] != wanted:
                        continue
                    try:
                        drops = int(parts[-1])
                    except ValueError:
                        continue
                    total = drops if total is None else total + drops
        except OSError:
            continue
    return total


class KernelDrops:
    """Throttled reader of one bound port's kernel drop counter.

    The counter in /proc belongs to the socket, not to the process, so a
    freshly bound socket starts at zero; the first reading is still taken as
    a baseline so that a leftover socket on the same port cannot make the
    collector report loss it never suffered.
    """

    def __init__(self, port: int, interval_s: float = POLL_INTERVAL_S):
        self.port = int(port)
        self.interval_s = float(interval_s)
        self._baseline: int | None = None
        self._last_read = 0.0
        self._value = 0

    def poll(self, force: bool = False) -> int | None:
        """Drops since this reader was created, or None while unknown.

        Reads /proc at most once every `interval_s`; between reads it returns
        the last value, so this is safe to call from a collector's flush loop.
        """
        now = time.monotonic()
        if not force and self._baseline is not None and now - self._last_read < self.interval_s:
            return self._value
        raw = _read_port(self.port)
        if raw is None:
            return None if self._baseline is None else self._value
        self._last_read = now
        if self._baseline is None:
            self._baseline = raw
        self._value = max(0, raw - self._baseline)
        return self._value


def lru_add(store: collections.OrderedDict, key, cap: int = MAX_SEEN_SOURCES) -> bool:
    """True the first time `key` is offered to `store` since it was cleared.

    The key is a source address, which anyone with network reach can vary, so
    the memory is bounded and least-recently-used rather than growing for the
    life of the process.
    """
    if key in store:
        store.move_to_end(key)
        return False
    store[key] = None
    while len(store) > cap:
        store.popitem(last=False)
    return True


class UdpReceiver:
    """What the three UDP listeners share: sockets, threads, drops, status.

    Subclasses own their settings, decoding and writer thread; they supply
    _handle_datagram for one datagram and _listening_text for the head of the
    status line.
    """

    NOUN = "Collector"
    PORT_LABEL = "UDP"
    # The word the kernel-drop line names the port by ("NetFlow", "trap",
    # "syslog").
    DROPS_PORT_NOUN = "UDP"
    LOG_CATEGORY: str | None = None
    # Whether stop() files a "<NOUN> stopped" line; only the flow collector did.
    STOP_LOG = False
    QUEUE_SIZE = 20_000
    COUNTERS: dict = {}

    def __init__(self, log=None):
        self.log = log or NullLog()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._queue: queue.Queue = queue.Queue(maxsize=self.QUEUE_SIZE)
        self._seen: collections.OrderedDict = collections.OrderedDict()
        self.counters: dict = dict(self.COUNTERS)
        self.error: str | None = None
        self.bound: tuple[str, int] | None = None
        self.family = socket.AF_INET
        self.rcvbuf = 0
        self.ports: dict[str, int] = {}
        # A receive thread must never be able to die on message content, so
        # its per-datagram work is guarded and the failures counted here;
        # _crash records a thread that ended anyway, so the status strip can
        # say "stopped unexpectedly" instead of looking like an operator stop.
        self._loop_errors = 0
        self._crash: str | None = None
        self._drops: KernelDrops | None = None
        self._drops_logged = False
        self._log_times: dict[str, float] = {}

    # --------------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        # Every thread, not any of them: a dead writer with a live receiver
        # left this True while nothing at all was being stored, and the status
        # strip went on reading "listening ... last message just now".
        return bool(self._threads) and all(t.is_alive() for t in self._threads)

    def _reset_for_start(self) -> None:
        self.error = None
        self._crash = None
        self._loop_errors = 0
        self._stop.clear()
        self._seen.clear()

    def _bind(self, kind: int, address: str, port: int, buffer_bytes: int):
        """A listening socket, with the clamped-receive-buffer warning."""
        sock, self.family = bind(kind, address, port, buffer_bytes)
        try:
            self.rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        except OSError:
            self.rcvbuf = 0
        if kind == socket.SOCK_DGRAM and self.rcvbuf and self.rcvbuf < buffer_bytes:
            # Linux reports back twice what it granted, so a readback below
            # the request means net.core.rmem_max clamped it, the commonest
            # reason for kernel drops under load.
            self.log.add(ERROR,
                         f"The receive buffer was clamped to {self.rcvbuf} bytes "
                         f"(asked for {buffer_bytes})",
                         detail="Raise net.core.rmem_max on this host, or lower "
                                "the buffer size in Settings so the two agree.")
        return sock

    def _arm_kernel_drops(self, port: int) -> None:
        """Start counting the kernel's own loss on `port`, where it is published.

        The counter key is absent rather than zero on a platform that does not
        publish the figure: an absent number is honest, a fabricated one is not.
        """
        self._drops = KernelDrops(port) if supported() else None
        self._drops_logged = False
        if self._drops is not None:
            self.counters["kernel_dropped"] = 0
        else:
            self.counters.pop("kernel_dropped", None)

    def _spawn(self, target, name: str) -> None:
        thread = threading.Thread(target=lambda: self._guard(target, name),
                                  name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _guard(self, target, name: str) -> None:
        """Run a receiver thread and remember how it ended, so a crash reads
        as "stopped unexpectedly" rather than as an operator stop."""
        try:
            target()
        except Exception as exc:
            self._crash = f"{name}: {exc}"
            self.log.add(ERROR, f"The {name} thread stopped unexpectedly: {exc}",
                         detail=traceback.format_exc())
        else:
            if not self._stop.is_set():
                self._crash = f"{name} ended unexpectedly"

    def stop(self) -> None:
        if self.STOP_LOG and self.LOG_CATEGORY and self.running:
            self.log.add(self.LOG_CATEGORY, f"{self.NOUN} stopped")
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

    # ------------------------------------------------------------------ access

    def _first_from(self, source: str) -> bool:
        """True the first time a source is seen since the last start."""
        return lru_add(self._seen, source)

    # ------------------------------------------------------------------ errors

    def _poll_kernel_drops(self) -> None:
        """Read back the kernel's own loss counter for the bound port.

        counters["dropped"] only counts a message the writer queue could not
        take, which is loss the application caused; datagrams the socket
        buffer discarded before anyone read them were invisible.
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
                         f"The kernel is dropping datagrams on "
                         f"{self.DROPS_PORT_NOUN} port "
                         f"{self._drops.port}: {value} lost before they could "
                         f"be read",
                         detail="The socket receive buffer is full: the sender "
                                "is faster than this host can drain it. Raise "
                                "the buffer size in Settings, and on Linux "
                                "raise net.core.rmem_max to at least that "
                                "value.")

    def _log_throttled(self, key: str, message: str, detail: str = "",
                       target: str = "", interval_s: float = 60.0) -> bool:
        """Log one line per `key` per interval, so a flood of anything cannot
        fill the event log. True when this call did log."""
        now = time.time()
        if now - self._log_times.get(key, 0.0) < interval_s:
            return False
        self._log_times[key] = now
        self.log.add(ERROR, message, target=target, detail=detail)
        return True

    def _sync_error_counter(self) -> None:
        """Republish counters["errors"] after _loop_errors changed. Overridden
        where a decoder keeps errors of its own to add in."""
        self.counters["errors"] = self._loop_errors

    def _note_error(self, exc: Exception) -> None:
        """Count a datagram the receive path could not process, and log at
        most one traceback a minute so a flood cannot fill the event log."""
        self._loop_errors += 1
        self._sync_error_counter()
        self._log_throttled("receive", f"Receive error: {exc}",
                            detail=traceback.format_exc())

    # ----------------------------------------------------------------- threads

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
                self._handle_datagram(data, address)
            except Exception as exc:
                self._note_error(exc)

    def _handle_datagram(self, data: bytes, address) -> None:
        """One datagram, already read off the socket. Anything it raises is
        counted and throttled by _receive_udp."""
        raise NotImplementedError

    # ------------------------------------------------------------------ status

    def _listening_text(self) -> str:
        """The head of the status line while the receiver is up: where it is
        listening, and how long ago the last message arrived."""
        raise NotImplementedError

    def _status_parts(self) -> list[str]:
        """Per-receiver tail of the status line: throttled, truncated, and the
        other counters worth surfacing."""
        return []

    def status_text(self) -> str:
        if self.error:
            return self.error
        if not self.running:
            if self._crash:
                return f"{self.NOUN} stopped unexpectedly: {self._crash}"
            return f"{self.NOUN} stopped"
        parts = [self._listening_text()]
        lost = self.counters.get("kernel_dropped", 0)
        if lost:
            parts.append(f"{lost} dropped by the kernel")
        parts.extend(self._status_parts())
        return " · ".join(parts)
