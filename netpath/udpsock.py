"""Socket facts the three collectors share: dual-stack binds, source
addresses, and how many datagrams the kernel threw away before anyone read
them.

All three listeners bound AF_INET only, so a device sending syslog or traps
from an IPv6 management address could not reach the collector at all — no
bind error, no rejection counter, just silence, with nothing to tell "not
configured" apart from "cannot be received". `bind` here asks for a
dual-stack socket and falls back to IPv4 where the platform will not give
one, and `normalise_source` folds the `::ffff:a.b.c.d` form a dual-stack
socket reports back to the dotted quad the allow lists and the device
correlation are written in.

The drop counter:

Every collector counts a message it had to drop because its own queue was
full, but that only fires once the message has already been read off the
socket.  The real loss point under load is the socket receive buffer, and
nothing read it back: the review offered 300,000 syslog messages at 38k/s,
93,412 were stored, 206,588 were dropped by the kernel, and the status strip
said "93,412 messages · 93,412 stored" with a loss counter of zero.  That is
worse than an outage, because it looks fine.

Linux publishes the figure as the last column of ``/proc/net/udp`` and
``/proc/net/udp6``, one row per bound socket, keyed on the local address and
port in hex.  No other platform this application runs on exposes anything
comparable cheaply, so there the counter is simply absent rather than
guessed at — an absent number is honest, a fabricated one is not.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import time

log = logging.getLogger(__name__)

PROC_FILES = ("/proc/net/udp", "/proc/net/udp6")
POLL_INTERVAL_S = 5.0


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
