"""How many datagrams the kernel threw away before a collector could read them.

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
import sys
import time

log = logging.getLogger(__name__)

PROC_FILES = ("/proc/net/udp", "/proc/net/udp6")
POLL_INTERVAL_S = 5.0


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
