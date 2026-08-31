"""A bounded in-memory event log.

Every background worker writes here: the trace scheduler, the traceroute
subprocess wrapper, the reverse-DNS resolver and the flow collector. The debug
page reads it. Nothing is written to disk — this is for watching what the app
is doing right now, not for retention.

Writers are worker threads and the reader is the Qt main thread, so the deque
is guarded by a lock and readers pull by sequence number rather than holding a
reference to the buffer.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

# Categories are fixed so the debug page can offer them as filters without
# discovering them at runtime.
TRACE = "trace"
DNS = "dns"
NETFLOW = "netflow"
SNMP = "snmp"
NODES = "nodes"
ALERTS = "alerts"
IPAM = "ipam"
WIRELESS = "wireless"
CONFIGRX = "configrx"
SYSTEM = "system"
ERROR = "error"

CATEGORIES = [TRACE, DNS, NETFLOW, SNMP, NODES, ALERTS, IPAM, WIRELESS,
             CONFIGRX, SYSTEM, ERROR]

DETAIL_LIMIT = 6000


@dataclass
class Event:
    seq: int
    ts: float
    category: str
    target: str
    message: str
    detail: str = ""

    @property
    def clock(self) -> str:
        local = time.localtime(self.ts)
        return f"{time.strftime('%H:%M:%S', local)}.{int((self.ts % 1) * 1000):03d}"


class EventLog:
    def __init__(self, capacity: int = 3000):
        self._lock = threading.Lock()
        self._events: deque[Event] = deque(maxlen=capacity)
        self._seq = 0
        self._targets: set[str] = set()

    def add(self, category: str, message: str, target: str = "",
            detail: str = "") -> None:
        if detail and len(detail) > DETAIL_LIMIT:
            detail = detail[:DETAIL_LIMIT] + "\n… truncated …"
        with self._lock:
            self._seq += 1
            self._events.append(Event(self._seq, time.time(), category,
                                      target, message, detail))
            if target:
                self._targets.add(target)

    def since(self, seq: int) -> list[Event]:
        """Everything newer than `seq`, oldest first."""
        with self._lock:
            return [event for event in self._events if event.seq > seq]

    def all(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._seq

    def targets(self) -> list[str]:
        with self._lock:
            return sorted(self._targets)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class NullLog:
    """Stand-in so instrumented code never has to check for None."""

    def add(self, *args, **kwargs) -> None:
        return None

    def since(self, seq: int) -> list:
        return []

    def all(self) -> list:
        return []

    @property
    def last_seq(self) -> int:
        return 0

    def targets(self) -> list:
        return []

    def clear(self) -> None:
        return None
