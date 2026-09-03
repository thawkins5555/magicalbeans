"""A bounded in-memory event log -- bounded in both of its collections.

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
from collections import OrderedDict, deque
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
MESSAGE_LIMIT = 512

# How many distinct targets the filter drop-down remembers. The events
# themselves are capped at `capacity` (3,000), but the set of targets seen
# was not capped, pruned, or cleared: the resolver adds one per address it
# looks up, the SSH terminal one per device, ConfigRX one per device, and
# the trap and syslog paths one per source -- so on a fleet that also
# resolves traceroute hops and receives syslog from transient sources it
# grew for the process's lifetime, and targets() sorted the whole thing
# under the lock on every debug-page poll. 1,000 is well past any real
# fleet's device count and bounds both.
TARGET_LIMIT = 1000


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
    def __init__(self, capacity: int = 3000, target_limit: int = TARGET_LIMIT):
        self._lock = threading.Lock()
        self._events: deque[Event] = deque(maxlen=capacity)
        self._seq = 0
        # An OrderedDict used as an LRU set: re-seeing a target moves it to
        # the end, so what falls off the front is genuinely the least
        # recently mentioned. `_sorted_targets` caches what targets() hands
        # back, because that is read on every debug-page poll and only
        # changes when a target is first seen or evicted.
        self._targets: OrderedDict[str, None] = OrderedDict()
        self._target_limit = max(1, int(target_limit))
        self._sorted_targets: list[str] = []

    def add(self, category: str, message: str, target: str = "",
            detail: str = "") -> None:
        if message and len(message) > MESSAGE_LIMIT:
            # A message is a headline: the debug page renders it in a table
            # cell and one row of it is not worth a screenful. Anything that
            # long belongs in `detail`, which has its own, larger cap.
            message = message[:MESSAGE_LIMIT] + "…"
        if detail and len(detail) > DETAIL_LIMIT:
            detail = detail[:DETAIL_LIMIT] + "\n… truncated …"
        with self._lock:
            self._seq += 1
            self._events.append(Event(self._seq, time.time(), category,
                                      target, message, detail))
            if target:
                self._note_target(target)

    def _note_target(self, target: str) -> None:
        """Caller holds the lock. Only a first sighting or an eviction
        invalidates the cached sort; a repeat sighting is a move_to_end."""
        if target in self._targets:
            self._targets.move_to_end(target)
            return
        self._targets[target] = None
        while len(self._targets) > self._target_limit:
            self._targets.popitem(last=False)
        self._sorted_targets = []

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
            if not self._sorted_targets and self._targets:
                self._sorted_targets = sorted(self._targets)
            return list(self._sorted_targets)

    def clear(self) -> None:
        """Clears the targets as well as the events. It did not, so the
        filter drop-down went on offering every device the log had ever
        mentioned after the operator had emptied it."""
        with self._lock:
            self._events.clear()
            self._targets.clear()
            self._sorted_targets = []


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
