"""A bounded in-memory event log, written by every background worker (trace
scheduler, traceroute wrapper, reverse-DNS resolver, flow collector) and
read by the debug page — for watching what the app is doing now, never
written to disk. Guarded by a lock; readers pull by sequence number rather
than holding a reference to the buffer.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

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

# The default ring, overridable per install by `debug_log_capacity`.
DEFAULT_CAPACITY = 10000

# How many distinct targets the filter drop-down remembers. The events
# themselves are capped at `capacity`, but the set of targets seen
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
    def __init__(self, capacity: int = DEFAULT_CAPACITY,
                 target_limit: int = TARGET_LIMIT):
        self._lock = threading.Lock()
        self._events: deque[Event] = deque(maxlen=max(1, int(capacity)))
        self._seq = 0
        # Identifies this process's log: seq restarts at 0 on every start,
        # so a reader's cursor is only meaningful within one epoch.
        self.epoch = time.time()
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

    def since_with_seq(self, seq: int) -> tuple[list[Event], int]:
        """One snapshot. Read under two lock holds, an event landing between
        them is absent from the batch and already behind the cursor."""
        with self._lock:
            return ([event for event in self._events if event.seq > seq],
                    self._seq)

    def all(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    def set_capacity(self, n: int) -> None:
        n = max(1, int(n))
        with self._lock:
            if self._events.maxlen == n:
                return
            # maxlen keeps the LAST n, so a shrink drops the oldest.
            self._events = deque(self._events, maxlen=n)

    @property
    def capacity(self) -> int:
        return self._events.maxlen

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

    epoch = 0.0

    def since(self, seq: int) -> list:
        return []

    def since_with_seq(self, seq: int) -> tuple:
        return ([], 0)

    def all(self) -> list:
        return []

    def set_capacity(self, n: int) -> None:
        return None

    @property
    def capacity(self) -> int:
        return 0

    @property
    def last_seq(self) -> int:
        return 0

    def targets(self) -> list:
        return []

    def clear(self) -> None:
        return None
