"""The per-module read/write permission model. Deliberately its own small
module rather than folded into appdb.py or eventlog.py: eventlog.CATEGORIES
is a different, non-matching taxonomy (built for the Debug page's log
filter, missing Syslog/Dashboard/Settings/Debug, including non-module
system/error categories) and was never meant to double as an authorization
module list.

MODULES is the exhaustive list of gate-able modules — one per top-level
tab, including the two added alongside this feature (Wireless, ConfigRX).
"dashboard" is intentionally excluded: it's an aggregate view of whatever
other modules a user can already read, not a module with its own data to
gate (see api.get_state's per-section filtering).
"""

from __future__ import annotations

MODULES = (
    "netpath", "netflow", "snmp", "syslog", "ipam", "nodes", "alerts",
    "wireless", "configrx", "settings", "debug",
    # Not a tab: the interactive SSH terminal opened from a Nodes device, and
    # forgetting a remembered host key. Its own module because ConfigRX write
    # means "may back up configs", a boundary of exactly two fixed read-only
    # commands, and an interactive shell is a different thing to be trusted
    # with. Appended rather than slotted in beside configrx so the grid a user
    # already knows does not reshuffle.
    "ssh",
)

READ = "read"
WRITE = "write"
LEVELS = (READ, WRITE)


def allows(granted: str | None, required: str) -> bool:
    """True if a `granted` level (None, 'read' or 'write' — whatever a user
    actually has for a module) satisfies a route's `required` level. write
    implies read; anything implies nothing granted at all is refused."""
    if not granted:
        return False
    if required == READ:
        return granted in (READ, WRITE)
    return granted == WRITE
