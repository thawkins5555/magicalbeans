"""The per-module read/write permission model. Deliberately its own small
module rather than folded into appdb.py or eventlog.py: eventlog.CATEGORIES
is a different, non-matching taxonomy (built for the Debug page's log
filter, missing Syslog/Dashboard/Settings/Debug, including non-module
system/error categories) and was never meant to double as an authorization
module list.

MODULES is the exhaustive list of gate-able modules — one per top-level
tab, including the two added alongside this feature (Wireless, ConfigRX),
plus "ssh", the one entry with no tab of its own: an interactive shell on a
device is a different power from reading or backing up its config, so it is
its own module, granted to nobody by default.
"dashboard" is intentionally excluded: it's an aggregate view of whatever
other modules a user can already read, not a module with its own data to
gate (see api.get_state's per-section filtering).

configrx's read tier is the least obvious grant in this table, so it is
worth stating plainly what it hands over: GET /api/configrx/backups/<id>
gives a configrx:read account a device's stored configuration verbatim —
secrets redacted, but topology intact, meaning interface addressing, ACLs,
routes and VPN peers for every device with a capture on file. Reading one
backup's content used to require write, the same as every other module's
read/write split; a security review ahead of 4.48.1 raised the question
of whether "read" should carry that much and the operator's answer was
yes, on the reasoning that seeing what changed on a switch is the point
of the module and should not itself require the permission to change one
(see server.py's ROUTES comment beside that route for the fuller
argument). Granting configrx:read is granting that, not merely "may see
backup metadata" — know it before handing it out.
"""

from __future__ import annotations

MODULES = (
    "netpath", "netflow", "snmp", "syslog", "ipam", "nodes", "alerts",
    "wireless", "configrx", "settings", "debug",
    # Not a tab: the interactive SSH terminal opened from a Nodes device.
    # Its own module because ConfigRX write means "may back up configs", a
    # boundary of exactly two fixed read-only commands, and an interactive
    # shell is a different thing to be trusted with. Appended rather than
    # slotted in beside configrx so the grid a user already knows does not
    # reshuffle.
    "ssh",
    # Not a tab either: administering the application itself — accounts and
    # their grants, password resets for other people, the maintenance
    # actions that delete retention data, the audit log, and whether this
    # host may replace its own code from GitHub. It exists because
    # `settings: write` was quietly all of that as well as "may change the
    # poll interval": the lowest-privilege way to hold Settings was also the
    # way to grant yourself every module. Appended, again, so the grid does
    # not reshuffle; migrated onto the accounts that already held
    # settings:write, so nobody loses access on upgrade.
    "admin",
)

READ = "read"
WRITE = "write"
LEVELS = (READ, WRITE)


class Forbidden(PermissionError):
    """A refusal about what this operator may do, not about who they are.

    The distinction is not cosmetic. A bare PermissionError is answered 401,
    which the browser side reads as "your session has gone" and follows by
    replacing the page with the sign-in form. For a caller whose session is
    perfectly good that is a redirect to sign-in and straight back again,
    with the refusal — the sentence that says which setting to turn on, or
    that the action needs an administrator — thrown away in between. This is
    answered 403, so the message reaches the person who asked.
    """


def allows(granted: str | None, required: str) -> bool:
    """True if a `granted` level (None, 'read' or 'write' — whatever a user
    actually has for a module) satisfies a route's `required` level. write
    implies read; anything implies nothing granted at all is refused."""
    if not granted:
        return False
    if required == READ:
        return granted in (READ, WRITE)
    return granted == WRITE
