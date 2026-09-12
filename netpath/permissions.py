"""The per-module read/write permission model. MODULES is the exhaustive
list of gate-able modules — one per top-level tab, plus "ssh" (an
interactive shell is a different power from reading/backing up a config,
granted to nobody by default). configrx:read is the least obvious grant:
it hands over a device's full stored configuration (secrets redacted,
topology intact — addressing, ACLs, routes, VPN peers), not merely backup
metadata, on the reasoning that seeing a change should not require the
permission to make one.
"""

from __future__ import annotations

# Nothing derives this list from the three tables that must agree with it —
# server.ROUTES' permission tuples, api.SETTINGS_SCOPES and
# service._MODULE_SCOPES. tests/test_permission_registry.py is what keeps the
# four in step; a new module means editing all four and that suite says so.
MODULES = (
    "netpath", "netflow", "snmp", "syslog", "ipam", "nodes", "alerts",
    "wireless", "configrx",
    # MAPPER (4.54): a real tab, like every module above it, so it takes an
    # ordinary slot among them rather than being appended past "settings"
    # the way ssh/admin below are — those two are appended because they are
    # NOT tabs and have no natural slot to begin with; mapper has one (it
    # sits with the Nodes group in the shell, see index.html). Slotted after
    # "configrx" rather than after "nodes" itself so this tuple's position
    # (the only thing that matters here — user_permissions is keyed
    # (username, module), so no account's grant moves no matter where a new
    # module is inserted) still puts "ssh" and "admin" last, which is all
    # test_web_security.py actually pins: MODULES[-2:] == ("ssh", "admin").
    # This placement keeps that true.
    "mapper",
    "settings", "debug",
    # The WEB button's TCP relay is a power of its own — nodes:read means
    # "may see this device", not "may reach its management page through
    # this server". Slotted before "ssh" so MODULES[-2:] == ("ssh", "admin")
    # still holds.
    "web",
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
