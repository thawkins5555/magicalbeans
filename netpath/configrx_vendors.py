"""The hard safety boundary of ConfigRX's BACKUP path: an exhaustive,
per-vendor allow-list of exactly what a backup may ever send over an SSH
session. Nothing on that path sends anything beyond a vendor's
`pager_off` lines (session-scoped, read-only pagination settings) and its
single `show_config` command — there is no free-form command execution
anywhere in ConfigRX, by construction: nothing here accepts arbitrary
text and there is no code path that builds a command from anything other
than these fixed strings.

That guarantee is about backups. The interactive SSH terminal
(sshterm.py) is a separate feature with a separate boundary — a real
shell, driven by a human, behind its own `ssh` permission that nobody
holds by default — and it neither uses this table nor reaches the backup
path. ConfigRX write still means only "may back up configs".

Vendor keys are lowercase, matching nodeoids.vendor_for()'s output (itself
sourced from trapoids.WELL_KNOWN's vendor-root names) so a Nodes device's
already-detected vendor can be used directly; a device_config row's
vendor_override is free text for anyone WELL_KNOWN or vendor_for() doesn't
cover (e.g. "hp"/"aruba", which has no SNMP enterprise root registered
there today).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Vendor:
    label: str
    pager_off: tuple = field(default_factory=tuple)
    show_config: str = ""


VENDORS = {
    "cisco": Vendor("Cisco IOS/IOS-XE", ("terminal length 0",), "show running-config"),
    "fortinet": Vendor("Fortinet FortiOS",
                       ("config system console", "set output standard", "end"),
                       "show full-configuration"),
    "juniper": Vendor("Juniper Junos", ("set cli screen-length 0",), "show configuration"),
    "mikrotik": Vendor("MikroTik RouterOS", (), "/export"),
    "hp": Vendor("HP/Aruba", ("no page",), "show running-config"),
    "aruba": Vendor("HP/Aruba", ("no paging",), "show running-config"),
}


def resolve(vendor_key: str) -> Vendor | None:
    return VENDORS.get((vendor_key or "").strip().lower()) or None
