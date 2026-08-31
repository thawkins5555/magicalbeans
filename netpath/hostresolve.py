"""Shared "best-known display name for an IP" lookup, used by Syslog's
Host column and the Alerts module's Object column alike, so both agree
with the Nodes module's own display precedence rather than each picking
a different one."""

from __future__ import annotations


def resolve_name(nodes_db, app_db, ip: str, device=None) -> str | None:
    """The Nodes module's SNMP-polled `sys_name` first (matching Nodes'
    own display convention, `sys_name || name || ip`), then a manually-set
    device name that isn't just the bare IP, then the DNS reverse-lookup
    cache. None if nothing is known. Pass `device` when the caller already
    has the row, to skip a redundant lookup."""
    if device is None and nodes_db is not None:
        device = nodes_db.device_by_ip(ip)
    if device:
        name = device["sys_name"] or (
            device["name"] if device["name"] != device["ip"] else "")
        if name:
            return name
    if app_db is not None:
        names = app_db.hostnames([ip])
        if names.get(ip):
            return names[ip]
    return None
