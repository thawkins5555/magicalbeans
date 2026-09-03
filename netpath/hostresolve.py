"""Shared "best-known display name for an IP" lookup, used by Syslog's
Host column, the Alerts module's Object column and NetPath's hop labels
alike, so they agree with the Nodes module's own display precedence rather
than each picking a different one."""

from __future__ import annotations


def device_name(device) -> str:
    """A Nodes device's display name, the way Nodes itself computes it:
    the manual name when the device is explicitly pinned to it, else the
    SNMP-polled sysName, else the manual name, else nothing.

    `display_name_source` used to be ignored here, so a device deliberately
    pinned to its manual name still displayed its sysName everywhere except
    the Nodes tab and ConfigRX. Same precedence as api._configrx_device_json.
    """
    if not device:
        return ""
    keys = device.keys() if hasattr(device, "keys") else device
    pinned = ("display_name_source" in keys
              and device["display_name_source"] == "manual")
    manual = device["name"] if device["name"] != device["ip"] else ""
    if pinned and manual:
        return manual
    return device["sys_name"] or manual or ""


def device_for_ip(nodes_db, ip: str):
    """The Nodes device at `ip`, by its polling address or by any address it
    is known to own.

    Matching on `devices.ip` alone means a switch polled at its management
    VLAN address but built with `logging source-interface Loopback0` — the
    standard build wherever there is a management VRF — correlates with
    nothing: no name in the Syslog Host column, no name on the alert, no way
    to filter its messages by device. The alias table is looked up through
    getattr because a database from before it exists simply does not have it.
    """
    if nodes_db is None:
        return None
    device = nodes_db.device_by_ip(ip)
    if device is not None:
        return device
    lookup = getattr(nodes_db, "device_id_for_address", None)
    if lookup is None:
        return None
    try:
        device_id = lookup(ip)
    except Exception:
        return None
    return nodes_db.device(device_id) if device_id else None


def resolve_name(nodes_db, app_db, ip: str, device=None) -> str | None:
    """The Nodes module's device name first (see device_name), then the DNS
    reverse-lookup cache. None if nothing is known. Pass `device` when the
    caller already has the row, to skip a redundant lookup."""
    if device is None:
        device = device_for_ip(nodes_db, ip)
    name = device_name(device)
    if name:
        return name
    if app_db is not None:
        names = app_db.hostnames([ip])
        if names.get(ip):
            return names[ip]
    return None


def fill_from_nodes(nodes_db, names: dict, ips) -> dict:
    """Adds a Nodes device name for every IP the DNS cache could not name.

    DNS first, Nodes second — the opposite order to resolve_name above, and
    deliberately so: this fills the gaps in a *reverse-DNS* result rather than
    deciding a display name from scratch. A hop with a real PTR record keeps
    it; a hop with none, which the graph labelled "no PTR record", gets the
    name of the device this app is already monitoring at that address.

    Returns {ip: source} for the ones it filled, so a caller can say where a
    name came from — "this hop is a device I manage" is the useful part.
    """
    filled = {}
    if nodes_db is None:
        return filled
    for ip in ips:
        if names.get(ip):
            continue
        device = device_for_ip(nodes_db, ip)
        name = device_name(device)
        if name:
            names[ip] = name
            filled[ip] = "nodes"
    return filled
