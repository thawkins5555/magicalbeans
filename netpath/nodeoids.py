"""Built-in polled-metric OID catalog for the Nodes poller.

Not a MIB compiler (same framing as trapoids.py). A fixed table of OIDs
this app polls by default, split into "always poll" (near-universal
SNMPv2-MIB scalars and the IF-MIB interface table) and "poll if the vendor
OID resolves" (best-effort — a failed GET on one of these is silently
skipped, never counted as a poll failure).
"""

from __future__ import annotations

DEFAULT_SNMP_PORT = 161   # shared by nodepoll.py and nodediscover.py

# Always attempted — standard SNMPv2-MIB scalars every agent implements.
SYSTEM_SCALARS = {
    "sys_descr":     "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_uptime":    "1.3.6.1.2.1.1.3.0",
    "sys_contact":   "1.3.6.1.2.1.1.4.0",
    "sys_name":      "1.3.6.1.2.1.1.5.0",
    "sys_location":  "1.3.6.1.2.1.1.6.0",
}

# IF-MIB table, walked (GETBULK/GETNEXT) per device, one row per interface.
# ifXTable's 64-bit/high-speed columns are preferred when present, since a
# 32-bit ifInOctets counter on a gigabit link wraps in under 35 seconds at
# line rate and would misreport as a rate reset far too often to be useful.
IF_TABLE = {
    "if_index":        "1.3.6.1.2.1.2.2.1.1",
    "if_descr":        "1.3.6.1.2.1.2.2.1.2",
    "if_admin_status": "1.3.6.1.2.1.2.2.1.7",
    "if_oper_status":  "1.3.6.1.2.1.2.2.1.8",
    "if_phys_addr":    "1.3.6.1.2.1.2.2.1.6",
    "if_speed":        "1.3.6.1.2.1.2.2.1.5",        # 32-bit, bps
    "if_in_octets":    "1.3.6.1.2.1.2.2.1.10",       # 32-bit, fallback
    "if_out_octets":   "1.3.6.1.2.1.2.2.1.16",
    "if_in_errors":    "1.3.6.1.2.1.2.2.1.14",
    "if_out_errors":   "1.3.6.1.2.1.2.2.1.20",
    "if_in_discards":  "1.3.6.1.2.1.2.2.1.13",
    "if_out_discards": "1.3.6.1.2.1.2.2.1.19",
}
IFX_TABLE = {   # ifXTable, preferred when present (RFC 2863)
    "if_alias":         "1.3.6.1.2.1.31.1.1.1.18",
    "if_high_speed":    "1.3.6.1.2.1.31.1.1.1.15",   # Mbps, use *1e6 over if_speed
    "if_hc_in_octets":  "1.3.6.1.2.1.31.1.1.1.6",    # 64-bit
    "if_hc_out_octets": "1.3.6.1.2.1.31.1.1.1.10",
}

# Best-effort scalars: near-universal across net-snmp/Linux and many
# hardware vendors, but not part of the SNMPv2 mandatory set, so a failed
# GET here is silently skipped rather than counted as a poll failure.
UCD_SNMP = {           # UCD-SNMP-MIB — net-snmp / most Linux agents
    "cpu_raw_idle": "1.3.6.1.4.1.2021.11.11.0",      # percent idle, 100-x = busy
    "mem_avail_kb": "1.3.6.1.4.1.2021.4.6.0",
    "mem_total_kb": "1.3.6.1.4.1.2021.4.5.0",
    "load1":        "1.3.6.1.4.1.2021.10.1.3.1",
}
HOST_RESOURCES = {     # HOST-RESOURCES-MIB — Windows, many appliances
    "hr_processor_load": "1.3.6.1.2.1.25.3.3.1.2",   # table, one row per CPU, averaged
    "hr_storage_table":  "1.3.6.1.2.1.25.2.3.1",      # table: size/used per storage unit
}

ENUMS = {
    "if_admin_status": {1: "up", 2: "down", 3: "testing"},
    "if_oper_status": {1: "up", 2: "down", 3: "testing", 4: "unknown",
                       5: "dormant", 6: "notPresent", 7: "lowerLayerDown"},
}


def enum_text(key: str, value) -> str:
    """Delegates to the same table shape trapoids.enum_text() uses, kept
    separate because Nodes' keys are short metric names, not raw OIDs."""
    table = ENUMS.get(key)
    if not table:
        return str(value)
    try:
        name = table.get(int(value)) if value is not None else None
    except (TypeError, ValueError):
        return str(value)
    return f"{name} ({value})" if name else str(value)


def vendor_for(sys_object_id: str) -> str:
    """Longest-prefix match against trapoids.WELL_KNOWN's vendor-root
    entries, reused rather than duplicated."""
    from .trapoids import WELL_KNOWN
    if not sys_object_id:
        return ""
    oid = sys_object_id.strip(".")
    parts = oid.split(".")
    for cut in range(len(parts), 0, -1):
        name = WELL_KNOWN.get(".".join(parts[:cut]))
        if name:
            return name
    return ""


def suggest_group(sys_descr: str, sys_object_id: str, groups: list) -> int | None:
    """Discovery's best-effort profile suggestion: an exact vendor-name
    match against an existing group's name, else the Default group's id,
    else None. Never silently creates a group — a human always confirms."""
    vendor = vendor_for(sys_object_id)
    if vendor:
        for group in groups:
            if group["name"].strip().lower() == vendor.strip().lower():
                return group["id"]
    for group in groups:
        if group["is_default"]:
            return group["id"]
    return None
