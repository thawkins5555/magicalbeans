"""Built-in polled-metric OID catalog for the Nodes poller.

Not a MIB compiler (same framing as trapoids.py). A fixed table of OIDs
this app polls by default, split into "always poll" (near-universal
SNMPv2-MIB scalars and the IF-MIB interface table) and "poll if the vendor
OID resolves" (best-effort — a failed GET on one of these is silently
skipped, never counted as a poll failure).
"""

from __future__ import annotations

DEFAULT_SNMP_PORT = 161   # shared by nodepoll.py and nodediscover.py

# Subtree roots the OID browser opens on. Every SNMP agent answers both:
# system is six scalars, and interfaces is the ifTable this app already polls,
# so neither is an expensive walk on any device.
SYSTEM_BASE = "1.3.6.1.2.1.1"
INTERFACES_BASE = "1.3.6.1.2.1.2"

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


ENTERPRISES = "1.3.6.1.4.1"


def enterprise_root(sys_object_id: str) -> str:
    """'1.3.6.1.4.1.9.1.1208' -> '1.3.6.1.4.1.9' (the vendor's own arc).
    Empty for anything outside the enterprises subtree — a device whose
    sysObjectID sits in the standard tree has no vendor MIB at all, which
    vendor_for() alone can't tell you: it longest-prefix-matches
    trapoids.WELL_KNOWN, which names standard nodes too ("system" for
    1.3.6.1.2.1.1)."""
    oid = (sys_object_id or "").strip().strip(".")
    if not oid.startswith(ENTERPRISES + "."):
        return ""
    parts = oid.split(".")
    if len(parts) < 7:
        return ""
    return ".".join(parts[:7])


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


# Substring -> vendor, tried in order against a lowercased sysDescr, first
# match winning. Only consulted when sysObjectID identified nothing: plenty of
# gear answers a generic or net-snmp sysObjectID while describing itself
# perfectly well in text, and a device this app cannot name gets neither a
# profile suggestion nor a vendor MIB.
#
# Ordered so a longer, more specific string is tested before anything it
# contains. Deliberately conservative — a wrong guess here is worse than a
# blank, and identify_vendor() labels these as guesses so nothing downstream
# mistakes one for an authoritative arc match.
SYSDESCR_VENDORS: tuple[tuple[str, str], ...] = (
    ("phoenix contact", "phoenixContact"),
    ("phoenixcontact", "phoenixContact"),
    ("allied telesis", "alliedTelesis"),
    ("rockwell automation", "rockwellAutomation"),
    ("check point", "checkPoint"),
    ("palo alto", "paloAlto"),
    ("tp-link", "tpLink"),
    ("d-link", "dlink"),
    ("hewlett packard", "hp"),
    ("hewlett-packard", "hp"),
    ("procurve", "hp"),
    ("aruba", "aruba"),
    ("ubiquiti", "ubiquiti"),
    ("mikrotik", "mikrotik"),
    ("routeros", "mikrotik"),
    ("fortigate", "fortinet"),
    ("fortiswitch", "fortinet"),
    ("fortinet", "fortinet"),
    ("hirschmann", "hirschmann"),
    ("westermo", "westermo"),
    ("sonicwall", "sonicwall"),
    ("watchguard", "watchguard"),
    ("juniper", "juniper"),
    ("arista", "arista"),
    ("extreme", "extremeNetworks"),
    ("brocade", "brocade"),
    ("synology", "synology"),
    ("ruckus", "ruckus"),
    ("cambium", "cambium"),
    ("aerohive", "aerohive"),
    ("netgear", "netgear"),
    ("zyxel", "zyxel"),
    ("sophos", "sophos"),
    ("citrix", "citrix"),
    ("raritan", "raritan"),
    ("liebert", "vertiv"),
    ("vertiv", "vertiv"),
    ("eaton", "eaton"),
    ("rittal", "rittal"),
    ("moxa", "moxa"),
    ("adtran", "adtran"),
    ("huawei", "huawei"),
    ("cisco", "cisco"),
    ("dell", "dell"),
    ("apc ", "apc"),
)


def vendor_from_descr(sys_descr: str) -> str:
    """Best-effort vendor from the sysDescr string. Empty when nothing
    matches — never a partial or fuzzy guess."""
    text = (sys_descr or "").lower()
    if not text:
        return ""
    for needle, vendor in SYSDESCR_VENDORS:
        if needle in text:
            return vendor
    return ""


# Arcs that name the SNMP *agent* rather than whoever made the device. A
# Phoenix Contact radio, a Moxa switch and a Linux server all answer
# 1.3.6.1.4.1.8072.x because they all run net-snmp, so treating that as the
# vendor is what left this whole class of device unidentifiable — and it is
# the class the sysDescr fallback exists for. Still used as a last resort,
# since "net-snmp" beats nothing at all.
GENERIC_AGENT_VENDORS = frozenset({"netSnmp", "ucdavis"})


# Proprietary scalars that PROVE a vendor when they answer, for gear whose
# sysObjectID names only the SNMP agent it runs. (oid, needle, vendor): the
# answer is matched case-insensitively against the needle, so an object that
# exists but says something else proves nothing.
#
# Read in a SEPARATE best-effort GET, never merged into the identity request.
# An SNMPv1 agent asked for an object it does not implement answers noSuchName
# with the whole varbind list echoed back as nulls -- and nodepoll only raises
# on authorizationError, so sysDescr, sysObjectID, sysName and sysLocation
# would all come back blank with no exception to catch. One unanswerable OID
# must not be able to blank a device's identity.
VENDOR_PROBES: tuple[tuple[str, str, str], ...] = (
    # Moxa's own switch tree. Moxa gear routinely answers 1.3.6.1.4.1.8072.x
    # (net-snmp) for sysObjectID and says nothing useful in sysDescr, which is
    # exactly the class this probe exists for.
    ("1.3.6.1.4.1.8691.15.33.1.5.3.1.2.2", "moxa", "moxa"),
)


def probe_oids() -> tuple[str, ...]:
    """Every OID in VENDOR_PROBES, in order, for one GET."""
    return tuple(oid for oid, _needle, _vendor in VENDOR_PROBES)


def probe_arc(vendor: str) -> str:
    """The enterprise arc of the probe OID that names `vendor`, or "".

    A probe exists precisely because the device's sysObjectID does NOT name
    its maker -- Moxa gear answers the net-snmp arc -- so once a probe has
    identified one, the sysObjectID is the wrong OID to ask coverage
    questions about: no Moxa MIB will ever describe objects under
    1.3.6.1.4.1.8072, and a mib_missing alert raised against it could never
    be cleared by installing the Moxa bundle. The probe OID sits inside the
    vendor's own tree, so its arc is the right question to ask instead.
    """
    for oid, _needle, probe_vendor in VENDOR_PROBES:
        if probe_vendor == vendor:
            return enterprise_root(oid)
    return ""


def vendor_from_probe(values: dict) -> str:
    """Best-effort vendor from a vendor-probe GET's answers. Empty when
    nothing answered or nothing matched -- same contract as
    vendor_from_descr, and deliberately not a fuzzy guess."""
    for oid, needle, vendor in VENDOR_PROBES:
        value = (values or {}).get(oid)
        if value is None:
            continue
        if needle in str(value).strip().lower():
            return vendor
    return ""


# Display names for vendor keys whose token does not read as the vendor's own
# name. The KEY is what everything that behaves per-vendor compares against --
# ConfigRX's backup command, the Cisco per-VLAN MAC read, discovery's profile
# suggestion -- so it stays a lowercase/camelCase token and is never rewritten
# to a pretty string. This map is presentation only, and a key with no entry
# falls through unchanged, so adding one moves nothing else.
VENDOR_LABELS: dict[str, str] = {
    "moxa": "Moxa",
    "rockwellAutomation": "Rockwell Automation",
}


def vendor_label(vendor: str) -> str:
    """The display form of a vendor key, or the key itself."""
    key = (vendor or "").strip()
    return VENDOR_LABELS.get(key, key)


def identify_vendor(sys_object_id: str, sys_descr: str = "") -> tuple[str, str]:
    """(vendor, how) — 'sysObjectID', 'sysDescr' or '' when unidentified.

    Two sources with genuinely different standing, so the caller can say which
    one spoke. A sysObjectID prefix is an assignment from IANA and is as close
    to authoritative as this gets; a sysDescr keyword is text a vendor chose to
    write, matched by substring, and can be wrong. Collapsing them into one
    string would make a guess indistinguishable from a fact.
    """
    # Only an arc under `enterprises` names a vendor. WELL_KNOWN also names
    # standard-tree nodes, so an unadorned vendor_for() call reports a device
    # with a standard-tree sysObjectID as vendor "system" — which is what it
    # used to store, and it is not a vendor.
    vendor = vendor_for(sys_object_id) if enterprise_root(sys_object_id) else ""
    if vendor and vendor not in GENERIC_AGENT_VENDORS:
        return vendor, "sysObjectID"
    # An agent arc identifies the software, not the maker: prefer what the
    # device says about itself, and keep the agent name only if it says
    # nothing useful.
    from_descr = vendor_from_descr(sys_descr)
    if from_descr:
        return from_descr, "sysDescr"
    if vendor:
        return vendor, "sysObjectID"
    return "", ""


# ---------------------------------------------------------- custom identity

def normalize_oid(text: str) -> str:
    """A dotted OID with surrounding whitespace and leading dot stripped, or
    "" for anything that is not one. Deliberately strict: this string goes
    straight into an SNMP request, so a typo should read as "not configured"
    rather than as a request for something meaningless."""
    oid = (text or "").strip().strip(".")
    if not oid:
        return ""
    parts = oid.split(".")
    if len(parts) < 2 or not all(part.isdigit() for part in parts):
        return ""
    return oid


def oid_variants(text: str) -> tuple[str, ...]:
    """Both forms of an operator-typed OID: the object itself and its .0
    instance.

    An OID browser shows "1.3.6.1.4.1.9.1.1208"; a MIB says the same; but the
    thing an agent actually answers is the instance, "…1208.0". Asking for
    both in one GET costs one extra varbind on a request already being made
    and removes the single most likely way to get this wrong. Ordered so the
    OID as typed wins when both answer — a real table cell the operator picked
    deliberately is not second-guessed.
    """
    oid = normalize_oid(text)
    if not oid:
        return ()
    return (oid,) if oid.endswith(".0") else (oid, oid + ".0")


def identity_oid_variants(config: dict) -> dict:
    """{"vendor": (...), "location": (...), "all": [...]} for a device's
    effective config. Empty tuples when nothing is configured, which is the
    normal case and costs nothing."""
    vendor = oid_variants((config or {}).get("vendor_oid") or "")
    location = oid_variants((config or {}).get("location_oid") or "")
    merged = []
    for oid in vendor + location:
        if oid not in merged:
            merged.append(oid)
    return {"vendor": vendor, "location": location, "all": merged}


def first_text(values: dict, oids) -> str:
    """The first non-empty printable answer among `oids`, as text.

    A vendor or a location is a label, so a numeric answer is almost certainly
    the operator having pointed at the wrong object; it is still rendered
    rather than dropped, because a device that reports its site as a number is
    the operator's business, not this function's.
    """
    for oid in oids or ():
        value = values.get(oid)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
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
