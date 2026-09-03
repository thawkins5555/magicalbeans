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
    # ifCounterDiscontinuityTime: the sysUpTime at which this interface's
    # counters were last discontinuous (a card reseat, a counter reset, a
    # module reload). A rate computed across one of those is fiction — the
    # counters went backwards for a reason that has nothing to do with a
    # 32-bit wrap — so the poller stores it and drops that interface's
    # rates for the one poll where it changed.
    "if_discontinuity": "1.3.6.1.2.1.31.1.1.1.19",
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

# ------------------------------------------------------------ vendor health
#
# The review's §4.1 S9: the poller read no vendor health at all — no CPU or
# memory from Cisco, Fortinet or Juniper, HOST-RESOURCES-MIB defined above
# and never referenced — so `cpu_high`, `mem_high` and `disk_high` could
# only ever fire on a device running net-snmp. These are the scalars that
# make those rules live on real network gear, keyed by the vendor's own
# enterprise arc so a device is only ever asked for objects its maker
# defines.
#
# Each probe is (metric key, label, unit, OID, how):
#   "scalar"       the OID is already an instance; read it in the GET
#   "column_first" a table column; the first numeric row (a chassis's first
#                  routing engine, its first CPU)
#   "column_max"   a table column; the worst row (temperatures, where the
#                  hottest sensor is the one that matters)
#   "column_avg"   a table column; the mean (per-core CPU load)
VENDOR_HEALTH = {
    9: (        # Cisco — CISCO-PROCESS-MIB cpmCPUTotal5minRev
        ("cpu_pct", "CPU", "%", "1.3.6.1.4.1.9.9.109.1.1.1.1.8", "column_first"),
    ),
    12356: (    # Fortinet — FORTINET-FORTIGATE-MIB, all plain scalars
        ("cpu_pct", "CPU", "%", "1.3.6.1.4.1.12356.101.4.1.3.0", "scalar"),
        ("mem_pct", "Memory", "%", "1.3.6.1.4.1.12356.101.4.1.4.0", "scalar"),
        ("session_count", "Firewall sessions", "sessions",
         "1.3.6.1.4.1.12356.101.4.1.8.0", "scalar"),
    ),
    2636: (     # Juniper — JUNIPER-MIB jnxOperatingTable
        ("cpu_pct", "CPU", "%", "1.3.6.1.4.1.2636.3.1.13.1.8", "column_first"),
        ("temp_c", "Temperature", "°C", "1.3.6.1.4.1.2636.3.1.13.1.7", "column_max"),
    ),
}

# CISCO-MEMORY-POOL-MIB: used and free per pool, in bytes. A percentage
# needs both columns, so it does not fit the single-column shape above.
CISCO_MEMORY_USED = "1.3.6.1.4.1.9.9.48.1.1.1.5"
CISCO_MEMORY_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.6"

# HOST-RESOURCES-MIB, the fallback for everything else — Windows, Palo Alto,
# most appliances. Only read when the vendor table above named nothing and
# UCD-SNMP did not answer either, so a net-snmp box costs no extra requests.
GENERIC_HEALTH = (
    ("cpu_pct", "CPU", "%", "1.3.6.1.2.1.25.3.3.1.2", "column_avg"),
)

# hrStorageTable: type, allocation unit, size and used, per storage unit.
# hrStorageFixedDisk is the row an operator means by "disk"; RAM and virtual
# memory rows live in the same table and would report a machine using its
# page cache as a full disk.
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
HR_STORAGE_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"

# ipAddrTable's ipAdEntAddr column: every IPv4 address this device answers
# on. Its own traps and syslog messages come from whichever of them the
# device chose, which is how a message from a loopback ends up belonging to
# nobody. Walked rarely (see nodepoll._ADDRESS_REFRESH_S), not every poll.
IP_ADDR_TABLE = "1.3.6.1.2.1.4.20.1.1"


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


def oid_key(oid: str) -> tuple:
    """An OID as a tuple of ints, so "…1.10" orders after "…1.9" rather than
    between "…1.1" and "…1.2" the way string comparison would put it. A
    malformed arc sorts as a string after every numeric one — the callers
    only ever ask "did the walk advance?", and a garbled answer did not.

    Lives here rather than in nodepoll because vendorid needs it too, and
    nodepoll imports vendorid."""
    return tuple((0, int(arc)) if arc.isdigit() else (1, arc)
                 for arc in str(oid).split("."))


def enterprise_arc(oid: str) -> int | None:
    """The enterprise number of an OID under `enterprises`, or None for
    anything outside it: '1.3.6.1.4.1.9.1.1208' -> 9."""
    root = enterprise_root(oid)
    if not root:
        return None
    try:
        return int(root.split(".")[6])
    except (IndexError, ValueError):
        return None


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
    entries, reused rather than duplicated; then, for an arc that table
    does not name, the bundled enterprise-number list (enterprises.py) —
    so a device under an arc this app holds no MIB for still gets a name
    rather than a number. Callers that need to know how much to trust the
    name ask enterprises.is_verified()."""
    from .trapoids import WELL_KNOWN
    if not sys_object_id:
        return ""
    oid = sys_object_id.strip(".")
    parts = oid.split(".")
    for cut in range(len(parts), 0, -1):
        name = WELL_KNOWN.get(".".join(parts[:cut]))
        if name:
            # Through canonical_key, so a device under one of a maker's
            # narrower arcs (hpCompaq, dellNetworking, arubaCx) is stored
            # under the same key as one under its main arc and the two land
            # in one row of the vendor filter.
            from . import enterprises
            return enterprises.canonical_key(name)
    arc = enterprise_arc(oid)
    if arc is not None:
        from . import enterprises
        hit = enterprises.lookup(arc)
        if hit:
            return hit[0]
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
# Display names live in enterprises.py, beside the arc table that already
# carries one for every vendor named by an arc -- a second table here would
# drift out of step with it. The KEY is still what everything that behaves
# per-vendor compares against (ConfigRX's backup command, the Cisco per-VLAN
# MAC read, discovery's profile suggestion), so it stays a lowercase/camelCase
# token and is never rewritten to a pretty string.
def vendor_label(vendor: str) -> str:
    """A vendor key as its maker's own name, or the key unchanged."""
    from . import enterprises
    return enterprises.display_name(vendor or "")


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
