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

# -------------------------------------------------------------- L2 topology
#
# LLDP-MIB (IEEE 802.1AB-2005) lldpRemTable — "what is plugged into what",
# the walk the review's Tier 1 #5 named as entirely missing. Each row is one
# neighbour heard on one local port, indexed by
# lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex (three arcs); the columns
# below are walked separately (one GETBULK column walk each, the same shape
# _walk_column already uses for the FDB) and joined back together on that
# shared index suffix in nodepoll._run_lldp_table.
#
# lldpRemLocalPortNum is NOT necessarily an ifIndex — RFC 802.1AB leaves how
# a local port is numbered to lldpLocPortTable, which maps it to a port only
# via lldpLocPortIdSubtype/lldpLocPortId (interfaceAlias, macAddress, ...),
# not to ifIndex directly. In practice the overwhelming majority of agents
# this app polls (net-snmp's own LLDP implementation included) number
# lldpLocPortNum identically to ifIndex, so that identity is used directly
# rather than resolving the local-port table — the same pragmatic call
# CISCO_MEMORY_* above makes for a vendor table nobody here has walked
# against every implementation. A device that numbers them differently
# stores neighbours against the wrong local port rather than not at all,
# which read_device_lldp_neighbors's docstring says plainly.
LLDP_REM_CHASSIS_ID_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID         = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_ID_SUBTYPE    = "1.0.8802.1.1.2.1.4.1.1.6"
LLDP_REM_PORT_ID            = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC          = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME           = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYS_DESC           = "1.0.8802.1.1.2.1.4.1.1.10"

# lldpRemChassisIdSubtype's enumeration — needed to tell "this chassis id is
# a MAC address" (4, the common case, joinable against an interface's
# phys_addr) from a locally-assigned string or a network address.
LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS = 4

# CDP (CISCO-CDP-MIB) cdpCacheTable, read as a fallback/supplement on Cisco
# gear: plenty of older Cisco switches speak CDP only, or speak both and
# CDP's cdpCachePlatform says something LLDP's sysDescr does not. Indexed by
# cdpCacheIfIndex.cdpCacheDeviceIndex — the first arc genuinely *is* the
# local ifIndex, unlike LLDP's local port number above, so no join is
# needed to place a row on its interface.
CDP_CACHE_ADDRESS     = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_CACHE_DEVICE_ID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_CACHE_PLATFORM    = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

# ------------------------------------------------------------------- PoE
#
# POWER-ETHERNET-MIB (RFC 3621). pethMainPseTable is the PSE's own power
# budget, indexed by pethMainPseGroupIndex alone (one row per power supply
# unit — almost always just "1" on an access switch). pethPsePortTable is
# per-port admin/detection state, indexed by
# pethPsePortGroupIndex.pethPsePortIndex; as with LLDP's local port number
# above, pethPsePortIndex is not guaranteed to equal ifIndex by the MIB
# itself, but is on every agent this app has been checked against — see
# nodepoll._run_poe for the same caveat LLDP's local-port comment carries.
PETH_MAIN_PSE_POWER      = "1.3.6.1.2.1.105.1.3.1.1.2"   # watts, nominal budget
PETH_MAIN_PSE_OPER_STATUS = "1.3.6.1.2.1.105.1.3.1.1.3"  # on(1)/off(2)/faulty(3)
PETH_MAIN_PSE_CONSUMPTION = "1.3.6.1.2.1.105.1.3.1.1.4"  # watts, in use now
PETH_PSE_PORT_ADMIN       = "1.3.6.1.2.1.105.1.1.1.1.3"  # enabled(1)/disabled(2)
PETH_PSE_PORT_DETECTION   = "1.3.6.1.2.1.105.1.1.1.1.6"  # disabled/searching/
                                                          # deliveringPower/fault/...

PETH_PORT_ADMIN_ENUM = {1: "enabled", 2: "disabled"}
PETH_PORT_DETECTION_ENUM = {1: "disabled", 2: "searching", 3: "deliveringPower",
                            4: "fault", 5: "test", 6: "otherFault"}

# CISCO-POWER-ETHERNET-EXT-MIB's per-port milliwatt reading — the actual
# draw, which the standard MIB above only gives at PSE-wide granularity on
# most Cisco IOS trains. Shares pethPsePortTable's own
# group-index.port-index numbering, so it joins onto the same rows.
CISCO_POE_PORT_POWER_MW = "1.3.6.1.4.1.9.9.402.1.2.1.1.5"

# ------------------------------------------------------------------- STP
#
# BRIDGE-MIB (RFC 4188) dot1dStp: the bridge-wide spanning-tree state as six
# scalars, read in one GET like SYSTEM_SCALARS, plus a per-port state table
# indexed by dot1dStpPort — which IS dot1dBasePort, the same bridge-port
# numbering the MAC table walk already resolves to ifIndex via
# nodepoll._bridge_port_map, so no separate local-port guess is needed here.
DOT1D_STP_PROTOCOL_SPEC   = "1.3.6.1.2.1.17.2.1.0"   # unknown(1)/decLb100(2)/ieee8021d(3)
DOT1D_STP_PRIORITY        = "1.3.6.1.2.1.17.2.2.0"
DOT1D_STP_TIME_SINCE_CHANGE = "1.3.6.1.2.1.17.2.3.0"  # TimeTicks
DOT1D_STP_TOP_CHANGES     = "1.3.6.1.2.1.17.2.4.0"   # cumulative Counter
DOT1D_STP_DESIGNATED_ROOT = "1.3.6.1.2.1.17.2.5.0"   # 8-octet bridge id
DOT1D_STP_ROOT_COST       = "1.3.6.1.2.1.17.2.6.0"
DOT1D_STP_ROOT_PORT       = "1.3.6.1.2.1.17.2.7.0"
DOT1D_STP_PORT_STATE      = "1.3.6.1.2.1.17.2.15.1.3"  # per dot1dStpPort

DOT1D_STP_PORT_STATE_ENUM = {1: "disabled", 2: "blocking", 3: "listening",
                             4: "learning", 5: "forwarding", 6: "broken"}
DOT1D_STP_PROTOCOL_SPEC_ENUM = {1: "unknown", 2: "decLb100", 3: "ieee8021d"}

# ---------------------------------------------------------- PtP radio links
#
# Point-to-point wireless bridges (Tier 1 #8): a PtP link has exactly one
# remote end, so its RF quality is a handful of scalars, not a walkable
# table — read the same way VENDOR_HEALTH's "scalar" probes are, one GET,
# best-effort, and stored as ordinary metric samples so the existing
# series()/chart machinery shows RF history for free (see
# nodepoll._poll_rf_metrics). Keyed by enterprise arc exactly like
# VENDOR_HEALTH, so a device that is not a radio costs nothing extra.
#
# The instance numbering below matches what this app's own demo fleet
# answers (demo/personas.py's ubiquiti_airfiber/cambium_ptp personas), which
# is the only ground truth available without a live unit of either vendor
# on hand — the same caveat CISCO_MEMORY_* above has always carried for a
# vendor table this app has not walked against every firmware. A real
# airFiber's AIRFIBER-MIB and a real PTP 670's CAMBIUM-PTP670-MIB should be
# checked against a live device and this table adjusted if its numbering
# differs.
RF_METRICS = {
    41112: (    # Ubiquiti airFiber/airMAX
        ("rf_rssi_dbm", "RSSI", "dBm", "1.3.6.1.4.1.41112.1.3.2.1.1.0", "scalar"),
        ("rf_snr_db", "SNR", "dB", "1.3.6.1.4.1.41112.1.3.2.1.2.0", "scalar"),
        ("rf_capacity_bps", "Link capacity", "bps",
         "1.3.6.1.4.1.41112.1.3.2.1.3.0", "scalar"),
        ("rf_remote_rssi_dbm", "Remote RSSI", "dBm",
         "1.3.6.1.4.1.41112.1.3.2.1.4.0", "scalar"),
    ),
    17713: (    # Cambium PTP-series
        ("rf_rx_level_dbm", "Receive level", "dBm",
         "1.3.6.1.4.1.17713.21.1.2.1.0", "scalar"),
        ("rf_path_loss_db", "Path loss", "dB",
         "1.3.6.1.4.1.17713.21.1.2.2.0", "scalar"),
        ("rf_capacity_bps", "Link capacity", "bps",
         "1.3.6.1.4.1.17713.21.1.2.3.0", "scalar"),
        ("rf_vector_error_db", "Vector error (modulation quality)", "dB",
         "1.3.6.1.4.1.17713.21.1.2.4.0", "scalar"),
    ),
}

# Enterprise arcs RF_METRICS covers — the gate that keeps the RF read off
# every non-radio device's poll, named separately so nodepoll doesn't
# reach into RF_METRICS' keys directly.
RF_VENDOR_ARCS = frozenset(RF_METRICS)


# ------------------------------------------------------------- UPS-MIB
#
# UPS-MIB (RFC 1628), 1.3.6.1.2.1.33. The gap this closes: trapoids.py
# already decodes upsTrapOnBattery/upsTrapAlarmEntryAdded/etc as UPS
# *traps* (a UPS can shout), and VENDOR_HEALTH above already names the
# APC/Eaton/Vertiv enterprise arcs for identification — but nothing has
# ever polled 1.3.6.1.2.1.33 itself, so nothing has ever ASKED a UPS how
# it is: no charge, no runtime, no load, no "replace battery".
#
# Unlike VENDOR_HEALTH, this table is not keyed by enterprise arc. A UPS's
# maker varies far more than a switch's does — APC's arc is 318, Eaton's
# 534, Vertiv/Liebert's 476, and plenty of small UPS brands sit on a
# rebadged OEM card under yet another arc entirely — and UPS-MIB is the
# one object tree nearly all of them answer regardless, which is the
# whole reason it was standardised. Keying it to an arc would mean
# maintaining a vendor list for every UPS a site might plug in for no
# benefit: see nodepoll._poll_ups_health for how it is gated instead (a
# cheap scalar GET first, on every device, and the two table walks only
# when that GET proves the device worth asking further).
#
# (metric key, label, unit, OID, how, scale) — one field longer than
# VENDOR_HEALTH's tuples. `scale` is the multiplier applied to the raw
# number the agent returns before it becomes the stored metric value,
# defaulting to 1.0 for every probe but one: RFC 1628 defines
# upsBatteryVoltage in tenths of a volt, and storing 240 as "24.0 V" would
# read as a UPS wired for a mains voltage rather than a 24 V battery
# string. Nothing else here needs scaling — upsInputVoltage and
# upsOutputPercentLoad are already whole Volts/percent, and the two enum
# scalars (battery status, output source) are stored as their raw integer
# code rather than decoded to text, the same way if_admin_status and
# if_oper_status are: an alert rule's threshold evaluator only ever
# compares numbers (see alertsdb._BUILTIN_RULES' ups_battery_low/
# ups_battery_replace/ups_on_battery for why that matters), and enum_text()
# below still renders the code as a label wherever the UI wants one.
UPS_BATTERY_STATUS       = "1.3.6.1.2.1.33.1.2.1.0"
UPS_SECONDS_ON_BATTERY   = "1.3.6.1.2.1.33.1.2.2.0"
UPS_ESTIMATED_MINUTES    = "1.3.6.1.2.1.33.1.2.3.0"
UPS_ESTIMATED_CHARGE_PCT = "1.3.6.1.2.1.33.1.2.4.0"
UPS_BATTERY_VOLTAGE      = "1.3.6.1.2.1.33.1.2.5.0"   # decivolts -- scaled 0.1
UPS_BATTERY_TEMPERATURE  = "1.3.6.1.2.1.33.1.2.7.0"
UPS_INPUT_VOLTAGE        = "1.3.6.1.2.1.33.1.3.3.1.3"   # table: upsInputTable
UPS_OUTPUT_SOURCE        = "1.3.6.1.2.1.33.1.4.1.0"
UPS_OUTPUT_PERCENT_LOAD  = "1.3.6.1.2.1.33.1.4.4.1.5"   # table: upsOutputTable
UPS_ALARMS_PRESENT       = "1.3.6.1.2.1.33.1.6.1.0"

UPS_BATTERY_STATUS_ENUM = {1: "unknown", 2: "batteryNormal", 3: "batteryLow",
                           4: "batteryDepleted"}
UPS_OUTPUT_SOURCE_ENUM = {1: "other", 2: "none", 3: "normal", 4: "bypass",
                          5: "battery", 6: "booster", 7: "reducer"}

UPS_HEALTH = (
    ("ups_battery_status", "Battery status", "", UPS_BATTERY_STATUS,
     "scalar", 1.0),
    ("ups_on_battery_s", "Seconds on battery", "s", UPS_SECONDS_ON_BATTERY,
     "scalar", 1.0),
    ("ups_runtime_min", "Estimated runtime remaining", "min",
     UPS_ESTIMATED_MINUTES, "scalar", 1.0),
    ("ups_battery_charge_pct", "Battery charge", "%", UPS_ESTIMATED_CHARGE_PCT,
     "scalar", 1.0),
    ("ups_battery_voltage", "Battery voltage", "V", UPS_BATTERY_VOLTAGE,
     "scalar", 0.1),
    ("ups_battery_temp_c", "Battery temperature", "°C", UPS_BATTERY_TEMPERATURE,
     "scalar", 1.0),
    ("ups_output_source", "Output source", "", UPS_OUTPUT_SOURCE,
     "scalar", 1.0),
    ("ups_alarms", "Active alarms", "", UPS_ALARMS_PRESENT, "scalar", 1.0),
    # upsInputTable/upsOutputTable rows, one per input/output line. A
    # three-phase unit answers one row per phase; the input side takes the
    # first line as representative (the same call VENDOR_HEALTH's Cisco
    # probe makes for "a chassis's first routing engine" — correlating a
    # phase imbalance is not what this rule is for), while the output side
    # takes the worst (highest-loaded) line, because "is any output
    # circuit overloaded" is the question an operator actually has.
    ("ups_input_voltage", "Input voltage", "V", UPS_INPUT_VOLTAGE,
     "column_first", 1.0),
    ("ups_output_load_pct", "Output load", "%", UPS_OUTPUT_PERCENT_LOAD,
     "column_max", 1.0),
)

# APC PowerNet-MIB's upsAdvBatteryRunTimeRemaining, in TimeTicks (hundredths
# of a second rather than UPS-MIB's whole minutes). Consulted only when the
# standard upsEstimatedMinutesRemaining scalar above did not answer, and
# only on APC's own arc (318) -- the same "ask the vendor's own object only
# once the standard one has been tried and failed" order GENERIC_HEALTH
# already follows for CPU. Unlike every other OID in this file, this one
# is NOT cross-checked against a live APC unit or a bundled MIB in this
# build: it is the object every apcupsd/check_apc-style monitoring script
# this author has seen uses for the same reading, which is real but
# secondhand corroboration, the same standing enterprises.py's CURATED
# table (rather than VERIFIED) already gives that kind of evidence. Written
# here rather than added to enterprises.py because it names a MIB object,
# not a vendor arc.
APC_BATTERY_RUNTIME_TIMETICKS = "1.3.6.1.4.1.318.1.1.1.2.2.3.0"


ENUMS = {
    "if_admin_status": {1: "up", 2: "down", 3: "testing"},
    "if_oper_status": {1: "up", 2: "down", 3: "testing", 4: "unknown",
                       5: "dormant", 6: "notPresent", 7: "lowerLayerDown"},
    "ups_battery_status": UPS_BATTERY_STATUS_ENUM,
    "ups_output_source": UPS_OUTPUT_SOURCE_ENUM,
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
