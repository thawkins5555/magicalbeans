"""OID constants for FortiGate Wireless Controller polling (fgWc, under
Fortinet's enterprise MIB), hand-listed from the vendor's
FORTINET-CORE-MIB.mib / FORTINET-FORTIGATE-MIB.mib rather than parsed at
runtime — the same "not a MIB compiler" convention trapoids.py and
nodeoids.py already use for other fixed, known vendor tables. mibparse.py
exists for MIBs an admin uploads for name resolution elsewhere in the app;
polling itself doesn't depend on it, so a parsing gap there can't break
this module's numeric OIDs.

Three tables, all indexed by (fgVdEntIndex, WtpId[, RadioId]):

  fortinet(1.3.6.1.4.1.12356).fnFortiGateMib(101).fgWc(14).fgWcWtpTables(4)
    .fgWcWtpConfigTable(3)         -- the AP's configured name
    .fgWcWtpSessionTable(4)        -- live status, MAC, model, client count
    .fgWcWtpSessionRadioTable(5)   -- per-radio channel/tx power/clients
"""

from __future__ import annotations

FORTINET = "1.3.6.1.4.1.12356"
FG_MIB = f"{FORTINET}.101"
FG_WC = f"{FG_MIB}.14"
WTP_TABLES = f"{FG_WC}.4"

# Column OIDs, relative to each table's own entry base
# (<WTP_TABLES>.<table>.1.<column>) -- the base itself, not a leaf value.
WTP_CONFIG_ENTRY = f"{WTP_TABLES}.3.1"
WTP_SESSION_ENTRY = f"{WTP_TABLES}.4.1"
WTP_SESSION_RADIO_ENTRY = f"{WTP_TABLES}.5.1"

# fgWcWtpConfigEntry (config -- admin-set, not live status)
WTP_CONFIG_NAME = f"{WTP_CONFIG_ENTRY}.3"          # DisplayString

# fgWcWtpSessionEntry (live status)
# fgWcWtpSessionWtpIpAddress: the AP's own address as the controller sees it,
# read from the session table this module already walks — so it costs no extra
# SNMP. It is what makes a per-AP response time possible at all: the module
# never talks to an AP directly, only to the controller.
WTP_SESSION_IP = f"{WTP_SESSION_ENTRY}.3"           # InetAddress
WTP_SESSION_MAC = f"{WTP_SESSION_ENTRY}.6"          # PhysAddress
WTP_SESSION_CONNECTION_STATE = f"{WTP_SESSION_ENTRY}.7"   # INTEGER, see below
WTP_SESSION_MODEL = f"{WTP_SESSION_ENTRY}.12"       # DisplayString
WTP_SESSION_STATION_COUNT = f"{WTP_SESSION_ENTRY}.17"      # Gauge32

# fgWcWtpSessionRadioEntry (per-radio, indexed by an additional RadioId)
WTP_RADIO_MODE = f"{WTP_SESSION_RADIO_ENTRY}.3"             # FgWcWtpRadioMode
WTP_RADIO_CHANNEL = f"{WTP_SESSION_RADIO_ENTRY}.7"          # FgWcWtpRadioChannelNumber
# fgWcWtpSessionRadioOperatingPower. The MIB's DESCRIPTION reads, verbatim:
# "Represents the current operating power of this radio, in dBm." Observed
# FortiOS does not do that: a FAP-231F reports values like 51 here, and
# 51 dBm is ~126 W EIRP, roughly a thousand times what any indoor AP can
# emit (a FortiAP's conducted output tops out near 20 dBm). What it is
# actually reporting is FortiOS's own 0-100 tx-power *level* percentage.
# Hence the auto-detection in fortipoll.py rather than a blanket "dBm"
# label: values above a plausible dBm ceiling are read as a percentage,
# and the raw number is always shown so the guess can be checked.
WTP_RADIO_OPERATING_POWER = f"{WTP_SESSION_RADIO_ENTRY}.8"  # Integer32
WTP_RADIO_STATION_COUNT = f"{WTP_SESSION_RADIO_ENTRY}.9"    # Gauge32

# The highest conducted output any Wi-Fi radio plausibly reports in dBm.
# 30 dBm is 1 W, already above every regulatory domain's indoor limit, so a
# value above it did not come from a dBm-reporting agent.
MAX_PLAUSIBLE_DBM = 30

# FgWcWtpRadioMode, quoted from the MIB's own TEXTUAL-CONVENTION. Worth
# polling because it explains an otherwise baffling radio: a FAP-231F's
# third radio is a dedicated scanner, so its "power" describes a receiver.
RADIO_MODE = {
    0: "other", 1: "not present", 2: "disabled", 3: "ap",
    4: "monitor", 5: "sniffer",
}

CONNECTION_STATE = {
    0: "other", 1: "offline", 2: "online",
    3: "downloading_image", 4: "connected_image", 5: "standby",
}
