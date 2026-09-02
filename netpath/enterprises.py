"""IANA enterprise numbers -> vendor, for arcs no uploaded MIB describes.

Two tables, deliberately kept apart:

- VERIFIED: every arc was read out of the vendor's own MIB text (the
  ``::= { enterprises N }`` line) — the same rule trapoids.WELL_KNOWN's 4.28
  block set. These decide a vendor at high confidence.
- CURATED: hand-authored from memory of the IANA registry. The registry
  itself (www.iana.org/assignments/enterprise-numbers) is not reachable from
  the build environment, so nothing here was checked against it in this
  build. These decide at *medium* confidence, and the arc number is always
  written into the device's evidence, so a wrong entry is auditable and
  scoped to devices nothing else can name. Keep this list conservative: a
  vendor mislabelled is worse than a vendor left as a number.

Keys match trapoids.WELL_KNOWN and nodeoids.SYSDESCR_VENDORS wherever both
name the same vendor, so the walk, the sysObjectID table and the sysDescr
guess all agree on one spelling ("phoenixContact", not three variants).
"""

from __future__ import annotations

# arc -> (vendor key, display name)
VERIFIED: dict[int, tuple[str, str]] = {
    # trapoids.WELL_KNOWN roots — every one read from MIB text.
    9: ("cisco", "Cisco"),
    11: ("hp", "HP / HPE"),
    161: ("motorola", "Motorola"),          # Cambium's Canopy/PMP line lives here
    171: ("dlink", "D-Link"),
    232: ("hpCompaq", "HP / Compaq"),
    248: ("hirschmann", "Hirschmann"),
    311: ("microsoft", "Microsoft"),
    318: ("apc", "APC / Schneider"),
    476: ("vertiv", "Vertiv / Liebert"),
    534: ("eaton", "Eaton"),
    664: ("adtran", "Adtran"),
    674: ("dell", "Dell"),
    789: ("netApp", "NetApp"),
    890: ("zyxel", "Zyxel"),
    1916: ("extremeNetworks", "Extreme Networks"),
    1991: ("brocade", "Brocade"),
    2011: ("huawei", "Huawei"),
    2021: ("ucdavis", "UCD-SNMP (agent)"),
    2604: ("sophos", "Sophos"),
    2606: ("rittal", "Rittal"),
    2620: ("checkPoint", "Check Point"),
    2636: ("juniper", "Juniper"),
    3097: ("watchguard", "WatchGuard"),
    3375: ("f5", "F5"),
    4413: ("broadcom", "Broadcom (FASTPATH)"),
    4526: ("netgear", "NETGEAR"),
    5951: ("citrix", "Citrix"),
    6027: ("dellNetworking", "Dell Networking"),
    6574: ("synology", "Synology"),
    6876: ("vmware", "VMware"),
    8072: ("netSnmp", "Net-SNMP (agent)"),
    8691: ("moxa", "Moxa"),                # MOXA-GENERAL-MIB: moxa ::= { enterprises 8691 }
    8741: ("sonicwall", "SonicWall"),
    11863: ("tpLink", "TP-Link"),
    12276: ("f5Networks", "F5 Networks"),
    12356: ("fortinet", "Fortinet"),
    13742: ("raritan", "Raritan"),
    14823: ("aruba", "Aruba"),
    14988: ("mikrotik", "MikroTik"),
    25053: ("ruckus", "Ruckus"),
    25461: ("paloAlto", "Palo Alto Networks"),
    25506: ("h3c", "H3C"),
    26928: ("aerohive", "Aerohive"),
    30065: ("arista", "Arista"),
    41112: ("ubiquiti", "Ubiquiti"),
    47196: ("arubaCx", "Aruba CX (HPE)"),
    # Catalog bundle arcs verified for 4.32 from the bundle's own root file.
    705: ("mge", "MGE (Eaton)"),               # MG-SNMP-UPS-MIB merlinGerin
    14179: ("airespace", "Airespace (Cisco WLC)"),
    17713: ("cambium", "Cambium Networks"),    # CAMBIUM-PTP650-MIB
}

# Hand-authored. See the module docstring: unverified in this build, medium
# confidence, conservative by design.
CURATED: dict[int, tuple[str, str]] = {
    2: ("ibm", "IBM"),
    23: ("novell", "Novell"),
    42: ("sun", "Sun / Oracle"),
    43: ("3com", "3Com"),
    45: ("synoptics", "SynOptics / Bay Networks"),
    52: ("enterasys", "Enterasys"),          # Cabletron's arc
    111: ("oracle", "Oracle"),
    116: ("hitachi", "Hitachi"),
    119: ("nec", "NEC"),
    164: ("rad", "RAD Data Communications"),
    193: ("ericsson", "Ericsson"),
    207: ("alliedTelesis", "Allied Telesis"),
    244: ("lantronix", "Lantronix"),
    253: ("xerox", "Xerox"),
    332: ("digi", "Digi International"),
    343: ("intel", "Intel"),
    368: ("axis", "Axis Communications"),
    388: ("symbol", "Symbol / Zebra"),
    562: ("nortel", "Nortel"),
    637: ("alcatel", "Alcatel"),
    641: ("lexmark", "Lexmark"),
    1027: ("mitel", "Mitel"),
    1139: ("emc", "EMC"),
    1588: ("brocadeFabric", "Brocade (fabric OS)"),
    1751: ("lucent", "Lucent"),
    1872: ("alteon", "Alteon / Radware"),
    2272: ("nortelPassport", "Nortel Passport"),
    2334: ("packeteer", "Packeteer"),
    2925: ("avocent", "Avocent"),            # Cyclades' arc
    3224: ("netscreen", "NetScreen / Juniper"),
    3833: ("schneider", "Schneider Electric"),
    3955: ("linksys", "Linksys"),
    4196: ("siemens", "Siemens"),
    4346: ("phoenixContact", "Phoenix Contact"),
    4491: ("cableLabs", "CableLabs"),
    5624: ("enterasys", "Enterasys"),
    6486: ("alcatelLucentEnterprise", "Alcatel-Lucent Enterprise"),
    6527: ("nokia", "Nokia (Alcatel-Lucent SR)"),
    6889: ("avaya", "Avaya"),
    7367: ("draytek", "DrayTek"),
    7779: ("infoblox", "Infoblox"),
    8744: ("colubris", "Colubris / HP"),
    10297: ("dellPowerConnect", "Dell PowerConnect"),
    10418: ("avocent", "Avocent"),
    10876: ("supermicro", "Supermicro"),
    12325: ("pfSense", "pfSense / BSD"),
    12394: ("alvarion", "Alvarion"),
    13885: ("polycom", "Polycom"),
    14525: ("trapeze", "Trapeze / Juniper"),
    15004: ("meru", "Meru / Fortinet"),
    16177: ("westermo", "Westermo"),
    17163: ("riverbed", "Riverbed"),
    18334: ("konica", "Konica Minolta"),
    20992: ("cradlepoint", "Cradlepoint"),
    21839: ("bluecoat", "Blue Coat / Symantec"),
    23695: ("peplink", "Peplink"),
    24681: ("qnap", "QNAP"),
    25049: ("opengear", "Opengear"),
    25376: ("mellanox", "Mellanox / NVIDIA"),
    26543: ("ruggedcom", "RuggedCom / Siemens"),
    28557: ("zhone", "Zhone / DZS"),
    29671: ("meraki", "Cisco Meraki"),
    32473: ("example", "Example enterprise (RFC 5612)"),
    35265: ("eltex", "Eltex"),
    36207: ("solarWinds", "SolarWinds"),
    38300: ("radwin", "RADWIN"),
    39165: ("hikvision", "Hikvision"),
    40310: ("silverPeak", "Silver Peak / HPE"),
    40418: ("edgecore", "Edgecore"),
    41263: ("nutanix", "Nutanix"),
    41482: ("proxmox", "Proxmox"),
    41916: ("ceragon", "Ceragon"),
    42397: ("grandstream", "Grandstream"),
    44641: ("dahua", "Dahua"),
    45437: ("sierraWireless", "Sierra Wireless"),
    46242: ("netonix", "Netonix"),
    46366: ("mimosa", "Mimosa Networks"),
    48690: ("teltonika", "Teltonika"),
    50588: ("zebra", "Zebra"),
}

# Verified always wins over a curated guess for the same arc.
ENTERPRISES: dict[int, tuple[str, str]] = {**CURATED, **VERIFIED}


def lookup(arc) -> tuple[str, str] | None:
    """(vendor key, display name) for an enterprise number, or None."""
    try:
        return ENTERPRISES.get(int(arc))
    except (TypeError, ValueError):
        return None


def is_verified(arc) -> bool:
    try:
        return int(arc) in VERIFIED
    except (TypeError, ValueError):
        return False


# Vendors identified by sysDescr alone, which therefore have no arc to be
# keyed by here. Rockwell Automation is one: no Rockwell MIB was reachable to
# read a verified arc out of, and a guessed arc silently mislabels every
# device beneath it, so it is named by sysDescr only -- and still deserves to
# read as its own name rather than as a camelCase token.
ARCLESS_DISPLAY: dict[str, str] = {
    "rockwellAutomation": "Rockwell Automation",
}

_DISPLAY: dict[str, str] = {}
for _arc, (_key, _name) in ENTERPRISES.items():
    _DISPLAY.setdefault(_key, _name)
del _arc, _key, _name
for _key, _name in ARCLESS_DISPLAY.items():
    _DISPLAY.setdefault(_key, _name)
del _key, _name


def display_name(key: str) -> str:
    """A human label for a vendor key, falling back to the key itself so a
    vendor named only by sysDescr still reads as something."""
    return _DISPLAY.get(key or "", key or "")
