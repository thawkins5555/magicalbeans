"""IANA enterprise numbers -> vendor, for arcs no uploaded MIB describes.

Every arc in both tables below is hand-authored from the IANA Private
Enterprise Number registry (www.iana.org/assignments/enterprise-numbers),
which is not reachable from the build environment. What separates the two
tables is corroboration, not origin:

- VERIFIED: cross-checked against a real device's sysObjectID or a bundled
  MIB — the arc has been seen in the field or read out of MIB text in this
  tree. These decide a vendor at high confidence.
- CURATED: not cross-checked in this build. These decide at *medium*
  confidence, and the arc number is always written into the device's
  evidence, so a wrong entry is auditable and scoped to devices nothing
  else can name. Keep this list conservative: a vendor mislabelled is
  worse than a vendor left as a number.

Neither table was transcribed from vendor MIB modules, which is what this
docstring claimed until 4.37.0: the tree holds vendor MIB text for exactly
one of the 53 VERIFIED arcs (Moxa's 8691), and the file that ships those
arcs — mibs/enterprise-roots.mib — says as much in terms.

One vendor, one key. A manufacturer that holds several arcs (HPE holds
five) is keyed under one canonical name through VENDOR_ALIASES, so the
Nodes vendor filter shows one row per manufacturer rather than one per
arc; the arc's own label stays available as a model hint through
arc_label(). Keys match trapoids.WELL_KNOWN and nodeoids.SYSDESCR_VENDORS
wherever both name the same vendor, so the walk, the sysObjectID table and
the sysDescr guess all agree on one spelling ("phoenixContact", not three
variants).
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
    # Allen-Bradley Company, Inc. -- the brand Rockwell Automation sells its
    # factory-automation line under, and the holder of PEN 95
    # (1.3.6.1.4.1.95). IANA itself is blocked by this build's egress proxy;
    # the number was taken from Wikidata's Allen-Bradley entry (Q2648305),
    # which carries the IANA PEN property, and is CURATED rather than
    # VERIFIED because no Rockwell MIB and no Rockwell device was reachable
    # here to cross-check it against. Without it a ControlLogix or
    # CompactLogix controller answering its own arc reads as "unknown
    # enterprise arc 95".
    95: ("rockwellAutomation", "Rockwell Automation / Allen-Bradley"),
}

# Verified always wins over a curated guess for the same arc.
ENTERPRISES: dict[int, tuple[str, str]] = {**CURATED, **VERIFIED}

# A narrow, arc-specific key -> the one key that names the manufacturer.
#
# A manufacturer often holds several PENs -- HPE answers on five of them,
# Dell on three -- and keying a device by whichever arc it happened to
# answer split one fleet across several rows of the Nodes vendor filter:
# "Aruba" and "Aruba CX (HPE)" read as two unrelated vendors, and 112 Aruba
# APs became four rows an operator had to add up by hand. The arc-specific
# label is still worth showing, but as a *model* hint (arc_label()), never
# as the vendor.
#
# hpCompaq (232) is deliberately NOT folded into hp: that arc is HP's server
# and iLO line, and per-vendor behaviour keyed on "hp" is written for HP
# switches.
VENDOR_ALIASES: dict[str, str] = {
    "arubaCx": "aruba",              # 47196, ArubaOS-CX
    "colubris": "hp",                # 8744, HP's wireless line
    "silverPeak": "hp",              # 40310, HPE Aruba EdgeConnect
    "dellNetworking": "dell",        # 6027, the Force10 line
    "dellPowerConnect": "dell",      # 10297
    "f5Networks": "f5",              # 12276, F5's other arc
    "brocadeFabric": "brocade",      # 1588, Fabric OS
}


def canonical_key(key: str) -> str:
    """The one key that names this vendor. Every reader of a vendor key
    should go through here, so a device keyed by a narrow arc and a device
    keyed by the manufacturer's main arc land in the same row."""
    return VENDOR_ALIASES.get(key or "", key or "")


def lookup(arc) -> tuple[str, str] | None:
    """(canonical vendor key, the arc's own display name) for an enterprise
    number, or None. The key is canonical; the name is the arc's, which for
    an aliased arc is a model rather than a vendor ("Aruba CX (HPE)") --
    display_name(key) is the vendor's own name."""
    try:
        hit = ENTERPRISES.get(int(arc))
    except (TypeError, ValueError):
        return None
    if hit is None:
        return None
    return canonical_key(hit[0]), hit[1]


def arc_label(arc) -> str:
    """The arc's own label, aliased or not -- "Aruba CX (HPE)" for 47196.
    A model hint for the evidence line, never the vendor."""
    try:
        hit = ENTERPRISES.get(int(arc))
    except (TypeError, ValueError):
        return ""
    return hit[1] if hit else ""


def is_verified(arc) -> bool:
    try:
        return int(arc) in VERIFIED
    except (TypeError, ValueError):
        return False


# Vendors identified by sysDescr alone, which therefore have no arc to be
# keyed by here, and still deserve to read as their own name rather than as
# a camelCase token. Empty since 4.37.0: Rockwell Automation was the only
# entry and now has arc 95 above, so it is reachable from a sysObjectID as
# well as from a sysDescr substring.
ARCLESS_DISPLAY: dict[str, str] = {}

# An aliased arc's label names a model, not a manufacturer, so it must not
# become the display name of the key it aliases to: without the skip,
# whichever of HPE's five arcs came first would have decided what "hp"
# reads as.
_DISPLAY: dict[str, str] = {}
for _arc, (_key, _name) in ENTERPRISES.items():
    if _key not in VENDOR_ALIASES:
        _DISPLAY.setdefault(_key, _name)
for _key, _name in ARCLESS_DISPLAY.items():
    _DISPLAY.setdefault(_key, _name)
del _arc, _key, _name


def display_name(key: str) -> str:
    """A human label for a vendor key, falling back to the key itself so a
    vendor named only by sysDescr still reads as something. Aliased through
    canonical_key() first, so a device stored under a narrow key by an
    earlier release still displays as its manufacturer."""
    key = canonical_key(key)
    return _DISPLAY.get(key or "", key or "")
