"""SNMP OID names, enum tables, and default severity rules.

This is a name table, not a MIB compiler. Parsing SMIv1/SMIv2 `.mib`/`.my`
ASN.1 modules is a substantial parser project of its own and is out of scope
for a stdlib-only app. The built-in table below plus the admin-editable
`oid_names` setting (see trapdecode.Decoder.configure) covers the traps any
given site actually cares about without that undertaking.
"""

from __future__ import annotations

WELL_KNOWN = {
    # -------------------------------------------------- SNMPv2-MIB (system)
    "1.3.6.1.2.1.1":           "system",
    "1.3.6.1.2.1.1.1":         "sysDescr",
    "1.3.6.1.2.1.1.2":         "sysObjectID",
    "1.3.6.1.2.1.1.3":         "sysUpTime",
    "1.3.6.1.2.1.1.4":         "sysContact",
    "1.3.6.1.2.1.1.5":         "sysName",
    "1.3.6.1.2.1.1.6":         "sysLocation",
    "1.3.6.1.2.1.1.7":         "sysServices",
    # --------------------------------------------- SNMPv2-MIB (trap group)
    "1.3.6.1.6.3.1.1.4.1":     "snmpTrapOID",
    "1.3.6.1.6.3.1.1.4.3":     "snmpTrapEnterprise",
    "1.3.6.1.6.3.1.1.5.1":     "coldStart",
    "1.3.6.1.6.3.1.1.5.2":     "warmStart",
    "1.3.6.1.6.3.1.1.5.3":     "linkDown",
    "1.3.6.1.6.3.1.1.5.4":     "linkUp",
    "1.3.6.1.6.3.1.1.5.5":     "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6":     "egpNeighborLoss",
    "1.3.6.1.6.3.18.1.3":      "snmpTrapAddress",
    "1.3.6.1.6.3.18.1.4":      "snmpTrapCommunity",
    # ------------------------------------------------------------- IF-MIB
    "1.3.6.1.2.1.2.2.1.1":     "ifIndex",
    "1.3.6.1.2.1.2.2.1.2":     "ifDescr",
    "1.3.6.1.2.1.2.2.1.3":     "ifType",
    "1.3.6.1.2.1.2.2.1.4":     "ifMtu",
    "1.3.6.1.2.1.2.2.1.5":     "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6":     "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7":     "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8":     "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1":  "ifName",
    "1.3.6.1.2.1.31.1.1.1.15": "ifHighSpeed",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
    # ------------------------------------------------- BRIDGE-MIB / RSTP
    "1.3.6.1.2.1.17.0.1":      "newRoot",
    "1.3.6.1.2.1.17.0.2":      "topologyChange",
    # ---------------------------------------------------------- BGP4-MIB
    "1.3.6.1.2.1.15.7.1":      "bgpEstablished",
    "1.3.6.1.2.1.15.7.2":      "bgpBackwardTransition",
    "1.3.6.1.2.1.15.3.1.7":    "bgpPeerState",
    "1.3.6.1.2.1.15.3.1.14":   "bgpPeerLastError",
    # ----------------------------------------------------------- UPS-MIB
    "1.3.6.1.2.1.33.2.1":      "upsTrapOnBattery",
    "1.3.6.1.2.1.33.2.2":      "upsTrapTestCompleted",
    "1.3.6.1.2.1.33.2.3":      "upsTrapAlarmEntryAdded",
    "1.3.6.1.2.1.33.2.4":      "upsTrapAlarmEntryRemoved",
    # -------------------------------------------------------- ENTITY-MIB
    "1.3.6.1.2.1.47.1.1.1.1.2": "entPhysicalDescr",
    "1.3.6.1.2.1.47.1.1.1.1.7": "entPhysicalName",
    # ------------------------------------------- vendor roots (prefixes)
    "1.3.6.1.4.1.9":           "cisco",
    "1.3.6.1.4.1.9.9.41.2.0.1": "clogMessageGenerated",
    "1.3.6.1.4.1.9.9.43.2.0.1": "ciscoConfigManEvent",
    "1.3.6.1.4.1.9.9.187.0.1": "cbgpFsmStateChange",
    "1.3.6.1.4.1.232":         "hpCompaq",
    "1.3.6.1.4.1.311":         "microsoft",
    "1.3.6.1.4.1.318":         "apc",
    "1.3.6.1.4.1.674":         "dell",
    "1.3.6.1.4.1.789":         "netApp",
    "1.3.6.1.4.1.1916":        "extremeNetworks",
    "1.3.6.1.4.1.1991":        "brocade",
    "1.3.6.1.4.1.2011":        "huawei",
    "1.3.6.1.4.1.2021":        "ucdavis",
    "1.3.6.1.4.1.2636":        "juniper",
    "1.3.6.1.4.1.3375":        "f5",
    "1.3.6.1.4.1.4526":        "netgear",
    "1.3.6.1.4.1.6876":        "vmware",
    "1.3.6.1.4.1.8072":        "netSnmp",
    "1.3.6.1.4.1.12356":       "fortinet",
    "1.3.6.1.4.1.14988":       "mikrotik",
    "1.3.6.1.4.1.25461":       "paloAlto",
    "1.3.6.1.4.1.25506":       "h3c",
    "1.3.6.1.4.1.30065":       "arista",
    # --- added 4.28.0. Every arc below was read out of that vendor's own MIB
    # text (the "::= { enterprises N }" line), not from memory: a wrong arc
    # silently mislabels every device under it, which is worse than a blank
    # Vendor column. The MIB catalog shipped bundles for vendors this table
    # could not even name, so a device could have its MIB installed and still
    # show no vendor at all.
    "1.3.6.1.4.1.11":          "hp",             # HP-ICF-OID
    "1.3.6.1.4.1.161":         "motorola",       # Cambium's Canopy/PMP line
                                                 # still registers under
                                                 # Motorola's arc, so this is
                                                 # named for the arc's owner
                                                 # rather than for Cambium.
    "1.3.6.1.4.1.171":         "dlink",
    "1.3.6.1.4.1.248":         "hirschmann",
    "1.3.6.1.4.1.476":         "vertiv",         # Liebert / Emerson
    "1.3.6.1.4.1.534":         "eaton",
    "1.3.6.1.4.1.664":         "adtran",
    "1.3.6.1.4.1.890":         "zyxel",
    "1.3.6.1.4.1.2604":        "sophos",
    "1.3.6.1.4.1.2606":        "rittal",
    "1.3.6.1.4.1.2620":        "checkPoint",
    "1.3.6.1.4.1.3097":        "watchguard",
    "1.3.6.1.4.1.4413":        "broadcom",       # NETGEAR's managed switches
                                                 # run OEM'd Broadcom FASTPATH
                                                 # and report here; so do other
                                                 # FASTPATH OEMs, hence the
                                                 # arc's real owner, not
                                                 # "netgear".
    "1.3.6.1.4.1.5951":        "citrix",         # NetScaler
    "1.3.6.1.4.1.6027":        "dellNetworking", # Force10 line; 674 is the
                                                 # separate Dell/OpenManage arc
    "1.3.6.1.4.1.6574":        "synology",
    "1.3.6.1.4.1.8741":        "sonicwall",
    "1.3.6.1.4.1.11863":       "tpLink",
    "1.3.6.1.4.1.12276":       "f5Networks",     # 3375 is F5's other arc
    "1.3.6.1.4.1.13742":       "raritan",
    "1.3.6.1.4.1.14823":       "aruba",
    "1.3.6.1.4.1.25053":       "ruckus",
    "1.3.6.1.4.1.26928":       "aerohive",
    "1.3.6.1.4.1.41112":       "ubiquiti",
    "1.3.6.1.4.1.47196":       "arubaCx",        # HPE's ArubaOS-CX line
}

# The short label the table column and the kind filter show.
KIND_BY_OID = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    "1.3.6.1.2.1.17.0.1":  "newRoot",
    "1.3.6.1.2.1.17.0.2":  "topologyChange",
    "1.3.6.1.2.1.15.7.1":  "bgpEstablished",
    "1.3.6.1.2.1.15.7.2":  "bgpBackwardTransition",
    "1.3.6.1.2.1.33.2.1":  "upsOnBattery",
}

# Every kind the filter dropdown offers, in the order it offers them.
KINDS = ["coldStart", "warmStart", "linkDown", "linkUp",
         "authenticationFailure", "egpNeighborLoss", "newRoot",
         "topologyChange", "bgpEstablished", "bgpBackwardTransition",
         "upsOnBattery", "enterpriseSpecific", "encrypted"]

# Longest prefix wins; the decoder re-sorts after appending user rules.
# The scale is syslog's, deliberately: 0 emergency … 7 debug. A future
# alerting engine can then treat a trap and a syslog line as the same kind of
# thing without translating between two severity vocabularies.
DEFAULT_SEVERITY_RULES = [
    ("1.3.6.1.6.3.1.1.5.1", 4),   # coldStart            -> warning
    ("1.3.6.1.6.3.1.1.5.2", 4),   # warmStart            -> warning
    ("1.3.6.1.6.3.1.1.5.3", 3),   # linkDown             -> error
    ("1.3.6.1.6.3.1.1.5.4", 5),   # linkUp               -> notice
    ("1.3.6.1.6.3.1.1.5.5", 4),   # authenticationFailure-> warning
    ("1.3.6.1.6.3.1.1.5.6", 3),   # egpNeighborLoss      -> error
    ("1.3.6.1.2.1.15.7.1",  5),   # bgpEstablished       -> notice
    ("1.3.6.1.2.1.15.7.2",  3),   # bgpBackwardTransition-> error
    ("1.3.6.1.2.1.17.0.1",  4),   # newRoot              -> warning
    ("1.3.6.1.2.1.17.0.2",  5),   # topologyChange       -> notice
    ("1.3.6.1.2.1.33.2.1",  2),   # upsTrapOnBattery     -> critical
]

# Enum-valued objects worth showing by name rather than as a bare number.
ENUMS = {
    "1.3.6.1.2.1.2.2.1.7": {1: "up", 2: "down", 3: "testing"},          # ifAdminStatus
    "1.3.6.1.2.1.2.2.1.8": {1: "up", 2: "down", 3: "testing",
                            4: "unknown", 5: "dormant", 6: "notPresent",
                            7: "lowerLayerDown"},                        # ifOperStatus
    "1.3.6.1.2.1.15.3.1.7": {1: "idle", 2: "connect", 3: "active",
                             4: "opensent", 5: "openconfirm",
                             6: "established"},                          # bgpPeerState
}


def enum_text(oid: str, kind: str, value, fallback: str) -> str:
    """Name a numeric enum where one is known: 'down (2)' rather than '2'."""
    if kind != "INTEGER":
        return fallback
    parts = oid.rsplit(".", 1)
    table = ENUMS.get(oid) or (ENUMS.get(parts[0]) if len(parts) == 2 else None)
    if not table:
        return fallback
    try:
        name = table.get(int(value) if value is not None else None)
    except (TypeError, ValueError):
        return fallback
    return f"{name} ({value})" if name else fallback
