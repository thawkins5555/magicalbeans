"""A mode-selected v2c stub serving the four Tier 1 walks this plan added:
LLDP/CDP neighbours, PoE, STP and PtP radio RF — one process per mode, the
same "MODE global, table_for() picks the OID dict" shape stub_agent_fdb.py
already established, so each new suite doesn't need its own stub script.

    stub_agent_l2.py <port> <mode>

Modes:
  lldp          one LLDP neighbour on local port 1: a MAC-address chassis id
                (subtype 4) so nodesdb's device-match join can be tested,
                and a non-Cisco sysObjectID so CDP is never attempted.
  cdp           a Cisco sysObjectID and a CDP cdpCacheTable entry on
                ifIndex 3, no LLDP table at all — the "CDP is a fallback on
                gear that only speaks CDP" case.
  lldp_and_cdp  a Cisco sysObjectID answering BOTH tables at once — the
                "CDP supplements LLDP rather than only replacing it" case.
  no_l2         a Cisco sysObjectID with neither table implemented.
  lldp_manaddr  three LLDP neighbours exercising lldpRemManAddrTable: an
                IPv4 management address, an IPv6 one, and one with no
                management address row at all.
  poe           POWER-ETHERNET-MIB: a PSE budget/consumption pair and two
                ports (ifIndex 1 delivering power, ifIndex 2 disabled),
                plus the Cisco per-port milliwatt extension on port 1.
  no_poe        no pethMainPseTable at all.
  stp           BRIDGE-MIB dot1dStp: bridge-wide scalars, a
                dot1dBasePortIfIndex map (bridge port 5 -> ifIndex 1, 7 ->
                ifIndex 2, the same shape stub_agent_fdb.py's BASE table
                uses) and per-port state (5 forwarding, 7 blocking). A
                BUMP_TOPO control datagram increments the topology-change
                counter, for the "the counter actually moves" test.
  no_stp        no dot1dStp scalars at all.
  pvst          Classic PVST+: the DEFAULT context (community "public")
                answers dot1dStpPortState port 7 forwarding, the same as
                `stp` mode's bridge/scalar tables; `public@20` answers
                port 7 blocking, `public@30` answers it forwarding again
                -- the per-VLAN read nodepoll._cisco_vlan_stp needs to see
                the redundant uplink other than in VLAN 20. vtpVlanState
                also answers VLAN 1002 (legacy), operational but never
                actually walked (nodepoll drops the 1002-1005 range before
                asking) -- see the COMMUNITIES control datagram below.
  pvst-slow     Same as `pvst`, except `public@30` is never answered at
                all, so its column walk times out -- the "cut short, keep
                what is stored" case.
  pvst_no_vtp   Same bridge/scalar tables as `pvst`, no vtpVlanState table
                at all -- the "no VTP means no per-VLAN capability" latch.
  pvst-empty1   Bridge scalars and dot1dBasePortIfIndex answered as usual,
                but NO dot1dStpPortState rows at all in the DEFAULT context
                -- VLAN 1's own member ports are all trunk-pruned. VLAN
                contexts answer exactly as `pvst` -- the "the early return
                before the per-VLAN block must not skip it" case.
  pvst-no-scalars  DEFAULT context answers bridge ports and vtpVlanState
                but no dot1dStp scalars at all (protocolSpecification
                included); `public@20`/`public@30` answer port state as
                `pvst` -- the "a per-VLAN answer must stop the
                stp_capable=False latch" case.
  pvst-disabled Port 7 reads disabled(1) in every VLAN context (20 and
                30), forwarding(5) only in the DEFAULT context -- the
                "listening/learning/disabled/broken must not collapse to
                forwarding" case.
  pvst-orphan   A third bridge port (9 -> ifIndex 3) answered only in the
                DEFAULT context's dot1dStpPortState, never inside any VLAN
                context -- the "global-only port keeps its global state"
                case.
  pvst-50vlan   50 VLANs in vtpVlanState (1-50); every context answers the
                same port state as `pvst`'s DEFAULT -- the "sliced to the
                first 48 VLANs still counts as a complete pass" case.
  pvst-mixed    Port 7 absent from the DEFAULT context's port-state table
                entirely, listening(3) in VLAN 20 and learning(4) in VLAN
                30 -- two non-forwarding, non-blocking states with no
                global reading to fall back on, so the merge must still
                pick one rather than leave stp_state unset.

  airfiber      a Ubiquiti sysObjectID and the four RF_METRICS[41112]
                scalars, numbered exactly as demo/personas.py's
                ubiquiti_airfiber persona answers them.
  cambium       a Cambium sysObjectID and the four RF_METRICS[17713]
                scalars, numbered exactly as demo/personas.py's
                cambium_ptp persona answers them.
  arp           the legacy ipNetToMediaTable only (RFC 1213's, what nearly
                every agent actually populates): three good rows on two
                interfaces, one invalid(2) row that must be dropped, one
                whose PhysAddress is four octets (not a MAC) that must be
                dropped, and one MAC whose six bytes are all printable
                ASCII — the shape this app's OCTET STRING decoder hands
                back as text rather than colon-hex, which
                nodepoll._octets_from_value must still turn into the right
                six bytes.
  arp_physical  the IP-MIB successor ipNetToPhysicalTable only — what
                newer gear populates instead: an IPv4 row, an IPv6
                neighbour on the same MAC, a local(5) row, an invalid(2)
                row to drop and a dns(16)-typed row to skip.
  arp_both      both tables at once, with one row that is ONLY in the
                successor table — a modern agent answering both. The
                legacy table must win outright (no merge): the
                successor-only row must not appear, and nothing may be
                double-counted.
  no_arp        generic scalars only, neither ARP table.
  arp_big       120 ipNetToMediaTable rows across four interfaces — enough
                to measure a GETBULK walk's request count against, and to
                put a snmp_walk_max_rows cap below.

Control datagrams, on the same socket as SNMP itself (see
stub_agent_fdb.py, which established this convention):
  STATS       -> the request count so far, as decimal text
  RESET       -> zeroes it
  BUMP_TOPO   -> increments the STP topology-change counter (stp mode only)
  HIDE <ip>   -> stops serving that IP's ARP row(s) in every arp mode, so a
                 second walk sees the entry gone — for the "the entry aged
                 out of the cache" history test. stub_agent_fdb.py's
                 HIDE <mac>, keyed by address instead.
  COMMUNITIES -> comma-joined community strings seen since the last RESET,
                 so a test can prove which `@vlan` contexts were actually
                 asked for (pvst modes only -- every other mode answers on
                 the plain community alone).
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_END_OF_MIB_VIEW,
    T_NO_SUCH_OBJECT, T_NULL, T_SEQUENCE, V1, V2C, _tlv, enc_int, enc_octets,
    enc_varbind,
)

GENERIC_SCALARS = {
    "1.3.6.1.2.1.1.1.0": ("str", "l2 stub device"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.99999.1"),
    "1.3.6.1.2.1.1.3.0": ("int", 123456),
    "1.3.6.1.2.1.1.5.0": ("str", "l2-stub"),
}
CISCO_SCALARS = {**GENERIC_SCALARS,
                 "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.9.1.1208")}

# ------------------------------------------------------------------- LLDP
LLDP_TABLE = {
    # lldpRemChassisIdSubtype.<timeMark>.<localPort>.<remIndex> = 4 (macAddress)
    "1.0.8802.1.1.2.1.4.1.1.4.0.1.1": ("int", 4),
    "1.0.8802.1.1.2.1.4.1.1.5.0.1.1": ("bytes", bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
    "1.0.8802.1.1.2.1.4.1.1.6.0.1.1": ("int", 5),         # portId subtype: interfaceName
    "1.0.8802.1.1.2.1.4.1.1.7.0.1.1": ("str", "Gi0/24"),
    "1.0.8802.1.1.2.1.4.1.1.8.0.1.1": ("str", "uplink to core"),
    "1.0.8802.1.1.2.1.4.1.1.9.0.1.1": ("str", "core-sw-1"),
    "1.0.8802.1.1.2.1.4.1.1.10.0.1.1": ("str", "Core switch, IOS 15.2"),
}

# lldpRemManAddrTable: the address lives in the INDEX after the shared
# timeMark.localPort.remIndex prefix — addrSubtype.addrLen.addr[.addr...]
# (RFC 2579 InetAddress). Three neighbours: an IPv4 management address, an
# IPv6 one, and a third with no management address row at all.
LLDP_MANADDR_TABLE = {
    # local port 1, remIndex 1 -- IPv4 management address 10.0.0.9
    "1.0.8802.1.1.2.1.4.1.1.4.0.1.1": ("int", 4),
    "1.0.8802.1.1.2.1.4.1.1.5.0.1.1": ("bytes", bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])),
    "1.0.8802.1.1.2.1.4.1.1.6.0.1.1": ("int", 5),
    "1.0.8802.1.1.2.1.4.1.1.7.0.1.1": ("str", "Gi0/1"),
    "1.0.8802.1.1.2.1.4.1.1.8.0.1.1": ("str", "uplink v4"),
    "1.0.8802.1.1.2.1.4.1.1.9.0.1.1": ("str", "core-sw-v4"),
    "1.0.8802.1.1.2.1.4.1.1.10.0.1.1": ("str", "IPv4 neighbour"),
    "1.0.8802.1.1.2.1.4.2.1.3.0.1.1.1.4.10.0.0.9": ("int", 1),
    # local port 2, remIndex 1 -- IPv6 management address fe80::1
    "1.0.8802.1.1.2.1.4.1.1.4.0.2.1": ("int", 4),
    "1.0.8802.1.1.2.1.4.1.1.5.0.2.1": ("bytes", bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02])),
    "1.0.8802.1.1.2.1.4.1.1.6.0.2.1": ("int", 5),
    "1.0.8802.1.1.2.1.4.1.1.7.0.2.1": ("str", "Gi0/2"),
    "1.0.8802.1.1.2.1.4.1.1.8.0.2.1": ("str", "uplink v6"),
    "1.0.8802.1.1.2.1.4.1.1.9.0.2.1": ("str", "core-sw-v6"),
    "1.0.8802.1.1.2.1.4.1.1.10.0.2.1": ("str", "IPv6 neighbour"),
    "1.0.8802.1.1.2.1.4.2.1.3.0.2.1.2.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1": ("int", 2),
    # local port 3, remIndex 1 -- no management address row at all
    "1.0.8802.1.1.2.1.4.1.1.4.0.3.1": ("int", 4),
    "1.0.8802.1.1.2.1.4.1.1.5.0.3.1": ("bytes", bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03])),
    "1.0.8802.1.1.2.1.4.1.1.6.0.3.1": ("int", 5),
    "1.0.8802.1.1.2.1.4.1.1.7.0.3.1": ("str", "Gi0/3"),
    "1.0.8802.1.1.2.1.4.1.1.8.0.3.1": ("str", "no addr"),
    "1.0.8802.1.1.2.1.4.1.1.9.0.3.1": ("str", "core-sw-none"),
    "1.0.8802.1.1.2.1.4.1.1.10.0.3.1": ("str", "No address neighbour"),
}

# lldpLocPortTable: local port numbers 101-104 that are NOT ifIndexes.
# 101 -> "7" (subtype 7 local, a numeric ifIndex); 102 -> "Gi0/2" (subtype
# 5 interfaceName, matches ifDescr GigabitEthernet0/2 after expansion);
# 103 -> opaque id, placed by its port description; 104 -> unplaceable.
LLDP_LOCPORT_TABLE = {
    "1.0.8802.1.1.2.1.3.7.1.2.101": ("int", 7),
    "1.0.8802.1.1.2.1.3.7.1.3.101": ("str", "7"),
    "1.0.8802.1.1.2.1.3.7.1.4.101": ("str", "port 7"),
    "1.0.8802.1.1.2.1.3.7.1.2.102": ("int", 5),
    "1.0.8802.1.1.2.1.3.7.1.3.102": ("str", "Gi0/2"),
    "1.0.8802.1.1.2.1.3.7.1.4.102": ("str", "GigabitEthernet0/2"),
    "1.0.8802.1.1.2.1.3.7.1.2.103": ("int", 7),
    "1.0.8802.1.1.2.1.3.7.1.3.103": ("str", "slot-3"),
    "1.0.8802.1.1.2.1.3.7.1.4.103": ("str", "GigabitEthernet0/3"),
    "1.0.8802.1.1.2.1.3.7.1.2.104": ("int", 7),
    "1.0.8802.1.1.2.1.3.7.1.3.104": ("str", "mgmt"),
    "1.0.8802.1.1.2.1.3.7.1.4.104": ("str", "management"),
}
for _port, _name in ((101, "n-101"), (102, "n-102"), (103, "n-103"), (104, "n-104")):
    LLDP_LOCPORT_TABLE.update({
        f"1.0.8802.1.1.2.1.4.1.1.4.0.{_port}.1": ("int", 4),
        f"1.0.8802.1.1.2.1.4.1.1.5.0.{_port}.1": ("bytes", bytes([0xaa, 0xbb, 0xcc, 0, 0, _port])),
        f"1.0.8802.1.1.2.1.4.1.1.6.0.{_port}.1": ("int", 5),
        f"1.0.8802.1.1.2.1.4.1.1.7.0.{_port}.1": ("str", "eth0"),
        f"1.0.8802.1.1.2.1.4.1.1.8.0.{_port}.1": ("str", "uplink"),
        f"1.0.8802.1.1.2.1.4.1.1.9.0.{_port}.1": ("str", _name),
        f"1.0.8802.1.1.2.1.4.1.1.10.0.{_port}.1": ("str", "neighbour"),
    })

# ------------------------------------------------------------------- CDP
CDP_TABLE = {
    # cdpCache<Column>.<ifIndex>.<deviceIndex>
    "1.3.6.1.4.1.9.9.23.1.2.1.1.4.3.1": ("bytes", bytes([10, 0, 0, 9])),   # address
    "1.3.6.1.4.1.9.9.23.1.2.1.1.6.3.1": ("str", "access-sw-9"),           # device id
    "1.3.6.1.4.1.9.9.23.1.2.1.1.7.3.1": ("str", "GigabitEthernet0/1"),    # device port
    "1.3.6.1.4.1.9.9.23.1.2.1.1.8.3.1": ("str", "cisco WS-C2960X"),       # platform
}

# ------------------------------------------------------------------- PoE
POE_TABLE = {
    "1.3.6.1.2.1.105.1.3.1.1.2.1": ("int", 370),     # pethMainPsePower, group 1: 370W
    "1.3.6.1.2.1.105.1.3.1.1.3.1": ("int", 1),       # pethMainPseOperStatus: on
    "1.3.6.1.2.1.105.1.3.1.1.4.1": ("int", 214),     # pethMainPseConsumptionPower: 214W
    "1.3.6.1.2.1.105.1.1.1.1.3.1.1": ("int", 1),     # port 1 admin: enabled
    "1.3.6.1.2.1.105.1.1.1.1.3.1.2": ("int", 2),     # port 2 admin: disabled
    "1.3.6.1.2.1.105.1.1.1.1.6.1.1": ("int", 3),     # port 1 detection: deliveringPower
    "1.3.6.1.2.1.105.1.1.1.1.6.1.2": ("int", 1),     # port 2 detection: disabled
    "1.3.6.1.4.1.9.9.402.1.2.1.1.5.1.1": ("int", 15400),   # Cisco per-port mW, port 1
}

# ------------------------------------------------------------------- STP
BRIDGE_PORTS = {
    "1.3.6.1.2.1.17.1.4.1.2.5": ("int", 1),   # dot1dBasePortIfIndex: bridge port 5 -> ifIndex 1
    "1.3.6.1.2.1.17.1.4.1.2.7": ("int", 2),   # bridge port 7 -> ifIndex 2
}
STP_SCALARS = {
    "1.3.6.1.2.1.17.2.1.0": ("int", 3),           # dot1dStpProtocolSpecification: ieee8021d
    "1.3.6.1.2.1.17.2.2.0": ("int", 32768),       # dot1dStpPriority
    "1.3.6.1.2.1.17.2.3.0": ("int", 12000),       # dot1dStpTimeSinceTopologyChange (TimeTicks)
    "1.3.6.1.2.1.17.2.4.0": ("int", 5),           # dot1dStpTopChanges — TOPO_CHANGES below shadows this
    "1.3.6.1.2.1.17.2.5.0": ("bytes", bytes([0x80, 0x00]) + bytes([0, 0x11, 0x22, 0x33, 0x44, 0x55])),
    "1.3.6.1.2.1.17.2.6.0": ("int", 4),           # dot1dStpRootCost
    "1.3.6.1.2.1.17.2.7.0": ("int", 1),           # dot1dStpRootPort
}
STP_PORT_STATE = {
    "1.3.6.1.2.1.17.2.15.1.3.5": ("int", 5),      # bridge port 5: forwarding
    "1.3.6.1.2.1.17.2.15.1.3.7": ("int", 2),      # bridge port 7: blocking
}
TOPO_CHANGES = 5   # mutated by BUMP_TOPO

# ----------------------------------------------------------------- PVST
# Classic PVST+: dot1dStpPortState only tells the truth inside each VLAN's
# own community context (nodepoll._cisco_vlan_stp), the STP counterpart of
# stub_agent_fdb.py's "cisco" mode for the MAC table. Port 7 (-> ifIndex 2
# via BRIDGE_PORTS above) forwards in the DEFAULT context and in VLAN 30,
# but blocks in VLAN 20 -- the redundant uplink the global-only read
# misses entirely. Port 5 (-> ifIndex 1) is the opposite proof: the
# DEFAULT context calls it blocking, but every VLAN that answers it says
# forwarding, so the per-VLAN merge must win over a stale global reading.
PVST_PORT_STATE = {
    "1.3.6.1.2.1.17.2.15.1.3.5": ("int", 2),      # DEFAULT context: blocking
    "1.3.6.1.2.1.17.2.15.1.3.7": ("int", 5),      # DEFAULT context: forwarding
}
PVST_VTP = {
    "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.20": ("int", 1),
    "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.30": ("int", 1),
    "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.1002": ("int", 1),   # legacy -- never walked
}
PVST_PER_VLAN = {
    "20": {"1.3.6.1.2.1.17.2.15.1.3.5": ("int", 5),      # port 5: forwarding
          "1.3.6.1.2.1.17.2.15.1.3.7": ("int", 2)},      # port 7: blocking
    "30": {"1.3.6.1.2.1.17.2.15.1.3.5": ("int", 5),      # port 5: forwarding
          "1.3.6.1.2.1.17.2.15.1.3.7": ("int", 5)},      # port 7: forwarding
    # Would flip both ports' verdicts if the 1002-1005 drop ever failed and
    # this got asked.
    "1002": {"1.3.6.1.2.1.17.2.15.1.3.5": ("int", 2),
            "1.3.6.1.2.1.17.2.15.1.3.7": ("int", 2)},
}

# pvst-disabled: port 7 disabled(1) in every VLAN context.
PVST_DISABLED_PER_VLAN = {"1.3.6.1.2.1.17.2.15.1.3.7": ("int", 1)}

# pvst-orphan: a third bridge port answered only in the DEFAULT context.
BRIDGE_PORTS_ORPHAN = {**BRIDGE_PORTS, "1.3.6.1.2.1.17.1.4.1.2.9": ("int", 3)}
STP_PORT_STATE_ORPHAN_DEFAULT = {**PVST_PORT_STATE,
                                 "1.3.6.1.2.1.17.2.15.1.3.9": ("int", 5)}

# pvst-50vlan: vtpVlanState for VLANs 1-50, all operational(1).
PVST_VTP_50 = {f"1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.{v}": ("int", 1)
              for v in range(1, 51)}

# pvst-mixed: port 7 listening in VLAN 20, learning in VLAN 30, answered in
# neither the DEFAULT context.
PVST_MIXED_PER_VLAN = {
    "20": {"1.3.6.1.2.1.17.2.15.1.3.7": ("int", 3)},    # port 7: listening
    "30": {"1.3.6.1.2.1.17.2.15.1.3.7": ("int", 4)},    # port 7: learning
}

SEEN_COMMUNITIES = set()   # communities seen since the last RESET (pvst modes)

# --------------------------------------------------------------- PtP RF
AIRFIBER_TABLE = {
    "1.3.6.1.4.1.41112.1.3.2.1.1.0": ("int", -58),
    "1.3.6.1.4.1.41112.1.3.2.1.2.0": ("int", 28),
    "1.3.6.1.4.1.41112.1.3.2.1.3.0": ("int", 700_000_000),
    "1.3.6.1.4.1.41112.1.3.2.1.4.0": ("int", -61),
}
CAMBIUM_TABLE = {
    "1.3.6.1.4.1.17713.21.1.2.1.0": ("int", -52),
    "1.3.6.1.4.1.17713.21.1.2.2.0": ("int", 112),
    "1.3.6.1.4.1.17713.21.1.2.3.0": ("int", 320_000_000),
    "1.3.6.1.4.1.17713.21.1.2.4.0": ("int", -31),
}

# ------------------------------------------------------------------- ARP
# ipNetToMediaTable, index ifIndex.a.b.c.d. Columns: .1 ifIndex (INTEGER,
# present so the walk of .2 has a neighbour before it), .2 PhysAddress,
# .4 type (1 other, 2 invalid, 3 dynamic, 4 static). .3 (the address again,
# as IpAddress) is deliberately absent: the walker never asks for it, and
# the app's stub encoder has no IpAddress tag anyway.
_MEDIA = "1.3.6.1.2.1.4.22.1"
ARP_MEDIA_TABLE = {
    f"{_MEDIA}.1.1.10.0.0.5":  ("int", 1),
    f"{_MEDIA}.1.1.10.0.0.6":  ("int", 1),
    f"{_MEDIA}.1.1.10.0.0.7":  ("int", 1),
    f"{_MEDIA}.1.2.10.0.1.9":  ("int", 2),
    f"{_MEDIA}.1.2.10.0.1.66": ("int", 2),
    f"{_MEDIA}.2.1.10.0.0.5":  ("bytes", bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
    f"{_MEDIA}.2.1.10.0.0.6":  ("bytes", bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
    # Four octets: a PhysAddress that is not a MAC (a DLCI, say). Dropped.
    f"{_MEDIA}.2.1.10.0.0.7":  ("bytes", bytes([0x0a, 0x00, 0x00, 0x07])),
    # "ABCDEF" — six printable bytes, so the decoder hands back text.
    f"{_MEDIA}.2.2.10.0.1.9":  ("bytes", b"ABCDEF"),
    f"{_MEDIA}.2.2.10.0.1.66": ("bytes", bytes([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])),
    f"{_MEDIA}.4.1.10.0.0.5":  ("int", 3),   # dynamic
    f"{_MEDIA}.4.1.10.0.0.6":  ("int", 4),   # static
    f"{_MEDIA}.4.1.10.0.0.7":  ("int", 3),
    f"{_MEDIA}.4.2.10.0.1.9":  ("int", 3),
    f"{_MEDIA}.4.2.10.0.1.66": ("int", 2),   # invalid: being removed, drop it
}
# ipNetToPhysicalTable, index ifIndex.addrType.addrLen.<addrLen arcs>.
# Columns: .4 PhysAddress, .6 type (adds local(5) to the enum above).
_PHYS = "1.3.6.1.2.1.4.35.1"
_FE80_1 = "2.16." + ".".join(str(b) for b in bytes.fromhex("fe800000000000000000000000000001"))
ARP_PHYSICAL_TABLE = {
    f"{_PHYS}.4.1.1.4.10.0.0.5":  ("bytes", bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
    # The same host's link-local IPv6 address, on the same MAC.
    f"{_PHYS}.4.1.{_FE80_1}":     ("bytes", bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
    f"{_PHYS}.4.2.1.4.10.0.1.1":  ("bytes", bytes([0x00, 0x00, 0x5e, 0x00, 0x01, 0x01])),
    f"{_PHYS}.4.2.1.4.10.0.1.9":  ("bytes", b"ABCDEF"),
    f"{_PHYS}.4.2.1.4.10.0.1.66": ("bytes", bytes([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])),
    # dns(16)-typed address "host": legal in the MIB, not something this
    # app can store as an IP. Skipped.
    f"{_PHYS}.4.2.16.4.104.111.115.116": ("bytes", bytes([0, 0, 0, 0, 0, 0x99])),
    f"{_PHYS}.6.1.1.4.10.0.0.5":  ("int", 3),   # dynamic
    f"{_PHYS}.6.1.{_FE80_1}":     ("int", 3),
    f"{_PHYS}.6.2.1.4.10.0.1.1":  ("int", 5),   # local: the router's own address
    f"{_PHYS}.6.2.1.4.10.0.1.9":  ("int", 4),   # static
    f"{_PHYS}.6.2.1.4.10.0.1.66": ("int", 2),   # invalid
    f"{_PHYS}.6.2.16.4.104.111.115.116": ("int", 3),
}
# What a modern agent answering BOTH tables adds to the successor table
# only — must never show up while the legacy table has anything to say.
ARP_PHYSICAL_EXTRA = {
    f"{_PHYS}.4.3.1.4.10.0.9.9": ("bytes", bytes([0x02, 0x00, 0x00, 0x00, 0x99, 0x99])),
    f"{_PHYS}.6.3.1.4.10.0.9.9": ("int", 3),
}


def _big_arp_table():
    """120 ipNetToMediaTable rows across four interfaces, each with a
    distinct deterministic MAC — the shape "120-row ARP cache" refers to."""
    table = {}
    for if_index in range(1, 5):
        for host in range(1, 31):
            ip = f"10.{if_index}.0.{host}"
            suffix = f"{if_index}.{ip}"
            table[f"{_MEDIA}.2.{suffix}"] = (
                "bytes", bytes([0x02, 0xaa, if_index, 0, 0, host]))
            table[f"{_MEDIA}.4.{suffix}"] = ("int", 3)
    return table


ARP_BIG_TABLE = _big_arp_table()

HIDDEN_IPS = set()   # addresses (see HIDE) currently withheld from the ARP tables


def _ip_of_arp_oid(oid):
    """The address an ARP-table row OID's index spells out, in the form
    nodepoll stores it, or "" for an OID that is not an ARP row. Legacy
    rows end in the four dotted-decimal arcs; successor rows carry
    addrType.addrLen.<arcs> after the ifIndex."""
    import ipaddress
    parts = oid.split(".")
    try:
        if oid.startswith(_MEDIA + "."):
            return str(ipaddress.ip_address(bytes(int(p) for p in parts[-4:])))
        if oid.startswith(_PHYS + "."):
            base_len = len(_PHYS.split(".")) + 1   # column arc
            if_type_len = parts[base_len + 1:base_len + 3]
            addr_len = int(if_type_len[1])
            arcs = [int(p) for p in parts[base_len + 3:]]
            if len(arcs) != addr_len or addr_len not in (4, 16):
                return ""
            return str(ipaddress.ip_address(bytes(arcs)))
    except (ValueError, IndexError):
        return ""
    return ""


def _without_hidden(table):
    if not HIDDEN_IPS:
        return table
    return {oid: entry for oid, entry in table.items()
            if _ip_of_arp_oid(oid) not in HIDDEN_IPS}


MODE = "lldp"


def read_community(data: bytes) -> str:
    """Pulls the community straight off the wire -- stub_agent_fdb.py's own
    read_community, needed here for the same reason: pvst mode's VLAN
    lives in the community, and decode_response skips it."""
    def length_at(i):
        first = data[i]
        if first < 0x80:
            return first, i + 1
        n = first & 0x7F
        return int.from_bytes(data[i + 1:i + 1 + n], "big"), i + 1 + n

    i = 1                       # past the outer SEQUENCE tag
    _outer, i = length_at(i)
    assert data[i] == 0x02      # version INTEGER
    vlen, i = length_at(i + 1)
    i += vlen
    assert data[i] == 0x04      # community OCTET STRING
    clen, i = length_at(i + 1)
    return data[i:i + clen].decode("utf-8", "replace")


def table_for(community="public"):
    if MODE == "arp":
        return {**GENERIC_SCALARS, **_without_hidden(ARP_MEDIA_TABLE)}
    if MODE == "arp_physical":
        return {**GENERIC_SCALARS, **_without_hidden(ARP_PHYSICAL_TABLE)}
    if MODE == "arp_both":
        return {**GENERIC_SCALARS,
                **_without_hidden({**ARP_MEDIA_TABLE, **ARP_PHYSICAL_TABLE,
                                   **ARP_PHYSICAL_EXTRA})}
    if MODE == "no_arp":
        return dict(GENERIC_SCALARS)
    if MODE == "arp_big":
        return {**GENERIC_SCALARS, **_without_hidden(ARP_BIG_TABLE)}
    if MODE == "lldp":
        return {**GENERIC_SCALARS, **LLDP_TABLE}
    if MODE == "lldp_manaddr":
        return {**GENERIC_SCALARS, **LLDP_MANADDR_TABLE}
    if MODE == "lldp_locport":
        return {**GENERIC_SCALARS, **LLDP_LOCPORT_TABLE}
    if MODE == "cdp":
        return {**CISCO_SCALARS, **CDP_TABLE}
    if MODE == "lldp_and_cdp":
        return {**CISCO_SCALARS, **LLDP_TABLE, **CDP_TABLE}
    if MODE == "no_l2":
        return dict(CISCO_SCALARS)
    if MODE == "poe":
        return {**GENERIC_SCALARS, **POE_TABLE}
    if MODE == "no_poe":
        return dict(GENERIC_SCALARS)
    if MODE == "stp":
        table = {**GENERIC_SCALARS, **BRIDGE_PORTS, **STP_SCALARS, **STP_PORT_STATE}
        table["1.3.6.1.2.1.17.2.4.0"] = ("int", TOPO_CHANGES)
        return table
    if MODE == "no_stp":
        return {**GENERIC_SCALARS, **BRIDGE_PORTS}
    if MODE in ("pvst", "pvst-slow"):
        # vtpVlanState is never walked in a per-VLAN context by real
        # nodepoll code (_cisco_vlan_stp only scopes dot1dStpPortState
        # there), and a real per-VLAN context doesn't answer it either --
        # so dot1dStpPortState IS the last object of THAT context's view,
        # same as the real device this stub models.
        table = {**GENERIC_SCALARS, **BRIDGE_PORTS, **STP_SCALARS, **PVST_PORT_STATE}
        if "@" in community:
            vlan = community.split("@", 1)[1]
            table.update(PVST_PER_VLAN.get(vlan, {}))
        else:
            table.update(PVST_VTP)
        return table
    if MODE == "pvst_no_vtp":
        return {**GENERIC_SCALARS, **BRIDGE_PORTS, **STP_SCALARS, **PVST_PORT_STATE}
    if MODE == "pvst-empty1":
        table = {**GENERIC_SCALARS, **BRIDGE_PORTS, **STP_SCALARS, **PVST_VTP}
        if "@" in community:
            vlan = community.split("@", 1)[1]
            table.update(PVST_PER_VLAN.get(vlan, {}))
        return table
    if MODE == "pvst-no-scalars":
        table = {**GENERIC_SCALARS, **BRIDGE_PORTS, **PVST_VTP}
        if "@" in community:
            vlan = community.split("@", 1)[1]
            table.update(PVST_PER_VLAN.get(vlan, {}))
        return table
    if MODE == "pvst-disabled":
        table = {**GENERIC_SCALARS, **BRIDGE_PORTS, **STP_SCALARS, **PVST_PORT_STATE,
                 **PVST_VTP}
        if "@" in community:
            table.update(PVST_DISABLED_PER_VLAN)
        return table
    if MODE == "pvst-orphan":
        table = {**GENERIC_SCALARS, **BRIDGE_PORTS_ORPHAN, **STP_SCALARS, **PVST_VTP}
        if "@" in community:
            vlan = community.split("@", 1)[1]
            table.update(PVST_PER_VLAN.get(vlan, {}))
        else:
            table.update(STP_PORT_STATE_ORPHAN_DEFAULT)
        return table
    if MODE == "pvst-mixed":
        table = {**GENERIC_SCALARS, **BRIDGE_PORTS, **STP_SCALARS, **PVST_VTP}
        if "@" in community:
            vlan = community.split("@", 1)[1]
            table.update(PVST_MIXED_PER_VLAN.get(vlan, {}))
        return table
    if MODE == "pvst-50vlan":
        return {**GENERIC_SCALARS, **BRIDGE_PORTS, **STP_SCALARS, **PVST_PORT_STATE,
                **PVST_VTP_50}
    if MODE == "airfiber":
        return {**GENERIC_SCALARS, **AIRFIBER_TABLE,
                "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.41112.1.3")}
    if MODE == "cambium":
        return {**GENERIC_SCALARS, **CAMBIUM_TABLE,
                "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.17713.21.1.1")}
    return dict(GENERIC_SCALARS)


def oid_key(oid):
    return tuple(int(a) for a in oid.split("."))


def encode_value(kind, value):
    if kind == "str":
        return enc_octets(value)
    if kind == "bytes":
        return enc_octets(value)
    return enc_int(value)


def reply(request_id, body, community="public", *, version=V2C,
         error_status=0, error_index=0):
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(error_status) +
              enc_int(error_index) + _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(version) + enc_octets(community) + pdu)


def main():
    global MODE, TOPO_CHANGES
    port = int(sys.argv[1])
    MODE = sys.argv[2] if len(sys.argv) > 2 else "lldp"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"L2 stub ({MODE}) listening on 127.0.0.1:{port}", flush=True)
    count = 0
    while True:
        data, addr = sock.recvfrom(65535)
        if data == b"STATS":
            sock.sendto(str(count).encode(), addr)
            continue
        if data == b"RESET":
            count = 0
            SEEN_COMMUNITIES.clear()
            sock.sendto(b"0", addr)
            continue
        if data == b"COMMUNITIES":
            sock.sendto(",".join(sorted(SEEN_COMMUNITIES)).encode(), addr)
            continue
        if data == b"BUMP_TOPO":
            TOPO_CHANGES += 1
            sock.sendto(str(TOPO_CHANGES).encode(), addr)
            continue
        if data.startswith(b"HIDE "):
            ip = data[5:].decode("utf-8", "replace").strip()
            if ip:
                HIDDEN_IPS.add(ip)
            sock.sendto(b"ok", addr)
            continue
        try:
            request = decode_response(data)
        except Exception:
            continue
        if not request.varbinds:
            continue
        try:
            community = read_community(data)
        except Exception:
            community = "public"
        SEEN_COMMUNITIES.add(community)
        if MODE == "pvst-slow" and community == "public@30":
            continue                # the agent stalling on this one VLAN
        count += 1
        table = table_for(community)
        keys = sorted(table, key=oid_key)
        oids = [vb["oid"] for vb in request.varbinds]
        if request.pdu_tag == PDU_GET:
            body = b""
            for oid in oids:
                entry = table.get(oid)
                body += enc_varbind(oid, _tlv(T_NO_SUCH_OBJECT, b"")
                                    if entry is None else encode_value(*entry))
        elif request.pdu_tag == PDU_GETNEXT:
            rk = oid_key(oids[0])
            nxt = next((k for k in keys if oid_key(k) > rk), None)
            if nxt is None and MODE == "pvst" and request.version == V1:
                # v1 has no endOfMibView; a real v1 agent answers a GETNEXT
                # past its last object with noSuchName(2) (RFC 1157).
                sock.sendto(reply(request.request_id,
                                  enc_varbind(oids[0], _tlv(T_NULL, b"")),
                                  community, version=V1, error_status=2,
                                  error_index=1), addr)
                continue
            body = (enc_varbind(oids[0], _tlv(T_END_OF_MIB_VIEW, b""))
                    if nxt is None else enc_varbind(nxt, encode_value(*table[nxt])))
        elif request.pdu_tag == PDU_GETBULK:
            max_repetitions = max(1, request.error_index or 1)
            cursor = oids[0]
            body = b""
            for _ in range(max_repetitions):
                rk = oid_key(cursor)
                nxt = next((k for k in keys if oid_key(k) > rk), None)
                if nxt is None:
                    body += enc_varbind(cursor, _tlv(T_END_OF_MIB_VIEW, b""))
                    break
                body += enc_varbind(nxt, encode_value(*table[nxt]))
                cursor = nxt
        else:
            continue
        sock.sendto(reply(request.request_id, body, community), addr)


if __name__ == "__main__":
    main()
