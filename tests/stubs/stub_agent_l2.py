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
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_END_OF_MIB_VIEW,
    T_NO_SUCH_OBJECT, T_SEQUENCE, V2C, _tlv, enc_int, enc_octets, enc_varbind,
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


def table_for():
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


def reply(request_id, body):
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets("public") + pdu)


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
            sock.sendto(b"0", addr)
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
        count += 1
        table = table_for()
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
        sock.sendto(reply(request.request_id, body), addr)


if __name__ == "__main__":
    main()
