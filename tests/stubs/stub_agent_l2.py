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

Two control datagrams, on the same socket as SNMP itself (see
stub_agent_fdb.py, which established this convention):
  STATS       -> the request count so far, as decimal text
  RESET       -> zeroes it
  BUMP_TOPO   -> increments the STP topology-change counter (stp mode only)
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

MODE = "lldp"


def table_for():
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
