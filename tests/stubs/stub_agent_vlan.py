"""A mode-selected v2c stub serving the per-port VLAN membership tables
nodepoll.read_device_vlans() walks — the same "MODE global, table_for()
picks the OID dict" shape stub_agent_l2.py already established for the
LLDP/CDP/PoE/STP/RF suites, so this new suite doesn't need its own stub
plumbing either.

    stub_agent_vlan.py <port> <mode>

Modes:
  dot1q             Q-BRIDGE-MIB standards path only (no Cisco tables):
                     dot1dBasePortIfIndex (bridge port 1 -> ifIndex 1, port
                     2 -> ifIndex 2), three named VLANs (10 "data", 20
                     "voice", 30 "guest" — 30 has no membership, just a
                     name), dot1qVlanStaticEgressPorts/UntaggedPorts so
                     ifIndex 1 carries VLAN 10 untagged (access) and
                     ifIndex 2 carries VLAN 10 tagged + VLAN 20 untagged
                     (trunk), and dot1qPvid matching each port's untagged
                     VLAN.
  dot1q_no_baseport  The same dot1q tables, minus dot1dBasePortIfIndex —
                     the "bridge port number used as ifIndex" fallback case.
                     Bridge ports 1/2 are reused as the suffixes so the
                     fallback lands on the same ifIndex 1/2 the dot1q mode
                     above resolves through the (here, absent) map.
  cisco_vtp          CISCO-VTP-MIB only (no dot1q tables): vtpVlanName for
                     VLAN 10 "data" and VLAN 1030 "voice-ext" (an extended-
                     range VLAN, so the vlanTrunkPortVlansEnabled2k column
                     is the one that has to answer for it), ifIndex 1
                     trunking with native VLAN 10 and both VLANs enabled —
                     10 via the base bitmap, 1030 via the 2k one.
  both               Answers BOTH tables, on a SECOND port (ifIndex 5) that
                     dot1q describes as VLAN 10 untagged/native and Cisco
                     describes as a trunk with native VLAN 20 carrying
                     VLANs 10 (tagged) and 20 (native/untagged) — a direct
                     contradiction on VLAN 10's tagged/untagged status and
                     on the port's native VLAN, so the "Cisco supersedes"
                     rule has something to actually decide between.
  cisco_mixed        One Cisco switch with a real trunk (ifIndex 1: VTP
                     status trunking, native VLAN 10, allow-list {10, 20})
                     and a real access port (ifIndex 2: VTP status
                     notTrunking, plus the native-VLAN/allow-list answers a
                     real IOS access port still gives -- default native 1
                     and an allow-list, here standing in for "allow every
                     VLAN" as just VLAN 1 -- both of which must be ignored)
                     described by dot1q as VLAN 30 untagged/native. Covers
                     the "trunk allow-list applied to access ports too" fix.
  no_vlan            Answers neither Q-BRIDGE nor CISCO-VTP VLAN tables —
                     read_device_vlans must return None.
  baseport_only      Answers ONLY dot1dBasePortIfIndex (BRIDGE-MIB) — no
                     Q-BRIDGE or CISCO-VTP table at all. A switch with no
                     VLAN-related MIB whatsoever still speaks plain
                     bridging, so read_device_vlans must still return None
                     rather than mistake this answer for VLAN evidence.

Two control datagrams, on the same socket as SNMP itself (see
stub_agent_l2.py, which established this convention):
  STATS       -> the request count so far, as decimal text
  RESET       -> zeroes it
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
    "1.3.6.1.2.1.1.1.0": ("str", "vlan stub device"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.99999.2"),
    "1.3.6.1.2.1.1.3.0": ("int", 123456),
    "1.3.6.1.2.1.1.5.0": ("str", "vlan-stub"),
}
CISCO_SCALARS = {**GENERIC_SCALARS,
                 "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.9.1.1208")}

# --------------------------------------------------------------- Q-BRIDGE
#
# Bit positions below are hand-computed against nodepoll._decode_port_list's
# documented PortList layout (most significant bit of byte 0 is bridge port
# 1, 1-based): byte index i, bit b (0 = MSB) encodes bridge port i*8 + b + 1.
# CISCO-VTP-MIB's own vlanTrunkPortVlansEnabled* bitmaps, further down, are
# NOT this layout -- see the note beside VTP_TRUNK_ENABLED below.
BASE_PORT_IFINDEX = {
    # dot1dBasePortIfIndex.<bridge port> = ifIndex
    "1.3.6.1.2.1.17.1.4.1.2.1": ("int", 1),
    "1.3.6.1.2.1.17.1.4.1.2.2": ("int", 2),
}
DOT1Q_NAMES = {
    # dot1qVlanStaticName.<vlan>
    "1.3.6.1.2.1.17.7.1.4.3.1.1.10": ("str", "data"),
    "1.3.6.1.2.1.17.7.1.4.3.1.1.20": ("str", "voice"),
    "1.3.6.1.2.1.17.7.1.4.3.1.1.30": ("str", "guest"),
}
DOT1Q_EGRESS = {
    # dot1qVlanStaticEgressPorts.<vlan>: VLAN 10 on bridge ports 1 and 2
    # (0xC0 = bit0+bit1 = ports 1,2); VLAN 20 on bridge port 2 only (0x40).
    "1.3.6.1.2.1.17.7.1.4.3.1.2.10": ("bytes", bytes([0xC0])),
    "1.3.6.1.2.1.17.7.1.4.3.1.2.20": ("bytes", bytes([0x40])),
}
DOT1Q_UNTAGGED = {
    # dot1qVlanStaticUntaggedPorts.<vlan>: VLAN 10 untagged on port 1 only
    # (0x80) -- so port 2 carries VLAN 10 tagged (egress but not untagged).
    # VLAN 20 untagged on port 2 (0x40), matching its only egress port.
    "1.3.6.1.2.1.17.7.1.4.3.1.4.10": ("bytes", bytes([0x80])),
    "1.3.6.1.2.1.17.7.1.4.3.1.4.20": ("bytes", bytes([0x40])),
}
DOT1Q_PVID = {
    # dot1qPvid.<bridge port>: port 1's native/access VLAN is 10 (matching
    # its only untagged membership); port 2's is 20.
    "1.3.6.1.2.1.17.7.1.4.5.1.1.1": ("int", 10),
    "1.3.6.1.2.1.17.7.1.4.5.1.1.2": ("int", 20),
}

# The same dot1q membership tables, but keyed under bridge ports 1/2 with
# NO dot1dBasePortIfIndex answering at all -- read_device_vlans must fall
# back to treating the bridge port number as the ifIndex directly.
DOT1Q_NO_BASEPORT = {**DOT1Q_NAMES, **DOT1Q_EGRESS, **DOT1Q_UNTAGGED, **DOT1Q_PVID}

# ----------------------------------------------------------- CISCO-VTP-MIB
VTP_NAMES = {
    # vtpVlanName.<vlan>: 1030 is an extended-range VLAN (above 1023), so
    # only the vlanTrunkPortVlansEnabled2k column (base 1024) can carry it.
    "1.3.6.1.4.1.9.9.46.1.3.1.1.4.10": ("str", "data"),
    "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1030": ("str", "voice-ext"),
}
VTP_TRUNK_STATUS = {
    # vlanTrunkPortDynamicStatus.<ifIndex>: 1 = trunking
    "1.3.6.1.4.1.9.9.46.1.6.1.1.14.1": ("int", 1),
}
VTP_TRUNK_NATIVE = {
    # vlanTrunkPortNativeVlan.<ifIndex>
    "1.3.6.1.4.1.9.9.46.1.6.1.1.5.1": ("int", 10),
}
# CISCO-VTP-MIB's vlanTrunkPortVlansEnabled* bitmaps are NOT PortList-style:
# per the MIB's own DESCRIPTION, octet 0's most significant bit is VLAN 0
# (0-based), not "the lowest VLAN plus one" the way a PortList's octet 0
# reserves its MSB for bridge port 1 -- see nodepoll._decode_vlan_bitmap.
# So VLAN v within a column sits at byte index v // 8, bit index v % 8
# (0 = MSB), weight 0x80 >> (v % 8).
VTP_TRUNK_ENABLED = {
    # vlanTrunkPortVlansEnabled.<ifIndex> (base 0): VLAN 10 -> byte index 1,
    # bit 2 -> 0x20 in the second byte.
    "1.3.6.1.4.1.9.9.46.1.6.1.1.4.1": ("bytes", bytes([0x00, 0x20])),
    # vlanTrunkPortVlansEnabled2k.<ifIndex> (base 1024): VLAN 1030 is
    # position 6 (1030 - 1024) -> byte index 0, bit 6 -> 0x02.
    "1.3.6.1.4.1.9.9.46.1.6.1.1.17.1": ("bytes", bytes([0x02])),
}

# The "both" mode's second port (ifIndex 5 == bridge port 5, chosen equal
# so the same number reads correctly under either table's own indexing):
# dot1q says VLAN 10 untagged/native; Cisco says a trunk with native VLAN
# 20 carrying VLANs 10 (tagged) and 20 (native/untagged) -- a genuine
# contradiction on both VLAN 10's tagged status and the port's native VLAN.
BOTH_BASEPORT = {"1.3.6.1.2.1.17.1.4.1.2.5": ("int", 5)}
BOTH_DOT1Q_NAMES = {"1.3.6.1.2.1.17.7.1.4.3.1.1.10": ("str", "data")}
BOTH_DOT1Q_EGRESS = {
    # bridge port 5 -> position 5 -> byte index 0, bit 4 -> 0x08.
    "1.3.6.1.2.1.17.7.1.4.3.1.2.10": ("bytes", bytes([0x08])),
}
BOTH_DOT1Q_UNTAGGED = {
    "1.3.6.1.2.1.17.7.1.4.3.1.4.10": ("bytes", bytes([0x08])),
}
BOTH_DOT1Q_PVID = {"1.3.6.1.2.1.17.7.1.4.5.1.1.5": ("int", 10)}
BOTH_VTP_NAMES = {
    "1.3.6.1.4.1.9.9.46.1.3.1.1.4.10": ("str", "data"),
    "1.3.6.1.4.1.9.9.46.1.3.1.1.4.20": ("str", "voice"),
}
BOTH_TRUNK_STATUS = {"1.3.6.1.4.1.9.9.46.1.6.1.1.14.5": ("int", 1)}
BOTH_TRUNK_NATIVE = {"1.3.6.1.4.1.9.9.46.1.6.1.1.5.5": ("int", 20)}
BOTH_TRUNK_ENABLED = {
    # vlanTrunkPortVlansEnabled.5 (base 0, 0-indexed -- see VTP_TRUNK_ENABLED
    # above): VLAN 10 -> byte 1 bit 2 -> 0x20; VLAN 20 -> byte 2 bit 4 -> 0x08.
    "1.3.6.1.4.1.9.9.46.1.6.1.1.4.5": ("bytes", bytes([0x00, 0x20, 0x08])),
}

# ----------------------------------------------- cisco_mixed: trunk + access
#
# One Cisco switch with both a real trunk (ifIndex 1) and a real access port
# (ifIndex 2) -- the scenario Finding 3 (4.54.0 review) covers: on real IOS,
# vlanTrunkPortDynamicStatus carries a row for EVERY switchport, and an
# access port still answers vlanTrunkPortVlansEnabled with its configured
# allow-list (modelled here as VLAN 1 -- standing in for the real default of
# "every VLAN") and vlanTrunkPortNativeVlan with IOS's default of 1. Neither
# is meaningful for a port that is not trunking, so read_device_vlans must
# ignore both for ifIndex 2 and keep its standards-path answer instead: VLAN
# 30 untagged/native, from dot1qPvid and the Q-BRIDGE egress/untagged
# bitmaps, exactly as if this were an ordinary dot1q-only access port.
CISCO_MIXED_BASEPORT = {
    "1.3.6.1.2.1.17.1.4.1.2.1": ("int", 1),
    "1.3.6.1.2.1.17.1.4.1.2.2": ("int", 2),
}
CISCO_MIXED_DOT1Q_NAMES = {"1.3.6.1.2.1.17.7.1.4.3.1.1.30": ("str", "guest")}
CISCO_MIXED_DOT1Q_EGRESS = {
    # VLAN 30 on bridge port 2 only -> byte 0 bit 1 -> 0x40.
    "1.3.6.1.2.1.17.7.1.4.3.1.2.30": ("bytes", bytes([0x40])),
}
CISCO_MIXED_DOT1Q_UNTAGGED = {
    "1.3.6.1.2.1.17.7.1.4.3.1.4.30": ("bytes", bytes([0x40])),
}
CISCO_MIXED_DOT1Q_PVID = {"1.3.6.1.2.1.17.7.1.4.5.1.1.2": ("int", 30)}
CISCO_MIXED_VTP_NAMES = {
    "1.3.6.1.4.1.9.9.46.1.3.1.1.4.10": ("str", "data"),
    "1.3.6.1.4.1.9.9.46.1.3.1.1.4.20": ("str", "voice"),
}
CISCO_MIXED_TRUNK_STATUS = {
    "1.3.6.1.4.1.9.9.46.1.6.1.1.14.1": ("int", 1),   # ifIndex 1: trunking
    "1.3.6.1.4.1.9.9.46.1.6.1.1.14.2": ("int", 2),   # ifIndex 2: notTrunking
}
CISCO_MIXED_TRUNK_NATIVE = {
    "1.3.6.1.4.1.9.9.46.1.6.1.1.5.1": ("int", 10),   # ifIndex 1's real native VLAN
    # ifIndex 2 (access): IOS still answers this -- must be ignored in
    # favour of dot1qPvid's VLAN 30 above.
    "1.3.6.1.4.1.9.9.46.1.6.1.1.5.2": ("int", 1),
}
CISCO_MIXED_TRUNK_ENABLED = {
    # ifIndex 1 (trunk): VLANs 10 and 20 -> byte 1 bit 2 (0x20), byte 2 bit 4
    # (0x08).
    "1.3.6.1.4.1.9.9.46.1.6.1.1.4.1": ("bytes", bytes([0x00, 0x20, 0x08])),
    # ifIndex 2 (access): IOS still answers the configured allow-list here
    # too -- modelled as VLAN 1 (byte 0 bit 1 -> 0x40) standing in for the
    # real "allow every VLAN" default -- must be ignored.
    "1.3.6.1.4.1.9.9.46.1.6.1.1.4.2": ("bytes", bytes([0x40])),
}

MODE = "dot1q"


def table_for():
    if MODE == "dot1q":
        return {**GENERIC_SCALARS, **BASE_PORT_IFINDEX, **DOT1Q_NAMES,
                **DOT1Q_EGRESS, **DOT1Q_UNTAGGED, **DOT1Q_PVID}
    if MODE == "dot1q_no_baseport":
        return {**GENERIC_SCALARS, **DOT1Q_NO_BASEPORT}
    if MODE == "cisco_vtp":
        return {**CISCO_SCALARS, **VTP_NAMES, **VTP_TRUNK_STATUS,
                **VTP_TRUNK_NATIVE, **VTP_TRUNK_ENABLED}
    if MODE == "both":
        return {**CISCO_SCALARS, **BOTH_BASEPORT, **BOTH_DOT1Q_NAMES,
                **BOTH_DOT1Q_EGRESS, **BOTH_DOT1Q_UNTAGGED, **BOTH_DOT1Q_PVID,
                **BOTH_VTP_NAMES, **BOTH_TRUNK_STATUS, **BOTH_TRUNK_NATIVE,
                **BOTH_TRUNK_ENABLED}
    if MODE == "cisco_mixed":
        return {**CISCO_SCALARS, **CISCO_MIXED_BASEPORT,
                **CISCO_MIXED_DOT1Q_NAMES, **CISCO_MIXED_DOT1Q_EGRESS,
                **CISCO_MIXED_DOT1Q_UNTAGGED, **CISCO_MIXED_DOT1Q_PVID,
                **CISCO_MIXED_VTP_NAMES, **CISCO_MIXED_TRUNK_STATUS,
                **CISCO_MIXED_TRUNK_NATIVE, **CISCO_MIXED_TRUNK_ENABLED}
    if MODE == "no_vlan":
        return dict(GENERIC_SCALARS)
    if MODE == "baseport_only":
        return {**GENERIC_SCALARS, **BASE_PORT_IFINDEX}
    return dict(GENERIC_SCALARS)


def oid_key(oid):
    return tuple(int(a) for a in oid.split("."))


def encode_value(kind, value):
    if kind in ("str", "bytes"):
        return enc_octets(value)
    return enc_int(value)


def reply(request_id, body):
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets("public") + pdu)


def main():
    global MODE
    port = int(sys.argv[1])
    MODE = sys.argv[2] if len(sys.argv) > 2 else "dot1q"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"VLAN stub ({MODE}) listening on 127.0.0.1:{port}", flush=True)
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
