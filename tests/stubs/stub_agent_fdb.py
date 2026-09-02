"""v2c stub serving one of several forwarding-database shapes, so
read_mac_table()/read_device_mac_table()'s Q-BRIDGE / BRIDGE / Cisco-per-VLAN
paths, and nodepoll._walk_column's GETBULK walk, can each be exercised on
their own.

    stub_agent_fdb.py <port> dot1q|dot1d|cisco|cisco-strict|none|broken|big|bulk-toobig

`broken` serves two good GETNEXT rows and then echoes the request OID back —
the non-increasing answer a misbehaving agent gives, which loops a naive
walker until its cap.

`cisco` answers dot1dTpFdbPort ONLY inside a per-VLAN community context
(`public@10`), exactly as classic IOS does, and returns nothing at all for
the plain community — which is what makes the per-VLAN walk necessary.

`cisco-strict` goes further and hides dot1dBasePortIfIndex in those same
per-VLAN contexts, which is what the switches this path exists for actually
do: the global context answers no bridge table at all.

`big` serves ~90 dot1q FDB rows spread across 6 bridge ports — the size a
GETBULK walk's request count is worth measuring against a GETNEXT one.
`bulk-toobig` is the same table, but a GETBULK with more than 8
repetitions gets error_status=1 (tooBig) instead of an answer, exercising
_walk_column's halve-and-retry fallback.

Every GETBULK response honours `max_repetitions` (the request's own third
integer, decoded into `error_index` by the same code that decodes a real
GetBulk-PDU's error_index) by chaining the same lexicographic-successor
step GETNEXT uses, padding with endOfMibView once the table is exhausted —
the same shape a real agent's reply takes.

Two control datagrams, on the same socket as SNMP itself:
  STATS   -> the request count so far, as decimal text
  RESET   -> zeroes it
  HIDE <mac> -> stops serving that MAC's FDB row (any separator style, or
               none), so a second walk sees it gone — for the "a MAC left
               the port" history test. Bridge ports are unaffected.
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.nodesdb import normalize_mac
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_END_OF_MIB_VIEW,
    T_NO_SUCH_OBJECT, T_SEQUENCE, V2C, _tlv, enc_int, enc_octets, enc_varbind,
)

BASE = {
    "1.3.6.1.2.1.1.1.0": ("str", "FDB stub device"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.9.1.1208"),
    "1.3.6.1.2.1.1.3.0": ("int", 123456),
    "1.3.6.1.2.1.1.5.0": ("str", "fdb-stub"),
    # dot1dBasePortIfIndex: bridge port 5 -> ifIndex 1, port 7 -> ifIndex 2
    "1.3.6.1.2.1.17.1.4.1.2.5": ("int", 5),
    "1.3.6.1.2.1.17.1.4.1.2.7": ("int", 7),
}

# dot1qTpFdbPort, index <fdbId>.<6 MAC bytes>: VLAN 10 and VLAN 20 both
# learn the same MAC on port 5, which is legitimate and must not dedupe away.
DOT1Q = {
    "1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.17.34.51.68.85": ("int", 5),
    "1.3.6.1.2.1.17.7.1.2.2.1.2.20.0.17.34.51.68.85": ("int", 5),
    "1.3.6.1.2.1.17.7.1.2.2.1.2.10.170.187.204.221.238.255": ("int", 5),
    "1.3.6.1.2.1.17.7.1.2.2.1.2.10.0.18.52.86.120.154": ("int", 7),
}
DOT1D = {
    "1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85": ("int", 5),
    "1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255": ("int", 5),
    "1.3.6.1.2.1.17.4.3.1.2.0.18.52.86.120.154": ("int", 7),
}
# CISCO-VTP-MIB vtpVlanState: VLANs 10 and 30 operational, 1002 legacy.
VTP = {
    "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.10": ("int", 1),
    "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.30": ("int", 1),
    "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.1002": ("int", 1),
}
PER_VLAN = {
    "10": {"1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85": ("int", 5)},
    "30": {"1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255": ("int", 5)},
    # If the legacy VLANs were ever walked this would show up and fail the test.
    "1002": {"1.3.6.1.2.1.17.4.3.1.2.222.173.190.239.0.1": ("int", 5)},
}
# The bridge-port map, which cisco-strict serves only inside a VLAN context.
BRIDGE_PORTS = {k: v for k, v in BASE.items()
                if k.startswith("1.3.6.1.2.1.17.1.4.1.2.")}

# System scalars only — no dot1dBasePortIfIndex either, which is what makes
# this device genuinely "not a bridge" rather than "a bridge that has learned
# nothing on this port". read_mac_table must tell those two apart.
SCALARS_ONLY = {k: v for k, v in BASE.items() if k.startswith("1.3.6.1.2.1.1.")}


def _big_tables():
    """~90 dot1qTpFdbPort rows across 6 bridge ports, plus the matching
    dot1dBasePortIfIndex map — the shape "90-row FDB + 6 ports" refers to."""
    base = dict(SCALARS_ONLY)
    ports = {}
    fdb = {}
    for port in range(1, 7):
        ports[f"1.3.6.1.2.1.17.1.4.1.2.{port}"] = ("int", port)
        for row in range(15):
            # A distinct, deterministic MAC per (port, row): 6 bytes -> the
            # OID's own trailing 6 arcs (dot1dTpFdbTable's own index shape).
            octets = [0xAA, port, row, 0, 0, 1]
            suffix = ".".join(str(b) for b in octets)
            fdb[f"1.3.6.1.2.1.17.4.3.1.2.{suffix}"] = ("int", port)
    base.update(ports)
    return base, fdb


BIG_BASE, BIG_FDB = _big_tables()

MODE = "dot1q"
HIDDEN = set()   # normalised MACs (see HIDE) currently withheld from the FDB


def _mac_of_dot1d_oid(oid):
    """The MAC a dot1dTpFdbTable-shaped OID's trailing 6 arcs spell out,
    normalised the way nodesdb.normalize_mac stores it."""
    parts = oid.split(".")
    if len(parts) < 6:
        return ""
    try:
        return "".join(f"{int(p):02x}" for p in parts[-6:])
    except ValueError:
        return ""


# dot1qTpFdbTable's index is <fdbId>.<6 MAC bytes> and dot1dTpFdbTable's is
# the 6 MAC bytes alone, but either way the MAC is the trailing six arcs —
# so one prefix pair covers both tables' rows for the HIDE filter below.
_FDB_PREFIXES = ("1.3.6.1.2.1.17.4.3.1.2.", "1.3.6.1.2.1.17.7.1.2.2.1.2.")


def table_for(community):
    """The OIDs this community can see."""
    if MODE == "none":
        table = dict(SCALARS_ONLY)
    elif MODE == "broken":
        table = dict(SCALARS_ONLY)
    elif MODE in ("big", "bulk-toobig"):
        table = dict(BIG_BASE)
        table.update(BIG_FDB)
    else:
        table = dict(BASE)
        if MODE == "dot1q":
            table.update(DOT1Q)
        elif MODE == "dot1d":
            table.update(DOT1D)
        elif MODE == "cisco":
            table.update(VTP)
            if "@" in community:
                vlan = community.split("@", 1)[1]
                table.update(PER_VLAN.get(vlan, {}))
        elif MODE == "cisco-strict":
            for oid in BRIDGE_PORTS:
                table.pop(oid, None)
            table.update(VTP)
            if "@" in community:
                vlan = community.split("@", 1)[1]
                if vlan in PER_VLAN:
                    table.update(BRIDGE_PORTS)
                    table.update(PER_VLAN[vlan])
    if HIDDEN:
        # A HIDE datagram withholds a MAC's FDB row from every mode's
        # table alike — the "a MAC left the port" history test does not
        # care which forwarding-table shape it is run against.
        for oid in list(table):
            if oid.startswith(_FDB_PREFIXES) and _mac_of_dot1d_oid(oid) in HIDDEN:
                del table[oid]
    return table


def read_community(data: bytes) -> str:
    """snmppoll.decode_response skips the community, and the whole point of
    the Cisco path is that the community carries the VLAN — so pull it off
    the wire directly. v1/v2c framing is
    SEQUENCE { INTEGER version, OCTET STRING community, ... }."""
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


def oid_key(oid):
    return tuple(int(a) for a in oid.split("."))


def encode_value(kind, value):
    return enc_octets(value) if kind == "str" else enc_int(value)


def reply(request_id, body, community, error_status=0):
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(error_status) + enc_int(0) +
               _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(community) + pdu)


def _next(table, keys, asked):
    """One lexicographic-successor step — the walker's GETNEXT."""
    rk = oid_key(asked)
    nxt = next((k for k in keys if oid_key(k) > rk), None)
    return nxt


def main():
    global MODE
    port = int(sys.argv[1])
    MODE = sys.argv[2] if len(sys.argv) > 2 else "dot1q"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 0.0.0.0 so a test can give each device its own 127.0.0.x (devices.ip is
    # UNIQUE) and still reach this one stub.
    sock.bind(("0.0.0.0", port))
    print(f"FDB stub ({MODE}) listening on 127.0.0.1:{port}", flush=True)
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
        if data.startswith(b"HIDE "):
            mac = normalize_mac(data[5:].decode("utf-8", "replace"))
            if mac:
                HIDDEN.add(mac)
            sock.sendto(b"ok", addr)
            continue
        try:
            request = decode_response(data)
        except Exception:
            continue
        if not request.varbinds:
            continue
        count += 1
        try:
            community = read_community(data)
        except Exception:
            community = "public"
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
            if MODE == "broken":
                # A misbehaving agent: answers GETNEXT with the REQUESTED OID
                # after a couple of good rows, which loops a naive walker
                # forever. The two good rows prove the walk keeps what it got
                # before the fault.
                rk = oid_key(oids[0])
                good = [k for k in keys if oid_key(k) > rk]
                if len([k for k in keys if oid_key(k) <= rk]) >= 2 or not good:
                    body = enc_varbind(oids[0], enc_int(1))   # echoes the request
                else:
                    nxt = good[0]
                    body = enc_varbind(nxt, encode_value(*table[nxt]))
            else:
                nxt = _next(table, keys, oids[0])
                body = (enc_varbind(oids[0], _tlv(T_END_OF_MIB_VIEW, b""))
                        if nxt is None else enc_varbind(nxt, encode_value(*table[nxt])))
        elif request.pdu_tag == PDU_GETBULK:
            # non_repeaters lands in error_status, max_repetitions in
            # error_index — the same third/fourth integer slots a real
            # GetBulk-PDU carries them in (see snmppoll._pdu_bytes). Every
            # _walk_column call asks for exactly one column with nothing
            # non-repeated, so non_repeaters is not read here.
            max_repetitions = max(1, request.error_index or 1)
            if MODE == "bulk-toobig" and max_repetitions > 8:
                sock.sendto(reply(request.request_id, b"", community,
                                  error_status=1), addr)
                continue
            cursor = oids[0]
            body = b""
            for _ in range(max_repetitions):
                nxt = _next(table, keys, cursor)
                if nxt is None:
                    body += enc_varbind(cursor, _tlv(T_END_OF_MIB_VIEW, b""))
                    # Real agents keep padding with endOfMibView for the
                    # rest of the repetitions; one is enough here since the
                    # walker stops at the first end-of-table varbind.
                    break
                body += enc_varbind(nxt, encode_value(*table[nxt]))
                cursor = nxt
        else:
            continue
        sock.sendto(reply(request.request_id, body, community), addr)


if __name__ == "__main__":
    main()
