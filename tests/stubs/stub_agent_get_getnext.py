"""A generic v2c SNMP stub agent handling both GET and GETNEXT, serving a
fixed OID->value dict. Used to verify custom-MIB polling end to end: it
answers the standard system-scalars GET (so the base poll succeeds), lets
the ifIndex GETNEXT walk terminate immediately (nothing in-subtree), and
serves one or two custom-MIB scalar instance OIDs."""
import socket
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_END_OF_MIB_VIEW,
    T_NO_SUCH_OBJECT, T_SEQUENCE, V2C, _tlv, enc_int, enc_octets, enc_varbind,
)

COMMUNITY = "public"

OID_VALUES = {
    "1.3.6.1.2.1.1.1.0": ("str", "Test stub device"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.99999"),
    "1.3.6.1.2.1.1.3.0": ("int", 123456),
    "1.3.6.1.2.1.1.4.0": ("str", ""),
    "1.3.6.1.2.1.1.5.0": ("str", "stub-custom-mib-device"),
    "1.3.6.1.2.1.1.6.0": ("str", ""),
    # The custom MIB's scalar instance (testScalar ::= { testEnterprise 1 },
    # testEnterprise ::= { enterprises 99999 } -> 1.3.6.1.4.1.99999.1, GET
    # with the .0 instance suffix nodepoll.py's _poll_custom_mib appends).
    "1.3.6.1.4.1.99999.1.0": ("int", 42),
}


def oid_key(oid):
    return tuple(int(a) for a in oid.split("."))


def encode_value(kind, value):
    return enc_octets(value) if kind == "str" else enc_int(value)


def build_get_reply(request_id, requested_oids):
    body = b""
    for oid in requested_oids:
        entry = OID_VALUES.get(oid)
        if entry is None:
            body += enc_varbind(oid, _tlv(T_NO_SUCH_OBJECT, b""))
        else:
            body += enc_varbind(oid, encode_value(*entry))
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)


def build_getnext_reply(request_id, requested_oid):
    candidates = sorted(OID_VALUES.keys(), key=oid_key)
    rk = oid_key(requested_oid)
    next_oid = next((k for k in candidates if oid_key(k) > rk), None)
    if next_oid is None:
        body = enc_varbind(requested_oid, _tlv(T_END_OF_MIB_VIEW, b""))
    else:
        body = enc_varbind(next_oid, encode_value(*OID_VALUES[next_oid]))
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)


def build_getbulk_reply(request_id, requested_oid, max_repetitions):
    """Chains the same lexicographic-successor step build_getnext_reply
    uses, once per repetition, padding with endOfMibView once the table is
    exhausted — a GetBulk reply is exactly a repeated GetNext."""
    candidates = sorted(OID_VALUES.keys(), key=oid_key)
    cursor = requested_oid
    body = b""
    for _ in range(max(1, max_repetitions)):
        rk = oid_key(cursor)
        next_oid = next((k for k in candidates if oid_key(k) > rk), None)
        if next_oid is None:
            body += enc_varbind(cursor, _tlv(T_END_OF_MIB_VIEW, b""))
            break
        body += enc_varbind(next_oid, encode_value(*OID_VALUES[next_oid]))
        cursor = next_oid
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)


def main():
    port = int(sys.argv[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"GET/GETNEXT stub agent listening on 127.0.0.1:{port}", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            request = decode_response(data)
        except Exception as exc:
            print(f"decode failed: {exc}", flush=True)
            continue
        if not request.varbinds:
            continue
        oids = [vb["oid"] for vb in request.varbinds]
        if request.pdu_tag == PDU_GET:
            reply = build_get_reply(request.request_id, oids)
        elif request.pdu_tag == PDU_GETNEXT:
            reply = build_getnext_reply(request.request_id, oids[0])
        elif request.pdu_tag == PDU_GETBULK:
            reply = build_getbulk_reply(request.request_id, oids[0],
                                        request.error_index or 1)
        else:
            continue
        sock.sendto(reply, addr)


if __name__ == "__main__":
    main()
