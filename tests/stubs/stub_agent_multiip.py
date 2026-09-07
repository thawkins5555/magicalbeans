"""stub_agent_get_getnext.py plus an ipAddrTable: the same v2c GET/GETNEXT/
GETBULK agent, answering ipAdEntAddr for 127.0.0.1, 10.7.7.7 and 10.8.8.8
with the IpAddress TLV a real agent uses, plus the ifIndex and netmask
columns beside it.

This is what "one node per device" is tested against: a sweep that probes
two of these addresses reaches the same box twice, and the second row is
expected to fold into the first rather than be offered as a second device.
"""
import socket
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_END_OF_MIB_VIEW,
    T_IPADDRESS, T_NO_SUCH_OBJECT, T_SEQUENCE, V2C, _tlv, enc_int, enc_octets,
    enc_varbind,
)

COMMUNITY = "public"

ADDRESSES = ["127.0.0.1", "10.7.7.7", "10.8.8.8"]

OID_VALUES = {
    "1.3.6.1.2.1.1.1.0": ("str", "Multi-address stub router"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.99999"),
    "1.3.6.1.2.1.1.3.0": ("int", 123456),
    "1.3.6.1.2.1.1.4.0": ("str", ""),
    "1.3.6.1.2.1.1.5.0": ("str", "stub-multiip"),
    "1.3.6.1.2.1.1.6.0": ("str", ""),
}
for _i, _address in enumerate(ADDRESSES, start=1):
    OID_VALUES[f"1.3.6.1.2.1.4.20.1.1.{_address}"] = ("ip", _address)
    OID_VALUES[f"1.3.6.1.2.1.4.20.1.2.{_address}"] = ("int", _i)
    OID_VALUES[f"1.3.6.1.2.1.4.20.1.3.{_address}"] = ("ip", "255.255.255.0")


def oid_key(oid):
    return tuple(int(a) for a in oid.split("."))


def encode_value(kind, value):
    if kind == "ip":
        return _tlv(T_IPADDRESS, bytes(int(part) for part in value.split(".")))
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


def next_after(oid):
    candidates = sorted(OID_VALUES.keys(), key=oid_key)
    rk = oid_key(oid)
    return next((k for k in candidates if oid_key(k) > rk), None)


def build_getnext_reply(request_id, requested_oid):
    next_oid = next_after(requested_oid)
    if next_oid is None:
        body = enc_varbind(requested_oid, _tlv(T_END_OF_MIB_VIEW, b""))
    else:
        body = enc_varbind(next_oid, encode_value(*OID_VALUES[next_oid]))
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)


def build_getbulk_reply(request_id, requested_oid, max_repetitions):
    cursor = requested_oid
    body = b""
    for _ in range(max(1, max_repetitions)):
        next_oid = next_after(cursor)
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
    print(f"multi-address stub agent listening on 127.0.0.1:{port}", flush=True)
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
