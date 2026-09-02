"""Answers the standard system-scalars GET normally, but silently drops
any GETNEXT for the ifIndex table — simulating a device that answers its
identity fine but then genuinely stops responding partway through
interface discovery. Used to confirm a real timeout is now reported as
snmp_error rather than silently treated as "zero interfaces"."""
import socket
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_GETBULK, PDU_GETNEXT, PDU_RESPONSE, T_NO_SUCH_OBJECT,
    T_SEQUENCE, V2C, _tlv, enc_int, enc_octets, enc_varbind,
)

COMMUNITY = "public"
IF_INDEX_BASE = "1.3.6.1.2.1.2.2.1.1"

SCALARS = {
    "1.3.6.1.2.1.1.1.0": "Timeout-test stub",
    "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.99999",
    "1.3.6.1.2.1.1.4.0": "",
    "1.3.6.1.2.1.1.5.0": "timeout-stub-device",
    "1.3.6.1.2.1.1.6.0": "",
}


def build_get_reply(request_id, requested_oids):
    body = b""
    for oid in requested_oids:
        if oid == "1.3.6.1.2.1.1.3.0":
            body += enc_varbind(oid, enc_int(999))
        elif oid in SCALARS:
            body += enc_varbind(oid, enc_octets(SCALARS[oid]))
        else:
            body += enc_varbind(oid, _tlv(T_NO_SUCH_OBJECT, b""))
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)


def main():
    port = int(sys.argv[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"partial-timeout stub agent listening on 127.0.0.1:{port}", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            request = decode_response(data)
        except Exception:
            continue
        if not request.varbinds:
            continue
        oids = [vb["oid"] for vb in request.varbinds]
        if request.pdu_tag == PDU_GET:
            sock.sendto(build_get_reply(request.request_id, oids), addr)
        elif request.pdu_tag in (PDU_GETNEXT, PDU_GETBULK) and oids[0].startswith(IF_INDEX_BASE):
            kind = "GETNEXT" if request.pdu_tag == PDU_GETNEXT else "GETBULK"
            print(f"dropping {kind} for {oids[0]} (simulated timeout)", flush=True)
            continue   # silently drop -- simulates the device going unresponsive
        elif request.pdu_tag in (PDU_GETNEXT, PDU_GETBULK):
            sock.sendto(build_get_reply(request.request_id, oids), addr)  # harmless fallback


if __name__ == "__main__":
    main()
