"""A v2c SNMP stub agent that refuses a GET carrying more than `--max-varbinds`
varbinds with error-status tooBig(1) and an EMPTY varbind list -- RFC 3416's
own answer, and the one most agents give a request for several hundred
objects. Serves TEST-MIB's 100 scalars (1.3.6.1.4.1.99999.N.0 = N) so a
caller can prove a whole MIB is read in batches the agent will take.

    stub_agent_toobig.py <port> [max_varbinds]
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath.snmppoll import decode_response
from netpath.trapdecode import (
    PDU_GET, PDU_RESPONSE, T_NO_SUCH_OBJECT, T_SEQUENCE, V2C, _tlv, enc_int,
    enc_octets, enc_varbind,
)

COMMUNITY = "public"
SCALARS = 100
OID_VALUES = {f"1.3.6.1.4.1.99999.{n}.0": n for n in range(1, SCALARS + 1)}


def build_reply(request_id, oids, max_varbinds):
    if len(oids) > max_varbinds:
        pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(1) + enc_int(0) +
                   _tlv(T_SEQUENCE, b""))
        return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)
    body = b""
    for oid in oids:
        value = OID_VALUES.get(oid)
        body += enc_varbind(oid, _tlv(T_NO_SUCH_OBJECT, b"")
                            if value is None else enc_int(value))
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
               _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)


def main():
    port = int(sys.argv[1])
    max_varbinds = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"tooBig stub agent (cap {max_varbinds}) listening on "
          f"127.0.0.1:{port}", flush=True)
    biggest = 0
    while True:
        data, addr = sock.recvfrom(65535)
        if data == b"BIGGEST":
            sock.sendto(str(biggest).encode(), addr)
            continue
        try:
            request = decode_response(data)
        except Exception as exc:
            print(f"decode failed: {exc}", flush=True)
            continue
        if request.pdu_tag != PDU_GET or not request.varbinds:
            continue
        oids = [vb["oid"] for vb in request.varbinds]
        biggest = max(biggest, len(oids))
        sock.sendto(build_reply(request.request_id, oids, max_varbinds), addr)


if __name__ == "__main__":
    main()
