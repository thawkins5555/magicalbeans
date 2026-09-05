"""A mode-selected v2c stub for the vendor-coverage sweep's two additions to
nodeoids.VENDOR_HEALTH: Cisco's CISCO-ENVMON-MIB temperature column and
Juniper's jnxOperatingBuffer memory column — same "MODE global, table_for()
picks the OID dict" shape every other stub in this directory uses, kept as
its own script so this suite cannot perturb test_poll_write_path.py's own
"cisco" fixture.

    stub_agent_vendor_health.py <port> <mode>

Modes:
  cisco    A Cisco sysObjectID (enterprise arc 9). cpmCPUTotal5minRev: two
           rows (30, 50) -- column_first takes 30. ciscoEnvMonTemperature-
           StatusValue: two rows (45, 52) -- column_max takes 52 (the
           metric this stub exists for: Cisco had zero temperature
           coverage before this sweep).
  juniper  A Juniper sysObjectID (enterprise arc 2636). jnxOperatingCPU:
           two rows (20, 40) -- column_first takes 20. jnxOperatingTemp:
           two rows (38, 44) -- column_max takes 44 (already covered
           before this sweep; here as a regression check). jnxOperating-
           Buffer: two rows (55, 70) -- column_max takes 70 (the metric
           this stub exists for: Juniper had no mem_pct before this
           sweep).

Two control datagrams, on the same socket as SNMP itself (see
stub_agent_fdb.py, which established this convention):
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
    "1.3.6.1.2.1.1.1.0": ("str", "vendor health stub"),
    "1.3.6.1.2.1.1.3.0": ("int", 13579),
    "1.3.6.1.2.1.1.5.0": ("str", "vh-stub"),
}
CISCO_SCALARS = {**GENERIC_SCALARS,
                 "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.9.1.1208")}
JUNIPER_SCALARS = {**GENERIC_SCALARS,
                   "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.2636.1.1.1.2.82")}

# cpmCPUTotal5minRev, two routing-engine-ish rows: column_first takes 30.
CISCO_CPU_TABLE = {
    "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": ("int", 30),
    "1.3.6.1.4.1.9.9.109.1.1.1.1.8.2": ("int", 50),
}
# ciscoEnvMonTemperatureStatusValue, two sensor rows: column_max takes 52.
CISCO_TEMP_TABLE = {
    "1.3.6.1.4.1.9.9.13.1.3.1.3.1": ("int", 45),
    "1.3.6.1.4.1.9.9.13.1.3.1.3.2": ("int", 52),
}

# jnxOperatingCPU, two rows: column_first takes 20.
JUNIPER_CPU_TABLE = {
    "1.3.6.1.4.1.2636.3.1.13.1.8.1": ("int", 20),
    "1.3.6.1.4.1.2636.3.1.13.1.8.2": ("int", 40),
}
# jnxOperatingTemp, two rows: column_max takes 44.
JUNIPER_TEMP_TABLE = {
    "1.3.6.1.4.1.2636.3.1.13.1.7.1": ("int", 38),
    "1.3.6.1.4.1.2636.3.1.13.1.7.2": ("int", 44),
}
# jnxOperatingBuffer, two rows: column_max takes 70.
JUNIPER_BUFFER_TABLE = {
    "1.3.6.1.4.1.2636.3.1.13.1.11.1": ("int", 55),
    "1.3.6.1.4.1.2636.3.1.13.1.11.2": ("int", 70),
}

MODE = "cisco"


def table_for():
    if MODE == "cisco":
        return {**CISCO_SCALARS, **CISCO_CPU_TABLE, **CISCO_TEMP_TABLE}
    if MODE == "juniper":
        return {**JUNIPER_SCALARS, **JUNIPER_CPU_TABLE, **JUNIPER_TEMP_TABLE,
                **JUNIPER_BUFFER_TABLE}
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
    MODE = sys.argv[2] if len(sys.argv) > 2 else "cisco"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"vendor-health stub ({MODE}) listening on 127.0.0.1:{port}", flush=True)
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
