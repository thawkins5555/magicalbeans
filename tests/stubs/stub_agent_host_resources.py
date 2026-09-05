"""A mode-selected v2c stub for HOST-RESOURCES-MIB (RFC 2790): hrProcessorLoad
and hrStorageTable, the fallback nodepoll._poll_vendor_health reaches for once
neither a vendor arc nor UCD-SNMP-MIB has already produced cpu_pct/mem_pct —
same "MODE global, table_for() picks the OID dict" shape stub_agent_ups_env.py
and stub_agent_l2.py already established, kept as its own script so this
suite cannot perturb any existing one's table.

    stub_agent_host_resources.py <port> <mode>

Modes:
  windows    A generic Microsoft sysObjectID (enterprise arc 311 — real,
             VERIFIED in enterprises.py, and NOT one VENDOR_HEALTH has an
             entry for, so the generic fallback is what has to answer this
             device). No UCD-SNMP-MIB at all. hrProcessorLoad: two CPU rows
             (30%, 40% -- column_avg is 35.0). hrStorageTable: one RAM row
             (75% used), one hrStorageFixedDisk row (20% used), and one
             hrStorageVirtualMemory row at 95% used -- deliberately the
             WORST-looking row in the table, so a mem_pct that accidentally
             included it would be caught immediately rather than by luck.
  no_hr      Generic scalars only, no HOST-RESOURCES-MIB object at all:
             proves cpu_pct/disk_pct/mem_pct all stay absent rather than
             erroring when a device answers none of it.

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
    "1.3.6.1.2.1.1.1.0": ("str", "hr stub device"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.311.1.1.3.1.3"),  # Microsoft, arc 311
    "1.3.6.1.2.1.1.3.0": ("int", 246810),
    "1.3.6.1.2.1.1.5.0": ("str", "hr-stub"),
}

# hrProcessorLoad, two CPUs: (30 + 40) / 2 = 35.0
HR_PROCESSOR_TABLE = {
    "1.3.6.1.2.1.25.3.3.1.2.1": ("int", 30),
    "1.3.6.1.2.1.25.3.3.1.2.2": ("int", 40),
}

# hrStorageTable: type/size/used per row. Row 1 RAM (75% used), row 2 fixed
# disk (20% used), row 3 virtual memory (95% used -- must never be counted
# as either RAM or disk).
HR_STORAGE_TABLE = {
    "1.3.6.1.2.1.25.2.3.1.2.1": ("int", 2),          # type: hrStorageRam
    "1.3.6.1.2.1.25.2.3.1.2.2": ("int", 4),          # type: hrStorageFixedDisk
    "1.3.6.1.2.1.25.2.3.1.2.3": ("int", 3),          # type: hrStorageVirtualMemory
    "1.3.6.1.2.1.25.2.3.1.5.1": ("int", 1_000_000),  # RAM size
    "1.3.6.1.2.1.25.2.3.1.5.2": ("int", 500_000),    # disk size
    "1.3.6.1.2.1.25.2.3.1.5.3": ("int", 2_000_000),  # vmem size
    "1.3.6.1.2.1.25.2.3.1.6.1": ("int", 750_000),    # RAM used: 75%
    "1.3.6.1.2.1.25.2.3.1.6.2": ("int", 100_000),    # disk used: 20%
    "1.3.6.1.2.1.25.2.3.1.6.3": ("int", 1_900_000),  # vmem used: 95%
}

MODE = "windows"


def table_for():
    if MODE == "windows":
        return {**GENERIC_SCALARS, **HR_PROCESSOR_TABLE, **HR_STORAGE_TABLE}
    if MODE == "no_hr":
        return dict(GENERIC_SCALARS)
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
    MODE = sys.argv[2] if len(sys.argv) > 2 else "windows"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"HOST-RESOURCES stub ({MODE}) listening on 127.0.0.1:{port}", flush=True)
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
