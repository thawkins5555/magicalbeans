"""A mode-selected v2c stub for UPS-MIB (RFC 1628) and the device-level
ENTITY-SENSOR-MIB read (RFC 3433) — the same "MODE global, table_for()
picks the OID dict" shape stub_agent_l2.py and stub_agent_fdb.py already
established, kept as its own script rather than a new mode grafted onto
stub_agent_l2.py so this suite cannot perturb any existing one's table.

    stub_agent_ups_env.py <port> <mode>

Modes:
  ups        Full standard UPS-MIB: battery status batteryLow(3), 45s on
             battery, 12 minutes estimated remaining, 63% charge, a 24.3 V
             battery (243 decivolts, so the /10 scale is exercised),
             31 C battery temperature, output source battery(5), 2 active
             alarms, a two-line upsInputTable (118 V, 121 V -- column_first
             takes 118) and a two-line upsOutputTable (55%, 72% --
             column_max takes 72). A generic (non-APC) sysObjectID, so the
             APC runtime fallback is never reached from this mode.
  no_ups     Generic scalars only, no UPS-MIB object at all: proves the two
             UPS table walks are never attempted when the scalar batch
             answered nothing.
  apc_ups    UPS-MIB scalars WITHOUT upsEstimatedMinutesRemaining (the
             standard scalar this app prefers is simply absent, the way a
             real APC agent's answer varies by firmware), an APC sysObjectID
             (enterprise arc 318) and upsAdvBatteryRunTimeRemaining served
             in TimeTicks -- the fallback path.
  sensors    ENTITY-SENSOR-MIB, four entities: one (#1) mapped to ifIndex 1
             through entAliasMappingIdentifier, a fractional-precision
             temperature (45.1 C) -- the read_dom()-reachable case; three
             (#2-#4) mapped to nothing, all invisible to read_dom() and all
             visible to the device-level scan: #2 a humidity reading with a
             NEGATIVE scale exponent (milli, scale=8), #3 a temperature
             marked nonoperational (status=3, must be excluded), #4 a
             plain-ok temperature hotter than #1 (must win the device's
             worst-of reading).

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
    "1.3.6.1.2.1.1.1.0": ("str", "ups/env stub device"),
    "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.99998.1"),
    "1.3.6.1.2.1.1.3.0": ("int", 654321),
    "1.3.6.1.2.1.1.5.0": ("str", "ups-env-stub"),
}
APC_SCALARS = {**GENERIC_SCALARS,
               "1.3.6.1.2.1.1.2.0": ("str", "1.3.6.1.4.1.318.1.1.1")}

# ----------------------------------------------------------------- UPS-MIB
UPS_TABLE = {
    "1.3.6.1.2.1.33.1.2.1.0": ("int", 3),          # upsBatteryStatus: batteryLow
    "1.3.6.1.2.1.33.1.2.2.0": ("int", 45),         # upsSecondsOnBattery
    "1.3.6.1.2.1.33.1.2.3.0": ("int", 12),         # upsEstimatedMinutesRemaining
    "1.3.6.1.2.1.33.1.2.4.0": ("int", 63),         # upsEstimatedChargeRemaining
    "1.3.6.1.2.1.33.1.2.5.0": ("int", 243),        # upsBatteryVoltage: 24.3 V
    "1.3.6.1.2.1.33.1.2.7.0": ("int", 31),         # upsBatteryTemperature
    "1.3.6.1.2.1.33.1.4.1.0": ("int", 5),          # upsOutputSource: battery
    "1.3.6.1.2.1.33.1.6.1.0": ("int", 2),          # upsAlarmsPresent
    "1.3.6.1.2.1.33.1.3.3.1.3.1": ("int", 118),    # upsInputVoltage, line 1
    "1.3.6.1.2.1.33.1.3.3.1.3.2": ("int", 121),    # upsInputVoltage, line 2
    "1.3.6.1.2.1.33.1.4.4.1.5.1": ("int", 55),     # upsOutputPercentLoad, line 1
    "1.3.6.1.2.1.33.1.4.4.1.5.2": ("int", 72),     # upsOutputPercentLoad, line 2
}
APC_UPS_TABLE = {k: v for k, v in UPS_TABLE.items()
                 if k != "1.3.6.1.2.1.33.1.2.3.0"}   # no upsEstimatedMinutesRemaining
APC_RUNTIME_TABLE = {
    "1.3.6.1.4.1.318.1.1.1.2.2.3.0": ("int", 900_000),   # TimeTicks: 9000 s = 150 min
}

# ---------------------------------------------------------- ENTITY-SENSOR
# entPhysicalDescr / entPhySensor{Type,Scale,Precision,Value,Status,Units},
# entity 1 mapped to ifIndex 1, entities 2-4 mapped to nothing.
SENSOR_TABLE = {
    "1.3.6.1.2.1.47.1.1.1.1.2.1": ("str", "Xcvr temp"),
    "1.3.6.1.2.1.47.1.1.1.1.2.2": ("str", "Chassis humidity"),
    "1.3.6.1.2.1.47.1.1.1.1.2.3": ("str", "Failed probe"),
    "1.3.6.1.2.1.47.1.1.1.1.2.4": ("str", "Hot spot"),

    "1.3.6.1.2.1.99.1.1.1.1.1": ("int", 8),    # #1 type: celsius
    "1.3.6.1.2.1.99.1.1.1.1.2": ("int", 9),    # #2 type: %RH
    "1.3.6.1.2.1.99.1.1.1.1.3": ("int", 8),    # #3 type: celsius
    "1.3.6.1.2.1.99.1.1.1.1.4": ("int", 8),    # #4 type: celsius

    "1.3.6.1.2.1.99.1.1.1.2.1": ("int", 9),    # #1 scale: units (10^0)
    "1.3.6.1.2.1.99.1.1.1.2.2": ("int", 8),    # #2 scale: milli (10^-3) -- negative exponent
    "1.3.6.1.2.1.99.1.1.1.2.3": ("int", 9),
    "1.3.6.1.2.1.99.1.1.1.2.4": ("int", 9),

    "1.3.6.1.2.1.99.1.1.1.3.1": ("int", 1),    # #1 precision: 1 decimal place
    "1.3.6.1.2.1.99.1.1.1.3.2": ("int", 0),
    "1.3.6.1.2.1.99.1.1.1.3.3": ("int", 0),
    "1.3.6.1.2.1.99.1.1.1.3.4": ("int", 0),

    "1.3.6.1.2.1.99.1.1.1.4.1": ("int", 451),    # #1 value: 451 * 10^0 / 10^1 = 45.1 C
    "1.3.6.1.2.1.99.1.1.1.4.2": ("int", 65000),  # #2 value: 65000 * 10^-3 / 10^0 = 65.0 %RH
    "1.3.6.1.2.1.99.1.1.1.4.3": ("int", 99),     # #3 value: would be 99 C if not excluded
    "1.3.6.1.2.1.99.1.1.1.4.4": ("int", 52),     # #4 value: 52 C -- the device's hottest OK reading

    "1.3.6.1.2.1.99.1.1.1.5.1": ("int", 1),    # #1 status: ok
    "1.3.6.1.2.1.99.1.1.1.5.2": ("int", 1),    # #2 status: ok
    "1.3.6.1.2.1.99.1.1.1.5.3": ("int", 3),    # #3 status: nonoperational
    "1.3.6.1.2.1.99.1.1.1.5.4": ("int", 1),    # #4 status: ok

    # entAliasMappingIdentifier: only entity 1 maps to an ifIndex.
    "1.3.6.1.2.1.47.1.3.2.1.2.1.1": ("str", "1.3.6.1.2.1.2.2.1.1.1"),
}

MODE = "ups"


def table_for():
    if MODE == "ups":
        return {**GENERIC_SCALARS, **UPS_TABLE}
    if MODE == "no_ups":
        return dict(GENERIC_SCALARS)
    if MODE == "apc_ups":
        return {**APC_SCALARS, **APC_UPS_TABLE, **APC_RUNTIME_TABLE}
    if MODE == "sensors":
        return {**GENERIC_SCALARS, **SENSOR_TABLE}
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
    MODE = sys.argv[2] if len(sys.argv) > 2 else "ups"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"UPS/env stub ({MODE}) listening on 127.0.0.1:{port}", flush=True)
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
