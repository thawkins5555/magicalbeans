"""A minimal UDP SNMP stub agent serving a synthetic fgWc AP table
(fgWcWtpConfigTable / fgWcWtpSessionTable / fgWcWtpSessionRadioTable) for
testing WirelessPoller's GETNEXT table-walking end to end, without a real
FortiGate Wireless Controller. Only implements what the poller actually
uses: v2c GETNEXT over exactly the OIDs in fortinetoids.py."""
import socket
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath import fortinetoids as oids  # noqa: E402
from netpath.snmppoll import decode_response  # noqa: E402
from netpath.trapdecode import (  # noqa: E402
    PDU_RESPONSE, T_END_OF_MIB_VIEW, T_SEQUENCE, V2C, _tlv, enc_int,
    enc_octets, enc_oid, enc_varbind,
)

COMMUNITY = "public"


def wtp_suffix(vdom: str, wtp_id: str) -> str:
    chars = ".".join(str(ord(c)) for c in wtp_id)
    return f"{vdom}.{len(wtp_id)}.{chars}"


def build_table():
    """Two synthetic APs, one online with two radios, one offline."""
    aps = [
        {"vdom": "1", "wtp_id": "AP0001", "name": "Lobby-AP", "mac": bytes.fromhex("00119300aabb"),
         "state": 2, "model": "FAP231F", "clients": 14,
         "radios": [{"id": 1, "channel": 6, "power": 17, "clients": 9},
                    {"id": 2, "channel": 44, "power": 14, "clients": 5}]},
        {"vdom": "1", "wtp_id": "AP0002", "name": "Warehouse-AP", "mac": bytes.fromhex("00119300ccdd"),
         "state": 1, "model": "FAP231F", "clients": 0,
         "radios": [{"id": 1, "channel": 11, "power": 20, "clients": 0}]},
    ]

    table: dict[str, bytes] = {}
    for ap in aps:
        suffix = wtp_suffix(ap["vdom"], ap["wtp_id"])
        table[f"{oids.WTP_CONFIG_NAME}.{suffix}"] = enc_octets(ap["name"])
        table[f"{oids.WTP_SESSION_MAC}.{suffix}"] = enc_octets(ap["mac"])
        table[f"{oids.WTP_SESSION_CONNECTION_STATE}.{suffix}"] = enc_int(ap["state"])
        table[f"{oids.WTP_SESSION_MODEL}.{suffix}"] = enc_octets(ap["model"])
        table[f"{oids.WTP_SESSION_STATION_COUNT}.{suffix}"] = enc_int(ap["clients"])
        for radio in ap["radios"]:
            rsuffix = f"{suffix}.{radio['id']}"
            table[f"{oids.WTP_RADIO_CHANNEL}.{rsuffix}"] = enc_int(radio["channel"])
            table[f"{oids.WTP_RADIO_OPERATING_POWER}.{rsuffix}"] = enc_int(radio["power"])
            table[f"{oids.WTP_RADIO_STATION_COUNT}.{rsuffix}"] = enc_int(radio["clients"])
    return table


def oid_key(oid: str):
    return tuple(int(a) for a in oid.split("."))


def next_oid(table, requested):
    keys = sorted(table.keys(), key=oid_key)
    rk = oid_key(requested)
    for k in keys:
        if oid_key(k) > rk:
            return k
    return None


def build_reply(request_id, oid, value_bytes):
    body = enc_varbind(oid, value_bytes) if value_bytes is not None else \
        enc_varbind(oid, _tlv(T_END_OF_MIB_VIEW, b""))
    pdu = _tlv(PDU_RESPONSE, enc_int(request_id) + enc_int(0) + enc_int(0) +
              _tlv(T_SEQUENCE, body))
    return _tlv(T_SEQUENCE, enc_int(V2C) + enc_octets(COMMUNITY) + pdu)


def main():
    port = int(sys.argv[1])
    table = build_table()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"wireless stub agent listening on 127.0.0.1:{port} "
         f"({len(table)} OIDs)", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            request = decode_response(data)
        except Exception as exc:
            print(f"decode failed: {exc}", flush=True)
            continue
        if not request.varbinds:
            continue
        requested = request.varbinds[0]["oid"]
        nxt = next_oid(table, requested)
        reply_oid = nxt or requested
        value = table.get(nxt) if nxt else None
        sock.sendto(build_reply(request.request_id, reply_oid, value), addr)


if __name__ == "__main__":
    main()
