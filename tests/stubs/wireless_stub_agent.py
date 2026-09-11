"""A minimal UDP SNMP stub agent serving a synthetic fgWc AP table
(fgWcWtpConfigTable / fgWcWtpSessionTable / fgWcWtpSessionRadioTable /
fgWcWtpProfileRadioTable) for testing WirelessPoller's GETNEXT table-walking
end to end, without a real FortiGate Wireless Controller. Only implements what
the poller actually uses: v2c GETNEXT over exactly the fgWc OIDs in
nodeoids.py.

An optional second argument names a mutation file, re-read before every reply,
which lets a suite change what the controller reports between two polls:

    AP0001.uptime=41000          session column 8 (WTP boot uptime, ticks)
    AP0001.session_uptime=900    session column 10
    AP0001.2.channel=149         radio 2's operating channel
    AP0001.1.mode=4              radio 1's FgWcWtpRadioMode
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))  # the repo root, from tests/stubs/
from netpath import nodeoids as oids  # noqa: E402
from netpath.snmppoll import decode_response  # noqa: E402
from netpath.trapdecode import (  # noqa: E402
    PDU_RESPONSE, T_END_OF_MIB_VIEW, T_SEQUENCE, V2C, _tlv, enc_int,
    enc_octets, enc_oid, enc_varbind,
)

COMMUNITY = "public"


def wtp_suffix(vdom: str, wtp_id: str) -> str:
    chars = ".".join(str(ord(c)) for c in wtp_id)
    return f"{vdom}.{len(wtp_id)}.{chars}"


def aps():
    """Two synthetic APs, one online with two radios, one offline."""
    return [
        {"vdom": "1", "wtp_id": "AP0001", "name": "Lobby-AP", "mac": bytes.fromhex("00119300aabb"),
         "state": 2, "model": "FAP231F", "clients": 14,
         # 127.0.0.1 rather than a routable-looking address so the poller's
         # per-AP ping sweep answers at once instead of waiting out a timeout.
         "ip": bytes([127, 0, 0, 1]),
         "uptime": 1_234_500, "session_uptime": 120_000, "profile": "FAP231F-default",
         "radios": [{"id": 1, "channel": 6, "power": 17, "clients": 9, "mode": 3,
                     "bssid": bytes.fromhex("00119300aac0"), "width": 1},
                    {"id": 2, "channel": 44, "power": 14, "clients": 5, "mode": 3,
                     "bssid": bytes.fromhex("00119300aac1"), "width": 3}]},
        {"vdom": "1", "wtp_id": "AP0002", "name": "Warehouse-AP", "mac": bytes.fromhex("00119300ccdd"),
         "state": 1, "model": "FAP231F", "clients": 0,
         "ip": bytes([10, 20, 30, 42]),
         # Its own profile, so the channel-width join has two profiles to tell
         # apart rather than one row every AP happens to land on.
         "uptime": 5_000_000, "session_uptime": 4_900_000, "profile": "FAP231F-monitor",
         "radios": [{"id": 1, "channel": 11, "power": 20, "clients": 0, "mode": 4,
                     "bssid": bytes.fromhex("00119300ccf0"), "width": 2}],
        },
    ]


def apply_overrides(table, overrides: dict) -> None:
    """`AP0001.uptime=…` on an AP, `AP0001.2.channel=…` on one of its radios."""
    by_wtp = {ap["wtp_id"]: ap for ap in table}
    for key, value in overrides.items():
        parts = key.split(".")
        ap = by_wtp.get(parts[0])
        if ap is None:
            continue
        if len(parts) == 2:
            ap[parts[1]] = int(value)
        elif len(parts) == 3:
            for radio in ap["radios"]:
                if str(radio["id"]) == parts[1]:
                    radio[parts[2]] = int(value)


def read_overrides(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {}
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


def build_table(overrides: dict | None = None):
    table_aps = aps()
    apply_overrides(table_aps, overrides or {})

    table: dict[str, bytes] = {}
    profiles: dict[tuple[str, str], dict] = {}
    for ap in table_aps:
        suffix = wtp_suffix(ap["vdom"], ap["wtp_id"])
        table[f"{oids.WTP_CONFIG_NAME}.{suffix}"] = enc_octets(ap["name"])
        table[f"{oids.WTP_SESSION_IP}.{suffix}"] = enc_octets(ap["ip"])
        table[f"{oids.WTP_SESSION_MAC}.{suffix}"] = enc_octets(ap["mac"])
        table[f"{oids.WTP_SESSION_CONNECTION_STATE}.{suffix}"] = enc_int(ap["state"])
        # TimeTicks on the wire; encoded as a plain INTEGER here because the
        # poller reads the number, not the tag.
        table[f"{oids.WTP_SESSION_UPTIME}.{suffix}"] = enc_int(ap["uptime"])
        table[f"{oids.WTP_SESSION_SESSION_UPTIME}.{suffix}"] = enc_int(ap["session_uptime"])
        table[f"{oids.WTP_SESSION_PROFILE}.{suffix}"] = enc_octets(ap["profile"])
        table[f"{oids.WTP_SESSION_MODEL}.{suffix}"] = enc_octets(ap["model"])
        table[f"{oids.WTP_SESSION_STATION_COUNT}.{suffix}"] = enc_int(ap["clients"])
        for radio in ap["radios"]:
            rsuffix = f"{suffix}.{radio['id']}"
            table[f"{oids.WTP_RADIO_MODE}.{rsuffix}"] = enc_int(radio["mode"])
            table[f"{oids.WTP_RADIO_BSSID}.{rsuffix}"] = enc_octets(radio["bssid"])
            # A channel of -1 means "this radio answers no channel at all",
            # which is what a disabled radio does and what the poller stores
            # as NULL; there is no such reading on the wire.
            if radio["channel"] >= 0:
                table[f"{oids.WTP_RADIO_CHANNEL}.{rsuffix}"] = enc_int(radio["channel"])
            table[f"{oids.WTP_RADIO_OPERATING_POWER}.{rsuffix}"] = enc_int(radio["power"])
            table[f"{oids.WTP_RADIO_STATION_COUNT}.{rsuffix}"] = enc_int(radio["clients"])
            profiles[(ap["vdom"], ap["profile"], radio["id"])] = radio
    # fgWcWtpProfileRadioTable is indexed by (vdom, profileName, radioId), so
    # it carries one row per profile radio however many APs share the profile.
    for (vdom, profile, radio_id), radio in profiles.items():
        psuffix = f"{wtp_suffix(vdom, profile)}.{radio_id}"
        table[f"{oids.WTP_PROFILE_RADIO_CHANNEL_WIDTH}.{psuffix}"] = enc_int(radio["width"])
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
    state_path = sys.argv[2] if len(sys.argv) > 2 else None
    overrides = read_overrides(state_path)
    table = build_table(overrides)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"wireless stub agent listening on 127.0.0.1:{port} "
         f"({len(table)} OIDs)", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        fresh = read_overrides(state_path)
        if fresh != overrides:
            overrides = fresh
            table = build_table(overrides)
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
