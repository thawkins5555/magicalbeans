#!/usr/bin/env python3
"""Traffic generators for the SappiWhere demo: NetFlow, SNMP traps, syslog.

Everything here is both an importable API and a CLI.  Each sender binds its
socket to a *source* address (a 127.0.x.y loopback alias belonging to one
simulated device) before sending, because all three of the app's listeners
attribute what they receive to the packet's source IP and nothing else:

    netpath/collector.py:168   exporter = address[0]
    netpath/snmptrapd.py:195   source   = address[0]
    netpath/syslogd.py:208     source   = address[0]

So the only way to make one collector see forty devices is forty source
addresses.  On Linux the whole of 127.0.0.0/8 is local, so binding
127.0.3.7 needs no interface configuration at all.

Nothing is sent before it has been decoded in-process by the app's own
decoder and checked field by field - a generator that emits packets the app
silently drops is worse than no generator, because the demo then fails
somewhere else entirely.

CLI
---
    python3 demo/generators.py netflow --sources 127.0.1.1,127.0.1.2 \\
        --rate 20 --duration 30 --version mixed
    python3 demo/generators.py traps   --count 8 --rate 5 --duration 20 --mix storm
    python3 demo/generators.py syslog  --count 8 --rate 40 --duration 20 \\
        --tcp --framing octet
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import struct
import sys
import time
from typing import NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _path in (REPO, HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from netpath import nfdecode, syslogparse, trapdecode          # noqa: E402

NETFLOW_DEST = ("127.0.0.1", 2055)
TRAP_DEST = ("127.0.0.1", 162)
SYSLOG_DEST = ("127.0.0.1", 514)


# ---------------------------------------------------------------- plumbing

def _udp(source_ip: str) -> socket.socket:
    """A UDP socket bound to one simulated device's address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((source_ip, 0))
    return sock


def _tcp(source_ip: str, dest) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((source_ip, 0))
    sock.settimeout(5.0)
    sock.connect(tuple(dest))
    return sock


def _pace(rate_per_s: float, duration_s: float):
    """Yield 0, 1, 2, ... at `rate_per_s`, for `duration_s` seconds.

    Sleeps to the next scheduled instant rather than for a fixed interval, so
    the time spent building and verifying a packet does not accumulate into
    drift over a long run.
    """
    if rate_per_s <= 0 or duration_s <= 0:
        return
    interval = 1.0 / rate_per_s
    start = time.monotonic()
    index = 0
    while True:
        now = time.monotonic()
        if now - start >= duration_s:
            return
        target = start + index * interval
        if target > now:
            time.sleep(min(target - now, duration_s - (now - start)))
            if time.monotonic() - start >= duration_s:
                return
        yield index
        index += 1


def _ip_int(text: str) -> int:
    return struct.unpack("!I", socket.inet_aton(text))[0]


def fleet_sources(count: int) -> list[str]:
    """Source addresses for `count` simulated devices, from personas.py."""
    try:
        from personas import fleet_plan                        # noqa: PLC0415
    except ImportError as exc:                                 # pragma: no cover
        raise SystemExit(
            f"--count needs demo/personas.py (fleet_plan): {exc}. "
            "Pass --sources ip,ip,... instead.") from exc
    return [str(device["ip"]) for device in fleet_plan(count)]


# ============================================================== NetFlow ====

class Record(NamedTuple):
    """One flow, in the shape both the v5 and the v9 encoder need."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    tos: int
    tcp_flags: int
    in_if: int
    out_if: int
    src_as: int
    dst_as: int
    next_hop: str
    packets: int
    bytes: int
    first_ms: int
    last_ms: int


# label, server ip, port, protocol, tos, dst AS, byte range, packet range,
# tcp flags, weight.  Byte counts are per exported record, not per session:
# NetFlow exports a long-lived flow in chunks on the active timeout, which is
# also why the "backup" entry can total 10 GB across a run while every single
# record stays inside v5's 32-bit dOctets field.
SERVICES = [
    ("dns",     "10.20.0.53",    53, 17, 0x00, 64500, (78, 512),                (1, 4),        0x00, 26),
    ("https",   "203.0.113.10", 443,  6, 0x00, 15169, (1_400, 1_800_000),       (10, 1_400),   0x1B, 30),
    ("smb",     "10.20.0.20",   445,  6, 0x08, 64500, (8_000, 6_500_000),       (24, 5_000),   0x1B, 14),
    ("rdp",     "10.20.0.30",  3389,  6, 0x88, 64500, (3_000, 420_000),         (40, 1_200),   0x1B, 10),
    ("modbus",  "10.30.0.11",   502,  6, 0xB8, 64500, (240, 3_600),             (4, 42),       0x1B, 8),
    ("enip",    "10.30.0.12", 44818,  6, 0xB8, 64500, (300, 9_000),             (6, 90),       0x1B, 6),
    ("backup",  "10.20.0.40", 10000,  6, 0x00, 64500, (900_000_000, 1_400_000_000), (700_000, 1_100_000), 0x1B, 3),
    ("video",   "10.20.0.60",  5004, 17, 0xA0, 64500, (1_100_000, 1_500_000),   (900, 1_300),  0x00, 8),
]
_SERVICE_WEIGHTS = [entry[9] for entry in SERVICES]

CLIENT_AS = 64512
NEXT_HOPS = ["10.255.0.1", "10.254.0.1", "10.0.5.1"]


class ExporterState:
    """Per-exporter counters a real router would keep across packets."""

    def __init__(self, ip: str, index: int, boot_ago_s: float):
        self.ip = ip
        self.index = index
        self.site = index % 8 + 1
        self.domain = 100 + index               # v9 source_id / observation domain
        self.boot = time.time() - boot_ago_s
        self.flow_sequence = 0                  # v5: counts flows
        self.packet_sequence = 0                # v9: counts packets
        self.packets_since_template = 0
        self.last_template = 0.0

    def uptime_ms(self) -> int:
        return int((time.time() - self.boot) * 1000) & 0xFFFFFFFF


def make_records(state: ExporterState, rng: random.Random, count: int) -> list[Record]:
    """A handful of plausible conversations for one export packet."""
    records: list[Record] = []
    uptime = state.uptime_ms()
    for _ in range(count):
        service = rng.choices(SERVICES, weights=_SERVICE_WEIGHTS, k=1)[0]
        (_label, server_ip, server_port, protocol, tos, dst_as,
         byte_range, packet_range, flags, _weight) = service

        client = f"10.10.{state.site}.{rng.randint(10, 240)}"
        client_port = rng.randint(1024, 65535)
        in_if = rng.randint(1, 4)
        out_if = rng.choice([i for i in (1, 2, 3, 4) if i != in_if])
        packets = rng.randint(*packet_range)
        octets = rng.randint(*byte_range)
        # Keep every record inside v5's 32-bit dOctets/dPkts fields.
        octets = min(octets, 0xFFFFFFFF)
        packets = min(packets, 0xFFFFFFFF)

        duration_ms = rng.randint(20, 55_000)
        last = max(1, uptime - rng.randint(0, 4_000))
        first = max(1, last - duration_ms)
        next_hop = rng.choice(NEXT_HOPS)

        records.append(Record(
            src_ip=client, dst_ip=server_ip,
            src_port=client_port, dst_port=server_port,
            protocol=protocol, tos=tos, tcp_flags=flags,
            in_if=in_if, out_if=out_if,
            src_as=CLIENT_AS, dst_as=dst_as, next_hop=next_hop,
            packets=packets, bytes=octets,
            first_ms=first, last_ms=last))

        # The matching return flow: same conversation seen the other way, with
        # the interfaces swapped, which is what makes the app's per-interface
        # totals add up.
        if rng.random() < 0.55 and len(records) < count:
            back_packets = max(1, int(packets * rng.uniform(0.3, 1.2)))
            back_octets = max(64, int(octets * rng.uniform(0.05, 0.9)))
            records.append(Record(
                src_ip=server_ip, dst_ip=client,
                src_port=server_port, dst_port=client_port,
                protocol=protocol, tos=tos, tcp_flags=flags,
                in_if=out_if, out_if=in_if,
                src_as=dst_as, dst_as=CLIENT_AS, next_hop=next_hop,
                packets=min(back_packets, 0xFFFFFFFF),
                bytes=min(back_octets, 0xFFFFFFFF),
                first_ms=first, last_ms=last))
    return records[:count]


# ------------------------------------------------------------- v5 encoder

V5_SAMPLING = 1000
# Top two bits of the v5 header's sampling field are the mode; nfdecode.py:166
# masks them off with & 0x3FFF.  0b10 is "random 1 in N".
V5_SAMPLING_FIELD = 0x8000 | (V5_SAMPLING & 0x3FFF)


def build_v5(state: ExporterState, records: list[Record]) -> bytes:
    """A NetFlow v5 packet: 24-byte header + 48 bytes per record.

    The record layout is the one nfdecode._decode_v5 unpacks with
    "!IIIHHIIIIHHBBBBHHBBH" (nfdecode.py:176) - note three IPs, then the two
    ifIndexes, and only then the counters.
    """
    now = time.time()
    unix_secs = int(now)
    unix_nsecs = int((now - unix_secs) * 1e9)
    header = struct.pack(
        "!HHIIIIBBH", 5, len(records), state.uptime_ms(), unix_secs,
        unix_nsecs, state.flow_sequence, 0, state.index & 0xFF,
        V5_SAMPLING_FIELD)
    body = b"".join(
        struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            _ip_int(r.src_ip), _ip_int(r.dst_ip), _ip_int(r.next_hop),
            r.in_if, r.out_if, r.packets, r.bytes, r.first_ms, r.last_ms,
            r.src_port, r.dst_port, 0, r.tcp_flags, r.protocol, r.tos,
            r.src_as, r.dst_as, 24, 24, 0)
        for r in records)
    state.flow_sequence += len(records)
    return header + body


# ------------------------------------------------------------- v9 encoder

V9_TEMPLATE_ID = 256
V9_OPTIONS_TEMPLATE_ID = 258
V9_SAMPLING = 100

# (information element id, length).  Every id here is one nfdecode.py names at
# the top of the module, so every field survives the round trip into flowdb.
V9_FIELDS = [
    (nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4),
    (nfdecode.PROTOCOL, 1), (nfdecode.TOS, 1), (nfdecode.TCP_FLAGS, 1),
    (nfdecode.SRC_PORT, 2), (nfdecode.SRC_IPV4, 4), (nfdecode.IN_IF, 2),
    (nfdecode.DST_PORT, 2), (nfdecode.DST_IPV4, 4), (nfdecode.OUT_IF, 2),
    (nfdecode.NEXT_HOP_V4, 4), (nfdecode.SRC_AS, 2), (nfdecode.DST_AS, 2),
    (nfdecode.LAST_SWITCHED, 4), (nfdecode.FIRST_SWITCHED, 4),
]
V9_RECORD_LEN = sum(length for _, length in V9_FIELDS)
# One packer for the record, in exactly V9_FIELDS' order.  Asserted against the
# template's own length so a field added to one and not the other fails here
# rather than as an undecodable packet at the collector.
V9_RECORD = struct.Struct("!IIBBBHIHHIHIHHII")
assert V9_RECORD.size == V9_RECORD_LEN, "V9_RECORD does not match V9_FIELDS"

# v9 options templates carry a scope (what the option is about) and then the
# option fields.  nfdecode._read_options_template reads scope_len/option_len as
# byte counts and divides by 4 (nfdecode.py:282), so both must be multiples of
# four - a single 4-byte scope field and a single 4-byte option field here.
V9_SCOPE_SYSTEM = 1


def _pad4(body: bytes) -> bytes:
    return body + b"\x00" * (-len(body) % 4)


def _flowset(set_id: int, body: bytes) -> bytes:
    body = _pad4(body)
    return struct.pack("!HH", set_id, 4 + len(body)) + body


def build_v9_template_sets() -> bytes:
    data_template = struct.pack("!HH", V9_TEMPLATE_ID, len(V9_FIELDS))
    data_template += b"".join(struct.pack("!HH", fid, length)
                              for fid, length in V9_FIELDS)

    options_template = struct.pack("!HHH", V9_OPTIONS_TEMPLATE_ID, 4, 4)
    options_template += struct.pack("!HH", V9_SCOPE_SYSTEM, 4)
    options_template += struct.pack("!HH", nfdecode.SAMPLING_INTERVAL, 4)

    options_data = struct.pack("!II", 0, V9_SAMPLING)

    return (_flowset(0, data_template)
            + _flowset(1, options_template)
            + _flowset(V9_OPTIONS_TEMPLATE_ID, options_data))


def build_v9(state: ExporterState, records: list[Record],
             with_templates: bool) -> bytes:
    body = b""
    record_count = len(records)
    if with_templates:
        body += build_v9_template_sets()
        record_count += 3          # 2 templates + 1 options record
        state.packets_since_template = 0
        state.last_template = time.time()

    data = b"".join(
        V9_RECORD.pack(
            r.bytes, r.packets, r.protocol, r.tos, r.tcp_flags,
            r.src_port, _ip_int(r.src_ip), r.in_if,
            r.dst_port, _ip_int(r.dst_ip), r.out_if,
            _ip_int(r.next_hop), r.src_as, r.dst_as,
            r.last_ms, r.first_ms)
        for r in records)
    body += _flowset(V9_TEMPLATE_ID, data)

    state.packet_sequence += 1
    state.packets_since_template += 1
    header = struct.pack("!HHIIII", 9, record_count, state.uptime_ms(),
                         int(time.time()), state.packet_sequence, state.domain)
    return header + body


def v9_needs_templates(state: ExporterState) -> bool:
    """Cisco's default is every 20 packets and every 60 seconds, and the app
    shows "last template" as a first-class status line (collector.py:260), so
    both timers are worth honouring."""
    return (state.packets_since_template >= 20
            or time.time() - state.last_template >= 60.0)


# ------------------------------------------------------------ verification

def _verify_flows(decoder, packet: bytes, exporter: str,
                  records: list[Record], version: int) -> None:
    """Decode a packet with the app's own decoder and compare field by field."""
    flows = decoder.decode(packet, exporter)
    if len(flows) != len(records):
        raise AssertionError(
            f"v{version} packet from {exporter}: decoded {len(flows)} flows, "
            f"built {len(records)}")
    for flow, record in zip(flows, records):
        checks = {
            "src_ip": (flow.src_ip, record.src_ip),
            "dst_ip": (flow.dst_ip, record.dst_ip),
            "next_hop": (flow.next_hop, record.next_hop),
            "src_port": (flow.src_port, record.src_port),
            "dst_port": (flow.dst_port, record.dst_port),
            "protocol": (flow.protocol, record.protocol),
            "tos": (flow.tos, record.tos),
            "tcp_flags": (flow.tcp_flags, record.tcp_flags),
            "in_if": (flow.in_if, record.in_if),
            "out_if": (flow.out_if, record.out_if),
            "src_as": (flow.src_as, record.src_as),
            "dst_as": (flow.dst_as, record.dst_as),
            "packets": (flow.packets, record.packets),
            "bytes": (flow.bytes, record.bytes),
            "version": (flow.version, version),
        }
        for name, (got, want) in checks.items():
            if got != want:
                raise AssertionError(
                    f"v{version} {exporter}: {name} decoded as {got!r}, "
                    f"built {want!r}")
        if not flow.ts_start <= flow.ts_end:
            raise AssertionError(f"v{version} {exporter}: ts_start > ts_end")
        expected_sampling = V5_SAMPLING if version == 5 else V9_SAMPLING
        if flow.sampling != expected_sampling:
            raise AssertionError(
                f"v{version} {exporter}: sampling decoded as {flow.sampling}, "
                f"expected {expected_sampling}")


def selftest_netflow(seed: int = 1) -> dict:
    """Build one v5 and one v9 exchange and decode both, without any socket."""
    rng = random.Random(seed)
    decoder = nfdecode.Decoder()
    results = {}

    v5_state = ExporterState("127.0.9.5", 5, 3600)
    records = make_records(v5_state, rng, 6)
    _verify_flows(decoder, build_v5(v5_state, records), v5_state.ip, records, 5)
    results["v5_flows"] = len(records)

    v9_state = ExporterState("127.0.9.9", 9, 7200)
    records = make_records(v9_state, rng, 6)
    _verify_flows(decoder, build_v9(v9_state, records, True), v9_state.ip,
                  records, 9)
    # And again without templates, which is the steady state - it must decode
    # from the cached template rather than needing the template resent.
    records = make_records(v9_state, rng, 5)
    _verify_flows(decoder, build_v9(v9_state, records, False), v9_state.ip,
                  records, 9)
    results["v9_flows"] = 11
    results["templates"] = decoder.stats["templates"]
    results["no_template"] = decoder.stats["no_template"]
    results["errors"] = decoder.stats["errors"]
    if decoder.stats["errors"] or decoder.stats["no_template"]:
        raise AssertionError(f"netflow self-test: {decoder.stats}")
    return results


def send_netflow(exporters: list[str], rate_per_s: float, duration_s: float,
                 version=9, dest=NETFLOW_DEST, seed: int = 1) -> dict:
    """Send NetFlow from each of `exporters` at `rate_per_s` packets a second.

    `version` is 5, 9 or "mixed"; mixed assigns a version per exporter rather
    than alternating within one exporter, because a real router does not
    change export version between packets and the decoder caches templates per
    exporter.
    """
    if not exporters:
        raise ValueError("send_netflow needs at least one exporter address")
    version = 5 if str(version) == "5" else 9 if str(version) == "9" else "mixed"

    rng = random.Random(seed)
    states = {ip: ExporterState(ip, index, rng.uniform(3600, 400_000))
              for index, ip in enumerate(exporters)}
    versions = {}
    for index, ip in enumerate(exporters):
        versions[ip] = version if version != "mixed" else (5 if index % 2 else 9)

    verifier = nfdecode.Decoder()
    sockets = {ip: _udp(ip) for ip in exporters}
    summary = {"packets": 0, "flows": 0, "bytes": 0, "exporters": len(exporters),
               "v5": 0, "v9": 0, "templates": 0}
    try:
        for tick in _pace(rate_per_s, duration_s):
            exporter = exporters[tick % len(exporters)]
            state = states[exporter]
            records = make_records(state, rng, rng.randint(4, 14))
            if versions[exporter] == 5:
                packet = build_v5(state, records)
                summary["v5"] += 1
            else:
                with_templates = (state.last_template == 0.0
                                  or v9_needs_templates(state))
                packet = build_v9(state, records, with_templates)
                summary["v9"] += 1
                summary["templates"] += 1 if with_templates else 0
            _verify_flows(verifier, packet, exporter, records,
                          versions[exporter])
            sockets[exporter].sendto(packet, tuple(dest))
            summary["packets"] += 1
            summary["flows"] += len(records)
            summary["bytes"] += len(packet)
    finally:
        for sock in sockets.values():
            sock.close()
    return summary


# ============================================================= SNMP traps ==

COLD_START = "1.3.6.1.6.3.1.1.5.1"
LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
LINK_UP = "1.3.6.1.6.3.1.1.5.4"
AUTH_FAILURE = "1.3.6.1.6.3.1.1.5.5"
BGP_BACKWARD_TRANSITION = "1.3.6.1.2.1.15.7.2"
CISCO_ENTERPRISE = "1.3.6.1.4.1.9"
CBGP_FSM_STATE_CHANGE = "1.3.6.1.4.1.9.9.187.0.1"
CISCO_ENV_MON_TEMP = "1.3.6.1.4.1.9.9.13.3.0.2"

IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
# BGP4-MIB bgpPeerEntry.  bgpPeerState is .2 and bgpPeerRemoteAddr is .7 in
# the published MIB; netpath/trapoids.py:51 has .7 down as bgpPeerState, so
# these are sent at their real OIDs and the app's label for .7 is wrong.
BGP_PEER_STATE = "1.3.6.1.2.1.15.3.1.2"
BGP_PEER_REMOTE_ADDR = "1.3.6.1.2.1.15.3.1.7"
BGP_PEER_LAST_ERROR = "1.3.6.1.2.1.15.3.1.14"
ENT_PHYSICAL_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"

PORT_NAMES = ["GigabitEthernet0/{}", "GigabitEthernet1/0/{}", "Te1/1/{}",
              "port{}", "eth1/{}"]


def _if_varbinds(if_index: int, descr: str, oper: int, admin: int = 1):
    """The four varbinds every real linkDown/linkUp carries, plus ifAlias."""
    return [
        (f"{IF_INDEX}.{if_index}", trapdecode.enc_int(if_index)),
        (f"{IF_DESCR}.{if_index}", trapdecode.enc_octets(descr)),
        (f"{IF_ADMIN_STATUS}.{if_index}", trapdecode.enc_int(admin)),
        (f"{IF_OPER_STATUS}.{if_index}", trapdecode.enc_int(oper)),
        (f"{IF_ALIAS}.{if_index}", trapdecode.enc_octets(f"uplink {descr}")),
    ]


def build_inform(community: str, trap_oid: str, uptime_ticks: int,
                 varbinds=None, request_id: int = 1) -> bytes:
    """An SNMPv2c InformRequest.

    trapdecode has no builder for one (build_v2c_trap emits PDU_TRAP_V2), but
    an inform is the identical PDU body under tag PDU_INFORM - see
    trapdecode._decode_v1_v2c, which routes both to _read_trap_v2.  Sending one
    exercises snmptrapd._acknowledge, the only path on which the receiver ever
    transmits.
    """
    body = trapdecode.enc_varbind(
        trapdecode.SYS_UPTIME_0,
        trapdecode.enc_unsigned(trapdecode.T_TIMETICKS, uptime_ticks))
    body += trapdecode.enc_varbind(trapdecode.SNMP_TRAP_OID_0,
                                   trapdecode.enc_oid(trap_oid))
    for oid, value in (varbinds or []):
        body += trapdecode.enc_varbind(oid, value)
    pdu = trapdecode._tlv(
        trapdecode.PDU_INFORM,
        trapdecode.enc_int(request_id) + trapdecode.enc_int(0)
        + trapdecode.enc_int(0) + trapdecode._tlv(trapdecode.T_SEQUENCE, body))
    return trapdecode._tlv(
        trapdecode.T_SEQUENCE,
        trapdecode.enc_int(trapdecode.V2C)
        + trapdecode.enc_octets(community) + pdu)


class TrapPlan(NamedTuple):
    packet: bytes
    expect_oid: str
    expect_kind: str
    label: str


def _trap_catalogue(rng: random.Random, source: str, community: str,
                    uptime: int, request_id: int, storm: bool) -> list[TrapPlan]:
    """One "beat" of traps: a list built fresh each time so the varbinds move.

    In storm mode a beat is a burst of linkDown/linkUp transitions on a single
    interface, which is what alertrules.evaluate_flapping counts; in normal
    mode a beat is a spread of the trap kinds a mixed estate actually emits.
    """
    plans: list[TrapPlan] = []
    if_index = rng.randint(1, 48)
    descr = rng.choice(PORT_NAMES).format(if_index)

    def v2c(trap_oid, varbinds, kind, label):
        packet = trapdecode.build_v2c_trap(community, trap_oid, uptime,
                                           varbinds, request_id)
        return TrapPlan(packet, trap_oid, kind, label)

    roll = rng.random()
    if storm:
        for _ in range(rng.randint(2, 4)):
            plans.append(v2c(LINK_DOWN, _if_varbinds(if_index, descr, oper=2),
                             "linkDown", f"linkDown {descr}"))
            plans.append(v2c(LINK_UP, _if_varbinds(if_index, descr, oper=1),
                             "linkUp", f"linkUp {descr}"))
    elif roll < 0.42:
        plans.append(v2c(LINK_DOWN, _if_varbinds(if_index, descr, oper=2),
                         "linkDown", f"linkDown {descr}"))
        plans.append(v2c(LINK_UP, _if_varbinds(if_index, descr, oper=1),
                         "linkUp", f"linkUp {descr}"))
    elif roll < 0.55:
        plans.append(v2c(COLD_START, [], "coldStart", "coldStart"))
    elif roll < 0.68:
        plans.append(v2c(AUTH_FAILURE, [
            ("1.3.6.1.6.3.18.1.3.0", trapdecode._tlv(
                trapdecode.T_IPADDRESS,
                socket.inet_aton(f"198.51.100.{rng.randint(2, 250)}"))),
            ("1.3.6.1.6.3.18.1.4.0", trapdecode.enc_octets("private")),
        ], "authenticationFailure", "authenticationFailure"))
    elif roll < 0.82:
        peer = f"198.51.100.{rng.randint(2, 250)}"
        plans.append(v2c(BGP_BACKWARD_TRANSITION, [
            (f"{BGP_PEER_REMOTE_ADDR}.{peer}",
             trapdecode._tlv(trapdecode.T_IPADDRESS, socket.inet_aton(peer))),
            (f"{BGP_PEER_STATE}.{peer}", trapdecode.enc_int(rng.choice([1, 2, 3]))),
            (f"{BGP_PEER_LAST_ERROR}.{peer}", trapdecode.enc_octets(b"\x06\x04")),
        ], "bgpBackwardTransition", "bgpBackwardTransition"))
    elif roll < 0.93:
        peer = f"198.51.100.{rng.randint(2, 250)}"
        plans.append(v2c(CBGP_FSM_STATE_CHANGE, [
            (f"{BGP_PEER_REMOTE_ADDR}.{peer}",
             trapdecode._tlv(trapdecode.T_IPADDRESS, socket.inet_aton(peer))),
            (f"{BGP_PEER_STATE}.{peer}", trapdecode.enc_int(2)),
        ], "enterpriseSpecific", "cbgpFsmStateChange"))
    else:
        # An OID under a known vendor root but not in the name table, so the
        # decoder's longest-prefix fallback shows "cisco.9.13.3.0.2".
        plans.append(v2c(CISCO_ENV_MON_TEMP, [
            (f"{ENT_PHYSICAL_NAME}.1", trapdecode.enc_octets("Chassis Temp Sensor")),
            ("1.3.6.1.4.1.9.9.13.1.3.1.3.1", trapdecode.enc_int(rng.randint(58, 74))),
            ("1.3.6.1.4.1.9.9.13.1.3.1.6.1", trapdecode.enc_int(3)),
        ], "enterpriseSpecific", "ciscoEnvMonTempStatusChange"))

    # Roughly one v1 trap per five v2c ones: plenty of field gear still only
    # speaks v1, and RFC 3584 mapping (trapdecode.py:496) is worth showing.
    if rng.random() < 0.2:
        specific = rng.choice([1, 3, 7])
        packet = trapdecode.build_v1_trap(
            community, CISCO_ENTERPRISE, source, generic=6, specific=specific,
            uptime_ticks=uptime,
            varbinds=_if_varbinds(if_index, descr, oper=2))
        plans.append(TrapPlan(packet, f"{CISCO_ENTERPRISE}.0.{specific}",
                              "enterpriseSpecific", f"v1 enterprise .{specific}"))
    return plans


def _verify_trap(decoder, packet: bytes, source: str, plan: TrapPlan):
    trap = decoder.decode(packet, source)
    if trap is None:
        raise AssertionError(f"{plan.label}: trapdecode returned None")
    if trap.trap_oid != plan.expect_oid:
        raise AssertionError(
            f"{plan.label}: trap_oid decoded as {trap.trap_oid!r}, "
            f"built {plan.expect_oid!r}")
    if trap.trap_kind != plan.expect_kind:
        raise AssertionError(
            f"{plan.label}: trap_kind decoded as {trap.trap_kind!r}, "
            f"expected {plan.expect_kind!r}")
    if trap.source != source:
        raise AssertionError(f"{plan.label}: source {trap.source!r}")
    return trap


def selftest_traps(seed: int = 1) -> dict:
    rng = random.Random(seed)
    decoder = trapdecode.Decoder()
    checked = 0
    kinds = set()
    for beat in range(60):
        for plan in _trap_catalogue(rng, "127.0.9.1", "public", 100 * beat,
                                    beat + 1, storm=bool(beat % 7 == 0)):
            _verify_trap(decoder, plan.packet, "127.0.9.1", plan)
            kinds.add(plan.expect_kind)
            checked += 1
    inform = build_inform("public", LINK_DOWN, 4242,
                          _if_varbinds(3, "GigabitEthernet0/3", oper=2), 99)
    trap = decoder.decode(inform, "127.0.9.1")
    if trap is None or not trap.is_inform or trap.request_id != 99:
        raise AssertionError(f"inform did not decode as an inform: {trap}")
    if not trap.varbinds_tlv_span:
        raise AssertionError("inform has no varbinds_tlv_span, so snmptrapd "
                             "cannot acknowledge it")
    return {"checked": checked + 1, "kinds": sorted(kinds),
            "errors": decoder.stats["errors"]}


def send_inform(source: str, dest=TRAP_DEST, community: str = "public",
                trap_oid: str = LINK_DOWN, request_id: int = 4242,
                timeout_s: float = 2.0) -> bool:
    """Send one v2c inform and wait for the receiver's Response-PDU.

    Returns True if an acknowledgement came back, which is the only way to
    tell from outside that snmptrapd._acknowledge ran.
    """
    packet = build_inform(community, trap_oid, int(time.time() * 100) & 0x7FFFFFFF,
                          _if_varbinds(7, "GigabitEthernet0/7", oper=2),
                          request_id)
    decoder = trapdecode.Decoder()
    trap = decoder.decode(packet, source)
    if trap is None or not trap.is_inform:
        raise AssertionError("inform failed its own decode check")
    sock = _udp(source)
    try:
        sock.settimeout(timeout_s)
        sock.sendto(packet, tuple(dest))
        try:
            reply, _ = sock.recvfrom(65535)
        except (socket.timeout, OSError):
            return False
        return bool(reply) and reply[0] == trapdecode.T_SEQUENCE
    finally:
        sock.close()


def send_traps(sources: list[str], rate_per_s: float, duration_s: float,
               dest=TRAP_DEST, community: str = "public",
               mix: str = "normal", seed: int = 1) -> dict:
    """Send SNMP traps from each of `sources` at roughly `rate_per_s`.

    Each beat can produce several traps (a linkDown/linkUp pair, a storm
    burst), so the rate is beats per second and `packets` is what actually
    went out.
    """
    if not sources:
        raise ValueError("send_traps needs at least one source address")
    storm = str(mix).lower() == "storm"
    rng = random.Random(seed)
    decoder = trapdecode.Decoder()
    sockets = {ip: _udp(ip) for ip in sources}
    summary = {"packets": 0, "beats": 0, "sources": len(sources),
               "v1": 0, "v2c": 0, "informs": 0, "informs_acked": 0,
               "mix": "storm" if storm else "normal"}
    try:
        for tick in _pace(rate_per_s, duration_s):
            source = sources[tick % len(sources)]
            uptime = int((time.time() % 86400) * 100)
            for plan in _trap_catalogue(rng, source, community, uptime,
                                        tick + 1, storm):
                trap = _verify_trap(decoder, plan.packet, source, plan)
                sockets[source].sendto(plan.packet, tuple(dest))
                summary["packets"] += 1
                summary["v1" if trap.version == trapdecode.V1 else "v2c"] += 1
            summary["beats"] += 1
    finally:
        for sock in sockets.values():
            sock.close()

    # One inform at the end, from the first source, to exercise the ack path.
    summary["informs"] = 1
    summary["informs_acked"] = int(send_inform(sources[0], dest, community))
    summary["packets"] += 1
    return summary


# ================================================================ syslog ===

def _pri(facility: int, severity: int) -> int:
    return facility * 8 + severity


class LogTemplate(NamedTuple):
    weight: int
    shape: str          # "3164" or "5424"
    facility: int
    severity: int
    app: str            # "" when the vendor's line carries no parsable tag
    procid: str
    msgid: str
    text: str           # {n} placeholders filled from the rng
    expect_app: str     # what syslogparse.parse should come back with


# Modelled on what the gear actually puts on the wire.  `expect_app` records
# what netpath/syslogparse.py can get out of each shape - several vendors send
# a line with no RFC 3164 tag at all, and the parser correctly degrades to
# "whole line is the message", which the demo should show rather than hide.
LOG_TEMPLATES = [
    LogTemplate(14, "3164", 23, 3, "%LINK-3-UPDOWN", "", "",
                "Interface GigabitEthernet0/{n}, changed state to down",
                "%LINK-3-UPDOWN"),
    LogTemplate(14, "3164", 23, 5, "%LINEPROTO-5-UPDOWN", "", "",
                "Line protocol on Interface GigabitEthernet0/{n}, "
                "changed state to up", "%LINEPROTO-5-UPDOWN"),
    LogTemplate(8, "3164", 23, 5, "%SYS-5-CONFIG_I", "", "",
                "Configured from console by admin on vty{n} (10.10.4.{n})",
                "%SYS-5-CONFIG_I"),
    LogTemplate(10, "3164", 23, 6, "%SEC-6-IPACCESSLOGP", "", "",
                "list INBOUND-FILTER denied tcp 198.51.100.{n}(4{n}12) -> "
                "10.20.0.20(445), 1 packet", "%SEC-6-IPACCESSLOGP"),
    LogTemplate(6, "3164", 20, 4, "rpd", "1{n}84", "",
                "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 198.51.100.{n} "
                "(External AS 64512) changed state from Established to Idle "
                "(event RecvNotify)", "rpd"),
    LogTemplate(5, "3164", 20, 5, "mgd", "27{n}1", "",
                "UI_COMMIT: User 'netops' requested 'commit' operation "
                "(comment: change CR-90{n})", "mgd"),
    # FortiGate writes bare key=value with no tag; the RFC 3164 tag regex
    # (syslogparse.py:65) needs a colon before the first space and there is
    # none, so app stays empty and the whole line becomes the message.
    LogTemplate(8, "3164", 16, 4, "", "", "",
                "date=2026-09-02 time=10:1{n}:00 devname=\"fgt-edge-0{n}\" "
                "devid=\"FG100ETK1900{n}\" logid=\"0101037129\" type=\"event\" "
                "subtype=\"vpn\" level=\"warning\" vd=\"root\" "
                "logdesc=\"IPsec phase 2 status changed\" "
                "action=\"tunnel-down\" remip=203.0.113.{n} "
                "tunnelid=1{n} tunneltype=\"ipsec\" status=\"down\"", ""),
    # Palo Alto's classic CSV, also tagless.
    LogTemplate(5, "3164", 16, 5, "", "", "",
                "1,2026/09/02 10:1{n}:00,001801037{n},THREAT,vulnerability,"
                "2049,2026/09/02 10:1{n}:00,10.10.3.{n},203.0.113.{n},"
                "0.0.0.0,0.0.0.0,allow-outbound,,,web-browsing,vsys1,trust,"
                "untrust,ae1.10,ae2.20,log-forwarding,reset-both", ""),
    LogTemplate(6, "5424", 16, 4, "PAN-OS", "47{n}1", "THREAT",
                "url filtering blocked 10.10.3.{n} -> "
                "malware.example (category command-and-control)", "PAN-OS"),
    LogTemplate(5, "5424", 4, 5, "sshd", "8{n}12", "AUTHPRIV",
                "Accepted publickey for netops from 10.10.1.{n} port 5{n}22 "
                "ssh2", "sshd"),
    LogTemplate(6, "3164", 16, 3, "EDS", "0", "",
                "Port {n} link down (Moxa EDS-408A, redundant ring recovering)",
                "EDS"),
    LogTemplate(5, "3164", 16, 4, "S7-1500", "1", "",
                "CPU diagnostic buffer entry 0x45{n}2: module fault on rack 0 "
                "slot {n}", "S7-1500"),
    # --- severity 0-2: these are the ones the built-in syslog_critical rule
    # (alertsdb.py:241, severity 2) actually fires on - alertengine.py:1116
    # keeps a syslog occurrence only when its severity is <= the rule's.
    LogTemplate(2, "3164", 16, 2, "S7-1500", "1", "",
                "CPU changed to STOP mode: unrecoverable diagnostic fault, "
                "safety interlock on line {n} released", "S7-1500"),
    LogTemplate(2, "3164", 0, 1, "upsd", "4{n}2", "",
                "UPS ups-0{n}@localhost on battery, estimated runtime "
                "{n} minutes", "upsd"),
    LogTemplate(1, "3164", 23, 0, "%ENVM-0-SHUTDOWN", "", "",
                "Shutting down system now: chassis temperature "
                "1{n}5C exceeds critical threshold", "%ENVM-0-SHUTDOWN"),
    LogTemplate(2, "5424", 16, 2, "fnsysctl", "1{n}", "HACHK",
                "HA heartbeat lost on both links, cluster split brain "
                "detected on member {n}", "fnsysctl"),
]
_LOG_WEIGHTS = [t.weight for t in LOG_TEMPLATES]

HOST_ROLES = ["core-sw-0{}", "dist-sw-0{}", "acc-sw-0{}", "fgt-edge-0{}",
              "mx-edge-0{}", "plc-line{}", "moxa-eds-0{}", "pa-fw-0{}"]

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _hostname(rng: random.Random, source: str) -> str:
    digit = int(source.rsplit(".", 1)[-1]) % 9 + 1
    return rng.choice(HOST_ROLES).format(digit)


def build_log_line(rng: random.Random, source: str,
                   template: LogTemplate | None = None,
                   now: float | None = None) -> tuple[str, LogTemplate, str]:
    """Return (line, template, hostname) for one message."""
    template = template or rng.choices(LOG_TEMPLATES, weights=_LOG_WEIGHTS, k=1)[0]
    now = now or time.time()
    host = _hostname(rng, source)
    number = rng.randint(1, 9)
    text = template.text.replace("{n}", str(number))
    pri = _pri(template.facility, template.severity)

    if template.shape == "5424":
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
        stamp += f".{int((now % 1) * 1_000_000):06d}Z"
        procid = template.procid.replace("{n}", str(number)) or "-"
        line = (f"<{pri}>1 {stamp} {host} {template.app or '-'} {procid} "
                f"{template.msgid or '-'} - {text}")
        return line, template, host

    local = time.localtime(now)
    stamp = (f"{_MONTHS[local.tm_mon - 1]} {local.tm_mday:2d} "
             f"{local.tm_hour:02d}:{local.tm_min:02d}:{local.tm_sec:02d}")
    tag = ""
    if template.app:
        procid = template.procid.replace("{n}", str(number))
        tag = f"{template.app}[{procid}]: " if procid else f"{template.app}: "
    line = f"<{pri}>{stamp} {host} {tag}{text}"
    return line, template, host


def _verify_line(line: str, template: LogTemplate, host: str,
                 source: str) -> None:
    entry = syslogparse.parse(line.encode("utf-8"), source)
    if entry.severity != template.severity:
        raise AssertionError(
            f"severity parsed as {entry.severity}, built {template.severity}: "
            f"{line[:90]}")
    if entry.facility != template.facility:
        raise AssertionError(
            f"facility parsed as {entry.facility}, built {template.facility}: "
            f"{line[:90]}")
    if entry.app != template.expect_app:
        raise AssertionError(
            f"app parsed as {entry.app!r}, expected {template.expect_app!r}: "
            f"{line[:90]}")
    if template.expect_app and entry.host != host:
        raise AssertionError(
            f"host parsed as {entry.host!r}, built {host!r}: {line[:90]}")
    if not entry.message:
        raise AssertionError(f"empty message from: {line[:90]}")


def selftest_syslog(seed: int = 1) -> dict:
    rng = random.Random(seed)
    checked = 0
    severities = set()
    for template in LOG_TEMPLATES:
        for _ in range(12):
            line, used, host = build_log_line(rng, "127.0.9.1", template)
            _verify_line(line, used, host, "127.0.9.1")
            severities.add(used.severity)
            checked += 1
    return {"checked": checked, "templates": len(LOG_TEMPLATES),
            "severities": sorted(severities),
            "critical_or_worse": sorted(s for s in severities if s <= 2)}


def _frame(line: str, framing: str) -> bytes:
    raw = line.encode("utf-8")
    if framing == "octet":
        # RFC 6587 octet counting, which syslogd._read_stream:237 recognises by
        # a leading run of digits followed by a space.
        return str(len(raw)).encode("ascii") + b" " + raw
    return raw + b"\n"


def send_syslog(sources: list[str], rate_per_s: float, duration_s: float,
                dest=SYSLOG_DEST, tcp: bool = False,
                framing: str = "newline", seed: int = 1) -> dict:
    """Send syslog from each of `sources` at `rate_per_s` messages a second.

    With tcp=True one connection per source is held open for the whole run and
    every message goes down it, which is the case the app's stream reassembler
    exists for.  framing="octet" uses RFC 6587 octet counting; "both"
    alternates the two framings on the one connection, which is legal and does
    happen when a relay rewrites some messages and not others.
    """
    if not sources:
        raise ValueError("send_syslog needs at least one source address")
    rng = random.Random(seed)
    summary = {"messages": 0, "sources": len(sources), "bytes": 0,
               "transport": "tcp" if tcp else "udp", "framing": framing,
               "by_severity": {}}

    conns: dict[str, socket.socket] = {}
    try:
        for source in sources:
            conns[source] = _tcp(source, dest) if tcp else _udp(source)

        for tick in _pace(rate_per_s, duration_s):
            source = sources[tick % len(sources)]
            line, template, host = build_log_line(rng, source)
            _verify_line(line, template, host, source)
            if tcp:
                shape = framing
                if framing == "both":
                    shape = "octet" if tick % 2 else "newline"
                payload = _frame(line, shape)
                conns[source].sendall(payload)
            else:
                payload = line.encode("utf-8")
                conns[source].sendto(payload, tuple(dest))
            summary["messages"] += 1
            summary["bytes"] += len(payload)
            key = syslogparse.SEVERITIES[template.severity]
            summary["by_severity"][key] = summary["by_severity"].get(key, 0) + 1
    finally:
        for sock in conns.values():
            try:
                sock.close()
            except OSError:
                pass
    return summary


# =================================================================== CLI ===

def _parse_dest(text: str, default) -> tuple[str, int]:
    if not text:
        return default
    host, _, port = text.partition(":")
    return (host or default[0], int(port) if port else default[1])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="demo/generators.py",
        description="Send NetFlow, SNMP traps or syslog to a local SappiWhere.")
    parser.add_argument("what", choices=["netflow", "traps", "syslog",
                                         "selftest"])
    parser.add_argument("--sources", default="",
                        help="comma-separated source IPs (127.0.x.y)")
    parser.add_argument("--count", type=int, default=0,
                        help="use the first N devices of personas.fleet_plan()")
    parser.add_argument("--rate", type=float, default=10.0,
                        help="packets (netflow/syslog) or beats (traps) per second")
    parser.add_argument("--duration", type=float, default=10.0, help="seconds")
    parser.add_argument("--dest", default="",
                        help="host[:port]; defaults to 127.0.0.1 and the "
                             "listener's own port")
    parser.add_argument("--version", default="9", choices=["5", "9", "mixed"],
                        help="netflow export version")
    parser.add_argument("--tcp", action="store_true", help="syslog over TCP")
    parser.add_argument("--framing", default="newline",
                        choices=["newline", "octet", "both"],
                        help="syslog TCP framing")
    parser.add_argument("--mix", default="normal", choices=["normal", "storm"],
                        help="trap mix")
    parser.add_argument("--community", default="public")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)

    if args.what == "selftest":
        print("netflow:", selftest_netflow(args.seed))
        print("traps:  ", selftest_traps(args.seed))
        print("syslog: ", selftest_syslog(args.seed))
        return 0

    if args.sources:
        sources = [item.strip() for item in args.sources.split(",") if item.strip()]
    elif args.count:
        sources = fleet_sources(args.count)
    else:
        sources = ["127.0.1.1"]

    started = time.time()
    if args.what == "netflow":
        dest = _parse_dest(args.dest, NETFLOW_DEST)
        result = send_netflow(sources, args.rate, args.duration,
                              args.version, dest, args.seed)
        print(f"netflow: {result['packets']} packets "
              f"({result['flows']} flows, {result['v5']} v5 / {result['v9']} v9, "
              f"{result['templates']} with templates, {result['bytes']} bytes) "
              f"from {result['exporters']} exporters to {dest[0]}:{dest[1]} "
              f"in {time.time() - started:.1f}s")
    elif args.what == "traps":
        dest = _parse_dest(args.dest, TRAP_DEST)
        result = send_traps(sources, args.rate, args.duration, dest,
                            args.community, args.mix, args.seed)
        print(f"traps: {result['packets']} packets "
              f"({result['v1']} v1 / {result['v2c']} v2c, {result['beats']} beats, "
              f"mix={result['mix']}, informs acked "
              f"{result['informs_acked']}/{result['informs']}) "
              f"from {result['sources']} sources to {dest[0]}:{dest[1]} "
              f"in {time.time() - started:.1f}s")
    else:
        dest = _parse_dest(args.dest, SYSLOG_DEST)
        result = send_syslog(sources, args.rate, args.duration, dest,
                             args.tcp, args.framing, args.seed)
        worst = ", ".join(f"{k}={v}" for k, v in sorted(result["by_severity"].items()))
        print(f"syslog: {result['messages']} messages ({result['bytes']} bytes) "
              f"over {result['transport']}/{result['framing']} "
              f"from {result['sources']} sources to {dest[0]}:{dest[1]} "
              f"in {time.time() - started:.1f}s [{worst}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
