#!/usr/bin/env python3
"""A multi-exporter NetFlow v5/v9 and IPFIX traffic simulator.

Standard library only. Exporter 1 speaks NetFlow v5, exporters 2 and 3
NetFlow v9 (exporter 3 also announces 1:100 sampling through a v9 options
template, resent like a real router does), exporter 4 IPFIX; further
exporters repeat that four-way cycle. Each exporter binds its sender socket
to its own loopback address (127.0.0.2, 127.0.0.3, ... - the scheme
demo/personas.py's fleet devices use, index 0 == 127.0.0.2) so demo/seed.py's
Nodes devices can name them, and falls back to the default outbound address
with a warning if the bind fails.

Every exporter has 4-6 interfaces (a WAN uplink, a LAN, a DMZ and a mostly-
idle port, sometimes a couple more), traffic runs between about 40 internal
hosts on two /24s and a dozen external addresses on common application
ports (443, 80, 53, 2055, 161, 3268, 5007, 22, 445 and one unregistered
port), one exporter runs about 10x busier than the rest, and volume follows
a diurnal curve: quiet 01:00-06:00, peak in the mid-afternoon.

    python3 demo/flows.py [--host 127.0.0.1] [--port 2055] [--exporters 4]
                          [--days 3] [--burst] [--live] [--rate 60]
                          [--flows N] [--seed 1] [--quiet]

--burst sends `--days` of history oldest first (arrival order matches time
order, since the collector's row cap deletes by arrival order), paced under
the collector's 20,000-datagram queue at roughly 400 datagrams/s; the
default (3 days, 4 exporters) sends about 301,000 flow records (300,990 with
the default seed). --live then
carries on (or runs alone) at --rate records/s until Ctrl-C, resending
v9/IPFIX templates every 60 s. --flows caps the total records sent across
both phases.

One line "sending to host:port from N exporters" prints at start; a summary
of records, datagrams and per-exporter totals prints at exit.
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netpath.nfdecode import (                              # noqa: E402
    DST_AS, DST_IPV4, DST_PORT, FIRST_SWITCHED, FLOW_END_SECONDS,
    FLOW_START_SECONDS, IN_IF, IPFIX, LAST_SWITCHED, OCTETS, OUT_IF,
    PACKETS, PROTOCOL, SAMPLING_INTERVAL, SRC_AS, SRC_IPV4, SRC_PORT, TOS,
    V5, V9,
)

VERSION_CYCLE = (V5, V9, V9, IPFIX)
HAS_OPTIONS_POS = 2                  # the third exporter of every group of 4

INTERNAL_SUBNETS = ("10.20.1.", "10.20.2.")
INTERNAL_HOSTS = [f"{net}{n}" for net in INTERNAL_SUBNETS for n in range(10, 30)]
EXTERNAL_HOSTS = [f"203.0.113.{n}" for n in range(1, 13)]

APP_PORTS = (443, 80, 53, 2055, 161, 3268, 5007, 22, 445, 40012)
APP_PROTOCOL = {443: 6, 80: 6, 53: 17, 2055: 17, 161: 17, 3268: 6, 5007: 6,
                22: 6, 445: 6, 40012: 17}

BUSY_INDEX = 0
# quiet 01:00-06:00, peak in the mid-afternoon.
HOURLY_WEIGHT = (0.30, 0.22, 0.18, 0.15, 0.15, 0.18, 0.30, 0.55, 0.75, 0.85,
                 0.92, 0.97, 1.00, 0.98, 1.00, 0.97, 0.90, 0.80, 0.68, 0.58,
                 0.52, 0.46, 0.40, 0.35)
BASE_RECORDS_PER_HOUR = 545
BUSY_MULTIPLIER = 10.0

V5_BATCH = 30
V9_BATCH = 20
IPFIX_BATCH = 20
REFRESH_EVERY_PACKETS = 200          # "like a real router" template resend
LIVE_TEMPLATE_REFRESH_S = 60.0

V9_TEMPLATE_ID = 256
V9_OPTIONS_TEMPLATE_ID = 257
IPFIX_TEMPLATE_ID = 256
SAMPLING_SCOPE_FIELD = 130           # exporterIPv4Address, a harmless scope
SAMPLING_RATE = 100

V9_FIELDS = [(SRC_IPV4, 4), (DST_IPV4, 4), (SRC_PORT, 2), (DST_PORT, 2),
             (PROTOCOL, 1), (TOS, 1), (IN_IF, 2), (OUT_IF, 2), (OCTETS, 4),
             (PACKETS, 4), (FIRST_SWITCHED, 4), (LAST_SWITCHED, 4),
             (SRC_AS, 2), (DST_AS, 2)]
IPFIX_FIELDS = [(SRC_IPV4, 4), (DST_IPV4, 4), (SRC_PORT, 2), (DST_PORT, 2),
                (PROTOCOL, 1), (TOS, 1), (IN_IF, 2), (OUT_IF, 2),
                (OCTETS, 4), (PACKETS, 4), (FLOW_START_SECONDS, 4),
                (FLOW_END_SECONDS, 4), (SRC_AS, 2), (DST_AS, 2)]


# ---------------------------------------------------------------- exporters

def exporter_address(index: int) -> str:
    """127.0.0.2, 127.0.0.3, ... one per exporter, index 0 == 127.0.0.2 -
    the same scheme demo/personas.py:ip_for() uses for fleet devices."""
    return "127.0.0.%d" % (index + 2)


@dataclass
class ExporterConfig:
    index: int
    address: str
    version: int
    has_options: bool
    busy: bool
    boot: float                       # this exporter's simulated boot time
    interfaces: list
    paths: list = field(default_factory=list)   # (in_if, out_if, weight)


def _build_paths(rng: random.Random, ifaces: list) -> list:
    """Weighted (in_if, out_if) pairs covering every interface as both an
    in_if and an out_if. Weights are jittered per exporter so each one's
    in/out mix is its own, not a copy of the others."""
    wan, lan = ifaces[0], ifaces[1]
    dmz = ifaces[2] if len(ifaces) > 2 else lan
    idle = ifaces[3] if len(ifaces) > 3 else wan
    base = [(lan, wan, 40.0), (wan, lan, 38.0), (lan, dmz, 12.0),
            (dmz, lan, 11.0), (dmz, wan, 5.0), (wan, dmz, 4.0),
            (idle, idle, 1.0)]
    for extra in ifaces[4:]:
        base.append((lan, extra, 3.0))
        base.append((extra, lan, 3.0))
    return [(a, b, max(1.0, w * rng.uniform(0.7, 1.3))) for a, b, w in base]


def build_exporters(count: int, seed: int, boot_reference: float) -> list:
    """`count` deterministic exporter configurations. `boot_reference` is the
    simulated start of the whole run (v5/v9 timestamps are boot + an uptime
    offset; every exporter's own boot sits before it, far enough back to
    cover the burst window)."""
    exporters = []
    for index in range(max(1, count)):
        rng = random.Random(seed * 97 + index)
        version = VERSION_CYCLE[index % len(VERSION_CYCLE)]
        has_options = version == V9 and index % len(VERSION_CYCLE) == HAS_OPTIONS_POS
        n_ifaces = rng.randint(4, 6)
        ifaces = list(range(1, n_ifaces + 1))
        boot = boot_reference - rng.uniform(0, 3600)
        exporters.append(ExporterConfig(
            index=index, address=exporter_address(index), version=version,
            has_options=has_options, busy=(index == BUSY_INDEX), boot=boot,
            interfaces=ifaces, paths=_build_paths(rng, ifaces)))
    return exporters


def _weighted_choice(rng: random.Random, items: list):
    total = sum(item[-1] for item in items)
    pick = rng.uniform(0, total)
    upto = 0.0
    for item in items:
        upto += item[-1]
        if pick <= upto:
            return item
    return items[-1]


def _make_flow(exp: ExporterConfig, rng: random.Random, ts_end: float) -> dict:
    in_if, out_if, _weight = _weighted_choice(rng, exp.paths)
    wan = exp.interfaces[0]
    if out_if == wan and in_if != wan:
        src, dst = rng.choice(INTERNAL_HOSTS), rng.choice(EXTERNAL_HOSTS)
    elif in_if == wan and out_if != wan:
        src, dst = rng.choice(EXTERNAL_HOSTS), rng.choice(INTERNAL_HOSTS)
    else:
        src, dst = rng.sample(INTERNAL_HOSTS, 2)
    port = rng.choice(APP_PORTS)
    protocol = APP_PROTOCOL[port]
    packets = rng.randint(1, 60)
    duration = rng.uniform(0.1, 30.0)
    return {
        "src_ip": src, "dst_ip": dst,
        "src_port": rng.randint(1024, 65000), "dst_port": port,
        "protocol": protocol, "tos": rng.choice((0, 0, 0, 32, 184)),
        "tcp_flags": 0x1B if protocol == 6 else 0,
        "in_if": in_if, "out_if": out_if,
        "next_hop": rng.choice(INTERNAL_HOSTS),
        "src_as": 64500 if src in INTERNAL_HOSTS else 64501,
        "dst_as": 64500 if dst in INTERNAL_HOSTS else 64501,
        "packets": packets, "bytes": packets * rng.randint(80, 1400),
        "ts_start": max(0.0, ts_end - duration), "ts_end": ts_end,
    }


# ---------------------------------------------------------- flow generator

def generate_flows(exporters: list, t0: float, t1: float, seed: int,
                    flows_cap: int | None = None):
    """Yields (exporter_index, ts_end, flow_dict), oldest first.

    Walked hour by hour: every exporter's share for that hour is generated
    with timestamps jittered inside it, the hour's records from every
    exporter are merged and time-sorted, then the next hour starts - so the
    whole sequence this yields is globally non-decreasing in ts_end, which
    is what a real burst arriving at the collector needs to be.
    """
    rngs = {exp.index: random.Random(seed * 97 + exp.index + 1) for exp in exporters}
    hour = int(t0 // 3600) * 3600
    sent = 0
    while hour < t1:
        span_lo, span_hi = max(hour, t0), min(hour + 3600, t1)
        if span_hi <= span_lo:
            hour += 3600
            continue
        batch = []
        weight = HOURLY_WEIGHT[int(hour // 3600) % 24]
        for exp in exporters:
            mult = BUSY_MULTIPLIER if exp.busy else 1.0
            count = round(BASE_RECORDS_PER_HOUR * weight * mult
                          * (span_hi - span_lo) / 3600.0)
            rng = rngs[exp.index]
            for _ in range(count):
                ts_end = rng.uniform(span_lo, span_hi)
                batch.append((exp.index, ts_end, _make_flow(exp, rng, ts_end)))
        batch.sort(key=lambda item: item[1])
        for item in batch:
            if flows_cap is not None and sent >= flows_cap:
                return
            yield item
            sent += 1
        hour += 3600


# ------------------------------------------------------------- v5 packets

def build_v5(records: list, unix_secs: int, sys_uptime_ms: int,
             flow_sequence: int = 0, sampling_raw: int = 0) -> bytes:
    """One NetFlow v5 datagram: header plus `records`, each a dict with
    src_ip/dst_ip/next_hop/in_if/out_if/packets/octets/first_ms/last_ms/
    src_port/dst_port/tcp_flags/protocol/tos/src_as/dst_as."""
    header = struct.pack("!HHIIIIBBH", V5, len(records), sys_uptime_ms,
                         unix_secs, 0, flow_sequence, 0, 0, sampling_raw)
    body = b"".join(struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        int.from_bytes(socket.inet_aton(r["src_ip"]), "big"),
        int.from_bytes(socket.inet_aton(r["dst_ip"]), "big"),
        int.from_bytes(socket.inet_aton(r["next_hop"]), "big"),
        r["in_if"], r["out_if"], r["packets"], r["octets"],
        r["first_ms"], r["last_ms"], r["src_port"], r["dst_port"],
        0, r["tcp_flags"], r["protocol"], r["tos"],
        r["src_as"], r["dst_as"], 0, 0, 0)
        for r in records)
    return header + body


# ------------------------------------------------------------- v9 flowsets

def build_v9_template(template_id: int, fields: list) -> bytes:
    """One v9 template flowset (set id 0). `fields` is [(field_id, size)]."""
    body = struct.pack("!HH", template_id, len(fields))
    for field_id, size in fields:
        body += struct.pack("!HH", field_id, size)
    return struct.pack("!HH", 0, 4 + len(body)) + body


def build_v9_options(template_id: int, scope_fields: list,
                      option_fields: list) -> bytes:
    """One v9 options-template flowset (set id 1)."""
    body = struct.pack("!HHH", template_id, len(scope_fields) * 4,
                       len(option_fields) * 4)
    for field_id, size in scope_fields + option_fields:
        body += struct.pack("!HH", field_id, size)
    return struct.pack("!HH", 1, 4 + len(body)) + body


def _encode_records(fields: list, records: list) -> bytes:
    body = b""
    for record in records:
        for field_id, size in fields:
            value = record.get(field_id, 0)
            body += value if isinstance(value, bytes) else int(value).to_bytes(size, "big")
    return body


def build_v9_data(template_id: int, fields: list, records: list) -> bytes:
    """One v9 data flowset (set id == template_id, always >= 256). `records`
    is a list of {field_id: int-or-bytes} matching `fields`."""
    body = _encode_records(fields, records)
    return struct.pack("!HH", template_id, 4 + len(body)) + body


def _v9_header(unix_secs: int, sys_uptime_ms: int, sequence: int,
              domain: int, n_sets: int) -> bytes:
    return struct.pack("!HHIIII", V9, n_sets, sys_uptime_ms, unix_secs,
                       sequence, domain)


# ---------------------------------------------------------- ipfix flowsets

def build_ipfix_template(template_id: int, fields: list, is_options: bool = False,
                         scope_count: int = 0) -> bytes:
    """One IPFIX template flowset (set id 2, or 3 for an options template)."""
    if is_options:
        body = struct.pack("!HHH", template_id, len(fields), scope_count)
        set_id = 3
    else:
        body = struct.pack("!HH", template_id, len(fields))
        set_id = 2
    for field_id, size in fields:
        body += struct.pack("!HH", field_id, size)
    return struct.pack("!HH", set_id, 4 + len(body)) + body


def build_ipfix_data(template_id: int, fields: list, records: list) -> bytes:
    """One IPFIX data flowset (set id == template_id, always >= 256)."""
    body = _encode_records(fields, records)
    return struct.pack("!HH", template_id, 4 + len(body)) + body


def _ipfix_header(export_time: int, sequence: int, domain: int,
                  total_len: int) -> bytes:
    return struct.pack("!HHIII", IPFIX, total_len, export_time, sequence, domain)


# --------------------------------------------------------- datagram stream

def _boot_header_fields(now_ts: float, boot: float) -> tuple:
    """(unix_secs, sys_uptime_ms) such that unix_secs - sys_uptime_ms/1000
    reconstructs `boot` to within a millisecond, so a record's own
    boot-relative first/last ms lands on its intended wall-clock time."""
    unix_secs = int(now_ts)
    return unix_secs, int(max(0.0, (unix_secs - boot) * 1000))


def _v5_record(flow: dict, boot: float) -> dict:
    return {**flow, "octets": flow["bytes"],
            "first_ms": int(max(0.0, (flow["ts_start"] - boot) * 1000)),
            "last_ms": int(max(0.0, (flow["ts_end"] - boot) * 1000))}


def _v9_record(flow: dict, boot: float) -> dict:
    return {
        SRC_IPV4: socket.inet_aton(flow["src_ip"]),
        DST_IPV4: socket.inet_aton(flow["dst_ip"]),
        SRC_PORT: flow["src_port"], DST_PORT: flow["dst_port"],
        PROTOCOL: flow["protocol"], TOS: flow["tos"],
        IN_IF: flow["in_if"], OUT_IF: flow["out_if"],
        OCTETS: flow["bytes"], PACKETS: flow["packets"],
        FIRST_SWITCHED: int(max(0.0, (flow["ts_start"] - boot) * 1000)),
        LAST_SWITCHED: int(max(0.0, (flow["ts_end"] - boot) * 1000)),
        SRC_AS: flow["src_as"], DST_AS: flow["dst_as"],
    }


def _ipfix_record(flow: dict) -> dict:
    return {
        SRC_IPV4: socket.inet_aton(flow["src_ip"]),
        DST_IPV4: socket.inet_aton(flow["dst_ip"]),
        SRC_PORT: flow["src_port"], DST_PORT: flow["dst_port"],
        PROTOCOL: flow["protocol"], TOS: flow["tos"],
        IN_IF: flow["in_if"], OUT_IF: flow["out_if"],
        OCTETS: flow["bytes"], PACKETS: flow["packets"],
        FLOW_START_SECONDS: int(flow["ts_start"]),
        FLOW_END_SECONDS: int(flow["ts_end"]),
        SRC_AS: flow["src_as"], DST_AS: flow["dst_as"],
    }


def _refresh_sets(exp: ExporterConfig) -> bytes:
    if exp.version == V9:
        sets = build_v9_template(V9_TEMPLATE_ID, V9_FIELDS)
        if exp.has_options:
            sets += build_v9_options(V9_OPTIONS_TEMPLATE_ID,
                                     [(SAMPLING_SCOPE_FIELD, 4)],
                                     [(SAMPLING_INTERVAL, 4)])
            sets += build_v9_data(
                V9_OPTIONS_TEMPLATE_ID,
                [(SAMPLING_SCOPE_FIELD, 4), (SAMPLING_INTERVAL, 4)],
                [{SAMPLING_SCOPE_FIELD: socket.inet_aton(exp.address),
                  SAMPLING_INTERVAL: SAMPLING_RATE}])
        return sets
    return build_ipfix_template(IPFIX_TEMPLATE_ID, IPFIX_FIELDS)


def _batch_size(exp: ExporterConfig) -> int:
    if exp.version == V5:
        return V5_BATCH
    return V9_BATCH if exp.version == V9 else IPFIX_BATCH


class _ExporterState:
    """Per-exporter bookkeeping stream_datagrams and the live loop share:
    the pending record buffer, sequence counters and template-refresh
    cadence."""

    def __init__(self, exp: ExporterConfig):
        self.exp = exp
        self.pending: list = []
        self.packets = 0
        self.records = 0
        self.packets_since_refresh = 0
        self.last_refresh_wall = 0.0

    def refresh_datagram(self, now_ts: float) -> bytes:
        exp = self.exp
        sets = _refresh_sets(exp)
        if exp.version == V9:
            unix_secs, sys_uptime_ms = _boot_header_fields(now_ts, exp.boot)
            header = _v9_header(unix_secs, sys_uptime_ms, self.packets + 1, 0,
                                1 + int(exp.has_options) * 2)
        else:
            header = _ipfix_header(int(now_ts), self.records, 0, 16 + len(sets))
        self.packets += 1
        self.packets_since_refresh = 0
        self.last_refresh_wall = now_ts
        return header + sets

    def flush_datagram(self, now_ts: float):
        """The pending records as one datagram, or None if there are none.
        Returns (datagram_bytes, n_records)."""
        if not self.pending:
            return None
        exp = self.exp
        records = self.pending
        self.pending = []
        if exp.version == V5:
            unix_secs, sys_uptime_ms = _boot_header_fields(now_ts, exp.boot)
            datagram = build_v5(
                [_v5_record(flow, exp.boot) for flow in records],
                unix_secs=unix_secs, sys_uptime_ms=sys_uptime_ms,
                flow_sequence=self.records)
        elif exp.version == V9:
            data = build_v9_data(V9_TEMPLATE_ID, V9_FIELDS,
                                 [_v9_record(f, exp.boot) for f in records])
            unix_secs, sys_uptime_ms = _boot_header_fields(now_ts, exp.boot)
            header = _v9_header(unix_secs, sys_uptime_ms, self.packets + 1, 0, 1)
            datagram = header + data
        else:
            data = build_ipfix_data(IPFIX_TEMPLATE_ID, IPFIX_FIELDS,
                                    [_ipfix_record(f) for f in records])
            datagram = _ipfix_header(int(now_ts), self.records + len(records),
                                     0, 16 + len(data)) + data
        self.packets += 1
        self.records += len(records)
        self.packets_since_refresh += 1
        return datagram, len(records)


def stream_datagrams(exporters: list, t0: float, t1: float, seed: int,
                     flows_cap: int | None = None):
    """Yields (exporter_index, ts_end, datagram_bytes, n_records), oldest
    first - the same datagrams main() would send, built with no socket
    involved so a test can decode them directly. A template/options refresh
    datagram carries n_records == 0: it produces no Flow on its own."""
    states = {exp.index: _ExporterState(exp) for exp in exporters}
    for exp_index, ts_end, flow in generate_flows(exporters, t0, t1, seed, flows_cap):
        state = states[exp_index]
        exp = state.exp
        if exp.version != V5 and state.packets == 0:
            yield exp_index, ts_end, state.refresh_datagram(ts_end), 0
        state.pending.append(flow)
        if len(state.pending) >= _batch_size(exp):
            result = state.flush_datagram(ts_end)
            if result is not None:
                datagram, n_records = result
                yield exp_index, ts_end, datagram, n_records
        if (exp.version != V5
                and state.packets_since_refresh >= REFRESH_EVERY_PACKETS):
            yield exp_index, ts_end, state.refresh_datagram(ts_end), 0
    for exp in exporters:
        result = states[exp.index].flush_datagram(t1)
        if result is not None:
            datagram, n_records = result
            yield exp.index, t1, datagram, n_records


# ------------------------------------------------------------------- send

def _open_socket(exp: ExporterConfig, quiet: bool) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((exp.address, 0))
    except OSError as exc:
        if not quiet:
            print(f"warning: exporter {exp.index + 1} could not bind "
                 f"{exp.address} ({exc}); using the default source address",
                 file=sys.stderr)
    return sock


def _send(sock: socket.socket, host: str, port: int, datagram: bytes,
          errors: list) -> None:
    try:
        sock.sendto(datagram, (host, port))
    except OSError as exc:
        errors.append(str(exc))


def _run_burst(exporters: list, sockets: dict, host: str, port: int,
               days: float, seed: int, flows_cap, quiet: bool,
               totals: dict, errors: list) -> int:
    now = time.time()
    t0, t1 = now - days * 86400, now
    rate_per_s = 400.0
    interval = 1.0 / rate_per_s
    next_send = time.monotonic()
    total_records = 0
    last_hour_shown = None
    for exp_index, ts_end, datagram, n_records in stream_datagrams(
            exporters, t0, t1, seed, flows_cap):
        _send(sockets[exp_index], host, port, datagram, errors)
        totals[exp_index]["datagrams"] += 1
        totals[exp_index]["records"] += n_records
        total_records += n_records
        now_mono = time.monotonic()
        wait = next_send - now_mono
        if wait > 0:
            time.sleep(wait)
        next_send = max(next_send + interval, time.monotonic())
        if not quiet:
            hour = int(ts_end // 3600)
            if hour != last_hour_shown:
                last_hour_shown = hour
                print(f"  burst: {time.strftime('%Y-%m-%d %H:00', time.localtime(hour * 3600))}"
                     f" - {total_records} records sent so far")
    return total_records


def _run_live(exporters: list, sockets: dict, host: str, port: int,
             rate: float, seed: int, flows_cap, records_sent: int,
             quiet: bool, totals: dict, errors: list) -> None:
    states = {exp.index: _ExporterState(exp) for exp in exporters}
    weights = {exp.index: BUSY_MULTIPLIER if exp.busy else 1.0 for exp in exporters}
    total_weight = sum(weights.values())
    per_exporter_interval = {
        exp.index: total_weight / (weights[exp.index] * max(rate, 0.01))
        for exp in exporters}
    rng = {exp.index: random.Random(seed * 97 + exp.index + 9973) for exp in exporters}
    next_due = {exp.index: time.monotonic() for exp in exporters}
    sent = records_sent
    if not quiet:
        print(f"  live: {rate} records/s aggregate until Ctrl-C")
    while flows_cap is None or sent < flows_cap:
        now_mono = time.monotonic()
        soonest = min(next_due.values())
        if soonest > now_mono:
            time.sleep(min(soonest - now_mono, 1.0))
            continue
        for exp in exporters:
            if next_due[exp.index] > now_mono:
                continue
            state = states[exp.index]
            now_wall = time.time()
            if (exp.version != V5
                    and now_wall - state.last_refresh_wall >= LIVE_TEMPLATE_REFRESH_S):
                _send(sockets[exp.index], host, port,
                     state.refresh_datagram(now_wall), errors)
                totals[exp.index]["datagrams"] += 1
            flow = _make_flow(exp, rng[exp.index], now_wall)
            state.pending.append(flow)
            result = state.flush_datagram(now_wall)
            if result is not None:
                _send(sockets[exp.index], host, port, result[0], errors)
                totals[exp.index]["datagrams"] += 1
                totals[exp.index]["live_records"] += result[1]
            sent += 1
            next_due[exp.index] += per_exporter_interval[exp.index]
            if flows_cap is not None and sent >= flows_cap:
                break


# ------------------------------------------------------------------- main

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="127.0.0.1",
                        help="collector host to send to (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2055,
                        help="collector UDP port (default 2055)")
    parser.add_argument("--exporters", type=int, default=4,
                        help="how many simulated exporters (default 4)")
    parser.add_argument("--days", type=float, default=3,
                        help="days of history for --burst (default 3)")
    parser.add_argument("--burst", action="store_true",
                        help="send --days of history, oldest first")
    parser.add_argument("--live", action="store_true",
                        help="keep sending live traffic until Ctrl-C")
    parser.add_argument("--rate", type=float, default=60,
                        help="live records/s aggregate (default 60)")
    parser.add_argument("--flows", type=int, default=None,
                        help="cap on total records sent")
    parser.add_argument("--seed", type=int, default=1,
                        help="deterministic RNG seed (default 1)")
    parser.add_argument("--quiet", action="store_true",
                        help="only print the start banner and summary")
    args = parser.parse_args(argv)

    if not args.burst and not args.live:
        args.burst = True

    # v5/v9 uptime counters cannot be negative, so every exporter's boot
    # must precede the oldest flow a burst will carry.
    boot_reference = time.time() - args.days * 86400 - 3600
    exporters = build_exporters(args.exporters, args.seed, boot_reference)
    sockets = {exp.index: _open_socket(exp, args.quiet) for exp in exporters}
    totals = {exp.index: {"datagrams": 0, "records": 0, "live_records": 0,
                          "version": exp.version, "address": exp.address}
             for exp in exporters}
    errors: list = []

    print(f"sending to {args.host}:{args.port} from {len(exporters)} exporters",
          flush=True)

    sent = 0
    try:
        if args.burst:
            sent = _run_burst(exporters, sockets, args.host, args.port,
                              args.days, args.seed, args.flows, args.quiet,
                              totals, errors)
        if args.live:
            _run_live(exporters, sockets, args.host, args.port, args.rate,
                     args.seed, args.flows, sent, args.quiet, totals, errors)
    except KeyboardInterrupt:
        pass
    finally:
        for sock in sockets.values():
            sock.close()

    total_records = sum(t["records"] + t["live_records"] for t in totals.values())
    total_datagrams = sum(t["datagrams"] for t in totals.values())
    print(f"sent {total_records} records in {total_datagrams} datagrams"
         f"{f' ({len(errors)} send errors)' if errors else ''}")
    for exp in exporters:
        t = totals[exp.index]
        version_name = {V5: "v5", V9: "v9", IPFIX: "ipfix"}[exp.version]
        print(f"  exporter {exp.index + 1} {exp.address} ({version_name}): "
             f"{t['datagrams']} datagrams")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
