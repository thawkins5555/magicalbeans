"""Decoders for NetFlow v5, NetFlow v9 and IPFIX (v10).

v5 is a fixed 48-byte record and needs no state. v9 and IPFIX are
template-driven: the exporter periodically sends a template describing the
layout of the data records that follow, and until that template arrives the
data records are undecodable. Templates are cached per
(exporter, observation domain, template id) because ids are only unique within
a domain, and an exporter that reboots will reuse ids for different layouts.

Nothing here touches the database or the network; feed it bytes, get Flows.
"""

from __future__ import annotations

import collections
import socket
import struct
import time
from dataclasses import dataclass, field

# Template ids, observation domains and exporter addresses all come off the
# wire, so both caches are keyed on data an attacker (or a rebooting exporter
# that never reuses a domain) chooses. Bounded, least-recently-used, and
# generous enough for a few thousand exporters' worth of real templates.
MAX_TEMPLATES = 4096
MAX_SAMPLING = 4096

V5 = 5
V9 = 9
IPFIX = 10

# IANA information element ids. v9 uses the same numbering for these.
OCTETS = 1
PACKETS = 2
PROTOCOL = 4
TOS = 5
TCP_FLAGS = 6
SRC_PORT = 7
SRC_IPV4 = 8
IN_IF = 10
DST_PORT = 11
DST_IPV4 = 12
OUT_IF = 14
NEXT_HOP_V4 = 15
SRC_AS = 16
DST_AS = 17
LAST_SWITCHED = 21
FIRST_SWITCHED = 22
SRC_IPV6 = 27
DST_IPV6 = 28
SAMPLING_INTERVAL = 34
SAMPLING_ALGORITHM = 35
FLOW_SAMPLER_ID = 48                 # v9 flowSamplerID
FLOW_SAMPLER_RANDOM_INTERVAL = 50    # v9 flowSamplerRandomInterval
NEXT_HOP_V6 = 62
FLOW_START_SECONDS = 150
FLOW_END_SECONDS = 151
FLOW_START_MS = 152
FLOW_END_MS = 153
OCTETS_TOTAL = 85
PACKETS_TOTAL = 86
SAMPLER_RANDOM_INTERVAL = 305
SELECTOR_ID = 302                    # IPFIX selectorId
SAMPLING_FLOW_INTERVAL = 309         # IPFIX samplingFlowInterval

# Information elements that carry a sampling rate, and the ones that identify
# which sampler it belongs to. A router with per-interface or per-sampler
# rates sends several options records; keying only on the exporter address
# kept whichever arrived last and applied it to everything.
RATE_FIELDS = (SAMPLING_INTERVAL, SAMPLER_RANDOM_INTERVAL,
               FLOW_SAMPLER_RANDOM_INTERVAL, SAMPLING_FLOW_INTERVAL)
SAMPLER_ID_FIELDS = (FLOW_SAMPLER_ID, SELECTOR_ID)

IPV4_FIELDS = {SRC_IPV4, DST_IPV4, NEXT_HOP_V4}
IPV6_FIELDS = {SRC_IPV6, DST_IPV6, NEXT_HOP_V6}


@dataclass
class Flow:
    exporter: str
    version: int
    ts_start: float
    ts_end: float
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    tos: int = 0
    tcp_flags: int = 0
    in_if: int = 0
    out_if: int = 0
    src_as: int = 0
    dst_as: int = 0
    next_hop: str = ""
    packets: int = 0
    bytes: int = 0
    sampling: int = 1
    # Which sampler produced this flow, so a rate that arrives after it does
    # can be applied to it rather than being lost.
    domain: int = 0
    sampler_id: int = 0


class _Lru(collections.OrderedDict):
    """A dict with a hard entry limit, dropping the least recently used key.

    Both of the decoder's caches are keyed on values the exporter chooses, so
    an unbounded dict is a memory leak that any sender can drive.
    """

    def __init__(self, limit: int):
        super().__init__()
        self.limit = limit
        self.evictions = 0

    def __setitem__(self, key, value) -> None:
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self.limit:
            self.popitem(last=False)
            self.evictions += 1

    def get(self, key, default=None):
        if key in self:
            self.move_to_end(key)
            return self[key]
        return default


@dataclass
class Template:
    template_id: int
    fields: list[tuple[int, int, int]] = field(default_factory=list)  # (id, len, enterprise)
    is_options: bool = False
    scope_count: int = 0
    # 0xFFFF means "variable length" in IPFIX only. In v9 it is a legitimate
    # fixed 65535-byte field, and reading it as a variable-length one silently
    # decoded the following field's bytes as a counter.
    ipfix: bool = False

    @property
    def length(self) -> int | None:
        """Fixed record length, or None when the template has a variable field."""
        total = 0
        for _, size, _ in self.fields:
            if self.ipfix and size == 0xFFFF:
                return None
            total += size
        return total


class DecodeError(Exception):
    pass


def _ip(raw: bytes) -> str:
    try:
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        if len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except OSError:
        pass
    return ""


def _int(raw: bytes) -> int:
    return int.from_bytes(raw, "big") if raw else 0


def _sampler_id(values: dict[int, bytes]) -> int:
    """Which sampler a record belongs to, 0 when it does not say."""
    for key in SAMPLER_ID_FIELDS:
        if key in values:
            return _int(values[key])
    return 0


def _pick(*candidates: bytes | None) -> bytes:
    """First address field with real content.

    Several platforms carry both the v4 and the v6 address pair in one
    template and zero-fill the unused pair. `b"\x00\x00\x00\x00"` is truthy,
    so an `or` chain rendered every IPv6 flow on such an exporter as
    0.0.0.0 -> 0.0.0.0, which then dominated every top-N chart.
    """
    for candidate in candidates:
        if candidate and any(candidate):
            return candidate
    return b""


class Decoder:
    """Stateful across packets: holds the template cache and per-exporter sampling."""

    def __init__(self, default_sampling: int = 1, trust_exporter_sampling: bool = True):
        self.templates: _Lru = _Lru(MAX_TEMPLATES)
        # (exporter, observation domain, sampler id) -> rate
        self.sampling: _Lru = _Lru(MAX_SAMPLING)
        # Rates learned since the caller last drained this, so it can correct
        # flows stored before the options record that announced them.
        self.learned_rates: list[tuple[str, int, int, int]] = []
        self.default_sampling = max(1, int(default_sampling))
        self.trust_exporter_sampling = trust_exporter_sampling
        self.stats = {"packets": 0, "flows": 0, "templates": 0, "errors": 0,
                      "no_template": 0, "bad_template": 0}

    def sampling_for(self, exporter: str, domain: int = 0,
                     sampler_id: int = 0) -> int:
        """The rate for one sampler, falling back to the exporter's own.

        Most exporters announce a single rate and send no sampler id at all,
        so the exact key, the domain-wide key and the exporter-wide key are
        tried in that order before the configured default.
        """
        if not self.trust_exporter_sampling:
            return self.default_sampling
        for key in ((exporter, domain, sampler_id), (exporter, domain, 0),
                    (exporter, 0, 0)):
            rate = self.sampling.get(key)
            if rate:
                return max(1, rate)
        return max(1, self.default_sampling)

    def _set_sampling(self, exporter: str, domain: int, sampler_id: int,
                      rate: int) -> None:
        """Record a rate, and note it when it is new or changed so the caller
        can correct the flows already stored under that key: an options
        template arrives on a slower cycle than data, so the flows decoded
        before the first one were stored with sampling=1 permanently and every
        byte figure for that window was understated by the sampling factor."""
        key = (exporter, domain, sampler_id)
        if self.sampling.get(key) == rate:
            self.sampling[key] = rate           # refresh its LRU position
            return
        self.sampling[key] = rate
        self.learned_rates.append((exporter, domain, sampler_id, rate))

    def decode(self, data: bytes, exporter: str) -> list[Flow]:
        self.stats["packets"] += 1
        if len(data) < 4:
            self.stats["errors"] += 1
            return []
        version = struct.unpack_from("!H", data, 0)[0]
        try:
            if version == V5:
                flows = self._decode_v5(data, exporter)
            elif version == V9:
                flows = self._decode_v9(data, exporter)
            elif version == IPFIX:
                flows = self._decode_ipfix(data, exporter)
            else:
                self.stats["errors"] += 1
                return []
        except (DecodeError, struct.error, IndexError, ValueError):
            # DecodeError belongs in this tuple: the short-header guards below
            # raise it, and without it one runt datagram unwound out of the
            # receive thread and killed the listener for the life of the
            # process.
            self.stats["errors"] += 1
            return []
        self.stats["flows"] += len(flows)
        return flows

    # --------------------------------------------------------------- v5

    def _decode_v5(self, data: bytes, exporter: str) -> list[Flow]:
        if len(data) < 24:
            raise DecodeError("short v5 header")
        (_, count, sys_uptime, unix_secs, _, _,
         _, _, sampling_raw) = struct.unpack_from("!HHIIIIBBH", data, 0)

        # Top two bits are the sampling mode, the rest is the interval.
        interval = sampling_raw & 0x3FFF
        if interval > 1:
            self._set_sampling(exporter, 0, 0, interval)
        sampling = self.sampling_for(exporter)

        boot = unix_secs - sys_uptime / 1000.0
        flows = []
        for index in range(min(count, (len(data) - 24) // 48)):
            offset = 24 + index * 48
            (src, dst, nexthop, in_if, out_if, packets, octets, first, last,
             src_port, dst_port, _, tcp_flags, protocol, tos,
             src_as, dst_as, _, _, _) = struct.unpack_from(
                "!IIIHHIIIIHHBBBBHHBBH", data, offset)
            flows.append(Flow(
                exporter=exporter, version=V5,
                ts_start=boot + first / 1000.0,
                ts_end=boot + last / 1000.0,
                src_ip=socket.inet_ntop(socket.AF_INET, struct.pack("!I", src)),
                dst_ip=socket.inet_ntop(socket.AF_INET, struct.pack("!I", dst)),
                next_hop=socket.inet_ntop(socket.AF_INET, struct.pack("!I", nexthop)),
                src_port=src_port, dst_port=dst_port, protocol=protocol, tos=tos,
                tcp_flags=tcp_flags, in_if=in_if, out_if=out_if,
                src_as=src_as, dst_as=dst_as,
                packets=packets, bytes=octets, sampling=sampling,
            ))
        return flows

    # --------------------------------------------------------------- v9

    def _decode_v9(self, data: bytes, exporter: str) -> list[Flow]:
        if len(data) < 20:
            raise DecodeError("short v9 header")
        _, _, sys_uptime, unix_secs, _, domain = struct.unpack_from("!HHIIII", data, 0)
        boot = unix_secs - sys_uptime / 1000.0
        offset = 20
        flows: list[Flow] = []

        while offset + 4 <= len(data):
            set_id, set_len = struct.unpack_from("!HH", data, offset)
            if set_len < 4 or offset + set_len > len(data):
                break
            body = data[offset + 4: offset + set_len]
            if set_id == 0:
                self._read_templates(body, exporter, domain, options=False, ipfix=False)
            elif set_id == 1:
                self._read_options_template(body, exporter, domain, ipfix=False)
            elif set_id >= 256:
                flows.extend(self._read_data(body, exporter, domain, set_id,
                                             V9, boot, unix_secs))
            offset += set_len
        return flows

    # ------------------------------------------------------------ ipfix

    def _decode_ipfix(self, data: bytes, exporter: str) -> list[Flow]:
        if len(data) < 16:
            raise DecodeError("short ipfix header")
        _, length, export_time, _, domain = struct.unpack_from("!HHIII", data, 0)
        length = min(length, len(data))
        offset = 16
        flows: list[Flow] = []

        while offset + 4 <= length:
            set_id, set_len = struct.unpack_from("!HH", data, offset)
            if set_len < 4 or offset + set_len > length:
                break
            body = data[offset + 4: offset + set_len]
            if set_id == 2:
                self._read_templates(body, exporter, domain, options=False, ipfix=True)
            elif set_id == 3:
                self._read_options_template(body, exporter, domain, ipfix=True)
            elif set_id >= 256:
                flows.extend(self._read_data(body, exporter, domain, set_id,
                                             IPFIX, 0.0, export_time))
            offset += set_len
        return flows

    # ------------------------------------------------------- templates

    def _read_templates(self, body: bytes, exporter: str, domain: int,
                        options: bool, ipfix: bool) -> None:
        offset = 0
        while offset + 4 <= len(body):
            template_id, count = struct.unpack_from("!HH", body, offset)
            offset += 4
            template = Template(template_id=template_id, is_options=options,
                                ipfix=ipfix)
            broken = count == 0
            for _ in range(count):
                if offset + 4 > len(body):
                    return
                field_id, size = struct.unpack_from("!HH", body, offset)
                offset += 4
                enterprise = 0
                if ipfix and field_id & 0x8000:
                    field_id &= 0x7FFF
                    if offset + 4 > len(body):
                        return
                    enterprise = struct.unpack_from("!I", body, offset)[0]
                    offset += 4
                if size <= 0:
                    broken = True
                template.fields.append((field_id, size, enterprise))
            if broken:
                # A template with no fields, or with a zero-length field, has a
                # record length of zero: caching it made _read_data loop
                # forever at 100% CPU on the receive thread with `running`
                # still true. Refuse it, and forget any earlier template with
                # the same id so stale layouts cannot be decoded either.
                self.stats["bad_template"] += 1
                self.stats["errors"] += 1
                self.templates.pop((exporter, domain, template_id), None)
                continue
            self.templates[(exporter, domain, template_id)] = template
            self.stats["templates"] += 1

    def _read_options_template(self, body: bytes, exporter: str, domain: int,
                               ipfix: bool) -> None:
        """Options templates differ between v9 and IPFIX only in their header."""
        if ipfix:
            if len(body) < 4:
                return
            template_id, total = struct.unpack_from("!HH", body, 0)
            scope_count = struct.unpack_from("!H", body, 4)[0] if len(body) >= 6 else 0
            offset = 6
            field_count = total
        else:
            if len(body) < 6:
                return
            template_id, scope_len, option_len = struct.unpack_from("!HHH", body, 0)
            offset = 6
            scope_count = scope_len // 4
            field_count = scope_count + option_len // 4

        template = Template(template_id=template_id, is_options=True,
                            scope_count=scope_count, ipfix=ipfix)
        broken = field_count == 0
        for _ in range(field_count):
            if offset + 4 > len(body):
                break
            field_id, size = struct.unpack_from("!HH", body, offset)
            offset += 4
            enterprise = 0
            if ipfix and field_id & 0x8000:
                field_id &= 0x7FFF
                if offset + 4 > len(body):
                    break
                enterprise = struct.unpack_from("!I", body, offset)[0]
                offset += 4
            if size <= 0:
                broken = True
            template.fields.append((field_id, size, enterprise))
        if broken:
            self.stats["bad_template"] += 1
            self.stats["errors"] += 1
            self.templates.pop((exporter, domain, template_id), None)
            return
        self.templates[(exporter, domain, template_id)] = template
        self.stats["templates"] += 1

    # ------------------------------------------------------------- data

    def _read_data(self, body: bytes, exporter: str, domain: int, template_id: int,
                   version: int, boot: float, export_time: float) -> list[Flow]:
        template = self.templates.get((exporter, domain, template_id))
        if template is None:
            self.stats["no_template"] += 1
            return []

        flows: list[Flow] = []
        offset = 0
        fixed = template.length
        if fixed is not None and fixed <= 0:
            # Belt and braces beside the guard in _read_templates: a cached
            # template from before this check, or one whose fields sum to
            # zero, would never advance `offset`.
            self.stats["bad_template"] += 1
            self.stats["errors"] += 1
            self.templates.pop((exporter, domain, template_id), None)
            return []

        while offset < len(body):
            if fixed is not None:
                if offset + fixed > len(body):
                    break
                values, offset = self._read_fixed(body, offset, template)
            else:
                values, offset, ok = self._read_variable(body, offset, template)
                if not ok:
                    break

            if template.is_options:
                self._apply_options(values, exporter, domain)
                continue

            flow = self._build_flow(values, exporter, version, boot, export_time,
                                    domain)
            if flow is not None:
                flows.append(flow)

            # Padding: a run shorter than the record length is the set's tail.
            if fixed is not None and len(body) - offset < fixed:
                break
        return flows

    def _read_fixed(self, body: bytes, offset: int, template: Template):
        values: dict[int, bytes] = {}
        for field_id, size, enterprise in template.fields:
            chunk = body[offset:offset + size]
            offset += size
            if enterprise == 0:
                values[field_id] = chunk
        return values, offset

    def _read_variable(self, body: bytes, offset: int, template: Template):
        values: dict[int, bytes] = {}
        for field_id, size, enterprise in template.fields:
            if size == 0xFFFF:
                if offset >= len(body):
                    return values, offset, False
                size = body[offset]
                offset += 1
                if size == 255:
                    if offset + 2 > len(body):
                        return values, offset, False
                    size = struct.unpack_from("!H", body, offset)[0]
                    offset += 2
            if offset + size > len(body):
                return values, offset, False
            chunk = body[offset:offset + size]
            offset += size
            if enterprise == 0:
                values[field_id] = chunk
        return values, offset, True

    def _apply_options(self, values: dict[int, bytes], exporter: str,
                       domain: int) -> None:
        sampler_id = _sampler_id(values)
        for key in RATE_FIELDS:
            if key in values:
                rate = _int(values[key])
                if rate > 1:
                    self._set_sampling(exporter, domain, sampler_id, rate)

    def _build_flow(self, values: dict[int, bytes], exporter: str, version: int,
                    boot: float, export_time: float, domain: int = 0) -> Flow | None:
        octets = _int(values.get(OCTETS) or values.get(OCTETS_TOTAL) or b"")
        packets = _int(values.get(PACKETS) or values.get(PACKETS_TOTAL) or b"")
        if not octets and not packets:
            return None

        start = end = None
        if FLOW_START_MS in values:
            start = _int(values[FLOW_START_MS]) / 1000.0
        elif FLOW_START_SECONDS in values:
            start = float(_int(values[FLOW_START_SECONDS]))
        elif FIRST_SWITCHED in values and boot:
            start = boot + _int(values[FIRST_SWITCHED]) / 1000.0

        if FLOW_END_MS in values:
            end = _int(values[FLOW_END_MS]) / 1000.0
        elif FLOW_END_SECONDS in values:
            end = float(_int(values[FLOW_END_SECONDS]))
        elif LAST_SWITCHED in values and boot:
            end = boot + _int(values[LAST_SWITCHED]) / 1000.0

        if end is None:
            end = float(export_time) or time.time()
        if start is None:
            start = end
        # Exporters with a bad clock can send times far from now; clamp so one
        # misconfigured device cannot stretch every chart's axis.
        now = time.time()
        if not (now - 86400 * 30 < end < now + 3600):
            end = now
            start = min(start, end) if start else end

        sampler_id = _sampler_id(values)
        src = _pick(values.get(SRC_IPV4), values.get(SRC_IPV6))
        dst = _pick(values.get(DST_IPV4), values.get(DST_IPV6))
        hop = _pick(values.get(NEXT_HOP_V4), values.get(NEXT_HOP_V6))

        return Flow(
            exporter=exporter, version=version,
            ts_start=min(start, end), ts_end=end,
            src_ip=_ip(src), dst_ip=_ip(dst), next_hop=_ip(hop),
            src_port=_int(values.get(SRC_PORT, b"")),
            dst_port=_int(values.get(DST_PORT, b"")),
            protocol=_int(values.get(PROTOCOL, b"")),
            tos=_int(values.get(TOS, b"")),
            tcp_flags=_int(values.get(TCP_FLAGS, b"")),
            in_if=_int(values.get(IN_IF, b"")),
            out_if=_int(values.get(OUT_IF, b"")),
            src_as=_int(values.get(SRC_AS, b"")),
            dst_as=_int(values.get(DST_AS, b"")),
            packets=packets, bytes=octets,
            domain=domain, sampler_id=sampler_id,
            sampling=self.sampling_for(exporter, domain, sampler_id),
        )
