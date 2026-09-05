"""Device personas for the SappiWhere demo fleet.

A *persona* is a recipe for one kind of box: the ordered OID table it
answers, the shape of its interface table, its forwarding database, its
vendor-arc objects. A *device state* (``DeviceState``) is one instance of
a persona on one loopback IP, carrying the behaviour knobs the demo drives
(alive/dead, reboot, wrong community, slow, tooBig, 32-bit wrap, flapping
ports, v1-only, v3 mode).

The OID table is deliberately SHARED between every device of the same
persona variant: every value that differs per device, or with time, is a
callable ``fn(state, now)`` evaluated at reply time, so a thousand-device
fleet costs one table per persona rather than a thousand copies of it.

    entries = {oid_str: (ber_tag, constant_or_callable)}

Ordering is numeric (``netpath.nodeoids.oid_key``), which is what makes
GETNEXT/GETBULK walks come out in the same order a real agent's do.

Public surface the seed script depends on (keep stable)::

    fleet_plan(count) -> list[dict]
        [{index, ip, name, persona, site, snmp_version, community,
          profile, knobs}, ...]
        index 0 is the core switch, index 1 the wireless controller, and
        indices 2..13 are the fixed SPECIALS below (13 is the ConfigRX SSH
        demo device, pinned to 127.0.0.1). Everything from 14 on is a
        deterministic weighted mix.

    SPECIALS -> dict[int, dict]
        {index: {ip, persona, profile, knob, note}} — the devices whose
        misbehaviour the demo is built around.

    ip_for(index) -> "127.0.x.y"
    PROFILES -> dict[str, dict]  (snmp_version/community/v3 user+password)
    SITES -> tuple[str, ...]

    build_device(entry) -> DeviceState
    PERSONAS -> dict[str, Persona]

Stdlib only, like the app.
"""

from __future__ import annotations

import math
import os
import sys
import time
import zlib
from bisect import bisect_right

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netpath import fortinetoids as fgoids            # noqa: E402
from netpath.nodeoids import oid_key                  # noqa: E402
from netpath.trapdecode import (                      # noqa: E402
    T_COUNTER32, T_COUNTER64, T_GAUGE32, T_INTEGER, T_IPADDRESS,
    T_OCTET_STRING, T_OID, T_TIMETICKS, _tlv, enc_int, enc_octets, enc_oid,
    enc_unsigned,
)

# --------------------------------------------------------------- encoding

def encode(tag: int, value) -> bytes:
    """One varbind value, BER-encoded with trapdecode's own primitives."""
    if tag == T_OCTET_STRING:
        return enc_octets(value)
    if tag == T_OID:
        return enc_oid(value)
    if tag == T_INTEGER:
        return enc_int(value)
    if tag == T_IPADDRESS:
        return _tlv(T_IPADDRESS, bytes(int(p) for p in str(value).split(".")))
    return enc_unsigned(tag, value)


def h(*parts) -> int:
    """A deterministic non-negative hash — same fleet every run."""
    return zlib.crc32("|".join(str(p) for p in parts).encode("utf-8"))


# ------------------------------------------------------------------ table

class Table:
    """An ordered OID table: GET by exact OID, GETNEXT by binary search."""

    __slots__ = ("entries", "oids", "keys")

    def __init__(self, entries: dict):
        self.entries = entries
        self.oids = sorted(entries, key=oid_key)
        self.keys = [oid_key(o) for o in self.oids]

    def __len__(self) -> int:
        return len(self.oids)

    def has(self, oid: str) -> bool:
        return oid in self.entries

    def next_oid(self, oid: str) -> str | None:
        i = bisect_right(self.keys, oid_key(oid))
        return self.oids[i] if i < len(self.oids) else None

    def value_bytes(self, oid: str, state, now: float) -> bytes:
        tag, value = self.entries[oid]
        if callable(value):
            value = value(state, now)
        return encode(tag, value)


class Persona:
    """A named recipe. ``table()`` memoises one Table per variant, so the
    500-port chassis and the wrap32 device get their own and everything
    else shares."""

    def __init__(self, key: str, builder, ports: int = 0, label: str = ""):
        self.key = key
        self.label = label or key
        self.ports = ports
        self._builder = builder
        self._cache: dict[tuple, Table] = {}

    def table(self, wrap32: bool = False, ports: int | None = None,
              vlan: str | None = None) -> Table:
        variant = (bool(wrap32), int(ports or 0), vlan)
        cached = self._cache.get(variant)
        if cached is None:
            cached = Table(self._builder(bool(wrap32), ports or self.ports, vlan))
            self._cache[variant] = cached
        return cached

    def vlans(self) -> tuple[str, ...]:
        """Per-VLAN community contexts this persona answers (Cisco only)."""
        return ()


class CiscoVlanPersona(Persona):
    def __init__(self, key, builder, ports=0, label="", vlan_list=()):
        super().__init__(key, builder, ports, label)
        self._vlans = tuple(vlan_list)

    def vlans(self) -> tuple[str, ...]:
        return self._vlans


# ------------------------------------------------------------ device state

class DeviceState:
    """One simulated box. Everything the demo can change at run time lives
    here; the persona's callables read it at reply time, so a knob change
    shows up in the very next answer with nothing to rebuild."""

    def __init__(self, entry: dict, persona: Persona):
        knobs = dict(entry.get("knobs") or {})
        self.index = int(entry["index"])
        self.ip = entry["ip"]
        self.name = entry["name"]
        self.site = entry.get("site", "Site-A")
        self.persona_key = entry["persona"]
        self.persona = persona
        self.profile = entry.get("profile", "v2c-public")
        self.snmp_version = int(entry.get("snmp_version", 1))
        self.community = entry.get("community", "public")
        self.knobs = knobs

        now = time.time()
        self.start_ts = now
        # A fleet whose devices all booted at the same instant looks fake and
        # makes every uptime identical; spread them over ~40 days.
        self.boot_ts = now - (h("boot", self.name) % 3_456_000) - 600
        self.alive = bool(knobs.get("alive", True))
        self.v1_only = bool(knobs.get("v1_only", False))
        self.auth_fail = bool(knobs.get("auth_fail", False))
        self.slow_ms = int(knobs.get("slow_ms", 0))
        self.toobig = bool(knobs.get("toobig", False))
        self.wrap32 = bool(knobs.get("wrap32", False))
        self.chassis_ports = int(knobs.get("chassis_ports", 0)) or None
        self.flapping = set(knobs.get("flapping", ()))
        self.v3 = knobs.get("v3")                       # None|"noauth"|"sha"
        self.v3_user = knobs.get("v3_user", "poller")
        self.v3_password = knobs.get("v3_password", "")
        # Scheduled misbehaviour, evaluated from the clock at reply time so
        # the selector loop stays purely reactive.
        self.dark_after_s = knobs.get("dark_after_s")   # first outage at t+N
        self.dark_for_s = int(knobs.get("dark_for_s", 0) or 0)
        self.dark_every_s = int(knobs.get("dark_every_s", 0) or 0)
        self.reboot_every_s = int(knobs.get("reboot_every_s", 0) or 0)

        self.engine_id = bytes.fromhex("80001f8880") + \
            (h("engine", self.name) & 0xFFFFFFFF).to_bytes(4, "big") + b"\x01"
        self.engine_boots = 1 + (h("boots", self.name) % 5)

        self.requests = 0
        self.gets = 0
        self.getnexts = 0
        self.getbulks = 0
        self.drops = 0
        self.last_request_ts = 0.0

    # ---------------------------------------------------------- schedules

    def is_alive(self, now: float) -> bool:
        if not self.alive:
            return False
        if self.dark_after_s is not None and self.dark_for_s:
            elapsed = now - self.start_ts - float(self.dark_after_s)
            if elapsed >= 0:
                period = self.dark_every_s or (self.dark_for_s * 2)
                if (elapsed % period) < self.dark_for_s:
                    return False
        return True

    def boot(self, now: float) -> float:
        """The boot timestamp in force right now — a device on a reboot
        schedule restarts its uptime every reboot_every_s."""
        if self.reboot_every_s > 0:
            elapsed = now - self.start_ts
            if elapsed >= self.reboot_every_s:
                return self.start_ts + (elapsed // self.reboot_every_s) * self.reboot_every_s
        return self.boot_ts

    def reboot(self, now: float | None = None) -> None:
        self.boot_ts = now or time.time()
        self.engine_boots += 1

    def uptime_ticks(self, now: float) -> int:
        return int(max(0.0, now - self.boot(now)) * 100) % (2 ** 32)

    # ------------------------------------------------------------ helpers

    def table(self, vlan: str | None = None) -> Table:
        return self.persona.table(wrap32=self.wrap32, ports=self.chassis_ports,
                                  vlan=vlan)

    def accepts(self, community: str) -> tuple[bool, str | None]:
        """(ok, vlan-context). Classic IOS answers its bridge table only
        inside a `community@vlan` context, which is why the app has a
        per-VLAN MAC path at all — the Cisco personas reproduce that."""
        if community == self.community:
            return True, None
        if "@" in community:
            base, vlan = community.split("@", 1)
            if base == self.community and vlan in self.persona.vlans():
                return True, vlan
        return False, None

    def mac(self, offset: int = 0) -> bytes:
        seed = h("mac", self.name)
        return bytes((0x02, (seed >> 16) & 0xFF, (seed >> 8) & 0xFF,
                      seed & 0xFF, (offset >> 8) & 0xFF, offset & 0xFF))

    def port_idle(self, if_index: int, idle_frac: float) -> bool:
        if idle_frac <= 0:
            return False
        return (h("idle", self.name, if_index) % 1000) < idle_frac * 1000

    def oper_status(self, now: float, if_index: int, idle_frac: float = 0.0) -> int:
        if if_index in self.flapping:
            period = 20 + (h("flap", self.name, if_index) % 21)   # 20..40 s
            return 1 if int(now // period) % 2 == 0 else 2
        return 2 if self.port_idle(if_index, idle_frac) else 1

    def util(self, now: float, if_index: int, idle_frac: float) -> float:
        """Deterministic link utilisation, drifting slowly so the charts in
        the app actually move."""
        if self.port_idle(if_index, idle_frac):
            return 0.0
        base = 0.02 + (h("util", self.name, if_index) % 550) / 1000.0
        phase = (h("phase", self.name, if_index) % 628) / 100.0
        return max(0.0, base * (1.0 + 0.35 * math.sin(now / 37.0 + phase)))

    def octets(self, now: float, if_index: int, speed_bps: float,
               direction: str, idle_frac: float, bits: int = 64) -> int:
        up = max(0.0, now - self.boot(now))
        if self.wrap32:
            # Laps a 32-bit octet counter in ~60 s, which is exactly the
            # case nodeoids.IFX_TABLE's comment says the HC columns exist
            # for — and this device deliberately has no HC columns.
            per_s = (2 ** 32) / 60.0
        else:
            share = 1.0 if direction == "in" else 0.62
            per_s = (speed_bps / 8.0) * self.util(now, if_index, idle_frac) * share
        return int(up * per_s) % (2 ** bits)

    def errors(self, now: float, if_index: int, kind: str) -> int:
        up = max(0.0, now - self.boot(now))
        rate = (h(kind, self.name, if_index) % 40) / 10000.0
        return int(up * rate) % (2 ** 32)

    def snapshot(self) -> dict:
        return {
            "name": self.name, "persona": self.persona_key, "site": self.site,
            "profile": self.profile, "snmp_version": self.snmp_version,
            "alive": self.is_alive(time.time()),
            "requests": self.requests, "gets": self.gets,
            "getnexts": self.getnexts, "getbulks": self.getbulks,
            "drops": self.drops, "last_request_ts": self.last_request_ts,
            "knobs": {
                "alive": self.alive, "v1_only": self.v1_only,
                "auth_fail": self.auth_fail, "slow_ms": self.slow_ms,
                "toobig": self.toobig, "wrap32": self.wrap32,
                "chassis_ports": self.chassis_ports or 0,
                "flapping": sorted(self.flapping), "v3": self.v3,
                "community": self.community,
                "dark_after_s": self.dark_after_s, "dark_for_s": self.dark_for_s,
                "reboot_every_s": self.reboot_every_s,
                "uptime_s": int(time.time() - self.boot(time.time())),
            },
        }


# ------------------------------------------------------- shared builders

SYS = "1.3.6.1.2.1.1"
IF_ENTRY = "1.3.6.1.2.1.2.2.1"
IFX_ENTRY = "1.3.6.1.2.1.31.1.1.1"
DOT1D_BASE_PORT = "1.3.6.1.2.1.17.1.4.1.2"
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2.1"
ENT_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
ENT_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
ENT_ALIAS_MAPPING = "1.3.6.1.2.1.47.1.3.2.1.2"
ENT_SENSOR = "1.3.6.1.2.1.99.1.1.1"
UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"
UCD_MEM_TOTAL = "1.3.6.1.4.1.2021.4.5.0"
UCD_MEM_AVAIL = "1.3.6.1.4.1.2021.4.6.0"
UCD_LOAD1 = "1.3.6.1.4.1.2021.10.1.3.1"


def system_scalars(descr: str, sys_object_id: str, name=None, contact: str = "",
                   location=None, services: int = 78) -> dict:
    """The six SNMPv2-MIB scalars nodeoids.SYSTEM_SCALARS asks for, plus
    sysServices. sysName/sysLocation default to the device's own name and
    site so one table serves every device of the persona."""
    return {
        f"{SYS}.1.0": (T_OCTET_STRING, descr),
        f"{SYS}.2.0": (T_OID, sys_object_id),
        f"{SYS}.3.0": (T_TIMETICKS, lambda st, now: st.uptime_ticks(now)),
        f"{SYS}.4.0": (T_OCTET_STRING, contact or "noc@example.net"),
        f"{SYS}.5.0": (T_OCTET_STRING, name if name is not None
                       else (lambda st, now: st.name)),
        f"{SYS}.6.0": (T_OCTET_STRING, location if location is not None
                       else (lambda st, now: st.site)),
        f"{SYS}.7.0": (T_INTEGER, services),
    }


def if_table(ports, kinds, rates, hc: bool = True, idle_frac: float = 0.0,
             alias=None, mtu: int = 1500) -> dict:
    """ifTable + (optionally) ifXTable for `ports`.

    ports  -- list of ifDescr strings; ifIndex is the position + 1.
    kinds  -- one ifType int, or a list parallel to ports.
    rates  -- one nominal speed in bits/s, or a list parallel to ports.
    hc     -- include the ifXTable 64-bit/high-speed columns. The wrap32
              persona sets this False, which is what forces nodepoll back
              onto the 32-bit ifInOctets column.
    """
    n = len(ports)
    kinds = list(kinds) if isinstance(kinds, (list, tuple)) else [kinds] * n
    rates = list(rates) if isinstance(rates, (list, tuple)) else [rates] * n
    entries: dict = {"1.3.6.1.2.1.2.1.0": (T_INTEGER, n)}
    for pos, descr in enumerate(ports):
        idx = pos + 1
        speed = float(rates[pos])
        name = alias(idx, descr) if alias else ""
        entries[f"{IF_ENTRY}.1.{idx}"] = (T_INTEGER, idx)
        entries[f"{IF_ENTRY}.2.{idx}"] = (T_OCTET_STRING, descr)
        entries[f"{IF_ENTRY}.3.{idx}"] = (T_INTEGER, kinds[pos])
        entries[f"{IF_ENTRY}.4.{idx}"] = (T_INTEGER, mtu)
        # ifSpeed is a Gauge32 in bits/s and saturates at 4294967295 —
        # a 10G port really does report 4294967295 here, which is why
        # ifHighSpeed exists.
        entries[f"{IF_ENTRY}.5.{idx}"] = (T_GAUGE32, min(int(speed), 4294967295))
        entries[f"{IF_ENTRY}.6.{idx}"] = (
            T_OCTET_STRING, (lambda st, now, i=idx: st.mac(i)))
        entries[f"{IF_ENTRY}.7.{idx}"] = (T_INTEGER, 1)          # ifAdminStatus
        entries[f"{IF_ENTRY}.8.{idx}"] = (
            T_INTEGER, (lambda st, now, i=idx: st.oper_status(now, i, idle_frac)))
        entries[f"{IF_ENTRY}.9.{idx}"] = (T_TIMETICKS, 0)        # ifLastChange
        entries[f"{IF_ENTRY}.10.{idx}"] = (
            T_COUNTER32,
            lambda st, now, i=idx, s=speed: st.octets(now, i, s, "in", idle_frac, 32))
        entries[f"{IF_ENTRY}.13.{idx}"] = (
            T_COUNTER32, lambda st, now, i=idx: st.errors(now, i, "indisc"))
        entries[f"{IF_ENTRY}.14.{idx}"] = (
            T_COUNTER32, lambda st, now, i=idx: st.errors(now, i, "inerr"))
        entries[f"{IF_ENTRY}.16.{idx}"] = (
            T_COUNTER32,
            lambda st, now, i=idx, s=speed: st.octets(now, i, s, "out", idle_frac, 32))
        entries[f"{IF_ENTRY}.19.{idx}"] = (
            T_COUNTER32, lambda st, now, i=idx: st.errors(now, i, "outdisc"))
        entries[f"{IF_ENTRY}.20.{idx}"] = (
            T_COUNTER32, lambda st, now, i=idx: st.errors(now, i, "outerr"))
        if hc:
            entries[f"{IFX_ENTRY}.1.{idx}"] = (T_OCTET_STRING, descr)   # ifName
            entries[f"{IFX_ENTRY}.6.{idx}"] = (
                T_COUNTER64,
                lambda st, now, i=idx, s=speed: st.octets(now, i, s, "in", idle_frac, 64))
            entries[f"{IFX_ENTRY}.10.{idx}"] = (
                T_COUNTER64,
                lambda st, now, i=idx, s=speed: st.octets(now, i, s, "out", idle_frac, 64))
            entries[f"{IFX_ENTRY}.15.{idx}"] = (T_GAUGE32, int(speed // 1_000_000))
            entries[f"{IFX_ENTRY}.18.{idx}"] = (T_OCTET_STRING, name)   # ifAlias
    return entries


def ucd_cpu_mem(idle_pct: float, avail_kb: int, total_kb: int) -> dict:
    """UCD-SNMP-MIB CPU/memory — the pair nodepoll turns into the cpu_pct
    and mem_pct gauges. Idle drifts so the graphs are not flat lines."""
    def idle(st, now):
        drift = 12.0 * math.sin(now / 53.0 + (h("cpu", st.name) % 628) / 100.0)
        return int(max(1.0, min(99.0, idle_pct + drift)))

    def avail(st, now):
        drift = 1.0 + 0.08 * math.sin(now / 71.0 + (h("mem", st.name) % 628) / 100.0)
        return int(min(total_kb, avail_kb * drift))

    return {
        UCD_CPU_IDLE: (T_INTEGER, idle),
        UCD_MEM_TOTAL: (T_INTEGER, total_kb),
        UCD_MEM_AVAIL: (T_INTEGER, avail),
        UCD_LOAD1: (T_OCTET_STRING,
                    lambda st, now: f"{(100 - idle(st, now)) / 25.0:.2f}"),
    }


def host_resources(cpus: int, storages) -> dict:
    """HOST-RESOURCES-MIB hrProcessorLoad and hrStorageTable.

    nodeoids.HOST_RESOURCES (nodeoids.py:64-66) names both of these as
    "poll if the vendor OID resolves" scalars — but nothing in the app
    ever reads that constant, so a device answering them today shows no
    CPU and no memory. The personas answer anyway, so the demo can point
    at real data the app is choosing not to collect.

    storages: [(descr, alloc_units, size_units, used_fraction)]
    """
    entries: dict = {}
    for cpu in range(1, cpus + 1):
        entries[f"1.3.6.1.2.1.25.3.3.1.2.{cpu}"] = (
            T_INTEGER,
            lambda st, now, c=cpu: int(max(1, min(99,
                25 + (h("hrcpu", st.name, c) % 30) +
                12 * math.sin(now / 43.0 + c)))))
    for i, (descr, units, size, used) in enumerate(storages, start=1):
        entries[f"1.3.6.1.2.1.25.2.3.1.1.{i}"] = (T_INTEGER, i)
        entries[f"1.3.6.1.2.1.25.2.3.1.2.{i}"] = (T_OID, "1.3.6.1.2.1.25.2.1.2")
        entries[f"1.3.6.1.2.1.25.2.3.1.3.{i}"] = (T_OCTET_STRING, descr)
        entries[f"1.3.6.1.2.1.25.2.3.1.4.{i}"] = (T_INTEGER, units)
        entries[f"1.3.6.1.2.1.25.2.3.1.5.{i}"] = (T_INTEGER, size)
        entries[f"1.3.6.1.2.1.25.2.3.1.6.{i}"] = (
            T_INTEGER,
            lambda st, now, s=size, u=used:
                int(s * min(0.98, u * (1.0 + 0.06 * math.sin(now / 67.0)))))
    return entries


def _mac_arcs(seed: int, n: int) -> list[str]:
    """n deterministic MACs as their own dotted-arc index suffixes — the
    form both FDB tables carry the address in."""
    out = []
    for i in range(n):
        raw = h("fdbmac", seed, i)
        octets = (0x00, 0x1b, (raw >> 16) & 0xFF, (raw >> 8) & 0xFF,
                  raw & 0xFF, (i * 7 + 3) & 0xFF)
        out.append(".".join(str(b) for b in octets))
    return out


def bridge_ports(port_to_if: dict) -> dict:
    """dot1dBasePortIfIndex — the bridge-port -> ifIndex map every
    forwarding-table read in nodepoll needs before the FDB means anything."""
    return {f"{DOT1D_BASE_PORT}.{port}": (T_INTEGER, if_index)
            for port, if_index in port_to_if.items()}


def qbridge_fdb(port_macs: dict, vlan: int = 10) -> dict:
    """dot1qTpFdbPort, indexed <fdbId>.<6 MAC arcs> — the modern table."""
    entries: dict = {}
    for port, macs in port_macs.items():
        for mac in macs:
            entries[f"{DOT1Q_FDB_PORT}.{vlan}.{mac}"] = (T_INTEGER, port)
    return entries


def dot1d_fdb(port_macs: dict) -> dict:
    """dot1dTpFdbPort, indexed by the 6 MAC arcs alone — the classic table."""
    entries: dict = {}
    for port, macs in port_macs.items():
        for mac in macs:
            entries[f"{DOT1D_FDB_PORT}.{mac}"] = (T_INTEGER, port)
    return entries


def vtp_vlans(vlans) -> dict:
    """CISCO-VTP-MIB vtpVlanState — the VLAN list nodepoll walks before it
    tries each `community@vlan` context. 1002-1005 are the legacy VLANs
    the app deliberately skips, so they are here to prove it does."""
    entries = {f"{VTP_VLAN_STATE}.{v}": (T_INTEGER, 1) for v in vlans}
    for legacy in (1002, 1003, 1004, 1005):
        entries[f"{VTP_VLAN_STATE}.{legacy}"] = (T_INTEGER, 1)
    return entries


def entity_sensors(port_sensors: dict) -> dict:
    """ENTITY-MIB + ENTITY-SENSOR-MIB for a handful of optical ports, the
    shape nodepoll.read_dom() expects: entAliasMappingIdentifier ties a
    physical entity to its ifIndex, entPhysicalContainedIn nests each
    sensor under that entity, and entPhySensor* carries the reading.

    port_sensors: {if_index: [(label, sensor_type, units, base_value, swing)]}
    """
    entries: dict = {}
    for if_index, sensors in port_sensors.items():
        port_entity = 1000 + if_index
        entries[f"{ENT_DESCR}.{port_entity}"] = (
            T_OCTET_STRING, f"SFP+ transceiver, port {if_index}")
        entries[f"{ENT_CONTAINED_IN}.{port_entity}"] = (T_INTEGER, 1)
        entries[f"{ENT_ALIAS_MAPPING}.{port_entity}.0"] = (
            T_OID, f"1.3.6.1.2.1.2.2.1.1.{if_index}")
        for slot, (label, stype, units, base, swing) in enumerate(sensors, start=1):
            entity = 10000 + if_index * 10 + slot
            entries[f"{ENT_DESCR}.{entity}"] = (T_OCTET_STRING, label)
            entries[f"{ENT_CONTAINED_IN}.{entity}"] = (T_INTEGER, port_entity)
            entries[f"{ENT_SENSOR}.1.{entity}"] = (T_INTEGER, stype)
            entries[f"{ENT_SENSOR}.2.{entity}"] = (T_INTEGER, 9)     # units (10^0)
            entries[f"{ENT_SENSOR}.3.{entity}"] = (T_INTEGER, 3)     # 3 decimals
            entries[f"{ENT_SENSOR}.4.{entity}"] = (
                T_INTEGER,
                lambda st, now, b=base, s=swing, e=entity:
                    int(round((b + s * math.sin(now / 29.0 + (h("dom", st.name, e) % 628) / 100.0)) * 1000)))
            entries[f"{ENT_SENSOR}.5.{entity}"] = (T_INTEGER, 1)     # ok
            entries[f"{ENT_SENSOR}.6.{entity}"] = (T_OCTET_STRING, units)
    return entries


def arc_objects(arc: int, extra_scalars: dict | None = None) -> dict:
    """A couple of objects under the vendor's own enterprise arc, so
    vendorid.hop_enterprise_arcs() finds something when it hops from
    1.3.6.1.4.1 — a device that answers nothing under its own arc looks
    like a device with no vendor MIB at all."""
    root = f"1.3.6.1.4.1.{arc}"
    entries = {
        f"{root}.1.1.1.0": (T_OCTET_STRING, f"enterprise {arc} agent"),
        f"{root}.1.1.2.0": (T_TIMETICKS, lambda st, now: st.uptime_ticks(now)),
    }
    entries.update(extra_scalars or {})
    return entries


# --------------------------------------------------------------- personas

def _gig_ports(count: int, uplinks: int, uplink_kind: str = "TenGigabitEthernet",
               prefix: str = "GigabitEthernet"):
    ports = [f"{prefix}1/0/{i}" for i in range(1, count + 1)]
    ports += [f"{uplink_kind}1/1/{i}" for i in range(1, uplinks + 1)]
    kinds = [6] * (count + uplinks)
    rates = [1_000_000_000] * count + [10_000_000_000] * uplinks
    return ports, kinds, rates


def _switch_fdb_ports(access_count: int, macs_per_port: int, seed_name: str):
    """{bridge port -> [mac arcs]} and {bridge port -> ifIndex}. Bridge port
    numbers deliberately differ from ifIndex — conflating the two is the
    classic FDB bug, and this makes the app prove it does not."""
    port_macs = {}
    port_to_if = {}
    for i in range(1, access_count + 1):
        bridge_port = 100 + i
        port_to_if[bridge_port] = i
        port_macs[bridge_port] = _mac_arcs(h(seed_name, i), macs_per_port)
    return port_macs, port_to_if


CISCO_ACCESS_DESCR = (
    "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
    "Version 15.2(7)E3, RELEASE SOFTWARE (fc2), Copyright (c) 1986-2021 by "
    "Cisco Systems, Inc.")
CISCO_CORE_DESCR = (
    "Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software "
    "(CAT9K_IOSXE), Version 17.3.5, RELEASE SOFTWARE (fc1)")

DOM_SENSORS = [
    ("Transceiver temperature", 8, "C", 41.0, 3.5),
    ("Transceiver supply voltage", 4, "V", 3.28, 0.04),
    ("Transceiver bias current", 5, "mA", 0.0072, 0.0004),
    ("Transceiver tx power", 1, "dBm", -2.4, 0.5),
    ("Transceiver rx power", 1, "dBm", -5.8, 1.4),
]


def _build_cisco_access(wrap32: bool, ports: int, vlan: str | None) -> dict:
    access = 48
    names, kinds, rates = _gig_ports(access, 2)
    entries = system_scalars(CISCO_ACCESS_DESCR, "1.3.6.1.4.1.9.1.1208")
    entries.update(if_table(names, kinds, rates, hc=not wrap32, idle_frac=0.22,
                            alias=lambda i, d: (f"uplink to core" if i > access
                                                else f"access port {i}")))
    port_macs, port_to_if = _switch_fdb_ports(access, 4, "access")
    entries.update(bridge_ports(port_to_if))
    entries.update(qbridge_fdb(port_macs, vlan=10))
    entries.update(entity_sensors({access + 1: DOM_SENSORS,
                                   access + 2: DOM_SENSORS}))
    entries.update(host_resources(1, [("Physical memory", 1024, 524288, 0.61)]))
    entries.update(arc_objects(9, {
        # CISCO-PROCESS-MIB cpmCPUTotal5minRev, one of the two objects an
        # operator would actually chart on IOS.
        "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": (
            T_GAUGE32, lambda st, now: 12 + (h("cpu5", st.name) % 30)),
        "1.3.6.1.4.1.9.9.48.1.1.1.5.1": (
            T_GAUGE32, lambda st, now: 90_000_000 + (h("memfree", st.name) % 40_000_000)),
    }))
    return entries


def _build_cisco_core(wrap32: bool, ports: int, vlan: str | None) -> dict:
    access = max(8, (ports or 96) - 8)
    uplinks = 8
    names = [f"GigabitEthernet1/0/{i}" for i in range(1, access + 1)]
    names += [f"TenGigabitEthernet1/1/{i}" for i in range(1, uplinks + 1)]
    kinds = [6] * (access + uplinks)
    rates = [1_000_000_000] * access + [10_000_000_000] * uplinks
    entries = system_scalars(CISCO_CORE_DESCR, "1.3.6.1.4.1.9.1.2494")
    entries.update(if_table(names, kinds, rates, hc=not wrap32, idle_frac=0.08,
                            alias=lambda i, d: ("core uplink" if i > access
                                                else f"downlink {i}"),
                            mtu=9216))
    port_macs, port_to_if = _switch_fdb_ports(access + uplinks, 6, "core")
    entries.update(bridge_ports(port_to_if))
    entries.update(vtp_vlans(CORE_VLANS))
    entries.update(entity_sensors({access + i: DOM_SENSORS
                                   for i in range(1, uplinks + 1)}))
    entries.update(host_resources(2, [("Physical memory", 1024, 2097152, 0.48)]))
    entries.update(arc_objects(9, {
        "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": (
            T_GAUGE32, lambda st, now: 20 + (h("cpu5", st.name) % 40)),
    }))
    if vlan is not None:
        # Classic IOS: the bridge table only exists inside a per-VLAN
        # community context. Each VLAN shows a slice of the MACs.
        slice_macs = {port: macs[(int(vlan) // 10) % len(macs):][:2]
                      for port, macs in port_macs.items()}
        entries.update(dot1d_fdb(slice_macs))
    return entries


CORE_VLANS = (10, 20, 30, 40, 50)


def _build_aruba(wrap32: bool, ports: int, vlan: str | None) -> dict:
    count = 24
    names = [f"1/{i}" for i in range(1, count + 1)]
    entries = system_scalars(
        "Aruba JL258A 2930F-8G-PoE+-2SFP+ Switch, revision WC.16.10.0021, "
        "ROM WC.16.01.0006 (/ws/swbuildm/rel_ukiah_qaoff)",
        "1.3.6.1.4.1.14823.1.2.104")
    entries.update(if_table(names, 6, 1_000_000_000, hc=not wrap32, idle_frac=0.3,
                            alias=lambda i, d: f"port {i}"))
    port_macs, port_to_if = _switch_fdb_ports(count, 3, "aruba")
    entries.update(bridge_ports(port_to_if))
    entries.update(dot1d_fdb(port_macs))
    entries.update(arc_objects(14823, {
        "1.3.6.1.4.1.14823.2.2.1.1.1.9.0": (
            T_INTEGER, lambda st, now: 15 + (h("acpu", st.name) % 35)),
    }))
    return entries


def _build_fortigate(wrap32: bool, ports: int, vlan: str | None) -> dict:
    names = ["port1", "port2", "port3", "port4", "port5", "wan1", "wan2"]
    entries = system_scalars(
        "FortiGate-60F v7.2.5,build1517,230606 (GA.M)",
        "1.3.6.1.4.1.12356.101.1.6001")
    entries.update(if_table(names, 6, 1_000_000_000, hc=not wrap32,
                            alias=lambda i, d: ("internet" if i > 5 else f"lan {i}")))
    entries.update(host_resources(2, [("Physical memory", 1024, 2097152, 0.55),
                                      ("/data", 4096, 1048576, 0.31)]))
    entries.update(arc_objects(12356, {
        # Real Fortinet scalars the app does NOT poll — here so a demo can
        # show that a FortiGate's session count and CPU are invisible to
        # SappiWhere unless somebody adds them as a custom MIB object.
        "1.3.6.1.4.1.12356.101.4.1.3.0": (            # fgSysCpuUsage
            T_GAUGE32, lambda st, now: 8 + (h("fgcpu", st.name) % 25)),
        "1.3.6.1.4.1.12356.101.4.1.4.0": (            # fgSysMemUsage
            T_GAUGE32, lambda st, now: 40 + (h("fgmem", st.name) % 30)),
        "1.3.6.1.4.1.12356.101.4.1.8.0": (            # fgSysSesCount
            T_GAUGE32,
            lambda st, now: 2000 + int(900 * math.sin(now / 61.0)) +
            (h("fgses", st.name) % 4000)),
        "1.3.6.1.4.1.12356.101.12.2.2.1.1.1": (       # fgVpnTunEntIndex
            T_INTEGER, 1),
        "1.3.6.1.4.1.12356.101.12.2.2.1.2.1": (       # fgVpnTunEntPhase1Name
            T_OCTET_STRING, "branch-to-hq"),
        "1.3.6.1.4.1.12356.101.12.2.2.1.20.1": (      # fgVpnTunEntStatus
            T_INTEGER, 2),
    }))
    return entries


def _build_paloalto(wrap32: bool, ports: int, vlan: str | None) -> dict:
    names = [f"ethernet1/{i}" for i in range(1, 9)]
    entries = system_scalars(
        "Palo Alto Networks PA-3220 series firewall", "1.3.6.1.4.1.25461.2.3.28")
    entries.update(if_table(names, 6, 1_000_000_000, hc=not wrap32,
                            alias=lambda i, d: f"zone-{i}"))
    entries.update(host_resources(4, [("Physical memory", 1024, 8388608, 0.42),
                                      ("/opt/panlogs", 4096, 4194304, 0.66)]))
    entries.update(arc_objects(25461, {
        "1.3.6.1.4.1.25461.2.1.2.1.1.0": (T_OCTET_STRING, "PA-3220"),
        "1.3.6.1.4.1.25461.2.1.2.1.3.0": (T_OCTET_STRING, "10.2.6-h3"),
        "1.3.6.1.4.1.25461.2.1.2.3.1.0": (            # panSessionUtilization
            T_GAUGE32, lambda st, now: 10 + (h("panu", st.name) % 40)),
        "1.3.6.1.4.1.25461.2.1.2.3.3.0": (            # panSessionActive
            T_GAUGE32,
            lambda st, now: 5000 + int(2500 * math.sin(now / 47.0)) +
            (h("pans", st.name) % 9000)),
    }))
    return entries


def _build_juniper(wrap32: bool, ports: int, vlan: str | None) -> dict:
    names = [f"ge-0/0/{i}" for i in range(0, 24)] + ["xe-0/1/0", "xe-0/1/1"]
    kinds = [6] * 26
    rates = [1_000_000_000] * 24 + [10_000_000_000] * 2
    entries = system_scalars(
        "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS "
        "20.4R3-S4.8, Build date: 2022-04-21", "1.3.6.1.4.1.2636.1.1.1.2.82")
    entries.update(if_table(names, kinds, rates, hc=not wrap32, idle_frac=0.2,
                            alias=lambda i, d: f"access {i}"))
    entries.update(arc_objects(2636, {
        "1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0": (      # jnxOperatingCPU
            T_INTEGER, lambda st, now: 5 + (h("jcpu", st.name) % 35)),
        "1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0": (     # jnxOperatingBuffer
            T_INTEGER, lambda st, now: 30 + (h("jbuf", st.name) % 40)),
    }))
    return entries


def _build_airfiber(wrap32: bool, ports: int, vlan: str | None) -> dict:
    entries = system_scalars(
        "Ubiquiti airFiber AF-11FX, firmware 4.1.3, Linux 3.6.5",
        "1.3.6.1.4.1.41112.1.3")
    entries.update(if_table(["eth0", "rf0"], [6, 6],
                            [1_000_000_000, 1_200_000_000], hc=not wrap32,
                            alias=lambda i, d: ("radio link" if i == 2 else "lan")))

    def fade(base, swing, key):
        def value(st, now):
            phase = (h(key, st.name) % 628) / 100.0
            weather = math.sin(now / 97.0 + phase) * swing
            return int(round(base + weather))
        return value

    entries.update(arc_objects(41112, {
        "1.3.6.1.4.1.41112.1.3.2.1.1.0": (T_INTEGER, fade(-58, 7, "rssi")),
        "1.3.6.1.4.1.41112.1.3.2.1.2.0": (T_INTEGER, fade(28, 6, "snr")),
        "1.3.6.1.4.1.41112.1.3.2.1.3.0": (T_GAUGE32, fade(700_000_000, 180_000_000,
                                                          "cap")),
        "1.3.6.1.4.1.41112.1.3.2.1.4.0": (T_INTEGER, fade(-61, 7, "remrssi")),
        "1.3.6.1.4.1.41112.1.3.2.1.5.0": (T_OCTET_STRING, "11GHz-FDD"),
    }))
    return entries


def _build_cambium(wrap32: bool, ports: int, vlan: str | None) -> dict:
    entries = system_scalars(
        "Cambium Networks PTP 670 Series, software 50-06-05",
        "1.3.6.1.4.1.17713.21.1.1")
    entries.update(if_table(["eth1", "wireless"], [6, 6],
                            [1_000_000_000, 450_000_000], hc=not wrap32,
                            alias=lambda i, d: ("PTP link" if i == 2 else "lan")))

    def drift(base, swing, key):
        def value(st, now):
            phase = (h(key, st.name) % 628) / 100.0
            return int(round(base + swing * math.sin(now / 83.0 + phase)))
        return value

    entries.update(arc_objects(17713, {
        "1.3.6.1.4.1.17713.21.1.2.1.0": (T_INTEGER, drift(-52, 6, "crx")),
        "1.3.6.1.4.1.17713.21.1.2.2.0": (T_INTEGER, drift(112, 5, "closs")),
        "1.3.6.1.4.1.17713.21.1.2.3.0": (T_GAUGE32, drift(320_000_000, 90_000_000,
                                                          "ccap")),
        "1.3.6.1.4.1.17713.21.1.2.4.0": (T_INTEGER, drift(-31, 4, "cvec")),
        "1.3.6.1.4.1.17713.21.1.2.5.0": (T_OCTET_STRING, "5.8 GHz / 40 MHz"),
    }))
    return entries


def _wtp_suffix(vdom: str, wtp_id: str) -> str:
    """The fgWc index shape: vdom, then the WTP id as a length-prefixed run
    of character arcs (see tests/stubs/wireless_stub_agent.py)."""
    chars = ".".join(str(ord(c)) for c in wtp_id)
    return f"{vdom}.{len(wtp_id)}.{chars}"


AP_NAMES = ["Lobby", "Reception", "Warehouse-N", "Warehouse-S", "Office-1",
            "Office-2", "Canteen", "Loading-Bay", "Meeting-A", "Meeting-B",
            "Yard", "Server-Room"]


def _build_fortigate_wlc(wrap32: bool, ports: int, vlan: str | None) -> dict:
    entries = system_scalars(
        "FortiGate-100F v7.2.8,build1639,240110 (GA.M) wireless-controller",
        "1.3.6.1.4.1.12356.101.1.10040")
    entries.update(if_table(["port1", "port2", "port3", "port4"], 6,
                            1_000_000_000, hc=not wrap32,
                            alias=lambda i, d: f"ap segment {i}"))
    offline = {"AP0003", "AP0011"}
    for n, label in enumerate(AP_NAMES, start=1):
        wtp_id = f"AP{n:04d}"
        suffix = _wtp_suffix("1", wtp_id)
        online = wtp_id not in offline
        mac = bytes((0x00, 0x11, 0x93, 0x00, (n >> 8) & 0xFF, n & 0xFF))
        entries[f"{fgoids.WTP_CONFIG_NAME}.{suffix}"] = (
            T_OCTET_STRING, f"{label}-AP")
        entries[f"{fgoids.WTP_SESSION_IP}.{suffix}"] = (
            T_OCTET_STRING, f"10.90.0.{10 + n}")
        entries[f"{fgoids.WTP_SESSION_MAC}.{suffix}"] = (T_OCTET_STRING, mac)
        entries[f"{fgoids.WTP_SESSION_CONNECTION_STATE}.{suffix}"] = (
            T_INTEGER, 2 if online else 1)
        entries[f"{fgoids.WTP_SESSION_MODEL}.{suffix}"] = (
            T_OCTET_STRING, "FAP-231F")
        entries[f"{fgoids.WTP_SESSION_STATION_COUNT}.{suffix}"] = (
            T_GAUGE32,
            (lambda st, now, k=n: 0) if not online else
            (lambda st, now, k=n: max(0, 8 + (h("clients", st.name, k) % 22) +
                                      int(6 * math.sin(now / 41.0 + k)))))
        for radio in (1, 2):
            rsuffix = f"{suffix}.{radio}"
            channel = (1, 6, 11)[n % 3] if radio == 1 else (36, 44, 149)[n % 3]
            entries[f"{fgoids.WTP_RADIO_MODE}.{rsuffix}"] = (T_INTEGER, 3)
            entries[f"{fgoids.WTP_RADIO_CHANNEL}.{rsuffix}"] = (T_INTEGER, channel)
            # Deliberately in FortiOS's own 0-100 "power level" units, not
            # dBm — the exact mismatch fortipoll.py auto-detects.
            entries[f"{fgoids.WTP_RADIO_OPERATING_POWER}.{rsuffix}"] = (
                T_INTEGER, 51 if radio == 1 else 44)
            entries[f"{fgoids.WTP_RADIO_STATION_COUNT}.{rsuffix}"] = (
                T_GAUGE32,
                (lambda st, now, k=n, r=radio: 0) if not online else
                (lambda st, now, k=n, r=radio:
                    max(0, 4 + (h("rclients", st.name, k, r) % 12) +
                        int(3 * math.sin(now / 37.0 + k + r)))))
    entries.update(arc_objects(12356, {
        "1.3.6.1.4.1.12356.101.4.1.3.0": (
            T_GAUGE32, lambda st, now: 14 + (h("wlccpu", st.name) % 20)),
        "1.3.6.1.4.1.12356.101.4.1.4.0": (
            T_GAUGE32, lambda st, now: 52 + (h("wlcmem", st.name) % 18)),
    }))
    return entries


def _build_mikrotik(wrap32: bool, ports: int, vlan: str | None) -> dict:
    names = [f"sfp-sfpplus{i}" for i in range(1, 13)] + ["ether1"]
    kinds = [6] * 13
    rates = [10_000_000_000] * 12 + [1_000_000_000]
    entries = system_scalars(
        "RouterOS CCR2004-1G-12S+2XS", "1.3.6.1.4.1.14988.1")
    entries.update(if_table(names, kinds, rates, hc=not wrap32, idle_frac=0.35,
                            alias=lambda i, d: f"link {i}"))
    entries.update(ucd_cpu_mem(78.0, 380_000, 1_024_000))
    entries.update(host_resources(4, [("Physical memory", 1024, 1024000, 0.63)]))
    entries.update(arc_objects(14988, {
        "1.3.6.1.4.1.14988.1.1.3.100.1.3.1": (        # mtxrHlTemperature
            T_INTEGER, lambda st, now: 380 + (h("mttemp", st.name) % 90)),
        "1.3.6.1.4.1.14988.1.1.7.4.0": (              # mtxrLicVersion
            T_OCTET_STRING, "7.11.2"),
    }))
    return entries


def _build_scalance(wrap32: bool, ports: int, vlan: str | None) -> dict:
    names = [f"P0.{i}" for i in range(1, 9)]
    entries = system_scalars(
        "Siemens, SIMATIC NET, SCALANCE XC208, 6GK5 208-0BA00-2AC2, "
        "HW: 3, FW: V4.4", "1.3.6.1.4.1.4196.1.1.5.2.22")
    entries.update(if_table(names, 6, 100_000_000, hc=not wrap32, idle_frac=0.3,
                            alias=lambda i, d: f"cell port {i}"))
    port_macs, port_to_if = _switch_fdb_ports(8, 2, "scalance")
    entries.update(bridge_ports(port_to_if))
    entries.update(dot1d_fdb(port_macs))
    entries.update(arc_objects(4196, {
        "1.3.6.1.4.1.4196.1.1.5.3.1.1.0": (T_INTEGER, 1),      # power supply 1 ok
        "1.3.6.1.4.1.4196.1.1.5.3.1.2.0": (T_INTEGER, 2),      # power supply 2 failed
    }))
    return entries


def _build_moxa(wrap32: bool, ports: int, vlan: str | None) -> dict:
    names = [f"Port {i}" for i in range(1, 9)]
    entries = system_scalars(
        "Moxa EDS-408A-MM-SC Managed Redundant Switch, V3.9 build 19061410",
        "1.3.6.1.4.1.8691.7.6")
    entries.update(if_table(names, 6, 100_000_000, hc=not wrap32, idle_frac=0.25,
                            alias=lambda i, d: f"field port {i}"))
    port_macs, port_to_if = _switch_fdb_ports(8, 2, "moxa")
    entries.update(bridge_ports(port_to_if))
    entries.update(dot1d_fdb(port_macs))
    entries.update(arc_objects(8691, {
        "1.3.6.1.4.1.8691.7.6.1.1.1.0": (T_OCTET_STRING, "EDS-408A-MM-SC"),
        "1.3.6.1.4.1.8691.7.6.1.1.5.0": (T_INTEGER, 1),        # turbo ring healthy
    }))
    return entries


def _build_rockwell(wrap32: bool, ports: int, vlan: str | None) -> dict:
    # sysObjectID names net-snmp, not Rockwell: identification has to come
    # off sysDescr (nodeoids.identify_vendor's GENERIC_AGENT_VENDORS path).
    entries = system_scalars(
        "Rockwell Automation 1756-EN2T/B EtherNet/IP Bridge, Rev 11.003, "
        "Serial 00C0FFEE", "1.3.6.1.4.1.8072.3.2.10")
    entries.update(if_table(["Backplane", "Port1"], [53, 6],
                            [100_000_000, 100_000_000], hc=not wrap32,
                            alias=lambda i, d: "controlnet" if i == 1 else "plant lan"))
    entries.update(arc_objects(8072))
    return entries


def _build_s7_plc(wrap32: bool, ports: int, vlan: str | None) -> dict:
    entries = system_scalars(
        "Siemens SIMATIC S7-1500 CPU 1516-3 PN/DP, FW V2.9.2",
        "1.3.6.1.4.1.4196.1.1.1.1")
    entries.update(if_table(["X1 P1", "X1 P2"], 6, [100_000_000, 100_000_000],
                            hc=not wrap32,
                            alias=lambda i, d: f"profinet {i}"))
    entries.update(arc_objects(4196, {
        "1.3.6.1.4.1.4196.1.1.1.2.1.0": (T_OCTET_STRING, "RUN"),
    }))
    return entries


def _build_linux(wrap32: bool, ports: int, vlan: str | None) -> dict:
    entries = system_scalars(
        "Linux app-host 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 "
        "13:30:08 UTC 2023 x86_64", "1.3.6.1.4.1.8072.3.2.10", services=72)
    entries.update(if_table(["lo", "ens192"], [24, 6],
                            [10_000_000, 1_000_000_000], hc=not wrap32,
                            alias=lambda i, d: "loopback" if i == 1 else "vmnic"))
    entries.update(ucd_cpu_mem(64.0, 2_400_000, 8_192_000))
    entries.update(host_resources(8, [("Physical memory", 1024, 8192000, 0.71),
                                      ("/", 4096, 26214400, 0.44)]))
    entries.update(arc_objects(8072, {
        "1.3.6.1.4.1.8072.1.3.2.2.1.2.1": (T_OCTET_STRING, "nagios-check"),
    }))
    return entries


PERSONAS: dict[str, Persona] = {
    "cisco_access": Persona("cisco_access", _build_cisco_access, 50,
                            "Cisco 2960X access switch"),
    "cisco_core": CiscoVlanPersona("cisco_core", _build_cisco_core, 96,
                                   "Cisco 9500 core switch",
                                   tuple(str(v) for v in CORE_VLANS)),
    "aruba_switch": Persona("aruba_switch", _build_aruba, 24, "Aruba 2930F"),
    "fortigate": Persona("fortigate", _build_fortigate, 7, "FortiGate 60F"),
    "paloalto": Persona("paloalto", _build_paloalto, 8, "Palo Alto PA-3220"),
    "juniper": Persona("juniper", _build_juniper, 26, "Juniper EX4300"),
    "ubiquiti_airfiber": Persona("ubiquiti_airfiber", _build_airfiber, 2,
                                 "Ubiquiti airFiber AF-11FX"),
    "cambium_ptp": Persona("cambium_ptp", _build_cambium, 2, "Cambium PTP 670"),
    "fortigate_wlc": Persona("fortigate_wlc", _build_fortigate_wlc, 4,
                             "FortiGate 100F wireless controller"),
    "mikrotik": Persona("mikrotik", _build_mikrotik, 13, "MikroTik CCR2004"),
    "siemens_scalance": Persona("siemens_scalance", _build_scalance, 8,
                                "Siemens SCALANCE XC208"),
    "moxa": Persona("moxa", _build_moxa, 8, "Moxa EDS-408A"),
    "rockwell_plc": Persona("rockwell_plc", _build_rockwell, 2,
                            "Rockwell 1756-EN2T"),
    "siemens_s7_plc": Persona("siemens_s7_plc", _build_s7_plc, 2,
                              "Siemens S7-1500"),
    "linux_host": Persona("linux_host", _build_linux, 2, "Linux host"),
}


# ------------------------------------------------------------------- fleet

SITES = ("Site-A", "Site-B", "Site-C")

PROFILES: dict[str, dict] = {
    "v2c-public": {"snmp_version": 1, "community": "public"},
    "v1-public": {"snmp_version": 0, "community": "public"},
    "v3-noauth": {"snmp_version": 3, "v3_user": "poller"},
    "v3-sha": {"snmp_version": 3, "v3_user": "poller",
               "v3_auth_proto": "SHA",
               "v3_auth_password": "correct horse battery staple"},
}

# index -> the one thing this device exists to demonstrate. The seed script
# reads this to label the devices it creates, and the demo script drives it.
SPECIALS: dict[int, dict] = {
    2: {"persona": "cisco_access", "profile": "v1-public", "knob": "v1_only",
        "note": "answers SNMPv1 framing only; a GETBULK gets a v1 error, "
                "so nodepoll._walk_column must fall back to GETNEXT"},
    3: {"persona": "cisco_access", "profile": "v2c-public",
        "knob": "community=secret42",
        "note": "device community is secret42 while the profile says public "
                "— every poll times out, exactly like real gear"},
    4: {"persona": "cisco_access", "profile": "v2c-public", "knob": "auth_fail",
        "note": "answers error_status=16 authorizationError; nodepoll raises "
                "_AuthFailure and the device shows status 'auth'"},
    5: {"persona": "cisco_access", "profile": "v2c-public", "knob": "slow_ms=2600",
        "note": "replies 2.6 s late — inside a 3 s timeout, outside a 2 s one"},
    6: {"persona": "cisco_access", "profile": "v2c-public", "knob": "toobig",
        "note": "GETBULK with max_repetitions > 8 gets error_status=1 tooBig; "
                "exercises _walk_column's halve-and-retry"},
    7: {"persona": "cisco_access", "profile": "v2c-public", "knob": "wrap32",
        "note": "no ifXTable at all and a rate that laps a 32-bit octet "
                "counter every ~60 s"},
    8: {"persona": "cisco_core", "profile": "v2c-public", "knob": "chassis_ports=500",
        "note": "500 interfaces — nodepoll._poll_interfaces caps at 512 and "
                "makes one GET per interface"},
    9: {"persona": "cisco_access", "profile": "v3-noauth", "knob": "v3=noauth",
        "note": "SNMPv3 noAuthNoPriv, user 'poller' (engine discovery first)"},
    10: {"persona": "cisco_access", "profile": "v3-sha", "knob": "v3=sha",
         "note": "SNMPv3 authNoPriv HMAC-SHA1-96, user 'poller', password "
                 "'correct horse battery staple'"},
    11: {"persona": "cisco_access", "profile": "v2c-public",
         "knob": "dark_after_s=120,dark_for_s=180",
         "note": "goes dark 120 s in for 180 s, every 300 s thereafter"},
    12: {"persona": "cisco_access", "profile": "v2c-public",
         "knob": "reboot_every_s=240",
         "note": "sysUpTime resets every 240 s — nodepoll.detect_reboot fires"},
    # A plain, healthy access switch by SNMP — its only special property is
    # its IP. demo/fake_ssh.py binds exclusively to 127.0.0.1, and Nodes
    # requires a unique IP per device, so this is the one device seed.py and
    # scenario.py can point at a real SSH persona (re-pointing its ssh_port
    # and vendor_override across the fake_ssh personas they want to exercise,
    # one at a time) to walk ConfigRX's platforms and enable-mode escalation
    # against something that actually answers, instead of only configuring
    # vendor overrides nothing ever connects to.
    13: {"persona": "cisco_access", "profile": "v2c-public", "knob": "",
         "name": "configrx-ssh-01", "ip": "127.0.0.1",
         "note": "the ConfigRX SSH demo device — normal SNMP, but its IP is "
                 "demo/fake_ssh.py's only bind address"},
}

# The last index SPECIALS occupies; the weighted mix starts one past it.
_FIXED_INDEX_MAX = max(SPECIALS)

# One 100-slot cycle of the weighted mix used from index _FIXED_INDEX_MAX+1 on.
_MIX_WEIGHTS = (
    ("cisco_access", 55), ("aruba_switch", 8), ("fortigate", 5),
    ("paloalto", 3), ("juniper", 3), ("ubiquiti_airfiber", 5),
    ("cambium_ptp", 3), ("mikrotik", 4), ("siemens_scalance", 4),
    ("moxa", 3), ("rockwell_plc", 3), ("siemens_s7_plc", 2),
    ("linux_host", 2),
)

_NAME_PREFIX = {
    "cisco_access": "acc-sw", "cisco_core": "core-sw", "aruba_switch": "aru-sw",
    "fortigate": "fw", "paloalto": "pan-fw", "juniper": "jnpr-sw",
    "ubiquiti_airfiber": "ptp", "cambium_ptp": "cmb", "mikrotik": "mt-rtr",
    "siemens_scalance": "scal-sw", "moxa": "moxa-sw", "rockwell_plc": "plc-ab",
    "siemens_s7_plc": "plc-s7", "linux_host": "srv", "fortigate_wlc": "wlc",
}


def _mix_cycle() -> list[str]:
    """The 100-slot persona cycle, spread rather than blocked so a fleet of
    any size gets a representative mix. Deterministic: a fixed shuffle
    seed, so run N twice and every device keeps its identity."""
    import random
    slots: list[str] = []
    for key, weight in _MIX_WEIGHTS:
        slots.extend([key] * weight)
    random.Random(20260902).shuffle(slots)
    return slots


_CYCLE = _mix_cycle()


def ip_for(index: int) -> str:
    """127.0.x.y, 250 devices per /24 — index 0 is 127.0.0.2."""
    return "127.0.%d.%d" % (index // 250, index % 250 + 2)


def _site_for(index: int, persona: str, access_seen: int) -> str:
    if index <= _FIXED_INDEX_MAX:
        return "Site-A"
    if persona == "cisco_access":
        # The first 500 access switches hang off the core at Site-A; the
        # rest are the remote sites.
        return "Site-A" if access_seen < 500 else SITES[1 + (index % 2)]
    return SITES[index % 3]


def fleet_plan(count: int) -> list[dict]:
    """The whole fleet, deterministically.

    Returns a list of dicts, one per device::

        {"index": int, "ip": "127.0.x.y", "name": str, "persona": str,
         "site": str, "snmp_version": 0|1|3, "community": str,
         "profile": str, "knobs": {...}}

    `community` is what the DEVICE accepts, which is not always what the
    profile configures — index 3 exists precisely to show the difference.
    Index 0 is the core switch, index 1 the wireless controller, indices
    2..13 are SPECIALS (13 is the ConfigRX SSH demo device), and everything
    after is the weighted mix.
    """
    count = max(1, int(count))
    plan: list[dict] = []
    counters: dict[str, int] = {}
    access_seen = 0

    for index in range(count):
        if index == 0:
            persona, name, profile = "cisco_core", "core-sw-01", "v2c-public"
        elif index == 1:
            persona, name, profile = "fortigate_wlc", "wlc-01", "v2c-public"
        elif index in SPECIALS:
            spec = SPECIALS[index]
            persona, profile = spec["persona"], spec["profile"]
            name = spec.get("name")
        else:
            persona = _CYCLE[(index - (_FIXED_INDEX_MAX + 1)) % len(_CYCLE)]
            profile, name = "v2c-public", None

        if name is None:
            counters[persona] = counters.get(persona, 0) + 1
            width = 3 if persona == "cisco_access" else 2
            name = f"{_NAME_PREFIX[persona]}-{counters[persona]:0{width}d}"
        else:
            counters[persona] = counters.get(persona, 0) + 1

        if persona == "cisco_access":
            access_seen += 1

        knobs: dict = {}
        community = "public"
        settings = PROFILES[profile]
        version = settings["snmp_version"]

        if index in SPECIALS:
            knob = SPECIALS[index]["knob"]
            if knob == "v1_only":
                knobs["v1_only"] = True
            elif knob.startswith("community="):
                community = knob.split("=", 1)[1]
            elif knob == "auth_fail":
                knobs["auth_fail"] = True
            elif knob.startswith("slow_ms="):
                knobs["slow_ms"] = int(knob.split("=", 1)[1])
            elif knob == "toobig":
                knobs["toobig"] = True
            elif knob == "wrap32":
                knobs["wrap32"] = True
            elif knob.startswith("chassis_ports="):
                knobs["chassis_ports"] = int(knob.split("=", 1)[1])
            elif knob == "v3=noauth":
                knobs["v3"] = "noauth"
            elif knob == "v3=sha":
                knobs["v3"] = "sha"
            elif knob.startswith("dark_after_s="):
                knobs["dark_after_s"] = 120
                knobs["dark_for_s"] = 180
                knobs["dark_every_s"] = 300
            elif knob.startswith("reboot_every_s="):
                knobs["reboot_every_s"] = 240

        if version == 3:
            knobs.setdefault("v3", "sha" if profile == "v3-sha" else "noauth")
            knobs["v3_user"] = settings["v3_user"]
            knobs["v3_password"] = settings.get("v3_auth_password", "")

        # A handful of flapping ports out in the fleet, so "something is
        # wrong somewhere" is discoverable rather than staged.
        if (index > _FIXED_INDEX_MAX and persona == "cisco_access"
                and index % 37 == 0):
            knobs["flapping"] = [3 + (index % 40)]

        ip = (SPECIALS[index]["ip"] if index in SPECIALS and "ip" in SPECIALS[index]
              else ip_for(index))
        plan.append({
            "index": index,
            "ip": ip,
            "name": name,
            "persona": persona,
            "site": _site_for(index, persona, access_seen),
            "snmp_version": version,
            "community": community,
            "profile": profile,
            "knobs": knobs,
        })
    return plan


def build_device(entry: dict) -> DeviceState:
    """One runnable device from a fleet_plan() entry."""
    return DeviceState(entry, PERSONAS[entry["persona"]])


if __name__ == "__main__":
    plan = fleet_plan(40)
    counts: dict[str, int] = {}
    for row in plan:
        counts[row["persona"]] = counts.get(row["persona"], 0) + 1
    print(f"{len(plan)} devices, {len(counts)} personas")
    for row in plan[:14]:
        print(f"  {row['index']:>3} {row['ip']:<12} {row['name']:<12} "
              f"{row['persona']:<18} {row['profile']:<11} {row['site']}")
    for key, persona in PERSONAS.items():
        table = persona.table()
        print(f"  {key:<20} {len(table):>5} OIDs")
