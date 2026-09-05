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
        indices 2..29 are the fixed SPECIALS below (13 is the ConfigRX SSH
        demo device, pinned to 127.0.0.1). Everything from 30 on is a
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
from netpath.nodeoids import (                        # noqa: E402
    CDP_CACHE_ADDRESS, CDP_CACHE_DEVICE_ID, CDP_CACHE_DEVICE_PORT,
    CDP_CACHE_PLATFORM, CISCO_POE_PORT_POWER_MW, DOT1D_STP_DESIGNATED_ROOT,
    DOT1D_STP_PORT_STATE, DOT1D_STP_PRIORITY, DOT1D_STP_PROTOCOL_SPEC,
    DOT1D_STP_ROOT_COST, DOT1D_STP_ROOT_PORT, DOT1D_STP_TIME_SINCE_CHANGE,
    DOT1D_STP_TOP_CHANGES, LLDP_REM_CHASSIS_ID, LLDP_REM_CHASSIS_ID_SUBTYPE,
    LLDP_REM_PORT_DESC, LLDP_REM_PORT_ID, LLDP_REM_PORT_ID_SUBTYPE,
    LLDP_REM_SYS_DESC, LLDP_REM_SYS_NAME, PETH_MAIN_PSE_CONSUMPTION,
    PETH_MAIN_PSE_OPER_STATUS, PETH_MAIN_PSE_POWER, PETH_PSE_PORT_ADMIN,
    PETH_PSE_PORT_DETECTION, oid_key,
)
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
        # apc_ups and room_alert's SPECIALS entries: mains has failed (the
        # UPS output source and PowerNet status flip, the charge/runtime
        # scalars count down), or the room sensor is pinned hot.
        self.on_battery = bool(knobs.get("on_battery", False))
        self.temp_hot = bool(knobs.get("temp_hot", False))
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
                "on_battery": self.on_battery, "temp_hot": self.temp_hot,
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

# hrStorageTable's type column names what a row IS — nodepoll._host_resources_
# disk_pct (nodepoll.py:2012-2039) only ever counts a row typed
# hrStorageFixedDisk as "the disk"; every existing caller of host_resources()
# below wants a RAM/appdata figure with no disk semantics, so that stays the
# default and only the new Windows personas pass a type explicitly.
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_STORAGE_VIRTUAL_MEMORY = "1.3.6.1.2.1.25.2.1.3"
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"
HR_SYSTEM_UPTIME = "1.3.6.1.2.1.25.1.1.0"
HR_SW_RUN = "1.3.6.1.2.1.25.4.2.1"
HR_DEVICE_STATUS = "1.3.6.1.2.1.25.3.2.1.5"

UPS_MIB = "1.3.6.1.2.1.33"                      # RFC 1628 UPS-MIB
PRT_MARKER_SUPPLIES = "1.3.6.1.2.1.43.11.1.1"   # RFC 3805 Printer-MIB
PRT_INPUT = "1.3.6.1.2.1.43.8.2.1"
PRT_ALERT = "1.3.6.1.2.1.43.18.1.1"
PRT_GENERAL = "1.3.6.1.2.1.43.5.1.1"


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

    nodepoll._poll_vendor_health falls back to nodeoids.GENERIC_HEALTH's
    hrProcessorLoad column_avg for cpu_pct, and disk_pct always comes from
    _host_resources_disk_pct's hrStorageFixedDisk-filtered read of
    hrStorageTable — both real, live paths (see windows_server/
    windows_endpoint below for the persona that demonstrates them on
    purpose, including the asymmetry that mem_pct has no such
    HOST-RESOURCES fallback at all). Every OTHER persona answering this
    table answers it as incidental realism, not to demonstrate anything.

    storages: [(descr, alloc_units, size_units, used_fraction)], or with a
    5th element, [(descr, alloc_units, size_units, used_fraction,
    storage_type_oid)] — the type OID defaults to HR_STORAGE_RAM, which is
    what every caller before the Windows personas wanted (a memory or
    app-data figure with no "disk" semantics); pass HR_STORAGE_FIXED_DISK
    (or HR_STORAGE_VIRTUAL_MEMORY) explicitly for a row that should count as
    one of those instead.
    """
    entries: dict = {}
    for cpu in range(1, cpus + 1):
        entries[f"1.3.6.1.2.1.25.3.3.1.2.{cpu}"] = (
            T_INTEGER,
            lambda st, now, c=cpu: int(max(1, min(99,
                25 + (h("hrcpu", st.name, c) % 30) +
                12 * math.sin(now / 43.0 + c)))))
    for i, row in enumerate(storages, start=1):
        descr, units, size, used = row[:4]
        storage_type = row[4] if len(row) > 4 else HR_STORAGE_RAM
        entries[f"1.3.6.1.2.1.25.2.3.1.1.{i}"] = (T_INTEGER, i)
        entries[f"1.3.6.1.2.1.25.2.3.1.2.{i}"] = (T_OID, storage_type)
        entries[f"1.3.6.1.2.1.25.2.3.1.3.{i}"] = (T_OCTET_STRING, descr)
        entries[f"1.3.6.1.2.1.25.2.3.1.4.{i}"] = (T_INTEGER, units)
        entries[f"1.3.6.1.2.1.25.2.3.1.5.{i}"] = (T_INTEGER, size)
        entries[f"1.3.6.1.2.1.25.2.3.1.6.{i}"] = (
            T_INTEGER,
            lambda st, now, s=size, u=used:
                int(s * min(0.98, u * (1.0 + 0.06 * math.sin(now / 67.0)))))
    return entries


def hr_sw_run(procs) -> dict:
    """HOST-RESOURCES-MIB hrSWRunTable — the running-process list a Windows
    box answers and the personas above never have (they have no processor/
    storage story worth a process list either).

    procs: [(name, path, run_type, status)]. run_type: 2=operatingSystem,
    4=application. status: 1=running. hrSWRunID (an OID, "the software's own
    product ID") is answered as zeroDotZero — nothing in this demo invents a
    product-ID registry, and a real agent that does not track one answers
    the same way.
    """
    entries: dict = {}
    for i, (name, path, run_type, status) in enumerate(procs, start=1):
        entries[f"{HR_SW_RUN}.1.{i}"] = (T_INTEGER, i)
        entries[f"{HR_SW_RUN}.2.{i}"] = (T_OCTET_STRING, name)
        entries[f"{HR_SW_RUN}.3.{i}"] = (T_OID, "0.0")
        entries[f"{HR_SW_RUN}.4.{i}"] = (T_OCTET_STRING, path)
        entries[f"{HR_SW_RUN}.6.{i}"] = (T_INTEGER, run_type)
        entries[f"{HR_SW_RUN}.7.{i}"] = (T_INTEGER, status)
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


# There is no OUI/MAC-vendor lookup anywhere in netpath/ (a tablet has no
# SNMP agent of its own, so the only honest way this fleet can represent one
# is as a leaf MAC in a switch's forwarding table). These are real
# IEEE-assigned OUIs — not cross-checked against a live registry in this
# environment, so treat the exact bytes as "commonly cited as Apple/Samsung"
# rather than freshly verified — used by _switch_fdb_ports' tablet_ports to
# make a couple of FDB rows look like the phones/tablets they represent
# instead of every MAC anonymously sharing this file's own made-up prefix.
APPLE_OUI = (0xAC, 0xDE, 0x48)
SAMSUNG_OUI = (0x5C, 0x0A, 0x5B)


def _oui_mac_arc(oui: tuple[int, int, int], seed) -> str:
    raw = h("tabletmac", seed)
    octets = oui + ((raw >> 16) & 0xFF, (raw >> 8) & 0xFF, raw & 0xFF)
    return ".".join(str(b) for b in octets)


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


def entity_sensors(port_sensors: dict, parent_label: str | None = None,
                   link_to_if: bool = True) -> dict:
    """ENTITY-MIB + ENTITY-SENSOR-MIB for a handful of sensors: entPhysical-
    ContainedIn nests each sensor under its parent entity and entPhySensor*
    carries the reading. entAliasMappingIdentifier additionally ties the
    parent entity to an ifIndex — the mapping nodepoll.read_dom() (the
    interface dialog's on-demand DOM read) requires to find a transceiver's
    sensors, but NOT the whole-device ENTITY-SENSOR-MIB walk in
    nodepoll._poll_environment (nodepoll.py:3081), which was written
    specifically because a chassis sensor with no port to be "on" — an
    environmental monitor's temperature/humidity probes — needed a path
    that does not depend on it.

    port_sensors: {if_index: [(label, sensor_type, units, base_value, swing)]}
    parent_label -- the containing entity's own description. Every existing
    caller is a switch's optical port, so the default stays the SFP+
    transceiver text; a chassis-mounted sensor board (Room Alert) passes its
    own text instead.
    link_to_if -- publish the entAliasMappingIdentifier row (default True,
    every switch/PtP caller's real topology). A standalone environmental
    monitor passes False: its probes are not on any interface, so read_dom()
    correctly finds nothing for it while _poll_environment still does.

    `base_value` may be a callable ``fn(state, now) -> float`` instead of a
    number, for a reading a device knob should be able to move (a UPS's
    input voltage, a Room Alert pinned hot) rather than one that only drifts
    with the clock; `swing` is ignored when it is.
    """
    entries: dict = {}
    for if_index, sensors in port_sensors.items():
        port_entity = 1000 + if_index
        label = parent_label or f"SFP+ transceiver, port {if_index}"
        entries[f"{ENT_DESCR}.{port_entity}"] = (T_OCTET_STRING, label)
        entries[f"{ENT_CONTAINED_IN}.{port_entity}"] = (T_INTEGER, 1)
        if link_to_if:
            entries[f"{ENT_ALIAS_MAPPING}.{port_entity}.0"] = (
                T_OID, f"1.3.6.1.2.1.2.2.1.1.{if_index}")
        for slot, (label, stype, units, base, swing) in enumerate(sensors, start=1):
            entity = 10000 + if_index * 10 + slot
            entries[f"{ENT_DESCR}.{entity}"] = (T_OCTET_STRING, label)
            entries[f"{ENT_CONTAINED_IN}.{entity}"] = (T_INTEGER, port_entity)
            entries[f"{ENT_SENSOR}.1.{entity}"] = (T_INTEGER, stype)
            entries[f"{ENT_SENSOR}.2.{entity}"] = (T_INTEGER, 9)     # units (10^0)
            entries[f"{ENT_SENSOR}.3.{entity}"] = (T_INTEGER, 3)     # 3 decimals
            if callable(base):
                entries[f"{ENT_SENSOR}.4.{entity}"] = (
                    T_INTEGER,
                    lambda st, now, fn=base: int(round(fn(st, now) * 1000)))
            else:
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


# ---------------------------------------------------------- L2 topology
#
# LLDP/CDP neighbours, PoE and STP were three of 4.47.0's Tier 1 features
# and none of them had ever been answered by this fleet — the Topology
# tab, the device pane's Neighbours/Bridge&RF subtabs and the upstream-
# suggestion feature all had nothing to draw. What follows makes a
# specific, deliberate SUBSET of the fleet answer all four, shaped to
# match the site plan fleet_plan() already describes rather than wired so
# every device claims to neighbour every other one (which would light up
# the Topology tab and prove nothing).
#
# The anchor is core-sw-01 — index 0, the one name fleet_plan() NEVER
# varies regardless of --count — so every claim below can be a real,
# resolvable fact about the fleet's actual shape without needing to know
# which specific device instance is being built: acc-sw-001 through
# acc-sw-010 are the ten access switches SPECIALS always numbers first
# (indices 2-7,9-12), so they exist at any --count large enough to reach
# those indices at all, the same guarantee this file's other "pin one
# early" reasoning already relies on (see _MUST_APPEAR_EARLY's since-
# removed comment history, or SPECIALS itself).

def _mac_for(name: str, offset: int = 0) -> bytes:
    """The MAC DeviceState.mac(offset) would compute for the device
    NAMED `name` — used here so one persona's LLDP chassis-MAC claim
    about ANOTHER device agrees with what that other device's own
    interface table actually answers for ifPhysAddress (nodesdb's
    chassis-MAC neighbour join, gated on chassis_id_subtype 4), without
    needing a live DeviceState for it: a persona builder only ever knows
    a neighbour's NAME, never its instance. Must stay byte-for-byte
    identical to DeviceState.mac()'s own formula."""
    seed = h("mac", name)
    return bytes((0x02, (seed >> 16) & 0xFF, (seed >> 8) & 0xFF,
                 seed & 0xFF, (offset >> 8) & 0xFF, offset & 0xFF))


# Every switch persona that answers dot1dStp agrees on this SAME 8-octet
# bridge id (2-byte priority + 6-byte MAC) as the designated root — the
# way a real, converged spanning tree actually looks from any bridge in
# it — computed from core-sw-01's own identity so it is not just a
# plausible-looking constant.
ROOT_BRIDGE_ID = bytes((0x80, 0x00)) + _mac_for("core-sw-01", 0)


def lldp_neighbor(if_index: int, sys_name: str, chassis_id, port_id: str,
                  port_descr: str = "", sys_descr: str = "",
                  chassis_id_subtype: int = 4, port_id_subtype: int = 5,
                  rem_index: int = 1) -> dict:
    """One lldpRemTable row (LLDP-MIB) describing the neighbour seen on
    THIS device's own `if_index`. Indexed
    lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex; nodepoll._walk_lldp
    uses lldpRemLocalPortNum directly as the ifIndex (see nodeoids' LLDP
    block for why — the overwhelming majority of real agents, this one
    included, number it identically) and treats the rest of the suffix as
    an opaque key, so timeMark is fixed at 0 and remIndex at 1 — this demo
    never puts two neighbours on one port.

    chassis_id defaults to a MAC (subtype 4,
    nodeoids.LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS) — pass bytes from
    _mac_for() so nodesdb's chassis-MAC join actually resolves rather
    than only the sysName one; a caller with no real MAC to offer can
    pass a string and chassis_id_subtype=7 (locallyAssigned) instead.
    """
    suffix = f"0.{if_index}.{rem_index}"
    return {
        f"{LLDP_REM_CHASSIS_ID_SUBTYPE}.{suffix}": (T_INTEGER, chassis_id_subtype),
        f"{LLDP_REM_CHASSIS_ID}.{suffix}": (T_OCTET_STRING, chassis_id),
        f"{LLDP_REM_PORT_ID_SUBTYPE}.{suffix}": (T_INTEGER, port_id_subtype),
        f"{LLDP_REM_PORT_ID}.{suffix}": (T_OCTET_STRING, port_id),
        f"{LLDP_REM_PORT_DESC}.{suffix}": (T_OCTET_STRING, port_descr),
        f"{LLDP_REM_SYS_NAME}.{suffix}": (T_OCTET_STRING, sys_name),
        f"{LLDP_REM_SYS_DESC}.{suffix}": (T_OCTET_STRING, sys_descr),
    }


def cdp_neighbor(if_index: int, device_id: str, device_port: str = "",
                 platform: str = "", address: bytes | None = None,
                 cache_index: int = 1) -> dict:
    """One CISCO-CDP-MIB cdpCacheTable row, on the vendor's own arc as a
    fallback/supplement alongside LLDP — indexed cdpCacheIfIndex directly
    (unlike LLDP's local-port assumption, this really IS the ifIndex per
    the MIB's own INDEX clause, so no join is needed). `address` (raw
    bytes, e.g. a 4-byte IPv4) is optional: cdpCacheAddress is display-
    only in this app (nodesdb never joins on it), so a caller with
    nothing plausible to offer can simply leave it out.
    """
    suffix = f"{if_index}.{cache_index}"
    entries = {
        f"{CDP_CACHE_DEVICE_ID}.{suffix}": (T_OCTET_STRING, device_id),
        f"{CDP_CACHE_DEVICE_PORT}.{suffix}": (T_OCTET_STRING, device_port),
        f"{CDP_CACHE_PLATFORM}.{suffix}": (T_OCTET_STRING, platform),
    }
    if address is not None:
        entries[f"{CDP_CACHE_ADDRESS}.{suffix}"] = (T_OCTET_STRING, address)
    return entries


def dot1d_stp(priority: int, root_cost: int, root_port: int,
             top_changes: int = 3, time_since_change_ticks: int = 360_000) -> dict:
    """The seven dot1dStp scalars (BRIDGE-MIB) nodepoll._poll_stp reads in
    one GET. designated_root is always ROOT_BRIDGE_ID — see that
    constant's own comment — so every bridge that answers this agrees on
    who the root is; priority/cost/port are what actually varies per
    bridge, the same way a real spanning tree does. root_cost=0,
    root_port=0 for the root bridge itself (core-sw-01's own call site).
    """
    return {
        DOT1D_STP_PROTOCOL_SPEC: (T_INTEGER, 3),            # ieee8021d
        DOT1D_STP_PRIORITY: (T_INTEGER, priority),
        DOT1D_STP_TIME_SINCE_CHANGE: (T_TIMETICKS, time_since_change_ticks),
        DOT1D_STP_TOP_CHANGES: (T_COUNTER32, top_changes),
        DOT1D_STP_DESIGNATED_ROOT: (T_OCTET_STRING, ROOT_BRIDGE_ID),
        DOT1D_STP_ROOT_COST: (T_INTEGER, root_cost),
        DOT1D_STP_ROOT_PORT: (T_INTEGER, root_port),
    }


def dot1d_stp_ports(port_states: dict) -> dict:
    """dot1dStpPort's per-port state. Keyed by the SAME bridge-port number
    bridge_ports()/the FDB tables already use — dot1dStpPort IS
    dot1dBasePort (nodeoids' STP comment), so this shares that numbering
    rather than inventing a second one. port_states: {bridge_port: state}
    — 5 (forwarding) for a normal working port, 2 (blocking) for a
    redundant link deliberately shown blocked."""
    return {f"{DOT1D_STP_PORT_STATE}.{port}": (T_INTEGER, state)
            for port, state in port_states.items()}


def poe_pse(budget_w: float, port_ifindexes, port_draw_w: dict | None = None,
           cisco_extension: bool = False) -> dict:
    """POWER-ETHERNET-MIB: pethMainPseTable (one PSU, group index 1) and
    pethPsePortTable — nodeoids' PoE comment: pethPsePortIndex is treated
    as an ifIndex directly, the same real-agent convention LLDP's local-
    port number already relies on. `cisco_extension` adds the per-port
    milliwatt reading at CISCO_POE_PORT_POWER_MW (arc 9.9.402) for a
    device whose sysDescr says Cisco; a non-Cisco PSE must never answer
    it, which is why this defaults off.

    port_draw_w: {if_index: watts} for a port actually delivering power
    (admin enabled, detected deliveringPower); every if_index in
    port_ifindexes NOT in port_draw_w answers enabled/searching instead —
    a real switch with more PoE-capable ports than connected powered
    devices.
    """
    port_draw_w = port_draw_w or {}
    consumption_w = sum(port_draw_w.values())
    entries = {
        f"{PETH_MAIN_PSE_POWER}.1": (T_GAUGE32, int(budget_w)),
        f"{PETH_MAIN_PSE_OPER_STATUS}.1": (T_INTEGER, 1),          # on
        f"{PETH_MAIN_PSE_CONSUMPTION}.1": (T_GAUGE32, int(consumption_w)),
    }
    for if_index in port_ifindexes:
        entries[f"{PETH_PSE_PORT_ADMIN}.1.{if_index}"] = (T_INTEGER, 1)  # enabled
        drawing = if_index in port_draw_w
        entries[f"{PETH_PSE_PORT_DETECTION}.1.{if_index}"] = (
            T_INTEGER, 3 if drawing else 2)     # deliveringPower / searching
        if drawing and cisco_extension:
            entries[f"{CISCO_POE_PORT_POWER_MW}.1.{if_index}"] = (
                T_INTEGER, int(port_draw_w[if_index] * 1000))
    return entries


# --------------------------------------------------------------- personas

def _gig_ports(count: int, uplinks: int, uplink_kind: str = "TenGigabitEthernet",
               prefix: str = "GigabitEthernet"):
    ports = [f"{prefix}1/0/{i}" for i in range(1, count + 1)]
    ports += [f"{uplink_kind}1/1/{i}" for i in range(1, uplinks + 1)]
    kinds = [6] * (count + uplinks)
    rates = [1_000_000_000] * count + [10_000_000_000] * uplinks
    return ports, kinds, rates


def _switch_fdb_ports(access_count: int, macs_per_port: int, seed_name: str,
                      tablet_ports: dict[int, tuple[int, int, int]] | None = None):
    """{bridge port -> [mac arcs]} and {bridge port -> ifIndex}. Bridge port
    numbers deliberately differ from ifIndex — conflating the two is the
    classic FDB bug, and this makes the app prove it does not.

    tablet_ports: {bridge_port: OUI} swaps that port's last MAC arc for one
    under a real phone/tablet vendor's OUI (see APPLE_OUI/SAMSUNG_OUI) — a
    tablet or phone has no SNMP agent, so a leaf MAC on an access port is
    the only place this fleet can represent one honestly.
    """
    port_macs = {}
    port_to_if = {}
    for i in range(1, access_count + 1):
        bridge_port = 100 + i
        port_to_if[bridge_port] = i
        macs = _mac_arcs(h(seed_name, i), macs_per_port)
        if tablet_ports and bridge_port in tablet_ports:
            macs[-1] = _oui_mac_arc(tablet_ports[bridge_port], h(seed_name, i))
        port_macs[bridge_port] = macs
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
    port_macs, port_to_if = _switch_fdb_ports(
        access, 4, "access",
        # Two of this access switch's ports have a phone/tablet leaf MAC in
        # the FDB — see APPLE_OUI/SAMSUNG_OUI's comment: a tablet has no
        # SNMP agent, so this is the only honest place to represent one.
        tablet_ports={103: APPLE_OUI, 107: SAMSUNG_OUI})
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
    # L2 topology: every access switch's real uplink is core-sw-01 (see
    # this section's own module comment) — reported via both LLDP and CDP,
    # the way a real Cisco access switch actually answers both at once.
    uplink_if = access + 1
    entries.update(lldp_neighbor(
        uplink_if, sys_name="core-sw-01", chassis_id=_mac_for("core-sw-01", 1),
        port_id="GigabitEthernet1/0/1", port_descr="downlink 1",
        sys_descr=CISCO_CORE_DESCR))
    entries.update(cdp_neighbor(
        uplink_if, device_id="core-sw-01", device_port="GigabitEthernet1/0/1",
        platform="cisco WS-C9500-24Y4C"))
    # PoE: every access port capable, roughly a third actually drawing
    # power right now — a real closet switch with more PoE ports than
    # currently-plugged-in phones/APs.
    entries.update(poe_pse(
        740, range(1, access + 1),
        port_draw_w={i: 6.5 + (h("poe", i) % 90) / 10.0
                    for i in range(1, access + 1) if h("poedraw", i) % 3 == 0},
        cisco_extension=True))
    entries.update(dot1d_stp(priority=32768, root_cost=4, root_port=uplink_if))
    entries.update(dot1d_stp_ports({port: 5 for port in port_to_if}))  # forwarding
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
    # L2 topology: only the DEFAULT-sized core (core-sw-01, access == 88 —
    # Persona.table() always resolves `ports` to a real int, never None:
    # it falls back to the persona's own declared 96 when no override is
    # given, so `ports` itself is never falsy here) gets a downlink
    # neighbour table. The 500-port chassis SPECIALS variant
    # (chassis_ports=500, a different device entirely) exists to
    # demonstrate the interface cap, not this device's own place in the
    # topology, and claiming the same ten access switches would make two
    # different "core" devices both report being their upstream.
    if access == 88:
        for n in range(1, 11):
            name = f"acc-sw-{n:03d}"
            entries.update(lldp_neighbor(
                n, sys_name=name, chassis_id=_mac_for(name, 49),
                port_id="GigabitEthernet1/0/49", port_descr="uplink to core",
                sys_descr=CISCO_ACCESS_DESCR))
            entries.update(cdp_neighbor(
                n, device_id=name, device_port="GigabitEthernet1/0/49",
                platform="cisco WS-C2960X-48FPD-L"))
        entries.update(dot1d_stp(priority=4096, root_cost=0, root_port=0))
        entries.update(dot1d_stp_ports({port: 5 for port in port_to_if}))
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
    # L2 topology: this switch's uplink (its last port, 1/24) really does
    # go to the plant core. No CDP — Aruba is not Cisco.
    entries.update(lldp_neighbor(
        count, sys_name="core-sw-01", chassis_id=_mac_for("core-sw-01", 1),
        port_id="GigabitEthernet1/0/1", port_descr="downlink 1",
        sys_descr=CISCO_CORE_DESCR))
    # PoE+: the model name (2930F-8G-PoE+) already promises it — standard
    # MIB only, no Cisco extension.
    entries.update(poe_pse(
        370, range(1, count + 1),
        port_draw_w={i: 5.0 + (h("apoe", i) % 60) / 10.0
                    for i in range(1, count + 1) if h("apoedraw", i) % 3 == 0}))
    entries.update(dot1d_stp(priority=32768, root_cost=4, root_port=count))
    entries.update(dot1d_stp_ports({port: 5 for port in port_to_if}))
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
    # L2 topology: this distribution switch's first uplink (xe-0/1/0,
    # ifIndex 25) goes to the plant core.
    entries.update(lldp_neighbor(
        25, sys_name="core-sw-01", chassis_id=_mac_for("core-sw-01", 1),
        port_id="GigabitEthernet1/0/1", port_descr="downlink 1",
        sys_descr=CISCO_CORE_DESCR))
    entries.update(dot1d_stp(priority=32768, root_cost=4, root_port=25))
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
    # L2 topology: this cell/area switch's uplink (port 8) goes to the
    # plant core. No PoE — industrial DIN-rail switches this size
    # typically are not PSEs.
    entries.update(lldp_neighbor(
        8, sys_name="core-sw-01", chassis_id=_mac_for("core-sw-01", 1),
        port_id="GigabitEthernet1/0/1", port_descr="downlink 1",
        sys_descr=CISCO_CORE_DESCR))
    entries.update(dot1d_stp(priority=32768, root_cost=19, root_port=8))
    entries.update(dot1d_stp_ports({port: 5 for port in port_to_if}))
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
    # L2 topology: this field switch's uplink (port 8) goes to the plant
    # core. No PoE, same reasoning as SCALANCE above.
    entries.update(lldp_neighbor(
        8, sys_name="core-sw-01", chassis_id=_mac_for("core-sw-01", 1),
        port_id="GigabitEthernet1/0/1", port_descr="downlink 1",
        sys_descr=CISCO_CORE_DESCR))
    entries.update(dot1d_stp(priority=32768, root_cost=19, root_port=8))
    entries.update(dot1d_stp_ports({port: 5 for port in port_to_if}))
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


# ------------------------------------------------------ estate device personas
#
# The switches, firewalls and PtP bridges above are the network the app
# already knows how to poll. A plant site is mostly NOT those: UPSs keeping
# a wiring closet up during a brownout, a Room Alert watching that same
# closet's temperature, the printer down the hall, and far more servers and
# PCs than there are switches to plug them into. These five personas are
# what makes the fleet answer for that estate rather than only its network.


def _supply_level(base_pct: float, swing: float, key: str):
    """A consumable's percent-remaining, drifting slowly downward-and-up
    like the DOM/CPU readings above — the same "graphs actually move"
    reasoning, applied to a toner cartridge instead of a link's optics."""
    def value(st, now):
        drift = swing * math.sin(now / 131.0 + (h(key, st.name) % 628) / 100.0)
        return int(max(0, min(100, base_pct + drift)))
    return value


def printer_supplies(supplies, trays) -> dict:
    """RFC 3805 Printer-MIB prtMarkerSuppliesTable and prtInputTable — the
    two tables a print-management tool actually watches (toner/waste level,
    a tray running out of paper). Both tables index on
    (hrDeviceIndex, tableOwnIndex); this fleet only ever answers as
    hrDeviceIndex 1, so every row's first index arc is fixed at 1.

    supplies: [(descr, prtMarkerSuppliesType, max_capacity, level)] — level
    may be a callable, the same convention as if_table's octet counters.
    trays: [(descr, max_capacity, level)]
    """
    entries: dict = {}
    for i, (descr, kind, cap, level) in enumerate(supplies, start=1):
        entries[f"{PRT_MARKER_SUPPLIES}.5.1.{i}"] = (T_INTEGER, kind)
        entries[f"{PRT_MARKER_SUPPLIES}.6.1.{i}"] = (T_OCTET_STRING, descr)
        entries[f"{PRT_MARKER_SUPPLIES}.7.1.{i}"] = (T_INTEGER, 19)  # percent
        entries[f"{PRT_MARKER_SUPPLIES}.8.1.{i}"] = (T_INTEGER, cap)
        entries[f"{PRT_MARKER_SUPPLIES}.9.1.{i}"] = (T_INTEGER, level)
    for i, (descr, cap, level) in enumerate(trays, start=1):
        entries[f"{PRT_INPUT}.8.1.{i}"] = (T_INTEGER, cap)
        entries[f"{PRT_INPUT}.9.1.{i}"] = (T_INTEGER, level)
        entries[f"{PRT_INPUT}.13.1.{i}"] = (T_OCTET_STRING, descr)
    return entries


def _build_apc_ups(wrap32: bool, ports: int, vlan: str | None) -> dict:
    # RFC 1628 UPS-MIB (1.3.6.1.2.1.33) is small and precisely specified, so
    # every upsMIB OID below is real, and every one of them matches
    # nodeoids.UPS_HEALTH (nodeoids.py:324-351) — nodepoll._poll_ups_health
    # now reads this table on every device, not gated by vendor arc, so this
    # persona is really polled: ups_battery_status, ups_on_battery_s,
    # ups_battery_charge_pct etc. all become real metrics, and alertsdb's
    # ups_on_battery/ups_battery_low/ups_battery_replace rules can actually
    # fire off them (see the on_battery SPECIALS knob, index 14).
    #
    # Deliberately does NOT answer upsEstimatedMinutesRemaining (.1.2.3.0) —
    # some real APC firmware leaves it at 0 or unset and only populates the
    # PowerNet-MIB equivalent, which is exactly the gap
    # nodepoll._apc_runtime_fallback (nodepoll.py:2242) exists to cover: it
    # is tried only when the standard scalar did not answer, and only on
    # APC's own arc. This persona is what exercises that fallback rather
    # than only the ordinary path — see eaton_ups for the ordinary path on a
    # vendor with no such fallback available.
    #
    # The PowerNet-MIB objects below (APC's own enterprise arc, 318 —
    # VERIFIED as "apc" in netpath/enterprises.py) are reconstructed from
    # public monitoring-tool templates rather than a MIB file this tree
    # carries a copy of, so their exact sub-arc numbering is plausible, not
    # cross-checked the way the RFC objects are — except
    # upsAdvBatteryRunTimeRemaining (.2.2.3.0), which matches
    # nodeoids.APC_BATTERY_RUNTIME_TIMETICKS exactly (both this file and
    # nodeoids.py derived it independently from the same real-world
    # monitoring convention, which is about as much cross-checking as an
    # unbundled vendor MIB gets here).
    entries = system_scalars(
        "APC Web/SNMP Management Card (AP9631) *PMDU: SMTe, Firmware "
        "v3.9.2, hardware rev 05 — Smart-UPS SMT3000RM2U",
        "1.3.6.1.4.1.318.1.3.2.11")
    entries.update(if_table(["eth0"], 6, 100_000_000, hc=not wrap32,
                            alias=lambda i, d: "management"))

    def seconds_on_battery(st, now):
        return int(now - st.start_ts) % 3600 if st.on_battery else 0

    def charge_remaining(st, now):
        if not st.on_battery:
            return 100
        # Drains to a full "replace the battery" arc within a few minutes —
        # fast enough that on_battery (SPECIALS index 14) can walk an
        # operator through ups_on_battery -> ups_battery_low ->
        # ups_battery_replace inside one demo run.
        drained = min(85.0, seconds_on_battery(st, now) / 3.0)
        return max(15, int(100 - drained))

    def minutes_remaining(st, now):
        if not st.on_battery:
            return 87
        return max(2, int(42 * charge_remaining(st, now) / 100.0))

    def battery_status(st, now):
        if not st.on_battery:
            return 2                                   # batteryNormal
        charge = charge_remaining(st, now)
        if charge <= 15:
            return 4                                   # batteryDepleted
        if charge < 25:
            return 3                                   # batteryLow
        return 2

    def input_voltage(st, now):
        return 0 if st.on_battery else 118 + (h("upsvin", st.name) % 5)

    def output_voltage(st, now):
        return 118 + (h("upsvout", st.name) % 5)

    def output_load(st, now):
        return 28 + (h("upsload", st.name) % 15)

    entries.update({
        # upsIdent
        f"{UPS_MIB}.1.1.1.0": (T_OCTET_STRING, "American Power Conversion"),
        f"{UPS_MIB}.1.1.2.0": (T_OCTET_STRING, "Smart-UPS SMT3000RM2U"),
        f"{UPS_MIB}.1.1.3.0": (T_OCTET_STRING, "UPS 09.3 / ID=1005"),
        f"{UPS_MIB}.1.1.4.0": (T_OCTET_STRING, "AP9631 v3.9.2"),
        # upsBattery — no .1.2.3.0 (upsEstimatedMinutesRemaining); see the
        # function docstring above.
        f"{UPS_MIB}.1.2.1.0": (T_INTEGER, battery_status),
        f"{UPS_MIB}.1.2.2.0": (T_INTEGER, seconds_on_battery),
        f"{UPS_MIB}.1.2.4.0": (T_INTEGER, charge_remaining),
        f"{UPS_MIB}.1.2.5.0": (T_INTEGER, 1920),                    # 192.0 VDC
        f"{UPS_MIB}.1.2.7.0": (
            T_INTEGER, lambda st, now: 26 + (h("upstemp", st.name) % 6)),
        # upsInput — one incoming line
        f"{UPS_MIB}.1.3.2.0": (T_INTEGER, 1),
        f"{UPS_MIB}.1.3.3.1.1.1": (T_INTEGER, 1),
        f"{UPS_MIB}.1.3.3.1.2.1": (T_INTEGER, 600),                 # 60.0 Hz
        f"{UPS_MIB}.1.3.3.1.3.1": (T_INTEGER, input_voltage),
        # upsOutput — one outgoing line
        f"{UPS_MIB}.1.4.1.0": (
            T_INTEGER, lambda st, now: 5 if st.on_battery else 3),  # battery(5)/normal(3)
        f"{UPS_MIB}.1.4.2.0": (T_INTEGER, 600),
        f"{UPS_MIB}.1.4.3.0": (T_INTEGER, 1),
        f"{UPS_MIB}.1.4.4.1.1.1": (T_INTEGER, 1),
        f"{UPS_MIB}.1.4.4.1.2.1": (T_INTEGER, output_voltage),
        f"{UPS_MIB}.1.4.4.1.5.1": (T_INTEGER, output_load),
        # upsAlarm
        f"{UPS_MIB}.1.6.1.0": (
            T_INTEGER, lambda st, now: 1 if st.on_battery else 0),
        # PowerNet-MIB — the same readings a real APC card also answers
        # under its own arc, which is the one its own management software
        # actually polls, and (for upsAdvBatteryRunTimeRemaining alone) the
        # one nodepoll._apc_runtime_fallback reads in place of the standard
        # scalar this persona omits.
        "1.3.6.1.4.1.318.1.1.1.2.1.1.0": (T_INTEGER, battery_status),
        "1.3.6.1.4.1.318.1.1.1.2.2.1.0": (T_INTEGER, charge_remaining),
        "1.3.6.1.4.1.318.1.1.1.2.2.3.0": (
            T_TIMETICKS, lambda st, now: minutes_remaining(st, now) * 6000),
        "1.3.6.1.4.1.318.1.1.1.2.2.4.0": (T_INTEGER, 1),      # no replace needed
        "1.3.6.1.4.1.318.1.1.1.3.2.1.0": (T_INTEGER, input_voltage),
        "1.3.6.1.4.1.318.1.1.1.4.1.1.0": (
            T_INTEGER, lambda st, now: 3 if st.on_battery else 2),  # onBattery(3)/onLine(2)
        "1.3.6.1.4.1.318.1.1.1.4.2.3.0": (T_INTEGER, output_load),
    })
    return entries


def _build_eaton_ups(wrap32: bool, ports: int, vlan: str | None) -> dict:
    # A second UPS vendor, answering nothing but the standard RFC 1628
    # scalars — no enterprise-arc extras, and (unlike apc_ups)
    # upsEstimatedMinutesRemaining IS answered — to prove
    # nodepoll._poll_ups_health's "tried on every device, not gated by
    # enterprise arc" design (nodeoids.py:283-292) actually holds for a UPS
    # that is not APC. Eaton's arc (534, VERIFIED as "eaton" in
    # enterprises.py) identifies the vendor; nothing under it is read by
    # this MIB or answered by this persona.
    entries = system_scalars(
        "Eaton 5PX 3000VA Network Card-MS, firmware 3.5.11",
        "1.3.6.1.4.1.534.1.9.5")
    entries.update(if_table(["eth0"], 6, 100_000_000, hc=not wrap32,
                            alias=lambda i, d: "management"))
    entries.update({
        f"{UPS_MIB}.1.1.1.0": (T_OCTET_STRING, "Eaton"),
        f"{UPS_MIB}.1.1.2.0": (T_OCTET_STRING, "5PX3000RT"),
        f"{UPS_MIB}.1.1.3.0": (T_OCTET_STRING, "01"),
        f"{UPS_MIB}.1.1.4.0": (T_OCTET_STRING, "3.5.11"),
        f"{UPS_MIB}.1.2.1.0": (T_INTEGER, 2),                       # batteryNormal
        f"{UPS_MIB}.1.2.2.0": (T_INTEGER, 0),
        f"{UPS_MIB}.1.2.3.0": (T_INTEGER,
            lambda st, now: 58 + (h("eamin", st.name) % 8)),
        f"{UPS_MIB}.1.2.4.0": (T_INTEGER, 100),
        f"{UPS_MIB}.1.2.5.0": (T_INTEGER, 480),                     # 48.0 VDC
        f"{UPS_MIB}.1.2.7.0": (
            T_INTEGER, lambda st, now: 24 + (h("eatemp", st.name) % 5)),
        f"{UPS_MIB}.1.3.2.0": (T_INTEGER, 1),
        f"{UPS_MIB}.1.3.3.1.1.1": (T_INTEGER, 1),
        f"{UPS_MIB}.1.3.3.1.2.1": (T_INTEGER, 600),
        f"{UPS_MIB}.1.3.3.1.3.1": (
            T_INTEGER, lambda st, now: 118 + (h("eavin", st.name) % 5)),
        f"{UPS_MIB}.1.4.1.0": (T_INTEGER, 3),                       # normal
        f"{UPS_MIB}.1.4.2.0": (T_INTEGER, 600),
        f"{UPS_MIB}.1.4.3.0": (T_INTEGER, 1),
        f"{UPS_MIB}.1.4.4.1.1.1": (T_INTEGER, 1),
        f"{UPS_MIB}.1.4.4.1.2.1": (
            T_INTEGER, lambda st, now: 118 + (h("eavout", st.name) % 5)),
        f"{UPS_MIB}.1.4.4.1.5.1": (
            T_INTEGER, lambda st, now: 22 + (h("eaload", st.name) % 12)),
        f"{UPS_MIB}.1.6.1.0": (T_INTEGER, 0),
    })
    return entries


def _room_temp_c(st, now):
    if st.temp_hot:
        return 42.0 + 1.2 * math.sin(now / 29.0 + (h("roomhot", st.name) % 628) / 100.0)
    return 22.0 + 3.5 * math.sin(now / 29.0 + (h("room", st.name) % 628) / 100.0)


def _build_room_alert(wrap32: bool, ports: int, vlan: str | None) -> dict:
    # ENTITY-SENSOR-MIB (RFC 3433) is the standards-based half of this
    # persona: type 8 is temperature in °C, type 9 is %RH, exactly the two
    # readings an AVTECH Room Alert exposes (nodepoll's own
    # _SENSOR_TYPE_UNITS agrees, nodepoll.py:2926-2928).
    #
    # entity_sensors() is called with link_to_if=False on purpose: a Room
    # Alert's temperature/humidity probes belong to the chassis, not to any
    # port, so no entAliasMappingIdentifier row is published for them. That
    # means nodepoll.read_dom() (the interface dialog's on-demand DOM read,
    # which still gates on that mapping) correctly finds nothing here — but
    # nodepoll._poll_environment (nodepoll.py:3081), the whole-device
    # ENTITY-SENSOR-MIB walk added specifically because a chassis sensor has
    # no port to be "on", finds and polls them regardless: temp_c and
    # humidity_pct become real metrics, and alertsdb's temp_high/
    # humidity_high thresholds (35°C/30°C, 80%/70%RH) evaluate against them.
    # The temp_hot SPECIALS knob (index 15) pushes the reading past 35°C —
    # see selftest.test_room_alert_dom for both halves proven together.
    #
    # AVTECH's own enterprise arc (20916, CURATED — medium confidence, see
    # enterprises.py's own docstring — as "avtech" in netpath/enterprises.py)
    # is what identifies this persona; its Device MIB is not bundled in this
    # tree and is far less documented than an RFC MIB, so the scalars under
    # it below are representative, not cross-checked column numbers the way
    # the ENTITY-SENSOR-MIB ones above are.
    entries = system_scalars(
        "AVTECH Room Alert 32E, firmware 4.42",
        "1.3.6.1.4.1.20916.1.8.2", services=64)
    entries.update(if_table(["eth0"], 6, 100_000_000, hc=not wrap32,
                            alias=lambda i, d: "management"))
    entries.update(entity_sensors(
        {1: [("Room temperature", 8, "°C", _room_temp_c, 0),
             ("Room humidity", 9, "%RH", 45.0, 8.0)]},
        parent_label="Room Alert sensor bank", link_to_if=False))
    entries.update(arc_objects(20916, {
        # Native tenths-of-a-unit scalars mirroring the two ENTITY-SENSOR
        # readings above, plus a couple of dry-contact digital inputs (a
        # door switch, a water-leak rope) — a Room Alert's other headline
        # feature, alongside temperature and humidity.
        "1.3.6.1.4.1.20916.1.6.1.1.1.3.1": (
            T_INTEGER, lambda st, now: int(round(_room_temp_c(st, now) * 10))),
        "1.3.6.1.4.1.20916.1.6.1.2.1.3.1": (
            T_INTEGER, lambda st, now: 450 + (h("roomrh", st.name) % 80)),
        "1.3.6.1.4.1.20916.1.5.1.1.1.3.1": (T_INTEGER, 0),    # door: closed
        "1.3.6.1.4.1.20916.1.5.1.1.1.3.2": (T_INTEGER, 0),    # water: dry
    }))
    return entries


def _build_printer_mfp(wrap32: bool, ports: int, vlan: str | None) -> dict:
    # HP's real enterprise arc (11, VERIFIED as "hp" in enterprises.py) so
    # this persona identifies the way the rest of the fleet does; the model
    # suffix under it is a plausible LaserJet Enterprise MFP sysObjectID,
    # not one read off a real device.
    entries = system_scalars(
        "HP LaserJet Enterprise MFP M528, firmware 2411240_000005",
        "1.3.6.1.4.1.11.2.3.9.1")
    entries.update(if_table(["network"], 6, 1_000_000_000, hc=not wrap32,
                            alias=lambda i, d: "management"))
    entries.update(printer_supplies(
        [("Black Toner Cartridge HP W1470X", 3, 100,
          _supply_level(58, 6, "toner")),
         ("Waste Toner Container", 4, 100,
          _supply_level(22, 5, "waste"))],
        [("Tray 1", 250, _supply_level(70, 10, "tray1")),
         ("Tray 2", 550, _supply_level(35, 12, "tray2"))]))
    entries[f"{PRT_GENERAL}.16.1"] = (T_OCTET_STRING, "3rd-Floor-MFP")
    entries[f"{HR_DEVICE_STATUS}.1"] = (T_INTEGER, 2)             # running
    # prtMarkerLifeCount (RFC 3805 prtMarkerTable) — the page counter every
    # print-management tool bills usage off of.
    entries["1.3.6.1.2.1.43.10.2.1.4.1.1"] = (
        T_COUNTER32,
        lambda st, now: int(max(0.0, now - st.boot(now)) * 0.9) % (2 ** 32))
    # prtAlertTable: two standing alerts, so the demo has something to open
    # rather than an empty table. Only the columns this file can vouch for
    # against RFC 3805 are populated — prtAlertGroup/prtAlertCode are large
    # enumerations this tree does not carry a copy of, so they are left out
    # rather than guessed at.
    entries.update({
        f"{PRT_ALERT}.2.1.1": (T_INTEGER, 4),                     # warning
        f"{PRT_ALERT}.8.1.1": (T_OCTET_STRING, "Toner Low"),
        f"{PRT_ALERT}.2.1.2": (T_INTEGER, 3),                     # critical
        f"{PRT_ALERT}.8.1.2": (T_OCTET_STRING, "Tray 2 Empty"),
    })
    return entries


def _build_windows_server(wrap32: bool, ports: int, vlan: str | None) -> dict:
    # HOST-RESOURCES-MIB, answered in full, to demonstrate a specific
    # asymmetry: nodepoll._poll_vendor_health (nodepoll.py:2086-2148) falls
    # back to nodeoids.GENERIC_HEALTH's hrProcessorLoad column_avg for
    # cpu_pct when nothing better answered, and disk_pct always comes from
    # _host_resources_disk_pct (nodepoll.py:2036-2063), filtered to rows
    # typed hrStorageFixedDisk (nodeoids.HR_STORAGE_FIXED_DISK) — both of
    # which this persona answers, so CPU and disk populate. mem_pct has NO
    # such HOST-RESOURCES fallback anywhere in nodepoll.py: it comes only
    # from UCD-SNMP-MIB (this persona answers none), the Cisco memory-pool
    # special case (arc 9), or a Fortinet/Juniper VENDOR_HEALTH scalar —
    # none of which applies to a Microsoft sysObjectID. So a Windows Server
    # in this fleet reports CPU and disk but never memory, confirmed by
    # exhaustive search of nodepoll.py for every mem_pct producer rather
    # than inferred. hrSystemUptime and hrSWRunTable are answered too, on
    # top of hrProcessorLoad/hrStorageTable's own GENERIC_HEALTH/
    # HR_STORAGE_* paths above.
    entries = system_scalars(
        "Hardware: AMD64 Family 25 Model 1 Stepping 1 AT/AT COMPATIBLE - "
        "Software: Windows Version 10.0 (Build 20348 Multiprocessor Free)",
        "1.3.6.1.4.1.311.1.1.3.1.3", services=76)
    entries.update(if_table(
        ["Intel(R) I350 Gigabit Network Connection",
         "Microsoft Network Adapter Multiplexor Driver"],
        6, 1_000_000_000, hc=not wrap32,
        alias=lambda i, d: "nic" if i == 1 else "team"))
    entries[HR_SYSTEM_UPTIME] = (T_TIMETICKS, lambda st, now: st.uptime_ticks(now))
    entries.update(host_resources(4, [
        ("C:\\  Label:    Serial Number 4a3d9f21", 4096, 122_070_312, 0.58,
         HR_STORAGE_FIXED_DISK),
        ("D:\\  Label: Data  Serial Number 9e6c1a04", 4096, 244_140_625, 0.37,
         HR_STORAGE_FIXED_DISK),
        ("Physical Memory", 1024, 33_554_432, 0.61, HR_STORAGE_RAM),
    ]))
    entries.update(hr_sw_run([
        ("System", "", 2, 1),
        ("services.exe", r"C:\Windows\System32\services.exe", 4, 1),
        ("lsass.exe", r"C:\Windows\System32\lsass.exe", 4, 1),
        ("w3wp.exe", r"C:\Windows\System32\inetsrv\w3wp.exe", 4, 1),
        ("sqlservr.exe",
         r"C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\sqlservr.exe",
         4, 1),
    ]))
    return entries


def _build_windows_endpoint(wrap32: bool, ports: int, vlan: str | None) -> dict:
    # The same HOST-RESOURCES shape as windows_server — and the same CPU/
    # disk-but-no-memory asymmetry, see that function's comment — cut down
    # to what a PC or tablet actually is: one adapter — wireless-looking,
    # since the fleet's tablets and laptop-class PCs both go over Wi-Fi,
    # hence ifType 71 (ieee80211) rather than 6 — two small disks (a system
    # drive and a recovery/data partition), and a process table short enough
    # that the many devices of this persona the fleet holds cost almost
    # nothing beyond the one shared, memoised table.
    entries = system_scalars(
        "Hardware: AMD64 Family 25 Model 1 Stepping 1 AT/AT COMPATIBLE - "
        "Software: Windows Version 10.0 (Build 19045 Multiprocessor Free)",
        "1.3.6.1.4.1.311.1.1.3.1.1", services=76)
    entries.update(if_table(["Intel(R) Wi-Fi 6 AX201 160MHz"], 71, 866_000_000,
                            hc=not wrap32, alias=lambda i, d: "wifi"))
    entries[HR_SYSTEM_UPTIME] = (T_TIMETICKS, lambda st, now: st.uptime_ticks(now))
    entries.update(host_resources(2, [
        ("C:\\  Label:    Serial Number 7c21ab90", 4096, 30_517_578, 0.71,
         HR_STORAGE_FIXED_DISK),
        ("D:\\  Label: Recovery  Serial Number 2b48f317", 4096, 1_310_720, 0.22,
         HR_STORAGE_FIXED_DISK),
        ("Physical Memory", 1024, 8_388_608, 0.66, HR_STORAGE_RAM),
    ]))
    entries.update(hr_sw_run([
        ("System", "", 2, 1),
        ("explorer.exe", r"C:\Windows\explorer.exe", 4, 1),
    ]))
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
    "apc_ups": Persona("apc_ups", _build_apc_ups, 1, "APC Smart-UPS SMT3000"),
    "room_alert": Persona("room_alert", _build_room_alert, 1,
                          "AVTECH Room Alert 32E"),
    "printer_mfp": Persona("printer_mfp", _build_printer_mfp, 1,
                           "HP LaserJet Enterprise MFP"),
    "windows_server": Persona("windows_server", _build_windows_server, 2,
                              "Windows Server 2022"),
    "windows_endpoint": Persona("windows_endpoint", _build_windows_endpoint, 1,
                                "Windows PC/tablet"),
    "eaton_ups": Persona("eaton_ups", _build_eaton_ups, 1, "Eaton 5PX 3000VA"),
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
    14: {"persona": "apc_ups", "profile": "v2c-public", "knob": "on_battery",
         "note": "mains has failed; upsOutputSource and PowerNet's "
                 "upsBasicOutputStatus both flip to onBattery, and the "
                 "charge/runtime-remaining scalars count down"},
    15: {"persona": "room_alert", "profile": "v2c-public", "knob": "temp_hot",
         "note": "the room sensor is pinned above a safe running "
                 "temperature; nodepoll._poll_environment turns it into a "
                 "real temp_c metric and alertsdb's temp_high rule (35°C) "
                 "fires off it"},
    # The remaining four new device classes have no misbehaviour knob of
    # their own — each is pinned here anyway so it, like every class above,
    # is guaranteed present even at --count 25 rather than left to the
    # weighted mix's shuffle luck; _FIXED_INDEX_MAX follows from this
    # automatically.
    16: {"persona": "printer_mfp", "profile": "v2c-public", "knob": "",
         "note": "answers RFC 3805 Printer-MIB in full (toner level, page "
                 "count, alerts); nothing in netpath polls 1.3.6.1.2.1.43 "
                 "at all, so none of it reaches the app"},
    17: {"persona": "windows_server", "profile": "v2c-public", "knob": "",
         "note": "hrProcessorLoad and a hrStorageFixedDisk row both feed "
                 "real metrics (cpu_pct, disk_pct), but no code path in "
                 "nodepoll.py produces mem_pct for a Windows host — CPU "
                 "and disk populate, memory never does"},
    18: {"persona": "windows_endpoint", "profile": "v2c-public", "knob": "",
         "note": "the same CPU/disk-but-no-memory gap as windows_server, "
                 "at the scale (many PCs/tablets) that actually matters "
                 "for the estate"},
    19: {"persona": "eaton_ups", "profile": "v2c-public", "knob": "",
         "note": "standard UPS-MIB only, no vendor arc extras — proves "
                 "nodepoll._poll_ups_health's per-device (not per-arc) "
                 "design works for a UPS that is not APC"},
    # A real site has a fixed handful of these roles, not a number that
    # grows with the fleet — the same reasoning index 0 (the one core
    # switch) and index 1 (the one wireless controller) already follow.
    # Pinning them here rather than in _MIX_WEIGHTS is what keeps them at a
    # constant count regardless of --count; see that constant's own
    # comment for the count that produced (2 perimeter firewalls per
    # vendor, one at each of two independent edges; 3 distribution-layer
    # switches and 3 remote-site backhaul routers — "a couple of firewalls
    # ... a handful of routers").
    20: {"persona": "fortigate", "profile": "v2c-public", "knob": "",
         "note": "perimeter firewall #1 — a fixed role, not a proportional "
                 "one; see _MIX_WEIGHTS' comment"},
    21: {"persona": "fortigate", "profile": "v2c-public", "knob": "",
         "note": "perimeter firewall #2 (the redundant edge)"},
    22: {"persona": "paloalto", "profile": "v2c-public", "knob": "",
         "note": "perimeter firewall #3 — the OT/plant-network boundary, "
                 "a second vendor rather than a second unit of the same one"},
    23: {"persona": "paloalto", "profile": "v2c-public", "knob": "",
         "note": "perimeter firewall #4 (the corporate-network boundary)"},
    24: {"persona": "juniper", "profile": "v2c-public", "knob": "",
         "note": "a distribution-layer switch, one of three — a fixed "
                 "count, not the access-switch proportional role"},
    25: {"persona": "juniper", "profile": "v2c-public", "knob": ""},
    26: {"persona": "juniper", "profile": "v2c-public", "knob": ""},
    27: {"persona": "mikrotik", "profile": "v2c-public", "knob": "",
         "note": "a remote-site backhaul router, one of three (one per "
                 "site) — a fixed count, not a proportional one"},
    28: {"persona": "mikrotik", "profile": "v2c-public", "knob": ""},
    29: {"persona": "mikrotik", "profile": "v2c-public", "knob": ""},
}

# The last index SPECIALS occupies; the weighted mix starts one past it.
_FIXED_INDEX_MAX = max(SPECIALS)

# One 100-slot cycle of the weighted mix used from index _FIXED_INDEX_MAX+1 on
# — for the roles a plant site has HUNDREDS of, proportional to fleet size.
# fortigate/paloalto/juniper/mikrotik are deliberately NOT in here: a site
# does not get more firewalls or more core/distribution gear as its fleet
# grows, so those four are fixed-count SPECIALS entries (20-29) instead —
# see the comment there. What is actually proportional in a plant is access
# switches (still the majority), and then endpoints, printers, UPSs, Room
# Alerts, servers, PtP bridges, industrial switches and PLCs, all in the
# hundreds; windows_endpoint's 17 reflects PCs/tablets outnumbering
# everything but the switches themselves. Each of the personas the fixed
# SPECIALS block already covers additionally appears here too, for the
# realistic bulk numbers beyond that one guaranteed instance.
_MIX_WEIGHTS = (
    ("cisco_access", 43), ("aruba_switch", 6),
    ("ubiquiti_airfiber", 4), ("cambium_ptp", 2),
    ("siemens_scalance", 4), ("moxa", 3),
    ("rockwell_plc", 3), ("siemens_s7_plc", 2),
    ("linux_host", 2),
    ("windows_server", 3), ("windows_endpoint", 17),
    ("apc_ups", 4), ("room_alert", 2), ("printer_mfp", 3), ("eaton_ups", 2),
)

_NAME_PREFIX = {
    "cisco_access": "acc-sw", "cisco_core": "core-sw", "aruba_switch": "aru-sw",
    "fortigate": "fw", "paloalto": "pan-fw", "juniper": "jnpr-sw",
    "ubiquiti_airfiber": "ptp", "cambium_ptp": "cmb", "mikrotik": "mt-rtr",
    "siemens_scalance": "scal-sw", "moxa": "moxa-sw", "rockwell_plc": "plc-ab",
    "siemens_s7_plc": "plc-s7", "linux_host": "srv", "fortigate_wlc": "wlc",
    "apc_ups": "ups", "room_alert": "ra", "printer_mfp": "prn",
    "windows_server": "winsrv", "windows_endpoint": "pc", "eaton_ups": "ups2",
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
    2..29 are SPECIALS (13 is the ConfigRX SSH demo device), and everything
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
            elif knob == "on_battery":
                knobs["on_battery"] = True
            elif knob == "temp_hot":
                knobs["temp_hot"] = True

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
    for row in plan[:30]:
        print(f"  {row['index']:>3} {row['ip']:<12} {row['name']:<12} "
              f"{row['persona']:<18} {row['profile']:<11} {row['site']}")
    for key, persona in PERSONAS.items():
        table = persona.table()
        print(f"  {key:<20} {len(table):>5} OIDs")
