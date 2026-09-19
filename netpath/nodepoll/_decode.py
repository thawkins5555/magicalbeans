from __future__ import annotations

import ipaddress
import re
from .. import namelookup, nodeoids
from ..snmpformat import detect_reboot, format_cdp_address, format_chassis_address
from ._consts import USM_STATS


# The per-interface metric keys one poll emits, in the order they are
# recorded. `in_bps`/`out_bps` and the two `*_err` keys keep the names the
# charts and any stored history already use; the rest are new in 4.39.0.
def _INTERFACE_METRICS(in_bps, out_bps, in_err_rate, out_err_rate,
                       in_disc_rate, out_disc_rate, in_util, out_util):
    return (
        ("in_bps", "bps", in_bps),
        ("out_bps", "bps", out_bps),
        ("in_err", "err/s", in_err_rate),
        ("out_err", "err/s", out_err_rate),
        ("in_error_rate", "err/s", in_err_rate),
        ("out_error_rate", "err/s", out_err_rate),
        ("in_discard_rate", "disc/s", in_disc_rate),
        ("out_discard_rate", "disc/s", out_disc_rate),
        ("in_util_pct", "%", in_util),
        ("out_util_pct", "%", out_util),
    )


# suffix -> (unit, device-level label). A device-level key is the worst
# value across the device's interfaces this poll, which is what a rule
# written against a device rather than a port can usefully mean.
_DEVICE_MAX_KEYS = {
    "in_util_pct": ("%", "Interface inbound utilization (busiest port)"),
    "out_util_pct": ("%", "Interface outbound utilization (busiest port)"),
    "in_error_rate": ("err/s", "Interface inbound errors (worst port)"),
    "out_error_rate": ("err/s", "Interface outbound errors (worst port)"),
    "in_discard_rate": ("disc/s", "Interface inbound discards (worst port)"),
    "out_discard_rate": ("disc/s", "Interface outbound discards (worst port)"),
}


# root key -> (label suffix, unit); full key is "<root>.<ifIndex>", the
# shape the per-interface if_* keys already use.
_SFP_METRICS = {
    "sfp_rx_dbm": ("Rx power", "dBm"),
    "sfp_tx_dbm": ("Tx power", "dBm"),
    "sfp_bias_ma": ("bias current", "mA"),
    "sfp_volt": ("supply voltage", "V"),
    "sfp_temp_c": ("optic temperature", "°C"),
}

# Standard PMD media codes -- the IEEE 802.3 clause suffix a module names
# itself by, which the SFF/MSA part numbers copy -- and the fiber each runs
# on. The alphabet the classifier reads, so a part number nobody has listed
# still classifies. Matched longest-first: LRM is MULTIMODE despite reading
# like LR, and LX4 is the mode-conditioned variant that runs on MMF.
_MEDIA_MODE = {
    "sx": "mm", "fx": "mm", "sr": "mm", "srl": "mm", "sr4": "mm",
    "csr4": "mm", "esr4": "mm", "lrm": "mm", "lx4": "mm", "sw": "mm",
    "mm": "mm", "mmf": "mm", "mmd": "mm",
    "lx": "sm", "lx10": "sm", "lh": "sm", "fb": "sm", "ex": "sm",
    "zx": "sm", "lr": "sm", "lr4": "sm", "lr10": "sm", "er": "sm",
    "er4": "sm", "er4l": "sm", "zr": "sm", "zr4": "sm", "lw": "sm",
    "psm4": "sm", "cwdm": "sm", "cwdm4": "sm", "dwdm": "sm",
    "sm": "sm", "smf": "sm", "smd": "sm",
}
# BiDi is single-mode and carries its own reach/direction suffix (BX10-U,
# BX20-D, BX40), so it is a pattern rather than a table key.
_BIDI_CODE = r"bx\d*[ud]?"
# Codes too short to trust bare: "sw" is how half a fleet abbreviates
# "switch". They still count in the BASE- and part-suffix forms.
_BARE_UNSAFE = frozenset({"sw", "lw", "fb"})


def _media_codes(mode: str, bare: bool = False) -> str:
    """_MEDIA_MODE's codes for one fiber type as a regex alternation,
    longest first so LRM wins over LR and LX4 over LX."""
    codes = [code for code, value in _MEDIA_MODE.items() if value == mode
             and not (bare and code in _BARE_UNSAFE)]
    return "|".join(sorted(codes, key=len, reverse=True))


def _media_pattern(mode: str) -> str:
    """The three shapes a media code is written in, for one fiber type: a
    bare token, the BASE- form a description uses (100Base-FX), and the
    part-number suffix a model name uses (GLC-LH-SMD, SFP-10G-SR-S). The
    optional speed in front of the code is what makes Cisco's glued
    spelling -- GLC-FE-100FX -- read the same as the spaced one."""
    speed = r"\d*(?:g|gb)?"
    return (rf"\b{speed}(?:{_media_codes(mode, bare=True)})\b"
            rf"|base-?(?:{_media_codes(mode)})\b"
            rf"|-{speed}(?:{_media_codes(mode)})(?:-[sx])?\b")


# A cage, and what is in it: entPhysicalDescr/ModelName/VendorType text that
# names a transceiver. Deliberately not "1000BaseT" and friends on their own
# -- a fixed copper port describes itself that way and is not an SFP slot --
# so only an optical media suffix or a form factor counts.
_TRANSCEIVER_TEXT = re.compile(
    r"\b(?:[cq]?sfp\d*|xfp|x2|gbic|xcvr|transceiver)\b|\bglc-|\bsfp-"
    rf"|base-?(?:{_media_codes('mm')}|{_media_codes('sm')}|{_BIDI_CODE})\b",
    re.I)

# Copper proof for text _TRANSCEIVER_TEXT already matched: BASE-T(X), the
# GLC-T[E]/SFP-*-T part-number families, and copper/RJ45/catX words.
_COPPER_TEXT = re.compile(
    r"\b(?:\d+g?base-?tx?|glc-te?|sfp-?(?:10g|1ge?|ge)?-?t(?:-s|-x)?|rj-?45"
    r"|copper|cat[56][ae]?)\b", re.I)

# Multimode (850 nm) and single-mode (1270-1610 nm) proof out of the same
# transceiver text, built from _MEDIA_MODE. Copper/DAC/AOC text matches
# neither; the wavelength arm catches a module that quotes no PMD at all.
_OPTIC_MM_TEXT = re.compile(
    _media_pattern("mm") + r"|\b(?:850|1300)\s?nm\b", re.I)
_OPTIC_SM_TEXT = re.compile(
    _media_pattern("sm") + rf"|\b{_BIDI_CODE}\b|base-?{_BIDI_CODE}\b"
    rf"|-{_BIDI_CODE}\b|\b1[2-6]\d{{2}}\s?nm\b", re.I)


def _envmon_rows(*columns) -> list[str]:
    """Every index any of a CISCO-ENVMON table's columns answered for, in
    index order. Keyed on the union rather than on the description column:
    a fan tray whose ciscoEnvMonFanDescr row is absent still has a state row
    saying whether it is spinning, and a device with three trays and two
    descriptions used to list two fans.
    """
    suffixes = set()
    for column in columns:
        suffixes.update(column)
    return sorted(suffixes, key=lambda s: (_envmon_sort_key(s), s))


def _envmon_sort_key(suffix: str) -> tuple:
    parts = suffix.split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return (float("inf"),)


def _optic_mode(*texts) -> str | None:
    """'sm', 'mm', or None from transceiver text, checking MM before SM on
    each text in the order given -- first hit wins."""
    for text in texts:
        text = str(text or "")
        if not text:
            continue
        if _OPTIC_MM_TEXT.search(text):
            return "mm"
        if _OPTIC_SM_TEXT.search(text):
            return "sm"
    return None


# ifMauType's value OID's last arc is a dot3MauType (RFC 3636/4836); a
# device that answers it gets the last say over ambiguous/wrong text.
# Copper dot3MauTypes: 10/100/1000BASE-T(X)/-FD, 1000BASE-CX(-FD), 10GBASE-CX4/T.
_COPPER_MAU_ARCS = frozenset({
    5, 10, 11, 14, 15, 16, 19, 20, 27, 28, 29, 30, 41, 54,
})
# Fiber dot3MauTypes: arcs naming an optical PMD. 1000BASE-X (21, 22),
# 10GBASE-X/R/W (31, 33, 37) are "unknown PMD" and vote for nothing.
_FIBER_MAU_ARCS = frozenset({
    3, 6, 7, 8, 12, 13, 17, 18, 23, 24, 25, 26,
    32, 34, 35, 36, 38, 39, 40, *range(44, 54),
})

# dBm(14) says a sensor reads optical power but not which way the light is
# going, so the direction comes out of the sensor's own name.
_OPTIC_RX = re.compile(r"\b(rx|receive[d]?|input)\b", re.I)
_OPTIC_TX = re.compile(r"\b(tx|transmit(ted)?|output|laser)\b", re.I)


def _optical_direction(label: str, descr: str) -> str | None:
    """'rx', 'tx', or None for an optical-power reading whose name says
    neither. entPhysicalName is asked first (the column a Cisco agent puts
    "Te1/1/1 Receive Power" in); entPhysicalDescr is the fallback for agents
    that leave the name empty. Rx wins a name claiming both, since a
    receive-power alarm is the one that catches a dying link."""
    for text in (label, descr):
        text = str(text or "")
        if not text:
            continue
        rx = bool(_OPTIC_RX.search(text))
        tx = bool(_OPTIC_TX.search(text))
        if rx:
            return "rx"
        if tx:
            return "tx"
    return None


_VENDOR_NUMERIC_RE = re.compile(r"[-+]?\d+(?:\.\d+)?")


def _vendor_numeric(raw, numeric_prefix: bool) -> float | None:
    """A nodeoids.SensorTable/PsuTable reading as a float, or None.

    `numeric_prefix` vendors (HP's "45C", Fortinet's mixed-unit strings)
    always go through the regex, since a plain float() would raise on the
    trailing unit letter; every other vendor's column is already numeric
    SNMP (Integer32/Gauge32), so the regex is only a fallback there for an
    agent that answers it as a numeric string anyway.
    """
    if raw is None:
        return None
    if not numeric_prefix and isinstance(raw, (int, float)):
        return float(raw)
    match = _VENDOR_NUMERIC_RE.match(str(raw).strip())
    return float(match.group(0)) if match else None


def _vendor_state_value(raw, state_map: dict | None, state_default=None):
    """A vendor's own state enum normalised through a
    nodeoids.SensorTable/PsuTable's `state_map`, or None to skip the row
    entirely (not present, administratively off — not a fourth severity).

    An int raw value is looked up directly; a string one is matched exactly
    first (a vendor answering "Normal"/"normal" alike) and then by
    substring, for the handful of vendors whose free-text status embeds the
    word that matters ("Fault detected" still means fault). `state_default`
    covers a vendor with only a couple of named states and everything else
    implied ("else -> critical") — a map with no default and no match skips
    the row, which is the right call for silently-added new enum values.
    """
    if not state_map or raw is None:
        return None
    if isinstance(raw, str):
        key = raw.strip().lower()
        if key in state_map:
            return state_map[key]
        for needle, level in state_map.items():
            if isinstance(needle, str) and needle and needle in key:
                return level
        return state_default
    try:
        ikey = int(raw)
    except (TypeError, ValueError):
        return state_default
    return state_map.get(ikey, state_default)


_VENDOR_IDX_BASE = 1000


def _flatten_vendor_idx(suffix: str) -> str:
    """A walked column's index suffix as one integer string, the shape
    the metric keys need (root.<int>). A plain index is unchanged; a
    compound one (Netgear unit.sensor, Dell type.unit.psu, Raritan
    pduId.sensorID) is packed base 1000 so unit 2 sensor 1 (2001) can never
    overwrite unit 1 sensor 1 (1001). Sibling columns of one table share
    the index shape, so every map built from them packs the same way.
    """
    if "." not in suffix:
        return suffix
    packed = 0
    for part in suffix.split("."):
        try:
            packed = packed * _VENDOR_IDX_BASE + int(part)
        except ValueError:
            return suffix.rsplit(".", 1)[-1]
    return str(packed)


_DOTTED_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _inet_address_text(value) -> str:
    """An InetAddress (RFC 4001) IPv4 value as dotted text, or "" for
    anything not a plain 4-byte address (accepts raw bytes, dotted text,
    or space-separated hex)."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value or "").strip()
        if not text:
            return ""
        if _DOTTED_IPV4_RE.match(text):
            return text
        groups = text.replace(":", " ").split()
        try:
            raw = bytes(int(g, 16) for g in groups if len(g) <= 2)
        except ValueError:
            return ""
        if len(raw) != len(groups):
            return ""
    return ".".join(str(b) for b in raw) if len(raw) == 4 else ""


def report_reason(response) -> tuple[str, str]:
    """(usmStats name, plain explanation) for a Report-PDU, or ("", "")
    when it names nothing this table knows."""
    for vb in getattr(response, "varbinds", None) or ():
        oid = str(vb.get("oid") or "")
        # The instance is the counter's OID with .0 appended.
        known = USM_STATS.get(oid) or USM_STATS.get(oid.rsplit(".", 1)[0])
        if known:
            return known
    return "", ""


def counter_rate(previous: int | None, previous_ts: float, current: int | None,
                 current_ts: float, bit_width: int, *,
                 speed_bps: float | None = None) -> float | None:
    """Per-second rate (units of the counter, e.g. bytes/sec for an octet
    counter) from two counter samples, handling wraparound and rejecting
    nonsense. A 32-bit counter that decreased is assumed to have wrapped
    once; a 64-bit counter that decreased is assumed to have been reset
    (rebooted/reinitialized) since a real wrap would take centuries at any
    realistic speed. If speed_bps is given (bits/sec) and the implied rate
    would exceed ~1.3x it, the sample is treated as a reset rather than a
    multi-wrap and None is returned — this is why ifXTable's 64-bit
    counters (nodeoids.IFX_TABLE) are preferred whenever present."""
    if previous is None or current is None:
        return None
    dt = current_ts - previous_ts
    if dt <= 0:
        return None
    if current >= previous:
        rate = (current - previous) / dt
    elif bit_width >= 64:
        return None
    else:
        modulus = 2 ** bit_width
        rate = (modulus - previous + current) / dt
    if speed_bps and rate * 8 > speed_bps * 1.3:
        return None
    return rate


IF_SPEED_SENTINEL = 4_294_967_295
# 1.6 TbE, the next rate the standard defines: a full doubling above 800GbE,
# the fastest Ethernet port actually shipping, and still three orders below
# what a kbit/s-for-Mbit/s ifHighSpeed makes of a 10G port.
MAX_PLAUSIBLE_SPEED_BPS = 1.6e12
# ...but that ceiling describes a PHYSICAL PORT, and an aggregate's rate is
# the sum of its members: the bound for one of those is the largest bundle
# that can exist, 802.3ad's 16 members at 800GbE.
MAX_PLAUSIBLE_AGGREGATE_BPS = 16 * 800e9
# ieee8023adLag and propVirtual: what a modern and an older platform
# respectively call a Port-channel.
AGGREGATE_IF_TYPES = frozenset({53, 161})


def interface_speed_bps(speed, high_speed, if_type=None) -> float | None:
    """One interface's line rate in bits/sec from ifSpeed (bit/s, Gauge32,
    saturating at IF_SPEED_SENTINEL) and ifHighSpeed (Mbit/s), refusing an
    ifHighSpeed that cannot be what the MIB says it is — the same shape of
    refusal counter_rate makes when a derived rate outruns the link.

    ifHighSpeed is preferred as it always was; it is the only one of the two
    that can express a modern link. But agents exist (per-linecard, which is
    why only a few ports on a device are wrong) that answer it in kbit/s, and
    x 1e6 then reports a 10 Gb/s port as 10 Tb/s — the right digits, three
    orders out, and a utilization consequently near 0%. So: a value above the
    ceiling is not a link that exists, and a value 100x or more above a
    NON-saturated ifSpeed is contradicted by the device itself, since an
    unsaturated ifSpeed is exact. A rejected reading falls to ifSpeed where
    ifSpeed can answer; it cannot above ~4.29 Gb/s, which is exactly where the
    quirk shows, so there the reading is retried as kbit/s and kept only if
    THAT lands inside the ceiling. A genuine 400G or 800G port passes every
    check untouched and is never rescaled.

    Two readings that trip those rules legitimately, each exempted by
    something checkable. An 8x400G port-channel answers 3,200,000 against a
    saturated ifSpeed, and no arithmetic separates that from a quirky 3.2
    Gb/s port — a 3.2 Tb/s bundle exists, a 3.2 Tb/s port does not — so
    if_type decides, and only the ceiling moves. And an agent reporting
    ifSpeed as speed mod 2^32 rather than saturated gives a 400G port
    568,041,472 beside a correct ifHighSpeed: not a contradiction but the
    same number truncated, recognised exactly rather than guessed at. The
    1 Gb/s quirk cannot pass as one — 1e12 % 2**32 is 3,567,587,328, not the
    1e9 its ifSpeed reports."""
    high_bps = (float(high_speed) * 1_000_000
                if isinstance(high_speed, (int, float)) and high_speed else None)
    speed_bps = float(speed) if isinstance(speed, (int, float)) else None
    if high_bps is None:
        return speed_bps
    aggregate = (isinstance(if_type, (int, float))
                 and int(if_type) in AGGREGATE_IF_TYPES)
    ceiling = MAX_PLAUSIBLE_AGGREGATE_BPS if aggregate else MAX_PLAUSIBLE_SPEED_BPS
    wrapped = high_bps > IF_SPEED_SENTINEL and high_bps % 2 ** 32 == speed_bps
    contradicted = (speed_bps is not None and 0 < speed_bps < IF_SPEED_SENTINEL
                    and high_bps >= speed_bps * 100 and not wrapped)
    if high_bps <= ceiling and not contradicted:
        return high_bps
    if speed_bps is not None and 0 < speed_bps < IF_SPEED_SENTINEL:
        return speed_bps
    rescaled = high_bps / 1000
    if rescaled <= ceiling:
        return rescaled
    return speed_bps


# The inverse of the sentence above, kept beside it so the two cannot drift.
# Both groups are pinned to the two shapes trapdecode.format_ticks can emit,
# not to `(.+?)`: the pre-5.3 sentence ("uptime dropped from 1036800000 to
# 15000 hundredths of a second after 300s") is still readable out of a row the
# 5.2 poller wrote, and a loose group matched it and handed the raw tick counts
# to the reboot email as uptimes -- the very mistake 5.3 removed.
_UPTIME_TEXT = r"(\d+d \d\d:\d\d:\d\d|\d\d:\d\d:\d\d\.\d\d)"
_REBOOT_UPTIMES = re.compile(f"uptime dropped from {_UPTIME_TEXT} to {_UPTIME_TEXT}")


def reboot_uptimes(detail: str) -> tuple[str, str]:
    """The before/after uptimes out of a `rebooted` device_event's detail.

    Read back out of the event row rather than off the device, because the
    device row no longer has them: `devices.last_uptime_ticks` was overwritten
    with the post-reboot reading by the poll that detected the reboot, and the
    pre-reboot figure is gone for good by the time the alert engine drains the
    event. ("", "") for a detail this did not write.
    """
    match = _REBOOT_UPTIMES.search(detail or "")
    return (match.group(1), match.group(2)) if match else ("", "")


def _interface_reassigned(prior: "sqlite3.Row | dict", row: dict) -> bool:
    """True only on affirmative evidence that the physical port at this
    ifIndex changed between `prior` and `row` — a stack member reboot can
    move port 5 from ifIndex 10 to 14.

    ifPhysAddress first: the burned-in MAC is tied to the hardware, not to
    how the agent numbers the port, so it survives a renumbering that descr
    (which encodes the member number) would not. ifDescr is the fallback
    where phys_addr is blank, common on logical interfaces.

    A field empty on either side is never evidence — only a disagreement
    between two non-empty values counts. Otherwise a platform that does not
    populate either column would have every reboot read as a reassignment,
    suppressing every post-reboot oper_status comparison forever."""
    for field in ("phys_addr", "descr"):
        old = prior[field] if field in prior.keys() else None
        new = row.get(field)
        if old and new:
            return old != new
    return False


# Moved to nodeoids in 4.32 so vendorid can share it; kept under its old
# name here so the walk code and its tests read unchanged.
_oid_key = nodeoids.oid_key


def neighbor_ip_candidates(row) -> list[str]:
    """Addresses a neighbour row identifies itself by, best evidence first:
    CDP's cdpCacheAddress, an LLDP subtype-5 chassis id, or sys_name (this
    module copies cdpCacheDeviceId into both). `row` is a sqlite3.Row
    (nodesdb.all_neighbours()/neighbours_for_devices()) or a hand-built
    dict alike -- neither type can be relied on to have `.get`, so `in
    row.keys()` guards every read, the same way mapper._get does."""
    keys = row.keys()

    def value(key):
        return row[key] if key in keys else None

    candidates = []

    def add(text):
        text = str(text or "").strip()
        if namelookup.is_ip_literal(text) and text not in candidates:
            candidates.append(text)

    add(value("remote_address"))
    if value("chassis_id_subtype") == 5:
        add(format_chassis_address(value("chassis_id")))
    add(value("sys_name"))
    return candidates


def _int_keyed(column: dict) -> dict:
    """A `_walk_column` result with every index suffix parsed to int,
    dropping anything that is not one. Several VLAN-walk columns below are
    indexed by a bare bridge port or ifIndex (a single arc), and this is
    the one-line version of the `try: int(suffix) except...: continue` loop
    every other table walk in this file already repeats inline — worth
    naming once here because the VLAN walk needs it five separate times."""
    out = {}
    for suffix, value in column.items():
        try:
            out[int(suffix)] = value
        except (TypeError, ValueError):
            continue
    return out


# The short interface-name forms IOS/NX-OS write in entPhysicalName, mapped
# to the long form the same box writes in ifDescr — "Te1/1/1 Transmit Power"
# against "TenGigabitEthernet1/1/1". See _canonical_if_name, which is the
# only reason this table exists: a Cisco sensor is very often reachable only
# by this name match, because CISCO-ENTITY-SENSOR-MIB gear routinely leaves
# entAliasMappingIdentifier empty.
_IF_NAME_ABBREVIATIONS = {
    "fa": "fastethernet", "gi": "gigabitethernet",
    "te": "tengigabitethernet", "twe": "twentyfivegige",
    "fo": "fortygigabitethernet", "hu": "hundredgige",
    "eth": "ethernet", "tw": "twogigabitethernet",
    "fi": "fivegigabitethernet", "po": "port-channel",
    "ap": "appgigabitethernet",
}


def _canonical_if_name(name: str) -> str:
    """An interface name reduced to a form two spellings of the same port
    compare equal on: lowercased, whitespace removed, and a leading
    abbreviation expanded to its long form.

    The expansion applies only when the WHOLE leading run of letters is an
    abbreviation, so "TenGigabitEthernet1/1/1" is never re-read as "Te" +
    "nGigabitEthernet1/1/1" and mangled into something that matches
    nothing.
    """
    text = "".join(str(name or "").split()).lower()
    head = ""
    for char in text:
        if not char.isalpha():
            break
        head += char
    expanded = _IF_NAME_ABBREVIATIONS.get(head) if head else None
    return expanded + text[len(head):] if expanded else text


# trapdecode._octets_text's own two non-literal branches, and only those:
# its six-byte MAC-address special case always joins with ':' and always
# lowercase hex (`f"{b:02x}"`); its general fallback always joins with ' '
# and always UPPERCASE hex (`f"{b:02X}"`). A literal run that merely looks
# hex-ish (a single odd-length token, or one that mixes case, or one whose
# groups run together with no separating space) can never have come out of
# either branch, so it is deliberately NOT matched here — see
# _octets_from_value.
_HEX_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_HEX_OCTETS_RE = re.compile(r"^[0-9A-F]{2}(?: [0-9A-F]{2})*$")


def _octets_from_value(raw) -> bytes:
    """The bytes behind a PortList/VLAN-bitmap OCTET STRING, whether `raw`
    is already bytes (callers and tests that have them directly) or has
    been through this app's shared OCTET_STRING decoder for a live walk
    (trapdecode._octets_text — the same one format_cdp_address documents):
    plain text when every byte happened to be printable, colon-separated
    lowercase hex when the string was exactly six bytes and not all
    printable (that decoder's MAC-address special case), or space-separated
    uppercase hex otherwise.

    That decode is NOT losslessly reversible, despite this file previously
    documenting it as such, and this function cannot make it so — the raw
    octets are gone before it is ever called. `trapdecode._decode_value`
    returns an OCTET STRING's printable rendering as the value itself, so
    the bytes are discarded at BER-parse time; recovering them would mean
    re-implementing v1/v2c/v3 parsing here. INTERNALS.md records this as a
    known limit of the whole SNMP path — the LLDP chassis-id decode has it
    too — rather than of this function alone.

    What this DOES do is narrow the guess to the shapes `_octets_text`
    provably produces — its six-group lowercase colon-hex MAC form, or a
    run of space-separated uppercase hex pairs — instead of the previous
    heuristic, which reinterpreted any printable one-or-two-character hex
    look-alike and so turned a literal "A" (0x41, ports 2 and 8) into 0x0A
    (ports 5 and 7).

    Two ambiguities are irreducible, and are resolved the way that is right
    more often on real hardware rather than pretended away:

      - 0x0A, 0x0D and 0x20 all render as the same single space, so all
        three read back as 0x20 (port 3). A PortList setting ports 5 and 7
        is indistinguishable from one setting port 3.
      - A run matching the uppercase-hex-pair shape is read AS hex, so the
        text "12" becomes the one byte 0x12 rather than the two literal
        characters "1" and "2". An agent's PortList reaches `_octets_text`
        as hex far more often than a switch answers with literal decimal
        text, so this is the better default — but it is a default, not a
        certainty.
    """
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    text = str(raw or "")
    if not text:
        return b""
    if _HEX_MAC_RE.match(text):
        return bytes(int(part, 16) for part in text.split(":"))
    if _HEX_OCTETS_RE.match(text):
        return bytes(int(part, 16) for part in text.split(" "))
    return text.encode("latin-1", "replace")


def _bit_positions(octets: bytes):
    """(octet index, bit index within it — 0 the most significant) for
    every set bit of a big-endian bitmap, the scan _decode_port_list and
    _decode_vlan_bitmap share; they differ only in how a position becomes
    a port or VLAN number (see _decode_vlan_bitmap's own docstring)."""
    for i, byte in enumerate(octets):
        for bit in range(8):
            if byte & (0x80 >> bit):
                yield i, bit


def _decode_port_list(raw) -> list[int]:
    """Bridge port numbers set in a Q-BRIDGE-MIB PortList OCTET STRING
    (dot1qVlanStatic/CurrentEgressPorts, …UntaggedPorts).

    A PortList (RFC 4363) is a big-endian bitmap: the most significant bit
    of byte 0 is bridge port 1, the next bit down is port 2, ... the least
    significant bit of byte 0 is port 8, the most significant bit of byte 1
    is port 9, and so on — 1-based, unlike CISCO-VTP-MIB's own bitmaps (see
    _decode_vlan_bitmap, which shares this function's octet-decoding and
    bit-scan but not its 1-based numbering).

    `raw` is either raw bytes, or text already through this app's shared
    OCTET_STRING decoder — see _octets_from_value for how that text is
    turned back into bytes, and why that is best-effort rather than
    lossless for a short run of bytes that all happen to be printable.
    """
    return [i * 8 + bit + 1 for i, bit in _bit_positions(_octets_from_value(raw))]


def _decode_vlan_bitmap(raw, base: int) -> list[int]:
    """VLAN ids set in one of CISCO-VTP-MIB's four vlanTrunkPortVlansEnabled*
    bitmaps (see nodeoids' VTP_TRUNK_VLANS_ENABLED* block for the four
    OIDs and their base offsets). Same big-endian, most-significant-bit-
    first octet scan _decode_port_list uses — but 0-based, NOT 1-based
    like that PortList convention: CISCO-VTP-MIB's own DESCRIPTION says
    the first octet specifies VLANs 0 through 7, its most significant bit
    the LOWEST-numbered of those, not "the lowest VLAN plus one" the way a
    PortList's octet 0 reserves its most significant bit for bridge port 1
    rather than port 0. Adding `base` (0, 1024, 2048 or 3072 — one per
    column) places the result in the right thousand."""
    return [base + i * 8 + bit
           for i, bit in _bit_positions(_octets_from_value(raw))]
