"""Pure SNMP formatting/detection helpers with no store dependency, so
nodesdb.py and wirelessdb.py can import them at top level."""
from __future__ import annotations

import ipaddress

from . import namelookup
from .alertmail import duration_text
from .trapdecode import format_ticks


def detect_reboot(uptime_ticks: int, uptime_ts: float, previous_ticks: int | None,
                  previous_ts: float) -> tuple[bool, str]:
    """sysUpTime is a TimeTicks (hundredths of a second) since the agent's
    own last (re)initialization, wrapping at ~497 days (2**32 hundredths).
    A reboot is detected when the current uptime is significantly smaller
    than the previous reading, ruling out two false-positive cases: a
    497-day wrap (only plausible when the previous reading was already
    enormous) and ordinary jitter (a 30-second grace band)."""
    if previous_ticks is None:
        return False, ""
    elapsed_s = uptime_ts - previous_ts
    if elapsed_s <= 0:
        return False, ""
    grace_ticks = 30 * 100
    if uptime_ticks + grace_ticks >= previous_ticks:
        return False, ""   # uptime kept increasing (or barely dipped): normal
    wrap_modulus = 2 ** 32
    near_wrap = previous_ticks > wrap_modulus - (elapsed_s * 100 + grace_ticks) * 2
    if near_wrap:
        return False, ""
    # duration_text refuses a sub-second gap, and "after  without a reading"
    # would be the result of pasting its "" in unguarded.
    gap = duration_text(elapsed_s)
    sentence = (f"uptime dropped from {format_ticks(previous_ticks)} to "
                f"{format_ticks(uptime_ticks)}")
    if gap:
        sentence += f" after {gap} without a reading"
    return True, sentence


def format_cdp_address(raw) -> str:
    """cdpCacheAddress, as this app's OCTET_STRING decoder hands it back,
    is a space-separated run of hex bytes for anything non-printable (see
    trapdecode._octets_text) — a raw IPv4 address decodes as e.g.
    "0A 00 00 09". Reformatted to dotted-decimal when it is exactly four
    bytes; left as-is (and still informative) for anything else, since a
    real cdpCacheAddress can carry a different protocol's address entirely
    and this app does not attempt every one CISCO-CDP-MIB allows."""
    text = str(raw or "").strip()
    if not text:
        return ""
    parts = text.split()
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return text
    if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
        return ".".join(str(o) for o in octets)
    return text


def format_chassis_address(raw) -> str:
    """An LLDP chassis id of subtype 5 (network address) as a plain address literal, or "" if it does not decode to one."""
    text = str(raw or "").strip()
    if not text:
        return ""
    if namelookup.is_ip_literal(text):
        return text
    parts = text.split()
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return ""
    if not octets or not all(0 <= o <= 255 for o in octets):
        return ""
    if len(octets) in (5, 17) and octets[0] in (1, 2):
        parts, octets = parts[1:], octets[1:]
    if len(octets) == 16:
        return str(ipaddress.IPv6Address(bytes(octets)))
    address = format_cdp_address(" ".join(parts))
    return address if namelookup.is_ip_literal(address) else ""
