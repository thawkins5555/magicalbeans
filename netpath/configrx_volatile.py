"""Per-vendor volatile-line stripping for ConfigRX captures.

Some "show config" lines change on every poll regardless of whether the
configuration itself changed (an NTP clock-skew counter, a save-time
banner); left in, they'd make `configrxdb.add_backup`'s hash-based change
detection store a new version every cycle for nothing an operator would
call a change.
"""

from __future__ import annotations

import re

_CISCO_CLASSIC = (
    re.compile(r"^ntp clock-period \d+$"),
    re.compile(r"^! Last configuration change"),
    re.compile(r"^! NVRAM config last updated"),
    re.compile(r"^! No configuration change since last restart"),
    re.compile(r"^Building configuration"),
    re.compile(r"^Current configuration : \d+ bytes"),
)

VOLATILE: dict[str, tuple[re.Pattern, ...]] = {
    "cisco": _CISCO_CLASSIC,
    "cisco-sb": _CISCO_CLASSIC,
    "cisco-asa": _CISCO_CLASSIC,
    "cisco-wlc": _CISCO_CLASSIC,
    "cisco-nxos": (
        re.compile(r"^!Running configuration last done at"),
        re.compile(r"^!Time:"),
        re.compile(r"^!Startup config saved at"),
    ),
    "cisco-iosxr": (
        re.compile(r"^!! Last configuration change"),
    ),
    "juniper": (
        re.compile(r"^## Last commit:"),
        re.compile(r"^## Last changed:"),
    ),
    "mikrotik": (
        re.compile(r"^# (?:\w{3}/\d\d/\d{4}|\d{4}-\d\d-\d\d) \d\d:\d\d:\d\d by RouterOS"),
    ),
    "hp": (
        re.compile(r"^; Last configuration change"),
    ),
    "aruba": (
        re.compile(r"^; Last configuration change"),
    ),
    "fortinet": (
        re.compile(r"^#conf_file_ver="),
    ),
    # moxa, siemens, rockwellautomation, ubiquiti and anything unrecognised
    # get no built-in patterns — extra_patterns still apply.
}


def strip_volatile(text: str, vendor_key: str,
                   extra_patterns: tuple[re.Pattern, ...] = ()) -> str:
    """`text` with every whole line matching a built-in pattern for
    `vendor_key`, or any of `extra_patterns`, dropped entirely. Matched from
    the start (`Pattern.match`), not the whole line, so patterns need not
    anchor trailing content.
    """
    patterns = VOLATILE.get((vendor_key or "").strip().lower(), ()) + tuple(extra_patterns)
    if not patterns:
        return text
    lines = [line for line in text.split("\n")
            if not any(p.match(line) for p in patterns)]
    return "\n".join(lines)
