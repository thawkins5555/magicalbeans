"""Per-vendor volatile-line stripping for ConfigRX captures.

A device's "show config" output sometimes carries a line that changes on
every poll regardless of whether the configuration itself changed — an NTP
clock-skew counter, a "config last saved at HH:MM:SS" banner. Left in,
`configrxdb.add_backup`'s sha256-of-the-cleaned-text change detection stores
a new version every cycle even though nothing an operator would call a
change actually happened. `strip_volatile` drops those whole lines before
the hash is taken (see configrx.py's `_clean_output`, which calls this
before redaction).

Keyed by the same vendor key as `configrx.VENDORS`, so each set of patterns
only ever applies to that vendor's own captures. A vendor with nothing
volatile documented here (or one this module simply hasn't covered yet)
maps to no built-in patterns and every line of its capture passes through
unless an operator-supplied `extra_patterns` line also matches — those
apply to every vendor, since a site-local banner is not vendor-specific.
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
    # Documentation-sourced vendors (moxa, siemens, rockwellautomation,
    # ubiquiti) and anything unrecognised: no volatile lines documented,
    # so they get no built-in patterns here — extra_patterns still apply.
}


def strip_volatile(text: str, vendor_key: str,
                   extra_patterns: tuple[re.Pattern, ...] = ()) -> str:
    """`text` with every whole line matching a built-in pattern for
    `vendor_key`, or any of `extra_patterns`, dropped entirely. A line is
    matched from its start (`Pattern.match`), not required to match the
    whole line, so a pattern need not account for trailing whitespace or
    content the vendor appends after the part that identifies it.
    """
    patterns = VOLATILE.get((vendor_key or "").strip().lower(), ()) + tuple(extra_patterns)
    if not patterns:
        return text
    lines = [line for line in text.split("\n")
            if not any(p.match(line) for p in patterns)]
    return "\n".join(lines)
