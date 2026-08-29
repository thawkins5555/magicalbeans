"""Syslog parsing and collection.

Two wire formats are in use and both turn up on the same port: RFC 3164, the
original BSD one that most network gear still speaks, and RFC 5424, which
carries a real timestamp and structured data. Neither is reliably well formed,
so parsing degrades rather than fails — an unparseable line is still stored,
with the whole line as its message.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

FACILITIES = [
    "kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6",
    "local7",
]

SEVERITIES = [
    "emergency", "alert", "critical", "error",
    "warning", "notice", "info", "debug",
]

MONTHS = {name: index for index, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def facility_name(number) -> str:
    try:
        return FACILITIES[int(number)]
    except (TypeError, ValueError, IndexError):
        return f"facility {number}"


def severity_name(number) -> str:
    try:
        return SEVERITIES[int(number)]
    except (TypeError, ValueError, IndexError):
        return f"severity {number}"


@dataclass
class LogEntry:
    ts: float
    source: str
    host: str = ""
    facility: int = 1
    severity: int = 6
    app: str = ""
    procid: str = ""
    msgid: str = ""
    message: str = ""
    raw: str = ""


_PRI = re.compile(r"^<(\d{1,3})>")
_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$", re.S)
_TAG = re.compile(r"^(?P<app>[^\s\[:]{1,48})(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$", re.S)
_RFC5424_TS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(Z|[+-]\d{2}:\d{2})$")


def _parse_5424_time(text: str) -> float | None:
    match = _RFC5424_TS.match(text)
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    try:
        import calendar
        stamp = calendar.timegm((int(year), int(month), int(day),
                                 int(hour), int(minute), int(second), 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    if fraction:
        stamp += float(f"0.{fraction}")
    if zone and zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        offset = int(zone[1:3]) * 3600 + int(zone[4:6]) * 60
        stamp -= sign * offset
    return stamp


def _parse_3164_time(month: str, day: str, clock: str, now: float) -> float:
    """BSD timestamps carry no year, so infer it from the current date.

    A December message read in January belongs to the previous year; without
    this every year boundary would file a day of logs twelve months ahead.
    """
    local = time.localtime(now)
    hour, minute, second = (int(part) for part in clock.split(":"))
    month_number = MONTHS.get(month, local.tm_mon)
    year = local.tm_year
    if month_number == 12 and local.tm_mon == 1:
        year -= 1
    elif month_number == 1 and local.tm_mon == 12:
        year += 1
    try:
        return time.mktime((year, month_number, int(day), hour, minute, second,
                            0, 0, -1))
    except (ValueError, OverflowError):
        return now


def parse(data: bytes, source: str, now: float | None = None) -> LogEntry:
    """Turn one datagram into an entry. Never raises."""
    now = now or time.time()
    try:
        text = data.decode("utf-8", "replace").strip("\r\n\x00 ")
    except Exception:
        text = repr(data)

    entry = LogEntry(ts=now, source=source, message=text, raw=text)

    priority = _PRI.match(text)
    body = text
    if priority:
        value = int(priority.group(1))
        entry.facility = value >> 3
        entry.severity = value & 0x07
        body = text[priority.end():]

    # RFC 5424 announces itself with a version number of 1.
    if body[:2] == "1 ":
        parts = body[2:].split(" ", 5)
        if len(parts) >= 6:
            stamp, host, app, procid, msgid, rest = parts
            when = _parse_5424_time(stamp)
            entry.ts = when if when else now
            entry.host = "" if host == "-" else host
            entry.app = "" if app == "-" else app
            entry.procid = "" if procid == "-" else procid
            entry.msgid = "" if msgid == "-" else msgid
            entry.message = _strip_structured_data(rest)
            return entry

    legacy = _RFC3164.match(body)
    if legacy:
        entry.ts = _parse_3164_time(legacy.group("mon"), legacy.group("day"),
                                    legacy.group("time"), now)
        rest = legacy.group("rest")
        # Hostname is optional in practice; treat a leading token with no colon
        # as the host and anything else as the start of the message.
        pieces = rest.split(" ", 1)
        if len(pieces) == 2 and ":" not in pieces[0] and "[" not in pieces[0]:
            entry.host, rest = pieces[0], pieces[1]
        tag = _TAG.match(rest)
        if tag:
            entry.app = tag.group("app")
            entry.procid = tag.group("pid") or ""
            entry.message = tag.group("msg")
        else:
            entry.message = rest
        return entry

    # Neither shape matched. Keep the line rather than dropping it.
    entry.message = body.strip() or text
    return entry


def _strip_structured_data(rest: str) -> str:
    """Drop the RFC 5424 structured-data block, keeping the readable message."""
    rest = rest.lstrip()
    if not rest.startswith("["):
        return rest[2:] if rest.startswith("- ") else (
            "" if rest == "-" else rest)
    depth = 0
    escaped = False
    for index, char in enumerate(rest):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return rest[index + 1:].lstrip()
    return rest
