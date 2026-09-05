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

# The largest PRI a valid message can carry: facility 23, severity 7.
MAX_PRI = 191
# How far a device's own clock may differ from ours before its timestamp is
# discarded in favour of the arrival time. A BSD timestamp carries no year and
# no timezone, so a device in another zone, or with a wrong clock, files rows
# hours or months away from when they happened. Those sort to the top of every
# newest-first search for ever and, when they land in the future, prune's
# `ts < cutoff` can never remove them.
CLOCK_SKEW_S = 3600.0

# RFC 5424 places no limit on how many SD-ELEMENTs one message carries, but no
# real device sends more than a handful — a relayed line chaining several
# rsyslog hops through is the heaviest case seen in practice, at two or three.
# A message claiming thousands is not describing a bigger event, only costing
# more to parse; see _strip_structured_data for what it costs without a cap.
MAX_SD_ELEMENTS = 64

# Every *run* of C0 control bytes (0x00-0x1F) and DEL (0x7F). `.strip(
# "\r\n\x00 ")` only ever trimmed the *ends* of the decoded text, so an
# embedded NUL, CR or LF — or a full ANSI/VT100 escape sequence, which always
# opens with ESC, 0x1B — reached the stored message unmodified from any
# unauthenticated sender on UDP/514. The web UI escapes correctly on render
# (verified: this is not a stored-XSS issue), but the stored column is a
# ready-made terminal-escape-injection primitive for any CLI or export
# consumer that later cats these rows to a real terminal — a message can end
# with its own colour or cursor codes and hide or rewrite whatever prints
# after it.
#
# Replaced with a single space, not deleted: a device that legitimately
# packs a multi-line block (a stack trace, a config diff) into one syslog
# datagram separates its lines with a real \n, and deleting it outright would
# silently weld the words on either side into one ("line one\nline two"
# becomes "line oneline two") — corrupting a message this parser is supposed
# to store as-is just as surely as the injection this fix closes. A run of
# several control bytes (a Windows \r\n, or padding) collapses to one space
# rather than one per byte, so it still reads as a single word boundary.
# This still fully destroys CR, LF, NUL and the ESC byte every ANSI/VT100
# sequence starts with, and costs nothing real: the PRI, the RFC 5424 header
# fields and the structured-data brackets this parser reads are all
# printable ASCII, and none of the shapes below need a raw control byte to
# recognise them.
_CONTROL_BYTES = re.compile(r"[\x00-\x1f\x7f]+")


def _strip_control(text: str) -> str:
    return _CONTROL_BYTES.sub(" ", text)


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
        stamp = time.mktime((year, month_number, int(day), hour, minute, second,
                             0, 0, -1))
    except (ValueError, OverflowError):
        return now
    # mktime read the device's clock as this server's local time, which is
    # wrong for any device in another timezone and for any device with a wrong
    # clock. Rather than filing the row hours or months away from when it
    # happened, fall back to the arrival time, which is at least true.
    if abs(stamp - now) > CLOCK_SKEW_S:
        return now
    return stamp


def parse(data: bytes, source: str, now: float | None = None) -> LogEntry:
    """Turn one datagram into an entry. Never raises."""
    now = now or time.time()
    try:
        text = _strip_control(data.decode("utf-8", "replace")).strip(" ")
    except Exception:
        text = repr(data)

    entry = LogEntry(ts=now, source=source, message=text, raw=text)

    priority = _PRI.match(text)
    body = text
    if priority:
        value = int(priority.group(1))
        if value <= MAX_PRI:
            entry.facility = value >> 3
            entry.severity = value & 0x07
            body = text[priority.end():]
        # Above 191 the angle brackets are not a PRI at all — <999> yielded
        # facility 124, which no filter dropdown offers — so the whole line
        # stays message text at the default facility and severity.

    # RFC 5424 announces itself with a version number of 1.
    if body[:2] == "1 ":
        parts = body[2:].split(" ", 5)
        # A heartbeat with no MSG at all is valid and common, and splits into
        # five parts; requiring six stored the whole header as the message.
        if len(parts) == 5:
            parts = parts + [""]
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
    """Drop the RFC 5424 structured-data block, keeping the readable message.

    A message carries any number of SD-ELEMENTs, and relayed rsyslog lines
    routinely carry two —
    `[timeQuality tzKnown="1"][origin ip="10.1.1.1" software="rsyslogd"]`.
    Returning after the first one left the rest of the metadata blob in the
    message column and in the trigram index, so searches matched SD noise.

    Walks the string with an index rather than reassigning `rest` to a slice
    of itself each time round the loop: `rest = rest[end:]` copies everything
    from `end` to the end of the string, so a message carrying thousands of
    tiny elements — nothing RFC 5424 forbids, and free for a device or an
    attacker on 514/udp or /tcp to send — cost O(elements^2) rather than
    O(length). `_end_of_element` still only scans one element per call, so
    the whole walk is linear in the string once no fresh slice is taken.

    MAX_SD_ELEMENTS bounds the *count* of elements this function will parse,
    independent of that fix: a message is still free to be large (a single
    SD-ELEMENT's value can legitimately run to a few KB), so capping total
    length would either truncate a real one or need to be generous enough to
    let this run anyway. Capping the element count instead bounds the work
    directly, since each one costs the same regardless of how small it is.
    Past the cap, whatever is left — genuine elements this device actually
    sent, or the attacker's padding — is kept verbatim as message text rather
    than parsed further or silently dropped; a message is stored either way,
    just with unusually many brackets sitting in its message column instead
    of behind the structured-data label, which is what every message already
    looked like before this function existed.
    """
    rest = rest.lstrip()
    if not rest.startswith("["):
        return rest[2:] if rest.startswith("- ") else (
            "" if rest == "-" else rest)
    pos = 0
    end_of_string = len(rest)
    elements = 0
    while pos < end_of_string and rest[pos] == "[":
        if elements >= MAX_SD_ELEMENTS:
            break
        stop = _end_of_element(rest, pos)
        if stop is None:
            return rest[pos:]        # unterminated: keep it rather than guess
        pos = stop
        while pos < end_of_string and rest[pos].isspace():
            pos += 1
        elements += 1
    return rest[pos:]


def _end_of_element(rest: str, start: int = 0) -> int | None:
    """Index just past the first balanced `[...]` starting at `start`, or
    None if unterminated. Takes a start offset instead of always scanning
    from position 0 so a caller walking several elements in one string (see
    _strip_structured_data) can do it in one left-to-right pass rather than
    re-scanning a fresh copy of the tail for each one."""
    depth = 0
    escaped = False
    for index in range(start, len(rest)):
        char = rest[index]
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
                return index + 1
    return None
