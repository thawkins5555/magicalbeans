"""Pulls one interface's own block out of a whole-device stored
configuration -- the Interface Detail dialog's RUNNING CONFIGURATION tile
reads a device's latest ConfigRX backup and shows just this port's stanza,
never the whole file.

Handles the indented-block vendors (Cisco IOS/IOS-XE/NX-OS/IOS-XR, Arista,
Aruba/HP ProCurve, Aruba CX) and a simplified brace-matcher for Juniper's
`interfaces { ge-0/0/0 { ... } }` style. Pure text in, text or None out --
no device access, no SNMP, so this is trivially unit-testable.
"""

from __future__ import annotations

import re

_INTERFACE_HEADER_RE = re.compile(r"^interface\s+(\S.*?)\s*$", re.IGNORECASE)

# A candidate's alphabetic (and hyphen -- "Port-channel") lead, split from
# whatever follows (digits/slashes/dots/colons for every vendor this ships
# against). A name with no letter at all (ProCurve's "1/A1") has no prefix,
# so it only ever matches by exact equality below.
_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z-]*)(.*)$")


def _split_prefix(name: str) -> tuple[str, str]:
    m = _PREFIX_RE.match(name)
    return (m.group(1), m.group(2)) if m else ("", name)


def _exact_match(a: str, b: str) -> bool:
    a, b = a.strip(), b.strip()
    return bool(a) and bool(b) and a.lower() == b.lower()


def _prefix_match(a: str, b: str) -> bool:
    """The Gi/GigabitEthernet, Po/Port-channel style match: same trailing
    digits/slashes/dots/colons, and one's alphabetic prefix a
    case-insensitive prefix of the other's -- so Gi1/0/1 never matches
    Gi1/0/10. Ambiguous on its own (Tw also prefixes TwentyFiveGigE), so
    callers try _exact_match across every header first."""
    a, b = a.strip(), b.strip()
    if not a or not b:
        return False
    prefix_a, rest_a = _split_prefix(a)
    prefix_b, rest_b = _split_prefix(b)
    if not prefix_a or not prefix_b:
        return False
    if rest_a.lower() != rest_b.lower():
        return False
    prefix_a, prefix_b = prefix_a.lower(), prefix_b.lower()
    return prefix_a.startswith(prefix_b) or prefix_b.startswith(prefix_a)


def _names_match(a: str, b: str) -> bool:
    """Nodes' SNMP ifName/ifDescr (short or long form) against a config's
    own interface name -- exact match or the prefix rule (see
    _prefix_match). Used by the Juniper brace-matcher, which has no
    multi-header ambiguity to resolve with a two-pass search."""
    return _exact_match(a, b) or _prefix_match(a, b)


def _indented_block(lines: list[str], start: int) -> str:
    """`lines[start]` is the 'interface ...' header. Collects it plus every
    following line that is indented or is a bare '!' separator, stopping at
    the first non-indented line that is not '!' -- which is either the next
    stanza's own header (NX-OS's no-separator style) or a '!'-delimited
    block's separator. The trailing '!', if any, is dropped."""
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.startswith((" ", "\t")) or line.strip() == "!":
            block.append(line)
            continue
        break
    while block and block[-1].strip() == "!":
        block.pop()
    return "\n".join(block)


_JUNIPER_INTERFACES_RE = re.compile(r"^\s*interfaces\s*\{\s*$")
_JUNIPER_NAMED_BLOCK_RE = re.compile(r"^\s*(\S+)\s*\{\s*$")


def _juniper_block(text: str, candidates: list[str]) -> str | None:
    """A simplified brace-matcher for Junos' pretty-printed `interfaces {
    ge-0/0/0 { ... } }` form -- one token per line, as `show configuration`
    prints it. Does not attempt Junos' single-line `set` output."""
    lines = text.split("\n")
    depth = 0
    inside = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if not inside:
            if _JUNIPER_INTERFACES_RE.match(line):
                inside, depth = True, 1
            i += 1
            continue
        if depth == 1:
            m = _JUNIPER_NAMED_BLOCK_RE.match(line)
            if m and any(_names_match(m.group(1), c) for c in candidates):
                block = [line]
                braces = line.count("{") - line.count("}")
                j = i + 1
                while j < len(lines) and braces > 0:
                    block.append(lines[j])
                    braces += lines[j].count("{") - lines[j].count("}")
                    j += 1
                return "\n".join(block)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            inside = False
        i += 1
    return None


def interface_stanza(text: str, names: list[str]) -> str | None:
    """The stored config's own block for one interface, or None when no
    line names it. `names` is the caller's candidate list (typically the
    interface's ifName and ifDescr); any one of them matching is enough.

    Two passes over every header: exact equality first, then the prefix
    rule -- otherwise an earlier prefix-only match (Tw1/0/1 against
    TwentyFiveGigE1/0/1) could win over a later exact one for the same
    file."""
    if not text:
        return None
    candidates = [n for n in names if n]
    if not candidates:
        return None
    lines = text.split("\n")
    headers = []
    for i, line in enumerate(lines):
        m = _INTERFACE_HEADER_RE.match(line)
        if m:
            headers.append((i, m.group(1)))
    for i, header in headers:
        if any(_exact_match(header, c) for c in candidates):
            return _indented_block(lines, i)
    for i, header in headers:
        if any(_prefix_match(header, c) for c in candidates):
            return _indented_block(lines, i)
    return _juniper_block(text, candidates)
