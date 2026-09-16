"""Pulls one interface's own block out of a whole-device stored config, for
the Interface Detail dialog's RUNNING CONFIGURATION tile. Covers the
indented-block vendors (Cisco, Arista, Aruba) plus a Juniper brace-matcher.
Pure text in, text or None out."""

from __future__ import annotations

import re

_INTERFACE_HEADER_RE = re.compile(r"^interface\s+(\S.*?)\s*$", re.IGNORECASE)

# A header nested under something else -- IOS-XR's `interface X` inside a
# `router ospf` stanza, or a paged capture with pager residue ahead of the
# line. Column-0 headers are always tried first, so a real column-0 stanza
# never loses to one of these.
_INTERFACE_HEADER_INDENTED_RE = re.compile(r"^(\s+)interface\s+(\S.*?)\s*$", re.IGNORECASE)

# A candidate's alphabetic lead (Gi, Port-channel) split from its digits/
# slashes/dots/colons; ProCurve's "1/A1" has no letter lead, so no prefix.
_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z-]*)(.*)$")


def _split_prefix(name: str) -> tuple[str, str]:
    m = _PREFIX_RE.match(name)
    return (m.group(1), m.group(2)) if m else ("", name)


def _exact_match(a: str, b: str) -> bool:
    a, b = a.strip(), b.strip()
    return bool(a) and bool(b) and a.lower() == b.lower()


def _prefix_match(a: str, b: str) -> bool:
    """Gi/GigabitEthernet-style match: same trailing digits, one's prefix a
    prefix of the other's. Ambiguous alone (Tw also prefixes TwentyFiveGigE)
    -- callers try _exact_match across every header first."""
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
    """Exact or prefix match; used by the Juniper brace-matcher, which has
    no multi-header ambiguity to resolve with a two-pass search."""
    return _exact_match(a, b) or _prefix_match(a, b)


def _indented_block(lines: list[str], start: int) -> str:
    """Collects the header at lines[start] plus every indented or bare '!'
    line after it, stopping at the next non-indented line; a trailing '!'
    is dropped."""
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.startswith((" ", "\t")) or line.strip() == "!":
            block.append(line)
            continue
        break
    while block and block[-1].strip() == "!":
        block.pop()
    return "\n".join(block)


def _indent_len(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _indented_header_block(lines: list[str], start: int, header_indent: int) -> str:
    """Collects an indented header plus following lines indented deeper
    than it. A bare '!' or a line at the header's own indent or shallower
    ends the block and is not part of it -- there is no trailing '!' left
    to strip afterwards, unlike the column-0 form."""
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() == "!":
            break
        stripped = line.lstrip(" \t")
        if not stripped or _indent_len(line) <= header_indent:
            break
        block.append(line)
    return "\n".join(block)


_JUNIPER_INTERFACES_RE = re.compile(r"^\s*interfaces\s*\{\s*$")
_JUNIPER_NAMED_BLOCK_RE = re.compile(r"^\s*(\S+)\s*\{\s*$")


def _juniper_block(text: str, candidates: list[str]) -> str | None:
    """Brace-matcher for Junos' pretty-printed `interfaces { ge-0/0/0 { ...
    } }` form; does not attempt the single-line `set` output."""
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
    """The stored config's own block for one of `names` (ifName/ifDescr),
    or None. Column-0 headers are tried first -- exact equality, then the
    prefix rule -- so an earlier prefix-only hit (Tw1/0/1 against
    TwentyFiveGigE1/0/1), or an indented header nested under something
    else, never wins over a later exact column-0 one. Indented headers are
    then tried the same way, for a paged capture with pager residue ahead
    of the line."""
    if not text:
        return None
    candidates = [n for n in names if n]
    if not candidates:
        return None
    lines = text.split("\n")
    headers = []
    indented_headers = []
    for i, line in enumerate(lines):
        m = _INTERFACE_HEADER_RE.match(line)
        if m:
            headers.append((i, m.group(1)))
            continue
        m = _INTERFACE_HEADER_INDENTED_RE.match(line)
        if m:
            indented_headers.append((i, len(m.group(1)), m.group(2)))
    for i, header in headers:
        if any(_exact_match(header, c) for c in candidates):
            return _indented_block(lines, i)
    for i, header in headers:
        if any(_prefix_match(header, c) for c in candidates):
            return _indented_block(lines, i)
    for i, indent, header in indented_headers:
        if any(_exact_match(header, c) for c in candidates):
            return _indented_header_block(lines, i, indent)
    for i, indent, header in indented_headers:
        if any(_prefix_match(header, c) for c in candidates):
            return _indented_header_block(lines, i, indent)
    return _juniper_block(text, candidates)


def count_interface_headers(text: str) -> int:
    """How many 'interface' headers (column-0 or indented) the stored
    config carries -- what the interface dialog tells the operator it
    searched among when none of them matched."""
    if not text:
        return 0
    lines = text.split("\n")
    return (sum(1 for line in lines if _INTERFACE_HEADER_RE.match(line))
           + sum(1 for line in lines if _INTERFACE_HEADER_INDENTED_RE.match(line)))
