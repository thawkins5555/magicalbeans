"""Search across stored configurations — the query ConfigRX could not
answer before this file existed. `configrx.diff_texts` compares two
backups of the SAME device; nothing anywhere asked "which of my 2,000
switches has the wrong NTP server" across ALL of them, because nothing
kept a searchable copy of more than one device's capture at a time.

Two things make that query dangerous to add carelessly, and both are
handled here rather than left to whoever eventually wires a route to it.

Secrets. A stored capture is the device's credentials (configrx_redact.py's
own words), and get_configrx_diff already treats a cross-backup VIEW as
requiring stricter handling than a single backup's own download: it
redacts unconditionally, even for a device with store_secrets on, because
"nothing here may hand an unredacted secret to a diff reader even when the
device's own setting would let the single-backup view do exactly that."
A search box is a strictly worse place to leak one than a diff — a diff
only ever shows two specific backups an authorised caller already chose to
open, where a search box is *probed*, on purpose, with arbitrary
substrings, by anyone who can reach it. So the search index
(configrxdb.config_lines) is built ONLY from redacted text, written once
when a new capture lands (replace_search_lines), never from the verbatim
row `backups.content_gz` may also hold. There is no code path in this file
that ever reads a backup's raw content — only ConfigRxWorker (configrx.py)
does that, redacts it, and hands the redacted text here.

Regular expressions. `mibparse.py`'s _IMPORT_GROUP_RE and four macro
regexes used to be quadratic in the size of an uploaded file and froze the
whole application for 17 seconds on one crafted 32 KB upload (fixed in
4.39.0, see REVIEW-NETWORK-ENGINEER.md's G-10/G-11) — but that was OUR
regex, misbehaving on ordinary input, and the fix was to rewrite it. This
file runs an OPERATOR-SUPPLIED regex against every device's capture, which
is a different and harder problem: the pattern itself may be the thing
that misbehaves, on input that is not otherwise unusual at all. Nothing
here can rewrite an adversarial pattern the way mibparse rewrote its own,
so three independent bounds apply instead, none of them sufcient alone:

  1. compile_bounded() rejects a pattern before it is ever run at all —
     too long, or shaped like the nested-repetition every catastrophic-
     backtracking regex in common use has ((a+)+, (a*)+ and their many
     variants; see _has_nested_repetition). A heuristic, not a proof —
     Cox's "Regular Expression Matching Can Be Simple And Fast" is the
     usual citation for why a general one is not simple — so it catches
     the common shapes, not every possible one.
  2. Every line tested is capped at MAX_LINE_CHARS_FOR_MATCH first. Python
     has no way to preempt a `re` call that is already running — no
     signal.alarm on Windows, and a background-thread timeout only stops
     the CALLER from waiting, not the orphaned thread from spinning — so
     the only thing that actually bounds a single match call's worst case
     is bounding what it is handed. A real config line is a few hundred
     characters at most; this cap would never truncate one.
  3. SEARCH_BUDGET_S is a wall-clock ceiling on the WHOLE search, checked
     between devices (the same "checked between phases" shape
     mibparse.parse's own budget uses). It cannot stop one pathological
     line from taking as long as (2) allows, but it stops that cost from
     being paid once per device across a 2,000-device fleet — a search
     that hits the ceiling returns what it found so far with
     truncated=True rather than pretending to be complete.
"""

from __future__ import annotations

import re
import time

MAX_PATTERN_CHARS = 200
MAX_LINE_CHARS_FOR_MATCH = 4000
MAX_DOCUMENT_CHARS_FOR_MATCH = 2_000_000
SEARCH_BUDGET_S = 2.0
# Trigram (configrxdb._enable_search_fts) indexes three-character runs, so
# it has nothing to match on for a shorter query — same floor and same
# reasoning as syslogdb.SyslogDatabase.MIN_INDEXED_TERM.
MIN_INDEXED_CHARS = 3
DEFAULT_LIMIT = 500


class UnsafeRegex(ValueError):
    """Raised by compile_bounded() — the pattern is refused before it is
    ever run, not merely bounded once running. A caller turns this into a
    plain 400-style message; it is never a sign the search itself failed."""


def _has_nested_repetition(pattern: str) -> bool:
    """True when `pattern` contains a group that can already match the same
    text more than one way — because it repeats internally ((a+)+, (a*)+,
    ((a|b)+)+) or because it is a top-level alternation (a|aa)+ — and is
    ITSELF quantified again. Both shapes are ambiguous about how many ways
    the group can consume a given run of input, and an engine that
    backtracks (Python's `re` does) re-tries every one of those ways for
    every position the outer quantifier repeats at, which is what makes
    each of them run in exponential time on ordinary non-matching text —
    measured on this machine: `(a|aa)+$` against 35 non-matching
    characters already takes 2.6 seconds, and `(a+)+$` is the same shape
    with one alternative removed.

    Not a full analysis (undecidable in general for the constructs
    Python's `re` supports — see Cox, "Regular Expression Matching Can Be
    Simple And Fast") and deliberately over-inclusive: `(tcp|udp)+` is
    refused even though "tcp" and "udp" cannot actually overlap, because
    telling a genuinely safe alternation apart from a dangerous one needs
    exactly the kind of analysis this function is not attempting. A
    character class is skipped whole rather than parsed, so a `|` or
    quantifier char written literally inside `[...]` is never mistaken
    for one; the "can match more than one way" flag is tracked per
    currently-open group and propagated outward on close, so the shape
    still trips the check however many groups deep it is nested.
    """
    n = len(pattern)
    i = 0
    # One entry per currently-open group: can it already match a given run
    # of input more than one way (an internal repetition, or a top-level
    # alternation), directly or via a child group?
    open_groups: list[bool] = []
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and pattern[j] == "]":     # a leading ']' is literal
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            open_groups.append(False)
            i += 1
            continue
        if c == ")":
            if open_groups:
                ambiguous = open_groups.pop()
                quantified_after, consumed = _quantifier_at(pattern, i + 1)
                if ambiguous and quantified_after:
                    return True
                # Propagate to the parent group if THIS group was already
                # ambiguous (nested one level deeper), or if this group is
                # itself being quantified right now — either way the
                # parent now contains something that can match more than
                # one way, which is what matters if the parent is
                # quantified too.
                if open_groups and (ambiguous or quantified_after):
                    open_groups[-1] = True
                i += 1 + consumed
                continue
            i += 1
            continue
        if c == "|" and open_groups:
            open_groups[-1] = True
            i += 1
            continue
        quantifier_here, consumed = _quantifier_at(pattern, i)
        if quantifier_here and open_groups:
            open_groups[-1] = True
        i += max(consumed, 1)
    return False


_COUNTED_RE = re.compile(r"\{\d*(?:,\d*)?\}")


def _quantifier_at(pattern: str, i: int) -> tuple[bool, int]:
    """(is there a quantifier starting at index i, how many chars it is) —
    '+', '*' and a counted '{m,n}' (including its lazy '?' suffix, which
    changes backtracking order but not whether the group can repeat)."""
    if i >= len(pattern):
        return False, 0
    if pattern[i] in "+*":
        lazy = i + 1 < len(pattern) and pattern[i + 1] == "?"
        return True, 2 if lazy else 1
    if pattern[i] == "{":
        m = _COUNTED_RE.match(pattern, i)
        if m:
            end = m.end()
            lazy = end < len(pattern) and pattern[end] == "?"
            return True, (end - i) + (1 if lazy else 0)
    return False, 0


def compile_bounded(pattern: str, flags: int = 0) -> re.Pattern:
    """A pattern refused up front is a pattern never run at all — see the
    module docstring for what this does and does not guarantee."""
    if not pattern:
        raise UnsafeRegex("Pattern must not be empty")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise UnsafeRegex(
            f"Pattern is {len(pattern)} characters, over the "
            f"{MAX_PATTERN_CHARS}-character limit for a search or "
            f"compliance rule run against every device's capture")
    if _has_nested_repetition(pattern):
        raise UnsafeRegex(
            "Pattern repeats a group that can already repeat (something "
            "shaped like (a+)+ or (a*)+) — this is the construct behind "
            "almost every regular expression that runs in exponential "
            "time on ordinary text. Rewrite it without the nested "
            "repetition, e.g. a+ instead of (a+)+.")
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise UnsafeRegex(f"Not a valid regular expression: {exc}") from exc


def _bounded_line(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS_FOR_MATCH else line[:MAX_LINE_CHARS_FOR_MATCH]


def bounded_document(text: str) -> str:
    """The same defence as _bounded_line, sized for a whole capture rather
    than one line — configrx_compliance evaluates a rule against the
    document as a whole (so `^ntp server 10\\.0\\.0\\.5$` with MULTILINE
    can anchor per line), not line by line, so the cap here is the
    document-sized equivalent of MAX_LINE_CHARS_FOR_MATCH."""
    return text if len(text) <= MAX_DOCUMENT_CHARS_FOR_MATCH else text[:MAX_DOCUMENT_CHARS_FOR_MATCH]


def _fts_query(text: str) -> str:
    """The whole query as one quoted FTS5 phrase.

    syslogdb._fts_query splits on whitespace and ANDs each term — right
    for log search, where several words in any order across different
    columns is the question. A config search is closer to "does this
    literal run of characters appear" (an IP octet, a community name, a
    directive fragment with its own spaces), so the whole string is one
    phrase: trigram's shingles reconstruct substring matching for a
    quoted phrase the same way they do for `LIKE '%needle%'`, just
    through an index instead of a scan. Embedded double quotes are
    doubled, FTS5's own escape for a literal quote inside a phrase.
    """
    return '"' + text.replace('"', '""') + '"'


def can_index(text: str) -> bool:
    return len(text) >= MIN_INDEXED_CHARS


def search(db, query: str, mode: str = "text", device_ids: list[int] | None = None,
          limit: int = DEFAULT_LIMIT) -> dict:
    """One query against every device's latest (redacted) capture.

    mode: "text" for a plain substring, "regex" for a bounded regular
    expression (see compile_bounded — raises UnsafeRegex for a pattern
    this refuses to run at all).

    Returns {"matches": [{"device_id", "line_no", "line"}, ...],
    "truncated": bool, "indexed": bool}. `truncated` is True when
    SEARCH_BUDGET_S was reached before every device's capture had been
    tried (regex mode, or text mode with FTS5 unavailable/query too
    short) — the caller must say the result may be incomplete rather than
    present it as exhaustive. `indexed` says whether the FTS5 index
    answered the query or the full scan did, the same distinction
    syslogdb's own `fts` flag on its /api/syslog/state response makes.
    """
    query = (query or "").strip()
    if not query:
        return {"matches": [], "truncated": False, "indexed": False}

    if mode == "regex":
        pattern = compile_bounded(query)
        return _scan(db, pattern.search, device_ids, limit)

    if mode != "text":
        raise ValueError(f"Unknown search mode {mode!r}")

    if db.search_fts and can_index(query):
        rows = db.search_fts_match(_fts_query(query), device_ids, limit)
        return {"matches": [dict(row) for row in rows],
               "truncated": False, "indexed": True}

    # Fallback: no FTS5, or a query under the trigram floor. A plain
    # substring test, not a regex — a literal query must never be treated
    # as one, the same reasoning syslogdb's own scan path never runs the
    # user's text through LIKE's own wildcard syntax unescaped either
    # (here it is simpler: Python's `in` has no metacharacters at all).
    needle = query
    return _scan(db, lambda line: needle in line, device_ids, limit)


def _scan(db, matches_line, device_ids: list[int] | None, limit: int) -> dict:
    """Shared by regex mode and the plain-substring fallback: walk every
    indexed line, grouped by device so the wall-clock budget can be
    checked between devices rather than between individual lines — cheap
    enough not to matter against SEARCH_BUDGET_S, and matches this
    codebase's own "checked between phases" convention for a budget that
    cannot preempt a single call already in flight (see mibparse.parse's
    check_budget and the module docstring above)."""
    rows = db.all_search_lines(device_ids)
    deadline = time.monotonic() + SEARCH_BUDGET_S
    out: list[dict] = []
    truncated = False
    current_device = None
    for row in rows:
        if row["device_id"] != current_device:
            current_device = row["device_id"]
            if time.monotonic() > deadline:
                # Ran out of time, not out of matches — distinct from the
                # `limit` cap below, which is an ordinary "there may be
                # more, ask for another page" result and not flagged here.
                truncated = True
                break
        if len(out) >= limit:
            break
        if matches_line(_bounded_line(row["line"])):
            out.append({"device_id": row["device_id"], "line_no": row["line_no"],
                       "line": row["line"]})
    return {"matches": out, "truncated": truncated, "indexed": False}
