"""Cross-device configuration search, plus compliance rule evaluation.

Search matches a substring or bounded regex over every device's redacted
capture; compliance checks must_match/must_not_match rules against a
device's own unredacted capture, line by line. Both share
compile_bounded's ReDoS guard and a wall-clock budget.
"""

from __future__ import annotations

import re
import time


# --- Cross-device search over stored (redacted-only) configurations; compile_bounded/MAX_LINE_CHARS_FOR_MATCH/SEARCH_BUDGET_S bound an operator-supplied regex against ReDoS. ---

MAX_PATTERN_CHARS = 200
MAX_LINE_CHARS_FOR_MATCH = 250
# See _has_adjacent_quantifiers: more than this many chained quantified atoms is refused.
MAX_ADJACENT_QUANTIFIER_RUN = 3
SEARCH_BUDGET_S = 2.0
# Trigram indexing has nothing to match below this length (see syslogdb.MIN_INDEXED_TERM).
MIN_INDEXED_CHARS = 3
DEFAULT_LIMIT = 500


class UnsafeRegex(ValueError):
    """Raised by compile_bounded() — the pattern is refused before it is
    ever run, not merely bounded once running. A caller turns this into a
    plain 400-style message; it is never a sign the search itself failed."""


_COUNTED_RE = re.compile(r"\{\d*(?:,\d*)?\}")

# A counted repeat of an already-repeating group is only safe while the count
# is small: (a+){1,100} backtracks exponentially exactly as (a+)+ does, and
# MAX_LINE_CHARS_FOR_MATCH is 250. Past this many repeats a counted
# quantifier is treated as unbounded, which keeps the documented exemption
# for small fixed repeats like (\d{1,3}\.){3}.
MAX_SAFE_COUNTED_REPEAT = 4


def _counted_upper(inner: str) -> int:
    """The largest repeat count `{...}`'s body allows, 0 if it does not say."""
    upper = inner.split(",")[-1]
    return int(upper) if upper.isdigit() else 0


def _quantifier_at(pattern: str, i: int) -> tuple[bool, int, bool]:
    """(is there a quantifier at i, how many chars it spans, is it
    unbounded) for '+', '*', or a counted '{m,n}' (with its lazy '?')."""
    if i >= len(pattern):
        return False, 0, False
    if pattern[i] in "+*":
        lazy = i + 1 < len(pattern) and pattern[i + 1] == "?"
        return True, 2 if lazy else 1, True
    if pattern[i] == "{":
        m = _COUNTED_RE.match(pattern, i)
        if m:
            end = m.end()
            lazy = end < len(pattern) and pattern[end] == "?"
            inner = pattern[i + 1:end - 1]
            unbounded = (inner.endswith(",")
                         or _counted_upper(inner) > MAX_SAFE_COUNTED_REPEAT)
            return True, (end - i) + (1 if lazy else 0), unbounded
    return False, 0, False


def _variable_repeat_at(pattern: str, i: int) -> bool:
    """Whether the quantifier at i can match a VARYING number of copies --
    '+', '*', and '{m,n}' with m != n. A fixed '{2}' cannot, so it always
    divides the input at the same place and two neighbouring repeats of the
    group holding it can never trade characters with each other."""
    if i >= len(pattern):
        return False
    if pattern[i] in "+*":
        return True
    if pattern[i] == "{":
        m = _COUNTED_RE.match(pattern, i)
        if m:
            parts = pattern[i + 1:m.end() - 1].split(",")
            if len(parts) == 1:
                return False                      # {n}: exactly n copies
            low, high = parts[0] or "0", parts[1]
            return not (low.isdigit() and high.isdigit() and low == high)
    return False


def _skip_char_class(pattern: str, i: int) -> int:
    """Index just past the `[...]` starting at i (which must be '['),
    treating a leading ']' as the literal IEEE/POSIX convention does."""
    n = len(pattern)
    j = i + 1
    if j < n and pattern[j] == "]":
        j += 1
    while j < n and pattern[j] != "]":
        j += 2 if pattern[j] == "\\" else 1
    return j + 1


def _has_nested_repetition(pattern: str) -> bool:
    r"""True for a group that can already match the same run of text more than
    one way ((a+)+, (a|aa)+) and is itself quantified with no upper bound.

    A group only counts as ambiguous when it holds an alternation, or when its
    LAST element repeats a varying number of times -- that is what lets two
    neighbouring repeats of the group trade characters with each other, which
    is the whole of the blow-up. A group whose last element is a fixed repeat
    ({2}) or a separator the repeat cannot match (\w+\.) divides the input at
    one place instead, so the MAC, IPv6 and FQDN patterns an operator actually
    writes are accepted alongside the documented (\d{1,3}\.){3}\d{1,3}, while
    (\d{1,3}){3,} -- the same idiom with nothing between the repeats -- is
    not. Not a full analysis; a heuristic, deliberately over-inclusive.
    """
    n = len(pattern)
    i = 0
    # Per open group: [it contains an alternation, its last element so far
    # repeats a varying number of times].
    open_groups: list[list[bool]] = []

    def tail(varying: bool) -> None:
        if open_groups:
            open_groups[-1][1] = varying

    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            tail(False)
            continue
        if c == "[":
            i = _skip_char_class(pattern, i)
            tail(False)
            continue
        if c == "(":
            open_groups.append([False, False])
            i += 1
            continue
        if c == ")":
            if open_groups:
                alternation, varying_tail = open_groups.pop()
                ambiguous = alternation or varying_tail
                quantified_after, consumed, unbounded_after = _quantifier_at(pattern, i + 1)
                if ambiguous and quantified_after and unbounded_after:
                    return True
                # The group is one element of its parent, and leaves the parent
                # open to the same split only when it can itself swallow a run
                # of text more than one way or without an upper bound.
                tail(ambiguous or (quantified_after and unbounded_after))
                i += 1 + consumed
                continue
            i += 1
            continue
        if c == "|":
            if open_groups:
                open_groups[-1][0] = True
                open_groups[-1][1] = False
            i += 1
            continue
        quantifier_here, consumed, _unbounded_here = _quantifier_at(pattern, i)
        if quantifier_here:
            tail(_variable_repeat_at(pattern, i))
            i += consumed
            continue
        tail(False)
        i += 1
    return False


def _has_adjacent_quantifiers(pattern: str, max_run: int = MAX_ADJACENT_QUANTIFIER_RUN) -> bool:
    """True when more than `max_run` quantified atoms that can match the
    same characters occur back to back — \\d+\\d+\\d+\\d+, (a+)(a+)(a+)(a+).
    Two adjacent plain literals that clearly differ (a+b+) reset the run,
    since they can't actually match the same characters."""
    n = len(pattern)
    i = 0
    run = 0
    last_literal: str | None = None
    while i < n:
        c = pattern[i]
        if c in "()|":
            i += 1
            continue
        if c == "\\":
            atom_end = min(i + 2, n)
            plain_literal = False
        elif c == "[":
            atom_end = _skip_char_class(pattern, i)
            plain_literal = False
        else:
            atom_end = i + 1
            plain_literal = True
        quantified, consumed, _unbounded = _quantifier_at(pattern, atom_end)
        if quantified:
            if plain_literal and last_literal is not None and last_literal != c:
                run = 1
            else:
                run += 1
            if run > max_run:
                return True
            last_literal = c if plain_literal else None
        else:
            run = 0
            last_literal = None
        i = atom_end + consumed
    return False


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
            "Pattern repeats a group that can already repeat, with nothing "
            "bounding how many times the outer repeat can happen — a group "
            "counts as already repeating when it holds an alternation or "
            "ends in an open-ended repeat (something shaped like (a+)+ or "
            "(a|aa)+) — this is the construct behind "
            "almost every regular expression that runs in exponential "
            "time on ordinary text. Rewrite it without the nested "
            "repetition, e.g. a+ instead of (a+)+. A group repeated a "
            "small FIXED number of times, like (\\d{1,3}\\.){3}\\d{1,3}, "
            f"is fine — an outer repeat that is open-ended (+, *, or "
            f"{{n,}} with no upper limit) or larger than "
            f"{MAX_SAFE_COUNTED_REPEAT} is refused.")
    if _has_adjacent_quantifiers(pattern):
        raise UnsafeRegex(
            f"Pattern chains more than {MAX_ADJACENT_QUANTIFIER_RUN} "
            f"repeated tokens that can match the same characters with "
            f"nothing distinguishing them in between (something shaped "
            f"like \\d+\\d+\\d+\\d+) — this runs in polynomial time that "
            f"gets impractical fast. Put a literal separator between "
            f"repeated tokens (\\d+\\.\\d+, not \\d+\\d+) or reduce how "
            f"many are chained.")
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise UnsafeRegex(f"Not a valid regular expression: {exc}") from exc


def bounded_line(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS_FOR_MATCH else line[:MAX_LINE_CHARS_FOR_MATCH]


def _fts_query(text: str) -> str:
    """The whole query as one quoted FTS5 phrase (not per-word ANDed like
    syslogdb's), so trigram matching approximates a substring search.
    Embedded double quotes are doubled per FTS5's own escaping."""
    return '"' + text.replace('"', '""') + '"'


def can_index(text: str) -> bool:
    return len(text) >= MIN_INDEXED_CHARS


def search(db, query: str, mode: str = "text", device_ids: list[int] | None = None,
          limit: int = DEFAULT_LIMIT) -> dict:
    """One query against every device's latest (redacted) capture.

    mode: "text" for a plain substring, "regex" for a bounded regex (see
    compile_bounded). Returns {"matches": [...], "truncated", "indexed"};
    truncated means SEARCH_BUDGET_S was hit before every capture was tried.
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

    # Fallback: no FTS5, or a query under the trigram floor. Plain substring
    # test — a literal query must never be treated as a regex.
    needle = query
    return _scan(db, lambda line: needle in line, device_ids, limit)


def _scan(db, matches_line, device_ids: list[int] | None, limit: int) -> dict:
    """Shared by regex mode and the plain-substring fallback: walk every
    indexed line, checking the wall-clock budget before each one rather
    than only between devices, since one device's line count alone can
    exceed SEARCH_BUDGET_S even with each line capped."""
    rows = db.all_search_lines(device_ids)
    deadline = time.monotonic() + SEARCH_BUDGET_S
    out: list[dict] = []
    truncated = False
    for row in rows:
        if time.monotonic() > deadline:
            # Ran out of time, not out of matches (distinct from the `limit` cap below).
            truncated = True
            break
        if len(out) >= limit:
            break
        if matches_line(bounded_line(row["line"])):
            out.append({"device_id": row["device_id"], "line_no": row["line_no"],
                       "line": row["line"]})
    return {"matches": out, "truncated": truncated, "indexed": False}


# --- Compliance rule sets: evaluated line by line against a device's own (unredacted) capture. ---

class RuleKind:
    MUST_MATCH = "must_match"
    MUST_NOT_MATCH = "must_not_match"


_VALID_KINDS = (RuleKind.MUST_MATCH, RuleKind.MUST_NOT_MATCH)

COMPLIANCE_FAIL_METRIC = "compliance_fail_count"

# Wall-clock ceiling for one evaluate_all/evaluate_device_all_rule_sets call —
# headroom for a normal fleet, a hard stop for one bad rule.
COMPLIANCE_SWEEP_BUDGET_S = 10.0

# Distinct from "not_assessed": this device has a capture but ran out of
# budget before every rule set finished. Never counted as "assessed".
STATUS_NOT_YET_ASSESSED = "not_yet_assessed"


def add_rule_set(db, name: str, device_group_id: int | None = None) -> int:
    return db.add_rule_set(name, device_group_id)


def add_rule(db, rule_set_id: int, description: str, kind: str, pattern: str,
            ordinal: int = 0) -> int:
    """Validates via compile_bounded (raises UnsafeRegex) before storing —
    configrxdb.add_rule itself does not validate, so this is the only safe
    entry point for a new rule's pattern."""
    if kind not in _VALID_KINDS:
        raise ValueError(f"kind must be one of {_VALID_KINDS}, got {kind!r}")
    if not description or not description.strip():
        raise ValueError("A rule needs a human-readable description")
    compile_bounded(pattern)
    return db.add_rule(rule_set_id, description, kind, pattern, ordinal)


def _device_ids_in_scope(nodes_db, rule_set_row) -> list[int]:
    group_id = rule_set_row["device_group_id"]
    rows = (nodes_db.devices(device_group_id=group_id) if group_id is not None
           else nodes_db.devices())
    return [row["id"] for row in rows]


def evaluate_device(db, device_id: int, rules, deadline: float | None = None) -> dict:
    """One device against an already-fetched list of compliance_rules rows.
    Returns {"status", "failed_rules", "backup_id", "truncated"}; does not
    write anything (see set_compliance_result). `deadline`, when given, is
    checked before every rule and every line, since proving a
    MUST_NOT_MATCH rule never matches means scanning every line.
    """
    backups = db.backups_for(device_id, limit=1)
    if not backups:
        return {"status": "not_assessed", "failed_rules": [], "backup_id": None,
               "truncated": False}
    backup_id = backups[0]["id"]
    content = db.backup_content(backup_id) or ""
    lines = [bounded_line(line) for line in content.split("\n")]

    failed = []
    truncated = False
    for rule in rules:
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        try:
            pattern = compile_bounded(rule["pattern"])
        except UnsafeRegex as exc:
            # A rule stored before this check existed (or tightened since) fails
            # CLOSED rather than vanishing silently from every result -- and
            # carries why, so the failure does not read as the device's fault.
            failed.append({"rule_id": rule["id"],
                           "description": rule["description"],
                           "reason": f"Rule not evaluated: {exc}"})
            continue
        matched = False
        for line in lines:
            if deadline is not None and time.monotonic() > deadline:
                truncated = True
                break
            if pattern.search(line):
                matched = True
                break
        if truncated:
            # Not resolved either way — do not score it as pass or fail.
            break
        ok = matched if rule["kind"] == RuleKind.MUST_MATCH else not matched
        if not ok:
            failed.append({"rule_id": rule["id"], "description": rule["description"]})

    if failed:
        status = "fail"
    elif truncated:
        status = STATUS_NOT_YET_ASSESSED
    else:
        status = "pass"
    return {"status": status, "failed_rules": failed, "backup_id": backup_id,
           "truncated": truncated}


def _record_metric(nodes_db, db, device_id: int) -> None:
    """Reads back this device's own just-written results (correct
    regardless of how many rule sets were evaluated in this pass). Records
    nothing when every result is not_assessed or not_yet_assessed — an
    unfinished check must never read as a compliant 0."""
    results = db.compliance_results_for_device(device_id)
    assessed = [r for r in results if r["status"] in ("pass", "fail")]
    if not assessed:
        return
    fail_count = sum(1 for r in assessed if r["status"] == "fail")
    nodes_db.record_metric_samples(device_id, [
        (COMPLIANCE_FAIL_METRIC, "ConfigRX rule sets failing", "count",
         "gauge", time.time(), fail_count),
    ])


def evaluate_device_all_rule_sets(db, nodes_db, device_id: int,
                                  budget_s: float | None = COMPLIANCE_SWEEP_BUDGET_S,
                                  stats: dict | None = None) -> int:
    """Every enabled rule set in scope for this device — called right after
    a new capture is stored, so results catch up without waiting for the
    next sweep. Returns how many rule sets were (re)evaluated. `budget_s`
    bounds the whole call; pass a `stats` dict to learn if it was hit.
    """
    device = nodes_db.device(device_id)
    if not device:
        return 0
    deadline = time.monotonic() + budget_s if budget_s is not None else None
    count = 0
    truncated = False
    for rule_set in db.rule_sets(enabled_only=True):
        group_id = rule_set["device_group_id"]
        if group_id is not None and device["device_group_id"] != group_id:
            continue
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        rules = db.rules_for(rule_set["id"])
        result = evaluate_device(db, device_id, rules, deadline=deadline)
        db.set_compliance_result(device_id, rule_set["id"], result["status"],
                                 result["failed_rules"], result["backup_id"])
        count += 1
        if result["truncated"]:
            truncated = True
            break
    if count:
        _record_metric(nodes_db, db, device_id)
    if stats is not None:
        stats["truncated"] = truncated
    return count


def evaluate_all(db, nodes_db, rule_set_id: int | None = None,
                 budget_s: float | None = COMPLIANCE_SWEEP_BUDGET_S,
                 stats: dict | None = None) -> int:
    """Every device in scope, for one rule set (rule_set_id given) or every
    enabled one (the default) — the periodic sweep and manual re-evaluate.
    Returns how many device x rule-set results were (re)computed.
    `budget_s` bounds the whole call, checked before each rule set, each
    device, and (inside evaluate_device) each rule and line.
    """
    if rule_set_id is not None:
        row = db.rule_set(rule_set_id)
        rule_sets = [row] if row is not None and row["enabled"] else []
    else:
        rule_sets = db.rule_sets(enabled_only=True)

    deadline = time.monotonic() + budget_s if budget_s is not None else None
    count = 0
    truncated = False
    touched_devices: set[int] = set()
    for rule_set in rule_sets:
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        device_ids = _device_ids_in_scope(nodes_db, rule_set)
        rules = db.rules_for(rule_set["id"])
        for device_id in device_ids:
            if deadline is not None and time.monotonic() > deadline:
                truncated = True
                break
            result = evaluate_device(db, device_id, rules, deadline=deadline)
            db.set_compliance_result(device_id, rule_set["id"], result["status"],
                                     result["failed_rules"], result["backup_id"])
            touched_devices.add(device_id)
            count += 1
            if result["truncated"]:
                truncated = True
                break
        if truncated:
            break
    for device_id in touched_devices:
        _record_metric(nodes_db, db, device_id)
    if stats is not None:
        stats["truncated"] = truncated
    return count
