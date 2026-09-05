"""Regression tests for two quadratic-time DoS bugs a fuzz campaign found in
files that take input straight off the wire (`syslogparse.py`, unauthenticated
on 514/udp+tcp) and off an upload (`mibparse.py`, the file whose own docstring
already records two earlier instances of this exact bug class being fixed).

Both bugs shared one shape: a hand-written loop whose per-iteration cost was
assumed O(1) but was actually O(remaining input), because each iteration threw
away a Python string and rebuilt a shorter one from a slice — `rest = rest[i:]`
in syslogparse, `text.find("\\n", ...)` scanning to end-of-file in mibparse.
Neither is a regex, so neither would have been caught by only auditing this
codebase's regexes for catastrophic backtracking.

Every timing assertion below carries a wide margin: the bound is comfortably
above what the fixed code measures on a slow, loaded machine, and comfortably
below what the unfixed code measured in the campaign that found these (recorded
in each comment) — tight enough that reverting either fix fails its test, not
tight enough to flap in CI. Control cases are included alongside each
regression, so an "optimisation" that got its speed by parsing less (or not at
all) fails those instead of merely coincidentally passing the timing check.
"""
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import mibparse
from netpath import syslogparse

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{(': ' + detail) if detail else ''}")
    if not ok:
        FAILURES.append(label)


def timed(fn, *args, **kwargs):
    started = time.perf_counter()
    value = fn(*args, **kwargs)
    return value, time.perf_counter() - started


# ============================================================ syslogparse.py
#
# netpath/syslogparse.py:206-230, _strip_structured_data/_end_of_element.
# An RFC 5424 message's structured-data block is a run of zero or more
# `[...]` SD-ELEMENTs; nothing in the RFC bounds how many. The old code
# walked them with `rest = rest[end:].lstrip()` each time round the loop —
# a fresh copy of everything left, every iteration — so N tiny elements cost
# O(N^2). Measured before the fix: 240,000 elements (~720 KB) took 2.34 s;
# 500,000 elements (~1.5 MB) did not finish in 8 s. Both figures came from
# feeding syslogparse.parse() directly, the same entry point used below.

print("D1  syslogparse: many small SD-ELEMENTs no longer costs O(elements^2)")


def sd_message(count: int, tail: bytes = b" tail") -> bytes:
    elements = b"".join(b"[a]" for _ in range(count))
    return (b"<134>1 2024-01-01T00:00:00Z host app 1 msgid " + elements + tail)


# 500,000 elements is the exact size that did not finish in 8 s before the
# fix. 1 s is ~8x the ~0.03s the fixed+capped code actually measures, and
# two orders of magnitude below "did not finish in 8 s".
many_small, elapsed = timed(syslogparse.parse, sd_message(500_000), "10.0.0.1")
check("500,000 tiny SD-ELEMENTs parse in under 1 s (unfixed: did not finish in 8s)",
      elapsed < 1.0, f"{elapsed:.3f}s")

# The cap (MAX_SD_ELEMENTS) is what makes the above true independent of size
# at all — confirm growing the input further doesn't grow the time, which a
# plain O(n) fix (with no cap) would not give you.
huge_small, elapsed_huge = timed(syslogparse.parse, sd_message(4_000_000), "10.0.0.1")
check("4,000,000 tiny SD-ELEMENTs cost about the same as 500,000 (the cap, not just linearity)",
      elapsed_huge < 1.0, f"{elapsed_huge:.3f}s")

# Control: a handful of large elements (the realistic shape — a real
# SD-ELEMENT's value can legitimately run to a few KB) must stay linear in
# their own size and must NOT be truncated by the element-count cap, proving
# the fix is an algorithmic one and not a length cap wearing a disguise.
big_value = "x" * 500_000
big_elements = "".join(f'[e{i} k="{big_value}"]' for i in range(10))
big_msg = (f"<134>1 2024-01-01T00:00:00Z host app 1 msgid {big_elements} tail").encode()
_, elapsed_big = timed(syslogparse.parse, big_msg, "10.0.0.1")
check("10 large (500 KB) SD-ELEMENTs — ~5 MB total — still parse in under 2 s",
      elapsed_big < 2.0, f"{elapsed_big:.3f}s")

# ---------------------------------------------- D1 correctness, not just speed
#
# A "fix" that stopped parsing structured data at all (return the raw tail
# unchanged, say) would pass every timing check above. These assert the
# actual parsed shape survives, both below and around the cap.

entry = syslogparse.parse(sd_message(10), "10.0.0.1")
check("10 SD-ELEMENTs (well under the cap) are still fully stripped",
      entry.message == "tail", repr(entry.message))

cap = syslogparse.MAX_SD_ELEMENTS
at_cap = syslogparse.parse(sd_message(cap), "10.0.0.1")
check(f"exactly MAX_SD_ELEMENTS ({cap}) elements are all stripped",
      at_cap.message == "tail", repr(at_cap.message))

over_cap_msg = (b"<134>1 2024-01-01T00:00:00Z host app 1 msgid "
                + b"".join(f"[e{i}]".encode() for i in range(cap + 5)) + b" tail")
over_cap = syslogparse.parse(over_cap_msg, "10.0.0.1")
check("past the cap, the surplus elements are kept verbatim as message text, not dropped",
      over_cap.message == "[e64][e65][e66][e67][e68] tail", repr(over_cap.message))

# The exact multi-element and escaped-bracket shapes test_collectors_hardening.py
# already covers for correctness (rsyslog's two-element relay chain, a `\]`
# escaped inside a quoted value) are not repeated here; this suite only adds
# the size dimension that campaign's fuzzing covered and that one didn't.


# ================================================================ mibparse.py
#
# netpath/mibparse.py:120, _strip_comments_and_strings. Its own docstring
# already names two earlier quadratic-regex bugs fixed in this file; this is
# a third, same shape, different mechanism: `text.find("\n", ...)` inside the
# ASN.1 `--`-comment branch scanned to end-of-file every time no newline was
# ahead, so a file consisting of long runs of `--` with no intervening
# newline (one long logical line — a real shape for a minified or
# half-downloaded MIB) cost O(markers x length). Measured before the fix:
# 600,000 units (~1.8 MB, "-- " repeated) took 5.25 s — already past this
# file's own PARSE_BUDGET_S (5.0) — and 700,000 units (~2.1 MB) took 7.2 s.
# Worse, parse()'s budget was (and, for every phase but this one, still is)
# checked only *between* phases: masked = _strip_comments_and_strings(text)
# ran to completion before check_budget() ever got a look, so the budget
# could not stop this even though it fires while the file is still well
# under the 8 MB default upload cap.

print("D2  mibparse: comment/string masking no longer costs O(markers x length)")

# 2,000,000 units (~6 MB) is comfortably inside the shipped 8 MB cap and would
# have been minutes of held GIL before the fix (the curve is quadratic: 700K
# units already took 7.2s, and 2M is ~8x more content). 3s is ~2-3x the ~1.2s
# the fixed code actually measures here, and nowhere near what the unfixed
# curve predicts for this size.
no_newlines = "-- " * 2_000_000
result, elapsed = timed(mibparse.parse, no_newlines,
                        max_bytes=64 * 1024 * 1024, budget_s=999999)
check("2,000,000 '-- ' units with no newline anywhere parse in under 3 s",
      elapsed < 3.0, f"{elapsed:.3f}s, {len(no_newlines):,} chars")

# Control: the identical content, but with a newline after every unit (so the
# comment closes on the newline instead of forcing an end-of-file scan for
# one that isn't there) must stay just as fast — proving the fix targets the
# no-newline case specifically rather than slowing down the common one.
with_newlines = "-- \n" * 2_000_000
_, elapsed_ctrl = timed(mibparse.parse, with_newlines,
                        max_bytes=64 * 1024 * 1024, budget_s=999999)
check("the same content WITH newlines is unaffected (already-linear case stays linear)",
      elapsed_ctrl < 3.0, f"{elapsed_ctrl:.3f}s")

# ---------------------------------------- D2 correctness, not just speed
#
# A "fix" that made masking fast by returning the input unmasked (skipping
# the comment/string blanking step entirely) would pass the timing checks
# above but break every regex that depends on `--`/`::=` inside a comment or
# string being inert. Confirm masking still does its job on ordinary input.
tricky = mibparse.parse(
    'F DEFINITIONS ::= BEGIN\n'
    '-- a comment with a fake ::= { mib-2 999 } in it\n'
    'a OBJECT-TYPE\n  SYNTAX Integer32\n'
    '  DESCRIPTION "text with -- two dashes and a literal ::= { x 1 } in it"\n'
    '  ::= { mib-2 7 }\nEND', max_bytes=1024 * 1024)
found = {o.name: o for o in tricky.objects}
check("masking still makes a fake '::= { }' inside a comment or string inert",
      list(found) == ["a"] and found["a"].last_arc == "7", str(list(found)))
check("...while DESCRIPTION text itself still comes back unmasked",
      "-- two dashes" in found["a"].description
      and "::= { x 1 }" in found["a"].description, found["a"].description)

# ---------------------------------------- the budget now applies from inside
#
# Before the fix, parse()'s wall-clock budget (PARSE_BUDGET_S) was checked
# only after _strip_comments_and_strings() returned — so a masking phase slow
# enough to blow the budget on its own always finished first regardless, and
# for the pathological no-newline shape above, "finished first" meant paying
# the full quadratic cost every time. The masking loop now takes its own
# `deadline` and checks it periodically (every 4096 iterations) from inside,
# so a slow pass is now cut off early rather than needing to run to
# completion before the budget is ever consulted.
#
# To prove "cut off early" rather than "happens to finish fast enough not to
# matter", this uses an input large enough that a full (now-linear) masking
# pass measurably takes a comfortable fraction of a second — verified
# separately at ~0.86s for this exact size on this hardware — paired with a
# real but artificially tiny budget (0.05s). If the internal check did not
# exist (reverting just that part of the fix, keeping the O(n) algorithm),
# this would take the full ~0.86s before the *outer* check_budget() caught
# it; the assertion below is far tighter than that, so it specifically
# fails without the in-loop check.
slow_but_linear = "-- " * 3_000_000     # ~9 MB, comfortably under the 64 MB cap given below
started = time.perf_counter()
try:
    mibparse.parse(slow_but_linear, max_bytes=64 * 1024 * 1024, budget_s=0.05)
    check("a tiny budget on a large no-newline file raises MibParseTimeout", False,
          "parse() returned normally")
except mibparse.MibParseTimeout:
    elapsed_budget = time.perf_counter() - started
    check("a tiny budget on a large no-newline file raises MibParseTimeout", True)
    check("...and does so well before a full masking pass would complete "
          "(proves the check fires from inside the loop, not only after it)",
          elapsed_budget < 0.5, f"{elapsed_budget:.3f}s")


if FAILURES:
    print(f"\nFAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    raise SystemExit(1)
print("\nall syslog/mib DoS regression checks passed")
