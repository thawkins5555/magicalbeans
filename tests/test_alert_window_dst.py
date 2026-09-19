"""A weekly maintenance window must land on the same LOCAL wall-clock time
every week, even across a daylight-saving change -- not drift an hour the
way a raw `(now - start_ts) % 604800` on epoch seconds does.

time.localtime is monkeypatched with a synthetic, fixed-offset DST rule
(independent of the host's real timezone) so this passes on any machine:
before `transition_ts` the fake local zone is `before_offset_s` from UTC,
at and after it, `after_offset_s`. House style: a plain script, FAILS
collects failed check() names, exit 1 if anything failed.
"""
import calendar
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import alertsdb
from netpath.alertsdb import is_window_active, _window_occurrence_end

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def fake_localtime_factory(transition_ts, before_offset_s, after_offset_s):
    def fake_localtime(ts=None):
        ts = time.time() if ts is None else ts
        offset = after_offset_s if ts >= transition_ts else before_offset_s
        return time.gmtime(ts + offset)
    return fake_localtime


def old_raw_elapsed(row, now):
    """The pre-fix formula (raw epoch modulo), to prove the new one
    disagrees with it exactly where the bug bit."""
    return (now - row["start_ts"]) % (7 * 86400.0)


WEEK_S = 7 * 86400.0
X0 = calendar.timegm((2027, 3, 7, 2, 0, 0, 0, 0, 0))  # a "wall clock" reference


def run_case(label, before_offset_s, after_offset_s):
    """One weekly 02:00-04:00 window, first occurrence before the DST
    change, second occurrence one calendar week later (local), after it."""
    duration = 2 * 3600
    start_ts = X0 - before_offset_s          # local wall 02:00, pre-change
    transition_ts = start_ts + 3 * 86400     # mid-week between the two Sundays
    localtime = fake_localtime_factory(transition_ts, before_offset_s, after_offset_s)
    second_wall = X0 + WEEK_S                # same local wall time, one week on
    second_start = second_wall - after_offset_s

    real_localtime = alertsdb.time.localtime
    alertsdb.time.localtime = localtime
    try:
        row = {"start_ts": start_ts, "end_ts": start_ts + duration,
              "recurrence": "weekly"}

        check(f"{label}: first occurrence is active at its own local 02:30",
              is_window_active(row, start_ts + 1800))
        check(f"{label}: second occurrence is active at local 02:30 the week after, "
              "across the clock change",
              is_window_active(row, second_start + 1800),
              (second_start + 1800, transition_ts))
        check(f"{label}: ...inactive an hour before local 02:00 that week",
              not is_window_active(row, second_start - 1800))
        check(f"{label}: ...inactive an hour after local 04:00 that week",
              not is_window_active(row, second_start + duration + 1800))
        check(f"{label}: _window_occurrence_end matches the local 04:00 boundary",
              abs(_window_occurrence_end(row, second_start + 1800)
                  - (second_start + duration)) < 1.0)

        drift = (second_start + 1800) - (start_ts + 1800 + WEEK_S)
        if before_offset_s > after_offset_s:
            # Fall back: the raw formula runs the window an hour EARLY.
            probe = second_start - 1800
        elif before_offset_s < after_offset_s:
            # Spring forward: the raw formula runs the window an hour LATE.
            probe = second_start + duration + 1800
        else:
            probe = None
        if probe is not None:
            check(f"{label}: the raw pre-fix epoch formula disagrees with the "
                  "fix at the moment the drift would show (proving this case "
                  "exercises the bug)",
                  old_raw_elapsed(row, probe) < duration, (probe, drift))
        else:
            check(f"{label}: no actual clock change -- raw epoch and local "
                  "wall-clock formulas agree",
                  drift == 0, drift)
    finally:
        alertsdb.time.localtime = real_localtime


# US-style spring-forward: standard (UTC-5) to daylight (UTC-4), local wall
# clock jumps forward, so the raw-epoch gap between the two Sundays is an
# hour SHORT of a real week.
run_case("spring forward", -5 * 3600, -4 * 3600)

# Autumn: daylight (UTC-4) to standard (UTC-5), clocks fall back, so the
# raw-epoch gap is an hour LONG -- this is the review's own reproduction
# ("...runs 01:00-03:00 after the clocks change").
run_case("autumn back", -4 * 3600, -5 * 3600)

# No transition at all: behaviour must be exactly as it always was.
run_case("no DST change", -5 * 3600, -5 * 3600)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
