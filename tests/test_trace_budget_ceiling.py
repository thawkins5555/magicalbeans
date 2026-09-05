"""tracer.expected_budget()'s ceiling — the second instance, in one night's
own campaign, of the shape a downstream review's `poll_interval_s x
down_after_failures` finding already named: three fields (max_hops, probes,
timeout_s), each individually bounded and each individually justified
against its own mechanism (db.py's MAX_MAX_HOPS/MAX_PROBES/MAX_TIMEOUT_S),
multiply together in this one formula with nothing ever checking the
PRODUCT. On Windows (parallel=1, since tracer.PROBE_PARALLELISM's 16-way
value is Linux-only) the three individually-sane maxima computed a
153,015-second (42.5 hour) worst case for a single trace — occupying one of,
at most, trace_workers (bounded to 64) worker slots for a day and a half,
from nothing more hostile than a fat-fingered "make it thorough" target
configuration.

Fixed by MAX_EXPECTED_BUDGET_S, a ceiling on the computed value rather than
a further tightening of any one input — see tracer.py's own comment above
expected_budget() for why capping the product, not the factors, is what
survives a fourth field joining this formula the way these three did without
anyone computing what they multiply to.
"""
import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import tracer

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{(': ' + str(detail)) if detail else ''}")
    if not ok:
        FAILURES.append(label)


print("B1  the worst individually-legal combination is bounded — and this is "
     "the check that fails if the ceiling is removed")

# db.py's own MAX_MAX_HOPS / MAX_PROBES / MAX_TIMEOUT_S, all at once -- every
# one of these three values, alone, is accepted by the API route's own
# validation (scenario-metrics' test_target_validation.py covers that side);
# this is what happens when a caller sets all three on the same target.
MAX_HOPS, MAX_PROBES, MAX_TIMEOUT_S = 255, 20, 30.0

windows_worst = tracer.expected_budget(MAX_HOPS, MAX_PROBES, MAX_TIMEOUT_S, parallel=1)
linux_worst = tracer.expected_budget(MAX_HOPS, MAX_PROBES, MAX_TIMEOUT_S, parallel=16)

# The pre-fix numbers, so a reader (or a future test failure) sees exactly
# what this used to compute to, not just what it computes to now. Deleting
# either MAX_EXPECTED_BUDGET_S or the min() around it in tracer.py makes
# windows_worst come back as uncapped_windows (153,015.0) instead — a
# concrete, non-vacuous way this test fails without the fix, not merely a
# re-confirmation of today's passing behaviour.
uncapped_windows = MAX_HOPS * MAX_PROBES * MAX_TIMEOUT_S + 15   # 153,015s
uncapped_linux = -(-MAX_HOPS // 16) * MAX_PROBES * MAX_TIMEOUT_S + 15  # ceil(255/16)=16 -> 9,615s

check(f"Windows (serial): {windows_worst:.0f}s, not the uncapped {uncapped_windows:,.0f}s "
      f"(42.5 hours)", windows_worst == tracer.MAX_EXPECTED_BUDGET_S, windows_worst)
check(f"Linux (16-way parallel): {linux_worst:.0f}s, not the uncapped {uncapped_linux:,.0f}s",
      linux_worst == tracer.MAX_EXPECTED_BUDGET_S, linux_worst)

print("B2  an ordinary configuration is unchanged")

# The default target (30 hops, 3 probes, 2s timeout) must compute exactly
# what the pre-ceiling formula always gave it -- the cap must never bind
# anything a real, live network trace actually needs.
default_windows = tracer.expected_budget(30, 3, 2.0, parallel=1)
default_linux = tracer.expected_budget(30, 3, 2.0, parallel=16)
check("Windows default (30, 3, 2.0) is the uncapped 195s, not clipped",
      default_windows == 30 * 3 * 2.0 + 15 == 195.0, default_windows)
check("Linux default (30, 3, 2.0) is the uncapped 27s, not clipped",
      default_linux == 2 * 3 * 2.0 + 15 == 27.0, default_linux)
check("both defaults sit comfortably under the ceiling",
      default_windows < tracer.MAX_EXPECTED_BUDGET_S / 2
      and default_linux < tracer.MAX_EXPECTED_BUDGET_S / 2,
      (default_windows, default_linux))

if FAILURES:
    print(f"\nFAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    raise SystemExit(1)
print("\nall trace-budget ceiling checks passed")
