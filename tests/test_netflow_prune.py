"""Flow retention: the right rows go, the write lock is never held long, and
the rollups outlive the raw flows they were built from.

NetFlow is UDP, so a writer stalled behind a month-wide DELETE is lost data
with nothing to retransmit it. Every stage here is therefore checked for what
it removed AND for how long any one batch held the lock.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import os
import shutil
import sys
import time
import types

from _paths import tmpdir

from netpath import flowdb
from netpath.flowdb import FlowDatabase
from netpath.sqlitebase import TRIM_LOCK_TARGET_S

TMPDIR = tmpdir("netflow_prune_")
FAILS: list[str] = []

NO_FILTERS: dict = {}


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


def store(name: str) -> FlowDatabase:
    return FlowDatabase(os.path.join(TMPDIR, name))


def flow(index: int, ts: float):
    return types.SimpleNamespace(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 7}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443)[index % 2],
        protocol=6, tos=0, tcp_flags=0, in_if=1, out_if=2,
        src_as=64500, dst_as=64600, next_hop=None,
        packets=1 + index % 9, bytes=100 + index, sampling=1,
        domain=0, sampler_id=0)


def counts(db: FlowDatabase) -> tuple[int, int, int]:
    with db._lock:
        return tuple(db._conn.execute(
            "SELECT (SELECT COUNT(*) FROM flows),"
            " (SELECT COUNT(*) FROM flow_rollup),"
            " (SELECT COUNT(*) FROM flow_rollup_span)").fetchone())


def timed_batches(db: FlowDatabase) -> list[float]:
    """Wrap _delete_batches' inner delete so every batch is timed."""
    held: list[float] = []
    original = FlowDatabase._delete_batches

    def wrapper(self, low, cut, deadline, delete=None, **kwargs):
        inner = delete or self._trim_delete

        def timing(lo, up):
            started = time.monotonic()
            removed = inner(lo, up)
            held.append(time.monotonic() - started)
            return removed

        return original(self, low, cut, deadline, timing, **kwargs)

    FlowDatabase._delete_batches = wrapper
    db._restore_delete_batches = lambda: setattr(
        FlowDatabase, "_delete_batches", original)
    return held


# ------------------------------------------------------------------------- 1

def test_1_age_and_row_cap() -> None:
    print("1: age and the row cap remove the right rows and no others")
    db = store("age.db")
    now = time.time()
    db.insert_flows([flow(i, now - 10 * 86400 + i * 60) for i in range(10 * 1440)])
    # An exporter whose clock is days out, sitting among the oldest ids.
    with db._lock:
        db._conn.execute(
            "UPDATE flows SET ts_start = ?, ts_end = ? WHERE id = 5", (now, now))
        db._conn.commit()

    removed = db.prune(1, 0, minute_days=90, rollup_days=90)
    left = counts(db)[0]
    stale = db._conn.execute(
        "SELECT COUNT(*) AS n FROM flows WHERE ts_end < ?",
        (now - 86400,)).fetchone()["n"]
    check(stale == 0 and 1400 < left < 1450,
          f"a one-day retention leaves the last day and nothing older "
          f"({left} rows, {removed} removed, {stale} past the cutoff)")
    check(db._conn.execute(
        "SELECT COUNT(*) AS n FROM flows WHERE id = 5").fetchone()["n"] == 1,
        "the clock-skewed row inside the deleted id range survives: the ids "
        "only chunk the sweep, each batch still filters on ts_end")
    check(not db.last_prune_incomplete, "and the sweep reports itself finished")

    db.prune(1, 500, minute_days=90, rollup_days=90)
    left = counts(db)[0]
    check(left <= 500,
          f"a row cap of 500 takes the store down to it ({left} rows)")
    check(db._conn.execute(
        "SELECT MIN(ts_end) AS lo FROM flows").fetchone()["lo"] > now - 86400,
        "and what it kept is the newest, not an arbitrary slice")
    db.close()


# ------------------------------------------------------------------------- 2

def test_2_rollups_outlive_the_raw_flows() -> None:
    print("2: a 30-day chart survives a one-day raw retention")
    db = store("outlive.db")
    now = time.time()
    # Aligned to the widest bucket the UI asks for, so the 30-day view's own
    # snapped-down t0 is still inside what the rollups cover.
    start = flowdb._align_down(now - 20 * 86400, 21600)
    db.insert_flows([flow(i, start + i * 600.0) for i in range(2800)])
    db.compact_rollup(3600, max_buckets=10_000, budget_s=120)
    while True:
        written, done = db.backfill_rollup(3600, max_buckets=10_000, budget_s=120)
        if done or not written:
            break
    before = db.overview(start, now, "Source", NO_FILTERS, 21600)[4]

    db.prune(1, 0, minute_days=0, rollup_days=90)
    raw_left, rollup_left, spans_left = counts(db)
    check(raw_left < 200 and rollup_left > 0 and spans_left > 0,
          f"raw retention emptied the flows, the hourly rollups stayed "
          f"({raw_left} flows, {spans_left} hourly buckets)")
    after = db.overview(start, now, "Source", NO_FILTERS, 21600)[4]
    check(after == before,
          f"and a 20-day chart still returns the same totals it did before "
          f"the raw rows were deleted ({after} vs {before})")
    check(db.oldest_ts() is not None and db.oldest_ts() < now - 19 * 86400,
          "the store still reports how far its history reaches, which is the "
          "rollups' reach, not the raw table's")
    db.close()


# ------------------------------------------------------------------------- 3

def test_3_a_budget_bounded_sweep_resumes() -> None:
    print("3: a sweep that runs out of budget says so and finishes next time")
    db = store("budget.db")
    now = time.time()
    db.insert_flows([flow(i, now - 10 * 86400 + i * 20) for i in range(40_000)])

    removed = db.prune(1, 0, minute_days=0, rollup_days=0, budget_s=0.0)
    check(db.last_prune_incomplete,
          f"a zero-second budget leaves the sweep incomplete ({removed} rows "
          f"removed)")
    still = db._conn.execute(
        "SELECT COUNT(*) AS n FROM flows WHERE ts_end < ?",
        (now - 86400,)).fetchone()["n"]
    check(still > 0, f"...with {still} rows past the cutoff still stored")

    db.prune(1, 0, minute_days=0, rollup_days=0, budget_s=60.0)
    check(not db.last_prune_incomplete, "the next call finishes the sweep")
    still = db._conn.execute(
        "SELECT COUNT(*) AS n FROM flows WHERE ts_end < ?",
        (now - 86400,)).fetchone()["n"]
    check(still == 0, "and nothing past the cutoff is left")
    db.close()


# ------------------------------------------------------------------------- 4

def test_4_no_batch_holds_the_lock() -> None:
    print("4: no single delete batch holds the write lock for long")
    db = store("lock.db")
    now = time.time()
    db.insert_flows([flow(i, now - 10 * 86400 + i * 14.0) for i in range(60_000)])
    db.compact_rollup(3600, max_buckets=10_000, budget_s=120)
    while True:
        written, done = db.backfill_rollup(3600, max_buckets=10_000, budget_s=120)
        if done or not written:
            break

    held = timed_batches(db)
    try:
        db.prune(1, 0, minute_days=0, rollup_days=0, budget_s=120.0)
    finally:
        db._restore_delete_batches()
    worst = max(held) if held else 0.0
    check(len(held) > 1,
          f"the sweep really was batched ({len(held)} batches)")
    # Generous: the adaptive sizing aims at TRIM_LOCK_TARGET_S and only
    # measures a batch after running it, so the first one of each stage can
    # overshoot before it halves.
    check(worst < TRIM_LOCK_TARGET_S * 20,
          f"the worst batch held the lock {worst * 1000:.0f} ms, well inside "
          f"a generous multiple of the {TRIM_LOCK_TARGET_S * 1000:.0f} ms "
          f"target")
    raw_left, rollup_left, spans_left = counts(db)
    stale = db._conn.execute(
        "SELECT COUNT(*) AS n FROM flows WHERE ts_end < ?",
        (now - 86400,)).fetchone()["n"]
    check(stale == 0 and raw_left and not rollup_left and not spans_left,
          f"and the sweep removed every row past its cutoff and, with the "
          f"rollup retentions at zero, both summary tables ({raw_left} flows, "
          f"{spans_left} buckets)")
    db.close()


# ------------------------------------------------------------------------- 5

def test_5_delete_everything_clears_the_charts() -> None:
    print("5: 'delete all flow records' takes the summaries with it")
    db = store("wipe.db")
    now = time.time()
    start = flowdb._align_down(now - 4 * 3600, 3600)
    db.insert_flows([flow(i, start + i * 5.0) for i in range(2000)])
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        while True:
            written, done = db.backfill_rollup(tier, max_buckets=10_000,
                                               budget_s=120)
            if done or not written:
                break
    check(all(counts(db)), f"the three tables all hold rows first {counts(db)}")

    removed = db.prune(0, 0, minute_days=0, rollup_days=0)
    check(counts(db) == (0, 0, 0),
          f"prune(0, 0, minute_days=0, rollup_days=0) empties all three "
          f"({removed} rows)")
    check(db.overview(start, now, "Source", NO_FILTERS, 3600)[4]
          == {"bytes": 0, "packets": 0, "flows": 0},
          "so the chart the button was pressed to clear is actually empty")
    db.close()


# ------------------------------------------------------------------------- 6

def test_6_the_size_cap_takes_raw_first() -> None:
    print("6: the file size cap empties the raw table before the summaries")
    db = store("trim.db")
    now = time.time()
    start = flowdb._align_down(now - 6 * 3600, 3600)
    db.insert_flows([flow(i, start + i * 0.5) for i in range(40_000)])
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        while True:
            written, done = db.backfill_rollup(tier, max_buckets=10_000,
                                               budget_s=120)
            if done or not written:
                break
    before = db.size_bytes()
    raw_before, _rollup_before, spans_before = counts(db)

    # A cap the raw table alone cannot meet: without the second stage the
    # base implementation would stop at TRIM_FLOOR and warn about the cap
    # for ever while the rollups held the space.
    db.trim_to_size(int(before * 0.1), budget_s=60.0)
    raw_after, _rollup_after, spans_after = counts(db)
    check(raw_after < raw_before and raw_after <= db.TRIM_FLOOR,
          f"stage one took the raw flows down to their floor "
          f"({raw_before} -> {raw_after})")
    check(spans_after < spans_before,
          f"stage two then gave up the oldest rollup buckets "
          f"({spans_before} -> {spans_after})")
    check(db.size_bytes() < before,
          f"and the file shrank ({before // 1024} KiB -> "
          f"{db.size_bytes() // 1024} KiB)")
    # The minute tier gives first: it is the one holding the space, and the
    # hourly tier is what a wide chart has left to read.
    floor, _watermark = db.rollup_bounds(60)
    check(floor is not None and floor > start,
          "the minute floor moved up with the buckets that went, so routing "
          "stops claiming history the trim deleted")
    db.close()


# ------------------------------------------------------------------------- 7

def vm_steps(db: FlowDatabase, call) -> tuple[object, int]:
    """SQLite VM steps one call costs. What changed here is the plan, and a
    stopwatch is a flaky way of asserting one."""
    counted = [0]

    def tick():
        counted[0] += 1
        return 0

    db._conn.set_progress_handler(tick, 1000)
    try:
        return call(), counted[0]
    finally:
        db._conn.set_progress_handler(None, 0)


def aged_store(name: str, now: float, skewed: bool) -> FlowDatabase:
    """31 days of flows -- so a 30-day retention ages out about a
    thirtieth of them -- optionally with one row arriving now from an
    exporter whose clock is 400 days out."""
    db = store(name)
    db.insert_flows([flow(i, now - 31 * 86400 + i * (31 * 86400 / 40_000))
                     for i in range(40_000)])
    if skewed:
        db.insert_flows([flow(1, now - 400 * 86400)])
    return db


def test_7_a_wrong_clock_does_not_widen_the_sweep() -> None:
    print("7: one exporter's ancient clock does not make the sweep walk the "
          "whole table")
    now = time.time()
    reclaim_budget = flowdb.PRUNE_RECLAIM_BUDGET_S
    # The reclaim pass is time-budgeted and would swamp the measurement.
    flowdb.PRUNE_RECLAIM_BUDGET_S = 0.0
    try:
        plain = aged_store("skew_none.db", now, skewed=False)
        _r, plain_steps = vm_steps(
            plain, lambda: plain.prune(30, 0, minute_days=90, rollup_days=90,
                                       budget_s=60.0))
        skewed = aged_store("skew_one.db", now, skewed=True)
        removed, skewed_steps = vm_steps(
            skewed, lambda: skewed.prune(30, 0, minute_days=90, rollup_days=90,
                                         budget_s=60.0))
    finally:
        flowdb.PRUNE_RECLAIM_BUDGET_S = reclaim_budget

    left = skewed._conn.execute(
        "SELECT COUNT(*) AS n FROM flows WHERE ts_end < ?",
        (now - 30 * 86400,)).fetchone()["n"]
    check(left == 0 and removed > 1000,
          f"the skewed row and every other aged row are gone ({removed} "
          f"removed, {left} past the cutoff)")
    check(not skewed.last_prune_incomplete,
          "and the sweep finished rather than warning that it ran out of "
          "budget")
    check(skewed_steps <= plain_steps * 2,
          f"the sweep costs what it deletes, not the size of the id span the "
          f"one bad row spreads it across ({skewed_steps * 1000} VM steps "
          f"against {plain_steps * 1000} without it)")
    plain.close()
    skewed.close()


TESTS = [
    test_1_age_and_row_cap,
    test_2_rollups_outlive_the_raw_flows,
    test_3_a_budget_bounded_sweep_resumes,
    test_4_no_batch_holds_the_lock,
    test_5_delete_everything_clears_the_charts,
    test_6_the_size_cap_takes_raw_first,
    test_7_a_wrong_clock_does_not_widen_the_sweep,
]


def main() -> int:
    try:
        for test in TESTS:
            test()
            print()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"{len(FAILS)} CHECK(S) FAILED:")
        for item in FAILS:
            print(f"  - {item}")
        return 1
    print("ALL NETFLOW PRUNE ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
