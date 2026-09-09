"""The NetFlow rollups answer the same question the raw flows do.

Every assertion here is a comparison rather than a golden number: the
invariant that matters is that a rollup-served window and a raw-served one
agree, so each check asks flowdb the same question twice — once normally and
once with _rollup_plan forced to None — and compares the two answers element
for element.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import os
import shutil
import sys
import time
import types

from _paths import tmpdir

from netpath import flowdb
from netpath.collector import Collector, RESAMPLE_MAX_AGE_S
from netpath.flowdb import DIMENSIONS, ROLLUP_KEYS, FlowDatabase

TMPDIR = tmpdir("netflow_rollup_")
FAILS: list[str] = []

# The six the UI actually asks for: api._flow_bucket's ladder against app.js's
# range list yields exactly these.
BUCKETS = (10, 60, 300, 900, 3600, 21600)
NO_FILTERS = {"src_ip": "", "dst_ip": "", "port": None, "protocol": None,
              "exporter": None}


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


def store(name: str) -> FlowDatabase:
    return FlowDatabase(os.path.join(TMPDIR, name))


def flow(index: int, ts: float, **overrides):
    """One decoded flow, every dimension varying at a different period so no
    two of them are the same grouping in disguise."""
    fields = dict(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 7}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443, 53, 22)[index % 4],
        protocol=(6, 17, 1)[index % 3], tos=index % 4, tcp_flags=0,
        in_if=index % 6, out_if=index % 8,
        src_as=64500 + index % 3, dst_as=64600 + index % 2, next_hop=None,
        packets=1 + index % 9, bytes=100 + index * 7,
        sampling=(1, 2, 10)[index % 3], domain=0, sampler_id=0)
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


def cover(db: FlowDatabase, *, minutes: bool = True, hours: bool = True) -> None:
    """Bring both tiers up to date the way the service does: compact seeds the
    watermark at now and moves it forward, backfill walks the floor back over
    the history already stored."""
    for tier, wanted in ((60, minutes), (3600, hours)):
        if not wanted:
            continue
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        while True:
            written, done = db.backfill_rollup(tier, max_buckets=10_000,
                                               budget_s=120)
            if done or not written:
                break


def raw(db: FlowDatabase, method: str, *args, **kwargs):
    """The same call with the rollups taken out of the picture."""
    real = FlowDatabase._rollup_plan
    FlowDatabase._rollup_plan = lambda *a, **k: None
    try:
        return getattr(db, method)(*args, **kwargs)
    finally:
        FlowDatabase._rollup_plan = real


# ------------------------------------------------------------------------- 1

def test_1_rollup_and_raw_agree() -> None:
    """Every dimension, every bucket size the UI can ask for."""
    print("1: a rollup-served window equals the same window read from raw")
    db = store("equivalence.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3 * 3600
    db.insert_flows([flow(i, start + i * (3 * 3600) / 1500.0)
                     for i in range(1500)])
    cover(db)

    served = {}
    mismatched = []
    for dimension in DIMENSIONS:
        for bucket in BUCKETS:
            args = (start, end, dimension, NO_FILTERS, bucket)
            plan = db._rollup_plan(start, end, dimension, NO_FILTERS, bucket)
            served[bucket] = None if plan is None else plan[0]
            if db.overview(*args) != raw(db, "overview", *args):
                mismatched.append(f"{dimension} at {bucket}s")
    check(not mismatched,
          f"all {len(DIMENSIONS)} dimensions x {len(BUCKETS)} bucket sizes "
          f"agree exactly — times, totals, top rows and every series value "
          f"({', '.join(mismatched[:3])})")
    check(served == {10: None, 60: 60, 300: 60, 900: 60, 3600: 3600,
                     21600: 3600},
          f"...and each bucket size was routed to the tier meant to serve it "
          f"({served})")
    check(db.totals(start, end, NO_FILTERS) == raw(db, "totals", start, end,
                                                   NO_FILTERS),
          "totals() agrees too")
    check(db.top(start, end, "Conversation", NO_FILTERS, 10)
          == raw(db, "top", start, end, "Conversation", NO_FILTERS, 10),
          "and so does top()")
    db.close()


# ------------------------------------------------------------------------- 2

def test_2_totals_survive_truncation() -> None:
    """More distinct keys in one bucket than the cap can hold."""
    print("2: the totals stay exact where the top-K cap threw keys away")
    db = store("truncation.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3600
    cap = ROLLUP_KEYS[60]
    # One minute, three times as many conversations as the cap keeps.
    rows = [flow(i, start + 30, src_ip=f"10.1.{i // 256}.{i % 256}",
                 dst_ip="10.9.9.9", bytes=1000 + i, sampling=1)
            for i in range(cap * 3)]
    db.insert_flows(rows)
    cover(db)

    stored = db._conn.execute(
        "SELECT COUNT(*) AS n FROM flow_rollup WHERE tier = 60 AND dim = ?"
        " AND bucket = ?",
        (flowdb.DIMENSION_IDS["Conversation"],
         flowdb._align_down(start + 30, 60))).fetchone()["n"]
    check(stored == cap,
          f"the bucket kept exactly ROLLUP_KEYS[60] conversations of the "
          f"{cap * 3} it saw ({stored})")

    times, series, _b, top_rows, totals = db.overview(
        start, end, "Conversation", NO_FILTERS, 60, series_limit=8, top_limit=10)
    reference = raw(db, "totals", start, end, NO_FILTERS)
    check(totals == reference,
          f"the totals still match raw exactly ({totals} vs {reference})")
    check(all(row["key"] in {r.src_ip + " → " + r.dst_ip for r in rows[-cap:]}
              for row in top_rows),
          "the named rows are the heaviest conversations, which are the ones "
          "the cap kept")
    other = series.get("— other —")
    named = sum(sum(values) for key, values in series.items()
                if key != "— other —")
    check(other is not None and named + sum(other) == totals["bytes"],
          "and what the named series leave over is in '— other —', to the byte")
    db.close()


# ------------------------------------------------------------------------- 3

def test_3_the_seal_boundary_counts_once() -> None:
    """The regression test for the stitch between the two arms."""
    print("3: a flow at the seal is counted once, not twice and not never")
    db = store("seal.db")
    now = time.time()
    start = flowdb._align_down(now - 3600, 60)
    db.insert_flows([flow(i, start + i * 30.0) for i in range(60)])
    cover(db, hours=False)

    plan = db._rollup_plan(start, now, "Source", NO_FILTERS, 60)
    check(plan is not None, "the window is rollup-served to begin with")
    seal = plan[2]
    db.insert_flows([flow(900, float(seal), bytes=777_000, sampling=1),
                     flow(901, seal - 1.0, bytes=555_000, sampling=1)])
    cover(db, hours=False)

    got = db.overview(start, now, "Source", NO_FILTERS, 60)
    want = raw(db, "overview", start, now, "Source", NO_FILTERS, 60)
    check(got[4] == want[4],
          f"the totals over a window straddling the seal match raw "
          f"({got[4]} vs {want[4]})")
    check(got == want, "and so does every other part of the answer")
    db.close()


# ------------------------------------------------------------------------- 4

def test_4_sampling_in_both_orders() -> None:
    """A rate can be announced before or after the bucket is summarised."""
    print("4: a sampling rate announced late still reaches the rollups")
    db = store("sampling.db")
    now = time.time()
    start = flowdb._align_down(now - 1800, 60)
    db.insert_flows([flow(i, start + i * 20.0, sampling=1) for i in range(80)])

    # (a) corrected before the bucket was ever summarised.
    db.record_sampling_rates([("10.0.0.0", 0, 0, 50)], since_ts=0.0)
    cover(db, hours=False)
    db.compact_rollup(60, max_buckets=10_000, budget_s=120)
    check(db.overview(start, now, "Exporter", NO_FILTERS, 60)
          == raw(db, "overview", start, now, "Exporter", NO_FILTERS, 60),
          "a rate applied before compaction is in the rollup")
    check(db._private_setting(flowdb._DIRTY % 60) is None,
          "and a pass that has followed a rewrite clears its marker")

    # (b) announced after the buckets were built.
    db.record_sampling_rates([("10.0.0.1", 0, 0, 40)], since_ts=0.0)
    check(db._private_setting(flowdb._DIRTY % 60) == 0.0
          and db._private_setting(flowdb._DIRTY % 3600) == 0.0,
          "a rewrite that corrected rows marks every tier from how far "
          "back it reached")
    check(db.overview(start, now, "Exporter", NO_FILTERS, 60)
          != raw(db, "overview", start, now, "Exporter", NO_FILTERS, 60),
          "...and until the next pass the rollup does disagree, so the check "
          "below is not passing by accident")
    db.compact_rollup(60, max_buckets=10_000, budget_s=120)
    check(db.overview(start, now, "Exporter", NO_FILTERS, 60)
          == raw(db, "overview", start, now, "Exporter", NO_FILTERS, 60),
          "one compaction later the rollup follows the rewrite back and "
          "agrees again")
    check(db._private_setting(flowdb._DIRTY % 60) is None
          and db._private_setting(flowdb._DIRTY % 3600) == 0.0,
          "the minute tier clears its own marker once it has followed "
          "it, and leaves the hourly tier's alone")

    # (c) the rewrite itself is bounded, which is what makes (b) sound.
    db.insert_flows([flow(0, now - 3 * RESAMPLE_MAX_AGE_S, exporter="10.0.0.9",
                          sampling=1),
                     flow(1, now - 60, exporter="10.0.0.9", sampling=1)])
    collector = Collector(db)
    collector.started_at = 0.0
    collector.decoder.learned_rates = [("10.0.0.9", 0, 0, 33)]
    collector._apply_learned_rates()
    rates = db._conn.execute(
        "SELECT ts_end, sampling FROM flows WHERE exporter = '10.0.0.9'"
        " ORDER BY ts_end").fetchall()
    check([row["sampling"] for row in rates] == [1, 33],
          f"the collector's rewrite stops at RESAMPLE_MAX_AGE_S and leaves "
          f"older rows alone ({[row['sampling'] for row in rates]})")
    db.close()


# ------------------------------------------------------------------------- 5

def test_5_filters_never_touch_a_rollup() -> None:
    """Proven with a rollup deliberately holding the wrong numbers."""
    print("5: a filtered query is answered from raw, whatever the rollup says")
    db = store("filters.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3600
    db.insert_flows([flow(i, start + i * 3.0) for i in range(600)])
    cover(db)
    with db._lock:
        db._conn.execute("UPDATE flow_rollup_span SET bytes = bytes + 1000000")
        db._conn.commit()

    poisoned = db.totals(start, end, NO_FILTERS)
    honest = raw(db, "totals", start, end, NO_FILTERS)
    check(poisoned["bytes"] > honest["bytes"],
          "the unfiltered answer does come from the (poisoned) rollup, so the "
          "checks below are actually exercising the routing rule")
    for name, filters in (
            ("source address", {**NO_FILTERS, "src_ip": "192.168.0.1"}),
            ("port", {**NO_FILTERS, "port": "443"}),
            ("protocol", {**NO_FILTERS, "protocol": 6}),
            ("exporter", {**NO_FILTERS, "exporter": "10.0.0.1"})):
        got = db.overview(start, end, "Source", filters, 300)
        want = raw(db, "overview", start, end, "Source", filters, 300)
        check(got == want and got[4]["bytes"] < poisoned["bytes"],
              f"a query filtered by {name} returns the exact raw answer")
    db.close()


# ------------------------------------------------------------------------- 6

def test_6_off_grid_buckets_stay_on_raw() -> None:
    print("6: a bucket the tiers do not divide is answered from raw")
    db = store("offgrid.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 1800
    db.insert_flows([flow(i, start + i * 2.0) for i in range(600)])
    cover(db)
    with db._lock:
        db._conn.execute("UPDATE flow_rollup_span SET bytes = bytes + 1000000")
        db._conn.commit()
    for bucket in (10, 18):
        check(db._rollup_plan(start, end, "Source", NO_FILTERS, bucket) is None,
              f"a {bucket}-second bucket has no tier that divides it")
        got = db.overview(start, end, "Source", NO_FILTERS, bucket)
        check(got == raw(db, "overview", start, end, "Source", NO_FILTERS, bucket),
              f"...and the {bucket}-second answer is the raw one, to the byte")
    db.close()


# ------------------------------------------------------------------------- 7

def test_7_compaction_is_idempotent() -> None:
    print("7: compacting twice leaves the tables byte for byte the same")
    db = store("idempotent.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3600
    db.insert_flows([flow(i, start + i * 3.0) for i in range(600)])
    cover(db)

    def contents():
        with db._lock:
            return (db._conn.execute(
                "SELECT tier, dim, bucket, key, bytes, packets, flows"
                " FROM flow_rollup ORDER BY tier, dim, bucket, key").fetchall(),
                db._conn.execute(
                "SELECT tier, bucket, bytes, packets, flows"
                " FROM flow_rollup_span ORDER BY tier, bucket").fetchall())

    before = [tuple(row) for table in contents() for row in table]
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        db.backfill_rollup(tier, max_buckets=10_000, budget_s=120)
    after = [tuple(row) for table in contents() for row in table]
    check(before and before == after,
          f"{len(before)} rollup rows are unchanged by a second pass")
    db.close()


# ------------------------------------------------------------------------- 8

def test_8_a_window_below_the_floor_falls_back() -> None:
    print("8: a window reaching past what the rollups cover reads raw")
    db = store("floor.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 4 * 3600
    db.insert_flows([flow(i, start + i * 8.0) for i in range(1500)])
    cover(db)
    # Only the hourly tier is poisoned, so which tier answered is visible in
    # the number that comes back.
    with db._lock:
        db._conn.execute("UPDATE flow_rollup_span SET bytes = bytes + 1000000"
                         " WHERE tier = 3600")
        db._conn.commit()
    honest = raw(db, "overview", start, end, "Source", NO_FILTERS, 3600)[4]
    plan = db._rollup_plan(start, end, "Source", NO_FILTERS, 3600)
    check(plan is not None and plan[0] == 3600
          and db.overview(start, end, "Source", NO_FILTERS, 3600)[4]["bytes"]
          > honest["bytes"],
          "with both floors below the window the hourly tier answers")

    db._set_private_setting(flowdb._FLOOR % 3600, int(start + 2 * 3600))
    plan = db._rollup_plan(start, end, "Source", NO_FILTERS, 3600)
    check(plan is not None and plan[0] == 60,
          "with the hourly floor moved inside the window it drops to the "
          "minute tier rather than answering short")
    got = db.overview(start, end, "Source", NO_FILTERS, 3600)
    check(got == raw(db, "overview", start, end, "Source", NO_FILTERS, 3600),
          "...and that answer is exact")

    db._set_private_setting(flowdb._FLOOR % 60, int(start + 2 * 3600))
    check(db._rollup_plan(start, end, "Source", NO_FILTERS, 3600) is None,
          "with neither floor reaching the start of the window, no tier "
          "claims it")
    got = db.overview(start, end, "Source", NO_FILTERS, 3600)
    check(got == raw(db, "overview", start, end, "Source", NO_FILTERS, 3600),
          "...and the whole window is read from raw")
    db.close()


# ------------------------------------------------------------------------- 9

def slow_buckets(seconds: float):
    """Make one bucket cost real time, the way 60k flows/minute across eleven
    dimensions does. A budget is wall clock, so nothing else reproduces a
    pass that runs out of it. Returns the undo."""
    real = FlowDatabase._compact_bucket

    def slower(self, tier, bucket):
        time.sleep(seconds)
        return real(self, tier, bucket)

    FlowDatabase._compact_bucket = slower
    return lambda: setattr(FlowDatabase, "_compact_bucket", real)


def test_9_the_watermark_advances_under_a_tight_budget() -> None:
    print("9: a pass with no budget for the redo window still builds forward")
    db = store("progress.db")
    now = time.time()
    start = flowdb._align_down(now - 3600, 60)
    db.insert_flows([flow(i, start + i * 2.0) for i in range(1800)])
    db.compact_rollup(60, max_buckets=10_000, budget_s=120)

    # A store whose collector has outrun compaction: sealed buckets nobody
    # has built yet, and a redo window far wider than one pass can afford.
    sealed = flowdb._align_down(time.time() - flowdb._ROLLUP_LAG_S, 60)
    db._set_private_setting(flowdb._FLOOR % 60, sealed - 40 * 60)
    db._set_private_setting(flowdb._WATERMARK % 60, sealed - 10 * 60)
    db._mark_dirty(float(sealed - 40 * 60), [60])

    undo = slow_buckets(0.02)
    try:
        marks = []
        for _ in range(8):
            db.compact_rollup(60, budget_s=0.05)
            marks.append(db.rollup_bounds(60)[1])
    finally:
        undo()
    check(marks[0] > sealed - 10 * 60,
          f"the very first pass moves the watermark forward "
          f"({marks[0] - (sealed - 10 * 60)} s of it)")
    check(marks == sorted(marks) and marks[-1] >= sealed,
          f"and eight of them reach the newest sealed bucket rather than "
          f"redoing the same window for ever ({marks[-1] - sealed} s past it)")
    check(db._private_setting(flowdb._DIRTY % 60) is not None,
          "what the budget never reached is still marked dirty, so the redo "
          "resumes there instead of being lost")
    db.close()


# ------------------------------------------------------------------------ 10

def test_10_a_late_exporter_still_reaches_the_rollups() -> None:
    print("10: a flow landing far behind the watermark is summarised too")
    db = store("late.db")
    now = time.time()
    start = flowdb._align_down(now - 7200, 3600)
    db.insert_flows([flow(i, start + i * 4.0) for i in range(1500)])
    cover(db)

    # Forty minutes behind the watermark: ts_end comes from the exporter's
    # clock (nfdecode accepts anything within 30 days of now), so a device
    # with an active timeout or a skewed clock lands here routinely. Such a
    # flow used to exist in raw alone -- on the 15-minute view, gone from
    # the 1-hour one.
    _floor, watermark = db.rollup_bounds(60)
    late = float(watermark - 40 * 60)
    db.insert_flows([flow(9000, late, src_ip="10.9.9.9", bytes=999_000,
                          sampling=1)])
    check(db.overview(start, now, "Source", NO_FILTERS, 60)
          != raw(db, "overview", start, now, "Source", NO_FILTERS, 60),
          "before the next pass the rollup is behind the raw rows, so the "
          "check below is not passing by accident")

    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
    for bucket in (60, 3600):
        got = db.overview(start, now, "Source", NO_FILTERS, bucket)
        want = raw(db, "overview", start, now, "Source", NO_FILTERS, bucket)
        check(got == want,
              f"one compaction later the {bucket}s view agrees with raw again "
              f"({got[4]} vs {want[4]})")
        check(any(row["key"] == "10.9.9.9" for row in got[3]),
              f"...and the late flow is one of the {bucket}s view's own rows")
    db.close()


# ------------------------------------------------------------------------ 11

def test_11_the_residual_never_stacks_downwards() -> None:
    print("11: a bucket read mid-rebuild does not draw a negative 'other'")
    db = store("residual.db")
    now = time.time()
    start = flowdb._align_down(now - 3600, 60)
    db.insert_flows([flow(i, start + i * 3.0) for i in range(600)])
    cover(db, hours=False)

    # A dimension's rows and its bucket's span row are written in separate
    # transactions, so a dimension rebuilt after late flows arrived can be
    # read against a span built before them. Reproduced here by shrinking
    # the spans: the stored keys then outweigh the total they are measured
    # against, which is what the residual is computed from.
    with db._lock:
        db._conn.execute(
            "UPDATE flow_rollup_span SET bytes = bytes / 3 WHERE tier = 60")
        db._conn.commit()

    _times, series, _b, _top, _totals = db.overview(
        start, now, "Source", NO_FILTERS, 60)
    negative = [(key, value) for key, values in series.items()
                for value in values if value < 0]
    check(not negative,
          f"no series the chart stacks is negative ({negative[:3]})")
    db.close()


# ------------------------------------------------------------------------ 12

def test_12_a_rewrite_reaches_both_tiers() -> None:
    print("12: a sampling rewrite is not consumed by whichever tier is first")
    db = store("resample_tiers.db")
    now = time.time()
    start = flowdb._align_down(now - 4 * 3600, 3600)
    db.insert_flows([flow(i, start + i * 8.0, sampling=1) for i in range(1500)])
    cover(db)
    # A store that has been running a while rather than one still seeding:
    # both tiers have consumed everything the initial load marked, so the
    # rewrite below is the only dirt there is.
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)

    db.record_sampling_rates([("10.0.0.1", 0, 0, 40)], since_ts=0.0)
    # The order the service compacts in: the minute tier, then the hourly one
    # built from it. One shared marker meant the minute pass cleared it and
    # the hourly tier never learned the rows had changed.
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
    for bucket in (60, 3600):
        got = db.overview(start, now, "Exporter", NO_FILTERS, bucket)
        want = raw(db, "overview", start, now, "Exporter", NO_FILTERS, bucket)
        check(got == want,
              f"the {bucket}s view follows the rewrite back and agrees with "
              f"raw ({got[4]} vs {want[4]})")

    # And a pass that runs out of budget leaves the mark for the next one,
    # rather than clearing it on the way past.
    db.record_sampling_rates([("10.0.0.2", 0, 0, 25)], since_ts=0.0)
    undo = slow_buckets(0.02)
    try:
        db.compact_rollup(60, budget_s=0.03)
    finally:
        undo()
    check(db._private_setting(flowdb._DIRTY % 60) is not None,
          "a pass too short to finish the rewrite keeps the mark")
    db.compact_rollup(60, max_buckets=10_000, budget_s=120)
    check(db.overview(start, now, "Exporter", NO_FILTERS, 60)
          == raw(db, "overview", start, now, "Exporter", NO_FILTERS, 60),
          "...and the pass after it finishes the job")
    db.close()


# ------------------------------------------------------------------------ 13

def test_13_one_slot_takes_the_coarsest_tier() -> None:
    print("13: top() and totals() take the coarsest tier that reaches them")
    db = store("single_slot.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 4 * 3600
    db.insert_flows([flow(i, start + i * 8.0) for i in range(1500)])
    cover(db)

    plan = db._rollup_plan(start, end, "Source", NO_FILTERS, None)
    check(plan is not None and plan[0] == 3600,
          f"with one slot to fill and both tiers reaching the window, the "
          f"hourly tier answers — sixty times fewer rows for the same number "
          f"({plan})")

    # The rule that makes that safe: a tier whose buckets do not start on t0
    # would leave the first partial bucket out of both arms, so a window
    # starting inside an hour drops to the tier that does divide it.
    plan = db._rollup_plan(float(start + 600), end, "Source", NO_FILTERS, None)
    check(plan is not None and plan[0] == 60,
          f"a window starting inside an hour falls to the minute tier, not "
          f"to the hourly one it does not line up with ({plan})")

    # What rollup_minute_days does to a window older than a couple of days:
    # the minute tier no longer reaches it, the hourly tier still does. That
    # used to fall all the way to raw.
    db._set_private_setting(flowdb._FLOOR % 60, int(end))
    plan = db._rollup_plan(start, end, "Source", NO_FILTERS, None)
    check(plan is not None and plan[0] == 3600,
          f"and with only the hourly floor left below the window it still "
          f"answers, rather than scanning every flow in it ({plan})")
    check(db.totals(start, end, NO_FILTERS)
          == raw(db, "totals", start, end, NO_FILTERS),
          "totals() over that window is exact")
    check(db.top(start, end, "Source", NO_FILTERS, 10)
          == raw(db, "top", start, end, "Source", NO_FILTERS, 10),
          "and so is top()")
    db.close()


# ------------------------------------------------------------------------ 14

def test_14_a_named_series_is_whole_in_every_bucket() -> None:
    """test_2 proves the TOTALS survive the cap. This is the check it left
    out: that a key the operator is watching — one of the window's top keys,
    so a named band on the chart — reads its true value in every bucket,
    including the buckets where the cap threw it away."""
    print("14: a named series has no holes where the cap bit")
    db = store("holes.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3600
    cap = ROLLUP_KEYS[60]
    regulars = [f"10.2.0.{k} → 10.9.9.9" for k in range(10)]
    flooded = (7, 23, 24)
    rows = []
    for minute in range(60):
        ts = start + minute * 60 + 30
        lull = minute in flooded
        for k in range(10):
            # Ten conversations that own the hour, at a tenth of their usual
            # volume in the flooded minutes: still the window's top ten by a
            # mile, and still present in those minutes — just no longer in
            # their top-48.
            rows.append(flow(k, ts, src_ip=f"10.2.0.{k}", dst_ip="10.9.9.9",
                             bytes=(1_000 if lull else 100_000) + k, sampling=1))
        if lull:
            # Three times the cap in one-off conversations, each heavier in
            # that minute than any regular is.
            rows.extend(flow(i, ts, src_ip=f"10.3.{i // 256}.{i % 256}",
                             dst_ip="10.9.9.9", bytes=5_000 + i, sampling=1)
                        for i in range(cap * 3))
    db.insert_flows(rows)
    cover(db)

    # First the fact the check below rests on: in a flooded minute the rollup
    # really did drop the regulars, so agreement is not for want of a cap.
    kept = {row["key"] for row in db._conn.execute(
        "SELECT key FROM flow_rollup WHERE tier = 60 AND dim = ? AND bucket = ?",
        (flowdb.DIMENSION_IDS["Conversation"],
         start + flooded[0] * 60)).fetchall()}
    check(len(kept) == cap and not (kept & set(regulars)),
          f"the flooded minute's rollup holds the cap's worth of keys and "
          f"none of the ten regulars ({len(kept)} kept, "
          f"{len(kept & set(regulars))} regulars among them)")

    for bucket in (60, 300, 3600):
        got = db.overview(start, end, "Conversation", NO_FILTERS, bucket,
                          series_limit=8, top_limit=10)
        want = raw(db, "overview", start, end, "Conversation", NO_FILTERS,
                   bucket, series_limit=8, top_limit=10)
        plan = db._rollup_plan(start, end, "Conversation", NO_FILTERS, bucket)
        holes = [(key, slot) for key, values in want[1].items()
                 for slot, value in enumerate(values)
                 if got[1].get(key, [None] * len(values))[slot] != value]
        check(plan is not None and not holes,
              f"at {bucket}s (tier {plan and plan[0]}) every named series "
              f"equals raw in every bucket ({len(holes)} slots differ: "
              f"{holes[:3]})")
        check(got == want,
              f"...and so does the rest of the {bucket}s answer")
    check(db.top(start, end, "Conversation", NO_FILTERS, 10)
          == raw(db, "top", start, end, "Conversation", NO_FILTERS, 10),
          "the top rows over the window are exact too, not just ranked right")

    # The bookkeeping that makes that possible.
    dim = flowdb.DIMENSION_IDS["Conversation"]
    flagged = [row["bucket"] for row in db._conn.execute(
        "SELECT bucket FROM flow_rollup_trunc WHERE tier = 60 AND dim = ?"
        " ORDER BY bucket", (dim,)).fetchall()]
    check(flagged == [start + m * 60 for m in flooded],
          f"exactly the flooded minutes are flagged for the dimension "
          f"({[(b - start) // 60 for b in flagged]})")
    check(db._conn.execute(
        "SELECT COUNT(*) AS n FROM flow_rollup_trunc WHERE tier = 3600"
        " AND dim = ? AND bucket = ?", (dim, start)).fetchone()["n"] == 1,
          "and the hour built from them is flagged as well, since its sums "
          "are short by what those minutes lost")
    check(db._conn.execute(
        "SELECT COUNT(*) AS n FROM flow_rollup_trunc WHERE dim = ?",
        (flowdb.DIMENSION_IDS["Protocol"],)).fetchone()["n"] == 0,
          "a dimension the cap never bit (three protocols) is not flagged")

    # Compacting the bucket again writes the same flag, not a second one, and
    # a bucket that no longer overflows loses its flag with its rows.
    db._compact_bucket(60, start + flooded[0] * 60)
    with db._lock:
        db._conn.execute("DELETE FROM flows WHERE src_ip LIKE '10.3.%'"
                         " AND ts_end >= ? AND ts_end < ?",
                         (start + flooded[1] * 60, start + flooded[1] * 60 + 60))
        db._conn.commit()
    db._compact_bucket(60, start + flooded[1] * 60)
    flagged = [row["bucket"] for row in db._conn.execute(
        "SELECT bucket FROM flow_rollup_trunc WHERE tier = 60 AND dim = ?"
        " ORDER BY bucket", (dim,)).fetchall()]
    check(flagged == [start + m * 60 for m in (flooded[0], flooded[2])],
          f"a rebuilt bucket keeps one flag, and one rebuilt under the cap "
          f"drops its flag ({[(b - start) // 60 for b in flagged]})")

    # Once retention has eaten the raw rows behind a flagged bucket there is
    # nothing to repair it from, and the capped rollup is the honest answer:
    # the hole is back, but the bucket's total is not, and the other flagged
    # bucket, whose raw rows survive, is still whole.
    with db._lock:
        db._conn.execute("DELETE FROM flows WHERE ts_end < ?",
                         (start + (flooded[0] + 1) * 60,))
        db._conn.commit()
    _t, series, _b, _top, _totals = db.overview(
        start, end, "Conversation", NO_FILTERS, 60, series_limit=8)
    spans = db._agg_rows(start, end, None, NO_FILTERS, 60)[4]
    early, late = flooded[0], flooded[2]
    # The eight heaviest regulars are the named bands (bytes = 100_000 + k).
    named = {key: 1_000 + k for k, key in enumerate(regulars)}
    named = dict(sorted(named.items(), key=lambda kv: -kv[1])[:8])
    check(all(series[key][early] == 0 for key in named)
          and all(series[key][late] == lull for key, lull in named.items()),
          "a flagged bucket the raw rows no longer reach is served capped, "
          "one they still reach is served whole")
    check(sum(values[early] for values in series.values())
          == spans[early][0],
          "and the capped bucket still adds up to its span, to the byte")

    # The flags go out with the rows they describe.
    db.prune(0, 0, minute_days=0, rollup_days=0)
    check(db._conn.execute("SELECT COUNT(*) AS n FROM flow_rollup_trunc"
                           ).fetchone()["n"] == 0,
          "retention takes the flags with the rollup rows")
    db.close()


TESTS = [
    test_1_rollup_and_raw_agree,
    test_2_totals_survive_truncation,
    test_3_the_seal_boundary_counts_once,
    test_4_sampling_in_both_orders,
    test_5_filters_never_touch_a_rollup,
    test_6_off_grid_buckets_stay_on_raw,
    test_7_compaction_is_idempotent,
    test_8_a_window_below_the_floor_falls_back,
    test_9_the_watermark_advances_under_a_tight_budget,
    test_10_a_late_exporter_still_reaches_the_rollups,
    test_11_the_residual_never_stacks_downwards,
    test_12_a_rewrite_reaches_both_tiers,
    test_13_one_slot_takes_the_coarsest_tier,
    test_14_a_named_series_is_whole_in_every_bucket,
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
    print("ALL NETFLOW ROLLUP ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
