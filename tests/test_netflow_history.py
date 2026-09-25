"""The operator's case: a multi-day chart filtered to one exporter, on a store
whose row cap leaves the raw table a couple of hours deep.

Four exporters, a week of flows (one exporter ten times busier than the
rest, each with its own interfaces), summarised, then capped to about two
hours of records. The exporter-filtered three-day chart and the interface
report must look the same after the cap as before it, and a filter the
summaries cannot answer must say it is records-only.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import os
import random
import shutil
import sys
import time
import types

from _paths import tmpdir

from netpath import flowdb
from netpath.flowdb import FlowDatabase

TMPDIR = tmpdir("netflow_history_")
FAILS: list[str] = []

DAY = 86400
EXPORTERS = ("10.199.17.1", "10.199.17.2", "10.199.17.3", "10.199.17.4")
BUSY = EXPORTERS[0]
APPS = (443, 80, 53, 2055, 161, 3268, 5007, 22)
NO_FILTERS = {"src_ip": "", "dst_ip": "", "port": None, "protocol": None,
              "exporter": None, "iface": None, "direction": "both"}


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


def raw(db: FlowDatabase, method: str, *args, **kwargs):
    real = FlowDatabase._rollup_plan
    FlowDatabase._rollup_plan = lambda *a, **k: None
    try:
        return getattr(db, method)(*args, **kwargs)
    finally:
        FlowDatabase._rollup_plan = real


def cover(db: FlowDatabase) -> None:
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=100_000, budget_s=600)
        while True:
            written, done = db.backfill_rollup(tier, max_buckets=100_000,
                                               budget_s=600)
            if done or not written:
                break


def week_of_flows(now: float) -> list:
    """Oldest first, so ids follow time the way a collector's do. A flow a
    minute per quiet exporter, ten a minute for the busy one; a diurnal
    swing in volume, never in presence."""
    rng = random.Random(1567)
    start = flowdb._align_down(now - 7 * DAY, 3600)
    rows = []
    for number, exporter in enumerate(EXPORTERS):
        step = 6.0 if exporter == BUSY else 60.0
        interfaces = [100 * (number + 1) + k for k in range(1, 5)]
        ts = start + number
        while ts < now - 30:
            hour = (ts % DAY) / 3600.0
            swing = 1.5 + (1.0 if 8 <= hour < 18 else 0.0)
            app = rng.choice(APPS)
            rows.append(types.SimpleNamespace(
                exporter=exporter, version=9, ts_start=ts - 5, ts_end=ts,
                src_ip=f"10.20.{number}.{rng.randrange(1, 41)}",
                dst_ip=f"172.16.0.{rng.randrange(1, 11)}",
                src_port=rng.randrange(49152, 65535), dst_port=app,
                protocol=17 if app in (53, 161, 2055) else 6, tos=0,
                tcp_flags=0, in_if=rng.choice(interfaces),
                out_if=rng.choice(interfaces), src_as=0, dst_as=0,
                next_hop=None, packets=rng.randrange(1, 40),
                bytes=int(rng.randrange(200, 20_000) * swing), sampling=1,
                domain=0, sampler_id=0))
            ts += step
    rows.sort(key=lambda flow: flow.ts_end)
    return rows


def main() -> int:
    try:
        run()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"{len(FAILS)} CHECK(S) FAILED:")
        for item in FAILS:
            print(f"  - {item}")
        return 1
    print("ALL NETFLOW HISTORY ASSERTIONS PASSED")
    return 0


def run() -> None:
    print("the operator's case: a 3-day exporter chart outlives a 2-hour "
          "raw table")
    now = time.time()
    db = FlowDatabase(os.path.join(TMPDIR, "history.db"))
    rows = week_of_flows(now)
    for first in range(0, len(rows), 20_000):
        db.insert_flows(rows[first:first + 20_000])
    started = time.monotonic()
    cover(db)
    print(f"  ({len(rows)} flows summarised in "
          f"{time.monotonic() - started:.1f} s)")

    t1 = now
    t0 = now - 3 * DAY
    hour0 = flowdb._align_up(t0, 3600)
    iface = 101
    exporter_filter = {**NO_FILTERS, "exporter": BUSY}
    iface_filter = {**NO_FILTERS, "exporter": BUSY, "iface": iface,
                    "direction": "both"}
    src_filter = {**NO_FILTERS, "src_ip": "10.20.0.7"}

    def snapshot():
        return {
            "exporters": {exporter: db.overview(
                t0, t1, "Application", {**NO_FILTERS, "exporter": exporter},
                900) for exporter in EXPORTERS},
            "conversation": db.overview(t0, t1, "Conversation",
                                        exporter_filter, 900),
            "interface": db.overview(hour0, t1, "Application", iface_filter,
                                     3600),
            "report": db.interface_totals(hour0, t1, BUSY),
            # One slot: whole hours only, as for any single-slot read.
            "totals": db.totals(hour0, t1, NO_FILTERS),
            "exporter_totals": db.totals(hour0, t1, exporter_filter),
        }

    before = snapshot()
    check(before["exporters"][BUSY] == raw(db, "overview", t0, t1,
                                           "Application", exporter_filter, 900),
          "before the cap, the summaries' exporter chart equals the raw one")
    check(before["report"] == raw(db, "interface_totals", hour0, t1, BUSY)
          and before["interface"] == raw(db, "overview", hour0, t1,
                                         "Application", iface_filter, 3600),
          "...and so do the interface report and interface chart")
    check(before["exporter_totals"] == raw(db, "totals", hour0, t1,
                                           exporter_filter),
          "...and the exporter's totals")

    per_minute = 10 + 3
    max_flows = 2 * 60 * per_minute
    db.prune(14, max_flows, budget_s=120)
    cov = db.coverage()
    raw_hours = (now - cov["raw_oldest"]) / 3600.0
    check(1.5 <= raw_hours <= 2.5,
          f"the row cap leaves the raw table about two hours deep "
          f"({raw_hours:.2f} h, {max_flows} rows)")

    after = snapshot()
    for exporter in EXPORTERS:
        times, _series, bucket_s, _top, totals = after["exporters"][exporter]
        spans = db._agg_rows(t0, t1, None, {**NO_FILTERS, "exporter": exporter},
                             900)[4]
        empty = [slot for slot in range(len(times)) if not spans.get(slot)]
        days = {int((times[slot] - times[0]) // DAY) for slot in spans}
        check(bucket_s == 3600 and not empty and days == {0, 1, 2, 3}
              and totals["flows"] > 0,
              f"{exporter}: the 3-day chart has traffic in every hour of "
              f"every day ({len(times)} hourly buckets, {len(empty)} empty)")
        check(after["exporters"][exporter] == before["exporters"][exporter],
              f"{exporter}: and it is the chart it was before the cap")

    _t, series, _b, _top, totals = after["conversation"]
    spans = db._agg_rows(t0, t1, None, exporter_filter, 900)[4]
    check(totals == before["conversation"][4]
          and all(sum(values[slot] for values in series.values())
                  == spans[slot][0] for slot in spans),
          "over the conversation cap the totals are unchanged and every "
          "bucket still adds up to its span, the rest in 'other'")
    check(after["interface"] == before["interface"]
          and after["report"] == before["report"]
          and any(row["iface"] == iface and row["dir"] == side
                  for row in after["report"] for side in ("in", "out")),
          "the interface chart and report are unchanged by the cap")
    check(after["totals"] == before["totals"]
          and after["exporter_totals"] == before["exporter_totals"],
          f"totals are exact, unfiltered and per exporter "
          f"({after['exporter_totals']['flows']} flows)")

    info: dict = {}
    db.overview(t0, t1, "Application", src_filter, 900, info=info)
    check(info["records_only"] and info["summaries_from"] is None,
          f"a source-address filter says it is records-only ({info})")
    info = {}
    db.overview(t0, t1, "Application", exporter_filter, 900, info=info)
    check(not info["records_only"] and info["widened"]
          and info["summaries_from"] <= t0,
          f"while the exporter filter says where its summaries start ({info})")
    check(cov["scoped_hourly_floor"] <= now - 6 * DAY
          and cov["iface_hourly_floor"] <= now - 6 * DAY
          and now - 2 * DAY - 120 <= cov["scoped_minute_floor"]
          <= now - 2 * DAY + 3600,
          f"coverage() reports the scoped floors: a week hourly, two days "
          f"by the minute ({cov})")
    db.close()


if __name__ == "__main__":
    sys.exit(main())
