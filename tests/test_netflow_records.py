"""The flow record list and its CSV export, against the FLOW_SCAN_CAP bound.

`flows()` bounds the volume orderings by id because `bytes * sampling` is a
product no index can serve. Every check here is about what that bound may
and may not do to an answer: it may cut the ordering short and say so, and
it may never turn a window that holds records into an empty list.

FLOW_SCAN_CAP is lowered for the duration rather than five million rows
being written -- it is the ratio between the cap and the id span that
decides the behaviour, not the absolute number.

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

TMPDIR = tmpdir("netflow_records_")
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


def flow(index: int, ts: float, **overrides):
    fields = dict(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 7}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443, 53, 22)[index % 4],
        protocol=(6, 17, 1)[index % 3], tos=index % 4, tcp_flags=0,
        in_if=index % 6, out_if=index % 8,
        src_as=64500 + index % 3, dst_as=64600 + index % 2, next_hop=None,
        packets=1 + index % 9, bytes=100 + index, sampling=1,
        domain=0, sampler_id=0)
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


def filled(name: str, total: int, span: float) -> tuple[FlowDatabase, float]:
    """`total` flows spread evenly over the `span` seconds ending now."""
    db = store(name)
    now = time.time()
    db.insert_flows([flow(i, now - span + i * (span / total))
                     for i in range(total)])
    return db, now


# ------------------------------------------------------------------------- 1

def test_1_an_old_window_still_returns_its_records() -> None:
    print("1: a window older than the scan bound is not an empty list")
    db, now = filled("old.db", 6000, 3600.0)
    original = flowdb.FLOW_SCAN_CAP
    # The newest 2000 ids stand in for the newest two million: the window
    # asked for below sits wholly under that bound, as any records view of a
    # 40-minute-old window does on a five-million-row store.
    flowdb.FLOW_SCAN_CAP = 2000
    try:
        t0, t1 = now - 2400, now - 1800
        rows, bounded = db.flows(t0, t1, NO_FILTERS, order="time")
        check(rows and not bounded,
              f"ordered by time the window returns its records unbounded "
              f"({len(rows)} rows, bounded={bounded})")

        heaviest, bounded = db.flows(t0, t1, NO_FILTERS, order="bytes")
        check(heaviest,
              f"and ordered by volume it returns them too, rather than "
              f"nothing at all ({len(heaviest)} rows)")
        check(not bounded,
              "with the bound reported as not having bitten, because the "
              "answer really is the heaviest in the window")
        inside = [row for row in heaviest if not t0 <= row["ts_end"] <= t1]
        check(not inside, f"every row is inside the window ({len(inside)} "
                          f"outside it)")
        volumes = [row["bytes"] * row["sampling"] for row in heaviest]
        check(volumes == sorted(volumes, reverse=True),
              "and they are in descending volume order")

        packets, _bounded = db.flows(t0, t1, NO_FILTERS, order="packets")
        check(bool(packets), f"the packets ordering answers as well "
                             f"({len(packets)} rows)")
    finally:
        flowdb.FLOW_SCAN_CAP = original
    db.close()


# ------------------------------------------------------------------------- 2

def test_2_a_recent_window_is_still_bounded() -> None:
    print("2: a window reaching under the bound still says the bound bit")
    db, now = filled("recent.db", 6000, 3600.0)
    original = flowdb.FLOW_SCAN_CAP
    flowdb.FLOW_SCAN_CAP = 2000
    try:
        rows, bounded = db.flows(now - 3600, now, NO_FILTERS, order="bytes")
        check(rows and bounded,
              f"a window straddling the bound is answered and flagged "
              f"({len(rows)} rows, bounded={bounded})")
        oldest = min(row["ts_end"] for row in rows)
        check(oldest > now - 3600,
              "and what came back is from the recent end, which is what the "
              "bound is for")
        _rows, bounded = db.flows(now - 3600, now, NO_FILTERS, order="time")
        check(not bounded,
              "the time ordering over the same window is never bounded: it "
              "is ix_flows_ts end to end")
    finally:
        flowdb.FLOW_SCAN_CAP = original
    db.close()


# ------------------------------------------------------------------------- 3

def test_3_an_empty_window_stays_empty() -> None:
    print("3: a window that holds nothing is not rescued into holding rows")
    db, now = filled("empty.db", 500, 600.0)
    for order in ("time", "bytes", "packets"):
        rows, bounded = db.flows(now + 600, now + 1200, NO_FILTERS, order=order)
        check(not rows and not bounded,
              f"a window past the newest flow is empty ordered by {order}")
    db.close()


# ------------------------------------------------------------------------- 4

def test_4_filters_still_apply_on_the_fallback() -> None:
    print("4: the unbounded fallback is still the filtered query")
    db, now = filled("filtered.db", 6000, 3600.0)
    original = flowdb.FLOW_SCAN_CAP
    flowdb.FLOW_SCAN_CAP = 2000
    try:
        rows, _bounded = db.flows(now - 2400, now - 1800,
                                  {"exporter": "10.0.0.1"}, order="bytes")
        check(rows and all(row["exporter"] == "10.0.0.1" for row in rows),
              f"every row of the fallback answer matches the filter "
              f"({len(rows)} rows)")
    finally:
        flowdb.FLOW_SCAN_CAP = original
    db.close()


TESTS = [
    test_1_an_old_window_still_returns_its_records,
    test_2_a_recent_window_is_still_bounded,
    test_3_an_empty_window_stays_empty,
    test_4_filters_still_apply_on_the_fallback,
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
    print("ALL NETFLOW RECORD ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
