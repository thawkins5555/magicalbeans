"""The NetFlow overview read from raw flows versus from the rollups, measured.

Deliberately not a test_*.py: what this costs depends on the disk under it, so
it prints numbers rather than asserting them (run_all.py only picks up
test_*.py).

    python3 tests/bench_flow_overview.py [rows ...]

Each `rows` figure is one run: that many flows are seeded across the widest
window the UI offers, both tiers are built over them, and the six bucket sizes
api._flow_bucket can hand flowdb are timed twice — once as shipped, once with
_rollup_plan forced to None, which is the query path that existed before the
rollups.
"""
import os
import sys
import time

import _paths
from _paths import tmpdir

from netpath import flowdb
from netpath.flowdb import FlowDatabase

SPAN = 30 * 86400          # app.js's widest range
# The six the UI asks for, with the window each of them is chosen for.
CASES = ((10, 900), (60, 3600), (300, 21600), (900, 86400),
         (3600, 259200), (21600, 2592000))
INSERT_BATCH = 100_000


def seed(db: FlowDatabase, rows: int, end: float) -> None:
    """`rows` flows spread evenly across the window before `end`, written the
    way the collector writes them (one transaction per batch)."""
    step = SPAN / rows
    start = end - SPAN
    written = 0
    while written < rows:
        batch = min(INSERT_BATCH, rows - written)
        with db._lock:
            db._conn.executemany(
                "INSERT INTO flows(exporter, version, ts_start, ts_end, src_ip,"
                " dst_ip, src_port, dst_port, protocol, tos, in_if, out_if,"
                " src_as, dst_as, packets, bytes, sampling)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(f"10.0.0.{i % 4}", 9, start + i * step, start + i * step,
                  f"192.168.{i // 251 % 256}.{i % 251}", f"8.8.{i % 7}.{i % 13}",
                  1024 + i % 4001, (80, 443, 53, 22)[i % 4], (6, 17)[i % 2],
                  i % 8, i % 12, i % 12, 64500 + i % 5, 64600 + i % 5,
                  1 + i % 9, 100 + i % 9973, (1, 2, 10)[i % 3])
                 for i in range(written, written + batch)])
            db._conn.commit()
        written += batch


def build(db: FlowDatabase) -> float:
    """Both tiers over everything stored, as the service's rollup loop and
    maintenance backfill would eventually have done."""
    started = time.monotonic()
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10**9, budget_s=10**6)
        while True:
            _written, done = db.backfill_rollup(tier, max_buckets=10**9,
                                                budget_s=10**6)
            if done:
                break
    return time.monotonic() - started


def timed(db: FlowDatabase, t0: float, t1: float, bucket: float,
          rollups: bool) -> tuple[float, int]:
    real = FlowDatabase._rollup_plan
    if not rollups:
        FlowDatabase._rollup_plan = lambda *a, **k: None
    try:
        started = time.monotonic()
        result = db.overview(t0, t1, "Conversation", {}, bucket)
        return time.monotonic() - started, result[4]["bytes"]
    finally:
        FlowDatabase._rollup_plan = real


def run(folder: str, rows: int) -> None:
    end = flowdb._align_down(time.time() - 300, 21600)
    db = FlowDatabase(os.path.join(folder, f"bench-{rows}.db"))
    started = time.monotonic()
    seed(db, rows, end)
    print(f"\n{rows:,} flows over {SPAN // 86400} days "
          f"(seeded in {time.monotonic() - started:.1f} s, "
          f"{db.size_bytes() / 1e6:.0f} MB)")
    print(f"  rollups built in {build(db):.1f} s, "
          f"{db.size_bytes() / 1e6:.0f} MB with them")
    print(f"  {'window':>8}  {'bucket':>7}  {'raw':>10}  {'rollup':>10}  "
          f"{'speedup':>8}  {'served by':>9}  agree")
    for bucket, span in CASES:
        t0, t1 = end - span, end
        raw_s, raw_bytes = timed(db, t0, t1, bucket, rollups=False)
        roll_s, roll_bytes = timed(db, t0, t1, bucket, rollups=True)
        plan = db._rollup_plan(flowdb._align_down(t0, bucket), t1,
                               "Conversation", {}, bucket)
        print(f"  {span:>8}  {bucket:>7}  {raw_s * 1000:>8.0f} ms  "
              f"{roll_s * 1000:>8.0f} ms  {raw_s / max(roll_s, 1e-9):>7.1f}x  "
              f"{('tier ' + str(plan[0])) if plan else 'raw':>9}  "
              f"{'exact' if raw_bytes == roll_bytes else 'differs'}")
    db.close()


def main(argv) -> int:
    sizes = [int(item.replace("_", "")) for item in argv] or [1_000_000]
    folder = tmpdir("bench_flow_overview_")
    print(f"scratch: {folder}")
    for rows in sizes:
        run(folder, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
