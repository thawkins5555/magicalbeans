"""NetFlow store at the operator's scale, once, for a baseline.

Deliberately not a test_*.py (run_all.py only picks up test_*.py): informational.

    python3 tests/bench_flow_scale.py [--rows N] [--hours H] [--days D]

Seeds a dense recent stretch (`--rows` over `--hours`, ending 200 s ago)
behind an older sparse stretch (`--days` at ~2% of the dense rate), builds
both rollup tiers, then prunes to the dense stretch's raw retention -- the
operator's shape: raw covers the recent hours, the summaries the whole span.
Six exporters, 10.0.0.1-.6, each with interfaces 1-8.
"""
import argparse
import os
import sys
import threading
import time
import types

import _paths
from _paths import tmpdir

from netpath import flowdb
from netpath.flowdb import FlowDatabase

EXPORTERS = [f"10.0.0.{i}" for i in range(1, 7)]
INSERT_BATCH = 100_000
SPARSE_RATE_FRACTION = 0.02


def row(i: int, ts: float) -> tuple:
    return (EXPORTERS[i % len(EXPORTERS)], 9, ts, ts,
            f"192.168.{i // 251 % 256}.{i % 251}", f"8.8.{i % 7}.{i % 13}",
            1024 + i % 4001, (80, 443, 53, 22)[i % 4], (6, 17)[i % 2],
            i % 8, 1 + i % 8, 1 + i % 8, 64500 + i % 5, 64600 + i % 5,
            1 + i % 9, 100 + i % 9973, 1)


def seed(db: FlowDatabase, rows: int, start: float, end: float) -> None:
    """`rows` flows spread evenly across [start, end), written the way the
    collector writes them (one transaction per batch)."""
    if rows <= 0:
        return
    step = (end - start) / rows
    written = 0
    while written < rows:
        batch = min(INSERT_BATCH, rows - written)
        with db._lock:
            db._conn.executemany(
                "INSERT INTO flows(exporter, version, ts_start, ts_end, src_ip,"
                " dst_ip, src_port, dst_port, protocol, tos, in_if, out_if,"
                " src_as, dst_as, packets, bytes, sampling)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [row(i, start + i * step)
                 for i in range(written, written + batch)])
            db._conn.commit()
        written += batch


def build(db: FlowDatabase) -> float:
    """Both tiers over everything stored, as the rollup loop eventually would."""
    started = time.monotonic()
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10**9, budget_s=10**6)
        while True:
            _written, done = db.backfill_rollup(tier, max_buckets=10**9,
                                                budget_s=10**6)
            if done:
                break
    return time.monotonic() - started


def one_flow(ts: float) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        exporter="10.0.0.1", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip="192.168.9.9", dst_ip="8.8.4.4", src_port=51000, dst_port=443,
        protocol=6, tos=0, tcp_flags=0, in_if=3, out_if=4,
        src_as=64500, dst_as=64600, next_hop=None, packets=5, bytes=4000,
        sampling=1, domain=0, sampler_id=0)


def timed(label: str, fn) -> None:
    started = time.monotonic()
    fn()
    print(f"  {label:<52} {(time.monotonic() - started) * 1000:8.1f} ms")


def contention(db: FlowDatabase, label: str, thread_call) -> None:
    thread_elapsed = []

    def runner():
        started = time.monotonic()
        thread_call()
        thread_elapsed.append(time.monotonic() - started)

    t = threading.Thread(target=runner)
    t.start()
    time.sleep(0.05)
    started = time.monotonic()
    db.coverage()
    coverage_wait = time.monotonic() - started
    started = time.monotonic()
    db.insert_flows([one_flow(time.time())])
    insert_wait = time.monotonic() - started
    t.join()
    print(f"  contention ({label}): thread {thread_elapsed[0] * 1000:.0f} ms,"
          f" coverage waited {coverage_wait * 1000:.0f} ms,"
          f" insert waited {insert_wait * 1000:.0f} ms")


def run(folder: str, rows: int, hours: float, days: float) -> None:
    db = FlowDatabase(os.path.join(folder, "bench.db"))
    print(f"netpath.__file__ = {__import__('netpath').__file__}")

    now = time.time()
    dense_end = now - 200
    dense_start = dense_end - hours * 3600
    sparse_rows = round(rows * SPARSE_RATE_FRACTION * (days * 86400)
                        / (hours * 3600))

    started = time.monotonic()
    seed(db, sparse_rows, dense_start - days * 86400, dense_start)
    seed(db, rows, dense_start, dense_end)
    seed_s = time.monotonic() - started
    print(f"seeded {rows:,} dense + {sparse_rows:,} sparse flows in"
          f" {seed_s:.1f} s ({db.size_bytes() / 1e6:.0f} MB)")

    build_s = build(db)
    print(f"rollups built in {build_s:.1f} s ({db.size_bytes() / 1e6:.0f} MB)")

    db.prune(retention_days=hours / 24, max_flows=rows)
    print(f"pruned to raw {hours}h / {rows:,} rows"
          f" ({db.size_bytes() / 1e6:.0f} MB)")

    t1 = time.time()
    print("queries:")
    timed("overview  24h  unfiltered  Application  b=900",
          lambda: db.overview(t1 - 86400, t1, "Application", {}, 900))
    timed("overview  7d   exporter=10.0.0.1          b=3600",
          lambda: db.overview(t1 - 7 * 86400, t1, "Application",
                              {"exporter": "10.0.0.1"}, 3600))
    timed("overview  24h  exporter+iface+dir         b=900",
          lambda: db.overview(t1 - 86400, t1, "Application",
                              {"exporter": "10.0.0.1", "iface": 3,
                               "direction": "both"}, 900))
    timed("overview  24h  src_ip=192.168.1. (records) b=900",
          lambda: db.overview(t1 - 86400, t1, "Application",
                              {"src_ip": "192.168.1."}, 900))
    timed("flows()   24h  order=bytes limit=200",
          lambda: db.flows(t1 - 86400, t1, {}, limit=200, order="bytes"))
    timed("exporter_totals(now-300, now)",
          lambda: db.exporter_totals(t1 - 300, t1))
    for span, label in ((3600, "1h"), (86400, "24h"), (7 * 86400, "7d")):
        timed(f"interface_totals over {label}",
              lambda span=span: db.interface_totals(t1 - span, t1))
    timed("coverage()", lambda: db.coverage())

    print("contention:")
    contention(db, "flows() 24h",
              lambda: db.flows(t1 - 86400, t1, {}, limit=200, order="bytes"))
    contention(db, "overview exporter=10.0.0.1 7d",
              lambda: db.overview(t1 - 7 * 86400, t1, "Application",
                                  {"exporter": "10.0.0.1"}, 3600))

    print(f"lock_stats: {db.lock_stats()}")
    print(f"read_lock_stats: {getattr(db, 'read_lock_stats', lambda: {})()}")
    db.close()


def main(argv) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=5_000_000)
    parser.add_argument("--hours", type=float, default=1.7)
    parser.add_argument("--days", type=float, default=2)
    args = parser.parse_args(argv)
    folder = tmpdir("bench_flow_scale_")
    print(f"scratch: {folder}")
    run(folder, args.rows, args.hours, args.days)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
