"""Per-sample versus batched metric writes, measured.

Deliberately not a test_*.py: throughput depends on the disk under it, so
this prints numbers rather than asserting them (run_all.py only picks up
test_*.py). It exists so the claim in the 4.39.0 notes — that batching a
poll's samples into one transaction is worth roughly two orders of
magnitude — can be re-checked on any machine rather than taken on trust.

    python3 tests/bench_record_samples.py [rows] [preload]

`rows` is how many samples one "poll" writes (default 500, a 500-port
chassis's four rates per port is more); `preload` is how many sample rows
are already in the table, since the review measured the per-row path
degrading from 13,731/s on an empty file to 2,181/s at 5M rows.
"""
import os
import sys
import time

import _paths
from _paths import tmpdir

from netpath.nodesdb import NodesDatabase


def build(path: str, preload: int):
    db = NodesDatabase(path)
    group_id = db.ensure_default_group()
    device_id = db.add_device("127.0.0.1", "bench", group_id=group_id)
    if preload:
        metric_id = db.record_metric_sample(
            device_id, "preload", "Preload", "", "gauge", 0.0, 0.0)
        with db._lock:
            db._conn.executemany(
                "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                " VALUES (?,?,?)",
                [(metric_id, float(i + 1), float(i)) for i in range(preload)])
            db._conn.commit()
    return db, device_id


def record_one_at_a_time(db, device_id, key, label, unit, kind, ts, value):
    """What record_metric_sample was before 4.39.0: a SELECT, an INSERT or
    an UPDATE, the sample, and a commit — per sample. Reproduced here
    rather than kept in the module, so the shipped code has one write path.
    """
    with db._lock:
        row = db._conn.execute(
            "SELECT id FROM metrics WHERE device_id=? AND key=?",
            (device_id, key)).fetchone()
        if row is None:
            cur = db._conn.execute(
                "INSERT INTO metrics(device_id, key, label, unit, kind,"
                " last_value, last_ts) VALUES (?,?,?,?,?,?,?)",
                (device_id, key, label, unit, kind, value, ts))
            metric_id = cur.lastrowid
        else:
            metric_id = row["id"]
            db._conn.execute(
                "UPDATE metrics SET last_value=?, last_ts=?, label=?, unit=?"
                " WHERE id=?", (value, ts, label, unit, metric_id))
        if value is not None:
            db._conn.execute(
                "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                " VALUES (?,?,?)", (metric_id, ts, value))
        db._conn.commit()


def main(argv):
    rows = int(argv[0]) if argv else 500
    preload = int(argv[1]) if len(argv) > 1 else 200_000
    folder = tmpdir("bench_samples_")

    print(f"{rows} samples per poll, {preload:,} sample rows already stored\n")

    db, device_id = build(os.path.join(folder, "per_row.db"), preload)
    batch = [(f"per_row.{i}", f"metric {i}", "u", "gauge", 0.0, float(i))
             for i in range(rows)]
    started = time.monotonic()
    for key, label, unit, kind, _ts, value in batch:
        record_one_at_a_time(db, device_id, key, label, unit, kind,
                             time.time(), value)
    per_row_s = time.monotonic() - started
    db.close()

    db, device_id = build(os.path.join(folder, "batched.db"), preload)
    now = time.time()
    batch = [(f"batched.{i}", f"metric {i}", "u", "gauge", now, float(i))
             for i in range(rows)]
    started = time.monotonic()
    db.record_metric_samples(device_id, batch)
    batched_s = time.monotonic() - started
    db.close()

    print(f"one commit per sample : {per_row_s:8.3f} s  "
          f"{rows / per_row_s:12,.0f} samples/s")
    print(f"one commit per poll   : {batched_s:8.3f} s  "
          f"{rows / batched_s:12,.0f} samples/s")
    print(f"\nbatched is {per_row_s / batched_s:.0f}x faster for this poll")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
