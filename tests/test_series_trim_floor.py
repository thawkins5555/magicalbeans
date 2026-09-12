"""nodes_series.db's size cap: which of the two tables gives, and how far.

`trim_to_size` used a flat 5,000-row floor under the raw samples and trimmed
them first -- a tenth of a sample per metric across a 49,607-metric fleet,
so a store on its cap shredded the window the 1-hour charts read and never
reached the 400-day history it was protecting. Two things are pinned: both
floors scale with the metric count, and the rollups are the stage that
gives first. Real store, throwaway file, test_storage_oldest.py's shape:
only real rows have a size on disk.
"""
import os
import shutil
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesseriesdb import NodesSeriesDatabase

TMPDIR = _paths.tmpdir("series_trim_floor_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


METRICS = 2_000
SAMPLES_EACH = 100
HOURS_EACH = 60
BASE_TS = 1_700_000_000.0


def seed(db):
    """METRICS metrics, SAMPLES_EACH raw samples and HOURS_EACH rollups each,
    oldest first so both tables have a genuine age ordering to trim by."""
    with db._lock:
        db._conn.executemany(
            "INSERT INTO metrics(device_id, key, label, unit, kind)"
            " VALUES (?,?,?,?,?)",
            [(1 + i % 250, f"if_in_octets.{i}", f"Port {i}", "bps",
              "counter_rate") for i in range(METRICS)])
        ids = [row["id"] for row in db._conn.execute(
            "SELECT id FROM metrics ORDER BY id").fetchall()]
        db._conn.executemany(
            "INSERT INTO samples(metric_id, ts, value) VALUES (?,?,?)",
            [(mid, BASE_TS + s * 60.0, float(s)) for s in range(SAMPLES_EACH)
             for mid in ids])
        db._conn.executemany(
            "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
            " VALUES (?,?,?,?,?,?)",
            [(mid, int(BASE_TS) - h * 3600, 60, 0.0, float(h), float(h) * 2)
             for h in range(HOURS_EACH) for mid in ids])
        db._conn.commit()


def counts(db):
    with db._lock:
        return (db._conn.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"],
                db._conn.execute(
                    "SELECT COUNT(*) AS n FROM samples_hourly").fetchone()["n"])


def oldest(db, table, column):
    with db._lock:
        return db._conn.execute(
            f"SELECT MIN({column}) AS v FROM {table}").fetchone()["v"]


# --------------------------------------------------- 1. the floors scale

small = NodesSeriesDatabase(os.path.join(TMPDIR, "small.db"))
check("an empty store still keeps the flat floor under both tables, so a "
      "handful of metrics is not trimmed to nothing",
      small._sample_floor() == 5_000 and small._hourly_floor() == 5_000,
      (small._sample_floor(), small._hourly_floor()))

db = NodesSeriesDatabase(os.path.join(TMPDIR, "nodes_series.db"))
seed(db)

check("the raw floor is half an hour of polling per metric, not a flat "
      "5,000 rows across the whole fleet",
      db._sample_floor() == 30 * METRICS, db._sample_floor())
check("...and the rollup floor is still a day of hours per metric",
      db._hourly_floor() == 24 * METRICS, db._hourly_floor())

raw_before, roll_before = counts(db)
check("the seed is above both floors, so either table could give",
      raw_before > db._sample_floor() and roll_before > db._hourly_floor(),
      (raw_before, roll_before))


# ------------------------------------- 2. a small breach: the rollups give

size = db.size_bytes()
oldest_hour_before = oldest(db, "samples_hourly", "hour")
removed = db.trim_to_size(int(size * 0.92))
raw_after, roll_after = counts(db)

check("a cap just under the file's size removes something", removed > 0, removed)
check("the rollups are what gave -- they are the long history, and the raw "
      "window is what a chart is about to read",
      roll_after < roll_before, (roll_before, roll_after))
check("...and not one raw sample was touched while the rollups were still "
      "above their floor",
      raw_after == raw_before, (raw_before, raw_after))
check("what it deleted is the oldest hours, never the recent ones "
      "compact_rollup's redo window rewrites",
      oldest(db, "samples_hourly", "hour") > oldest_hour_before,
      (oldest_hour_before, oldest(db, "samples_hourly", "hour")))


# --------------------------- 3. a severe breach: raw gives, down to the floor

db.trim_to_size(4096)
raw_floored, roll_floored = counts(db)

check("a cap nothing can fit under still leaves the raw floor intact, "
      "rather than shredding the window every 1-hour chart reads",
      raw_floored >= db._sample_floor(), (raw_floored, db._sample_floor()))
check("...and leaves the rollup floor intact too",
      roll_floored >= db._hourly_floor(), (roll_floored, db._hourly_floor()))
check("the rollups were spent before the raw samples were, so the file "
      "gave up its far end before its recent end",
      roll_floored <= db._hourly_floor() + 24 * METRICS
      and roll_before - roll_floored > 0,
      (roll_before, roll_floored, raw_before, raw_floored))
check("and the raw rows that did go were the oldest ones",
      raw_floored == raw_before
      or oldest(db, "samples", "ts") > BASE_TS,
      (raw_before, raw_floored, oldest(db, "samples", "ts")))

db.close()
small.close()
shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
