"""The history maintenance rewrite (compact_rollup, prune's per-band delete)
must delete/summarise exactly what the shipped 5.46.0 code did, just through
a per-metric seek instead of a metric-id range scan. _trim_hourly's own
section below is a plain regression guard -- it was tried as a batched
rewrite too, then reverted, and is unchanged from 5.46.0.

Each piece is checked two ways: an "old_*" function from
_old_series_maintenance.py, copied verbatim from the pre-rewrite code, is run
against one store while the live class method runs against an identically
seeded twin; the resulting tables are then compared row for row. Seed values
are small integers throughout, so AVG cannot pick up a different rounding
from a different summation order. bench_prune.py's --oracle mode uses the
same oracle functions to compare wall time and lock hold at real scale.

Also covers the mid-rewrite union view (_union_sql/_live_tables) that
test_series_without_rowid.py exercises for the rewrite itself: maintenance
must keep working, and keep matching the old code, while a table is split
across `table`/`table_new`.
"""
import os
import shutil
import sqlite3
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from _old_series_maintenance import (old_compact_rollup, old_prune,
                                     old_prune_by_band, old_trim_hourly)
from netpath.nodesseriesdb import NodesSeriesDatabase, SCOPE_DEVICE, SCOPE_INTERFACE

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


TMPDIR = _paths.tmpdir("series_maintenance_equiv_")
HOUR = 3600


# -------------------------------------------------------------------- utils

def snapshot(db, table, columns):
    cols = ", ".join(columns)
    with db._lock:
        return sorted(tuple(row) for row in db._conn.execute(
            f"SELECT {cols} FROM {table}").fetchall())


def plan(db, sql, params):
    with db._lock:
        return [row[3] for row in
                db._conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()]


# =================================================== 1. compact_rollup, fresh

NOW = 1_800_000_000.0
NOW_HOUR = int(NOW // 3600) * 3600 - 3600
METRICS_A = 24
DEVICE_TIER_HOURS = 30      # device-level metrics: samples across 30 hours
PORT_TIER_HOURS = 30


def seed_rollup_case(db):
    """24 metrics (half device-level, half per-port), samples across 30
    distinct hours, irregular offsets within the hour, one metric skipping
    one whole hour, some samples exactly on an hour boundary, and the last
    2 hours (the redo window) left for a second wave below."""
    ids = []
    for i in range(METRICS_A):
        key = f"cpu_pct_{i}" if i % 2 == 0 else f"if_in_bps.{i}"
        ids.append(db.record_metric_sample(
            1 + i % 3, key, key, "u", "gauge", NOW - 60, 0.0))
    rows = []
    for h in range(DEVICE_TIER_HOURS):
        hour = NOW_HOUR - h * HOUR
        for j, mid in enumerate(ids):
            if h == 5 and j == 3:
                continue        # a metric with no samples in this hour
            # Irregular offsets, plus one sample exactly on the boundary.
            offsets = (0, 137, 900, 2400, 3599) if j % 4 else (0, 1800)
            for off in offsets:
                rows.append((mid, hour + off, float((h + j + off) % 50)))
    with db._lock:
        db._conn.executemany(
            "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
            " VALUES (?,?,?)", rows)
        db._conn.commit()
    return ids


db_old = NodesSeriesDatabase(os.path.join(TMPDIR, "rollup_old.db"))
db_new = NodesSeriesDatabase(os.path.join(TMPDIR, "rollup_new.db"))
ids_old = seed_rollup_case(db_old)
ids_new = seed_rollup_case(db_new)

written_old = old_compact_rollup(db_old, max_hours=200)
written_new = db_new.compact_rollup(max_hours=200)
check("compact_rollup: same number of (metric, hour) rows written",
      written_old == written_new, (written_old, written_new))

cols = ("metric_id", "hour", "n", "vmin", "vavg", "vmax")
snap_old = snapshot(db_old, "samples_hourly", cols)
snap_new = snapshot(db_new, "samples_hourly", cols)
check("compact_rollup: samples_hourly is byte-identical to the old scan",
      snap_old == snap_new,
      f"{len(snap_old)} vs {len(snap_new)} rows"
      if len(snap_old) != len(snap_new) else "values differ")

# A second wave landing inside the redo window, then a second rollup pass on
# each -- proves the per-metric seek still re-aggregates a summarised hour
# whose samples changed after the fact, the same as the range scan did.
live_rows = [(mid, NOW - 30.0, 7.0) for mid in ids_old]
with db_old._lock:
    db_old._conn.executemany(
        "INSERT OR REPLACE INTO samples(metric_id, ts, value) VALUES (?,?,?)",
        live_rows)
    db_old._conn.commit()
with db_new._lock:
    db_new._conn.executemany(
        "INSERT OR REPLACE INTO samples(metric_id, ts, value) VALUES (?,?,?)",
        [(mid, NOW - 30.0, 7.0) for mid in ids_new])
    db_new._conn.commit()
old_compact_rollup(db_old, max_hours=200)
db_new.compact_rollup(max_hours=200)
snap_old2 = snapshot(db_old, "samples_hourly", cols)
snap_new2 = snapshot(db_new, "samples_hourly", cols)
check("compact_rollup: redo-window re-aggregation matches too",
      snap_old2 == snap_new2, (len(snap_old2), len(snap_new2)))

# EXPLAIN: the new per-hour statement seeks (metric_id=? AND ts>? AND ts<?),
# not a range scan that stops SQLite pushing ts into the seek.
band_low, band_high = ids_new[0], ids_new[-1]
rollup_plan = plan(
    db_new,
    f"SELECT s.metric_id AS metric_id, COUNT(*) AS n, MIN(s.value) AS vmin,"
    f" AVG(s.value) AS vavg, MAX(s.value) AS vmax"
    f" FROM metrics m CROSS JOIN samples s"
    f" ON s.metric_id = m.id AND s.ts >= ? AND s.ts < ? AND s.value IS NOT NULL"
    f" WHERE m.id >= ? AND m.id <= ? GROUP BY s.metric_id",
    (NOW_HOUR, NOW_HOUR + HOUR, band_low, band_high))
check("compact_rollup: EXPLAIN shows a per-metric seek, not a range scan",
      any("SEARCH s USING PRIMARY KEY (metric_id=? AND ts>? AND ts<?)" in p
          for p in rollup_plan), rollup_plan)

db_old.close()
db_new.close()


# ======================================= 2. compact_rollup, mid-rewrite union
#
# Same shape as test_series_without_rowid.py's fixture: an old-shape file,
# opened (which marks the rewrite), driven partway through identically on
# two copies, then compact_rollup run on each -- old range scan on one,
# new per-metric join on the other, over the SAME union of table/table_new.

OLD_DDL = """
CREATE TABLE metrics (
    id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL, key TEXT NOT NULL,
    label TEXT NOT NULL, unit TEXT NOT NULL, kind TEXT NOT NULL,
    last_value REAL, last_ts REAL, UNIQUE(device_id, key));
CREATE INDEX ix_metrics_key ON metrics(key);
CREATE TABLE samples (
    metric_id INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    ts REAL NOT NULL, value REAL, PRIMARY KEY (metric_id, ts));
CREATE INDEX ix_samples_ts ON samples(ts);
CREATE TABLE samples_hourly (
    metric_id INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour INTEGER NOT NULL, n INTEGER NOT NULL,
    vmin REAL, vavg REAL, vmax REAL, PRIMARY KEY (metric_id, hour));
CREATE INDEX ix_samples_hourly_hour ON samples_hourly(hour);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
"""
MID_METRICS = 16
MID_SAMPLES_EACH = 20


def build_mid_fixture(path):
    conn = sqlite3.connect(path)
    conn.executescript(OLD_DDL)
    conn.executemany(
        "INSERT INTO metrics(id, device_id, key, label, unit, kind,"
        " last_value, last_ts) VALUES (?,?,?,?,?,'gauge',?,?)",
        [(i + 1, 1 + i % 3, f"if_in_octets.{i}" if i % 2 else f"cpu_pct_{i}",
          f"metric {i}", "bps", 0.0, NOW - 60) for i in range(MID_METRICS)])
    samples = [(i + 1, NOW_HOUR - (MID_SAMPLES_EACH - s) * 300.0, float(s))
               for i in range(MID_METRICS) for s in range(MID_SAMPLES_EACH)]
    conn.executemany("INSERT INTO samples(metric_id, ts, value)"
                     " VALUES (?,?,?)", samples)
    conn.commit()
    conn.close()


mid_old_path = os.path.join(TMPDIR, "mid_old.db")
mid_new_path = os.path.join(TMPDIR, "mid_new.db")
build_mid_fixture(mid_old_path)
build_mid_fixture(mid_new_path)

mid_old = NodesSeriesDatabase(mid_old_path)
mid_new = NodesSeriesDatabase(mid_new_path)
check("mid-rewrite fixture: both copies opened into the same rewriting state",
      mid_old.rewrite_pending() and mid_new.rewrite_pending())

# Same band width, same stop count on both -- _rewrite_table is unchanged
# code, so this leaves both copies in an identical split state.
BAND = 4


class StopAfter:
    def __init__(self, n):
        self.n, self.seen = n, 0

    def is_set(self):
        self.seen += 1
        return self.seen > self.n


mid_old._rewrite_table("samples", stop=StopAfter(2), band=BAND)
mid_new._rewrite_table("samples", stop=StopAfter(2), band=BAND)
check("mid-rewrite fixture: both copies stopped at the same cursor",
      mid_old._private_setting("samples_rewrite_cursor")
      == mid_new._private_setting("samples_rewrite_cursor"),
      (mid_old._private_setting("samples_rewrite_cursor"),
       mid_new._private_setting("samples_rewrite_cursor")))

old_compact_rollup(mid_old, max_hours=200)
mid_new.compact_rollup(max_hours=200)
mid_snap_old = snapshot(mid_old, "samples_hourly", cols)
mid_snap_new = snapshot(mid_new, "samples_hourly", cols)
check("compact_rollup over the mid-rewrite union matches the old scan",
      mid_snap_old == mid_snap_new, (len(mid_snap_old), len(mid_snap_new)))

mid_old.close()
mid_new.close()


# ================================================================ 3. prune

def seed_prune_case(db, metrics=20, days=6, per_day=8):
    """Raw samples spread across `days` (well past both retention tiers) and
    rollups spread across a couple of years, so both the age-based sample
    prune and the rollup prune have real work on both tiers."""
    ids = []
    for i in range(metrics):
        key = f"cpu_pct_{i}" if i % 2 == 0 else f"if_in_bps.{i}"
        ids.append(db.record_metric_sample(
            1 + i % 4, key, key, "u", "gauge", NOW, 0.0))
    with db._lock:
        db._conn.executemany(
            "INSERT OR REPLACE INTO samples(metric_id, ts, value) VALUES (?,?,?)",
            [(mid, NOW - d * 86400 - p * 3600, float((d + p) % 30))
             for mid in ids for d in range(days) for p in range(per_day)])
        db._conn.executemany(
            "INSERT OR REPLACE INTO samples_hourly(metric_id, hour, n, vmin,"
            " vavg, vmax) VALUES (?,?,4,0,?,?)",
            [(mid, int(NOW - d * 86400), float(d % 20), float(d % 20) * 2)
             for mid in ids for d in range(0, 800, 3)])
        db._conn.commit()
    return ids


# 3a. cap should run: enough raw rows per metric to exceed a tight cap, and
# settings under which the new skip must NOT engage.
db_old = NodesSeriesDatabase(os.path.join(TMPDIR, "prune_old.db"))
db_new = NodesSeriesDatabase(os.path.join(TMPDIR, "prune_new.db"))
seed_prune_case(db_old)
seed_prune_case(db_new)

removed_old = old_prune(db_old, sample_days=3, rollup_days=400,
                        interface_sample_days=1, interface_rollup_days=90,
                        max_samples_per_metric=10)
removed_new = db_new.prune(sample_days=3, rollup_days=400,
                           interface_sample_days=1, interface_rollup_days=90,
                           max_samples_per_metric=10, poll_interval_s=1.0)
check("prune (cap binding): same total rows removed",
      removed_old == removed_new, (removed_old, removed_new))
raw_cols = ("metric_id", "ts", "value")
check("prune (cap binding): samples byte-identical",
      snapshot(db_old, "samples", raw_cols) == snapshot(db_new, "samples", raw_cols))
check("prune (cap binding): samples_hourly byte-identical",
      snapshot(db_old, "samples_hourly", cols) == snapshot(db_new, "samples_hourly", cols))
db_old.close()
db_new.close()

# EXPLAIN for the per-band DELETE the age-based passes now issue.
probe = NodesSeriesDatabase(os.path.join(TMPDIR, "prune_probe.db"))
pid = probe.record_metric_sample(1, "cpu_pct", "cpu", "u", "gauge", NOW, 0.0)
with probe._lock:
    probe._conn.execute(
        "INSERT INTO samples(metric_id, ts, value) VALUES (?,?,?)",
        (pid, NOW - 1000, 1.0))
    probe._conn.commit()
band_plan = plan(probe, f"DELETE FROM samples WHERE metric_id IN ({pid})"
                        f" AND ts < ?", (NOW,))
check("prune: EXPLAIN shows a per-metric seek on the batched DELETE",
      any("SEARCH samples USING PRIMARY KEY (metric_id=? AND ts<?)" in p
          for p in band_plan), band_plan)
probe.close()

# 3b. cap should be skipped, but ONLY when told a real interval: settings
# under which nothing could exceed the cap given retention alone, so old
# (always calls cap) and a new call that's EXPLICITLY given the interval
# (skips the call) must still land on the identical, unchanged table.
db_old = NodesSeriesDatabase(os.path.join(TMPDIR, "prune_skip_old.db"))
db_new = NodesSeriesDatabase(os.path.join(TMPDIR, "prune_skip_new.db"))
seed_prune_case(db_old, metrics=6, days=2, per_day=4)
seed_prune_case(db_new, metrics=6, days=2, per_day=4)

called = []
real_cap = NodesSeriesDatabase.cap_samples_per_metric


def spying_cap(self, *a, **kw):
    called.append((a, kw))
    return real_cap(self, *a, **kw)


NodesSeriesDatabase.cap_samples_per_metric = spying_cap
try:
    removed_old = old_prune(db_old, sample_days=3, rollup_days=400,
                            interface_sample_days=1, interface_rollup_days=90,
                            max_samples_per_metric=5000)
    called.clear()
    removed_new = db_new.prune(sample_days=3, rollup_days=400,
                               interface_sample_days=1,
                               interface_rollup_days=90,
                               max_samples_per_metric=5000,
                               poll_interval_s=120.0)
    check("prune (cap a no-op, interval given): the skip actually avoided "
          "calling cap", called == [], called)
finally:
    NodesSeriesDatabase.cap_samples_per_metric = real_cap

check("prune (cap a no-op, interval given): same total removed either way",
      removed_old == removed_new, (removed_old, removed_new))
check("prune (cap a no-op, interval given): samples byte-identical",
      snapshot(db_old, "samples", raw_cols) == snapshot(db_new, "samples", raw_cols))
check("prune (cap a no-op, interval given): samples_hourly byte-identical",
      snapshot(db_old, "samples_hourly", cols) == snapshot(db_new, "samples_hourly", cols))
db_old.close()
db_new.close()

# 3c. Same settings, but poll_interval_s omitted (None, the default): the
# skip must NOT engage -- under-enforcing the cap on a guessed interval is
# worse than the scan it would save, so None runs cap unconditionally, the
# same as old_prune always did.
db_old = NodesSeriesDatabase(os.path.join(TMPDIR, "prune_noskip_old.db"))
db_new = NodesSeriesDatabase(os.path.join(TMPDIR, "prune_noskip_new.db"))
seed_prune_case(db_old, metrics=6, days=2, per_day=4)
seed_prune_case(db_new, metrics=6, days=2, per_day=4)

NodesSeriesDatabase.cap_samples_per_metric = spying_cap
try:
    removed_old = old_prune(db_old, sample_days=3, rollup_days=400,
                            interface_sample_days=1, interface_rollup_days=90,
                            max_samples_per_metric=5000)
    called.clear()
    removed_new = db_new.prune(sample_days=3, rollup_days=400,
                               interface_sample_days=1,
                               interface_rollup_days=90,
                               max_samples_per_metric=5000)
    check("prune (poll_interval_s=None): cap still runs, not skipped",
          len(called) == 1, called)
finally:
    NodesSeriesDatabase.cap_samples_per_metric = real_cap

check("prune (poll_interval_s=None): same total removed either way",
      removed_old == removed_new, (removed_old, removed_new))
check("prune (poll_interval_s=None): samples byte-identical",
      snapshot(db_old, "samples", raw_cols) == snapshot(db_new, "samples", raw_cols))
check("prune (poll_interval_s=None): samples_hourly byte-identical",
      snapshot(db_old, "samples_hourly", cols) == snapshot(db_new, "samples_hourly", cols))
db_old.close()
db_new.close()


# ============================================================ 4. _trim_hourly
#
# Unchanged from 5.46.0 (a batched version was tried and reverted); this is
# a regression guard should someone batch it again without updating the
# oracle.
TRIM_METRICS = 40
TRIM_HOURS = 600

db_old = NodesSeriesDatabase(os.path.join(TMPDIR, "trim_old.db"))
db_new = NodesSeriesDatabase(os.path.join(TMPDIR, "trim_new.db"))
for db in (db_old, db_new):
    with db._lock:
        db._conn.executemany(
            "INSERT INTO metrics(device_id, key, label, unit, kind)"
            " VALUES (?,?,?,?,?)",
            [(1 + i % 20, f"if_in_octets.{i}", f"port {i}", "bps",
              "counter_rate") for i in range(TRIM_METRICS)])
        trim_ids = [row["id"] for row in db._conn.execute(
            "SELECT id FROM metrics ORDER BY id").fetchall()]
        db._conn.executemany(
            "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
            " VALUES (?,?,60,0.0,?,?)",
            [(mid, NOW_HOUR - h * HOUR, float(h % 40), float(h % 40) * 2)
             for h in range(TRIM_HOURS) for mid in trim_ids])
        db._conn.commit()

floor = db_old._hourly_floor()
check("trim setup: the seed is comfortably above the floor",
      TRIM_METRICS * TRIM_HOURS > floor * 2, (TRIM_METRICS * TRIM_HOURS, floor))

removed_old = old_trim_hourly(db_old, floor)
removed_new = db_new._trim_hourly(floor)
check("_trim_hourly: same number of rows removed", removed_old == removed_new,
      (removed_old, removed_new))
check("_trim_hourly: samples_hourly byte-identical to the oracle",
      snapshot(db_old, "samples_hourly", cols) == snapshot(db_new, "samples_hourly", cols))

db_old.close()
db_new.close()

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
