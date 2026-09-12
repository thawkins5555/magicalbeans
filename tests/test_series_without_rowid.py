"""The rewrite of nodes_series.db's tables into their WITHOUT ROWID shape.

An old-shape file is built by hand -- the pre-rewrite DDL below, rowid
tables with a secondary index on the timestamp column -- then opened with
the current code and driven through the band-by-band rewrite: interrupted
mid-way with a stop event, reopened, resumed, finished.

tests/test_nodes_split_upgrade.py is the model. What it proves about the
5.0.0 split, this proves about the rewrite: the cursor commits with the
rows it covers, so an interrupted run resumes rather than repeats; every
key survives; the reads answer from the union of both halves while the
split is in flight; and -- the property a copy-then-swap would fail -- the
file never holds two copies, so page_count never climbs past the old file
plus one band in flight.
"""
import os
import sqlite3
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesseriesdb import NodesSeriesDatabase

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


HOUR = 3600
NOW = 1_760_000_000.0
NOW_HOUR = int(NOW // HOUR) * HOUR
METRICS = 120
SAMPLES_EACH = 40
HOURS_EACH = 24
BAND = 8            # metric ids per band, small enough to interrupt

# The shape every install before this change has: both tables rowid tables,
# each with a secondary index on its time column.
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


def build_old(path):
    """An old-shape nodes_series.db, and the keys it holds."""
    conn = sqlite3.connect(path)
    conn.executescript(OLD_DDL)
    conn.executemany(
        "INSERT INTO metrics(id, device_id, key, label, unit, kind,"
        " last_value, last_ts) VALUES (?,?,?,?,?,'gauge',?,?)",
        [(i + 1, 1 + i % 4,
          f"if_in_octets.{i}" if i % 2 else f"cpu_pct_{i}",
          f"metric {i}", "bps", float(i), NOW - 60)
         for i in range(METRICS)])
    ids = [row[0] for row in conn.execute("SELECT id FROM metrics ORDER BY id")]
    # Ascending ts per metric, so both halves of a split table hold a
    # genuine ordering and series() has something to merge wrongly.
    samples = [(mid, NOW - (SAMPLES_EACH - s) * 60.0 + 0.137, float(s * 3))
               for mid in ids for s in range(SAMPLES_EACH)]
    conn.executemany("INSERT INTO samples(metric_id, ts, value)"
                     " VALUES (?,?,?)", samples)
    rollups = [(mid, NOW_HOUR - (h + 1) * HOUR, 60, 1.0, float(h), float(h) * 2)
               for mid in ids for h in range(HOURS_EACH)]
    conn.executemany(
        "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
        " VALUES (?,?,?,?,?,?)", rollups)
    conn.commit()
    pages = conn.execute("PRAGMA page_count").fetchone()[0]
    conn.close()
    return ids, {(m, t) for m, t, _v in samples}, \
        {(m, h) for m, h, *_ in rollups}, pages


def table_sql(db, table):
    row = db._conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone()
    return "" if row is None else (row["sql"] or "")


def index_names(db):
    return {row[0] for row in db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'"
        " AND name NOT LIKE 'sqlite_%'")}


def keys(db, sql):
    with db._lock:
        return {tuple(row) for row in db._conn.execute(sql).fetchall()}


def pages(db):
    with db._lock:
        return db._conn.execute("PRAGMA page_count").fetchone()[0]


work = _paths.tmpdir("series_without_rowid_")
path = os.path.join(work, "nodes_series.db")
metric_ids, raw_keys, hourly_keys, pages_before = build_old(path)

conn = sqlite3.connect(path)
fixture = conn.execute(
    "SELECT sql FROM sqlite_master WHERE name='samples'").fetchone()[0]
conn.close()
check("the fixture really is the old rowid shape",
      "WITHOUT ROWID" not in fixture.upper(), fixture)
print(f"      fixture: {len(raw_keys):,} samples, {len(hourly_keys):,} "
      f"rollups, {pages_before:,} pages")


# ------------------------------------------------- opening marks the rewrite

db = NodesSeriesDatabase(path)
check("opening an old-shape file marks the rewrite rather than doing it on "
      "the open thread", db.rewrite_pending() is True
      and db._private_setting("samples_rewrite_state") == "rewriting",
      db._private_setting("samples_rewrite_state"))
check("...and creates the new table beside the old one, empty",
      "WITHOUT ROWID" in table_sql(db, "samples_new").upper()
      and keys(db, "SELECT COUNT(*) FROM samples_new") == {(0,)},
      table_sql(db, "samples_new"))
check("scope was still backfilled from the stored keys",
      keys(db, "SELECT COUNT(*) FROM metrics WHERE scope = 1")
      == {(METRICS // 2,)},
      keys(db, "SELECT COUNT(*) FROM metrics WHERE scope = 1"))

# A sample written after the freeze: the live tail the poller keeps adding
# while the bands run, which only the final transaction can catch up.
live_ts = NOW + 10.0
db.record_metric_samples(1 + 0 % 4, [("cpu_pct_0", "metric 0", "bps",
                                      "gauge", live_ts, 7.5)])
raw_keys.add((metric_ids[0], live_ts))


# ----------------------------------------- interrupted, and the file's size

class StopAfter:
    """A stop flag that lets `n` bands through, recording the file's page
    count each time it is asked -- the hook for proving the file never holds
    two copies of the table."""

    def __init__(self, n):
        self.n = n
        self.seen = 0
        self.pages = []

    def is_set(self):
        self.pages.append(pages(db))
        self.seen += 1
        return self.seen > self.n


stop = StopAfter(4)
finished = db._rewrite_table("samples", stop=stop, band=BAND)
cursor = int(db._private_setting("samples_rewrite_cursor"))
check("a stop between bands leaves the rewrite unfinished and the cursor "
      "part way through", finished is False and 0 < cursor < METRICS + 1,
      (finished, cursor))
check("...with the bands it did copy in the new table and gone from the old",
      keys(db, "SELECT COUNT(*) FROM samples_new") != {(0,)}
      and keys(db, "SELECT COUNT(*) FROM samples WHERE metric_id < %d"
                   % cursor) == {(0,)},
      (keys(db, "SELECT COUNT(*) FROM samples_new"),
       keys(db, "SELECT COUNT(*) FROM samples WHERE metric_id < %d" % cursor)))

old_half = keys(db, "SELECT metric_id, ts FROM samples")
new_half = keys(db, "SELECT metric_id, ts FROM samples_new")
check("nothing was lost or duplicated across the split -- the two halves "
      "are disjoint and together they are the whole table",
      old_half | new_half == raw_keys and not (old_half & new_half),
      (len(old_half), len(new_half), len(raw_keys)))


# ---------------------------------------- the reads answer from both halves
#
# Metric i+1 belongs to device 1 + i % 4, per build_old. The window stays
# inside the per-port raw boundary (one day), so both reads are raw reads --
# a wider one on a dotted key would read the rollups, per the retention tiers.
FIRST_DEVICE = 1
LAST_DEVICE = 1 + (METRICS - 1) % 4

series_split = db.series(FIRST_DEVICE, metric_ids[0], NOW - 3600, NOW + 60)
check("series() answers a metric already moved to the new table",
      len(series_split) == SAMPLES_EACH + 1, len(series_split))
# metric_ids is 1..METRICS and the cursor is part way up it, so the last
# metric is certainly still in the old table.
series_old = db.series(LAST_DEVICE, metric_ids[-1], NOW - 3600, NOW + 60)
check("...and one still in the old table, over the same union",
      len(series_old) == SAMPLES_EACH, len(series_old))
bucketed = db.series(FIRST_DEVICE, metric_ids[0], NOW - 3600, NOW + 60,
                     bucket_s=600)
check("...and the bucketed form reads the union too",
      bucketed and sum(row["n"] for row in bucketed) == SAMPLES_EACH + 1,
      bucketed[:2])

rolled = db.compact_rollup(max_hours=4)
check("compact_rollup reads the union while the split is in flight, so an "
      "hour whose samples have moved is still summarised", rolled > 0, rolled)

report = db.rewrite_progress()
check("the progress the storage report shows is the band cursor",
      report.get("samples") == (cursor, METRICS + 1), report)


# ------------------------------------------------ a restart resumes

db.close()
db = NodesSeriesDatabase(path)
check("the cursor survives a reopen -- the rewrite resumes rather than "
      "repeats", int(db._private_setting("samples_rewrite_cursor")) == cursor
      and db.rewrite_pending() is True,
      db._private_setting("samples_rewrite_cursor"))
check("...and the reopen did not reset the new table",
      keys(db, "SELECT COUNT(*) FROM samples_new") != {(0,)})

stop2 = StopAfter(10_000)
check("the rest of the rewrite finishes",
      db._rewrite_table("samples", stop=stop2, band=BAND) is True)


# ----------------------------------------------------- the finished shape

check("samples reports WITHOUT ROWID",
      "WITHOUT ROWID" in table_sql(db, "samples").upper(),
      table_sql(db, "samples"))
check("...the old table is gone, not left beside it",
      table_sql(db, "samples_new") == "")
check("...and the index on ts went with it, which is most of the saving",
      "ix_samples_ts" not in index_names(db), sorted(index_names(db)))
check("every (metric_id, ts) survived, the live tail past the freeze "
      "included",
      keys(db, "SELECT metric_id, ts FROM samples") == raw_keys,
      len(keys(db, "SELECT metric_id, ts FROM samples") ^ raw_keys))
check("the values came with them",
      keys(db, "SELECT value FROM samples WHERE metric_id = 1 AND ts = %r"
               % live_ts) == {(7.5,)})
check("the rollups were not touched by the raw table's rewrite",
      keys(db, "SELECT metric_id, hour FROM samples_hourly") >= hourly_keys)
check("the marker reads 'done' and the bookkeeping rows are gone",
      db._private_setting("samples_rewrite_state") == "done"
      and db._private_setting("samples_rewrite_cursor") is None,
      (db._private_setting("samples_rewrite_state"),
       db._private_setting("samples_rewrite_cursor")))
check("rewrite_pending() is False, so nothing starts a thread for it again",
      db.rewrite_pending() is False)

worst = max(stop.pages + stop2.pages)
# One band of this fixture is 8 metrics of 40 samples; a copy-then-swap
# would have to reach 2x the table's pages, which is the number this bounds
# well away from.
check(f"the file never held two copies: page_count peaked at {worst:,} "
      f"against {pages_before:,} before, never past one band in flight",
      worst <= pages_before + 32, (worst, pages_before))
check("...and ended smaller than it started, the whole point of the change",
      pages(db) < pages_before, (pages(db), pages_before))
print(f"      pages: {pages_before:,} before, peak {worst:,}, "
      f"{pages(db):,} after")

series_after = db.series(FIRST_DEVICE, metric_ids[0], NOW - 3600, NOW + 60)
check("series() reads the finished table unchanged",
      len(series_after) == SAMPLES_EACH + 1, len(series_after))
db.close()


# ------------------------------------------------- a fresh file is born new

fresh_dir = _paths.tmpdir("series_without_rowid_fresh_")
fresh = NodesSeriesDatabase(os.path.join(fresh_dir, "nodes_series.db"))
check("a fresh store creates samples WITHOUT ROWID and never marks a "
      "rewrite", "WITHOUT ROWID" in table_sql(fresh, "samples").upper()
      and fresh.rewrite_pending() is False
      and fresh._private_setting("samples_rewrite_state") is None,
      fresh._private_setting("samples_rewrite_state"))
check("...and no index on ts", "ix_samples_ts" not in index_names(fresh))
fresh.record_metric_sample(1, "cpu_pct", "CPU", "%", "gauge", NOW, 3.0)
check("...and records and reads a sample through it",
      len(fresh.series(1, 1, NOW - 60, NOW + 60)) == 1)
fresh.close()

reopened = NodesSeriesDatabase(path)
check("reopening a finished rewrite is a no-op",
      reopened.rewrite_pending() is False
      and "WITHOUT ROWID" in table_sql(reopened, "samples").upper())
check("...and continue_rewrite() has nothing to do",
      reopened.continue_rewrite() is True)
reopened.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
