"""NodesDatabase.series(..., bucket_s=...) and the /series API's bucket_s
parameter: bucket boundaries, avg/min/max per bucket, the window/2 cap, and
that bucket_s=0 (or omitted) is still the plain raw-row path. No SNMP
traffic involved, so no stub agent — just the database and the API function
directly, the way test_timeout_accuracy.py exercises _poll_device directly."""
import os
import sys

from _paths import tmpdir

TMPDIR = tmpdir("series_buckets_")

from netpath.nodesdb import NodesDatabase
from netpath.web import api

nodes_db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
group_id = nodes_db.ensure_default_group()
device_id = nodes_db.add_device("127.0.0.1", name="bucket-test", group_id=group_id)
other_device_id = nodes_db.add_device("127.0.0.2", name="bucket-test-other", group_id=group_id)

# 60 samples, 10s apart, ts = 0..590, value = ts. Deterministic per-bucket
# avg/min/max fall out of that directly (a bucket of 6 points ending at
# multiples of 60 averages to its own midpoint minus 5).
metric_id = None
for i in range(60):
    ts = float(i * 10)
    metric_id = nodes_db.record_metric_sample(
        device_id, "if_in_bps.1", "if1 in_bps", "bps", "gauge", ts, ts)
assert metric_id is not None

# ------------------------------------------------------------- boundaries

# bucket_s=60 over [0, 600): 10 buckets of 6 points each (0,10,..,50 / 60,
# 70,..,110 / ...). Bucket boundaries are floor(ts/60)*60, so a point
# exactly on a boundary (ts=60) belongs to the bucket it starts, not the
# one before it.
rows = nodes_db.series(device_id, metric_id, 0, 600, bucket_s=60)
print(f"{len(rows)} bucket(s): {[(r['ts'], r['avg'], r['min'], r['max']) for r in rows]}")
assert len(rows) == 10, f"expected 10 buckets, got {len(rows)}"
assert [r["ts"] for r in rows] == [i * 60 for i in range(10)], \
    "bucket timestamps should be exact multiples of bucket_s"

# ------------------------------------------------------------- avg/min/max

first = rows[0]
assert first["min"] == 0.0 and first["max"] == 50.0, first
assert first["avg"] == sum(range(0, 60, 10)) / 6, first
assert first["n"] == 6, first

second = rows[1]
assert second["min"] == 60.0 and second["max"] == 110.0, second
assert second["avg"] == sum(range(60, 120, 10)) / 6, second

print("PASS: bucket boundaries and avg/min/max are correct")

# ------------------------------------------------------------- raw (bucket_s=0)

raw_default = nodes_db.series(device_id, metric_id, 0, 600)
raw_explicit = nodes_db.series(device_id, metric_id, 0, 600, bucket_s=0)
for raw in (raw_default, raw_explicit):
    assert len(raw) == 60, f"expected 60 raw rows, got {len(raw)}"
    assert "avg" not in raw[0] and "value" in raw[0], \
        "bucket_s=0 (or omitted) must stay the raw {ts, value} shape"
    assert raw[0] == {"ts": 0.0, "value": 0.0}, raw[0]
print("PASS: bucket_s=0 (and omitting it) still returns raw rows")

# ------------------------------------------------------------- device scoping

# Same as the un-bucketed path: a metric id that belongs to another device
# must not leak that device's data back under this one's name.
assert nodes_db.series(other_device_id, metric_id, 0, 600, bucket_s=60) == []
print("PASS: bucketed series still enforces device_id ownership of metric_id")

# --------------------------------------------------------------- API layer


class _FakeService:
    def __init__(self, db):
        self.nodes_db = db


service = _FakeService(nodes_db)

result = api.get_nodes_device_series(
    service, {"metric_id": str(metric_id), "t0": "0", "t1": "600", "bucket_s": "60"},
    None, device_id)
assert len(result["points"]) == 10, result
assert result["points"][0]["ts"] == 0
print("PASS: the API function threads bucket_s through to nodesdb.series")

# window/2 cap: ask for a bucket wider than the window itself; the API must
# clamp it to (t1-t0)/2 rather than handing sqlite a bucket bigger than the
# whole request, which would collapse everything into one point.
capped = api.get_nodes_device_series(
    service, {"metric_id": str(metric_id), "t0": "0", "t1": "600", "bucket_s": "10000"},
    None, device_id)
uncapped_equivalent = nodes_db.series(device_id, metric_id, 0, 600, bucket_s=300)
assert [r["ts"] for r in capped["points"]] == [r["ts"] for r in uncapped_equivalent], \
    (capped["points"], uncapped_equivalent)
assert len(capped["points"]) == 2, capped["points"]
print("PASS: bucket_s is capped at window/2 by the API")

# A negative bucket_s is treated the same as 0 (raw), not as an error.
negative = api.get_nodes_device_series(
    service, {"metric_id": str(metric_id), "t0": "0", "t1": "600", "bucket_s": "-5"},
    None, device_id)
assert len(negative["points"]) == 60 and "value" in negative["points"][0]
print("PASS: a negative bucket_s falls back to raw rows rather than erroring")

# --------------------------------------------------- per-metric sample cap
#
# §4.1 B1 / §4.5 F1: sample_row_cap_per_metric counted the WHOLE samples
# table, so at 2,000 devices and ~90 metrics each, 50,000 surviving rows is
# 0.29 samples per metric — every chart empty and every threshold streak
# reset — and the single DELETE of the other ~11 million rows held the
# process lock for tens of seconds. The cap is now per metric.

import sqlite3
import threading

cap_device = nodes_db.add_device("127.0.0.3", name="cap-test", group_id=group_id)
caps = {}
for key, count in (("busy", 100), ("medium", 50), ("quiet", 10)):
    for i in range(count):
        caps[key] = nodes_db.record_metric_sample(
            cap_device, key, key, "u", "gauge", float(1000 + i), float(i))


def stored(metric_id):
    return nodes_db.series(cap_device, metric_id, 0, 10_000)


removed = nodes_db.cap_samples_per_metric(40)
window_functions = sqlite3.sqlite_version_info >= (3, 25, 0)
if not window_functions:
    print(f"SKIP: SQLite {sqlite3.sqlite_version} has no window functions")
else:
    counts = {key: len(stored(metric_id)) for key, metric_id in caps.items()}
    print(f"after capping at 40: {counts}, {removed} row(s) removed")
    assert counts == {"busy": 40, "medium": 40, "quiet": 10}, counts
    # 60 from `busy`, 10 from `medium`, and 20 from the 60-sample
    # if_in_bps.1 metric this file created earlier: the cap is per metric
    # across the whole database, not per device.
    assert removed == 90, removed
    assert len(nodes_db.series(device_id, metric_id, 0, 600)) == 40
    print("PASS: the cap applies per metric, not across the whole table")

    # The newest are what survive: a cap that kept the oldest 40 would leave
    # charts showing last week and nothing since.
    kept = stored(caps["busy"])
    assert kept[0]["ts"] == 1060.0 and kept[-1]["ts"] == 1099.0, (kept[0], kept[-1])
    print("PASS: the newest samples are the ones kept")

    # Idempotent: a second pass at the same cap has nothing left to do.
    assert nodes_db.cap_samples_per_metric(40) == 0
    print("PASS: capping again removes nothing")

    # A writer must not be blocked for the length of the whole pass. With
    # 600 metrics the cap runs several chunks, releasing the lock between
    # them; a writer on another thread gets in while it runs.
    for i in range(600):
        for j in range(3):
            nodes_db.record_metric_sample(
                cap_device, f"bulk.{i}", "bulk", "u", "gauge", float(j), float(j))
    interleaved = []

    def writer():
        for i in range(20):
            nodes_db.record_metric_sample(
                cap_device, "concurrent", "concurrent", "u", "gauge",
                float(i), float(i))
            interleaved.append(i)

    thread = threading.Thread(target=writer)
    thread.start()
    nodes_db.cap_samples_per_metric(1, chunk=50)
    thread.join(timeout=30)
    assert not thread.is_alive(), "a writer was blocked for the whole cap pass"
    assert len(interleaved) == 20, interleaved
    print("PASS: a concurrent writer runs while the cap pass is chunking")

# -------------------------------------------------------- hourly rollups
#
# §4.1 B2 / §4.5 F2: compact_rollup() was never called, so samples_hourly
# was always empty and any chart window over three days returned nothing —
# while the storage document promised rollups. And when it was called it
# deleted every raw sample older than an hour, which would have emptied the
# raw window a short chart reads.

import time as _time

roll_db = NodesDatabase(os.path.join(TMPDIR, "rollup.db"))
roll_group = roll_db.ensure_default_group()
roll_device = roll_db.add_device("127.0.0.4", name="rollup-test",
                                 group_id=roll_group)

# Five days of samples, six per hour, ending an hour ago so every hour in
# the range is complete. Value = the hour index, so each hour's min/avg/max
# is exactly that index and a wrong bucket is obvious.
HOUR = 3600
now_hour = int(_time.time() // HOUR) * HOUR
first_hour = now_hour - 5 * 24 * HOUR
roll_metric = None
for h in range(5 * 24):
    hour_start = first_hour + h * HOUR
    for step in range(6):
        roll_metric = roll_db.record_metric_sample(
            roll_device, "cpu_pct", "CPU", "%", "gauge",
            float(hour_start + step * 600), float(h))

def raw_count(db, metric_id):
    with db._lock:
        return db._conn.execute(
            "SELECT COUNT(*) AS n FROM samples WHERE metric_id = ?",
            (metric_id,)).fetchone()["n"]


raw_before = raw_count(roll_db, roll_metric)
# A pass is bounded (max_hours) so a long backlog never stalls maintenance
# in one go; the watermark makes the next pass continue where it stopped.
passes = 0
written = 0
watermark = None
while passes < 10:
    written += roll_db.compact_rollup()
    passes += 1
    moved = roll_db._private_setting(roll_db._ROLLUP_WATERMARK)
    if moved == watermark:
        break                 # caught up: the watermark stopped advancing
    watermark = moved
print(f"rollup wrote {written} metric-hour(s) over {passes} pass(es) from "
      f"{raw_before} raw sample(s)")
assert passes > 1, "a 5-day backlog should take more than one bounded pass"
assert written >= 5 * 24 - 1, written

with roll_db._lock:
    hourly = roll_db._conn.execute(
        "SELECT hour, n, vmin, vavg, vmax FROM samples_hourly"
        " WHERE metric_id = ? ORDER BY hour", (roll_metric,)).fetchall()
assert len(hourly) >= 5 * 24 - 1, len(hourly)
assert all(row["n"] == 6 for row in hourly), \
    [row["n"] for row in hourly if row["n"] != 6]
sample_hour = hourly[10]
expected = (sample_hour["hour"] - first_hour) / HOUR
assert sample_hour["vmin"] == sample_hour["vmax"] == expected, dict(sample_hour)
print("PASS: every complete hour is summarised as n=6 with the right min/avg/max")

raw_after = raw_count(roll_db, roll_metric)
assert raw_after == raw_before, (raw_before, raw_after)
print("PASS: the rollup leaves the raw samples alone")

# A second pass re-does only the two-hour overlap, and writes nothing new.
before_rows = len(hourly)
written_again = roll_db.compact_rollup()
with roll_db._lock:
    after_rows = roll_db._conn.execute(
        "SELECT COUNT(*) AS n FROM samples_hourly WHERE metric_id = ?",
        (roll_metric,)).fetchone()["n"]
assert after_rows == before_rows, (before_rows, after_rows)
assert written_again <= 3, written_again
print(f"PASS: a second rollup pass adds no rows (re-did {written_again} hour(s) "
      f"for late samples)")

# A five-day window reads the hourly table; a one-day window reads raw.
wide = roll_db.series(roll_device, roll_metric, first_hour, now_hour)
assert len(wide) >= 5 * 24 - 1, len(wide)
assert "n" in wide[0] and "avg" in wide[0], wide[0]
narrow = roll_db.series(roll_device, roll_metric, now_hour - 23 * HOUR, now_hour)
assert narrow and "value" in narrow[0], narrow[:1]
print("PASS: a 5-day window reads hourly rollups, a 1-day window reads raw")

# prune acts on the right table: raw by sample_days, rollups by rollup_days.
roll_db.prune(sample_days=2, rollup_days=400, event_days=999,
              discovery_days=999)
with roll_db._lock:
    oldest_left = roll_db._conn.execute(
        "SELECT MIN(ts) AS t, COUNT(*) AS n FROM samples WHERE metric_id = ?",
        (roll_metric,)).fetchone()
assert oldest_left["n"], "pruning raw samples must not empty the table"
assert oldest_left["t"] >= _time.time() - 2 * 86400 - HOUR, dict(oldest_left)
with roll_db._lock:
    still_hourly = roll_db._conn.execute(
        "SELECT COUNT(*) AS n FROM samples_hourly").fetchone()["n"]
assert still_hourly == after_rows, (still_hourly, after_rows)
print("PASS: pruning raw samples by age leaves the rollups untouched")

roll_db.prune(sample_days=999, rollup_days=1, event_days=999, discovery_days=999)
with roll_db._lock:
    left = roll_db._conn.execute(
        "SELECT COUNT(*) AS n FROM samples_hourly").fetchone()["n"]
assert 0 < left < after_rows, (left, after_rows)
print(f"PASS: rollup_days prunes samples_hourly ({after_rows} -> {left} rows)")

roll_db.close()

# ------------------------------------------------- space, without a VACUUM
#
# §4.5 F5: trim_to_size ran VACUUM inside the module lock up to six times —
# 6.49 s per VACUUM at 2 million rows, a 38.9 s stall for the whole call,
# during which every poll worker, the alert tick and every HTTP handler
# waited on the same lock. dbmaint frees pages in short steps instead.

trim_path = os.path.join(TMPDIR, "trim.db")
trim_db = NodesDatabase(trim_path)
with trim_db._lock:
    mode = trim_db._conn.execute("PRAGMA auto_vacuum").fetchone()[0]
assert mode == 2, f"a fresh nodes.db should be in incremental auto-vacuum, got {mode}"
print("PASS: a fresh database opens in incremental auto-vacuum mode")

trim_group = trim_db.ensure_default_group()
trim_device = trim_db.add_device("127.0.0.5", name="trim-test", group_id=trim_group)
# 300 metrics x 60 timestamps: one batched write per timestamp, the shape
# a poll actually produces. record_metric_samples keeps one row per key, so
# the timestamps have to come from separate calls.
for t in range(60):
    trim_db.record_metric_samples(
        trim_device,
        [(f"bulk.{j}", "bulk", "u", "gauge", float(t), float(t * j))
         for j in range(300)])
with trim_db._lock:
    trim_db._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
before_bytes = os.path.getsize(trim_path)

# Deliberately below the current size, so the trim loop actually runs.
blocked = []


def poll_writer(db, stop):
    """A poll worker's write path, timed. Nothing it does should ever wait
    more than a fraction of a second on the trim."""
    while not stop.is_set():
        started = _time.monotonic()
        db.record_metric_samples(
            trim_device, [("concurrent", "concurrent", "u", "gauge",
                           _time.time(), 1.0)])
        blocked.append(_time.monotonic() - started)
        _time.sleep(0.005)


stop = threading.Event()
writer_thread = threading.Thread(target=poll_writer, args=(trim_db, stop))
writer_thread.start()
trim_removed = trim_db.trim_to_size(before_bytes // 2)
stop.set()
writer_thread.join(timeout=10)
assert not writer_thread.is_alive(), "the writer thread never finished"

with trim_db._lock:
    trim_db._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
after_bytes = os.path.getsize(trim_path)
print(f"trim removed {trim_removed} sample(s); file {before_bytes:,} -> "
      f"{after_bytes:,} bytes; {len(blocked)} writes, worst wait "
      f"{max(blocked or [0]):.3f}s")
assert trim_removed > 0, "the trim removed nothing"
assert after_bytes < before_bytes, (before_bytes, after_bytes)
print("PASS: the file shrinks without a VACUUM")
assert blocked, "the writer never ran"
assert max(blocked) < 0.5, f"a writer waited {max(blocked):.2f}s during the trim"
print("PASS: a writer is never blocked for more than a step of the reclaim")

trim_db.close()

nodes_db.close()
# --- starting the application must not wait for a whole-file rewrite
# 4.38 moved every database to incremental auto-vacuum. Converting an
# existing one is a VACUUM, and doing that for ten databases while the
# operator waits for the window took 26 seconds on 840 MB of real data.
# The conversion belongs to maintenance, not to startup.
import tempfile as _tempfile, threading as _threading, time as _time
from netpath import dbopen as _dbopen, dbmaint as _dbmaint

_dir = _tempfile.mkdtemp()
_path = os.path.join(_dir, "startup.db")
_c = _dbopen.connect(_path)
_c.execute("CREATE TABLE bulk(a blob)")
_c.executemany("INSERT INTO bulk VALUES (?)", [(b"z" * 4000,)] * 6000)
_c.commit()
_pages = _c.execute("PRAGMA page_count").fetchone()[0]
assert _pages > _dbmaint.CONVERT_AT_OPEN_PAGES, _pages
_c.close()

_c = _dbopen.connect(_path)
_started = _time.monotonic()
_converted = _dbmaint.enable_incremental_vacuum(_c, "startup")
_elapsed = _time.monotonic() - _started
assert _converted is False, "a large database must not be converted at open"
assert _elapsed < 0.25, f"the open path took {_elapsed:.2f}s"
assert _c.execute("PRAGMA auto_vacuum").fetchone()[0] != 2
print(f"a large database is not converted while the app is starting "
      f"({_elapsed*1000:.0f} ms) OK")

# Maintenance does the conversion, and then reclaims.
_c.execute("DELETE FROM bulk"); _c.commit()
_before = os.path.getsize(_path)
_dbmaint.reclaim(_c, _threading.RLock(), label="startup")
assert _c.execute("PRAGMA auto_vacuum").fetchone()[0] == 2, \
    "maintenance must convert what the open path deferred"
assert os.path.getsize(_path) < _before / 2, (_before, os.path.getsize(_path))
print("maintenance converts it and reclaims the space OK")

# And a database already in incremental mode costs nothing to reopen.
_c.close()
_c = _dbopen.connect(_path)
_started = _time.monotonic()
assert _dbmaint.enable_incremental_vacuum(_c, "startup") is True
assert _time.monotonic() - _started < 0.25
print("an already-converted database reopens without a rewrite OK")
_c.close()

print("ALL SERIES-BUCKET ASSERTIONS PASSED")
