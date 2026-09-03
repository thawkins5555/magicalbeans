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

nodes_db.close()
print("ALL SERIES-BUCKET ASSERTIONS PASSED")
