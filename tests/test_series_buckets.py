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

nodes_db.close()
print("ALL SERIES-BUCKET ASSERTIONS PASSED")
