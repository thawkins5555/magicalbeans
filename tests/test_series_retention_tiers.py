"""Retention tiering by metric class: per-port metrics keep a shorter raw
and rollup history than device-level ones, and series() picks its source
from the metric's own tier rather than from one module-wide constant.

Direct database calls, no SNMP stub, the shape test_series_buckets.py uses.

The two defects pinned here are the discriminator and the coupling.
`key LIKE 'if_%'` would have put `if_in_error_rate` -- a bare, device-level
worst-port metric an alert rule reads -- on the short retention, and missed
the per-port `sfp_*` families; the test is the dot. And a boundary fixed at
three days would have had a two-day window on a per-port metric read
`samples` and find one day in it.
"""
import os
import time

from _paths import tmpdir

TMPDIR = tmpdir("series_retention_tiers_")

from netpath.nodesdb import NodesDatabase
from netpath import nodesseriesdb

DAY = 86400
HOUR = 3600

nodes_db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
series_db = nodes_db.series_db
group_id = nodes_db.ensure_default_group()
device_id = nodes_db.add_device("127.0.0.1", name="tier-test", group_id=group_id)

# ------------------------------------------------------- the discriminator

NOW = time.time()
KEYS = {
    "cpu_pct": nodesseriesdb.SCOPE_DEVICE,
    # Bare: nodepoll writes six device-level worst-port summaries under the
    # same `if_` prefix a per-port key uses.
    "if_in_error_rate": nodesseriesdb.SCOPE_DEVICE,
    "if_in_err.3": nodesseriesdb.SCOPE_INTERFACE,
    "if_in_bps.1": nodesseriesdb.SCOPE_INTERFACE,
    "sfp_rx_dbm.7": nodesseriesdb.SCOPE_INTERFACE,
}
metric_ids = {}
for key, _scope in KEYS.items():
    metric_ids[key] = nodes_db.record_metric_sample(
        device_id, key, key, "u", "gauge", NOW, 1.0)


def scope_of(key):
    with series_db._lock:
        return series_db._conn.execute(
            "SELECT scope FROM metrics WHERE id = ?",
            (metric_ids[key],)).fetchone()["scope"]


for key, expected in KEYS.items():
    got = scope_of(key)
    assert got == expected, f"{key}: scope {got}, expected {expected}"
print("PASS: the dot is the discriminator, not the if_ prefix "
      "(if_in_error_rate is device-level, if_in_err.3 is not)")

# A metric's class is written at creation and not touched again, the same
# contract `kind` has.
nodes_db.record_metric_sample(
    device_id, "if_in_err.3", "renamed", "u", "counter_rate", NOW + 1, 2.0)
assert scope_of("if_in_err.3") == nodesseriesdb.SCOPE_INTERFACE
print("PASS: a later poll does not move a metric between tiers")

# ------------------------------------------------------------ the migration

# The pre-tiering shape: metrics with no `scope` column at all. _migrate
# has to add it and backfill from the keys already stored.
legacy_path = os.path.join(TMPDIR, "legacy_series.db")
import sqlite3

legacy = sqlite3.connect(legacy_path)
legacy.executescript("""
CREATE TABLE metrics (
    id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL, key TEXT NOT NULL,
    label TEXT NOT NULL, unit TEXT NOT NULL, kind TEXT NOT NULL,
    last_value REAL, last_ts REAL, UNIQUE(device_id, key));
CREATE TABLE samples (
    metric_id INTEGER NOT NULL, ts REAL NOT NULL, value REAL,
    PRIMARY KEY (metric_id, ts));
CREATE TABLE samples_hourly (
    metric_id INTEGER NOT NULL, hour INTEGER NOT NULL, n INTEGER NOT NULL,
    vmin REAL, vavg REAL, vmax REAL, PRIMARY KEY (metric_id, hour));
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
""")
legacy.executemany(
    "INSERT INTO metrics(id, device_id, key, label, unit, kind)"
    " VALUES (?,1,?,?,'u','gauge')",
    [(1, "cpu_pct", "CPU"), (2, "if_in_error_rate", "worst in errors"),
     (3, "if_out_bps.12", "port 12 out")])
legacy.commit()
legacy.close()

upgraded = nodesseriesdb.NodesSeriesDatabase(legacy_path)
with upgraded._lock:
    backfilled = {row["key"]: row["scope"] for row in upgraded._conn.execute(
        "SELECT key, scope FROM metrics").fetchall()}
upgraded.close()
assert backfilled == {"cpu_pct": 0, "if_in_error_rate": 0,
                      "if_out_bps.12": 1}, backfilled
print("PASS: _migrate adds scope and backfills it from the stored keys")

# ------------------------------------------------------------ prune tiering

# Four days of raw and of rollups, one row an hour, for one bare metric and
# one dotted one. Every age is exactly NOW - n*HOUR, so what survives a
# cutoff is arithmetic.
prune_db = NodesDatabase(os.path.join(TMPDIR, "prune.db"))
prune_series = prune_db.series_db
prune_group = prune_db.ensure_default_group()
prune_device = prune_db.add_device("127.0.0.2", name="prune-test",
                                   group_id=prune_group)
HOURS = 4 * 24
ids = {}
for key in ("cpu_pct", "if_in_bps.4"):
    ids[key] = prune_db.record_metric_sample(
        prune_device, key, key, "u", "gauge", NOW, 0.0)
with prune_series._lock:
    for key, metric_id in ids.items():
        prune_series._conn.executemany(
            "INSERT OR REPLACE INTO samples(metric_id, ts, value) VALUES (?,?,?)",
            [(metric_id, NOW - h * HOUR, float(h)) for h in range(HOURS)])
        prune_series._conn.executemany(
            "INSERT OR REPLACE INTO samples_hourly(metric_id, hour, n, vmin,"
            " vavg, vmax) VALUES (?,?,6,0,?,?)",
            [(metric_id, int(NOW - h * HOUR), float(h), float(h))
             for h in range(HOURS)])
    prune_series._conn.commit()


def counts(table, column):
    with prune_series._lock:
        rows = prune_series._conn.execute(
            f"SELECT metric_id, COUNT(*) AS n, MIN({column}) AS oldest"
            f" FROM {table} GROUP BY metric_id").fetchall()
    return {row["metric_id"]: (row["n"], row["oldest"]) for row in rows}


before_raw = counts("samples", "ts")
assert all(n == HOURS for n, _oldest in before_raw.values()), before_raw

prune_db.prune(sample_days=3, rollup_days=400,
               interface_sample_days=1, interface_rollup_days=2,
               event_days=999, discovery_days=999)

raw = counts("samples", "ts")
device_raw, port_raw = raw[ids["cpu_pct"]], raw[ids["if_in_bps.4"]]
# The row whose age is exactly the retention is already past the cutoff by
# the time prune reads the clock, so each tier keeps its own span of hours.
assert device_raw[0] == 3 * 24, device_raw
assert port_raw[0] == 1 * 24, port_raw
assert device_raw[1] >= NOW - 3 * DAY, device_raw
assert port_raw[1] >= NOW - 1 * DAY, port_raw
print(f"PASS: raw prunes per tier -- device-level kept {device_raw[0]} rows, "
      f"per-port kept {port_raw[0]} of {HOURS}")

hourly = counts("samples_hourly", "hour")
device_hourly = hourly[ids["cpu_pct"]]
port_hourly = hourly[ids["if_in_bps.4"]]
assert device_hourly[0] == HOURS, device_hourly
assert port_hourly[0] == 2 * 24, port_hourly
print(f"PASS: rollups prune per tier too -- device-level untouched at "
      f"{device_hourly[0]}, per-port down to {port_hourly[0]}")

# The unfiltered pass is not tier-aware, and must not be: a device-level
# cutoff shorter than the per-port one still takes the per-port rows.
prune_db.prune(sample_days=0.25, rollup_days=1,
               interface_sample_days=999, interface_rollup_days=999,
               event_days=999, discovery_days=999)
raw = counts("samples", "ts")
assert raw[ids["cpu_pct"]][0] <= 7, raw
assert raw[ids["if_in_bps.4"]][0] <= 7, raw
print("PASS: the long cutoff is unfiltered -- it takes both tiers")

prune_db.close()

# -------------------------------------------------- series() source choice

# A per-port metric with four days of raw and four days of rollups: nothing
# is missing from either table, so the only thing deciding the answer's
# shape is which source series() chose.
pick_db = NodesDatabase(os.path.join(TMPDIR, "pick.db"))
pick_series = pick_db.series_db
pick_group = pick_db.ensure_default_group()
pick_device = pick_db.add_device("127.0.0.3", name="pick-test",
                                 group_id=pick_group)
pick = {}
for key in ("cpu_pct", "if_in_bps.9"):
    pick[key] = pick_db.record_metric_sample(
        pick_device, key, key, "u", "gauge", NOW, 0.0)
with pick_series._lock:
    for metric_id in pick.values():
        pick_series._conn.executemany(
            "INSERT OR REPLACE INTO samples(metric_id, ts, value) VALUES (?,?,?)",
            [(metric_id, NOW - h * HOUR, float(h)) for h in range(HOURS)])
        pick_series._conn.executemany(
            "INSERT OR REPLACE INTO samples_hourly(metric_id, hour, n, vmin,"
            " vavg, vmax) VALUES (?,?,6,0,?,?)",
            [(metric_id, int(NOW - h * HOUR), float(h), float(h))
             for h in range(HOURS)])
    pick_series._conn.commit()


def shape(metric_id, days):
    rows = pick_db.series(pick_device, metric_id, NOW - days * DAY, NOW)
    assert rows, (metric_id, days)
    return "hourly" if "avg" in rows[0] else "raw", len(rows)


assert shape(pick["if_in_bps.9"], 0.5) == ("raw", 13), \
    shape(pick["if_in_bps.9"], 0.5)
print("PASS: a half-day window on a per-port metric reads raw")

two_day_port = shape(pick["if_in_bps.9"], 2)
assert two_day_port[0] == "hourly", two_day_port
# 48 hours of rollups, plus the hour on the window's own edge when the
# integer hour key has not been truncated below it.
assert two_day_port[1] in (2 * 24, 2 * 24 + 1), two_day_port
print(f"PASS: a two-day window on a per-port metric reads hourly "
      f"({two_day_port[1]} rows), not a truncated raw series")

two_day_device = shape(pick["cpu_pct"], 2)
assert two_day_device[0] == "raw", two_day_device
print("PASS: the same two-day window on a device-level metric still reads raw")

assert shape(pick["cpu_pct"], 4)[0] == "hourly", shape(pick["cpu_pct"], 4)
print("PASS: a four-day window on a device-level metric reads hourly")

# The boundary a caller can ask for is the one series() uses, so nothing
# mirroring the choice has to hold a second copy of it.
assert pick_series.raw_window_s(pick_device, pick["cpu_pct"]) \
    == nodesseriesdb.RAW_WINDOW_S
assert pick_series.raw_window_s(pick_device, pick["if_in_bps.9"]) \
    == nodesseriesdb.INTERFACE_RAW_WINDOW_S
assert nodesseriesdb.INTERFACE_RAW_WINDOW_S < nodesseriesdb.RAW_WINDOW_S
# A metric this device does not own has no raw window at all, which is what
# nodesdb.series reads as "nothing to merge".
assert pick_series.raw_window_s(pick_device + 99, pick["cpu_pct"]) == 0.0
assert pick_db.series(pick_device + 99, pick["cpu_pct"], NOW - DAY, NOW) == []
print("PASS: raw_window_s reports the same boundary per tier, and 0 for a "
      "metric the device does not own")

pick_db.close()

# --------------------------------------------------------------- settings

from netpath import nodesdb as nodesdb_module

for key, expected in (("interface_sample_retention_days", 1),
                      ("interface_rollup_retention_days", 90),
                      ("sample_retention_days", 3),
                      ("rollup_retention_days", 400)):
    assert nodesdb_module.DEFAULTS[key] == expected, (key, expected)
    assert isinstance(nodesdb_module.DEFAULTS[key], int), key
loaded = nodes_db.settings()
assert loaded["interface_sample_retention_days"] == 1
assert loaded["interface_rollup_retention_days"] == 90
print("PASS: both tiers have int defaults and reach settings()")

nodes_db.close()

print("ALL SERIES RETENTION TIER ASSERTIONS PASSED")
