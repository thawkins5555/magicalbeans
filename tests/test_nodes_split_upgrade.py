"""The 5.0.0 split of nodes.db into nodes.db + nodes_series.db + nodes_mibs.db.

A pre-split nodes.db is built by hand (the legacy DDL below, including the
two `REFERENCES mib_files(id) ON DELETE SET NULL` columns that make the
migration a table rebuild rather than a copy), then opened with the current
code and driven through all three phases: the synchronous phase 1, the
resumable background phase 2, and the phase 3 that drops the old tables and
reclaims the file.
"""
import os
import sqlite3
import threading
import time

from _paths import tmpdir

from netpath.nodesdb import NodesDatabase

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


HOUR = 3600
NOW = time.time()
NOW_HOUR = int(NOW // HOUR) * HOUR

# The 4.54 shape of the five tables that move, plus the two columns whose
# foreign key is the whole reason phase 1 rebuilds `devices` and `groups`.
LEGACY_DDL = """
CREATE TABLE mib_files (
    id INTEGER PRIMARY KEY, filename TEXT NOT NULL, module TEXT,
    uploaded_ts REAL NOT NULL, object_count INTEGER NOT NULL DEFAULT 0,
    unresolved TEXT NOT NULL DEFAULT '[]', parse_notes TEXT, content TEXT);
CREATE TABLE mib_objects (
    id INTEGER PRIMARY KEY,
    mib_file_id INTEGER REFERENCES mib_files(id) ON DELETE CASCADE,
    name TEXT NOT NULL, oid TEXT, description TEXT, syntax TEXT, enums TEXT,
    is_notification INTEGER NOT NULL DEFAULT 0,
    edited INTEGER NOT NULL DEFAULT 0, UNIQUE(mib_file_id, name));
CREATE INDEX IF NOT EXISTS ix_mib_objects_oid ON mib_objects(oid);
CREATE TABLE metrics (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key TEXT NOT NULL, label TEXT NOT NULL, unit TEXT NOT NULL,
    kind TEXT NOT NULL, last_value REAL, last_ts REAL, UNIQUE(device_id, key));
CREATE INDEX IF NOT EXISTS ix_metrics_key ON metrics(key);
CREATE TABLE samples (
    metric_id INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    ts REAL NOT NULL, value REAL, PRIMARY KEY (metric_id, ts));
CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts);
CREATE TABLE samples_hourly (
    metric_id INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour INTEGER NOT NULL, n INTEGER NOT NULL,
    vmin REAL, vavg REAL, vmax REAL, PRIMARY KEY (metric_id, hour));
CREATE INDEX IF NOT EXISTS ix_samples_hourly_hour ON samples_hourly(hour);
"""


def build_legacy(path):
    """A nodes.db in its pre-5.0 shape: the current inventory tables (built
    by the current code, then rewound) plus the five that moved."""
    db = NodesDatabase(path)
    gid = db.ensure_default_group()
    dev_a = db.add_device("10.9.0.1", name="core-1", group_id=gid)
    dev_b = db.add_device("10.9.0.2", name="edge-1", group_id=gid)
    db.close()
    for name in ("nodes_series.db", "nodes_mibs.db"):
        sibling = os.path.join(os.path.dirname(path), name)
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(sibling + suffix):
                os.remove(sibling + suffix)

    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_DDL)
    # Put the foreign key back on the two columns the current code creates
    # as plain integers, so the fixture is genuinely the old shape.
    for table in ("devices", "groups"):
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone()[0]
        sql = sql.replace(
            "mib_file_id INTEGER",
            "mib_file_id INTEGER REFERENCES mib_files(id) ON DELETE SET NULL")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("PRAGMA legacy_alter_table=ON")
        conn.execute(sql.replace(table, "__old", 1))
        conn.execute(f"INSERT INTO __old SELECT * FROM {table}")
        conn.execute(f"DROP TABLE {table}")
        conn.execute(f"ALTER TABLE __old RENAME TO {table}")
    conn.execute("INSERT INTO mib_files(id, filename, module, uploaded_ts,"
                 " object_count, unresolved, parse_notes, content)"
                 " VALUES (5, 'ACME.mib', 'ACME-MIB', ?, 2, '[]', '', 'ACME DEFINITIONS')",
                 (NOW - 86400,))
    conn.executemany(
        "INSERT INTO mib_objects(id, mib_file_id, name, oid, is_notification,"
        " edited) VALUES (?,5,?,?,0,0)",
        [(11, "acmeCpu", "1.3.6.1.4.1.9999.1"),
         (12, "acmeMem", "1.3.6.1.4.1.9999.2")])
    conn.execute("UPDATE devices SET mib_file_id = 5 WHERE id = ?", (dev_a,))
    conn.execute("UPDATE groups SET mib_file_id = 5 WHERE id = ?", (gid,))
    metric_ids = (101, 102, 103)
    conn.executemany(
        "INSERT INTO metrics(id, device_id, key, label, unit, kind, last_value,"
        " last_ts) VALUES (?,?,?,?,?,'gauge',?,?)",
        [(101, dev_a, "cpu_pct", "CPU", "%", 41.0, NOW - 60),
         (102, dev_a, "mem_pct", "Memory", "%", 62.0, NOW - 60),
         (103, dev_b, "cpu_pct", "CPU", "%", 8.0, NOW - 60)])
    # 48 complete hours of rollups per metric, ending at the hour before last.
    rollups = []
    for mid in metric_ids:
        for i in range(48):
            hour = NOW_HOUR - (i + 2) * HOUR
            rollups.append((mid, hour, 30, 1.0, 5.0 + i, 9.0 + i))
    conn.executemany(
        "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
        " VALUES (?,?,?,?,?,?)", rollups)
    # Raw samples in the hour after the watermark: not copied, but rolled up.
    tail_hour = NOW_HOUR - HOUR
    conn.executemany(
        "INSERT INTO samples(metric_id, ts, value) VALUES (?,?,?)",
        [(mid, tail_hour + 60 * k, 20.0 + k) for mid in metric_ids
         for k in range(10)])
    conn.execute("INSERT INTO settings(key, value) VALUES ('rollup_watermark_hour', ?)",
                 (str(int(tail_hour)),))
    conn.commit()
    conn.close()
    return gid, dev_a, dev_b


def table_names(path):
    conn = sqlite3.connect(path)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    return names


work = tmpdir("nodes_split_")
nodes_path = os.path.join(work, "nodes.db")
series_path = os.path.join(work, "nodes_series.db")
mibs_path = os.path.join(work, "nodes_mibs.db")
group_id, device_a, device_b = build_legacy(nodes_path)

legacy_tables = table_names(nodes_path)
check("the fixture really is the pre-split shape",
      {"metrics", "samples", "samples_hourly", "mib_files", "mib_objects"}
      <= legacy_tables, sorted(legacy_tables))
conn = sqlite3.connect(nodes_path)
fixture_sql = conn.execute(
    "SELECT sql FROM sqlite_master WHERE name='devices'").fetchone()[0]
conn.close()
check("...including the mib_files foreign key on devices",
      "REFERENCES mib_files" in fixture_sql)

# ------------------------------------------------------------- phase 1
started = time.monotonic()
db = NodesDatabase(nodes_path)
elapsed = time.monotonic() - started
print(f"      phase 1 took {elapsed * 1000:.0f} ms on the fixture")

check("phase 1 leaves the marker at 'rollups'",
      db._private_setting("split_state") == "rollups",
      db._private_setting("split_state"))
check("...and says so through split_pending()", db.split_pending() is True)

sql = db._conn.execute(
    "SELECT sql FROM sqlite_master WHERE name='devices'").fetchone()["sql"]
check("devices no longer references mib_files", "REFERENCES mib_files" not in sql, sql)
sql_groups = db._conn.execute(
    "SELECT sql FROM sqlite_master WHERE name='groups'").fetchone()["sql"]
check("...and neither does groups", "REFERENCES mib_files" not in sql_groups)
check("the rebuild kept the rows",
      db.device(device_a)["name"] == "core-1" and db.device(device_b)["ip"] == "10.9.0.2")
check("...and the mib_file_id assignments",
      db.device(device_a)["mib_file_id"] == 5
      and db.group(group_id)["mib_file_id"] == 5,
      (db.device(device_a)["mib_file_id"], db.group(group_id)["mib_file_id"]))
check("foreign_key_check is clean after the rebuild",
      db._conn.execute("PRAGMA foreign_key_check").fetchall() == [])

check("metric ids came across unchanged",
      {row["id"] for row in db.metrics(device_a)} == {101, 102}, )
check("...and the metric values with them",
      db.metric(101)["last_value"] == 41.0 and db.metric(103)["device_id"] == device_b)
check("the MIB file and its objects came across with their ids",
      db.mib_file(5)["module"] == "ACME-MIB"
      and {o["id"] for o in db.mib_objects(5)} == {11, 12})
check("the MIB content survived the copy",
      db.mib_file(5)["content"] == "ACME DEFINITIONS")

# Raw samples are deliberately not copied, but the tail past the watermark is
# summarised so the right-hand edge of a wide chart is not a hole.
raw_left = db.series_db._conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
check("raw samples are not copied", raw_left == 0, raw_left)
tail = db.series_db._conn.execute(
    "SELECT COUNT(*) FROM samples_hourly WHERE hour = ?",
    (NOW_HOUR - HOUR,)).fetchone()[0]
check("...but the tail past the watermark was rolled up", tail == 3, tail)

wide = db.series(device_a, 101, NOW - 60 * 86400, NOW)
check("a wide chart still shows all 48 hours during phase 2",
      len(wide) == 49, len(wide))     # 48 legacy + the rolled-up tail hour

new_device = db.add_device("10.9.0.3", name="added-during-split", group_id=group_id)
check("add_device works with the legacy mib_files table still present",
      db.device(new_device) is not None)

# ------------------------------------------------------------- phase 2
class OneBatch:
    """A stop flag that lets exactly one batch through, so the interrupted
    case is tested rather than waited for."""

    def __init__(self):
        self.seen = 0

    def is_set(self):
        self.seen += 1
        return self.seen > 1


db.series_db._set_private_setting("legacy_rollup_rowid", 0)
db.series_db._set_private_setting("legacy_rollup_end", None)
partial = db.series_db.import_legacy_rollups(nodes_path, batch=20,
                                             stop=OneBatch())
cursor_at, end_at = db.series_db.legacy_rollup_cursor()
check("a bounded phase-2 batch copies some rows and persists its cursor",
      0 < partial < 144 and 0 < cursor_at < end_at, (partial, cursor_at, end_at))
db.close()

db = NodesDatabase(nodes_path)
resumed_cursor, _ = db.series_db.legacy_rollup_cursor()
check("the cursor survives a reopen", resumed_cursor == cursor_at,
      (resumed_cursor, cursor_at))
check("reopening during phase 2 does not move the marker back",
      db._private_setting("split_state") == "rollups")

# ------------------------------------------------------------- phase 3
db.finish_split_now()
check("the marker reaches 'done'",
      db._private_setting("split_state") == "done",
      db._private_setting("split_state"))
after = table_names(nodes_path)
check("the five legacy tables are gone",
      not ({"metrics", "samples", "samples_hourly", "mib_files", "mib_objects"}
           & after), sorted(after))
check("foreign_key_check is still clean",
      db._conn.execute("PRAGMA foreign_key_check").fetchall() == [])

hourly = db.series_db._conn.execute(
    "SELECT COUNT(*) FROM samples_hourly").fetchone()[0]
check("every rollup row arrived", hourly == 48 * 3 + 3, hourly)
raw_left = db.series_db._conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
check("and no raw samples with them", raw_left == 0, raw_left)
freelist = db._conn.execute("PRAGMA freelist_count").fetchone()[0]
check("nodes.db was reclaimed after the drop", freelist == 0, freelist)

wide = db.series(device_a, 101, NOW - 60 * 86400, NOW)
check("the wide chart still reads all 49 hours after the split",
      len(wide) == 49, len(wide))

# ------------------------------------------------ cross-file consistency
db.remove_device(device_b)
check("remove_device clears the series rows across the file boundary",
      db.series_db.metrics(device_b) == [], db.series_db.metrics(device_b))
db.bulk_remove_devices([device_a])
check("bulk_remove_devices does too",
      db.series_db.metrics(device_a) == [], db.series_db.metrics(device_a))

db.update_device(new_device, mib_file_id=5)
db.remove_mib_file(5)
check("remove_mib_file NULLs the device assignment",
      db.device(new_device)["mib_file_id"] is None)
check("...and the group's", db.group(group_id)["mib_file_id"] is None)
check("...and really removed the file", db.mib_file(5) is None)
db.close()

# --------------------------------------------------------- reopen, fresh
db = NodesDatabase(nodes_path)
check("reopening a finished split is a no-op",
      db._private_setting("split_state") == "done" and db.split_pending() is False)
check("...and the legacy tables stay gone",
      not ({"metrics", "samples"} & table_names(nodes_path)))
db.close()

fresh_dir = tmpdir("nodes_split_fresh_")
fresh = NodesDatabase(os.path.join(fresh_dir, "nodes.db"))
check("a fresh 5.0 database has no split marker at all",
      fresh._private_setting("split_state") is None
      and fresh.split_pending() is False,
      fresh._private_setting("split_state"))
gid2 = fresh.ensure_default_group()
did2 = fresh.add_device("10.9.9.9", group_id=gid2)
fresh.record_metric_sample(did2, "cpu_pct", "CPU", "%", "gauge", NOW, 3.0)
check("...and still records metrics into its sibling file",
      len(fresh.metrics(did2)) == 1)
check("...which is a real file beside it",
      os.path.isfile(os.path.join(fresh_dir, "nodes_series.db"))
      and os.path.isfile(os.path.join(fresh_dir, "nodes_mibs.db")))
fresh.close()

mem = NodesDatabase(":memory:")
mem_gid = mem.ensure_default_group()
mem_did = mem.add_device("10.9.9.10", group_id=mem_gid)
mem.record_metric_sample(mem_did, "cpu_pct", "CPU", "%", "gauge", NOW, 7.0)
check(":memory: opens with in-memory siblings and works",
      len(mem.metrics(mem_did)) == 1 and mem.series_db.path == ":memory:")
mem.close()

# ------------------------------------------- the missing-rollup retry path
retry_dir = tmpdir("nodes_split_retry_")
retry_path = os.path.join(retry_dir, "nodes.db")
build_legacy(retry_path)
db = NodesDatabase(retry_path)
# Claim the whole legacy range as already copied without copying anything:
# phase 3's check must notice and the retry must repair it.
db.series_db._set_private_setting("legacy_rollup_end", 10 ** 9)
db.series_db._set_private_setting("legacy_rollup_rowid", 10 ** 9)
check("the fixture starts with nothing copied but the cursor at the end",
      db.series_db.legacy_rollups_missing(retry_path) == 144,
      db.series_db.legacy_rollups_missing(retry_path))
db.finish_split_now()
check("phase 3's retry copies what the cursor skipped",
      db._private_setting("split_state") == "done"
      and db.series_db._conn.execute(
          "SELECT COUNT(*) FROM samples_hourly").fetchone()[0] == 147,
      db.series_db._conn.execute("SELECT COUNT(*) FROM samples_hourly").fetchone()[0])
db.close()

# ------------------------------------ phase 2 lets the rest of the app in
lock_dir = tmpdir("nodes_split_lock_")
lock_path = os.path.join(lock_dir, "nodes.db")
_, probe_device, _ = build_legacy(lock_path)
db = NodesDatabase(lock_path)
series = db.series_db
probe_free = []
probe_latency = []


def probe_series_lock():
    got = series._lock.acquire(timeout=2.0)
    if got:
        series._lock.release()
    probe_free.append(got)
    started = time.monotonic()
    series.metrics(probe_device)
    probe_latency.append(time.monotonic() - started)


class ProbeBetweenBatches:
    """`stop` is consulted once per batch, which makes it the hook for
    asking — from another thread, mid-import — whether phase 2 is sitting on
    the store lock. It used to hold it for the whole import, which stalled
    polling, charts and alerting until the last row landed."""

    def __init__(self):
        self.batches = 0

    def is_set(self):
        self.batches += 1
        if self.batches <= 3:
            thread = threading.Thread(target=probe_series_lock)
            thread.start()
            thread.join(timeout=5.0)
        return False


series._set_private_setting("legacy_rollup_rowid", 0)
series._set_private_setting("legacy_rollup_end", None)
copied = series.import_legacy_rollups(lock_path, batch=20,
                                      stop=ProbeBetweenBatches())
check("phase 2 releases the store lock between batches",
      len(probe_free) >= 3 and all(probe_free), probe_free)
check("...so a concurrent chart read answers promptly throughout",
      bool(probe_latency) and max(probe_latency) < 1.0, probe_latency)
check("...and the import still copied every row", copied == 144, copied)
db.close()

# ------------------------------- a restart mid-phase-2 does not redo phase 1
rerun_dir = tmpdir("nodes_split_rerun_")
rerun_path = os.path.join(rerun_dir, "nodes.db")
build_legacy(rerun_path)
db = NodesDatabase(rerun_path)
check("the rerun fixture is parked at 'rollups'",
      db._private_setting("split_state") == "rollups")
db.remove_mib_file(5)
split_hour = NOW_HOUR - HOUR
db.series_db._conn.execute(
    "DELETE FROM samples_hourly WHERE hour = ? AND metric_id = 103",
    (split_hour,))
db.series_db._conn.commit()
db.close()

db = NodesDatabase(rerun_path)
check("a MIB deleted during phase 2 is not resurrected by a restart",
      db.mib_file(5) is None)
split_rows = db.series_db._conn.execute(
    "SELECT COUNT(*) FROM samples_hourly WHERE hour = ?",
    (split_hour,)).fetchone()[0]
check("...and the split-hour rollup is left as the new store has it",
      split_rows == 2, split_rows)
db.close()

print()
if FAILS:
    print(f"{len(FAILS)} FAILED: " + ", ".join(FAILS))
    raise SystemExit(1)
print("all checks passed")
