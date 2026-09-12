"""The Nodes module's time series: metric definitions, raw samples and the
hourly rollups they are summarised into.

Its own file, not a section of nodes.db, because these three tables are the
ones that grow, so a size cap here never has to consider the device
inventory and the poller's hot write path stops contending for the same
file the web page reads devices from. `metrics.device_id` is a plain
integer rather than a foreign key for the same reason every other store
does this (configrx.device_config, mapper.map_nodes): the devices it names
live in nodes.db, and NodesDatabase.remove_device keeps the two in step.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time

from .sqlitebase import SqliteStore, id_chunks, reclaim

log = logging.getLogger(__name__)

# How wide a chart window still reads raw samples before falling back to
# samples_hourly; sample_retention_days defaults to the same three days.
RAW_WINDOW_S = 3 * 86400

# One batch of prune(), in rows, and the band _delete_batches may move it
# inside. Sized like the walk tables' rather than like netpath.db's: a batch
# of contiguous rowids spans every metric in the fleet, so it touches very
# nearly every leaf page of the (metric_id, ts) primary key whatever its
# size, and small batches pay that whole cost again per commit. 400,000
# samples over 20,000 metrics, with bench_prune's 5 ms reader:
#
#     unbatched      1.9 s, one hold of 1,864 ms, reader stalled 919 ms
#      2,000 rows    1.8 s, 53 holds, median  20 ms, reader stalled 919 ms
#     20,000 rows    1.8 s, 20 holds, median  96 ms, reader stalled 448 ms
#     50,000 rows    1.5 s, 16 holds, median 105 ms, reader stalled 1516 ms
SAMPLE_PRUNE_CHUNK = 20_000
SAMPLE_PRUNE_CHUNK_MIN = 5_000
SAMPLE_PRUNE_CHUNK_MAX = 80_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL,
    key             TEXT NOT NULL,
    label           TEXT NOT NULL,
    unit            TEXT NOT NULL,
    kind            TEXT NOT NULL,                  -- 'gauge'|'counter_rate'
    last_value      REAL,
    last_ts         REAL,
    UNIQUE(device_id, key)
);
-- metrics_for_keys asks by key, not device_id, which UNIQUE(device_id, key)
-- can't serve; in SCHEMA since this table is created fresh here.
CREATE INDEX IF NOT EXISTS ix_metrics_key ON metrics(key);

CREATE TABLE IF NOT EXISTS samples (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    value           REAL,
    PRIMARY KEY (metric_id, ts)
);
-- The PK leads on metric_id; without this, compact_rollup's per-hour
-- aggregate and prune's delete-by-age scanned the whole (largest) table.
CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS samples_hourly (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour            INTEGER NOT NULL,
    n               INTEGER NOT NULL,
    vmin            REAL, vavg REAL, vmax REAL,
    PRIMARY KEY (metric_id, hour)
);
-- The PK leads on metric_id; prune()'s "older than N days" needs this too.
CREATE INDEX IF NOT EXISTS ix_samples_hourly_hour ON samples_hourly(hour);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Rows copied per transaction while phase 2 lifts the legacy rollups across.
LEGACY_BATCH = 20_000
LEGACY_BATCH_MIN = 2_000
LEGACY_BATCH_MAX = 100_000
LEGACY_LOCK_TARGET_S = 0.15

_LEGACY_ROWID = "legacy_rollup_rowid"
_LEGACY_END = "legacy_rollup_end"


class NodesSeriesDatabase(SqliteStore):
    """metrics / samples / samples_hourly, and nothing else."""

    SCHEMA = SCHEMA
    DEFAULTS: dict = {}
    LABEL = "nodes_series"
    # Rollups reach furthest back; raw samples cover the first hour,
    # before any hour is summarised.
    OLDEST_TS_SQL = ("SELECT MIN(ts) FROM (SELECT MIN(hour) AS ts FROM"
                     " samples_hourly UNION ALL SELECT MIN(ts) FROM samples)")

    _CAP_MIN_SQLITE = (3, 25, 0)   # window functions

    def __init__(self, path: str):
        self._warned_no_window = False
        super().__init__(path)

    # ---------------------------------------------------------------- writes

    def record_metric_samples(self, device_id: int, rows: list) -> dict:
        """Every metric one poll produced, in one transaction rather than a
        per-sample commit (~2,000 fsyncs on a 500-port chassis). `kind` is
        written only at creation — a poll must never silently change a
        metric's unit under months of chart history. A value of None
        updates last_ts and stores no sample: "polled, no answer" isn't a
        zero. Returns {key: metric_id} so a caller needing an id doesn't
        have to read it back.
        """
        latest: dict[str, tuple] = {}
        for row in rows or ():
            key, label, unit, kind, ts, value = row
            latest[key] = (label, unit, kind, ts, value)
        if not latest:
            return {}
        with self._lock:
            try:
                ids = {r["key"]: r["id"] for r in self._conn.execute(
                    "SELECT id, key FROM metrics WHERE device_id = ?",
                    (device_id,)).fetchall()}
                missing = [(device_id, key, label, unit, kind)
                           for key, (label, unit, kind, _ts, _value) in latest.items()
                           if key not in ids]
                if missing:
                    self._conn.executemany(
                        "INSERT OR IGNORE INTO metrics(device_id, key, label, unit,"
                        " kind) VALUES (?,?,?,?,?)", missing)
                    marks = ",".join("?" * len(missing))
                    for r in self._conn.execute(
                            f"SELECT id, key FROM metrics WHERE device_id = ?"
                            f" AND key IN ({marks})",
                            (device_id, *[m[1] for m in missing])).fetchall():
                        ids[r["key"]] = r["id"]
                self._conn.executemany(
                    "UPDATE metrics SET last_value=?, last_ts=?, label=?, unit=?"
                    " WHERE id=?",
                    [(value, ts, label, unit, ids[key])
                     for key, (label, unit, _kind, ts, value) in latest.items()
                     if key in ids])
                samples = [(ids[key], ts, value)
                           for key, (_label, _unit, _kind, ts, value) in latest.items()
                           if value is not None and key in ids]
                if samples:
                    self._conn.executemany(
                        "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                        " VALUES (?,?,?)", samples)
                self._conn.commit()
            except sqlite3.DatabaseError:
                self._conn.rollback()
                raise
        return {key: ids[key] for key in latest if key in ids}

    def record_metric_sample(self, device_id: int, key: str, label: str,
                             unit: str, kind: str, ts: float,
                             value: float | None) -> int:
        """One-row wrapper around record_metric_samples, for callers that
        genuinely have exactly one."""
        ids = self.record_metric_samples(
            device_id, [(key, label, unit, kind, ts, value)])
        return ids[key]

    # ----------------------------------------------------------------- reads

    def metrics(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE device_id = ? ORDER BY label",
                (device_id,)).fetchall()

    def metric(self, metric_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE id = ?", (metric_id,)).fetchone()

    def metrics_for_keys(self, keys) -> list[sqlite3.Row]:
        """The newest value of each named metric key, fleet-wide, in one
        query — replaces a per-device `SELECT *` that read 400,000 full
        rows every five seconds at 2,000 devices to evaluate a handful of
        threshold rules. Disabled devices are the facade's filter, not
        this one's — that's nodes.db's fact."""
        keys = [str(k) for k in keys if k]
        if not keys:
            return []
        marks = ",".join("?" * len(keys))
        with self._lock:
            return self._conn.execute(
                "SELECT device_id, key, label, last_value, last_ts"
                f" FROM metrics WHERE key IN ({marks})", keys).fetchall()

    def metrics_for_families(self, keys) -> list[sqlite3.Row]:
        """The newest value of each named metric key AND of every per-port
        child of one, fleet-wide -- "cpu_pct" alone, but "sfp_rx_dbm" and
        every "sfp_rx_dbm.<if_index>" with it.

        Matched as `key = root OR (key >= 'root.' AND key < 'root/')` rather
        than LIKE, since SQLite can drive ix_metrics_key from that range
        unconditionally, while the LIKE optimisation depends on a pragma and
        can silently fall back to a full scan. `unit` is selected too, since
        a per-port alert needs to say dBm, not just "-24.1".
        """
        roots = [str(k) for k in keys if k]
        if not roots:
            return []
        clauses, args = [], []
        for root in roots:
            clauses.append("(key = ? OR (key >= ? AND key < ?))")
            args += [root, root + ".", root + "/"]
        with self._lock:
            return self._conn.execute(
                "SELECT device_id, key, label, unit, last_value, last_ts"
                f" FROM metrics WHERE {' OR '.join(clauses)}", args).fetchall()

    _IDS_PER_QUERY = 500

    def metrics_for_devices(self, device_ids, keys) -> list[sqlite3.Row]:
        """The newest value of each named metric key, for named devices
        only. Chunked by _IDS_PER_QUERY; the facade drops disabled devices
        from the result."""
        ids = list(dict.fromkeys(int(d) for d in device_ids))
        keys = [str(k) for k in keys if k]
        if not ids or not keys:
            return []
        key_marks = ",".join("?" * len(keys))
        rows: list[sqlite3.Row] = []
        with self._lock:
            for chunk in id_chunks(ids, self._IDS_PER_QUERY):
                marks = ",".join("?" * len(chunk))
                rows += self._conn.execute(
                    "SELECT device_id, key, label, last_value, last_ts"
                    f" FROM metrics WHERE device_id IN ({marks})"
                    f" AND key IN ({key_marks})", [*chunk, *keys]).fetchall()
        return rows

    def count_for_device(self, device_id: int) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM metrics WHERE device_id = ?",
                (device_id,)).fetchone()[0]

    def top_metric_rows(self, key: str, *, ascending: bool = False
                        ) -> list[sqlite3.Row]:
        """Every device's current value of one metric key, best first. NULL
        last_value rows are excluded — a metric with no sample yet isn't a
        zero, and sorting it as one puts silent devices at the top. The
        facade trims to enabled devices and to `n`.
        """
        order = "ASC" if ascending else "DESC"
        with self._lock:
            return self._conn.execute(
                f"SELECT device_id, id AS metric_id, key, label, unit,"
                f" last_value, last_ts FROM metrics"
                f" WHERE key = ? AND last_value IS NOT NULL"
                f" ORDER BY last_value {order}", (key,)).fetchall()

    def metric_window_aggregates(self, key: str, h0: int, h1: int, *,
                                 like: bool = False,
                                 device_ids: list[int] | None = None
                                 ) -> list[sqlite3.Row]:
        """Peak and mean of every matching metric series over [h0, h1], from
        samples_hourly — a raw scan wouldn't finish at fleet scale."""
        key_clause = "m.key LIKE ?" if like else "m.key = ?"
        # One pass per id chunk, concatenated: every output row is one
        # metric's own aggregate, so splitting the narrowing list cannot
        # merge or double-count anything. None/empty means "whole fleet",
        # which is a single pass with no device clause at all.
        chunks = (list(id_chunks(device_ids, self._IDS_PER_QUERY))
                  if device_ids else [None])
        rows: list[sqlite3.Row] = []
        for chunk in chunks:
            device_clause = ""
            params: list = [key]
            if chunk:
                marks = ",".join("?" * len(chunk))
                device_clause = f" AND m.device_id IN ({marks})"
                params.extend(chunk)
            params.extend([h0, h1])
            with self._lock:
                rows += self._conn.execute(
                    f"WITH candidates AS ("
                    f" SELECT m.id AS metric_id, m.device_id, m.key, m.label, m.unit"
                    f" FROM metrics m WHERE {key_clause}{device_clause})"
                    f" SELECT c.metric_id, c.device_id, c.key, c.label, c.unit,"
                    f" MAX(sh.vmax) AS peak, SUM(sh.vavg * sh.n) AS sum_avg_n,"
                    f" SUM(sh.n) AS total_n, COUNT(*) AS n_hours"
                    # CROSS JOIN disables join reordering: forces small `candidates`
                    # to drive the loop instead of SQLite scanning samples_hourly
                    # from the hour index across unrelated metrics.
                    f" FROM candidates c CROSS JOIN samples_hourly sh"
                    f" ON sh.metric_id = c.metric_id"
                    f" WHERE sh.hour >= ? AND sh.hour <= ? GROUP BY c.metric_id",
                    params).fetchall()
        return rows

    def series(self, device_id: int, metric_id: int, t0: float, t1: float,
               bucket_s: float = 0) -> list[dict]:
        """Raw-vs-hourly selection: a wide window reads samples_hourly
        instead of scanning months of raw points. `device_id` is enforced
        since metric ids are global — a stale dialog passing a mismatched
        id gets nothing back rather than another device's data under this
        one's name. `bucket_s > 0` buckets raw samples server-side into the
        same `{ts, avg, min, max}` shape the hourly rollup uses, so
        `drawSeriesChart` renders either unchanged; ignored once a window
        is wide enough to read the rollup instead.
        """
        with self._lock:
            if not self._conn.execute(
                    "SELECT 1 FROM metrics WHERE id = ? AND device_id = ?",
                    (metric_id, device_id)).fetchone():
                return []
            if (t1 - t0) <= RAW_WINDOW_S:
                if bucket_s and bucket_s > 0:
                    rows = self._conn.execute(
                        "SELECT (CAST(ts / ? AS INTEGER)) * ? AS bucket_ts,"
                        " AVG(value) AS avg, MIN(value) AS min, MAX(value) AS max,"
                        " COUNT(*) AS n FROM samples WHERE metric_id = ?"
                        " AND ts >= ? AND ts <= ? GROUP BY 1 ORDER BY 1",
                        (bucket_s, bucket_s, metric_id, t0, t1)).fetchall()
                    return [{"ts": row["bucket_ts"], "avg": row["avg"],
                            "min": row["min"], "max": row["max"], "n": row["n"]}
                            for row in rows]
                rows = self._conn.execute(
                    "SELECT ts, value FROM samples WHERE metric_id = ?"
                    " AND ts >= ? AND ts <= ? ORDER BY ts",
                    (metric_id, t0, t1)).fetchall()
                return [{"ts": row["ts"], "value": row["value"]} for row in rows]
            rows = self._conn.execute(
                "SELECT hour, n, vmin, vavg, vmax FROM samples_hourly"
                " WHERE metric_id = ? AND hour >= ? AND hour <= ? ORDER BY hour",
                (metric_id, t0, t1)).fetchall()
            return [{"ts": row["hour"], "min": row["vmin"], "avg": row["vavg"],
                    "max": row["vmax"], "n": row["n"]} for row in rows]

    def owns_metric(self, device_id: int, metric_id: int) -> bool:
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM metrics WHERE id = ? AND device_id = ?",
                (metric_id, device_id)).fetchone() is not None

    def device_ids_with_metrics(self) -> list[int]:
        with self._lock:
            return [row[0] for row in self._conn.execute(
                "SELECT DISTINCT device_id FROM metrics").fetchall()]

    # ---------------------------------------------------------------- rollup

    _ROLLUP_WATERMARK = "rollup_watermark_hour"
    # Re-aggregates the last 2 hours so a late-arriving sample (a slow poll,
    # a lagging clock) isn't lost once its hour is summarised.
    _ROLLUP_REDO_HOURS = 2

    def compact_rollup(self, max_hours: int = 48) -> int:
        """Summarise complete hours of raw samples into samples_hourly, from
        a private watermark, one transaction per hour so the lock is never
        held across more than one. `max_hours` bounds a single pass; the
        watermark lets a long backlog work off over several passes.

        Returns the number of (metric, hour) rows written.
        """
        now = time.time()
        # The current hour is still collecting samples and would summarise wrong.
        latest_complete = int(now // 3600) * 3600 - 3600
        watermark = self._private_setting(self._ROLLUP_WATERMARK)
        if watermark is None:
            with self._lock:
                row = self._conn.execute(
                    "SELECT MIN(ts) AS oldest FROM samples").fetchone()
            oldest = row["oldest"] if row else None
            if oldest is None:
                self._set_private_setting(self._ROLLUP_WATERMARK,
                                          latest_complete + 3600)
                return 0
            hour = int(float(oldest) // 3600) * 3600
        else:
            hour = int(watermark) - self._ROLLUP_REDO_HOURS * 3600
        written = 0
        processed = 0
        while hour <= latest_complete and processed < max_hours:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT metric_id, COUNT(*) AS n, MIN(value) AS vmin,"
                    " AVG(value) AS vavg, MAX(value) AS vmax FROM samples"
                    " WHERE ts >= ? AND ts < ? AND value IS NOT NULL"
                    " GROUP BY metric_id", (hour, hour + 3600)).fetchall()
                if rows:
                    self._conn.executemany(
                        "INSERT INTO samples_hourly(metric_id, hour, n, vmin,"
                        " vavg, vmax) VALUES (?,?,?,?,?,?)"
                        " ON CONFLICT(metric_id, hour) DO UPDATE SET"
                        " n=excluded.n, vmin=excluded.vmin, vavg=excluded.vavg,"
                        " vmax=excluded.vmax",
                        [(row["metric_id"], hour, row["n"], row["vmin"],
                          row["vavg"], row["vmax"]) for row in rows])
                    written += len(rows)
                self._conn.commit()
            hour += 3600
            processed += 1
        self._set_private_setting(self._ROLLUP_WATERMARK, hour)
        return written

    # -------------------------------------------------------------- deletion

    def delete_metrics_for_devices(self, device_ids) -> int:
        """Drop every metric (and, by cascade, sample/rollup row) for
        devices no longer in nodes.db."""
        ids = [int(i) for i in device_ids or ()]
        if not ids:
            return 0
        removed = 0
        with self._lock:
            for chunk in id_chunks(ids):
                marks = ",".join("?" * len(chunk))
                cursor = self._conn.execute(
                    f"DELETE FROM metrics WHERE device_id IN ({marks})", chunk)
                removed += cursor.rowcount or 0
            self._conn.commit()
        return removed

    PURGE_PAUSE_S = 0.01

    def delete_metrics_for_device_batched(self, device_id: int,
                                          deadline: float) -> tuple[int, bool]:
        """One device's series history, in lock-bounded, resumable batches."""
        device_id = int(device_id)
        where = "metric_id IN (SELECT id FROM metrics WHERE device_id = ?)"
        removed = 0
        for table in ("samples", "samples_hourly"):
            got, done = self._delete_by_rowid(table, where, (device_id,), deadline,
                                              pause=self.PURGE_PAUSE_S)
            removed += got
            if not done:
                return removed, False
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM metrics WHERE device_id = ?", (device_id,))
            removed += cursor.rowcount or 0
            self._conn.commit()
        return removed, True

    def prune_orphan_metrics(self, live_ids) -> int:
        """Metrics whose device is gone from nodes.db — catches what the
        cross-file split's ON DELETE CASCADE no longer does."""
        live = {int(i) for i in live_ids or ()}
        orphans = [i for i in self.device_ids_with_metrics() if i not in live]
        return self.delete_metrics_for_devices(orphans)

    def cap_samples_per_metric(self, n: int, chunk: int = 200) -> int:
        """Keep at most the newest `n` raw samples of EACH metric, in
        chunks of `chunk` so a poll worker waits for at most one chunk's
        lock. Needs SQLite 3.25's window functions; older, does nothing
        and says so once.
        """
        if n <= 0:
            return 0
        if sqlite3.sqlite_version_info < self._CAP_MIN_SQLITE:
            if not self._warned_no_window:
                self._warned_no_window = True
                log.warning(
                    "nodes: SQLite %s cannot cap samples per metric (needs "
                    "%s); raw samples are bounded by sample_retention_days "
                    "alone", sqlite3.sqlite_version,
                    ".".join(str(part) for part in self._CAP_MIN_SQLITE))
            return 0
        with self._lock:
            metric_ids = [row["id"] for row in
                          self._conn.execute("SELECT id FROM metrics").fetchall()]
        removed = 0
        for batch in id_chunks(metric_ids, max(1, chunk)):
            marks = ",".join("?" * len(batch))
            with self._lock:
                cursor = self._conn.execute(
                    f"DELETE FROM samples WHERE rowid IN ("
                    f" SELECT rowid FROM ("
                    f"  SELECT rowid, ROW_NUMBER() OVER ("
                    f"   PARTITION BY metric_id ORDER BY ts DESC) AS rn"
                    f"  FROM samples WHERE metric_id IN ({marks})"
                    f" ) WHERE rn > ?)", (*batch, int(n)))
                removed += cursor.rowcount or 0
                self._conn.commit()
        return removed

    def _prune_by_rowid(self, table: str, where: str, params) -> int:
        """A by-age DELETE cut into lock-bounded batches by rowid.

        `samples` is the largest table in the product and this store guards
        one connection with one lock, so an unbatched sweep -- and above all
        the "delete every stored sample" the Settings maintenance button
        issues on the request thread -- held it for the whole delete, which
        is every chart read and every record_poll write queued behind it.

        Chunked by rowid because neither table has an id of its own; every
        batch still carries `where`, so the range decides only how the sweep
        is cut up and never which rows go. The range is wide: rowids are
        handed out in arrival order while the cutoff is on the row's own
        timestamp, and a device with a wrong clock puts the two out of step.
        Wide but cheap -- a batch that finds nothing is an index probe.
        """
        removed, _ = self._delete_by_rowid(table, where, params, float("inf"))
        return removed

    def _delete_by_rowid(self, table: str, where: str, params, deadline: float,
                         pause: float = 0.0) -> tuple[int, bool]:
        """_prune_by_rowid's body with a deadline: (rows removed, finished)."""
        with self._lock:
            bounds = self._conn.execute(
                f"SELECT MIN(rowid) AS lo, MAX(rowid) AS hi FROM {table}"
                f" WHERE {where}", params).fetchone()
        low = bounds["lo"]
        if low is None:
            return 0, True
        cut = bounds["hi"] + 1

        def delete(low_id: int, upper: int) -> int:
            cursor = self._conn.execute(
                f"DELETE FROM {table} WHERE rowid >= ? AND rowid < ?"
                f" AND {where}", (low_id, upper, *params))
            return cursor.rowcount or 0

        removed, reached = self._delete_batches(
            low, cut, deadline, delete, chunk=SAMPLE_PRUNE_CHUNK,
            chunk_min=SAMPLE_PRUNE_CHUNK_MIN, chunk_max=SAMPLE_PRUNE_CHUNK_MAX,
            pause=pause)
        return removed, reached >= cut

    def prune(self, *, sample_days: float = 3, rollup_days: float = 400,
              max_samples_per_metric: int = 0) -> int:
        """Age out raw samples and hourly rollups. Passing 0 (the Settings
        page's maintenance button) matches every existing row."""
        removed = 0
        now = time.time()
        removed += self._prune_by_rowid(
            "samples", "ts < ?", (now - sample_days * 86400,))
        # The hourly rollups are the long history now, so they are
        # bounded by their own retention rather than kept forever.
        removed += self._prune_by_rowid(
            "samples_hourly", "hour < ?", (now - rollup_days * 86400,))
        removed += self.cap_samples_per_metric(max_samples_per_metric)
        if removed:
            # Freed pages go back in short steps with the lock released
            # between them, not through a whole-file VACUUM.
            reclaim(self._conn, self._lock, label=self.LABEL)
        return removed

    _TRIM_SAMPLE_FLOOR = 5_000

    def _hourly_floor(self) -> int:
        """How far down the rollups may be trimmed: a day of hours per
        metric, or the raw floor, whichever is larger -- below that a wide
        chart has nothing left to draw and the raw fallback is long gone."""
        with self._lock:
            metrics = self._conn.execute(
                "SELECT COUNT(*) AS n FROM metrics").fetchone()["n"]
        return max(24 * metrics, self._TRIM_SAMPLE_FLOOR)

    def trim_to_size(self, max_bytes: int, budget_s: float | None = None) -> int:
        """Delete the oldest metric history until under the size cap: raw
        samples first, then the hourly rollups.

        Incremental reclaim, not VACUUM: a whole-file rewrite under the
        module lock stalls every poll worker and HTTP handler. Stage two
        deletes by `hour` ascending, so it never touches the recent hours
        compact_rollup's redo window rewrites.
        """
        if max_bytes <= 0:
            return 0
        deadline = None if budget_s is None else time.monotonic() + max(0.0, budget_s)
        hourly_floor = self._hourly_floor()
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            shrank = False
            for table, column, floor in (
                    ("samples", "ts", self._TRIM_SAMPLE_FLOOR),
                    ("samples_hourly", "hour", hourly_floor)):
                with self._lock:
                    total = self._conn.execute(
                        f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
                    if total <= floor:
                        continue
                    chunk = min(total - floor, max(int(total * 0.15), floor))
                    cursor = self._conn.execute(
                        f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM"
                        f" {table} ORDER BY {column} ASC LIMIT ?)", (chunk,))
                    removed += cursor.rowcount or 0
                    shrank = shrank or bool(cursor.rowcount)
                    self._conn.commit()
                if shrank:
                    break   # the rollups give only once the raw floor is reached
            reclaim(self._conn, self._lock, label=self.LABEL)
            # Neither table can give anything up; another pass would only
            # re-measure and reclaim what's already reclaimed.
            if not shrank:
                break
        return removed

    # ------------------------------------------------------------- migration

    def _attached(self, legacy_path: str):
        """ATTACH `legacy_path` as `old`, always detached again (even on
        exception) — an ATTACH left open makes every later VACUUM fail."""
        store = self

        class _Attach:
            def __enter__(self):
                # ATTACH is refused mid-transaction; a read may hold one open.
                store._conn.commit()
                store._conn.execute("ATTACH DATABASE ? AS old", (legacy_path,))
                return store._conn

            def __exit__(self, *exc):
                try:
                    store._conn.execute("DETACH DATABASE old")
                except sqlite3.DatabaseError:
                    pass
                return False

        return _Attach()

    def import_legacy_metrics(self, legacy_path: str) -> tuple[int, int]:
        """Copy every metric row across with its id intact — other stores
        already hold that id (an alert threshold, a chart link). Returns
        (copied here, present in the legacy file) so the caller can refuse
        to go further if they disagree."""
        with self._lock, self._attached(legacy_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO main.metrics(id, device_id, key, label,"
                " unit, kind, last_value, last_ts)"
                " SELECT id, device_id, key, label, unit, kind, last_value,"
                " last_ts FROM old.metrics")
            conn.commit()
            here = conn.execute("SELECT COUNT(*) FROM main.metrics").fetchone()[0]
            there = conn.execute("SELECT COUNT(*) FROM old.metrics").fetchone()[0]
        return here, there

    def rollup_legacy_samples(self, legacy_path: str, from_hour: int) -> int:
        """compact_rollup's aggregate, run once over the legacy tail from
        `from_hour`: raw samples aren't copied (bulk of the old file, expire
        in 3 days anyway), but skipping this would hole the edge of every
        wide chart until they did."""
        latest_complete = int(time.time() // 3600) * 3600
        with self._lock, self._attached(legacy_path) as conn:
            cursor = conn.execute(
                "INSERT INTO main.samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
                " SELECT metric_id, CAST(ts / 3600 AS INTEGER) * 3600 AS hour,"
                " COUNT(*), MIN(value), AVG(value), MAX(value)"
                " FROM old.samples WHERE value IS NOT NULL AND ts >= ? AND ts < ?"
                " GROUP BY metric_id, hour"
                " ON CONFLICT(metric_id, hour) DO UPDATE SET"
                " n=excluded.n, vmin=excluded.vmin, vavg=excluded.vavg,"
                " vmax=excluded.vmax",
                (from_hour, latest_complete))
            written = cursor.rowcount or 0
            conn.commit()
        return written

    def legacy_rollup_cursor(self) -> tuple[int, int | None]:
        return (int(self._private_setting(_LEGACY_ROWID, 0) or 0),
                self._private_setting(_LEGACY_END))

    def import_legacy_rollups(self, legacy_path: str, *, stop=None,
                              batch: int | None = None,
                              min_hour: float | None = None,
                              restart: bool = False) -> int:
        """Lift `samples_hourly` out of the legacy file in rowid-cursor
        batches, resumable across restarts — the cursor commits with the
        rows it covers. The EXISTS guard on `metrics` drops rows whose
        metric never made it across (a device deleted mid-migration).
        `restart` rewinds the cursor for phase 3's one retry. Returns the
        rows copied by this call.
        """
        if restart:
            self._set_private_setting(_LEGACY_ROWID, 0)
            self._set_private_setting(_LEGACY_END, None)
        low, end = self.legacy_rollup_cursor()
        copied = 0
        floor = 0.0 if min_hour is None else float(min_hour)
        size = LEGACY_BATCH if batch is None else int(batch)
        if end is None:
            with self._lock, self._attached(legacy_path) as conn:
                row = conn.execute(
                    "SELECT MAX(rowid) FROM old.samples_hourly").fetchone()
                end = int(row[0] or 0)
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (_LEGACY_END, json.dumps(end)))
                conn.commit()
        while low < end:
            if stop is not None and stop.is_set():
                break
            upper = min(low + size, end)
            started = time.monotonic()
            # Per batch, not around the whole loop: phase 2 runs for minutes,
            # and polling/charts/alerting all want this connection meanwhile.
            with self._lock, self._attached(legacy_path) as conn:
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO main.samples_hourly"
                    "(metric_id, hour, n, vmin, vavg, vmax)"
                    " SELECT sh.metric_id, sh.hour, sh.n, sh.vmin, sh.vavg, sh.vmax"
                    " FROM old.samples_hourly sh"
                    " WHERE sh.rowid > ? AND sh.rowid <= ? AND sh.hour >= ?"
                    " AND EXISTS (SELECT 1 FROM main.metrics m"
                    "             WHERE m.id = sh.metric_id)",
                    (low, upper, floor))
                copied += cursor.rowcount or 0
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (_LEGACY_ROWID, json.dumps(upper)))
                conn.commit()
            held = time.monotonic() - started
            low = upper
            # Same adaptive shape as SqliteStore._delete_batches.
            if held > LEGACY_LOCK_TARGET_S:
                size = max(LEGACY_BATCH_MIN, size // 2)
            elif held < LEGACY_LOCK_TARGET_S / 4:
                size = min(LEGACY_BATCH_MAX, size * 2)
        return copied

    def legacy_rollups_missing(self, legacy_path: str,
                               min_hour: float | None = None) -> int:
        """How many legacy rollup rows (of those whose metric exists here)
        this store still lacks. What phase 3 checks before dropping the
        legacy tables."""
        floor = 0.0 if min_hour is None else float(min_hour)
        with self._lock, self._attached(legacy_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM old.samples_hourly sh WHERE sh.hour >= ?"
                " AND EXISTS (SELECT 1 FROM main.metrics m WHERE m.id = sh.metric_id)"
                " AND NOT EXISTS (SELECT 1 FROM main.samples_hourly h"
                "                 WHERE h.metric_id = sh.metric_id"
                "                   AND h.hour = sh.hour)", (floor,)).fetchone()
        return int(row[0] or 0)

    def legacy_hourly_rows(self, legacy_path: str, metric_id: int,
                           h0: float, h1: float) -> list[dict]:
        """Rollup rows still only in the legacy file, for a chart drawn while
        phase 2 is still running."""
        with self._lock, self._attached(legacy_path) as conn:
            rows = conn.execute(
                "SELECT hour, n, vmin, vavg, vmax FROM old.samples_hourly"
                " WHERE metric_id = ? AND hour >= ? AND hour <= ? ORDER BY hour",
                (metric_id, h0, h1)).fetchall()
        return [{"ts": row["hour"], "min": row["vmin"], "avg": row["vavg"],
                 "max": row["vmax"], "n": row["n"]} for row in rows]
