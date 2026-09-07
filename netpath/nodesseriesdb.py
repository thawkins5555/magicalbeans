"""The Nodes module's time series: metric definitions, raw samples and the
hourly rollups they are summarised into.

Its own file rather than a section of nodes.db because these three tables
are the ones that grow: `samples` dominates the write rate, `samples_hourly`
dominates the size, and `metrics` is a large static table beside them.
Keeping them here means a size cap that trims history never has to consider
the device inventory, and the poller's hot write path no longer contends for
the same file the web page reads devices from.

`metrics.device_id` is a plain integer, not a foreign key: the devices it
names live in nodes.db. That is already the convention across this
application's stores (configrx.device_config, mapper.map_nodes), and
NodesDatabase.remove_device is what keeps the two sides in step.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time

from .sqlitebase import SqliteStore, id_chunks, reclaim

log = logging.getLogger(__name__)

# How wide a chart window still reads raw samples. Wider than this reads
# samples_hourly instead — which is why sample_retention_days defaults to
# the same three days: raw points older than the widest raw window can
# answer nothing a rollup does not.
RAW_WINDOW_S = 3 * 86400

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
-- The alert engine asks for one metric key across the whole fleet twelve
-- times a minute (metrics_for_keys); the UNIQUE(device_id, key) index leads
-- with device_id and cannot serve a key-first query. In SCHEMA rather than a
-- migration because this table is created here for the first time.
CREATE INDEX IF NOT EXISTS ix_metrics_key ON metrics(key);

CREATE TABLE IF NOT EXISTS samples (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    value           REAL,
    PRIMARY KEY (metric_id, ts)
);
-- The primary key leads on metric_id, so the two queries that ask about
-- time across every metric — compact_rollup's per-hour aggregate and
-- prune's delete by age — scanned the whole table without this. On the
-- largest table in the database that was seconds of held lock per pass.
CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS samples_hourly (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour            INTEGER NOT NULL,
    n               INTEGER NOT NULL,
    vmin            REAL, vavg REAL, vmax REAL,
    PRIMARY KEY (metric_id, hour)
);
-- The primary key leads on metric_id, so "every rollup row older than N
-- days" — what prune() asks once per maintenance pass — would scan the
-- whole table without this.
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

    _CAP_MIN_SQLITE = (3, 25, 0)   # window functions

    def __init__(self, path: str):
        self._warned_no_window = False
        super().__init__(path)

    # ---------------------------------------------------------------- writes

    def record_metric_samples(self, device_id: int, rows: list) -> dict:
        """Every metric one poll produced, in one transaction.

        `rows` is a sequence of (key, label, unit, kind, ts, value). One
        SELECT of the device's existing metric ids, one INSERT for keys never
        seen before, one UPDATE of the current values, one INSERT for the
        samples — a per-sample commit is ~2,000 fsyncs on a 500-port chassis.

        `kind` is written only when the metric row is created. Changing a
        metric's kind under a chart that has months of history in the other
        unit is not something a poll should do silently, and the poller
        never means to: the kind is a property of the OID, not of a
        reading. A value of None updates last_ts and stores no sample —
        "polled, no answer" is not a zero.

        Returns {key: metric_id} for every row, so a caller that needs an
        id (a chart link, a threshold) does not have to read them back.
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
        """One metric sample — a one-row wrapper around
        record_metric_samples, kept for the callers (tests, on-demand
        reads) that genuinely have exactly one."""
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
        """The newest value of each named metric key, fleet-wide, in one query.

        The alert engine used to read `SELECT * FROM metrics WHERE device_id
        = ?` once per device per tick — at 2,000 devices and ~90 metrics
        each, 400,000 full rows every five seconds through the same
        connection and lock the poller writes with, to evaluate a handful of
        threshold rules. It reads four columns for the keys that have a rule
        instead. Whose devices are disabled is nodes.db's fact, so the
        facade filters those out of this result.
        """
        keys = [str(k) for k in keys if k]
        if not keys:
            return []
        marks = ",".join("?" * len(keys))
        with self._lock:
            return self._conn.execute(
                "SELECT device_id, key, label, last_value, last_ts"
                f" FROM metrics WHERE key IN ({marks})", keys).fetchall()

    _IDS_PER_QUERY = 500

    def metrics_for_devices(self, device_ids, keys) -> list[sqlite3.Row]:
        """The newest value of each named metric key, for named devices only.

        Chunked by _IDS_PER_QUERY for the bind-parameter reason id_chunks
        exists for, and empty input touches the database not at all. The
        facade drops disabled devices from the result."""
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
        """Every device's current value of one metric key, best first.

        NULL last_value rows are excluded: a metric that has never produced
        a sample is not a zero, and sorting it as one puts silent devices at
        the top of a "best" list and hides real ones. The facade trims this
        to enabled devices and to `n`, which it can only do with nodes.db's
        device rows in hand.
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
        """Peak and mean of every matching metric series over [h0, h1], read
        from samples_hourly (never samples — a raw scan would not finish at
        fleet scale). report.top_metric_ranking names the devices afterwards.
        """
        key_clause = "m.key LIKE ?" if like else "m.key = ?"
        params: list = [key]
        device_clause = ""
        if device_ids:
            marks = ",".join("?" * len(device_ids))
            device_clause = f" AND m.device_id IN ({marks})"
            params.extend(device_ids)
        params.extend([h0, h1])
        with self._lock:
            return self._conn.execute(
                f"WITH candidates AS ("
                f" SELECT m.id AS metric_id, m.device_id, m.key, m.label, m.unit"
                f" FROM metrics m WHERE {key_clause}{device_clause})"
                f" SELECT c.metric_id, c.device_id, c.key, c.label, c.unit,"
                f" MAX(sh.vmax) AS peak, SUM(sh.vavg * sh.n) AS sum_avg_n,"
                f" SUM(sh.n) AS total_n, COUNT(*) AS n_hours"
                # CROSS JOIN, deliberately: it disables SQLite's join reordering,
                # forcing small `candidates` to drive the loop and huge
                # `samples_hourly` to be probed by its own primary key per
                # candidate — a plain JOIN let SQLite start from the hour index
                # instead and scan every unrelated metric family's rows in range.
                f" FROM candidates c CROSS JOIN samples_hourly sh"
                f" ON sh.metric_id = c.metric_id"
                f" WHERE sh.hour >= ? AND sh.hour <= ? GROUP BY c.metric_id",
                params).fetchall()

    def series(self, device_id: int, metric_id: int, t0: float, t1: float,
               bucket_s: float = 0) -> list[dict]:
        """Raw-vs-hourly selection: a wide window reads the rollup table
        instead of scanning months of raw points.

        `device_id` is enforced, not decorative. Metric ids are global, so
        without the check a caller passing another device's metric id got that
        device's data back under this device's name — which is exactly what a
        stale dialog does when the selected device changes underneath it. A
        mismatch now returns nothing, which reads as "no samples" rather than
        as somebody else's traffic.

        `bucket_s > 0` buckets raw samples server-side into fixed-width
        windows aligned to epoch time (`floor(ts / bucket_s) * bucket_s`),
        returning the same `{ts, avg, min, max}` shape the hourly rollup
        uses so `drawSeriesChart` renders either one unchanged. Bucketing
        only applies within the raw-sample window (<= 3 days); a wider
        window already reads the hourly rollup and ignores `bucket_s`.
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
    # Hours already rolled up that are aggregated again on the next pass, so
    # a sample that arrived after its hour was summarised is not lost. Two
    # covers a poll that started before the hour ended and a clock that is a
    # little behind.
    _ROLLUP_REDO_HOURS = 2

    def compact_rollup(self, max_hours: int = 48) -> int:
        """Summarise complete hours of raw samples into samples_hourly.

        Raw rows are left alone (prune and the per-metric cap own their
        lifetime), work starts from a private watermark rather than from the
        beginning of time, and each hour is its own transaction so the lock
        is never held across more than one. `max_hours` bounds a single
        pass; the watermark makes the next pass continue where this one
        stopped, so a long backlog is worked off over several passes instead
        of in one stall.

        Returns the number of (metric, hour) rows written.
        """
        now = time.time()
        # The last hour that has fully elapsed. The current hour is still
        # collecting samples and would be summarised wrong.
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
        """Drop every metric (and, by cascade, every sample and rollup row)
        belonging to devices that no longer exist in nodes.db."""
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

    def prune_orphan_metrics(self, live_ids) -> int:
        """Metrics whose device is gone from nodes.db — the cross-file
        counterpart of the ON DELETE CASCADE the two tables used to share.
        A device removed while this store was unreachable, or by a 4.x
        binary, leaves rows only this can find."""
        live = {int(i) for i in live_ids or ()}
        orphans = [i for i in self.device_ids_with_metrics() if i not in live]
        return self.delete_metrics_for_devices(orphans)

    def cap_samples_per_metric(self, n: int, chunk: int = 200) -> int:
        """Keep at most the newest `n` raw samples of EACH metric.

        Per metric with a window function, in chunks of `chunk` metrics,
        taking the lock for each chunk and releasing it in between, so a poll
        worker waits for one chunk at most. Window functions need SQLite
        3.25; on anything older this does nothing and says so once.
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
        for start in range(0, len(metric_ids), max(1, chunk)):
            batch = metric_ids[start:start + max(1, chunk)]
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

    def prune(self, *, sample_days: float = 3, rollup_days: float = 400,
              max_samples_per_metric: int = 0) -> int:
        """Age out raw samples and hourly rollups. A caller that wants
        "delete everything now" (the Settings page's maintenance button)
        passes 0, which computes a cutoff of "now" and so matches every
        existing row."""
        removed = 0
        now = time.time()
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM samples WHERE ts < ?", (now - sample_days * 86400,))
            removed += cursor.rowcount or 0
            # The hourly rollups are the long history now, so they are
            # bounded by their own retention rather than kept forever.
            cursor = self._conn.execute(
                "DELETE FROM samples_hourly WHERE hour < ?",
                (now - rollup_days * 86400,))
            removed += cursor.rowcount or 0
            self._conn.commit()
        removed += self.cap_samples_per_metric(max_samples_per_metric)
        if removed:
            # Freed pages go back in short steps with the lock released
            # between them, not through a whole-file VACUUM.
            reclaim(self._conn, self._lock, label=self.LABEL)
        return removed

    def trim_to_size(self, max_bytes: int) -> int:
        """Delete the oldest raw samples until the file is back under its cap.

        Incremental reclaim rather than VACUUM: a whole-file rewrite under
        the module lock stalls every poll worker and HTTP handler.
        """
        if max_bytes <= 0:
            return 0
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
                if total <= 5000:
                    break
                chunk = max(int(total * 0.15), 5000)
                cursor = self._conn.execute(
                    "DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples"
                    " ORDER BY ts ASC LIMIT ?)", (chunk,))
                removed += cursor.rowcount or 0
                self._conn.commit()
            reclaim(self._conn, self._lock, label=self.LABEL)
        return removed

    # ------------------------------------------------------------- migration

    def _attached(self, legacy_path: str):
        """ATTACH `legacy_path` as `old` for the duration of the block.

        Always detached again, including on the way out of an exception:
        an ATTACH left open makes every later VACUUM fail, and `reclaim`
        runs from the maintenance timer without knowing a migration happened.
        """
        store = self

        class _Attach:
            def __enter__(self):
                # ATTACH is refused inside a transaction, and the shared
                # connection may still be holding one open from a read.
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
        """Copy every metric row across with its id intact.

        The ids are what every other store already holds (an alert
        threshold, a chart link), so they are carried, not regenerated.
        Returns (copied here, present in the legacy file) so the caller can
        refuse to go further if the two disagree.
        """
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
        """Summarise the legacy raw samples from `from_hour` onwards into the
        new rollups.

        Raw samples are deliberately not copied — they are the bulk of the
        old file and expire in three days anyway — but the partial hours
        since the last rollup watermark would otherwise be lost outright,
        leaving a hole at the right-hand edge of every wide chart. This is
        the same aggregate compact_rollup does, run once over the tail.
        """
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
        batches, resumable across restarts.

        The cursor is written in the same transaction as the rows it covers,
        so an interrupted run resumes exactly where it stopped rather than
        redoing work or skipping it. `INSERT OR IGNORE` guarded by an EXISTS
        on `metrics` drops rows whose metric never made it across (a device
        deleted mid-migration), which would otherwise violate the foreign
        key. `restart` rewinds the cursor, for the one retry phase 3 makes
        when a row arrived behind it. Returns the rows copied by this call.
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
            # The lock and the ATTACH are per batch, not around the whole
            # loop: phase 2 runs for minutes on a large file, and polling,
            # charts and alerting all want this same connection meanwhile.
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
            # Same adaptive shape as SqliteStore._delete_batches: keep one
            # batch's lock hold near the target however wide the rows are.
            if held > LEGACY_LOCK_TARGET_S:
                size = max(LEGACY_BATCH_MIN, size // 2)
            elif held < LEGACY_LOCK_TARGET_S / 4:
                size = min(LEGACY_BATCH_MAX, size * 2)
        return copied

    def legacy_rollups_missing(self, legacy_path: str,
                               min_hour: float | None = None) -> int:
        """How many legacy rollup rows this store still does not hold, of
        those whose metric exists here. What phase 3 checks before dropping
        the legacy tables."""
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
