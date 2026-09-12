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
# samples_hourly, one boundary per metric class. It has to follow retention,
# or a two-day window on a port metric reads `samples` and finds one day.
RAW_WINDOW_S = 3 * 86400
INTERFACE_RAW_WINDOW_S = 1 * 86400

# metrics.scope. The dot, not the `if_` prefix: nodepoll writes six
# device-level worst-port metrics as a bare `if_*`.
SCOPE_DEVICE = 0
SCOPE_INTERFACE = 1


def raw_window_for_scope(scope: int) -> float:
    """The raw-vs-hourly boundary for one metric class."""
    return (INTERFACE_RAW_WINDOW_S if scope == SCOPE_INTERFACE
            else RAW_WINDOW_S)

# One batch of prune(), in METRIC IDS rather than rows: neither table has a
# rowid any more, so a by-age sweep is cut up by bands of the primary key's
# leading column, as wide as the rows it deletes and no wider.
#
# The first band is sized from a rows-per-metric guess (500 metrics put
# ~400 k rows in one DELETE); _delete_batches widens it from there.
SAMPLE_BAND_FIRST_ROWS = 20_000
RAW_ROWS_PER_METRIC_GUESS = RAW_WINDOW_S / 60     # a 60-second poll
SAMPLE_BAND_METRICS_START = max(
    1, int(SAMPLE_BAND_FIRST_ROWS // RAW_ROWS_PER_METRIC_GUESS))
SAMPLE_BAND_METRICS = 500
# 1: an overrunning band may narrow below the starting width.
SAMPLE_BAND_METRICS_MIN = 1
SAMPLE_BAND_METRICS_MAX = 5_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL,
    key             TEXT NOT NULL,
    label           TEXT NOT NULL,
    unit            TEXT NOT NULL,
    kind            TEXT NOT NULL,                  -- 'gauge'|'counter_rate'
    scope           INTEGER NOT NULL DEFAULT 0,     -- 0 device-level, 1 per-port
    last_value      REAL,
    last_ts         REAL,
    UNIQUE(device_id, key)
);
-- metrics_for_keys asks by key, not device_id, which UNIQUE(device_id, key)
-- can't serve; in SCHEMA since this table is created fresh here.
CREATE INDEX IF NOT EXISTS ix_metrics_key ON metrics(key);

-- WITHOUT ROWID, and no index on ts: 66.7 -> 23.8 measured bytes per row,
-- which on the largest table in the product is most of the file. The rowid
-- and its automatic (metric_id, ts) index were a second copy of the key,
-- and the ts index a third. What paid for them was compact_rollup's
-- per-hour aggregate and prune's delete-by-age; both now walk metric-id
-- bands of the primary key instead, which is a range scan already in the
-- order the GROUP BY wants. An existing file is rewritten into this shape
-- by _rewrite_table.
CREATE TABLE IF NOT EXISTS samples (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    value           REAL,
    PRIMARY KEY (metric_id, ts)
) WITHOUT ROWID;

-- WITHOUT ROWID too: 66.3 -> 47.5 measured bytes per row, the rowid and
-- its automatic index having been a second copy of the key. The index on
-- hour stays, unlike samples': trim_to_size deletes by `hour` ascending
-- and MIN(hour) is what oldest_ts() reports, and neither has a cheap plan
-- without it. Dropping it is worth a further 14.2 B/row and wants a
-- persisted oldest-hour watermark, which is its own change.
CREATE TABLE IF NOT EXISTS samples_hourly (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour            INTEGER NOT NULL,
    n               INTEGER NOT NULL,
    vmin            REAL, vavg REAL, vmax REAL,
    PRIMARY KEY (metric_id, hour)
) WITHOUT ROWID;
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

# The WITHOUT ROWID rewrite. One band of metric ids per transaction, copied
# into `<table>_new` and deleted from `<table>` in that same transaction, so
# the file never holds two copies of the table.
REWRITE_BAND_METRICS = 200
REWRITE_BAND_MIN = 20
REWRITE_BAND_MAX = 2_000
REWRITE_LOCK_TARGET_S = 0.15

# The live tail _finish_rewrite may copy in its single transaction: the
# freeze advances and the bands run again until fewer rows than this remain.
REWRITE_TAIL_ROWS = 50_000
REWRITE_CATCHUP_PASSES = 8

# Per table: the key column beside metric_id, the column list to copy, the
# `_new` table's DDL, and the indexes to recreate after the rename.
_REWRITE_SPEC = {
    "samples": (
        "ts", "metric_id, ts, value",
        "CREATE TABLE samples_new ("
        " metric_id INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,"
        " ts REAL NOT NULL, value REAL,"
        " PRIMARY KEY (metric_id, ts)) WITHOUT ROWID",
        (),
    ),
    "samples_hourly": (
        "hour", "metric_id, hour, n, vmin, vavg, vmax",
        "CREATE TABLE samples_hourly_new ("
        " metric_id INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,"
        " hour INTEGER NOT NULL, n INTEGER NOT NULL,"
        " vmin REAL, vavg REAL, vmax REAL,"
        " PRIMARY KEY (metric_id, hour)) WITHOUT ROWID",
        # Dropped with the old table, so recreated after the rename and in
        # the same transaction: prune and oldest_ts need it.
        ("CREATE INDEX IF NOT EXISTS ix_samples_hourly_hour"
         " ON samples_hourly(hour)",),
    ),
}


def _rewrite_keys(table: str) -> tuple[str, str, str, str]:
    """One rewrite's four settings rows: state, cursor, end, freeze."""
    return (f"{table}_rewrite_state", f"{table}_rewrite_cursor",
            f"{table}_rewrite_end", f"{table}_rewrite_freeze")


class NodesSeriesDatabase(SqliteStore):
    """metrics / samples / samples_hourly, and nothing else."""

    SCHEMA = SCHEMA
    DEFAULTS: dict = {}
    LABEL = "nodes_series"
    # MIN(hour) once any hour is summarised; `samples` has no ts index.
    OLDEST_TS_SQL = ("SELECT COALESCE((SELECT MIN(hour) FROM samples_hourly),"
                     " (SELECT MIN(ts) FROM samples))")

    _CAP_MIN_SQLITE = (3, 25, 0)   # window functions

    def __init__(self, path: str):
        self._warned_no_window = False
        self._rewrite_state: dict[str, str] = {}
        super().__init__(path)

    def _migrate(self) -> None:
        # Stored rather than re-derived per candidate row: prune filters
        # on it, and a class cannot change under its history.
        if self.ensure_columns("metrics",
                               {"scope": "INTEGER NOT NULL DEFAULT 0"}):
            self._conn.execute(
                "UPDATE metrics SET scope = 1 WHERE key LIKE '%.%'")
        for table in _REWRITE_SPEC:
            self._open_rewrite(table)

    # ---------------------------------------------------------------- writes

    def record_metric_samples(self, device_id: int, rows: list) -> dict:
        """Every metric one poll produced, in one transaction rather than a
        per-sample commit (~2,000 fsyncs on a 500-port chassis). `kind` and `scope` are
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
                missing = [(device_id, key, label, unit, kind,
                            SCOPE_INTERFACE if "." in key else SCOPE_DEVICE)
                           for key, (label, unit, kind, _ts, _value) in latest.items()
                           if key not in ids]
                if missing:
                    self._conn.executemany(
                        "INSERT OR IGNORE INTO metrics(device_id, key, label, unit,"
                        " kind, scope) VALUES (?,?,?,?,?,?)", missing)
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
                    f" FROM candidates c CROSS JOIN"
                    f" {self._union_sql('samples_hourly')} sh"
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

        "Wide enough" is the metric's own class, read from the same row as
        the ownership check: a per-port metric keeps less raw history.
        """
        with self._lock:
            owner = self._conn.execute(
                "SELECT scope FROM metrics WHERE id = ? AND device_id = ?",
                (metric_id, device_id)).fetchone()
            if not owner:
                return []
            if (t1 - t0) <= raw_window_for_scope(owner["scope"]):
                raw = self._union_sql("samples")
                if bucket_s and bucket_s > 0:
                    rows = self._conn.execute(
                        f"SELECT (CAST(ts / ? AS INTEGER)) * ? AS bucket_ts,"
                        f" AVG(value) AS avg, MIN(value) AS min,"
                        f" MAX(value) AS max, COUNT(*) AS n FROM {raw}"
                        f" WHERE metric_id = ?"
                        f" AND ts >= ? AND ts <= ? GROUP BY 1 ORDER BY 1",
                        (bucket_s, bucket_s, metric_id, t0, t1)).fetchall()
                    return [{"ts": row["bucket_ts"], "avg": row["avg"],
                            "min": row["min"], "max": row["max"], "n": row["n"]}
                            for row in rows]
                rows = self._conn.execute(
                    f"SELECT ts, value FROM {raw} WHERE metric_id = ?"
                    f" AND ts >= ? AND ts <= ? ORDER BY ts",
                    (metric_id, t0, t1)).fetchall()
                return [{"ts": row["ts"], "value": row["value"]} for row in rows]
            rows = self._conn.execute(
                f"SELECT hour, n, vmin, vavg, vmax"
                f" FROM {self._union_sql('samples_hourly')}"
                f" WHERE metric_id = ? AND hour >= ? AND hour <= ?"
                f" ORDER BY hour", (metric_id, t0, t1)).fetchall()
            return [{"ts": row["hour"], "min": row["vmin"], "avg": row["vavg"],
                    "max": row["vmax"], "n": row["n"]} for row in rows]

    def owns_metric(self, device_id: int, metric_id: int) -> bool:
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM metrics WHERE id = ? AND device_id = ?",
                (metric_id, device_id)).fetchone() is not None

    def raw_window_s(self, device_id: int, metric_id: int) -> float:
        """The window width below which series() answers this metric from
        raw samples, or 0 for a metric this device does not own. Exists so
        nodesdb.series asks rather than keeping its own copy."""
        with self._lock:
            row = self._conn.execute(
                "SELECT scope FROM metrics WHERE id = ? AND device_id = ?",
                (metric_id, device_id)).fetchone()
        return 0.0 if row is None else raw_window_for_scope(row["scope"])

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
                # Once only, on a store that has never rolled up, whose
                # samples table is empty or an hour old.
                row = self._conn.execute(
                    f"SELECT MIN(ts) AS oldest"
                    f" FROM {self._union_sql('samples')}").fetchone()
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
            # One statement per metric-id band rather than one per hour
            # over the whole table: the aggregate is then a primary-key
            # range scan, already in the order the GROUP BY wants.
            for low, high in self._metric_bands():
                with self._lock:
                    source = self._union_sql("samples")
                    rows = self._conn.execute(
                        f"SELECT metric_id, COUNT(*) AS n, MIN(value) AS vmin,"
                        f" AVG(value) AS vavg, MAX(value) AS vmax"
                        f" FROM {source}"
                        f" WHERE metric_id >= ? AND metric_id <= ?"
                        f" AND ts >= ? AND ts < ? AND value IS NOT NULL"
                        f" GROUP BY metric_id",
                        (low, high, hour, hour + 3600)).fetchall()
                    if rows:
                        self._conn.executemany(
                            "INSERT INTO samples_hourly(metric_id, hour, n,"
                            " vmin, vavg, vmax) VALUES (?,?,?,?,?,?)"
                            " ON CONFLICT(metric_id, hour) DO UPDATE SET"
                            " n=excluded.n, vmin=excluded.vmin,"
                            " vavg=excluded.vavg, vmax=excluded.vmax",
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
        for base in ("samples", "samples_hourly"):
            for table in self._live_tables(base):
                got, done = self._delete_by_band(
                    table, where, (device_id,), deadline,
                    pause=self.PURGE_PAUSE_S,
                    bounds_where="device_id = ?", bounds_params=(device_id,))
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

    def cap_samples_per_metric(self, n: int, chunk: int = 200,
                               scope: int | None = None) -> int:
        """Keep at most the newest `n` raw samples of EACH metric, in
        chunks of `chunk` so a poll worker waits for at most one chunk's
        lock. Needs SQLite 3.25's window functions; older, does nothing
        and says so once. `scope` caps one metric class only, so the two
        retention tiers can be given different depths."""
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
        clause = "" if scope is None else f" WHERE scope = {int(scope)}"
        with self._lock:
            metric_ids = [row["id"] for row in self._conn.execute(
                f"SELECT id FROM metrics{clause}").fetchall()]
        removed = 0
        for table in self._live_tables("samples"):
            for batch in id_chunks(metric_ids, max(1, chunk)):
                marks = ",".join("?" * len(batch))
                with self._lock:
                    if not self._still_live("samples", table):
                        break
                    # The row value (metric_id, ts) in place of the rowid
                    # this table no longer has; row values need SQLite 3.15.
                    cursor = self._conn.execute(
                        f"DELETE FROM {table} WHERE (metric_id, ts) IN ("
                        f" SELECT metric_id, ts FROM ("
                        f"  SELECT metric_id, ts, ROW_NUMBER() OVER ("
                        f"   PARTITION BY metric_id ORDER BY ts DESC) AS rn"
                        f"  FROM {table} WHERE metric_id IN ({marks})"
                        f" ) WHERE rn > ?)", (*batch, int(n)))
                    removed += cursor.rowcount or 0
                    self._conn.commit()
        return removed

    def _prune_by_band(self, table: str, where: str, params,
                       interface_only: bool = False) -> int:
        """A by-age DELETE cut into lock-bounded batches by metric-id band.

        `samples` is the largest table in the product and this store guards
        one connection with one lock, so an unbatched sweep -- and above all
        the "delete every stored sample" the Settings maintenance button
        issues on the request thread -- held it for the whole delete, which
        is every chart read and every record_poll write queued behind it.

        Chunked by metric_id, the leading column of both primary keys; every
        batch still carries `where`, so the band decides only the cut-up.
        """
        removed, _ = self._delete_by_band(table, where, params, float("inf"),
                                          interface_only=interface_only)
        return removed

    def _delete_by_band(self, table: str, where: str, params, deadline: float,
                        pause: float = 0.0, interface_only: bool = False,
                        bounds_where: str = "", bounds_params=()) -> tuple[int, bool]:
        """_prune_by_band's body with a deadline: (rows removed, finished).
        Bands come from `metrics` (probing `samples` would be a full scan);
        `bounds_where` narrows them, so a purge starts at its device's ids."""
        scope_clause = ""
        probe_terms = []
        probe_params = list(bounds_params)
        if interface_only:
            scope_clause = (f" AND metric_id IN (SELECT id FROM metrics"
                            f" WHERE scope = {SCOPE_INTERFACE}"
                            f" AND id >= ? AND id < ?)")
            probe_terms.append(f"scope = {SCOPE_INTERFACE}")
        if bounds_where:
            probe_terms.append(f"({bounds_where})")
        scope_probe = (" WHERE " + " AND ".join(probe_terms)) if probe_terms else ""
        base = table[:-4] if table.endswith("_new") else table
        with self._lock:
            bounds = self._conn.execute(
                f"SELECT MIN(id) AS lo, MAX(id) AS hi"
                f" FROM metrics{scope_probe}", probe_params).fetchone()
        low = bounds["lo"]
        if low is None:
            return 0, True
        cut = bounds["hi"] + 1

        def delete(low_id: int, upper: int) -> int:
            if not self._still_live(base, table):
                return 0
            args = [low_id, upper, *params]
            if interface_only:
                args += [low_id, upper]
            cursor = self._conn.execute(
                f"DELETE FROM {table} WHERE metric_id >= ? AND metric_id < ?"
                f" AND {where}{scope_clause}", args)
            return cursor.rowcount or 0

        removed, reached = self._delete_batches(
            low, cut, deadline, delete, chunk=SAMPLE_BAND_METRICS_START,
            chunk_min=SAMPLE_BAND_METRICS_MIN,
            chunk_max=SAMPLE_BAND_METRICS_MAX, pause=pause)
        return removed, reached >= cut

    def prune(self, *, sample_days: float = 3, rollup_days: float = 400,
              interface_sample_days: float = 1,
              interface_rollup_days: float = 90,
              max_samples_per_metric: int = 0) -> int:
        """Age out raw samples and hourly rollups, in two passes per table.
        Per-port metrics are 94% of the rows, so they age out on their own
        pair of cutoffs; the unfiltered pass runs first. Passing 0 (the
        Settings maintenance button) matches every existing row."""
        removed = 0
        now = time.time()
        for table in self._live_tables("samples"):
            removed += self._prune_by_band(
                table, "ts < ?", (now - sample_days * 86400,))
            removed += self._prune_by_band(
                table, "ts < ?", (now - interface_sample_days * 86400,),
                interface_only=True)
        # The hourly rollups are the long history now, so they are
        # bounded by their own retention rather than kept forever.
        for table in self._live_tables("samples_hourly"):
            removed += self._prune_by_band(
                table, "hour < ?", (now - rollup_days * 86400,))
            removed += self._prune_by_band(
                table, "hour < ?",
                (now - interface_rollup_days * 86400,), interface_only=True)
        removed += self.cap_samples_per_metric(max_samples_per_metric)
        if removed:
            # Freed pages go back in short steps with the lock released
            # between them, not through a whole-file VACUUM.
            reclaim(self._conn, self._lock, label=self.LABEL)
        return removed

    # The flat floor under either table, and the per-metric ones above it.
    _TRIM_SAMPLE_FLOOR = 5_000
    _TRIM_RAW_PER_METRIC = 30
    _TRIM_HOURS_PER_METRIC = 24

    def _metric_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM metrics").fetchone()["n"]

    def _sample_floor(self) -> int:
        """How far down the raw samples may be trimmed: half an hour of
        polling per metric, or the flat floor, whichever is larger."""
        return max(self._TRIM_RAW_PER_METRIC * self._metric_count(),
                   self._TRIM_SAMPLE_FLOOR)

    def _hourly_floor(self) -> int:
        """How far down the rollups may be trimmed: a day of hours per
        metric, or the flat floor, whichever is larger -- below that a wide
        chart has nothing left to draw and the raw fallback is long gone."""
        return max(self._TRIM_HOURS_PER_METRIC * self._metric_count(),
                   self._TRIM_SAMPLE_FLOOR)

    def trim_to_size(self, max_bytes: int, budget_s: float | None = None) -> int:
        """Delete the oldest metric history until under the size cap: the
        hourly rollups first, then the raw samples.

        The rollups give first: their oldest hours cost a wide chart its far
        end, while raw rows are the window a 1-hour chart is about to read.
        Reclaim is incremental, not a VACUUM, and stage one deletes by
        `hour` ascending, clear of compact_rollup's redo window.
        """
        if max_bytes <= 0:
            return 0
        deadline = None if budget_s is None else time.monotonic() + max(0.0, budget_s)
        hourly_floor = self._hourly_floor()
        sample_floor = self._sample_floor()
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            # Raw gives only once the rollups are at their floor.
            gave = self._trim_hourly(hourly_floor)
            if not gave:
                gave = self._trim_raw(sample_floor)
            removed += gave
            reclaim(self._conn, self._lock, label=self.LABEL)
            # Neither table can give anything up; another pass would only
            # re-measure and reclaim what's already reclaimed.
            if not gave:
                break
        return removed

    def _trim_hourly(self, floor: int) -> int:
        """The oldest hours, by the hour index, in one statement per pass.
        The row value (metric_id, hour) stands in for the absent rowid."""
        removed = 0
        for table in self._live_tables("samples_hourly"):
            with self._lock:
                if not self._still_live("samples_hourly", table):
                    continue
                total = self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
                if total <= floor:
                    continue
                chunk = min(total - floor, max(int(total * 0.15), floor))
                cursor = self._conn.execute(
                    f"DELETE FROM {table} WHERE (metric_id, hour) IN ("
                    f" SELECT metric_id, hour FROM {table}"
                    f" ORDER BY hour ASC LIMIT ?)", (chunk,))
                removed += cursor.rowcount or 0
                self._conn.commit()
        return removed

    def _raw_holders(self) -> list[tuple[int, int, int]]:
        """(scope, raw rows, metrics holding raw rows) per class; an empty
        metric must not count toward the depth or the trim overshoots."""
        out = []
        for scope in (SCOPE_DEVICE, SCOPE_INTERFACE):
            rows = 0
            with self._lock:
                tables = self._live_tables("samples")
                exists = " OR ".join(
                    f"EXISTS (SELECT 1 FROM {table} s WHERE s.metric_id = m.id)"
                    for table in tables)
                for table in tables:
                    rows += self._conn.execute(
                        f"SELECT COUNT(*) AS n FROM {table} WHERE metric_id IN"
                        f" (SELECT id FROM metrics WHERE scope = ?)",
                        (scope,)).fetchone()["n"]
                holders = self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM metrics m"
                    f" WHERE m.scope = ? AND ({exists})",
                    (scope,)).fetchone()["n"]
            out.append((scope, rows, holders))
        return out

    def _trim_raw(self, floor: int) -> int:
        """Each metric's oldest raw samples, evenly within its class, down to
        `floor` rows in total. Not the globally oldest rows: `samples` has no
        index on ts, so that would be a full scan feeding a sorter holding
        15% of it. Per scope class, each giving up the same share of its own
        rows -- one depth across both tiers would cap a device-level metric
        to a port metric's day.
        """
        classes = self._raw_holders()
        total = sum(rows for _scope, rows, _holders in classes)
        if total <= floor:
            return 0
        want = min(total - floor, max(int(total * 0.15), floor))
        removed = 0
        for scope, rows, holders in classes:
            if not rows or not holders:
                continue
            share = -(-(want * rows) // total)
            # Rounded up, so the survivors land on or above the floor.
            keep = max(1, -(-(rows - share) // holders))
            removed += self.cap_samples_per_metric(keep, scope=scope)
        return removed

    # --------------------------------------------- the WITHOUT ROWID rewrite

    def _open_rewrite(self, table: str) -> None:
        """Decide at open what this table's rewrite still owes, and cache
        it: every delete path asks, several times per band."""
        state_key, cursor_key, end_key, freeze_key = _rewrite_keys(table)
        _key, _columns, ddl, _indexes = _REWRITE_SPEC[table]
        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,)).fetchone()
        if row is None:
            return
        have_new = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table + "_new",)).fetchone() is not None
        if "WITHOUT ROWID" in (row["sql"] or "").upper():
            # Created fresh, or a rewrite that finished. A crash between the
            # rename and the state write leaves "rewriting" on a done table.
            if not have_new:
                for stale in (state_key, cursor_key, end_key, freeze_key):
                    self._clear_private_setting(stale, commit=False)
                self._conn.commit()
            self._rewrite_state[table] = ""
            return
        state = self._private_setting(state_key, "") or ""
        # "rewriting" with no `_new` beside it is not resumable: start over.
        if state != "rewriting" or not have_new:
            self._conn.execute(f"DROP TABLE IF EXISTS {table}_new")
            self._conn.execute(ddl)
            bounds = self._conn.execute(
                f"SELECT MAX(metric_id) AS hi FROM {table}").fetchone()
            self._set_private_setting(cursor_key, 0, commit=False)
            self._set_private_setting(end_key, int((bounds["hi"] or 0)) + 1,
                                      commit=False)
            # Rows past the freeze are the live tail, caught up later.
            self._set_private_setting(freeze_key, time.time(), commit=False)
            self._set_private_setting(state_key, "rewriting", commit=False)
            log.info("nodes_series: %s is the old rowid shape; rewriting it "
                     "WITHOUT ROWID in metric-id bands", table)
        self._rewrite_state[table] = "rewriting"

    def _rewriting(self, table: str) -> bool:
        return self._rewrite_state.get(table) == "rewriting"

    def _live_tables(self, table: str) -> tuple[str, ...]:
        """`table`, plus the half-written `_new` beside it mid-rewrite. Every
        delete path iterates it, or "delete everything" would miss a half."""
        return (table, table + "_new") if self._rewriting(table) else (table,)

    def _still_live(self, base: str, table: str) -> bool:
        """Whether `table` is still one of `base`'s halves. With the lock
        held, immediately before the statement: a caller that walked
        _live_tables once hits "no such table" if the rename landed."""
        return table in self._live_tables(base)

    def _union_sql(self, table: str) -> str:
        """A FROM-clause source covering both halves of a split table.

        A writer can put a key back in the old table after its band has
        passed (compact_rollup rewriting an hour, a re-poll of the same
        timestamp), and the old table holds the fresher row, so the new half
        contributes only keys the old one lacks.
        """
        if not self._rewriting(table):
            return table
        key, columns, _ddl, _indexes = _REWRITE_SPEC[table]
        return (f"(SELECT {columns} FROM {table} UNION ALL"
                f" SELECT {columns} FROM {table}_new _new WHERE NOT EXISTS ("
                f" SELECT 1 FROM {table} _old"
                f" WHERE _old.metric_id = _new.metric_id"
                f" AND _old.{key} = _new.{key}))")

    def _metric_bands(self, width: int | None = None):
        """Contiguous (low, high) metric-id ranges covering every metric."""
        with self._lock:
            ids = [row[0] for row in self._conn.execute(
                "SELECT id FROM metrics ORDER BY id").fetchall()]
        for chunk in id_chunks(ids, self._IDS_PER_QUERY if width is None
                               else max(1, int(width))):
            yield chunk[0], chunk[-1]

    def rewrite_pending(self) -> bool:
        """Whether any table still owes a rewrite."""
        return any(self._rewriting(table) for table in _REWRITE_SPEC)

    def rewrite_progress(self) -> dict:
        """{table: (cursor, end)} mid-rewrite, for the report's note."""
        out = {}
        for table in _REWRITE_SPEC:
            if not self._rewriting(table):
                continue
            _state, cursor_key, end_key, _freeze = _rewrite_keys(table)
            out[table] = (int(self._private_setting(cursor_key, 0) or 0),
                          int(self._private_setting(end_key, 0) or 0))
        return out

    def continue_rewrite(self, stop=None, log_add=None) -> bool:
        """Rewrite whatever is still owed, one table at a time. Stops on
        `stop` between bands with the cursor persisted, so the next start
        resumes."""
        for table in _REWRITE_SPEC:
            if not self._rewriting(table):
                continue
            started = time.monotonic()
            if not self._rewrite_table(table, stop=stop):
                return False
            if log_add is not None:
                log_add(f"Nodes: rewrote {table} into its smaller "
                        f"WITHOUT ROWID form "
                        f"({time.monotonic() - started:.0f} s)")
        return True

    def _rewrite_table(self, table: str, *, stop=None,
                       band: int | None = None) -> bool:
        """Copy-and-delete `table` into `<table>_new` band by band, then
        rename. Returns False when `stop` interrupted it."""
        key, columns, _ddl, _indexes = _REWRITE_SPEC[table]
        _state_key, cursor_key, end_key, freeze_key = _rewrite_keys(table)
        cursor = int(self._private_setting(cursor_key, 0) or 0)
        end = int(self._private_setting(end_key, 0) or 0)
        freeze = float(self._private_setting(freeze_key, 0) or 0)
        width = REWRITE_BAND_METRICS if band is None else int(band)

        def bands(cursor: int, freeze: float, width: int) -> tuple[bool, int]:
            """[cursor, end) one band at a time; (uninterrupted, width)."""
            while cursor < end:
                if stop is not None and stop.is_set():
                    return False, width
                upper = min(cursor + width, end)
                started = time.monotonic()
                # Per band, not around the loop: the rewrite runs for
                # minutes, and polling and charts want this connection too.
                with self._lock:
                    self._conn.execute(
                        f"INSERT OR REPLACE INTO {table}_new({columns})"
                        f" SELECT {columns} FROM {table}"
                        f" WHERE metric_id >= ? AND metric_id < ?"
                        f" AND {key} < ?", (cursor, upper, freeze))
                    self._conn.execute(
                        f"DELETE FROM {table} WHERE metric_id >= ?"
                        f" AND metric_id < ? AND {key} < ?",
                        (cursor, upper, freeze))
                    self._set_private_setting(cursor_key, upper, commit=False)
                    self._conn.commit()
                held = time.monotonic() - started
                cursor = upper
                if held > REWRITE_LOCK_TARGET_S:
                    width = max(REWRITE_BAND_MIN, width // 2)
                elif held < REWRITE_LOCK_TARGET_S / 4:
                    width = min(REWRITE_BAND_MAX, width * 2)
            return True, width

        ok, width = bands(cursor, freeze, width)
        if not ok:
            return False
        # The freeze was taken when the rewrite opened, so every row written
        # since is still in the old table for _finish_rewrite to copy in one
        # transaction. Re-band against an advanced freeze, `end` moving with
        # it, until the remainder is small. Bounded: a tail the poller keeps
        # extending is never caught.
        for _ in range(REWRITE_CATCHUP_PASSES):
            with self._lock:
                left = self._conn.execute(
                    f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                hi = self._conn.execute(
                    "SELECT MAX(id) AS hi FROM metrics").fetchone()["hi"]
            if left <= REWRITE_TAIL_ROWS:
                break
            end = max(end, int(hi or 0) + 1)
            freeze = time.time()
            self._set_private_setting(end_key, end, commit=False)
            self._set_private_setting(freeze_key, freeze, commit=False)
            self._set_private_setting(cursor_key, 0)
            ok, width = bands(0, freeze, width)
            if not ok:
                return False
        return self._finish_rewrite(table)

    def _finish_rewrite(self, table: str) -> bool:
        """The last transaction: catch up the live tail, check no key was
        left behind, drop, rename, rebuild the indexes. The gate is
        `left == 0` alone -- a row count cannot be an invariant while the
        poller inserts; safety comes from the copy, the delete and the
        cursor sharing one transaction."""
        key, columns, _ddl, indexes = _REWRITE_SPEC[table]
        state_key, cursor_key, end_key, freeze_key = _rewrite_keys(table)
        with self._lock:
            # A pragma is a no-op mid-transaction, and a read may hold one.
            self._conn.commit()
            self._conn.execute("PRAGMA foreign_keys=OFF")
            self._conn.execute("PRAGMA legacy_alter_table=ON")
            try:
                self._conn.execute(
                    f"INSERT OR REPLACE INTO {table}_new({columns})"
                    f" SELECT {columns} FROM {table}")
                left = self._conn.execute(
                    f"SELECT COUNT(*) FROM {table} o WHERE NOT EXISTS ("
                    f" SELECT 1 FROM {table}_new n WHERE n.metric_id ="
                    f" o.metric_id AND n.{key} = o.{key})").fetchone()[0]
                after = self._conn.execute(
                    f"SELECT COUNT(*) FROM {table}_new").fetchone()[0]
                if left:
                    self._conn.rollback()
                    log.error("nodes_series: %s rewrite left %d rows "
                              "uncopied (%d in the new table); keeping the "
                              "old table and retrying on the next start",
                              table, left, after)
                    return False
                self._conn.execute(f"DROP TABLE {table}")
                self._conn.execute(
                    f"ALTER TABLE {table}_new RENAME TO {table}")
                for ddl in indexes:
                    self._conn.execute(ddl)
                # In the renaming transaction, under its lock: a caller
                # holding a captured `_new` must not still read "rewriting".
                self._set_private_setting(state_key, "done", commit=False)
                for stale in (cursor_key, end_key, freeze_key):
                    self._clear_private_setting(stale, commit=False)
                self._conn.commit()
                self._rewrite_state[table] = "done"
            except sqlite3.DatabaseError:
                # Before the pragmas, which are no-ops mid-transaction.
                self._conn.rollback()
                raise
            finally:
                self._conn.execute("PRAGMA legacy_alter_table=OFF")
                self._conn.execute("PRAGMA foreign_keys=ON")
        log.info("nodes_series: %s is now WITHOUT ROWID (%d rows)",
                 table, after)
        reclaim(self._conn, self._lock, label=self.LABEL)
        return True

    def rewrite_now(self, band: int | None = None) -> bool:
        """The whole rewrite, synchronously: tests and the demo seeder."""
        return all(self._rewrite_table(table, band=band)
                   for table in list(_REWRITE_SPEC) if self._rewriting(table))

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
                " unit, kind, last_value, last_ts, scope)"
                " SELECT id, device_id, key, label, unit, kind, last_value,"
                " last_ts, key LIKE '%.%' FROM old.metrics")
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
        # Over the union: rows already lifted across may sit in the new
        # half, and counting only the old one would copy them twice.
        here = self._union_sql("samples_hourly").replace(
            "samples_hourly", "main.samples_hourly")
        with self._lock, self._attached(legacy_path) as conn:
            row = conn.execute(
                f"SELECT COUNT(*) FROM old.samples_hourly sh WHERE sh.hour >= ?"
                f" AND EXISTS (SELECT 1 FROM main.metrics m"
                f"             WHERE m.id = sh.metric_id)"
                f" AND NOT EXISTS (SELECT 1 FROM {here} h"
                f"                 WHERE h.metric_id = sh.metric_id"
                f"                   AND h.hour = sh.hour)", (floor,)).fetchone()
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
