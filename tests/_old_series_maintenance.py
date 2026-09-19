"""A frozen reference copy of nodesseriesdb.py's pre-rewrite maintenance
bodies, for test_series_maintenance_equivalence.py and bench_prune.py's
--oracle mode only -- never import this from product code.
"""
import time

from netpath import nodesseriesdb
from netpath.nodesseriesdb import SCOPE_INTERFACE
from netpath.sqlitebase import reclaim


def old_compact_rollup(db, max_hours=48):
    now = time.time()
    latest_complete = int(now // 3600) * 3600 - 3600
    watermark = db._private_setting(db._ROLLUP_WATERMARK)
    if watermark is None:
        with db._lock:
            row = db._conn.execute(
                f"SELECT MIN(ts) AS oldest"
                f" FROM {db._union_sql('samples')}").fetchone()
        oldest = row["oldest"] if row else None
        if oldest is None:
            db._set_private_setting(db._ROLLUP_WATERMARK, latest_complete + 3600)
            return 0
        hour = int(float(oldest) // 3600) * 3600
    else:
        hour = int(watermark) - db._ROLLUP_REDO_HOURS * 3600
    written = 0
    processed = 0
    while hour <= latest_complete and processed < max_hours:
        for low, high in db._metric_bands():
            with db._lock:
                source = db._union_sql("samples")
                rows = db._conn.execute(
                    f"SELECT metric_id, COUNT(*) AS n, MIN(value) AS vmin,"
                    f" AVG(value) AS vavg, MAX(value) AS vmax"
                    f" FROM {source}"
                    f" WHERE metric_id >= ? AND metric_id <= ?"
                    f" AND ts >= ? AND ts < ? AND value IS NOT NULL"
                    f" GROUP BY metric_id",
                    (low, high, hour, hour + 3600)).fetchall()
                if rows:
                    db._conn.executemany(
                        "INSERT INTO samples_hourly(metric_id, hour, n,"
                        " vmin, vavg, vmax) VALUES (?,?,?,?,?,?)"
                        " ON CONFLICT(metric_id, hour) DO UPDATE SET"
                        " n=excluded.n, vmin=excluded.vmin,"
                        " vavg=excluded.vavg, vmax=excluded.vmax",
                        [(r["metric_id"], hour, r["n"], r["vmin"],
                          r["vavg"], r["vmax"]) for r in rows])
                    written += len(rows)
                db._conn.commit()
        hour += 3600
        processed += 1
    db._set_private_setting(db._ROLLUP_WATERMARK, hour)
    return written


def old_delete_by_band(db, table, where, params, deadline, pause=0.0,
                       interface_only=False, bounds_where="", bounds_params=()):
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
    with db._lock:
        bounds = db._conn.execute(
            f"SELECT MIN(id) AS lo, MAX(id) AS hi"
            f" FROM metrics{scope_probe}", probe_params).fetchone()
    low = bounds["lo"]
    if low is None:
        return 0, True
    cut = bounds["hi"] + 1

    def delete(low_id, upper):
        if not db._still_live(base, table):
            return 0
        args = [low_id, upper, *params]
        if interface_only:
            args += [low_id, upper]
        cursor = db._conn.execute(
            f"DELETE FROM {table} WHERE metric_id >= ? AND metric_id < ?"
            f" AND {where}{scope_clause}", args)
        return cursor.rowcount or 0

    removed, reached = db._delete_batches(
        low, cut, deadline, delete,
        chunk=nodesseriesdb.SAMPLE_BAND_METRICS_START,
        chunk_min=nodesseriesdb.SAMPLE_BAND_METRICS_MIN,
        chunk_max=nodesseriesdb.SAMPLE_BAND_METRICS_MAX, pause=pause)
    return removed, reached >= cut


def old_prune_by_band(db, table, where, params, interface_only=False):
    removed, _ = old_delete_by_band(db, table, where, params, float("inf"),
                                    interface_only=interface_only)
    return removed


def old_prune(db, *, sample_days=3, rollup_days=400, interface_sample_days=1,
             interface_rollup_days=90, max_samples_per_metric=0):
    """The pre-rewrite prune(): unconditional cap call, no poll_interval_s."""
    removed = 0
    now = time.time()
    for table in db._live_tables("samples"):
        removed += old_prune_by_band(db, table, "ts < ?",
                                     (now - sample_days * 86400,))
        removed += old_prune_by_band(db, table, "ts < ?",
                                     (now - interface_sample_days * 86400,),
                                     interface_only=True)
    for table in db._live_tables("samples_hourly"):
        removed += old_prune_by_band(db, table, "hour < ?",
                                     (now - rollup_days * 86400,))
        removed += old_prune_by_band(db, table, "hour < ?",
                                     (now - interface_rollup_days * 86400,),
                                     interface_only=True)
    removed += db.cap_samples_per_metric(max_samples_per_metric)
    if removed:
        reclaim(db._conn, db._lock, label=db.LABEL)
    return removed


def old_trim_hourly(db, floor):
    removed = 0
    for table in db._live_tables("samples_hourly"):
        with db._lock:
            if not db._still_live("samples_hourly", table):
                continue
            total = db._conn.execute(
                f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            if total <= floor:
                continue
            chunk = min(total - floor, max(int(total * 0.15), floor))
            cursor = db._conn.execute(
                f"DELETE FROM {table} WHERE (metric_id, hour) IN ("
                f" SELECT metric_id, hour FROM {table}"
                f" ORDER BY hour ASC LIMIT ?)", (chunk,))
            removed += cursor.rowcount or 0
            db._conn.commit()
    return removed
