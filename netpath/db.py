"""SQLite persistence for the NetPath module: destinations, traces and hops.

This file holds traceroute records and the NetPath module's own settings, and
nothing else. Global settings, user accounts and the shared reverse-DNS cache
moved to appdb.py, which is what every module reads them from.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time

from statistics import mean

from . import dbmaint, dbopen, settingsutil
from .tracer import TraceResult

log = logging.getLogger(__name__)

# Trimming a database back under its size cap: rows are deleted in fixed
# batches, each in its own short transaction, so the write lock is never held
# for more than one batch. The old shape deleted 15% of the table and then
# VACUUMed the whole file with the lock held, up to six times per maintenance
# pass — measured at a 4.1 s stall on one insert against a 232 MB file, and it
# still finished above the cap and reported success.
TRIM_CHUNK = 2_000           # rows per lock acquisition, adapted below
TRIM_CHUNK_MIN = 500
TRIM_CHUNK_MAX = 50_000
TRIM_LOCK_TARGET_S = 0.15    # how long one batch may hold the write lock
TRIM_PASSES = 40             # delete/reclaim rounds before giving up
TRIM_BUDGET_S = 30.0         # wall clock for one trim_to_size call

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY,
    host        TEXT    NOT NULL UNIQUE,
    label       TEXT,
    interval_s  INTEGER NOT NULL DEFAULT 300,
    max_hops    INTEGER NOT NULL DEFAULT 30,
    probes      INTEGER NOT NULL DEFAULT 3,
    warn_rtt_ms REAL    NOT NULL DEFAULT 150,
    warn_loss   REAL    NOT NULL DEFAULT 10,
    timeout_s   REAL    NOT NULL DEFAULT 2.0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_ts  REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS traces (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    started_ts REAL    NOT NULL,
    duration_s REAL,
    status     TEXT    NOT NULL,
    reached    INTEGER NOT NULL,
    hop_count  INTEGER,
    rtt_ms     REAL,
    loss_pct   REAL,
    path_sig   TEXT,
    error      TEXT,
    icmp_code  TEXT,
    icmp_from  TEXT
);
CREATE INDEX IF NOT EXISTS ix_traces_target_ts ON traces(target_id, started_ts);

CREATE TABLE IF NOT EXISTS hops (
    id       INTEGER PRIMARY KEY,
    trace_id INTEGER NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
    ttl      INTEGER NOT NULL,
    ip       TEXT,
    rtt_ms   REAL,
    loss_pct REAL
);
CREATE INDEX IF NOT EXISTS ix_hops_trace ON hops(trace_id, ttl);
CREATE INDEX IF NOT EXISTS ix_hops_ip ON hops(ip);

CREATE TABLE IF NOT EXISTS hop_stats (
    target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL,
    probes     INTEGER NOT NULL DEFAULT 0,
    lost       INTEGER NOT NULL DEFAULT 0,
    rtt_sum    REAL    NOT NULL DEFAULT 0,
    rtt_min    REAL,
    rtt_max    REAL,
    updated_ts REAL    NOT NULL,
    PRIMARY KEY (target_id, ip)
);

-- NetPath's own settings. Global ones are in app.db; NetFlow and Syslog keep
-- theirs in their own files.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# NetPath only.
NETPATH_DEFAULTS = {
    "trace_workers": 4,
    "trace_retention_days": 90,
    "default_interval_s": 300,
    "default_max_hops": 30,
    "default_probes": 3,
    "default_timeout_s": 2.0,
    "default_warn_rtt_ms": 150.0,
    "default_warn_loss": 10.0,
    # Hours a hop may go unseen before it drops out of the path diagram. Aged
    # against the end of the displayed window rather than the clock, so panning
    # back through history still draws the path as it was then.
    "topology_stale_hours": 24.0,
}

# Kept as a name because settings dicts are passed around merged: this module
# and appdb.py each filter a merged dict down to the keys they own.
APP_DEFAULTS = NETPATH_DEFAULTS

# Bounds on the numbers a target row (add_target/update_target) or the
# matching global defaults (save_settings) may carry. Neither route validated
# these before now -- coerce_settings (settingsutil.py) only checks that a
# value is *a number*, never that it is a sane one -- and four of them are not
# cosmetic: they are handed straight to a subprocess argument, a per-run
# time budget, or a thread pool size.
#
#   max_hops  -> tracer._build_command's "-h"/"-m": a raw CLI argument to the
#                traceroute/tracert binary, and a term in expected_budget's
#                worst-case-runtime arithmetic. TTL is one byte on the wire,
#                so no path is ever more than 255 hops regardless of what a
#                target claims.
#   probes    -> tracer._build_command's "-q" (Linux only; Windows tracert
#                always sends exactly 3 and ignores this): how many probe
#                packets go out at *every* hop, and also a term in
#                expected_budget. An unbounded value is both a probe flood
#                against every router on the path and a way to stretch one
#                trace's worst-case runtime arbitrarily far.
#   timeout_s -> tracer._build_command's "-w": too low starves every probe
#                before a reply can arrive; too high multiplies through
#                expected_budget the same way an inflated probes count does.
#   interval_s -> monitor.py's scheduler: `next_run = last_run + interval_s`.
#                At or below zero a target is perpetually "due", so the
#                scheduler launches a fresh traceroute subprocess against it
#                as fast as the worker pool can turn them over -- a spawn
#                storm and a probe flood aimed at one destination, the same
#                shape ipam_scan.py's own docstring already describes for an
#                unpaced ping sweep.
#   trace_workers -> service.py hands this straight to
#                ThreadPoolExecutor(max_workers=...); it is a settings-level
#                default, not a per-target field, but the same "never
#                checked past being a number" gap.
#
# warn_rtt_ms/warn_loss reach neither a subprocess, a loop bound nor an
# allocation -- only classify()'s comparison in monitor.py -- so they are
# clamped to what is merely sane (non-negative; a percentage) rather than
# to a mechanism-driven ceiling.
MIN_INTERVAL_S, MAX_INTERVAL_S = 5.0, 30 * 24 * 3600.0
MIN_MAX_HOPS, MAX_MAX_HOPS = 1, 255
MIN_PROBES, MAX_PROBES = 1, 20
MIN_TIMEOUT_S, MAX_TIMEOUT_S = 0.1, 30.0
MIN_TRACE_WORKERS, MAX_TRACE_WORKERS = 1, 64


def _clamp(value, lo, hi, kind=float):
    try:
        value = kind(value)
    except (TypeError, ValueError):
        return lo
    return min(max(value, lo), hi)


def _clamp_target_fields(fields: dict) -> dict:
    """Bounds-check the numeric target fields present in `fields`, in place.

    Applied by both add_target and update_target so a target can never be
    written -- however it got here -- with a value that turns the next
    traceroute run against it into an unbounded subprocess argument or an
    unpaced spawn loop. Fields not present are left untouched; update_target
    already filters to its own allow-list before this runs.
    """
    if "interval_s" in fields:
        fields["interval_s"] = _clamp(fields["interval_s"], MIN_INTERVAL_S,
                                      MAX_INTERVAL_S, int)
    if "max_hops" in fields:
        fields["max_hops"] = _clamp(fields["max_hops"], MIN_MAX_HOPS,
                                    MAX_MAX_HOPS, int)
    if "probes" in fields:
        fields["probes"] = _clamp(fields["probes"], MIN_PROBES, MAX_PROBES, int)
    if "timeout_s" in fields:
        fields["timeout_s"] = _clamp(fields["timeout_s"], MIN_TIMEOUT_S,
                                     MAX_TIMEOUT_S, float)
    if "warn_rtt_ms" in fields:
        fields["warn_rtt_ms"] = _clamp(fields["warn_rtt_ms"], 0.0,
                                       float("inf"), float)
    if "warn_loss" in fields:
        fields["warn_loss"] = _clamp(fields["warn_loss"], 0.0, 100.0, float)
    return fields


class Database:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = dbopen.connect(path)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            dbmaint.enable_incremental_vacuum(self._conn, "netpath.db")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS silently leaves an existing table alone, so
        new columns have to be added explicitly or an upgraded install fails on
        first write.
        """
        traces = {row["name"] for row in
                  self._conn.execute("PRAGMA table_info(traces)").fetchall()}
        for column, definition in [("icmp_code", "TEXT"), ("icmp_from", "TEXT")]:
            if column not in traces:
                self._conn.execute(
                    f"ALTER TABLE traces ADD COLUMN {column} {definition}")

        targets = {row["name"] for row in
                   self._conn.execute("PRAGMA table_info(targets)").fetchall()}
        if "timeout_s" not in targets:
            self._conn.execute(
                "ALTER TABLE targets ADD COLUMN timeout_s REAL NOT NULL DEFAULT 2.0")
        if "hop_probe_enabled" not in targets:
            self._conn.execute(
                "ALTER TABLE targets ADD COLUMN hop_probe_enabled INTEGER NOT NULL DEFAULT 0")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = dict(APP_DEFAULTS)
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        for row in rows:
            if row["key"] in values:
                try:
                    values[row["key"]] = json.loads(row["value"])
                except (ValueError, TypeError):
                    pass
        return settingsutil.coerce_settings(NETPATH_DEFAULTS, values, strict=False)

    def save_settings(self, values: dict) -> None:
        values = dict(values)
        if "trace_workers" in values:
            values["trace_workers"] = _clamp(
                values["trace_workers"], MIN_TRACE_WORKERS, MAX_TRACE_WORKERS, int)
        # The five default_* keys are exactly the target fields under a
        # prefix -- new targets are created from them (post_target's
        # `defaults["default_probes"]` etc., api.py) -- so they get the
        # identical clamp add_target/update_target apply to a target's own
        # values, by stripping and restoring the prefix around the same
        # helper rather than duplicating its bounds.
        defaulted = {k[len("default_"):]: v for k, v in values.items()
                    if k.startswith("default_") and k in APP_DEFAULTS}
        _clamp_target_fields(defaulted)
        for key, value in defaulted.items():
            values[f"default_{key}"] = value
        with self._lock:
            for key, value in values.items():
                if key not in APP_DEFAULTS:
                    continue
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)),
                )
            self._conn.commit()

    # ---------------------------------------------------------------- targets

    def add_target(
        self,
        host: str,
        label: str | None = None,
        interval_s: int = 300,
        max_hops: int = 30,
        probes: int = 3,
        warn_rtt_ms: float = 150.0,
        warn_loss: float = 10.0,
        timeout_s: float = 2.0,
    ) -> int:
        fields = _clamp_target_fields({
            "interval_s": interval_s, "max_hops": max_hops, "probes": probes,
            "warn_rtt_ms": warn_rtt_ms, "warn_loss": warn_loss,
            "timeout_s": timeout_s,
        })
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO targets(host, label, interval_s, max_hops, probes,"
                " warn_rtt_ms, warn_loss, timeout_s, enabled, created_ts)"
                " VALUES (?,?,?,?,?,?,?,?,1,?)",
                (host, label or host, fields["interval_s"], fields["max_hops"],
                 fields["probes"], fields["warn_rtt_ms"], fields["warn_loss"],
                 fields["timeout_s"], time.time()),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def update_target(self, target_id: int, **fields) -> None:
        allowed = {
            "host", "label", "interval_s", "max_hops", "probes",
            "warn_rtt_ms", "warn_loss", "timeout_s", "enabled",
            "hop_probe_enabled",
        }
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        _clamp_target_fields(sets)
        clause = ", ".join(f"{k}=?" for k in sets)
        with self._lock:
            self._conn.execute(
                f"UPDATE targets SET {clause} WHERE id=?",
                (*sets.values(), target_id),
            )
            self._conn.commit()

    def remove_target(self, target_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM hops WHERE trace_id IN "
                               "(SELECT id FROM traces WHERE target_id=?)", (target_id,))
            self._conn.execute("DELETE FROM traces WHERE target_id=?", (target_id,))
            self._conn.execute("DELETE FROM hop_stats WHERE target_id=?", (target_id,))
            self._conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
            self._conn.commit()

    def targets(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM targets ORDER BY label COLLATE NOCASE"
            ).fetchall()

    def target(self, target_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM targets WHERE id=?", (target_id,)
            ).fetchone()

    # ----------------------------------------------------------------- traces

    def record_trace(self, target_id: int, result: TraceResult, status: str) -> int:
        rtt = result.dest_rtt()
        loss = result.dest_loss() if result.hops else 100.0
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO traces(target_id, started_ts, duration_s, status, reached,"
                " hop_count, rtt_ms, loss_pct, path_sig, error, icmp_code, icmp_from)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    target_id,
                    result.started_ts,
                    result.duration_s,
                    status,
                    1 if result.reached else 0,
                    len(result.hops),
                    rtt,
                    loss,
                    result.path_signature() if result.hops else None,
                    result.error,
                    result.unreachable_code,
                    result.unreachable_from,
                ),
            )
            trace_id = int(cur.lastrowid)
            rows = []
            for hop in result.hops:
                if not hop.addrs:
                    rows.append((trace_id, hop.ttl, None, None, hop.loss_pct))
                    continue
                for ip, rtts in hop.addrs.items():
                    rows.append((
                        trace_id, hop.ttl, ip,
                        mean(rtts) if rtts else None,
                        hop.loss_pct,
                    ))
            if rows:
                self._conn.executemany(
                    "INSERT INTO hops(trace_id, ttl, ip, rtt_ms, loss_pct) VALUES (?,?,?,?,?)",
                    rows,
                )
            self._conn.commit()
            return trace_id

    def record_overrun(self, target_id: int, scheduled_ts: float,
                       running_since: float | None, note: str) -> int:
        """A scheduled run that never started, because the last one is still going.

        Written as a real row rather than left as a gap: a missing block reads
        as "the app was not running", which is a different problem with a
        different fix. This one says the interval is too short for the path.
        """
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO traces(target_id, started_ts, duration_s, status,"
                " reached, hop_count, rtt_ms, loss_pct, path_sig, error)"
                " VALUES (?,?,?,?,0,0,NULL,NULL,NULL,?)",
                (target_id, scheduled_ts,
                 (scheduled_ts - running_since) if running_since else None,
                 "overrun", note),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def last_trace(self, target_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM traces WHERE target_id=? ORDER BY started_ts DESC LIMIT 1",
                (target_id,),
            ).fetchone()

    def last_traces(self, target_ids: list[int]) -> dict[int, sqlite3.Row]:
        """last_trace() for many targets in one query — target_id -> row.
        A target with no traces yet is simply absent from the result."""
        if not target_ids:
            return {}
        marks = ",".join("?" * len(target_ids))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT t.* FROM traces t"
                f" JOIN (SELECT target_id, MAX(started_ts) AS ts FROM traces"
                f" WHERE target_id IN ({marks}) GROUP BY target_id) latest"
                f" ON t.target_id = latest.target_id AND t.started_ts = latest.ts",
                target_ids,
            ).fetchall()
        return {row["target_id"]: row for row in rows}

    def traces_between(self, target_id: int, t0: float, t1: float) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM traces WHERE target_id=? AND started_ts>=? AND started_ts<=?"
                " ORDER BY started_ts",
                (target_id, t0, t1),
            ).fetchall()

    def reach_summary(self, target_id: int, t0: float, t1: float) -> dict:
        """{"traces": n, "unreached": n, "measured": n} over a window.

        Counted in SQLite rather than by reading every row back, because the
        alert engine asks this per destination on every tick and the answer is
        three integers.

        `measured` excludes the statuses that are a fault in the measurement
        rather than in the path — a traceroute that could not run at all, and
        a slot skipped because the previous run was still going. Counting
        those as unreachable would report a missing traceroute binary or a
        badly chosen interval as a network outage.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS traces,"
                " SUM(CASE WHEN status NOT IN ('error','overrun') THEN 1 ELSE 0 END) AS measured,"
                " SUM(CASE WHEN status NOT IN ('error','overrun') AND reached = 0"
                "     THEN 1 ELSE 0 END) AS unreached"
                " FROM traces WHERE target_id=? AND started_ts>=? AND started_ts<=?",
                (target_id, t0, t1)).fetchone()
        return {"traces": row["traces"] or 0,
                "measured": row["measured"] or 0,
                "unreached": row["unreached"] or 0}

    def hop_rows_between(self, target_id: int, t0: float, t1: float) -> list[sqlite3.Row]:
        """Flat join of hops to traces, used to build the path topology."""
        with self._lock:
            return self._conn.execute(
                "SELECT t.id AS trace_id, t.started_ts, h.ttl, h.ip, h.rtt_ms, h.loss_pct"
                " FROM traces t JOIN hops h ON h.trace_id = t.id"
                " WHERE t.target_id=? AND t.started_ts>=? AND t.started_ts<=?"
                " ORDER BY t.started_ts, h.ttl",
                (target_id, t0, t1),
            ).fetchall()

    # ------------------------------------------------- addresses to be named

    def distinct_hop_ips(self, limit: int = 2000) -> list[str]:
        """Every hop address seen, most recent first.

        The reverse-DNS cache lives in app.db now, so this can no longer be a
        join that returns only the unknown ones. Instead this returns the
        candidates and AppDatabase.unknown_ips filters them. The set is bounded
        by the number of distinct routers on the monitored paths — hundreds,
        not millions — and ix_hops_ip keeps it an index scan.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, MAX(id) AS seen FROM hops WHERE ip IS NOT NULL"
                " GROUP BY ip ORDER BY seen DESC LIMIT ?", (limit,)).fetchall()
        return [row["ip"] for row in rows]

    def hop_ip_count(self) -> int:
        """Distinct hop addresses, for the "pending lookups" figure."""
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(DISTINCT ip) AS n FROM hops"
                " WHERE ip IS NOT NULL").fetchone()["n"] or 0

    def destination_ip(self, target_id: int) -> str | None:
        """Address of the final hop of the most recent trace that got through.

        Read from stored data rather than resolving again, so the UI never
        blocks on DNS.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT h.ip AS ip FROM traces t JOIN hops h ON h.trace_id = t.id"
                " WHERE t.target_id=? AND t.reached=1 AND h.ip IS NOT NULL"
                " ORDER BY t.started_ts DESC, h.ttl DESC LIMIT 1",
                (target_id,),
            ).fetchone()
        return row["ip"] if row else None

    def target_by_destination_ip(self, ip: str) -> sqlite3.Row | None:
        """The target whose most recent successful trace ended exactly at this IP.

        Reuses destination_ip()'s "final hop of the most recent reached trace"
        definition rather than matching any hop along the path, so a shared
        upstream router does not make every flow through it look like it went
        to the same place. Target counts are small (a handful to a few dozen),
        so a per-target scan of already-indexed queries is simpler and safer
        than trying to encode the same "final hop" logic in one raw join.
        """
        with self._lock:
            targets = self._conn.execute("SELECT id FROM targets").fetchall()
        best_ts, best_id = None, None
        for row in targets:
            target_id = row["id"]
            if self.destination_ip(target_id) != ip:
                continue
            last = self.last_trace(target_id)
            if last is None:
                continue
            if best_ts is None or last["started_ts"] > best_ts:
                best_ts, best_id = last["started_ts"], target_id
        return self.target(best_id) if best_id is not None else None

    def targets_by_destination_ips(self, ips) -> dict[str, int]:
        """Bulk form of target_by_destination_ip, for annotating many flow rows
        without one query per row."""
        wanted = set(ips)
        if not wanted:
            return {}
        with self._lock:
            targets = self._conn.execute("SELECT id FROM targets").fetchall()
        best: dict[str, tuple[float, int]] = {}
        for row in targets:
            target_id = row["id"]
            ip = self.destination_ip(target_id)
            if ip not in wanted:
                continue
            last = self.last_trace(target_id)
            if last is None:
                continue
            ts = last["started_ts"]
            if ip not in best or ts > best[ip][0]:
                best[ip] = (ts, target_id)
        return {ip: target_id for ip, (ts, target_id) in best.items()}

    # -------------------------------------------------------- continuous probing

    def record_hop_probe(self, target_id: int, ip: str, result) -> None:
        """Upsert running probe counters for one hop. Never stores per-probe
        rows — probes/lost/rtt_sum/rtt_min/rtt_max are cumulative counters, so
        a target probed every few seconds for days does not bloat the table."""
        self.record_hop_probes([(target_id, ip, result)])

    def record_hop_probes(self, probes) -> int:
        """Fold a whole round of hop probes into hop_stats in one transaction.

        One SELECT + UPSERT + commit per probe meant ten opted-in targets with
        fifteen hops each committing 150 times every four seconds, on the same
        database and the same lock the trace scheduler writes traces to. A
        round is a batch: one read of the rows it touches, one executemany,
        one commit.
        """
        wanted = {(target_id, ip) for target_id, ip, _ in probes}
        if not wanted:
            return 0
        with self._lock:
            existing = {}
            for target_id, ip in wanted:
                row = self._conn.execute(
                    "SELECT probes, lost, rtt_sum, rtt_min, rtt_max FROM hop_stats"
                    " WHERE target_id=? AND ip=?", (target_id, ip)).fetchone()
                if row is not None:
                    existing[(target_id, ip)] = (row["probes"], row["lost"],
                                                 row["rtt_sum"], row["rtt_min"],
                                                 row["rtt_max"])
            now = time.time()
            merged: dict[tuple[int, str], list] = {}
            for target_id, ip, result in probes:
                key = (target_id, ip)
                current = merged.get(key)
                if current is None:
                    base = existing.get(key, (0, 0, 0.0, None, None))
                    current = [base[0], base[1], base[2], base[3], base[4]]
                    merged[key] = current
                current[0] += result.sent
                current[1] += result.lost
                current[2] += result.rtt_ms or 0.0
                if result.rtt_ms is not None:
                    current[3] = (result.rtt_ms if current[3] is None
                                  else min(current[3], result.rtt_ms))
                    current[4] = (result.rtt_ms if current[4] is None
                                  else max(current[4], result.rtt_ms))
            self._conn.executemany(
                "INSERT INTO hop_stats(target_id, ip, probes, lost, rtt_sum,"
                " rtt_min, rtt_max, updated_ts) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(target_id, ip) DO UPDATE SET probes=excluded.probes,"
                " lost=excluded.lost, rtt_sum=excluded.rtt_sum,"
                " rtt_min=excluded.rtt_min, rtt_max=excluded.rtt_max,"
                " updated_ts=excluded.updated_ts",
                [(target_id, ip, values[0], values[1], values[2], values[3],
                  values[4], now)
                 for (target_id, ip), values in merged.items()])
            self._conn.commit()
        return len(merged)

    def hop_stats_for_target(self, target_id: int) -> dict[str, sqlite3.Row]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM hop_stats WHERE target_id=?", (target_id,)).fetchall()
        return {row["ip"]: row for row in rows}

    def reset_hop_stats(self, target_id: int, keep_ips) -> None:
        """Drop stats for hops no longer on the current path, so a route
        change never blends old-path and new-path numbers together."""
        keep = set(keep_ips)
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip FROM hop_stats WHERE target_id=?", (target_id,)).fetchall()
            stale = [row["ip"] for row in rows if row["ip"] not in keep]
            if stale:
                marks = ",".join("?" * len(stale))
                self._conn.execute(
                    f"DELETE FROM hop_stats WHERE target_id=? AND ip IN ({marks})",
                    (target_id, *stale))
                self._conn.commit()

    def trace_nearest(self, target_id: int, ts: float,
                      max_delta: float | None = None):
        """The trace closest in time to `ts`, or None if none is close enough.

        Two index-backed lookups rather than an ORDER BY ABS(...) scan, which
        would read every trace for the target.
        """
        with self._lock:
            before = self._conn.execute(
                "SELECT * FROM traces WHERE target_id=? AND started_ts<=?"
                " ORDER BY started_ts DESC LIMIT 1",
                (target_id, ts),
            ).fetchone()
            after = self._conn.execute(
                "SELECT * FROM traces WHERE target_id=? AND started_ts>?"
                " ORDER BY started_ts ASC LIMIT 1",
                (target_id, ts),
            ).fetchone()
        candidates = [row for row in (before, after) if row is not None]
        if not candidates:
            return None
        best = min(candidates, key=lambda row: abs(row["started_ts"] - ts))
        if max_delta is not None and abs(best["started_ts"] - ts) > max_delta:
            return None
        return best

    def hop_rows_for_trace(self, trace_id: int) -> list:
        """Hops of a single trace, shaped like hop_rows_between for reuse."""
        with self._lock:
            return self._conn.execute(
                "SELECT t.id AS trace_id, t.started_ts, h.ttl, h.ip, h.rtt_ms,"
                " h.loss_pct FROM traces t JOIN hops h ON h.trace_id = t.id"
                " WHERE t.id=? ORDER BY h.ttl",
                (trace_id,),
            ).fetchall()

    def data_span(self, target_id: int) -> tuple[float, float] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(started_ts) AS lo, MAX(started_ts) AS hi"
                " FROM traces WHERE target_id=?",
                (target_id,),
            ).fetchone()
        if not row or row["lo"] is None:
            return None
        return float(row["lo"]), float(row["hi"])

    def size_bytes(self) -> int:
        """On-disk size, counting the WAL, which can be a large share of it."""
        import os
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def trim_to_size(self, max_bytes: int) -> int:
        """Delete the oldest traces, and their hops, until the file fits
        under the cap."""
        if max_bytes <= 0:
            return 0
        removed = 0
        deadline = time.monotonic() + TRIM_BUDGET_S
        for _ in range(TRIM_PASSES):
            size = self.size_bytes()
            if size <= max_bytes:
                break
            with self._lock:
                bounds = self._conn.execute(
                    "SELECT MIN(id) AS lo, MAX(id) AS hi FROM traces").fetchone()
            low, high = bounds["lo"], bounds["hi"]
            # Ids are handed out in arrival order, so the id span is both the
            # right definition of "oldest" — immune to a device with a wrong
            # clock — and a proxy for the row count that costs one index probe
            # rather than the full scan a COUNT(*) would.
            deletable = 0 if low is None else max(0, high - low + 1 - 200)
            if deletable:
                span = high - low + 1
                want = min(deletable, max(1, int(
                    span * (1.0 - max_bytes / float(size)) * 1.1)))
                cut = low + want
                chunk = TRIM_CHUNK
                while low < cut and time.monotonic() < deadline:
                    upper = min(low + chunk, cut)
                    started = time.monotonic()
                    with self._lock:
                        self._conn.execute(
                            "DELETE FROM hops"
                            " WHERE trace_id >= ? AND trace_id < ?",
                            (low, upper))
                        cursor = self._conn.execute(
                            "DELETE FROM traces"
                            " WHERE id >= ? AND id < ?", (low, upper))
                        removed += cursor.rowcount or 0
                        self._conn.commit()
                    held = time.monotonic() - started
                    low = upper
                    # Keep one batch's lock hold near TRIM_LOCK_TARGET_S
                    # however large the rows turn out to be — a trap with its
                    # raw frame stored costs an order of magnitude more than a
                    # syslog line, and one fixed batch size cannot suit both.
                    if held > TRIM_LOCK_TARGET_S:
                        chunk = max(TRIM_CHUNK_MIN, chunk // 2)
                    elif held < TRIM_LOCK_TARGET_S / 4:
                        chunk = min(TRIM_CHUNK_MAX, chunk * 2)
            # Hand the freed pages back, in short slices outside the lock
            # block. reclaim takes the lock itself and reacquires it in a
            # tight loop, and a Python lock is not fair, so it is asked for a
            # little at a time rather than for one long run.
            while time.monotonic() < deadline:
                if not dbmaint.reclaim(self._conn, self._lock, pages=500,
                                       budget_s=0.2, label="netpath.db"):
                    break
            if not deletable or time.monotonic() >= deadline:
                break
        if self.size_bytes() > max_bytes:
            log.warning("%s: %d bytes after removing %d rows, still above the "
                        "%d byte cap; continuing at the next maintenance pass",
                        "netpath.db", self.size_bytes(), removed, max_bytes)
        return removed
    def prune(self, older_than_days: float) -> int:
        """Delete every trace (and its hops) older than `older_than_days`.

        Batched in the same adaptive, lock-bounded chunks trim_to_size uses
        thirty lines above, for the same reason: one DELETE spanning months
        of per-hop rows held the write lock — and so the trace scheduler and
        anything else on this connection, including a request on the HTTP
        thread that triggered this via a settings save — for as long as the
        whole sweep took. TRIM_LOCK_TARGET_S's own comment has the
        measurement (4.1s stalled) that shape was fixed for; prune() simply
        never got the same fix, since it sits beside a comment about the
        VACUUM it used to call rather than the DELETE beside that comment.

        The id range a batch touches is only how the sweep is chunked, not
        what it deletes — each batch's own DELETE still filters on
        started_ts, so a device with a wrong clock (trim_to_size's own
        reason for preferring id ordering there) cannot make prune() keep or
        drop the wrong rows here.
        """
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            bounds = self._conn.execute(
                "SELECT MIN(id) AS lo, MAX(id) AS hi FROM traces"
                " WHERE started_ts < ?", (cutoff,)).fetchone()
        low, high = bounds["lo"], bounds["hi"]
        if low is None:
            return 0
        removed = 0
        deadline = time.monotonic() + TRIM_BUDGET_S
        chunk = TRIM_CHUNK
        cut = high + 1   # exclusive: every id in [low, cut) is a candidate
        while low < cut and time.monotonic() < deadline:
            upper = min(low + chunk, cut)
            started = time.monotonic()
            with self._lock:
                self._conn.execute(
                    "DELETE FROM hops WHERE trace_id IN (SELECT id FROM traces"
                    " WHERE id >= ? AND id < ? AND started_ts < ?)",
                    (low, upper, cutoff))
                cursor = self._conn.execute(
                    "DELETE FROM traces"
                    " WHERE id >= ? AND id < ? AND started_ts < ?",
                    (low, upper, cutoff))
                removed += cursor.rowcount or 0
                self._conn.commit()
            held = time.monotonic() - started
            low = upper
            # Same target, same adaptation as trim_to_size: a trace with its
            # raw frame stored costs far more per row than a bare hop.
            if held > TRIM_LOCK_TARGET_S:
                chunk = max(TRIM_CHUNK_MIN, chunk // 2)
            elif held < TRIM_LOCK_TARGET_S / 4:
                chunk = min(TRIM_CHUNK_MAX, chunk * 2)
        if low < cut:
            log.warning("netpath.db: prune of traces older than %.1f days did "
                        "not finish within its budget; continuing at the next "
                        "maintenance pass", older_than_days)
        if removed:
            # Nothing deleted means nothing to give back. The old code
            # rewrote the whole file with VACUUM on every call regardless,
            # which on a netpath.db holding months of per-hop rows froze the
            # trace scheduler and the UI for seconds at a time. Handed back
            # in the same short, lock-releasing slices trim_to_size uses,
            # rather than one longer reclaim() call at whatever its own
            # defaults are, for the same reason the deletes above are
            # chunked: this can now run under a settings-save request too.
            while time.monotonic() < deadline:
                if not dbmaint.reclaim(self._conn, self._lock, pages=500,
                                       budget_s=0.2, label="netpath.db"):
                    break
        return removed
