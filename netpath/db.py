"""SQLite persistence for the NetPath module: destinations, traces and hops.

This file holds traceroute records and the NetPath module's own settings, and
nothing else. Global settings, user accounts and the shared reverse-DNS cache
moved to appdb.py, which is what every module reads them from.
"""

from __future__ import annotations

import logging
import sqlite3
import time

from statistics import mean

from .sqlitebase import (  # re-exported: tests adjust netpath.db.TRIM_CHUNK
    TRIM_BUDGET_S, TRIM_CHUNK, TRIM_CHUNK_MAX, TRIM_CHUNK_MIN, SqliteStore)
from .tracer import TraceResult

log = logging.getLogger(__name__)

# prune()'s reclaim pass gets this much time of its own rather than sharing
# older_than_days' delete deadline: a long delete sweep would otherwise leave
# reclaim nothing, and the file would sit large until a later pass had spare.
PRUNE_RECLAIM_BUDGET_S = 5.0

# A settings save runs maintenance synchronously on the HTTP thread, so that
# path gets a short leash instead of the full TRIM_BUDGET_S; a backlog too big
# for one short pass is worked down over several saves.
FORCED_PRUNE_BUDGET_S = 2.0

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
# matching global defaults (save_settings) may carry. coerce_settings only
# checks that a value is a number, never that it is a sane one, and these
# reach a subprocess argument (max_hops, probes, timeout_s), a scheduler
# interval, or a thread-pool size. warn_rtt_ms/warn_loss reach only a
# comparison, so they are merely clamped to sane.
MIN_INTERVAL_S, MAX_INTERVAL_S = 5.0, 30 * 24 * 3600.0
MIN_MAX_HOPS, MAX_MAX_HOPS = 1, 255
MIN_PROBES, MAX_PROBES = 1, 20
MIN_TIMEOUT_S, MAX_TIMEOUT_S = 0.1, 30.0
MIN_TRACE_WORKERS, MAX_TRACE_WORKERS = 1, 64
# A stored 0 would make prune()'s cutoff time.time() and delete every trace on
# every maintenance pass; settings() clamps it after coercion, which has no
# notion of per-key bounds.
MIN_TRACE_RETENTION_DAYS, MAX_TRACE_RETENTION_DAYS = 1, 3650


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


class Database(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = APP_DEFAULTS
    LABEL = "netpath.db"
    TRIM_TABLE = "traces"
    TRIM_FLOOR = 200

    def __init__(self, path: str):
        # Set by prune(): whether its last call finished the whole sweep
        # inside budget, or gave up with rows past the cutoff still in the
        # table, so a caller can tell a partial sweep from a complete one.
        self.last_prune_incomplete = False
        super().__init__(path)

    def _migrate(self) -> None:
        self.ensure_columns("traces", {"icmp_code": "TEXT", "icmp_from": "TEXT"})
        self.ensure_columns("targets", {
            "timeout_s": "REAL NOT NULL DEFAULT 2.0",
            "hop_probe_enabled": "INTEGER NOT NULL DEFAULT 0"})

    # -------------------------------------------------------------- settings

    def settings(self) -> dict:
        coerced = super().settings()
        if "trace_retention_days" in coerced:
            coerced["trace_retention_days"] = _clamp(
                coerced["trace_retention_days"], MIN_TRACE_RETENTION_DAYS,
                MAX_TRACE_RETENTION_DAYS, int)
        return coerced

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
        super().save_settings(values)

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

    def live_size_bytes(self) -> int:
        """Size of the *live* data: pages holding rows, excluding the WAL and
        anything already on SQLite's freelist.

        What trim_to_size measures against the cap. size_bytes() counts free
        pages a prune() has not yet reclaimed as if they were rows, which
        would delete traces still inside the retention window.
        """
        with self._lock:
            page_count = self._conn.execute("PRAGMA page_count").fetchone()[0]
            freelist_count = self._conn.execute("PRAGMA freelist_count").fetchone()[0]
            page_size = self._conn.execute("PRAGMA page_size").fetchone()[0]
        return max(0, page_count - freelist_count) * page_size

    def _trim_size(self) -> int:
        return self.live_size_bytes()

    def _trim_delete(self, low: int, upper: int) -> int:
        """Hops first, then their traces. Lock held, no commit."""
        self._conn.execute(
            "DELETE FROM hops WHERE trace_id >= ? AND trace_id < ?", (low, upper))
        cursor = self._conn.execute(
            "DELETE FROM traces WHERE id >= ? AND id < ?", (low, upper))
        return cursor.rowcount or 0

    def prune(self, older_than_days: float, budget_s: float = TRIM_BUDGET_S) -> int:
        """Delete every trace (and its hops) older than `older_than_days`.

        Batched in adaptive, lock-bounded chunks: one DELETE spanning months
        of per-hop rows holds the write lock, and so the trace scheduler, for
        as long as the whole sweep takes. The id range only chunks the sweep —
        each batch still filters on started_ts, so a device with a wrong clock
        cannot make prune() drop the wrong rows.

        `budget_s` bounds only the delete loop; the reclaim pass that follows
        gets its own PRUNE_RECLAIM_BUDGET_S.
        """
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            bounds = self._conn.execute(
                "SELECT MIN(id) AS lo, MAX(id) AS hi FROM traces"
                " WHERE started_ts < ?", (cutoff,)).fetchone()
        low, high = bounds["lo"], bounds["hi"]
        if low is None:
            self.last_prune_incomplete = False
            return 0
        deadline = time.monotonic() + budget_s
        cut = high + 1   # exclusive: every id in [low, cut) is a candidate

        def delete(lo: int, up: int) -> int:
            self._conn.execute(
                "DELETE FROM hops WHERE trace_id IN (SELECT id FROM traces"
                " WHERE id >= ? AND id < ? AND started_ts < ?)",
                (lo, up, cutoff))
            cursor = self._conn.execute(
                "DELETE FROM traces"
                " WHERE id >= ? AND id < ? AND started_ts < ?",
                (lo, up, cutoff))
            return cursor.rowcount or 0

        # The chunk bounds are passed from this module's globals rather than
        # left to the base's, because they are the ones tests adjust.
        removed, low = self._delete_batches(
            low, cut, deadline, delete, chunk=TRIM_CHUNK,
            chunk_min=TRIM_CHUNK_MIN, chunk_max=TRIM_CHUNK_MAX)
        self.last_prune_incomplete = low < cut
        if self.last_prune_incomplete:
            log.warning("netpath.db: prune of traces older than %.1f days did "
                        "not finish within its budget; continuing at the next "
                        "maintenance pass", older_than_days)
        if removed:
            # Its own deadline, not `deadline` above: that one may already be
            # spent on deletes, and reclaim is worth a little time even then.
            self._reclaim_until(time.monotonic() + PRUNE_RECLAIM_BUDGET_S)
        return removed
