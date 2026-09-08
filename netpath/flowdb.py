"""Storage and aggregation for collected flows.

Flows live in their own SQLite file: a busy exporter writes orders of
magnitude more rows than the path monitor does, and SQLite allows one writer
at a time.

Beside the raw rows sit two tiers of rollup, 60-second and hourly buckets,
each holding the heaviest ROLLUP_KEYS keys of every dimension plus a
separate per-bucket grand total. That cap is what makes a chart cost
O(window / bucket) rather than O(flows): a week of raw rows is hundreds of
millions, a week of hourly rollup is a few thousand. A key expression that
evaluates to NULL cannot be stored (the rollup's primary key forbids it) and
so lands in the residual the grand total leaves behind, where the raw path
would have shown it as its own "unknown" series.
"""

from __future__ import annotations

import sqlite3
import time

from .sqlitebase import SqliteStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id        INTEGER PRIMARY KEY,
    exporter  TEXT    NOT NULL,
    version   INTEGER NOT NULL,
    ts_start  REAL    NOT NULL,
    ts_end    REAL    NOT NULL,
    src_ip    TEXT,
    dst_ip    TEXT,
    src_port  INTEGER,
    dst_port  INTEGER,
    protocol  INTEGER,
    tos       INTEGER,
    tcp_flags INTEGER,
    in_if     INTEGER,
    out_if    INTEGER,
    src_as    INTEGER,
    dst_as    INTEGER,
    next_hop  TEXT,
    packets   INTEGER,
    bytes     INTEGER,
    sampling  INTEGER DEFAULT 1,
    -- Which sampler produced the flow, so a rate announced after it arrived
    -- can still be applied to it.
    domain    INTEGER DEFAULT 0,
    sampler_id INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_flows_ts ON flows(ts_end);
CREATE INDEX IF NOT EXISTS ix_flows_exporter ON flows(exporter, ts_end);

CREATE TABLE IF NOT EXISTS exporters (
    address    TEXT PRIMARY KEY,
    name       TEXT,
    version    INTEGER,
    first_seen REAL,
    last_seen  REAL,
    packets    INTEGER DEFAULT 0,
    flows      INTEGER DEFAULT 0,
    sampling   INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS interfaces (
    exporter TEXT    NOT NULL,
    if_index INTEGER NOT NULL,
    name     TEXT,
    PRIMARY KEY (exporter, if_index)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Sampling rates as the exporter announced them, one row per sampler rather
-- than one per exporter: a router with per-interface rates sends several
-- options records and keeping only the last one applied the wrong factor to
-- everything else.
CREATE TABLE IF NOT EXISTS samplers (
    exporter   TEXT    NOT NULL,
    domain     INTEGER NOT NULL DEFAULT 0,
    sampler_id INTEGER NOT NULL DEFAULT 0,
    rate       INTEGER NOT NULL DEFAULT 1,
    updated_ts REAL,
    PRIMARY KEY (exporter, domain, sampler_id)
);

-- The heaviest keys of one dimension in one bucket, with the sampling factor
-- already multiplied in: it is per row, so it cannot be reapplied to a stored
-- sum. BLOB affinity stores each key as whatever the raw GROUP BY produced —
-- an integer port comes back an integer, an address comes back text — so the
-- two query paths hand api._flow_label the same thing. WITHOUT ROWID makes
-- the table its own clustered index in (tier, dim, bucket) order, which is
-- the order every read scans it in.
CREATE TABLE IF NOT EXISTS flow_rollup (
    tier    INTEGER NOT NULL,   -- bucket width in seconds: 60 or 3600
    dim     INTEGER NOT NULL,   -- flowdb.DIMENSION_IDS, append-only
    bucket  INTEGER NOT NULL,   -- epoch seconds, always a multiple of tier
    key     BLOB    NOT NULL,
    bytes   INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flows   INTEGER NOT NULL,
    PRIMARY KEY (tier, dim, bucket, key)
) WITHOUT ROWID;

-- Retention deletes by age across every dimension at once, which the
-- dimension-leading primary key cannot serve.
CREATE INDEX IF NOT EXISTS ix_flow_rollup_bucket ON flow_rollup(tier, bucket);

-- What every dimension sums to, kept once rather than eleven times: the same
-- flows are counted whichever way they are grouped. This is what keeps the
-- totals exact under the top-K cap — the residual is this minus the keys
-- that were stored.
CREATE TABLE IF NOT EXISTS flow_rollup_span (
    tier    INTEGER NOT NULL,
    bucket  INTEGER NOT NULL,
    bytes   INTEGER NOT NULL,
    packets INTEGER NOT NULL,
    flows   INTEGER NOT NULL,
    PRIMARY KEY (tier, bucket)
) WITHOUT ROWID;
"""

DEFAULTS = {
    "enabled": True,
    "bind_address": "0.0.0.0",
    "port": 2055,
    "accept_v5": True,
    "accept_v9": True,
    "accept_ipfix": True,
    "default_sampling": 1,
    "trust_exporter_sampling": True,
    "auto_accept_exporters": True,
    "allowed_exporters": "",
    # retention_days and max_flows bound the raw flows alone; the rollups
    # outlive them, which is what lets a 30-day chart still be drawn from a
    # fortnight's raw retention.
    "retention_days": 14,
    "max_flows": 5_000_000,
    "rollup_minute_days": 2,
    "rollup_retention_days": 90,
    "resolve_addresses": False,
    "resolve_ports": True,
    "top_n": 10,
    "bucket_seconds": 0,          # 0 means "choose from the window"
    "interface_names": "",        # "10.0.0.1:1=WAN" per line
    "custom_ports": "",           # "22609=NVR" per line, for unregistered ports
    "socket_buffer_kb": 4096,
    # Comma-joined column keys the flow-record table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns": "",
}

# Key expressions for the group-by dimensions the UI offers. The application
# dimension uses the lower port number, which is the usual heuristic for
# telling the service port from the ephemeral client port.
DIMENSIONS = {
    "Application": "CASE WHEN dst_port <= src_port THEN dst_port ELSE src_port END",
    "Protocol": "protocol",
    "Source": "src_ip",
    "Destination": "dst_ip",
    "Conversation": "src_ip || ' \u2192 ' || dst_ip",
    "Exporter": "exporter",
    "Ingress interface": "exporter || ':' || in_if",
    "Egress interface": "exporter || ':' || out_if",
    "Source AS": "src_as",
    "Destination AS": "dst_as",
    "ToS": "tos",
}

# The number each dimension is stored under in flow_rollup. Written out rather
# than derived from DIMENSIONS' order, because that order is published to the
# browser (api._config's "dimensions") and reordering the list for the UI's
# sake must not silently reinterpret every stored row. Append only.
DIMENSION_IDS = {"Application": 1, "Protocol": 2, "Source": 3, "Destination": 4,
                 "Conversation": 5, "Exporter": 6, "Ingress interface": 7,
                 "Egress interface": 8, "Source AS": 9, "Destination AS": 10,
                 "ToS": 11}

# Bucket widths, matched to api._flow_bucket's ladder: 60 serves the 60/300/900
# buckets, 3600 serves 3600 and 21600. The 10-second bucket the 15-minute view
# asks for stays on raw, where a quarter of an hour of rows is cheap.
ROLLUP_TIERS = (60, 3600)

# Keys kept per (tier, dimension, bucket). Chosen against the UI rather than
# the data: netflow.js offers a Top N up to 25, so the cap has to sit well
# above that for every bar the page draws to be exact.
ROLLUP_KEYS = {60: 48, 3600: 64}

# Which setting bounds each tier's history. The minute tier is the expensive
# one (~42 MB a day against ~0.9 MB for the hourly tier), and only the windows
# narrow enough to use it need it.
ROLLUP_DAYS_SETTING = {60: "rollup_minute_days", 3600: "rollup_retention_days"}

# A bucket is summarised only once its end is this old: an exporter with an
# active timeout or a skewed clock keeps sending flows for a window that has
# already closed.
_ROLLUP_LAG_S = 120
# How many sealed buckets each pass recomputes behind the watermark, so those
# late flows are not lost. The minute window is deliberately wider than
# collector.RESAMPLE_MAX_AGE_S, the age at which a sampling rate announced
# after the fact can still rewrite a raw row.
_ROLLUP_REDO = {60: 20, 3600: 2}
_ROLLUP_MAX_BUCKETS = {60: 240, 3600: 48}
_ROLLUP_BUDGET_S = 5.0

_WATERMARK = "flow_rollup_watermark_%d"     # forward edge: built below this
_FLOOR = "flow_rollup_floor_%d"             # backward edge backfill has reached
# The oldest ts_end a sampling rewrite has touched since the last compaction.
_RESAMPLE_FLOOR = "flow_resample_floor_ts"


def _align_down(ts: float, width: float) -> int:
    return int(float(ts) // width) * int(width)


class FlowDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "flows.db"
    TRIM_TABLE = "flows"
    OLDEST_TS_SQL = "SELECT ts_start FROM flows ORDER BY id LIMIT 1"
    TRIM_FLOOR = 1000

    def _migrate(self) -> None:
        # Existing rows keep the sampling factor baked into them at decode time.
        self.ensure_columns("flows", {"domain": "INTEGER DEFAULT 0",
                                      "sampler_id": "INTEGER DEFAULT 0"})

    # ------------------------------------------------------------------ write

    def insert_flows(self, flows) -> int:
        rows = [
            (f.exporter, f.version, f.ts_start, f.ts_end, f.src_ip, f.dst_ip,
             f.src_port, f.dst_port, f.protocol, f.tos, f.tcp_flags,
             f.in_if, f.out_if, f.src_as, f.dst_as, f.next_hop,
             f.packets, f.bytes, f.sampling, f.domain, f.sampler_id)
            for f in flows
        ]
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                "INSERT INTO flows(exporter, version, ts_start, ts_end, src_ip,"
                " dst_ip, src_port, dst_port, protocol, tos, tcp_flags, in_if,"
                " out_if, src_as, dst_as, next_hop, packets, bytes, sampling,"
                " domain, sampler_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self._conn.commit()
        return len(rows)

    def touch_exporter(self, address: str, version: int, packets: int,
                       flows: int, sampling: int) -> None:
        """One exporter's counters. A one-row wrapper around touch_exporters."""
        self.touch_exporters([(address, version, packets, flows, sampling)])

    def touch_exporters(self, entries) -> int:
        """Fold a flush's worth of exporter counters in with one commit,
        rather than taking the flow writer's lock once per exporter."""
        rows = list(entries)
        if not rows:
            return 0
        now = time.time()
        with self._lock:
            self._conn.executemany(
                "INSERT INTO exporters(address, version, first_seen, last_seen,"
                " packets, flows, sampling) VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(address) DO UPDATE SET last_seen=excluded.last_seen,"
                " version=excluded.version, sampling=excluded.sampling,"
                " packets=exporters.packets+excluded.packets,"
                " flows=exporters.flows+excluded.flows",
                [(address, version, now, now, packets, flows, sampling)
                 for address, version, packets, flows, sampling in rows])
            self._conn.commit()
        return len(rows)

    def record_sampling_rates(self, rates, since_ts: float = 0.0) -> int:
        """Store announced sampling rates, and correct the flows that arrived
        before the announcement.

        Options templates come on a slower cycle than data, so flows decoded
        before the first one carry sampling=1; the factor is applied at query
        time, so only a rewrite can put them right. Bounded to `since_ts`.
        """
        rows = list(rates)
        if not rows:
            return 0
        now = time.time()
        corrected = 0
        with self._lock:
            self._conn.executemany(
                "INSERT INTO samplers(exporter, domain, sampler_id, rate,"
                " updated_ts) VALUES (?,?,?,?,?)"
                " ON CONFLICT(exporter, domain, sampler_id) DO UPDATE SET"
                " rate=excluded.rate, updated_ts=excluded.updated_ts",
                [(exporter, domain, sampler_id, rate, now)
                 for exporter, domain, sampler_id, rate in rows])
            for exporter, domain, sampler_id, rate in rows:
                cursor = self._conn.execute(
                    "UPDATE flows SET sampling = ? WHERE exporter = ?"
                    " AND domain = ? AND sampler_id = ? AND sampling <> ?"
                    " AND ts_end >= ?",
                    (rate, exporter, domain, sampler_id, rate, since_ts))
                corrected += cursor.rowcount or 0
            self._conn.commit()
        return corrected

    def samplers(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM samplers ORDER BY exporter, domain, sampler_id"
            ).fetchall()

    def exporters(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM exporters ORDER BY last_seen DESC").fetchall()

    def set_interface_names(self, mapping: dict[tuple[str, int], str]) -> None:
        with self._lock:
            for (exporter, index), name in mapping.items():
                self._conn.execute(
                    "INSERT INTO interfaces(exporter, if_index, name) VALUES (?,?,?)"
                    " ON CONFLICT(exporter, if_index) DO UPDATE SET name=excluded.name",
                    (exporter, index, name),
                )
            self._conn.commit()

    def interface_names(self) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM interfaces").fetchall()
        return {f"{row['exporter']}:{row['if_index']}": row["name"] for row in rows}

    # ----------------------------------------------------------------- rollup

    def rollup_bounds(self, tier: int) -> tuple[int | None, int | None]:
        """(floor, watermark): the oldest bucket this tier covers and the
        first one it does not. Either is None before the tier is seeded."""
        floor = self._private_setting(_FLOOR % tier)
        watermark = self._private_setting(_WATERMARK % tier)
        return (None if floor is None else int(floor),
                None if watermark is None else int(watermark))

    def _from_minute_tier(self, tier: int, bucket: int) -> bool:
        """Whether the minute tier already covers this whole bucket. Sixty
        minute rows in place of an hour of raw flows is the same answer
        read sixty times more cheaply."""
        if tier == 60:
            return False
        floor, watermark = self.rollup_bounds(60)
        return (floor is not None and watermark is not None
                and bucket >= floor and bucket + tier <= watermark)

    def _compact_bucket(self, tier: int, bucket: int) -> int:
        """Rebuild one bucket of every dimension, and its span row.

        Delete and insert rather than upsert: which keys make the top-K
        changes when a bucket is recomputed, so a key that has dropped out
        of the cap has to be cleared rather than left behind at its old
        value. One transaction per dimension, so the write lock is never
        held across more than one.
        """
        limit = ROLLUP_KEYS[tier]
        from_minutes = self._from_minute_tier(tier, bucket)
        written = 0
        for name, expr in DIMENSIONS.items():
            dim = DIMENSION_IDS[name]
            with self._lock:
                self._conn.execute(
                    "DELETE FROM flow_rollup WHERE tier = ? AND dim = ?"
                    " AND bucket = ?", (tier, dim, bucket))
                if from_minutes:
                    cursor = self._conn.execute(
                        "INSERT INTO flow_rollup(tier, dim, bucket, key, bytes,"
                        " packets, flows) SELECT ?, ?, ?, key, bytes, packets,"
                        " flows FROM (SELECT key, SUM(bytes) AS bytes,"
                        " SUM(packets) AS packets, SUM(flows) AS flows"
                        " FROM flow_rollup WHERE tier = 60 AND dim = ?"
                        " AND bucket >= ? AND bucket < ?"
                        " GROUP BY key ORDER BY bytes DESC LIMIT ?)",
                        (tier, dim, bucket, dim, bucket, bucket + tier, limit))
                else:
                    cursor = self._conn.execute(
                        f"INSERT INTO flow_rollup(tier, dim, bucket, key, bytes,"
                        f" packets, flows) SELECT ?, ?, ?, key, bytes, packets,"
                        f" flows FROM (SELECT {expr} AS key,"
                        f" COALESCE(SUM(bytes * sampling), 0) AS bytes,"
                        f" COALESCE(SUM(packets * sampling), 0) AS packets,"
                        f" COUNT(*) AS flows FROM flows"
                        f" WHERE ts_end >= ? AND ts_end < ?"
                        f" AND ({expr}) IS NOT NULL"
                        f" GROUP BY key ORDER BY bytes DESC LIMIT ?)",
                        (tier, dim, bucket, bucket, bucket + tier, limit))
                written += cursor.rowcount or 0
                self._conn.commit()
            # The collector's writer is waiting on this lock and a Python lock
            # is not fair, the same reason sqlitebase.reclaim yields between
            # its steps.
            time.sleep(0)
        with self._lock:
            self._conn.execute(
                "DELETE FROM flow_rollup_span WHERE tier = ? AND bucket = ?",
                (tier, bucket))
            if from_minutes:
                self._conn.execute(
                    "INSERT INTO flow_rollup_span(tier, bucket, bytes, packets,"
                    " flows) SELECT ?, ?, SUM(bytes), SUM(packets), SUM(flows)"
                    " FROM flow_rollup_span WHERE tier = 60 AND bucket >= ?"
                    " AND bucket < ? HAVING COUNT(*) > 0",
                    (tier, bucket, bucket, bucket + tier))
            else:
                self._conn.execute(
                    "INSERT INTO flow_rollup_span(tier, bucket, bytes, packets,"
                    " flows) SELECT ?, ?,"
                    " COALESCE(SUM(bytes * sampling), 0),"
                    " COALESCE(SUM(packets * sampling), 0), COUNT(*) FROM flows"
                    " WHERE ts_end >= ? AND ts_end < ? HAVING COUNT(*) > 0",
                    (tier, bucket, bucket, bucket + tier))
            self._conn.commit()
        return written

    def compact_rollup(self, tier: int, max_buckets: int | None = None,
                       budget_s: float = _ROLLUP_BUDGET_S) -> int:
        """Summarise sealed buckets into `tier`, from a private watermark.

        Seeded at the current bucket rather than at the oldest stored flow:
        a store that has been collecting for a fortnight would otherwise
        grind through all of it before producing a bucket anyone is looking
        at. backfill_rollup pages the history in from the other end.

        Returns the number of rollup rows written.
        """
        now = time.time()
        sealed = _align_down(now - _ROLLUP_LAG_S, tier)
        floor, watermark = self.rollup_bounds(tier)
        if watermark is None:
            start = _align_down(now, tier)
            self._set_private_setting(_WATERMARK % tier, start)
            self._set_private_setting(_FLOOR % tier, start)
            return 0
        bucket = watermark - _ROLLUP_REDO[tier] * tier
        # A rewritten sampling factor changes rows a sealed bucket has
        # already been built from, so follow the rewrite back rather than
        # leaving the rollup quietly disagreeing with the raw rows.
        resampled = self._private_setting(_RESAMPLE_FLOOR)
        if resampled is not None:
            bucket = min(bucket, _align_down(float(resampled), tier))
        if floor is not None:
            bucket = max(bucket, floor)
        limit = _ROLLUP_MAX_BUCKETS[tier] if max_buckets is None else max_buckets
        deadline = time.monotonic() + budget_s
        written = 0
        processed = 0
        while (bucket + tier <= sealed and processed < limit
               and time.monotonic() < deadline):
            written += self._compact_bucket(tier, bucket)
            bucket += tier
            processed += 1
        # max(): a pass that ran out of budget inside the redo window must
        # not wind the watermark back to where it started.
        self._set_private_setting(_WATERMARK % tier, max(bucket, watermark))
        self._set_private_setting(_RESAMPLE_FLOOR, None)
        return written

    def backfill_rollup(self, tier: int, max_buckets: int | None = None,
                        budget_s: float = _ROLLUP_BUDGET_S) -> tuple[int, bool]:
        """Walk the floor backwards through history one bucket at a time,
        committing the cursor as it goes so it resumes across restarts.

        Newest first, because _rollup_plan refuses a tier whose floor does
        not reach the start of the window asked for: as the cursor walks
        back, progressively wider windows move off raw, and none is ever
        slower than it was before.

        Returns (rows written, whether this pass reached the end of the
        walk) — the flag only once, so a caller can log it as an event.
        """
        floor, _watermark = self.rollup_bounds(tier)
        if floor is None:
            return 0, False
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(ts_end) AS oldest FROM flows").fetchone()
        oldest = row["oldest"] if row else None
        setting = ROLLUP_DAYS_SETTING[tier]
        days = float(self.settings().get(setting, DEFAULTS[setting]))
        # No point summarising what retention will delete on this same sweep.
        stop = _align_down(time.time() - days * 86400, tier)
        if oldest is not None:
            stop = max(stop, _align_down(float(oldest), tier))
        limit = _ROLLUP_MAX_BUCKETS[tier] if max_buckets is None else max_buckets
        deadline = time.monotonic() + budget_s
        written = 0
        processed = 0
        bucket = floor - tier
        while (bucket >= stop and processed < limit
               and time.monotonic() < deadline):
            written += self._compact_bucket(tier, bucket)
            self._set_private_setting(_FLOOR % tier, bucket)
            bucket -= tier
            processed += 1
        done = bucket < stop and processed > 0
        return written, done

    # ------------------------------------------------------------- maintenance

    def prune(self, retention_days: float, max_flows: int) -> int:
        removed = 0
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM flows WHERE ts_end < ?", (cutoff,))
            removed += cur.rowcount or 0
            total = self._conn.execute("SELECT COUNT(*) AS n FROM flows").fetchone()["n"]
            if max_flows and total > max_flows:
                cur = self._conn.execute(
                    "DELETE FROM flows WHERE id IN (SELECT id FROM flows"
                    " ORDER BY ts_end ASC LIMIT ?)", (total - max_flows,))
                removed += cur.rowcount or 0
            self._conn.commit()
        return removed

    def recent_endpoints(self, limit: int = 300, since_s: float = 3600) -> list[str]:
        """Busiest source and destination addresses seen recently.

        Bounded on purpose: a busy exporter sees tens of thousands of distinct
        addresses and only the heaviest ones reach the views.
        """
        cutoff = time.time() - since_s
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, SUM(b) AS bytes FROM ("
                "  SELECT src_ip AS ip, bytes * sampling AS b FROM flows"
                "   WHERE ts_end >= ?"
                "  UNION ALL"
                "  SELECT dst_ip AS ip, bytes * sampling AS b FROM flows"
                "   WHERE ts_end >= ?"
                ") WHERE ip IS NOT NULL AND ip != ''"
                " GROUP BY ip ORDER BY bytes DESC LIMIT ?",
                (cutoff, cutoff, limit)).fetchall()
        return [row["ip"] for row in rows]

    def stats(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS flows, MIN(ts_end) AS lo, MAX(ts_end) AS hi,"
                " SUM(bytes * sampling) AS bytes FROM flows").fetchone()
        return {"flows": row["flows"] or 0, "lo": row["lo"], "hi": row["hi"],
                "bytes": row["bytes"] or 0}

    # ------------------------------------------------------------------ query

    def _where(self, t0: float, t1: float, filters: dict) -> tuple[str, list]:
        clauses = ["ts_end >= ?", "ts_end <= ?"]
        params: list = [t0, t1]
        if filters.get("src_ip"):
            clauses.append("src_ip LIKE ?")
            params.append(f"%{filters['src_ip']}%")
        if filters.get("dst_ip"):
            clauses.append("dst_ip LIKE ?")
            params.append(f"%{filters['dst_ip']}%")
        if filters.get("port"):
            clauses.append("(src_port = ? OR dst_port = ?)")
            params.extend([int(filters["port"]), int(filters["port"])])
        if filters.get("protocol"):
            clauses.append("protocol = ?")
            params.append(int(filters["protocol"]))
        if filters.get("exporter"):
            clauses.append("exporter = ?")
            params.append(filters["exporter"])
        return " AND ".join(clauses), params

    def top(self, t0: float, t1: float, dimension: str, filters: dict,
            limit: int = 10) -> list[sqlite3.Row]:
        key = DIMENSIONS.get(dimension, DIMENSIONS["Application"])
        where, params = self._where(t0, t1, filters)
        with self._lock:
            return self._conn.execute(
                f"SELECT {key} AS key, SUM(bytes * sampling) AS bytes,"
                f" SUM(packets * sampling) AS packets, COUNT(*) AS flows"
                f" FROM flows WHERE {where} GROUP BY key"
                f" ORDER BY bytes DESC LIMIT ?",
                (*params, limit),
            ).fetchall()

    def series(self, t0: float, t1: float, dimension: str, filters: dict,
               bucket_s: float, limit: int = 8):
        """Stacked series for the top keys, with everything else as 'other'."""
        key = DIMENSIONS.get(dimension, DIMENSIONS["Application"])
        where, params = self._where(t0, t1, filters)
        bucket_s = max(float(bucket_s), 1.0)
        n_buckets = max(1, int((t1 - t0) / bucket_s) + 1)

        top_rows = self.top(t0, t1, dimension, filters, limit)
        top_keys = [row["key"] for row in top_rows]

        with self._lock:
            rows = self._conn.execute(
                f"SELECT {key} AS key, CAST((ts_end - ?) / ? AS INTEGER) AS slot,"
                f" SUM(bytes * sampling) AS bytes FROM flows WHERE {where}"
                f" GROUP BY key, slot",
                (t0, bucket_s, *params),
            ).fetchall()

        series: dict[object, list[float]] = {k: [0.0] * n_buckets for k in top_keys}
        other = [0.0] * n_buckets
        for row in rows:
            slot = row["slot"]
            if slot is None or slot < 0 or slot >= n_buckets:
                continue
            target = series.get(row["key"])
            if target is None:
                other[slot] += row["bytes"] or 0
            else:
                target[slot] += row["bytes"] or 0
        if any(other):
            series["\u2014 other \u2014"] = other

        times = [t0 + i * bucket_s for i in range(n_buckets)]
        return times, series, bucket_s

    def overview(self, t0: float, t1: float, dimension: str, filters: dict,
                 bucket_s: float, series_limit: int = 8, top_limit: int = 10):
        """Everything the NetFlow overview needs, from one pass over the window.

        The `GROUP BY key, slot` scan holds all three answers: per key it is
        top(), over everything it is totals(), by slot it is the series.
        Returns (times, series, bucket_s, top_rows, totals).
        """
        key = DIMENSIONS.get(dimension, DIMENSIONS["Application"])
        where, params = self._where(t0, t1, filters)
        bucket_s = max(float(bucket_s), 1.0)
        n_buckets = max(1, int((t1 - t0) / bucket_s) + 1)

        with self._lock:
            rows = self._conn.execute(
                f"SELECT {key} AS key, CAST((ts_end - ?) / ? AS INTEGER) AS slot,"
                f" SUM(bytes * sampling) AS bytes,"
                f" SUM(packets * sampling) AS packets, COUNT(*) AS flows"
                f" FROM flows WHERE {where} GROUP BY key, slot",
                (t0, bucket_s, *params),
            ).fetchall()

        per_key: dict[object, dict] = {}
        totals = {"bytes": 0, "packets": 0, "flows": 0}
        for row in rows:
            entry = per_key.setdefault(
                row["key"], {"bytes": 0, "packets": 0, "flows": 0})
            entry["bytes"] += row["bytes"] or 0
            entry["packets"] += row["packets"] or 0
            entry["flows"] += row["flows"] or 0
            totals["bytes"] += row["bytes"] or 0
            totals["packets"] += row["packets"] or 0
            totals["flows"] += row["flows"] or 0

        # The name breaks a tie, so two equal-volume keys keep the same order
        # — and so the same colour — from one refresh to the next. SQL's
        # ORDER BY left that order arbitrary.
        ordered = sorted(per_key.items(),
                         key=lambda kv: (-kv[1]["bytes"], str(kv[0])))
        top_rows = [{"key": k, **v} for k, v in ordered[:top_limit]]
        top_keys = [k for k, _ in ordered[:series_limit]]

        series: dict[object, list[float]] = {k: [0.0] * n_buckets for k in top_keys}
        other = [0.0] * n_buckets
        wanted = set(top_keys)
        for row in rows:
            slot = row["slot"]
            if slot is None or slot < 0 or slot >= n_buckets:
                continue
            if row["key"] in wanted:
                series[row["key"]][slot] += row["bytes"] or 0
            else:
                other[slot] += row["bytes"] or 0
        if any(other):
            series["\u2014 other \u2014"] = other

        times = [t0 + i * bucket_s for i in range(n_buckets)]
        return times, series, bucket_s, top_rows, totals

    def flows(self, t0: float, t1: float, filters: dict, limit: int = 200,
              order: str = "bytes") -> list[sqlite3.Row]:
        where, params = self._where(t0, t1, filters)
        column = {"bytes": "bytes * sampling", "packets": "packets * sampling",
                  "time": "ts_end"}.get(order, "bytes * sampling")
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM flows WHERE {where} ORDER BY {column} DESC LIMIT ?",
                (*params, limit),
            ).fetchall()

    def totals(self, t0: float, t1: float, filters: dict) -> dict:
        where, params = self._where(t0, t1, filters)
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS flows, SUM(bytes * sampling) AS bytes,"
                f" SUM(packets * sampling) AS packets FROM flows WHERE {where}",
                params,
            ).fetchone()
        return {"flows": row["flows"] or 0, "bytes": row["bytes"] or 0,
                "packets": row["packets"] or 0}
