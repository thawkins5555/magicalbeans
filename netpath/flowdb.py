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

What that costs in accuracy: totals are exact whichever path answers, since
the grand total is not capped. A key that is above the cap in every bucket
it appears in is exact too. A key that dips below the cap in some buckets is
short by what it lost there, and that traffic is in "— other —" rather than
missing. Filtered queries are never rollup-served and are exact throughout.
"""

from __future__ import annotations

import logging
import sqlite3
import time

from .sqlitebase import (  # re-exported: tests adjust netpath.flowdb.TRIM_CHUNK
    TRIM_BUDGET_S, TRIM_CHUNK, TRIM_CHUNK_MAX, TRIM_CHUNK_MIN, SqliteStore)

log = logging.getLogger(__name__)

# prune()'s reclaim pass gets its own time rather than sharing the delete
# deadline, the same split netpath.db.prune makes.
PRUNE_RECLAIM_BUDGET_S = 5.0

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
-- The only index on flows: every other filter (src_ip LIKE, port, protocol)
-- is a residual tested against a window ix_flows_ts already narrowed, and an
-- index the writer pays for on every insert has to earn more than that.
-- drop_legacy_indexes() removes the ix_flows_exporter an older store has.
CREATE INDEX IF NOT EXISTS ix_flows_ts ON flows(ts_end);

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
# already closed. Flows that land later still than that are not lost either:
# every writer records how far back it reached (_DIRTY) and the next pass
# rebuilds exactly those buckets, however far behind the watermark they are.
_ROLLUP_LAG_S = 120
_ROLLUP_MAX_BUCKETS = {60: 240, 3600: 48}
_ROLLUP_BUDGET_S = 5.0

# How far back down the table the flow-record list sorts. Ordering by
# bytes * sampling cannot be index-served — the sort key is a product, and
# sampling is rewritten after the fact — so the scan is bounded by id
# instead, ids being handed out in arrival order. Not a setting: it is what
# the sort costs, not a retention choice.
FLOW_SCAN_CAP = 2_000_000

_WATERMARK = "flow_rollup_watermark_%d"     # forward edge: built below this
_FLOOR = "flow_rollup_floor_%d"             # backward edge backfill has reached
# The oldest ts_end a writer has touched since this tier last compacted: what
# the next pass has to rebuild behind its watermark, and nothing more.
_DIRTY = "flow_rollup_dirty_ts_%d"
# The oldest ts_end a sampling rewrite has touched since the last compaction.
_RESAMPLE_FLOOR = "flow_resample_floor_ts"


def _align_down(ts: float, width: float) -> int:
    return int(float(ts) // width) * int(width)


class FlowDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "flows.db"
    TRIM_TABLE = "flows"
    # The rollups reach further back than the raw rows they were built from,
    # so asking flows alone under-reports how much history this store holds.
    OLDEST_TS_SQL = ("SELECT MIN(ts) FROM ("
                     "SELECT MIN(ts_start) AS ts FROM flows"
                     " UNION ALL SELECT MIN(bucket) FROM flow_rollup"
                     " UNION ALL SELECT MIN(bucket) FROM flow_rollup_span)")
    TRIM_FLOOR = 1000
    # Rollup rows a tier keeps whatever the size cap says: below this the wide
    # charts it is the only source for have nothing left to draw, and the raw
    # rows they would fall back to are long gone.
    TRIM_ROLLUP_FLOOR = 5_000

    def __init__(self, path: str):
        # Set by prune(): whether its last call finished the whole sweep
        # inside budget, so a caller can tell a partial sweep from a
        # complete one.
        self.last_prune_incomplete = False
        super().__init__(path)

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
            # Which buckets this flush landed in is the exporter's clock's
            # answer, not the wall clock's, so the compaction that has to
            # rebuild them is told rather than left to guess a window. In the
            # same transaction as the rows it describes.
            self._mark_dirty(min(row[3] for row in rows))
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
        if corrected:
            # Rows a sealed rollup bucket was built from have just changed
            # value. Recording how far back lets compact_rollup follow the
            # rewrite rather than quietly disagreeing with the raw rows,
            # whatever the caller's bound turns out to be.
            floor = self._private_setting(_RESAMPLE_FLOOR)
            if floor is None or since_ts < float(floor):
                self._set_private_setting(_RESAMPLE_FLOOR, since_ts)
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

    def _mark_dirty(self, ts: float, tiers=ROLLUP_TIERS) -> None:
        """Lower each tier's redo floor to `ts`.

        Called by whatever changed the rows, so a pass rebuilds exactly the
        buckets that moved rather than a fixed window behind the watermark:
        a window wide enough for the slowest exporter is write amplification
        for every other pass, and any fixed width is still too narrow for an
        exporter further behind than that.
        """
        for tier in tiers:
            key = _DIRTY % tier
            current = self._private_setting(key)
            if current is None or float(ts) < float(current):
                self._set_private_setting(key, float(ts))

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

        Seeded at the newest sealed bucket rather than at the oldest stored
        flow: a store that has been collecting for a fortnight would
        otherwise grind through all of it before producing a bucket anyone
        is looking at. backfill_rollup pages the history in from the other
        end.

        New buckets first, redo second. Spending the budget on the redo
        window first leaves the watermark where it was whenever that window
        alone costs more than the budget, so the next pass repeats identical
        work while real time adds a bucket a minute and the unsummarised
        tail grows without bound. This order makes the watermark advance on
        every pass, whatever the redo costs.

        Returns the number of rollup rows written.
        """
        now = time.time()
        sealed = _align_down(now - _ROLLUP_LAG_S, tier)
        floor, watermark = self.rollup_bounds(tier)
        if watermark is None:
            # At the first unsealed bucket, not at the current one: the
            # watermark is a claim that everything below it is built, and
            # backfill starts one bucket below it. Seeding at `now` would
            # have it build the bucket still collecting flows and then never
            # revisit it, because compaction only ever moves forward.
            self._set_private_setting(_WATERMARK % tier, sealed)
            self._set_private_setting(_FLOOR % tier, sealed)
            return 0
        limit = _ROLLUP_MAX_BUCKETS[tier] if max_buckets is None else max_buckets
        deadline = time.monotonic() + budget_s
        written = 0
        processed = 0
        bucket = watermark
        while (bucket + tier <= sealed and processed < limit
               and time.monotonic() < deadline):
            written += self._compact_bucket(tier, bucket)
            bucket += tier
            processed += 1
        if bucket != watermark:
            self._set_private_setting(_WATERMARK % tier, bucket)
        return written + self._redo_dirty(tier, watermark, floor,
                                          limit - processed, deadline)

    def _redo_dirty(self, tier: int, upto: int, floor: int | None,
                    limit: int, deadline: float) -> int:
        """Rebuild the buckets a writer has touched behind `upto`.

        Taken and cleared under one lock, so a flush landing mid-pass marks
        the tier dirty again rather than having its mark thrown away at the
        end. Oldest first, and whatever the budget did not reach is marked
        dirty again, so the walk resumes there instead of starting over.
        """
        with self._lock:
            dirty = self._private_setting(_DIRTY % tier)
            # A rewritten sampling factor changes rows a sealed bucket has
            # already been built from, and so is the same kind of dirt.
            resampled = self._private_setting(_RESAMPLE_FLOOR)
            self._set_private_setting(_DIRTY % tier, None)
            self._set_private_setting(_RESAMPLE_FLOOR, None)
        marks = [float(mark) for mark in (dirty, resampled) if mark is not None]
        if not marks:
            return 0
        bucket = _align_down(min(marks), tier)
        if floor is not None:
            bucket = max(bucket, floor)
        written = 0
        processed = 0
        while (bucket < upto and processed < limit
               and time.monotonic() < deadline):
            written += self._compact_bucket(tier, bucket)
            bucket += tier
            processed += 1
        if bucket < upto:
            # The coarser tiers are built from this one where it covers them,
            # so what is still dirty here is still dirty there.
            self._mark_dirty(float(bucket),
                             [wider for wider in ROLLUP_TIERS if wider >= tier])
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
        if oldest is None:
            # Nothing to summarise from. Walking on would build empty buckets
            # every sweep until the retention floor caught up with the cursor.
            return 0, False
        setting = ROLLUP_DAYS_SETTING[tier]
        days = float(self.settings().get(setting, DEFAULTS[setting]))
        # Neither below the raw rows the summaries are built from, nor below
        # what retention will delete on this same sweep.
        stop = max(_align_down(time.time() - days * 86400, tier),
                   _align_down(float(oldest), tier))
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

    _DROPPED_EXPORTER_IX = "dropped_ix_flows_exporter"

    def drop_legacy_indexes(self) -> bool:
        """Drop the ix_flows_exporter an older store still carries.

        Off the open path on purpose: dropping the index of a table with
        tens of millions of rows walks and frees every one of its pages,
        which is the class of work that made startup take half a minute
        before (sqlitebase.CONVERT_AT_OPEN_PAGES exists for the same
        reason). A pause on the maintenance timer is expected; a pause at
        startup is a bug. Returns whether it did anything.
        """
        if self._private_setting(self._DROPPED_EXPORTER_IX):
            return False
        with self._lock:
            self._conn.execute("DROP INDEX IF EXISTS ix_flows_exporter")
            self._conn.commit()
        self._set_private_setting(self._DROPPED_EXPORTER_IX, True)
        return True

    def _delete_rollup(self, tier: int, low: int, upper: int) -> int:
        """Both rollup tables for buckets in [low, upper). Lock held, no
        commit: _delete_batches owns each."""
        cursor = self._conn.execute(
            "DELETE FROM flow_rollup WHERE tier = ? AND bucket >= ?"
            " AND bucket < ?", (tier, low, upper))
        removed = cursor.rowcount or 0
        cursor = self._conn.execute(
            "DELETE FROM flow_rollup_span WHERE tier = ? AND bucket >= ?"
            " AND bucket < ?", (tier, low, upper))
        return removed + (cursor.rowcount or 0)

    def _prune_rollup(self, tier: int, days: float, deadline: float) -> int:
        """Age out one tier, walking bucket timestamps the way the raw
        stages walk ids: _delete_batches only needs a monotonic coordinate,
        and it sizes its own batches from how long each one held the lock."""
        cutoff = _align_down(time.time() - days * 86400, tier)
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(bucket) AS lo FROM flow_rollup_span WHERE tier = ?"
                " AND bucket < ?", (tier, cutoff)).fetchone()
        oldest = row["lo"] if row else None
        if oldest is None:
            return 0
        removed, reached = self._delete_batches(
            int(oldest), cutoff, deadline,
            delete=lambda lo, up: self._delete_rollup(tier, lo, up),
            chunk=3600, chunk_min=60, chunk_max=7 * 86400)
        # Routing must stop trusting history that is no longer there, even
        # where the sweep only reached part of it.
        floor, _watermark = self.rollup_bounds(tier)
        if floor is not None and reached > floor:
            self._set_private_setting(_FLOOR % tier, reached)
        return removed

    def prune(self, retention_days: float, max_flows: int, *,
              minute_days: float | None = None, rollup_days: float | None = None,
              budget_s: float = TRIM_BUDGET_S) -> int:
        """Age out raw flows, cap their row count, and age out the rollups.

        Batched in adaptive, lock-bounded chunks rather than one DELETE per
        stage: the write lock is the one the collector's writer needs, and
        NetFlow is UDP, so a writer stalled behind a month-wide delete is
        lost data. The id range only chunks the sweep — each batch still
        filters on ts_end, so an exporter with a wrong clock cannot make
        prune() drop the wrong rows.

        `retention_days` and `max_flows` bound the raw table alone. Passing
        0 for each of the four (the Settings page's maintenance button)
        matches every existing row.
        """
        now = time.time()
        cutoff = now - retention_days * 86400
        deadline = time.monotonic() + budget_s
        removed = 0
        incomplete = False

        with self._lock:
            bounds = self._conn.execute(
                "SELECT MIN(id) AS lo, MAX(id) AS hi FROM flows"
                " WHERE ts_end < ?", (cutoff,)).fetchone()
        low, high = bounds["lo"], bounds["hi"]
        if low is not None:
            def by_age(lo: int, up: int) -> int:
                cursor = self._conn.execute(
                    "DELETE FROM flows WHERE id >= ? AND id < ? AND ts_end < ?",
                    (lo, up, cutoff))
                return cursor.rowcount or 0

            aged, reached = self._delete_batches(
                low, high + 1, deadline, by_age, chunk=TRIM_CHUNK,
                chunk_min=TRIM_CHUNK_MIN, chunk_max=TRIM_CHUNK_MAX)
            removed += aged
            incomplete = incomplete or reached < high + 1

        if max_flows:
            # Two index probes rather than the COUNT(*) full scan this used
            # to pay on every maintenance pass: ids are handed out in arrival
            # order, so the span is both the right definition of "oldest" and
            # a good enough proxy for the row count.
            with self._lock:
                bounds = self._conn.execute(
                    "SELECT MIN(id) AS lo, MAX(id) AS hi FROM flows").fetchone()
            low, high = bounds["lo"], bounds["hi"]
            over = 0 if low is None else (high - low + 1) - max_flows
            if over > 0:
                capped, reached = self._delete_batches(
                    low, low + over, deadline, chunk=TRIM_CHUNK,
                    chunk_min=TRIM_CHUNK_MIN, chunk_max=TRIM_CHUNK_MAX)
                removed += capped
                incomplete = incomplete or reached < low + over

        for tier, days in ((60, minute_days), (3600, rollup_days)):
            if days is None:
                setting = ROLLUP_DAYS_SETTING[tier]
                days = float(self.settings().get(setting, DEFAULTS[setting]))
            removed += self._prune_rollup(tier, float(days), deadline)

        self.last_prune_incomplete = incomplete
        if incomplete:
            log.warning("netpath.flowdb: prune of flows older than %.1f days did "
                        "not finish within its budget; continuing at the next "
                        "maintenance pass", retention_days)
        if removed:
            self._reclaim_until(time.monotonic() + PRUNE_RECLAIM_BUDGET_S)
        return removed

    def trim_to_size(self, max_bytes: int, budget_s: float | None = None) -> int:
        """Delete the oldest flow history until the store fits under the cap:
        raw flows first, then the rollups.

        Without stage two the base implementation would delete raw down to
        TRIM_FLOOR and then warn about the cap forever while the rollups held
        the space. Stage two deletes by oldest bucket, so it never touches
        the recent ones compact_rollup's redo window rewrites.
        """
        removed = super().trim_to_size(max_bytes, budget_s)
        if max_bytes <= 0 or self._trim_size() <= max_bytes:
            return removed
        deadline = time.monotonic() + (TRIM_BUDGET_S if budget_s is None else budget_s)
        for tier in ROLLUP_TIERS:
            if self._trim_size() <= max_bytes or time.monotonic() >= deadline:
                break
            with self._lock:
                bounds = self._conn.execute(
                    "SELECT MIN(bucket) AS lo, MAX(bucket) AS hi"
                    " FROM flow_rollup_span WHERE tier = ?", (tier,)).fetchone()
                held = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM flow_rollup WHERE tier = ?",
                    (tier,)).fetchone()["n"]
            if bounds["lo"] is None or held <= self.TRIM_ROLLUP_FLOOR:
                continue
            size = self._trim_size()
            span = bounds["hi"] - bounds["lo"] + tier
            want = max(tier, int(span * (1.0 - max_bytes / float(size)) * 1.1))
            batch_removed, reached = self._delete_batches(
                int(bounds["lo"]), int(bounds["lo"]) + want, deadline,
                delete=lambda lo, up, t=tier: self._delete_rollup(t, lo, up),
                chunk=3600, chunk_min=60, chunk_max=7 * 86400)
            removed += batch_removed
            floor, _watermark = self.rollup_bounds(tier)
            if floor is not None and reached > floor:
                self._set_private_setting(_FLOOR % tier, reached)
            self._reclaim_until(deadline)
        return removed

    def recent_endpoints(self, limit: int = 300, since_s: float = 3600) -> list[str]:
        """Busiest source and destination addresses seen recently.

        Answered from the minute tier where it covers the window: a few
        thousand rollup rows in place of two full scans of every flow in the
        last hour, joined. Bounded on purpose either way: a busy exporter
        sees tens of thousands of distinct addresses and only the heaviest
        ones reach the views.
        """
        cutoff = time.time() - since_s
        floor, watermark = self.rollup_bounds(60)
        if floor is not None and watermark is not None and cutoff >= floor:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT key AS ip, SUM(bytes) AS bytes FROM flow_rollup"
                    " WHERE tier = 60 AND dim IN (?,?) AND bucket >= ?"
                    " AND bucket < ? AND key != ''"
                    " GROUP BY ip ORDER BY bytes DESC LIMIT ?",
                    (DIMENSION_IDS["Source"], DIMENSION_IDS["Destination"],
                     _align_down(cutoff, 60), watermark, limit)).fetchall()
            return [row["ip"] for row in rows]
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

    def _rollup_plan(self, t0: float, t1: float, dimension: str | None,
                     filters: dict, bucket_s: float | None):
        """Which rollup tier can answer this window, or None for raw.

        Returns (tier, dim, seal_ts): buckets in [t0, seal_ts) come from the
        rollup and flows from seal_ts to t1 from the raw table. seal_ts is a
        multiple of the tier, so the two ranges are exactly complementary —
        nothing is counted twice and nothing falls between them. `dim` is
        None when only the spans are wanted.

        A filtered query is never rollup-served: the rollup holds one row
        per key, and the columns the filters select on are not in it.
        """
        if filters and any(filters.values()):
            return None
        if dimension is not None and dimension not in DIMENSION_IDS:
            return None
        for tier in sorted(ROLLUP_TIERS, reverse=True):
            if bucket_s is None:
                # Nothing to slot, so the finest tier is enough and the
                # window start moves by at most a minute.
                if tier != min(ROLLUP_TIERS):
                    continue
            elif tier > bucket_s or bucket_s % tier:
                # A bucket lands wholly inside one slot only when every slot
                # boundary is a multiple of the tier.
                continue
            floor, watermark = self.rollup_bounds(tier)
            if floor is None or watermark is None or t0 < floor:
                continue
            # Never past t1: a bucket straddling the end of the window holds
            # flows the raw path would not have counted.
            seal = min(watermark, _align_down(t1, tier))
            if seal <= t0:
                continue
            dim = None if dimension is None else DIMENSION_IDS[dimension]
            return tier, dim, seal
        return None

    def _agg_rows(self, t0: float, t1: float, dimension: str | None,
                  filters: dict, bucket_s: float | None):
        """One window's aggregate: (t0, bucket_s, n_buckets, rows, spans).

        `rows` are (key, slot, bytes, packets, flows) per grouping key;
        `spans` maps a slot to that slot's grand [bytes, packets, flows],
        which the rows do not add up to on their own — a rollup keeps only
        the heaviest keys of each bucket, and the span is what the residual
        is measured against. `dimension` of None asks for the spans alone,
        `bucket_s` of None puts the whole window in one slot.

        The returned `t0` is the aligned one, on the raw path as much as the
        rollup one: a bucket lands wholly inside one slot only when the
        slots start on a bucket boundary, and aligning only where a rollup
        happened to be used would shift the window under the operator every
        time a filter was toggled.
        """
        if bucket_s is None:
            align, n_buckets = float(min(ROLLUP_TIERS)), 1
        else:
            bucket_s = max(float(bucket_s), 1.0)
            # Under a minute nothing is rollup-served anyway.
            align = bucket_s if bucket_s % 60 == 0 else 0.0
        if align:
            t0 = float(_align_down(t0, align))
        if bucket_s is not None:
            n_buckets = max(1, int((t1 - t0) / bucket_s) + 1)
        plan = self._rollup_plan(t0, t1, dimension, filters, bucket_s)

        def slot(column: str) -> tuple[str, list]:
            if bucket_s is None:
                return "0", []
            return f"CAST(({column} - ?) / ? AS INTEGER)", [t0, bucket_s]

        key_sql: list[str] = []
        key_params: list = []
        span_sql: list[str] = []
        span_params: list = []
        raw_from = t0
        if plan is not None:
            tier, dim, raw_from = plan
            expr, expr_params = slot("bucket")
            if dim is not None:
                key_sql.append(
                    f"SELECT key, {expr} AS slot, bytes, packets, flows"
                    f" FROM flow_rollup WHERE tier = ? AND dim = ?"
                    f" AND bucket >= ? AND bucket < ?")
                key_params.extend([*expr_params, tier, dim, t0, raw_from])
            span_sql.append(
                f"SELECT {expr} AS slot, bytes, packets, flows"
                f" FROM flow_rollup_span WHERE tier = ? AND bucket >= ?"
                f" AND bucket < ?")
            span_params.extend([*expr_params, tier, t0, raw_from])

        where, where_params = self._where(raw_from, t1, filters)
        expr, expr_params = slot("ts_end")
        if dimension is not None:
            key = DIMENSIONS.get(dimension, DIMENSIONS["Application"])
            # Where a rollup covers part of the window the raw tail drops its
            # NULL keys too, so traffic a rollup cannot store does not appear
            # as its own series for three minutes of an hour-wide chart.
            unstorable = f" AND ({key}) IS NOT NULL" if plan is not None else ""
            key_sql.append(
                f"SELECT {key} AS key, {expr} AS slot,"
                f" bytes * sampling AS bytes, packets * sampling AS packets,"
                f" 1 AS flows FROM flows WHERE {where}{unstorable}")
            key_params.extend([*expr_params, *where_params])
        if plan is not None or dimension is None:
            span_sql.append(
                f"SELECT {expr} AS slot, bytes * sampling AS bytes,"
                f" packets * sampling AS packets, 1 AS flows"
                f" FROM flows WHERE {where}")
            span_params.extend([*expr_params, *where_params])

        rows: list = []
        spans: dict[int, list] = {}
        with self._lock:
            if key_sql:
                rows = self._conn.execute(
                    "SELECT key, slot, SUM(bytes) AS bytes,"
                    " SUM(packets) AS packets, SUM(flows) AS flows FROM ("
                    + " UNION ALL ".join(key_sql) +
                    ") GROUP BY key, slot", key_params).fetchall()
            if span_sql:
                for row in self._conn.execute(
                        "SELECT slot, SUM(bytes) AS bytes,"
                        " SUM(packets) AS packets, SUM(flows) AS flows FROM ("
                        + " UNION ALL ".join(span_sql) +
                        ") GROUP BY slot", span_params).fetchall():
                    spans[row["slot"]] = [row["bytes"] or 0, row["packets"] or 0,
                                          row["flows"] or 0]
        if not span_sql:
            # The raw path already read every key there is, so adding them up
            # is the same number a second scan of the window would return.
            for row in rows:
                entry = spans.setdefault(row["slot"], [0, 0, 0])
                entry[0] += row["bytes"] or 0
                entry[1] += row["packets"] or 0
                entry[2] += row["flows"] or 0
        if bucket_s is None:
            bucket_s = max(float(t1) - t0, 1.0)
        return t0, bucket_s, n_buckets, rows, spans

    def top(self, t0: float, t1: float, dimension: str, filters: dict,
            limit: int = 10) -> list[dict]:
        _times, _series, _bucket_s, top_rows, _totals = self.overview(
            t0, t1, dimension, filters, None, series_limit=0, top_limit=limit)
        return top_rows

    def series(self, t0: float, t1: float, dimension: str, filters: dict,
               bucket_s: float, limit: int = 8):
        """Stacked series for the top keys, with everything else as 'other'."""
        times, series, bucket_s, _top_rows, _totals = self.overview(
            t0, t1, dimension, filters, bucket_s, series_limit=limit,
            top_limit=limit)
        return times, series, bucket_s

    def overview(self, t0: float, t1: float, dimension: str, filters: dict,
                 bucket_s: float, series_limit: int = 8, top_limit: int = 10):
        """Everything the NetFlow overview needs, from one pass over the window.

        The `GROUP BY key, slot` scan holds two of the three answers: per key
        it is top(), by slot it is the series. The totals come from the
        per-slot grand totals instead, so they stay exact over a rollup that
        stored only the heaviest keys of each bucket.
        Returns (times, series, bucket_s, top_rows, totals).
        """
        t0, bucket_s, n_buckets, rows, spans = self._agg_rows(
            t0, t1, dimension, filters, bucket_s)

        per_key: dict[object, dict] = {}
        for row in rows:
            entry = per_key.setdefault(
                row["key"], {"bytes": 0, "packets": 0, "flows": 0})
            entry["bytes"] += row["bytes"] or 0
            entry["packets"] += row["packets"] or 0
            entry["flows"] += row["flows"] or 0

        totals = {"bytes": 0, "packets": 0, "flows": 0}
        for values in spans.values():
            totals["bytes"] += values[0]
            totals["packets"] += values[1]
            totals["flows"] += values[2]

        # The name breaks a tie, so two equal-volume keys keep the same order
        # — and so the same colour — from one refresh to the next. SQL's
        # ORDER BY left that order arbitrary.
        ordered = sorted(per_key.items(),
                         key=lambda kv: (-kv[1]["bytes"], str(kv[0])))
        top_rows = [{"key": k, **v} for k, v in ordered[:top_limit]]
        top_keys = [k for k, _ in ordered[:series_limit]]

        series: dict[object, list[float]] = {k: [0.0] * n_buckets for k in top_keys}
        wanted = set(top_keys)
        for row in rows:
            slot = row["slot"]
            if slot is None or slot < 0 or slot >= n_buckets:
                continue
            if row["key"] in wanted:
                series[row["key"]][slot] += row["bytes"] or 0

        # What the named series leave over, taken from the slot's own total
        # rather than by adding up the keys that were left out: on the rollup
        # path not all of them are stored, and on the raw path this is the
        # same number either way.
        other = [0.0] * n_buckets
        for slot, values in spans.items():
            if slot is None or slot < 0 or slot >= n_buckets:
                continue
            other[slot] += values[0]
        for values in series.values():
            for index, value in enumerate(values):
                other[index] -= value
        if any(other):
            series["\u2014 other \u2014"] = other

        times = [t0 + i * bucket_s for i in range(n_buckets)]
        return times, series, bucket_s, top_rows, totals

    def flows(self, t0: float, t1: float, filters: dict, limit: int = 200,
              order: str = "bytes") -> tuple[list[sqlite3.Row], bool]:
        """The window's heaviest — or most recent — individual records.

        Returns (rows, whether the FLOW_SCAN_CAP bound cut the window short),
        so the page can say the ordering is over the most recent flows rather
        than imply it searched every one of them. `order == "time"` is served
        end to end by ix_flows_ts and the bound never bites there.
        """
        where, params = self._where(t0, t1, filters)
        column = {"bytes": "bytes * sampling", "packets": "packets * sampling",
                  "time": "ts_end"}.get(order, "bytes * sampling")
        with self._lock:
            highest = self._conn.execute(
                "SELECT MAX(id) AS hi FROM flows").fetchone()["hi"] or 0
            floor_id = highest - FLOW_SCAN_CAP
            rows = self._conn.execute(
                f"SELECT * FROM flows WHERE id > ? AND {where}"
                f" ORDER BY {column} DESC LIMIT ?",
                (floor_id, *params, limit)).fetchall()
            # One primary-key probe rather than a count of what was left out:
            # ids are handed out in arrival order, so whether the row at the
            # bound is still inside the window is the same question.
            edge = None
            if floor_id > 0:
                edge = self._conn.execute(
                    "SELECT ts_end FROM flows WHERE id <= ? ORDER BY id DESC"
                    " LIMIT 1", (floor_id,)).fetchone()
        return rows, bool(edge is not None and edge["ts_end"] >= t0)

    def totals(self, t0: float, t1: float, filters: dict) -> dict:
        """Exact on both paths: a rollup's span row is the whole bucket, not
        the keys that fitted under the cap."""
        _t0, _bucket_s, _n, _rows, spans = self._agg_rows(
            t0, t1, None, filters, None)
        out = {"flows": 0, "bytes": 0, "packets": 0}
        for values in spans.values():
            out["bytes"] += values[0]
            out["packets"] += values[1]
            out["flows"] += values[2]
        return out
