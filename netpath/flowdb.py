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
missing — and the chart cannot tell the two apart, so the band an operator
is watching simply has holes in it. Every bucket where the cap bit is
therefore recorded (flow_rollup_trunc), and a read repairs those buckets
from the raw rows for as long as the raw rows still cover them; only a
bucket older than the raw retention keeps the hole.

Summaries are kept per scope as well as globally: per exporter at both tiers,
and per (exporter, interface, direction) at the hourly tier, each with its own
smaller cap. An exporter or interface filter reads its scope; an address,
port or protocol filter has no scope and reads raw.
"""

from __future__ import annotations

import logging
import sqlite3
import time

from .sqlitebase import (  # re-exported: tests adjust netpath.flowdb.TRIM_CHUNK
    LIKE_ESCAPE, TRIM_BUDGET_S, TRIM_CHUNK, TRIM_CHUNK_MAX, TRIM_CHUNK_MIN,
    SqliteStore, id_chunks, like_contains, marks_for)

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
"""

# Also run statement by statement by _before_schema's rebuild of an older store.
ROLLUP_SCHEMA = """
-- The heaviest keys of one dimension in one bucket, with the sampling factor
-- already multiplied in: it is per row, so it cannot be reapplied to a stored
-- sum. BLOB affinity stores each key as whatever the raw GROUP BY produced —
-- an integer port comes back an integer, an address comes back text — so the
-- two query paths hand api._flow_label the same thing. WITHOUT ROWID makes
-- the table its own clustered index in (tier, scope, dim, bucket) order,
-- which is the order every read scans it in. The scope columns default to
-- the global scope ('', -1, ''); see GLOBAL_SCOPE.
CREATE TABLE IF NOT EXISTS flow_rollup (
    tier     INTEGER NOT NULL,   -- bucket width in seconds: 60 or 3600
    exporter TEXT    NOT NULL DEFAULT '',
    iface    INTEGER NOT NULL DEFAULT -1,
    dir      TEXT    NOT NULL DEFAULT '',   -- 'in' / 'out' with an iface
    dim      INTEGER NOT NULL,   -- flowdb.DIMENSION_IDS, append-only
    bucket   INTEGER NOT NULL,   -- epoch seconds, always a multiple of tier
    key      BLOB    NOT NULL,
    bytes    INTEGER NOT NULL,
    packets  INTEGER NOT NULL,
    flows    INTEGER NOT NULL,
    PRIMARY KEY (tier, exporter, iface, dir, dim, bucket, key)
) WITHOUT ROWID;

-- Retention deletes by age across every scope and dimension at once, which
-- the scope-leading primary keys cannot serve; so do the per-bucket rebuilds.
CREATE INDEX IF NOT EXISTS ix_flow_rollup_bucket ON flow_rollup(tier, bucket);

-- What every dimension sums to, kept once rather than eleven times: the same
-- flows are counted whichever way they are grouped. This is what keeps the
-- totals exact under the top-K cap — the residual is this minus the keys
-- that were stored.
CREATE TABLE IF NOT EXISTS flow_rollup_span (
    tier     INTEGER NOT NULL,
    exporter TEXT    NOT NULL DEFAULT '',
    iface    INTEGER NOT NULL DEFAULT -1,
    dir      TEXT    NOT NULL DEFAULT '',
    bucket   INTEGER NOT NULL,
    bytes    INTEGER NOT NULL,
    packets  INTEGER NOT NULL,
    flows    INTEGER NOT NULL,
    PRIMARY KEY (tier, exporter, iface, dir, bucket)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_flow_rollup_span_bucket
    ON flow_rollup_span(tier, bucket);

-- Which (tier, dim, bucket) cells the ROLLUP_KEYS cap actually cut short:
-- present when the bucket held at least as many distinct keys as the cap
-- kept, absent otherwise. A read serves a flagged bucket from the raw rows
-- instead of the capped ones while the raw rows still reach it, so a key
-- that dipped below the cap for a minute is not drawn as zero for that
-- minute. Written and cleared by _compact_bucket alongside the rows it
-- describes, and aged out with them.
CREATE TABLE IF NOT EXISTS flow_rollup_trunc (
    tier     INTEGER NOT NULL,
    exporter TEXT    NOT NULL DEFAULT '',
    iface    INTEGER NOT NULL DEFAULT -1,
    dir      TEXT    NOT NULL DEFAULT '',
    dim      INTEGER NOT NULL,
    bucket   INTEGER NOT NULL,
    PRIMARY KEY (tier, exporter, iface, dir, dim, bucket)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_flow_rollup_trunc_bucket
    ON flow_rollup_trunc(tier, bucket);
"""

SCHEMA += ROLLUP_SCHEMA

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
    "rollup_interface_days": 30,
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

# The same cap for the scoped summaries. Smaller, because there are many
# more of them: E exporters x 10 dimensions per bucket, and for interfaces
# E x I x 2 directions x 10 per hour. Interface breakdowns are hourly only.
SCOPED_KEYS = {"exporter": {60: 32, 3600: 48}, "interface": {3600: 16}}

# (exporter, iface, dir) of the unscoped summaries.
GLOBAL_SCOPE = ("", -1, "")
_GLOBAL_SQL = "exporter = '' AND iface = -1 AND dir = ''"
_DIRECTIONS = {"in": ("in",), "out": ("out",), "both": ("in", "out")}
_IF_COLUMN = {"in": "in_if", "out": "out_if"}

# How much one read will repair from the raw rows before it gives up and
# serves the capped rollup as stored — two bounds, for two different costs.
# Both are for the global scope; see _repair_budget for the scoped ones.
#
# _REPAIR_MAX_BUCKETS bounds the statement. Each contiguous run of flagged
# buckets costs the key statement _agg_rows builds SIX bound parameters: two
# in the rollup arm's `AND NOT (bucket >= ? AND bucket < ?)` exclusion and
# four in the run's own UNION ALL raw arm (two for the slot expression, two
# for the ts_end range). The rest of the statement binds ten (six in the
# rollup arm, four in the raw tail; a filtered query is never repaired, so
# no filter terms). The worst case — no two flagged buckets adjacent — is
# one run per bucket, so 120 buckets is 120 * 6 + 10 = 730 parameters
# against the 999 an older SQLite allows (sqlitebase.id_chunks explains why
# 999, not 32766, is the number to plan for), a quarter of the limit
# spare; it is also 122 arms against the default compound-select ceiling
# of 500. 200 was over: 200 * 6 + 10 is about 1,200, and the query raised
# "too many SQL variables" on exactly the chart the bound was meant to keep
# whole. Past it a chart's holes stay exactly as they did before the flag
# existed, which is the answer the bound has always given.
#
# _REPAIR_MAX_FLOWS bounds the work: the raw rows the repair arms will scan,
# known in advance from the span rows' own flow counts. The overview holds
# the collector's write lock for the whole query and NetFlow is UDP, so a
# repair that took seconds would cost flows at the socket to redraw a chart;
# a hundred thousand rows is a few hundred milliseconds. A quiet store never
# reaches it; a store busy enough to does not get its holes repaired, which
# is where it stood before.
_REPAIR_MAX_BUCKETS = 120
_REPAIR_MAX_FLOWS = 100_000


def _repair_budget(scopes) -> tuple[int, int]:
    """(flagged buckets, raw flows) one scope of a query may repair.

    A scoped run costs up to eight parameters rather than six (the raw arm
    carries exporter = ? and in_if/out_if = ?), so 90 runs are the global
    120's ~730 parameters, split between the scopes of an 'both' query.
    """
    if list(scopes) == [GLOBAL_SCOPE]:
        return _REPAIR_MAX_BUCKETS, _REPAIR_MAX_FLOWS
    return (_REPAIR_MAX_BUCKETS * 3 // 4 // len(scopes),
            _REPAIR_MAX_FLOWS // len(scopes))

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
# the next pass has to rebuild behind its watermark, and nothing more. Per
# tier, because each consumes it at its own pace — one shared mark was
# cleared by whichever tier compacted first, and the other never saw it.
_DIRTY = "flow_rollup_dirty_ts_%d"
# How far back each tier's exporter-scope rows (and every scoped span row)
# reach, and the hourly interface breakdown's own: a store upgraded from the
# unscoped layout has none below the watermark it had. Backfill lowers each
# only while contiguous with it.
_SCOPED_FLOOR = "flow_rollup_scoped_floor_%d"
_IFACE_FLOOR = "flow_rollup_iface_floor"


def _align_down(ts: float, width: float) -> int:
    return int(float(ts) // width) * int(width)


def _align_up(ts: float, width: float) -> int:
    return -_align_down(-float(ts), width)


def _iface_filter(filters: dict) -> int | None:
    """The interface a filter names, only meaningful with an exporter."""
    iface = filters.get("iface")
    if not filters.get("exporter") or iface is None or iface == "":
        return None
    iface = int(iface)
    return iface if iface >= 0 else None


def _scopes(filters: dict) -> tuple[str | None, list]:
    """(kind, scopes) a filter set reads, kind None when only raw can answer."""
    if any(filters.get(name) for name in ("src_ip", "dst_ip", "port",
                                            "protocol")):
        return None, []
    exporter = filters.get("exporter")
    if not exporter:
        return "global", [GLOBAL_SCOPE]
    iface = _iface_filter(filters)
    if iface is None:
        return "exporter", [(exporter, -1, "")]
    sides = _DIRECTIONS.get(filters.get("direction") or "both",
                            _DIRECTIONS["both"])
    return "interface", [(exporter, iface, side) for side in sides]


def _sides(filters: dict) -> tuple:
    """The raw arms an aggregate needs: one per direction of an interface
    filter, so a hairpin flow counts once each way, as the scopes do."""
    if _iface_filter(filters) is None:
        return (None,)
    return _DIRECTIONS.get(filters.get("direction") or "both",
                           _DIRECTIONS["both"])


def _scope_where(scope) -> tuple[str, list]:
    """The raw-row clause equivalent to one scope."""
    exporter, iface, side = scope
    if not exporter:
        return "", []
    if iface < 0:
        return " AND exporter = ?", [exporter]
    return f" AND exporter = ? AND {_IF_COLUMN[side]} = ?", [exporter, iface]


def _statements(script: str):
    """Split a DDL script into statements, comments and all."""
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            yield pending
            pending = ""


def _top_k_sql(scope_cols: str, partition: str, source: str) -> str:
    """INSERT the heaviest keys of every partition of `source`: bind tier,
    dim, bucket, then the source's own parameters, then the cap."""
    return (f"INSERT INTO flow_rollup(tier, exporter, iface, dir, dim, bucket,"
            f" key, bytes, packets, flows) SELECT ?, {scope_cols}, ?, ?, key,"
            f" bytes, packets, flows FROM (SELECT *, ROW_NUMBER() OVER"
            f" (PARTITION BY {partition} ORDER BY bytes DESC, key) AS rn"
            f" FROM ({source})) WHERE rn <= ?")


_RAW_SUMS = ("COALESCE(SUM(bytes * sampling), 0) AS bytes,"
             " COALESCE(SUM(packets * sampling), 0) AS packets,"
             " COUNT(*) AS flows")


class FlowDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "flows.db"
    TRIM_TABLE = "flows"
    # The rollups reach further back than the raw rows they were built from,
    # so asking flows alone under-reports how much history this store holds.
    # Index probes, never a scan: /api/state polls this every ten seconds,
    # on the collector's write lock, for every open tab. MIN(ts_start) has no
    # index (ix_flows_ts is on ts_end) and walked the table; MIN(bucket) FROM
    # flow_rollup walked ix_flow_rollup_bucket in full, that index leading on
    # tier defeating the MIN optimisation. The oldest id is the oldest
    # arrival, and flow_rollup_span holds a row for every bucket flow_rollup
    # does — one arm per tier, since its primary key leads on tier and then
    # scope, so the global scope is bound to keep each arm a probe.
    OLDEST_TS_SQL = (
        "SELECT MIN(ts) FROM ("
        "SELECT ts FROM (SELECT ts_start AS ts FROM flows ORDER BY id LIMIT 1)"
        + "".join(f" UNION ALL SELECT MIN(bucket) FROM flow_rollup_span"
                  f" WHERE tier = {tier} AND {_GLOBAL_SQL}"
                  for tier in ROLLUP_TIERS) + ")")
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
        self.cap_held_back = 0   # rows prune()'s row-cap stage spared, not yet summarised
        self._compact_hit_limit: dict[int, bool] = {}   # tier -> whether compact_rollup's last call used its full bucket limit
        self._iface_built: int | None = None   # the last hourly bucket whose interface breakdown _compact_bucket rebuilt
        super().__init__(path)

    def _before_schema(self) -> None:
        """Rebuild an unscoped store's summaries with the scope columns.

        Before SCHEMA, so its CREATE ... IF NOT EXISTS never lands an index
        on an old table. One transaction; a *_old table found at open is a
        rebuild to finish, not one to start.
        """
        names = {row[0] for row in self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN"
            " ('flow_rollup', 'flow_rollup_span', 'flow_rollup_trunc',"
            " 'flow_rollup_old', 'flow_rollup_span_old',"
            " 'flow_rollup_trunc_old')")}
        legacy = "flow_rollup" in names and "exporter" not in {
            row[1] for row in self._conn.execute(
                "PRAGMA table_info(flow_rollup)")}
        if not legacy and not any(name.endswith("_old") for name in names):
            return
        copies = (("flow_rollup", "tier, dim, bucket, key, bytes, packets, flows"),
                  ("flow_rollup_span", "tier, bucket, bytes, packets, flows"),
                  ("flow_rollup_trunc", "tier, dim, bucket"))
        copied = 0
        self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if legacy:
                for index in ("ix_flow_rollup_bucket", "ix_flow_rollup_span_bucket",
                              "ix_flow_rollup_trunc_bucket"):
                    self._conn.execute(f"DROP INDEX IF EXISTS {index}")
                for table, _columns in copies:
                    if table in names:
                        self._conn.execute(
                            f"ALTER TABLE {table} RENAME TO {table}_old")
                        names.add(f"{table}_old")
            for statement in _statements(ROLLUP_SCHEMA):
                self._conn.execute(statement)
            for table, columns in copies:
                if f"{table}_old" not in names:
                    continue
                copied += self._conn.execute(
                    f"INSERT OR IGNORE INTO {table}({columns})"
                    f" SELECT {columns} FROM {table}_old").rowcount or 0
                self._conn.execute(f"DROP TABLE {table}_old")
            has_settings = self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table'"
                " AND name = 'settings'").fetchone() is not None
            for tier in ROLLUP_TIERS if has_settings else ():
                watermark = self._private_setting(_WATERMARK % tier)
                if watermark is None:
                    continue
                self._set_private_setting(_SCOPED_FLOOR % tier, watermark,
                                          commit=False)
                if tier in SCOPED_KEYS["interface"]:
                    self._set_private_setting(_IFACE_FLOOR, watermark,
                                              commit=False)
            self._conn.commit()
        except sqlite3.DatabaseError:
            self._conn.rollback()
            raise
        log.info("netpath.flowdb: flow summaries rebuilt with a scope column"
                 " (%d row(s) carried over as the global scope)", copied)

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

    def save_template_cache(self, payload) -> None:
        """Persist the decoder's learned v9/IPFIX templates across a restart."""
        self._set_private_setting("template_cache", payload)

    def load_template_cache(self) -> list:
        return self._private_setting("template_cache", []) or []

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
            # value, which is the same kind of dirt a late flush leaves:
            # each tier rebuilds from here, and each clears its own mark once
            # it has, so whichever compacts first cannot consume it for the
            # other. Whatever the caller's bound turns out to be.
            self._mark_dirty(since_ts)
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
            self._conn.executemany(
                "INSERT INTO interfaces(exporter, if_index, name) VALUES (?,?,?)"
                " ON CONFLICT(exporter, if_index) DO UPDATE SET name=excluded.name",
                [(exporter, index, name)
                 for (exporter, index), name in mapping.items()])
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

    def _scope_floor(self, tier: int, kind: str) -> int | None:
        """How far back a tier answers for a scope kind: the tier's floor,
        raised by the scoped floor, and for interfaces by their own."""
        floor, _watermark = self.rollup_bounds(tier)
        marks = [floor]
        if kind != "global":
            marks.append(self._private_setting(_SCOPED_FLOOR % tier))
        if kind == "interface" and tier in SCOPED_KEYS["interface"]:
            marks.append(self._private_setting(_IFACE_FLOOR))
        if any(mark is None for mark in marks):
            return None
        return max(int(mark) for mark in marks)

    def _seed_scoped(self, tier: int, at: int) -> None:
        """Start a tier's scoped floors where its scoped rows start, if unset."""
        keys = [_SCOPED_FLOOR % tier]
        if tier in SCOPED_KEYS["interface"]:
            keys.append(_IFACE_FLOOR)
        for key in keys:
            if self._private_setting(key) is None:
                self._set_private_setting(key, int(at))

    def _raise_floors(self, tier: int, reached: int) -> None:
        """Retention or the size cap removed every scope below `reached`."""
        keys = [_FLOOR % tier, _SCOPED_FLOOR % tier]
        if tier in SCOPED_KEYS["interface"]:
            keys.append(_IFACE_FLOOR)
        for key in keys:
            current = self._private_setting(key)
            if current is not None and reached > int(current):
                self._set_private_setting(key, reached)

    def _oldest_raw(self) -> float | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(ts_end) AS oldest FROM flows").fetchone()
        return row["oldest"] if row else None

    def _raw_covers(self, tier: int, bucket: int, from_minutes: bool) -> bool:
        """Whether the raw rows still hold everything the bucket's minute
        rows counted: interface breakdowns can only be built from raw."""
        if not from_minutes:
            return True
        with self._lock:
            wanted = self._conn.execute(
                f"SELECT COALESCE(SUM(flows), 0) AS n FROM flow_rollup_span"
                f" WHERE tier = 60 AND {_GLOBAL_SQL} AND bucket >= ?"
                f" AND bucket < ?", (bucket, bucket + tier)).fetchone()["n"]
            held = self._conn.execute(
                "SELECT COUNT(*) AS n FROM flows WHERE ts_end >= ?"
                " AND ts_end < ?", (bucket, bucket + tier)).fetchone()["n"]
        return held >= wanted

    def _compact_bucket(self, tier: int, bucket: int) -> int:
        """Rebuild one bucket of every dimension and scope, and its spans.

        Delete and insert rather than upsert: which keys make the top-K
        changes when a bucket is recomputed, so a key that has dropped out
        of the cap has to be cleared rather than left behind at its old
        value. One transaction per dimension and scope, so the write lock is
        never held across more than one.
        """
        from_minutes = self._from_minute_tier(tier, bucket)
        scoped_floor = self._private_setting(_SCOPED_FLOOR % 60)
        scoped_minutes = (from_minutes and scoped_floor is not None
                          and bucket >= int(scoped_floor))
        exporters: list = []
        if scoped_minutes:
            with self._lock:
                exporters = [row[0] for row in self._conn.execute(
                    "SELECT DISTINCT exporter FROM flow_rollup_span"
                    " WHERE tier = 60 AND bucket >= ? AND bucket < ?"
                    " AND exporter != '' AND iface = -1",
                    (bucket, bucket + tier))]
        # Kept as built rather than rebuilt short once raw has been pruned.
        interfaces = (tier in SCOPED_KEYS["interface"]
                      and self._raw_covers(tier, bucket, from_minutes))
        written = 0
        for name, expr in DIMENSIONS.items():
            dim = DIMENSION_IDS[name]
            written += self._compact_global(tier, bucket, dim, expr,
                                            from_minutes)
            # The collector's writer is waiting on this lock and a Python lock
            # is not fair, the same reason sqlitebase.reclaim yields between
            # its steps.
            time.sleep(0)
            if name == "Exporter":
                continue   # one key per exporter scope: its span says it all
            written += self._compact_exporters(tier, bucket, dim, expr,
                                               scoped_minutes, exporters)
            time.sleep(0)
            if interfaces:
                for side in _DIRECTIONS["both"]:
                    written += self._compact_interfaces(tier, bucket, dim,
                                                        expr, side)
                    time.sleep(0)
        self._compact_spans(tier, bucket, from_minutes, scoped_minutes,
                            tier == 60 or scoped_minutes or interfaces)
        if tier in SCOPED_KEYS["interface"]:
            self._iface_built = bucket if interfaces else None
        return written

    def _compact_global(self, tier: int, bucket: int, dim: int, expr: str,
                        from_minutes: bool) -> int:
        limit = ROLLUP_KEYS[tier]
        with self._lock:
            self._conn.execute(
                f"DELETE FROM flow_rollup WHERE tier = ? AND {_GLOBAL_SQL}"
                f" AND dim = ? AND bucket = ?", (tier, dim, bucket))
            # The flag goes with the rows it describes: a bucket rebuilt
            # with fewer keys than the cap — late flows resampled away,
            # say — stops being flagged rather than being repaired from
            # raw for ever.
            self._conn.execute(
                f"DELETE FROM flow_rollup_trunc WHERE tier = ? AND {_GLOBAL_SQL}"
                f" AND dim = ? AND bucket = ?", (tier, dim, bucket))
            if from_minutes:
                cursor = self._conn.execute(
                    f"INSERT INTO flow_rollup(tier, dim, bucket, key, bytes,"
                    f" packets, flows) SELECT ?, ?, ?, key, bytes, packets,"
                    f" flows FROM (SELECT key, SUM(bytes) AS bytes,"
                    f" SUM(packets) AS packets, SUM(flows) AS flows"
                    f" FROM flow_rollup WHERE tier = 60 AND {_GLOBAL_SQL}"
                    f" AND dim = ? AND bucket >= ? AND bucket < ?"
                    f" GROUP BY key ORDER BY bytes DESC LIMIT ?)",
                    (tier, dim, bucket, dim, bucket, bucket + tier, limit))
            else:
                cursor = self._conn.execute(
                    f"INSERT INTO flow_rollup(tier, dim, bucket, key, bytes,"
                    f" packets, flows) SELECT ?, ?, ?, key, bytes, packets,"
                    f" flows FROM (SELECT {expr} AS key, {_RAW_SUMS} FROM flows"
                    f" WHERE ts_end >= ? AND ts_end < ?"
                    f" AND ({expr}) IS NOT NULL"
                    f" GROUP BY key ORDER BY bytes DESC LIMIT ?)",
                    (tier, dim, bucket, bucket, bucket + tier, limit))
            stored = cursor.rowcount or 0
            # rowcount reaching the LIMIT is the only evidence there is
            # that the cap bit — the query cannot say how many keys it
            # did not keep without counting them, which is the scan the
            # cap exists to avoid. A bucket holding exactly `limit` keys
            # is flagged too: a false positive that costs one raw read
            # and changes no number.
            truncated = stored >= limit
            if not truncated and from_minutes:
                # Built from minute rows that were themselves capped:
                # the hour's sums are short by whatever those minutes
                # lost, whether or not its own LIMIT was reached.
                truncated = self._conn.execute(
                    f"SELECT 1 FROM flow_rollup_trunc WHERE tier = 60"
                    f" AND {_GLOBAL_SQL} AND dim = ? AND bucket >= ?"
                    f" AND bucket < ? LIMIT 1",
                    (dim, bucket, bucket + tier)).fetchone() is not None
            if truncated:
                self._conn.execute(
                    "INSERT INTO flow_rollup_trunc(tier, dim, bucket)"
                    " VALUES (?, ?, ?)", (tier, dim, bucket))
            self._conn.commit()
        return stored

    def _compact_exporters(self, tier: int, bucket: int, dim: int, expr: str,
                           from_minutes: bool, exporters: list) -> int:
        """The exporter scope of one dimension: each exporter's top keys."""
        limit = SCOPED_KEYS["exporter"][tier]
        scope = "exporter != '' AND iface = -1"
        stored = 0
        with self._lock:
            for table in ("flow_rollup", "flow_rollup_trunc"):
                self._conn.execute(
                    f"DELETE FROM {table} WHERE tier = ? AND bucket = ?"
                    f" AND dim = ? AND {scope}", (tier, bucket, dim))
            if from_minutes:
                for chunk in id_chunks(exporters):
                    source = (f"SELECT exporter, key, SUM(bytes) AS bytes,"
                              f" SUM(packets) AS packets, SUM(flows) AS flows"
                              f" FROM flow_rollup WHERE tier = 60"
                              f" AND exporter IN ({marks_for(chunk)})"
                              f" AND iface = -1 AND dir = '' AND dim = ?"
                              f" AND bucket >= ? AND bucket < ?"
                              f" GROUP BY exporter, key")
                    stored += self._conn.execute(
                        _top_k_sql("exporter, -1, ''", "exporter", source),
                        (tier, dim, bucket, *chunk, dim, bucket, bucket + tier,
                         limit)).rowcount or 0
                self._conn.execute(
                    f"INSERT OR IGNORE INTO flow_rollup_trunc(tier, exporter,"
                    f" iface, dir, dim, bucket) SELECT DISTINCT ?, exporter,"
                    f" -1, '', ?, ? FROM flow_rollup_trunc WHERE tier = 60"
                    f" AND bucket >= ? AND bucket < ? AND dim = ? AND {scope}",
                    (tier, dim, bucket, bucket, bucket + tier, dim))
            else:
                source = (f"SELECT exporter, {expr} AS key, {_RAW_SUMS}"
                          f" FROM flows WHERE ts_end >= ? AND ts_end < ?"
                          f" AND ({expr}) IS NOT NULL GROUP BY exporter, key")
                stored = self._conn.execute(
                    _top_k_sql("exporter, -1, ''", "exporter", source),
                    (tier, dim, bucket, bucket, bucket + tier,
                     limit)).rowcount or 0
            self._flag_capped(tier, bucket, dim, scope, "exporter, -1, ''",
                              "exporter", limit)
            self._conn.commit()
        return stored

    def _compact_interfaces(self, tier: int, bucket: int, dim: int, expr: str,
                            side: str) -> int:
        """One direction of the interface scope of one dimension, from raw:
        flows with in_if (or out_if) = N are interface N's."""
        limit = SCOPED_KEYS["interface"][tier]
        column = _IF_COLUMN[side]
        scope = "iface >= 0 AND dir = ?"
        with self._lock:
            for table in ("flow_rollup", "flow_rollup_trunc"):
                self._conn.execute(
                    f"DELETE FROM {table} WHERE tier = ? AND bucket = ?"
                    f" AND dim = ? AND {scope}", (tier, bucket, dim, side))
            source = (f"SELECT exporter, {column} AS iface, {expr} AS key,"
                      f" {_RAW_SUMS} FROM flows WHERE ts_end >= ?"
                      f" AND ts_end < ? AND {column} >= 0"
                      f" AND ({expr}) IS NOT NULL"
                      f" GROUP BY exporter, {column}, key")
            stored = self._conn.execute(
                _top_k_sql(f"exporter, iface, '{side}'", "exporter, iface",
                           source),
                (tier, dim, bucket, bucket, bucket + tier,
                 limit)).rowcount or 0
            self._flag_capped(tier, bucket, dim, scope, "exporter, iface, dir",
                              "exporter, iface, dir", limit, (side,))
            self._conn.commit()
        return stored

    def _flag_capped(self, tier: int, bucket: int, dim: int, scope: str,
                     columns: str, group: str, limit: int, extra=()) -> None:
        """Flag every scope of the bucket whose stored keys reached the cap.
        Lock held, no commit."""
        self._conn.execute(
            f"INSERT OR IGNORE INTO flow_rollup_trunc(tier, exporter, iface,"
            f" dir, dim, bucket) SELECT ?, {columns}, ?, ? FROM flow_rollup"
            f" WHERE tier = ? AND bucket = ? AND dim = ? AND {scope}"
            f" GROUP BY {group} HAVING COUNT(*) >= ?",
            (tier, dim, bucket, tier, bucket, dim, *extra, limit))

    def _compact_spans(self, tier: int, bucket: int, from_minutes: bool,
                       scoped_minutes: bool, interfaces: bool) -> None:
        """Every scope's grand totals for the bucket, in one transaction.
        Interface spans are left as they are when `interfaces` is false."""
        upper = bucket + tier
        raw_where = "ts_end >= ? AND ts_end < ?"
        minute_where = "tier = 60 AND bucket >= ? AND bucket < ?"
        with self._lock:
            self._conn.execute(
                "DELETE FROM flow_rollup_span WHERE tier = ? AND bucket = ?"
                + ("" if interfaces else " AND iface = -1"), (tier, bucket))
            if from_minutes:
                self._conn.execute(
                    f"INSERT INTO flow_rollup_span(tier, bucket, bytes, packets,"
                    f" flows) SELECT ?, ?, SUM(bytes), SUM(packets), SUM(flows)"
                    f" FROM flow_rollup_span WHERE {minute_where}"
                    f" AND {_GLOBAL_SQL} HAVING COUNT(*) > 0",
                    (tier, bucket, bucket, upper))
            else:
                self._conn.execute(
                    f"INSERT INTO flow_rollup_span(tier, bucket, bytes, packets,"
                    f" flows) SELECT ?, ?, {_RAW_SUMS} FROM flows"
                    f" WHERE {raw_where} HAVING COUNT(*) > 0",
                    (tier, bucket, bucket, upper))
            insert = ("INSERT INTO flow_rollup_span(tier, exporter, iface, dir,"
                      " bucket, bytes, packets, flows) ")
            if scoped_minutes:
                self._conn.execute(
                    insert + f"SELECT ?, exporter, iface, dir, ?, SUM(bytes),"
                    f" SUM(packets), SUM(flows) FROM flow_rollup_span"
                    f" WHERE {minute_where} AND exporter != ''"
                    + ("" if interfaces else " AND iface = -1")
                    + " GROUP BY exporter, iface, dir",
                    (tier, bucket, bucket, upper))
            else:
                self._conn.execute(
                    insert + f"SELECT ?, exporter, -1, '', ?, {_RAW_SUMS}"
                    f" FROM flows WHERE {raw_where} GROUP BY exporter",
                    (tier, bucket, bucket, upper))
                for side, column in _IF_COLUMN.items() if interfaces else ():
                    self._conn.execute(
                        insert + f"SELECT ?, exporter, {column}, '{side}', ?,"
                        f" {_RAW_SUMS} FROM flows WHERE {raw_where}"
                        f" AND {column} >= 0 GROUP BY exporter, {column}",
                        (tier, bucket, bucket, upper))
            self._conn.commit()

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
            self._seed_scoped(tier, sealed)
            self._compact_hit_limit[tier] = False
            return 0
        self._seed_scoped(tier, watermark)
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
        self._compact_hit_limit[tier] = processed >= limit   # a catch-up signal _rollup_loop repeats compaction on
        return written + self._redo_dirty(tier, watermark, floor,
                                          limit - processed, deadline)

    def compact_hit_limit(self, tier: int) -> bool:
        """Whether the last compact_rollup(tier) call used its full bucket allowance."""
        return self._compact_hit_limit.get(tier, False)

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
            self._set_private_setting(_DIRTY % tier, None)
        if dirty is None:
            return 0
        bucket = _align_down(float(dirty), tier)
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
        stop = self._backfill_stop(tier)
        if stop is None:
            # Nothing to summarise from. Walking on would build empty buckets
            # every sweep until the retention floor caught up with the cursor.
            return 0, False
        limit = _ROLLUP_MAX_BUCKETS[tier] if max_buckets is None else max_buckets
        deadline = time.monotonic() + budget_s
        written = 0
        processed = 0
        bucket = floor - tier
        while (bucket >= stop and processed < limit
               and time.monotonic() < deadline):
            written += self._compact_bucket(tier, bucket)
            self._set_private_setting(_FLOOR % tier, bucket)
            # A gap in a scope's history (an upgraded store's) stays a gap.
            scoped = self._private_setting(_SCOPED_FLOOR % tier)
            if scoped is not None and int(scoped) == bucket + tier:
                self._set_private_setting(_SCOPED_FLOOR % tier, bucket)
            iface = (self._private_setting(_IFACE_FLOOR)
                     if tier in SCOPED_KEYS["interface"] else None)
            if (iface is not None and int(iface) == bucket + tier
                    and self._iface_built == bucket):
                self._set_private_setting(_IFACE_FLOOR, bucket)
            bucket -= tier
            processed += 1
        done = bucket < stop and processed > 0
        return written, done

    def _backfill_stop(self, tier: int) -> int | None:
        """The oldest bucket backfill may build, or None with no raw rows:
        neither below the raw rows the summaries are built from, nor below
        what retention will delete on this same sweep."""
        oldest = self._oldest_raw()
        if oldest is None:
            return None
        setting = ROLLUP_DAYS_SETTING[tier]
        days = float(self.settings().get(setting, DEFAULTS[setting]))
        return max(_align_down(time.time() - days * 86400, tier),
                   _align_down(float(oldest), tier))

    def backfill_pending(self, tier: int) -> bool:
        """Whether backfill_rollup(tier) still has history to walk."""
        floor, _watermark = self.rollup_bounds(tier)
        if floor is None:
            return False
        stop = self._backfill_stop(tier)
        return stop is not None and floor - tier >= stop

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

    def _delete_rollup(self, tier: int, low: int, upper: int,
                       scope: str = "") -> int:
        """All three rollup tables for buckets in [low, upper), every scope
        unless `scope` narrows it. Lock held, no commit: _delete_batches
        owns each."""
        cursor = self._conn.execute(
            f"DELETE FROM flow_rollup WHERE tier = ? AND bucket >= ?"
            f" AND bucket < ?{scope}", (tier, low, upper))
        removed = cursor.rowcount or 0
        cursor = self._conn.execute(
            f"DELETE FROM flow_rollup_span WHERE tier = ? AND bucket >= ?"
            f" AND bucket < ?{scope}", (tier, low, upper))
        removed += cursor.rowcount or 0
        # The flags describe rows that are now gone, and a flag with no
        # rollup behind it would otherwise outlive every retention there is.
        # Not counted: they are bookkeeping, not history.
        self._conn.execute(
            f"DELETE FROM flow_rollup_trunc WHERE tier = ? AND bucket >= ?"
            f" AND bucket < ?{scope}", (tier, low, upper))
        return removed

    def _prune_rollup(self, tier: int, days: float, deadline: float) -> int:
        """Age out one tier, walking bucket timestamps the way the raw
        stages walk ids: _delete_batches only needs a monotonic coordinate,
        and it sizes its own batches from how long each one held the lock."""
        cutoff = _align_down(time.time() - days * 86400, tier)
        with self._lock:
            row = self._conn.execute(
                f"SELECT MIN(bucket) AS lo FROM flow_rollup_span WHERE tier = ?"
                f" AND {_GLOBAL_SQL} AND bucket < ?", (tier, cutoff)).fetchone()
        oldest = row["lo"] if row else None
        if oldest is None:
            return 0
        removed, reached = self._delete_batches(
            int(oldest), cutoff, deadline,
            delete=lambda lo, up: self._delete_rollup(tier, lo, up),
            chunk=3600, chunk_min=60, chunk_max=7 * 86400)
        # Routing must stop trusting history that is no longer there, even
        # where the sweep only reached part of it.
        self._raise_floors(tier, reached)
        return removed

    def _prune_interfaces(self, days: float, deadline: float) -> int:
        """Age out the hourly interface scope on its own, shorter clock."""
        tier = 3600
        cutoff = _align_down(time.time() - days * 86400, tier)
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(bucket) AS lo FROM flow_rollup_span WHERE tier = ?"
                " AND bucket < ? AND iface >= 0", (tier, cutoff)).fetchone()
        oldest = row["lo"] if row else None
        removed = 0
        reached = cutoff
        if oldest is not None:
            removed, reached = self._delete_batches(
                int(oldest), cutoff, deadline,
                delete=lambda lo, up: self._delete_rollup(tier, lo, up,
                                                          " AND iface >= 0"),
                chunk=3600, chunk_min=3600, chunk_max=7 * 86400)
        current = self._private_setting(_IFACE_FLOOR)
        if current is not None and reached > int(current):
            self._set_private_setting(_IFACE_FLOOR, reached)
        return removed

    def _summary_watermark(self) -> int | None:
        """The oldest bucket some seeded tier has yet to build from raw: the
        hourly interface breakdown is built from raw an hour after the fact."""
        marks = [self.rollup_bounds(tier)[1] for tier in ROLLUP_TIERS]
        marks = [mark for mark in marks if mark is not None]
        return min(marks) if marks else None

    def prune(self, retention_days: float, max_flows: int, *,
              minute_days: float | None = None, rollup_days: float | None = None,
              interface_days: float | None = None,
              budget_s: float = TRIM_BUDGET_S) -> int:
        """Age out raw flows, cap their row count, and age out the rollups.

        Batched in adaptive, lock-bounded chunks rather than one DELETE per
        stage: the write lock is the one the collector's writer needs, and
        NetFlow is UDP, so a writer stalled behind a month-wide delete is
        lost data. Every batch of the age stage filters on ts_end, so an
        exporter with a wrong clock cannot make prune() drop the wrong rows;
        the row-cap stage chunks by id, which is arrival order.

        `retention_days` and `max_flows` bound the raw table alone;
        `interface_days` bounds the hourly interface breakdowns. Passing 0
        for the first four (the Settings page's maintenance button) matches
        every existing row.
        """
        now = time.time()
        cutoff = now - retention_days * 86400
        deadline = time.monotonic() + budget_s
        removed = 0
        incomplete = False

        # Counted, not bounded by MIN(id)/MAX(id) over the aged rows: one
        # flow arriving now from an exporter whose clock is years out takes
        # the newest id, which put MAX(id) at the end of the table and had
        # every sweep chunk-walk all five million rows of it — correctly
        # filtered, but O(table) every fifteen minutes, and slow enough to
        # trip the incomplete warning below. The count is the same
        # covering-index scan of ix_flows_ts the bounds query was.
        with self._lock:
            aged = self._conn.execute(
                "SELECT COUNT(*) AS n FROM flows WHERE ts_end < ?",
                (cutoff,)).fetchone()["n"]
        if aged:
            def by_age(lo: int, up: int) -> int:
                # Driven off ix_flows_ts, oldest first: the coordinate
                # _delete_batches walks is how many rows have gone, so the
                # sweep costs what it deletes and nothing for what it keeps.
                cursor = self._conn.execute(
                    "DELETE FROM flows WHERE id IN (SELECT id FROM flows"
                    " WHERE ts_end < ? ORDER BY ts_end LIMIT ?)",
                    (cutoff, up - lo))
                return cursor.rowcount or 0

            gone, reached = self._delete_batches(
                0, aged, deadline, by_age, chunk=TRIM_CHUNK,
                chunk_min=TRIM_CHUNK_MIN, chunk_max=TRIM_CHUNK_MAX)
            removed += gone
            incomplete = incomplete or reached < aged

        held_back = 0
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
                cap_upper = low + over
                # Never cap past what the summaries have built, so a slow compact_rollup cannot leave a permanent hole.
                summary_watermark = self._summary_watermark()
                if summary_watermark is not None:
                    # Upper-bounded at now+3600 (the decoders' own clamp) so a bad-clock row cannot pin this on itself forever.
                    with self._lock:
                        row = self._conn.execute(
                            "SELECT MIN(id) AS id FROM flows"
                            " WHERE ts_end >= ? AND ts_end < ?",
                            (summary_watermark, time.time() + 3600)).fetchone()
                    watermark_id = row["id"]
                    if watermark_id is not None and watermark_id < cap_upper:
                        held_back = cap_upper - watermark_id
                        cap_upper = watermark_id
                if cap_upper > low:
                    capped, reached = self._delete_batches(
                        low, cap_upper, deadline, chunk=TRIM_CHUNK,
                        chunk_min=TRIM_CHUNK_MIN, chunk_max=TRIM_CHUNK_MAX)
                    removed += capped
                    incomplete = incomplete or reached < cap_upper
        self.cap_held_back = held_back
        if held_back:
            log.warning("netpath.flowdb: row cap held back %d flow(s) not yet"
                        " summarised (summaries watermark behind)", held_back)

        for tier, days in ((60, minute_days), (3600, rollup_days)):
            if days is None:
                setting = ROLLUP_DAYS_SETTING[tier]
                days = float(self.settings().get(setting, DEFAULTS[setting]))
            removed += self._prune_rollup(tier, float(days), deadline)
        if interface_days is None:
            interface_days = float(self.settings().get(
                "rollup_interface_days", DEFAULTS["rollup_interface_days"]))
        removed += self._prune_interfaces(float(interface_days), deadline)

        self.last_prune_incomplete = incomplete
        if incomplete:
            log.warning("netpath.flowdb: prune of flows older than %.1f days did "
                        "not finish within its budget; continuing at the next "
                        "maintenance pass", retention_days)
        if removed:
            self._reclaim_until(time.monotonic() + PRUNE_RECLAIM_BUDGET_S)
        return removed

    def _trim_more(self, max_bytes: int, budget_s: float | None = None) -> int:
        """Stage two of the size cap: the oldest rollup buckets, once the raw
        flows have reached TRIM_FLOOR.

        Without it the base implementation would delete raw down to that
        floor and then warn about the cap forever while the rollups held the
        space. Deletes by oldest bucket, so it never touches the recent ones
        a compaction pass rewrites. A hook rather than an override, so the
        base emits its over-cap warning after this rather than before it.
        """
        removed = 0
        if max_bytes <= 0 or self._trim_size() <= max_bytes:
            return removed
        deadline = time.monotonic() + (TRIM_BUDGET_S if budget_s is None else budget_s)
        for tier in ROLLUP_TIERS:
            if self._trim_size() <= max_bytes or time.monotonic() >= deadline:
                break
            with self._lock:
                bounds = self._conn.execute(
                    f"SELECT MIN(bucket) AS lo, MAX(bucket) AS hi"
                    f" FROM flow_rollup_span WHERE tier = ? AND {_GLOBAL_SQL}",
                    (tier,)).fetchone()
                held = self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM flow_rollup WHERE tier = ?"
                    f" AND {_GLOBAL_SQL}", (tier,)).fetchone()["n"]
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
            self._raise_floors(tier, reached)
            self._reclaim_until(deadline)
        return removed

    def _trim_id_ceiling(self, cut: int) -> int | None:
        """Caps the size cap's first stage at the summaries' watermark, the
        same protection prune()'s row-cap stage applies to its own cut."""
        summary_watermark = self._summary_watermark()
        if summary_watermark is None:
            return None
        with self._lock:
            ceiling_row = self._conn.execute(
                "SELECT MIN(id) AS id FROM flows WHERE ts_end >= ? AND ts_end < ?",
                (summary_watermark, time.time() + 3600)).fetchone()
        ceiling = ceiling_row["id"]
        if ceiling is None or ceiling >= cut:
            return ceiling
        held = cut - ceiling
        self.cap_held_back = held
        log.warning("netpath.flowdb: size cap held back %d flow(s) not yet"
                    " summarised (summaries watermark behind)", held)
        return ceiling

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
                    f"SELECT key AS ip, SUM(bytes) AS bytes FROM flow_rollup"
                    f" WHERE tier = 60 AND {_GLOBAL_SQL} AND dim IN (?,?)"
                    f" AND bucket >= ? AND bucket < ? AND key != ''"
                    f" GROUP BY ip ORDER BY bytes DESC LIMIT ?",
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

    def minute_lag_s(self) -> float | None:
        """Seconds sealed time is ahead of the minute rollup watermark, or None before the tier is seeded."""
        _floor, watermark = self.rollup_bounds(60)
        if watermark is None:
            return None
        sealed = _align_down(time.time() - _ROLLUP_LAG_S, 60)
        return max(0.0, sealed - watermark)

    def coverage(self) -> dict:
        """What each tier still covers, for the NetFlow status strip (A5)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT MIN(ts_end) AS oldest, MAX(ts_end) AS newest"
                " FROM flows").fetchone()
        minute_floor, minute_watermark = self.rollup_bounds(60)
        hourly_floor, hourly_watermark = self.rollup_bounds(3600)
        return {
            "raw_oldest": row["oldest"], "raw_newest": row["newest"],
            "minute_floor": minute_floor, "minute_watermark": minute_watermark,
            "hourly_floor": hourly_floor, "hourly_watermark": hourly_watermark,
            # Where an exporter filter, and an interface one, reach back to.
            "scoped_minute_floor": self._scope_floor(60, "exporter"),
            "scoped_hourly_floor": self._scope_floor(3600, "exporter"),
            "iface_hourly_floor": self._scope_floor(3600, "interface"),
            "cap_held_back": self.cap_held_back,
            "prune_incomplete": self.last_prune_incomplete,
        }

    # ------------------------------------------------------------------ query

    def _where(self, t0: float, t1: float, filters: dict,
               side: str | None = None) -> tuple[str, list]:
        """`side` pins an interface filter to one direction; without it
        'both' matches either, which is what the record list wants."""
        clauses = ["ts_end >= ?", "ts_end <= ?"]
        params: list = [t0, t1]
        if filters.get("src_ip"):
            clauses.append(f"src_ip LIKE ? {LIKE_ESCAPE}")
            params.append(like_contains(filters["src_ip"]))
        if filters.get("dst_ip"):
            clauses.append(f"dst_ip LIKE ? {LIKE_ESCAPE}")
            params.append(like_contains(filters["dst_ip"]))
        if filters.get("port"):
            clauses.append("(src_port = ? OR dst_port = ?)")
            params.extend([int(filters["port"]), int(filters["port"])])
        if filters.get("protocol"):
            clauses.append("protocol = ?")
            params.append(int(filters["protocol"]))
        if filters.get("exporter"):
            clauses.append("exporter = ?")
            params.append(filters["exporter"])
        iface = _iface_filter(filters)
        if iface is not None:
            side = side or filters.get("direction") or "both"
            if side in _IF_COLUMN:
                clauses.append(f"{_IF_COLUMN[side]} = ?")
                params.append(iface)
            else:
                clauses.append("(in_if = ? OR out_if = ?)")
                params.extend([iface, iface])
        return " AND ".join(clauses), params

    def _rollup_plan(self, t0: float, t1: float, dimension: str | None,
                     filters: dict, bucket_s: float | None):
        """Which rollup tier and scopes can answer this window, or None for
        raw.

        Returns (tier, dim, seal_ts, scopes): buckets in [t0, seal_ts) come
        from the rollup and flows from seal_ts to t1 from the raw table.
        seal_ts is a multiple of the tier, so the two ranges are exactly
        complementary — nothing is counted twice and nothing falls between
        them. `dim` is None when only the spans are wanted; `scopes` are
        the (exporter, iface, dir) summaries to read, two for an interface
        in both directions.

        An address, port or protocol filter is never rollup-served: no scope
        holds those columns. An interface filter reads the hourly tier only.
        """
        kind, scopes = _scopes(filters)
        if kind is None:
            return None
        if dimension is not None and dimension not in DIMENSION_IDS:
            return None
        tiers = (tuple(SCOPED_KEYS["interface"]) if kind == "interface"
                 else sorted(ROLLUP_TIERS, reverse=True))
        for tier in tiers:
            if bucket_s is None:
                # One slot, so the coarsest tier that reaches t0 is the
                # cheapest answer, not the finest — the loop is already in
                # that order. It has to start on t0 as well: the rollup arm
                # reads whole buckets from t0 up and the raw arm starts at
                # the seal, so a bucket straddling the start of the window
                # would fall between them and be counted by neither.
                if t0 != _align_down(t0, tier):
                    continue
            elif tier > bucket_s or bucket_s % tier:
                # A bucket lands wholly inside one slot only when every slot
                # boundary is a multiple of the tier.
                continue
            floor = self._scope_floor(tier, kind)
            _floor, watermark = self.rollup_bounds(tier)
            if floor is None or watermark is None or t0 < floor:
                continue
            # Never past t1: a bucket straddling the end of the window holds
            # flows the raw path would not have counted.
            seal = min(watermark, _align_down(t1, tier))
            if seal <= t0:
                continue
            dim = None if dimension is None else DIMENSION_IDS[dimension]
            return tier, dim, seal, scopes
        return None

    def _widens(self, t0: float, kind: str) -> bool:
        """A4: whether a sub-hour bucket should widen to the hourly tier,
        because only it reaches t0 for this scope. An interface filter has
        no minute tier, so what it is weighed against is the raw rows."""
        hourly_floor = self._scope_floor(3600, kind)
        _floor, hourly_watermark = self.rollup_bounds(3600)
        if (hourly_floor is None or hourly_watermark is None
                or _align_down(t0, 3600) < hourly_floor
                or hourly_watermark <= t0):
            return False
        if kind == "interface":
            oldest = self._oldest_raw()
            return oldest is None or oldest > t0
        minute_floor = self._scope_floor(60, kind)
        return minute_floor is not None and t0 < minute_floor

    def _repair_ranges(self, tier: int, scope, dim: int, t0: float,
                       seal: float, max_buckets: int = _REPAIR_MAX_BUCKETS,
                       max_flows: int = _REPAIR_MAX_FLOWS) -> list[list[int]]:
        """Which buckets of [t0, seal) the raw rows answer for instead of
        the rollup: the ones _compact_bucket flagged as cut short by the
        cap in this scope, where the raw rows still hold everything the
        bucket was built from.

        Returned as [low, upper) runs rather than buckets, adjacent flags
        merged: in the common case — an exporter over the cap in every
        minute — that is one run, and so one extra arm in the query. An
        empty list means "serve the rollup as stored", which is also the
        answer past either bound.

        "Still hold everything" is checked, not assumed: a run is repaired
        only if the raw rows in it that belong to the scope number at least
        what its span rows counted when the buckets were built. Retention
        ages the raw rows out oldest first, but the row cap deletes by id —
        arrival order, which an exporter with a skewed clock does not keep —
        and a rule read off MIN(ts_end) mistook the first bucket of a
        store's history for a pruned one. Late flows only ever push the raw
        count above the span's, and a raw answer that is fresher than the
        rollup is the better one. The work bound is the global span's count:
        a scoped arm still walks every raw row in its range.
        """
        scope_where, scope_params = _scope_where(scope)
        with self._lock:
            rows = self._conn.execute(
                "SELECT bucket FROM flow_rollup_trunc WHERE tier = ?"
                " AND exporter = ? AND iface = ? AND dir = ? AND dim = ?"
                " AND bucket >= ? AND bucket < ? ORDER BY bucket LIMIT ?",
                (tier, *scope, dim, t0, seal, max_buckets + 1)).fetchall()
            if not rows or len(rows) > max_buckets:
                return []
            runs: list[list[int]] = []
            for row in rows:
                bucket = int(row["bucket"])
                if runs and runs[-1][1] == bucket:
                    runs[-1][1] = bucket + tier
                else:
                    runs.append([bucket, bucket + tier])

            def span_flows(low: int, upper: int, span_scope) -> int:
                return self._conn.execute(
                    "SELECT COALESCE(SUM(flows), 0) AS n FROM flow_rollup_span"
                    " WHERE tier = ? AND exporter = ? AND iface = ? AND dir = ?"
                    " AND bucket >= ? AND bucket < ?",
                    (tier, *span_scope, low, upper)).fetchone()["n"]

            work = [span_flows(low, upper, GLOBAL_SCOPE) for low, upper in runs]
            if sum(work) > max_flows:
                return []
            kept = []
            for (low, upper), total in zip(runs, work):
                wanted = (total if tuple(scope) == GLOBAL_SCOPE
                          else span_flows(low, upper, scope))
                held = self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM flows WHERE ts_end >= ?"
                    f" AND ts_end < ?{scope_where}",
                    (low, upper, *scope_params)).fetchone()["n"]
                if held >= wanted:
                    kept.append([low, upper])
        return kept

    def _agg_rows(self, t0: float, t1: float, dimension: str | None,
                  filters: dict, bucket_s: float | None, info: dict | None = None):
        """One window's aggregate: (t0, bucket_s, n_buckets, rows, spans).

        `rows` are (key, slot, bytes, packets, flows) per grouping key;
        `spans` maps a slot to that slot's grand [bytes, packets, flows],
        which the rows do not add up to on their own — a rollup keeps only
        the heaviest keys of each bucket, and the span is what the residual
        is measured against. `dimension` of None asks for the spans alone,
        `bucket_s` of None puts the whole window in one slot. `info`, when
        given, is filled with how the window was answered (see overview).

        The returned `t0` is the aligned one, on the raw path as much as the
        rollup one: a bucket lands wholly inside one slot only when the
        slots start on a bucket boundary, and aligning only where a rollup
        happened to be used would shift the window under the operator every
        time a filter was toggled.
        """
        kind, _scope_list = _scopes(filters)
        widened = False
        if bucket_s is None:
            align, n_buckets = float(min(ROLLUP_TIERS)), 1
        else:
            bucket_s = max(float(bucket_s), 1.0)
            # A4: widen to the hourly tier rather than falling back to raw when only it reaches t0 (see A4 in CHANGELOG).
            if (bucket_s % 60 == 0 and bucket_s < 3600 and kind is not None
                    and self._widens(t0, kind)):
                bucket_s = 3600.0
                widened = True
            # Under a minute nothing is rollup-served anyway.
            align = bucket_s if bucket_s % 60 == 0 else 0.0
        if align:
            t0 = float(_align_down(t0, align))
        if bucket_s is not None:
            n_buckets = max(1, int((t1 - t0) / bucket_s) + 1)
        plan = self._rollup_plan(t0, t1, dimension, filters, bucket_s)
        if info is not None:
            info.update(records_only=plan is None,
                        tier=None if plan is None else plan[0],
                        summaries_from=(None if plan is None
                                        else self._scope_floor(plan[0], kind)),
                        widened=widened)

        def slot(column: str) -> tuple[str, list]:
            if bucket_s is None:
                return "0", []
            return f"CAST(({column} - ?) / ? AS INTEGER)", [t0, bucket_s]

        key_sql: list[str] = []
        key_params: list = []
        span_sql: list[str] = []
        span_params: list = []
        raw_from = t0
        repairs: list = []
        if plan is not None:
            tier, dim, raw_from, scopes = plan
            expr, expr_params = slot("bucket")
            max_buckets, max_flows = _repair_budget(scopes)
            scope_sql = "tier = ? AND exporter = ? AND iface = ? AND dir = ?"
            for scope in scopes:
                if dim == DIMENSION_IDS["Exporter"] and tuple(scope) != GLOBAL_SCOPE:
                    # A scope holds one exporter, so its span is the only key.
                    key_sql.append(
                        f"SELECT ? AS key, {expr} AS slot, bytes, packets,"
                        f" flows FROM flow_rollup_span WHERE {scope_sql}"
                        f" AND bucket >= ? AND bucket < ?")
                    key_params.extend([scope[0], *expr_params, tier, *scope,
                                       t0, raw_from])
                elif dim is not None:
                    # The buckets the cap cut short leave the rollup arm here
                    # and join the raw arms below, so each is counted by
                    # exactly one of them. The spans are untouched either
                    # way: they were never capped, and the residual is
                    # measured against them.
                    repair = self._repair_ranges(tier, scope, dim, t0, raw_from,
                                                 max_buckets, max_flows)
                    repairs.append((scope, repair))
                    excluded = "".join(" AND NOT (bucket >= ? AND bucket < ?)"
                                       for _ in repair)
                    key_sql.append(
                        f"SELECT key, {expr} AS slot, bytes, packets, flows"
                        f" FROM flow_rollup WHERE {scope_sql} AND dim = ?"
                        f" AND bucket >= ? AND bucket < ?{excluded}")
                    key_params.extend([*expr_params, tier, *scope, dim, t0,
                                       raw_from,
                                       *(edge for run in repair for edge in run)])
                span_sql.append(
                    f"SELECT {expr} AS slot, bytes, packets, flows"
                    f" FROM flow_rollup_span WHERE {scope_sql}"
                    f" AND bucket >= ? AND bucket < ?")
                span_params.extend([*expr_params, tier, *scope, t0, raw_from])

        expr, expr_params = slot("ts_end")
        wheres = [self._where(raw_from, t1, filters, side)
                  for side in _sides(filters)]
        if dimension is not None:
            key = DIMENSIONS.get(dimension, DIMENSIONS["Application"])
            # Where a rollup covers part of the window the raw tail drops its
            # NULL keys too, so traffic a rollup cannot store does not appear
            # as its own series for three minutes of an hour-wide chart.
            unstorable = f" AND ({key}) IS NOT NULL" if plan is not None else ""
            for where, where_params in wheres:
                key_sql.append(
                    f"SELECT {key} AS key, {expr} AS slot,"
                    f" bytes * sampling AS bytes, packets * sampling AS packets,"
                    f" 1 AS flows FROM flows WHERE {where}{unstorable}")
                key_params.extend([*expr_params, *where_params])
            # One arm per run of repaired buckets, each an ix_flows_ts range
            # like the tail above — half-open, the way the rollup bucket it
            # stands in for is — narrowed to the scope it repairs. Other
            # filters are never in play: they have no plan to repair.
            for scope, repair in repairs:
                scope_where, scope_params = _scope_where(scope)
                for low, upper in repair:
                    key_sql.append(
                        f"SELECT {key} AS key, {expr} AS slot,"
                        f" bytes * sampling AS bytes, packets * sampling AS packets,"
                        f" 1 AS flows FROM flows WHERE ts_end >= ? AND ts_end < ?"
                        f"{scope_where}{unstorable}")
                    key_params.extend([*expr_params, low, upper, *scope_params])
        if plan is not None or dimension is None:
            for where, where_params in wheres:
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

    def _span_plan(self, t0: float, t1: float, kind: str):
        """(tier, start, seal) for a totals read: the finest tier whose
        scoped spans reach t0 serves [start, seal), whole buckets inside the
        window, and raw the edges; tier None means raw throughout."""
        for tier in sorted(ROLLUP_TIERS):
            start = _align_up(t0, tier)
            floor = self._scope_floor(tier, kind)
            _floor, watermark = self.rollup_bounds(tier)
            if floor is None or watermark is None or start < floor:
                continue
            seal = min(watermark, _align_down(t1, tier))
            if seal > start:
                return tier, start, seal
        return None, t1, t1

    def interface_totals(self, t0: float, t1: float,
                         exporter: str | None = None) -> list[dict]:
        """Traffic per (exporter, interface, direction) over the window:
        'in' is flows with in_if = iface, 'out' those with out_if = iface.
        `exporter` of None means every exporter."""
        tier, start, seal = self._span_plan(t0, t1, "interface")
        where = " AND exporter = ?" if exporter else ""
        extra = [exporter] if exporter else []
        sql = []
        params: list = []
        if tier is not None:
            sql.append(f"SELECT exporter, iface, dir, bytes, packets, flows"
                       f" FROM flow_rollup_span WHERE tier = ? AND bucket >= ?"
                       f" AND bucket < ? AND iface >= 0{where}")
            params.extend([tier, start, seal, *extra])
        for low, upper, closed in ((t0, start, False), (seal, t1, True)):
            if upper < low or (upper == low and not closed):
                continue
            for side, column in _IF_COLUMN.items():
                sql.append(
                    f"SELECT exporter, {column} AS iface, '{side}' AS dir,"
                    f" {_RAW_SUMS} FROM flows WHERE ts_end >= ?"
                    f" AND ts_end {'<=' if closed else '<'} ? AND {column} >= 0"
                    f"{where} GROUP BY exporter, {column}")
                params.extend([low, upper, *extra])
        with self._lock:
            rows = self._conn.execute(
                "SELECT exporter, iface, dir, SUM(bytes) AS bytes,"
                " SUM(packets) AS packets, SUM(flows) AS flows FROM ("
                + " UNION ALL ".join(sql) + ") GROUP BY exporter, iface, dir"
                " ORDER BY exporter, iface, dir", params).fetchall()
        return [{"exporter": row["exporter"], "iface": row["iface"],
                 "dir": row["dir"], "bytes": row["bytes"] or 0,
                 "packets": row["packets"] or 0, "flows": row["flows"] or 0}
                for row in rows]

    def exporter_totals(self, t0: float, t1: float) -> dict:
        """{exporter: {"bytes", "packets", "flows"}} over the window."""
        tier, start, seal = self._span_plan(t0, t1, "exporter")
        sql = []
        params: list = []
        if tier is not None:
            sql.append("SELECT exporter, bytes, packets, flows"
                       " FROM flow_rollup_span WHERE tier = ? AND bucket >= ?"
                       " AND bucket < ? AND exporter != '' AND iface = -1")
            params.extend([tier, start, seal])
        for low, upper, closed in ((t0, start, False), (seal, t1, True)):
            if upper < low or (upper == low and not closed):
                continue
            sql.append(f"SELECT exporter, {_RAW_SUMS} FROM flows"
                       f" WHERE ts_end >= ? AND ts_end {'<=' if closed else '<'} ?"
                       f" GROUP BY exporter")
            params.extend([low, upper])
        with self._lock:
            rows = self._conn.execute(
                "SELECT exporter, SUM(bytes) AS bytes, SUM(packets) AS packets,"
                " SUM(flows) AS flows FROM (" + " UNION ALL ".join(sql)
                + ") GROUP BY exporter", params).fetchall()
        return {row["exporter"]: {"bytes": row["bytes"] or 0,
                                  "packets": row["packets"] or 0,
                                  "flows": row["flows"] or 0} for row in rows}

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
                 bucket_s: float, series_limit: int = 8, top_limit: int = 10,
                 info: dict | None = None):
        """Everything the NetFlow overview needs, from one pass over the window.

        The `GROUP BY key, slot` scan holds two of the three answers: per key
        it is top(), by slot it is the series. The totals come from the
        per-slot grand totals instead, so they stay exact over a rollup that
        stored only the heaviest keys of each bucket.
        Returns (times, series, bucket_s, top_rows, totals). `info`, when a
        dict, gets records_only (no summary answered), tier, summaries_from
        (the floor of the scope that did) and widened (bucket_s raised to
        the hourly tier).
        """
        t0, bucket_s, n_buckets, rows, spans = self._agg_rows(
            t0, t1, dimension, filters, bucket_s, info)

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
        # Clamped, because the two halves of a bucket are written in
        # separate transactions: a dimension rebuilt after late flows
        # arrived can be read against a span row built before them, and the
        # keys then briefly outweigh the total they are measured against.
        # A bucket or two behind is what that is; a series stacking
        # downwards is not something traffic does.
        other = [max(0.0, value) for value in other]
        if any(other):
            series["\u2014 other \u2014"] = other

        times = [t0 + i * bucket_s for i in range(n_buckets)]
        return times, series, bucket_s, top_rows, totals

    def flows(self, t0: float, t1: float, filters: dict, limit: int = 200,
              order: str = "bytes") -> tuple[list[sqlite3.Row], bool]:
        """The window's heaviest — or most recent — individual records.

        Returns (rows, whether the FLOW_SCAN_CAP bound cut the window short),
        so the page can say the ordering is over the most recent flows rather
        than imply it searched every one of them.

        The bound is for the two volume orderings alone: they sort on a
        product no index can serve, while `order == "time"` is ix_flows_ts
        end to end and has nothing to bound. And a window lying wholly below
        the bound is answered unbounded rather than empty — there is no
        ordering left to cut short there, and an empty list is not what "the
        heaviest of the most recent" means.
        """
        where, params = self._where(t0, t1, filters)
        column = {"bytes": "bytes * sampling", "packets": "packets * sampling",
                  "time": "ts_end"}.get(order, "bytes * sampling")
        with self._lock:
            if order in ("bytes", "packets"):
                highest = self._conn.execute(
                    "SELECT MAX(id) AS hi FROM flows").fetchone()["hi"] or 0
                floor_id = highest - FLOW_SCAN_CAP
                if floor_id > 0:
                    rows = self._conn.execute(
                        f"SELECT * FROM flows WHERE id > ? AND {where}"
                        f" ORDER BY {column} DESC LIMIT ?",
                        (floor_id, *params, limit)).fetchall()
                    # One primary-key probe rather than a count of what was
                    # left out: ids are handed out in arrival order, so
                    # whether the row at the bound is still inside the window
                    # is the same question.
                    edge = self._conn.execute(
                        "SELECT ts_end FROM flows WHERE id <= ? ORDER BY id"
                        " DESC LIMIT 1", (floor_id,)).fetchone()
                    bounded = bool(edge is not None and edge["ts_end"] >= t0)
                    if rows or not bounded:
                        return rows, bounded
            rows = self._conn.execute(
                f"SELECT * FROM flows WHERE {where}"
                f" ORDER BY {column} DESC LIMIT ?",
                (*params, limit)).fetchall()
        return rows, False

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
