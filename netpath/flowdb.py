"""Storage and aggregation for collected flows.

Flows live in their own SQLite file: a busy exporter writes orders of
magnitude more rows than the path monitor does, and SQLite allows one writer
at a time.
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
    "retention_days": 14,
    "max_flows": 5_000_000,
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
