"""Storage for received SNMP traps.

No FTS5, unlike syslog. Syslog needs a trigram index because a busy firewall
produces millions of rows a day. Traps are two to four orders of magnitude
rarer, and the useful queries are on indexed columns (`ts`, `severity`,
`source`, `trap_oid`) — a `LIKE` over `varbind_text`, already narrowed by the
time window, reads a handful of rows.

Varbinds are stored as one JSON column, not a child table. A varbind list is
read exactly once, whole, by the detail panel of a selected row; it is never
joined, grouped or aggregated. A child table would add write amplification of
five to twenty times on the hot insert path, a second index, and a second
query on every detail click, to buy an ability nothing asks for. Free-text
search over the varbinds is already served by the denormalized
`varbind_text` column.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS traps (
    id           INTEGER PRIMARY KEY,
    ts           REAL    NOT NULL,
    source       TEXT    NOT NULL,   -- sending IP
    version      INTEGER NOT NULL,   -- 0 = v1, 1 = v2c, 3 = v3
    community    TEXT,               -- v1/v2c community, or the v3 user name
    engine_id    TEXT,               -- v3 authoritative engine id, hex
    security     TEXT,               -- '' | noAuthNoPriv | authNoPriv | authPriv
    auth_state   TEXT,               -- '' | ok | failed | unverified | encrypted
    trap_oid     TEXT,               -- the trap identity, one axis for v1 and v2
    trap_name    TEXT,               -- resolved, for display and searching
    trap_kind    TEXT,               -- coldStart | linkDown | ... | enterpriseSpecific
    severity     INTEGER NOT NULL,   -- 0..7, the same scale syslog uses
    generic      INTEGER,            -- v1 only
    specific     INTEGER,            -- v1 only
    enterprise   TEXT,               -- v1 only
    agent_addr   TEXT,               -- v1 only, the agent's own idea of its address
    uptime       INTEGER,            -- TimeTicks since the agent booted
    is_inform    INTEGER NOT NULL DEFAULT 0,
    varbind_n    INTEGER NOT NULL DEFAULT 0,
    varbinds     TEXT    NOT NULL DEFAULT '[]',  -- JSON [{oid,name,type,value,text}]
    varbind_text TEXT,                           -- flattened, for LIKE search
    raw_len      INTEGER,
    raw          BLOB                            -- only when store_raw is on
);
CREATE INDEX IF NOT EXISTS ix_traps_ts        ON traps(ts);
CREATE INDEX IF NOT EXISTS ix_traps_sev_ts    ON traps(severity, ts);
CREATE INDEX IF NOT EXISTS ix_traps_source_ts ON traps(source, ts);
CREATE INDEX IF NOT EXISTS ix_traps_oid_ts    ON traps(trap_oid, ts);
CREATE INDEX IF NOT EXISTS ix_traps_kind_ts   ON traps(trap_kind, ts);

-- One row per hour per severity, so the timeline never scans the trap table.
CREATE TABLE IF NOT EXISTS trap_counts (
    hour     INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    n        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, severity)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

DEFAULTS = {
    "enabled": True,
    "bind_address": "0.0.0.0",
    "port": 162,
    "socket_buffer_kb": 2048,
    # Which versions to decode at all. Turning one off makes its packets a
    # counted rejection rather than a stored row.
    "accept_v1": True,
    "accept_v2c": True,
    "accept_v3": True,
    # An InformRequest is a trap that wants an acknowledgement. Without one
    # the sender retransmits until it gives up, so this is on by default.
    "acknowledge_informs": True,
    # Source access control, exactly as syslog does it: an empty allow list
    # plus auto-accept means "from anywhere"; a non-empty list means only those.
    "auto_accept_sources": True,
    "allowed_sources": "",
    # Community access control. The same shape, but keyed on a string that
    # arrives inside the packet rather than on the sending address.
    "auto_accept_communities": True,
    "accepted_communities": "",
    # SNMPv3 users, one per line: "name / SHA / password".
    # Used only to verify the authentication digest on authNoPriv and authPriv
    # messages; privacy (decryption) is not implemented.
    "v3_users": "",
    # Volume control at the door, before anything is written.
    "min_severity": 7,          # keep this severity and anything worse
    "max_varbinds": 64,
    "max_value_chars": 512,
    "store_raw": False,         # keep the original datagram, for debugging
    # Admin-supplied names and severities. One "OID = text" per line.
    "oid_names": "",
    "severity_rules": "",
    "retention_days": 90,
    "max_rows": 5_000_000,
    "resolve_sources": False,
}


class SnmpTrapDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.store_raw = False
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = dict(DEFAULTS)
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        for row in rows:
            if row["key"] in values:
                try:
                    values[row["key"]] = json.loads(row["value"])
                except (ValueError, TypeError):
                    pass
        return values

    def save_settings(self, values: dict) -> None:
        with self._lock:
            for key, value in values.items():
                if key not in DEFAULTS:
                    continue
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)))
            self._conn.commit()

    # ------------------------------------------------------------------ write

    def insert(self, traps) -> int:
        store_raw = self.store_raw
        rows = [(t.ts, t.source, t.version, t.community, t.engine_id, t.security,
                 t.auth_state, t.trap_oid, t.trap_name, t.trap_kind, t.severity,
                 t.generic, t.specific, t.enterprise, t.agent_addr, t.uptime,
                 1 if t.is_inform else 0, len(t.varbinds),
                 json.dumps(t.varbinds, separators=(",", ":")), t.varbind_text,
                 len(t.raw), t.raw if store_raw else None)
                for t in traps]
        if not rows:
            return 0

        counts: dict[tuple[int, int], int] = {}
        for trap in traps:
            key = (int(trap.ts // 3600) * 3600, int(trap.severity))
            counts[key] = counts.get(key, 0) + 1

        with self._lock:
            self._conn.executemany(
                "INSERT INTO traps(ts, source, version, community, engine_id,"
                " security, auth_state, trap_oid, trap_name, trap_kind,"
                " severity, generic, specific, enterprise, agent_addr, uptime,"
                " is_inform, varbind_n, varbinds, varbind_text, raw_len, raw)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows)
            self._conn.executemany(
                "INSERT INTO trap_counts(hour, severity, n) VALUES (?,?,?)"
                " ON CONFLICT(hour, severity) DO UPDATE SET n = n + excluded.n",
                [(hour, severity, n) for (hour, severity), n in counts.items()])
            self._conn.commit()
        return len(rows)

    # ------------------------------------------------------------------ query

    def _where(self, t0: float, t1: float, filters: dict) -> tuple[str, list]:
        clauses = ["ts >= ?", "ts <= ?"]
        params: list = [t0, t1]
        if filters.get("severity") not in (None, ""):
            clauses.append("severity <= ?")             # this level and worse
            params.append(int(filters["severity"]))
        if filters.get("version") not in (None, ""):
            clauses.append("version = ?")
            params.append(int(filters["version"]))
        if filters.get("kind"):
            clauses.append("trap_kind = ?")
            params.append(filters["kind"])
        if filters.get("source"):
            clauses.append("source LIKE ?")
            params.append(f"%{filters['source']}%")
        if filters.get("oid"):
            clauses.append("(trap_oid LIKE ? OR trap_name LIKE ?)")
            params.append(f"%{filters['oid']}%")
            params.append(f"%{filters['oid']}%")
        if filters.get("community"):
            clauses.append("community LIKE ?")
            params.append(f"%{filters['community']}%")
        return " AND ".join(clauses), params

    # The columns a free-text search looks in.
    SCAN_COLUMNS = ("source", "community", "trap_oid", "trap_name",
                    "trap_kind", "varbind_text")

    def _scan_clause(self, text: str) -> tuple[str, list]:
        """A LIKE across every searchable column, one term at a time. Every
        term must appear somewhere, matching what an indexed search would do."""
        terms = [term for term in str(text).split() if term] or [text]
        clauses, params = [], []
        for term in terms:
            clauses.append("(" + " OR ".join(
                f"{column} LIKE ?" for column in self.SCAN_COLUMNS) + ")")
            params.extend([f"%{term}%"] * len(self.SCAN_COLUMNS))
        return " AND ".join(clauses), params

    def search(self, t0: float, t1: float, filters: dict, limit: int = 300,
               newest_first: bool = True) -> list[sqlite3.Row]:
        where, params = self._where(t0, t1, filters)
        order = "DESC" if newest_first else "ASC"
        text = (filters.get("text") or "").strip()

        with self._lock:
            if text:
                scan, scan_params = self._scan_clause(text)
                return self._conn.execute(
                    f"SELECT * FROM traps WHERE {where} AND {scan}"
                    f" ORDER BY ts {order} LIMIT ?",
                    (*params, *scan_params, limit)).fetchall()
            return self._conn.execute(
                f"SELECT * FROM traps WHERE {where}"
                f" ORDER BY ts {order} LIMIT ?", (*params, limit)).fetchall()

    def histogram(self, t0: float, t1: float, bucket_s: float = 3600,
                  filters: dict | None = None) -> list[dict]:
        """Counts per bucket, from the rollup when nothing else is filtered."""
        filters = filters or {}
        bucket_s = max(float(bucket_s), 60.0)
        start = int(t0 // bucket_s) * bucket_s
        slots = max(1, int((t1 - start) / bucket_s) + 1)
        buckets = [{"t0": start + i * bucket_s, "t1": start + (i + 1) * bucket_s,
                    "total": 0, "by_severity": {}} for i in range(slots)]

        plain = not any(filters.get(key) for key in
                        ("text", "version", "kind", "source", "oid", "community"))
        with self._lock:
            if plain and bucket_s >= 3600 and bucket_s % 3600 == 0:
                rows = self._conn.execute(
                    "SELECT hour, severity, n FROM trap_counts"
                    " WHERE hour >= ? AND hour <= ?", (start, t1)).fetchall()
                for row in rows:
                    if (filters.get("severity") not in (None, "")
                            and row["severity"] > int(filters["severity"])):
                        continue
                    index = int((row["hour"] - start) / bucket_s)
                    if 0 <= index < slots:
                        buckets[index]["total"] += row["n"]
                        key = str(row["severity"])
                        by = buckets[index]["by_severity"]
                        by[key] = by.get(key, 0) + row["n"]
                return buckets

            where, params = self._where(t0, t1, filters)
            text = (filters.get("text") or "").strip()
            if text:
                scan, scan_params = self._scan_clause(text)
                sql = (f"SELECT CAST((ts - ?) / ? AS INTEGER) AS slot,"
                       f" severity AS severity, COUNT(*) AS n FROM traps"
                       f" WHERE {where} AND {scan} GROUP BY slot, severity")
                args = (start, bucket_s, *params, *scan_params)
            else:
                sql = (f"SELECT CAST((ts - ?) / ? AS INTEGER) AS slot,"
                       f" severity AS severity, COUNT(*) AS n FROM traps"
                       f" WHERE {where} GROUP BY slot, severity")
                args = (start, bucket_s, *params)

            for row in self._conn.execute(sql, args).fetchall():
                index = row["slot"]
                if index is None or not (0 <= index < slots):
                    continue
                buckets[index]["total"] += row["n"]
                key = str(row["severity"])
                by = buckets[index]["by_severity"]
                by[key] = by.get(key, 0) + row["n"]
        return buckets

    def recent_sources(self, since_s: float = 86400, limit: int = 100) -> list[sqlite3.Row]:
        cutoff = time.time() - since_s
        with self._lock:
            return self._conn.execute(
                "SELECT source, COUNT(*) AS n, MAX(ts) AS last_seen FROM traps"
                " WHERE ts >= ? GROUP BY source ORDER BY n DESC LIMIT ?",
                (cutoff, limit)).fetchall()

    def kinds(self, since_s: float = 86400, limit: int = 30) -> list[sqlite3.Row]:
        cutoff = time.time() - since_s
        with self._lock:
            return self._conn.execute(
                "SELECT trap_kind, COUNT(*) AS n FROM traps"
                " WHERE ts >= ? GROUP BY trap_kind ORDER BY n DESC LIMIT ?",
                (cutoff, limit)).fetchall()

    def stats(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS rows, MIN(ts) AS lo, MAX(ts) AS hi"
                " FROM traps").fetchone()
            last_hour = self._conn.execute(
                "SELECT SUM(n) AS n FROM trap_counts WHERE hour >= ?",
                (int((time.time() - 3600) // 3600) * 3600,)).fetchone()
        return {"rows": row["rows"] or 0, "lo": row["lo"], "hi": row["hi"],
                "last_hour": last_hour["n"] or 0, "bytes": self.size_bytes()}

    # ------------------------------------------------------------ maintenance

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def prune(self, retention_days: float, max_rows: int) -> int:
        removed = 0
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            cursor = self._conn.execute("DELETE FROM traps WHERE ts < ?", (cutoff,))
            removed += cursor.rowcount or 0
            self._conn.execute("DELETE FROM trap_counts WHERE hour < ?", (cutoff,))
            total = self._conn.execute(
                "SELECT COUNT(*) AS n FROM traps").fetchone()["n"]
            if max_rows and total > max_rows:
                cursor = self._conn.execute(
                    "DELETE FROM traps WHERE id IN (SELECT id FROM traps"
                    " ORDER BY ts ASC LIMIT ?)", (total - max_rows,))
                removed += cursor.rowcount or 0
            self._conn.commit()
        return removed

    def trim_to_size(self, max_bytes: int) -> int:
        if max_bytes <= 0:
            return 0
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM traps").fetchone()["n"]
                if total <= 5000:
                    break
                chunk = max(int(total * 0.15), 5000)
                cursor = self._conn.execute(
                    "DELETE FROM traps WHERE id IN (SELECT id FROM traps"
                    " ORDER BY ts ASC LIMIT ?)", (chunk,))
                removed += cursor.rowcount or 0
                self._conn.commit()
                self._conn.execute("VACUUM")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed
