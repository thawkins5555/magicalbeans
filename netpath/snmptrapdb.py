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
import logging
import os
import sqlite3
import threading
import time

from . import dbmaint, dbopen, settingsutil

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

# This database's SIZE CAP (max_snmp_db_mb, what trim_to_size above is given
# as max_bytes) lives in appdb.py's GLOBAL_DEFAULTS, not here — every
# module's own *_db_mb setting does, one place, so Settings can show them
# side by side. Documented here anyway, since this is the module an operator
# sizing that cap would actually open:
#
#   A 250-device review install logged a 75-second trap burst that wrote
#   98.6 MB — 38% of the 256 MB the cap shipped at — which is roughly
#   1.3 MB/s, ~197 MB of traps per minute sustained. At that rate a REAL
#   storm (a site-wide power event, a flapping upstream link fanning traps
#   out from everything behind it) reaches a 256 MB cap in under four
#   minutes and starts discarding trap HISTORY while the incident that
#   produced it is still active — the exact moment an operator most needs
#   all of it. retention_days (90, above) is meant to be what decides how
#   long trap history lives; a cap this tight let the size limit win that
#   argument silently, deleting rows the day-count setting had not asked to
#   lose yet. max_snmp_db_mb is 1024 in appdb.py now, matching
#   max_syslog_db_mb and max_nodes_db_mb — both of which see comparable or
#   worse burst volume and were never shipped at 256 to begin with.

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
    # Whether a v3 trap whose authentication digest does not verify is
    # discarded. On, because the alternative is what shipped: the digest was
    # computed, the failure was counted, and the trap was stored and alerted
    # on anyway, so anyone with network reach to the trap port could
    # manufacture alerts and page the on-call. Turning it off restores the
    # old behaviour for a site that needs to see what is arriving.
    "reject_failed_auth": True,
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
    # Comma-joined column keys the trap table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns": "",
}


class SnmpTrapDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = dbopen.connect(path)
        self._conn.row_factory = sqlite3.Row
        self.store_raw = False
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            dbmaint.enable_incremental_vacuum(self._conn, "snmptraps.db")
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
        return settingsutil.coerce_settings(DEFAULTS, values, strict=False)

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

    def traps_since(self, last_id: int, limit: int | None = 500) -> list[sqlite3.Row]:
        """Rows newer than last_id, oldest first. The alert engine reads
        forward by id and keeps its own cursor, so it never re-reads a trap
        and never depends on wall-clock ordering — a device with a bad
        clock can file a trap timestamped in the past; its rowid is still
        monotonic.

        `limit` is the caller's per-tick budget; None means "everything newer",
        which only a caller that has already sized the backlog with max_id()
        should ask for. The engine used to take the 500 default once per
        five-second tick, i.e. 100 rows/s against a measured ingest of nearly
        12,000/s, so a busy site fell behind for ever with no way to see it.
        """
        with self._lock:
            if limit is None:
                return self._conn.execute(
                    "SELECT * FROM traps WHERE id > ? ORDER BY id ASC",
                    (int(last_id),)).fetchall()
            return self._conn.execute(
                "SELECT * FROM traps WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(last_id), int(limit))).fetchall()

    def max_id(self) -> int:
        """Highest stored trap id, so a reader can size its own backlog
        (max_id() - cursor) and say how far behind it is."""
        with self._lock:
            row = self._conn.execute("SELECT MAX(id) AS m FROM traps").fetchone()
        return int(row["m"] or 0)

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
        """Delete the oldest traps until the file fits under the cap.

        Batched and reclaimed rather than deleted-and-VACUUMed: insert()
        takes the same lock, so a whole-file rewrite under it blocked the
        receiver's writer thread and filled the queue behind it.
        """
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
                    "SELECT MIN(id) AS lo, MAX(id) AS hi FROM traps").fetchone()
            low, high = bounds["lo"], bounds["hi"]
            # Ids are handed out in arrival order, so the id span is both the
            # right definition of "oldest" — immune to a device with a wrong
            # clock — and a proxy for the row count that costs one index probe
            # rather than the full scan a COUNT(*) would.
            deletable = 0 if low is None else max(0, high - low + 1 - 5000)
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
                        cursor = self._conn.execute(
                            "DELETE FROM traps"
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
                                       budget_s=0.2, label="snmptraps.db"):
                    break
            if not deletable or time.monotonic() >= deadline:
                break
        if self.size_bytes() > max_bytes:
            log.warning("%s: %d bytes after removing %d rows, still above the "
                        "%d byte cap; continuing at the next maintenance pass",
                        "snmptraps.db", self.size_bytes(), removed, max_bytes)
        return removed
