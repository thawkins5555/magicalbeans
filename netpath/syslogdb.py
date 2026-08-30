"""Storage for collected syslog.

Two decisions here are about staying quick under volume.

The hourly counts the timeline draws are kept in a rollup table updated as
messages land, so the last 24 hours costs 24 rows to read rather than a scan of
however many million messages arrived. Without it the timeline would get slower
every day the collector runs.

Message search uses FTS5 with the trigram tokenizer where SQLite has it, which
almost every build does. Trigram indexes three-character runs rather than
words, so a search for part of a word finds it: `face` matches `interface`. A
`LIKE '%needle%'` does the same thing but cannot use an index and reads every
row in the window; on a day of logs from a chatty firewall that is seconds per
keystroke. The scan is kept as the fallback for builds without FTS5 or with an
SQLite too old for trigram, and for queries under three characters, which
trigram cannot index. The app says which one is in use.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id       INTEGER PRIMARY KEY,
    ts       REAL    NOT NULL,
    source   TEXT    NOT NULL,
    host     TEXT,
    facility INTEGER,
    severity INTEGER,
    app      TEXT,
    procid   TEXT,
    msgid    TEXT,
    message  TEXT    NOT NULL,
    raw      TEXT
);
CREATE INDEX IF NOT EXISTS ix_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS ix_logs_sev_ts ON logs(severity, ts);
CREATE INDEX IF NOT EXISTS ix_logs_source_ts ON logs(source, ts);

-- One row per hour per severity, so the timeline never scans the message table.
CREATE TABLE IF NOT EXISTS log_counts (
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
    "port": 514,                  # UDP
    "tcp_port": 0,                # 0 = the same port as UDP
    "accept_udp": True,
    "accept_tcp": False,
    "socket_buffer_kb": 4096,
    "auto_accept_sources": True,
    "allowed_sources": "",
    # Volume control at the door, so noise never reaches the database.
    "min_severity": 7,            # keep this severity and anything worse
    "max_message_chars": 2048,
    "retention_days": 30,
    "max_rows": 20_000_000,
    "resolve_sources": False,
    # Syslog timestamps come from the sending device. One with a wrong clock
    # files its messages at the wrong time, which is worse than useless when
    # correlating an incident, so arrival time can be used instead.
    "use_receive_time": False,
}


class SyslogDatabase:
    BACKFILL_CHUNK = 20_000

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.fts = False
        # Set when an index from an older build had to be dropped; the refill
        # runs on a thread so opening the database stays instant.
        self._backfill_wanted = False
        self.index_ready = True
        self.index_progress = (0, 0)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._enable_fts()
            self._conn.commit()

    def _enable_fts(self) -> None:
        """Create the search index, rebuilding it if its shape has changed.

        `trigram` indexes every three-character run rather than whole words,
        which is what makes `face` find `interface`. `unicode61`, which this
        used before, can only match a token from its start, so a substring in
        the middle of a word was unfindable however it was quoted.

        The cost is a larger index — roughly three entries per character rather
        than one per word — and a floor of three characters on a query. Both are
        worth it: the alternative is a LIKE scan of the whole window, which is
        seconds per keystroke on a busy day.

        `source` is indexed alongside the message so that typing a sending
        address into the search box finds it, which is what people try first.
        """
        try:
            existing = self._conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table'"
                " AND name='logs_fts'").fetchone()
            if existing and not self._index_is_current(existing["sql"]):
                # An index built by an older version. Drop it and refill in the
                # background: searching falls back to LIKE until that finishes,
                # which is slower but returns the same rows.
                self._conn.execute("DROP TABLE logs_fts")
                existing = None
                self._backfill_wanted = True
            self._conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5("
                " message, app, host, source, content='logs',"
                " content_rowid='id', tokenize='trigram')")
            self.fts = True
        except sqlite3.OperationalError:
            # No FTS5, or an SQLite too old for the trigram tokenizer
            # (3.34, December 2020). Search still works, by scanning.
            self.fts = False

    @staticmethod
    def _index_is_current(sql: str) -> bool:
        text = (sql or "").lower()
        return "trigram" in text and "source" in text

    def start_index_backfill(self) -> None:
        """Refill a dropped index without holding the write lock.

        Done in chunks on a background thread rather than with FTS5's own
        `rebuild`, which is a single statement: on a database with millions of
        messages that would block the collector for as long as it ran, and
        block startup if it ran here.
        """
        if not self.fts or not self._backfill_wanted:
            return
        self._backfill_wanted = False
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS hi, COUNT(*) AS n FROM logs").fetchone()
        watermark, total = row["hi"] or 0, row["n"] or 0
        if not total:
            self.index_ready = True
            return
        self.index_ready = False
        self.index_progress = (0, total)
        thread = threading.Thread(target=self._backfill, args=(watermark, total),
                                  name="syslog-index", daemon=True)
        thread.start()

    def _backfill(self, watermark: int, total: int) -> None:
        """Messages newer than the watermark are indexed as they arrive, so
        only what was already stored has to be walked."""
        cursor, done = 0, 0
        try:
            while cursor < watermark:
                with self._lock:
                    self._conn.execute(
                        "INSERT INTO logs_fts(rowid, message, app, host, source)"
                        " SELECT id, message, app, host, source FROM logs"
                        " WHERE id > ? AND id <= ? ORDER BY id LIMIT ?",
                        (cursor, watermark, self.BACKFILL_CHUNK))
                    row = self._conn.execute(
                        "SELECT MAX(id) AS hi FROM (SELECT id FROM logs"
                        " WHERE id > ? AND id <= ? ORDER BY id LIMIT ?)",
                        (cursor, watermark, self.BACKFILL_CHUNK)).fetchone()
                    self._conn.commit()
                if not row or row["hi"] is None:
                    break
                done += self.BACKFILL_CHUNK
                cursor = row["hi"]
                self.index_progress = (min(done, total), total)
                # Let the collector and any reader in between chunks.
                time.sleep(0.02)
        except sqlite3.Error:
            self.fts = False        # fall back to scanning rather than lie
        finally:
            self.index_ready = True
            self.index_progress = (total, total)

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

    def insert(self, entries) -> int:
        rows = [(e.ts, e.source, e.host, e.facility, e.severity, e.app,
                 e.procid, e.msgid, e.message, e.raw) for e in entries]
        if not rows:
            return 0
        counts: dict[tuple[int, int], int] = {}
        for entry in entries:
            key = (int(entry.ts // 3600) * 3600, int(entry.severity))
            counts[key] = counts.get(key, 0) + 1

        with self._lock:
            self._conn.executemany(
                "INSERT INTO logs(ts, source, host, facility, severity, app,"
                " procid, msgid, message, raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows)
            if self.fts:
                # executemany leaves cursor.lastrowid unset, so ask SQLite
                # directly; ids are contiguous because one thread writes.
                last_id = self._conn.execute(
                    "SELECT last_insert_rowid()").fetchone()[0]
                first_id = last_id - len(rows) + 1
                self._conn.executemany(
                    "INSERT INTO logs_fts(rowid, message, app, host, source)"
                    " VALUES (?,?,?,?,?)",
                    [(first_id + index, entry.message, entry.app, entry.host,
                      entry.source)
                     for index, entry in enumerate(entries)])
            self._conn.executemany(
                "INSERT INTO log_counts(hour, severity, n) VALUES (?,?,?)"
                " ON CONFLICT(hour, severity) DO UPDATE SET n = n + excluded.n",
                [(hour, severity, n) for (hour, severity), n in counts.items()])
            self._conn.commit()
        return len(rows)

    # ------------------------------------------------------------------ query

    def _where(self, t0: float, t1: float, filters: dict) -> tuple[str, list]:
        clauses = ["l.ts >= ?", "l.ts <= ?"]
        params: list = [t0, t1]
        if filters.get("severity") not in (None, ""):
            clauses.append("l.severity <= ?")          # at least this serious
            params.append(int(filters["severity"]))
        if filters.get("facility") not in (None, ""):
            clauses.append("l.facility = ?")
            params.append(int(filters["facility"]))
        if filters.get("source"):
            # Matched against the resolved name as well, so the box accepts
            # either `10.20.3.4` or `core-sw-01` without the user having to
            # know which one this device reports.
            clauses.append("l.source LIKE ?")
            params.append(f"%{filters['source']}%")
        if filters.get("host"):
            clauses.append("l.host LIKE ?")
            params.append(f"%{filters['host']}%")
        if filters.get("app"):
            clauses.append("l.app LIKE ?")
            params.append(f"%{filters['app']}%")
        return " AND ".join(clauses), params

    # Trigram indexes runs of three characters, so it has nothing to match on
    # for a shorter term.
    MIN_INDEXED_TERM = 3

    def _can_index(self, text: str) -> bool:
        """Whether the index can answer this, or it has to be scanned for."""
        if not self.fts or not self.index_ready:
            return False
        terms = str(text).split()
        return bool(terms) and all(len(term) >= self.MIN_INDEXED_TERM
                                   for term in terms)

    @staticmethod
    def _fts_query(text: str) -> str:
        """Turn a plain phrase into an FTS expression, quoting each term.

        Users type `error 10.1.2.3`, not FTS syntax; quoting keeps punctuation
        in addresses from being read as operators. Each term is a substring to
        be found anywhere, and several terms must all appear, in any order and
        any field.
        """
        terms = [term for term in str(text).split() if term]
        return " AND ".join(f'"{term.replace(chr(34), "")}"' for term in terms)

    # The columns a free-text search looks in when it has to scan. `source` is
    # here so that typing a sending address into the search box finds it.
    SCAN_COLUMNS = ("l.message", "l.app", "l.host", "l.source")

    def _scan_clause(self, text: str) -> tuple[str, list]:
        """A LIKE across every searchable column, one term at a time.

        Every term must appear somewhere, matching what the index does, so the
        two paths return the same rows and only differ in how long they take.
        """
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
            if text and self._can_index(text):
                return self._conn.execute(
                    f"SELECT l.* FROM logs_fts f JOIN logs l ON l.id = f.rowid"
                    f" WHERE logs_fts MATCH ? AND {where}"
                    f" ORDER BY l.ts {order} LIMIT ?",
                    (self._fts_query(text), *params, limit)).fetchall()
            if text:
                scan, scan_params = self._scan_clause(text)
                return self._conn.execute(
                    f"SELECT l.* FROM logs l WHERE {where} AND {scan}"
                    f" ORDER BY l.ts {order} LIMIT ?",
                    (*params, *scan_params, limit)).fetchall()
            return self._conn.execute(
                f"SELECT l.* FROM logs l WHERE {where}"
                f" ORDER BY l.ts {order} LIMIT ?", (*params, limit)).fetchall()

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
                        ("text", "facility", "source", "host", "app"))
        with self._lock:
            if plain and bucket_s >= 3600 and bucket_s % 3600 == 0:
                rows = self._conn.execute(
                    "SELECT hour, severity, n FROM log_counts"
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
            if text and self._can_index(text):
                sql = (f"SELECT CAST((l.ts - ?) / ? AS INTEGER) AS slot,"
                       f" l.severity AS severity, COUNT(*) AS n"
                       f" FROM logs_fts f JOIN logs l ON l.id = f.rowid"
                       f" WHERE logs_fts MATCH ? AND {where}"
                       f" GROUP BY slot, severity")
                args = (start, bucket_s, self._fts_query(text), *params)
            elif text:
                scan, scan_params = self._scan_clause(text)
                sql = (f"SELECT CAST((l.ts - ?) / ? AS INTEGER) AS slot,"
                       f" l.severity AS severity, COUNT(*) AS n FROM logs l"
                       f" WHERE {where} AND {scan} GROUP BY slot, severity")
                args = (start, bucket_s, *params, *scan_params)
            else:
                sql = (f"SELECT CAST((l.ts - ?) / ? AS INTEGER) AS slot,"
                       f" l.severity AS severity, COUNT(*) AS n FROM logs l"
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

    def rows_since(self, last_id: int, limit: int = 500) -> list[sqlite3.Row]:
        """Rows newer than last_id, oldest first — same cursor-read contract
        as SnmpTrapDatabase.traps_since, used by the alert engine."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM logs WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(last_id), int(limit))).fetchall()

    def max_id(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT MAX(id) AS m FROM logs").fetchone()
        return int(row["m"] or 0)

    def sources(self, since_s: float = 86400, limit: int = 50) -> list[sqlite3.Row]:
        cutoff = time.time() - since_s
        with self._lock:
            return self._conn.execute(
                "SELECT source, COUNT(*) AS n, MAX(ts) AS last_seen FROM logs"
                " WHERE ts >= ? GROUP BY source ORDER BY n DESC LIMIT ?",
                (cutoff, limit)).fetchall()

    def stats(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS rows, MIN(ts) AS lo, MAX(ts) AS hi"
                " FROM logs").fetchone()
            last_hour = self._conn.execute(
                "SELECT SUM(n) AS n FROM log_counts WHERE hour >= ?",
                (int((time.time() - 3600) // 3600) * 3600,)).fetchone()
        done, total = self.index_progress
        return {"rows": row["rows"] or 0, "lo": row["lo"], "hi": row["hi"],
                "last_hour": last_hour["n"] or 0, "fts": self.fts,
                "index_ready": self.index_ready,
                "index_done": done, "index_total": total,
                "bytes": self.size_bytes()}

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
            cursor = self._conn.execute("DELETE FROM logs WHERE ts < ?", (cutoff,))
            removed += cursor.rowcount or 0
            self._conn.execute("DELETE FROM log_counts WHERE hour < ?", (cutoff,))
            total = self._conn.execute(
                "SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
            if max_rows and total > max_rows:
                cursor = self._conn.execute(
                    "DELETE FROM logs WHERE id IN (SELECT id FROM logs"
                    " ORDER BY ts ASC LIMIT ?)", (total - max_rows,))
                removed += cursor.rowcount or 0
            if removed and self.fts:
                self._conn.execute("INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")
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
                    "SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
                if total <= 5000:
                    break
                chunk = max(int(total * 0.15), 5000)
                cursor = self._conn.execute(
                    "DELETE FROM logs WHERE id IN (SELECT id FROM logs"
                    " ORDER BY ts ASC LIMIT ?)", (chunk,))
                removed += cursor.rowcount or 0
                if self.fts:
                    self._conn.execute(
                        "INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")
                self._conn.commit()
                self._conn.execute("VACUUM")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed
