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

import collections
import json
import logging
import os
import sqlite3
import threading
import time

from . import dbmaint, dbopen, settingsutil
from .eventlog import ERROR, NullLog, SYSTEM

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

# RETURNING (SQLite 3.35, March 2021) is what makes a targeted FTS delete
# possible: an external-content FTS5 table cannot work out what a deleted row
# contained, so without the old column values the only way to keep the index
# honest was to rebuild the whole thing.
HAS_RETURNING = sqlite3.sqlite_version_info >= (3, 35)
# How often the pre-3.35 fallback is allowed to rebuild the index.
REBUILD_INTERVAL_S = 3600.0

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
    # Comma-joined column keys the syslog message table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns": "",
    # Volume controls for one noisy source, so a single device in a debug loop
    # cannot evict every other device's messages from the queue.
    "per_source_rate": 200,       # messages a second, 0 disables the limit
    "collapse_repeats_s": 5.0,    # merge identical consecutive lines within
                                  # this many seconds into one row, 0 disables
    "max_tcp_clients": 64,
}


class SyslogDatabase:
    BACKFILL_CHUNK = 20_000
    # How long close() waits for a chunk already in progress to notice the
    # stop event and land before the connection underneath it is closed —
    # generous for one bulk INSERT of at most BACKFILL_CHUNK rows.
    BACKFILL_STOP_TIMEOUT_S = 10.0

    def __init__(self, path: str, log=None):
        self.path = path
        # Optional and defaulted, unlike its siblings in nodesdb.py/
        # ipamdb.py/alertsdb.py, none of which take the application's
        # EventLog at all: a dropped-index rebuild silently downgrading
        # search to scanning for the rest of the process, with nothing
        # anywhere saying so, is exactly the kind of fact an operator needs
        # and the module logger (below) never reaches the UI to tell them.
        self.log = log or NullLog()
        self._lock = threading.RLock()
        self._conn = dbopen.connect(path)
        self._conn.row_factory = sqlite3.Row
        self.fts = False
        self._last_rebuild: float | None = None
        # Last row stored per source, for consecutive-duplicate collapsing.
        # Keyed on a spoofable source address, so bounded and LRU.
        self._last_row: collections.OrderedDict = collections.OrderedDict()
        self.collapse_repeats_s = 0.0
        # Set when an index from an older build had to be dropped, or a
        # previous run's backfill was cut short by shutdown (see
        # _read_backfill_cursor); the refill runs on a thread so opening
        # the database stays instant.
        self._backfill_wanted = False
        # Row id to resume from — 0 for a fresh rebuild, or wherever a
        # prior run's interrupted backfill persisted having reached.
        self._backfill_start_cursor = 0
        self._backfill_stop = threading.Event()
        self._backfill_thread: threading.Thread | None = None
        self.index_ready = True
        self.index_progress = (0, 0)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            dbmaint.enable_incremental_vacuum(self._conn, "syslog.db")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._enable_fts()
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS leaves an existing table alone, so an
        install from before repeat collapsing needs the column added
        explicitly or the next insert fails.
        """
        columns = {row["name"] for row in
                   self._conn.execute("PRAGMA table_info(logs)").fetchall()}
        if "repeat_count" not in columns:
            self._conn.execute("ALTER TABLE logs ADD COLUMN repeat_count"
                               " INTEGER NOT NULL DEFAULT 1")

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
                self._backfill_start_cursor = 0
                # Whatever an earlier, unrelated interruption had persisted
                # (see _read_backfill_cursor) is against a table this drop
                # just erased — stale, and superseded by the fresh rebuild
                # this migration is about to start anyway.
                self._write_backfill_cursor(None)
            self._conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5("
                " message, app, host, source, content='logs',"
                " content_rowid='id', tokenize='trigram')")
            self.fts = True
            if not self._backfill_wanted:
                # Not a schema migration, but a previous run's backfill may
                # still have unfinished business: shutdown can cut one short
                # (see _backfill), and unlike the migration case above the
                # table it was filling is still exactly the one just
                # confirmed to exist, so resuming means picking the row id
                # it had reached, not starting over from 0.
                resume_cursor = self._read_backfill_cursor()
                if resume_cursor is not None:
                    self._backfill_wanted = True
                    self._backfill_start_cursor = resume_cursor
        except sqlite3.OperationalError:
            # No FTS5, or an SQLite too old for the trigram tokenizer
            # (3.34, December 2020). Search still works, by scanning.
            self.fts = False

    @staticmethod
    def _index_is_current(sql: str) -> bool:
        text = (sql or "").lower()
        return "trigram" in text and "source" in text

    # --------------------------------------------------- backfill persistence
    #
    # A row id in the generic `settings` table under a key of its own, not in
    # DEFAULTS: this is bookkeeping about the index, not a user-facing
    # preference, and settings()/save_settings() only ever look at DEFAULTS'
    # own keys, so it stays invisible to the API and the Settings page.
    _BACKFILL_CURSOR_KEY = "_fts_backfill_cursor"

    def _read_backfill_cursor(self) -> int | None:
        """The row id an earlier, shutdown-interrupted backfill had reached,
        or None if there is nothing to resume (never started one, or the
        last one ran to completion). Caller holds no lock of its own — this
        one does, and is only ever called from inside __init__/_enable_fts,
        which hold the same RLock and so re-enter it rather than blocking."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                (self._BACKFILL_CURSOR_KEY,)).fetchone()
        if row is None or row["value"] is None:
            return None
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return None

    def _write_backfill_cursor(self, cursor: int | None) -> None:
        """cursor=None clears the marker (nothing to resume) rather than a
        second done flag standing for the same fact. Caller holds the lock
        and commits — this never does either on its own, so it can share a
        transaction with the chunk it is persisting progress for."""
        if cursor is None:
            self._conn.execute(
                "DELETE FROM settings WHERE key = ?", (self._BACKFILL_CURSOR_KEY,))
        else:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (self._BACKFILL_CURSOR_KEY, str(cursor)))

    # ------------------------------------------------------------ backfill

    def start_index_backfill(self) -> None:
        """Refill a dropped or previously-interrupted index without holding
        the write lock.

        Done in chunks on a background thread rather than with FTS5's own
        `rebuild`, which is a single statement: on a database with millions of
        messages that would block the collector for as long as it ran, and
        block startup if it ran here.
        """
        if not self.fts or not self._backfill_wanted:
            return
        self._backfill_wanted = False
        cursor = self._backfill_start_cursor
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS hi, COUNT(*) AS n FROM logs").fetchone()
        watermark, total = row["hi"] or 0, row["n"] or 0
        if not total or watermark <= cursor:
            self.index_ready = True
            with self._lock:
                self._write_backfill_cursor(None)
                self._conn.commit()
            return
        self.index_ready = False
        self.index_progress = (cursor, total)
        self._backfill_stop.clear()
        self._backfill_thread = threading.Thread(
            target=self._backfill, args=(cursor, watermark, total),
            name="syslog-index", daemon=True)
        self._backfill_thread.start()

    def _backfill(self, cursor: int, watermark: int, total: int) -> None:
        """Messages newer than the watermark are indexed as they arrive, so
        only what was already stored has to be walked. `cursor` may be
        greater than 0 when resuming a backfill a previous run's shutdown
        cut short (see start_index_backfill/_read_backfill_cursor); rows at
        or below it are already indexed and are not walked again.

        Three ways out, each recorded so the next start knows which one
        happened: finishes on its own (the common case — index_ready=True,
        nothing to resume); is stopped by close() (index_ready is left
        exactly as it was, and the row id reached is persisted to resume
        from); or hits a genuine sqlite3.Error unrelated to being stopped
        (fts=False, logged, nothing to resume — rebuilding an index that
        keeps failing on every restart would just fail the same way again).
        """
        outcome = "done"
        try:
            while cursor < watermark:
                if self._backfill_stop.is_set():
                    outcome = "interrupted"
                    break
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
                    if row and row["hi"] is not None:
                        cursor = row["hi"]
                    self._conn.commit()
                if not row or row["hi"] is None:
                    break
                self.index_progress = (min(cursor, total), total)
                # Let the collector and any reader in between chunks.
                time.sleep(0.02)
        except sqlite3.Error as exc:
            if self._backfill_stop.is_set():
                # The database closing under this chunk is close()'s own
                # doing, not a genuine failure — the same non-bug shape as
                # the check at the top of the loop, just caught here
                # instead, because the stop landed mid-chunk rather than
                # between them.
                outcome = "interrupted"
            else:
                outcome = "failed"
                self.fts = False    # fall back to scanning rather than lie
                self.log.add(ERROR, "Full-text search unavailable, falling "
                                    f"back to scanning: {exc}")

        if outcome == "interrupted":
            try:
                with self._lock:
                    self._write_backfill_cursor(cursor)
                    self._conn.commit()
            except sqlite3.Error:
                pass
            self.log.add(SYSTEM, "Syslog search index backfill paused for "
                                 f"shutdown at {min(cursor, total):,} of "
                                 f"{total:,} messages; it will resume from "
                                 f"there next start")
            return

        # done or failed: either way there is nothing left to resume.
        try:
            with self._lock:
                self._write_backfill_cursor(None)
                self._conn.commit()
        except sqlite3.Error:
            pass
        self.index_ready = True
        self.index_progress = (total, total)

    def close(self) -> None:
        self._backfill_stop.set()
        thread = self._backfill_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=self.BACKFILL_STOP_TIMEOUT_S)
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

    def _collapse(self, entries) -> tuple[list[tuple], list[int]]:
        """Split a batch into rows to insert and rows to fold into a repeat.

        A device in a debug loop sends the same line thousands of times; one
        row per line buries every other message and inflates the index for no
        information. A consecutive identical line from the same source within
        the window bumps the previous row's repeat_count instead — the
        *immediately preceding* row remembered for that source, so two
        different messages interleaving (A, B, A, B, ...) never fold into
        each other; only a genuinely unbroken run of the same message does.

        Returns (to_insert, bumps): to_insert is a list of (entry,
        repeat_count_holder) pairs for rows that must be freshly written —
        repeat_count_holder is a one-element list, `[n]`, not a plain int,
        for the reason below; bumps is the ids of rows already on disk (from
        an EARLIER call to insert()) whose repeat_count needs incrementing.

        `_last_row` (a bounded per-source LRU) used to be updated only for a
        bump, mid-loop, or once per insert() call via `_remember` — using
        the row's real database id, which only exists after the write. A
        fresh (non-repeat) row was therefore invisible to this method until
        the NEXT call to insert(): a repeat of it later in the very SAME
        batch found nothing to bump against and was written as a row of its
        own too. A batch drains the collector's queue every FLUSH_S seconds
        or BATCH messages, whichever comes first (syslogd.py) — a few
        hundred milliseconds to a second — and a storm (a flapping optic, an
        STP reconvergence, an auth retry loop) routinely fires the identical
        line far faster than that, so an entire storm typically arrives
        inside ONE call to insert(): 500 identical lines in a single flush
        used to become 500 rows, not one row with repeat_count=500 — this
        was weakest at exactly the burst rate it exists for, and only ever
        earned its keep against a slow, steady trickle that would not have
        hurt anyway.

        Fixed by giving every not-yet-written row a mutable one-element
        `repeat_count` holder, referenced directly from `_last_row` in place
        of a row id. A later repeat within the SAME batch bumps that holder
        in place — the row is not written yet, so there is nothing in the
        database to UPDATE — while a repeat that lands in a LATER batch,
        after `_remember` (below) has replaced the holder with the row's
        real id once it exists, becomes an ordinary bump against the
        database, exactly as before.
        """
        window = self.collapse_repeats_s
        if window <= 0:
            return [(entry, [1]) for entry in entries], []
        to_insert: list[tuple] = []
        bumps: list[int] = []
        for entry in entries:
            key = entry.source
            previous = self._last_row.get(key)
            if (previous is not None and previous[1] == entry.message
                    and entry.ts - previous[2] <= window):
                ref = previous[0]
                if isinstance(ref, list):
                    # Still sitting in `to_insert` from earlier in this same
                    # batch — nothing to UPDATE yet, so fold it in directly.
                    ref[0] += 1
                else:
                    # Already a real row from an earlier call to insert().
                    bumps.append(ref)
                # The run's row keeps the first occurrence's timestamp — when
                # it started is the useful figure — but the window walks
                # forward so a steady repeat stays one row.
                self._last_row[key] = (ref, previous[1], entry.ts)
                self._last_row.move_to_end(key)
                continue
            holder = [1]
            to_insert.append((entry, holder))
            self._last_row[key] = (holder, entry.message, entry.ts)
            self._last_row.move_to_end(key)
        return to_insert, bumps

    def _remember(self, first_id: int, to_insert) -> None:
        """Replaces each freshly-written row's pending holder (see
        _collapse) with its real database id, so a repeat arriving in a
        LATER call to insert() bumps the row itself rather than a holder
        that stops existing once this call returns. Only touches a source
        whose `_last_row` entry is STILL this exact holder — a source that
        moved on to a different message later in the same batch already
        points at that message's own holder, fixed up on its own turn of
        this same loop."""
        for index, (entry, holder) in enumerate(to_insert):
            current = self._last_row.get(entry.source)
            if current is not None and current[0] is holder:
                self._last_row[entry.source] = (first_id + index, current[1],
                                                current[2])
                self._last_row.move_to_end(entry.source)
        while len(self._last_row) > 4096:
            self._last_row.popitem(last=False)

    def insert(self, entries) -> tuple[int, int]:
        """Stores `entries`, returning (stored, collapsed): `stored` is the
        number of NEW rows written, `collapsed` is how many of the incoming
        entries did not get a row of their own — folded into another row's
        repeat_count instead, same-batch or against an earlier one.
        `stored + collapsed == len(entries)` always, so a caller's own
        "messages received" counter can be reconciled against the two
        without a fresh row for every collapsed repeat."""
        if not entries:
            return 0, 0
        total_in = len(entries)
        counts: dict[tuple[int, int], int] = {}
        for entry in entries:
            key = (int(entry.ts // 3600) * 3600, int(entry.severity))
            counts[key] = counts.get(key, 0) + 1

        with self._lock:
            # Collapsing is decided under the lock so two writers cannot bump
            # the same row concurrently.
            to_insert, bumps = self._collapse(entries)
            rows = [(e.ts, e.source, e.host, e.facility, e.severity, e.app,
                     e.procid, e.msgid, e.message, e.raw, holder[0])
                    for e, holder in to_insert]
            if bumps:
                self._conn.executemany(
                    "UPDATE logs SET repeat_count = repeat_count + 1"
                    " WHERE id = ?", [(row_id,) for row_id in bumps])
            if not rows:
                # The hourly timeline still counts every message that arrived:
                # a storm that collapses to one row is still a storm.
                self._conn.executemany(
                    "INSERT INTO log_counts(hour, severity, n) VALUES (?,?,?)"
                    " ON CONFLICT(hour, severity) DO UPDATE SET n = n + excluded.n",
                    [(hour, severity, n) for (hour, severity), n in counts.items()])
                self._conn.commit()
                return 0, total_in
            self._conn.executemany(
                "INSERT INTO logs(ts, source, host, facility, severity, app,"
                " procid, msgid, message, raw, repeat_count)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
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
                     for index, (entry, _holder) in enumerate(to_insert)])
            else:
                last_id = self._conn.execute(
                    "SELECT last_insert_rowid()").fetchone()[0]
                first_id = last_id - len(rows) + 1
            self._remember(first_id, to_insert)
            self._conn.executemany(
                "INSERT INTO log_counts(hour, severity, n) VALUES (?,?,?)"
                " ON CONFLICT(hour, severity) DO UPDATE SET n = n + excluded.n",
                [(hour, severity, n) for (hour, severity), n in counts.items()])
            self._conn.commit()
        return len(rows), total_in - len(rows)

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
        in addresses from being read as operators (and keeps NEAR, AND and
        stray quotes out of the query language entirely -- everything typed
        is data). Each term is a substring to be found anywhere, and several
        terms must all appear, in any order and any field.

        The one exception is the app's universal wildcard convention: a `*`
        at the very end of a term survives quoting as an FTS5 prefix operator
        (`"interfac"*` matches any word starting with those letters), which is
        what every other search box in the app means by a trailing `*`.
        Quoting it like every other character, as before, made it a literal
        asterisk to match against -- one the tokenizer never produces -- so a
        prefix search silently returned zero rows. A `*` anywhere else in a
        term (leading, embedded, or a lone `*`) has no meaning in that
        convention and is dropped rather than quoted literally, for the same
        reason: a quoted literal `*` can never match real content, so keeping
        it would just be a second way to silently return nothing.
        """
        terms = [term for term in str(text).split() if term]
        parts = []
        for term in terms:
            prefix = term.endswith("*") and len(term) > 1
            core = (term[:-1] if prefix else term).replace("*", "")
            core = core.replace(chr(34), "")
            quoted = f'"{core}"'
            parts.append(quoted + "*" if prefix and core else quoted)
        return " AND ".join(parts)

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

    def rows_since(self, last_id: int, limit: int | None = 500) -> list[sqlite3.Row]:
        """Rows newer than last_id, oldest first — same cursor-read contract
        as SnmpTrapDatabase.traps_since, used by the alert engine.

        `limit` is the caller's per-tick budget; None means "everything
        newer", which only a caller that has already sized the backlog with
        max_id() should ask for.
        """
        with self._lock:
            if limit is None:
                return self._conn.execute(
                    "SELECT * FROM logs WHERE id > ? ORDER BY id ASC",
                    (int(last_id),)).fetchall()
            return self._conn.execute(
                "SELECT * FROM logs WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(last_id), int(limit))).fetchall()

    def max_id(self) -> int:
        """Highest stored log id, so a reader can size its own backlog
        (max_id() - cursor) and say how far behind it is."""
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

    def _delete_logs(self, where: str, params) -> int:
        """Delete matching log rows and their index entries, without a rebuild.

        `INSERT INTO logs_fts(logs_fts) VALUES('rebuild')` costs a full
        re-index of the whole table however few rows were removed — measured
        at 18.6 s to delete a single row from a million, with the write lock
        held the whole time, every fifteen minutes once retention bites.
        RETURNING hands back exactly the column values FTS5 needs to retire
        each row's entries, so the cost becomes proportional to what was
        actually deleted. Must be called with the lock held.
        """
        if self.fts and HAS_RETURNING:
            rows = self._conn.execute(
                f"DELETE FROM logs WHERE {where}"
                " RETURNING id, message, app, host, source", params).fetchall()
            if rows:
                self._conn.executemany(
                    "INSERT INTO logs_fts(logs_fts, rowid, message, app, host,"
                    " source) VALUES ('delete', ?, ?, ?, ?, ?)",
                    [(row["id"], row["message"], row["app"], row["host"],
                      row["source"]) for row in rows])
            return len(rows)

        cursor = self._conn.execute(f"DELETE FROM logs WHERE {where}", params)
        removed = cursor.rowcount or 0
        if removed and self.fts:
            self._rebuild_index()
        return removed

    def _rebuild_index(self) -> None:
        """Pre-3.35 fallback: a full rebuild, at most once an hour.

        Orphaned index rows are harmless — search joins `logs` on the rowid
        and drops what no longer exists — so the rebuild is housekeeping, not
        correctness, and running it on every prune was the whole problem.
        """
        now = time.monotonic()
        if self._last_rebuild is not None and now - self._last_rebuild < REBUILD_INTERVAL_S:
            return
        self._last_rebuild = now
        self._conn.execute("INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")

    def prune(self, retention_days: float, max_rows: int) -> int:
        removed = 0
        now = time.time()
        cutoff = now - retention_days * 86400
        with self._lock:
            removed += self._delete_logs("ts < ?", (cutoff,))
            # A device whose clock is set years ahead files rows that sort to
            # the top of every newest-first search and that `ts < cutoff` can
            # never reach. Arrival-time clamping stops new ones; this removes
            # the ones already stored.
            removed += self._delete_logs("ts > ?", (now + 86400,))
            self._conn.execute("DELETE FROM log_counts WHERE hour < ?", (cutoff,))
            total = self._conn.execute(
                "SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
            if max_rows and total > max_rows:
                removed += self._delete_logs(
                    "id IN (SELECT id FROM logs ORDER BY ts ASC LIMIT ?)",
                    (total - max_rows,))
            self._conn.commit()
        return removed

    def trim_to_size(self, max_bytes: int) -> int:
        """Delete the oldest messages until the file fits under the cap.

        Batched and reclaimed rather than deleted-and-VACUUMed: the write
        lock is the one the syslog writer thread needs, and holding it
        across a whole-file rewrite stalled ingest for seconds at a time.
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
                    "SELECT MIN(id) AS lo, MAX(id) AS hi FROM logs").fetchone()
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
                        removed += self._delete_logs(
                            "id >= ? AND id < ?", (low, upper))
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
                                       budget_s=0.2, label="syslog.db"):
                    break
            if not deletable or time.monotonic() >= deadline:
                break
        if self.size_bytes() > max_bytes:
            log.warning("%s: %d bytes after removing %d rows, still above the "
                        "%d byte cap; continuing at the next maintenance pass",
                        "syslog.db", self.size_bytes(), removed, max_bytes)
        return removed
