"""Storage for collected syslog.

The timeline reads an hourly rollup table rather than scanning messages.
Search uses FTS5 with the trigram tokenizer where SQLite has it, falling back
to a LIKE scan otherwise and for queries under three characters.
"""

from __future__ import annotations

import collections
import logging
import sqlite3
import threading
import time

from .eventlog import ERROR, NullLog, SYSTEM
from .sqlitebase import LIKE_ESCAPE, SqliteStore, id_chunks, like_contains

log = logging.getLogger(__name__)

# One prune batch, in rows, and the band the adaptation may move it inside.
#
# Its own figure rather than sqlitebase's TRIM_CHUNK, which is sized for
# netpath.db's per-hop rows. Every row removed here also costs an FTS5 index
# delete, so a batch is expensive out of proportion to its size and the figure
# has to come from a measurement. Back to back on a million messages, half of
# them past the cutoff, with a reader taking the same lock every 5 ms
# (tests/bench_prune.py's volume and its reader):
#
#     unbatched         6.4 s, one hold of 6,418 ms
#      2,000 rows      13.1 s, 250 holds, worst 462 ms, reader stalled 701 ms
#     10,000 rows       8.3 s,  50 holds, worst 339 ms, reader stalled 481 ms
#
# On the repetitive shape real syslog actually has - the bench holds only
# 10,000 distinct messages in a million rows, so every FTS posting list is a
# hundred entries long and the FTS delete dominates - the same sweep is much
# more expensive, and the size that wins moves with it:
#
#      2,000 rows      31.9 s, reader stalled 2,856 ms
#     10,000 rows      31.8 s, reader stalled 3,497 ms
#     25,000 rows      16.9 s, reader stalled 3,183 ms
#     50,000 rows       9.4 s, reader stalled 2,772 ms
#    100,000 rows       9.2 s, reader stalled 2,877 ms
#
# 50,000 looks better on both of those columns and was tried; it is not.
# Measured per LOCK HOLD rather than per sweep, a 50,000-row batch on this
# store holds the store for a median of 578 ms - nearly four times the
# 150 ms target, and a UI freeze of that length every batch. The shorter
# total is bought by making each individual pause worse, which is the
# opposite of what this is for: nothing waits on the sweep finishing, and
# everything waits on a hold. 10,000 stays.
#
# Committing in pieces costs something whatever the size - a batch's commit
# rewrites the index pages it dirtied, and the next batch dirties more of the
# same - so the largest batch that still keeps the hold near the target wins
# on both counts here.
#
# The band matters as much as the figure. _delete_batches only DOUBLES a batch
# that held the lock for under a quarter of TRIM_LOCK_TARGET_S, and only
# halves one that held it for longer than the target, so a first batch landing
# between the two pins the size for the whole sweep: the start is the
# operating point, not a seed. A store whose batches come off the page cache
# can otherwise double its way up until one of them holds the lock for a
# second or more, which is what the maximum is for.
PRUNE_CHUNK = 10_000
PRUNE_CHUNK_MIN = 2_000
PRUNE_CHUNK_MAX = 20_000

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


class SyslogDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "syslog.db"
    TRIM_TABLE = "logs"
    OLDEST_TS_SQL = "SELECT MIN(ts) FROM logs"
    TRIM_FLOOR = 5000
    # Set by prune() when its budget ran out before the backlog did, the same
    # flag netpath.db and netpath.flowdb raise for the same reason.
    last_prune_incomplete = False

    BACKFILL_CHUNK = 20_000
    # How long close() waits for a chunk already in progress to notice the
    # stop event and land before the connection underneath it is closed —
    # generous for one bulk INSERT of at most BACKFILL_CHUNK rows.
    BACKFILL_STOP_TIMEOUT_S = 10.0

    def __init__(self, path: str, log=None):
        # The EventLog is optional but wanted: a dropped index silently
        # downgrading search to scanning for the rest of the process is a
        # fact an operator needs, and the module logger never reaches the UI.
        self.log = log or NullLog()
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
        super().__init__(path)

    def _migrate(self) -> None:
        self.ensure_columns(
            "logs", {"repeat_count": "INTEGER NOT NULL DEFAULT 1"})
        self._enable_fts()

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

    def begin_close(self) -> None:
        self._backfill_stop.set()

    def close(self, timeout_s: float | None = None) -> None:
        self.begin_close()
        budget = (self.BACKFILL_STOP_TIMEOUT_S if timeout_s is None
                  else max(0.0, timeout_s))
        deadline = time.monotonic() + budget
        thread = self._backfill_thread
        if thread is not None and thread.is_alive():
            # The join and the close share the budget rather than taking one
            # each: the caller's deadline is for this store as a whole.
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        super().close(max(0.0, deadline - time.monotonic()))

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
            clauses.append(f"l.source LIKE ? {LIKE_ESCAPE}")
            params.append(like_contains(filters["source"]))
        if filters.get("host"):
            clause = f"l.host LIKE ? {LIKE_ESCAPE}"
            params.append(like_contains(filters["host"]))
            # Widened by the addresses the API resolved the fragment to;
            # one parenthesis, so a second chunk cannot escape the time AND.
            ips = [ip for ip in (filters.get("host_ips") or ()) if ip]
            if ips:
                ors = []
                for chunk in id_chunks(ips):
                    ors.append(f"l.source IN ({','.join('?' * len(chunk))})")
                    params.extend(chunk)
                clause = f"({clause} OR {' OR '.join(ors)})"
            clauses.append(clause)
        if filters.get("app"):
            clauses.append(f"l.app LIKE ? {LIKE_ESCAPE}")
            params.append(like_contains(filters["app"]))
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
                f"{column} LIKE ? {LIKE_ESCAPE}"
                for column in self.SCAN_COLUMNS) + ")")
            params.extend([like_contains(term)] * len(self.SCAN_COLUMNS))
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

    def _trim_delete(self, low: int, upper: int) -> int:
        return self._delete_logs("id >= ? AND id < ?", (low, upper))

    def _delete_logs(self, where: str, params) -> int:
        """Delete matching log rows and their index entries, without a rebuild.

        `INSERT INTO logs_fts(logs_fts) VALUES('rebuild')` re-indexes the
        whole table however few rows were removed, with the write lock held.
        RETURNING hands back exactly the column values FTS5 needs to retire
        each row's entries, so the cost is proportional to what was deleted.
        Must be called with the lock held.
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

    def _id_bounds(self, where: str, params) -> tuple[int | None, int]:
        """(lowest id matching `where`, one past the highest), or (None, 0).

        Two index probes rather than a COUNT, and the pair _delete_batches
        walks. Cheap now that Wave 1 indexed the columns retention filters on.
        """
        with self._lock:
            row = self._conn.execute(
                f"SELECT MIN(id) AS lo, MAX(id) AS hi FROM logs WHERE {where}",
                params).fetchone()
        return row["lo"], (row["hi"] or 0) + 1

    def _batched_delete_logs(self, where: str, params, low: int, cut: int,
                             deadline: float) -> tuple[int, int]:
        """Delete the ids in [low, cut) matching `where`, a batch per lock
        hold.

        The id range only chunks the sweep - every batch still carries
        `where`, so a device with a wrong clock cannot make a prune drop the
        wrong rows. netpath.db.prune's shape, and measurably the right one
        here: chunking by how many rows have gone instead, which re-runs an
        `ORDER BY ts LIMIT` for every batch, cost half as much again in total
        and five times the worst lock hold on a million messages.

        A clock years behind does cost something even so - its row takes a
        current id while sorting to the far past, which puts MAX(id) at the
        end of the table and has the sweep chunk-walk ids it will not delete.
        Those batches are empty index probes rather than work, which is the
        cheap way to be wrong here.

        Returns (rows removed, the id reached), so a caller can tell a
        finished sweep from one a budget cut short. Each batch goes through
        _delete_logs, so the FTS index is retired with the rows it belongs to
        and is consistent at every point a reader can observe.
        """
        def delete(low_id: int, upper: int) -> int:
            return self._delete_logs(f"id >= ? AND id < ? AND {where}",
                                     (low_id, upper, *params))

        return self._delete_batches(
            low, cut, deadline, delete, chunk=PRUNE_CHUNK,
            chunk_min=PRUNE_CHUNK_MIN, chunk_max=PRUNE_CHUNK_MAX)

    def prune(self, retention_days: float, max_rows: int,
              budget_s: float | None = None) -> int:
        """Age out messages, drop future-dated ones, then cap the row count.

        Batched in adaptive, lock-bounded chunks rather than one DELETE per
        stage. Every read on this store takes the same single lock the delete
        takes, so an unbatched sweep of a month of messages froze every page
        touching syslog for as long as the whole DELETE ran - and this store
        was by far the worst of them, because each removed row also costs an
        FTS5 index delete.

        Which rows go is unchanged: the stages, their order and their
        predicates are what they were.

        `budget_s` is None by default, and so by default there is no
        deadline: this prune never had one, and cutting a retention sweep
        short is a retention change, not the latency change this is. A caller
        that must bound the sweep passes one, and last_prune_incomplete then
        says the backlog is unfinished.
        """
        removed = 0
        now = time.time()
        cutoff = now - retention_days * 86400
        deadline = (float("inf") if budget_s is None
                    else time.monotonic() + budget_s)
        incomplete = False

        low, cut = self._id_bounds("ts < ?", (cutoff,))
        if low is not None:
            gone, reached = self._batched_delete_logs(
                "ts < ?", (cutoff,), low, cut, deadline)
            removed += gone
            incomplete = incomplete or reached < cut

        # A device whose clock is set years ahead files rows that sort to
        # the top of every newest-first search and that `ts < cutoff` can
        # never reach. Arrival-time clamping stops new ones; this removes
        # the ones already stored.
        horizon = now + 86400
        low, cut = self._id_bounds("ts > ?", (horizon,))
        if low is not None:
            gone, reached = self._batched_delete_logs(
                "ts > ?", (horizon,), low, cut, deadline)
            removed += gone
            incomplete = incomplete or reached < cut

        # log_counts is one row per hour per severity - a month of it is a few
        # thousand rows, and it has no id to chunk on. Its own short lock hold
        # rather than a share of the sweep's, which is all that force-fitting
        # it into the id-range helper would have bought it.
        with self._lock:
            self._conn.execute("DELETE FROM log_counts WHERE hour < ?", (cutoff,))
            self._conn.commit()

        if max_rows:
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
            over = total - max_rows
            if over > 0:
                # The one stage an id range cannot express: once a clock is
                # wrong, "the oldest `over` rows BY ts" is not an id range.
                # Chunked by how many have gone instead, re-selecting the
                # oldest remaining each time, which is the same set the single
                # DELETE picked - nothing arriving mid-sweep can join it,
                # because a new row's ts is now and the set is the oldest end
                # of the table.
                def by_ts(low_n: int, upper: int) -> int:
                    return self._delete_logs(
                        "id IN (SELECT id FROM logs ORDER BY ts ASC LIMIT ?)",
                        (upper - low_n,))

                gone, reached = self._delete_batches(
                    0, over, deadline, by_ts, chunk=PRUNE_CHUNK,
                    chunk_min=PRUNE_CHUNK_MIN, chunk_max=PRUNE_CHUNK_MAX)
                removed += gone
                incomplete = incomplete or reached < over

        self.last_prune_incomplete = incomplete
        if incomplete:
            log.warning("netpath.syslogdb: prune of messages older than %.1f "
                        "days did not finish within its budget; continuing at "
                        "the next maintenance pass", retention_days)
        return removed
