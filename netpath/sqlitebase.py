"""The SQLite foundation every database module in the application sits on.

Opening a file with owner-only modes and the app's pragmas, converting it to
incremental auto-vacuum and reclaiming space without VACUUM, coercing settings
values to the types their defaults declare, and trimming a table to a size cap
in lock-bounded batches.
"""
from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import stat
import threading
import time

log = logging.getLogger(__name__)


# --------------------------------------------------------------------- open

def _tighten(path: str) -> None:
    """chmod 0600 the database and its WAL/SHM files where that is meaningful."""
    if os.name == "nt":
        return
    for suffix in ("", "-wal", "-shm"):
        candidate = path + suffix
        try:
            current = stat.S_IMODE(os.stat(candidate).st_mode)
        except OSError:
            continue
        if current & 0o077:
            try:
                os.chmod(candidate, 0o600)
            except OSError:
                pass


def connect(path: str, **kwargs) -> sqlite3.Connection:
    """Open ``path`` like ``sqlite3.connect`` and restrict it to the owner.

    In-memory databases (``:memory:`` or empty path) are returned untouched.
    ``check_same_thread`` defaults to False because every database in the
    application is shared by worker threads behind its own lock.
    """
    kwargs.setdefault("check_same_thread", False)
    conn = sqlite3.connect(path, **kwargs)
    # Set here rather than per caller so no module can forget one. Without
    # busy_timeout a second writer gets SQLITE_BUSY immediately instead of
    # waiting out the one write transaction held under the module lock;
    # cache_size (negative = KiB) and mmap_size (a ceiling the OS may use,
    # not an allocation) otherwise stay at SQLite's small stock defaults.
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA cache_size=-20000")
        conn.execute("PRAGMA mmap_size=268435456")
        # Sorts and grouping that no index can serve stay in memory rather
        # than spilling to a temp file. Most of the reads that cost anything
        # here are of that shape -- an ORDER BY over an expression, or over a
        # column the filter already had to scan -- so this is the cheapest
        # line in the file. Bounded by SQLite's own temp allocations.
        conn.execute("PRAGMA temp_store=MEMORY")
    except sqlite3.DatabaseError:
        pass
    if path and path != ":memory:" and not path.startswith("file:"):
        _tighten(path)
        try:
            # Creating the WAL files early lets their modes be fixed here
            # rather than at the first write on a shared connection.
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        _tighten(path)
    return conn


# --------------------------------------------------------------- reclaiming

INCREMENTAL = 2

# An existing database is converted at open only when it is at most this many
# pages — about 8 MB at the default page size. The conversion is a whole-file
# VACUUM, and doing seven of them at startup is how launching the application
# came to take half a minute on a real fleet's data.
CONVERT_AT_OPEN_PAGES = 2000


def enable_incremental_vacuum(conn: sqlite3.Connection, label: str = "",
                              max_pages: int | None = CONVERT_AT_OPEN_PAGES) -> bool:
    """Switch ``conn``'s database to incremental auto-vacuum.

    An existing database created with ``auto_vacuum=NONE`` needs one
    whole-file ``VACUUM`` to rebuild its page map, so by default that happens
    only for a database small enough for it to be imperceptible; ``reclaim``
    converts the rest by passing ``max_pages=None``. Returns True when the
    database is in incremental mode afterwards.
    """
    try:
        mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
    except sqlite3.DatabaseError:
        return False
    if mode == INCREMENTAL:
        return True
    try:
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
    except sqlite3.DatabaseError:
        return False
    if max_pages is not None and pages > max_pages:
        # Not now: this is the startup path.
        return False
    try:
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
        if mode != INCREMENTAL:
            # The pragma alone only takes on a database with no pages at all,
            # and opening one in WAL mode already writes page 1 — so even a
            # brand-new file needs the VACUUM for the setting to stick.
            started = time.monotonic()
            conn.execute("VACUUM")
            if pages > 1:
                log.info("%s: converted to incremental auto-vacuum in %.1f s",
                         label or "database", time.monotonic() - started)
            mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
    except sqlite3.DatabaseError as exc:
        log.warning("%s: could not enable incremental vacuum: %s", label or "database", exc)
        return False
    return mode == INCREMENTAL


def reclaim(conn: sqlite3.Connection, lock: threading.Lock | threading.RLock,
            pages: int = 2000, budget_s: float = 2.0, label: str = "") -> int:
    """Free unused pages in steps of ``pages`` until none remain or the time
    budget is spent.  Each step runs inside ``lock``; the lock is released
    between steps.  Returns the number of pages freed.
    """
    # Whatever the open path was too large to convert. This runs from the
    # prune and trim paths, so the one-time whole-file rewrite lands on the
    # maintenance timer where a pause is expected rather than at startup.
    with lock:
        enable_incremental_vacuum(conn, label, max_pages=None)
    freed = 0
    deadline = time.monotonic() + max(0.0, budget_s)
    while True:
        with lock:
            try:
                before = conn.execute("PRAGMA freelist_count").fetchone()[0]
                if before <= 0:
                    break
                conn.execute(f"PRAGMA incremental_vacuum({int(pages)})")
                after = conn.execute("PRAGMA freelist_count").fetchone()[0]
            except sqlite3.DatabaseError as exc:
                log.warning("%s: incremental vacuum failed: %s", label or "database", exc)
                break
        freed += max(0, before - after)
        if after <= 0 or after == before or time.monotonic() >= deadline:
            break
        # Release the GIL before reacquiring the lock. A Python lock is not
        # fair: without this the loop reacquires it before a waiting writer is
        # ever scheduled, so releasing it between steps bought the writer
        # nothing.
        time.sleep(0)
    with lock:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.DatabaseError:
            pass
    return freed


# ------------------------------------------------------------------ settings

_BOOL_TRUE = {"true", "1", "yes", "on"}
_BOOL_FALSE = {"false", "0", "no", "off"}


def _coerce_bool(value):
    if isinstance(value, bool):
        return value, True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 0:
            return False, True
        if value == 1:
            return True, True
        return None, False
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _BOOL_TRUE:
            return True, True
        if text in _BOOL_FALSE:
            return False, True
    return None, False


def _coerce_number(value, kind):
    if isinstance(value, bool) or value is None:
        return None, False
    if isinstance(value, (int, float)):
        num = value
    elif isinstance(value, str):
        try:
            num = float(value)
        except (ValueError, TypeError):
            return None, False
    else:
        return None, False
    if isinstance(num, float) and (math.isnan(num) or math.isinf(num)):
        return None, False
    return (int(num) if kind is int else float(num)), True


def _coerce_list_of_str(value):
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value), True
    return None, False


def _coerce_str(value):
    if isinstance(value, bool):
        return None, False
    if isinstance(value, str):
        return value, True
    if isinstance(value, (int, float)):
        return str(value), True
    return None, False


def coerce_settings(defaults: dict, values: dict, *, strict: bool) -> dict:
    """Coerce each key in `values` that also exists in `defaults` to match
    that default's type. Keys not present in `defaults` are dropped.

    strict=True: a value that cannot be coerced raises
    ValueError(f"{key} must be a {kind}"). strict=False: it is replaced with
    the default value instead, so a database already holding a bad value (a
    null, or a browser NaN) still starts the service.

    Only the keys present in `values` come back: post_settings hands the
    result to an apply_* method that update()s the live dict, so a result
    padded out with every default would reset each setting the request did
    not mention.
    """
    result = {}
    for key, value in values.items():
        if key not in defaults:
            continue
        default = defaults[key]
        if isinstance(default, bool):
            coerced, ok = _coerce_bool(value)
            kind = "true/false value"
        elif isinstance(default, int):
            coerced, ok = _coerce_number(value, int)
            kind = "number"
        elif isinstance(default, float):
            coerced, ok = _coerce_number(value, float)
            kind = "number"
        elif isinstance(default, list):
            coerced, ok = _coerce_list_of_str(value)
            kind = "list of strings"
        elif isinstance(default, str):
            coerced, ok = _coerce_str(value)
            kind = "string"
        else:
            coerced, ok = value, True
        if ok:
            result[key] = coerced
        elif strict:
            raise ValueError(f"{key} must be a {kind}")
        else:
            result[key] = default
    return result


# ------------------------------------------------------------------ id sets

# One SQLite statement can bind at most SQLITE_MAX_VARIABLE_NUMBER
# parameters, and the bulk routes bind one per id in a "WHERE id IN (?,?,…)".
# That ceiling is 32766 on SQLite 3.32 and newer (3.45 here) but 999 on
# anything older, and this application does not choose which SQLite its
# Python was linked against — so the number is not knowable at the call
# site, and a request that works on one operator's install would fail on
# another's with "too many SQL variables", an OperationalError the route
# would answer as a 500.
#
# Splitting the ids rather than capping them keeps the shipped workflow
# whole: the Devices page offers a 1000-row page size and a select-all that
# checks every row on it, so any cap below 1000 breaks bulk delete or bulk
# poll for an operator doing the obvious thing. Every chunk runs inside the
# caller's single `with self._lock:` and one commit, so the operation stays
# atomic — the split is a statement-size detail, not a transaction boundary.
_ID_CHUNK = 500


def id_chunks(ids, size: int = _ID_CHUNK):
    ids = list(ids)
    for start in range(0, len(ids), size):
        yield ids[start:start + size]


# A LIKE needle that matches the operator's text literally. Every search box
# in the product feeds LIKE, where a typed `_` or `%` is a wildcard unless
# escaped; pair each of these with `LIKE ? ESCAPE '\\'`.
LIKE_ESCAPE = "ESCAPE '\\'"


def _like_escape(text) -> str:
    return (str(text).replace("\\", "\\\\")
            .replace("%", "\\%").replace("_", "\\_"))


def like_contains(text) -> str:
    return "%" + _like_escape(text) + "%"


def like_prefix(text) -> str:
    return _like_escape(text) + "%"


# ----------------------------------------------------------------- histogram

# The three event stores (alerts, traps, syslog) answer /histogram with one
# shape: contiguous fixed-width buckets over [t0, t1], added into by slot
# index. Shared here so the three cannot drift apart.

def hist_buckets(t0: float, t1: float, bucket_s: float) -> tuple:
    """(start, bucket_s, slots, buckets) for a histogram over [t0, t1].
    bucket_s is floored at a minute and start snapped down to a bucket
    boundary, so the first bucket may begin before t0."""
    bucket_s = max(float(bucket_s), 60.0)
    start = int(t0 // bucket_s) * bucket_s
    slots = max(1, int((t1 - start) / bucket_s) + 1)
    buckets = [{"t0": start + i * bucket_s, "t1": start + (i + 1) * bucket_s,
                "total": 0, "by_severity": {}} for i in range(slots)]
    return start, bucket_s, slots, buckets


def hist_add(buckets: list, slots: int, index, severity, n: int) -> None:
    """Add n rows of `severity` to bucket `index`, ignoring out-of-range slots."""
    if index is None or not (0 <= index < slots):
        return
    buckets[index]["total"] += n
    key = str(severity)
    by = buckets[index]["by_severity"]
    by[key] = by.get(key, 0) + n


def hist_from_rollup(buckets: list, slots: int, start: float, bucket_s: float,
                     rows, severity_cap=None) -> list:
    """Fill buckets from hour/severity/n rollup rows, dropping rows above the
    optional severity ceiling (a larger severity number is less severe)."""
    cap = None if severity_cap in (None, "") else int(severity_cap)
    for row in rows:
        if cap is not None and row["severity"] > cap:
            continue
        hist_add(buckets, slots, int((row["hour"] - start) / bucket_s),
                 row["severity"], row["n"])
    return buckets


# --------------------------------------------------------------------- trim

TRIM_CHUNK = 2_000         # rows per lock acquisition, adapted below
TRIM_CHUNK_MIN = 500
TRIM_CHUNK_MAX = 50_000
TRIM_LOCK_TARGET_S = 0.15    # how long one batch may hold the write lock
TRIM_PASSES = 40             # delete/reclaim rounds before giving up
TRIM_BUDGET_S = 30.0         # wall clock for one full trim_to_size call


class InstrumentedLock:
    """An RLock that records how long callers wait for it and hold it.

    Every read in this application takes its store's single write lock, not
    just every write — so although all thirteen files are in WAL mode, and
    WAL would let readers run alongside a writer, that concurrency is not
    reachable through one connection behind one Python lock. Whether that
    costs anything at a given fleet size is an empirical question, and this
    is the measurement that answers it: `wait_s` per store per minute is the
    time the web tier spent queued behind the poller and the collectors.

    Measured cost is 0.8 us per acquisition on top of a plain RLock's 0.1 us
    -- two perf_counter calls and a thread-local lookup. Stated as a share
    rather than a ratio, because the ratio flatters and frightens by turns:
    that is 0.25% of a scheduler pass and 7% of the cheapest single-row read
    in the application, and at ten thousand acquisitions a second it is
    eight milliseconds. It stays on in production at that price, rather than
    sitting behind a flag nobody turns on until it is too late to be useful.

    Re-entrancy is counted per thread and only the outermost acquisition is
    recorded: several stores nest `with self._lock:` deliberately (syslogdb
    documents its own at length), and counting the inner ones would report
    hold time that overlaps itself.

    Implements acquire()/release() as well as the context-manager protocol
    because callers use both -- tests/test_nodes_split_upgrade.py probes a
    store lock with acquire(timeout=...), and tests/test_collectors_hardening.py
    wraps one in a spy that delegates both.
    """

    __slots__ = ("_lock", "_local", "_stats")

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._local = threading.local()
        self._stats = {"acquisitions": 0, "wait_s": 0.0,
                       "hold_s": 0.0, "max_hold_s": 0.0}

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        clock = time.perf_counter
        started = clock()
        if not self._lock.acquire(blocking, timeout):
            return False
        local = self._local
        try:
            depth = local.depth
        except AttributeError:
            depth = 0                   # first acquisition on this thread
        local.depth = depth + 1
        if not depth:
            now = clock()
            local.waited = now - started
            local.held_at = now
        return True

    def release(self) -> None:
        local = self._local
        held = getattr(local, "depth", 0)
        if held <= 0:
            # Not held by this thread. Hand straight to the real lock so it
            # raises its own "cannot release un-acquired lock" rather than an
            # AttributeError off the counters, and leave the depth alone: a
            # bogus release must not leave this thread's bookkeeping negative
            # and its later, legitimate holds unrecorded.
            self._lock.release()
            return
        depth = held - 1
        local.depth = depth
        if not depth:
            # Recorded before the underlying release, so this runs while the
            # lock is still held and the counters need no lock of their own.
            held = time.perf_counter() - local.held_at
            stats = self._stats
            stats["acquisitions"] += 1
            stats["wait_s"] += local.waited
            stats["hold_s"] += held
            if held > stats["max_hold_s"]:
                stats["max_hold_s"] = held
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc) -> bool:
        self.release()
        return False

    def stats(self) -> dict:
        """Cumulative since process start, like every other counter here.
        A caller wanting a rate takes two snapshots and subtracts."""
        return dict(self._stats)


class SqliteStore:
    """One SQLite file: opened, migrated, settings-carrying, size-capped.

    Subclasses set SCHEMA/DEFAULTS/LABEL and, where they trim, TRIM_TABLE and
    TRIM_FLOOR; they hook in with _before_schema/_migrate/_after_open.
    """

    SCHEMA = ""
    DEFAULTS: dict = {}
    LABEL = "database"
    PRAGMAS = ("journal_mode=WAL", "synchronous=NORMAL", "foreign_keys=ON")
    TRIM_TABLE = ""
    TRIM_FLOOR = 200
    # None for a store with no history (the MIB and mapper files hold
    # current state, not a log).
    OLDEST_TS_SQL: str | None = None

    def __init__(self, path: str):
        self.path = path
        self._lock = InstrumentedLock()
        # close() is called twice on some paths (a self-update's before-restart
        # hook, then the console's own teardown), and once through it the
        # connection is gone; the flag makes the second call free.
        self._closed = False
        self._conn = connect(path)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            for pragma in self.PRAGMAS:
                self._conn.execute(f"PRAGMA {pragma}")
            self._before_schema()
            enable_incremental_vacuum(self._conn, self.LABEL)
            if self.SCHEMA:
                self._conn.executescript(self.SCHEMA)
            self._migrate()
            self._conn.commit()
        self._after_open()

    # ------------------------------------------------------------- lifecycle

    def optimize(self) -> None:
        """Let SQLite update the statistics its planner reads.

        Neither this nor ANALYZE had ever been run anywhere in this
        application, so every query with more than one usable index has been
        planned on stock guesses since it was written. Called from the
        maintenance sweep rather than at open: on a cold large file it can
        take a while, and startup time is already a sore point (see
        enable_incremental_vacuum's note about half a minute).

        Best-effort. A planner hint that cannot be refreshed is not a reason
        to fail a maintenance pass.
        """
        try:
            with self._lock:
                self._conn.execute("PRAGMA optimize")
        except sqlite3.DatabaseError as exc:
            log.debug("%s: PRAGMA optimize failed: %s", self.LABEL, exc)

    def lock_stats(self) -> dict:
        """How much time this store's single lock has cost, cumulatively.

        `wait_s` is the interesting one: it is time threads spent queued for
        a file that WAL would have let them read concurrently. A store whose
        wait is negligible does not need a read connection; one whose wait
        is a real share of request latency does.
        """
        stats = getattr(self._lock, "stats", None)
        # A test may have swapped the lock for a plain one or a spy; report
        # nothing rather than raising into whatever is asking.
        return stats() if callable(stats) else {}

    def _before_schema(self) -> None:
        """Anything that must observe the file as it was before SCHEMA ran."""

    def _migrate(self) -> None:
        """Columns and indexes added after a database was first created."""

    def _after_open(self) -> None:
        """Seeding and other work that needs the schema in place."""

    def ensure_columns(self, table: str, columns) -> set[str]:
        """Add whichever of `columns` the table does not have, and return the
        names added so a caller can gate a one-time backfill on it.

        `columns` is a mapping of column name to its SQL type, or any iterable
        of (name, type) pairs.
        """
        have = {row["name"] for row in
                self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
        items = columns.items() if hasattr(columns, "items") else columns
        added: set[str] = set()
        for name, definition in items:
            if name in have:
                continue
            self._conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
            added.add(name)
        return added

    # A FULL checkpoint can't run past another connection's read lock,
    # reporting that in the result row's first column (0 completed, 1 busy)
    # rather than raising. Measured: retries after the 5s busy_timeout cost
    # ~344ms total, completing in under a millisecond once the reader lets go.
    CHECKPOINT_RETRIES = 4
    CHECKPOINT_RETRY_TIMEOUT_MS = 50
    CHECKPOINT_RETRY_WAIT_S = 0.05

    def _checkpoint_full(self) -> bool:
        """Fold the log back into the database file. True when it really did. The caller holds the store lock."""
        if not self._conn.execute("PRAGMA wal_checkpoint(FULL)").fetchone()[0]:
            return True
        restore = self._conn.execute("PRAGMA busy_timeout").fetchone()[0]
        self._conn.execute(
            f"PRAGMA busy_timeout={self.CHECKPOINT_RETRY_TIMEOUT_MS}")
        try:
            for _ in range(self.CHECKPOINT_RETRIES):
                time.sleep(self.CHECKPOINT_RETRY_WAIT_S)
                if not self._conn.execute(
                        "PRAGMA wal_checkpoint(FULL)").fetchone()[0]:
                    return True
        finally:
            self._conn.execute(f"PRAGMA busy_timeout={restore}")
        return False

    def _commit_durable(self) -> None:
        """Commit, and do not return until the transaction is on the platter.

        For the handful of writers that store an operator-entered credential.
        Most of these stores run `synchronous=NORMAL`, which in WAL mode does
        not fsync at commit: the write is safe against corruption but a power
        loss can lose a transaction SQLite already reported committed, and
        "we said we stored your password" has to stay true. A full checkpoint
        forces the log back into the database file and syncs it; it costs a
        few milliseconds, on writes that happen a handful of times a year.

        Retried briefly and, if it still cannot run, logged rather than
        silently dropped.
        """
        with self._lock:
            self._conn.commit()
            if self._checkpoint_full():
                return
            log.warning(
                "%s: the credential just written is committed but still only "
                "in the write-ahead log -- a full checkpoint could not run "
                "past another connection's read lock in %.1fs. The row is "
                "there and readable; it is a power loss before the next "
                "checkpoint that could lose it.",
                os.path.basename(self.path),
                self.CHECKPOINT_RETRIES * self.CHECKPOINT_RETRY_WAIT_S)

    # How long close() waits for whatever holds the store lock before closing
    # anyway. The lock is held by ordinary queries, and the web server's
    # request threads are daemons that survive WebServer.stop() (see
    # ThreadingHTTPServer.daemon_threads), so a wide search started a moment
    # before shutdown used to hold this connection open with no bound at all.
    CLOSE_LOCK_WAIT_S = 2.0

    def begin_close(self) -> None:
        """Ask anything this store owns to wind down, without waiting.
        A no-op here; the two stores with backfill threads override it so
        their threads are already stopping by the time close() joins them."""

    def close(self, timeout_s: float | None = None) -> None:
        """Close the connection, waiting at most `timeout_s` for the store
        lock first.

        Closing without the lock is deliberate and is the better of the two
        failures available: a worker still mid-query gets
        `ProgrammingError: Cannot operate on a closed database`, which every
        worker's guard already handles and which costs one measurement — where
        waiting for the lock costs a shutdown that never returns.
        """
        if self._closed:
            return
        self._closed = True
        wait = self.CLOSE_LOCK_WAIT_S if timeout_s is None else max(0.0, timeout_s)
        held = self._lock.acquire(timeout=wait) if wait else self._lock.acquire(
            blocking=False)
        try:
            self._conn.close()
        finally:
            if held:
                self._lock.release()

    def size_bytes(self) -> int:
        """The file and its WAL/SHM companions on disk."""
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def oldest_ts(self) -> float | None:
        """When this store's history starts, in epoch seconds, or None when
        it holds none."""
        if not self.OLDEST_TS_SQL:
            return None
        try:
            with self._lock:
                row = self._conn.execute(self.OLDEST_TS_SQL).fetchone()
        except sqlite3.ProgrammingError:
            return None
        value = row[0] if row else None
        return None if value is None else float(value)

    # -------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = dict(self.DEFAULTS)
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        for row in rows:
            if row["key"] in values:
                try:
                    values[row["key"]] = json.loads(row["value"])
                except (ValueError, TypeError):
                    pass
        return coerce_settings(self.DEFAULTS, values, strict=False)

    def save_settings(self, values: dict) -> None:
        """Store the keys this store owns. Anything else in the dict is
        ignored, so one merged settings dict can be handed to each store in
        turn and each takes only what it owns."""
        with self._lock:
            for key, value in values.items():
                if key not in self.DEFAULTS:
                    continue
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)),
                )
            self._conn.commit()

    def _private_setting(self, key: str, default=None):
        """A settings row a module keeps for itself. Not in DEFAULTS, so
        settings() never returns it and save_settings() cannot be made to
        overwrite it from the settings dialog — it is bookkeeping, not a
        preference."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (ValueError, TypeError):
            return default

    def _set_private_setting(self, key: str, value, commit: bool = True) -> None:
        """commit=False for a caller that owns the transaction."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES (?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)))
            if commit:
                self._conn.commit()

    def _clear_private_setting(self, key: str, commit: bool = True) -> None:
        """Remove the row rather than storing a null, for bookkeeping whose
        ABSENCE is the fact. commit=False as above."""
        with self._lock:
            self._conn.execute("DELETE FROM settings WHERE key = ?", (key,))
            if commit:
                self._conn.commit()

    # ------------------------------------------------------------------ trim

    def _trim_size(self) -> int:
        """The figure trim_to_size compares against the cap."""
        return self.size_bytes()

    def _trim_delete(self, low: int, upper: int) -> int:
        """Delete ids in [low, upper) from TRIM_TABLE; returns rows removed.

        Called with the lock held and without committing — _delete_batches
        owns both.
        """
        cursor = self._conn.execute(
            f"DELETE FROM {self.TRIM_TABLE} WHERE id >= ? AND id < ?",
            (low, upper))
        return cursor.rowcount or 0

    def _delete_batches(self, low: int, cut: int, deadline: float, delete=None,
                        *, chunk: int | None = None, chunk_min: int | None = None,
                        chunk_max: int | None = None,
                        pause: float = 0.0) -> tuple[int, int]:
        """Delete ids in [low, cut) in batches until `deadline`.

        Returns (rows removed, the id reached). `delete` defaults to
        _trim_delete; the chunk bounds default to this module's, and are
        passed explicitly by callers whose own module globals are the ones
        tests adjust. `pause` sleeps that long between batches, giving a
        reader a chance at the lock; left at 0 except by the device purge.
        """
        delete = delete or self._trim_delete
        batch = TRIM_CHUNK if chunk is None else chunk
        smallest = TRIM_CHUNK_MIN if chunk_min is None else chunk_min
        largest = TRIM_CHUNK_MAX if chunk_max is None else chunk_max
        removed = 0
        while low < cut and time.monotonic() < deadline:
            upper = min(low + batch, cut)
            started = time.monotonic()
            with self._lock:
                removed += delete(low, upper)
                self._conn.commit()
            held = time.monotonic() - started
            low = upper
            if pause:
                time.sleep(pause)
            # Keep one batch's lock hold near TRIM_LOCK_TARGET_S however large
            # the rows turn out to be — a trap with its raw frame stored costs
            # an order of magnitude more than a syslog line, and one fixed
            # batch size cannot suit both.
            #
            # The band is wide (target/4 to target), so a first batch landing
            # inside it never moves again: the STARTING chunk is the operating
            # point, not a seed it converges away from. TRIM_CHUNK is sized
            # for netpath.db's per-hop rows, so a store whose rows are a
            # different size should pass its own measured chunk/min/max rather
            # than inherit these. Measured while batching the prunes: at the
            # wrong chunk size, batching a delete cost sixteen times the
            # unbatched total, because every commit rewrites the index leaf
            # pages the next batch is about to dirty again.
            if held > TRIM_LOCK_TARGET_S:
                batch = max(smallest, batch // 2)
            elif held < TRIM_LOCK_TARGET_S / 4:
                batch = min(largest, batch * 2)
        return removed, low

    def _reclaim_until(self, deadline: float) -> None:
        # In short slices, outside the delete batches' lock block: reclaim
        # takes the lock itself and reacquires it in a tight loop, and a
        # Python lock is not fair.
        while time.monotonic() < deadline:
            if not reclaim(self._conn, self._lock, pages=500, budget_s=0.2,
                           label=self.LABEL):
                break

    def _trim_more(self, max_bytes: int, budget_s: float | None) -> int:
        """Whatever a subclass trims after the rows in TRIM_TABLE, returning
        how many it removed.

        A hook rather than an override of trim_to_size, so the over-cap
        warning below is emitted once the whole job is done: flowdb's second
        stage gives up rollup buckets after the raw flows have reached their
        floor, and a store whose summaries hold the space used to be warned
        about on every sweep from the middle of a trim that then succeeded.
        """
        return 0

    def trim_to_size(self, max_bytes: int, budget_s: float | None = None) -> int:
        """Delete the oldest rows until the store fits under the cap.

        Batched and reclaimed rather than deleted-and-VACUUMed: the write lock
        is the one the ingest thread needs, and holding it across a whole-file
        rewrite stalls ingest for seconds at a time.
        """
        if max_bytes <= 0:
            return 0
        removed = 0
        deadline = time.monotonic() + (TRIM_BUDGET_S if budget_s is None else budget_s)
        for _ in range(TRIM_PASSES):
            size = self._trim_size()
            if size <= max_bytes:
                break
            with self._lock:
                bounds = self._conn.execute(
                    f"SELECT MIN(id) AS lo, MAX(id) AS hi FROM {self.TRIM_TABLE}"
                ).fetchone()
            low, high = bounds["lo"], bounds["hi"]
            # Ids are handed out in arrival order, so the id span is both the
            # right definition of "oldest" — immune to a device with a wrong
            # clock — and a proxy for the row count that costs one index probe
            # rather than the full scan a COUNT(*) would.
            deletable = 0 if low is None else max(0, high - low + 1 - self.TRIM_FLOOR)
            if deletable:
                span = high - low + 1
                want = min(deletable, max(1, int(
                    span * (1.0 - max_bytes / float(size)) * 1.1)))
                batch_removed, _ = self._delete_batches(low, low + want, deadline)
                removed += batch_removed
            self._reclaim_until(deadline)
            if not deletable or time.monotonic() >= deadline:
                break
        removed += self._trim_more(max_bytes, budget_s)
        if self._trim_size() > max_bytes:
            log.warning("%s: %d bytes after removing %d rows, still above the "
                        "%d byte cap; continuing at the next maintenance pass",
                        self.LABEL, self._trim_size(), removed, max_bytes)
        return removed
