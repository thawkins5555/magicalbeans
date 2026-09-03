"""Space reclamation for the application's SQLite files without ``VACUUM``.

``VACUUM`` rewrites the whole file while holding an exclusive lock, and on a
connection shared between threads it cannot run outside the module lock
without interleaving with other statements.  The review measured multi-
second stalls on every trim.  Instead each database is switched to
``auto_vacuum=INCREMENTAL`` once, and callers run ``reclaim`` after their
prune/trim transaction: it frees pages in short steps inside the lock,
releasing it between steps so writers are never blocked for more than one
step, then truncates the WAL.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time

log = logging.getLogger(__name__)

INCREMENTAL = 2


# An existing database is converted at open only when it is at most this
# many pages — about 8 MB at SQLite's default page size, which converts in
# well under a tenth of a second. Anything larger is left for reclaim() to
# convert during maintenance. The conversion is a whole-file VACUUM, and
# seven of them running while an operator waits for the window is how
# starting the application came to take half a minute on a real fleet's data.
CONVERT_AT_OPEN_PAGES = 2000


def enable_incremental_vacuum(conn: sqlite3.Connection, label: str = "",
                              max_pages: int | None = CONVERT_AT_OPEN_PAGES) -> bool:
    """Switch ``conn``'s database to incremental auto-vacuum.

    A new (empty) database takes the pragma for free.  An existing database
    created with ``auto_vacuum=NONE`` needs one ``VACUUM`` to rebuild its
    page map, which rewrites the whole file — so by default that is done
    only for a database small enough for it to be imperceptible, and
    ``reclaim`` (which runs from the prune and trim paths, on the
    maintenance timer rather than at startup) converts the rest by passing
    ``max_pages=None``.

    Returns True when the database is in incremental mode afterwards. False
    means "not converted yet", which costs nothing: ``reclaim`` still
    checkpoints, and the next maintenance pass tries again.
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
            # brand-new file needs the VACUUM for the setting to stick. It is
            # instant when there is nothing in the file; only a database with
            # real content in it is worth mentioning in the log.
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
    # prune and trim paths — the maintenance timer, not startup — so the
    # one-time whole-file rewrite lands where a pause is expected. Under the
    # lock, like every other statement on this shared connection.
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
        # fair: without this the loop reacquires it before a waiting writer
        # is ever scheduled, so "the lock is released between steps" bought
        # the writer nothing.
        time.sleep(0)
    with lock:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.DatabaseError:
            pass
    return freed
