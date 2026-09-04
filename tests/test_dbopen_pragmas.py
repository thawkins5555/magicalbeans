"""Tier 0 fix T0-5: dbopen.connect() sets busy_timeout, cache_size and
mmap_size centrally, so every one of the app's ten SQLite files gets a
sane wait-under-contention instead of an immediate SQLITE_BUSY, without
each database module having to remember to ask for it itself."""
import os
import sqlite3

from _paths import tmpdir  # noqa: F401  (repo root on sys.path)

from netpath import dbopen

TMP = tmpdir("dbopen_pragmas_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def pragma(conn: sqlite3.Connection, name: str):
    return conn.execute(f"PRAGMA {name}").fetchone()[0]


# --------------------------------------------------- 1. a real file on disk

path = os.path.join(TMP, "one.db")
conn = dbopen.connect(path)
try:
    check("busy_timeout is set to a few seconds, not the SQLite default of 0",
          pragma(conn, "busy_timeout") == 5000, pragma(conn, "busy_timeout"))
    check("cache_size is raised above SQLite's small stock default (-2000)",
          pragma(conn, "cache_size") == -20000, pragma(conn, "cache_size"))
    check("mmap_size is set to a real ceiling, not left at 0",
          pragma(conn, "mmap_size") == 268435456, pragma(conn, "mmap_size"))
    # dbopen.connect's own responsibility, unaffected by the new pragmas.
    check("journal_mode is still WAL",
          str(pragma(conn, "journal_mode")).lower() == "wal",
          pragma(conn, "journal_mode"))
finally:
    conn.close()

# ------------------------------------- 2. busy_timeout actually makes a
#                                          second writer wait, not throw

path2 = os.path.join(TMP, "two.db")
holder = dbopen.connect(path2)
holder.execute("CREATE TABLE t(x)")
holder.execute("BEGIN IMMEDIATE")
holder.execute("INSERT INTO t VALUES (1)")

waiter = dbopen.connect(path2)
started = __import__("time").time()
try:
    # The holder's write transaction has the write lock; without
    # busy_timeout this raises "database is locked" immediately (well under
    # a millisecond). With it, sqlite3 polls internally until either it
    # succeeds or the timeout elapses -- proven by checking this call takes
    # meaningfully longer than instantaneous before it (eventually) still
    # fails, since the holder never commits.
    waiter.execute("BEGIN IMMEDIATE")
    ok = False
    reason = "unexpectedly acquired the write lock"
except sqlite3.OperationalError as exc:
    elapsed = __import__("time").time() - started
    ok = elapsed >= 1.0 and "locked" in str(exc).lower()
    reason = f"elapsed={elapsed:.2f}s exc={exc}"
check("a second writer waits out busy_timeout instead of failing instantly",
      ok, reason)
holder.close()
waiter.close()

# ---------------------------------------------- 3. an in-memory connection
#                                                    is not broken by any of this

mem = dbopen.connect(":memory:")
try:
    check(":memory: still gets the same pragmas (harmless, nothing contends)",
          pragma(mem, "busy_timeout") == 5000, pragma(mem, "busy_timeout"))
    mem.execute("CREATE TABLE t(x)")
    mem.execute("INSERT INTO t VALUES (1)")
    check(":memory: is still fully usable",
          mem.execute("SELECT x FROM t").fetchone()[0] == 1)
finally:
    mem.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
