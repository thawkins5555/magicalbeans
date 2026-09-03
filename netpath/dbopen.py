"""One place to open a SQLite file with the modes the application relies on.

Every database module used to call ``sqlite3.connect(path,
check_same_thread=False)`` directly, which leaves the file (and its
``-wal``/``-shm`` companions) with the process umask — typically 0644, so any
local account can read stored settings, DPAPI blobs, syslog and config
backups.  ``connect`` narrows the file modes to the owner on POSIX hosts and
returns the connection unchanged otherwise, so callers keep their existing
pragma and schema setup.
"""
from __future__ import annotations

import os
import sqlite3
import stat


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
