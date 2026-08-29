"""The application's own database: settings, accounts and the shared name cache.

Everything here crosses module boundaries or belongs to the application rather
than to one of its collectors. The three data files — netpath.db, flows.db and
syslog.db — hold records and their own module's settings, and nothing else.

What lives here and why:

* **Global settings.** The Settings tab holds what more than one module reads:
  reverse DNS, refresh intervals, the web listener, session lifetimes and the
  per-database size caps. Module settings stay with their module.
* **Users.** Accounts are the application's, not the traceroute module's. They
  also want a different backup policy from network data: small, precious, and
  nothing you would ever want trimmed by a size cap.
* **The reverse-DNS cache.** NetPath names hop addresses from it, NetFlow names
  flow endpoints and Syslog names sending devices. It followed the `dns_*`
  settings into the global scope.

Sessions and login throttling are deliberately absent: both are in-memory in
auth.py, so a restart logs everyone out. That is the safe default and keeps
tokens out of any file.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS users (
    username     TEXT PRIMARY KEY,
    password     TEXT NOT NULL,          -- a hash; never the password itself
    created_ts   REAL NOT NULL,
    updated_ts   REAL NOT NULL,
    last_login   REAL,
    must_change  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hostnames (
    ip          TEXT PRIMARY KEY,
    hostname    TEXT,
    resolved_ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_hostnames_resolved ON hostnames(resolved_ts);

-- Housekeeping this file needs about itself. Not user-visible, and separate
-- from `settings` so a marker can never be mistaken for a setting.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

MIGRATION_MARKER = "migrated_from_netpath_db"

HOSTNAME_TTL_S = 7 * 86400

# Global: read by more than one module, so it belongs to none of them.
GLOBAL_DEFAULTS = {
    "dns_enabled": True,
    "dns_workers": 8,
    "dns_timeout_s": 3.0,
    "dns_cache_days": 7,
    "dns_server": "",              # blank = whatever this machine is set to use
    "dns_use_nslookup": True,
    # Per module, because they want very different rates: the route graph is
    # cheap and wants to feel live, the flow charts are expensive aggregations
    # that barely change in a few seconds, and the debug page is watching
    # things that move by the second.
    "netpath_refresh_s": 2,
    "netflow_refresh_s": 30,
    "syslog_refresh_s": 10,
    "debug_refresh_s": 1,
    "web_host": "0.0.0.0",
    "web_port": 8443,
    "web_cert": "",
    "web_key": "",
    # Idle timeout: no activity for this long signs the session out. Short by
    # default, because this is graded on presence, not on the tab being open
    # — see SessionStore.touch() in auth.py. Absolute: signed out this long
    # after login regardless of activity, as a hard ceiling.
    "session_idle_minutes": 10,
    "session_max_hours": 12,
    "max_trace_db_mb": 512,
    "max_flow_db_mb": 2048,
    "max_syslog_db_mb": 1024,
}

# Tables this file took over whole. `settings` is not among them: that table
# exists in both files and has to be split by key, because netpath.db keeps its
# own module settings.
MIGRATED_TABLES = ("users", "hostnames")


class AppDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES (?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value))
            self._conn.commit()

    # -------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = dict(GLOBAL_DEFAULTS)
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
        """Store the global keys. Anything else in the dict is ignored, so a
        merged settings dict can be handed to this and to Database in turn and
        each takes only what it owns."""
        with self._lock:
            for key, value in values.items():
                if key not in GLOBAL_DEFAULTS:
                    continue
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)),
                )
            self._conn.commit()

    # ----------------------------------------------------------------- users

    def users(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT username, created_ts, updated_ts, last_login, must_change"
                " FROM users ORDER BY username COLLATE NOCASE").fetchall()

    def user(self, username: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                (username,)).fetchone()

    def user_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM users").fetchone()["n"]

    def add_user(self, username: str, password_hash: str,
                 must_change: bool = True) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO users(username, password, created_ts, updated_ts,"
                " must_change) VALUES (?,?,?,?,?)",
                (username, password_hash, now, now, 1 if must_change else 0))
            self._conn.commit()

    def set_password(self, username: str, password_hash: str,
                     must_change: bool = False) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE users SET password = ?, updated_ts = ?, must_change = ?"
                " WHERE username = ? COLLATE NOCASE",
                (password_hash, time.time(), 1 if must_change else 0, username))
            self._conn.commit()

    def touch_login(self, username: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE users SET last_login = ? WHERE username = ? COLLATE NOCASE",
                (time.time(), username))
            self._conn.commit()

    def remove_user(self, username: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM users WHERE username = ? COLLATE NOCASE", (username,))
            self._conn.commit()

    # ------------------------------------------------------------- hostnames

    def hostnames(self, ips) -> dict[str, str | None]:
        """Cached reverse-DNS names. A missing key means "not looked up yet";
        a None value means "looked up, no PTR record"."""
        ips = [ip for ip in set(ips) if ip]
        if not ips:
            return {}
        found: dict[str, str | None] = {}
        with self._lock:
            for chunk in range(0, len(ips), 400):
                batch = ips[chunk:chunk + 400]
                marks = ",".join("?" * len(batch))
                rows = self._conn.execute(
                    f"SELECT ip, hostname FROM hostnames WHERE ip IN ({marks})", batch
                ).fetchall()
                for row in rows:
                    found[row["ip"]] = row["hostname"]
        return found

    def set_hostname(self, ip: str, hostname: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO hostnames(ip, hostname, resolved_ts) VALUES (?,?,?)"
                " ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname,"
                " resolved_ts=excluded.resolved_ts",
                (ip, hostname, time.time()),
            )
            self._conn.commit()

    def cache_stats(self) -> dict:
        """How much of the cache is filled. The pending count needs the hop
        table, which is in another file now, so the caller supplies it."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n, SUM(hostname IS NOT NULL) AS named"
                " FROM hostnames").fetchone()
        return {"cached": row["n"] or 0, "named": row["named"] or 0}

    def unknown_ips(self, ips, cache_ttl_s: float | None = None) -> list[str]:
        """Of the addresses given, those with no fresh cached answer.

        This replaces the old join against the hops table: the candidates come
        from whichever module wants them named, and only the filtering happens
        here. Order is preserved so the caller's priority survives.
        """
        ips = [ip for ip in dict.fromkeys(ips) if ip]
        if not ips:
            return []
        cutoff = time.time() - (cache_ttl_s or HOSTNAME_TTL_S)
        known: set[str] = set()
        with self._lock:
            for start in range(0, len(ips), 400):
                batch = ips[start:start + 400]
                marks = ",".join("?" * len(batch))
                rows = self._conn.execute(
                    f"SELECT ip FROM hostnames WHERE ip IN ({marks})"
                    f" AND resolved_ts >= ?", (*batch, cutoff)).fetchall()
                known.update(row["ip"] for row in rows)
        return [ip for ip in ips if ip not in known]

    def clear_hostnames(self) -> int:
        """Drop the cache so every address is looked up again."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM hostnames")
            self._conn.commit()
        return cur.rowcount or 0

    def prune_hostnames(self, older_than_days: float) -> int:
        """Forget entries nothing has refreshed. Names do change eventually."""
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM hostnames WHERE resolved_ts < ?", (cutoff,))
            self._conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------------------------ size

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total


# ----------------------------------------------------------------- migration

def migrate_from(app_db: AppDatabase, legacy_path: str, log=None) -> dict:
    """Move settings, users and the name cache out of an older netpath.db.

    Runs once, on the first launch of a build that has this file. The copy is
    committed and verified before anything is dropped from the source, so an
    interruption at any point leaves a working install: either the old file
    still has everything, or the new one does.

    Returns a report of what moved; an empty dict means there was nothing to do.
    """
    def note(message: str) -> None:
        if log is not None:
            from .eventlog import SYSTEM
            log.add(SYSTEM, message)

    if not os.path.exists(legacy_path):
        return {}
    if app_db.meta(MIGRATION_MARKER):
        return {}          # already done
    # No marker but a populated file means an earlier attempt was interrupted.
    # Every step below is INSERT OR REPLACE, so running it again is safe and is
    # the only way a half-finished migration ever completes.

    source = sqlite3.connect(legacy_path)
    source.row_factory = sqlite3.Row
    try:
        present = {row["name"] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        movable = [table for table in MIGRATED_TABLES if table in present]
        has_settings = "settings" in present
        if not movable and not has_settings:
            return {}

        counts: dict[str, int] = {}
        global_keys: list[str] = []

        with app_db._lock:
            target = app_db._conn

            for table in movable:
                rows = source.execute(f"SELECT * FROM {table}").fetchall()
                counts[table] = len(rows)
                if not rows:
                    continue
                columns = rows[0].keys()
                marks = ",".join("?" * len(columns))
                target.executemany(
                    f"INSERT OR REPLACE INTO {table}"
                    f" ({','.join(columns)}) VALUES ({marks})",
                    [tuple(row[column] for column in columns) for row in rows])

            # Settings are split, not moved: the global keys come here, the
            # NetPath keys stay where they are, and anything belonging to
            # neither is a leftover from an older build and is dropped.
            if has_settings:
                rows = source.execute("SELECT key, value FROM settings").fetchall()
                keep = [row for row in rows if row["key"] in GLOBAL_DEFAULTS]
                global_keys = [row["key"] for row in keep]
                if keep:
                    target.executemany(
                        "INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)",
                        [(row["key"], row["value"]) for row in keep])
                counts["settings"] = len(keep)

            target.commit()

            # Verify the copy landed before destroying anything at the source.
            for table in movable:
                actual = target.execute(
                    f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
                if actual < counts[table]:
                    note(f"Migration to app.db incomplete for {table} "
                         f"({actual} of {counts[table]}); nothing has been "
                         f"removed from netpath.db.")
                    return counts
            if global_keys:
                marks = ",".join("?" * len(global_keys))
                actual = target.execute(
                    f"SELECT COUNT(*) AS n FROM settings WHERE key IN ({marks})",
                    global_keys).fetchone()["n"]
                if actual < len(global_keys):
                    note(f"Migration of settings to app.db incomplete "
                         f"({actual} of {len(global_keys)}); nothing has been "
                         f"removed from netpath.db.")
                    return counts

        moved = ", ".join(f"{n} {table}" for table, n in sorted(counts.items()) if n)
        note(f"Moved application data to app.db: {moved or 'nothing to move'}. "
             f"netpath.db now holds destinations, traces and NetPath settings.")

        for table in movable:
            source.execute(f"DROP TABLE IF EXISTS {table}")
        if global_keys:
            marks = ",".join("?" * len(global_keys))
            source.execute(f"DELETE FROM settings WHERE key IN ({marks})",
                           global_keys)
        source.commit()
        source.execute("VACUUM")
        app_db.set_meta(MIGRATION_MARKER, str(time.time()))
        return counts
    finally:
        source.close()
