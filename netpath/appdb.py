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
import logging
import os
import sqlite3
import threading
import time

from . import dbopen

log_module = logging.getLogger(__name__)

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

-- Absence of a row for (username, module) means no access at all. A
-- fresh install has no rows and no users beyond the seeded default admin
-- (see AppDatabase.backfill_permissions() for the upgrade case, where
-- existing accounts get full access rather than being silently locked out
-- the moment this table starts being enforced).
CREATE TABLE IF NOT EXISTS user_permissions (
    username TEXT NOT NULL,
    module   TEXT NOT NULL,
    level    TEXT NOT NULL CHECK (level IN ('read','write')),
    PRIMARY KEY (username, module)
);

CREATE TABLE IF NOT EXISTS hostnames (
    ip          TEXT PRIMARY KEY,
    hostname    TEXT,
    resolved_ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_hostnames_resolved ON hostnames(resolved_ts);

-- ASN/organization for hop addresses, alongside the reverse-DNS name above.
-- A standalone table rather than columns on hostnames: ASN assignment
-- changes far less often than a PTR record, so it wants its own, much
-- longer, TTL and its own pruning schedule.
CREATE TABLE IF NOT EXISTS asn_cache (
    ip          TEXT PRIMARY KEY,
    asn         INTEGER,
    org         TEXT,
    resolved_ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_asn_cache_resolved ON asn_cache(resolved_ts);

-- Who did what, on disk and append-only.
--
-- Sign-ins and failed sign-ins, account creation, permission changes,
-- password resets, credential storage and settings changes used to land
-- only in eventlog.py's 3,000-entry in-memory ring — lost on every
-- restart (including the one a self-update performs), a few minutes deep
-- on a busy install, and erasable outright by anyone with `debug: write`.
--
-- This table is the opposite of that ring in every way that matters: it
-- survives a restart, nothing trims it (retention here is a filesystem
-- decision, not a setting an attacker can turn down), and there is no API
-- that deletes from it. The two are complementary — the ring is for
-- watching the application work, this is for answering "who changed
-- that" a month later.
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY,
    ts       REAL NOT NULL,
    username TEXT NOT NULL,
    client   TEXT NOT NULL,
    action   TEXT NOT NULL,
    target   TEXT NOT NULL DEFAULT '',
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);

-- Housekeeping this file needs about itself. Not user-visible, and separate
-- from `settings` so a marker can never be mistaken for a setting.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Per-field caps on an audit row. Every one of these fields can carry text
# the caller chose — a username, a settings key, a device label — and an
# audit trail that can be filled with one enormous row is not one.
AUDIT_LIMITS = {"username": 64, "client": 64, "action": 64,
                "target": 256, "detail": 512}

# Never returned in one page, whatever the caller asks for.
AUDIT_MAX_LIMIT = 5000

MIGRATION_MARKER = "migrated_from_netpath_db"
# Set once the one-time `ssh` grant below has been considered, so that an
# administrator who deliberately takes the permission away is not handed it
# back on the next restart.
SSH_BACKFILL_MARKER = "ssh_permission_backfilled"
# The same, for the `admin` capability split out of `settings` in 4.37.
ADMIN_BACKFILL_MARKER = "admin_permission_backfilled"

HOSTNAME_TTL_S = 7 * 86400
ASN_TTL_S = 30 * 86400

# Global: read by more than one module, so it belongs to none of them.
GLOBAL_DEFAULTS = {
    # How often the Dashboard re-reads its tiles.
    "dashboard_refresh_s": 5,
    "dns_enabled": True,
    "dns_workers": 8,
    "dns_timeout_s": 3.0,
    "dns_cache_days": 7,
    "dns_server": "",              # blank = whatever this machine is set to use
    "dns_use_nslookup": True,
    "asn_enabled": True,
    "asn_cache_days": 30,
    "asn_server": "",              # blank = a public recursive resolver
    # Per module, because they want very different rates: the route graph is
    # cheap and wants to feel live, the flow charts are expensive aggregations
    # that barely change in a few seconds, and the debug page is watching
    # things that move by the second.
    "netpath_refresh_s": 2,
    "nodes_refresh_s": 10,
    "alerts_refresh_s": 10,
    "netflow_refresh_s": 30,
    "snmp_refresh_s": 10,
    "syslog_refresh_s": 10,
    "ipam_refresh_s": 30,          # was missing entirely; app.js's rateFor()
                                    # silently fell back to a hardcoded 2000ms
    "wireless_refresh_s": 15,
    "configrx_refresh_s": 15,
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
    "max_nodes_db_mb": 1024,       # samples accumulate; closer to flows than traps
    "max_alerts_db_mb": 128,       # alert/notification history, much lighter
    "max_snmp_db_mb": 256,
    "max_syslog_db_mb": 1024,
    "max_ipam_db_mb": 256,
    # Whether this host may replace its own code with what GitHub offers
    # (selfupdate.py). Off, because on a change-controlled network nobody
    # would choose "install whatever the internet offers, when anyone
    # presses a button" as a default — and before this existed there was no
    # way to say no. Only an administrator may turn it on.
    "updates_enabled": False,
    # Whether an SMTP password may be sent over a connection with no
    # transport security. Off: the test-email endpoint refuses `none` (and
    # any other value that is not ssl/starttls) when a password will be
    # sent, because that puts the credential on the wire in the clear.
    # Global rather than an Alerts setting so it reads as what it is — a
    # policy decision about credentials, not a mail preference.
    "smtp_allow_plain_auth": False,
    # Networks nothing in this application may ever probe: no ping sweep,
    # no SNMP guess, nothing. Comma- or space-separated CIDRs; empty means
    # no exclusions. Global rather than an IPAM or Nodes setting because it
    # is a fact about the plant, not about a module — the safety of a
    # segment full of PLCs does not depend on which tab started the scan.
    # A discovery job whose whole target is inside the list fails saying so
    # rather than quietly finding nothing.
    "never_scan_cidrs": "",
}

# Tables this file took over whole. `settings` is not among them: that table
# exists in both files and has to be split by key, because netpath.db keeps its
# own module settings.
MIGRATED_TABLES = ("users", "hostnames")


class AppDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        # dbopen.connect rather than sqlite3.connect: this file holds the
        # scrypt password hashes and the permission grants, and was being
        # created 0644 for any local account to read.
        self._conn = dbopen.connect(path)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            had_permissions_table = self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table'"
                " AND name='user_permissions'").fetchone() is not None
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        # Neither backfill runs here. On an install that predates app.db the
        # accounts they grant against are still in netpath.db at this point:
        # Service.__init__ copies them over with migrate_from() immediately
        # after this constructor returns, and then calls
        # backfill_permissions(). Running against the empty table would set
        # the ssh marker having granted nobody, permanently.
        self._needs_full_backfill = not had_permissions_table

    def backfill_permissions(self, log=None) -> None:
        """Grants the permissions an upgrade owes existing accounts. Call it
        once the `users` table is final — that is, after migrate_from() has
        had its chance to bring accounts in from a legacy netpath.db. Every
        half is idempotent (the full backfill only runs when this database
        had no user_permissions table when it was opened, and each of the
        others is an INSERT OR IGNORE behind a marker), so a second call
        does nothing.

        `log` is the application's event log when the caller has one, so an
        operator sees which accounts were granted what; the module logger
        gets the same line either way.
        """
        with self._lock:
            if self._needs_full_backfill:
                self._backfill_full_permissions()
                self._needs_full_backfill = False
            self._backfill_ssh_permission()
            self._backfill_admin_permission(log)
            self._conn.commit()

    def _backfill_admin_permission(self, log=None) -> None:
        """`admin` is new in 4.37: it is the half of `settings` that was
        never named — creating and deleting accounts, changing anyone's
        grants, resetting other people's passwords, the maintenance actions
        that delete retention data, reading the audit log, and letting this
        host replace its own code. Every existing account that holds
        `settings: write` was already able to do all of it, so taking it
        away on upgrade would lock an install out of its own user
        management. They get `admin: write`; nobody else does.

        Exactly once: the marker is written whether or not anything is
        granted, so revoking the capability afterwards sticks. A fresh
        install has no users at this point (the default admin is seeded
        later, in Service.__init__, with every module including this one),
        so it is a no-op there.

        Called from backfill_permissions(), which holds the lock, commits,
        and only runs once the accounts have been migrated in — the marker
        must not be spent on an empty table.
        """
        from . import permissions
        if self._conn.execute("SELECT 1 FROM meta WHERE key = ?",
                              (ADMIN_BACKFILL_MARKER,)).fetchone():
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)",
            (ADMIN_BACKFILL_MARKER, str(time.time())))
        granted = [row["username"] for row in self._conn.execute(
            "SELECT username FROM user_permissions WHERE module = 'settings'"
            " AND level = ? ORDER BY username COLLATE NOCASE",
            (permissions.WRITE,)).fetchall()]
        for username in granted:
            self._conn.execute(
                "INSERT OR IGNORE INTO user_permissions(username, module, level)"
                " VALUES (?,?,?)", (username, "admin", permissions.WRITE))
        if granted:
            message = ("Administrator access is now its own permission. "
                       + ", ".join(granted) + " already held Settings write, "
                       "which included it, so they keep it; every other "
                       "account starts without it.")
            log_module.info("admin backfill granted: %s", ", ".join(granted))
            if log is not None:
                from .eventlog import SYSTEM
                log.add(SYSTEM, message)

    def _backfill_full_permissions(self) -> None:
        """user_permissions is new — an install upgrading from before this
        feature existed already has accounts with (undifferentiated) full
        access to everything; enforcing permissions from this point on
        must not silently lock any of them out. Grant every existing
        account write (which implies read) on every module. A fresh
        install has no users yet at this point (the default admin account
        is seeded later, in Service.__init__, once it already sees this
        table), so this is a no-op there — nothing to backfill.

        Called from backfill_permissions(), which holds the lock and
        commits, and only once the accounts have been migrated in."""
        from . import permissions
        usernames = [row["username"] for row in
                    self._conn.execute("SELECT username FROM users").fetchall()]
        for username in usernames:
            for module in permissions.MODULES:
                self._conn.execute(
                    "INSERT OR IGNORE INTO user_permissions(username, module, level)"
                    " VALUES (?,?,?)", (username, module, permissions.WRITE))

    def _backfill_ssh_permission(self) -> None:
        """The `ssh` module (an interactive shell on a device) is newer than
        the permission table, so every existing account has no row for it
        and would be refused — which is the right default for a permission
        this sharp, but wrong for the accounts that already hold write on
        everything else. Those are administrators by any reading, and the
        SSH button took the place of one they already had, so they get it
        once, here. Everybody else starts with none, which is the entire
        point of giving a shell its own module rather than folding it into
        ConfigRX or Nodes.

        Exactly once: the marker is written whether or not anything is
        granted, so revoking the permission afterwards sticks. A fresh
        install has no users at this point (the default admin is seeded
        later, in Service.__init__, with every module), so this is a no-op
        there.

        Called from backfill_permissions(), which holds the lock and
        commits, and only once the accounts have been migrated in — the
        marker must not be spent on an empty table.
        """
        from . import permissions
        if self._conn.execute("SELECT 1 FROM meta WHERE key = ?",
                              (SSH_BACKFILL_MARKER,)).fetchone():
            return
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?,?)",
            (SSH_BACKFILL_MARKER, str(time.time())))
        # Every module that predates BOTH capabilities. `admin` has to be
        # excluded as well as `ssh`: it was appended in 4.37, so no existing
        # account has a row for it, and comparing against it would mean
        # "holds write on everything" was true of nobody and this backfill
        # silently granted ssh to no one on the upgrade path it exists for.
        others = [module for module in permissions.MODULES
                  if module not in ("ssh", "admin")]
        for row in self._conn.execute("SELECT username FROM users").fetchall():
            username = row["username"]
            grants = {grant["module"]: grant["level"] for grant in
                      self._conn.execute(
                          "SELECT module, level FROM user_permissions"
                          " WHERE username = ? COLLATE NOCASE",
                          (username,)).fetchall()}
            if all(grants.get(module) == permissions.WRITE for module in others):
                self._conn.execute(
                    "INSERT OR IGNORE INTO user_permissions(username, module,"
                    " level) VALUES (?,?,?)",
                    (username, "ssh", permissions.WRITE))

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
            self._conn.execute(
                "DELETE FROM user_permissions WHERE username = ? COLLATE NOCASE",
                (username,))
            self._conn.commit()

    # --------------------------------------------------------- permissions

    def permissions_for(self, username: str) -> dict[str, str]:
        """{module: 'read'|'write'} for whatever the account has been
        granted; a module absent from the dict means no access at all."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT module, level FROM user_permissions"
                " WHERE username = ? COLLATE NOCASE", (username,)).fetchall()
        return {row["module"]: row["level"] for row in rows}

    def usernames_with(self, module: str, level: str) -> list[str]:
        """Every account holding exactly `level` on `module`. Used to keep
        the last administrator from being reduced or removed — an install
        with no administrator left has no way back into its own user
        management short of editing the database by hand."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT username FROM user_permissions WHERE module = ?"
                " AND level = ? ORDER BY username COLLATE NOCASE",
                (module, level)).fetchall()
        return [row["username"] for row in rows]

    def set_permissions(self, username: str, grants: dict[str, str]) -> None:
        """Replaces this account's entire permission set with `grants`
        ({module: 'read'|'write'} — a module simply omitted means none).
        Called whole rather than per-module so the Users UI's one grid
        submit is one atomic change, not a flicker of intermediate states."""
        from . import permissions
        with self._lock:
            self._conn.execute(
                "DELETE FROM user_permissions WHERE username = ? COLLATE NOCASE",
                (username,))
            for module, level in grants.items():
                if module not in permissions.MODULES or level not in permissions.LEVELS:
                    continue
                self._conn.execute(
                    "INSERT INTO user_permissions(username, module, level)"
                    " VALUES (?,?,?)", (username, module, level))
            self._conn.commit()

    # ----------------------------------------------------------------- audit

    @staticmethod
    def _clip(value, key: str) -> str:
        text = "" if value is None else str(value)
        limit = AUDIT_LIMITS[key]
        return text if len(text) <= limit else text[:limit - 1] + "…"

    def audit(self, username: str, client: str, action: str,
              target: str = "", detail: str = "") -> None:
        """Record one thing somebody did. Never raises: an audit write that
        fails must not turn a successful action into a 500, and the caller
        has already done the thing by the time this runs."""
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO audit(ts, username, client, action, target,"
                    " detail) VALUES (?,?,?,?,?,?)",
                    (time.time(), self._clip(username, "username"),
                     self._clip(client, "client"), self._clip(action, "action"),
                     self._clip(target, "target"), self._clip(detail, "detail")))
                self._conn.commit()
        except sqlite3.DatabaseError:
            log_module.exception("could not write an audit row for %r", action)

    def audit_events(self, since_id: int = 0,
                     limit: int = 500) -> list[sqlite3.Row]:
        """Rows newer than `since_id`, oldest first — the same "since a
        cursor" shape the Debug page's event feed uses, so a caller polls
        by passing back the last id it saw."""
        limit = max(1, min(int(limit or 500), AUDIT_MAX_LIMIT))
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM audit WHERE id > ? ORDER BY id LIMIT ?",
                (int(since_id or 0), limit)).fetchall()

    def audit_last_id(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS n FROM audit").fetchone()
        return int(row["n"] or 0)

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

    def search_hostnames(self, query: str, limit: int = 50) -> list[sqlite3.Row]:
        """Cached names — from PTR lookups on hop, flow, syslog and IPAM
        addresses alike — whose hostname or IP contains `query`. The forward
        half of what this cache is for: it exists to turn an address into a
        name for display, but the same table answers "what's the IP for this
        name" just as well, and an IP substring is worth matching here too
        since a caller may already half-know the address."""
        with self._lock:
            return self._conn.execute(
                "SELECT ip, hostname FROM hostnames WHERE hostname LIKE ? OR ip LIKE ?"
                " ORDER BY (hostname LIKE ?) DESC, hostname LIMIT ?",
                (f"%{query}%", f"%{query}%", f"{query}%", limit)).fetchall()

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

    # -------------------------------------------------------------- asn_cache

    def asn_info(self, ips) -> dict[str, tuple[int | None, str | None]]:
        """Cached (asn, org) per address. A missing key means "not looked up
        yet"; a (None, None) value means "looked up, nothing global/found"."""
        ips = [ip for ip in set(ips) if ip]
        if not ips:
            return {}
        found: dict[str, tuple[int | None, str | None]] = {}
        with self._lock:
            for chunk in range(0, len(ips), 400):
                batch = ips[chunk:chunk + 400]
                marks = ",".join("?" * len(batch))
                rows = self._conn.execute(
                    f"SELECT ip, asn, org FROM asn_cache WHERE ip IN ({marks})",
                    batch).fetchall()
                for row in rows:
                    found[row["ip"]] = (row["asn"], row["org"])
        return found

    def unknown_asn_ips(self, ips, cache_ttl_s: float | None = None) -> list[str]:
        """Of the addresses given, those with no fresh cached ASN answer.
        Same shape as unknown_ips(), against the longer-lived asn_cache."""
        ips = [ip for ip in dict.fromkeys(ips) if ip]
        if not ips:
            return []
        cutoff = time.time() - (cache_ttl_s or ASN_TTL_S)
        known: set[str] = set()
        with self._lock:
            for start in range(0, len(ips), 400):
                batch = ips[start:start + 400]
                marks = ",".join("?" * len(batch))
                rows = self._conn.execute(
                    f"SELECT ip FROM asn_cache WHERE ip IN ({marks})"
                    f" AND resolved_ts >= ?", (*batch, cutoff)).fetchall()
                known.update(row["ip"] for row in rows)
        return [ip for ip in ips if ip not in known]

    def set_asn(self, ip: str, asn: int | None, org: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO asn_cache(ip, asn, org, resolved_ts) VALUES (?,?,?,?)"
                " ON CONFLICT(ip) DO UPDATE SET asn=excluded.asn,"
                " org=excluded.org, resolved_ts=excluded.resolved_ts",
                (ip, asn, org, time.time()),
            )
            self._conn.commit()

    def prune_asn_cache(self, older_than_days: float) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM asn_cache WHERE resolved_ts < ?", (cutoff,))
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


def write_meta(path: str, key: str, value: str) -> None:
    """Set one housekeeping marker through a connection of this call's own.

    For the one caller that has no live AppDatabase to go through:
    selfupdate stops the service — which closes app.db — before it replaces
    the package directory, and still has to record what it installed.
    """
    if not path:
        return
    conn = dbopen.connect(path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,"
                     " value TEXT)")
        conn.execute("INSERT INTO meta(key, value) VALUES (?,?)"
                     " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, str(value)))
        conn.commit()
    finally:
        conn.close()


def write_audit(path: str, username: str, client: str, action: str,
                target: str = "", detail: str = "") -> None:
    """Record one audit row through a connection of this call's own.

    Same reason as write_meta, for the entry that matters most: a completed
    self-update. `apply()` closes every database before it replaces the
    package, so the handle the service was using is gone by the time there
    is an outcome to record — and `AppDatabase.audit()` swallowed the
    resulting ProgrammingError, which meant "this host replaced its own
    code" was the one action the audit log never kept, and every successful
    update wrote a traceback to the service log instead.

    Never raises, for the same reason `audit()` does not: the update has
    already happened, and losing the row must not turn it into a 500.
    """
    if not path:
        return
    try:
        conn = dbopen.connect(path)
        try:
            conn.execute(
                "INSERT INTO audit(ts, username, client, action, target,"
                " detail) VALUES (?,?,?,?,?,?)",
                (time.time(), username[:AUDIT_LIMITS["username"]],
                 client[:AUDIT_LIMITS["client"]],
                 action[:AUDIT_LIMITS["action"]],
                 target[:AUDIT_LIMITS["target"]],
                 detail[:AUDIT_LIMITS["detail"]]))
            conn.commit()
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        log_module.exception("could not write an audit row for %r", action)


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

    source = dbopen.connect(legacy_path)
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
