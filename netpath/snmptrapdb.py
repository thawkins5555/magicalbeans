"""Storage for received SNMP traps.

No FTS5, unlike syslog: traps are rarer and the useful queries are on indexed
columns, so a LIKE over `varbind_text` inside the time window reads a handful
of rows. Varbinds are one JSON column: read whole, once, never joined.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time

from .sqlitebase import (LIKE_ESCAPE, SqliteStore, hist_add, hist_buckets,
                         hist_from_rollup, like_contains)

log = logging.getLogger(__name__)

# One prune batch, in rows, and the band the adaptation may move it inside.
#
# Its own figure rather than sqlitebase's TRIM_CHUNK, for syslogdb's reason
# and with the opposite answer: a trap's row is heavy (its varbinds travel
# with it) and `traps` carries five secondary indexes, so a batch's commit is
# dear enough that the sweep costs the same either way and the smaller batch
# is simply kinder to whoever is reading. Back to back on 1,020,000 traps,
# half past the cutoff, with bench_prune's reader:
#
#     unbatched         2.8 s, one hold of 2,791 ms
#      2,000 rows       6.8 s, 255 holds, worst 242 ms, reader stalled 227 ms
#     10,000 rows       6.6 s,  51 holds, worst 289 ms, reader stalled 404 ms
#
# The band matters as much as the figure. _delete_batches only DOUBLES a batch
# that held the lock for under a quarter of TRIM_LOCK_TARGET_S, and only
# halves one that held it for longer than the target, so a first batch landing
# between the two pins the size for the whole sweep: the start is the
# operating point, not a seed. A store whose batches come off the page cache
# can otherwise double its way up until one of them holds the lock for a
# second or more, which is what the maximum is for.
PRUNE_CHUNK = 2_000
PRUNE_CHUNK_MIN = 1_000
PRUNE_CHUNK_MAX = 10_000

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

-- The SNMPv3 trap users' authentication passwords. Its own table, not the
-- JSON `settings` row, for alertsdb.smtp_credential's reason: a DPAPI blob
-- is not a string/number, and a row that /api/config serves to every
-- account with `snmp: read` is the wrong place for a password the rest of
-- the product encrypts (CREDENTIAL-SECURITY.md s11). The name and protocol
-- stay in the settings row, which is what the Settings textarea shows and
-- edits.
CREATE TABLE IF NOT EXISTS trap_v3_users (
    name          TEXT PRIMARY KEY,
    auth_proto    TEXT,
    auth_pass_enc BLOB
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
    # SNMPv3 users, one per line. Stored, and returned by settings(), as
    # "name / SHA": the password is kept encrypted in trap_v3_users and
    # never travels in this value. A save may carry "name / SHA / password"
    # to set or change one; see save_settings below.
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


V3_NO_CREDENTIAL_STORE = (
    "This machine cannot store an SNMPv3 trap password: it is not Windows "
    "and no portable secret store passphrase is configured "
    "(NETPATH_SECRET_PASSPHRASE_FILE or NETPATH_SECRET_PASSPHRASE — see "
    "CREDENTIAL-SECURITY.md). Leave the password off the line to keep "
    "whatever is already stored for that user.")


def parse_v3_user_lines(text) -> list[tuple[str, str, str | None]]:
    """The textarea's lines as (name, protocol, password) triples.

    A password of None means the line carried none — "keep whatever is
    stored for this name", which is what every line looks like once
    settings() has been through it. A password of nothing but asterisks
    reads the same way, so an operator who retypes a mask they saw
    somewhere does not blank the credential with it.
    """
    users = []
    for line in str(text or "").splitlines():
        parts = [part.strip() for part in line.split("/")]
        if not parts[0]:
            continue
        proto = parts[1] if len(parts) > 1 else ""
        password = parts[2] if len(parts) > 2 else ""
        if not password or set(password) == {"*"}:
            password = None
        users.append((parts[0], proto, password))
    return users


def v3_user_lines(users) -> str:
    """The triples back as textarea text, with no password in it."""
    return "\n".join(f"{name} / {proto}" if proto else name
                     for name, proto, _ in users)


class SnmpTrapDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "snmptraps.db"
    TRIM_TABLE = "traps"
    OLDEST_TS_SQL = "SELECT MIN(ts) FROM traps"
    TRIM_FLOOR = 5000
    # Set by prune() when its budget ran out before the backlog did, the same
    # flag netpath.db and netpath.flowdb raise for the same reason.
    last_prune_incomplete = False

    def __init__(self, path: str):
        self.store_raw = False
        super().__init__(path)

    def _after_open(self) -> None:
        self._migrate_v3_passwords()

    # -------------------------------------------------------------- v3 users

    def settings(self) -> dict:
        """The stored settings, with no v3 password in them.

        `v3_users` comes back as "name / SHA" lines whatever is stored, and
        `v3_users_stored` says how many of those names have a password on
        file, so the Settings dialog can tell an operator a credential
        exists without being shown it. /api/config serves this dict to every
        account holding `snmp: read`, which is why the password never joins
        it.
        """
        values = super().settings()
        users = parse_v3_user_lines(values.get("v3_users", ""))
        values["v3_users"] = v3_user_lines(users)
        with self._lock:
            rows = self._conn.execute(
                "SELECT name FROM trap_v3_users"
                " WHERE auth_pass_enc IS NOT NULL").fetchall()
        stored = {row["name"] for row in rows}
        # A password still in the settings row counts too: on a host with no
        # credential store _migrate_v3_passwords cannot encrypt it yet, and
        # the receiver is nonetheless authenticating traps with it.
        stored.update(name for name, _, password in users if password)
        values["v3_users_stored"] = len(stored)
        return values

    def save_settings(self, values: dict) -> None:
        """Store the settings, routing any v3 password to trap_v3_users.

        A line carrying a password sets or replaces that user's; a line
        without one keeps what is stored for that name; a name no longer
        listed loses its stored password with its line. Only names and
        protocols reach the settings row.
        """
        if "v3_users" in values:
            users = parse_v3_user_lines(values["v3_users"])
            # Stripped in the caller's own dict, and before anything can
            # fail: `values` is the live settings dict the service hands
            # /api/config, so a save this host refuses must not leave the
            # typed password sitting in it either.
            values["v3_users"] = v3_user_lines(users)
            self._write_v3_users(users)
        super().save_settings(values)

    def v3_user_secret(self, name: str) -> str | None:
        """A v3 user's authentication password, or None.

        The trap decoder's secret source (snmptrapd wires it in), and the
        only way back to a stored password: nothing serves it to a caller
        outside this process.
        """
        name = str(name)
        with self._lock:
            row = self._conn.execute(
                "SELECT auth_pass_enc FROM trap_v3_users WHERE name = ?",
                (name,)).fetchone()
        if row is not None and row["auth_pass_enc"]:
            from . import dpapi
            try:
                return dpapi.unprotect(bytes(row["auth_pass_enc"])).decode("utf-8")
            except (dpapi.DpapiUnavailable, UnicodeDecodeError) as exc:
                log.warning("netpath.snmptrapdb: the stored SNMPv3 password "
                            "for trap user %r could not be decrypted (%s); "
                            "traps from that user cannot be verified until it "
                            "is entered again", name, exc)
                return None
        return self._legacy_v3_password(name)

    def _legacy_v3_password(self, name: str) -> str | None:
        """The password out of the settings row, on a database whose
        migration could not run because this host has no credential store.
        Unchanged from where it has always been — settings() still refuses
        to hand it to the API — and encrypted by the first open that can."""
        for stored, _, password in parse_v3_user_lines(self._stored_v3_users()):
            if stored == name and password:
                return password
        return None

    def _stored_v3_users(self) -> str:
        """The v3_users settings value as it is on disk, passwords and all."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = 'v3_users'").fetchone()
        if row is None:
            return ""
        try:
            return str(json.loads(row["value"]) or "")
        except (ValueError, TypeError):
            return ""

    def _set_v3_user(self, name: str, proto: str, password_enc) -> None:
        with self._lock:
            if password_enc is None:
                self._conn.execute(
                    "INSERT INTO trap_v3_users(name, auth_proto) VALUES (?,?)"
                    " ON CONFLICT(name) DO UPDATE SET"
                    " auth_proto = excluded.auth_proto",
                    (name, proto))
            else:
                self._conn.execute(
                    "INSERT INTO trap_v3_users(name, auth_proto, auth_pass_enc)"
                    " VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET"
                    " auth_proto = excluded.auth_proto,"
                    " auth_pass_enc = excluded.auth_pass_enc",
                    (name, proto, password_enc))
            self._commit_durable()

    def _write_v3_users(self, users) -> None:
        """Every password encrypted before anything is written, so a host
        that cannot encrypt refuses the save whole rather than storing half
        of it."""
        from . import dpapi

        encrypted = []
        for name, proto, password in users:
            if password is None:
                encrypted.append((name, proto, None))
                continue
            if not dpapi.available():
                raise ValueError(V3_NO_CREDENTIAL_STORE)
            try:
                encrypted.append(
                    (name, proto, dpapi.protect(password.encode("utf-8"))))
            except dpapi.DpapiUnavailable as exc:
                raise ValueError(str(exc)) from exc

        for name, proto, blob in encrypted:
            self._set_v3_user(name, proto, blob)

        listed = {name for name, _, _ in users}
        with self._lock:
            rows = self._conn.execute("SELECT name FROM trap_v3_users").fetchall()
            # One statement per departing name rather than an IN list: the
            # textarea has no length limit and SQLite's variable ceiling is
            # not knowable here (sqlitebase.id_chunks' note), and a v3 user
            # list is a handful of rows.
            for row in rows:
                if row["name"] not in listed:
                    self._conn.execute(
                        "DELETE FROM trap_v3_users WHERE name = ?", (row["name"],))
            self._conn.commit()

    def _migrate_v3_passwords(self) -> None:
        """Move a plaintext password out of the settings row into
        trap_v3_users, encrypted, and blank it out of the row.

        Runs at every open and does nothing once nothing is left in the
        clear, which is after the first open on a host that can encrypt. A
        host that cannot keeps the row it has always had: blanking it would
        stop the receiver verifying traps it verifies today, and there is
        nowhere else to put the password until a credential store exists.
        """
        users = parse_v3_user_lines(self._stored_v3_users())
        if not any(password for _, _, password in users):
            return

        from . import dpapi
        if not dpapi.available():
            log.warning("netpath.snmptrapdb: the SNMPv3 trap users' passwords "
                        "are still stored in the clear because this host has "
                        "no credential store; configure one and restart to "
                        "have them encrypted (see CREDENTIAL-SECURITY.md)")
            return
        try:
            blobs = [(name, proto,
                      None if password is None
                      else dpapi.protect(password.encode("utf-8")))
                     for name, proto, password in users]
        except dpapi.DpapiUnavailable as exc:
            log.warning("netpath.snmptrapdb: could not encrypt the stored "
                        "SNMPv3 trap passwords (%s); they stay as they are", exc)
            return

        for name, proto, blob in blobs:
            self._set_v3_user(name, proto, blob)
        with self._lock:
            self._conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'v3_users'",
                (json.dumps(v3_user_lines(users)),))
            self._commit_durable()
        log.info("netpath.snmptrapdb: encrypted %d stored SNMPv3 trap "
                 "password(s) and removed them from the settings row",
                 sum(1 for _, _, password in users if password))

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
            clauses.append(f"source LIKE ? {LIKE_ESCAPE}")
            params.append(like_contains(filters["source"]))
        if filters.get("oid"):
            clauses.append(f"(trap_oid LIKE ? {LIKE_ESCAPE}"
                           f" OR trap_name LIKE ? {LIKE_ESCAPE})")
            params.append(like_contains(filters["oid"]))
            params.append(like_contains(filters["oid"]))
        if filters.get("community"):
            clauses.append(f"community LIKE ? {LIKE_ESCAPE}")
            params.append(like_contains(filters["community"]))
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
        start, bucket_s, slots, buckets = hist_buckets(t0, t1, bucket_s)

        plain = not any(filters.get(key) for key in
                        ("text", "version", "kind", "source", "oid", "community"))
        with self._lock:
            if plain and bucket_s >= 3600 and bucket_s % 3600 == 0:
                rows = self._conn.execute(
                    "SELECT hour, severity, n FROM trap_counts"
                    " WHERE hour >= ? AND hour <= ?", (start, t1)).fetchall()
                return hist_from_rollup(buckets, slots, start, bucket_s, rows,
                                        filters.get("severity"))

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
                hist_add(buckets, slots, row["slot"], row["severity"], row["n"])
        return buckets

    def traps_since(self, last_id: int, limit: int | None = 500) -> list[sqlite3.Row]:
        """Rows newer than last_id, oldest first.

        By id, not by ts: a device with a bad clock can file a trap
        timestamped in the past, and its rowid is still monotonic. `limit` is
        the caller's per-tick budget; None means everything newer.
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

    def _batched_delete_traps(self, where: str, params, low: int, cut: int,
                              deadline: float) -> tuple[int, int]:
        """Delete the ids in [low, cut) matching `where`, a batch per lock
        hold.

        The id range only chunks the sweep - every batch still carries
        `where`, so an exporter with a wrong clock cannot make a prune drop
        the wrong rows. syslogdb._batched_delete_logs' shape and its
        measurements: chunking by rows-gone instead cost a third again in
        total and three times the worst lock hold.
        """
        def delete(low_id: int, upper: int) -> int:
            cursor = self._conn.execute(
                f"DELETE FROM traps WHERE id >= ? AND id < ? AND {where}",
                (low_id, upper, *params))
            return cursor.rowcount or 0

        return self._delete_batches(
            low, cut, deadline, delete, chunk=PRUNE_CHUNK,
            chunk_min=PRUNE_CHUNK_MIN, chunk_max=PRUNE_CHUNK_MAX)

    def prune(self, retention_days: float, max_rows: int,
              budget_s: float | None = None) -> int:
        """Age out traps, then cap the row count.

        Batched in adaptive, lock-bounded chunks rather than one DELETE per
        stage: every read on this store takes the same single lock the delete
        takes, so an unbatched sweep froze the trap pages - and the
        receiver's own writer - for as long as the whole DELETE ran.

        Which rows go is unchanged.

        `budget_s` is None by default, and so by default there is no
        deadline: this prune never had one, and cutting a retention sweep
        short is a retention change, not the latency change this is. A caller
        that must bound the sweep passes one, and last_prune_incomplete then
        says the backlog is unfinished.
        """
        removed = 0
        cutoff = time.time() - retention_days * 86400
        deadline = (float("inf") if budget_s is None
                    else time.monotonic() + budget_s)
        incomplete = False

        with self._lock:
            bounds = self._conn.execute(
                "SELECT MIN(id) AS lo, MAX(id) AS hi FROM traps WHERE ts < ?",
                (cutoff,)).fetchone()
        low = bounds["lo"]
        if low is not None:
            cut = bounds["hi"] + 1
            gone, reached = self._batched_delete_traps(
                "ts < ?", (cutoff,), low, cut, deadline)
            removed += gone
            incomplete = incomplete or reached < cut

        # trap_counts is one row per hour per severity and has no id to chunk
        # on: a short lock hold of its own, not a share of the sweep's.
        with self._lock:
            self._conn.execute("DELETE FROM trap_counts WHERE hour < ?", (cutoff,))
            self._conn.commit()

        if max_rows:
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM traps").fetchone()["n"]
            over = total - max_rows
            if over > 0:
                # Not an id range: this stage picks by ts, and a trap carries
                # the sender's clock. Chunked by how many have gone, which is
                # the same set the single DELETE picked.
                def by_ts(low_n: int, upper: int) -> int:
                    cursor = self._conn.execute(
                        "DELETE FROM traps WHERE id IN (SELECT id FROM traps"
                        " ORDER BY ts ASC LIMIT ?)", (upper - low_n,))
                    return cursor.rowcount or 0

                gone, reached = self._delete_batches(
                    0, over, deadline, by_ts, chunk=PRUNE_CHUNK,
                    chunk_min=PRUNE_CHUNK_MIN, chunk_max=PRUNE_CHUNK_MAX)
                removed += gone
                incomplete = incomplete or reached < over

        self.last_prune_incomplete = incomplete
        if incomplete:
            log.warning("netpath.snmptrapdb: prune of traps older than %.1f "
                        "days did not finish within its budget; continuing at "
                        "the next maintenance pass", retention_days)
        return removed
