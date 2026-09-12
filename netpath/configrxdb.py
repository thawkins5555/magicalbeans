"""ConfigRxDatabase: SSH config-backup storage.

Rows are keyed by the Nodes device id, with no cross-file foreign key. SSH
passwords and enable secrets are DPAPI-encrypted and never returned by a read
method. Backups are zlib-compressed and stored only when the hash changes.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import zlib

from . import configrx_redact
from .sqlitebase import SqliteStore, id_chunks, reclaim

# RETURNING (SQLite 3.35) is what makes the targeted FTS delete in
# _delete_search_lines possible instead of a whole-index rebuild.
HAS_RETURNING = sqlite3.sqlite_version_info >= (3, 35)
_REBUILD_INTERVAL_S = 3600.0

# One-time backfill of the cross-device search index for an install whose
# backup history predates it: replace_search_lines only runs on a changed
# capture, so an unchanged device would never fill its rows. Chunked by
# device_id and resumable so the fleet is never indexed under one lock hold.
SEARCH_BACKFILL_CHUNK_DEVICES = 200
SEARCH_BACKFILL_STOP_TIMEOUT_S = 5.0
_SEARCH_BACKFILL_CURSOR_KEY = "_search_backfill_cursor"

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_config (
    device_id           INTEGER PRIMARY KEY,
    backup_enabled       INTEGER NOT NULL DEFAULT 0,
    ssh_port             INTEGER NOT NULL DEFAULT 22,
    ssh_username         TEXT,
    ssh_password_enc     BLOB,
    -- DPAPI-encrypted exactly like ssh_password_enc, for the handful of
    -- vendors (configrx.Vendor.enable_command) whose login shell
    -- is not already privileged EXEC. NULL for every other device, and
    -- for one of these vendors with no secret stored yet: the escalation
    -- is still attempted, answering the device's password prompt with an
    -- empty line, because a device with no enable password set accepts
    -- exactly that and there is no way to tell the two apart from here.
    -- One that does want a password re-prompts, the prompt is not a
    -- prompt this code recognises, and the capture ends as
    -- "enable-failed" without a show-config ever being sent.
    enable_secret_enc     BLOB,
    vendor_override       TEXT,
    last_backup_ts        REAL,
    last_backup_status    TEXT,
    last_backup_error     TEXT,
    -- Store this device's config verbatim, secrets and all, instead of
    -- running the redaction pass (configrx_redact.py) over it first. Off,
    -- and per device rather than global: turning it on is a decision about
    -- one switch, taken by someone who knows what that switch's config
    -- contains.
    store_secrets         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS backups (
    id           INTEGER PRIMARY KEY,
    device_id    INTEGER NOT NULL,
    ts           REAL NOT NULL,
    content_gz   BLOB NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    -- Whether the secrets in this row were replaced before it was stored.
    -- Recorded per row, not inferred from the device's current setting:
    -- the setting can be changed afterwards, and what matters when reading
    -- a backup is what happened to THAT capture. Rows stored before 4.37
    -- are 0, which is true of them.
    redacted     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_backups_device ON backups(device_id, ts);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- One remembered SSH host key per host and port, shared by ConfigRX's
-- backups and the interactive SSH terminal: whichever of the two reaches a
-- device first stores what it was shown, and both refuse a later connection
-- that presents a different key. Keyed by host+port rather than by device id
-- because a host key belongs to the endpoint, not to the Nodes row pointing
-- at it, and because two device rows for the same address must not each
-- remember a different key.
--
-- key_b64 is the wire encoding of the key (paramiko's get_base64(), the same
-- text a known_hosts line carries) so the stored key can be handed back to
-- paramiko verbatim; fingerprint is the SHA-256 of those same bytes, kept
-- alongside only so the UI and error messages need no paramiko to render it.
-- No index beyond the primary key: every read is a (host, port) lookup.
CREATE TABLE IF NOT EXISTS ssh_host_keys (
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    key_type      TEXT NOT NULL,
    key_b64       TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    first_seen_ts REAL NOT NULL,
    last_seen_ts  REAL NOT NULL,
    trusted_by    TEXT,
    PRIMARY KEY (host, port)
);

-- Cross-device search index (configrx_compliance.py): each device's LATEST
-- capture, one row per line so a match carries its own line number
-- without re-splitting a whole capture at read time. Always built from
-- REDACTED text, regardless of a device's store_secrets setting or that
-- capture's own `redacted` flag on the backups row — see
-- configrx_compliance.py's module docstring for why a cross-device search
-- view earns the same "redact unconditionally" treatment
-- get_configrx_diff already gives a comparison view, rather than the
-- single-backup route's permission-gated one: a search box is probed with
-- arbitrary substrings by design, which makes it a strictly worse place
-- to leak a secret through than a single device's own download. Replaced
-- wholesale for one device whenever a new backup lands for it — see
-- replace_search_lines.
CREATE TABLE IF NOT EXISTS config_lines (
    id        INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL,
    line_no   INTEGER NOT NULL,
    line      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_config_lines_device ON config_lines(device_id, line_no);

-- Compliance (configrx_compliance.py): a named set of must-match/must-
-- not-match rules against a device's latest capture, evaluated on a
-- schedule and when a new capture arrives — never from a page load, so
-- this table is what a 2,000-row device list actually reads rather than
-- running every rule set's regexes per view.
CREATE TABLE IF NOT EXISTS compliance_rule_sets (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    -- NULL scopes to every device; set to one Nodes device_groups.id so
    -- "access switches must have port security" is not evaluated against
    -- (and does not fail) every firewall.
    device_group_id INTEGER,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_ts      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS compliance_rules (
    id          INTEGER PRIMARY KEY,
    rule_set_id INTEGER NOT NULL REFERENCES compliance_rule_sets(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    kind        TEXT NOT NULL,      -- configrx_compliance.RuleKind
    -- Validated through configrx_compliance.compile_bounded before this row is
    -- ever written (see add_rule), so a rule set can never be SAVED with a
    -- pattern that would hang an evaluation later.
    pattern     TEXT NOT NULL,
    ordinal     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_compliance_rules_set ON compliance_rules(rule_set_id, ordinal);

-- The one result per (device, rule set) a device list actually reads.
-- `failed_rules` is a JSON list of {"rule_id", "description"} — never the
-- line that failed the rule, so a compliance view cannot become a second
-- way to read a config line a searcher would otherwise be refused (see
-- configrx_compliance.py's module docstring). An entry may carry a third
-- key, "reason", when the rule could not be run at all (its pattern is one
-- compile_bounded refuses); it describes the pattern, never the capture.
-- status is 'not_assessed'
-- for a device with no capture yet, never a silent 'pass'.
CREATE TABLE IF NOT EXISTS compliance_results (
    device_id    INTEGER NOT NULL,
    rule_set_id  INTEGER NOT NULL REFERENCES compliance_rule_sets(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,
    failed_rules TEXT NOT NULL DEFAULT '[]',
    backup_id    INTEGER,
    evaluated_ts REAL NOT NULL,
    PRIMARY KEY (device_id, rule_set_id)
);
"""

DEFAULTS = {
    "enabled": True,
    "backup_interval_hours": 24,
    # How many devices are backed up at once. Small on purpose and not
    # autoscaled: the binding constraint is at the far end, where plenty of
    # platforms cap total vty sessions at five, and no signal available here
    # can see that. A setting only because it was a bare constant before.
    "configrx_workers": 4,
    "retention_days": 90,
    "retention_count_per_device": 30,
    # Ceiling on one "show config" read, in seconds. Only a ceiling — the read
    # normally ends the moment the device's prompt comes back, so a fast switch
    # is not slowed by a generous value here. Set high because a large config
    # over a slow WAN link legitimately takes minutes, and cutting the read
    # short is how a partial config gets captured.
    "capture_timeout_s": 180,
    # Offer SHA-1 key exchange and ssh-rsa host keys as a last resort, for
    # the older switches and firewalls that offer nothing newer. OFF by
    # default: it weakens the handshake for every device, not only the ones
    # that need it, and a default that quietly does so is the wrong way
    # round — a site with gear that offers nothing newer turns it on, once,
    # deliberately. A device that needs it says so plainly in its backup
    # error (LEGACY_KEX_DISABLED), naming this setting.
    # Only effective when the installed paramiko still implements them —
    # paramiko 5 removed the code (see configrx._apply_legacy_algorithms).
    "allow_legacy_ssh": False,
    # Comma-joined column keys the ConfigRX device table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns": "",
    # Comma-joined column keys the backups table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns_backups": "",
    # Site-local lines to strip on top of configrx_volatile.VOLATILE's
    # built-ins; validated at save time (api.post_settings) so a bad
    # pattern is refused before it ever runs against a real capture.
    "ignore_line_patterns": "",
}

DEVICE_CONFIG_EDITABLE = ("backup_enabled", "ssh_port", "ssh_username",
                          "vendor_override", "store_secrets")

# set_credential's fourth argument default: "leave enable_secret_enc exactly
# as it is". None is not usable for that — it is also the value that CLEARS
# the column — and every existing caller of set_credential (the API's
# ssh_username/ssh_password routes) passes only three arguments, so leaving
# a device's enable secret untouched when only the SSH credential is being
# (re)saved has to be the default, not something every call site must
# remember to ask for.
_UNCHANGED = object()


class ConfigRxDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "configrx.db"
    OLDEST_TS_SQL = "SELECT MIN(ts) FROM backups"

    def __init__(self, path: str):
        self.search_fts = False
        self._last_search_rebuild: float | None = None
        self._search_backfill_stop = threading.Event()
        self._search_backfill_thread: threading.Thread | None = None
        super().__init__(path)

    def _migrate(self) -> None:
        self.ensure_columns("device_config", {
            "store_secrets": "INTEGER NOT NULL DEFAULT 0",
            "enable_secret_enc": "BLOB"})
        self.ensure_columns("backups", {"redacted": "INTEGER NOT NULL DEFAULT 0"})
        self._enable_search_fts()

    def _enable_search_fts(self) -> None:
        """Create the line-search index where the build has FTS5.

        `trigram` indexes every three-character run rather than whole words,
        so part of a directive or a bare IP octet is findable mid-line. Absent
        silently otherwise; config_lines is then searched by full scan.
        """
        try:
            self._conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS config_lines_fts USING fts5("
                " line, content='config_lines', content_rowid='id',"
                " tokenize='trigram')")
            self.search_fts = True
        except sqlite3.OperationalError:
            self.search_fts = False

    def begin_close(self) -> None:
        self._search_backfill_stop.set()

    def close(self, timeout_s: float | None = None) -> None:
        # Signal first, then give the backfill thread a bounded window to land
        # on a chunk boundary; it persists its cursor, so one that misses the
        # window just resumes from there next start.
        self.begin_close()
        budget = (SEARCH_BACKFILL_STOP_TIMEOUT_S if timeout_s is None
                  else max(0.0, timeout_s))
        deadline = time.monotonic() + budget
        thread = self._search_backfill_thread
        if thread is not None and thread.is_alive():
            # The join and the close share the budget, not one each.
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        super().close(max(0.0, deadline - time.monotonic()))

    # ----------------------------------------------------------- device_config

    def device_config(self, device_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_config WHERE device_id = ?", (device_id,)).fetchone()

    def all_device_configs(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM device_config").fetchall()

    def _ensure_row(self, device_id: int) -> None:
        self._conn.execute(
            "INSERT INTO device_config(device_id) VALUES (?)"
            " ON CONFLICT(device_id) DO NOTHING", (device_id,))

    def update_device_config(self, device_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in DEVICE_CONFIG_EDITABLE}
        if not allowed:
            return
        with self._lock:
            self._ensure_row(device_id)
            clauses = ", ".join(f"{key} = ?" for key in allowed)
            self._conn.execute(
                f"UPDATE device_config SET {clauses} WHERE device_id = ?",
                (*allowed.values(), device_id))
            self._conn.commit()

    def set_credential(self, device_id: int, username: str, password_enc: bytes | None,
                       enable_secret_enc=_UNCHANGED) -> None:
        """Sets the SSH username/password. `enable_secret_enc` is separate
        from those two on purpose — omit it (the default) to leave a
        previously-stored enable secret exactly as it is while the SSH
        credential is (re)saved; pass encrypted bytes to set one or `None`
        to clear it, in the same call."""
        with self._lock:
            self._ensure_row(device_id)
            if enable_secret_enc is _UNCHANGED:
                self._conn.execute(
                    "UPDATE device_config SET ssh_username = ?, ssh_password_enc = ?"
                    " WHERE device_id = ?", (username, password_enc, device_id))
            else:
                self._conn.execute(
                    "UPDATE device_config SET ssh_username = ?, ssh_password_enc = ?,"
                    " enable_secret_enc = ? WHERE device_id = ?",
                    (username, password_enc, enable_secret_enc, device_id))
            self._commit_durable()

    def clear_credential(self, device_id: int) -> None:
        """Both stored secrets, not just the password.

        An operator clearing a device's credential means "this application
        should hold nothing for this device any more" — decommissioning it,
        or rotating after an exposure. Leaving the enable secret behind kept
        an encrypted secret in configrx.db that nothing could reach and
        nothing would ever use again (a backup needs the SSH password to get
        as far as an enable prompt), while `has_enable_secret` went on
        reporting it. Inert, but not what the operator asked for.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE device_config SET ssh_password_enc = NULL, "
                "enable_secret_enc = NULL WHERE device_id = ?",
                (device_id,))
            self._conn.commit()

    def set_enable_secret(self, device_id: int, enable_secret_enc: bytes | None) -> None:
        """Sets or (passed None) clears just the enable secret, independent
        of the SSH credential — for a vendor with configrx.Vendor.
        enable_command, stored and decrypted exactly like ssh_password_enc
        (see configrx.ConfigRxWorker._backup_device)."""
        with self._lock:
            self._ensure_row(device_id)
            self._conn.execute(
                "UPDATE device_config SET enable_secret_enc = ? WHERE device_id = ?",
                (enable_secret_enc, device_id))
            self._commit_durable()

    def clear_enable_secret(self, device_id: int) -> None:
        self.set_enable_secret(device_id, None)

    def forget_device(self, device_id: int) -> None:
        """Called when a device is removed from Nodes, so ConfigRX does not
        keep polling (or displaying) a device that no longer exists.

        The remembered host key stays. A key belongs to an address and port,
        not to a device row: another device may already be recorded at the
        same address, and re-adding this one must not silently start trusting
        whatever answers there. Only ConfigRX's Forget (forget_host_key)
        removes a key, deliberately and per address."""
        with self._lock:
            self._conn.execute("DELETE FROM device_config WHERE device_id = ?", (device_id,))
            self._conn.execute("DELETE FROM backups WHERE device_id = ?", (device_id,))
            self._conn.execute("DELETE FROM compliance_results WHERE device_id = ?", (device_id,))
            self._conn.commit()
        # Outside that transaction and chunked: was the longest part of deleting a device.
        self._delete_search_lines(device_id, batched=True)

    def reassign_device(self, old_device_id: int, new_device_id: int,
                        move_config: bool = True) -> bool:
        """Two device rows turned out to be one: hand ConfigRX's half to
        the surviving id. The whole record moves only if the winner has
        none of its own; otherwise its settings/index/compliance stand and
        only the backups move (dated captures, never wrong about having
        happened). The loser's config row is dropped either way — see
        forget_device for why that id can't keep owning a credential."""
        with self._lock:
            winner = self._conn.execute(
                "SELECT 1 FROM device_config WHERE device_id = ?",
                (new_device_id,)).fetchone()
            whole = move_config and winner is None
            if whole:
                self._conn.execute(
                    "UPDATE device_config SET device_id = ? WHERE device_id = ?",
                    (new_device_id, old_device_id))
                self._conn.execute(
                    "UPDATE config_lines SET device_id = ? WHERE device_id = ?",
                    (new_device_id, old_device_id))
                self._conn.execute(
                    "UPDATE OR REPLACE compliance_results SET device_id = ?"
                    " WHERE device_id = ?", (new_device_id, old_device_id))
            else:
                self._conn.execute(
                    "DELETE FROM device_config WHERE device_id = ?", (old_device_id,))
                self._delete_search_lines(old_device_id)
                self._conn.execute(
                    "DELETE FROM compliance_results WHERE device_id = ?",
                    (old_device_id,))
            self._conn.execute(
                "UPDATE backups SET device_id = ? WHERE device_id = ?",
                (new_device_id, old_device_id))
            self._conn.commit()
        return whole

    def devices_due(self, interval_hours: float) -> list[sqlite3.Row]:
        cutoff = time.time() - max(1, interval_hours) * 3600
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_config WHERE backup_enabled = 1"
                " AND (last_backup_ts IS NULL OR last_backup_ts <= ?)",
                (cutoff,)).fetchall()

    def record_backup_attempt(self, device_id: int, ok: bool, status: str, error: str = "") -> None:
        with self._lock:
            self._ensure_row(device_id)
            self._conn.execute(
                "UPDATE device_config SET last_backup_ts = ?, last_backup_status = ?,"
                " last_backup_error = ? WHERE device_id = ?",
                (time.time(), status if ok else "error", error, device_id))
            self._conn.commit()

    # --------------------------------------------------------- ssh host keys

    def host_key(self, host: str, port: int):
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM ssh_host_keys WHERE host = ? AND port = ?",
                (host, int(port))).fetchone()

    def store_host_key(self, host: str, port: int, key_type: str, key_b64: str,
                       fingerprint: str, trusted_by: str = "") -> None:
        """Remembers this key for this host and port, replacing whatever was
        there. first_seen_ts is reset: a replacement is a NEW key, and "first
        seen" answering "since when has this device presented this key" is the
        only reading of it that is any use when one changes."""
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO ssh_host_keys(host, port, key_type, key_b64, fingerprint,"
                " first_seen_ts, last_seen_ts, trusted_by) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(host, port) DO UPDATE SET key_type=excluded.key_type,"
                " key_b64=excluded.key_b64, fingerprint=excluded.fingerprint,"
                " first_seen_ts=excluded.first_seen_ts, last_seen_ts=excluded.last_seen_ts,"
                " trusted_by=excluded.trusted_by",
                (host, int(port), key_type, key_b64, fingerprint, now, now, trusted_by or ""))
            self._conn.commit()

    def touch_host_key(self, host: str, port: int) -> None:
        """last_seen_ts only — "this same key was presented again just now"."""
        with self._lock:
            self._conn.execute(
                "UPDATE ssh_host_keys SET last_seen_ts = ? WHERE host = ? AND port = ?",
                (time.time(), host, int(port)))
            self._conn.commit()

    def forget_host_key(self, host: str, port: int) -> bool:
        """True when a key went, False when there was none — a second Forget
        click is a no-op, not an error."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM ssh_host_keys WHERE host = ? AND port = ?", (host, int(port)))
            self._conn.commit()
            return cur.rowcount > 0

    # ----------------------------------------------------------------- backups

    def latest_backup_hash(self, device_id: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT sha256 FROM backups WHERE device_id = ? ORDER BY ts DESC LIMIT 1",
                (device_id,)).fetchone()
        return row["sha256"] if row else None

    def latest_backup_size(self, device_id: int) -> int | None:
        """The stored byte size of the device's most recent backup, or None
        when it has none yet — for ConfigRxWorker's own "this capture is
        far smaller than the last one" check, run before add_backup below
        so the caller still has a size to compare a NEW capture against."""
        with self._lock:
            row = self._conn.execute(
                "SELECT size_bytes FROM backups WHERE device_id = ? ORDER BY ts DESC LIMIT 1",
                (device_id,)).fetchone()
        return row["size_bytes"] if row else None

    def add_backup(self, device_id: int, content: str,
                   redacted: bool = False) -> tuple[int | None, str]:
        """Stores `content` as a new backup unless it is byte-identical to
        the device's most recent one, in which case nothing is written —
        the caller still records the poll itself via record_backup_attempt.
        Returns (backup_id or None, sha256).

        `redacted` records whether the caller took the secrets out before
        handing the text over; it is stored on the row rather than looked
        up from the device's current setting, because the setting can be
        changed after the fact and what matters is what happened to THIS
        capture. The hash is of the text as stored, so turning the setting
        on or off makes the next capture differ from the last one and be
        kept — which is right: it genuinely is a different document."""
        raw = content.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        if digest == self.latest_backup_hash(device_id):
            return None, digest
        compressed = zlib.compress(raw)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO backups(device_id, ts, content_gz, sha256,"
                " size_bytes, redacted) VALUES (?,?,?,?,?,?)",
                (device_id, time.time(), compressed, digest, len(raw),
                 1 if redacted else 0))
            self._conn.commit()
            return cur.lastrowid, digest

    def backups_for(self, device_id: int, limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT id, device_id, ts, sha256, size_bytes, redacted FROM backups"
                " WHERE device_id = ? ORDER BY ts DESC LIMIT ?",
                (device_id, limit)).fetchall()

    def backup(self, backup_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT id, device_id, ts, sha256, size_bytes, redacted FROM backups"
                " WHERE id = ?",
                (backup_id,)).fetchone()

    def backup_content(self, backup_id: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT content_gz FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not row:
            return None
        return zlib.decompress(row["content_gz"]).decode("utf-8", "replace")

    def delete_backup(self, backup_id: int) -> bool:
        """Removes one stored backup. True when a row went, False when the id
        was already gone — a double-click is a no-op, not an error.

        Note for callers: deleting a device's MOST RECENT backup changes what
        the next run stores, because add_backup dedupes against
        latest_backup_hash. The operator is warned about that in the UI; this
        method just does what it was asked."""
        with self._lock:
            cur = self._conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
            self._conn.commit()
            return bool(cur.rowcount)

    def delete_backups(self, backup_ids: list[int]) -> int:
        """The bulk form, one statement rather than one per id."""
        if not backup_ids:
            return 0
        removed = 0
        with self._lock:
            for chunk in id_chunks(backup_ids):
                marks = ",".join("?" * len(chunk))
                cur = self._conn.execute(
                    f"DELETE FROM backups WHERE id IN ({marks})", chunk)
                removed += cur.rowcount or 0
            self._conn.commit()
            return removed

    def prune(self, retention_days: float, retention_count_per_device: int) -> int:
        """retention_days=0 deletes every backup regardless of age;
        retention_count_per_device=0 skips the count-based cap."""
        removed = 0
        with self._lock:
            cutoff = time.time() - retention_days * 86400
            cur = self._conn.execute("DELETE FROM backups WHERE ts < ?", (cutoff,))
            removed += cur.rowcount or 0
            if retention_count_per_device:
                device_ids = [r["device_id"] for r in
                             self._conn.execute("SELECT DISTINCT device_id FROM backups")]
                for device_id in device_ids:
                    ids = [r["id"] for r in self._conn.execute(
                        "SELECT id FROM backups WHERE device_id = ? ORDER BY ts DESC",
                        (device_id,))]
                    stale = ids[retention_count_per_device:]
                    for chunk in id_chunks(stale):
                        marks = ",".join("?" * len(chunk))
                        cur = self._conn.execute(
                            f"DELETE FROM backups WHERE id IN ({marks})", chunk)
                        removed += cur.rowcount or 0
            self._conn.commit()
        # Reclaim after the lock, in steps.
        if removed:
            reclaim(self._conn, self._lock, label="backups")
        return removed

    # ------------------------------------------------------------ search index

    def replace_search_lines(self, device_id: int, redacted_text: str) -> None:
        """Replaces device_id's rows in the cross-device search index with
        `redacted_text` split one line per row.

        `redacted_text` must already be redacted — this method has no
        opinion about secrets, the same division of responsibility
        configrx.diff_texts's own docstring draws for the diff path.
        configrx.ConfigRxWorker._backup_device is the one caller, and it
        redacts unconditionally before calling this, regardless of that
        device's store_secrets setting — see configrx_compliance.py's module
        docstring for why.
        """
        lines = redacted_text.split("\n")
        with self._lock:
            self._delete_search_lines(device_id)
            if lines:
                self._conn.executemany(
                    "INSERT INTO config_lines(device_id, line_no, line) VALUES (?,?,?)",
                    [(device_id, i, line) for i, line in enumerate(lines, start=1)])
                if self.search_fts:
                    last_id = self._conn.execute(
                        "SELECT last_insert_rowid()").fetchone()[0]
                    first_id = last_id - len(lines) + 1
                    self._conn.executemany(
                        "INSERT INTO config_lines_fts(rowid, line) VALUES (?,?)",
                        [(first_id + i, line) for i, line in enumerate(lines)])
            self._conn.commit()

    def has_search_lines(self, device_id: int) -> bool:
        """True when device_id already has at least one row in the search
        index — served entirely by ix_config_lines_device, so this is cheap
        enough for ConfigRxWorker._backup_device's `unchanged` branch to
        call on every poll. That is exactly what it is for: it is what
        lets a device whose configuration has not moved skip paying for
        redact()+replace_search_lines again once it has been indexed
        once, whether that happened through an earlier changed/suspect
        capture or through backfill_one_device below."""
        with self._lock:
            return self._conn.execute(
                "SELECT 1 FROM config_lines WHERE device_id = ? LIMIT 1",
                (device_id,)).fetchone() is not None

    SEARCH_LINE_CHUNK = 2_000

    def _delete_search_lines(self, device_id: int, *, batched: bool = False) -> None:
        """Drop one device's lines and their index entries. Lock held (unless `batched`).

        RETURNING hands back what FTS5 needs to retire each entry, so the cost
        is proportional to the lines removed rather than a whole re-index.
        """
        if not batched:
            self._delete_search_chunk(device_id, None)
            return
        while True:
            with self._lock:
                removed = self._delete_search_chunk(device_id,
                                                    self.SEARCH_LINE_CHUNK)
                self._conn.commit()
            if removed < self.SEARCH_LINE_CHUNK:
                return

    def _delete_search_chunk(self, device_id: int, limit: int | None) -> int:
        """At most `limit` of one device's lines (all of them when None)."""
        where = "device_id = ?"
        params: tuple = (device_id,)
        if limit is not None:
            where = ("id IN (SELECT id FROM config_lines WHERE device_id = ?"
                     " LIMIT ?)")
            params = (device_id, int(limit))
        if self.search_fts and HAS_RETURNING:
            rows = self._conn.execute(
                f"DELETE FROM config_lines WHERE {where} RETURNING id, line",
                params).fetchall()
            if rows:
                self._conn.executemany(
                    "INSERT INTO config_lines_fts(config_lines_fts, rowid, line)"
                    " VALUES ('delete', ?, ?)",
                    [(row["id"], row["line"]) for row in rows])
            return len(rows)
        cursor = self._conn.execute(
            f"DELETE FROM config_lines WHERE {where}", params)
        if cursor.rowcount and self.search_fts:
            self._rebuild_search_index()
        return cursor.rowcount or 0

    def _rebuild_search_index(self) -> None:
        """Pre-3.35 fallback, at most once an hour. Orphaned index rows are
        harmless — search joins on the rowid — so this is housekeeping."""
        now = time.monotonic()
        if (self._last_search_rebuild is not None
                and now - self._last_search_rebuild < _REBUILD_INTERVAL_S):
            return
        self._last_search_rebuild = now
        self._conn.execute("INSERT INTO config_lines_fts(config_lines_fts) VALUES('rebuild')")

    def search_fts_match(self, fts_query: str, device_ids: list[int] | None,
                         limit: int) -> list[sqlite3.Row]:
        """Rows (device_id, line_no, line) the FTS index says match —
        configrx_compliance.py builds `fts_query` and applies the wall-clock
        budget; this method is pure SQL."""
        where = ""
        params: list = [fts_query]
        if device_ids:
            marks = ",".join("?" * len(device_ids))
            where = f" AND c.device_id IN ({marks})"
            params.extend(device_ids)
        with self._lock:
            return self._conn.execute(
                "SELECT c.device_id, c.line_no, c.line FROM config_lines_fts f"
                " JOIN config_lines c ON c.id = f.rowid"
                f" WHERE config_lines_fts MATCH ?{where} LIMIT ?",
                (*params, limit)).fetchall()

    def all_search_lines(self, device_ids: list[int] | None = None) -> list[sqlite3.Row]:
        """Every indexed line, ordered by device so a caller can group them
        per device cheaply (the rows already arrive in that order — see
        ix_config_lines_device). The full-scan path: a query too short for
        FTS5's trigram floor, an SQLite build with no FTS5 at all, or a
        regular expression, which FTS5's own query language cannot express
        no matter how it is indexed."""
        where, params = "", []
        if device_ids:
            marks = ",".join("?" * len(device_ids))
            where = f" WHERE device_id IN ({marks})"
            params = list(device_ids)
        with self._lock:
            return self._conn.execute(
                "SELECT device_id, line_no, line FROM config_lines"
                f"{where} ORDER BY device_id, line_no", params).fetchall()

    # ------------------------------------------------ search index backfill

    def _read_search_backfill_cursor(self) -> int:
        """The device_id an earlier, interrupted backfill run (see close())
        had reached, or 0 to start from the beginning — a fresh install has
        no marker at all, and 0 is a safe "before every real device_id"
        floor the same way start_index_backfill's own cursor=0 is."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                (_SEARCH_BACKFILL_CURSOR_KEY,)).fetchone()
        if row is None or row["value"] is None:
            return 0
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return 0

    def _write_search_backfill_cursor(self, cursor: int) -> None:
        """Persist `cursor` as a permanent high-water mark, never cleared.

        A device_id once walked never needs walking again: its first capture
        always indexes itself, and has_search_lines keeps it indexed after
        that. Clearing the marker would re-scan `backups` from 0 for ever.
        Caller holds the lock and commits.
        """
        self._conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (_SEARCH_BACKFILL_CURSOR_KEY, str(cursor)))

    def start_search_backfill(self) -> None:
        """Kicks off the one-time search-index backfill on a background
        thread, called from ConfigRxWorker.start() (configrx.py).

        A no-op, cheaply, in the case that matters most: a fleet that has
        already been fully walked (by a previous run, or because it never
        needed backfilling — every device backed up at least once after
        this feature shipped) has no device_id left above the persisted
        cursor, checked with one bounded query rather than assumed, so
        starting and stopping the worker from the UI does not keep
        re-spawning a thread that would immediately find nothing to do.
        """
        if self._search_backfill_thread and self._search_backfill_thread.is_alive():
            return
        cursor = self._read_search_backfill_cursor()
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM backups WHERE device_id > ? LIMIT 1",
                (cursor,)).fetchone()
        if row is None:
            return
        self._search_backfill_stop.clear()
        self._search_backfill_thread = threading.Thread(
            target=self._search_backfill, args=(cursor,),
            name="configrx-search-backfill", daemon=True)
        self._search_backfill_thread.start()

    def _search_backfill(self, cursor: int) -> None:
        """Walks the device_ids present in `backups`, strictly increasing
        from `cursor`, SEARCH_BACKFILL_CHUNK_DEVICES at a time, indexing
        whichever of them has no search rows yet (backfill_one_device
        already skips one that does, whether from a previous partial run
        or a real capture landing for it while this was in progress).

        Each chunk's cursor is persisted and committed before the next
        chunk starts and _lock is only ever held for one chunk's read or
        one device's write at a time, never across the whole fleet — a
        shutdown (see close()) loses at most one in-flight chunk, not the
        whole backfill, and the next start resumes exactly after the last
        one that completed.
        """
        try:
            while not self._search_backfill_stop.is_set():
                with self._lock:
                    chunk = [r["device_id"] for r in self._conn.execute(
                        "SELECT DISTINCT device_id FROM backups WHERE device_id > ?"
                        " ORDER BY device_id LIMIT ?",
                        (cursor, SEARCH_BACKFILL_CHUNK_DEVICES)).fetchall()]
                if not chunk:
                    break
                for device_id in chunk:
                    if self._search_backfill_stop.is_set():
                        break
                    self.backfill_one_device(device_id)
                cursor = chunk[-1]
                with self._lock:
                    self._write_search_backfill_cursor(cursor)
                    self._conn.commit()
                # Courtesy pause between chunks so a fleet-wide backfill
                # never monopolizes this connection against a backup landing
                # or a search running on another thread.
                time.sleep(0.02)
        except sqlite3.Error:
            # The connection closing under this chunk is close()'s doing, not
            # a failure; the persisted cursor is where the next start resumes.
            return

    def backfill_one_device(self, device_id: int) -> None:
        """Indexes device_id from its latest stored backup, unless it is
        already indexed. Mirrors exactly what ConfigRxWorker._backup_device
        computes for the search index at capture time: the `redacted` flag
        stored on that backups row says whether the content is already
        secrets-free (store_secrets was off when it was captured) or still
        needs a redaction pass now (store_secrets was on) — the same
        unconditional "search is always redacted, regardless of
        store_secrets" rule from configrx_compliance.py's module docstring,
        just applied after the fact instead of at capture time.

        Public (not prefixed) because it is also exactly the tool a
        forgotten/never-run backfill's test double needs to call directly,
        one device at a time, without spinning up the background thread.
        """
        if self.has_search_lines(device_id):
            return
        with self._lock:
            row = self._conn.execute(
                "SELECT content_gz, redacted FROM backups WHERE device_id = ?"
                " ORDER BY ts DESC LIMIT 1", (device_id,)).fetchone()
        if row is None:
            return
        content = zlib.decompress(row["content_gz"]).decode("utf-8", "replace")
        search_text = content if row["redacted"] else configrx_redact.redact(content)[0]
        self.replace_search_lines(device_id, search_text)

    # ------------------------------------------------------------- compliance

    def add_rule_set(self, name: str, device_group_id: int | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO compliance_rule_sets(name, device_group_id, created_ts)"
                " VALUES (?,?,?)", (name, device_group_id, time.time()))
            self._conn.commit()
            return cur.lastrowid

    def update_rule_set(self, rule_set_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items()
                  if k in ("name", "device_group_id", "enabled")}
        if not allowed:
            return
        with self._lock:
            clauses = ", ".join(f"{key} = ?" for key in allowed)
            self._conn.execute(
                f"UPDATE compliance_rule_sets SET {clauses} WHERE id = ?",
                (*allowed.values(), rule_set_id))
            self._conn.commit()

    def delete_rule_set(self, rule_set_id: int) -> None:
        """Cascades to its rules (ON DELETE CASCADE) and its stored results
        (no FK there, since a result outlives whichever rule within the set
        produced it — deleted explicitly instead, same one statement)."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM compliance_rule_sets WHERE id = ?", (rule_set_id,))
            self._conn.execute(
                "DELETE FROM compliance_results WHERE rule_set_id = ?", (rule_set_id,))
            self._conn.commit()

    def rule_sets(self, enabled_only: bool = False) -> list[sqlite3.Row]:
        where = " WHERE enabled = 1" if enabled_only else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM compliance_rule_sets{where} ORDER BY name COLLATE NOCASE"
            ).fetchall()

    def rule_set(self, rule_set_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM compliance_rule_sets WHERE id = ?", (rule_set_id,)).fetchone()

    def add_rule(self, rule_set_id: int, description: str, kind: str,
                pattern: str, ordinal: int = 0) -> int:
        """The caller (configrx_compliance.add_rule) is what runs `pattern`
        through configrx_compliance.compile_bounded before this is ever
        called — this method just stores what it is given."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO compliance_rules(rule_set_id, description, kind,"
                " pattern, ordinal) VALUES (?,?,?,?,?)",
                (rule_set_id, description, kind, pattern, ordinal))
            self._conn.commit()
            return cur.lastrowid

    def delete_rule(self, rule_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM compliance_rules WHERE id = ?", (rule_id,))
            self._conn.commit()

    def rules_for(self, rule_set_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM compliance_rules WHERE rule_set_id = ?"
                " ORDER BY ordinal, id", (rule_set_id,)).fetchall()

    def set_compliance_result(self, device_id: int, rule_set_id: int, status: str,
                              failed_rules: list, backup_id: int | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO compliance_results(device_id, rule_set_id, status,"
                " failed_rules, backup_id, evaluated_ts) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(device_id, rule_set_id) DO UPDATE SET"
                " status=excluded.status, failed_rules=excluded.failed_rules,"
                " backup_id=excluded.backup_id, evaluated_ts=excluded.evaluated_ts",
                (device_id, rule_set_id, status, json.dumps(failed_rules),
                 backup_id, time.time()))
            self._conn.commit()

    def compliance_result(self, device_id: int, rule_set_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM compliance_results WHERE device_id = ? AND rule_set_id = ?",
                (device_id, rule_set_id)).fetchone()

    def compliance_results_for_device(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM compliance_results WHERE device_id = ?",
                (device_id,)).fetchall()

    def compliance_results_for_rule_set(self, rule_set_id: int) -> list[sqlite3.Row]:
        """Every device's latest result for one rule set — the column a
        2,000-row device list actually reads."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM compliance_results WHERE rule_set_id = ?",
                (rule_set_id,)).fetchall()
