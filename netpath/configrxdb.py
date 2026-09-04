"""ConfigRxDatabase: SSH config-backup storage.

ConfigRX has no device table of its own — per the explicit product
decision, it reuses Nodes' existing device list wholesale. This database
only stores ConfigRX's own per-device backup configuration (SSH port/
username/password, backup-enabled flag, vendor override), keyed by the
Nodes device id with no real cross-database foreign key — the same
pattern Alerts already uses for its own `entity_id` columns, since a
SQLite database file cannot enforce a foreign key into a different file.

The SSH password is DPAPI-encrypted at rest (dpapi.py, the only secret
storage this app has), exactly like every other stored credential here:
never returned from any read method as anything but a has_credential
boolean at the API layer, decrypted only immediately before an SSH
connection and discarded right after (see configrx.ConfigRxWorker). The
optional per-device enable secret (enable_secret_enc, for a vendor whose
login shell is not already privileged EXEC) follows the identical
discipline, one column over — see set_credential/set_enable_secret below.

A backup's content is stored zlib-compressed and only when its hash
differs from that device's most recently stored backup — an unchanged
config does not grow the database on every scheduled pull.

One table here is not ConfigRX's alone: `ssh_host_keys` is the remembered
host key per (host, port), written and checked by both the backup worker
and the interactive SSH terminal. It lives in this database because this
is where SSH for these devices already lives; it is keyed by address, not
by device id, and so survives nothing else about a device changing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import zlib

from . import dbmaint, dbopen, settingsutil

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_config (
    device_id           INTEGER PRIMARY KEY,
    backup_enabled       INTEGER NOT NULL DEFAULT 0,
    ssh_port             INTEGER NOT NULL DEFAULT 22,
    ssh_username         TEXT,
    ssh_password_enc     BLOB,
    -- DPAPI-encrypted exactly like ssh_password_enc, for the handful of
    -- vendors (configrx_vendors.Vendor.enable_command) whose login shell
    -- is not already privileged EXEC. NULL for every other device, and
    -- for one of these vendors with no secret stored yet — the worker
    -- then reports that plainly rather than guessing an empty password.
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
"""

DEFAULTS = {
    "enabled": True,
    "backup_interval_hours": 24,
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


class ConfigRxDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        # dbopen.connect rather than sqlite3.connect: this file holds every
        # captured device config (communities, TACACS/RADIUS keys, IPsec
        # pre-shared keys, enable secrets) and the DPAPI-wrapped SSH
        # passwords, and was being created 0644.
        self._conn = dbopen.connect(path)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            dbmaint.enable_incremental_vacuum(self._conn, "configrx.db")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Adds columns a database created by an older build predates. Same
        shape as nodesdb._migrate and wirelessdb._migrate: diff PRAGMA
        table_info against what the CREATE TABLE above declares and ALTER
        TABLE in what is missing, never rewrite the CREATE. Idempotent, so
        it runs on every open."""
        wanted = {
            "device_config": [("store_secrets", "INTEGER NOT NULL DEFAULT 0"),
                              ("enable_secret_enc", "BLOB")],
            "backups": [("redacted", "INTEGER NOT NULL DEFAULT 0")],
        }
        for table, columns in wanted.items():
            present = {row["name"] for row in
                       self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for name, declaration in columns:
                if name not in present:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -------------------------------------------------------------- settings

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
            self._conn.commit()

    def clear_credential(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE device_config SET ssh_password_enc = NULL WHERE device_id = ?",
                (device_id,))
            self._conn.commit()

    def set_enable_secret(self, device_id: int, enable_secret_enc: bytes | None) -> None:
        """Sets or (passed None) clears just the enable secret, independent
        of the SSH credential — for a vendor with configrx_vendors.Vendor.
        enable_command, stored and decrypted exactly like ssh_password_enc
        (see configrx.ConfigRxWorker._backup_device)."""
        with self._lock:
            self._ensure_row(device_id)
            self._conn.execute(
                "UPDATE device_config SET enable_secret_enc = ? WHERE device_id = ?",
                (enable_secret_enc, device_id))
            self._conn.commit()

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
            self._conn.commit()

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

    def host_keys(self) -> list:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM ssh_host_keys ORDER BY host, port").fetchall()

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
        marks = ",".join("?" * len(backup_ids))
        with self._lock:
            cur = self._conn.execute(
                f"DELETE FROM backups WHERE id IN ({marks})", backup_ids)
            self._conn.commit()
            return cur.rowcount or 0

    def prune(self, retention_days: float, retention_count_per_device: int) -> int:
        """retention_days=0 deletes every backup regardless of age — the
        same "0 means everything" convention alertsdb.prune()/syslogdb.
        prune() already use for their own manual "prune now" actions —
        while retention_count_per_device=0 means no count-based cap at
        all (skipped), matching syslogdb.prune()'s max_rows=0 convention."""
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
                    if stale:
                        marks = ",".join("?" * len(stale))
                        cur = self._conn.execute(
                            f"DELETE FROM backups WHERE id IN ({marks})", stale)
                        removed += cur.rowcount or 0
            self._conn.commit()
        # Reclaim after the lock, in steps, as every other database does.
        if removed:
            dbmaint.reclaim(self._conn, self._lock, label="backups")
        return removed

    # ------------------------------------------------------------- maintenance

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total
