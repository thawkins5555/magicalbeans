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
connection and discarded right after (see configrx.ConfigRxWorker).

A backup's content is stored zlib-compressed and only when its hash
differs from that device's most recently stored backup — an unchanged
config does not grow the database on every scheduled pull.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import zlib

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_config (
    device_id           INTEGER PRIMARY KEY,
    backup_enabled       INTEGER NOT NULL DEFAULT 0,
    ssh_port             INTEGER NOT NULL DEFAULT 22,
    ssh_username         TEXT,
    ssh_password_enc     BLOB,
    vendor_override       TEXT,
    last_backup_ts        REAL,
    last_backup_status    TEXT,
    last_backup_error     TEXT
);

CREATE TABLE IF NOT EXISTS backups (
    id           INTEGER PRIMARY KEY,
    device_id    INTEGER NOT NULL,
    ts           REAL NOT NULL,
    content_gz   BLOB NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_backups_device ON backups(device_id, ts);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
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
    # the older switches and firewalls that offer nothing newer. On by
    # default because backing those up is the job; turn it off where policy
    # forbids SHA-1 and every device is known to speak something modern.
    # Only effective when the installed paramiko still implements them —
    # paramiko 5 removed the code (see configrx._apply_legacy_algorithms).
    "allow_legacy_ssh": True,
}

DEVICE_CONFIG_EDITABLE = ("backup_enabled", "ssh_port", "ssh_username", "vendor_override")


class ConfigRxDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

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
        return values

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

    def set_credential(self, device_id: int, username: str, password_enc: bytes | None) -> None:
        with self._lock:
            self._ensure_row(device_id)
            self._conn.execute(
                "UPDATE device_config SET ssh_username = ?, ssh_password_enc = ?"
                " WHERE device_id = ?", (username, password_enc, device_id))
            self._conn.commit()

    def clear_credential(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE device_config SET ssh_password_enc = NULL WHERE device_id = ?",
                (device_id,))
            self._conn.commit()

    def forget_device(self, device_id: int) -> None:
        """Called when a device is removed from Nodes, so ConfigRX does not
        keep polling (or displaying) a device that no longer exists."""
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

    # ----------------------------------------------------------------- backups

    def latest_backup_hash(self, device_id: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT sha256 FROM backups WHERE device_id = ? ORDER BY ts DESC LIMIT 1",
                (device_id,)).fetchone()
        return row["sha256"] if row else None

    def add_backup(self, device_id: int, content: str) -> tuple[int | None, str]:
        """Stores `content` as a new backup unless it is byte-identical to
        the device's most recent one, in which case nothing is written —
        the caller still records the poll itself via record_backup_attempt.
        Returns (backup_id or None, sha256)."""
        raw = content.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        if digest == self.latest_backup_hash(device_id):
            return None, digest
        compressed = zlib.compress(raw)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO backups(device_id, ts, content_gz, sha256, size_bytes)"
                " VALUES (?,?,?,?,?)",
                (device_id, time.time(), compressed, digest, len(raw)))
            self._conn.commit()
            return cur.lastrowid, digest

    def backups_for(self, device_id: int, limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT id, device_id, ts, sha256, size_bytes FROM backups"
                " WHERE device_id = ? ORDER BY ts DESC LIMIT ?",
                (device_id, limit)).fetchall()

    def backup(self, backup_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT id, device_id, ts, sha256, size_bytes FROM backups WHERE id = ?",
                (backup_id,)).fetchone()

    def backup_content(self, backup_id: int) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT content_gz FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not row:
            return None
        return zlib.decompress(row["content_gz"]).decode("utf-8", "replace")

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
            removed += cur.rowcount
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
                        removed += cur.rowcount
            self._conn.commit()
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
