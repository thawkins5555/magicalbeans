"""WirelessDatabase: FortiGate Wireless Controller polling storage.

One or a handful of controllers (unlike Nodes' potentially-hundreds of
devices), each polled directly over SNMP for its managed APs — no
polling-profile system needed, so a controller carries its own SNMP
credential columns directly, the same shape devices/device_groups use in
nodesdb.py (snmp_version/community/v3_user/v3_auth_proto/
v3_auth_pass_enc, DPAPI-encrypted, decrypted just before use and never
returned).
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS controllers (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL,
    ip               TEXT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    snmp_version     INTEGER NOT NULL DEFAULT 1,   -- 0=v1, 1=v2c, 3=v3
    community        TEXT,
    v3_user          TEXT,
    v3_auth_proto    TEXT,
    v3_auth_pass_enc BLOB,
    last_poll_ts     REAL,
    last_poll_ok     INTEGER,
    last_poll_error  TEXT,
    created_ts       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS access_points (
    id              INTEGER PRIMARY KEY,
    controller_id   INTEGER NOT NULL REFERENCES controllers(id) ON DELETE CASCADE,
    wtp_id          TEXT NOT NULL,     -- the controller's own WTP identifier (usually a serial)
    vdom            TEXT NOT NULL DEFAULT '',
    name            TEXT,
    status          TEXT NOT NULL DEFAULT 'other',   -- see fortinetoids.CONNECTION_STATE
    model           TEXT,
    mac_address     TEXT,
    station_count   INTEGER,
    last_seen_ts    REAL NOT NULL,
    UNIQUE(controller_id, vdom, wtp_id)
);
CREATE INDEX IF NOT EXISTS ix_aps_controller ON access_points(controller_id);

CREATE TABLE IF NOT EXISTS radios (
    ap_id                INTEGER NOT NULL REFERENCES access_points(id) ON DELETE CASCADE,
    radio_id             TEXT NOT NULL,
    channel              TEXT,
    operating_power_dbm  INTEGER,
    station_count        INTEGER,
    PRIMARY KEY (ap_id, radio_id)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

DEFAULTS = {
    "enabled": True,
    "poll_interval_s": 60,
    # An AP the controller stops reporting (removed, powered off, or the
    # controller itself unreachable) is aged out rather than kept forever
    # showing a stale "online" status from its last successful poll.
    "stale_after_polls": 5,
}

CONTROLLER_EDITABLE = ("name", "ip", "enabled", "snmp_version", "community",
                       "v3_user", "v3_auth_proto")


class WirelessDatabase:
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
                import json
                try:
                    values[row["key"]] = json.loads(row["value"])
                except (ValueError, TypeError):
                    pass
        return values

    def save_settings(self, values: dict) -> None:
        import json
        with self._lock:
            for key, value in values.items():
                if key not in DEFAULTS:
                    continue
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)))
            self._conn.commit()

    # ------------------------------------------------------------ controllers

    def controllers(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM controllers ORDER BY name COLLATE NOCASE").fetchall()

    def controller(self, controller_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM controllers WHERE id = ?", (controller_id,)).fetchone()

    def add_controller(self, name: str, ip: str, **overrides) -> int:
        cols = ["name", "ip", "created_ts"]
        vals = [name, ip, time.time()]
        for key in ("snmp_version", "community", "v3_user", "v3_auth_proto"):
            if key in overrides:
                cols.append(key)
                vals.append(overrides[key])
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO controllers({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def update_controller(self, controller_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in CONTROLLER_EDITABLE}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE controllers SET {clauses} WHERE id = ?",
                (*allowed.values(), controller_id))
            self._conn.commit()

    def remove_controller(self, controller_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM controllers WHERE id = ?", (controller_id,))
            self._conn.commit()

    def set_credential(self, controller_id: int, password_enc: bytes | None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE controllers SET v3_auth_pass_enc = ? WHERE id = ?",
                (password_enc, controller_id))
            self._conn.commit()

    def record_poll(self, controller_id: int, ok: bool, error: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE controllers SET last_poll_ts = ?, last_poll_ok = ?,"
                " last_poll_error = ? WHERE id = ?",
                (time.time(), 1 if ok else 0, error, controller_id))
            self._conn.commit()

    # ---------------------------------------------------------- access points

    def upsert_ap(self, controller_id: int, wtp_id: str, vdom: str, **fields) -> int:
        now = time.time()
        cols = ["controller_id", "wtp_id", "vdom", "last_seen_ts"] + list(fields)
        vals = [controller_id, wtp_id, vdom, now] + list(fields.values())
        marks = ",".join("?" * len(vals))
        update_clause = ", ".join(f"{k} = excluded.{k}" for k in
                                  ("last_seen_ts", *fields))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO access_points({','.join(cols)}) VALUES ({marks})"
                f" ON CONFLICT(controller_id, vdom, wtp_id)"
                f" DO UPDATE SET {update_clause}",
                vals)
            self._conn.commit()
            row = self._conn.execute(
                "SELECT id FROM access_points WHERE controller_id = ? AND vdom = ?"
                " AND wtp_id = ?", (controller_id, vdom, wtp_id)).fetchone()
            return row["id"]

    def replace_radios(self, ap_id: int, radios: list[dict]) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM radios WHERE ap_id = ?", (ap_id,))
            for radio in radios:
                self._conn.execute(
                    "INSERT INTO radios(ap_id, radio_id, channel,"
                    " operating_power_dbm, station_count) VALUES (?,?,?,?,?)",
                    (ap_id, radio["radio_id"], radio.get("channel"),
                     radio.get("operating_power_dbm"), radio.get("station_count")))
            self._conn.commit()

    def access_points(self, controller_id: int | None = None) -> list[sqlite3.Row]:
        clause = " WHERE controller_id = ?" if controller_id is not None else ""
        params = (controller_id,) if controller_id is not None else ()
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM access_points{clause} ORDER BY name COLLATE NOCASE, wtp_id",
                params).fetchall()

    def radios_for(self, ap_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM radios WHERE ap_id = ? ORDER BY radio_id",
                (ap_id,)).fetchall()

    def ap_counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM access_points GROUP BY status").fetchall()
        counts = {"total": 0}
        for row in rows:
            counts["total"] += row["n"]
            counts[row["status"]] = row["n"]
        return counts

    def prune_stale(self, controller_id: int, seen_wtp_ids: set[tuple[str, str]]) -> None:
        """Removes APs this poll didn't see for a controller that itself
        polled successfully — a real "this AP is gone", not "the
        controller was briefly unreachable" (record_poll's ok=False case
        never calls this, so a transient controller outage doesn't wipe
        its whole AP list)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, vdom, wtp_id FROM access_points WHERE controller_id = ?",
                (controller_id,)).fetchall()
            stale_ids = [row["id"] for row in rows
                        if (row["vdom"], row["wtp_id"]) not in seen_wtp_ids]
            if stale_ids:
                marks = ",".join("?" * len(stale_ids))
                self._conn.execute(
                    f"DELETE FROM access_points WHERE id IN ({marks})", stale_ids)
            self._conn.commit()

    # ------------------------------------------------------------- maintenance

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total
