"""Storage for the Nodes module: devices, polling groups ("profiles"),
interfaces, polled metrics and their samples, device/interface state
events, uploaded vendor MIBs, and discovery jobs.

Two tables are genuinely unbounded and pruned by age/size: `samples` (raw
metric points) and `device_events`/`interface_events` (state transitions).
Everything else — `devices`, `groups`, `interfaces`, `mib_files`/
`mib_objects` — describes the network as it is configured and currently
known, not a log, and is never trimmed by age or size; only explicit
deletion removes a row from those tables. This mirrors the same bounded/
unbounded split `ipamdb.py`'s `scans` (pruned) vs. `subnets`/`hosts`
(never pruned by age) already established in this codebase.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (               -- "polling profiles"
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    snmp_version    INTEGER NOT NULL DEFAULT 1,    -- 0=v1, 1=v2c, 3=v3
    community       TEXT,                          -- v1/v2c
    v3_user         TEXT,                          -- v3
    v3_auth_proto   TEXT,                           -- MD5/SHA/SHA224/256/384/512
    v3_auth_pass_enc BLOB,                          -- DPAPI-encrypted; NULL = none stored
    poll_interval_s INTEGER NOT NULL DEFAULT 120,
    snmp_timeout_s  REAL NOT NULL DEFAULT 3.0,
    snmp_retries    INTEGER NOT NULL DEFAULT 2,
    ping_enabled    INTEGER NOT NULL DEFAULT 1,
    snmp_enabled    INTEGER NOT NULL DEFAULT 1,
    oid_set         TEXT NOT NULL DEFAULT 'auto',  -- 'auto' | comma-separated metric keys
    is_default      INTEGER NOT NULL DEFAULT 0,
    created_ts      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY,
    ip              TEXT NOT NULL UNIQUE,
    name            TEXT,                          -- display name, defaults to ip
    group_id        INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    -- per-device overrides; NULL means "use the group's value"
    snmp_version    INTEGER,
    community       TEXT,
    v3_user         TEXT,
    v3_auth_proto   TEXT,
    v3_auth_pass_enc BLOB,
    poll_interval_s INTEGER,
    snmp_timeout_s  REAL,
    snmp_retries    INTEGER,
    ping_enabled    INTEGER,
    snmp_enabled    INTEGER,
    oid_set         TEXT,
    -- discovered/learned identity, refreshed by every successful poll
    sys_descr       TEXT,
    sys_name        TEXT,
    sys_object_id   TEXT,
    sys_contact     TEXT,
    sys_location    TEXT,
    vendor          TEXT,
    -- live state
    status          TEXT NOT NULL DEFAULT 'unknown', -- unknown|up|down|unsupported|auth
    ping_ok         INTEGER,
    ping_rtt_ms     REAL,
    snmp_ok         INTEGER,
    snmp_error      TEXT,
    consecutive_fail INTEGER NOT NULL DEFAULT 0,
    last_poll_ts    REAL,
    last_up_ts      REAL,
    last_down_ts    REAL,
    last_uptime_ticks INTEGER,                      -- sysUpTime.0, for reboot detection
    last_uptime_ts  REAL,
    created_ts      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_devices_group ON devices(group_id);
CREATE INDEX IF NOT EXISTS ix_devices_status ON devices(status);

CREATE TABLE IF NOT EXISTS interfaces (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index        INTEGER NOT NULL,
    descr           TEXT,
    alias           TEXT,
    phys_addr       TEXT,
    speed_bps       INTEGER,
    admin_status    TEXT,
    oper_status     TEXT,
    last_in_octets  INTEGER,
    last_out_octets INTEGER,
    last_sample_ts  REAL,
    in_bps          REAL,
    out_bps         REAL,
    in_error_rate   REAL,
    out_error_rate  REAL,
    last_seen_ts    REAL NOT NULL,
    UNIQUE(device_id, if_index)
);
CREATE INDEX IF NOT EXISTS ix_interfaces_device ON interfaces(device_id);

CREATE TABLE IF NOT EXISTS metrics (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key             TEXT NOT NULL,
    label           TEXT NOT NULL,
    unit            TEXT NOT NULL,
    kind            TEXT NOT NULL,                  -- 'gauge'|'counter_rate'
    last_value      REAL,
    last_ts         REAL,
    UNIQUE(device_id, key)
);

CREATE TABLE IF NOT EXISTS samples (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    value           REAL,
    PRIMARY KEY (metric_id, ts)
);
CREATE TABLE IF NOT EXISTS samples_hourly (
    metric_id       INTEGER NOT NULL REFERENCES metrics(id) ON DELETE CASCADE,
    hour            INTEGER NOT NULL,
    n               INTEGER NOT NULL,
    vmin            REAL, vavg REAL, vmax REAL,
    PRIMARY KEY (metric_id, hour)
);

CREATE TABLE IF NOT EXISTS device_events (
    id              INTEGER PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    kind            TEXT NOT NULL,   -- down|up|rebooted|auth_fail|poll_overrun|unsupported
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS ix_device_events_device_ts ON device_events(device_id, ts);
CREATE INDEX IF NOT EXISTS ix_device_events_ts ON device_events(ts);

CREATE TABLE IF NOT EXISTS interface_events (
    id              INTEGER PRIMARY KEY,
    interface_id    INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    ts              REAL NOT NULL,
    kind            TEXT NOT NULL,    -- link_down|link_up
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS ix_interface_events_ts ON interface_events(ts);

CREATE TABLE IF NOT EXISTS mib_files (
    id              INTEGER PRIMARY KEY,
    filename        TEXT NOT NULL,
    module          TEXT,
    uploaded_ts     REAL NOT NULL,
    object_count    INTEGER NOT NULL DEFAULT 0,
    unresolved      TEXT NOT NULL DEFAULT '[]',
    parse_notes     TEXT,
    -- The original text, kept so "resolve again" can re-parse from
    -- scratch: mib_objects only stores the final oid (or NULL), not the
    -- parent/last_arc an unresolved object would need to retry against.
    content         TEXT
);
CREATE TABLE IF NOT EXISTS mib_objects (
    id              INTEGER PRIMARY KEY,
    mib_file_id     INTEGER REFERENCES mib_files(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    oid             TEXT,
    description     TEXT,
    syntax          TEXT,
    enums           TEXT,
    is_notification INTEGER NOT NULL DEFAULT 0,
    edited          INTEGER NOT NULL DEFAULT 0,
    UNIQUE(mib_file_id, name)
);
CREATE INDEX IF NOT EXISTS ix_mib_objects_oid ON mib_objects(oid);

CREATE TABLE IF NOT EXISTS discovery_jobs (
    id              INTEGER PRIMARY KEY,
    kind            TEXT NOT NULL,        -- 'device'|'subnet'
    target          TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'running',  -- running|done|cancelled|error
    total           INTEGER NOT NULL DEFAULT 0,
    probed          INTEGER NOT NULL DEFAULT 0,
    responded       INTEGER NOT NULL DEFAULT 0,
    identified      INTEGER NOT NULL DEFAULT 0,
    started_ts      REAL NOT NULL,
    finished_ts     REAL,
    error           TEXT
);
CREATE TABLE IF NOT EXISTS discovery_results (
    id              INTEGER PRIMARY KEY,
    job_id          INTEGER NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    ping_ok         INTEGER NOT NULL DEFAULT 0,
    snmp_ok         INTEGER NOT NULL DEFAULT 0,
    community_or_user TEXT,
    snmp_version    INTEGER,
    sys_descr       TEXT,
    sys_name        TEXT,
    sys_object_id   TEXT,
    vendor          TEXT,
    suggested_group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    promoted_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_discovery_results_job ON discovery_results(job_id);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

DEFAULTS = {
    "enabled": True,
    "poll_workers": 16,
    "default_interval_s": 120,
    "default_snmp_timeout_s": 3.0,
    "default_snmp_retries": 2,
    "down_after_failures": 3,        # consecutive poll failures before status -> down
    "unreachable_ping_only": False,  # if true, ping alone can mark a device up even with snmp_ok false
    "sample_retention_days": 400,    # raw samples; hourly rollups are never pruned by age
    "sample_row_cap_per_metric": 50_000,
    "event_retention_days": 180,
    "discovery_retention_days": 30,
    "max_mib_bytes": 8 * 1024 * 1024,
    "resolve_addresses": True,
    "max_scan_addresses": 1024,
    "discovery_communities": "public",
    "rollup_enabled": True,
}

_OVERRIDE_COLUMNS = ("snmp_version", "community", "v3_user", "v3_auth_proto",
                     "v3_auth_pass_enc", "poll_interval_s", "snmp_timeout_s",
                     "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set")

_GROUP_EDITABLE = ("name", "snmp_version", "community", "v3_user",
                   "v3_auth_proto", "poll_interval_s", "snmp_timeout_s",
                   "snmp_retries", "ping_enabled", "snmp_enabled", "oid_set")

_DEVICE_EDITABLE = ("name", "group_id", "enabled") + _OVERRIDE_COLUMNS


class NodesDatabase:
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
        self._seed()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _seed(self) -> None:
        """Creates a `Default` polling profile if none exists yet. Idempotent
        on every open — a device with no group falls back to this one, and
        every device created before any profile exists gets it."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM groups WHERE is_default = 1 LIMIT 1").fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO groups(name, snmp_version, community,"
                    " poll_interval_s, snmp_timeout_s, snmp_retries,"
                    " ping_enabled, snmp_enabled, oid_set, is_default, created_ts)"
                    " VALUES ('Default', 1, 'public', 120, 3.0, 2, 1, 1, 'auto', 1, ?)",
                    (time.time(),))
                self._conn.commit()

    def ensure_default_group(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM groups WHERE is_default = 1 LIMIT 1").fetchone()
        if row:
            return row["id"]
        self._seed()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM groups WHERE is_default = 1 LIMIT 1").fetchone()
        return row["id"]

    # --------------------------------------------------------------- settings

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

    # ----------------------------------------------------------------- groups

    def groups(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM groups ORDER BY is_default DESC, name COLLATE NOCASE"
            ).fetchall()

    def group(self, group_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()

    def add_group(self, name: str, **fields) -> int:
        cols = ["name", "created_ts"]
        vals = [name, time.time()]
        for key in _GROUP_EDITABLE:
            if key in fields and key != "name":
                cols.append(key)
                vals.append(fields[key])
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO groups({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def update_group(self, group_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in _GROUP_EDITABLE}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE groups SET {clauses} WHERE id = ?",
                (*allowed.values(), group_id))
            self._conn.commit()

    def set_group_credential(self, group_id: int, user: str, auth_proto: str,
                             password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE groups SET v3_user=?, v3_auth_proto=?, v3_auth_pass_enc=?"
                " WHERE id=?", (user, auth_proto, password_enc, group_id))
            self._conn.commit()

    def clear_group_credential(self, group_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE groups SET v3_auth_pass_enc=NULL WHERE id=?", (group_id,))
            self._conn.commit()

    def remove_group(self, group_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM groups WHERE id = ? AND is_default = 0",
                               (group_id,))
            self._conn.commit()

    # ---------------------------------------------------------------- devices

    def devices(self, group_id: int | None = None, status: str | None = None,
               text: str | None = None) -> list[sqlite3.Row]:
        clauses, params = [], []
        if group_id is not None:
            clauses.append("group_id = ?")
            params.append(group_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if text:
            clauses.append("(ip LIKE ? OR name LIKE ? OR sys_name LIKE ?)")
            params.extend([f"%{text}%"] * 3)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM devices{where} ORDER BY name COLLATE NOCASE, ip",
                params).fetchall()

    def device(self, device_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()

    def device_by_ip(self, ip: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()

    def device_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM devices").fetchone()["n"]

    def device_counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM devices GROUP BY status").fetchall()
        counts = {"total": 0, "up": 0, "down": 0, "unknown": 0,
                 "unsupported": 0, "auth": 0}
        for row in rows:
            counts["total"] += row["n"]
            counts[row["status"]] = counts.get(row["status"], 0) + row["n"]
        return counts

    def add_device(self, ip: str, name: str | None = None,
                   group_id: int | None = None, **overrides) -> int:
        cols = ["ip", "name", "group_id", "created_ts"]
        vals = [ip, name or ip, group_id, time.time()]
        for key in _OVERRIDE_COLUMNS:
            if key in overrides:
                cols.append(key)
                vals.append(overrides[key])
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO devices({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def update_device(self, device_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in _DEVICE_EDITABLE}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE devices SET {clauses} WHERE id = ?",
                (*allowed.values(), device_id))
            self._conn.commit()

    def set_device_credential(self, device_id: int, user: str, auth_proto: str,
                              password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET v3_user=?, v3_auth_proto=?, v3_auth_pass_enc=?"
                " WHERE id=?", (user, auth_proto, password_enc, device_id))
            self._conn.commit()

    def clear_device_credential(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE devices SET v3_auth_pass_enc=NULL WHERE id=?", (device_id,))
            self._conn.commit()

    def remove_device(self, device_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            self._conn.commit()

    def effective_config(self, device_row: sqlite3.Row) -> dict:
        """Merges a device's own non-NULL override columns over its group's
        row (or DEFAULTS if the device has no group). This is the single
        place "per device or per device group" is actually resolved."""
        group_row = self.group(device_row["group_id"]) if device_row["group_id"] else None
        config = {}
        for key in _OVERRIDE_COLUMNS:
            value = device_row[key] if key in device_row.keys() else None
            if value is None and group_row is not None and key in group_row.keys():
                value = group_row[key]
            config[key] = value
        if config.get("snmp_version") is None:
            config["snmp_version"] = 1
        if config.get("poll_interval_s") is None:
            config["poll_interval_s"] = self.settings().get("default_interval_s", 120)
        if config.get("snmp_timeout_s") is None:
            config["snmp_timeout_s"] = self.settings().get("default_snmp_timeout_s", 3.0)
        if config.get("snmp_retries") is None:
            config["snmp_retries"] = self.settings().get("default_snmp_retries", 2)
        if config.get("ping_enabled") is None:
            config["ping_enabled"] = 1
        if config.get("snmp_enabled") is None:
            config["snmp_enabled"] = 1
        if config.get("oid_set") is None:
            config["oid_set"] = "auto"
        return config

    def record_poll(self, device_id: int, *, ping_ok, ping_rtt_ms, snmp_ok,
                    snmp_error, identity: dict | None,
                    uptime_ticks: int | None, status: str,
                    reachable: bool) -> sqlite3.Row | None:
        """Updates the device row's live-state columns. Returns the previous
        row first so the poller can diff old vs. new status without a
        second read.

        `reachable` is whether THIS poll actually succeeded — distinct from
        `status`, the display label, because the caller may deliberately
        keep showing the last-known "up"/"down" label during a grace
        window (down_after_failures) rather than flapping to "unknown" on
        every missed poll. consecutive_fail must track `reachable`, not the
        literal status string: tying it to status=="up" would let the
        grace window's own preserved "up" label reset the failure streak
        back to zero on every poll, and a failing device could never
        actually reach "down"."""
        with self._lock:
            previous = self._conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
            if previous is None:
                return None
            now = time.time()
            fields = {
                "ping_ok": 1 if ping_ok else (0 if ping_ok is False else None),
                "ping_rtt_ms": ping_rtt_ms,
                "snmp_ok": 1 if snmp_ok else (0 if snmp_ok is False else None),
                "snmp_error": snmp_error,
                "status": status,
                "last_poll_ts": now,
            }
            if identity:
                fields.update({
                    "sys_descr": identity.get("sys_descr"),
                    "sys_name": identity.get("sys_name"),
                    "sys_object_id": identity.get("sys_object_id"),
                    "sys_contact": identity.get("sys_contact"),
                    "sys_location": identity.get("sys_location"),
                    "vendor": identity.get("vendor"),
                })
            if uptime_ticks is not None:
                fields["last_uptime_ticks"] = uptime_ticks
                fields["last_uptime_ts"] = now
            if status == "up":
                fields["last_up_ts"] = now
            elif status == "down":
                fields["last_down_ts"] = now
            fields["consecutive_fail"] = (
                0 if reachable else (previous["consecutive_fail"] or 0) + 1)
            clauses = ", ".join(f"{key} = ?" for key in fields)
            self._conn.execute(
                f"UPDATE devices SET {clauses} WHERE id = ?",
                (*fields.values(), device_id))
            self._conn.commit()
            return previous

    # ------------------------------------------------------------- interfaces

    def interfaces(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interfaces WHERE device_id = ? ORDER BY if_index",
                (device_id,)).fetchall()

    def replace_interfaces(self, device_id: int, rows: list[dict]) -> dict:
        """Wholesale replace of a device's interface table each poll cycle.
        Matches existing rows by if_index to carry forward
        last_in_octets/last_out_octets/last_sample_ts so a rate calc isn't
        lost across a routine poll; inserts new ones; deletes vanished
        ones."""
        now = time.time()
        with self._lock:
            existing = {row["if_index"]: row for row in self._conn.execute(
                "SELECT * FROM interfaces WHERE device_id = ?", (device_id,)).fetchall()}
            seen_indexes = set()
            added, removed, reindexed = [], [], []
            for row in rows:
                if_index = row["if_index"]
                seen_indexes.add(if_index)
                prior = existing.get(if_index)
                if prior is None:
                    added.append(if_index)
                    self._conn.execute(
                        "INSERT INTO interfaces(device_id, if_index, descr, alias,"
                        " phys_addr, speed_bps, admin_status, oper_status,"
                        " last_seen_ts) VALUES (?,?,?,?,?,?,?,?,?)",
                        (device_id, if_index, row.get("descr"), row.get("alias"),
                         row.get("phys_addr"), row.get("speed_bps"),
                         row.get("admin_status"), row.get("oper_status"), now))
                else:
                    if prior["descr"] != row.get("descr"):
                        reindexed.append(if_index)
                    self._conn.execute(
                        "UPDATE interfaces SET descr=?, alias=?, phys_addr=?,"
                        " speed_bps=?, admin_status=?, oper_status=?, last_seen_ts=?"
                        " WHERE device_id=? AND if_index=?",
                        (row.get("descr"), row.get("alias"), row.get("phys_addr"),
                         row.get("speed_bps"), row.get("admin_status"),
                         row.get("oper_status"), now, device_id, if_index))
            for if_index in existing:
                if if_index not in seen_indexes:
                    removed.append(if_index)
            if removed:
                marks = ",".join("?" * len(removed))
                self._conn.execute(
                    f"DELETE FROM interfaces WHERE device_id=? AND if_index IN ({marks})",
                    (device_id, *removed))
            self._conn.commit()
        return {"added": added, "removed": removed, "reindexed": reindexed}

    def update_interface_rate(self, device_id: int, if_index: int, *,
                              in_octets: int | None, out_octets: int | None,
                              in_bps: float | None, out_bps: float | None,
                              in_error_rate: float | None, out_error_rate: float | None,
                              ts: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE interfaces SET last_in_octets=?, last_out_octets=?,"
                " last_sample_ts=?, in_bps=?, out_bps=?, in_error_rate=?,"
                " out_error_rate=? WHERE device_id=? AND if_index=?",
                (in_octets, out_octets, ts, in_bps, out_bps, in_error_rate,
                 out_error_rate, device_id, if_index))
            self._conn.commit()

    # ---------------------------------------------------------------- metrics

    def record_metric_sample(self, device_id: int, key: str, label: str,
                             unit: str, kind: str, ts: float, value: float | None) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM metrics WHERE device_id=? AND key=?",
                (device_id, key)).fetchone()
            if row is None:
                cur = self._conn.execute(
                    "INSERT INTO metrics(device_id, key, label, unit, kind,"
                    " last_value, last_ts) VALUES (?,?,?,?,?,?,?)",
                    (device_id, key, label, unit, kind, value, ts))
                metric_id = cur.lastrowid
            else:
                metric_id = row["id"]
                self._conn.execute(
                    "UPDATE metrics SET last_value=?, last_ts=?, label=?, unit=?"
                    " WHERE id=?", (value, ts, label, unit, metric_id))
            if value is not None:
                self._conn.execute(
                    "INSERT OR REPLACE INTO samples(metric_id, ts, value)"
                    " VALUES (?,?,?)", (metric_id, ts, value))
            self._conn.commit()
            return metric_id

    def metrics(self, device_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE device_id = ? ORDER BY label",
                (device_id,)).fetchall()

    def metric(self, metric_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM metrics WHERE id = ?", (metric_id,)).fetchone()

    def series(self, device_id: int, metric_id: int, t0: float, t1: float) -> list[dict]:
        """Raw-vs-hourly selection: a wide window reads the rollup table
        instead of scanning months of raw points."""
        with self._lock:
            if (t1 - t0) <= 86400 * 3:
                rows = self._conn.execute(
                    "SELECT ts, value FROM samples WHERE metric_id = ?"
                    " AND ts >= ? AND ts <= ? ORDER BY ts",
                    (metric_id, t0, t1)).fetchall()
                return [{"ts": row["ts"], "value": row["value"]} for row in rows]
            rows = self._conn.execute(
                "SELECT hour, n, vmin, vavg, vmax FROM samples_hourly"
                " WHERE metric_id = ? AND hour >= ? AND hour <= ? ORDER BY hour",
                (metric_id, t0, t1)).fetchall()
            return [{"ts": row["hour"], "min": row["vmin"], "avg": row["vavg"],
                    "max": row["vmax"], "n": row["n"]} for row in rows]

    def compact_rollup(self) -> int:
        """Aggregates any raw samples older than one hour into
        samples_hourly, min/avg/max per (metric, hour), then deletes the
        raw rows that were just rolled up. Idempotent: an hour already
        fully rolled up produces nothing new to aggregate."""
        cutoff_hour = int(time.time() // 3600) * 3600 - 3600
        with self._lock:
            rows = self._conn.execute(
                "SELECT metric_id, CAST(ts / 3600 AS INTEGER) * 3600 AS hour,"
                " COUNT(*) AS n, MIN(value) AS vmin, AVG(value) AS vavg,"
                " MAX(value) AS vmax FROM samples WHERE ts < ?"
                " GROUP BY metric_id, hour", (cutoff_hour,)).fetchall()
            for row in rows:
                self._conn.execute(
                    "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
                    " VALUES (?,?,?,?,?,?) ON CONFLICT(metric_id, hour) DO UPDATE SET"
                    " n=excluded.n, vmin=excluded.vmin, vavg=excluded.vavg,"
                    " vmax=excluded.vmax",
                    (row["metric_id"], row["hour"], row["n"], row["vmin"],
                     row["vavg"], row["vmax"]))
            cursor = self._conn.execute(
                "DELETE FROM samples WHERE ts < ?", (cutoff_hour,))
            self._conn.commit()
            return cursor.rowcount or 0

    # ----------------------------------------------------------------- events

    def record_device_event(self, device_id: int, kind: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO device_events(device_id, ts, kind, detail)"
                " VALUES (?,?,?,?)", (device_id, time.time(), kind, detail))
            self._conn.commit()

    def device_events(self, device_id: int | None = None, since_s: float | None = None,
                      kinds: list[str] | None = None, limit: int = 300) -> list[sqlite3.Row]:
        clauses, params = [], []
        if device_id is not None:
            clauses.append("device_id = ?")
            params.append(device_id)
        if since_s is not None:
            clauses.append("ts >= ?")
            params.append(time.time() - since_s)
        if kinds:
            marks = ",".join("?" * len(kinds))
            clauses.append(f"kind IN ({marks})")
            params.extend(kinds)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM device_events{where} ORDER BY ts DESC LIMIT ?",
                (*params, limit)).fetchall()

    def device_events_since(self, last_id: int, limit: int = 2000) -> list[sqlite3.Row]:
        """Rows newer than last_id, oldest first — the same cursor-read
        contract SnmpTrapDatabase.traps_since/SyslogDatabase.rows_since
        use, so the alert engine's drain functions are uniform across
        every source."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM device_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(last_id), int(limit))).fetchall()

    def max_device_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS m FROM device_events").fetchone()
        return int(row["m"] or 0)

    def record_interface_event(self, interface_id: int, kind: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO interface_events(interface_id, ts, kind, detail)"
                " VALUES (?,?,?,?)", (interface_id, time.time(), kind, detail))
            self._conn.commit()

    def interface_events(self, interface_id: int | None = None,
                         since_s: float | None = None, limit: int = 300) -> list[sqlite3.Row]:
        clauses, params = [], []
        if interface_id is not None:
            clauses.append("interface_id = ?")
            params.append(interface_id)
        if since_s is not None:
            clauses.append("ts >= ?")
            params.append(time.time() - since_s)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM interface_events{where} ORDER BY ts DESC LIMIT ?",
                (*params, limit)).fetchall()

    def interface_events_since(self, last_id: int, limit: int = 2000) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interface_events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(last_id), int(limit))).fetchall()

    def max_interface_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(id) AS m FROM interface_events").fetchone()
        return int(row["m"] or 0)

    def interface_by_id(self, interface_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interfaces WHERE id = ?", (interface_id,)).fetchone()

    def recent_interface_events_for(self, interface_id: int, since_s: float = 900,
                                    limit: int = 50) -> list[sqlite3.Row]:
        cutoff = time.time() - since_s
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM interface_events WHERE interface_id = ? AND ts >= ?"
                " ORDER BY ts DESC LIMIT ?", (interface_id, cutoff, limit)).fetchall()

    def interface_id_for(self, device_id: int, if_index: int) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM interfaces WHERE device_id=? AND if_index=?",
                (device_id, if_index)).fetchone()
        return row["id"] if row else None

    # ------------------------------------------------------------------- MIBs

    def add_mib_file(self, filename: str, module: str, object_count: int,
                     unresolved: list[str], parse_notes: str,
                     content: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO mib_files(filename, module, uploaded_ts, object_count,"
                " unresolved, parse_notes, content) VALUES (?,?,?,?,?,?,?)",
                (filename, module, time.time(), object_count,
                 json.dumps(unresolved), parse_notes, content))
            self._conn.commit()
            return cur.lastrowid

    def update_mib_file(self, mib_file_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items()
                  if k in ("module", "object_count", "unresolved", "parse_notes")}
        if not allowed:
            return
        if "unresolved" in allowed:
            allowed["unresolved"] = json.dumps(allowed["unresolved"])
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE mib_files SET {clauses} WHERE id = ?",
                (*allowed.values(), mib_file_id))
            self._conn.commit()

    def replace_mib_objects(self, mib_file_id: int, objects: list[dict]) -> None:
        """Deletes and re-inserts every non-edited object; rows with
        edited=1 are left untouched so an admin's manual correction
        survives a re-resolve."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM mib_objects WHERE mib_file_id = ? AND edited = 0",
                (mib_file_id,))
            for obj in objects:
                self._conn.execute(
                    "INSERT INTO mib_objects(mib_file_id, name, oid, description,"
                    " syntax, enums, is_notification) VALUES (?,?,?,?,?,?,?)"
                    " ON CONFLICT(mib_file_id, name) DO UPDATE SET"
                    " oid=excluded.oid, description=excluded.description,"
                    " syntax=excluded.syntax, enums=excluded.enums,"
                    " is_notification=excluded.is_notification"
                    " WHERE mib_objects.edited = 0",
                    (mib_file_id, obj["name"], obj.get("oid"), obj.get("description"),
                     obj.get("syntax"), json.dumps(obj["enums"]) if obj.get("enums") else None,
                     1 if obj.get("is_notification") else 0))
            self._conn.commit()

    def mib_files(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM mib_files ORDER BY uploaded_ts DESC").fetchall()

    def mib_file(self, mib_file_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM mib_files WHERE id = ?", (mib_file_id,)).fetchone()

    def mib_objects(self, mib_file_id: int | None = None,
                    resolved_only: bool = False) -> list[sqlite3.Row]:
        clauses, params = [], []
        if mib_file_id is not None:
            clauses.append("mib_file_id = ?")
            params.append(mib_file_id)
        if resolved_only:
            clauses.append("oid IS NOT NULL")
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM mib_objects{where} ORDER BY name", params).fetchall()

    def all_known_oids(self) -> dict[str, str]:
        """Every resolved mib_objects name -> OID, across every uploaded
        file — fed into mibparse.resolve()'s `known` dict so a later
        upload can resolve against an earlier one's objects."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, oid FROM mib_objects WHERE oid IS NOT NULL").fetchall()
        return {row["name"]: row["oid"] for row in rows}

    def update_mib_object(self, object_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items()
                  if k in ("name", "oid", "description", "syntax", "enums")}
        if not allowed:
            return
        if "enums" in allowed and allowed["enums"] is not None:
            allowed["enums"] = json.dumps(allowed["enums"])
        allowed["edited"] = 1
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE mib_objects SET {clauses} WHERE id = ?",
                (*allowed.values(), object_id))
            self._conn.commit()

    def remove_mib_file(self, mib_file_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM mib_files WHERE id = ?", (mib_file_id,))
            self._conn.commit()

    def oid_name_lines(self) -> str:
        """Every resolved mib_objects OID -> name pair, rendered as
        'OID = name' lines — feeds Service._snmp_settings_with_mibs() and
        Nodes' own OID name resolution."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT oid, name FROM mib_objects WHERE oid IS NOT NULL"
            ).fetchall()
        return "\n".join(f"{row['oid']} = {row['name']}" for row in rows)

    # ------------------------------------------------------------- discovery

    def add_discovery_job(self, kind: str, target: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO discovery_jobs(kind, target, started_ts)"
                " VALUES (?,?,?)", (kind, target, time.time()))
            self._conn.commit()
            return cur.lastrowid

    def update_discovery_job(self, job_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items() if k in
                  ("state", "total", "probed", "responded", "identified",
                   "finished_ts", "error")}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE discovery_jobs SET {clauses} WHERE id = ?",
                (*allowed.values(), job_id))
            self._conn.commit()

    def discovery_jobs(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_jobs ORDER BY started_ts DESC LIMIT ?",
                (limit,)).fetchall()

    def discovery_job(self, job_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_jobs WHERE id = ?", (job_id,)).fetchone()

    def add_discovery_result(self, job_id: int, **fields) -> int:
        cols = ["job_id"] + list(fields.keys())
        vals = [job_id] + list(fields.values())
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO discovery_results({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def discovery_results(self, job_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_results WHERE job_id = ? ORDER BY ip",
                (job_id,)).fetchall()

    def discovery_result(self, result_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM discovery_results WHERE id = ?", (result_id,)).fetchone()

    def mark_promoted(self, result_id: int, device_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE discovery_results SET promoted_device_id = ? WHERE id = ?",
                (device_id, result_id))
            self._conn.commit()

    # -------------------------------------------------------------- storage

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def prune(self, *, sample_days: float = 400, rollup_days: float = 0,
             event_days: float = 180, poll_days: float = 0,
             discovery_days: float = 30, max_samples: int = 0) -> int:
        """Trims the unbounded tables only: samples, device/interface
        events, discovery jobs. Devices, groups, interfaces and MIBs are
        current-state tables, never pruned by age here."""
        removed = 0
        now = time.time()
        with self._lock:
            # Unconditional, like every other module's prune() — a caller
            # that wants "delete everything now" (the Settings page's
            # maintenance button) passes 0, which computes a cutoff of
            # "now" and so matches every existing row; a 0 that instead
            # skipped the DELETE entirely would make that button silently
            # do nothing, as it originally did before this fix.
            cursor = self._conn.execute(
                "DELETE FROM samples WHERE ts < ?", (now - sample_days * 86400,))
            removed += cursor.rowcount or 0
            cursor = self._conn.execute(
                "DELETE FROM device_events WHERE ts < ?", (now - event_days * 86400,))
            removed += cursor.rowcount or 0
            cursor = self._conn.execute(
                "DELETE FROM interface_events WHERE ts < ?", (now - event_days * 86400,))
            removed += cursor.rowcount or 0
            cursor = self._conn.execute(
                "DELETE FROM discovery_jobs WHERE started_ts < ? AND state != 'running'",
                (now - discovery_days * 86400,))
            removed += cursor.rowcount or 0
            if max_samples:
                cursor = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM samples")
                total = cursor.fetchone()["n"]
                if total > max_samples:
                    cursor = self._conn.execute(
                        "DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples"
                        " ORDER BY ts ASC LIMIT ?)", (total - max_samples,))
                    removed += cursor.rowcount or 0
            self._conn.commit()
        return removed

    def trim_to_size(self, max_bytes: int) -> int:
        if max_bytes <= 0:
            return 0
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM samples").fetchone()["n"]
                if total <= 5000:
                    break
                chunk = max(int(total * 0.15), 5000)
                cursor = self._conn.execute(
                    "DELETE FROM samples WHERE rowid IN (SELECT rowid FROM samples"
                    " ORDER BY ts ASC LIMIT ?)", (chunk,))
                removed += cursor.rowcount or 0
                self._conn.commit()
                self._conn.execute("VACUUM")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed
