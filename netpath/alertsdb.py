"""Storage for the Alerts module: rule definitions, open/acknowledged/
resolved alerts, email templates, notification history, SMTP settings and
credential, and per-source evaluation cursors.

Alert volume is orders of magnitude lower than trap or syslog volume, so
unlike `syslogdb.py`/`snmptrapdb.py` there is no hourly rollup table for the
histogram — a live `GROUP BY` over `alerts` is always cheap enough, the same
reasoning `snmptrapdb.py` already used to justify skipping FTS5 search.

Exactly one OPEN or ACKED alert may exist per `dedup_key` at a time (a
partial unique index, not a full UNIQUE constraint, because the same
dedup_key legitimately recurs after a prior alert resolves) — a repeated
occurrence increments that alert's `count` rather than opening a duplicate.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id              INTEGER PRIMARY KEY,
    key             TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,          -- 'device_event'|'interface_event'|'threshold'|'trap'|'syslog'|'ipam'
    source_kind     TEXT,                   -- meaning depends on kind, see nodesdb/alertrules
    severity        INTEGER NOT NULL DEFAULT 4,   -- syslog 0-7 scale, shared across every module
    enabled         INTEGER NOT NULL DEFAULT 1,
    is_builtin      INTEGER NOT NULL DEFAULT 0,
    device_filter   TEXT NOT NULL DEFAULT '',
    threshold       REAL,
    clear_threshold REAL,
    for_polls       INTEGER NOT NULL DEFAULT 1,
    template_id     INTEGER REFERENCES templates(id) ON DELETE SET NULL,
    created_ts      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS templates (
    id              INTEGER PRIMARY KEY,
    key             TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    is_html         INTEGER NOT NULL DEFAULT 0,
    is_builtin      INTEGER NOT NULL DEFAULT 0,
    builtin_subject TEXT,
    builtin_body    TEXT,
    updated_ts      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY,
    rule_id         INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    dedup_key       TEXT NOT NULL,
    entity_kind     TEXT NOT NULL,           -- 'device'|'interface'|'trap'|'syslog'|'ipam'
    entity_id       TEXT NOT NULL,
    entity_label    TEXT NOT NULL,
    severity        INTEGER NOT NULL,
    message         TEXT NOT NULL,
    detail          TEXT,
    state           TEXT NOT NULL DEFAULT 'open',  -- open|acked|resolved
    count           INTEGER NOT NULL DEFAULT 1,
    opened_ts       REAL NOT NULL,
    last_ts         REAL NOT NULL,
    acked_ts        REAL,
    acked_by        TEXT,
    ack_note        TEXT,
    resolved_ts     REAL,
    resolved_by     TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_state_ts ON alerts(state, last_ts);
CREATE INDEX IF NOT EXISTS ix_alerts_rule ON alerts(rule_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_active_dedup
    ON alerts(dedup_key) WHERE state IN ('open', 'acked');

CREATE TABLE IF NOT EXISTS notifications (
    id              INTEGER PRIMARY KEY,
    alert_id        INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,           -- 'alert'|'renotify'|'clear'|'test'
    ts              REAL NOT NULL,
    to_addr         TEXT NOT NULL,
    subject         TEXT NOT NULL,
    ok              INTEGER NOT NULL,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS ix_notifications_ts ON notifications(ts);
CREATE INDEX IF NOT EXISTS ix_notifications_alert ON notifications(alert_id);

-- Evaluation cursors: how far each source has already been drained, so a
-- restart does not re-evaluate a source's whole history as new occurrences.
CREATE TABLE IF NOT EXISTS meta (
    source          TEXT PRIMARY KEY,
    cursor_id       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- A DPAPI blob cannot live in the generic JSON `settings` table alongside
-- ordinary string/number values, so it gets its own single-row table.
CREATE TABLE IF NOT EXISTS smtp_credential (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_enc BLOB
);
"""

DEFAULTS = {
    "enabled": True,
    "min_severity": 7,             # evaluate this severity and worse (7 = everything)
    "retention_days": 180,          # resolved alerts + notification history
    # SMTP
    "email_enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_security": "starttls",    # none|starttls|ssl
    "smtp_verify_cert": True,
    "smtp_username": "",
    "smtp_from": "",
    "smtp_from_name": "SappiWhere",
    "smtp_to_default": [],          # fallback recipients
    "smtp_timeout_s": 15.0,
    # volume control
    "renotify_minutes": 0,          # 0 = notify once per open alert, never again while open
    "notify_on_clear": True,
    "max_emails_per_hour": 60,
}

_RULE_EDITABLE = ("name", "severity", "enabled", "device_filter", "threshold",
                  "clear_threshold", "for_polls", "template_id")
_RULE_CUSTOM_EDITABLE = _RULE_EDITABLE + ("kind", "source_kind")

# 26 built-in rules: 7 device_event + 3 interface_event + 10 threshold +
# 3 trap + 1 syslog + 1 ipam + 1 wireless_event. Each `template` name is a
# templates.key —
# most non-primary rules reuse a generic template rather than a bespoke
# one, since only 5 ship; an admin can point any rule at any template.
_BUILTIN_RULES = [
    # key, name, kind, source_kind, severity, template, threshold, clear_threshold, for_polls
    ("device_down", "Device not responding", "device_event", "down", 1, "device_down", None, None, 1),
    ("device_up", "Device recovered", "device_event", "up", 5, "device_up", None, None, 1),
    ("device_rebooted", "Device rebooted", "device_event", "rebooted", 4, "device_rebooted", None, None, 1),
    ("device_auth_fail", "SNMP authentication failing", "device_event", "auth_fail", 3, "device_down", None, None, 1),
    ("device_unsupported", "Device requires unsupported SNMP privacy", "device_event", "unsupported", 5, "device_down", None, None, 1),
    ("poll_overrun", "Poll taking longer than its interval", "device_event", "poll_overrun", 4, "device_down", None, None, 1),
    ("mib_missing", "Vendor MIB not uploaded for this device", "device_event", "mib_missing", 6, "device_down", None, None, 1),
    ("interface_down", "Interface down", "interface_event", "link_down", 3, "device_down", None, None, 1),
    ("interface_up", "Interface recovered", "interface_event", "link_up", 6, "device_up", None, None, 1),
    ("interface_flapping", "Interface flapping", "interface_event", "flapping", 3, "device_down", None, None, 1),
    ("cpu_high", "CPU utilization high", "threshold", "cpu_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("mem_high", "Memory utilization high", "threshold", "mem_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("if_in_util_high", "Interface inbound utilization high", "threshold", "if_in_util_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("if_out_util_high", "Interface outbound utilization high", "threshold", "if_out_util_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("if_in_errors_high", "Interface inbound error rate high", "threshold", "if_in_error_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("if_out_errors_high", "Interface outbound error rate high", "threshold", "if_out_error_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("if_in_discards_high", "Interface inbound discard rate high", "threshold", "if_in_discard_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("if_out_discards_high", "Interface outbound discard rate high", "threshold", "if_out_discard_rate", 4, "threshold_breach", 10.0, 1.0, 2),
    ("disk_high", "Storage utilization high", "threshold", "disk_pct", 4, "threshold_breach", 90.0, 80.0, 2),
    ("response_time_high", "Ping response time high", "threshold", "ping_rtt_ms", 5, "threshold_breach", 500.0, 300.0, 2),
    ("trap_critical", "Critical SNMP trap received", "trap", "", 2, "trap_forwarded", None, None, 1),
    ("trap_cold_start", "Device cold start trap", "trap", "coldStart", 4, "trap_forwarded", None, None, 1),
    ("trap_link_down_unmanaged", "Link-down trap from an unmanaged device", "trap", "linkDown", 3, "trap_forwarded", None, None, 1),
    ("syslog_critical", "Critical syslog message", "syslog", "", 2, "trap_forwarded", None, None, 1),
    ("ipam_new_conflict", "New IPAM address conflict", "ipam", "", 4, "trap_forwarded", None, None, 1),
    ("wireless_ap_removed", "Access point removed from its controller", "wireless_event", "ap_removed", 3, "device_down", None, None, 1),
]

_BUILTIN_TEMPLATE_KEYS = ("device_down", "device_up", "device_rebooted",
                         "threshold_breach", "trap_forwarded")


class AlertsDatabase:
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
        self._seed_templates()
        self._seed_rules()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _seed_templates(self) -> None:
        from . import alertmail
        now = time.time()
        with self._lock:
            for key in _BUILTIN_TEMPLATE_KEYS:
                spec = alertmail.BUILTIN_TEMPLATES[key]
                self._conn.execute(
                    "INSERT OR IGNORE INTO templates(key, name, subject, body,"
                    " is_html, is_builtin, builtin_subject, builtin_body, updated_ts)"
                    " VALUES (?,?,?,?,0,1,?,?,?)",
                    (key, spec["name"], spec["subject"], spec["body"],
                     spec["subject"], spec["body"], now))
            self._conn.commit()

    def _seed_rules(self) -> None:
        now = time.time()
        with self._lock:
            template_ids = {row["key"]: row["id"] for row in
                            self._conn.execute("SELECT key, id FROM templates").fetchall()}
            for (key, name, kind, source_kind, severity, template_key,
                 threshold, clear_threshold, for_polls) in _BUILTIN_RULES:
                self._conn.execute(
                    "INSERT OR IGNORE INTO rules(key, name, kind, source_kind,"
                    " severity, enabled, is_builtin, device_filter, threshold,"
                    " clear_threshold, for_polls, template_id, created_ts)"
                    " VALUES (?,?,?,?,?,1,1,'',?,?,?,?,?)",
                    (key, name, kind, source_kind, severity, threshold,
                     clear_threshold, for_polls, template_ids.get(template_key), now))
            self._conn.commit()

    # --------------------------------------------------------------- settings

    def settings(self) -> dict:
        values = dict(DEFAULTS)
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
            cred = self._conn.execute(
                "SELECT password_enc FROM smtp_credential WHERE id = 1").fetchone()
        for row in rows:
            if row["key"] in values:
                try:
                    values[row["key"]] = json.loads(row["value"])
                except (ValueError, TypeError):
                    pass
        values["has_smtp_credential"] = bool(cred and cred["password_enc"])
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

    def set_smtp_credential(self, password_enc: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO smtp_credential(id, password_enc) VALUES (1, ?)"
                " ON CONFLICT(id) DO UPDATE SET password_enc=excluded.password_enc",
                (password_enc,))
            self._conn.commit()

    def clear_smtp_credential(self) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO smtp_credential(id, password_enc) VALUES (1, NULL)"
                " ON CONFLICT(id) DO UPDATE SET password_enc=NULL")
            self._conn.commit()

    def smtp_password_enc(self) -> bytes | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT password_enc FROM smtp_credential WHERE id = 1").fetchone()
        return bytes(row["password_enc"]) if row and row["password_enc"] else None

    # ------------------------------------------------------------------ rules

    def rules(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM rules ORDER BY is_builtin DESC, name COLLATE NOCASE"
            ).fetchall()

    def rule(self, rule_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()

    def rule_by_key(self, key: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM rules WHERE key = ?", (key,)).fetchone()

    def add_rule(self, key: str, name: str, kind: str, source_kind: str, **fields) -> int:
        cols = ["key", "name", "kind", "source_kind", "created_ts"]
        vals = [key, name, kind, source_kind, time.time()]
        for field_key in _RULE_EDITABLE:
            if field_key in fields and field_key != "name":
                cols.append(field_key)
                vals.append(fields[field_key])
        marks = ",".join("?" * len(vals))
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO rules({','.join(cols)}) VALUES ({marks})", vals)
            self._conn.commit()
            return cur.lastrowid

    def update_rule(self, rule_id: int, **fields) -> None:
        row = self.rule(rule_id)
        if row is None:
            return
        allowed_keys = _RULE_EDITABLE if row["is_builtin"] else _RULE_CUSTOM_EDITABLE
        allowed = {k: v for k, v in fields.items() if k in allowed_keys}
        if not allowed:
            return
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE rules SET {clauses} WHERE id = ?",
                (*allowed.values(), rule_id))
            self._conn.commit()

    def remove_rule(self, rule_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM rules WHERE id = ? AND is_builtin = 0", (rule_id,))
            self._conn.commit()
            return (cursor.rowcount or 0) > 0

    # -------------------------------------------------------------- templates

    def templates(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM templates ORDER BY is_builtin DESC, name COLLATE NOCASE"
            ).fetchall()

    def template(self, template_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()

    def template_by_key(self, key: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM templates WHERE key = ?", (key,)).fetchone()

    def add_template(self, key: str, name: str, subject: str, body: str,
                     is_html: bool = False) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO templates(key, name, subject, body, is_html,"
                " is_builtin, updated_ts) VALUES (?,?,?,?,?,0,?)",
                (key, name, subject, body, 1 if is_html else 0, time.time()))
            self._conn.commit()
            return cur.lastrowid

    def update_template(self, template_id: int, **fields) -> None:
        allowed = {k: v for k, v in fields.items()
                  if k in ("name", "subject", "body", "is_html")}
        if not allowed:
            return
        allowed["updated_ts"] = time.time()
        clauses = ", ".join(f"{key} = ?" for key in allowed)
        with self._lock:
            self._conn.execute(
                f"UPDATE templates SET {clauses} WHERE id = ?",
                (*allowed.values(), template_id))
            self._conn.commit()

    def reset_template(self, template_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE templates SET subject = builtin_subject, body = builtin_body,"
                " updated_ts = ? WHERE id = ? AND is_builtin = 1",
                (time.time(), template_id))
            self._conn.commit()

    def remove_template(self, template_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM templates WHERE id = ? AND is_builtin = 0", (template_id,))
            self._conn.commit()
            return (cursor.rowcount or 0) > 0

    # ---------------------------------------------------------------- alerts

    def alerts(self, state: str | None = None, severity: int | None = None,
              rule_id: int | None = None, device_text: str | None = None,
              text: str | None = None, t0: float | None = None,
              t1: float | None = None, limit: int = 300) -> list[sqlite3.Row]:
        clauses, params = [], []
        if state == "unresolved":
            clauses.append("state IN ('open', 'acked')")
        elif state:
            clauses.append("state = ?")
            params.append(state)
        if severity is not None:
            clauses.append("severity <= ?")
            params.append(severity)
        if rule_id is not None:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if device_text:
            clauses.append("entity_label LIKE ?")
            params.append(f"%{device_text}%")
        if text:
            clauses.append("(message LIKE ? OR entity_label LIKE ?)")
            params.extend([f"%{text}%"] * 2)
        if t0 is not None:
            clauses.append("last_ts >= ?")
            params.append(t0)
        if t1 is not None:
            clauses.append("opened_ts <= ?")
            params.append(t1)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM alerts{where} ORDER BY last_ts DESC LIMIT ?",
                (*params, limit)).fetchall()

    def alert(self, alert_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    def open_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE state = 'open'"
            ).fetchone()["n"]

    def open_summary(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT state, MIN(severity) AS worst, COUNT(*) AS n FROM alerts"
                " WHERE state IN ('open', 'acked') GROUP BY state").fetchall()
        open_n = acked_n = 0
        worst = None
        for row in rows:
            if row["state"] == "open":
                open_n = row["n"]
            elif row["state"] == "acked":
                acked_n = row["n"]
            if worst is None or (row["worst"] is not None and row["worst"] < worst):
                worst = row["worst"]
        return {"open": open_n, "acked": acked_n, "worst": worst,
               "all_acked": open_n == 0 and acked_n > 0}

    def histogram(self, t0: float, t1: float, bucket_s: float = 3600) -> list[dict]:
        bucket_s = max(float(bucket_s), 60.0)
        start = int(t0 // bucket_s) * bucket_s
        slots = max(1, int((t1 - start) / bucket_s) + 1)
        buckets = [{"t0": start + i * bucket_s, "t1": start + (i + 1) * bucket_s,
                   "total": 0, "by_severity": {}} for i in range(slots)]
        with self._lock:
            rows = self._conn.execute(
                "SELECT CAST((opened_ts - ?) / ? AS INTEGER) AS slot,"
                " severity, COUNT(*) AS n FROM alerts"
                " WHERE opened_ts >= ? AND opened_ts <= ? GROUP BY slot, severity",
                (start, bucket_s, t0, t1)).fetchall()
        for row in rows:
            index = row["slot"]
            if index is None or not (0 <= index < slots):
                continue
            buckets[index]["total"] += row["n"]
            key = str(row["severity"])
            by = buckets[index]["by_severity"]
            by[key] = by.get(key, 0) + row["n"]
        return buckets

    def open_or_increment(self, rule_id: int, dedup_key: str, entity_kind: str,
                          entity_id: str, entity_label: str, severity: int,
                          message: str, detail: str, ts: float) -> tuple[sqlite3.Row, bool]:
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM alerts WHERE dedup_key = ? AND state IN ('open','acked')",
                (dedup_key,)).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE alerts SET count = count + 1, last_ts = ?,"
                    " entity_label = ?, message = ?, detail = ? WHERE id = ?",
                    (ts, entity_label, message, detail, existing["id"]))
                self._conn.commit()
                row = self._conn.execute(
                    "SELECT * FROM alerts WHERE id = ?", (existing["id"],)).fetchone()
                return row, False
            cur = self._conn.execute(
                "INSERT INTO alerts(rule_id, dedup_key, entity_kind, entity_id,"
                " entity_label, severity, message, detail, opened_ts, last_ts)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (rule_id, dedup_key, entity_kind, entity_id, entity_label,
                 severity, message, detail, ts, ts))
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()
            return row, True

    def resolve(self, alert_id: int, by: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET state='resolved', resolved_ts=?, resolved_by=?"
                " WHERE id=? AND state IN ('open','acked')",
                (time.time(), by, alert_id))
            self._conn.commit()

    def resolve_many(self, alert_ids: list[int], by: str = "") -> int:
        if not alert_ids:
            return 0
        marks = ",".join("?" * len(alert_ids))
        with self._lock:
            cursor = self._conn.execute(
                f"UPDATE alerts SET state='resolved', resolved_ts=?, resolved_by=?"
                f" WHERE id IN ({marks}) AND state IN ('open','acked')",
                (time.time(), by, *alert_ids))
            self._conn.commit()
            return cursor.rowcount or 0

    def resolve_by_dedup(self, dedup_key: str, by: str = "") -> sqlite3.Row | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM alerts WHERE dedup_key = ? AND state IN ('open','acked')",
                (dedup_key,)).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE alerts SET state='resolved', resolved_ts=?, resolved_by=?"
                " WHERE id=?", (time.time(), by, row["id"]))
            self._conn.commit()
            return self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (row["id"],)).fetchone()

    def acknowledge(self, alert_id: int, by: str, note: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET state='acked', acked_ts=?, acked_by=?, ack_note=?"
                " WHERE id=? AND state='open'", (time.time(), by, note, alert_id))
            self._conn.commit()

    def acknowledge_all(self, by: str) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE alerts SET state='acked', acked_ts=?, acked_by=?"
                " WHERE state='open'", (time.time(), by))
            self._conn.commit()
            return cursor.rowcount or 0

    # ------------------------------------------------------------ notifications

    def record_notification(self, alert_id: int | None, kind: str, to_addr: str,
                            subject: str, ok: bool, error: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO notifications(alert_id, kind, ts, to_addr, subject,"
                " ok, error) VALUES (?,?,?,?,?,?,?)",
                (alert_id, kind, time.time(), to_addr, subject, 1 if ok else 0, error))
            self._conn.commit()

    def notifications_for(self, alert_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM notifications WHERE alert_id = ? ORDER BY ts DESC",
                (alert_id,)).fetchall()

    # ----------------------------------------------------------------- cursors

    def cursor(self, source: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT cursor_id FROM meta WHERE source = ?", (source,)).fetchone()
        return row["cursor_id"] if row else 0

    def has_cursor(self, source: str) -> bool:
        """Whether `source` has ever been seeded, distinct from cursor()
        legitimately returning 0 once it has been. A fresh install must
        seed every cursor to each source's current max id on its first
        tick — never to 0 — so it doesn't evaluate a source's entire
        pre-existing history as brand new occurrences."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM meta WHERE source = ?", (source,)).fetchone()
        return row is not None

    def set_cursor(self, source: str, value: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(source, cursor_id) VALUES (?,?)"
                " ON CONFLICT(source) DO UPDATE SET cursor_id=excluded.cursor_id",
                (source, value))
            self._conn.commit()

    # ------------------------------------------------------------------ storage

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def prune(self, retention_days: float, max_rows: int = 0) -> int:
        """Deletes resolved alerts (and, via the FK, their notifications)
        older than the cutoff. Open/acknowledged alerts are never pruned
        by age or count — an alert nobody has resolved does not silently
        disappear from history because it has been open a long time."""
        removed = 0
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM alerts WHERE state = 'resolved' AND resolved_ts < ?",
                (cutoff,))
            removed += cursor.rowcount or 0
            if max_rows:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM alerts WHERE state = 'resolved'"
                ).fetchone()["n"]
                if total > max_rows:
                    cursor = self._conn.execute(
                        "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts"
                        " WHERE state = 'resolved' ORDER BY resolved_ts ASC LIMIT ?)",
                        (total - max_rows,))
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
                    "SELECT COUNT(*) AS n FROM alerts WHERE state = 'resolved'"
                ).fetchone()["n"]
                if total <= 500:
                    break
                chunk = max(int(total * 0.15), 200)
                cursor = self._conn.execute(
                    "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts"
                    " WHERE state = 'resolved' ORDER BY resolved_ts ASC LIMIT ?)",
                    (chunk,))
                removed += cursor.rowcount or 0
                self._conn.commit()
                self._conn.execute("VACUUM")
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed
