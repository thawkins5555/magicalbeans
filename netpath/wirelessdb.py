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
    missed_polls    INTEGER NOT NULL DEFAULT 0,
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

-- An AP leaving the controller's own list is a real operational event
-- (someone unplugged it, it was decommissioned, it lost power), so it is
-- recorded here rather than the row simply vanishing. The Alerts engine
-- drains this table with a cursor, exactly as it drains Nodes' own
-- device_events/interface_events.
CREATE TABLE IF NOT EXISTS ap_events (
    id            INTEGER PRIMARY KEY,
    ts            REAL NOT NULL,
    controller_id INTEGER NOT NULL,
    wtp_id        TEXT NOT NULL,
    vdom          TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_ap_events_ts ON ap_events(ts);

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
    # Comma-joined column keys the AP table shows; "" means the frontend's
    # defaults. Lives here (not in the browser's localStorage) so it sits
    # beside the rest of the dialog's settings and survives Reset layout,
    # which clears per-browser widths but must not eat a settings choice.
    "table_columns": "",
    # How to read fgWcWtpSessionRadioOperatingPower. The MIB says dBm;
    # observed FortiOS reports its own 0-100 tx-power level in the same
    # object (see fortinetoids.WTP_RADIO_OPERATING_POWER). "auto" decides
    # per controller from the values that controller actually returns;
    # "dbm" and "percent" force one reading when an operator knows better.
    "radio_power_unit": "auto",
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
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Adds columns an older database predates. Same shape as
        nodesdb._migrate: diff PRAGMA table_info and ALTER TABLE what's
        missing, never rewrite the CREATE TABLE above."""
        aps = {row["name"] for row in
               self._conn.execute("PRAGMA table_info(access_points)").fetchall()}
        for column, decl in (("ip", "TEXT"), ("response_ms", "REAL")):
            if column not in aps:
                self._conn.execute(
                    f"ALTER TABLE access_points ADD COLUMN {column} {decl}")
        if "out_of_service" not in aps:
            self._conn.execute(
                "ALTER TABLE access_points ADD COLUMN"
                " out_of_service INTEGER NOT NULL DEFAULT 0")
        radios = {row["name"] for row in
                  self._conn.execute("PRAGMA table_info(radios)").fetchall()}
        if "mode" not in radios:
            # fgWcWtpSessionRadioMode. Stored as the decoded text, not the
            # raw enum, because that is what every reader of this row wants
            # and the mapping lives in one place (fortinetoids.RADIO_MODE).
            self._conn.execute("ALTER TABLE radios ADD COLUMN mode TEXT")

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
        # A poll that sees this AP is exactly the "not stale" signal
        # prune_stale's missed-poll counter needs, so upsert_ap is the
        # one place that resets it back to 0 — every AP passed here comes
        # from this poll's own seen set.
        now = time.time()
        cols = ["controller_id", "wtp_id", "vdom", "last_seen_ts", "missed_polls"] + list(fields)
        vals = [controller_id, wtp_id, vdom, now, 0] + list(fields.values())
        marks = ",".join("?" * len(vals))
        update_clause = ", ".join(f"{k} = excluded.{k}" for k in
                                  ("last_seen_ts", "missed_polls", *fields))
        with self._lock:
            existed = self._conn.execute(
                "SELECT status, out_of_service FROM access_points"
                " WHERE controller_id = ? AND vdom = ?"
                " AND wtp_id = ?", (controller_id, vdom, wtp_id)).fetchone()
            self._conn.execute(
                f"INSERT INTO access_points({','.join(cols)}) VALUES ({marks})"
                f" ON CONFLICT(controller_id, vdom, wtp_id)"
                f" DO UPDATE SET {update_clause}",
                vals)
            self._conn.commit()
            if existed is None:
                # A brand-new row is either a newly discovered AP or one
                # that was previously aged out and came back. Recording
                # ap_returned for both is deliberate: the Alerts engine
                # pairs it with wireless_ap_removed (alertrules.CLEARS) to
                # auto-resolve a standing "removed" alert, and a genuinely
                # new AP has no such alert, so for it this row is inert.
                name = str(fields.get("name") or wtp_id)
                self.add_ap_event(controller_id, wtp_id, vdom, name, "ap_returned",
                                  f"{name} is reported by its controller again")
            else:
                self._record_status_change(controller_id, wtp_id, vdom, existed,
                                           fields)
            row = self._conn.execute(
                "SELECT id FROM access_points WHERE controller_id = ? AND vdom = ?"
                " AND wtp_id = ?", (controller_id, vdom, wtp_id)).fetchone()
            return row["id"]

    # The one connection state that unambiguously means "this AP is not
    # working" (fortinetoids.CONNECTION_STATE). Deliberately narrow: the
    # states around it are `downloading_image` and `connected_image`, which an
    # AP passes through during a routine firmware upgrade, plus `standby` (an
    # AP held in reserve on purpose) and `other`, which means the controller
    # did not say. Alerting on "not online" rather than "offline" would raise
    # — and then clear — one alert per AP on every fleet upgrade, which is
    # exactly the kind of noise the 4.29.0 rollup work existed to remove.
    _OFFLINE_STATE = "offline"

    def _record_status_change(self, controller_id, wtp_id, vdom, previous,
                              fields) -> None:
        """Records ap_offline / ap_online on a connection-state transition.

        The gap this closes: an AP that stops working while its controller
        still lists it was a silent UPDATE here. upsert_ap resets missed_polls
        on every poll that sees the AP — correctly, since the poll did see it —
        so prune_stale skips it and ap_removed never fires. An AP could be
        dead for a week with nothing but a red dot on the Wireless tab.

        Mirrors ap_removed/ap_returned exactly, including the exemption: an AP
        deliberately marked out of service raises neither, for the same reason
        it is never aged out. Called with the lock already held.
        """
        if "status" not in fields:
            return
        if previous["out_of_service"]:
            return
        was_offline = (previous["status"] or "") == self._OFFLINE_STATE
        now_offline = str(fields.get("status") or "") == self._OFFLINE_STATE
        if was_offline == now_offline:
            return
        name = str(fields.get("name") or wtp_id)
        if now_offline:
            self.add_ap_event(
                controller_id, wtp_id, vdom, name, "ap_offline",
                f"{name} is offline — its controller still lists it")
        else:
            self.add_ap_event(
                controller_id, wtp_id, vdom, name, "ap_online",
                f"{name} is {fields.get('status') or 'reachable'} again")

    def replace_radios(self, ap_id: int, radios: list[dict]) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM radios WHERE ap_id = ?", (ap_id,))
            for radio in radios:
                self._conn.execute(
                    "INSERT INTO radios(ap_id, radio_id, channel,"
                    " operating_power_dbm, station_count, mode)"
                    " VALUES (?,?,?,?,?,?)",
                    (ap_id, radio["radio_id"], radio.get("channel"),
                     radio.get("operating_power_dbm"),
                     radio.get("station_count"), radio.get("mode")))
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

    def access_point(self, ap_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM access_points WHERE id = ?", (ap_id,)).fetchone()

    def set_out_of_service(self, ap_id: int, out_of_service: bool) -> None:
        """Marks an AP as deliberately out of service. Two consequences,
        both in prune_stale below: it is never aged out (so the marking —
        and the AP — survives the controller no longer reporting it, which
        is exactly what happens when someone unracks it), and its
        disappearance raises no ap_removed event, since a human already
        said they know about it.

        missed_polls resets on either flip: prune_stale skips this AP
        entirely while the flag is set, freezing whatever count it had, so
        without the reset an AP returned to service would carry its stale
        pre-marking misses and could be aged out (and alerted on) by a
        single lost reply instead of getting the full consecutive-miss
        grace window back."""
        with self._lock:
            self._conn.execute(
                "UPDATE access_points SET out_of_service = ?, missed_polls = 0"
                " WHERE id = ?",
                (1 if out_of_service else 0, ap_id))
            self._conn.commit()

    def remove_ap(self, ap_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM access_points WHERE id = ?", (ap_id,))
            self._conn.commit()

    def ap_counts(self) -> dict:
        """Tallies that agree with the AP list's Show filter, by
        construction: an out-of-service AP is counted only under
        out_of_service (its last reported status is an admin-acknowledged
        stale fact, not a live one), and "offline" means every in-service
        AP that is not online — standby, downloading_image, other included
        — exactly the set the filter's Offline choice lists."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM access_points"
                " WHERE out_of_service = 0 GROUP BY status").fetchall()
            oos = self._conn.execute(
                "SELECT COUNT(*) AS n FROM access_points"
                " WHERE out_of_service = 1").fetchone()["n"]
        counts = {"total": 0}
        for row in rows:
            counts["total"] += row["n"]
            counts[row["status"]] = row["n"]
        counts["offline"] = counts["total"] - counts.get("online", 0)
        counts["out_of_service"] = oos
        counts["total"] += oos
        return counts

    # -------------------------------------------------------------- ap events

    def add_ap_event(self, controller_id: int, wtp_id: str, vdom: str,
                     name: str, kind: str, detail: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO ap_events(ts, controller_id, wtp_id, vdom, name,"
                " kind, detail) VALUES (?,?,?,?,?,?,?)",
                (time.time(), controller_id, wtp_id, vdom, name, kind, detail))
            self._conn.commit()

    def ap_events_since(self, last_id: int, limit: int = 2000) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM ap_events WHERE id > ? ORDER BY id LIMIT ?",
                (last_id, limit)).fetchall()

    def max_ap_event_id(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT MAX(id) AS m FROM ap_events").fetchone()
        return row["m"] or 0

    def prune_ap_events(self, retention_days: float = 90) -> None:
        """Same shape as nodesdb's device_events retention: lifecycle
        events are a log, not an archive. Called from the service
        maintenance loop."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM ap_events WHERE ts < ?",
                (time.time() - retention_days * 86400,))
            self._conn.commit()

    def prune_stale(self, controller_id: int, seen_wtp_ids: set[tuple[str, str]],
                    stale_after_polls: int = 5) -> list[dict]:
        """Ages an AP out only after `stale_after_polls` consecutive polls
        that didn't see it, for a controller whose own poll otherwise
        succeeded — a real "this AP is gone", not "the controller was
        briefly unreachable" (record_poll's ok=False case never calls
        this, so a transient controller outage doesn't wipe its whole AP
        list) or "one GETNEXT reply got lost on an otherwise-fine poll"
        (a single miss on lossy SNMP-over-UDP just increments the
        counter; upsert_ap resets it back to 0 the moment the AP is seen
        again).

        An AP a human has marked out of service is exempt entirely: it is
        never aged out and never counted as missing, so the marking (and
        the row carrying it) survives the controller dropping it, which is
        precisely what happens once it is unracked.

        Returns the APs actually removed, so the caller can raise a real
        event for each rather than letting them vanish silently."""
        threshold = max(1, stale_after_polls)
        removed: list[dict] = []
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, vdom, wtp_id, name, missed_polls, out_of_service"
                " FROM access_points WHERE controller_id = ?", (controller_id,)).fetchall()
            stale_ids = []
            for row in rows:
                if row["out_of_service"]:
                    continue
                if (row["vdom"], row["wtp_id"]) in seen_wtp_ids:
                    continue
                missed = row["missed_polls"] + 1
                if missed >= threshold:
                    stale_ids.append(row["id"])
                    removed.append({"id": row["id"], "vdom": row["vdom"],
                                    "wtp_id": row["wtp_id"],
                                    "name": row["name"] or row["wtp_id"],
                                    "missed_polls": missed})
                else:
                    self._conn.execute(
                        "UPDATE access_points SET missed_polls = ? WHERE id = ?",
                        (missed, row["id"]))
            if stale_ids:
                marks = ",".join("?" * len(stale_ids))
                self._conn.execute(
                    f"DELETE FROM access_points WHERE id IN ({marks})", stale_ids)
            self._conn.commit()
            # add_ap_event is the one owner of the ap_events INSERT; the
            # RLock makes calling it from inside this lock safe.
            for ap in removed:
                self.add_ap_event(
                    controller_id, ap["wtp_id"], ap["vdom"], ap["name"], "ap_removed",
                    f"{ap['name']} is no longer reported by its controller"
                    f" (missing from {ap['missed_polls']} consecutive polls)")
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
