"""WirelessDatabase: FortiGate Wireless Controller polling storage.

A handful of controllers, each polled directly over SNMP for its managed APs,
so a controller carries its own SNMP credential columns rather than a polling
profile. The v3 auth password is DPAPI-encrypted and never returned.
"""

from __future__ import annotations

import sqlite3
import time

from .sqlitebase import SqliteStore, reclaim

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
    status          TEXT NOT NULL DEFAULT 'other',   -- see nodeoids.CONNECTION_STATE
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
    # Same switch as Nodes' v3_verify_replies, for the same reason and
    # with the same default: the wireless poller verifies a controller's
    # signed reply since 5.8.0, and a controller behind something that
    # strips or breaks the signature needs a way to keep polling.
    "v3_verify_replies": True,
    # Comma-joined column keys the AP table shows; "" means the frontend's
    # defaults. Lives here (not in the browser's localStorage) so it sits
    # beside the rest of the dialog's settings and survives Reset layout,
    # which clears per-browser widths but must not eat a settings choice.
    "table_columns": "",
    # How to read fgWcWtpSessionRadioOperatingPower. The MIB says dBm;
    # observed FortiOS reports its own 0-100 tx-power level in the same
    # object (see nodeoids.WTP_RADIO_OPERATING_POWER). "auto" decides
    # per controller from the values that controller actually returns;
    # "dbm" and "percent" force one reading when an operator knows better.
    "radio_power_unit": "auto",
}

CONTROLLER_EDITABLE = ("name", "ip", "enabled", "snmp_version", "community",
                       "v3_user", "v3_auth_proto")


def _radio_changes(previous: dict, radios: list[dict]) -> list[str]:
    """One sentence per radio whose channel or mode moved. A radio with no
    previous row is silent (a new AP is not a channel change), and so is a
    reading that arrived or vanished — "— to 44" is a radio being enabled."""
    changes = []
    for radio in radios:
        old = previous.get(radio["radio_id"])
        if old is None:
            continue
        label = f"radio {radio['radio_id']}"
        for field, word in (("channel", "channel"), ("mode", "mode")):
            was, now = old[field], radio.get(field)
            if was and now and str(was) != str(now):
                changes.append(f"{label}: {word} {was} → {now}")
    return changes


class WirelessDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "wireless.db"
    OLDEST_TS_SQL = "SELECT MIN(ts) FROM ap_events"

    def _migrate(self) -> None:
        self.ensure_columns("access_points", {
            "ip": "TEXT", "response_ms": "REAL",
            "out_of_service": "INTEGER NOT NULL DEFAULT 0"})
        # uptime_ticks/uptime_ts are the pair detect_reboot compares, stored
        # the way nodesdb stores last_uptime_ticks/last_uptime_ts.
        self.ensure_columns("access_points", {
            "uptime_ticks": "INTEGER", "uptime_ts": "REAL",
            "session_uptime_ticks": "INTEGER", "profile": "TEXT"})
        # fgWcWtpSessionRadioMode, stored decoded rather than as the raw enum
        # so the mapping lives in one place (nodeoids.RADIO_MODE).
        self.ensure_columns("radios", {"mode": "TEXT"})
        # channel_width is the PROFILE's configured width, joined on by
        # (vdom, profile, radio id) -- there is no per-radio width in the MIB.
        self.ensure_columns("radios", {"bssid": "TEXT", "channel_width": "TEXT"})

    # ------------------------------------------------------------ controllers

    def controllers(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM controllers ORDER BY name COLLATE NOCASE").fetchall()

    def controller_count(self) -> int:
        """For /api/state, which used to fetch every controller row to count
        them on every poll."""
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM controllers").fetchone()[0]

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
            self._commit_durable()

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
                "SELECT status, out_of_service, uptime_ticks, uptime_ts"
                " FROM access_points"
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
                self._record_reboot(controller_id, wtp_id, vdom, existed, fields)
            row = self._conn.execute(
                "SELECT id FROM access_points WHERE controller_id = ? AND vdom = ?"
                " AND wtp_id = ?", (controller_id, vdom, wtp_id)).fetchone()
            return row["id"]

    # The one connection state that unambiguously means "this AP is not
    # working" (nodeoids.CONNECTION_STATE). Deliberately narrow: the
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

    def _record_reboot(self, controller_id, wtp_id, vdom, previous, fields) -> None:
        """Records ap_rebooted when fgWcWtpSessionWtpUpTime falls. The
        comparison — and the 497-day TimeTicks wrap it rules out — is Nodes'
        own detect_reboot; the import is local because nothing else in this
        storage module needs the SNMP stack behind it. Lock already held."""
        from .nodepoll import detect_reboot

        ticks = fields.get("uptime_ticks")
        read_at = fields.get("uptime_ts")
        if ticks is None or not read_at or previous["uptime_ticks"] is None:
            return
        if not previous["uptime_ts"]:
            return
        rebooted, sentence = detect_reboot(int(ticks), float(read_at),
                                           int(previous["uptime_ticks"]),
                                           float(previous["uptime_ts"]))
        if not rebooted:
            return
        name = str(fields.get("name") or wtp_id)
        self.add_ap_event(controller_id, wtp_id, vdom, name, "ap_rebooted",
                          f"{name} rebooted — {sentence}")

    def replace_radios(self, ap_id: int, radios: list[dict], *,
                       controller_id: int | None = None, wtp_id: str | None = None,
                       vdom: str = "", name: str = "") -> None:
        """The radio rows are replaced wholesale, so the diff has to be taken
        first: a channel or mode that moved (DARRP re-picking a channel, a
        radio switched to monitor) would otherwise be overwritten silently.
        The keyword arguments are what an ap_event needs and a radio row does
        not carry; without them the diff is skipped and this is a plain
        replace, which is what keeps every existing caller working."""
        with self._lock:
            previous = {}
            if controller_id is not None and wtp_id is not None:
                previous = {row["radio_id"]: row for row in self._conn.execute(
                    "SELECT radio_id, channel, mode FROM radios WHERE ap_id = ?",
                    (ap_id,)).fetchall()}
            self._conn.execute("DELETE FROM radios WHERE ap_id = ?", (ap_id,))
            for radio in radios:
                self._conn.execute(
                    "INSERT INTO radios(ap_id, radio_id, channel,"
                    " operating_power_dbm, station_count, mode, bssid,"
                    " channel_width) VALUES (?,?,?,?,?,?,?,?)",
                    (ap_id, radio["radio_id"], radio.get("channel"),
                     radio.get("operating_power_dbm"),
                     radio.get("station_count"), radio.get("mode"),
                     radio.get("bssid"), radio.get("channel_width")))
            self._conn.commit()
            for detail in _radio_changes(previous, radios):
                self.add_ap_event(controller_id, wtp_id, vdom,
                                  name or wtp_id or "", "radio_channel_changed",
                                  detail)

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

    def prune_ap_events(self, retention_days: float = 90) -> int:
        """Lifecycle events are a log, not an archive. Called from the
        service maintenance loop."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM ap_events WHERE ts < ?",
                (time.time() - retention_days * 86400,))
            removed = cur.rowcount or 0
            self._conn.commit()
        # Reclaim after the lock, in steps.
        if removed:
            reclaim(self._conn, self._lock, label="ap_events")
        return removed

    def prune_stale(self, controller_id: int, seen_wtp_ids: set[tuple[str, str]],
                    stale_after_polls: int = 5) -> list[dict]:
        """Age an AP out after `stale_after_polls` consecutive polls that
        did not see it, and return the APs removed.

        Only called for a controller whose own poll succeeded, so a transient
        controller outage cannot wipe its AP list. An AP marked out of service
        is exempt: it is never aged out and never counted as missing.
        """
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
