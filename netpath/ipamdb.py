"""Storage for the IPAM module: subnets, discovered addresses, conflicts, and
what a Windows DHCP server reports about its scopes and leases.

Discovered rows (ping sweep plus the local ARP table) and reported rows (a
DHCP server's own records) share the tables behind a `source` marker: neither
view is complete, and a conflict is a disagreement between them.
"""

from __future__ import annotations

import ipaddress
import sqlite3
import time

from .ipam_dhcp import stored_mac
from .sqlitebase import (LIKE_ESCAPE, SqliteStore, like_contains,
                         like_prefix)


_MAC_SEPARATORS = ":-. \t"
_HEX = set("0123456789abcdefABCDEF")


def mac_search_digits(text) -> str:
    """What an operator typed, as bare lower-case hex if it could be a MAC
    or the start of one, else "".

    The search box gets a MAC in whatever spelling was nearest to hand —
    pasted from a switch (`aabb.ccdd.eeff`), from Windows (`AA-BB-CC-...`),
    from a label on the device (the last four digits, bare) — and the
    stored column has one spelling, so the comparison has to happen on a
    form both sides can be reduced to. This is that form; _mac_digits_sql
    is the column side of the same reduction.

    Not nodesdb.normalize_mac, which does the same reduction for the Nodes
    stack: the two are kept apart on purpose, so that IPAM's store does not
    import the Nodes store for a five-line string function. Not
    ipam_scan.mac_colon either — that produces the *stored* shape and
    refuses a prefix, where a prefix is exactly what an OUI search is.

    Digits-and-dots only is refused: "10.0.0.5" reduces to "10005", which is
    valid hex and would quietly turn an address search into a MAC-prefix
    search. A genuinely all-numeric MAC typed with dots is rare enough to be
    worth losing next to searching by IP, which people do constantly.
    """
    raw = str(text or "").strip()
    if not raw or all(c.isdigit() or c == "." for c in raw):
        return ""
    cleaned = "".join(c for c in raw if c not in _MAC_SEPARATORS)
    if not cleaned or len(cleaned) > 12 or any(c not in _HEX for c in cleaned):
        return ""
    return cleaned.lower()


# Fewer hex digits than this and a MAC clause is noise: "ab" is in most
# addresses, and a two-letter hostname fragment would light up half the
# lease table. The same floor nodesdb's device filter uses for its
# mac_entries clause.
MAC_SEARCH_MIN_DIGITS = 4


def _mac_digits_sql(column: str) -> str:
    """`column` reduced to bare lower-case hex in SQL — the stored side of
    mac_search_digits. The column is colon-separated lower case for every
    row written since the DHCP ingest started normalising and for every
    row _migrate rewrote, so the REPLACEs are mostly a no-op; they stay
    so a row that somehow kept an older spelling is still found rather
    than silently absent, which is indistinguishable from "not leased".
    Unindexable, like every other clause in the searches that use it —
    those are all leading-% LIKEs and already scan."""
    return f"REPLACE(REPLACE(REPLACE(LOWER({column}),'-',''),':',''),'.','')"


def scope_size(start_ip: str, end_ip: str) -> int | None:
    """Addresses in a DHCP scope's dynamic range, inclusive — shared by the
    usage donut and the leased-IP history, so both agree on what "total"
    means for a scope."""
    try:
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))
    except (ValueError, TypeError):
        return None
    return max(0, end - start + 1)


SCHEMA = """
CREATE TABLE IF NOT EXISTS subnets (
    id          INTEGER PRIMARY KEY,
    cidr        TEXT    NOT NULL UNIQUE,
    label       TEXT,
    vlan        TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_ts  REAL    NOT NULL
);

-- One row per address SappiWhere's own sweep has ever seen answer, on either
-- ICMP or ARP. `mac` is the most recently observed one; history of a MAC
-- changing lives in `conflicts`, not here.
CREATE TABLE IF NOT EXISTS hosts (
    ip          TEXT    PRIMARY KEY,
    subnet_id   INTEGER REFERENCES subnets(id) ON DELETE SET NULL,
    mac         TEXT,
    alive       INTEGER NOT NULL DEFAULT 0,
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    last_up     REAL,
    last_mac_ts REAL
);
CREATE INDEX IF NOT EXISTS ix_hosts_subnet ON hosts(subnet_id);
CREATE INDEX IF NOT EXISTS ix_hosts_mac ON hosts(mac);
-- prune_hosts deletes "last_seen < ? AND alive = 0". Equality column first,
-- so the range on last_seen runs inside the alive=0 group rather than over
-- the whole table; neither index above can serve it at all.
CREATE INDEX IF NOT EXISTS ix_hosts_alive_seen ON hosts(alive, last_seen);

-- Two different addresses answering as the same IP, caught one of two ways:
-- the sweep itself saw two MACs for one IP across scans ('scan'), or the
-- sweep's MAC for an IP disagrees with what the DHCP server most recently
-- reported for that same IP ('scan_dhcp'). Left for a person to dismiss
-- rather than auto-resolved, since only a person knows whether it was a NIC
-- swap, a DHCP server slow to expire a lease, or something worth chasing.
CREATE TABLE IF NOT EXISTS conflicts (
    id           INTEGER PRIMARY KEY,
    ip           TEXT    NOT NULL,
    mac_a        TEXT    NOT NULL,
    mac_b        TEXT    NOT NULL,
    source       TEXT    NOT NULL,
    detected_ts  REAL    NOT NULL,
    last_seen_ts REAL    NOT NULL,
    resolved_ts  REAL
);
CREATE INDEX IF NOT EXISTS ix_conflicts_open ON conflicts(ip, resolved_ts);
-- prune_conflicts ranges on resolved_ts alone, which ix_conflicts_open
-- cannot answer: that one leads with ip, and the prune constrains no ip.
CREATE INDEX IF NOT EXISTS ix_conflicts_resolved ON conflicts(resolved_ts);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    subnet_id   INTEGER NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,
    started_ts  REAL    NOT NULL,
    finished_ts REAL,
    addresses   INTEGER,
    alive       INTEGER,
    conflicts   INTEGER NOT NULL DEFAULT 0,
    status      TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS ix_scans_subnet ON scans(subnet_id, started_ts);

-- A Windows DHCP server SappiWhere reads from. Nothing here grants write
-- access. `username`/`password_enc` are optional: leave them blank to
-- authenticate as whichever Windows account runs SappiWhere, or via a
-- matching Windows Credential Manager entry — see ipam_dhcp.py. Filling
-- them in stores a credential instead, encrypted at rest; see dpapi.py.
CREATE TABLE IF NOT EXISTS dhcp_servers (
    id            INTEGER PRIMARY KEY,
    address       TEXT    NOT NULL UNIQUE,
    label         TEXT,
    enabled       INTEGER NOT NULL DEFAULT 1,
    username      TEXT,
    password_enc  BLOB,
    last_poll_ts  REAL,
    last_status   TEXT,
    last_error    TEXT,
    created_ts    REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS dhcp_scopes (
    id               INTEGER PRIMARY KEY,
    server_id        INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
    scope_id         TEXT    NOT NULL,
    name             TEXT,
    start_ip         TEXT,
    end_ip           TEXT,
    mask             TEXT,
    state            TEXT,
    lease_duration_s INTEGER,
    description      TEXT,
    router           TEXT,
    polled_ts        REAL    NOT NULL,
    UNIQUE(server_id, scope_id)
);

-- Dynamic leases and static reservations both land here — the DhcpServer
-- module reports a reservation as a lease with an AddressState that says so
-- — with `is_reservation` set from the separate reservation list so the UI
-- can tell them apart without parsing that string. `mac` is stored the way
-- hosts.mac is (ipam_scan.mac_colon: lower case, colons) rather than the
-- way the server spells it (AA-BB-CC-DD-EE-FF), so the two tables compare
-- equal for the same card and dhcp_leases_for_mac can look one up through
-- ix_dhcp_leases_mac instead of scanning; ipam_dhcp.stored_mac converts
-- at ingest and _migrate below rewrote whatever was stored before it did.
CREATE TABLE IF NOT EXISTS dhcp_leases (
    id               INTEGER PRIMARY KEY,
    server_id        INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
    scope_id         TEXT    NOT NULL,
    ip               TEXT    NOT NULL,
    mac              TEXT,
    hostname         TEXT,
    address_state    TEXT,
    lease_expires_ts REAL,
    is_reservation   INTEGER NOT NULL DEFAULT 0,
    description      TEXT,
    polled_ts        REAL    NOT NULL,
    UNIQUE(server_id, ip)
);
CREATE INDEX IF NOT EXISTS ix_dhcp_leases_scope ON dhcp_leases(server_id, scope_id);
-- Serves dhcp_leases_for_mac's equality lookup. The substring search in
-- search_dhcp cannot use it (leading-% LIKE over a REPLACE expression) and
-- never could, so before the exact lookup existed this index cost every
-- poll's wholesale re-insert something and answered nothing.
CREATE INDEX IF NOT EXISTS ix_dhcp_leases_mac ON dhcp_leases(mac);

-- One usage snapshot per scope per poll, so the DHCP page can chart the
-- leased-IP count over time rather than only ever showing the current
-- figure. dhcp_scopes/dhcp_leases above are replaced wholesale on every
-- poll and hold no history of their own — this is deliberately separate
-- so that replacement never loses anything.
CREATE TABLE IF NOT EXISTS dhcp_scope_history (
    id        INTEGER PRIMARY KEY,
    server_id INTEGER NOT NULL REFERENCES dhcp_servers(id) ON DELETE CASCADE,
    scope_id  TEXT    NOT NULL,
    leased    INTEGER NOT NULL,
    reserved  INTEGER NOT NULL,
    total     INTEGER,
    polled_ts REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dhcp_scope_history
    ON dhcp_scope_history(server_id, scope_id, polled_ts);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

DEFAULTS = {
    "enabled": True,
    "scan_interval_minutes": 60,
    "ping_timeout_ms": 800,
    "ping_workers": 64,
    # How many subnets sweep at once. The real concurrency is this times
    # ping_workers above -- 4 x 64 is 256 probes in flight -- which is why it
    # was worth a setting rather than the module constant it used to be:
    # until now it could not be changed by any means at all, from any screen
    # or any API call, because it was in neither DEFAULTS nor any dialog.
    "max_concurrent_scans": 4,
    # A safety ceiling on how many addresses one subnet may sweep, not a
    # suggestion: adding a subnet larger than this is refused outright,
    # because a fat-fingered /8 would otherwise turn into a few hundred
    # thousand ICMP probes against a live network.
    "max_scan_addresses": 1024,
    "host_retention_days": 30,
    "conflict_retention_days": 90,
    "scan_history_days": 30,
    "resolve_hosts": True,
    "dhcp_poll_interval_minutes": 15,
    "dhcp_timeout_s": 30,
    "dhcp_history_days": 35,
    # Comma-joined column keys the IPAM host table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns_hosts": "",
    # Comma-joined column keys the DHCP lease table shows; "" means the
    # frontend's defaults. Lives here rather than in the browser's
    # localStorage so it sits beside the rest of the module's settings
    # and survives Reset layout, which clears per-browser column widths
    # but must not eat a settings choice.
    "table_columns_leases": "",
}


class IpamDatabase(SqliteStore):
    # Durability kept at SQLite's default: these rows must survive a power loss.
    PRAGMAS = ("journal_mode=WAL", "synchronous=FULL", "foreign_keys=ON")
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "ipam.db"
    # Scan history is the one table here that grows without bound: subnets,
    # hosts and open conflicts are all bounded by what is on the network.
    TRIM_TABLE = "scans"
    TRIM_FLOOR = 200
    OLDEST_TS_SQL = "SELECT MIN(started_ts) FROM scans"

    # ping_workers x max_concurrent_scans is the real number of probes in
    # flight, so neither may be unbounded from a settings form: the browser's
    # max attribute is not a check, it is a hint to whoever is typing.
    MAX_CONCURRENT_SCANS = 16
    MAX_PING_WORKERS = 256

    def save_settings(self, values: dict) -> None:
        if "max_concurrent_scans" in values or "ping_workers" in values:
            values = dict(values)
            for key, ceiling in (("max_concurrent_scans", self.MAX_CONCURRENT_SCANS),
                                 ("ping_workers", self.MAX_PING_WORKERS)):
                if key in values:
                    try:
                        values[key] = max(1, min(ceiling, int(values[key])))
                    except (TypeError, ValueError):
                        values.pop(key)
        super().save_settings(values)

    def _migrate(self) -> None:
        self.ensure_columns("dhcp_servers",
                            {"username": "TEXT", "password_enc": "BLOB"})
        self.ensure_columns("dhcp_scopes", {"router": "TEXT"})
        self._normalise_lease_macs()

    # The settings row that says _normalise_lease_macs has run — the same
    # done-marker flowdb.drop_legacy_indexes keeps, for the same reason.
    _LEASE_MACS_NORMALISED = "normalised_lease_macs"

    def _normalise_lease_macs(self) -> None:
        """Rewrite dhcp_leases.mac rows stored in the server's own spelling
        (`AA-BB-CC-DD-EE-FF`) into the colon form ipam_dhcp now writes at
        ingest, so an upgraded install searches and cross-checks correctly
        from its first open rather than one poll interval later.

        Every poll replaces a server's leases wholesale, so ingest alone
        would self-heal within an interval; this makes the upgrade correct
        immediately and, more to the point, leaves nothing for a reader to
        special-case. It calls ipam_dhcp.stored_mac, the function the
        ingest path calls per row, on purpose — a second spelling of the
        rule here (a SQL rewrite, or mac_colon restated) would drift from
        the first. So an already-colon row converts to itself and is
        skipped, and a ClientId that is not a MAC at all is left exactly as
        stored, because that is what ingest does with it.

        Once, not on every open: the marker is a private settings row, and
        a store that carries it is not scanned again — the scan is the
        whole table, and an install's lease table is the one IPAM table
        that can be large. Interrupted part-way it is still correct: the
        caller holds the lock, the UPDATEs and the marker's own INSERT sit
        in one transaction, and the marker is written last, so a crash
        before the commit rolls both back and the next open starts over,
        while a crash after it has nothing left to do.
        """
        if self._private_setting(self._LEASE_MACS_NORMALISED):
            return
        rows = self._conn.execute(
            "SELECT id, mac FROM dhcp_leases WHERE mac IS NOT NULL AND mac <> ''"
        ).fetchall()
        changed = []
        for row in rows:
            canonical = stored_mac(row["mac"])
            if canonical != row["mac"]:
                changed.append((canonical, row["id"]))
        if changed:
            self._conn.executemany(
                "UPDATE dhcp_leases SET mac=? WHERE id=?", changed)
        # Joins the transaction the UPDATEs opened; its commit lands both.
        self._set_private_setting(self._LEASE_MACS_NORMALISED, True)

    # --------------------------------------------------------------- subnets

    def add_subnet(self, cidr: str, label: str | None = None,
                   vlan: str | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO subnets(cidr, label, vlan, enabled, created_ts)"
                " VALUES (?,?,?,1,?)", (cidr, label or cidr, vlan, time.time()))
            self._conn.commit()
            return int(cur.lastrowid)

    def update_subnet(self, subnet_id: int, **fields) -> None:
        allowed = {"cidr", "label", "vlan", "enabled"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        clause = ", ".join(f"{k}=?" for k in sets)
        with self._lock:
            self._conn.execute(f"UPDATE subnets SET {clause} WHERE id=?",
                               (*sets.values(), subnet_id))
            self._conn.commit()

    def remove_subnet(self, subnet_id: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE hosts SET subnet_id=NULL WHERE subnet_id=?",
                               (subnet_id,))
            self._conn.execute("DELETE FROM scans WHERE subnet_id=?", (subnet_id,))
            self._conn.execute("DELETE FROM subnets WHERE id=?", (subnet_id,))
            self._conn.commit()

    def subnets(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM subnets ORDER BY label COLLATE NOCASE").fetchall()

    def subnet(self, subnet_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM subnets WHERE id=?", (subnet_id,)).fetchone()

    def _rows_by_ids(self, table: str, ids: list[int]) -> list[sqlite3.Row]:
        """`SELECT * FROM <table> WHERE id IN (...)` — the one place the
        placeholder list is built for the *_by_ids() lookups, which otherwise
        differ only in the table they read. `table` is always a literal at
        the call site, never input."""
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        with self._lock:
            return self._conn.execute(
                f"SELECT * FROM {table} WHERE id IN ({marks})", ids).fetchall()

    def subnets_by_ids(self, subnet_ids: list[int]) -> list[sqlite3.Row]:
        """subnet() for many ids in one query, for labeling a handful of
        subnets (e.g. ones currently mid-scan) without loading the whole
        table."""
        return self._rows_by_ids("subnets", subnet_ids)

    # ----------------------------------------------------------------- scans

    def start_scan(self, subnet_id: int, address_count: int) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans(subnet_id, started_ts, addresses, status)"
                " VALUES (?,?,?,'running')", (subnet_id, time.time(), address_count))
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, alive: int, conflicts: int,
                    error: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_ts=?, alive=?, conflicts=?,"
                " status=?, error=? WHERE id=?",
                (time.time(), alive, conflicts, "error" if error else "ok",
                 error, scan_id))
            self._conn.commit()

    def recent_scans(self, subnet_id: int | None = None, limit: int = 20) -> list:
        with self._lock:
            if subnet_id is not None:
                return self._conn.execute(
                    "SELECT * FROM scans WHERE subnet_id=?"
                    " ORDER BY started_ts DESC LIMIT ?", (subnet_id, limit)).fetchall()
            return self._conn.execute(
                "SELECT * FROM scans ORDER BY started_ts DESC LIMIT ?",
                (limit,)).fetchall()

    def prune_scans(self, older_than_days: float) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM scans WHERE started_ts < ?", (cutoff,))
            self._conn.commit()
        return cur.rowcount or 0

    def clear_subnet_data(self, subnet_id: int) -> dict:
        """Delete every discovered host and scan record for one subnet —
        the host inventory and pie chart reset to zero, as if the subnet had
        just been added, without the subnet itself having to be removed and
        re-added. Its configuration (cidr, label, vlan, enabled) is
        untouched, and so is the conflict log: a conflict already found is a
        historical fact independent of the current inventory snapshot, and
        clearing one shouldn't quietly erase the other.
        """
        with self._lock:
            hosts = self._conn.execute(
                "DELETE FROM hosts WHERE subnet_id=?", (subnet_id,)).rowcount
            scans = self._conn.execute(
                "DELETE FROM scans WHERE subnet_id=?", (subnet_id,)).rowcount
            self._conn.commit()
        return {"hosts": hosts or 0, "scans": scans or 0}

    # ----------------------------------------------------------------- hosts

    def record_host(self, ip: str, subnet_id: int | None, alive: bool,
                    mac: str | None) -> sqlite3.Row | None:
        """Store one address's result and return its *previous* row, if any —
        the caller needs the prior MAC to notice a conflict, and reading it
        back out after the write would be one query too many."""
        now = time.time()
        with self._lock:
            previous = self._conn.execute(
                "SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
            if previous is None:
                self._conn.execute(
                    "INSERT INTO hosts(ip, subnet_id, mac, alive, first_seen,"
                    " last_seen, last_up, last_mac_ts) VALUES (?,?,?,?,?,?,?,?)",
                    (ip, subnet_id, mac, 1 if alive else 0, now, now,
                     now if alive else None, now if mac else None))
            else:
                mac_changed = mac and mac != previous["mac"]
                self._conn.execute(
                    "UPDATE hosts SET subnet_id=?, mac=COALESCE(?, mac),"
                    " alive=?, last_seen=?, last_up=COALESCE(?, last_up),"
                    " last_mac_ts=CASE WHEN ? THEN ? ELSE last_mac_ts END"
                    " WHERE ip=?",
                    (subnet_id, mac, 1 if alive else 0, now,
                     now if alive else None, mac_changed, now, ip))
            self._conn.commit()
        return previous

    def hosts(self, subnet_id: int | None = None) -> list[sqlite3.Row]:
        where = " WHERE h.subnet_id=?" if subnet_id is not None else ""
        params = [subnet_id] if subnet_id is not None else []
        with self._lock:
            return self._conn.execute(
                f"SELECT h.*, s.label AS subnet_label FROM hosts h"
                f" LEFT JOIN subnets s ON s.id = h.subnet_id{where}"
                f" ORDER BY h.ip", params).fetchall()

    def host_counts(self, subnet_id: int) -> dict:
        """Alive / previously-up-but-down-now counts for one subnet, without
        fetching every host row — used for the utilization pie chart.

        A row exists for every address that has ever been *probed*, answer or
        not, so the presence of a row says nothing about whether anything is
        there. `last_up` is the discriminator: it is only ever written when
        an address actually replied. An address that has been swept a hundred
        times and never answered has a row, alive = 0 and last_up = NULL, and
        belongs in "never seen" — counting it as "seen before, now down"
        reported an empty subnet as almost fully occupied.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total,"
                " SUM(alive) AS alive,"
                " SUM(alive = 0 AND last_up IS NOT NULL) AS seen_down"
                " FROM hosts WHERE subnet_id=?", (subnet_id,)).fetchone()
        return {"alive": row["alive"] or 0, "seen_down": row["seen_down"] or 0}

    def host(self, ip: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()

    def prune_hosts(self, older_than_days: float) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM hosts WHERE last_seen < ? AND alive = 0", (cutoff,))
            self._conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------------------- conflicts

    def record_conflict(self, ip: str, mac_a: str, mac_b: str, source: str) -> bool:
        """Open a conflict, or refresh an existing unresolved one for the same
        pair. Returns True for a newly opened conflict, which is what the
        scanner uses to decide whether this scan's summary should mention it."""
        now = time.time()
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM conflicts WHERE ip=? AND resolved_ts IS NULL"
                " AND ((mac_a=? AND mac_b=?) OR (mac_a=? AND mac_b=?))",
                (ip, mac_a, mac_b, mac_b, mac_a)).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE conflicts SET last_seen_ts=? WHERE id=?",
                    (now, existing["id"]))
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO conflicts(ip, mac_a, mac_b, source, detected_ts,"
                " last_seen_ts) VALUES (?,?,?,?,?,?)",
                (ip, mac_a, mac_b, source, now, now))
            self._conn.commit()
            return True

    def conflicts(self, include_resolved: bool = False) -> list[sqlite3.Row]:
        with self._lock:
            if include_resolved:
                return self._conn.execute(
                    "SELECT * FROM conflicts ORDER BY last_seen_ts DESC").fetchall()
            return self._conn.execute(
                "SELECT * FROM conflicts WHERE resolved_ts IS NULL"
                " ORDER BY last_seen_ts DESC").fetchall()

    def conflicts_since(self, cursor: int, limit: int | None = None
                        ) -> list[sqlite3.Row]:
        """Conflicts newer than `cursor`, oldest first, for a cursor-scoped
        reader. conflicts(include_resolved=True) read every conflict ever
        recorded (~60 ms at 20,000 rows, on every engine tick) so the caller
        could keep the handful with a higher id."""
        sql = "SELECT * FROM conflicts WHERE id > ? ORDER BY id"
        params: list = [int(cursor)]
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def conflicts_max_id(self) -> int:
        """The highest conflict id, for a drain's cursor seed and its
        backlog figure."""
        with self._lock:
            return self._conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM conflicts").fetchone()[0]

    def resolved_conflict_ids(self) -> set:
        """Ids of conflicts that have been resolved. _pair_ipam_resolutions
        intersects this with its open alerts; it has no use for the rows."""
        with self._lock:
            return {row["id"] for row in self._conn.execute(
                "SELECT id FROM conflicts WHERE resolved_ts IS NOT NULL")}

    def conflict_count(self) -> int:
        """Open conflicts, counted in SQL. /api/state used to take len() of
        conflicts() — every open row fetched and thrown away, twice a second
        per open tab."""
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM conflicts WHERE resolved_ts IS NULL").fetchone()[0]

    def resolve_conflict(self, conflict_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE conflicts SET resolved_ts=? WHERE id=?",
                (time.time(), conflict_id))
            self._conn.commit()

    def prune_conflicts(self, older_than_days: float) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM conflicts WHERE resolved_ts IS NOT NULL"
                " AND resolved_ts < ?", (cutoff,))
            self._conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------------------ dhcp: servers

    def add_dhcp_server(self, address: str, label: str | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO dhcp_servers(address, label, enabled, created_ts)"
                " VALUES (?,?,1,?)", (address, label or address, time.time()))
            self._conn.commit()
            return int(cur.lastrowid)

    def update_dhcp_server(self, server_id: int, **fields) -> None:
        allowed = {"address", "label", "enabled"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        clause = ", ".join(f"{k}=?" for k in sets)
        with self._lock:
            self._conn.execute(f"UPDATE dhcp_servers SET {clause} WHERE id=?",
                               (*sets.values(), server_id))
            self._conn.commit()

    def set_dhcp_credential(self, server_id: int, username: str,
                            password_enc: bytes) -> None:
        """Store a username and an already-encrypted password. Encryption is
        the caller's job (dpapi.py) — this method only ever sees ciphertext,
        so a bug here cannot leak a plaintext password into a query log."""
        with self._lock:
            self._conn.execute(
                "UPDATE dhcp_servers SET username=?, password_enc=? WHERE id=?",
                (username, password_enc, server_id))
            self._conn.commit()

    def clear_dhcp_credential(self, server_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE dhcp_servers SET username=NULL, password_enc=NULL WHERE id=?",
                (server_id,))
            self._conn.commit()

    def remove_dhcp_server(self, server_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM dhcp_scopes WHERE server_id=?", (server_id,))
            self._conn.execute("DELETE FROM dhcp_leases WHERE server_id=?", (server_id,))
            self._conn.execute("DELETE FROM dhcp_scope_history WHERE server_id=?", (server_id,))
            self._conn.execute("DELETE FROM dhcp_servers WHERE id=?", (server_id,))
            self._conn.commit()

    def dhcp_servers(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM dhcp_servers ORDER BY label COLLATE NOCASE").fetchall()

    def dhcp_server(self, server_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM dhcp_servers WHERE id=?", (server_id,)).fetchone()

    def dhcp_servers_by_ids(self, server_ids: list[int]) -> list[sqlite3.Row]:
        """dhcp_server() for many ids in one query — the dhcp_servers()
        counterpart to subnets_by_ids()."""
        return self._rows_by_ids("dhcp_servers", server_ids)

    def set_dhcp_poll_result(self, server_id: int, ok: bool,
                             error: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE dhcp_servers SET last_poll_ts=?, last_status=?,"
                " last_error=? WHERE id=?",
                (time.time(), "ok" if ok else "error", error, server_id))
            self._conn.commit()

    # ------------------------------------------------------- dhcp: scopes/leases

    def replace_dhcp_scopes(self, server_id: int, scopes: list[dict]) -> None:
        """A poll is a full snapshot, so scopes and leases are replaced
        wholesale rather than diffed — the DHCP server is the source of
        truth and a scope removed there should disappear here too."""
        now = time.time()
        with self._lock:
            self._conn.execute("DELETE FROM dhcp_scopes WHERE server_id=?", (server_id,))
            self._conn.executemany(
                "INSERT INTO dhcp_scopes(server_id, scope_id, name, start_ip,"
                " end_ip, mask, state, lease_duration_s, description, router,"
                " polled_ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(server_id, s.get("scope_id"), s.get("name"), s.get("start_ip"),
                  s.get("end_ip"), s.get("mask"), s.get("state"),
                  s.get("lease_duration_s"), s.get("description"), s.get("router"), now)
                 for s in scopes])
            self._conn.commit()

    def replace_dhcp_leases(self, server_id: int, leases: list[dict]) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute("DELETE FROM dhcp_leases WHERE server_id=?", (server_id,))
            self._conn.executemany(
                "INSERT INTO dhcp_leases(server_id, scope_id, ip, mac, hostname,"
                " address_state, lease_expires_ts, is_reservation, description,"
                " polled_ts) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(server_id, l.get("scope_id"), l.get("ip"), l.get("mac"),
                  l.get("hostname"), l.get("address_state"),
                  l.get("lease_expires_ts"), 1 if l.get("is_reservation") else 0,
                  l.get("description"), now)
                 for l in leases])
            self._conn.commit()

    def dhcp_scopes(self, server_id: int | None = None) -> list[sqlite3.Row]:
        where = " WHERE c.server_id=?" if server_id is not None else ""
        params = [server_id] if server_id is not None else []
        with self._lock:
            return self._conn.execute(
                f"SELECT c.*, s.label AS server_label FROM dhcp_scopes c"
                f" JOIN dhcp_servers s ON s.id = c.server_id{where}"
                f" ORDER BY s.label, c.scope_id", params).fetchall()

    def dhcp_leases(self, server_id: int | None = None,
                    scope_id: str | None = None) -> list[sqlite3.Row]:
        clauses, params = [], []
        if server_id is not None:
            clauses.append("l.server_id=?"); params.append(server_id)
        if scope_id is not None:
            clauses.append("l.scope_id=?"); params.append(scope_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            return self._conn.execute(
                f"SELECT l.*, s.label AS server_label FROM dhcp_leases l"
                f" JOIN dhcp_servers s ON s.id = l.server_id{where}"
                f" ORDER BY l.ip", params).fetchall()

    def dhcp_scope_usage(self) -> list[sqlite3.Row]:
        """(server_id, scope_id, used, reserved) per scope, counted in SQL.

        The alert engine wants two numbers per scope on every 5-second tick;
        reading dhcp_leases() for them materialised the whole lease table as
        Row objects under this database's lock (~100 ms at 24,000 leases,
        twelve times a minute) to compute a figure that changes once per
        15-minute DHCP poll. The index on (server_id, scope_id) covers this.
        """
        with self._lock:
            return self._conn.execute(
                "SELECT server_id, scope_id, COUNT(*) AS used,"
                " SUM(CASE WHEN is_reservation THEN 1 ELSE 0 END) AS reserved"
                " FROM dhcp_leases GROUP BY server_id, scope_id").fetchall()

    def record_scope_usage(self, server_id: int, scope_id: str, leased: int,
                           reserved: int, total: int | None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO dhcp_scope_history(server_id, scope_id, leased,"
                " reserved, total, polled_ts) VALUES (?,?,?,?,?,?)",
                (server_id, scope_id, leased, reserved, total, time.time()))
            self._conn.commit()

    def scope_usage_history(self, server_id: int, scope_id: str,
                            t0: float, t1: float) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT leased, reserved, total, polled_ts FROM dhcp_scope_history"
                " WHERE server_id=? AND scope_id=? AND polled_ts>=? AND polled_ts<=?"
                " ORDER BY polled_ts",
                (server_id, scope_id, t0, t1)).fetchall()

    def prune_scope_history(self, older_than_days: float) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM dhcp_scope_history WHERE polled_ts < ?", (cutoff,))
            self._conn.commit()
        return cur.rowcount or 0

    def dhcp_lease_for_ip(self, ip: str) -> sqlite3.Row | None:
        """The freshest lease record for an address, across every server —
        used by conflict detection to cross-check a scanned MAC."""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM dhcp_leases WHERE ip=? ORDER BY polled_ts DESC LIMIT 1",
                (ip,)).fetchone()

    @staticmethod
    def _mac_clause(column: str, query: str) -> tuple[str, list]:
        """The MAC half of a search WHERE, or nothing: `(" OR <expr> LIKE ?",
        [needle])` when `query` reads as at least MAC_SEARCH_MIN_DIGITS of
        hex, `("", [])` otherwise. Substring rather than prefix, matching
        what the raw `mac LIKE '%q%'` it replaces did for the one spelling
        it happened to catch: an OUI is a prefix, but the four digits on a
        device's label are the tail, and people search by both.

        A plain `mac LIKE '%query%'` looked like it did this and did not:
        the column held the server's `AA-BB-CC-DD-EE-FF` and the box held
        whatever the operator had to hand, and zero results looks exactly
        like "this address is not leased". Both sides are reduced to bare
        hex so the spelling on either cannot matter.
        """
        digits = mac_search_digits(query)
        if len(digits) < MAC_SEARCH_MIN_DIGITS:
            return "", []
        return f" OR {_mac_digits_sql(column)} LIKE ?", [f"%{digits}%"]

    def search_hosts(self, query: str, limit: int = 50) -> list[sqlite3.Row]:
        """Discovered hosts whose address or MAC contains `query`, the MAC
        in any spelling an operator might type. Bare IP and MAC lookups
        belong here rather than in the DHCP or reverse-DNS searches: a host
        SappiWhere's own sweep found can be alive with neither a lease nor
        a PTR record to its name."""
        like = like_contains(query)
        mac_sql, mac_params = self._mac_clause("h.mac", query)
        with self._lock:
            return self._conn.execute(
                "SELECT h.*, s.cidr AS subnet_cidr FROM hosts h"
                " LEFT JOIN subnets s ON s.id = h.subnet_id"
                f" WHERE h.ip LIKE ? {LIKE_ESCAPE}{mac_sql}"
                " ORDER BY h.ip LIMIT ?",
                (like, *mac_params, limit)).fetchall()

    def search_dhcp(self, query: str, limit: int = 50) -> list[sqlite3.Row]:
        """Leases and reservations whose IP, client-reported hostname or
        description contains `query`, or whose MAC does in any spelling.
        Hostname is the forward half of IPAM's name lookup — what a device
        called itself when it got the address, rather than what reverse DNS
        says now — but IP and MAC belong here too: a lease is often the only
        record of a device that never answered SappiWhere's own ping sweep
        (asleep, off-segment, or behind a firewall that drops ICMP but still
        asked the DHCP server for an address).

        "Any spelling" is a substring match on the bare hex of both sides,
        and it discards the octet boundaries with the separators: "aa:bb"
        finds 0a:ab:bc:00:00:01 as well as aa:bb:cc:dd:ee:ff. That is the
        accepted price of a search that takes the four digits off a
        device's label (a tail, not a prefix) in whatever spelling was to
        hand — one more row in a list, never a missing one. A caller that
        has a whole address and wants only that card asks
        dhcp_leases_for_mac, which compares the stored form exactly.

        The column can hold a ClientId that is not a MAC at all — a DHCPv6
        DUID, a BOOTP reservation's hardware-type-prefixed id — which
        stored_mac keeps as the server reported it and the lease table
        shows. Those are longer than twelve hex digits, so the reduction
        refuses them, and they are matched verbatim instead, in the
        server's own spelling: the term the reduced clause replaced, kept
        for the rows the reduced clause cannot describe. Only for those —
        a needle that does read as hex stays under MAC_SEARCH_MIN_DIGITS'
        floor, which a verbatim `LIKE '%ab%'` would have gone around."""
        like = like_contains(query)
        mac_sql, mac_params = self._mac_clause("l.mac", query)
        if not mac_search_digits(query):
            mac_sql, mac_params = f" OR l.mac LIKE ? {LIKE_ESCAPE}", [like]
        with self._lock:
            return self._conn.execute(
                "SELECT l.*, s.label AS server_label FROM dhcp_leases l"
                " JOIN dhcp_servers s ON s.id = l.server_id"
                f" WHERE l.ip LIKE ? {LIKE_ESCAPE}"
                f"    OR l.hostname LIKE ? {LIKE_ESCAPE}"
                f"    OR l.description LIKE ? {LIKE_ESCAPE}{mac_sql}"
                f" ORDER BY (l.hostname LIKE ? {LIKE_ESCAPE}) DESC, l.ip"
                " LIMIT ?",
                (like, like, like, *mac_params,
                 like_prefix(query), limit)).fetchall()

    def dhcp_leases_for_mac(self, mac: str, limit: int = 50) -> list[sqlite3.Row]:
        """Every lease and reservation held by one MAC, across every server,
        freshest poll first — for "where is this card" rather than "what
        matches this text": the answer is the address(es) it holds now,
        what it called itself, when the lease runs out, and whether it was
        reserved for it. `mac` is accepted in any spelling and must be a
        whole address; a prefix is a search, and search_dhcp does that.

        An equality on the stored colon form, so ix_dhcp_leases_mac answers
        it — the reason the column is normalised at ingest rather than only
        reduced at query time. `server_label` and `scope_name` come along
        because the caller is about to show the row to a person, and two
        servers can each hold a lease for the same card (a laptop that
        moved sites) that are told apart only by which server said so.
        """
        digits = mac_search_digits(mac)
        if len(digits) != 12:
            return []
        # The shape mac_colon writes, built directly: lower-case pairs,
        # colon-joined, which is what ingest and _migrate both leave in
        # the column.
        stored = ":".join(digits[i:i + 2] for i in range(0, 12, 2))
        with self._lock:
            return self._conn.execute(
                "SELECT l.*, s.label AS server_label, c.name AS scope_name"
                " FROM dhcp_leases l"
                " JOIN dhcp_servers s ON s.id = l.server_id"
                " LEFT JOIN dhcp_scopes c ON c.server_id = l.server_id"
                "                        AND c.scope_id = l.scope_id"
                " WHERE l.mac = ?"
                " ORDER BY l.polled_ts DESC, l.lease_expires_ts DESC, l.ip"
                " LIMIT ?",
                (stored, limit)).fetchall()
