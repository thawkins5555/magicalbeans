"""Storage for the IPAM module: subnets, discovered addresses, conflicts, and
what a Windows DHCP server reports about its scopes and leases.

Two things land in this file that come from very different places and are
kept apart by a `source` marker rather than separate tables, because a host
row and a lease row describe the same kind of fact — an IP is in use — and
most of the useful work (conflict detection) is comparing them:

* **Discovered** — from SappiWhere's own ping sweep and a look at the local
  ARP table afterward. This only sees MAC addresses on the same broadcast
  domain as whichever machine runs SappiWhere; it cannot see across a router.
* **Reported** — pulled read-only from a Windows DHCP server's own idea of
  its scopes and leases. This has no such limit, but is bounded by whatever
  the DHCP server has itself observed or been told; a static IP assigned
  outside DHCP is invisible to it.

Neither view is complete on its own, and a live host on a real subnet is the
overlap between them. That is also where most of the value of catching a
conflict lives: a device answering on the wire with a MAC the DHCP server
never handed that address to is either squatting on a reservation or the
DHCP server's records are stale, and either is worth a look.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
import time


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
-- can tell them apart without parsing that string.
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


class IpamDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created.

        CREATE TABLE IF NOT EXISTS silently leaves an existing table alone, so
        an install from before the credential fields existed needs them added
        explicitly or the next write to dhcp_servers fails.
        """
        servers = {row["name"] for row in
                  self._conn.execute("PRAGMA table_info(dhcp_servers)").fetchall()}
        for column, definition in [("username", "TEXT"), ("password_enc", "BLOB")]:
            if column not in servers:
                self._conn.execute(
                    f"ALTER TABLE dhcp_servers ADD COLUMN {column} {definition}")

        scopes = {row["name"] for row in
                 self._conn.execute("PRAGMA table_info(dhcp_scopes)").fetchall()}
        if "router" not in scopes:
            self._conn.execute("ALTER TABLE dhcp_scopes ADD COLUMN router TEXT")

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

    def search_hosts(self, query: str, limit: int = 50) -> list[sqlite3.Row]:
        """Discovered hosts whose address or MAC contains `query`. Bare IP
        and MAC lookups belong here rather than in the DHCP or reverse-DNS
        searches: a host SappiWhere's own sweep found can be alive with
        neither a lease nor a PTR record to its name."""
        like = f"%{query}%"
        with self._lock:
            return self._conn.execute(
                "SELECT h.*, s.cidr AS subnet_cidr FROM hosts h"
                " LEFT JOIN subnets s ON s.id = h.subnet_id"
                " WHERE h.ip LIKE ? OR h.mac LIKE ?"
                " ORDER BY h.ip LIMIT ?",
                (like, like, limit)).fetchall()

    def search_dhcp(self, query: str, limit: int = 50) -> list[sqlite3.Row]:
        """Leases and reservations whose IP, MAC, client-reported hostname or
        description contains `query`. Hostname is the forward half of IPAM's
        name lookup — what a device called itself when it got the address,
        rather than what reverse DNS says now — but IP and MAC belong here
        too: a lease is often the only record of a device that never
        answered SappiWhere's own ping sweep (asleep, off-segment, or behind
        a firewall that drops ICMP but still asked the DHCP server for an
        address)."""
        like = f"%{query}%"
        with self._lock:
            return self._conn.execute(
                "SELECT l.*, s.label AS server_label FROM dhcp_leases l"
                " JOIN dhcp_servers s ON s.id = l.server_id"
                " WHERE l.ip LIKE ? OR l.mac LIKE ? OR l.hostname LIKE ?"
                "    OR l.description LIKE ?"
                " ORDER BY (l.hostname LIKE ?) DESC, l.ip"
                " LIMIT ?",
                (like, like, like, like, f"{query}%", limit)).fetchall()

    # ------------------------------------------------------------------ size

    def size_bytes(self) -> int:
        import os
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def trim_to_size(self, max_bytes: int) -> int:
        """Delete the oldest scan records until the file fits under the cap.

        Scan history is the one table here that grows without bound —
        subnets, hosts and open conflicts are all bounded by what currently
        exists on the network, not by time. Deletes in chunks and vacuums
        between them, because SQLite does not return space to the filesystem
        until it is vacuumed — without that the loop would never see the
        size fall and would empty the table.
        """
        if max_bytes <= 0:
            return 0
        removed = 0
        for _ in range(6):
            if self.size_bytes() <= max_bytes:
                break
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
                if total <= 200:
                    break
                chunk = max(int(total * 0.15), 200)
                cur = self._conn.execute(
                    "DELETE FROM scans WHERE id IN "
                    "(SELECT id FROM scans ORDER BY started_ts LIMIT ?)", (chunk,))
                removed += cur.rowcount or 0
                self._conn.commit()
                self._conn.execute("VACUUM")
                # VACUUM alone does not shrink the files in WAL mode: the freed
                # pages sit in the write-ahead log until it is checkpointed and
                # truncated, so the loop would never see the size fall.
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return removed
