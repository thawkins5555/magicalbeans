"""MapperDatabase: storage for the MAPPER module's manually-built L2 maps.

A map starts BLANK -- devices and unmanaged peers are placed on it by hand,
never auto-populated -- so this store is mostly bookkeeping for where things
were dropped and what an operator called them, plus one genuinely global
table (vlan_colors) shared by every map. There is nothing here about SNMP
polling or VLAN discovery: that data lives in nodesdb (neighbors, mac_entries)
and is read live, joined against these placements, when a map is rendered.
"""

from __future__ import annotations

import sqlite3
import time

from .sqlitebase import SqliteStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS maps (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    notes      TEXT NOT NULL DEFAULT '',
    created_ts REAL NOT NULL,
    updated_ts REAL NOT NULL,
    UNIQUE (name COLLATE NOCASE)
);

-- One row per device or unmanaged peer placed on one map. device_id and
-- peer_key are mutually exclusive (add_node enforces exactly one is set):
-- a managed device points at nodesdb.devices by id, while an unmanaged
-- CDP/LLDP neighbour -- never polled itself, only ever seen as someone
-- else's neighbour row -- is identified by a stable peer_key derived from
-- its chassis id instead.
CREATE TABLE IF NOT EXISTS map_nodes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    map_id     INTEGER NOT NULL,
    device_id  INTEGER,
    peer_key   TEXT NOT NULL DEFAULT '',
    label      TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT '',
    x          REAL NOT NULL DEFAULT 0,
    y          REAL NOT NULL DEFAULT 0,
    added_ts   REAL NOT NULL,
    FOREIGN KEY (map_id) REFERENCES maps(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_map_nodes_map ON map_nodes(map_id);
-- Two partial indexes rather than one composite UNIQUE(map_id, device_id,
-- peer_key): device_id and peer_key are never both set on the same row (one
-- is always NULL/''), so a single composite index would let the same device
-- land on a map twice as long as each row's NULL device_id/'' peer_key made
-- the tuples look distinct. Each identity gets its own uniqueness guarantee
-- in the column that actually carries it.
CREATE UNIQUE INDEX IF NOT EXISTS ux_map_nodes_device
    ON map_nodes(map_id, device_id) WHERE device_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_map_nodes_peer
    ON map_nodes(map_id, peer_key) WHERE peer_key <> '';

-- A user override of the otherwise-deterministic colour a VLAN gets on a
-- map. Global rather than per-map: VLAN 20 should draw the same colour
-- everywhere, or a strand followed from one map to another would appear to
-- change identity for no reason.
CREATE TABLE IF NOT EXISTS vlan_colors (
    vlan         INTEGER PRIMARY KEY,
    color_index  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

DEFAULTS = {
    # At or above this many VLANs on one trunk, the link collapses from
    # individually drawn strands into a single thick line -- past this
    # count, one strand per VLAN stops reading as "detail" and starts
    # reading as visual noise. 1..30, enforced by the web layer.
    "vlan_collapse_threshold": 8,
    # A genuine hard ceiling on how many strands are ever drawn
    # individually -- checked by mapper.render_plan INDEPENDENTLY of
    # vlan_collapse_threshold (count < threshold AND count < max_strands is
    # what keeps a link in "strands" mode), so a link collapses at whichever
    # of the two it reaches first: a mis-set threshold (say, left at 200)
    # cannot make a 200-VLAN trunk render 200 strands, because this cap
    # still forces it to collapse at 30. The web layer's
    # _check_mapper_settings refuses to store a pair with max_strand_vlans
    # at or below vlan_collapse_threshold going forward (there would be no
    # strand mode left to reach), but render_plan enforces its half
    # unconditionally either way. The same number is ALSO the VLAN count at
    # which link_width_max's width is reached -- one setting doing both
    # jobs, which is why the settings dialog's "Never draw more than N
    # strands" label carries a hint spelling out the second half too.
    "max_strand_vlans": 30,
    # Stroke width in px for a single undivided strand (a link carrying one
    # VLAN, or one strand of a multi-VLAN link below the collapse threshold).
    "link_width_min": 1.5,
    # Stroke width in px for a fully collapsed trunk at max_strand_vlans --
    # width scales between these two bounds with the VLAN count, so a
    # collapsed link still visually communicates "carries a lot" without
    # drawing every strand.
    "link_width_max": 14.0,
    # MAPPER-only visual theme, independent of the app-wide colour theme --
    # see MAP_STYLES below.
    "map_style": "modern",
    # Whether dragging a node rounds its position to grid_size -- off by
    # default so a freshly opened blank map doesn't fight a new operator's
    # first placement.
    "snap_to_grid": False,
    # Grid pitch in px, used only when snap_to_grid is on.
    "grid_size": 20,
    # A small label at each end of a link naming that end's own port
    # (link.a_port/b_port, already resolved server side) -- drawn by
    # mapper.js's drawPortLabels regardless of plan.mode, since even a
    # "plain" (no known VLANs) link has two real ports.
    "show_port_labels": True,
    # The VLAN id on each drawn strand, or the VLAN count on a collapsed
    # trunk -- drawn by mapper.js's drawLink. On by default like
    # show_port_labels above; both are legible-by-default settings an
    # operator turns off on a busy map where the labels start to crowd the
    # lines, not features anyone would want to discover by opting in.
    "show_vlan_labels": True,
    # Chassis-temperature badge on a node -- off by default so a fresh map
    # is uncluttered; an operator who cares about thermals opts in per map.
    "badge_temp": False,
    "badge_cpu": False,
    "badge_ports": False,
    # Seconds between automatic refreshes while the MAPPER tab is visible;
    # 0 means manual-refresh-only (the Refresh button always works
    # regardless of this setting).
    "refresh_interval_s": 30,
    # A neighbour row older than this stops being drawn as a live link --
    # keeps a map from showing a link to a peer whose CDP/LLDP entry is
    # ageing out of nodesdb but hasn't been pruned yet.
    "stale_link_hours": 24.0,
}

# Auto-detected from vendor/sysDescr by default ('' on a node); an operator
# can force one of these instead. Exported so the web layer validates
# against the same list rather than duplicating it.
ROLES = ("", "switch", "router", "firewall", "ap", "server", "unmanaged")

# The MAPPER-only "map style" setting -- distinct from the app-wide colour
# theme, since a map's visual idiom (line weights, node chrome) is a MAPPER
# concern even for an operator using the app's "light" theme.
MAP_STYLES = ("modern", "classic", "blueprint", "minimal")


class MapperDatabase(SqliteStore):
    SCHEMA = SCHEMA
    DEFAULTS = DEFAULTS
    LABEL = "mapper.db"

    # ------------------------------------------------------------------ maps

    def maps(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM maps ORDER BY name COLLATE NOCASE").fetchall()

    def map_row(self, map_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM maps WHERE id = ?", (map_id,)).fetchone()

    def create_map(self, name: str, notes: str = "", now: float | None = None) -> int:
        name = (name or "").strip()
        if not name:
            raise ValueError("Map name cannot be blank.")
        now = time.time() if now is None else now
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM maps WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
            if existing is not None:
                raise ValueError(f"A map named \"{name}\" already exists.")
            cur = self._conn.execute(
                "INSERT INTO maps(name, notes, created_ts, updated_ts)"
                " VALUES (?,?,?,?)", (name, notes or "", now, now))
            self._conn.commit()
            return int(cur.lastrowid)

    def rename_map(self, map_id: int, name: str, notes: str | None = None,
                   now: float | None = None) -> None:
        name = (name or "").strip()
        if not name:
            raise ValueError("Map name cannot be blank.")
        now = time.time() if now is None else now
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM maps WHERE name = ? COLLATE NOCASE AND id != ?",
                (name, map_id)).fetchone()
            if existing is not None:
                raise ValueError(f"A map named \"{name}\" already exists.")
            if notes is None:
                self._conn.execute(
                    "UPDATE maps SET name = ?, updated_ts = ? WHERE id = ?",
                    (name, now, map_id))
            else:
                self._conn.execute(
                    "UPDATE maps SET name = ?, notes = ?, updated_ts = ? WHERE id = ?",
                    (name, notes, now, map_id))
            self._conn.commit()

    def delete_map(self, map_id: int) -> bool:
        # map_nodes rows are removed by the ON DELETE CASCADE declared in
        # SCHEMA (foreign_keys=ON is one of SqliteStore.PRAGMAS) -- not by a
        # DELETE here, so there is exactly one place that decides what
        # deleting a map takes with it.
        with self._lock:
            cur = self._conn.execute("DELETE FROM maps WHERE id = ?", (map_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def _touch_map(self, map_id: int, now: float | None = None) -> None:
        """Bump updated_ts. Called with the lock already held."""
        self._conn.execute(
            "UPDATE maps SET updated_ts = ? WHERE id = ?",
            (time.time() if now is None else now, map_id))

    # ----------------------------------------------------------------- nodes

    def nodes(self, map_id: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM map_nodes WHERE map_id = ? ORDER BY id", (map_id,)).fetchall()

    def add_node(self, map_id: int, *, device_id: int | None = None, peer_key: str = "",
                 label: str = "", role: str = "", x: float = 0.0, y: float = 0.0,
                 now: float | None = None) -> int:
        peer_key = peer_key or ""
        if (device_id is None) == (not peer_key):
            raise ValueError("add_node needs exactly one of device_id or peer_key.")
        if role not in ROLES:
            raise ValueError(f"Unknown role: {role!r}")
        now = time.time() if now is None else now
        with self._lock:
            if device_id is not None:
                existing = self._conn.execute(
                    "SELECT id FROM map_nodes WHERE map_id = ? AND device_id = ?",
                    (map_id, device_id)).fetchone()
            else:
                existing = self._conn.execute(
                    "SELECT id FROM map_nodes WHERE map_id = ? AND peer_key = ?",
                    (map_id, peer_key)).fetchone()
            if existing is not None:
                # Already on this map: return its id unchanged rather than
                # raising or moving it. A double-click on "add" (or an "Add
                # neighbours" helper re-offering a peer already placed) must
                # not explode, and must not undo the position an operator
                # already dragged the node to.
                return int(existing["id"])
            cur = self._conn.execute(
                "INSERT INTO map_nodes(map_id, device_id, peer_key, label, role,"
                " x, y, added_ts) VALUES (?,?,?,?,?,?,?,?)",
                (map_id, device_id, peer_key, label or "", role, x, y, now))
            self._touch_map(map_id, now)
            self._conn.commit()
            return int(cur.lastrowid)

    def update_nodes(self, map_id: int, updates: list[dict]) -> int:
        """Bulk position/label/role write, one transaction. An id that is not
        on this map is silently skipped -- a stale drag replayed from a
        browser tab that had the map open before it was deleted (here, or in
        another tab) elsewhere must not raise."""
        if not updates:
            return 0
        # Validated before a single UPDATE runs, not inside the loop: raising
        # partway through would leave the earlier rows already written into an
        # open transaction that nothing here commits or rolls back, so the next
        # unrelated commit on this connection would silently adopt half a drag.
        for item in updates:
            if "role" in item and item["role"] not in ROLES:
                raise ValueError(f"Unknown role: {item['role']!r}")
        changed = 0
        with self._lock:
            on_map = {row["id"] for row in self._conn.execute(
                "SELECT id FROM map_nodes WHERE map_id = ?", (map_id,)).fetchall()}
            for item in updates:
                node_id = item.get("id")
                if node_id not in on_map:
                    continue
                sets, vals = [], []
                for col in ("x", "y", "label", "role"):
                    if col in item:
                        sets.append(f"{col} = ?")
                        vals.append(item[col])
                if not sets:
                    continue
                vals.append(node_id)
                self._conn.execute(
                    f"UPDATE map_nodes SET {', '.join(sets)} WHERE id = ?", vals)
                changed += 1
            if changed:
                self._touch_map(map_id)
            self._conn.commit()
        return changed

    def reassign_device(self, old_device_id: int, new_device_id: int) -> int:
        """Two device rows turned out to be one: every placement of the old
        id becomes a placement of the new one. Where a map has both
        placed, the old node is deleted, not repointed — the unique index
        would refuse it, and the winner's own position is the one kept."""
        moved = 0
        now = time.time()
        with self._lock:
            touched = set()
            rows = self._conn.execute(
                "SELECT id, map_id FROM map_nodes WHERE device_id = ?",
                (old_device_id,)).fetchall()
            already = {row["map_id"] for row in self._conn.execute(
                "SELECT map_id FROM map_nodes WHERE device_id = ?",
                (new_device_id,)).fetchall()}
            for row in rows:
                if row["map_id"] in already:
                    self._conn.execute(
                        "DELETE FROM map_nodes WHERE id = ?", (row["id"],))
                else:
                    self._conn.execute(
                        "UPDATE map_nodes SET device_id = ? WHERE id = ?",
                        (new_device_id, row["id"]))
                    moved += 1
                touched.add(row["map_id"])
            for map_id in touched:
                self._touch_map(map_id, now)
            self._conn.commit()
        return moved

    def forget_device(self, device_id: int) -> int:
        """Remove every placement of a device Nodes has deleted."""
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, map_id FROM map_nodes WHERE device_id = ?",
                (int(device_id),)).fetchall()
            for row in rows:
                self._conn.execute(
                    "DELETE FROM map_nodes WHERE id = ?", (row["id"],))
            for map_id in {row["map_id"] for row in rows}:
                self._touch_map(map_id, now)
            self._conn.commit()
        return len(rows)

    def remove_node(self, map_id: int, node_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM map_nodes WHERE id = ? AND map_id = ?", (node_id, map_id))
            if cur.rowcount:
                self._touch_map(map_id)
            self._conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------ vlan colors

    def vlan_colors(self) -> dict[int, int]:
        with self._lock:
            rows = self._conn.execute("SELECT vlan, color_index FROM vlan_colors").fetchall()
        return {row["vlan"]: row["color_index"] for row in rows}

    def set_vlan_color(self, vlan: int, color_index: int | None) -> None:
        with self._lock:
            if color_index is None:
                self._conn.execute("DELETE FROM vlan_colors WHERE vlan = ?", (vlan,))
            else:
                self._conn.execute(
                    "INSERT INTO vlan_colors(vlan, color_index) VALUES (?,?)"
                    " ON CONFLICT(vlan) DO UPDATE SET color_index = excluded.color_index",
                    (vlan, color_index))
            self._conn.commit()

    # -------------------------------------------------------------- settings

    def save_settings(self, values: dict) -> None:
        if "map_style" in values and values["map_style"] not in MAP_STYLES:
            raise ValueError(f"Unknown map_style: {values['map_style']!r}")
        super().save_settings(values)
