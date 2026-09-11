"""The Nodes module's MIB corpus: uploaded files and the objects parsed out
of them.

Its own file because a vendor bundle's `content` column is a multi-megabyte
lump that would otherwise sit in the middle of the poller's hot write path,
and nothing here changes between uploads. `devices.mib_file_id` and
`groups.mib_file_id` live in nodes.db as plain integers; NodesDatabase.
remove_mib_file NULLs those when a file goes.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time

from .sqlitebase import SqliteStore

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS mib_files (
    id              INTEGER PRIMARY KEY,
    filename        TEXT NOT NULL,
    module          TEXT,
    uploaded_ts     REAL NOT NULL,
    object_count    INTEGER NOT NULL DEFAULT 0,
    unresolved      TEXT NOT NULL DEFAULT '[]',
    parse_notes     TEXT,
    -- Kept for "resolve again": mib_objects stores only the final oid, not
    -- what an unresolved object would need to retry against.
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

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class NodesMibDatabase(SqliteStore):
    """mib_files / mib_objects, and nothing else."""

    SCHEMA = SCHEMA
    DEFAULTS: dict = {}

    # Bumped by every write below and read by mib_generation. In memory
    # rather than a table: it only has to distinguish two reads within one
    # process, which is what the caches keyed on it are asking.
    _writes = 0
    LABEL = "nodes_mibs"

    # ----------------------------------------------------------------- files

    def add_mib_file(self, filename: str, module: str, object_count: int,
                     unresolved: list[str], parse_notes: str,
                     content: str = "") -> int:
        with self._lock:
            self._writes += 1
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

    def mib_files(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM mib_files ORDER BY uploaded_ts DESC").fetchall()

    def mib_file(self, mib_file_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM mib_files WHERE id = ?", (mib_file_id,)).fetchone()

    def remove_mib_file(self, mib_file_id: int) -> None:
        with self._lock:
            self._writes += 1
            self._conn.execute("DELETE FROM mib_files WHERE id = ?", (mib_file_id,))
            self._conn.commit()

    # --------------------------------------------------------------- objects

    def replace_mib_objects(self, mib_file_id: int, objects: list[dict]) -> None:
        """Deletes and re-inserts every non-edited object; rows with
        edited=1 are left untouched so an admin's manual correction
        survives a re-resolve."""
        with self._lock:
            self._writes += 1
            self._conn.execute(
                "DELETE FROM mib_objects WHERE mib_file_id = ? AND edited = 0",
                (mib_file_id,))
            # executemany, not a loop: a bundle install is tens of thousands
            # of objects and this is a save the operator sits and waits on.
            self._conn.executemany(
                "INSERT INTO mib_objects(mib_file_id, name, oid, description,"
                " syntax, enums, is_notification) VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(mib_file_id, name) DO UPDATE SET"
                " oid=excluded.oid, description=excluded.description,"
                " syntax=excluded.syntax, enums=excluded.enums,"
                " is_notification=excluded.is_notification"
                " WHERE mib_objects.edited = 0",
                [(mib_file_id, obj["name"], obj.get("oid"), obj.get("description"),
                  obj.get("syntax"),
                  json.dumps(obj["enums"]) if obj.get("enums") else None,
                  1 if obj.get("is_notification") else 0)
                 for obj in objects])
            self._conn.commit()

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
            self._writes += 1
            self._conn.execute(
                f"UPDATE mib_objects SET {clauses} WHERE id = ?",
                (*allowed.values(), object_id))
            self._conn.commit()

    # -------------------------------------------------------------- coverage

    def has_mib_covering(self, sys_object_id: str) -> bool:
        """Whether an uploaded MIB describes objects under this device's
        vendor arc. "Covering" means deeper than the bare enterprise root
        (e.g. 1.3.6.1.4.1.9 alone names the vendor but decodes nothing) —
        this app ships ~20 vendor roots, so a plain prefix test would
        never report anything missing.

        A range, not `oid LIKE 'prefix.%'`: LIKE gives ix_mib_objects_oid a
        lower bound only, so this scanned the rest of the corpus on every
        poll of every device. `'/'` is `'.'`+1 in ASCII and every OID is
        [0-9.], so the two select the identical rows. Same in
        mib_file_covering below, and in enterprise_objects."""
        from . import nodeoids
        prefix = nodeoids.enterprise_root(sys_object_id)
        if not prefix:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM mib_objects WHERE oid IS NOT NULL"
                " AND oid >= ? AND oid < ? LIMIT 1",
                (prefix + ".", prefix + "/")).fetchone()
        return row is not None

    def mib_file_covering(self, sys_object_id: str) -> int | None:
        """Which uploaded MIB describes this vendor's objects, for
        nodepoll._check_vendor_mib's auto-assignment — the one with the
        most resolved objects under the vendor arc, since a bundle is
        usually several files and only one carries the bulk of them."""
        from . import nodeoids
        prefix = nodeoids.enterprise_root(sys_object_id)
        if not prefix:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT mib_file_id, COUNT(*) AS n FROM mib_objects"
                " WHERE oid IS NOT NULL AND oid >= ? AND oid < ?"
                " GROUP BY mib_file_id ORDER BY n DESC LIMIT 1",
                (prefix + ".", prefix + "/")).fetchone()
        return row["mib_file_id"] if row else None

    def all_known_oids(self) -> dict[str, str]:
        """Every resolved mib_objects name -> OID, across every uploaded
        file — fed into mibparse.resolve()'s `known` dict so a later
        upload can resolve against an earlier one's objects."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, oid FROM mib_objects WHERE oid IS NOT NULL").fetchall()
        return {row["name"]: row["oid"] for row in rows}

    def oid_name_lines(self) -> str:
        """Every resolved mib_objects OID -> name pair, rendered as
        'OID = name' lines — feeds Service._snmp_settings_with_mibs() and
        Nodes' own OID name resolution."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT oid, name FROM mib_objects WHERE oid IS NOT NULL"
            ).fetchall()
        return "\n".join(f"{row['oid']} = {row['name']}" for row in rows)

    def enterprise_objects(self) -> list[tuple[int, str]]:
        """(mib_file_id, oid) for every resolved object under `enterprises`,
        for vendorid.build_mib_index. A range predicate, not LIKE, since
        LIKE can't use ix_mib_objects_oid — fine for one row, not for the
        tens of thousands this returns."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT mib_file_id, oid FROM mib_objects"
                " WHERE oid >= '1.3.6.1.4.1.' AND oid < '1.3.6.1.4.1/'").fetchall()
        return [(row["mib_file_id"], row["oid"]) for row in rows]

    def mib_generation(self) -> tuple:
        """Changes whenever the MIB corpus does — an upload, a delete, a
        catalog install or a resolve-all rewrite — so the poller can keep
        one built index until it is actually stale.

        The counter is what makes that true, and the shape of the table is
        why it has to be there. `mib_objects.id` is INTEGER PRIMARY KEY
        without AUTOINCREMENT, so SQLite reuses ids freed at the top of the
        table: re-resolving a file deletes its rows and re-inserts the same
        NUMBER of rows into the same id range, leaving MAX(id), the object
        count and the file count all identical. Anything keyed on those
        three alone would go on serving the pre-resolve names — numeric OIDs
        for the objects the Resolve button had just made known — until some
        unrelated MIB happened to move one of them.

        Bumped by every write here rather than by each caller, because the
        callers are several and in other modules (the resolve-all loop is in
        mibparse, the catalog install runs on its own thread) and one that
        forgets is a silent wrong answer rather than a crash.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT (SELECT MAX(id) FROM mib_objects) AS top,"
                " (SELECT COUNT(*) FROM mib_objects) AS n_objects,"
                " (SELECT COUNT(*) FROM mib_files) AS n_files").fetchone()
            writes = self._writes
        return (row["top"], row["n_objects"], row["n_files"], writes)

    # ------------------------------------------------------------- migration

    def import_legacy(self, legacy_path: str) -> tuple[int, int, int, int]:
        """Copy mib_files/mib_objects out of a pre-5.0 nodes.db, ids intact
        (devices/groups.mib_file_id already point at them). Returns (files
        here, files there, objects here, objects there) so the caller can
        refuse to drop the originals on a mismatch."""
        with self._lock:
            self._writes += 1
            self._conn.commit()
            self._conn.execute("ATTACH DATABASE ? AS old", (legacy_path,))
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO main.mib_files(id, filename, module,"
                    " uploaded_ts, object_count, unresolved, parse_notes, content)"
                    " SELECT id, filename, module, uploaded_ts, object_count,"
                    " unresolved, parse_notes, content FROM old.mib_files")
                self._conn.execute(
                    "INSERT OR IGNORE INTO main.mib_objects(id, mib_file_id, name,"
                    " oid, description, syntax, enums, is_notification, edited)"
                    " SELECT id, mib_file_id, name, oid, description, syntax,"
                    " enums, is_notification, edited FROM old.mib_objects")
                self._conn.commit()
                counts = tuple(self._conn.execute(
                    "SELECT (SELECT COUNT(*) FROM main.mib_files),"
                    " (SELECT COUNT(*) FROM old.mib_files),"
                    " (SELECT COUNT(*) FROM main.mib_objects),"
                    " (SELECT COUNT(*) FROM old.mib_objects)").fetchone())
            finally:
                try:
                    self._conn.execute("DETACH DATABASE old")
                except sqlite3.DatabaseError:
                    pass
        return counts
