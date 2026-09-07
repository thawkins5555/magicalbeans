"""The Nodes module's MIB corpus: uploaded files and the objects parsed out
of them.

Its own file because a MIB file's `content` column keeps the original text
for a later re-resolve, and a vendor bundle is a multi-megabyte lump sitting
in the middle of the poller's hot write path. Nothing else in nodes.db is
read or written at anything like that size, and nothing here changes between
uploads — so the two belong on different pages.

`devices.mib_file_id` and `groups.mib_file_id` live in nodes.db and name a
row here as a plain integer. NodesDatabase.remove_mib_file is what NULLs
those assignments when a file goes.
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

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class NodesMibDatabase(SqliteStore):
    """mib_files / mib_objects, and nothing else."""

    SCHEMA = SCHEMA
    DEFAULTS: dict = {}
    LABEL = "nodes_mibs"

    # ----------------------------------------------------------------- files

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
            self._conn.execute("DELETE FROM mib_files WHERE id = ?", (mib_file_id,))
            self._conn.commit()

    # --------------------------------------------------------------- objects

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
            self._conn.execute(
                f"UPDATE mib_objects SET {clauses} WHERE id = ?",
                (*allowed.values(), object_id))
            self._conn.commit()

    # -------------------------------------------------------------- coverage

    def has_mib_covering(self, sys_object_id: str) -> bool:
        """Whether any uploaded MIB actually describes objects belonging to
        this device's vendor, given its sysObjectID.

        "Covering" deliberately means *deeper than the bare enterprise
        arc*: this app ships enterprise-number roots for ~20 vendors, so a
        plain prefix test would match every common vendor out of the box
        and could never report anything as missing. A root-only entry
        (1.3.6.1.4.1.9, six arcs) names the vendor; it decodes nothing. An
        object below it (1.3.6.1.4.1.9.9.13.1.3.1.3, say) is a real
        description, and that is what this looks for."""
        from . import nodeoids
        prefix = nodeoids.enterprise_root(sys_object_id)
        if not prefix:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM mib_objects WHERE oid IS NOT NULL"
                " AND oid LIKE ? LIMIT 1", (prefix + ".%",)).fetchone()
        return row is not None

    def mib_file_covering(self, sys_object_id: str) -> int | None:
        """Which uploaded MIB describes this vendor's objects, for the
        auto-assignment in nodepoll._check_vendor_mib.

        has_mib_covering() answers "is there one"; this answers "which one",
        and picks the file with the most resolved objects under the vendor's
        arc when several qualify — a vendor bundle is usually several files,
        of which one carries the bulk of the real objects and the rest are
        type or registration modules that would poll nothing.
        """
        from . import nodeoids
        prefix = nodeoids.enterprise_root(sys_object_id)
        if not prefix:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT mib_file_id, COUNT(*) AS n FROM mib_objects"
                " WHERE oid IS NOT NULL AND oid LIKE ?"
                " GROUP BY mib_file_id ORDER BY n DESC LIMIT 1",
                (prefix + ".%",)).fetchone()
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
        for vendorid.build_mib_index. A range predicate rather than LIKE:
        SQLite's LIKE is case-insensitive by default and does not use
        ix_mib_objects_oid, which is fine for has_mib_covering's single row
        and not for the tens of thousands this returns."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT mib_file_id, oid FROM mib_objects"
                " WHERE oid >= '1.3.6.1.4.1.' AND oid < '1.3.6.1.4.1/'").fetchall()
        return [(row["mib_file_id"], row["oid"]) for row in rows]

    def mib_generation(self) -> tuple:
        """Changes whenever the MIB corpus does — an upload, a delete, a
        catalog install or a resolve-all rewrite — so the poller can keep
        one built index until it is actually stale."""
        with self._lock:
            row = self._conn.execute(
                "SELECT (SELECT MAX(id) FROM mib_objects) AS top,"
                " (SELECT COUNT(*) FROM mib_objects) AS n_objects,"
                " (SELECT COUNT(*) FROM mib_files) AS n_files").fetchone()
        return (row["top"], row["n_objects"], row["n_files"])

    # ------------------------------------------------------------- migration

    def import_legacy(self, legacy_path: str) -> tuple[int, int, int, int]:
        """Copy mib_files and mib_objects out of a pre-5.0 nodes.db, ids
        intact — devices.mib_file_id and groups.mib_file_id already point at
        them. Returns (files here, files there, objects here, objects there)
        so the caller can refuse to drop the originals on a mismatch.
        """
        with self._lock:
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
