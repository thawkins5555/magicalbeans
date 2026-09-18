"""MapperDatabase: maps, map_nodes (cascade-deleted with their map, one
device or peer per map enforced by two partial unique indexes), the global
vlan_colors override table, and settings coercion/validation.
"""
import sqlite3
import time

from _paths import tmpdir

from netpath.mapperdb import (DEFAULTS, FRAME_COLOR_MAX, FRAME_TEXT_SIZE_MAX, MAP_STYLES,
                              MapperDatabase, ROLES)

TMPDIR = tmpdir("mapperdb_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_db(name: str) -> MapperDatabase:
    return MapperDatabase(f"{TMPDIR}/{name}.db")


# ------------------------------------------------------------------- maps

db = new_db("maps")

map_id = db.create_map("Core", "the core switches")
check("create_map returns an int id", isinstance(map_id, int))

row = db.map_row(map_id)
check("map_row reads back name/notes",
      row is not None and row["name"] == "Core" and row["notes"] == "the core switches", row)

try:
    db.create_map("core")
    check("duplicate name (differing only in case) raises ValueError", False)
except ValueError as exc:
    check("duplicate name (differing only in case) raises ValueError", True)
    check("...with a readable message naming the map",
          "Core" in str(exc) or "core" in str(exc), str(exc))

try:
    db.create_map("   ")
    check("blank name raises ValueError", False)
except ValueError:
    check("blank name raises ValueError", True)

other_id = db.create_map("Edge")
try:
    db.rename_map(other_id, "core")  # "Core" (case-insensitive) already belongs to map_id
    check("rename_map to another map's name (case-insensitive) raises", False)
except ValueError:
    check("rename_map to another map's name (case-insensitive) raises", True)

before_rename = db.map_row(other_id)["updated_ts"]
db.rename_map(other_id, "Edge Ring", "notes here", now=before_rename + 10)
renamed = db.map_row(other_id)
check("rename_map updates name, notes and updated_ts",
      renamed["name"] == "Edge Ring" and renamed["notes"] == "notes here"
      and renamed["updated_ts"] == before_rename + 10, renamed)

check("delete_map on a real id returns True", db.delete_map(other_id) is True)
check("delete_map again on the same id returns False", db.delete_map(other_id) is False)
db.close()

# ------------------------------------------------------- cascade on delete

db = new_db("cascade")
map_id = db.create_map("Cascade Map")
node_id = db.add_node(map_id, device_id=1, x=1, y=2)
node2_id = db.add_node(map_id, device_id=2, x=3, y=4)
link_id = db.add_link(map_id, node_id, node2_id, "")
frame_id = db.add_frame(map_id, x=0, y=0, width=100, height=80, label="Rack A")
check("node exists before delete", len(db.nodes(map_id)) == 2)
db.delete_map(map_id)
with db._lock:
    remaining = db._conn.execute(
        "SELECT COUNT(*) AS n FROM map_nodes WHERE id = ?", (node_id,)).fetchone()["n"]
    remaining_links = db._conn.execute(
        "SELECT COUNT(*) AS n FROM map_links WHERE id = ?", (link_id,)).fetchone()["n"]
    remaining_frames = db._conn.execute(
        "SELECT COUNT(*) AS n FROM map_frames WHERE id = ?", (frame_id,)).fetchone()["n"]
check("deleting a map cascades its map_nodes rows away (foreign_keys=ON is live)",
      remaining == 0, remaining)
check("...and its map_links rows too", remaining_links == 0, remaining_links)
check("...and its map_frames rows too", remaining_frames == 0, remaining_frames)
db.close()

# ------------------------------------------------------------------ nodes

db = new_db("nodes")
map_id = db.create_map("Nodes Map")

try:
    db.add_node(map_id)
    check("add_node with neither device_id nor peer_key raises", False)
except ValueError:
    check("add_node with neither device_id nor peer_key raises", True)

try:
    db.add_node(map_id, device_id=1, peer_key="chassis:aa")
    check("add_node with both device_id and peer_key raises", False)
except ValueError:
    check("add_node with both device_id and peer_key raises", True)

first_id = db.add_node(map_id, device_id=42, x=10.0, y=20.0, role="switch")
same_id = db.add_node(map_id, device_id=42, x=999.0, y=999.0)
check("adding the same device twice returns the same id", same_id == first_id, (first_id, same_id))
row = next(r for r in db.nodes(map_id) if r["id"] == first_id)
check("...and does not reset its x/y", row["x"] == 10.0 and row["y"] == 20.0, dict(row))

peer_id = db.add_node(map_id, peer_key="chassis:aabbcc", label="unmanaged switch")
check("an unmanaged peer node is added distinctly", peer_id != first_id)

try:
    db.add_node(map_id, device_id=7, role="bogus")
    check("add_node with an invalid role raises", False)
except ValueError:
    check("add_node with an invalid role raises", True)

# ------------------------------------------------------- add_placeholder

ph_id = db.add_placeholder(map_id, label="Comm Room A")
ph_row = next(r for r in db.nodes(map_id) if r["id"] == ph_id)
check("add_placeholder inserts a device_id-NULL row with a placeholder: peer_key",
      ph_row["device_id"] is None and ph_row["peer_key"].startswith("placeholder:"),
      dict(ph_row))
check("...and its label is stored", ph_row["label"] == "Comm Room A")

try:
    db.add_placeholder(map_id, label="")
    check("add_placeholder rejects a blank label", False)
except ValueError:
    check("add_placeholder rejects a blank label", True)

try:
    db.add_placeholder(map_id, label="   ")
    check("add_placeholder rejects a whitespace-only label", False)
except ValueError:
    check("add_placeholder rejects a whitespace-only label", True)

ph2_id = db.add_placeholder(map_id, label="Comm Room A")
check("two placeholders with the same label are two distinct rows",
      ph2_id != ph_id and ph_row["peer_key"] !=
      next(r for r in db.nodes(map_id) if r["id"] == ph2_id)["peer_key"])

# ---------------------------------------------------------- update_nodes

other_map = db.create_map("Other Map")
other_node = db.add_node(other_map, device_id=42, x=0, y=0)  # same device, different map: fine

before = db.map_row(map_id)["updated_ts"]
time.sleep(0.01)
n = db.update_nodes(map_id, [
    {"id": first_id, "x": 100.0, "y": 200.0},
    {"id": peer_id, "label": "renamed peer", "role": "unmanaged"},
    {"id": other_node, "x": 5.0, "y": 5.0},  # belongs to a different map -- must be ignored
])
check("update_nodes moves/edits only the ids on this map", n == 2, n)
moved = next(r for r in db.nodes(map_id) if r["id"] == first_id)
check("...position actually moved", moved["x"] == 100.0 and moved["y"] == 200.0, dict(moved))
relabeled = next(r for r in db.nodes(map_id) if r["id"] == peer_id)
check("...label/role actually changed",
      relabeled["label"] == "renamed peer" and relabeled["role"] == "unmanaged", dict(relabeled))
other_untouched = db.map_row(other_map)
with db._lock:
    other_row = db._conn.execute(
        "SELECT x, y FROM map_nodes WHERE id = ?", (other_node,)).fetchone()
check("...an id belonging to another map is ignored, not moved",
      other_row["x"] == 0 and other_row["y"] == 0, dict(other_row))
after = db.map_row(map_id)["updated_ts"]
check("update_nodes bumps the map's updated_ts", after > before, (before, after))

try:
    db.update_nodes(map_id, [{"id": first_id, "role": "bogus"}])
    check("update_nodes with an invalid role raises", False)
except ValueError:
    check("update_nodes with an invalid role raises", True)

check("update_nodes with an empty list is a no-op returning 0",
      db.update_nodes(map_id, []) == 0)

# ------------------------------------------------------------- remove_node

check("remove_node returns False for an id that is not there",
      db.remove_node(map_id, 999999) is False)
check("remove_node returns True and removes a real node",
      db.remove_node(map_id, peer_id) is True)
check("...it is actually gone", all(r["id"] != peer_id for r in db.nodes(map_id)))
db.close()

# ---------------------------------------------------------------- map_links

db = new_db("links")
map_id = db.create_map("Links map")
a_id = db.add_node(map_id, device_id=1)
b_id = db.add_node(map_id, device_id=2)
c_id = db.add_node(map_id, device_id=3)

link_id = db.add_link(map_id, a_id, b_id, "spare fiber")
check("add_link returns an int id", isinstance(link_id, int))
rows = db.links(map_id)
check("links(map_id) reads it back",
      len(rows) == 1 and rows[0]["a_node_id"] == a_id and rows[0]["b_node_id"] == b_id
      and rows[0]["label"] == "spare fiber", [dict(r) for r in rows])

try:
    db.add_link(map_id, a_id, a_id, "")
    check("a==b raises ValueError", False)
except ValueError:
    check("a==b raises ValueError", True)

try:
    db.add_link(map_id, b_id, a_id, "reverse")
    check("a duplicate in the reverse direction raises ValueError", False)
except ValueError:
    check("a duplicate in the reverse direction raises ValueError", True)
check("...and no second row was written", len(db.links(map_id)) == 1)

try:
    db.add_link(map_id, a_id, 999999, "")
    check("a node id off this map raises ValueError", False)
except ValueError:
    check("a node id off this map raises ValueError", True)

try:
    db.add_link(map_id, a_id, c_id, "x" * 61)
    check("a label over 60 chars raises ValueError", False)
except ValueError:
    check("a label over 60 chars raises ValueError", True)

link2_id = db.add_link(map_id, a_id, c_id, "")
check("a second, distinct pair is allowed", len(db.links(map_id)) == 2)

check("delete_link returns False for an id that is not there",
      db.delete_link(map_id, 999999) is False)
check("delete_link returns True and removes a real link",
      db.delete_link(map_id, link2_id) is True)
check("...it is actually gone", len(db.links(map_id)) == 1)

# Cascade: removing a node this store's own FOREIGN KEY ... ON DELETE
# CASCADE covers (foreign_keys=ON is one of SqliteStore.PRAGMAS) -- no
# explicit delete_link call needed in remove_node itself.
db.remove_node(map_id, b_id)
check("removing a node the remaining link points at cascades the link away",
      db.links(map_id) == [])

ph_id = db.add_placeholder(map_id, label="Patch Panel")
ph_link_id = db.add_link(map_id, a_id, ph_id, "")
db.remove_node(map_id, ph_id)
check("removing a placeholder cascades its manual link away too",
      all(r["id"] != ph_link_id for r in db.links(map_id)))
db.close()

# --------------------------------------------------------------- map_frames

db = new_db("frames")
map_id = db.create_map("Frames map")

frame_id = db.add_frame(map_id, x=10, y=20, width=200, height=150, label="Core Rack", color=2)
check("add_frame returns an int id", isinstance(frame_id, int))
rows = db.frames(map_id)
check("frames(map_id) reads it back",
      len(rows) == 1 and rows[0]["x"] == 10 and rows[0]["y"] == 20
      and rows[0]["width"] == 200 and rows[0]["height"] == 150
      and rows[0]["label"] == "Core Rack" and rows[0]["color"] == 2, [dict(r) for r in rows])

blank_id = db.add_frame(map_id, x=0, y=0, width=40, height=40)
check("label/color default to '' and 0",
      next(r for r in db.frames(map_id) if r["id"] == blank_id)["label"] == "" and
      next(r for r in db.frames(map_id) if r["id"] == blank_id)["color"] == 0)
check("add_frame with no text_size argument defaults to 1 (Medium)",
      next(r for r in db.frames(map_id) if r["id"] == blank_id)["text_size"] == 1)

for size in (0, 1, 2):
    size_id = db.add_frame(map_id, x=0, y=0, width=100, height=100, text_size=size)
    check(f"add_frame stores text_size {size} and reads it back",
          next(r for r in db.frames(map_id) if r["id"] == size_id)["text_size"] == size)

for kwargs, why in (
    ({"x": 0, "y": 0, "width": 39.9, "height": 100}, "width under 40"),
    ({"x": 0, "y": 0, "width": 100, "height": 10}, "height under 40"),
    ({"x": 0, "y": 0, "label": "x" * 61, "width": 100, "height": 100}, "label over 60 chars"),
    ({"x": 0, "y": 0, "color": FRAME_COLOR_MAX + 1, "width": 100, "height": 100},
     "color out of range"),
    ({"x": 0, "y": 0, "color": -1, "width": 100, "height": 100}, "negative color"),
    ({"x": float("nan"), "y": 0, "width": 100, "height": 100}, "non-finite x"),
    ({"x": float("inf"), "y": 0, "width": 100, "height": 100}, "infinite x"),
    ({"x": True, "y": 0, "width": 100, "height": 100}, "boolean x"),
    ({"x": None, "y": 0, "width": 100, "height": 100}, "None x"),
    ({"x": "12", "y": 0, "width": 100, "height": 100}, "string x"),
    ({"x": 0, "y": 0, "color": True, "width": 100, "height": 100}, "boolean color"),
    ({"x": 0, "y": 0, "color": 2.0, "width": 100, "height": 100}, "float color"),
    ({"x": 0, "y": 0, "color": "2", "width": 100, "height": 100}, "string color"),
    ({"x": 0, "y": 0, "label": 123, "width": 100, "height": 100}, "non-string label"),
    ({"x": 0, "y": 0, "text_size": FRAME_TEXT_SIZE_MAX + 1, "width": 100, "height": 100},
     "text_size out of range"),
    ({"x": 0, "y": 0, "text_size": -1, "width": 100, "height": 100}, "negative text_size"),
    ({"x": 0, "y": 0, "text_size": True, "width": 100, "height": 100}, "boolean text_size"),
    ({"x": 0, "y": 0, "text_size": 1.0, "width": 100, "height": 100}, "float text_size"),
):
    try:
        db.add_frame(map_id, **kwargs)
        check(f"add_frame rejects {why}", False)
    except ValueError as exc:
        check(f"add_frame rejects {why}", True)
        check(f"...with a readable message ({why})", len(str(exc)) > 0, str(exc))

check("update_frame changes only the given fields",
      db.update_frame(map_id, frame_id, label="Renamed Rack") is True)
renamed = next(r for r in db.frames(map_id) if r["id"] == frame_id)
check("...label changed, position untouched",
      renamed["label"] == "Renamed Rack" and renamed["x"] == 10 and renamed["y"] == 20,
      dict(renamed))

check("update_frame moves x/y/width/height together",
      db.update_frame(map_id, frame_id, x=50, y=60, width=300, height=250) is True)
moved = next(r for r in db.frames(map_id) if r["id"] == frame_id)
check("...all four landed",
      moved["x"] == 50 and moved["y"] == 60 and moved["width"] == 300
      and moved["height"] == 250, dict(moved))

check("update_frame ignores a key that isn't a frame column",
      db.update_frame(map_id, frame_id, bogus="nope", label="Still Renamed") is True)
check("...the recognised key still landed",
      next(r for r in db.frames(map_id) if r["id"] == frame_id)["label"] == "Still Renamed")

check("update_frame on a missing frame id returns False",
      db.update_frame(map_id, 999999, label="Nope") is False)

check("update_frame(label=None) clears the label to ''",
      db.update_frame(map_id, frame_id, label=None) is True)
check("...it landed as ''",
      next(r for r in db.frames(map_id) if r["id"] == frame_id)["label"] == "")

try:
    db.update_frame(map_id, frame_id, label=123)
    check("update_frame rejects a non-string label", False)
except ValueError as exc:
    check("update_frame rejects a non-string label", True)
    check("...with a readable message", len(str(exc)) > 0, str(exc))

try:
    db.update_frame(map_id, frame_id, width=10)
    check("update_frame validates like add_frame (width under 40 raises)", False)
except ValueError:
    check("update_frame validates like add_frame (width under 40 raises)", True)

for bad_size, why in ((3, "out-of-range (3)"), (-1, "out-of-range (-1)"),
                      (True, "a boolean"), (1.0, "a float")):
    try:
        db.update_frame(map_id, frame_id, text_size=bad_size)
        check(f"update_frame rejects text_size {why}", False)
    except ValueError as exc:
        check(f"update_frame rejects text_size {why}", True)
        check(f"...with a readable message ({why})", len(str(exc)) > 0, str(exc))

for size in (0, 2, 1):
    check(f"update_frame(text_size={size}) lands",
          db.update_frame(map_id, frame_id, text_size=size) is True)
    check(f"...and reads back as {size}",
          next(r for r in db.frames(map_id) if r["id"] == frame_id)["text_size"] == size)

check("delete_frame returns False for an id that is not there",
      db.delete_frame(map_id, 999999) is False)
check("delete_frame returns True and removes a real frame",
      db.delete_frame(map_id, blank_id) is True)
check("...it is actually gone", all(r["id"] != blank_id for r in db.frames(map_id)))
db.close()

# ---------------------------------------------------------------- map_notes

db = new_db("notes")
map_id = db.create_map("Notes map")

note_id = db.add_note(map_id, x=10, y=20, width=200, height=150, text="Core Rack")
check("add_note with no text_size argument defaults to 1 (Medium)",
      next(r for r in db.notes(map_id) if r["id"] == note_id)["text_size"] == 1)

for size in (0, 1, 2):
    size_id = db.add_note(map_id, x=0, y=0, width=100, height=100, text_size=size)
    check(f"add_note stores text_size {size} and reads it back",
          next(r for r in db.notes(map_id) if r["id"] == size_id)["text_size"] == size)

for kwargs, why in (
    ({"x": 0, "y": 0, "text_size": FRAME_TEXT_SIZE_MAX + 1, "width": 100, "height": 100},
     "text_size out of range"),
    ({"x": 0, "y": 0, "text_size": -1, "width": 100, "height": 100}, "negative text_size"),
    ({"x": 0, "y": 0, "text_size": True, "width": 100, "height": 100}, "boolean text_size"),
    ({"x": 0, "y": 0, "text_size": 1.0, "width": 100, "height": 100}, "float text_size"),
):
    try:
        db.add_note(map_id, **kwargs)
        check(f"add_note rejects {why}", False)
    except ValueError as exc:
        check(f"add_note rejects {why}", True)
        check(f"...with a readable message ({why})", len(str(exc)) > 0, str(exc))

for bad_size, why in ((3, "out-of-range (3)"), (-1, "out-of-range (-1)"),
                      (True, "a boolean"), (1.0, "a float")):
    try:
        db.update_note(map_id, note_id, text_size=bad_size)
        check(f"update_note rejects text_size {why}", False)
    except ValueError as exc:
        check(f"update_note rejects text_size {why}", True)
        check(f"...with a readable message ({why})", len(str(exc)) > 0, str(exc))

for size in (0, 2, 1):
    check(f"update_note(text_size={size}) lands",
          db.update_note(map_id, note_id, text_size=size) is True)
    check(f"...and reads back as {size}",
          next(r for r in db.notes(map_id) if r["id"] == note_id)["text_size"] == size)
db.close()

# --------------------------------------------------------------- settings

db = new_db("settings")
check("DEFAULTS round-trip unchanged with nothing saved",
      db.settings()["vlan_collapse_threshold"] == DEFAULTS["vlan_collapse_threshold"])

db.save_settings({"vlan_collapse_threshold": "12", "unknown_key": "x"})
settings = db.settings()
check("a string \"12\" saved for an int default comes back as int 12",
      settings["vlan_collapse_threshold"] == 12 and isinstance(settings["vlan_collapse_threshold"], int),
      settings["vlan_collapse_threshold"])
check("an unknown key is ignored by save_settings",
      "unknown_key" not in settings, settings)

db.save_settings({"map_style": "blueprint"})
check("a valid map_style is saved", db.settings()["map_style"] == "blueprint")

try:
    db.save_settings({"map_style": "psychedelic"})
    check("an invalid map_style raises", False)
except ValueError:
    check("an invalid map_style raises", True)
check("...and the bad value was not stored", db.settings()["map_style"] == "blueprint")

check("ROLES and MAP_STYLES are exported tuples",
      isinstance(ROLES, tuple) and isinstance(MAP_STYLES, tuple))
db.close()

# ------------------------------------------------------------- vlan_colors

db = new_db("vlans")
check("vlan_colors starts empty", db.vlan_colors() == {})
db.set_vlan_color(20, 3)
db.set_vlan_color(30, 5)
check("vlan_colors reads back both overrides", db.vlan_colors() == {20: 3, 30: 5}, db.vlan_colors())
db.set_vlan_color(20, None)
check("set_vlan_color(None) clears the override", db.vlan_colors() == {30: 5}, db.vlan_colors())
db.close()

# --------------------------------------------------------- upgrade path

db = new_db("upgrade")
map_id = db.create_map("Persisted")
db.add_node(map_id, device_id=1, x=3, y=4)
db.set_vlan_color(99, 1)
db.save_settings({"grid_size": 40})
db.close()

reopened = MapperDatabase(f"{TMPDIR}/upgrade.db")
check("opening the same file twice migrates cleanly and keeps maps",
      len(reopened.maps()) == 1 and reopened.maps()[0]["name"] == "Persisted")
check("...and keeps map_nodes", len(reopened.nodes(map_id)) == 1)
check("...and keeps vlan_colors", reopened.vlan_colors() == {99: 1})
check("...and keeps settings", reopened.settings()["grid_size"] == 40)
reopened.close()

# ---------------------------------------------------- text_size install path
#
# A pre-5.39 map_frames/map_notes pair, built by hand without the text_size
# column, to prove MapperDatabase's ensure_columns migration installs it
# cleanly on top of an existing field, not just a brand-new file.

old_path = f"{TMPDIR}/pretextsize.db"
raw = sqlite3.connect(old_path)
raw.execute("""
    CREATE TABLE maps (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT NOT NULL,
        notes      TEXT NOT NULL DEFAULT '',
        created_ts REAL NOT NULL,
        updated_ts REAL NOT NULL,
        UNIQUE (name COLLATE NOCASE)
    )
""")
raw.execute("""
    CREATE TABLE map_frames (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        map_id     INTEGER NOT NULL,
        label      TEXT NOT NULL DEFAULT '',
        x          REAL NOT NULL,
        y          REAL NOT NULL,
        width      REAL NOT NULL,
        height     REAL NOT NULL,
        color      INTEGER NOT NULL DEFAULT 0,
        added_ts   REAL NOT NULL,
        FOREIGN KEY (map_id) REFERENCES maps(id) ON DELETE CASCADE
    )
""")
# Raw sqlite3.connect() does not enforce foreign keys by default, so
# node_id can stay NULL here without a map_nodes table to point at.
raw.execute("""
    CREATE TABLE map_notes (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        map_id     INTEGER NOT NULL,
        node_id    INTEGER,
        text       TEXT NOT NULL DEFAULT '',
        x          REAL NOT NULL,
        y          REAL NOT NULL,
        width      REAL NOT NULL,
        height     REAL NOT NULL,
        color      INTEGER NOT NULL DEFAULT 0,
        added_ts   REAL NOT NULL,
        FOREIGN KEY (map_id) REFERENCES maps(id) ON DELETE CASCADE,
        FOREIGN KEY (node_id) REFERENCES map_nodes(id) ON DELETE SET NULL
    )
""")
raw.execute("INSERT INTO maps(id, name, notes, created_ts, updated_ts)"
           " VALUES (1, 'Old Map', '', 0, 0)")
raw.execute("INSERT INTO map_frames(id, map_id, label, x, y, width, height, color, added_ts)"
           " VALUES (1, 1, 'Pre-existing Rack', 5, 5, 100, 100, 0, 0)")
raw.execute("INSERT INTO map_notes(id, map_id, node_id, text, x, y, width, height, color,"
           " added_ts) VALUES (1, 1, NULL, 'Pre-existing Note', 5, 5, 100, 100, 0, 0)")
raw.commit()
raw.close()

upgraded = MapperDatabase(old_path)
with upgraded._lock:
    frame_cols = {row["name"] for row in
           upgraded._conn.execute("PRAGMA table_info(map_frames)").fetchall()}
    note_cols = {row["name"] for row in
           upgraded._conn.execute("PRAGMA table_info(map_notes)").fetchall()}
check("opening a pre-text_size database adds the column to map_frames",
      "text_size" in frame_cols, frame_cols)
check("...and to map_notes", "text_size" in note_cols, note_cols)
pre_existing = next(r for r in upgraded.frames(1) if r["id"] == 1)
check("...and the pre-existing frame row reads text_size == 1 (the default)",
      pre_existing["text_size"] == 1, dict(pre_existing))
check("update_frame(text_size=2) lands on the migrated row",
      upgraded.update_frame(1, 1, text_size=2) is True)
check("...and reads back as 2",
      next(r for r in upgraded.frames(1) if r["id"] == 1)["text_size"] == 2)
pre_existing_note = next(r for r in upgraded.notes(1) if r["id"] == 1)
check("...and the pre-existing note row reads text_size == 1 (the default)",
      pre_existing_note["text_size"] == 1, dict(pre_existing_note))
check("update_note(text_size=2) lands on the migrated row",
      upgraded.update_note(1, 1, text_size=2) is True)
check("...and reads back as 2",
      next(r for r in upgraded.notes(1) if r["id"] == 1)["text_size"] == 2)
upgraded.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
