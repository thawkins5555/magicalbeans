"""MapperDatabase: maps, map_nodes (cascade-deleted with their map, one
device or peer per map enforced by two partial unique indexes), the global
vlan_colors override table, and settings coercion/validation.
"""
import time

from _paths import tmpdir

from netpath.mapperdb import DEFAULTS, MAP_STYLES, MapperDatabase, ROLES

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
check("node exists before delete", len(db.nodes(map_id)) == 1)
db.delete_map(map_id)
with db._lock:
    remaining = db._conn.execute(
        "SELECT COUNT(*) AS n FROM map_nodes WHERE id = ?", (node_id,)).fetchone()["n"]
check("deleting a map cascades its map_nodes rows away (foreign_keys=ON is live)",
      remaining == 0, remaining)
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

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
