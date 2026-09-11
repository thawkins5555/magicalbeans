"""Device search (nodesdb.devices/devices_count `text` filter) matches what an
operator knows about a device: sys_location, sys_descr, sys_contact and vendor
as well as name/IP/sys_name/MAC. Proves each of the four fields matches, that
name/IP/sys_name/MAC behaviour is unchanged, and that a match tracks a device
live across rename/re-identify/update/delete, since the search reads the
devices table's own columns (see nodesdb.py's _device_filter_clause).
"""
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesdb import NodesDatabase

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(errors="replace")

TMPDIR = _paths.tmpdir("device_search_fields_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def set_identity_fields(db, device_id, **fields):
    """Writes straight to the devices row, the same way a poll would —
    none of sys_location/sys_descr/sys_contact/vendor are reachable through
    update_device()'s allow-list, only through a poll (or, here, a raw
    UPDATE), matching the pattern test_report_availability.py and
    test_vendor_arc.py already use for identity columns update_device()
    does not cover."""
    clauses = ", ".join(f"{k} = ?" for k in fields)
    db._conn.execute(f"UPDATE devices SET {clauses} WHERE id = ?",
                      (*fields.values(), device_id))
    db._conn.commit()


def names(rows):
    return sorted(r["name"] for r in rows)


db = NodesDatabase(f"{TMPDIR}/nodes.db")

# ---------------------------------------------------------------- fixtures
moxa_id = db.add_device("10.0.1.50", "ind-switch-01")
set_identity_fields(
    db, moxa_id,
    sys_descr="Moxa EDS-508A industrial switch",
    sys_location="Site-B / Panel 3",
    sys_contact="ops-b@example.net",
    vendor="moxa")

cisco_id = db.add_device("10.0.2.10", "acc-sw-114")
set_identity_fields(
    db, cisco_id,
    sys_descr="Cisco IOS Software, Catalyst L3 Switch",
    sys_location="Site-A / IDF 2",
    sys_contact="ops-sitea@example.net",
    vendor="cisco")

plain_id = db.add_device("10.0.3.5", "printer-hp-01")
set_identity_fields(db, plain_id, sys_name="hp-printer-lobby")

db._conn.execute(
    "INSERT INTO mac_entries(device_id, if_index, mac, seen_ts, present)"
    " VALUES (?, 1, 'aabbccddeeff', ?, 1)", (cisco_id, 1e9))
db._conn.commit()

# --------------------------------------------------------- newly-searchable

r = db.devices(text="Site-B")
check("sys_location finds its device ('Site-B')",
      names(r) == ["ind-switch-01"], names(r))

r = db.devices(text="Moxa")
check("sys_descr (model/description) finds its device ('Moxa')",
      names(r) == ["ind-switch-01"], names(r))

r = db.devices(text="cisco")
check("vendor finds its device ('cisco')",
      names(r) == ["acc-sw-114"], names(r))

r = db.devices(text="ops-sitea@example.net")
check("sys_contact finds its device",
      names(r) == ["acc-sw-114"], names(r))

check("devices_count agrees with devices() for a newly-searchable field",
      db.devices_count(text="Site-B") == 1, db.devices_count(text="Site-B"))

r = db.devices(text="nonexistent-field-value-xyz")
check("a term matching nothing in any column returns nothing",
      r == [], names(r))

# ------------------------------------------------------- existing behaviour
r = db.devices(text="acc-sw")
check("name search is unchanged",
      names(r) == ["acc-sw-114"], names(r))

r = db.devices(text="10.0.1.50")
check("ip search is unchanged",
      names(r) == ["ind-switch-01"], names(r))

r = db.devices(text="hp-printer-lobby")
check("sys_name search is unchanged",
      names(r) == ["printer-hp-01"], names(r))

r = db.devices(text="aabbccddeeff")
check("MAC-table search is unchanged",
      names(r) == ["acc-sw-114"], names(r))

r = db.devices()
check("no text filter still returns every device",
      names(r) == ["acc-sw-114", "ind-switch-01", "printer-hp-01"], names(r))

# ---------------------------------------------------- stays live, no index
set_identity_fields(db, moxa_id, sys_location="Site-C / Panel 3")
r = db.devices(text="Site-B")
check("a moved device drops out of its old location search immediately",
      r == [], names(r))
r = db.devices(text="Site-C")
check("...and appears under its new location immediately",
      names(r) == ["ind-switch-01"], names(r))

db.update_device(moxa_id, name="renamed-switch")
r = db.devices(text="Site-C")
check("a rename does not disturb the field search that still matches",
      names(r) == ["renamed-switch"], names(r))

set_identity_fields(db, moxa_id, vendor="siemens", sys_descr="SCALANCE X208")
r = db.devices(text="moxa")
check("re-identifying a device to a new vendor drops the old vendor match",
      r == [], names(r))
r = db.devices(text="SCALANCE")
check("...and the new model is searchable right away",
      names(r) == ["renamed-switch"], names(r))

db.remove_device(moxa_id)
r = db.devices(text="SCALANCE")
check("a deleted device is gone from search, not a dangling match",
      r == [], names(r))
r = db.devices(text="Site-C")
check("...under every one of its fields, not just the one just checked",
      r == [], names(r))

# --------------------------------------------- wildcards typed in the box
#
# `_` and `%` are LIKE's own wildcards. An operator typing a device name that
# contains one means the character, not the pattern: before the escape,
# searching "core_sw" also returned "core-sw-1" and searching "%" returned
# the whole fleet.
lit_a = db.add_device("10.9.0.1", "core-sw-1")
lit_b = db.add_device("10.9.0.2", "core_sw_2")
lit_c = db.add_device("10.9.0.3", "100% full")
set_identity_fields(db, lit_c, sys_location="Plant_A")

r = db.devices(text="core_sw")
check("an underscore in the search box matches an underscore, not any character",
      names(r) == ["core_sw_2"], names(r))
check("...and the count agrees with the list",
      db.devices_count(text="core_sw") == 1, db.devices_count(text="core_sw"))
r = db.devices(text="%")
check("a per-cent sign matches the device that has one, not every device",
      names(r) == ["100% full"], names(r))
check("...and its count too",
      db.devices_count(text="%") == 1, db.devices_count(text="%"))
r = db.devices(text="Plant_A")
check("the same on the identity fields the box also searches",
      names(r) == ["100% full"], names(r))
check("a backslash in the search box is a backslash",
      db.devices(text="a\\b") == [], db.devices(text="a\\b"))
check("device_ips_by_name takes the text literally as well",
      db.device_ips_by_name("core_sw") == ["10.9.0.2"],
      db.device_ips_by_name("core_sw"))
check("...and a hyphen still finds the hyphenated one",
      db.device_ips_by_name("core-sw") == ["10.9.0.1"],
      db.device_ips_by_name("core-sw"))

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    raise SystemExit(1)
print("all checks passed")
