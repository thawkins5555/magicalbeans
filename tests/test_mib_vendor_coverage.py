"""nodesmibdb's two vendor-coverage lookups — has_mib_covering and
mib_file_covering — answer the right arc, and answer it with an index seek.

nodepoll._check_vendor_mib asks has_mib_covering on every poll of every
device, so with the shipped catalog bundles installed (~10^5 objects) the
question has to cost an index probe, not a scan from the vendor's arc to the
end of the corpus. `oid LIKE 'prefix.%'` gives SQLite only a lower bound on
ix_mib_objects_oid; the range `oid >= 'prefix.' AND oid < 'prefix/'` gives it
both, and selects exactly the same rows because every OID is [0-9.] and '/'
is '.'+1 in ASCII.

The boundary is the part a sloppy bound gets wrong: a MIB under
1.3.6.1.4.1.9 (Cisco) must not answer for 1.3.6.1.4.1.90 (Whitetree), and
the reverse.
"""
import os

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesmibdb import NodesMibDatabase

TMP = _paths.tmpdir("mib_vendor_coverage_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name +
          (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


db = NodesMibDatabase(os.path.join(TMP, "nodes_mibs.db"))

cisco = db.add_mib_file("CISCO-TEST-MIB.my", "CISCO-TEST-MIB", 3, [], "")
db.replace_mib_objects(cisco, [
    {"name": "ciscoScalarA", "oid": "1.3.6.1.4.1.9.9.109.1.1.1"},
    {"name": "ciscoScalarB", "oid": "1.3.6.1.4.1.9.2.1.58"},
    # The bare vendor root itself: it names the vendor and decodes nothing,
    # which is why "covering" means strictly below the arc.
    {"name": "ciscoRoot", "oid": "1.3.6.1.4.1.9"},
])
apc = db.add_mib_file("PowerNet-MIB.mib", "PowerNet-MIB", 1, [], "")
db.replace_mib_objects(apc, [
    {"name": "upsBasicOutputStatus", "oid": "1.3.6.1.4.1.318.1.1.1.4.1.1"}])
# A second file under the SAME arc, with more objects under it than the
# first: mib_file_covering must pick this one.
cisco_bulk = db.add_mib_file("CISCO-ENTITY.my", "CISCO-ENTITY", 4, [], "")
db.replace_mib_objects(cisco_bulk, [
    {"name": f"ciscoEntity{i}", "oid": f"1.3.6.1.4.1.9.6.1.{i}"}
    for i in range(4)])

# 1.3.6.1.4.1.90 is a different vendor that shares 1.3.6.1.4.1.9's digits.
whitetree = db.add_mib_file("WT-MIB.mib", "WT-MIB", 1, [], "")
db.replace_mib_objects(whitetree, [
    {"name": "wtScalar", "oid": "1.3.6.1.4.1.90.1.2.3"}])

# ------------------------------------------------------------- which rows

check("a device under a covered arc reports covered",
      db.has_mib_covering("1.3.6.1.4.1.9.1.1208") is True)
check("a device under an arc nothing describes reports uncovered",
      db.has_mib_covering("1.3.6.1.4.1.12356.101.1") is False)
check("1.3.6.1.4.1.9 and 1.3.6.1.4.1.90 are different vendors: the shorter"
      " arc's objects do not cover the longer one",
      db.has_mib_covering("1.3.6.1.4.1.90.1.2.3") is True
      and db.mib_file_covering("1.3.6.1.4.1.90.1.2.3") == whitetree,
      db.mib_file_covering("1.3.6.1.4.1.90.1.2.3"))
db.remove_mib_file(whitetree)
check("...and with that vendor's file gone, the other vendor's objects do"
      " not stand in for it",
      db.has_mib_covering("1.3.6.1.4.1.90.1.2.3") is False)
check("the shorter arc is unaffected by the longer one's removal",
      db.has_mib_covering("1.3.6.1.4.1.9.1.1208") is True)

check("a sysObjectID outside the enterprises subtree has no vendor arc",
      db.has_mib_covering("1.3.6.1.2.1.1.1.0") is False
      and db.mib_file_covering("1.3.6.1.2.1.1.1.0") is None)

check("mib_file_covering picks the file with the most objects under the arc",
      db.mib_file_covering("1.3.6.1.4.1.9.1.1208") == cisco_bulk,
      db.mib_file_covering("1.3.6.1.4.1.9.1.1208"))
check("...and names the right file for a different vendor",
      db.mib_file_covering("1.3.6.1.4.1.318.1.1.1") == apc,
      db.mib_file_covering("1.3.6.1.4.1.318.1.1.1"))

# A file holding only the bare vendor root covers nothing: has_mib_covering
# exists to say "this vendor's objects are missing" on an install that ships
# ~20 vendor roots already.
root_only = db.add_mib_file("ROOT-ONLY.mib", "ROOT-ONLY", 1, [], "")
db.replace_mib_objects(root_only, [
    {"name": "juniperRoot", "oid": "1.3.6.1.4.1.2636"}])
check("a file holding only the bare vendor root does not count as covering",
      db.has_mib_covering("1.3.6.1.4.1.2636.1.1.1.2.29") is False)


# ---------------------------------------------------- and how it is found
#
# The plan, not a timing: what an index costs depends on the machine, but
# whether SQLite was given an upper bound as well as a lower one does not.
# Taken against the statement the module actually ran — sqlite3's trace
# callback hands it back with its parameters already substituted — so there
# is no hand-copied second version of the query here to drift from the one
# in nodesmibdb.

def plan_of(call):
    seen = []
    db._conn.set_trace_callback(seen.append)
    try:
        call()
    finally:
        db._conn.set_trace_callback(None)
    selects = [sql for sql in seen if sql.lstrip()[:6].upper() == "SELECT"]
    with db._lock:
        return [row[3] for row in db._conn.execute(
            "EXPLAIN QUERY PLAN " + max(selects, key=len)).fetchall()]


covering_plan = plan_of(lambda: db.has_mib_covering("1.3.6.1.4.1.9.1.1208"))
check("has_mib_covering seeks a bounded range of ix_mib_objects_oid",
      any("oid>? AND oid<?" in line for line in covering_plan), covering_plan)

# What it replaced, for the record: LIKE against a BINARY-collated column
# with case_sensitive_like off gives SQLite the lower bound only.
with db._lock:
    like_plan = [row[3] for row in db._conn.execute(
        "EXPLAIN QUERY PLAN SELECT 1 FROM mib_objects WHERE oid IS NOT NULL"
        " AND oid LIKE '1.3.6.1.4.1.9.%' LIMIT 1").fetchall()]
check("...where the LIKE it replaced got a lower bound only (the defect)",
      any("oid>?" in line and "oid<?" not in line for line in like_plan),
      like_plan)

file_plan = plan_of(lambda: db.mib_file_covering("1.3.6.1.4.1.9.1.1208"))
check("mib_file_covering seeks ix_mib_objects_oid rather than scanning it",
      any("oid>? AND oid<?" in line for line in file_plan)
      and not any(line.startswith("SCAN mib_objects") for line in file_plan),
      file_plan)

db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
