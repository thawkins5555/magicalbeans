"""nodesdb's polling-profile override accounting: override_fields() names
the device columns that are non-NULL (with "" also meaning inherit for the
two OID columns), and devices(overrides_only=True) / devices_count() agree
with it, paged or not.

These pin behaviour that already landed in nodesdb; none of them is
red-before-green."""
import os

from _paths import tmpdir  # noqa: F401  (repo root on sys.path)

from netpath import nodesdb, sqlitebase
from netpath.nodesdb import NodesDatabase, override_fields

TMP = tmpdir("device_overrides_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


db = NodesDatabase(os.path.join(TMP, "nodes.db"))
try:
    gid = db.add_group("profile", snmp_version=1, community="public", poll_interval_s=60)

    plain = db.add_device("10.0.0.1", "plain", gid)
    check("a fully inherited device reports zero overrides",
          override_fields(db.device(plain)) == (), override_fields(db.device(plain)))

    one = db.add_device("10.0.0.2", "one", gid, poll_interval_s=120)
    check("one set column is exactly one override, by name",
          override_fields(db.device(one)) == ("poll_interval_s",),
          override_fields(db.device(one)))

    empty_oid = db.add_device("10.0.0.3", "empty-oid", gid, vendor_oid="", location_oid="")
    check('vendor_oid="" and location_oid="" are not overrides',
          override_fields(db.device(empty_oid)) == (), override_fields(db.device(empty_oid)))

    real_oid = db.add_device("10.0.0.4", "real-oid", gid, vendor_oid="1.3.6")
    check('vendor_oid="1.3.6" is an override',
          override_fields(db.device(real_oid)) == ("vendor_oid",),
          override_fields(db.device(real_oid)))

    db.update_device(one, snmp_timeout_s=5, ping_enabled=0)
    check("update_device adds to the set, in _OVERRIDE_COLUMNS order",
          override_fields(db.device(one)) == ("poll_interval_s", "snmp_timeout_s", "ping_enabled"),
          override_fields(db.device(one)))
    db.update_device(one, snmp_timeout_s=None)
    check("clearing a column back to NULL drops it from the set",
          "snmp_timeout_s" not in override_fields(db.device(one)),
          override_fields(db.device(one)))

    check("every override column is reported when all are set",
          set(override_fields(db.device(db.add_device(
              "10.0.0.5", "all", gid,
              **{col: ("1.3.6" if col in nodesdb._EMPTY_IS_UNSET else 1)
                 for col in nodesdb._OVERRIDE_COLUMNS}))))
          == set(nodesdb._OVERRIDE_COLUMNS))

    for i in range(6, 20):
        db.add_device(f"10.0.0.{i}", f"bulk-{i:02d}", gid,
                      **({"snmp_retries": 3} if i % 3 == 0 else {}))
    db.update_device(db.add_device("10.0.0.20", "down-override", gid, ping_count=2),
                     enabled=1)

    everything = db.devices()
    expected = {r["id"] for r in everything if override_fields(r)}
    got = {r["id"] for r in db.devices(overrides_only=True)}
    check("devices(overrides_only=True) is exactly the set override_fields implies",
          got == expected and expected, (sorted(got), sorted(expected)))
    check("devices_count(overrides_only=True) agrees",
          db.devices_count(overrides_only=True) == len(expected),
          db.devices_count(overrides_only=True))
    check("the unfiltered list and count are untouched",
          len(everything) == db.devices_count() == 20, len(everything))

    # Paging: every page is a slice of the same set, no gaps, no repeats.
    total = db.devices_count(overrides_only=True)
    seen, offset, pages = [], 0, 0
    while True:
        page = db.devices(overrides_only=True, limit=3, offset=offset)
        if not page:
            break
        seen.extend(r["id"] for r in page)
        check(f"page at offset {offset} holds only overriding devices",
              all(override_fields(r) for r in page))
        offset += 3
        pages += 1
    check("paged overrides_only walks the whole set exactly once",
          sorted(seen) == sorted(expected) and len(seen) == total, (seen, total))
    check("page count matches the count", pages == -(-total // 3), (pages, total))

    check("overrides_only composes with the text filter",
          {r["id"] for r in db.devices(overrides_only=True, text="bulk")}
          == {r["id"] for r in everything
              if override_fields(r) and r["name"].startswith("bulk")}
          and db.devices_count(overrides_only=True, text="bulk")
          == len([r for r in everything
                  if override_fields(r) and r["name"].startswith("bulk")]))

    auto = db.add_device("10.0.0.21", "auto-mib", gid)
    db.update_device(auto, mib_file_id=5, mib_file_auto=1)
    check("a MIB the poller assigned itself is not an override",
          override_fields(db.device(auto)) == (), override_fields(db.device(auto)))
    check("...and overrides_only agrees",
          auto not in {r["id"] for r in db.devices(overrides_only=True)})
    db.update_device(auto, mib_file_id=5)
    check("the same MIB chosen by an operator is an override (auto flag reset)",
          override_fields(db.device(auto)) == ("mib_file_id",)
          and auto in {r["id"] for r in db.devices(overrides_only=True)},
          dict(db.device(auto)))
    db.update_device(auto, mib_file_id=None)
    check("clearing the MIB clears the override",
          override_fields(db.device(auto)) == ())
    db.update_device(auto, mib_file_id=5, mib_file_auto=1)
    db.bulk_update_devices([auto], mib_file_id=6)
    check("a bulk MIB assignment resets the auto flag too",
          override_fields(db.device(auto)) == ("mib_file_id",), dict(db.device(auto)))

    # exclude_ids past one chunk: the NOT IN chunks must AND, never OR.
    bulk = [db.add_device(f"10.1.{i // 250}.{i % 250}", f"chunk-{i:03d}", gid)
            for i in range(520)]
    excluded = set(bulk[:510])
    check("the exclusion list spans more than one chunk",
          len(excluded) > sqlitebase._ID_CHUNK, (len(excluded), sqlitebase._ID_CHUNK))
    all_ids = {r["id"] for r in db.devices()}
    kept = {r["id"] for r in db.devices(exclude_ids=excluded)}
    check("exclude_ids spanning two chunks drops exactly those ids",
          kept == all_ids - excluded, (len(kept), len(all_ids), len(excluded)))
    check("devices_count(exclude_ids=...) agrees across chunks",
          db.devices_count(exclude_ids=excluded) == len(all_ids) - len(excluded),
          (db.devices_count(exclude_ids=excluded), len(all_ids) - len(excluded)))

    # ------------------------------------- repair_auto_mib_overrides (5.20.4)
    #
    # Pre-5.18.0, _auto_assign_mib set mib_file_id with no mib_file_auto
    # marker, so devices it picked for still count "1 override" today.
    # The repair only reclassifies mib_file_id where it is the device's
    # SOLE override and still matches the vendor lookup -- anything else
    # might be a hand pin, not a stale auto-pick.
    mib_good = db.add_mib_file("good.mib", "GOOD-MIB", 1, [], "")
    db.replace_mib_objects(mib_good, [
        {"name": "goodScalar", "oid": "1.3.6.1.4.1.88888.1.1",
         "description": "", "syntax": "INTEGER", "enums": None,
         "is_notification": False}])
    mib_other = db.add_mib_file("other.mib", "OTHER-MIB", 1, [], "")
    db.replace_mib_objects(mib_other, [
        {"name": "otherScalar", "oid": "1.3.6.1.4.1.77777.1.1",
         "description": "", "syntax": "INTEGER", "enums": None,
         "is_notification": False}])
    VENDOR_ARC_OID = "1.3.6.1.4.1.88888.9.9"
    check("fixture sanity: mib_file_covering resolves the arc to mib_good",
          db.mib_file_covering(VENDOR_ARC_OID) == mib_good,
          db.mib_file_covering(VENDOR_ARC_OID))

    # (a) legacy auto-pick: no auto marker, sole override, still matches
    # the vendor lookup -> repaired.
    legacy = db.add_device("10.0.1.1", "legacy-auto", gid, mib_file_id=mib_good)
    db.seed_identity(legacy, sys_object_id=VENDOR_ARC_OID)

    # (b) same, plus a genuine second override -> the operator was in
    # there on purpose, so leave it alone.
    legacy_plus = db.add_device("10.0.1.2", "legacy-plus-override", gid,
                                mib_file_id=mib_good, community="private")
    db.seed_identity(legacy_plus, sys_object_id=VENDOR_ARC_OID)

    # (c) stored MIB isn't what the vendor lookup would pick for this
    # sysObjectID -> could be a hand choice, leave it alone.
    legacy_mismatch = db.add_device("10.0.1.3", "legacy-mismatch", gid,
                                    mib_file_id=mib_other)
    db.seed_identity(legacy_mismatch, sys_object_id=VENDOR_ARC_OID)

    # (d) already marked automatic -> nothing to do, not counted.
    already_auto = db.add_device("10.0.1.4", "already-auto", gid)
    db.update_device(already_auto, mib_file_id=mib_good, mib_file_auto=1)
    db.seed_identity(already_auto, sys_object_id=VENDOR_ARC_OID)

    # (g) identified by walk under a generic arc: the old auto-pick keyed
    # on vendor_arc, so the repair must too.
    legacy_walk = db.add_device("10.0.1.5", "legacy-walk", gid, mib_file_id=mib_good)
    db.seed_identity(legacy_walk, sys_object_id="1.3.6.1.4.1.8072.3.2.10")
    with db._lock:
        db._conn.execute("UPDATE devices SET vendor_arc = 88888 WHERE id = ?",
                         (legacy_walk,))
        db._conn.commit()

    # (h) vendor_arc points elsewhere even though sysObjectID sits under
    # the covered arc: the recorded arc wins, so no match, untouched.
    legacy_arc_other = db.add_device("10.0.1.6", "legacy-arc-other", gid,
                                     mib_file_id=mib_good)
    db.seed_identity(legacy_arc_other, sys_object_id=VENDOR_ARC_OID)
    with db._lock:
        db._conn.execute("UPDATE devices SET vendor_arc = 77777 WHERE id = ?",
                         (legacy_arc_other,))
        db._conn.commit()

    before = {d: override_fields(db.device(d))
             for d in (legacy, legacy_plus, legacy_mismatch, already_auto,
                       legacy_walk, legacy_arc_other)}
    repaired = db.repair_auto_mib_overrides()

    check("(e) the return value is the number of devices actually repaired",
          repaired == 2, repaired)
    check("(g) a walk-identified device is matched on its vendor_arc, not sysObjectID",
          override_fields(db.device(legacy_walk)) == ()
          and db.device(legacy_walk)["mib_file_auto"] == 1,
          dict(db.device(legacy_walk)))
    check("(h) a vendor_arc that points elsewhere is not overridden by sysObjectID",
          override_fields(db.device(legacy_arc_other)) == before[legacy_arc_other]
          and not db.device(legacy_arc_other)["mib_file_auto"],
          dict(db.device(legacy_arc_other)))
    check("(a) the legacy auto-pick loses its override and gains the flag",
          override_fields(db.device(legacy)) == ()
          and db.device(legacy)["mib_file_auto"] == 1,
          dict(db.device(legacy)))
    check("(b) a device with a second override is left untouched",
          override_fields(db.device(legacy_plus)) == before[legacy_plus]
          and not db.device(legacy_plus)["mib_file_auto"],
          dict(db.device(legacy_plus)))
    check("(c) a stored MIB that isn't the vendor lookup's pick is left untouched",
          override_fields(db.device(legacy_mismatch)) == before[legacy_mismatch]
          and not db.device(legacy_mismatch)["mib_file_auto"],
          dict(db.device(legacy_mismatch)))
    check("(d) an already-automatic MIB is untouched and not recounted",
          override_fields(db.device(already_auto)) == before[already_auto]
          and db.device(already_auto)["mib_file_auto"] == 1,
          dict(db.device(already_auto)))
    check("(f) running the repair again finds nothing left to repair",
          db.repair_auto_mib_overrides() == 0)
finally:
    db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
