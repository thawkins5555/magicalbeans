"""nodesdb's polling-profile override accounting: override_fields() names
the device columns that are non-NULL (with "" also meaning inherit for the
two OID columns), and devices(overrides_only=True) / devices_count() agree
with it, paged or not.

These pin behaviour that already landed in nodesdb; none of them is
red-before-green."""
import os

from _paths import tmpdir  # noqa: F401  (repo root on sys.path)

from netpath import nodesdb
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
finally:
    db.close()

print()
print("FAILURES:", FAILS if FAILS else "none")
raise SystemExit(1 if FAILS else 0)
