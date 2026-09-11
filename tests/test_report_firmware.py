"""report.firmware_inventory: what every device is running, off the identity
columns a poll already stores. Covers the row contents, the vendor-then-version
ordering, the "N devices, M distinct versions" summary counts, the device_ids
filter, and that a device which has never named its software is still a row
(with empty strings, not an invented version) sorted after the ones that did.
"""
import sys

import _paths  # noqa: F401

from netpath import report
from netpath.nodesdb import NodesDatabase

TMPDIR = _paths.tmpdir("report_firmware_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def set_fields(db, device_id, **fields):
    """Straight to the devices row, as a poll would: none of these columns
    is reachable through update_device()'s allow-list (the same shortcut
    test_device_search_fields.py takes)."""
    clauses = ", ".join(f"{k} = ?" for k in fields)
    db._conn.execute(f"UPDATE devices SET {clauses} WHERE id = ?",
                     (*fields.values(), device_id))
    db._conn.commit()


db = NodesDatabase(f"{TMPDIR}/nodes.db")

sw1 = db.add_device("10.1.0.1", "acc-sw-01")
set_fields(db, sw1, vendor="cisco",
           sys_descr="Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M),"
                     " Version 15.2(7)E4, RELEASE SOFTWARE (fc2)",
           sw_version="15.2(7)E4", sw_image="C2960X-UNIVERSALK9-M",
           sw_image_file="flash:/c2960x.bin", last_poll_ts=1_700_000_000.0)

sw2 = db.add_device("10.1.0.2", "acc-sw-02")
set_fields(db, sw2, vendor="cisco", sys_descr="Cisco IOS Software, C2960X Software",
           sw_version="15.0(2)SE11", sw_image="C2960X-UNIVERSALK9-M")

fgt = db.add_device("10.1.0.3", "fw-01")
set_fields(db, fgt, vendor="fortinet", sys_descr="FortiGate-100F",
           sw_version="7.2.8", sw_image="build1639 (GA.M)")

quiet = db.add_device("10.1.0.4", "plc-01")
set_fields(db, quiet, vendor="cisco", sys_descr="Linux plc-01 4.9.0 #1 SMP")

result = report.firmware_inventory(db)
rows = result.rows
by_name = {r.name: r for r in rows}

check("every device on file is a row", len(rows) == 4, [r.name for r in rows])
check("a device that never named its software is a row with empty fields, "
      "not a missing one and not a guess",
      by_name["plc-01"].sw_version == "" and by_name["plc-01"].sw_image == "",
      by_name.get("plc-01"))
check("the version, image and boot file are carried through as stored",
      (by_name["acc-sw-01"].sw_version == "15.2(7)E4"
       and by_name["acc-sw-01"].sw_image == "C2960X-UNIVERSALK9-M"
       and by_name["acc-sw-01"].sw_image_file == "flash:/c2960x.bin"),
      by_name["acc-sw-01"])
check("the model hint is sysDescr's first clause, not a parsed model number",
      by_name["acc-sw-01"].model_hint
      == "Cisco IOS Software" or by_name["acc-sw-01"].model_hint.startswith("Cisco IOS"),
      by_name["acc-sw-01"].model_hint)
check("last_poll_ts comes along, so a version can be read against its age",
      by_name["acc-sw-01"].last_poll_ts == 1_700_000_000.0,
      by_name["acc-sw-01"].last_poll_ts)

check("rows are ordered by vendor, then version",
      [r.name for r in rows] == ["acc-sw-02", "acc-sw-01", "plc-01", "fw-01"],
      [(r.vendor, r.sw_version, r.name) for r in rows])

check("the summary counts devices and DISTINCT versions (3 versions across "
      "4 devices)",
      result.device_count == 4 and result.version_count == 3, result.to_dict())
check("...and says how many named no version at all",
      result.unknown_count == 1, result.unknown_count)

narrowed = report.firmware_inventory(db, [fgt])
check("device_ids narrows the report",
      [r.name for r in narrowed.rows] == ["fw-01"]
      and narrowed.device_count == 1 and narrowed.version_count == 1,
      narrowed.to_dict())

check("an empty device_ids list reports on nothing rather than on the fleet",
      report.firmware_inventory(db, []).rows == [],
      report.firmware_inventory(db, []).to_dict())

payload = result.to_dict()
check("to_dict() is JSON-shaped all the way down (a route returns it as is)",
      isinstance(payload["rows"], list) and isinstance(payload["rows"][0], dict)
      and set(payload["rows"][0]) == {
          "device_id", "name", "ip", "vendor", "model_hint", "sw_version",
          "sw_image", "sw_image_file", "last_poll_ts"},
      payload["rows"][0])

# A device with no name falls back to its IP, the way every other report and
# table in this app names an unnamed device.
nameless = db.add_device("10.1.0.9")
set_fields(db, nameless, name="", vendor="", sw_version="1.0")
rows = report.firmware_inventory(db, [nameless]).rows
check("an unnamed device is reported by its IP", rows[0].name == "10.1.0.9",
      rows[0])

db.close()

print()
if FAILS:
    print(f"{len(FAILS)} check(s) failed: {', '.join(FAILS)}")
    sys.exit(1)
print("all checks passed")
