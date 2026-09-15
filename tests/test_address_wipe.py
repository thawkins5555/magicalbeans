"""The one-time wipe of everything device_addresses ever held besides its
own interface table: discovery, trap_agent_addr and merge rows are stale
from before 5.29.0 and are deleted once, behind a migration marker; a
second open touches nothing further, even a row added after the wipe."""

import os
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesdb import CONFIGURED_SOURCE, NodesDatabase

TMPDIR = _paths.tmpdir("address_wipe_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def rows_for(db, device_id):
    return {r["ip"]: r for r in db.device_addresses(device_id)}


db_path = os.path.join(TMPDIR, "nodes.db")
db = NodesDatabase(db_path)
sw = db.add_device("10.70.0.1", "sw-a")

print("1. a mix of sources, wiped down to the interface table alone")
db.record_device_addresses(sw, ["10.70.9.1"], "discovery")
db.record_device_addresses(sw, ["10.70.9.2"], "trap_agent_addr")
db.record_device_addresses(sw, ["10.70.9.3"], "merge")
db.record_device_addresses(sw, ["10.70.9.4"], CONFIGURED_SOURCE)
check("all four rows are on disk before the wipe",
      len(rows_for(db, sw)) == 4, rows_for(db, sw))

db._clear_private_setting(db._ADDRESSES_INTERFACE_ONLY_5_29)
db._migrate()
after = rows_for(db, sw)
check("only the ipAddrTable row survives",
      set(after) == {"10.70.9.4"}, sorted(after))
check("...still carrying its own source",
      after["10.70.9.4"]["source"] == CONFIGURED_SOURCE, after["10.70.9.4"]["source"])
check("the marker is set",
      db._private_setting(db._ADDRESSES_INTERFACE_ONLY_5_29) is True)

print("2. a second open deletes nothing")
db.record_device_addresses(sw, ["10.70.9.5"], "discovery")
db.close()
db2 = NodesDatabase(db_path)
still = rows_for(db2, sw)
check("a row added after the wipe survives the next open untouched",
      set(still) == {"10.70.9.4", "10.70.9.5"}, sorted(still))
db2.close()

print()
print("FAILURES: " + (", ".join(FAILS) if FAILS else "none"))
sys.exit(1 if FAILS else 0)
