"""Duplicate-device verdicts trust only a device's own address table
(CONFIGURED_SOURCE = 'ipAddrTable', present=1). A discovered, trap-learned
or merge-carried alias is never evidence two devices are one, though every
reader keeps seeing it when asked for the unfiltered ('default') set."""

import os
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import nodesdb
from netpath.nodesdb import NodesDatabase

TMPDIR = _paths.tmpdir("duplicate_evidence_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def pair_for(db, a_id, b_id):
    lo, hi = (a_id, b_id) if a_id < b_id else (b_id, a_id)
    for item in db.duplicate_candidates():
        if (item["a_id"], item["b_id"]) == (lo, hi):
            return item
    return None


db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
a = db.add_device("10.60.0.1", "dev-a")
b = db.add_device("10.60.0.2", "dev-b")
c = db.add_device("10.60.0.3", "dev-c")

check("CONFIGURED_SOURCE is ipAddrTable", nodesdb.CONFIGURED_SOURCE == "ipAddrTable")

print("1. only-ever-a-correlation sources never produce a pair")
for source in ("discovery", "trap_agent_addr", "merge"):
    db.record_device_addresses(a, ["10.60.0.2"], source)
    check(f"{source}: no duplicate pair", pair_for(db, a, b) is None)
    check(f"{source}: address_owners(configured=True) omits it",
          "10.60.0.2" not in db.address_owners(configured=True))
    check(f"{source}: device_id_for_address(configured=True) is B (primary)",
          db.device_id_for_address("10.60.0.2", configured=True) == b)
    check(f"{source}: address_owners() (default) still sees the alias on A",
          db.address_owners().get("10.60.0.2") == a)
    check(f"{source}: device_id_for_address() (default) is B (primary wins)",
          db.device_id_for_address("10.60.0.2") == b)

print("2. an ipAddrTable row is evidence; losing it stops being evidence")
db.record_device_addresses(a, ["10.60.0.2"], "ipAddrTable", complete=True)
pair = pair_for(db, a, b)
check("configured alias produces a high pair", pair is not None and pair["confidence"] == "high",
      pair)
check("...with the configured-evidence reason text",
      pair is not None and "both have 10.60.0.2 configured" in pair["reasons"], pair)
check("address_owners(configured=True) now has it",
      db.address_owners(configured=True).get("10.60.0.2") == a)
check("device_id_for_address(configured=True) still resolves to B (primary first)",
      db.device_id_for_address("10.60.0.2", configured=True) == b)

db.record_device_addresses(a, [], "ipAddrTable", complete=True)
check("an empty complete walk clears the pair (present=0)", pair_for(db, a, b) is None)

print("3. alias-to-alias evidence follows the same rule on both sides")
db.record_device_addresses(a, ["10.60.9.9"], "ipAddrTable", complete=True)
db.record_device_addresses(c, ["10.60.9.9"], "discovery")
check("one side discovery-only: no pair", pair_for(db, a, c) is None)
db.record_device_addresses(c, ["10.60.9.9"], "ipAddrTable", complete=True)
pair = pair_for(db, a, c)
check("both sides configured: high pair", pair is not None and pair["confidence"] == "high", pair)
check("...with the configured-evidence reason text",
      pair is not None and "both have 10.60.9.9 configured" in pair["reasons"], pair)

print("4. shared interface MAC still produces its pair, untouched by this rule")
d = db.add_device("10.60.0.4", "dev-d")
e = db.add_device("10.60.0.5", "dev-e")
db.replace_interfaces(d, [{"if_index": 1, "descr": "Gi0/1",
                           "phys_addr": "aa:bb:cc:dd:ee:01"}])
db.replace_interfaces(e, [{"if_index": 1, "descr": "Gi0/1",
                           "phys_addr": "aa:bb:cc:dd:ee:01"}])
pair = pair_for(db, d, e)
check("a shared interface MAC still pairs the devices",
      pair is not None and pair["shared_macs"] == 1, pair)
check("...for the reason of a shared MAC, not an address",
      pair is not None and any("shared interface MAC" in r for r in pair["reasons"]), pair)

print("5. shared sysName still produces its (low-confidence) pair")
f = db.add_device("10.60.0.6", "dev-f")
g = db.add_device("10.60.0.7", "dev-g")
db.seed_identity(f, sys_name="twin-switch")
db.seed_identity(g, sys_name="twin-switch")
pair = pair_for(db, f, g)
check("a shared sysName alone still pairs the devices (low)",
      pair is not None and pair["confidence"] == "low", pair)
check("...for the reason of a shared name",
      pair is not None and any("both call themselves" in r for r in pair["reasons"]), pair)

db.close()
print()
print("FAILURES: " + (", ".join(FAILS) if FAILS else "none"))
sys.exit(1 if FAILS else 0)
