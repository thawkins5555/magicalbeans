"""device_addresses ages out like the other walk tables: a complete
ipAddrTable walk marks the addresses it no longer lists present=0, a
partial writer (trap, discovery) marks nothing, prune deletes what nothing
has refreshed, and a present alias wins over a stale one when an address
is resolved to a device."""

import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesdb import NodesDatabase

TMPDIR = _paths.tmpdir("device_address_ageout_")
FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def rows_for(db, device_id):
    return {r["ip"]: r for r in db.device_addresses(device_id)}


db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
sw = db.add_device("10.30.0.1", "sw-a")
rt = db.add_device("10.30.0.2", "rt-b")

print("1. a complete walk marks what it no longer lists")
db.record_device_addresses(sw, ["10.30.9.1", "10.30.9.2"], "ipAddrTable", complete=True)
first = rows_for(db, sw)
check("both walked addresses are present", all(first[ip]["present"] == 1 for ip in first)
      and set(first) == {"10.30.9.1", "10.30.9.2"}, sorted(first))
check("first_seen_ts is stamped", all(first[ip]["first_seen_ts"] for ip in first))
time.sleep(0.01)
db.record_device_addresses(sw, ["10.30.9.1"], "ipAddrTable", complete=True)
second = rows_for(db, sw)
check("the address no longer walked is kept but marked present=0",
      second["10.30.9.2"]["present"] == 0 and second["10.30.9.1"]["present"] == 1)
check("...and its first_seen_ts survives the re-walk",
      second["10.30.9.1"]["first_seen_ts"] == first["10.30.9.1"]["first_seen_ts"])

print("2. a partial writer marks nothing absent")
db.record_device_addresses(sw, ["10.30.9.7"], "trap")
third = rows_for(db, sw)
check("a trap-learned address does not touch the walk's rows",
      third["10.30.9.1"]["present"] == 1 and third["10.30.9.7"]["present"] == 1)
db.record_device_addresses(sw, ["10.30.9.1"], "ipAddrTable", complete=True)
check("...and a complete walk of another source leaves the trap row alone",
      rows_for(db, sw)["10.30.9.7"]["present"] == 1)

print("3. an empty complete walk still reaches the marking step")
db.record_device_addresses(sw, [], "ipAddrTable", complete=True)
fourth = rows_for(db, sw)
check("every ipAddrTable row is now stale",
      all(r["present"] == 0 for ip, r in fourth.items() if r["source"] == "ipAddrTable"))
check("...and the trap row is not", fourth["10.30.9.7"]["present"] == 1)

print("4. resolution prefers a present row over a newer stale one")
db.record_device_addresses(rt, ["10.30.9.2"], "ipAddrTable", complete=True)
check("the address moves to the device that currently reports it",
      db.device_id_for_address("10.30.9.2") == rt)
with db._lock:
    db._conn.execute("UPDATE device_addresses SET seen_ts = seen_ts + 1000"
                     " WHERE device_id = ? AND ip = '10.30.9.2'", (sw,))
    db._conn.commit()
check("...even when the stale row carries the newer seen_ts",
      db.device_id_for_address("10.30.9.2") == rt)

print("5. prune deletes what nothing has refreshed")
with db._lock:
    db._conn.execute("UPDATE device_addresses SET seen_ts = ? WHERE device_id = ?",
                     (time.time() - 200 * 86400, sw))
    db._conn.commit()
removed = db.prune_device_addresses(180 * 86400)
check("the old rows are gone", removed >= 3 and not rows_for(db, sw), removed)
check("...and the fresh device keeps its alias", "10.30.9.2" in rows_for(db, rt))

print("6. a stuck discovery job ages out with the rest")
old = time.time() - 40 * 86400
with db._lock:
    db._conn.execute(
        "INSERT INTO discovery_jobs(kind, target, state, started_ts)"
        " VALUES ('subnet', '10.0.0.0/24', 'running', ?)", (old,))
    db._conn.commit()
db.prune(discovery_days=30)
with db._lock:
    left = db._conn.execute("SELECT COUNT(*) FROM discovery_jobs").fetchone()[0]
check("a job 'running' for forty days is pruned", left == 0, left)

db.close()
print()
print("FAILURES: " + (", ".join(FAILS) if FAILS else "none"))
sys.exit(1 if FAILS else 0)
