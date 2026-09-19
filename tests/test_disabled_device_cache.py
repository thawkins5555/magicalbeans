"""disabled_device_ids() used to full-scan devices on every call; it is read
several times a tick from alertengine (metrics_for_keys, metrics_for_families,
interface_thresholds lookups, the two more at nodesdb.py:4565/5612). It is
now cached, rebuilt only when config_generation moves -- every write that can
flip `enabled` (update_device, bulk_update_devices, request_device_removal)
bumps that counter. A partial index (ix_devices_disabled) backs the rebuild
itself. This pins: no query on an unchanged generation, a flip is picked up
on the very next call, and prints EXPLAIN QUERY PLAN for the query the
rebuild runs."""
import os
import sys

import _paths
from _paths import tmpdir

TMPDIR = tmpdir("disabled_device_cache_")

from netpath.nodesdb import NodesDatabase

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


class StatementCounter:
    def __init__(self, conn):
        self.conn = conn
        self.statements = []

    def __enter__(self):
        self.conn.set_trace_callback(self.statements.append)
        return self

    def __exit__(self, *exc):
        self.conn.set_trace_callback(None)
        return False


def main():
    db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
    group_id = db.ensure_default_group()
    ids = [db.add_device(f"10.0.0.{i}", f"dev-{i}", group_id=group_id)
          for i in range(50)]
    db.update_device(ids[3], enabled=False)
    db.update_device(ids[17], enabled=False)

    first = db.disabled_device_ids()
    check(first == {ids[3], ids[17]},
          f"disabled_device_ids() reports exactly the disabled devices (got {first})")

    with StatementCounter(db._conn) as counter:
        again = db.disabled_device_ids()
    reads = [s for s in counter.statements if "FROM devices" in s]
    check(not reads,
          f"a second call on an unchanged generation reads devices "
          f"{len(reads)} time(s) (the cache is read instead)")
    check(again == first, "…and returns the same set")

    generation = db.config_generation()
    db.update_device(ids[3], enabled=True)
    check(db.config_generation() != generation,
          "re-enabling a device moves config_generation")
    check(db.disabled_device_ids() == {ids[17]},
          "…and the very next call sees the change")

    generation = db.config_generation()
    db.bulk_update_devices([ids[5], ids[9]], enabled=False)
    check(db.config_generation() != generation,
          "bulk_update_devices moves it too")
    check(db.disabled_device_ids() == {ids[17], ids[5], ids[9]},
          "…and the bulk flip is picked up immediately")

    generation = db.config_generation()
    db.remove_device(ids[17])
    check(db.config_generation() != generation,
          "removing a device (request_device_removal) moves it too")
    check(ids[17] not in db.disabled_device_ids(),
          "…and the removed device drops out (purged, not just disabled)")

    plan = db._conn.execute(
        "EXPLAIN QUERY PLAN SELECT id FROM devices WHERE enabled = 0").fetchall()
    print("EXPLAIN QUERY PLAN SELECT id FROM devices WHERE enabled = 0:")
    for row in plan:
        print(f"  {tuple(row)}")
    check(any("ix_devices_disabled" in str(tuple(row)) for row in plan),
          f"the partial index is what the planner actually uses (plan={[tuple(r) for r in plan]})")

    db.close()

    print()
    if FAILURES:
        print(f"FAILURES: {len(FAILURES)}")
        for item in FAILURES:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
