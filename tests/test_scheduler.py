"""The poller's scheduling thread: what one pass costs, that a settings
change is picked up, and that the thread survives a database error.

§4.1 S5 / §4.5 F4 measured 4,001 SQLite statements a second at 2,000
devices — the loop re-read the whole device table and called
effective_config() per device, which itself reads the settings table four
times and the device's group once, all under the lock every poll worker
needs. §4.1 S2: the same loop had no exception guard, so one transient
database error stopped all polling permanently, silently, with
`poller.error` still None.

No SNMP traffic here — the pass is driven directly, the way
test_series_buckets.py drives the database directly.
"""
import os
import sys
import threading
import time

import _paths
from _paths import tmpdir

TMPDIR = tmpdir("scheduler_")

from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase

DEVICES = 300
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
    db.update_group(group_id, poll_interval_s=3600)
    for i in range(DEVICES):
        db.add_device(f"10.{i // 256}.{i % 256}.1", f"dev-{i}", group_id=group_id)

    poller = NodePoller(db)
    now = time.time()
    # Nothing is due, so this measures the steady-state pass rather than
    # 300 submissions. (A due device with no executor is a no-op anyway,
    # but it would add its own statements.)
    poller._next_run = {i + 1: now + 3600 for i in range(DEVICES)}

    poller._schedule_pass()                 # warm: builds the merged configs
    with StatementCounter(db._conn) as counter:
        poller._schedule_pass()
    print(f"      steady pass at {DEVICES} devices: {len(counter.statements)} "
          f"statement(s)")
    check(len(counter.statements) <= 5,
          f"a steady pass costs at most 5 statements regardless of fleet size "
          f"(got {len(counter.statements)})")
    check(not any("FROM settings" in s for s in counter.statements),
          "…and does not re-read the settings table")

    # A cold pass — the one that rebuilds the configs — must also be a
    # handful of statements, not one per device.
    poller._configs = None
    with StatementCounter(db._conn) as counter:
        poller._schedule_pass()
    print(f"      config rebuild at {DEVICES} devices: "
          f"{len(counter.statements)} statement(s)")
    check(len(counter.statements) <= 10,
          f"rebuilding every device's config is a fixed handful of queries "
          f"(got {len(counter.statements)})")

    # ------------------------------------------------ a change is noticed

    check(poller._configs[1]["poll_interval_s"] == 3600,
          "the cached config carries the profile's interval")
    generation = db.config_generation()
    db.update_group(group_id, poll_interval_s=45)
    check(db.config_generation() != generation,
          "editing a profile moves the config generation")
    poller._schedule_pass()
    check(poller._configs[1]["poll_interval_s"] == 45,
          f"…and the next pass polls at the new interval "
          f"(got {poller._configs[1]['poll_interval_s']})")

    generation = db.config_generation()
    db.update_device(1, poll_interval_s=17)
    check(db.config_generation() != generation,
          "editing a device moves it too")
    poller._schedule_pass()
    check(poller._configs[1]["poll_interval_s"] == 17,
          "…and the device's own override wins")

    generation = db.config_generation()
    db.save_settings({"default_interval_s": 90})
    check(db.config_generation() != generation,
          "saving Nodes settings moves it as well")

    # A device added after the last rebuild is picked up, not lost.
    new_id = db.add_device("192.0.2.77", "late-arrival", group_id=group_id)
    poller._schedule_pass()
    check(new_id in poller._configs,
          "a device added between passes is scheduled on the next one")

    # ------------------------------------------- the thread does not die

    poller.error = None
    real_rows = db.schedule_rows
    calls = {"n": 0}

    def exploding_schedule_rows():
        calls["n"] += 1
        raise RuntimeError("database is locked")

    db.schedule_rows = exploding_schedule_rows
    thread = threading.Thread(target=poller._loop, daemon=True)
    poller._stop.clear()
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline and not poller.error:
        time.sleep(0.05)
    check(bool(poller.error) and "database is locked" in poller.error,
          f"a failing pass is reported instead of killing the thread "
          f"(error={poller.error!r})")
    check(thread.is_alive(), "…and the scheduling thread is still running")
    check(poller.status_text() == poller.error,
          "…and the status strip says so rather than 'Polling N devices'")

    # It keeps trying rather than stopping after the first failure.
    attempts = calls["n"]
    time.sleep(1.3)
    check(calls["n"] > attempts,
          f"…and it tries again on the next tick "
          f"({attempts} -> {calls['n']} attempts)")

    db.schedule_rows = real_rows
    deadline = time.time() + 5
    while time.time() < deadline and poller.error:
        time.sleep(0.05)
    check(poller.error is None,
          f"the error clears once passes succeed again (error={poller.error!r})")

    poller._stop.set()
    thread.join(timeout=3)
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
