"""fortipoll's SNMPv3 walk requests used to read the engine tuple raw
(engineTime never advanced -- >150s stale fails notInTimeWindows), retried
never on a Report, and checked no msgID. _snmp_walk_request now goes through
nodepoll's shared v3_exchange (nodepoll/_session.py), the same one
_v3_exchange wraps for NodePoller -- same engine-advance, resync-retry and
msgID match nodepoll already has, one session per walk kept from 5.46.0.
No wireless stub speaks v3, so this drives WirelessPoller._walk_column
against stub_agent_iftable.py's v3 mode instead -- same protocol engine
test_poll_write_path.py already exercises for NodePoller, walking a
FortiGate OID the stub does not know (irrelevant to the engine handshake,
which happens on the first GETNEXT regardless of what it asks)."""
import json
import os
import sys
import time

import _paths
from _paths import spawn_stub, tmpdir

TMPDIR = tmpdir("fortipoll_v3_exchange_")

from netpath.fortipoll import WirelessPoller
import netpath.fortipoll as fortipoll_mod
from netpath.wirelessdb import WirelessDatabase
from netpath import nodeoids as oids

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


def read_stats(path):
    deadline = time.monotonic() + 3.0
    while True:
        try:
            with open(path) as handle:
                return json.load(handle)
        except (PermissionError, FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def main():
    # ---------------------------------------------- engineTime advances

    stats = os.path.join(TMPDIR, "v3.json")
    proc, fortipoll_mod.SNMP_PORT = spawn_stub(
        "stub_agent_iftable.py", "v3", "--window", "1", "--stats", stats)
    try:
        db = WirelessDatabase(os.path.join(TMPDIR, "v3.db"))
        controller_id = db.add_controller("v3-test", "127.0.0.1",
                                          snmp_version=3, v3_user="poller")
        controller = dict(db.controller(controller_id))
        config = dict(controller)
        poller = WirelessPoller(db)

        poller._walk_column(controller, config, oids.WTP_SESSION_MAC)
        after_first = read_stats(stats)
        check(after_first["discoveries"] == 1,
              "the first walk discovers the engine exactly once")

        time.sleep(2.5)   # past the stub's 1s window if engineTime were frozen
        reports_before = after_first["reports"]
        poller._walk_column(controller, config, oids.WTP_SESSION_MAC)
        after_second = read_stats(stats)
        check(after_second["reports"] == reports_before,
              f"…with no Report-PDU: engineTime advanced with the clock "
              f"(reports {reports_before} -> {after_second['reports']})")

        db.close()
    finally:
        proc.kill()

    # ---------------------------------------------- one Report -> one retry -> success

    stats = os.path.join(TMPDIR, "v3boots.json")
    proc, fortipoll_mod.SNMP_PORT = spawn_stub(
        "stub_agent_iftable.py", "v3", "--window", "1",
        "--bump-boots-at", "1", "--stats", stats)
    try:
        db = WirelessDatabase(os.path.join(TMPDIR, "v3boots.db"))
        controller_id = db.add_controller("v3-boots", "127.0.0.1",
                                          snmp_version=3, v3_user="poller")
        controller = dict(db.controller(controller_id))
        config = dict(controller)
        poller = WirelessPoller(db)

        poller._walk_column(controller, config, oids.WTP_SESSION_MAC)   # discovery
        before = read_stats(stats)
        time.sleep(1.2)   # the agent restarts (engineBoots += 1) in here

        values = poller._walk_column(controller, config, oids.WTP_SESSION_MAC)
        after = read_stats(stats)
        check(after["engine_boots"] == before["engine_boots"] + 1,
              "the stub agent restarted between the two walks")
        check(after["reports"] - before["reports"] == 1,
              f"the restart costs exactly one Report-PDU "
              f"(got {after['reports'] - before['reports']})")
        check(isinstance(values, dict),
              "…and the walk recovers within itself instead of raising")

        db.close()
    finally:
        proc.kill()

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
