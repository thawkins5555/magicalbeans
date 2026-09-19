"""_poll_controller used to read db.settings() three times per controller
poll (v3_verify_replies, history_sample_s, stale_after_polls). It now reads
a cache, rebuilt when WirelessDatabase._settings_generation moves (bumped
inside save_settings itself) or on start(). Generation, not "refreshed on
start() alone": service.py's _apply_wireless SAVES synchronously on the
request thread but QUEUES the actual worker restart onto a serial executor
(_DEFERRED_SCOPES) -- a save must still reach the very next controller poll
before that restart ever runs, the same promptness an uncached
self.db.settings() read always had. No SNMP here: driven against a stub the
way test_wireless_poller does, since _poll_controller's settings reads
happen before any column walk result is used."""
import os
import sys

import _paths
from _paths import spawn_stub, tmpdir

TMPDIR = tmpdir("wireless_settings_cache_")

from netpath.fortipoll import WirelessPoller
import netpath.fortipoll as fortipoll_mod
from netpath.wirelessdb import WirelessDatabase

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
    stub, fortipoll_mod.SNMP_PORT = spawn_stub("wireless_stub_agent.py")
    try:
        db = WirelessDatabase(os.path.join(TMPDIR, "wireless.db"))
        controller_id = db.add_controller("Test Controller", "127.0.0.1",
                                          snmp_version=1, community="public")
        controller = db.controller(controller_id)

        poller = WirelessPoller(db)
        poller._spawn = lambda *a, **k: None    # no loop thread: only start()'s cache fill matters here
        poller.start()          # fills _settings_state, the way _restart() does on a save

        with StatementCounter(db._conn) as counter:
            poller._poll_controller(dict(controller))
        reads = [s for s in counter.statements if "FROM settings" in s]
        check(not reads,
              f"one controller poll reads the settings table {len(reads)} "
              f"time(s) (the cached settings are read instead)")
        check(poller._settings_state[1]["stale_after_polls"]
              == db.settings()["stale_after_polls"],
              "…and what it cached is what the settings table says")

        # The regression to guard against: a save lands (synchronously) well
        # before _apply_wireless's queued restart actually calls start() --
        # simulated here by NOT calling start() at all after the save.
        db.save_settings({"stale_after_polls": 9})
        check(poller._settings_state[1]["stale_after_polls"] != 9,
              "sanity: the cache has not been touched by the save itself")
        with StatementCounter(db._conn) as counter:
            poller._poll_controller(dict(controller))
        reads = [s for s in counter.statements if "FROM settings" in s]
        check(len(reads) == 1,
              f"a save moves the generation, so the very next poll (still "
              f"ahead of any restart) rebuilds the cache once "
              f"(got {len(reads)} read(s))")
        check(poller._settings_state[1]["stale_after_polls"] == 9,
              "…and sees the new value without waiting for a restart")

        # A later restart (whenever the queued one actually runs, or the
        # manual enable/disable route in api/wireless.py) still works too.
        db.save_settings({"stale_after_polls": 4})
        poller.start()
        check(poller._settings_state[1]["stale_after_polls"] == 4,
              "…and start() itself still picks up whatever is current")

        poller.stop()
        db.close()
    finally:
        stub.kill()

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
