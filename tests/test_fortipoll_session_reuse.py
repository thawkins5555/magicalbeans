"""_snmp_walk_request (formerly _snmp_get_next) used to open a new _Session
(a UDP socket) for every request inside _walk_column's loop. _walk_column
now opens one session for the whole walk and reuses it. Same PDUs/request
ids/timeouts/retries/error mapping -- this pins only that the socket count
drops to one per walk (not one per row), that _poll_controller opens exactly
one per column walked, and that the walked values are unchanged, against the
real stub agent."""
import os
import sys

import _paths
from _paths import spawn_stub, tmpdir

TMPDIR = tmpdir("fortipoll_session_reuse_")

from netpath.fortipoll import WirelessPoller
import netpath.fortipoll as fortipoll_mod
from netpath.wirelessdb import WirelessDatabase
from netpath import nodeoids as oids

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


def counting_session(counts):
    """A _Session subclass that counts constructions and close()s, real
    socket and wire behaviour otherwise unchanged."""
    real_session = fortipoll_mod._Session

    class CountingSession(real_session):
        def __init__(self, *args, **kwargs):
            counts["opened"] += 1
            super().__init__(*args, **kwargs)

        def close(self):
            counts["closed"] += 1
            super().close()

    return CountingSession


def main():
    stub, fortipoll_mod.SNMP_PORT = spawn_stub("wireless_stub_agent.py")
    try:
        db = WirelessDatabase(os.path.join(TMPDIR, "wireless.db"))
        controller_id = db.add_controller("Test Controller", "127.0.0.1",
                                          snmp_version=1, community="public")
        controller = dict(db.controller(controller_id))
        config = {"snmp_version": 1, "community": "public"}

        poller = WirelessPoller(db)
        counts = {"opened": 0, "closed": 0}
        real_session = fortipoll_mod._Session
        fortipoll_mod._Session = counting_session(counts)
        try:
            # One column, two AP rows -- the old code opened a session per
            # row (plus the terminating GETNEXT); it must now open exactly one.
            values = poller._walk_column(controller, config, oids.WTP_SESSION_MAC)
        finally:
            fortipoll_mod._Session = real_session

        check(len(values) == 2, f"the walk still finds both APs' MACs (got {values})")
        check(counts["opened"] == 1,
              f"one column walk opens {counts['opened']} session(s), not one per row")
        check(counts["closed"] == 1,
              f"…and closes exactly {counts['closed']} of them")

        # ---------------------------------------------- a whole controller poll

        counts = {"opened": 0, "closed": 0}
        fortipoll_mod._Session = counting_session(counts)
        try:
            poller._poll_controller(controller)
        finally:
            fortipoll_mod._Session = real_session

        aps = db.access_points(controller_id)
        check(len(aps) == 2, f"the full poll still finds 2 APs (got {len(aps)})")
        # _poll_controller walks 15 columns (see its own body); one session
        # each, not one per (column, row) -- which at 2 APs / 3 radios would
        # otherwise run into dozens.
        check(counts["opened"] == 15,
              f"one controller poll opens {counts['opened']} session(s) "
              f"(one per column walked), not one per row across every column")
        check(counts["opened"] == counts["closed"],
              "…and every session opened is closed")

        # -------------------------------------------- a walk that raises mid-way

        counts = {"opened": 0, "closed": 0}
        fortipoll_mod._Session = counting_session(counts)
        real_walk_request = poller._snmp_walk_request
        calls = {"n": 0}

        # Raised on the very first request, not the second: with GETBULK a
        # two-row column can finish in one round trip, so only the first
        # call is guaranteed to happen whichever protocol the walk used.
        def failing_walk_request(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise fortipoll_mod.SnmpError("stub-injected failure")
            return real_walk_request(*args, **kwargs)

        poller._snmp_walk_request = failing_walk_request
        try:
            try:
                poller._walk_column(controller, config, oids.WTP_SESSION_MAC)
                raised = False
            except fortipoll_mod.SnmpError:
                raised = True
        finally:
            poller._snmp_walk_request = real_walk_request
            fortipoll_mod._Session = real_session

        check(raised, "the injected failure reaches _walk_column's caller")
        check(counts["opened"] == 1 and counts["closed"] == 1,
              f"…and the walk's one session is still closed on the way out "
              f"(opened={counts['opened']}, closed={counts['closed']})")

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
