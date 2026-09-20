"""5.50.0: an operationally-down interface stops storing per-port samples.
At fleet scale (2,000 devices x 50 ports, 60s poll) writing ten metric rows
a poll for every down port -- most of it zeros -- was ~800,000 inserts a
cycle and tens of GB of raw samples a day. record_metric_samples already
treats a None value as "polled, no answer" (updates last_ts, stores no
sample row); this only has to stop poll_mixin computing a real number for a
port that is down and hand it None instead, without dropping the tuple.

_poll_interfaces is stubbed directly rather than taught to the SNMP stub
agent, since oper_status per port is all this needs to control.
"""
import os
import sys
import time

import _paths
from _paths import spawn_stub, tmpdir

TMPDIR = tmpdir("poll_down_ports_")

from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


_PER_PORT_SUFFIXES = (
    "in_bps", "out_bps", "in_err", "out_err", "in_error_rate",
    "out_error_rate", "in_discard_rate", "out_discard_rate",
    "in_util_pct", "out_util_pct")


def _rows(oper7: str, oper8: str, octets: tuple):
    """Two interfaces (7, 8) with independently controllable oper_status."""
    o7, o8 = octets
    return [
        {"if_index": 7, "descr": "Gi0/7", "alias": "", "admin_status": "up",
         "oper_status": oper7, "speed_bps": 1_000_000_000, "in_octets": o7,
         "out_octets": o7 // 2, "in_errors": 0, "out_errors": 0,
         "in_discards": 0, "out_discards": 0},
        {"if_index": 8, "descr": "Gi0/8", "alias": "", "admin_status": "up",
         "oper_status": oper8, "speed_bps": 1_000_000_000, "in_octets": o8,
         "out_octets": o8 // 2, "in_errors": 0, "out_errors": 0,
         "in_discards": 0, "out_discards": 0},
    ]


def main():
    print("\n-- down ports stop storing per-interface samples")
    proc, port = spawn_stub("stub_agent_iftable.py", "ok", "--interfaces", "1")
    try:
        _paths.patch_nodepoll("DEFAULT_SNMP_PORT", port)
        db = NodesDatabase(os.path.join(TMPDIR, "down.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "down-port-test", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)

        def poll(rows):
            poller._poll_interfaces = lambda *a, **kw: (rows, True, "", None)
            device = db.device(device_id)
            poller._poll_device(device, db.effective_config(device))

        # Poll 1: both ports up, baseline counters -- no prior yet, so no
        # rate is computable regardless of up/down (existing behaviour,
        # unaffected).
        poll(_rows("up", "up", (1_000_000, 2_000_000)))
        time.sleep(1.05)

        # Poll 2: port 7 stays up and passes traffic; port 8 goes down.
        poll(_rows("up", "down", (2_000_000, 2_000_000)))
        metrics = {row["key"]: row for row in db.metrics(device_id)}
        m7, m8 = metrics.get("if_in_bps.7"), metrics.get("if_in_bps.8")
        check(m7 is not None and m7["last_value"] is not None and m7["last_value"] > 0,
              f"an up port keeps computing and storing its rate ({m7 and dict(m7)})")
        check(m8 is not None and m8["last_value"] is None,
              f"a down port's rate metric is present but NULL, not a zero "
              f"({m8 and dict(m8)})")
        check(m8 is not None and m8["last_ts"] is not None
              and abs(m8["last_ts"] - m7["last_ts"]) < 2,
              f"...with last_ts current, same poll as the up port "
              f"({m8 and dict(m8)})")
        window = (m7["last_ts"] - 60, m7["last_ts"] + 60)
        series8 = db.series(device_id, m8["id"], *window)
        check(series8 == [],
              f"…and no raw sample row was written for the down port ({series8})")
        series7 = db.series(device_id, m7["id"], *window)
        check(len(series7) == 1,
              f"…while the up port's real rate landed one sample ({series7})")

        for suffix in _PER_PORT_SUFFIXES:
            m = metrics.get(f"if_{suffix}.8")
            check(m is not None and m["last_value"] is None,
                  f"every one of the ten per-port keys is NULL for the down "
                  f"port, none dropped ({suffix}: {m and dict(m)})")

        # Poll 3: port 7 goes down too -- every port on the device is down.
        time.sleep(1.05)
        poll(_rows("down", "down", (3_000_000, 2_000_000)))
        metrics = {row["key"]: row for row in db.metrics(device_id)}
        for suffix in ("in_util_pct", "out_util_pct", "in_error_rate",
                      "out_error_rate", "in_discard_rate", "out_discard_rate"):
            m = metrics.get(f"if_{suffix}")
            check(m is not None and m["last_value"] is None,
                  f"the device-level worst-port aggregate reports NULL, not "
                  f"vanished, when every port is down "
                  f"({suffix}: {m and dict(m)})")

        # A dormant port is treated the same as down, not as up.
        time.sleep(1.05)
        poll(_rows("up", "dormant", (4_000_000, 2_000_000)))
        metrics = {row["key"]: row for row in db.metrics(device_id)}
        check(metrics["if_in_bps.8"]["last_value"] is None,
              f"a dormant port is treated as down, not up "
              f"({dict(metrics['if_in_bps.8'])})")

        poller.shutdown()
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
