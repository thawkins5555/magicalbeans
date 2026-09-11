"""Controller poll staggering: a restart used to seed every controller's
first due time at 0, so they all fired on the first pass of _loop and stayed
phase-locked for the life of the process — one SNMP burst per interval
however many controllers a site has.

Pure scheduling: no SNMP, no threads, no sleeps. _schedule_pass is driven
against a clock the test advances by hand, with poll_now replaced by a
recorder and fortipoll.random seeded so every number below is reproducible."""
import os
import random
import sys
import time

import _paths  # noqa: F401
from _paths import tmpdir

from netpath import fortipoll
from netpath.fortipoll import WirelessPoller
from netpath.wirelessdb import WirelessDatabase

CONTROLLERS = 12
INTERVAL = 60
T0 = 1_700_000_000.0
FAILURES = []
SPREAD = getattr(fortipoll, "POLL_SPREAD_S", 30.0)


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


class Clock:
    def __init__(self, at: float):
        self.now = at

    def time(self) -> float:
        return self.now

    def __getattr__(self, name):
        return getattr(time, name)


def build(last_poll_ts=None):
    db = WirelessDatabase(os.path.join(tmpdir("wl_stagger_"), "wireless.db"))
    db.save_settings({"poll_interval_s": INTERVAL})
    ids = [db.add_controller(f"wlc-{i}", f"10.0.0.{i + 1}", snmp_version=1,
                             community="public") for i in range(CONTROLLERS)]
    if last_poll_ts is not None:
        with db._lock:
            db._conn.executemany(
                "UPDATE controllers SET last_poll_ts = ?, last_poll_ok = 1"
                " WHERE id = ?", [(last_poll_ts, cid) for cid in ids])
            db._conn.commit()
    poller = WirelessPoller(db)
    polled = []
    poller.poll_now = lambda controller_id: polled.append(
        (controller_id, fortipoll.time.time()))
    return db, poller, ids, polled


def run_passes(poller, clock, seconds: int) -> None:
    for _ in range(seconds):
        clock.now += 1.0
        poller._schedule_pass()


def per_pass(polled) -> dict[float, int]:
    counts: dict[float, int] = {}
    for _cid, at in polled:
        counts[at] = counts.get(at, 0) + 1
    return counts


# --------------------------------------------------- 1. a restart spreads

def restart_spread(clock):
    db, poller, ids, polled = build(last_poll_ts=T0 - 10 * INTERVAL)
    clock.now = T0
    poller._schedule_pass()
    dues = [poller._next_run[cid] for cid in ids]
    check(not polled,
          f"a set of controllers with a stale last_poll_ts does not all fire "
          f"on pass one ({len(polled)} polled)")
    check(all(T0 <= due <= T0 + SPREAD for due in dues),
          f"…their due times land inside the spread window "
          f"({min(dues) - T0:.1f}..{max(dues) - T0:.1f} s)")
    check(len(set(dues)) > CONTROLLERS // 2,
          f"…at distinct times ({len(set(dues))} distinct of {CONTROLLERS})")

    run_passes(poller, clock, int(SPREAD) + 1)
    check({cid for cid, _at in polled} == set(ids),
          f"every controller is polled within the spread window "
          f"({len({cid for cid, _at in polled})} of {CONTROLLERS})")
    peak = max(per_pass(polled).values(), default=0)
    check(peak <= max(2, CONTROLLERS // 3),
          f"…with no single pass taking more than a third of them (peak {peak})")
    db.close()


# ------------------------------------ 2. a controller not yet due waits

def not_yet_due(clock):
    db, poller, ids, polled = build(last_poll_ts=T0 - 5)
    clock.now = T0
    poller._schedule_pass()
    check(not polled, "a controller polled 5 s ago is not polled again at once")
    check(all(poller._next_run[cid] >= T0 + INTERVAL - 5 for cid in ids),
          "…its due time still honours its own interval")
    db.close()


# ----------------------------------- 3. never polled: immediate, pinned

def never_polled(clock):
    db, poller, ids, polled = build()
    clock.now = T0
    poller._schedule_pass()
    check({cid for cid, _at in polled} == set(ids),
          "a controller that has never been polled is polled on the first "
          "pass [pinned, not shown red]")
    db.close()


# ------------------------------------------- 4. the spread survives a cycle

def stays_spread(clock):
    db, poller, _ids, polled = build(last_poll_ts=T0 - 10 * INTERVAL)
    clock.now = T0
    run_passes(poller, clock, 3 * INTERVAL)
    peak = max(per_pass(polled).values())
    check(peak <= max(2, CONTROLLERS // 3),
          f"three cycles on, the load is still spread (peak {peak} per pass)")
    by_controller: dict[int, list[float]] = {}
    for cid, at in polled:
        by_controller.setdefault(cid, []).append(at)
    gaps = [b - a for stamps in by_controller.values()
            for a, b in zip(stamps, stamps[1:])]
    check(gaps and max(gaps) <= INTERVAL,
          f"…and no controller's period exceeds its interval "
          f"(max gap {max(gaps) if gaps else 0:.1f} s)")
    db.close()


# --------------------------------------- 5. disabled controllers are skipped

def disabled_skipped(clock):
    db, poller, ids, polled = build()
    db.update_controller(ids[0], enabled=False)
    clock.now = T0
    poller._schedule_pass()
    check(ids[0] not in {cid for cid, _at in polled},
          "a disabled controller is not polled [pinned, not shown red]")
    db.close()


def main():
    clock = Clock(T0)
    real_time, real_random = fortipoll.time, fortipoll.random
    fortipoll.time = clock
    fortipoll.random = random.Random(11)
    try:
        restart_spread(clock)
        not_yet_due(clock)
        never_polled(clock)
        stays_spread(clock)
        disabled_skipped(clock)
    finally:
        fortipoll.time, fortipoll.random = real_time, real_random

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
