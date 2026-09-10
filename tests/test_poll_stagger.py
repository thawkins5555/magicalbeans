"""Jitter on the main poll cycle: a restart spreads a stale fleet over
_STARTUP_SPREAD_S instead of firing it on pass one, and the first reschedule
after a poll breaks the phase lock that kept devices due together for the
life of the process. The startup spread is the one deliberate delay, bounded
by _STARTUP_SPREAD_S or the interval; a never-polled device is never delayed,
and neither spread stretches any device's period past its interval.

No threads and no sleeps: _schedule_pass is driven directly against a clock
the test advances by hand and a seeded random.Random swapped into nodepoll,
so every number below is reproducible."""
import os
import random
import sys
import time

import _paths  # noqa: F401
from _paths import tmpdir

from netpath import nodepoll
from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase

DEVICES = 200
INTERVAL = 60
T0 = 1_700_000_000.0
FAILURES = []
# getattr so the suite also runs against a nodepoll.py that predates the fix.
SPREAD = getattr(nodepoll, "_STARTUP_SPREAD_S", 30.0)
MIN_FRACTION = getattr(nodepoll, "_STAGGER_MIN_FRACTION", 0.5)


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
    """A fleet on one interval, a poller whose _submit only records, and
    the (device_id, now, next_run) tuple of every submission."""
    db = NodesDatabase(os.path.join(tmpdir("stagger_"), "nodes.db"))
    group = db.ensure_default_group()
    db.update_group(group, poll_interval_s=INTERVAL)
    ids = [db.add_device(f"10.{i // 250}.{i % 250}.1", f"dev-{i}", group_id=group)
           for i in range(DEVICES)]
    if last_poll_ts is not None:
        with db._lock:
            db._conn.executemany(
                "UPDATE devices SET last_poll_ts = ? WHERE id = ?",
                [(last_poll_ts, device_id) for device_id in ids])
            db._conn.commit()
    poller = NodePoller(db)
    submissions = []

    def submit(device_id):
        submissions.append((device_id, nodepoll.time.time(),
                            poller._next_run[device_id]))
        return False

    poller._submit = submit
    return db, poller, ids, submissions


def run_passes(poller, clock, seconds: int) -> None:
    for _ in range(seconds):
        clock.now += 1.0
        poller._schedule_pass()


def per_pass(submissions) -> dict[float, int]:
    counts: dict[float, int] = {}
    for _device_id, at, _due in submissions:
        counts[at] = counts.get(at, 0) + 1
    return counts


# ------------------------------------------------------ 1. restart spread

def restart_spread(clock):
    db, poller, ids, submissions = build(last_poll_ts=T0 - 10 * INTERVAL)
    clock.now = T0
    poller._schedule_pass()
    dues = [poller._next_run[i] for i in ids]
    check(not submissions,
          f"a fleet with stale last_poll_ts does not all fire on pass one "
          f"({len(submissions)} submitted)")
    check(all(T0 <= due <= T0 + SPREAD for due in dues),
          f"…its due times are within _STARTUP_SPREAD_S of the pass "
          f"(range {min(dues) - T0:.1f}..{max(dues) - T0:.1f} s)")
    check(max(dues) - min(dues) > SPREAD / 2,
          f"…and spread across that window ({max(dues) - min(dues):.1f} s)")

    run_passes(poller, clock, int(SPREAD))
    polled = {device_id for device_id, _at, _due in submissions}
    peak = max(per_pass(submissions).values(), default=0)
    check(polled == set(ids),
          f"every stale device is polled within _STARTUP_SPREAD_S "
          f"({len(polled)} of {DEVICES})")
    check(len(submissions) == DEVICES,
          f"…exactly once each ({len(submissions)} submissions)")
    check(peak <= DEVICES // 4,
          f"…with no single pass submitting more than a quarter of the fleet "
          f"(peak {peak})")
    check(all(due - at <= INTERVAL for _id, at, due in submissions),
          "…and none rescheduled later than its interval")
    db.close()


# ---------------------------------------------- 2. never polled: pinned

def never_polled_still_immediate(clock):
    """Cannot fail against HEAD by construction: it pins the behaviour the
    fix must preserve, that a device with no last_poll_ts is polled now."""
    db, poller, ids, submissions = build()
    clock.now = T0
    poller._schedule_pass()
    check({d for d, _at, _due in submissions} == set(ids),
          f"a never-polled fleet is submitted on its first pass "
          f"({len(submissions)} of {DEVICES}) [pinned, not shown red]")

    added = db.add_device("192.0.2.77", "late-arrival",
                          group_id=db.ensure_default_group())
    del submissions[:]
    run_passes(poller, clock, 1)
    check([d for d, _at, _due in submissions] == [added],
          "a device added between passes is polled on the very next one "
          "[pinned, not shown red]")
    db.close()


# ------------------------------------------- 3 + 4. phase break, period

def phase_break(clock):
    db, poller, ids, submissions = build()
    clock.now = T0
    stuck = ids[-1]
    poller._queued[stuck] = T0 - 1
    poller._schedule_pass()
    check(poller._next_run[stuck] == T0 + INTERVAL
          and stuck not in poller._staggered,
          "a device still queued when it comes due is not pulled earlier, "
          "and keeps its phase break for later")
    del poller._queued[stuck]
    ids = ids[:-1]
    dues = [poller._next_run[i] for i in ids]
    check(len(set(dues)) > DEVICES // 2,
          f"after one cycle a phase-locked fleet has dispersed due times "
          f"({len(set(dues))} distinct of {DEVICES})")
    check(all(T0 + MIN_FRACTION * INTERVAL <= due <= T0 + INTERVAL for due in dues),
          f"…every one pulled earlier, never later, within "
          f"[{MIN_FRACTION:.1f}, 1.0] x interval "
          f"(range {min(dues) - T0:.1f}..{max(dues) - T0:.1f} s)")

    del submissions[:]
    cycles = 4
    run_passes(poller, clock, cycles * INTERVAL)
    peak = max(per_pass(submissions).values())
    check(peak <= DEVICES // 4,
          f"the second cycle is spread rather than a burst (peak {peak} per pass)")
    check(all(due - at == INTERVAL
              for device_id, at, due in submissions if device_id != stuck),
          "…and every reschedule after the first is the plain interval")
    own = [due - at for device_id, at, due in submissions if device_id == stuck]
    check(own and MIN_FRACTION * INTERVAL <= own[0] < INTERVAL
          and all(gap == INTERVAL for gap in own[1:]),
          f"…the once-stuck device gets its phase break on its next reschedule "
          f"({own[:2]})")

    by_device: dict[int, list[float]] = {}
    for device_id, at, _due in submissions:
        by_device.setdefault(device_id, []).append(at)
    gaps = [later - earlier for stamps in by_device.values()
            for earlier, later in zip(stamps, stamps[1:])]
    check(max(gaps) <= INTERVAL,
          f"no device's period ever exceeds its interval (max gap {max(gaps):.1f} s)")
    check(max(len(stamps) for stamps in by_device.values()) <= cycles + 1,
          "…and the jitter costs at most one extra poll per device")

    staggered = getattr(poller, "_staggered", None)
    poller._forget_devices({ids[0]})
    check(staggered is not None and staggered == {ids[0]},
          "the phase-break flag is dropped with the device's other state")
    db.close()


# ------------------------------------------------------------ focus path

def focus_unjittered(clock):
    db, poller, ids, submissions = build()
    focused, fast, ttl = ids[0], 5.0, 120.0
    clock.now = T0
    poller.set_focus(focused, ttl, fast)
    run_passes(poller, clock, int(ttl))
    own = [(at, due) for device_id, at, due in submissions if device_id == focused]
    check(own and all(due - at == fast for at, due in own),
          f"a focused device keeps its exact fast cadence, no jitter "
          f"({len(own)} polls)")

    del submissions[:]
    run_passes(poller, clock, 2 * INTERVAL)
    own = [due - at for device_id, at, due in submissions if device_id == focused]
    check(len(own) >= 2 and MIN_FRACTION * INTERVAL <= own[0] < INTERVAL,
          f"…its first unfocused reschedule is the jittered one "
          f"({own[0] if own else None!r} s)")
    check(len(own) >= 2 and all(gap == INTERVAL for gap in own[1:]),
          f"…and every one after that is the plain interval ({own[1:]})")
    db.close()


def main():
    clock = Clock(T0)
    real_time, real_random = nodepoll.time, nodepoll.random
    nodepoll.time = clock
    nodepoll.random = random.Random(7)
    try:
        restart_spread(clock)
        never_polled_still_immediate(clock)
        phase_break(clock)
        focus_unjittered(clock)
    finally:
        nodepoll.time, nodepoll.random = real_time, real_random

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
