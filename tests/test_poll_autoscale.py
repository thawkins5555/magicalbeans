"""The poll pool sizing itself, and a down device's SNMP backing off.

Two changes that share a file and a motive: at a thousand devices the pool
size an operator picked once is the wrong number most of the time, and the
most expensive thing this poller does is keep asking a device that is not
answering. Neither may change what the fleet's status timeline says, which
is what most of the checks below are actually about.

No SNMP and no sockets. The controller is arithmetic over dicts already in
hand, and the backoff is exercised through _poll_device with ping stubbed.
"""
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import _paths  # noqa: F401  (repo root + tests dir on sys.path)
from _paths import tmpdir

from netpath import nodepoll
from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


def build(devices=300, interval=60, **settings):
    db = NodesDatabase(os.path.join(tmpdir("autoscale_"), "nodes.db"))
    group = db.ensure_default_group()
    # The timeout has to be set on the GROUP, not through save_settings: the
    # seeded default profile carries its own snmp_timeout_s of 3.0 and two
    # retries, and a profile value wins over the global default. Without this
    # the backoff checks below -- which call _poll_device for real against an
    # address nothing answers on -- wait out three seconds three times per
    # poll, which was 117 of this suite's 118 seconds.
    db.update_group(group, poll_interval_s=interval,
                    snmp_timeout_s=0.2, snmp_retries=0)
    ids = [db.add_device("10.0.%d.%d" % (i // 250, i % 250), "dev%d" % i,
                         group_id=group)
           for i in range(devices)]
    values = {"poll_workers_auto": True, "poll_workers_min": 4,
              "poll_workers_max": 128}
    values.update(settings)
    db.save_settings(values)
    poller = NodePoller(db)
    poller._read_pool_settings(db.settings())
    poller._executor = ThreadPoolExecutor(max_workers=8)
    return db, poller, ids


def drive(poller, ids, cost, interval, seconds, start):
    """`seconds` of scheduling passes at 1 Hz with every device costing
    `cost`, and the pool size it settles at.

    The demand figure is computed once rather than per tick: every device
    here has the same cost, so the sum _schedule_pass would accumulate is
    constant, and re-adding three hundred identical terms a few thousand
    times is the whole runtime of this suite rather than any of its meaning.
    """
    for device_id in ids:
        poller._poll_cost[device_id] = cost
    demand = sum(poller._poll_cost[i] / interval for i in ids)
    for tick in range(seconds):
        poller._autoscale_pass(start + tick, demand)
    return poller._executor._max_workers


# ------------------------------------------------------------- the controller

def controller():
    db, poller, ids = build()
    at = time.time()

    # A healthy fleet needs almost nothing: 300 devices at 0.3 s each every
    # 60 s is 1.5 workers' worth of work. It must fall to the floor and stop.
    size = drive(poller, ids, 0.30, 60, 400, at)
    check(size == 4, "a fleet needing 1.5 workers falls to the floor of 4 "
                     "(got %d)" % size)

    # A quarter of the fleet goes down. A down device costs about 9 s, so
    # demand rises to ~12.4 workers and the pool has to follow it.
    at += 1000
    for device_id in ids[:75]:
        poller._poll_cost[device_id] = 9.0
    demand = sum(poller._poll_cost[i] / 60 for i in ids)
    for tick in range(600):
        poller._autoscale_pass(at + tick, demand)
    grown = poller._executor._max_workers
    check(grown >= 18, "a site outage grows the pool to cover it "
                       "(12.4 needed, x1.5 headroom, got %d)" % grown)

    # ...and it comes back down when the outage clears, never under the floor.
    at += 2000
    size = drive(poller, ids, 0.30, 60, 2000, at)
    check(size == 4, "the pool returns to the floor once the outage clears "
                     "(got %d)" % size)

    # The ceiling is a hard stop, not a suggestion.
    at += 5000
    size = drive(poller, ids, 60.0, 60, 4000, at)
    check(size == 128, "demand far past the ceiling stops at the ceiling "
                       "(got %d)" % size)
    db.close()


def bounds_and_damping():
    db, poller, ids = build(devices=10)
    at = time.time()

    # Growth is capped per step: however large the demand, one resize must
    # not leap from the floor to the ceiling.
    poller._executor = ThreadPoolExecutor(max_workers=4)
    for device_id in ids:
        poller._poll_cost[device_id] = 60.0
    poller._autoscale_pass(at, 600.0)
    check(poller._executor._max_workers <= 8,
          "one resize at most doubles the pool (4 -> %d)"
          % poller._executor._max_workers)

    # Shrinking takes repeated agreement, so one quiet pass cannot halve a
    # pool that is about to be busy again.
    db2, poller2, _ids2 = build(devices=10)
    poller2._executor = ThreadPoolExecutor(max_workers=64)
    at2 = time.time()
    poller2._autoscale_pass(at2, 0.1)
    check(poller2._executor._max_workers == 64,
          "one low reading does not shrink the pool")
    for tick in range(1, poller2._AUTOSCALE_SHRINK_VOTES - 1):
        poller2._autoscale_pass(at2 + tick * poller2._AUTOSCALE_INTERVAL_S, 0.1)
    check(poller2._executor._max_workers == 64,
          "...nor do %d of them, one short of the vote"
          % (poller2._AUTOSCALE_SHRINK_VOTES - 1))
    poller2._autoscale_pass(
        at2 + (poller2._AUTOSCALE_SHRINK_VOTES - 1) * poller2._AUTOSCALE_INTERVAL_S,
        0.1)
    check(poller2._executor._max_workers < 64,
          "...and the %dth does shrink it, by a quarter at most (64 -> %d)"
          % (poller2._AUTOSCALE_SHRINK_VOTES, poller2._executor._max_workers))
    check(poller2._executor._max_workers >= 48,
          "...never more than a quarter in one step (got %d)"
          % poller2._executor._max_workers)
    db.close()
    db2.close()


def auto_off_is_unchanged():
    db, poller, _ids = build(poll_workers_auto=False, poll_workers=23)
    check(poller._initial_pool_size() == 23,
          "with auto off the pool is exactly poll_workers")
    check(poller._autoscale_ceiling is None,
          "...and no ceiling is published, so the saturation alert reads as it "
          "always did")
    before = poller._executor._max_workers
    for tick in range(400):
        poller._autoscale_pass(time.time() + tick, 999.0)
    check(poller._executor._max_workers == before,
          "...and no amount of demand resizes it")
    db.close()


def upgrade_keeps_the_operators_number():
    """The floor of an upgraded install is whatever it was already running."""
    path = os.path.join(tmpdir("autoscale_upgrade_"), "nodes.db")
    db = NodesDatabase(path)
    db.save_settings({"poll_workers": 48})
    db.close()

    # An install from before the setting existed.
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM settings WHERE key = 'poll_workers_min'")
    conn.commit()
    conn.close()

    db = NodesDatabase(path)
    settings = db.settings()
    check(settings["poll_workers_min"] == 48,
          "an upgrade seeds the floor from the operator's own poll_workers "
          "(got %s)" % settings["poll_workers_min"])
    poller = NodePoller(db)
    poller._read_pool_settings(settings)
    check(poller._initial_pool_size() >= 48,
          "...so the pool never starts smaller than the fleet already ran at")
    db.close()


def clamps():
    db = NodesDatabase(os.path.join(tmpdir("autoscale_clamp_"), "nodes.db"))
    db.save_settings({"poll_workers": 100000})
    check(db.settings()["poll_workers"] == NodesDatabase.MAX_POLL_WORKERS,
          "poll_workers is bounded server-side, not only by the browser")
    db.save_settings({"poll_workers_min": 200, "poll_workers_max": 50})
    settings = db.settings()
    check(settings["poll_workers_min"] <= settings["poll_workers_max"],
          "an inverted floor/ceiling pair is settled rather than stored (%s / %s)"
          % (settings["poll_workers_min"], settings["poll_workers_max"]))
    db.save_settings({"poll_pool_headroom": 99})
    check(db.settings()["poll_pool_headroom"] == 4.0, "headroom is bounded too")
    db.close()


def scheduling_pass_issues_no_sql():
    """Why floor and ceiling are cached on the poller rather than read.

    tests/test_scheduler.py pins a steady pass at five statements; this
    checks the autoscaler specifically contributes none of its own.
    """
    db, poller, _ids = build(devices=50)
    statements = []
    db._conn.set_trace_callback(statements.append)
    try:
        poller._autoscale_pass(time.time(), 3.0)
        poller._autoscale_pass(time.time() + 100, 3.0)
    finally:
        db._conn.set_trace_callback(None)
    check(not statements, "the autoscaler issues no SQL at all (got %s)" % statements)
    db.close()


# ---------------------------------------------------------- the SNMP backoff

def backoff_cadence():
    db, poller, _ids = build(devices=1)
    check(poller._SNMP_BACKOFF_SKIPS == 2, "two skips, then an attempt")
    pattern = [poller._snmp_backoff_due(1) for _ in range(9)]
    check(pattern == [True, True, False] * 3,
          "a down device skips SNMP on two cycles in three (got %s)" % pattern)
    check(pattern.count(False) == 3,
          "...so SNMP is attempted 3 times in 9 cycles, not 9")
    db.close()


def backoff_never_touches_a_device_answering_ping():
    """snmp_failing_ping_ok is the alert that has to keep counting.

    A device answering ping with a dead SNMP agent is NOT down, and it is
    exactly what snmp_fail_alert_after counts toward. If such a device could
    be backed off, that alert would never reach its threshold. Checked by
    polling one rather than by reading the predicate, so it keeps meaning
    something if the predicate is rewritten.
    """
    db, poller, ids = build(devices=1, interval=10)
    device_id = ids[0]
    # Formally down first, so the status half of the predicate is satisfied
    # and only the ping half is left to do the work.
    for _ in range(4):
        db.record_poll(device_id, ping_ok=False, ping_rtt_ms=None, snmp_ok=False,
                       snmp_error="timeout", identity=None, uptime_ticks=None,
                       status="down", reachable=False)
    check(db.device(device_id)["status"] == "down", "the fixture device is down")

    # Now ping starts answering while SNMP stays dead: the reachable-but-
    # broken case. Every cycle must still attempt SNMP.
    original = nodepoll.ping_many
    nodepoll.ping_many = lambda ip, count=3, timeout_ms=1000: (count, count, 1.0)
    try:
        config = db.effective_config(db.device(device_id))
        config["snmp_enabled"] = True
        config["ping_enabled"] = True
        before = poller.counters["snmp_backoff"]
        for _ in range(6):
            poller._poll_device(db.device(device_id), config)
        skipped = poller.counters["snmp_backoff"] - before
    finally:
        nodepoll.ping_many = original

    check(skipped == 0,
          "a device answering ping never has its SNMP backed off, whatever its "
          "stored status says (skipped %d of 6 cycles)" % skipped)
    check(poller._snmp_failing_count.get(device_id, 0) > 0,
          "...so snmp_fail_alert_after keeps counting toward "
          "snmp_failing_ping_ok (count %d)"
          % poller._snmp_failing_count.get(device_id, 0))
    db.close()


def backoff_needs_ping_to_be_running():
    """With ping switched off, SNMP is the only evidence the device exists.

    Ping being unbacked-off is the whole reason the backoff is safe: it is
    what notices the recovery. A profile with ping disabled has no such
    safety, so nothing may be skipped there -- caught for real by
    test_nodepoll_e2e, where a ping-less device that came back was never
    seen to come back.
    """
    db, poller, ids = build(devices=1, interval=10)
    device_id = ids[0]
    for _ in range(4):
        db.record_poll(device_id, ping_ok=None, ping_rtt_ms=None, snmp_ok=False,
                       snmp_error="timeout", identity=None, uptime_ticks=None,
                       status="down", reachable=False)
    config = db.effective_config(db.device(device_id))
    config["snmp_enabled"] = True
    config["ping_enabled"] = False
    before = poller.counters["snmp_backoff"]
    for _ in range(6):
        poller._poll_device(db.device(device_id), config)
    skipped = poller.counters["snmp_backoff"] - before
    check(skipped == 0,
          "a device with ping disabled never has its SNMP backed off "
          "(skipped %d of 6 cycles)" % skipped)
    db.close()


def backoff_records_no_phantom_snmp_failure():
    """A skipped SNMP phase must not read as a failed one.

    snmp_failing_now is `snmp_ok is False and ping_ok`. Carrying False
    forward through a skipped cycle makes that true the moment ping
    recovers, counting a failure toward snmp_fail_alert_after on a poll that
    never spoke SNMP. None is this file's own "did not touch that method",
    and is what the skipped branch leaves in place -- while the device ROW
    still stores what SNMP last actually reported.
    """
    db, poller, ids = build(devices=1, interval=10)
    device_id = ids[0]
    for _ in range(4):
        db.record_poll(device_id, ping_ok=False, ping_rtt_ms=None, snmp_ok=False,
                       snmp_error="timeout", identity=None, uptime_ticks=None,
                       status="down", reachable=False)
    check(db.device(device_id)["status"] == "down", "the fixture device is down")

    pings = []

    def fake_ping(ip, count=3, timeout_ms=1000):
        pings.append(ip)
        return count, 0, None

    original = nodepoll.ping_many
    nodepoll.ping_many = fake_ping
    try:
        config = db.effective_config(db.device(device_id))
        config["snmp_enabled"] = True
        config["ping_enabled"] = True
        # Two backed-off cycles, then the third, which is the attempt.
        for _ in range(poller._SNMP_BACKOFF_SKIPS):
            poller._poll_device(db.device(device_id), config)
        backed_off = db.device(device_id)
        skipped_count = poller.counters["snmp_backoff"]
        poller._poll_device(db.device(device_id), config)
    finally:
        nodepoll.ping_many = original

    check(len(pings) == poller._SNMP_BACKOFF_SKIPS + 1,
          "ping runs on every cycle, backed-off ones included (got %d)" % len(pings))
    check(backed_off["snmp_ok"] == 0,
          "a backed-off cycle carries the stored SNMP state forward rather than "
          "blanking it (got %r)" % backed_off["snmp_ok"])
    check(backed_off["snmp_error"] == "timeout",
          "...and the error it last reported with it (got %r)"
          % backed_off["snmp_error"])
    check(skipped_count == poller._SNMP_BACKOFF_SKIPS,
          "...for exactly the two cycles the cap allows (got %d)" % skipped_count)
    after = db.device(device_id)
    check(after["snmp_error"] and after["snmp_error"] != "timeout",
          "...and the third cycle really does attempt SNMP again, writing what "
          "it found (got %r)" % after["snmp_error"])
    check(poller._snmp_failing_count.get(device_id, 0) == 0,
          "no phantom SNMP failure is counted on a cycle that skipped SNMP")
    check(poller.counters["snmp_backoff"] >= 1,
          "the skipped cycles are counted, so they are visible on Debug (got %d)"
          % poller.counters["snmp_backoff"])
    db.close()


def main() -> int:
    print("The poll pool sizes itself")
    controller()
    bounds_and_damping()
    auto_off_is_unchanged()
    upgrade_keeps_the_operators_number()
    clamps()
    scheduling_pass_issues_no_sql()
    print("A down device backs off SNMP, never ping")
    backoff_cadence()
    backoff_never_touches_a_device_answering_ping()
    backoff_needs_ping_to_be_running()
    backoff_records_no_phantom_snmp_failure()
    print()
    if FAILURES:
        print("FAILURES: %d" % len(FAILURES))
        for item in FAILURES:
            print("  - " + item)
        return 1
    print("FAILURES: none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
