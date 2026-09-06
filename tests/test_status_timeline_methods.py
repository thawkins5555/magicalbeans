"""The split SNMP/ping status timeline (Task in the 4.52.0 plan that added
device_method_segments): per-method transition events recorded by
nodepoll._poll_device, the nodesdb query that turns them into segments, and
the api.py shape the frontend's split-lane view reads.

Three independent pieces, in one file because they are one feature:
  1. Against a real StubAgent (reused from test_nodepoll_e2e.py) through the
     actual poller, proving snmp_up/snmp_down are TRANSITIONS — recorded on a
     real change, not once per poll. Plus two regression cases against the
     same stub: a fresh NodePoller backfilling an upgraded install's missing
     lane events (run_upgrade_seeding_section), and snmp_fail_alert_after's
     consecutive-failure count actually resetting on a success rather than
     merely pausing (run_snmp_fail_alert_after_reset_section).
  2. nodesdb.device_method_segments against a plain in-memory NodesDatabase
     with hand-placed events (the same back-dating trick
     test_report_availability.py uses), proving the segment shape and the
     None-means-never-observed contract.
  3. api.get_nodes_device_timeline's response shape, called directly against
     a minimal fake service rather than over real HTTP — this suite only
     cares what keys land in the dict, not the HTTP plumbing.
"""
import os
import shutil
import sys
import tempfile
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesdb import NodesDatabase
from netpath.nodepoll import NodePoller
from netpath.web import api as webapi

from test_nodepoll_e2e import StubAgent

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------------ 1. poller

def event_kinds(db, device_id, kinds):
    # device_events() comes back newest-first (ORDER BY ts DESC); the
    # transition-only assertions below read in the order things actually
    # happened, so sort back to chronological.
    rows = [e for e in db.device_events(device_id) if e["kind"] in kinds]
    rows.sort(key=lambda e: e["ts"])
    return [e["kind"] for e in rows]


def run_poller_section():
    tmp = tempfile.mkdtemp(prefix="status_timeline_methods_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))

    agent = StubAgent()
    agent.start()
    time.sleep(0.1)

    import netpath.nodepoll as nodepoll_mod
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port

    group_id = db.ensure_default_group()
    # ping_enabled=0, same reasoning test_nodepoll_e2e.py's stub device uses:
    # 127.0.0.1 always answers ICMP wherever ping is installed, which would
    # make ping_ok track nothing interesting here. This section is about the
    # SNMP lane; ping_up/ping_down get their own coverage in the nodesdb
    # section below, driven directly rather than through a real ping.
    device_id = db.add_device("127.0.0.1", "split-timeline-stub", group_id=group_id,
                              snmp_version=1, community="public", ping_enabled=0,
                              poll_interval_s=999, snmp_timeout_s=0.5, snmp_retries=0)
    poller = NodePoller(db)

    def do_poll():
        device = db.device(device_id)
        config = db.effective_config(device)
        poller._poll_device(device, config)

    try:
        # poll 1: first-ever observation seeds an snmp_up (previous None -> up)
        do_poll()
        kinds = event_kinds(db, device_id, ("snmp_up", "snmp_down"))
        check("first poll seeds one snmp_up (previous None -> up)",
             kinds == ["snmp_up"], str(kinds))
        check("ping disabled -> no ping_up/ping_down at all",
             not event_kinds(db, device_id, ("ping_up", "ping_down")))

        # poll 2: agent still up, nothing changed -> no new event
        do_poll()
        kinds = event_kinds(db, device_id, ("snmp_up", "snmp_down"))
        check("a second identical successful poll records nothing new (transition only)",
             kinds == ["snmp_up"], str(kinds))

        # poll 3: agent goes dark -> one snmp_down
        agent.alive = False
        do_poll()
        kinds = event_kinds(db, device_id, ("snmp_up", "snmp_down"))
        check("SNMP failing records one snmp_down",
             kinds == ["snmp_up", "snmp_down"], str(kinds))

        # poll 4: still dark -> no duplicate snmp_down
        do_poll()
        kinds = event_kinds(db, device_id, ("snmp_up", "snmp_down"))
        check("a second identical failing poll records nothing new (transition only)",
             kinds == ["snmp_up", "snmp_down"], str(kinds))

        # poll 5: agent recovers -> a second snmp_up
        agent.alive = True
        do_poll()
        kinds = event_kinds(db, device_id, ("snmp_up", "snmp_down"))
        check("recovery records a second snmp_up",
             kinds == ["snmp_up", "snmp_down", "snmp_up"], str(kinds))

        # The overall up/down events (what alerts/reports read) must be
        # untouched by any of this — this device never actually reached
        # `down` (SNMP-only, unreachable_ping_only doesn't apply with ping
        # off) so there should be no down/up events at all from polls 1-5.
        check("overall up/down events are unaffected by the per-method log",
             not event_kinds(db, device_id, ("down",)))
    finally:
        poller.shutdown()
        agent.stop()
        db.close()


# ------------------------------------------------------- 1b. upgrade seeding

def run_upgrade_seeding_section():
    """An install upgraded from before the split lanes existed has device
    rows with snmp_ok/ping_ok already populated but no snmp_*/ping_* events
    at all -- nodepoll._poll_device's `unseeded` check (has_method_events)
    exists so a FRESH NodePoller (a fresh process, not just a call --
    _method_seeded is per-instance) backfills one seed event per lane on its
    first poll of such a device, instead of waiting for the next real flap
    to populate only the lane that flapped.

    Simulated here by polling once normally (which writes real
    snmp_*/ping_* rows), deleting exactly those rows to stand in for an
    install that predates them, then handing the same on-disk device to a
    brand new NodePoller instance."""
    tmp = tempfile.mkdtemp(prefix="status_timeline_methods_upgrade_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))

    agent = StubAgent()
    agent.start()
    time.sleep(0.1)

    import netpath.nodepoll as nodepoll_mod
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port

    ping_available = shutil.which("ping") is not None
    group_id = db.ensure_default_group()
    device_id = db.add_device("127.0.0.1", "upgrade-seed-stub", group_id=group_id,
                              snmp_version=1, community="public",
                              ping_enabled=1 if ping_available else 0,
                              poll_interval_s=999, snmp_timeout_s=0.5, snmp_retries=0)

    def do_poll(poller):
        device = db.device(device_id)
        config = db.effective_config(device)
        poller._poll_device(device, config)

    poller = NodePoller(db)
    try:
        # Stand in for however this device originally reached its current
        # snmp_ok/ping_ok: a normal poll, which also happens to write the
        # very seed rows the next step erases.
        do_poll(poller)
        db._conn.execute(
            "DELETE FROM device_events WHERE device_id=? AND kind IN"
            " ('snmp_up','snmp_down','ping_up','ping_down')", (device_id,))
        db._conn.commit()
        check("pre-upgrade simulation: no per-method events remain",
             not event_kinds(db, device_id,
                             ("snmp_up", "snmp_down", "ping_up", "ping_down")))
    finally:
        poller.shutdown()

    # A fresh NodePoller (empty _method_seeded, the same as a restarted
    # process) on the SAME database and device: has_method_events() now sees
    # nothing, so this poller must seed both lanes from the device row's
    # current snmp_ok/ping_ok the moment it polls, not wait for a flap.
    fresh_poller = NodePoller(db)
    try:
        device_before = db.device(device_id)
        expected_snmp = "snmp_up" if device_before["snmp_ok"] else "snmp_down"
        do_poll(fresh_poller)

        snmp_kinds = event_kinds(db, device_id, ("snmp_up", "snmp_down"))
        check("fresh poller seeds exactly one snmp_* event matching current snmp_ok",
             snmp_kinds == [expected_snmp], str(snmp_kinds))

        ping_kinds = event_kinds(db, device_id, ("ping_up", "ping_down"))
        if ping_available:
            expected_ping = "ping_up" if device_before["ping_ok"] else "ping_down"
            check("fresh poller seeds exactly one ping_* event matching current ping_ok",
                 ping_kinds == [expected_ping], str(ping_kinds))
        else:
            print("SKIP: no ping on this machine; ping lane left disabled, "
                  "asserting no ping_* event instead")
            check("ping disabled on this machine -> no ping_* event seeded",
                 not ping_kinds, str(ping_kinds))

        # Seeding is a once-per-poller-instance thing, not a per-poll thing:
        # a second poll with nothing changed must add nothing further.
        do_poll(fresh_poller)
        check("a second poll with no change records no further snmp_* lane event",
             event_kinds(db, device_id, ("snmp_up", "snmp_down")) == snmp_kinds,
             str(event_kinds(db, device_id, ("snmp_up", "snmp_down"))))
        check("a second poll with no change records no further ping_* lane event",
             event_kinds(db, device_id, ("ping_up", "ping_down")) == ping_kinds,
             str(event_kinds(db, device_id, ("ping_up", "ping_down"))))
    finally:
        fresh_poller.shutdown()
        agent.stop()
        db.close()


# ------------------------------------------ 1c. snmp_fail_alert_after reset

def run_snmp_fail_alert_after_reset_section():
    """snmp_fail_alert_after gates snmp_error behind N CONSECUTIVE qualifying
    failures (nodepoll._poll_device's `_snmp_failing_count`) -- any poll
    where SNMP answers resets the count to zero, it doesn't just pause it.
    test_nodepoll_e2e.py already proves threshold=2 fires on the SECOND of
    two back-to-back failures; this proves the reset itself is real: with
    the threshold at 3, two failures then a success then two MORE failures
    (five failures total, but never three in a row) must record nothing,
    and only a third consecutive failure after that reset fires."""
    if shutil.which("ping") is None:
        print("SKIP: no ping on this machine; the snmp_fail_alert_after "
              "reset case needs a device that keeps answering ping while "
              "SNMP fails")
        return

    tmp = tempfile.mkdtemp(prefix="status_timeline_methods_resetcount_")
    db = NodesDatabase(os.path.join(tmp, "nodes.db"))
    db.save_settings({"snmp_fail_alert_after": 3})

    agent = StubAgent()
    agent.start()
    time.sleep(0.1)

    import netpath.nodepoll as nodepoll_mod
    nodepoll_mod.DEFAULT_SNMP_PORT = agent.port

    group_id = db.ensure_default_group()
    device_id = db.add_device("127.0.0.1", "fail-count-reset-stub", group_id=group_id,
                              snmp_version=1, community="public", ping_enabled=1,
                              poll_interval_s=999, snmp_timeout_s=0.4, snmp_retries=0)
    poller = NodePoller(db)

    def do_poll():
        device = db.device(device_id)
        config = db.effective_config(device)
        poller._poll_device(device, config)

    def snmp_error_count():
        return len(db.device_events(device_id, kinds=["snmp_error"]))

    try:
        # A working baseline first, so the failures below start the count
        # from a known SNMP-ok state.
        do_poll()
        check("baseline poll: agent answers", bool(db.device(device_id)["snmp_ok"]))

        # Two consecutive qualifying failures (ping stays OK throughout --
        # loopback always answers ICMP): below the threshold of 3.
        agent.alive = False
        do_poll()
        do_poll()
        check("two consecutive failures, threshold 3: no snmp_error yet",
             snmp_error_count() == 0, str(snmp_error_count()))

        # SNMP answers once more -- this must reset the in-memory count to
        # zero, not merely pause it at 2.
        agent.alive = True
        do_poll()
        check("SNMP recovered before the reset test",
             bool(db.device(device_id)["snmp_ok"]))
        check("count reset: still no snmp_error right after the recovery poll",
             snmp_error_count() == 0, str(snmp_error_count()))

        # Two MORE consecutive failures. If the earlier two had survived the
        # reset, this would be the 4th/5th qualifying failure and would
        # already have fired at an unreset 3rd; if the reset is real, this
        # is only the 1st/2nd again, still below threshold.
        agent.alive = False
        do_poll()
        do_poll()
        check("two more consecutive failures after the reset: still no"
             " snmp_error (count restarted from zero, not resumed from 2)",
             snmp_error_count() == 0, str(snmp_error_count()))

        # The third consecutive failure since the reset crosses the
        # threshold and must fire.
        do_poll()
        check("the third consecutive failure since the reset fires snmp_error",
             snmp_error_count() == 1, str(snmp_error_count()))
    finally:
        poller.shutdown()
        agent.stop()
        db.close()


# -------------------------------------------------------------- 2. nodesdb

def event_at(db, device_id, kind, ts, detail=""):
    """record_device_event always stamps time.time(); back-date it, the same
    trick test_report_availability.py uses when the public API has no
    timestamp parameter to hand it directly."""
    db.record_device_event(device_id, kind, detail)
    db._conn.execute(
        "UPDATE device_events SET ts = ? WHERE id = (SELECT MAX(id) FROM device_events"
        " WHERE device_id = ? AND kind = ?)",
        (ts, device_id, kind))
    db._conn.commit()


def run_nodesdb_section():
    db = NodesDatabase(":memory:")
    group_id = db.ensure_default_group()
    device_id = db.add_device("10.0.9.9", "segments-device", group_id=group_id)

    now = time.time()
    t0, t1 = now - 3600, now

    # No event of either method has ever been recorded -> both None, not [].
    result = db.device_method_segments(device_id, t0, t1)
    check("no per-method events at all -> both methods None",
         result == {"snmp": None, "ping": None}, str(result))

    # SNMP: up before the window, down partway through it. Ping: untouched.
    event_at(db, device_id, "snmp_up", t0 - 1800, "")
    event_at(db, device_id, "snmp_down", t0 + 1200, "boom")
    db._conn.execute("UPDATE devices SET snmp_ok = 0 WHERE id = ?", (device_id,))
    db._conn.commit()

    result = db.device_method_segments(device_id, t0, t1)
    check("ping still has no events -> stays None",
         result["ping"] is None, str(result))
    snmp_segs = result["snmp"]
    check("snmp has two segments: up (from before the window) then down",
         len(snmp_segs) == 2 and snmp_segs[0]["status"] == "up"
         and snmp_segs[1]["status"] == "down", str(snmp_segs))
    check("the up segment starts at t0, not at the event's own (earlier) ts",
         snmp_segs[0]["ts_start"] == t0, str(snmp_segs))
    check("the down segment runs to t1 (current snmp_ok is 0)",
         snmp_segs[1]["ts_end"] == t1, str(snmp_segs))

    # Now ping gets its own event -> both methods populated independently.
    event_at(db, device_id, "ping_up", t0 + 600, "")
    db._conn.execute("UPDATE devices SET ping_ok = 1 WHERE id = ?", (device_id,))
    db._conn.commit()
    result = db.device_method_segments(device_id, t0, t1)
    ping_segs = result["ping"]
    check("ping now has its own segments, independent of snmp's",
         ping_segs is not None and ping_segs[-1]["status"] == "up", str(ping_segs))
    check("device_status_segments (combined) is untouched by any of this",
         db.device_status_segments(device_id, t0, t1) is not None)

    db.close()


# ------------------------------------------------------------------ 3. api

class _FakeService:
    def __init__(self, nodes_db):
        self.nodes_db = nodes_db


def run_api_section():
    db = NodesDatabase(":memory:")
    group_id = db.ensure_default_group()
    device_id = db.add_device("10.0.9.10", "api-shape-device", group_id=group_id,
                              ping_enabled=1, snmp_enabled=1)
    service = _FakeService(db)

    now = time.time()
    result = webapi.get_nodes_device_timeline(
        service, {"t0": now - 3600, "t1": now}, {}, device_id)

    check("response has t0/t1/segments/methods/methods_enabled",
         set(("t0", "t1", "segments", "methods", "methods_enabled")) <= set(result),
         str(sorted(result)))
    check("segments is still a plain list (existing callers keep working)",
         isinstance(result["segments"], list), str(result.get("segments")))
    check("methods has snmp/ping keys, both None (no events recorded yet)",
         result["methods"] == {"snmp": None, "ping": None}, str(result["methods"]))
    check("methods_enabled reflects the device's effective config (both enabled)",
         result["methods_enabled"] == {"snmp": True, "ping": True},
         str(result["methods_enabled"]))

    # A device with SNMP off entirely: methods_enabled.snmp must be False.
    ping_only_id = db.add_device("10.0.9.11", "ping-only-device", group_id=group_id,
                                 ping_enabled=1, snmp_enabled=0)
    result = webapi.get_nodes_device_timeline(
        service, {"t0": now - 3600, "t1": now}, {}, ping_only_id)
    check("SNMP-disabled device reports methods_enabled.snmp == False",
         result["methods_enabled"] == {"snmp": False, "ping": True},
         str(result["methods_enabled"]))

    db.close()


run_poller_section()
run_upgrade_seeding_section()
run_snmp_fail_alert_after_reset_section()
run_nodesdb_section()
run_api_section()

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
