"""Every scheduler keyed on wall-clock due times stalls after a
backward clock step (large NTP correction, VM resume) -- a due time computed
forward from the old, larger `now` reads as arbitrarily far in the future
once `now` steps back, and nothing until this fix ever re-derived it. Each
case below: seed a due time, step the clock back by more than one interval,
run one more pass, and check the due time is clamped to at most one interval
past the stepped-back clock rather than left at its stale value."""
import os
import sys
import threading
import time

import _paths
from _paths import tmpdir

TMPDIR = tmpdir("backward_clock_step_")

from netpath.nodepoll import NodePoller
import netpath.nodepoll.poller as nodepoll_poller_mod
from netpath.nodesdb import NodesDatabase
from netpath.wirelessdb import WirelessDatabase
from netpath.fortipoll import WirelessPoller
import netpath.fortipoll as fortipoll_mod
from netpath.ipamdb import IpamDatabase
from netpath.ipam_worker import IpamWorker
import netpath.ipam_worker as ipam_worker_mod
from netpath.db import Database
from netpath import monitor as monitor_mod
from netpath.syslogd import SyslogCollector

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


def test_nodepoll_schedule_pass():
    db = NodesDatabase(os.path.join(tmpdir("bm7_nodepoll_"), "nodes.db"))
    try:
        gid = db.ensure_default_group()
        db.update_group(gid, poll_interval_s=600)
        ids = [db.add_device(f"10.1.0.{i + 1}", f"d{i}", group_id=gid) for i in range(5)]
        poller = NodePoller(db)
        poller._schedule_pass()   # warm: seeds _next_run
        real_time = time.time
        now_before = real_time()
        nodepoll_poller_mod.time.time = lambda: now_before - 3600
        try:
            poller._schedule_pass()
            stepped_now = now_before - 3600
            stuck = {i: poller._next_run[i] for i in ids
                    if poller._next_run[i] - stepped_now > 600 + 60}
        finally:
            nodepoll_poller_mod.time.time = real_time
        check(not stuck,
              f"NodePoller._schedule_pass: a 1h backward step does not "
              f"strand a device past its own interval ({stuck})")
    finally:
        db.close()


def test_nodepoll_walk_schedulers():
    """_maybe_walk_mac_table/_lldp/_vlans/_arp_table all take `now` as a
    parameter, so the backward step is simulated directly, no clock patch
    needed. One representative call proves the shared fix shape; the other
    three use the identical clamp."""
    db = NodesDatabase(os.path.join(tmpdir("bm7_nodepoll_walks_"), "nodes.db"))
    try:
        gid = db.ensure_default_group()
        device_id = db.add_device("10.1.1.1", "sw1", group_id=gid,
                                  mac_table_interval_s=1800)
        device = db.device(device_id)
        config = db.effective_config(device)
        poller = NodePoller(db)
        now = time.time()
        poller._maybe_walk_mac_table(device, config, now)   # warm: seeds _next_mac_walk
        before = poller._next_mac_walk[device_id]
        check(before > now, f"the first call schedules a future walk ({before})")

        stepped_now = now - 3600
        poller._maybe_walk_mac_table(device, config, stepped_now)
        after = poller._next_mac_walk[device_id]
        check(after - stepped_now <= 1800 + 60,
              f"a 1h backward step does not strand the MAC walk past its "
              f"own interval (due={after}, stepped_now={stepped_now}, "
              f"diff={after - stepped_now})")
    finally:
        db.close()


def test_fortipoll_schedule_pass():
    db = WirelessDatabase(os.path.join(tmpdir("bm7_fortipoll_"), "wireless.db"))
    try:
        controller_id = db.add_controller("c1", "10.2.0.1", snmp_version=1,
                                          community="public")
        poller = WirelessPoller(db)
        poller._executor = None   # poll_now no-ops without a pool; only scheduling matters
        poller._schedule_pass()   # warm: seeds _next_run (poll_interval_s default 60)
        real_time = time.time
        now_before = real_time()
        fortipoll_mod.time.time = lambda: now_before - 3600
        try:
            poller._schedule_pass()
            stepped_now = now_before - 3600
            due = poller._next_run[controller_id]
        finally:
            fortipoll_mod.time.time = real_time
        check(due - stepped_now <= 60 + 30,
              f"WirelessPoller._schedule_pass: a 1h backward step does not "
              f"strand a controller past its own interval "
              f"(due={due}, stepped_now={stepped_now})")
    finally:
        db.close()


def test_ipam_worker_tick():
    folder = tmpdir("bm7_ipam_")
    idb = IpamDatabase(os.path.join(folder, "ipam.db"))
    try:
        subnet_id = idb.add_subnet("192.0.2.0/29", "test")
        idb.save_settings({"scan_interval_minutes": 10})
        worker = IpamWorker(idb)
        worker._staggered = True   # skip the spread-first-scans pass
        worker._next_scan[subnet_id] = time.time() + 600   # pretend a scan just ran
        real_time = time.time
        now_before = real_time()
        ipam_worker_mod.time.time = lambda: now_before - 3600
        try:
            worker._tick()
            stepped_now = now_before - 3600
            due = worker._next_scan[subnet_id]
        finally:
            ipam_worker_mod.time.time = real_time
        check(due - stepped_now <= 600 + 60,
              f"IpamWorker._tick: a 1h backward step does not strand a "
              f"subnet scan past its own interval (due={due}, "
              f"stepped_now={stepped_now})")
    finally:
        idb.close()


def test_monitor_loop():
    folder = tmpdir("bm7_monitor_")
    db = Database(os.path.join(folder, "netpath.db"))
    try:
        target_id = db.add_target("192.0.2.1", interval_s=120)
        mon = monitor_mod.Monitor(db, workers=1)
        mon._next_run[target_id] = time.time() + 120   # a due time already computed
        real_time = time.time
        now_before = real_time()
        monitor_mod.time.time = lambda: now_before - 3600
        thread = threading.Thread(target=mon._loop, daemon=True)
        mon._stop.clear()
        thread.start()
        time.sleep(0.2)
        mon._stop.set()
        monitor_mod.time.time = real_time
        thread.join(timeout=3)
        stepped_now = now_before - 3600
        due = mon._next_run[target_id]
        check(due - stepped_now <= 120 + 60,
              f"Monitor._loop: a 1h backward step does not strand a target "
              f"past its own interval (due={due}, stepped_now={stepped_now})")
        mon._executor.shutdown(wait=False, cancel_futures=True)
    finally:
        db.close()


def test_https_checker_loop():
    folder = tmpdir("bm7_https_")
    db = Database(os.path.join(folder, "netpath.db"))
    try:
        target_id = db.add_target("192.0.2.2", interval_s=90)
        db.update_target(target_id, https_url="https://192.0.2.2/")
        checker = monitor_mod.HttpsChecker(db, workers=1)
        checker._next_run[target_id] = time.time() + 90
        real_time = time.time
        now_before = real_time()
        monitor_mod.time.time = lambda: now_before - 3600
        thread = threading.Thread(target=checker._loop, daemon=True)
        checker._stop.clear()
        thread.start()
        time.sleep(0.2)
        checker._stop.set()
        monitor_mod.time.time = real_time
        thread.join(timeout=3)
        stepped_now = now_before - 3600
        due = checker._next_run[target_id]
        check(due - stepped_now <= 90 + 60,
              f"HttpsChecker._loop: a 1h backward step does not strand a "
              f"target past its own interval (due={due}, stepped_now={stepped_now})")
        checker._executor.shutdown(wait=False, cancel_futures=True)
    finally:
        db.close()


def test_syslogd_token_bucket():
    server = SyslogCollector.__new__(SyslogCollector)
    server._rate = 10.0
    server._buckets = __import__("collections").OrderedDict()
    server._counter_lock = threading.Lock()
    server._allowed = set()
    server._auto_accept = True
    now = 1_000_000.0
    check(server._within_rate("10.3.0.1", now),
          "the first message from a source is allowed")
    bucket_before = list(server._buckets["10.3.0.1"])
    # A 1-hour backward step: the elapsed term must not go negative and
    # drain (or wildly inflate, in the other direction) the bucket.
    stepped_now = now - 3600
    server._within_rate("10.3.0.1", stepped_now)
    tokens_after = server._buckets["10.3.0.1"][0]
    check(tokens_after >= 0,
          f"a backward clock step does not drive the token count negative "
          f"(before={bucket_before[0]}, after={tokens_after})")


def main():
    test_nodepoll_schedule_pass()
    test_nodepoll_walk_schedulers()
    test_fortipoll_schedule_pass()
    test_ipam_worker_tick()
    test_monitor_loop()
    test_https_checker_loop()
    test_syslogd_token_bucket()

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
