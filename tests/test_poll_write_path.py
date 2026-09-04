"""What one poll does: the transactions it writes, and the datagrams it
is willing to believe.

The review's §4.5 F3 measured one commit per metric sample — roughly 2,500
transactions for a 500-port chassis and ~288,000 per cycle across a
2,000-device fleet. The fix is a small number of batched transactions per
poll, so the thing to assert is not "it is faster" (a timing test is a
flaky test) but *how many transactions a poll takes*, counted exactly, off
sqlite3's own statement trace.

Also asserts that the batched writers store the same values the one-row
writers did, since record_metric_sample and update_interface_rate are now
wrappers around them.
"""
import json
import os
import socket
import sys
import time

import _paths
from _paths import spawn_stub, tmpdir

TMPDIR = tmpdir("poll_write_path_")

from netpath import nodepoll as nodepoll_mod
from netpath.nodepoll import NodePoller
from netpath.nodesdb import NodesDatabase

FAILURES = []


def check(condition, message):
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        FAILURES.append(message)


class CommitCounter:
    """Counts COMMIT statements on a connection via set_trace_callback.

    sqlite3 emits the statement text of everything it executes, so an
    explicit `commit()` shows up as "COMMIT". Statements are counted too,
    because "one transaction holding 900 statements" is not the win either.
    """

    def __init__(self, conn):
        self.conn = conn
        self.commits = 0
        self.statements = 0

    def __enter__(self):
        self.conn.set_trace_callback(self._trace)
        return self

    def __exit__(self, *exc):
        self.conn.set_trace_callback(None)
        return False

    def _trace(self, statement):
        self.statements += 1
        if statement.strip().upper().startswith("COMMIT"):
            self.commits += 1


def read_stats(path):
    """The stub rewrites its stats file (atomically, temp + replace) after
    every datagram it serves, and the test reads it the moment a poll
    returns. On Windows that races: the reader's open() can land during the
    replace and raise PermissionError, or read the file between the stub's
    last reply and its rewrite. Retry for a moment rather than let one race
    take the whole suite down with a traceback."""
    deadline = time.monotonic() + 3.0
    while True:
        try:
            with open(path) as handle:
                return json.load(handle)
        except (PermissionError, FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def v3_engine_time():
    """SNMPv3 engineTime was learned at discovery and sent back unchanged
    for the life of the process, so an agent enforcing RFC 3414 §3.2's
    time window started rejecting every request as soon as the cached
    value drifted past it. The stub enforces a deliberately tight ±1 s
    window so the drift shows up in seconds rather than in minutes.
    """
    print("\n-- SNMPv3 engine time and Report handling")
    stats = os.path.join(TMPDIR, "v3.json")
    proc, port = spawn_stub("stub_agent_iftable.py", "v3",
                            "--window", "1", "--stats", stats)
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "v3.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "v3-test", group_id=group_id,
            snmp_version=3, v3_user="poller", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)

        def poll():
            device = db.device(device_id)
            poller._poll_device(device, db.effective_config(device))
            return db.device(device_id)

        device = poll()
        check(device["status"] == "up",
              f"a v3 device polls (status={device['status']!r}, "
              f"error={device['snmp_error']!r})")
        after_first = read_stats(stats)
        check(after_first["discoveries"] == 1,
              "the first poll discovers the engine exactly once")

        # Long enough that an engineTime frozen at discovery is now outside
        # the stub's window, while one that advanced with the clock is not.
        time.sleep(2.5)
        counted = after_first["reports"]
        device = poll()
        after_second = read_stats(stats)
        check(device["status"] == "up",
              f"…and the poll 2.5 s later still succeeds "
              f"(status={device['status']!r}, error={device['snmp_error']!r})")
        check(after_second["reports"] == counted,
              f"…with no Report-PDU: engineTime advanced with the clock "
              f"(reports {counted} -> {after_second['reports']})")
        check(poller.counters["auth_fail"] == 0,
              "no spurious auth_fail was counted")
        check(not db.device_events(device_id, kinds=["auth_fail"]),
              "…and no spurious auth_fail event was recorded")

        poller.shutdown()
        db.close()
    finally:
        proc.kill()

    # A restarted agent: engineBoots increments, so every cached parameter
    # is stale. One Report, learned from, and the poll still succeeds.
    stats = os.path.join(TMPDIR, "v3boots.json")
    proc, port = spawn_stub("stub_agent_iftable.py", "v3", "--window", "1",
                            "--bump-boots-at", "1", "--stats", stats)
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "v3boots.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "v3-boots", group_id=group_id,
            snmp_version=3, v3_user="poller", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        device = db.device(device_id)
        poller._poll_device(device, db.effective_config(device))   # discovery
        before = read_stats(stats)
        time.sleep(1.2)                        # the agent restarts in here
        device = db.device(device_id)
        poller._poll_device(device, db.effective_config(device))   # boots bump
        device = db.device(device_id)
        after = read_stats(stats)
        check(after["engine_boots"] == before["engine_boots"] + 1,
              "the stub agent restarted between the two polls")
        check(after["reports"] - before["reports"] == 1,
              f"the restart costs exactly one Report-PDU "
              f"(got {after['reports'] - before['reports']})")
        check(device["status"] == "up",
              f"…and the poll recovers within itself instead of failing "
              f"(status={device['status']!r}, error={device['snmp_error']!r})")
        poller.shutdown()
        db.close()
    finally:
        proc.kill()


def pool_and_walks():
    """The poll pool's own health, the per-device caches, and the walk that
    used to open a socket per row."""
    print("\n-- pool, caches and walks")
    proc, port = spawn_stub("stub_agent_iftable.py", "ok", "--interfaces", "6")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "pool.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "pool-test", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)

        # --------------------------------------------- GETBULK in _walk_from
        device = db.device(device_id)
        config = db.effective_config(device)
        sent = {"n": 0}
        real_walk_request = poller._walk_request

        def counting(session, dev, cfg, oid, pdu_tag, max_repetitions=0):
            sent["n"] += 1
            return real_walk_request(session, dev, cfg, oid, pdu_tag,
                                     max_repetitions)

        poller._walk_request = counting
        rows, stopped = poller._walk_from(
            device, config, "1.3.6.1.2.1.2.2.1.1", max_rows=100, budget_s=10)
        poller._walk_request = real_walk_request
        check(len(rows) == 6,
              f"the subtree walk found every row ({len(rows)}, stopped: {stopped})")
        check(sent["n"] < len(rows),
              f"…in fewer requests than rows, so it used GETBULK "
              f"({sent['n']} request(s) for {len(rows)} row(s))")

        # A device that answered tooBig keeps the smaller repetition count.
        poller._remember_repetitions(device, 5)
        use_bulk, reps = poller._bulk_settings(device, config)
        check(use_bulk and reps == 5,
              f"the repetition count a device coped with is remembered "
              f"({use_bulk}, {reps})")
        v1_config = dict(config, snmp_version=0)
        check(poller._bulk_settings(device, v1_config) == (False, 0),
              "…and v1 still walks with GETNEXT, which is all it has")

        # ------------------------------------------------ pool saturation
        check(poller.pool_state()["saturated"] is False,
              "an idle pool is not saturated")
        occurrences = []

        class FakeEngine:
            def system_occurrence(self, rule_key, entity_id, label,
                                  severity=3, extra=None, message=""):
                occurrences.append(("raise", rule_key, entity_id, extra))

            def clear_system_occurrence(self, rule_key, entity_id):
                occurrences.append(("clear", rule_key, entity_id, None))

        poller.alert_engine = FakeEngine()

        class Pool:
            _max_workers = 2

        poller._executor = Pool()
        with poller._lock:
            poller._started.update({1: 0.0, 2: 0.0})
            poller._queued.update({3: 0.0, 4: 0.0})
        check(poller.pool_state()["saturated"] is True,
              "every worker busy with devices waiting is saturation")
        check("2 busy and 2 queued of 2 worker(s)" in
              (poller.status_text() if poller.running else
               f"{poller.pool_state()['busy']} busy and "
               f"{poller.pool_state()['queued']} queued of "
               f"{poller.pool_state()['workers']} worker(s)"),
              "…and busy and queued are counted separately, not summed")

        now = time.time()
        poller._note_saturation(now)
        check(not occurrences,
              "a moment of saturation raises nothing (a poll cycle starts busy)")
        poller._note_saturation(now + poller._SATURATION_S - 1)
        check(not occurrences, "…nor does four and a half minutes of it")
        poller._note_saturation(now + poller._SATURATION_S + 1)
        check([o[:3] for o in occurrences] ==
              [("raise", "poll_pool_saturated", "poller")],
              f"…but five minutes does, once ({occurrences})")
        poller._note_saturation(now + poller._SATURATION_S + 120)
        check(len(occurrences) == 1, "…and it is not raised again while it lasts")

        with poller._lock:
            poller._queued.clear()
        poller._note_saturation(time.time())
        check([o[:3] for o in occurrences][-1] ==
              ("clear", "poll_pool_saturated", "poller"),
              f"…and it is cleared when the pool catches up ({occurrences})")
        poller._executor = None

        # -------------------------------------- per-device cache cleanup
        poller._next_run[999] = 1.0
        poller._credentials[999] = 0
        poller._addresses_read[999] = 1.0
        poller._bulk_repetitions[999] = 5
        poller._engines.set(999, b"engine", 1, 1)
        poller._forget_devices({device_id})
        check(999 not in poller._next_run and 999 not in poller._credentials
              and 999 not in poller._addresses_read
              and 999 not in poller._bulk_repetitions
              and poller._engines.get(999) is None,
              "a deleted device's per-device caches are dropped")
        check(device_id in poller._bulk_repetitions,
              "…and a device that still exists keeps its own")

        # ---------------------------------- a down device stops re-sweeping
        # Two credentials on the profile, and a device that answers
        # neither: the first failing poll tries both, the next one tries
        # only the last-known-good until the retry window passes.
        db.add_group_credential(group_id, label="alternate", snmp_version=1,
                                community="other")
        down_id = db.add_device(
            "127.0.0.9", "down-device", group_id=group_id, ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=0.2, snmp_retries=0)
        tried = []
        real_scalars = poller._poll_snmp_scalars

        def counting_scalars(dev, cfg):
            tried.append(cfg.get("community"))
            raise __import__("netpath.snmppoll", fromlist=["x"]).SnmpTimeout(
                "no reply")

        poller._poll_snmp_scalars = counting_scalars
        down = db.device(down_id)
        for _ in range(2):
            try:
                poller._poll_snmp_scalars_with_credential(
                    down, db.effective_config(down))
            except Exception:
                pass
        poller._poll_snmp_scalars = real_scalars
        check(tried[:2] == ["public", "other"],
              f"the first failing poll tries every credential ({tried})")
        check(len(tried) == 3,
              f"…and the next one tries only the cached candidate ({tried})")

        # ------------------------------------- MAC walks off the poll pool
        poller.start({"poll_workers": 2})
        try:
            check(poller._mac_executor is not None
                  and poller._mac_executor is not poller._executor,
                  "forwarding-table walks have their own pool")
            check(poller._mac_executor._max_workers == poller._MAC_WALK_WORKERS,
                  f"…of {poller._MAC_WALK_WORKERS} threads "
                  f"({poller._mac_executor._max_workers})")
        finally:
            poller.stop()
        check(poller._mac_executor is None,
              "…and it is shut down with the poller")

        poller.shutdown()
        db.close()
    finally:
        proc.kill()


def ipv6_polling():
    """§4.1 N3: AF_INET was hardcoded in _Session and in the discovery
    probe, and tracer.resolve used the IPv4-only gethostbyname, so an
    IPv6 management plane could not be polled, discovered or traced."""
    print("\n-- IPv6")
    import socket as _socket
    from netpath import ipam_scan, tracer

    # resolve() answers for a v6 literal and a v6-only name.
    check(tracer.resolve("::1") == "::1",
          f"tracer.resolve returns an IPv6 literal unchanged "
          f"(got {tracer.resolve('::1')!r})")
    check(tracer.resolve("127.0.0.1") == "127.0.0.1",
          "…and an IPv4 literal, as before")
    check(tracer.resolve("localhost") in ("127.0.0.1", "::1"),
          f"…and a name (got {tracer.resolve('localhost')!r})")
    check(tracer.resolve("no-such-host.invalid") is None,
          "…and None for a name that does not resolve")

    # usable_addresses takes a v6 prefix, and still refuses a huge one.
    small = ipam_scan.usable_addresses("2001:db8::/126", 1024)
    check(small == ["2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"],
          f"an IPv6 /126 enumerates its four addresses ({small})")
    check(ipam_scan.subnet_size("2001:db8::/126") == 4,
          "…and subnet_size agrees with it")
    refused = False
    try:
        ipam_scan.usable_addresses("2001:db8::/64", 1024)
    except ipam_scan.SubnetTooLarge:
        refused = True
    check(refused, "…while a /64 is refused rather than enumerated")
    check(len(ipam_scan.usable_addresses("192.168.4.0/24", 1024)) == 254,
          "…and IPv4 is unchanged")

    # The family is chosen from the address itself. Asserted by recording
    # what _Session asks socket.socket for, so it holds on a host with no
    # IPv6 stack at all (this container has none).
    from netpath.nodepoll import _Session
    asked = []
    real_socket = _socket.socket

    def recording_socket(family, kind, *rest):
        asked.append(family)
        return real_socket(_socket.AF_INET, kind, *rest)

    nodepoll_mod.socket.socket = recording_socket
    try:
        _Session("10.0.0.1", 161, 1.0, 0).close()
        _Session("2001:db8::1", 161, 1.0, 0).close()
    finally:
        nodepoll_mod.socket.socket = real_socket
    check(asked == [_socket.AF_INET, _socket.AF_INET6],
          f"_Session opens AF_INET6 for a v6 address and AF_INET for a v4 one "
          f"({asked})")

    from netpath import nodediscover
    asked = []
    # After B4 fix, nodediscover uses _Session from nodepoll, so we mock
    # _Session's socket usage via nodepoll module instead of nodediscover's socket
    nodepoll_mod.socket.socket = recording_socket
    try:
        for target in ("10.0.0.1", "2001:db8::1"):
            try:
                nodediscover._snmp_identify(target, 1, "public", 0.2, ["1.3.6.1.2.1.1.1.0"])
            except Exception:
                pass
    finally:
        nodepoll_mod.socket.socket = real_socket
    check(asked == [_socket.AF_INET, _socket.AF_INET6],
          f"…and so does the discovery probe ({asked})")

    try:
        probe = _socket.socket(_socket.AF_INET6, _socket.SOCK_DGRAM)
        probe.bind(("::1", 0))
        probe.close()
    except OSError as exc:
        print(f"      (no IPv6 loopback on this host: {exc}); skipping the poll")
        return

    proc, port = spawn_stub("stub_agent_iftable.py", "ok", "--host", "::1")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "ipv6.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "::1", "v6-switch", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        _poll_once(poller, db, device_id)
        device = db.device(device_id)
        check(device["status"] == "up",
              f"a device on an IPv6 address polls (status={device['status']!r}, "
              f"error={device['snmp_error']!r})")
        check(device["sys_name"] == "iftable-stub",
              "…with its identity read")
        check(len(db.interfaces(device_id)) == 2,
              f"…and its interfaces ({len(db.interfaces(device_id))})")
        poller.shutdown()
        db.close()
    finally:
        proc.kill()


def vendor_health():
    """§4.1 S9: the poller read no vendor health at all, so cpu_high,
    mem_high and disk_high could only ever fire on a device running
    net-snmp — every Cisco, Fortinet and Juniper box in the estate was
    silent on the metrics the shipped rules watch."""
    print("\n-- vendor health")

    proc, port = spawn_stub("stub_agent_iftable.py", "fortigate")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "fortigate.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "fw-01", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        _poll_once(poller, db, device_id)
        metrics = {r["key"]: r for r in db.metrics(device_id)}
        check(metrics.get("cpu_pct") and metrics["cpu_pct"]["last_value"] == 95.0,
              f"a FortiGate reports its CPU "
              f"({metrics.get('cpu_pct') and metrics['cpu_pct']['last_value']})")
        check(metrics.get("mem_pct") and metrics["mem_pct"]["last_value"] == 61.0,
              "…its memory")
        check(metrics.get("session_count")
              and metrics["session_count"]["last_value"] == 1234.0,
              "…and its session count")
        # cpu_high opens at 90% and warns at 80%: the shipped threshold is
        # unchanged, and 95% is above it. That is the behaviour change.
        check(metrics["cpu_pct"]["last_value"] > 90.0,
              "…which is above the shipped cpu_high threshold of 90%")

        # ipAddrTable: the loopback the device also answers on resolves to
        # it, so a trap or syslog message from there is attributable.
        check(db.device_id_for_address("10.9.9.9") == device_id,
              "an address from ipAddrTable resolves to the device")
        check(db.device_id_for_address("127.0.0.1") == device_id,
              "…and so does its own primary address")
        # Walked at most once an hour, not once a poll.
        reads = dict(poller._addresses_read)
        _poll_once(poller, db, device_id)
        check(poller._addresses_read == reads,
              "…and the address walk does not repeat on the next poll")
        poller.shutdown()
        db.close()
    finally:
        proc.kill()

    proc, port = spawn_stub("stub_agent_iftable.py", "cisco")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "cisco.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "core-01", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        _poll_once(poller, db, device_id)
        metrics = {r["key"]: r for r in db.metrics(device_id)}
        check(metrics.get("cpu_pct") and metrics["cpu_pct"]["last_value"] == 42.0,
              f"a Cisco device reports cpmCPUTotal5minRev "
              f"({metrics.get('cpu_pct') and metrics['cpu_pct']['last_value']})")
        # 300 MB used of 400 MB across both pools.
        value = metrics.get("mem_pct") and metrics["mem_pct"]["last_value"]
        check(value is not None and abs(value - 75.0) < 0.01,
              f"…and its memory pools summed to a percentage ({value})")
        poller.shutdown()
        db.close()
    finally:
        proc.kill()


def _poll_once(poller, db, device_id):
    device = db.device(device_id)
    poller._poll_device(device, db.effective_config(device))


def interface_reads():
    """The three ways reading a device's interfaces used to go wrong: an
    SNMPv1 agent answering noSuchName for the whole PDU, a device that
    stops answering half way down the table, and one malformed index."""

    # ---------------------------------------------------- SNMPv1 gets rows
    print("\n-- SNMPv1 interfaces")
    proc, port = spawn_stub("stub_agent_iftable.py", "v1_nosuchname",
                            "--interfaces", "3")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "v1.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "v1-switch", group_id=group_id,
            snmp_version=0, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        _poll_once(poller, db, device_id)
        device = db.device(device_id)
        check(device["status"] == "up" and device["sys_name"] == "iftable-stub",
              f"a v1 device polls (status={device['status']!r}, "
              f"sys_name={device['sys_name']!r})")
        ifaces = {r["if_index"]: r for r in db.interfaces(device_id)}
        check(set(ifaces) == {1, 2, 3},
              f"every interface on a v1 device is discovered ({sorted(ifaces)})")
        check(all(r["descr"] for r in ifaces.values()),
              f"…with its description "
              f"({[r['descr'] for r in ifaces.values()]})")
        check(ifaces[1]["speed_bps"] == 1_000_000_000,
              f"…and its speed ({ifaces[1]['speed_bps']})")
        time.sleep(1.05)
        _poll_once(poller, db, device_id)
        ifaces = {r["if_index"]: r for r in db.interfaces(device_id)}
        check(ifaces[1]["in_bps"] is not None and ifaces[1]["in_bps"] > 0,
              f"…and a real counter rate on the next poll "
              f"(in_bps={ifaces[1]['in_bps']})")
        check(ifaces[1]["last_in_discards"] is not None,
              "ifInDiscards is stored")
        metrics = {r["key"] for r in db.metrics(device_id)}
        check("if_in_util_pct" in metrics and "if_in_error_rate" in metrics
              and "if_in_discard_rate" in metrics,
              f"the device-level keys the shipped threshold rules read now "
              f"exist ({sorted(k for k in metrics if not k[-2:].isdigit())})")
        poller.shutdown()
        db.close()
    finally:
        proc.kill()

    # ------------------------------------------- a device that goes quiet
    print("\n-- a device that stops answering mid-table")
    proc, port = spawn_stub("stub_agent_iftable.py", "dark_after_walk",
                            "--interfaces", "40", "--dark-after", "3")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "dark.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "dark-switch", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=0.3, snmp_retries=1)
        poller = NodePoller(db)
        # An interface stored by an earlier poll that this one will not
        # reach. A partial read is not evidence that it is gone.
        db.replace_interfaces(device_id, [{"if_index": 99, "descr": "Gi9/99"}])
        started = time.monotonic()
        _poll_once(poller, db, device_id)
        elapsed = time.monotonic() - started
        # 39 unanswered interfaces at 0.3 s x 2 attempts is 23 s; the
        # give-up-after-three rule should cost under two.
        print(f"      the poll took {elapsed:.1f}s for 40 interfaces")
        check(elapsed < 6.0,
              f"a device that goes quiet does not hold the worker for "
              f"N x timeout x retries (took {elapsed:.1f}s)")
        ifaces = {r["if_index"]: r for r in db.interfaces(device_id)}
        check(99 in ifaces,
              f"an interface the partial read never reached is kept "
              f"({sorted(ifaces)})")
        check(1 in ifaces, "…alongside the ones it did read")
        poller.shutdown()
        db.close()
    finally:
        proc.kill()

    # ------------------------------------------------ one malformed index
    print("\n-- a malformed ifIndex")
    proc, port = spawn_stub("stub_agent_iftable.py", "nonnumeric",
                            "--interfaces", "3")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "nonnumeric.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "odd-switch", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        _poll_once(poller, db, device_id)
        ifaces = {r["if_index"] for r in db.interfaces(device_id)}
        check(ifaces == {1, 2, 3},
              f"one unparseable index no longer truncates the table "
              f"({sorted(ifaces)})")
        poller.shutdown()
        db.close()
    finally:
        proc.kill()


def request_matching():
    """A reply is only an answer when it came from the device we asked and
    carries the request id we sent. The stub sends a late answer to
    somebody else's attempt first, with a visibly wrong sysName; a
    receiver that takes the first datagram off the socket stores it."""
    print("\n-- request matching")
    proc, port = spawn_stub("stub_agent_iftable.py", "stale_id")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "stale.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "stale-test", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)
        device = db.device(device_id)
        poller._poll_device(device, db.effective_config(device))
        device = db.device(device_id)
        check(device["sys_name"] == "iftable-stub",
              f"the stale reply is ignored and the matching one is stored "
              f"(sys_name={device['sys_name']!r})")
        check(device["status"] == "up",
              f"…and the poll still succeeds (status={device['status']!r})")

        # Two requests in a row must not reuse an id, or the test above
        # would pass by luck rather than by matching.
        session = poller._session_for(device, db.effective_config(device))
        ids = {session.next_request_id() for _ in range(200)}
        check(len(ids) == 200, "a session's request ids do not repeat")
        session.close()

        # A datagram from any other address is not an answer. Targeting a
        # closed port relied on platform-specific ICMP behaviour: on Linux
        # an unconnected UDP send to a closed local port typically leaves
        # the socket to time out with nothing delivered back, but on
        # Windows the ICMP port-unreachable commonly does surface, as
        # ConnectionResetError on the next recvfrom, which is not
        # SnmpTimeout and made this test flaky there. A real socket bound
        # and never read from is a genuine black hole on either platform —
        # nothing rejects the datagram, so it is simply never answered.
        from netpath.snmppoll import SnmpTimeout
        black_hole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        black_hole.bind(("127.0.0.1", 0))
        black_hole_port = black_hole.getsockname()[1]
        session = poller._session_for(device, {"snmp_timeout_s": 0.4,
                                               "snmp_retries": 0})
        session.ip = "127.0.0.1"
        session.port = black_hole_port
        raised = False
        try:
            session.request(b"\x30\x00", 1)
        except SnmpTimeout:
            raised = True
        except Exception:
            pass
        check(raised, "a request to an address that answers nothing times out")
        session.close()
        black_hole.close()

        poller.shutdown()
        db.close()
    finally:
        proc.kill()


def reboot_suppression():
    """A device that restarted between two polls restarts its interface
    counters with itself. counter_rate cannot tell that apart from a
    32-bit wrap, so it used to report the switch as having carried
    hundreds of megabits in the eight seconds it had been up. The rates
    for that one poll are dropped instead; the counters are still stored,
    so the poll after it measures against the post-reboot baseline.
    """
    print("\n-- reboot suppression")
    proc, port = spawn_stub("stub_agent_iftable.py", "reboot",
                            "--interfaces", "2", "--reboot-after", "2")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "reboot.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "reboot-test", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)

        def poll():
            device = db.device(device_id)
            poller._poll_device(device, db.effective_config(device))
            time.sleep(0.05)
            return {r["if_index"]: r for r in db.interfaces(device_id)}[1]

        poll()                                  # 1: baseline, no rate yet
        before = poll()                         # 2: still up, real rates
        check(before["in_bps"] is not None and before["in_bps"] > 0,
              f"a normal poll computes a rate (in_bps={before['in_bps']})")
        check(before["in_error_rate"] is not None and before["in_error_rate"] > 0,
              "…and an error rate")

        during = poll()                         # 3: uptime dropped
        check(db.device_events(device_id, kinds=["rebooted"]),
              "the reboot itself is still recorded as an event")
        check(during["in_bps"] is None and during["out_bps"] is None,
              f"the reboot poll stores no octet rate "
              f"(in_bps={during['in_bps']}, out_bps={during['out_bps']})")
        check(during["in_error_rate"] is None,
              f"…and no phantom error-rate spike "
              f"(in_error_rate={during['in_error_rate']})")
        check(during["last_in_octets"] is not None
              and during["last_in_octets"] < 10_000,
              f"…but the post-reboot counters are stored as the new baseline "
              f"(last_in_octets={during['last_in_octets']})")

        after = poll()                          # 4: measured off that baseline
        check(after["in_bps"] is not None and after["in_bps"] > 0,
              f"the poll after the reboot measures normally again "
              f"(in_bps={after['in_bps']})")

        poller.shutdown()
        db.close()
    finally:
        proc.kill()


def main():
    proc, port = spawn_stub("stub_agent_iftable.py", "ok", "--interfaces", "24")
    try:
        nodepoll_mod.DEFAULT_SNMP_PORT = port
        db = NodesDatabase(os.path.join(TMPDIR, "nodes.db"))
        group_id = db.ensure_default_group()
        device_id = db.add_device(
            "127.0.0.1", "write-path", group_id=group_id,
            snmp_version=1, community="public", ping_enabled=0,
            poll_interval_s=999, snmp_timeout_s=1.0, snmp_retries=1)
        poller = NodePoller(db)

        def poll():
            device = db.device(device_id)
            poller._poll_device(device, db.effective_config(device))

        # Poll 1 discovers everything; poll 2 is the steady-state poll the
        # fleet actually spends its life doing, and the one to count.
        poll()
        time.sleep(1.05)
        with CommitCounter(db._conn) as counter:
            poll()
        print(f"      poll 2: {counter.commits} commit(s), "
              f"{counter.statements} statement(s) for 24 interfaces")

        # record_poll, replace_interfaces, update_interface_rates,
        # record_metric_samples — four, plus headroom for a device event.
        check(counter.commits <= 6,
              f"a steady-state poll of 24 interfaces takes <= 6 commits "
              f"(got {counter.commits})")
        # Before batching this was ~4 commits per interface plus 2 scalars:
        # roughly 100 here, and 2,000 on a 500-port chassis.
        check(counter.commits < 24,
              "the commit count no longer scales with the interface count")

        metrics = {row["key"]: row for row in db.metrics(device_id)}
        check(len(metrics) >= 24,
              f"every interface still produced metrics ({len(metrics)} keys)")
        check("if_in_bps.1" in metrics and metrics["if_in_bps.1"]["last_value"] is not None,
              "interface rates are still recorded through the batched path")
        check(abs(metrics["cpu_pct"]["last_value"] - 25.0) < 0.01,
              f"scalar metrics still correct (cpu_pct="
              f"{metrics['cpu_pct']['last_value']})")

        ifaces = {row["if_index"]: row for row in db.interfaces(device_id)}
        check(len(ifaces) == 24, f"24 interfaces stored (got {len(ifaces)})")
        check(ifaces[3]["in_bps"] is not None and ifaces[3]["in_bps"] >= 0,
              "update_interface_rates stored a computed rate")
        check(ifaces[3]["last_in_octets"] is not None,
              "update_interface_rates stored the raw counter for the next poll")

        # -------------------------------------------- the one-row wrappers

        metric_id = db.record_metric_sample(
            device_id, "wrapper_check", "Wrapper", "%", "gauge", 1234.0, 7.5)
        row = db.metric(metric_id)
        check(row["last_value"] == 7.5 and row["kind"] == "gauge",
              "record_metric_sample still writes one metric and its sample")
        series = db.series(device_id, metric_id, 0, 2000)
        check(series == [{"ts": 1234.0, "value": 7.5}],
              f"the sample landed in `samples` too ({series})")

        # A None value updates last_ts without inventing a zero sample.
        db.record_metric_sample(
            device_id, "wrapper_check", "Wrapper", "%", "gauge", 1300.0, None)
        row = db.metric(metric_id)
        check(row["last_value"] is None and row["last_ts"] == 1300.0,
              "a None value updates the metric but stores no sample")
        check(len(db.series(device_id, metric_id, 0, 2000)) == 1,
              "…and leaves the sample count alone")

        # kind is written once, at creation, and never rewritten: a poll
        # must not silently switch a chart's units.
        db.record_metric_sample(
            device_id, "wrapper_check", "Wrapper", "%", "counter_rate", 1400.0, 1.0)
        check(db.metric(metric_id)["kind"] == "gauge",
              "a later sample never rewrites a metric's kind")

        db.update_interface_rate(
            device_id, 1, in_octets=10, out_octets=20, in_errors=1,
            out_errors=2, in_bps=3.0, out_bps=4.0, in_error_rate=0.5,
            out_error_rate=0.25, ts=999.0)
        row = {r["if_index"]: r for r in db.interfaces(device_id)}[1]
        check(row["in_bps"] == 3.0 and row["last_in_octets"] == 10
              and row["out_error_rate"] == 0.25 and row["last_sample_ts"] == 999.0,
              "update_interface_rate (the one-row wrapper) still writes every column")

        poller.shutdown()
        db.close()
    finally:
        proc.kill()

    reboot_suppression()
    interface_reads()
    vendor_health()
    ipv6_polling()
    pool_and_walks()
    request_matching()
    v3_engine_time()

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
