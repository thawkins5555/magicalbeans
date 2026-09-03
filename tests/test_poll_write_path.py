"""What one poll actually writes to nodes.db.

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
import os
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
