"""The flow stages of the real maintenance sweep, in the order they run.

Driven through `Service.run_maintenance(force=True)` rather than through
flowdb directly: what is being pinned here is the ordering of the stages
against each other, which only the sweep has an opinion about.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import os
import shutil
import sys
import time
import types

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.flowdb import ROLLUP_TIERS
from netpath.web import Service

TMPDIR = _paths.tmpdir("netflow_maintenance_")

FAILS: list[str] = []

DB_NAMES = ("netpath", "flows", "syslog", "app", "ipam", "snmptraps", "nodes",
            "alerts", "wireless", "configrx")


def check(name, ok, detail="") -> None:
    print(("PASS  " if ok else "FAIL  ") + name
          + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def new_service(subdir):
    data_dir = os.path.join(TMPDIR, subdir)
    os.makedirs(data_dir, exist_ok=True)
    return Service(*[os.path.join(data_dir, name + ".db") for name in DB_NAMES])


def flow(index: int, ts: float):
    return types.SimpleNamespace(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 7}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443)[index % 2],
        protocol=6, tos=0, tcp_flags=0, in_if=1, out_if=2,
        src_as=64500, dst_as=64600, next_hop=None,
        packets=1 + index % 9, bytes=100 + index, sampling=1,
        domain=0, sampler_id=0)


def quiet_flow_settings(service) -> None:
    """Retention and the row cap out of the way, so anything the sweep
    removes from the raw table is the size cap and nothing else."""
    service.flow_settings["retention_days"] = 365
    service.flow_settings["max_flows"] = 0
    service.flow_settings["rollup_minute_days"] = 365
    service.flow_settings["rollup_retention_days"] = 365
    service.settings["max_trace_db_mb"] = 0


def raw_count(service) -> int:
    return service.flow_db._conn.execute(
        "SELECT COUNT(*) FROM flows").fetchone()[0]


# ------------------- 1. the size cap runs after the history is summarised

# A store already at its cap used to give its oldest raw rows up to the trim
# on every sweep while the backfill advanced one bucket per sweep behind it,
# so the promise that a 30-day chart outlives a fortnight of raw retention
# never materialised for old history.
service = new_service("t1")
NOW = time.time()
SPAN = 8 * 3600.0
TOTAL = 120_000
OLDEST = NOW - SPAN
service.flow_db.insert_flows(
    [flow(i, OLDEST + i * (SPAN / TOTAL)) for i in range(TOTAL)])
quiet_flow_settings(service)

before_bytes = service.flow_db.size_bytes()
before_rows = raw_count(service)
# Well under the file, well over what the rollups themselves need: the trim
# has to bite on the raw table, and must not reach its second stage, which
# would delete the very rollup buckets this case is about.
service.settings["max_flow_db_mb"] = max(1, int(before_bytes * 0.55) // 1048576)

service.run_maintenance(force=True)

after_rows = raw_count(service)
check("the size cap did remove raw flows, so the ordering below is actually "
      "being exercised",
      after_rows < before_rows,
      f"{before_rows} -> {after_rows} rows, {before_bytes} bytes")
oldest_left = service.flow_db._conn.execute(
    "SELECT MIN(ts_end) FROM flows").fetchone()[0]
check("...and it removed the oldest of them, which is the raw history the "
      "rollups are the only remaining source for",
      oldest_left is not None and oldest_left > OLDEST + 600,
      f"oldest raw row is now {oldest_left - OLDEST:.0f} s into the history")

floors = {tier: service.flow_db.rollup_bounds(tier)[0] for tier in ROLLUP_TIERS}
check("the hourly rollups reach back to the history the trim then deleted: "
      "the backfill summarised those buckets before the cap took the rows",
      floors[3600] is not None and floors[3600] <= OLDEST + 3600,
      f"hourly floor is {floors[3600] - OLDEST:.0f} s into the history, "
      f"oldest surviving raw row {oldest_left - OLDEST:.0f} s")
spans = service.flow_db._conn.execute(
    "SELECT COUNT(*) FROM flow_rollup_span WHERE tier = 3600"
    " AND bucket < ?", (oldest_left,)).fetchone()[0]
check("...with buckets actually stored below the oldest surviving raw row, "
      "so a wide chart still has something to draw there",
      spans > 0, spans)

service.shutdown()
shutil.rmtree(os.path.join(TMPDIR, "t1"), ignore_errors=True)

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
