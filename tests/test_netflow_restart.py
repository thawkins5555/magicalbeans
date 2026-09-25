"""A NetFlow store survives its process dying mid-compaction, and a collector
restart keeps decoding v9.

The crash is real: a child process opens the store, inserts flows, starts
compacting and calls os._exit() inside a summary transaction, with no close
and nothing flushed. The parent reopens the file and checks that what the
watermarks and floors claim is what is stored, that compaction resumes, and
that every bucket then equals the raw rows it was built from.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import os
import shutil
import socket
import struct
import subprocess
import sys
import time

from _paths import REPO_ROOT, free_udp_port, tmpdir

from netpath import flowdb, nfdecode
from netpath.collector import Collector
from netpath.flowdb import DIMENSIONS, FlowDatabase

TMPDIR = tmpdir("netflow_restart_")
FAILS: list[str] = []

NO_FILTERS = {"src_ip": "", "dst_ip": "", "port": None, "protocol": None,
              "exporter": None, "iface": None, "direction": "both"}

# Dies inside the Nth scoped summary transaction of this run: after its
# DELETE and INSERT, before its COMMIT.
CHILD = r"""
import os, sys, types
sys.path.insert(0, sys.argv[1])
from netpath import flowdb
from netpath.flowdb import FlowDatabase

path, mode, start, crash_at = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
db = FlowDatabase(path)
calls = [0]
real = FlowDatabase._flag_capped

def dying(self, *args):
    calls[0] += 1
    if calls[0] >= crash_at:
        os._exit(17)
    return real(self, *args)

FlowDatabase._flag_capped = dying
if mode == "forward":
    db.insert_flows([types.SimpleNamespace(
        exporter=f"10.0.0.{i % 3}", version=9, ts_start=start + i * 5.0 - 1,
        ts_end=start + i * 5.0, src_ip=f"192.168.0.{i % 7}",
        dst_ip=f"8.8.8.{i % 5}", src_port=1000 + i % 11,
        dst_port=(80, 443, 53, 22)[i % 4], protocol=(6, 17)[i % 2], tos=0,
        tcp_flags=0, in_if=i % 4, out_if=i % 5, src_as=0, dst_as=0,
        next_hop=None, packets=1 + i % 9, bytes=100 + i, sampling=(1, 2)[i % 2],
        domain=0, sampler_id=0) for i in range(int(sys.argv[6]))])
    db._set_private_setting(flowdb._FLOOR % 60, start)
    db._set_private_setting(flowdb._WATERMARK % 60, start)
    db.compact_rollup(60, max_buckets=10_000, budget_s=600)
else:
    db.compact_rollup(3600, max_buckets=10_000, budget_s=600)
    db.backfill_rollup(3600, max_buckets=10_000, budget_s=600)
os._exit(0)
"""


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


def raw(db: FlowDatabase, method: str, *args, **kwargs):
    real = FlowDatabase._rollup_plan
    FlowDatabase._rollup_plan = lambda *a, **k: None
    try:
        return getattr(db, method)(*args, **kwargs)
    finally:
        FlowDatabase._rollup_plan = real


def crash(path: str, mode: str, start: int, crash_at: int, rows: int = 0) -> int:
    result = subprocess.run(
        [sys.executable, "-c", CHILD, REPO_ROOT, path, mode, str(start),
         str(crash_at), str(rows)],
        capture_output=True, text=True, timeout=600)
    if result.returncode != 17:
        print(result.stdout, result.stderr)
    return result.returncode


def spans_match_raw(db: FlowDatabase, tier: int, low: int, upper: int) -> list:
    """Buckets in [low, upper) whose global span differs from raw."""
    with db._lock:
        stored = {row[0]: tuple(row[1:]) for row in db._conn.execute(
            f"SELECT bucket, bytes, packets, flows FROM flow_rollup_span"
            f" WHERE tier = ? AND {flowdb._GLOBAL_SQL} AND bucket >= ?"
            f" AND bucket < ?", (tier, low, upper))}
        want = {row[0]: tuple(row[1:]) for row in db._conn.execute(
            "SELECT CAST(ts_end / ? AS INTEGER) * ?, SUM(bytes * sampling),"
            " SUM(packets * sampling), COUNT(*) FROM flows WHERE ts_end >= ?"
            " AND ts_end < ? GROUP BY 1", (tier, tier, low, upper))}
    return sorted(bucket for bucket in set(stored) | set(want)
                  if stored.get(bucket) != want.get(bucket))


def test_1_crash_mid_compaction() -> None:
    print("1: a process killed mid-compaction leaves a store that resumes "
          "exactly")
    path = os.path.join(TMPDIR, "crash.db")
    now = time.time()
    start = flowdb._align_down(now - 4 * 3600, 3600)
    rows = int((now - 200 - start) / 5.0)
    # Ten scoped transactions per minute bucket: dies in the 41st bucket.
    code = crash(path, "forward", start, 40 * 10 + 4, rows)
    check(code == 17, f"the child died mid-pass, as arranged (exit {code})")

    db = FlowDatabase(path)
    floor, watermark = db.rollup_bounds(60)
    dirty = db._private_setting(flowdb._DIRTY % 60)
    stored = db._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    check(stored == rows, f"every inserted flow is on disk ({stored} of {rows})")
    check(floor == start and watermark == start and dirty is not None
          and dirty <= watermark,
          f"the watermark never claimed the buckets the pass had not "
          f"finished, and the dirty mark still covers them (floor "
          f"{floor - start}, watermark {watermark - start}, dirty "
          f"{dirty - start if dirty is not None else None})")
    partial = db._conn.execute(
        "SELECT COUNT(*) FROM flow_rollup_span WHERE tier = 60 AND bucket >= ?",
        (start + 40 * 60,)).fetchone()[0]
    check(partial == 0,
          f"the bucket it died in never got the span row written after its "
          f"dimensions ({partial})")
    end = now
    check(db.overview(start, end, "Source", NO_FILTERS, 60)
          == raw(db, "overview", start, end, "Source", NO_FILTERS, 60),
          "reads straight after the reopen equal raw: nothing counted twice")

    db.compact_rollup(60, max_buckets=10_000, budget_s=600)
    _floor, watermark = db.rollup_bounds(60)
    check(watermark >= flowdb._align_down(now - flowdb._ROLLUP_LAG_S, 60) - 60
          and db._private_setting(flowdb._DIRTY % 60) is None,
          "one pass later the minute watermark is current and the dirty mark "
          "consumed")
    gaps = spans_match_raw(db, 60, start, watermark)
    check(not gaps, f"every minute's total equals raw, no gap and no double "
                    f"count ({len(gaps)} differ)")
    mismatched = [f"{dimension} {name}" for dimension in DIMENSIONS
                  for name, filters in (
                      ("global", NO_FILTERS),
                      ("exporter", {**NO_FILTERS, "exporter": "10.0.0.1"}))
                  if db.overview(start, watermark, dimension, filters, 60)
                  != raw(db, "overview", start, watermark, dimension, filters,
                         60)]
    check(not mismatched, f"and every dimension, global and per exporter, "
                          f"equals raw ({mismatched[:3]})")
    db.close()

    # Now the hourly backfill: two hours in, dies in the third.
    code = crash(path, "backfill", start, 2 * 30 + 7)
    check(code == 17, f"the child died mid-backfill (exit {code})")
    db = FlowDatabase(path)
    floor, watermark = db.rollup_bounds(3600)
    scoped = db._private_setting(flowdb._SCOPED_FLOOR % 3600)
    iface = db._private_setting(flowdb._IFACE_FLOOR)
    check(floor == watermark - 2 * 3600 and scoped == floor and iface == floor,
          f"the hourly floor stands on the last whole bucket, the scoped "
          f"floors with it ({(watermark - floor) // 3600} h built)")
    gaps = spans_match_raw(db, 3600, floor, watermark)
    check(not gaps, f"and the hours it claims equal raw ({gaps})")
    while True:
        written, done = db.backfill_rollup(3600, max_buckets=10_000,
                                           budget_s=600)
        if done or not written:
            break
    floor, watermark = db.rollup_bounds(3600)
    check(floor == start and db._private_setting(flowdb._IFACE_FLOOR) == start,
          "backfill resumes and reaches the oldest hour, interface floor too")
    iface_filter = {**NO_FILTERS, "exporter": "10.0.0.1", "iface": 1}
    mismatched = [f"{dimension} {name}" for dimension in DIMENSIONS
                  for name, filters in (
                      ("global", NO_FILTERS),
                      ("exporter", {**NO_FILTERS, "exporter": "10.0.0.2"}),
                      ("interface", iface_filter))
                  if db.overview(start, watermark, dimension, filters, 3600)
                  != raw(db, "overview", start, watermark, dimension, filters,
                         3600)]
    check(not spans_match_raw(db, 3600, start, watermark) and not mismatched,
          f"every hour equals raw, global, per exporter and per interface "
          f"({mismatched[:3]})")
    check(db._rollup_plan(start, watermark, "Source", iface_filter, 3600)
          is not None, "...and the interface one is summary-served")
    db.close()


# ------------------------------------------------------------------------- 2

def v9_packet(sets: bytes, sequence: int) -> bytes:
    return struct.pack("!HHIIII", 9, 1, 1000, int(time.time()), sequence, 0) + sets


def v9_set(set_id: int, payload: bytes) -> bytes:
    return struct.pack("!HH", set_id, 4 + len(payload)) + payload


FIELDS = [(nfdecode.SRC_IPV4, 4), (nfdecode.DST_IPV4, 4), (nfdecode.IN_IF, 2),
          (nfdecode.OUT_IF, 2), (nfdecode.OCTETS, 4), (nfdecode.PACKETS, 4)]


def template_set() -> bytes:
    body = struct.pack("!HH", 700, len(FIELDS))
    for field_id, size in FIELDS:
        body += struct.pack("!HH", field_id, size)
    return v9_set(0, body)


def data_set(count: int) -> bytes:
    return v9_set(700, b"".join(
        socket.inet_aton("10.1.1.1") + socket.inet_aton("10.2.2.2")
        + struct.pack("!HHII", 3, 4, 1500 + n, 10) for n in range(count)))


def send(port: int, payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, ("127.0.0.1", port))
    finally:
        sock.close()


def wait_for(predicate, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_2_collector_restart_keeps_templates() -> None:
    print("2: a collector restarted on the same store decodes v9 without "
          "waiting for a template")
    db = FlowDatabase(os.path.join(TMPDIR, "collector.db"))

    def stored() -> int:
        with db._lock:
            return db._conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

    settings = {**flowdb.DEFAULTS, "bind_address": "127.0.0.1"}
    first = Collector(db)
    check(first.start({**settings, "port": free_udp_port()}),
          f"the first collector binds ({first.error})")
    send(first.bound[1], v9_packet(template_set() + data_set(3), 1))
    check(wait_for(lambda: stored() == 3),
          f"template and data decode and are stored ({stored()} flows)")
    first.stop()
    check(any(entry["template_id"] == 700 for entry in db.load_template_cache()),
          "stopping saves the template it learned")

    second = Collector(db)   # a new process: a fresh decoder, no templates
    check(second.start({**settings, "port": free_udp_port()}),
          f"a second collector binds ({second.error})")
    try:
        check(("127.0.0.1", 0, 700) in second.decoder.templates,
              "and starts with the saved template restored")
        send(second.bound[1], v9_packet(data_set(4), 2))
        check(wait_for(lambda: stored() == 7)
              and second.counters["flows"] == 4,
              f"data sent with no template after the restart is decoded and "
              f"counted ({stored()} stored, {second.counters['flows']} counted)")
        with db._lock:
            row = db._conn.execute(
                "SELECT exporter, in_if, out_if, bytes FROM flows"
                " ORDER BY id DESC LIMIT 1").fetchone()
        check(tuple(row) == ("127.0.0.1", 3, 4, 1503),
              f"with its fields intact ({tuple(row)})")
    finally:
        second.stop()
        db.close()


TESTS = [
    test_1_crash_mid_compaction,
    test_2_collector_restart_keeps_templates,
]


def main() -> int:
    try:
        for test in TESTS:
            test()
            print()
    finally:
        shutil.rmtree(TMPDIR, ignore_errors=True)
    if FAILS:
        print(f"{len(FAILS)} CHECK(S) FAILED:")
        for item in FAILS:
            print(f"  - {item}")
        return 1
    print("ALL NETFLOW RESTART ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
