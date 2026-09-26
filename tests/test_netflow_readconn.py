"""NetFlow request-path reads on their own connection.

Charts, the record list and the totals read through a second, query-only
connection behind its own lock, so the collector's writer and the summariser
never queue behind them; coverage() answers from its last result rather than
wait; _raw_holds is memoised; and _span_plan tiles a window coarsest tier
first.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import random
import shutil
import sqlite3
import sys
import threading
import time
import types

from _paths import tmpdir

from netpath import flowdb
from netpath.flowdb import FlowDatabase

TMPDIR = tmpdir("netflow_readconn_")
FAILS: list[str] = []

NO_FILTERS = {"src_ip": "", "dst_ip": "", "port": None, "protocol": None,
              "exporter": None, "iface": None, "direction": "both"}
EXPORTER = "10.0.0.1"


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


def store(name: str) -> FlowDatabase:
    return FlowDatabase(f"{TMPDIR}/{name}")


def flow(index: int, ts: float):
    return types.SimpleNamespace(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 4}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443, 53, 22)[index % 4],
        protocol=(6, 17, 1)[index % 3], tos=0, tcp_flags=0,
        in_if=index % 6, out_if=index % 8, src_as=0, dst_as=0, next_hop=None,
        packets=1 + index % 9, bytes=100 + index * 7,
        sampling=(1, 2, 10)[index % 3], domain=0, sampler_id=0)


def cover(db: FlowDatabase) -> None:
    for tier in flowdb.ROLLUP_TIERS:
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        while True:
            written, done = db.backfill_rollup(tier, max_buckets=10_000,
                                               budget_s=120)
            if done or not written:
                break


def holding(lock, seconds: float) -> threading.Thread:
    """Hold `lock` on another thread for `seconds`; returns once it is held."""
    held = threading.Event()

    def run():
        with lock:
            held.set()
            time.sleep(seconds)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    held.wait(5)
    return thread


class Spy:
    """The read connection, counting what runs on it."""

    def __init__(self, conn):
        self.conn = conn
        self.sql: list[str] = []

    def execute(self, sql, *args):
        self.sql.append(sql)
        return self.conn.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.conn, name)


def raw_walks(spy: Spy) -> int:
    return sum("SELECT 1 FROM flows" in sql for sql in spy.sql)


# ------------------------------------------------------------------------- a

def test_a_visibility() -> None:
    print("a: a committed write is visible on the read connection")
    db = store("visible.db")
    now = time.time()
    check(db._read_conn is not db._conn and db._read_lock is not db._lock,
          "a file store reads through its own connection and lock")
    db.insert_flows([flow(1, now - 5)])
    rows, _bounded = db.flows(now - 60, now, NO_FILTERS)
    _times, _series, _bucket, _top, totals = db.overview(
        now - 60, now, "Source", NO_FILTERS, 10)
    check(len(rows) == 1 and totals["flows"] == 1,
          f"flows() and overview() see the flow insert_flows committed "
          f"({len(rows)} row(s), {totals['flows']} flow(s))")
    db.touch_exporters([(EXPORTER, 9, 1, 1, 1)])
    check([row["address"] for row in db.exporters()] == [EXPORTER],
          "exporters() sees touch_exporters' commit")
    try:
        db._read_conn.execute("DELETE FROM flows")
        refused = False
    except sqlite3.OperationalError:
        refused = True
    check(refused and len(db.flows(now - 60, now, NO_FILTERS)[0]) == 1,
          "the read connection refuses a write (query_only)")
    check(db.read_lock_stats().get("acquisitions", 0) > 0,
          f"read_lock_stats() counts the read lock ({db.read_lock_stats()})")
    db.close()


# ------------------------------------------------------------------------- b

def test_b_no_waiting() -> None:
    print("b: coverage(), the writer and the record list do not wait")
    db = store("waiting.db")
    now = time.time()
    db.insert_flows([flow(i, now - 30 + i) for i in range(10)])
    last = db.coverage()
    thread = holding(db._read_lock, 1.0)
    started = time.monotonic()
    cov = db.coverage()
    elapsed = time.monotonic() - started
    check(elapsed < 0.4 and cov == last,
          f"with the read lock held, coverage() returns its last answer in "
          f"{elapsed:.2f} s")
    started = time.monotonic()
    db.insert_flows([flow(99, now - 1)])
    elapsed = time.monotonic() - started
    check(elapsed < 0.4,
          f"and insert_flows does not wait behind the reader ({elapsed:.2f} s)")
    thread.join()
    check(db.coverage()["raw_newest"] == now - 1,
          "once the lock is free coverage() reads again")
    thread = holding(db._lock, 1.0)
    started = time.monotonic()
    rows, _bounded = db.flows(now - 60, now, NO_FILTERS, limit=500)
    elapsed = time.monotonic() - started
    check(elapsed < 0.4 and len(rows) == 11,
          f"with the write lock held, flows() answers in {elapsed:.2f} s")
    thread.join()
    db.close()


# ------------------------------------------------------------------------- c

def test_c_raw_holds_memo() -> None:
    print("c: _raw_holds is memoised for a minute, and prune() clears it")
    db = store("memo.db")
    base = flowdb._align_down(time.time(), 3600) - 4 * 3600
    db.insert_flows([flow(i, base + i * 20.0) for i in range(3 * 180)])
    cover(db)
    spy = Spy(db._read_conn)
    db._read_conn = spy
    try:
        db._raw_holds_memo.clear()
        upper = base + 3 * 3600
        first = db._raw_holds(3600, base + 100.0, upper)
        walked = len(spy.sql)
        again = db._raw_holds(3600, base + 100.0, upper)
        slid = db._raw_holds(3600, base + 105.0, upper)
        check(first and again and slid and walked == 2
              and len(spy.sql) == walked,
              f"the second call, and one a poll later in the same hour, do "
              f"not query ({walked} statement(s), then {len(spy.sql) - walked})")
        key = (3600, base, upper)
        db._raw_holds_memo[key] = (time.monotonic() - 61, True)
        db._raw_holds(3600, base + 100.0, upper)
        check(len(spy.sql) == walked + 2, "a stale answer is recomputed")
        db.prune(365, 0, budget_s=10)
        check(not db._raw_holds_memo, "prune() clears the memo")
        before = len(spy.sql)
        db._raw_holds(3600, base + 100.0, upper)
        check(len(spy.sql) == before + 2, "and the next call queries again")
        stale = time.monotonic() - 120
        for n in range(250):
            db._raw_holds_memo[(3600, n, n)] = (stale, False)
        db._raw_holds(3600, base + 200.0, base + 2 * 3600)
        check(len(db._raw_holds_memo) <= 3,
              f"stale entries are dropped once it grows "
              f"({len(db._raw_holds_memo)} left)")

        db._raw_holds_memo.clear()
        iface = {**NO_FILTERS, "exporter": EXPORTER, "iface": 4}
        t0 = base + 1000.0
        spy.sql.clear()
        db.overview(t0, time.time(), "Application", iface, 300)
        first_poll = raw_walks(spy)
        spy.sql.clear()
        db.overview(t0 + 10, time.time(), "Application", iface, 300)
        check(first_poll >= 1 and raw_walks(spy) == 0,
              f"an interface chart's next poll does not re-walk raw "
              f"({first_poll} walk(s), then {raw_walks(spy)})")
    finally:
        db._read_conn = spy.conn
    db.close()


# ------------------------------------------------------------------------- d

def test_d_span_plan() -> None:
    print("d: _span_plan tiles hours, minutes and raw edges exactly")
    db = store("span.db")
    base = flowdb._align_down(time.time(), 3600) - 8 * 3600
    db.insert_flows([flow(i, base + i * 7.0)
                     for i in range(int(6 * 3600 / 7))])
    t0 = base + 3600 + 1234.5
    t1 = base + 5 * 3600 + 2700.25
    minute_start = flowdb._align_up(t0, 60)
    minute_seal = base + 5 * 3600 + 1800
    edges = (t0, minute_start, base + 2 * 3600, base + 4 * 3600, minute_seal,
             t1)
    db.insert_flows([flow(1000 + n, ts) for n, ts in enumerate(
        (*edges, t0 - 0.001, t1 + 0.001))])
    cover(db)
    db._set_private_setting(flowdb._WATERMARK % 3600, base + 4 * 3600)
    db._set_private_setting(flowdb._WATERMARK % 60, minute_seal)

    def want_exporters(lo, hi):
        return {row[0]: {"bytes": row[1], "packets": row[2], "flows": row[3]}
                for row in db._conn.execute(
                    "SELECT exporter, SUM(bytes * sampling),"
                    " SUM(packets * sampling), COUNT(*) FROM flows"
                    " WHERE ts_end >= ? AND ts_end <= ? GROUP BY exporter",
                    (lo, hi))}

    def want_interfaces(lo, hi, exporter=None):
        rows = []
        for side, column in (("in", "in_if"), ("out", "out_if")):
            rows += [{"exporter": row[0], "iface": row[1], "dir": side,
                      "bytes": row[2], "packets": row[3], "flows": row[4]}
                     for row in db._conn.execute(
                         f"SELECT exporter, {column}, SUM(bytes * sampling),"
                         f" SUM(packets * sampling), COUNT(*) FROM flows"
                         f" WHERE ts_end >= ? AND ts_end <= ? AND {column} >= 0"
                         f" AND (? IS NULL OR exporter = ?)"
                         f" GROUP BY exporter, {column}",
                         (lo, hi, exporter, exporter))]
        return sorted(rows, key=lambda r: (r["exporter"], r["iface"], r["dir"]))

    for kind in ("exporter", "interface"):
        arms, raw_edges = db._span_plan(t0, t1, kind)
        check(arms == [(3600, base + 2 * 3600, base + 4 * 3600),
                       (60, minute_start, base + 2 * 3600),
                       (60, base + 4 * 3600, minute_seal)]
              and raw_edges == [(t0, minute_start, False),
                                (minute_seal, t1, True)],
              f"{kind}: hours first, minutes either side, raw at both ends "
              f"({arms}, {raw_edges})")
    check(db.exporter_totals(t0, t1) == want_exporters(t0, t1),
          "exporter_totals over all three arms equals raw")
    check(db.interface_totals(t0, t1) == want_interfaces(t0, t1)
          and db.interface_totals(t0, t1, EXPORTER)
          == want_interfaces(t0, t1, EXPORTER),
          "interface_totals over all three arms equals raw, all exporters "
          "and one")

    rng = random.Random(5)
    bad = []
    for _ in range(40):
        lo = base + rng.uniform(-600, 6 * 3600)
        hi = lo + rng.choice((0.0, 59.0, 3600.0, rng.uniform(0, 6 * 3600)))
        for kind in ("exporter", "interface"):
            arms, raw_edges = db._span_plan(lo, hi, kind)
            pieces = sorted([(s, e) for _t, s, e in arms]
                            + [(s, e) for s, e, _c in raw_edges])
            joined = all(a[1] == b[0] for a, b in zip(pieces, pieces[1:]))
            if not (pieces and pieces[0][0] == lo and pieces[-1][1] == hi
                    and joined
                    and [c for _s, _e, c in raw_edges].count(True) <= 1):
                bad.append((kind, lo, hi, arms, raw_edges))
        if (db.exporter_totals(lo, hi) != want_exporters(lo, hi)
                or db.interface_totals(lo, hi) != want_interfaces(lo, hi)):
            bad.append(("totals", lo, hi))
    check(not bad, f"40 random windows tile exactly and total as raw ({bad[:2]})")
    db.close()


# ------------------------------------------------------------------------- e

def test_e_close() -> None:
    print("e: close() closes both connections, once")
    db = store("close.db")
    db.close()
    closed = []
    for conn in (db._conn, db._read_conn):
        try:
            conn.execute("SELECT 1")
            closed.append(False)
        except sqlite3.ProgrammingError:
            closed.append(True)
    check(closed == [True, True], f"both connections are closed ({closed})")
    try:
        db.close()
        twice = True
    except Exception as exc:                          # noqa: BLE001
        twice = False
        print(f"    {exc!r}")
    check(twice, "a second close() is a no-op")
    db = store("close_held.db")
    thread = holding(db._read_lock, 1.0)
    started = time.monotonic()
    db.close(timeout_s=0.1)
    elapsed = time.monotonic() - started
    thread.join()
    check(elapsed < 0.6, f"a held read lock delays close() by its timeout "
                         f"alone ({elapsed:.2f} s)")


# ------------------------------------------------------------------------- f

def test_f_memory() -> None:
    print("f: an in-memory store reads through its one connection")
    db = FlowDatabase(":memory:")
    now = time.time()
    check(db._read_conn is db._conn and db._read_lock is db._lock,
          "the read pair aliases the write pair")
    db.insert_flows([flow(1, now - 5)])
    check(len(db.flows(now - 60, now, NO_FILTERS)[0]) == 1
          and db.coverage()["raw_newest"] == now - 5,
          "and reads what it wrote")
    db.close()
    db.close()
    check(True, "close() twice is fine")


TESTS = [test_a_visibility, test_b_no_waiting, test_c_raw_holds_memo,
         test_d_span_plan, test_e_close, test_f_memory]


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
    print("ALL NETFLOW READ-CONNECTION ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
