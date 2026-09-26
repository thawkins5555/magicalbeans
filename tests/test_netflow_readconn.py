"""NetFlow request-path reads on their own connection.

Charts, the record list and the totals read through a second, query-only
connection behind its own lock, so the collector's writer and the summariser
never queue behind them; coverage() answers from its last result rather than
wait; _raw_holds is memoised; _span_plan tiles a window coarsest tier first;
an hourly chart's tail comes from the minute tier; and the MIN/MAX bounds
coverage() and prune() read are index probes.

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


def flow(index: int, ts: float, **overrides):
    fields = dict(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 4}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443, 53, 22)[index % 4],
        protocol=(6, 17, 1)[index % 3], tos=0, tcp_flags=0,
        in_if=index % 6, out_if=index % 8, src_as=0, dst_as=0, next_hop=None,
        packets=1 + index % 9, bytes=100 + index * 7,
        sampling=(1, 2, 10)[index % 3], domain=0, sampler_id=0)
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


def raw(db: FlowDatabase, method: str, *args, **kwargs):
    real = FlowDatabase._rollup_plan
    FlowDatabase._rollup_plan = lambda *a, **k: None
    try:
        return getattr(db, method)(*args, **kwargs)
    finally:
        FlowDatabase._rollup_plan = real


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
        self.hook = None

    def execute(self, sql, *args):
        self.sql.append(sql)
        if self.hook:
            self.hook()
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
    print("c: _raw_holds is memoised for a minute, until a prune or trim")
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
        check(list(db._raw_holds_memo) == [(3600, base + 3600, upper)],
              "keyed on the first whole bucket, which both queries bind")
        key = (3600, base + 3600, upper)
        db._raw_holds_memo[key] = (time.monotonic() - 61, True)
        db._raw_holds(3600, base + 100.0, upper)
        check(len(spy.sql) == walked + 2, "a stale answer is recomputed")

        def queries() -> int:
            before = len(spy.sql)
            db._raw_holds(3600, base + 100.0, upper)
            return len(spy.sql) - before

        db.prune(365, 0, budget_s=10)
        check(queries() == 2, "after prune() the next call queries again")
        real_stage = db._prune_interfaces

        def mid_prune(*args, **kwargs):
            db._raw_holds(3600, base + 100.0, upper)
            return real_stage(*args, **kwargs)

        db._prune_interfaces = mid_prune
        db.prune(365, 0, budget_s=10)
        del db._prune_interfaces
        check(queries() == 2,
              "an answer computed during a prune does not outlive it")
        db.trim_to_size(10 ** 12)
        check(queries() == 2, "nor one from before the size cap's trim")
        check(queries() == 0, "and a fresh answer is reused again")

        def stamp():
            db._raw_holds_cleared = time.monotonic()

        db._raw_holds_memo.clear()
        spy.hook = stamp
        db._raw_holds(3600, base + 100.0, upper)
        spy.hook = None
        check(queries() == 2,
              "an answer computed across a prune's end is discarded")
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

        with db._lock:
            db._conn.execute("DELETE FROM flows WHERE id IN (SELECT id FROM"
                             " flows WHERE ts_end >= ? ORDER BY ts_end"
                             " LIMIT 5)", (base + 3600,))
            db._conn.commit()
        db.prune(365, 0, budget_s=10)
        check(not db._raw_holds(3600, base + 100.0, upper),
              "five flows gone from the whole buckets are missed, however "
              "many the partial hour before them holds")
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

    early = base - 3 * 86400
    arms, raw_edges = db._span_plan(early, t1, "interface")
    check(arms == [(3600, base, base + 4 * 3600),
                   (60, base + 4 * 3600, minute_seal)]
          and raw_edges == [(early, base, False), (minute_seal, t1, True)]
          and db.interface_totals(early, t1) == want_interfaces(early, t1)
          and db.exporter_totals(early, t1) == want_exporters(early, t1),
          "a window starting below the floors is served from the floor up, "
          "raw only below it, and still totals as raw")

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


# ------------------------------------------------------------------------- g

def test_g_minute_tail() -> None:
    print("g: an hourly chart's tail comes from the minute tier, not raw")
    db = store("tail.db")
    now = time.time()
    base = flowdb._align_down(now, 3600) - 5 * 3600
    rows = [flow(i, base + i * 6.0) for i in range(int((now - 5 - base) / 6))]
    # Ten minutes over the minute cap, inside the hour the tail will cover.
    burst = flowdb._align_down(now - flowdb._ROLLUP_LAG_S, 3600) - 3600
    rows += [flow(k, burst + minute * 60 + 30, src_ip=f"172.16.0.{k}",
                  bytes=50, sampling=1)
             for minute in range(10) for k in range(60)]
    db.insert_flows(rows)
    cover(db)
    hourly = db.rollup_bounds(3600)[1] - 3600
    db._set_private_setting(flowdb._WATERMARK % 3600, hourly)
    week = flowdb._align_down(now - 8 * 86400, 86400)
    for key in (flowdb._FLOOR % 3600, flowdb._SCOPED_FLOOR % 3600,
                flowdb._IFACE_FLOOR):
        db._set_private_setting(key, week)
    t0, t1 = now - 7 * 86400, now
    tail = db._minute_tail("global", "Source", hourly, t1)
    check(tail is not None and tail >= hourly + 3600 and tail < t1,
          f"the hourly watermark sits an hour behind the minute tier's "
          f"({(tail or 0) - hourly} s of tail from minutes, raw after)")

    exporter = {**NO_FILTERS, "exporter": EXPORTER}
    iface = {**exporter, "iface": 4}
    cases = [("Source", NO_FILTERS, 3600), ("Conversation", NO_FILTERS, 21600),
             ("Source", exporter, 3600), ("Conversation", exporter, 3600),
             ("Application", iface, 3600)]
    for dimension, filters, bucket in cases:
        info: dict = {}
        got = db.overview(t0, t1, dimension, filters, bucket, info=info)
        want = raw(db, "overview", t0, t1, dimension, filters, bucket)
        check(info["tier"] == 3600 and got == want,
              f"7 days of {dimension} by {bucket}s, filters "
              f"{ {k: v for k, v in filters.items() if v and k != 'direction'} }"
              f": equal to raw, capped minutes repaired")
    check(db.totals(flowdb._align_down(t0, 3600), t1, exporter)
          == raw(db, "totals", flowdb._align_down(t0, 3600), t1, exporter),
          "and one-slot totals()")

    saved = flowdb._REPAIR_MAX_FLOWS
    flowdb._REPAIR_MAX_FLOWS = 0
    try:
        got = db.overview(t0, t1, "Source", NO_FILTERS, 3600, top_limit=500)
    finally:
        flowdb._REPAIR_MAX_FLOWS = saved
    want = raw(db, "overview", t0, t1, "Source", NO_FILTERS, 3600,
               top_limit=500)
    keys = {row["key"]: row["bytes"] for row in got[3]}
    raw_keys = {row["key"]: row["bytes"] for row in want[3]}
    check(got[4] == want[4]
          and all(keys.get(k, 0) <= v for k, v in raw_keys.items())
          and all(keys[f"192.168.0.{n}"] == raw_keys[f"192.168.0.{n}"]
                  for n in range(4))
          and len(keys) < len(raw_keys),
          f"with the repair stood down the totals stay exact and only keys "
          f"under the minute cap come up short ({len(keys)} of "
          f"{len(raw_keys)} keys)")

    with db._lock:
        poisoned = db._conn.execute(
            f"UPDATE flow_rollup_span SET bytes = bytes + 1000000 WHERE"
            f" tier = 60 AND {flowdb._GLOBAL_SQL} AND bucket >= ?"
            f" AND bucket < ?", (hourly, tail)).rowcount
        db._conn.commit()
    after = db.overview(t0, t1, "Source", NO_FILTERS, 3600)[4]
    check(after["bytes"] - want[4]["bytes"] == poisoned * 1_000_000,
          f"the tail's totals are read from the {poisoned} minute span rows")
    db.close()


# ------------------------------------------------------------------------- h

def test_h_index_probes() -> None:
    print("h: coverage() and prune()'s row cap read their bounds by probe")
    db = store("probes.db")
    now = time.time()
    db.insert_flows([flow(i, now - 100 + i) for i in range(50)])
    seen: list[str] = []
    for conn in (db._conn, db._read_conn):
        conn.set_trace_callback(seen.append)
    try:
        db.coverage()
        db.prune(365, 10 ** 9, budget_s=10)
    finally:
        for conn in (db._conn, db._read_conn):
            conn.set_trace_callback(None)
    bounds = [sql for sql in seen
              if ("MIN(ts_end)" in sql and "MAX(ts_end)" in sql)
              or ("MIN(id)" in sql and "MAX(id)" in sql)]
    plans = [[row["detail"] for row in db._conn.execute(
        "EXPLAIN QUERY PLAN " + sql)] for sql in bounds]
    check(len(bounds) == 2
          and not any(line.startswith("SCAN flows")
                      for plan in plans for line in plan),
          f"no scan of flows in either ({plans})")
    db.close()


TESTS = [test_a_visibility, test_b_no_waiting, test_c_raw_holds_memo,
         test_d_span_plan, test_e_close, test_f_memory, test_g_minute_tail,
         test_h_index_probes]


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
