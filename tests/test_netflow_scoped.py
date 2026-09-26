"""The scoped NetFlow summaries answer what the raw flows do.

Per exporter (both tiers) and per (exporter, interface, direction) (hourly),
each scope is checked the way test_netflow_rollup checks the global one: the
same question asked twice, once normally and once with _rollup_plan forced
to None, compared element for element.

Plain script, no pytest: run it, read the PASS lines, non-zero exit on failure.
"""
import logging
import os
import shutil
import sqlite3
import sys
import time
import types

from _paths import tmpdir

from netpath import flowdb
from netpath.flowdb import DIMENSIONS, SCOPED_KEYS, FlowDatabase

TMPDIR = tmpdir("netflow_scoped_")
FAILS: list[str] = []

BUCKETS = (10, 60, 300, 900, 3600, 21600)
NO_FILTERS = {"src_ip": "", "dst_ip": "", "port": None, "protocol": None,
              "exporter": None, "iface": None, "direction": "both"}
EXPORTER = "10.0.0.1"
IFACE = 4   # exporter 10.0.0.1 sees it both ways, hairpins included


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"  PASS: {message}")
    else:
        print(f"  FAIL: {message}")
        FAILS.append(message)


def store(name: str) -> FlowDatabase:
    return FlowDatabase(os.path.join(TMPDIR, name))


def flow(index: int, ts: float, **overrides):
    """Under every scope's cap: at most 20 conversations per exporter and 10
    per interface and direction."""
    fields = dict(
        exporter=f"10.0.0.{index % 3}", version=9, ts_start=ts - 1, ts_end=ts,
        src_ip=f"192.168.0.{index % 4}", dst_ip=f"8.8.8.{index % 5}",
        src_port=1000 + index % 11, dst_port=(80, 443, 53, 22)[index % 4],
        protocol=(6, 17, 1)[index % 3], tos=index % 4, tcp_flags=0,
        in_if=index % 6, out_if=index % 8,
        src_as=64500 + index % 3, dst_as=64600 + index % 2, next_hop=None,
        packets=1 + index % 9, bytes=100 + index * 7,
        sampling=(1, 2, 10)[index % 3], domain=0, sampler_id=0)
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


def cover(db: FlowDatabase, *, minutes: bool = True, hours: bool = True) -> None:
    for tier, wanted in ((60, minutes), (3600, hours)):
        if not wanted:
            continue
        db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        while True:
            written, done = db.backfill_rollup(tier, max_buckets=10_000,
                                               budget_s=120)
            if done or not written:
                break


def raw(db: FlowDatabase, method: str, *args, **kwargs):
    real = FlowDatabase._rollup_plan
    FlowDatabase._rollup_plan = lambda *a, **k: None
    try:
        return getattr(db, method)(*args, **kwargs)
    finally:
        FlowDatabase._rollup_plan = real


def scoped(**extra) -> dict:
    return {**NO_FILTERS, "exporter": EXPORTER, **extra}


INTERFACE_FILTERS = {side: scoped(iface=IFACE, direction=side)
                     for side in ("in", "out", "both")}


def count(db: FlowDatabase, sql: str, params=()) -> int:
    with db._lock:
        return db._conn.execute(sql, params).fetchone()[0]


# ------------------------------------------------------------------------- 1

def test_1_scopes_agree_with_raw() -> None:
    print("1: exporter and interface scopes equal raw, every dimension and bucket")
    db = store("agree.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3 * 3600
    db.insert_flows([flow(i, start + i * (3 * 3600) / 1500.0)
                     for i in range(1500)])
    cover(db)
    check(count(db, "SELECT COUNT(*) FROM flow_rollup_trunc WHERE exporter != ''")
          == 0, "the fixture sits under every scope's cap: nothing is flagged")

    cases = [("exporter", scoped())] + [
        (f"interface {side}", filters)
        for side, filters in INTERFACE_FILTERS.items()]
    expected = {"exporter": {10: None, 60: 60, 300: 60, 900: 60, 3600: 3600,
                             21600: 3600}}
    for name, filters in cases:
        served = {}
        mismatched = []
        for dimension in DIMENSIONS:
            for bucket in BUCKETS:
                args = (start, end, dimension, filters, bucket)
                plan = db._rollup_plan(start, end, dimension, filters, bucket)
                served[bucket] = None if plan is None else plan[0]
                got, want = db.overview(*args), raw(db, "overview", *args)
                if got != want or not got[4]["flows"]:
                    mismatched.append(f"{dimension} at {bucket}s")
        check(not mismatched,
              f"{name}: all {len(DIMENSIONS)} dimensions x {len(BUCKETS)} "
              f"buckets agree exactly ({', '.join(mismatched[:3])})")
        want_served = expected.get(name, {10: None, 60: None, 300: None,
                                          900: None, 3600: 3600, 21600: 3600})
        check(served == want_served,
              f"{name}: routed as intended while raw still reaches t0 "
              f"({served})")
        check(db.totals(start, end, filters)
              == raw(db, "totals", start, end, filters),
              f"{name}: totals() agrees")
        check(db.top(start, end, "Conversation", filters, 10)
              == raw(db, "top", start, end, "Conversation", filters, 10),
              f"{name}: top() agrees")

    both = db.totals(start, end, INTERFACE_FILTERS["both"])
    sides = [db.totals(start, end, INTERFACE_FILTERS[side])
             for side in ("in", "out")]
    check(both == {key: sides[0][key] + sides[1][key] for key in both},
          "'both' is in plus out, a hairpin counted once each way")
    rows, _bounded = db.flows(start, end, INTERFACE_FILTERS["both"], limit=5000)
    want = count(db, "SELECT COUNT(*) FROM flows WHERE exporter = ?"
                 " AND (in_if = ? OR out_if = ?)", (EXPORTER, IFACE, IFACE))
    check(len(rows) == want and len({row["id"] for row in rows}) == want,
          f"the record list lists each matching flow once ({len(rows)} of "
          f"{want})")
    db.close()


# ------------------------------------------------------------------------- 2

def test_2_caps_flags_and_repair() -> None:
    print("2: each scope keeps its cap, flags what it cut, and repairs it")
    db = store("caps.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3600
    minute = start + 10 * 60
    rows = [flow(i, start + i * 6.0) for i in range(600)]
    cap = SCOPED_KEYS["exporter"][60]
    # One minute with three times the exporter cap in conversations, all on
    # one exporter and one ingress interface.
    rows += [flow(i, minute + 30, exporter=EXPORTER, in_if=IFACE, out_if=7,
                  src_ip=f"10.5.{i // 256}.{i % 256}", dst_ip="10.9.9.9",
                  bytes=5_000 + i, sampling=1) for i in range(cap * 3)]
    db.insert_flows(rows)
    cover(db)
    dim = flowdb.DIMENSION_IDS["Conversation"]
    stored = count(db, "SELECT COUNT(*) FROM flow_rollup WHERE tier = 60"
                   " AND exporter = ? AND iface = -1 AND dim = ? AND bucket = ?",
                   (EXPORTER, dim, minute))
    check(stored == cap, f"the exporter's minute kept exactly {cap} "
                         f"conversations ({stored})")
    flagged = count(db, "SELECT COUNT(*) FROM flow_rollup_trunc WHERE tier = 60"
                    " AND exporter = ? AND iface = -1 AND dim = ? AND bucket = ?",
                    (EXPORTER, dim, minute))
    others = count(db, "SELECT COUNT(*) FROM flow_rollup_trunc WHERE tier = 60"
                   " AND exporter NOT IN ('', ?) AND dim = ?", (EXPORTER, dim))
    check(flagged == 1 and others == 0,
          "only that exporter's minute is flagged, not its neighbours'")
    icap = SCOPED_KEYS["interface"][3600]
    istored = count(db, "SELECT COUNT(*) FROM flow_rollup WHERE tier = 3600"
                    " AND exporter = ? AND iface = ? AND dir = 'in' AND dim = ?"
                    " AND bucket = ?", (EXPORTER, IFACE, dim, start))
    iflagged = count(db, "SELECT COUNT(*) FROM flow_rollup_trunc WHERE tier = 3600"
                     " AND exporter = ? AND iface = ? AND dir = 'in' AND dim = ?"
                     " AND bucket = ?", (EXPORTER, IFACE, dim, start))
    check(istored == icap and iflagged == 1,
          f"the interface's hour kept {icap} and is flagged ({istored}, "
          f"{iflagged})")

    for name, filters, bucket in (("exporter", scoped(), 60),
                                  ("interface in", INTERFACE_FILTERS["in"], 3600),
                                  ("interface both", INTERFACE_FILTERS["both"],
                                   3600)):
        plan = db._rollup_plan(start, end, "Conversation", filters, bucket)
        runs = [db._repair_ranges(plan[0], scope, dim, start, plan[2])
                for scope in plan[3]] if plan else []
        got = db.overview(start, end, "Conversation", filters, bucket)
        want = raw(db, "overview", start, end, "Conversation", filters, bucket)
        check(plan is not None and any(runs) and got == want,
              f"{name}: the flagged bucket is repaired from raw and the whole "
              f"answer equals raw (runs {runs})")

    # Raw gone behind the flagged buckets: served capped, still adds up.
    with db._lock:
        db._conn.execute("DELETE FROM flows WHERE ts_end < ?", (minute + 60,))
        db._conn.commit()
    for name, filters, bucket, slot in (
            ("exporter", scoped(), 60, 10),
            ("interface in", INTERFACE_FILTERS["in"], 3600, 0)):
        _t, series, _b, _top, totals = db.overview(
            start, end, "Conversation", filters, bucket, series_limit=8)
        spans = db._agg_rows(start, end, None, filters, bucket)[4]
        other = series.get("— other —")
        check(other is not None and other[slot] > 0
              and sum(values[slot] for values in series.values())
              == spans[slot][0],
              f"{name}: past the raw rows the capped bucket's 'other' takes "
              f"the rest and the slot still adds up to its span, to the byte")
    db.close()


# ------------------------------------------------------------------------- 3

def test_3_scoped_repair_fits_999_variables() -> None:
    print("3: the scoped worst-case repair statement fits 999 variables")
    limit = getattr(sqlite3, "SQLITE_LIMIT_VARIABLE_NUMBER", None)
    end = flowdb._align_down(time.time() - 300, 3600)
    for name, filters, tier in (("exporter", scoped(), 60),
                                ("interface both", INTERFACE_FILTERS["both"],
                                 3600)):
        db = store(f"variables_{tier}.db")
        _kind, scopes = flowdb._scopes(filters)
        bound, _flows = flowdb._repair_budget(scopes)
        buckets = bound * 2 * len(scopes) + 10
        start = end - buckets * tier
        rows = []
        for n in range(buckets):
            ts = start + n * tier + 30
            rows.extend(flow(k, ts, exporter=EXPORTER, in_if=IFACE, out_if=IFACE,
                             src_ip=f"10.4.0.{k}", dst_ip="10.9.9.9",
                             bytes=1_000 + k, sampling=1) for k in range(3))
        db.insert_flows(rows)
        if tier == 60:
            cover(db, hours=False)
        else:
            db._set_private_setting(flowdb._FLOOR % 3600, start)
            db._set_private_setting(flowdb._WATERMARK % 3600, start)
            db._set_private_setting(flowdb._SCOPED_FLOOR % 3600, start)
            db._set_private_setting(flowdb._IFACE_FLOOR, start)
            db.compact_rollup(3600, max_buckets=10_000, budget_s=300)
        dim = flowdb.DIMENSION_IDS["Conversation"]
        with db._lock:
            db._conn.executemany(
                "INSERT OR IGNORE INTO flow_rollup_trunc(tier, exporter, iface,"
                " dir, dim, bucket) VALUES (?, ?, ?, ?, ?, ?)",
                [(tier, *scope, dim, start + n * tier)
                 for scope in scopes for n in range(0, bound * 2, 2)])
            db._conn.commit()
        bucket = tier if tier == 3600 else 60
        plan = db._rollup_plan(start, end, "Conversation", filters, bucket)
        runs = [len(db._repair_ranges(tier, scope, dim, start, plan[2], bound))
                for scope in scopes] if plan else []
        check(plan is not None and runs == [bound] * len(scopes),
              f"{name}: {runs} non-adjacent runs, the scoped bound of {bound} "
              f"per scope")
        if limit is not None and hasattr(db._conn, "setlimit"):
            db._conn.setlimit(limit, 999)
        try:
            got, error = db.overview(start, end, "Conversation", filters,
                                     bucket), None
        except sqlite3.OperationalError as exc:
            got, error = None, exc
        want = raw(db, "overview", start, end, "Conversation", filters, bucket)
        check(error is None and got == want,
              f"{name}: overview answers under 999 variables and equals raw "
              f"({error})")
        db.close()


# ------------------------------------------------------------------------- 4

OLD_ROLLUP = """
CREATE TABLE flow_rollup (tier INTEGER NOT NULL, dim INTEGER NOT NULL,
    bucket INTEGER NOT NULL, key BLOB NOT NULL, bytes INTEGER NOT NULL,
    packets INTEGER NOT NULL, flows INTEGER NOT NULL,
    PRIMARY KEY (tier, dim, bucket, key)) WITHOUT ROWID;
CREATE INDEX ix_flow_rollup_bucket ON flow_rollup(tier, bucket);
CREATE TABLE flow_rollup_span (tier INTEGER NOT NULL, bucket INTEGER NOT NULL,
    bytes INTEGER NOT NULL, packets INTEGER NOT NULL, flows INTEGER NOT NULL,
    PRIMARY KEY (tier, bucket)) WITHOUT ROWID;
CREATE TABLE flow_rollup_trunc (tier INTEGER NOT NULL, dim INTEGER NOT NULL,
    bucket INTEGER NOT NULL, PRIMARY KEY (tier, dim, bucket)) WITHOUT ROWID;
"""


class captured_log:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.logger = logging.getLogger("netpath.flowdb")
        self.handler = logging.Handler()
        self.handler.emit = lambda record: self.lines.append(record.getMessage())
        self.logger.addHandler(self.handler)
        self.level = self.logger.level
        self.logger.setLevel(logging.INFO)

    def detach(self) -> None:
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.level)


def test_4_migration_of_an_unscoped_store() -> None:
    print("4: an unscoped store is rebuilt in place, global answers unchanged")
    reference = store("migrate_ref.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3 * 3600
    flows = [flow(i, start + i * 7.0) for i in range(1500)]
    reference.insert_flows(flows)
    cover(reference)

    path = os.path.join(TMPDIR, "migrate_old.db")
    old = sqlite3.connect(path)
    old.executescript(flowdb.SCHEMA.replace(flowdb.ROLLUP_SCHEMA, "")
                      + OLD_ROLLUP)
    raw_rows = [tuple(row) for row in reference._conn.execute(
        "SELECT * FROM flows ORDER BY id")]
    old.executemany(f"INSERT INTO flows VALUES ({','.join('?' * len(raw_rows[0]))})",
                    raw_rows)
    glob = flowdb._GLOBAL_SQL
    for table, columns in (("flow_rollup", "tier, dim, bucket, key, bytes,"
                            " packets, flows"),
                           ("flow_rollup_span", "tier, bucket, bytes, packets,"
                            " flows"),
                           ("flow_rollup_trunc", "tier, dim, bucket")):
        rows = reference._conn.execute(
            f"SELECT {columns} FROM {table} WHERE {glob}").fetchall()
        old.executemany(f"INSERT INTO {table}({columns}) VALUES"
                        f" ({','.join('?' * (columns.count(',') + 1))})",
                        [tuple(row) for row in rows])
    for key in (flowdb._FLOOR, flowdb._WATERMARK):
        for tier in flowdb.ROLLUP_TIERS:
            old.execute("INSERT INTO settings(key, value) VALUES (?, ?)",
                        (key % tier, str(reference._private_setting(key % tier))))
    old.commit()
    old.close()

    log = captured_log()
    try:
        db = FlowDatabase(path)
    finally:
        log.detach()
    columns = {row[1] for row in db._conn.execute("PRAGMA table_info(flow_rollup)")}
    leftovers = [row[0] for row in db._conn.execute(
        "SELECT name FROM sqlite_master WHERE name LIKE '%\\_old' ESCAPE '\\'")]
    check({"exporter", "iface", "dir"} <= columns and not leftovers,
          f"the tables carry the scope columns and no *_old table is left "
          f"({leftovers})")
    indexes = {row[0] for row in db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index'"
        " AND tbl_name LIKE 'flow_rollup%'")}
    check({"ix_flow_rollup_bucket", "ix_flow_rollup_span_bucket",
           "ix_flow_rollup_trunc_bucket"} <= indexes,
          f"with every retention index on the new tables ({sorted(indexes)})")
    check(sum("rebuilt with a scope column" in line for line in log.lines) == 1,
          f"one log line says so ({log.lines})")
    for tier in flowdb.ROLLUP_TIERS:
        check(db._private_setting(flowdb._BREAKDOWN_FLOOR % tier)
              == reference.rollup_bounds(tier)[1]
              and db._private_setting(flowdb._SCOPED_FLOOR % tier)
              == reference.rollup_bounds(tier)[0],
              f"tier {tier}: the old watermark is the breakdown floor, the "
              f"scoped floor the tier's own")
    check(db._private_setting(flowdb._IFACE_BREAKDOWN_FLOOR)
          == reference.rollup_bounds(3600)[1]
          and db._private_setting(flowdb._IFACE_FLOOR)
          == reference.rollup_bounds(3600)[0],
          "and so are the interface floors")

    mismatched = [f"{dimension} at {bucket}s" for dimension in DIMENSIONS
                  for bucket in BUCKETS
                  if db.overview(start, end, dimension, NO_FILTERS, bucket)
                  != reference.overview(start, end, dimension, NO_FILTERS,
                                        bucket)]
    check(not mismatched,
          f"every global answer is what the unmigrated rows gave "
          f"({mismatched[:3]})")
    check(db._rollup_plan(start, end, "Source", NO_FILTERS, 60) is not None,
          "...and still comes from the summaries")
    info: dict = {}
    got = db.overview(start, end, "Source", scoped(), 300, info=info)
    check(info["records_only"] and got == raw(db, "overview", start, end,
                                             "Source", scoped(), 300),
          "an exporter filter below the breakdown floor reads raw while raw "
          "reaches t0, and says so")
    before = [tuple(row) for row in db._conn.execute(
        "SELECT * FROM flow_rollup ORDER BY 1, 2, 3, 4, 5, 6, 7")]
    db.close()

    log = captured_log()
    try:
        again = FlowDatabase(path)
    finally:
        log.detach()
    after = [tuple(row) for row in again._conn.execute(
        "SELECT * FROM flow_rollup ORDER BY 1, 2, 3, 4, 5, 6, 7")]
    check(not log.lines and before == after,
          "re-opening is a no-op: nothing logged, nothing changed")

    # A rebuild interrupted between copy and drop: *_old found at open.
    with again._lock:
        again._conn.executescript(
            "CREATE TABLE flow_rollup_span_old (tier INTEGER, bucket INTEGER,"
            " bytes INTEGER, packets INTEGER, flows INTEGER);"
            f"INSERT INTO flow_rollup_span_old VALUES (60, {start - 60}, 1, 1, 1);")
    again.close()
    resumed = FlowDatabase(path)
    check(count(resumed, "SELECT COUNT(*) FROM flow_rollup_span WHERE bucket = ?"
                         f" AND {glob}", (start - 60,)) == 1
          and count(resumed, "SELECT COUNT(*) FROM sqlite_master"
                             " WHERE name = 'flow_rollup_span_old'") == 0,
          "a *_old table found at open is copied in and dropped")
    resumed.close()
    reference.close()


# ------------------------------------------------------------------------- 5

def test_5_retention_and_trim_reach_scoped_rows() -> None:
    print("5: retention and the size cap reach every scope")
    db = store("retention.db")
    now = time.time()
    start = flowdb._align_down(now - 5 * 86400, 3600)
    db.insert_flows([flow(i, start + i * 300.0)
                     for i in range(int((now - 600 - start) / 300))])
    db.save_settings({"rollup_minute_days": 3})
    cover(db)
    check(count(db, "SELECT COUNT(*) FROM flow_rollup WHERE tier = 3600"
                    " AND iface >= 0 AND bucket < ?", (now - 3 * 86400,)) > 0
          and count(db, "SELECT COUNT(*) FROM flow_rollup WHERE tier = 60"
                        " AND exporter != '' AND bucket < ?",
                    (now - 2 * 86400,)) > 0,
          "scoped rows exist at both tiers past every cutoff below")

    db.prune(3650, 0, minute_days=2, rollup_days=4, interface_days=3,
             budget_s=60)
    minute_cut = flowdb._align_down(now - 2 * 86400, 60)
    hourly_cut = flowdb._align_down(now - 4 * 86400, 3600)
    iface_cut = flowdb._align_down(now - 3 * 86400, 3600)
    stale = {table: count(db, f"SELECT COUNT(*) FROM {table} WHERE"
                              f" (tier = 60 AND bucket < ?) OR"
                              f" (tier = 3600 AND bucket < ?) OR"
                              f" (tier = 3600 AND iface >= 0 AND bucket < ?)",
                          (minute_cut, hourly_cut, iface_cut))
             for table in ("flow_rollup", "flow_rollup_span", "flow_rollup_trunc")}
    check(not any(stale.values()),
          f"nothing of any scope is left past its retention ({stale})")
    kept = count(db, "SELECT COUNT(*) FROM flow_rollup WHERE tier = 3600"
                     " AND exporter != '' AND iface = -1 AND bucket < ?",
                 (iface_cut,))
    check(kept > 0, f"the exporter scope outlives the interface one ({kept} "
                    f"hourly rows between the two cutoffs)")
    check(db._private_setting(flowdb._IFACE_FLOOR) >= iface_cut
          and db._private_setting(flowdb._SCOPED_FLOOR % 60) >= minute_cut
          and db._private_setting(flowdb._SCOPED_FLOOR % 3600) >= hourly_cut,
          "and every floor moved up with what went")
    t0 = flowdb._align_down(now - 3.5 * 86400, 3600)
    check(db._rollup_plan(t0, now, "Source", INTERFACE_FILTERS["in"], 3600)
          is None and db._rollup_plan(t0, now, "Source", scoped(), 3600)
          is not None,
          "so a window past the interface retention is not claimed by it, "
          "while the exporter scope still answers it")

    floors = {tier: db.rollup_bounds(tier)[0] for tier in flowdb.ROLLUP_TIERS}
    db._trim_more(1, budget_s=60)
    for tier in flowdb.ROLLUP_TIERS:
        floor = db.rollup_bounds(tier)[0]
        below = count(db, "SELECT COUNT(*) FROM flow_rollup_span WHERE tier = ?"
                          " AND exporter != '' AND bucket < ?", (tier, floor))
        check(floor > floors[tier] and below == 0
              and db._private_setting(flowdb._SCOPED_FLOOR % tier) >= floor,
              f"tier {tier}: the size cap's second stage took scoped rows "
              f"with the global ones and raised the scoped floor with the "
              f"floor ({below} left below it)")
    db.close()


# ------------------------------------------------------------------------- 6

def test_6_hourly_from_minutes_equals_hourly_from_raw() -> None:
    print("6: hourly exporter rows built from minute rows equal ones built "
          "from raw")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 3 * 3600
    rows = [flow(i, start + i * 7.0) for i in range(1500)]
    both = store("hourly_minutes.db")
    both.insert_flows(rows)
    cover(both)
    hourly = store("hourly_raw.db")
    hourly.insert_flows(rows)
    cover(hourly, minutes=False)
    check(both._from_minute_tier(3600, start)
          and not hourly._from_minute_tier(3600, start),
          "one store built its hours from minutes, the other from raw")

    def contents(db, table, columns):
        return [tuple(row) for row in db._conn.execute(
            f"SELECT {columns} FROM {table} WHERE tier = 3600"
            f" AND exporter != '' AND bucket >= ? AND bucket < ?"
            f" ORDER BY {columns}", (start, end))]

    for table, columns in (("flow_rollup", "exporter, iface, dir, dim, bucket,"
                            " key, bytes, packets, flows"),
                           ("flow_rollup_span", "exporter, iface, dir, bucket,"
                            " bytes, packets, flows"),
                           ("flow_rollup_trunc", "exporter, iface, dir, dim,"
                            " bucket")):
        a, b = contents(both, table, columns), contents(hourly, table, columns)
        check(a == b and (a or table == "flow_rollup_trunc"),
              f"{table}: {len(a)} scoped hourly rows identical either way")
    both.close()
    hourly.close()


# ------------------------------------------------------------------------- 7

def test_7_interface_buckets_widen_to_the_hour() -> None:
    print("7: an interface filter widens 60/300/900 buckets to 3600 once only "
          "the hourly summaries reach t0")
    db = store("widen.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 6 * 3600
    db.insert_flows([flow(i, start + i * 10.0) for i in range(6 * 360)])
    cover(db)
    filters = INTERFACE_FILTERS["both"]
    unwidened = {bucket: db._agg_rows(start, end, None, filters, bucket)[1]
                 for bucket in (60, 300, 900)}
    check(unwidened == {60: 60, 300: 300, 900: 900},
          f"while raw reaches t0 the bucket asked for is kept ({unwidened})")
    before = db.overview(start, end, "Application", filters, 3600)

    with db._lock:
        db._conn.execute("DELETE FROM flows WHERE ts_end < ?", (end - 3600,))
        db._conn.commit()
    for bucket in (60, 300, 900):
        info: dict = {}
        got = db.overview(start, end, "Application", filters, bucket, info=info)
        check(got[2] == 3600 and info["widened"] and info["tier"] == 3600
              and not info["records_only"] and got == before,
              f"{bucket}s widens to the hourly tier and draws the same hours "
              f"the summaries always held ({info})")
    info = {}
    db.overview(start, end, "Application", filters, 10, info=info)
    check(info["records_only"] and not info["widened"],
          f"a 10-second bucket stays on the records ({info})")
    db.close()


# ------------------------------------------------------------------------- 8

def test_8_row_cap_holds_back_at_the_hourly_watermark() -> None:
    print("8: the row cap keeps rows the hourly tier has not built yet")
    db = store("holdback.db")
    now = time.time()
    rows = [flow(i, now - 3 * 3600 + i * 20.0) for i in range(3 * 180 - 10)]
    db.insert_flows(rows)
    minute_mark = flowdb._align_down(now - 180, 60)
    hourly_mark = flowdb._align_down(now - 2 * 3600, 3600)
    for tier, mark in ((60, minute_mark), (3600, hourly_mark)):
        db._set_private_setting(flowdb._FLOOR % tier,
                                flowdb._align_down(now - 3 * 3600, tier))
        db._set_private_setting(flowdb._WATERMARK % tier, mark)
    protected = sum(1 for r in rows if r.ts_end >= hourly_mark)
    db.prune(3650, 40, minute_days=3650, rollup_days=3650, interface_days=3650,
             budget_s=30)
    left = count(db, "SELECT COUNT(*) FROM flows")
    kept = count(db, "SELECT COUNT(*) FROM flows WHERE ts_end >= ?",
                 (hourly_mark,))
    check(kept == protected and db.cap_held_back > 0
          and left == 40 + db.cap_held_back,
          f"every row from the hourly watermark on survives, not just the "
          f"minute one's ({kept} of {protected}; {left} left = 40 + "
          f"{db.cap_held_back} held back)")
    ceiling = count(db, "SELECT MIN(id) FROM flows WHERE ts_end >= ?",
                    (hourly_mark,))
    check(db._trim_id_ceiling(ceiling + 1) == ceiling,
          "the size cap's ceiling is the same hourly watermark")
    db.close()


# ------------------------------------------------------------------------- 9

def test_9_oldest_ts_stays_a_probe() -> None:
    print("9: OLDEST_TS_SQL never scans a rollup table")
    db = store("oldest.db")
    end = flowdb._align_down(time.time() - 300, 3600)
    db.insert_flows([flow(i, end - 3 * 3600 + i * 7.0) for i in range(1500)])
    cover(db)
    plan = [" ".join(str(c) for c in row) for row in db._conn.execute(
        "EXPLAIN QUERY PLAN " + FlowDatabase.OLDEST_TS_SQL)]
    check(not any("SCAN flow_rollup" in line for line in plan)
          and sum("SEARCH flow_rollup_span USING PRIMARY KEY" in line
                  for line in plan) == len(flowdb.ROLLUP_TIERS),
          f"one primary-key probe per tier ({plan})")
    check(db.oldest_ts() is not None
          and db.oldest_ts() <= db.rollup_bounds(3600)[0] + 3600,
          "and it still answers with the summaries' reach")
    db.close()


# ------------------------------------------------------------------------ 10

def test_10_totals_reads() -> None:
    print("10: exporter_totals, interface_totals and coverage")
    db = store("totals.db")
    now = time.time()
    start = flowdb._align_down(now - 4 * 3600, 3600)
    db.insert_flows([flow(i, start + i * 5.0)
                     for i in range(int((now - start) / 5.0))])
    cover(db)

    def want_exporters(t0, t1):
        return {row[0]: {"bytes": row[1], "packets": row[2], "flows": row[3]}
                for row in db._conn.execute(
                    "SELECT exporter, SUM(bytes * sampling),"
                    " SUM(packets * sampling), COUNT(*) FROM flows"
                    " WHERE ts_end >= ? AND ts_end <= ? GROUP BY exporter",
                    (t0, t1))}

    def want_interfaces(t0, t1, exporter=None):
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
                         (t0, t1, exporter, exporter))]
        return sorted(rows, key=lambda r: (r["exporter"], r["iface"], r["dir"]))

    windows = (("last 5 minutes", now - 300, now),
               ("2.5 hours, unaligned", now - 2.5 * 3600 - 17, now - 40),
               ("3 whole hours", start + 3600, start + 4 * 3600))
    for name, t0, t1 in windows:
        tiers = (db._span_plan(t0, t1, "exporter")[0],
                 db._span_plan(t0, t1, "interface")[0])
        check(db.exporter_totals(t0, t1) == want_exporters(t0, t1),
              f"{name}: exporter_totals equals raw (tier {tiers[0]})")
        check(db.interface_totals(t0, t1) == want_interfaces(t0, t1)
              and db.interface_totals(t0, t1, EXPORTER)
              == want_interfaces(t0, t1, EXPORTER),
              f"{name}: interface_totals equals raw, all exporters and one "
              f"(tier {tiers[1]})")
    check(db._span_plan(now - 300, now, "exporter")[0] == 60
          and db._span_plan(start + 3600, start + 4 * 3600, "interface")[0]
          == 60,
          "the finest tier reaching t0 serves the spans")
    cov = db.coverage()
    check(cov["scoped_minute_floor"] == db.rollup_bounds(60)[0]
          and cov["scoped_hourly_floor"] == db.rollup_bounds(3600)[0]
          and cov["iface_hourly_floor"] == db.rollup_bounds(3600)[0],
          f"coverage() reports the scoped floors, level with a fresh store's "
          f"floors ({cov})")
    db._set_private_setting(flowdb._SCOPED_FLOOR % 60, start + 2 * 3600)
    t0, t1 = start + 3600, now - 40
    check(db._span_plan(t0, t1, "exporter")[0] == 3600
          and db._span_plan(t0, t1, "interface")[0] == 3600
          and db.exporter_totals(t0, t1) == want_exporters(t0, t1)
          and db.interface_totals(t0, t1) == want_interfaces(t0, t1),
          "and with the minute scope short of t0 the hourly tier answers, "
          "still equal to raw")
    check(db.coverage()["scoped_minute_floor"] == start + 2 * 3600,
          "and coverage() follows the scoped floor, not the tier's")
    db.close()


# ------------------------------------------------------------------------ 11

V6 = "2001:db8::1"
# Global interface keys and how each splits; None never does.
SPLITS = {7: {f"{EXPORTER}:1": (EXPORTER, 1), f"{EXPORTER}:2": (EXPORTER, 2),
              f"{V6}:3": (V6, 3), "junk": None, f"{EXPORTER}:x": None},
          8: {f"{EXPORTER}:2": (EXPORTER, 2), f"{V6}:1": (V6, 1),
              f"{V6}:-1": None}}
FLOORS = {60: 2 * 3600, 3600: 6 * 3600}   # each tier's floor below `hour`


def seed_global(conn, hour: int) -> dict:
    """Global rows only, for every bucket from each tier's floor up to `hour`.
    Returns the scoped spans they imply, {(tier, exporter, iface, dir,
    bucket): (bytes, packets, flows)}."""
    rows, spans, want = [], [], {}
    for tier, depth in FLOORS.items():
        for bucket in range(hour - depth, hour, tier):
            n = (bucket // tier) % 7
            for i, exporter in enumerate((EXPORTER, V6)):
                sums = (1000 * (i + 1) + n, 10 * (i + 1), i + 1)
                rows.append((tier, flowdb.DIMENSION_IDS["Exporter"], bucket,
                             exporter, *sums))
                want[(tier, exporter, -1, "", bucket)] = sums
            for dim, side in ((7, "in"), (8, "out")):
                for i, (key, split) in enumerate(SPLITS[dim].items()):
                    sums = (100 * (i + 1) + n, i + 1, 1)
                    rows.append((tier, dim, bucket, key, *sums))
                    if split:
                        want[(tier, *split, side, bucket)] = sums
            rows.append((tier, flowdb.DIMENSION_IDS["Application"], bucket, 443,
                         1500 + n, 30, 3))
            spans.append((tier, bucket, 3000 + 2 * n, 30, 3))
    conn.executemany("INSERT INTO flow_rollup(tier, dim, bucket, key, bytes,"
                     " packets, flows) VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    conn.executemany("INSERT INTO flow_rollup_span(tier, bucket, bytes, packets,"
                     " flows) VALUES (?, ?, ?, ?, ?)", spans)
    conn.commit()
    return want


def scoped_spans(db: FlowDatabase) -> dict:
    return {tuple(row[:5]): tuple(row[5:]) for row in db._conn.execute(
        "SELECT tier, exporter, iface, dir, bucket, bytes, packets, flows"
        " FROM flow_rollup_span WHERE exporter != ''")}


def summed(want: dict, tier: int, exporter: str, iface: int = -1,
           sides=("",), low: int = 0, upper: int = 2 ** 62) -> dict:
    rows = [sums for (t, e, i, d, b), sums in want.items()
            if (t, e, i) == (tier, exporter, iface) and d in sides
            and low <= b < upper]
    return {name: sum(row[k] for row in rows)
            for k, name in enumerate(("bytes", "packets", "flows"))}


def opened(path: str) -> tuple[FlowDatabase, list[str]]:
    log = captured_log()
    try:
        return FlowDatabase(path), log.lines
    finally:
        log.detach()


def test_11_upgraded_history_gets_scoped_totals() -> None:
    print("11: an upgraded store's exporters and interfaces get their totals "
          "for the history before their summaries")
    hour = flowdb._align_down(time.time() - 300, 3600)
    floors = {tier: hour - depth for tier, depth in FLOORS.items()}
    path = os.path.join(TMPDIR, "reconstruct_old.db")
    old = sqlite3.connect(path)
    old.executescript(flowdb.SCHEMA.replace(flowdb.ROLLUP_SCHEMA, "")
                      + OLD_ROLLUP)
    want = seed_global(old, hour)
    for tier in flowdb.ROLLUP_TIERS:
        for key, value in ((flowdb._FLOOR, floors[tier]),
                           (flowdb._WATERMARK, hour)):
            old.execute("INSERT INTO settings(key, value) VALUES (?, ?)",
                        (key % tier, str(value)))
    old.commit()
    old.close()

    db, lines = opened(path)
    got = scoped_spans(db)
    check(got == want,
          f"every pre-upgrade bucket has its exporter and interface span rows "
          f"at both tiers, summing as the global rows; IPv6 keys split on the "
          f"last ':', malformed ones skipped ({len(got)} of {len(want)})")
    exporters = sum(1 for key in want if key[2] == -1)
    rebuilt = [line for line in lines if "totals rebuilt" in line]
    check(len(rebuilt) == 1 and f"{exporters} exporter row(s), "
          f"{len(want) - exporters} interface row(s)" in rebuilt[0],
          f"one log line counts them ({rebuilt})")
    cov = db.coverage()
    check(cov["breakdown_minute_floor"] == hour
          and cov["breakdown_hourly_floor"] == hour
          and cov["iface_breakdown_floor"] == hour
          and cov["scoped_minute_floor"] == floors[60]
          and cov["scoped_hourly_floor"] == floors[3600]
          and cov["iface_hourly_floor"] == floors[3600],
          f"coverage() keeps the old watermark as the breakdown floors, the "
          f"scoped floors now the global ones ({cov})")

    for tier in flowdb.ROLLUP_TIERS:
        for exporter in (EXPORTER, V6):
            info: dict = {}
            _t, series, _b, _top, totals = db.overview(
                floors[tier], hour, "Application",
                {**NO_FILTERS, "exporter": exporter}, tier, info=info)
            check(not info["records_only"] and info["tier"] == tier
                  and info["summaries_from"] == floors[tier]
                  and info["breakdown_from"] == hour
                  and totals == summed(want, tier, exporter)
                  and set(series) == {"— other —"}
                  and sum(series["— other —"]) == totals["bytes"],
                  f"{exporter}, tier {tier}: summary-served, totals are its "
                  f"global Exporter rows, all of it '— other —', breakdown "
                  f"from the old watermark ({info})")
    for filters, sides in (
            ({**NO_FILTERS, "exporter": EXPORTER, "iface": 2,
              "direction": "both"}, ("in", "out")),
            ({**NO_FILTERS, "exporter": V6, "iface": 3, "direction": "in"},
             ("in",))):
        info = {}
        _t, series, _b, _top, totals = db.overview(
            floors[3600], hour, "Application", filters, 3600, info=info)
        check(not info["records_only"] and info["tier"] == 3600
              and info["breakdown_from"] == hour
              and totals == summed(want, 3600, filters["exporter"],
                                   filters["iface"], sides)
              and set(series) == {"— other —"},
              f"interface {filters['exporter']}:{filters['iface']} "
              f"{filters['direction']}: likewise, from the global interface "
              f"rows ({info})")
    info = {}
    db.overview(floors[3600], hour, "Application", NO_FILTERS, 3600, info=info)
    check(not info["records_only"] and info["breakdown_from"] is None,
          f"the global scope has no breakdown floor ({info})")
    rows = db.interface_totals(floors[3600], hour)
    check(db.exporter_totals(floors[3600], hour)
          == {e: summed(want, 3600, e) for e in (EXPORTER, V6)}
          and {(r["exporter"], r["iface"], r["dir"]) for r in rows}
          == {key[1:4] for key in want if key[0] == 3600 and key[2] >= 0}
          and all({k: r[k] for k in ("bytes", "packets", "flows")}
                  == summed(want, 3600, r["exporter"], r["iface"], (r["dir"],))
                  for r in rows),
          "exporter_totals and interface_totals read the same totals")

    tables = ("flow_rollup", "flow_rollup_span", "settings")
    before = {table: count(db, f"SELECT COUNT(*) FROM {table}")
              for table in tables}
    db.close()
    db, lines = opened(path)
    check(not lines and db._private_setting(flowdb._RECONSTRUCTED) is True
          and {table: count(db, f"SELECT COUNT(*) FROM {table}")
               for table in tables} == before,
          "a second open is a no-op: the setting is present, nothing logged "
          "or added")

    exporter = {**NO_FILTERS, "exporter": EXPORTER}
    # Raw holds the last hour at the density the spans counted (3 an hour),
    # then one flush from a clock six hours behind.
    db.insert_flows([flow(i, hour - 3600 + i * 1200, exporter=EXPORTER)
                     for i in range(3)])
    db.insert_flows([flow(3, floors[3600], exporter=EXPORTER)])
    for tier in flowdb.ROLLUP_TIERS:
        info = {}
        totals = db.overview(floors[tier], hour, "Application", exporter,
                             tier, info=info)[4]
        check(not info["records_only"] and info["tier"] == tier
              and totals == summed(want, tier, EXPORTER),
              f"tier {tier}: one stray flow six hours behind leaves the "
              f"pre-upgrade window summary-served ({info})")
    info = {}
    got = db.overview(floors[3600], hour, "Application",
                      {**exporter, "iface": 2, "direction": "both"}, 300,
                      info=info)
    check(got[2] == 3600 and info["widened"] and not info["records_only"]
          and info["tier"] == 3600
          and got[4] == summed(want, 3600, EXPORTER, 2, ("in", "out")),
          f"and an interface-filtered 300s window still widens to the hour "
          f"and stays summary-served ({info})")
    db.insert_flows([flow(i, floors[3600] - 3000 + i * 300, exporter=EXPORTER)
                     for i in range(84)])
    info = {}
    got = db.overview(floors[3600], hour, "Application", exporter, 3600,
                      info=info)
    check(info["records_only"] and len(got[1]) > 1
          and got == raw(db, "overview", floors[3600], hour, "Application",
                         exporter, 3600),
          f"with raw holding every flow the pre-upgrade spans counted, raw "
          f"draws the breakdown as it did before ({info})")
    for tier in flowdb.ROLLUP_TIERS:
        db.backfill_rollup(tier, max_buckets=1)
        floor = db.rollup_bounds(tier)[0]
        check(floor == floors[tier] - tier
              and db._private_setting(flowdb._SCOPED_FLOOR % tier) == floor,
              f"tier {tier}: backfill lowers the scoped floor with the floor")
    check(db._private_setting(flowdb._IFACE_FLOOR) == floors[3600] - 3600,
          "and the interface floor with the hourly one")
    db.close()

    db = store("reconstruct_5670.db")
    want = seed_global(db._conn, hour)
    for tier in flowdb.ROLLUP_TIERS:
        for key, value in ((flowdb._FLOOR, floors[tier]),
                           (flowdb._WATERMARK, hour),
                           (flowdb._SCOPED_FLOOR, hour)):
            db._set_private_setting(key % tier, value)
    db._set_private_setting(flowdb._IFACE_FLOOR, hour)
    redo = hour - 3600
    stored = (3600, EXPORTER, -1, "", flowdb.DIMENSION_IDS["Application"],
              redo, 443, 700, 7, 1)
    db._conn.execute("INSERT INTO flow_rollup VALUES (?, ?, ?, ?, ?, ?, ?, ?,"
                     " ?, ?)", stored)
    db._conn.commit()
    db._clear_private_setting(flowdb._RECONSTRUCTED)
    path = db.path
    db.close()
    db, lines = opened(path)
    cov = db.coverage()
    check(scoped_spans(db) == want and len(lines) == 1
          and cov["breakdown_hourly_floor"] == hour
          and cov["scoped_hourly_floor"] == floors[3600],
          "a store already on the scoped layout without the setting is "
          "reconstructed at its next open too")
    db._compact_bucket(3600, redo)
    kept = [tuple(row) for row in db._conn.execute(
        "SELECT * FROM flow_rollup WHERE tier = 3600 AND exporter != ''"
        " AND bucket = ?", (redo,))]
    span = db._conn.execute(
        "SELECT bytes, packets, flows FROM flow_rollup_span WHERE tier = 3600"
        " AND exporter = ? AND iface = -1 AND bucket = ?",
        (EXPORTER, redo)).fetchone()
    minutes = summed(want, 60, EXPORTER, low=redo, upper=redo + 3600)
    check(kept == [stored] and tuple(span) == tuple(minutes.values()),
          f"a redo of a pre-upgrade hour raw no longer holds keeps its exporter "
          f"keys as built rather than emptying them, and sums its span from "
          f"the minutes ({kept})")
    db.close()


# ------------------------------------------------------------------------ 12

COUNTED = {"global rows": f"flow_rollup WHERE {flowdb._GLOBAL_SQL}",
           "global spans": f"flow_rollup_span WHERE {flowdb._GLOBAL_SQL}",
           "exporter spans": "flow_rollup_span WHERE exporter != ''"
                             " AND iface = -1"}


def built(db: FlowDatabase, tier: int, below: int) -> tuple[dict, list]:
    """({what: rows}, every row, span and flag) of a tier below `below`."""
    counts = {name: count(db, f"SELECT COUNT(*) FROM {sql} AND tier = ?"
                          f" AND bucket < ?", (tier, below))
              for name, sql in COUNTED.items()}
    rows = [sorted(tuple(row) for row in db._conn.execute(
        f"SELECT * FROM {table} WHERE tier = ? AND bucket < ?", (tier, below)))
        for table in ("flow_rollup", "flow_rollup_span", "flow_rollup_trunc")]
    return counts, rows


def span(db: FlowDatabase, tier: int, exporter: str, ts: float) -> tuple:
    row = db._conn.execute(
        "SELECT bytes, packets, flows FROM flow_rollup_span WHERE tier = ?"
        " AND exporter = ? AND iface = -1 AND dir = '' AND bucket = ?",
        (tier, exporter, flowdb._align_down(ts, tier))).fetchone()
    return (0, 0, 0) if row is None else tuple(row)


def test_12_redo_keeps_what_raw_no_longer_holds() -> None:
    print("12: a flush from a lagging clock leaves the summaries raw no longer "
          "holds as built")
    end = flowdb._align_down(time.time() - 300, 3600)
    start = end - 6 * 3600
    kept = end - 3600
    for name, minutes in (("minute tier built", True),
                          ("hourly tier from raw", False)):
        db = store(f"redo_{int(minutes)}.db")
        db.insert_flows([flow(i, start + i * 10.0) for i in range(6 * 360)])
        cover(db, minutes=minutes)
        with db._lock:
            db._conn.execute("DELETE FROM flows WHERE ts_end < ?", (kept,))
            db._conn.commit()
        tiers = flowdb.ROLLUP_TIERS if minutes else (3600,)
        before = {tier: built(db, tier, kept) for tier in tiers}
        db.insert_flows([flow(0, time.time() - 6 * 3600, exporter=EXPORTER)])
        for tier in tiers:
            db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
            after = built(db, tier, kept)
            check(after == before[tier] and before[tier][0]["global spans"]
                  and db._private_setting(flowdb._DIRTY % tier) is None,
                  f"{name}, tier {tier}: the redo walked the old hours and "
                  f"kept them as built ({before[tier][0]} -> {after[0]})")

        late = kept + 1805
        added = flow(1, late, exporter=EXPORTER)
        grew = (added.bytes * added.sampling, added.packets * added.sampling, 1)
        was = {(tier, scope): span(db, tier, scope, late)
               for tier in tiers for scope in ("", EXPORTER)}
        db.insert_flows([added])
        for tier in tiers:
            db.compact_rollup(tier, max_buckets=10_000, budget_s=120)
        now = {key: span(db, *key, late) for key in was}
        check(all(now[key] == tuple(a + b for a, b in zip(was[key], grew))
                  and was[key][2] for key in was),
              f"{name}: a late flow into a bucket raw still holds is folded "
              f"into its global and exporter spans ({was} -> {now})")
        db.close()


TESTS = [
    test_1_scopes_agree_with_raw,
    test_2_caps_flags_and_repair,
    test_3_scoped_repair_fits_999_variables,
    test_4_migration_of_an_unscoped_store,
    test_5_retention_and_trim_reach_scoped_rows,
    test_6_hourly_from_minutes_equals_hourly_from_raw,
    test_7_interface_buckets_widen_to_the_hour,
    test_8_row_cap_holds_back_at_the_hourly_watermark,
    test_9_oldest_ts_stays_a_probe,
    test_10_totals_reads,
    test_11_upgraded_history_gets_scoped_totals,
    test_12_redo_keeps_what_raw_no_longer_holds,
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
    print("ALL NETFLOW SCOPED ASSERTIONS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
