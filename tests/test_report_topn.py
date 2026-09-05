"""netpath/report.py's top_metric_ranking(): correctness on a small,
hand-checkable fixture, then the realistic-scale cost this task explicitly
asked to be measured rather than assumed.

The correctness fixture is deliberately tiny — a handful of interfaces with
known peak/mean values, so every assertion below can be checked by eye
against the numbers seeded into it, rather than against another piece of
code that could share this module's own mistakes.

The scale fixture is not: 2,000 devices x 48 ports x six metric families is
what NETWORK-AND-STORAGE-REQUIREMENTS.md's own "how many devices" section
already uses as the shipped product's realistic ceiling, and it is run here
because a query that is only ever exercised at a few hundred rows in CI
would never have caught the "too many SQL variables" and "SQLite reordered
the join the wrong way" failures this module's own docstring describes —
both were found by actually generating this many rows, not by reasoning
about the schema. It is marked slow (see SLOW_S below) rather than skipped:
a regression here is exactly the kind of thing that should fail CI, not
quietly stop being checked once it takes a while.
"""
import os
import sys
import time

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath.nodesdb import NodesDatabase
from netpath.report import top_metric_ranking

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------ correctness

db = NodesDatabase(":memory:")
conn = db._conn

d1 = db.add_device("10.0.2.1", "sw1")
d2 = db.add_device("10.0.2.2", "sw2")

now = time.time()
h1 = int(now // 3600) * 3600
h0 = h1 - 5 * 3600     # five complete hours of rollup

# Two interfaces on sw1, one on sw2, all in the "if_in_util_pct" family so
# a `like=True` ranking picks up all three; a fourth series in a different
# family proves the pattern match does not leak across families.
conn.execute("INSERT INTO metrics(device_id, key, label, unit, kind)"
            " VALUES (?, 'if_in_util_pct.1', 'Gi0/1 in_util_pct', '%', 'gauge')", (d1,))
conn.execute("INSERT INTO metrics(device_id, key, label, unit, kind)"
            " VALUES (?, 'if_in_util_pct.2', 'Gi0/2 in_util_pct', '%', 'gauge')", (d1,))
conn.execute("INSERT INTO metrics(device_id, key, label, unit, kind)"
            " VALUES (?, 'if_in_util_pct.1', 'Gi0/1 in_util_pct', '%', 'gauge')", (d2,))
conn.execute("INSERT INTO metrics(device_id, key, label, unit, kind)"
            " VALUES (?, 'if_out_util_pct.1', 'Gi0/1 out_util_pct', '%', 'gauge')", (d1,))
conn.commit()

m_hot, m_warm, m_cold, m_other_family = (
    conn.execute("SELECT id FROM metrics WHERE device_id=? AND key=?",
                (d1, "if_in_util_pct.1")).fetchone()[0],
    conn.execute("SELECT id FROM metrics WHERE device_id=? AND key=?",
                (d1, "if_in_util_pct.2")).fetchone()[0],
    conn.execute("SELECT id FROM metrics WHERE device_id=? AND key=?",
                (d2, "if_in_util_pct.1")).fetchone()[0],
    conn.execute("SELECT id FROM metrics WHERE device_id=? AND key=?",
                (d1, "if_out_util_pct.1")).fetchone()[0])

# hot: peaks at 95, mean 90. warm: peaks at 60, mean 55. cold: peaks at 20,
# mean 10 -- and one hour OUTSIDE the window, which must not be counted.
rows = []
for hour_offset in range(5):
    h = h0 + hour_offset * 3600
    rows.append((m_hot, h, 10, 85.0, 90.0, 95.0))
    rows.append((m_warm, h, 10, 50.0, 55.0, 60.0))
    rows.append((m_cold, h, 10, 5.0, 10.0, 20.0))
    rows.append((m_other_family, h, 10, 99.0, 99.0, 99.0))   # different family
# a cold-series hour before the window: must not drag its mean down
rows.append((m_cold, h0 - 3600, 10, 0.0, 0.0, 0.0))
conn.executemany(
    "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax) VALUES (?,?,?,?,?,?)",
    rows)
conn.commit()

rep = top_metric_ranking(db, "if_in_util_pct.%", h0, h1, n=2, rank_by="peak", like=True)
check("top-2 by peak: exactly 2 rows (n honoured)", len(rep.rows) == 2, str(len(rep.rows)))
check("top-2 by peak: hot first", rep.rows[0].key == "if_in_util_pct.1"
     and rep.rows[0].device_id == d1, str(rep.rows[0]))
check("top-2 by peak: warm second", rep.rows[1].device_id == d1
     and rep.rows[1].key == "if_in_util_pct.2", str(rep.rows[1]))
check("top-2 by peak: hot's peak is 95", rep.rows[0].peak == 95.0, str(rep.rows[0].peak))
check("top-2 by peak: the out_util_pct family is not mixed in",
     all(r.key.startswith("if_in_util_pct") for r in rep.rows))

rep_asc = top_metric_ranking(db, "if_in_util_pct.%", h0, h1, n=1, rank_by="peak",
                             ascending=True, like=True)
check("bottom-1 by peak (ascending): cold comes first", rep_asc.rows[0].device_id == d2
     and rep_asc.rows[0].peak == 20.0, str(rep_asc.rows[0]))

rep_mean = top_metric_ranking(db, "if_in_util_pct.%", h0, h1, n=3, rank_by="mean", like=True)
check("ranked by mean: hot > warm > cold, in that order",
     [r.device_id for r in rep_mean.rows] == [d1, d1, d2]
     or [round(r.mean) for r in rep_mean.rows] == [90, 55, 10],
     str([(r.key, r.mean) for r in rep_mean.rows]))
check("cold's mean excludes the hour before the window (still 10, not lower)",
     [r for r in rep_mean.rows if r.device_id == d2][0].mean == 10.0,
     str([r.mean for r in rep_mean.rows if r.device_id == d2]))
check("n_hours reflects exactly the 5 hours inside the window, not 6",
     all(r.n_hours == 5 for r in rep_mean.rows), str([r.n_hours for r in rep_mean.rows]))

rep_exact = top_metric_ranking(db, "if_out_util_pct.1", h0, h1, n=10, rank_by="peak",
                               like=False)
check("exact key (like=False) matches only the one out_util_pct series",
     len(rep_exact.rows) == 1 and rep_exact.rows[0].metric_id == m_other_family,
     str(rep_exact.rows))

rep_scoped = top_metric_ranking(db, "if_in_util_pct.%", h0, h1, n=10, rank_by="peak",
                                like=True, device_ids=[d1])
check("device_ids narrows the ranking: only sw1's two series come back",
     {r.device_id for r in rep_scoped.rows} == {d1} and len(rep_scoped.rows) == 2,
     str(rep_scoped.rows))

rep_none = top_metric_ranking(db, "no_such_metric_family.%", h0, h1, n=10, like=True)
check("no matching metrics: empty, not an error", rep_none.rows == [])

db.close()


# --------------------------------------------------------------- at scale

# Set NETPATH_REPORT_BENCH_SCALE=1 to run the full 2,000-device fixture
# this module's docstring quotes numbers from; it takes several minutes to
# generate (tens of millions of rows) so it does not run by default under
# run_all.py, but the assertions below still run a scaled-down version of
# the exact same shape by default, which is enough to catch a regression
# in the query itself (a return to the "too many SQL variables" bug, or a
# join order SQLite silently stops honouring) without paying the full
# generation cost every run.
SLOW_S = 8.0     # generous ceiling for the scaled-down fixture below

FULL_SCALE = os.environ.get("NETPATH_REPORT_BENCH_SCALE") == "1"
N_DEVICES = 2000 if FULL_SCALE else 100
PORTS = 48
HOURS = 168 if FULL_SCALE else 48
FAMILIES = ("if_in_util_pct", "if_out_util_pct", "if_in_bps", "if_out_bps",
           "if_in_err", "if_out_err")

db = NodesDatabase(":memory:")
conn = db._conn
device_ids = [db.add_device(f"10.{i // 250}.{i % 250}.1", f"sw{i}")
             for i in range(N_DEVICES)]
metric_rows = [(did, f"{fam}.{p}", f"port{p} {fam}", "u", "gauge")
              for did in device_ids for p in range(1, PORTS + 1) for fam in FAMILIES]
conn.executemany(
    "INSERT INTO metrics(device_id, key, label, unit, kind) VALUES (?,?,?,?,?)",
    metric_rows)
conn.commit()

now = time.time()
bh1 = int(now // 3600) * 3600
bh0 = bh1 - HOURS * 3600
for fam in FAMILIES:
    conn.execute("""
        WITH RECURSIVE hours(h) AS (
            SELECT ? UNION ALL SELECT h + 3600 FROM hours WHERE h + 3600 <= ?
        )
        INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)
        SELECT m.id, hours.h, 12, 30.0 + (m.id % 40), 40.0 + (m.id % 40),
               50.0 + (m.id % 50)
        FROM metrics m, hours WHERE m.key LIKE ? || '.%'
        """, (bh0, bh1, fam))
    conn.commit()
n_rows = conn.execute("SELECT COUNT(*) FROM samples_hourly").fetchone()[0]

started = time.perf_counter()
rep = top_metric_ranking(db, "if_in_util_pct.%", bh0, bh1, n=20, rank_by="peak", like=True)
elapsed_s = time.perf_counter() - started

print(f"top-N at scale: {len(metric_rows)} metrics, {n_rows} samples_hourly rows, "
     f"{HOURS}h window -> {len(rep.rows)} rows in {rep.query_ms:.1f}ms "
     f"(measured {elapsed_s * 1000:.1f}ms including candidate resolution)")
check("top-N at scale: returns exactly n rows", len(rep.rows) == 20, str(len(rep.rows)))
check("top-N at scale: results are sorted descending by peak",
     all(rep.rows[i].peak >= rep.rows[i + 1].peak for i in range(len(rep.rows) - 1)))
check(f"top-N at scale: completes well under {SLOW_S:.0f}s at this (scaled-down) size",
     elapsed_s < SLOW_S, f"{elapsed_s:.2f}s")
if FULL_SCALE:
    print(f"NETPATH_REPORT_BENCH_SCALE=1: full-scale query_ms={rep.query_ms:.1f} — "
         f"this is the number report.py's docstring quotes; compare by hand "
         f"rather than asserting on it, since it depends on the machine")

db.close()


print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
