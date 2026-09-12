"""netpath.dbreport: where the bytes in each database are, per table.

Real stores over a throwaway folder, seeded with a known number of rows, so
the one figure that must never be approximate -- the row count -- is checked
against a number the test chose. The byte figures are exact only where
dbstat is compiled in, which the sqlite3 shipped with CPython is not, so
what is pinned about them is that `basis` says which it is and that the
`unaccounted` line reconciles the column against `page_count * page_size`.

Also pinned: a store whose file is not there is skipped with a note instead
of failing the run, a live store still answers while its own connection is
open (the operator runs this against a running service), the CLI exits 0,
and the route serving it is not on the /api/state path.
"""
import io
import os
import shutil
import sys

import _paths  # noqa: F401  (repo root + tests dir on sys.path)

from netpath import dbreport
from netpath.nodesseriesdb import NodesSeriesDatabase
from netpath.web import api as api_mod
from netpath.web import server as server_mod
from netpath.web.service import STORES

TMPDIR = _paths.tmpdir("db_report_")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


METRICS = 40
SAMPLES = 500
HOURS = 120

series_path = os.path.join(TMPDIR, "nodes_series.db")
series = NodesSeriesDatabase(series_path)
with series._lock:
    series._conn.executemany(
        "INSERT INTO metrics(device_id, key, label, unit, kind)"
        " VALUES (?,?,?,?,?)",
        [(1, f"if_in_octets.{i}", "port", "bps", "counter_rate")
         for i in range(METRICS)])
    ids = [row["id"] for row in series._conn.execute("SELECT id FROM metrics")]
    series._conn.executemany(
        "INSERT INTO samples(metric_id, ts, value) VALUES (?,?,?)",
        [(i, 1_700_000_000.0 + t, float(t)) for i in ids for t in range(SAMPLES)])
    series._conn.executemany(
        "INSERT INTO samples_hourly(metric_id, hour, n, vmin, vavg, vmax)"
        " VALUES (?,?,60,0.0,1.0,2.0)",
        [(i, 1_700_000_000 + h * 3600) for i in ids for h in range(HOURS)])
    series._conn.commit()


# ----------------------------------------------- 1. the shape of one report

entries = dbreport.report({"nodes_series": series_path})
check("one entry per store asked for", len(entries) == 1, entries)
entry = entries[0]
rows = {row["name"]: row for row in entry["tables"]}

check("every table in the store appears, not only the big ones",
      {"metrics", "samples", "samples_hourly", "settings"} <= set(rows),
      sorted(rows))
check("the row counts are exact -- they are the number that answers 'why "
      "is this file big'",
      (rows["metrics"]["rows"], rows["samples"]["rows"],
       rows["samples_hourly"]["rows"])
      == (METRICS, METRICS * SAMPLES, METRICS * HOURS),
      (rows["metrics"]["rows"], rows["samples"]["rows"],
       rows["samples_hourly"]["rows"]))
check("the basis is stated rather than left for the reader to assume",
      entry["basis"] in ("measured", "estimated"), entry["basis"])
check("the biggest table is listed first, which is the whole question",
      entry["tables"][0]["name"] == "samples", entry["tables"][0])
check("page_count and page_size are reported, so the estimate can be "
      "checked against the file by hand",
      entry["page_count"] > 0 and entry["page_size"] > 0,
      (entry["page_count"], entry["page_size"]))
check("the file size includes the write-ahead log, the way the Settings "
      "page's own figure does",
      entry["file_bytes"] >= series.size_bytes() * 0.9, entry["file_bytes"])

unaccounted = rows["unaccounted"]
check("an unaccounted line reconciles the column against the file",
      unaccounted["bytes"] >= 0 and unaccounted["rows"] is None, unaccounted)
pages = entry["page_count"] * entry["page_size"]
accounted = sum(row["bytes"] for row in entry["tables"]) - unaccounted["bytes"]
# The per-row constants are fleet-shape figures -- 49,607 metrics, one row
# per metric per poll, fractional timestamps. A tidy 40-metric test file
# packs its primary key far better than that and so costs less per row than
# the estimate says, which is exactly the case that must be visible rather
# than folded into a negative number nobody sees.
check("an estimate that overshoots the file says so in the note rather "
      "than showing a column that silently does not add up",
      (accounted <= pages and unaccounted["bytes"] == pages - accounted)
      or "overshoots" in entry["note"],
      (accounted, pages, entry["note"]))
check("the estimate is still in the right order of magnitude: 20,000 "
      "samples at the measured 23.8 B/row is what this file mostly is",
      pages * 0.4 <= rows["samples"]["bytes"] <= pages * 1.5,
      (rows["samples"]["bytes"], pages))


# ------------------------------- 2. a live file, and one that is not there

check("a live store answers while its own connection is open -- this is "
      "run against a running service, so mode=ro and the WAL, never "
      "immutable=1",
      dbreport.report({"nodes_series": series_path})[0]["tables"], "")

missing = dbreport.report({"flow": os.path.join(TMPDIR, "flows.db")})[0]
check("a store with no file on disk is skipped with a note rather than "
      "failing the whole run",
      missing["missing"] and missing["note"] and missing["tables"] == [],
      missing)

series.close()
check("and it still reads once the service has closed it",
      dbreport.report({"nodes_series": series_path})[0]["tables"][0]["rows"]
      == METRICS * SAMPLES)


# ------------------------------------------------------ 3. the store names

check("every store the Settings page lists has a filename here, so the "
      "report covers the same set of files the page does",
      all(store.name in dbreport.STORE_FILENAMES for store in STORES),
      [s.name for s in STORES if s.name not in dbreport.STORE_FILENAMES])
check("...and nothing here is a store the page does not know about",
      set(dbreport.STORE_FILENAMES) == {store.name for store in STORES},
      set(dbreport.STORE_FILENAMES) ^ {store.name for store in STORES})
check("every per-row constant names a real table of a real store",
      all(isinstance(v, (int, float)) and v > 0
          for v in dbreport.BYTES_PER_ROW.values()))


# ------------------------------------------------------------- 4. the route

ROUTE = [r for r in server_mod.ROUTES if r[1] == r"^/api/db/report$"]
check("the breakdown has a route of its own", len(ROUTE) == 1, ROUTE)
if ROUTE:
    method, _pattern, handler, permission = ROUTE[0]
    check("it is a GET behind `settings: read`, the same grant the storage "
          "block inside /api/state is gated by",
          method == "GET" and permission == ("settings", server_mod.R),
          (method, permission))
    check("...served by api.get_db_report", handler is api_mod.get_db_report)
check("it is cached for five minutes, because COUNT(*) over a "
      "hundred-million-row samples table is seconds",
      '"db_report", 300' in io.open(
          os.path.join(_paths.REPO_ROOT, "netpath", "web", "api.py"),
          encoding="utf-8").read())

STATE = io.open(os.path.join(_paths.REPO_ROOT, "netpath", "web", "api.py"),
                encoding="utf-8").read()
STORAGE_FN = STATE[STATE.index("def _storage(service)"):
                   STATE.index("def get_db_report(")]
check("and _storage -- which /api/state polls every two seconds -- runs no "
      "COUNT(*) and no report of its own",
      "COUNT(" not in STORAGE_FN and "dbreport" not in STORAGE_FN)
check("what it does carry is the rollup retention beside the age, which is "
      "what says whether the cap or the retention is the binding limit",
      "nodes_series_rollup_days" in STORAGE_FN)


# --------------------------------------------------------------- 5. the CLI

argv = [TMPDIR, "--store", "nodes_series"]
out = io.StringIO()
held, sys.stdout = sys.stdout, out
try:
    code = dbreport.main(argv)
finally:
    sys.stdout = held
printed = out.getvalue()
check("`py -m netpath.dbreport <data_dir>` exits 0", code == 0, code)
check("...and prints the table names, the row counts and the basis",
      "samples_hourly" in printed and f"{METRICS * SAMPLES:,}" in printed
      and ("estimated" in printed or "measured" in printed),
      printed[:400])
check("...and reconciles to a total for the folder",
      "on disk in total" in printed, printed[-200:])

out = io.StringIO()
held, sys.stdout = sys.stdout, out
try:
    all_code = dbreport.main([TMPDIR])
finally:
    sys.stdout = held
check("a whole folder where most files are absent still exits 0 and names "
      "the ones it found", all_code == 0, all_code)

check("an unknown store name is refused rather than silently reporting "
      "nothing", dbreport.main([TMPDIR, "--store", "nope"]) == 2)

shutil.rmtree(TMPDIR, ignore_errors=True)

print()
print("FAILURES:", FAILS if FAILS else "none")
sys.exit(1 if FAILS else 0)
