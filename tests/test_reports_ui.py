"""Static checks for the Nodes -> REPORTS subtab (nodes.js/index.html).

netpath/report.py's two routes — GET /api/nodes/reports/availability and
GET /api/nodes/reports/top-metrics — are covered end to end on the backend
by test_report_availability.py, test_report_topn.py and test_report_routes.py.
Nothing in the shipped JavaScript called either one until this screen: this
suite is the frontend half, in the same style as test_frontend_contracts.py
(it reads the shipped files as text and asserts what must be true of them,
rather than driving a browser — tests/ui/walk.mjs is where that lives).

Covers:
  - both report routes are actually called from nodes.js
  - the REPORTS subtab and its two nested reports (AVAILABILITY, TOP-N BY
    METRIC) exist, following the same subtab/subpage markup every other
    Nodes subtab uses
  - the screen is read-only end to end: no data-requires-write control
    anywhere in it, matching what a "nodes": read grant can already do
  - CSV export is client-built (report.py has no export.csv route of its
    own) but still goes out through App.saveCsv, the one function that
    hands a browser a file, rather than a second implementation of it
  - tables go through App.grid/App.sortRows/App.drawRows, not a fourth
    hand-rolled table renderer
  - a run button's own request runs inside the App.runJob promise, not
    before it — see nodes.js's own comment on this: a device-group lookup
    before that call would leave the button clickable long enough for a
    second click to abort the first request as "superseded" and report a
    failure that never happened
"""
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "netpath", "web", "static")

failures = []


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
        return handle.read()


def check(condition, message):
    if condition:
        print("OK   %s" % message)
    else:
        print("FAIL %s" % message)
        failures.append(message)


INDEX = read("index.html")
NODES = read("nodes.js")

# ---------------------------------------------------------------------------
# 1. Both report routes are actually called from the shipped JS. This is
#    the defect this whole screen exists to fix: two working, tested,
#    permission-gated routes with zero callers.
check("'/api/nodes/reports/availability'" in NODES,
      "nodes.js calls GET /api/nodes/reports/availability")
check("'/api/nodes/reports/top-metrics'" in NODES,
      "nodes.js calls GET /api/nodes/reports/top-metrics")

# ---------------------------------------------------------------------------
# 2. The REPORTS subtab exists on the Nodes page, alongside the other four,
#    and routes the same way they do (a plain button in the page's own
#    top-level .subtabs nav — app.js's wireSubtabRouting/applySubtabFromRoute
#    pick it up generically, with no code of their own to change).
NODES_SECTION = INDEX[INDEX.index('id="page-nodes"'):INDEX.index('id="page-alerts"')]
check('data-subtab="reports"' in NODES_SECTION and 'id="nodes-sub-reports"' in NODES_SECTION,
      "the REPORTS subtab and its subpage exist on the Nodes page")
TOP_NAV = NODES_SECTION[NODES_SECTION.index('<nav class="subtabs">'):
                         NODES_SECTION.index('</nav>')]
check(re.findall(r'data-subtab="(\w+)"', TOP_NAV)
      == ["devices", "topology", "discovery", "profiles", "reports"],
      "REPORTS is a fifth top-level Nodes subtab, after Profiles & MIBs, "
      "not a nested view mistaken for one")

# ---------------------------------------------------------------------------
# 3. Inside REPORTS, the two reports are nested subtabs following the same
#    pattern the device detail pane's own nested subtabs use (a second
#    <nav class="subtabs"> whose parent is NOT the page itself, so app.js's
#    generic top-level routing correctly leaves it alone and nodes.js wires
#    it by hand — see selectReportsSub).
REPORTS_SECTION = NODES_SECTION[NODES_SECTION.index('id="nodes-sub-reports"'):]
check('data-subtab="availability"' in REPORTS_SECTION
      and 'id="nd-rep-sub-availability"' in REPORTS_SECTION,
      "the Availability report subtab and its subpage exist")
check('data-subtab="topmetrics"' in REPORTS_SECTION
      and 'id="nd-rep-sub-topmetrics"' in REPORTS_SECTION,
      "the Top-N report subtab and its subpage exist")
check("function selectReportsSub(" in NODES,
      "nodes.js wires the nested reports subtabs by hand, like selectDetailSub")
check("recallSub('nodes.reports'" in NODES and "rememberSub('nodes.reports'" in NODES,
      "the chosen report subtab survives a reload, the same way every "
      "other Nodes sub-view does")

# ---------------------------------------------------------------------------
# 4. Both reports are read-only end to end — a "nodes": read (viewer)
#    account can use this screen in full, which is the point of a reporting
#    screen. Matched on the REPORTS subpage's own markup slice, the same
#    way test_frontend_contracts.py checks the Audit subpage.
check("data-requires-write" not in REPORTS_SECTION,
      "no control inside the REPORTS subtab writes anything")

# ---------------------------------------------------------------------------
# 5. The filter bar, tables and actions an operator needs exist: a period
#    (From/To, plus quick presets), a device-group filter, Run and Export
#    CSV for each report, and the Top-N-specific controls report.py's own
#    handler reads (key, like, rank_by, ascending, n).
for element_id in ["nd-rep-avail-t0", "nd-rep-avail-t1", "nd-rep-avail-devgroup",
                   "nd-rep-avail-run", "nd-rep-avail-export-csv", "nd-rep-avail-table",
                   "nd-rep-avail-lastmonth"]:
    check('id="%s"' % element_id in REPORTS_SECTION or 'id="%s"' % element_id in NODES_SECTION,
          "Availability report control #%s exists" % element_id)
for element_id in ["nd-rep-topn-key", "nd-rep-topn-like", "nd-rep-topn-rankby",
                   "nd-rep-topn-ascending", "nd-rep-topn-n", "nd-rep-topn-t0",
                   "nd-rep-topn-t1", "nd-rep-topn-devgroup", "nd-rep-topn-run",
                   "nd-rep-topn-export-csv", "nd-rep-topn-table"]:
    check('id="%s"' % element_id in NODES_SECTION,
          "Top-N report control #%s exists" % element_id)

# ---------------------------------------------------------------------------
# 6. report.py's own query parameters are the ones actually sent: rank_by,
#    ascending, like, n, device_ids, t0/t1 — read from api.py's
#    get_nodes_reports_top_metrics rather than guessed.
TOPN_JOB = NODES[NODES.index("function runTopMetricsReport("):
                 NODES.index("function exportTopnReportCsv(")]
for param in ["key", "t0", "t1", "rank_by", "ascending", "like", "n", "device_ids"]:
    check(("%s:" % param) in TOPN_JOB or ("%s," % param) in TOPN_JOB
          or ("%s " % param) in TOPN_JOB,
          "the top-metrics request sends %r" % param)

# ---------------------------------------------------------------------------
# 7. Tables reuse the house grid, not a fourth hand-rolled renderer — the
#    same contract test_frontend_contracts.py enforces for setText/setBg/
#    deviceIndex/plottedRange, applied to App.grid/App.sortRows/App.drawRows.
check(NODES.count("App.grid(App.el('nd-rep-avail-table')") == 1
      and NODES.count("App.grid(App.el('nd-rep-topn-table')") == 1,
      "both report tables are built with App.grid")
check("App.sortRows(rows, view.repAvailSort.key" in NODES
      and "App.sortRows(rows, view.repTopnSort.key" in NODES,
      "both report tables sort with App.sortRows, not an inline .sort()")
check(NODES.count("App.drawRows(body,") >= 2 or NODES.count("App.drawRows(body, sorted") >= 1,
      "row rendering goes through App.drawRows")

# ---------------------------------------------------------------------------
# 8. CSV export: report.py has no export.csv route (its two routes answer
#    JSON only), so the file is built from the rows already fetched rather
#    than a second round trip — but it still leaves the browser through
#    App.saveCsv, the one function every other export in this app uses,
#    not a second copy of the Blob-and-anchor trick.
check("function saveReportCsv(" in NODES and "App.saveCsv(" in NODES,
      "report CSV export goes out through App.saveCsv")
CSV_HELPER = NODES[NODES.index("function csvField("):NODES.index("const AVAIL_COLUMNS")]
check("new Blob(" not in CSV_HELPER,
      "the report CSV helpers do not re-implement the Blob download "
      "App.saveCsv already does (nodes.js has its own, unrelated, for the "
      "OID walk download — this checks only the report CSV code)")
check("App.el('nd-rep-avail-export-csv').onclick = exportAvailReportCsv" in NODES
      and "App.el('nd-rep-topn-export-csv').onclick = exportTopnReportCsv" in NODES,
      "both Export CSV buttons are wired to a report-specific export function")

# ---------------------------------------------------------------------------
# 9. The device-group filter resolves through App.deviceIndex(), the one
#    shared device cache (test_frontend_contracts.py's own contract #10) —
#    not a second, module-local fetch of /api/nodes/devices.
check("function reportDeviceIds(" in NODES and "App.deviceIndex()" in NODES,
      "the group filter reads App.deviceIndex() rather than fetching its own list")

# ---------------------------------------------------------------------------
# 10. A run button's request — including the async device-group lookup —
#     happens INSIDE the promise App.runJob is given, so the button is
#     disabled for the whole request. Doing the lookup before calling
#     App.runJob would leave a window where a second click starts a second
#     fetch to the same URL; app.js's own by-path in-flight rule then
#     aborts the first one as "superseded" and App.runJob reports that as
#     a failure that never actually happened.
for fn_name, call_name in [("runAvailabilityReport", "reportDeviceIds('nd-rep-avail-devgroup')"),
                           ("runTopMetricsReport", "reportDeviceIds('nd-rep-topn-devgroup')")]:
    body = NODES[NODES.index("function %s(" % fn_name):]
    body = body[:body.index("\n  }\n", body.index("App.runJob("))]
    run_job_at = body.index("App.runJob(")
    lookup_at = body.index(call_name)
    check(lookup_at > run_job_at,
          "%s calls %s AFTER App.runJob (inside its promise), not before it"
          % (fn_name, call_name))

# ---------------------------------------------------------------------------
# 11. The window sent to the server never reaches into the future: the "To"
#     date is capped at now, since report.py's own routes default t1 to
#     time.time() and a caller asking past that would just be asking for
#     data that cannot exist yet.
check("Math.min(t1Raw, Date.now() / 1000)" in NODES,
      "the report period's end is capped at now, never sent as a future timestamp")

print()
if failures:
    print("FAILED %d contract(s):" % len(failures))
    for message in failures:
        print("  - %s" % message)
    sys.exit(1)
print("ALL REPORTS-UI CONTRACTS HOLD")
