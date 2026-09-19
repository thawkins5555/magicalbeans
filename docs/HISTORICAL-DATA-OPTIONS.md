# Historical data: how the industry does it, and options for this platform

The operator asked how mainstream network monitoring products retrieve,
display, filter, and export historical data — for devices, interfaces,
environmental sensors, CPU, and similar metrics — and wanted a set of
options for how this platform could do the same. This document is that
research and that menu, kept as the record of that decision — see
"Status" below for which options were chosen and shipped.

## How the mainstream products do it

| Product | Storage / retention tiers | How you pick a time range | How history is shown | Filtering | Export |
|---|---|---|---|---|---|
| LibreNMS (and Observium / Cacti — the RRD family) | Round-robin files with consolidation tiers: 5-minute samples for about a week, then 30-minute, 2-hour, and daily averages kept for years | Graph pages offer preset ranges (day/week/month/year) plus a from/to date pair | Graphs are rendered as PNG/SVG images, one page per port or sensor | Per-port and per-sensor graph pages; no cross-device query view | The API returns a graph image (default last 24 hours, or a custom from/to); CSV export of port utilisation is a recurring community request rather than a built-in feature |
| PRTG (Paessler) | Raw data kept 365 days by default | Every sensor has a Historic Data tab: explicit start and end date-time, plus an averaging interval (raw, 5 min, 15 min, hour, day, …) | Table or graph, selectable, for the chosen sensor | One sensor at a time from its Historic Data tab | CSV, XML, JSON, or HTML from the UI, or the same data via `/api/historicdata.csv` with `sdate`/`edate`/`avg` parameters; reports can be scheduled and emailed |
| Zabbix | History (raw values) kept days to weeks; trends (hourly min/avg/max) kept for years | One time selector shared across every graph: relative presets, an absolute from/to with a calendar picker, drag-to-zoom into a highlighted region, a double-click and dedicated buttons to zoom back out, and arrows to shift the window forward/back | Latest Data view shows a graph per item; the same shared selector applies everywhere | Filterable by host, host group, and item in Latest Data | CSV export from Latest Data and dashboards; richer export typically goes through Grafana on top of Zabbix |
| SolarWinds NPM | Detailed stats ~7 days, hourly stats ~30 days, daily stats ~365 days; charts summarise down to roughly 300 plotted points regardless of range | PerfStack (Performance Analysis): drag to zoom, a slider to shift the visible window | PerfStack overlays many metrics from many devices on one shared time axis; results can be exported to a Custom Chart page; real-time charts exist separately for live polling | Add/remove entities and metrics freely on the PerfStack canvas | Export to CSV from PerfStack / Custom Charts |
| Grafana (commonly layered on LibreNMS, Zabbix, or Prometheus) | Inherits retention from whatever it queries | A global time picker (relative and absolute) shared by every panel on a dashboard; drag-to-zoom on any panel; double-click to zoom back out | Panels on shared dashboards; Explore mode for ad-hoc, one-off queries | Per-panel query filters; dashboard-wide variables | Inspect → Data → Download CSV on any panel; dashboards are shareable as links |

A few notes worth calling out:

- The **RRD family** (LibreNMS, Observium, Cacti) trades exact history for
  fixed disk size: old detail is averaged away automatically, and graphs
  are pre-rendered images rather than interactive charts, so export means
  "save the picture" more often than "get the numbers."
- **PRTG** is the most export-friendly out of the box — the CSV/XML/JSON
  API for historic data is a first-class, documented feature, not a
  workaround.
- **Zabbix's** two-tier history/trends split, and its one time selector
  used everywhere, is close in spirit to where this platform is headed
  with drill-down on every chart.
- **SolarWinds PerfStack** is the strongest example of overlaying several
  devices' metrics on one chart for side-by-side troubleshooting.
- **Grafana** shows what a shared, dashboard-wide time control feels like
  once several tools sit behind it — most LibreNMS and Zabbix shops that
  want serious ad-hoc analysis end up running Grafana on top anyway.

Sources:

- https://www.paessler.com/manuals/prtg/historic_data_reports
- https://helpdesk.paessler.com/en/support/solutions/articles/76000063676-how-can-i-export-historic-data-from-the-prtg-api-
- https://www.zabbix.com/documentation/current/en/manual/web_interface/time_period_selector
- https://www.zabbix.com/documentation/current/en/manual/config/items/history_and_trends
- https://documentation.solarwinds.com/en/success_center/orionplatform/content/core-customizing-charts-in-the-orion-web-console-sw1349.htm
- https://support.solarwinds.com/SuccessCenter/s/article/SolarWinds-Performance-Analysis-PerfStack
- https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/panel-inspector/
- https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/panel-overview/
- https://community.librenms.org/t/api-get-graphs-with-time-frame/22131
- https://community.librenms.org/t/export-ports-utilization-bits-into-csv-format/13642

## What they have in common

Across all five products, six patterns show up repeatedly:

1. **Tiered retention** — raw samples for a short window, then hourly
   averages, then daily averages, so storage stays bounded while old
   trends are still visible.
2. **Three ways to pick a range on every chart** — a relative preset
   (last hour/day/week), an absolute from/to picker, and drag-to-zoom
   directly on the chart.
3. **A per-object history page** — pick one device, port, or sensor and
   see a table next to its graph, not just a picture.
4. **Export from both the screen and an API** — CSV or JSON, so the data
   can be pulled into a spreadsheet or a script, not only viewed.
5. **Overlaying several objects on one chart** — comparing two interfaces
   or two devices side by side on a shared time axis.
6. **Scheduled reports by email** — the history gets pushed to someone on
   a schedule instead of requiring them to log in and look.

## Where this application stands today

- Metric history for devices and interfaces — bandwidth, errors,
  utilisation, CPU, memory, temperature and other environmental sensors,
  and RF — is kept as raw samples plus hourly min/avg/max rollups in the
  Nodes series database.
- Raw detail is kept for about three days at the device level, and one day
  per port; older data falls back to the hourly rollup automatically.
- Charts on most screens offered fixed preset windows only. This release
  (5.22.0) adds a custom from/to range and drag-to-zoom to every chart
  with a time axis, closing part of the gap with the products above.
- Reports (availability and Top-N) return JSON with a client-side CSV
  conversion in the browser; there is no server-side CSV export of raw
  series data, and no equivalent of PRTG's `/api/historicdata.csv`.
- The Wireless module keeps current state only — no history at all for
  client counts, RSSI, or channel utilisation per access point.
- NetFlow, Syslog, and Traps each have their own storage and retention,
  separate from the Nodes series database.

## Options

Each option below stands on its own; they are not mutually exclusive.

### A. A History explorer (new Nodes sub-tab)

**What the operator gets:** pick any combination of devices, interfaces,
sensors, or CPU/memory metrics, a time range, and an aggregation level;
see them overlaid on one chart with a table underneath; download as CSV.
This is the platform's answer to PRTG's Historic Data tab and SolarWinds'
PerfStack, combined into one screen.

**Where it hooks in:** the batch series route this release adds for
dashboard tiles (fetches several metrics for a shared window in one
request); the existing Reports engine for the table/CSV half.

**Effort:** Medium — most of the plumbing (series storage, the batch
route, range picking) already exists after this release; this is mainly a
new screen and a query builder.

**Trade-offs:** none functional; it's new UI surface to maintain.

### B. A Historic data panel inside the device and interface dialogs

**What the operator gets:** a small table of the exact samples behind
whatever range is currently on screen, with a CSV button — PRTG's
per-sensor tab, scoped down to "whatever I'm already looking at."

**Where it hooks in:** the dialogs that already draw these charts
(`nodes.js`); no new route beyond what draws the chart today.

**Effort:** Small.

**Trade-offs:** narrower than Option A — one device/interface at a time,
no cross-device overlay.

### C. A series export API (CSV/JSON, from/to, aggregation)

**What the operator gets:** the same data Option A or B would show, but
pullable directly with the existing API tokens — from Excel, PowerShell,
or a scheduled script, without opening the UI at all.

**Where it hooks in:** the same series database and batch route as A;
this is the "give me the numbers" counterpart to PRTG's
`/api/historicdata.csv`.

**Effort:** Small — mostly a CSV/JSON serializer on top of data already
being fetched for charts.

**Trade-offs:** none; this is the option with the best effort-to-value
ratio on its own.

### D. A Grafana-compatible JSON data source

**What the operator gets:** for any team that already runs Grafana
elsewhere, this platform's history becomes just another data source they
can chart, alert on, and dashboard alongside everything else they track.

**Where it hooks in:** a new read-only HTTP endpoint speaking Grafana's
JSON datasource protocol, backed by the same series database.

**Effort:** Medium.

**Trade-offs:** only pays off for sites that already run Grafana; it adds
and maintains a second protocol surface for no benefit to sites that
don't.

### E. Scheduled emailed reports

**What the operator gets:** a daily or weekly summary (Markdown or a CSV
attachment) landing in an inbox automatically, the way PRTG's scheduled
reports work — availability, Top-N talkers, whatever the existing Reports
engine already computes, on a timer instead of on demand.

**Where it hooks in:** the existing Reports engine and the alert email
sender (`alertmail.py`), which already knows how to send mail reliably.

**Effort:** Small–Medium.

**Trade-offs:** reuses existing report content rather than adding new
metrics; value is in the delivery mechanism, not new data.

### F. Retention changes

**What the operator gets:** a daily rollup tier beyond the current
hourly one, for readable multi-year trend views without keeping raw data
forever; optionally, longer raw retention per port where disk allows.

**Where it hooks in:** the Nodes series database's existing rollup job;
the storage-cap machinery that limits total disk use already exists, so
this is tuning within a system already built to stay bounded.

**Effort:** Medium — the rollup logic itself is a small change, but it
needs a migration pass over existing data and careful testing of the
storage cap interaction.

**Trade-offs:** more disk use unless offset by shortening another tier;
no functional risk otherwise.

### G. Wireless history

**What the operator gets:** the same kind of chart the wired side already
has — client counts, RSSI, and channel utilisation over time per access
point — where today the Wireless module shows only current state with
nothing to look back on.

**Where it hooks in:** a new time-series store for the Wireless module,
most naturally following the same shape as the Nodes series database.

**Effort:** Large — this is new data collection and storage, not just a
new view on data already being kept.

**Trade-offs:** the only option here that adds new polling load; sized on
its own rather than bundled with the others.

### Recommendation

Options **A and C** first — the batch series route already being added
this release makes the History explorer (A) cheap to build, and the
export API (C) is small on its own and gives immediate value (pulling
data into a spreadsheet) even before A exists. **F** (a daily retention
tier) makes sense next, once disk headroom is confirmed. **G** (Wireless
history) is its own piece of work, sized separately, since it is new data
collection rather than a new view on data already collected.

Nothing here is scheduled; pick the options and Bob will plan them.

### Status

The operator chose **A, E, and G**; all three ship in 5.23.0. Option A
landed as the Nodes → HISTORY sub-tab, with a series CSV export route
alongside it. Option E landed as Nodes → Reports → SCHEDULED, sending a
summary body plus a CSV attachment on a daily, weekly, or monthly
schedule. Option G landed as per-AP client and radio history in the
Wireless AP detail pane, covering only the metrics already polled
today (client counts, channel, tx power, online state) with no new
SNMP columns added.
