<!-- Research note, 5.9.0. Nothing here is implemented: it exists so the
     additional per-AP data can be chosen with its cost known. -->

# FORTI-AP: what else can be polled, and what it would cost

Research note, not an implementation. Nothing here is wired up. Every
file:line reference below was checked against the 5.9.0 release tree, with
this release's documentation pass applied, on 2026-09-10.

## What is polled today

One transport, SNMP, and only to the controller. There is no REST or HTTPS
path to a FortiGate or FortiManager anywhere in the codebase (grepped for
`fortigate|fortios|fortimanager` against any HTTP client; nothing), and no
Fortinet MIB is shipped in `netpath/mibs/` — the OIDs are hand-listed
constants at `netpath/nodeoids.py:815-853`.

`WirelessPoller._poll_controller` (`netpath/fortipoll.py:232-241`) walks ten
columns per controller per cycle, each as a separate GETNEXT sweep
(`_walk_column`, `:313-346`):

| table (`1.3.6.1.4.1.12356.101.14.4.<t>.1`) | column | stored as |
|---|---|---|
| `fgWcWtpConfigTable` (`.3.1`) | 3 name | `access_points.name` |
| `fgWcWtpSessionTable` (`.4.1`) | 3 IP, 6 MAC, 7 connection state, 12 model, 17 station count | `access_points.ip/mac_address/status/model/station_count` |
| `fgWcWtpSessionRadioTable` (`.5.1`) | 3 mode, 7 channel, 8 operating power, 9 station count | `radios.mode/channel/operating_power_dbm/station_count` |

Two more things are known without asking the controller: the AP's ICMP
round-trip (`_ping_ap`, `:204-223`, online APs only, 700 ms per probe and a
20 s budget for the whole controller, `:49-50`), and the vdom and WTP id
decoded from the OID index (`_split_vdom_wtp`, `:391-408`).

Storage (`netpath/wirelessdb.py`): every declared column is written by the
poller — there is nothing declared-but-unfilled to switch on for free.
`radios` rows are deleted and re-inserted on every poll (`replace_radios`,
`:270-281`), so there is no per-radio history of any kind; `access_points`
is an upsert, so there is no per-AP history either beyond `last_seen_ts`.
The only durable record is `ap_events` — `ap_removed`/`ap_returned` and
`ap_offline`/`ap_online` transitions (`:238-268`, `:387-431`), which the
Alerts engine drains.

The Wireless tab shows a table and a text detail pane; no charts
(`netpath/web/static/wireless.js:1-7` says the histogram was left out on
purpose — "a handful of controllers generates nothing worth charting").

Two facts about the walk that drive every cost figure below:

- It is one GETNEXT per row per column, no GETBULK (`fortipoll.py:14-16`).
  A column over N APs costs N+1 round trips (the +1 walks off the end of
  the column); a per-radio column over R radios costs R+1. Each request
  also opens and closes its own UDP socket (`_snmp_get_next`, `:350`,
  `:388`).
- A column walk stops silently-with-a-log-line at 4096 rows (`:316`,
  `:338-345`). That cap does not matter for APs; it matters a great deal
  for anything keyed per client (Tier C).

## Step 0 — measure before choosing anything

The columns polled today are 3 / 3, 6, 7, 12, 17 / 3, 7, 8, 9. The gaps
are the candidates. Which of those gaps a given FortiOS build actually
populates, and what it puts there, is an empirical question, and this MIB
has already been caught answering it wrongly: `nodeoids.py:843-851` and
`INTERNALS.md:6832-6844` document that `fgWcWtpSessionRadioOperatingPower`
is described as dBm and observed FortiOS returns its 0-100 power level in
that object, which is why `api._power_unit` auto-detects per controller.
A candidate list built from MIB text would inherit that risk on every
row. So:

**Walk the three table entries and the `fgWc` root on a production
controller, and keep the output.** The app can do this itself: the OID
browser (`api.get_nodes_device_oids`, `netpath/web/api.py:4864`, backed by
`NodePoller.walk_subtree`, `netpath/nodepoll.py:7184`) walks any numeric
OID from a Nodes device's pane. Three practical points:

1. The browser is a Nodes feature. The controller must exist as a Nodes
   device with working SNMP — the Wireless tab already assumes it usually
   does (`wireless.js:197-198`, the controller-to-device link).
2. The browser caps a walk at 600 rows or 20 s (`nodepoll.py:7181-7182`)
   and says which limit it hit. On a controller with, say, 40 APs and a
   session table of 20-odd columns, walking `.4.1` whole is ~800 rows and
   will be cut short. Walk one column at a time (`.4.1.<n>`) on a big
   controller; walking the whole entry is fine on a small one.
3. Walk `1.3.6.1.4.1.12356.101.14` from the top as well, not only the
   three known tables. The repo's own comment (`nodeoids.py:807-812`)
   lists three tables under `fgWcWtpTables(4)` and says nothing about
   what else sits under `fgWc(14)`. Whether a per-SSID or per-client table
   exists at all on this firmware — the whole of Tier C — is answered by
   that one walk and by nothing in this repository.

Record: the column numbers that return rows, the SNMP type, two or three
raw values per column, and the FortiOS build (`sysDescr` is in the
default browse set). Also note whether the config table has rows the
session table lacks: the poller lists APs by iterating the MAC column
(`fortipoll.py:254`), so an AP that is configured but has never
associated is invisible today, and only a live walk says whether that
case exists.

**Honesty about what follows.** In Tiers B and C I name *capabilities*,
not OIDs. I have not verified in this repository any `fgWc` column beyond
the ten polled, and I am not going to write down column numbers from
memory of a MIB that has already lied once. Where a capability turns out
not to exist on the walked firmware, strike it.

## Tier A — zero extra SNMP

Everything here is derived from rows the poller already has in hand each
cycle. The cost is storage and a small amount of code; the design stance
in `INTERNALS.md:6958-6966` ("derived ... so adding one costs no extra
SNMP") is exactly this tier. It should go first.

### A1. Per-AP client count as a time series

Today `station_count` is overwritten each poll. One new table — one row
per AP per poll — turns it into history. The repo already has this shape
built and charted for a module that is also "a handful of things":
`dhcp_scope_history` (`netpath/ipamdb.py:212-228`) is one row per scope
per poll, written by `record_scope_usage` (`:725-732`), read by a
windowed query (`:734-742`), pruned at `dhcp_history_days` (default 35,
`netpath/web/service.py:1430-1431`), served by `get_ipam_dhcp_scope_history`
(`api.py:3058-3071`) and drawn by `drawScopeTrend` (`ipam.js:896`). An
`ap_history(ap_id, ts, station_count)` table is that pattern copied
verbatim, with its prune added beside `prune_ap_events()` at
`service.py:1443`.

Size, at the 60 s default (`fortipoll.py:154`; `wirelessdb.py:82`): 40 APs
is 57,600 rows/day; at roughly 40 bytes a row with its index that is
about 2.3 MB/day, ~80 MB at 35 days. Reasonable, but not nothing for a
file that is otherwise a few hundred KB. Two ways down: record every
fifth poll (5-minute resolution, ~16 MB at 35 days — client counts do not
move faster than that in any useful sense), or copy `nodesseriesdb`'s
raw-plus-hourly-rollup split (`netpath/nodesseriesdb.py:44-62`; raw 3
days, rollup 400 days). The first is one line of code; the second is a
compaction job. Start with the first.

What it lets an operator see, none of which is visible today:

- which APs are at their client ceiling and when — the capacity-planning
  question, answered per AP per hour instead of by whoever was looking at
  the tab at 09:00;
- an AP that is *online* with zero clients for hours where it used to
  carry forty — a radio that stopped serving without the controller
  marking the AP offline. `ap_offline` cannot fire for it
  (`wirelessdb.py:236-268` is keyed on connection state), so today it is
  invisible;
- evidence for "the Wi-Fi was slow at 14:00 in the warehouse": was the AP
  carrying 3 clients or 90.

On the chart: the "nothing worth charting" comment at `wireless.js:4-5`
is about the *event histogram* that `events.js` has — event volume across
a handful of controllers, which is genuinely flat. A per-AP client trend
is a different object, and IPAM made the opposite call for the same
reason on the same scale (one DHCP server, a few scopes, still worth a
trend line). One SVG per selected AP in the detail pane, 24 h / 7 d
toggle, copied from `drawScopeTrend`. Note there is no shared chart
helper in `app.js` — `ipam.js` and `nodes.js` (`drawSeriesChart`,
`nodes.js:1189`) each carry their own — so this is a copy, not a call.

### A2. Channel-change events

Before `replace_radios` deletes the old rows (`wirelessdb.py:272`), read
them and compare `channel` per `radio_id`. A change becomes an
`ap_events` row (kind `radio_channel_changed`, detail "radio 2: 44 → 149")
through the existing `add_ap_event`. No schema change; one SELECT per AP
per poll on a table of a few hundred rows.

This is the one Tier A item with an operational bite for a FortiGate
operator specifically: on 5 GHz a channel move is usually a DFS radar
event or DARRP, and both are invisible today except as a momentarily
different number in a column nobody sorts by. An event row gives a
timeline; an alert rule can be added later if wanted, but it should be
an event and not an alert by default — a site with aggressive DARRP would
otherwise page on every optimisation pass. Keying the diff on the radio's
`mode` as well as `channel` catches a radio flipping to monitor or
disabled for the same price.

### A3. Flap counting

Already recorded: every `ap_offline`/`ap_online` transition is an
`ap_events` row. A count over the last 24 h is one grouped query per
page load, exposed as an optional `flaps_24h` column in `_ap_json` and
`ALL_COLUMNS`. No new storage. It surfaces the AP that goes down for one
poll every night at 02:10 (a PoE budget, a switch port, a bad cable),
which today produces a pair of alerts each time and no pattern anyone
sees.

### A4. Per-radio client distribution over time

The same history table with `radio_id` and `channel` added (or a second
`radio_history` table), 2-3× the rows of A1. It answers the 2.4 GHz
versus 5 GHz split — whether band steering is doing anything — and gives
a channel timeline per radio, which is A2 drawn as a lane rather than
listed as events. Worth doing only if A1 earns its keep; the AP-level
count answers most of the questions first.

### A5. Small derived fields

"Online since" from the newest `ap_online`/`ap_returned` event (not a
true AP uptime — that is B1); fleet counts by model and by vdom for the
status strip. Trivial, no storage, mention only so they are not mistaken
for something that needs polling.

## Tier B — one extra column walk each

Cost model, per controller per poll, on top of today's 6(N+1) + 4(R+1)
requests for N APs and R radios:

- one more per-AP column: N+1 GETNEXTs;
- one more per-radio column: R+1 GETNEXTs, so 2-3× a per-AP column on
  a fleet of dual- and tri-radio APs.

Worked example, N = 40, R = 100: today is 246 + 404 = 650 requests a
cycle, 39,000 an hour at the 60 s default. One per-AP column adds 41
(+6 %); one per-radio column adds 101 (+16 %). What that costs in
seconds is the per-request constant, which is the thing to measure in
Step 0 (time a 41-row column walk in the browser): on a LAN it is a few
milliseconds of network plus whatever the FortiGate's SNMP agent takes to
find the row, and the agent is the larger term. At 5 ms a request the
whole of today's poll is ~3 s and one column is ~0.2 s; at 20 ms it is
~13 s and ~0.8 s. Either way a column is cheap and the ping sweep
(up to 20 s) remains the dominant cost of the cycle — but four or five
per-radio columns together are not cheap, and the poll must finish
inside its interval on a 10 s floor (`fortipoll.py:154`). The failure
path is unchanged: a dead controller costs one timeout×retries, not one
per column (`:107-112`).

Capabilities, in order of usefulness to an operator. All are named, not
verified; Step 0 decides which exist and at which column.

- **B1. AP uptime / session uptime.** Catches the reboot that lasts less
  than a poll interval, which `ap_offline` misses entirely (the poller
  only sees connection state at 60 s samples). Strong candidate: one
  per-AP column, answers "which AP restarted last night" directly.
- **B2. Firmware version.** Answers "which APs have not taken the
  upgrade" without opening the FortiGate. Changes rarely; the poller has
  no every-Nth-poll mechanism (`_loop`, `:149-163`, is one cadence for
  everything), but at N+1 requests it is not worth building one.
- **B3. Assigned WTP profile / admin-enable state** (config table).
  Cheap; useful for "why is this AP behaving differently" (wrong
  profile) and for not alerting on an AP an admin disabled on purpose —
  which is what `out_of_service` already covers on our side.
- **B4. Serial number.** `access_points.wtp_id` is documented as "usually
  a serial" (`wirelessdb.py:35`). Confirm on the walk before spending a
  column on a duplicate.
- **B5. Per-radio BSSID, channel width, noise floor.** Each is a
  per-radio column at R+1. Noise floor is the one an operator cannot get
  from the AP list in the FortiGate GUI at a glance and would matter for
  a warehouse with interference; BSSID mostly matters for correlating
  client-side reports; channel width matters little once channel is
  known. Pick at most one on the first pass.
- **B6. Byte counters** (per session or per radio). The most expensive
  item in this tier, disproportionately: two columns (in and out),
  counter-rate arithmetic, wrap handling, and a time series before the
  number means anything — that is Tier A's storage plus B's walks plus
  code the wireless module does not have and `nodesseriesdb` does. The
  FortiGate GUI already shows AP throughput well. Defer.

For a per-AP column the poller side is one `_walk_column` call at
`fortipoll.py:232-241` and one keyword into `upsert_ap` (`:264-272`); for
a per-radio column it is the `radios.append` dict (`:287-294`) plus the
INSERT in `replace_radios` and `_radio_json` (`api.py:7333-7349`) and the
detail pane lines (`wireless.js:207-227`) rather than `ALL_COLUMNS`.

## Tier C — a new table: per-client data

MAC, SSID, RSSI, rate, association time, serving AP/radio. Whether the
controller exposes any of this over SNMP on the deployed firmware is the
first thing Step 0's walk of `.14` establishes; nothing in this repository
says it does.

If it exists, the cost is a different shape from everything above
because it scales with clients, not APs. With C clients and k columns
walked, it is k(C+1) requests a cycle. 1,500 clients across the 40-AP
example and five columns is ~7,500 GETNEXTs per poll — 11× today's entire
poll of that controller, and at 60 s it would likely overrun its own
interval on a busy site; it would need a cadence of its own. The 4096-row
cap in `_walk_column` (`fortipoll.py:316`) truncates any column on a
controller with more clients than that, with only a log line to say so.
Storage as a wholesale-replaced "current clients" table (the `radios`
pattern) is fine; as history it is C rows a minute — 2 million a day at
1,500 clients — and not viable without sampling. It needs new schema, a
new API and a new UI (a client list, a per-AP client pane, a search),
and it stores client MAC addresses, which in the EU operating companies
is personal data with a retention question attached.

The FortiGate GUI already answers "who is on this AP right now" well.
The case for doing it here is a client-search across controllers and a
history the GUI does not keep; neither is worth this cost before A1 and
B1 exist.

## Tier D — off SNMP: the FortiGate REST API

FortiOS has an HTTPS REST API that reports more per-AP and per-client
detail than the MIB ever will (capability, not verified here). It would
be a wholly new transport in a module whose entire design is one SNMP
walk per controller: a second credential type (an API token — the DPAPI
encrypt-and-never-return pattern for the v3 password exists,
`wirelessdb.py:5`, but the storage, the form, the refusal paths and the
tests would all be new), TLS trust for self-signed FortiGate certs,
admin-profile permissions on the FortiGate side, response shapes that
change across FortiOS majors, and a failure mode ("SNMP works, REST is
refused") the UI has no way to express. Flagged so the option is on
record; not recommended, and not before Tiers A and B have shown SNMP is
insufficient for a question someone actually asked.

## Cost of adding a column, once chosen

Cheap and well-trodden. Six touch points for a per-AP column:

1. `netpath/nodeoids.py` — one constant beside `:834-838`, with a comment
   stating what the walk actually returned (type and a sample value), the
   way `:843-851` does for operating power.
2. `netpath/wirelessdb.py:115-121` — one entry in `_migrate`'s
   `ensure_columns` call (`SqliteStore.ensure_columns`,
   `netpath/sqlitebase.py:484-501`, is a PRAGMA-diff-then-ALTER; it is
   idempotent and needs no version bump).
3. `netpath/fortipoll.py:232-241` — one `_walk_column` call; thread the
   value into `upsert_ap` at `:264-272`, with a `_format_*`/`_as_int`
   normaliser if the type needs one.
4. `netpath/web/api.py:7376-7411` — one field in `_ap_json`.
5. `netpath/web/static/wireless.js:87-126` — one `ALL_COLUMNS` entry
   (off by default; `table_columns` in settings carries the operator's
   choice).
6. `tests/stubs/wireless_stub_agent.py:42-51` — one line per AP in
   `build_table`, and an assertion in `tests/test_wireless_poller.py`.

Plus two that are easy to forget: the demo persona
(`demo/personas.py:1534-1552`) if the demo should show the column, and
the column list in `FEATURES.md` (the "Choose which columns to show"
paragraph). The cleanest worked example is the per-AP response time —
`CHANGELOG.md:5406-5412`, which sits under the **4.28.0** heading at
`:5358`, not 5.1.0 — which touched every one of these and added
`_format_ip` for a type that arrived in a form the MIB did not describe
(`fortipoll.py:418-448`).

## Two defects to fix in passing

**The stub is behind the poller.** `tests/stubs/wireless_stub_agent.py:42-51`
serves eight of the ten columns: it emits neither `WTP_SESSION_IP` nor
`WTP_RADIO_MODE`. The poller walks both, gets an empty dict for each, and
`test_wireless_poller.py` asserts nothing about `ip` or `mode`, so the
two most recently added fields are untested end to end — and the stub's
docstring ("exactly the fgWc OIDs in nodeoids.py") is no longer true. The
demo persona does serve both (`demo/personas.py:1537-1538`, `:1548`), so
there is a working template. Anything added under Tier B lands in the
stub in the same change, or it will be untested too.

**Every controller polls at the same second.** `_loop`
(`fortipoll.py:149-163`) takes `now` once per pass and seeds each
controller's due time with `next_run.get(id, 0)`, so every enabled
controller is due on the first pass and rescheduled to the same `now +
interval`. With `ThreadPoolExecutor(max_workers=4)` (`:82`) that means
up to four controllers' walks and 20 s ping sweeps run in the same window
every cycle. On a handful of controllers it is harmless; it becomes
visible the moment a per-client table or more columns lengthen the cycle.
The node poller does not have this shape: it seeds from the device's own
`last_poll_ts` (`netpath/nodepoll.py:2241-2247`, and the docstring at
`:4-5`), and its secondary walks spread the first run with
`random.uniform(0, interval)` (`:2530-2532`, `:2562`, `:2591`, `:2629`).
Either is a two-line change here — seeding from `controllers.last_poll_ts`
is the closer match. The node poller's own version of this was fixed in
5.9.0: it now spreads the first poll after a restart and breaks the shared
phase on the first reschedule after that (`tests/test_poll_stagger.py`).
The wireless `_loop` should adopt the same shape, and has not yet.

## Recommendation

Do these, in this order:

1. **Step 0 this week, before any code.** Walk `.14`, then `.14.4.3.1`,
   `.14.4.4.1` and `.14.4.5.1` column by column, on one production
   controller, and check the raw output into the repo as a fixture. It
   costs an hour, it is the only thing that turns Tier B from a list of
   names into a list of columns, and the fixture is also the honest
   replacement for a stub that currently invents its own table shape.
2. **A1 + A2 as the first build**: per-AP client history on the
   `dhcp_scope_history` pattern with a 5-minute sample and a 35-day
   prune, one trend chart in the detail pane, and channel-change events.
   Together they give the module a memory it has never had, for zero
   SNMP, and A2 is the one item on this whole list that reports something
   a FortiGate operator cannot see anywhere else at a glance. Fix the
   stub and the scheduler phase in the same change.
3. **A3 (flap count) as a column** if step 2 lands cleanly; it is a query,
   not a feature.
4. **B1 (uptime) and B2 (firmware)** once Step 0 says they exist — two
   per-AP columns, ~+12 % requests on the worked example, and each
   answers a question operators ask by name. Stop there in Tier B unless
   someone asks for noise floor.

Leave alone: B6 byte counters (a lot of machinery for a number the
FortiGate shows better), all of Tier C (cost scales with clients, a
privacy question, and no demonstrated need), and Tier D (a new transport
for a module built around not having one). Any of these can be revisited
with the Step 0 walk in hand and a named question that A and B could not
answer.
