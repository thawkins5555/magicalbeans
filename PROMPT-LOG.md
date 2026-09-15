# Prompt log

A short note on each request made in this working session, oldest first,
grouped by the version that carries it. This is a working record for the
operator — the full story of each change is in `CHANGELOG.md`, and this file
does not replace it.

## 5.26.0 — Duplicate devices: configured addresses only, not discovery IPs

**Operator prompt:**
"ONLY IP's that are actually configured on a device's physical
interfaces or vlan interfaces should be considered when detecting
duplicate devices.  Currently it seems the system is using
'discovery' IP addresses and considering it a device duplicate when
that IP address isn't actually assigned to an interface on the
device.  Those discovered IP's should be used for things like IP
address conflict (if multiple MACS arp to a single IP) etc but not
for actual NODE Device Duplicates."

**Planning answers:**
1. Which addresses count as "configured" — everything in the
   device's own address table: physical interface IPs, VLAN
   interface IPs, loopbacks, tunnel interfaces, and management
   addresses (i.e. what SNMP's address table on the device itself
   reports, not what the discovery sweep merely probed).
2. Scope — all three places the system tells the operator two
   devices are the same box: the Duplicates button, the discovery
   screen's "Same as an existing device" hint and its promote step,
   and the 409 conflict check when adding a device by hand or
   through bulk import.

**Notes:** an address now only counts as duplicate evidence when it
came from reading the device's own address table and is currently
present there; addresses picked up purely by discovery probing, by
SNMP traps, or inherited during a merge are kept — they still feed
IP-conflict detection (two MACs answering for one IP) and IPAM — but
no longer make two unrelated devices look like the same one. The
discovery sweep now records what it actually reads off each device's
address table as configured evidence, separately from the one address
it used to reach the device, which is recorded as discovery-only. The
Duplicates dialog and the device's Addresses tab now say which
addresses are configured versus merely seen by discovery, so this
isn't a silent change. Added `tests/test_duplicate_evidence.py` and a
new section in the existing device-identity tests covering the
configured-vs-discovered split.

**Outcome.** Shipped as 5.26.0. Full suite 167/171 with only the four known environmental failures (no passphrase, no traceroute, socket family, prune-lock timing), Nodes browser walk 80/80 with zero console, page or HTTP errors as admin and viewer. One existing test (test_state_cache) seeded its alias with a made-up source and needed to seed a configured one. Javariius pass 1 "not ready" on one false INTERNALS sentence about the 409 wording plus the empty outcome line, no code faults; four nits taken (comment trims, bulk-import hint wording, contract description, an upgrade note in CHANGELOG). Pass 2 reported in chat. Held on the session branch until the operator clears the push to main.

## 5.25.0 — SFP copper/laser identification

**Operator prompt, two items:**
- "Is there a way via SNMP to determine the difference between a fiber
  SFP and a copper SFP?"
- "I want the Nodes -> Devices -> Interfaces -> should show one of
  three icons - DOM for laser DOM SFP's, 'SFP' for laser non DOM, and
  'COP' for non-DOM copper SFP's.  The Report should have an
  additional copper identifying if the type is copper or laser."

**Notes:**
1. Answered in chat, no code changed. ENTITY-MIB's module description
   and vendor-type name the part number (GLC-T, SFP-10G-T vs SX/SR/LR),
   which is the most reliable signal. MAU-MIB's ifMauType names the
   media type outright where the vendor fills it in. Wavelength and
   connector type from the transceiver EEPROM work where a vendor MIB
   exposes them — copper modules report a wavelength of 0. DOM sensor
   absence is only a hint, since some copper modules report a
   temperature sensor. Plain IF-MIB type and speed cannot tell copper
   and fiber apart.
2. Planning answers: "Module text plus MAU-MIB" for the proof a module
   is copper, and "COP" for a copper module that still reports a
   temperature sensor. The plan adds a `copper` media value decided
   from the module description text plus a new MAU-MIB column walk,
   badges each interface DOM/SFP/COP in the interface list and the
   report's Kind column, and adds a Medium column (Copper/Laser) to
   the SFP inventory report and its CSV/email output. Alerting is
   unchanged. **Outcome.** Shipped as 5.25.0. Javariius pass 1 "not ready" with one blocker (a MAU copper answer would have badged every fixed copper port on a Catalyst) and five should-fixes, pass 2 one should-fix (the "unknown PMD" MAU codes must not veto copper text), pass 3 "ready to push". Along the way a 5.24.0 bug surfaced: the SFP inventory table on screen collapsed each device to one row (rows keyed by device id); fixed. Targeted tests green; the operator asked for the push ahead of Testy's final full-suite and walk run, whose result is reported in chat.

## 5.24.0 — Priority port tint, History search by name, SFP inventory report

**Operator prompt, three items:**
- "Priority ports should be slightly tinted in the Nodes -> Devices ->
  Devices Details -> Interfaces list"
- "Nodes -> History -> Device doesn't  show names but only IP's - should
  be abLE TO search by IP or name and should show both in the drop
  down."
- "Create a report that will export a full list of Node SFP's ->
  Should show the device name, device IP, switch port and whether it's
  a regular SFP or a DOM SFP."

**Notes:**
1. Rows flagged Priority get a light tint in both copies of the
   interface table (the device details dialog and its embedded view),
   so a priority port is visible at a glance without opening a filter.
2. The History device picker was reading the manual name field, which
   most devices never have set, and falling back to the bare IP. It now
   resolves a name the same way the device list does — a pinned manual
   name, else the SNMP hostname, else the stored name, else the IP — and
   the dropdown shows both name and IP together; the
   server-side search already matched on IP, name, and hostname, so no
   change was needed there.
3. New Nodes → Reports → SFP INVENTORY report, built from the per-port
   media data the environment poll already collects: device name,
   device IP, switch port, and a DOM/SFP call — DOM for an optic that
   publishes light levels, plain SFP for a transceiver the switch names
   but that reports no sensors, with empty cages left out. Available as
   a CSV export and as a scheduled emailed report kind alongside the
   existing report schedules.

**Outcome.** All three items shipped as 5.24.0. Full suite 166/170 with only the four known environmental failures (no passphrase, no traceroute, socket family, prune-lock timing), browser walk 77/77 with zero console, page or HTTP errors as admin and viewer, Javariius pass 1 "not ready" (three doc inaccuracies, six nits, all closed), pass 2 "ready to push". One walk step in Mapper (Connect/Remove) proved a harness race and was hardened to wait for the map reload; no product change. New tests: tests/test_sfp_report.py.

## 5.7.0 — Five reports

**"Five things..."** — the standing working policy, plus five field reports:
MAPPER drawing links twice, the NetFlow window not matching what was asked for,
global search not finding a MAC on a switch port, DHCP leases not searchable by
MAC, and no way to search an ARP table.
→ All five delivered. Switch ARP polling and storage were new work, not a fix.

**"The application updates from Main - Main should be the most recent version of
the application."** — a correction to how releases reach the estate.
→ Release process changed: `main` now carries the newest version, and the branch
is fast-forwarded into it rather than lagging.

**"push to main"**
→ 5.7.0 shipped.

## 5.7.1 — The temp folder that wasn't there

**"Update is giving me this error: ... [WinError 3] The system cannot find the
path specified"** — the self-update failed on a per-session Windows temp
directory that no longer existed.
→ New `netpath/temppath.py`: recreates a vanished system temp directory, then
falls back through `%LOCALAPPDATA%\Temp`, `%SystemRoot%\Temp` and the install
root, proving each is writable by writing to it.

**"DHCP IPAM is giving similar error - is this related?"** — same failure, second
symptom.
→ Yes, same root cause. The DHCP poller's PowerShell scratch file went through
the same fixed path helper.

**"push to main when done"**
→ 5.7.1 shipped.

## 5.7.2 — The password that was never wrong

**"Please double check the SNMP V3 polling - I have confirmed username and
password but I am getting 'Authorization Error'."**
→ The credential was never the problem. The diagnostics were: several distinct
protocol failures all reported as one generic message, and a device that was
reachable could be marked down by it. The SNMPv3 error paths were separated so
each says what actually happened.

## 5.8.0 — The privacy password, and the reply nobody checked

**"Use cryptography as an optional dependency then."** — a redirect, after I
proposed writing AES by hand.
→ Correct call, and the right one. SNMPv3 **authPriv** now works via
`cryptography` as an optional dependency (`netpath/snmpcrypt.py`), degrading
cleanly when it is absent. Reply verification was added at the same time.

**"before pushing to main perform an /ultrareview"**
→ No such command exists. Composed the equivalent: a security review followed by
three adversarial passes with mutation testing. It found a decryption oracle and
a stop-ship defect that marked reachable devices as down.

**"After review push to main"**
→ 5.8.0 shipped, with the review findings fixed first.

## 5.8.1 — The restart that fixed it

**"The SNMP V3 Test gives response ... but fails when attempting the actual
'poll now' and the automatic poller both fail saying 'No Reply'."** and **"One
SNMPV3 to a separate Palo Alto is successfully working - the 1st one I added is
working fine - I added 3 more ... they are suffering from this."**
→ The second message was the one that solved it: same credential, same model,
only the later-added devices affected, and a restart cured them. A cached SNMPv3
engine that went stale could never recover, because only an explicit auth
failure cleared it and this firewall answers a stale request with silence. It
now recovers on its own, and "Poll now" clears the cache the way an operator
retry should.

## 5.9.0 — Six operator asks

**"Develop with Fable and Deploy with Opus. Use Sonnet for non-reasoning
tasks."** — sent as an interrupt, then withdrawn ("ignore my last message"),
then restated as standing policy.
→ In force. It is how this release was built.

**The six asks**, with two new standing constraints — keep code comments to only
what is necessary (prose 10% or less), and do not push to `main` or run a code
review, because one review and one push happen at end of day.

1. **Maintenance devices still show as offline on the Dashboard.**
   → Maintenance lives in a different database file from the fleet counts, so
   the exclusion has to happen above both. Devices in maintenance mode or inside
   an active maintenance window no longer count as down — on the Dashboard, the
   Nodes strip and the tab badges alike. They are shown as their own figure
   rather than silently disappearing.
2. **Search syslogs by hostname and part of a hostname.**
   → The Host column often shows a name resolved from Nodes or DNS that was
   never stored, so searching for it found nothing. The typed fragment is now
   resolved to the addresses it could mean, and matched against those too. Works
   on log history already recorded.
3. **What more can be polled from the APs in the Forti-AP module?**
   → Research, not a change. A costed options list, from what is free today
   through one extra request per AP to a new per-client table and the REST API,
   with a recommendation and a warning: measure the controller before choosing,
   because this MIB has already been caught misreporting its own units.
4. **Stagger node polling so nodes do not all hit the pollers at once.**
   → The scheduler gave every device that came due together the same next due
   time, permanently, so a fleet that started in step stayed in step. Jitter
   was added at two points: the first poll after a restart, which an already
   overdue device now waits for by at most thirty seconds or one interval,
   whichever is shorter; and the first reschedule after that, which only ever
   moves a poll earlier, so once running nothing is polled less often than
   configured.
5. **The Dashboard loads slowly while the pollers are busy.**
   → It was the one aggregate page recomputing everything for every open tab
   every five seconds, fetching up to 5,001 alert rows to count them, and
   scanning a day of events with no limit to show ten. All three fixed.
6. **Identify which nodes have profile overrides.**
   → A marker on the device row naming what it overrides, a sortable Overrides
   column, and an "Only with overrides" filter.

**"Try again"** — after the development model hit a session limit and four
parallel streams died mid-flight.
→ Resumed all four from where they stopped rather than restarting.

## 5.9.1 — In-depth code review

**"Plan with Fable and deploy with up to 5 Opus agents ... An in-depth code
review of the application paying special attention to performance, security,
design quality and maintainability."** — with the standing constraints restated:
comments only where necessary (prose 10% or less), remove nothing without
permission, no push to `main` and no review of the diff (both happen at end of
day), one full test-suite pass at the end, and this log kept per prompt.
→ Branch restarted from `origin/main` (5.9.0), since the designated branch's
history was already wholly inside `main`. Planning questions asked before any
agent was started; see the answers recorded below.

**Planning answers** — deliver a report *and* fix confirmed defects (larger
design items become proposals); the report is `CODE-REVIEW.md` in the repo
root; fixes ship as 5.9.1; scope is everything under `netpath/` (backend and
frontend, vendored xterm excluded), with `demo/` and the test harness out of
scope; benchmarks run only where a fix is meant to move one.
→ Five Opus reviewers by area, one Sonnet gathering code metrics, then a
consolidation pass that re-verifies every finding before any fix is written.

**Review phase complete** — seven reviewers (five backend areas, two frontend)
and a metrics pass returned 81 findings: 2 critical, 17 high, 29 medium, 33 low,
plus 30 larger proposals and 20 unconfirmed items. Every finding was re-read
against the code by the lead before a fixer was given it; two were reclassified
as proposals (a deliberate CA-bundle choice, a reflector best handled in the
runbook). Fixers run in file-owned lanes so no two agents edit the same module.

**Fix phase complete** — eight file-owned lanes (server, data, poller, api,
alerts, trap secrets, frontend core, frontend modules) fixed 79 of the 81
findings; one became a proposal (the update path's CA bundle, a deliberate
choice) and one a runbook note (the trap receiver acknowledging informs from
any source). Every fix carries a test shown red before it. Report in
`CODE-REVIEW.md`; release notes under 5.9.1 in `CHANGELOG.md`; internals and
features updated where a mechanism or a screen changed. Full-suite pass and
the browser walk follow, once, at the end.

**"push to main once complete"** — lifts the earlier hold on `main`.
→ After the final full-suite pass and the browser walk, `main` is
fast-forwarded to this branch and pushed, so the estate updates to 5.9.1.

**Closed out** — the full suite ran once at the end: 140 of 141 passed, the
skip being the desktop console suite (no PySide6 here) and the failure the
pre-existing lock-fairness assertion that fails on unchanged 5.9.0 in this
container too. That run surfaced one integration defect (a sensor-scale clamp
stopping at units where the MIB runs to yotta), fixed before the walk. The
browser walk passed 63 of 63 checks as admin and as viewer with no console,
page or HTTP error. `main` fast-forwarded to 5.9.1 and pushed.

## 5.10.0 — Six asks

**"Plan with Fable and deploy with up to 5 Opus agents ... To work on: [six
items]"** — with the standing constraints restated: comments only where
necessary (prose 10% or less), remove nothing without permission, no push to
`main` and no review of the diff (both happen at end of day), one full
test-suite pass at the end, this log kept per prompt, check on every agent at
least every ten minutes.
→ Planned first; eight planning questions asked and answered before any agent
started. Ships as 5.10.0 on the same branch, above 5.9.1.

**Planning answers** — recovery subjects carry `[RECOVER]` in place of the
level tag; FORTI-AP B5 delivers BSSID plus the *configured* channel width via
the WTP-profile join (the MIB has no per-radio noise floor — struck); an AP
reboot raises a warning rule shipped enabled, a channel change is an event
with its rule shipped disabled; Cisco software version and image are split
from sysDescr with the boot-image path kept as a third field; the HTTPS check
counts 2xx/3xx as available, verifies certificates with a per-destination
opt-out, follows the destination's trace interval, and opens a critical alert
after three failures; device delete becomes an asynchronous background purge
in lock-friendly batches; release is 5.10.0 with this log as the per-prompt
record.

1. **`[RECOVER]` on recovery notifications.**
2. **FORTI-AP A2, B1, B5 and their prerequisites.**
3. **Routes: HTTPS availability check per destination.**
4. **Deleting devices with large history freezes the application.**
5. **Dashboard often blank until another tab is visited.**
6. **Software version and image in the device header, plus a firmware report.**
→ Five Opus lanes (wireless, nodes-firmware, nodes-delete, netpath-https,
frontend-core + alerts subject), Sonnet for docs and demo data.

**Deployment complete** — all six shipped: `[RECOVER]` subjects on recovery
notifications; FORTI-AP's channel-change and reboot events plus BSSID and
configured channel width; a per-destination HTTPS availability check on
Routes with its own alert rule; device delete as an asynchronous background
purge; a Dashboard that paints on the very first load; and software
version/image in the device header, an optional column, and a new Firmware
inventory report. `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`FORTIAP-POLLING-OPTIONS.md`, `NETWORK-AND-STORAGE-REQUIREMENTS.md` and
`RUNBOOK.md` are updated to match. The full test suite and the browser walk
ran once at the end, as the standing constraint requires: 137 of 139 suites passed, 9 skipped for optional dependencies (paramiko, PySide6); the two failures were `test_collectors_hardening.py`, which passed once `traceroute` was installed on the container, and the pre-existing `test_prune_lock_hold.py` lock-fairness flake on `syslog logs` (code this release does not touch, recorded as intermittent since 5.9.0); the browser walk passed 65 of 65 checks including the new cold-load Dashboard check.

## 5.11.0 — Four asks, one deferred

**"Plan with Fable and deploy with up to 5 Opus agents ... To work on: [five
items]"** — the standing constraints restated: comments only where necessary
(prose 10% or less), remove nothing without permission, this log kept per
prompt, check on every agent at least every ten minutes, one full test-suite
pass at the end, then a code review of the day's changes and a push to main.
→ Planned first; two rounds of questions answered before any agent started.
Ships as 5.11.0 on today's branch, above 5.10.0. Subagent lanes in worktrees
rather than a teammate group: the items are independent and each lane's
deliverable is a commit plus a report.

**"What branch are you working off of ... confirm that you see all changes
made today"** and **"Everything will need to be re-run vs the branch from
today and the code review needs to include all changes made to the repository
branches today."**
→ The local checkout was at 5.5.0; the remote carried 5.9.1 on `main` and
5.10.0 on today's branch. All work rebased onto today's branch; the review
covers every commit made to any branch today.

**Planning answers** — the "1 override" marker is the 5.9.0 feature naming
which polling-profile columns a device sets itself; the operator will check
whether those are legitimate and report back (**deferred**). The 7-day option
goes everywhere the mute dropdown appears and the server cap rises to 168
hours. A per-alert mute is scoped to one rule on one device, sharing the
duration dropdown with *Mute device*. The Debug log fix resyncs the page's
cursor after a restart, makes the cursor read atomic, raises the ring to
10,000 events with a setting, and marks the restart in the log. The Neighbours
table keeps its format; an IP-only remote is named through the same chain as
Nodes (device, then DNS cache). Review depth: full for 5.10.0 and the new work,
a lighter pass over the 5.9.1 fixes. At the end `main` is fast-forwarded to
the branch and both are pushed.

1. **Mute a device for 7 days.**
2. **Mute a specific alert on a specific device.**
3. **The Debug event log seems to randomly clear.**
4. **Neighbours: name the remote device.**
→ Three Opus lanes (alerts, debug log, neighbours), then three Opus reviewers,
with Sonnet for docs and the test runs.

**Deployment complete** — four of the five items shipped; the fifth, the "1
override" marker, is deferred to the operator's own check rather than a
code change. The mute cap rose from 24 hours to 168 (7 days) everywhere the
mute dropdown appears, on the server and in both the alert detail and Bulk
mute. A per-alert mute — **Mute alert** beside **Mute device** — scopes to
one rule on one device, stored in the existing `alert_mutes` table as
entity kind `device_rule` with no migration, checked in the engine's
`_apply` alongside the renotify, recovery-mail and held-first-notice gates
it already had, surfaced as a tag on the Alerts list, a count on Nodes and
a named list in the device pane, and carried through `forget_device` and
`merge_device`. The Debug event log's three faults — the page's cursor not
surviving a server restart, the cursor-and-batch read across two lock
holds, and a fixed 3,000-event ring — are fixed: a `log_epoch` per process
plus a cursor-went-backwards check drives a one-time refetch from zero, one
lock hold now covers a snapshot of both cursor and batch, and the ring is
10,000 by default with a new `debug_log_capacity` setting (1,000–50,000)
applied live, with an "Event log started" line marking every restart.
Neighbours names an IP-only remote through the same chain Syslog's Host
column uses — a matched Nodes device, then the reverse-DNS cache — cache
only, with the addresses queued for the background resolver; the CSV
export gained `resolved_name` and `resolved_source`, and MAPPER's own
matching SQL is untouched. `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`
and `RUNBOOK.md` are updated to match. The full test suite and the browser
walk, then a code review of the day's changes, follow once at the end, as
the standing constraint requires — counts and findings appended here when
they complete.

## 5.12.0 — What is no longer in use

**"Your only job is to look for code, documents and files that are no longer in
use and suggest plan for removal."** — the standing working policy, plus a
single standing task: find what is dead and plan its removal, removing nothing
from the GUI without express permission.
→ Audited the whole tree mechanically rather than by reading: 1,865 top-level
Python definitions, 1,295 methods, 1,091 imports, 72 modules, every static
`.js` symbol, 294 CSS classes, 108 custom properties, 261 HTTP routes, 237
settings keys, 151 test suites, 21 bundled MIBs. The tree was close to clean —
about 210 lines of genuinely dead code in a 3.5 MB package, and not one
orphaned module, file, dependency or test. What was actually recoverable was
2.0 GB of disk, eleven stale branches and three documents that were working
records rather than product documentation.

**Removed:** `ipam_scan.scan_subnet()` (a pre-composed wrapper superseded by
`IpamWorker._scan` composing `sweep`/`read_arp_table`/`usable_addresses`
itself), `dpapi.self_test()` and `secretstore.self_test()` (written for a
"Check encryption" button that was never built), `HttpsChecker.check_now` (a
copy of the live `HopProber.trace_now`, never routed), `nodesdb`'s unused
`import threading`, `PDU_SET` and `enc_oid` from `snmppoll`'s trapdecode
import, the `--vlan-1..16` design tokens and their test contract (superseded by
`--canvas-vlan-*`, which every consumer had already moved to), `a11yTable()`,
two unreferenced `STATUS_COLOR` objects, two unreferenced `ago` bindings and the
`.dot-inline` rule. Nothing removed rendered anything: zero pixels changed.

**Archived, not deleted** — `docs/history/` now holds `CODE-REVIEW.md` (a
session log whose findings are all marked fixed, kept as the audit trail for
security work), `FORTIAP-POLLING-OPTIONS.md` (whose own header declares its
implemented parts historical, kept for per-OID measurements recorded nowhere
else) and `DEMO-EVALUATION.md`, a 588-line fleet evaluation rescued from an
abandoned branch that was 439 commits behind before that branch was dropped.

**Three findings were not cleanup, and were fixed rather than deleted.** The
self-update verified path — newest tag plus published `SHA256SUMS` — was fully
implemented and tested but never called, so `apply()` followed the mutable
`main` tip with nothing checking the bytes it swapped in. It is now wired up,
with an explicitly logged fallback and a hard abort on digest mismatch. This
repository carries one tag and no releases, so the fallback is what runs until
the release process starts cutting tags with a `SHA256SUMS` asset: the change
is correct and dormant, and engaging it is a process change, not a code one.
`RUNBOOK.md` was missing from `_COPY_ALONGSIDE`, so every self-update stripped
the on-call runbook from the install that README tells the operator to read
before going live; it now ships. And `alertsdb.purge_expired_mutes()` had no
callers — but `prune()` was already deleting those rows with its own inline
SQL, so this was duplicated logic rather than the storage leak it first looked
like; `prune()` now calls the method instead of re-implementing it, at
identical behaviour.

**Flagged, not actioned:** eleven pieces of live duplication (a whole
seven-function time-window controller reimplemented across `netflow.js` and
`netpath.js`, the bulk-selection trio written three times, `histogram()` in two
stores), five routes with no front-end caller that are deliberate token-API
surface, and a mechanical split for `api.py`'s 10,268 lines along the 27
section boundaries it already carries.

## 5.13.0 — Neon Signs, and the backlog nobody had actioned

**Team setup** — a named team for this release: Bob leads; Troy and Laura on
Opus; Testy, Fisty and Stephen King on Sonnet; Securitas on Opus; Dingus1 and
Dingus2 on Haiku; Javariius reviewing on Fable. Standing rules: no HTML docs,
comments capped at 20% prose, nothing removed from the GUI, everything written
for a network engineer or CTO reading it, plan before running to completion.
Testy runs no repeated full suites and drives the browser walk instead; Stephen
King keeps this prompt log; Javariius reviews before any push. Two work items:
a Neon Signs theme with neon tubes running across the page, bright but
readable and contrasty, and a sweep of the previously flagged backlog with a
plan to implement it.
→ Team and rules recorded; work assigned across the waves.

**Planning answers** — build the Neon theme together with Tier 1 (twelve
small items) and Tier 2 (the medium refactors and the eleven duplications);
Tier 3 (trap decryption, the three big file splits, GETBULK interface reads,
SQL-paged upstream suggestions, the generation scheme, the webhook credential
slot, ETag on the device list) is deferred to a written proposal rather than
built. The Neon theme: glow on structure only, no flicker; electric cyan as
the accent, hot pink for fail, lime for ok, yellow for warn.
→ Neon shipped: eighth theme, three new `--tube`/`--tube-text`/`--tube-line`
  tokens, glow hooks across structure, all eight themes' AA pairs
  recomputed (tightest 5.49:1).
→ Tier 1 shipped in full: all twelve items landed (chart range, 404s,
  get_debug split, login 503, app.db warning, syslog cursor, dialog
  pollers, mapper scene, address refresh, pattern cache, paramiko and
  CREDENTIAL-SECURITY prose).
→ Tier 2: eight of eleven landed (nodes.refresh split, drawRows, window
  helpers, escaping contract, mapper_upstream split, drain contract,
  PREDICATES, best_effort); histogram dedup, WEB-P3 and API-P2/P3 landed
  after that note. API-P3's contract found `_discovery_result_json` handing
  the SNMP community to read-only accounts; fixed.
→ Review (Bob, after Javariius hit the account's Fable quota): two fixes —
  an access-denied optional SNMP read is not a credential verdict, and a
  body field naming a missing device stays a 400. Comment prose trimmed
  from 25% to 18% of added lines.
→ Suites: 153. The first full run was killed for memory at 121 with
  agents still alive; the other 32 ran individually. 141 pass, 1 skipped
  (no PySide6), 11 fail identically on the pristine base or on this
  cp1252 console (palo_alto_polling, prune_lock_hold, selfupdate_job,
  service_shutdown, snmpv3_diagnostics, snmpv3_keys, snmpv3_priv_e2e,
  https_check, ipam_dhcp_temp, temppath, wireless_radio_events). Eight
  suites needed 400→404 updated for the new not-found path, one fake
  service needed a permissions stub.
→ Walk: 932 steps, 887 ok, 45 planned skips, 0 failed; the 40 console
  errors are the viewer/NOC 403s the matrix provokes, the 3 page errors
  are on paths this release did not touch.

## 5.14.0 — The Nodes database, and what it keeps

**Team setup** — a named team for this release: Bob leads; Dora explores;
Thing1 and Thing2 on Opus; Testy, Fisty and Stephen King on Sonnet; Dingus1
and Dingus2 on Haiku; Javariius reviewing on Fable. Standing rules carried
forward. Task: reduce the nodes database's size, verify temp data (MAC/ARP)
is actually aged out, split long-term from short-term storage, list what is
kept forever, and propose options.
→ Team and rules recorded; task assigned across the waves.

**Planning answers** — build the trim-floor fix, a storage report, per-port
retention tiering (1 day raw, 90 days hourly; device-level stays at 3/400),
the WITHOUT ROWID rewrite, and device_addresses age-out tied to the 180-day
event retention. Defer the hour-index watermark, the daily tier and
zero-suppression. Raise the series cap default from 1 GB to 8 GB. The user
will run the storage report against the live install before defaults are
final.
→ Aging verified: MAC, ARP, LLDP and VLAN tables age out at 7 days, events
  at 180, discovery at 30, per-port raw at 3 days, hourly at 400 days.
→ Stored forever, by design and otherwise: inventory tables, vendor_learned
  and MIB files are correctly permanent; device_addresses and stuck
  discovery jobs are leaks with no age-out path.
→ Where the bytes go: 94% of metrics are per-port; each sample is stored
  three times over; default retention at 250 devices runs to roughly 39 GB
  against a 1 GB cap, so the cap is trimming raw data to a 5,000-row floor
  every minute.
→ Part 0 (trim floor): both floors under `trim_to_size` now scale with the
  metric count instead of a flat 5,000, and the stage order is reversed —
  hourly rollups give up their oldest hours first, raw samples only once
  those are at their own floor.
→ Part 1 (storage report): `netpath/dbreport.py` reports every store's
  exact row counts and measured-or-estimated bytes, on the command line
  and behind `GET /api/db/report`; Settings → Data & Retention gains a
  per-file expand and a line naming whether the cap or the retention
  setting is what actually bounds Nodes metric history. The series cap
  default rises from 1 GB to 8 GB; saved values untouched.
→ Part 2 (retention tiering): `metrics.scope` distinguishes per-port from
  device-level (a dot in the key, not the `if_` prefix); two new settings,
  `interface_sample_retention_days` (1) and `interface_rollup_retention_days`
  (90), carry the same 1..3650 floor as the existing rollup setting;
  `series()` picks raw versus hourly per metric by its own class. Shortens
  per-port history on the first maintenance pass after upgrade, and is
  one-way for data already gone.
→ Part 4 (device_addresses age-out): a complete walk marks the addresses
  it did not see `present=0`, following the walk-table shape already used
  for MAC/ARP; prune deletes those rows on the existing 180-day event
  clock; a present alias wins resolution over a stale one; a discovery job
  stuck `running` past the window is pruned alongside it.
→ Table rewrite landed: samples and samples_hourly WITHOUT ROWID (23.8 /
  47.5 B/row from 66.7), copy-and-delete migration rehearsed against a
  copy of this box's live file with a stop and restart: 230,485 rows
  before and after, 21.9 MB → 7.0 MB, peak +215 pages.
→ Review (Javariius, two passes): nine findings, then two more, all
  closed — the prune's band probe had become a full scan of samples, the
  migration's tail catch-up was unbounded, the cap line blamed the cap
  on every young install, the batched alias lookup ignored `present`,
  a purge walked the fleet's id space to its device. Prose 27.8% → 19.8%.
→ Suites: 157. One full run, alone: 145 pass, 1 skipped (no PySide6),
  11 known pre-existing failures, and one test expectation updated (a
  budgeted purge step may now finish the raw table before the hourly).
→ Walk: 932 steps, 887 ok, 45 planned skips, 0 failed; the 40 console
  errors and 2 page errors are the viewer/NOC permission refusals the
  matrix provokes. Storage panel expand and the two per-port fields
  checked by hand.
→ Pushed to main.
→ Post-release Q&A: "I'm struggling with the dbreport command - please
  elaborate" — run it from the install directory as
  `py -m netpath.dbreport <data_dir>`. "How long should the command take
  to run? The database file immediately got larger after I updated the
  application." — dbreport itself runs in seconds; the file growth is
  separate, expected while the background rewrite is in progress and
  because the cap no longer trims as aggressively.

## 5.15.0 — [title tentative]

**Team setup** — a named team for this release, same roster and rules
carried forward from 5.14.0: Bob leads; Dora explores; Thing1 and Thing2
on Sonnet; Testy, Fisty and Stephen King on Sonnet; Dingus1 and Dingus2 on
Haiku; Javariius reviewing on Fable. Two work items assigned:
(a) new ConfigRX backups show only time taken, not the date;
(b) flesh out and polish firmware versions across all included MIBs —
the Node → Device → Device Details dialog must show firmware version
regardless of vendor; the firmware report must identify and export
firmware and software versions for every device with an included MIB
and auto ID; the report's Device field must include IP address and
name (SNMP, manual, or DNS).
→ Team and rules recorded; task assigned across the waves.
→ Planning answers: two fields throughout, software and firmware version,
  not one; the Device Details dialog always shows the software-version
  line regardless of vendor; the firmware report's Device field renders
  as "name (ip)" with the name source (SNMP, manual, or DNS) noted; the
  ConfigRX backup list's Taken column always shows date and time, not
  time alone.
→ ConfigRX: the Taken column dropped the date whenever a device's backups
  all fell inside one hour (a freshly added device); it now shows date and
  time on every row.
→ Device Details always shows the software line ("not reported" when
  nothing answered) with the source in brackets, and a firmware line when
  the device has a separate boot/firmware version.
→ Versions: 19 more vendor arcs answer from their own MIB object (every
  OID re-derived mechanically from the catalog MIB text; four were wrong
  in the first pass and fixed); five vendors read a table column; the
  ENTITY-MIB fallback finds the chassis row instead of index 1; walks are
  gated to once a day per device. WatchGuard, Rittal and Netgear's old
  broadcom tree have no pollable object and stay on sysDescr/ENTITY.
→ Firmware report: Device is "name (ip)" with the name source (sysName,
  manual, reverse DNS, ip), a Firmware column, five new CSV columns.
→ Javariius: nine findings over two passes, all fixed, approved.
→ Full suite 151/157, the six known environmental failures only.
→ Browser walk 890 steps ok, 0 failed; a firmware-report step added.
→ Pushed to main.

## 5.16.0

**Team setup** — a named team with eight work items assigned across the
roster: (1) "Non-default profile counted as an override" — discovery
promote pins the sweep's own community as if it were special; (2) "IPAM
Conflicts wired to every IP source" — device ARP tables, addresses and
learned MACs never reach IPAM; (3) "Per-sensor temperature thresholds
from SNMP, all catalog vendors"; (4) "Power-supply loss alert" — nothing
polls PSU state today; (5) "Mapper: port/VLAN labels crossed by lines;
names should be hostname/DNS/SNMP plus IP"; (6) "Checkbox: drag selects
or pans"; (7) "More of the name in the node box"; (8) "Learned MACs in
the port dialog" — the dialog only ever waits on a live SNMP read.
→ Planning answers: learned MACs feed IPAM as a "seen" source with the
  switch and port shown on the address; the obscured mapper text is the
  port/VLAN labels, not something else on the canvas; device-reported
  thresholds are read first, with the existing chassis rule and
  per-device override kept as the fallback for a device with nothing
  better to offer; a PSU alert fires on failed/no input/shutdown for a
  present supply, never on an empty bay.
→ Clarification: the port dialog's MAC field should fill from the
  stored, previously-learned table rather than waiting on a live walk.
→ "Do not spawn any agents or teammates other than those listed."
→ "1"
→ /schedule and /loop status requests: a 15-minute status loop set for
  the release.
→ Plan approved.
→ Interruption: "Why are you continuing to spawn Fable agents when you
  have been directed not to do so?" Thing2, running on Fable in error,
  was stopped and respawned on Sonnet; a memory note was written so
  every roster name is spawned with its assigned model from then on.

## 5.17.0 — Find box uplink hits, chart tooltips, syslog name search, neighbour name + IP

**"do not push to main - let me know when u are done and we will start the
next work"** — a hold on `main`, to be lifted only once told.
→ In force for this release; no push without a further instruction.

**The 5.17.0 work prompt**, four items:

1. Node search must not include LLDP entries that match.
2. Device Details graphs need tooltips.
3. Syslog cannot be searched for part of a host name.
4. Neighbours tab should show the remote device name as well as its IP.
→ Traced and planned before any agent started; see the planning answers below.

**Planning answers** — the Find box case is a MAC search hitting
uplink-learned entries; Neighbours rows show name and IP on every row;
tooltips show the time and the value at the cursor; the syslog case is the
free-text box, with the Host column already showing the Nodes name that
free text could not search on.
→ Plan approved; work assigned across the roster.

## 5.18.0 — Port names, device names everywhere, IPAM in-use rows, MIB auto-assign, chart ranges, mapper drawing and matching

**The 5.18.0 work list**, nine items:

1. "Local port shows 'if 12' instead of a real port name."
2. "Remote device on Neighbours shows only the IP, no name."
3. "IPAM addresses that are in use but not leased don't show on the DHCP
   grid."
4. "Mapper's Add-neighbours list doesn't resolve names for peers."
5. "A MIB the app picked itself counts as an override."
6. "The interface bandwidth chart is stuck at one hour."
7. "Mapper draws labels under the link lines, and VLAN numbers stack on
   top of each other."
8. "Mapper misses a neighbour that Nodes can place by IP, and draws no
   link for it."
9. "Reports show the bare IP twice — once where a name should be."
→ Traced and planned before any agent started; see the planning answers
below.

**Planning answers** — Local port should show the short ifName form
(Gi1/0/10); the interface chart gets the same range list as the Packet
loss chart; IPAM's in-use-not-leased addresses are mixed into the lease
grid itself, with the State column saying "in use, not leased" rather
than sitting only on the summary donut.
→ Causes traced for all nine; plan drafted.

**"i have updated the CLAUDE.md file can you please confirm you see it and
understand its directions?"**
→ Confirmed: exploration from here on must go through the deep-code-explorer
skill, reporting back in its six-section form.

**Further planning answers** — the Mapper fix has to cover both what
Add-neighbours offers and what actually draws as a link, not just the
candidate list; this round's name-chain sweep covers Reports, Neighbours
and the Mapper, with every other bare-IP site (Alerts, Events, NetFlow
talker labels, Dashboard tiles, Wireless, IPAM host names) listed for a
future round rather than touched now.
→ Plan updated to match.

**Plan approved.**
→ Work assigned across the roster; lanes run in parallel in main's working
tree.

## 5.19.0 — Twilio SMS alerting

**Team-rules prompt** — same standing rules as before, with the work item:
"Implement Twilio Text Message integration on alerts. Each alert should have
the ability to turn on or off SMS texting just like email."

**Planning answers** — one global SMS number list in Settings → Alerts with a
per-rule on/off toggle; SMS follows email's timing (roll-up hold, digest,
re-notify, recovery texts) with its own hourly cap; a fixed short text of at
most 160 characters, no template editor; Twilio set up with Account SID, Auth
Token (stored encrypted like the SMTP password), From number, optional
Messaging Service SID, and a "Send test text" button.
→ Plan approved.

## 5.20.0 — Twilio API keys

**Team-rules prompt** — the standing rules as before (named team led by Bob;
no HTML pages for documents; comments at 20% prose or less; nothing removed
from the GUI without permission; speak to the operator as a network
engineer/CTO; Testy runs the full suite once after changes and walks only
edited modules without screenshots; Stephen_King keeps this log; Javariius
reviews before the push to main), with the work item: "Twilio SMS
functionality was added with only 'Auth Tokens' please also add the ability
to integrate with Twilio API keys."
→ Dora mapped the 5.19.0 Twilio code (hand-rolled REST in alertmail.py, the
auth token in its own DPAPI-encrypted single-row table bound to the Account
SID, one fieldset in the Alerts settings dialog).

**Planning answers** — an "Authenticate with" selector (Auth token | API
key) with the Account SID always shown; one stored secret at a time, the
existing sms_credential row widened with auth_mode and api_key_sid columns,
existing installs migrating as auth_token; version 5.20.0; branch pushed
then main fast-forwarded, no pull request.
→ Plan written and approved.

**Plan approved.**
→ Thing1 on the backend, Thing2 on the dialog, Testy/Fisty on verification,
Javariius on review.

**Deployment**
→ Thing1 built the backend, Thing2 the dialog; Bob closed the stale-key-SID
gap. Testy ran one full pass plus a headless dialog walk. Javariius
approved with nits (test precision, a mode-switch guard in the dialog, a
stripped key SID), all closed before the branch was pushed and main
fast-forwarded.

## 5.20.1 — SMS consent notice

**"Test SMS is failing immediately."** — traced with the operator to a
blank From number, not a fault; the stored API key and the test route
were proven against a Twilio stub.
→ No code change; operator set the From number.

**"Give me sample SMS messages ... for A2P Campaign examples"** —
samples built from the real text builder (severity tag, rule, entity,
detail), with the note that alert texts carry no brand name.
→ Samples handed over for the campaign submission.

**Twilio opt-in rejection reply** — advised in-app consent rather than
a verbal script; drafted the reply and the consent wording.
→ Reply sent; wording carried into the plan.

**"Add the consent notice and push to main"**
→ Thing2 added the notice and a contract check, Stephen_King the docs,
Javariius reviewed, branch pushed and main fast-forwarded.

## 5.20.2 — TLS behind an inspecting firewall

**"After adding the correct from number I get this error: ... Missing
Authority Key Identifier"** — diagnosed as Python 3.13's stricter
`VERIFY_X509_STRICT` X.509 checking meeting an SSL-inspecting firewall's
re-signed certificate; one shared verified context, with that one flag
cleared, now used by the Twilio, webhook and SMTP senders alike.
→ Javariius reviewed; branch pushed and main fast-forwarded.

## 5.20.3 — The HTTPS monitor behind an inspecting firewall

**"Yes, fix the HTTPS monitor too"**
→ One shared `verified_context()` in `tlscontext.py`; `alertmail` and
`selfupdate` build on it, so the HTTPS monitor and the self-updater
verify like the senders now do. Javariius reviewed; branch pushed and
main fast-forwarded.

## 5.20.4 — The auto-assigned MIB, repaired for the fleet

**"I need a way to clear the single override that is listing on 300
devices from when the auto vendor ID assigned their MIB..."**
→ Dora found the rows carry no auto marker from before 5.18.0 — the
`mib_file_auto` column didn't exist yet when they were written, so
they're stored the same as a hand-picked MIB. Planning answers: a
one-time startup repair rather than a bulk action, scoped to devices
whose only override is a vendor-matching MIB, leaving any other
override or a non-matching MIB alone. Thing1 built it, Javariius
reviewed, branch pushed and main fast-forwarded.

## 5.20.5 — The auto-assigned MIB, repaired for the fleet (second pass)

**"Not sure how long this should take but it appears as though the
nodes still show the 1 override item"**
→ The 5.20.4 signature checked the stored MIB against the vendor's
largest uploaded file, but `_auto_assign_mib` had always used the
identification walk's own pick instead, so any vendor with more than
one uploaded file left most of its devices skipped. Widened the
match to any of the vendor's covering files and reran the repair once
under a new marker. Javariius reviewed; branch pushed and main
fast-forwarded.

## 5.21.0 — A modular Dashboard, and global find to the switch port

**Team-rules prompt** — the standing rules as before, with four work items:
(a) global find should show an IP or MAC's hits on switch-port MAC tables
and ARP tables, naming the port; (b) the Nodes CSV export lists the IP in
both the Name and IP columns; (c) the Debug Event log resets its scroll
position on every new event; (d) make the Dashboard modular — rearrange
tiles, add and remove them, from a catalogue of tile types including
interface graphs, taking cues from SolarWinds, Auvik, PRTG and Zabbix.

**Planning answers, round one** — an IP search today surfaces only the ARP
row, so the fix chains ARP to MAC to switch port; dashboard layout is per
account, saved on the server; tiles drag-to-reorder in a grid with a
per-tile width setting rather than free placement; one dashboard per
account.

**Planning answers, round two** — all four tile families ship: graphs,
single-device status, module overviews, and lists/notes; an explicit Edit
layout button rather than an always-editable canvas; one release, 5.21.0,
rather than shipping the fixes first; graphs default to a 24-hour window
refreshed every 60 seconds.

**Plan approved.**
→ Work assigned across the roster: Thing1 the backend (both fixes, the
layout storage and routes, `/api/nodes/events`), Thing2 the frontend
(the scroll fix, the shared chart renderer, `dashboard.js` and its
catalogue of 24 tile types), Stephen_King the docs. Testy ran the full
suite (152/158; the six failures were environmental or pre-existing on
main) and a headless walk of Dashboard, Debug, Nodes CSV and global find.
Javariius found one blocker (a graph tile with no device chosen made the
layout unsaveable) and sixteen smaller findings; all closed, re-review
"ready to push". Fisty chunked the new MAC query to the bulk contract and
re-pinned the Workers tile check. Shipped as 5.21.0 on `main`.

## Team rules in the repo

**Does the web portal have a CLAUDE.md file I can edit so that I don't have to give
the same instructions with every prompt?** — Yes. The repo's `CLAUDE.md` is loaded
at session start from the fresh clone; it held one line pointing at the
deep-code-explorer skill.

**Set them up for me** — Standing rules written into `CLAUDE.md`; nine named
teammates defined under `.claude/agents/` with their models pinned. The
unnamed `deep-explorer.md` agent was folded into `dora.md`.

**Please check the repo now for the deep-code-explorer skill and the explorer
agent** — Found on `main` in `54c699e`, pushed from another device after
5.21.0. The skill now runs as Dora, so no unnamed agent is spawned.

→ Javariius reviewed the ten files against the operator's verbatim rules;
one wording fix. Committed on the session branch and fast-forwarded to `main`.

## 5.22.0 — TACACS+ sign-in, richer dashboard graphs, and a look at history

**Operator prompt, five items:**
- Add TACACS functionality for logging into the system
- Dashboard graphs tile - I would like to be able to add multiple interfaces
up/down traffic to a single graph. Graphs should also be able to be named
and have a built in drop down to change the timeline period without having
to 'edit layout' and then configure the tile. You should be able to set a
maximum value for the graphs.
- When adding an interface traffic graph on the dashboard the auto fill
suggestions popup should match the theme. Currently it looks similar to a
browser autofill which could be confusing.
- All graphs should have the ability to drill down and select dates and
times.
- Research how the most popular network monitoring systems retrieve,
display, filter and output historical data for devices, interfaces,
environmental sensors, CPU, etc and give me options for different ways to
implement into the GUI and platform.

**Planning answers** — TACACS+ falls back to local accounts only when the
AAA server is unreachable, and an explicit reject from the server is final
(no silent fallback to local on a reject); local accounts are never sent
to TACACS+ for verification; a TACACS+ user gets one configurable default
role and is auto-created on first successful sign-in; the multi-interface
graph extends the existing Interface traffic tile rather than adding a new
tile type; drill-down (drag-to-zoom plus an explicit date/time picker)
goes on every chart with a time axis, not just the dashboard; a time
window picked directly on a tile (outside Edit layout) is saved back to
the account's dashboard layout immediately; the research is delivered as
both a chat summary and a standing reference doc,
`docs/HISTORICAL-DATA-OPTIONS.md`, with no history-explorer feature built
yet — it is a menu of options for a future decision. Version for this
work: 5.22.0.

→ Thing1 the backend (`tacacsclient.py`, the third `auth_source` and
auto-create path in `post_login`, the widened dashboard layout schema and
`GET /api/nodes/series/batch`), Thing2 the frontend (the multi-interface
tile config form, the on-tile window control, the themed device
combobox, and the shared `Custom…` range dialog plus drag/wheel/keyboard
zoom wired onto every time-axis chart), Stephen_King the paper and the
docs. Testy ran the full suite once (161/167; the six failures were the
four known environmental ones plus two real single-assertion misses in
the frontend commit) and a headless walk of Dashboard, Nodes, Settings,
NetFlow, Routes, Syslog/Trap and Alerts (61/69 first time). Fisty found
the walk's real causes: the shared range dialog answered Apply as
cancelled because the modal closed before the promise settled, an
unconfigured Interface traffic tile sent an empty interface list the
server refuses, and the combobox duplicated the panel-surface rule.
Javariius reviewed three times: first pass "not ready" with two high
findings (drag-zoom wrote fractional timestamps the server refuses; the
PAP START carried minor version 0, which the reference daemon rejects)
and eleven smaller ones, all closed by Fisty; second pass caught that
wheel ticks recomputed from a stale window, closed by Bob; third pass
"ready to push". Final state: full suite 163/167 with exactly the four
environmental failures, the walk 69/69 on the release commit. Shipped
as 5.22.0 on `main`.

**Javariius's review, four corrections before push:** two `FEATURES.md`
passages overstated what a drag or a wheel-turn does to the device and
interface dialogs — only picking **Custom…** actually closes and
reopens the dialog; drag and wheel just pin the chart where it is,
dialog untouched. `CHANGELOG.md` overstated the zoom refactor — NetFlow
and Routes keep their own existing wheel/keyboard/brush code and only
picked up **Custom…**; the new shared `App.attachChartZoom` helper is
what the Dashboard tiles and the Nodes charts actually run on. One gap
Javariius flagged in the TACACS+ write-up: with auto-create on, an
existing local account is answered without ever reaching the AAA
server while an unknown one is sent on to it, so a caller can tell a
real local username from a made-up one just by which reply comes
back — called out plainly in `FEATURES.md` and
`CREDENTIAL-SECURITY.md` §12, with auto-create-off as the way round it
where that matters. One addition alongside the fixes: Dashboard tile
wheel-zoom now needs Ctrl/Cmd held, since a tile lives on a page that
still needs to scroll under a plain wheel; drag-zoom is unchanged.
Noted for the record in `INTERNALS.md` too: the PAP START this client
sends carries minor version 1 (`0xC1`, RFC 8907 §5.4.2.2) and the reply
is decoded using the version byte the *reply* actually carries, and
`Service.authenticate_tacacs` now remembers an unreachable AAA server
for ten seconds so a server outage fails every concurrent sign-in fast
instead of making each one sit out the full timeout.
→ Stephen_King. `FEATURES.md`, `CHANGELOG.md`, `CREDENTIAL-SECURITY.md`,
`INTERNALS.md` corrected and extended; no code touched.

## 5.23.0 — History options A/E/G, priority-port alerting, NetFlow gaps, and Mapper fixes

**Operator prompt, nine items:**
- Proceed with options A, E and G from `docs/HISTORICAL-DATA-OPTIONS.md`.
- Add uptime as a column choice on Nodes → Devices.
- Question: does the app have an API receiver for external API requests,
  or is the API only how the GUI talks to the backend?
- Do not include poll overruns in the device details dialog's event log.
- NetFlow export has no timestamps.
- NetFlow randomly misses large blocks of data over 24 hours and over
  3 days.
- Mapper PNG export uses different fonts than the screen and items
  overlap.
- Add a manual line between two devices on Mapper.
- Alert only on ports flagged Priority when they drop link.

**Planning answers** — Wireless history (option G) covers only what is
already polled today — client counts per AP and radio, channel, tx
power, online state — no new SNMP columns are added to get there.
Priority-flagged ports get a new, dedicated built-in rule, "Priority
interface down"; the existing Interface down rule is untouched and
keeps firing for every port as before. Scheduled reports (option E)
send a summary body plus a CSV attachment on a daily, weekly, or
monthly schedule. The NetFlow gaps get all three suspected causes
fixed, not just one: templates being dropped on any NetFlow settings
save, the raw-row cap deleting flows before they're summarised into
rollups, and wide chart windows silently falling back to thinned raw
rows when the minute rollup doesn't reach back far enough — plus a
coverage readout so a gap is visible instead of silent. Version for
this work: 5.23.0.

**Bob's answer on the API question** — Yes: every `/api/*` route
accepts an `Authorization: Bearer` API token as well as the browser
session cookie. Tokens are issued and revoked under Settings → Tokens
(admin-only), carry the issuing account's own permissions, never
expire from inactivity, and never mint a cookie. Scripts get past the
CSRF check because a request with no `Origin` header is accepted.
There is no inbound data-push receiver beyond the existing syslog,
trap, and NetFlow protocol listeners — nothing else accepts pushed
data from outside.

**Also recorded:** a short Status paragraph was added under the
Recommendation section of `docs/HISTORICAL-DATA-OPTIONS.md` noting the
operator's choice of A, E and G and how each shipped — A as the Nodes
→ HISTORY sub-tab with a series CSV export route, E as Nodes → Reports
→ SCHEDULED, and G as per-AP client/radio history in the Wireless AP
detail pane.

**Outcome.** Thing1 and Thing2 built the nine items above: three NetFlow
gap causes closed (template carry-over across a collector restart, the
row cap no longer outrunning the minute rollup, a wide chart widening
its own bucket instead of falling back to thinned raw rows) plus a
history/coverage readout on the NetFlow status strip; readable local-time
columns on the flow, Syslog and SNMP Trap CSV exports; priority ports
(`interface_flags`, a dedicated `priority_interface_down` alert rule
gated to flagged ports, `link_up` clearing it alongside the existing
`interface_down` rule); scheduled emailed reports (`reportsched.py`,
`report_schedules`, up to 50 schedules, reusing Alerts' own SMTP
settings); the Nodes → HISTORY explorer and its series CSV export; wireless
AP/radio history sampling with a new `max_wireless_db_mb` size cap; the
Mapper PNG export's font/style fidelity and pixel-density fix, plus the
new Connect tool for manually drawn map links; an optional device Uptime
column; and the device dialog's event log dropping poll-overrun entries.
Stephen_King wrote `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`NETWORK-AND-STORAGE-REQUIREMENTS.md` and this entry against the diff
(`e8cdc01..HEAD`, implementation commit `bf9b5ee`), reading the actual
code for every claim rather than the task description alone; the wireless
history disk estimate in `NETWORK-AND-STORAGE-REQUIREMENTS.md` is
arithmetic from the row layout, not a measured benchmark, and is
labelled as such. Testing: the full suite on the release commit passed 159 of 164 with only the four environmental failures this container always shows (SMS passphrase, traceroute, the prune-lock timing check and the SNMP socket family in the web-gates test), and the browser walk passed 76 of 76 with no console, page or HTTP errors as admin or viewer. One real regression surfaced on the first pass and was fixed: the Reports UI contract test pinned four Nodes sub-tabs and now pins five. Javariius reviewed twice; the first pass found five should-fix items (a whole-fleet Top-N schedule with no window cap, a v5 exporter with a future clock able to pin the NetFlow row cap, unvalidated wireless history settings, missing tests for the rollup catch-up and coverage code, and comment density) plus nits, all closed before the second pass returned "ready to push".
→ Stephen_King. `CHANGELOG.md`, `FEATURES.md`, `INTERNALS.md`,
`NETWORK-AND-STORAGE-REQUIREMENTS.md` written for 5.23.0; no code
touched.
