# SappiWhere 4.35.0 — a network engineer's review

Reviewed at commit `05259ae` (Merge 4.35.0) on 2026-09-02, from the point of view of
an operator responsible for a very large mixed fleet: thousands of switches,
firewalls, wireless access points, point-to-point wireless bridges and
industrial PLCs. The question throughout was practical: *would this tool make
monitoring and maintaining that fleet faster, and what has to change before it
does?*

Nothing in `netpath/` or `tests/` was modified for this review. Every finding
row in §4 carries a `file:line` reference and a tag, and the tags mean exactly
this:

- **CONFIRMED** — either the behaviour was produced by running code (one of the
  reviewers' benchmarks, fuzzers, stub agents or experiment scripts, or the live
  campaign in §3), or the finding is the *absence* of something and that absence
  was established by exhaustive search of the shipped source. A CONFIRMED row
  states what was run or searched.
- **PLAUSIBLE** — traced in the source and reasoned about, but never executed.
  The mechanism is real in the code; the consequence is an inference. Four rows
  carry this tag (P-S7, P-S8, S-N13, X-F23) and each says why.

Identifiers are prefixed by section — `P-` polling core (§4.1), `C-` collectors
(§4.2), `A-` alerting (§4.3), `S-` security (§4.4), `X-` performance (§4.5),
`U-` UX and documentation (§4.6) — because the first draft of this report reused
`B1`, `S1`, `N1` and `F1` in several sections at once and its own cross-references
became ambiguous. Every row in the documentation-truth table at the end of §4.6
was checked against the code or the running application and is CONFIRMED.

Bugs are documented here with proposed patches; none were applied, by request.
Appendix C records what a re-review of this document withdrew, corrected and
added, and §9 records what was subsequently implemented.

Companion material: the `demo/` directory holds the reproducible harness used
for the live demonstration (see §2 and `demo/README.md`).

---

## Verdict

SappiWhere is a well-engineered *interface-counter and path monitor* with an
unusually careful SNMP implementation, a good alert-state model, excellent
collector decoders and honest documentation. It is not yet a *fleet* monitor for
the network described above, for four structural reasons:

1. **On Linux it cannot hold a secret.** Every stored credential goes through
   Windows DPAPI (`netpath/dpapi.py:49-50`), and eight API endpoints refuse to
   store one anywhere else (`netpath/web/api.py:1411, 2346, 2464, 2542, 3243,
   3485, 3777, 3810`). A Linux headless install therefore has no SNMPv3
   authNoPriv polling, no ConfigRX backups, no authenticated SMTP and no stored
   wireless credential. That is the README's own documented deployment shape.
2. **It sees only IF-MIB on non-Linux gear.** CPU and memory come from
   UCD-SNMP-MIB alone (`netpath/nodeoids.py:58-63`); `HOST_RESOURCES` is
   declared and never read (`nodeoids.py:64-67`). Nothing polls Cisco, Aruba,
   Juniper, Fortinet or Palo Alto health OIDs, environment sensors, PoE, LLDP,
   ARP, BGP, firewall sessions or wireless RF metrics. Seven of the 32 built-in
   alert rules can never fire because nothing produces their metric key.
   *(4.37.0 ships 35 built-in rules and all seven of those are live; see §9
   A-F1 and P-S9.)*
3. **A site outage is N alerts, not one.** Rollup is same-device only
   (`netpath/alertrules.py:142-189`); there is no topology, no upstream field,
   no LLDP/CDP discovery to build one from, no maintenance calendar (device
   mutes are capped at 24 h), and email is the only channel.
4. **Its history is being thrown away.** `sample_row_cap_per_metric` is applied
   as a whole-table cap (`netpath/nodesdb.py:2171-2179`), so every 15 minutes the
   fleet's metric history is trimmed to 50,000 rows total, and the hourly rollup
   that should replace it (`compact_rollup`, `nodesdb.py:1480`) is never called.
   At fleet scale no chart can draw a line, and the prune stalls the process.

The live campaign put numbers on it: at 250 devices the poller and the alert
engine behaved as designed (143 dark devices → 143 alerts, correctly rolled up
per device); at 1,000 devices the 32-worker pool was saturated at idle and a
500-device site outage produced 16 `device_down` alerts in four minutes; at
2,000 devices the same outage produced **none**, because each device was being
polled once every four minutes against a 60 s profile. Meanwhile every tier
opened one `mib_missing` alert per device on first poll, emailed as "is not
responding".

Every one of those is fixable, and most of the code needed already exists in the
repository. §6 ranks the work. The short version: fix the retention and write
path (two days), add a platform-neutral secret store, poll vendor health OIDs
through the existing best-effort GET, add an upstream-device field and a webhook
channel to the alert engine, and build the empty Dashboard. That turns a good
path monitor into a usable fleet monitor.

**Already resolved upstream while this review was being written.** Releases
4.36.0 and 4.36.1 shipped an SSH host-key store (`netpath/hostkeys.py`) and an
interactive SSH terminal. Two findings in this report are closed by them and are
marked **RESOLVED UPSTREAM in 4.36.x** where they appear: ConfigRX accepting any
SSH host key on every connection (§4.4 S-S2, §7 #29) and the absence of any way
to forget a pinned key — a "Forget host key" action now exists and is gated on
`configrx: write`. The rest of the verdict stands as measured; see §1 for what
else 4.36.x changed.

---

## 1. How the review was done

**The software moved during the review.** Every measurement, line number and
finding below was taken against **4.35.0** at commit `05259ae`. While the review
was being written `origin/main` advanced fourteen commits to **4.36.1**, and the
work that follows from this report is based on that. The report has not been
re-measured against 4.36.1; where a line number was checked against the newer
tree it is cited as such, and where a finding is already closed it is marked
**RESOLVED UPSTREAM in 4.36.x** rather than deleted, so the evidence stays
readable.

The 4.36.x delta, in one paragraph: 4.36.0 added an SSH host-key store
(`netpath/hostkeys.py`, table `ssh_host_keys` in `configrx.db`, keyed on
host+port, pinned on first sight and refused on change, with `forget_host_key`
behind `configrx: write`) and an interactive SSH terminal reached from the device
pane (`netpath/sshterm.py`, `netpath/web/wsock.py`, `netpath/web/static/ssh.*`
with a vendored xterm.js), which brought a new `ssh` permission module, an Origin
check on the WebSocket upgrade, per-account session caps and refused logins
recorded as device events; the CSP gained `frame-ancestors 'none'` and
`connect-src 'self'`; `tests/run_all.py` learned to read exit code 77 as SKIP;
and three suites were added (`test_ssh_hostkeys.py`, `test_ssh_terminal.py`,
`test_wsock.py`). 4.36.1 was a review pass over that work. Nothing in 4.36.x
touched the poller, the retention path, the alert engine or the collectors, so
§4.1, §4.2, §4.3 and §4.5 are unaffected; §4.4 loses S-S2 and gains the terminal
as new attack surface that this review never examined (Appendix C).

- **Code review by six parallel reviewers**, each owning one area and required
  to reproduce findings rather than assert them: SNMP polling core; receive-side
  collectors and decoders; alerting; security and credentials; performance and
  scale (with micro-benchmarks against the real `NodesDatabase`); UX,
  accessibility and documentation truth (with a live Playwright session against
  2,000 seeded devices).
- **A live demonstration against a simulated fleet.** Because the SNMP port is a
  module constant (`netpath/nodeoids.py:12`) rather than a per-device field, the
  demo gives every simulated device its own loopback address on UDP 161 so the
  *unmodified* application polls it exactly as it would real gear. The fleet
  simulator (`demo/fleet.py`, `demo/personas.py`) serves fifteen device personas
  with the application's own BER encoders and answers SNMPv1, v2c, v3
  noAuthNoPriv and v3 authNoPriv SHA. Generators send NetFlow v5/v9, SNMP traps
  (v1, v2c, inform) and syslog (RFC 3164/5424, UDP and both TCP framings) from
  the devices' source addresses. A scripted `traceroute` shim gives NetPath
  multi-hop, route-change, refused, silent and dead paths on loopback. A
  paramiko fake SSH device exercises ConfigRX's capture chain directly.
- **A timed incident campaign** (`demo/scenario.py`) at 250, 1,000 and 2,000
  devices: baseline, core-switch outage taking its downstream access switches,
  outage recovery, port-flap storm, reboots, authentication failures, trap and
  syslog burst, NetFlow burst, final recovery. (A first pass of this campaign
  taught the harness two things about the application that are findings in
  their own right: a simulated device that stops answering SNMP is still *up*
  while loopback answers ping, so the ping shim now consults the fleet; and the
  API session signed the campaign script out after ten minutes, so the client
  now re-authenticates on 401. See §4.4 S-N15 and §4.1 P-N11.) Alerts, emails at a local SMTP sink, poll counters,
  overruns, process CPU and RSS were sampled before and after each step.
- **A Playwright walk** (`demo/ui_walk.mjs`) of all twelve tabs, every subtab
  and every dialog, capturing screenshots, console errors, failed requests and
  Nodes-table render time at each tier.

What could not be demonstrated end to end, and why:

| Feature | Reason | What was done instead |
|---|---|---|
| ConfigRX backups through the worker | SSH password is DPAPI-only; `configrx.py:641-653` refuses without one | `demo/configrx_probe.py` drives `_pull_config`/`_capture_problem` directly against seven fake SSH personas (all behaved correctly, §8) |
| SNMPv3 authNoPriv polling through the UI | auth password is DPAPI-only | the simulator's SHA device was verified against `nodepoll` in-process with `dpapi.unprotect` stubbed; the API refusal was recorded verbatim |
| IPAM ARP/conflict detection | loopback has no ARP; real `arp` reads nothing useful | ping sweep of `127.0.0.0/24` demonstrated; conflict logic reviewed by reading |
| Windows DHCP visibility | PowerShell/RSAT only | reviewed by reading (`ipam_dhcp.py`) |
| Authenticated SMTP | DPAPI-only | unauthenticated local sink |
| Real multi-hop traceroute | loopback is one hop | scripted shim with the exact `_parse_unix` grammar |

---

## 2. What was demonstrated

### 2.1 The simulated fleet

`demo/personas.py` allocates devices deterministically. Index 0 is the core
switch `core-sw-01` (127.0.0.2); index 1 is a FortiGate wireless controller
`wlc-01` serving twelve APs with two radios each (127.0.0.3). The rest is a
weighted mix: ~55% Cisco access switches (48 ports, Q-BRIDGE forwarding tables,
the first 500 in site A as the core's downstream), Aruba switches (dot1d FDB),
FortiGate and Palo Alto firewalls (with vendor session/VPN scalars under their
enterprise arcs so it is visible that the app ignores them), Juniper routers,
Ubiquiti airFiber and Cambium PTP bridges (with fake RSSI/SNR/capacity scalars),
MikroTik, Siemens Scalance and Moxa industrial switches, Rockwell and Siemens S7
PLCs (two-port agents identified by sysDescr), and net-snmp Linux hosts (the
only persona whose CPU and memory the app can read).

Thirteen devices are fixed rather than drawn from the weighted mix: index 0
(the core switch) and index 1 (the wireless controller) named above, plus the
**eleven** at indices 2–12 below, which exercise the poller's edge paths
(`demo/personas.py` `SPECIALS`). An earlier draft of this report called all
thirteen "special devices", which did not match the eleven rows in the table.

| Index | IP | Behaviour |
|---|---|---|
| 2 | 127.0.0.4 | SNMPv1 only (GETBULK answered with a v1 error) |
| 3 | 127.0.0.5 | wrong community (`secret42`), app times out |
| 4 | 127.0.0.6 | replies `authorizationError` (error_status 16) |
| 5 | 127.0.0.7 | slow responder, 2,600 ms |
| 6 | 127.0.0.8 | `tooBig` above 8 repetitions |
| 7 | 127.0.0.9 | 32-bit counters that wrap within a minute, no ifXTable |
| 8 | 127.0.0.10 | 500-port chassis |
| 9 | 127.0.0.11 | SNMPv3 noAuthNoPriv, user `poller` |
| 10 | 127.0.0.12 | SNMPv3 authNoPriv SHA |
| 11 | 127.0.0.13 | goes dark for 180 s every 300 s |
| 12 | 127.0.0.14 | reboots every 240 s (sysUpTime resets) |

### 2.2 Feature checklist

| Area | Exercised | Outcome |
|---|---|---|
| Nodes: add devices, profiles (v1, v2c, v3-noauth), sites | API, 250–2,000 devices | works, but **27–333 devices/s** over single POSTs and falling with fleet size (250 in 0.75 s = 333/s; 1,000 in 23.0 s = 43/s; 2,000 in 73.0 s = 27/s — §3.1). An earlier draft quoted "430–630/s" from a warm-cache micro-benchmark that no tier reproduced. No bulk-add endpoint |
| Nodes: identity, vendor identification, arc-hop walk | all personas | correct vendor for every arc persona; Rockwell via sysDescr only |
| Nodes: interface tables, 64-bit and 32-bit counters, rates | all personas | correct; one GET per interface (513 requests per poll of the chassis) |
| Nodes: link events, flapping, reboot detection | flap storm, reboot step | events recorded; flap rule blunted by poll-interval sampling |
| Nodes: MAC tables (Q-BRIDGE, dot1d, Cisco per-VLAN) and MAC search | access and core personas | works; excellent search-to-port interaction |
| Nodes: DOM/optics in the interface dialog | core persona sensors | works, on demand only |
| Nodes: v1-only device | special 2 | identity fine, **every interface blank** (§4.1 P-B3) |
| Nodes: wrong community, auth failure, slow, tooBig, wrap | specials 3–7 | timeout, auth_fail event, intermittent timeouts, halve-and-retry, wrap handled |
| Nodes: SNMPv3 | specials 9–10 | noAuth works; authNoPriv cannot be configured on Linux |
| Nodes: discovery sweep of 127.0.0.0/24 | API | works; SNMP phase serial per address |
| Nodes: MIB upload and custom scalar poll, OID browser, full walk | API and UI | works; custom values stored but never charted |
| Alerts: rules, thresholds, ack, resolve, mute, bulk actions, engine counters | all steps | works; see §4.3 for what does not |
| Alerts: email via SMTP sink | outage step | works; 60/hour cap silently drops the rest |
| NetPath: multi-hop, route change, refused, silent, dead, degraded | shim | all rendered as documented, snapshot and aggregate views |
| NetFlow: v5, v9 with templates, mixed exporters | burst step | decoded and charted; exporter version mislabelled in a mixed batch |
| SNMP Trap: v1, v2c, inform ack, vendor traps | burst step | decoded and named; `trap_critical` fires on every trap |
| Syslog: 3164, 5424, UDP, TCP newline and octet framing | burst step | stored and searchable |
| Wireless: FortiGate WLC with 12 APs | poll | APs and radios listed, offline APs alert |
| ConfigRX: capture chain | fake SSH personas | correct on all seven; worker itself blocked on Linux |
| IPAM: subnet sweep | API | alive hosts listed; ARP empty by construction |
| Users and permissions, viewer account, help panel, settings, maintenance | UI walk | works; read-only users get a 403 on the Settings tab |
| Dashboard | UI walk | empty placeholder; it is the post-login landing page |

---

## 3. Demonstration results

All three tiers ran the same nine-step campaign against the same application
build on one Linux container (Python 3.11, local disk). The campaign deliberately
overrode six shipped settings so that a 25-minute run would exercise paths that
would otherwise take days to reach, and **every number in §3 is a number taken
under those overrides**:

| Setting | Shipped default | Campaign value | Why |
|---|---|---|---|
| `poll_interval_s` (profile) | 120 s | **60 s** | two poll cycles per campaign step |
| `poll_workers` | **16** | **32** | the reviewers wanted the pool, not the worker count, to be the limit |
| `cpu_high` threshold | 90% | **20%** | loopback personas never reach 90% |
| `response_time_high` | 500 ms | **5 ms** | loopback RTT is ~0.05 ms |
| new-device grace | 300 s | **0 s** | onboarding behaviour visible inside a step |
| hourly email cap | 60 | raised | so every notification was counted at the sink |

Numbers are from `demo/out/results-<N>.json`; "alerts" are rows opened or
resolved during the step's window, "emails" are messages received by the local
SMTP sink during it.

**What the numbers do not mean.** This is a simulated fleet on one loopback
interface, and four things follow from that which a reader must carry into every
table below. **One:** the fleet ran at *twice* the shipped poll rate on *twice*
the shipped worker count, so the saturation in §3.3 is not the shipped
configuration failing — it is the shipped configuration's ceiling located by
pushing past it, and a like-for-like column at shipped defaults is the first
thing the verification phase must produce (`demo/seed.py --defaults` exists for
exactly that). **Two:** loopback round-trip time is ~0.05 ms against a real
management network's 1–30 ms, so every per-device cost here is a floor; the SNMP
request counts (§4.5 X-F6) matter far more on real wire than these timings
suggest, and the two thresholds lowered to 20% and 5 ms fired on noise rather
than on load — the `cpu_high` and `response_time_high` counts in §3.2 measure the
alert path, not the fleet. **Three:** reachability is shimmed. A simulated device
that stops answering SNMP still answers ICMP on loopback, so `demo/` gives the
poller a `ping` shim that consults the fleet's own state; without it no device
ever reaches `down` and the outage steps measure nothing (this is §4.1 P-N11 seen
from the harness side). **Four:** the process had a whole container to itself with
a local filesystem and no other tenant. A Windows host, a network share or a
shared VM will be slower, in the write path especially. Nothing here is a
capacity guarantee; it is a comparison between three tiers of the same fleet
under the same overrides.

### 3.1 Cross-tier summary

| Measure | 250 devices | 1,000 devices | 2,000 devices |
|---|---|---|---|
| Seeding via single POSTs | 250 in 0.75 s | 1,000 in 23.0 s | 2,000 in 73.0 s |
| Devices up after the first poll cycle | 249/250 within 12 s | 955/1,000 after 73 s (never 100%) | 1,911/2,000 after 219 s (never 100%) |
| Baseline app CPU / RSS | 27% / 88 MB | 67% / 121 MB | 70% / 167 MB (268 MB by the end) |
| Site outage: devices dark → `device_down` alerts inside the window → emails in the step | 143 → 143 → 238 | 500 → **16** → 1,783 | 500 → **0** → 1,639 |
| Open alerts before the outage / after full recovery | 258 / 405 | 609 / 1,601 (list capped at 2,000 from step 2 on) | 882 / 2,000 (capped) |
| Open alerts at the end of the run (nothing left failing) | 636 | 1,448 (capped view) | 1,935 (capped view) |
| Emails over the whole run | 1,338 | 3,349 | 4,441 |
| Poll-overrun events recorded over the run | 9 | 6,420 | 26,361 |
| Longest single device poll observed (interval 60 s) | 160 s | 129 s | 159 s |
| Average / peak busy poll workers (of 32 configured; shipped default is 16) | 11 / 33 | 31 / 47 | 28 / 48 |
| App CPU during the trap + syslog burst | 63% | 84% | 86% |
| `samples` rows / `samples_hourly` rows at the end | 162,766 / 0 | 441,991 / 0 | 585,259 / 0 |
| Nodes table fill time after refresh | 181 ms | 1,854 ms | 1,488 ms (see note) |
| `/api/nodes/devices` payload per refresh | 332 KB | 1.32 MB in 653 ms | 2.64 MB in 201 ms |
| Browser long tasks during the walk (longest) | 52 (230 ms) | 122 (429 ms) | 251 (1,460 ms) |
| Uncaught page errors / failed requests | 0 / 0 (two 403s for the read-only user on Settings) | 0 / 0 (same two 403s) | 0 / 0 (same two 403s) |

Three rows in that table need reading carefully:

- **"Busy poll workers … 33 / 47 / 48 of 32" is not a contradiction.** The gauge
  reported by `NodePoller.status_text()` counts *queued plus running* work items,
  not threads, so it can and does exceed the pool size — a peak of 48 against 32
  workers means 32 polls in flight and 16 waiting. Read the peak as backlog
  depth, not as concurrency. B12 in the implementation plan renames it for
  exactly this reason.
- **The Nodes fill time is not monotonic** (1,854 ms at 1,000 devices against
  1,488 ms at 2,000). The 1,000-device walk overlapped the outage step's alert
  backlog, so the browser was competing with a busy server for the same lock; the
  2,000-device walk ran in a quieter window. Treat the pair as noise around
  "roughly 1.5–1.9 s at four-figure device counts", not as a trend.
- **Three different payload sizes appear for `/api/nodes/devices` at 2,000
  devices** — 2.18 MB (§4.5 X-F7), 2.19 MB (§4.6 U-F3) and 2.64 MB (above).
  They are three different database states: the first two were measured against a
  seeded 2,000-device table early in a run, the third at the end of a full
  campaign with every device's identity fields, `sys_descr` and vendor evidence
  populated. All three are "over two megabytes per refresh per tab"; the spread
  is what identity data costs.

### 3.2 What each step showed (250-device tier; the larger tiers are read against it in §3.3)

| Step | Alerts opened | Alerts cleared | Emails | Polls ok / timeout / auth | CPU% |
|---|---|---|---|---|---|
| 1 baseline (120 s) | cpu_high 15, interface_down 1, interface_up 4, netpath_unreachable 1, poll_overrun 1, mib_missing 1 | — | 173 | 492 / 1 / 6 | 27 |
| 2 core + 143 Site-A switches dark (240 s) | **device_down 143**, packet_loss_high 94, netpath_path_unstable 1 | packet_loss_high 93 | **238** | 347 / 567 / 0 | 14 |
| 3 outage recovery (150 s) | **device_up 143**, device_rebooted 1, interface_down 1, interface_flapping 1 | device_down 143, interface_down 1 | **292** | 567 / 7 / 6 | 29 |
| 4 flap storm, port 7 on 100 switches (120 s) | interface_down 56, interface_up 34 | interface_down 12 | 103 | 492 / 1 / 6 | 26 |
| 5 reboot 20 devices (120 s) | **device_rebooted 20**, interface_down 50, interface_flapping 17, interface_up 22 | interface_down 29 | 138 | 492 / 1 / 6 | 28 |
| 6 wrong credentials on 5 devices (90 s) | **device_auth_fail 5**, interface_down 36, interface_flapping 19, interface_up 8 | interface_down 33 | 100 | 481 / 2 / 16 | 32 |
| 7 trap + syslog storm (75 s) | trap_critical 5, syslog_critical 17, trap_link_down_unmanaged 1, interface_* 26 | interface_down 18 | 77 | 242 / 0 / 8 | **64** |
| 8 NetFlow burst, mixed v5/v9 at 200 flows/s (75 s) | interface_* 32 | interface_down 18 | 50 | 241 / 0 / 8 | 31 |
| 9 flaps stop, credentials restored (150 s) | interface_down 8, interface_up 24 | interface_down 48 | 80 | 717 / 3 / 9 | 29 |

Reading the 250-tier run against the findings:

- **Outage fan-out (§4.3 A-F3, A-F4, A-F24).** 143 devices behind one core produced 143
  independent "Device not responding" alerts and 238 emails, then 143 "Device
  recovered" alerts and 292 more emails. Nothing correlated them to the core
  switch. The per-device `packet_loss_high` alerts (94) did roll up under
  `device_down` once the third failed poll landed, which is the same-device
  rollup working as designed.
- **Recoveries never close (§4.3 A-F9).** After the outage was fully recovered the
  open-alert count was 405, up from 258 before it: the 143 `device_up` rows stay
  open until someone clicks Resolve. By the end of the run, with nothing failing,
  636 alerts were open.
- **Flapping is detected late and partially (§4.3 A-F13).** A port toggling every
  20–40 s on 100 switches produced 56 `interface_down` and 34 `interface_up`
  alerts in its first two minutes but only 1 `interface_flapping`; the flapping
  rule caught up during the *following* steps (17, 19, 6, 10) because it needs
  three sampled transitions inside a ten-minute window and the poller samples
  once a minute.
- **Reboots, auth failures, traps and syslog fired correctly** (20 of 20
  reboots, 5 of 5 auth failures, 17 critical syslog, 5 trap alerts). The
  `trap_critical` rule opened on `linkUp` and config-save traps as well as real
  faults (§4.3 A-F5), and one `linkDown` from a *managed* switch also opened
  "Link-down trap from an unmanaged device" (A-F6).
- **Poll pool saturation is visible (§4.1 P-S1, P-S5).** With 32 workers, the busiest
  sample had 33 in flight and the longest single poll took 160 s against a 60 s
  interval: the dark devices each cost three SNMP timeouts plus three ping
  timeouts per poll, and the 500-port chassis costs 513 requests. `poll_overrun`
  events were recorded but nothing said "the pool is full".
- **History is not being kept (§4.1 P-B1, P-B2).** 162,766 raw sample rows and an
  hourly rollup table with **zero** rows after 25 minutes. An earlier draft of
  this report said the 50,000-row global cap "had not yet bitten"; that was wrong,
  and the truth is worse. The cap *had* bitten. The `samples` table at the end of
  each run spans only the last **7.8 / 9.1 / 11.9 minutes** of a ~25-minute run at
  250 / 1,000 / 2,000 devices: the 15-minute prune ran, deleted everything older
  than the newest 50,000 rows, and the fleet then rewrote the table back up to
  162,766 / 441,991 / 585,259 rows in the minutes that followed. The row count at
  the end of a run is not history — it is the few minutes of writes that happened
  to land after the last prune. What survives *a* prune is 50,000 rows shared
  across every metric of every device: with 23,432 / 84,257 / 171,910 rows in
  `metrics` (≈94 / 84 / 86 metrics per device), that is **2.13 / 0.59 / 0.29
  samples per metric** at the three tiers. At 2,000 devices, fewer than one sample
  in three metrics survives — no chart can draw a line and no threshold streak can
  span a prune. §4.5 X-F1 carried "1.29 samples per metric"; the measured figure
  is 0.29.
- **Onboarding storm (§4.3 A-F27).** **235** `mib_missing` alert rows opened
  within the first poll of seeding, and **234** messages with the subject "… is
  not responding" arrived at the sink inside the same window (§4.3 A-F26). The two
  counters differ by one because they are read from different ends of the same
  window — the rows from `alerts.db`, the messages at the SMTP sink — and one
  message landed just after it closed. Use 235 for alerts opened and 234 for
  emails delivered; earlier drafts used the two interchangeably.
- **The UI held up at this size.** 250 rows filled in 181 ms, no uncaught page
  errors across 12 tabs, 10 subtabs and 21 dialogs; the read-only user saw every
  tab with zero write controls, and hit two 403s opening Settings (§4.6 U-C3).

### 3.3 Scale tiers

**1,000 devices.** The same campaign, four times the fleet, on the same 32
workers at a 60 s interval:

| Step | Alerts opened | Alerts cleared | Emails | Polls ok / timeout / auth | Overruns | CPU% |
|---|---|---|---|---|---|---|
| 1 baseline (122 s) | — (list already capped) | — | 382 | 1,378 / 2 / 6 | 421 | 67 |
| 2 core + 499 Site-A switches dark (241 s) | packet_loss_high 371, **poll_overrun 563**, **device_down 16**, cpu_high 13, netpath 2 | packet_loss_high 16 | **1,783** | 971 / 1,015 / 0 | 1,485 | 56 |
| 3 outage recovery (151 s) | interface_up 1 | device_down 16, packet_loss_high 365 | 392 | 1,664 / 2 / 6 | 413 | 66 |
| 4 flap storm (122 s) | interface_down 53, interface_up 19, interface_flapping 1 | interface_down 7 | 106 | 1,396 / 1 / 6 | 697 | 59 |
| 5 reboot 20 (121 s) | device_rebooted 20, interface_* 41 | interface_down 39 | 113 | 1,330 / 2 / 6 | 519 | 59 |
| 6 wrong credentials on 5 (91 s) | device_auth_fail 5, interface_* 26 | interface_down 22 | 101 | 902 / 0 / 8 | 693 | 66 |
| 7 trap + syslog storm (76 s) | trap_critical 5, syslog_critical 8, unmanaged 1 | interface_down 2 | 36 | 656 / 0 / 8 | 220 | **84** |
| 8 NetFlow burst (76 s) | interface_* 40, response_time_high 1 | interface_down 36 | 117 | 797 / 1 / 8 | 364 | 65 |
| 9 flaps stop, credentials restored (151 s) | interface_* 33 | interface_down 43 | 79 | 1,572 / 1 / 9 | 745 | 61 |

The per-step columns above and in §3.1 do not add up to the run totals, and are
not meant to: a step's row covers only that step's own window. At 250 devices the
nine steps account for 1,251 of 1,338 emails, at 1,000 for 3,109 of 3,349, at
2,000 for 3,885 of 4,441 and 21,001 of 26,361 overruns. The nine windows sum to
about 19 minutes of a ~25-minute run; the balance falls in seeding and in the
inter-step gaps where the harness snapshots counters and reconfigures the fleet,
and the poller keeps running throughout.

What changed between 250 and 1,000 devices:

- **The poller fell behind before anything failed.** With nothing wrong, the
  pool sat at 31 of 32 workers busy, the baseline consumed 67% of a core, and
  421 poll overruns were recorded in two minutes; over the run 6,420 overrun
  events and 984 `poll_overrun` alerts were written. 4.5% of the fleet never
  completed a first poll inside 73 s.
- **A 500-device outage was mostly invisible for four minutes.** Only 16 of the
  499 dark switches accumulated the three failed polls needed to become
  `down` inside a 241 s window, because polls of dark devices (three ping
  timeouts plus three SNMP timeouts each) occupied the saturated pool and the
  60 s interval could not be met: 1,015 timeouts against 971 successful polls.
  The operator's first signal was 371 `packet_loss_high` alerts and 563
  `poll_overrun` alerts, not "site A is down", and 1,783 emails in four
  minutes. This is §4.1 P-S1, P-S5, P-N5 and §4.5 X-F15 measured together.
- **The alert list stopped being complete.** `GET /api/alerts` takes a `limit`
  that **defaults to 300** and is **hard-capped at 2,000** (`api.py:3027`,
  `:3031`); both numbers appear in this report and they describe different things.
  The campaign asked for the maximum, so from step 2 onward it hit the 2,000-row
  cap and every later snapshot is a truncated view. An operator's browser, which
  does not raise the limit, would have seen 300 — less than a fifth of it (§4.3
  A-F20, §4.6 U-F10).
- **The onboarding storm scaled linearly:** 948 `mib_missing` alerts on the
  first poll, each emailed as "is not responding" (§4.3 A-F26, A-F27).
- **The browser cost scaled linearly too:** 1,000 rows took 1.85 s to fill after
  a refresh from a 1.32 MB payload that took 653 ms to serve, with 122 long
  tasks (longest 429 ms) during the walk (§4.5 X-F7, X-F20).
- Still no rows in the hourly rollup table after 442k raw samples (§4.1 P-B2).

**2,000 devices.** The first full poll cycle took 219 s to reach 95% of the
fleet and never reached 100%; the baseline sat at 70% CPU with 1,822 overruns
in two minutes.

| Step | Alerts opened | Alerts cleared | Emails | Polls ok / timeout / auth | Overruns | CPU% | RSS MB |
|---|---|---|---|---|---|---|---|
| 1 baseline (121 s) | — (list capped) | — | 397 | 1,370 / 0 / 3 | 1,822 | 70 | 167 |
| 2 core + 499 Site-A switches dark (240 s) | **none visible — no `down` event was recorded for any device** | — | **1,639** | 1,374 / 499 / 0 | **5,423** | 69 | 189 |
| 3 outage recovery (151 s) | — | — | 546 | 1,505 / 0 / 0 | 2,174 | 70 | 200 |
| 4 flap storm (122 s) | — | interface_down 7 | 356 | 1,110 / 1 / 3 | 1,831 | 71 | 208 |
| 5 reboot 20 (121 s) | — (21 `rebooted` events in the DB) | — | 325 | 1,323 / 0 / 3 | 3,490 | 63 | 228 |
| 6 wrong credentials on 5 (91 s) | — (6 `device_auth_fail` rows in the DB) | — | 356 | 903 / 0 / 0 | 1,279 | 77 | 229 |
| 7 trap + syslog storm (77 s) | — (5 trap, 20 syslog rows in the DB) | interface_down 25 | 28 | 494 / 1 / 8 | 338 | **86** | 264 |
| 8 NetFlow burst (77 s) | cpu_high 2 | interface_down 20 | 122 | 718 / 0 / 0 | 1,653 | 71 | 265 |
| 9 flaps stop, credentials restored (151 s) | interface_* 33 | interface_down 26 | 116 | 1,620 / 1 / 3 | 2,991 | 63 | 268 |

What the 2,000-device run shows:

- **The outage was never detected.** 499 switches stopped answering for four
  minutes and the `device_events` table holds **zero `down` rows** for the whole
  run: 1,871 polls completed in 240 s across 2,000 devices, i.e. each device was
  polled about once every four minutes against a 60 s profile, so no device
  reached three consecutive failures. The only signals were 5,423 poll overruns
  and 1,639 emails, almost all of them `poll_overrun` and `mib_missing` noise.
  At this size, on this hardware, with 32 workers and a 60 s interval, **the
  poller cannot see a site outage**. This is consistent with the capacity ceiling
  §4.5 estimated (~1,350 devices at 48 ports and 120 s; ~680 at 60 s), but it does
  not measure it: the tiers were 250, 1,000 and 2,000, so the ~680-device figure
  falls between two tiers and was never bracketed. What was measured end to end is
  narrower and still decisive — at 1,000 devices detection is late (16 of 499
  inside four minutes) and at 2,000 it does not happen at all. An earlier draft
  claimed the ~680 ceiling itself was "measured end to end"; it was extrapolated
  from the write-path benchmarks and is corroborated, not measured, by the tiers.
- **The alert list was capped for the entire campaign from step 2**, so the
  campaign's own per-step "alerts opened" column went blind; the rows above
  marked "in the DB" were read directly from `alerts.db`. An operator's browser,
  defaulting to 300 rows, would have seen 15% of it (§4.3 A-F20, §4.6 U-F10).
- **Every device raised `poll_overrun`** (2,000 alerts, 26,361 events) — the
  one alert that fires reliably at this scale is the one saying the monitor
  itself is late.
- **Onboarding:** 1,898 `mib_missing` alerts, each emailed as "is not
  responding"; 4,441 emails over 25 minutes with nothing genuinely wrong except
  the incidents the campaign injected.
- **UI:** 2,000 rows filled in 1.5 s from a 2.64 MB payload (served in 201 ms);
  251 long tasks during the walk, the longest 1.46 s; still no uncaught page
  errors. RSS grew from 167 MB to 268 MB over the run.
- 585,259 raw samples, hourly rollup still empty (§4.1 P-B2).

### 3.4 What the three tiers say together

| | 250 | 1,000 | 2,000 |
|---|---|---|---|
| Polls per device per minute achieved (60 s profile) | ~1.0 | ~0.5 | ~0.25 |
| Dark devices detected as down within 4 min | 143 of 143 | 16 of 499 | 0 of 499 |
| Baseline CPU | 27% | 67% | 70% |
| Emails during the outage step | 238 | 1,783 | 1,639 |

The poller works correctly and the alert semantics hold at 250 devices; by
1,000 the pool is saturated and detection is late; by 2,000 detection fails.
The five ★ fixes in §4.5 (batched sample writes, a fixed retention cap with the
rollup running, cached settings in the scheduler, one keyed alert query, and
GETBULK for the interface columns) plus concurrent pings with back-off for
failing devices (§4.5 X-F15) are what move that ceiling; none of them is large.

---

## 4. Findings by area

Severity: **blocker** (stops the product working for this fleet), **severe**,
**notable**. Effort: S (hours), M (days), L (weeks).

### 4.1 SNMP polling core

| # | Sev | Tag | Finding | Evidence | Fix / effort |
|---|---|---|---|---|---|
| P-B1 | blocker | **CONFIRMED** | `sample_row_cap_per_metric` is a whole-table cap: 50,000 rows total survive each 15-minute prune, i.e. under a third of one poll cycle at 2,000 devices. Charts empty, threshold streaks reset. CONFIRMED (3 metrics × 100 samples, cap 150 → 50 each). | `nodesdb.py:342`, `service.py:715-719`, `nodesdb.py:2171-2179` | per-metric `ROW_NUMBER()` delete in chunks; **S** |
| P-B2 | blocker | **CONFIRMED** | `compact_rollup()` is never called; `samples_hourly` is always empty; any chart window over 3 days returns 0 points; storage doc promises rollups. CONFIRMED. | `nodesdb.py:1480-1503`, `nodes.js:951-954`, `NETWORK-AND-STORAGE-REQUIREMENTS.md:270` | call from `run_maintenance()`, prune by `rollup_days`; **M** |
| P-B3 | blocker (v1 gear) | **CONFIRMED** | Every interface on an SNMPv1 device is blank: the per-interface GET mixes ifXTable OIDs, a v1 agent answers `noSuchName` for the whole PDU, and only status 16 raises. Device shows *up* with no counters, no link events. CONFIRMED against a v1 stub. The identity GET already has the v1 split. | `nodepoll.py:1642-1645`, `:1173-1176`, `:1240-1259` | split the GET on v1 as `_identity_extras` does, or walk columns; **S** |
| P-S1 | severe | **CONFIRMED** | `_poll_interfaces` has no wall-clock budget: a device that answers its ifIndex walk and then goes quiet holds a pool worker for ports × timeout × attempts. Measured against a stub: **6.02 s for 10 ports** at `snmp_timeout_s` 0.3 and two attempts per port (10 × 0.3 × 2). Extrapolating needs the attempt count stated, because `_Session.request` loops `range(self.retries + 1)` (`nodepoll.py:86`): the shipped defaults are `snmp_timeout_s` **3.0** and `snmp_retries` **2**, i.e. **three** attempts, so the 500-port chassis persona costs 500 × 3.0 × 3 = **4,500 s ≈ 75 min** and a 512-port device 4,608 s ≈ 77 min. The measured 6.02 s used two attempts, not three; both figures are right, and the 77 min quoted in the first draft holds only under the shipped `snmp_retries = 2`. | `nodepoll.py:1641`, `:86`, `nodesdb.py:33-34`, `:323-324` | deadline of 0.5 × interval, abandon after 3 consecutive timeouts; **S** |
| P-S2 | severe | **CONFIRMED** | The scheduler thread has no exception guard; one transient DB error stops all polling permanently and silently (`poller.error` stays `None`). | `nodepoll.py:690-721` | `try/except` **and** `self.error`. The first draft said "as `monitor.py:376-402` does"; `monitor.py` guards its loop but does not set an error field either, so there is no pattern to copy — the status surface is new work, and the fix must also clear `self.error` on the next clean pass or the UI will show a stale failure forever; **S** |
| P-S3 | severe | **CONFIRMED** | SNMPv3 engineTime is cached at discovery and never advanced, so every v3 device fails about every third poll with a spurious auth_fail event. CONFIRMED by trace. | `nodepoll.py:56-58`, `:1145`, `:1164-1171` | send `engine_time + (now - learned_at)`; **S** |
| P-S4 | severe | **CONFIRMED** | authPriv is unsupported (no priv columns), and the failure is misreported twice: the agent's `unsupportedSecLevels` Report becomes "engine resync required", and the `"unsupported" in msg` substring never matches its own message, so the whole `unsupported` status/event/rule path is dead. CONFIRMED. | `nodepoll.py:917`, `:1153-1158`, `snmppoll.py:232-235`, `alertsdb.py:218` | decode `usmStats*` and classify by type; **M** (priv itself **L**) |
| P-S5 | severe | **CONFIRMED** | Scheduler reloads the whole device table and calls `effective_config` per device once a second: 4,001 SQLite statements/s at 2,000 devices, ~12% of a core, under the lock every worker needs. CONFIRMED (118 ms/iteration). | `nodepoll.py:694-697`, `nodesdb.py:1081-1119` | cache settings and groups; select only loop columns; **S** |
| P-S6 | severe | **CONFIRMED** | `record_metric_sample` commits once per sample: ~2,500 commits in a single poll of the 500-port chassis (0.212 s for 500 ports, measured). Fleet-wide the figure depends on metrics per device, and the campaign settled that: 171,910 rows in `metrics` at 2,000 devices is **≈86 metrics per device**, so ~172,000 commits per poll cycle — **2,870/s at a 60 s interval**, 1,435/s at the shipped 120 s. An earlier draft said "~288,000 per cycle" from an assumed 144 metrics/device, and §4.5 X-F3's "fleet needs 3,233/s" used 97; at the measured ~86 both become ~2,870/s at 60 s. Use that number. | `nodesdb.py:1379-1420`, `nodepoll.py:1053-1064` | one transaction per device poll, `executemany`; **M** |
| P-S7 | severe | **PLAUSIBLE** | MAC-table walks run on the poll pool rather than an executor of their own, and the Cisco per-VLAN path checks its 15 s budget only *between* VLANs, so the last VLAN entered can run two unbounded column walks past the deadline. The budget check is plainly in the wrong place in the loop; no device was made to hold a worker this way, which is why this is PLAUSIBLE rather than CONFIRMED. | `nodepoll.py:752`, `:2196-2233` | own executor, deadline inside `_walk_column`; **S/M** |
| P-S8 | severe | **PLAUSIBLE** | `counter_rate` treats any decrease as a counter wrap and `ifCounterDiscontinuityTime` is never polled, so a reboot is indistinguishable from a wrap and should produce a phantom spike — the 220 Mbps figure is arithmetic on a 32-bit counter, not an observed sample. The mechanism is plain in the code; the spike itself was never reproduced, which is why this row is PLAUSIBLE. | `nodepoll.py:122-148`, `nodeoids.py:48-53` | poll discontinuity time and suppress one poll after `detect_reboot`. Not **S**: it needs an `interfaces.discontinuity_ts` column through the `_migrate()` pattern, and the suppression has to survive the poll that discovers the reboot, so **S/M** |
| P-S9 | severe | **CONFIRMED** | No vendor health polling at all: no Cisco/Aruba/Juniper/PAN/Fortinet CPU or memory, no ENTITY-SENSOR or ENVMON on a schedule, no PoE (MIB ships, unread), no STP, no LLDP/CDP, no ARP, no BGP, no firewall sessions/VPN/HA, no RF metrics. `HOST_RESOURCES` defined, never referenced. CONFIRMED by grep. | `nodeoids.py:58-67`, `nodepoll.py:1306` | per-vendor scalar table keyed on `detected_vendor`, ride the existing best-effort GET; **M**, tables **L** |
| P-S10 | severe | **CONFIRMED** | `cpu_pct`, `mem_pct` and every custom-MIB metric are stored and never displayed; the only charts are hard-coded interface and loss keys. | `nodes.js:16-19`, `:506`, `:1649-1650` | render `view.metrics` with the existing chart renderer; **S** |
| P-N1 | notable | **CONFIRMED** | Custom-MIB polling sends one unchunked GET of every object in the MIB (267 varbinds = 4 KB request), including table columns; `tooBig` yields zero metrics with no error. | `nodepoll.py:1582-1625` | filter table columns, chunk to 25, honour tooBig; **M** |
| P-N2 | notable | **CONFIRMED** | A reply is accepted without checking request-id or source address; a late reply to attempt 1 is consumed as the answer to attempt 2 (observed with the 2.6 s device). v3 msgID also unchecked; v3 response digests are never verified (`_verify_v3` exists, used for traps only). CONFIRMED. | `nodepoll.py:82-97`, `:1125-1160`, `:2438`, `:2473` | compare ids and address, drain mismatches; verify inbound HMAC; **S** |
| P-N3 | notable | **CONFIRMED** | No per-device SNMP port; no IPv6 polling (`AF_INET` hardcoded). | `nodeoids.py:12`, `nodepoll.py:73` | `snmp_port` override column, `getaddrinfo`; **S** each |
| P-N4 | notable | **CONFIRMED** | No bulk device import; discovery capped at 1,024 addresses per job with a serial SNMP phase (2 versions × N communities × timeout per silent address). | `api.py:1773`, `nodesdb.py:353`, `nodediscover.py:176-231` | CSV import endpoint, parallel probe phase; **S/M** |
| P-N5 | notable | **CONFIRMED** | Ping is three serial subprocess spawns per device per poll on the poll worker; a down device costs ~12 s of worker time per cycle; 160 down devices saturate the pool. | `ipam_scan.py:127-157`, `nodepoll.py:846` | concurrent probes, back-off for failing devices; **M** |
| P-N6 | notable | **CONFIRMED** | A down device re-sweeps every credential candidate every poll (36 s of worker time with four candidates); the on-demand path already has negative caching. | `nodepoll.py:1195-1209`, `:1099-1101` | reuse `_credential_probe_failed`; **S** |
| P-N7 | notable | **CONFIRMED** | `_walk_indexes` breaks on the first non-integer suffix, and `replace_interfaces` then deletes the missing rows and their events. | `nodepoll.py:1810-1819`, `nodesdb.py:1368-1375` | `continue`; refuse deletes on an unclean walk; **S** |
| P-N8 | notable | **CONFIRMED** | Non-ASCII octet strings render as hex (`Wärmetauscher 3` → `57 C3 A4 …`); a 6-byte one renders as a MAC. Stored `sys_descr` is uncapped. | `trapdecode.py:195-214` | try UTF-8 then latin-1; cap stored size; **S** |
| P-N9 | notable | **CONFIRMED** | `_walk_from` (OID browser, full walk, vendor identification) is GETNEXT-only and opens a socket per row; fleet-wide first identification ≈ 2.8 h. | `nodepoll.py:2305-2368`, `:2331` | share `_walk_column`'s GETBULK path; **S/M** |
| P-N10 | notable | **CONFIRMED** | `fortipoll._walk_column` has no non-increasing-OID guard and hardcodes timeouts. | `fortipoll.py:252-271` | reuse `nodepoll._walk_column`; **S** |
| P-N11 | notable | **CONFIRMED** | The shipped test suite fails on any machine with `ping` installed (`test_nodepoll_e2e.py:287`): the device answers ICMP so it never reaches `down`. Passes with ping removed from PATH. CONFIRMED both ways. The substantive half: a switch whose SNMP agent is dead but which answers ping never fires `device_down`. | `tests/test_nodepoll_e2e.py:219`, `tests/README.md:3-6` | disable ping in the test profile; add an "SNMP failing, ping OK" rule; **S** |

### 4.2 Collectors and decoders

| # | Sev | Tag | Finding | Evidence | Fix / effort |
|---|---|---|---|---|---|
| C-B1 | blocker | **CONFIRMED** | One 18-byte datagram kills the NetFlow listener: `DecodeError` is not in the decoder's except tuple and the receive loop has no guard. Status reads "Collector stopped" as if an operator did it. CONFIRMED live. | `nfdecode.py:150,160`, `collector.py:185` | add to the tuple and wrap the loop (same for traps and syslog); **S** |
| C-B2 | blocker | **CONFIRMED** | A v9/IPFIX template with zero-length fields spins the receive thread at 100% CPU forever with `running` still true. CONFIRMED. | `nfdecode.py:89-96`, `:316-337` | reject `length <= 0` templates; **S** |
| C-B3 | blocker | **CONFIRMED** | Kernel socket-buffer drops are invisible: 300k syslog messages at 38k/s → 93k stored, 206k dropped, `counters["dropped"] == 0`. CONFIRMED. | `syslogd.py:199-208`, `collector.py:158-209`, `snmptrapd.py:183-192` | read `SO_RXQ_OVFL` or `/proc/net/udp` drops; surface it; **M** |
| C-B4 | blocker | **CONFIRMED** | Every syslog prune rebuilds the entire FTS5 index under the write lock: 18.6 s to delete one row from a 1M-row table, every 15 minutes. CONFIRMED. | `syslogdb.py:482-484`, `:504-506` | targeted FTS `delete`; **S** |
| C-B5 | blocker | **CONFIRMED** | The alert engine drains 500 rows per 5 s tick per source (100 rows/s) against a measured ingest of ~11,800/s; a busy site falls behind forever with no lag indicator. CONFIRMED. | `alertengine.py:499,520`, `:28` | loop to catch up with a budget; show backlog; **M** |
| C-S1 | severe | **CONFIRMED** | SNMPv3 trap authentication is computed and counted but never enforced: 401 forged traps stored and alerted. CONFIRMED. | `snmptrapd.py:172-179`, `:194-231` | `reject_failed_auth` default on; **S** |
| C-S2 | severe | **CONFIRMED**, with a corrected precondition | A v3 trap whose user name **is one of the configured `v3_users`** and whose engine id is new costs a 1 MiB password-to-key hash on the receive thread (~430 traps/s ceiling) and adds an entry to a `_KEY_CACHE` that is never evicted. The first draft said this happened for *any* forged trap; it does not — `_verify_v3` looks the user up first and returns `"unverified"` before deriving anything when the name is unknown (`trapdecode.py:659-662`), so an attacker who does not know a configured v3 user name pays nothing. The attack needs a known user name (readable from any captured trap, and often the same across a fleet), after which the engine id is attacker-chosen and the cache grows without bound. The template and `_seen` dicts in the NetFlow decoder are unbounded for anyone. | `trapdecode.py:321`, `:323-346`, `:658-682`, `nfdecode.py:122-123` | bounded LRU caches; **S** |
| C-S3 | severe | **CONFIRMED** | Dual-stack templates render IPv6 flows as `0.0.0.0` (zero-filled v4 field is truthy). CONFIRMED. | `nfdecode.py:409-411` | pick by content; **S** |
| C-S4 | severe | **CONFIRMED** | `HopProber` submits a new unbounded round of ping subprocesses every 4 s with no in-flight tracking and commits per probe. | `monitor.py:634-646`, `db.py:449-474` | in-flight set as `Monitor` has; batch upserts; **M** |
| C-S5 | severe | **CONFIRMED** | All three listeners and NetPath are IPv4-only; a device on an IPv6 management plane is silently unreachable. | `collector.py:90`, `syslogd.py:130`, `snmptrapd.py:126`, `tracer.py:380-384` | dual-stack bind; `getaddrinfo`; **M** |
| C-S6 | severe | **CONFIRMED** | Syslog over TCP spawns a thread per connection with no cap and never reaps the list. | `syslogd.py:210-221` | cap and prune; **S** |
| C-S7 | severe | **CONFIRMED** | Device correlation is exact-IP equality: a switch logging from `Loopback0` while polled on its management VLAN matches nothing (no name in the Host column, no name on the alert). | `hostresolve.py:33-34`, `nodesdb.py:950-953` | `device_addresses` alias table fed from `ipAddrTable`; **M** |
| C-S8 | severe | **CONFIRMED** | Syslog and trap occurrences never set `device_name`, so name-scoped rules silently never match. | `alertengine.py:504-509`, `:535-539` | set it; **S** |
| C-S9 | severe | **CONFIRMED** | RFC 5424 structured data: only the first element is stripped; relayed rsyslog messages carry `[origin …]` into the message column and index. CONFIRMED. | `syslogparse.py:168-188` | loop; **S** |
| C-N1 | notable | **CONFIRMED** | Non-English Windows `tracert` loses the ICMP-unreachable hop entirely (English phrase table). | `tracer.py:46-53`, `:294-296` | match on structure; **S** |
| C-N2 | notable | **CONFIRMED** | v9 field length 0xFFFF misread as IPFIX variable-length; silent corruption. | `nfdecode.py:89-96` | version-aware; **S** |
| C-N3 | notable | **CONFIRMED** | `touch_exporter` stamps every exporter in a flush batch with the first flow's version (observed live with mixed v5/v9); commits per exporter. | `collector.py:231-233`, `flowdb.py:177-190` | carry version per exporter; **S** |
| C-N4 | notable | **CONFIRMED** | RFC 3164 timestamps get no future clamp and assume the server's timezone; a December message read in June files six months ahead and can never be pruned. | `syslogparse.py:91-109`, `syslogdb.py:468-474` | clamp to now ± 1 h; **S** |
| C-N5 | notable | **CONFIRMED** | RFC 5424 with an empty MSG stores the header as the message. | `syslogparse.py:131-142` | accept 5 parts; **S** |
| C-N6 | notable | **CONFIRMED** | Sampling is one rate per exporter applied only to flows after the options template; earlier flows are stored under-scaled forever. | `nfdecode.py:369-374`, `flowdb.py:322` | resolve rate at query time; **M** |
| C-N7 | notable | **CONFIRMED** | Syslog storage is ~455 B/message measured vs the documented ~150 B. | `NETWORK-AND-STORAGE-REQUIREMENTS.md:269` | fix the figure; **S** |
| C-N8 | notable | **CONFIRMED** | Exporter interface names are hand-typed `ip:ifIndex=name` lines while `nodes.db` already holds `if_index`, `descr`, `speed_bps` for every managed device. | `flowdb.py:53-58`, `service.py:492-504` | seed from Nodes; add utilisation %; **M** |
| C-N9 | notable | **CONFIRMED** | No trap varbind conditions and no syslog regex or "N in M minutes" rules; the two rules a NOC actually writes are impossible. All syslog alerts from one host collapse into one row whose message is overwritten. | `alertsdb.py:26-50`, `alertrules.py:39-54` | `match_text`/`match_field`/`count_window_s` on rules; **M/L** |
| C-N10 | notable | **CONFIRMED** | No per-source rate limiting or repeat suppression on syslog or traps; one device in a debug loop evicts everyone else's messages. | `syslogd.py:174-197` | per-source token bucket; **M** |
| C-N11 | notable | **CONFIRMED** | `trapoids.py:51` labels `1.3.6.1.2.1.15.3.1.7` as `bgpPeerState`; it is `bgpPeerRemoteAddr` (state is `.1.2`). Rendered live as `bgpPeerState.198.51.100.75=198.51.100.75`. | `trapoids.py:51`, `:174` | correct the arc; **S** |
| C-N12 | notable | **CONFIRMED** | TCP syslog framer treats any leading `<digits><space>` as an RFC 6587 length; a newline-framed line starting with a number desynchronises the connection. | `syslogd.py:236-244` | require `<` after the count; **S** |
| C-N13 | notable | **CONFIRMED** | `Database.prune` (NetPath) VACUUMs unconditionally, even when nothing was deleted. | `db.py:590-602` | only when rows removed; **S** |
| C-N14 | notable | **CONFIRMED** | `reached` is decided against the app's own DNS answer; round-robin or anycast names record as never reached. | `tracer.py:399`, `:453` | parse the address from the traceroute header; **S** |

### 4.3 Alerting

Rule liveness (reproduced by writing every metric key the poller can produce and
ticking the engine): **7 of 32 built-in rules are DEAD, 10 PARTIAL.** Dead:
`if_in_util_high`, `if_out_util_high`, `if_in_errors_high`, `if_out_errors_high`,
`if_in_discards_high`, `if_out_discards_high`, `disk_high` — nothing writes
`if_in_util_pct`, `if_*_error_rate`, `if_*_discard_rate` or `disk_pct`; the
poller writes per-port keys (`if_in_bps.3`) that no single rule can match.
`cpu_high`/`mem_high` are UCD-only, so on a switch/firewall fleet the live device
thresholds are `ping_rtt_ms` and `ping_loss_pct`.

| # | Sev | Tag | Finding | Evidence | Fix / effort |
|---|---|---|---|---|---|
| A-F1 | blocker | **CONFIRMED** | Seven dead threshold rules, enabled and documented; `source_kind` is not editable on built-ins. | `alertsdb.py:226-232`, `alertengine.py:653-655`, `alertsdb.py:201-204` | compute util % from `in_bps`/`speed_bps`, poll discards, walk `hrStorageTable`; per-port key patterns; **L** (labelling **S**) |
| A-F2 | blocker | **CONFIRMED** | SMTP is sent inline on the engine tick with no circuit breaker; failures do not consume the hourly quota. 500 devices down with a dead relay = 500 × 15 s ≈ 2 h of frozen engine. CONFIRMED (25.7 s at a 0.05 s simulated failure; 12.3 s with a healthy relay vs a 5 s tick). | `alertengine.py:1218-1228`, `:1146-1152`, `alertmail.py:262-273` | sender queue thread + breaker; **M** |
| A-F3 | severe | **CONFIRMED** | 500 outages → 500 alerts, 60 emails, 440 dropped with no `notifications` row; the only trace is one line in a 3,000-entry in-memory ring that the poller overwrites in ~90 s. CONFIRMED. | `alertengine.py:1159-1170`, `eventlog.py:56-58` | write a rate-limited row per alert; digest email; **S/M** |
| A-F4 | severe | **CONFIRMED** | No digest, batching or correlation window: one email per alert. | `alertengine.py:1096-1152` | `digest_seconds`; **M** |
| A-F5 | severe | **CONFIRMED** | `trap_critical` fires on every trap of any severity (severity gate is syslog-only); 50 informational config-save traps opened a severity-2 "Critical SNMP trap". CONFIRMED. | `alertengine.py:504-509`, `:1111-1122`, `alertsdb.py:238` | carry trap severity, gate it; **S** |
| A-F6 | severe | **CONFIRMED** | Trap dedup key is the trap OID, not the source: 200 `linkDown` traps from 200 switches collapse into one alert naming no device; `trap_link_down_unmanaged` never checks whether the source is managed. CONFIRMED. | `alertrules.py:43`, `alertengine.py:494-512` | `source:oid` entity, real unmanaged gate; **S** |
| A-F7 | severe | **CONFIRMED** | Syslog alerts collapse per host; three distinct faults become one row, first two lost. CONFIRMED. | `alertengine.py:535-539`, `alertsdb.py:697-712` | message signature in the dedup key; **M** |
| A-F8 | severe | **CONFIRMED** | `renotify_minutes` never fires: `open_or_increment` refreshes `last_ts` and returns the re-read row before the comparison; event-driven rules see no new occurrence anyway. CONFIRMED (renotify 1 min, 20 min breach → 1 email). | `alertengine.py:1146-1152`, `alertsdb.py:697-712` | `last_notified_ts`, per-tick sweep; **M** |
| A-F9 | severe | **CONFIRMED** | Eleven rules have no auto-resolve path (`device_up`, `device_rebooted`, `poll_overrun`, `interface_up`, `interface_flapping`, `trap_*`, `syslog_critical`, `ipam_new_conflict`); recoveries accumulate as open alerts. CONFIRMED. | `alertrules.py:115-135`, `alertengine.py:696-704` | `auto_resolve_after_s`; pair IPAM conflict-resolved; **M** |
| A-F10 | severe | **CONFIRMED** | A stale metric holds a threshold alert open forever and re-raises it every tick (opened from a 45-day-old sample; `last_ts` = now), sorting it to the top. CONFIRMED. | `alertengine.py:672-695`, `alertsdb.py:644` | treat samples older than N × interval as absent; **S** |
| A-F11 | severe | **CONFIRMED** | Hand-resolving "Device not responding" un-suppresses every child: three fresh alerts and emails within 5 s for a device still down. CONFIRMED. | `alertengine.py:1042-1051`, `:1126-1137` | extend sticky-resolve to `ROLLS_UP` children while `status == 'down'`; **M** |
| A-F12 | severe | **CONFIRMED** | Drain cursors commit before the apply loop; one exception mid-loop permanently discards the rest of the batch (injected failure lost 8 of 10 outages). CONFIRMED. | `alertengine.py:156-177`, `:418-419` | per-occurrence guard, commit cursor after apply; **S/M** |
| A-F13 | notable | **CONFIRMED** | Flapping detection only sees transitions slower than the poll interval; true fast flapping is invisible, and the device's own linkDown/linkUp traps land in F6's collapsed alert. | `nodepoll.py:1046-1053`, `alertrules.py:56-66` | count trap transitions per source; read `ifLastChange`; **M** |
| A-F14 | notable | **CONFIRMED** | `_evaluate_thresholds` walks every enabled device and reads every one of its metrics on every 5 s tick, to evaluate four live rules — ~400,000 rows fetched of which 88% no rule reads. Cost scales with metrics per device, which is why two figures appear in this report and neither is wrong: **0.96 s/tick** (this row) and **0.85 s/tick** (§4.5 X-F8) are two runs at ~200 metrics per device, and **436 ms** is the same benchmark at 100. At the ~86 metrics per device the campaign actually measured (§4.1 P-S6) the tick costs ≈0.40 s — still a tenth of the interval spent re-reading rows nothing wants. | `alertengine.py:615-705` (the function; device loop at `:650-705`), `nodesdb.py:1422-1426` | one keyed query; **S** |
| A-F15 | notable | **CONFIRMED** | SMTP auth cannot be configured on Linux (DPAPI). | `api.py:3237-3251` | platform-neutral secret store (§6) |
| A-F16 | notable | **CONFIRMED** | Email is the only channel: no webhook, Slack, Teams, PagerDuty, SMS, syslog or trap forwarding. | `alertengine.py:1156-1230` | generic webhook with the existing template engine; **M** |
| A-F17 | notable | **CONFIRMED** | No per-rule recipients, escalation, on-call or shift awareness; every alert goes to `smtp_to_default`. | `alertengine.py:1199-1205` | `recipients` column; **S**; escalation **M** |
| A-F18 | notable | **CONFIRMED** | Mute is device-only, capped at 24 h, cannot be scheduled; traps, syslog, IPAM, NetPath targets and APs cannot be muted at all. | `alertengine.py:170,179-215`, `alertsdb.py:199` | maintenance windows table keyed on `(entity_kind, entity_id)` with schedule; **M** |
| A-F19 | notable | **CONFIRMED** | Acknowledge is irreversible; "Acknowledge all" zeroes the fleet badge; the badge has no severity colour though `open_summary()` computes `worst`. | `alertsdb.py:936-949`, `app.js:1008-1013` | un-ack; badge shows open + acked with colour; **S** |
| A-F20 | notable | **CONFIRMED** | Alert list silently truncates at 300 with no total; bulk actions act on the page. | `api.py:2981`, `alerts.js:57-65`, `:213` | return `total`, act on the filter; **S/M** |
| A-F21 | notable | **CONFIRMED** | Emails carry an unlabelled server-local timestamp. | `alertmail.py:104-108` | add offset; **S** |
| A-F22 | notable | **CONFIRMED** | `count` inflates by 12/minute on threshold alerts and is printed in the email ("occurred 8640 time(s)"). | `alertengine.py:678-695` | increment on new sample only; **S** |
| A-F23 | notable | **CONFIRMED** | `duration_text(0.4)` renders "0 s" — the case its docstring says it avoids. Seen live in a recovery mail. | `alertmail.py:132-138` | round first; **S** |
| A-F24 | severe | **CONFIRMED** | No dependency map: a core failure is N independent alerts; interface alerts on the upstream's ports are excluded from rollup by design. | `alertrules.py:142-189`, `:158-162` | upstream-device field (manual or seeded from NetPath), consulted before opening `device_down`; **L**, very high value |
| A-F25 | notable | **CONFIRMED** | Missing NOC essentials: top-N noisy devices, alert history/MTTR report, SLA/uptime report (segments already computed in `device_status_segments`), per-site filter, export, ticket link, runbook URL, appendable notes, desktop notification. | `alertsdb.py:675-695`, `nodesdb.py:1558-1592` | top-N and CSV **S**; runbook column **S**; site filter and SLA **M** |
| A-F26 | severe | **CONFIRMED** | Six unrelated rules are bound to the `device_down` email template, whose subject is "{{device_name}} is not responding": `device_auth_fail`, `device_unsupported`, `poll_overrun`, `mib_missing` (`alertsdb.py:217-220`), `interface_down` (`:221`) and `interface_flapping` (`:223`) — plus the two wireless rules at `:243` and `:248`. The first draft cited the block as `217-222`, which wrongly included `interface_up` at `:222`; that rule is bound to `device_up` and is correct. CONFIRMED in the demo: adding 250 devices produced 234 emails titled "acc-sw-070 is not responding" that were actually "vendor MIB not uploaded". An operator reading the inbox sees a site outage that is not happening. | `alertsdb.py:217-221`, `:223`, `alertmail.py:20` | one generic "{{rule_name}}: {{entity_label}}" template for non-outage rules; **S** |
| A-F27 | severe | **CONFIRMED** | Onboarding storm: every device with a recognised enterprise arc and no uploaded MIB opens `mib_missing` on its first poll. 234 alerts and their emails within the first minute of seeding 250 devices; with the default 300 s grace they are held, then fire anyway because the condition persists. Nothing bulk-resolves them and the rule has no auto-resolve. CONFIRMED. | `nodepoll.py:1390`, `alertsdb.py:220` | ship `mib_missing` disabled or severity 7 with no email; bulk-resolve by rule; **S** |

### 4.4 Security and credentials

| # | Sev | Tag | Finding | Evidence | Fix / effort |
|---|---|---|---|---|---|
| S-B1 | blocker | **CONFIRMED** | Self-update executes unsigned code from the tip of a mutable GitHub branch: no signature, hash, tag pin or disable setting. Push access to the repo is RCE on every host holding the plant's credentials. CONFIRMED. | `selfupdate.py:54-56`, `:86-108`, `:261-322`, `server.py:238` | signed tags or pinned digest; `updates_enabled` default off; **M** |
| S-B2 | blocker | **CONFIRMED** | The forced admin password change is enforced only in `app.js:1019`; `admin`/`admin` with `must_change` set gets 200 from every API route. CONFIRMED. | `api.py:3887-3927`, `server.py:437-520` | refuse routes except session/password while set; **S** |
| S-B3 | blocker | **CONFIRMED** | Privilege escalation: `debug: write` → `POST /api/settings {scope:"debug"}` falls through to `apply_global_settings` (bind address, port, TLS paths, DNS server, session lifetimes) and echoes the unfiltered settings. CONFIRMED with a debug-only user. | `server.py:48-56`, `api.py:841-862`, `service.py:229-253` | derive the module from the dispatch table; filter the response; **S** |
| S-S1 | severe | **CONFIRMED** | `POST /api/alerts/smtp/test` sends the stored SMTP password in cleartext AUTH PLAIN to any host and port in the body (also an SSRF primitive). CONFIRMED against a listener. Same class: DHCP and device edit before test/poll. | `api.py:3265-3298`, `alertmail.py:262-272` | refuse the stored secret with a body-supplied host; **M** |
| S-S2 | severe | **CONFIRMED** — **RESOLVED UPSTREAM in 4.36.x** | ConfigRX accepted any SSH host key on every connection: no `known_hosts`, no pinning, `allow_legacy_ssh` default true, password auth only. As measured against 4.35.0 this was a man-in-the-middle away from every stored device password. **Closed by 4.36.0**, which added `netpath/hostkeys.py` — a host-key store in `configrx.db` keyed on host and port, pinned on first sight and refused on change, shared by ConfigRX and the SSH terminal — with a "Forget host key" action gated on `configrx: write`. The row is kept because the evidence and the reasoning still apply to any 4.35 install. `allow_legacy_ssh` defaulting to true is **not** closed and remains in scope (D5). | `configrx.py:288-299`, `:655-662`, `:503-504`; fixed in `netpath/hostkeys.py` | persist and pin host keys (**done in 4.36.0**); default legacy off; **M** |
| S-S3 | severe | **CONFIRMED** | Config backups (communities, TACACS keys, IPsec PSKs, enable secrets) are zlib-only and served to any `configrx: read` user; not listed in `CREDENTIAL-SECURITY.md`'s inventory. | `configrxdb.py:224-229`, `api.py:3846-3851`, `server.py:229` | gate content on WRITE; redact known secret lines; **M** |
| S-S4 | severe | **CONFIRMED** | Database files are created 0644 in a 0755 directory; no chmod or umask anywhere. CONFIRMED. | `__main__.py:20-27` | `mode=0o700`, `chmod 0o600`; **S** |
| S-S5 | severe | **CONFIRMED** | DPAPI-only secret storage: nothing credentialed works on Linux (see Verdict). | `dpapi.py:47-49`, eight `api.py` endpoints | platform-neutral `secretstore`; **L** |
| S-S6 | severe | **CONFIRMED** | Default bind is plain HTTP on 0.0.0.0 and the headless banner still says "There is no authentication yet" on every start (auth shipped in 4.22). CONFIRMED. | `__main__.py:144-145`, `:177`, `server.py:8-10` | delete the claims; default to loopback; warn without TLS; **S** |
| S-S7 | severe | **CONFIRMED** | `settings: write` is undeclared root: grants itself every module, resets any password, triggers self-update; no self-escalation guard. | `server.py:68-71`, `api.py:3977-4013` | explicit admin capability; **M** |
| S-N1 | notable | **CONFIRMED** | Username enumeration: the dummy hash uses N=2^14 vs real 2^17 (0.055 s vs 0.48 s). CONFIRMED. | `api.py:3903-3907` | build from live constants; **S** |
| S-N2 | notable | **CONFIRMED** | Login throttle is delay-only, dilutes under concurrency (12 parallel guesses in 10.7 s), any successful login clears the whole client key; ~134 MiB scrypt per attempt on a public endpoint. | `auth.py:265-304`, `api.py:3895-3897` | semaphore, lockout, never clear on another user's success; **M** |
| S-N3 | notable | **CONFIRMED** | No CSRF token; Origin never checked (SameSite + JSON content type only). | `server.py:466-472` | require same-origin `Origin`/`Sec-Fetch-Site`; **S** |
| S-N4 | notable | **CONFIRMED** | No `frame-ancestors`, `form-action`, `base-uri` or HSTS. | `server.py:345-350` | extend CSP; **S** |
| S-N5 | notable | **CONFIRMED** | `App.modal()` interpolates device `sysName` into `innerHTML` unescaped (markup injection; CSP blocks script). | `app.js:386-392`, `nodes.js:1971`, `configrx.js:346` | escape in `modal()`; **S** |
| S-N6 | notable | **CONFIRMED** | Body `_agent` overrides the real User-Agent in the session list; underscore keys are stripped from the query only. | `server.py:441-443`, `api.py:3924` | filter body keys; **S** |
| S-N7 | notable | **CONFIRMED** | `apply_netpath_settings` mutates the shared global settings dict. | `service.py:66`, `:258-263` | separate dicts; **S** |
| S-N8 | notable | **CONFIRMED** | MIB catalog downloads use no vendored CA bundle and no integrity pin. | `mibcatalog.py:626-650` | reuse `selfupdate._ssl_context()`, pin SHA-256; **S** |
| S-N9 | notable | **CONFIRMED** | The audit trail is a 3,000-entry in-memory ring a `debug: write` user can flush; a 200 KB username evicts it. | `eventlog.py:55-70`, `api.py:3908` | on-disk append-only audit log; **M** |
| S-N10 | notable | **CONFIRMED** | No session revocation; `debug: read` reads every module's events. | `api.py:3963-3975`, `:687-830` | delete-session route; filter events by grant; **S** |
| S-N11 | notable | **CONFIRMED** | Discovery sweeps have no pacing (64 parallel pings, then SNMP probes) and no never-scan list — a known way to upset fragile PLC stacks; `/focus` (3 s polling) is gated on READ. | `ipam_scan.py:225-235`, `nodediscover.py:138-172`, `server.py:130` | probes/s ceiling, deny-list, WRITE on focus; **M** |
| S-N12 | notable | **CONFIRMED** | Maintenance "prune" actions delete *everything* (`prune(0, 0)`), including all config backups, with no typed confirmation. | `api.py:876-913` | require `confirm` and log counts; **S** |
| S-N13 | notable | **PLAUSIBLE** | Slowloris: no handler timeout, no connection cap, 128 MiB max body. PLAUSIBLE. | `server.py:316`, `:367`, `:565-568` | `timeout = 30`, bounded pool; **S** |
| S-N14 | notable | **CONFIRMED** | Chunked request bodies are treated as empty (a proxy forwarding chunked POSTs would execute defaults). CONFIRMED. | `server.py:369-381` | reject `Transfer-Encoding`; **S** |
| S-N15 | notable | **CONFIRMED** | Scripts are signed out after the idle timeout regardless of API activity: the timeout counts browser heartbeats only, so a polling automation loses its session after 10 min (the campaign's snapshots went blank at exactly that point) and must re-login; there is no API token or service account and no documented heartbeat for non-browser clients. CONFIRMED in the demo. | `auth.py:180-193`, `app.js:136-216` | API tokens, or a documented `/api/heartbeat` for scripts; **S/M** |
| S-N16 | notable | **CONFIRMED** | SNMP community strings are stored in cleartext and returned in full to any account with `nodes: read`: `_device_json`, `_group_json`, `_group_credential_json` and `_controller_json` all copy `community` into the response. A read-only operator can read every device's write-community-in-practice string. | `api.py:1531-1609`, `:3321` | return `has_community` for READ, the value only for WRITE; **S** |
| S-A1 | absent | **CONFIRMED** | LDAP/AD/SAML/RADIUS/TACACS+, MFA, API tokens or service accounts, per-site RBAC, password expiry, persisted failed-login records, on-disk audit log. | `permissions.py:16-19`, `FEATURES.md:48` | procurement gates for a regulated network; **L** |

### 4.5 Performance and scale

All eight fixes claimed in `PERFORMANCE_REVIEW.md` are present and correct; that
review only looked at request-path N+1s. **Estimated** capacity as shipped (bound
by per-sample commits on a realistically sized `samples` table): **~1,350
devices** at 48 ports and 120 s, ~680 at 60 s, ~130 for 500-port chassis. After
the five fixes marked ★ below: ~4,000–5,000 at 120 s.

These are extrapolations from the write-path benchmarks below, not tier
measurements: the campaign ran at 250, 1,000 and 2,000 devices, so no tier sits
near ~680 and none of these figures was bracketed by a run. What the tiers do
show (§3.3) is consistent with them — detection is late at 1,000 and absent at
2,000, both at a 60 s interval.

| # | Sev | Tag | Finding | Measured | Fix / effort |
|---|---|---|---|---|---|
| X-F1 ★ | blocker | **CONFIRMED** | Global sample cap (see §4.1 P-B1): the 50,000 surviving rows are shared across every metric of every device, so at 2,000 devices — 171,910 rows in `metrics`, ≈86 metrics per device — **0.29 samples per metric** survive a prune, not the 1.29 the first draft printed (that figure divided by an assumed metric count instead of the measured one). Under one sample in three metrics survives; the DELETE of ~11.1M rows holds the process lock ~44 s every 15 min. | 1.11M rows / 4.42 s at 1/10 scale; 50,000 ÷ 171,910 = 0.29 | per-metric cap, chunked; **S** |
| X-F2 ★ | blocker | **CONFIRMED** | `compact_rollup()` dead; 400-day windows return 0 points. | 0 points | call from maintenance; **M** |
| X-F3 ★ | blocker | **CONFIRMED** | One commit per metric sample: 13,731/s on an empty table → **2,181/s** at 5M rows, while batching sustains **150,832/s** — **69×**, not the 62× the first draft printed (2,181 → 150,832 is 69.2). The fleet's requirement is ~2,870/s at 2,000 devices and a 60 s interval, computed from the measured ≈86 metrics per device (§4.1 P-S6); an earlier draft said 3,233/s from an assumed 97. Either way the shipped write path cannot meet it and the batched one clears it fifty times over. | 2,181/s per-row → 150,832/s batched = 69× | `record_metric_samples`, one transaction per device poll; **M** |
| X-F4 ★ | severe | **CONFIRMED** | Scheduler loop: 4,001 queries/s at 2,000 devices. | 118 ms/iteration | cache settings/groups; **S** |
| X-F5 | severe | **CONFIRMED** | `trim_to_size()` runs VACUUM inside the lock up to six times (6.49 s each at 2M rows). Same shape in five other DB modules. | 38.9 s stall | VACUUM outside the lock or incremental; **M** |
| X-F6 ★ | severe | **CONFIRMED** | One SNMP GET per port: 500-port chassis at 30 ms RTT = 15.2 s serial per poll. | — | GETBULK the columns (machinery at `nodepoll.py:1742-1778`); **M** |
| X-F7 | severe | **CONFIRMED** | `/api/nodes/devices` unpaged: 2.18 MB and 115 ms of lock-held CPU per refresh per tab (default every 10 s; the UI walk saw it every 2 s). Measured on a freshly seeded 2,000-device table; the same endpoint served 2.64 MB at the end of a full campaign once identity fields were populated (§3.1). | 2,175.9 KiB | paging + drop `sys_descr` from the list; **M** |
| X-F8 | severe | **CONFIRMED** | Alert tick reads every metric of every device every 5 s. 0.85 s/tick at ~200 metrics per device; see §4.3 A-F14 for why this report carries 0.85, 0.96 and 0.436 for the same operation. | 436 ms at 100/device; ≈0.40 s at the 86/device measured live | keyed query; **M** |
| X-F10 | notable | **CONFIRMED** | MAC prefix search uses `LIKE`, defeating its index: 528× slower than a range scan; fired per keystroke. | 10.57 ms vs 0.02 ms | range predicate; **S** |
| X-F11 | severe | **CONFIRMED** | Raw samples: 9.1 GB/day at 2,000 × 48 ports; 400-day default = 3.6 TB (only survivable because F1 throws it away). | 33 B/row | fix F2, document per-port cost; **S** |
| X-F12 | severe | **CONFIRMED** | One `RLock` and one connection serialise 16 workers, the scheduler, the alert tick, maintenance and every HTTP handler; WAL buys nothing. | 16 threads = 3.5× not 16× | per-worker connections with `busy_timeout`; **L** |
| X-F15 | notable | **CONFIRMED** | Ping = 3 serial subprocess spawns per device per poll; a down device costs ~12 s of worker time. | 2.3 ms/spawn | concurrent probes, back-off; **M** |
| X-F17 | notable | **CONFIRMED** | `/api/state` fans out across ten databases and 30 `stat()` calls every 2 s per tab. | — | COUNT queries, cache sizes; **S** |
| X-F19 | notable | **CONFIRMED** | No `visibilitychange` handling; a minimised tab polls forever. | — | pause hidden tabs; **S** |
| X-F20 | notable | **CONFIRMED** | Table sort calls `localeCompare` per comparison (19 of 29 ms per redraw at 2,000 rows); no virtual scrolling (24,000 live cells). | 29.4 ms JS | hoist an `Intl.Collator` **S**; virtual rows **L** |
| X-F21 | notable | **CONFIRMED** | `series()` returns every raw point (28,800 for 24 h at focus cadence); the chart cannot show more than ~800. | 26.8 ms/50k | default `bucket_s` from pixel width; **S** |
| X-F22 | notable | **CONFIRMED** | Pure-Python BER: 22% of one core at 2,000 × 48 ports at 120 s, 44% at 60 s. | 122 µs encode | F6 removes most of it |
| X-F9 | notable | **CONFIRMED** | `hostresolve.resolve_name()` is called inside the per-rule loop of `_evaluate_thresholds`, so it runs devices × rules times per tick; on a fleet mid-discovery each miss costs one `app_db.hostnames([ip])` query. 2,000 devices × 6 live rules = 12,000 calls per 5 s tick. | traced | hoist `label` out of the rule loop (`alertengine.py:676`); **S** |
| X-F13 | notable | **CONFIRMED** | `_poll_device` calls `interface_id_for()` for an id it already holds in the `existing` dict two lines above: one avoidable SELECT per interface per poll, ~800 queries/s at 2,000 × 48 ports and 120 s, each taking the global lock. | traced | use `prior["id"]` (`nodepoll.py:1005`, `:1043`); **S** |
| X-F14 | notable | **CONFIRMED** | `replace_interfaces` matches on `if_index` and UPDATEs — the right shape — but UPDATEs unconditionally, including the polls where every compared field is identical: 500 no-op row rewrites per poll of the chassis, each dirtying a page that must be journalled and checkpointed. | traced + benchmarked | compare against the already-loaded `prior` row (`nodesdb.py:1341`, `:1358`); **S** |
| X-F16 | notable | **CONFIRMED** | `_extra_resolve_targets()` full-table-scans the IPAM hosts and the device table every 15 s whether or not anything needs resolving, then discards the result whenever the primary hop batch already has 40 entries: ~1.7 device-table scans a minute on the poll writers' lock, for nothing. | 25 ms/scan at 2,000 | move the block behind the existing `len(batch) < 40` test (`service.py:604-622`, `monitor.py:381-385`); **S** |
| X-F18 | notable | **CONFIRMED** | One open Nodes tab is ~1.6 requests/s: `refresh()` fires five parallel requests and `loadDetail()` five more, four of which (groups, device-groups, MIB files, the column set) only ever change on operator action. | traced | fetch those four once and on mutation (`nodes.js:3160-3166`, `:498-504`); **S** |
| X-F23 | notable | **PLAUSIBLE** | Unbounded `IN (...)` lists: a "select all → bulk poll" at 2,000 devices builds a 2,000-element list. SQLite 3.45 allows 32,766 host parameters, so this does not fire here — but older builds, including the system SQLite in some Windows Python distributions, default to 999. Not reproduced. | not reproduced | chunk at 500 in `_rows_by_ids` and `devices_by_ids` (`nodesdb.py:955-963`, `:1036-1050`, `ipamdb.py:313-323`); **S** |
| X-F24 | nit | **CONFIRMED** | `metrics()` carries an `ORDER BY label` that its hottest caller throws away into a dict on the next line: 388,000 rows sorted every 5 s for nothing at 2,000 devices. | traced | drop the `ORDER BY`, sort in the one caller that displays it (`nodesdb.py:1422-1426`, `api.py:2288`); **S** — subsumed by X-F8 |
| X-F25 | nit | **CONFIRMED** | `settings()` re-reads the whole settings table and re-runs `json.loads` per row on every call, and it is called from `effective_config()`, `_poll_device` and `_tick` — the three hottest paths in the process. | ~0.05 ms/call | memoise behind a generation counter bumped by `save_settings()` (`nodesdb.py:686-696`); **S** — subsumed by X-F4 |
| X-F26 | nit | **CONFIRMED** | `journal_mode=WAL`, `synchronous=NORMAL` and `foreign_keys=ON` are the right choices; `busy_timeout`, `cache_size` and `mmap_size` are unset. `cache_size` defaults to 2 MB against databases that reach a gigabyte, and `busy_timeout` becomes mandatory the moment X-F12 is fixed. | — | `PRAGMA cache_size=-65536`, `PRAGMA busy_timeout=5000` (`nodesdb.py:495-497`); **S** |
| X-F27 | nit | **CONFIRMED** | `_migrate()` runs six `PRAGMA table_info` calls and several `CREATE INDEX IF NOT EXISTS` statements on every open. Startup-only, idempotent, ~10 ms — correct as written. Recorded so a slow first `/api/state` is not mistaken for a steady-state cost. | ~10 ms at open | none needed (`nodesdb.py:507-654`) |
| X-F28 | severe | **CONFIRMED** | Single process, no remote pollers, no sharding: every ceiling compounds in one process and a datacentre failure takes monitoring with it. | — | remote-poller agent; **L** |

### 4.6 UX, accessibility and documentation truth

| # | Sev | Tag | Finding | Evidence | Fix / effort |
|---|---|---|---|---|---|
| U-F12 | blocker | **CONFIRMED** | The Dashboard is a 385-byte placeholder, and `login.js:44` makes it the landing page after every sign-in. | `dashboard.js`, `index.html:41-47` | tile grid over existing endpoints; **M** |
| U-F27 | blocker (on-call) | **CONFIRMED** | Zero media queries; `body{overflow:hidden}` clips rather than scrolls; at 390 px six of twelve tabs are unreachable and every device name is cut. CONFIRMED with a screenshot. | `app.css:51-59`, `app.js:956-960` | `nav{overflow-x:auto}` **S**; narrow layout **L** |
| U-F36 | blocker (intermittent) | **CONFIRMED** | ConfigRX reported "paramiko is not installed" beside "paramiko 4.0.0" in the same `/api/state`; the unlocked `_paramiko_ok` cache is written from two threads, and when it caches `False` the module is disabled fleet-wide and legacy SSH is never applied. Reproduced once. | `configrx.py:78`, `:105-120`, `:493` | put the cache behind the lock; **S** |
| U-F1 | severe | **CONFIRMED** | No URL routing: nothing can be linked to, Back does nothing, escalations are prose. CONFIRMED. | `app.js:963-985` | hash routes; **M** |
| U-F2 | severe | **CONFIRMED** | Search is `LIKE %q%` over ip, name, sys_name only: `q="Cisco"` returns 0 rows with Vendor visible as a column. | `nodesdb.py:932-937` | add vendor/location/contact, CIDR, field qualifiers; **S/M** |
| U-F3 | severe | **CONFIRMED** | No paging or virtualisation; 2.19 MB per refresh, 25,402 DOM nodes at 2,000 devices. | `api.py`, `nodes.js:196-230` | server paging; **M** |
| U-F4 | severe | **CONFIRMED** | One flat group level; no sites, tags or saved views; column layout is global. | `nodes.js:145-150`, `:185-186` | tags + per-user saved views; **L** |
| U-F5 | severe | **CONFIRMED** | No export of any table, in any tab: no CSV, no clipboard, no print view. README documents a "Data > Export window to CSV" that does not exist. | grep, `README.md:592`, `FEATURES.md:1850` | generic `GET /api/<module>/export.csv` honouring the current filter; **M** |
| U-F6 | severe | **CONFIRMED** | No CSV or bulk import: onboarding 500 devices is 500 dialogs (`POST /api/nodes/devices` is one device per call). | `api.py:1773`, `nodes.js` add-device dialog | paste-CSV import behind `POST /api/nodes/devices/bulk`; **M** |
| U-F7 | severe | **CONFIRMED** | Maintenance windows impossible (see §4.3 A-F18). | `alerts.js:36`, `:307`, `api.py:3049-3056` | **M** |
| U-F10 | severe | **CONFIRMED** | Alerts list truncates at 300 and the label says "300 shown" with no total; select-all acknowledges 300 of N. | `api.py:2981`, `alerts.js:213` | total + honest label; **S** |
| U-F15 | severe | **CONFIRMED** | Zero ARIA anywhere outside the 4.35 help panel: no `role`, no `aria-*` on any control the operator uses all day. CONFIRMED in the DOM at 2,000 devices. | `app.js:385-415`, `:455-476` | lift the help panel's own patterns into the shared helpers; **S** |
| U-F16 | severe | **CONFIRMED** | 29 tables, 30 `<th>`, zero `scope`, zero `<caption>`, zero `aria-sort`: a screen reader cannot say which column a cell belongs to. | `app.js:692-796` (`App.grid`) | one change in the shared grid helper; **S** |
| U-F17 | severe | **CONFIRMED** | Sorting is mouse-only — headers are `<th>` with a click handler, no `tabindex`, no key handler. | `app.js:692-796` | `tabindex="0"` + Enter/Space in the grid helper; **S** |
| U-F18 | severe | **CONFIRMED** | The main modal has no dialog role, no `aria-modal`, no focus trap and drops focus to `body` on close — while the help panel ten lines away does all three correctly. | `app.js:385-425`, `:455-476` | lift help-panel behaviour into `modal()`; **S** |
| U-F19 | severe | **CONFIRMED** | Nothing is announced: no `aria-live`/`role="status"` on the connection state, the idle banner or the bulk-action result, so a screen-reader user never learns the server went away. | `app.js:130-134`, `:197-213` | `role="status"` on `#conn` and the bulk notice, `role="alert"` on the idle banner; **S** |
| U-F20 | severe | **CONFIRMED** | Under deuteranopia `--ok`, `--fail`, `--blocked` collapse to three khakis (1.34:1 apart); `--fail` and `--error` have identical luminance; timelines are colour-only with mouse-only tooltips. | `theme.py:38-44`, `nodes.js:826-833` | extend the existing hatch/stripe vocabulary; **S** |
| U-F21 | severe | **CONFIRMED** | `.hint` is 2.50:1 contrast at 11 px and it renders every device's IP address. | `app.css:264`, `nodes.js:143` | use `--muted`; **S** |
| U-F23 | severe | **CONFIRMED** | Server loss shows the raw string "Failed to fetch" in 11 px grey while 2,000 stale rows stay on screen looking live; no staleness marking, no reconnect signal. CONFIRMED offline. | `app.js:130-134`, `:1076-1096` | operator-language message, dim stale content; **S/M** |
| U-F24 | notable | **CONFIRMED** | No spinners, no `aria-busy`, no request timeout. | `app.js:104-116` | **S** |
| U-F13 | notable | **CONFIRMED** | The README's NetFlow keyboard shortcuts (Ctrl+=/−/arrows/0/Home) do not exist; no modifier-key handler exists anywhere. CONFIRMED by grep and in the browser. | `README.md:280-293` | implement or delete; **S** |
| U-F22 | notable | **CONFIRMED** | The help "?" covers 2 of ~150 settings. | `nodes.js:2356` | content, not code; **M** |
| U-F28 | notable | **CONFIRMED** | No favicon (404 on every load — `/favicon.ico` is in `PUBLIC_PATHS` and no file answers it), no alert count in the title, no desktop notification. | `server.py:260` (`PUBLIC_PATHS`; `:245` in the 4.35.0 tree), `web/static/` | **S** |
| U-F29 | notable | **CONFIRMED** | Timestamps are browser-local with no zone indicator anywhere. | `app.js:223-235` | zone label, UTC toggle; **S/M** |
| U-F31 | severe | **CONFIRMED** | Wireless is FortiGate-only and the UI never says so. | `wirelessdb.py:1`, `wireless.js` | say it in the tab and empty state; **S** |
| U-F32 | severe | **CONFIRMED** | IPAM's DHCP form renders fully on Linux with Windows-only help text; `IS_WINDOWS` is defined and never used. | `ipam_dhcp.py:54`, `ipam.js:445` | gate the form; **S** |
| U-F33 | severe | **CONFIRMED** | ConfigRX detects a change (SHA-256) and cannot show a diff. | `configrx.js:452-456` | `difflib` unified diff endpoint; **M** |
| U-F34 | notable | **CONFIRMED** | `POST /api/nodes/devices` accepts `snmp_version: "2c"` and the poller then raises `ValueError` on every poll of that device. CONFIRMED. | `api.py`, `nodepoll.py:1261` | validate and coerce; **S** |
| U-F8 | notable | **CONFIRMED** | No side-by-side device comparison: the detail pane is bound to `view.selected`, so "why is this switch slower than its twin" is answered by alt-tabbing and remembering numbers. | `nodes.js:3175-3179` | "Pin to compare" over the existing splitter machinery (`app.js:577`); **M** |
| U-F9 | notable | **CONFIRMED** | The interface bandwidth dialog is hard-coded to a one-hour window with no range control, so a nightly backup saturating a link cannot be seen. | `nodes.js:1566` | reuse the existing `RANGES` select (`app.js:299`); **S** |
| U-F11 | notable | **CONFIRMED** | Bulk actions exist for poll, re-identify, profile, group, delete, ack and resolve, but not for **mute**, tag, credential change, enable/disable polling, export or add — and bulk mute is the one an on-call operator needs at 02:00. | `index.html:89-100`, `:201`, `:229-234` | bulk mute on top of U-F7's work; **S** |
| U-F14 | notable | **CONFIRMED** | "Ctrl+click bulk select" headlines the 4.21.0 CHANGELOG entry and no longer exists (checkboxes replaced it; no `ctrlKey` handler ships). Historically accurate as a changelog entry, but a reader scanning headlines for "how do I multi-select" is sent to a removed feature. | `CHANGELOG.md:1024`, `:641`, `:666`, `:673`, `FEATURES.md:162`, `:586` | a "(removed in 4.2x — use the row checkboxes)" note on the heading; **S** |
| U-F25 | nit | **CONFIRMED** | Empty states are a strength — IPAM, NetPath, Wireless, ConfigRX and the two detail panes all name the next action — with two gaps: the Nodes table at zero devices shows a bare header and "0 device(s)", and the Wireless and ConfigRX tables render empty headers with no guidance. | `configrx.js:452-456`, `index.html:108`, `:243` | one call-to-action line per empty table; **S** |
| U-F26 | nit (positive) | **CONFIRMED** | 401-after-idle is handled better than most commercial NMS: any non-login 401 redirects to `/login`, and the idle clock is genuinely presence-based (only real input resets it, heartbeats throttled to 20 s, the server's figure authoritative against clock skew) with a "Signing out in N s" banner at 60 s. Only defect: no `aria-live` (U-F19). | `app.js:110-113`, `:136-216` | keep it |
| U-F30 | nit | **CONFIRMED** | `stamp()` uses `toLocaleDateString` while `clock()` hand-builds `HH:MM`, so one string mixes a localised date with a forced 24 h time; no i18n framework, all strings inline. 24 h is right for network operations — this is a consistency nit. | `app.js:223-235` | one formatter; **S** |
| U-F35 | nit (positive) | **CONFIRMED** | Interface events, the MAC-table cascade and the on-demand optics/sensor readout are the best interactions in the product, and discovery partly covers the missing bulk import (U-F6). | UI walk, all tiers | keep them |
| U-C1 | notable | **CONFIRMED** | `window.App` does not exist (`const App` in a classic script); documentation and any automation assuming a window global is wrong. | `app.js:3` | expose it; **S** |
| U-C2 | notable | **CONFIRMED** | Uncaught `TypeError` from the OID browser when another dialog replaces the modal mid-walk (`#oid-status` gone); same pattern in `deviceDialog`. CONFIRMED in the console log. | `nodes.js:1261`, `:1346`, `:922` | check the dialog identity, not the modal; **S** |
| U-C3 | notable | **CONFIRMED** | Read-only users get a 403 every time they open Settings (`loadUsers()` called unconditionally; route needs WRITE); the grid is silently empty. | `settings.js:442`, `server.py:68` | gate on the grant; **S** |

Documentation truth table. Every row was checked against the code or the running
application and is therefore **CONFIRMED**; no row here is an inference. The
first draft left four rows unnumbered and merged three pairs, so ids in earlier
correspondence may not match — D11, D14, D23 and D24 are the four that had none,
and D25 is new (see Appendix C).

| # | Claim | Where | Reality |
|---|---|---|---|
| D1 | "`deploy\Install-Shortcut.ps1` builds it", with a usage example | `README.md:99`, `:102` | no `deploy/` directory exists in the repository |
| D2 | "`deploy\Update-SappiWhere.ps1` wraps that", with a usage example | `README.md:453`, `:459` | same: the only documented update path is a missing script |
| D3 | "There is no authentication yet: bind somewhere you trust." | `__main__.py:177-180`, printed on every headless start | auth, sessions and permissions since 4.22 |
| D4 | The same claim in the server's module docstring | `web/server.py:8-10` | as D3 |
| D5 | NetFlow chart Ctrl shortcuts (Ctrl+=/−, Ctrl+←/→, Ctrl+0, Home) | `README.md:280-293` | not implemented; no modifier-key handler exists anywhere |
| D6 | "there is no SNMP polling … and no alerting engine … yet" | `FEATURES.md:1141-1143` | both exist (`nodepoll.py`, `alertengine.py`) |
| D7 | "Data > Export window to CSV" | `README.md:592`, `FEATURES.md:1850` | no CSV export exists, in any tab |
| D8 | "Verified with a Playwright test" | `PERFORMANCE_REVIEW.md:69-79` | no Playwright test is in the repository |
| D9 | "Verified with a Playwright test" (second occurrence) | `PERFORMANCE_REVIEW.md:93-95` | as D8 |
| D10 | "Worth adding next — alerting on status transitions" | `README.md:598-600` | shipped |
| D11 | "raw samples roll up into hourly min/avg/max after 3 days" | `NETWORK-AND-STORAGE-REQUIREMENTS.md:270` | the rollup never runs: `compact_rollup()` has no caller (§4.1 P-B2) |
| D12 | "SHOW RUN — available once SSH integration is added" | `nodes.js:1577` (in the UI) | ConfigRX shipped; and since 4.36.0 there is an SSH terminal too |
| D13 | "hundreds of devices" | `FEATURES.md:177` | the only scale figure in 470 KB of documentation |
| D14 | "~150 bytes per syslog message" | `NETWORK-AND-STORAGE-REQUIREMENTS.md:269` | ~455 B measured (§4.2 C-N7), three times the estimate |
| D15 | ports table | `NETWORK-AND-STORAGE-REQUIREMENTS.md:21-25` | correct throughout; the most trustworthy document in the set |
| D16 | — | all `.md` | no table of contents in any document, including the 245 KB `INTERNALS.md` |
| D17 | — | all `.md` | no quick-start: nothing takes a new operator from "installed" to "first device polled" |
| D18 | — | all `.md` | no API reference, for ~170 routes |
| D19 | — | all `.md` | no backup or restore guide, for a product with ten WAL databases |
| D20 | — | all `.md` | no runbook for the failures this review found (poller stopped, collector stopped, cap reached) |
| D21 | upgrade guide | `README.md` | Windows-only, though Linux/systemd is a documented deployment |
| D22 | — | `README.md` | covers 4 of 12 tabs; neither Nodes nor Alerts is among them |
| D23 | "CPU/memory where UCD-SNMP-MIB **or HOST-RESOURCES-MIB** is present" | `FEATURES.md:94-96` | `HOST_RESOURCES` is defined at `nodeoids.py:64-67` and referenced nowhere (§4.1 P-S9) |
| D24 | engine parameters "only need refreshing if the target reboots" | `nodepoll.py:44-46`, `INTERNALS.md:445` | engineTime is never advanced (§4.1 P-S3) |
| D25 | "Never phones home. There is no telemetry, **no update check**…" | `CREDENTIAL-SECURITY.md:573` (§8) | the Update button calls `selfupdate.latest_commit()`, which requests `https://api.github.com/repos/…/commits/<branch>` on every press (`selfupdate.py:86-92`). Nothing is *sent* — no telemetry, no credential — but an outbound request to GitHub is made, and the sentence as written says it is not. Added by the re-review (Appendix C) |
| D26 | "There is no authentication yet, so bind to an interface you trust…" — a **third** copy of D3/D4, and the one an operator sees most | `console.py:523-527`, the permanent hint under the listener card, repainted every second | as D3/D4. Three shipped places say it, two of them on screen or in the log on every single run. Found by the fresh-eyes pass (G-23) |
| D27 | `VERIFIED`: "every arc was read out of the vendor's own MIB text (the `::= { enterprises N }` line)" | `enterprises.py:1-19`, reaching the operator as `confidence: high` in the device pane and in `vendor_evidence` | true of 1 of the 53 arcs. The repository contains vendor MIB text for Moxa's 8691 and for nothing else in the table, so the other 52 cannot have been read from anything in this build. The arcs themselves spot-check clean against real sysObjectIDs; it is the provenance claim that is false, and it is the claim `high` confidence rests on. Found by the fresh-eyes pass (G-15) |
| D28 | — | `netpath/mibs/` | eighteen of the twenty-one bundled `.mib` files are third-party (IETF standards-track under BCP 78, IEEE Std 802.1AB, IANA, Net-SNMP) and carried no attribution or licence notice at all, while the vendored xterm.js beside them correctly ships `LICENSE-xterm.txt`. Three of the files carry no copyright block internally either. Found by the fresh-eyes pass (G-32) |

---

## 5. Device-class coverage

What the product actually gives an operator for each class in this fleet, as
shipped, on Linux.

| Class | Discovery / identify | Health and metrics | Events and alerts | Config |
|---|---|---|---|---|
| **Switches** (Cisco, Aruba, Juniper, MikroTik, industrial Moxa/Siemens/Hirschmann) | sweep + sysObjectID arc; confident and evidence-backed | interface counters, errors, up/down, RTT/loss; MAC tables (excellent); DOM on demand. **No** CPU, memory, temperature, PSU/fan, PoE, STP, LLDP/CDP, ARP | link events, flap (blunted), reboot, device down (only if ping also fails), traps and syslog stored | ConfigRX for 6 vendors — **unusable on Linux** (SSH password DPAPI-only), no diff |
| **Firewalls** (FortiGate, Palo Alto, Check Point, SonicWall) | identified | interface counters and ping only. **No** sessions, VPN tunnels, HA state, CPU, memory, policy hits | generic only | FortiOS backup (same Linux caveat); PAN and Check Point not in the vendor list |
| **Wireless APs** | FortiGate WLC only: AP name, model, state, channel, tx-power, clients, per-radio | **No** Cisco WLC, Aruba, Meraki, Ruckus, UniFi; no client RSSI/SNR, no channel utilisation | AP offline / removed (Fortinet) | — |
| **P2P bridges** (Ubiquiti airFiber/airMAX, Cambium PTP, Mimosa, RADWIN) | identified | throughput only. **No** RSSI, SNR, modulation, capacity, remote-side signal — the numbers that predict a link failure; not reachable via the custom-MIB path (table-indexed) | link up/down | — |
| **PLCs** (Rockwell/Allen-Bradley, Siemens S7) | Rockwell by sysDescr substring only (no enterprise arc); Siemens by arc | IF-MIB is most of what their agents expose, so the gap is small; **no** Modbus/EtherNet-IP/PROFINET/S7 client (protocol names appear only as port labels in `services.py`) | ping/link | — |
| **Linux/net-snmp hosts** | identified | the only class with CPU and memory | full threshold set | — |

Cross-cutting on this fleet: SNMPv3 authPriv is unsupported and authNoPriv is
unconfigurable on Linux, so a hardened OT policy forces v2c everywhere; no
per-device SNMP port; no IPv6; a device that logs from a loopback address
different from its polled address correlates with nothing.

Two lines of this table have moved since it was measured against 4.35.0. The
Config column's "no host-key checking" caveat is closed — 4.36.0 pins a device's
SSH host key on first sight and refuses a changed one for both ConfigRX and the
new terminal (§4.4 S-S2) — and switches, firewalls and PLCs now have an
interactive SSH session from the device pane, which is a genuine addition to the
Config column for every class that speaks SSH. The credential problem underneath
is unchanged: on Linux there is still nowhere to store the password that session
or a backup needs.

---

## 6. Recommendations, ranked

Ordered by what most reduces the operator's time per incident and per change,
weighted by effort. "Where" names the code that already carries the mechanism.

### Tier 0 — correctness fixes to ship before anything else (all S unless noted)

1. **Per-metric sample cap and chunked prune** — `nodesdb.py:2171-2179`, `service.py:719`. Without this nothing charts and the process stalls 44 s every 15 minutes.
2. **Call `compact_rollup()` from maintenance and prune it by age** — `service.py:715`, `nodesdb.py:1480`. **M.**
3. **Batch each poll's samples into one transaction** — `nodesdb.py:1398`, `nodepoll.py:1055-1064`. **69×** write throughput (2,181/s → 150,832/s, §4.5 X-F3); raises the ceiling past 5,000 devices on its own. **M.**
4. **Exception guards on every loop that must not die**: `NodePoller._loop` (`nodepoll.py:690`), the NetFlow/trap/syslog receive loops (`collector.py:185`, and `DecodeError` in `nfdecode.py:150`), the alert apply loop with cursor commit after apply (`alertengine.py:156-177`).
5. **SMTP off the tick**: sender queue thread, failures count against the quota, breaker after N failures — `alertengine.py:1218-1228`. **M.**
6. **Fix `renotify_minutes`** (`last_notified_ts`) and give momentary-event rules an `auto_resolve_after_s` — `alertengine.py:1146-1152`, `alertrules.py:115-135`. **M.**
7. **Trap identity and severity**: entity `source:oid`, carry `traps.severity`, apply the gate to traps, real "unmanaged" check — `alertengine.py:504-509`, `:1116`. Syslog dedup on a message signature — `:535-539`.
7a. **Stop non-outage rules emailing "is not responding"**: give `mib_missing`, `device_auth_fail`, `device_unsupported`, `poll_overrun`, `interface_down` and `interface_flapping` their own subjects — `alertsdb.py:217-221`, `:223` (and the two wireless rules at `:243`, `:248`); ship `mib_missing` without email. Not **S**: see §7 #22a.
8. **SNMPv1 interface GET split** — `nodepoll.py:1642-1645`. Every v1-only switch and PLC is invisible until this lands.
9. **Advance SNMPv3 engineTime** — `nodepoll.py:1145`, `:1164-1171`.
10. **Security blockers**: server-side `must_change` (`server.py:_route`), the `debug` settings scope escalation (`server.py:48-56`), signed or pinned self-update with an off switch (`selfupdate.py`), stored-SMTP-password exfiltration (`api.py:3265-3298`), database file modes (`__main__.py:20-27`), and the two stale "no authentication yet" strings.
11. **Zero-length template guard** (`nfdecode.py:316-337`), **targeted FTS delete** instead of rebuild (`syslogdb.py:482`), **kernel drop counter** (`syslogd.py`, `collector.py`, `snmptrapd.py`; **M**), **alert drain catch-up loop with a visible backlog** (`alertengine.py:499,520`; **M**).
12. **Cache settings and groups in the scheduler** (`nodepoll.py:694-697`) and **one keyed query for the alert tick** (`alertengine.py:649-651`; **M**).
13. **Fix the test** that fails wherever `ping` is installed (`tests/test_nodepoll_e2e.py:219`) and add a CI job that runs `tests/run_all.py`.

### Tier 1 — what makes it a fleet monitor (the missing features)

| # | Feature | Why it saves time | Effort | Where it lands |
|---|---|---|---|---|
| 1 | **Platform-neutral secret store** (passphrase-derived key supplied at start, or libsecret/keyring) behind the `protect`/`unprotect` interface | Unlocks SNMPv3, ConfigRX, authenticated SMTP, wireless and DHCP credentials on Linux — five features at once | L | `dpapi.py` → `secretstore.py`; the eight `api.py` endpoints |
| 2 | **Upstream-device field and topology rollup** (manual first, then seeded from LLDP/CDP and the NetPath route graph) | A core failure becomes one alert instead of 500; the on-call reads one page, not a storm | L | `nodesdb` (`upstream_id`), `alertengine._rollup_parent` |
| 3 | **LLDP/CDP neighbour walk** (`lldpRemTable`, `cdpCacheTable`; both MIBs already ship) with a device-to-device map | Replaces the traceroute hop graph with a real L2 topology; feeds #2; "which port is the uplink" answered without a console | M | `nodepoll` (a `_walk_column` pair), a `neighbors` table, a map view |
| 4 | **Vendor health OIDs** keyed on `detected_vendor`: Cisco `cpmCPUTotal5minRev`/`ciscoMemoryPool`, Fortinet `fgSysCpuUsage`/`fgSysMemUsage`/`fgSysSesCount`/VPN tunnel count/HA state, Juniper `jnxOperating*`, PAN `hrProcessorLoad` + session stats, `hrProcessorLoad`/`hrStorage` generally; scheduled ENTITY-SENSOR/ENVMON temperature, PSU, fan; POWER-ETHERNET PoE budget | Turns an interface counter into a device monitor; makes `cpu_high`/`mem_high`/`disk_high` live on every class; answers "is the firewall out of sessions" | M scalars / L tables | `nodeoids.py` + `_poll_snmp_scalars`; a per-poll table-walk path |
| 5 | **P2P bridge RF metrics** (Ubiquiti airFiber/airMAX, Cambium PTP, Mimosa, RADWIN: RSSI, SNR, modulation, capacity, remote RSSI) as first-class, chartable, thresholdable metrics with per-link rules | The one class of device where degradation is visible days before failure; today invisible | M | same table-walk path as #4 |
| 6 | **Generic webhook channel** (URL, headers, JSON body through the existing template engine) plus per-rule recipients and an escalation timer | Covers Slack, Teams, PagerDuty Events, ticketing in one feature; ends the shared-inbox failure mode | M | `alertwebhook.py` (~40 lines of `urllib`), `rules.recipients`, `_notify` |
| 7 | **Maintenance windows** (entity kind: device, group, site, rule, all; start/end; recurring) consulted where mutes are today, plus bulk mute | A weekend cutover is one entry, not 400 daily clicks per device | M | `alertsdb` (`maintenance_windows`), `alertengine.py:170-215`, Alerts tab |
| 8 | **Dashboard**: fleet health tiles, open alerts by severity, module health strip, top offenders (worst loss, RTT, most flaps and alerts in 24 h), storage headroom — all from existing endpoints, each tile deep-linking | The screen every shift starts on; today it is blank | M (L with links) | `dashboard.js`, `index.html:41-47` |
| 9 | **URL routing** (`#/nodes/device/1234`, `#/alerts/998`) | Permalinks in tickets and chat; Back works; the Dashboard becomes clickable | M | `app.js` router + `selectFromRoute` per module |
| 10 | **CSV import and export** (devices with profile/site/overrides; alerts, interfaces, MAC tables with the current filter) | Onboarding a site from a spreadsheet in minutes; audits and post-incident reviews without screenshots | M | `POST /api/nodes/devices/bulk`, `GET /api/<module>/export.csv` |
| 11 | **Trap varbind and syslog pattern rules** (`match_field`, regex, `count_threshold` in `count_window_s`) with the matched text in the dedup key | The two rules a NOC actually writes become possible | M/L | `alertsdb` rules columns, `alertengine._apply` |
| 12 | **Device address aliases** (`device_addresses` from `ipAddrTable`, v1 `agent_addr`, manual) | Syslog and traps from loopback/management-VRF sources correlate to the device | M | `nodesdb`, `hostresolve.resolve_name` |
| 13 | **ConfigRX diff** between adjacent backups, a config-change alert rule, host-key pinning, and vendor profiles for Palo Alto, Check Point, Arista, Extreme, Ubiquiti, Moxa, Siemens | Change control needs "what changed", not "something changed" | M | `configrx.js:452`, `GET /api/configrx/backups/{a}/diff/{b}`, `configrx_vendors.py` |
| 14 | **Server-side paging and virtual rows for Nodes and Alerts**, honest totals | Stops 2 MB per refresh per tab and "300 shown" lies | M | `api.py`, `nodes.js`, `alerts.js` |
| 15 | **Tags and per-user saved views** | "All access switches at the northern mill" as a click, not a naming convention | L | `nodesdb`, `nodes.js` |
| 16 | **Remote pollers** (an agent that runs `_poll_device` locally and ships results) | The only change that raises the ceiling by an order of magnitude and survives a datacentre loss | L | new component |
| 17 | **Per-device SNMP port, IPv6 polling and IPv6 listeners** | NAT'd sites, port-forwarded PLC gateways, IPv6 management planes | S each | `nodeoids.py:12` call sites, `nodepoll.py:73`, three listeners |
| 18 | **Interface names for NetFlow from Nodes, and utilisation %** | "Which uplink is at 90%" without the router config open | M | `service._apply_interface_names` |
| 19 | **Persistent audit log**, API tokens, directory auth (LDAP/AD/TACACS+), per-site RBAC | Procurement gates on a regulated network | M/L | `eventlog.py`, `auth.py`, `permissions.py` |
| 20 | **Discovery pacing and a never-scan list** | Prevents the 64-way ICMP/SNMP sweep from upsetting fragile PLC stacks | M | `ipam_scan.sweep`, `nodediscover._run` |

### Tier 2 — quality of life for a large fleet (mostly S)

- Render `view.metrics` (CPU, memory, custom MIB values) with the existing chart renderer, and a metric-key picker plus "last matched" column for rules.
- Un-acknowledge; badge shows open + acked with severity colour; top-N noisy devices; runbook URL per rule; appendable alert notes; alert CSV.
- "SNMP failing while ping succeeds" rule; poll-pool saturation counter and alert; effective-retention figure beside each retention setting; `kernel_dropped` in every collector strip.
- `interface` bandwidth dialog with the standard range picker instead of a fixed hour.
- Accessibility in one place: `scope`/`aria-sort`/`tabindex` in the shared grid helper, dialog semantics and focus return lifted from the help panel into `modal()`, `role="status"` on the connection and bulk notices, hatch patterns for ok/fail/blocked, `.hint` contrast.
- Operator-language offline message with stale-content dimming; spinners and a request timeout; favicon; open-alert count in the title; optional desktop notification; timezone label.
- Say "FortiGate" on the Wireless tab; gate the DHCP form on PowerShell presence; accept `"2c"` in the API; expose `App` on `window`.
- Documentation: a table of contents per file, a quick-start, an API reference generated from the route table, a backup/restore guide for ten WAL databases, a Linux upgrade path, a runbook for "poller stopped / collector stopped / cap reached", and removal of the six documented features that do not exist.

---

## 7. Bugs and documentation defects, with proposed patches

Documented only, per the reviewer's instruction. Each is CONFIRMED unless the
row it belongs to in §4 says otherwise, and each carries the effort the
re-review settled on rather than the first draft's estimate — five of these were
understated and say so in place (#2, #4, #6, #12, #22a).

1. `netpath/nodesdb.py:2171-2179` — replace the global `LIMIT (total - max_samples)` delete with a per-metric window:
   `DELETE FROM samples WHERE rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER (PARTITION BY metric_id ORDER BY ts DESC) rn FROM samples) WHERE rn > ?)`, executed in chunks outside the lock.
2. `netpath/web/service.py:715` — after `nodes_db.prune(...)`, call `nodes_db.compact_rollup(...)` and prune `samples_hourly` by age. **Larger than it looks:** `compact_rollup()` as written *deletes every raw sample older than one hour* once it has aggregated, so it cannot simply be called — it has to stop deleting first, or calling it destroys more history than the cap does. It also needs a new `rollup_retention_days` setting (there is no age to prune `samples_hourly` by today; `sample_retention_days` covers raw rows only), an index on `samples_hourly(hour)` for the prune to use, and a watermark so a second pass over the same hour writes nothing. Effort **M**, not S.
3. `netpath/nodesdb.py:1398` — add `record_metric_samples(device_id, rows)` (one `metrics` upsert pass, one `executemany`, one commit); call it once from `_poll_device` with the poll's accumulated rows.
4. `netpath/nodepoll.py:690-721` — wrap the loop body in `try/except Exception as exc: self.error = str(exc); self.log.add(ERROR, ...)`; continue, and clear `self.error` on the next clean pass. The first draft pointed at `monitor.py:376-402` as the pattern to copy; that is only half true — `monitor.py` has the `try/except` but no error field, so the status half is new code and `status_text()` has to learn to render it.
5. `netpath/nodepoll.py:1642-1645` — on `is_v1`, issue the IF-MIB GET and the ifXTable GET separately, tolerating `noSuchName` on the second, as `_identity_extras` (`:1211-1229`) already does.
6. `netpath/nodepoll.py:1145, 2453, 2492` — use `engine_time + int(now - learned_at)`. There are **three** v3 send sites, not one, and the second half of the fix is missing from two of them: only `_snmp_get` has any Report-PDU handling at all; `_snmp_get_next` and `_walk_request` have none, so a Report arriving there is decoded as an ordinary response with no varbinds and the poll silently returns nothing. Doing this properly means one `_v3_exchange()` helper used by all three, which invalidates the cached engine parameters, rediscovers, retries once, and raises a typed failure on a second Report with the `usmStats*` OID decoded (#8). Effort **M**, not S.
7. `netpath/nodepoll.py:82-97` — compare `response.request_id` to the sent id and `_addr[0]` to `self.ip`; keep receiving until the deadline on mismatch. Thread the v3 `msgID` the same way. Verify inbound v3 digests with `trapdecode.find_auth_span` + HMAC as the trap receiver does.
8. `netpath/nodepoll.py:917` — classify `status = "unsupported"` from the exception type (`SnmpUnsupported`), and decode the Report's `usmStats*` OID into a real message in `_snmp_get`.
9. `netpath/nfdecode.py:150` — add `DecodeError` to the except tuple; `netpath/collector.py:185` — wrap the receive body in `try/except Exception`, count and log. Same for `snmptrapd._receive`/`_enqueue` and `syslogd._receive_udp`/`_enqueue`.
10. `netpath/nfdecode.py:316-337` — treat `fixed is not None and fixed <= 0` as a broken template: count, drop the cache entry, return `[]`; refuse `count == 0` templates at `:250-265`.
11. `netpath/nfdecode.py:409-411` — choose the address field by content: skip `None`, `b""` and all-zero bytes before falling back.
12. `netpath/syslogdb.py:482-484, 504-506` — replace `INSERT INTO logs_fts(logs_fts) VALUES('rebuild')` with per-row `'delete'` entries for the rows removed. `RETURNING id` alone is not enough: an FTS5 external-content `'delete'` command must be given **the original column values as well as the rowid**, so the DELETE has to be `RETURNING id, message, app, host, source` and each returned row replayed into `logs_fts`. `RETURNING` needs SQLite ≥ 3.35, so the statement needs a `sqlite3.sqlite_version_info` guard with the existing rebuild kept as the fallback — throttled to at most once an hour, since that is the 18.6 s stall. Effort **S/M**, not S.
13. `netpath/alertengine.py:499, 520` — loop the drain until `max_id` is reached or a per-tick budget expires; expose `max_id - cursor` as `backlog` in `counters`.
14. `netpath/snmptrapd.py:194-231` — after the community check, drop rows whose `auth_state == "failed"` when a new `reject_failed_auth` setting (default on) is set; count them.
15. `netpath/alertengine.py:504-509` — `entity_id = f"{row['source']}:{row['trap_oid']}"`, `severity=row["severity"]`, `device_name=<resolved>`; `:1116` — extend the severity gate to `kind in ("syslog", "trap")`; `trap_link_down_unmanaged` gets `nodes_db.device_by_ip(source) is None`.
16. `netpath/alertengine.py:535-539` — include a normalised message signature (Cisco `%FAC-SEV-MNEM`, else a digits-stripped hash) in the syslog dedup key; set `device_name=label`.
17. `netpath/alertengine.py:1146-1152` — compare against a new `last_notified_ts` (or `MAX(ts)` from `notifications`) rather than `last_ts`; drive renotify from a per-tick sweep of open alerts.
18. `netpath/alertengine.py:1218-1228` — move `alertmail.send` to a bounded queue drained by its own thread; append to `_sent_this_hour` on attempt, not success; open a breaker after N consecutive failures and raise an in-app alert about the mail path.
19. `netpath/alertengine.py:156-177, 418-419` — wrap each occurrence in its own `try`; advance a source's cursor only after its occurrences are applied.
20. `netpath/alertengine.py:672-676` — treat a metric whose `last_ts` is older than 3 × the device's poll interval as absent: clear the streak and resolve.
21. `netpath/alertengine.py:1042-1051` — while `nodes_db.device(id)["status"] == "down"`, keep `ROLLS_UP` children suppressed even if the parent alert was operator-resolved.
22. `netpath/alertmail.py:132-138` — `total = int(round(total))` before the `<= 0` test. `:104-108` — append `%z`.
22a. `netpath/alertsdb.py:217-221`, `:223` (and the wireless rules at `:243`, `:248`) — bind `device_auth_fail`, `device_unsupported`, `poll_overrun`, `mib_missing`, `interface_down` and `interface_flapping` to a new generic template (`subject: "SappiWhere: {{rule_name}} — {{entity_label}}"`) instead of `device_down`. Note `:222` is `interface_up`, which is bound to `device_up` and is correct — the first draft's `217-222` swept it in. **Two things make this more than a one-line edit.** First, `_seed_rules()` is `INSERT OR IGNORE`, so editing the seed list changes nothing on an existing database: the re-binding needs a named, run-once migration that re-points only rules still bound to the shipped `device_down` template, so an operator's own choice is never overwritten. Second, `notify = 0` for `mib_missing` is not a value that exists — `rules` has no `notify` column, so it must be added through `_migrate()` and honoured in `_notify()`. Effort **S/M**, not S.
22b. `netpath/auth.py:180-193` — accept a `heartbeat` on any authenticated API request that carries an `X-Sappiwhere-Client: script` header, or add long-lived API tokens (`api_tokens` table, `Authorization: Bearer`), so automation is not signed out by the browser idle rule.
23. `netpath/web/server.py:_route` — when `app_db.user(username)["must_change"]`, refuse every route except `/api/session`, `/api/logout`, `/api/state`, `/api/password`.
24. `netpath/web/server.py:48-56` — return `("settings", W)` for any scope `post_settings` does not dispatch explicitly; `api.py:841-862` — filter the returned settings through the same rule `get_state` uses.
25. `netpath/selfupdate.py` — pin to a signed tag or a published SHA-256; add `updates_enabled` (default false) checked in `apply()` and `post_update`.
26. `netpath/web/api.py:3265-3298` — refuse to use the stored SMTP password when the body overrides host/port/security; reject `smtp_security` values that disable transport security when a password will be sent.
27. `netpath/__main__.py:20-27` — `os.makedirs(folder, mode=0o700)`; `os.chmod(path, 0o600)` after every `sqlite3.connect`. `:177-180` — delete the "no authentication yet" lines; `web/server.py:8-10` likewise.
28. `netpath/configrx.py:78, 105-120` — guard `_paramiko_ok` with the module lock or derive it from `paramiko_identity()`.
29. `netpath/configrx.py:288-299` — **RESOLVED UPSTREAM in 4.36.x.** Host keys are persisted in `configrx.db` by `netpath/hostkeys.py`, pinned on first sight, refused on change, and forgettable through an action gated on `configrx: write`; ConfigRX and the SSH terminal share the store. What is **not** done and remains in scope: `allow_legacy_ssh` still defaults to true, and `_paramiko_ok` is still an unlocked cache (#28).
30. `netpath/trapoids.py:51, 174` — `1.3.6.1.2.1.15.3.1.7` is `bgpPeerRemoteAddr`; `bgpPeerState` is `1.3.6.1.2.1.15.3.1.2`; move the enum.
31. `netpath/syslogd.py:236-244` — require the byte after the count to be `<` before treating a prefix as an RFC 6587 length. `:210-221` — cap client threads and prune the list.
32. `netpath/syslogparse.py:168-188` — loop over consecutive `[...]` elements; `:131-142` — accept 5 parts with an empty MSG; `:91-109` — clamp 3164 timestamps to now ± 1 h.
33. `netpath/collector.py:231-233` — carry each exporter's own version into `per_exporter`; `flowdb.touch_exporter` takes a list and commits once.
34. `netpath/nodesdb.py:931, 1281-1293` — `mac >= :p AND mac < :p || char(0xFFFD)` instead of `LIKE`.
35. `netpath/web/static/app.js:947` — hoist one `Intl.Collator(undefined, {numeric: true, sensitivity: 'base'})`. `:385-415` — add `role="dialog"`, `aria-modal`, `aria-labelledby`, save the trigger and restore focus on close (copy `:455-476`). `:386-392` — escape `title`. `:3` — `window.App = App`.
36. `netpath/web/static/nodes.js:1261, 922` — compare against a per-dialog token stored on the dialog element, not `oidDialogSeq && !modal.hidden`.
37. `netpath/web/static/settings.js:442` — call `loadUsers()` only when `App.state.grants.settings === 'write'`.
38. `netpath/web/api.py` device create/update — validate `snmp_version` against `{0, 1, 3, "1", "2c", "3"}` and coerce.
39. `netpath/web/static/app.css:264` — `.hint { color: var(--muted) }`; `nav { overflow-x: auto }`.
40. `tests/test_nodepoll_e2e.py:219` — set `ping_enabled=0` on the profile (or patch the ping function as `test_nodediscover_e2e.py:104` does).
41. Docs: delete the `deploy\` script references at `README.md:99-103, 453-460` and document Linux/systemd and Windows NSSM instead; **keep** `README.md:280-293` (the NetFlow shortcuts) and implement them, since the README has promised them for four releases; delete `README.md:592` and `FEATURES.md:1850` ("Export window to CSV"); rewrite `FEATURES.md:1141-1143`; strike or commit the Playwright tests claimed in `PERFORMANCE_REVIEW.md:69-79, 93-95`; correct `NETWORK-AND-STORAGE-REQUIREMENTS.md:269-270`; correct `FEATURES.md:94-96`; note in `NETWORK-AND-STORAGE-REQUIREMENTS.md` that on non-Windows hosts no credential feature is available and that the collectors are IPv4-only; add a ConfigRX backup row to `CREDENTIAL-SECURITY.md`'s inventory; and correct `CREDENTIAL-SECURITY.md:573`, which says the application performs "no update check" while the Update button calls `selfupdate.latest_commit()` against `api.github.com` on every press (D25). Add what D16–D22 say is missing: a table of contents per long document, a `QUICKSTART.md`, a `BACKUP-RESTORE.md` for the ten WAL databases, and a `RUNBOOK.md`.

---

## 8. Strengths worth keeping

These are genuinely good and should survive any refactor.

- **The SNMP wire implementation is provably correct without hardware.** `snmppoll.__main__` round-trips every PDU type, checks the GETBULK repetition slot, verifies all six auth digest lengths, and signs a v3 message with the encoder while verifying it with the trap receiver's independent decoder. `trapdecode.py` survived 20,000 bit flips, every truncation, BER length bombs and nesting bombs without raising. The `Reader`-over-offsets design that lets the v3 HMAC hash the original buffer in place is the right call.
- **Walk loop guards, `tooBig` halve-and-retry, and the timeout-vs-end-of-table distinction** (`raise_on_timeout`) are all correct and reproduced; per-row sample timestamps threaded into `counter_rate` are a subtle correctness fix most tools never make.
- **Vendor identification** by enterprise-arc hopping with confidence marks (`?`, `~`, `*`) and stored evidence, zero steady-state traffic, and a walk that never overrules a real IANA arc.
- **The MAC-table cascade** (Q-BRIDGE → BRIDGE → Cisco `community@vlan`), "answered" distinguished from "empty", aged entries kept as `present=0`, and the MAC-to-port search that refuses to auto-open a port when several switches see the MAC. The best interaction in the product.
- **Credential handling**: scrypt at current parameters with transparent rehash, NIST-style password policy, secrets decrypted just before use and dropped in `finally`, never returned by any API, never logged; an exemplary env-var PowerShell credential path; ConfigRX's "read-only by construction" claim verified true; SNMP SET never sent; discovery that refuses to guess `public`.
- **ConfigRX's capture chain** (verified against seven fake devices): waits through Cisco's "Building configuration" pause, answers pagers, refuses truncated and unprivileged captures with a named reason, learns FortiOS and MikroTik prompts, and falls back to silence for a menu-style banner.
- **Alert semantics**: dedup keys on stable database ids, a partial unique index enforcing one open alert per key, sample-time (not tick) streaks across all three evaluators, the 4.34 sticky operator-resolve, persisted new-device grace, correctly seeded first-run cursors, recovery notices with real downtime, and a template migration that never overwrites an operator's edit.
- **Collectors**: the two-thread receive/write split with a bounded queue; RFC 3584 v1-to-v2 trap mapping with a positional fallback; flow-time clamping; hourly rollup tables for syslog and traps; `SO_EXCLUSIVEADDRUSE` on Windows; FTS5 trigram syslog search with a graceful fallback.
- **NetPath** path monitoring, silent-hop collapsing, refused-vs-no-reply distinction with hatching, point-in-time snapshots, window-relative hop aging, and the honest exclusion of `error`/`overrun` from reachability.
- **UI details**: the presence-based idle timeout with a countdown banner, bulk alert handling with server-reported counts and a warning that "Acknowledge all" ignores the filter, mute state surfaced in the Nodes table, empty states that name the next action, one confirm shape for destructive actions, draggable persistent splitters, and the 4.35 help panel as a mechanism.
- **Documentation candour**: `FEATURES.md`'s "Deliberate limits", `NETWORK-AND-STORAGE-REQUIREMENTS.md` (verified accurate on ports), and `CREDENTIAL-SECURITY.md`'s argued trade-offs. The load-bearing comments throughout the code explain *why*, which is what made a review of this depth possible in a day.

---

## 9. What was implemented

One row per finding actually closed, naming the step from the implementation
plan, the commit that closed it and the test that proves it. A finding with no
row here, and not in the Deferred list beneath the table, is still open; a
finding closed by 4.36.x rather than by this work says so in the Commit column.
Where a finding had two halves and only one was in scope, the Finding column
says which half.

The documentation-truth rows at the end of §4.6 (D1–D28) are not repeated here:
all twenty-eight are closed by the documentation workstream, in `35e5a2d`,
`1c52ac5`, `c90b5fa`, `e9da3d6`, `fbead48` and `07317d3`, and the
`CHANGELOG.md` 4.37.0 Documentation block lists them one by one.

Suites named `§X` refer to the section marker of that name inside the file;
`tests/test_poll_write_path.py` is organised as named functions instead.

| Finding | Step | Commit | Test |
|---|---|---|---|
| P-B1 | B2 | `d390b7e` | `tests/test_series_buckets.py` — per-metric sample cap |
| P-B2 | B3 | `389b36c` | `tests/test_series_buckets.py` — hourly rollups |
| P-B3 | B6 | `3ecadd6` | `tests/test_poll_write_path.py` `interface_reads()` |
| P-S1 | B6 | `3ecadd6` | `tests/test_poll_write_path.py` `interface_reads()` |
| P-S2 | B5 | `9551ae9` | `tests/test_scheduler.py` |
| P-S3 | B8 | `2483eda` | `tests/test_poll_write_path.py` `v3_engine_time()` |
| P-S4 (the misreporting half; see Deferred for authPriv) | B8 | `2483eda` | `tests/test_poll_write_path.py` `v3_engine_time()` |
| P-S5 | B5 | `9551ae9` | `tests/test_scheduler.py` |
| P-S6 | B1 | `456c16f` | `tests/test_poll_write_path.py` — COMMIT trace |
| P-S7 | B12 | `b9ed558` | `tests/test_poll_write_path.py` `pool_and_walks()` |
| P-S8 | B0, B7 | `2dae599`, `20b61d7` | `tests/test_poll_write_path.py` `reboot_suppression()` |
| P-S9 (health OIDs; see Deferred for PoE/STP/LLDP/ARP/BGP) | B10 | `b94aede` | `tests/test_poll_write_path.py` `vendor_health()` |
| P-N2 | B9 | `4b371d8` | `tests/test_poll_write_path.py` `request_matching()` |
| P-N3 (the IPv6 half; see Deferred for the per-device port) | B11 | `07c7c7d` | `tests/test_poll_write_path.py` `ipv6_polling()` |
| P-N6 | B12 | `b9ed558` | `tests/test_poll_write_path.py` `pool_and_walks()` |
| P-N7 | B6 | `3ecadd6` | `tests/test_poll_write_path.py` `interface_reads()` |
| P-N9 | B12 | `b9ed558` | `tests/test_poll_write_path.py` `pool_and_walks()` |
| P-N11 | B13 | `c830f73` | `tests/test_nodepoll_e2e.py` |
| C-B1 | C1 | `aa2b3e9` | `tests/test_collectors_hardening.py` §C1 |
| C-B2 | C2 | `b032dc3` | `tests/test_collectors_hardening.py` §C2 |
| C-B3 | C3 | `75f63c8` | `tests/test_collectors_hardening.py` §C3 |
| C-B4 | C4 | `da2b5a6` | `tests/test_collectors_hardening.py` §C4 |
| C-B5 | C5, A1 | `537f3cb`, `be5ca8a` | `tests/test_collectors_hardening.py` §C5; `tests/test_alert_engine_fixes.py` §A1 |
| C-S1 | C6 | `fdf7f3c` | `tests/test_collectors_hardening.py` §C6 |
| C-S2 (the unbounded cache; the 1 MiB-per-trap claim was withdrawn — Appendix C) | C2, C6 | `b032dc3`, `fdf7f3c` | `tests/test_collectors_hardening.py` §C2, §C6 |
| C-S3 | C2 | `b032dc3` | `tests/test_collectors_hardening.py` §C2 |
| C-S4 | C9 | `e041124` | `tests/test_collectors_hardening.py` §C9 |
| C-S5 | C9, B11 | `e041124`, `07c7c7d` | `tests/test_collectors_hardening.py` §C9; `tests/test_poll_write_path.py` `ipv6_polling()` |
| C-S6 | C7 | `91427ca` | `tests/test_collectors_hardening.py` §C7 |
| C-S7 | C8 | `da75aca`, `3b44726` | `tests/test_collectors_hardening.py` §C8 |
| C-S8 | A5 | `7494b99` | `tests/test_alert_engine_fixes.py` §A5 |
| C-S9 | C7 | `91427ca` | `tests/test_collectors_hardening.py` §C7 |
| C-N1 | C9 | `e041124` | `tests/test_collectors_hardening.py` §C9 |
| C-N2 | C2 | `b032dc3` | `tests/test_collectors_hardening.py` §C2 |
| C-N3 | C10 | `aacc9fe` | `tests/test_collectors_hardening.py` §C10 |
| C-N4 | C7 | `91427ca` | `tests/test_collectors_hardening.py` §C7 |
| C-N5 | C7 | `91427ca` | `tests/test_collectors_hardening.py` §C7 |
| C-N6 | C10 | `aacc9fe` | `tests/test_collectors_hardening.py` §C10 |
| C-N7 (the documented figure, corrected) | F2 | `1c52ac5` | none — `NETWORK-AND-STORAGE-REQUIREMENTS.md` |
| C-N10 | C7 | `91427ca` | `tests/test_collectors_hardening.py` §C7 |
| C-N11 | C11 | `64079d5` | `tests/test_collectors_hardening.py` §C11 |
| C-N12 | C7 | `91427ca` | `tests/test_collectors_hardening.py` §C7 |
| C-N13 | C9 | `e041124` | `tests/test_collectors_hardening.py` §C9 |
| C-N14 | C9 | `e041124` | `tests/test_collectors_hardening.py` §C9 |
| A-F1 | B6, B10 | `3ecadd6`, `b94aede` | `tests/test_poll_write_path.py` `interface_reads()`, `vendor_health()` |
| A-F2 | A2 | `cc3b5a5` | `tests/test_alert_engine_fixes.py` §A2 |
| A-F3 | A11 | `a77b1b7` | `tests/test_alert_engine_fixes.py` §A11 |
| A-F5 | A4 | `0744b62` | `tests/test_alert_engine_fixes.py` §A4 |
| A-F6 | A4, A5 | `0744b62`, `7494b99` | `tests/test_alert_engine_fixes.py` §A4, §A5 |
| A-F7 | A4 | `0744b62` | `tests/test_alert_engine_fixes.py` §A4 — syslog identity |
| A-F8 | A3 | `49ec57d` | `tests/test_alert_engine_fixes.py` §A3 |
| A-F9 | A6 | `8366da7` | `tests/test_alert_engine_fixes.py` §A6 |
| A-F10 | A7 | `af9bcab` | `tests/test_alert_engine_fixes.py` §A7 |
| A-F11 | A11 | `a77b1b7` | `tests/test_alert_engine_fixes.py` §A11 — F11 |
| A-F12 | A1 | `be5ca8a` | `tests/test_alert_engine_fixes.py` §A1 |
| A-F14 | A7, B0 | `af9bcab`, `2dae599` | `tests/test_alert_engine_fixes.py` §A7 |
| A-F20 | E6 | `3ff71cb`, `58366e3` | `tests/ui/walk.mjs` — misc |
| A-F21 | A9 | `c6b544e` | `tests/test_alert_engine_fixes.py` §A9 |
| A-F22 | A10 | `ee43b4a` | `tests/test_alert_engine_fixes.py` §A10 |
| A-F23 | A9 | `c6b544e` | `tests/test_alert_engine_fixes.py` §A9 |
| A-F24 | A11, B0 | `a77b1b7`, `2dae599` | `tests/test_alert_engine_fixes.py` §A11 |
| A-F26 | A8 | `2557217` | `tests/test_alert_engine_fixes.py` §A8 |
| A-F27 (the email storm; the alerts themselves still open) | A8 | `2557217` | `tests/test_alert_engine_fixes.py` §A8 |
| S-B1 | D3 | `48ba132` | `tests/test_security_fixes.py` §D3 |
| S-B2 | D1 | `ae02159` | `tests/test_security_fixes.py` §D1 |
| S-B3 | D2 | `fdddbf1` | `tests/test_security_fixes.py` §D2 |
| S-S1 | D4 | `5a6eb5e` | `tests/test_security_fixes.py` §D4 |
| S-S2 | — (4.36.0/4.36.1), plus D5 for `allow_legacy_ssh` | 4.36.x; `4155c36` | `tests/test_ssh_hostkeys.py` |
| S-S3 | D11 | `ad8bc94` | `tests/test_security_fixes.py` §D11 |
| S-S4 | D5, B4, A12 | `4155c36`, `ca8bf68`, `6cb6868` | `tests/test_security_fixes.py` §D5 |
| S-S6 (the banner; see Deferred for the default bind) | D15, H9 | `8f15dc3`, `953b2ad` | `tests/test_security_fixes.py` §D15; `tests/test_parsers_hardening.py` §H9 |
| S-S7 | D8 | `15f1487` | `tests/test_security_fixes.py` §D8 |
| S-N1 | D7 | `0276397` | `tests/test_security_fixes.py` §D7 |
| S-N2 | D7 | `0276397` | `tests/test_security_fixes.py` §D7 |
| S-N3 | D6, D13 | `6257679`, `ad7c261` | `tests/test_security_fixes.py` §D6, §D13 |
| S-N4 | D6 | `6257679` | `tests/test_security_fixes.py` §D6 |
| S-N5 | E2, E15 | `9c71c60`, `54635c3` | `tests/ui/walk.mjs` — dialog |
| S-N6 | D6 | `6257679` | `tests/test_security_fixes.py` §D6 |
| S-N8 | D12 | `e4bb4c3` | `tests/test_security_fixes.py` §D12 |
| S-N9 | D9 | `7e739fa` | `tests/test_security_fixes.py` §D9 |
| S-N11 | D12 | `e4bb4c3`, `62de1f4` | `tests/test_security_fixes.py` §D12 |
| S-N12 | D9 | `7e739fa` | `tests/test_security_fixes.py` §D9 |
| S-N13 | D6 | `6257679` | `tests/test_security_fixes.py` §D6 |
| S-N14 | D6 | `6257679` | `tests/test_security_fixes.py` §D6 |
| S-N16 | D10 | `1d0469a` | `tests/test_security_fixes.py` §D10 |
| X-F1 ★ | B2 | `d390b7e` | `tests/test_series_buckets.py` — per-metric sample cap |
| X-F2 ★ | B3 | `389b36c` | `tests/test_series_buckets.py` — hourly rollups |
| X-F3 ★ | B1 | `456c16f` | `tests/test_poll_write_path.py` — COMMIT trace; `tests/bench_record_samples.py` |
| X-F4 ★ | B5 | `9551ae9` | `tests/test_scheduler.py` |
| X-F5 | B4, C4, A12 | `ca8bf68`, `da2b5a6` + `b568b02`, `6cb6868` | `tests/test_series_buckets.py`; `tests/test_collectors_hardening.py` §C4, §C4 (G-24); `tests/test_alert_engine_fixes.py` — storage trim |
| X-F8 | A7 | `af9bcab` | `tests/test_alert_engine_fixes.py` §A7 |
| X-F11 | B3 | `389b36c` | `tests/test_series_buckets.py` — hourly rollups |
| X-F13 | B1 | `456c16f` | `tests/test_poll_write_path.py` — `replace_interfaces` id map |
| X-F19 | E4/E14 | `bb7a0af` | `tests/ui/walk.mjs` — offline |
| U-F1 | E11 | `7e78111` | `tests/ui/walk.mjs` — routing |
| U-F10 | E6 | `3ff71cb`, `58366e3` | `tests/ui/walk.mjs` — misc |
| U-F12 | E10 | `fa1df44` | `tests/ui/walk.mjs` — dashboard |
| U-F13 | E9 | `153d808` | `tests/ui/walk.mjs` — misc |
| U-F15 | E1, E2 | `6e60afa`, `9c71c60` | `tests/ui/walk.mjs` — tabs and ARIA |
| U-F16 | E1 | `6e60afa` | `tests/ui/walk.mjs` — tabs and ARIA |
| U-F17 | E1 | `6e60afa` | `tests/ui/walk.mjs` — tabs and ARIA |
| U-F18 | E2 | `9c71c60` | `tests/ui/walk.mjs` — dialog |
| U-F19 | E2 | `9c71c60` | `tests/ui/walk.mjs` — tabs and ARIA |
| U-F20 | E3 | `1c7c0e7` | `tests/ui/walk.mjs` — misc |
| U-F21 | E3 | `1c7c0e7` | `tests/ui/walk.mjs` — misc |
| U-F23 | E4/E14 | `bb7a0af` | `tests/ui/walk.mjs` — offline |
| U-F24 (the request timeout; see Deferred for spinners and `aria-busy`) | E4/E14 | `bb7a0af` | `tests/ui/walk.mjs` — offline |
| U-F27 (the tab-bar half; see Deferred for the narrow layout) | E8 | `4ab5da8` | none — one CSS rule |
| U-F28 | E5 | `ad6576b`, `58366e3` | `tests/ui/walk.mjs` — misc |
| U-F32 | E7 | `c03cd1c` | `tests/ui/walk.mjs` — misc |
| U-F36 | D5 | `4155c36` | none — the lock is unobservable from outside |
| U-C1 | E9 | `153d808` | `tests/ui/walk.mjs` — misc |
| U-C2 | E9 | `153d808` | `tests/ui/walk.mjs` — misc |
| U-C3 | E9 | `153d808` | `tests/ui/walk.mjs` — read-only |
| G-1 | I1 | `677a59a` | `tests/test_wsock.py`; `tests/test_ssh_terminal.py` |
| G-2 | I2 | `7b55941` | `tests/test_ssh_terminal.py` |
| G-3 | I4 | `31139cc` | `tests/test_ssh_terminal.py` |
| G-4 | I4 | `31139cc` | `tests/test_ssh_terminal.py` |
| G-5 | I3 | `0dfa814` | `tests/test_ssh_terminal.py` |
| G-6 | I5 | `2ca65bf` | `tests/test_ssh_terminal.py`; `tests/test_ssh_hostkeys.py` |
| G-7 | D13 | `ad7c261` | `tests/test_security_fixes.py` §D13 |
| G-8 | I6 | `7a6b016` | `tests/test_wsock.py` |
| G-9 | I5 | `2ca65bf` | `tests/test_ssh_terminal.py` |
| G-10 | H1 | `67de5ff`, `57ed61e` | `tests/test_parsers_hardening.py` §H1 |
| G-11 | H1 | `67de5ff` | `tests/test_parsers_hardening.py` §H1 |
| G-12 | H2 | `2335f18` | `tests/test_parsers_hardening.py` §H2 |
| G-13 | H3 | `500e4b9` | `tests/test_parsers_hardening.py` §H3 |
| G-14 | H3 | `500e4b9` | `tests/test_parsers_hardening.py` §H3 |
| G-15 | H5, F6 | `e96c9d3`, `07317d3` | `tests/test_parsers_hardening.py` §H5 |
| G-16 | H5 | `e96c9d3`, `57ed61e` | `tests/test_parsers_hardening.py` §H5 |
| G-17 | H5 | `e96c9d3` | `tests/test_parsers_hardening.py` §H5 |
| G-18 | H6 | `af183da` | `tests/test_parsers_hardening.py` §H6 |
| G-19 | H6 | `af183da` | `tests/test_parsers_hardening.py` §H6 |
| G-20 | H6 | `af183da` | `tests/test_parsers_hardening.py` §H6 |
| G-21 | H7 | `84d41bc`, `62de1f4` | `tests/test_parsers_hardening.py` §H7 |
| G-22 | D14, H9 | `22e1350`, `953b2ad` | `tests/test_security_fixes.py` §D14; `tests/test_parsers_hardening.py` §H9 |
| G-23 | D15, H9, F6 | `8f15dc3`, `953b2ad`, `07317d3` | `tests/test_security_fixes.py` §D15; `tests/test_parsers_hardening.py` §H9 |
| G-24 | C4 | `b568b02` | `tests/test_collectors_hardening.py` §C4 (G-24) |
| G-25 | H10 | `6dc4d86` | `tests/test_parsers_hardening.py` §H10 |
| G-27 | H8 | `38e7611` | `tests/test_parsers_hardening.py` §H8 |
| G-28 | E4/E14 | `bb7a0af` | `tests/ui/walk.mjs` — offline |
| G-29 | E15 | `54635c3` | `tests/ui/walk.mjs` — misc |
| G-30 | E16 | `a876d3d` | `tests/ui/walk.mjs` — misc |
| G-31 | H11 | `0175cf5` | `tests/test_parsers_hardening.py` §H11 |
| G-32 | F6 | `07317d3` | none — `netpath/mibs/NOTICE.md` |
| G-33 | H4 | `eb2734b` | `tests/test_parsers_hardening.py` §H4 |

### Deferred

Everything below was read, and left. Each line says why. The plan's "out of
scope" list is the source for most of them: this release was three weeks of
correctness and safety work, not a feature release, and a finding that asks for
a new subsystem was ruled out at the start rather than attempted badly.

- **A portable secret store** — S-S5, A-F15, and the first structural reason in
  the Verdict. Deliberately not built. Writing a weak one is worse than
  documenting the limitation, which `CREDENTIAL-SECURITY.md` §10 now does at
  length.
- **Alert routing and workflow** — A-F4 (digest and correlation window), A-F16
  (webhook, Slack, Teams, PagerDuty, SMS, trap forwarding), A-F17 (per-rule
  recipients, escalation, on-call), A-F18 and U-F7 (maintenance windows, muting
  anything that is not a device), A-F19 (un-acknowledge), A-F25 (top-N,
  MTTR/SLA reporting, ticket and runbook links). Each is a feature, and the
  dependency map they wanted (A-F24, which did land) had to come first.
- **Pattern-matched event rules** — A-F13 (sub-poll-interval flap detection),
  C-N9 (trap varbind conditions, syslog regex, "N in M minutes"). Out of scope:
  a rule language is its own design, and A4's per-signature syslog keying takes
  the immediate pain out of C-N9's second half.
- **Paging, virtualisation and layout** — X-F7, X-F18, U-F3, X-F20
  (`localeCompare` per comparison), X-F21 (`series()` returning every raw
  point), U-F27's other half (zero media queries; at 390 px six of twelve tabs
  are unreachable), and U-F24's other half (still no spinners and no
  `aria-busy`; only the request timeout was in scope). Approved as "defer; ship
  only the tab-bar scroll fix"; the Dashboard (E10) is the answer to "what do I
  look at first" that paging was being asked for.
- **Import and export** — U-F5 (CSV/clipboard/print), U-F6 (bulk import),
  P-N4 (bulk device import and the 1,024-address discovery cap). The
  documentation claiming an export that never existed is corrected (D7); the
  export itself is not built.
- **Remaining poller coverage** — P-S9's other half (PoE, STP, LLDP/CDP, ARP,
  BGP, ENTITY-SENSOR on a schedule), P-S4's authPriv half (SNMPv3 privacy is on
  the out-of-scope list), P-N3's per-device SNMP port, P-N1 (unchunked custom-MIB
  GET), P-N8 (non-ASCII octet strings rendered as hex), P-N10 (`fortipoll`'s
  missing non-increasing-OID guard), P-N5/X-F15 (ping is still three serial
  subprocess spawns per device per poll). B10 took the health OIDs that make the
  shipped rules fire; the rest is a second pass.
- **Metric display** — P-S10. `cpu_pct` now reaches an operator through the
  Dashboard's "Highest CPU" list (E10), but the device pane still has no chart
  for a custom-MIB metric key. Device-pane metric charts are out of scope.
- **Search and comparison** — U-F2 (search covers ip/name/sys_name only),
  X-F10 (MAC prefix search uses `LIKE` and defeats its index), U-F4 (sites,
  tags, saved views), U-F8 (side-by-side comparison), U-F9 (the interface
  bandwidth dialog's fixed window), U-F11 (bulk mute), U-F33 (ConfigRX diff),
  U-F22 (the help "?" covers 2 of ~150 settings), U-F29/U-F30 (browser-local
  timestamps with no zone in the UI — alert *email* is fixed by A9), U-F31
  (Wireless is FortiGate-only and does not say so; the tab relabel was the one
  UI item explicitly not approved), U-F34 (`snmp_version: "2c"` is still
  accepted and still raises on every poll of that device), U-F25/U-F26/U-F35
  (nits and positives, no action intended).
- **Architecture** — X-F28 (single process, no remote pollers or sharding),
  X-F12 (one lock and one connection serialising every writer), X-F17
  (`/api/state`'s fan-out across ten databases), X-F16 (`_extra_resolve_targets`
  full-scanning every fifteen seconds), X-F9 (`resolve_name` inside the
  per-rule loop — A7 removed the metric fan-out around it, not the call),
  X-F14 (`replace_interfaces` still UPDATEs rows whose every field is
  identical), X-F22 (pure-Python BER), X-F23 (unbounded `IN (…)` lists, which
  do not fire on the SQLite this ships against), X-F25 (`settings()` re-reads
  the whole table per call — B5 removed the scheduler's copy of the problem,
  not the poll and tick copies), X-F26 (`busy_timeout`, `cache_size` and
  `mmap_size` still unset), X-F24 (`metrics()`'s discarded `ORDER BY label`).
  X-F27 is recorded in §4.5 as correct as written and needs nothing.
- **Directory authentication and session policy** — S-A1 in full (LDAP/AD/SAML,
  MFA, API tokens, per-site RBAC, password expiry), S-N10 (no session
  revocation, and `debug: read` reading every module's events), S-N15 (a
  polling script is still signed out after the idle timeout, because only
  POST/PUT/DELETE and the browser heartbeat count as presence), S-N7
  (`apply_netpath_settings` mutating the shared settings dict), and S-S6's other
  half — the default bind is still plain HTTP on `0.0.0.0`, which is a
  deployment decision the documentation now covers rather than a default this
  release changed.
- **G-26** — `ipam_scan.read_arp_table` still catches only `OSError` and not the
  `subprocess.TimeoutExpired` its own ten-second timeout can raise. The only
  fresh-eyes finding not closed; it was routed to a workstream whose remaining
  steps ran out of budget, and it is a two-line fix waiting for the next pass.
- **Follow-ons this work created**, recorded so they are not lost: rejecting a
  cycle in `upstream_id` at the API rather than only surviving one; ordering
  `device_down` occurrences upstream-first within a tick so a fan-out sends
  exactly one email instead of one per branch; a table of previous built-in rule
  defaults so a changed default reaches an existing install; cursor pushdown for
  the IPAM conflict drain, which is the one source still reading from the start;
  and retiring the two temporary API routes that E12's forms used before
  `58366e3` put the fields on the objects themselves.

---

## Appendix A — reproducing the demonstration

```bash
# as root, from the repository root; ports 161/162/514/2055/8443/8099/1025
ulimit -n 8192
export PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
python3 demo/selftest.py                       # every persona through the app's own decoders
python3 demo/scenario.py --count 250 --out demo/out
python3 demo/scenario.py --count 1000 --out demo/out
python3 demo/scenario.py --count 2000 --out demo/out
python3 demo/fake_ssh.py & python3 demo/configrx_probe.py   # ConfigRX capture chain
```

`demo/README.md` documents every file, the persona roster (`demo/personas.py`
`SPECIALS`), the fleet control API, and the caveats (loopback, shimmed
traceroute). Screenshots, logs and per-tier `results-<N>.json` are written under
`demo/out/`, which is not committed.

## Appendix B — review method

Six reviewers worked in parallel, each restricted to reading and to running code
against temporary databases and loopback ports above 1024, and each required to
mark findings CONFIRMED only after reproduction. Their reproduction scripts
(twelve performance benchmarks, three alert-engine experiments, stub agents for
the v1 and misbehaving-agent cases, Playwright DOM audits at 2,000 devices, and
decoder fuzzers) informed §4; the numbers quoted there come from those runs on a
Linux container with a local filesystem and are therefore optimistic for a
Windows host or a network share.


## Appendix C — review of this review

This report was re-read against the code and against the reviewers' own notes
before any of it was implemented, on the principle that a document which asks for
three weeks of work should survive the same scrutiny it applies. It mostly did.
What follows is everything the re-review changed, so that anyone holding an
earlier copy can tell which numbers moved and why.

### Withdrawn

- **"At this tier the 50,000-row global cap had not yet bitten"** (§3.2). Wrong,
  and wrong in the safe direction. The cap had bitten at every tier; the row
  counts quoted are the few minutes of writes that landed after the last prune,
  not history retained. Replaced with the measured window (7.8 / 9.1 / 11.9
  minutes) and the surviving samples per metric.
- **"~680 devices … measured end to end"** (§3.3). Extrapolated, not measured:
  the tiers were 250, 1,000 and 2,000, so no run bracketed it. Softened to
  "consistent with", with the two things that *were* measured stated instead.
- **"430–630 devices/s" seeding** (§2.2). A warm-cache micro-benchmark that no
  tier reproduced. The tiers measured 333 / 43 / 27 per second.
- **"Each forged v3 trap costs a 1 MiB hash"** (§4.2 C-S2). Only true for a trap
  claiming a *configured* v3 user name; an unknown name returns "unverified"
  before any derivation (`trapdecode.py:659-662`). The finding stands with the
  precondition stated; the attacker model does not.
- **"as `monitor.py:376-402` does"** (§4.1 P-S2, §7 #4). `monitor.py` guards its
  loop but sets no error field, so there was no pattern to copy and the status
  half of the fix is new work.
- **"Thirteen special devices"** (§2.1) against a table of eleven rows.

### Corrected

| What | Was | Is |
|---|---|---|
| Samples surviving a prune per metric, 2,000 devices | 1.29 | **0.29** (50,000 ÷ 171,910 metrics) |
| Batched-write speed-up | 62× | **69×** (2,181/s → 150,832/s) |
| Fleet write requirement at 2,000 devices, 60 s | 3,233/s (97 metrics/device assumed) | **~2,870/s** (≈86 metrics/device measured) |
| Commits per poll cycle, fleet-wide | ~288,000 | **~172,000** |
| Alert tick cost | 0.85 s and 0.96 s quoted as if identical | both are ~200 metrics/device runs; ≈**0.40 s** at the 86/device measured |
| `mib_missing` at 250 devices | 234 and 235 used interchangeably | **235** alert rows, **234** emails |
| `alertsdb.py` non-outage template bindings | `217-222` | `217-221`, `223` (`:222` is `interface_up`, correctly bound) |
| `_poll_interfaces` worst case | "77 min at defaults" beside a 2-attempt measurement | 75 min for 500 ports at the shipped 3.0 s × 3 attempts; the assumption is now stated |
| `/api/alerts` limit | "300" and "2,000" in different sections | default **300**, hard cap **2,000**; both stated together |
| `PUBLIC_PATHS` | `server.py:245` | `server.py:260` in the 4.36.1 tree |
| `_evaluate_thresholds` | `alertengine.py:646-705` | function is `615-705` |
| Effort estimates | S | **M** for §7 #2 and #6; **S/M** for #12, #22a and §4.1 P-S8 |
| Finding identifiers | `B1`/`S1`/`N1`/`F1` reused across five sections | prefixed `P-` `C-` `A-` `S-` `X-` `U-`, all 34 cross-references updated |
| Tags | 99 of 149 rows untagged, §4.5 entirely untagged | every row tagged; the preamble now says what the tags mean |

Two cross-references were simply pointing at the wrong finding: §1's note about
the ping shim cited §4.3 F27 (the onboarding storm) where it meant §4.1 P-N11,
and §4.6's ConfigRX `_paramiko_ok` race carried a `D`-series identifier that
belongs to the documentation-truth table. It is now U-F36.

### Added

- **Twenty finding rows** the first draft dropped although its own reviewers had
  written them up: §4.5 X-F9, X-F13, X-F14, X-F16, X-F18, X-F23, X-F24, X-F25,
  X-F26, X-F27; §4.6 U-F8, U-F9, U-F11, U-F14, U-F25, U-F26, U-F30, U-F35; §4.4
  S-N16 (community strings returned in full to `nodes: read`). The §4.6 rows that
  had been merged — "F5/F6" and "F15–F18" — are split, so U-F5, U-F6, U-F15,
  U-F16, U-F17, U-F18 and U-F19 each stand on their own.
- **Ids for the eleven documentation-truth rows that had none or shared one**:
  D11, D14, D23, D24, and D16–D22 split into seven.
- **D25 to D28**, four documentation claims the first draft missed. D25:
  `CREDENTIAL-SECURITY.md` says the application performs "no update check"
  while the Update button calls `api.github.com` on every press. D26: there is a
  *third* "there is no authentication yet" string, in `console.py`, under the
  listener card, repainted every second — the two the report found are the two
  an operator sees least. D27: `enterprises.VERIFIED` asserts that every arc was
  read from the vendor's own MIB text, which is true of one arc in fifty-three,
  and `high` confidence in the device pane rests on that assertion. D28: the
  twenty-one bundled MIB modules had no attribution or licence notice, eighteen
  of them being other people's work.
- **The §3 caveat paragraph** ("What the numbers do not mean"), the table of the
  six settings the campaign overrode, and the note that the per-step columns do
  not sum to the run totals.
- **§1's statement that the software moved to 4.36.1** during the review, and
  **RESOLVED UPSTREAM** marks on the findings that release closed.
- **§9**, for what is actually implemented.

### Not carried forward

Three findings the reviewers raised are absent from §4 and are recorded here
rather than lost: `namelookup.reverse` mutating the process-global socket
timeout from eight threads; the traceroute worst-case guidance being calibrated
for serial probes (PLAUSIBLE, still unowned); and `performance` F17's
`/api/state` fan-out, which *is* carried as X-F17. The first of those was picked
up and **reproduced** by the fresh-eyes pass below — it is G-18, and the timeout
is left set permanently rather than merely raced on, which is worse than the
collectors reviewer's version of it.

### Files this review never read, and what was in them

The report's 395 `file:line` references touch most of the package and miss
twenty-five files entirely, including four that did not exist when the review
started and are the most security-relevant code in the product — an interactive
shell carried over a WebSocket. A seventh reviewer went through all of them
read-only, with the same rule: CONFIRMED only after reproduction. It found
**33 defects**, thirty-one of them reproduced.

**The headline is the one this review most obviously should have caught.** A
single authenticated 32 KB MIB upload freezes the entire application for
**17 seconds** — every poll, every collector write, every open browser — because
`mibparse._IMPORT_GROUP_RE` is quadratic in the size of an `IMPORTS` block and
four more macro regexes rescan the whole file from every candidate start
(G-10, G-11). `POST /api/nodes/mibs` is reachable by any account with `nodes:
write`, `max_mib_bytes` defaults to 8 MB, and nothing bounds the parse. The
original review never opened `mibparse.py`, so it graded the upload path on the
strength of the SNMP decoders beside it. It is the clearest single argument for
this appendix existing: six careful reviewers reading 90% of a codebase
produced a report whose worst omission was in the 10% nobody read.

Two secondary lessons. `vendorid.py` and `enterprises.py` were **praised in §8
without being read** — and `enterprises.VERIFIED`, whose name asserts
provenance, turns out to carry entries the repository itself contradicts
(G-15), which is exactly the kind of claim §8 was recommending other people
trust. And `snmptrapdb.py` and `ipamdb.py` carry the same VACUUM-under-the-lock
shape as §4.5 X-F5, which the report had guessed at ("Same shape in five other
DB modules") without checking: it is there, in both (G-24).

The last column records what 4.37.0 did with each row. Thirty-two of the
thirty-three are closed in this release; only G-26 is not, and §9's Deferred
list says why. §9 carries the commit and the test for every one of them.

| id | Where | Sev | Tag | What | Owner | Fixed in 4.37.0 |
|---|---|---|---|---|---|---|
| G-1 | `web/wsock.py:347-360` | high | CONFIRMED | An idle terminal burns a whole CPU core once the socket's fd is ≥ 1024 | D | yes — I1 |
| G-2 | `sshterm.py:271-294` | high | CONFIRMED | A socket that never sends `open` holds a session slot, a thread and its authorisation forever | D | yes — I2 |
| G-3 | `sshterm.py:540-569` | medium | PLAUSIBLE | One exception kills the watchdog, and with it every limit on a live shell | D | yes — I4 |
| G-4 | `sshterm.py:170-180` | medium | PLAUSIBLE | Shutting the service down can take minutes because sessions are stopped one at a time | D | yes — I4 |
| G-5 | `sshterm.py:71, 296-316` | medium | CONFIRMED | The failed-login cap is per socket, so the page is still a password oracle | D | yes — I3 |
| G-6 | `sshterm.py:415-434` | low | CONFIRMED | The terminal never records that a remembered host key was presented again | D | yes — I5 |
| G-7 | `web/server.py:546-550` | low | CONFIRMED | The WebSocket Origin check ignores the scheme | D | yes — D13 |
| G-8 | `web/wsock.py:244-263` | low | CONFIRMED | Reserved WebSocket opcodes are accepted as data | D | yes — I6 |
| G-9 | `sshterm.py:243, 483` | low | CONFIRMED | Any frame refreshes the idle timer, so a shell need never be typed at | D | yes — I5 |
| G-10 | `mibparse.py:105, 169-172` | **critical** | CONFIRMED | `_IMPORT_GROUP_RE` is quadratic: one 32 KB upload freezes the whole application for 17 seconds | B (+ D) | yes — H1 |
| G-11 | `mibparse.py:107-123` | **critical** | CONFIRMED | The four macro regexes rescan the whole file from every candidate start | B (+ D) | yes — H1 |
| G-12 | `mibparse.py:288-299, 344-353` | high | CONFIRMED | `resolve()` is O(n²) in the number of objects, and `resolve_all()` runs it eight times over every file | B | yes — H2 |
| G-13 | `mibparse.py:77-100` | medium | CONFIRMED | `_strip_comments_and_strings` costs nine bytes of memory per input byte | B | yes — H3 |
| G-14 | `mibparse.py:185, 338-339` | low | CONFIRMED | An enum value with more than 4,300 digits raises Python's integer guard out of `parse()` | B | yes — H3 |
| G-15 | `enterprises.py:1-19, 24-77` | medium | PLAUSIBLE | `enterprises.VERIFIED` claims a provenance the repository contradicts | F (+ B) | yes — H5, F6 |
| G-16 | `enterprises.py:66, 73, 102, 110, 124, 129` | low | CONFIRMED | One vendor, several keys — the vendor filter splits a fleet across rows | B | yes — H5 |
| G-17 | `enterprises.py:184-187`, `nodeoids.py:171` | low | CONFIRMED | Nothing can identify Rockwell Automation / Allen-Bradley gear | B | yes — H5 |
| G-18 | `namelookup.py:283-292` | high | CONFIRMED | `reverse()` sets a process-global socket timeout, and concurrent resolver workers leave it set permanently | C | yes — H6 |
| G-19 | `namelookup.py:107, 116-123, 151-167` | medium | CONFIRMED | The raw PTR/TXT resolver accepts an answer from any host and has no overall deadline | C | yes — H6 |
| G-20 | `namelookup.py:263-265` | low | PLAUSIBLE | `nslookup` arguments are not validated | C | yes — H6 |
| G-21 | `eventlog.py:60, 70-71, 91-93` | medium | CONFIRMED | `EventLog` remembers every target it has ever seen, and `clear()` does not clear them | C | yes — H7 |
| G-22 | `web/server.py:297-305`, `console.py:569-581` | medium | CONFIRMED | `AccessLog.clients` grows one entry per source address forever, and the console re-sorts it every second | D (+ E) | yes — D14, H9 |
| G-23 | `web/server.py:8`, `console.py:524`, `__main__.py:177` | medium | CONFIRMED | Three shipped places tell the operator there is no authentication | F (+ D, E) | yes — D15, H9, F6 |
| G-24 | `snmptrapdb.py:375-395`, `ipamdb.py:715-747` | high | CONFIRMED | `trim_to_size()` runs VACUUM up to six times while holding the write lock — §4.5 X-F5's guess, confirmed | C | yes — C4 |
| G-25 | `ipam_worker.py:96-131` | high | CONFIRMED | Every enabled subnet scans at once on the first tick, each with 64 ping subprocesses | C | yes — H10 |
| G-26 | `ipam_scan.py:180-185` | low | CONFIRMED | `read_arp_table` does not catch the timeout it sets | C | **no** — deferred |
| G-27 | `analysis.py:278-284`, `web/api.py:50-55, 290-308` | high | CONFIRMED | One GET allocates a bucket per time slot from two unclamped query parameters | D | yes — H8 |
| G-28 | `web/static/app.js:100-117, 1038-1086` | medium | CONFIRMED | A 10 Hz timer that never stops, and not one fetch that can be cancelled | E | yes — E4/E14 |
| G-29 | `web/static/debug.js:21, 117-127` | low | CONFIRMED | `escape()` leaves single quotes alone, and two server fields skip it entirely | E | yes — E15 |
| G-30 | `web/static/debug.js:258-275, 386-388` | low | CONFIRMED | The debug event table re-renders 2,000 rows on every keystroke | E | yes — E16 |
| G-31 | `services.py:18-69` | low | CONFIRMED | Duplicate keys and editorial labels in `PORTS` | C | yes — H11 |
| G-32 | `netpath/mibs/*.mib` | low | CONFIRMED | No attribution or licence notice for any of the 21 bundled MIBs | F | yes — F6 |
| G-33 | `netpath/mibs/SNMPv2-TC.mib` | low | CONFIRMED | `SNMPv2-TC.mib` is shipped, seeded, and yields nothing | B | yes — H4 |

The full write-ups, with the reproduction script for each CONFIRMED row, are
the seventh reviewer's own report. Findings are routed to the workstream that
owns the file; `mibparse.py`, `ipam_worker.py`, `namelookup.py`, `eventlog.py`,
`console.py` and `analysis.py` had no owner in the plan at all, which is
another way of saying the same thing this appendix says.
