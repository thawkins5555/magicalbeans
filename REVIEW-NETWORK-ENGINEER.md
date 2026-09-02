# SappiWhere 4.35.0 — a network engineer's review

Reviewed at commit `05259ae` (Merge 4.35.0) on 2026-09-02, from the point of view of
an operator responsible for a very large mixed fleet: thousands of switches,
firewalls, wireless access points, point-to-point wireless bridges and
industrial PLCs. The question throughout was practical: *would this tool make
monitoring and maintaining that fleet faster, and what has to change before it
does?*

Nothing in `netpath/` or `tests/` was modified for this review. Every finding
below carries a `file:line` reference and is marked **CONFIRMED** (reproduced by
running code, or traced unambiguously) or **PLAUSIBLE** (traced, not executed).
Bugs are documented here with proposed patches; none were applied, by request.

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

---

## 1. How the review was done

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
  now re-authenticates on 401. See §4.4 N15 and §4.3 F27.) Alerts, emails at a local SMTP sink, poll counters,
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

Thirteen special devices exercise the poller's edge paths:

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
| Nodes: add devices, profiles (v1, v2c, v3-noauth), sites | API, 250–2,000 devices | works; 430–630 devices/s over single POSTs; no bulk-add endpoint |
| Nodes: identity, vendor identification, arc-hop walk | all personas | correct vendor for every arc persona; Rockwell via sysDescr only |
| Nodes: interface tables, 64-bit and 32-bit counters, rates | all personas | correct; one GET per interface (513 requests per poll of the chassis) |
| Nodes: link events, flapping, reboot detection | flap storm, reboot step | events recorded; flap rule blunted by poll-interval sampling |
| Nodes: MAC tables (Q-BRIDGE, dot1d, Cisco per-VLAN) and MAC search | access and core personas | works; excellent search-to-port interaction |
| Nodes: DOM/optics in the interface dialog | core persona sensors | works, on demand only |
| Nodes: v1-only device | special 2 | identity fine, **every interface blank** (§4.1 B3) |
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
build on one Linux container (Python 3.11, local disk), with the polling
profile at a 60 s interval, 32 poll workers, the `cpu_high` threshold lowered to
20% and `response_time_high` to 5 ms so the fleet would trip them, the
new-device grace set to 0, and the email cap raised so every notification was
counted at the sink. Numbers are from `demo/out/results-<N>.json`; "alerts"
are rows opened or resolved during the step's window, "emails" are messages
received by the local SMTP sink during it.

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
| Average / peak busy poll workers (of 32) | 11 / 33 | 31 / 47 | 28 / 48 |
| App CPU during the trap + syslog burst | 63% | 84% | 86% |
| `samples` rows / `samples_hourly` rows at the end | 162,766 / 0 | 441,991 / 0 | 585,259 / 0 |
| Nodes table fill time after refresh | 181 ms | 1,854 ms | 1,488 ms |
| `/api/nodes/devices` payload per refresh | 332 KB | 1.32 MB in 653 ms | 2.64 MB in 201 ms |
| Browser long tasks during the walk (longest) | 52 (230 ms) | 122 (429 ms) | 251 (1,460 ms) |
| Uncaught page errors / failed requests | 0 / 0 (two 403s for the read-only user on Settings) | 0 / 0 (same two 403s) | 0 / 0 (same two 403s) |

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

- **Outage fan-out (§4.3 F3, F4, F24).** 143 devices behind one core produced 143
  independent "Device not responding" alerts and 238 emails, then 143 "Device
  recovered" alerts and 292 more emails. Nothing correlated them to the core
  switch. The per-device `packet_loss_high` alerts (94) did roll up under
  `device_down` once the third failed poll landed, which is the same-device
  rollup working as designed.
- **Recoveries never close (§4.3 F9).** After the outage was fully recovered the
  open-alert count was 405, up from 258 before it: the 143 `device_up` rows stay
  open until someone clicks Resolve. By the end of the run, with nothing failing,
  636 alerts were open.
- **Flapping is detected late and partially (§4.3 F13).** A port toggling every
  20–40 s on 100 switches produced 56 `interface_down` and 34 `interface_up`
  alerts in its first two minutes but only 1 `interface_flapping`; the flapping
  rule caught up during the *following* steps (17, 19, 6, 10) because it needs
  three sampled transitions inside a ten-minute window and the poller samples
  once a minute.
- **Reboots, auth failures, traps and syslog fired correctly** (20 of 20
  reboots, 5 of 5 auth failures, 17 critical syslog, 5 trap alerts). The
  `trap_critical` rule opened on `linkUp` and config-save traps as well as real
  faults (§4.3 F5), and one `linkDown` from a *managed* switch also opened
  "Link-down trap from an unmanaged device" (F6).
- **Poll pool saturation is visible (§4.1 S1, S5).** With 32 workers, the busiest
  sample had 33 in flight and the longest single poll took 160 s against a 60 s
  interval: the dark devices each cost three SNMP timeouts plus three ping
  timeouts per poll, and the 500-port chassis costs 513 requests. `poll_overrun`
  events were recorded but nothing said "the pool is full".
- **History is not being kept (§4.1 B1, B2).** 162,766 raw sample rows and an
  hourly rollup table with zero rows after 25 minutes; at this tier the 50,000-row
  global cap had not yet bitten because the 15-minute prune had run only once.
- **Onboarding storm (§4.3 F27).** 235 `mib_missing` alerts opened within the
  first poll of seeding, every one emailed with the subject "… is not responding"
  (§4.3 F26).
- **The UI held up at this size.** 250 rows filled in 181 ms, no uncaught page
  errors across 12 tabs, 10 subtabs and 21 dialogs; the read-only user saw every
  tab with zero write controls, and hit two 403s opening Settings (§4.6 C3).

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
  minutes. This is §4.1 S1, S5, N5 and §4.5 F15 measured together.
- **The alert list stopped being complete.** From step 2 onward the API's
  2,000-row cap was hit and every later snapshot is a truncated view; the UI's
  own default of 300 rows would have shown less than a fifth of it (§4.3 F20,
  §4.6 F10).
- **The onboarding storm scaled linearly:** 948 `mib_missing` alerts on the
  first poll, each emailed as "is not responding" (§4.3 F26, F27).
- **The browser cost scaled linearly too:** 1,000 rows took 1.85 s to fill after
  a refresh from a 1.32 MB payload that took 653 ms to serve, with 122 long
  tasks (longest 429 ms) during the walk (§4.5 F7, F20).
- Still no rows in the hourly rollup table after 442k raw samples (§4.1 B2).

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
  At this size, on this hardware, with 32 workers, **the poller cannot see a
  site outage**. This is the capacity ceiling §4.5 predicted (~1,350 devices at
  48 ports and 120 s; roughly half that at 60 s) measured end to end.
- **The alert list was capped for the entire campaign from step 2**, so the
  campaign's own per-step "alerts opened" column went blind; the rows above
  marked "in the DB" were read directly from `alerts.db`. An operator's browser,
  defaulting to 300 rows, would have seen 15% of it (§4.3 F20, §4.6 F10).
- **Every device raised `poll_overrun`** (2,000 alerts, 26,361 events) — the
  one alert that fires reliably at this scale is the one saying the monitor
  itself is late.
- **Onboarding:** 1,898 `mib_missing` alerts, each emailed as "is not
  responding"; 4,441 emails over 25 minutes with nothing genuinely wrong except
  the incidents the campaign injected.
- **UI:** 2,000 rows filled in 1.5 s from a 2.64 MB payload (served in 201 ms);
  251 long tasks during the walk, the longest 1.46 s; still no uncaught page
  errors. RSS grew from 167 MB to 268 MB over the run.
- 585,259 raw samples, hourly rollup still empty (§4.1 B2).

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
failing devices (§4.5 F15) are what move that ceiling; none of them is large.

---

## 4. Findings by area

Severity: **blocker** (stops the product working for this fleet), **severe**,
**notable**. Effort: S (hours), M (days), L (weeks).

### 4.1 SNMP polling core

| # | Sev | Finding | Evidence | Fix / effort |
|---|---|---|---|---|
| B1 | blocker | `sample_row_cap_per_metric` is a whole-table cap: 50,000 rows total survive each 15-minute prune, i.e. under a third of one poll cycle at 2,000 devices. Charts empty, threshold streaks reset. CONFIRMED (3 metrics × 100 samples, cap 150 → 50 each). | `nodesdb.py:342`, `service.py:715-719`, `nodesdb.py:2171-2179` | per-metric `ROW_NUMBER()` delete in chunks; **S** |
| B2 | blocker | `compact_rollup()` is never called; `samples_hourly` is always empty; any chart window over 3 days returns 0 points; storage doc promises rollups. CONFIRMED. | `nodesdb.py:1480-1503`, `nodes.js:951-954`, `NETWORK-AND-STORAGE-REQUIREMENTS.md:270` | call from `run_maintenance()`, prune by `rollup_days`; **M** |
| B3 | blocker (v1 gear) | Every interface on an SNMPv1 device is blank: the per-interface GET mixes ifXTable OIDs, a v1 agent answers `noSuchName` for the whole PDU, and only status 16 raises. Device shows *up* with no counters, no link events. CONFIRMED against a v1 stub. The identity GET already has the v1 split. | `nodepoll.py:1642-1645`, `:1173-1176`, `:1240-1259` | split the GET on v1 as `_identity_extras` does, or walk columns; **S** |
| S1 | severe | `_poll_interfaces` has no wall-clock budget: a device that answers its ifIndex walk then goes quiet holds a worker for N × timeout × retries (77 min at defaults for 512 ports). CONFIRMED (6.02 s = 10 × 0.3 × 2). | `nodepoll.py:1641` | deadline of 0.5 × interval, abandon after 3 consecutive timeouts; **S** |
| S2 | severe | The scheduler thread has no exception guard; one transient DB error stops all polling permanently and silently (`poller.error` stays `None`). CONFIRMED. | `nodepoll.py:690-721` | `try/except` + `self.error`, as `monitor.py:376-402` does; **S** |
| S3 | severe | SNMPv3 engineTime is cached at discovery and never advanced, so every v3 device fails about every third poll with a spurious auth_fail event. CONFIRMED by trace. | `nodepoll.py:56-58`, `:1145`, `:1164-1171` | send `engine_time + (now - learned_at)`; **S** |
| S4 | severe | authPriv is unsupported (no priv columns), and the failure is misreported twice: the agent's `unsupportedSecLevels` Report becomes "engine resync required", and the `"unsupported" in msg` substring never matches its own message, so the whole `unsupported` status/event/rule path is dead. CONFIRMED. | `nodepoll.py:917`, `:1153-1158`, `snmppoll.py:232-235`, `alertsdb.py:218` | decode `usmStats*` and classify by type; **M** (priv itself **L**) |
| S5 | severe | Scheduler reloads the whole device table and calls `effective_config` per device once a second: 4,001 SQLite statements/s at 2,000 devices, ~12% of a core, under the lock every worker needs. CONFIRMED (118 ms/iteration). | `nodepoll.py:694-697`, `nodesdb.py:1081-1119` | cache settings and groups; select only loop columns; **S** |
| S6 | severe | ~2,500 commits per poll of a 500-port chassis (`record_metric_sample` commits per sample); ~288,000 commits per cycle fleet-wide. CONFIRMED (0.212 s for 500 ports). | `nodesdb.py:1379-1420`, `nodepoll.py:1053-1064` | one transaction per device poll, `executemany`; **M** |
| S7 | severe | MAC-table walks run on the poll pool; Cisco per-VLAN walks check the 15 s budget only between VLANs, so the last VLAN can run two unbounded walks. | `nodepoll.py:752`, `:2196-2233` | own executor, deadline inside `_walk_column`; **S/M** |
| S8 | severe | A reboot produces a phantom 220 Mbps spike: `counter_rate` treats any decrease as a wrap and `ifCounterDiscontinuityTime` is never polled. | `nodepoll.py:122-148`, `nodeoids.py:48-53` | poll discontinuity time, suppress one poll after `detect_reboot`; **S** |
| S9 | severe | No vendor health polling at all: no Cisco/Aruba/Juniper/PAN/Fortinet CPU or memory, no ENTITY-SENSOR or ENVMON on a schedule, no PoE (MIB ships, unread), no STP, no LLDP/CDP, no ARP, no BGP, no firewall sessions/VPN/HA, no RF metrics. `HOST_RESOURCES` defined, never referenced. CONFIRMED by grep. | `nodeoids.py:58-67`, `nodepoll.py:1306` | per-vendor scalar table keyed on `detected_vendor`, ride the existing best-effort GET; **M**, tables **L** |
| S10 | severe | `cpu_pct`, `mem_pct` and every custom-MIB metric are stored and never displayed; the only charts are hard-coded interface and loss keys. | `nodes.js:16-19`, `:506`, `:1649-1650` | render `view.metrics` with the existing chart renderer; **S** |
| N1 | notable | Custom-MIB polling sends one unchunked GET of every object in the MIB (267 varbinds = 4 KB request), including table columns; `tooBig` yields zero metrics with no error. | `nodepoll.py:1582-1625` | filter table columns, chunk to 25, honour tooBig; **M** |
| N2 | notable | A reply is accepted without checking request-id or source address; a late reply to attempt 1 is consumed as the answer to attempt 2 (observed with the 2.6 s device). v3 msgID also unchecked; v3 response digests are never verified (`_verify_v3` exists, used for traps only). CONFIRMED. | `nodepoll.py:82-97`, `:1125-1160`, `:2438`, `:2473` | compare ids and address, drain mismatches; verify inbound HMAC; **S** |
| N3 | notable | No per-device SNMP port; no IPv6 polling (`AF_INET` hardcoded). | `nodeoids.py:12`, `nodepoll.py:73` | `snmp_port` override column, `getaddrinfo`; **S** each |
| N4 | notable | No bulk device import; discovery capped at 1,024 addresses per job with a serial SNMP phase (2 versions × N communities × timeout per silent address). | `api.py:1773`, `nodesdb.py:353`, `nodediscover.py:176-231` | CSV import endpoint, parallel probe phase; **S/M** |
| N5 | notable | Ping is three serial subprocess spawns per device per poll on the poll worker; a down device costs ~12 s of worker time per cycle; 160 down devices saturate the pool. | `ipam_scan.py:127-157`, `nodepoll.py:846` | concurrent probes, back-off for failing devices; **M** |
| N6 | notable | A down device re-sweeps every credential candidate every poll (36 s of worker time with four candidates); the on-demand path already has negative caching. | `nodepoll.py:1195-1209`, `:1099-1101` | reuse `_credential_probe_failed`; **S** |
| N7 | notable | `_walk_indexes` breaks on the first non-integer suffix, and `replace_interfaces` then deletes the missing rows and their events. | `nodepoll.py:1810-1819`, `nodesdb.py:1368-1375` | `continue`; refuse deletes on an unclean walk; **S** |
| N8 | notable | Non-ASCII octet strings render as hex (`Wärmetauscher 3` → `57 C3 A4 …`); a 6-byte one renders as a MAC. Stored `sys_descr` is uncapped. | `trapdecode.py:195-214` | try UTF-8 then latin-1; cap stored size; **S** |
| N9 | notable | `_walk_from` (OID browser, full walk, vendor identification) is GETNEXT-only and opens a socket per row; fleet-wide first identification ≈ 2.8 h. | `nodepoll.py:2305-2368`, `:2331` | share `_walk_column`'s GETBULK path; **S/M** |
| N10 | notable | `fortipoll._walk_column` has no non-increasing-OID guard and hardcodes timeouts. | `fortipoll.py:252-271` | reuse `nodepoll._walk_column`; **S** |
| N11 | notable | The shipped test suite fails on any machine with `ping` installed (`test_nodepoll_e2e.py:287`): the device answers ICMP so it never reaches `down`. Passes with ping removed from PATH. CONFIRMED both ways. The substantive half: a switch whose SNMP agent is dead but which answers ping never fires `device_down`. | `tests/test_nodepoll_e2e.py:219`, `tests/README.md:3-6` | disable ping in the test profile; add an "SNMP failing, ping OK" rule; **S** |

### 4.2 Collectors and decoders

| # | Sev | Finding | Evidence | Fix / effort |
|---|---|---|---|---|
| B1 | blocker | One 18-byte datagram kills the NetFlow listener: `DecodeError` is not in the decoder's except tuple and the receive loop has no guard. Status reads "Collector stopped" as if an operator did it. CONFIRMED live. | `nfdecode.py:150,160`, `collector.py:185` | add to the tuple and wrap the loop (same for traps and syslog); **S** |
| B2 | blocker | A v9/IPFIX template with zero-length fields spins the receive thread at 100% CPU forever with `running` still true. CONFIRMED. | `nfdecode.py:89-96`, `:316-337` | reject `length <= 0` templates; **S** |
| B3 | blocker | Kernel socket-buffer drops are invisible: 300k syslog messages at 38k/s → 93k stored, 206k dropped, `counters["dropped"] == 0`. CONFIRMED. | `syslogd.py:199-208`, `collector.py:158-209`, `snmptrapd.py:183-192` | read `SO_RXQ_OVFL` or `/proc/net/udp` drops; surface it; **M** |
| B4 | blocker | Every syslog prune rebuilds the entire FTS5 index under the write lock: 18.6 s to delete one row from a 1M-row table, every 15 minutes. CONFIRMED. | `syslogdb.py:482-484`, `:504-506` | targeted FTS `delete`; **S** |
| B5 | blocker | The alert engine drains 500 rows per 5 s tick per source (100 rows/s) against a measured ingest of ~11,800/s; a busy site falls behind forever with no lag indicator. CONFIRMED. | `alertengine.py:499,520`, `:28` | loop to catch up with a budget; show backlog; **M** |
| S1 | severe | SNMPv3 trap authentication is computed and counted but never enforced: 401 forged traps stored and alerted. CONFIRMED. | `snmptrapd.py:172-179`, `:194-231` | `reject_failed_auth` default on; **S** |
| S2 | severe | Each forged v3 trap with a fresh engine id costs a 1 MiB hash on the receive thread (~430 traps/s ceiling) and grows `_KEY_CACHE` unbounded; templates and `_seen` dicts likewise. | `trapdecode.py:323-345`, `nfdecode.py:122-123` | bounded LRU caches; **S** |
| S3 | severe | Dual-stack templates render IPv6 flows as `0.0.0.0` (zero-filled v4 field is truthy). CONFIRMED. | `nfdecode.py:409-411` | pick by content; **S** |
| S4 | severe | `HopProber` submits a new unbounded round of ping subprocesses every 4 s with no in-flight tracking and commits per probe. | `monitor.py:634-646`, `db.py:449-474` | in-flight set as `Monitor` has; batch upserts; **M** |
| S5 | severe | All three listeners and NetPath are IPv4-only; a device on an IPv6 management plane is silently unreachable. | `collector.py:90`, `syslogd.py:130`, `snmptrapd.py:126`, `tracer.py:380-384` | dual-stack bind; `getaddrinfo`; **M** |
| S6 | severe | Syslog over TCP spawns a thread per connection with no cap and never reaps the list. | `syslogd.py:210-221` | cap and prune; **S** |
| S7 | severe | Device correlation is exact-IP equality: a switch logging from `Loopback0` while polled on its management VLAN matches nothing (no name in the Host column, no name on the alert). | `hostresolve.py:33-34`, `nodesdb.py:950-953` | `device_addresses` alias table fed from `ipAddrTable`; **M** |
| S8 | severe | Syslog and trap occurrences never set `device_name`, so name-scoped rules silently never match. | `alertengine.py:504-509`, `:535-539` | set it; **S** |
| S9 | severe | RFC 5424 structured data: only the first element is stripped; relayed rsyslog messages carry `[origin …]` into the message column and index. CONFIRMED. | `syslogparse.py:168-188` | loop; **S** |
| N1 | notable | Non-English Windows `tracert` loses the ICMP-unreachable hop entirely (English phrase table). | `tracer.py:46-53`, `:294-296` | match on structure; **S** |
| N2 | notable | v9 field length 0xFFFF misread as IPFIX variable-length; silent corruption. | `nfdecode.py:89-96` | version-aware; **S** |
| N3 | notable | `touch_exporter` stamps every exporter in a flush batch with the first flow's version (observed live with mixed v5/v9); commits per exporter. | `collector.py:231-233`, `flowdb.py:177-190` | carry version per exporter; **S** |
| N4 | notable | RFC 3164 timestamps get no future clamp and assume the server's timezone; a December message read in June files six months ahead and can never be pruned. | `syslogparse.py:91-109`, `syslogdb.py:468-474` | clamp to now ± 1 h; **S** |
| N5 | notable | RFC 5424 with an empty MSG stores the header as the message. | `syslogparse.py:131-142` | accept 5 parts; **S** |
| N6 | notable | Sampling is one rate per exporter applied only to flows after the options template; earlier flows are stored under-scaled forever. | `nfdecode.py:369-374`, `flowdb.py:322` | resolve rate at query time; **M** |
| N7 | notable | Syslog storage is ~455 B/message measured vs the documented ~150 B. | `NETWORK-AND-STORAGE-REQUIREMENTS.md:269` | fix the figure; **S** |
| N8 | notable | Exporter interface names are hand-typed `ip:ifIndex=name` lines while `nodes.db` already holds `if_index`, `descr`, `speed_bps` for every managed device. | `flowdb.py:53-58`, `service.py:492-504` | seed from Nodes; add utilisation %; **M** |
| N9 | notable | No trap varbind conditions and no syslog regex or "N in M minutes" rules; the two rules a NOC actually writes are impossible. All syslog alerts from one host collapse into one row whose message is overwritten. | `alertsdb.py:26-50`, `alertrules.py:39-54` | `match_text`/`match_field`/`count_window_s` on rules; **M/L** |
| N10 | notable | No per-source rate limiting or repeat suppression on syslog or traps; one device in a debug loop evicts everyone else's messages. | `syslogd.py:174-197` | per-source token bucket; **M** |
| N11 | notable | `trapoids.py:51` labels `1.3.6.1.2.1.15.3.1.7` as `bgpPeerState`; it is `bgpPeerRemoteAddr` (state is `.1.2`). Rendered live as `bgpPeerState.198.51.100.75=198.51.100.75`. | `trapoids.py:51`, `:174` | correct the arc; **S** |
| N12 | notable | TCP syslog framer treats any leading `<digits><space>` as an RFC 6587 length; a newline-framed line starting with a number desynchronises the connection. | `syslogd.py:236-244` | require `<` after the count; **S** |
| N13 | notable | `Database.prune` (NetPath) VACUUMs unconditionally, even when nothing was deleted. | `db.py:590-602` | only when rows removed; **S** |
| N14 | notable | `reached` is decided against the app's own DNS answer; round-robin or anycast names record as never reached. | `tracer.py:399`, `:453` | parse the address from the traceroute header; **S** |

### 4.3 Alerting

Rule liveness (reproduced by writing every metric key the poller can produce and
ticking the engine): **7 of 32 built-in rules are DEAD, 10 PARTIAL.** Dead:
`if_in_util_high`, `if_out_util_high`, `if_in_errors_high`, `if_out_errors_high`,
`if_in_discards_high`, `if_out_discards_high`, `disk_high` — nothing writes
`if_in_util_pct`, `if_*_error_rate`, `if_*_discard_rate` or `disk_pct`; the
poller writes per-port keys (`if_in_bps.3`) that no single rule can match.
`cpu_high`/`mem_high` are UCD-only, so on a switch/firewall fleet the live device
thresholds are `ping_rtt_ms` and `ping_loss_pct`.

| # | Sev | Finding | Evidence | Fix / effort |
|---|---|---|---|---|
| F1 | blocker | Seven dead threshold rules, enabled and documented; `source_kind` is not editable on built-ins. | `alertsdb.py:226-232`, `alertengine.py:653-655`, `alertsdb.py:201-204` | compute util % from `in_bps`/`speed_bps`, poll discards, walk `hrStorageTable`; per-port key patterns; **L** (labelling **S**) |
| F2 | blocker | SMTP is sent inline on the engine tick with no circuit breaker; failures do not consume the hourly quota. 500 devices down with a dead relay = 500 × 15 s ≈ 2 h of frozen engine. CONFIRMED (25.7 s at a 0.05 s simulated failure; 12.3 s with a healthy relay vs a 5 s tick). | `alertengine.py:1218-1228`, `:1146-1152`, `alertmail.py:262-273` | sender queue thread + breaker; **M** |
| F3 | severe | 500 outages → 500 alerts, 60 emails, 440 dropped with no `notifications` row; the only trace is one line in a 3,000-entry in-memory ring that the poller overwrites in ~90 s. CONFIRMED. | `alertengine.py:1159-1170`, `eventlog.py:56-58` | write a rate-limited row per alert; digest email; **S/M** |
| F4 | severe | No digest, batching or correlation window: one email per alert. | `alertengine.py:1096-1152` | `digest_seconds`; **M** |
| F5 | severe | `trap_critical` fires on every trap of any severity (severity gate is syslog-only); 50 informational config-save traps opened a severity-2 "Critical SNMP trap". CONFIRMED. | `alertengine.py:504-509`, `:1111-1122`, `alertsdb.py:238` | carry trap severity, gate it; **S** |
| F6 | severe | Trap dedup key is the trap OID, not the source: 200 `linkDown` traps from 200 switches collapse into one alert naming no device; `trap_link_down_unmanaged` never checks whether the source is managed. CONFIRMED. | `alertrules.py:43`, `alertengine.py:494-512` | `source:oid` entity, real unmanaged gate; **S** |
| F7 | severe | Syslog alerts collapse per host; three distinct faults become one row, first two lost. CONFIRMED. | `alertengine.py:535-539`, `alertsdb.py:697-712` | message signature in the dedup key; **M** |
| F8 | severe | `renotify_minutes` never fires: `open_or_increment` refreshes `last_ts` and returns the re-read row before the comparison; event-driven rules see no new occurrence anyway. CONFIRMED (renotify 1 min, 20 min breach → 1 email). | `alertengine.py:1146-1152`, `alertsdb.py:697-712` | `last_notified_ts`, per-tick sweep; **M** |
| F9 | severe | Eleven rules have no auto-resolve path (`device_up`, `device_rebooted`, `poll_overrun`, `interface_up`, `interface_flapping`, `trap_*`, `syslog_critical`, `ipam_new_conflict`); recoveries accumulate as open alerts. CONFIRMED. | `alertrules.py:115-135`, `alertengine.py:696-704` | `auto_resolve_after_s`; pair IPAM conflict-resolved; **M** |
| F10 | severe | A stale metric holds a threshold alert open forever and re-raises it every tick (opened from a 45-day-old sample; `last_ts` = now), sorting it to the top. CONFIRMED. | `alertengine.py:672-695`, `alertsdb.py:644` | treat samples older than N × interval as absent; **S** |
| F11 | severe | Hand-resolving "Device not responding" un-suppresses every child: three fresh alerts and emails within 5 s for a device still down. CONFIRMED. | `alertengine.py:1042-1051`, `:1126-1137` | extend sticky-resolve to `ROLLS_UP` children while `status == 'down'`; **M** |
| F12 | severe | Drain cursors commit before the apply loop; one exception mid-loop permanently discards the rest of the batch (injected failure lost 8 of 10 outages). CONFIRMED. | `alertengine.py:156-177`, `:418-419` | per-occurrence guard, commit cursor after apply; **S/M** |
| F13 | notable | Flapping detection only sees transitions slower than the poll interval; true fast flapping is invisible, and the device's own linkDown/linkUp traps land in F6's collapsed alert. | `nodepoll.py:1046-1053`, `alertrules.py:56-66` | count trap transitions per source; read `ifLastChange`; **M** |
| F14 | notable | `_evaluate_thresholds` reads ~400,000 metric rows every 5 s to evaluate four live rules (0.96 s/tick at 2,000 × 200, 88% fetching rows no rule reads). CONFIRMED. | `alertengine.py:646-705`, `nodesdb.py:1422-1426` | one keyed query; **S** |
| F15 | notable | SMTP auth cannot be configured on Linux (DPAPI). | `api.py:3237-3251` | platform-neutral secret store (§6) |
| F16 | notable | Email is the only channel: no webhook, Slack, Teams, PagerDuty, SMS, syslog or trap forwarding. | `alertengine.py:1156-1230` | generic webhook with the existing template engine; **M** |
| F17 | notable | No per-rule recipients, escalation, on-call or shift awareness; every alert goes to `smtp_to_default`. | `alertengine.py:1199-1205` | `recipients` column; **S**; escalation **M** |
| F18 | notable | Mute is device-only, capped at 24 h, cannot be scheduled; traps, syslog, IPAM, NetPath targets and APs cannot be muted at all. | `alertengine.py:170,179-215`, `alertsdb.py:199` | maintenance windows table keyed on `(entity_kind, entity_id)` with schedule; **M** |
| F19 | notable | Acknowledge is irreversible; "Acknowledge all" zeroes the fleet badge; the badge has no severity colour though `open_summary()` computes `worst`. | `alertsdb.py:936-949`, `app.js:1008-1013` | un-ack; badge shows open + acked with colour; **S** |
| F20 | notable | Alert list silently truncates at 300 with no total; bulk actions act on the page. | `api.py:2981`, `alerts.js:57-65`, `:213` | return `total`, act on the filter; **S/M** |
| F21 | notable | Emails carry an unlabelled server-local timestamp. | `alertmail.py:104-108` | add offset; **S** |
| F22 | notable | `count` inflates by 12/minute on threshold alerts and is printed in the email ("occurred 8640 time(s)"). | `alertengine.py:678-695` | increment on new sample only; **S** |
| F23 | notable | `duration_text(0.4)` renders "0 s" — the case its docstring says it avoids. Seen live in a recovery mail. | `alertmail.py:132-138` | round first; **S** |
| F24 | severe | No dependency map: a core failure is N independent alerts; interface alerts on the upstream's ports are excluded from rollup by design. | `alertrules.py:142-189`, `:158-162` | upstream-device field (manual or seeded from NetPath), consulted before opening `device_down`; **L**, very high value |
| F26 | severe | Six unrelated rules are bound to the `device_down` email template, whose subject is "{{device_name}} is not responding": `device_auth_fail`, `device_unsupported`, `poll_overrun`, `mib_missing`, `interface_down`, `interface_flapping`. CONFIRMED in the demo: adding 250 devices produced 234 emails titled "acc-sw-070 is not responding" that were actually "vendor MIB not uploaded". An operator reading the inbox sees a site outage that is not happening. | `alertsdb.py:217-222`, `alertmail.py:20` | one generic "{{rule_name}}: {{entity_label}}" template for non-outage rules; **S** |
| F27 | severe | Onboarding storm: every device with a recognised enterprise arc and no uploaded MIB opens `mib_missing` on its first poll. 234 alerts and their emails within the first minute of seeding 250 devices; with the default 300 s grace they are held, then fire anyway because the condition persists. Nothing bulk-resolves them and the rule has no auto-resolve. CONFIRMED. | `nodepoll.py:1390`, `alertsdb.py:220` | ship `mib_missing` disabled or severity 7 with no email; bulk-resolve by rule; **S** |
| F25 | notable | Missing NOC essentials: top-N noisy devices, alert history/MTTR report, SLA/uptime report (segments already computed in `device_status_segments`), per-site filter, export, ticket link, runbook URL, appendable notes, desktop notification. | `alertsdb.py:675-695`, `nodesdb.py:1558-1592` | top-N and CSV **S**; runbook column **S**; site filter and SLA **M** |

### 4.4 Security and credentials

| # | Sev | Finding | Evidence | Fix / effort |
|---|---|---|---|---|
| B1 | blocker | Self-update executes unsigned code from the tip of a mutable GitHub branch: no signature, hash, tag pin or disable setting. Push access to the repo is RCE on every host holding the plant's credentials. CONFIRMED. | `selfupdate.py:54-56`, `:86-108`, `:261-322`, `server.py:238` | signed tags or pinned digest; `updates_enabled` default off; **M** |
| B2 | blocker | The forced admin password change is enforced only in `app.js:1019`; `admin`/`admin` with `must_change` set gets 200 from every API route. CONFIRMED. | `api.py:3887-3927`, `server.py:437-520` | refuse routes except session/password while set; **S** |
| B3 | blocker | Privilege escalation: `debug: write` → `POST /api/settings {scope:"debug"}` falls through to `apply_global_settings` (bind address, port, TLS paths, DNS server, session lifetimes) and echoes the unfiltered settings. CONFIRMED with a debug-only user. | `server.py:48-56`, `api.py:841-862`, `service.py:229-253` | derive the module from the dispatch table; filter the response; **S** |
| S1 | severe | `POST /api/alerts/smtp/test` sends the stored SMTP password in cleartext AUTH PLAIN to any host and port in the body (also an SSRF primitive). CONFIRMED against a listener. Same class: DHCP and device edit before test/poll. | `api.py:3265-3298`, `alertmail.py:262-272` | refuse the stored secret with a body-supplied host; **M** |
| S2 | severe | ConfigRX accepts any SSH host key on every connection; no known_hosts; `allow_legacy_ssh` default true; password auth only. | `configrx.py:288-299`, `:655-662`, `:503-504` | persist and pin host keys; default legacy off; **M** |
| S3 | severe | Config backups (communities, TACACS keys, IPsec PSKs, enable secrets) are zlib-only and served to any `configrx: read` user; not listed in `CREDENTIAL-SECURITY.md`'s inventory. | `configrxdb.py:224-229`, `api.py:3846-3851`, `server.py:229` | gate content on WRITE; redact known secret lines; **M** |
| S4 | severe | Database files are created 0644 in a 0755 directory; no chmod or umask anywhere. CONFIRMED. | `__main__.py:20-27` | `mode=0o700`, `chmod 0o600`; **S** |
| S5 | severe | DPAPI-only secret storage: nothing credentialed works on Linux (see Verdict). | `dpapi.py:47-49`, eight `api.py` endpoints | platform-neutral `secretstore`; **L** |
| S6 | severe | Default bind is plain HTTP on 0.0.0.0 and the headless banner still says "There is no authentication yet" on every start (auth shipped in 4.22). CONFIRMED. | `__main__.py:144-145`, `:177`, `server.py:8-10` | delete the claims; default to loopback; warn without TLS; **S** |
| S7 | severe | `settings: write` is undeclared root: grants itself every module, resets any password, triggers self-update; no self-escalation guard. | `server.py:68-71`, `api.py:3977-4013` | explicit admin capability; **M** |
| N1 | notable | Username enumeration: the dummy hash uses N=2^14 vs real 2^17 (0.055 s vs 0.48 s). CONFIRMED. | `api.py:3903-3907` | build from live constants; **S** |
| N2 | notable | Login throttle is delay-only, dilutes under concurrency (12 parallel guesses in 10.7 s), any successful login clears the whole client key; ~134 MiB scrypt per attempt on a public endpoint. | `auth.py:265-304`, `api.py:3895-3897` | semaphore, lockout, never clear on another user's success; **M** |
| N3 | notable | No CSRF token; Origin never checked (SameSite + JSON content type only). | `server.py:466-472` | require same-origin `Origin`/`Sec-Fetch-Site`; **S** |
| N4 | notable | No `frame-ancestors`, `form-action`, `base-uri` or HSTS. | `server.py:345-350` | extend CSP; **S** |
| N5 | notable | `App.modal()` interpolates device `sysName` into `innerHTML` unescaped (markup injection; CSP blocks script). | `app.js:386-392`, `nodes.js:1971`, `configrx.js:346` | escape in `modal()`; **S** |
| N6 | notable | Body `_agent` overrides the real User-Agent in the session list; underscore keys are stripped from the query only. | `server.py:441-443`, `api.py:3924` | filter body keys; **S** |
| N7 | notable | `apply_netpath_settings` mutates the shared global settings dict. | `service.py:66`, `:258-263` | separate dicts; **S** |
| N8 | notable | MIB catalog downloads use no vendored CA bundle and no integrity pin. | `mibcatalog.py:626-650` | reuse `selfupdate._ssl_context()`, pin SHA-256; **S** |
| N9 | notable | The audit trail is a 3,000-entry in-memory ring a `debug: write` user can flush; a 200 KB username evicts it. | `eventlog.py:55-70`, `api.py:3908` | on-disk append-only audit log; **M** |
| N10 | notable | No session revocation; `debug: read` reads every module's events. | `api.py:3963-3975`, `:687-830` | delete-session route; filter events by grant; **S** |
| N11 | notable | Discovery sweeps have no pacing (64 parallel pings, then SNMP probes) and no never-scan list — a known way to upset fragile PLC stacks; `/focus` (3 s polling) is gated on READ. | `ipam_scan.py:225-235`, `nodediscover.py:138-172`, `server.py:130` | probes/s ceiling, deny-list, WRITE on focus; **M** |
| N12 | notable | Maintenance "prune" actions delete *everything* (`prune(0, 0)`), including all config backups, with no typed confirmation. | `api.py:876-913` | require `confirm` and log counts; **S** |
| N13 | notable | Slowloris: no handler timeout, no connection cap, 128 MiB max body. PLAUSIBLE. | `server.py:316`, `:367`, `:565-568` | `timeout = 30`, bounded pool; **S** |
| N14 | notable | Chunked request bodies are treated as empty (a proxy forwarding chunked POSTs would execute defaults). CONFIRMED. | `server.py:369-381` | reject `Transfer-Encoding`; **S** |
| N15 | notable | Scripts are signed out after the idle timeout regardless of API activity: the timeout counts browser heartbeats only, so a polling automation loses its session after 10 min (the campaign's snapshots went blank at exactly that point) and must re-login; there is no API token or service account and no documented heartbeat for non-browser clients. CONFIRMED in the demo. | `auth.py:180-193`, `app.js:136-216` | API tokens, or a documented `/api/heartbeat` for scripts; **S/M** |
| — | absent | LDAP/AD/SAML/RADIUS/TACACS+, MFA, API tokens or service accounts, per-site RBAC, password expiry, persisted failed-login records, on-disk audit log. | `permissions.py:16-19`, `FEATURES.md:48` | procurement gates for a regulated network; **L** |

### 4.5 Performance and scale

All eight fixes claimed in `PERFORMANCE_REVIEW.md` are present and correct; that
review only looked at request-path N+1s. Measured capacity as shipped (bound by
per-sample commits on a realistically sized `samples` table): **~1,350 devices**
at 48 ports and 120 s, ~680 at 60 s, ~130 for 500-port chassis. After the five
fixes marked ★ below: ~4,000–5,000 at 120 s.

| # | Sev | Finding | Measured | Fix / effort |
|---|---|---|---|---|
| F1 ★ | blocker | Global sample cap (see 4.1 B1): 1.29 samples per metric survive at 2,000 devices; the DELETE of ~11.1M rows holds the process lock ~44 s every 15 min. | 1.11M rows / 4.42 s at 1/10 scale | per-metric cap, chunked; **S** |
| F2 ★ | blocker | `compact_rollup()` dead; 400-day windows return 0 points. | 0 points | call from maintenance; **M** |
| F3 ★ | blocker | One commit per metric sample: 13,731/s empty → 2,181/s at 5M rows; fleet needs 3,233/s; batching is 62× faster. | 150,832/s batched | `record_metric_samples`, one transaction per device poll; **M** |
| F4 ★ | severe | Scheduler loop: 4,001 queries/s at 2,000 devices. | 118 ms/iteration | cache settings/groups; **S** |
| F5 | severe | `trim_to_size()` runs VACUUM inside the lock up to six times (6.49 s each at 2M rows). Same shape in five other DB modules. | 38.9 s stall | VACUUM outside the lock or incremental; **M** |
| F6 ★ | severe | One SNMP GET per port: 500-port chassis at 30 ms RTT = 15.2 s serial per poll. | — | GETBULK the columns (machinery at `nodepoll.py:1742-1778`); **M** |
| F7 | severe | `/api/nodes/devices` unpaged: 2.18 MB and 115 ms of lock-held CPU per refresh per tab (default every 10 s; the UI walk saw it every 2 s). | 2,175.9 KiB | paging + drop `sys_descr` from the list; **M** |
| F8 | severe | Alert tick reads every metric of every device every 5 s (0.85 s/tick at real metric counts). | 436 ms at 100/device | keyed query; **M** |
| F10 | notable | MAC prefix search uses `LIKE`, defeating its index: 528× slower than a range scan; fired per keystroke. | 10.57 ms vs 0.02 ms | range predicate; **S** |
| F11 | severe | Raw samples: 9.1 GB/day at 2,000 × 48 ports; 400-day default = 3.6 TB (only survivable because F1 throws it away). | 33 B/row | fix F2, document per-port cost; **S** |
| F12 | severe | One `RLock` and one connection serialise 16 workers, the scheduler, the alert tick, maintenance and every HTTP handler; WAL buys nothing. | 16 threads = 3.5× not 16× | per-worker connections with `busy_timeout`; **L** |
| F15 | notable | Ping = 3 serial subprocess spawns per device per poll; a down device costs ~12 s of worker time. | 2.3 ms/spawn | concurrent probes, back-off; **M** |
| F17 | notable | `/api/state` fans out across ten databases and 30 `stat()` calls every 2 s per tab. | — | COUNT queries, cache sizes; **S** |
| F19 | notable | No `visibilitychange` handling; a minimised tab polls forever. | — | pause hidden tabs; **S** |
| F20 | notable | Table sort calls `localeCompare` per comparison (19 of 29 ms per redraw at 2,000 rows); no virtual scrolling (24,000 live cells). | 29.4 ms JS | hoist an `Intl.Collator` **S**; virtual rows **L** |
| F21 | notable | `series()` returns every raw point (28,800 for 24 h at focus cadence); the chart cannot show more than ~800. | 26.8 ms/50k | default `bucket_s` from pixel width; **S** |
| F22 | notable | Pure-Python BER: 22% of one core at 2,000 × 48 ports at 120 s, 44% at 60 s. | 122 µs encode | F6 removes most of it |
| F28 | severe | Single process, no remote pollers, no sharding: every ceiling compounds in one process and a datacentre failure takes monitoring with it. | — | remote-poller agent; **L** |

### 4.6 UX, accessibility and documentation truth

| # | Sev | Finding | Evidence | Fix / effort |
|---|---|---|---|---|
| F12 | blocker | The Dashboard is a 385-byte placeholder, and `login.js:44` makes it the landing page after every sign-in. | `dashboard.js`, `index.html:41-47` | tile grid over existing endpoints; **M** |
| F27 | blocker (on-call) | Zero media queries; `body{overflow:hidden}` clips rather than scrolls; at 390 px six of twelve tabs are unreachable and every device name is cut. CONFIRMED with a screenshot. | `app.css:51-59`, `app.js:956-960` | `nav{overflow-x:auto}` **S**; narrow layout **L** |
| D14 | blocker (intermittent) | ConfigRX reported "paramiko is not installed" beside "paramiko 4.0.0" in the same `/api/state`; the unlocked `_paramiko_ok` cache is written from two threads, and when it caches `False` the module is disabled fleet-wide and legacy SSH is never applied. Reproduced once. | `configrx.py:78`, `:105-120`, `:493` | put the cache behind the lock; **S** |
| F1 | severe | No URL routing: nothing can be linked to, Back does nothing, escalations are prose. CONFIRMED. | `app.js:963-985` | hash routes; **M** |
| F2 | severe | Search is `LIKE %q%` over ip, name, sys_name only: `q="Cisco"` returns 0 rows with Vendor visible as a column. | `nodesdb.py:932-937` | add vendor/location/contact, CIDR, field qualifiers; **S/M** |
| F3 | severe | No paging or virtualisation; 2.19 MB per refresh, 25,402 DOM nodes at 2,000 devices. | `api.py`, `nodes.js:196-230` | server paging; **M** |
| F4 | severe | One flat group level; no sites, tags or saved views; column layout is global. | `nodes.js:145-150`, `:185-186` | tags + per-user saved views; **L** |
| F5/F6 | severe | No export of any table; no CSV import (500 devices is 500 dialogs). README documents an "Export window to CSV" that does not exist. | grep, `README.md:592` | generic export endpoint, paste-CSV import; **M** each |
| F7 | severe | Maintenance windows impossible (see 4.3 F18). | `alerts.js:36`, `:307`, `api.py:3049-3056` | **M** |
| F10 | severe | Alerts list truncates at 300 and the label says "300 shown" with no total; select-all acknowledges 300 of N. | `api.py:2981`, `alerts.js:213` | total + honest label; **S** |
| F15–F18 | severe | Zero ARIA outside the 4.35 help panel: 29 tables with no `scope`, `aria-sort` or caption; sorting mouse-only; the main modal has no dialog role, no focus trap and drops focus to `body` on close — while the help panel ten lines away does all three correctly. CONFIRMED in the DOM. | `app.js:385-415`, `:455-476` | one change in the shared grid helper; lift help-panel behaviour into `modal()`; **S** |
| F20 | severe | Under deuteranopia `--ok`, `--fail`, `--blocked` collapse to three khakis (1.34:1 apart); `--fail` and `--error` have identical luminance; timelines are colour-only with mouse-only tooltips. | `theme.py:38-44`, `nodes.js:826-833` | extend the existing hatch/stripe vocabulary; **S** |
| F21 | severe | `.hint` is 2.50:1 contrast at 11 px and it renders every device's IP address. | `app.css:264`, `nodes.js:143` | use `--muted`; **S** |
| F23 | severe | Server loss shows the raw string "Failed to fetch" in 11 px grey while 2,000 stale rows stay on screen looking live; no staleness marking, no reconnect signal. CONFIRMED offline. | `app.js:130-134`, `:1076-1096` | operator-language message, dim stale content; **S/M** |
| F24 | notable | No spinners, no `aria-busy`, no request timeout. | `app.js:104-116` | **S** |
| F13 | notable | The README's NetFlow keyboard shortcuts (Ctrl+=/−/arrows/0/Home) do not exist; no modifier-key handler exists anywhere. CONFIRMED by grep and in the browser. | `README.md:280-293` | implement or delete; **S** |
| F22 | notable | The help "?" covers 2 of ~150 settings. | `nodes.js:2356` | content, not code; **M** |
| F28 | notable | No favicon (404 on every load), no alert count in the title, no desktop notification. | `server.py:245`, static | **S** |
| F29 | notable | Timestamps are browser-local with no zone indicator anywhere. | `app.js:223-235` | zone label, UTC toggle; **S/M** |
| F31 | severe | Wireless is FortiGate-only and the UI never says so. | `wirelessdb.py:1`, `wireless.js` | say it in the tab and empty state; **S** |
| F32 | severe | IPAM's DHCP form renders fully on Linux with Windows-only help text; `IS_WINDOWS` is defined and never used. | `ipam_dhcp.py:54`, `ipam.js:445` | gate the form; **S** |
| F33 | severe | ConfigRX detects a change (SHA-256) and cannot show a diff. | `configrx.js:452-456` | `difflib` unified diff endpoint; **M** |
| F34 | notable | `POST /api/nodes/devices` accepts `snmp_version: "2c"` and the poller then raises `ValueError` on every poll of that device. CONFIRMED. | `api.py`, `nodepoll.py:1261` | validate and coerce; **S** |
| C1 | notable | `window.App` does not exist (`const App` in a classic script); documentation and any automation assuming a window global is wrong. | `app.js:3` | expose it; **S** |
| C2 | notable | Uncaught `TypeError` from the OID browser when another dialog replaces the modal mid-walk (`#oid-status` gone); same pattern in `deviceDialog`. CONFIRMED in the console log. | `nodes.js:1261`, `:1346`, `:922` | check the dialog identity, not the modal; **S** |
| C3 | notable | Read-only users get a 403 every time they open Settings (`loadUsers()` called unconditionally; route needs WRITE); the grid is silently empty. | `settings.js:442`, `server.py:68` | gate on the grant; **S** |

Documentation truth table (each row checked against code or the running app):

| # | Claim | Where | Reality |
|---|---|---|---|
| D1/D2 | `deploy\Install-Shortcut.ps1`, `deploy\Update-SappiWhere.ps1` | `README.md:99, 102, 453, 459` | no `deploy/` directory exists; the only documented update path is a missing script |
| D3/D4 | "There is no authentication yet" | `__main__.py:177` (printed every start), `web/server.py:8-10` | auth, sessions, permissions since 4.22 |
| D5 | NetFlow chart Ctrl shortcuts | `README.md:280-289` | not implemented |
| D6 | "there is no SNMP polling … and no alerting engine … yet" | `FEATURES.md:1141-1143` | both exist (`nodepoll.py`, `alertengine.py`) |
| D7 | "Data > Export window to CSV" | `README.md:592`, `FEATURES.md:1850` | no CSV export exists |
| D8/D9 | "Verified with a Playwright test" (twice) | `PERFORMANCE_REVIEW.md:69-79, 93-95` | no Playwright test is in the repository |
| D10 | "Worth adding next — alerting on status transitions" | `README.md:598-600` | shipped |
| D12 | "SHOW RUN — available once SSH integration is added" | `nodes.js:1577` (in the UI) | ConfigRX shipped |
| D13 | "hundreds of devices" | `FEATURES.md:177` | the only scale figure in 470 KB of docs |
| — | "raw samples roll up into hourly min/avg/max after 3 days" | `NETWORK-AND-STORAGE-REQUIREMENTS.md:270` | rollup never runs |
| — | "~150 bytes per syslog message" | `NETWORK-AND-STORAGE-REQUIREMENTS.md:269` | ~455 B measured |
| — | "CPU/memory where UCD-SNMP-MIB or HOST-RESOURCES-MIB is present" | `FEATURES.md:94-96` | HOST-RESOURCES is never polled |
| — | engine parameters "only need refreshing if the target reboots" | `nodepoll.py:44-46`, `INTERNALS.md:445` | engineTime is never advanced (4.1 S3) |
| D15 | ports table | `NETWORK-AND-STORAGE-REQUIREMENTS.md:21-25` | correct throughout; the most trustworthy document in the set |
| D16–D22 | no table of contents in any document; no quick-start; no API reference for 170 routes; no backup/restore guide for ten WAL databases; no runbook; upgrade guide is Windows-only; README covers 4 of 12 tabs (not Nodes or Alerts) | all `.md` | — |

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

---

## 6. Recommendations, ranked

Ordered by what most reduces the operator's time per incident and per change,
weighted by effort. "Where" names the code that already carries the mechanism.

### Tier 0 — correctness fixes to ship before anything else (all S unless noted)

1. **Per-metric sample cap and chunked prune** — `nodesdb.py:2171-2179`, `service.py:719`. Without this nothing charts and the process stalls 44 s every 15 minutes.
2. **Call `compact_rollup()` from maintenance and prune it by age** — `service.py:715`, `nodesdb.py:1480`. **M.**
3. **Batch each poll's samples into one transaction** — `nodesdb.py:1398`, `nodepoll.py:1055-1064`. 62× write throughput; raises the ceiling past 5,000 devices on its own. **M.**
4. **Exception guards on every loop that must not die**: `NodePoller._loop` (`nodepoll.py:690`), the NetFlow/trap/syslog receive loops (`collector.py:185`, and `DecodeError` in `nfdecode.py:150`), the alert apply loop with cursor commit after apply (`alertengine.py:156-177`).
5. **SMTP off the tick**: sender queue thread, failures count against the quota, breaker after N failures — `alertengine.py:1218-1228`. **M.**
6. **Fix `renotify_minutes`** (`last_notified_ts`) and give momentary-event rules an `auto_resolve_after_s` — `alertengine.py:1146-1152`, `alertrules.py:115-135`. **M.**
7. **Trap identity and severity**: entity `source:oid`, carry `traps.severity`, apply the gate to traps, real "unmanaged" check — `alertengine.py:504-509`, `:1116`. Syslog dedup on a message signature — `:535-539`.
7a. **Stop non-outage rules emailing "is not responding"**: give `mib_missing`, `device_auth_fail`, `device_unsupported`, `poll_overrun`, `interface_down` and `interface_flapping` their own subjects — `alertsdb.py:217-222`; ship `mib_missing` without email.
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

Documented only, per the reviewer's instruction. Each is CONFIRMED unless noted.

1. `netpath/nodesdb.py:2171-2179` — replace the global `LIMIT (total - max_samples)` delete with a per-metric window:
   `DELETE FROM samples WHERE rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER (PARTITION BY metric_id ORDER BY ts DESC) rn FROM samples) WHERE rn > ?)`, executed in chunks outside the lock.
2. `netpath/web/service.py:715` — after `nodes_db.prune(...)`, call `nodes_db.compact_rollup(...)` and prune `samples_hourly` by `rollup_days`.
3. `netpath/nodesdb.py:1398` — add `record_metric_samples(device_id, rows)` (one `metrics` upsert pass, one `executemany`, one commit); call it once from `_poll_device` with the poll's accumulated rows.
4. `netpath/nodepoll.py:690-721` — wrap the loop body in `try/except Exception as exc: self.error = str(exc); self.log.add(ERROR, ...)`; continue.
5. `netpath/nodepoll.py:1642-1645` — on `is_v1`, issue the IF-MIB GET and the ifXTable GET separately, tolerating `noSuchName` on the second, as `_identity_extras` (`:1211-1229`) already does.
6. `netpath/nodepoll.py:1145, 2453, 2492` — use `engine_time + int(now - learned_at)`; on a Report, rediscover and retry once in the same call.
7. `netpath/nodepoll.py:82-97` — compare `response.request_id` to the sent id and `_addr[0]` to `self.ip`; keep receiving until the deadline on mismatch. Thread the v3 `msgID` the same way. Verify inbound v3 digests with `trapdecode.find_auth_span` + HMAC as the trap receiver does.
8. `netpath/nodepoll.py:917` — classify `status = "unsupported"` from the exception type (`SnmpUnsupported`), and decode the Report's `usmStats*` OID into a real message in `_snmp_get`.
9. `netpath/nfdecode.py:150` — add `DecodeError` to the except tuple; `netpath/collector.py:185` — wrap the receive body in `try/except Exception`, count and log. Same for `snmptrapd._receive`/`_enqueue` and `syslogd._receive_udp`/`_enqueue`.
10. `netpath/nfdecode.py:316-337` — treat `fixed is not None and fixed <= 0` as a broken template: count, drop the cache entry, return `[]`; refuse `count == 0` templates at `:250-265`.
11. `netpath/nfdecode.py:409-411` — choose the address field by content: skip `None`, `b""` and all-zero bytes before falling back.
12. `netpath/syslogdb.py:482-484, 504-506` — replace `INSERT INTO logs_fts(logs_fts) VALUES('rebuild')` with per-row `'delete'` entries for the ids removed (collect with `RETURNING id`).
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
22a. `netpath/alertsdb.py:217-222` — bind `device_auth_fail`, `device_unsupported`, `poll_overrun`, `mib_missing`, `interface_down` and `interface_flapping` to a new generic template (`subject: "SappiWhere: {{rule_name}} — {{entity_label}}"`) instead of `device_down`; seed `mib_missing` with `notify = 0`.
22b. `netpath/auth.py:180-193` — accept a `heartbeat` on any authenticated API request that carries an `X-Sappiwhere-Client: script` header, or add long-lived API tokens (`api_tokens` table, `Authorization: Bearer`), so automation is not signed out by the browser idle rule.
23. `netpath/web/server.py:_route` — when `app_db.user(username)["must_change"]`, refuse every route except `/api/session`, `/api/logout`, `/api/state`, `/api/password`.
24. `netpath/web/server.py:48-56` — return `("settings", W)` for any scope `post_settings` does not dispatch explicitly; `api.py:841-862` — filter the returned settings through the same rule `get_state` uses.
25. `netpath/selfupdate.py` — pin to a signed tag or a published SHA-256; add `updates_enabled` (default false) checked in `apply()` and `post_update`.
26. `netpath/web/api.py:3265-3298` — refuse to use the stored SMTP password when the body overrides host/port/security; reject `smtp_security` values that disable transport security when a password will be sent.
27. `netpath/__main__.py:20-27` — `os.makedirs(folder, mode=0o700)`; `os.chmod(path, 0o600)` after every `sqlite3.connect`. `:177-180` — delete the "no authentication yet" lines; `web/server.py:8-10` likewise.
28. `netpath/configrx.py:78, 105-120` — guard `_paramiko_ok` with the module lock or derive it from `paramiko_identity()`.
29. `netpath/configrx.py:288-299` — persist host keys in `configrx.db`, pin on first success, refuse or require acknowledgement on change; default `allow_legacy_ssh` to false.
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
41. Docs: delete `README.md:99-103, 280-293, 453-460, 592`; rewrite `FEATURES.md:1141-1143`; strike or commit the Playwright tests claimed in `PERFORMANCE_REVIEW.md:69-79, 93-95`; correct `NETWORK-AND-STORAGE-REQUIREMENTS.md:269-270`; correct `FEATURES.md:94-96`; note in `NETWORK-AND-STORAGE-REQUIREMENTS.md` that on non-Windows hosts no credential feature is available and that the collectors are IPv4-only; add a ConfigRX backup row to `CREDENTIAL-SECURITY.md`'s inventory.

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
