# SappiWhere 4.46.4 — a fleet operator's evaluation

Evaluated at commit `57367c7` (4.46.4) on 2026-09-04, from the position of an
engineer responsible for a single site of up to 2,000 mixed devices: access
switches, wireless controllers and APs, point-to-point wireless bridges,
industrial switches and PLCs. The question is a buying question, not a code
question: **would this tool run my site, and what has to change before it
could?**

Nothing in `netpath/`, `demo/` or `tests/` was modified. Every number below
came from a run on this hardware and names the run it came from; every gap
names the file and line that establishes it.

**Read this with `REVIEW-NETWORK-ENGINEER.md`, not instead of it.** That
document is a code-level review of **4.35.0**, with a campaign re-run at
4.39.0. This one is a *product* evaluation of **4.46.4** — eleven releases
later — and its most useful section is §2, which says what those eleven
releases actually changed.

## Evidence grades

Every claim carries one of:

- **MEASURED** — produced by a run on this hardware, naming the artefact.
- **TRACED** — established by reading the shipped source, with `file:line` at
  4.46.4. Used for the absence of a feature, which no run can prove.
- **CORRECTED** — something an earlier pass of this evaluation got wrong, kept
  visible rather than quietly removed. There are two; both are in §6.

## Test environment, stated because it bounds everything

4 CPUs, 16 GB RAM, 30 GB free disk, Linux, Python 3.11.15, local disk. The
application, the simulated fleet and the browser all share those four cores.
This matters enough that every tier carries a contention control (§3.1) saying
whether the number describes the product or the harness.

**It is a Linux host, and that removes features by design.** Every stored
credential goes through Windows DPAPI (`netpath/dpapi.py`), so SNMPv3
authentication, ConfigRX SSH backups, authenticated SMTP, the wireless
controller credential and the DHCP credential cannot be used here at all. That
is not a defect of the test rig; it is the shipped behaviour on the platform
the README documents for headless installs, and §4 records it as the single
largest structural finding in this report.

## 1. Verdict

**A genuinely well-built monitoring tool for a few hundred devices, and not yet
a fleet manager for two thousand.** I would deploy it on a 250–500 device site
tomorrow and be pleased with it. I would not buy it for the site described
without three things changing, and one of them is not a feature but a race.

Where the line actually falls, measured:

- **250 devices — comfortable.** Zero poll overruns across all nine incidents,
  a 143-device site outage correctly collapsed to five alerts, the interface
  responsive throughout.
- **1000 devices — works, but the alert rollup stops holding.** A 499-device
  outage produced 377 separate alerts and 1,355 emails in four minutes.
- **2000 devices — the outage is not detected.** Neither the tuned nor the
  shipped configuration opened a single device-down alert when a quarter of the
  site went dark. At shipped defaults it also sent **zero emails**, having spent
  its whole hourly budget in the first two minutes.

The polling engine is not the problem — at shipped defaults it idles at 2,000
devices with zero overruns. The problem is everything around it: one process,
one connection per database behind one lock, no remote pollers, and an alert
path whose correctness depends on winning a race against its own poll cycle.

**What would genuinely draw me to it.** The SNMP implementation is careful in
ways most products are not — `tooBig` halve-and-retry, v1 fallback, per-VLAN
community contexts, vendor-arc identification, all verified against fifteen
device personas. "Down" means ping *and* SNMP both failed, so a bad community
reads as misconfigured rather than dead. Every threshold has real hysteresis.
Permissions are airtight — 24 of 24 cross-module write attempts refused
cleanly, and not one control was shown to an account that could not use it. It
deploys as one Python process with no database server, no agent and no licence.
And it is honest: it counts kernel drops rather than reporting a comfortable
zero, raises an alert naming its own remedy when the pool saturates, and its
runbook states plainly that remote pollers do not exist.

**What would stop me buying it**, in order:

1. **It cannot tell me my site is down at 2,000 devices** (§3.3).
2. **There is no export of anything, from any screen** (§4). No CSV, no PDF, no
   scheduled report. For an audited site that is disqualifying on its own.
3. **Email is the only notification channel, and its default budget is 60 an
   hour** (§3.4). No webhook, no Slack, no PagerDuty, no ticketing.
4. **No maintenance windows.** Mutes are per-device, ad-hoc, capped at 24 hours,
   with no bulk operation — a weekend cutover is unmanageable.
5. **On Linux it cannot store a credential at all**, so ConfigRX backups,
   SNMPv3 polling and authenticated mail are unavailable on the platform the
   README documents for headless installs (§4).
6. **Local accounts only** — no LDAP/AD/SAML, no MFA, no API tokens.

**Recommendation: pilot, do not deploy.** Run it on one site of a few hundred
devices where its strengths are real and its ceilings are far away. Revisit for
the full fleet when §7's Tier 0 and the first four Tier 1 items land — most of
which are days of work rather than months, because the mechanisms already
exist in the code.

## 2. What eleven releases changed — the delta from 4.35.0

This is the section that justifies a second review, so it goes first.

Every finding the 4.35.0 review left in its **Deferred** list was re-checked
against 4.46.4 by searching for the *behaviour*, not by trusting its line
numbers. The result is blunt:

> **Of roughly fifty open findings, five are closed. Exactly one of those was
> closed by the eleven releases under review.**

**Closed by 4.40–4.46 (one):**

| ID | What it was | What closed it | Evidence at HEAD |
|---|---|---|---|
| X-F17 | `/api/state` fanned out across ten databases plus ~30 `stat()` calls, every 2 s, for every open tab | **4.43.0** | `netpath/web/api.py:211,290` — both hot paths now go through `service.cached_poll(..., 10, ...)` |

**Closed, but before the window — the old review's Deferred list was already
stale when it shipped (four):** `X-F16` (`netpath/monitor.py:381`), `X-F9`
(`alertengine.py:1126-1131`), the event-filtering half of `S-N10`
(`api.py:884-897`), and `G-26` (`ipam_scan.py:189`, whose fix commit landed
*nine minutes after* the review's own "mark deferred" commit). Worth knowing if
you are using that document as a to-do list: four of its open items were
already done.

**What 4.40–4.46 did deliver** is real, and it is almost entirely presentation
and wire efficiency:

- **Kiosk mode** (`/?kiosk=1`) with a session hold correctly restricted to
  accounts holding no write grant anywhere — MEASURED working, §4.
- **Three themes** (dark / light / high-contrast, the last held to WCAG AAA by
  `tests/test_design_tokens.py`) — MEASURED surviving reload, §4.
- **Responsive layout** at two breakpoints, and **touch/pen** support on every
  drag, plus keyboard-operable splitters — MEASURED clean, §4.
- **gzip + HTTP/1.1 keep-alive + content-hashed ETags** (4.43.0). This is the
  most valuable of the set for a large site and it is measurable: the device
  list that the old review reported as a 2.74 MB payload is still the same
  JSON, still unpaged — but now **19.5 KB on the wire at 250 devices**
  (MEASURED, §3.2). *The symptom improved by an order of magnitude; the defect
  did not change at all.*
- **Device "up since" / uptime**, IPAM worker startable from its own strip, and
  a refresh-rate control for every module (4.44.0).

**Still open at 4.46.4** — each TRACED at HEAD, and each one a thing a network
engineer asks for in the first week:

| Gap | Evidence at 4.46.4 |
|---|---|
| No CSV or any export, from any tab | zero hits for `text/csv`/`export.csv`/`to_csv` across `netpath/`; confirmed live (§4) |
| No bulk device import; one `POST` per device | `netpath/web/server.py:259`; MEASURED 17.9 devices/s at 250 |
| No maintenance windows; mute is device-only and capped at 24 h | `alertsdb.py:242` `MAX_MUTE_HOURS = 24.0`; `api.py:3577-3589` raises `"Only devices can be muted"` |
| No bulk mute | no route in `server.py:329-337`; confirmed live (§4) |
| Email is the only notification channel | zero hits for `webhook`/`slack`/`teams`/`pagerduty` across `netpath/` |
| No per-rule recipients, no escalation, no on-call | `alertsdb.py:29-64`; `alertengine.py:2139` reads one global recipient list |
| No un-acknowledge | `ack`/`ack-all`/`bulk-ack` routes exist, no `unack` |
| No L2 topology, no LLDP/CDP walk | zero `lldp`/`cdp` in `nodeoids.py`/`nodepoll.py`; `alertrules.py:256-259` says so in prose |
| No PoE, STP, ARP or BGP polling | same files |
| No SNMPv3 authPriv | `nodepoll.py:45` — the comment still reads "authPriv is not supported by this poller" |
| No per-device SNMP port | `nodepoll.py:1615,3233,3359,3378` hardcode `DEFAULT_SNMP_PORT` |
| No LDAP/AD/SAML/MFA, no API tokens, no per-site RBAC | zero `ldap`/`saml`/`tacacs`/`mfa`/`bearer` in `auth.py`, `permissions.py`, `server.py` |
| No ConfigRX diff | zero `difflib`/`unified_diff` in `configrx*.py` |
| No paging or virtualisation on the device list | `api.py:2106-2131` takes no `limit`/`offset`; no virtualisation in `nodes.js` |
| Sort still constructs a collator per comparison | `app.js:2839` |
| `busy_timeout`, `cache_size`, `mmap_size` still unset on every database | `nodesdb.py:554-556` sets only three pragmas |
| Ping is still one subprocess per probe | `ipam_scan.py:133-139` |
| Wireless is FortiGate-only and the UI never says so | `index.html:43` — the tab reads only `WIRELESS` |

The shape of the delta is therefore: **the product became markedly nicer to
look at and much lighter on the wire, and did not become more capable as a
fleet manager.** If you evaluated 4.35.0 and passed on it for a functional
reason, that reason is almost certainly still true.

## 3. Measured performance

Four full nine-step campaigns on the hardware named above. Each ran the same scripted
incidents: a baseline, a core switch plus its whole access layer dropped,
recovery, an interface flap storm, twenty reboots, five authentication
failures, a trap and syslog burst, a NetFlow burst, and a final recovery.

**Configuration matters more than any number below.** The harness tunes six
settings away from what the product ships so a twenty-minute run reaches states
that would otherwise take days. Runs 1–3 use that tuning (60 s poll interval,
32 workers). **Run 4 uses the shipped configuration** (120 s, 16 workers) and is
the only row a reader may compare against their own install.

### 3.1 Validity — is this the product or the harness?

The simulated fleet is a single-threaded loop serving up to 2,000 UDP sockets on
the same four cores as the application. If it were the bottleneck, the product
would look worse than it is. `demo/scenario.py` never measures it, so a separate
sampler recorded both processes plus per-socket receive-queue depth and drops
from `/proc/net/udp`.

| Tier | Fleet CPU (p95, of one core) | Datagrams dropped | Queue non-empty | Verdict |
|---|---|---|---|---|
| 250 | 28.6% | **0** | 2.1% | product |
| 1000 | 31.7% | **0** | 11.6% | product |
| 2000 tuned | 32.9% | **0** | 16.9% | product |
| 2000 shipped | 29.5% | **0** | 9.5% | product |

**Not one datagram was dropped in any run**, and the simulator never exceeded a
third of one core. Every number below is the application's.

One harness cost is worth naming because it is also a real product behaviour:
ICMP is one subprocess per probe (`ipam_scan.py:133-139`), which produced
**92–102 process creations per second** and a load average of 15 on four cores.
On a real install that is `fork`/`exec` per echo request, three per device per
poll — the harness exaggerates the cost, but not the design.

### 3.2 The scale ladder

| | 250 | 1000 | 2000 tuned | 2000 shipped |
|---|---|---|---|---|
| Baseline app CPU | 19.3% | 67.0% | 68.2% | 53.4% |
| **Baseline poll overruns** | **0** | **0** | **1,291** | **0** |
| Overruns, whole run | **0** | 4 | **17,648** | 1,764 |
| Nodes table fill (2,000 rows) | 204 ms | 955 ms | 1,127 ms | 876 ms |
| Device list, decoded | 359 KB | 1.44 MB | 2.86 MB | 2.86 MB |
| Device list, **on the wire** | 19.5 KB | — | **127.5 KB** | — |
| Longest long task | 264 ms | 805 ms | 1,899 ms | 2,218 ms |
| Worst scroll frame | 67 ms | — | 633 ms | — |
| `nodes.db` after ~22 min | 87 MB | 372 MB | 477 MB | — |
| Seeding rate | 17.9/s | 16.6/s | 13.1/s | 15.2/s |
| Emails, whole run | 1,671 | 3,780 | 3,323 | **60** |

At shipped defaults the poller **keeps up at idle even at 2,000 devices** — zero
baseline overruns, 53% of one core. That is a real improvement over the state
the 4.35.0 review measured, and it deserves saying.

### 3.3 What happens when the site goes down — the finding that matters

The same scripted outage at every tier: the core switch and its entire Site-A
access layer dropped simultaneously.

| Tier | Devices dropped | `Device not responding` alerts | Overruns in that step | Emails in that step |
|---|---|---|---|---|
| 250 | 143 | **5** | 0 | 162 |
| 1000 | 499 | **377** | 0 | 1,355 |
| 2000 tuned | 499 | **0** | 3,426 | 1,390 |
| **2000 shipped** | **499** | **0** | 1,362 | **0** |

Read that column downwards. It is three different failures, and only the first
is the one the product intends.

**At 250 the dependency rollup works, and works well.** 143 devices behind a
dead core produce five alerts. The engine walks the whole ancestor chain and
re-opens children correctly when the parent recovers. This is better than
several commercial products manage and it is the product's best idea.

**At 1000 the rollup loses a race.** 377 of 499 devices opened their own alert,
alongside 734 packet-loss, 376 memory and 281 CPU alerts — roughly 1,768 alerts
and **1,355 emails in 241 seconds**. Suppression only holds if the parent is
polled and marked down *before* its children; when the cycle stretches, the
children get there first. The 4.35.0 review's own follow-on list named this
("order `device_down` occurrences upstream-first within a tick") and it is
still open at 4.46.4.

**At 2000 the outage is not detected at all.** Neither configuration opened a
single `device_down` alert. The tuned run was already over capacity at idle
(1,291 baseline overruns); the shipped run idles cleanly and then produces
1,331 "poll taking longer than its interval" alerts and one "polling pool
saturated" when the site drops. Confirmed live on the running instance:
**5,854 cumulative overruns with 1,726 poll items queued against 32 workers.**

To its credit the product does not show a green screen — it says it is
drowning, and the saturation alert names its own remedy. But the operator sees
*"polling is slow"*, not *"a quarter of the site is dark"*, and those demand
different responses at 02:00.

### 3.4 The notification budget, at shipped defaults

`max_emails_per_hour` ships at 60. In run 4 the **entire hour's budget was spent
in the first two minutes** — 60 emails during the baseline step — after which
the outage, the flap storm, the reboots and the authentication failures
generated **zero emails between them**.

The alerts are all correctly recorded in the database. Nobody is told about
them. On a fleet this size the shipped cap is not a safety valve, it is a mute
button with a two-minute timer.

### 3.5 The alert console cannot list its own alerts

`GET /api/alerts` caps `limit` at 2,000 (`api.py:3529`). At 1000, 2000 and 2000
shipped, the campaign recorded `alerts_truncated` — the list was cut off. An
operator paging through an incident at fleet scale is looking at a truncated
view of it, at exactly the moment completeness matters.

### 3.6 Storage

Measured after ~22 minutes of the scripted campaign, against the shipped caps:

| Database | 250 | 1000 | 2000 | Default cap |
|---|---|---|---|---|
| `nodes.db` | 87 MB | 372 MB | 477 MB | 1,024 MB |
| `snmptraps.db` | **98.6 MB** | 98.6 MB | 98.6 MB | 256 MB |
| `syslog.db` | 27.7 MB | 28.1 MB | 27.8 MB | 1,024 MB |

Two things follow. A **75-second** trap burst wrote 98.6 MB — 38% of the trap
database's entire cap from one minute of traps; a genuine trap storm on a
2,000-device site would reach the cap in minutes and begin discarding history.
And `nodes.db` reached 477 MB in 22 minutes at 2,000 devices, so the 1 GB cap —
not the 3-day raw retention setting — is what will actually decide how much
history you keep. The settings page offers day counts; the size cap silently
wins.

## 4. Feature-by-feature results

Driven against the 250-device instance after it had lived through all nine
scripted incidents: 177 API calls plus a 30-step browser probe.
**86 pass, 5 partial, 1 fail, 2 blocked, 3 absent.**

### What works, and works well

| Area | Result |
|---|---|
| **Permissions** | **24 of 24 clean.** Every cross-module write attempt by the read-only `viewer` and the two-module `noc` account returned `403` with a readable message — no 500s, no stack traces, nothing unexpectedly permitted. The browser probe separately found **zero controls shown to an account that could not use them**. This is better than most commercial products manage. |
| **Alerting engine** | 35 built-in rules, 6 templates. Threshold edit, acknowledge and resolve all correct. Template preview works for a *read-only* account — deliberate and right, since previewing changes nothing. |
| **Dependency rollup** | Configured upstream links held: a 143-device site outage produced **5** `Device not responding` alerts, not 143 (§3.3). |
| **Bulk operations** | `bulk-identify` and `bulk-poll` across 50 devices returned accurate per-device dispositions (`queued`, `already_polling`, `missing`). |
| **Wireless** | Controller poll returned 12 APs / 24 radios; out-of-service toggle, AP delete and re-discovery on next poll all correct. |
| **Audit log** | Admin-only (`viewer` correctly refused), records credential and permission events, and **no secret material appears in it**. |
| **Themes / kiosk / layout** | All three themes survive a reload with no unstyled paint. Kiosk holds the session for a read-only account and **refuses an administrator** with the documented reason. Zero layout overflow across six widths × twelve tabs. |
| **Collectors** | v5/v9 NetFlow, trap storm and dual-framing syslog all ingested with **zero drops** at 250 devices. SNMP informs are acknowledged. |

### Defects found

**D1 — Prefix search silently returns nothing.** MEASURED on the live instance:

```
q=interface   -> 300 rows
q=inter       -> 300 rows     (substring matching already works)
q=interfac*   ->   0 rows
```

`syslogdb._fts_query()` quotes every term literally, so the `*` is matched as a
character. An operator who types the universal prefix convention gets an empty
result and concludes there is nothing to find — the worst failure mode a search
box has, because it looks like an answer. The underlying trigram index would
have matched; only the query builder stands in the way.

**D2 — A shipped MIB catalog entry cannot be installed.** The one-click catalog
install of `cisco-core` fails: the vendor file exceeds the hard size cap the
installer enforces. A curated catalog whose own entry is too large for its own
installer is a defect in the feature that most differentiates this product's
SNMP handling.

**D3 — The best feature in the product is off by default.** `mac_table_interval_s`
defaults to `0`, meaning off (`nodesdb.py:162-165`). Fleet-wide MAC-to-port
search — "which switch port is this device on", the single most common thing a
switch engineer does — therefore returns nothing on a fresh install, and
nothing in the first-run experience points at the setting. Turned on, it works
and it is excellent: **885 ms** from a cold dashboard to the answer (MEASURED).
Left as shipped, an evaluator never sees it.

### Absent — confirmed by probing, not by reading

- **No export of anything, anywhere.** No CSV, no clipboard, no print, from any
  of the twelve tabs. The only two downloads in the product are a debug text
  dump and a raw SNMP walk. Every table — devices, interfaces, alerts, flows,
  traps, syslog, IPAM hosts, DHCP leases, APs — is screen-only. For a regulated
  or audited site this alone is disqualifying.
- **No bulk mute.** Silencing a site for a maintenance window is one API call
  per device, and each mute expires after at most 24 hours.
- **No wireless radio history.** Radio state is current-value only, so "was this
  AP's channel utilisation climbing all week" cannot be asked.

### Blocked by platform, not by defect

Five credential-storing features refuse on any non-Windows host, each with an
explicit message rather than a silent failure. The exact text, captured live:

> `This machine cannot encrypt a stored credential — DPAPI is Windows-only.`

That covers SNMPv3 authentication, the SMTP password, ConfigRX SSH, the
wireless controller credential and the DHCP credential. The refusals are
honest and well-worded. The consequence is not: **on the Linux headless
install the README documents, ConfigRX can never complete a backup, SNMPv3
devices can never be polled, and authenticated mail can never be sent.** The
UI still renders every one of those forms.

## 5. Against the platforms it would be bought instead of

Rows chosen for the site described: 2,000 mixed devices, one plant, industrial
edge, a small team. ● present · ◐ partial · ○ absent.

| Capability | SappiWhere 4.46.4 | SolarWinds NPM | LibreNMS | Auvik | PRTG |
|---|---|---|---|---|---|
| SNMP v1/v2c polling correctness | ● (unusually good) | ● | ● | ● | ● |
| SNMPv3 authPriv | ○ `nodepoll.py:45` | ● | ● | ● | ● |
| L2 topology map (LLDP/CDP) | ○ | ● | ● | ● (its main selling point) | ◐ |
| Dependency-aware alert rollup | ● full ancestor chain | ● | ◐ | ● | ● |
| Maintenance windows / scheduled mute | ○ 24 h ad-hoc, device-only | ● | ● | ● | ● |
| Notification channels beyond email | ○ | ● | ● | ● | ● |
| Escalation / on-call rota | ○ | ● | ◐ | ● | ◐ |
| CSV / PDF / scheduled reports | ○ none at all | ● | ● | ● | ● |
| Config backup | ◐ Windows-host only | ● | ● | ● | ◐ |
| Config diff / golden config / push | ○ | ● | ● | ● | ○ |
| NetFlow / IPFIX | ● v5, v9, IPFIX | ● | ◐ | ○ | ● |
| sFlow | ○ | ● | ● | ○ | ● |
| Syslog + trap collection | ● | ● | ● | ◐ | ● |
| Event correlation across sources | ○ | ● | ◐ | ◐ | ◐ |
| Wireless: multi-vendor | ○ FortiGate only | ● | ● | ● | ● |
| PtP wireless link RF metrics | ○ | ◐ | ● | ○ | ◐ |
| Industrial protocol awareness | ○ port labels only | ◐ | ◐ | ○ | ● |
| LDAP / AD / SAML / MFA | ○ local accounts only | ● | ● | ● | ● |
| API tokens / service accounts | ○ session cookie only | ● | ● | ● | ● |
| Per-site / per-tenant RBAC | ○ per-module only | ● | ● | ● | ● |
| High availability / failover | ○ single process | ● | ● | ● (SaaS) | ● |
| Distributed / remote pollers | ○ `RUNBOOK.md:319` | ● | ● | ● | ● |
| Audit log | ● append-only | ● | ◐ | ● | ● |
| Dark mode / kiosk / NOC wall | ● best in this list | ◐ | ◐ | ◐ | ◐ |
| Deep-linkable URLs | ● | ◐ | ● | ◐ | ◐ |
| Deployment weight | ● one process, stdlib, ten files | ○ heavy | ◐ LAMP+RRD | ● SaaS | ◐ |
| Licensing | ● none | ○ per-element | ● free | ○ per-device | ○ per-sensor |

### Where it genuinely wins

**Deployment weight and honesty.** One Python process, no database server, no
web server, no agent, no licence. `python -m netpath --headless` and you are
monitoring. Against LibreNMS's PHP + MySQL + RRD stack or an NPM install, this
is a different category of effort, and for a plant with no dedicated monitoring
team that is worth a great deal.

**Alert semantics.** Hysteresis on every threshold (separate fire and clear
values plus a consecutive-sample requirement), "down" defined as *ping AND SNMP
both failing* so a bad community reads as misconfigured rather than dead, and
a rollup that walks the whole ancestor chain and correctly re-opens children
when the parent recovers. Several commercial products get the last one wrong.

**It tells you when it cannot cope.** The poller raises a saturation alert
naming its own remedy, counts per-socket kernel drops rather than reporting a
comfortable zero, and its documentation states its own limits — `RUNBOOK.md:319`
says plainly "There are no remote pollers in this release." That candour is
rare and it is worth money at 02:00.

**The interface.** Three themes, a real kiosk mode with a correctly-restricted
session hold, deep-linkable URLs you can paste into a ticket, keyboard-operable
splitters, and zero layout overflow from 1600 px down to 768 px — all verified,
not claimed. It is nicer to sit in front of than anything else in that table.

### Where it cannot compete

Not the polling — the **operations** around it. No export means no report to
management and no evidence for an audit. No maintenance window means a weekend
cutover is hundreds of clicks that expire after 24 hours anyway. No channel but
email means no integration with the ticketing system the site already runs. No
directory authentication means an engineer who leaves must be removed here by
hand. No L2 topology means the one question a switch fleet is bought to answer
— *what is plugged into what* — is answered by a traceroute hop graph instead.

## 6. Coverage by device class — for this fleet specifically

The simulated fleet mirrors the site described. At 2,000 devices it contains
1,105 Cisco access switches, 159 Aruba, 100 FortiGate, 59 Palo Alto, 59
Juniper, **99 Ubiquiti airFiber + 59 Cambium PTP point-to-point bridges**,
**80 Siemens SCALANCE + 60 Moxa industrial switches**, **59 Rockwell + 39
Siemens S7 PLCs**, 79 MikroTik, 40 Linux hosts, one core and one wireless
controller. All 623 wire-format checks pass against every one of those
personas, so everything below is a question of *what the product asks for*,
not whether the device answers.

| Class | What you get | What is missing | Verdict |
|---|---|---|---|
| **Access switches** (1,105) | Interface counters, errors, discards, utilisation, status, uptime, vendor identification, per-port MAC/FDB (once enabled), DOM/SFP optics | PoE budget and per-port power — the single most-asked question on an access layer with APs and cameras on it. No STP state, so a loop or a topology change is invisible | **Good**, with a PoE-shaped hole |
| **Wireless controller + APs** | Per-AP status, client count, model, per-radio channel/mode/power, real per-AP ICMP RTT, ageing with an out-of-service exemption | FortiGate only, and the UI never says so (`index.html:43`). No SSID entity, no client list, no rogue detection, no RF utilisation, **no history at all** — radios are current-value only | **Adequate if you are a Fortinet site, unusable otherwise** |
| **PtP wireless bridges** (158) | Interface counters. That is all | RSSI, SNR, modulation, link capacity, remote-end RSSI — every metric that makes a radio link *predictable*. A degrading link is visible days ahead in its SNR and not at all in its interface counters | **Effectively unmonitored.** The class where degradation is most predictable is the class with the least visibility |
| **Industrial switches** (140) | Standard IF-MIB, and a genuinely good Moxa MIB bundle in the catalog (~25 MIBs incl. TurboRing, TurboChain, Dual-Homing, PoE-BT) | Nothing walks ring state on a schedule. **Hirschmann is trap-arc-recognised only** — no MIB bundle, so no HIPER-Ring or MRP objects. **Siemens SCALANCE: nothing at all**, despite 80 of them in the fleet | **Moxa good, Hirschmann thin, SCALANCE absent** |
| **PLCs** (98) | ICMP reachability, and SNMP interface counters where the PLC exposes them | No OPC-UA, no S7comm, no Modbus, no EtherNet/IP or CIP. No tag or register reading, no PLC run/stop state, no fault-word. Port numbers are *labelled* in NetFlow (`services.py`: 502 Modbus, 44818 EtherNet/IP, 102 ISO-TSAP, 34962-4 PROFINET) — labels, not monitoring | **Reachability only.** You will know a PLC stopped answering ping; you will not know it faulted |
| **Firewalls** | Interface counters, and vendor health OIDs for FortiGate CPU/memory | Session counts, VPN tunnel state, HA state | **Basic** |

Two things deserve specific credit for an OT network, because they show
somebody thought about it:

- IPAM scanning is **rate-limited to 200/s deliberately**, with the comment
  explaining that faster sweeps "knocked over legacy PLC and RTU stacks"
  (`ipam_scan.py:238`).
- The focus-poll — which raises a single device to a 3-second cadence — is
  gated as a **write** permission specifically because the target "may be a
  PLC" (`server.py:270`), and a read-only account is correctly refused
  (MEASURED, §4).

That care is real and unusual. It is also the whole of the industrial story:
the product is careful *not to break* OT devices, and has no way to *monitor*
them beyond reachability.

## 7. Recommendations, ranked

Ranked by operator time saved per incident against the effort to build, from
the position of someone who would have to run this. **S** ≈ days, **M** ≈ a
week or two, **L** ≈ a project.

### Tier 0 — before anyone runs this on a real fleet

1. **Turn the MAC table on by default, or ask on first run.** `nodesdb.py:162`.
   The best feature in the product is invisible out of the box. One default. **S**
2. **Fix prefix search.** `syslogdb._fts_query()` quotes `*` literally, so the
   universal convention returns zero rows on a corpus that would have matched.
   A search box that answers "nothing" when it means "I did not understand you"
   costs an engineer an hour before they stop trusting it. **S**
3. **Fix the MIB catalog size cap** so a shipped catalog entry can actually be
   installed. **S**
4. **Say "FortiGate" on the Wireless tab.** `index.html:43`. A one-word change
   that stops an evaluator concluding the product is broken for their Aruba
   estate. **S**
5. **Set `busy_timeout` on every database.** `nodesdb.py:554-556`. Ten SQLite
   files, one connection each behind one lock, and no busy timeout anywhere;
   the failure mode under contention is an exception rather than a wait. **S**

### Tier 1 — what makes it a fleet tool rather than a device tool

| # | Change | Why it is worth the most | Effort |
|---|---|---|---|
| 1 | **Export.** `GET /api/<module>/export.csv` honouring the current filter, on every table | Unblocks reporting, audit evidence, capacity work and post-incident review in one move. It is the single most-missed feature in the product and the cheapest of the big ones | **M** |
| 2 | **Maintenance windows**, plus bulk mute and mute of a group or site | A planned weekend cutover is currently hundreds of API calls that expire after 24 h. This is the difference between an alerting system people trust and one they mute permanently | **M** |
| 3 | **One outbound webhook channel** (URL, headers, JSON body through the existing template engine) | ~40 lines of `urllib` buys Slack, Teams, PagerDuty and every ticketing system at once, and ends the shared-inbox failure mode | **M** |
| 4 | **Bulk device import** (CSV, or a bulk POST) | Onboarding 2,000 devices is 2,000 API calls at a MEASURED 16.6/s. A site becomes a spreadsheet paste instead of a two-minute script | **S/M** |
| 5 | **LLDP/CDP neighbour walk and an L2 map** — both MIBs already ship | Answers "what is plugged into what" without a console session, and feeds a real topology instead of manually-set upstream links | **L** |
| 6 | **Server-side paging on the device list** | `api.py:2106-2131` still returns the whole fleet. gzip hid the symptom; the query, the serialisation and the DOM cost are all still linear | **M** |
| 7 | **PoE and STP polling** | The two things an access-layer engineer asks that the product cannot answer today | **M** |
| 8 | **PtP link RF metrics** (RSSI, SNR, modulation, capacity) for airFiber / Cambium | The one device class where failure is predictable days ahead, currently monitored only by interface counters | **M** |
| 9 | **A portable secret store** behind the existing `protect`/`unprotect` interface | Unlocks five features on the platform the README documents for headless installs. Today a Linux deployment cannot back up a config or poll SNMPv3 at all | **L** |
| 10 | **Directory auth and API tokens** | Procurement gates on this at any regulated site, and automation currently has to hold a human password against a 10-minute idle timeout | **L** |

### Tier 2 — worth doing, cheap

- Hoist one `Intl.Collator` in `app.js:2839` — a one-line change to a sort that
  currently builds a collator per comparison.
- Batch ICMP (`fping`-style or a raw socket) instead of one subprocess per
  probe (`ipam_scan.py:133-139`); MEASURED at 88–134 forks/s and a load average
  of 15 on four cores at 1,000 devices.
- Un-acknowledge. Acknowledging is currently irreversible.
- A ConfigRX diff between adjacent backups — the hashes that detect the change
  are already stored.
- Raise or explain the trap database cap: a 75-second trap burst wrote
  **98.6 MB**, 38% of the 256 MB default, at only 250 devices (MEASURED).

## 8. Limits of this evaluation, and what I got wrong

Stated so the numbers can be discounted where they deserve to be.

- **Everything is loopback.** The devices are UDP sockets, not machines, so
  round-trip time is essentially zero and real WAN figures will be worse. The
  poll-cycle arithmetic in §3.3 gets *harder* with real latency, not easier.
- **The trap, syslog and NetFlow bursts are 60–75 seconds**, not sustained
  load. The storage extrapolation in §3.6 is arithmetic from a short burst.
- **Two thresholds fire on simulated data, not product behaviour.** The
  personas report high memory, so `mem_high` opened several hundred alerts at
  shipped defaults. That is the fleet generator's characteristic and I have not
  treated it as a finding.
- **Windows was not tested.** Every credential feature is Windows-only, so the
  five blocked features in §4 are *reported as blocked on this platform*, not
  as broken. On a Windows host they may work exactly as documented.
- **I did not test upgrade-in-place** beyond the shipped suite, which pins a
  release thirteen versions behind the current one.

**Two things this evaluation got wrong and corrected:**

1. I first recorded SNMP informs as unacknowledged. That was my own error — I
   had restarted the application, and the counters are in memory. Sending
   informs against a running instance moved `informs_acked` from 0 to 1.
   **Informs work.**
2. My browser probe reported that the device table "never rendered a row within
   180 s" at 2,000 devices. Two independent measurements contradict it — a
   direct API call returns in 174–874 ms, and the repository's own walk fills
   2,000 rows in 1,127 ms — so the probe was at fault and the claim is
   withdrawn rather than reported.

Both are recorded because a review that hides its own corrections is asking to
be trusted on everything else it did not check.

## Appendix — reproducing this

```bash
python3 tests/run_all.py                 # 31 suites; needs traceroute installed
python3 demo/selftest.py                 # 623 wire-format checks, all personas
python3 demo/scenario.py --count 250  --out demo/out/250     --topology
python3 demo/scenario.py --count 1000 --out demo/out/1000    --topology
python3 demo/scenario.py --count 2000 --out demo/out/2000    --topology
python3 demo/scenario.py --count 2000 --out demo/out/2000def --topology --defaults
```

Use a **separate `--out` per run**: `demo/scenario.py` suffixes only the data
directory and the two results files with the device count, so two runs at the
same count into one directory overwrite each other's logs, screenshots and
`creds.txt`.

Each run writes `results-<n>.json`/`.md`. The contention control described in
§3.1 is not part of the shipped harness and was added for this evaluation.
