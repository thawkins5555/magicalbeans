# SappiWhere 4.49.0 — a plant network engineer's evaluation

*This document is being written as the campaign runs. Sections marked ⏳ are not
finished. Nothing below is a placeholder for a number that was never measured — a
figure appears here only once something produced it.*

Reviewed from commit `51ebbe8` (4.48.0) on 2026-09-04, on the branch
`claude/operator-demo-4-49-0`, from the seat of the person who would have to live
with this software: a network engineer responsible for one large plant site of
roughly 2,000 endpoints — access switches, industrial switches, access points,
point-to-point wireless bridges, PLCs and UOCs, PCs, printers, tablets, servers,
UPSs and Room Alert environmental units — who already runs an enterprise monitoring
platform and is deciding whether this one would replace it.

The question throughout is not "is the code correct". It is: **would this make my
job faster, does it survive my site, and what would make me choose it?**

Two earlier evaluations exist and are not repeated here. `REVIEW-NETWORK-ENGINEER.md`
(4.35.0) looked at the poller, the collectors and the alert engine; `UI-UX-REVIEW-4.48.md`
(4.47.0) looked at the interface. Their fixes shipped as 4.39.0, 4.47.0 and 4.48.0.
What neither did was drive the product against the estate this operator actually
has, at the scale they actually run, on the platform they actually run it on.

## Convention

Every finding carries a `file:line` and one of two tags:

- **CONFIRMED** — the behaviour was produced by running code, or the finding is an
  *absence* and that absence was established by exhaustive search. A CONFIRMED row
  says what was run or searched.
- **PLAUSIBLE** — traced in the source and reasoned about, never executed. The
  mechanism is real; the consequence is an inference. Each such row says why it
  could not be executed.

Identifiers are prefixed by section, because the last review's first draft reused
`B1`/`S1`/`N1` across sections and its own cross-references became ambiguous.

---

## 1. Verdict

⏳ Written last, from the evidence.

---

## 2. How this was run

### 2.1 The platform

Windows 11 Home 10.0.26200, 28 logical cores, 15.7 GB RAM. Python 3.12.4 (reachable
as `py`; `python` and `python3` are not on PATH). Node 24.19.0 with Playwright
1.56.1 installed globally. paramiko 4.0.0 present, so the two SSH suites that skip
in CI ran here.

This matters more than it looks. The product's own documentation, its demo harness
and its CI all treat Linux as the reference platform, and **the harness could not
run on Windows at all** until this campaign fixed it. Section 3 records what had to
change, because "can a Windows shop evaluate this product" is itself an answer.

### 2.2 The simulated estate

⏳ Persona mix, per tier.

### 2.3 The tiers

| Tier | Devices | What it was for |
| --- | --- | --- |
| A | 250 | Every feature, every incident, the full UI matrix |
| B | 1,000 | Performance only |
| C | 2,000 | Performance only — the operator's real scale |

---

## 3. What had to change before the product could be evaluated on Windows

⏳ In progress. Established so far:

**W-1 — `netpath/ipam_scan.py` resolves `ping` differently from `netpath/tracer.py`,
and only one of them honours PATH. CONFIRMED.** `tracer.py:436` calls
`shutil.which("ping")`; `ipam_scan.py:121-124` returns a bare `["ping", "-n", "1",
"-w", str(timeout_ms), ip]`. On Windows `CreateProcess` appends only `.exe` to an
extensionless name and does not consult `PATHEXT`, so a bare `"ping"` reaches
`C:\WINDOWS\system32\ping.EXE` no matter what is earlier on PATH — verified by
putting a directory containing `npm.cmd` first on PATH and observing
`subprocess.run(['npm','--version'])` raise `FileNotFoundError [WinError 2]`.

This is not a harness detail. `nodepoll.py:1349` computes
`reachable = snmp_ok or (unreachable_ping_only and ping_ok)`, and the shipped
defaults are `ping_enabled = 1` (`nodesdb.py:40`) with `unreachable_ping_only = True`
(`nodesdb.py:414`). Windows answers `ping 127.0.0.2` with `Reply from 127.0.0.2 …
TTL=128` even with nothing bound to that address at all. So on Windows, against any
loopback-simulated fleet, **a device that has stopped answering SNMP entirely still
reads as reachable** — and the outage detection the whole product exists for is
silently disabled. Two callers of the same binary resolving it two different ways is
the root cause.

**W-2 — the demo harness's ICMP substitutes cannot execute on Windows. CONFIRMED.**
`demo/bin/ping` and `demo/bin/traceroute` are extensionless Python scripts with
`#!/usr/bin/env python3`. `shutil.which('ping')` on Windows *does* return the
extensionless file, and executing it raises `OSError [WinError 193] not a valid
Win32 application` — so putting `demo/bin` on PATH under Windows is worse than
leaving it off: it breaks `tracer.ping()` outright rather than falling through.
On top of that the app asks for `tracert`, not `traceroute` (`tracer.py:214`), and
the shims speak Linux argv and print fractional `time=1.234 ms` where the Windows
parser `_WIN_PING_TIME` (`tracer.py:420`) matches integer milliseconds only.

**W-3 — the fleet simulator dies above 512 devices on Windows. CONFIRMED.**
`demo/fleet.py` registered every device socket on one `selectors.DefaultSelector`,
which on Windows is `SelectSelector`, hard-capped at `FD_SETSIZE` = 512. Measured on
this machine: 512 descriptors select fine at 0.08 ms per call; 513 raises
`ValueError: too many file descriptors in select()`. The failure mode is the nasty
one — every socket *binds* successfully and the process dies on the first
`serve_forever()` iteration, so a 2,000-device run looks like it started.

**W-4 — `SO_REUSEADDR` lets a second fleet silently steal a bound address on
Windows. CONFIRMED.** Two processes binding `127.0.0.2:161` both succeed, with no
error anywhere, and delivery becomes indeterminate.

**W-5 — the campaign conductor measures no CPU and no memory on Windows.
CONFIRMED.** `demo/scenario.py:135-145` reads `/proc/<pid>/stat` and `/status`,
catches `OSError`, returns `{}`; every CPU% and RSS column in the results is blank —
which are precisely the numbers a scale campaign exists to produce.

All five are now fixed, and verified independently of the person who fixed them:

- The fleet binds 2,000 devices in **0.85 s** across five shards, with devices at
  `127.0.0.2`, `127.0.1.100`, `127.0.3.50` and `127.0.7.200` — four different shards —
  all answering a real SNMPv1 GET decoded by the application's own codec. The fleet
  process sits at **8.8 MB RSS and 0.02 s CPU** while idle.
- `SO_EXCLUSIVEADDRUSE` now fails a duplicate bind loudly. That was demonstrated by
  accident during verification: a 2,000-device run refused 25 sockets because another
  process already held `127.0.0.2`–`127.0.0.26`, and said so, where the old code would
  have bound them silently and delivered packets to whichever process the OS preferred.
- With `demo/bin` first on PATH, `shutil.which` returns `ping.CMD` / `tracert.CMD` /
  `traceroute.CMD`. Driven through the product's own parsers rather than by eye:
  `tracer.run_trace('10.0.0.1', 12, 3, 1.0)` returns `reached=True` with four hops,
  three probes each and RTTs of 1.0 / 3.0 / 5–6 / 7.0 ms; `ipam_scan.ping_many` returns
  `(3, 3, 7.33)` for a reachable address and `(3, 0, None)` for an unreachable one. The
  outage path is alive on Windows for the first time.
- `read_proc` returns a real RSS (21.5 MB for a fresh interpreter) and `cpu_percent`
  reads **100.0** across a one-second busy loop and **0.0** across a one-second sleep.

**W-6 — a Windows deployment finding that came out of fixing W-1, and is about the
product rather than the harness. CONFIRMED (measured).**
`netpath/ipam_scan._icmp_socket_kind()` returns `None` on Windows — verified by
calling it — so `ping_many()` always takes the subprocess path. The shipped defaults
are `ping_enabled = 1`, `ping_interval_s = 0` (ping on *every* poll,
`nodesdb.py:423`) and `ping_count = 3`. At 2,000 devices on a 60-second interval that
is **6,000 process creations a minute, 100 a second, sustained**.

Measured here, `ping_many(ip, 3, 1000)` took 239 ms and 227 ms per device against the
harness's Python shim; the shim pays interpreter startup three times, so the honest
figure for real gear is a real `ping.exe` at around 6 ms plus process creation — call
it 20–25 ms per device per poll, or roughly 40 seconds of pure `CreateProcess` work in
every 60-second window, on the same box that has to run the poller. On Linux the
datagram-socket path avoids all of it.

This is not a bug: the code explains the fallback and the subprocess path is
deliberate. It is a real, measurable Windows deployment cost that nothing in the
product tells the operator about, and the two settings that mitigate it —
`ping_interval_s` and `ping_enabled` — are ones nobody would know to reach for. At
minimum the Dashboard's poll-pool tile should say when ping is the reason the pool is
saturated.

---

## 4. What this product does that would make an operator want it

A review that only lists absences is not much use for deciding anything, and there is
a real answer to "why would I look at this instead of what I already run".

**It is one process and ten files, and you can read all of it.** No agent to deploy, no
message bus, no time-series database to operate, no Java. `pip install -r
requirements.txt` and `py -m netpath --headless --port 8443`, and it is running. For a
plant with one network engineer and no platform team, that is not a small thing — it is
the difference between a tool you own and a tool that owns you. The ten SQLite files
sit next to each other and `BACKUP-RESTORE.md` tells you what each is for.

**The SNMP implementation is unusually careful, and it shows in the places that
normally hurt.** It prefers `ifXTable`'s 64-bit counters and explains why in the code
— a 32-bit `ifInOctets` wraps in under 35 seconds at gigabit line rate. It matches
request and response ids. It halves and retries a GETBULK that comes back `tooBig`. It
falls back from GETBULK to GETNEXT for a v1-only device. It caches which of a
profile's alternate credentials last worked for a given device so a mixed-vendor
subnet does not cost extra requests every poll. Those are the five things that make
polling real gear either work or not, and someone has clearly been bitten by all five.

**The alert state model is right.** Severity on the syslog 0–7 scale shared across
every module, so a trap, a syslog message and a threshold breach are comparable.
Hysteresis as a separate clear threshold rather than the same number. `for_polls` and
`for_seconds` so a breach must persist. `renotify_minutes` for "still happening".
Rollup so a device that is down does not also alert about its CPU, its memory and
every one of its interfaces. And rules that ship deliberately hard to trip, with the
reasoning written down beside them — the NetPath unreachable rule's comment about why
it clears at 100% rather than 50% is the kind of thing you normally only learn by
being paged at 3 a.m. for a month.

**The comments are the documentation, and they are honest.** Nearly every non-obvious
decision in this codebase carries a paragraph explaining the failure that motivated
it, including the ones the authors decided *not* to fix and why —
`alertrules.py:250-266` on why LLDP neighbours do not drive suppression is the best
example, and it is a better piece of engineering writing than most vendors' release
notes. An operator can find out why something behaves as it does without opening a
support case.

**It takes the wall display seriously.** Kiosk mode with a rotation, a session
countdown so a wallboard does not silently become a sign-in page overnight, three
themes including a high-contrast one, and a layout that works from 320px to 1920px.
Control rooms have screens on walls and tablets on trolleys, and most monitoring
products treat both as an afterthought.

**Credential handling is documented to a standard most products do not attempt.**
`CREDENTIAL-SECURITY.md` states, per credential, how it is protected and what happens
when the platform store is unavailable — and the code refuses to store a secret it
cannot protect rather than storing it badly. Refusing is the right answer and it is
rare.

**The collectors decode properly rather than approximately.** NetFlow v5/v9 with real
template handling, SNMP traps and informs with varbind decoding against an uploadable
MIB catalog, syslog over UDP and TCP with both framings. These are the parts that
usually turn out to be a regex over the first eighty characters.

---

## 5. Findings

### 5.1 The estate it cannot see

⏳ In progress. Established by exhaustive search of `netpath/`:

| Device class | What the poller reads | What the operator gets |
| --- | --- | --- |
| UPS | nothing under `1.3.6.1.2.1.33` | sysDescr, uptime, one interface, ping. No battery, no runtime, no load, no input voltage. UPS *traps* are decoded (`trapoids.py:58-62`) and the APC/Eaton/Vertiv arcs are named (`enterprises.py:44-46,84`), so a UPS can shout but is never asked how it is. |
| Printer | nothing under `1.3.6.1.2.1.43` | sysDescr and an interface. No toner, no page count, no "out of paper". |
| Environmental (Room Alert) | ENTITY-SENSOR-MIB is decoded only by `nodepoll.read_dom` (~2827), on demand, for one interface, and only for entities `entAliasMappingIdentifier` maps to an ifIndex (~2843-2851) | nothing. A sensor that maps to no port returns `[]` and the dialog says there are none. `temp_c` today comes from the Juniper `jnxOperatingTable` alone. |
| Windows PC / server | `hrProcessorLoad` averaged, `hrStorageFixedDisk` rows | CPU yes, disk yes, **memory no** — `mem_pct` comes only from UCD-SNMP, a Fortinet scalar or the Cisco memory pool. |
| Tablet | — | a tablet runs no SNMP agent; it is only ever a MAC in a forwarding table or a DHCP lease, and there is **no OUI or MAC-vendor lookup anywhere in `netpath/`**, so it is anonymous. |

### 5.2 The navigation bar

⏳

### 5.3 The shape of the estate

**O-8 — a device can be in exactly one group, and there is no site, no location, no
role and no tag. CONFIRMED (schema, exhaustive).** `netpath/nodesdb.py:84-90`: a
device has `group_id` (its polling profile) and `device_group_id` (one organisational
group, single-valued, nullable). Grepping `nodesdb.py` for "site" returns three
comments and no column.

A plant is not one flat list. A switch is in Building 4, *and* on the access layer,
*and* behind No. 2 paper machine, *and* production-critical. Today you pick one of
those to be its group and lose the other three. Everything downstream inherits the
limit — the device filter, the maintenance-window scope, alert routing, the
Dashboard, and per-module permissions that cannot be narrowed to a site.

The smallest honest fix is free-form tags in a many-to-many table, offered as a filter
everywhere the group filter already appears and accepted as a scope everywhere a group
is accepted. That single change makes maintenance windows, alert routing and saved
views workable without any of them growing a scope model of its own.

**O-9 — maintenance windows mute devices, and a plant does not shut down a device.
CONFIRMED.** `netpath/alertsdb.py:301-313`: scope is a group or an explicit list of
device ids. There is no way to say "during this window suppress `interface_down` and
`interface_flapping`, but still tell me if the device itself dies" — which is exactly
what a cutover needs, because you are pulling cables, you expect ports to bounce, and
you very much still want to know if you have killed the switch. Nor can a window cover
an interface, a NetPath destination or a DHCP scope. `MAX_MUTE_HOURS = 24` and the
60-hour occurrence cap are sensible and well argued; the scope model underneath them
is not rich enough to use.

### 5.4 Finding things

**O-1 — global search drops every group after the first failure. CONFIRMED (source,
exhaustive).** `netpath/web/static/app.js:1876-1932`. One `try` wraps all four lookups
— MAC, devices, alerts, NetPath destinations — and the single `catch` at the end
carries the comment "a failed lookup just leaves that group out". It does not: an
exception in the devices lookup skips alerts and NetPath entirely. The comment states
the intended behaviour and the structure does not implement it. Per-group `try`/`catch`
is the fix.

**O-2 — global search cannot reach half the product. CONFIRMED (exhaustive read of
`gsearchRun`).** It covers MAC addresses, devices, alerts and NetPath destinations. It
does not cover IPAM hosts or subnets, syslog messages, SNMP traps, stored ConfigRX
configurations, wireless access points, or interfaces by description or alias. The two
absences that hurt most on a plant are the interface alias — which is how an engineer
finds "the port that feeds press 3" — and the stored configuration text.

**O-3 — device search matches three columns and scans the table. CONFIRMED.**
`netpath/nodesdb.py:1186-1193`: `ip LIKE %q% OR name LIKE %q% OR sys_name LIKE %q%`.
Leading wildcards defeat every index, so each keystroke is a full scan of `devices`.

The part that makes this worth fixing rather than merely worth noting: **the columns
are already there.** `devices` stores `sys_descr`, `sys_location` and `sys_contact`,
refreshed by every successful poll (`nodesdb.py:104-109`), and `interfaces` stores
`alias` — the ifAlias, the description an engineer typed on the port itself
(`nodesdb.py:134`). On a plant, `sysLocation` is how you find "Building 4 MCC" and
`ifAlias` is how you find "press-3-feed". Both are polled, both are stored, and
neither is searchable. Adding them to the `WHERE` clause is a few lines; making the
search indexed rather than a triple leading-wildcard scan is the larger half.

What is genuinely absent from the schema, as opposed to merely unsearched, is a
free-text note per device (`nodesdb.py:84-123` has no `notes`, no serial, no asset
tag, no criticality). On a plant the note an operator most wants to attach is "do not
reboot during a run" and there is nowhere to put it.

**O-5 — ConfigRX stores two thousand configurations and gives you no way to ask a
question of them. CONFIRMED (exhaustive search of `configrx*.py` and the API).**
`netpath/configrx.py` captures a running configuration per vendor over SSH, and
`diff_texts` (line 570) compares two backups *of the same device*. There is no search
across the stored corpus and no compliance check of any kind — grepping `netpath/` for
compliance, golden or baseline returns nothing.

For a plant this is the daily question, and it cannot be asked: *which of my switches
does not have the right NTP server, the right SNMP community, port security on the
access ports, the right VLAN on the spare port?* The data is already captured and
already stored. Two features, in value order: search across the stored configurations,
which is a scan of a table the product already fills; and named compliance rule sets of
must-match and must-not-match patterns, with a pass/fail column on the ConfigRX list
and an alert rule for a device that falls out of compliance. This is the difference
between a backup tool and a configuration management tool, and it is the most common
reason an operator keeps paying for a second product.

### 5.5 Being told about it

**O-4 — the rollup that stops a site outage becoming three hundred alerts depends on a
field you must set by hand, two thousand times, and the data to propose it is already
collected and unused. CONFIRMED.**

`netpath/alertrules.py:250-266` explains, at length and honestly, why LLDP/CDP
neighbours are *not* used to drive suppression: the neighbour-to-device match is a
suggestion rather than a fact, a neighbour row can go stale between walks, and
suppressing a real port fault on a wrong guess is the one failure an alert system must
never have. It concludes that suppression should be driven only by `upstream_id`,
which an operator sets deliberately. **That reasoning is right.**

What is missing is the means. `nodesdb.all_neighbours()` and `neighbours_of()` already
hold the collected neighbours with the product's own best-effort device match;
`post_nodes_devices_bulk_update` already exists; and there is no route, no screen and
no action anywhere that offers those matches to an operator to review and accept —
grepped `api.py`, `nodesdb.py` and `nodes.js` for suggest, adopt and promote-upstream,
and found nothing. So the only path to a working rollup is two thousand manual edits,
one device at a time, through the Edit dialog.

The demo harness makes the point by accident: `demo/seed.py --topology` sets
`upstream_id` for every Site-A device in one pass, because a scripted campaign cannot
afford to do it by hand either.

**O-14 — discovery sweeps a subnet you name, and cannot follow the network it has
already mapped. CONFIRMED (`netpath/nodediscover.py`, exhaustive).** `_run` (line 138)
takes one `target` — a CIDR expanded by `usable_addresses` up to
`max_scan_addresses` (default 1024, settable) or a single address — and sweeps it.
That is the only discovery mode, and the module docstring (line 7) states that a sweep
is deliberately "a one-shot bounded task, not a recurring per-target" one.

Three consequences at 2,000 devices. Onboarding is one sweep per subnet, by hand,
across a plant's patchwork of VLANs, with no multi-range job and no import of ranges.
Nothing runs on a schedule, so a switch a contractor installed on Tuesday stays
invisible until somebody thinks to sweep for it. And the product already knows the
topology and will not walk it: LLDP and CDP neighbours are collected into the
`neighbors` table, and a seed crawl — start at the core switch, follow neighbours
outward, list every device reached that is not already monitored — needs no new data
and reads the same table O-4 needs. The two features share a query and should be built
together.

**O-6 — every alert email goes to the same list. CONFIRMED (schema and settings,
exhaustive).** `netpath/alertsdb.py:31-62` is the `rules` table. A rule has `notify` —
mail it or do not — and `device_filter`, and nothing else about who hears it. The only
recipient setting is `smtp_to_default` (line 177), one global list; the one webhook
(`alertmail.send_webhook`, line 614) is global too.

On a plant that is unusable. The electricians want the UPS and environmental alerts,
IT wants the switches, the process engineers want the PLCs and the industrial
switches, and the night shift wants critical only. Today they all get everything, or
the rule is off for everyone. The first thing every operator does about that is write
a mail rule, and the second is stop reading the mail. The parts to fix it exist:
per-rule recipients defaulting to `smtp_to_default` so nothing changes on upgrade, and
a severity floor per destination. `device_filter` already shows the shape a
rule-scoped setting takes here.

**O-7 — a rule can be notified or silent, and nothing in between. CONFIRMED.** No
escalation when nobody acknowledges, no on-call rota, no ticket or runbook link on a
rule, no per-recipient digest. `renotify_minutes` exists, so the product already
understands "still happening" — it simply has nowhere else to send it.

### 5.6 Answering for it afterwards

**O-10 — the audit trail is written, is served, and cannot be seen. CONFIRMED
(exhaustive).** `netpath/appdb.py:107-116` defines the `audit` table, whose own comment
says it exists "for answering 'who changed that' a month later".
`netpath/web/api.py:1366` serves it as `get_audit`, wired at `server.py:492` to
`GET /api/audit` behind `admin: read`. Grepping `netpath/web/static/*.js` for "audit"
returns nothing — no page, no tab, no dialog, no link. The one feature whose entire
purpose is to be read by a person is the one feature no person can reach. A Settings
subtab over a route that already exists is a small piece of work.

**O-11 — the audit trail records the administration of the product and almost none of
the engineering done with it. CONFIRMED.** Fifty-two `_audit(...)` call sites,
twenty-six distinct actions, covering accounts, tokens, passwords, LDAP, credentials,
settings, self-update and the whole alert workflow. Not audited: adding, editing or
deleting a **device**; bulk import; device-group and polling-profile changes; MIB
upload; creating, editing, disabling or deleting an **alert rule**, including changing
its threshold; adding or removing a **NetPath destination**; IPAM subnet changes;
ConfigRX backup and restore.

So "who muted that alert" is answerable and "who changed the CPU threshold from 90 to
99 last March" is not — and the second is the one an outage post-mortem actually asks.
On a site under an ISO, food-safety or pharmaceutical regime that is a compliance
blocker rather than a nicety. The mechanism is already there: `_audit` is one line per
handler.

### 5.7 Showing somebody else

**O-12 — the data for a report is kept for four hundred days and there is no report.
CONFIRMED.** `netpath/nodesdb.py:427-437` keeps three days of raw samples and **400
days of hourly rollups**, deliberately and well argued; `compact_rollup` (line 2382)
fills them and `series()` (2330) reads them for a wide window. The product therefore
holds a year of every metric on every interface on every device.

Nothing turns that into an answer. `top_metric` (2309) exists for the Dashboard's own
tiles. `availability()` (`netpath/analysis.py`, called at `api.py:495`) computes
availability for a NetPath traceroute destination only — there is no device or
interface availability figure anywhere. Grepping `api.py` for a report handler returns
nothing: no MTTR, no SLA, no month-end summary, nothing scheduled, nothing exportable.

The two reports an operator is asked for by name every month are "what was the
availability of these thirty devices" and "which twenty links came closest to
saturation". Both are a `GROUP BY` away from data already on disk. This is the cheapest
large win in the product.

### 5.8 Performance and scale

⏳ The tier numbers land here.

**O-13 — every one of the twelve modules is downloaded, parsed and compiled before the
Dashboard paints. CONFIRMED (`index.html:1335-1347`, byte counts measured).** Thirteen
`<script defer>` tags load `app.js` and every module unconditionally. Measured:
`nodes.js` 264 KB, `app.js` 220 KB, `alerts.js` 90 KB, `app.css` 79 KB, `index.html`
76 KB, `ipam.js` 61 KB, `netpath.js` 60 KB, `configrx.js` 55 KB — **1.17 MB
uncompressed**, roughly 324 KB gzipped, on every load.

`defer` means this is not a rendering stall; it is bandwidth, parse time and memory,
for eleven modules the operator may never open, and it is most visible where it is
least affordable — a tablet on plant Wi-Fi. The fix is contained because the structure
is already right: `selectTab` exists, each module has its own `init()`, and the assets
are already versioned and immutably cached. Load a module's script the first time its
tab is selected, keeping `app.js`, `boot.js` and `dashboard.js` eager. A previous
review declined minification (PERF-004) with reasons; this is a different and larger
lever, and it makes the source no harder to read.

### 5.9 Security and permissions

⏳

**The self-update path, reported and deliberately not changed.** By the operator's own
instruction this pass documents rather than alters it. ⏳ The exact description, and
the bounds of the exposure, land here once verified against the current code.

---

## 6. Against the platforms it is competing with

Ranked by what each absence costs *this* operator on *this* site, not by whether a
competitor's brochure lists it. Several things a brochure would make much of — sFlow,
NETCONF, RESTCONF — sit near the bottom, because a plant with 2,000 endpoints and one
network engineer does not use them.

**Would stop me adopting it**

1. **No reporting.** Section 5.7 / O-12. I am asked for availability and utilisation
   figures every month by people who do not log in. Today I would have to write the
   SQL myself.
2. **No configuration compliance and no search across stored configurations.** O-5.
   This is the second product I would have to keep paying for.
3. **Alert routing is one mailing list.** O-6, O-7. Every recipient gets everything,
   so within a month nobody reads any of it.
4. **The rollup needs two thousand manual edits before it works.** O-4. Until then a
   site outage is a mailbox full of alerts, which is the same as no alerts.

**Would cost me real time every week**

5. **One group per device, no site, no tag.** O-8. Everything downstream is narrower
   than it needs to be because of it.
6. **Discovery cannot follow the topology it has already collected, and never runs on
   a schedule.** O-14. New equipment is invisible until somebody remembers to sweep.
7. **Search reaches four of twelve modules, and not interface aliases or stored
   configurations.** O-1, O-2, O-3.
8. **The audit trail cannot be read and does not cover engineering changes.** O-10,
   O-11 — and on a site under an ISO or food-safety regime this moves up two
   categories.

**Would notice, could live with**

9. **No per-site RBAC.** Permissions are per module across thirteen modules, including
   `ssh` and `admin` — which is a genuinely good model, just not divisible by site. A
   contractor working on Building 4 gets Nodes write everywhere or nowhere.
10. **Wireless is FortiGate-only.** The tab is honestly named FORTIWIRELESS, which is
    more than most products would do, but a mixed AP estate is only half seen.
11. **No syslog rule conditions beyond severity and a substring.** No regular
    expressions, no "N occurrences in M minutes".
12. **One process, one host.** No remote pollers, no sharding, no high availability.
    At one site with 2,000 endpoints that is arguably right; it is a ceiling rather
    than a fault.

**Would not miss**

13. sFlow — NetFlow v5/v9 and IPFIX cover this estate.
14. NETCONF and RESTCONF — nothing here speaks them, and ConfigRX's SSH capture is
    what actually works against a mixed fleet of this age.
15. SAML and MFA — LDAP simple bind plus scoped API tokens is proportionate for an
    on-premises tool on a plant network.

---

## 7. What was fixed in this pass

⏳

## 8. What was deliberately not built

⏳

## 9. Evidence index

⏳
