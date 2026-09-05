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

⏳ Written last, from the evidence. The shape of it, as the campaign stands:

This is a genuinely well-built monitoring system with an unusually honest codebase, and
it is not yet a *fleet management* system. The distinction matters for the decision.

What it does, it does properly. The SNMP implementation handles the five things that
decide whether polling real gear works at all. The alert state model is right, and its
notification rollup is now demonstrably right: a 108-device site outage in this campaign
opened 228 alerts and sent **11 emails**, where the same shape of event at 4.35.0
produced 1,355. The collectors decode rather than approximate. And the code explains
itself, including the decisions it chose *not* to make — which is rarer and more useful
than most vendor documentation.

Where it falls short is not in what it measures but in what it lets you *do with*
what it measured. It holds 400 days of every metric and cannot produce a report. It
holds two thousand device configurations and cannot answer a question about them. It
collects the topology and will not let you use it. It writes an audit trail nobody can
read. In each case the data is already there and the last mile is missing — which is
good news for the roadmap and bad news for the operator who needs the answer this
month.

The estate gap is the other half. This campaign found the product could not see a UPS,
a printer, an environmental sensor, or a Windows host's memory — four device classes a
plant is full of — and built two of them. That work also produced the campaign's most
instructive defect: the moment `temp_c` existed, ten switches' transceiver temperatures
started tripping a rule meant for a comms room. Adding a metric is easy; adding one that
means the same thing on every device it appears on is the hard part, and it is where a
monitoring product is won or lost.

⏳ Final judgement, with the 1,000 and 2,000 tier numbers, lands here.

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

The harness that shipped with this product simulated a *network*: switches,
firewalls, point-to-point bridges, two PLCs and a Linux host — fifteen personas, all
of them things with a routing table. A plant is not that. A plant is mostly things
plugged *into* the network, and none of them had a persona, so the product had never
been shown them.

Five were added for this campaign — an APC Smart-UPS answering RFC 1628 UPS-MIB and
the PowerNet enterprise arc, an Eaton UPS answering the standard MIB only (so a
finding about UPS support cannot be dismissed as vendor-specific), an AVTECH Room
Alert answering ENTITY-SENSOR-MIB and its own arc, an RFC 3805 multifunction printer,
and Windows server and endpoint personas answering HOST-RESOURCES-MIB properly. The
mix was then rebalanced so the roles a site has a fixed handful of stay fixed as the
count grows, because a plant does not acquire more firewalls when it acquires more
access switches.

`demo/selftest.py` — the offline wire-format conformance check that drives every
persona through the application's own SNMP codec — went from **623 checks to 897**,
all passing.

At the 2,000-device tier the estate is:

| Count | Devices |
| ---: | --- |
| 862 | Cisco 2960X access switches |
| 333 | Windows endpoints (PCs and tablets) |
| 138 | industrial switches — 78 Siemens SCALANCE, 59 Moxa |
| 122 | UPSs — 81 APC, 41 Eaton |
| 119 | Aruba 2930F switches |
| 119 | point-to-point wireless bridges — 79 Ubiquiti airFiber, 40 Cambium PTP |
| 100 | PLCs — 60 Rockwell 1756-EN2T, 40 Siemens S7-1500 |
| 60 | Windows servers |
| 59 | printers |
| 41 | Room Alert environmental monitors |
| 38 | Linux hosts |
| 13 | fixed infrastructure — 2 core switches, 2 FortiGates, 2 Palo Altos, 1 wireless controller, 3 Juniper, 3 MikroTik |

Plus the scripted awkward cases the harness already had, which are worth naming
because they are what a real fleet actually looks like: a device that answers SNMPv1
framing only, one whose community does not match the profile, one that returns
`authorizationError`, one that replies 2.6 seconds late, one that refuses a GETBULK
with `tooBig`, one with no `ifXTable` at all whose 32-bit counters lap, a 500-port
chassis, v3 with and without authentication, a device that goes dark on a schedule and
one that reboots periodically.

Tablets deliberately have no persona, because a tablet does not run an SNMP agent and
inventing one would fake the answer. They appear the way they really do — as MAC
addresses in a switch's forwarding table.

### 2.3 The tiers

| Tier | Devices | What it was for |
| --- | --- | --- |
| A | 250 | Every feature, every incident, the full UI matrix |
| B | 1,000 | Performance only |
| C | 2,000 | Performance only — the operator's real scale |

### 2.4 How the findings were established, and how three of them were withdrawn

Two habits did most of the work here, and they are worth stating because they changed
what several findings turned out to *be*.

**Every timing claim was paired with a control that isolates the mechanism.** Showing
that a syslog message with 240,000 structured-data elements takes 2.34 seconds is a
number; showing that an *unterminated* bracket and a 250,000-level *balanced* nesting of
the same field both stay linear is what proves it is the reslicing loop rather than a
regular expression. Running 4,000,000 elements and getting the same time as 500,000 is
what proves a cap rather than a speed-up. Running ten 500 KB elements is what proves the
cap is on count and not on length. Three of this review's findings changed shape because
of a control case, and one changed from "a quadratic denial of service" to "a quadratic
whose input nobody can reach" — which is a different sentence entirely.

**Nothing self-reported was taken on trust.** Every fix in section 7 was checked by
somebody who did not write it, and the checks found things: that a complexity claim held
under the cap being disabled, that a cycle-detection claim held for the hard case
constructed independently, that a "before" state was really as described (read out of
`git log -p`, because half the claims in any review are about a state nobody can see any
more) — and, twice, that a claim was wrong.

**Three findings were withdrawn.** One of mine: I read two HTTP 403s in a console log
and concluded the interface was offering controls the server then refused. It was not —
they were the test harness deliberately probing the permission boundary, a write
attempted as a read-only account (must fail) and the same write as an operator account
(must succeed), both recorded as passing. The agent I asked to fix it traced every path,
could not reproduce it, and declined — which was correct, and is why it is withdrawn
rather than "fixed" by a change that would have done nothing. **A console log records
what happened, not what was offered.** Two more were withdrawn as already fixed since the
last review, and are recorded in section 5.9.

The point of saying this in the report is not modesty. It is that a review which reports
only what it found, and never what it got wrong, gives an operator no way to calibrate
the rest.

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

**W-7 — the harness told the application a downed device was reachable, and nothing
failed. CONFIRMED (measured, then fixed).** Found while analysing the rehearsal run,
and worth recording because of the *shape* of it rather than the incident.

`demo/scenario.py`'s `start_app` built the application's environment with `PATH` (so
the ICMP substitute is found) and `NETPATH_PING_MODE=subprocess` (so the socket path
cannot bypass it) — and never set `FLEET_CONTROL_PORT`. `demo/bin/ping`'s
`fleet_alive` defaults that to 8099, which is *also* `scenario.py`'s own default
`--control-port`. So at default settings everything worked and nothing revealed the
omission. Run with any other control port — which any run sharing a machine with a
second fleet must do — and the shim queried 8099, found nothing, timed out, and fell
through to "assume alive".

Measured: after the outage step took thirteen devices down and the recovery step
brought them back, the alert database held **zero `device_down` alerts and eleven open
`snmp_failing_ping_ok`** — "SNMP failing while the device answers ping", which is
exactly and accurately what the application saw. The product was right; the harness was
lying to it, and the campaign would have reported a false negative about outage
detection. Verified after the fix: `/alive` true → `ping_many` `(3, 3, 1.0)`; POST
`down`; `/alive` false → `ping_many` `(3, 0, None)`.

The class matters more than the case: **a default that happens to equal another
component's default hides an omission, and the run that would catch it is exactly the
run nobody does.**

All of these are now fixed, and verified independently of the person who fixed them:

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

**The notification rollup works, and the number says so.** In the 250-device campaign,
the scripted site outage — the core switch plus the Site-A access layer, 108 devices —
opened **228 alerts and sent 11 emails**. The earlier review of 4.35.0 measured the same
shape of event at 1,000 devices producing 377 child alerts and 1,355 emails. The hold on
first notification, so the dependency rollup can suppress children before anything is
sent, and the coalescing of everything due in the same flush into one digest, is the
difference between a mailbox an operator reads and one they filter to a folder. This is
the single most important thing 4.47.0 got right.

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

Two of those five were built during this pass and are now live; the table above
describes the product as it was found. What the same instance reports today, queried
device by device:

```
ups-01  (apc)        ups_battery_charge_pct  15.0 %
                     ups_runtime_min          6.0 min
                     ups_battery_status       4.0      (batteryDepleted)
                     ups_battery_voltage    192.0 V
                     ups_battery_temp_c      31.0 °C
                     ups_input_voltage        0.0 V    (mains gone)
                     ups_alarms               1.0
ra-01   (avtech)     temp_c                  41.8 °C
                     humidity_pct            40.7 %RH
```

A UPS running on battery with fifteen per cent charge and six minutes of runtime left
is now something the product can see, alert on and chart. It could not, this morning.

The two that were not built are worth stating as measurements rather than assertions,
because the same query makes them concrete:

- `prn-01`, correctly identified as `hp`, returns **twelve metrics — every one an
  interface counter or a ping result.** No toner, no page count, no paper tray, no
  printer status.
- `pc-01`, correctly identified as `microsoft`, returns `cpu_pct 36.0` and
  `disk_pct 72.4` and **no `mem_pct` at all** — because memory comes only from
  UCD-SNMP, a Fortinet scalar or the Cisco memory pool, and a Windows host answers
  none of the three.

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

**O-17 — removing a custom alert rule silently destroys every alert it ever raised,
including the resolved ones that are the record of past incidents. CONFIRMED.**
`netpath/alertsdb.py:86` declares `rule_id INTEGER NOT NULL REFERENCES rules(id) ON
DELETE CASCADE`. `delete_rule` (line 1122) refuses built-ins but deletes any custom
rule, and SQLite then removes every row in `alerts` that points at it. The
confirmation (`alerts.js:988-991`) reads, in full: *"Remove &lt;name&gt;?"* It does not
mention the alerts, and neither does the API.

So an operator who writes a rule for "PLC unreachable", runs it for a year, then tidies
the rule list in an idle moment, deletes the entire incident history for that
condition — with the dialog telling them nothing. Because the alert list is where a
post-mortem starts, the loss is invisible until somebody goes looking a month later.

Either fix is acceptable: refuse to delete a rule that has alerts and offer `enabled =
0` instead — that column exists and already means "stop evaluating this" — or
denormalise the rule's name onto the alert and change the constraint to `ON DELETE SET
NULL`, so the history outlives its rule. At the very least the confirmation must say
how many alerts will go with it.

**O-18 — `temp_high` fired ten times on a twenty-five device fleet, because one metric
key now means three different things. CONFIRMED (live instance).**

The environmental and UPS polling this campaign added works: a running seeded instance
raised *UPS running on battery power*, *UPS battery low* and *UPS battery depleted,
replace it* against a simulated APC answering RFC 1628 — device states this product
could not see at all a few hours earlier. It also raised **Temperature high ten times**
on a fleet containing one or two Room Alerts.

Queried device by device on that instance, `temp_c` is being reported by eleven
devices:

| Device | Vendor | `temp_c` | `humidity_pct` |
| --- | --- | ---: | ---: |
| acc-sw-001, 002, 004, 005, 006, 009, 010 | cisco | 40.4 – 44.5 | — |
| core-sw-01, core-sw-02 | cisco | 43.3, 44.3 | — |
| configrx-ssh-01 | cisco | 37.7 | — |
| **ra-01** | **avtech** | **41.8** | **40.7** |

Ten of the eleven are switches reporting their SFP transceivers' DOM temperature,
where 40–55 °C is entirely normal and is the reason DOM exists. The eleventh is the
one real environmental sensor — and 41.8 °C in a comms room is an emergency. **A
single `temp_c` key with a single threshold cannot tell those two facts apart.** The
operator's first day with the feature is ten alerts about healthy switches sitting
beside one genuine air-conditioning failure, indistinguishable; their second action is
to turn the rule off, which also turns off the alarm it was built for.

That is precisely the failure the earlier review recorded for `mib_missing`, which
opened on 234 devices of a fresh 250-device install and now ships with `notify` off
because of it. The fix is not a higher threshold: ENTITY-SENSOR-MIB already
distinguishes sensor types and `entPhysicalDescr` names each entity, so the sensor's
kind is available in the walk already being done. Separate keys — `temp_ambient_c`,
`temp_chassis_c`, `temp_optic_c` — give a plant an ambient threshold it can set once
and trust.

This was only visible because the fleet gained personas with real sensors. A
network-only fleet would never have shown it, which is the argument for the persona
work in section 2.2.

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

#### Tier A — 250 devices, all nine incidents

Setup, which is itself a number worth having: **250 devices added in 0.661 s** (378 a
second) as part of a seed that completed in 10.9 s, and the **first full poll cycle
finished 10.0 s later with 249 of 250 up.** A fresh installation is monitoring a
250-device site inside twenty seconds.

| Step | Duration | Alerts opened | Cleared | Emails | CPU | RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 · baseline | 120 s | 122 | 0 | 0 | 23.8 % | 97.8 MB |
| 2 · core + Site-A down (108 devices) | 240 s | 228 | 292 | **11** | 11.4 % | 106.3 MB |
| 3 · outage recovery | 150 s | 296 | 109 | 7 | 22.8 % | 109.2 MB |
| 4 · interface flap storm | 120 s | 72 | 6 | 4 | 26.3 % | **236.7 MB** |
| 5 · reboot 20 devices | 120 s | 111 | 45 | 10 | 28.7 % | 103.4 MB |
| 6 · SNMP auth failure on 5 | 90 s | 73 | 18 | 5 | 31.4 % | 104.3 MB |
| 7 · trap + syslog burst | 75 s | 128 | 19 | 6 | 38.0 % | 160.4 MB |
| 8 · NetFlow burst, 200 flows/s | 75 s | 37 | 8 | 10 | 24.8 % | 176.3 MB |
| 9 · recovery | 150 s | 43 | 61 | 31 | 32.3 % | 102.7 MB |

Three things to read out of that table.

**The notification rollup is the headline.** A 108-device site outage opened 228 alerts
and sent **11 emails**. The 4.35.0 campaign measured the equivalent event producing
1,355. That is the difference between a mailbox somebody reads and one they filter away,
and it is the most valuable thing 4.47.0 shipped.

**Memory is a high-water mark, not a leak.** RSS more than doubled during the flap storm
— 109 MB to 237 MB in 120 seconds, for a storm against *three* devices — and was back to
103 MB by step 5. Sampling the process directly a minute into that step confirmed
101.9 MB. So the allocator returns it. What is not established is the scaling factor: a
site-wide flap event at 2,000 devices — a spanning-tree reconvergence, a UPS transfer
browning out a wiring closet — is precisely the moment the monitoring system must not
run out of memory, and it is the moment its own memory peaks. That is a Tier C question.

**CPU sits between 11 % and 38 % of one core** across every incident, on a 28-core
machine, at 250 devices with a 60-second interval and 32 workers. Notably it is *lower*
during the outage (11.4 %) than at baseline (23.8 %) — a device that has stopped
answering costs a timeout, not a walk.

#### API response times at 250 devices

Measured against the live campaign instance, signed in as admin:

| Route | Time | Payload |
| --- | ---: | ---: |
| `/api/config` | 4.7 ms | 7.3 KB |
| `/api/state` | 40.5 ms | 4.7 KB |
| `/api/nodes/devices?limit=250` | 43.2 ms | **423 KB** |
| `/api/alerts?limit=500` | 48.0 ms | 309 KB |
| `/api/dashboard` | 53.6 ms | 3.3 KB |

`/api/state` is the one to watch: its own docstring notes it is polled every two seconds
by every open tab and that every count is a `COUNT(*)`, with a short cache over the
figures that cannot usefully change at that rate. At 40 ms and 4.7 KB for 250 devices
that is comfortable; the fan-out across ten databases is what Tier C tests.

The device list is 423 KB for 250 devices — about 1.7 KB each — which at a 500-row page
is around 845 KB per page on a 2,000-device fleet. It is server-side paged, so that is
the ceiling rather than the total, but it is a large page for a tablet.

#### What the collectors did, at the end of Tier A

| Collector | Counters |
| --- | --- |
| NetFlow | 12,000 packets → **107,067 flows**, 0 dropped, 0 rejected, 0 errors |
| Syslog | 35,997 messages, 35,687 stored, 0 dropped, 0 rejected, 0 throttled, 0 errors, 20 TCP clients |
| Nodes poller | 5,261 polls · 4,742 ok · 447 timeout · 71 auth-fail · **5 overruns** · 488 MAC walks · 247 identifications · **0 LLDP walks, 0 PoE polls, 0 STP polls** |
| Alert engine | **122,425 evaluated** · 1,475 opened · 560 resolved · **6,587 rolled up** · 79 emails · 0 backlog · 0 apply errors |
| Wireless | 21 polls, 21 ok, 0 errors |
| ConfigRX | 6 backups · 3 changed · 1 suspect · 0 errors |

Not one packet dropped, rejected or errored in either collector, across 107,000 flows
and 36,000 syslog messages including a deliberate burst over both UDP and TCP framings.
The alert engine evaluated 122,425 occurrences with zero backlog and zero apply errors.

**And 6,587 rolled up against 1,475 opened, which puts O-25 in proportion.** The rollup
is not broken — it suppressed four and a half times more alerts than it let through. What
it cannot do is retract a child that was already open when its parent arrived, and on the
shipped configuration that case is guaranteed for the metric rules, because a metric
degrades before a device is declared down. So the rollup works hard and misses precisely
the 108 that mattered most.

**The three zeros are a finding of their own — see O-27.** After 5,261 polls, no LLDP
walk, no PoE poll and no STP poll has ever happened, because no persona in the demo fleet
implements any of those tables.

**O-31 — the syslog counters do not balance, so an operator cannot tell deduplication
from data loss. CONFIRMED (three samples six seconds apart, then traced).** 35,997
messages arrived; 35,687 are recorded as stored; `dropped`, `rejected`, `filtered`,
`throttled` and `errors` are all zero. 310 messages are accounted for by nothing, and
every counter whose job is to explain a shortfall reads zero.

They are not lost. `syslogd.py:453` does `counters["stored"] += self.db.insert(pending)`,
and `syslogdb.insert` collapses repeated identical messages into a `repeat_count` bump
rather than a new row, returning the number of **rows** written. The hourly timeline
still counts every message, with a good comment saying why: *"a storm that collapses to
one row is still a storm."*

The behaviour is right; the instrument is wrong, about the one question these counters
exist to answer. An operator asking "is my syslog collector dropping messages" sees a
310-message shortfall with every explanatory counter at zero and cannot reach the correct
conclusion from the screen. On a plant where a failing switch repeats the same message a
thousand times a minute, that gap becomes enormous and looks exactly like loss. The
number is already computed — `insert()` has `bumps` — so exposing a `collapsed` counter
beside `stored` closes the arithmetic and makes a real shortfall mean something again.

⏳ Tier B (1,000) and Tier C (2,000) land here.

**O-13 — every one of the twelve modules is downloaded, parsed and compiled before the
Dashboard paints. CONFIRMED (`index.html:1335-1347`, byte counts measured).** Thirteen
`<script defer>` tags load `app.js` and every module unconditionally. Measured:
`nodes.js` 264 KB, `app.js` 220 KB, `alerts.js` 90 KB, `app.css` 79 KB, `index.html`
76 KB, `ipam.js` 61 KB, `netpath.js` 60 KB, `configrx.js` 55 KB — **1.17 MB
uncompressed**, roughly 324 KB gzipped, on every load.

`defer` means this is not a rendering stall; it is bandwidth, parse time and memory,
for eleven modules the operator may never open, and it is worst exactly where it is
least affordable — a tablet on plant Wi-Fi. The fix is contained because the structure
is already right: `selectTab` exists, each module has its own `init()`, and the assets
are already versioned and immutably cached. Load a module's script the first time its
tab is selected, keeping `app.js`, `boot.js` and `dashboard.js` eager. A previous
review declined minification (PERF-004) with reasons; this is a different and larger
lever, and it makes the source no harder to read.

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

#### Two ways to stop the monitoring system with one packet

Both found by fuzzing the decoders directly, both with a measured curve, both with a
control case isolating the mechanism, and both fixed in this pass.

**O-23 — a syslog message can be made to cost quadratic time, on an unauthenticated
port. CONFIRMED (measured).** `netpath/syslogparse.py:206-210`, in
`_strip_structured_data`:

```python
while rest.startswith("["):
    end = _end_of_element(rest)
    if end is None:
        return rest
    rest = rest[end:].lstrip()      # copies the whole remaining string, every time
```

`_end_of_element` is cheap per element. The reslice is not: it copies everything that
remains, once per element. An RFC 5424 message carrying many small SD-ELEMENTs is
therefore O(n²) in their count:

| SD-ELEMENTs | message size | time |
| ---: | ---: | ---: |
| 20,000 | ~60 KB | 0.038 s |
| 80,000 | ~240 KB | 0.192 s |
| 160,000 | ~480 KB | 0.652 s |
| 240,000 | ~720 KB | **2.34 s** |
| 500,000 | ~1.5 MB | **timeout, > 8 s** |

The control matters as much as the curve: an *unterminated* bracket and a 250,000-level
*balanced* nesting of the same field both stayed linear to 500 KB, because each enters
`_end_of_element` once and never re-enters the reslicing loop. So it is that loop, not
a regular expression.

Syslog listens on **514/udp and 514/tcp** and is unauthenticated by design. Anyone who
can send a datagram to the host can stall syslog ingestion for seconds, or indefinitely.
On a plant network that is anyone who can reach the management VLAN, including a
compromised device the monitoring system exists to watch.

**O-24 — a MIB file can be made to cost quadratic time inside the very call the
five-second budget was meant to bound. CONFIRMED (measured).**
`netpath/mibparse.py:152`, in `_strip_comments_and_strings`, calls
`text.find("\n", start + 2)` on every `--` comment marker. Where there is no newline
ahead — one long logical line, which is what a minified, pasted or half-downloaded MIB
looks like — each call scans to end of file for a newline that is not there.

| markers | file size | time |
| ---: | ---: | ---: |
| 100,000 | 300 KB | 0.166 s |
| 400,000 | 1.2 MB | 2.36 s |
| 600,000 | 1.8 MB | **5.25 s** |
| 700,000 | 2.1 MB | **7.21 s** |

The same content with a newline after each unit is flatly linear — 0.057 s, 0.115 s,
0.233 s — which isolates the newline scan as the mechanism.

The important half is not the timing. `parse()` (`mibparse.py:340-372`) calls
`_strip_comments_and_strings` at line 371 and checks its own `PARSE_BUDGET_S = 5.0`
only at line 372, **after** that call returns. The 1.8 MB reproducer above already
exceeds the budget *inside* the unguarded call, so the ceiling that exists to cap how
long a hostile upload can hold the interpreter never gets the chance to fire.
Extrapolated to the shipped 8 MB upload cap, a full-size file is on the order of one to
two minutes of held GIL. **A wall-clock ceiling checked only between phases cannot
bound a phase.**

This is also the third instance of one bug class in a file whose own docstring records
the first two being fixed — the macro-clause `::=` scan and the IMPORTS symbol-list
scan. All three are "scan forward for a terminator that may not be there". The class was
fixed twice by patching instances.

**And a fourth phase has the same exposure, bounded. CONFIRMED by independent check.**
The agent who fixed the above reported that `_strip_comments_and_strings` was the *only*
phase called without internal checkpointing. Verification refuted that:
`_iter_macro_clauses` is a generator whose per-header work is invisible to the caller's
`if not index % 256: check_budget()`, because that check fires only on *yielded* clauses.
A MIB of 2,000,000 `OBJECT-TYPE` headers that never close with `::= { }` yields nothing,
so the budget is never consulted — measured at a **16× overshoot** of a 0.2 second budget.

It is bounded, and the bound is why this is a note rather than a defect: at the enforced
default `max_mib_bytes` of 8 MB the same shape completes in about 2.1 seconds, inside the
5.0 second budget, `max_mib_bytes` is an operator setting rather than attacker input, and
`MACRO_CLAUSE_LIMIT`'s windowing keeps the work linear regardless. Reachable only by an
administrator who has raised that cap far past its default, for a file they chose to
upload.

Recorded because the general lesson is now twice-proved in this one file: **a budget
checked between units of work cannot bound a unit of work**, and "unit" includes the
invisible interior of a generator.

**PLAUSIBLE, deliberately not changed: SNMPv3 trap key-derivation amplification.**
`netpath/trapdecode.py:328`'s `localized_key` hashes a 1 MiB buffer per cache miss,
bounded by a 256-entry LRU. `_verify_v3` (line 666) reaches it only when the
wire-supplied `msgUserName` matches a *configured* user — so this needs an attacker who
already knows a valid v3 username, who can then forge a fresh `engine_id` per packet to
defeat the cache and force a full 1 MiB hash per trap. Left unmodified: two verified
fixes in decoders that handle unauthenticated input are worth more than three with one
speculative.

**What was fuzzed and found clean**, because negative evidence is what tells an
operator which decoders have been beaten on: `trapdecode` against 1 KB–1 MB of random
input, OIDs of 1,000 / 10,000 / 100,000 arcs (linear), and truncation at *every one* of
the 84 byte boundaries of a valid v2c trap, with no unhandled exception anywhere;
`nfdecode` against v9-tagged garbage to 1 MB, a zero-field template, a zero-length
field, a template that redefines itself mid-packet, and a template declaring a
60,000-byte field in a 10-byte record — each rejected or handled with no over-read;
`syslogparse`'s two regular expressions fed pathological input to 1 MB with no
backtracking; and `mibparse` against unterminated quoted strings, unterminated
`OBJECT-TYPE` headers (the exact shape of the two previously-fixed bugs — still
linear, so those fixes hold), 80,000-pair enum tables, an unterminated `IMPORTS` block,
and 500,000 unbounded `::= {}` assignments.

#### The permission model, checked mechanically and found sound

**No route's gate disagrees with its handler, across all 213 routes. CONFIRMED
(exhaustive, mechanical).** The route table in `netpath/web/server.py` was AST-parsed
into 213 `(method, pattern, handler, requirement)` tuples, and every handler's body
AST-walked — recursing four levels into other handlers it calls — for write evidence:
`execute`/`executemany` with INSERT / UPDATE / DELETE / REPLACE, or any call whose
attribute name carries a write verb. Seven routes were flagged and all seven are false
positives on reading: `post_login`'s pre-authentication credential bookkeeping, five
routes matching `hostresolve.resolve_name` (a pure lookup), and `get_nodes_device`
matching `alerts_db.mute_row` (a SELECT for the active mute).

The two routes whose gate is a function of the request body were read by hand and are
correct. `_settings_requirement` is worth quoting as evidence of how this codebase
handles a permission bug once it finds one: it derives the gate from the same
`SETTINGS_SCOPES` table the handler dispatches on, specifically so the two cannot drift
— the fix for a real defect in which a `debug: write` account could rewrite global
settings, including the LDAP configuration and the self-update toggle, through the
fall-through path.

The three ways in agree. Session cookie, Bearer API token and LDAP-provisioned account
all converge on one check in `server.py`'s `_route`, and `permissions_for` is keyed only
on username, so a token really does carry exactly its account's grants with no second
model to drift — established by reading the code, not the comment that claims it. The
eight ungated routes are pre-authentication or session-lifecycle, or do their own
per-module filtering inside the handler. `PUBLIC_PATHS` contains the sign-in page's own
assets and nothing else.

**One property of the model worth stating rather than fixing.**
`GET /api/configrx/backups/(\d+)` is gated `configrx: read`, and returns a device's
stored configuration — secrets redacted, but interface addressing, ACLs, routes and VPN
peers intact. That is materially wider than "read" carries anywhere else in the table.
The downgrade from write to read was deliberate, was raised in the previous release's
security review, and the decision was to keep it; it is recorded here so that whoever
hands out that grant knows what they are handing out.

#### The self-update path, described and deliberately not changed

By the operator's own instruction this pass documents rather than alters it. What
follows was established by reading `netpath/selfupdate.py` end to end, not from its own
security note.

**What *is* verified before downloaded code is executed.** The archive size, capped at
64 MB and enforced by reading one byte past the limit and refusing. That the extracted
tree looks like this application — both `netpath/__init__.py` and
`netpath/web/__init__.py` must be present. That the archive contains no symlinks or
device files and cannot escape its extraction directory, checked by `realpath` and a
prefix comparison. And every mode bit in the archive is discarded and replaced with
0755/0644 regardless of what it claimed.

**What is not verified: no tag, no digest, no signature.** `apply()` calls
`latest_commit()` — the mutable tip of the `main` branch, through GitHub's commits API
— not `latest_tag()`. `_download_tarball()` does compute a SHA-256 of what it
downloaded, and nothing compares it to anything; the module says so itself, in as many
words: *"Nothing checks this digest: the branch pull has no published digest to check it
against."* `latest_tag()` and `published_digest()` are fully implemented and still
covered by tests, and `apply()` calls neither.

So push access to that repository is code execution on every install with updates
enabled.

**The mitigations are real, and were confirmed in the current code rather than taken
from the docstring.** `updates_enabled` defaults to `False`. The setting is in
`api.py`'s `ADMIN_ONLY_SETTINGS`, so only an administrator can turn it on. The trigger
route `POST /api/update` is separately gated on the `admin` permission in the routing
table, not merely on the setting. `updates_enabled()` is re-read from stored settings on
every `apply()` call rather than cached, so switching it off takes effect immediately.
And the archive cap, the discarded mode bits and the shape check above all apply.

The honest summary for an operator: this is off by default, an administrator must
deliberately enable it, and if they do, the software will fetch and run whatever is at
the tip of a branch. An installation that leaves it off is not exposed. One that turns
it on has accepted a supply-chain dependency on that repository's access control, and
should know that is what it is — which is the reason for writing it down here rather
than quietly fixing it.

#### Two open items from the previous review that are already closed

Both were carried forward as outstanding and both turn out to be fixed, established by
reading the current code:

`ipam_scan.read_arp_table` was recorded as catching only `OSError` and not the
`subprocess.TimeoutExpired` its own ten-second timeout can raise — "a two-line fix
waiting for the next pass". It now catches `(subprocess.TimeoutExpired, OSError)`, with
a comment naming the old bug precisely: *"TimeoutExpired is a SubprocessError, not an
OSError, so the one failure this call arranges for itself was the one it did not
catch."*

`eventlog.py`'s target set was recorded as growing for the process's lifetime and being
sorted under the lock on every Debug-page poll. `TARGET_LIMIT` now bounds it as an LRU,
and `targets()` re-sorts only when a new sighting or an eviction has invalidated the
cached order.

#### What was checked and found clean

Negative evidence, because on a single-process application with one SQLite writer the
question "what work happens while a lock is held" decides whether it survives a bad
night. `dbmaint.reclaim` releases the lock between incremental-vacuum steps and yields
the GIL between them so a waiting writer is actually scheduled. The DNS resolver's
blocking calls — `gethostbyaddr`, the UDP exchange, the `nslookup` subprocess — all run
on a worker pool with no lock held; the registry lock guards only the pending-and-started
bookkeeping either side. `ipam_worker` has the same shape: its lock guards small sets,
while sweeps, ARP reads and DHCP polls run outside it on a capped pool. No leaked
sockets, handles or threads were found on the ICMP paths, which close selector and
socket in `finally`. And `wsock.py`'s Windows drain-before-shutdown fix is present and
correct, including the ownership rule that only the thread owning `recv()` may drain
directly, because two threads reading one SSL object corrupts rather than raises.

One narrow observation rather than a finding: `secretstore` derives its scrypt keys
inside the cache lock rather than outside it, so a first-ever derivation blocks any
other thread wanting a *different* parameter set. Since only one parameter set is in use
per process, this is a one-time cost at the first credential access after startup and
not a per-call one.

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

⏳ Assembled as the work lands. Confirmed so far:

**Bulk mute was not leaking an error message — it was broken outright. CONFIRMED.**
This went in as a cosmetic item ("the server's `device_ids and/or group_id is
required` reaches the operator verbatim") and turned out to be the symptom of a real
fault. The bulk-mute dialog and the maintenance-window dialog share one scope picker,
and `readScopeFields` answers in the *window* shape — `scope_kind`,
`scope_group_id`, `scope_device_ids`. The bulk-mute route is the older of the two and
never grew that shape; `_bulk_mute_device_ids` in `api.py` reads `device_ids` and
`group_id`. So **every** bulk mute reached the server as fields it does not read, and
**every** bulk mute failed, whatever the operator selected. The error message was the
only part working as intended. Fixed by translating at the call site rather than
reshaping the shared picker, since the windows dialog is right to keep the shape it
has.

**Template Preview silently committed the edit it was previewing. CONFIRMED.** The
preview route reads the stored row rather than the request body, so Preview had always
had to save first — meaning an operator who previewed a change and then thought better
of it had already overwritten the template with no way back. Fixed by snapshotting the
server's version when the dialog opens and restoring it on Cancel, but only if Preview
actually saved. The honest limit is recorded in the code: Escape and a backdrop click
go through `app.js`'s own discard prompt, which has no per-dialog cleanup hook, so a
complete fix is either `app.js`'s to make or belongs on the server, by letting the
preview route accept an unsaved subject and body.

**The "N shown with no denominator" the previous review could not locate.
CONFIRMED — it was the Nodes device count.** `nd-count` read `500 device(s)` with
nothing to compare against, on a list that is now server-side paged and can genuinely
be showing a fraction of what matched. It now uses the same `App.countLabel` the rest
of the application moved to.

**Destructive verbs shared a button row with Save, with no visual weight.** Remove
device, Clear credential, Discard scan and Reset template to default all sat beside
Save looking identical to it. Each now carries the `danger` tier, which `app.js`'s
`modal()` also peels to the start of the row, away from Save.

**O-16 — under a service manager the application printed nothing at all, including
its "you are running without TLS" warning. CONFIRMED, measured both ways, and fixed.**
`netpath/__main__.py` had seven `print()` calls and not one passed `flush=True`;
nothing reconfigured stdout. CPython only line-buffers a stream attached to a
terminal, and a service manager gives it a file or a pipe, so a handful of short lines
sat in an 8 KB buffer indefinitely.

Started as `py -m netpath --headless --port 8490` with stdout redirected to a file:
**after 120 seconds the log was still completely empty**, while the server had been
answering HTTP 200 the whole time. The same command with `-u`: banner in **1.2
seconds**. `demo/scenario.py` already passed `-u`, which is how the workaround stayed
hidden.

Three consequences, worst last. Any script waiting for the documented "serving" line
hangs. `RUNBOOK.md` sends an operator to the log at 02:00, the log is empty, and they
conclude the process never started. And the line that never arrived includes
`WARNING: serving on <host> without TLS. Sign-ins … travel in the clear`
(`__main__.py:199`) — the one warning whose entire job is to reach somebody before
they put a password on an unencrypted page is the one a service-managed install was
guaranteed never to see.

Fixed by reconfiguring both streams for line buffering once, before anything prints,
rather than chasing `flush=True` through each call site. Verified: with no `-u`, the
banner now arrives in **1.58 s**.

**`resolveMacSearch` said nothing when the search was not a MAC at all.** It now
distinguishes "you typed something that is not a MAC" from "the server refused this
MAC", using a client-side mirror of `nodesdb`'s own `looks_like_mac_search` carve-out
for digits and dots — because an IP address's octets are valid hex too, and searching
by address is the far more common reason to type digits and dots into that box.

## 8. What was deliberately not built

⏳

## 9. Evidence index

⏳
