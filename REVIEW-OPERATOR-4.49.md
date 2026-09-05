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

Would I run my site on this? **Yes, with three things fixed and two settings changed on
day one** — and I would want the reasons in section 6 understood before signing anything,
because what it does not do it does not do at all rather than badly.

**What it is.** A genuinely well-built monitoring system, in a codebase that explains
itself better than most vendor documentation, that is not yet a fleet *management*
system. The distinction is the whole decision.

**What it does, it does properly.** The SNMP implementation handles the five things that
decide whether polling real gear works at all — 64-bit counters preferred, request and
response ids matched, `tooBig` halved and retried, GETNEXT fallback for a v1-only device,
and the last working credential cached per device. The alert state model is right, with
hysteresis as a separate number, persistence requirements, and a rollup. Its notification
layer is demonstrably right: a 108-device site outage in this campaign opened 228 alerts
and sent **11 emails**, where the same shape of event at 4.35.0 produced 1,355. The
collectors decode rather than approximate — 107,000 NetFlow flows and 36,000 syslog
messages across a deliberate burst, with nothing dropped, rejected or errored. And the
permission model held under an exhaustive mechanical check of all 213 routes at the time
it was audited — 227 now, the fourteen added later by the ConfigRX and reporting work
passing the identical standing check with no new exemption needed.

**Where it falls short is not in what it measures but in what it lets you do with what it
measured.** It keeps 400 days of every metric and cannot produce a report. It holds two
thousand device configurations and, until this pass, could not answer a question about
them. It collects the topology and would not let you use it. It writes an audit trail
nobody can read. In each case the data is already on disk and the last mile is missing,
which is good news for a roadmap and bad news for the operator who needs the answer this
month.

**The single most important thing this review found is not a bug.** With shipped defaults
— `down_after_failures = 3` and `poll_interval_s = 120` — **a dead device is reported
about six minutes after it dies, and an outage shorter than three poll cycles is never
reported at all.** Each setting is individually sensible; nothing multiplies them out and
tells the operator what their configuration means in minutes. Measured on this campaign,
81 of 165 devices in a scripted site outage were noticed to be down at approximately the
moment the site came back. Every other alerting feature — the rollup, the digest, the
topology — is downstream of an alert that has to be raised first.

**The estate gap is the other half.** This product could not see a UPS, a printer, an
environmental sensor, or a Windows host's memory — four device classes a plant is full
of. Two were built here; the vendor coverage table in section 5.1 says plainly what it can
and cannot tell you about each of sixteen vendors, which nobody had ever written down.

**And the most instructive defect of the campaign was one the campaign caused.** Making
the Settings module load on demand — a measured, tested improvement that cut the cold load
by 73% — silently broke the forced password change, because a security control consulted a
module that no longer existed at that moment. A fresh install left an administrator on
`admin`/`admin` in an application that looked entirely normal. It was found only because
one reviewer drove a *pristine* instance; every other test in this campaign ran against a
seeded database whose password had already been changed. That is the class of regression
that appears in neither the performance review nor the security review, because it belongs
to neither.

**Four of this review's own findings were withdrawn** after evidence contradicted them,
including two where the database said the opposite of what had been claimed. They are
recorded in section 2.4 with what replaced them, because a review that reports only what
it found gives an operator no way to calibrate the rest.

**The 1,000- and 2,000-device tier numbers (section 5.10) sharpen this rather than change
it.** Onboarding is quadratic in the number of devices already present — 250 devices at
2.64 ms each, 2,000 at 23.2 ms each, a tenfold per-device slowdown across an eightfold
fleet — through the per-device API path the demo harness uses; the bulk-import route that
has existed since 4.47.0 was not measured, so this is a finding about the slow path, not
about onboarding as a whole. Polling is the more consequential shape: near-linear to a
thousand devices, the behaviour an operator would plan around, and then a cliff between
one and two thousand — a 4.7× slowdown in poll-cycle time for CPU that rose only 15%,
which rules out "buy a bigger box" and points at something serialising rather than
computing. The leading candidate — the single SQLite writer every poll result queues
behind — is a hypothesis the numbers are consistent with, not a measurement; nothing in
the product records write-lock wait time, which is itself a finding. A further run
isolating the ping-interval hypothesis was still in progress as this was finished; its
result would narrow the cause further but would not change the shape already measured.

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

**Four findings were withdrawn, all mine.** O-21: I read two HTTP 403s in a console log
and concluded the interface was offering controls the server then refused. It was not —
they were the test harness deliberately probing the permission boundary, a write
attempted as a read-only account (must fail) and the same write as an operator account
(must succeed), both recorded as passing. The agent I asked to fix it traced every path,
could not reproduce it, and declined — which was correct, and is why it is withdrawn
rather than "fixed" by a change that would have done nothing. **A console log records
what happened, not what was offered.** Two more were withdrawn as already fixed since the
last review, and are recorded in section 5.9. The fourth, O-59, is recorded in full where
it was made (section 5.10, "What configuring the topology is actually worth"): I read a
timestamp adjacency between a rollup's own alert closing and a set of downstream alerts
opening one tick later, and wrote up a mechanism I had not checked — that the rollup
missed those alerts and the feature therefore cost more email than not configuring it at
all. A teammate traced every one of the 86 alerts through both databases; none of it was
true. What survived the trace (O-59b, O-59c) is narrower and real, and is not what I
originally reported.

The point of saying this in the report is not modesty. It is that a review which reports
only what it found, and never what it got wrong, gives an operator no way to calibrate
the rest.

**And the review was wrong about its own instrumentation twice, which is a different
failure from being wrong about the product.** A stale figure or a withdrawn causal story
is a claim that turned out false; an instrument that is not measuring what it claims to
is a claim that was never checkable in the first place, and this campaign found two.
`demo/out/tierA/ui/buttons-*-250.json` — the button-census files section 9 cites as
"every control enumerated... activated against which were not" — were produced by a walk
that measured activation through a mechanism a later fix changed: navigation had been
bypassing a real click, so a control could read as never-activated while the page it
opens had, in fact, been reached. Any coverage figure sourced from those particular files
undercounts what was actually exercised, and is superseded by the rehearsal run that
followed the fix (25 devices, no fleet behind them: 94 of 130 controls driven, 9 skipped
by deliberate policy, 25 not reached with a named list) and, later, by an authoritative
fleet-backed run at the full tier. As ui-walk put it: **a coverage number is only as
honest as its instrumentation.** Separately, a permission-gate test for ConfigRX was
found still asserting a boundary the product had already moved past — the test was
green, and it was green because it was checking the wrong thing, not because the gate
was right. Both read as verified. Neither was measuring what it claimed to.

A third, smaller version of the same thing: the 213-route permission audit (section
5.11) was described in conversation, more than once, as having been checked by
*mutation testing* — deliberately introducing a mismatch and confirming the check catches
it. No such harness exists. What is actually in `tests/test_web_gates.py` is an AST-based
cross-reference with exact-set and exact-count assertions — `PUBLIC_PATHS`,
`UNGATED_EXPECTED`, a per-module tier count for every one of thirteen modules — which is a
genuinely strong check and is why the audit could name seven false positives rather than
zero findings meaning nothing was looked at. But it is not mutation testing, and the
phrase was caught before it reached this document rather than after, which is the reason
it is recorded here as a correction rather than silently dropped.

**What the seven corrections and this near-miss have in common is the same failure at
different depths.** Six were stale prose describing real work that had since moved. The
seventh, O-59, was a mechanism inferred from a timestamp and written up as measured fact.
The eighth was a technique named that was never actually run. Each looked like evidence
and was not, for a different reason — an update that never landed, a story never checked
against the data that could have settled it, a name for a check stronger than the one that
existed. A report's credibility does not rest on having been right the first time; it
rests on being willing to say, in the same document, exactly where it was not.

**Two more things about the conditions this was run in, since they affected results.**

A finding was nearly published against the wrong code. The 250-device campaign's process
started at 00:03:39; a fix to the alert engine was saved at 00:35:09; Python does not
hot-reload. The agent whose own fix would have been credited caught it by checking a file
timestamp against a process start, then went further and read the run's database to
establish that the code path in question could not have fired regardless. Attributing a
measurement to the wrong code is the error that makes a whole report untrustworthy, and
the only defence is checking rather than assuming.

And the campaign broke its own tests. A timing assertion written on an idle machine
measured 3.03 s and 5.81 s against a 3.0 s bound while a dozen agents did CPU-bound work
on the same host — a real failure, in a real test, caused by the review itself. The
bounds were widened to this codebase's own stated standard, and, more usefully, the file's
header now records that they were widened once, why, and what the flake actually measured.
A comment claiming a generous margin without the episode that tested it is aspirational;
one with the numbers is evidence.

**O-47 — the campaign's own generated report stated something untrue about the product,
and it would have been published that way. CONFIRMED (trivial to check, easy to miss),
fixed.** `results-250.md`, produced by `demo/scenario.py`, said *"250 devices added in
0.661s ... via one `POST /api/nodes/devices` each — there is no bulk-add endpoint."*
There is: `POST /api/nodes/devices/bulk-import` has been registered since 4.47.0, gated
`nodes: write`, with a row cap and a created/duplicate/invalid breakdown. The harness
simply never adopted it, and the note describing why it measured the slow path was
stale. Recorded because of where it lived rather than what it said: that sentence sits in
the generated output this review's own numbers are quoted from. A harness that narrates
the product has to be as accurate as the product, or it launders a stale assumption into
the report as a measurement. Fixed by correcting the generated line to say what actually
happened — the per-device path was measured deliberately, because the harness was not
updated to use the bulk route that exists — rather than asserting the route is absent.

**O-37 — the test runner reported a passing suite as FAILED because its own console
output contained a character Windows' console encoding could not print. CONFIRMED.**
`tests/run_all.py --only syslog` reported the DoS-fixes suite as FAIL; running the exact
same file directly, at the same moment, exited 0 with all twelve checks passing, and
`--only mib` had picked up the identical file cleanly seconds earlier. The cause is the
runner's own tail-printing of a child's output raising `UnicodeEncodeError` on cp1252 for
an em-dash-adjacent character. `run_all.py:45-50` already documents having been bitten by
exactly this class once — decoding the child's output as `errors="replace"` rather than
the platform default, because cp1252 decoding of an em dash used to kill the runner — but
that fixed the *decode* of the child's output, not the *encode* when the runner prints it
back out to its own (also cp1252) console. A test runner that reports a false failure is
worse than a slow one: it trains people to disbelieve it, and the day it is genuinely
right, nobody looks. It is also the same defect class as the `__main__.py` stdout finding
in this same review — Windows console encoding, met from two directions in one day.

---

## 3. What had to change before the product could be evaluated on Windows

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

**W-7 / O-19 — the harness told the application a downed device was reachable, and
nothing failed. CONFIRMED (measured, then fixed).** Found while analysing the rehearsal
run, and worth recording because of the *shape* of it rather than the incident.

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

**W-6 / O-15 / O-22 — a Windows deployment finding that came out of fixing W-1, and is
about the product rather than the harness. CONFIRMED (measured).**
`netpath/ipam_scan._icmp_socket_kind()` returns `None` on Windows — verified by
calling it — so `ping_many()` always takes the subprocess path, and there is no ICMP
fast path at all on this platform. The shipped defaults are `ping_enabled = 1`,
`ping_interval_s = 0` (ping on *every* poll, `nodesdb.py:423`) and `ping_count = 3`. At
2,000 devices on a 60-second interval that is **6,000 process creations a minute, 100 a
second, sustained** — which does not fit inside the interval it is meant to serve (below).

Measured properly, eight runs of `ping_many(ip, 3, 1000)` each:

| Path | Mean per call | Per probe |
| --- | ---: | ---: |
| Real `C:\WINDOWS\system32\ping.EXE` | 46.7 ms | **15.6 ms** |
| Through the harness's Python shim | 192.3 ms | 64 ms |

The shim's figure is a harness artefact — `ping.cmd` is a two-hop chain through cmd.exe's
batch dispatch and then the `py` launcher — and must not be quoted as a product cost.
**15.6 ms per probe is the number that describes a production Windows install.**

At 2,000 devices, three probes, a 60-second interval: 6,000 process creations a minute,
at 15.6 ms each, is **94 seconds of `CreateProcess` work to be done inside every
60-second window**. It does not fit serially. It works at all only because the poller
spreads it across its worker pool — which is then doing that instead of polling. On
Linux the datagram-socket path avoids every bit of it.

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

Established by exhaustive search of `netpath/`:

| Device class | What the poller reads | What the operator gets |
| --- | --- | --- |
| UPS | nothing under `1.3.6.1.2.1.33` | sysDescr, uptime, one interface, ping. No battery, no runtime, no load, no input voltage. UPS *traps* are decoded (`trapoids.py:58-62`) and the APC/Eaton/Vertiv arcs are named (`enterprises.py:44-46,84`), so a UPS can shout but is never asked how it is. |
| Printer | nothing under `1.3.6.1.2.1.43` | sysDescr and an interface. No toner, no page count, no "out of paper". |
| Environmental (Room Alert) | ENTITY-SENSOR-MIB is decoded only by `nodepoll.read_dom` (~2827), on demand, for one interface, and only for entities `entAliasMappingIdentifier` maps to an ifIndex (~2843-2851) | nothing. A sensor that maps to no port returns `[]` and the dialog says there are none. `temp_c` today comes from the Juniper `jnxOperatingTable` alone. |
| Windows PC / server | `hrProcessorLoad` averaged, `hrStorageFixedDisk` rows | CPU yes, disk yes, **memory no** — `mem_pct` comes only from UCD-SNMP, a Fortinet scalar or the Cisco memory pool. |
| Tablet | — | a tablet runs no SNMP agent; it is only ever a MAC in a forwarding table or a DHCP lease, and there is **no OUI or MAC-vendor lookup anywhere in `netpath/`**, so it is anonymous. |

#### What this product can tell you about each vendor on this estate

Nobody had ever written this down, and it is the first thing an operator deciding
whether to adopt it should be able to read. `VENDOR_HEALTH` is keyed by enterprise arc,
which is the right design — a device is only asked for objects its own maker defines —
so the question is exactly answerable.

| Vendor | Before this pass | After |
| --- | --- | --- |
| Cisco | CPU, memory | **+ temperature** (CISCO-ENVMON-MIB) |
| Juniper | CPU, temperature | **+ memory** (`jnxOperatingBuffer`) |
| Microsoft (Windows) | CPU, disk | **+ memory** (`hrStorageRam`) |
| Palo Alto | nothing from the vendor table | CPU, memory, disk — reached free through the generic HOST-RESOURCES fallback |
| Fortinet | CPU, memory, session count | already complete |
| APC, Eaton | — | full UPS-MIB (this pass) |
| AVTECH | — | full ENTITY-SENSOR-MIB (this pass) |
| MikroTik | CPU, memory (UCD-SNMP) | unchanged |
| Aruba | **nothing** | unchanged — see below |
| Siemens, Moxa | **nothing** | unchanged — no confident health MIB for either industrial line |
| Ubiquiti, Cambium | RF metrics (RSSI, SNR, capacity) | unchanged — the real health signal for a radio link |
| Rockwell | **nothing** | unchanged — structurally unreachable, see O-44 |
| HP | printers: Printer-MIB only | unchanged |

**O-45 — the Cisco temperature gap was the largest single hole in the product, and it is
now fixed.** 862 of the 2,000-device estate are Cisco access switches — the switch in an
un-air-conditioned closet with a UPS under it — and not one of them could report that it
was cooking, by any route: no vendor entry for the environmental objects, and the
platform did not answer ENTITY-SENSOR-MIB. Closed with CISCO-ENVMON-MIB's
`ciscoEnvMonTemperatureStatusValue`, taken as a column maximum so the hottest sensor is
the one reported — a MIB that predates the CISCO-PROCESS-MIB and CISCO-MEMORY-POOL-MIB
entries already in use, and among the most widely implemented Cisco MIBs there is.
Juniper gained `mem_pct` from `jnxOperatingBuffer` in the same pass, off the table its
existing CPU and temperature columns already come from — worth recording how that one
was decided: only moderately confident of the OID from memory, the agent found the demo
Juniper persona, written independently by a different agent, already answering exactly
that OID with a naming comment. Two independent sources agreeing is why it shipped, and
why MikroTik's and Aruba's temperature did not (below).

**Aruba was deliberately left alone, and the reasoning is worth quoting.** A CPU-shaped
OID exists under that arc, but every source places it in ArubaOS's *wireless controller*
MIB rather than the ArubaOS-Switch line a 2930F actually runs — and **asking the wrong
device family for the wrong object is worse than asking nothing**, because a number that
looks plausible is one nobody checks. MikroTik's temperature was left out on the same
grounds. Juniper's memory shipped because a second, independent source agreed: the demo
persona, written by a different agent, already answered exactly that OID with a naming
comment.

**O-44 — a device identified by its description can never receive vendor health,
whatever MIB exists. CONFIRMED (structural).** `vendorid.decide()` returns
`vendor_arc = None` for a device recognised from `sysDescr` text rather than from
`sysObjectID`'s arc — which is exactly a PLC running a generic net-snmp agent. Since
`VENDOR_HEALTH` is keyed by arc, the lookup can never fire for that entire class, and
**no amount of MIB work would help**: a perfect Allen-Bradley health table would sit
unreachable because nothing would look it up.

On this estate that is 100 PLCs, which on a plant are the devices whose downtime costs
the most. It is invisible from the coverage table above unless somebody reads the
identification path, and it is a different kind of gap from "we do not have that MIB" —
which is why the honest interim answer may be to make the emptiness *explain itself*.
A device pane reading "no health metrics — this vendor was identified by description and
has no health table" is worth more than a blank pane an operator reads as a fault.

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

The operator's own complaint was that the four group descriptors — NOW, INVENTORY,
TELEMETRY, ADMIN — look like navigation and link to nothing. They were not elements at
all: CSS generated content off a `data-label` attribute, so not selectable, not
focusable, not translatable by a page translator, and invisible to every JavaScript
query in the application. And because nothing hid the wrapper when permissions hid the
tabs inside it, an account without telemetry grants saw a "TELEMETRY" heading with
nothing beneath it.

**Decision: flatten to twelve tabs, not build dropdowns.** The reasoning, since it is a
judgement rather than a defect. The alerts count badge has to be readable without an
interaction, and under a "Now" menu it is invisible until the menu opens unless the
number is mirrored onto the trigger — creating a second owner of the same figure. Under
alarm, twelve fixed one-click targets beat four triggers and a transient overlay. The
`.page` elements are `role="tabpanel"` pointing back at each tab, and the roving-tabindex
handler is shared with four real subtab strips, so `role="menubar"` would fork the
keyboard contract into two implementations. `boot.js`'s first-paint rule underlines
`.tab[data-tab="…"]`, which would need a tab-to-group map inside it — a second list to
fall out of step. Kiosk hides the strip entirely, so a menu buys a wall display nothing.
And the four words cost roughly 300 px of a strip that must live inside 1366 px.

The grouping survives without the words: a 1 px hairline on the first tab of each group.
About 9 px each instead of 75, no generated text inside the tablist — and, the point,
when permissions hide that tab the divider goes with it, so the orphan-heading defect
becomes structurally impossible rather than fixed by a second hiding pass.

**Ten further defects were found alongside it and all are fixed.** The one an operator
would actually have noticed: `#tabs::after`, the fade that signals "there is more strip
off to the right", was an absolutely positioned child of the scrolling container, so it
translated with `scrollLeft` — correct only at rest, drifting into the middle of the
strip and washing out whatever tab sat under it once scrolled, and never appearing at
the real right edge at all. It is now drawn on the utility group outside the scroller.
The evidence is two screenshots: the fade at the true edge at `scrollLeft 0`, and gone at
the true end.

Also fixed: `has-overflow` never cleared at the right end, so once a strip overflowed the
fade stayed lit forever, including where there was nothing left to warn about; nothing
recomputed overflow on scroll, or when the alerts badge changed digit count and altered
the ALERTS tab's width; the newly active tab was never scrolled into view, so a digit
shortcut, a hash route, Back/Forward, kiosk rotation or the permissions fallback could
all leave it off-screen; every tab was a tab stop until the first `selectTab` ran at the
very end of `start()`; the wordmark was a focusable non-tab inside `role="tablist"`,
making arrow keys a silent no-op when it held focus; and at 360 px the utility group's
three text labels took 55% of the bar, leaving the strip 33%. Search, Account and Sign
out became icons below 480 px, moving **75 px from the utility group to the strip** —
better than doubling what the strip had.

That figure is worth a note on how it was arrived at, because it is a small lesson in
measurement. Two people measured it independently and got different absolute numbers:
198 → 123 px and 119 → 194 px in one harness, 257.5 → 182.4 and 59.5 → 134.6 in the
other. But **both shifted by exactly 75 px, and in both the two widths summed to exactly
317 px before and after.** The mechanism, the direction and the magnitude agree
completely; only the starting split differs, for an identified reason — a different
placeholder username in `#whoami`. So the claim is the delta, not the absolutes, and the
invariant sum is what shows the fix moves width rather than growing or shrinking the bar.

**One thing my brief got wrong, and the correction is a better finding.** I reported the
kiosk help text as promising digit shortcuts the handler did not implement. It did not —
the title said 1-9 and the handler checked 1-9. The real defect underneath was that
`aria-keyshortcuts` did not exist at all, and nothing kept it in step as permissions
hid tabs and shifted which nine were visible. That is now generated and recomputed, with
a test pairing the two so they cannot drift.

**And an honest limit, in the reviewer's own words:** at 1366 px the strip still
overflows by 119 px — one tab's worth — against 0 px at 1920. That is categorically
different from the 360 px case where more than half the bar was three buttons with no
business costing that much. Ten of twelve tabs are visible with no interaction, the fade
now honestly signals the other two, and `scrollIntoView` guarantees any route to a tab
lands it in view. Squeezing further buys 40–90 px at one width, worsens click targets
everywhere the breakpoint applies, and still would not close the gap at 1280. Twelve
full-vocabulary tabs is simply more chrome than a 1366 px laptop shows flat, once
shortening the names and re-grouping are both off the table — and shortening was off the
table deliberately, because FORTIWIRELESS was renamed to be honest about being
FortiGate-only.

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

### 5.4 The ten minutes that matter most

> **Fixed in this pass.** The device summary header now carries Alerts · ConfigRX ·
> Syslog · SNMP traps, each landing pre-filtered on that device, each gated on the
> account's read grant, and each using a route the target module already understood — so
> nothing in those four modules had to change. `nodes.js` went from one `App.buildRoute`
> call to five. Building it surfaced a defect of its own: the Alerts list had no
> `emptyMessage` at all, so a device-filtered view with no matches would have shown a bare
> header over nothing. No count is shown on any link, deliberately — the header redraws on
> every refresh tick, so a count would be a request per device per refresh.

**O-32 — every module links into Nodes. Nodes links back to nothing. CONFIRMED
(exhaustive).** `alerts.js`, `syslog.js`, `snmp.js`, `ipam.js` and `wireless.js` each
link a device address back to its Nodes page. Across the whole of `nodes.js` —
5,100 lines — **`App.buildRoute` is called exactly once**, and it targets Nodes' own
device route. Not one call anywhere builds a route into Alerts, ConfigRX, Syslog or SNMP
for the device on screen.

So the device detail pane — the page an operator is looking at *first*, during an
outage, by construction, because a device went dark and they opened the device — cannot
answer: does this have any open alerts? did its configuration change recently? what has
it logged in the last hour? has it sent a trap? Each of those is a tab switch and a
re-lookup of the same device by name or address, four times, by hand, done by the person
with the least time available to do it.

This is not new infrastructure. Every one of those modules already knows how to land
pre-filtered on a specific device — that is precisely what the existing inbound links
prove — so it is the same three-line pattern, pointed the other way, in the device
summary header beside SSH and WEB.

It is ranked here, above every interface defect in this review and below only the
ConfigRX and reporting gaps, because it costs almost nothing and it changes the shape of
the ten minutes that matter most. It was also not on anybody's list: it came from an
agent that had spent two hours correlating exactly this information by hand, across all
twelve modules, in order to verify other fixes — which is its own argument.

### 5.5 The terminal, and whether it earns its place

Nothing in this campaign had touched the SSH terminal or the sign-in page — the two
things an operator meets first and reaches for at 2 a.m. Both were driven properly:
twelve simulated SSH devices, an escalation flow, a forced mid-session disconnect, both
session caps under real pressure, and a genuinely pristine first-run instance.

**The infrastructure holds under direct pressure, verified at the wire protocol.** Both
refusal sentences arrive in full *before* the close frame: "You already have 4 SSH
sessions open" at the per-user cap of four, and "There are already 16 SSH sessions open"
at the app-wide cap of sixteen, each followed by close code 4429. **That is the Windows
connection-reset fix confirmed alive in a real socket** rather than in a unit test — the
bug where a refused WebSocket's explanatory sentence was discarded by the reset that
followed its shutdown, leaving the operator with a bare disconnection.

Also confirmed live: an abruptly killed connection with no close frame — the
laptop-lid-shut case — frees its slot inside half a second; the handshake timeout closes
at 15.1 seconds with a named reason; signing out kills a live shell in about a second
with "You were signed out"; and the auth-failure cooldown locks a device-and-account pair
after five wrong passwords, which the reviewer hit for real mid-testing. All twelve
personas connected cleanly with no console errors, including the device stuck at an
unprivileged prompt, which answers `% Invalid input detected` and stays usable.

**The verdict, in the reviewer's own words:**

> Yes, it earns its place, but narrowly, on infrastructure rather than on the terminal
> experience itself. What justifies it over PuTTY isn't anything about typing into it —
> it's everything around the typing: one click from the device you're already looking at
> rather than a saved session profile you have to go find, the credential already there
> so you're not pasting a password into a terminal emulator's config dialog, the host key
> already pinned with a real, specific "this changed and nothing was sent" warning instead
> of PuTTY's easy-to-click-through prompt, and a set of limits that are actually enforced
> server-side and that I watched hold under direct pressure. That's real operational value
> a standalone client can't give you, especially the bit where signing out of the web app
> can't leave an orphaned shell into a switch.
>
> Where it doesn't yet earn its place is as a *tool*: no command history, and no session
> transcript — so the audit trail says a session happened, by whom, for how long, but not
> what was done in it, which is the thing an incident review actually wants. An operator
> who already has PuTTY open won't switch for the terminal; they'll reach for this one
> anyway the first time they're already staring at a flapping interface in the device pane
> and don't want to go find the host and copy an IP. Command history and a session log are
> the two additions that would turn "reasonable enough not to avoid" into "the one I open
> on purpose."

**O-49 — and the accessibility gap found on the way. CONFIRMED, fixed.** `ssh.js`'s
`#ssh-log`, the live region mirroring terminal output to a screen reader, flushed a line
only on `\n`. Almost every device prompt arrives *without* one, because the device has
finished talking and is waiting for a keystroke: `acc-sw-001#`, `Password: `, `Select an
option:`. So the single most important line for a screen-reader user — the device is
ready, and here is what it said — was silently dropped, for the rest of the session, on
every persona. Confirmed empty before the fix across twelve connections and populated
after. As the reviewer put it: that gap says accessibility had not been sat in front of a
device yet either.

### 5.6 Finding things

> **O-1 and O-2 are both fixed in this pass.** Every group now carries its own
> `try`/`catch`, each commented *"this group's own failure, not every group after it"* —
> so the comment that described the intended behaviour is finally true. And the search
> reaches **eight** groups rather than four: MAC addresses, devices, alerts, NetPath
> destinations, IPAM hosts, IPAM subnets, syslog messages and wireless access points, all
> through endpoints that already existed. ConfigRX is left as an explicitly marked,
> deliberately unwired gap rather than a guessed call, pending its own search endpoint.
> Two queries remain unbuilt and are specified rather than invented: widening the device
> filter to include `sys_location`, which is free because the Devices group already calls
> that endpoint, and a cross-device interface search on `alias`/`descr`, which needs a
> query that does not exist yet. That second one is still the most valuable and the
> cheapest, and it is why the paragraph below stays in the report.

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

**O-42 — an empty search opens a blocking dialog to say "type at least two characters".
CONFIRMED (found because it broke an automated walk).** `netpath/web/static/ipam.js:1186`'s
`searchHosts()` calls `App.modal(...)` unconditionally, so pressing Find with an empty
box opens a modal whose entire content is a validation message — where every other
filter control in the product validates inline or simply does nothing. Small on its own,
but it had a large effect: an automated walk clicked the button, the modal opened, and
every subsequent click for the rest of that account's pass hit the backdrop and timed
out — 49 cascading failures from one dialog. An operator does not cascade, but they do
get a dialog they must dismiss to tell them something the field could have said next to
itself, at the moment they were in a hurry. A modal is the heaviest instrument in the
interface and should be reserved for a question, a confirmation, or content that needs
the page's whole attention; "you typed too little" is none of those.

**O-43 — ten interactive controls have no id and cannot be addressed at all.
CONFIRMED.** NetFlow's "top ports" list renders ten `<div role="button">` rows carrying
no id, so nothing can name them — not a test, not a keyboard shortcut, not a deep link,
not a support instruction ("click the third one" is not one). The same census found a
bare "Help" button and two per-row Users-grid actions ("Permissions", "Remove") in the
same state: twelve to fourteen unaddressable controls depending on the account. Minor on
its own, and worth recording as a class, because it is the difference between a coverage
claim that can be substantiated and one that cannot — a campaign can honestly say "129
controls enumerated, 73 activated, here are the other 56 and why" only for controls that
can be named.

> **Built in this pass, and not yet reachable — state it precisely rather than as either
> "missing" or "fixed".** `netpath/configrx_search.py` and `netpath/configrx_compliance.py`
> now exist and implement close to exactly what this finding recommends: a per-line search
> index built **only from redacted text, unconditionally**, so there is no permission check
> in the search path to loosen because there is no unredacted copy to gate; a bounded
> regular-expression analyser that refuses catastrophic patterns before they run; and named
> must-match / must-not-match rule sets, scoped to a device group, evaluated after each
> capture and on an hourly sweep, storing pass/fail per device rather than re-running
> patterns on every page view.
>
> **Update, later the same night: both are now wired to routes, neither to a screen.**
> `server.py` carries `GET /api/configrx/search`, full rule-set and rule CRUD
> (`/api/configrx/rule-sets`, its `(id)` and `(id)/rules` children), `GET
> .../rule-sets/(id)/results`, `POST .../rule-sets/(id)/evaluate` and `GET
> /api/configrx/devices/(id)/compliance` — all gated `configrx: read`/`write`
> appropriately, and covered by `tests/test_configrx_search_routes.py` and
> `tests/test_configrx_search_compliance.py`, both passing, including a fixture that ran
> two real rule sets against five real SSH captures and got the pass/fail split (one clean
> device, four with a named rule failure each) that a reader can query directly out of
> `demo/out/configrx_compliance/configrx.db`. So an administrator with a token can already
> ask the question this finding describes.
>
> **`configrx.js` has none of this.** No rule-set editor, no search box, no compliance
> column on the device list, no way for an operator using the actual web application to
> reach any of the routes above. So the operator-facing conclusion below — that the
> question cannot be asked *through the interface* — is still true tonight, and section
> 6's ranking still stands, but for a narrower reason than it did an hour ago: this is now
> a UI gap on top of a complete, tested backend, not an absent feature. The evidentiary
> claim in the paragraph below ("grepping `netpath/` returns nothing") is stale twice
> over now: it describes the product as found at the start of this pass, which is what a
> finding should do, but a reader running that grep today gets two substantial files and
> a working API behind them.

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

**O-56 / O-57 — redaction is correct and it still costs you an answer. One half
inherent, one half fixed.** ConfigRX redacts recognised secrets before they leave storage
in two separate places — the cross-device search index (always, regardless of a device's
own `store_secrets` setting) and the diff view (unconditionally, even for a device whose
raw backups are kept verbatim) — because a search box and a comparison view are both
places a secret must never leak to a reader who has not earned the single-backup download
permission. That design is not in question. What it costs is a specific, narrow and
easy-to-miss capability: the tool's ability to tell an operator that a secret's *value*
changed, as opposed to whether a secret-bearing *directive* is present at all. Found
independently, hours apart, by two different people looking at two different features —
worth a sentence on its own, since that is what makes it a design consequence rather than
a bug somebody happened to notice twice.

**O-56 (compliance).** A rule can ask "does this device have an SNMP community
configured" and get a correct answer regardless of that device's `store_secrets` setting,
because the directive's shape survives redaction. But a rule that asks "is the SNMP
community still the vendor default (`public`/`private`)" is checking the community's
actual *value* — and `configrx_redact.redact()` maps every recognised secret onto the
identical literal `<redacted>` token. On a device that stores redacted captures, `public`
and a properly rotated strong community both collapse to that same token, so the rule
cannot fire either way: not a false pass, not a false fail, just silently unable to tell
the two apart. Demonstrated directly, both directions on one real capture: the same
SNMP-default rule fires correctly against the device's actual capture (`store_secrets`
on) and cannot fire at all against the identical capture redacted the way a
`store_secrets`-off device would have stored it.

**O-57 (diff), and this half is fixed.** The same collapse has a sharper edge on the diff
view, because there redaction is applied unconditionally on *both* sides regardless of
either backup's own storage setting. Two backups whose stored bytes provably differ —
different SHA-256, computed over the unredacted content before either row is ever
touched — could still render as a completely empty diff, because the entire difference
between them lived inside text that maps onto the same `<redacted>` token both times. An
empty diff is the honest answer for "nothing changed" and for "only a secret's value
changed," and those are not the same thing to tell an operator who is looking at a diff
specifically because they suspect a credential was rotated. Fixed: `get_configrx_diff`
now sets `redacted_only_change` whenever the visible diff is empty but the two backups'
SHA-256 values differ, so the interface has what it needs to say "something changed here
that redaction is hiding from you" instead of a bare, reassuring blank — `configrx.js`
renders it, and `tests/test_security_fixes.py`'s D11 block pins it so a regression here
is a visible test failure, not a silent one.

The shared point is not "fix the redaction" — weakening it defeats the reason it exists.
It is that storing less than the full capture is a real, ongoing cost, not a one-time
tradeoff paid at the point a setting is chosen, and neither compliance nor search
currently has O-57's equivalent signal: a rule like O-56's stays silently unable to
answer the one question it was written to ask, with nothing in its result that says so.
Two places worth it going, beyond documentation: a rule that checks a secret-shaped
pattern (a community string, a password literal) could be flagged at `add_rule` time —
not refused, just annotated — as "this rule can only ever fire against a device with
`store_secrets` on," so an operator writing it learns the limit before trusting a clean
result across the whole fleet; and `evaluate_device` already knows which lines
`redact()` would have touched, so a compliance result could carry the same kind of
"redaction may be hiding something here" signal O-57 now gives the diff view, rather
than an operator finding out only when O-56 bites them on the day a password actually
changed.

**O-58 — the retention prune for `netpath.db` is the one place that did not learn the
lesson its own sibling function is named for, and it runs synchronously off an unrelated
settings save. CONFIRMED.** `db.py:770`'s `prune()` does two unbatched `DELETE`s — every
hop row belonging to an expired trace, then the traces themselves — inside a single
`with self._lock:` transaction, so nothing else on that connection (not the trace
scheduler, not the timeline an operator is looking at) runs until it finishes. Thirty
lines above it, `trim_to_size()` deletes in adaptive batches of 500–50,000 rows, each in
its own short transaction bounded by `TRIM_LOCK_TARGET_S = 0.15`, with the comment at
`db.py:24-32` recording exactly why: the old unbatched shape measured a 4.1-second stall
on a 232 MB file. `prune()` was never given the same treatment — its own comment
discusses only the VACUUM it used to call, and the delete beside it was never what
anyone looked at.

The trigger is what makes this worth more than a note: `service.py:405`'s
`apply_global_settings` calls `run_maintenance(force=True)` synchronously on the HTTP
thread that just saved the settings. So an operator changing an unrelated field — a
refresh interval, say — starts a full retention sweep of every database, including this
unbatched one, and the browser waits for it. At 2,000 endpoints with months of per-hop
rows against the shipped 512 MB cap, that is a multi-second freeze of the whole
application produced by saving a setting on an unrelated page. The fix is to batch it the
way `trim_to_size` already does, in the same file, with the same constant.

### 5.7 Being told about it

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

**O-60 — the alert email put severity in the signature and left it out of the subject,
so a mailbox full of one outage could not be triaged without opening every message.
CONFIRMED (read from the 61 messages Tier B's own SMTP sink captured), fixed.** Every
built-in template ended `-- SappiWhere, {{severity_name}}` and no subject line carried
severity at all — `"SappiWhere: {{device_name}} is not responding"`. The consequence only
appears at scale, which is why a small rehearsal never showed it: Tier B's single site
outage produced 29 near-identical notifications, and an operator's phone showed a column
of subjects differing only by device name, with the one fact that decides whether to get
out of bed sitting at the bottom of each body. Fixed by moving `{{severity_tag}}` into
every subject line — one field already computed and already in the template context, now
also read where it is actually needed first.

**O-61 — two rules describing one condition on one device sent two near-identical
emails. CONFIRMED (same capture).** `ups-01` produced two "has recovered" messages eleven
seconds apart, with different outage-start timestamps and different severities: one from
`ups_battery_low` (severity 3), one from `ups_battery_replace` (severity 2) — two tiers
of the same underlying battery state, each with its own rule and its own notification.
The rollup handles a parent device suppressing its children; it does not handle two rules
on the *same* device describing the *same* physical fact, so an operator reads the second
message as a second, unrelated event. The tiering itself is right — "low" and "needs
replacing" are genuinely different actions worth telling someone about — what is wrong is
that both arrive as independent incidents rather than as one alert whose severity moved.

**O-25 — a finding of mine, withdrawn, and the better one that replaced it.**

I claimed the rollup could not retract a child alert that was already open when its
parent arrived. The evidence looked strong: during the 108-device outage the alert list
held 108 `device_down` and 108 `packet_loss_high` rows for the same devices, and on
**108 of 108** the child had opened first, by 58 to 118 seconds.

The database says otherwise. Every pair in that run was cross-referenced afterwards:

```
devices with both rows                                          108
packet_loss_high resolved within 10 s of device_down OPENING    108
packet_loss_high resolved within 10 s of device_down RESOLVING    0
```

Every child resolved about **three seconds** after its parent opened — not at recovery
two minutes later. `_absorb_subordinates`, the method immediately after the one I cited,
already does precisely the retroactive resolve I said was missing, and a passing test
covers it. My snapshot landed inside that three-second window. The ordering measurement
stands; the conclusion I drew from it does not.

**O-25b — the real defect, found while disproving mine, and fixed. CONFIRMED
(reproduced before and after).** A device whose *own* `device_down` never opens — because
an ancestor's outage already rolled it up through the topology path — never gets its
other children swept. `_absorb_subordinates` runs only off a device's own `device_down`
opening, and a topology-covered device's `device_down` structurally never does that, in
either arrival order:

```
B's packet_loss_high, open before the outage       open
device_down opened for A, the core                     1   (expected 1)
device_down opened for B, rolled into A                0   (expected 0)
packet_loss_high STILL open for B afterwards           1   ← the defect
```

This matters more than the case I imagined, and for a specific reason: **it is exactly
the shape a real site outage takes once `upstream_id` is actually set** — the state the
entire upstream-suggestion feature exists to make reachable. So the better a site's
topology, the worse this bug would have been. A plant that had done the work and earned
one alert instead of three hundred would have been rewarded with an orphaned
`packet_loss_high` on every downstream device.

And my own 108-device measurement could never have caught it, because that outage
produced 108 independent `device_down` rows with nothing chained to anything — which
brings us to a caveat that applies to every number in section 5.9.

**Caveat: the campaign measured the un-chained case throughout.** Checked directly
against the run's own database, **zero devices had `upstream_id` set**. That is realistic
for a fresh installation and unrealistic for a site that has done the work. A separate
run with the topology configured is what establishes what a well-configured site
actually sees, and it is reported in section 5.10, "What configuring the topology is
actually worth" — including O-59's withdrawal, which is itself a product of taking that
separate run seriously enough to trace rather than eyeball.

**O-52 — half a site's outage alerts arrive at about the moment the site comes back, and
it is arithmetic rather than a defect. CONFIRMED (direct query, then traced to the two
settings that cause it).**

The topology run's alert database, queried against the campaign log's absolute step times
rather than by counting rows, says this about a 240-second outage of a core switch and the
108 devices behind it:

- the **core** opened its own `device_down` at outage + 162.8 s;
- **2** of the 83 non-core rows behaved exactly as designed — opened seconds after the
  core's, absorbed by it, then correctly *re-opened* at recovery because those two were
  genuinely still down on their own account;
- **81** opened at essentially the same instant the core's alert **resolved** — within
  0.1 s of each other, both at recovery + 42.6 s — and resolved themselves ten seconds
  later.

So the 81 were never a rollup failure. **By the time the poller recorded them as down, the
outage was already over**, and there was nothing left to roll them into. No version of the
suppression mechanism, however written, could have caught them.

**The cause is a multiplication nobody states.** `down_after_failures` defaults to **3**
(`nodesdb.py:408`). `poll_interval_s` defaults to **120** (`nodesdb.py:37`). Three
consecutive failed polls at two minutes each is **six minutes** before a device is
declared down — and that is the floor, before the cycle stretches under an outage, which
it does, because a failed poll costs its timeout and its retries where a healthy one costs
milliseconds. The campaign ran at 60 seconds, which is why the core took 162.8 s rather
than six minutes and why devices deeper in the sweep took longer still.

Each half is individually defensible. Three failures is sane anti-flap; two minutes is
reasonable for a large fleet. **What nobody says out loud is their product**: on shipped
defaults this system reports a dead device about six minutes after it dies, and **an
outage shorter than three poll cycles is invisible entirely** — a switch that reboots in
four minutes was, as far as this product is concerned, never down.

That is not a request to change the poller. It is that the two settings which determine an
operator's detection floor live in different places, neither states the product of the
other, and nothing in the interface says what the current configuration means in minutes.
**A line on the Nodes settings page reading "with these settings a device is reported down
about six minutes after it stops answering" would be worth more than most of the metrics
in this product**, and it costs a multiplication.

Everything else in this section is downstream of it. The rollup, the notification digest
and the topology work can do nothing about an alert that has not been raised yet.

**And `device_down` is not the only rule with a floor nobody multiplies out.** Every rule
with a persistence requirement was checked against its own cadence:

| Rule family | Persistence | Cadence | Floor |
| --- | --- | ---: | ---: |
| `device_down` | 3 consecutive failed polls | 120 s | **6 min** |
| Ten SNMP/ping thresholds — CPU, memory, disk, the four interface rates, discards, response time | `for_polls` 2 | 120 s | **4 min** |
| The five new UPS/environmental thresholds — load, ambient, chassis, optic, humidity | `for_polls` 2 | 120 s | **4 min** |
| `ups_on_battery`, `ups_battery_low`, `ups_battery_replace` | `for_polls` 1 | 120 s | up to **2 min** |
| **`packet_loss_high`** | `for_seconds` 60 — *not* its `for_polls` 2 | 120 s | **4 min** |
| `netpath_unreachable`, `netpath_latency_high` | `for_polls` 3 | 300 s | **15 min** |
| `netpath_path_unstable` | 5 traces inside a one-hour lookback | 300 s | **25 min** before it can evaluate at all |
| `dhcp_scope_exhaustion` | `for_polls` 1 | 15 min | up to **15 min** |
| `interface_flapping` | 3 transitions in a rolling 600 s window | every 5 s tick | **no floor** — three flaps in ten seconds alert in ten seconds |
| Every event rule — device up, reboot, traps, syslog, wireless | none | — | **no floor** |

Two things in that table are worth an operator's attention beyond the arithmetic.

**`packet_loss_high` carries two persistence settings, and only one of them runs.** Its
tuple sets `for_polls = 2` like its neighbours, and `alertsdb.py:624` additionally gives it
`for_seconds = 60`. `evaluate_threshold` (`alertrules.py:185-190`) returns on `for_seconds`
before it ever reads `for_polls`, so for this one rule the number shown in the rules table
is the number that does nothing.

At the shipped cadence the two happen to agree, and the floor above is the 4 minutes its
neighbours get. The reason is worth stating because it is not obvious and I got it wrong
first: `breach_seconds` is measured from *sample* timestamps, not wall-clock
(`alertengine.py:1177-1180`, and the comment there says so), so it does not tick up
continuously — it jumps 0 → 120 → 240. A 60-second bar sitting inside the first 120-second
interval is therefore cleared at exactly the same sample as a two-poll streak. Identical
behaviour, by coincidence of the default interval.

Change the interval and they stop agreeing. At a 30-second poll the `for_seconds = 60` bar
needs three samples where the displayed `for_polls = 2` needs two — the rule becomes
*slower* than its own configuration says. At a 300-second poll both need two and they agree
again. So the defect is not the current timing; it is that a rule shows an operator a
persistence value that is not the one in force, and the discrepancy appears and disappears
depending on a setting on another page.

Worth adding: `alertengine.py:1077-1083` documents fixing this same sample-versus-tick
confusion once already in the engine itself, by gating streak advancement on
`sample_ts != previous_ts`. Before that fix a 60-second bar *would* have been reachable
inside one 120-second interval, off twelve five-second ticks. The code is right and the
comment is good; the rules table is what is out of step.

**And `interface_flapping` is not part of this problem at all.** Despite having its own
window and transition-count settings, it is evaluated every five-second engine tick against
a rolling lookback of transitions already recorded — so its floor is however long three
real flaps take, not a fixed delay. Folding it into the same "N × interval" framing would
be wrong.

The NetPath rules being 15 to 25 minutes is deliberate and the code says so at length: a
path monitor that cries wolf gets turned off. That is a good decision made explicitly.
It is still a number an operator should be told rather than left to derive.

One settings-page line per family — each stating what the current configuration means in
minutes — would close all of this in a single change rather than one per rule.

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

> **Fixed in this pass.** Temperature is now three metric keys with three rules:
> `temp_optic_c` (80/70 °C) where the sensor maps to a port, `temp_ambient_c` (30/25 °C)
> where it maps to no port *and* the device answers a humidity sensor anywhere — the
> signal that it is a dedicated environmental monitor, which generalises past one vendor —
> and `temp_chassis_c` (75/65 °C) for everything else. The default is the safe one: a
> sensor that cannot be positively identified as environmental stays chassis and never
> silently becomes ambient, since ambient-by-default is what produced the ten false alarms.
> Juniper's `jnxOperatingTable` reading lands in `temp_chassis_c` too, guarded so a device
> answering both mechanisms reports one figure rather than two. And a named migration
> retires the superseded `temp_high` rule on upgrade — resolving its open alerts with an
> explanatory note, then disabling and *relabelling* rather than deleting, because the
> rule row is the alerts table's `ON DELETE CASCADE` parent and deleting it would destroy
> the history the note exists to preserve.

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

**O-26 — a quarter of a fresh install's alerts are housekeeping, at the same visual
weight as a real fault. CONFIRMED (Tier A, 250 devices).** Alert composition mid-run: 237
of 712 rows (33%) are `mib_missing` — one per device with a recognised enterprise arc and
no uploaded MIB. It ships at severity 6 with `notify` off, `alertsdb.py:41-45` explaining
exactly why, so nobody is emailed about it. But it is a third of what an operator sees on
the Alerts page on their first morning, mixed in with `device_down` and
`packet_loss_high` at the same visual weight, and the Severity filter defaults to "any".
`mib_missing` is not an event — nothing happened. It is a to-do about the installation.
A "setup" or "housekeeping" classification, excluded from the default view and counted on
a Settings page instead, would remove a third of the noise without hiding anything and
without resorting to a severity floor that would also hide genuine info-level alerts.
(CPU and memory in that same run are inflated by `demo/seed.py`'s deliberately lowered
thresholds for a loopback fleet; that is harness tuning, not a product fault, and is not
part of this finding.)

### 5.8 Answering for it afterwards

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

### 5.9 Showing somebody else

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

Both were built in this pass, and building them produced three findings that are worth
more than the feature.

**O-38 — a maintenance window is remembered forever; a mute is deleted the moment it
lapses. CONFIRMED.** `alertsdb.windows()` retains every window — past, active and
future, by its own docstring — so a report covering last Tuesday can retroactively
exclude a window that ran last Tuesday, weekly recurrence included.
`purge_expired_mutes` **deletes** the row. A mute that lapsed before the report ran
leaves no trace at all.

The consequence is sharper than the fact. Because a still-visible mute requires
`until_ts > now`, and a historical report ends at or before now, a visible mute can only
ever exclude "from when it was created onward" — never a bounded middle slice the way a
window can — since there is no record of a mute being *lifted* early either. So the two
mechanisms an operator reaches for to say the same thing ("do not count this against me,
I was working on it") behave completely differently in a report, and nothing tells them
which to pick if they ever want the number to be defensible afterwards. On a plant where
the monthly availability figure is a deliverable, that is the difference between a number
and an argument. The report now carries it as an unconditional caveat; the real fix is to
stop deleting the row.

**O-39 — a month-wide top-N at full fleet scale takes about a hundred seconds.
CONFIRMED (measured, then projected on an established scaling law).** Against a real
fixture of 2,000 devices × 48 ports × 6 metric families — 576,000 series, **97.3 million
rows** in `samples_hourly` — ranking one family of 96,000 candidates cost **45.8 s** with
a naive `JOIN` that SQLite reordered into a whole-table scan, and **22–23 s** with a
forced `CROSS JOIN` letting candidates drive the loop.

The half that makes the projection trustworthy: re-running with and without five decoy
metric families produced the same time either way, establishing that the cost tracks
(candidates × hours) rather than table size. A month is 730 hours against the 168
measured, so a full-fleet month-wide ranking is **95–100 seconds**. For context, a year
of hourly rollups at that shape is about 5.05 billion rows, and at the shipped 400-day
retention 5.53 billion — a conservative floor, since the poller emits ten interface
metric keys per port and the fixture used six.

**A hundred seconds is not a page load.** Whatever surfaces this has to be a job with a
result, not a request. That is a design constraint discovered before the feature was
built rather than after it shipped, which is the entire argument for measuring first.

**O-40 — `samples_hourly` is a ROWID table, so its own primary key costs an extra lookup
per row.** `PRIMARY KEY(metric_id, hour)` on a ROWID table indexes *into* rowids rather
than being the rows' storage, so even a perfect range scan pays a second lookup per
matched row. Declaring it `WITHOUT ROWID` makes that pair the clustering key and puts the
aggregate columns inline. No new index is needed — the existing key already leads
correctly; the original fault was a query letting SQLite reorder away from it. Specified
with its numbers rather than applied, because a schema migration on a populated table is
not a thing to slip into a review.

### 5.10 Performance and scale

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

**O-28 — memory is a high-water mark, not a leak.** RSS more than doubled during the flap storm
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

**O-46 — forty long tasks in one browser walk, the longest 228 ms, at a quarter of the
operator's fleet size. CONFIRMED (Tier A metrics).** The Nodes table filled 250 of 250
rows in 108 ms and `/api/nodes/devices` returned 422,667 bytes in 18 ms — both good — but
the same session recorded **40 long tasks, the longest 228 ms**. A long task is the main
thread blocked past 50 ms: the page is not responding to anything, including a click the
operator has already made. 228 ms is perceptible, and forty of them across one session is
not a single bad moment, on a machine with 28 cores and no network in the way. Not
diagnosed here — the metric records that they happened, not what caused them — but the
candidates are enumerable: table rendering, the two-second `/api/state` poll, chart
redraws, the sort. A previous review measured and fixed a Debug-tab case of exactly this
shape (8,042 DOM mutations per ten idle seconds), so the class is known to occur here and
known to be fixable. Worth measuring again at the 2,000 tier, where the table is eight
times the size.

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

**And 6,587 rolled up against 1,475 opened.** The rollup suppressed four and a half
times more alerts than it let through, while evaluating 122,000 occurrences with no
backlog. See section 5.6 for a finding of mine about it that turned out to be wrong, and
the better one that replaced it.

**The three zeros are a finding of their own — see O-27.** After 5,261 polls, no LLDP
walk, no PoE poll and no STP poll has ever happened, because no persona in the demo fleet
implements any of those tables.

> **O-31 and O-41 are both fixed in this pass.** `syslogd.py:511-519` no longer does
> `counters["stored"] += self.db.insert(pending)` — `syslogdb.insert()` now returns
> `(stored, collapsed)`, and both are added to their own counters (`"collapsed": 0` sits
> beside `"stored"` in the counters dict), so `messages == stored + collapsed +
> filtered + dropped` is reconstructible on screen rather than needing the `SUM(repeat_count)`
> reconciliation below to be run by hand. Surfaced in `syslog.js`'s status line the same way
> `filtered`/`dropped`/`rejected` already were.
>
> And the O-41 mechanism itself — the reason `collapsed` used to undercount a genuine
> storm — is fixed too. `syslogdb.py:290-381` gives every not-yet-written row a mutable
> one-element `repeat_count` holder, referenced directly from `_last_row` in place of a row
> id, so a repeat later in the *same* batch bumps that holder in place instead of finding
> nothing to bump against and becoming a row of its own. Regression-tested directly against
> the case that broke: 50 brand-new identical messages fed in one `insert()` call now
> produce one row with `repeat_count = 50`, not 50 rows — plus the control that a run
> broken by an *interleaved* different message still does not collapse across the break,
> and the `SUM(repeat_count)` reconciliation below still holds exactly after the fix, on a
> randomised 80-batch, 1,717-message workload. The paragraphs below describe the product
> as found, which is what a finding should do — the code they quote is no longer what ships.

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

Verified independently, and the verification settled it: across 50 batches and 715 fed
messages, `SUM(repeat_count)` over every row equals **715 exactly**, while `insert()`
returned 557. Nothing is lost. The instrument counts rows.

**O-41 — and the deduplication does not fire for a storm that arrives inside one flush
cycle, which is the case it exists for. CONFIRMED (constructed, both directions).**
Found while verifying the above. `syslogdb._collapse()` compares each entry only against
`self._last_row`, which is set either mid-loop when a bump occurs against an
*already-committed* row, or once per `insert()` **after** the write completes. It is
never updated for a fresh entry mid-loop.

So a run of brand-new identical messages beginning and ending inside one batch does not
collapse against itself at all: 50 identical never-before-seen messages fed in one
`insert()` produced **50 separate rows**, each with `repeat_count = 1`. The control in
the other direction confirms the mechanism does work — seeding one such message in a
prior call and feeding nine more in the next batch collapsed all nine into zero fresh
rows. Collapsing takes effect from the *second* batch a message appears in, onward.

A flush window is a few hundred milliseconds to a second. A switch with a failing optic,
a spanning-tree reconvergence, an authentication loop — each fires the same line hundreds
of times a second, comfortably inside one batch. **So the feature whose entire purpose is
to stop a storm becoming N rows is weakest at exactly the storm rate that matters, and
strongest at the slow repetition that would not have hurt anyway.**

#### What configuring the topology is actually worth

The same scripted incident — one core switch plus the Site-A access layer, 108 devices —
run three times at 250 devices:

| Run | Configuration | Alerts opened | Emails |
| --- | --- | ---: | ---: |
| Tier A | un-chained, no `upstream_id` set anywhere | 228 | 11 |
| Tier T | chained, pre-fix code | 124 | 11 |
| Tier T2 | chained, current code | 139 | 14 |

**Configuring the topology roughly halves the alert count.** That is real and worth
having, and it is nothing like the single alert the mechanism is designed to produce.

Two things to read out of it. The 124-versus-139 spread between two runs of *identical*
code and configuration is poll-cycle timing noise — so at this fleet size a single run's
alert count is not reproducible to better than about ten per cent, and no figure in this
section should be quoted to three digits.

And the reason it is not one alert is **O-52, not the rollup.** Suppression can only act
on a child alert raised *while its parent's alert is open*, and the six-minute detection
floor means most downstream devices are not noticed down until the outage is already over
— at which point there is no parent left to roll into. Measured directly on the first run:
81 of 83 non-core alerts opened at the instant the core's own alert *resolved*, within
0.1 seconds of it.

**The rollup works. It is starved of anything to work on.** So the honest statement of
what the topology feature is worth is: it halves the noise today, and it would collapse a
site outage to one alert if devices were detected down promptly. The upstream-suggestion
work built in this pass makes the topology reachable at all; the detection floor decides
how much good that does.

**O-59 — WITHDRAWN AS WRITTEN. The rollup did not miss anything; I connected two true
numbers with a causal story that was not checked.** I had written this up as "the rollup
missed 86 of 96 `device_down` alerts, and the chained run sent more email than the
un-chained one, in the exact scenario the feature exists for" — read from timestamp
adjacency: 86 downstream alerts opening one tick after the core's own alert had closed.
Both halves are false, traced all 86 through `device_events` and `alerts` rather than
taken from the adjacency alone.

The 86 real "down" events landed at T+0 to T+1.5 s alongside the core's, and every one of
them was **correctly suppressed for the whole outage** — no alert row exists for any of
them during the outage window. The rollup did exactly what it was built to do. The rows I
saw at T+119.7 s are not those originals reopening; they are new occurrences deliberately
raised by `_replay_downstream_outages` (`alertengine.py:775`), which fires once an
ancestor recovers and re-checks whether each child is genuinely *still* down — so a device
that is really still broken does not fall silent the moment its upstream clears. Working
as designed, not a defect. And none of the 86 sent an email: all were held under
`notify_rollup_delay_s` and cancelled as cleared within the window. The 14-versus-11 email
difference is real as a count and is not attributable to this mechanism at all — the
messages in that window are unrelated UPS/NetPath/SNMP notices.

What went wrong is specific and worth naming rather than smoothing over: a timestamp
adjacency was read as a mechanism and the mechanism was written up as measured fact,
when the database could have answered which it was in one query. It is the same shape of
error as O-25 — a snapshot inside a short window read as a permanent condition — the
fourth finding this campaign has had to overturn with evidence rather than three, and
recorded as such in section 2.4.

Two narrower findings survive the trace, and are real:

**O-59b — ten of the replayed devices were told they were down after they had already
recovered. CONFIRMED (10 of 86 traced against their own metric sample nearest the
alert's `opened_ts`).** `_replay_downstream_outages` decides whom to re-raise by reading
the live `devices.status` column, which lags that device's own metric sample by a few
seconds at 165 devices behind one core spread across 32 poll workers. Ten devices had
already returned to zero loss at the instant an alert opened saying they were down. The
obvious one-line fix does not work, and was checked rather than assumed: swapping the
live column read for `_still_true` changes nothing, because `_still_true`'s own `"down"`
branch (`alertengine.py:656-657`) reads the identical column — same race, same source. A
real fix is a grace delay before replaying, which changes when an operator is told about a
genuinely-broken device, so it is not a same-night change.

**O-59c — seventy-six true alerts arrive as seventy-six separate incidents rather than
one coalesced notice. CONFIRMED (76 of 86 were genuinely still down when re-raised,
resolving nine to ten seconds later).** These are not wrong: the product is correctly
asking "this device is still down nine seconds after the site came back — do you want to
know?" The question is whether that belongs as one alert per device or one notice per
ancestor. The notification path already protects the operator from the consequence — all
76 were held and cancelled inside the roll-up window, so no email went out — so the cost
is in the alert list, not the inbox: 76 rows opening and closing within ten seconds during
the exact minutes an operator is reading what happened. Coalescing everything a single
ancestor's replay raises into one notice is the fix, and it is a real change to how that
path opens alerts. Specified here, not built.

#### Tier B — 1,000 devices, the same nine incidents

**1,000 devices seeded in 10.67 s** (94 a second — an order of magnitude slower per
device than Tier A's 378 a second, which is O-63 below) and the **first full poll cycle
finished 50.9 s later.**

| Step | Alerts opened | Cleared | Emails | CPU | RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 · baseline | 383 | 0 | 0 | 123.1 % | 125.4 MB |
| 2 · core + Site-A down | 1,021 | 956 | 29 | 39.7 % | 132.4 MB |
| 3 · outage recovery | 1,119 | 379 | 19 | 132.4 % | 136.4 MB |
| 4 · interface flap storm | 84 | 18 | 6 | 121.3 % | 136.0 MB |
| 5 · reboot 20 devices | 118 | 47 | 17 | 124.6 % | 137.3 MB |
| 6 · SNMP auth failure | 78 | 27 | 12 | 124.9 % | 137.3 MB |
| 7 · trap + syslog burst | 44 | 23 | 8 | 120.6 % | 136.4 MB |
| 8 · NetFlow burst | 63 | 12 | 11 | 128.6 % | 143.5 MB |
| 9 · final recovery | 46 | 62 | **49** | 130.6 % | 145.2 MB |

**151 emails across the run, against Tier A's 84** — a run with four times the devices did
not produce four times the email, which on its own would read as the rollup scaling well.
It does not survive step 9: see O-64 below.

**CPU at Tier B sits far above Tier A's 11–38 % band — 121–133 % throughout, more than a
full core.** That is the expected shape of four times the fleet on the same machine, not
a new finding on its own; what it rules out is covered in O-66's addendum.

**O-63 — adding devices one at a time is quadratic in the number of devices already
present. CONFIRMED (three points on the curve, measured by the harness itself).**

| devices | seed time | per device |
| ---: | ---: | ---: |
| 250 | 0.661 s | 2.64 ms |
| 1,000 | 10.67 s | 10.67 ms |
| 2,000 | 46.35 s | 23.2 ms |

Four times the devices cost 16.1× the time; twice the devices cost 4.3×. Both are the
n² signature to within measurement noise, and the per-device figure — the number that
would stay flat if this were linear — quadruples across the range. Each device added
costs more because of the devices already there. Extrapolating the same curve, a
5,000-device estate takes roughly five minutes to load and a 10,000-device one roughly
twenty, for what is conceptually 10,000 inserts.

The measured path is `POST /api/nodes/devices` once per device, which is what the harness
uses. **`POST /api/nodes/devices/bulk-import` has existed since 4.47.0 and was not
measured**, so the honest statement is that the per-device path is quadratic and the bulk
path is unknown, not that onboarding itself is quadratic. That distinction matters: an
operator loading a plant inventory from a CSV may never touch the slow path, while one
adding devices from a discovery scan or a script certainly does. Not a crisis on its own
— nobody rebuilds an estate often — but it is the shape that matters: a per-request cost
that grows with table size is the same defect class this campaign has now found five
times in decoders and delete paths, appearing in the write path instead.

**O-64 — alert opens are digested. Recoveries are not. So the product is loudest at the
moment things get better. CONFIRMED (code path read, and the step-9 mail breakdown
matches exactly).** `_notify_clear` (`alertengine.py:2621`) calls `_notify` directly with
no digest branch of any kind; only opens ever reach `_sweep_notify_rollup`'s
`DIGEST_THRESHOLD` and `_send_digest`. A clear is always sent individually, uncapped.

Tier B's step 9 — an ordinary recovery, flaps stopping and SNMP auth being restored —
produced **49 emails, more than the 29 the site outage itself produced two steps
earlier.** The breakdown is exactly what the code predicts: six digests covering that
step's own alert opens, then a wall of individual "X has recovered" and "X /
GigabitEthernetY has recovered" messages, one per interface that stopped flapping and one
per auth failure that cleared. An operator resolving a hundred flapping ports gets a
hundred emails for doing the right thing — the mechanism that would prevent it already
exists and is simply not wired to this side. The consequence is worse than the volume:
this trains an operator to ignore recovery mail, which is the category that contains
"and this one did not come back." Specified in full and deliberately not built this pass
(section 8).

**O-65 — detection time does not degrade much with fleet size, but its spread does, and
the spread is what an operator actually experiences. CONFIRMED (measured per device from
the first sample recording ≥99% ping loss).**

| | devices measured | min | max | mean | median |
| --- | ---: | ---: | ---: | ---: | ---: |
| 250 | 108 | 125.3 s | 126.8 s | 125.7 s | 125.6 s |
| 1,000 | 395 | 133.5 s | 197.2 s | 153.7 s | 150.0 s |

The mean moved 22%. **The range went from 1.5 seconds to 64 seconds.** At 250 devices
every device is detected at essentially the same moment; at 1,000 a tail takes up to
197 s. This is what quiet degradation looks like: the average barely moves, so nothing
looks wrong on a dashboard that only shows the mean, while some fraction of a large
fleet is noticed materially later, and which devices fall in that tail changes run to
run. Method note worth keeping for whoever repeats this: `device_events`' own "down"
timestamp is useless for this measurement — it is copied straight into the alert's
`opened_ts` by construction, so the gap is trivially 0.0 s at every scale and measures
nothing. The ping-loss sample is the only honest proxy available.

#### Tier C1 — 2,000 devices, first two numbers

**2,000 devices seeded in 46.35 s, first full poll cycle 238.7 s, baseline CPU 141.0%,
RSS 156.8 MB.** C1 is still running as this section is written; the full nine-incident
table is not yet in hand and will not be guessed at here.

**O-66 — the first full poll cycle scales acceptably to 1,000 devices and then falls off
a cliff. CONFIRMED (three tiers, same frozen commit, same machine).**

| devices | seed | per device | first full poll cycle | per device |
| ---: | ---: | ---: | ---: | ---: |
| 250 | 0.661 s | 2.64 ms | 10.0 s | 40.0 ms |
| 1,000 | 10.67 s | 10.67 ms | 50.9 s | 50.9 ms |
| 2,000 | 46.35 s | 23.18 ms | 238.7 s | 119.3 ms |

Fitting time ~ nᵏ between adjacent tiers separates two different problems a single ratio
would have hidden:

| | seed k | poll k |
| --- | ---: | ---: |
| 250 → 1,000 | 2.01 | 1.17 |
| 1,000 → 2,000 | 2.12 | 2.23 |

**Seeding is quadratic across the whole range** — uniform, predictable, and the subject
of O-63 above. **Polling is a different shape entirely.** It is near-linear up to a
thousand devices, which is the behaviour an operator would expect and plan around, and
then degrades sharply between one and two thousand. That is not an algorithm that was
always quadratic; that is a resource ceiling being reached somewhere between the two
tiers. The per-device cost is flat-ish from 250 to 1,000 (40.0 → 50.9 ms) and then more
than doubles (→ 119.3 ms). Why the distinction decides what to do about it: a uniformly
quadratic algorithm has to be rewritten, while a cliff means something specific
saturates — a worker pool, a subprocess spawn rate, a socket budget — and raising that
one limit may move the cliff without touching the design.

The most likely candidate is measurable rather than arguable: at the shipped
`ping_interval_s = 0` every device is pinged on every poll, and on Windows that is three
sequential `ping.exe` subprocesses per device (O-15/O-22), measured at ~15.6 ms per probe
on a live device and about 3.0 s on a dead one. **Tier C2 runs the identical 2,000-device
scenario with `--ping-interval 300` and nothing else changed**, which isolates that
hypothesis: if C2's first full poll cycle comes back near the linear projection of
~100 s, ping is the cliff and the fix is a default, not a rewrite. If C2 lands near C1's
238.7 s, the ceiling is somewhere else and this stays open. ⏳ C2's own number lands here
once it completes.

**O-66, addendum — the cliff is not CPU, and that narrows it usefully.** Baseline-step
CPU across the three tiers: 23.8% at 250, 123.1% at 1,000, 141.0% at 2,000. Between the
last two the poll cycle took 4.7 times longer while CPU rose by only 15%. On a 28-core
machine 141% is 1.4 cores — the process is not compute-bound and is nowhere near the
hardware's limit. So the cliff is something serialising, not something computing. That
rules out the explanation people reach for first ("it needs a bigger box") and points
instead at a resource only one thing can hold at a time. The architecture names an
obvious candidate: one SQLite writer behind one lock, with every polled device's results
going through it, while thirty-two poll workers can gather concurrently and then queue to
write.

This is worth stating carefully rather than asserted, because it is a hypothesis
consistent with the numbers, not a measurement: what would settle it is the write-lock
wait time per poll cycle, which nothing currently records. That absence is itself worth
noting — an operator asking "why is my 2,000-device poll cycle four minutes" has no
instrument in the product that can answer, and neither did this campaign. Tier C2 still
discriminates the ping hypothesis first; if C2 comes back near C1, ping is not the cliff
and the serialisation explanation gains weight.

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

lever, and it makes the source no harder to read.

### 5.11 Security and permissions

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

**O-34 — and a fourth phase has the same exposure, bounded. CONFIRMED by independent
check.**
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

**O-36 — a NetPath destination with a non-positive interval turns the traceroute
scheduler into a subprocess spawn storm against its own host. CONFIRMED (fixed).**
`netpath/db.py`'s `add_target`/`update_target` accepted any numeric value and wrote it
through. `monitor.py`'s scheduler computes `next_run = last_run + interval_s`, so at zero
or below a destination is **perpetually due**: the scheduler launches a traceroute
subprocess against it as fast as the worker pool turns them over, forever. That is the
same spawn-storm shape `ipam_scan.py`'s own docstring names for an unpaced ping sweep,
except self-inflicted through an ordinary API field.

Its siblings had the same gap and all reach a real mechanism: `max_hops` is a literal
subprocess argument and a term in the worst-case runtime arithmetic; `probes` is packets
sent at *every* router on the path; `timeout_s` is `-w`; `trace_workers` goes straight
into `ThreadPoolExecutor(max_workers=…)`. All are now clamped at the storage layer as a
backstop — 1–255 hops, 1–20 probes (just above Linux traceroute's own parallelism cap of
16), 0.1–30 s timeout, 5 s to 30 days interval, 1–64 workers — each bound justified by
the mechanism it guards rather than picked, with API-side rejection specified separately.

Two fields were deliberately clamped only to *sane* rather than to a mechanism ceiling:
`warn_rtt_ms` and `warn_loss` reach nothing but a comparison. Drawing that distinction is
what makes this a sweep rather than a habit.

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

**No route's gate disagrees with its handler, across all 213 routes at the time this was
audited — 227 now. CONFIRMED (exhaustive, mechanical).** The route table in
`netpath/web/server.py` was AST-parsed into 213 `(method, pattern, handler, requirement)`
tuples, and every handler's body AST-walked — recursing four levels into other handlers it
calls — for write evidence:
`execute`/`executemany` with INSERT / UPDATE / DELETE / REPLACE, or any call whose
attribute name carries a write verb. Seven routes were flagged and all seven are false
positives on reading: `post_login`'s pre-authentication credential bookkeeping, five
routes matching `hostresolve.resolve_name` (a pure lookup), and `get_nodes_device`
matching `alerts_db.mute_row` (a SELECT for the active mute).

That cross-reference now runs at test time against the same seven-entry allow-list,
rather than being a one-off — the difference between "we checked once" and "it cannot
regress" — and it is the reason the fourteen routes the ConfigRX search, compliance and
reporting work added later in this same pass could pass the identical check with no new
allow-list entry needed, rather than requiring a second by-hand audit. The table stands
at 227 routes now; the check, not a repeated count, is what kept that difference honest.

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

**The one thing to take from this review if you take nothing else.** Twice in one night,
from opposite directions, this campaign found a number that nobody had multiplied out:

- O-52: `down_after_failures` **3** × `poll_interval_s` **120 s** = a **six-minute**
  detection floor, and an outage shorter than three poll cycles never reported at all.
- O-55: `max_hops` **255** × `probes` **20** × `timeout_s` **30 s** = a **42.5-hour**
  ceiling on a single hung traceroute on Windows — in bounds this campaign had itself
  added a few hours earlier, each one justified against its own mechanism.

Every individual value in both is defensible and documented. Both products are
indefensible and undocumented. Neither is visible from reading either setting, and
nothing in the interface states them. **A bound justified against its own mechanism is not
a bound on the system** — and wherever two or more operator-settable numbers multiply into
a real cost, a wait, a timeout, a thread's lifetime, it is the product that should be
bounded and the product that should be displayed. Neither the code nor the interface
currently does either.

**Before any of it: two settings to change on day one.** Not an absence and not a defect,
which is why it sits above the list rather than in it. `poll_interval_s` at 120 seconds
and `down_after_failures` at 3 multiply to a six-minute detection floor, and an outage
shorter than three poll cycles is never reported at all. Nothing in the product states
that product. Whatever else is decided, an operator adopting this should set those two
deliberately, in the knowledge of what they multiply to, on the first day — and section
5.7 argues the product should tell them rather than making them work it out.

**Would stop me adopting it**

1. **No reporting.** Section 5.7 / O-12. I am asked for availability and utilisation
   figures every month by people who do not log in. Today I would have to write the
   SQL myself.
2. **No configuration compliance and no search across stored configurations, from the
   interface.** O-5. The backend and the API are built and tested against real
   captures as of tonight — an administrator with a token could already ask this
   question — but there is no screen, so through the actual web application it is
   still unaskable. This is the second product I would have to keep paying for, until
   `configrx.js` catches up with the work already sitting behind it.
3. **Alert routing is one mailing list.** O-6, O-7. Every recipient gets everything,
   so within a month nobody reads any of it.
4. **The rollup needs two thousand manual edits before it works.** O-4, O-52. Until the
   upstream field is set a site outage is a mailbox full of alerts, which is the same as
   no alerts.

**Would cost me real time every week**

5. **One group per device, no site, no tag.** O-8. Everything downstream is narrower
   than it needs to be because of it.
6. **Discovery cannot follow the topology it has already collected, and never runs on
   a schedule.** O-14. New equipment is invisible until somebody remembers to sweep.
7. **Search still cannot reach an interface alias or a stored configuration.** O-3, and
   the unbuilt half of O-2. The rest of O-1 and O-2 is fixed in this pass — the search now
   covers eight groups rather than four and no longer drops every group after a failure —
   but `ifAlias`, the description an engineer typed on the port itself, remains polled,
   stored and unsearchable, and that is the one this operator would use daily.
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

### The one this review broke itself

**O-48 — the forced password change stopped firing on a fresh install, because of a
performance improvement made in this same pass. CONFIRMED on a pristine instance,
root-caused, fixed.**

On a genuinely fresh database, `admin`/`admin` signs in, lands on the Dashboard, and the
**entire application renders normally — all twelve tabs visible and clickable** — with
nothing but a one-line orange message under the Dashboard title: "The dashboard could not
be read: password change required". No modal, ever. Not after four seconds, not after
visiting other tabs, and not by opening Account by hand, which yields the ordinary
non-forced dialog with a live Settings page interactive behind it, refusing every read.

`login.html`'s own first-run note promises: *"You will be asked to choose a new password
before anything else."*

The cause is this campaign's own work. `app.js:4447-4451` runs on the first state poll
after sign-in, before the operator has clicked anything:

```js
if (payload.session.must_change && !state.promptedChange) {
  state.promptedChange = true;
  if (pages.settings && pages.settings.forcePasswordChange) { … }
}
```

**Settings is now a lazy module** — introduced by the cold-load work that dropped the
first paint's script cost from loading all thirteen files unconditionally (section 5.10's
O-13: 1.17 MB uncompressed, ~324 KB gzipped) to just the three still-eager ones. Measured
directly: `boot.js` (2,502 B), `app.js` (74,533 B) and `dashboard.js` (4,182 B) gzipped sum
to **81,217 bytes, ≈79 KB** — so `pages.settings` does not exist yet, the branch is
skipped silently, and `state.promptedChange = true` is set **unconditionally**, so it
never retries for the rest of the session.

Two faults. A lazy module consulted before it can exist; and a sentinel that records "we
tried once" where it should record "we prompted" — which was wrong before lazy loading
and only became reachable because of it.

**Three things make this worth putting at the top of the section rather than buried in
it.**

The consequence is the worst available: a fresh installation leaves an administrator on
the default password, in an application that looks entirely normal, with no forced path
off it and one line of orange text as the only signal. And as the agent who found it
observed, the whole sign-in page's security story — host-key pinning included — is
undercut by an operator who was never forced off `admin`/`admin`.

**A performance change moved a security control's precondition.** That is the class of
regression which appears in neither the performance review nor the security review,
because it belongs to neither. Nothing about the lazy-loading work was wrong on its own
terms; it was measured and tested, and this is the one path its own browser walk could
not exercise, for the reason given below.

**And it was findable only because somebody drove a pristine instance.** Every other test
in this campaign — every walk, every tier, every screenshot — ran against a seeded
database whose admin password had already been changed. The one scenario nobody had
exercised was the first thirty seconds of a new installation, which is the only scenario
every single customer experiences.

**The fix removes the dependency rather than working around it.** `accountModal` lives in
`app.js` and needs nothing from `settings.js`, so the forced prompt now calls it directly
instead of delegating through a module that may not be loaded. And the sentinel is set
only once the call has actually run, inside a `try`, so a genuine failure — the modal
element missing from the DOM, say — is retried on the next poll rather than never
prompting again. Both faults closed, and the control no longer has a load-order
precondition at all.

It has its own browser test, `tests/ui/pristine_login.mjs`, deliberately separate from the
main walk — because `demo/seed.py`'s first step changes the admin password and clears
`must_change`, so the existing suite *cannot* exercise this path. A test that needs an
unseeded instance cannot live in a file that needs a seeded one, and saying so in the test
is how the next person avoids folding it back in.

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

### The unbounded commitments

Six of them, all found by the same question — *what does this allocate, loop over or
wait for, on the strength of a number a stranger supplied?* — and all fixed.

**O-50 — one TCP connection could hold unbounded memory on the unauthenticated syslog
port, with every counter reading zero. CONFIRMED (measured before and after).** The RFC
6587 octet-counting framer read a declared length of up to ten digits — 9,999,999,999 —
and waited for `recv()` to satisfy it. `settimeout(30)` bounds each individual read, not
the connection's lifetime, so a sender trickling a few bytes every 25 seconds keeps the
timeout from ever firing while the buffer grows.

Measured with `tracemalloc` against the unfixed code: one connection, 2 GB declared,
1 MB/s fed in. After 50 MB sent — **42 MB current, 82.5 MB peak** (the peak roughly
double because `buffer += chunk` briefly holds both copies during the grow), with
`messages`, `errors`, `rejected` and `dropped` all at **zero** throughout. Unbounded, and
completely invisible.

The gap was an asymmetry rather than an oversight: the *newline* framing path already had
a one-megabyte runaway cutoff — silent, with no counter — and the octet path had no
equivalent. `_max_tcp_clients` at 64 already bounded how *many* connections could do this,
so the honest statement is that 64 × unbounded became 64 × one megabyte.

Fixed differently per framing, because they recover differently. Octet counting refuses on
the **declared length alone**, before a byte of body is buffered, and closes the
connection — there is no honest resynchronisation past a bad declared length, since
finding the next frame means reading past exactly the commitment being refused, and
refusing on the prefix kills the slow drip at its root. Newline framing keeps
discard-and-continue, since the next `\n` is findable without trusting the sender, but is
now counted rather than silently vanishing. After: **0.14 MB current, 0.25 MB peak**,
connection closed within one read cycle, counter at 1 and staying at 1 through five
further trickled chunks, with a legitimate 500 KB octet-framed message still parsing.

**O-36 — a NetPath destination with a non-positive interval turned the scheduler into a
spawn storm against its own host** (section 5.11).

**And the two quadratic parsers** (section 5.11), both reachable from unauthenticated
ports.

**O-53 — the ConfigRX compliance sweep had no wall-clock budget, and it runs on the same
thread that schedules every device's backup. CONFIRMED (measured), fixed.**
`configrx_compliance.py`'s `evaluate_all()` had no ceiling, while its sibling
`configrx_search.py` has one and its own docstring explains why it is needed. The
triggering pattern is not exotic: `compile_bounded(r"a+a+a+c")` is an *allowed* pattern —
three quantified atoms, right at the permitted boundary — and reads as a typo, not an
attack. One 250-character line with no `c` cost 0.2303 s against it; 200 devices × 200
such lines through the real database and evaluator did not finish in 120 seconds, and the
arithmetic projects to about two and a half hours. A normal fleet (2,000 devices, 800
realistic lines, four realistic rules) finishes in 0.4 s, so this was never about slowness
in the ordinary case — it was an absent ceiling. The severity is in where it runs:
`evaluate_all()` is called from `ConfigRxWorker._loop()`, the same loop iteration that
checks which devices are due for a backup, so a sweep that never returns silently switches
off configuration backups for the whole fleet, with nothing timed, logged or counted to
say so. Fixed with `COMPLIANCE_SWEEP_BUDGET_S = 10.0`, checked before each rule set,
before each device, and inside `evaluate_device` itself before each rule and each line —
the last of those is what bounds a single bad must-not-match rule, since proving "never
matches" means scanning every line.

**O-54 — the whole-fleet report guard tested the shape of the request rather than the
size of the work, and any caller who named every device explicitly walked straight past
it. CONFIRMED (logic, unambiguous), fixed.** The month-wide top-metrics report route
refused a whole-fleet-equivalent query only when `device_ids` was *absent*, on the
reasoning that an explicit list means a narrower ask. It does not: `device_ids` naming
every device in the fleet produces the identical query, the identical candidate count and
the identical ~100-second cost (§5.10, O-39) as the case being refused, and a dashboard
that builds its device list explicitly rather than omitting the parameter to mean
"everything" is an ordinary thing to write, not a contrived caller. Fixed by measuring how
many devices the request actually resolves to — `device_ids` omitted counts as every
device on file, the same as `device_ids` naming every one explicitly, since they produce
the same query — and scaling that count against the requested window before the guard
decides, so half the fleet over fourteen days costs the same as the whole fleet over
seven and is refused the same way.

The counter placement in O-50 is the detail worth keeping: it was put where an operator
already looks *because of* O-31 earlier the same night. A collector that refuses silently
is exactly how the previous counter gap happened, and the campaign did not repeat it three
hours later.

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

**O-29 — a read-only account was shown two live-looking buttons that did nothing at
all. CONFIRMED, and it is the worst of this class.** In the Maintenance windows dialog,
`windowRowHtml()` rendered "End now" and "Delete" on every row regardless of grant,
while the wiring loop sat behind `if (!writable) return box;`. So for an account with
Alerts read, both buttons rendered exactly like working ones and simply had no
`onclick`. Reachable, not theoretical: the outer button is deliberately *not*
write-gated, because viewing the windows is a legitimate read action.

A disabled button that says "Needs Alerts write" teaches an operator the shape of their
own access. A button that looks live and silently does nothing teaches them the software
is broken — and the next thing they do is stop trusting the parts that work.

The sweep that found it is worth as much as the fix: about fifty `.disabled =` sites
across twelve module files, sorted into transient in-flight states that self-describe
through their own button text ("Polling…", "Failed", "3 already polling") and legitimately
need no title, and durable business-rule disables that do — of which the handful that
exist already carried a real reason. No second instance of this shape exists anywhere in
those files.

**O-30 — and one control hides where it should disable.** The OID browser's whole-device
walk button was `hidden` for a non-writer rather than disabled with a reason: the exact
inverse, and against the reasoning written beside the application's own write-gate
mechanism. A control that vanishes leaves an operator unable to tell "I may not do this"
from "this product cannot do this", and the second conclusion is the one that loses a
sale. Now disabled in place, after checking that the button sits last in its row so the
layout does not move, and that every path which re-enables it is reachable only by
clicking the button itself.

**The tab badge undercounted the list it sits above.** `open_count` counts `state =
'open'` only, while the Alerts list's default State is "unresolved", which the server
maps to `state IN ('open','acked')`. From the moment anybody acknowledged anything —
routine — the badge undercounted the default view by exactly the acked count, with
nothing saying that was expected. `/api/state` now carries `unresolved_count` off the
summary dict it was already fetching, at no extra query; the client reads it with a
fallback so the two halves could land in either order. The kiosk wall-display figure was
deliberately left on the narrower number, because "what has nobody looked at yet" is a
different and also useful question, and an acknowledged alert has been looked at.

**O-20 — a read-only account could open two configurations and not diff them.**
`server.py:479` gated `get_configrx_diff` on ConfigRX *write*, while `server.py:470` — the
deliberate 4.48.0 change — gates fetching a stored backup on *read*. Diffing two things
you are already permitted to read is not a write, and it is the most common thing anyone
does with configuration backups: the person asking "what changed on that switch before
the line stopped" needed the same grant as the person who can push a credential. Now
`read`, with the test that asserted the old behaviour updated to assert the new one.
Found on a browser walk under both non-admin roles, each timing out on the same disabled
diff button with `title="Your account can read ConfigRX but not change it."`

**O-33 — a background worker wrote to a closed database at shutdown, printing a
traceback into the log an operator is told to read at 2 a.m. CONFIRMED (reproduced in a
test run's teardown), fixed.** `monitor.py:222`'s `record_trace` raised
`sqlite3.ProgrammingError: Cannot operate on a closed database`, the trace scheduler
thread racing the database close during shutdown. The exit code was unaffected, which is
exactly why it survived unnoticed — a test runner and an operator read the same log
differently, and a service stop that ends in a Python traceback is indistinguishable, at
2 a.m., from a service that crashed. The file already documented an analogous shutdown
race for the node poller and waited it out; this was the same class on a different
worker, not covered by that wait. Fixed the same way: `monitor.Scheduler.shutdown()` now
stops accepting new work and drains in-flight traces — scaled to the slowest in-flight
target's own worst-case budget rather than a flat guess — before the executor and its
connection close, and `service.py`'s own shutdown path calls it.

**O-51 — this campaign's own new UPS and environmental polling made 1,900 devices pay
for a probe forever. CONFIRMED by its own author, fixed.** PoE and STP already use a
persisted capability flag — NULL until the first probe, then true or false forever,
precisely so a device confirmed not to support something is never asked again. The new
UPS-MIB probe and the device-level environmental sensor scan had no such memory: they
followed UCD-SNMP's "ask every device every poll" model instead, on the reasoning that
one small GET is cheap. It is cheap for one device and not for a fleet — at 2,000 devices
with perhaps 100 real UPSs, the other 1,900 paid a UPS-MIB scalar GET every poll
indefinitely, and the environmental scan (a GETBULK walk, not a scalar) retried every
300 seconds indefinitely on every device that is not an environmental monitor. Fixed by
matching the existing pattern exactly: `ups_capable`/`sensor_capable` persisted columns,
checked before probing, recorded only on the first probe. Tested for the thing that
matters rather than the thing that is easy — not that the feature works, but that the
*second* call costs zero requests. Found when its own author was asked what in their work
they were least sure of; the question "could this cost a device that is neither"
produced a real regression no test would have failed on and no review would have seen,
because nothing was wrong — it was merely expensive, forever, invisibly.

**O-62 — the SSH terminal's own 900-second idle timeout was unreachable at shipped
defaults, and an idle operator was bounced to the sign-in page instead of being told the
terminal timed out. CONFIRMED (measured: closed at 600.3 s with the wrong close code, not
900 s with the right one), fixed.** `sshterm.py`'s watchdog checked two clocks every
second — the web login session, then the terminal's own `IDLE_TIMEOUT_S` (900 s) — both
reset by the same keystroke. The web session's own default idle window
(`session_idle_minutes: 10` = 600 s) is always shorter, so the web clock always expired
first: the dedicated SSH idle branch and its specific message ("Closed after 15
minute(s) idle") could never fire at shipped settings, and the operator got redirected to
`/login` instead — a more generic, less reassuring explanation than the true one. Fixed
by computing an effective idle window as the minimum of the two clocks and checking *that*
first, with the message naming the real, capped number of minutes rather than the
constant the module started with — so the terminal now correctly reports its own timeout
rather than deferring to a less specific one that would have fired first anyway. Found by
running it, not by reading it: an earlier read of the same file correctly concluded the
idle timer is keyed only to keystrokes and ignores resize traffic — both true, and both
missing the interaction that made the specific timer moot.

## 8. What was deliberately not built

Named, with the reason, so that nothing here reads as an oversight.

**Printer polling.** The operator's decision: simulate it, prove the gap, do not build
it. It is proved — `prn-01`, correctly vendor-identified as `hp`, returns twelve metrics
of which every one is an interface counter or a ping result. RFC 3805's Printer-MIB
would give toner and waste levels, paper trays, page counts and a printer status. Ranked
below UPS and environmental because a printer that has run out of toner does not stop a
production line.

**The self-update supply chain.** The operator's decision: report, do not change. Fully
described in section 5.10, including exactly what is and is not verified and the five
mitigations that actually hold. Changing it would change what an existing installation
follows on its next update, and that is not a decision to make inside a review.

**A "below N is bad" threshold direction.** `evaluate_threshold` supports only "breach
when value is at or above the threshold". So `ups_runtime_low` — alert when a UPS has
under ten minutes left — cannot be expressed, and neither can a low battery charge, a
low free-disk figure, or an interface that has gone abnormally quiet. The agent that hit
this declined to ship the rule with an inverted metric, which would have corrupted the
value for charting and booby-trapped the threshold field for whoever edited it next.
Right call; the evaluator change is real work with real blast radius across every
existing rule, and it belongs in its own pass. It is the highest-ranked item in the
backlog.

**A digest for recovery mail, and coalescing for a rollup's own replay.** Two email-volume
fixes, both specified in full and both declined this pass because each is a real change to
when and how an alert opens or sends, not a one-line patch. O-64: `_notify_clear`
(`alertengine.py:2621`) calls `_notify` directly with no digest branch, where an alert open
already has one (`_sweep_notify_rollup`'s `DIGEST_THRESHOLD`/`_send_digest`) — measured at
49 recovery emails against the 29 the outage itself produced two steps earlier (section
5.10, Tier B). O-61: two rules describing one condition on one device — `ups_battery_low`
and `ups_battery_replace` — send two independent "has recovered" emails rather than one
alert whose severity moved. Both are specified rather than built because wiring a digest
onto the clear path changes the notification contract for every existing rule, and
coalescing two rules' notifications on one device needs a notion of "these two describe
the same fact" that does not exist in the schema yet — real work with real blast radius,
the same standard applied to the threshold-direction item above.

**Per-device bulk-action attribution in the audit trail.** A bulk update, delete or
import cannot carry a filterable per-device target without either overflowing the
256-character target field on any real-sized batch, or a join table. So "was device N
touched by a bulk operation" remains unanswerable after this pass. Stated as an accepted
limitation rather than half-solved.

**Fan-out capping in the topology builder.** `build_topology`'s edge loop is O(fan-out²)
per hop-pair, where fan-out is the number of distinct addresses seen at one TTL within a
single trace. Measured at 0.4 s for fan-out 20 and 1.2 s for 40. But fan-out is a set,
it is 1 whenever a hop answers consistently, it grows only with genuine ECMP diversity —
a handful of parallel uplinks in any real network — and it is driven by neither trace
count, window length, nor fleet size, and no remote party can raise it. A work ceiling
was added at a level no real network reaches; the picture is deliberately not collapsed,
because showing path divergence is the entire purpose of that view.

**Everything structural.** SAML and multi-factor authentication, per-site RBAC, remote
pollers, sharding, high availability, sFlow, NETCONF, and multi-vendor wireless. Each
changes the process model, the permission table's shape, or what "one SQLite writer"
means. They are later work, not declined work, and section 6 ranks them by what they
would actually cost this operator.

## 9. Evidence index

Everything in this document that carries a number came from one of these. Nothing was
reconstructed after the fact.

**The campaign runs**, under `demo/out/`: `tierA/` for the 250-device run —
`scenario-250.log` with its per-step alert, email, CPU and RSS figures,
`results-250.json` and `.md`, `seed_summary.json`, `mail-250.log`, the app, fleet and
generator logs, and `ui/` holding the browser walk's screenshots, console capture,
metrics and per-step results. `rehearsal/` holds the 25-device proving run that found the
`FLEET_CONTROL_PORT` defect. ⏳ Tier B and Tier C directories land beside them.

**The button census**, `demo/out/*/ui/buttons-<account>-<tag>.json` — per account, every
control enumerated with its label, disabled state and disabled reason, and the
cross-reference of which were activated against which were not. This is what the
coverage claim in section 2 rests on, and it is deliberately published rather than
summarised, because "every button was tested" is a claim nobody should accept without
the list.

**The nav-bar screenshots**, including the pair that is the whole argument for one fix:
the overflow fade sitting at the strip's true right edge at `scrollLeft 0`, and absent at
the true end. Plus the strip at 1920, 1366, 1280, 900 and 360 px in both themes, and as
a read-only account.

**The device-pane screenshots** showing the four new cross-module links in place, each
target landing pre-filtered, and the permission parity check under a read-only account.

**The fuzzing harness and its curves** — input size against elapsed time for both
quadratic findings, with the control cases that isolate each mechanism, and the
independent re-measurement that confirmed time-per-element stays flat once the caps are
disabled.

**The route-gate cross-reference**, now a permanent check in `tests/test_web_gates.py`
rather than a one-off: 213 routes parsed from the table at audit time (227 now — the
fourteen added since all pass the identical standing check), every handler walked for
write evidence, seven named false positives, and exact expected sets for the ungated
routes and the public paths.

**The test suites.** Baseline before the campaign: 53 of 53 green. ⏳ Final count lands
here. Every new suite added by this work is listed in section 7.

**The live instances themselves**, queried directly for the alert composition, the
collector counters, the API response times and payload sizes, the per-device metric
tables that establish what a UPS, a Room Alert, a printer and a Windows host actually
report, and the 108-of-108 measurement of child alerts opening before their parent.
