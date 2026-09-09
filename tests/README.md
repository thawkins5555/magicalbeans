# Tests

Plain Python scripts, standard library only, like the application itself. No
pytest, no network, no root: every suite that needs an SNMP agent starts its own
stub (`tests/stubs/`) as a child process on a free loopback UDP port, points the
module under test at that port, and kills it when done. Databases go to a fresh
temporary directory per run.

Nothing here depends on `ping` being absent. That sentence used to read "no
`ping` binary", which described the machine the suites were written on rather
than a property of the suites: `test_nodepoll_e2e.py` asserted that a device
which stops answering SNMP reaches `down`, and on any machine with `iputils`
installed — every CI runner, most developer laptops — 127.0.0.1 answered ICMP,
`unreachable_ping_only` kept the device `up`, and the suite failed. It now
disables ping on the test profile explicitly, so it passes with or without the
binary. The CI workflow installs `iputils-ping` deliberately, to keep it that
way.

```
python3 tests/run_all.py              # every suite, PASS/FAIL per file
python3 tests/run_all.py --only mib   # suites whose filename contains "mib"
python3 tests/test_wireless_poller.py # one suite on its own
node   tests/ui/walk.mjs              # the browser checks, against a running demo fleet
```

Each suite exits non-zero on the first failed assertion and prints what it
was checking. `run_all.py` shows the last lines of a failing suite's output.

## Running suites

`python3 tests/run_all.py` runs every `tests/test_*.py` as its own subprocess
and prints PASS/FAIL/SKIP per file; `--only <substring>` narrows that to
suites whose filename contains it (`--only mib`); any suite also runs on its
own (`python3 tests/test_wireless_poller.py`); `node tests/ui/walk.mjs` is
the browser walk, against a running demo fleet (see below). Suites are named
by subject — what they test — not by review round or fix number.

A suite needing an SNMP agent starts its own stub from `tests/stubs/` as a
child process (`spawn_stub("<script>.py")`, from `_paths`, which also puts
the repo root on `sys.path`) on a free loopback UDP port and kills it when
done; a stub must print a line containing "listening" to stdout, flushed,
once it has bound its socket, which is what the caller waits on.

A suite that cannot run for want of an optional dependency (paramiko,
Playwright) exits `77` rather than failing; `run_all.py` reports that as
SKIP, and "no suites ran" if that is all that happened.

One family is worth calling out by name: `test_frontend_contracts.py`,
`test_time_contracts.py`, `test_layout_contracts.py`, `test_design_tokens.py`
and `test_static_headers.py` read the shipped JS/HTML/CSS as text rather than
running it, and pin the literal strings, shared helpers, CSS tokens and
response headers that a refactor could otherwise change invisibly — no
stub, no browser, no server.

## The benchmarks (`bench_*.py`)

`run_all.py` globs `test_*.py`, so nothing named `bench_*` is ever collected —
which is the point. What a benchmark measures depends on the disk, the core
count and the operating system under it, and a threshold that passes on one
machine is a false alarm on the next, so these print numbers rather than
asserting them and are run by hand when a change is meant to move one:

```
python3 tests/bench_flow_overview.py [rows ...]        # raw flows vs the rollups
python3 tests/bench_record_samples.py [rows] [preload] # per-sample vs batched writes
python3 tests/bench_web_requests.py [devices ...] [--tabs N] [--iterations N]
python3 tests/bench_db_search.py [scale ...] [--repeats N]
python3 tests/bench_prune.py [rows]                    # every prune, and what it freezes
python3 tests/bench_poll_cycle.py [devices ...]        # poll lateness by fleet and pool size
python3 tests/bench_ping.py                            # one ICMP probe, each path this host has
python3 tests/bench_lock_contention.py                 # does a read wait on the poller's writes
```


`bench_web_requests.py` stands up a real `Service` over ten SQLite files and a
`WebServer` on a free loopback port — the same fixture `test_web_security.py`
builds — seeds a fleet of that many devices with interfaces, alerts, polling
profiles and device groups **straight through the database objects**, and then
drives `http.client` over one keep-alive connection. Seeding through the API
would be timing the fixture builder with the thing being measured. It prints
p50/p95/max, response bytes and gzipped bytes per route, then the three
composites an operator would recognise: first paint (index.html plus the five
files it names, `boot.js` included, each asked for as `?v=` the way the markup
spells it), one Nodes tab refresh tick (the nine requests `nodes.js`'s
`refresh()` and `loadDetail()` actually fire, now that only the sub-pane on
screen is fetched), and what `--tabs` browsers all
polling `/api/state` every two seconds cost the server per wall second.

Its `sql` and `lock ms` columns read whatever per-store lock and per-route
latency counters `/api/debug` happens to expose: a snapshot is taken either
side of each route's batch and the numeric leaves whose names mention sql or a
lock are diffed. Where `/api/debug` carries no such fields the columns print
`-` and the bench says so on its header line, so it runs against a build with
the instrumentation and one without.

`bench_db_search.py` seeds every store to three sizes and times each hot or
flagged read, printing rows, mean, p95 and the **first line of `EXPLAIN QUERY
PLAN`** for the query that actually ran — captured with sqlite3's trace
callback while the method executes, so the plan can never drift from the SQL
the module builds. That column is the durable half of the baseline: it records
whether each read scans or seeks, which is the fact an index would have to
change. Sizes are scale factors over a base profile (default `1 4 16`), chosen
so `x4` puts the fleet at the 2,000 devices the comment in `nodesdb.py`'s device search
records its text-search measurement against.

`bench_lock_contention.py` answers the one architectural question this
release put to the numbers: each store is a single SQLite connection behind a
single lock, so every read queues behind every write although WAL would have
let them run together — does that cost anything at a real fleet size? It
times web-shaped reads with a paced writer alongside, and **the pacing is the
whole point**. Unpaced, a writer commits about eleven thousand transactions a
second and reports a p95 two orders of magnitude worse than the truth; a
2,000-device fleet on the shipped interval commits about 17. Deciding from
the first would buy a risky change to fix a problem no install has. Run it
before proposing read-only connections again.

`bench_prune.py` is the one whose last column matters most. Every store here
guards one sqlite connection with one RLock, and each shipped prune holds it
for the whole DELETE, so a second thread reads the store every 5 ms while the
prune runs and keeps the worst wait it saw: that is "the page froze for a
moment", and no wall-clock total for the prune can show it. It also reports
INSERT throughput into each store's hot table before and after its prune, so
the cost of a retention index is recorded beside its benefit.

`bench_poll_cycle.py` drives the real `NodePoller._loop`/`_schedule_pass`
against a real `ThreadPoolExecutor`, monkeypatching only `_poll_device` to a
sleep drawn from a fixed, seeded distribution — no SNMP, no sockets, same
schedule every run. Its headline is lateness (`actual_poll_ts - due_ts`),
which is how late an outage would be noticed; the overrun counter the product
ships only starts moving a whole cycle later. `--stub` is the calibration
pass: real `tests/stubs` agents through the real `_poll_device`, so the
synthetic costs can be checked against the real parse-and-write path.

`bench_ping.py` forces each `NETPATH_PING_MODE` in turn and times probes to
127.0.0.1, which is what makes it runnable anywhere: the target answers
instantly everywhere, so what is left is the cost of the mechanism. It asks
`ipam_scan.ping_mode_summary()` and `_icmp_socket_kind()` what the paths are
rather than knowing itself, so a new implementation added to `ipam_scan.py`
appears as a new row without the bench changing.

## The browser checks (`tests/ui/`)

`tests/ui/walk.mjs` is the one part of this directory that is not a plain Python
script and not standard-library-only: it drives a real Chromium through
Playwright, because the things it checks — that a table has `scope` and
`aria-sort`, that focus returns to the trigger when a dialog closes, that a hash
route restores a selection, that no page error is thrown across twelve tabs,
that ArrowRight moves both focus and selection on a nested `.subtabs` group,
that a status timeline segment's colour-blind texture resolves against its
own chart's `<defs>` rather than whichever chart's landed in the DOM first —
cannot be checked any other way. Its own count of `role="tab"` is taken
against `#tabs` specifically, not the whole document: Nodes, Alerts and
IPAM's `.subtabs` groups are genuine nested tablists now, with their own
`role="tablist"`/`"tab"`/`"tabpanel"`, so a
document-wide count of either role is no longer twelve or one, and counting it
that way would be asserting a number that stopped being true rather than the
contract the top strip actually has. It is deliberately outside `run_all.py`,
which stays dependency-free.

It needs a running application with data behind it:

```bash
python3 demo/fleet.py --count 50 &                 # simulated devices on loopback
python3 -m netpath --headless --port 8099 &        # the application
python3 demo/seed.py --base http://127.0.0.1:8099  # devices, profiles, a target
node tests/ui/walk.mjs                             # the checks
```

It exits non-zero on the first failed assertion, and prints every console error
and failed request it saw. The CI workflow's `ui-walk` job runs it on every
push.

`tests/ui/pristine_login.mjs` is a second, much smaller browser check with a
requirement `walk.mjs` cannot satisfy: an instance that has never had
`demo/seed.py` run against it, because seed.py's own first step changes the
admin password and clears `must_change` — the exact state this check exists
to walk in before. It signs in with the shipped `admin`/`admin`, does nothing
else (no tab, no click), and asserts the forced password-change dialog opens
on its own within a few seconds of the state poll, *and* that it did so
before `App.pages.settings` was ever registered — 4.49.0's lazy module
loading broke this dialog silently by routing it through a lazy module that
had not loaded yet on the very first poll after login, and this is the
regression guard for exactly that failure mode, not just "the dialog
eventually shows up":

```bash
python3 -m netpath --headless --port 8471 --db /tmp/pristine.db &  # no seed.py
node tests/ui/pristine_login.mjs --base http://127.0.0.1:8471
```

Same exit-code convention as `walk.mjs` (0 pass, 1 fail, 77 SKIP for no
Playwright/browser); also SKIPs, rather than failing, if it is pointed at an
instance whose admin account does not have `must_change` set, since that
means the instance is not the pristine one this check needs.

Two exceptions to "no dependencies": `stub_ssh_device.py` is a real paramiko
SSH server, imported in-process rather than spawned (there is no `sshd`
here, and no banner to wait for — construct `StubDevice()` and read
`.port`), and `test_ssh_terminal.py` and `test_ssh_hostkeys.py` need
paramiko itself. A suite that cannot run for want of an optional dependency
exits `77` after printing why; `run_all.py` reports that as SKIP rather than
FAIL, and says "no suites ran" if that is all that happened.
