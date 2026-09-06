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
