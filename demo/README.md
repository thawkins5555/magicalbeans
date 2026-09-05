# SappiWhere demo harness

A self-contained rig that stands up a fake network, points a real SappiWhere at
it, drives nine scripted incidents through it, walks the browser UI with
Playwright, and writes down what happened.

Nothing here touches `netpath/` or `tests/`. Everything the app talks to is on
the loopback interface: simulated SNMP agents on `127.0.0.2` upwards, a
scripted `traceroute`/`ping` on `PATH`, a throwaway SMTP sink on
`127.0.0.1:1025`.

---

## Quick start

```bash
# From the repository root, as root (see Prerequisites).
python3 demo/scenario.py --count 250 --out demo/out
```

That is the whole demo. It takes roughly 20 minutes at `--count 250`, and
leaves everything in `demo/out/`. For a five-minute smoke test:

```bash
python3 demo/scenario.py --count 25 --out demo/out --fast --skip-ui
```

`--fast` scales every wait down 4x; `--skip-ui` leaves out the browser walk.

---

## Prerequisites

| Need | Why | If you skip it |
| --- | --- | --- |
| **root** (or `CAP_NET_BIND_SERVICE`) | the app listens on syslog **514/udp+tcp**, SNMP traps **162/udp** and the simulated agents answer on **161/udp** | those collectors report `running: false` and steps 6 and 7 measure nothing |
| **`ulimit -n` ≥ 4096** | one UDP socket per simulated device, plus the poller's own | `fleet.py` dies part-way through `bind()` |
| **Python 3.9+** (stdlib only) | everything except the UI walk | — |
| **Node 22 + Playwright 1.56** installed globally | `demo/ui_walk.mjs` | the scenario records `skipped` and carries on |
| `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers` | where Chromium lives | Playwright cannot find a browser |
| *(optional)* real `ping`/`traceroute` | not needed — `demo/bin` shadows both | — |

Raise the file-descriptor limit before a large fleet:

```bash
ulimit -n 8192
```

Playwright is resolved through `npm root -g`, so it does not have to be
installed next to the repository:

```bash
npm root -g            # e.g. /opt/node22/lib/node_modules
node -e "require(require('child_process').execSync('npm root -g').toString().trim() + '/playwright')"
```

Ports used: **8443** (app), **8099** (fleet control), **1025** (SMTP sink),
**161** (simulated agents), **162**, **514**, **2055**. Pass `--port` and
`--control-port` to `scenario.py` if any of them are already taken.

---

## The files

| File | What it is |
| --- | --- |
| `personas.py` | `fleet_plan(count) -> list[dict]` and `SPECIALS` — the device roster: index, IP, name, persona, site, SNMP version, community, polling profile, per-device knobs. **The single source of truth for what the fleet contains.** |
| `fleet.py` | The simulated devices. Binds one UDP socket per address on `127.0.0.2+` and answers SNMP from the persona's OID tree. Control API on `127.0.0.1:8099`. |
| `generators.py` | NetFlow v5/v9, SNMP traps and syslog senders, as functions and as a CLI. |
| `bin/ping`, `bin/traceroute` | Scripted stand-ins put at the front of `PATH`, so NetPath traces a network that does not exist. Paths come from `routes.json`. |
| `seed.py` | Fills a running app over its HTTP API: groups, profiles, devices, NetPath targets, IPAM, wireless, ConfigRX, settings, alert rules, users. `--defaults` seeds without tuning anything the application ships — see [Campaign settings vs shipped defaults](#campaign-settings-vs-shipped-defaults). |
| `ui_walk.mjs` | Drives the browser with Playwright: every tab (by `data-tab`, so a label rename cannot break it), every subtab including Nodes' Topology and the device-detail pane's four nested ones, every dialog it can reach (device groups, the MIB catalog, Upload MIB, ConfigRX's device-settings and bulk-settings dialogs, and the rest), a MAC search and ConfigRX's inline config viewer and diff, a kiosk-mode (`?kiosk=1`) pass, and every top-level tab again under each of the three themes and at three viewport sizes — screenshots, console log, timing metrics. |
| `scenario.py` | The conductor. Starts everything, runs `seed.py`, runs the eight incidents, runs `ui_walk.mjs`, writes the report, stops everything. |
| `.gitignore` | Ignores `out/`. |

### Where the fleet roster is documented

`personas.py` is the reference. Read `SPECIALS` in it for the scripted
special cases; `GET http://127.0.0.1:8099/specials` prints the same table from
a running fleet, and `GET /personas` lists the persona keys.

The shape at a glance: index 0 is the core switch `core-sw-01` at
`127.0.0.2`; index 1 is the FortiGate wireless controller `wlc-01` at
`127.0.0.3`; indices 2–12 are the scripted awkward cases (v1-only, wrong
community, auth failure, slow responder, tooBig, 32-bit counter wrap, a
500-port chassis, v3-noAuth, v3-SHA, a device that goes dark on a schedule,
and one that reboots periodically); everything after that is access switches,
the first 500 of them in `Site-A` behind the core.

---

## Running the pieces separately

Handy when you are working on one part and do not want the full 20 minutes.

**1. The fleet on its own**

```bash
python3 demo/fleet.py --count 250 --control-port 8099
# waits for "listening", then:
curl -s http://127.0.0.1:8099/state | python3 -m json.tool | head
curl -s -X POST http://127.0.0.1:8099/event -H 'Content-Type: application/json' \
     -d '{"ip": "127.0.0.2", "action": "down"}'
curl -s -X POST http://127.0.0.1:8099/event -H 'Content-Type: application/json' \
     -d '{"select": {"persona": "cisco_access", "site": "Site-A", "limit": 500}, "action": "down"}'
```

Actions: `down up reboot flap_start flap_stop slow community auth_fail_on
auth_fail_off toobig_on toobig_off`. `flap_start`/`flap_stop` take the
interface index as `arg`; `slow` takes milliseconds; `community` takes a
string.

**2. The app on its own**

```bash
PATH="$PWD/demo/bin:$PATH" python3 -m netpath --headless \
    --host 127.0.0.1 --port 8443 --db demo/out/data/netpath.db
```

Wait for `SappiWhere serving on http://127.0.0.1:8443/`. First sign-in is
`admin` / `admin`, which forces a password change.

**3. Seeding**

```bash
python3 demo/seed.py --base http://127.0.0.1:8443 --count 250 --out demo/out
python3 demo/seed.py --base http://127.0.0.1:8443 --count 250 --out demo/out --defaults
```

Idempotent — re-running it re-reads `demo/out/creds.txt`, skips devices whose
IP already exists, and refreshes what it can. Every call is appended to
`demo/out/seed_log.json`.

### Campaign settings vs shipped defaults

By default `seed.py` tunes six things away from what the application ships, so
that a 20-minute run on a loopback fleet reaches states that would otherwise
take days. That is the right choice for a demonstration and the wrong one for a
capacity figure, and it is why the campaign's numbers cannot be read as "what
this application does at 2,000 devices".

`--defaults` makes none of those changes, so the same nine-step campaign can be
run once at the shipped configuration and the two columns compared like for
like.

| Setting | Shipped | Campaign (default) | `--defaults` |
| --- | --- | --- | --- |
| profile `poll_interval_s` | 120 s | 60 s | 120 s |
| profile `snmp_timeout_s` / `snmp_retries` | 3.0 s / 2 | 2 s / 1 | 3.0 s / 2 |
| profile `mac_table_interval_s` | 3600 s | 300 s | 3600 s |
| `poll_workers` | 16 | 32 (`--workers`) | 16 |
| `new_device_grace_s` | 300 s | 0 | 300 s |
| `max_emails_per_hour` | 60 | 10,000 | 60 |
| `cpu_high` threshold | 90% / clear 80 / 2 polls | 20% / 10 / 1 | 90% / 80 / 2 |
| `response_time_high` | 500 ms / 300 / 2 | 5 ms / 2 / 1 | 500 ms / 300 / 2 |

What `--defaults` still does, because it is plumbing rather than tuning and the
run measures nothing without it: points SMTP at the sink on `127.0.0.1:1025`
so mail can be counted, turns on syslog over TCP so both framings are
exercised, and starts the alert engine. None of those changes how hard the
application has to work.

**Run `--defaults` against a fresh database.** It does not *reset* anything — it
simply makes no override — so pointing it at a database a tuned run already
seeded leaves that run's 60-second interval and 20% CPU threshold in place.
`scenario.py` uses a fresh `data-<count>/` per run, so a scenario run is always
clean.

Two things to expect from a `--defaults` run, neither of which is a fault:

- **`cpu_high` and `response_time_high` never fire.** A net-snmp persona idles
  far below 90% and loopback round-trip time is about 0.05 ms against a 500 ms
  threshold. At shipped values the threshold path is genuinely not exercised;
  that is the honest result, and it is what the lowered thresholds were hiding.
- **Fewer emails, and a visible cap.** Sixty an hour is reached in the first
  minute of a 250-device outage. The rest are recorded against their alerts as
  failed notifications rather than arriving at the sink, so the sink's count is
  a floor, not a total.

**4. Traffic**

```bash
python3 demo/generators.py netflow --count 20 --rate 200 --duration 60 --version mixed
python3 demo/generators.py traps   --count 20 --rate 200 --duration 60 --mix storm
python3 demo/generators.py syslog  --count 20 --rate 400 --duration 60
python3 demo/generators.py syslog  --count 20 --rate 200 --duration 60 --tcp --framing octet
```

**5. The UI walk**

```bash
node demo/ui_walk.mjs --base http://127.0.0.1:8443 \
     --creds demo/out/creds.txt --out demo/out/ui --tag 250
```

---

## What the scenario does

| Step | Action | Base duration |
| --- | --- | --- |
| 1 | baseline, nothing happening | 120 s |
| 2 | core switch down + the 500 `Site-A` access switches behind it down | 180 s |
| 3 | interface 7 flapping on 100 access switches | 120 s |
| 4 | reboot 20 devices | 120 s |
| 5 | SNMP auth failure on 5 devices | 90 s |
| 6 | trap storm + syslog burst (part over TCP with octet framing) | 60 s of traffic |
| 7 | NetFlow burst, mixed v5/v9, 200 flows/s | 60 s of traffic |
| 8 | recovery: everything back up, flapping stopped, auth restored | 180 s |

Before and after each step it snapshots `/api/state`, `/api/debug`
(`node_counters` including overruns, plus per-worker elapsed), open alerts
grouped by rule, the SMTP sink's message count, the app's CPU% and RSS from
`/proc/<pid>/stat` and `/proc/<pid>/status`, and the fleet's own `/state`.

---

## Output

Everything lands in `demo/out/` (git-ignored):

```
creds.txt                 admin / viewer / noc passwords this run generated
seed_log.json             every API call: endpoint, status, error text
seed_summary.json         per-step seeding summary, including the refusals
results-<count>.json      the full metric record
results-<count>.md        the readable table: alerts by rule, emails, polls,
                          overruns, poll latency, CPU%, RSS
mail-<count>.log          the SMTP sink's transcript (one message per
                          "---------- MESSAGE FOLLOWS ----------")
app-<count>.log           the app's stdout
fleet-<count>.log         the fleet's stdout
scenario-<count>.log      the run's own log
data-<count>/             the ten SQLite databases for this run
ui/tab-*.png              one screenshot per top-level tab, admin pass
ui/sub-*.png              one per subtab, admin pass (includes Nodes'
                          Topology and the device-detail pane's four
                          nested subtabs)
ui/dlg-*.png              one per dialog it could open
ui/feature-*.png          MAC search, ConfigRX's inline config viewer
                          and diff (panes, not dialogs)
ui/theme-<theme>-*.png    every top-level tab under dark/light/contrast
ui/viewport-<WxH>-*.png   every top-level tab at 1920x1080, 1366x768
                          and 1280x720
ui/kiosk-*.png            a kiosk-mode (?kiosk=1) session
ui/viewer-*.png           the same top-level tabs as the read-only
                          `viewer` account
ui/console-<count>.json   console errors/warnings, page errors, failed
                          requests, every HTTP response >= 400 (every pass)
ui/metrics-<count>.json   nodes-table fill time, long tasks, payload size
ui/walk-<count>.json      per-step ok/skipped/failed
```

Each run uses a fresh `data-<count>/` directory, so there is no teardown step
— delete `demo/out/` to start over.

---

## Accounts

`seed.py` writes three sets of credentials to `demo/out/creds.txt`:

| Account | Access |
| --- | --- |
| `admin` | write on everything (the built-in account, password rotated on first run) |
| `viewer` | read on every module |
| `noc` | write on Nodes and Alerts, read elsewhere |

Two quirks worth knowing, both in the app rather than here:

* Changing a password destroys every session for that account
  (`netpath/web/api.py:4060`), so `seed.py` signs in again straight after.
* `POST /api/users` always sets `must_change`, and an admin *reset* sets it
  again — only the account changing its **own** password clears it. `seed.py`
  therefore signs in once as each new account to clear the flag, so the UI walk
  is not blocked by a forced-change dialog.

---

## Caveats

* **Everything is loopback.** The devices are UDP sockets on `127.0.0.x:161`,
  not machines. Latency figures are the app's own scheduling and parsing cost
  with essentially no network in them — real WAN numbers will be worse.
* **`traceroute` and `ping` are shims.** `demo/bin` goes to the front of
  `PATH`, so NetPath sees the scripted topologies in `demo/routes.json`
  (`10.0.0.1` multihop, `.2` route change, `.3` refused `!X`, `.4` silent hop,
  `.5` dead, `.6` degraded). Nothing leaves the machine. Remove `demo/bin` from
  `PATH` and NetPath will trace the real network instead.
* **No credential can be stored on Linux unless a passphrase is
  configured**, from 4.47.0 — see `CREDENTIAL-SECURITY.md` §10. This
  harness does not set `NETPATH_SECRET_PASSPHRASE_FILE` or
  `NETPATH_SECRET_PASSPHRASE`, so every "save this password" endpoint still
  refuses with a 400 exactly as before — SNMPv3 auth passwords, the SMTP
  password, ConfigRX SSH passwords, DHCP server credentials. `seed.py` calls
  them anyway and records the exact refusal text in `seed_log.json` under
  `refusals`. That is intended evidence, not a failure; set one of those two
  environment variables before starting the fleet to seed a run with
  credentials actually stored instead.
* **ConfigRX backups will not succeed** without something answering SSH, and
  (absent the passphrase above) the credential cannot be stored anyway. The
  seeding proves the configuration path, not a completed backup.
* **`GET /api/alerts` caps `limit` at 2000** (`netpath/web/api.py:2973`), so a
  very large outage can truncate the per-rule counts. `results-<count>.json`
  records `alerts_truncated` when it does. **Export CSV** on the Alerts tab is
  not subject to this cap — it goes to 50,000 rows — but the seeding scripts
  do not exercise it.
* **`GET /api/nodes/devices` still returns the whole fleet in one JSON body
  when called with no parameters**, which is what every script in this
  harness does — the UI walk measures how big that gets
  (`ui/metrics-<count>.json`, `devices_payload_bytes`). From 4.47.0 the route
  also accepts `limit`/`offset` for a paged caller; nothing here uses that
  path, so this harness's numbers are still the whole-fleet cost.
* **Seeding a fleet is still one `POST /api/nodes/devices` per device.** A
  bulk-import route (`POST /api/nodes/devices/bulk-import`) exists from
  4.47.0, but `seed.py` does not use it — the per-device rate it prints is
  deliberately measuring the single-device path's cost, which is what a
  script written against an older release still pays.
* **Ports 161/162/514 are shared.** If another copy of the fleet or the app is
  already running on the machine, the second one silently loses the race —
  check `app-<count>.log` and `fleet-<count>.log` before believing a zero.
