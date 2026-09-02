# SappiWhere demo harness

A self-contained rig that stands up a fake network, points a real SappiWhere at
it, drives eight scripted incidents through it, walks the browser UI with
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
| `seed.py` | Fills a running app over its HTTP API: groups, profiles, devices, NetPath targets, IPAM, wireless, ConfigRX, settings, alert rules, users. |
| `ui_walk.mjs` | Drives the browser with Playwright: every tab, every subtab, every dialog, screenshots, console log, timing metrics. |
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
```

Idempotent — re-running it re-reads `demo/out/creds.txt`, skips devices whose
IP already exists, and refreshes what it can. Every call is appended to
`demo/out/seed_log.json`.

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
ui/tab-*.png              one screenshot per tab
ui/sub-*.png              one per subtab
ui/dlg-*.png              one per dialog
ui/viewer-*.png               the same tabs as the read-only `viewer` account
ui/console-<count>.json   console errors/warnings, page errors, failed
                          requests, every HTTP response >= 400
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
* **No credential can be stored on Linux.** Every "save this password"
  endpoint goes through Windows DPAPI and refuses with a 400 off Windows —
  SNMPv3 auth passwords, the SMTP password, ConfigRX SSH passwords, DHCP
  server credentials. `seed.py` calls them anyway and records the exact
  refusal text in `seed_log.json` under `refusals`. That is intended evidence,
  not a failure.
* **ConfigRX backups will not succeed** without something answering SSH, and
  the credential above cannot be stored anyway. The seeding proves the
  configuration path, not a completed backup.
* **`GET /api/alerts` caps `limit` at 2000** (`netpath/web/api.py:2973`), so a
  very large outage can truncate the per-rule counts. `results-<count>.json`
  records `alerts_truncated` when it does.
* **`GET /api/nodes/devices` has no paging** — it returns the whole fleet in
  one JSON body. The UI walk measures how big that gets
  (`ui/metrics-<count>.json`, `devices_payload_bytes`).
* **There is no bulk device-add endpoint.** Seeding a fleet is one
  `POST /api/nodes/devices` per device; `seed.py` prints the rate it achieved,
  which is itself one of the measurements.
* **Ports 161/162/514 are shared.** If another copy of the fleet or the app is
  already running on the machine, the second one silently loses the race —
  check `app-<count>.log` and `fleet-<count>.log` before believing a zero.
