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

| suite | what it proves | stub |
|---|---|---|
| `test_nodepoll_e2e.py` | the poll chain end to end: scalars, IF-MIB tables, counters, flaps, reboots, a dark device, and the SNMP authentication events as transitions held by the poller (repeat failures, and an error alternating between auth and timeout, record one `auth_fail`; SNMP working again records exactly one `auth_ok`; a timeout that recovers records nothing) | in-process `StubAgent` |
| `test_nodediscover_e2e.py` | device and subnet discovery, promotion, the size guard, mid-sweep cancel | in-process `StubAgent` |
| `test_custom_mib_e2e.py` | a custom MIB uploaded through the API is polled under its own object name | `stub_agent_get_getnext.py` |
| `test_timeout_accuracy.py` | a walk that times out mid-table is reported as such, with the identity kept | `stub_agent_partial_timeout.py` |
| `test_wireless_poller.py` | the FortiGate AP tables land as access points and radios | `wireless_stub_agent.py` |
| `test_alert_operator_resolve.py` | an operator-resolved threshold alert (Nodes, NetPath and DHCP scope) does not re-open for the same breach run — a dip into the hysteresis band is not a clear and does not start a new one — but does after a real clear plus a fresh breach; an engine auto-resolve is never mistaken for one; and a hand-resolved rollup parent covers the children it was hiding while its condition holds — three devices down, their packet-loss alerts stay shut until a device answers again (past the resolve window too, announced once in the Nodes log), where acknowledging behaves the same as it always did | none — drives `AlertEngine` directly |
| `test_alerts_api.py` | the alert rows the web API hands the page: the device an alert resolves to (its own for a device alert, the parent switch for an interface one, none for anything outside Nodes or a device since removed), that no `device_name` is sent, and the device mute that hangs off it — muting from an interface alert lands on the switch, shows in the mute list and on the Nodes row, and is refused with 403 to a read-only account | none — a real `Service` + `WebServer` over loopback |
| `test_alerts_bulk_resolve.py` | the operator's own path for the same rule: three device outages resolved in one `POST /api/alerts/bulk-resolve` (`resolved: 3`), refused to a read-only account, and nothing re-opened or notified by the ticks that follow | none — a real `Service` + `WebServer` |
| `test_series_buckets.py` | `NodesDatabase.series(..., bucket_s=...)` bucket boundaries/avg/min/max, the `/series` API's `bucket_s` param and its window/2 cap, raw rows when `bucket_s=0` | none — no SNMP involved |
| `test_mac_tables.py` | GETBULK forwarding-table walks (request counts, tooBig fallback, v1 GETNEXT, the row cap) and the present/first-seen history the Find box searches | `stub_agent_fdb.py` |
| `test_ssh_hostkeys.py` | the shared SSH host-key store: fingerprints, the first connection storing a key, the same key touching last-seen, a changed key refused (by bytes, whatever its type), trust and forget, ConfigRX backing up behind all of it, that removing a device (singly or in bulk) leaves its key, and that Forget is ConfigRX write's — 403 for an `ssh`-write-only account | in-process `stub_ssh_device.py` (needs paramiko), plus a real `WebServer` for the route rules |
| `test_alert_engine_fixes.py` | the alert engine's 4.39.0 behaviour: cursors that advance only after a batch is applied (a poisoned occurrence is skipped, the rest still open), mail on a queue with a circuit breaker and the `smtp_failing` self-alert, `last_notified_ts` driving renotify from a per-tick sweep, trap and syslog identity keyed per source device and per message signature, the severity gate applied to traps, `auto_resolve_after_s`, `rules.notify`, `threshold_stale_s`, one keyed metric query per tick, and `upstream_id` rollup including the fan-out case | none — drives `AlertEngine` directly, with a `FakeMail` collector that can be told to raise |
| `test_poll_write_path.py` | the batched write path: one transaction per device poll rather than one per sample (a trace callback counts the COMMITs), `record_metric_samples` and `update_interface_rates`, `replace_interfaces` returning its id map, the per-metric row cap deleting the right rows and leaving a metric under the cap alone, and `compact_rollup` no longer deleting the raw samples it aggregated | in-process `StubAgent`, `stub_agent_iftable.py` |
| `test_scheduler.py` | the scheduler pass: statement count per steady pass at 300 devices, a settings or profile edit picked up through the config generation counter, and a raising `schedule_rows` setting `poller.error` without killing the thread | none |
| `test_collectors_hardening.py` | the receive loops surviving what used to kill them: a malformed NetFlow datagram followed by a good one, a zero-length template, v9 `0xFFFF`, dual-stack address selection, bounded caches, the targeted FTS delete against the rebuild, `reject_failed_auth` dropping forged v3 traps, the syslog framer requiring `<` after a length prefix, multiple structured-data elements, the timestamp clamp, and the per-source token bucket | fuzz corpora and in-process listeners |
| `test_parsers_hardening.py` | the fresh-eyes findings in the files the review never opened: `mibparse` parsing and resolving in linear time under a budget (with the shipped MIBs producing the same objects as before), no per-character copy and no `int()` escaping `parse()`, a textual-conventions-only module reporting success, one canonical vendor key per manufacturer and the Rockwell arc, `namelookup` leaving the process-global socket timeout alone and refusing an answer from a host it did not ask, the event log's target set bounded and cleared, the timeline's window and block ceilings, the console's bounded client list and its listener hint, IPAM's staggered and capped subnet scans, and the de-duplicated port-name table | none — pure parsing and in-process objects |
| `test_security_fixes.py` | the server-side gates, driven against a real `WebServer` on a high port with a temporary database: `must_change` refusing every route but the password change, the `debug`-scope settings escalation, `updates_enabled` refusing an update and a tampered tarball being rejected, the SMTP test refusing a stored password with a body-supplied host, database file modes, the response headers, community strings hidden from read-only accounts, the `admin` capability, audit rows surviving a restart, ConfigRX's `ssh_port` refused outside 1-65535 before it ever reaches a socket, the enable secret's three-way contract on the credential route (absent leaves a stored secret alone, present-and-empty clears it, present-and-non-empty replaces it) and `clear_credential` clearing both the SSH password and the enable secret rather than just the password, `/api/session` carrying the running version on both the unauthenticated sign-in branch and the authenticated one, `/api/config`'s `configrx_vendors` matching `configrx_vendors.VENDORS` exactly — same keys, same labels, same order, key and label only — and absent (not empty) for an account with no ConfigRX grant, and the enable-secret-only delete route clearing just `enable_secret_enc` while `ssh_password_enc` (proven by decrypting it back) and `ssh_username` stay put, refused without ConfigRX write, and a clean 400 rather than a traceback on an unknown device id | none — a real server |
| `test_web_gates.py` | the halves a browser cannot be trusted to hold: `must_change` refusing every route but the password change while `/api/state` and `/api/heartbeat` stay reachable to raise and hold the prompt; device address validation (a malformed address, a hostname, a truncated address and blank all refused, valid IPv4/IPv6 accepted, a duplicate refused); NetPath target host validation on both `POST /api/netpath/targets` and `PUT /api/netpath/targets/<id>` — the edit route was added to this check after a test written for the add route's validation found edit accepting the exact bad host add had just refused, with a refused edit leaving the stored host unchanged; `/api/state` and `/api/config`'s per-permission block shape (a limited account's own modules present, the rest absent, `permissions` naming exactly what was granted, both idle and absolute session countdowns carried); a strip toggle bumping `config_version`; and the kiosk heartbeat honoured only for a write-less account, without extending its own idle countdown on a refusal | none — a real `Service` + `WebServer` |
| `test_upgrade_from_previous.py` | databases in the previous release's shape open and migrate; with git history, the previous main commit creates every database and the current application starts on them; accounts migrated out of a legacy netpath.db get the permissions the upgrade owes them, once; an existing alerts.db gains the new hand-resolve index and loses the one it replaces | none — the previous release's own code |
| `test_wsock.py` | the WebSocket transport on its own: the handshake and its refusals, masked client frames, fragmentation (2 MB in 125-byte frames reassembled in linear time), ping/pong, the close handshake, the 2 MB cap, a peer that stops reading — the send times out, the parked reader is released and the socket still closes — and `close()`'s own receive-buffer drain (needed because Windows resets a connection closed with data still unread, discarding the close frame just written): bounded in time against a peer flooding 200 KB rather than reading, not inheriting a long send timeout another thread left on the shared socket, and still delivering the close code and its reason to the peer once the drain is done | none — a socketpair |
| `test_ssh_terminal.py` | the terminal end to end: the upgrade behind the `ssh` permission (403/401 before the hijack), a shell over the socket with ConfigRX's stored credential, keystrokes and output, `need-credentials` then `auth`, a changed host key and `trust`, the session caps (4429, application-wide and per account) and idle timeout (4408), the `Origin` rule (a missing or foreign origin is a 403 with no upgrade), a shell closing 4401 on sign-out and on a revoked `ssh` grant, five refused logins ending the session with each one audited and no password anywhere, `resize` before `open`, an `open` pipelined behind the handshake, the same conversation over TLS with output and keystrokes in flight at once, the device-event audit trail, and the one-time `ssh` permission backfill | in-process `StubDevice` (paramiko) |
| `test_settings_types.py` | settings values are typed: `POST /api/settings` refuses a `null` or non-numeric value with 400 before anything is written, a numeric string lands as an int, a one-key body leaves every other setting alone, a hand-poisoned settings row loads as its default, a `Service` still constructs on a poisoned database, and the numeric range guard exercised across the family rather than one representative key — `dns_workers` refused and accepted at both its floor (1) and ceiling (32), and `netpath_refresh_s`, `session_max_hours`, and the float `dns_timeout_s` each refused just outside their own floor and ceiling and accepted at the ceiling | none — a real `Service` + `WebServer` |
| `test_nodes_api_fixes.py` | `POST /api/nodes/devices` stores `upstream_id` and `vendor_override` (and refuses a bad one before the device exists), a device Test whose socket cannot be opened answers `snmp.ok: false` rather than 500, and the discovery probe drops a datagram from another address or with another request id | none — a real `Service` + `WebServer`, two loopback UDP sockets |
| `test_service_shutdown.py` | `Service.shutdown()` waits for a maintenance sweep in flight (forced from a settings save, or the timer) instead of closing databases under it, and two sweeps never overlap | none — a real `Service` |
| `test_db_reclaim.py` | `app.db`, `wireless.db` and `configrx.db` open in incremental auto-vacuum mode and shrink after their prunes without `VACUUM` | none |
| `test_poller_counters.py` | the poller's statistics counters stay exact under 50 threads bumping them at once | none |
| `test_configrx_cisco_platforms.py` | every Cisco persona in `demo/fake_ssh.py` backing up through the real capture chain: NX-OS and IOS-XR on IOS's own commands, an SG/CBS switch that rejects its own pager-off and pages anyway, a WLC whose privileged prompt ends `>` with no enable step, an ASA that escalates via `enable` and its stored secret before pager-off/show are ever sent (and is refused with a clear message on a wrong secret), the documented refusals still held by `cisco-truncate`/`unprivileged`, the `enable_secret_enc` column and its `set_credential`/`set_enable_secret`/`clear_enable_secret` contract, and one end-to-end backup through a real `Service`, the real (passphrase-file-backed) secret store and `ConfigRxWorker.backup_now` | in-process `stub_ssh_device.py` (needs paramiko), sharing personas with `demo/fake_ssh.py` |
| `test_frontend_contracts.py` | static invariants of the shipped frontend that no runtime test can see: no native `alert(`; every dialog goes through `App.modal`, and a destructive one through `App.confirmDestructive` rather than a hand-rolled Remove/Delete pair; the dialog body is a `<form class="modal-form">` whose primary button is the submit button, found by `.modal-buttons` rather than a `.row` a dialog body might have of its own; every dialog action runs through `runModalAction` rather than a bare `onclick` that drops the promise it returns; Escape and the backdrop both ask before discarding an edit through `requestCloseModal`; write gating (`applyWriteGate`) disables a control and shows why rather than hiding it; every write control in `MUST_BE_GATED` carries the `data-requires-write` module it writes to; the live region and the toast region each exist exactly once, the toast region hidden from assistive technology; a dialog body button is typed `type="button"` so only the primary submits; and three pieces of shared logic stay shared rather than reappearing per module — the write-only-if-changed guard (`setText`/`setBg`/`setHtml` and kin) lives in app.js alone, the device-by-ip/id cache in front of `/api/nodes/devices` is `App.deviceIndex` and nothing else, and the histogram range narrower is `App.plottedRange`, matched on each one's shape (a cache-hit idiom in front of the endpoint, a scan for the first/last non-empty bucket) rather than its name, since a module is free to rename what it must not re-implement | none — reads the shipped JS/HTML as text |
| `test_time_contracts.py` | one relative-time vocabulary and one background-worker vocabulary, read the same way: no module defines its own `ago(`, formats a `Date` with `toLocale*String` or `toISOString`, or draws a bare wall clock with `App.clock` outside app.js, which alone defines `ago`/`when`/`timeCell`/`agoCell`/`isoLocal`/`timeZoneLabel`/`countLabel`; Syslog and SNMP Trap's counts say "N of M shown", never a bare "N shown"; every `*_refresh_s` key the poll loop reads has a matching Settings input, including the Debug rate's integer floor; each module's status strip, start/stop toggle and Dashboard tile agree on one noun (poller, collector, receiver, worker); the wireless Poll now button and the route-expand toggle's label and `aria-pressed` follow the state they describe; and the time zone is named once in Settings and carried on the Syslog Time column | none — reads the shipped JS/HTML as text |
| `test_syslog_mib_dos_fixes.py` | two quadratic-time DoS regressions found by fuzzing decoders that take unauthenticated or uploaded input: `syslogparse`'s structured-data walk no longer costs O(elements²) as SD-ELEMENT count grows (500,000 tiny elements in under a second, 4,000,000 costing about the same, `MAX_SD_ELEMENTS` truncating the excess to message text rather than dropping it), and `mibparse`'s comment/string masking no longer costs O(markers × length) with no newline ahead (2,000,000 no-newline units in under three seconds, the identical content with newlines staying just as fast), plus a tiny real budget on a large no-newline file proving the masking loop's own deadline check fires from inside it rather than only between phases | none — pure parsing |
| `test_ups_environment.py` | UPS-MIB (RFC 1628) polling gated on one scalar GET before either table walk runs, the APC PowerNet-MIB TimeTicks runtime fallback tried only on APC's own arc once the standard scalar is empty, and ENTITY-SENSOR-MIB's device-level environmental poll classifying a temperature reading into `temp_optic_c`/`temp_ambient_c`/`temp_chassis_c` by port-mapping and humidity-sensor presence rather than one shared key | `stub_agent_ups_env.py` |
| `test_host_resources_mem.py` | the HOST-RESOURCES-MIB `mem_pct` fallback (`hrStorageRam`), tried only once none of UCD-SNMP, the Fortinet scalar or the Cisco memory pool has already answered it, sharing its `hrStorageTable` walk with the existing `disk_pct` fallback rather than paying for it twice | `stub_agent_host_resources.py` |
| `test_upstream_suggestions.py` | the upstream-suggestion review flow: a clean chassis-MAC match, a sysName-only match, an ambiguous device with more than one candidate, a stale neighbour rated down a confidence tier, a 2-device and a 3-device cycle refused outright by `_find_upstream_cycle`, a cycle that only completes through an edge already on file rather than one in the batch, a valid batch applied in one transaction, and the routes' own read/write gating | none — drives `NodesDatabase`/the API handlers directly |
| `test_configrx_search_compliance.py` | cross-device configuration search and named compliance rule sets against `ConfigRxDatabase` directly: a substring search finding the same line across several devices' captures through FTS5 and through the full-scan fallback for a too-short query; a bounded regular-expression search, and the three catastrophic-backtracking shapes `compile_bounded` refuses outright, each timed to confirm the refusal is cheap rather than merely the assertion passing; a line long enough to matter still bounded by the per-line length cap; the search index holding only redacted text regardless of what a `store_secrets` device's raw capture contains; a rule set passing some devices and failing others, with the failing rules named in the result; a device with no stored capture reading `not_assessed`, never a silent pass, and contributing no `compliance_fail_count` sample; a rule set scoped to one device group evaluating only devices in it; a rule's pattern and kind validated at `add_rule` time; and `forget_device` removing a device's search-index rows and compliance results along with its backups | none — drives the two modules directly against a real `ConfigRxDatabase`, no HTTP route exists yet |
| `test_report_availability.py` | `device_availability_report`'s own reasoning for what a gap in `device_status_segments` is *not* the same as "down": a window clipped to a device's `created_ts` with the excluded span reported rather than silently shrunk, a maintenance window's occurrences (including a weekly recurrence spanning the report window) excluded retroactively for any past span, a still-active mute's own `created_ts`/`until_ts` excluded the same way with the caveat that an already-expired-and-purged mute cannot be, and a segment longer than the gap-flag threshold carried forward from the last known status flagged in the device's own caveats rather than invented as down time | none — drives `report.py` against a real `NodesDatabase`/`AlertsDatabase` |
| `test_report_topn.py` | `top_metric_ranking`'s CROSS JOIN plan against a 2,000-device × 48-port × six-metric-family `samples_hourly` fixture, measured against the plain-JOIN plan SQLite would otherwise choose (45.8s vs. 14.2s across one week of hourly rows, and flat regardless of how many other metric families share the table, versus scaling with the whole table) — the exact numbers `report.py`'s own docstring and the API's fleet-wide refusal threshold are measured against | none — drives `report.py` against a real `NodesDatabase` fixture |

Adding a suite: import `_paths` first (it puts the repo root on `sys.path`),
use `spawn_stub("<script>.py")` for an agent, and keep the file name
`test_*.py` so the runner finds it. A stub must print one line containing
"listening" to stdout, flushed, after it has bound its socket.

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
and failed request it saw. `PERFORMANCE_REVIEW.md` used to claim its table-diff
work was "verified with a Playwright test" when no such test was in the
repository; this is that test, and the CI workflow's `ui-walk` job runs it on
every push.

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
