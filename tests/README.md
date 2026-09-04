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
| `test_security_fixes.py` | the server-side gates, driven against a real `WebServer` on a high port with a temporary database: `must_change` refusing every route but the password change, the `debug`-scope settings escalation, `updates_enabled` refusing an update and a tampered tarball being rejected, the SMTP test refusing a stored password with a body-supplied host, database file modes, the response headers, community strings hidden from read-only accounts, the `admin` capability, and audit rows surviving a restart | none — a real server |
| `test_upgrade_from_previous.py` | databases in the previous release's shape open and migrate; with git history, the previous main commit creates every database and the current application starts on them; accounts migrated out of a legacy netpath.db get the permissions the upgrade owes them, once; an existing alerts.db gains the new hand-resolve index and loses the one it replaces | none — the previous release's own code |
| `test_wsock.py` | the WebSocket transport on its own: the handshake and its refusals, masked client frames, fragmentation (2 MB in 125-byte frames reassembled in linear time), ping/pong, the close handshake, the 2 MB cap, and a peer that stops reading — the send times out, the parked reader is released and the socket still closes | none — a socketpair |
| `test_ssh_terminal.py` | the terminal end to end: the upgrade behind the `ssh` permission (403/401 before the hijack), a shell over the socket with ConfigRX's stored credential, keystrokes and output, `need-credentials` then `auth`, a changed host key and `trust`, the session caps (4429, application-wide and per account) and idle timeout (4408), the `Origin` rule (a missing or foreign origin is a 403 with no upgrade), a shell closing 4401 on sign-out and on a revoked `ssh` grant, five refused logins ending the session with each one audited and no password anywhere, `resize` before `open`, an `open` pipelined behind the handshake, the same conversation over TLS with output and keystrokes in flight at once, the device-event audit trail, and the one-time `ssh` permission backfill | in-process `StubDevice` (paramiko) |
| `test_settings_types.py` | settings values are typed: `POST /api/settings` refuses a `null` or non-numeric value with 400 before anything is written, a numeric string lands as an int, a one-key body leaves every other setting alone, a hand-poisoned settings row loads as its default, and a `Service` still constructs on a poisoned database | none — a real `Service` + `WebServer` |
| `test_nodes_api_fixes.py` | `POST /api/nodes/devices` stores `upstream_id` and `vendor_override` (and refuses a bad one before the device exists), a device Test whose socket cannot be opened answers `snmp.ok: false` rather than 500, and the discovery probe drops a datagram from another address or with another request id | none — a real `Service` + `WebServer`, two loopback UDP sockets |
| `test_service_shutdown.py` | `Service.shutdown()` waits for a maintenance sweep in flight (forced from a settings save, or the timer) instead of closing databases under it, and two sweeps never overlap | none — a real `Service` |
| `test_db_reclaim.py` | `app.db`, `wireless.db` and `configrx.db` open in incremental auto-vacuum mode and shrink after their prunes without `VACUUM` | none |
| `test_poller_counters.py` | the poller's statistics counters stay exact under 50 threads bumping them at once | none |

Adding a suite: import `_paths` first (it puts the repo root on `sys.path`),
use `spawn_stub("<script>.py")` for an agent, and keep the file name
`test_*.py` so the runner finds it. A stub must print one line containing
"listening" to stdout, flushed, after it has bound its socket.

## The browser checks (`tests/ui/`)

`tests/ui/walk.mjs` is the one part of this directory that is not a plain Python
script and not standard-library-only: it drives a real Chromium through
Playwright, because the things it checks — that a table has `scope` and
`aria-sort`, that focus returns to the trigger when a dialog closes, that a hash
route restores a selection, that no page error is thrown across twelve tabs —
cannot be checked any other way. It is deliberately outside `run_all.py`, which
stays dependency-free.

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

Two exceptions to "no dependencies": `stub_ssh_device.py` is a real paramiko
SSH server, imported in-process rather than spawned (there is no `sshd`
here, and no banner to wait for — construct `StubDevice()` and read
`.port`), and `test_ssh_terminal.py` and `test_ssh_hostkeys.py` need
paramiko itself. A suite that cannot run for want of an optional dependency
exits `77` after printing why; `run_all.py` reports that as SKIP rather than
FAIL, and says "no suites ran" if that is all that happened.
