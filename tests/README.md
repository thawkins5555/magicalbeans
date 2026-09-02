# Tests

Plain Python scripts, standard library only, like the application itself. No
pytest, no network, no `ping` binary, no root: every suite that needs an SNMP
agent starts its own stub (`tests/stubs/`) as a child process on a free loopback
UDP port, points the module under test at that port, and kills it when done.
Databases go to a fresh temporary directory per run.

```
python3 tests/run_all.py              # every suite, PASS/FAIL per file
python3 tests/run_all.py --only mib   # suites whose filename contains "mib"
python3 tests/test_wireless_poller.py # one suite on its own
```

Each suite exits non-zero on the first failed assertion and prints what it
was checking. `run_all.py` shows the last lines of a failing suite's output.

| suite | what it proves | stub |
|---|---|---|
| `test_nodepoll_e2e.py` | the poll chain end to end: scalars, IF-MIB tables, counters, flaps, reboots, a dark device | in-process `StubAgent` |
| `test_nodediscover_e2e.py` | device and subnet discovery, promotion, the size guard, mid-sweep cancel | in-process `StubAgent` |
| `test_custom_mib_e2e.py` | a custom MIB uploaded through the API is polled under its own object name | `stub_agent_get_getnext.py` |
| `test_timeout_accuracy.py` | a walk that times out mid-table is reported as such, with the identity kept | `stub_agent_partial_timeout.py` |
| `test_wireless_poller.py` | the FortiGate AP tables land as access points and radios | `wireless_stub_agent.py` |
| `test_alert_operator_resolve.py` | an operator-resolved threshold alert (Nodes and NetPath) does not re-open for the same breach run, but does after a clear plus a fresh breach; an engine auto-resolve is never mistaken for one | none — drives `AlertEngine` directly |
| `test_series_buckets.py` | `NodesDatabase.series(..., bucket_s=...)` bucket boundaries/avg/min/max, the `/series` API's `bucket_s` param and its window/2 cap, raw rows when `bucket_s=0` | none — no SNMP involved |
| `test_mac_tables.py` | GETBULK forwarding-table walks (request counts, tooBig fallback, v1 GETNEXT, the row cap) and the present/first-seen history the Find box searches | `stub_agent_fdb.py` |
| `test_ssh_hostkeys.py` | the shared SSH host-key store: fingerprints, the first connection storing a key, the same key touching last-seen, a changed key refused (by bytes, whatever its type), trust and forget, ConfigRX backing up behind all of it, that removing a device (singly or in bulk) leaves its key, and that Forget is ConfigRX write's — 403 for an `ssh`-write-only account | in-process `stub_ssh_device.py` (needs paramiko), plus a real `WebServer` for the route rules |
| `test_upgrade_from_previous.py` | databases in the previous release's shape open and migrate; with git history, the previous main commit creates every database and the current application starts on them; accounts migrated out of a legacy netpath.db get the permissions the upgrade owes them, once | none — the previous release's own code |
| `test_wsock.py` | the WebSocket transport on its own: the handshake and its refusals, masked client frames, fragmentation (2 MB in 125-byte frames reassembled in linear time), ping/pong, the close handshake, the 2 MB cap, and a peer that stops reading — the send times out, the parked reader is released and the socket still closes | none — a socketpair |
| `test_ssh_terminal.py` | the terminal end to end: the upgrade behind the `ssh` permission (403/401 before the hijack), a shell over the socket with ConfigRX's stored credential, keystrokes and output, `need-credentials` then `auth`, a changed host key and `trust`, the session caps (4429, application-wide and per account) and idle timeout (4408), the `Origin` rule (a missing or foreign origin is a 403 with no upgrade), a shell closing 4401 on sign-out and on a revoked `ssh` grant, five refused logins ending the session with each one audited and no password anywhere, `resize` before `open`, an `open` pipelined behind the handshake, the same conversation over TLS with output and keystrokes in flight at once, the device-event audit trail, and the one-time `ssh` permission backfill | in-process `StubDevice` (paramiko) |

Adding a suite: import `_paths` first (it puts the repo root on `sys.path`),
use `spawn_stub("<script>.py")` for an agent, and keep the file name
`test_*.py` so the runner finds it. A stub must print one line containing
"listening" to stdout, flushed, after it has bound its socket.

Two exceptions to "no dependencies": `stub_ssh_device.py` is a real paramiko
SSH server, imported in-process rather than spawned (there is no `sshd`
here, and no banner to wait for — construct `StubDevice()` and read
`.port`), and `test_ssh_terminal.py` and `test_ssh_hostkeys.py` need
paramiko itself. A suite that cannot run for want of an optional dependency
exits `77` after printing why; `run_all.py` reports that as SKIP rather than
FAIL, and says "no suites ran" if that is all that happened.
