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
| `test_ssh_hostkeys.py` | the shared SSH host-key store: fingerprints, the first connection storing a key, the same key touching last-seen, a changed key refused (by bytes, whatever its type), trust and forget, and ConfigRX backing up behind all of it | in-process `stub_ssh_device.py` (needs paramiko) |
| `test_upgrade_from_previous.py` | databases in the previous release's shape open and migrate; with git history, the previous main commit creates every database and the current application starts on them | none — the previous release's own code |

Adding a suite: import `_paths` first (it puts the repo root on `sys.path`),
use `spawn_stub("<script>.py")` for an agent, and keep the file name
`test_*.py` so the runner finds it. A stub must print one line containing
"listening" to stdout, flushed, after it has bound its socket.
