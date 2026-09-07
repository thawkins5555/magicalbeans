# SappiWhere — Internals

What `FEATURES.md` describes from the outside, this describes from the
inside: which file does the work, which function, and the actual mechanism
— algorithms, wire formats, schema, threading. `README.md` is setup;
`NETWORK-AND-STORAGE-REQUIREMENTS.md` is ports and files;
`CREDENTIAL-SECURITY.md` is exactly how secrets are protected, in more
depth than the summary here. This is the one to open when something needs
fixing, not just using.

## Contents

- [Layout](#layout) — the file map
- [Process model](#process-model) — threads, who owns which loop
- [Data layer](#data-layer) — the thirteen databases, migrations, retention
- [Nodes](#nodes) — the SNMP poller, the wire, the scheduler, the write path
- [MAPPER](#mapper) — link assembly, the render plan, VLAN membership
- [Alerts](#alerts) — occurrences, dedup keys, rollup, notification
- [NetPath](#netpath) · [NetFlow](#netflow) · [SNMP Trap](#snmp-trap) · [Syslog](#syslog) · [IPAM](#ipam)
- [Self-update (`selfupdate.py`)](#self-update-selfupdatepy)
- [Auth (`auth.py`)](#auth-authpy) · [Permissions](#permissions-permissionspy-appdbs-user_permissions)
- [Wireless](#wireless-nodeoidspy-wirelessdbpy-fortipollpy) · [ConfigRX](#configrx-configrxdbpy-configrxpy)
- [Web layer](#web-layer) — routing, the API, the browser application
- [Tests (`tests/`)](#tests-tests)

## Layout

```
netpath/
  __main__.py      CLI entry point, argument parsing, run_headless / run_console
  console.py       the service console window (PySide6)
  selfupdate.py    self-update: check, download, swap, restart
  tracer.py        runs traceroute/tracert, parses output
  db.py            NetPath's SQLite: targets, traces, hops
  monitor.py       Monitor (trace scheduler), Resolver (reverse DNS)
  analysis.py      traces -> topology graph, traces -> timeline buckets
  theme.py         palettes, fonts, stylesheet for the console window
  nfdecode.py      NetFlow v5/v9/IPFIX decoding, template cache
  collector.py     NetFlow UDP listener and batched writer
  flowdb.py        flow storage, settings, aggregation queries
  services.py      port/protocol names, byte/rate formatting
  syslogparse.py   RFC 3164 / RFC 5424 parsing
  syslogd.py       syslog UDP/TCP listener
  syslogdb.py      syslog storage, rollup counts, FTS5 trigram search
  trapdecode.py    SNMP trap BER/ASN.1 decode + encode, v3 USM auth;
                   well-known OID names, enum tables, default severities
  snmptrapd.py     SNMP trap UDP listener
  snmptrapdb.py    SNMP trap storage, rollup counts
  namelookup.py    reverse DNS: system resolver, direct PTR query, nslookup;
                   shared "best display name for an IP", used by Syslog,
                   Alerts and NetPath alike
  worker.py        subprocess launch without a console window; ago(ts)
                   elapsed-time formatting; the Worker mixin background
                   workers subclass for start/stop/status plumbing
  auth.py          password hashing, sessions, login throttling
  eventlog.py      bounded in-memory event buffer
  appdb.py         app.db: global settings, users, shared reverse-DNS cache
  dpapi.py         Windows DPAPI wrapper for the stored DHCP credential
  ipamdb.py        ipam.db: subnets, hosts, conflicts, DHCP scopes/leases
  ipam_scan.py     ping sweep, ARP table read, MAC normalization
  ipam_dhcp.py     PowerShell scripts that query a DHCP server
  ipam_worker.py   IPAM scheduler: subnet scans, DHCP polls, conflict checks
  nodeoids.py      built-in polled-metric OID catalog for the Nodes poller;
                   also the OID constants for FortiGate Wireless Controller
                   polling
  nodepoll.py      NodePoller: the per-device SNMP/ping scheduler
  nodesdb.py       nodes.db: devices, profiles, interfaces, state
                   events, discovery jobs; the facade over the two below
  nodesseriesdb.py nodes_series.db: metrics, samples, samples_hourly
  nodesmibdb.py    nodes_mibs.db: mib_files, mib_objects
  nodediscover.py  per-device/subnet discovery: ping sweep + best-effort
                   SNMP v1/v2c identification
  snmppoll.py      SNMP wire format for the Nodes poller: GET/GETNEXT/
                   GETBULK builders, response decoder, v1/v2c/v3 assembly
  vendorid.py      vendor identification from a device's populated
                   enterprise OID arcs
  enterprises.py   IANA enterprise-number -> vendor table
  mibcatalog.py    curated catalog of vendor MIB bundles, installed on
                   demand
  mibparse.py      stdlib-only, best-effort MIB text parser
  alertsdb.py      alerts.db: rules, open/acked/resolved alerts,
                   templates, notification history, SMTP settings
  alertrules.py    alert rule/occurrence matching, flapping and
                   threshold hysteresis evaluators
  alertengine.py   AlertEngine: the 5-second evaluation scheduler,
                   drains events/traps/syslog/IPAM into alerts
  alertmail.py     alert email: {{token}} template rendering, stdlib SMTP
  fortipoll.py     WirelessPoller: polls FortiGate controllers for
                   managed APs over SNMP
  wirelessdb.py    wireless.db: controller storage and SNMP credentials
  configrxdb.py    configrx.db: backup config storage, keyed to Nodes'
                   device ids
  configrx.py      ConfigRxWorker: scheduled read-only SSH config pulls;
                   per-vendor allow-list of the exact commands a backup
                   may send over SSH
  configrx_redact.py      strips secrets from a captured config before
                   it is stored
  configrx_compliance.py  cross-device search over stored configs, with a
                   bounded-regex compiler; rule sets: must/must-not-match
                   checks against each device's latest capture
  hostkeys.py      remembered SSH host keys, shared by ConfigRX and the
                   SSH terminal
  sshterm.py       interactive SSH sessions for the browser terminal,
                   over a WebSocket
  permissions.py   the per-module read/write permission model
  report.py        availability and link-saturation reports, from
                   history Nodes and Alerts already keep
  sqlitebase.py    the `SqliteStore` base class every database module
                   subclasses (open/pragma/migrate/close, settings,
                   trim/reclaim); opens a SQLite file with owner-only
                   file permissions, incremental-vacuum space
                   reclamation without VACUUM's stop-the-world lock,
                   and settings-dict type coercion
  secretstore.py   portable secret store: passphrase-derived key,
                   stand-in for DPAPI off Windows
  ldapclient.py    minimal LDAPv3 simple-bind client for directory auth
  udpsock.py       dual-stack UDP bind and drop-counter helpers, and
                   the `UdpReceiver` base class the three collectors
                   subclass
  web/
    __init__.py    exports Service and WebServer
    service.py     Service: owns every database and background worker
    api.py         JSON endpoint handlers, one function per route
    server.py      HTTP(S) server, routing, sessions, static files
    wsock.py       RFC 6455 WebSocket framing, server side, stdlib only
    static/        the browser interface
tests/
  run_all.py       runs every tests/test_*.py as its own process, PASS/FAIL per file
  _paths.py        repo root on sys.path, free ports, spawn_stub() for a child stub agent
  stubs/           minimal UDP SNMP agents the end-to-end suites talk to
  test_*.py        the suites themselves (see tests/README.md)
```

## Process model

One process, several threads, no external dependencies beyond the standard
library (PySide6 only for the console window). `netpath/__main__.py`'s
`main()` builds a `Service` (`web/service.py`), which opens thirteen SQLite
connections and starts every background worker, then either hands it to a
`WebServer` alone (`--headless`) or to both a `WebServer` and a
`ConsoleWindow` (default). Every module below is a thread or a pool of
threads owned by `Service`; there is no separate process for any collector
or scheduler.

Most of these workers — `Monitor`, `Resolver` and `AsnResolver` (all in
`monitor.py`), `NodePoller`, `WirelessPoller`, `AlertEngine`,
`ConfigRxWorker`, `IpamWorker`, and `alertmail`'s `MailQueue`/
`WebhookQueue` — mix in `worker.Worker` (`netpath/worker.py`) rather than
each hand-rolling the same thread handle, counter bump and status ladder:
`running` (is the thread alive), `_spawn`/`_join` (start/stop the thread),
`_bump(key)` (a locked counter increment), and `status_text()` (falls back
through an error, then `STOPPED_TEXT`, then the worker's own
`_running_text()`). `worker.py` also holds `hidden()` — keyword arguments
that suppress a console window for a spawned subprocess, used by `tracer.py`
and `ipam_scan.py` — and `ago(ts)`, the one relative-time wording
(`"3m ago"`) every status strip's elapsed-time text is built from.

`Service.start()` order matters: `Monitor` (traces) and `Resolver`
(reverse DNS) start first, then the NetFlow `Collector` and
`SyslogCollector` if enabled, then the `IpamWorker`, then a syslog
full-text index backfill kicks off in the background if needed. `Service.
shutdown()` reverses it, draining in-flight traces (`Monitor.drain()`,
up to 3 seconds) before closing any database, since a trace still running
when its database closes raises inside the worker thread and loses the
measurement.

**`main()` reconfigures stdout/stderr for line buffering before anything
prints — 4.49.0.** CPython only line-buffers a stream attached to a real
terminal; redirected to a file or a pipe, exactly what a service manager
gives it, both switch to block buffering and hold output in an 8 KB buffer
until it fills or the process exits. That's invisible in the console window,
where every `print()` appears to work, which is exactly how it went
unnoticed: nothing here is wrong until something downstream is watching the
log rather than the terminal. Measured: `python -m netpath --headless` with
stdout redirected to a file left the log completely empty after 120 seconds
while the server was already answering requests the whole time; the same
command with `-u` printed its banner in 1.2 s (`demo/scenario.py` already
passed `-u`, which is how this stayed hidden through every campaign that used
the demo harness). The consequence that matters most: the line that never
arrived under the bug is `WARNING: serving on <host> without TLS. Sign-ins …
travel in the clear` — the one warning whose entire job is to reach someone
before they put a password on an unencrypted page. `_line_buffer_stdio()`
calls `sys.stdout.reconfigure(line_buffering=True)` and the same for
`sys.stderr`, once, at the top of `main()`, rather than adding `flush=True`
to each of the module's `print()` call sites individually; `reconfigure` is
`None` under `pythonw.exe` (no console at all) and the call is skipped
there, and any `AttributeError`/`ValueError`/`OSError` — a stream already
detached or replaced — is swallowed rather than crashing startup over a
cosmetic improvement.

**`Service.shutdown()` now actually drains the node poller and the
wireless poller before closing their databases — 4.49.0.** Both were
called with `.stop()`, where every other worker on the list is called with
`.shutdown()`; `NodePoller.shutdown()` existed but was itself only
`self.stop()` under a different name, and `WirelessPoller` had no
`shutdown()` at all. Neither poller's in-flight work was ever given a
chance to finish before the database underneath it closed. Both now
compute `_inflight_budget_s()` — for every device the poller is currently
mid-poll on, the longest that specific poll could still legitimately run
given that device's own configured ping/SNMP timeouts and retries (and, if
it has more than one stored credential to try, one more probe budget on
top), capped at a 30-second ceiling so one misconfigured device cannot
hang a restart indefinitely — and `shutdown(drain_s=0.0)` waits
`max(drain_s, self._inflight_budget_s())` for it, mirroring
`Monitor._inflight_budget_s`, the identical idea already in place for the
trace scheduler this class was copied from.

## Data layer

Thirteen SQLite files, every `*Database` class subclassing `SqliteStore`
(`netpath/sqlitebase.py`). `sqlitebase.connect()` opens the file at
owner-only permissions (mode 0600, POSIX only) and sets `busy_timeout=5000`,
`cache_size=-20000` and `mmap_size=268435456` once, here, so no module can
forget one. `SqliteStore.__init__` then runs, under the store's own `RLock`
(every database now uses an `RLock`, where some previously used a plain
`Lock`; `check_same_thread=False` lets any worker thread use the connection
directly, so something has to serialise them): the uniform `PRAGMAS` —
`journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON` by default;
`netpath.db`, `ipam.db` and `app.db` override the tuple to keep
`synchronous=FULL`, as they always had — then `_before_schema()`
(appdb's hook to read the file as it was before `SCHEMA` runs),
`enable_incremental_vacuum()` (see below), the class's own `SCHEMA` string
of `CREATE TABLE IF NOT EXISTS` statements, `_migrate()`, a commit, and
finally `_after_open()` (nodesdb and alertsdb seed rows here, once the
schema is in place). `_migrate()` calls `self.ensure_columns(table,
columns)` for whichever columns are missing — it diffs `PRAGMA
table_info(<table>)` against what the code now expects, issues `ALTER TABLE
... ADD COLUMN` for the difference, and returns the names actually added so
a caller can gate a one-time backfill on it — because `CREATE TABLE IF NOT
EXISTS` silently leaves an existing table alone, an upgraded install needs
the new columns added explicitly or the first write touching them fails.

**Indexes on migrated columns go in `_migrate()`, never in `SCHEMA`.** The
schema script runs first, and `CREATE TABLE IF NOT EXISTS` on an existing
table adds nothing, so a `CREATE INDEX` in that script that names a column
the migration is about to add fails with "no such column" on every database
from an earlier release — and `executescript` aborts the whole script, so
nothing opens. A fresh database never shows it, which is exactly why a test
suite that starts from empty files cannot catch it. 4.34.0 shipped one of
these (`ix_mac_entries_mac_present`) and would not start on an upgraded
install; `tests/test_upgrade_from_previous.py` now opens databases in the
previous release's shape, and `nodesdb.py` carries the rule at both the
schema and the migration site.

**Settings** are `SqliteStore.settings()`/`save_settings()`: a flat
`key`/`value` table, JSON-encoded, read back against the class's own
`DEFAULTS` dict and coerced to each default's type
(`sqlitebase.coerce_settings`, tolerant here — a value that will not coerce
is replaced by its default rather than raising, so a database already
holding a bad value still starts the service). `save_settings` writes only the keys it
owns, so one merged settings dict can be handed to every store in turn and
each takes only what it recognises; `alertsdb` and `configrxdb` wrap both
methods with their own credential/webhook handling before calling `super()`.

**Size caps** share one algorithm, `SqliteStore.trim_to_size(max_bytes,
budget_s=None)`: while `_trim_size()` (`size_bytes()` by default — the file
plus its `-wal`/`-shm` — unless overridden) is over the cap, find the id
span of `TRIM_TABLE`, delete down to `TRIM_FLOOR` rows in adaptive
lock-bounded batches (`_delete_batches`, whose chunk size backs off when one
batch holds the write lock too long and grows again when it doesn't) via
`_trim_delete`, then reclaim the freed pages in short slices through
`enable_incremental_vacuum`'s incremental-vacuum path rather than a
blocking `VACUUM` — the write lock is the one the ingest thread needs, and
holding it across a whole-file rewrite stalls ingest for seconds at a time.
Capped at 40 delete/reclaim passes so a runaway cap setting can't loop
forever. `db.py`'s `Database` overrides `_trim_size` to `live_size_bytes()`
(free pages a prune hasn't reclaimed yet would otherwise look like rows
still inside the retention window) and `_trim_delete` to remove a trace's
hops before the trace row itself; `syslogdb.py` routes `_trim_delete`
through its own FTS-aware `_delete_logs()` so the search index and the
message rows never disagree; `nodesdb.py` and `alertsdb.py` keep their own
`trim_to_size()` entirely, since each spans several tables rather than one
dominant one. `Service.run_maintenance()` (`web/service.py`) calls
`Service._trim_db()` for each of the eight databases that has a
`max_*_db_mb` setting (netpath, flow, syslog, snmp, ipam, nodes,
nodes_series, alerts — not `app.db`, `wireless.db`, `configrx.db`,
`mapper.db` or `nodes_mibs.db`, none of which has a size cap), plus the
day-based retention prunes for each module,
`AppDatabase.prune_hostnames()` for the reverse-DNS cache and
`AppDatabase.prune_asn_cache()` for the ASN/owner cache. `nodes.db`'s own
retention prune now covers `vlans`/`vlan_ports`/`port_vlans` too
(`prune_vlans`/`prune_vlan_ports`/`prune_port_vlans`, called from
`run_maintenance` on the same `mac_table_retention_days` clock as
`prune_neighbors` — see MAPPER below for why that clock rather than a
fourth setting).

| File | Owner class | Holds |
| --- | --- | --- |
| `app.db` | `AppDatabase` (`appdb.py`) | global settings, `users`, `user_permissions` (per-account per-module read/write grants), `hostnames` (the shared reverse-DNS cache), `asn_cache` (ASN/owner per address, long TTL), a `meta` table for one-off markers like the update-installed commit |
| `netpath.db` | `Database` (`db.py`) | `targets`, `traces`, `hops`, `hop_stats` (cumulative continuous-probe counters per target/hop), NetPath's own settings |
| `flows.db` | `FlowDatabase` (`flowdb.py`) | `flows`, `exporters`, `interfaces`, NetFlow's own settings |
| `syslog.db` | `SyslogDatabase` (`syslogdb.py`) | `logs`, `log_counts` (hourly rollup), the FTS5 index, Syslog's own settings |
| `ipam.db` | `IpamDatabase` (`ipamdb.py`) | `subnets`, `hosts`, `conflicts`, `scans`, `dhcp_servers`, `dhcp_scopes`, `dhcp_leases`, `dhcp_scope_history` (leased-IP trend), IPAM's own settings |
| `nodes.db` | `NodesDatabase` (`nodesdb.py`) | `groups` (polling profiles), `device_groups` (organizational, unrelated to `groups`), `devices`, `interfaces`, `device_events`/`interface_events`, `discovery_jobs`/`discovery_results`, `vlans`/`vlan_ports`/`port_vlans` (per-port VLAN membership, for MAPPER), `mac_entries`, `neighbors`, `device_addresses`, `vendor_learned`, Nodes' own settings. Also the facade over the two files below |
| `nodes_series.db` | `NodesSeriesDatabase` (`nodesseriesdb.py`) | `metrics`, `samples`, `samples_hourly` — the Nodes tables that grow |
| `nodes_mibs.db` | `NodesMibDatabase` (`nodesmibdb.py`) | `mib_files` (including each file's original text), `mib_objects` |
| `alerts.db` | `AlertsDatabase` (`alertsdb.py`) | `rules`, `templates`, `alerts`, `notifications`, `meta` (per-source evaluation cursors), `smtp_credential`, `device_thresholds` (per-device threshold-rule overrides), Alerts' own settings |
| `snmptraps.db` | `SnmpTrapDatabase` (`snmptrapdb.py`) | `traps` (received traps and informs, decoded), `trap_counts` (hourly rollup), SNMP Trap's own settings |
| `wireless.db` | `WirelessDatabase` (`wirelessdb.py`) | `controllers` (each with its own SNMP credential columns), `access_points`, `radios`, Wireless' own settings |
| `configrx.db` | `ConfigRxDatabase` (`configrxdb.py`) | `device_config` (per-device backup settings, SSH credential and optional enable secret, keyed by a Nodes device id with no real FK), `backups` (zlib-compressed, hash-deduped), ConfigRX's own settings |
| `mapper.db` | `MapperDatabase` (`mapperdb.py`) | `maps`, `map_nodes` (devices/unmanaged peers placed on a map, and where), `vlan_colors` (a global VLAN colour override, not per-map), Mapper's own settings |

---

### Nodes split (5.0.0)

Until 4.54 `nodes.db` held everything the module knows: the device
inventory *and* every metric definition, every raw sample, every hourly
rollup, and the full text of every uploaded MIB. Those last five tables are
the only ones that grow — `samples` dominates the write rate,
`samples_hourly` dominates the size, `metrics` is a large static table, and
a vendor MIB bundle is a multi-megabyte lump sitting in the middle of the
poller's hot write path. A size cap on that one file could not trim history
without also being a cap on the inventory, and every metric write contended
with every page read.

5.0.0 splits them into `nodes_series.db` (`nodesseriesdb.py`) and
`nodes_mibs.db` (`nodesmibdb.py`), opened as siblings of whatever path
`--nodes-db` resolved to (`nodes.db` → `nodes_series.db`, derived from the
stem so two stores in one directory never share a pair). There is no new
constructor argument and no new CLI flag, the same precedent `mapper.db`
set. `NodesDatabase` keeps every public name it had: the series and MIB
methods forward to `self.series_db` / `self.mib_db` in one contiguous
delegation block, and only the handful that genuinely need both sides are
composed rather than forwarded — `metrics_for_keys` drops disabled devices
in Python, `top_metric` ranks in the series file and names the devices from
this one, `remove_device`/`bulk_remove_devices` follow through to
`delete_metrics_for_devices`, `remove_mib_file` NULLs
`devices.mib_file_id`/`groups.mib_file_id` itself, and
`report.top_metric_ranking` aggregates in `nodes_series.db` and resolves
names with one bounded `devices_by_ids`. Cross-file ids are plain integers,
already the convention (`configrx.device_config`, `mapper.map_nodes`).

**Why the migration rebuilds two tables.** `devices.mib_file_id` and
`groups.mib_file_id` were added by `ensure_columns` with `REFERENCES
mib_files(id) ON DELETE SET NULL`. After `DROP TABLE mib_files` every
INSERT and DELETE on either table fails with "no such table", and a DROP
with `foreign_keys=ON` fires SET NULL over every assignment on the way out.
SQLite cannot alter a constraint, so phase 1 rebuilds both tables from
their own stored `sqlite_master.sql` with the clause removed: commit,
`PRAGMA foreign_keys=OFF` (a no-op inside a transaction, hence the commit
first), create `__split_rebuild` from the edited DDL, copy, count-check,
drop, rename, `PRAGMA foreign_key_check`, `foreign_keys=ON`.

**The three phases**, marked by the private setting `split_state` in
`nodes.db` (absent = fresh 5.0 or never split, `rollups` = phase 1 done,
`done` = finished):

1. Synchronous in `_before_schema()`, and re-runnable — nothing in
   `nodes.db` changes until the rebuild at the end, so an interrupted run
   leaves a file 4.x can still open and simply starts over. The series
   store ATTACHes `nodes.db` and copies `metrics` with their ids intact,
   counts are verified, the raw samples *since* `rollup_watermark_hour` are
   summarised into the new `samples_hourly` (raw samples are not copied —
   they expire in three days — so this is what bounds the loss to the
   current partial hour), the MIB store imports `mib_files` and
   `mib_objects`, and then the two tables are rebuilt.
2. `Service.start()`'s `netpath-nodes-split` thread calls
   `continue_split()`, which lifts `samples_hourly` across in rowid-cursor
   batches of 20,000 with the cursor persisted in the same transaction as
   the rows it covers, an adaptive batch size, and `INSERT OR IGNORE`
   guarded by an `EXISTS` on `metrics`. It honours the service's stop
   event; `shutdown()` joins the thread before any database closes.
   Meanwhile `series()` merges the not-yet-copied legacy rollup rows into
   any window wider than `RAW_WINDOW_S`, so a year-wide chart is complete
   throughout.
3. `_finish_split()` re-checks that no legacy rollup row is missing (one
   retry, for a row a poll added behind the cursor), drops the five legacy
   tables with `foreign_keys=OFF`, sets the marker to `done`, and reclaims
   in incremental slices for up to 120 seconds. `finish_split_now()` is the
   synchronous entry point for tests and the demo seeder.

Every ATTACH is detached again, including on the way out of an exception:
an ATTACH left open makes every later `VACUUM` fail, and `reclaim()` runs
from the maintenance timer without knowing a migration ever happened.

A 4.x binary can still open `nodes.db` until phase 3 completes, and not
after.

`nodes.db` itself is now almost static, so its `trim_to_size` trims the
oldest 15% of `device_events`/`interface_events` (floor 5,000 each) — the
only unbounded tables it has left — while `max_nodes_series_db_mb` (default
1024) caps the metric history. `nodes_mibs.db` is deliberately uncapped: a
MIB is not history, and trimming it would silently stop traps decoding.

---

## Nodes

### Wire format (`snmppoll.py`)

Every BER/ASN.1 primitive (`Reader`, tag constants, `_signed`/`_unsigned`/
`_oid`/`_decode_value`, `_tlv`/`enc_int`/`enc_unsigned`/`enc_octets`/
`enc_oid`/`enc_varbind`) is imported from `trapdecode.py`, not
duplicated — this file is purely the poller-specific half (request
building, response decoding) of the same wire format the trap receiver
already decodes. `build_request()` builds GET/GETNEXT/GETBULK/SET for
v1/v2c; for GETBULK the second and third integers after request-id are
non-repeaters/max-repetitions rather than error-status/error-index — same
wire position (RFC 3416 §3), different meaning, so the caller has to know
which PDU it's building. `decode_response()` is the mirror of the trap
decoder's own decode path, reused for both a real Response-PDU and (in
the self-test) decoding a just-built request back, since a Response-PDU
and a Get/GetNext/GetBulk-PDU share the same request-id/slot-2/slot-3/
varbind-list shape.

v3 signing (`build_v3_request`) is the exact reverse of
`trapdecode.Decoder._verify_v3`: assemble the full message with the
authentication-parameters field zero-filled at its real length, compute
an HMAC over the assembled bytes with that field still zeroed, then
splice the digest into the same span `find_auth_span()` (a re-parse of
the just-built message) locates — provably the same operation as
verification, run in reverse, and cross-checked against the trap
decoder's own verifier in the self-test. `localized_key()` (RFC 3414
A.2.1/A.2.2 password-to-key + engine localization) was lifted from
`Decoder._localized_key` to a module-level function in `trapdecode.py`
so both the trap receiver's inbound verification and the poller's
outbound signing share one implementation rather than risking drift
between two. `discovery_probe()` builds the empty, unauthenticated,
reportable GET RFC 3414 §4 defines for learning `engineID`/`engineBoots`/
`engineTime` from a target's Report-PDU before any authenticated request
can be built. `authPriv` is rejected — `decode_response` raises
`SnmpUnsupported` if a decoded v3 message's `msgFlags` carry the privacy
bit — matching the trap receiver's own inbound-decryption deferral;
`nodesdb`'s schema has no privacy-protocol column at all, so the UI never
offers configuring it in the first place.

### Vendor identification (`vendorid.py`, `enterprises.py`, `nodepoll.py`)

**The arc hop.** Vendor identity lives entirely under `1.3.6.1.4.1`. A
GETNEXT at `1.3.6.1.4.1` lands on the first object under the first populated
enterprise arc N; a GETNEXT at `1.3.6.1.4.1.(N+1)` skips arc N entirely and
lands on the next. `vendorid.hop_enterprise_arcs(getnext)` enumerates every
arc a device populates in (arcs + 1) requests — typically three to eight —
which is why it is affordable inside a discovery sweep and finds vendors this
app holds no MIB for. Two loop guards end it: the reply must be strictly
greater than the probe (`nodeoids.oid_key`, moved there from nodepoll so both
import it) and its arc must exceed the last one recorded. `getnext` is
injected: the poller's wrapper (`_getnext_one`) and discovery's
(`_snmp_getnext_one`) both check `error_status`, because `_snmp_get_next`
never did and a v1 agent answers a probe past its last object with
`noSuchName` and the request OID echoed — which would read as a loop.

**The fingerprint.** `build_mib_index` turns `nodesdb.enterprise_objects()`
(a range predicate, `oid >= '1.3.6.1.4.1.' AND oid < '1.3.6.1.4.1/'`, so
`ix_mib_objects_oid` is used — `LIKE` is case-insensitive and skips it) into
object → *set of files*, so two MIBs defining the same object both get the
credit, unlike `_oid_name_table`'s arbitrary winner. A file whose every
enterprise object is the bare seven-part arc is root-only (the bundled
`enterprise-roots.mib`) and never scores, the same "strictly below the arc"
rule `has_mib_covering` applies. `fingerprint` credits each file with the
walked objects it names under each arc and ranks by `(named / seen, named)`.
The poller caches the index against `nodesdb.mib_generation()` and rebuilds
only when the corpus changes.

**Precedence** is `vendorid.decide`, in one place: manual > learned > a real
vendor arc in sysObjectID (`trapdecode.WELL_KNOWN` at high, the enterprise list
at high if verified else medium) > the walk (an arc an installed MIB names
objects under, by score; then a catalog arc; then any named arc — high with
score ≥ 0.5 and ≥ 10 named, else medium) > a sysDescr word at low > the
generic agent's own name at low. A real vendor arc is never replaced by a
walked one: OEM gear implements the chipset vendor's arc alongside its own.
`vendor_source` gained `walk`, `learned` and `manual`; `vendor_confidence` is
new. The MIB to assign and the bundle to suggest follow the *decided* arc,
never another. `poll_decision` is the zero-SNMP per-poll form: the same rule
with the walk replaced by the stored walk verdict *for this sysObjectID*, so
a walk-identified device stays stable between identifications and a manual or
learned vendor takes effect on the next poll without a walk.

**The walk runs off the poll pool** (`_VendorIdJob`, the `_OidWalkJob`
shape): up to ~565 requests and 20 s by budget, but a device that stops
answering half way pays its timeout per request on top, and on a 60 s
profile that is an overrun parked on one of four workers. `_maybe_identify`
starts one when `_identification_due` says so — never identified, identified
for a different sysObjectID, or the last run failed and an hour has passed
(at most three attempts) — and skips when `vendor_walk_parallel` jobs are
already running, which is what throttles the post-upgrade burst. A hop that
times out with no arcs is an error, not a verdict. The fingerprint walk runs
with `snmp_retries = 0`; the hop keeps the device's retries because a missed
hop loses an arc. Once `identified_ts` is set for the current sysObjectID,
`_identification_due` returns False before any I/O: the steady-state cost is
zero.

**Coverage and assignment key on the decided arc.** `_check_vendor_mib`
reads `vendor_detected` and `vendor_arc` from `poll_decision`, so a net-snmp
device the walk identified as Phoenix Contact records `mib_missing` for arc
4346 rather than silently passing on arc 8072. While a walk is still due the
poll path defers assignment (`defer_assignment`), because assignment never
overrides an existing choice and the walk's pick — the file that actually
named this device's objects — must not lose to "the file with the most
objects under the arc" merely by arriving second.

**Learning.** `set_vendor_override` writes `vendor_detected` as well as
`vendor` (the operator is asserting the real maker, so ConfigRX and the Cisco
MAC read follow — unlike `vendor_oid`, which stays display-only) and upserts
`vendor_learned` keyed on sysObjectID. `_learnable` refuses a generic-agent
arc or a sysObjectID outside enterprises: `8072.3.2.10` is every Linux box.
Clearing deletes the learned row only when this device made it, then
re-decides the row at once.

**`enterprises.py`** keeps two tables apart, `VERIFIED` and `CURATED`, and
`_arc_confidence` reads them directly — `vendor_for` merges them and can no
longer tell which a name came from — to stamp `high` on the first and `medium`
on the second. `vendor_for` is the fallback after `WELL_KNOWN` misses, so
`identify_vendor`, `suggest_group` and `browse_bases` all inherit the names,
and `mibcatalog.Bundle.arcs` and `vendor_key` join the catalog to the same
vocabulary.

**What the two tiers actually rest on**, because the names overstate it and a
`high` confidence reaches the operator in the device pane and in
`vendor_evidence`. Both tables are hand-authored from the IANA Private
Enterprise Number registry (<https://www.iana.org/assignments/enterprise-numbers>),
which is not reachable from this build environment and so was not machine-checked
against anything. `VERIFIED`'s docstring says every arc was "read out of the
vendor's own MIB text (the `::= { enterprises N }` line)"; that is true of
exactly one of its 53 arcs — Moxa's 8691, which `enterprise-roots-2.mib` cites
explicitly — because there is no Aruba, Ubiquiti, Hirschmann, Fortinet, Palo
Alto, MikroTik or Arista MIB anywhere in this tree to have read it from. The
arcs themselves look right: the ones used by the device classes in scope were
spot-checked against the sysObjectIDs those products report (9 Cisco, 11
HP/HPE, 248 Hirschmann, 318 APC, 2636 Juniper, 3833 Schneider, 4196 Siemens,
4346 Phoenix Contact, 8691 Moxa, 12356 Fortinet, 14823 Aruba, 14988 MikroTik,
25461 Palo Alto, 30065 Arista, 41112 Ubiquiti, 47196 Aruba CX) and none was
wrong. So read the tiers as *"more sure"* and *"less sure"* rather than as a
statement about primary sources: `VERIFIED` means an arc that was cross-checked
against real device output or a bundled MIB, `CURATED` one that was not. The
honest fix is a test that asserts each `VERIFIED` arc against a checked-in
extract of the IANA registry, which would turn the claim into something CI
keeps true; until that exists the docstring is the claim, and it is wrong.

### Identity OIDs (`nodesdb.py`, `nodepoll.py`, `nodeoids.py`)

`vendor_oid` and `location_oid` are ordinary members of `_OVERRIDE_COLUMNS`
and `_GROUP_EDITABLE`, so `effective_config()` resolves device-over-profile
for free and no new merge path exists. NULL means today's behaviour, which is
the whole backward-compatibility story.

Deliberately *not* reusing `oid_set`: that column is declared, migrated,
round-tripped by the API and read by nothing (`nodepoll.py` never mentions
it), and its schema comment promises a different feature — "comma-separated
metric keys". A pre-carved seat is not an invitation to sit in it with
something else.

`nodeoids.oid_variants()` returns both the object OID and its `.0` instance
unless one was typed, and `_poll_snmp_scalars` appends them to the GET it was
already making for the six system scalars — two extra varbinds, no extra
round trip. Asking for both removes the single most likely way to get this
wrong, since an OID browser, a MIB and an agent disagree about which form you
name. `normalize_oid()` rejects anything that is not dotted digits, so a typo
reads as "not configured" rather than going on the wire.

**Except on SNMPv1, where that merge is destructive.** By construction one of
the two forms cannot answer. On v2c and v3 that costs nothing: the agent
reports the missing object per-varbind as `noSuchObject` and every other answer
in the response is intact. SNMPv1 has no per-varbind exception — it answers a
request containing one unimplemented object with `noSuchName` and the request's
own varbind list echoed back as nulls, and `_check_error_status` raises only on
`authorizationError` — so the response parses cleanly and `identity` comes out
with sysDescr, sysObjectID, sysName and sysLocation all blank. Silently. A
device whose configured version is 0 therefore has its custom identity OIDs
read by `_identity_extras()`, a best-effort GET of their own whose failure
costs nothing but itself. Note that the version is read as
`config.get("snmp_version")` directly rather than through the usual
`int(config.get("snmp_version") or 1)`, which turns a configured 0 into 1.

**That guard is, as things stand, unreachable — a known defect.** `_snmp_get()`
resolves the version with exactly the `or 1` fallback described above, so a
device configured for SNMPv1 (`snmp_version = 0`) is put on the wire as v2c and
the `noSuchName` case never occurs. SNMPv1 is therefore never actually spoken by
the poller, whatever the profile says. The separate-GET split above is kept
because it becomes correct the instant that coercion is fixed, and because its
only cost meanwhile is one extra GET on v1-configured devices that also set a
custom identity OID. Fixing the coercion is deliberately out of scope of the
release that added this note: it changes how every v1-configured device is
polled, and deserves its own change with its own testing rather than riding
along with vendor identification.

**A per-vendor probe OID was tried here and removed.** An earlier cut of this
work read one proprietary Moxa scalar in a separate GET when the standard
sources named nothing, which worked but scaled by hand: one hardcoded OID per
vendor, each needing that vendor's MIB to find. The enterprise-arc walk in
`vendorid.py` answers the same question generically — it enumerates the arcs a
device actually populates, so it names Moxa from arc 8691 with no per-vendor
knowledge at all, and names vendors this application holds no MIB for. The
probe table, `probe_oids()`, `vendor_from_probe()` and the `vendor_source`
value `"probe"` are all gone; `walk` is the source value that replaced it.

**Display names** (`nodeoids.VENDOR_LABELS`, `vendor_label()`) are presentation
only, applied in `api._device_json` as a separate `vendor_label` field rather
than by rewriting `vendor`. The key is what ConfigRX, the Cisco MAC-table gate
and profile suggestion match on, so it stays a token; a key with no entry
serves itself, so adding one moves nothing else.

**The vendor split is the part to be careful with.** `identity["vendor"]` is
the *displayed* name and a custom OID may supply it; `vendor_detected` is
always what `identify_vendor()` worked out. Three readers behave differently
per vendor and must use the detected one — `configrx._backup_device` (an
exact `configrx.resolve()` dict lookup that "Cisco Systems, Inc."
fails), `nodepoll.read_mac_table`'s `is_cisco` gate, and
`nodeoids.suggest_group` (which reads sysObjectID itself, so it was already
safe). `nodesdb.detected_vendor(row)` is the single place that rule lives,
and it falls back to `vendor` for rows written before the column existed,
where the two were the same value by definition. `vendor_source` —
`sysObjectID` / `sysDescr` / `oid` — was computed on every poll and thrown
away; it is now stored, because an IANA arc assignment and a sysDescr
substring guess are not equally trustworthy and the header used to present
them identically.

### UPS and environmental health (`nodeoids.py`, `nodepoll.py`, `alertsdb.py`) — 4.49.0

Two new best-effort reads ride the ordinary poll, both added because a plant
site is full of devices that are not routers or switches: `_poll_ups_health`
(UPS-MIB, RFC 1628) and `_poll_environment` (ENTITY-SENSOR-MIB, RFC 3433,
promoted from an interface-only on-demand read to a whole-device cadenced
one). Both are gated for cost, differently, because the two device
populations they cover are shaped differently.

**UPS-MIB is not keyed by enterprise arc, unlike `VENDOR_HEALTH`.**
`nodeoids.UPS_HEALTH` is a flat tuple of (metric key, label, unit, OID,
"scalar"/"column_first"/"column_max", scale) probes, tried on *every* device
regardless of vendor — a UPS's maker varies far more than a switch's does
(APC's arc is 318, Eaton's 534, Vertiv/Liebert's 476, plenty of small brands
sit on a rebadged OEM card under yet another arc), and UPS-MIB is the one
object tree nearly all of them answer regardless, which is the whole reason
it was standardised. Cost is controlled without an arc gate:
`NodePoller._poll_ups_health` sends one GET of every scalar in `UPS_HEALTH`
first (`upsBatteryStatus`, `upsSecondsOnBattery`, `upsEstimatedMinutes`,
`upsEstimatedChargePct`, `upsBatteryVoltage`, `upsBatteryTemperature`,
`upsOutputSource`, `upsAlarmsPresent`), no more expensive than the UCD-SNMP
probe every device already gets, and only sends the two GETBULK table walks
(`upsInputTable`, `upsOutputTable`) once that GET shows at least one scalar
answered. A device that isn't a UPS answers none of the scalars and is never
asked for the tables at all — one extra GET a poll, the same one UCD-SNMP
already costs a non-UPS device. `upsBatteryVoltage` is the one probe scaled
(×0.1): RFC 1628 defines it in tenths of a volt, and storing 240 as "24.0 V"
would read as a battery string rather than mains-adjacent wiring. If the
standard `upsEstimatedMinutesRemaining` scalar didn't answer, and the
device's arc is APC's (318), `_apc_runtime_fallback` asks
`nodeoids.APC_BATTERY_RUNTIME_TIMETICKS` — PowerNet-MIB's own runtime object,
in TimeTicks (hundredths of a second) rather than whole minutes — the one OID
in this file not cross-checked against a live unit or a bundled MIB, standing
on the same kind of secondhand evidence `enterprises.py`'s CURATED table
already accepts elsewhere.

**ENTITY-SENSOR-MIB's device-level read shares its decode with the existing
per-port one, and nothing else.** Before 4.49.0 the only reader of this MIB
was `read_dom`, the on-demand SFP/DDM dialog, gated on
`entAliasMappingIdentifier` mapping a sensor entity to the one `ifIndex` a
human opened a dialog for — a gate that made every dedicated environmental
monitor's chassis temperature and humidity sensors invisible everywhere in
the app, because they map to no port at all. `_decode_entity_sensor` factors
the actual RFC 3433 scaling arithmetic (`value × 10^(3×(scale-9)) /
10^precision`) out of `read_dom` so both callers do it identically; the new
`_poll_environment` calls it for every sensor entity a device answers, using
`_walk_port_mapped_entities` (the same `entAliasMappingIdentifier` /
`entPhysicalContainedIn` walk `read_dom` already does, generalised from "does
this belong to ifIndex N" to "does this belong to any port at all") only to
*classify* a temperature reading, never to gate whether it's read.

A temperature reading becomes one of three metric keys before it is ever
stored:
- `temp_optic_c` — the sensor's containment chain reaches an entity
  `entAliasMappingIdentifier` maps to a port. Normal well above ambient by
  design (a transceiver's DOM commonly runs 40–55 °C).
- `temp_ambient_c` — the sensor maps to no port, *and* the same device
  answers at least one humidity sensor (`entPhySensorType` 9). A chassis
  essentially never carries a humidity probe; a dedicated room/rack monitor
  (AVTECH Room Alert and the like) always does, on any vendor's arc — using
  the humidity table as the signal generalises past AVTECH for free, rather
  than hard-coding a vendor check.
- `temp_chassis_c` — everything else unmapped, the deliberate *default*
  rather than `temp_ambient_c`: a device this can't positively identify as an
  environmental monitor must not have its ordinary board/PSU/fan warmth read
  as a room getting hot, which is the mistake this classification exists to
  fix. Juniper's own `jnxOperatingTable` temperature reading (`VENDOR_HEALTH`)
  was renamed from `temp_c` to this same key, so a device answering both
  never reports two disagreeing chassis figures.

The gate that made this necessary: for about a day of this campaign,
temperature shipped as a single `temp_c` key with a single `temp_high` rule,
and a running instance immediately produced ten false alerts on a 25-device
fleet — seven access switches and two core switches reporting their SFPs'
entirely normal 40–45 °C DOM readings, indistinguishable from a genuine
41.8 °C reading off the one real Room Alert in the fleet. `alertsdb.py`'s
`_retire_temp_high` migration disables and renames (never deletes, since
`rules.id` cascades onto `alerts`) any installation's copy of that rule that
still looks exactly like what shipped — `is_builtin`, unmodified
`source_kind`/`threshold`/`clear_threshold` — resolving its open alerts with
a note, and leaving a customized copy alone to simply never fire again.

**A third gap closed the same pass, smaller and in the same family:**
`mem_pct` had no HOST-RESOURCES-MIB fallback at all, while `cpu_pct` and
`disk_pct` for the same device already did. `_host_resources_storage_rows`
walks `hrStorageType`/`Size`/`Used` once per poll and shares the result
between `_host_resources_disk_pct` (the fullest `hrStorageFixedDisk` row) and
the new `_host_resources_mem_pct` (the `hrStorageRam` row alone — never
`hrStorageVirtualMemory`, for the same reason the disk reader excludes
anything that isn't a fixed disk: counting swap as physical memory would make
an ordinary swap file read as critically low RAM). Tried only once neither
UCD-SNMP, the Fortinet scalar nor the Cisco memory pool has already answered
`mem_pct`, so a net-snmp box or a FortiGate costs nothing extra; a Windows
host, a printer or most appliances — which answer none of the other three —
now get a `mem_pct` at all.

Both reads are cadenced rather than run on the ordinary poll cycle:
`_poll_ups_health` is best-effort every poll (cheap once gated, as above);
`_poll_environment` re-walks a device at most once every `_SENSOR_REFRESH_S`
(300 s, in-memory only, the same shape `_addresses_read`'s hourly
`ipAddrTable` cadence already uses) — comfortably inside the 900-second
default `threshold_stale_s` a threshold rule tolerates before treating a
metric as absent, since a temperature reading doesn't change between one
poll and the next the way an interface counter does, so there's nothing to
buy by re-walking it as often.

### Scheduler (`nodepoll.py`)

`NodePoller` is shaped like NetPath's own `Monitor`, not `IpamWorker` —
deliberately, because Nodes typically manages far more devices than IPAM
manages subnets, and a restart must not fire every device's poll at
once. A hot-resizable `ThreadPoolExecutor` (`reconfigure()` builds a new
pool and lets the old one drain in-flight work rather than cancelling
it, exactly like `Monitor.set_workers`), restart-safe per-device due-time
seeding (`_loop()` seeds a device's first `_next_run` from its own
`last_poll_ts + interval`, not `now`, so a device that was 90% of the way
through its interval when the service stopped is not immediately
re-polled the instant it restarts), reschedule-before-run, and overrun
detection (a device still running when its next tick comes due logs once
and records a `poll_overrun` device event rather than queuing a second
concurrent poll of the same device) are all copied from `Monitor`'s own
algorithm.

**An overrun is not recorded while the device is failing.** `_record_overrun`
returns early when `device["status"] == "down"` **or**
`device["consecutive_fail"] > 0`. A poll of a device that stopped answering
overruns by construction — every request in it spends its full timeout and
all its retries — so the event says nothing the outage does not. Both arms
are needed and neither is redundant: `down` only becomes true after
`down_after_failures` (3) *completed* failing polls, so the overruns lead
the outage by two or three intervals, and the first of them would otherwise
get out before `device_down` existed to roll it up. Suppressed at source
rather than filtered in the alert engine, the same shape as
`wirelessdb.out_of_service`: no event row, no Debug line, no alert. The
`ROLLED_UP_BY` entry for `poll_overrun` still exists, to catch an alert
opened in the moments before the first poll actually failed.

**MAC-table walks have their own cadence** (`_maybe_walk_mac_table`, called
once per device per `_loop` pass). A forwarding table is thousands of rows
per switch, and although GETBULK (below) has cut the request count roughly
twenty-fold, that is still not per-poll work, so `mac_table_interval_s` is a
separate interval — an override column on both
`devices` and `groups`, resolved by `effective_config` like every other
override, defaulting to **0 (never)** rather than to a global setting, so an
upgrade adds no SNMP load anywhere until a profile opts in. A device's first
walk is scheduled at a random point inside one interval so a restart does
not walk every opted-in switch at once, and a device that is down or whose
last poll failed is skipped for the same reason overruns are not recorded on
one. The walk itself runs on the poll pool via `_run_mac_table`, guarded by
`_mac_running` so one device never has two in flight.

`read_device_mac_table` is the whole-device form of `read_mac_table`, with
the same three-source cascade (Q-BRIDGE `dot1qTpFdbTable`, then BRIDGE-MIB
`dot1dTpFdbTable`, then Cisco per-VLAN contexts via `community@vlan`) and
the per-port filter removed; `_fdb_entries` gained an optional bridge-port →
ifIndex map so both forms share one parser. It returns **None** when the
device answers no forwarding table at all, which `_run_mac_table` treats as
"leave what is stored alone" — a switch that failed to answer once has not
forgotten every MAC it knows, and deleting its table would send the next
search nowhere.

**Whole-device OID walks** (`_OidWalkJob`, `start_oid_walk`) run on their own
thread rather than the poll pool: a full walk of a core switch is tens of
thousands of GETNEXTs and minutes of wall time, and parking one of the poll
workers on that would stall the devices behind it. One job per device at a
time, refused politely like `backup_now` does, held in `_oid_walks` in memory
— a walk result is transient, downloaded once and dropped, and a row
surviving a restart would describe a thread that is gone.
`walk_subtree` and the job share `_walk_from`, which gained a `cancelled`
predicate and an `on_row` progress hook; they differ only in their bounds and
in having a cancel, not in what a walk is. `GET …/oid-walk?download=1`
formats the file (`api._oid_walk_text`) and then calls `forget_oid_walk`, so
a 100,000-row walk does not sit in memory for the life of the process. The
file's header states plainly whether the walk completed, and names the
reason when it did not — a truncated walk that looks complete is the failure
this feature could most easily cause.

**Poll now, and what "already polling" means.** `poll_now(device_id)` is a
thin wrapper over `_submit()`, which drops the request when the device is
already in `_queued` or `_started` — a poll of one device is never run
concurrently with itself. Both now return a bool, because the frontend needs
to tell the two cases apart: 4.28.1's button watched the device's
`last_poll_ts` for movement and reported *Polled* when it moved, which on a
dropped click was the *other* poll's completion. `POST
/api/nodes/devices/<id>/poll` returns `queued`, and the bulk endpoint
`POST /api/nodes/devices/bulk-poll` returns `queued` / `already_polling` /
`missing` id lists, reusing `_bulk_device_ids` like every other Nodes bulk
handler. There is no bulk poller: it calls `poll_now` per id, which is the
whole point — the scheduler's own de-duplication is what makes that safe.

**Ping probing and the down rule.** Every device with `ping_enabled` is
pinged as well as polled, via `ipam_scan.ping_many(ip, count,
timeout_ms)`. That sends `count` probes one subprocess at a time rather
than one `ping -c N`: Windows and the BSDs disagree both on how to ask
for a burst and on how they summarise one, and a single probe per process
is the only form already known to work everywhere here. RTT is parsed out
of ping's own `time=` output using `tracer.py`'s existing
`_UNIX_PING_TIME`/`_WIN_PING_TIME` regexes, **not** measured as
wall-clock around the subprocess — the old single-ping path did that and
counted process spawn as network latency, reporting a sub-millisecond LAN
device at tens of milliseconds. Loss and RTT are written through the
ordinary `record_metric_sample()` sink as `ping_loss_pct` and
`ping_rtt_ms`, which is what finally gives the shipped
`response_time_high` rule a metric to read and lets `packet_loss_high`
exist at all. `ping_interval_s` (0 = every poll) decouples probing from
the poll cadence via a `_last_ping` map; on a skipped tick the device's
*previous* `ping_ok` stands, because "not probed" must never read as
"probe failed".

Reachability: with SNMP disabled, ping alone decides (unchanged, a
first-class configuration); with ping disabled, SNMP alone decides; with
both enabled, `reachable = snmp_ok or (unreachable_ping_only and
ping_ok)`. That flag now defaults to **True** — a device answering ICMP
with a broken community string is reachable and misconfigured, and
calling it down buries the SNMP error under an outage that is not
happening. It is resolved through `effective_config()` like every other
override, so a device or profile can restore the old behaviour;
`consecutive_fail`/`down_after_failures` are untouched, since they
already key off `reachable` rather than the status label.

`EngineCache` holds one `(engine_id, boots, engine_time, learned_at)`
tuple per device needing v3, kept for the process lifetime, and
`current()` returns `engine_time + (now - learned_at)` rather than the
value learned at discovery. That last part matters and was missing until
4.39.0: an agent accepts a message only inside a ±150 second window around
its own clock, so replaying the *discovered* `engine_time` on every
subsequent request meant a device drifted out of its own window after
about two and a half minutes and rejected roughly every third poll with a
Report — recorded as an authentication failure, which it was not. An
earlier edition of this file said engine parameters "only need refreshing
if the target reboots"; that was true of `engine_id` and `boots` and false
of `engine_time`, which advances with the agent's clock and must be
advanced with it here.

A Report-PDU is still what says a resynchronisation is needed. All three v3
send paths — `_snmp_get`, `_snmp_get_next` and `_walk_request` — now go
through one `_v3_exchange()` helper that invalidates the cache entry,
rediscovers and retries once; a second Report raises `_AuthFailure` with
the `usmStats*` counter decoded into a real message, and
`usmStatsUnsupportedSecLevels` raises `SnmpUnsupported` so the device is
marked `unsupported` by exception type rather than by matching a substring
of its own error string. Two of those three paths previously had no Report
handling at all and decoded one as an ordinary reply with no varbinds.

**Multiple credentials per profile.** A polling profile's own `snmp_version`/
`community`/`v3_*` columns are its "primary" credential, unconditionally
always present and always tried first — a single-credential profile (still
the common case) needed no migration and no behavior change at all when
this was added. `group_credentials` is a purely additive child table
holding only the *extra* alternates a profile wants tried after the
primary; `NodesDatabase.credential_candidates(device_row)` resolves the
ordered list to try for a given device: a device's own credential override,
if it has one set, is always exactly one candidate (a human already told
this app the real credentials for this specific device, so nothing else is
worth trying); otherwise it's the profile's primary credential followed by
every `group_credentials` row for that profile, in `id` order (insertion
order — no separate priority column). `NodePoller._credentials` is an
in-memory `device_id -> winning candidate index` cache, the same
process-lifetime-only tradeoff `EngineCache` above already makes:
`_poll_snmp_scalars_with_credential()` tries the cached index first, and
only walks the full candidate list from the top on a cache miss or if the
cached one stops working — so a profile covering several vendors or SNMP
versions costs one extra request per untried candidate only on a device's
first poll, or after its working credential stops answering, not on every
poll after that. Every failure `_poll_snmp_scalars()` alone could raise —
`SnmpTimeout`, `SnmpUnsupported` (an authPriv alternate in an otherwise
usable list), `_AuthFailure`, any other `SnmpError` — is credential-specific
in a mixed profile, so all of `SnmpError`'s subclasses are caught uniformly
while trying candidates and only re-raised, as the last one seen, once
every candidate has failed; the caller's existing status/counter
classification in `_poll_device` is unaffected; it just sees the same
exception type a single-credential poll would have raised.

**Display name** (`devices.display_name_source`, `'auto'|'manual'`): the
precedence lives in exactly one place, `nodes.js`'s `displayName()` —
`'auto'` is `sys_name || name || ip`, `'manual'` pins `name || ip`. The
`name` column itself stays the *manual* name (defaulting to the IP on
insert); promotion from discovery deliberately stopped copying `sys_name`
into it, seeding the identity columns via `nodesdb.seed_identity()`
instead, so a later manual rename is never shadowed by a stale copy of
the hostname, while the just-promoted device still shows its sysName
before its first poll.

**Device groups vs. polling profiles.** `device_groups` is a separate
table from `groups` (polling profiles), deliberately — conflating "which
credentials/interval a device uses" with "which folder it's organized
under" would make every future profile change also have to reason about
an unrelated grouping concept, and vice versa. `devices.device_group_id`
is a nullable FK with `ON DELETE SET NULL`, the same nullable-FK shape
`devices.group_id` already used, so removing a group only ungroups its
devices rather than requiring an in-use guard — unlike losing a polling
profile, losing an organizational folder is harmless.

**Bulk device operations** (`bulk_update_devices`/`bulk_remove_devices`,
`nodesdb.py`; `post_nodes_devices_bulk_update`/`_bulk_delete`, `api.py`):
one `UPDATE ... WHERE id IN (...)` / `DELETE ... WHERE id IN (...)`
inside a single lock/commit per call, the same "operate on a list of
ids from one request" shape `post_nodes_discovery_promote`'s
`result_ids` list already established, rather than one HTTP round trip
per device. `bulk_update_devices` reuses `update_device`'s
`_DEVICE_EDITABLE` allow-list unchanged, so a bulk "remove from group"
is exactly `device_group_id: null` through the same code path a
single-device edit already uses — no separate "clear" endpoint.

**Bulk selection is Ctrl/Cmd-click, not a checkbox column** (`nodes.js`
Devices table, `alerts.js` Alerts table — identical shape in both). Each
row's `tr.onclick` branches on `event.ctrlKey || event.metaKey`: a plain
click still does exactly what it always did (open the single-row detail
pane, `view.selected`), a modifier-key click toggles that row's id in
the bulk `Set` (`view.devicesChecked` / `view.checked`) instead. These
two selection concepts were already fully decoupled before this change
— a checkbox's own `onclick` used to call `e.stopPropagation()`
specifically so it never reached `tr.onclick` — which is what made
swapping the *input mechanism* (checkbox click → modifier-key click) a
pure interaction change with no effect on `drawBulkBar()`/the `bulk*()`
action functions, which still just read `[...view.devicesChecked]` /
`[...view.checked]` unaware of how the Set was populated. A row can
**Shared table machinery (`app.js`).** Four helpers, added in 4.30.0 by
lifting Wireless's bespoke column-picking out of that one module:
`visibleColumns(all, storedCsv)` resolves a catalogue plus a stored choice
into the columns to draw, `columnPickerFieldset`/`readColumnPicker` are the
settings-dialog block and its read-back, and `drawRows(tbody, rows, columns,
onRow)` builds the body from each column's `cell(row)`. That last one is the
part that makes hiding a column *safe*: every table used to zip a positional
array of `<td>` strings against its column list, so removing one column
silently shifted every later cell under the wrong header — netflow.js said so
in a comment ("this array and COLUMNS are zipped below, so the two orders
have to move together") and appended its route button outside the map
entirely, which is exactly the shape that breaks.

Three rules are encoded once rather than per module: unrecognised keys are
dropped (so a column a release removes does not break a saved choice, and an
older client ignores a newer one); a `fixed` column — a row checkbox, an
action button — is always drawn and never offered for hiding; and a stored
choice containing no non-fixed column falls back to the defaults, or
unticking everything would leave a table of nothing but checkboxes, the one
state with no way out. Storage is a `table_columns` key in the owning
module's own settings scope (`/api/settings`, ten scopes), never
`localStorage`, for the reason `wirelessdb.py:95` gives: Reset layout clears
per-browser *widths* and must not eat a settings choice. Sort state lives on
a `view.*Sort` object per table and, since 4.37.0, is seeded from the
per-browser view store (`App.recallSort`, below) — still a different key
from the layout, so Reset layout cannot eat it either.

`App.grid` gained a `selectAll: {key, checked, some, onToggle}` option that
renders the checkbox into the named column's header cell, with
`indeterminate` for a partial selection. It lives in `grid` rather than in
each module so there is one implementation and one tri-state rule.
`refreshSelectAll(table, total, selected)` corrects it in place after a
single-row toggle, because `toggleChecked` deliberately does not redraw.

**Design tokens** (`netpath/web/static/tokens.css`). Every colour, text
size, tracking, radius, shadow and z-index the interface uses is a custom
property in this one file, linked before `app.css` on all three pages
(`index.html`, `login.html`, `ssh.html`) and listed in `PUBLIC_PATHS`
because the sign-in page needs it before there is a session. `app.css`,
`ssh.css` and the module scripts read tokens by name and write no hex colour
or pixel font size of their own; `tests/test_design_tokens.py` fails if one
appears, if `theme.py`'s copy of the palette disagrees with the file, or if
any of the contrast ratios written beside the tones stops being true — it
recomputes every one from the hex values.

The tones are named for their role. Three text tiers — `--text`, `--muted`,
`--dim` — and the dimmest is 4.6:1 on `--raised`, the darkest surface text
is allowed on. There is no `--faint`: it was 2.5:1 and was being used for
prose. Structure that is not text but must be seen (dividers, grips, the
ring of an empty status mark) is `--line`, 3.1:1 on `--raised`; the fill for
"none of this yet" in a chart is `--data-neutral`, 3.05:1 on `--panel`.
Sizes are seven `rem` steps (`--fs-2xs` … `--fs-2xl`) plus `--fs-glyph` for
the ●▲■◆○ status marks only, so the browser's text-size setting is honoured
and a wall-display density can scale everything from the root. SVG chart
labels take the same tokens through their `font-size` and `fill`
presentation attributes, which are parsed as CSS and resolve `var()`.
A light or high-contrast theme is a `:root[data-theme]` block redefining
values; nothing outside the file has to move.

A row can still be simultaneously selected (detail pane) and checked (bulk set);
`tr.bulk-checked` and `tr.selected` (`app.css`) are separate rules for
exactly that reason, and `tr.bulk-checked.selected` gives the combination
its own shade rather than letting one tint win. The selected row is
`--selected` (a blue-grey a step off `--raised`; `--hairline` had put
`--muted` at 3.5:1 on the one row being read) plus an accent bar on its
*first cell only* — see the next sentence for why not every cell. The checked marker used to
be `box-shadow: inset 3px 0 0 var(--accent)`, which draws that bar on the
left edge of *every cell* — under `table-layout: fixed` that reads as a blue
stripe at each column divider rather than as a selected row, which is
exactly how it was reported. It is now `background: var(--checked)`, a solid
palette colour rather than a translucent accent so the tint is identical over
the odd and even row stripes (`tr:nth-child(even) td`); a translucent one
would composite differently on each and break the single unbroken bar the
change is for.
Because the bulk bar itself is `hidden` while nothing is checked, the
**Select all** button lives in the always-visible filter bar instead of
inside it — otherwise there'd be no way to reach it before checking at
least one row by hand.

**"Only offline" filter.** `devices(exclude_up=True)` appends
`status != 'up'` — deliberately not `status = 'down'`: down, unknown,
unsupported and auth-failed are all "not currently confirmed working,"
a broader and different question than the exact-match Status dropdown
sitting right next to it. `get_nodes_devices` treats the query param's
mere *presence* as the signal (`params.get("offline_only") is not
None`) rather than parsing its value — the frontend only ever includes
the key when the checkbox is checked, so there's no `"false"`-string
edge case to parse around.

**Default profile deletion and reassignment.** `remove_group()` no longer
special-cases `is_default` — every profile, default or not, is refused
deletion while `device_count_for_group()` is nonzero (a plain `COUNT(*)`,
not a full `devices()` fetch, to avoid paying for full rows just to
count). This tightens what was previously an inconsistency: a
*non*-default profile could always be deleted before, silently orphaning
its devices via the same `ON DELETE SET NULL`, while only the default one
was ever blocked. If the profile being removed is currently the default
(already confirmed unused), the same transaction promotes the next
remaining profile — lowest `id` — to default before deleting; if none
remain, no profile is left flagged default, which the existing
`ensure_default_group()` lazy-reseed already handles transparently the
next time one is needed, the same path a brand-new install already goes
through. `set_default_group()` is a two-statement transaction (clear the
old default, set the new one) with no in-use check, since making a
profile default moves no devices.

### Debug page node pollers

`get_debug`'s `node_workers` list is built the same way its existing
`ipam_workers` list is: `NodePoller.worker_state()` (already consumed
elsewhere to set each device's per-row `"polling"` flag) joined against
`nodes_db.devices()` for display labels, split into `"queued"` vs.
`"started"` states so the frontend's existing `elapsedText()` amber/queued
styling applies without any new CSS. `debug.js`'s `nodeWorkers`/
`nodeCells`/`nodeFetchedAt` triplet and `drawNodeWorkers()` are copies of
the pre-existing `ipam*`/`drawIpamWorkers()` shape, including the
`fastTick()` branch that advances displayed elapsed time between fetches
without re-polling.

**One chart renderer** (`nodes.js drawSeriesChart`): the device metric
chart and the interface dialog share one SVG renderer taking 1..n series
(raw or rollup points), unit-aware Y labels (`formatMetricValue`), and
time labels at fixed window fractions — sample-position labels cluster
and overlap when polls occupy a corner of the window. The min/max
rollup band draws only for a single series; overlapping bands read as
mud. The wheel-zoom handler is attached by ASSIGNMENT (`svg.onwheel =`)
on every draw, never `addEventListener`: the chart redraws each refresh
tick and accumulated listeners each zoomed from their own stale closure
window — the "timeframe doesn't scale" bug. `drawSeriesChart` returns
`null` only when it was handed no data object at all; an empty series
list still returns the plot geometry (built from the *requested*
t0/t1) so the wheel handler stays live and a zoom into a gap between
samples can still zoom back out. In/out interface metric pairs
(`if_in_bps.N`/`if_out_bps.N`, same for `_err`) are joined into one
picker option (`pair:<inId>:<outId>`) client-side; the storage and
series API stay strictly one-metric-per-id.

**Chart smoothing** (`nodes.js movingAverage`): a centered moving
average applied when the Smoothed checkbox is on (`opts.smooth`), before
peak/axis computation so the Y scale reflects what's actually plotted.
The window is **time-aware** since 4.34.0: `clamp(round(90 s / median
point spacing), 3, 25)` points, so it spans about ninety seconds of
wall-clock time whether the points are two minutes or fifteen seconds
apart (the count-based `round(n / 20)` it replaced shrank to ~27 s of
span exactly when 3 s focus polling made the series noisiest). It
shrinks at the array's edges rather than reaching past the data.
Bucketed and rollup points (`avg`/`min`/`max`) are smoothed on their
`avg` only; `min`/`max` pass through untouched, and `drawSeriesChart`
drops them from a smoothed multi-series draw (no band) while keeping
them for a single-series band.

**Series buckets, the rate timestamp and axis hysteresis** (4.34.0).
`NodesDatabase.series(device_id, metric_id, t0, t1, bucket_s=0)` groups
raw samples into epoch-aligned windows (`CAST(ts / bucket_s AS INTEGER)
* bucket_s`) when `bucket_s > 0` and the window is within the raw range
(≤ 3 days), returning the rollup's `{ts, avg, min, max, n}` shape so the
chart code renders either unchanged; `/series` accepts `bucket_s` and
caps it at half the window. The interface dialog asks for
`max(15, window / 240)` — 15 s buckets over its fixed hour, ≤ 240
points, so 3 s focus samples and 120 s profile samples land evenly
instead of the fast tail being packed into a few pixels. The rate's
`dt` was the other half of the jaggedness: `_poll_device` stamped every
interface with the poll-start `now` while each port's counters were read
by its own GET later in the poll, a ±17 % error at a 3 s spacing.
`_poll_interfaces` now stamps each row with `_sample_ts` taken right
after its GET returns, and that feeds `counter_rate` and
`update_interface_rate`; the recorded metric sample keeps `now` so it
stays aligned with the rest of the poll. `drawSeriesChart` takes an
`opts.axisMemory` object the dialog owns across redraws: the ceiling
grows immediately, and shrinks only when the new nice ceiling has fallen
below half the remembered one; a pinned `opts.peak` bypasses it. The
dialog's one 5 s timer refreshes the text readout every tick and the
chart every third tick — one bucket of new data per redraw.

**Device chart window model** (`nodes.js`, `view.chartRange`/
`chartWindow`): the same "frozen window that a preset reselect resets"
convention `netflow.js`/`netpath.js` already use for their own wheel
zoom. `chartWindow` is `null` while the chart follows "now" at
`chartRange` seconds (`loadSeries` recomputes `[now - chartRange, now]`
on every load); a wheel zoom sets it to the absolute `[t0, t1]`
`App.wheelWindow` returns and `loadSeries` uses that verbatim until the
range `<select>` is changed, which clears it back to `null`. Keeping
only the zoomed *span* and letting `loadSeries` re-anchor to "now" (the
first cut of this fix) silently discarded `wheelWindow`'s whole anchor
contract — zooming at any point in the chart would always recentre on
the right edge instead of keeping the point under the cursor fixed.
`loadSeries` also stamps each call with an incrementing
`view.seriesRequestId` and drops its response if a later call has
since started, so a quick run of wheel ticks can't have an earlier,
slower response overwrite a newer one.

**Selected-device fast poll** (`NodePoller.set_focus`): the browser
POSTs `/api/nodes/devices/{id}/focus` on every Nodes-tab refresh tick
while a device is selected; each call stores `(device_id, now + 15s,
focus_poll_interval_s)` and the 1 s scheduler loop takes
`min(profile interval, focus interval)` for that one device while the
lease is live (SNMP-enabled devices only — a fast ping-only cadence
shows nothing new). A short renewed lease, not an on/off switch,
because the off edge has no reliable messenger: a closed tab or crashed
browser sends nothing, and a TTL turns "no longer being watched" into
the absence of renewals. Overrun logging is suppressed only while the
focus interval is the governing one — a device that takes 5 s to answer
a 3 s cadence is expected, not an incident; blowing its own profile
interval still logs exactly as before. `set_focus` also pulls the
device's `_next_run` forward so the first fast poll lands within
seconds of selection rather than after the profile interval. Setting
`focus_poll_interval_s` to 0 makes `set_focus` a no-op that clears any
live lease.

**Interface error counters**: `_poll_interfaces` now keeps
`ifInErrors`/`ifOutErrors` (their OIDs were always in the GET — the
values were previously dropped on the floor and the `in_error_rate`/
`out_error_rate` columns written as permanent NULLs). `_run_one` feeds
them through the same `counter_rate()` as the octet counters (32-bit),
stores raw counts in the new `interfaces.last_in_errors`/
`last_out_errors` columns (added via `_migrate()`), and records
`if_in_err.{if_index}`/`if_out_err.{if_index}` metric samples next to
the existing bps ones — which is what the interface dialog's graph and
stats read.

**DOM/SFP sensors** (`NodePoller.read_dom`): a live, on-demand
three-table GETNEXT walk (via `_walk_column`, the generalization
`_walk_indexes` now wraps) run only when the interface dialog opens —
never on the poll cycle, since several table walks per interval would
be pure waste when nobody is looking. `entAliasMappingIdentifier` finds
the physical entity mapped to the ifIndex, `entPhysicalContainedIn`
gives the containment tree, and every `entPhySensorTable` row whose
ancestor chain reaches the port's entity is reported with the RFC 3433
scaling applied (value x 10^(3*(scale-9)), `precision` decimals) and
the device's own `entPhySensorUnitsDisplay` string as the unit — no
vendor unit tables. A device without ENTITY-MIB support returns `[]`,
which the dialog reports as "no DOM/sensor data" rather than an error.

**Whole-device hardware and DOM (`NodePoller.read_hardware`,
`read_dom_all`) — 4.53.0.** `_read_entity_sensors` generalises the same
`entAliasMappingIdentifier`/`entPhysicalContainedIn` walk above (via the
new `_entity_port_map`, entity → ifIndex for every entity on the device
at once) into a whole-device sensor list, shared by both: `read_hardware`
combines it with the already-polled cpu_pct/mem_pct/temp_*/humidity_pct
metrics (`_hardware_metrics`, a plain `metrics()` read, nothing walked)
and, on Cisco gear (`detected_vendor(device) == "cisco"`),
CISCO-ENVMON-MIB power-supply/fan/temperature state
(`_read_cisco_envmon`); `read_dom_all` is the same entity list filtered
to rows that resolved to a port, the device-wide counterpart of
`read_dom` above. Two routes back them, `GET
/api/nodes/devices/<id>/hardware` and `.../dom` (`api.py`,
`server.py`), read by the device dialog's HARDWARE SENSORS and DOM / SFP
SENSORS sections (`nodes.js`); both walk only while that dialog is open,
same reasoning as `read_dom`.

**MAC address table** (`NodePoller.read_mac_table`): same on-demand shape
as `read_dom` above — walked only while the interface dialog is open.
`dot1dBasePortIfIndex` (bridge port → ifIndex) is read first to find
which bridge port(s) map to the requested ifIndex; the forwarding entries
themselves then come from up to three sources, tried in order, first one
that yields anything winning:

1. **`dot1qTpFdbPort`** (`1.3.6.1.2.1.17.7.1.2.2.1.2`, Q-BRIDGE-MIB) —
   what most VLAN-aware switches actually answer. Its index is
   `<fdbId>.<6 MAC bytes>`, so the parser takes the **last six** arcs as
   the MAC and the first as the VLAN, which the dialog shows in its own
   column when any entry carries one.
2. **`dot1dTpFdbPort`** (original BRIDGE-MIB) — the only source read
   before 4.27.0, and still the fallback.
3. **Cisco per-VLAN community indexing** — classic IOS exposes its
   forwarding table only inside per-VLAN SNMP contexts, reached by
   re-querying with `community@<vlan>`. `dot1dBasePortIfIndex` lives in
   those same contexts on these switches, so this path re-reads it per
   VLAN when the global read came back empty — bailing out on an
   unanswered global bridge table would skip the Cisco path on exactly
   the devices it exists for. It reports back whether any VLAN context
   answered a bridge table, which is what keeps `None` ("cannot tell
   us") distinct from `[]` ("nothing learned here") on such a device. The VLAN list comes from
   CISCO-VTP-MIB `vtpVlanState` (`1.3.6.1.4.1.9.9.46.1.3.1.1.2`, state
   `1` only, 1002–1005 excluded), then source 2 is repeated per VLAN. It
   is **v1/v2c only** — there is no community to suffix under v3 — and
   gated on the device's vendor already reading `cisco`, so a 200-VLAN
   walk never starts against a switch that would not answer it anyway.
   `_MAX_VLAN_CONTEXTS` (48) and `_VLAN_WALK_BUDGET_S` (15s) bound it so
   opening a port dialog cannot hang. `_walk_column` derives its
   credentials through `credential_for(config)`, so passing a modified
   copy of the config is all that re-scoping a walk takes.

Both FDB tables are INDEXed by the MAC itself, so each row's own OID
suffix already *is* the learned address — no separate GET for an address
column is needed. Entries are deduplicated on the `(mac, vlan)` pair,
since the same address legitimately appears in several VLANs.

Note that **the MIB catalog cannot widen any of this**: the poller uses
hardcoded numeric OIDs throughout (`nodepoll.py`, `nodeoids.py`) and
uploaded MIBs only ever supply display names.
Adding Q-BRIDGE and the Cisco path is what changed the coverage.

Returns `None` (not `[]`) when the device answers no forwarding table at
all, which the dialog and the `/mac-table` API route's `"supported"` flag
both key off, so "this device can't tell us" and "this port genuinely has
zero MACs learned right now" render as different messages.

**Vendor identification** (`nodeoids.identify_vendor`): two sources with
different standing, reported separately so a guess is never mistaken for a
fact. `vendor_for()` longest-prefix-matches `trapdecode.WELL_KNOWN`, which the
Trap page's own decoding already uses — one table, not two — and 4.28.0 widened
its enterprise arcs from 19 to cover every vendor `mibcatalog.py` ships a
bundle for, plus industrial and wireless names. **Every added arc was read out
of that vendor's own MIB text** (`::= { enterprises N }`), not recalled: a
wrong arc silently mislabels every device beneath it, which is worse than a
blank column. Two consequences of doing it that way are worth knowing: `4413`
is Broadcom's, not NETGEAR's (NETGEAR's managed switches run OEM'd FASTPATH
and report there, as do other FASTPATH OEMs), and `161` is Motorola's, which
Cambium's Canopy line still registers under — both are named for the arc's
owner.

Two guards sit on top of the raw lookup. `WELL_KNOWN` also names standard-tree
nodes, so an unadorned `vendor_for()` reports a device with a standard-tree
sysObjectID as vendor `"system"` — which is what used to be stored;
`identify_vendor` gates the arc branch on `enterprise_root()` being non-empty.
And `GENERIC_AGENT_VENDORS` (net-snmp, ucdavis) names the *agent* rather than
the maker: a Phoenix Contact radio, a Moxa switch and a Linux server all answer
net-snmp's arc, so for those the `SYSDESCR_VENDORS` substring table is
consulted first and the agent name kept only as a last resort. This is the
class of device the fallback exists for; matching the agent arc first is what
stopped it ever running.

**Automatic MIB assignment** (`NodePoller._auto_assign_mib`): `has_mib_covering`
answers "is there a MIB for this vendor"; `nodesdb.mib_file_covering` answers
"which one", picking the file with the most resolved objects under the vendor's
arc — a bundle is usually several files of which one carries the real objects
and the rest are type or registration modules that would poll nothing. It sets
`mib_file_id` only where it is NULL, so a hand-picked MIB (including one
deliberately pointed elsewhere) is never replaced, and records a
`mib_assigned` device event, since this changes what is polled every cycle and
should be visible rather than discovered from new metric names.

**On-demand reads and the working credential** (`NodePoller.working_config`):
`effective_config()` resolves a device's own overrides over its profile's
columns — which is the profile's PRIMARY credential and nothing else. A
profile can also carry alternates (`group_credentials`, for a mixed-vendor
subnet), and the scheduled poller finds whichever one works and caches the
index in `self._credentials`. Every on-demand read built its own config from
`effective_config()`, so on a device answering an alternate it queried with
the wrong community: every request ignored, every read a timeout, on a device
the poller shows as up. That is what made the OID browser report "the device
stopped answering" for every device, and it left `read_mac_table` and
`read_dom` quietly returning "this device cannot tell us" on the same
devices — the same bug, invisible because those two swallow it by design.

`working_config()` is the fix and the single place this is resolved. One
candidate (the common case, and any device with its own credential override)
returns `effective_config` unchanged and costs no extra request; with
alternates the poller's cached winner is trusted, and only a device it has
not resolved yet is probed here — one cheap sysObjectID GET per candidate,
caching the winner exactly as the poll path does.

**OID browser** (`NodePoller.walk_subtree` / `browse_bases`, `api.get_nodes_device_oids`):
deliberately a sibling of `_walk_column` rather than a widening of it —
`_walk_column` returns index-suffix → value for one table column and caps at
512 rows, which is right for its callers and wrong for a browser that needs
the whole OID, the SNMP type and a reason for stopping. `walk_subtree` carries
its own row cap and wall-clock budget and reports which one it hit, so a
truncated walk cannot be mistaken for a device's complete answer. Names come
from `_oid_name_table()` — `nodesdb.all_known_oids()` inverted (it stores
name → OID, for `mibparse.resolve`'s `known` dict) merged over
`trapdecode.WELL_KNOWN` — matched longest-prefix, so an object's own OID matches
exactly while an instance or table row matches its column and keeps the rest as
the index. An OID nothing describes stays a number.

**Custom-MIB-scoped polling** (`NodePoller._poll_custom_mib`): a
device/group `mib_file_id` override (new `_OVERRIDE_COLUMNS` entry,
resolved by `effective_config()` the same as every other override, zero
extra code) selects one uploaded MIB whose resolved scalar objects
(`db.mib_objects(mib_file_id, resolved_only=True)`, excluding
notifications) get GETed every poll cycle and folded into the same
`metrics` list `record_metric_sample()` already loops over — no new
storage schema, `metrics`/`samples` are already generic per-device tables
keyed by an arbitrary string. The one non-obvious part: `mibparse.py`'s
stored OID for an `OBJECT-TYPE` clause is the object's *tree position*,
not a GET-able instance — real SNMP requires the standard scalar-instance
`.0` suffix (the same convention `nodeoids.SYSTEM_SCALARS`'s hand-written
OIDs already bake in), so `_poll_custom_mib` appends it before GETting.
This also naturally enforces the scalars-only scope without any explicit
detection: a genuine table-column OID harmlessly returns `noSuchInstance`
for its `.0` and is silently skipped, same as an object the device simply
doesn't support. Failure is best-effort exactly like `UCD_SNMP`/
`HOST_RESOURCES` elsewhere in this file — one `except SnmpError: pass`
around the whole GET, never failing the rest of the poll. Stored kind is
always `"gauge"`, deliberately never `"counter_rate"`: that string is
schema-documented as valid but has zero actual rate-computation consumers
anywhere in this codebase, so using it here would imply behavior that
doesn't exist.

**Timeout vs. end-of-table accuracy** (`_walk_column`,
`_poll_interfaces`): `SnmpTimeout` is a *subclass* of `SnmpError`, so a
bare `except SnmpError` at a table walk's loop-stop condition used to
treat a genuine mid-walk timeout (device stopped answering) identically
to `noSuchObject`/`noSuchInstance`/`endOfMibView`/leaving the subtree (the
table's real, clean end) — a device that timed out partway through
enumerating interfaces looked exactly like one with fewer interfaces, no
error surfaced anywhere. `_walk_column` and `_walk_indexes` gained an
opt-in `raise_on_timeout: bool = False` parameter instead of changing
default behavior everywhere: every on-demand/best-effort caller (DOM
reads, the MAC table, custom-MIB polling) still swallows a timeout the
same as any other `SnmpError`, since a stale sensor reading is harmless.
Only `_poll_interfaces`'s ifIndex-discovery walk — the one result that
actually drives the device's own up/down status — opts in, so a genuine
timeout there now raises and lands in `snmp_error` as "... table walk cut
short after N row(s)" instead of vanishing. A timeout on one interface's
own per-interface GET (not the ifIndex walk itself) is narrower still: it
doesn't invalidate the whole poll — the device answered enough to
enumerate interfaces — so it's counted (`skipped_timeouts`) and logged,
not raised.

**Missing vendor MIB detection** (`NodePoller._check_vendor_mib`,
`NodesDatabase.has_mib_covering`): vendor autodetection already happened
on every poll (`nodeoids.vendor_for` on the device's sysObjectID); this
reports the other half — that the vendor is known but nothing on the
server describes it. "Covering" means a resolved `mib_objects` row
*strictly below* the device's enterprise arc: the app bundles
enterprise-number roots for ~20 vendors, so a plain prefix test would
match every common vendor out of the box and could never report anything
missing. A root-only entry names a vendor; an object beneath it decodes
something, and only the latter counts.

Coverage is re-evaluated on every poll and diffed against a persisted
per-device verdict (`devices.mib_covered`, NULL/0/1 via `_migrate()`),
with events recorded only on transitions — `mib_missing` on the first
uncovered verdict or when a covering MIB is deleted, `mib_present` when
one arrives (paired in `alertrules.CLEARS`, so the upload auto-resolves
the standing alert). The first cut instead keyed off sysObjectID
*changes*, which made the feature inert for every device whose identity
was already stored — the whole existing fleet on an upgrade, and every
device promoted from Discovery, whose sysObjectID `seed_identity`
pre-fills. One guard remains: the check returns early unless
`nodeoids.enterprise_root()` is non-empty, specifically because
`vendor_for()` longest-prefix-matches `trapdecode.WELL_KNOWN`, which names
standard-tree nodes too ("system" for 1.3.6.1.2.1.1), so a device with a
standard-tree sysObjectID would otherwise be reported as missing a
"system MIB" that does not exist.

**Per-poll debug logging**: `eventlog.NODES` had been imported into
`nodepoll.py` since the Alerts build and never once used. `_poll_device`
now logs one `NODES`-category event per poll with a structured `detail`
(ping/SNMP outcome, interfaces found, metrics found or the exact
`snmp_error` text on failure, elapsed time) — the same
target-plus-structured-detail convention `monitor.py`'s traceroute
logging already uses. `get_debug()`'s `events` list was already fully
generic across every `eventlog` category via `service.log.since(since)`,
so these appear on the Debug tab with no additional plumbing; the one
addition there is `"node_counters": service.node_poller.counters` —
`NodePoller.counters` (`polls`/`ok`/`timeout`/`auth_fail`/`unsupported`/
`errors`/`overruns`) was already being incremented on every poll and
never surfaced anywhere before.

`counter_rate()` and `detect_reboot()` are pure functions, unit-tested in
the module's own `__main__` block with no network needed. A 32-bit
counter that decreased is assumed to have wrapped once; a 64-bit counter
that decreased is treated as a reset instead, since a genuine 64-bit wrap
would take centuries at any realistic speed — this is why `_poll_interfaces`
prefers ifXTable's high-capacity/high-speed columns whenever present. A
`speed_bps`-derived implausibility check (the implied rate exceeding
~1.3× the interface's own reported speed) catches the case a 32-bit
counter's single-wrap assumption cannot: a link fast enough to wrap more
than once between two polls is treated as a reset rather than a
fabricated multi-wrap number. `detect_reboot()` compares actual vs.
wall-clock-expected `sysUpTime` with a 30-second grace band, and
explicitly excludes the case where the previous reading was already near
`2**32` hundredths (TimeTicks' own ~497-day wraparound) so a genuine wrap
is never misreported as a restart.

`_poll_device()`'s status transitions use an explicit `reachable` flag
threaded through to `nodesdb.record_poll()`, separate from the *display*
status string: a device that just started failing keeps showing its last
real status (`up` or `down`) during the `down_after_failures` grace
window rather than flashing to `unknown` on a single missed poll, but
`consecutive_fail` still has to advance on every one of those grace-window
polls or the counter can never actually reach the threshold that would
flip the display to `down` — the same chicken-and-egg shape as
`alertengine.py`'s own threshold-hysteresis bug (below), independently
present here and fixed the same way: increment the streak before, not
inside, the branch that checks whether it crossed the line.

The "up" event (the one the built-in `device_up` alert rule reacts to as
"Device recovered") is gated by `not first_poll`, where
`first_poll = previous["last_poll_ts"] is None` — `previous` being the
pre-update row `record_poll()` returns, so this is a direct read of
whether the device has ever completed a poll before, not a guess from
its status text. Without it, `add_device()` leaving a fresh row at the
schema's `status='unknown'` default meant a brand-new device's very
first successful poll satisfied `was_status not in ("up",)` exactly the
same as a real down→up transition, firing (and emailing) a recovery
alert for a device that was never actually down. Deliberately scoped to
only the "up" branch: a device that comes up *down* or *unsupported* on
its first poll still fires that event immediately, since knowing a
just-added device is already unreachable is useful, only "recovered" is
nonsensical with nothing to have recovered from.

### Discovery (`nodediscover.py`)

`DiscoveryJob` runs on its own daemon thread, one per active job —
`IpamWorker`'s per-job-thread shape, not `Monitor`'s pool, since a
discovery sweep is a one-shot bounded task rather than a recurring
per-target schedule. It reuses `ipam_scan.sweep()`/`usable_addresses()`
for the ping half rather than reimplementing it, then attempts an
unauthenticated v1/v2c SNMP identity GET (`_snmp_identify`, one shot over
`nodepoll._Session`, so a reply is accepted only from the address asked
and only with the request id sent; the import of `_Session` is
function-local, which is what keeps the cycle away — `nodepoll` imports
this module at module level)
against whichever addresses answered, trying every v1/v2c community drawn
from a caller-chosen polling profile (`api.py`'s `post_nodes_discovery`
resolves the profile's primary credential plus its `group_credentials`
alternates into a comma-separated community list before calling in,
reusing the same `[primary] + group_credentials(...)` shape
`credential_candidates()` already assembles for polling — v3-only
credentials contribute nothing to the list, since discovery was already
v1/v2c-only). `nodediscover.py` itself still knows nothing about
profiles or credential storage — it only ever sees a plain community
string via the pre-existing `discovery_communities` override key, the
same one a hand-typed list used before profiles existed. `NodePoller`
owns the dict of active jobs and exposes
`start_discovery`/`cancel_discovery`/`promote`; `promote()` treats an
already-promoted result as a no-op rather than a duplicate-IP error, so a
partially-overlapping re-selection is always safe to retry.

The SNMP half is a thread pool (5.0.1). The ping half was always parallel
— `ipam_scan.sweep()` — but identification was one address at a time, and
since almost all of that time is a socket waiting for a device that will
never answer, a /24 of mostly-dead addresses took as long as the sum of
its timeouts. The job thread now submits each address to a
`ThreadPoolExecutor` of `discovery_workers` threads (default 32, ceiling
`MAX_DISCOVERY_WORKERS` = 256, per-scan override `workers` on
`POST /api/nodes/discovery`), and:

- **Pacing is unchanged and still belongs to the submitting thread.** The
  probe rate is a promise about packets per second, not about
  parallelism, so the submit loop still releases at most one probe per
  `1/discovery_probes_per_second`, on an absolute schedule (`started +
  slot * interval`) so a slow submit cannot make the rate drift upward to
  catch up afterwards. It waits on the stop event rather than sleeping,
  so a cancel lands inside a pacing gap as promptly as anywhere else.
  Addresses that never get a packet — the never-scan list, a subnet
  sweep's silent addresses — consume neither a slot nor a delay. What the
  pool buys is overlap of the *waiting*, which is where the time goes.
- **One lock, and nothing SNMP under it.** `_probe_one` runs on a pool
  thread and does only network work; `_record` takes the job's single
  lock and does all of the shared-state work in one step: the counters,
  `_result_addresses` → `fold_target` → `add_discovery_result` →
  `register_addresses`, and the coalesced progress write. The fold
  decision and the row it depends on cannot be separated, or two
  addresses of the same router finishing together would each find the
  other unclaimed and the box would be offered twice. Lock order is job
  lock → nodesdb lock, never the reverse.
- **Progress writes are coalesced** to one `update_discovery_job` per 250
  ms, since 256 workers finishing at once otherwise means 256 UPDATEs for
  a figure only the browser's poll reads. The single terminal write
  carries the exact final counters.
- **The job thread drains the pool itself**:
  `shutdown(wait=True, cancel_futures=self._stop.is_set())`, then
  `.result()` on every non-cancelled future so a worker's crash re-raises
  into `_run_safe` instead of vanishing, and only then the one terminal
  `update_discovery_job(state=…)`. A cancelled job's still-queued
  addresses are dropped, and `_probe_one` returns without recording
  anything if the stop flag is already set when it starts — a cancelled
  sweep should not claim to have probed addresses it never sent a packet
  to. One already in flight still records what it found.

One consequence worth knowing: the primary row of a multi-address device
is now whichever of its addresses answered *first*, not its lowest
address. Nothing downstream depends on which one it is — `discovery_results`
is `ORDER BY ip` and the browser's `drawDiscResultsTable` sorts client-side
— but a folded pair can come back the other way round from one sweep to the
next.

The `device`/`subnet` kind still exists internally (it decides "try SNMP
even without a ping reply") but is derived server-side by
`api.py`'s `_discovery_kind_for()` from the target string alone — a bare
address or /32 is a device probe, any other valid CIDR a subnet sweep —
so the UI no longer offers a kind picker. `_candidate_communities()`
lost its `["public"]` fallback: an empty community list (a v3-only
profile) now simply means the sweep runs ping-only, a combination
`post_nodes_discovery` refuses up front unless the job was started with
`allow_ping_only`.

Per-scan timing: the Start-discovery dialog's ping/SNMP timeout, retry
and worker values travel as `discovery_*` keys in the job's own settings
dict (the same override channel the profile's community list already
uses) — they exist only for that job and never touch stored settings.
`post_nodes_discovery` range-checks each one before it becomes an
override. Ping retries re-sweep only the not-yet-answered addresses;
`_try_snmp`'s default stays one shot per version/community combination
(a retry per guess makes a subnet sweep crawl) with extra attempts only
when this scan asked for them.

Cancel/remove: DELETE on a discovery job cancels it while it is running
(the row stays so partial results remain reviewable) and deletes it —
results cascading via the FK — once it is not, which is also what the
jobs list's Remove button and the cancelled-scan dialog's "Discard scan"
button call. The job's terminal state is decided by the stop flag after
the pool has drained, not by the submit loop: a cancel landing while the
final (or only) address was mid-probe used to fall through to `done`.

Approval flow: `discovery_jobs` carries `allow_ping_only` (a start-time
choice, not a promote-time one) and `reviewed`. The browser pops the
approve/deny dialog for any job that is `done` — or `cancelled`, where
it offers Discard instead of Dismiss — with `reviewed = 0` and
marks it reviewed via `POST .../reviewed` whichever button answers it —
on upgrade, `_migrate()` adds `reviewed` with DEFAULT 1 (unlike the
schema's DEFAULT 0) precisely so every pre-upgrade finished job counts
as already answered instead of popping a dialog apiece on first open.
`promote()` itself skips any `snmp_ok = 0` result on a job without
`allow_ping_only` — the dialog's checkbox rules are a convenience, the
poller's check is the rule — and creates an approved ping-only device
with a `snmp_enabled = 0` override so it doesn't fail SNMP every poll.

Address walk (5.0.0): a result that answered the identity GET is then
asked for `ipAdEntAddr` alone — one column, through
`_snmp_walk_column`, which is `_snmp_getnext_one` in a loop bounded by
the subtree prefix, 32 rows, a non-advancing answer and the end of the
MIB. It is not `nodepoll._walk_column`: that needs a polled device's
merged config and a session this module has no business building. A
mid-walk `SnmpError` returns what was already collected. The addresses
land in `discovery_results.ip_addresses` as JSON, filtered through
`nodesdb.alias_candidate` so the loopback every agent reports is never
one of them. `discovery_addresses` (default on) turns the whole thing
off, which makes a sweep exactly 4.54's.

Within one sweep, `owners` (`DiscoveryJob._owners`) maps each address to
the first result that reached it; `fold_target(mine, owners)` and
`register_addresses(owners, id, mine)` are pure so the rule is testable
without a socket. A later result that shares an address gets
`folded_into_result_id` and does not count towards the job's
`identified` figure — that figure is how many devices the sweep found,
not how many addresses answered. Since 5.0.1 "first" means first to
*finish*, not lowest address, and both calls happen inside `_record`'s
lock together with the INSERT whose id `register_addresses` stores —
`test_nodediscover_workers.py` runs two addresses of one device into
`_record` off a barrier to pin exactly that.

### Device identity, addresses and merge (`nodesdb.py`, `nodepoll.py`, `web/api.py`) — 5.0.0

`devices.ip` is UNIQUE and, until 5.0, was the whole of a device's
identity. A router reached on its loopback and again on a management
address was two devices: two rows polling one box, two sets of alerts,
two icons on a map, two link endpoints for one cable.

`device_addresses` already held the extra addresses — the hourly
`ipAddrTable` walk and `snmptrapd` both write it, so a trap from a
loopback could be attributed — but nothing read it for identity. 5.0
reads it in four places, and in none of them does anything merge by
itself.

**Where an address is decided.** `alias_candidate(ip)` is the one rule
for which addresses count: not blank, not `127.*`, not `0.0.0.0`/`::`.
`record_device_addresses` and discovery both go through it, so alias
storage and identity folding cannot disagree. The device's own primary
stays in `devices.ip` and is deliberately never mirrored into
`device_addresses`; `device_id_for_address` checks the primary first and
the aliases second, because the primary is the address an operator
configured and an alias is only ever supporting evidence.
`_migrate` adds `device_addresses.if_index`/`netmask` (COALESCEd on
upsert, so a source that knows only the address — a trap, a discovery
fold — never erases what the poller's fuller walk learned) and
`discovery_results.ip_addresses`/`folded_into_result_id`.

**Confidence, and what each level may do.** `_discovery_duplicate` in
`api.py` grades every discovery result against `_device_index(service)`
(one pass over the fleet per listing: primary IPs, aliases, and a
`(sysName, sysObjectID)` map):

- **high** — one of the addresses this box answered on is already a
  device's. Nothing else honestly explains that, so `promote()` records
  the addresses on the existing device and marks the result promoted to
  it instead of adding a row beside it.
- **medium** — sysName and sysObjectID both match a device the sweep
  never reached on any shared address. Two switches out of the same
  carton share that honestly, so it is a reason to look before ticking
  and never a reason to fold. The approval dialog leaves such a row
  unticked; ticking it adds the device.

`promote(job_id, result_ids, force=False)` resolves a folded result to
its primary first (ticking either row adds the one device), and `force`
skips the fold for the operator who has looked at the pair and says they
really are two boxes. The approval dialog never passes `force` — folding
is the whole point of the review it presents; "Add anyway" is offered by
**Add device** alone, where the operator typed the address themselves.

**Manual add and bulk import.** `api.Conflict(ValueError)` carries a
`payload`; `server.py`'s arm for it sits **before** the `ValueError` arm
and answers 409 with that payload merged into the body. `POST
/api/nodes/devices` raises it when the address is another device's
learned **alias** — naming that device, so the browser can offer "Add
anyway" (`force: true`) rather than only printing a refusal. A collision
with a device's own primary IP is a plain 400 with or without `force`:
the UNIQUE index behind the insert would refuse it however hard the
button was pressed, so offering "Add anyway" only bought a second
refusal. Bulk import puts the same case in its existing `duplicate`
disposition with `device_id` and `device_name`, and a body-level
`force: true` imports them.

**Finding duplicates already on file.** `duplicate_candidates(limit)`
runs three self-joins and merges them per pair:

| Source | Confidence |
|---|---|
| An address two devices both claim (alias vs primary, alias vs alias) | high |
| A shared interface MAC | high with two or more, or with a matching sysName; medium alone |
| sysName plus sysObjectID | medium |
| sysName alone | low |

The MAC source excludes the all-zero and broadcast addresses and the
HSRP/VRRP virtual prefixes (`00005e0001`, `00005e0002`, `00000c07ac`):
two routers sharing one of those are a working redundant pair, which is
the opposite of the same device twice. `ix_interfaces_phys_addr_nocase`
and `ix_devices_sys_name_nocase` keep the two case-insensitive joins off
a full scan.

**Merging.** `merge_plan` counts without writing; the dialog shows that
before the operator commits, because a merge cannot be undone.
`post_nodes_device_merge` executes in the order `delete_nodes_device`
already established for the same reason — ConfigRX, Alerts, Mapper, then
Nodes last — so a crash between two of them leaves a nodes row that still
owns whatever has not moved yet, rather than rows in three other files
keyed on an id SQLite is about to reissue.

`merge_devices` moves what belongs to the box rather than to the row: its
addresses (its own primary among them, now an alias with source `merge`,
saying where it used to be reachable), its `device_events`, the
`upstream_id` children pointing at it, and the `discovery_results` /
`vendor_learned` rows naming it. What it does **not** move is the polled
state both rows hold twice over — interfaces, metrics, MAC and neighbour
tables are the same physical ports read through a second address, and the
winner is already refreshing them. Those go with the loser through the FK
cascade, except `vlans`/`vlan_ports`/`port_vlans`, which have no foreign
key on `devices` at all and are deleted explicitly.

The other three stores each answer the same question their own way.
`configrxdb.reassign_device` moves the whole record only when the winner
has none of its own; otherwise the winner's settings, search index and
compliance results stand and only the backups move, because a backup is a
dated capture of one real switch and is never wrong about having
happened. Either way the loser's `device_config` row is dropped, for the
same reason `forget_device` gives: it holds an encrypted SSH password
keyed on an id SQLite will reissue. `alertsdb.merge_device` copies
thresholds only where the winner has none (the operator tuned theirs
against the device they were looking at), moves a mute, the parked
occurrences and any window naming the loser, and **resolves** the loser's
open alerts rather than repointing them — their entity no longer exists,
and an alert nobody can navigate to is worse than one closed with a
reason. `mapperdb.reassign_device` is described under MAPPER.

`device.merge` goes in the audit trail, and the Merge button carries
`data-requires-write="nodes"` — stamped onto the element after `App.modal`
renders it, since a button spec knows nothing about permissions, and then
`applyPermissions()` is re-run so a revoked grant settles on the open
dialog instead of leaving an irreversible control enabled.

### MIB parser (`mibparse.py`)

Not a MIB compiler, the same framing `trapdecode.py`'s own OID name table
uses. The whole strategy is one regex anchored on the literal
`::=` token: `_OBJECT_TYPE_RE`/`_OBJECT_ID_RE`/`_MODULE_IDENTITY_RE`/
`_NOTIFICATION_RE` find `NAME (OBJECT-TYPE|OBJECT IDENTIFIER|
MODULE-IDENTITY|OBJECT-IDENTITY|NOTIFICATION-TYPE) ... ::= { ... }`
without needing to parse anything about the macro body in between.
`MODULE-IDENTITY` matters more than it looks: nearly every RFC MIB names
its own root that way (`dot1dBridge MODULE-IDENTITY ... ::= { mib-2 17 }`)
and hangs the entire module beneath it, so without it BRIDGE-MIB,
LLDP-MIB, ENTITY-MIB, P/Q-BRIDGE-MIB and POWER-ETHERNET-MIB parsed to a
list of objects not one of which could resolve. The conformance macros
(`OBJECT-GROUP`, `NOTIFICATION-GROUP`, `MODULE-COMPLIANCE`) are still
ignored deliberately — they are agent-capability paperwork, nothing hangs
off them, and parsing them would roughly double `mib_objects` for no
polling value. The `IMPORTS` block is blanked (same length, newlines
preserved, so every later offset still lines up) once its symbols have
been recorded, because an import list names macros as bare symbols —
`IMPORTS MODULE-IDENTITY, OBJECT-TYPE ... FROM SNMPv2-SMI` reads to a
regex exactly like a definition whose name is `IMPORTS`.
`_strip_comments_and_strings()` masks `-- comments` and `"quoted
strings"` with spaces of the *same length*, preserving every other
byte's offset — the structural regexes run against this masked text (so
a `::=` or `--` sitting inside a DESCRIPTION string never gets mistaken
for real syntax), while DESCRIPTION/SYNTAX extraction re-slices the
*original*, unmasked text at the same span to recover the real content.
`_parse_oid_tail()` handles the general case inside a `::= { ... }`
clause: the first symbolic token is the parent, and every token after it
— whether a bare number or an annotated arc like `dod(6)` — contributes
one arc to a dotted `last_arc` chain, since a clause can carry more than
one trailing numeric arc (`{ ifMIB 2 0 }`, a NOTIFICATION-TYPE's usual
shape) as well as intermediate annotated arcs written for readability
(`{ iso org(3) dod(6) 1 }`); a fully-numeric brace body is a literal OID
needing no resolution at all.

`resolve()` repeatedly resolves any object whose parent is now known
(`WELL_KNOWN_ROOTS` plus every previously-resolved name, seeded by the
caller from `NodesDatabase.all_known_oids()` across every uploaded MIB)
until a fixed point, mutating each object's `.oid` in place and returning
the sorted list of still-unresolved parent names — this is the whole
"upload order matters" story: uploading a dependent MIB before the one
defining its parent branch leaves it (and anything depending on *it*)
unresolved, and re-running `resolve()` after the parent is uploaded
finishes the chain without re-parsing anything. `nodes_mibs.db`'s `mib_files`
table keeps the original uploaded text (`content` column) specifically
so a later Resolve can re-parse from scratch — `mib_objects` only ever
stores the final `oid` or `NULL`, never the `parent`/`last_arc` an
unresolved object would need to retry.

`load_into()`/`known_oids_for()` extract the exact parse → resolve →
store sequence `post_nodes_mib` runs, as module-level functions taking a
`NodesDatabase` directly, so a bundled MIB loaded at startup and a real
upload go through provably identical code — same review UI afterward,
same re-resolve behavior, same admin-edit-survives-re-resolve guarantee.

`resolve_all()` is what makes upload order stop mattering. `resolve()`
reaches a fixpoint *within one file*; what it cannot see is a parent
defined in a file parsed later. `resolve_all()` re-parses every stored
MIB that kept its `content`, then walks the whole set repeatedly, feeding
each pass's newly-resolved names into the next, until a pass gains
nothing (capped at `max_passes`, 8). Only files whose name→oid map
actually changed are written back, so calling it when everything already
resolves is a read-only no-op rather than a rewrite of every row. It runs
after a zip upload, after a catalog install, after bundled-MIB seeding,
and behind the **Resolve all** button. In practice the bundled IETF set
needs three passes and finishes at 100% resolved.

**A wall-clock budget checked only between phases cannot bound the phase
it's checked after — the fix in 4.49.0.** `parse()` refuses a file over
`max_bytes` (8 MiB by default) before scanning anything (`MibTooLarge`), and
is meant to abandon a file that runs past `budget_s` (`PARSE_BUDGET_S`, 5.0)
mid-parse (`MibParseTimeout`) via `check_budget()`, called between phases.
`_strip_comments_and_strings()` — the very first phase, masking `--
comments` and `"quoted strings"` before any structural regex runs — called
`text.find("\n", ...)` on every ASN.1 `--` comment marker to find where it
closes; where no newline lies ahead (one long logical line — a minified or
half-downloaded MIB, or a deliberately hostile upload) each call scanned to
end of file for a newline that wasn't there, at O(markers × length): 600,000
markers (~1.8 MB) measured at 5.25 s, already past `PARSE_BUDGET_S`, and
700,000 (~2.1 MB) at 7.21 s — and `check_budget()` never got a chance to fire
on any of it, because it only runs *after* this call returns. This is a third
instance of one bug class in a file whose docstring already named two
earlier ones (the macro-clause `::=` scan, the `IMPORTS` symbol-list scan),
both fixed by patching the one instance found.

Fixed two ways, together. `no_newline_from` caches the result once a search
for the next `\n` comes up empty: no later search, starting further along
the same string, can find one either, so the O(length) failure-mode search
only ever runs once per file rather than once per marker (the mirror `--`
search needs no such cache — at most one such search per call can come up
empty regardless of file size). And `_strip_comments_and_strings` now takes
the caller's `deadline` directly and calls a shared `_check_deadline()` every
4,096 loop iterations, rather than only being checked once it returns — so a
phase slow enough to blow the whole budget on its own is cut off *during*
it now, not after. Both fixes are independent: the cache makes the
pathological shape fast again; the in-loop check makes the budget actually
bound whichever phase it's checked inside, including this one and the
object-scanning loops below it, not only the boundaries between them.

### MIB catalog (`mibcatalog.py`)

A static list of `Bundle(key, vendor, name, description, source, files)`
where `files` is `[(filename, url)]`. Static because the catalog has to
be browsable on a server with no outbound access — `GET
/api/nodes/mib-catalog` never touches the network, it only annotates each
bundle with how many of its filenames are already in `mib_files`. Nothing
is mirrored into this repository: the URLs point at Cisco's own
`cisco-mibs` repository and at LibreNMS's aggregated vendor tree, and are
fetched only when an operator presses Install.

`POST /api/nodes/mib-catalog/{key}/install` starts one background thread
holding an `InstallJob` the UI polls at `/status`, shaped like the
discovery jobs in `nodediscover.py` — a plain object with single-assignment
fields, no locking beyond the GIL, because only the worker writes and only
the API reads. One install at a time by design: two racing installs would
interleave their fixpoint resolves over the same tables for no benefit.
Each file is capped at `max_mib_bytes` and the bundle as a whole at
`max_mib_bundle_bytes`; a filename already present is skipped rather than
loaded twice, since a second copy would define every name twice in
`all_known_oids()` and would discard the operator's edits on the first.
Every file is stored first and `resolve_all()` runs once at the end,
which is what lets a bundle be installed as an unordered heap.
`fetch_file()` reads one byte past the cap so an oversized file is refused
rather than silently truncated into a MIB that parses to nonsense, and
turns a `URLError` into a message naming outbound HTTPS and the
upload-by-hand alternative — a server with no internet must get an
explanation, not a traceback.

`unpack_zip()` backs the zip branch of `post_nodes_mib`. It enforces the
count and total-size caps against the archive's *declared* uncompressed
sizes before reading anything, so a zip bomb is refused without being
expanded, skips non-MIB members (vendors ship readmes and PDFs beside
their MIBs, and refusing the whole archive over those would be useless),
and flattens paths — a MIB's identity is its module name, not its folder.

`server.py`'s dispatcher coerces a captured route group to `int` only when
it is all digits; the catalog's `([\w-]+)` bundle key is the one route
group that is a name rather than a row id.

### Bundled default MIBs (`netpath/mibs/`, `Service._seed_default_mibs`)

Twenty-one files ship under `netpath/mibs/`, about 900 KB in total. Three
are hand-authored: `enterprise-roots.mib` (public IANA Private Enterprise
Number arcs for ~20 common vendors, matching `trapdecode.WELL_KNOWN`'s own
number-to-name table), `enterprise-roots-2.mib` and `if-mib-core.mib` (an OBJECT-TYPE subset of RFC
2863's IF-MIB covering exactly the columns `nodeoids.IF_TABLE`/`IFX_TABLE`
already poll — kept although the full IF-MIB now ships too, because a
device may be pinned to it by `mib_file_id`). The other eighteen are the
standard IETF modules verbatim: SNMPv2-SMI/TC/MIB, IANAifType-MIB,
INET-ADDRESS-MIB, IF-MIB, IP-MIB, TCP-MIB, UDP-MIB, HOST-RESOURCES-MIB,
UCD-SNMP-MIB, ENTITY-MIB, ENTITY-SENSOR-MIB, BRIDGE-MIB, P-BRIDGE-MIB,
Q-BRIDGE-MIB, LLDP-MIB and POWER-ETHERNET-MIB. These are RFC text, freely
redistributable, and no vendor-proprietary MIB is bundled — vendor MIBs
are fetched on demand by the catalog above.

An arc added after a release is a **new file**, not a new line in
`enterprise-roots.mib`, which is why `enterprise-roots-2.mib` exists (Moxa's
8691, added in 4.32.0). Seeding is tracked by filename, exactly so that a MIB
an admin deleted is never resurrected — which also means an edit to an
already-seeded file reaches no existing install. A new filename does. Vendor
identification itself never depends on this: it reads `trapdecode.WELL_KNOWN` in
code, so only the MIB browser and upload resolution are affected.

`Service._seed_default_mibs()` runs once from `start()`, before
`_snmp_settings_with_mibs()`. It cannot use "does a `mib_files` row with
this filename already exist" as its skip condition, because that row is
exactly what disappears when an admin deletes a bundled MIB on purpose —
checking presence there would silently recreate it on the next restart.
Instead, every filename ever successfully seeded is recorded in the
`seeded_mib_files` setting (a CSV string, alongside Nodes' other settings
in `nodes.db`) the first time it loads; each start checks a bundled
file's name against that list, not against `mib_files()`, so "already
seeded" and "deleted on purpose" are both skip conditions and neither is
ever confused with "never seeded". Newly seeded names are merged into the
setting and saved in the same pass, then `resolve_all()` runs over the
whole set and `_snmp_settings_with_mibs()` is re-run so the bundled
vendor names reach the SNMP Trap decoder on first start, exactly as any
other upload would. The fixpoint pass is not optional here: the bundled
set is a dependency graph (Q-BRIDGE-MIB hangs off P-BRIDGE-MIB,
ENTITY-SENSOR-MIB off ENTITY-MIB), and although one sweep in filename
order happens to work today, a file added later would otherwise land
half-resolved with nothing to say so.

### Device packet-loss chart (`nodes.js deviceDialog`, `nodesdb.series`)

Purely a front-end feature: `nodepoll` has recorded `ping_loss_pct` as a real
metric since 4.25, and `/api/nodes/devices/{id}/metrics` plus
`/api/nodes/devices/{id}/series` already serve it. 4.33.0 drew it in the
device pane under the status timeline; 4.34.0 moved it into the double-click
device dialog (`#ndd-loss-range`, `#ndd-loss-chart`), where the range, the
request ticket and the 15 s refresh timer are locals of that dialog's closure
— the same shape as the interface dialog's bandwidth chart — torn down on
`modal-closed` and guarded by the dialog's `current()` token. Windows past
six hours are fetched with `bucket_s = window / 300`.

Three things are deliberate:

- **Its own range dropdown and its own window state**, separate from the
  pane timeline's `view.chartRange`. The status timeline's range is about how
  long a device has been in a state; the loss chart's is about how a link has
  been behaving. Sharing one made both worse.
- **`opts.peak`**, a new option on `drawSeriesChart`, pins the Y axis to
  0–100 %. Without it the auto-scale is `niceCeiling(max(values, 0.001))`, so a
  device with no loss at all is drawn against a ceiling of 0.001 and its flat
  zero reads as a full-height alarm.
- **The range list stops at three days.** `nodesdb.series()` switches to the
  `samples_hourly` rollup table beyond `86400 * 3`, and `compact_rollup()` —
  the only thing that writes that table — is never called from anywhere in this
  application. A 7- or 30-day option would therefore be permanently empty, for
  every metric, not just this one. Wiring compaction into the maintenance loop
  is **not** a safe drive-by fix: it deletes raw samples older than an hour, so
  every window between one hour and three days, which reads raw samples today,
  would empty out instead. `fillRanges()` grew an optional `maxSeconds` for
  this; the status timeline keeps the full list because it reads
  `device_status_segments`, not samples.

The loader reads the metric id fresh from `/metrics` on every refresh rather
than from `view.metrics`: `loadDetail` replaces that wholesale and can switch
the selected device underneath an open dialog, which is how the interface
chart once requested another device's series.

### Device status timeline (`nodesdb.device_status_segments`)

`device_events` is a sparse *transition* log (one row per up/down/
unsupported/auth-failed change), not a dense per-poll sample log like
NetPath's `traces` table — a device polled every 60s that's been up for
a week can have zero `device_events` rows in that window. That's why
`analysis.build_timeline()` (NetPath's own status-lane builder, which
buckets dense per-poll rows into fixed-width slices) can't be reused
here: it has no concept of "no events in this window means nothing
changed," only of empty buckets.

`device_status_segments(device_id, t0, t1)` instead: reads the latest
relevant event strictly before `t0` (to know the state active when the
window opens — absent that, the window opens as `"unknown"`), every
relevant event inside `[t0, t1]`, and the device's *current* live
`status` column; then walks them pairwise into `{ts_start, ts_end,
status}` segments, extending the final one to `t1` using that current
status. `device_events.kind` values (`up`/`down`/`unsupported`/
`auth_fail`/`rebooted`/`poll_overrun`) collapse onto the same small
display-status vocabulary `devices.status` already uses
(`up`/`down`/`unsupported`/`auth`) — `rebooted` and `poll_overrun` are
ignored for segment purposes, since neither changes which of those four
states the device is in.

The frontend (`nodes.js`'s `drawStatusTimeline()`) renders this as one
`<rect>` per segment across the full window width, using the same
`STATUS_COLOR` map the device table's own status dot already uses —
modeled on NetPath's status-lane segment drawing
(`netpath.js`'s `<rect>`-per-segment loop), not `drawSeriesChart`'s
continuous-line renderer, which has no notion of a discrete state. It's
fetched alongside the rest of `loadDetail()`'s `Promise.all`, using the
same `t0`/`t1` window the metric chart's range picker already drives, so
switching the range re-fetches both together.

**Split SNMP/ping lanes (`nodesdb.device_method_segments`) — 4.53.0.**
The combined segments above follow `devices.status`, which is whichever
method `unreachable_ping_only` prefers (ping, by default) — a dead SNMP
agent behind a healthy ping never shows there. Four new
transition-only `device_events.kind` values, `snmp_up`/`snmp_down`/
`ping_up`/`ping_down`, are recorded by `nodepoll._poll_device` on a real
change in `snmp_ok`/`ping_ok` (compared against the pre-update device
row, seeded on first observation, never written when that poll didn't
touch the method at all). An install upgraded from before the lanes
existed already has `snmp_ok`/`ping_ok` populated, so no transition would
ever fire for an unchanged device: once per device per process the poller
asks `nodesdb.has_method_events` and, if nothing was ever recorded, treats
the previous values as unknown so that poll seeds both lanes. The kinds
are listed once, in `nodesdb.TIMELINE_ONLY_EVENT_KINDS`: the alert engine
skips them (they carry no meaning `up`/`down`/`snmp_error`/`auth_fail`
doesn't already cover), and the overview histogram and the device
dialog's EVENT LOG exclude them inside the query
(`device_events(exclude_kinds=)`) so an outage is one row, not three.
`device_method_segments(device_id, t0, t1)` walks each method's events
through the same pairwise-segment logic as `device_status_segments`
(both now share `_event_segments`, parameterised on which kinds count
and what the final segment's status is), keyed off `devices.snmp_ok`/
`ping_ok` for the live end-of-window status, and returns `{"snmp":
[...], "ping": [...]}` with `None` in place of a method's list when it
has never once recorded a transition — a method not polled at all, or
history from before this version. `get_nodes_device_timeline` (`api.py`)
adds this as `methods`, plus `methods_enabled` (from the device's
effective config, not the per-poll `polling` flag) so the frontend can
tell "never split" from "no transitions yet" before any have been
recorded. `nodes.js` draws two lanes, SNMP above PING, sharing the same
per-segment drawing code (`drawTimelineLane`) the combined view uses,
and falls back to the single lane when either `methods_enabled` says
only one method runs or the matching list is `None`.

### MAC search (`nodesdb.py`, `nodes.js`)

Nothing normalised a MAC address anywhere in this app before 4.31.0, and
nothing stored a learned one: `read_mac_table` is an explicitly on-demand
live walk, per device *per port*, run only while a dialog is open. So a
search had nothing to match. `mac_entries(device_id, if_index, mac, vlan,
seen_ts)` stores what the scheduled walks learn, keyed on all four of the
first columns and indexed on `mac`.

`mac` is stored **normalised** — lowercase hex, no separators — so one
stored row answers `AA-BB-CC-DD-EE-FF`, `aa:bb:cc:dd:ee:ff`,
`aabb.ccdd.eeff` and bare hex alike. `normalize_mac(text)` strips
`:-. ` and whitespace and returns "" for anything that is not hex or is
longer than twelve digits, so callers can use the empty string to mean
"that was not a MAC". Prefixes are allowed on purpose: searching an OUI is
a normal thing to want.

`looks_like_mac_search` is the search-path wrapper, and exists for one
false positive: `10.0.0.5` normalises to `10005`, which is valid hex, so a
plain `normalize_mac` would quietly turn every IP search into a MAC-prefix
search too. Text that is digits-and-dots only is an address, and a
genuinely all-numeric MAC typed with dots is rare enough to be worth
losing next to searching by IP, which people do constantly.

`devices(text=...)` matches `mac_entries` as well as `ip`/`name`/`sys_name`
when the text normalises to **four or more** hex digits; fewer would match
half the estate. `mac_locations(prefix)` returns every (device, port) a
matching address was learned on, joined to `interfaces` for the port
description — every one, never a chosen one, because a MAC on an uplink is
on every switch between here and the host and picking one silently sends
an engineer to the core switch for an access-port problem. `nodes.js`
decides from the count: exactly one (device, port) opens that port's
dialog, several are listed as clickable hits.

`replace_mac_entries` no longer deletes and reinserts a device's table on
each walk. It marks every stored row for the device `present = 0`, then
upserts this walk's rows back to `present = 1` with a fresh `seen_ts`
(`ON CONFLICT(device_id, if_index, mac, vlan)`); `first_seen_ts` is stamped
once, the first time a key is ever stored, and never touched again. A MAC
that steps off a port keeps its row — `present = 0`, `seen_ts` frozen at its
last confirmed sighting — so a search can still say where and when it was
last seen instead of finding nothing. `mac_locations` returns `present`,
`seen_ts` and `first_seen_ts` and orders present rows before stale ones;
`nodes.js` renders a present hit as before and a stale-only result as "last
seen on … at …". `prune_mac_entries` (a week by default, from
`mac_table_retention_days`) runs in `Service.run_maintenance` and deletes by
age regardless of the flag — a present row's `seen_ts` is refreshed on every
confirming walk, so in practice it reclaims only genuinely stale rows and
devices dropped from the schedule entirely. The old rule that a failed walk
(a `None` return) leaves the stored table untouched still holds.

**GETBULK table walks** (`nodepoll._walk_column`, `_session_for`,
`_walk_request`). One table column is walked over a single shared UDP
socket rather than a fresh socket per row, and on v2c/v3 with GETBULK —
`non_repeaters = 0`, `max_repetitions = settings["snmp_bulk_max_repetitions"]`
(default 40; 0 disables it and falls back to GETNEXT). A 90-row forwarding
table drops from ~100 requests to about 5. v1 has no GETBULK PDU and always
uses GETNEXT, still on the shared socket; the choice keys on the raw
configured version, deliberately not the `version or 1` coercion used only
for framing. Each response's varbinds are accepted in order until one leaves
the base OID's subtree, answers `noSuchObject`/`noSuchInstance`/`endOfMibView`,
or is not lexicographically after the last accepted OID (a looping agent),
and the next request resumes from there. `error_status == 1` (tooBig) halves
`max_repetitions` and retries, falling back to GETNEXT at one repetition
rather than looping. The old hardcoded 512-row ceiling is now
`settings["snmp_walk_max_rows"]` (default 16384), logged once when hit.
`_walk_indexes` and so interface discovery share this walker and the same
reduction.

The lookup runs only on a deliberate search — Enter in the Find box sets
`view.macSearchPending`, which `refresh()` consumes once — never on the
five-second refresh, because a dialog that reopens itself every five
seconds is unusable.

### Device and interface dialogs (`nodes.js`)

`drawIfaceTable` and `drawEventTable` used to hardcode `#nd-if-table` /
`#nd-ev-table` and read the module-level `view.ifaces` / `view.events`,
both of which always describe the *selected* device. The device dialog
shows a device that need not be selected, so both take a target element
and their data as arguments and the pane and the dialog share one
renderer rather than growing a second copy that drifts. The dialog fetches
by id for the same reason.

`interfaceDialog` had the same bug latent in it: it bound `deviceId` from
`view.selected`, so a port opened from the device dialog would have
charted whichever device the list happened to have selected. It now takes
an explicit id.

There is only one `#modal-box`, so opening a port from the device dialog
replaces it; the port dialog takes an `onBack` callback and grows a
**Back to device** button, the `confirmDestructive`-style reopen idiom.
`ifaceTitle` puts the parent device on its own line **inside** the `<h2>`
so it inherits the heading's size — a line in the body would render as
`.section` at 11px. The 5s refresh re-sets that whole `<h2>` from
`ifaceTitle`, so both lines are rebuilt together and cannot drift apart.

---

## MAPPER

MAPPER (`mapper.py`, `mapperdb.py`, `web/static/mapper.js`) is a manually-
built L2 map: an operator places devices and unmanaged peers on a named
map and MAPPER draws the links between whatever is placed, resolved live
against `nodesdb`'s neighbour and VLAN tables. Nothing here polls anything
of its own — `web/service.py`'s `_apply_mapper` is a documented no-op, and
`Service.mapper_db`'s path is derived from `configrx_db_path`'s directory
rather than taking an eleventh constructor argument, specifically so every
existing call site building a `Service` (every test, `demo/`,
`__main__.py`'s path resolution) keeps working unmodified.

### Storage (`mapperdb.py`)

`maps` / `map_nodes` / `vlan_colors`. A map row is just a name and notes;
`map_nodes` is one row per device or unmanaged peer placed on one map,
`device_id` and `peer_key` mutually exclusive (`add_node` raises unless
exactly one is set) and enforced unique per map through **two partial
indexes** — `ux_map_nodes_device` (`WHERE device_id IS NOT NULL`) and
`ux_map_nodes_peer` (`WHERE peer_key <> ''`) — rather than one composite
`UNIQUE(map_id, device_id, peer_key)`: because the column that is not this
row's identity is always NULL/`''`, a single composite index would let the
same device land on a map twice as long as each row's NULL device_id or
empty peer_key made the tuples look distinct to SQLite. Each identity gets
its own guarantee in the column that actually carries it. `vlan_colors` is
deliberately global rather than per-map: VLAN 20 should draw the same
colour on every map, or a strand followed from one map to another would
appear to change identity for no reason. Deleting a map cascades onto its
`map_nodes` through the schema's own `ON DELETE CASCADE` (`foreign_keys=ON`
is one of `SqliteStore.PRAGMAS`), not a second `DELETE` in `delete_map` —
one place decides what deleting a map takes with it.

`update_nodes` (the bulk position/label/role write a drag-end or an
align/distribute action sends) validates every item's `role` **before**
the first `UPDATE` runs, not inside the write loop — a bug caught during
this release: raising partway through the loop left the earlier rows of
that same call already written into a transaction nothing there commits or
rolls back, so the next unrelated commit on the connection would silently
adopt half a drag. The whole batch is validated up front instead, so a bad
item fails the call before anything is written.

One device entered twice multiplies here rather than merely repeating:
each row is placed separately, each draws its own neighbour links, and
the same physical cable appears as two links between four icons. That is
the visible cost of the duplicate problem "Device identity, addresses and
merge" (Nodes, above) exists to stop, and it is why `reassign_device` —
which repoints `map_nodes.device_id` and, on a map where both rows were
already placed, **deletes** the loser's node rather than repointing it
(`ux_map_nodes_device` would refuse the update, and two icons for one
switch is exactly what the merge is undoing) — keeps the winner's own
position: it is the node the operator has been looking at.

### Link assembly (`mapper.py`) — pure, no sqlite3/SNMP/HTTP

This module re-does, properly and with VLANs added, the reasoning the
pre-4.53.0 fleet-wide L2 graph carried in `web/api.py`'s deleted
`_topology_dedup_key`/`_topology_unknown_identity` (4.53.0's changelog:
"a separate module will replace the graph itself" — this one). Every
function is a plain transform over rows/dicts a caller hands in, which is
what makes `tests/test_mapper_links.py` exhaustive with no database or
poller in the loop.

- **`peer_identity(row)`** is what folds two unmatched neighbour rows into
  the same unmanaged peer: chassis id first (LLDP/CDP chassis ids are
  supposed to be globally unique, normally a MAC), then sysName (weaker —
  two sites can both name a phone the same thing — but still better than
  nothing), then a `(device_id, if_index, protocol)` fallback for a row
  with no identity at all. Each branch is prefixed (`chassis:`, `sysname:`,
  `row:`) so a chassis id that happens to look like a sysName string can
  never collide with one across the branch boundary.
- **`link_identity(device_id, if_index, matched_id, matched_if_index)`** is
  a link's *undirected* identity, so a cable walked from both ends folds
  into one line rather than drawing twice. When `matched_if_index` is
  known — nodesdb's join of the remote chassis MAC to the remote device's
  own interface — the key is `frozenset({(A, ifA), (B, ifB)})`: sorted
  before stringifying (`_link_id`) so the id does not depend on which end
  happened to be walked first, which matters because an id that changed
  with insertion order would look to the UI like the link itself had
  changed every time one end re-walked before the other. **A sysName-only
  match cannot be folded this way and deliberately isn't**: nodesdb only
  tells this code "these sysNames match", not which of the matched
  device's own ports faces this cable, so guessing would risk pairing a
  row against the *wrong* port on a multi-homed device. It gets its own
  per-row key (`("name-match", device_id, if_index)`) instead — drawn as a
  second, one-directional line rather than a wrong guess.
- **VLANs on a link are the union of what each end's own port reports,
  never the intersection.** A trunk is only really usable for a VLAN both
  ends allow, so intersection looks like the "more correct" answer — but
  one end very often has no VLAN data at all (an unmanaged peer has no
  VLAN MIB to ask; plenty of managed devices answer no VLAN MIB either),
  and intersecting anything with the empty set is the empty set. That
  would erase every VLAN on the link the moment either end is VLAN-blind,
  a strictly worse failure than occasionally showing a VLAN the far end
  doesn't carry.
- **A VLAN membership that has aged out no longer draws, matching how a
  stale neighbour link already behaved — a gap caught by review.** Before
  this release's fix, `api._mapper_port_vlans` read every `port_vlans` row
  for a device regardless of `present`, so a VLAN a trunk had genuinely
  stopped carrying kept drawing on the map, unchanged, until
  `prune_port_vlans` eventually deleted the row after
  `mac_table_retention_days` (7 days by default) — up to a week of a
  removed VLAN reading as still-present, on a map where the link it rode
  had already gone stale or dropped. `_mapper_port_vlans` now drops
  `present = 0` rows and any row older than `stale_after_s`, the identical
  two checks `assemble_links` already applies to the neighbour rows
  themselves (see its own "Presence and staleness" paragraph) — the same
  `stale_link_hours` setting, `None` when a caller means "trust `present`
  alone", passed through from `get_mapper_map`.
- **A Cisco switch answering the same neighbour over both LLDP and CDP on
  the same port used to be counted twice.** `assemble_links` now dedupes a
  peer's `seen_via` entries on `(device_id, if_index)` before appending —
  a bug found during this release: without it, "Add neighbours" reported
  the same physical cable as two, because a Cisco device answering both
  protocols for one neighbour produced two rows that both reached the
  peer-building code path.
- **`vlan_color_index(vlan, overrides=None)`** is a Knuth-style
  multiplicative hash into a 16-entry table (`(vlan * _KNUTH_MULTIPLIER) &
  0xFFFFFFFF`, top 4 bits kept) rather than `vlan % 16`: real sites number
  VLANs in round, evenly-spaced blocks (10, 20, 30, …, 100, 200), and every
  one of those is a multiple of 10, so `% 16` walks the same handful of
  residues over and over and collides most of a site's VLANs onto a few
  colours — precisely the "which colour is which VLAN" confusion the
  feature exists to prevent. `_KNUTH_MULTIPLIER` (1248904971) was chosen by
  searching odd 32-bit integers (multiplying by an odd constant is a
  bijection mod 2**32, so no VLAN id is ever folded onto another one's
  product — only the top bits kept afterward can collide) for one that
  keeps those specific round numbers scattered; `tests/test_mapper_links.py`
  asserts this over exactly the round-number ids a real network uses.
  `overrides` (from `mapperdb.vlan_colors()`) lets an operator pin one
  VLAN to a specific slot without touching the hash for every other one.
- **`render_plan(link, threshold, max_strands, width_min, width_max,
  color_overrides)`** is why the render plan is computed here, server
  side, rather than in `mapper.js`: the drawing maths — which VLANs
  collapse into which strand offsets, how wide a collapsed trunk gets —
  has to live in exactly one place or two browsers open on the same map
  could disagree about what a threshold-straddling link looks like, and a
  future change to the maths would have to be made (and tested) in one
  file rather than kept in step across a Python service and a browser
  script. Three modes: `"plain"` (0 known VLANs — still a real link, drawn
  as one neutral line, `known: False` so the UI can tell "no VLAN data at
  all" apart from "exactly one VLAN"), `"strands"` (fewer than `threshold`
  VLANs AND fewer than `max_strands`, one strand per VLAN, offsets spaced
  `width_min * 2` apart and centred so the bundle never drifts as the VLAN
  count changes), and `"collapsed"` (at or above `threshold`, OR at or
  above `max_strands`, one line whose width linearly interpolates between
  `width_min` at `threshold` and `width_max` at `max_strands`, clamped at
  both ends — a link sitting exactly at `threshold` draws at `width_min`,
  the same width the last strand mode used, so the transition has no
  visible jump). **`max_strands` is checked independently of `threshold` —
  "count < threshold AND count < max_strands", not "count < threshold"
  alone — because it is a genuine ceiling on how many strands are EVER
  drawn individually, not only a bound on how far the collapsed width can
  scale; an earlier version of `render_plan` used it for the width
  interpolation alone, so a `vlan_collapse_threshold` misconfigured well
  above `max_strand_vlans` could still draw hundreds of individual
  strands. `_check_mapper_settings` now refuses to store a
  `max_strand_vlans` at or below `vlan_collapse_threshold` going forward
  (that pair would leave no strand mode ever reachable), but `render_plan`
  itself has no way to know its caller validated anything, so it enforces
  the cap unconditionally either way.**

**`detect_role(vendor, sys_descr, sys_object_id, platform, unmanaged)`** is
a node's auto-detected role, pure and side-effect free — a classification
over fields `nodesdb` already has, no new polling. `unmanaged=True` returns
`"unmanaged"` unconditionally before any other field is even read: an
unmanaged CDP/LLDP peer has no device row of its own, only whatever its
neighbour report happened to say about it, far too thin a signal to guess
switch/router/firewall/ap/server from. Every blank field returns `""`, the
honest "found no signal", kept distinct from an operator's own explicit
"switch" pick by a separate `role_auto` flag (`api._mapper_node_role`)
rather than overloading the same string for both meanings. Rule order
after that — firewall, then AP, then router, then switch, then server,
then a `"switch"` default — matters, because several vendors' sysDescr
vocabulary only disambiguates in that order: **Fortinet and Cisco are
deliberately absent from `_FIREWALL_ONLY_VENDORS`** even though both sell
firewalls, because both vendor keys also cover switches, routers and APs
from the same maker (FortiGate/FortiSwitch/FortiAP all answer vendor
`fortinet`; ASA/Firepower sit alongside Catalyst/ISR/Aironet under
`cisco`) — only a model-line word in the sysDescr text itself
(`_FIREWALL_HINTS`, `_AP_HINTS`) can tell them apart, so the vendor key
alone is trusted only for a maker whose entire catalog really is one kind
of box (`_FIREWALL_ONLY_VENDORS`: Palo Alto, SonicWall, Check Point,
WatchGuard, pfSense). Switch hints are checked before the server rule so a
switch that also happens to run embedded Linux in its sysDescr banner
still reads as the switch it is, not a server. **The default for a
managed device with a signal but no specific match is `"switch"`, not
`""`**: the all-fields-blank check above already ruled out "nothing at
all", and on an LLDP/CDP-walked L2 map an unclassified box is far more
often a switch than a
router, firewall or AP — defaulting to the common case leaves less for an
operator's manual override to correct than defaulting to a generic glyph
every plain switch would otherwise need hand-classifying out of.
`api._mapper_node_role` prefers `map_nodes.role` (an operator's own
override) whenever it is set, calling `detect_role` only otherwise — the
two `""` meanings (mapperdb's "unset" storage value vs. detect_role's own
"no signal") are never compared to each other, only ever asked as two
separate questions, which is what keeps them from colliding.

**`api._mapper_node_name(label, resolved)`** is the fix for a node whose
operator-set label was being ignored by both the drawn name and the CSV
export: `get_mapper_map`'s `name` and `get_mapper_map_export`'s
`device_name` callable both used to read straight from the resolved
device/peer identity, so renaming a node on the map changed nothing an
operator could see reflected back, including in what they exported. Both
now read `name`/`resolved_name` from this one function instead, so a
label fix in one place fixes both consumers — `resolved_name` is kept
alongside `name` precisely so a client can still show "renamed from
`resolved_name`" without losing that fact the moment a label is set.

### A map GET's cost, and what a review found still wrong in the render — 4.54.0

**`get_mapper_map` reads only the devices a map actually places, not the
whole fleet — a fix, not the original design.** Before this release,
`get_mapper_map` called `nodesdb.all_neighbours()` and the fleet-wide
VLAN-membership read behind it directly: every neighbour row and every
`port_vlans` row in the database, inside the shared `nodesdb` lock, on
every single map refresh — 33.7 s on a synthetic 2,000-device fleet, for a
map placing two of them. `nodesdb.neighbours_for_devices(device_ids)` and
`api._mapper_port_vlans`'s own `port_vlans_for_devices(device_ids)` (both
chunked the same way `devices_by_ids` already is, for the same "a page-
sized bulk selection can still be hundreds wide" reason) cut that to
0.037 s for the same two-device map. This is sound specifically because
`assemble_links`'s own `on_map(device_id)` check drops any neighbour row
whose OBSERVING device is not on the map before it ever looks at the far
end (see its own docstring's processing-order paragraph): every row that
could matter to a map of `device_ids` has its own `device_id` among them,
so restricting the read to those ids loses nothing `all_neighbours()`
would have contributed.

**A strand's VLAN used to be conveyed by colour alone.** `mapper.js`'s
`drawLink` gave every strand of a "strands"-mode link the identical
`aria-label`/tooltip — the whole LINK's own text, naming no VLAN at all —
so colour was the only signal distinguishing strand N from strand N+1,
invisible to a colour-blind viewer or a screen reader. Every strand now
gets its own per-VLAN `aria-label` (`role="img"`, discoverable by a screen
reader's browse cursor even when not a Tab stop) and its own mouse
tooltip. Only the FIRST strand of a bundle is `focusable`/`role="button"`
and a Tab stop at all — the same single stop a `"collapsed"` link already
gets — deliberately not one Tab stop per strand: up to `max_strand_vlans`
(30) identically-shaped stops for one link was worse than one, and would
make a `"strands"` link behave nothing like a `"collapsed"` one for no
reason a keyboard user would understand. That one stop's `aria-label`
lists every VLAN on the link by id/name (`linkAriaLabel`), not just a
count.

**Three MAPPER settings that drew nothing at all, now wired up.**
`show_port_labels` (a small label at each end of a link naming that end's
own port, `link.a_port`/`b_port`) and `show_vlan_labels` (the VLAN id on
each strand, or the VLAN count on a collapsed trunk) both existed in
`mapperdb.DEFAULTS` — on by default — with nothing in `mapper.js` reading
either before this release; `drawLink`/`drawPortLabels` now gate on them.
Separately, a node's detail pane (`linkDetailHtml`'s node-side
counterpart) grew an actual rename control (`#mpd-rename`/
`#mpd-rename-save`), calling the same `PUT /api/mapper/maps/{id}/nodes`
bulk-update route `api._mapper_node_name` (above) already renders
correctly — the write path existed, but nothing in the interface reached
it from a node's own detail view before this release.

**A second review, after all of the above had shipped, found a third
fleet-wide read the first review's own fix (above) had not touched.**
`_mapper_vlans_json` still called `nodesdb.all_vlans()` — every VLAN row
in the whole fleet — to name a handful of VLAN ids a map's own links
already carry, inside the same shared lock `neighbours_for_devices`/
`port_vlans_for_devices` were introduced to get out from under: measured
at 88.2 ms on 2,000 devices × 50 VLANs, for a map placing two of them.
`nodesdb.vlans_for_devices(device_ids)` — the same chunked-IN-clause shape
as the other `*_for_devices` accessors, sound for the same reason: every
VLAN id `_mapper_vlans_json` could ever need a name for was read off a
link, and a link only exists between two devices this map places — cuts
that to 0.2 ms for the same two-device map. The true cost of a map GET
was always the sum of all three fleet-wide reads, not the two the first
review happened to name; `tests/test_mapper_api.py` now disables every
`all_*` accessor `nodesdb` has (not just the ones a reviewer happened to
name) and asserts a map GET still returns 200, so a fourth one added
later fails the same way rather than shipping unnoticed. `all_vlans`,
`all_port_vlans`, `all_vlan_ports` and `vlan_ports_for` — the fleet-wide
accessors nothing else called — are removed as dead; `all_neighbours`,
`vlans_for` and `port_vlans_for` stay, because tests still call them.

**The same review found `vlan_ports` was being written and pruned on
every poll and read by nothing at all.** `api._mapper_vlan_ports`, built
from the new `vlan_ports_for_devices(device_ids)` (`nodesdb.py`, the same
bounded shape as `port_vlans_for_devices`), feeds four new fields onto
every link `get_mapper_map` returns — `a_port_mode`/`a_native_vlan`/
`b_port_mode`/`b_native_vlan` — read from each end's own
`(device_id, if_index)` row, never the far end's, the same locality rule
`_mapper_port_vlans` already applies to `port_vlans`. This is a stronger
source than the link's own `native_vlan` (`mapper.assemble_links`, which
only ever derives one from `port_vlans.tagged` and only from the A side):
a device's own `vlan_ports` row is what it actually reports its port
configured with. `mapper.js`'s link tooltip shows the mode beside each
port and, when `a_native_vlan`/`b_native_vlan` disagree, names the
mismatch explicitly ("Native VLAN 1 on X, 99 on Y — mismatched") rather
than falling back to the link's own single, weaker `native_vlan` — a real
misconfiguration worth seeing rather than averaging away. `present = 0`
and stale-by-`seen_ts` rows are dropped, the same two checks
`_mapper_port_vlans` already applies, so a port that stopped reporting a
mode reads as unknown rather than keeping the mode it last had.

**And a gating gap, not a data one: several MAPPER write controls were
gated only once, at render.** The maps dialog's Rename and Delete, the
align dialog's eight buttons, and the VLAN colour swatch/picker built
their `disabled` attribute from a one-shot `App.canWrite('mapper') ? ''
: 'disabled'` ternary at render time and were never wired into
`applyPermissions()`'s periodic re-check the way every other write
control in the product already is (see "Gating disables; it never
hides", below) — a write permission revoked while any of those stayed
open left a control that still looked enabled until the operator closed
and reopened it. All now carry `data-requires-write="mapper"`, exactly
like every other write control `applyPermissions` walks.

### A map GET's cost, part two — 5.0.0

4.54.0 (above) bounded the map GET to the devices a map places. What it
did not touch was the SQL those bounded reads run, or the four reads a
badge and a port label still made outside them.

**`_NEIGHBOR_MATCH_SQL` compared with `LOWER()` on both sides.** Its two
case-insensitive joins — a neighbour's `sys_name` against
`devices.name`/`devices.sys_name`, and its chassis MAC against
`interfaces.phys_addr` — were written `LOWER(col) = LOWER(n.col)`.
`LOWER(col)` is an expression, so no index on `col` can serve it: SQLite
read and folded every row of `devices` (twice) and `interfaces` (once)
for every neighbour row, on every neighbours read and every map GET.
They are plain collated comparisons now (`col = n.col COLLATE NOCASE`),
which mean exactly the same thing — SQLite's NOCASE folds the same ASCII
range `LOWER` does — and can use an index of the same collation.
`_migrate` creates the two that were missing,
`ix_devices_sys_name_nocase` and `ix_interfaces_phys_addr_nocase`
(`devices(name COLLATE NOCASE, ip)` already existed for the other half of
the sysName join), and `EXPLAIN QUERY PLAN` now reports a MULTI-INDEX OR
across both device indexes plus a search on the interfaces one, where it
used to report three scans. Measured on a synthetic 2,000-device,
24,000-interface fleet with 800 neighbour rows: **3.81 s → 0.005 s** for
the fleet-wide form. `_UPSTREAM_CANDIDATE_SQL`, `neighbours_of`,
`all_neighbours` and `neighbours_for_devices` all inherit it.

**Three indexes dropped.** `ix_vlans_device`, `ix_vlan_ports_device` and
`ix_port_vlans_device` each indexed `device_id` on a table whose PRIMARY
KEY already *leads* with `device_id` — and a non-INTEGER primary key is
an index in SQLite. They answered nothing the table's own index did not,
and cost a B-tree write per row on every VLAN walk. They are gone from
`SCHEMA` and dropped in `_migrate`; the lookups they were added for read
exactly as they did.

**Four bounded accessors** replace the reads the route still made outside
its own device list — `metrics_for_devices(ids, keys)` (the badge values;
`metrics_for_keys` reads the whole fleet, which is right for the alert
engine and wrong here), `interface_counts(ids)` (one grouped COUNT, not
one `interfaces()` row read per placed device), `interface_port_labels_
for_devices(ids)` / `interface_port_labels(id)` (four columns, and
`_neighbor_local_port_labeler(service, prefetch_ids=…)` fills its whole
cache from one call instead of a `SELECT *` per device as each first
neighbour row arrives) and `device_summaries()` (seven columns for the
"Add device" list, where `devices()` returned `SELECT *` — around forty
columns including `sys_descr` and the vendor-evidence text — for the
whole fleet; 23.6 ms → 3.3 ms per call at 2,000 devices). Each chunks by
`_IDS_PER_QUERY` and returns an empty result for empty input without
touching the database, exactly as `devices_by_ids` does.

**No per-map memo, deliberately.** The obvious next step — cache a map's
assembled payload against `maps.updated_ts` — would be wrong: a node's
`status`, its badges and a link's `seen_ts` all change without anything
touching `maps.updated_ts`, so a memo keyed on it would serve a map whose
devices had since gone down. With the indexes above the GET is indexed
lookups over a handful of devices; there is nothing left worth the risk
of showing a stale map.

### Rendering (`mapper.js`) — 5.0.0

Every gesture used to call `draw()`, which rebuilt the entire scene —
grid, every link, every strand, every node, every listener — synchronously
inside the event. A pointermove fires faster than a frame.

- **`requestDraw()`** coalesces to one full redraw per animation frame.
  Everything that used to call `draw()` calls it; `loadMapData` keeps one
  synchronous `draw()` so a fresh payload is on screen before the function
  returns.
- **`applyTransform()`** is the whole of a pan, a wheel zoom, the zoom
  buttons, the arrow keys and Fit: they change where the scene sits, not
  what it contains, so they set one `transform` on `view.sceneGroup`. It
  falls back to `requestDraw()` when there is no scene yet.
- **`redrawDragged()`** moves the dragged `<g>`s and re-runs `drawLink`
  for `view.linksByNode`'s entries only — each link is drawn into its own
  `<g>` so exactly those can be emptied and refilled. One full redraw at
  drag end, where the dropped positions are what everything else is
  measured from.
- **The rubber band** is one rect created with the scene and moved in
  place, rather than appended by a full redraw per pointermove.
- **`applySelectionClasses()`** toggles `.selected` on elements that
  already exist. A drag begins by capturing the pointer on a node's own
  `<g>`; rebuilding the scene there would replace that element out from
  under the capture, which is why the start of a drag repaints the
  selection rather than redrawing.
- **Tooltips are built on first hover or focus**, not while drawing: a
  30-strand link built 30 strings — each resolving both endpoint names and
  joining every VLAN id — for text nobody may ever read. `aria-label`
  stays eager, because a screen reader needs it in the tree.
- **The grid is one `<pattern>` and one `<rect class="mp-grid">`** instead
  of one `<line>` per grid step (600 hit-testable elements on a map
  spanning 6,000 units at the default 20-unit grid). `.mp-grid-line` still
  names the stroke, so the per-style CSS is unchanged, and `.mp-grid` is
  `pointer-events: none` because the rect covers the whole drawing.
  `exportPng`'s `inlineComputedColors` gained one guard for it: a
  computed `fill` of `url(#mp-grid-pattern)` comes back absolutised
  against the page's own URL, which resolves to nothing inside the
  detached copy the PNG is rendered from, so a `url(…)` value is left
  alone and the clone's own same-document attribute carries it.
- **Lookups are Maps**, rebuilt once per payload in `rebuildLookups()`:
  `nodeMap`, `linkMap`, `vlanNameById` and `linksByNode`. Each was an
  `Array.find()` inside a loop over nodes, links or strands.
- **`contentBounds()` runs once per draw**, passed to `fitView(bounds,
  width, height)` and to `nextPlacement(index, bounds)` (which re-walked
  the map once per device being added).
- **`fastTick` no longer redraws the legend.** The legend changes when the
  map's data does, so `loadMapData()` and `activate()` draw it.

**Reloading `#/mapper/<id>`** left the canvas blank. `deliverRoute` awaits
`refreshNow('mapper')` and only then calls `activate()`, but `refresh()`
picked the *remembered* map — so the routed one arrived as a second load —
and it stamped `view.lastAutoTs` only after that first `await`, so the
poll tick landing meanwhile started a third. Two of the three raced
through `loadMapData`'s generation guard. `refresh()` now prefers the id
the address bar names (`App.currentRoute()`, `parseRoute` exported) and
stamps `lastAutoTs` before it awaits anything; `app.js`'s `refreshNow()`
marks the page `refreshing` for the whole call, so `master()`'s existing
overlap guard covers a route or tab refresh too; `scenePoint()` returns
`null` rather than reading a frame the first paint has not built; and
`draw()` re-reads the frame's *size* every time while leaving the
operator's own centre and zoom alone.

### Pointer input and re-fitting (`mapper.js`) — 5.0.1

**A click moved the node.** `event.currentTarget` is null the moment the
event carrying it finishes dispatching, and `onNodePointerDown`'s `up` and
`cancel` closures — which run on a *later* event — read it to take their
listeners off again. So `up` threw a TypeError on every release before it
removed anything: the `pointermove` listener stayed on the node's own `<g>`,
`view.nodeDrag` stayed set, and from then on every hover over the map moved
the node the operator had merely clicked, writing a new position each time.
The element is captured once (`const target = event.currentTarget`) into all
three listeners, and the teardown moved into a `finally` so a throw in the
position-write path cannot leave the gesture half-live either; `cancel`
detaches the same three listeners `up` does.

- **The drag threshold is screen pixels** (`MOVE_THRESHOLD_PX`, 3), not the
  2 *scene units* it was: at zoom 0.2 that was under half a pixel of pointer
  travel, so a click counted as a drag; at zoom 5 it took a centimetre.
- **The frame is frozen for the gesture.** Scene units per screen pixel
  (`perPixelX/perPixelY`) are read once, at the press, and the drag is the
  client delta scaled by them — a re-fit, a pane resize or a zoom arriving
  mid-gesture can no longer scale the tail of a drag differently from its
  head and jump the node out from under the pointer.
- **A press with no frame selects and starts nothing**, rather than
  recording a null origin that later moves would subtract from.

**Re-fitting.** `draw()` fitted the scene on *every* draw until the operator
happened to zoom or pan (`!view.userZoom`), so an auto-refresh, a pane
resize or a badge appearing threw away an arrangement just made. A map is
fitted when it is opened (`selectMap` sets `view.needsFit`) and when **Fit**
is pressed (`fitView` clears the flag); otherwise a draw updates only
`frame.width/height` and leaves centre and zoom alone. `view.userZoom` is
still written by the wheel, the pan, the zoom buttons and the arrow keys as
the record that the operator has moved the view themselves, but it no longer
gates the fit — `needsFit` does. (netpath.js's own `userZoom` is unrelated
and still gates its re-fit: that canvas is laid out fresh every poll,
MAPPER's is a place.)

**One measured element.** `draw()` sized the scene from `#mp-canvas` while
`scenePoint`, the pan and the wheel zoom all measured `#mp-svg` — the
canvas's own 1px border makes the two boxes differ in each axis, which is
enough to land a press beside the point it was aimed at. Everything measures
`#mp-svg` now, and `draw()` measures it *after* `showCanvas` (a canvas
returning from the empty state is `display:none` until then, and would
measure as zero).

**Nothing redraws under a gesture.** `gestureActive()` (a node drag, a
rubber band or a pan) gates `refresh()` and the `resize`/`panes-resized`
handlers, which is the promise FEATURES.md makes for the auto-refresh;
rebuilding the scene mid-drag also replaced the very `<g>` the pointer was
captured on. An explicit reload that still lands mid-drag (a settings save,
a VLAN colour change) ends the drag in `loadMapData` rather than dropping
nodes at coordinates from the payload it just replaced.

**A trunk with 200 VLANs.** `linkTooltip` listed all of them on one line,
in a box that follows the pointer, cannot be scrolled and had
`white-space: pre` — so the list ran off the side of the window and the
native-VLAN mismatch under it ran off the bottom. `VLAN_TOOLTIP_CAP`
(10) names the first ten and says how many more there are;
`.tooltip` wraps (`pre-wrap`, `overflow-wrap: anywhere`) and caps its own
height. `linkDetailHtml` caps at `VLAN_DETAIL_CAP` too, but behind a
`data-show-all-vlans` button `drawDetail` wires — the full list is still
one click away, in the one place that can scroll. `selectLink` resets
that choice, since it is a decision about the link being read.

**And a dialog bug the same pass found:** `openAddNeighbours` called
`App.grid` once, outside `redrawNeighbourRows`, so re-sorting the table
appended a second `<tbody>` and every neighbour appeared twice. It calls
`App.grid` per redraw now, exactly as `drawVlanTable` always has.

### Nodes' per-port VLAN membership (`nodesdb.py`, `nodeoids.py`, `nodepoll.py`)

Three new `nodesdb.py` tables rather than one, because they answer three
different questions and age independently: **`vlans`** — which VLANs a
device knows about at all, keyed `(device_id, vlan)`; **`vlan_ports`** —
which of its ports are trunk vs. access and a trunk's native VLAN, keyed
`(device_id, if_index)`, since a port has exactly one mode and native VLAN
at a time; **`port_vlans`** — the actual many-to-many a link's strands are
drawn from, keyed `(device_id, if_index, vlan)`. All three follow the same
present-flag ageing UPSERT `replace_neighbors` established: every stored
row for a device is marked `present = 0` at the start of a walk, then each
row the walk actually saw is upserted back to `present = 1` with a fresh
`seen_ts` — so a VLAN or membership nothing has seen recently reads as
*stale*, not as a topology change that never happened.

`nodepoll.read_device_vlans(device_id)` is the walk, four sources in
authority order:

1. **`dot1dBasePortIfIndex`** resolves a BRIDGE-MIB bridge port number to
   the ifIndex the rest of the app keys interfaces by — the same table the
   FDB walk already resolves through its own private `_bridge_port_map`.
   Absent entirely on some small switches, which is not the same fact as
   "this device has no ports": `resolve()` falls back to treating the
   bridge port number *as* the ifIndex directly, since plenty of small
   switches number 1:1 and never populate this table — a wrong guess on a
   device numbered differently only misattributes which port a VLAN
   belongs to, a smaller loss than dropping every membership the device
   reports.
2. **Q-BRIDGE-MIB**, the standards path: `dot1qVlanStaticName`/
   `...EgressPorts`/`...UntaggedPorts`, falling back to the
   `dot1qVlanCurrent*` pair only where the static table came back empty —
   a VTP/GVRP client legitimately carries no static configuration of its
   own. A port in the egress bitmap but not the untagged one carries that
   VLAN tagged; in both, untagged (`dot1qPvid` names which VLAN that
   untagged membership actually is, i.e. the port's native VLAN).
3. **CISCO-VTP-MIB, Cisco only** (`detected_vendor(device) == "cisco"`,
   the same gate `_walk_cdp` uses) — **and a Cisco answer for a port
   genuinely trunking supersedes whatever the standards path said about
   that same port**, rather than merging with it: `vlanTrunkPortVlansEnabled`
   (split across four OIDs — base 0/1024/2048/3072, since the base MIB
   predates VLANs above 1024) is the trunk's *configured* allow-list, while
   classic IOS's own `dot1q` egress bitmap often reflects only VLANs with a
   currently active member — a narrower, more volatile fact than what is
   actually configured to cross the trunk. `read_device_vlans` deletes any
   membership the standards path recorded for a port before writing the
   Cisco answer over it. **The supersede is gated on
   `vlanTrunkPortDynamicStatus == trunking(1)` for that same port — a real
   defect, caught by review, in an earlier version of this code that
   applied it unconditionally.** On real IOS, `vlanTrunkPortDynamicStatus`
   answers a row for EVERY switchport, access included, reporting
   `notTrunking(2)` — and such a port still answers `vlanTrunkPortVlansEnabled`
   with its configured allow-list (IOS's own default: every VLAN) and
   `vlanTrunkPortNativeVlan` with IOS's default of 1, neither of which is a
   fact about that access port at all. Applying the Cisco override
   unconditionally threw away a correctly-read access VLAN (`dot1qPvid`,
   via the standards path) in favour of a fabricated ~4094-VLAN trunk on
   every access port in the fleet. A port with `dynamicStatus != trunking`
   (`notTrunking`, or a port this column simply never covers) now keeps
   whatever the standards path already recorded for it, and is merely
   labelled `"access"` when IOS says outright that it is one.
4. **`mac_entries`' own `vlan` column**, evidence rather than
   configuration, consulted only for a port neither (2) nor (3) described
   at all: a VLAN whose traffic this device has learned on a port is
   evidence that VLAN crosses it even though no VLAN table said so, but
   never allowed to override an authoritative answer.

**PortList and VLAN-bitmap decoding** (`nodepoll._decode_port_list`,
`_decode_vlan_bitmap`) share one octet/bit scan (`_bit_positions`) but NOT
the same numbering — an off-by-one here, caught by review, meant every
Cisco trunk VLAN id `read_device_vlans` reported was one too high before
this release. A Q-BRIDGE-MIB PortList is 1-based: per RFC 4363, the most
significant bit of octet 0 is bridge port **1**, so `_decode_port_list`
adds 1 to the raw bit position (`i * 8 + bit + 1`). A CISCO-VTP-MIB
`vlanTrunkPortVlansEnabled*` bitmap is 0-based: per that MIB's own
DESCRIPTION, the most significant bit of octet 0 is VLAN **0**, so
`_decode_vlan_bitmap` adds the column's own base (0/1024/2048/3072)
straight to the raw bit position with no PortList-style `+ 1`
(`base + i * 8 + bit`). Same big-endian, most-significant-bit-first octet
layout, genuinely different origin — encoding a bitmap by taking one
function's output and shifting it by the other's base would reproduce
exactly this bug, which is why `demo/personas.py`'s own encoders
(`encode_port_list`, `encode_vlan_bitmap`) are two separate functions
reasoned from each MIB's DESCRIPTION rather than one relabelled as the
other. `_decode_port_list` accepts whichever form the shared OCTET STRING
decoder (`trapdecode._octets_text`) produced — plain text, colon-separated
hex (its MAC special case) or space-separated hex — plus raw bytes
directly, since all of those round-trip losslessly to the same bit
pattern; see "OCTET STRING decoding is best-effort, not lossless" below
for the one part of this path that is not.

`vlan_interval_s` (device/group setting, default 3600 s like
`lldp_interval_s`, 0 disables it) schedules `_maybe_walk_vlans` exactly
the way `_maybe_walk_lldp` schedules the neighbour walk, sharing the same
`_mac_executor` thread pool — a separate pool from the ping/SNMP poll
pool, so this walk cannot itself saturate it. It is editable per device
(`#nd-f-vlaninterval`) and per group (`#nd-p-vlaninterval`) in `nodes.js`,
the same pair of fields `lldp_interval_s` already has — a gap caught by
review: this setting shipped with no control anywhere in the interface,
so every device would have started its hourly walk on upgrade with no way
to retune or disable it.

**OCTET STRING decoding is best-effort, not lossless — a known limit, not
a bug still open.** `_decode_port_list` (and, through it, `_decode_vlan_bitmap`)
works from whatever `_octets_from_value` hands it, which for a value that
came off the wire as text is `trapdecode._octets_text`'s printable
rendering of the raw octets — the raw bytes themselves are discarded at
BER-parse time in `trapdecode.py` and never reach this code. That
rendering is not reversible in general: `_octets_text` collapses `0x0A`
(LF), `0x0D` (CR) and `0x20` (space) to the identical character, and a
short run of hex-looking characters with no separator is genuinely
ambiguous between "these are literal printable bytes" and "this is one
non-printable byte, hex-encoded" — `tests/test_port_vlans.py` pins the
current, considerably tighter heuristic instead of asserting a lossless
round-trip it cannot deliver. Precisely what it now does and does not
manage, since an overstated limit is as unhelpful as an unstated one:

- A lone `0x20` byte survives, where the previous code's `.strip()` threw
  it away silently and returned no ports at all. `0x0A` and `0x0D` do
  **not** survive as themselves — all three render as the same single
  character, so all three read back as `0x20`, i.e. port 3. A PortList
  setting ports 5 and 7 is indistinguishable from one setting port 3.
- A literal printable byte is no longer mistaken for hex: `0x41` ("A")
  used to be reinterpreted as `0x0A` and reported as ports 5 and 7 instead
  of ports 2 and 8. That specific class of error is gone.
- A run matching the uppercase-hex-pair shape is still read AS hex, so the
  text `"12"` becomes one byte `0x12` rather than two literal characters,
  and `"10 20 30"` becomes three bytes rather than eight. That is the
  right default — an agent's PortList reaches `_octets_text` as hex far
  more often than a switch answers in literal decimal — but it is a
  default, not a certainty, and no amount of care at this layer can make
  it one without the bytes `trapdecode.py` already discarded. **This affects the
pre-existing LLDP chassis-id path too** (`lldp_neighbor`'s `chassis_id`,
read through the same shared OCTET STRING decoder), not only this VLAN
walk — it was simply never named as a limitation until this release's own
review went looking for one.

### Per-device threshold overrides (see Alerts, below)

`alertsdb.device_thresholds`, `AlertEngine._evaluate_thresholds`'s
per-rule override lookup, and the `Occurrence.rule_key` fix a same-metric
Warning/Critical pair required are covered under "Per-device threshold
overrides, and a cross-match bug", in the Alerts section below — they are
an Alerts mechanism through and through. `GET`/`POST /api/alerts/device-thresholds` back two
surfaces: the device dialog's TEMPERATURE ALERTS section (`nodes.js`,
rendered from the same hardware fetch that already had the chassis
reading) and the Overrides column and dialog on Alerts → RULES
(`alerts.js`). Both carry `data-requires-write="alerts"` even inside the
Nodes dialog, a deliberate cross-module gate: the control lives on a
Nodes screen but the decision it takes is an Alerts one. `nodes.js` calls
`App.applyPermissions()` itself after inserting that markup, because
`applyPermissions` otherwise only reruns on a config-version change and
the gate would sit unapplied on freshly rendered controls until some
unrelated event happened to trigger it.

---

## Alerts

### Rule storage (`alertsdb.py`)

`alerts.dedup_key` is enforced unique only while `state IN ('open',
'acked')` — a partial unique index, not a full `UNIQUE` constraint,
because the same dedup key legitimately recurs after a prior alert with
that key resolves. `open_or_increment()` is a single `INSERT ... ON
CONFLICT (dedup_key) WHERE state IN ('open','acked') DO UPDATE SET
count = count + 1, ...` against that index — the whole "a repeated
occurrence increments one alert instead of opening a duplicate" behavior
lives in the database's own conflict resolution, not in application code
that could race between a read and a write.

44 built-in rules and 6 built-in templates are seeded via `INSERT OR
IGNORE` keyed on each row's unique `key`, run on every open — idempotent,
so a re-open never duplicates, and an admin's edit to a built-in rule's
severity or a template's wording survives a restart because the seed
only inserts a row that does not yet exist, never updates one that does.
A built-in rule's `remove_rule()`/template's `remove_template()` both
refuse outright (disable instead) rather than deleting, since a future
re-seed must never resurrect a half-configured duplicate underneath an
admin who thought they'd removed it.

### Evaluation cursors (`alertengine.py`)

Each occurrence source (`device_events`, `interface_events`, `traps`,
`syslog`, `ipam_conflicts`) has its own `meta` row tracking the last-seen
id it has already evaluated. On a source's first-ever tick, the cursor
seeds to that source's *current* max id — never to `0` — so a fresh
install (or a newly-enabled Alerts module against months of pre-existing
trap/syslog history) does not evaluate that entire backlog as brand-new
occurrences the moment it turns on. This needed its own existence check,
`has_cursor(source)` (`SELECT 1 FROM meta WHERE source=?`), distinct from
`cursor(source)`'s int-returning `cursor()` — the two are easy to
conflate, since `cursor()` returns `0` both when a row has never been
seeded and when it has legitimately advanced back to `0`, and an earlier
version of every `_drain_*` method here used `if cursor == 0:` to decide
whether to seed, which correctly seeded on the very first tick but then
kept re-seeding to the current max on *every subsequent* tick too —
silently swallowing every new occurrence forever. Every drain method
checks `has_cursor()` now, and advances the cursor only after a whole
batch has been turned into occurrences (or explicitly skipped by
severity filtering), never before, so a crash mid-batch re-evaluates
that batch on restart rather than silently skipping part of it.

Threshold rules (`_evaluate_thresholds`) have no cursor at all — a
threshold is a state (above/below), not an event stream, so it is
re-evaluated against every threshold-kind rule's device on every 5-second
tick. Hysteresis is a `threshold`/`clear_threshold` gap plus a
`for_polls` consecutive-breach counter, tracked in memory
(`self._breach_streaks`, keyed by `(rule_id, device_id)`) rather than
persisted — a restart resets it, an accepted cold-start cost given ticks
are 5 seconds apart and `for_polls` defaults to 2. The streak has to be
incremented *before* `evaluate_threshold()` is called, not inside the
branch that checks whether it reached `for_polls` — the same
chicken-and-egg shape `nodepoll.py`'s own `consecutive_fail` handling
hit independently, and fixed the same way: an earlier version only
incremented the streak once a breach had already been detected, which
meant it could never actually reach `for_polls` and the alert could never
fire.

### DHCP scope thresholds (`alertengine._evaluate_dhcp_thresholds`)

`_evaluate_thresholds` is hard-wired to Nodes in three ways: it iterates
`nodes_db.devices()`, reads values out of the Nodes `metrics` table, and
stamps `entity_kind="device"`. A DHCP scope is none of those, so
`dhcp_scope_exhaustion` is a sibling evaluator and its own rule kind
(`dhcp_threshold`) rather than a new metric key. Utilization is
`(leases + reservations) / scope_size(start_ip, end_ip) * 100`, computed
the same way `api.get_ipam_dhcp_scopes` computes it so the number in the
alert is the number on screen; a scope whose range cannot be sized is
skipped rather than reported as 0%, which would read as "plenty of room".
Entity is `entity_kind="dhcp_scope"`, `entity_id="{server_id}:{scope_id}"`,
and `_device_ip_for` resolves that to the DHCP server's address for
`{{device_ip}}`.

The streak is the subtle part, and this evaluator got it right first.
`_dhcp_streaks` holds `(last polled_ts, streak)` and only advances the
streak when the scope's `polled_ts` actually moves, so `for_polls` means
DHCP polls rather than engine ticks — which matters because DHCP is polled
every 15 minutes while the engine ticks every `TICK_S` (5 s). As of 4.31.0
`_evaluate_thresholds` does the same thing; see below for why it had to.

### NetPath destination thresholds (`alertengine._evaluate_netpath_thresholds`)

A third threshold evaluator, for the same reason there is a second one: a
traceroute destination is not a Nodes device, has no row in the Nodes `metrics`
table, and its "poll" is its own `targets.interval_s`. Kind
`netpath_threshold`, `entity_kind="netpath_target"`, `entity_id` the target's
row id, and `_device_ip_for` resolves that through `db.destination_ip()` with
the configured host as the fallback — a destination entered as a hostname has
no address until a trace gets through.

The engine reaches NetPath the way it reaches Wireless: an optional
`netpath_db=` constructor argument (`Service` passes its own `Database`), so an
engine built without one raises none of these rules rather than failing.

`_netpath_metrics()` is the single place the three metrics are computed, and
the single place the skip conditions live. A metric it cannot compute honestly
is **absent** from the dict it returns, and an absent metric is skipped
entirely — it neither fires nor clears, and does not touch that rule's streak:

| `source_kind` | Value | Skipped when |
| --- | --- | --- |
| `trace_loss_pct` | `traces.loss_pct` — destination-hop loss on the newest trace | it is NULL |
| `trace_unreached_pct` | share of the window's traces with `reached = 0` | fewer than `NETPATH_MIN_WINDOW_TRACES` (5) measured traces in the window |
| `trace_rtt_warn_pct` | `100 * rtt_ms / max(warn_rtt_ms, 20)` | the trace did not reach the destination, or `warn_rtt_ms <= 0` |

Three details are load-bearing:

- **`status IN ('error', 'overrun')` produces no sample at all** — the whole
  target is skipped before any metric is computed. `record_trace` stores
  `loss_pct = 100` for a trace with no hops, so a `traceroute` binary that is
  missing on *this* machine, or a slot skipped because the previous run was
  still going, would otherwise be indistinguishable from a destination that
  went silent. `monitor.classify` keeps those statuses apart from `fail` for
  the same reason.
- **`reached` stands in for `TraceResult.rtt_is_to_refuser`.** That flag says
  the stored RTT is the time to a router that refused, not to the destination —
  and it is a property of the in-memory result that is never persisted. It can
  only be true when the destination was not reached, so `reached = 1` is a
  strictly stronger guard and needs no schema column.
- **Latency is relative to the destination's own `warn_rtt_ms`**, floored at
  `NETPATH_MIN_WARN_RTT_MS`. A single millisecond figure cannot serve a LAN hop
  and a satellite link, and three times a 5 ms warn threshold is 15 ms, which a
  three-probe mean crosses on a busy switch for no reason at all.

`_netpath_streaks` holds `(last started_ts, streak)` and advances only when the
trace's own `started_ts` moves — the same discipline as `_dhcp_streaks`, and
for a starker reason: the engine ticks every 5 s while a destination is traced
every 300 s by default, so a tick-counted streak would turn "three consecutive
traces" into fifteen seconds.

Rollup needed one generalisation. `_rollup_parent` hard-required
`entity_kind == "device"`; it now tests `alertrules.ROLLUP_ENTITY_KINDS`, which
lists the kinds that take part rather than dropping the guard, so a future
entity kind cannot inherit the device pairings by accident.
`netpath_path_unstable` and `netpath_latency_high` are `ROLLED_UP_BY`
`netpath_unreachable`, because a destination nothing comes back from is by
construction also one whose traces are failing and whose latency is
unmeasurable.

`_sweep_netpath_alerts()` closes a hole that only threshold kinds have: a
threshold alert clears by being re-evaluated and found to have recovered, which
never happens for a destination that was disabled or deleted. The sweep
resolves open netpath alerts whose entity is not in the current enabled-target
set and sends no clear email — nobody needs telling that a destination they
just turned off stopped being measured. It writes `resolved_by = ''`, the
same marker every other engine auto-resolve uses: the descriptive string it
used to write ("destination no longer traced") read to
`operator_resolved_since` as a hand resolve, which would have kept a
destination that is re-enabled and breaching the same rule again suppressed
for the whole seven-day window. See "Operator resolves stick" below.

**There is deliberately no per-hop rule.** Intermediate routers rate-limit ICMP
as policy (`monitor.classify`'s docstring is explicit that only the destination
hop decides a verdict), and `hop_stats` are cumulative counters reset only by a
path change, so any average over them stays high indefinitely after one bad
week. Per-hop MTR figures remain a route-graph diagnostic.

Mutes and the newly-added-device hold do not apply: `_occurrence_device`
returns `None` for anything that is not a Nodes device, so netpath occurrences
are structurally outside both — the same as syslog, IPAM, DHCP and APs.

### Threshold streaks and durations (`alertengine._evaluate_thresholds`)

Until 4.31.0 the device threshold evaluator counted **engine ticks**
against a latched `metric["last_value"]`: it incremented the streak on
every tick the value was over the threshold, whether or not a new sample
had arrived. Two consequences, both wrong and both invisible from the
setting's label. `for_polls = 2` meant ten seconds rather than two polls
(the engine ticks every 5 s; a device is polled every 60 by default). And
because the streak never reset while the value sat above the threshold, a
**single** bad sample satisfied any `for_polls` about ten seconds later
and went on satisfying it indefinitely — the value had stopped changing
but nothing compared `last_value` against `last_ts`.

`_breach_streaks` now holds `(last sample ts, streak, first breach ts)`
per `(rule_id, device_id)` and advances only when `metric["last_ts"]`
moves, exactly as `_dhcp_streaks` already did. The third element is what
makes a duration expressible at all: `breach_seconds` is
`sample_ts - first_breach_ts`, measured **between the samples themselves**
rather than by wall clock, so a device that stopped being polled cannot
accumulate breach time while silent. Any sample under the threshold clears
both.

`rules.for_seconds` (nullable INTEGER, added by `_migrate`'s
PRAGMA-and-ALTER convention) selects between the two. `evaluate_threshold`
takes `breach_seconds` as a fourth argument and uses `for_seconds` when it
is set, `for_polls` when it is NULL — never both, because "two polls AND
sixty seconds" is a rule nobody can reason about. NULL is the shipped
value for every rule but `packet_loss_high`, which ships at 60; the
migration also seeds that 60 onto an existing `alerts.db`, so an upgrade
gets the sustained behaviour rather than silently keeping the old one.
`for_seconds` had to be added in four places or it would be dropped
silently at each: `_migrate`, `_RULE_EDITABLE`, `put_alerts_rule`'s
allow-list, and `_rule_json`.

### Per-device threshold overrides, and a cross-match bug (`alertsdb.py`, `alertengine.py`, `alertrules.py`) — 4.54.0

`alertsdb.device_thresholds` is one table for every threshold-kind rule
rather than a temperature-specific one, keyed `(device_id, rule_key)` with
no surrogate id — a core switch in a hot closet and an access switch in an
air-conditioned comms room do not share a sane chassis-temperature limit,
and the same per-device tuning is just as sensible for CPU or memory
whenever a site wants it, so this serves all of them with no further
migration. `threshold`/`clear_threshold` NULL means "inherit the rule's own
value" — the same convention `rules.flap_window_s` already uses — so an
override that only wants `enabled = 0` (turn the rule off for one device,
distinct from setting the threshold sky-high: it also has no
`clear_threshold` to speak of) does not have to restate the rule's own
numbers. `_check_threshold_direction` (`alertsdb.py`) rejects an override
whose effective `clear_threshold` would not sit below its effective
`threshold`: `evaluate_threshold` has exactly one direction wired in
(breach at or above threshold, clear below `clear_threshold`), checked
against all twenty threshold-kind `_BUILTIN_RULES` rather than assumed.

`AlertEngine._evaluate_thresholds` reads every rule's override map once
per rule per tick (`device_threshold_map(rule_key)` → `{device_id: row}`),
not once per device — the same batching `metrics_for_keys` already exists
for, on a table that is usually empty or a handful of rows. A device with
`enabled = 0` is skipped before its streak is touched at all, and is never
written into `live_streaks`, so re-enabling it later starts a fresh streak
rather than resuming whatever was counted before it was switched off.

**A device with `enabled = 0` used to strand an open alert forever — a
regression caught by a second review, since the engine skipped the device
before it ever reached the branch that clears one.** A threshold alert
normally clears by being re-evaluated and found to have recovered; once a
device is skipped outright, nothing re-evaluates it, so an alert already
open when the override was set would sit open no matter how long the
device stayed cool. `_evaluate_thresholds` now resolves it in the same
step it skips the device: `self.db.resolve_by_dedup(f"{rule['key']}:
device:{device_id}", by="")`, following `_sweep_netpath_alerts`'s own
precedent for a destination taken out of rotation — "disabling ... is a
normal thing to do while working on" the thing it measures. `by=""` marks
it automatic rather than a hand resolve (re-enabling the rule for this
device and breaching again must open a fresh alert, not find itself
permanently suppressed by `operator_resolved_since`'s seven-day window),
and no clear email is sent, the same reasoning `_sweep_netpath_alerts`
already uses: nobody needs telling that a rule they just turned off for
this device has stopped being evaluated. This is a distinct case from a
rule disabled globally or a device deleted outright — both make the whole
rule or the whole device disappear at once, a rarer action after which an
operator expects things to vanish from Alerts; a per-device override is
the small, routine kind of change that must not have that effect.

**The streak key stays `(rule_id, device_id)` — it does NOT widen to
include the effective threshold/clear pair, and an earlier version of this
work that did widen it shipped a real regression, caught by review before
release.** `_child_first_breach_ts` — a rollup parent's hand-resolve asking
"did an operator resolve the run behind this occurrence" — has only a rule
and a device to look the streak up by; there is no occurrence carrying a
threshold/clear pair to widen that lookup key with, so it can only ever
ask by `(rule_id, device_id)`. Widening `_breach_streaks`' own key broke
that lookup silently: the entry the OLD three/four-element key produced
was never found by the two-element key `_child_first_breach_ts` asks for,
so a rollup parent resolved by hand could never confirm the child's run
had actually closed — resolving Critical by hand re-opened Warning on the
very next breach, the exact noise the rollup exists to prevent. The fix
keeps the key a plain two-tuple and carries the effective `threshold`/
`clear_threshold` pair a streak was counted under INSIDE the entry instead
(`self._breach_streaks[(rule_id, device_id)] = (last sample ts, streak,
first_breach_ts, threshold, clear_threshold)`): `_evaluate_thresholds`
compares the entry's stored pair against the current one on every tick,
and a mismatch resets the streak exactly as if the device had never been
seen before — same observable behaviour (a changed override starts a
fresh streak) as the regression's widened key, without breaking the
lookup a plain two-tuple key alone can satisfy. A deleted device's key
still drops out on its own, unaffected, the moment `live_streaks` replaces
`self._breach_streaks` each tick. `evaluate_threshold`'s own signature and
tests stay untouched — the effective threshold/clear pair is handed to it
as a plain `dict(rule)` copy with just those two fields swapped, since
`sqlite3.Row` and `dict` satisfy the same `.keys()` + `__getitem__`
protocol either way.

**The mismatch that resets a streak is not only a device's own override
changing.** For a device with no override at all, the "effective" pair
compared each tick is simply the rule's own `threshold`/`clear_threshold`
— so editing a rule's own numbers moves the effective pair for every
device evaluated against it, exactly the same as if each of them had just
had an override set, cleared, or edited. This is deliberate: a streak (and
a `for_seconds` run) counted against numbers that no longer apply is not
evidence of anything under the new ones. It has an operator-visible
consequence worth spelling out, though: resetting `first_breach_ts`
means `_operator_resolved` no longer recognizes the run as the one an
operator resolved by hand, so an alert that was hand-resolved but is
still genuinely breaching re-opens as a new run the next time this rule's
threshold or clear point is edited — the same as if the device had never
been seen before. There is no special case to suppress this; it follows
from the same comparison that makes a device override behave correctly.

**A bug this release's own build uncovered, not introduced by it.**
`AlertEngine._apply` matched an occurrence to a rule on `(kind,
source_kind)` alone. Two threshold rules can legitimately share a
`source_kind` — the shipped `ups_battery_low`/`ups_battery_replace` pair
already did — and `_apply` had no way to tell which of the two rules
actually raised a given occurrence: an occurrence `_evaluate_thresholds`
built while evaluating ONE rule's own streak also matched the OTHER rule
sharing the metric, double-incrementing it under the wrong rule's message
and quietly defeating the streak accounting `evaluate_threshold` had just
done. It went unnoticed until `temp_chassis_critical` — deliberately
reading the same `temp_chassis_c` metric as `temp_chassis_high` on purpose
— made the symptom visible in this release's own testing.
`alertrules.Occurrence` gained `rule_key: str = ""` (empty for every
occurrence not raised by a threshold evaluation, and for one parked before
this field existed — both load and match exactly as before), set to the
raising rule's own `key` in `_evaluate_thresholds`; `_apply` now narrows a
`kind == "threshold"` occurrence carrying a `rule_key` to the one rule that
key names before matching against anything else. `alertrules.ROLLED_UP_BY`
gained `"temp_chassis_high": "temp_chassis_critical"` on the strength of
the same mechanism the outage rollups already use, not a new one: the
entry isn't an outage rollup (`_rollup_parent`'s case 1 — a same-entity
open parent alert — is entity-kind generic and doesn't care), it just
reuses the existing map to express "an open Critical already says what
Warning is about to say" for a same-metric pair instead of an
unreachable-device implication.

### Alert mutes (`alertsdb.py`, `alertengine._muted`)

`alert_mutes(entity_kind, entity_id, until_ts, created_ts, created_by,
reason)` is a new table, so it lives in the `CREATE TABLE IF NOT EXISTS`
block beside `PENDING_SCHEMA` rather than in `_migrate` — `_migrate` only
ever ALTERs tables that already exist. Unique on `(entity_kind,
entity_id)`, with `mute()` upserting so pressing the button again extends
a mute instead of failing on the index.

The gate is in `_tick`, beside `_hold_for_new_device`, **not** in
`_apply`. A mute is per device, not per rule, so it belongs where one
check covers an occurrence rather than where one check covers a
(rule, occurrence) pair. `_occurrence_device` already resolves both
`entity_kind="device"` and `entity_kind="interface"` to a device row and
returns None for everything structurally outside Nodes, so a muted
switch's ports go quiet with it and syslog/trap/IPAM/AP occurrences
cannot be muted by a device mute — a property of the lookup rather than a
list of exemptions to maintain. The active mutes are read once per tick
into a dict, and the per-occurrence check short-circuits on that dict
being empty, which is the normal case.

A mute suppresses **new** alerts and their emails and deliberately leaves
open alerts alone. The CLEARS pairings live in the drains, which run
before the gate, so an alert opened before the mute still resolves when
its cause clears — the list stays truthful whatever the mute says. What
the mute adds there is `_notify_clear`'s own check (`_muted_alert`, its
own lookup because the drains run before `_tick` reads the per-tick dict):
the resolution lands, the email does not, because "muted" has to mean the
operator's inbox goes quiet or it has silenced only half of what it
promised. Nothing has to un-suppress when one lapses: thresholds
re-derive from live metrics on the next tick and a still-down device keeps
recording events. Expired rows read as "not muted" from `until_ts` alone
(the reads are on the hot path); `prune()` deletes them on the
housekeeping pass so the table does not grow a row per mute ever set.
`MAX_MUTE_HOURS` caps what the API will store, so a hand-made call cannot
silence a device until next year.

**The page is told which device an alert is about.** Since 4.37.0 every
alert row the API returns carries `device_id` — and, since 4.37.1, only
that: `device_name` went with it for a release and the page never once read
it, since the row already carries the engine's own `entity_label`. The rule
itself is `alertrules.device_id_for(entity_kind, entity_id)`, one function
in the dependency-free module both the engine and the API already import,
where it used to be three copies (`api._alert_device_id`,
`alertengine._occurrence_device`, `alertengine._muted_alert`): a device
alert is its own device, an interface alert (`entity_id` of the form
`<device_id>:<if_index>`) is the switch the port is on, and every other kind
is null — as is a device that has since been removed from Nodes, so the page
never offers a mute the API would refuse.

"Has since been removed" is one `devices_by_ids` query per page, returning
a **set of ids that still exist**; `_alert_json(row, present_ids)` takes it
as a required argument, because when it was optional a caller that forgot
it got every alert on the page silently reported as being about no device —
the Mute control greyed out everywhere for no visible reason. The set is
unsorted (it feeds an `IN (...)` list, which has no order to respect), and
`NodesDatabase.devices_by_ids` chunks it 500 ids to a statement: an alert
list is up to 2000 rows, and SQLite builds before 3.32 cap a statement at
999 bind parameters. `alerts.js showDetail` draws the mute area
from that field alone: enabled (the 1/6/12/24 h picker, or "Muted until … /
Lift mute" looked up in `view.mutes` by the same id) when it is set and the
account holds alerts write, otherwise disabled with a `title` and a `.hint`
line naming the reason. Before this the page tested `entity_kind ===
'device'`, which excluded every interface alert; that, the missing write
gate on the detail's own Resolve/Acknowledge, and a `bar` without `wrap`
inside an `overflow:hidden` pane were the three things reported as "the
Mute button disappeared". The detail bar's rebuild guard
(`detailSignature`) includes the device id and the mute state so a refresh
does not churn the pane under an open dropdown, and every single-row
action goes through `detailAction`, which paints a failure on the counters
line the way the bulk actions do.

The Nodes device list and single-device endpoints carry `muted_until`
from `alerts_db`, because a mute nobody can see is a mute somebody will
spend an afternoon looking for.

### Syslog severity matching (`alertrules.py`, `alertengine.py`)

`rule["severity"]` used to be write-only from the matcher's point of
view: `_apply()` stamped it onto the opened alert but never read it back
to decide whether a rule should match at all, so the built-in "Critical
syslog message" rule (severity 2) matched *every* syslog occurrence that
cleared the module-wide `min_severity` floor in `_drain_syslog()` — the
per-rule severity dropdown in the rule editor visually implies a
threshold ("this severity and worse"), matching the global setting's own
"Evaluate severity X and worse" wording, but nothing enforced that.
`Occurrence` gained a `severity: int | None = None` field, populated only
by `_drain_syslog()` from the row's own severity; `_apply()` skips a
`kind == "syslog"` rule whenever `occurrence.severity > rule["severity"]`
(lower number = more severe, same RFC 5424 convention as everywhere else
in the app). The global `min_severity` floor in `_drain_syslog()` is
still the outer gate — it decides which rows become occurrences at all —
and the per-rule check is the inner one, deciding which of those
occurrences match a *particular* rule; other kinds (`device_event`,
`interface_event`, `trap`) carry no `severity` on their `Occurrence` and
are unaffected, since `_apply()`'s check only fires when
`occurrence.severity is not None`.

### Bulk resolve and acknowledge (`alertsdb.py`)

`resolve_many(alert_ids, by)` mirrors `resolve()`'s single-id `UPDATE`
but over `WHERE id IN (?,?,...)` in one statement, the same shape as
Nodes' `bulk_update_devices` — one transaction regardless of how many
ids are selected, rather than looping a Python call per id. Both still
carry `AND state IN ('open','acked')`, so resolving an already-resolved
alert a second time (e.g. a stale checkbox from a previous filter view)
is a harmless no-op rather than an error.

`acknowledge_many(alert_ids, by)` is the same statement against
`state='open'` only — acknowledging a resolved or already-acked alert is
a no-op, matching single-alert `acknowledge()`. It exists because
"Acknowledge all" is deliberately server-wide (`ack-all`, ignoring both
the selection and the current filter), so there was no way to
acknowledge *exactly* the rows an operator had picked; `POST
/api/alerts/bulk-ack` and `alerts.js`'s shared `bulkAction(path)` are
the rest of that path.

Selection itself was the real complaint behind "bulk resolve only clears
one of the selected items": the list offered Ctrl-click selection with no
visible affordance, so a plain click looked like it was selecting when
all it did was move the detail highlight, and a bulk action then acted on
one row. `alerts.js`'s first column is now a real checkbox whose
`onclick` calls `stopPropagation()` — the box owns selection, the rest of
the row owns the detail pane, and Ctrl-click still toggles so the old
habit keeps working. The `UPDATE ... WHERE id IN` statements themselves
were never at fault and are unchanged.

### Operator resolves stick (`alertengine.py`, `alertsdb.py`)

Threshold and NetPath alerts are re-derived from live state on every tick
(see the rollup section: that is what lets a still-breaching metric re-open
on its own when an outage ends). The cost of that design was that
`open_or_increment`'s dedup lookup only sees `open`/`acked` rows, so an
alert an operator resolved while the metric was still over its limit was
opened again as a new row on the next tick — new id, unticked, a fresh
notification. "Bulk resolve does nothing" was this, five seconds later.

The rule now: **an operator's resolve closes the breach run it was made
in.** All three threshold evaluators — `_evaluate_thresholds`,
`_evaluate_dhcp_thresholds` and `_evaluate_netpath_thresholds` — keep
`first_breach_ts` in their streak state (the NetPath streak gained it in
4.34.0, the DHCP streak in 4.37.0), and once per tick the engine loads
`AlertsDatabase.operator_resolved_since(cutoff)` — `dedup_key → latest
resolved_ts` over resolved rows whose `resolved_by` is neither `''` nor
`'engine'`, within `OPERATOR_RESOLVE_WINDOW_S` (seven days), served by
`ix_alerts_state_resolved (state, resolved_ts, dedup_key)`. A breach whose
`first_breach_ts` is at or before that timestamp is the run the operator
already closed and produces no occurrence. All three ask it through one
helper, `_operator_resolved(rule, occurrence, first_breach_ts)`; it was
three verbatim copies until 4.37.1, and the DHCP evaluator spent a release
without the copy at all.

**A run ends on an observed clear, not on the first sample under the
threshold** (4.37.1). `evaluate_threshold` only reports `clear` below
`clear_threshold`; the gap up to `threshold` is the hysteresis band, which
exists precisely because a value wobbling around the limit has not
recovered. Every evaluator nevertheless reset `first_breach_ts` on `not
over`, so a CPU that dipped from 99 % to 85 % (`cpu_high` clears at 80) and
went back up counted as a new run — and the alert an operator had resolved
came back, the 4.34.0 complaint reached through the band instead of through
a poll. `first_breach_ts` is now cleared only when the evaluator's own
`result == "clear"`. The *streak* still resets on any sample under the
threshold: `for_polls` means consecutive polls over it, which is a different
question.

Every resolve a person makes goes through the API with a session username,
so "non-empty and not `engine`" is exactly "resolved by hand" — written
`COALESCE(resolved_by, '') NOT IN ('', 'engine')`. The COALESCE changes
nothing for that WHERE clause (a NULL `resolved_by` makes the predicate
NULL, which WHERE discards exactly as it discards false, which is the
wanted answer); it is written out because the predicate reads as a
statement about the data rather than as a filter that happens to work, and
because asking it the other way round — `NOT (...)`, or inside a CASE —
would otherwise yield NULL where it wanted true. Rows with a NULL
`resolved_by` do exist: a much older build, or a hand edit in `sqlite3`.

That index leads with `(state, resolved_ts)` because this is a range scan
over recent resolves. Its predecessor `ix_alerts_dedup_state` led with
`dedup_key`, the one column the query does not constrain, so SQLite walked
every resolved alert in the table on every tick. `_migrate` drops the old
index and creates the new one — an index, never in `SCHEMA`; see the
storage-layer rule above. Nothing else reads resolved rows by dedup key:
`ux_alerts_active_dedup` is a *partial* index over `open`/`acked` and so
can never serve them, and the single-key `operator_resolved_ts` that might
have wanted a second index was deleted in 4.37.1 with no callers ever
having existed.

**A resolve of a rollup parent covers the children it was hiding**
(`_parent_operator_resolved`, 4.37.0). A child is suppressed only while its
parent is open or acknowledged (`_rollup_parent` → `open_by_dedup`), so
resolving "Device not responding" for a device that is still down released
every alert that outage was covering: a dead device records
`ping_loss_pct = 100` on every poll, so "Packet loss to device high" was
guaranteed to be breaching and opened one new row and one new email per
device on the next tick. The gate above could not see it — it is keyed on
the *child's* dedup key, which no person ever resolved, and the engine
deliberately absorbs children with `resolved_by = ''` so they stay free to
re-open. `_apply` therefore asks, when `_rollup_parent` finds nothing and
`ROLLED_UP_BY` names a parent, whether that parent's dedup key is in the
per-tick `_operator_resolves` cache and whether its condition still holds:
for `device_down` that the device's `status` is still `"down"` (exactly
`_still_true`'s predicate for a held `down` occurrence), and for a parent
with no such state to re-read (`netpath_unreachable`) that the child's own
`first_breach_ts` is at or before the resolve. If so the occurrence is
counted `rolled_up` and dropped, with no rollup note — there is no open
parent row to write one onto. Widening `open_by_dedup` to resolved rows was
rejected: that would suppress children forever. This ends by itself, the
moment the device answers again, and a child still breaching on its own
account (a device that is up but lossy) opens normally.

**The cover ends when the device answers, not when the resolve gets old**
(`_parent_covers`, 4.37.1). `_operator_resolves` only reaches back
`OPERATOR_RESOLVE_WINDOW_S`, so a device hand-resolved and left down was
covered right up to the moment the resolve fell out of that window — and
then every still-breaching child opened in a single tick, one row and one
email per rule per device, seven days after anybody did anything.
`_parent_covers` is `parent dedup key → when the cover started`: the engine
records the key the first time it suppresses on the strength of a hand
resolve, and from then on the key counts as resolved whether or not
`_operator_resolves` can still see it. The entry is dropped on the tick
`_still_true` says the device is answering, which is the moment the cover
was always meant to end. In memory, so a restart forgets it — the same
tradeoff the threshold gate documents, and a restart re-derives the outage
alert anyway. The first time a device's cover takes effect the engine
writes one `NODES` line saying so, so the silence that follows can be
found from the Nodes page, where the device is visibly down; it is not
repeated per tick.

It costs no query. The parent's rule comes from `_rules_by_key`, rebuilt
once per tick from the rule list `_tick` already reads — `_rollup_parent`
reads the same snapshot as of 4.37.1, where it used to run a
`rule_by_key()` query per suppressed occurrence per tick and could see a
different rule set from the check beside it. (`_rules_by_key` holds only
*enabled* rules, which is exactly the `enabled` test `_rollup_parent` made
by hand.) The hand resolve comes from the per-tick `_operator_resolves`
cache, and the device read behind the condition is memoised per tick in
`_parent_conditions`, so N children of one dead device ask once.

Two engine paths used to write descriptive strings into `resolved_by` —
the NetPath sweep for a destination no longer traced, and a child alert
absorbed into a device outage. Both now write `''`: with the rule above, a
descriptive string would have read as an operator's decision and kept a
re-enabled destination, or a still-breaching child metric after the device
recovered, closed forever. The rollup's reason lives on the parent's
`rollup_note`, where an operator reads it anyway.

The suppression is in-memory streak state, deliberately not persisted:
after a restart every streak rebuilds from scratch, `first_breach_ts`
becomes "since restart", and a still-breaching alert an operator resolved
before the restart re-opens once. The seven-day window is a backstop, not
the mechanism — a clear ends suppression long before it matters.

**Device events are transitions, and `auth_fail` had stopped being one**
(`nodepoll._poll_device`). The up/down/unsupported events are recorded on a
change of state; `auth_fail` was recorded on *every* poll that failed with
an authentication error, so "SNMP authentication failing" re-opened within
a poll interval however often it was resolved — the credentials are wrong
until somebody fixes them, and the poller was reporting that as news each
minute.

The transition is held by the poller, in `NodePoller._auth_failing`
(a `set[int]` of device ids, mutated under the poller's own `_lock` since
polls run on a `ThreadPoolExecutor`): **entering the set records
`auth_fail`, leaving it — SNMP actually working — records `auth_ok`, and
nothing else records anything.** 4.37.0 derived both from the previous
poll's `snmp_ok`/`snmp_error` on the device row, which cannot answer
either question:

- `snmp_ok == 0` last poll and working now is not "the credentials were
  rejected and are now accepted". A device on a lossy WAN link that times
  out one poll in ten wrote an `auth_ok` on every recovery, and every one
  became an engine occurrence against `device_auth_fail`'s CLEARS pair.
- `_poll_snmp_scalars_with_credential` re-raises the *last* candidate's
  error, so a profile with several credentials can alternate the recorded
  error between an auth string and a timeout while nothing about the device
  changed. "A different auth error is a new fact" then re-recorded
  `auth_fail` every other poll — the de-duplication defeating itself.

`_auth_failing` is in memory and process-lifetime only, like `_credentials`
beside it: a restart re-records one `auth_fail` per still-failing device,
which is one event, not one per poll.

### Newly added device hold (`alertengine.py`, `alertsdb.py`)

`_apply()` is the single choke point where an occurrence becomes an alert, so
the hold sits just before it, in `_tick`. `_occurrence_device()` resolves the
device an occurrence is about — a `device` entity's id *is* the device id, an
`interface` entity's is `<device_id>:<if_index>` — and returns None for
anything else. That is what makes syslog, traps, IPAM conflicts, DHCP scopes
and wireless AP events structurally un-holdable: they never resolve to a row
in Nodes' device table, so they are exempt by construction rather than by a
list somebody has to remember to extend.

Three different shapes of condition, handled three different ways, because
"still true five minutes later" means something different to each:

- **Steady states** — `down`, `mib_missing`, `link_down` — are recorded on a
  *transition*, so suppressing one would lose it forever. These are parked in
  `pending_alerts` (a table, not memory, so a restart inside the window does
  not drop them) with `fire_after_ts = created_ts + grace`, and `_drain_pending`
  re-asks current state via `_still_true()` when the time comes: the device's
  `status`, its `mib_covered`, the interface's `oper_status`. Still true →
  replayed through the normal path with `replayed` set so the hold cannot
  catch it twice. Cleared → dropped, with a line in the event log saying so.
- **Momentary events** — `rebooted`, `up`, `poll_overrun`, `auth_fail` — cannot
  be "still true" later; by definition they already happened. They are dropped
  rather than parked, which is what "don't alert on a device I just added"
  means for them. Parking one would fire it five minutes late, describing
  something that is over.
- **Thresholds** are not parked at all, on purpose. `_evaluate_thresholds`
  re-derives them from current values on *every* tick, so one suppressed
  inside the window simply reappears on the first tick after it. Parking them
  as well would open the same alert twice.

### Alert rollup (`alertrules.py`, `alertengine.py`, `alertsdb.py`)

`alertrules.ROLLED_UP_BY` maps a rule key to the rule key whose open alert
makes it redundant — every entry currently points at `device_down`. It sits
beside `CLEARS` and is built the same way, and `ROLLS_UP` inverts it once at
import so a parent's children are a lookup rather than a scan per tick. It is
**static** because "which alerts a dead device implies" is a property of what
this app measures, not a per-site preference; the `rollup_enabled` setting
(`alertsdb.DEFAULTS`, default on) is the on/off switch, not a way to rewrite
the map.

Membership is drawn on one line: everything in it can only be measured *by
polling the device* — the two ping rules, and the SNMP-metric thresholds for
CPU, memory, storage and interface utilisation/error/discard rates. The
interface event rules (`interface_down`, `interface_up`,
`interface_flapping`) are deliberately absent: those come from ifOperStatus
transitions the device reported before it went away, so a port that went down
for its own reason is a fact about the network rather than an artefact of
unreachability.

Both halves live in `_apply()`, the same single choke point the new-device
hold uses:

- **Suppress.** Before `open_or_increment`, `_rollup_parent()` looks the
  parent up by `dedup_key(parent_rule, occurrence)` — reusing the existing
  addressing scheme rather than adding a second one — and a hit means the
  occurrence is dropped: never opened, so never emailed. `open_by_dedup`
  treats `acked` as open on purpose: an operator ticking the outage off has
  not made the device reachable.
- **Absorb.** When a parent opens (`is_new`), `_absorb_subordinates()` walks
  `ROLLS_UP` and calls the existing `resolve_by_dedup` for each child with
  `by="rolled up into <parent name>"`. It deliberately does *not* call
  `_notify_clear`: a "packet loss recovered" email while the device is still
  down would be a lie, and fewer emails per outage is the point.

Both paths record a line on the parent through `alertsdb.add_rollup_note`,
which dedupes by line so a flapping device does not grow the same note
hundreds of times. That note is its own `alerts.rollup_note` column (added by
`_migrate`, the usual PRAGMA + ALTER convention) rather than appended to
`detail`, which `open_or_increment` overwrites every time an alert recurs.

**The recovery path needs no code.** `device_up` resolves `device_down`
through `CLEARS`, and from the next tick `_evaluate_thresholds` re-derives
every threshold from current metrics — so a still-breaching CPU re-opens by
itself and one that recovered with the device stays closed. Nothing is ever
"un-suppressed"; there is no suppression state to unwind.

**A bug the rollup work uncovered.** `_apply`'s source_kind filter listed
`device_event`, `interface_event`, `trap`, `wireless_event` and
`dhcp_threshold` but not `threshold`, so a threshold occurrence matched
*every* threshold rule: one high CPU reading opened CPU, memory, disk and all
six interface-rate alerts for that device, each carrying the CPU
occurrence's message. `threshold` is now on the list. `syslog` and `ipam` are
still deliberately off it — their occurrences always carry `source_kind ""`,
so filtering on it would silently stop matching any custom rule that has one
set.

### Upstream suggestions (`nodesdb.py`, `web/api.py`) — 4.49.0

The means a *different*, cross-device rollup was missing — not the
same-device metric rollup the previous section documents (a device's own
CPU/disk/interface alerts folding under that same device's `device_down`),
but the topology rollup `_rollup_parent`'s third and fourth answers cover:
case 3 asks `alertengine._upstream_outage`, which walks
`nodesdb.upstream_chain(device_id)` looking for an ancestor with its own
already-open `device_down` alert and, if found, treats the child occurrence
as already covered rather than opening a new alert for it; case 4 asks the
same question on behalf of a *child rule* (`packet_loss_high`, `cpu_high`,
…) whose own device's `device_down` is never going to open one to check
against, for the identical reason case 3 exists. That mechanism has existed
since `upstream_id` shipped in 4.37.0 and works correctly; what was missing
is that `upstream_id` is a plain operator-typed field with no assistance
populating it, so at fleet scale nobody sets it and the walk has nothing to
climb. `alertrules.py` is explicit that this may only ever be driven by an
operator-confirmed `devices.upstream_id`, never directly by an LLDP/CDP
neighbour match — a neighbour row is a best-effort guess that can go stale
between walks or collide on a non-unique sysName, and suppressing a real
fault on a wrong guess is the one failure this feature must not have. What
nothing offered, before this release, was a way to turn that guess into a
confirmed value faster than one Edit dialog per device.

A companion fix landed the same pass, on the *absorb* side rather than the
*suppress* side above: a device fully covered by an ancestor's outage — by
either of the two routes above, or by `_absorb_downstream` resolving a
downstream device's own `device_down` into the ancestor whose alert got
there first — never itself opens a `device_down` alert, and the ordinary
absorption of a device's *other* rolled-up children (`_absorb_subordinates`)
only ever triggers off that alert opening. So a `packet_loss_high` or
`cpu_high` alert already open on a device before an outage reached it had
nothing left to trigger its own absorption once the device was covered, and
stayed on the Alerts page indefinitely. `_absorb_children_of` closes this —
called from both `_absorb_downstream` and `_rollup_parent`'s case 4 — by
resolving a covered device's own already-open children directly, bounded to
one indexed `resolve_by_dedup` per name in `ROLLS_UP["device_down"]` (a
short, fixed list) rather than a scan of the alerts table.

`nodesdb._upstream_confidence(match_kind, present)` scores one candidate into
one of four tiers: `chassis_mac` + `present` is **high** (rank 3);
`chassis_mac` + stale, or `sys_name` + `present`, is **medium** (rank 2);
`sys_name` + stale is **low** (rank 1) — a MAC-address match rates above a
sysName match regardless of freshness (a MAC collision is far rarer than two
sites both naming a switch "core-sw-1"), and a neighbour row nothing has
confirmed since an earlier walk never rates above a fresh one of the same
kind. This is a sort/filter hint only, never a threshold anything applies
automatically. `_group_upstream_candidates()` folds the raw per-neighbour-row
SQL into one
entry per observing device, keeping the single best-evidenced candidate per
distinct matched device (present beats stale, then confidence tier, then most
recently seen) and flagging `ambiguous: true` whenever a device's own rows
resolve to two or more *different* matched devices — a two-candidate device
an operator resolves is useful; a confident wrong pick chosen automatically
is exactly the failure `ROLLED_UP_BY`'s own comment warns against.
`NodesDatabase.upstream_suggestions()`/`upstream_suggestions_count()` expose
this, paged the same way `devices()` is, behind
`GET /api/nodes/upstream-suggestions`.

`POST /api/nodes/upstream-suggestions/apply` takes `{"assignments":
[{"device_id", "upstream_id"}, ...]}` (up to 2,000 pairs; a repeated
`device_id` collapses to its last entry) and writes them all in one
transaction — but not before `_find_upstream_cycle()` checks the *whole
proposed graph* for a cycle no individual pair could show. `_clean_upstream_id`
already refuses a single device pointed at itself; what it cannot see is a
batch where device A's upstream becomes B and, in the same batch, B's becomes
A — each pair valid alone, only the two together forming a loop.
`_find_upstream_cycle` walks every touched device's own upstream chain under
the proposed values (falling back to what's on file for a device the batch
doesn't mention), and — unlike the alert engine's own hot-path
`upstream_chain`, which caps its walk at `max_depth=8` for latency reasons —
can afford to walk as far as the whole fleet before concluding there's no
cycle, since this only ever runs against an operator-submitted batch. A batch
that would create one is refused outright, naming the devices involved,
rather than silently applying whatever assignments aren't part of it.
`NodesDatabase.set_upstream_ids()` is the one write behind an accepted batch
— `executemany`, since (unlike a bulk edit broadcasting one value to many
devices) every device here gets its own value.

### Interface flapping thresholds (`alertsdb.py`, `alertengine.py`)

`alertrules.evaluate_flapping()` always took `window_s` and
`min_transitions` arguments, but nothing ever passed them, so the shipped
600s/3 was unreachable from the UI. `alertsdb.py` had no `_migrate()` at
all; it has one now, following the `nodesdb._migrate` PRAGMA-then-ALTER
convention, adding two nullable `rules` columns — `flap_window_s` and
`flap_min_transitions` — both added to `_RULE_EDITABLE` so the builtin
rule can be edited. NULL means "as shipped", so an existing install
behaves identically until someone changes it.

`flap_min_transitions` is floored at 2 where it is read: the editor's
field will not produce less, but `PUT /api/alerts/rules/:id` accepts any
integer, and 1 would open an alert on every single link event.

The coupling worth knowing about: `_tick()` fetches the events to judge
with `nodes_db.recent_interface_events_for()`, whose defaults are
`since_s=900, limit=50`. A configured window longer than 15 minutes would
therefore have silently seen nothing, so the engine passes
`since_s=max(flap_window, 900.0)` and
`limit=max(flap_min * 10, 50)` — the fetch window can never be narrower
than the window being evaluated.

### Object column resolution (`alertengine.py`)

Each drain that produces a device- or IP-backed `Occurrence`
(`_drain_device_events`, both `_drain_interface_events` label sites,
`_drain_syslog`, `_drain_ipam_conflicts`, `_evaluate_thresholds`) builds
its `entity_label` through `namelookup.resolve_name()` (see Syslog's
"Host cross-referencing," below) rather than the `device["name"] or
device["ip"]` every one of them used independently before — falling
back to the bare IP as the final resort, since the Object column should
always show *something*. `_drain_syslog` follows the same "don't
override a real self-reported host" rule Syslog's own Host column uses,
so an alert opened from a syslog line matches whatever the Syslog page
itself would show for that exact message rather than falling back to a
raw, unresolved IP the way it used to (that drain reads `syslog_db`
rows directly, bypassing `get_syslog_search`'s resolution entirely, so
this had silently drifted out of sync with the page it was reporting
on). `trap` occurrences are deliberately left alone — `entity_label`
there is the trap's *name/OID* (what kind of trap), not a device label,
and resolving it to a hostname would erase that information for no
benefit. Because `alerts.entity_label` is stored on the row and only
refreshed on each repeat occurrence (`open_or_increment`, above), a
resolved-name improvement like this reaches already-open/recurring
alerts automatically on their next occurrence — no backfill needed —
but a one-shot alert that never repeats keeps whatever label it opened
with.

### Notifications (`alertmail.py`, `alertengine.py`)

`{{token}}` substitution (`_TOKEN = re.compile(r"\{\{(\w+)\}\}")`) is
hand-rolled, not Jinja2 or any templating library, matching the
stdlib-only rule the rest of this app follows for BER/ASN.1 and MIB
parsing alike. `build_context()` returns every token every template kind
might use as one superset dict; an unknown token renders as an empty
string rather than leaving a literal `{{token}}` in a sent email, a
last-resort safety net since the template editor's own token palette is
meant to prevent that ever mattering in practice.

`_notify()` computes `{{device_ip}}` by looking up the device fresh at
send time (`_device_ip_for()`, parsing `alerts.entity_id` back into a
device id) rather than trusting anything carried on the `Occurrence` —
`entity_id` is the device's *stable database id*, kept constant across
an IP change specifically so the dedup key does not orphan itself, which
means it is never the address itself; an early version passed
`occurrence.device_ip` straight into the template context, which worked
for a live device-down/up occurrence but produced `{{device_ip}}` →
the device's numeric id for the synthesized "clear" notification below,
since that occurrence has no live poll behind it to carry a real address.

`down_since`, `recovered_time` and `downtime` are derived inside
`build_context()` from the alert row itself whenever `resolved_ts` is set,
rather than only where the engine happens to know them. A recovery sends **two**
notifications — the "Device recovered" alert in its own right, and the
resolution of the outage it cleared — and both render the same `device_up`
template; the resolution one is built from a synthesized occurrence with no
extras, so tokens threaded through the occurrence alone would render empty on
exactly the email that is about the outage. `extra` still updates the context
last, so the drain's own values win where it has better ones: the `up` event's
timestamp is the moment the device answered, while `resolved_ts` is whenever
the next tick got round to noticing. The same derivation gives interface,
wireless and threshold clears a real duration, which none of them had.

Until 4.32.0 the shipped `device_up` body said "as of `{{last_time}}`", which
on a resolution is `alerts.last_ts` — when the *outage* last recurred, a moment
before it cleared. Correcting a shipped template needs a migration, since
`_seed_templates` inserts `OR IGNORE` and would leave every existing install on
the old text forever: `_migrate_templates()` always refreshes
`builtin_subject`/`builtin_body` (so "Reset to built-in" offers this release's
wording) and rewrites the live `subject`/`body` only where they still match,
character for character, `_PREVIOUS_BUILTIN_TEMPLATES` — anything else is an
operator's edit and is left alone. It runs before `_seed_templates`, so a fresh
database matches nothing and is simply seeded.

A resolution email (`_notify_clear()`, kind `"clear"` — the
`notifications.kind` enum value the schema already reserved for this)
fires when the CLEARS map (or a threshold dropping back below its clear
value) auto-resolves an alert, gated by the `notify_on_clear` setting.
It deliberately renders the generic `device_up` template rather than the
*cleared* alert's own rule template: the cleared rule's own wording
describes the original problem ("X stopped responding"), which would
read backwards on an email announcing that the problem is over.
`device_up` doubles as that generic "recovered" template for
`interface_up` and every threshold clear too, the same reasoning that
justified shipping only 5 built-in templates instead of one per rule.

`smtp_to_default` is a JSON array now (an add/remove list in the
settings UI, `alerts.js`), not the comma-separated string it used to be
— a change in what one settings value's JSON blob holds, not a schema
change, since `alertsdb.py`'s settings table stores each value as
`json.dumps(value)` under its key with no column type to migrate.
`_notify()` still accepts either shape on read (`isinstance(raw, str)`
→ split on commas, else treat it as already a list) purely so a
deployment upgrading mid-flight doesn't lose its configured recipients
on the first tick after the upgrade, before anyone has re-opened Alerts
settings and hit Save; the frontend does the same normalization
(`normalizeRecipients()`) when it loads whatever's currently stored, so
either representation renders correctly as a list either way.

Rate limiting (`max_emails_per_hour`) prunes a rolling
`self._sent_this_hour` list to the trailing 60 minutes and logs the
suppression exactly once per hour crossed, not once per suppressed
alert — alerts continue to open/increment/resolve and appear in the UI
regardless of whether email is enabled or currently rate-limited;
"evaluate rules" and "send email" are deliberately independent so a
misconfigured or over-quota mail server never blinds the Alerts page
itself.

### Reports (`report.py`, `web/api.py`) — 4.49.0

Sits above `nodesdb.py`/`alertsdb.py` rather than inside either — it reads
`device_status_segments` and `samples_hourly` (both already public methods)
and reaches into their SQLite connections directly only for the handful of
aggregate queries neither module exposes, rather than adding methods to
files other agents were editing the same hour.

**Availability is built on `device_status_segments`, never on
`devices.status`/`last_up_ts`/`last_down_ts`**, because the device row only
ever holds the *current* status and when it last changed — there is no
column holding "how long was it down last Tuesday", only the sequence of
`device_events` rows that method already turns into ordered,
non-overlapping segments over an arbitrary window. Four ways a gap in that
history is deliberately *not* counted as downtime, each handled rather than
assumed: the window is clipped to `[max(t0, created_ts), t1]` for a device
that did not exist yet, with how much was cut off reported rather than
silently shrunk; a maintenance window's occurrences (including a weekly
recurrence spanning the report window, generalising `is_window_active`'s
own arithmetic to "any past span" rather than only "right now") are
excluded for their full retroactive span; an *active* mute's own
`created_ts`/`until_ts` is excluded the same way, with the caveat that
`alertsdb.purge_expired_mutes` deletes a lapsed mute's row, so one that
already expired and was purged is invisible here and its downtime, if any,
reads as ordinary down time; and a segment longer than `GAP_FLAG_S` (3
hours) — which can only ever carry the *last known* status forward through
silence, never invent a down segment nothing recorded — is flagged in the
device's own `caveats` with its span, since a stopped poller and a boring
month look identical to this method and only a human cross-checking
`RUNBOOK.md` can tell them apart.

**`top_metric_ranking` reads `samples_hourly`, never raw `samples`** — three
days of raw samples is not a month at fleet scale — as one CTE-based query
rather than resolving candidate metric ids in Python first and passing them
back as an `IN (...)` list, which at 2,000 devices × 48 ports already blows
past SQLite's own bound-parameter ceiling for one interface-metric family.
The join from the small `candidates` CTE to the huge `samples_hourly` is a
`CROSS JOIN` deliberately, not a plain `JOIN`: a plain join leaves SQLite
free to reorder the two tables, and against a realistic fleet-sized
`samples_hourly` (several metric families mixed together, not just the one
queried) it chooses to start from the hour index and filter every row in
range by a per-row lookup into `candidates` — scanning every *other*
family's rows too. `CROSS JOIN` disables that reordering, forcing the small
table to drive the loop. Measured, 2,000 devices × 48 ports × one
interface-metric family (96,000 series) against a 97M-row `samples_hourly`
built from six metric families, one week of hourly rows: the plain-join
plan took 45.8s; the `CROSS JOIN` plan, 14.2s, and — unlike the plain-join
plan, whose cost scales with the *whole* table — stayed flat whether the
decoy families were present or not. A month projects to roughly 60-100s at
this scale, still too slow for an interactive request; the API route
(`get_nodes_reports_top_metrics`) refuses a whole-fleet-equivalent request
over `REPORT_TOP_METRICS_WHOLE_FLEET_MAX_WINDOW_S` (7 days) outright,
scaled by how many devices the request actually resolves to (so a caller
who happens to enumerate every device explicitly cannot walk around the
same check omitting `device_ids` would trigger) rather than serve it slowly
on a request thread. `device_availability_report` has no equivalent
documented cost at fleet scale and so carries no cap of its own yet — a
real number should replace that gap if a fleet-wide availability report
turns out to be slow too, not a guess.

Both routes are thin dispatch over `report.py`'s own functions: query-string
parsing, resolving an omitted `device_ids` to the whole fleet, and, for
top-N, the refusal above. Neither has a page in the interface reading it
yet.

---

## NetPath

### Running a trace

`tracer.py`'s `run_trace()` resolves the destination with
`socket.gethostbyname()` first — a name that won't resolve fails
immediately without ever shelling out — then builds a platform command
(`_build_command()`): `traceroute -n -q <probes> -m <max_hops> -w
<timeout>` on Linux/macOS, `tracert -d -h <max_hops> -w <timeout_ms>` on
Windows (which always sends 3 probes per hop; there's no equivalent flag).
Run via `subprocess.run` with a timeout equal to `expected_budget() =
max_hops * probes * timeout_s + 15` — the same formula `Monitor` uses to
detect an overrun, so the two can never disagree about what "too long"
means. From 4.49.0 that figure is capped at `MAX_EXPECTED_BUDGET_S` (600 s):
`max_hops`, `probes` and `timeout_s` all feed straight into this arithmetic
as well as into the traceroute/tracert command line itself, and until this
release none of the three (nor `interval_s`, nor the settings-level
`trace_workers`) was checked for being anything past *a number* —
`coerce_settings` (`sqlitebase.py`) only ever confirms the type.
`db.py`'s `_clamp_target_fields()` now bounds all five on `add_target`/
`update_target`/`save_settings` (`interval_s` 5 s–30 days, `max_hops`
1–255 — one byte on the wire, so no path is ever longer regardless of what
a target claims, `probes` 1–20, `timeout_s` 0.1–30 s, `trace_workers`
1–64), each a mechanism-driven ceiling rather than a round number:
`max_hops`/`probes`/`timeout_s` bound both the subprocess argument and this
budget arithmetic; `interval_s` bounds `monitor.py`'s own `next_run =
last_run + interval_s` — at or below zero a target is perpetually due, and
the scheduler launches a fresh subprocess against it as fast as the worker
pool turns them over, the exact spawn-storm shape `ipam_scan.py`'s own
docstring already names for an unpaced ping sweep; `trace_workers` bounds
the size `ThreadPoolExecutor(max_workers=...)` is built with in
`service.py`. `warn_rtt_ms`/`warn_loss` are clamped too, but only to what
is sane (non-negative; a percentage), since neither reaches a subprocess, a
loop bound or an allocation — only `classify()`'s comparison.

Output parsing is two separate functions, `_parse_unix()` and
`_parse_windows()`, because the shapes differ enough that a shared parser
would be messier than two simple ones. Both build a list of `Hop` objects,
each holding a `dict[str, list[float]]` mapping every address seen at
that TTL to its RTT samples — the dict, not a single address, is what
makes a forked path visible: two keys in one hop means two different
routers answered probes at that hop. `_parse_unix()` walks tokens
looking for `*` (loss), a float followed by `ms` (an RTT sample attached
to whichever address token came most recently), or an ICMP annotation
token starting with `!` (attached to the current address in
`hop.annotations`). `_parse_windows()` first collects the RTT columns
(`<1 ms` becomes `0.5`), then looks for a bracketed IPv6 address or the
first IP-shaped token in the tail, and separately checks the tail against
`WINDOWS_UNREACHABLE`, a dict of English phrases (`"destination host
unreachable"` etc.) mapped to the same `!H`/`!X`/... codes Unix
`traceroute` prints directly — `tracert` has no ICMP annotation syntax of
its own, so this normalizes it to look the same as `!H`.

**Refusal detection**: `TraceResult.unreachable` walks hops in reverse and
returns the first `(code, address)` found in any hop's `annotations`.
`dest_rtt()` prefers the destination hop's own average RTT; if the
destination never answered but a router refused, it falls back to that
router's RTT at whatever earlier hop it answered — `rtt_is_to_refuser`
flags this case so the UI can say "measured to X, not the target." If
`tracert` prints the refusal on its own line after the numbered hops
(one of the two shapes it uses), `run_trace()` attributes it to the last
router that actually answered, since there's no hop number to key off.

**Classification** (`monitor.py`'s `classify()`): only the destination
hop's own answer decides `ok`/`warn`/`fail`/`blocked`/`error` — an
intermediate router's 100% loss is not itself a fault, since routers
routinely rate-limit or ignore ICMP. `blocked` (a refusal) and `fail`
(silence) are kept as separate statuses deliberately, not shades of the
same "bad": a `!X` names the responsible router and usually points at an
ACL, where silence tells you nothing about where the problem is.

### Storage and the scheduler

`db.py`'s `traces` table stores one row per run with `path_sig`
(`TraceResult.path_signature()`, a SHA-1 of the primary address at each
TTL, truncated to 16 hex characters — used to detect a route change
without storing the whole path twice) and `icmp_code`/`icmp_from` for a
refusal. `hops` stores one row per (trace, TTL, address) — again, more
than one row at the same TTL for the same trace is exactly how a
within-run fork gets recorded.

`Monitor` (`monitor.py`) runs a 1-second-granularity loop
(`_loop()`) that computes each enabled target's next-due time from its
`interval_s` and the last stored trace, and submits due targets to a
`ThreadPoolExecutor` sized by the `trace_workers` setting
(`set_workers()` swaps in a new pool live; already-running traces finish
on the old one). If a target is still in flight when its next slot comes
due, `_record_overrun()` writes a synthetic `overrun` trace row rather
than silently skipping the slot — the timeline needs to distinguish "the
app wasn't running" (a true gap) from "this destination's traces are
backing up" (an overrun), and only the latter has a fix that involves
touching that destination's settings rather than the app itself.

### Continuous per-hop probing (`HopProber`, in `monitor.py`)

A scheduled trace samples a path once per `interval_s`; `HopProber` fills
the gaps for targets that opt in (`targets.hop_probe_enabled`, off by
default), with a background thread pool (`_loop()`, 4s cadence by default)
that sends one `tracer.ping()` — a single ICMP echo via the system `ping`
binary, the same subprocess-based, no-raw-sockets design as `run_trace()` —
to every IP currently known as a hop of an enabled target.

It never discovers hops on its own. `Monitor._run_one()` calls
`Service._on_trace_complete()` after every finished trace (wired through
`Monitor`'s existing `on_complete` callback slot), which calls
`HopProber.refresh_hops(target_id)`: this reads the just-completed trace's
hop IPs via `db.hop_rows_for_trace(db.last_trace(target_id)["id"])` and
diffs them against what was probed last time. A changed hop set — a route
change — triggers `db.reset_hop_stats(target_id, keep_ips=current)`, which
deletes rows for any IP no longer on the path; this is why continuous
probing never shows a hop's numbers gradually drifting after a route
change, they reset cleanly instead.

Storage is `db.py`'s `hop_stats` table, one row per `(target_id, ip)` with
running counters (`probes`, `lost`, `rtt_sum`, `rtt_min`, `rtt_max`,
`updated_ts`) rather than one row per probe — `record_hop_probe()` reads
the existing row, folds in the new `PingResult`, and writes it back via
`INSERT ... ON CONFLICT DO UPDATE`. A target probed every few seconds for
weeks still costs one row per hop, not thousands. `_topology_json()` in
`api.py` joins this table's data into each node's response
(`probe_count`, `probe_loss`, `probe_rtt_min/avg/max`) alongside whatever
`build_topology()` derived from the traceroute history itself — the two
are independent measurements of the same path, shown side by side in the
hop tooltip in `netpath.js` rather than merged into one number.

### ASN and owner lookup (`AsnResolver`, in `monitor.py` + `namelookup.py`)

Structured exactly like `Resolver` — its own polling loop, its own thread
pool, its own cache table (`asn_cache` in `appdb.py`, mirroring
`hostnames` but with a much longer default TTL: 30 days versus 7, since an
address's ASN/owner changes far less often than its PTR record) — but
targeting `db.distinct_hop_ips()` filtered through
`AppDatabase.unknown_asn_ips()` instead of `unknown_ips()`. It does no
independent hop discovery: every address `Resolver` already names a
hostname for is automatically a candidate here too.

The lookup itself (`namelookup.asn_lookup()`) uses Team Cymru's DNS-based
whois, which answers ordinary recursive DNS queries against two public
zones rather than requiring contact with Cymru's own servers directly:
`d.c.b.a.origin.asn.cymru.com` (reversed IP) returns a TXT record whose
first field is the originating ASN (`"15169 | 8.8.8.0/24 | US | arin |
..."`), and a second query against `AS<asn>.asn.cymru.com` returns the
short organization name (`"...| GOOGLE, US"`). Both queries go through
`namelookup.query_txt()`, a hand-rolled raw-UDP TXT query added alongside
the existing `query_ptr()` — same packet encode/decode helpers
(`_encode()`, `_read_name()`), same one-shot-socket-per-query shape, just
a different record type (`TXT = 16`) and multi-string TXT rdata
reassembly. There's no portable way to discover the system's configured
DNS resolver via raw sockets (unlike `Resolver`, which gets that for free
from `socket.gethostbyaddr()` for its primary PTR attempt), so `asn_lookup`
takes an explicit `server` (the `asn_server` setting, a separate value
from `dns_server` since an internal-only resolver used for PTR lookups may
not do public-internet recursion) and falls back to a public resolver
(`8.8.8.8`) when none is configured.

**Privacy guardrail**: `asn_lookup()` gates on
`ipaddress.ip_address(ip).is_global` before opening any socket — not
`is_private` alone, which would miss loopback, link-local and CGNAT
(`100.64.0.0/10`) addresses that `is_global` correctly excludes in one
check (verified directly: `is_global` is `False` for `10.x`, `192.168.x`,
`127.0.0.1`, `169.254.x` and `100.64.x` alike, `True` only for real
public addresses). A non-global address returns `(None, None)`
immediately, with no DNS packet ever sent — confirmed by timing (~70µs,
no network round trip) against a private test address. Since the vast
majority of any traced path's early hops are internal addresses, this
guardrail is not an edge case; it fires on nearly every trace, on nearly
every hop before the path leaves the local network.

### Reverse DNS (`Resolver`, in `monitor.py`)

A separate polling loop (`_loop()`, every `poll_s` seconds) asks
`AppDatabase.unknown_ips()` for up to 40 addresses without a fresh cache
entry, drawn from `Database.distinct_hop_ips()` plus whatever
`extra_ips()` callback was supplied — `Service._extra_resolve_targets()`
wires this to flow endpoints, syslog sources and IPAM hosts, gated by
each module's own `resolve_*` setting, which is why the resolver's own
docstring says "NetFlow and Syslog read the same names": there is
exactly one cache (`AppDatabase.hostnames`), and every module that wants
a name reads and writes through it.

Each address is resolved on a worker thread (`_resolve()`) via
`namelookup.reverse()`, three attempts in order: `socket.gethostbyaddr()`
(goes through the OS resolver stack, including its negative cache and
NetBIOS fallback on Windows), then a raw PTR query built and parsed by
hand (`query_ptr()` — encodes the question, sends one UDP packet, decodes
compressed name pointers per RFC 1035) straight to a nominated server if
`dns_server` is set, then `nslookup` as a subprocess if none of the above
found anything — kept specifically because it's the tool people check
with by hand, so whatever it finds, this finds too. As of the IPAM
integration, a fourth fallback runs if all three come back empty:
`IpamDatabase.dhcp_lease_for_ip()` is checked, and if a DHCP lease names
a hostname for that address, that becomes the cached name (tagged `"dhcp"`
in the Debug log's `how` field) — a device that never gets a DNS entry
but did ask a DHCP server for an address is nameable this way when it
would otherwise never be. Either way, `AppDatabase.set_hostname(ip,
name)` writes the result — `name=None` is cached too, meaning "looked up,
nothing found," distinct from no row at all ("never looked up"), so the
next resolver pass doesn't retry a genuinely nameless address until the
TTL (`dns_cache_days`, default 7) expires.

### Per-destination timeline windows (`netpath.js`)

`view.t0/t1/follow` are page-global, so switching destination used to
carry whatever window was on screen onto the next one. `view.windows`
keys `{t0, t1, follow, range}` by target id, persisted to `localStorage`
under `sappiwhere.netpath.windows` with the same try/catch every other
`localStorage` write in `app.js` uses (a private window or a full quota
must not break the page).

`view.windowFor` records which destination the window on screen belongs
to; `refresh()` compares it to `view.targetId` and calls `applyWindow()`
when they diverge, so restoring happens in exactly one place regardless
of how the selection changed — the target list, the NetFlow "view route"
jump through `activate()`, or the first load picking `targets[0]`. Every
`setWindow()` and the Follow checkbox call `rememberWindow()`.

A *following* window is stored as bounds but restored as a span anchored
to now — restoring a day-old `t1` verbatim would silently unfollow it. A
destination with no entry starts on the page's own default (`Last hour`)
rather than inheriting the previous destination's range, which is the
behaviour being fixed. `pruneWindows()` drops entries for destinations
that no longer exist on every `refresh()`, so the key cannot grow
forever.

### Topology and timeline (`analysis.py`)

`build_topology()` takes raw hop rows and a candidate destination IP.
It groups hops per trace by TTL first (`per_trace[trace_id][ttl] =
{addresses}`), then derives three things from that grouping: `node_counts`
(how many traces saw each `(ttl, ip)` pair — this is what sizes the box
and, summed, becomes each edge's thickness), `edge_counts` (every
`(ttl, ip) -> (ttl+1, ip)` pair actually observed consecutively within a
single trace), and a path *signature* per trace (the sorted-first address
at each TTL) counted in a `Counter` to get `distinct_paths`. A `PathNode`
carries `hostname_known` separately from `hostname`, so the UI can print
`resolving…` for "not looked up yet" and `no PTR record` for "looked up,
found nothing" — collapsing those into a single `None` would make them
indistinguishable.

**Hop aging** (`stale_after_s` / `window_end`) drops a `(ttl, ip)` pair
that stopped appearing. `hops` has no timestamp of its own, but
`db.hop_rows_between()` already selects `t.started_ts` on every row, so
`PathNode.last_seen`/`PathEdge.last_seen` are derived from the trace join
with no schema change. The cutoff is `window_end - stale_after_s`, where
`window_end` is the `t1` of the window the rows came from — **not**
wall-clock now. That distinction is the whole point: aging against the
clock would empty the graph the moment anyone panned the timeline back
past the cutoff, which is exactly when the old path is what they want to
see. An edge is dropped whenever either endpoint was, so no edge is ever
left pointing at a hop that is no longer drawn. `api.get_topology` passes
`topology_stale_hours` (NetPath settings, default 24, 0 disables) only on
the windowed branch; the pinned-snapshot branch deliberately never ages,
since one trace is one instant and every hop in it was seen at it.

**Silent-hop collapsing** (`Topology.silent_runs()`) walks TTLs in order
and finds maximal runs where every TTL in the run has exactly one node,
and that node's `ip is None` (nothing replied at that TTL in any trace) —
a run of two or more collapses to one marker in the UI. This is a display
concern only; hop numbers in the underlying data are untouched, which is
why expanding a collapsed run never renumbers what follows it.

`build_timeline()` buckets traces into fixed-width slices anchored to the
Unix epoch (`math.floor(t0 / bucket_s) * bucket_s`), not to the window's
left edge — this is what makes a block mean the same wall-clock interval
whether the window pans or zooms. Each bucket tracks the worst status
seen (`analysis.worst()`, using a fixed severity order where `blocked`
outranks `fail` and `overrun` outranks both — a measurement fault is
worse than a network fault because there's genuinely no data for that
slot) and separately tracks average RTT and average/max loss. `path_
changed` is set when a bucket's last-seen `path_sig` differs from the
previous bucket's, which drives the small tick marks above the RTT lane.

---

## NetFlow

### Wire decoding (`nfdecode.py`)

`Decoder.decode()` reads the first two bytes as the version and dispatches
to `_decode_v5()`, `_decode_v9()` or `_decode_ipfix()`. v5 is a fixed
24-byte header plus 48-byte records — `struct.unpack_from("!HHIIIIBBH",
...)` for the header, straight into `Flow` objects, no state needed
beyond a per-exporter sampling rate parsed out of the header's low 14
bits (`sampling_raw & 0x3FFF`).

v9 and IPFIX are template-driven and share almost all of their decoding
logic despite different header layouts: both walk a sequence of *sets*
(`set_id`, `set_len`, then `set_len - 4` bytes of body), where
`set_id == 0` (v9) or `2` (IPFIX) is a template definition, `1`/`3` is an
*options* template (carries metadata like the sampling interval rather
than flow records), and anything `>= 256` is data keyed to a
previously-seen template id. Templates are cached in `self.templates`
keyed by `(exporter, domain, template_id)` — the id alone isn't unique,
because an exporter that reboots (or accepts flows from more than one
observation domain) can reuse an id for a different field layout, and
keying by exporter+domain as well keeps those apart. A data set whose
template hasn't arrived yet increments `stats["no_template"]` and is
silently skipped rather than erroring — the exporter will resend the
template within a minute or two, and every record before that is
genuinely undecodable, not a bug.

Fields with `size == 0xFFFF` in their template are IPFIX variable-length
fields; `_read_variable()` reads a length-prefix byte (or, if that byte
is `255`, a following 2-byte length) before each such field rather than
trusting the template's own fixed size. `_build_flow()` reads timestamps
in a fallback order (milliseconds since epoch, then seconds since epoch,
then the older `sysUpTime`-relative `FIRST_SWITCHED`/`LAST_SWITCHED`
fields converted using the header's boot time) and clamps anything more
than 30 days old or an hour in the future to "now" — one exporter with a
wrong clock would otherwise stretch every chart's time axis to fit it.

### Collector threading (`collector.py`)

`Collector` subclasses `udpsock.UdpReceiver` (bind, the receive-thread
guard, the kernel-drop poll, throttled error logging, the LRU of seen
exporters, `status_text()`) and adds what is specific to NetFlow: two
threads, deliberately. `_receive()` does nothing but
`sock.recvfrom()`, a version/allow-list check, and `decoder.decode()`,
then hands the resulting flows to a bounded `queue.Queue`; `_write()`
drains that queue and calls `db.insert_flows()` in batches (every 1
second or 500 flows, whichever comes first). Committing to SQLite on the
receive thread would leave the socket unserviced for however long the
commit takes, and NetFlow is UDP — a packet that arrives during that
window is gone, not retried. `queue.Full` counts as `dropped` rather than
blocking, for the same reason.

On Windows, the socket binds with `SO_EXCLUSIVEADDRUSE` instead of
`SO_REUSEADDR`: Windows allows two processes to share a UDP port under
`SO_REUSEADDR` and delivers each datagram to only one of them, so a
leftover instance would silently swallow every packet while the visible
one looks healthy. Exclusive binding turns that into an immediate,
visible "port already in use" at startup instead.

### Storage and views (`flowdb.py`)

`flows` is one row per decoded record; `exporters` is touched once per
batch-flush per exporter (`touch_exporter()`) with its most recent
version, packet/flow counts and sampling rate, for the status strip.
Aggregation for the traffic chart and top-N bars groups by whatever
`Group by` dimension the frontend asked for (`DIMENSIONS` in `flowdb.py`
— application, protocol, source, destination, conversation, exporter,
interface, AS, ToS) and multiplies every byte/packet figure by the
flow's stored `sampling` rate before returning it, since that's the only
point downstream of decode where the true (unsampled) volume can still be
reconstructed.

**One scan per refresh** (`overview()`): the page used to cost four full
aggregate passes over the window — `series()` called `top()` internally,
`get_flow_overview` called `top()` again beside it, and `totals()` made a
third — each walking the same rows. Widening the window multiplies the
rows every one of them reads, which is why zooming out felt like the app
had hung. `overview()` does the single `GROUP BY key, slot` pass those
three shared and derives all of it from the result: summed per key it is
`top`, summed overall it is `totals`, and bucketed it is the stacked
series. Ties are broken by name rather than left to SQL's arbitrary
`ORDER BY` order, so two equal-volume keys keep the same position — and
therefore the same colour — between refreshes. `series()`, `top()` and
`totals()` remain for their other callers.

The record list's `ORDER BY bytes * sampling DESC` over the whole window
is the remaining unindexed cost, left alone deliberately: changing it
would change what "top 250 by volume" means.

### Zoom debounce and the stale-response guard (`netflow.js`)

The `overview()` rework above halves nothing on its own if the page fires
a fetch per wheel event, which it did: `setWindow()` called
`App.refreshNow('netflow')` synchronously, so spinning the wheel out six
steps queued six overview+records pairs over ever-wider windows — faster
than the server could answer them. `setWindow()` now takes a `defer`
flag, set only from `svg.onwheel`: the window itself still moves on every
event and `showWindow()` repaints the label, so the gesture stays live,
but the fetch waits ~250 ms and any further step restarts that timer. A
direct change (the range dropdown, the zoom/pan buttons, a drag) is still
immediate — deferring those would only feel laggy.

Separately, `refresh()` stamps each run with `view.request` and drops its
response if the counter moved while it was in flight, the same guard
`nodes.js`'s `loadStatusTimeline` uses. Without it a slow wide-window
answer repaints over the newer narrow one the operator has already zoomed
back to.

### Flow-to-path correlation

NetPath only keeps trace history for pre-configured `targets` — there is
no reverse index from an arbitrary IP to a target, and a target's `host`
field can be a hostname whose current resolution has drifted from what it
was when last traced. So matching a flow's destination IP against NetPath
data means answering "which target's *most recent successful trace*
actually ended at this exact IP" rather than a literal string match — the
same question `db.destination_ip(target_id)` already answers in the other
direction (given a target, what did it last reach). `db.py`'s
`target_by_destination_ip(ip)` and its bulk form
`targets_by_destination_ips(ips)` answer it: for each target, compute its
`destination_ip()` (already indexed via `ix_hops_ip`, since it reads the
final hop of the most recent `reached=1` trace) and check whether that
equals the address being asked about — a scan over targets (typically a
handful to a few dozen), each an indexed lookup, rather than one raw SQL
join trying to encode "final hop of the most recent trace" as a single
query, which would risk matching an *intermediate* hop shared by several
targets' paths instead of the actual destination.

`api.get_flow_records()` calls `targets_by_destination_ips()` once per
request, over every distinct source and destination IP already present in
that page's flow rows, and stamps `src_target_id`/`dst_target_id` onto
each record. This means the frontend's "→ Route" button's enabled/disabled
state is known the instant the table renders — no per-row round trip when
a user clicks it, and no dead click. `netflow.js`'s `drawTable()` renders
an active `button.linkish` when `dst_target_id` is set, or a greyed `—`
with an explanatory tooltip when it isn't.

The cross-tab jump itself has no dedicated backend endpoint — it is pure
frontend state hand-off. `netpath.js` exports `activate(opts)` on
`App.pages.netpath` (alongside the existing `init`/`refresh`); calling it
with `{targetId, t0, t1}` sets `view.targetId`, clears pinned/expanded/
zoom state left over from whatever was previously showing, and calls the
existing `setWindow(t0, t1, false)` to move the time window and trigger a
refresh. `App.selectTab(name)` (`app.js`) already calls `page.activate()`
with no arguments on every ordinary tab switch — a pre-existing hook that
happened to have no implementation on the NetPath page before this
feature — so the click handler in `netflow.js` calls `activate()` with
the real options *before* `App.selectTab('netpath')`: the first refresh
triggered inside `activate()` no-ops (`refresh()` returns immediately when
`App.state.tab !== 'netpath'`), and `selectTab`'s own subsequent
`refreshNow('netpath')` does the actual fetch, now against the
already-updated target/window state. The window itself pads ±5 minutes
around the flow's own timestamp — a single flow record is a point in
time, but the route graph needs a span to draw traces from.

---

## SNMP Trap

### Decoding (`trapdecode.py`)

`Reader` walks a byte range and returns `(tag, value_start, value_end)`
TLVs as absolute offsets into the original datagram rather than slices —
required for SNMPv3 authentication, which has to hash the original buffer
with `msgAuthenticationParameters` zero-filled *in place*, byte-identical
to what the sender signed. `Decoder.decode()` follows `nfdecode.Decoder`'s
shape exactly: one `try/except` around the whole body, a `.stats` counter
dict, never raises past its own boundary, returns `None` on any failure.

v1's `Trap-PDU` (tag `0xA4`) and v2c/v3's `SNMPv2-Trap-PDU`/
`InformRequest-PDU` (tags `0xA7`/`0xA6`, structurally a `GetResponse-PDU`)
are different shapes read by different methods (`_read_trap_v1` /
`_read_trap_v2`); `_finish()` reconciles them onto one identity axis
afterward — `_read_trap_v1` maps a v1 trap's generic/specific numbers onto
the v2 `snmpTrapOID` space per RFC 3584 §3.1 so both versions are
searchable and filterable together.

v3 (`_decode_v3`) reads `msgFlags` to determine `auth`/`priv`, then always
decodes `msgSecurityParameters` (cleartext regardless of security level —
RFC 3414 §6). If `auth`, `_verify_v3()` looks up the user's
`(protocol, password)`, derives a localized key via `_localized_key()`
(RFC 3414 A.2.1/A.2.2: hash exactly 1 MiB of the repeated password, then
`hash(key || engineID || key)`; cached per `(protocol, password, engine)`
since the 1 MiB hash costs real milliseconds), zero-fills a `bytearray`
copy of the datagram at the authentication parameter's recorded offsets,
and compares an HMAC computed over that copy against what was sent, via
`hmac.compare_digest`. If `priv`, the `ScopedPDU` is encrypted and is not
parsed further — the standard library has no AES/DES implementation, and
this app takes no third-party dependencies — the trap is stored with
`auth_state="encrypted"` and everything the header carries in the clear;
`AUTH_PROTOCOLS`'s comment block marks exactly where a future
`trapcrypto.py` would plug in (`decrypt(protocol, key, priv_params,
engine_boots, engine_time, ciphertext) -> bytes | None`), so decryption
lands here without restructuring anything.

The OID name table at the bottom of `trapdecode.py` is just that — not a
MIB compiler; parsing SMIv1/SMIv2
ASN.1 modules is a substantial parser project of its own and out of scope
for a stdlib-only app. `Decoder.resolve_oid()` does exact-match first,
then walks the OID's arcs looking for the longest known *prefix* so an
unrecognized instance under a known table entry still resolves
(`ifDescr.7` for `1.3.6.1.2.1.2.2.1.2.7`). `Decoder.severity_for()` does
the same longest-prefix-wins search over `severity_rules`, which starts
from `trapdecode.DEFAULT_SEVERITY_RULES` and is re-sorted by `-len(prefix)`
whenever admin-supplied rules are appended in `configure()`, so a specific
rule always beats a vendor-wide one regardless of the order either list
was written in.

The encoder half (`build_v1_trap`, `build_v2c_trap`,
`build_inform_response`) is small and total, used by `post_snmp_test` and
by the inform-acknowledgement path. `build_inform_response()` splices the
acknowledged inform's own varbind-list bytes back verbatim — via
`Trap.varbinds_tlv_span`, the full TLV span (tag byte included) recorded
while parsing — rather than re-encoding the varbinds from their decoded
Python values, so nothing can be lost in a round trip through the decoder.

### Listener (`snmptrapd.py`)

Same `udpsock.UdpReceiver` base as NetFlow's and Syslog's collectors
(`NOUN = "Receiver"`), and the same rx/tx split, UDP only — SNMP has no TCP
transport in practice. `_accepted_source()` gates before decoding
(a rejected packet is never parsed, same as Syslog); `_accepted_community()`
necessarily runs after, since the community lives inside the packet.
`_enqueue()` filters on `trap.severity > min_severity` before the queue,
the same volume-control-at-the-door pattern Syslog uses.

`_acknowledge()` replies to a v1/v2c `InformRequest` on the same socket it
arrived on — still receive-only work, since it answers rather than
queries — using the recorded `varbinds_tlv_span` to splice the response
together without re-encoding. v3 informs are deliberately not
acknowledged: doing so correctly means acting as the authoritative SNMP
engine (answering discovery `Report`s, tracking `engineBoots`/
`engineTime`), which is USM's other half and belongs with a future poller.

### Storage (`snmptrapdb.py`)

`trap_counts` is a rollup table maintained incrementally as traps arrive,
the same shape as Syslog's `log_counts`, so the histogram costs at most a
few dozen rows to read regardless of how large `traps` has grown.

No FTS5, unlike Syslog. Syslog needs a trigram index because a busy
firewall can produce millions of lines a day; traps run two to four
orders of magnitude rarer, and the useful queries are on indexed columns
(`ts`, `severity`, `source`, `trap_oid`) — a `LIKE` over `varbind_text`,
already narrowed by the time window, reads a handful of rows. Varbinds are
one JSON column (`varbinds`), not a child table: a varbind list is read
exactly once, whole, by the detail panel for a selected row, never
joined, grouped or aggregated — a child table would add write
amplification on the hot insert path to buy an ability nothing asks for,
and free-text search over the varbinds is already served by the
denormalized `varbind_text` column.

---

## Syslog

### Parsing (`syslogparse.py`)

`parse()` never raises: it tries a `<PRI>` prefix (`_PRI`, sets facility
and severity from `value >> 3` / `value & 0x07`), then checks whether the
remaining text starts with an RFC 5424 version token (`"1 "`) and if so
splits it into `TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG` by
position — 5424's fields are fixed-order and space-separated up to the
message, which is why `split(" ", 5)` (not a full parse) is enough.
Otherwise it tries the RFC 3164 shape (`_RFC3164`: a three-letter month, a
day, `HH:MM:SS`, then the rest), reads an optional hostname token, then a
`_TAG` pattern (`app[pid]: message` or `app: message`). If neither shape
matches at all, the whole line becomes the message rather than being
dropped — most of what actually shows up on a syslog port is not
perfectly RFC-conformant, and a parse failure destroying the message
would be worse than an ungrouped one.

BSD timestamps carry no year (`_parse_3164_time()`); the year is inferred
from the current date, with a December-message-read-in-January (or the
reverse) case explicitly handled so a year boundary doesn't file a day of
logs twelve months off.

**`_strip_structured_data()` walks an RFC 5424 message's `[...]` SD-ELEMENT
run with an index now, not by reslicing — the DoS fix in 4.49.0.** RFC 5424
places no limit on how many SD-ELEMENTs a message carries; before this fix
the loop was `rest = rest[end:].lstrip()` each time round, which copies
everything left in the string on every element, costing O(elements²) for N
tiny ones on this unauthenticated port (514/udp+tcp): 240,000 elements
(~720 KB) measured at 2.34 s, 500,000 (~1.5 MB) did not finish in 8 s.
`_end_of_element()` now takes a `start` offset and the walk advances `pos`
through one string rather than creating a new one per element, so the whole
walk is linear in the message's length once no fresh slice is taken.
`MAX_SD_ELEMENTS` (64) bounds it further, independent of that fix: the
element *count* is capped directly, since real devices never send more than
a handful (a chained rsyslog relay is the heaviest ordinary case, at two or
three) and each element costs the same regardless of how small it is — so
capping length instead would either truncate a legitimately large single
element's value or need to be generous enough to let the pathological shape
run anyway. Past the cap, whatever is left — genuine elements the device
sent, or an attacker's padding — is kept verbatim as message text rather
than parsed further or dropped, so a real oversized message is still stored
in full, just with some of its structured data unlabelled.

### Listener (`syslogd.py`)

Same `udpsock.UdpReceiver` base and the same rx/tx split as NetFlow's
collector, and the same reasoning: a device misbehaving can produce
thousands of lines a second, so the receive path only reads, parses and
enqueues. `SyslogCollector` now inherits `UdpReceiver.running` — `bool(self.
_threads) and all(t.is_alive() for t in self._threads)` — rather than a
per-class copy; with a UDP thread, a TCP accept thread and a writer thread
all in play, a dead writer used to leave `running` true with nothing
actually being stored, and it now reports stopped the moment any one
thread has died, matching what the trap receiver's `running` already did.
TCP is handled by `_read_stream()`,
which reassembles a byte stream into messages under either framing in
use in the wild: RFC 6587 octet-counting (`"123 <13>..."` — a decimal
length, a space, then exactly that many bytes) is detected by checking
whether the text before the first space is all-digits and no longer than
10 characters; otherwise it falls back to newline-separated framing,
which is what most devices actually send regardless of what the RFC
says.

**`MAX_TCP_MESSAGE_BYTES` (1 MB) bounds both framings identically —
4.49.0.** The newline-framed path always had a cutoff for "no newline in
sight, and this has gone on too long"; the octet-counted path did not,
because its own length prefix reads up to ten digits — up to
9,999,999,999 — and nothing checked that number against anything before
buffering toward it. Measured directly before the fix: a connection that
declared a 2 GB octet count and trickled data toward it at 1 MB/s held the
collector's own traced memory at 42 MB after 50 MB sent (peaking at
82.5 MB, since `buffer += chunk` briefly holds the old and new buffer at
once), every counter — messages, errors, rejected, dropped — still at
zero, for as long as the connection stayed open, unauthenticated, on
514/tcp; `_max_tcp_clients` (default 64) bounds how many connections can
each do this at once, but nothing bounded any single one of them on its
own. The two framings now share one ceiling rather than the newline path
alone having one — no real syslog message, even one carrying a sizeable
RFC 5424 structured-data block, comes close to 1 MB.

Volume limiting happens in `_enqueue()`, before the queue: a message
whose severity number is numerically greater than `min_severity` (lower
severity number is more severe) is counted as `filtered` and dropped
before it ever reaches storage, and a message longer than
`max_message_chars` is truncated rather than rejected.

### Storage and search (`syslogdb.py`)

`log_counts` is a rollup table maintained incrementally as messages
arrive (one row per hour per severity), so the histogram costs 24 rows to
read rather than a scan of `logs` — it doesn't get slower as the database
grows.

Search prefers an FTS5 virtual table using the **trigram** tokenizer
(`content_rowid='id', tokenize='trigram'`) where the SQLite build has it
— every SQLite since roughly 2020 does — because a trigram index matches
a substring appearing anywhere in a field, not just at a word boundary,
which is what "search matches anywhere" in the UI actually means.
`SyslogDatabase._enable_fts()` checks for the capability at startup by
attempting the `CREATE VIRTUAL TABLE ... USING fts5(..., tokenize=
'trigram')` and catching `sqlite3.OperationalError`; if that fails —
no FTS5, or an SQLite too old for the trigram tokenizer (added in 3.34,
December 2020) — search falls back to a plain `LIKE '%needle%'` scan, and
queries under three characters always scan too, since there's nothing
for a three-character index to match below that length. An install
upgrading from an older index shape (`_index_is_current()` checks the
stored table SQL for `trigram` and `source`) gets the index dropped and
rebuilt once in the background, in chunks, without blocking search in the
meantime — it just scans until the backfill catches up.

### Host cross-referencing (`namelookup.py`, `api.py get_syslog_search`)

The `host` column stored in `logs` is exactly what `syslogparse.parse()`
found in the message — often empty, or just the sending device's own IP
repeated, since not every device bothers to self-report a real hostname.
Rather than rewrite that stored value, `get_syslog_search` fills the gap
at read time: for every row whose `host` is falsy or equal to its own
`source`, it calls `namelookup.resolve_name(nodes_db, app_db, ip)`. A
message that already carries its own real hostname is never touched;
this only ever fills what the device left blank.

`namelookup.resolve_name()` lives in the shared name-lookup module (not
folded into `nodesdb.py` or `appdb.py`, to avoid making either database
module depend on the other) used by both this and Alerts' `entity_label`
computation (`alertengine.py`, below). It replaced three previously
independent and disagreeing precedences that all existed at once before
this: `nodes.js`'s own device-list display (`sys_name || name || ip`),
this function's own earlier inline logic (`name` unless it equaled the
device's `ip`, else `sys_name` — the *opposite* order), and
`alertengine.py`'s (`name or ip`, no `sys_name` at all, no DNS at all).
`resolve_name()` now matches `nodes.js`'s own convention — `sys_name`
first, since it's what Nodes itself considers a device's canonical
display name — then a manually-set `name` that isn't just the bare IP,
then the DNS reverse-lookup cache, else `None`. Callers decide their own
last resort (Syslog's Host column leaves a true gap as `""`; Alerts
falls back to the bare IP, per its "always show something" requirement).

4.30.0 split the device half out as `device_name(device)` and fixed a real
omission in it: `display_name_source` was ignored, so a device explicitly
pinned to its manual name still displayed its sysName in Alerts, Syslog and
NetFlow — everywhere except the Nodes tab and ConfigRX, which each computed
the correct precedence themselves. One two-line fix in the shared helper
corrects all of its callers at once.

`fill_from_nodes(nodes_db, names, ips)` is the NetPath direction and runs the
precedence the *other* way round — DNS first, Nodes second — because it fills
gaps in a reverse-DNS result rather than deciding a display name from
scratch: a hop with a real PTR record keeps it, and only a hop the resolver
could not name falls back to the device this app monitors at that address. It
returns `{ip: "nodes"}` for what it filled, which `_topology_json` passes
through as `hostname_source` so the hop tooltip can say where the name came
from.

It is called in `get_path`/`get_topology` rather than in `monitor.Resolver`
for two reasons: `service.nodes_db` is already in hand at the API layer (the
resolver would need a new constructor argument), and a Nodes name written
into the *DNS* cache would be aged out on a DNS schedule
(`service.py` housekeeping) and go stale the moment the device is renamed.
Note the interaction with `analysis.PathNode.hostname_label`: it reports
`"resolving…"` when the IP is absent from the map entirely and
`"no PTR record"` when it is present but empty, so filling an entry is also
what makes the hop count as *looked up* — which is correct, and a hop that is
neither resolved nor managed still reads "resolving…".

This lookup is **not** gated by the `resolve_sources` setting the way
the Source column's separate `source_name` resolution still is — that
setting predates this fix and was found to be silently disabling the
entire Nodes/DNS lookup (including the Nodes half, not just DNS) on any
install where nobody had opened Syslog settings and turned it on, which
was the original report this fix addresses. Filling in what the Host
column already claims to mean isn't an opt-in display toggle the way
choosing between a raw address and a resolved name for the Source column
is.

---

## IPAM

### Sub-tab default (`index.html`, `ipam.js`)

Which of the three IPAM sub-tabs is active on first load is decided
purely by which button/panel pair carries the `active` CSS class in the
markup — `ipam.js`'s generic `selectSub()` (the same DOM-driven-default
convention Nodes' own sub-tabs use) is never called on init, only wired
to each button's `onclick`. Making DHCP the default was therefore a
markup change (moving `active` off `subnets`'s button/panel and onto
`dhcp`'s) plus updating `view.sub`'s initial value to match, not a
scheduling or state-loading change — sub-tabs aren't `localStorage`-
persisted the way the top-level module tabs are, so there was no stored
preference to account for either.

### Keeping the DHCP scope across servers (`ipam.js`)

`view.dhcpScopeId` is a `dhcp_scopes` **row id**, which differs per
server even for the same scope, so it cannot survive a server switch —
the old `onchange` nulled it and `loadDhcpScopes()` fell back to the
first scope. `view.dhcpScopeKey` carries the scope's own `scope_id`
string (`"10.20.3.0"`), which is what an operator means by "the same
scope", across the switch: after the new server's scopes load, a scope
whose `scope_id` matches is preferred, and only with no match does the
first-scope fallback apply. Whatever ends up selected — including that
fallback — is written back to `dhcpScopeKey`, so a later switch looks for
the scope actually on screen rather than a stale one. The same path runs
on a background refresh, so a poll cannot move the selection either.

### Leased-IP sparkline scale (`ipam.js drawScopeTrend`)

The Y-axis domain is computed from the window's own `min`/`max` leased
count (plus a small pad) rather than always running from `0` to the
data's max, unlike every other chart in this codebase (`nodes.js`,
`netflow.js` both deliberately anchor at `0`) — a deliberate, scoped
exception for this one sparkline, not a bug those charts should also be
fixed to match. It exists specifically because a scope oscillating in a
narrow band (say 40-45 leased out of a much larger scope) used to get
visually squashed into a few pixels at the very bottom of the chart when
the domain ran all the way down to zero; scaling to the data's own range
makes that same real movement fill most of the sparkline's height
instead. The area-fill polygon shares the same `y()` function as the
line, so it's now shaded between the line and the *local minimum*,
not true zero — a secondary, expected consequence of the non-zero floor
worth knowing if the fill ever looks like it's covering less than it
used to.

### Subnet sweep (`ipam_scan.py`)

`scan_subnet()` does exactly two things in order: `sweep()` pings every
address in the CIDR concurrently (a `ThreadPoolExecutor`, default 64
workers, one OS `ping` subprocess per address — `_ping_command()` builds
`ping -c 1 -W <timeout>` on Unix, `ping -n 1 -w <timeout_ms>` on
Windows), then `read_arp_table()` is called exactly **once**, after the
whole sweep, and its result is filtered to only addresses inside the
subnet's own `ipaddress.ip_network`:

```python
in_subnet = {ip: mac for ip, mac in arp.items()
            if ipaddress.ip_address(ip) in net}
```

This filter is the reason a discovered-host row can never have an
address outside its own subnet's CIDR — it is structurally impossible
for the sweep path to produce one. (An out-of-subnet result elsewhere in
IPAM search always comes from DHCP polling instead, which is entirely
independent of the subnets table — see below.)

Reading the ARP table once for the whole batch rather than once per
address is deliberate: a burst of ICMP populates the OS's own ARP cache
for whatever answers, and one `arp -a` / `ip neigh` command afterward is
one subprocess instead of hundreds. `read_arp_table()` picks the command
by platform (`arp -a` parsed by `_parse_windows_arp()`, `ip neigh` by
`_parse_linux_neigh()` — preferred over `arp -an` where `ip` exists, on
Linux — or `arp -an` by `_parse_bsd_arp()` on macOS/BSD), and
`mac_colon()` handles the three formats those commands actually
print: colon-separated, dash-separated with zero-padded octets
(Windows), and Cisco's unpadded dotted-quad-of-hex form — returning the
colon-separated form or `None`, the opposite convention from `nodesdb`'s
own `normalize_mac()` above, which is why the two were renamed apart
rather than left to be confused with each other.

### DHCP polling (`ipam_dhcp.py`)

One fixed PowerShell scriptblock (`_BODY`) does the actual query —
`Import-Module DhcpServer`, then `Get-DhcpServerv4Scope`,
`Get-DhcpServerv4Lease` and `Get-DhcpServerv4Reservation` per scope, plus
(since the subnet/router feature) `Get-DhcpServerv4OptionValue -OptionId
3` per scope for its router, wrapped in its own try/catch since not every
scope has one configured. Every cmdlet used is a `Get-`; nothing here can
write to a DHCP server. The same scriptblock runs two different ways
depending on whether a credential is configured:

- **Ambient identity** (username/password blank): `& $body $server` —
  invoked directly, in the *local* PowerShell process this application
  spawned. The `-ComputerName` parameter on each `Get-*` cmdlet is what
  reaches the remote server, over the DhcpServer module's own RPC
  endpoint. `Import-Module DhcpServer` therefore needs to succeed on
  **the machine running SappiWhere**, not the DHCP server — this is the
  detail that made an early support case (`Import-Module DhcpServer ...
  not loaded`) confusing until the ambient-vs-credentialed distinction
  was worked out: WinRM/CIM errors only apply to the credentialed path
  below.
- **A stored credential**: `Invoke-Command -ComputerName $server
  -Credential $cred -ScriptBlock $body -ArgumentList $server` — the
  scriptblock runs **on the DHCP server itself**, reached over WinRM.
  `Import-Module DhcpServer` here needs to succeed on the DHCP server,
  the opposite requirement from the ambient path. A stored credential is
  decrypted immediately before this one call
  (`ipam_worker.credential_for_server()`) and the plaintext reference is
  dropped (`finally: username = password = None`) right after, so its
  lifetime in the process is as short as the call that needs it.

The server address, and the username/password for the credentialed path,
travel as environment variables (`SAPPI_DHCP_SERVER`,
`SAPPI_DHCP_USERNAME`, `SAPPI_DHCP_PASSWORD`) rather than being woven
into the script text — the script itself is always one of two fixed
constants (`_SCRIPT` for a full poll, `_TEST_SCRIPT` for the cheap
reachability check), so there is no string for anything to inject into.

**Invocation** (`_run()`): the script is written to a temp `.ps1` file
with a UTF-8 byte-order mark and run with `-File`, not piped over stdin
with `-Command -` — the latter was the actual cause of an early bug
where PowerShell exited 0 having silently executed nothing at all, a
known rough edge of that invocation form with multi-statement scripts
containing scriptblocks and try/catch. The BOM matters because Windows
PowerShell 5.1 (unlike `pwsh`) infers a script file's encoding from its
byte-order mark and otherwise falls back to the system codepage. Output
is expected as one line of `ConvertTo-Json -Compress` on the last line of
stdout (anything printed earlier — a progress line, a warning — is
tolerated and ignored); the catch block on the PowerShell side prints
`{"error": ...}` and exits 1 on any failure, which `_run()` turns into a
`DhcpUnavailable` exception. `_friendly_error()` recognizes a handful of
error substrings from real field failures (`"TrustedHosts"`, `"CIM
server"`, `"DhcpServer" ... "not loaded"`) and appends the specific fix
for each, without hiding PowerShell's own message.

### Leased-IP history (`dhcp_scope_history`, in `ipamdb.py`)

`dhcp_scopes`/`dhcp_leases` are replaced wholesale on every poll
(`replace_dhcp_scopes()`/`replace_dhcp_leases()` in `ipamdb.py` —
`DELETE FROM ... WHERE server_id=?` then a bulk `INSERT`), so they hold
only the current snapshot and nothing about how it got there. The DHCP
page's trend chart needs the "how it got there" part, which is what
`dhcp_scope_history` is for: one row per scope per poll — `leased`,
`reserved`, `total`, `polled_ts` — that is *only ever inserted, never
replaced*, so a scope's history survives every subsequent poll that
overwrites `dhcp_scopes`/`dhcp_leases` out from under it.

`IpamWorker._poll()` (`ipam_worker.py`) calls
`_record_scope_history(server_id)` immediately after the two `replace_*`
calls land. Rather than trust field names on the raw PowerShell snapshot
(`snapshot.scopes`/`snapshot.leases`), it re-reads what was just
committed (`db.dhcp_scopes()`/`db.dhcp_leases()`) and counts leased vs.
reserved the same way `api.get_ipam_dhcp_scopes()` does — both now share
one `scope_size(start_ip, end_ip)` function in `ipamdb.py` (moved there
from a private duplicate in `web/api.py`) so a scope's "total" figure can
never quietly diverge between the live donut and the history chart.

`GET /api/ipam/dhcp/scope-history` (`api.get_ipam_dhcp_scope_history`)
takes `server_id`, `scope_id`, and a `t0`/`t1` window via the same
`_window()` helper NetPath's timeline endpoint uses, and returns every
history row in range — no bucketing, since even a 7-day window at the
default 15-minute poll interval is under 700 rows, trivial for an SVG
polyline. `ipam.js`'s `loadScopeTrend()` computes `t0`/`t1` itself from a
`24h`/`7d` toggle (`view.scopeTrendWindow`) rather than the server
choosing a default, so the two window buttons are just two different
requests, not two rendering modes of one payload.

`drawScopeTrend()` draws a plain filled-line chart by hand (`App.svgNode`,
same primitive every other hand-drawn chart in this app uses — no shared
"line chart" helper exists or was added for this, consistent with the
one-off SVG-building style already used for the route graph and
timelines): x is `polled_ts` mapped linearly across the container width, y
is `leased` scaled to the window's own peak, `vector-effect:
non-scaling-stroke` so the line stays a crisp 1.5px regardless of the
`viewBox` scaling trick used to make the SVG responsive. A single
`mousemove` listener on the whole `<svg>` finds the point nearest the
cursor (linear scan over `points` comparing `x(p.ts)` distance — cheap
enough at these point counts to skip a binary search) and shows only
that point's line via `App.tooltip`, the same nearest-sample idiom
`netflow.js`'s own chart tooltip already uses. An earlier version built
one tooltip string from every point up front and showed that whole
string on every mouse move regardless of cursor position — cheaper to
compute, but the entire multi-day series dumped into one tooltip
instead of the value actually under the cursor.

`remove_dhcp_server()` deletes `dhcp_scope_history` rows alongside
`dhcp_scopes`/`dhcp_leases` (manual cascade, matching how those two are
already cleaned up rather than relying on the `ON DELETE CASCADE`
foreign key alone). `Service.run_maintenance()` prunes rows older than
`dhcp_history_days` (default 35 — comfortably past the 7-day chart with
margin) the same way it prunes the reverse-DNS and ASN caches.

### Scheduling and conflict detection (`ipam_worker.py`)

`IpamWorker._tick()` runs every 5 seconds and, for each enabled subnet
and DHCP server, checks whether its own next-due time has passed
(`_next_scan`/`_next_dhcp_poll`, per-id dicts) and it isn't already
running (`_scanning`/`_polling`, per-id sets) — this is why a slow scan
of one subnet never delays another, and a DHCP server that's stopped
answering never blocks the others: each gets its own thread
(`_run_scan`/`_run_dhcp_poll`) and its own in-flight guard.

**Conflict detection** happens inline in `_scan()`, per address, two
independent checks:

1. **Scan-vs-scan**: if the address's previously recorded MAC
   (`IpamDatabase.record_host()` returns the *previous* row before
   overwriting it) differs from what just answered, that's a `"scan"`
   conflict — the same address answering as two different MACs across
   scans of the same subnet.
2. **Scan-vs-DHCP**: the address's DHCP lease record
   (`dhcp_lease_for_ip()`) is checked against what the sweep found, but
   only if that lease was polled within a freshness window — three times
   the DHCP poll interval, or an hour, whichever is longer
   (`dhcp_freshness_s`). A lease the DHCP server hasn't reclaimed yet is
   indistinguishable from a real conflict without this window, and
   flagging every such case would make the feature worthless through
   false positives.

`record_conflict()` itself dedupes: a conflict already open for that IP
and MAC pair doesn't create a second row.

### Find: the cross-source hostname/IP/MAC search

`Service.ipam_search()` (`web/service.py`) is the one place all three
name sources meet. It queries three independent methods — none of them
aware of the others — and merges by IP into one `dict[str, dict]`:

- `IpamDatabase.search_hosts()` — `WHERE h.ip LIKE ? OR h.mac LIKE ?`
  against the discovered-hosts table, joined to the subnet it belongs to.
  This is the only source for a device the sweep found that has neither a
  DHCP lease nor a PTR record.
- `IpamDatabase.search_dhcp()` — `WHERE l.ip LIKE ? OR l.mac LIKE ? OR
  l.hostname LIKE ? OR l.description LIKE ?` against `dhcp_leases`,
  joined to the server it came from.
- `AppDatabase.search_hostnames()` — `WHERE hostname LIKE ? OR ip LIKE ?`
  against the shared reverse-DNS cache — the same table `Resolver`
  writes to, so this also picks up the DHCP-fallback names described
  above.

Each result's `sources` list records which of the three found it (e.g.
`"DHCP lease (Main DHCP)"`, `"discovered by SappiWhere's own sweep"`,
`"reverse DNS"`) — a device found by more than one carries more than one
entry rather than being shown twice. A discovered-hosts pass afterward
fills in `subnet`/`alive` for any result not already placed by
`search_hosts()` itself (a DHCP- or DNS-only match whose address happens
to also be a currently swept host). Sorting prefers a name that starts
with the query, then an IP that contains it, then alphabetical — so an
exact prefix match on the thing you typed surfaces first regardless of
which source found it.

A result whose IP falls outside every subnet configured in IPAM is
expected, not a bug: DHCP polling (`IpamWorker._tick()`) iterates
`self.db.dhcp_servers()` entirely independently of
`self.db.subnets()` — a DHCP server's scopes are polled and recorded
regardless of whether that address range was ever separately added as an
IPAM subnet to sweep. The `sources` field is what makes this
self-explanatory in the UI instead of a recurring support question.

---

## Self-update (`selfupdate.py`)

`POST /api/update` (`web/api.py`'s `post_update`) starts a **job** and
answers `202` with its status straight away; `GET /api/update/status`
(administrator read) is what the Settings dialog polls once a second for
what actually happened. It used to be one synchronous call, and all three
of the things that made the update button lie came from that shape — see
"What the job fixed" below. `apply(app_db, report=None,
before_quiesce=None)` is still the entry point and still never raises:
every failure comes back as `{"ok": False, "error": ...}`.

The job is module state in `selfupdate.py` — `_job` guarded by `_job_lock`,
read by `status()` — deliberately not something the caller holds, so a
browser that reloaded mid-update can still ask where the update got to.
`start_job()` runs `apply()` on a non-daemon thread named
`sappiwhere-update` and refuses a second concurrent job with
`already_running` rather than queueing one behind the first;
`wait_for_job()` joins it. `STEPS` is the whole vocabulary:

1. **`checking`**: `latest_commit()` asks GitHub's REST API
   (`api.github.com/repos/thawkins5555/magicalbeans/commits/main`) for the
   branch tip's SHA and message. Compared against
   `app_db.meta("update_installed_commit")` (a generic key/value marker
   table in `app.db`, unrelated to any setting).
2. **`up_to_date`**: an exact match. A terminal step of its own, not a
   flavour of failure and not something the dialog has to infer from a
   field on a response — the button reporting "update failed" for a host
   that was already current is one of the complaints the job answers.
3. **`downloading`**: the tarball for that exact commit (not just the
   branch name, to avoid a race if something else pushes between the check
   and the download) comes from `codeload.github.com/.../tar.gz/<sha>` via
   plain `urllib.request` — no external HTTP library. TLS verification
   uses the system's trust store *and* a vendored copy of Mozilla's CA
   bundle (`netpath/cacert.pem`, the same one `pip`/`certifi` ship, loaded
   in addition to — not instead of — the system store by
   `_ssl_context()`), because a locked-down Windows server can be missing
   a root certificate with no route to fetch it on demand, and a headless
   install has no pip-installed `certifi` to lean on.
4. **`extracting`**: `_safe_extract()` only ever extracts ordinary files
   and directories, never symlinks or device nodes, and verifies every
   member's resolved path stays inside the destination directory before
   extracting anything — defense in depth against a corrupted or tampered
   archive, not something the real repository needs but cheap to have. The
   extracted tree must then contain `netpath/__init__.py` and
   `netpath/web/__init__.py`, or the whole thing is refused before
   touching anything already installed.
5. **`installing`**: the three install markers (`update_installed_commit`,
   `..._at`, and `..._tag` cleared, since a branch pull cannot honestly
   claim a tag) are written **through the open `AppDatabase` connection,
   before anything is torn down** — `set_meta()` under the same lock the
   rest of the application uses. Nothing on disk has changed at this
   point, so a write that fails costs nothing: the job stops on `failed`,
   the hook never runs and the package is never swapped. Then
   `before_quiesce(sha, message)` — the caller's last moment with app.db
   open, which `post_update` uses for the event-log line and the
   `update.installed` audit row.
6. **`restarting`**: `RESTART_GRACE_S` (2 s) first, which exists only so
   one poll of `/api/update/status` sees this step arrive before the
   listener goes away — without it the dialog's next request fails against
   a service that is deliberately going down, and cannot tell that from a
   fault. Then `_run_before_restart()` (stop the server, shut down the
   service), then `_swap_in()`: any existing `netpath.bak-*` directory is
   removed first (so exactly one backup ever exists), the running
   `netpath/` package directory is renamed to `netpath.bak-<timestamp>`,
   and the newly extracted one is moved into its place. If the move fails
   partway the backup is renamed straight back, `_restore_meta()` puts the
   markers back through short-lived connections (the version that boots
   must not read as the one that never installed), the job ends `failed` —
   and `schedule_restart()` still runs, because the service is already
   torn down and a restart on the previous version beats staying down.
   Finally the documentation files are copied alongside (cosmetic; a
   failure here is ignored) and `schedule_restart()` is called.
7. **`failed`**: the other terminal step, carrying the reason in `error`.

### What the job fixed

Three failures, all visible in `update_restart.log` from a production
Windows host, all of which made a working update report itself as broken:

- **The browser gave up before the update did.** `app.js`'s request
  deadline is 30 s; the before-restart hook alone — `Monitor.drain()`
  finishing in-flight traces, every worker stopping — was measured at
  37-63 s. The operator saw "No answer within 30 seconds" while the
  install went on succeeding behind it. The 202-plus-polling shape is the
  fix: nothing waits on a response that outlives its own deadline.
- **The markers could not be written after the teardown.** They used to be
  written last, from a fresh connection via `appdb.write_meta()`, against
  an `app.db` the shutdown had not finished releasing: 201 consecutive
  `database is locked` lines, and every next check therefore saw no
  installed commit and offered the same update again. Writing them first,
  through the connection that is still open, removes the race rather than
  retrying it.
- **The restart thread was a daemon.** `schedule_restart()` spawned it with
  `daemon=True`, and by the time it was sleeping the hook had already
  stopped everything that was keeping the interpreter busy — so the
  process could reach the point where it kills its daemon threads before
  this one woke. In 146 recorded attempts it never reached its first
  statement. It is `daemon=False` now, logs `restart thread started pid=`
  before it does anything else (so "never ran" is distinguishable from
  "ran and died"), and wraps its whole body in a `try`/`except` that logs
  a traceback.

### The restart itself

This is where most of the real engineering effort went, across three
separate, genuine bugs found against production Windows servers.

**POSIX** (`_restart_posix()`): `os.execv()` replaces the current process
image in place — same PID, no gap where nothing is listening.

**Windows** (`_restart_windows()`) has no equivalent: `os.execv()` on
Windows is emulated by spawning a brand-new process and then ending this
one, which surfaced two distinct problems before it worked reliably:

- **A race for the port and the databases.** The replacement was
  originally spawned *before* this process released anything, so for a
  brief window both processes were alive at once, competing for the same
  TCP port and the same SQLite files — the new one reliably lost that
  race and died within milliseconds. Fixed by a `before_restart` hook
  (registered from `__main__.py` via
  `selfupdate.set_before_restart_hook()`, wired to `server.stop()` +
  `service.shutdown()`) that `schedule_restart()` now runs and waits on
  *before* spawning the replacement at all — the several-second delay
  this can add is `Monitor.drain()` finishing in-flight traces during a
  clean shutdown, not something to work around.
- **A hidden, console-less child being killed by security software.**
  The replacement was originally spawned with `DETACHED_PROCESS` (no
  console, fully hidden) unconditionally. A process spawning a hidden,
  windowless child and then immediately exiting is a recognized pattern
  several antivirus/EDR products flag on sight. `_restart_windows()` now
  checks whether the original launch was headless (`"--headless"` or
  `"--web"` in `sys.argv`): headless keeps `DETACHED_PROCESS` since it
  has no window either way, but a console/GUI session's replacement gets
  `CREATE_NEW_CONSOLE` instead — its own visible window, nothing hidden.
  Every attempt, either way, is logged to `update_restart.log` in the
  app directory (PID, argv, the spawned child's PID, and whether it was
  still alive half a second later) — a plain file rather than the
  in-memory event log, because that log dies with the process at exactly
  the moment a failed restart most needs explaining.
- **The actual root cause of a silent, instant crash even after both of
  the above were fixed**: the relaunch command was built as
  `[sys.executable] + sys.argv`. For a process started with `-m
  netpath`, Python rewrites `sys.argv[0]` to `__main__.py`'s *resolved
  file path* — so the "restart" was actually relaunching that path
  directly, as a bare script, not `-m netpath`. Running `__main__.py` as
  a script rather than as a package module drops the package context
  every relative import in the file needs (`from . import selfupdate`,
  `from .web import Service`, ...), and it crashes on the very first one
  with `ImportError: attempted relative import with no known parent
  package` — within milliseconds, on `pythonw.exe`, with no console for
  anyone to see the traceback on. `_relaunch_args()` now always rebuilds
  the command as `[sys.executable, "-m", "netpath"] + sys.argv[1:]`
  instead of trusting `sys.argv[0]`, on both platforms — this bug was
  latent in the POSIX path too, just never exercised by testing because
  early tests used a throwaway driver script rather than the real
  `__main__.py`.

Sessions are held in memory only (`SessionStore`, see Auth below), so
every restart — successful or not — signs everyone out; the frontend
(`settings.js`'s `waitForRestart()`) polls the public `/api/session`
endpoint with a plain `fetch()` (not `App.get`, which would redirect to
`/login` on the first 401 rather than waiting for the server to actually
come back) until it answers again, then sends the browser to sign back
in.

`settings.js`'s `pollUpdateStatus()` runs ahead of that: a one-second loop
on `/api/update/status` that paints a sentence per step, ends green on
`up_to_date`, red with the reason on `failed`, and hands over to the
restart modal on `restarting`. A request that fails *after* `installing`
means the service is going down on purpose and is treated as the restart,
not as an error; before that, five consecutive failures give up and
re-enable the button. And because the job outlives the page that started
it, `load()` calls `resumeUpdateIfRunning()`: a browser reloaded
mid-update finds `state == "running"`, disables the button and rejoins the
same poll instead of showing an idle Settings page over an install in
flight.

---

## Auth (`auth.py`)

Passwords are hashed with scrypt at OWASP's current recommended cost
(`N=2^17, r=8, p=1`, roughly 128 MiB per verification), falling back to
PBKDF2-HMAC-SHA256 at 600,000 rounds only if the underlying OpenSSL is too
old for scrypt (`_scrypt_available()` probes this once). The stored
string is self-describing (`scrypt$N$r$p$salt$key` or
`pbkdf2_sha256$rounds$salt$key`), so raising the cost parameters later
doesn't invalidate existing hashes — `needs_rehash()` compares stored
parameters against current constants, and a successful login rehashes in
place if they're weaker (or if scrypt has become available since the
account was created under PBKDF2). `verify_password()` uses
`hmac.compare_digest()` for the final comparison specifically for its
constant-time guarantee.

**Sessions** (`SessionStore`) are an in-memory dict, deliberately never
persisted — a restart signs everyone out, which is the stated safe
default and also means a session token can never leak by ending up in a
database backup. Two clocks per session: idle timeout (`get()` expires a
session the idle window after `last_seen`) and an absolute lifetime
(`created` + max hours, checked the same way). `touch()` — which extends
`last_seen` — is called only for a POST/PUT/DELETE or the browser's own
heartbeat ping when it detects real mouse/keyboard input
(`app.js`'s `HEARTBEAT_GAP_MS` throttling), never for the periodic
`/api/state` poll every open tab makes on its own — the idle clock
tracks presence, not whether a tab happens to be open.

**Login throttling** (`LoginThrottle`) counts failures per username *and*
per source address independently, so one noisy client can't lock out an
account for everyone else and one account can't be used to lock out a
shared address (a NAT gateway, for instance). The delay is exponential
once past the threshold (`2 ** (failures - threshold)`, capped at 30s) —
5 failures adds a one-second delay, 10 adds thirty.

---

## Permissions (`permissions.py`, `appdb.py`'s `user_permissions`)

Its own small module rather than folded into `appdb.py` or `eventlog.py`:
`eventlog.CATEGORIES` is a different, non-matching taxonomy (built for
the Debug page's log filter — missing Syslog/Dashboard/Settings/Debug,
including non-module `system`/`error` categories) and was never meant to
double as an authorization module list. `permissions.MODULES` is the
exhaustive, deliberately explicit list — one entry per gate-able tab.
`dashboard` is not in it: it's an aggregate view of whatever other
modules the signed-in account can already read (see `api.get_state`
below), not a module with its own data to gate. `allows(granted,
required)` is the one comparison every check in this app makes: `None`
satisfies nothing, `read` satisfies `read`, and only `write` satisfies
`write` — write implies read by construction (`granted in (READ, WRITE)`
for a `read` requirement).

**Storage**: `user_permissions(username, module, level)`, a plain
`CREATE TABLE IF NOT EXISTS` — no `_migrate()` needed, since this is a
new table rather than a new column on an existing one. Its one piece of
migration-shaped logic lives in `AppDatabase.__init__`: if the table did
not exist before this run *and* `users` already has rows in it (an
existing install upgrading), every existing account is backfilled to
`write` on every module, so nobody who already had full access loses any
of it silently. This deliberately does **not** cover the bootstrap
default admin account on a brand-new install: `users` is empty at the
point the backfill would run (the default admin is seeded later, in
`web/service.py`'s `_ensure_default_user()`), so that seeding explicitly
calls `set_permissions(DEFAULT_USER, {m: WRITE for m in MODULES})` itself
right after creating the account — otherwise a fresh install's own
default admin would start with zero access to everything it just
installed.

**Enforcement** is one check, in `server.py`'s `_route()`: after
resolving the caller's username, look up
`service.app_db.permissions_for(username)` and evaluate the matched
route's `requirement` (see `web/server.py` above) against it before
calling the handler at all — a route with no matching or insufficient
grant never reaches its handler, returning 403 with `{"error": "No
{level} access to {module}"}`. This is the check that actually matters;
everything client-side (hiding a tab, hiding a write-gated button) is
strictly a courtesy on top of it, never a substitute.

**`/api/state` and `/api/config` are the one deliberate exception** to
"a route either passes or is refused outright." Every open tab polls
`/api/state` regardless of which module it's actually looking at —
Dashboard, which is always visible, depends on it — so blocking it for
anyone without a specific module's access would break Dashboard for
everyone but a full admin. Instead both routes always succeed and a
per-module map (`_STATE_MODULE_KEYS` for the live blocks, `_CONFIG_MODULE_KEYS`
for the settings blocks) strips the top-level keys the requesting account
can't read, after building the full response — a filter on the way out,
not a gate on the way in.

The two routes are the same payload split by *what changes it* (4.43.0).
`/api/config` — `api.get_config()` — is everything only an operator
changes: every `*_settings` block, `permissions`, `update`, `version`, the
constant vocabularies (`severities`, `facilities`, `trap_kinds`,
`dimensions`, `categories`). It carries `config_version`, an integer
`Service.bump_config()` moves from `apply_settings`, `apply_global_settings`,
`apply_netpath_settings`, `save_listener_settings`, and the account and
grant writers in `api.py`.
`/api/state` — `api.get_state()` — is what changes on its own: each
worker's `running`/`status`/`counters`, the counts behind the tab badges,
the session clocks, `storage`, `dns`; it repeats `config_version`. The
browser (`App.loadState`) fetches config once at start and again only when
the version it sees differs from the one it holds, then merges the two
into `App.state.serverState` so every consumer written against the single
payload still sees one object. Before the split the poll was 10.9 KB
every two seconds, of which 6–7 KB could not have changed since the last;
it is 4.5 KB identity, 1.3 KB on the wire. The poll also lost its
duplicated `app_db.user()` lookup, two `SELECT *`-then-`len()` counts
(`conflict_count()`, `controller_count()` are `COUNT(*)`), and its eleven
`size_bytes()` and the hostname-cache figures go through
`Service.cached_poll(key, ttl_s, compute)` — at most once per ten
seconds across every open tab, since neither means anything at
two-second resolution.

**Always-reachable password change**: `/api/password` is one of the
routes whose requirement is a callable rather than a static pair,
because "self change" and "reset someone else's password" need
different rules from the same route — changing your own password is
`None` (no permission needed at all, by explicit product requirement),
while resetting a different account's requires `("settings", WRITE)`.
Before this shipped, `api.py`'s `post_password` had no authorization
check on the reset path at all — `resetting = target.lower() !=
me.lower()` only decided whether to skip the *current-password*
check, not whether the caller was allowed to act on someone else's
account — so any signed-in user could silently reset any other user's
password. Fixed as a direct consequence of building this system
properly, not a separate patch. On the frontend, changing your own
password lives in `app.js`'s `accountModal()` — a small, self-contained
modal reachable from an always-visible "Account" control in the top bar,
deliberately outside `settings.js` and sharing no DOM ids with it, so it
works identically whether or not the signed-in account can read Settings
at all.

---

## Wireless (`nodeoids.py`, `wirelessdb.py`, `fortipoll.py`)

**OIDs** (`nodeoids.py`) are hand-listed constants, not parsed from
a MIB at runtime — the same "not a MIB compiler" convention `trapdecode.py`
already uses for other fixed, known vendor tables (see
Nodes above). Three tables under `fgWc` (`1.3.6.1.4.1.12356.101.14`),
all indexed by `(fgVdEntIndex, WtpId[, RadioId])`: `fgWcWtpConfigTable`
(the AP's configured name), `fgWcWtpSessionTable` (live status/MAC/
model/client count) and `fgWcWtpSessionRadioTable` (per-radio mode/
channel/tx power/client count, one additional `RadioId` index arc).

**The tx-power unit is a decision, not a constant.**
`fgWcWtpSessionRadioOperatingPower` (column 8) has the DESCRIPTION
"Represents the current operating power of this radio, in dBm." Observed
FortiOS does not honour that: a FAP-231F reports values like 51, and
51 dBm is ~126 W EIRP, about a thousand times a FortiAP's ~20 dBm
conducted ceiling. It is reporting FortiOS's own 0–100 power *level*.
`api._power_unit()` therefore decides per controller rather than
hard-coding either reading: if any of that controller's radios reports
above `nodeoids.MAX_PLAUSIBLE_DBM` (30 dBm = 1 W, already above every
indoor regulatory limit), the whole column is read as a percentage, since
no radio in one chassis switches units. `wireless_settings
["radio_power_unit"]` (`auto`/`dbm`/`percent`) forces it. The raw integer
is always carried through to the AP detail pane so the guess is
auditable, and the JSON field keeps its MIB name
(`operating_power_dbm`) rather than being renamed to match a guess.

**A scanning radio is excluded, not converted.** `api._SCAN_MODES` is
`monitor`/`sniffer`; `_radio_json` stamps `is_scan` from it, and `_ap_json`
filters those radios out of *both* the `powers` list fed to `_power_unit` and
the `tx_power_dbm` maximum. That exclusion is a bug fix, not a refinement:
4.25.0 fed every radio into the ceiling test, so one scanner reporting 51
flipped its entire controller to "% level" and relabelled serving radios that
were reporting a genuine 17 and 20 dBm. The frontend renders `Scan` for such a
radio ahead of any unit choice, and still prints its raw value beside it.

**Radio mode** (`fgWcWtpSessionRadioMode`, column 3, `FgWcWtpRadioMode` =
other/notExist/disabled/ap/monitor/sniffer) is walked and stored decoded
in `radios.mode`, added by `wirelessdb._migrate()`. It is what explains a
FAP-231F's puzzling third radio: it is a dedicated scanner, so its
"power" describes a receiver. The radio loop keys off the union of every
walked column rather than off the channel column alone — a monitor or
disabled radio reports a mode but often no channel, and keying on channel
dropped it from the list entirely. `WtpId` is a
string-valued (OCTET STRING) table index, so its OID-suffix encoding is
a length prefix followed by that many decimal char-code arcs —
`fortipoll._split_vdom_wtp()` is the one place that decoding happens,
shared by every table walk since all three share the same `(vdom,
wtp_id)` key.

**Polling** (`fortipoll.WirelessPoller`) reuses Nodes' own low-level SNMP
plumbing wholesale — `nodepoll._Session` (one UDP socket per poll, with
retry), `nodepoll.EngineCache` (v3 engine discovery caching, keyed here
by controller id instead of device id), `nodepoll.credential_for()`
(decrypt-just-before-use, discard after) — rather than reimplementing
any of it. Table walking is repeated GETNEXT (`_walk_column`), not
GETBULK: the same choice `nodepoll.py`'s own table walker already made
("avoiding a separate GETBULK code path"), matched here rather than
introducing a second table-walking idiom for one small poller. Same v3
limitation as Nodes: authPriv raises `SnmpUnsupported` at session setup,
since there is no AES/DES in the standard library and this app takes no
third-party dependency for it — v1/v2c community or v3 noAuthNoPriv/
authNoPriv only.

**Storage** (`wirelessdb.WirelessDatabase`): `controllers` (one row per
configured controller, carrying its own SNMP credential columns —
there's no group/profile system here, since a handful of controllers
doesn't need one), `access_points` and `radios` (child rows, replaced
wholesale on each successful poll of that controller via
`replace_radios()`), and `ap_events`. `prune_stale()` only ever runs
after a controller's own poll *succeeded* — a transient controller
outage never wipes its AP list, only a poll that genuinely completed but
no longer sees a particular AP does.

**AP removal is an event, not a silent delete.** `prune_stale()` records
an `ap_removed` row (via `add_ap_event`, the one owner of that INSERT)
for every AP it ages out and returns the removed list, so `fortipoll` can
log it and `alertengine`'s `_drain_ap_events()` can raise a real alert
(built-in rule `wireless_ap_removed`, kind `wireless_event`). The reverse
transition pairs the same way its device siblings do: `upsert_ap` records
`ap_returned` whenever it inserts a brand-new row, and
**AP offline vs AP removed.** `_record_status_change` (`wirelessdb.py`) is
called from `upsert_ap` when the row already existed, and records `ap_offline`
/ `ap_online` on the connection-state transition — mirroring the
`ap_removed`/`ap_returned` pair exactly, including the `out_of_service`
exemption and the fact that it fires on the *transition* rather than on every
poll that still finds the AP unhealthy. It runs with the database lock held,
which is safe because the lock is an `RLock` and `add_ap_event` takes it
again — the same thing the existing `ap_returned` call in `upsert_ap` does.

`_OFFLINE_STATE` is deliberately the single string `"offline"` rather than
"anything that is not online". `nodeoids.CONNECTION_STATE` also contains
`downloading_image` and `connected_image` — which every AP passes through on
a routine firmware upgrade — plus `standby` (held in reserve on purpose) and
`other` (the controller did not say). Alerting on "not online" would raise and
then clear one alert per AP on every fleet upgrade, which is the noise 4.29.0's
rollup work existed to remove.

The gap it closes is worth stating plainly, because it is not obvious from
either side: `upsert_ap` resets `missed_polls` to 0, correctly, since the poll
*did* see the AP; `prune_stale` therefore skips it, correctly; so `ap_removed`
never fires for an AP the controller still lists. An AP could be offline
indefinitely with nothing recorded anywhere. `wireless_ap_offline` is
deliberately absent from `ROLLED_UP_BY`: "the controller lost it" and "the
controller has it and it is not working" are different facts with different
remedies, and 4.29.0's rollup exists for alerts that *restate* one outage.

`alertrules.CLEARS` maps it to `wireless_ap_removed`, so an AP that comes
back auto-resolves its own removal alert (a genuinely new AP has no such
alert, making the event inert for it). The drain uses the same cursor
contract as every other source — first tick seeds `max_ap_event_id()`,
later ticks read `ap_events_since()` — prefetches the handful of
controllers once per drain rather than once per row, and
`AlertEngine`'s `wireless_db` is an optional keyword argument, so an
engine constructed without it simply raises no wireless occurrences.
`ap_events` rows age out after 90 days via `prune_ap_events()` in the
service maintenance loop, same as Nodes' own event tables.

**`out_of_service`** (added to `access_points` by a new
`wirelessdb._migrate()`, the same PRAGMA-diff/ALTER pattern nodesdb uses)
is an admin marking, orthogonal to the reported `status`. It does two
things, both inside `prune_stale`: such an AP is skipped entirely — never
aged out, never even counted as missing — and therefore never produces an
`ap_removed` event. That exemption is what makes the marking survive the
thing it describes: an unracked AP stops being reported, and without it
the row carrying "we know about this one" would be the first thing
deleted. The consequence is that an out-of-service AP can never age out
on its own, which is why `DELETE /api/wireless/aps/{id}` exists.

The API layer keeps the same precedence: `get_wireless_aps`'s `state`
filter lists an out-of-service AP only under `out_of_service`, never
under the status it last reported. Its `last_reported_ts` is the newest
successful poll across the controllers in view — one age for the page,
which is what made a per-AP "last seen" column redundant (every row came
from the same walk). The extra selectable columns (`radio_count`,
`channels`, `radio_station_count`) are derived in `_ap_json` from radio
rows the poller already walks, so adding one costs no extra SNMP.

### Per-AP response time (`fortipoll.py`, `nodeoids.py`)

The module's stated design is that it talks to the controller and never to an
AP, so a per-AP latency figure had nowhere to come from — `access_points` had
no address, because nothing needed one. `fgWcWtpSessionWtpIpAddress`
(`fgWcWtpSessionEntry 3`, read off the vendor's own MIB) is another column of
the session table the poller already walks, so learning each AP's address costs
no extra SNMP; only the ping is new traffic.

`_format_ip` is where the subtlety is. The value never arrives as bytes: by the
time `_walk_column` returns it, `snmppoll` has already run the OCTET STRING
through `_octets_text`, which renders a non-printable string as space-separated
hex ("7F 00 00 01"). So the hex form is the normal case, the dotted form (some
FortiOS builds, and the IpAddress type) is accepted too, and anything of the
wrong length becomes blank — notably a six-byte MAC, which must never be stored
as an address and pinged.

`_ping_ap` returns `None`, not `0`, when nothing answers: 0 would sort to the
top of the fastest APs and read as instant. An AP the controller already
reports as offline is not probed at all, and `PING_BUDGET_S` bounds the whole
controller's sweep so a rack of unreachable APs cannot each add a timeout to
the poll cycle.

## ConfigRX (`configrxdb.py`, `configrx.py`)

**No device table of its own.** Per the explicit product decision,
ConfigRX operates entirely on Nodes' existing device list — the device
picker in the UI calls `GET /api/nodes/devices` exactly as Nodes' own
table does. `configrxdb.device_config` stores only ConfigRX's own
per-device backup configuration, keyed by the Nodes device id with no
real foreign key (SQLite cannot enforce one across separate database
files) — the same pattern Alerts already established for its own
`entity_id` columns.

**The safety boundary** (hard requirement, stated explicitly so a later
change can't erode it by accident): `configrx._pull_config()` is the
*only* function in the entire module that writes to a device's shell
channel, and it sends exactly `vendor.pager_off`'s fixed lines followed
by `vendor.show_config` — plus, for a vendor whose login shell is not
already privileged EXEC (`vendor.enable_command` set — currently just
`cisco-asa`), the fixed `enable` command and the device's own stored
enable secret, sent back only as the answer to that device's own password
prompt (`_do_enable`, matched against `vendor.enable_password_re`, never
built into anything sent). All of it is sourced from
`configrx.VENDORS`, a hardcoded dict, never from anything the API
or UI accepts as free text. A device's `vendor_override` field is free
text, but it only ever selects *which* vendor's fixed commands to use
(`configrx.resolve()` does a dict lookup); an unrecognized value
simply fails to resolve and the backup is skipped with a clear error,
never used as literal command text. There is no exec-command endpoint, no
command parameter anywhere in `api.py`'s ConfigRX handlers, and no
free-form input field anywhere in `configrx.js` — grep for `channel.send`
in `configrx.py` to confirm this hasn't grown a call site beyond
`_pull_config` and `_do_enable`. `VENDORS` currently holds eleven keys:
`cisco`, `cisco-nxos`, `cisco-iosxr`, `cisco-sb`, `cisco-asa`,
`cisco-wlc`, `fortinet`, and four more besides — `cisco-asa` is the only
one carrying `enable_command`, since it is the only login shell here that
does not already land in privileged EXEC.

**The capture ends on the prompt, not on silence.** `_drain()` returned as
soon as it had any data and 1.5s passed with none, which is a fine rule for a
login banner and a catastrophic one for `show running-config`: a Cisco writes
`Building configuration...` immediately and then thinks, so the read ended on
the banner and those two lines were stored as a whole backup. The
`SHELL_MAX_S` ceiling never came into it, and the old `len(cleaned) < 20`
guard passed a ~45-character result.

`_read_until_prompt(channel, prompt, max_s, quiet_s)` replaces it and returns
`(text, ended)` where `ended` is one of `prompt` / `quiet` / `pager-loop` /
`timeout` / `closed` — so a complete capture is *distinguishable* from a
truncated one, which is what the storage guard needs. `_learn_prompt()` takes
the prompt from the last non-blank line of the login banner and returns `""`
unless it ends in `#`, `>`, `$` or `%`: a wrong prompt is worse than none,
because it would end every read at the first config line that matched, so an
unlearnable prompt falls back to a long silence window instead of a guess.
`_waiting_at()` is why a config line reading `switch#` never ends a read — a
prompt is written *without* a trailing newline, because the cursor stays on
it, so a buffer ending in a newline is never "waiting".

**Pagers are answered, and the safety boundary survives it.** `_PAGER_RE`
only stripped `--More--` lines after the fact, which does nothing for a device
sitting there waiting for a keypress. `_read_until_prompt` now matches
`_PAGER_TAIL_RE` at the *end* of the buffer and sends a single space
(`MAX_PAGER_REPLIES` caps the loop). That space carries no newline and no
text, so it cannot execute anything: it is a fixed in-band answer to a prompt
the device raised, and the boundary above — only `pager_off` plus
`show_config` are ever *run* — is intact. `_clean_output` gained
`_PAGER_INLINE_RE` for the markers a paged capture leaves mid-line after the
device erases its own with backspaces.

**A truncated capture is never stored.** `_capture_problem(cleaned, ended)`
returns the reason a capture must be refused or `""`: an empty body, an
`ended` of `timeout` / `pager-loop` / `closed`, a last line matching
`_STILL_WORKING_RE` ("Building configuration…"), or a body under the length
floor. That floor has two values on purpose: when the read ended on the
device's prompt the command demonstrably ran to completion, so a short result
is a genuinely short config — a stripped-down MikroTik `/export` really is
only a few lines — and `MIN_PROMPT_TERMINATED_CHARS` (80) only has to reject
a capture that is nothing but an error line. Any other ending carries no such
evidence, so `MIN_CONFIG_CHARS` (200) applies: a real running-config is
hundreds of lines. `_backup_device`
records a failed attempt naming it and returns before `add_backup`, because
storing a partial as a good version is worse than storing nothing: it becomes
the newest version, the next real backup reads as an enormous change, and a
restore from history hands someone a fragment. The ceiling itself is the
`capture_timeout_s` setting (`configrxdb.DEFAULTS`, 180s) rather than a
constant — a large config over a slow link legitimately takes minutes, and it
is only a ceiling, since a healthy device ends on its prompt in a second.

**Closing the channel is best-effort, so a device that hung up cannot
discard the read it already finished.** `_pull_config`'s `finally` block
closes the channel it opened, and closing one sends a message; when the
device has already hung up — the exact `"closed"` `ended` value above —
paramiko's own close handshake raises `EOFError` writing that message
into a socket that is already gone. Left unguarded, that `EOFError`
propagated out of the `finally` and replaced whatever `_pull_config` had
already returned, so the one case `_capture_problem` is careful to report
as "The device closed the connection before the config finished" instead
crashed the whole attempt with a bare `EOFError` — cleanup destroying a
result that had already been computed. The close is wrapped in its own
`try`/`except Exception: pass`, matching the pattern the SSH terminal's
own teardown (`sshterm.py`) already used for the identical situation.

**Legacy key exchange is feature-detected, and the version cap is the real
fix.** `configrx._apply_legacy_algorithms(paramiko)` appends
`diffie-hellman-group-exchange-sha1` / `-group14-sha1` / `-group1-sha1` and
`ssh-rsa` / `ssh-dss` to `Transport._preferred_kex` and `_preferred_keys` —
but only the names that `Transport._kex_info` / `_key_info` actually contain,
which is the whole trick. paramiko 3.x *implements* those classes and merely
leaves them out of its preferred list, where re-adding them works; paramiko
5.0 **deleted** them (`paramiko.kex_group1` is gone, `kex_gex` keeps only
`KexGexSHA256`, `_key_info` has no plain `ssh-rsa`), so there is nothing to
re-add and a version check would have to guess which world it is in. They are
*appended*, so a device capable of curve25519 still negotiates it and only one
offering nothing better falls this far; the function is idempotent, so
restarting the worker does not grow the lists. It runs once from `start()`,
gated on the `allow_legacy_ssh` setting, because it edits class-level state.

Because paramiko 5 cannot be fixed in code, `requirements.txt` pins
`paramiko>=3.4,<5`. `_connect_error_text()` covers the gap for an environment
that still has 5 installed: when a connect failure mentions kex *and*
`_legacy_kex_available` is False, it appends the cause and both remedies to
paramiko's own message, which otherwise says only "no acceptable kex
algorithm" and reads like a device problem. When legacy KEX *is* available the
device really did refuse, so the original text is left alone — the flag is
what distinguishes the two.

**paramiko is imported lazily and its absence is a status, not a crash.**
It is the one third-party dependency in this otherwise stdlib-only app,
so the import lives inside `_backup_device` and every other module runs
without it. Missing it is a deployment fact rather than a bug, so the
`ImportError` is caught right there and turned into a normal
`record_backup_attempt(..., status="error")` naming the pip command —
previously it propagated to `_run_one`'s handler and produced a raw
`ModuleNotFoundError` traceback in the Errors log, with the device's own
row saying nothing at all. `paramiko_available()` re-checks on each
`status_text()` call rather than caching at construction, so installing
it and restarting the worker is enough — no app restart.

**The SSH credential** follows the identical discipline every other
stored secret in this app does (see `CREDENTIAL-SECURITY.md`):
`_backup_device()` decrypts the DPAPI blob into a local `password`
variable immediately before `paramiko.SSHClient.connect()`, and
reassigns it to `None` in a `finally` block the moment the connection
attempt finishes, success or failure. The optional enable secret
(`device_config.enable_secret_enc`, its own column, set and cleared
through `configrxdb.set_credential`'s optional fourth argument or the
dedicated `set_enable_secret`/`clear_enable_secret`) follows the same
rule one step later: `_backup_device()` only decrypts it when the
resolved vendor's `enable_command` is set, into a local `enable_secret`
passed down to `_pull_config`, cleared in the same `finally` block that
clears `password`. `_AcceptAndRecordPolicy` (a
`paramiko.MissingHostKeyPolicy` subclass) never blocks on an
unrecognized host key — network gear rarely carries a stable
`known_hosts` entry — but, unlike `AutoAddPolicy`, flags that it
happened so `_backup_device()` can note it in the backup's own
`last_backup_status` rather than silently accepting an unknown key with
no record of it.

**Backup dedup**: `ConfigRxDatabase.add_backup()` hashes the cleaned
output (SHA-256) and compares it against `latest_backup_hash()` for that
device — a match stores nothing, an unchanged poll only updates
`last_backup_ts`/`last_backup_status`. This is why there is no
"changed since previous" flag anywhere in the API: every row that exists
in `backups` already represents a change, by construction, so the mere
presence of a row *is* the flag. `_clean_output()` strips ANSI escape
sequences and pager prompts (`--More--` and similar) a device's shell
may have echoed back even with paging disabled — best-effort display/
storage hygiene, not a parser, so it never raises.

**A capture much smaller than the last one is stored, but flagged, not
treated as an ordinary change.** `_backup_device` reads
`latest_backup_size()` — the byte size of the device's own most recent
stored backup — *before* `add_backup` inserts the new row, so the
comparison is against the previous backup rather than the one about to be
stored. A new capture under `SUSPECT_SHRINK_RATIO` (0.2, a fifth) of that
size is still stored — refusing it would be worse, the same reasoning
`_capture_problem`'s own docstring gives for a truncated read that still
reaches a prompt, since a device really can shed most of its
configuration in one legitimate change — but recorded with
`record_backup_attempt(..., status="suspect")` and its own
`counters["suspect"]` tally rather than the ordinary `"changed"` status
and counter, because presenting it as a plain diff would read as almost
the entire configuration having been deleted.

**Device naming** (`_configrx_device_json`) matches `nodes.js`'s own
`displayName()` precedence exactly: `sys_name` (SNMP hostname) unless
`display_name_source == 'manual'`, then the stored manual `name`, then
`ip` — previously it preferred the manual `name` first regardless of
`display_name_source`, so a device Nodes had never been told to pin to a
manual name showed a stale/blank one here instead of its live SNMP
hostname.

**Gating disables; it never hides.** `applyPermissions()` in `app.js`
originally wrote `el.hidden = !canWrite(...)` — bidirectionally — on every
`[data-requires-write]` element, so for an account *with* write access it
un-hid the ConfigRX bulk bar on every `loadState()` while `drawBulkBar()`
hid it again from the selection count: "Set SSH credential" flickered in
and out with the page shifting under it. The first fix made it one-way,
hide-only, which stopped the flicker and created a worse problem: a
read-only operator saw Nodes with no Add device, no Settings and no way to
tell a missing permission from a missing feature, and a grant made
mid-session waited for a reload because nothing could ever un-hide.

4.41.0 changes the mechanism rather than its direction. `applyWriteGate()`
sets `disabled` on a control (or `inert` on a `<div>`/`<span>`, which do
not honour `disabled`), records `dataset.writeDenied` so it only ever
re-enables what it itself disabled, and puts the reason in the control's
`title`. `explainDeniedGroups()` then adds **one** `.write-denied-why` line
per bar — not per button, or nine dead buttons would carry nine copies —
because a disabled control with only a tooltip is unreadable on a touch
screen and invisible to anyone who does not think to hover it. It is
rebuilt only when the set of denied controls actually changes, since
`applyPermissions` runs on every `loadState()`.

`disabled` has no second owner the way `.hidden` did: nothing in the app
enables a control it did not itself disable for an in-flight request, and
a denied control cannot be pressed to start one. So the gate is applied on
every poll and a permission that changes settles within one cycle in both
directions. The convention about placement still stands — `data-requires-
write` goes on the buttons, not on a container something else shows and
hides — but the reason is now only tidiness rather than correctness: the
wireless AP action buttons carry both `hidden` (owned by the selection)
and the gate (owned by this), and the two no longer fight.

**Bulk edit** (`post_configrx_devices_bulk_config`/
`post_configrx_devices_bulk_credential`): the same `_bulk_device_ids(body)`
helper and Ctrl/Cmd-click-to-select UI shape Nodes' own bulk device
operations already established, applied to ConfigRX's per-device config.
The credential path encrypts the password exactly once (`dpapi.protect()`
before the loop, never inside it) then calls `configrx_db.set_credential()`
once per selected device with that same ciphertext — one encryption, not
one per device, but still one full `set_credential()` write per device
since that's an existing single-device method with no schema reason to
grow a bulk variant of its own. The frontend's bulk-config request only
ever includes `backup_enabled` in its body when the "also enable backup"
checkbox is checked; omitting the key (rather than sending `false`) is
what makes leaving it unchecked a no-op instead of silently disabling
backup on every device that already had it on, matching the partial-
update semantics `update_device_config()` already has for every other
optional field.

**Scheduling** (`ConfigRxWorker`) mirrors `fortipoll.WirelessPoller`'s
shape (a small `ThreadPoolExecutor`, a scanning loop, a `_queued` set
for de-duplicating concurrent triggers of the same device) rather than
`nodepoll.py`'s larger multi-candidate-credential machinery, since a
device here has exactly one fixed SSH credential rather than a
group/profile fallback chain.

### Cross-device search and compliance (`configrx_compliance.py`) — 4.49.0

The query nothing before this pass could answer: `configrx.diff_texts`
compares two backups of the *same* device; nothing kept a searchable copy
of more than one device's capture at once. The search half of
`configrx_compliance.py` builds one
— `configrxdb.config_lines`, one row per device's latest capture, FTS5
trigram-indexed the same way syslog search already is, falling back to a
full scan for a query too short to index — and it is built **only from
redacted text**, written once when a new capture lands
(`replace_search_lines`), never from the verbatim row `backups.content_gz`
may also hold: `get_configrx_diff` already treats a cross-backup view as
needing stricter handling than a single backup's own download, and a
search box is a strictly worse place to leak a secret than a diff — a
diff only ever shows two specific backups an authorised caller already
chose to open, where a search box is *probed*, on purpose, with arbitrary
substrings, by anyone who can reach it.

**An operator-supplied regular expression is a harder problem than the two
quadratic bugs fixed elsewhere this pass.** Those were this application's
own regexes misbehaving on ordinary input, fixable by rewriting them; a
search or compliance pattern may itself be the thing that misbehaves, on
input that is not otherwise unusual at all, and telling a genuinely
dangerous pattern apart from a safe one in general is an open problem.
Three independent, deliberately over-inclusive bounds apply instead of
proof: `compile_bounded()` refuses, before ever running a pattern, either
of two shapes measured on this machine to blow up regardless of input — a
self-repeating group quantified again (`(a+)+`, `(a|aa)+`, `2.6s` at 35
characters for the latter), or more than `MAX_ADJACENT_QUANTIFIER_RUN`
(3) quantified atoms chained back to back with nothing to disambiguate
between them (`a+a+a+a+`, `13ms` at four chained atoms against 60
characters, `36s` at ten against 40) — while a fixed-count outer repeat
(`(\d{1,3}\.){3}\d{1,3}`) or a literal breaking the chain (`a+b+`, a
dotted-quad IP pattern) is exempt, since neither can grow exponentially
with input length. Every line actually tested is capped at
`MAX_LINE_CHARS_FOR_MATCH` (250 characters) — the worst shape the first
bound still lets through costs 0.22s at that size and grows roughly
cubically past it, and there is no `signal.alarm` on Windows (this
product's own deployment target) to preempt a `re` call already running,
so the only real bound on one match's worst case is bounding what it is
handed. And `SEARCH_BUDGET_S` (2.0s) is a wall-clock ceiling on the whole
search, checked before every line; a search that hits it returns what it
found so far with `truncated=True` rather than pretending to be complete.

`configrx_compliance.py` evaluates a rule (`must_match`/`must_not_match`,
validated through the identical `compile_bounded()` at `add_rule` time so
a rule set can never be *saved* with something that would hang an
evaluation later) the same way, line by line against a device's latest
capture rather than as one whole-document match — the same per-line cap
applied to a document that can run tens of thousands of characters would
otherwise cost minutes, not milliseconds, and there is no smaller bound to
give a whole-document match the way there is for one line; the real but
narrow cost is that a rule cannot span more than one line, which every
realistic example this feature's own brief names (an NTP server, an SNMP
community, port security, a VLAN) does not need to. A `must_not_match`
rule that legitimately never matches is the expensive case — proving no
match means checking every line, not stopping at the first — so
`COMPLIANCE_SWEEP_BUDGET_S` (10.0s) bounds a whole sweep the same way
`SEARCH_BUDGET_S` bounds a search; `evaluate_all()` runs on the same
thread `ConfigRxWorker._loop` uses to schedule every device's own backup,
so a sweep that ran long uncapped would silently stop that scheduling
from being checked for the fleet, not just cost this one feature time.
Results are stored one per (device, rule set) — `not_assessed` for a
device with no capture at all, never a silent pass — so a device list can
show a compliance column without re-running every rule on every page
view.

---

## Web layer

### `web/server.py`

Stdlib-only: `http.server.ThreadingHTTPServer` plus `ssl` when a
certificate is configured. `ROUTES` is a flat list of
`(method, compiled regex, handler, requirement)` tuples matched in
order; a route's captured groups (e.g. a numeric ID) are passed as
positional arguments to the handler after `(service, params, body)`.
`requirement` is the permission check for that route — see Permissions
below — and is `None`, a static `(module, level)` pair, or (for the
handful of routes whose actual requirement depends on the request body,
e.g. `/api/password`'s self-change-vs-reset distinction) a
`fn(params, body) -> (module, level) | None` callable. `PUBLIC_PATHS`/
`PUBLIC_API` are the only things reachable without a session — the login
page and what it needs to render, plus `/api/login` and `/api/session`
itself (the latter needed by `waitForRestart()`'s post-restart polling,
which by definition has no valid session yet).

Every write method (POST/PUT/DELETE) is rejected with 415 unless its
`Content-Type` is exactly `application/json` — a cross-site form can send
a POST but can't set that content type without a CORS preflight the
browser refuses, which is belt-and-braces alongside the session cookie's
own `SameSite=Strict`. Static files are served with `Cache-Control:
no-store` for HTML (an update swaps files out from under a browser that
already loaded the old shell; the shell itself must always be re-fetched)
and `no-cache` plus an `ETag` for everything else, so a reload after an
update picks up new scripts via a 304 once the browser has re-validated.

**The static handler (4.43.0).** `StaticCache` (`server.py`) reads every
file under `static/` once when the listener starts — `WebServer.start()`,
which `restart()` also goes through — and holds the bytes, a gzip of them,
a SHA-256-prefix ETag, and the content type from an explicit `MIME_TYPES`
map (never `mimetypes.guess_type` alone: it consults the Windows registry,
where `.js` has resolved to `text/plain`, and every response is `nosniff`).
`get()` costs one `stat` and reloads the entry if mtime or size moved, so
an edit while the server runs still shows on the next request. A
self-update cannot leave the map stale: it swaps the package with the
listener down and always ends in `execv`/`_exit`. The traversal guard is
`os.path.commonpath`, not a `startswith` on a directory name that is a
prefix of its siblings'. The 304 goes through `_send` like every other
response — it used to be three headers written by hand, and since
revalidation is the steady state for every script, most responses the
browser received carried no CSP, no `nosniff`, no `Referrer-Policy`.

**A versioned request skips revalidation entirely.** `_static(path,
versioned)` — `versioned` is `"v" in params`, a bare presence check,
because the `v` query parameter selects nothing about which file is
served, only how long the answer may be kept — serves `Cache-Control:
public, max-age=31536000, immutable` (plus the same `ETag`, unused) in
place of the `no-cache`/`ETag`/conditional-GET dance above, for anything
that is not HTML. `no-cache` still means what it always did: a browser
must ask before reusing a cached response, so a warm reload after an
update used to be sixteen conditional requests each answered 304 before
anything could render — cheap on a LAN, sixteen round trips on a NOC's
VPN link. `immutable` tells the browser not to ask at all, which is only
honest for a URL that changes when its content does; the unversioned path
is untouched byte-for-byte, still `no-cache` with its `ETag`, since
whatever still requests a plain `/app.js` has made no such promise. `/`
and `/login` stay `no-store` regardless of `?v=`, because the HTML shell
itself must always be re-fetched.

The markup asks for every asset as `?v=__SW_VERSION__`, and the static
cache substitutes the running `__version__` as each HTML file is read —
once per load, before the ETag and the gzip are computed, so both describe
the bytes that actually go out. It is substituted rather than written into
the file because a hand-maintained copy of a version number is one that
drifts, and this one is load-bearing: an asset is served immutable for a
year, so a static file that changed while the version did not would go on
being served from every warm cache until the next release. Bumping the one
line in `netpath/__init__.py` re-versions all seventeen URLs across
`index.html`, `login.html` and `ssh.html`; `test_design_tokens.py` checks
each one still carries the placeholder, which is how three vendored files
that had been missed were found.

**Compression** is negotiated once, in `_send`: text, JSON and SVG bodies
of 1 KB or more are gzipped when `Accept-Encoding` lists `gzip` with a
non-zero q (`_accepts_gzip` reads the header token-wise), with
`Vary: Accept-Encoding` on every compressible type whether or not this
response was compressed. Static bodies come pre-compressed from the cache;
JSON is compressed per response. Measured cold load: 800 KB → 242 KB.

**HTTP/1.1.** `Handler.protocol_version` is set, so connections are kept
alive; the library default was HTTP/1.0 and a page load opened one TCP
(TLS) connection per script. Two things follow. Every response must say
where it ends: `_send` always sends `Content-Length`, and a 304 sends no
body. And every request body must be consumed before the response — a
refusal that comes before the handler (401, 403, 415) used to answer with
the POST body still in the socket, which the close threw away and a
persistent connection would have fed to the next request's parser.
`_drain_request_body()` in `_send` reads and drops an unread body up to
`MAX_BODY_BYTES`, and closes the connection for anything larger or
chunked. Per-request state (`_body_consumed`) is reset in `_dispatch`,
because one `Handler` instance now serves every request on a connection.
`tests/test_static_headers.py` sends the exact refused-POST-then-GET
sequence over one connection.

### `web/api.py`

One function per route, `(service, params, body, *path_args) -> dict`
(JSON-serializable). `server.py` catches `PermissionError` -> 401,
`ValueError` -> 400, anything else -> 500 with the exception's
`type(exc).__name__: exc` as the message — handlers raise plain
exceptions rather than building HTTP responses themselves. A handful of
"test" or "check" style endpoints (`post_ipam_dhcp_server_test`,
`selfupdate.apply()`) instead return `{"ok": False, "error": ...}` on an
*expected* failure — a DHCP server not answering, no update available —
reserving raised exceptions for genuinely unexpected conditions.

**Shared route helpers.** `_page(params, default, cap)` is the `(limit,
offset)` every paginated list route reads and clamps. `_require(row, what)`
hands `row` back or raises `ValueError(f"No such {what}")` — the shape every
not-found route used to build by hand. `_pick(body, allowed)` is the
allow-list filter an update route runs its body through before anything
reaches a database column. `_encrypt_secret(secret, unavailable)` is the one
place a credential is DPAPI/passphrase-encrypted for storage, raising the
caller's own `unavailable` wording when neither is configured; the SNMPv3
credential routes build on it through `_store_v3_credential(...)` and
`_clear_credential(...)`, each keeping its own log/audit message and
"unavailable" text verbatim while the encrypt-then-store-then-log-then-audit
shape itself is written once.

**Settings dispatch.** `SETTINGS_SCOPES` maps a settings scope to the
response key its values come back under (`"netflow": "flow_settings"`, and
so on). `post_settings` validates and ranges-checks the body, then for any
scope but `global`/`netpath` calls `Service.apply_settings(scope, values)` —
one table-driven method (`_MODULE_SCOPES` in `service.py`, mapping each of
the nine module scopes — from 4.54.0, `mapper` joins the original eight —
to its settings attribute, database attribute, event-log line and
reconfigure function) that replaced eight near-identical
`apply_<scope>_settings` methods. `mapper`'s own reconfigure function,
`_apply_mapper`, is a documented no-op: MAPPER has no worker to restart,
and the entry exists so `post_settings` needs no special case that skips
calling one for exactly this module. `apply_global_settings` and
`apply_netpath_settings` keep their own methods, since both write
`self.settings` — the combined global-and-NetPath dict — rather than a
module's own settings attribute. The maintenance sweep's seven size-cap
trims (trace, flow, syslog, snmp, ipam, nodes, alerts) each go through
`Service._trim_db(key, db, label, noun, **kwargs)` in place of a repeated
"is the cap set; if so, trim and log" block.

### Backup deletion and in-flight state (`configrxdb.py`, `configrx.py`)

`delete_backup` / `delete_backups` sit beside `prune`, which was previously
the only thing that removed a backup row other than `forget_device`. The
caller-facing subtlety is documented on the method rather than left to be
discovered: deleting a device's *most recent* backup changes what the next
run stores, because `add_backup` dedupes against `latest_backup_hash`. The UI
says so in the confirmation when the selection includes the newest row.

`ConfigRxWorker._queued` was a bare `set[int]` that `_run_one` only discarded
in its `finally`, so "queued behind three others" and "mid-SSH-session" were
the same state. It is now `dict[int, float]` plus a `_started` map and a
`worker_state()` returning the same `{id: {queued, started}}` shape
`NodePoller.worker_state()` does — which is what lets
`_configrx_device_json` join it per device exactly the way the Nodes list
already joins its own (`api.py:1649`).

### Effective vendor in the ConfigRX list (`api.py`)

`_configrx_device_json` used to return Nodes' `devices.vendor` verbatim while
`vendor_override` came back as a separate field the UI only used to fill an
input. The worker meanwhile resolves `vendor_override or detected_vendor` —
so the list could show `cisco` for a device that backs up as `hp`. The row now
carries `effective_vendor` resolved the same way the worker resolves it, plus
`vendor_is_override` so the column can mark it, and the vendor filter matches
on that field. One resolution rule, in two places that agree.

### Bulk settings and bulk backups (`api.py`, `configrx.js`)

`post_configrx_devices_bulk_config`'s allow-list omitted `ssh_username`,
which the database layer had always permitted (`DEVICE_CONFIG_EDITABLE`).
The consequence was a bulk settings dialog that could set everything about
a batch of switches except who to log in as, which is why the pre-4.31
bulk dialog was credential-only and lived beside the single-device one.
It is in the allow-list now, and one dialog covers both.

Every field in the bulk dialog is opt-in — a select with a *Leave
unchanged* option, or a blank input — and only the keys actually set are
put in the request body, so a bulk form cannot silently rewrite settings
you did not come here to change. `backup_enabled` is a genuine three-way
choice; the old dialog's checkbox could only ever turn it **on**, because
"unchecked" had to mean "leave alone" and so could never mean "off".

`post_configrx_devices_bulk_backup` mirrors `post_nodes_devices_bulk_poll`:
id lists back, not counts, because "9 of 12 queued" leaves the operator to
work out which three. It has a fourth bucket Nodes has no counterpart to,
`not_enabled`, for the `backup_enabled` guard — a device with backups
switched off is skipped deliberately rather than backed up anyway. The
worker being stopped raises `NotRunning` **once for the whole request**,
not per device: it is one fact about the server, not twelve facts about
twelve switches. The button settles off the POST result with no watch
loop, the way `bulkPollNow` does — the device rows already carry
`backing_up`/`backup_queued`, so the list itself shows progress.

### Which paramiko is loaded (`configrx.py`)

`_connect_error_text` appends "the installed paramiko removed SHA-1 key
exchange" only when `_legacy_kex_offered is False` *and* `_legacy_kex_implemented`
is falsy, and `_apply_legacy_algorithms` sets the latter by intersecting
`_LEGACY_KEX` against `Transport._kex_info` — a capability check, not a version
test. So that branch is reachable only when the paramiko this **process**
loaded genuinely lacks those algorithms, and reports of it appearing after
installing 3.4 are reports of a process running something else: pip installs
into whichever interpreter it was run from, and a downgrade cannot take effect
until the process restarts, since `sys.modules` caches an imported module for
the life of the process.

The logic was correct, so none of it changed. What changed is that it now says
*which* paramiko: `paramiko_identity()` reports version and `__file__`,
`ssh_algorithm_status()` exposes both flags plus the live `_preferred_kex` /
`_preferred_keys` to the status line and the settings dialog, and
`_offered_algorithms_detail()` writes what was actually offered into a failed
connection's Debug event. A diagnosis nobody can check is not much better than
no diagnosis.

### The Discovery results grid (`nodes.js DISC_COLUMNS`, `drawDiscResultsTable`)

Until 4.37.0 the results pane under Nodes → Discovery was the last table in
the app written as one string of markup — no sorting, no widths, a bespoke
select-all — in the server's `ORDER BY ip`, which is text, so `.100` sorted
before `.9`. It now goes through the shared facility like every other list:
a `DISC_COLUMNS` catalogue in the shape `configrx.js` uses (a fixed `check`
column whose cell is the box, the em-dash hint for a result no credential
identified, or nothing for one already promoted; `ip` sorted as the dotted
string, which `App.sortRows`' numeric collation orders correctly; `ping_ok`
and `snmp_ok` with a `value` of 1/0 so they sort on the flag rather than
the word; `sys_name`; `vendor` with its marker, MIB hint and "(added)" tag,
the arc explanation on a `<span title>` because `App.drawRows` owns the
`<td>`), `App.grid` under the name `nodes-discovery` (so widths persist and
the sort is remembered like any other grid), `App.sortRows` into a copy —
never in place, because `view.discResults` is what the next fetch replaces
and what the approval dialog reads — and `App.drawRows`. Select-all is the
grid's own, computed over the *selectable* subset only; a single row's
toggle corrects the header box through `App.refreshSelectAll` rather than
redrawing. Ticks (`view.discChecked`) are keyed by result id, never by
position, so a re-sort carries them and Promote posts the same ids.

**A running sweep is followed.** `loadDiscJobsIfNeeded`, already called once
per Nodes tick, re-fetches the selected job's results while that job's state
is `running` and the Discovery sub-view is on screen, with one last fetch
on the tick it stops (a module-level `discPrevState` holds last tick's
`id:state`) and none after. Before this the results pane was refreshed only
by a job click or a promote, which is exactly what would have made a new
sort look as though it broke the live update. The draw saves and restores
the pane's `scrollTop`. The approval dialog keeps its plain string builder
but is handed its checked set explicitly instead of swapping
`view.discChecked` in and out of the module global for the length of one
build.

### Bulk selection (`nodes.js`, `alerts.js`, `configrx.js`)

All three selectable tables use one shape: a checkbox first column whose
`onclick` calls `stopPropagation()`, so the box owns selection and the rest of
the row owns the detail pane. Ctrl-click no longer toggles anything — it was
the only affordance before 4.27.0, and an invisible one, which is what made
"bulk resolve only cleared one row" look like a backend bug.

The performance change is separate from the checkboxes and worth not
conflating: `toggleChecked(id, tr)` takes the row and mutates that row's
`checked` property and `bulk-checked` class in place. Every module used to call
its full `drawTable()`, rebuilding every row to change one box, which is what
made ticking several rows on a long list feel slow. The full redraw is still
the path when no row is passed (Select all, Clear selection) and when the data
itself changes.

### Frontend (`web/static/app.js` + per-tab modules)

A single `MASTER_MS = 100`ms `setInterval` (`app.js`'s `master()`) drives
everything: it checks whether `STATE_MS` (2000ms) has elapsed since the
last `/api/state` poll and if so fetches it, then calls the active tab's
`fastTick()` (a cheap local repaint, e.g. counting up an elapsed-time
column) every beat and its `refresh()` (an actual server fetch) only
once `rateFor(tab)` — an internal helper, not exported on `App` — reads the
per-module refresh-interval setting and says it has elapsed. One shared
heartbeat rather than one
`setInterval` per module avoids several independent timers drifting
against each other while still letting NetPath poll every 2 seconds and
NetFlow's aggregations poll every 30.

`App.modal()` is the one dialog primitive every page uses. It fills
`#modal-box`'s `innerHTML` with a heading and a `<form class="modal-form">`
holding the body, an empty `.modal-error` paragraph and a
`.modal-buttons` row.

Three things about that shape are load-bearing:

* **It is a real form**, and the primary button is its `type="submit"`.
  That is what makes Enter submit a dialog — a form with no submit button
  only submits implicitly when it has exactly one field, and every dialog
  here has more. Before this the whole product had two `<form>` elements,
  both on pages that do not use `App.modal`, and Enter did nothing in any
  of the fifty-odd dialogs. Non-primary buttons are `type="button"` so a
  Cancel or a Copy can never submit by accident, and clicking the primary
  raises `submit`, which is where the handler runs — running it from the
  click as well would run it twice.
* **The button row is found by `.modal-buttons`, not `.row`.** Three
  dialog bodies (netflow.js, and events.js's snmp and syslog settings
  dialogs) lay out checkboxes in a
  `<div class="row">` of their own, and only the accident that all three
  pass `{buttonsTop}` kept the buttons out of them.
* **`runModalAction()` owns every press.** It clears the error slot, calls
  the handler, and — this is the part that was missing — keeps the promise
  the handler returns. It holds the button down while the request is in
  flight, and on rejection renders the reason into `.modal-error` and
  hands the button back. If the handler closed the dialog before it
  failed, the reason goes to `App.toast` instead of nowhere. What it
  replaced was `button.onclick = () => spec.onClick(box, button)`, which
  discarded the promise: twenty-nine async handlers had no error path, and
  a refused Save was indistinguishable from one that worked.

`App.requireFields(box, [[selector, label], …])` is the empty-field half:
it names the empty fields in `.modal-error`, marks them `aria-invalid`
(cleared on the next press) and moves focus to the first. Six dialogs used
to `return` silently instead, and two called native `alert()`.

`App.state.modalLocked` (added for the update-restart dialog) makes the
backdrop-click and Escape-key close handlers no-ops while set, so a
restart in progress can't be dismissed by accident.

`requestCloseModal()` is what Escape and the backdrop call. `closeModal()`
still closes unconditionally and is what a Cancel button uses — an
operator who presses Cancel has said what they want. `requestCloseModal`
asks first when the dialog is dirty, and asks *inside* the dialog (a
`.discard-prompt` appended to the box) rather than in a second dialog over
it: there is one `#modal-box`, so a confirmation opened in it would
destroy the very edits it is asking about. Dirtiness is tracked from the
operator's own `input`/`change` events rather than by diffing a snapshot,
because several dialogs redraw their contents from a poll while open and a
snapshot would call that redraw an unsaved edit.

**Time (4.44.0).** Every timestamp the browser shows goes through one set of
functions in `app.js`, and nothing else formats a `Date`: `App.ago(ts,
empty)` for a relative figure (`just now`, `3.2h ago`, `7.0d ago`, `in 40s`
— the tiers are `App.span`'s), `App.when(ts)` for the absolute form with the
date always present and the year when it is not this one, `App.timeCell(ts)`
for a Time column (the clock alone if the row is from today, the date as well
otherwise, `when()` in the title), `App.agoCell` for a relative figure
carrying its absolute in the title, `App.isoLocal` for an export
(`2026-09-03T14:32:07+02:00`), and `App.timeZoneLabel()` — this browser's
zone, which every Time header's `title` and the Settings page state. The
wire is epoch seconds everywhere; the server formats nothing for the
browser (the `clock` string on `/api/debug` is server-local and feeds the
desktop console only). Seven modules used to carry their own `ago()` in
three behaviours, and the Debug page showed one event stream in three zones.
`tests/test_time_contracts.py` fails on a private `ago()`, a `toLocale*`
call on a `Date`, or `App.clock` in a module.

`_device_json` (`api.py`) derives **`status_since_ts`** — `last_up_ts` is the
last poll that saw the device up and is rewritten on every up poll, so a
device that is up has been up since `last_down_ts` (else `created_ts`), and
the reverse — and **`sys_uptime_s`** from `last_uptime_ticks` aged forward
from `last_uptime_ts`, the pair reboot detection compares. Before this no
script read any of those five fields and the summary said `status up`.

**Nouns.** One per module wherever it is named — strip, toggle, settings
legend, Dashboard (`Workers`, all eight): Nodes and Wireless *poller*,
Alerts *alert engine*, NetFlow and Syslog *collector*, SNMP *receiver*, IPAM
and ConfigRX *worker*. `POST /api/ipam/worker {action}` is the IPAM toggle
the other seven already had, implemented through `Service.apply_settings("ipam",
...)` so it persists like the settings checkbox. The two search handlers name their cap
(`SEARCH_ROW_CAP`) and return `limit`/`cap`/`truncated`; `App.countLabel`
renders "N of M shown" for every list.

`App.tooltip(content, event)` takes either a string — assigned with
`textContent`, which is what every caller that has one still does — or an array
of `{text, color}` rows. Rows are built with `createElement`/`textContent` and
never `innerHTML`, so a hostname or a MIB object name can never become markup on
its way into a tooltip; the only thing that reaches a style is the colour, and
that always comes from a palette constant rather than from data. NetFlow's
`seriesColor(name, index)` is the single source of a series' colour, shared by
the stacked bands, the legend and the tooltip. The subtlety worth knowing:
`slotTip` sorts its rows by volume, so it has to carry each series' *original*
index through the sort — pairing row N with series N after sorting gives every
line the wrong colour, which looks plausible and is wrong.

`App.confirmDestructive(title, bodyHtml, confirmLabel, onConfirm,
afterClose)` is the one confirmation shape — Cancel first, the destructive
verb as the primary button, a body naming the collateral damage. Because
there is only one `#modal-box`, a confirm raised from inside another
dialog *replaces* it; such callers pass `afterClose(confirmed)` to reopen
their parent, and are told whether the action ran so they can reopen on
cancel only rather than rebuilding from data the action just invalidated.

The rule it exists to keep is that `afterClose` runs only *after* the
awaited `onConfirm` resolves. Seven dialogs hand-rolled their own
Cancel/Remove pair on `App.modal` instead, and one of them —
`bulkDeleteDevices` — closed the dialog and then awaited the request, so a
refusal reported the removal of up to forty devices that were all still
there. All seven are now `confirmDestructive`, and
`tests/test_frontend_contracts.py` fails if an eighth appears.

It no longer holds its own try/catch or button juggling: `runModalAction`
above does both for every dialog, so this one stopped being the exception
that got it right.

`closeModal()` dispatches a `modal-closed` window event. Anything a
dialog starts and must stop — a refresh interval, a poll of an install
job — hangs off that rather than off its own Close button, because
Escape and a backdrop click close the modal without that button ever
being pressed. The interface dialog additionally holds a monotonic token
(`view.ifaceDialogSeq`) that every timer tick and every one-shot `.then`
checks before touching the DOM: `App.modal` returns the same singleton
box and each dialog rebuilds the same element ids inside it, so "is my
chart still in the box?" cannot distinguish this dialog's chart from the
next port's — only a token can. That, plus a request-id guard on the
refresh and resolving metric ids from a fresh per-device fetch instead of
the device pane's shared `view.metrics`, is what stopped one port's
traffic being painted into another's.

Panel splitters (`data-splitter` attributes) and table column widths
persist to `localStorage`, keyed by page/table name, independent of
anything server-side — a layout tuned for one screen survives a reload
without needing a server round trip or a per-user setting.

### Lazy module loading (`app.js`, `index.html`) — 4.49.0

Before this release, `index.html` carried thirteen `<script defer>` tags —
`app.js`, `dashboard.js` and the other eleven per-tab modules — all
downloading, parsing and compiling before the Dashboard painted, on every
visit: 1.17 MB uncompressed, roughly 324 KB gzipped, most of it for tabs an
operator may never open. Only `app.js` and `dashboard.js` are still eager
now; Dashboard is what an account lands on and what `start()` still
initialises unconditionally the same way it always has.

Every other module's name is its filename's stem (`nodes` → `nodes.js`), so
nothing new needs to be kept in step. `isLazyModule(name)` is just
`name !== 'dashboard'`. `ensureModuleReady(name)`, called from
`activateTab()` (the one place `selectTab`/`applyRoute` hand off to a
module), is the whole mechanism: a module already marked `__ready` resolves
immediately; otherwise `loadScript()` appends a `<script src="/name.js?v=…">`
element to `<head>` and waits for its `load` event, then calls the module's
own `init()` exactly once and marks it ready. `moduleLoads`, keyed by tab
name, de-duplicates a digit shortcut, a click and a hash route all naming the
same not-yet-loaded tab inside the same second onto one fetch and one
`init()` rather than three. `ASSET_VERSION_QUERY`, captured once from
`document.currentScript.src` at this file's own top-level execution (the only
point that property is valid), makes a lazily inserted `<script>` ask for the
identical `?v=` query a `defer` tag would have, so a lazy module gets the same
immutable-cache behaviour every asset URL already carries.

The one visible sign a script is still in flight is `aria-busy="true"` on
`#page-<name>` — the identical mechanism `.page[aria-busy="true"]::before`
already draws for an ordinary data refresh over 400 ms, rather than a second
loading vocabulary invented just for this. A script that fails to fetch, or
whose `init()` throws, degrades exactly the way a module that failed during
eager startup already degraded before this release: added to `brokenPages`,
its tab hidden, the failure logged once, `updateTabOverflow()`/
`updateTabShortcuts()` recalculated for the tab that just disappeared, and
the operator moved off it automatically if it was the one open. The tab being
hidden is what stops a second attempt — never a silent retry loop.

### Tab bar: flat groups, icon collapse, the overflow fade (`index.html`, `app.css`, `app.js`) — 4.49.0

4.48.0 wrapped the twelve tabs in four `<div class="tab-group" data-label="…">`
wrappers (Now/Inventory/Telemetry/Admin) purely for a CSS `::before` label —
and that wrapping carried two real accessibility defects along with the
label, not merely a style choice later reverted on taste. First,
`role="tablist"`'s children were no longer the twelve `role="tab"` buttons
themselves but four plain `<div>`s each holding some of them, so every
screen reader's computed position for a tab ("tab 3 of 12") came out wrong,
counted against the wrapper's own child position rather than the tablist's.
Second, permissions can hide every tab in one of these groups at once (an
account with no read grant anywhere in Telemetry, say, or every module in a
group failing to start) — and a `<div>` is not itself hidden by any tab
inside it being hidden, so its `::before` label stood alone over empty
space, a heading with nothing under it. Both are defects of the *wrapper
existing at all*, not of which four names it carried, so removing it is
what fixes them rather than any relabelling would.

4.49.0 flattens the tabs back to twelve direct children of `#tabs` — one
`role="tablist"` and twelve `role="tab"` buttons with nothing between them,
which `tests/ui/walk.mjs` asserts by scoping its counts to `#tabs` either
way — with a `.tab.tab--group-start` hairline (`border-left`,
`margin-left`) on the first tab of each group after the first standing in
for the label the wrapper div used to draw with generated content, without
introducing another DOM layer for a hidden tab to end up orphaned inside.
It's written as the compound selector `.tab.tab--group-start` (specificity
0,2,0,0) rather than the bare class alone, because two later breakpoints
(1500px, 360px) redeclare `.tab`'s own padding as a shorthand — a bare
class would lose that specificity fight by source order and the divider
gap would vanish under 1500px.

**The overflow fade moved off `#tabs` itself.** It used to be `#tabs::after`
— an absolutely positioned child of the scrolling container, which put it at
the strip's visible right edge only while the strip was scrolled to rest.
Scrolling `#tabs` dragged the fade along with `scrollLeft`, washing out
whichever tab happened to sit under it while the strip's real right edge
went un-faded. It's drawn on `.tabs-utility` now — `#tabs`'s next sibling,
which never scrolls — as `#tabs.has-overflow + .tabs-utility::before`, with
`right: 100%` of `.tabs-utility` being `#tabs`'s real right edge regardless of
`#tabs`'s own `scrollLeft`. No `z-index` is needed: `.tabs-utility` simply
paints after `#tabs`'s own tabs in source order. `app.js` toggles
`#tabs.has-overflow` on load, on resize and on scroll by comparing
`scrollWidth` to `clientWidth` at both ends, same as before.

`selectTab()` now calls `current.scrollIntoView({inline: 'nearest', block:
'nearest'})` on the tab that just became current, guarded on
`bar.scrollWidth > bar.clientWidth + 1` so it's a no-op on every ordinary
click where the strip doesn't overflow at all — a digit shortcut, a pasted
hash route, Back/Forward, kiosk rotation and the `applyPermissions` fallback
(moving off a tab that just lost read access) could all previously land on a
tab while `#tabs` was scrolled elsewhere, leaving the newly-active tab
off-screen with nothing showing which one was selected.

Below 480px, `#global-search-btn`/`#account-btn`/`#signout` collapse from a
text label to an inline SVG icon: `.icon-toggle .label { display: none }` /
`.icon-toggle .ico { display: block }` under that breakpoint, reversed at
rest. `title`/`aria-label` on each button are unconditional, so the
accessible name never changes — only how much of the bar three buttons cost
changes, freeing room for the tab strip on a narrow viewport instead of
crowding it.

**`gsearchRun()`'s eight lookup groups (MAC, devices, alerts, NetPath
destinations, and — new in 4.49.0 — IPAM hosts, IPAM subnets, syslog
messages, wireless APs) each get their own `try`/`catch` now, not one shared
around the whole function.** The old single `try` carried a comment saying
"a failed lookup just leaves that group out", which the code did not
actually do: an exception thrown by the devices lookup skipped every group
queried after it in source order, not just that one. A working search that
happened to hit a slow or erroring dependency looked identical to a search
that returned nothing at all, which is the point of the fix — a group with
nothing to add (no permission, no match) and a group that failed are both
simply absent from the results, indistinguishable to the operator either way.

### Shared components (`app.js`, `app.css`) — 4.45.0

The rule for the frontend since 4.45.0 is that a module draws nothing it
could have asked `App` for. The pieces and where they came from:

- **Worker status strips and settings dialogs.** `App.strip(prefix, worker,
  opts)` draws a module's `<prefix>-status`/`-dot`/`-toggle`/`-counters`
  fastTick card through the write-only-if-changed guards, and
  `App.wireToggle(buttonId, stateKey, route, after)` is the paired start/stop
  button — together these replace what eight modules each drew by hand.
  `App.form` holds the three settings-field builders (`check`/`number`/
  `text`) and `form.readers(box)` the three value readers, replacing six
  verbatim copies across the module settings dialogs. `App.bulkBar(set,
  barId, labelId)`, `App.selectSub(page, name, opts)` (ARIA-aware subtab
  selection), `App.onRelayout(tab, fn)` (resize handling) and
  `App.filterValues(prefix, keys)` (reading a filter row into a query
  object) each replace one hand-rolled copy per module. `App.watchJob(button,
  opts)`, built on `App.settleButton(button, resting, holdMs)`, drives the
  "queue an action, then poll until it lands" pattern (ConfigRX backups,
  Nodes' MIB installs, upstream-suggestion apply). `App.emptyState(message)`/
  `App.loading()` are the two one-line markup helpers used in place of the
  ad hoc "no data"/"Loading…" strings each module used to write out. SNMP
  Trap and Syslog no longer have their own copies of any of this: `events.js`
  builds both tabs from one `eventsPage(spec)` factory, registered as
  `App.pages.snmp` and `App.pages.syslog`.
- **Surfaces.** One selector list in `app.css` paints every panel-like
  element (`.panel, .card, fieldset, .table-wrap, .canvas.chart, .detail,
  .login-box, .ssh-panel, .modal-box, …`); a second list gives the floating
  ones the larger radius and `--shadow-pop`. `tests/test_design_tokens.py`
  asserts the `background: var(--panel); border: 1px solid var(--hairline)`
  pair appears once, which is what stops a seventh copy appearing. The
  dialog is deliberately the lightest surface (`--panel` over a `--scrim`
  overlay with the deepest shadow): elevation reads as lightness on a dark
  theme, and the old darker box read as a hole.
- **Type in tables.** `table` is set in `--ui`; `td.mono`/`th.mono` opt a
  column back into `--mono`. `grid()` decides per column with the internal
  `isMono(column)` helper (not exported on `App`): an explicit `column.mono`
  wins, otherwise the key is matched against `MONO_KEYS` (ip, mac, oid, port,
  hex, id-like, time-like keys). The class goes on both the header and the
  cell so sort arrows and numbers line up. Hand-built tables (IPAM
  conflicts) add the class themselves.
- **`App.stackedHistogram(svg, host, {buckets, unit, span, onBucket, empty,
  minHeight})`.** One drawing for the Alerts, SNMP and Syslog severity
  histograms: legend for the severities present, gridlines with counts,
  time ticks, swatch tooltip rows via `App.tooltip`, and a transparent hit
  rect per bucket **only when `onBucket` is given** — so a chart without a
  click has no pointer cursor. `SEV_COLOR` (an internal array, not exported
  on `App`) is the one severity→token map. Syslog and SNMP wrap `onBucket`
  in `pinWindow`, which unticks Live,
  reveals `#sl-live`/`#sn-live` ("Return to live") and announces the pin;
  `returnToLive` reverses it.
- **`App.filterBar(tab, {text, selects, apply, clear, clears, onEnter,
  onClear})`.** Wires Enter on text fields, change on selects, the Search
  button and the Clear button. Clear empties each field (unchecks a
  checkbox), calls `syncControls` so the view store forgets the values —
  assigning `.value` fires no event, and without this a reload came back
  filtered by fields that looked empty — then refreshes. Nodes passes
  `onEnter` to set `macSearchPending`, because a MAC lookup may open a
  dialog and must run on a deliberate search only.
- **Empty and busy.** `App.emptyText(svg, w, h, text)` for charts;
  `.detail:empty::before { content: attr(data-empty) }` for detail panes,
  so the placeholder lives in the HTML beside the pane and needs no script;
  `.empty` for rows and blocks. `master()` sets `aria-busy="true"` on the
  page around `await page.refresh()`; `.page::before` is a 2px accent line
  whose opacity transitions in after a 400 ms delay, so a fast refresh never
  flickers and a slow one is visible.
- **Sign-in first-run note.** `GET /api/session` unauthenticated returns
  `{authenticated: false, first_run: bool}`; `_first_run` is a user-count
  and two column reads, never a password check. `login.js` unhides
  `#login-note` and pre-fills the username when it is true.

### Sortable hand-built tables (`App.sortableTable`, `app.js`) — 4.53.0

`App.grid` tables were already sortable; the close to twenty plain
`<table>`s each module built for itself — dialog device lists, the Debug
page's worker tables, Settings' permission grid — were not, and teaching
each one to opt in just means the next hand-built table forgets to.
Instead one pair of listeners delegated on `document` (click, and
Enter/Space on a focused header) makes every plain table with a header
row sortable on its own; `.grid` tables are explicitly skipped since
`App.grid` already handles its own.

`plainHeaderRow(table)` finds the header row in either shape this
codebase's hand-built tables use — a real `<thead>`, or a bare first
`<tr>` of `<th>` cells — and `decoratePlainHeader` marks each cell with
`.sortable`, a caret, `role="columnheader"` and `tabindex="0"` the first
time it sees that exact (post-rebuild) `<th>`, skipping a header with no
visible text or a control inside it (a select-all checkbox, an actions
column). `sniffColumnKind` reads a column's own rendered cell text
(`numeric`/`ip`/`date`/text, by an 80% majority rule) rather than being
told, since a hand-built table has no column metadata to declare a kind
with; blank cells (`''`/`'—'`/`'-'`/`'–'`, this codebase's own "nothing
here" convention) always sort last regardless of direction, and a row
with a `colspan` cell (an empty-state or group-header row) is left
pinned wherever its renderer put it.

The one thing delegation can't give a table that redraws itself with
`table.innerHTML = head; table.appendChild(newBody)` on every refresh
tick is memory of its own sort — the clicked `<th>` is destroyed and
rebuilt moments later. The chosen column and direction are kept instead
as `dataset.sortCol`/`dataset.sortDesc` on the `<table>` element itself,
which `App.el(id)` hands back unchanged across such a rebuild, and a
`MutationObserver` on `document.body` (`watchPlainTables`, started once
at load) reapplies them (`reapplyPlainSort`) whenever a table's header or
body actually changes — the one hook that reaches every renderer without
editing any of them. `sortPlainTable` skips the DOM move when the wanted
order already matches the current one, so `reapplyPlainSort` calling it
on every redraw of an already-sorted table doesn't loop the observer
against its own writes. `App.sortableTable(table)` (decorate + reapply)
is the one public entry a caller needs when it fills and reads back a
table synchronously, before the observer would otherwise reach it —
every other page just waits for the observer.

### Themes, breakpoints, pointer capture and kiosk (`tokens.css`, `boot.js`, `app.js`) — 4.46.0

- **Themes.** `tokens.css` is a base `:root` block (dark, `color-scheme:
  dark`) plus, from 4.54.0, six `:root[data-theme="…"]` blocks — `contrast`,
  `light`, `midnight`, `nord`, `solarized`, `slate` — each redefining every
  surface, text, structure, emphasis, meaning and selection token. Dark is
  the *absence* of the attribute, so a browser that never chose stores
  nothing. The choice lives in `localStorage['sappiwhere.theme']`, per
  browser: `boot.js` reads it and sets `documentElement.dataset.theme`
  before `<body>` parses on all three pages (it is loaded by `login.html`
  and `ssh.html` now and is in `PUBLIC_PATHS`; its tab half returns early
  off the application page); `App.setTheme()` changes it live, a `storage`
  listener follows other tabs, and Settings' Appearance fieldset is the UI.
  `boot.js`'s `THEMES` array and `app.js`'s own copy must list the same
  seven ids — a theme one file rejects that the other stored silently
  reverts to dark on whichever reload hits the disagreeing file first. The
  `--canvas-*` set (route/map canvas chrome — background, hairline, grid,
  text, the status colours) is untouched by all seven, with one exception
  from 4.54.0: `--canvas-vlan-1..16`, below. `tests/test_design_tokens.py`
  parses the file per block and recomputes every pair per theme — light,
  midnight, nord, solarized and slate at ordinary AA, contrast at AAA —
  and requires each theme block to define the full themed set, so a dark
  tone inherited onto a light ground fails instead of vanishing. From
  4.54.0 the same file also enforces two sixteen-entry VLAN palettes, both
  keyed by `vlan_color_index` and both held to the same two checks: each
  hue at least 3:1 against its own ground, and — since a hue nudged
  towards ANY of the other fifteen is as much a bug as one nudged towards
  its neighbour in the rotation — every one of the 120 pairs within a
  palette at least `VLAN_DISTANCE_FLOOR` (10.0) apart in CIE76
  (`lab()`/`delta_e76()`, the test file's own sRGB → CIE L\*a\*b\*
  conversion), not just adjacent-in-rotation pairs. **The two palettes are
  not interchangeable, and treating them as one was a defect two separate
  reviews caught before release, at two different layers.**
  `--canvas-vlan-1..16` is tuned against `--canvas`: a MAPPER trunk strand
  itself (`mapper.js`'s `drawLink`, `var(--canvas-vlan-N)`) draws on
  `#mp-canvas`, whose background is `--canvas` — white in every theme but
  Contrast, the same route-canvas idiom NetPath's own graph already
  established — not `--panel`. `--vlan-1..16` is tuned against `--panel`
  instead. Nine or ten of the sixteen `--vlan-*` hues fall under 3:1
  measured against white (`--vlan-4` lands near 1.5:1), which is what made
  the second palette necessary in the first place rather than reusing the
  first one for both grounds — the first review caught the strand itself
  needing its own copy. **A second review, after that fix had shipped,
  caught that MAPPER's own chrome — the VLAN table's colour swatch and its
  sixteen-swatch colour picker — still read `--vlan-1..16`, the
  `--panel`-tuned palette, rather than the `--canvas-vlan-1..16` a strand
  is actually stroked with:** in Dark, Midnight, Nord and Solarized, not
  one of the sixteen pairs was the same colour, so picking "Colour 1" off
  the swatch showed a hue the map never actually drew for VLAN 1 (Dark:
  swatch `--vlan-1` #DA6C6C, strand `--canvas-vlan-1` #862727). The table
  swatch (`mapper.js`'s `VLAN_COLUMNS`) and the picker
  (`openVlanColorPicker`) both read `--canvas-vlan-N` now, the same value
  the strand is stroked with; `.mp-swatch`'s own CSS border also moved
  from `--hairline` (a 1.3–1.6:1 surface-step divider, not meant to be
  seen on its own) to `--line` (≥3.38:1 against `--panel` in every theme),
  so the swatch still reads as a square even where its `--canvas-vlan-*`
  fill sits close to invisible against `--panel` (worst case, Nord:
  ~1.03:1 fill-on-panel). `--vlan-1..16` is no longer read by any part of
  the interface, though it stays defined and held to the same two checks
  in `test_design_tokens.py`. `--canvas-vlan-1..16` needs its own override
  only under `data-theme="contrast"` (the one theme where `--canvas`
  itself goes dark), reusing the light-on-dark `--vlan-1..16` rotation
  there for the same reason in reverse — the other six themes share one
  definition, since `--canvas` is the identical white for all of them.
  `theme.py` (the console window) stays on the dark values, unchanged by
  any of the six new theme blocks.
- **Breakpoints.** `@media (max-width: 1200px)` makes the fixed widths
  fluid; `(max-width: 900px)` stacks `[data-splitter].cols` and the NetPath
  page (both selectors the row rule uses, since boot.js's first-frame rule
  is heavier). `applyDensity()` toggles `body.narrow` at the same 900 px and
  never applies `compact`/`tiny` in kiosk.
- **Pointer capture.** `wireDivider`, the column grip, `netpath.js`
  `beginPan` and the two brush charts (`netpath.js` timeline, `netflow.js`)
  start on `pointerdown` (`button === 0 && isPrimary`), call
  `setPointerCapture`, and listen for `pointermove`/`pointerup`/
  `pointercancel` on the element itself; no `document`/`window` mouse
  listeners remain, and `touch-action: none` is set on `.divider`,
  `th .grip`, `#route-svg` and `.brush svg`. `wireDivider` reads
  `getComputedStyle(container).flexDirection` when a gesture starts, sets
  `role="separator"`, `tabindex`, `aria-orientation`, `aria-valuenow`, and
  handles Arrow (5 %, Shift 1 %), Home/End and Enter through the same
  `setShare` writer the drag uses; `dividerAria` callbacks refresh the
  orientation on resize. The header's keydown handles Alt+Arrow through
  `resizeColumn`, declared per column outside the sortable branch so both
  the grip block and the keydown see one binding. The grip sits inside its
  own cell (`right: 0`): a sticky `<th>` is a stacking context, so an
  overhang was painted over by the next header. `tests/test_layout_contracts.py`
  pins all of it.
- **Kiosk.** `initKiosk()` reads `?kiosk=1` from `location.search` (the
  hash stays the route; `writeRoute` preserves the search, `login.js` hands
  it back after sign-in and the 302 to `/login` carries it). It sets
  `html[data-kiosk]` (root `font-size: 125%`) and `body.kiosk` (tab strip
  hidden, `#kiosk-bar` shown, larger rows). `drawKioskBar()` runs once a
  second from `master()`: tab name, `App.clock`, the account, any refusal
  note, and `session ends in …` from `maxRemainingMs`. `idleTick` sends
  `{kiosk: true}` every `HEARTBEAT_GAP_MS` when there has been no input;
  `api.post_heartbeat` touches the session only for a plain heartbeat or a
  kiosk one from an account with no `'write'` in `permissions_for()`, and
  otherwise returns `ok: false` with a reason — which is why `server.py`
  skips its pre-dispatch touch for `/api/heartbeat` alone. One refusal is
  final for the page (`kioskHeld = false`). `nodes.js`/`alerts.js`
  `drawStatus` render `App.figures` into the strip in kiosk.
- **Tiles and figures.** `App.tile(title, html, {wide, tone})`,
  `App.figure(value, label, route, {className, title})` and
  `App.figures([...])` emit `.card.tile`, `.figure > .figure-value +
  .figure-label`; `dashboard.js` aliases them.

### The view store (`app.js` `sappiwhere.view`)

What the operator has a page *set to* — the column each table is sorted by,
what is typed in the filter bars, which sub-view is open — is the third
kind of per-browser state, beside the layout (splitters, widths) and the
tab. Until 4.37.0 none of it survived a reload: every filter's "current
value" was the DOM element itself, read at fetch time, and every sort a
`view.*Sort` literal, so a reload gave the markup defaults. One key now
holds it, shape `{user: username, sort: {gridName: {key, descending}},
pages: {page: {controls: {elementId: value}, sub: name}}}`, with the same
private-browsing try/catch every other `localStorage` write carries. Per
browser, never sent to the server. `Reset panel sizes` leaves it alone: it
means "put the furniture back".

Nine of the twelve pages opt in — Nodes, Alerts, Syslog, SNMP Trap,
NetFlow, IPAM, Wireless, ConfigRX and Debug, the ones with filter bars and
sortable grids. Dashboard and Settings have nothing of this kind to keep,
and NetPath deliberately keeps its own per-destination time windows in its
module state rather than in this store, because "what window am I looking
at" there is per destination and not per page.

It is **not** read once at init. The fill functions write to it (a stored
choice the list can no longer offer is dropped, below), `rememberControl`
writes on every keystroke in a filter box, and the fetch path reads it on
every tick that still has a late-filled select — twice a tick on Nodes,
once each on Alerts and ConfigRX. So the parsed store is cached in memory
(`viewCache`): `loadView()` returns the cache, `saveView` writes through it,
and the window `storage` event drops it, which is the browser telling this
tab that *another* tab wrote the key (it does not fire in the tab that
wrote, which is exactly the invalidation rule wanted).

The store also records the username it belongs to (`store.user`, set from
`loadState()`, which `start()` awaits before any module's `init()` runs). A
different operator signing in on the same browser discards the whole store
before anything restores from it, and signing out removes the key: a filter
bar holds the previous operator's own search terms and device names, which
is their work rather than a shared setting, and a NOC workstation gets used
by whoever is on shift.

The write path for sort is one line: `App.grid`'s
header-click handler calls `rememberSort(name, sort)` before `onSort`, so
every grid records its sort under the name it already passes for widths,
and a module opts in by seeding its state field with
`App.recallSort(gridName, fallback)` — twelve grids do, including
`nodes-discovery`. `UNSAVED_SORTS` exempts the OID-browser modal, whose
table is rebuilt over a different device each time it opens. Filters use
`App.restoreControls(page, ids)` at the **end** of each module's `init()`
(the ranges and severity lists are filled by then and nothing has been
fetched, so the first fetch reads the restored values out of the DOM
exactly as it reads the markup defaults) and `App.rememberControls(page,
ids)` at the **start** of it — `input` for text boxes, because `change` only
fires on blur and a reload with the cursor still in the field is the case
this exists for. The start matters: listeners run in registration order, so
registering the store's before the module's own `onchange` is what makes the
store current by the time the refresh those handlers kick off reads it back.
`restoreControls` at the end is safe beside it because assigning a value
from script fires no event at all.

That last point is also why a **Clear** button needs `App.syncControls(page,
ids)`: `nf-clear`, `sl-clear`, `sn-clear` and Debug's All/None set `.value`
or `.checked` directly, so nothing hears them, and the store would keep
exactly the filters the operator has just cleared. Sub-views go through
`App.recallSub(page, fallback, scope)`/`rememberSub`, honoured only while a
button for the stored name is still on the page — validated inside one nav,
the section's first `.subtabs` or the `scope` element's, since Nodes carries
a second nav inside the device pane and a name checked against the whole
page could match the wrong one.

**The late-filled selects.** Seven dropdowns are populated after `init()`
from fetched data (the Nodes profile and device-group filters, the Alerts
rule filter, the ConfigRX vendor filter, the Wireless controller list, the
NetFlow exporter list, the Debug target list). Assigning a stored value to
an empty `<select>` selects nothing, so each fill function falls back to
`App.savedControl(page, id)` when nothing is chosen yet, and — because the
first fetch happens *before* the fill — the fetch path does the same through
`App.controlOrSaved(page, id)`, so a restored dropdown filters the very
first request rather than showing the right label over an unfiltered list
for a tick. `controlOrSaved` hands the element the answer as soon as its
option list exists (more than the one "any" placeholder, for a `<select>`),
and only stands in for it before that: reading `select.value || saved`
instead meant an empty choice was indistinguishable from no answer, so
picking "any" re-sent the id just cleared for one cycle. A stored choice the
list can no longer offer (a deleted rule, a vendor with no devices left) is
dropped from the store by `App.rememberControl` rather than applied, so the
table recovers on the next refresh instead of staying empty behind an
invisible filter. Debug's target list is the exception: it is built
incrementally from the event stream and only ever grows, so a stored
destination the current batch has not mentioned is *appended as an option*
and selected rather than forgotten.

**Deliberately not stored:** the Live/Follow checkboxes on Syslog, Traps,
NetFlow and Debug — "Live off" remembered across a reload is a page that
has silently stopped moving with nothing on screen to say why; which
columns a table shows (an account setting, above); and the widths and
splitters (their own keys).

Because a stored splitter width beats the shipped `data-grow` on every
load, changing a shipped default is invisible to anyone who ever dragged
that divider. `LAYOUT_VERSION` plus `LAYOUT_RESET_ON_UPGRADE` handles
that: on load, if the stored version differs, the named splitters (and
only those) are dropped from the stored layout and the version is
recorded. Version 2 drops `alerts-main`, whose default moved from 60/40
to 70/30. Every other splitter the user has tuned is left alone.

**Which tab is active persists the same way** (`TAB_KEY =
'sappiwhere.tab'`). `selectTab(name)` writes the tab name to
`localStorage` on every switch, wrapped in the same try/catch every other
`localStorage` write in this file uses (private browsing or a full quota
must not break tab switching). `start()` reads it back before its own
first `selectTab()` call, validating the stored name against an actual
`.tab[data-tab="..."]` element in the DOM before trusting it — a build
that renamed or dropped a tab falls back to `'netpath'` rather than
landing on a dead tab.

That `start()`-driven restore alone still flashes NetPath on every
reload, because it runs late: `start()` is called from a `DOMContentLoaded`
listener, which fires only after every `<script src>` tag in `index.html`
has been fetched and executed (over a dozen of them — since 4.43.0
`defer`red, so fetched in parallel and gzipped, but still revalidated
`no-cache` with an `ETag` on every reload), and even then `start()` itself
`await`s `loadState()`
— one more round trip, to `/api/state` — before it reaches
`selectTab()`. The static
markup's own default (`class="tab active"` on the NetPath button,
`class="page active"` on `#page-netpath`) is what paints during that
entire window, on every single reload, regardless of which tab was
actually last open.

A first attempt closed most of that window with a second inline
`<script>` placed at the end of `<body>`, applying the same
`localStorage` lookup and class toggle before the external scripts even
started loading. That narrowed the flash a great deal but didn't remove
it: the script still sat after the *entire* rest of the page's markup —
every `.page` section, well over a thousand lines by now — so on a slow enough
connection the browser could still paint a frame or two of the static
default before the parser physically reached it.

**The actual fix moves the decision into `<head>`, before `<body>` has a
single byte of content to mis-paint in the first place.** A tiny script
there (`boot.js`) sets `document.documentElement.dataset.tab` (defaulting
to `'netpath'` if nothing is stored or `localStorage` throws) — reading
`localStorage` is all it does, and `<html>` already exists the moment any
`<head>` script runs, so this has nothing to wait on. `app.css` — loaded
by the `<link>` just above it, and render-blocking by the same browser
behavior that prevents FOUC generally — carries one `html[data-tab="X"]`
rule per tab, each duplicating what `.tab.active`/`.page.active` already
do (`color`/`border-bottom-color` for the tab button, `display:flex` for
the page, with `#page-netpath` alone getting `flex-direction: row` to
match its `.active` counterpart). The static `active` classes are gone
from `index.html`'s NetPath button and section entirely — there is no
default left to flash, only whichever `html[data-tab]` rule matches. By
the time `<body>` has anything to paint, the attribute the CSS keys off
is already sitting on `<html>`, set in `<head>`, before that paint could
possibly have happened.

It is `<script src="/boot.js">` rather than an inline block, and that is
load-bearing rather than stylistic: `server.py` sends `default-src
'self'`, under which the browser refuses an inline `<script>` outright.
As an inline block this whole anti-flash pass silently never ran — the
console said so on every page load — and the flash it exists to prevent
was back. A plain `<script src>` with no `defer` and no `type="module"`
still blocks parsing at that point in `<head>`, so the ordering the
paragraph above depends on is unchanged; it costs one extra same-origin
request, already in flight alongside `app.css`. Note that *restoring* the
tab was never affected either way — `start()` in `app.js` reads the same
`TAB_KEY` on load regardless — so the symptom was purely a flash of the
default tab, which is exactly why it went unnoticed. Keep `boot.js`'s key
and `'netpath'` fallback in step with `app.js`'s `TAB_KEY` and default.

Any future `<head>` bootstrapping belongs in `boot.js` for the same
reason; an inline `<script>` anywhere in this app is dead code unless the
CSP in `server.py` changes to allow it (which it should not — the point of
`default-src 'self'` is that injected markup cannot execute).

`selectTab(name)` in `app.js` sets the same `dataset.tab` on every call,
not just once — required, not cosmetic: without it, the attribute stays
stuck on whatever the page loaded with, and clicking a different tab
would leave the *old* `html[data-tab]` page and the *newly* `.active` one
both matching a `display:flex` rule at once. With it, the attribute and
the `.active` classes are always updated together in the same function,
so the two mechanisms can never disagree — one governs the first paint,
the other governs everything after, and they hand off exactly once,
silently.

Verified with real screenshots (not computed-style polling, which can
report styles that never actually get painted) captured every 50ms
through an artificially throttled reload — none of them show NetPath.

**A fresh sign-in always opens on Dashboard.** `login.js` writes
`'dashboard'` under the same `'sappiwhere.tab'` key immediately before its
`window.location.href = '/'` on a successful credential check — the two
files share nothing else (login.html "shares the stylesheet and nothing
else" with the rest of the app, so this key name is duplicated as a
literal rather than imported), but agreeing on the key is enough for
`app.js`'s existing restore-on-load logic to pick it up with no
special-casing on that side: a login looks exactly like a reload that
happens to find `'dashboard'` already stored. The "already signed in,
bounce back to /" redirect on the login page itself (`fetch('/api/session')`
finding an existing session) does *not* set this key — that path isn't a
login, just a page that immediately sends an already-authenticated visitor
onward, so whatever tab they had open stays open.

**Dashboard** (`dashboard.js`) is a placeholder module, registered the
same way every other page is (`App.pages.dashboard = { init, refresh }`,
both no-ops) purely so it participates correctly in the tab machinery
above — `selectTab`/`master()`/the reload-restores-tab logic all key off
`pages[name]` existing, so a tab with no module registered would either
throw or silently never refresh. `page-dashboard`'s markup in
`index.html` is static content, no chart or table of its own yet.

## Tests (`tests/`)

The end-to-end suites are plain scripts, standard library only like the rest
of the application, run one per process by `tests/run_all.py`. They are not a
unit-test layer: each one drives a real `NodePoller`, `DiscoveryJob`,
`WirelessPoller` or the whole `Service` + `WebServer` against a **stub SNMP
agent** — a few dozen lines of UDP socket that answers GET/GETNEXT for a
fixed OID table using `snmppoll`/`trapdecode`'s own encoders, so the wire
format under test is the application's own on both ends.

The one rule that makes them repeatable: **a suite owns its stub.**
`_paths.spawn_stub("<script>.py")` picks a free loopback UDP port, starts
`tests/stubs/<script>` as a child process with that port as `argv[1]`, and
returns only after reading the stub's one-line "listening" banner from its
stdout — so the socket is bound before the first request, with no sleep to
guess at. The suite then points the module under test at the port by
patching its port constant (`nodepoll.DEFAULT_SNMP_PORT`,
`nodediscover.DEFAULT_SNMP_PORT`, `fortipoll.SNMP_PORT`) and kills the child
in a `finally` or an `atexit` hook. Two suites (`test_nodepoll_e2e.py`,
`test_nodediscover_e2e.py`) use an in-process `StubAgent` thread instead,
for the cases that need to mutate the agent mid-test (an interface flapping,
a reboot, the agent going dark). Databases go to `tempfile.mkdtemp()`; ports
are never fixed; suites can run in parallel.

Two of the suites encode rules that are easy to mistake for bugs when read
cold. Discovery gets its community list only from the polling profile the
job was started with (`api._discovery_communities_for_group` →
`discovery_communities` override → `nodediscover._candidate_communities`,
"no fallback guess"), so a `DiscoveryJob` started from Python with no
override attempts no SNMP at all. And `NodePoller.promote` leaves a
promoted device's manual name as the IP on purpose and seeds `sys_name`
into the identity instead, so the display name follows the device and a
later rename is never shadowed by a copied sysName.

### Help links (`app.js registerHelp`, `helpLink`, `showHelp`)

A "?" beside a setting is `App.helpLink(key)`: a `<button type="button"
class="help-link" data-help="key">`. One delegated click handler in
`start()` opens `#help`, a second overlay created on first use and kept
above `#modal` (z-index 30 over 20). It is deliberately not a second use of
`App.modal`: there is one modal box, and replacing its content would destroy
the form the operator is reading the help for. Escape peels one layer — the
help if open, else the dialog — and a backdrop click or the Close button
closes the help alone.

Texts live with the feature, not in `app.js`: a module calls
`App.registerHelp({'nodes.profile.ping': {title, html}})` at load, keyed
module-first so two modules cannot collide and a grep finds every use. The
markup rule is that the link goes **outside** the `<label>` it belongs to,
because a click inside a label activates the label's control, and a "?" that
also ticked the checkbox would be worse than no help. The first entries are
the profile editor's Ping and SNMP checkboxes and the device form's matching
selectors, sharing the same two keys.

### The SSH terminal: WebSocket hijack, protocol, sessions (`web/wsock.py`, `sshterm.py`)

**Hijack and framing.** The web server is a `ThreadingHTTPServer` with one
daemon thread per connection, `wbufsize = 0` and a 30 s handler timeout.
It speaks HTTP/1.1 since 4.43.0; the hijack sets `close_connection` so
there is still no keep-alive pipeline to unwind behind a socket it takes
over. That shape makes a WebSocket almost
free: the connection can be taken over after the 101 and held for the life
of the conversation without blocking anything else. A route whose handler
carries `hijack = True` runs after exactly the same cookie → session →
permission tail as every other route — which is why the socket is a route
rather than a special case earlier in the dispatch: an unsigned-in or
unpermitted request is answered 401/403 as ordinary HTTP before anything is
hijacked. Three things then happen in `_route`, in this order, and the order
is the point:

1. **`Origin`.** The upgrade is a GET, so the JSON content-type check that
   is the CSRF gate for every writing route never sees it, and the session
   cookie's `SameSite=Strict` is *site*-scoped: another port on the NMS host
   or a sibling subdomain counts as the same site and its page would carry
   the cookie. So the hijack branch compares `urlparse(Origin).netloc`
   against `Host`, case-insensitively, and answers
   `403 {"error": "Cross-origin WebSocket refused"}` when they differ **or
   when `Origin` is absent** — a browser always sends it on an upgrade. The
   check lives here rather than in `wsock` because it is about who is
   asking, which is this layer's business and not the framing's.
2. **The accept.** `_route` itself calls `wsock.accept(self)`; a handshake
   that is not a valid upgrade raises `wsock.WebSocketError` before a byte
   is written and is answered 400. Only once the 101 is on the wire does
   `_status = 101` (so a refused upgrade is not logged as one), with
   `close_connection = True` so the connection simply ends afterwards.
3. **The handler**, called as `handler(websocket, service, params, *args)` —
   it is handed an established socket and never touches the request handler.

`web/wsock.py` is the framing: the RFC 6455 accept digest, the 101 written by
hand as HTTP/1.1 (a browser rejects a 101 announced as HTTP/1.0, which is
what `protocol_version` would otherwise produce), masked client frames,
fragment reassembly (a list and a running length, joined once — 2 MB of
125-byte fragments is 16,777 of them, and concatenating onto one buffer is
quadratic), ping → pong, the close handshake and unmasked server frames. A
frame — and a reassembled message — may not exceed 2 MB, enforced from the
length field before any payload is read (close 1009); a protocol error
closes 1002. The CSP is `default-src 'self'; style-src 'self'
'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'` — `'self'`
covers the same-origin `ws://`/`wss://` the terminal opens, while the bare
`ws: wss:` scheme-sources it used to carry matched any host at all, and
`frame-ancestors` keeps the terminal and its Trust button out of an iframe.

**One socket, one lock.** After the 101 the `WebSocket` stops using the
handler's `rfile`/`wfile` and talks to `handler.connection` directly,
draining whatever `rfile` had already buffered (a pipelined client) into its
own read buffer first. Everything touching the socket — every read, every
frame written, the close frame — goes through one `_io_lock`, because a
session has two threads on it and under TLS (`WebServer(certfile=…)` wraps
the listening socket) concurrent `SSL_read`/`SSL_write` on one `SSLSocket`
is not something OpenSSL supports: a TLS 1.3 post-handshake message arriving
during a `show tech-support` can end the connection with a record error. The
reader waits for readability **outside** the lock (`READ_SLICE_S = 0.25`)
and then takes it only for a non-blocking read, so the thread that is idle
almost all the time cannot starve the one with output to send. That wait is
`poll()` where the platform has it and a `selectors` object (epoll or kqueue
there, `select` on Windows) where it does not — deliberately *not*
`select.select`, which cannot express a descriptor at or above `FD_SETSIZE`
and, given this process holds thirteen databases with their WAL companions, three
UDP listeners, every poll worker's socket and one descriptor per open HTTP
connection, was reached routinely: past 1,024 the call raised on every pass
and the reader spun, burning a core for an idle terminal. The wait's answer
is not trusted either, since a whole record can already be decoded and
waiting inside the SSL object (an `SSLSocket` whose `pending()` says so skips
the wait altogether, so a decoded keystroke is not held for a slice). Writes take the lock
with `SEND_TIMEOUT_S = 15` on the socket: a browser that stops reading fails
the send, marks the socket closed and releases everything waiting on it, so
`stop()`, the idle watchdog and `SshSessionRegistry.shutdown()` are bounded
rather than parked behind a peer. `close()` sends its frame under the same
lock, then drains the receive buffer (`_drain()`, below) before it shuts
the socket down on *every* call, even one that finds the socket already
marked closed by a failed write — that shutdown is what ends a `recv()`
parked in the other thread.

**The drain exists because Windows resets a connection closed with unread
data, and a reset discards whatever was last written in the other
direction.** `close()`'s own shutdown is deliberate — a half-closed socket
is what unblocks the parked reader above — but a peer that still has
unread bytes sitting in its own send buffer (a client mid-keystroke when
the session cap turns it away, say) means the OS sees data still waiting
to be delivered at the moment the socket closes, and on Windows that
produces an RST rather than an orderly FIN. The RST arrives before the
close frame this same call just wrote, so the close frame — carrying the
one thing that matters here, the code and the sentence explaining the
refusal, "There are already 16 SSH sessions" among them — never reaches
the peer at all; it reads a bare `ConnectionResetError` instead of the
reason it was disconnected. Linux sends a FIN in the same circumstance
and the frame survives, which is why this went unnoticed until it was
chased on Windows specifically. `_drain(rounds=8)` empties the socket's
receive buffer first — non-blocking throughout, `select.select` gating
each read so it never waits on a peer that has gone quiet, and bounded to
eight reads because the point is to empty a buffer, not to keep reading a
peer that is still talking — turning the reset back into an orderly close
on both platforms. It is best-effort (`except (OSError, ValueError,
AttributeError): pass`): every failure inside it ends the same way success
does, with the socket shut down regardless.

**The protocol.** `GET /api/ssh/devices/<id>/socket`, with the session
cookie; no subprotocol. Text frames are JSON control messages, binary frames
are terminal bytes, both ways. The client sends `open` (`cols`/`rows`)
first, then `resize` and keystrokes; `auth` only in answer to
`need-credentials`; `trust` only in answer to a `hostkey changed`. The
server sends `status` (`connecting`, `connected`, `closed`),
`need-credentials` (`none-stored`, `auth-failed`, `decrypt-failed`, with
the username to prefill), `hostkey` (`new` is informational — the key was
stored, and both its fields come from the policy that stored it;
`changed` means the connection was refused and carries both
fingerprints and when the old key was first seen), `error` (connect
failures phrased by `configrx._connect_error_text`, so the legacy
key-exchange guidance is not duplicated), and channel output as binary.
Order on a fresh connection is `status connecting`, then any `hostkey`,
then `status connected`. `resize` is tolerated *before* `open` — the page
measures its terminal as it opens the socket and a notice appearing between
the two changes that measurement, so the size can legitimately arrive first;
the session applies it and goes on waiting for `open`. Close codes: 1000
normal, 4401 not authorised — a `trust` from an account that no longer holds
`ssh` write, and also the liveness watchdog below: signed out, session
expired or deleted, permission revoked — 4408 idle, which also covers a
socket that completed the handshake and then never sent its `open`
(`HANDSHAKE_TIMEOUT_S`), and 4429 too many, which means either session cap or
a request refused because this account has too many recent failed logins
against this device. An unpermitted or cross-origin upgrade never gets a
socket at all; it is an HTTP 403. A frame carrying a reserved opcode, or with
a reserved bit set, fails the connection rather than being reassembled as
terminal data: `wsock._DEFINED_OPS` is the closed set, and anything outside
it raises.

**The session registry and its limits.** `SshSessionRegistry` is built in
`Service.__init__` after the session store and ConfigRX's database, and
ended first in `Service.shutdown()` — before any database closes, because
a session writes its closing device event on the way out. Each session owns
a paramiko client and a shell channel and uses three threads: the request
handler's own thread reads the socket and writes keystrokes into the
channel, a pump thread reads channel output and sends it back, and a small
timer thread is the session's heartbeat. The constants in `sshterm.py` are
the whole policy: `CONNECT_TIMEOUT_S = 10` (ConfigRX's, for the same
reason), `HANDSHAKE_TIMEOUT_S = 15` — how long a socket that has completed
the WebSocket handshake may hold its slot, its thread and its authorisation
without sending `open`, after which it is closed 4408, because a slept laptop
used to keep all four of an account's slots indefinitely —
`IDLE_TIMEOUT_S = 900` measured on *keystrokes* — presence, not the
window being open, the rule `SessionStore.touch` applies to the web session
— `MAX_SESSIONS = 16` across the application and `MAX_SESSIONS_PER_USER = 4`
for one account (past either the socket closes 4429, with a message naming
the cap that was reached; the per-user one is what stops sixteen sockets
from one account locking every other operator out), `MAX_AUTH_ATTEMPTS = 5`
failed logins **per (account, device) pair** with `AUTH_FAILURE_WINDOW_S =
300` — see below — `TOUCH_INTERVAL_S = 30`, `PERMISSION_EVERY_TICKS = 5`,
`SHUTDOWN_BUDGET_S = 3.0` and `SHUTDOWN_GRACE_S = 0.5` — the total, not
per-session, that `SshSessionRegistry.shutdown()` may take, because stopping
a session takes its socket's I/O lock, which its own output pump can be
holding for up to `wsock.SEND_TIMEOUT_S` against a browser that stopped
reading, and sixteen of those in sequence is four minutes of an operator's
Ctrl+C apparently doing nothing while the poller and the databases wait; the
grace is for sockets shut down by force, which takes no lock, to let go of
their slots — and `MAX_OUTPUT_BYTES = 64 * 1024`, the size of one channel
read so a device dumping a huge `show tech-support` streams rather than being
buffered whole. The credential — ConfigRX's, decrypted at connect, or one
typed into the page — lives in a local for the length of the connect and is
dropped in its `finally`; the one case where it is held longer is between a
`hostkey changed` and the operator's answer, so that Trust reconnects
without asking again. Sessions are audited as `ssh` device events (who,
from where; the duration on close; a host key replaced; every refused login
with its attempt number and the SSH username tried; why a shell was closed
as unauthorised) and a NODES event-log line — never a keystroke, never a
credential.

**Liveness: a shell is only as live as the sign-in that opened it.** A
terminal outlives the request that opened it by hours, so being authorised
at the upgrade is not enough. The session keeps the web session token it was
opened with, and the 1 Hz watchdog re-reads `service.sessions.get(token)`
every tick and `permissions_for(app_user)["ssh"]` every fifth (the first is
a dictionary lookup, the second a database read): a sign-out, an expiry, a
deleted account or a revoked permission closes the shell with 4401, a
`status closed` saying which, and an audit line. In the other direction,
keystrokes are presence for the *web* session too — the same rule server.py
applies to a POST — so a binary frame calls `sessions.touch(token)`, at most
once every `TOUCH_INTERVAL_S`, since a shell is a great many keystrokes and
the web session's idle timeout is measured in hours. And every
`AuthenticationException` is counted and audited (`SSH login as <ssh user>
refused (attempt n of 5; requested by <app user> from <ip>)`, never the
password); at `MAX_AUTH_ATTEMPTS` the session says "Too many failed logins"
and closes 4429. **The count is kept per (account, device) pair, not per
socket** — which is the whole point of it. Per socket, five guesses were
followed by closing the window, opening it again and five more, so the page
was still an unthrottled password oracle against every device the
application can reach. Once the cap is spent, a new socket for that pair is
refused *before the device is contacted at all*, until the newest failure has
aged out of `AUTH_FAILURE_WINDOW_S`; a successful login clears the count, so
an operator who fumbled four passwords is not locked out an hour later.

**The `ssh` permission and its backfill.** `permissions.MODULES` gained
`"ssh"`, the only entry with no tab of its own: both terminal routes require
`("ssh", write)`, since there is no read-only half of "open a shell". It is
granted to nobody by default, which is the point of not folding it into
ConfigRX. Because the module is newer than `user_permissions`,
`AppDatabase._backfill_ssh_permission` runs once on open: any account
already holding write on *every other* module is an administrator by any
reading, and the SSH button took the place of one they already had, so it
gets `ssh: write`; everybody else starts with none. The run is recorded in
`meta` (`ssh_permission_backfilled`) whether or not anything was granted,
so an administrator who deliberately takes the permission away is not
handed it back on the next restart. The Settings permission grid renders
from `permissions.MODULES`, so the new column appears on its own.

### SSH host keys (`hostkeys.py`, `configrxdb.ssh_host_keys`)

`netpath/hostkeys.py` owns one table, `ssh_host_keys` in configrx.db, keyed
by `(host, port)`: `key_type`, `key_b64` (paramiko's `get_base64()`, the
wire form a known_hosts line carries), `fingerprint`, `first_seen_ts`,
`last_seen_ts`, `trusted_by`. It is keyed by address rather than by device
id because a host key belongs to the endpoint, not to the Nodes row pointing
at it, and two device rows for one address must not each remember a
different key. It lives in configrx.db because that is where SSH for these
devices already lives, but it is not ConfigRX's alone — the terminal writes
and checks the same rows. `HostKeyStore(configrx_db)` is the whole API:
`prepare(client, host, port)` loads the remembered key into an `SSHClient`
under paramiko's own naming (the bare host on port 22, `[host]:port`
otherwise) so paramiko itself checks the connection; `policy(host, port)`
is the `MissingHostKeyPolicy` for what paramiko finds unknown;
`trust(host, port, key, by)` replaces; `record_seen` touches last-seen;
`forget` removes; `as_changed(exc, host, port)` maps paramiko's own
`BadHostKeyException` to the app's `HostKeyChanged` and passes an
already-mapped one straight back, so a caller catching both types funnels
them through one line. The table is new, so
it ships in SCHEMA with its primary key and no other index — every read is
a `(host, port)` lookup.

**Compared by bytes, never by name.** A host key is identified by
`key.asbytes()` and fingerprinted as OpenSSH does — `SHA256:` plus unpadded
base64 of the SHA-256 of those bytes — so what the app displays can be read
against `ssh-keyscan` or `ssh-keygen -lf` output. Comparing by `get_name()`
would be wrong twice over: an RSA host key negotiates as `rsa-sha2-256` or
`-512` while the key object still calls itself `ssh-rsa`, so the same key
arrives under more than one label; and a genuinely different key of the
same type would compare equal.

**First connection, and a change.** The first time this app reaches a host
on a port, the policy stores the key it was shown and lets the connection
proceed, leaving the fingerprint and type on `policy.stored_new` /
`policy.stored_type` so the caller can say so — and say it about the right
key — network gear rarely carries a stable known_hosts entry anywhere,
and refusing every first connection only teaches operators to click past
warnings. Afterwards a different key raises `HostKeyChanged`, carrying both
fingerprints, the new key's type, when the old key was first seen, and the
new key object itself so a decision to trust it needs no second connection.
Two code paths produce it — paramiko's `BadHostKeyException` when `prepare`
loaded a key and the host presented another, and the policy's own refusal
when a row exists but no key could be loaded — and the policy re-reads the
store rather than trusting that `prepare` ran.

**What ConfigRX does with it.** `_backup_device` calls `prepare` and
installs the store's policy in place of the old accept-everything one. A
changed key fails the backup before anything is sent, with "Host key for
<ip> changed (was SHA256:… first seen <date>, now SHA256:…). Trust it from
the SSH window or forget it in ConfigRX." as the device's error and an
Errors-log event; no capture runs and nothing is stored. The status note
"(host key stored on first connection)" is appended only to the backup that
actually stored a key — the old "(host key not previously known)" was
appended to every backup, because the key was thrown away with the
connection. Reading a stored key is a `configrx` read (it is shown in
ConfigRX's device dialog with a Forget button); forgetting one is a
`configrx` write — forgetting is what lets the next connection accept
whatever it is offered, and configrx write already decides which port and
which credential that connection uses, so it is the permission that
already says which box is trusted; and there is deliberately no HTTP route
for trusting a *new* key — that decision is only taken with the offered key
in hand, over the terminal's own socket, under `ssh` write. Removing a
device from Nodes does **not** forget its key (4.36.1): the key belongs to
the address, a second device row at that address may rely on it, and a
`nodes` write must not be able to reset a trust anchor that `configrx`
write guards. `configrxdb.forget_device` therefore takes only the device
id.

**What the terminal does with it.** The same `prepare` / `policy` /
`connect` sequence, and — from 4.39.0 — the `record_seen(host, port)` that
closes it. A terminal connection that paramiko accepted against the stored
key now touches that row's `last_seen_ts`, so the fingerprint line in
ConfigRX's device dialog reports when the device last presented the key
rather than when it was first stored. Before this the terminal was the one
caller that checked a key and never said it had: an install whose operators
worked entirely from the terminal showed every key as last seen on the day
it was pinned.

**The scoped boundary.** "Only `pager_off` + `show_config` — plus, for a
vendor needing it, one fixed `enable` escalation answered with that
device's own stored secret — are ever sent" remains true and is still the
point of `configrx.py`'s vendor table, but it is now a property of the **backup
path** rather than of the application: the terminal in `sshterm.py` is a
real shell a person types into, behind its own `ssh` permission that
nobody holds by default, and it neither uses the vendor table, the enable
secret, nor `_pull_config` — a person at the terminal who needs privileged
mode types `enable` themselves. The two features share exactly one thing,
the host-key store.

### The SSH window (`static/ssh.html`, `ssh.js`, `ssh.css`)

A standalone page in `login.html`'s shape: it loads `app.css` for the
palette and the shared widgets and nothing else of the application — no
`boot.js`, no `app.js`, no refresh loop, no `App.modal`. It is not in
`PUBLIC_PATHS`, so a signed-out popup gets the same 302 to `/login` every
other page does. `ssh.js` first fetches `GET /api/ssh/devices/<id>` for the
header: 401 sends the window to `/login`, 403 says the account has no SSH
access, a missing paramiko shows its own message, and any other failure is
reported in the status line. Then it opens the WebSocket, built from
`location` so `https` gives `wss:`. Text frames are the JSON control
protocol (below, under `sshterm.py`), binary frames are terminal bytes in
both directions: `open` carries the fitted cols/rows before anything else,
because the server sizes the pty from them and a wrong size there is a
wrapped prompt for the life of the session; a debounced window resize
re-fits and sends `resize` only when the grid actually changed;
`term.onData` sends keystrokes verbatim. The two overlays are the page's
own markup — a credentials form filled from `need-credentials` (the
password field is emptied the moment it has been sent, and the page keeps
it nowhere else) and the host-key warning, which shows both fingerprints
and when the stored key was first seen behind **Trust the new key** and
**Cancel**. `beforeunload` closes the socket, which is the whole client-side
cleanup: the server tears the session down when the socket goes.

### Vendored frontend libraries (`static/vendor/`)

The CSP is `default-src 'self'` and these installs routinely have no route
to the internet, so a CDN is not an option; third-party browser libraries
are checked in as the publisher's own UMD bundle, byte for byte, and served
from `/vendor/` like any other static file — `_static` already resolves
nested paths and types them from the extension. Today that is xterm.js
5.5.0 (`window.Terminal`) and `@xterm/addon-fit` 0.10.0
(`window.FitAddon.FitAddon`), with their MIT licence as `LICENSE-xterm.txt`,
whose header also records the versions and where they came from. There is
no build step and no local patching: a fix applied to a vendored file is
invisible to the next update and would be silently lost, so anything that
needs changing is worked around in first-party code. The same obligation
applies to the twenty-one MIB modules in `netpath/mibs/`, eighteen of which are
other people's work — IETF standards-track modules under the Simplified BSD
terms of BCP 78, IEEE Std 802.1AB, IANA's `IANAifType-MIB` and Net-SNMP's
`UCD-SNMP-MIB` — and their attribution is `netpath/mibs/NOTICE.md`, which is to
the MIB bundle what `LICENSE-xterm.txt` is to xterm.js. Three of those files
carry no copyright block inside the file itself, which is why a notice beside
them was needed rather than optional. Updating one means
dropping in the new release's bundle and editing the version in the README.
xterm injects its own `<style>` at runtime, which the CSP's `style-src
'self' 'unsafe-inline'` already allowed.

### Opening the window, and Remove's new home (`nodes.js`)

`sshDevice()` is the application's only `window.open`. A shell is not a
dialog — it is kept open beside the rest of the product, resized and lived
in — so it gets a window: `window.open('/ssh.html?device=<id>&name=<encoded
display name>', 'ssh-<id>', 'width=1000,height=640,noopener')`. The window
name is keyed to the device, so a second SSH click on the same device
raises the window it already has rather than starting a rival session;
`noopener` keeps the popup from reaching back into the opener. The display
name rides in the query string because `displayName()`'s precedence is
private to `nodes.js`; it only has to hold until the API answers. The
button is `data-requires-write="ssh"` in the markup and `sshDevice()`
re-checks `App.canWrite('ssh')` itself — belt and braces now that
`applyPermissions` disables rather than hides, and still worth keeping
because the check is what stops a keyboard or scripted activation. Single-device removal moved out of the pane header and into the Edit
dialog, beside Clear credential, on `App.confirmDestructive` — the body
names the collateral (interfaces, metric history, events, and the ConfigRX
settings, credential and stored backups that `delete_nodes_device` drops
through `forget_device`); like Clear credential it passes `afterClose` to
reopen the editor when the operator backs out. Bulk Delete is untouched.
