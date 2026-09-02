# SappiWhere — Internals

What `FEATURES.md` describes from the outside, this describes from the
inside: which file does the work, which function, and the actual mechanism
— algorithms, wire formats, schema, threading. `README.md` is setup;
`NETWORK-AND-STORAGE-REQUIREMENTS.md` is ports and files;
`CREDENTIAL-SECURITY.md` is exactly how secrets are protected, in more
depth than the summary here. This is the one to open when something needs
fixing, not just using.

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
  trapdecode.py    SNMP trap BER/ASN.1 decode + encode, v3 USM auth
  trapoids.py      well-known OID names, enum tables, default severities
  snmptrapd.py     SNMP trap UDP listener
  snmptrapdb.py    SNMP trap storage, rollup counts
  namelookup.py    reverse DNS: system resolver, direct PTR query, nslookup
  procs.py         subprocess launch without a console window
  auth.py          password hashing, sessions, login throttling
  eventlog.py      bounded in-memory event buffer
  appdb.py         app.db: global settings, users, shared reverse-DNS cache
  dpapi.py         Windows DPAPI wrapper for the stored DHCP credential
  ipamdb.py        ipam.db: subnets, hosts, conflicts, DHCP scopes/leases
  ipam_scan.py     ping sweep, ARP table read, MAC normalization
  ipam_dhcp.py     PowerShell scripts that query a DHCP server
  ipam_worker.py   IPAM scheduler: subnet scans, DHCP polls, conflict checks
  web/
    service.py     Service: owns every database and background worker
    api.py         JSON endpoint handlers, one function per route
    server.py      HTTP(S) server, routing, sessions, static files
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
`main()` builds a `Service` (`web/service.py`), which opens five SQLite
connections and starts every background worker, then either hands it to a
`WebServer` alone (`--headless`) or to both a `WebServer` and a
`ConsoleWindow` (default). Every module below is a thread or a pool of
threads owned by `Service`; there is no separate process for any collector
or scheduler.

`Service.start()` order matters: `Monitor` (traces) and `Resolver`
(reverse DNS) start first, then the NetFlow `Collector` and
`SyslogCollector` if enabled, then the `IpamWorker`, then a syslog
full-text index backfill kicks off in the background if needed. `Service.
shutdown()` reverses it, draining in-flight traces (`Monitor.drain()`,
up to 3 seconds) before closing any database, since a trace still running
when its database closes raises inside the worker thread and loses the
measurement.

## Data layer

Ten SQLite files, each opened with `PRAGMA journal_mode=WAL` and (for
files with foreign keys) `PRAGMA foreign_keys=ON`. Every `*Database`
class follows the same shape: a `SCHEMA` string of `CREATE TABLE IF NOT
EXISTS` statements run at connect time, followed by a `_migrate()` method
that reads `PRAGMA table_info(<table>)`, diffs the column names against
what the code now expects, and issues `ALTER TABLE ... ADD COLUMN` for
whatever is missing — because `CREATE TABLE IF NOT EXISTS` silently
leaves an existing table alone, an upgraded install needs the new columns
added explicitly or the first write touching them fails. Every write goes
through an `RLock` (`db.py`, `appdb.py`) or plain `Lock`
(`flowdb.py`, `syslogdb.py`, `ipamdb.py`) held for the duration of the
SQL, since `check_same_thread=False` lets any worker thread use the
connection directly.

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

**Size caps** share one algorithm across `Database.trim_to_size()`,
`FlowDatabase.trim_to_size()`, `SyslogDatabase.trim_to_size()` and
`IpamDatabase.trim_to_size()`: while the file is over its cap, delete the
oldest ~15% of the dominant table (traces, flows, syslog messages, DHCP
scan history respectively) in one transaction, `VACUUM`, then
`PRAGMA wal_checkpoint(TRUNCATE)` — VACUUM alone doesn't shrink the file
in WAL mode, since freed pages sit in the write-ahead log until it's
checkpointed and truncated. Capped at 6 iterations so a runaway cap
setting can't loop forever. `Service.run_maintenance()` (`web/service.py`)
calls all four every 15 minutes, plus the day-based retention prunes for
each module, `AppDatabase.prune_hostnames()` for the reverse-DNS cache and
`AppDatabase.prune_asn_cache()` for the ASN/owner cache.

| File | Owner class | Holds |
| --- | --- | --- |
| `app.db` | `AppDatabase` (`appdb.py`) | global settings, `users`, `user_permissions` (per-account per-module read/write grants), `hostnames` (the shared reverse-DNS cache), `asn_cache` (ASN/owner per address, long TTL), a `meta` table for one-off markers like the update-installed commit |
| `netpath.db` | `Database` (`db.py`) | `targets`, `traces`, `hops`, `hop_stats` (cumulative continuous-probe counters per target/hop), NetPath's own settings |
| `flows.db` | `FlowDatabase` (`flowdb.py`) | `flows`, `exporters`, `interfaces`, NetFlow's own settings |
| `syslog.db` | `SyslogDatabase` (`syslogdb.py`) | `logs`, `log_counts` (hourly rollup), the FTS5 index, Syslog's own settings |
| `ipam.db` | `IpamDatabase` (`ipamdb.py`) | `subnets`, `hosts`, `conflicts`, `scans`, `dhcp_servers`, `dhcp_scopes`, `dhcp_leases`, `dhcp_scope_history` (leased-IP trend), IPAM's own settings |
| `nodes.db` | `NodesDatabase` (`nodesdb.py`) | `groups` (polling profiles), `device_groups` (organizational, unrelated to `groups`), `devices`, `interfaces`, `metrics`/`samples`/`samples_hourly`, `device_events`/`interface_events`, `mib_files`/`mib_objects`, `discovery_jobs`/`discovery_results`, Nodes' own settings |
| `alerts.db` | `AlertsDatabase` (`alertsdb.py`) | `rules`, `templates`, `alerts`, `notifications`, `meta` (per-source evaluation cursors), `smtp_credential`, Alerts' own settings |
| `wireless.db` | `WirelessDatabase` (`wirelessdb.py`) | `controllers` (each with its own SNMP credential columns), `access_points`, `radios`, Wireless' own settings |
| `configrx.db` | `ConfigRxDatabase` (`configrxdb.py`) | `device_config` (per-device backup settings and SSH credential, keyed by a Nodes device id with no real FK), `backups` (zlib-compressed, hash-deduped), ConfigRX's own settings |

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
vendor arc in sysObjectID (`trapoids.WELL_KNOWN` at high, the enterprise list
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

**`enterprises.py`** keeps VERIFIED (read from MIB text: every WELL_KNOWN
root plus the catalog arcs checked for 4.32 — 6027, 14179, 47196, 4413, 3375,
17713, 705, 534) apart from CURATED (from memory; the IANA registry is not
reachable from the build environment). `vendor_for` falls back to it after
WELL_KNOWN misses, so `identify_vendor`, `suggest_group` and `browse_bases`
inherit the names; `_arc_confidence` checks the tables directly because
`vendor_for` can no longer tell the two apart. `mibcatalog.Bundle.arcs` and
`vendor_key` join the catalog to the same vocabulary.

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
exact `configrx_vendors.resolve()` dict lookup that "Cisco Systems, Inc."
fails), `nodepoll.read_mac_table`'s `is_cisco` gate, and
`nodeoids.suggest_group` (which reads sysObjectID itself, so it was already
safe). `nodesdb.detected_vendor(row)` is the single place that rule lives,
and it falls back to `vendor` for rows written before the column existed,
where the two were the same value by definition. `vendor_source` —
`sysObjectID` / `sysDescr` / `oid` — was computed on every poll and thrown
away; it is now stored, because an IANA arc assignment and a sysDescr
substring guess are not equally trustworthy and the header used to present
them identically.

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
tuple per device needing v3, kept for the process lifetime — engine
parameters only need refreshing if the target actually reboots or its
clock skews enough to be rejected, which surfaces as a Report-PDU on the
next poll (`_snmp_get` invalidates the cache entry and raises
`_AuthFailure`, causing a fresh discovery next time) rather than a
background expiry timer.

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
module's own settings scope (`/api/settings`, nine scopes), never
`localStorage`, for the reason `wirelessdb.py:95` gives: Reset layout clears
per-browser *widths* and must not eat a settings choice. Sort state is the
opposite — a per-session `view.*Sort` object, deliberately not persisted,
because mixing the two storage models is how that bug happens.

`App.grid` gained a `selectAll: {key, checked, some, onToggle}` option that
renders the checkbox into the named column's header cell, with
`indeterminate` for a partial selection. It lives in `grid` rather than in
each module so there is one implementation and one tri-state rule.
`refreshSelectAll(table, total, selected)` corrects it in place after a
single-row toggle, because `toggleChecked` deliberately does not redraw.

A row can still be simultaneously selected (detail pane) and checked (bulk set);
`tr.bulk-checked` and `tr.selected` (`app.css`) are separate rules for
exactly that reason, and `tr.bulk-checked.selected` gives the combination
its own shade rather than letting one tint win. The checked marker used to
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
hardcoded numeric OIDs throughout (`nodepoll.py`, `nodeoids.py`,
`fortinetoids.py`) and uploaded MIBs only ever supply display names.
Adding Q-BRIDGE and the Cisco path is what changed the coverage.

Returns `None` (not `[]`) when the device answers no forwarding table at
all, which the dialog and the `/mac-table` API route's `"supported"` flag
both key off, so "this device can't tell us" and "this port genuinely has
zero MACs learned right now" render as different messages.

**Vendor identification** (`nodeoids.identify_vendor`): two sources with
different standing, reported separately so a guess is never mistaken for a
fact. `vendor_for()` longest-prefix-matches `trapoids.WELL_KNOWN`, which the
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
`trapoids.WELL_KNOWN` — matched longest-prefix, so an object's own OID matches
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
`vendor_for()` longest-prefix-matches `trapoids.WELL_KNOWN`, which names
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
unauthenticated v1/v2c SNMP identity GET (its own minimal single-shot UDP
helper, not `nodepoll._Session`, to keep this module free of a
module-level dependency on the poller and avoid a real import cycle)
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

The `device`/`subnet` kind still exists internally (it decides "try SNMP
even without a ping reply") but is derived server-side by
`api.py`'s `_discovery_kind_for()` from the target string alone — a bare
address or /32 is a device probe, any other valid CIDR a subnet sweep —
so the UI no longer offers a kind picker. `_candidate_communities()`
lost its `["public"]` fallback: an empty community list (a v3-only
profile) now simply means the sweep runs ping-only, a combination
`post_nodes_discovery` refuses up front unless the job was started with
`allow_ping_only`.

Per-scan timing: the Start-discovery dialog's ping/SNMP timeout and
retry values travel as `discovery_*` keys in the job's own settings
dict (the same override channel the profile's community list already
uses) — they exist only for that job and never touch stored settings.
Ping retries re-sweep only the not-yet-answered addresses;
`_try_snmp`'s default stays one shot per version/community combination
(a retry per guess makes a subnet sweep crawl) with extra attempts only
when this scan asked for them.

Cancel/remove: DELETE on a discovery job cancels it while it is running
(the row stays so partial results remain reviewable) and deletes it —
results cascading via the FK — once it is not, which is also what the
jobs list's Remove button and the cancelled-scan dialog's "Discard scan"
button call. The job's terminal state is decided by the stop flag after
the address loop, not only by the top-of-loop check: a cancel landing
while the final (or only) address was mid-probe used to fall through to
`done`.

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

### MIB parser (`mibparse.py`)

Not a MIB compiler, the same framing `trapoids.py` uses for its own OID
name table. The whole strategy is one regex anchored on the literal
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
finishes the chain without re-parsing anything. `nodes.db`'s `mib_files`
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
Number arcs for ~20 common vendors, matching `trapoids.WELL_KNOWN`'s own
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
identification itself never depends on this: it reads `trapoids.WELL_KNOWN` in
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

24 built-in rules and 5 built-in templates are seeded via `INSERT OR
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
set, with `resolved_by = "destination no longer traced"`, and sends no clear
email — nobody needs telling that a destination they just turned off stopped
being measured.

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
in.** Both `_evaluate_thresholds` and `_evaluate_netpath_thresholds` keep
`first_breach_ts` in their streak state (the NetPath streak gained it for
this), and once per tick the engine loads
`AlertsDatabase.operator_resolved_since(cutoff)` — `dedup_key → latest
resolved_ts` over resolved rows whose `resolved_by` is neither `''` nor
`'engine'`, within `OPERATOR_RESOLVE_WINDOW_S` (seven days), served by
`ix_alerts_dedup_state (dedup_key, state, resolved_ts)`. A breach whose
`first_breach_ts` is at or before that timestamp is the run the operator
already closed and produces no occurrence. A clear observation resets
`first_breach_ts`, so the next breach is a new run and opens normally.
Every resolve a person makes goes through the API with a session username,
so "non-empty and not `engine`" is exactly "resolved by hand".

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
its `entity_label` through `hostresolve.resolve_name()` (see Syslog's
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
means.

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

Two threads, deliberately: `_receive()` does nothing but
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

### Decoding (`trapdecode.py`, `trapoids.py`)

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

`trapoids.py` is a name table, not a MIB compiler — parsing SMIv1/SMIv2
ASN.1 modules is a substantial parser project of its own and out of scope
for a stdlib-only app. `Decoder.resolve_oid()` does exact-match first,
then walks the OID's arcs looking for the longest known *prefix* so an
unrecognized instance under a known table entry still resolves
(`ifDescr.7` for `1.3.6.1.2.1.2.2.1.2.7`). `Decoder.severity_for()` does
the same longest-prefix-wins search over `severity_rules`, which starts
from `trapoids.DEFAULT_SEVERITY_RULES` and is re-sorted by `-len(prefix)`
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

Same rx/tx split as NetFlow's and Syslog's collectors, UDP only — SNMP has
no TCP transport in practice. `_accepted_source()` gates before decoding
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

### Listener (`syslogd.py`)

Same rx/tx split as NetFlow's collector, and the same reasoning: a device
misbehaving can produce thousands of lines a second, so the receive path
only reads, parses and enqueues. TCP is handled by `_read_stream()`,
which reassembles a byte stream into messages under either framing in
use in the wild: RFC 6587 octet-counting (`"123 <13>..."` — a decimal
length, a space, then exactly that many bytes) is detected by checking
whether the text before the first space is all-digits and no longer than
10 characters; otherwise it falls back to newline-separated framing,
which is what most devices actually send regardless of what the RFC
says. A buffer that grows past 1 MB with no newline in sight is dropped
rather than retained forever, against a device stuck writing garbage.

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

### Host cross-referencing (`hostresolve.py`, `api.py get_syslog_search`)

The `host` column stored in `logs` is exactly what `syslogparse.parse()`
found in the message — often empty, or just the sending device's own IP
repeated, since not every device bothers to self-report a real hostname.
Rather than rewrite that stored value, `get_syslog_search` fills the gap
at read time: for every row whose `host` is falsy or equal to its own
`source`, it calls `hostresolve.resolve_name(nodes_db, app_db, ip)`. A
message that already carries its own real hostname is never touched;
this only ever fills what the device left blank.

`hostresolve.resolve_name()` is a small shared module (not folded into
`nodesdb.py` or `appdb.py`, to avoid making either database module
depend on the other) used by both this and Alerts' `entity_label`
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
`normalize_mac()` handles the three formats those commands actually
print: colon-separated, dash-separated with zero-padded octets
(Windows), and Cisco's unpadded dotted-quad-of-hex form.

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

One entry point, `apply(app_db)`, called from `POST /api/update`
(`web/api.py`'s `post_update`). Never raises — every failure comes back
as `{"ok": False, "error": ...}` so the Settings page can show it rather
than crash the request.

1. **Check**: `latest_commit()` asks GitHub's REST API
   (`api.github.com/repos/thawkins5555/magicalbeans/commits/main`) for the
   branch tip's SHA, message and date. Compared against
   `app_db.meta("update_installed_commit")` (a generic key/value marker
   table in `app.db`, unrelated to any setting); an exact match returns
   `{"ok": True, "up_to_date": True, ...}` immediately, no download.
2. **Download**: the tarball for that exact commit (not just the branch
   name, to avoid a race if something else pushes between the check and
   the download) comes from `codeload.github.com/.../tar.gz/<sha>` via
   plain `urllib.request` — no external HTTP library. TLS verification
   uses the system's trust store *and* a vendored copy of Mozilla's CA
   bundle (`netpath/cacert.pem`, the same one `pip`/`certifi` ship,
   loaded in addition to — not instead of — the system store by
   `_ssl_context()`), because a locked-down Windows server can be
   missing a root certificate with no route to fetch it on demand, and a
   headless install has no pip-installed `certifi` to lean on.
3. **Extract**: `_safe_extract()` only ever extracts ordinary files and
   directories, never symlinks or device nodes, and verifies every
   member's resolved path stays inside the destination directory before
   extracting anything — defense in depth against a corrupted or
   tampered archive, not something the real repository needs but cheap
   to have.
4. **Validate**: the extracted tree must contain `netpath/__init__.py`
   and `netpath/web/__init__.py`, or the whole thing is refused before
   touching anything already installed.
5. **Swap** (`_swap_in()`): any existing `netpath.bak-*` directory is
   removed first (so exactly one backup ever exists), the currently
   running `netpath/` package directory is renamed to
   `netpath.bak-<timestamp>`, and the newly extracted one is moved into
   its place. If the move fails partway, the backup is renamed straight
   back — the app is never left with no `netpath/` package directory at
   all.
6. **Restart** (`schedule_restart()`): a delayed background thread (1.5s,
   so the HTTP response for the triggering request has time to reach the
   browser) that calls a platform-specific restart function.

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

**`/api/state` is the one deliberate exception** to "a route either
passes or is refused outright." It's an omnibus endpoint every open tab
polls regardless of which module it's actually looking at — Dashboard,
which is always visible, depends on it — so blocking it for anyone
without a specific module's access would break Dashboard for everyone
but a full admin. Instead `api.get_state()` always succeeds and its
`_STATE_MODULE_KEYS` mapping strips the module-specific top-level keys
(e.g. `nodes_settings`/`nodes` for Nodes, `wireless_settings`/`wireless`
for Wireless) the requesting account can't read, after building the full
response — a filter on the way out, not a gate on the way in.

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

## Wireless (`fortinetoids.py`, `wirelessdb.py`, `fortipoll.py`)

**OIDs** (`fortinetoids.py`) are hand-listed constants, not parsed from
a MIB at runtime — the same "not a MIB compiler" convention `trapoids.py`
and `nodeoids.py` already use for other fixed, known vendor tables (see
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
above `fortinetoids.MAX_PLAUSIBLE_DBM` (30 dBm = 1 W, already above every
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
"anything that is not online". `fortinetoids.CONNECTION_STATE` also contains
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

### Per-AP response time (`fortipoll.py`, `fortinetoids.py`)

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

## ConfigRX (`configrxdb.py`, `configrx.py`, `configrx_vendors.py`)

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
by `vendor.show_config` — both sourced from `configrx_vendors.VENDORS`,
a hardcoded dict, never from anything the API or UI accepts as free
text. A device's `vendor_override` field is free text, but it only ever
selects *which* vendor's fixed commands to use (`configrx_vendors.
resolve()` does a dict lookup); an unrecognized value simply fails to
resolve and the backup is skipped with a clear error, never used as
literal command text. There is no exec-command endpoint, no command
parameter anywhere in `api.py`'s ConfigRX handlers, and no free-form
input field anywhere in `configrx.js` — grep for `channel.send` in
`configrx.py` to confirm this hasn't grown a second call site.

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
attempt finishes, success or failure. `_AcceptAndRecordPolicy` (a
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

**Device naming** (`_configrx_device_json`) matches `nodes.js`'s own
`displayName()` precedence exactly: `sys_name` (SNMP hostname) unless
`display_name_source == 'manual'`, then the stored manual `name`, then
`ip` — previously it preferred the manual `name` first regardless of
`display_name_source`, so a device Nodes had never been told to pin to a
manual name showed a stale/blank one here instead of its live SNMP
hostname.

**One owner per `.hidden`.** `applyPermissions()` in `app.js` originally
wrote `el.hidden = !canWrite(...)` — bidirectionally — on every
`[data-requires-write]` element, so for an account *with* write access it
un-hid the ConfigRX bulk bar on every `loadState()` while `drawBulkBar()`
hid it again from the selection count: "Set SSH credential" flickered in
and out with the page shifting under it. It now only ever *hides* (the
page reloads on login, so there is nothing it needs to un-hide; a grant
mid-session waits for the next reload). Two conventions still stand:
`data-requires-write` goes on the buttons, not on a container something
else shows and hides (a read-only account's one-shot hide would otherwise
stick to a bar the selection should later show), and feature code that
dynamically shows a write-gated control — the wireless AP action buttons —
checks `canWrite` itself, since a hide applied once at load can't gate a
later show.

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
and `no-cache` plus an `ETag` (`mtime-size`) for everything else, so a
reload after an update picks up new scripts via a 304 fast path once the
browser has re-validated.

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
once `App.rateFor(tab)` — read from the per-module refresh-interval
setting — has elapsed. One shared heartbeat rather than one
`setInterval` per module avoids several independent timers drifting
against each other while still letting NetPath poll every 2 seconds and
NetFlow's aggregations poll every 30.

`App.modal()` is the one dialog primitive every page uses — it fills
`#modal-box`'s `innerHTML` and appends a row of buttons, each wired to
call the caller's `onClick(box, button)`. `App.state.modalLocked` (added
for the update-restart dialog) makes the backdrop-click and Escape-key
close handlers no-ops while set, so a restart in progress can't be
dismissed by accident — every other modal in the app ignores the second
`button` argument and the lock entirely, so this was additive rather than
a rewrite.

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
afterClose)` is the one confirmation shape, matching the eight
hand-written confirms that already existed — Cancel first, the
destructive verb as the primary button, a body naming the collateral
damage. Because there is only one `#modal-box`, a confirm raised from
inside another dialog *replaces* it; such callers pass `afterClose
(confirmed)` to reopen their parent, and are told whether the action ran
so they can reopen on cancel only rather than rebuilding from data the
action just invalidated. The primary button disables itself for the
duration so a slow delete cannot run twice.

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
has been fetched and executed (over a dozen of them, each its own
blocking network round trip since `server.py` serves scripts `no-cache`
with an `ETag`), and even then `start()` itself `await`s `loadState()`
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
`BadHostKeyException` to the app's `HostKeyChanged`. The table is new, so
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
proceed, leaving the fingerprint on `policy.stored_new` so the caller can
say so — network gear rarely carries a stable known_hosts entry anywhere,
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
ConfigRX's device dialog with a Forget button); forgetting one is an `ssh`
write, since forgetting is what lets the next connection accept whatever it
is offered; and there is deliberately no HTTP route for trusting a *new*
key — that decision is only taken with the offered key in hand, over the
terminal's own socket. Removing a device from Nodes forgets its key.

**The scoped boundary.** "Only `pager_off` + `show_config` are ever sent"
remains true and is still the point of `configrx_vendors.py`, but it is now
a property of the **backup path** rather than of the application: the
terminal in `sshterm.py` is a real shell a person types into, behind its
own `ssh` permission that nobody holds by default, and it neither uses the
vendor table nor reaches `_pull_config`. The two features share exactly one
thing, the host-key store.

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
(`window.FitAddon.FitAddon`), with their MIT licence as `LICENSE-xterm.txt`
and `README.txt` recording the versions and where they came from. There is
no build step and no local patching: a fix applied to a vendored file is
invisible to the next update and would be silently lost, so anything that
needs changing is worked around in first-party code. Updating one means
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
re-checks `App.canWrite('ssh')` itself, since `applyPermissions` only ever
hides. Single-device removal moved out of the pane header and into the Edit
dialog, beside Clear credential, on `App.confirmDestructive` — the body
names the collateral (interfaces, metric history, events, and the ConfigRX
settings, credential and stored backups that `delete_nodes_device` drops
through `forget_device`); like Clear credential it passes `afterClose` to
reopen the editor when the operator backs out. Bulk Delete is untouched.
