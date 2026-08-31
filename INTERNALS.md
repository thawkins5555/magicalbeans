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

Five SQLite files, each opened with `PRAGMA journal_mode=WAL` and (for
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
| `app.db` | `AppDatabase` (`appdb.py`) | global settings, `users`, `hostnames` (the shared reverse-DNS cache), `asn_cache` (ASN/owner per address, long TTL), a `meta` table for one-off markers like the update-installed commit |
| `netpath.db` | `Database` (`db.py`) | `targets`, `traces`, `hops`, `hop_stats` (cumulative continuous-probe counters per target/hop), NetPath's own settings |
| `flows.db` | `FlowDatabase` (`flowdb.py`) | `flows`, `exporters`, `interfaces`, NetFlow's own settings |
| `syslog.db` | `SyslogDatabase` (`syslogdb.py`) | `logs`, `log_counts` (hourly rollup), the FTS5 index, Syslog's own settings |
| `ipam.db` | `IpamDatabase` (`ipamdb.py`) | `subnets`, `hosts`, `conflicts`, `scans`, `dhcp_servers`, `dhcp_scopes`, `dhcp_leases`, `dhcp_scope_history` (leased-IP trend), IPAM's own settings |
| `nodes.db` | `NodesDatabase` (`nodesdb.py`) | `groups` (polling profiles), `device_groups` (organizational, unrelated to `groups`), `devices`, `interfaces`, `metrics`/`samples`/`samples_hourly`, `device_events`/`interface_events`, `mib_files`/`mib_objects`, `discovery_jobs`/`discovery_results`, Nodes' own settings |
| `alerts.db` | `AlertsDatabase` (`alertsdb.py`) | `rules`, `templates`, `alerts`, `notifications`, `meta` (per-source evaluation cursors), `smtp_credential`, Alerts' own settings |

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
single-device edit already uses — no separate "clear" endpoint. The
frontend's checkbox column is layered onto `App.grid`'s output
(prepending a `<col>`/`<th>`/`<td>` after the grid builds its own
colgroup/thead) rather than added to `App.grid` itself, since
selection isn't sortable or width-persisted the way real columns are.

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
average applied only to raw (non-rollup) series when the Smoothed
checkbox is on (`opts.smooth`, read from `view.chartSmooth`), before
peak/axis computation so the Y scale reflects what's actually plotted.
Window size is `clamp(3, 9, round(n / 20))`, shrinking at the array's
edges rather than reaching past the data. Rollup points (`avg`/`min`/
`max`) are never smoothed — an hourly aggregate is already a form of
smoothing, and averaging an average would misrepresent it. The
interface dialog's own chart call site never passes `opts.smooth`, so
it always renders raw.

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
`::=` token: `_OBJECT_TYPE_RE`/`_OBJECT_ID_RE`/`_NOTIFICATION_RE` find
`NAME (OBJECT-TYPE|OBJECT IDENTIFIER|NOTIFICATION-TYPE) ... ::= { ... }`
without needing to parse anything about the macro body in between.
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

### Bundled default MIBs (`netpath/mibs/`, `Service._seed_default_mibs`)

Two hand-authored files ship under `netpath/mibs/`: `enterprise-roots.mib`
(public IANA Private Enterprise Number arcs for ~20 common vendors,
matching `trapoids.WELL_KNOWN`'s own number-to-name table) and
`if-mib-core.mib` (an OBJECT-TYPE subset of RFC 2863's IF-MIB covering
exactly the columns `nodeoids.IF_TABLE`/`IFX_TABLE` already poll). Both
are original text describing public IANA/IETF facts, not copied vendor
MIB material.

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
setting and saved in the same pass, then `_snmp_settings_with_mibs()` is
re-run so the bundled vendor names reach the SNMP Trap decoder on first
start, exactly as any other upload would.

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

### Host cross-referencing (`api.py get_syslog_search`)

The `host` column stored in `logs` is exactly what `syslogparse.parse()`
found in the message — often empty, or just the sending device's own IP
repeated, since not every device bothers to self-report a real hostname.
Rather than rewrite that stored value, `get_syslog_search` fills the gap
at read time, the same place and the same `resolve_sources` setting gate
already used to resolve the Source column's `source_name`: for every row
whose `host` is falsy or equal to its own `source`, it looks up
`service.nodes_db.device_by_ip(source)` first (using `name` when it
differs from the device's own `ip` — `add_device` seeds `name` to the IP
itself when nothing else is given, so an unrenamed device falls through
to `sys_name` instead of surfacing its own address as a "name"), then
`service.app_db.hostnames()` — the same reverse-DNS cache — as a second
pass over just the IPs still missing a name. A message that already
carries its own real hostname is never touched; this only ever fills
what the device left blank.

---

## IPAM

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

## Web layer

### `web/server.py`

Stdlib-only: `http.server.ThreadingHTTPServer` plus `ssl` when a
certificate is configured. `ROUTES` is a flat list of
`(method, compiled regex, handler)` tuples matched in order; a route's
captured groups (e.g. a numeric ID) are passed as positional arguments to
the handler after `(service, params, body)`. `PUBLIC_PATHS`/`PUBLIC_API`
are the only things reachable without a session — the login page and what
it needs to render, plus `/api/login` and `/api/session` itself (the
latter needed by `waitForRestart()`'s post-restart polling, which by
definition has no valid session yet).

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

Panel splitters (`data-splitter` attributes) and table column widths
persist to `localStorage`, keyed by page/table name, independent of
anything server-side — a layout tuned for one screen survives a reload
without needing a server round trip or a per-user setting.

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
has been fetched and executed (eight of them, each its own blocking
network round trip since `server.py` serves scripts `no-cache` with an
`ETag`), and even then `start()` itself `await`s `loadState()` — a ninth
round trip, to `/api/state` — before it reaches `selectTab()`. The static
markup's own default (`class="tab active"` on the NetPath button,
`class="page active"` on `#page-netpath`) is what paints during that
entire window, on every single reload, regardless of which tab was
actually last open.

A first attempt closed most of that window with a second inline
`<script>` placed at the end of `<body>`, applying the same
`localStorage` lookup and class toggle before the external scripts even
started loading. That narrowed the flash a great deal but didn't remove
it: the script still sat after the *entire* rest of the page's markup —
all seven `.page` sections, hundreds of lines — so on a slow enough
connection the browser could still paint a frame or two of the static
default before the parser physically reached it.

**The actual fix moves the decision into `<head>`, before `<body>` has a
single byte of content to mis-paint in the first place.** A tiny inline
script there sets `document.documentElement.dataset.tab` (defaulting to
`'netpath'` if nothing is stored or `localStorage` throws) — reading
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
