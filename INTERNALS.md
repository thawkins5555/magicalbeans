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
| `ipam.db` | `IpamDatabase` (`ipamdb.py`) | `subnets`, `hosts`, `conflicts`, `scans`, `dhcp_servers`, `dhcp_scopes`, `dhcp_leases`, IPAM's own settings |

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
