# SappiWhere — Features

What the application does, by module — the overview, deliberately light on
mechanism. For how each of this actually works underneath — which file,
which function, which algorithm — see `INTERNALS.md`. Setup and firewall
rules are in `README.md` and `NETWORK-AND-STORAGE-REQUIREMENTS.md`; the
build history is in `CHANGELOG.md`; exactly how passwords and credentials
are protected is in `CREDENTIAL-SECURITY.md`.

Seven tabs: **Dashboard**, **NetPath**, **NetFlow**, **Syslog**, **IPAM**,
then **Debug** and **Settings**, which stay rightmost so adding a module
never moves them. Dashboard is currently a placeholder — reserved space for
a future cross-module overview, not yet holding anything of its own.

Every sub-panel is resizable. Each page's panels are separated by draggable
dividers, sizes are remembered per splitter across reloads, double-clicking a
divider resets that one, and **Reset panel sizes** on the Settings tab resets
them all. The chrome also tightens automatically below 900 pixels of viewport
height, and again below 700, so a laptop gets a usable layout before anything
is dragged.

**Reloading the page returns to whichever tab was open**, not back to
NetPath — the browser remembers the last tab the same way it remembers
panel sizes and column widths, per browser rather than per account.
**Signing in always opens on Dashboard**, though: a fresh login is a new
visit, not a reload, so it starts from the same place every time rather
than wherever a previous session happened to leave off.

## How it runs

The interface is a browser. The service behind it starts either with a console
window or headless:

```
python -m netpath                      # service console window
python -m netpath --headless           # no window, for a service manager
```

The console is not the interface — it shows whether the server is up, who is
connected and what they requested, and lets you change the port, restart, or
open a browser. Closing it stops the service.

Signing in is required. A fresh install starts with **admin / admin** and
insists on a new password. Accounts are local for now, managed on the Settings
tab; TACACS is the next step.

The server uses only the Python standard library. PySide6 is needed for the
console window and nothing else, so a headless install needs neither it nor a
web framework. TLS is used when `--cert` and `--key` are supplied.

---

## Nodes — SNMP poller and device inventory

A filterable device table with at-a-glance status, and a per-device
drill-down: a zoomable metric chart, an interface table and an event
history. Discovery, polling profiles and vendor MIB upload live on their
own subtabs.

### Devices and polling

- **Polled over SNMP v1, v2c or v3** (noAuthNoPriv/authNoPriv — authPriv
  is rejected at session setup with a clear message, the same deferral
  the SNMP Trap receiver made for inbound decryption: there is no AES/DES
  in the standard library and this app takes no third-party dependency),
  or **ping alone** for a device with SNMP switched off entirely. A
  device's identity (`sysDescr`, `sysName`, vendor), interface table and
  scalar metrics (CPU/memory where UCD-SNMP-MIB or HOST-RESOURCES-MIB is
  present) all come from the same poll.
- **A device inherits its settings from a "polling profile"** (a group) —
  credentials, poll interval, timeout, retries, which of ping/SNMP are
  enabled — and can override any of it individually. One profile,
  `Default`, always exists.
- **The scheduler is shaped like NetPath's own trace `Monitor`**, not
  IPAM's worker: a hot-resizable thread pool, and restart-safe per-device
  due-time seeding from each device's own last poll time, so a restart
  with hundreds of devices configured does not fire all of them at once.
- **Status becomes "down" only after several consecutive failed polls**
  (configurable), not the first one, and a device that was only ever
  ping-reachable is distinguished from one that answered SNMP.
- **Interface counters handle wraparound**: a 32-bit counter that
  decreased is assumed to have wrapped once; a 64-bit counter (ifXTable's
  high-capacity columns, preferred whenever present since a 32-bit octet
  counter on a fast link can wrap more than once between polls) that
  decreased is treated as a reset instead, since a genuine 64-bit wrap
  would take centuries at any realistic speed.
- **A reboot is detected** by comparing a device's reported `sysUpTime`
  against what wall-clock time elapsed since the last poll would predict
  — well outside a clock-skew grace band, and not explained by the
  TimeTicks counter's own ~497-day wraparound.
- **Test** checks ping and SNMP against whatever is currently typed in
  the add/edit form, before it is saved, the same idiom IPAM's DHCP
  server test already uses.

### Discovery

- **Per-device or per-subnet.** A subnet sweep pings every address first
  (reusing IPAM's own sweep code, not a second implementation), then
  attempts an SNMP v1/v2c identity probe — trying each configured
  candidate community — against whichever addresses answered; a
  single-device job always attempts SNMP even without a ping reply, since
  a real device can have ICMP filtered. SNMPv3 is not auto-discovered: it
  needs a username a blind sweep does not have.
- **A subnet sweep refuses anything over the configured address-count
  limit** before sending a single packet, the same guard IPAM's own
  subnet scan uses.
- **Results can be reviewed and selectively promoted** into real devices;
  a result already promoted is a no-op to promote again, not a
  duplicate-IP error. Discovery suggests a polling profile from the
  device's vendor OID root where one matches, falling back to `Default`.

### Vendor MIBs

- **Uploaded and parsed by a hand-rolled, stdlib-only best-effort
  reader** — not a MIB compiler, the same framing the SNMP Trap
  receiver's own OID name table already used. It finds every
  `OBJECT-TYPE`/`OBJECT IDENTIFIER`/`NOTIFICATION-TYPE` clause and
  resolves its OID against whatever this app already knows (its own
  built-in roots, or a previously uploaded MIB's objects) — never by
  fetching an imported module automatically. Uploading a dependent MIB
  before the one defining its parent branch leaves it partially resolved
  until the parent is uploaded and Resolve is run again.
- **Extracted objects can be reviewed and hand-corrected**; an
  admin-edited object survives a later re-resolve of the same file.
- **Resolved names also flow into the SNMP Trap page** — a trap from a
  device an uploaded MIB describes shows a name instead of a raw OID
  there too, without duplicating the name table.

### Drill-down

Selecting a device opens its identity, live status, a metric picker with
a zoomable chart (recent points plotted directly; a wide window reads an
hourly min/avg/max rollup instead of scanning months of raw samples), its
current interface table, and a combined device/interface event history.

---

## Alerts — rule-based alerting and email notification

Evaluates Nodes' device and interface state, incoming SNMP traps, Syslog
messages and IPAM conflicts against a rule table, on the same 0–7
severity scale every other module already uses, opening or incrementing
alerts and optionally emailing about them.

### Rules

- **24 built-in rules** ship enabled: a device not responding, a device
  recovering, a device rebooting, SNMP authentication failing, a device
  needing unsupported SNMPv3 privacy, a poll running longer than its own
  interval, an interface going down/up/flapping, ten CPU/memory/
  interface-utilization/error-and-discard-rate/disk/ping-latency
  thresholds, a critical or cold-start SNMP trap, a linkDown trap from a
  device Nodes is not itself polling, a critical syslog line, and a new
  IPAM address conflict.
- **A built-in rule can be edited** (severity, enabled, which devices it
  applies to by a substring filter, its threshold/clear-threshold/
  consecutive-polls-before-firing where relevant, which template it
  uses) but not deleted — disable it instead. A custom rule can be added
  for anything the built-ins do not cover.
- **Threshold rules use hysteresis**: a `threshold` and a lower
  `clear_threshold`, plus a consecutive-polls-before-firing count, so a
  value oscillating right at the edge does not open and close the same
  alert every poll.
- **Repeated occurrences increment one open alert** rather than opening a
  duplicate — enforced by the database itself (an alert's dedup key can
  only be open or acknowledged once at a time), not by application logic
  that could race.

### Notifications

- **Email over the standard library's `smtplib`** — none, STARTTLS or
  SSL/TLS, with or without certificate verification (turning verification
  off is a deliberate, explicit opt-out, never a silent downgrade). A
  rate limit caps emails per hour; past it, sending is suspended for the
  rest of that hour and logged once, not per suppressed alert.
- **An open alert emails once by default**; a re-notify interval can be
  set to repeat while it stays open. An alert that clears — resolved
  automatically by a matching recovery occurrence, or a threshold
  dropping back below its clear value — can send its own notification,
  using the generic "device recovered" template rather than replaying
  the original problem's wording backwards; this is optional and can be
  turned off.
- **Test sends a real email** to an address typed in, using whatever SMTP
  settings are currently in the form before they are saved — the same
  "test what's typed" idiom as IPAM's DHCP test.

### Templates

- **5 built-in templates**, one each for a device going down, a device
  recovering, a device rebooting, a threshold breach, and a
  forwarded trap/syslog/IPAM event — using a hand-rolled `{{token}}`
  substitution, not a templating library. Each can be freely edited and
  reset to its shipped text; a built-in template cannot be deleted, since
  a rule referencing it would otherwise lose its wording silently. A
  custom template can be added and used by any rule.
- **Preview renders a template** against a real recent alert, or a
  synthetic sample when none exists yet, without sending anything.

---

## NetPath — path monitoring

Runs traceroutes to destinations you add, on a schedule, and keeps every one.

### Destinations

The destination the route graph is currently showing is bold in the list, so it
stays obvious after focus moves to the graph or the timeline. The dot beside
each one carries its latest status.

### Route graph

One column per hop, one box per address seen at that hop. Each box shows the
address, its reverse-DNS name, the average round-trip time and the share of
traces it appeared in.

- **Divergent paths** appear as two or more boxes in the same column. Edge
  thickness is the share of traces that used that link, so the usual route
  reads as a thick spine and detours as thin dashed branches.
- **Silent hops** — runs of consecutive hops that never reply — collapse into a
  single marker showing how many there are. Click to expand, click the tab
  above an expanded run to fold it back.
- **Refusals** are outlined in orange with a `REFUSED !X` badge on the router
  that sent the ICMP unreachable.
- **Zoom** with the `−` and `+` buttons or the scroll wheel, drag to pan, and
  **Fit** to reframe. Wheel zoom is anchored on the pointer, so the hop under
  the cursor stays where it is. The level is shown as a percentage and survives
  refreshes, so live data does not throw you back to fit-all.
- **ASN and owner**, when known, appear in a hop's tooltip beneath its name —
  `AS15169 (GOOGLE, US)` — so you can see which network a route is on and
  where it leaves your own provider.

### Continuous per-hop probing (MTR-style)

A destination can opt in to continuous probing — off by default, from its
Edit dialog — which pings every hop on its current path every few seconds,
independent of the scheduled traceroute above. Where a scheduled trace only
samples the path once per interval, this builds up loss and RTT statistics
between those samples too. A hop's tooltip then carries a second, live line —
probe count, loss %, and min/avg/max RTT — alongside the per-traceroute
numbers. When the path changes, statistics for hops that dropped off it are
cleared rather than carried forward, so a route change is never disguised as
an improvement or a regression on the old path.

This is real, continuous ICMP traffic for as long as it stays on, which is
why it defaults to off — turn it on for the destinations you want to watch
closely, not every one.

### Timeline

Three lanes on one shared time axis, with one block per scheduled poll.

| Lane | Shows |
| --- | --- |
| Round-trip time | Bar per block, scaled to the window's peak |
| Packet loss | Bar per block, fixed 0–100% scale, amber through red |
| Status | Worst verdict in the block |

Blocks are sized by the destination's trace interval, not by pixel width, so a
60-minute window on a destination polled every minute draws 60 blocks and a
dark block means a poll that did not happen. Boundaries snap to a wall-clock
grid, so a block covers the same slice of time as the window moves.

Ticks above the RTT lane mark blocks where the route changed.

Presets run 15 minutes to 30 days. Drag to focus a range, scroll to zoom
(anchored on the cursor), buttons to zoom and pan, right-click to clear.

### Point-in-time snapshots

Click any block and the route graph redraws from that single stored trace —
the route exactly as it was at that moment, not an average. A **Return to
live** button appears. This is the view for "what did the path look like when
the alert fired".

### Status

Only the destination hop decides the verdict. Intermediate routers rate-limit
ICMP routinely, so their loss is not a fault signal.

| Status | Meaning |
| --- | --- |
| Green — healthy | Destination answered within its thresholds |
| Amber — degraded | Answered, but loss or latency crossed a threshold |
| Red — no reply | Nothing came back and nothing said why |
| Orange, hatched — refused | A router answered with an ICMP unreachable |
| Teal, striped — skipped | The slot was lost: the previous trace was still running |
| Violet — probe failed | The trace could not run at all |

*Skipped* is a measurement fault rather than a network one. When a trace takes
longer than the destination's interval, the next run has nowhere to go, and the
block says so along with the arithmetic — how long the running trace has been
going, what the interval is, and the worst case those hop and probe settings
imply. Left as a gap it would read as "the app was not running", which has a
completely different fix.

*No reply* and *refused* are kept apart deliberately: silence tells you
nothing, while a refusal names the router and the reason, and usually points at
an ACL or a routing change.

### Per destination

Interval, max hops, probes per hop, probe timeout, and the latency and loss
thresholds that turn a trace amber. All of it is stated under the route header
— `every 60s · warn above 150 ms or 10% loss · probe 30 hops × 3 at 2s (worst
case 195s)` — and the two warn thresholds are drawn as dashed guides across the
RTT and loss lanes, so a bar crossing the line is visibly the reason the block
below it changed colour. The dialog shows the worst case those
settings imply, which is what an unreachable destination costs a worker.

---

## NetFlow — flow collection

Listens for exported flow records, stores them, and charts them.

- **NetFlow v5, NetFlow v9 and IPFIX** on one UDP socket, version read per
  packet, so a mixed fleet needs no extra configuration.
- **Templates** for v9 and IPFIX are cached per exporter and observation
  domain. Records arriving before their template are counted as *awaiting
  template* rather than silently dropped.
- **Template age** is reported beside the packet age in the collector status,
  because v9 and IPFIX records cannot be decoded until a template arrives and
  exporters resend them only every few minutes. It reads `no template yet` when
  none has been seen.
- **Sampling** is read from the v5 header and from v9/IPFIX options templates,
  with a manual override for exporters that report nothing. Every byte and
  packet figure is multiplied by the rate.
- **Send test packet** sends a valid zero-record NetFlow v5 packet over
  loopback and shows the PowerShell equivalent, so you can prove the socket is
  receiving before blaming the exporter.

### Views

A stacked traffic chart in bits per second, a top-N bar chart, and a flow
record table, all re-sliced together by **Group by**:

application (service port), protocol, source, destination, conversation,
exporter, ingress or egress interface, source or destination AS, or ToS.

**The flow record table sorts and resizes.** Click a column heading to order by
it, click again to reverse. Drag the edge of a heading to widen or narrow the
column; the widths are remembered per browser, and **Reset layout** clears them
along with the pane sizes.

Sorting arranges the records already on screen. The selector above the table —
*Top 250 by volume*, *by packets*, *most recent* — is a different thing: it
decides which 250 of the window the server sends. Ports and volumes sort by
their real value rather than the label, so `HTTPS (443)` lands between 80 and
1024 rather than under H, and `4.0 MB` sorts above `900 B`. Cells with nothing
in them sort to the bottom whichever way the column points.

Filters for source, destination, port, protocol and exporter apply to all three
at once. Clicking a bar filters to it.

### Flow-to-path correlation

A **→ Route** link on a flow record jumps straight to the NetPath route that
traffic actually took, when one was ever traced to that destination —
matched against each destination's real, last-known traced IP, not just its
configured hostname. The link is greyed out rather than hidden when no
destination has ever been traced there, so a flow to an untraced address
still shows the control, just not an active one. Following it switches to
the NetPath tab with that destination selected and the time window centred
on the flow's own timestamp.

### Port names

The application dimension uses the lower of the two port numbers, the usual
heuristic for telling a service port from an ephemeral client port.

Names come from three places, in order: names declared under **Port names** in
the NetFlow settings, a curated table of 188 common and industrial ports
(BACnet, DNP3, OPC-UA, PROFINET, IEC-104, ISO-TSAP, TACACS+, WireGuard and the
rest), and this machine's own services file for anything else registered with
IANA.

Ports that nobody registered — the ones a vendor picked privately — cannot be
identified from here, so declaring them is the only honest option:

```
22609 = NVR (camera recorder)
9000  = Historian
```

Declared names win over everything else.

### Names in the flow table

**Resolve names** on the controls row swaps addresses for their reverse-DNS
names everywhere they appear — the flow table's source and destination columns,
and the chart series and bar labels when grouping by Source, Destination or
Conversation. The address is shown until an answer arrives, and
stays if there is no PTR record; hovering a named cell shows both.

Each address gets four attempts: the system resolver, then a PTR query straight
to a nominated server if **Query server** is set on the Settings tab, then
`nslookup`, then — if none of those found a PTR record — whatever IPAM's DHCP
polling knows the address as, for a device that answers DHCP but was never
given a DNS entry. The fallbacks matter for internal ranges whose reverse zone
the system resolver will not answer for — if nslookup finds a name, so will
this — and the Debug log records which method produced each answer.

Lookups use the same cache and the same threads as NetPath's hop names, since
the reverse DNS setting is global. Only the endpoints carrying the most traffic
in the last hour are queried — a busy exporter sees tens of thousands of
distinct addresses and naming all of them would be wasted work. Nothing is
looked up at all while the checkbox is off.

### Zoom without a wheel

Drag across the chart to zoom into a range, scroll to zoom about the cursor,
or use the `‹ − + ›` buttons. **Follow now** pins the right edge to the
present, and any zoom or pan releases it.

### Storage

Flows live in their own database so a busy exporter does not contend with the
trace scheduler. Retention, a row cap and a file size cap all apply.

---

## SNMP Trap — trap and inform receiver

A receiver, a search, and an hourly histogram, graphically the same shape as
Syslog. Receive-only: there is no SNMP polling (GET/GETBULK) yet, and no
alerting engine ties traps, syslog and future ping/SNMP polling together yet.

### Collection

- **SNMPv1, v2c and v3** over UDP, each individually toggleable. All BER/
  ASN.1 decoding is hand-written — no third-party SNMP or ASN.1 library —
  and never raises past its own decode boundary: a malformed or truncated
  packet is counted and dropped rather than crashing the receiver.
- **v1's Trap-PDU** (enterprise, agent address, generic/specific trap
  numbers) is decoded on its own terms and also mapped onto the same
  snmpTrapOID identity v2c uses, so both versions are one searchable,
  filterable axis rather than two.
- **v3 authentication is verified** — MD5, SHA1, and the SHA-224/256/384/
  512 variants — against a list of configured users, each a `name / SHA /
  password` line. The digest is computed over the whole message with the
  authentication field blanked in place, per RFC 3414. A trap sent
  authPriv is detected and its header decoded, but the encrypted payload
  is not decrypted — decryption needs a block cipher the standard library
  does not provide, and this app takes no third-party dependencies. Such
  traps are stored and flagged as encrypted, not decoded, rather than
  dropped.
- **Every trap gets a severity, 0–7** — the exact scale Syslog uses — via a
  built-in OID-prefix rule table (coldStart, linkDown, bgpEstablished and
  the rest of the common ones) plus an admin-editable override list, so a
  future alerting engine can treat a trap and a syslog line the same way.
- **OID names resolve through a built-in table** of roughly 150 entries
  covering the standard MIBs and about twenty vendor roots, with
  longest-prefix matching so an unrecognized instance under a known table
  still shows a name (`ifDescr.7` rather than a bare OID). This is a name
  table, not a MIB compiler — `.mib`/`.my` files are not parsed. An
  admin-editable `OID = name` list extends it.
- **InformRequests are acknowledged** for v1 and v2c — a reply on the same
  socket the inform arrived on, which keeps this receive-only since it
  answers rather than queries. v3 informs are not acknowledged: doing so
  correctly means acting as the authoritative SNMP engine, which belongs
  with a future poller.
- **Source and community access control**, the same allow-list-or-
  auto-accept shape Syslog uses for sending addresses, plus a separate
  list for v1/v2c communities (which travel in cleartext in the packet,
  so this is a filter, not a secret).
- **Sending addresses can be resolved to names**, through the same cache
  NetPath and Syslog use.
- **Send test trap** sends a real coldStart trap to the receiver's own
  bound port and shows the PowerShell and net-snmp equivalents, the same
  loopback-proof pattern NetFlow and Syslog use.

### Search

Free text across the trap name, OID, community/user, source and every
varbind's text, plus filters for severity (at this level and worse), trap
kind, SNMP version, source IP and OID/name. Traps are rare enough — orders
of magnitude fewer than syslog messages — that a plain indexed scan is fast
without needing Syslog's trigram search index.

### Histogram

Traps per hour for the last 24 hours, stacked by severity, from the same
kind of hourly rollup table Syslog's histogram reads — it does not get
slower as the database fills. Clicking an hour narrows the search to it.

### Detail panel

Every varbind for the selected trap, each with its resolved name, OID,
decoded type and value — including MAC addresses recognized from six-byte
binary strings, TimeTicks rendered as `Xd HH:MM:SS`, and known enums (like
`ifOperStatus`) shown by name rather than as a bare number.

---

## Syslog — message collection

A collector, a search, and an hourly histogram.

### Collection

- **RFC 3164 and RFC 5424** on the same port. Anything matching neither is
  stored anyway with the whole line as its message, rather than dropped.
- **UDP and optionally TCP.** TCP handles both framings in the wild: RFC 6587
  octet counting and plain newline separation.
- **Ports are configurable and UDP and TCP can differ.** 514 is standard for
  both; 601 is the registered port for TCP syslog. Binding below 1024 needs
  administrator or root rights, so 5140 avoids that entirely.
- **Volume control at the door.** A minimum severity and a message length limit
  are applied as messages arrive, before the queue and before anything is
  written — a device stuck in a debug loop costs nothing beyond the parse.
  Filtered messages are counted separately so the filter never looks like loss.
- **Sending addresses can be resolved to names**, through the same cache and
  threads as NetPath's hop names — including, when DNS has nothing, whatever
  IPAM's DHCP polling knows the address as.
- **Send test message** sends one to the collector over loopback and shows the
  PowerShell equivalent, the same as the NetFlow test packet.
- **Hostname**, next to the message count above the table, switches the
  Source column between the resolved name and the raw address — on by
  default. The detail panel for a selected message always shows both.
- **The message table resizes**, the same way NetFlow's flow record table
  does. Drag the edge of a heading to widen or narrow the column; the
  widths are remembered per browser, and **Reset layout** on the Settings
  tab clears them back to defaults.

### Search

Free text across the message, app, hostname **and sending address**, plus
filters for severity (at this level and worse), facility, source IP, hostname
and app. Every search reports how long it took, next to the controls.

**A search matches anywhere, not only at the start of a word.** Typing `face`
finds `interface`; `onsole` finds `console`. Several words must all appear, in
any order and in any field, so `10.20.3.4 down` finds messages from that device
about something going down.

Because the sending address is indexed with the message, an IP typed into the
search box finds messages from that device without having to reach for the
Source IP filter. That filter is still there for narrowing a search that is
already about something else.

Where SQLite has FTS5 with the trigram tokenizer — which nearly every build
since 2020 has — this uses that index. Otherwise it falls back to a scan, and
the status strip says which is in use. Queries of one or two characters always
scan, since a three-character index has nothing to match on below that.

Upgrading an existing install rebuilds the index once, in the background, and
the strip shows the progress. Searching works throughout, by scanning.

**A substring index costs disk.** Indexing every three-character run rather
than every word roughly doubles `syslog.db`: on a sample of 50,000 typical
device messages it grew from 14.6 MB to 26.5 MB. Against a fixed size cap that
means about half as many messages are kept before the oldest are trimmed, so
raise the Syslog database cap if the retention matters more than the search.

### Histogram

Messages per hour for the last 24 hours, stacked by severity so a burst of
errors inside an otherwise busy hour is visible rather than swamped. Clicking
an hour narrows the search to it. Hovering gives the per-severity breakdown.

The counts come from a rollup table maintained as messages arrive, so drawing
this costs 24 rows to read rather than a scan of the message table — it does
not get slower as the database fills.

### A caveat about time

Syslog timestamps come from the sending device. One with a wrong clock will
file its messages at the wrong time, which is worse than useless when
correlating an incident. If messages arrive hours out of place, turn on **Use
arrival time** in the settings.

---

## IPAM — address inventory, conflicts, DHCP visibility

Three views inside one tab, switched locally: Subnets & Hosts, Conflicts, and
DHCP.

### Find

A search box in the IPAM strip answers the direction browsing by subnet
can't: "what's the IP for printer-3rd-floor" or "who is
aa:bb:cc:dd:ee:ff", rather than "what's on 10.20.3.0/24". Type at least two
characters of a hostname, IP address or MAC address and it checks
everything IPAM knows at once — hosts its own sweep discovered, DHCP leases
and reservations, and the shared reverse-DNS cache — and shows every match
in one list with its address, MAC, alive status, subnet and which of those
sources found it. A result outside every subnet configured here isn't a
bug: DHCP polling reads a server's scopes on its own, independent of what
subnets IPAM has been told to sweep, and the source column says so.

### Subnets & Hosts

Add a subnet in CIDR form and it is swept on a schedule: every address gets a
ping, then the local ARP table is read once for whatever answered. A subnet
larger than the configured limit — 1024 addresses by default — is refused
when added rather than silently truncated; narrow it or raise the limit
deliberately if you mean to sweep something that size.

**MAC addresses only appear for subnets on the same network segment as
whichever machine runs SappiWhere.** ARP does not cross a router. A remote
subnet still reports which addresses answered ICMP — that half of monitoring
works anywhere — but without a MAC there is nothing to compare across scans,
so conflict detection is only possible on a directly-attached subnet. This is
a property of ARP, not a limitation of the code.

**Every subnet shows a utilization donut** in the sidebar list — a glance at
alive, previously-seen-but-down, and never-seen, without opening it — and
selecting a subnet shows a larger version of the same chart above its host
table, with the counts and percentages spelled out beside it. An address only
counts as "seen before, now down" if it has genuinely answered at some point
in the past; an address that has been probed on every sweep and never once
replied is "never seen," however many times it's been swept. Hovering a
subnet's sidebar row gives the exact numbers as a tooltip.

The host table sorts and resizes the same way NetFlow's flow record table
does: click a heading to order by it, drag an edge to resize, both remembered
per browser. **Last reply** is when an address last actually answered;
**First probed** is when it first entered the sweep, which is not the same
thing and is worth not confusing — an address swept for weeks without ever
answering has a recent "first probed" and a "Last reply" of *never*.

**Clear stats**, in a subnet's Edit dialog, deletes its discovered hosts and
scan history — the donut resets to entirely "never seen," as if the subnet
had just been added — without touching the subnet's own configuration or its
conflict history, and without the remove-then-re-add round trip that was
previously the only way to start a subnet's inventory over. Refused while a
scan of that subnet is actively running, so it can't race the scan's own
writes.

### Conflicts

Opened one of two ways: the sweep itself sees an address answer as two
different MAC addresses across scans, or a scanned MAC disagrees with what a
polled DHCP server's own lease record most recently said for that address.
Both need a person to look at them — nothing here auto-resolves, because only
a person knows whether it was a NIC swap, a slow-to-expire lease, or something
worth chasing. **Mark resolved** dismisses one; **Show resolved** brings the
history back.

The DHCP cross-check only fires against reasonably fresh lease data — three
times the DHCP poll interval, or an hour, whichever is longer — so a DHCP
server that has not been polled recently does not generate false conflicts
against records nobody would trust anyway.

### DHCP

Read-only. Add a Windows DHCP server by hostname or address and SappiWhere
polls it on a schedule, pulling every scope, every lease and every
reservation through the `DhcpServer` PowerShell module's own `Get-*` cmdlets
— nothing else. There is no write path: nothing in this application can
change a scope, add or remove a reservation, or touch anything on the DHCP
server.

The layout mirrors Subnets & Hosts one level down: pick a server from the
dropdown at the top, and its scopes fill the sidebar — each with a mini
donut of leased (green), reserved (blue) and available (gray) addresses,
sorted by **Least available**, **Most available**, **Name** or **IP
address**, defaulting to least available so the scope closest to running
out is the first thing you see. Selecting one shows a bigger version of the
same donut above its Leases table, filtered to just that scope, with the
counts spelled out alongside the scope's own subnet (from its network
identity, not the narrower dynamic range) and its configured router
address where one is set.

Underneath that, a thin chart tracks the scope's leased-IP count over the
**last 24 hours** or **last 7 days** — one point per DHCP poll, filled area
under a line, with the current count and how much it has moved over the
window spelled out above it. Hovering shows the exact count (and, where
known, the percentage of the scope) at any point along it. This is
separate history from the live figures beside the donut: a poll's usage is
snapshotted every time regardless of whether anything changed, so the
chart still shows a flat line for a quiet scope rather than no data.

**Two ways to authenticate, per server.**

Leave the username and password blank and Windows resolves who's asking: the
account running SappiWhere, if it already has DHCP read rights, or a matching
entry in Windows Credential Manager on this machine (`cmdkey /add:<server>
/user:... /pass:...`, or Control Panel → Credential Manager) if a different
identity is needed. Nothing is stored either way — this is the same call the
DhcpServer module makes for any script run as that account, over the DHCP
server's own RPC endpoint, and needs nothing enabled on the DHCP server beyond
what the role already opens.

Fill in a username and password and SappiWhere stores that credential instead,
encrypted with Windows DPAPI so the stored value only decrypts on this
specific machine — not a portable secret if `ipam.db` is copied elsewhere, and
not readable by SappiWhere itself as plain text once saved. The listing
afterward shows the username and that a credential is stored; the password is
never returned by the API in any form, encrypted or not. This path runs the
same read-only query through PowerShell remoting instead of RPC, which needs
WinRM reachable on the DHCP server rather than SappiWhere's own machine having
the `DhcpServer` module installed — the trade-off going the other way from the
first method. A real DHCP server almost always already has the module, since
it ships with the role.

Storing a credential needs Windows — DPAPI is a Windows-only API — so on any
other platform the credential fields are refused with a message pointing at
Credential Manager instead, which works everywhere PowerShell reaches a DHCP
server regardless of what SappiWhere itself is running on.

**Test connection** on a server checks reachability and reports the DHCP
Server version and scope count without walking every scope's leases, useful
for confirming a new server before waiting on the first full poll — including
an unsaved username and password, to check a credential works before
committing to it. **Poll now** forces an immediate one. **Clear credential**
removes a stored one and reverts that server to ambient identity.

A reservation with no client having claimed it yet has no lease of its own on
the DHCP server, and would otherwise be invisible; SappiWhere synthesizes a
row for it so a configured-but-unused reservation still shows up.

Needs PowerShell with the `DhcpServer` module — part of RSAT: DHCP Server
Tools. For ambient identity or Credential Manager, that's on the machine
running SappiWhere, not necessarily the DHCP server itself. For a stored
credential, it's the other way around: the module needs to be on the DHCP
server, which it almost always already is.

---

## Debug

What the background threads are doing, right now. Nothing here is written to
disk.

- **Trace workers** — one row per destination: tracing, queued, scheduled or
  disabled; live elapsed time for anything running, coloured amber past half
  the timeout budget and red once overdue; last run, duration, next run and
  last verdict.
- **DNS lookups in progress** — one row per address currently out for a
  reverse-DNS lookup, with how long it's been running. Empty most of the time,
  since a name is only looked up once per cache period; a row here that never
  clears is the sign of a resolver actually stuck rather than just quiet.
- **IPAM agents running** — one row per subnet scan or DHCP poll actually in
  flight right now, each labelled with which subnet or server it's working on
  and how long it's taken so far. Distinct from IPAM's own tab, which shows
  the *result* of the last scan; this shows work in progress across every
  subnet and server at once.
- **Event log** — every trace, reverse-DNS lookup, collector, and IPAM event.
  Select one to see its detail: the exact command line, the resolved address,
  the path, the stored trace id and the raw traceroute output as the OS
  printed it.
- Filter by destination, by category (Traceroute, Reverse DNS, NetFlow, IPAM,
  System, Errors) or by free text across both messages and details.
- **Follow**, **Pause**, **Clear** and **Export** — the last writes the
  filtered view to a text file, which is the thing to attach to a ticket.

The status strip summarises pool usage, resolver state, DNS lookups in
progress, collector packet counts, and the IPAM worker's own state.

---

## Settings

Configuration sits at the level it belongs to.

| Where | What |
| --- | --- |
| **Settings** tab | Reverse DNS, ASN/owner lookup, refresh interval, data files and size caps, maintenance |
| **Settings** button, top right of NetPath | Concurrent traces, retention, defaults for new destinations |
| **Settings** button, top right of NetFlow | Listener, sampling, exporters, flow storage and display |
| **Settings** button, top right of Nodes | Poll worker pool, default interval/timeout/retries, down-after-failures, discovery, storage retention |
| **Settings** button, top right of Alerts | Engine on/off, evaluation severity floor, SMTP server and credential, volume limits |
| **Settings** button, top right of Syslog | Listener and ports, volume limits, sources, time handling, retention |
| **Add** / **Edit** on a destination | That destination's own probe settings, and — Edit only — continuous per-hop probing |

The Settings tab holds only what crosses module boundaries. Reverse DNS is the
clearest case: NetPath uses it to name hop addresses and NetFlow to name flow
endpoints. ASN/owner lookup sits beside it for the same reason and can name a
different query server, since a resolver good enough for internal reverse DNS
may not be able to reach the public internet, which the ASN lookup needs.

**Database size caps** — one per database, defaulting to 512 MB for traces,
2 GB for flows, 256 MB for SNMP traps, 1 GB for syslog, 256 MB for IPAM,
1 GB for Nodes and 128 MB for Alerts — are checked every 15 minutes. When
a file is over its cap the oldest records are deleted in chunks until it
fits, so the cap wins over the retention setting. For IPAM that means the
oldest scan history first — subnets, discovered hosts and open conflicts
describe the network as it is now, not a log, so a size cap isn't what
trims those; the day-based retention settings on the IPAM Settings
dialog are. Nodes and Alerts follow the identical split: devices,
polling profiles, interfaces and MIB objects describe the network as it
is configured now and are never trimmed by a cap, only samples/events
(Nodes) and resolved alerts/notifications (Alerts) are.

Nothing needs a restart: both thread pools resize live and the collector
rebinds its socket.

### Software update

One button — **Check for update & restart** — checks
`github.com/thawkins5555/magicalbeans`'s `main` branch for a commit newer
than what's installed. If there is one, it downloads it over plain HTTPS,
swaps it into the running install, and restarts the service so the new
code takes effect immediately; if not, it says so and stops there. The
screen grays out with a status dialog for the duration, since restarting
signs everyone out — sessions are in memory — and it lands you back on the
sign-in page once the service answers again. **Change password**,
elsewhere on this page, is the only other place a full page reload
follows a button press for the same reason: changing your own password
ends every session on that account, this one included.

---

## Data

Eight SQLite files, in WAL mode. One for the application, seven for records.

| File | Holds |
| --- | --- |
| `app.db` | Global settings, user accounts, the shared reverse-DNS cache |
| `netpath.db` | Destinations, traces, per-hop samples, NetPath settings |
| `flows.db` | Flow records, exporters, interface names, NetFlow settings |
| `snmptraps.db` | Traps, an OID name table, SNMP Trap settings |
| `syslog.db` | Messages, hourly rollup counts, search index, Syslog settings |
| `ipam.db` | Subnets, discovered hosts, conflicts, DHCP scopes and leases, IPAM settings, an optional DHCP credential |
| `nodes.db` | Devices, polling profiles, interfaces, metric samples, device/interface events, uploaded MIBs, discovery jobs, Nodes settings, optional SNMPv3 credentials |
| `alerts.db` | Rules, email templates, alerts, notification history, Alerts settings, an optional SMTP credential |

Each record file holds its own module's data and its own module's settings, and
nothing else. Anything read by more than one module — the reverse-DNS settings
and the cache they fill, the web listener, session lifetimes, the size caps —
is in `app.db`.

`app.db` is the one worth backing up: it is small, it does not grow with
traffic, and it is the only file whose contents cannot be rebuilt by collecting
again.

Default location is `%APPDATA%\netpath-monitor\` on Windows and
`~/.local/share/netpath-monitor/` elsewhere; override with `--db`, `--flow-db`,
`--snmp-db`, `--syslog-db`, `--app-db`, `--ipam-db`, `--nodes-db` and
`--alerts-db`. All eight upgrade their schema automatically on launch, and an
install that predates `app.db` moves its settings, accounts and name cache
into it on the first start.

**Data > Export window to CSV** writes the current window's traces.

---

## Deliberate limits

- **sFlow is not supported.** It samples packets rather than exporting flows,
  and is a different protocol.
- **The collector does not backfill.** Nothing is stored while it is stopped.
- **One instance owns each database.** SQLite allows a single writer; two
  copies pointed at the same file on a share will fight.
- **Individual flow packets are not logged.** The Debug page records the first
  packet from each exporter, each template, and decode failures — logging every
  packet would flood the buffer and slow the receive path.
- **Closing the service console stops collection**, leaving gaps in the
  timeline that show as dark blocks. Run `--headless` under a service manager
  for anything that should keep collecting unattended.
- **There are no roles.** Every account has full access, so adding one is an
  administrative act.
- **Sessions do not survive a restart.** They are held in memory deliberately;
  restarting the service signs everyone out.
- **IPAM discovery is ARP-based, so MAC addresses and conflict detection only
  work on a subnet directly attached to the machine running SappiWhere.** ARP
  does not cross a router. A remote subnet still reports which addresses
  answer ICMP; it will never report their MAC addresses.
- **IPAM cannot write to a DHCP server.** No scope, reservation or lease can be
  created, changed or removed from SappiWhere — deliberately, not as a
  not-yet-built feature. It reads scopes and leases and nothing else.
- **IPAM does not do SNMP.** A router's own ARP table, which would extend
  conflict detection to subnets SappiWhere is not directly attached to, is not
  polled. This is the natural next place to extend discovery, not something
  ruled out.
- **A stored DHCP credential is encrypted for one machine.** DPAPI ties it to
  the hardware that saved it; restoring `ipam.db` onto a different machine
  brings the credential's existence back but not its usability, and it needs
  re-entering there. Windows Credential Manager, the other way to authenticate
  a DHCP server, has no such restriction — it is configured per machine
  anyway, not shipped inside the database.
