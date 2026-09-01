# SappiWhere — Features

What the application does, by module — the overview, deliberately light on
mechanism. For how each of this actually works underneath — which file,
which function, which algorithm — see `INTERNALS.md`. Setup and firewall
rules are in `README.md` and `NETWORK-AND-STORAGE-REQUIREMENTS.md`; the
build history is in `CHANGELOG.md`; exactly how passwords and credentials
are protected is in `CREDENTIAL-SECURITY.md`.

**Dashboard**, **Nodes**, **Alerts**, **NetPath**, **NetFlow**, **SNMP
Trap**, **Syslog**, **IPAM**, **Wireless**, **ConfigRX**, then **Debug**
and **Settings**, which stay rightmost so adding a module never moves
them. Dashboard aggregates a summary of whatever other modules the
signed-in account can read — see Permissions, under Settings — rather
than being its own tab with data of its own. A tab the signed-in account
has no read access to is hidden from the tab bar entirely.

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
  enabled, how many ping probes to send and how long to wait for them,
  and whether SNMP failing on its own counts as down — and can override
  any of it individually. One profile, `Default`, always exists.
- **Every SNMP-polled device is pinged as well**, several probes per poll
  rather than one, so packet loss to the device is measurable at all — a
  single probe can only ever report 0% or 100%. Probe count (3 by
  default), timeout (1000 ms) and how often to ping (with every poll, by
  default) are set in Nodes settings and overridable per device and per
  profile. The results are recorded as ordinary metrics,
  `ping_loss_pct` and `ping_rtt_ms`, so they chart and so the built-in
  "Packet loss to device high" and "Ping response time high" alert rules
  have something to read. Round-trip time comes from ping's own reported
  figure, not from timing the subprocess, which counted process startup
  as network latency.
- **A device is DOWN only when ping and SNMP have both failed.** A switch
  that still answers ICMP but whose community string is wrong is
  reachable and misconfigured, not down, and reporting it as an outage
  hides the SNMP error that is the actual problem — so it stays UP with
  its error displayed. A device with SNMP switched off entirely is
  unaffected (ping alone has always decided there), as is one with ping
  switched off (SNMP alone decides). If you would rather treat SNMP
  failing as down on its own, the setting is in Nodes settings and can be
  overridden per device and per profile. Either way, the "consecutive
  failures before down" grace window is unchanged.
- **The displayed name prefers the SNMP hostname** (`sysName`), falling
  back to the manually entered name, then the IP — so a discovered device
  names itself. Each device's Edit form has a "Displayed name" choice
  (Auto, or pin the manual name), letting a hand-picked label win where
  wanted; the manual name can be added or changed at any time.
- **A profile can hold more than one SNMP credential**, of the same
  version or different ones — useful when one profile covers a mix of
  vendors or SNMP versions on the same subnet. Its own version/community/
  v3 fields are the "primary" credential, always tried first; any
  additional ones added under ADDITIONAL CREDENTIALS in the profile's
  Edit dialog are tried after it, in the order they were added, for any
  device that doesn't answer the primary. Whichever credential answers is
  remembered per device, so a poll only pays for trying several
  credentials on a device's first poll (or after its working one stops
  answering), not on every poll after that. A device with its own
  credential override still uses exactly that one, unchanged — the
  profile's list only comes into play for a device relying on the
  profile.
- **A profile can be deleted as long as no device currently uses it** —
  including the default profile. Deleting an in-use profile is refused
  with a message naming how many devices still reference it; deleting the
  default profile (once unused) promotes the next remaining profile
  automatically. Any profile can be made the default from a "Set default"
  button on the Profiles tab.
- **Devices can be organized into groups**, independent of which polling
  profile they use — purely organizational, a device belongs to at most
  one group at a time (or none). Groups are managed from a small dialog
  next to the Devices filter bar; removing a group leaves its devices
  ungrouped rather than erroring.
- **Devices can be selected and operated on in bulk.** Ctrl/Cmd-click a
  row to add or remove it from the selection (a plain click still opens
  its detail pane, unchanged), or use **Select all**; either reveals a
  bulk actions bar: Set profile, Set group, Remove from group, and
  Delete — each applied to every selected device in one request rather
  than one per device.
- **A "Only offline" checkbox** on the Devices filter bar shows devices
  whose status isn't `up` (down, unknown, unsupported, or auth-failed) —
  combinable with the Profile/Group/Status filters alongside it.
- **The scheduler is shaped like NetPath's own trace `Monitor`**, not
  IPAM's worker: a hot-resizable thread pool, and restart-safe per-device
  due-time seeding from each device's own last poll time, so a restart
  with hundreds of devices configured does not fire all of them at once.
- **The selected device polls fast while you watch it** — selecting a
  device drops its SNMP poll cadence to a configurable few seconds
  (Nodes → Settings, "Selected-device poll interval"; default 3 s, 0
  disables) so the drill-down moves live; the profile interval resumes
  on its own moments after the device is deselected or the tab is left.
- **Status becomes "down" only after several consecutive failed polls**
  (configurable), not the first one, and a device that was only ever
  ping-reachable is distinguished from one that answered SNMP.
- **A manually added device is polled immediately on save**, rather than
  waiting for its next scheduled turn — and its very first poll ever
  never fires a "Device recovered" alert on its own, since it was never
  confirmed down in the first place. A genuine down→up transition on an
  already-known device still alerts normally.
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

- **The target decides the scope — there is no device/subnet picker.** A
  bare IP or a /32 probes that one device (attempting SNMP even without a
  ping reply, since a real device can have ICMP filtered); any other CIDR
  sweeps the subnet: a ping pass first (reusing IPAM's own sweep code,
  not a second implementation), then an SNMP v1/v2c identity probe
  against whichever addresses answered. SNMPv3 is not auto-discovered:
  it needs a username a blind sweep does not have.
- **A polling profile is chosen before a scan runs, not typed communities.**
  Discovery's form offers a dropdown of every existing polling profile;
  every SNMP v1/v2c community that profile knows — its primary community
  plus any additional credentials — is tried during the probe, the same
  set a device on that profile would try when polling. A profile with no
  v1/v2c community at all is refused up front (unless ping-only devices
  are allowed, below) rather than silently guessing "public".
- **A subnet sweep refuses anything over the configured address-count
  limit** before sending a single packet, the same guard IPAM's own
  subnet scan uses.
- **Each scan sets its own timing.** Starting a scan opens a small dialog
  for ping/SNMP timeouts and retries, pre-filled from the module
  defaults — the values apply to that one sweep only. Extra ping passes
  revisit only the addresses that haven't answered; SNMP retries re-attempt
  each credential.
- **A finished scan ends in an approve/deny dialog** — every discovered
  device listed with a checkbox, SNMP-identified ones pre-checked, and
  nothing added until "Add approved" is clicked. Dismissing adds nothing,
  and either answer is final for that scan's dialog (the RESULTS pane
  remains for promoting later, with the same defaults). Devices that only
  answered ping are excluded unless the scan was started with the
  "Also offer ping-only devices" option — enforced server-side, not just
  in the dialog — and an approved ping-only device is created with SNMP
  polling switched off so it doesn't sit failing SNMP forever.
- **A cancelled scan gets the same dialog for whatever it found** before
  it stopped — add those devices, or Discard the scan and its results
  entirely. Any scan that is no longer running can be removed from the
  jobs list with its Remove button. Running scans are visible on the
  Debug page (DISCOVERY SCANS RUNNING) with live progress.
- **Promotion is idempotent**: a result already promoted is a no-op to
  promote again, not a duplicate-IP error. Discovery suggests a polling
  profile from the device's vendor OID root where one matches, falling
  back to `Default`, and pre-fills the discovered identity so the new
  device shows its sysName immediately instead of waiting for the first
  poll.

### Vendor MIBs

- **The standard IETF MIBs ship with the app and load automatically on
  first start** — the full IF-MIB, IP-MIB, TCP-MIB, UDP-MIB, ENTITY-MIB,
  ENTITY-SENSOR-MIB, BRIDGE-MIB, P-BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB,
  POWER-ETHERNET-MIB, HOST-RESOURCES-MIB, UCD-SNMP-MIB, SNMPv2-MIB and
  the SMI/TC/IANA type modules they import — plus a hand-written IF-MIB
  core subset kept from earlier releases and enterprise-number roots for
  around twenty common vendors. They load through the exact same
  upload/parse path described below, so they're indistinguishable from an
  upload afterward, and a real vendor MIB uploaded later resolves its
  parent enterprise arc immediately instead of reporting it unresolved
  until a second file arrives. Deleting a bundled MIB is respected; it
  does not come back on the next restart.
- **A catalog of vendor MIB bundles installs on demand.** Nodes →
  Profiles & MIBs → **MIB catalog** lists curated bundles for Cisco (IOS
  and wireless), Fortinet, Juniper, Aruba (ArubaOS and CX), HP ProCurve,
  Arista, MikroTik, Ubiquiti, Extreme, Dell, NETGEAR, SonicWall, APC,
  Synology, VMware, Palo Alto, Check Point, WatchGuard, Sophos, F5 BIG-IP,
  Citrix NetScaler, Ruckus, Cambium, Aerohive, Zyxel, TP-Link, Eaton,
  Vertiv/Liebert, Raritan and Rittal — 32 bundles in all. The catalog itself is static data compiled into
  the app, so the list is browsable with no internet access at all; only
  pressing Install fetches anything, and it fetches from the vendor's or
  the distribution's own public repository rather than from a copy held
  here. A server with no outbound HTTPS gets a clear message saying so,
  and the same files can be downloaded by hand and uploaded instead.
  Installing a large bundle grows `nodes.db` by roughly the size of the
  MIB text it holds. This is deliberately not "every MIB in existence":
  the Cisco MIB repository alone is 2,921 files and around 350MB, which
  would multiply this app's database size by two orders of magnitude to
  supply the handful of MIBs an operator actually polls.
- **Uploaded and parsed by a hand-rolled, stdlib-only best-effort
  reader** — not a MIB compiler, the same framing the SNMP Trap
  receiver's own OID name table already used. It finds every
  `OBJECT-TYPE`/`OBJECT IDENTIFIER`/`MODULE-IDENTITY`/`OBJECT-IDENTITY`/
  `NOTIFICATION-TYPE` clause and resolves its OID against whatever this
  app already knows (its own built-in roots, or a previously uploaded
  MIB's objects) — never by fetching an imported module automatically.
- **A zip of MIBs can be uploaded whole, and upload order no longer
  matters.** Every MIB member of the archive is stored first and resolved
  afterwards, repeatedly, until a pass resolves nothing new — so a file
  that arrives before the one defining its parent branch still ends up
  fully resolved. The same pass runs after a catalog install, and on
  demand behind a **Resolve all** button for MIBs uploaded one at a time.
  Non-MIB members of an archive (readmes, PDFs) are skipped rather than
  refused, and per-file and total size caps are enforced against the
  archive's declared sizes before anything is expanded.
- **Extracted objects can be reviewed and hand-corrected**; an
  admin-edited object survives a later re-resolve of the same file.
- **Resolved names also flow into the SNMP Trap page** — a trap from a
  device an uploaded MIB describes shows a name instead of a raw OID
  there too, without duplicating the name table.
- **A device whose vendor MIB isn't here says so.** Every poll already
  identifies a device's vendor from its sysObjectID; when that vendor is
  identified but no uploaded MIB actually describes its objects, the
  device records it — naming the vendor and the OID — and a low-severity
  built-in alert rule surfaces it. Recorded on the change, not every
  poll: once when a device is first found uncovered, again if a covering
  MIB is later deleted, and uploading the missing MIB records the
  matching all-clear and auto-resolves the alert. The bundled
  enterprise-number roots deliberately don't count as coverage: a root
  arc names a vendor, it doesn't decode anything, so a device only looks
  covered once a MIB with real objects under that arc is uploaded.
- **Assign a MIB to a device or group to have it actually polled.** By
  itself, an uploaded MIB only feeds the browse view above — it has no
  effect on polling. Picking one from a device or group's "Custom MIB"
  override (alongside the other overrides, device beats group the same
  way every other override does) makes that MIB's own resolved scalar
  objects get GETed every poll cycle, alongside the fixed built-in set,
  and stored/shown under their own names. Best-effort like every other
  optional SNMP read here: an object this device doesn't answer is
  silently skipped rather than failing the poll. Scalars only — a MIB's
  own table objects (e.g. a vendor's per-sensor table) aren't walked by
  this feature.

### Drill-down

Selecting a device opens its identity, live status, a status timeline,
its current interface table, and a combined device/interface event
history.

**The status timeline is the device pane's headline** — a thin colored
bar of up/down/unsupported/auth-failed segments across the selected time
window, sized to match NetPath's own status lane rather than reading as
a chart panel. It's built from `device_events` (a sparse transition log,
not a dense per-poll sample table), so a device that's been up for a week
with zero events still renders as one solid "up" segment rather than
appearing to have no data. The range dropdown beside it sets the window.

**Bandwidth is a per-port question, so it is asked per port** — there is
no device-level metric chart or metric picker. Clicking an interface
opens that port's own graph (below), which is where a traffic question
actually gets answered; the device pane keeps the space for the
interface and event lists instead.

The interface list sorts by any column — Descr, Admin, Oper, Speed,
In, Out — the same way every other table in the app does. Which SNMP identity
fields the header shows (sysDescr, sysName, sysObjectID, contact,
location, vendor, SNMP version) is chosen in Nodes → Settings; the IP,
status and any SNMP error always show.

Clicking a port in the interface list opens that port's own dialog: a
live up/down bandwidth graph of the last hour with **Smoothed** on by
default (a centred moving average, unticked to see the raw per-poll
points), its statistics and
error counters (cumulative and per-second), its link up/down event
history, and DOM/SFP sensor readings — voltage, current, light levels,
temperature — read live over SNMP from devices that expose them via the
standard ENTITY-SENSOR-MIB (values, units and scaling exactly as the
device reports them; devices without it simply show "no DOM/sensor
data"), and the MAC addresses currently learned on that port — read live
over SNMP from the standard BRIDGE-MIB forwarding-database table
(devices that don't answer it show "no MAC address data" instead of an
empty table). Per-interface "show run" still appears as a placeholder
until SSH integration lands.

---

## Alerts — rule-based alerting and email notification

Evaluates Nodes' device and interface state, incoming SNMP traps, Syslog
messages and IPAM conflicts against a rule table, on the same 0–7
severity scale every other module already uses, opening or incrementing
alerts and optionally emailing about them.

### Working the alert list

- **Alerts can be resolved individually or in bulk.** Ctrl/Cmd-click a
  row to add or remove it from the selection (a plain click still opens
  the detail pane, unchanged), or use **Select all**; either reveals a
  bulk actions bar with a single **Resolve selected**, applied to every
  checked alert in one request — alongside the existing single-alert
  Resolve button in the detail pane and the all-open **Acknowledge all**
  button.
- **The Object column always shows a hostname when one is known** — the
  same precedence Syslog's Host column uses (Nodes' SNMP-polled name,
  then DNS, then the bare IP as a last resort) — rather than the raw IP
  or a bare manually-set device name it showed before.

### Rules

- **27 built-in rules** ship enabled: a device not responding, a device
  recovering, a device rebooting, SNMP authentication failing, a device
  needing unsupported SNMPv3 privacy, a poll running longer than its own
  interval, a device whose vendor MIB is missing, an interface going
  down/up/flapping, eleven CPU/memory/interface-utilization/
  error-and-discard-rate/disk/ping-latency/packet-loss thresholds, a
  critical or cold-start SNMP trap, a linkDown trap from a device Nodes
  is not itself polling, a critical syslog line, a new IPAM address
  conflict, an access point removed from its controller, and a DHCP
  scope running out of leases.
- **A built-in rule can be edited** (severity, enabled, which devices it
  applies to by a substring filter, its threshold/clear-threshold/
  consecutive-polls-before-firing where relevant, which template it
  uses) but not deleted — disable it instead. A custom rule can be added
  for anything the built-ins do not cover.
- **A rule's severity is a threshold for syslog messages, not just a
  label.** A syslog rule (built-in "Critical syslog message" included)
  only fires for messages at least as severe as the rule's own severity
  setting — a debug-level line no longer opens a "Critical" alert just
  because it cleared the module-wide "Evaluate severity X and worse"
  floor; that global setting is the outer gate, the per-rule severity is
  the inner one.
- **Threshold rules use hysteresis**: a `threshold` and a lower
  `clear_threshold`, plus a consecutive-polls-before-firing count, so a
  value oscillating right at the edge does not open and close the same
  alert every poll.
- **"DHCP scope running out of leases" watches IPAM, not Nodes.** Its
  utilization is leases plus reservations against the scope's own address
  range — counted exactly the way the DHCP page counts them, so the
  figure in the alert is the figure on screen — and it fires at 85% and
  clears at 75% by default, both adjustable like any other threshold.
  Its consecutive-polls count means DHCP polls: on the default
  15-minute DHCP cycle, 3 means three quarters of an hour, not the 15
  seconds three alert-engine ticks would take.
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
- **Default recipients are a list**, in Alerts settings — add an address
  or remove one from the visible list rather than editing a single
  comma-separated field.

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
- **A hop that stops appearing drops out.** A router that left the path
  weeks ago would otherwise sit in the diagram forever, since a wide
  window still contains the old traces it appeared in. Anything unseen
  for longer than the cutoff — 24 hours by default, set in NetPath
  settings, 0 to disable — is dropped, along with any edge that pointed
  at it. The cutoff is measured against the **end of the window being
  displayed**, not against the clock, so panning the timeline back into
  last month draws the path exactly as it stood then rather than emptying
  the graph. A pinned point-in-time snapshot is never aged: one trace is
  one instant, and every hop in it was seen at that instant.
- **A hop with no PTR record shows its ASN's org name instead**, when one is
  known — `GOOGLE, US` in place of "no PTR record". Since ASNs are only ever
  looked up for public addresses, this only ever applies to external hops;
  an unnamed hop inside your own network still reads "no PTR record". A real
  PTR name, once found, always wins over the ASN fallback.

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

A hop with live probe stats crossing that destination's own warn thresholds
turns amber on the route graph, with an "MTR: DEGRADED" badge; 100% loss
turns it red with "MTR: HIGH LOSS" — but only for a hop that has answered
at least one probe. Plenty of routers along a real path rate-limit or drop
ICMP by nature and sit at 100% loss forever without that meaning anything
is wrong; a hop with no answer on record keeps its ordinary coloring
instead, the same as a hop with no continuous probing at all. This is a
more current signal than the
traceroute-derived colors around it, so it outranks even the destination's
own green "target" marker — a target that's live-degraded is not painted
the same reassuring green as a healthy one.

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

**Hovering the traffic chart names what is under the cursor**, with a small
block in each line's own colour so a name in the tooltip can be matched to its
band in the stack without counting layers. The top-talkers bars are swatched to
match, so the same application is the same colour in both.

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

**The Exporter column names the device**, not just its address, and sits
immediately after Time — which box reported a flow is context for reading the
rest of the row. The name comes from the Nodes inventory, by the same
precedence Syslog's Host column and the Alerts Object column use: the
SNMP-polled `sysName`, then a manually entered device name, then the
reverse-DNS cache. An exporter that matches no known device keeps showing its
address. Hovering a row shows both the name and the address, since the address
is what the collector actually received the flow from, and the chart legend and
the top-talkers bars name the exporter the same way when grouping by Exporter.
Filtering still keys off the address, so a renamed device does not change what
a saved filter matches.

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
- **The Host column fills itself in when a device doesn't say.** Most
  devices put their own hostname in the message; when one doesn't (or
  just repeats its own IP there), the Host column falls back to a name
  cross-referenced from elsewhere in the app for that same source
  address — the Nodes module's SNMP-polled `sysName` first, then the
  same reverse-DNS cache the Source column uses. A device's own
  self-reported hostname is never overridden, only filled in when
  missing, and this always runs — unlike the Source column's resolved
  name, it isn't gated by **Resolve sending addresses to names**.
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

Three views inside one tab, switched locally: DHCP (the default view when
the tab opens), Conflicts, and Subnets & Hosts.

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
Unlike Nodes' and NetFlow's charts, the Y-axis is scaled to the window's
own min/max rather than anchored at zero, since this is a small sparkline
meant to show day-to-day movement — a scope oscillating in a narrow band
(say 40-45 leased) reads as real movement instead of a flat line pinned
to the bottom of the chart.

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

## Wireless — Fortinet AP dashboard

An at-a-glance table of every access point behind a FortiGate Wireless
Controller, without polling each AP individually — the controller
reports on all of them in one SNMP walk.

- **Add a controller** with its IP and an SNMP credential (v1/v2c
  community, or SNMPv3 noAuthNoPriv/authNoPriv — the same limitation
  Nodes has, since this app has no AES/DES implementation to speak
  authPriv with; the controller-add form says so directly). Managed from
  **Controllers**, next to the module's Settings button.
- **Per AP: status, name, client count, model, MAC address, and tx
  power** — the last shown per-radio, since a real AP has more than one
  (2.4/5/6 GHz). Selecting a row shows the full per-radio breakdown:
  mode, channel, tx power and client count for each.
- **Radio mode is shown, which explains an odd extra radio.** A FortiAP
  reports each radio as ap, monitor, sniffer, disabled or not present; a
  monitor radio is a dedicated rogue-AP scanner, so its "power" and
  client count describe a receiver and are not comparable to a serving
  radio's. The detail pane says so when one is present, and mode is
  available as a table column. A radio that reports a mode but no channel
  (which is exactly what a monitor radio does) is listed rather than
  dropped, so an AP shows all of its radios.
- **A scanning radio reads "Scan", not a converted number.** A monitor or
  sniffer radio is a receiver, so whatever the controller reports for its
  "operating power" is neither a transmit power in dBm nor a percentage of
  one. It is named rather than converted, left out of the AP's headline
  transmit power, and left out of the dBm-or-percentage decision below —
  a single scanner reporting an impossible figure must not change how its
  neighbours are read.
- **Transmit power is labelled with the unit it is actually in.**
  Fortinet's MIB documents `fgWcWtpSessionRadioOperatingPower` as dBm,
  but FortiOS reports its own 0–100 power *level* in that object — which
  is why an AP can report 51, a figure that as dBm would be about 126
  watts, roughly a thousand times what a FortiAP can emit (its conducted
  output tops out near 20 dBm). The reading is auto-detected per
  controller, counting only its serving radios: if any of them reports above
  30 dBm, that controller's whole column is read as a percentage. Settings → Radio tx power can
  force dBm or percent instead, and the AP detail pane always shows the
  raw number alongside, so the reading can be checked against the
  controller's own display.
- **Sort by any column** — click its heading, the same way every other
  table in the app sorts.
- **Settings → Radio tx power** forces dBm or the percentage reading where
  auto-detection gets it wrong.
- **Choose which columns to show** in Settings → Columns. The six above
  are the defaults; Controller, VDOM, WTP id, Radios, Radio modes,
  Channels, Radio clients and Last seen can be added. The list is the fields the
  controller's own SNMP tables report, so adding one costs no extra
  polling.
- **Polled on a fixed interval** (default 60 s) via repeated SNMP
  GETNEXT walks of the FortiGate Wireless Controller MIB's
  `fgWcWtpConfigTable`/`fgWcWtpSessionTable`/`fgWcWtpSessionRadioTable` —
  the exact same table-walking approach Nodes' own SNMP poller uses,
  rather than a second, separate GETBULK code path. A controller that's
  briefly unreachable does not wipe its AP list; only a poll that
  genuinely succeeded but no longer sees that AP counts against it.
- **An AP that disappears raises an alert rather than vanishing
  quietly.** Once a controller has failed to report an AP for the
  configured number of consecutive polls, it is removed from the list —
  and that removal opens an alert ("Access point removed from its
  controller") and writes an event to the log, so a decommissioned or
  unplugged AP is something you are told about rather than something you
  notice missing later. An AP that comes back auto-resolves its own
  removal alert, the same way a device coming back resolves device-down.
- **Mark an AP Out Of Service** when its absence is expected. That
  exempts it from both halves of the above: it is never aged out of the
  list (so the marking, and the AP, survive the controller dropping it —
  precisely what happens once it is unracked) and it never raises a
  removal alert. Marking it back into service restores normal behaviour;
  **Remove** clears one permanently.
- **Search** filters by AP name, MAC address, or model; a **Controller**
  dropdown narrows the list to one controller; a **Show** dropdown filters
  by Online, Offline, Out of service, or All (the default). Beside them,
  one **last reported** age covers the whole page — every AP in the list
  came from the same controller poll, so a per-row age said the same
  thing on every line.

## ConfigRX — SSH config backups

Scheduled, read-only backups of a device's running configuration, pulled
over SSH. **There is no device list of its own** — the searchable device
list is Nodes' own device list; ConfigRX only adds its own per-device
backup configuration (SSH port/username/password, whether backup is
enabled, an optional vendor override) on top of it. Each device's shown
name follows the same SNMP-hostname-first precedence every other module
already uses: its SNMP-reported name, unless it's been explicitly pinned
to a manual name in Nodes.

- **Bulk-edit SSH credentials and backup settings across many devices at
  once**: Ctrl/Cmd-click rows (or "select all") to check several devices,
  then set one shared SSH username/password/port and backup-enabled
  setting for all of them in a single action — the same shared-value
  bulk pattern Nodes' own bulk device operations already use. Leaving a
  bulk field blank/unchecked never overwrites what a device already had;
  only the fields you actually set are applied.
- **Selecting a device shows its stored backups** — timestamp and size —
  and selecting a backup shows its raw config text in a read-only panel.
  There is no editable field and no save-back action anywhere in this
  module: it only ever pulls a config, never pushes one, and there is no
  free-form command box anywhere in its UI or API.
- **A backup is only stored when it differs from the device's previous
  one** (compared by SHA-256 hash) — an unchanged config updates that
  device's last-checked time without growing the database. **Back up
  now** forces an immediate pull for one device, the same "do it now"
  convention Nodes' own **Poll now** uses.
- **Exactly one fixed, read-only command per vendor**, matched against
  the device's vendor as Nodes already detected it over SNMP (or an
  explicit override, for a vendor Nodes didn't identify): Cisco IOS
  `show running-config`, FortiOS `show full-configuration`, Junos `show
  configuration`, MikroTik RouterOS `/export`, HP/Aruba `show
  running-config` — plus, for vendors that need it, a session-scoped
  pagination-disable command (e.g. `terminal length 0`) sent first. An
  unrecognized vendor is skipped with a clear error rather than guessed
  at. ConfigRX never enters a device's configuration/enable-write mode
  and never sends anything beyond that one fixed command.
- **The SSH password is encrypted at rest** (see `CREDENTIAL-SECURITY.md`)
  and is never returned by any API response — only whether one is stored.
  It is decrypted only in memory, immediately before connecting, and
  discarded the moment the connection attempt finishes.
- **SSH needs the `paramiko` package**, the one third-party dependency in
  this otherwise standard-library-only app. Without it every other module
  runs normally and ConfigRX alone stands down, saying so plainly — in
  the worker's status line and on each affected device — with the install
  command, rather than failing with a traceback.
- **Older devices are reachable, deliberately.** Plenty of switches,
  routers and firewalls offer nothing better than SHA-1 key exchange
  (`diffie-hellman-group14-sha1` and older) and `ssh-rsa` host keys, and
  backing those up is precisely what this module is for — so ConfigRX
  offers those algorithms too, always *after* the modern ones, so anything
  capable of a current key exchange still negotiates one. **Allow legacy
  SSH algorithms** in ConfigRX settings turns this off where policy
  forbids SHA-1. It depends on the installed `paramiko` still implementing
  them: version 5.0 removed the code entirely, which is why this app pins
  `paramiko>=3.4,<5`. On a version that cannot, the failure says so and
  names the fix rather than reporting only paramiko's own
  "no acceptable kex algorithm".
- **Retention**: keep for N days, and/or keep at most N per device —
  either can be set to 0 to disable that particular cap. A device whose
  config never changes stays at one stored backup regardless of either
  cap, since an unchanged pull never creates a new row to begin with.

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
  printed it. Every Nodes poll now logs its own detail line too — ping/SNMP
  outcome, interfaces found, elapsed time, and, on a genuine SNMP failure,
  the exact error text — so "is this device really not answering, or is it
  something else" has a concrete answer instead of a guess. Cumulative
  poll counters (ok/timeout/auth-failed/unsupported/error) show in the
  status strip alongside the trace/DNS/IPAM/Nodes summary line.
- Filter by destination, by category (Traceroute, Reverse DNS, NetFlow, SNMP
  Trap, Nodes, Alerts, IPAM, Wireless, ConfigRX, System, Errors) or by free
  text across both messages and details.
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
| **Settings** button, top right of Wireless | Poller on/off, poll interval — controllers themselves are managed from **Controllers**, next to it |
| **Settings** button, top right of ConfigRX | Worker on/off, backup interval, retention (days and per-device count) |
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

**Anything that destroys stored data asks first.** Every maintenance
action here, the Debug page's log **Clear**, and every Remove/Clear/Reset
across Nodes, IPAM and Alerts raises a confirmation naming what is about
to be lost. The wording is specific where it matters: five of the
maintenance actions empty a whole table rather than pruning old rows, and
their dialogs say so rather than saying "prune". Alerts'
**Acknowledge all** and bulk **Resolve** confirm too — they delete
nothing, but neither can be undone one row at a time. Buttons that clear
a filter or a selection, which destroy nothing, are deliberately left
unconfirmed.

### Software update

One button — **Check for update & restart** — checks
`github.com/thawkins5555/magicalbeans`'s `main` branch for a commit newer
than what's installed. If there is one, it downloads it over plain HTTPS,
swaps it into the running install, and restarts the service so the new
code takes effect immediately; if not, it says so and stops there. The
screen grays out with a status dialog for the duration, since restarting
signs everyone out — sessions are in memory — and it lands you back on the
sign-in page once the service answers again. **Change password**, an
always-reachable "Account" control in the top bar rather than anything on
this page (see Permissions below), is the only other place a full page
reload follows a button press for the same reason: changing your own
password ends every session on that account, this one included.

### Permissions

Every account has an explicit **read** or **write** grant per module —
Nodes, Alerts, NetPath, NetFlow, SNMP Trap, Syslog, IPAM, Wireless,
ConfigRX, Settings, Debug — set from **Settings → Users** (itself gated
on Settings write access). Write implies read; no grant at all means no
access. A tab the signed-in account can't read is hidden from the tab
bar, and a write-gated control (add/edit/delete buttons, a module's
Settings gear) is hidden within a tab the account can only read — both
purely client-side conveniences, since the server enforces the identical
check on every route regardless of what the browser shows. The Dashboard
tab is the one exception: it's always visible and simply omits whatever
sections the signed-in account can't read, rather than being gated as a
whole.

**Changing your own password always works**, even with zero access to
Settings — it lives in an "Account" control in the top bar, independent
of the Settings tab, rather than being gated like everything else there.
Resetting a *different* account's password still requires Settings write
access, same as adding, editing or removing an account.

An install upgrading from a version before this shipped keeps every
existing account's access exactly as it was — the first time the
permissions table is created, every account already on file is granted
full write access to every module, so nobody loses anything on upgrade.
Only accounts created after that point start with whatever grants an
admin explicitly assigns in the Add User dialog.

---

## Data

Ten SQLite files, in WAL mode. One for the application, nine for records.

| File | Holds |
| --- | --- |
| `app.db` | Global settings, user accounts, per-account per-module permissions, the shared reverse-DNS cache |
| `netpath.db` | Destinations, traces, per-hop samples, NetPath settings |
| `flows.db` | Flow records, exporters, interface names, NetFlow settings |
| `snmptraps.db` | Traps, an OID name table, SNMP Trap settings |
| `syslog.db` | Messages, hourly rollup counts, search index, Syslog settings |
| `ipam.db` | Subnets, discovered hosts, conflicts, DHCP scopes and leases, IPAM settings, an optional DHCP credential |
| `nodes.db` | Devices, polling profiles, interfaces, metric samples, device/interface events, uploaded MIBs, discovery jobs, Nodes settings, optional SNMPv3 credentials |
| `alerts.db` | Rules, email templates, alerts, notification history, Alerts settings, an optional SMTP credential |
| `wireless.db` | Wireless controllers, access points, per-radio detail, Wireless settings, optional SNMP credentials |
| `configrx.db` | Per-device backup configuration (keyed by a Nodes device id, no real foreign key — see ConfigRX below), stored config backups, ConfigRX settings, optional SSH credentials |

Each record file holds its own module's data and its own module's settings, and
nothing else. Anything read by more than one module — the reverse-DNS settings
and the cache they fill, the web listener, session lifetimes, the size caps —
is in `app.db`.

`app.db` is the one worth backing up: it is small, it does not grow with
traffic, and it is the only file whose contents cannot be rebuilt by collecting
again.

Default location is `%APPDATA%\netpath-monitor\` on Windows and
`~/.local/share/netpath-monitor/` elsewhere; override with `--db`, `--flow-db`,
`--snmp-db`, `--syslog-db`, `--app-db`, `--ipam-db`, `--nodes-db`,
`--alerts-db`, `--wireless-db` and `--configrx-db`. All ten upgrade their
schema automatically on launch, and an install that predates `app.db`
moves its settings, accounts and name cache into it on the first start.

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
- **Permissions are per-module, not per-object.** An account with Nodes
  write access can edit or delete any device, not a subset of them —
  there is no per-device or per-group access control within a module.
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
- **ConfigRX can only back up a device whose vendor it recognizes.** A
  fixed, deliberately short allow-list — Cisco, FortiOS, Junos, MikroTik,
  HP/Aruba — is the entire set of "show config" commands this app knows
  how to run; a device Nodes couldn't identify, or one from a vendor not
  in that list, needs a vendor override set to a value on the list before
  it can be backed up, or it's skipped with a clear error. This is
  deliberate: adding a new vendor means adding its fixed, read-only show-
  command to `configrx_vendors.py`, never accepting one typed into a
  field.
- **ConfigRX never pushes a configuration change, to any device, ever.**
  There is no code path in this module capable of it — no free-form
  command box, no "push config" action, nowhere in its UI or API. It only
  ever pulls a read-only snapshot.
