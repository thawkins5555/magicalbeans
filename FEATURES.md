# SappiWhere — Features

What the application does, by module — the overview, deliberately light on
mechanism. For how each of this actually works underneath — which file,
which function, which algorithm — see `INTERNALS.md`. Setup and firewall
rules are in `README.md` and `NETWORK-AND-STORAGE-REQUIREMENTS.md`; the
build history is in `CHANGELOG.md`; exactly how passwords and credentials
are protected is in `CREDENTIAL-SECURITY.md`.

## Contents

- [How it runs](#how-it-runs)
- [Appearance, screens and the wall](#appearance-screens-and-the-wall)
- [Dashboard — the screen a shift starts on](#dashboard--the-screen-a-shift-starts-on)
- [Nodes — SNMP poller and device inventory](#nodes--snmp-poller-and-device-inventory)
- [Alerts — rule-based alerting and email notification](#alerts--rule-based-alerting-and-email-notification)
- [NetPath — path monitoring](#netpath--path-monitoring)
- [NetFlow — flow collection](#netflow--flow-collection)
- [SNMP Trap — trap and inform receiver](#snmp-trap--trap-and-inform-receiver)
- [Syslog — message collection](#syslog--message-collection)
- [IPAM — address inventory, conflicts, DHCP visibility](#ipam--address-inventory-conflicts-dhcp-visibility)
- [Wireless — Fortinet AP dashboard](#wireless--fortinet-ap-dashboard)
- [ConfigRX — SSH config backups](#configrx--ssh-config-backups)
- [Debug](#debug)
- [Settings](#settings)
- [Data](#data)
- [Deliberate limits](#deliberate-limits)

The twelve tabs sit flat in one strip, in frequency order — **Dashboard**,
**Alerts** · **Nodes**, **IPAM**, **FortiWireless**, **ConfigRX** ·
**Routes**, **NetFlow**, **Syslog**, **SNMP Trap** · **Settings**, **Debug**
— with a hairline before the first tab of each group after the first,
standing in for the four labelled sections (Now/Inventory/Telemetry/Admin)
an earlier revision drew as wrapped, named groups; Admin stays rightmost so
adding a module never moves it. The grouping is purely presentational either
way: there is one tab list underneath it, and who is signed in, the way to
the **Account** dialog, Sign out and the connection indicator sit outside
the scrolling strip entirely, so narrowing the window can shrink the tabs but
never scroll those out of reach — and below about 480 px, Search, Account and
Sign out collapse from a text label to an icon so they go on fitting beside
the tabs rather than crowding them out (each keeps its accessible name, so
nothing a screen reader announces changes). A tab that becomes current while
the strip is scrolled elsewhere — a digit shortcut, a pasted link, kiosk
rotation — scrolls itself into view. Routes is the NetPath module — the tab
says what it shows, the package, database and settings keep the name they
have always had. Dashboard aggregates whatever other modules the signed-in
account can read — see Permissions, under Settings — rather than holding data
of its own; from 4.39.0 it is a real page rather than a placeholder, and it
is described under **Dashboard** below. A tab the signed-in account has no
read access to is hidden from the tab bar entirely.

**Only Dashboard's own script loads before the page is usable.** Each of the
other eleven modules — 1.17 MB uncompressed between them, around 324 KB
gzipped, before 4.49.0 — now loads the first time its tab is actually
selected rather than unconditionally on every visit, at no cost to what
opening a tab for the first time looks like: the tab reads as still-working,
the same way an ordinary slow refresh already does, until its script and
first render are ready.

**A global search, on `/`,** looks across devices, MAC addresses,
interfaces, alerts and NetPath destinations, and — from 4.49.0 — IPAM hosts
and subnets, syslog messages and wireless access points, at once, and opens
whatever is picked at that record's own URL — the same link a colleague
could be sent instead. It stands down whenever a field, a dialog or the help
panel already has the keyboard, and the **Search** button beside Account and
Sign out opens it for a mouse. Each group of results is its own independent
lookup with its own failure handling: one group's endpoint being slow or
erroring drops that group from the results rather than the ones after it —
before 4.49.0 a single shared `try` meant one failing lookup silently emptied
every group queried after it, in whatever order they happened to run. Not yet
covered: an interface's own description or alias, and text inside a stored
ConfigRX backup.

Every sub-panel is resizable. Each page's panels are separated by draggable
dividers, sizes are remembered per splitter across reloads, double-clicking a
divider resets that one, and **Reset panel sizes** on the Settings tab resets
them all. The chrome also tightens automatically below 900 pixels of viewport
height, and again below 700, so a laptop gets a usable layout before anything
is dragged.

**Every selection has a URL.** From 4.39.0 the address bar carries the
open tab and the selected thing — `#/nodes`, `#/nodes?status=down`,
`#/nodes/device/41`, `#/nodes/device/41/port/3`, `#/alerts/12`,
`#/netpath/2`, `#/configrx/device/41/backup/9`, and `#/snmp/5512`,
`#/syslog/8801` and `#/wireless/3` for a trap, a message and an access
point. From 4.48.0 a tab's own subtabs carry the same URL — `#/nodes/topology`,
`#/settings/users` — so a pasted link lands a colleague on the pane that was
actually open, not just the tab. Back walks the selections, a reload lands where you were,
and a link pasted into a ticket or an email opens what it names for
anybody who can sign in and read that module. A route naming something the
account cannot read, or that no longer exists, falls back to the tab.

**Reloading the page returns to whichever tab was open**, not back to
NetPath — the browser remembers the last tab the same way it remembers
panel sizes and column widths, per browser rather than per account. **It
also keeps the view itself**: the column a table was sorted on and which
way, whatever was typed into a search box, every dropdown filter, and the
sub-tab a page was on (Devices or Discovery, Subnets or DHCP) all come back
as they were. That covers the nine pages that have filters and sortable
tables — Nodes, Alerts, Syslog, SNMP Trap, NetFlow, IPAM, Wireless,
ConfigRX and Debug. **Settings** remembers only which of its own subtabs
was open, the same per-browser way, since it has no filters or tables of
its own to keep; Dashboard has nothing of the kind at all, and NetPath
keeps its own time window per destination instead, since there the window
belongs to the destination rather than to the page. What
is deliberately *not* remembered is the Live / follow switch on the
streaming pages: a page that came back with its updates quietly switched
off would read as broken, so those start on every load. It is also *per
person*, not just per browser: signing out clears it, and a different
account signing in on the same browser starts with clean filters rather
than inheriting the last operator's searches. **Reset panel sizes** on the
Settings tab resets panel sizes and nothing else. **Signing in always opens
on Dashboard**, though: a fresh login is a new visit, not a reload, so it
starts from the same place every time rather than wherever a previous
session happened to leave off.

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

Signing in is required. A fresh install starts with **admin / admin** — the
sign-in page says so until someone has signed in — and insists on a new
password. Accounts are managed on the Settings tab and are local by
default; from 4.47.0 an account can instead be bound to an LDAP directory
(**auth_source: ldap**), verified against the directory on every sign-in
rather than a locally stored hash — see **Permissions** below. A script or
another system reaches the API through a bearer **API token** rather than
a stored username and password; see the same section.

The server uses only the Python standard library. PySide6 is needed for the
console window and nothing else, so a headless install needs neither it nor a
web framework. TLS is used when `--cert` and `--key` are supplied.

**Every main table works the same way.** The device list in Nodes, the alert
list, ConfigRX's devices and its stored backups, the flow, trap and syslog
lists, IPAM's hosts and DHCP leases, and the wireless AP list all share one
set of table behaviours:

- **Click a header to sort by that column**; click again to reverse it. Empty
  cells always sort last whichever way the column points — a blank is absent,
  not smaller than everything else. The sort lasts for the session.
- **Choose which columns are shown**, from that module's own Settings dialog.
  Each table offers more columns than it shows by default; tick the ones you
  want, or use All / None. Unticking everything restores the columns the page
  ships with rather than leaving an empty table, and a column a later release
  removes is ignored rather than breaking a saved choice. This is a setting
  and is shared by everyone using the server.
- **Drag a column edge to resize it.** Widths are per browser, not a setting,
  and **Reset layout** on the Settings tab clears them — it does not touch
  which columns are shown.
- **Where rows have checkboxes**, a select-all box sits in the header directly
  above them. It shows a dash when only some rows are ticked, and clicking it
  again clears the selection.
- **Export CSV**, from 4.47.0, honours whatever filter the table currently
  has applied — it is the rows on screen, not a fixed dump — and writes
  RFC 4180-quoted CSV with a UTF-8 BOM and a timestamped filename. Alerts
  exports up to 50,000 rows, well past its own console page; every other
  table exports what its search already caps at.

The Debug page is deliberately outside this: its tables are live worker state
rather than records to work through.

---

## Appearance, screens and the wall

### Themes

Three, chosen in the **Account** dialog under **Appearance · this
browser**: Dark
(the default), Light, and High contrast. The choice is stored in the browser,
not on the server — it belongs to the screen and the eyes in front of it, so
a shared NOC workstation keeps it across sign-ins and every account on that
machine sees it. It applies at once, needs no Apply, and the sign-in page
follows it. Light is the route canvas's palette applied to the whole
interface; High contrast keeps the same hues and pushes them apart to at
least 7:1. Charts follow the theme because every colour in the product is a
token.

### Any width

Below about 1200 px the sidebar narrows and dialogs size to the window;
below 900 px side-by-side panes stack and the NetPath destination list moves
above the route. The layout is measured down to 768 px (a tablet); below
that nothing is clipped, but nothing is designed for a phone either.

### Touch, pen and keyboard

Every drag — pane splitters, column grips, panning the route, brushing a
time range on a chart — works from a finger or a pen as it does from a
mouse. A pane splitter can be moved from the keyboard: Tab to it, arrow keys
move it 5 % (1 % with Shift), Home and End park it, Enter resets it, exactly
as a double-click does. A column header resizes with Alt+Left/Right.

### Accessibility

Keyboard and screen-reader support are built into the shell, not layered
onto it afterward.

- **The tab bar and every subtab bar behave like the tabs they say they
  are.** ArrowRight/ArrowLeft and Home/End move both focus and selection
  along the strip, and only the active tab sits in the page's own Tab
  order, so leaving the strip is one stop rather than twelve. One shared
  helper wires the same roving-tabindex behaviour onto every module's own
  subtab row — a device's INTERFACES/NEIGHBOURS/BRIDGE & RF/EVENTS group
  included — so no module has to implement it for itself.
- **Every chart, the route graph, the timeline and the topology map are
  reachable without a pointer.** Each carries a label built from the same
  summary its own header already shows, a visually hidden table stands
  beside a histogram with the buckets its bars draw, and a tooltip answers
  focus the same way it answers hover, in NetFlow, IPAM, NetPath, Nodes,
  SNMP Trap and Syslog alike. Keyboard movement suits what the chart is
  for: NetFlow's arrow keys pan and zoom, NetPath's timeline walks bucket
  by bucket with the crosshair following, IPAM's scope trend walks point
  by point, and the NetPath destination list — the control that decides
  what the whole module is showing — is a real listbox rather than a set
  of mouse-only rows.
- **The SSH terminal talks back to assistive technology.** Its status line
  is announced as it changes, and a visually hidden log receives each
  completed line of device output, so a screen reader hears the session
  instead of silence. The terminal has to keep Tab for the programs
  running on the device — vi, less, a switch's own menu console all need
  it — so Escape is left alone to reach them, and the published way out is
  **Ctrl+F6** instead, named in a hint under the terminal's header.
- **Status is never colour alone.** Every status mark on screen — up/down,
  a ConfigRX backup's changed/unchanged/suspect, a trap's or a syslog
  line's severity — pairs a distinct shape with the colour, and shows the
  word itself wherever there is room for it; a column too narrow for the
  word still names the mark through its own accessible label. The device
  status timeline and the route graph carry the same idea into texture —
  refused, skipped and unknown are each their own hatch or stripe, not
  only their own hue — while a plain, textureless fill is kept for "no
  data at all", so silence and an unknown reading never draw identically.
- **Focus is never thrown away by a redraw.** A discard prompt marks the
  form behind it inert rather than leaving Tab to wander through the
  fields it is asking about, sorting a table column restores focus to the
  header that was just sorted, and the idle-session countdown keeps
  ticking visibly every second but is only announced at its checkpoints,
  not on every tick.

### On a wall — `/?kiosk=1`

Open the application as `/?kiosk=1#/dashboard` (any tab route works) for a
wall display: the tab strip goes, everything is a quarter larger, and one
thin bar names the view, shows the clock, the account, and **how long the
session has left**. Sign-in keeps the flag, so a bookmark works.

The **Account** dialog can build the same link without typing it: choose
which tabs to **Rotate through** and **Every** how many seconds, then
**Open this view as a wall display**. A rotating kiosk shows a row of dots
for the views in the cycle and a countdown to the next one, so a person
walking past the wall can see what's coming as well as what's on it now.

The session is held open — the heartbeat goes without anyone at the
keyboard — **only for an account with no write permission on any module**.
Create a read-only account for the wall. An administrator who opens kiosk
mode is told in the bar that the idle sign-out still applies to them. The
absolute session length (`session_max_hours`, 12 by default) is not
extended by anything; the bar counts it down, and a site that wants a wall
to run longer raises that setting.

## Dashboard — the screen a shift starts on

The landing page after every sign-in. Until 4.39.0 it said "nothing here
yet" — which it had said for several releases while being the first thing
every operator saw. It now answers "what should I look at first" from data
the application already had, refreshed on the interval in
`dashboard_refresh_s` (five seconds by default).

| Tile | Shows |
| --- | --- |
| Fleet | Total devices, and how many are up, down, unknown or failing authentication, with the poll pool's busy and queued worker counts beneath |
| Open alerts | The count by severity, coloured by the worst severity open rather than by the total, so one severity-1 outage is never hidden behind forty notices |
| Workers | Every background process, by the noun its own tab uses — the Nodes poller, the alert engine, the NetFlow collector, the SNMP trap receiver, the Syslog collector, the IPAM worker, the Wireless poller, the ConfigRX worker: running or not, how much each has taken in, and every one of its counters that is not zero — dropped, dropped by the kernel, throttled, failed or unverified authentication, over the varbind limit, TCP connections refused, errors |
| Storage headroom | Each database against its own size cap |
| Worst ten (24 h) | Six lists: most device events, most interface events, most alerts, slowest to answer, worst packet loss, highest CPU |

**Every count is a link**, and a real one — an anchor with an `href`, so it
can be middle-clicked into a second tab or copied into a ticket. Clicking
"14 down" opens Nodes showing those fourteen rather than the whole fleet.

**A section the signed-in account cannot read is left out**, not drawn as a
zero: the Dashboard is the one tab that is always visible, and it omits
what the account has no grant for rather than showing a number that would
be a lie. The six 24-hour lists are refreshed on a slower cadence than the
tiles, since they are history rather than live state.

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
  scalar metrics all come from the same poll. **What "scalar metrics"
  means, exactly**, because an earlier edition of this file overstated it:
  CPU and memory came from **UCD-SNMP-MIB only** — `ssCpuRawIdle`,
  `memAvailReal`, `memTotalReal`, `laLoad` — which in practice means
  net-snmp on a Linux or BSD host and nothing else. HOST-RESOURCES-MIB was
  named here and never actually read. From 4.39.0 both are true: a
  best-effort vendor-health GET rides the same poll and reads
  `hrProcessorLoad` and `hrStorageTable` where they answer, plus Cisco
  (`cpmCPUTotal5minRev`, `ciscoMemoryPool`), Fortinet (`fgSysCpuUsage`,
  `fgSysMemUsage`, `fgSysSesCount`) and Juniper (`jnxOperatingCPU`,
  `jnxOperatingTemp`) health objects chosen by the device's detected
  enterprise arc. They are recorded as `cpu_pct`, `mem_pct`,
  `disk_pct` and `session_count`, which is what makes the shipped
  `cpu_high`, `mem_high` and `disk_high` rules live on a switch or a
  firewall rather than only on a Linux host. Thresholds are unchanged, so
  a device that was silent may start alerting once it starts reporting.
  From 4.49.0, `mem_pct` also falls back to the same `hrStorageTable`
  walk's physical-memory row when none of the three above answers it —
  a Windows PC, a printer, most appliances — so a device whose CPU and
  disk already worked through HOST-RESOURCES-MIB gets memory too, at no
  extra cost to a device that already had a working `mem_pct`.
- **A UPS wired to SNMP is asked how it is, not just left to shout.**
  Battery status, seconds on battery, estimated runtime and charge,
  battery voltage and temperature, input voltage, output load and active
  alarms (UPS-MIB, RFC 1628) are tried on every device — not gated by
  vendor arc the way the health probe above is, since a UPS's maker
  varies far more than a switch's does and UPS-MIB is the one object
  tree nearly all of them answer regardless. A non-UPS device costs one
  extra scalar GET a poll and nothing more: the two table walks (input
  line, output line) are only attempted once that GET shows the device
  is a UPS at all. A unit whose firmware doesn't populate the standard
  runtime figure falls back to APC's own PowerNet-MIB object, tried only
  on APC's arc. Four built-in rules read it: UPS running on battery,
  battery low, battery depleted (replace it), and output load high.
- **A device's own temperature and humidity are polled from
  ENTITY-SENSOR-MIB, not just an interface's SFP.** A dedicated
  environmental monitor (an AVTECH Room Alert, or any switch, router or
  PDU exposing chassis sensors through the standard MIB) is walked once
  every five minutes for a device-level reading, in addition to the
  on-demand per-port DOM/SFP read the interface dialog already offers.
  Temperature is stored as one of three separate metric keys —
  `temp_optic_c` for a sensor that maps to a port, `temp_ambient_c` for
  one that maps to no port on a device that also reports a humidity
  sensor, `temp_chassis_c` for everything else — because a comms room, a
  switch's own board and an optic's DOM reading have entirely different
  normal ranges (a healthy transceiver commonly runs 40–55 °C by design)
  and one key with one threshold cannot tell a healthy switch from an
  overheating room. Three built-in rules replace the one this briefly
  shipped as, each tuned to its own kind of reading, plus a humidity-high
  rule for the one metric that never needed splitting.
- **A device inherits its settings from a "polling profile"** (a group) —
  credentials, poll interval, timeout, retries, which of ping/SNMP are
  enabled, how many ping probes to send and how long to wait for them,
  and whether SNMP failing on its own counts as down — and can override
  any of it individually. One profile, `Default`, always exists.
- **A ? beside a setting explains it.** Where a control's effect is not
  obvious from its label — the Ping and SNMP checkboxes on a polling
  profile to begin with — a small **?** opens a plain-language note over the
  form: what the setting produces, what depends on it, and what changes when
  it is off. Escape or Close puts the form back exactly as it was.
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
- **Devices can be selected and operated on in bulk.** Every row carries
  a **checkbox** in its first column: tick the rows you want, or use
  **Select all**; either reveals a bulk actions bar: Set profile, Set
  group, Remove from group, and Delete — each applied to every selected
  device in one request rather than one per device. A plain click still
  opens the device's detail pane, unchanged. (Ctrl-click no longer
  selects — the checkboxes replaced it.)
- **Sort the device list by any column** — click its heading, the same
  way every other table in the app sorts. Status, Name, Profile, Group,
  Vendor, Response and Last poll all sort on what the column actually
  shows, so Profile sorts by profile name rather than by its internal id
  and Response sorts by the number of milliseconds rather than by the
  text around it. A device with no reading sorts to the bottom in both
  directions instead of leaping to the top when the order is reversed.
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
- **A whole site can be imported in one call, from 4.47.0.** A JSON array
  or pasted CSV of up to 2,000 rows, the same fields the single-device
  form accepts, every row validated before any of them is written, with a
  per-row disposition in the reply so a bad row is named rather than
  silently dropped — and the same identify-and-first-poll queueing the
  single-device Add already triggers. The device list itself takes
  `limit`/`offset` and a pager past the default page, for a fleet too
  large to load in one response.

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
- **A finished scan opens an approve/deny dialog once**, and only for the
  browser that started it — every discovered device listed with a
  checkbox, SNMP-identified ones pre-checked, and nothing added until
  "Add approved" is clicked. It no longer pops back open over whatever the
  operator came to Nodes to do: from any other visit, an unreviewed scan is
  a dismissible line in the strip instead, naming how many new devices it
  found with its own **Review** (opens the same dialog) and **Dismiss**.
  Dismissing, from either place, adds nothing, and either answer is final
  for that scan (the RESULTS pane remains for promoting later, with the
  same defaults). Devices that only answered ping are excluded unless the
  scan was started with the "Also offer ping-only devices" option —
  enforced server-side, not just in the dialog — and an approved ping-only
  device is created with SNMP polling switched off so it doesn't sit
  failing SNMP forever.
- **A result whose address is already a device says so, and drops out of
  the pile to add.** In place of a checkbox its row reads "Already added —
  <name>", linked straight to that device, and it is left out of the
  header's select-all — ticking every remaining box can never resubmit an
  address that's already monitored. **Add approved** reports how many of
  the ticked results were genuinely new, since a batch that included
  already-added rows would otherwise look like it added more than it did.
- **A cancelled scan gets the same dialog for whatever it found** before
  it stopped — add those devices, or Discard the scan and its results
  entirely. Any scan that is no longer running can be removed from the
  jobs list with its Remove button. Running scans are visible on the
  Debug page (DISCOVERY SCANS RUNNING) with live progress.
- **Results are a sortable table.** Click a heading to sort — IP addresses
  in numeric order, so .9 comes before .100 — drag the column edges, and
  use the header box to select every result the scan is allowed to add.
  Ticks belong to rows, not positions, so a re-sort carries them along and
  Promote adds exactly the devices that were ticked. While a scan is
  running its results fill in as they are found, keeping the sort and the
  ticks; the fetching stops when the sweep ends or the Discovery view is
  left.
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
  Vertiv/Liebert, Raritan, Rittal and Moxa — 33 bundles in all. The Moxa
  bundle covers the EDS, IKS and PT switch families and the AWK access
  point: system info and utilization, port status, PoE, Turbo Ring and
  Turbo Chain redundancy, dual homing, fiber check and digital I/O. The catalog itself is static data compiled into
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
- **Vendors are identified from the sysObjectID, and from the sysDescr
  where that says nothing.** The enterprise-arc table now covers every
  vendor the MIB catalog ships a bundle for, plus a range of industrial
  and wireless names — every arc read out of that vendor's own MIB text
  rather than from memory, since a wrong arc mislabels every device under
  it. Where the sysObjectID names only the SNMP *agent* (a Phoenix
  Contact radio, a Moxa switch and a Linux server all answer net-snmp's
  own arc), the sysDescr is consulted instead, so a device that used to
  show a blank Vendor now shows the right one. The two are not treated as
  equal: an arc match is an IANA assignment, a sysDescr match is a
  substring of text the vendor chose to write, and only the former is
  used where being wrong would matter.
- **A vendor is shown under its own name.** Vendor keys are terse tokens
  because everything that behaves differently per vendor matches on them —
  ConfigRX's backup command, the Cisco per-VLAN MAC read, discovery's
  profile suggestion — so where a key does not read as the vendor's name
  the Vendor column shows the name instead: "Moxa", "Rockwell Automation".
  Only the display changes; the stored key is untouched.
- **The matching MIB is assigned to the device automatically.** Once a
  vendor is identified and an uploaded MIB describes objects under that
  vendor's arc, the device's Custom MIB override is set for it, so
  installing a bundle actually starts decoding that vendor's data instead
  of waiting for someone to visit every device. It never overrides a MIB
  chosen by hand — including one deliberately pointed elsewhere — it is
  recorded in the device's own event history, and it can be changed or
  cleared from the same override afterwards.
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

### Vendor identification

- **The vendor is worked out from what the device answers, and the app
  says how sure it is.** Every device is walked once — a hop across the
  enterprise arcs it populates (a handful of requests), then a bounded walk
  under each (about 500 objects, 20 seconds) scored against every installed
  MIB. That happens on its first successful poll, again only if its
  sysObjectID changes, and behind **Re-identify**; the steady-state poll
  adds nothing. The Vendor column marks a name that is less than certain:
  `?` a guess from a word in sysDescr, `~` probable, `*` set by hand or
  learned. Hover for which source spoke.
- **Precedence, in order:** a vendor set by hand; one learned from an
  operator's override on a device with the same sysObjectID; a real vendor
  arc in the sysObjectID; the walk; a word in the sysDescr; the SNMP agent's
  own name. The walk never overrules a real vendor arc — OEM gear implements
  the chipset maker's arc alongside its own — but it is what names a device
  whose sysObjectID says only "net-snmp".
- **The device dialog shows the evidence:** the arcs found, how many objects
  each answered, which MIB named how many of them, the MIB that was assigned
  because of it, and the sentence that states why. Re-identify runs the
  walk again in front of you. A **Vendor (manual)** box overrides everything,
  for display and for ConfigRX's command choice; when the device's
  sysObjectID is specific to one vendor, every device with the same one
  follows on its next poll, and the dialog says whether that applies.
- **A bundle is suggested when it would help.** Catalog bundles know their
  enterprise arcs, so a device answering under an arc no installed MIB
  decodes gets "This looks like a Ubiquiti — Install the Ubiquiti MIBs"
  with the install one click away.
- **Arcs with no MIB still get a name** from a bundled enterprise-number
  list, at one of two confidence levels, always with the arc number shown as
  the evidence. Be clear about what that confidence is: both tiers are
  hand-authored from IANA's public Private Enterprise Number registry, and the
  application has no way to reach that registry to check itself. **High**
  means the arc was cross-checked against the sysObjectID a real device of that
  make reports, or against a MIB bundled here; **medium** means it was not. A
  wrong arc would produce a confidently wrong vendor name, so the arc number is
  always displayed beside the name — if it disagrees with what you know the
  device to be, the number is the thing to trust.
- **Discovery sweeps list each device's arcs** (a few extra requests per
  device that answers SNMP, switchable off under Settings → Nodes), mark
  confidence in the results table, hint at the bundle to install, and carry
  the verdict into the device on promotion.

### Drill-down

Selecting a device opens its identity, live status, a status timeline,
its current interface table, and a combined device/interface event
history.

**SSH opens a terminal to the device in a new window.** The pane's SSH
button (shown only to accounts with the SSH permission, see Permissions)
opens a real terminal — cursor keys, colours, pagers, `vi` — sized to the
window and refitted when it is resized. It signs in with the SSH credential
ConfigRX holds for the device, and asks for a username and password when
there is none or the device refuses it; a typed credential is used for that
connection only and never stored. The first connection stores the device's
host key; a later connection presenting a different key is refused with a
warning that names both fingerprints and when the old key was first seen,
and a **Trust the new key** button for a device that really was replaced.
Sessions end after fifteen minutes idle, at most sixteen run at once (four
per account), and each is recorded in the device's event log with who
opened it and from where. A session lives only as long as the web sign-in
behind it: signing out, the sign-in expiring, the SSH permission being
revoked or the account being removed closes the terminal within seconds
(typing in it counts as presence for the sign-in, the same as clicking in
the main window). Five refused logins close the window, and every refusal
is written to the device's event log with the account that asked and where
from — never the password. **Remove** now lives in the device's Edit dialog, beside Clear
credential, so the pane's buttons are the things you do *to* a device
rather than the one thing you do to get rid of it.

**A WEB button sits beside SSH**, a plain link to the device's own web
interface (`http://<ip>/`, IPv6 bracketed) opened in a new tab. Unlike
SSH it carries no permission of its own — it opens nothing on this
server, only a tab in the browser — so it shows for anyone who can see the
device at all, once the device has an address to link to.

**The status timeline is the device pane's headline** — a thin colored
bar of up/down/unsupported/auth-failed segments across the selected time
window, sized to match NetPath's own status lane rather than reading as
a chart panel. It's built from `device_events` (a sparse transition log,
not a dense per-poll sample table), so a device that's been up for a week
with zero events still renders as one solid "up" segment rather than
appearing to have no data. The range dropdown beside it sets the window.

**Packet loss is charted in the device dialog** — double-click a device row
— on its own time frame, with its own range dropdown: "how long has this been
down" (the timeline in the pane) and "how lossy is this link" are asked over
different spans, and the pane is the place for the answer that has to be
visible at a glance, the dialog for the one you open to study. The axis is
pinned to 0–100 %, so a healthy device draws a flat line along the bottom
rather than an auto-scaled one that makes a fraction of a percent look like an
outage. A device that is not being ping-probed says so instead of showing an
empty chart. The chart refreshes every fifteen seconds while the dialog is
open, so the fast polling a selected device gets shows up in it. Its ranges
stop at three days, because a wider metric window reads from an hourly rollup
table that nothing populates — a 7-day option would be permanently empty. The
status timeline keeps every range, since it is built from the event log rather
than from samples.

**The per-port bandwidth chart holds still under live polling.** Selecting a
device polls it every few seconds, and a chart drawn from every one of those
samples turned to hash the moment that started: the rate of a 3-second
interval was computed from timestamps taken at the start of the poll rather
than when the counters were actually read, the smoothing window shrank with
the sample spacing, and the axis was re-fitted to the raw maximum on every
redraw. Rates are now timed from the moment each port's counters came back,
the hour is drawn from fifteen-second averages so fast and slow samples land
evenly, **Smoothed** spans a fixed ninety seconds of wall-clock time whatever
the sample spacing, and the axis grows immediately for a real spike but does
not shrink for a small dip. The figures in the dialog's text still refresh
every five seconds; the chart redraws every fifteen, when it has a whole new
point to show.

**Bandwidth is still a per-port question, so it is still asked per port** —
there is no device-level bandwidth chart or metric picker. Clicking an
interface opens that port's own graph (below), which is where a traffic
question actually gets answered.

The interface list sorts by any column — Descr, Admin, Oper, Speed,
In, Out — the same way every other table in the app does. Which SNMP identity
fields the header shows (sysDescr, sysName, sysObjectID, contact,
location, vendor, SNMP version) is chosen in Nodes → Settings; the IP,
status and any SNMP error always show.

**Poll now shows that it is running.** A poll is handed to a worker
thread, so the button reports *Queued* or *Polling* until the device's own
last-poll time actually moves, then settles to *Polled* — it used to look
inert for however long the device took to answer. A click while that device
is already being polled cannot start a second poll, so the button says
*Already polling* rather than reporting *Polled* off the poll that was
already running.

**Poll now works on a selection, too.** Ticking rows reveals a bulk actions
bar with its own **Poll now**, which polls every ticked device immediately
rather than waiting for each one's interval, and reports how many it queued
and how many were already running. The detail pane's button only ever polls
the one device open in it.

**Double-clicking a row opens that device in a dialog** — its identity
line, its interface table and its event log — without moving what the
detail pane is showing anywhere you did not ask it to go. The dialog is
about the device you double-clicked, which is not necessarily the one
selected, so it reads that device by id rather than borrowing the pane's
data. Opening a port from the dialog charts *that* device, and offers a
way back to the dialog it came from. A single click still just moves the
detail pane.

**The Find box accepts a MAC address** as well as a name, an IP or a
sysName. Any notation works — `AA-BB-CC-DD-EE-FF`, `aa:bb:cc:dd:ee:ff`,
`aabb.ccdd.eeff`, bare hex — and so does a prefix of one, so the first
three octets of a vendor OUI is a valid search. The list filters to the
switches that have learned the address. When it resolves to exactly one
switch and one port, that port's dialog opens; when it resolves to
several, they are listed as a shortlist to pick from rather than one
being chosen for you — a MAC seen on an uplink is on every switch between
here and the host, which is the normal case, and guessing which one was
meant sends someone to the wrong place. **A MAC no switch is holding right
now** is not a dead end: the search says where and when it was last seen —
"last seen on *switch* · *port* at *time*" — from forwarding-table history
kept for the retention window, so an address that has gone quiet or moved
still points somewhere.

**Learning MAC addresses is on by default, hourly, and separately paced.** A
forwarding table is still read on its own schedule, not the poll cycle,
but it is no longer expensive: table walks use GETBULK, so a table that
once cost a hundred SNMP round trips now costs about five, and it can be
refreshed far more often for the same load. A polling profile (or a single
device) sets **Learn MAC addresses every N seconds**; 0 means never. From
4.47.0 the shipped default is 3600 (one hour) rather than 0, so fleet-wide
MAC-to-port search works the day a switch is added rather than only once
somebody finds the setting; an existing install upgrading into this release
keeps 0 wherever it was set explicitly; only a profile or device that had
never set the field at all — where "inherit" meant "never" by accident —
picks up the new hourly default. Five minutes is a fine setting to switch
down to once you know the load is affordable. A switch that is down or
whose last poll failed is not walked.
A MAC that leaves a port is not erased on the next walk: it is kept, marked
absent, with the time it was last confirmed, so the Find box can still say
where it was; entries no walk has refreshed for the retention window (a
week by default, set under **Nodes → Settings**) are then
dropped.

**Vendor and Location can be read from an OID you choose.** Vendor is
normally worked out from sysObjectID (an IANA arc assignment) with a sysDescr
keyword fallback, and Location is sysLocation. Plenty of gear puts its real
vendor or its site name in a proprietary scalar instead, so a device or a
whole polling profile can name a **Vendor OID** and a **Location OID** in its
edit form; a device's own setting beats the profile's, and blank means the
standard behaviour. Either form of the OID works — the object or its `.0`
instance — since both are asked for in the SNMP request the poller was
already making. **Browse OIDs** offers *Use as vendor* and *Use as location*
on every row, so the OID is picked from a list showing what it currently
returns rather than typed from memory.

A custom vendor changes **what is displayed**, nothing else: the vendor SNMP
detected is kept alongside it and remains what ConfigRX picks its backup
command from, what enables the Cisco per-VLAN MAC-table read, and what
discovery matches a profile against. The device header says which source the
displayed name came from, because an arc assignment, a sysDescr substring
guess and an operator-chosen OID are not equally trustworthy.

**Devices are keyed by IP address and cannot be added twice.** The address
column is unique, adding one that already exists is refused by name rather
than by a database error, and promoting a discovery result whose address is
already a device links to that device instead of creating a second one.
**Add device** validates before it posts — a blank address is flagged on
the field rather than the button silently doing nothing — and a refusal
from the server, a duplicate address included, is shown in the dialog's own
error line instead of vanishing into a rejected request nobody sees.

**Browse OIDs** opens a live view of what the device actually answers,
decoded against every MIB the app knows. It opens on `system`,
`interfaces` and the device's own vendor arc — a few hundred objects,
back in seconds — and an OID box with **Walk from here** reads any other
subtree on demand. The browsing table deliberately does not walk the whole
tree: a switch is tens of thousands of objects and minutes of SNMP, and
nobody reads that in a dialog. Each row shows the OID, its name where a MIB
describes it, the row index, the SNMP type and the value; an OID nothing
describes is shown as its number rather than guessed at, and uploading its
MIB names it immediately. A walk that hits its row or time limit says so
rather than looking complete. This is also how to read a device's
sysObjectID straight off it, which is what identifies its vendor.

**Download full walk** is the whole tree, as a file. It runs as a
background job on the server rather than in the dialog — showing a live
object count and a **Cancel** — and downloads when it finishes. Its header
states the device, the time, and whether the walk completed or was cut
short and why; a truncated walk that looks complete is the failure this
could most easily cause, so it never looks complete when it is not.
Cancelling keeps what has been read so far rather than throwing it away.
The row and time bounds are in Nodes → Settings (100,000 objects and ten
minutes by default) so a device whose agent loops cannot walk forever.

Every on-demand read — the OID browser, the MAC address table and the
DOM/SFP sensors — uses the credential the device **actually answers on**,
which for a profile carrying alternates is not necessarily its primary one.
A walk that still gets nothing names the address, the port and the kind of
credential tried (never the community itself), rather than only reporting
that the device stopped answering.

Clicking a port in the interface list opens that port's own dialog: a
live up/down bandwidth graph of the last hour with **Smoothed** on by
default (a centred moving average, unticked to see the raw per-poll
points), its statistics and
error counters (cumulative and per-second), its link up/down event
history, and DOM/SFP sensor readings — voltage, current, light levels,
temperature — read live over SNMP from devices that expose them via the
standard ENTITY-SENSOR-MIB (values, units and scaling exactly as the
device reports them; devices without it simply show "no DOM/sensor
data"), and the MAC addresses currently learned on that port, with the VLAN each
was learned in where the switch reports one — read live over SNMP from
three forwarding tables in turn: the VLAN-aware **Q-BRIDGE-MIB**
(`dot1qTpFdbTable`, which is what most modern switches actually answer),
then the original **BRIDGE-MIB** (`dot1dTpFdbTable`), and finally, on
Cisco devices only, the **per-VLAN SNMP contexts** classic IOS hides its
forwarding table behind (community indexing, `community@vlan`, with the
VLAN list read from CISCO-VTP-MIB). The first source that returns
anything wins. Devices that answer none of them show "no MAC address
data" instead of an empty table. Per-interface "show run" still appears as a placeholder
until SSH integration lands.

### Topology, neighbours, PoE and STP

From 4.47.0, Nodes walks past the SNMP poll to see the wire itself.

- **LLDP neighbours** (CDP as the Cisco fallback) are walked on their own
  schedule — **Learn neighbours every N seconds**, inherited like MAC
  learning and defaulting to the same hour — and kept with the same
  present/ageing semantics as the MAC table: a neighbour that drops off a
  port is marked absent rather than erased, so a stale link is visible as
  stale rather than gone. A neighbour is best-effort matched to a known
  device by sysName or chassis MAC.
- **A TOPOLOGY subtab** draws the stored neighbour table as a pan-and-zoom
  map, coloured by device status, with port names on hover; an
  unidentified neighbour — seen over LLDP/CDP but not itself polled —
  still gets its own node, dashed, rather than being left out. It exports
  CSV like every other table.
- **The device pane gains NEIGHBOURS and BRIDGE & RF sections.** NEIGHBOURS
  lists what that device's own ports have reported; BRIDGE & RF shows STP
  bridge and per-port state (BRIDGE-MIB) and, for a radio, RSSI, remote
  RSSI and capacity (airFiber/airMAX and Cambium PtP links) as history
  alongside the other metric charts.
- **PoE power draw** — budget and per-port wattage, Cisco's own per-port
  milliwatt object where present — appears on the interface table for a
  device that answers POWER-ETHERNET-MIB. A device is asked for any of
  these tables once and remembered rather than re-asked every poll.
- **From 4.49.0, the neighbours this walk collects can be reviewed and
  turned into an upstream device in one batch**, rather than one Edit
  dialog at a time — see **One outage, one alert**, under Alerts.

---

## Alerts — rule-based alerting and email notification

Evaluates Nodes' device and interface state, incoming SNMP traps, Syslog
messages and IPAM conflicts against a rule table, on the same 0–7
severity scale every other module already uses, opening or incrementing
alerts and optionally emailing about them.

### Working the alert list

- **Alerts can be acknowledged or resolved individually or in bulk.**
  Every row carries a **checkbox** in its first column: tick the rows you
  want, or use **Select all**. A plain click still opens the detail pane,
  unchanged. (Ctrl-click no longer selects — the checkboxes replaced it.)
  Any selection reveals a bulk actions bar with **Acknowledge
  selected** and **Resolve selected**, each applied to exactly the ticked
  alerts in one request — alongside the single-alert buttons in the
  detail pane and the server-wide **Acknowledge all**, which
  deliberately ignores the selection and its confirmation says so.
- **Resolving means resolved.** An alert an operator resolves stays
  closed for that breach run even when its condition still holds: a
  threshold alert re-opens only after the metric has been observed under
  its clear value and then breaches again, and a NetPath path alert only
  after a trace that reached the destination is followed by failing ones.
  Acknowledge is the way to keep an alert on the list while watching a live
  problem; Resolve is the statement that it is handled. The bulk buttons
  report their effect — "Resolved 3 of 4" beside the engine counters — so a
  row somebody else resolved between the tick and the click is visible as
  the one not acted on. A restart of the application forgets which breach
  runs were resolved by hand, so a still-breaching alert can re-open once
  after one.
- **Resolving an outage covers the alerts it was hiding.** "Device not
  responding" absorbs the packet-loss, response-time, CPU, memory,
  interface-counter and poll-overrun alerts of a device that is down. A
  hand resolve of that outage, single or bulk, keeps those covered for as
  long as the device is still down — they used to come straight back on
  the next tick, one new alert and one new email per device, which is what
  made bulk Resolve look as though it did nothing. The cover ends by itself
  when the device answers again, so a device that is up but lossy raises
  its packet-loss alert normally. Acknowledge keeps them covered exactly as
  before. The same discipline now holds for "SNMP authentication failing",
  recorded once when it starts and cleared when SNMP works again, and for
  a DHCP scope alert resolved by hand while the scope stays full.
- **A newly added device is given five minutes before it can raise an
  alert.** A device added a moment ago is usually still being set up —
  wrong community, not cabled yet, still booting — and the alerts that
  produces are about the setup, not about the network. Its alerts are
  held and then raised only if the condition is **still true** when the
  window ends, so a device that really is down is reported a little late
  rather than not at all, and one that settles in never alerts. A one-off
  event that cannot still be true later (rebooted, recovered, a poll
  overrun) is dropped rather than raised late. Held alerts survive a
  restart. The window is **Alerts → Settings → Hold alerts on a newly
  added device**; 0 turns it off. Nothing outside Nodes' device inventory
  is ever held — syslog, traps, IPAM conflicts, DHCP scopes and wireless
  AP events have no device to be new.
- **One outage raises one alert.** A device that has stopped answering will
  also look slow and lossy, and its CPU, memory, interface and storage
  figures stop being measurable — so a single outage used to arrive as five
  or six emails saying the same thing in different words. **Device not
  responding** now absorbs the alerts it implies: both ping alerts (response
  time, packet loss) and every SNMP-polled metric threshold (CPU, memory,
  storage, interface utilisation, error and discard rates) are resolved into
  it, named in its details so an operator can see where the latency alert
  went, and not raised again while the outage is open. No clear email is sent
  for an absorbed alert — "packet loss recovered" while the device is still
  down would be a lie — and the outage itself still notifies normally.
  **Interface down, up and flapping are never rolled up**: those come from
  status transitions the device reported before it went away, and a port that
  went down for its own reason is a fact about the network rather than an
  artefact of the device being unreachable. Nothing needs un-suppressing by
  hand: when the device answers again the outage resolves, thresholds
  re-derive from live metrics on the very next tick, and a metric that is
  genuinely still breaching re-opens on its own while one that recovered with
  the device stays closed. **Alerts → Settings → Roll implied alerts up**
  turns the whole behaviour off.
- **An access point that stops working raises an alert, not just a red dot.**
  *Access point offline* fires when an AP's connection state becomes offline
  and clears when it leaves that state — distinct from *Access point removed from its
  controller*, which is the controller no longer listing it at all. The two
  are different facts with different remedies, so neither rolls up under the
  other. An AP marked out of service raises neither, the same exemption that
  keeps it from being aged out. Only the controller's own *offline* state
  counts: the image-download states an AP passes through during a firmware
  upgrade, and a deliberately-held standby AP, are not outages, and treating
  them as ones would raise an alert per AP on every fleet upgrade. Note that **Device not responding does not
  cover access points**: that alert comes from Nodes' own device polling, and
  an AP lives in the Wireless module unless it has also been added to Nodes by
  IP in its own right.
- **A recovery says when, and for how long.** *Device recovered* used to
  read "responding again" and leave the length of the outage to be worked
  out from another row's timestamp; it now reads "responding again at
  14:03:21 after 2 h 14 m down" and names the moment the outage began. The
  start comes from the outage alert this recovery resolved — whose opened
  time is the moment the device stopped answering — and from the device's
  own event log when there is no such alert, because the rule was disabled,
  the device muted, the alert held as a newly added device, or it was
  resolved by hand. When neither knows, the duration is left out rather
  than guessed at. Any resolved alert also shows how long it stood, in its
  detail pane.
- **The Object column always shows a hostname when one is known** — the
  same precedence Syslog's Host column uses (Nodes' SNMP-polled name,
  then DNS, then the bare IP as a last resort) — rather than the raw IP
  or a bare manually-set device name it showed before.
- **A device's alerts can be muted for 1, 6, 12 or 24 hours.** *Mute
  device* sits beside Resolve and Acknowledge in the alert detail, for
  the hours you are working on a box and do not want to be told about it.
  A mute stops what happens **next** — new alerts and the emails they
  would send — and deliberately leaves alerts already open in the list, so
  it never quietly takes work off your screen. Those still **resolve**
  normally when their cause clears; what a mute silences is the mailbox,
  not the list. Muting a switch silences
  its **ports** with it, which is what an operator muting a switch means.
  Nothing needs un-suppressing when the mute lapses: thresholds re-derive
  from live metrics on the next tick and a still-down device keeps
  recording events, so the alerts simply come back. The mute is shown in
  the Nodes device list and in the device's detail header as well as in
  Alerts — a mute nobody can see is a mute somebody will spend an
  afternoon looking for. The button is offered on every alert that is
  about a device — a device alert, or an interface alert, which mutes the
  switch the port is on. It is always in the bar: when the alert is about
  something outside Nodes (a syslog source, a trap from an unpolled host,
  an IPAM conflict, a DHCP scope, a wireless AP) or its device has since
  been removed, or the account lacks write access to Alerts, the button is
  disabled with a line under the bar saying which, rather than absent — a
  control that is silently not there reads as a feature that has gone. A
  read-only account can see what is muted but cannot mute, and sees no
  Resolve or Acknowledge in the detail either, the same gate the bulk
  buttons carry.
- **A whole list or group can be muted in one call, from 4.47.0** —
  **Mute selected**, alongside the other bulk actions — still under the
  same 24-hour ad-hoc cap a single mute has always had.
- **Maintenance windows cover planned work longer than 24 hours.** Named,
  scheduled once or weekly, scoped to a device group or an explicit device
  list, up to fourteen days, creatable ahead of time and endable early.
  While one is active the devices it covers behave exactly like muted
  ones — new occurrences dropped, an interface quiet with its switch, a
  held roll-up notice kept pending until the window lifts — and the device
  list shows the coverage the same way it shows a mute, so a planned
  cutover never looks like an unexplained gap in monitoring. Alerts →
  **Maintenance** is where they are created and ended.
- **Un-acknowledge, single and bulk**, undoes an Acknowledge the same way
  Resolve is undone by the alert simply re-opening — the button and its
  gate sit beside Acknowledge in the detail pane and the bulk actions bar.
- **A poll overrun on a device that is not answering is not reported at
  all.** "Poll taking longer than its interval" is recorded when the
  previous poll is still running as the next falls due — which is exactly
  what a device that has stopped answering causes, since every request in
  that poll spends its full timeout and all its retries. It also arrives
  *first*: a device needs three completed failing polls before it is
  marked down, so the overruns used to lead the outage by two or three
  intervals and the first one got out before anything could suppress it.
  Now nothing is recorded while the device is down **or its last poll
  failed** — no alert, no event row, no Debug line — and an overrun alert
  raised in the moments before an outage is absorbed by *Device not
  responding* like the other polled-metric alerts.

### Rules

- **43 built-in rules** ship enabled: a device not responding, a device
  recovering, a device rebooting, SNMP authentication failing, a device
  needing unsupported SNMPv3 privacy, a poll running longer than its own
  interval, a device whose vendor MIB is missing, an interface going
  down/up/flapping, nineteen CPU/memory/interface-utilization/
  error-and-discard-rate/disk/ping-latency/packet-loss/UPS/
  environmental thresholds, a critical or cold-start SNMP trap, a
  linkDown trap from a device Nodes is not itself polling, a critical
  syslog line, a new IPAM address conflict, an access point removed from
  its controller or gone offline, a DHCP scope running out of leases, and
  three NetPath path rules (below). Seven of the interface and disk
  thresholds among those could never fire before 4.39.0, because nothing
  wrote the metric key they read: the poller now records `if_in_util_pct`,
  `if_out_util_pct`, `if_in_error_rate`, `if_out_error_rate`,
  `if_in_discard_rate`, `if_out_discard_rate` and `disk_pct`, both per
  port and as a device-level maximum, so they are live. Eight more, new in
  4.49.0, read the UPS and environmental metrics described under Nodes:
  UPS on battery, battery low, battery depleted, output load high, and
  ambient/chassis/optic temperature high plus humidity high — three
  separate temperature rules rather than one, because a comms room, a
  switch chassis and an SFP's DOM reading have different normal ranges
  entirely (see Nodes → Devices and polling).
- **Three of those 35 are new in 4.39.0**, and each one reports a failure
  that previously had nobody to report it. `snmp_failing_ping_ok` fires
  when a device answers ping while its SNMP agent has stopped answering —
  the case where a switch sat green with no counters behind it.
  `poll_pool_saturated` fires when every poll worker has been busy for five
  minutes, which is the fleet outgrowing its worker count rather than any
  one device failing. `smtp_failing` fires when the mail path itself stops
  working, and is the one rule whose notification cannot be delivered by
  the mechanism it is about — it exists so the alert list says so.
- **A rule carries three attributes that the rule dialog now edits.**
  Beyond severity, enablement, device filter and thresholds: an
  auto-resolve interval (`auto_resolve_after_s`, blank meaning never), an
  email switch (`notify`, on by default), and the template it uses — which
  for a rule that is not an outage is the generic `event_notice` rather
  than the "is not responding" wording six rules used to borrow.
- **A rule can resolve itself after a set time.** `auto_resolve_after_s` on
  a rule, measured from the last occurrence, closes an alert that describes
  a moment rather than a condition — "device recovered", "device rebooted",
  "interface flapping", a trap, a syslog line — instead of leaving it on the
  list until somebody clicks Resolve. Blank means never, which is the right
  answer for "device not responding". The built-ins are seeded with
  sensible values (an hour for recoveries and poll overruns, a day for
  traps and reboots, a week for "device requires unsupported SNMP privacy")
  and every one is editable in the rule dialog as "Auto-resolve after …
  minutes (blank = never)".
- **A rule can be told not to email.** `rules.notify` defaults to 1; setting
  it to 0 leaves the rule opening and tracking alerts in the list while
  sending nothing. `mib_missing` ships this way, because adding 250 devices
  to a new installation used to produce 250 emails in the first minute.
- **A threshold whose metric has gone stale is not a breach.** A sample
  older than `threshold_stale_s` (900 seconds by default) is treated as
  absent rather than as the current value, so a device that stopped
  answering does not hold a CPU alert open forever with a fortnight-old
  reading, and does not re-raise it on every tick.
- **A built-in rule can be edited** (severity, enabled, which devices it
  applies to by a substring filter, its threshold/clear-threshold/
  consecutive-polls-before-firing where relevant, which template it
  uses) but not deleted — disable it instead. **Interface flapping** has
  two settings of its own: how many link transitions, within how many
  minutes, count as flapping. Left blank they stay at the shipped 3
  transitions in 10 minutes. A custom rule can be added
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
- **A threshold can require a breach to be sustained for a length of
  time** rather than for a number of polls — *Or: sustained for N
  seconds* in the rule dialog, measured between the metric's own sample
  timestamps, so a device that stops being polled cannot accumulate
  breach time while silent. Blank keeps counting polls, which is what
  every rule but one does.
- **Packet loss ships requiring 60 seconds of sustained loss.** A probe
  lost to a busy CPU or a queued ARP is not an outage, and with the
  default of three ping probes per poll a single lost probe already reads
  as 33%, which cleared the shipped 20% threshold on its own. The rule
  dialog says this outright and points at the probe-count setting that
  changes the quantisation, because a threshold of 20% on three probes is
  not really adjustable between 1 and 33.
- **Fixed: "consecutive polls before firing" counted engine ticks.** The
  alert engine ticks every five seconds and a device is polled every
  sixty, so `for_polls = 2` meant "ten seconds"; worse, the count advanced
  whether or not a new sample had arrived, so one bad reading satisfied
  any count about ten seconds later and went on satisfying it for as long
  as the value sat there. The count now advances only when the metric's
  own timestamp moves — which is what the setting always said it did, and
  what the DHCP evaluator already did.
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

### One outage, one alert

A device can be given an **upstream device** on its own form: the switch,
router or firewall it sits behind. It is what turns a site outage into a
single alert, and it is the *only* thing the rollup below trusts — nothing
here is ever inferred and applied for you, on purpose. Nodes has collected
LLDP/CDP neighbours since 4.47.0, and each neighbour is best-effort matched
to a known device, but a neighbour row can go stale between walks and a
name can collide (two sites both naming a switch "core-sw-1"); suppressing a
real, unrelated fault because of a guess is the one failure this feature must
never have, so the neighbour table alone never sets `upstream_id`.

**From 4.49.0, reviewing that guess is no longer one Edit dialog per
device.** `GET /api/nodes/upstream-suggestions` lists every device with no
`upstream_id` set whose own collected neighbours matched another monitored
device, ranked by evidence — a chassis-MAC match rated above a sysName match,
a neighbour nothing has confirmed recently rated down regardless of match
kind — and flags a device with more than one plausible match rather than
picking one for you. An operator reviews the list and accepts a batch in one
call; the whole proposed graph is checked for a cycle no single pair could
show before anything is written, and a batch that would create one is
refused outright, naming the devices involved. This is still a proposal an
operator confirms, never something the rollup applies on its own — the
review is the fix for "two thousand manual edits", not a reason to stop
requiring one.

When a device stops answering and its upstream is also down, the alert rolls up
under the upstream's rather than opening on its own, with a note saying which
device it was implied by. A core switch taking five hundred access switches
with it is one "Device not responding" alert and one email instead of five
hundred of each. When the upstream recovers, every device still down below it
has its own alert re-opened, so nothing is quietly lost in the rollup.

Two details worth knowing. Resolving the parent by hand does **not** release
the children while the parent device is still `down` — that used to produce a
burst of fresh alerts and emails within seconds of an operator tidying the
list. And the chain is followed upward with a depth limit and a cycle guard, so
a mis-typed loop (A upstream of B, B upstream of A) terminates rather than
hanging the engine.

Interface alerts are deliberately **not** rolled up under a neighbouring
device's outage: without a neighbour map there is nothing to roll them up
under, and guessing would hide real faults.

### NetPath destinations

Three rules watch the paths NetPath traces, and all three are deliberately
hard to trip — a path monitor that cries wolf gets turned off.

| Rule | Fires when | Clears |
| --- | --- | --- |
| Destination unreachable | Nothing comes back from the destination on 3 consecutive traces — a quarter of an hour on the default interval | One answered probe |
| Path repeatedly failing | Half the traces in the window did not reach the destination | The share drops back under 20% |
| Latency far above normal | Round-trip time reaches 3x this destination's own warn threshold, on 3 consecutive traces | It falls back under 1.5x |

- **Latency is measured against each destination's own warn threshold**, not a
  fixed number of milliseconds, so one rule suits a LAN hop and a satellite
  link. A warn threshold under 20 ms is treated as 20 ms, because three times a
  few milliseconds is ordinary jitter rather than a degradation. A trace that
  did not reach the destination is not measured at all — its round-trip time is
  to whichever router refused it.
- **The window rule needs enough traces to mean anything.** Its window is the
  longer of an hour and six trace intervals, and it says nothing until at least
  five traces have landed in it. It is the only one of the three that can see a
  path which works intermittently, since counting consecutive failures by
  definition cannot.
- **One broken path is one alert.** An unreachable destination also has failing
  traces and unmeasurable latency, so the unreachable alert absorbs the other
  two for that destination, exactly as *Device not responding* absorbs the
  alerts a dead device implies.
- **A trace that could not run is never an outage.** A traceroute that failed
  on this machine, and a slot skipped because the previous run was still going,
  both record 100% loss by construction; alerting on them would report a
  missing `traceroute` or a badly chosen interval as a network breakdown. They
  produce no sample at all, and leave every count exactly as it was.
- **No per-hop rule, on purpose.** Intermediate routers rate-limit ICMP as a
  matter of policy, so their loss is not a fault signal — the same reason only
  the destination hop decides a trace's colour. The live per-hop probe counters
  are cumulative since the last path change, too, so a hop that was lossy last
  week would keep any average over them high indefinitely. Per-hop figures stay
  a diagnostic on the route graph.
- **A destination that stops being traced resolves its alerts.** Disabling or
  deleting one leaves nothing to re-evaluate, and an alert nothing can clear
  would sit open forever.
- **Consecutive traces are counted as traces.** The alert engine ticks every
  five seconds and a destination is traced every five minutes by default, so
  the count advances only when a new trace actually lands.
- These alerts are visible to anyone with read access to Alerts, whatever their
  NetPath access — the same as DHCP scopes, wireless access points and syslog
  hosts, which also name objects from their own modules.

### Notifications

- **Email over the standard library's `smtplib`** — none, STARTTLS or
  SSL/TLS, with or without certificate verification (turning verification
  off is a deliberate, explicit opt-out, never a silent downgrade). A
  rate limit caps emails per hour; past it, sending is suspended for the
  rest of that hour and logged once, not per suppressed alert.
- **A webhook is a second channel, beside email, from 4.47.0.** An
  operator-configured URL and headers receive a JSON payload carrying the
  same rendered subject an email gets, delivered off the engine's tick
  through its own queue: redirects are refused, HTTPS is required unless
  the URL points at a private network, and it has its own hourly budget,
  separate from email's, since what it rations is attempts rather than
  recipients. Every delivery or failure is recorded on the alert exactly
  as an email attempt is. A roll-up digest (below) goes out as one
  webhook the same way it goes out as one email.
- **A first notification can wait for the roll-up, from 4.47.0.**
  **Alerts → Settings → Hold the first email for N seconds**
  (`notify_rollup_delay_s`, default 240, 0 restores immediate sending) —
  an alert still opens in the UI and the list the instant it is detected;
  only its first *email* (or webhook) is held. It exists because roll-up
  only suppresses a child alert once its parent's own alert has opened,
  and which device a poller reaches first during a mass outage is
  arbitrary — a hundred children can each fire their own email before the
  parent's outage is even recorded. Holding the first notice gives the
  parent time to open and absorb them. Whatever decides the alert's fate
  before the window closes — it is absorbed under a parent, it clears, it
  expires —
  is recorded on the alert as the reason its first notice was never sent,
  and the matching clear email is skipped too, since nobody was told a
  problem began. More than three alerts still due when the window closes
  arrive as one digest email (or webhook) rather than one each, counted
  once against the hourly budget. A restart mid-window loses nothing: what
  is still due is read back from the database, not kept in memory.
- **Mail is sent off the engine's tick.** From 4.39.0 a notification is
  handed to a queue drained by its own thread, so a relay that has stopped
  answering delays mail and nothing else: the rule engine keeps evaluating,
  opening and resolving at its normal cadence. Five consecutive failures
  open a circuit breaker for fifteen minutes — queued mail is completed as
  failed without a connection attempt, and the first job after the cooldown
  is the probe that closes it again. A breaker that opens raises its own
  alert (`smtp_failing`), because "the monitor cannot tell you anything"
  is the one failure that cannot be delivered by email. Every attempt,
  successful or not, is recorded against the alert and counts towards the
  hourly cap, so a suppressed notification leaves a trace instead of
  vanishing into a log ring.
- **Six rules no longer email "is not responding".** `device_auth_fail`,
  `device_unsupported`, `poll_overrun`, `mib_missing`, `interface_down` and
  `interface_flapping` were bound to the outage template, so a missing
  vendor MIB arrived in the inbox with the subject "acc-sw-070 is not
  responding". They now use a generic `event_notice` template —
  "SappiWhere: <rule> — <what>" — and an operator's own template choice is
  never overwritten by the change.
- **An open alert emails once by default**; a re-notify interval can be
  set to repeat while it stays open. An alert that clears — resolved
  automatically by a matching recovery occurrence, or a threshold
  dropping back below its clear value — can send its own notification,
  using the generic "device recovered" template rather than replaying
  the original problem's wording backwards; this is optional and can be
  turned off. **Every resolution notification states when the problem
  cleared and how long it stood**, from three tokens (`recovered_time`,
  `down_since`, `downtime`) that any template can use — a port coming back
  and a threshold falling below its clear value now say so as plainly as a
  device answering again does. It used to say "as of {{last_time}}", which
  on a resolution is when the *problem* last recurred, a moment before it
  cleared.
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

Destinations also feed the Alerts module: an unreachable destination, a path
that keeps failing, and latency far above what that destination is set to warn
at each raise an alert. The rules, their thresholds and why they are hard to
trip are under **Alerts → NetPath destinations**.

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
- **A hop that is a device this app monitors shows that device's name.** A
  router with no reverse-DNS entry read "no PTR record" in the graph while
  showing its sysName in Alerts, NetFlow and Syslog. Hops with no PTR answer
  now fall back to the Nodes inventory at that address, and the hop tooltip
  says the name came from Nodes — "this hop is a device I manage" is the part
  worth knowing, and a PTR-derived name looks identical otherwise. A hop with
  a real PTR record keeps it.

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

**Each destination keeps its own window.** A link you watch by the hour and
one you watch by the minute no longer drag their range onto each other:
selecting a destination restores the window, preset and Follow state you last
left it on, and a destination you have never opened starts on the page default
of the last hour. The windows are remembered in your browser and survive a
reload; entries for deleted destinations are dropped automatically.

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
or use the `‹ − + ›` buttons. **Live** pins the right edge to the
present, and any zoom or pan releases it.

Wheel zoom moves the window on every step but waits a moment before fetching,
so spinning the wheel out several steps costs one query rather than one per
step; the window label tracks the gesture live meanwhile. A response for a
window you have already zoomed away from is discarded rather than drawn.

### Storage

Flows live in their own database so a busy exporter does not contend with the
trace scheduler. Retention, a row cap and a file size cap all apply.

---

## SNMP Trap — trap and inform receiver

A receiver, a search, and an hourly histogram, graphically the same shape as
Syslog. Receive-only in the sense that matters here — this module never sends
an SNMP request; it listens. (Two sentences that used to sit in this paragraph
said there was "no SNMP polling yet" and "no alerting engine yet". Both have
been wrong for several releases: **Nodes** polls with GET and GETBULK, and
**Alerts** is a rule engine over device events, traps, syslog, IPAM conflicts
and thresholds. Traps reaching this receiver are evaluated by it.)

From 4.39.0 a trap whose SNMPv3 authentication **fails** is dropped rather than
stored. The digest was always computed and counted; it was never enforced, so a
forged v3 trap was stored and could open an alert. The `reject_failed_auth`
setting controls this and defaults to on; traps that cannot be verified at all
(an unknown user name, or noAuthNoPriv) are counted separately as "unverified"
and still stored, because refusing them would silently discard the v1 and v2c
world. A per-source rate limit bounds what one device in a debug loop can do to
everyone else's history.

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
slower as the database fills. Clicking an hour narrows the search to it and
shows **Return to live**, as on Syslog.

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
errors inside an otherwise busy hour is visible rather than swamped. A legend
names the severities present and the axes carry counts and times. Clicking an
hour narrows the search to it, unticks **Live** and shows **Return to live**;
hovering gives the per-severity breakdown.

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

Three views inside one tab, switched locally: Subnets & Hosts (the default
view when the tab opens), Conflicts, and DHCP. Subnets & Hosts works on
every platform; DHCP needs a Windows host (below) and its subtab is
disabled and explained, rather than opening onto a page that can never
load, wherever it isn't available.

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
per browser. Its Alive column, and the Find box's results (above), draw up
and down with the same shape-and-colour status mark every other module's
tables use, rather than a colour of their own; an address that has never
once answered is `none`, not `fail`, matching what the sidebar donut
already calls "never seen" rather than an outage. **Last
reply** is when an address last actually answered;
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

**Switching servers keeps the scope you were looking at**, where the new
server has one with the same scope identifier — comparing the same subnet
across two servers no longer means finding it again in the sidebar every
time. Where the new server has no such scope it falls back to that
server's first, and from then on that is the scope a further switch looks
for. A background poll never moves the selection either.

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
- **Per AP: status, name, client count, model, MAC address, response
  time, and tx power** — the last shown per-radio, since a real AP has more than one
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
- **Response time is a real per-AP round-trip.** The controller reports
  each AP's own IP in the session table this module already walks, so
  finding it costs no extra SNMP; the AP is then pinged once per poll
  cycle. This is the one place the module reaches past the controller —
  everything else it knows comes from that single walk — and the sweep is
  bounded so a controller carrying a rack of APs cannot stretch a cycle.
  An AP that does not answer ICMP shows blank rather than 0 ms, and an
  offline AP is not probed at all. **IP** is available as a column too.
- **Sort by any column** — click its heading, the same way every other
  table in the app sorts.
- **Settings → Radio tx power** forces dBm or the percentage reading where
  auto-detection gets it wrong.
- **Choose which columns to show** in Settings → Columns. The six above
  are the defaults; Controller, VDOM, WTP id, Radios, Radio modes,
  Channels, Radio clients and Last seen can be added. The list is the fields the
  controller's own SNMP tables report, so adding one costs no extra
  polling; Response and IP are there too.
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

- **Settings and backups both work on a selection.** Tick the checkbox on
  each row (or "select all") to reveal the bulk actions bar.
  **Settings for selected** covers everything the single-device dialog
  does — whether to back the devices up, SSH port, username, password and
  vendor override — applied as one shared value to every ticked device,
  the same shared-value bulk pattern Nodes' own bulk operations use.
  Every field defaults to *leave unchanged*: a blank box or a dropdown
  left alone never overwrites what a device already had, and only the
  fields you actually set are applied. Backing up is a real three-way
  choice, so a batch can be switched **off** as well as on — the earlier
  bulk dialog could only ever turn it on. A password is stored only when a
  username is given with it, since the pair is what gets encrypted.
- **Back up selected** queues every ticked device at once, and reports
  which were queued, which were already queued, and which have backups
  switched off — id lists, not a bare count, because "9 of 12" leaves you
  to work out which three. A device with backups disabled is deliberately
  skipped rather than backed up anyway. If the worker is stopped, the
  whole request fails once with that reason rather than reporting the same
  thing per device.
- **Selecting a device shows its stored backups** — timestamp and size —
  and selecting a backup shows its raw config text in a read-only panel.
  There is no editable field and no save-back action anywhere in this
  module: it only ever pulls a config, never pushes one, and there is no
  free-form command box anywhere in its UI or API.
- **Opening a stored backup needs only ConfigRX read, not write** — seeing
  what changed on a switch is a narrower thing than being trusted to
  change it, and a read-only account's click on a backup answers that
  question instead of being refused outright. The one case still guarded
  is a backup a device is deliberately configured to keep unredacted: read
  it without ConfigRX write and it comes back through the same redaction
  pass the diff view below always applies to both sides, rather than as
  the secrets themselves.
- **Diff two backups, from 4.47.0.** A unified diff between any two of a
  device's stored backups — adjacent by default — gated exactly like
  reading a backup itself. Both sides are re-redacted before the diff
  runs regardless of what was stored, so a changed secret is elided
  rather than ever appearing in the diff text, and two backups that
  hash the same short-circuit to an empty diff before redaction is even
  asked to run.
- **A backup is only stored when it differs from the device's previous
  one** (compared by SHA-256 hash) — an unchanged config updates that
  device's last-checked time without growing the database. **Back up
  now** forces an immediate pull for one device, the same "do it now"
  convention Nodes' own **Poll now** uses. A device with backups switched
  off shows the button disabled with that reason rather than hiding it
  outright, and a failed attempt toasts the device and the reason instead
  of only flipping the button's label to *Failed*.
- **Exactly one fixed, read-only command per vendor**, matched against
  the device's vendor as Nodes already detected it over SNMP (or an
  explicit override, for a vendor Nodes didn't identify): Cisco IOS/IOS-XE,
  NX-OS and IOS-XR all `show running-config`; Cisco Small Business
  (SG/CBS) the same, after `terminal datadump`; Cisco ASA the same, after
  `terminal pager 0`; Cisco WLC (AireOS) `show run-config`, after `config
  paging disable`; FortiOS `show full-configuration`; Junos `show
  configuration`; MikroTik RouterOS `/export`; HP/Aruba `show
  running-config` — each preceded, where the platform needs it, by that
  one session-scoped pagination-disable command. An unrecognized vendor is
  skipped with a clear error rather than guessed at.
- **A platform whose login lands in user EXEC, not privileged, escalates
  first.** Cisco ASA is the one that ships this way: before its
  pagination-disable command, ConfigRX sends the literal `enable` and,
  when the device's own prompt asks for one, the enable secret stored for
  that device (below) — never a secret from anywhere else. A capture that
  never actually reaches privileged mode is refused rather than stored.
  Past that one step, ConfigRX still never enters a device's configuration
  mode and never sends anything beyond its fixed pager-off, enable and
  show-config commands.
- **A stored backup can be deleted**, one at a time or several at once from
  the backups list's own checkboxes. Deleting the **most recent** backup is
  called out separately in the confirmation: a new backup is only stored when
  it differs from the last one, so once the top row is gone the next run
  records the device's current config as a change even though nothing on the
  device changed.
- **A backup in progress is visible.** The device row reports *queued…* and
  *backing up…* rather than sitting on the last completed attempt for the
  whole run, and the Back up now button follows the same states through to the
  outcome instead of saying "Queued…" and going silent.
- **The Vendor column shows the vendor the backup will actually use**, and a
  dropdown filters on it. A per-device vendor override steers which
  show-config command runs, but the list used to show what Nodes detected — so
  a device could read `cisco` and back up as `hp` with nothing to show for it.
  An overridden value is marked as one.
- **A capture runs until the device is finished, not until it goes quiet.**
  A backup used to end on a pause in the output, and a switch answers
  `Building configuration...` instantly and then thinks for several seconds
  before streaming — so the stored "backup" was those two lines. ConfigRX
  learns the device's prompt from the login banner and reads until that
  prompt comes back, which is what a person waits for. **Capture timeout**
  (ConfigRX → Settings, 180 seconds by default) is only a ceiling on that
  wait: a fast switch still finishes the moment its prompt returns, and a
  large config over a slow link is given the minutes it genuinely needs.
- **Pager prompts are answered, not waited out.** A device that stops
  mid-config at `--More--` is waiting for a keypress, so ConfigRX sends a
  single space and keeps reading. That space is a fixed in-band answer to a
  prompt the device raised — no newline, no text — so it cannot execute
  anything, and the rule above is unchanged: the only things ever *run* on a
  device are the vendor's fixed pager-off lines and its show-config command.
- **A truncated capture is refused rather than stored.** A read that hit the
  capture timeout, that could not get past the device's pager, that ends on
  "Building configuration...", or that is too short to be a config (judged
  against a lower bar when the device gave its prompt back, since a small
  MikroTik export really is only a few lines) is
  recorded as a **failed attempt naming the reason**, and nothing is written
  to the backup history. A partial capture stored as a good version is worse
  than no backup at all: it becomes the newest version, the next real backup
  reads as an enormous change, and a restore from history hands someone a
  fragment.
- **A capture that completed but is suspiciously small is stored and
  flagged, not silently treated as a real change.** One under a fifth of
  the size of that device's previous stored backup did reach the device's
  own prompt, so it isn't refused outright — but it's marked `suspect`
  rather than `changed`, with its own count in the backups summary,
  because storing it as an ordinary change would make the next diff read
  as though the entire configuration had been deleted.
- **The SSH password is encrypted at rest** (see `CREDENTIAL-SECURITY.md`)
  and is never returned by any API response — only whether one is stored.
  It is decrypted only in memory, immediately before connecting, and
  discarded the moment the connection attempt finishes.
- **An enable secret can be stored per device**, beside the SSH username
  and password in the same single-device credential dialog, with a hint
  that it is only needed on a platform whose login lands in user EXEC
  rather than privileged EXEC. It is protected exactly like the SSH
  password — encrypted at rest, decrypted only in memory right before it's
  sent, never returned by any API response — and leaving the field blank
  on a save leaves a stored secret alone; **Clear credential** clears the
  enable secret along with the password rather than leaving it behind,
  unreachable, for the device.
- **Backing up with the worker stopped says so.** "Back up now" used to
  report success and do nothing: the queue it went into was never being
  drained. It is now refused with a message naming the reason, and the
  Start worker button is the fix it points at.
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
- **It names the paramiko this process is actually running.** "I installed
  3.4 and it still says the algorithms were removed" has one answer, and
  it is worth being able to see rather than deduce: pip installs into
  whichever interpreter it was run from, and a *downgrade* cannot take
  effect until the app restarts, because Python caches imported modules
  for the life of the process. ConfigRX → Settings and the module's own
  status line therefore report the loaded version **and the file it was
  loaded from**, and whether legacy key exchange is implemented by it and
  currently offered — before anything fails, not only in the error text
  of a backup that already failed. A failed connection also logs the key
  exchanges and host-key types actually offered into its Debug event
  detail, so "we offered these and the device refused" can be checked
  against the device's own logs.
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
  text across both messages and details. **All** and **None** beside the
  category boxes set every one at once, so narrowing to a single category
  is None then one tick rather than ten untick.
- **Scroll to newest**, **Pause**, **Clear** and **Export** — the last writes the
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
| **Settings** button, top right of ConfigRX | Worker on/off, backup interval, capture timeout, retention (days and per-device count) |
| **Add** / **Edit** on a destination | That destination's own probe settings, and — Edit only — continuous per-hop probing |

The Settings tab holds only what crosses module boundaries. Reverse DNS is the
clearest case: NetPath uses it to name hop addresses and NetFlow to name flow
endpoints. ASN/owner lookup sits beside it for the same reason and can name a
different query server, since a resolver good enough for internal reverse DNS
may not be able to reach the public internet, which the ASN lookup needs.

**The Settings tab has seven subtabs of its own** — General, Data &
retention, Sign-in, Users, Tokens & directory, Maintenance and Modules —
addressable in the URL (`#/settings/users`) the same way every other
module's subtabs are. **Modules** is one list linking to all nine
per-module Settings dialogs (Nodes, Alerts, Routes/NetPath, NetFlow, SNMP
Trap, Syslog, IPAM, FortiWireless, ConfigRX) rather than each module's own
Settings button being the only way to reach it — one place that answers
"where is the setting for X" without already knowing which tab it lives
on.

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
**Acknowledge all** and the bulk **Acknowledge selected** / **Resolve
selected** confirm too — they delete nothing, but none can be undone one
row at a time, and **Acknowledge all**'s confirmation spells out that it
takes every open alert on the server rather than the rows you ticked. Buttons that clear
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
ConfigRX, SSH, Settings, Debug and — new in 4.39.0 — Admin, set from
**Settings → Users** (itself gated on Admin write access). The grid there
offers a handful of **role presets** — Viewer, Operator, Admin — that fill
it in one click as a starting point rather than a lock (one manual change
and the picker relabels itself Custom), a **copy from** field that seeds a
new account's grants from an existing one's, and a **generated initial
password** rather than an empty field left for someone to fill in by
convention. Write implies read; no grant at all means no
access. A tab the signed-in account can't read is hidden from the tab
bar. A write-gated control within a tab the account *can* read — an
add/edit/delete button, a module's Settings gear — is **disabled and says
why**, in the control's tooltip and in one line under the bar it sits in.
It is not hidden: a control that is silently absent reads as a feature the
install does not have, which turned permission questions into support
calls about missing features. Both are purely client-side conveniences,
since the server enforces the identical check on every route regardless of
what the browser shows. Because it is a disable rather than a hide, it is
re-evaluated on every poll, so a grant given or taken away mid-session
takes effect within a couple of seconds instead of waiting for a reload. The Dashboard
tab is the one exception: it's always visible and simply omits whatever
sections the signed-in account can't read, rather than being gated as a
whole.

**Administering the application is its own grant, from 4.39.0.** Settings
write used to be root by accident: it could grant itself every other
module, reset anybody's password and make the host replace its own code.
**Admin** now covers exactly that work — adding, editing and removing
accounts, changing anybody's grants, resetting another account's password,
the maintenance actions that delete retention data, reading the audit log,
and the `updates_enabled` setting that decides whether self-update may run
at all — while Settings write goes back to meaning "may change how the
application is configured". Nobody can edit their own grants, and the last
account holding Admin write cannot be reduced, so an install cannot lock
itself out. On upgrade every account that held Settings write is given
Admin once, so nothing an operator could do the day before stops working;
from there the two can be granted and taken away separately.

**Changing your own password always works**, even with zero access to
Settings — it lives in an "Account" control in the top bar, independent
of the Settings tab, rather than being gated like everything else there.
The same dialog also shows how long the current session has left and
gathers **Appearance · this browser** — theme and the kiosk launcher (see
**On a wall**, above) — a per-browser preference that has no business
being on a page of settings the server stores for everyone. Resetting a
*different* account's password requires Admin write, same as adding,
editing or removing an account.

An install upgrading from a version before this shipped keeps every
existing account's access exactly as it was — the first time the
permissions table is created, every account already on file is granted
full write access to every module, so nobody loses anything on upgrade.
Only accounts created after that point start with whatever grants an
admin explicitly assigns in the Add User dialog. **SSH is the one module
that is not handed out that way**: it arrived later, it lets an account
type anything into a device, and ConfigRX write access was never meant to
imply it — so on upgrade only accounts that already hold write access to
every other module receive it, and everyone else gets it when an
administrator grants it.

**API tokens let a script authenticate without a stored password, from
4.47.0.** Admin write can issue a bearer token for any account — `sw_api_`
plus 256 bits from `secrets`, shown once — that carries exactly that
account's own grants, never wider. It is checked wherever the session
cookie is, but it is not a session: it never enters the session store, so
no idle timeout applies to it and it can never be used to open a kiosk. A
token is revocable, and every issue and revoke is audited.

**An account can authenticate against an LDAP directory instead of a local
password, from 4.47.0.** Set on the account (`auth_source: ldap`) in the
Add/Edit User dialog: the account keeps no local password hash and every
sign-in binds against the configured directory instead, over LDAPS or an
explicitly opted-in cleartext connection. If the directory cannot be
reached, sign-in fails closed rather than falling back to anything stored
locally, and the attempt is audited as its own action. Local accounts are
completely unaffected, and the last local administrator can never be
converted to `ldap` or demoted — an LDAP outage can never be the reason
nobody can reach the application at all.

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
  There is one capability above the modules: **`admin`**, which gates user
  administration, permission changes, the in-application update and the
  destructive maintenance actions. It exists because "Settings: write" used
  to imply all of those without saying so. Accounts that held Settings
  write when the database was upgraded were granted `admin` automatically,
  nobody can grant it to themselves, and the last account holding it cannot
  be stripped of it.
- **Storing a credential off Windows now needs one thing configured: a
  passphrase.** Every stored secret goes through Windows DPAPI on Windows,
  unchanged; from 4.47.0 it goes through a portable, scrypt-backed secret
  store on Linux, macOS or BSD once an operator sets
  `NETPATH_SECRET_PASSPHRASE_FILE` (a file private to the account the
  service runs as — recommended, since it survives an unattended restart)
  or `NETPATH_SECRET_PASSPHRASE` (weaker: readable by anything else running
  as the same account, documented as the fallback for tooling that can only
  set an environment variable). Configured, the SNMPv3 authentication
  password, the SSH password ConfigRX and the terminal need, an
  authenticated SMTP password and the wireless controller's SNMP
  credential all work the same as on Windows. The DHCP credential is the
  one exception, passphrase or not: it depends on PowerShell/RSAT rather
  than on credential encryption, so it stays Windows-only regardless.
  Configure nothing, and the behaviour off Windows is exactly what it
  always was: none of those credentials can be saved, and the API says so
  plainly rather than accepting the value and losing it. What the portable
  store protects, and what it
  deliberately does not — it is not tied to one machine the way DPAPI is,
  and it protects against a stolen copy of the data directory rather than
  against an attacker who gains the account the service itself runs
  as — is set out in full in `CREDENTIAL-SECURITY.md` §10, along with the
  two designs that were considered and rejected before this one.
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
  fixed, deliberately short allow-list — six Cisco platform families (IOS/
  IOS-XE, NX-OS, IOS-XR, Small Business, ASA, WLC), FortiOS, Junos,
  MikroTik, HP/Aruba — is the entire set of "show config" commands this
  app knows how to run; a device Nodes couldn't identify, or one from a
  vendor not in that list, needs a vendor override set to a value on the
  list before it can be backed up, or it's skipped with a clear error.
  This is deliberate: adding a new vendor means adding its fixed,
  read-only show-command to `configrx_vendors.py`, never accepting one
  typed into a field.
- **ConfigRX never pushes a configuration change, to any device, ever.**
  There is no code path in this module capable of it — no free-form
  command box, no "push config" action, nowhere in its UI or API. It only
  ever pulls a read-only snapshot. The interactive SSH terminal on the
  Nodes page is a different feature with its own permission (see Nodes →
  Drill-down); it shares ConfigRX's stored credential and host-key store,
  not its code.
- **Host keys are remembered.** The first connection to a device — a
  backup or a terminal session — stores its SSH host key; a later
  connection presenting a different key is refused and the backup fails
  with an error naming both fingerprints and when the old one was first
  seen. The device dialog shows the stored fingerprint with a **Forget**
  button (ConfigRX write, the permission that already chooses the port and
  credential the next connection uses) for a device that was genuinely
  replaced; the terminal window offers **Trust the new key** (SSH
  permission) for the same case. A key belongs to an address and port, not
  to a device row: removing a device from Nodes leaves its key in place, so
  a replacement at the same address is still challenged, and a second
  device row at that address keeps its protection.
