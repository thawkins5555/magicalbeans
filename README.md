# SappiWhere

See also: `FEATURES.md` for what each module does, `INTERNALS.md` for how
each one actually works — file by file, mechanism by mechanism —
`NETWORK-AND-STORAGE-REQUIREMENTS.md` for ports and protocols, `CHANGELOG.md`
for the build history, and `CREDENTIAL-SECURITY.md` for exactly how passwords
and stored credentials are protected.

New in this release: `QUICKSTART.md` takes a new installation from unpacked to
first device polled, `BACKUP-RESTORE.md` covers the ten database files, and
`RUNBOOK.md` is what to do at 02:00 when something has stopped.

## Contents

- [NetPath](#netpath) — the traceroute monitor this application started as
- [Install and run](#install-and-run) · [Accounts](#accounts)
- [A shortcut with no terminal window](#a-shortcut-with-no-terminal-window)
- [The service console](#the-service-console)
- [Using it](#using-it) — [concurrency](#concurrency-and-timeouts), [the three lanes](#the-three-lanes), [snapshots](#snapshot-vs-aggregate), [hop names](#hop-names), [silent hops](#silent-hops)
- [How status is decided](#how-status-is-decided) · [No reply vs refused](#no-reply-vs-refused)
- [Dashboard](#dashboard) — the landing page and its tiles
- [Linking to a device, a port or an alert](#linking-to-a-device-a-port-or-an-alert)
- [NetFlow](#netflow) — [protocols](#protocol-support), [settings](#settings-1), [views](#views), [zooming](#zooming-without-a-wheel), [storage](#storage), [troubleshooting](#when-no-flows-arrive)
- [IPAM](#ipam) — [subnets and hosts](#subnets--hosts), [conflicts](#conflicts), [DHCP](#dhcp)
- [Debug](#debug)
- [Settings](#settings-2) · [Retention and rollups](#retention-and-rollups)
- [Updating a remote server](#updating-a-remote-server)
- [Running as a service](#running-as-a-service) — systemd and NSSM
- [Layout](#layout)
- [Notes and limits](#notes-and-limits)

Tabs at the top of the window, in order: **Dashboard**; **Nodes**, an SNMP poller and device inventory; **Alerts**, a rule engine over Nodes/traps/syslog/IPAM with email notification; **NetPath**, a scheduled traceroute monitor; **NetFlow**, a flow collector; **SNMP Trap**, a trap and inform receiver; **Syslog**, a message collector; **IPAM**, subnet discovery, conflict detection, and read-only DHCP visibility; **Wireless**, a Fortinet access-point dashboard; **ConfigRX**, SSH configuration backups; **Debug**, a live view of what the background threads are doing; and **Settings**.

## NetPath

Scheduled traceroutes to destinations you add, stored in SQLite, with two views:

- **Route graph** — one column per hop, one box per address seen at that hop, showing its address and reverse-DNS name. Two boxes in a column means the path diverged. Edge thickness is the share of traces that used that link, so the usual route reads as a thick spine and detours as thin branches.
- **Timeline** — three lanes on one shared time axis: round-trip time, packet loss, and up/down status along the bottom. Zoom, pan, and drag to select a range; the route graph redraws for whatever range you select.

## Install and run

The interface is in a browser. Two ways to start the service behind it.

**With the service console** — a window showing whether the server is up and
who is connected:

```bash
pip install -r requirements.txt
python -m netpath
```

**Headless**, for a service manager:

```bash
python -m netpath --headless --port 8443
```

Then open `http://<host>:8443/` and sign in. A fresh install starts with
**admin / admin** and will insist on a new password before anything else.

Pass `--cert` and `--key` to serve TLS. Without a certificate the session
cookie travels in the clear, so on anything but a trusted segment, set one up.

### Accounts

Managed on the Settings tab (itself gated on Settings write access): add a
user with an initial password they must change, remove one, and see who
is signed in. Every account has an explicit read/write grant per module
— write implies read, no grant means no access — set from the same Add
User dialog or edited later per account. Changing your own password
always works regardless of any of that, from an "Account" control in the
top bar rather than the Settings tab.

Passwords are stored as salted scrypt hashes at the parameters OWASP currently
recommends, never in plain text and never recoverable. If the only account's
password is lost, the way back is to stop the service and delete the `users`
table from `app.db`; the default admin account is recreated on the next start
with full access to every module. The exact mechanics — hashing parameters,
login throttling, session cookie flags, the permission model, and how IPAM's
optional stored DHCP credential, Nodes' optional SNMPv3 credential, Alerts'
optional SMTP credential, Wireless' optional SNMP credential and ConfigRX's
optional SSH credential are protected — are in `CREDENTIAL-SECURITY.md`.

**Idle timeout** signs a session out after 10 minutes with no real mouse or
keyboard activity in the browser — adjustable on the Settings tab, under
Sign-in. It tracks presence rather than the tab being open: the background
polling every open tab does on its own does not count, only genuine input
does, sent as a heartbeat at most every 20 seconds. A banner gives 60 seconds'
warning before signing out, with a button to stay signed in. There is also an
absolute session length, 12 hours by default, that applies regardless of
activity.

PySide6 is only needed for the console window. A headless install needs nothing
but the standard library, so `requirements.txt` is optional on a server.

Requires Python 3.10+ and the system `traceroute` (macOS/Linux) or `tracert`
(Windows, built in). On Debian/Ubuntu: `sudo apt install traceroute`. Shelling
out to the OS tool means no raw sockets and no root.

The databases live beside each other; override any of them:

```bash
python -m netpath --db ./netpath.db --flow-db ./flows.db --syslog-db ./syslog.db --app-db ./app.db
```

The default folder is `%APPDATA%\netpath-monitor\` on Windows and
`~/.local/share/netpath-monitor/` elsewhere. That folder name is unchanged so
existing databases keep working.

## A shortcut with no terminal window

`python.exe` always opens a console window behind whatever it runs.
`pythonw.exe` is the same interpreter without one, and sits beside it in every
standard install. A shortcut pointing at that starts the service console alone:

```
Target:     C:\Python312\pythonw.exe -m netpath
Start in:   C:\apps\sappiwhere
```

Make it by hand — right-click the desktop, **New → Shortcut**, paste the target
above, then set **Start in** on the shortcut's Properties page. Copy it into
`%APPDATA%\Microsoft\Windows\Start Menu\Programs` for the Start Menu, or into
`%ProgramData%\Microsoft\Windows\Start Menu\Programs` for every user on the
machine.

(Earlier releases of this file described a `deploy\Install-Shortcut.ps1` that
would build the shortcut for you. There is no `deploy/` directory in this
repository and there never was; the reference has been removed rather than
left to send you looking. On a server you almost certainly want a real service
instead — see [Running as a service](#running-as-a-service).)

Nothing is lost by hiding the terminal. Everything that would have been printed
to it — collector errors, tracebacks from a worker — is captured and shown in
the console's own **Console output** pane, which is the more useful place for it
anyway. If the console was started from a terminal, a **Show terminal window**
box appears to hide or restore it without stopping the service.

## The service console

`python -m netpath` opens it. It answers the questions you would otherwise need
a browser for:

- Is the server running, on what URL, with how many requests and open
  connections.
- Who is connected — one row per client address, with request and error counts,
  first and last seen, and user agent.
- What was recently requested, with status and timing.
- The listener settings, with **Apply and restart**.
- A summary of the NetPath, NetFlow, Syslog and DNS collectors.
- **Console output** — anything printed by the service, captured so it survives
  running with no terminal.

Closing the console stops the service. For unattended running use `--headless`
under NSSM or a scheduled task on Windows, or a systemd unit on Linux.

## Using it

**Add** a destination and set how often to trace it, how many hops and probes, the per-probe timeout, and the thresholds that turn a trace amber. The dialog shows the worst case those settings imply. **Trace now** runs one immediately without waiting for the schedule.

### Concurrency and timeouts

**Settings**, top right of the NetPath tab, holds how many traces run at once (4 by default), how long traces are kept, and the defaults a new destination starts with.

The number that matters is the worst case per destination, `max hops × probes × probe timeout + 15s`. At the defaults that is 195 seconds. A healthy destination finishes in a few seconds because the trace stops when it arrives; an unreachable one walks every hop to its timeout and pays the full price, holding a worker the entire time. Two or three dead destinations can therefore starve the pool and leave healthy ones sitting in **queued** on the Debug page.

Two ways to fix that, and the first is usually better. Lowering a destination's **max hops** to just above its normal path length cuts the worst case directly and costs nothing when the path is healthy — a 12-hop path capped at 15 hops drops the worst case from 195s to about 105s. Raising **concurrent traces** also works: these threads spend their time blocked on a subprocess rather than on the CPU, so 16 is not extravagant.

The probe timeout is per destination because it should follow the path. A local gateway does not need 2 seconds; a satellite link might need more.

Both pools resize without a restart. Traces already running finish on the old pool.

### The three lanes

Splitting the metrics apart means you can tell similar-looking incidents from each other at a glance, which a single status strip can't do:

| Pattern | Reading |
| --- | --- |
| RTT spikes, loss flat, status amber | Congestion or a longer route — traffic is getting through, slowly |
| RTT flat, loss climbs, status amber | Something is dropping packets without adding delay, often a saturated link or a rate-limiting device |
| Status red, both lanes stop | The destination stopped answering entirely |
| Status dark, all lanes empty | No poll ran — the app was closed or monitoring was paused |

RTT bars scale to the tallest bar in the current window, with the peak printed on the right of the lane, so the lane is always a relative view rather than an absolute one. Loss bars scale to a fixed 0–100% and shade amber through red as they climb; a clean poll draws a thin green line along the bottom rather than nothing, so measured-and-fine stays distinct from not-measured. Status keeps the worst verdict in the block.

All three lanes use the same blocks, so a column is the same slice of time in every lane and you can read straight down. Status sits at the bottom, directly above the time axis, so the verdict reads as the baseline the two measurement lanes above it are explaining. `TimelineView.LANE_ORDER` controls the stacking if you want it another way. Hovering gives one tooltip with all three figures, and the crosshair spans all three.

One block is one poll. The block width comes from the selected destination's trace interval, not from the pixel width of the strip, so a 60-minute window on a destination polled every minute draws 60 blocks and each one is a single scheduled trace. Change the interval and the blocks resize on the next refresh.

Boundaries snap to a wall-clock grid rather than to the left edge of the window, so a block covers the same slice of time whether you pan, zoom or let the window slide forward. A dark block is a poll that produced no trace — the app was closed, or monitoring was paused — rather than a gap in the drawing.

When a window is long enough that one block per poll would fall below three pixels, the block grows to a whole multiple of the interval instead. The caption next to the Timeline heading always states which case you're in: `1 block = 1 poll (60s)` or `1 block = 5 polls (5m)`. A block is never a fractional number of polls.

The range control has presets from 15 minutes to 30 days, plus **All data** and **Custom range**. On top of that:

| Action | Result |
| --- | --- |
| Scroll | Zoom around the cursor |
| Ctrl-drag or middle-drag | Pan |
| Click | Pin that instant — the route graph shows that single trace |
| Drag | Select a range — the route graph aggregates over it |
| Right-click or double-click | Clear the pin and the selection |
| **Follow now** | Keep the window's right edge pinned to the present |

Small blue ticks above the strip mark buckets where the route changed. The line underneath the strip is average round-trip time to the destination.

In the route graph, the `−` and `+` buttons in the Route header zoom about the centre of the view and **Fit** reframes the whole route, so a wheel is never required. Drag to pan, and hover a box for full statistics. The current level is shown between the buttons and clamps between 15% and 600%.

The graph is rebuilt from scratch whenever new data lands, but your zoom and scroll position survive it. Until you touch the zoom, the view keeps fitting itself to whatever the route currently is; once you pick a level it is held through refreshes, expanding or collapsing silent hops, and pinning a snapshot. **Fit** hands control back to automatic, and switching destination resets to fit as well. The route canvas is deliberately light against the dark chrome — it is the pane you read addresses and names off, and it prints and screenshots cleanly for a ticket. `theme.py` keeps the two palettes separate: `CANVAS_*` for anything drawn on white, the rest for the surrounding UI.

### Snapshot vs aggregate

Clicking a block puts the route graph into snapshot mode: it draws one stored traceroute exactly as it came back at that moment, not an average. Every box reads 100%, because a single run either saw that address or didn't, and the header reports that trace's status, RTT and loss. A vertical marker on the timeline shows where you're pinned, and **Return to live** in the Route header takes you back.

This is the view for answering "what did the path look like when the alert fired." The aggregate view tells you a route splits 90/10; the snapshot tells you which way this particular trace went.

If you click a block with no trace in it, the graph says so rather than silently drawing the nearest one — the search tolerance is one block width. Dragging a range clears the pin and returns to aggregate; monitoring keeps running while pinned, so nothing is lost by leaving it there.

### Hop names

Traces run numerically and reverse DNS happens separately, in a background thread, cached in the `hostnames` table for a week. Asking traceroute to resolve inline would add a lookup to every hop of every run for routers whose names essentially never change. A box shows `resolving…` until the lookup lands, then either the name or `no PTR record` — plenty of backbone routers genuinely have none.

### Silent hops

Two or more consecutive hops where nothing ever replied collapse into one dashed marker reading `N hops, no reply`. That pattern is almost always one provider's core declining to send ICMP time-exceeded, so the run tells you only its own length. Click the marker to expand it, and click the tab above an expanded run to fold it back. **Expand silent hops** in the Route header unfolds every run at once and keeps unfolding new ones. Hop numbers stay true throughout — a collapsed run doesn't renumber what follows it.

## How status is decided

Only the destination hop decides the verdict. Intermediate routers routinely rate-limit or ignore ICMP, so a middle hop showing 100% loss while the destination answers is normal and is not a fault.

| Status | Meaning |
| --- | --- |
| Green — healthy | Destination answered, loss and latency under the target's thresholds |
| Amber — degraded | Destination answered, but loss or latency crossed a threshold |
| Red — no reply | The destination never answered and nothing said why |
| Orange, hatched — refused | A router answered with an ICMP unreachable |
| Violet — probe failed | The trace itself could not run: DNS failure, missing binary, timeout |

### No reply vs refused

These are separated because they are different faults with different owners.

**No reply** is silence. The probes went out and nothing came back. The destination might be down, might be up but filtering ICMP, or the path might be blackholed somewhere past the last router that answered. You cannot tell which from the trace alone.

**Refused** means a router sent back an ICMP destination-unreachable and named itself doing it. That is far more actionable: routing works up to that router, the router is healthy enough to generate ICMP, and something at or beyond it is rejecting the traffic on purpose. `!X` and `!A` (administratively prohibited) usually means an ACL or firewall rule — often a change someone made. `!H` means the router has no working path to the host on its directly connected network. `!N` means no route to the network at all.

A refused trace still gets an RTT. Windows prints the `reports:` line with no timing columns, but the router that refused has usually answered an earlier TTL, and that measurement is real — it is the round trip to the point where the traffic was rejected. Where the refusing router never answered earlier, the last responding hop is used instead. Either way the app is explicit that the figure is not to the target: the snapshot header reads `23.3 ms to 52.232.1.46`, the timeline tooltip says `(to 52.232.1.46, which refused)`, and the debug detail spells out `measured to 52.232.1.46, not the target`.

The app records the code and the address that sent it. The refusing hop is outlined in orange in the route graph with a `REFUSED !X` badge, the timeline tooltip names the code and the router, and the snapshot header reads in full, for example `!X administratively prohibited from 10.10.5.1`.

Refused blocks are hatched as well as coloured. Two shades of red are not a safe way to carry a distinction this important, and the hatching survives both a screenshot at low zoom and colour-blind viewing.

Windows and Unix report this differently, and `tracert` has two shapes for it. The common one carries no timing columns at all:

```
  2     8 ms     7 ms     8 ms  10.64.0.1
  3  52.232.1.46  reports: Destination host unreachable.
```

Both that form and the variant with timings are parsed, as is `traceroute`'s `!H`. If `tracert` prints the refusal on a line of its own after the numbered hops, it is attributed to the last router that answered.

Existing stored traces are not reclassified. Only the verdict is kept in the database, not the raw output, so anything recorded as *no reply* before this stays that way; new traces classify correctly.

One consequence worth knowing: a refused trace often shows 0% loss, because the router that refused did reply. The status lane carries the verdict; the loss lane is measuring something real but not the thing that failed.

Route changes are recorded as a path signature per trace and drawn as ticks, but they do not change the colour on their own — a route change with no latency or loss impact isn't a fault.

## Dashboard

The tab every sign-in lands on, and until 4.39.0 an empty placeholder. It is now
a grid of tiles built entirely from data the application already had, refreshed
on its own timer (`dashboard_refresh_s`, five seconds by default, on the
Settings tab):

| Tile | Shows |
| --- | --- |
| **Fleet** | devices up, down, unknown and failing authentication, as counts that link through to the Nodes tab filtered to each |
| **Open alerts** | a count per severity, coloured by the worst severity open — not by the total, so one severity-1 outage is never hidden behind forty severity-6 notices |
| **Collectors** | NetFlow, trap and syslog listeners: running or not, packets in, `kernel_dropped` if the kernel has discarded anything, and the alert engine's `backlog` if it is behind |
| **Storage** | each database's size against its cap, worst first |
| **Poller** | busy and queued work against the pool size, and whether the pool has been saturated long enough to raise `poll_pool_saturated` |
| **Top offenders** | ten worst by device events in 24 h, interface events, alerts, round-trip time, packet loss and CPU — six short lists, each row linking to the device |

Every tile is a link. Clicking a count sets the destination tab's filter, so
"14 down" opens Nodes showing those fourteen rather than the whole fleet.

`kernel_dropped` deserves a note, because it is new and it is the number that
tells you the truth. A UDP collector that is behind does not lose messages in
the application — it loses them in the kernel's socket buffer, before any of
this code sees them, and until 4.39.0 nothing counted that. The listeners now
read the drop counter for their own bound port every few seconds. A non-zero
value means messages arrived and were discarded; the application logs the first
increase as an error and shows the count in the collector's status strip.

## Linking to a device, a port or an alert

The address bar now carries the current selection, so a page can be linked to,
bookmarked, and pasted into a ticket. Back and Forward work.

| Route | Opens |
| --- | --- |
| `#/nodes` | a tab, by name — the same for `#/alerts`, `#/netpath`, `#/netflow`, `#/snmp`, `#/syslog`, `#/ipam`, `#/wireless`, `#/configrx`, `#/debug`, `#/settings` |
| `#/nodes/device/1234` | that device selected, detail pane open |
| `#/nodes/device/1234/port/7` | that device with interface index 7 open |
| `#/alerts/998` | that alert |
| `#/netpath/12` | that destination's route graph and timeline |
| `#/configrx/device/1234/backup/57` | one stored backup |
| `#/snmp/551`, `#/syslog/8802`, `#/wireless/3` | one trap, one message, one access point |

Switching tab pushes a history entry; changing the selection within a tab
replaces it, so Back leaves the tab rather than walking every row you clicked.
A route naming something that no longer exists opens the tab and says so
instead of failing silently.

## NetFlow

A collector that listens for exported flow records, stores them, and charts them.

### Protocol support

NetFlow v5, NetFlow v9 and IPFIX (v10), all on one UDP socket — the version is read from each packet, so a mixed fleet needs no extra configuration. v9 and IPFIX are template-driven: an exporter sends a template describing its record layout, and records arriving before that template can't be decoded. The status strip counts those as *awaiting template*; they stop appearing once the exporter's template refresh comes round, usually within a minute or two.

sFlow is a different protocol (packet sampling rather than flow export) and is not supported.

### Settings

Collector configuration is under **Settings**, top right of the NetFlow tab.

| Heading | What's there |
| --- | --- |
| Collector | Enable, bind address, UDP port, receive buffer, accepted versions |
| Sampling | Assumed rate, and whether to trust the rate the exporter reports |
| Exporters | Accept-any or an allow list, plus ifIndex-to-name mapping |
| Storage and Display | Retention, row cap, top N, chart interval, name resolution |

Reverse DNS threads, timeout and cache lifetime are shared with NetPath and live on the Settings tab.

Sampling matters more than it looks. A router sampling 1 in 1000 reports a thousandth of the real traffic; every byte and packet figure in the app is multiplied by the rate before display. v9 and IPFIX exporters usually advertise their rate in an options template, which is read automatically. v5 carries it in the header. Set the assumed rate manually for exporters that report nothing.

Interface names are entered one per line as `10.20.0.1:1=LAN-Core`. Without them the interface dimensions show raw ifIndex numbers, which are meaningless without the router's config in front of you.

### Views

Traffic over time is a stacked area chart of the top series plus an *other* band, in bits per second, so it reads the way link utilisation is usually quoted. Below it, a top-N bar chart and a flow record table share the width.

### Zooming without a wheel

The traffic chart has its own window, independent of the **Window** preset which just sets the starting span. Nothing needs a scroll wheel:

| Action | Result |
| --- | --- |
| Drag across the chart | Zoom into that range |
| `‹` `−` `+` `›` buttons | Pan back, zoom out, zoom in, pan forward |
| Ctrl+= / Ctrl+- | Zoom in / out |
| Ctrl+Left / Ctrl+Right | Pan by a quarter window |
| Ctrl+0 or Home | Back to the preset span, ending now |
| **Follow now** | Keep the right edge pinned to the present |

Zooming while following holds the right edge at the present and pulls the left edge in, so live traffic stays on screen. Zooming while not following works about the centre instead. Panning turns following off, since the two would fight. The range is shown next to the buttons and clamps between one minute and about four months.

The shortcuts are all Ctrl-modified deliberately: bare `+` and arrow keys would be captured by the filter boxes and dropdowns as soon as one had focus.

**Group by** re-slices all three: application (service port), protocol, source, destination, conversation, exporter, ingress or egress interface, source or destination AS, or ToS. Filters for source, destination, port, protocol and exporter apply everywhere at once, and clicking a bar filters to it where that makes sense.

**Resolve names** swaps addresses for reverse-DNS names in the flow table, using the same cache and threads as NetPath's hop names. Only the busiest endpoints of the last hour are queried, and only while it is on.

The application dimension uses the lower of the two port numbers, the usual heuristic for telling a service port from an ephemeral client port. It's a heuristic: peer-to-peer traffic and services on high ports won't classify cleanly.

### Storage

Settings, accounts and the shared reverse-DNS cache are in `app.db`, separate from all three record files. Flows go in their own `flows.db` beside `netpath.db`. A busy exporter writes far more rows than the path monitor does, and SQLite allows one writer at a time; sharing a file would make every flow batch contend with the trace scheduler.

Pruning runs every 15 minutes against the retention window, the row cap and the database size cap on the Settings tab. Sizing depends entirely on flow rate — a branch router might write a few hundred thousand rows a day, a datacentre edge far more. Watch the row count in the status strip for the first day and set the cap from what you see.

### Proving the socket receives

**Send test packet** on the NetFlow status strip sends a valid NetFlow v5 header declaring zero records to the collector over loopback, and shows the PowerShell command that does the same thing by hand. The packet counter should move within a few seconds while flows stored stays at zero — that is the point, it separates "the socket is receiving" from "the decoder is producing flows".

### When no flows arrive

The status strip is the first place to look. It now reports the last packet time, so `Listening on 0.0.0.0:2055 (UDP) · no packets yet (7 min)` distinguishes a socket that is bound but silent from one that is receiving.

The counters separate the failure modes. *Packets* counts datagrams that reached the socket; *flows stored* counts records decoded from them. Packets rising with flows flat means the exporter is sending but its template hasn't arrived yet, or its version is switched off. Packets flat means nothing is reaching the socket at all.

On Windows the collector binds with `SO_EXCLUSIVEADDRUSE` rather than `SO_REUSEADDR`. Windows lets two processes share a UDP port under `SO_REUSEADDR` and delivers datagrams to only one of them, so a leftover instance silently swallows every packet while the visible one looks healthy and idle. Exclusive binding turns that into a plain "port already in use" error at startup.

### Getting flows to it

Point exporters at this machine on UDP 2055 (or whatever port you set). On Cisco IOS the shape is `ip flow-export version 9` plus `ip flow-export destination <this-host> 2055`, with `ip flow ingress` on the interfaces you care about; other vendors differ but need the same three things. Windows Firewall will need an inbound UDP rule for the port, and the collector must be running for flows to be stored — it does not backfill.

## IPAM

Subnet discovery, IP conflict detection, and read-only visibility into a
Windows DHCP server's scopes and leases. Three views inside one tab: Subnets
& Hosts, Conflicts, and DHCP.

### Subnets & hosts

Add a subnet in CIDR form — `10.20.3.0/24` — and it is pinged address by
address on a schedule, then the local ARP table is read once for whatever
answered. A subnet bigger than the configured limit (1024 addresses by
default) is refused rather than swept partway; narrow it or raise the limit
under **Settings** on the IPAM tab if you mean to sweep something that size.

MAC addresses, and everything that depends on them, only show up for a
subnet on the same network segment as whichever machine runs SappiWhere —
ARP doesn't cross a router. A remote subnet still reports which addresses
answer, just not who they are.

Each subnet shows a small utilization donut in the sidebar — alive,
previously-up-but-down-now, and never-seen — and opening one shows a bigger
version above its host table with the counts spelled out. Only an address
that has genuinely answered at some point counts as "seen before, now down";
one that's been swept a hundred times without ever replying stays "never
seen," which is what tells an empty subnet apart from a full one at a glance.
**Clear stats**, in a subnet's Edit dialog, empties its discovered hosts and
scan history to start the inventory over without removing and re-adding it.

### Conflicts

Two ways one opens: the same address answers as two different MACs across
scans, or a scanned MAC disagrees with what a polled DHCP server's own lease
record most recently said for that address — including a reservation, which
is the one "known good" value worth checking against. Neither clears itself;
**Mark resolved** dismisses one once you know what happened.

### DHCP

Add a server by hostname or address and it's polled on a schedule for its
scopes, leases and reservations. Nothing here can write anything back — no
scope, reservation or lease can be created, changed or removed from
SappiWhere.

**Two ways to authenticate, chosen per server** — full detail, including
exactly how a stored credential is encrypted and why, is in
`CREDENTIAL-SECURITY.md`:

**Leave the username and password blank** to use whichever Windows account
runs SappiWhere, or a matching entry in Windows Credential Manager if that
account doesn't already have DHCP read rights:

```powershell
cmdkey /add:dhcp01.corp.local /user:CORP\svc-sappiwhere-ro /pass:********
```

Nothing is stored by SappiWhere either way — this is the same call any script
running as that account would make, over the DHCP server's own RPC endpoint.
It needs the `DhcpServer` PowerShell module (RSAT: DHCP Server Tools)
installed on the machine running SappiWhere, not on the DHCP server.

**Fill in a username and password** in the server's Edit dialog to store a
credential instead — the same shape of field as software that takes a DHCP
read-only account directly. It's encrypted with Windows DPAPI before it
touches disk, tied to this specific machine: not a plaintext secret in
`ipam.db`, and not something that would still work if that file were copied
elsewhere. **Test connection** in the same dialog checks it before you save,
and works against whatever's currently typed even if you haven't saved yet.
This path uses PowerShell remoting rather than RPC, so it needs WinRM
reachable on the DHCP server instead — `Test-WSMan dhcp01.corp.local` from
any Windows machine confirms whether it already is; `winrm quickconfig` on
the DHCP server turns it on if not. The account only needs DHCP read rights
there, typically membership in the local `DHCP Users` group — it does not
need to be an administrator on the DHCP server.

Storing a credential needs Windows, since DPAPI is a Windows-only API; on any
other platform the fields are refused with a message pointing at Credential
Manager instead, which works regardless of what SappiWhere itself runs on.

## Debug

A third tab showing what the background threads are doing. Nothing here is written to disk — it is a live view, discarded when the app closes.

**Trace workers** is one row per destination: whether a trace is in flight right now, how long the current one has been running, when it last ran and how long that took, when it next runs, and the last verdict. It answers "is it stuck or just not due yet."

The **Elapsed** column counts up live for anything in flight, and colours itself: blue while normal, amber past half the timeout budget, red and marked `overdue` past the point where the trace would be abandoned. The budget is `max_hops × probes × 2s + 15s`, the same figure the tracer uses to kill a run, so the warning and the timeout can never disagree.

A destination can also show **queued**, meaning it is waiting for a free worker rather than tracing. With more destinations than the four worker threads, that is normal and brief; if it is persistent, the workers are the bottleneck. The status strip separates the two — `1 of 4 trace workers busy, 2 queued`.

**Event log** is every trace, reverse-DNS lookup and collector event as it happens. Selecting a row shows its detail on the right — for a trace, that is the exact command line that ran, the resolved address, the path, the stored trace id and the raw traceroute output as the OS printed it. That is the view for arguing with what the parser produced.

Reverse-DNS events are the ones people expect to see and often don't. Results are cached for a week, so once the first sweep has named every hop address there is genuinely nothing left to log. The status strip shows the cache state — `DNS cache 37/41 named, nothing pending` — so silence is distinguishable from a stalled resolver, and **Re-run reverse DNS** under Maintenance on the Settings tab clears the cache to force a full re-lookup, which is also what to use after your DNS team adds PTR records.

Filter by destination, by category (Traceroute, Reverse DNS, NetFlow, System, Errors), or by free text matched against both the message and its detail. **Follow** keeps the newest event visible, **Pause** stops the table updating while the log keeps recording, and **Export** writes the currently filtered view to a text file — the thing to attach to a ticket.

The buffer holds the last 3000 events and each detail is capped, so a machine left running for a week costs a bounded amount of memory. Individual packets are not logged: the collector records the first packet from each exporter, each template received, and decode failures, but not the thousands of ordinary packets in between.

## Settings

Configuration sits at whichever level it actually belongs to.

| Where | What |
| --- | --- |
| **Settings** tab | Reverse DNS, view refresh interval, data file locations, maintenance |
| **Settings** button, top right of the NetPath tab | Concurrent traces, trace retention, defaults for new destinations |
| **Settings** button, top right of the NetFlow tab | Listener, sampling, exporters, flow storage and display |
| **Settings** button, top right of the IPAM tab | Scan interval and limits, DHCP poll interval, retention |
| **Add** / **Edit** on a destination | That destination's interval, hops, probes, timeout and thresholds |

Both module buttons sit in the top right of their page and share one style, so the same control is in the same place whichever module you are in.

The Settings tab holds only what crosses module boundaries. Reverse DNS is the clearest case: NetPath uses it to name hop addresses and NetFlow to name flow endpoints, so it belongs to neither. The same goes for the refresh interval and the two database files.

Changes on the Settings tab are staged, with **Apply changes** and **Revert**, because they restart the resolver and retime the views. The module dialogs commit on OK.

Nothing needs a restart. The trace pool and DNS pool resize live, and the collector rebinds its socket.

Destination defaults are worth a note: they seed the Add dialog only. Changing them leaves existing destinations alone, which is what you want when adding a batch of similar sites without disturbing what is already running.

### Retention and rollups

Three settings on the Nodes settings dialog decide how much metric history
survives, and from 4.39.0 they mean what they say.

| Setting | Default | What it bounds |
| --- | --- | --- |
| `sample_retention_days` | 3 | how long a raw sample is kept, per sample |
| `sample_row_cap_per_metric` | 5,000 | the newest N samples **per metric**, not per database |
| `rollup_retention_days` | 400 | how long the hourly min/avg/max rollups are kept |

The cap is the one that changed. It used to be applied to the `samples` table as
a whole: 50,000 rows survived each maintenance pass no matter how many devices
were writing, so on any fleet above a hundred devices almost all history was
deleted every fifteen minutes and no chart could draw a line. It is now applied
per metric, in chunks, so each metric keeps its own newest N samples and a large
fleet does not evict a small one.

The hourly rollup runs. `compact_rollup()` existed since 4.30 and nothing ever
called it, so `samples_hourly` was always empty and any chart window wider than
the raw retention returned no points. Maintenance now aggregates each complete
hour into min, average and max, keeps a watermark so it never re-does work, and
— importantly — no longer deletes the raw rows it aggregated. Charts read raw
samples inside three days and hourly rollups beyond that; the settings dialog
says so beside the retention field.

What this means in practice: a 48-port switch polled every 120 seconds writes
about 100 metrics per poll, so three days of raw samples is roughly 65 MB per
1,000 devices, and the hourly rollups that replace them are about a fiftieth of
that. `NETWORK-AND-STORAGE-REQUIREMENTS.md` has the per-port arithmetic.


## Updating a remote server

Downloading, uploading to OneDrive and downloading again works but is three
steps too many. Two better options, depending on how much you want to set up.

### PowerShell remoting, no setup

If WinRM is enabled on the target — it usually is on a domain-joined Windows
Server — copy straight from your workstation:

```powershell
$s = New-PSSession -ComputerName mill-mon-01
Copy-Item .\sappiwhere\* -Destination C:\apps\sappiwhere -Recurse -Force -ToSession $s
Remove-PSSession $s
```

There is no wrapper script for this; earlier releases of this file described a
`deploy\Update-SappiWhere.ps1`, and no `deploy/` directory exists in the
repository. Do the same steps by hand, in this order, because the order is the
part that matters:

```powershell
$s = New-PSSession -ComputerName mill-mon-01
Invoke-Command -Session $s { Stop-Service SappiWhere }            # 1. stop it
Invoke-Command -Session $s { Rename-Item C:\apps\sappiwhere C:\apps\sappiwhere.bak }
Copy-Item .\sappiwhere\* -Destination C:\apps\sappiwhere -Recurse -Force -ToSession $s
Invoke-Command -Session $s { Start-Service SappiWhere }           # 4. start it
Remove-PSSession $s
```

Then confirm the version, as below. The databases are never touched by any of
this — they live outside the application folder by default, in
`%APPDATA%\netpath-monitor\`. Read `BACKUP-RESTORE.md` before an upgrade that
crosses a schema change; the short version is that a copy of the ten `.db` files
taken while the service is stopped is a complete, restorable backup.

On Linux the equivalent is `systemctl stop sappiwhere`, replace the directory,
`systemctl start sappiwhere`. There is also an in-application update path — the
**Update** button on the Settings tab — which is **disabled by default from
4.39.0**: it does nothing until an administrator turns on the `updates_enabled`
setting.

Once it is on, that button installs **whatever is at the tip of `main`**. It
does not check a signature, a tag or a digest, so anyone who can push to this
repository can choose the code every install runs at the next press of it, on
hosts holding your SNMP communities and SSH credentials. This is known,
deliberate and temporary — 4.39.0 briefly required a published, digest-verified
release instead, which left every install already in the field unable to reach
4.39.0 through the button at all. See the SECURITY NOTE at the top of
`netpath/selfupdate.py` for what has to change to put the verified path back.
If you cannot accept that exposure, leave `updates_enabled` off — the default —
and replace the directory by hand.

### A file share, even less setup

If you can reach the server's disk, skip the cloud round trip entirely:

```powershell
Expand-Archive .\sappiwhere.zip -DestinationPath \\mill-mon-01\c$\apps\ -Force
```

### Git, the durable answer

If there is an internal Git server, a `git pull` on the target is the least
error-prone update there is, and it gives you the history and a way back. That
is the one worth setting up if this is going to be updated often.

### Confirming the update landed

Every build reports its version, so there is no guessing whether the copy
worked or the browser cached the old page:

```powershell
Invoke-RestMethod http://mill-mon-01:8443/api/state | Select-Object version
```

The version also shows in the top right of the browser interface and in the
service console's title bar.

Note what that version actually tells you: it comes from the server, so it
changes the moment the service restarts, whether or not the open page has
reloaded. A browser that has not reloaded is still running the old JavaScript
while showing the new number. The page itself is served `no-store` and the
scripts carry validators, so a plain reload is enough — but after an update,
reload before concluding that something is missing.

## Running as a service

The web mode is a long-running process with no window, so on a server it wants
a supervisor.

On **Windows**, [NSSM](https://nssm.cc) is the least surprising option. It wraps
any executable as a real service with automatic restart:

```
nssm install SappiWhere C:\Python312\pythonw.exe "-m netpath --web --host 127.0.0.1 --port 8443"
nssm set SappiWhere AppDirectory C:\apps\sappiwhere
nssm set SappiWhere Start SERVICE_AUTO_START
nssm set SappiWhere AppExit Default Restart
nssm start SappiWhere
```

Run it as a dedicated low-privilege account, not `LocalSystem`: stored
credentials are encrypted with DPAPI *for the account that stored them*, so the
account the service runs as is the account that must store them, and a service
account that cannot log in interactively is exactly what you want holding them.
`nssm edit SappiWhere` opens the dialog for that.

A scheduled task set to "run at boot, whether or not the user is logged on"
also works and needs nothing installed, but it will not restart the process if
it exits.

On **Linux**, a systemd unit:

```ini
[Unit]
Description=SappiWhere
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 -m netpath --web --host 127.0.0.1 --port 8443
WorkingDirectory=/opt/netpath
Restart=always

[Install]
WantedBy=multi-user.target
```

Add `User=sappiwhere` and `Group=sappiwhere` and give that account the data
folder; from 4.39.0 the application creates `~/.local/share/netpath-monitor/`
mode `0700` and its database files mode `0600`, so a shared server does not
expose one operator's SNMP communities to another. `systemctl enable --now
sappiwhere` after `daemon-reload`.

Run this way the service keeps collecting whether or not anyone has a browser
open, and with no console window to close by accident.

Note what a Linux service **cannot** do: it cannot store any credential.
Encrypted credential storage is Windows DPAPI only, so SNMPv3 authentication
passwords, the SSH password ConfigRX and the terminal need, an authenticated
SMTP password, the wireless controller's SNMP credential and the DHCP
credential can all be entered on Windows and none of them on Linux. A Linux
deployment polls SNMPv1/v2c and v3 noAuthNoPriv, relays mail through a server
that does not ask for authentication, and does not back up configurations. This
is a deliberate limitation, not an oversight — `CREDENTIAL-SECURITY.md`
explains what a portable secret store would have to promise and why the
application would rather refuse than promise it weakly.

## Layout

The interface lives entirely in the browser now — `web/static/` — talking to
the backend over the JSON endpoints in `web/api.py`. `console.py` is the only
thing left with a native window: the small service-status console described
above, not the application itself.

```
netpath/
  __main__.py      CLI entry point: parses args, starts headless or console mode
  console.py       the service console window (PySide6): status, connections,
                   listener settings, captured output
  tracer.py        runs traceroute/tracert, parses output into hops
  db.py            SQLite schema and queries for traces and hops
  monitor.py       background scheduler and thread pool, status classification,
                   reverse-DNS resolver
  analysis.py      traces -> topology graph, traces -> timeline buckets
  theme.py         palettes, fonts and stylesheet for the console window
  nfdecode.py      NetFlow v5/v9/IPFIX packet decoding and template cache
  collector.py     UDP listener and batched writer for NetFlow
  flowdb.py        flow storage, settings, aggregation queries
  services.py      port and protocol names, byte and rate formatting
  syslogparse.py   RFC 3164 and RFC 5424 message parsing
  syslogd.py       syslog UDP/TCP listener
  syslogdb.py      syslog storage, rollup counts, trigram substring search
  namelookup.py    reverse DNS: system resolver, direct PTR query, nslookup
  procs.py         launching child processes with no console window
  auth.py          password hashing, users, sessions, login throttling
  eventlog.py      bounded in-memory event buffer shared by all workers
  appdb.py         shared settings and accounts (app.db)
  dpapi.py         Windows DPAPI wrapper for encrypting stored DHCP credentials
  ipamdb.py        subnet, host, conflict storage and queries
  ipam_scan.py     subnet ping sweep and ARP-table reconciliation
  ipam_dhcp.py     polls a Windows DHCP server's scopes, leases and reservations
  ipam_worker.py   background scheduler for subnet scans and DHCP polling
  web/
    __init__.py    exports Service and WebServer
    service.py     headless service: opens the databases, starts the
                   scheduler, resolver and collectors
    api.py         JSON endpoints — one function per route, grouped by
                   NetPath, NetFlow, syslog, IPAM, auth and users
    server.py      HTTP(S) server: routing, sessions/cookies, access log,
                   serving static/
    static/        the browser interface
      index.html   the twelve-tab shell
      login.html   the sign-in page
      tokens.css   the design tokens: every colour, text size and
                   spacing value, with its measured contrast
      app.css      shared styling for the whole interface, on the tokens
      app.js       shared plumbing: server calls, tab switching, the
                   refresh loop, modals
      netpath.js   NetPath tab: route graph, timeline, destinations
      netflow.js   NetFlow tab: traffic chart, top-N, flow table, filters
      syslog.js    Syslog tab: message table, filters, collector settings
      ipam.js      IPAM tab: subnets & hosts, conflicts, DHCP
      debug.js     Debug tab: trace workers, event log
      settings.js  Settings tab: reverse DNS, refresh interval, database
                   locations, maintenance
      login.js     sign-in form and idle/session-timeout handling
```

Traces and hops go in `traces` and `hops`, with resolved names in `hostnames`. A hop row exists per distinct address seen at that TTL in that run, plus a null-address row when every probe timed out — that is what lets a single run show a fork, and what makes the `no reply` boxes appear in the graph.

## Notes and limits

Windows `tracert` always sends three probes per hop and reports one address per hop, so within-run divergence only shows up on macOS and Linux; on Windows you still see divergence across runs, which is the more common case anyway.

Parsing is tolerant of the common GNU, BSD/macOS and Windows output shapes, including `!H`-style ICMP annotations and `<1 ms`. If you hit an unusual `traceroute` variant, `_parse_unix` in `tracer.py` is where to adjust.

Traces run in a thread pool, one in flight per destination. The UI polls the database every two seconds and only rebuilds the route graph when something actually changed.

Current sizes are shown beside each cap on the Settings tab and in the service
console. `NETWORK-AND-STORAGE-REQUIREMENTS.md` covers the file locations, what
each database holds and why, and what bounds their growth. **Delete traces older than 90 days**, under Maintenance on the Settings tab, prunes and vacuums; roughly, one destination traced every five minutes with 15 hops is about 4 MB a month.

## Worth adding next

A second graph pane for comparing two destinations that share upstream hops;
CSV export of the current window's traces. (Alerting on NetPath status
transitions used to be listed here and has shipped — the rules are
`netpath_unreachable`, `netpath_path_unstable` and `netpath_latency_high` on the
Alerts tab.)
