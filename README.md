# SappiWhere

See also: `FEATURES.md` for what each module does, `INTERNALS.md` for how
each one actually works — file by file, mechanism by mechanism —
`NETWORK-AND-STORAGE-REQUIREMENTS.md` for ports and protocols, `CHANGELOG.md`
for the build history, `CREDENTIAL-SECURITY.md` for exactly how passwords
and stored credentials are protected, and `RUNBOOK.md` for what to do at
02:00 when something has stopped. [Quick start](#quick-start),
[Releasing](#releasing) and [Backup and restore](#backup-and-restore) are
sections of this document.

## Contents

- [NetPath](#netpath) — the traceroute monitor this application started as
- [Install and run](#install-and-run) · [Quick start](#quick-start) · [Accounts](#accounts)
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
- [Releasing](#releasing)
- [Backup and restore](#backup-and-restore)

Twelve tabs at the top of the window, in frequency order with a hairline marking where each of four groups used to be labelled: **Dashboard** and **Alerts**, a rule engine over Nodes/traps/syslog/IPAM with email notification; **Nodes**, an SNMP poller and device inventory, **IPAM**, subnet discovery, conflict detection, and read-only DHCP visibility, **FORTI-AP**, a Fortinet access-point dashboard, and **CONFIGRX**, SSH configuration backups; **Routes**, the scheduled traceroute monitor (the NetPath module this application started as, named on screen for what it shows), **NetFlow**, a flow collector, **Syslog**, a message collector, and **SNMP Trap**, a trap and inform receiver; **Settings** and **Debug**, a live view of what the background threads are doing. Who is signed in, the **Account** control — which also holds the version number and the per-browser Appearance settings — and **Sign out** sit beside the tabs rather than inside the scrolling strip, so narrowing the window never hides them; below about 480 px those three collapse to icons to leave more of the strip for the tabs themselves.

## NetPath

Scheduled traceroutes to destinations you add, stored in SQLite, with two views:

- **Route graph** — one column per hop, one box per address seen at that hop, showing its address and reverse-DNS name. Two boxes in a column means the path diverged. Edge thickness is the share of traces that used that link, so the usual route reads as a thick spine and detours as thin branches.
- **Timeline** — three lanes on one shared time axis: round-trip time, packet loss, and up/down status along the bottom. Zoom, pan, and drag to select a range; the route graph redraws for whatever range you select.

## Install and run

The interface is in a browser. Two ways to start the service behind it.

A note on the commands below before they start piling up: this document
writes `python`/`pip`, which is what Linux and macOS give you. A stock
Windows install has no `python` or `pip` on `PATH` at all — only the `py`
launcher, installed alongside every python.org release specifically to be
the one thing that's always there even with several Python versions
installed side by side. Everywhere this document says `python` or `pip`,
a Windows reader runs `py` or `py -m pip` instead.

**With the service console** — a window showing whether the server is up and
who is connected:

```bash
pip install -r requirements.txt
python -m netpath
```

```powershell
py -m pip install -r requirements.txt
py -m netpath
```

**Headless**, for a service manager:

```bash
python -m netpath --headless --port 8443
```

```powershell
py -m netpath --headless --port 8443
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

An account can instead be bound to an LDAP directory (simple bind, LDAPS or
an explicit cleartext opt-in) rather than a local password, and Settings can
issue a scoped API token for a script or another system to authenticate
with instead of holding a session. Local accounts are unaffected either
way, and the last local administrator can never be converted or demoted.

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

```powershell
py -m netpath --db .\netpath.db --flow-db .\flows.db --syslog-db .\syslog.db --app-db .\app.db
```

The default folder is `%APPDATA%\netpath-monitor\` on Windows and
`~/.local/share/netpath-monitor/` elsewhere. That folder name is unchanged so
existing databases keep working.

## Quick start

From an unpacked copy to a device being polled, an alert you trust, and a path
being watched. About twenty minutes, most of it waiting for a poll.

1. **Start the service** (see [Install and run](#install-and-run) above), bound
   to loopback first: `--host 127.0.0.1`. Open it up deliberately once the
   admin password is changed and, ideally, a certificate is in place.
2. **Sign in as `admin`/`admin`.** The server refuses every API call except
   sign-out and the password change itself until you pick a new one. Then,
   straight away, make yourself a second account with the `admin` capability
   on **Settings → Users** — one account is one lost password away from a
   stopped service.
3. **Add a polling profile** — **Nodes → Settings → Polling profiles → Add.**
   A v2c profile with your read community, a 120 s poll interval and ping
   enabled is a reasonable first one; a profile can hold several credentials,
   tried in order, for a fleet with more than one community.
4. **Add your first device** — **Nodes → Add device**, address plus that
   profile, name left blank so it takes `sysName`. It polls within its
   interval; selecting it forces a three-second cadence while you watch.
   Fill in **Upstream device** once you have more than a rack — an outage
   behind it then opens one alert instead of fifty.
5. **Check the poll worked**: a green status, a vendor and an interface count
   within a couple of minutes. `unknown` with no error means not polled yet;
   `auth_fail` means the wrong community; `down` immediately means neither
   ping nor SNMP answered; up with no interfaces on an SNMPv1-only device
   means setting the profile's version to 1.
6. **Add a Routes destination** — **Routes → Add**, an address you care about
   reaching, five minutes, default hops and probes. This is the module that
   answers "is it us or is it them" during an incident.
7. **Turn on email** — **Alerts → Settings → Notifications**, SMTP server,
   port, security mode, From/To, then send a test. On Linux, macOS or BSD a
   stored SMTP password needs `NETPATH_SECRET_PASSPHRASE_FILE` (or the weaker
   `NETPATH_SECRET_PASSPHRASE`) set before the service starts — see
   `CREDENTIAL-SECURITY.md` §10 — otherwise the field refuses the value
   rather than accepting and losing it; an unauthenticated internal relay
   works either way.
8. **The next hour, roughly in order of value**: set `sample_retention_days`
   and `rollup_retention_days` (Nodes → Settings) for the history you want;
   point devices' syslog and traps here (UDP 514/162 — both listeners are off
   by default); run a discovery sweep or bulk-import the rest of the fleet
   (Nodes); fill in Upstream device everywhere; read `RUNBOOK.md` once, before
   you need it; set up [backups](#backup-and-restore); run it as a
   [service](#running-as-a-service) rather than in a terminal.

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

The console itself has no view onto stdout/stderr any more. Anything the
service would print — collector errors, tracebacks from a worker — still
goes to the terminal when it is shown, or to whatever a service manager
captures under `--headless`; nothing is captured in-app. If the console was
started from a terminal, a **Show terminal window** box on its status card
hides or restores that terminal without stopping the service.

## The service console

`python -m netpath` (`py -m netpath` on Windows) opens it. It answers the
questions you would otherwise need a browser for:

- Is the server running, on what URL, with how many requests and open
  connections.
- Who is connected — one row per client address, with request and error counts,
  first and last seen, and user agent.
- RAM and CPU used by the service process.
- The listener settings, with **Apply and restart**.
- A summary of the NetPath, NetFlow, Syslog and DNS collectors.

Closing the console stops the service. For unattended running use `--headless`
under NSSM or a scheduled task on Windows, or a systemd unit on Linux.

## Using it

**Add** a destination and set how often to trace it, how many hops and probes, the per-probe timeout, and the thresholds that turn a trace amber. The dialog shows the worst case those settings imply. **Trace now** runs one immediately without waiting for the schedule.

### Concurrency and timeouts

**Settings**, top right of the Routes tab, holds how many traces run at once (4 by default), how long traces are kept, and the defaults a new destination starts with.

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
| **Live** | Keep the window's right edge pinned to the present |

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

## Display: themes, small screens, the wall

Seven themes — Dark, Light, High contrast, Midnight, Nord, Solarized and
Slate — under **Appearance · this browser**, in the **Account** dialog
reachable from the top bar, stored per browser so a shared workstation
keeps its choice across sign-ins. The layout
works down to a 768 px tablet; every drag works from a finger or a pen, and
pane splitters and column widths can be changed from the keyboard (arrow keys
on a splitter, Alt+Arrow on a column header).

For a wall display open `/?kiosk=1#/dashboard`: no tab strip, a quarter
larger, and a thin bar with the view, the clock and the session's remaining
time. The session is held open only for an account with **no write
permission anywhere** — make a read-only account for the wall; the absolute
session length (`session_max_hours`) still applies and is counted down.

## Dashboard

The tab every sign-in lands on, and until 4.39.0 an empty placeholder. It is now
a grid of tiles built entirely from data the application already had, refreshed
on its own timer (`dashboard_refresh_s`, five seconds by default, on the
Settings tab):

| Tile | Shows |
| --- | --- |
| **Fleet** | devices up, down, unknown and failing authentication, as counts that link through to the Nodes tab filtered to each |
| **Open alerts** | a count per severity, coloured by the worst severity open — not by the total, so one severity-1 outage is never hidden behind forty severity-6 notices |
| **Workers** | all eight background processes — the Nodes poller, alert engine, NetFlow collector, SNMP trap receiver, Syslog collector, IPAM worker, Wireless poller and ConfigRX worker: running or not, packets in, `kernel_dropped` if the kernel has discarded anything, and the alert engine's `backlog` if it is behind |
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
| `#/nodes` | a tab, by name — the same for `#/alerts`, `#/netpath`, `#/netflow`, `#/snmp`, `#/syslog`, `#/ipam`, `#/wireless`, `#/configrx`, `#/mapper`, `#/debug`, `#/settings` |
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
| **Live** | Keep the right edge pinned to the present |

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

Filter by destination, by category (Traceroute, Reverse DNS, NetFlow, System, Errors), or by free text matched against both the message and its detail. **Scroll to newest** keeps the newest event visible, **Pause** stops the table updating while the log keeps recording, and **Export** writes the currently filtered view to a text file — the thing to attach to a ticket.

The buffer holds the last 3000 events and each detail is capped, so a machine left running for a week costs a bounded amount of memory. Individual packets are not logged: the collector records the first packet from each exporter, each template received, and decode failures, but not the thousands of ordinary packets in between.

## Settings

Configuration sits at whichever level it actually belongs to.

| Where | What |
| --- | --- |
| **Settings** tab | Reverse DNS, view refresh interval, data file locations, maintenance |
| **Settings** button, top right of the Routes tab | Concurrent traces, trace retention, defaults for new destinations |
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
`%APPDATA%\netpath-monitor\`. Read [Backup and restore](#backup-and-restore)
before an upgrade that crosses a schema change; the short version is that a
copy of the thirteen `.db` files taken while the service is stopped is a
complete, restorable backup.

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

The version also shows in the browser interface's **Account** dialog and in
the service console's title bar.

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

Note what a Linux service can and cannot do about stored credentials. On
Windows, credential encryption is DPAPI, unconditionally. On Linux it needs
one thing configured: a passphrase. Set `NETPATH_SECRET_PASSPHRASE_FILE` to
a file private to the service's own account (recommended — it survives an
unattended restart the way a passphrase typed in cannot) or
`NETPATH_SECRET_PASSPHRASE` directly (weaker: readable by anything else
running as the same account), and SNMPv3 authentication passwords, the SSH
password ConfigRX and the terminal need, an authenticated SMTP password and
the wireless controller's SNMP credential can all be stored exactly as they
are on Windows. The DHCP credential is the one exception, Windows or not —
it depends on PowerShell/RSAT, not on DPAPI, so it stays Windows-only
regardless. With no passphrase configured, the pre-4.47.0 behaviour is
unchanged: none of those credentials can be stored, a Linux deployment polls
SNMPv1/v2c and v3 noAuthNoPriv, relays mail through a server that does not
ask for authentication, and does not back up configurations.
`CREDENTIAL-SECURITY.md` §10 sets out exactly what the passphrase-based
store protects and what it does not — it is not tied to one machine the
way DPAPI is.

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
  trapdecode.py    SNMP trap BER/ASN.1 decoding and encoding, v3 USM auth;
                   well-known trap OID names, enum tables, default severities
  snmptrapd.py     SNMP trap UDP listener
  snmptrapdb.py    SNMP trap storage, rollup counts
  namelookup.py    reverse DNS: system resolver, direct PTR query, nslookup;
                   shared "best-known display name for an IP", used by
                   Syslog, Alerts and NetPath alike
  worker.py        launching child processes with no console window;
                   ago(ts) elapsed-time formatting; the Worker mixin
                   background workers subclass
  auth.py          password hashing, users, sessions, login throttling
  eventlog.py      bounded in-memory event buffer shared by all workers
  appdb.py         shared settings and accounts (app.db)
  dpapi.py         Windows DPAPI wrapper for encrypting stored DHCP credentials
  ipamdb.py        subnet, host, conflict storage and queries
  ipam_scan.py     subnet ping sweep and ARP-table reconciliation
  ipam_dhcp.py     polls a Windows DHCP server's scopes, leases and reservations
  ipam_worker.py   background scheduler for subnet scans and DHCP polling
  nodeoids.py      built-in polled-metric OID catalog for the Nodes poller;
                   also OID constants for FortiGate Wireless Controller
                   polling
  nodepoll.py      NodePoller: the per-device SNMP/ping scheduler
  nodesdb.py       nodes.db: devices, polling profiles, interfaces, state
                   events, discovery, per-port VLAN membership (`vlans`/
                   `vlan_ports`/`port_vlans`, for MAPPER); also the facade
                   over the two files below, so every caller still sees one
                   Nodes database
  nodesseriesdb.py nodes_series.db: polled metrics, their raw samples and
                   the hourly rollups — the tables that grow
  nodesmibdb.py    nodes_mibs.db: uploaded MIB files and the objects parsed
                   out of them
  nodediscover.py  per-device and per-subnet discovery: ping sweep plus
                   best-effort SNMP v1/v2c identification
  snmppoll.py      SNMP wire format for the Nodes poller: GET/GETNEXT/
                   GETBULK builders, response decoder, v1/v2c/v3 assembly
  vendorid.py      vendor identification from a device's populated
                   enterprise OID arcs
  enterprises.py   IANA enterprise-number -> vendor table, for arcs no
                   uploaded MIB describes
  mibcatalog.py    curated catalog of vendor MIB bundles, installed on demand
  mibparse.py      stdlib-only, best-effort MIB text parser
  alertsdb.py      alerts.db: rule definitions, open/acked/resolved alerts,
                   per-device threshold-rule overrides, email templates,
                   notification history, SMTP settings
  alertrules.py    alert rule/occurrence matching, flapping and threshold
                   hysteresis evaluators
  alertengine.py   AlertEngine: the 5-second evaluation scheduler that
                   drains events/traps/syslog/IPAM into alerts
  alertmail.py     alert email: {{token}} template rendering, stdlib SMTP
  fortipoll.py     WirelessPoller: polls FortiGate controllers for managed
                   APs over SNMP
  wirelessdb.py    wireless.db: controller storage and SNMP credentials
  configrxdb.py    configrx.db: backup config storage, keyed to Nodes'
                   own device ids
  configrx.py      ConfigRxWorker: scheduled read-only "show config" pulls
                   over SSH, the backup path's safety boundary; per-vendor
                   allow-list of the exact commands a backup may ever send
  configrx_redact.py     strips secrets (community strings, PSKs, enable
                   passwords) from a captured config before it is stored
  configrx_compliance.py cross-device search over stored configs, with a
                   bounded-regex compiler so a query can't hang; rule sets:
                   must-match/must-not-match checks against each device's
                   latest capture
  mapper.py        MAPPER's pure link-assembly and render-plan layer: folds
                   LLDP/CDP neighbour rows into undirected links, computes
                   each link's drawn strands/collapse/colours; no sqlite3,
                   no SNMP, no HTTP
  mapperdb.py      mapper.db: named maps, the devices/unmanaged peers
                   placed on each and where, a VLAN colour override table,
                   Mapper settings
  hostkeys.py      remembered SSH host keys, shared by ConfigRX and the
                   SSH terminal; refuses a changed key
  sshterm.py       interactive SSH sessions for the browser terminal
                   window, over a WebSocket
  permissions.py   the per-module read/write permission model
  report.py        availability and link-saturation reports, computed
                   from history Nodes and Alerts already keep
  sqlitebase.py    the SqliteStore base class every database module
                   subclasses (open/pragma/migrate/close, settings,
                   trim/reclaim); opens a SQLite file with owner-only
                   file permissions, incremental-vacuum space reclamation
                   without VACUUM's stop-the-world lock, and settings-dict
                   type coercion
  secretstore.py   the portable secret store: a passphrase-derived key,
                   a stand-in for DPAPI on hosts without it
  ldapclient.py    a minimal LDAPv3 simple-bind client for directory auth
  udpsock.py       dual-stack UDP bind and drop-counter helpers, and the
                   UdpReceiver base class the three collectors subclass
  web/
    __init__.py    exports Service and WebServer
    service.py     headless service: opens the databases, starts the
                   scheduler, resolver and collectors
    api.py         JSON endpoints — one function per route, grouped by
                   NetPath, NetFlow, syslog, IPAM, auth and users, plus
                   nodes, alerts, snmp, wireless, configrx, mapper, ssh,
                   debug, settings, dashboard, audit, maintenance, update,
                   platform, config, tokens and password
    server.py      HTTP(S) server: routing, sessions/cookies, access log,
                   serving static/
    wsock.py       RFC 6455 WebSocket framing, server side, stdlib only
    static/        the browser interface
      index.html   the thirteen-tab shell
      login.html   the sign-in page
      tokens.css   the design tokens: every colour, text size and
                   spacing value, with its measured contrast
      app.css      shared styling for the whole interface, on the tokens
      app.js       shared plumbing: server calls, tab switching, the
                   refresh loop, modals
      boot.js      marks which tab paints first, before <body> has a
                   single byte of content to render
      dashboard.js Dashboard tab: fleet/alert/collector/storage/poller
                   tiles, worst-ten offender lists
      netpath.js   Routes tab: route graph, timeline, destinations
      netflow.js   NetFlow tab: traffic chart, top-N, flow table, filters
      events.js    SNMP Trap tab (hourly histogram, trap table, varbinds)
                   and Syslog tab (message table, filters, collector
                   settings), one shared page factory
      ipam.js      IPAM tab: subnets & hosts, conflicts, DHCP
      nodes.js     Nodes tab: device inventory, per-device drill-down
                   chart, discovery, polling profiles, vendor MIBs
      alerts.js    Alerts tab: open/acked/resolved alerts, histogram,
                   rules, email templates
      wireless.js  Wireless tab: FortiGate-managed APs at a glance
      configrx.js  ConfigRX tab: device list, stored backups, read-only
                   backup viewer
      mapper.js    MAPPER tab: manually-built L2 map, pan/zoom/drag
                   canvas, VLAN-strand links, PNG/CSV export
      debug.js     Debug tab: trace workers, event log
      settings.js  Settings tab: reverse DNS, refresh interval, database
                   locations, maintenance
      login.js     sign-in form and idle/session-timeout handling
      ssh.html     the standalone SSH terminal popup window
      ssh.css      styling for the SSH popup, on top of app.css
      ssh.js       the SSH window: xterm.js terminal driven over a
                   WebSocket
      vendor/      vendored third-party JS (xterm.js and its fit addon),
                   with `LICENSE-xterm.txt` recording their versions,
                   provenance and the no-build-step/no-patching rule
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

## Releasing

Self-update is off by default (`updates_enabled`, in Settings). An install
that leaves it off never contacts GitHub at all, and is updated by replacing
the `netpath` directory by hand.

**What the Update button does today**: `GET .../commits/main` for the current
tip of the branch; stop if that commit is already recorded as installed;
download `codeload.github.com/.../tar.gz/<sha>`, capped at 64 MiB with
nothing verifying those bytes beyond the cap; unpack, stop every worker,
replace the `netpath` package, record the commit, and re-exec. Whoever can
push to `main` therefore chooses what every install with the setting on will
run at the next press, on hosts holding SNMP communities and SSH credentials.
That is known, deliberate and temporary — see the SECURITY NOTE at the top of
`netpath/selfupdate.py` for what has to change to put the verified path below
back in use. If that exposure is not acceptable, leave `updates_enabled` off
— the default — and replace the directory by hand instead.

**The verified path** (implemented; not what the button currently uses): the
newest published tag by version order, that tag's GitHub release, and in its
asset list a file called exactly `SHA256SUMS` — no asset, no install. The
tag's tarball is downloaded and hashed as it streams, compared against
`SHA256SUMS`'s line for `<repo>-<tag>.tar.gz`, and only a match is unpacked
and swapped in. It proves the tarball is byte-for-byte what the release
named; it does not prove who named it — there is no signature.

**Cutting a release:**

```sh
# 1. Tag the commit and push the tag.
git tag -a v4.53.0 -m "SappiWhere 4.53.0"
git push origin v4.53.0

# 2. Hash the tarball GitHub actually serves for that tag — the same URL the
#    updater uses. Do not build your own tarball; the digest must be of the
#    bytes the updater will receive.
TAG=v4.53.0
curl -fsSL -o "magicalbeans-$TAG.tar.gz" \
  "https://codeload.github.com/thawkins5555/magicalbeans/tar.gz/refs/tags/$TAG"
sha256sum "magicalbeans-$TAG.tar.gz" > SHA256SUMS

# 3. Create the release for that tag and attach SHA256SUMS as an asset —
#    a release asset, never a file committed in the repository: a digest
#    that travels inside the archive it describes proves nothing.
gh release create "$TAG" SHA256SUMS --title "SappiWhere 4.53.0" --notes-file -
```

`SHA256SUMS` is `sha256sum`'s own format, checkable by hand with
`sha256sum -c SHA256SUMS`; extra lines for other files are ignored.

**Checklist:**

- [ ] `CHANGELOG.md` has the release's section, and `netpath/__init__.py`
      carries the version being tagged — load-bearing at runtime, since it
      lands in every static asset's URL (`app.js?v=...`, served `public,
      max-age=31536000, immutable`). Bump it for any release that changes a
      static file, however small; a browser holding an old URL never asks
      again for up to a year.
- [ ] `python3 tests/run_all.py` is green.
- [ ] Tag pushed.
- [ ] `SHA256SUMS` generated from the codeload tarball for that tag.
- [ ] Release created for the tag with `SHA256SUMS` attached.
- [ ] `sha256sum -c SHA256SUMS` passes against a freshly downloaded tarball.

## Backup and restore

Thirteen SQLite databases, all in WAL mode, all written by one live process.
**Copying only the `.db` file while the service is writing gives a torn
backup** — every database also has a `-wal` (committed transactions not yet
folded into the main file) and usually a `-shm`. Do not use `cp`, `rsync` or
a snapshot on a running instance unless it is genuinely atomic across all
three files of every database at once.

What to back up is everything in the data directory
(`~/.local/share/netpath-monitor/` on Linux/macOS,
`%APPDATA%\netpath-monitor\` on Windows, or wherever `--db`/`--nodes-db`/etc.
point): the thirteen `.db` files, and `secret.salt` — the per-install salt the
portable secret store (non-Windows hosts with a passphrase configured;
`netpath/secretstore.py`, `CREDENTIAL-SECURITY.md`) derives its encryption
key from. `NETWORK-AND-STORAGE-REQUIREMENTS.md` says what each database
holds.

**Method 1 — stop, copy, start.** Simple, complete, needs a maintenance
window. A clean shutdown checkpoints and removes the `-wal` files; archiving
the whole directory (not a `*.db` glob) also picks up `secret.salt`
automatically:

```bash
systemctl stop sappiwhere
tar czf sappiwhere-$(date +%F).tar.gz -C ~/.local/share netpath-monitor
systemctl start sappiwhere
```

```powershell
Stop-Service SappiWhere
Compress-Archive -Path $env:APPDATA\netpath-monitor\* -DestinationPath D:\backups\sappiwhere-$(Get-Date -f yyyy-MM-dd).zip
Start-Service SappiWhere
```

**Method 2 — `sqlite3 .backup`, no downtime.** Takes a read lock, copies
pages, retries any changed underneath it, and folds the WAL in, leaving one
self-contained `.db` with no `-wal` beside it. Unlike Method 1 it does not
sweep up `secret.salt` for free, so the script must copy it explicitly —
skipping it is how a restore onto new hardware loses every credential the
portable secret store ever encrypted, permanently:

```bash
#!/bin/sh
set -eu
SRC="$HOME/.local/share/netpath-monitor"; DST="/backup/sappiwhere/$(date +%F)"
mkdir -p "$DST"
for f in app nodes nodes_series nodes_mibs alerts netpath flows snmptraps \
         syslog ipam wireless configrx mapper; do
    [ -f "$SRC/$f.db" ] || continue
    sqlite3 "$SRC/$f.db" ".backup '$DST/$f.db'"
done
[ -f "$SRC/secret.salt" ] && cp -p "$SRC/secret.salt" "$DST/secret.salt"
sqlite3 "$DST/nodes.db" "PRAGMA integrity_check;"    # sanity, not a formality
```

Run it as the account that owns the files — from 4.39.0 the directory is
`0700` and the databases (and `secret.salt`) `0600`. Back up `configrx.db` at
the cadence of your change-control process, not your metrics; it is the file
whose loss cannot be reconstructed by waiting. There is no in-application
backup; **Settings → Maintenance** prunes and vacuums but does not export.

**Restoring**, in order: stop the service; move the current directory aside
rather than deleting it; restore the files (including any `-wal`/`-shm` for a
Method 1 archive — a Method 2 backup has neither); fix ownership and modes
(service account, `0700` on the directory, `0600` on the files); start it and
watch the log — schemas migrate forward automatically, so restoring an older
release's backup into a newer install is supported; then verify by signing
in, checking the device count, checking the alert rules, and opening one
ConfigRX backup. The databases are independent, so restoring one alone (say
`configrx.db` from a week ago) is fine; the only cross-file references are
alert rows naming a device id in `nodes.db`, and a mismatch there just
renders as an id rather than a name.

**The DPAPI caveat.** On Windows, every encrypted credential — the DHCP
credential, SNMPv3 authentication passwords, the SMTP password, the wireless
controller's SNMP credential, ConfigRX's SSH password and its optional
per-device enable secret — is protected in machine-and-account scope.
Restoring onto the same machine and service account works, including
credentials; restoring onto a different account or different hardware brings
back ciphertext that will not decrypt, and each credential needs re-entering
— budget for that during disaster recovery, and keep them in a password
manager rather than a text file next to the backup. A Linux/macOS/BSD backup
follows the same shape if a passphrase-based secret store
(`netpath/secretstore.py`) was configured on the host it came from, and has
nothing to lose if one never was. SSH host keys are not encrypted and restore
cleanly, and account passwords (scrypt hashes) restore fine everywhere.

Verify a backup you already have:

```bash
sqlite3 /backup/sappiwhere/2026-09-01/nodes.db "PRAGMA integrity_check;"
sqlite3 /backup/sappiwhere/2026-09-01/nodes.db "SELECT COUNT(*) FROM devices;"
```

`integrity_check` returning anything but `ok` means that backup is not one;
a count that is zero when it should not be means the copy was taken mid-write
or as the wrong user.

Not in any backup: sessions and the Debug tab's event buffer (both in memory,
reset on restart, deliberately) and anything a collector did not receive
while the service was down — nothing here backfills.
