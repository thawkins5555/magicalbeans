# SappiWhere — Changelog

Firewall and protocol requirements are in `NETWORK-AND-STORAGE-REQUIREMENTS.md`. A guide to what the application does is in `FEATURES.md`, and how it does it in `INTERNALS.md`. How credentials are protected is in `CREDENTIAL-SECURITY.md`.

## Releases

Listed newest first. Version numbers are build order, not dates.

### 4.9.2 — No more NetPath flash on reload

- **Reloading no longer flashes NetPath** before settling on the tab you
  were actually on. The remembered tab is now applied by a small inline
  script that runs the instant the page's markup is parsed, rather than
  waiting on every module's script file to load and the app's own first
  server round trip — both of which the previous fix still had to wait
  through before it could act.

### 4.9.1 — Sign-in always opens on Dashboard

- **Signing in now always lands on the Dashboard tab**, regardless of
  which tab a previous session left active. A reload while already
  signed in still returns to whichever tab was open, as of 4.9.0 — this
  only changes what a fresh login itself opens to.

### 4.9.0 — DHCP leased-IP trend chart, tab persists on reload, Dashboard tab

- **DHCP scopes get a leased-IP trend chart**, a thin line chart under the
  usage donut showing the last 24 hours or 7 days, toggled per scope, with
  a hover tooltip for the exact count (and percentage, where known) at any
  point. One snapshot is recorded per scope on every poll, kept separately
  from the live scope/lease data those polls otherwise replace wholesale,
  so the trend survives every subsequent poll. A new **Keep DHCP
  leased-IP history for** setting (default 35 days) controls retention.
- **Reloading the page now returns to whichever tab was open**, instead of
  always resetting to NetPath. Remembered per browser, the same way panel
  sizes and column widths already are.
- **A new Dashboard tab**, at the far left of the tab list ahead of
  NetPath. Currently a placeholder with nothing on it yet — reserved space
  for a future cross-module overview.

### 4.8.1 — Resizable Syslog and NetFlow columns

- **Syslog's message table can now be resized** column by column, the same
  drag-the-header-edge mechanism NetFlow and IPAM already use. Widths are
  remembered per browser and clear with the rest via **Reset layout**.
- **NetFlow's column widths now default close to what each field actually
  needs** — narrow for ports, protocol and byte/packet counts — rather
  than one uniform width for every column, so Source and Destination (the
  two that can hold a long resolved hostname) get the extra room instead.
  Anyone who already dragged a NetFlow column keeps that width; this only
  changes the starting point for columns nobody has touched yet.

### 4.8.0 — Flow-to-path correlation, continuous per-hop probing, ASN/owner lookup

- **Flow-to-path correlation.** Every row in the NetFlow table now carries a
  "→ Route" link to the NetPath route that traffic actually took, when one
  was ever traced — matched against each target's real, last-known
  destination IP, not just its configured hostname. No matching route
  greys the link out rather than hiding it, so the feature stays
  discoverable. Jumping over selects the matching destination in NetPath
  and centers its time window on the flow's own timestamp.
- **Continuous, MTR-style per-hop probing**, opt-in per destination (off by
  default — it adds a steady stream of ICMP pings to every hop of the path,
  independent of the scheduled traceroute). Turn it on from a destination's
  Edit dialog; the route graph's hop tooltips then show live cumulative
  probe count, loss % and min/avg/max RTT alongside the per-traceroute
  numbers. A route change automatically clears stats for hops that dropped
  off the path, so old and new numbers are never blended together.
- **ASN and organization lookup** for every hop, shown next to the
  reverse-DNS name, so you can see where a route leaves your provider —
  "AS15169 (GOOGLE, US)" and similar. Uses Team Cymru's DNS-based whois, on
  its own long-lived cache (30 days by default) separate from the hostname
  cache, since ownership changes far less often than a PTR record. Private,
  loopback, link-local and carrier-grade-NAT addresses are never looked up
  at all — no query naming an internal address ever leaves the host.
  Configurable, including a dedicated query server, under Settings →
  ASN / Owner Lookup.

### 4.7.0 — Scope sort by IP, half-width buttons, IPAM as a DNS fallback

- **Scopes sort by IP address** too now, alongside Least available (the
  default), Most available and Name — numerically, so 10.0.10.0 doesn't
  sort ahead of 10.0.2.0.
- **Change password and Check for update & restart** no longer stretch to
  the full width of their row.
- **NetFlow and Syslog can get a name from IPAM when DNS has nothing.** The
  reverse-DNS resolver falls back to whatever a DHCP lease says a device's
  hostname is when a PTR lookup comes back empty, and caches that the same
  as a real DNS answer — in the one shared cache both modules already read
  from, so neither needed any changes of its own.
- **Syslog's Messages header gets a Hostname checkbox**, on by default,
  next to the message count: unchecked, the Source column always shows the
  raw address even when a name is known.

### 4.6.0 – 4.6.3 — DHCP reformatted to match Subnets & Hosts

The DHCP page now mirrors Subnets & Hosts one level down. Server selection
moved into a compact dropdown at the top; the sidebar it vacated now holds
**Scopes**, each with a mini utilization donut — leased, reserved,
available — the same visual language as the subnet donuts. Selecting a
scope shows a bigger version of that donut above its **Leases** table,
filtered to just that scope, the same way the Hosts table already filters
to the selected subnet.

- Scopes sort by **Least available** (the default), **Most available** or
  **Name**.
- The detail header adds the scope's own **subnet**, computed from its
  network identity (ScopeId + mask) rather than the narrower dynamic
  range, and its configured **router** address (DHCP option 3), fetched
  per scope and not previously read at all.
- `dhcp_scopes` gained a `router` column, added to existing databases
  through the same `ALTER TABLE` migration pattern already used for the
  DHCP credential fields.

### 4.5.0 – 4.5.1 — Find: search IPAM by hostname, IP or MAC

A search box in the IPAM strip answers the direction browsing by subnet
never could: given a name, MAC or partial IP, what's the address. Checks
three sources at once — hosts SappiWhere's own sweep discovered, DHCP
leases and reservations, and the shared reverse-DNS cache — and merges
matches found in more than one by IP. A result outside every configured
subnet isn't a bug: DHCP polling reads a server's scopes independently of
what subnets are being swept, and each result names which source found it.

### 4.5.2 – 4.5.7 — DHCP Test Connection: reliability and readable errors

Test Connection went from a silent "PowerShell exited with code 0, no
output" to actually working, through a real chain of distinct failures
found and fixed against a production DHCP server:

- **The root cause of the silent failure**: the script was piped to
  PowerShell over stdin with `-Command -`, which is unreliable for a
  multi-statement script with scriptblocks and try/catch on native
  Windows PowerShell — it can read and execute nothing while still
  exiting 0. Switched to writing the script to a temp `.ps1` file and
  running it with `-File`, the officially supported way, written with a
  UTF-8 BOM so Windows PowerShell 5.1 reads it correctly regardless of
  the system codepage.
- **WinRM TrustedHosts, CIM/WMI access-denied, and DhcpServer
  module-not-loaded** errors — each a distinct, genuine step in getting a
  credentialed connection working (Kerberos can't vouch for a bare IP;
  the account needs the DHCP server's local `DHCP Users` group, a
  separate permission from WinRM access; and the DHCP server needs
  `RSAT-DHCP` installed, which can silently not take effect until WinRM
  itself is restarted) — now come back with the actual fix appended
  rather than the raw PowerShell message alone.
- **The button itself shows progress**: disabled and relabeled "Testing…"
  for the duration, since a PowerShell round trip over WinRM can
  legitimately take up to thirty seconds and previously gave no
  indication anything was happening.

### 4.4.0 — A blocking restart dialog, and an IPAM database cap

Clicking the update button now grays out the screen with a modal
explaining a restart is in progress and that it will sign everyone out,
rather than leaving that as a status line easy to miss on another tab.
IPAM's `ipam.db` gets the same size-cap treatment the other three
databases already had — 256 MB by default, trimming the oldest scan
history first, since subnets, hosts and open conflicts describe the
network as it is now rather than a log a cap should be trimming.

### 4.2.0 – 4.3.6 — A self-update button

Settings gained one button: check `github.com/thawkins5555/magicalbeans`'s
`main` branch for a commit newer than what's installed, and if there is
one, download it over plain HTTPS, swap it into the running install, and
restart. Getting the restart itself to actually work reliably took three
real, distinct bugs found against production Windows servers, each fixed
in turn:

- **`CERTIFICATE_VERIFY_FAILED`** on a Windows server with no route to
  fetch a missing root certificate — fixed by vendoring Mozilla's CA
  bundle (the same one `pip` ships) and trusting it alongside the system
  store rather than instead of it.
- **The restart not restarting at all.** `os.execv` behaves nothing like
  POSIX exec on Windows — it spawns a new process and ends the old one —
  and a naive replacement process was losing a race for the port and the
  databases against the process it was replacing, then separately dying
  within milliseconds of starting for a second, unrelated reason.
- **The actual root cause of that second death**: the relaunch command
  was rebuilt from `sys.argv`, but `-m netpath` rewrites `sys.argv[0]` to
  `__main__.py`'s resolved file path — so every restart was actually
  running that path as a bare script rather than `-m netpath`, which
  drops the package context every relative import in this app needs and
  crashes instantly with no visible error on `pythonw.exe`. Fixed by
  rebuilding the relaunch command as `-m netpath` explicitly rather than
  trusting `sys.argv[0]`.

### 2.7.0 — Three IPAM display bugs fixed

Reported against a real subnet: a stray `\25B2` appearing after sorting a
column, the Last seen/First seen columns visibly out of step with their
data, and a subnet showing 86% of its addresses as "seen before, now down"
that plainly hadn't ever been occupied that heavily.

- **The sort caret rendered as literal text.** A CSS `content` property was
  written with a doubled backslash, so the browser showed `\25B2` instead of
  a triangle. Replaced with a real element in the DOM rather than a
  positioned `::after` pseudo-element, which also restores sticky table
  headers that the old approach had silently broken.
- **Two columns were right-aligned while their cells stayed left-aligned.**
  `numeric: true` was controlling both how a column sorts and whether it's
  right-aligned, and a "14s ago"-style column sorts by timestamp but reads
  as text. Sorting and alignment are now independent settings, and every
  column in a sortable table gets an explicit width so the header row and
  the body are measured from the same numbers.
- **"Seen before, now down" was counting addresses that had never been seen
  at all.** A host gets a row the moment it's *probed*, answer or not; the
  usage breakdown was treating "has a row" as "was up before," which made
  every never-answering address in a subnet look like a former occupant.
  Fixed to key off `last_up`, which is only ever written when an address
  actually replies — an address probed a hundred times with no reply is now
  correctly "never seen." The host table's timestamp columns had the same
  confusion baked into their labels and are renamed to match what they
  actually show: **Last reply** (from `last_up`, "never" if nothing has ever
  answered) and **First probed** (when the sweep first tried it, which is
  not the same thing an earlier "First seen" label implied).

### 2.6.0 — Live agent visibility on Debug, per-subnet utilization charts, and a way to reset a subnet's inventory

- **The Debug page now shows DNS and IPAM work in progress**, not just
  NetPath's trace workers. A "DNS lookups in progress" table lists every
  address currently out for a reverse-DNS lookup with its elapsed time; an
  "IPAM agents running" table lists every subnet scan or DHCP poll actually
  in flight. Fixed a real latent bug found while wiring this up:
  `Resolver.drain()` called a method that never existed on that class —
  dead code that would have raised if anything had ever invoked it.
- **Every subnet shows a utilization donut** — alive, previously-seen-but-
  down, never-seen — in the sidebar list, and a larger version with the
  counts spelled out above its host table when selected.
- **Clear stats**, in a subnet's Edit dialog, resets its discovered hosts and
  scan history to start over without removing and re-adding the subnet.
  Refused while a scan of that subnet is running, so it can't race the
  scan's own writes.
- The IPAM event category, added with the module itself, had no display
  label in the Debug log's category filter and showed as raw `ipam` text;
  fixed.

### 2.5.0 — A stored credential option for DHCP polling

IPAM's DHCP servers could only authenticate ambiently or via Windows
Credential Manager. That's still there and still the default, but a server
can now be given a username and password directly instead — the shape of
field software with a dedicated read-only DHCP account tends to have.

- **A DHCP server can store a username and password**, for people migrating
  from a tool that took a credential directly rather than through Windows.
  Both mechanisms coexist per server: leave the fields blank for ambient
  identity or Credential Manager as before, fill them in to override with a
  stored credential for that one server.
- **The password is encrypted with Windows DPAPI**, machine-bound, before it
  is written to `ipam.db`. It is never returned by the API in any form —
  the server listing shows only that a credential is stored and its
  username. Storing one is refused with a clear message on any platform
  where DPAPI isn't available, rather than falling back to writing it in the
  clear.
- **The stored-credential path uses PowerShell remoting** (`Invoke-Command
  -Credential`) rather than the RPC call the ambient path uses, since the
  DhcpServer module's cmdlets don't accept a credential directly against
  `-ComputerName`. This needs WinRM reachable on the DHCP server instead of
  the `DhcpServer` module being present on the SappiWhere machine — the
  trade-off runs the other way from the default path. A real DHCP server
  almost always already has the module, since it ships with the role.
- **Test connection** now also accepts an unsaved username and password, so a
  credential can be checked before it's committed to.
- **Clear credential** reverts a server to ambient identity.
- The same injection-safety property as the original DHCP client holds here
  too: the username and password travel to the PowerShell process as
  environment variables, never woven into command text, and every DHCP
  cmdlet called — on either path — is still a `Get-`.

### 2.4.0 — IPAM: discovery, conflicts, read-only Windows DHCP

A new module and tab: subnet discovery, IP conflict detection, and read-only
visibility into a Windows DHCP server's scopes and leases. Backed by a fifth
database, `ipam.db`.

- **Subnet discovery.** Add a subnet in CIDR form and it is swept on a
  schedule: every address is pinged, then the local ARP table is read once for
  whatever answered. A subnet larger than a configurable limit (1024
  addresses by default) is refused when added rather than silently truncated.
- **MAC addresses and conflict detection are ARP-based**, so they only work on
  a subnet directly attached to the machine running SappiWhere — ARP does not
  cross a router. A remote subnet still reports which addresses answer ICMP.
  This is documented as a deliberate limit, not fixed silently.
- **Conflict detection**, two ways: the same address answering as two
  different MACs across scans, or a scanned MAC disagreeing with what a polled
  DHCP server's own lease record says for that address. Neither auto-resolves
  — a person marks one resolved once they know what happened.
- **Read-only Windows DHCP polling**, via the `DhcpServer` PowerShell module's
  own `Get-DhcpServerv4Scope`, `Get-DhcpServerv4Lease` and
  `Get-DhcpServerv4Reservation` — nothing else. The PowerShell script that runs
  is a fixed constant, never built from input; the target server name travels
  as an environment variable rather than being woven into command text, so
  there is no string for it to inject into. There is no write path: nothing in
  SappiWhere can create, change or remove a scope, reservation or lease.
- **No credential is ever stored.** DHCP polling authenticates as whichever
  Windows account runs SappiWhere, or — if that account does not already have
  DHCP read rights — a matching entry in Windows Credential Manager on this
  machine, added once with `cmdkey` or Control Panel and associated with that
  server's name. SappiWhere has nowhere to put a password even if it wanted to.
- **Test connection** checks reachability and reports the DHCP Server version
  and scope count without walking every scope's leases, for confirming a new
  server quickly. **Poll now** and **Scan now** force an immediate run outside
  the schedule.
- The host and lease tables sort and resize the same way NetFlow's flow record
  table does, reusing the same grid helper.
- IPAM's discovered hosts feed into the shared reverse-DNS cache alongside
  NetFlow's and Syslog's, gated by their own settings as before.
- Retention: discovered hosts, resolved conflicts and scan history are each
  pruned on their own schedule; DHCP scopes and leases are replaced wholesale
  on every poll, since the DHCP server is the source of truth for those.

### 2.3.0 — Idle sign-out for the web login

The session idle timeout (`session_idle_minutes`) existed in the code but
could not actually fire: every open browser tab polls the server every couple
of seconds regardless of whether anyone is present, and that polling was
extending the same idle timer meant to catch an unattended session.

- **Sessions now distinguish presence from polling.** A background read no
  longer extends a session. Only a deliberate action does — any write, or a
  heartbeat the browser sends solely when it detects real mouse or keyboard
  input, at most every 20 seconds.
- **Default idle timeout lowered from 4 hours to 10 minutes**, since it is now
  a timeout that actually enforces itself.
- **New Sign-in section on the Settings tab**: idle timeout and absolute
  session length, both adjustable and applied to every active session
  immediately.
- **A 60-second warning banner** appears before sign-out, with a button to
  stay signed in, so the shorter default doesn't cut someone off mid-task
  without notice.
- The admin "who's signed in" list now shows genuine idle time instead of a
  number that was always close to zero.

### 2.2.0 — Substring search, sortable flow records

- **Syslog search matches anywhere in a word.** `face` now finds `interface`.
  The index was tokenized by word, so a query could only ever match from the
  start of a token; it is now a trigram index, which indexes every
  three-character run. Queries of one or two characters scan instead, since a
  trigram index has nothing to match on below three.
- **The sending address is searchable from the main search box.** It is indexed
  alongside the message, so typing `10.20.3.4` finds messages from that device.
  The Source IP filter stays for narrowing a search that is about something
  else, and its label now says IP.
- **Multiple search terms** must all appear, in any order and any field, rather
  than being treated as one phrase.
- **The index rebuilds itself once** on the first launch after upgrading,
  in the background and in chunks so the collector keeps writing and the
  service starts immediately. Searching works throughout, by scanning, and the
  syslog status strip shows the progress.
- The scan fallback now searches the same four columns as the index, so both
  paths return the same rows and differ only in speed.
- **`syslog.db` roughly doubles in size.** A trigram index holds far more than
  a word index: 50,000 sample messages went from 14.6 MB to 26.5 MB. Against a
  fixed cap that halves how many messages are retained, so raise the Syslog
  database cap if history matters more than the search.
- **Flow record columns sort and resize.** Click a heading to sort, again to
  reverse; drag its edge to resize. Widths persist per browser and are cleared
  by Reset layout. Ports and volumes sort by value rather than by their
  label — `HTTPS (443)` is not text between 44 and 45 — and empty cells sort
  last in both directions.
- The records selector is relabelled *Top 250 by volume / by packets / most
  recent*, since it chooses which records are fetched while the headings choose
  how they are arranged.

### 2.1.0 — Application data split out of the trace database

`netpath.db` had been carrying three things that are not traceroute records:
the global settings, the user accounts and the reverse-DNS cache. They now live
in a fourth file, `app.db`, and each record database holds only its own
module's data and its own module's settings.

- **New `app.db`**, beside the others, holding global settings, accounts and
  the shared name cache. Path overridable with `--app-db`.
- **Settings are split by scope on disk**, matching the split the Settings
  pages already made: global keys in `app.db`, NetPath keys in `netpath.db`,
  NetFlow and Syslog keys where they already were.
- **Existing installs migrate on first launch.** Settings, accounts and cached
  names are copied across, verified, and only then removed from `netpath.db`.
  An interrupted migration is retried on the next start rather than left half
  done; nothing is deleted from the source until the copy is confirmed.
- **The reverse-DNS resolver no longer joins hops against the cache**, since
  they are in different files. It reads candidate addresses from `netpath.db`
  and filters them against `app.db`. A new index on `hops(ip)` keeps that a
  cheap index scan.
- **Cached names are pruned** on the maintenance cycle instead of accumulating
  for the life of the install.
- **The Data files panel lists all four**, with the Syslog path shown for the
  first time. `app.db` has no size cap: it does not grow with traffic, and it
  is the file to back up.
- Sessions and login throttling are unchanged — both stay in memory, so no
  token is ever written to any file.

### 2.0.0 — Browser interface

The application can now run headless and be used through a web browser. The
desktop window still works and is unchanged; both are front ends over the same
core.

```
python -m netpath --web --port 8443
```

- New `netpath/web` package: a `Service` owning the databases and background
  workers, a JSON API, and a browser front end.
- Standard-library HTTP server, so the deployment gains no dependencies. TLS
  when `--cert` and `--key` are given.
- `--host` and `--port` control the listener; the port defaults to 8443.
- All four tabs are present in the browser: route graph, three-lane timeline,
  snapshots, flow charts and table, worker state, event log and settings.
- Every module setting is reachable from the same places as on the desktop.

**No authentication yet.** Bind to an interface you trust until the TACACS work
lands.

### 4.1.0 — Database sizes on show, and a storage document

- The sign-in page carries nothing but the name and the two fields. It no
  longer advertises the default credentials, which is not information an
  unauthenticated visitor needs.
- **Current database size beside each cap** on the Settings tab, with a small
  bar that turns amber past 75% and red past 90%. A cap means little without
  the number it is capping next to it. The bars update as the cap is typed, so
  the effect of a change is visible before it is applied.
- **A Databases card in the service console** showing the same three figures
  with their paths, so the disk position is answerable without a browser.
- `NETWORK-REQUIREMENTS.md` is now
  **`NETWORK-AND-STORAGE-REQUIREMENTS.md`**, covering what is written to the
  local machine as well as what crosses the network: the exact file locations
  on each platform, what each database holds and why it has to, what bounds the
  size and in what order, and what is never written at all.

### 4.0.1 — Overlapping labels, and browsers holding stale scripts

Fixed: the `HOP n` labels sat at a fixed height above the middle of the route
graph, which put them inside the box whenever a column held a single hop. They
are now placed relative to the top of their own column, so they clear it
however many addresses that hop has.

Fixed: the warn threshold labels on the timeline were right-aligned, where the
lane already carries its scale figure and where the newest bars are drawn. They
have moved to the left of the lane, over a small backing plate.

Fixed, and the reason the threshold line looked missing after an update: the
browser was still running the previous JavaScript. The version in the corner
comes from the server, so it changes as soon as the service restarts whether or
not the page has reloaded — which made a stale script look like a missing
feature. The shell is now served `no-store` so a reload always fetches the
current script tags, and the scripts carry an `ETag` so the browser can tell
stale from current rather than guessing. A revalidation of an unchanged file
returns 304 and no body.

### 4.0.0 — Sign-in, local users, and thresholds on the NetPath page

**Everything now requires signing in.** A fresh install creates **admin /
admin**, flagged so the first thing it does is insist on a new password.

Passwords are never stored. What is kept is an scrypt hash at the parameters
OWASP currently recommends — N=2^17, r=8, p=1, roughly 128 MiB and a second per
verification — with a 16-byte random salt per password, falling back to
PBKDF2-HMAC-SHA256 at 600,000 rounds where the SSL library underneath is too
old for scrypt. The stored string records which was used and with what cost, so
raising it later does not invalidate anyone: hashes are upgraded quietly on the
next successful sign-in.

Other things that matter more than they look:

- **Sign-in failures are indistinguishable.** An unknown username still costs a
  full hash verification against a dummy, so response time cannot be used to
  discover which accounts exist, and both cases return the same words.
- **Failed attempts are throttled** per username *and* per source address, so
  one noisy address cannot lock out an account and one account cannot lock out
  an address. The delay doubles past five failures, capped at 30 seconds.
- **Sessions are server-side and in memory**, so a restart signs everyone out
  and no token is written to a file that also holds network data. The cookie is
  `HttpOnly`, `SameSite=Strict`, and `Secure` when TLS is on — it is left off
  over plain HTTP, where a Secure cookie would simply be discarded.
- **Changing a password ends every session using that account**, including the
  one making the change.
- **State-changing requests must be `application/json`.** A cross-site form can
  send a POST but cannot set that content type without a preflight the browser
  will refuse; with `SameSite=Strict` that is belt and braces, but both are
  free.
- **Password rules are length and a blocklist**, not composition. Twelve
  characters minimum, and the passwords every attacker tries first are refused.
  Requiring a capital and a digit pushes people toward predictable manglings,
  which is why NIST dropped it.

Users are managed on the Settings tab: add with an initial password they must
change, remove, and see who is currently signed in. There are no roles — every
account has full access, which is why adding one is an administrative act. You
cannot remove the account you are signed in with, so there is always a way back.

**The NetPath page now states the terms it is judging by.** Under the route
header: `every 60s · warn above 150 ms or 10% loss · probe 30 hops × 3 at 2s
(worst case 195s)`. The warn thresholds are also drawn as dashed guides across
the RTT and loss lanes, so a bar crossing the line is visibly why the block
below it turned amber.

### 3.4.1 — A console window flashed for every trace

Fixed: running from the `pythonw.exe` shortcut made a console window appear and
disappear for every traceroute. With no console of its own, Windows gives each
child process a new one — so removing the black window from the app put one on
every `tracert` instead.

`tracert` and `nslookup` are now launched with `CREATE_NO_WINDOW`, with a
hidden `STARTUPINFO` as well for shells that honour that instead. Both come
from one helper in `procs.py`, so a future subprocess cannot quietly forget it.

### 3.4.0 — Run without a terminal window

- **Console output** pane in the service console, capturing stdout and stderr.
  Under `pythonw.exe` both streams are `None` and anything printed — a
  traceback from a worker, a collector error — would otherwise vanish. Now it
  is visible in the window, which is a better place for it than a terminal
  nobody is watching.
- **Show terminal window** checkbox, when there is a terminal to show. Hiding
  it does not stop the service. It is absent under `pythonw.exe`, where there
  is nothing to show.
- **`deploy\Install-Shortcut.ps1`** creates desktop and Start Menu shortcuts
  pointing at `pythonw.exe -m netpath`, so the console opens on its own with no
  black window behind it.

### 3.3.1 — The Syslog page laid out sideways

Fixed: the Syslog page was never added to the rule giving a page a column
layout, so its status card, filter bar and content sat **side by side**. With a
short status nobody would notice; with a long one — a bind failure — the card
grew wide enough to push the filters, histogram, table and the Settings button
off the right-hand edge, leaving a page that was nothing but an error message.

The previous fix was real but addressed the wrong layer: it stopped the status
text from overflowing *within* the strip, which does not help when the strip
itself is a row item free to grow.

Pages are now column by default with NetPath opting into a row, rather than
each page opting into column. A module added later cannot be forgotten and end
up sideways. The status strip is also `flex: none`, so it can neither grow nor
be squeezed out of shape.

### 3.3.0 — Deployment, versions, and a drag-select fix

Fixed: dragging the route graph started a browser text selection, highlighting
the hop labels under the pointer and leaving them highlighted after the drag.
The drawings now suppress selection, and the drag cancels any that was in
progress. The timeline and flow chart had the same problem when dragging to
select a range.

- Every build reports a **version**, shown in the top right of the browser
  interface, in the service console's title bar, and from
  `GET /api/state`. Updating a remote machine no longer means guessing whether
  the files landed or the browser cached the old page.
- **`deploy\Update-SappiWhere.ps1`** updates a local or remote install from the
  release zip over PowerShell remoting: it verifies the archive before touching
  anything, stops the service or process, keeps the previous copy as `.bak`,
  copies, restarts, and reports the version now running. The databases are left
  alone.

### 3.2.1 — A long status could hide the module buttons

Fixed: a long collector status pushed the Settings, Start and test buttons out
of the status strip entirely, so a bind failure hid the one control needed to
fix it. Flex items take their content as a minimum width by default, and the
status line is set `white-space: pre`, so its minimum was the whole string and
it could not shrink. The line now ellipsizes, the buttons are pinned, and the
full text is available on hover and in the Debug log. Both the Syslog and
NetFlow strips were affected.

Also: a failed bind turns the status red, and the message now names only the
ports that matter (`0.0.0.0:514` rather than `0.0.0.0:514/514`) and says how to
find the process holding the port.

### 3.2.0 — Syslog listener and volume settings

Syslog ports were always configurable, and the Settings button was always in the
top right of the module page. What was missing were the settings people actually
reach for once a collector is taking real traffic.

- **UDP and TCP on separate ports.** 514 is standard for both, but 601 is the
  registered port for TCP syslog and plenty of estates split them. `0` for the
  TCP port means "same as UDP". The status strip names both: `Listening on
  0.0.0.0 (UDP 514, TCP 601)`.
- **Keep severity X and worse** drops anything less serious as it arrives,
  before the queue and before anything is written, so a device stuck in a debug
  loop costs nothing beyond the parse. Filtered messages are counted separately
  in the status strip, so the filter never looks like data loss.
- **Truncate messages at N characters**, floored at 80. One malformed device
  sending megabyte lines should not be able to fill the disk.
- **Resolve sending addresses to names**, through the same cache and threads as
  everything else. The source column shows the name where there is one and the
  address where there isn't.

**The syslog database size cap moved to the Settings tab**, defaulting to 1 GB,
alongside the trace and flow caps. All three databases share one disk, so their
limits belong in one place rather than scattered across module dialogs.

### 3.1.0 — The desktop application becomes a service console

The desktop interface is deprecated and removed. Everything it did is in the
browser, and keeping two front ends in step was doubling the work on every
change.

What `python -m netpath` opens now is a small service console:

- Whether the server is running, its URL, request count, open connections and
  uptime.
- **Connected clients** — one row per address with request and error counts,
  when it first and last appeared, and its user agent.
- **Recent requests** — method, path, status and how long each took. Static
  files are counted but kept out of the list, which would otherwise be nothing
  but the five scripts every page load fetches.
- **Listener** — bind address, port, certificate and key, with *Apply and
  restart*. A bind failure is reported rather than swallowed, with the reason.
- **Collectors** — a read-only summary of NetPath, NetFlow, Syslog and DNS.
- **Open in browser**, and start/stop for the server.

`--headless` (or the old `--web`) runs with no window, which is what a service
manager wants. Closing the console stops the service, and the window says so.

The listener settings are stored, so the port set in the console is the port
used next time. Command line arguments still win for the run that supplies
them.

Removed: `mainwindow.py`, `pathview.py`, `timelineview.py`, `flowtab.py`,
`flowcharts.py`, `debugtab.py`, `settingstab.py`, `settingsui.py`. The Qt
dependency now exists only for the console, so a headless install still needs
nothing but the standard library.

### 3.0.0 — SappiWhere, Syslog, and resizable panels

**Renamed to SappiWhere.** The application now covers three collectors, so
naming the whole thing after one of them had stopped making sense.

**New Syslog module.**

- Collector for RFC 3164 and RFC 5424 on the same port, over UDP and
  optionally TCP. TCP handles both framings: RFC 6587 octet counting and the
  far more common newline separation. A line matching neither format is still
  stored rather than dropped.
- Search across message, app and host, with filters for severity, facility,
  source, host and app, over any window.
- A histogram of messages per hour for the last 24 hours, stacked by severity
  so a burst of errors inside a busy hour is visible. Clicking an hour narrows
  the search to it.
- Selecting a message shows every decoded field and the raw line as it arrived.

  Two decisions were about staying quick under volume. Hourly counts are kept
  in a rollup table updated as messages land, so drawing the timeline costs 24
  rows rather than a scan that gets slower every day — measured at 0.3 ms
  against a day of data. Message search uses SQLite's FTS5 index where the
  build has it, because `LIKE '%needle%'` cannot use an index and reads every
  row in the window; searches measured at 0.2–1.7 ms. The status strip says
  which mode is in use.

  Syslog timestamps come from the sending device, so a device with a wrong
  clock files its messages at the wrong time. **Use arrival time** in the
  settings overrides that.

**Resizable panels everywhere.** Every sub-panel on every page now has a
draggable divider: the NetPath sidebar and its route/timeline split, the
NetFlow chart against the bars and table, the Syslog histogram against the
message list, and the Debug worker table against the event log. Sizes are
remembered per splitter across reloads; double-clicking a divider resets that
one, and **Reset panel sizes** on the Settings tab resets all of them.

**Density follows the viewport.** Below 900 pixels of height the chrome tightens
— smaller padding, tabs, table rows and sidebar — and below 700 it tightens
further and drops the hint lines. The defaults should already fit rather than
needing to be dragged first.

**Debug and Settings are always the rightmost tabs**, so adding a module never
moves them.

### 2.3.0 — Overrunning traces, and Save at the top

- A scheduled trace that cannot start because the previous one is still running
  is now recorded and shown as **skipped**, teal with vertical stripes, rather
  than left as a gap. A gap means the app was not running, which is a different
  problem with a different fix; this one means the interval is too short for
  the path.

  The block carries the diagnosis: *"Previous trace still running after 3s;
  interval is 3s. A trace to this destination can take up to 195s, so the
  interval needs to be longer than that or the hop count reduced."* The worst
  case comes from the same `expected_budget()` the watchdog uses, so the advice
  cannot contradict the timeout. The Debug log records each skip as an error.

  It ranks above the network faults in a block, because whatever the path was
  doing, that slot produced no measurement and the schedule is the reason.
  Vertical stripes, so it cannot be mistaken for the refusal's diagonal hatch.

- The NetFlow settings dialog puts Save and Cancel at the top, on both the
  desktop and the browser, so they are reachable without scrolling past every
  group. In the browser they stay pinned while the form scrolls.

Fixed: shutting down closed the databases while a trace was still running, so
the last measurement was lost to a `Cannot operate on a closed database` error
in the worker. In-flight traces now get up to three seconds to land first.

### 2.2.0 — Template age, port names, reverse-DNS fallbacks

- The collector status now reports when the last **template** arrived, beside
  the last packet: `last packet just now · last template 4m ago`. v9 and IPFIX
  records are undecodable until a template turns up and exporters resend them
  only every few minutes, so its age is worth as much as the packet age. It
  reads `no template yet` when none has been seen.

- Port naming widened considerably. Three sources in order: names the site has
  declared, a curated table now covering 188 ports including industrial and
  infrastructure ones (BACnet, DNP3, OPC-UA, PROFINET, IEC-104, ISO-TSAP,
  TACACS+, WireGuard), and this machine's own services file for everything else
  registered with IANA.

  Ports that are not registered cannot be known from here — vendors pick them
  privately — so **Port names** in the NetFlow settings takes `22609 = NVR`
  lines for site-specific ones. Those win over everything else.

- Reverse DNS now makes three attempts per address instead of one: the system
  resolver, then a PTR query straight to a nominated server if **Query server**
  is set, then `nslookup`. The Debug log records which method answered, so a
  name only nslookup can find identifies the system resolver as the problem
  rather than the DNS records.

  The direct query is a real DNS client, not a subprocess: it handles
  compression pointers and NXDOMAIN, and honours its own timeout.

### 2.1.0 — Per-module refresh rates

Refresh rate is now set per module rather than once for the whole application,
because the three want very different things.

| Module | Default | Why |
| --- | --- | --- |
| NetPath | 2s | Cheap queries, and the route graph benefits from feeling live |
| NetFlow | 30s | Aggregations over a whole window that barely move in seconds |
| Debug | 1s | Watching things that change by the second |

- The NetFlow collector strip keeps updating every two seconds from the shared
  state poll while the charts below refresh on their own slow schedule, and
  reports how old the charts are. Changing the window, a filter or the grouping
  fetches immediately rather than waiting out the interval.
- The Debug page's elapsed counters advance ten times a second without asking
  the server again: the value is carried forward from the moment it arrived,
  which also sidesteps any clock difference between browser and server.
  Measured at ten distinct rising values over two seconds from two API calls.
- One 100 ms heartbeat drives everything, so the three rates cannot drift
  against each other.

Fixed: **Resolve names** applied to the flow record table but not to the
charts, so grouping by Source, Destination or Conversation still showed raw
addresses. All three now show names where a name exists and the address where
it does not, on both the desktop and the browser.

### 2.0.4 — Hover panels in the browser

Fixed: hovering showed nothing useful. The browser build used SVG `<title>`
elements, which take about a second to appear, cannot be styled and do not
follow the cursor — and the NetFlow traffic chart had no hover at all, so the
per-series breakdown the desktop shows was simply missing.

- A proper hover panel, styled like the rest of the app, following the cursor
  and flipping sides rather than running off the edge of the window.
- Route graph: address, name, average RTT, loss, prevalence, and the refusal
  code where there is one.
- Timeline: a dotted crosshair plus the block's status breakdown, RTT, loss,
  ICMP reason and whether the route changed.
- NetFlow chart: crosshair plus the per-series rates and total at that instant.
- Top-N bars and flow records get the same treatment; the flow row shows the
  full addresses and names, which the table itself truncates.

### 2.0.3 — Wheel zoom on both time axes

Fixed: neither the NetFlow traffic chart nor the NetPath timeline responded to
the scroll wheel in the browser. Both had drag and buttons but no wheel, which
the desktop timeline has always had.

- Wheel zoom on the NetPath timeline and the NetFlow traffic chart, anchored on
  the instant under the cursor so it stays put as the window narrows.
- Zooming turns **Follow now** off, since holding the right edge at the present
  and zooming about a point elsewhere are contradictory.
- Shared `App.wheelWindow` so the two axes cannot drift apart. At the 60-second
  and four-month limits it keeps the anchor's position within the window
  instead of silently recentring.

### 2.0.2 — Route graph pan and wheel zoom in the browser

Fixed: the browser route graph showed a grab cursor but could not actually be
dragged, and the scroll wheel did nothing — only the `−` and `+` buttons
worked. The CSS promised an interaction the JavaScript never implemented.

- Drag to pan, with the cursor changing to grabbing while held. The drag is
  tracked on the window, so releasing outside the canvas still ends it.
- Wheel zoom, anchored on the pointer: the point under the cursor stays put
  rather than the view jumping to centre.
- Both respect the same 15%–600% limits as the buttons, and both count as a
  deliberate view choice, so a refresh no longer refits over them.
- A drag no longer counts as a click, so panning across a collapsed run of
  silent hops does not expand it.

### 2.0.1 — Browser interface fixes

Fixed: the modal container was styled `display: flex`, and a class selector
beats the user agent's rule for the `hidden` attribute, so the dialog overlay
was always present — a full-screen translucent black layer that dimmed the page
and swallowed every click.

Fixed: the page started itself from an inline `<script>`, which the server's own
Content-Security-Policy forbids. Nothing initialised: dropdowns stayed empty and
the connection indicator sat at "connecting…". Startup now happens from
`app.js` on `DOMContentLoaded`, and the policy stays strict.

Added `[hidden] { display: none !important; }` so the attribute cannot be
overridden by a later rule again.

### 1.15.0 — Names in the flow table

- **Resolve names** checkbox on the NetFlow controls row swaps addresses for
  reverse-DNS names in the flow table, with the address on hover.
- Flow endpoints are resolved by the shared resolver into the shared cache, so
  a name learned for one module is available to the other.
- Only the highest-volume endpoints of the last hour are queried, and only
  while the checkbox is on.

Fixed: the *Reverse-resolve addresses in the flow table* setting existed in the
NetFlow dialog but was never implemented — the table always drew raw addresses
and nothing ever looked up a flow endpoint.

### 1.14.0 — Interface corrections

- Debug page splits 65 / 35 between trace workers and the event log.
- Module settings buttons moved to the top right of both the NetPath and
  NetFlow pages, sharing one style so the control is in the same place
  whichever module you are in.
- **Send test packet** on the NetFlow page sends a zero-record NetFlow v5
  packet over loopback and shows the PowerShell equivalent, with a copy button.
- Database size caps, one per file, on the Settings tab. Checked every 15
  minutes; the oldest records are deleted in chunks until the file fits, so the
  cap wins over the retention setting.
- The Settings page scrollbar is always visible and wider, since the page
  scrolls and a thin auto-hiding bar gave no hint there was more below.
- The active destination is bold in the NetPath list.
- Network requirements split into `NETWORK-AND-STORAGE-REQUIREMENTS.md`, and a new
  `FEATURES.md` describes what the application does.

Fixed: spin buttons on every numeric field had mismatched click targets. The
field's padding shrank the content rect Qt sizes the buttons from, leaving the
up button 14×11 against the down button's 14×12. Both are now 20×14 with
explicit geometry.

Fixed: `VACUUM` does not shrink a SQLite file in WAL mode until the log is
checkpointed, so the size-cap loop deleted records without ever seeing the file
get smaller.

Fixed: selecting a destination and then clicking the route graph left the list
row nearly black on a dark background — Qt falls back to its inactive palette
once the list loses focus.

### 1.13.0 — Settings restructured by scope

Configuration now sits at whichever level it belongs to, rather than all in one
place.

- **Settings** tab holds only what crosses module boundaries: reverse DNS,
  view refresh interval, database file locations and maintenance actions.
- **NetPath settings**, a new button on the NetPath sidebar: concurrent traces,
  trace retention, and the defaults a new destination starts with.
- **Settings** on the NetFlow status strip reverted to its own dialog covering
  the collector, sampling, exporters and flow storage.
- Reverse DNS gained an on/off switch and a configurable cache lifetime,
  previously hard-coded at seven days.
- View refresh interval is now configurable. The Debug page deliberately
  refreshes faster so its elapsed timers stay smooth.
- Trace retention is a setting; the maintenance action reads it instead of
  assuming 90 days.
- Destination defaults seed the Add dialog only, leaving existing destinations
  untouched.
- Shared settings widgets moved to `settingsui.py` so the dialogs and the tab
  cannot drift apart visually.

Fixed: NetFlow settings applied to the running collector but were never written
to disk, so they reverted on the next launch.

### 1.12.0 — Settings tab

- Added a Settings tab after Debug, replacing the settings dialogs and most of
  the Data menu.
- Staged changes with **Apply changes** and **Revert**.

Fixed: labels and check boxes painted their own background, showing as dark
rectangles on the lighter group panels.

### 1.11.0 — Adjustable concurrency and timeouts

- Concurrent trace count is configurable, previously a hard-coded 4.
- Probe timeout is configurable per destination, previously a hard-coded 2s.
- Reverse DNS thread count and timeout are configurable.
- The destination dialog shows the worst case those settings imply: *"A dead
  destination ties up a worker for up to 195s."*
- Trace and DNS thread pools resize without a restart.
- Single `expected_budget()` shared by the tracer's watchdog and the Debug
  page's overdue marker, so they cannot disagree.

**Schema:** `settings` table and a `timeout_s` column on `targets`, added by
migration on first launch.

### 1.10.0 — Elapsed time for running traces

- **Elapsed** column on the Debug page counts up live, coloured blue while
  normal, amber past half the timeout budget, red and marked *overdue* past the
  point where the trace would be abandoned.
- Destinations waiting for a free worker show as **queued**, distinct from
  tracing.

Fixed: queued traces were counted as occupying a worker, producing summaries
like "3 of 1 trace workers busy".

Fixed: the scheduler could call `submit()` on an already shut-down thread pool,
raising `RuntimeError` and silently killing the scheduler thread — after which
no further traces would ever run.

### 1.9.0 — Refused vs no reply

- New status **refused** for destinations where a router answered with an ICMP
  unreachable, distinct from **no reply** where nothing came back at all.
- ICMP codes parsed and stored with the address that sent them: `!H`, `!N`,
  `!P`, `!X` and others on Unix, and both `tracert` phrasings on Windows.
- The refusing hop is outlined in the route graph with a `REFUSED !X` badge;
  the timeline tooltip and snapshot header name the code and the router.
- Refused blocks are hatched as well as coloured, so the distinction survives a
  screenshot and colour-blind viewing.
- A refused trace still reports an RTT — the round trip to the router that
  refused — and every surface states that it is not to the target.

Fixed: the Windows form of the unreachable line carries no timing columns, and
the parser required at least one timing field, so the line was dropped entirely
and the trace looked like it simply stopped.

Fixed: the Windows address extractor took the last address-like token on a
line, which grabbed the wrong value on a `reports:` line.

**Schema:** `icmp_code` and `icmp_from` columns on `traces`, added by migration.

### 1.8.0 — Debug page

- New Debug tab with live trace worker state and a filterable event log.
- Every trace, reverse DNS lookup and collector event is recorded with detail:
  the exact command line, the resolved address, the path, the stored trace id
  and the raw traceroute output.
- Filter by destination, category or free text; Follow, Pause, Clear and Export.
- Bounded to the last 3000 events with capped detail, so a long-running session
  costs a fixed amount of memory.
- Reverse DNS cache state shown in the status strip, and a maintenance action
  to clear the cache and force a re-lookup.

### 1.7.0 — Zoom that survives a refresh

- The route graph keeps your zoom level and scroll position when new data
  arrives, instead of refitting on every refresh.
- Auto-fit continues until you choose a zoom level; **Fit** hands control back.
- Live zoom percentage shown beside the zoom buttons.
- Zoom buttons on the route graph, so no scroll wheel is required.

Fixed: the scroll wheel ignored the zoom limits the buttons respected.

### 1.6.0 — Wheel-free zoom on NetFlow

- Drag across the traffic chart to zoom into a range.
- Pan and zoom buttons, plus Ctrl+= / Ctrl+- / Ctrl+arrows / Ctrl+0.
- **Follow now** pins the right edge to the present.

Fixed: on Windows the collector bound with `SO_REUSEADDR`, which lets a second
process bind the same UDP port and silently take delivery of the packets. It
now binds with `SO_EXCLUSIVEADDRUSE` so a leftover instance produces a clear
"port already in use" error instead of stealing traffic.

- Collector status now reports when the last packet arrived, so a bound but
  silent socket is distinguishable from one that is receiving.

### 1.5.0 — NetFlow module

- Tab bar added; NetPath and NetFlow as separate modules.
- Collector for NetFlow v5, NetFlow v9 and IPFIX on one UDP socket, with the
  template cache v9 and IPFIX require.
- Sampling honoured from the v5 header and v9/IPFIX options templates, with a
  manual override.
- Stacked traffic chart, top-N bar chart and a flow record table, all re-sliced
  by group-by: application, protocol, source, destination, conversation,
  exporter, ingress or egress interface, AS or ToS.
- Flows stored in their own database so a busy exporter does not contend with
  the trace scheduler.
- Receive and write split across two threads: a commit on the receive path
  would leave the socket buffer unserviced long enough to drop packets.

Fixed: the stacked area chart painted bands in series order, so the last band
covered all the others and the chart rendered as one flat mass.

Fixed: alternating table rows fell back to the default light palette, putting
near-white text on a near-white background.

### 1.4.0 — Point-in-time snapshots

- Clicking the timeline pins that instant and redraws the route graph from that
  single trace, with a **Return to live** button.
- Clicking a block with no trace says so rather than snapping to the nearest.
- `trace_nearest()` uses two index-backed queries rather than a full scan.

### 1.3.0 — Three timeline lanes

- The timeline split into round-trip time, packet loss and up/down status on a
  shared time axis, so a latency spike, a loss event and an outage are
  distinguishable at a glance.
- Status placed at the bottom, against the time axis.
- Loss bars scale to a fixed 0–100%; RTT bars scale to the window's peak.
- A clean poll draws a thin green line rather than nothing, keeping "measured
  and fine" distinct from "no data".

### 1.2.0 — Readability

- The route canvas is light against the dark chrome, with its own palette so
  the greys and accents have real contrast on white.

### 1.1.0 — One block per poll

- Timeline blocks are sized by the destination's trace interval rather than by
  pixel width: a 60-minute window on a destination polled every minute draws 60
  blocks.
- Boundaries snap to a wall-clock grid, so a block covers the same slice of time
  as the window pans or slides.
- Beyond the pixel budget a block grows to a whole multiple of the interval,
  never a fractional number of polls.
- A dark block now unambiguously means a poll that did not happen.

### 1.0.1 — Names and silent hops

- Renamed to SappiWhere.
- Hop boxes show reverse-DNS names alongside addresses, resolved in the
  background and cached, rather than making every trace wait on DNS.
- Runs of consecutive hops that never reply collapse into a single marker,
  expandable by clicking.

**Schema:** `hostnames` table.

### 1.0.0 — Initial release

- Scheduled traceroutes to user-added destinations, stored in SQLite.
- Route graph showing every address seen at every hop, with divergent paths as
  parallel branches and edge thickness by share of traces.
- Status timeline with an adjustable time period.
- Status determined by the destination hop only, since intermediate routers
  rate-limit ICMP and their loss is not a fault signal.
- Cross-platform: shells out to `traceroute` or `tracert`, so no raw sockets and
  no administrator rights.
