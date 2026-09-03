# SappiWhere — Network and Storage Requirements

Everything the application needs on the network and everything it writes to
disk, in one place.

Nothing outside this document is opened, contacted or written: there is no
telemetry, no update check, no outbound connection and no file created anywhere
other than the locations below. How the credentials that do exist — a web
login password, an optional stored DHCP credential, an optional stored
SNMPv3, SMTP, Wireless SNMP or ConfigRX SSH credential — are protected is
covered in full in `CREDENTIAL-SECURITY.md`, not repeated here.

---

## Network

### Inbound

| Purpose | Protocol | Port | Required? |
| --- | --- | --- | --- |
| Web interface | TCP | 8443 (configurable) | Only when running with `--headless` |
| NetFlow / IPFIX collector | UDP | 2055 (configurable) | Only if the NetFlow module is used |
| SNMP trap receiver | UDP | 162 (configurable) | Only if the SNMP Trap module is used |
| Syslog collector | UDP | 514 (configurable) | Only if the Syslog module is used |
| Syslog collector | TCP | 514 (configurable, off by default) | Only if TCP syslog is enabled |
| ICMP Time Exceeded (type 11) replies from routers | ICMP | — | Yes, for NetPath |
| ICMP Destination Unreachable (type 3) replies | ICMP | — | Yes, for NetPath |
| ICMP Echo Reply (type 0) from the destination | ICMP | — | Windows only, for NetPath |
| UDP Port Unreachable replies from the destination | ICMP | — | macOS/Linux only, for NetPath |

**IPv6.** From 4.37.0 the three collectors bind dual-stack where the operating
system allows it (`AF_INET6` with `IPV6_V6ONLY` off, falling back to IPv4 if
that is refused), and a source arriving as an IPv4-mapped address is normalised
back to its plain form so it still matches a device. NetPath resolves and
traces to IPv6 destinations, and the SNMP poller reaches a device whose address
contains a colon. Earlier releases were IPv4-only throughout, silently: a
device on an IPv6 management plane was unreachable and nothing said so.

**Credential storage is a Windows-only capability.** This is a network and
storage requirement in practice, because it decides what a Linux host can
actually do. Encrypted credentials use Windows DPAPI and there is no portable
equivalent in this release, so on a non-Windows host SNMPv3 authNoPriv polling,
ConfigRX backups, the SSH terminal's stored password, authenticated SMTP and
the DHCP credential are all unavailable — the API refuses to store the secret
rather than keeping it weakly. Plan a Linux deployment around SNMPv1/v2c or v3
noAuthNoPriv and an unauthenticated relay, or run the service on Windows. See
`CREDENTIAL-SECURITY.md`.

The collector port is set under **Settings** on the NetFlow tab. Common
alternatives are 2056, 4739 (the IPFIX default) and 9995. Ports below 1024
require administrator rights to bind.

The web port is set with `--port`. It carries no authentication yet, so bind it
to an interface you trust with `--host`, or to `127.0.0.1` and reach it through
something that does authenticate. TLS is used when `--cert` and `--key` are
given and plain HTTP otherwise; the port number does not change that.

Syslog's standard port is 514, but binding below 1024 needs administrator or
root rights. Running the collector on 5140 and pointing devices at that avoids
the privilege entirely, which is usually the better answer on Windows.

SNMP's standard trap port is 162, with the same privilege requirement below
1024; 1162 avoids it. On Windows, the built-in "SNMP Trap" service also binds
162 by default and will silently take traps meant for this app — stop that
service first, or use a different port.

On Windows each listening port needs an inbound firewall rule:

```powershell
New-NetFirewallRule -DisplayName "SappiWhere web" `
    -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
New-NetFirewallRule -DisplayName "SappiWhere syslog" `
    -Direction Inbound -Protocol UDP -LocalPort 514 -Action Allow
New-NetFirewallRule -DisplayName "SappiWhere SNMP trap" `
    -Direction Inbound -Protocol UDP -LocalPort 162 -Action Allow
```

On Windows this needs an inbound firewall rule:

```powershell
New-NetFirewallRule -DisplayName "SappiWhere NetFlow" `
    -Direction Inbound -Protocol UDP -LocalPort 2055 -Action Allow
```

The ICMP replies are responses to probes this host sent, so a stateful firewall
normally permits them without a rule. A firewall that blocks ICMP inbound will
make every destination show as *no reply* regardless of whether it is actually
reachable.

### Outbound

| Purpose | Protocol | Port | Notes |
| --- | --- | --- | --- |
| Traceroute probes, Windows | ICMP Echo Request (type 8) | — | `tracert` with increasing TTL |
| Traceroute probes, macOS/Linux | UDP | 33434–33534 | `traceroute` default; incrementing destination port per probe |
| Forward DNS, resolving destination names | UDP/TCP | 53 | To this machine's configured DNS servers |
| Reverse DNS (PTR), naming hop addresses | UDP/TCP | 53 | Same servers; can be disabled on the Settings tab |
| IPAM subnet discovery | ICMP Echo Request (type 8) | — | One ping per address in an enabled subnet, on a schedule |
| IPAM DHCP polling, ambient identity or Credential Manager | TCP (MS-RPC) | 135, plus a dynamic high port | To each configured Windows DHCP server; read-only |
| IPAM DHCP polling, a stored credential | TCP (WinRM) | 5985 (HTTP) or 5986 (HTTPS) | Only for a server with a username and password saved; read-only |
| Nodes SNMP polling | UDP | 161 (fixed) | GET/GETBULK to each configured device, on its own poll interval |
| Nodes ping monitoring | ICMP Echo Request (type 8) | — | One ping per device with ping enabled, on its own poll interval |
| Nodes per-device or per-subnet discovery | ICMP Echo Request (type 8), then UDP 161 | — | Same shape as IPAM's own subnet sweep, plus an SNMP identity probe against whatever answers |
| Alerts email notification | TCP (SMTP) | 25/587/465 (server-dependent) | Only if email notification is enabled; none, STARTTLS or SSL/TLS per the configured server |
| Wireless SNMP polling | UDP | 161 (fixed) | GETNEXT to each configured FortiGate Wireless Controller, on its own poll interval — never to the APs behind it individually |
| ConfigRX config backup | TCP (SSH) | 22 (configurable per device) | Only for a device with backup enabled and a credential stored; read-only — one fixed "show config" command, never a push |

Traceroute probes go to every destination you add, and to every router on the
path to it. Firewalls between here and a destination need to permit the probe
type above and allow the ICMP replies back.

No outbound connection is made for the NetFlow module — it only listens.

DHCP polling's transport depends on how a server authenticates. Ambient
identity and Credential Manager both go through the `DhcpServer` PowerShell
module's own transport, Microsoft's RPC over TCP: an initial connection to the
endpoint mapper on 135, which hands back a dynamically chosen high port for
the actual call. The exact high port varies and is not something this
application controls; a firewall between SappiWhere and a DHCP server needs
either the full dynamic RPC range open or, better, the DHCP server's RPC port
range fixed to something narrower with `netsh int ipv4 set dynamicport tcp
startport=<n> numberofports=<n>` (see Microsoft's guidance on restricting RPC
dynamic port allocation). This is a property of Windows RPC, not of
SappiWhere.

A stored credential goes over PowerShell remoting instead — `Invoke-Command`
to the DHCP server, which needs WinRM listening there. This is usually already
true of a domain-joined server with remote management enabled, but is worth
checking before relying on it: `Test-WSMan <server>` from any Windows machine
confirms whether WinRM answers. If it doesn't, `winrm quickconfig` on the DHCP
server turns it on. The read-only account only needs whatever local rights
let it query DHCP; it does not need to be a local administrator on the DHCP
server for this to work, though DHCP Server management typically expects
membership in the local `DHCP Users` group or higher.

Discovery's ARP lookups are read-only and local to whichever machine runs
SappiWhere — nothing is transmitted on the wire beyond the ping itself; the
address-to-MAC mapping comes from the operating system's own ARP cache, which
only reflects the local broadcast domain regardless.

Nodes polls port 161 always — it is the standard SNMP agent port and is not
currently configurable per device or profile. An SNMPv3 device with only
`authPriv` configured is rejected at session setup rather than polled: this
app has no AES/DES implementation and takes no third-party dependency, the
same deferral the SNMP Trap receiver made for inbound decryption. Wireless
polling is the identical shape and the identical `authPriv` limitation,
against a controller instead of a device.

ConfigRX is the one place this application makes an outbound SSH
connection, and the one place it depends on a third-party library
(paramiko) rather than the standard library alone — a deliberate,
documented exception, made specifically so an SSH password never has to
travel on a command line or appear in a process list; see
`CREDENTIAL-SECURITY.md`. It only ever runs one fixed, read-only "show
config" command per connection, never anything that could change a
device's configuration.

### Local

| Purpose | Protocol | Address |
| --- | --- | --- |
| Loopback test of the flow collector | UDP | 127.0.0.1 on the flow port |
| Loopback test of the syslog collector | UDP | 127.0.0.1 on the syslog port |

Browsers reach the web interface over TCP to whichever address `--host` binds.
The page loads no external resources — no CDN, no fonts, no analytics — so a
browser with no internet access works normally.

### Not used

sFlow, syslog over TLS, NetFlow over TCP or SCTP, and IPv6 flow export are
not supported. SNMPv3 `authPriv` is not supported for polling, and v3
informs are not acknowledged — see `FEATURES.md`. The application makes no
outbound connection to the internet other than DNS, the traceroute probes
themselves, and — only if Alerts' email notification is turned on — the
configured SMTP server.

---

## Storage

Ten SQLite databases and nothing else. No registry keys, no temporary files
left behind, no writes to the application folder at runtime — the code
directory can be read-only.

### Where

| File | Holds | Grows with |
| --- | --- | --- |
| `app.db` | Global settings, user accounts, the shared reverse-DNS cache | Distinct addresses seen — kilobytes |
| `netpath.db` | Destinations, traces, per-hop samples, NetPath settings | Trace frequency |
| `flows.db` | Flow records, exporters, interface names, NetFlow settings | Exported flow volume |
| `snmptraps.db` | Traps, hourly rollup counts, SNMP Trap settings | Trap rate — normally light; a device stuck in a fault loop is the exception |
| `syslog.db` | Messages, hourly rollup counts, the search index, Syslog settings | Message rate — the substring index is roughly the size of the messages again |
| `ipam.db` | Subnets, discovered hosts, conflicts, DHCP scopes and leases, IPAM settings, an optional DHCP credential | Subnet sizes swept and DHCP scope sizes — bounded by the per-subnet address cap |
| `nodes.db` | Devices, polling profiles, interfaces, metric samples, device/interface events, uploaded MIBs, discovery jobs, Nodes settings, optional SNMPv3 credentials | Device count × poll frequency × metrics per device |
| `alerts.db` | Rules, email templates, alerts, notification history, Alerts settings, an optional SMTP credential | Alert volume — normally light; a flapping device or a noisy threshold is the exception |
| `wireless.db` | Controllers, access points, per-radio detail, Wireless settings, optional SNMP credentials | Controller count × AP count per controller — normally small, a handful of controllers rather than hundreds |
| `configrx.db` | Per-device backup configuration, stored config backups (compressed, hash-deduped), ConfigRX settings, optional SSH credentials | Device count × how often a device's config actually changes — an unchanged config never adds a row |

The split is deliberate. The nine record files each hold one module's data
and that module's own settings; nothing else goes in them. Configuration
read by more than one module, and the accounts that guard all of it, are in
`app.db`, which is not subject to any size cap and is never trimmed by
maintenance.

For backups that means `app.db` is the file that matters. Losing a record file
costs history; losing `app.db` costs the configuration and every account.

One caveat specific to `ipam.db`, `nodes.db`, `alerts.db`, `wireless.db`
and `configrx.db`: any stored credential in them — a DHCP server's
password, a device or polling profile's SNMPv3 auth password, the SMTP
password, a Wireless controller's SNMP auth password, a ConfigRX SSH
password — is encrypted with Windows DPAPI, tied to the machine that
encrypted it. Restoring one of these files onto different hardware
brings the credential's existence back but not its usability — DPAPI
will not decrypt it there, and the credential needs re-entering on the
new machine. Everything else in each file restores normally.

All ten sit in one folder, chosen at first run:

| Platform | Default location |
| --- | --- |
| Windows | `%APPDATA%\netpath-monitor\` — for a service account, `C:\Windows\System32\config\systemprofile\AppData\Roaming\netpath-monitor\` |
| Linux, macOS | `$XDG_DATA_HOME/netpath-monitor/`, or `~/.local/share/netpath-monitor/` |

Override any of them individually:

```
python -m netpath --db D:\data\netpath.db --flow-db D:\data\flows.db \
                  --syslog-db D:\data\syslog.db --app-db D:\data\app.db \
                  --ipam-db D:\data\ipam.db --snmp-db D:\data\snmptraps.db \
                  --nodes-db D:\data\nodes.db --alerts-db D:\data\alerts.db \
                  --wireless-db D:\data\wireless.db --configrx-db D:\data\configrx.db
```

Running as a service, set these explicitly. The default resolves against the
service account's profile, which is a surprising place to find several
gigabytes of flow records later.

Each database is in WAL mode, so each has two companions beside it:

| File | What it is |
| --- | --- |
| `<name>.db` | The database |
| `<name>.db-wal` | Write-ahead log — recent writes not yet folded in |
| `<name>.db-shm` | Shared-memory index for the WAL |

The `-wal` and `-shm` files appear while the service runs and normally
disappear on a clean stop. Copy all three together, or stop the service first,
or the most recent data is lost.

**File modes, on POSIX hosts.** From 4.37.0 the data folder is created `0700`
and every database, along with its `-wal` and `-shm` companions, is narrowed to
`0600` when it is opened. Before that they were created with the process umask
— typically a `0644` file in a `0755` directory — so any local account on the
host could read stored settings, encrypted credential blobs, syslog, traps and
configuration backups. A folder or file from an older install is tightened on
the next start; if you have deliberately widened them (a backup agent running
as another account, say) that widening is undone, and the right answer is to
give the agent group access to a copy rather than to the live folder. Windows
hosts are unchanged: NTFS inheritance from the data folder governs there, and
nothing in the application alters an ACL.

### Why each one is written

**Traces** are the point of the NetPath module: a route graph and a timeline
are drawn from stored history, so nothing can be shown for a period that was
not recorded. Each trace writes one row plus one row per address seen at each
hop.

**Reverse-DNS answers** are cached so the same router is not looked up on every
trace. Without the cache a busy install would generate a DNS query per hop per
poll, which is both slow and rude to the DNS servers.

**Hourly syslog and SNMP trap counts** are kept alongside the messages/traps
so the timeline reads at most a few dozen rows rather than scanning a day of
records. Without it the histogram gets slower every day the collector runs.

**User accounts** hold a username and a salted scrypt hash. No password is
stored, in any form, at any point. See `FEATURES.md`.

**Settings** are stored so the service comes back the way it was left,
including the web listener, so a port set in the console survives a restart.

### How large

It depends entirely on what is being watched, so measure rather than estimate.
The Settings tab shows the current size of each database against its cap, and
the service console shows the same three figures.

Rough shapes to start from:

| Module | Driver | Order of magnitude |
| --- | --- | --- |
| NetPath | destinations × polls per day × hops | a few MB per destination per month |
| NetFlow | flow records exported | tens of MB to several GB per day |
| SNMP Trap | traps per device per day | ~200 bytes per trap; normally the smallest of the record files |
| Syslog | messages per second | **~455 bytes per message**, measured, not the ~150 this table used to claim — a stored row is the decoded fields *plus* the original line *plus* its entry in the FTS5 trigram search index, and the index is most of the difference. Budget for it: 10 messages/s is about 390 MB a day. |
| Nodes | devices × poll frequency × metrics per device | ~33 bytes per sample row; see the per-port arithmetic below. Raw samples are kept for `sample_retention_days` (3 by default) and rolled up into hourly min/avg/max, which are kept for `rollup_retention_days` (400). A second limit runs beside the day count: `sample_row_cap_per_metric` (5,000) is the most raw rows any one metric keeps, and from 4.37.0 it is applied per metric rather than to the whole `samples` table — as a whole-table cap of 50,000 rows it left a 2,000-device fleet with under a third of one poll cycle of history. **The rollup genuinely runs from 4.37.0** too; in every earlier release `compact_rollup()` had no caller, `samples_hourly` was always empty, and a chart wider than the raw window drew nothing. |
| Alerts | alert volume | normally the smallest of all — resolved alerts and notification history, not a per-poll log |
| Wireless | controller count × AP count | a few KB per AP; normally tiny, since a site has a handful of controllers, not hundreds |
| ConfigRX | device count × how often configs actually change | a device's own config text, compressed, once per change — most devices add nothing between backups |

### What a port costs

Nodes is the module whose storage is easiest to get wrong, because the cost is
per *interface*, not per device, and a 48-port switch is 48 interfaces plus the
device itself.

A poll of one interface records six metrics: inbound and outbound bits per
second, error rate, discard rate, and inbound and outbound utilisation
percentage. A sample row is about **33 bytes**. So, per device per poll:

    ports × 6 samples × 33 B  +  ~5 device-level samples (RTT, loss, CPU, memory, uptime)

| Fleet | Interval | Raw samples per day | Raw bytes per day |
| --- | --- | --- | --- |
| 100 × 48-port switches | 120 s | 20.9 M | ~690 MB |
| 1,000 × 48-port switches | 120 s | 209 M | ~6.9 GB |
| 2,000 × 48-port switches | 120 s | 418 M | ~13.8 GB |
| 2,000 × 48-port switches | 60 s | 836 M | ~27.6 GB |
| one 500-port chassis | 120 s | 2.2 M | ~71 MB |

At the shipped three-day raw retention, the 2,000-device row above settles at
roughly **41 GB** of raw samples, which is why `sample_row_cap_per_metric`
exists and why it is applied per metric rather than to the table as a whole.
The hourly rollups that survive beyond three days are three rows (min, average,
max) per metric per hour: for the same fleet that is about **17 GB for the
full 400 days**, so the long tail costs less than half of one day of raw data
per month.

Two practical consequences. First, if you only need trends, shorten
`sample_retention_days` rather than lowering the row cap — the rollups keep the
shape of the history at a fiftieth of the size. Second, doubling the poll rate
doubles the storage exactly, with no economies anywhere; 60 seconds is a
meaningful decision, not a free one.

### How many devices

The honest answer is that it depends on ports per device, poll interval and
disk, and that this application is a single process with a single database
connection, so every ceiling compounds in one place. Measured on one Linux
container with a local disk, a 60-second interval and 48-port switches: a
fleet of **250** is comfortable, at **1,000** the poll pool saturates and an
outage takes several minutes to be seen, and at **2,000** an outage may not be
detected at all because each device is only reached every few minutes. Doubling
the interval to the shipped 120 seconds roughly doubles all three numbers.

Those figures are from before the 4.37.0 write-path work (batched sample
writes, cached scheduler configuration, one keyed query per alert tick, GETBULK
for the interface columns) which raises the write ceiling by about seventy
times on its own; re-measure on your own hardware rather than trusting either
set of numbers. `FEATURES.md` says "hundreds of devices" in one place; read
that as the size at which nothing needs thinking about, not as a limit.

### What keeps it bounded

Three limits, checked every 15 minutes, in this order:

1. **Retention** — delete anything older than N days. Per module, including
   ConfigRX's backups.
2. **Row cap** — delete the oldest rows beyond a count. NetFlow, SNMP Trap
   and Syslog; ConfigRX has the same idea per device instead of globally
   (keep at most N backups per device).
3. **Size cap** — delete oldest records in chunks until the file fits. Per
   database, defaulting to 512 MB for traces, 2 GB for flows, 256 MB for
   SNMP traps, 1 GB for syslog, 1 GB for Nodes and 128 MB for Alerts.
   Nodes and Alerts trim only their genuinely historical tables — metric
   samples and device/interface events for Nodes, resolved alerts and
   notification history for Alerts — never the current-state tables
   (devices, polling profiles, interfaces, MIB objects, rules, templates)
   that describe things as they are configured now, not a log. Wireless
   and ConfigRX have no absolute size cap of their own — Wireless because
   its data volume is inherently small (a handful of controllers and their
   APs, not per-poll samples), ConfigRX because retention (1) and the
   per-device count cap (2) together already bound it, and its own
   hash-dedup means an unchanging fleet of devices adds nothing between
   backups regardless.

The size cap wins over the other two: if retention says keep 30 days but the
cap is reached at 9, the ninth day is where it stops. That is deliberate —
filling a disk is worse than losing old data, and a monitoring tool that takes
a server down with it has failed at its job.

Deletion vacuums and checkpoints the WAL, so space is actually returned to the
filesystem rather than left as free pages inside the file.

### What is never written

- No password, in any form other than a salted hash.
- No session token; sessions are in memory and end when the service stops.
- No packet captures. NetFlow stores decoded flow records, not packets;
  syslog stores decoded messages plus the original line; SNMP Trap stores
  decoded traps only — the original datagram is kept only if **Store the
  original datagram** is turned on in its settings, off by default.
- No debug event log. What the Debug tab shows is a memory buffer, discarded on
  stop.
