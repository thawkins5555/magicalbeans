# SappiWhere — Network and Storage Requirements

Everything the application needs on the network and everything it writes to
disk, in one place.

Nothing outside this document is opened, contacted or written: there is no
telemetry, no update check, no outbound connection and no file created anywhere
other than the locations below. How the credentials that do exist — a web
login password, an optional stored DHCP credential — are protected is covered
in full in `CREDENTIAL-SECURITY.md`, not repeated here.

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

### Local

| Purpose | Protocol | Address |
| --- | --- | --- |
| Loopback test of the flow collector | UDP | 127.0.0.1 on the flow port |
| Loopback test of the syslog collector | UDP | 127.0.0.1 on the syslog port |

Browsers reach the web interface over TCP to whichever address `--host` binds.
The page loads no external resources — no CDN, no fonts, no analytics — so a
browser with no internet access works normally.

### Not used

sFlow, SNMP polling (GET/GETBULK), syslog over TLS, NetFlow over TCP or
SCTP, and IPv6 flow export are not supported. SNMP is received only —
traps and informs in, nothing queried out. The application makes no
outbound connection to the internet other than DNS and the traceroute
probes themselves.

---

## Storage

Six SQLite databases and nothing else. No registry keys, no temporary files
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

The split is deliberate. The five record files each hold one module's data and
that module's own settings; nothing else goes in them. Configuration read by
more than one module, and the accounts that guard all of it, are in `app.db`,
which is not subject to any size cap and is never trimmed by maintenance.

For backups that means `app.db` is the file that matters. Losing a record file
costs history; losing `app.db` costs the configuration and every account.

One caveat specific to `ipam.db`: if a DHCP server has a stored credential, its
password is encrypted with Windows DPAPI, tied to the machine that encrypted
it. Restoring `ipam.db` onto different hardware brings the credential's
existence back but not its usability — DPAPI will not decrypt it there, and
the DHCP server needs its credential re-entered on the new machine. Everything
else in the file restores normally.

All six sit in one folder, chosen at first run:

| Platform | Default location |
| --- | --- |
| Windows | `%APPDATA%\netpath-monitor\` — for a service account, `C:\Windows\System32\config\systemprofile\AppData\Roaming\netpath-monitor\` |
| Linux, macOS | `$XDG_DATA_HOME/netpath-monitor/`, or `~/.local/share/netpath-monitor/` |

Override any of them individually:

```
python -m netpath --db D:\data\netpath.db --flow-db D:\data\flows.db \
                  --syslog-db D:\data\syslog.db --app-db D:\data\app.db \
                  --ipam-db D:\data\ipam.db --snmp-db D:\data\snmptraps.db
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
| Syslog | messages per second | ~150 bytes per message |

### What keeps it bounded

Three limits, checked every 15 minutes, in this order:

1. **Retention** — delete anything older than N days. Per module.
2. **Row cap** — delete the oldest rows beyond a count. NetFlow, SNMP Trap and
   Syslog.
3. **Size cap** — delete oldest records in chunks until the file fits. Per
   database, defaulting to 512 MB for traces, 2 GB for flows, 256 MB for
   SNMP traps, 1 GB for syslog.

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
