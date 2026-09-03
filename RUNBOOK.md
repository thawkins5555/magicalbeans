# SappiWhere — Runbook

What to do when the monitoring itself is the thing that has gone wrong. Written
for whoever is on call, not for whoever built it: each section is a symptom you
can see on a screen, then the checks in the order worth doing them.

`README.md` is setup, `BACKUP-RESTORE.md` is recovery from backup,
`INTERNALS.md` is why any of this works the way it does.

---

## Contents

- [The poller has stopped](#the-poller-has-stopped)
- [A collector says "stopped unexpectedly"](#a-collector-says-stopped-unexpectedly)
- [A collector is losing messages (`kernel_dropped`)](#a-collector-is-losing-messages-kernel_dropped)
- [The alert engine is behind (`backlog`)](#the-alert-engine-is-behind-backlog)
- [Charts are empty, or history has vanished](#charts-are-empty-or-history-has-vanished)
- [The disk is filling up](#the-disk-is-filling-up)
- [Alert email has stopped](#alert-email-has-stopped)
- [A ConfigRX backup says the host key changed](#a-configrx-backup-says-the-host-key-changed)
- [The poll pool is saturated](#the-poll-pool-is-saturated)
- [A flood of alerts nobody asked for](#a-flood-of-alerts-nobody-asked-for)
- [Nobody can sign in](#nobody-can-sign-in)
- [A database is corrupt](#a-database-is-corrupt)

---

## The poller has stopped

**Symptom.** Device statuses stop changing. Every device stays whatever it was.
The Nodes tab still renders, the web interface is fine, but nothing is being
polled. The Dashboard's poller tile shows no busy workers.

**What it usually is.** One unhandled exception in the scheduler thread. Until
4.37.0 that thread had no guard: a single transient database error killed it
permanently and silently, with nothing on any screen saying so. From 4.37.0 the
loop is guarded, sets `poller.error`, and the Nodes tab and the Debug tab both
show the message.

**Checks, in order.**

1. **Nodes tab, poller status line.** If it names an error, that is your
   answer; go to step 4. If the application is older than 4.37.0 it will say
   nothing useful — go to step 2.
2. **Debug tab**, filter to Nodes. Look for a traceback. The last event before
   polling stopped is the interesting one, not the newest.
3. **The service log** — `journalctl -u sappiwhere --since "1 hour ago"`, or
   the service console's Console output pane.
4. **Act on the error.**
   - *"database is locked" or "disk I/O error"* — the disk, or a network share
     under the data directory. Check free space, check the mount. SQLite over
     NFS or SMB is a bad idea and this is how it announces itself.
   - *"unable to open database file"* — permissions. The data directory is
     `0700` and its files `0600` from 4.37.0; if the service account changed,
     it no longer owns them.
   - *A traceback in the polling code* — capture it, then restart.
5. **Restart the service.** The poller re-seeds each device's due time from its
   own last poll, so a restart does not fire the whole fleet at once.

**Confirm it recovered:** the poller status line shows busy workers, and a
device you select drops to the fast cadence and updates.

---

## A collector says "stopped unexpectedly"

**Symptom.** The NetFlow, SNMP Trap or Syslog tab shows the listener stopped,
with a reason, and the packet counter is frozen.

**What it usually is.** One malformed datagram. Before 4.37.0 the receive
threads had no exception guard and a decoder that raised took the listener with
it — an 18-byte NetFlow packet was enough — and the status read "Collector
stopped", indistinguishable from an operator stopping it. From 4.37.0 the
receive loops count the error, log the first one per minute, keep running, and
the status distinguishes *stopped* from *stopped unexpectedly: <reason>*.

**Checks, in order.**

1. **Read the reason on the status strip.** It names the exception.
2. **Debug tab**, filtered to that module. The `errors` counter tells you
   whether this is one bad sender or a flood.
3. **Find the sender.** The Debug log records the first packet from each
   exporter and every decode failure with its source address. A single device
   producing malformed exports is usually one with old firmware; take it out of
   the export list until it is upgraded.
4. **Restart the listener** from its settings dialog — off, Apply, on, Apply.
   The service does not need restarting.

**If it stops again immediately**, the sender is still sending it. The
listener now survives that, so a repeating error in the counter with the
listener still running is the expected state, not a fault to chase at 02:00.

---

## A collector is losing messages (`kernel_dropped`)

**Symptom.** `kernel_dropped` is non-zero in a collector's status strip or on
the Dashboard's collectors tile, and an ERROR appears in the log the first time
it rises.

**What it means, precisely.** Messages arrived at this host and the *kernel*
discarded them because the socket's receive buffer was full before this
application read from it. They were never seen by any code here and cannot be
recovered. This counter is new in 4.37.0; before it, this loss was completely
invisible — a measured 300,000 syslog messages at 38,000/s stored 93,000 and
reported zero dropped.

**Checks, in order.**

1. **Is it still rising?** A one-off during a burst is worth noting, not
   acting on. A counter climbing steadily is a capacity problem.
2. **What is sending?** Syslog tab, group by host over the last hour. One
   device in a debug loop is by far the most common cause and is worth fixing
   at the device.
3. **Raise the receive buffer** if the volume is legitimate. On Linux:
   ```
   sysctl -w net.core.rmem_max=16777216
   sysctl -w net.core.rmem_default=4194304
   ```
   and restart the service so the sockets pick it up. Make it permanent in
   `/etc/sysctl.d/`.
4. **Turn on per-source rate limiting.** The syslog collector's
   `per_source_rate`, in Syslog settings, is 200 messages a second per source
   by default; traffic above it is counted as `throttled` rather than dropped
   by the kernel, so you keep everyone else's messages and know whose you
   shed. Setting it to 0 disables the limit.
5. **Check the writer is not the bottleneck.** If `queue` in the Debug counters
   is also high, the receive thread is fine and the database write path is
   behind — see the disk section.

---

## The alert engine is behind (`backlog`)

**Symptom.** `backlog` on the Dashboard's collectors tile, or in the alert
engine's counters, is a large number and not falling. Alerts arrive minutes
after the event that caused them.

**What it means.** The engine drains new traps, syslog rows and device events
per tick. Its drain used to be capped at 500 rows per source per five-second
tick — 100 rows a second — against an ingest that can exceed 10,000 a second,
so a busy hour put it permanently behind with nothing indicating it. From
4.37.0 it loops to catch up within a per-tick budget and exposes how far behind
it is.

**Checks.** A backlog that falls steadily needs nothing; it is catching up.
One that grows means sustained ingest above what the engine can evaluate:
reduce the ingest (the rate limit above, or at the sending device), or reduce
the work per row by disabling syslog or trap rules you do not act on. A backlog
that is large and *static* means the engine is not running — see the poller
section, and check the Debug tab for the alert engine's own errors.

---

## Charts are empty, or history has vanished

**Symptom.** A device's metric chart draws nothing, or draws only the last few
minutes, or a window wider than a few days is blank.

**What it usually is, on 4.36.x and earlier.** Two defects that are fixed in
4.37.0 and worth recognising if you are running an older build:

- **The row cap was applied to the whole table, not per metric.** Fifty
  thousand sample rows survived each fifteen-minute maintenance pass no matter
  how many devices were writing, so above a hundred devices almost all history
  was deleted every quarter hour. Measured on a 2,000-device fleet, under one
  sample in three metrics survived a pass.
- **The hourly rollup never ran.** `samples_hourly` was always empty, so any
  chart window wider than the raw retention returned no points at all.

**On 4.37.0.** Check, in order:

1. **`sample_retention_days`** (Nodes → Settings), default 3. A window wider
   than this reads hourly rollups, not raw samples; the dialog says so.
2. **`sample_row_cap_per_metric`**, default 5,000. At a 120-second interval
   that is about a week per metric. If you have lowered it, that is your
   window.
3. **`rollup_retention_days`**, default 400, and whether `samples_hourly` has
   rows: `sqlite3 nodes.db "SELECT COUNT(*) FROM samples_hourly;"`. It fills on
   the first maintenance pass after an hour has completed, so a freshly
   installed system legitimately has none yet.
4. **Whether the metric is being written at all.** A blank CPU chart on a
   switch may simply mean the device does not answer any CPU object this
   application asks for. The device's metric list shows what it does answer.

---

## The disk is filling up

**Symptom.** Free space falling, or a database at its size cap, or write errors
in the log.

**Checks, in order.**

1. **Settings tab** shows each database's current size against its cap. The
   Dashboard's storage tile shows the same, worst first.
2. **Identify the file.** It will almost always be `flows.db` (2 GB cap by
   default) or `syslog.db` (1 GB). Syslog storage is about 455 bytes per
   message — the decoded fields, the original line, and its entry in the
   full-text search index — so 10 messages a second is roughly 390 MB a day.
3. **The size cap should already be holding it.** Three limits run every
   fifteen minutes, in order: retention by age, then a row cap, then the size
   cap, which deletes oldest-first in chunks until the file fits. The size cap
   wins over the others deliberately — filling a disk is worse than losing old
   data.
4. **If a file is over its cap and staying there**, maintenance is not running.
   Check the Debug tab for errors from the maintenance pass, and check that
   nothing has the database locked.
5. **Reclaiming space.** Deleting rows does not shrink the file by itself.
   From 4.37.0 the databases run in incremental-vacuum mode and free pages are
   returned a few thousand at a time after each trim, with the WAL truncated
   afterwards, so this happens on its own without the long lock-holding
   `VACUUM` earlier releases used. To force it: **Settings → Maintenance**.
6. **If the disk is genuinely full**, SQLite will be raising I/O errors and
   things will be stopping. Free space first, by moving an old backup off the
   volume, then lower the caps rather than relying on manual pruning.

---

## Alert email has stopped

**Symptom.** No alert mail, or an `smtp_failing` alert on the Alerts tab.

**What `smtp_failing` means.** From 4.37.0 mail is sent by a queue thread with
a circuit breaker: five consecutive failures open it for fifteen minutes, and
opening it raises this alert. The point is that "the monitor cannot tell you
anything" is precisely the failure that cannot be delivered by email, so it is
raised in the application instead.

**Checks, in order.**

1. **Alerts → Settings → Notifications → Send test.** The error it returns is
   the real one.
2. **The usual causes**, in order of likelihood: the relay stopped accepting
   mail from this host's address; a certificate expired and verification is on;
   the From address was rejected as unauthorised; DNS for the relay's name
   stopped resolving.
3. **The hourly cap.** If mail simply stopped mid-incident and resumed on the
   hour, you hit it. Every suppressed message is recorded against its alert as
   a failed notification, so the alert's detail pane tells you. Raise the cap,
   or use the rollup below to send fewer.
4. **On Linux, check you are not trying to authenticate.** An SMTP password
   cannot be stored on a non-Windows host at all; if the relay has started
   demanding authentication, this host can no longer send through it. See
   `CREDENTIAL-SECURITY.md` §10.
5. **The breaker closes itself.** The first job after the cooldown is the
   probe; if it succeeds the alert resolves on its own. You do not need to
   restart anything.

---

## A ConfigRX backup says the host key changed

**Symptom.** A backup fails with "host key changed — accept in the device's
ConfigRX settings", or the SSH terminal refuses to connect for the same reason.

**Treat this as a security event until you have explained it.** The
application pinned this device's SSH host key the first time it connected and
is now being offered a different one. The benign explanations are real and
common — the device was replaced, its firmware was upgraded, its keys were
regenerated, or two devices share an address through NAT — and so is the one
that is not benign: something is between you and the device, and the password
this connection would send is one it wants.

**Checks, in order.**

1. **Was this device touched?** Replacement, firmware upgrade, factory reset,
   key regeneration. Ask before assuming.
2. **Verify the key out of band.** On the device's own console:
   `show crypto key mypubkey rsa` on Cisco, `get system
   ssh-host-key` or the equivalent on FortiOS. Compare the fingerprint with
   the one the error reports. A console session over a serial cable or an
   established management path is the point — verifying it over the SSH
   session you are suspicious of proves nothing.
3. **If it checks out**, clear the stored key: the device's ConfigRX settings
   dialog has a **Forget host key** action, gated on `configrx: write`. The
   next connection pins the new key.
4. **If it does not check out**, stop. Do not clear the key. The stored
   credential has not been sent — the check happens before authentication —
   so nothing has leaked yet. Investigate the path.

The host-key store is shared by ConfigRX and the SSH terminal, so forgetting a
key affects both. It lives in `configrx.db` and survives a restore, which is
what you want.

---

## The poll pool is saturated

**Symptom.** `poll_overrun` events across the fleet, a `poll_pool_saturated`
alert, or the Dashboard's poller tile showing queued work consistently above
the pool size.

**Read the gauge correctly.** The busy figure counts queued *plus* running
work, so a number above the worker count is backlog depth, not impossible
concurrency: 48 against a pool of 16 means 16 polls in flight and 32 waiting.

**Checks, in order.**

1. **Are devices down?** A device that is not answering costs far more worker
   time than one that is — three ping timeouts plus three SNMP timeouts per
   poll. A site outage saturates a pool that was comfortable five minutes
   earlier, and the saturation is a symptom of the outage rather than a
   separate problem.
2. **Is one device eating a worker?** A device with hundreds of interfaces
   that stops answering part-way through its interface walk used to hold a
   worker for over an hour; from 4.37.0 there is a wall-clock deadline of half
   the poll interval and it gives up after three consecutive timeouts, logging
   "read N of M". Look for that message.
3. **Raise the interval before raising the workers.** Going from 60 to 120
   seconds halves the load exactly. More workers past a point buys nothing —
   this is a single process with a single database connection and the write
   path becomes the limit.
4. **Then raise the workers**, in steps, watching CPU. Sixteen is the shipped
   default.
5. **If it is steady-state saturation at your fleet size**, you are at the
   capacity of one instance. `NETWORK-AND-STORAGE-REQUIREMENTS.md` has
   measured figures. There are no remote pollers in this release.

---

## A flood of alerts nobody asked for

**Symptom.** Hundreds of alerts and emails in minutes.

**Work out which of the four it is.**

1. **A real outage, not rolled up.** Fifty devices behind one switch, each with
   its own alert, means the **upstream device** field is not set on them. Set
   it — on the device form — and the next outage is one alert. This is the
   single most valuable field in the product for anyone with more than a rack.
2. **Onboarding.** Adding devices raises `mib_missing` on every device with a
   recognised vendor and no uploaded MIB. From 4.37.0 that rule does not email
   and auto-resolves; on earlier builds every one of them arrived titled
   "<device> is not responding", which it was not.
3. **A device in a trap or syslog loop.** One device, one message repeated.
   Mute the device, fix it, unmute. Syslog settings' `per_source_rate` limits
   the damage at ingest, and a line a device repeats is collapsed into one row
   with a repeat count rather than filling the table.
4. **A rule that is too broad.** `trap_critical` matched every trap of any
   severity before 4.37.0, so a config-save trap opened a severity-2 "Critical
   SNMP trap". If you are on an older build, either disable that rule or raise
   its severity gate.

**To stop the noise now:** mute the device or devices (Alerts → the device's
row), or turn off the offending rule. **Acknowledge all** clears the badge
without resolving anything and ignores the current filter — its confirmation
says so.

---

## Nobody can sign in

1. **Is the service running?** `systemctl status sappiwhere`. If the browser
   shows a connection error rather than a sign-in page, this is the answer.
2. **Locked out after failed attempts?** From 4.37.0 an account is locked for a
   period after twenty failures in fifteen minutes and returns 429. It clears
   itself; wait, or restart the service.
3. **Stuck on "you must change your password"?** That is the server refusing
   every other route until the change is done, which is correct. Change it.
4. **The last admin password is genuinely lost.** Stop the service, delete the
   `users` table from `app.db`, start it: the default `admin`/`admin` account
   is recreated with full access and must change its password immediately.
   ```
   systemctl stop sappiwhere
   sqlite3 ~/.local/share/netpath-monitor/app.db "DROP TABLE users;"
   systemctl start sappiwhere
   ```
   This is a real recovery path and it is also why file permissions on the data
   directory matter: anyone who can write `app.db` can do this.
5. **After it is back**, check the audit log (Settings → Audit, `admin`
   capability) for what happened before the lockout.

---

## A database is corrupt

**Symptom.** "database disk image is malformed", or `PRAGMA integrity_check`
returning anything but `ok`.

1. **Stop the service.** Every further write makes it worse.
2. **Copy the file, its `-wal` and its `-shm`** somewhere safe before touching
   anything.
3. **Try the dump-and-reload**, which recovers more often than people expect:
   ```
   sqlite3 nodes.db ".recover" | sqlite3 nodes-recovered.db
   sqlite3 nodes-recovered.db "PRAGMA integrity_check;"
   ```
   If that returns `ok`, move it into place and start the service. Schemas
   migrate forward on open, so a recovered file from an older release is fine.
4. **Otherwise restore from backup** — `BACKUP-RESTORE.md`, and note the DPAPI
   caveat if you are restoring onto different hardware.
5. **The databases are independent.** A corrupt `flows.db` costs you flow
   history and nothing else; delete it and the application recreates it empty
   on the next start. Do not do that with `nodes.db`, `alerts.db` or
   `configrx.db` without a backup — those hold configuration, not just records.
6. **Then find out why.** Corruption in SQLite is almost always the storage
   underneath: a database on an NFS or SMB share, a volume that lies about
   flushes, or a disk that is failing. Check `dmesg` and SMART before putting
   it back on the same volume.
