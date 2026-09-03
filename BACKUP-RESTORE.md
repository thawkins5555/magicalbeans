# SappiWhere — Backup and restore

Ten SQLite databases, all in WAL mode, all written by one live process. That
combination has exactly one trap in it, and this document is mostly about not
falling into it.

`NETWORK-AND-STORAGE-REQUIREMENTS.md` says what each file holds and what bounds
its growth. `RUNBOOK.md` covers recovering from a corrupt file rather than from
a backup.

---

## The one thing to get right

**A running SQLite database in WAL mode is three files, and copying only the
`.db` gives you a torn backup.** Every database here has a `-wal` (the
write-ahead log, holding committed transactions not yet folded into the main
file) and usually a `-shm` (the shared-memory index into it). Copy
`nodes.db` alone while the poller is writing and you get a file that is
internally consistent as of some earlier point, missing everything in the WAL,
and quite possibly unopenable.

There are two correct answers. Pick one:

1. **Stop the service, copy everything, start it again.** Simple, complete,
   and requires a maintenance window.
2. **Use `sqlite3 .backup` against the live file.** No downtime, no window, and
   the one to automate.

Do not use `cp`, `rsync`, a filesystem snapshot or a VM snapshot on a running
instance unless you are snapshotting all three files of every database
atomically. A storage-level snapshot that is genuinely atomic across the whole
directory is safe; one taken file by file is not.

---

## What to back up

Everything in the data directory:

| Path | Holds | Lose it and… |
| --- | --- | --- |
| `app.db` | accounts, permissions, global settings, the audit log, the reverse-DNS cache | everyone is signed out and the default `admin`/`admin` account is recreated; the audit trail is gone |
| `nodes.db` | devices, polling profiles, credentials, interfaces, metric samples and rollups, MIBs | the entire inventory and all history |
| `alerts.db` | rules, templates, open and resolved alerts, notification history, mutes | your rule edits and template edits, and every alert's history |
| `netpath.db` | destinations, traces, per-hop samples | path history |
| `flows.db` | flow records, exporters, interface names | flow history |
| `snmptraps.db` | traps, the OID name table | trap history |
| `syslog.db` | messages, hourly rollups, the FTS5 search index | log history |
| `ipam.db` | subnets, hosts, conflicts, DHCP scopes and leases, the DHCP credential | address inventory |
| `wireless.db` | controllers, access points, radios | wireless history |
| `configrx.db` | stored configuration backups, SSH host keys, the SSH credential | **your device configuration history** — for many sites the most valuable file here |

The default directory is `~/.local/share/netpath-monitor/` on Linux and macOS,
`%APPDATA%\netpath-monitor\` on Windows. If you moved any of them with `--db`,
`--nodes-db`, `--alerts-db`, `--flow-db`, `--syslog-db`, `--app-db`,
`--ipam-db`, `--snmp-db`, `--wireless-db` or `--configrx-db`, back up where
they actually are.

Nothing outside that directory needs backing up. The application is code you
can re-fetch; a TLS certificate and key, if you pointed `--cert`/`--key` at
files of your own, are yours to look after.

---

## Method 1 — stop, copy, start

```bash
systemctl stop sappiwhere
tar czf sappiwhere-$(date +%F).tar.gz -C ~/.local/share netpath-monitor
systemctl start sappiwhere
```

A clean shutdown checkpoints and removes the `-wal` files, so what you have
tarred is complete. If the process was killed rather than stopped, the `-wal`
files will still be there — the `tar` above includes them, which is why it
archives the whole directory rather than a `*.db` glob. Never archive `*.db`
alone.

Windows:

```powershell
Stop-Service SappiWhere
Compress-Archive -Path $env:APPDATA\netpath-monitor\* -DestinationPath D:\backups\sappiwhere-$(Get-Date -f yyyy-MM-dd).zip
Start-Service SappiWhere
```

## Method 2 — `sqlite3 .backup`, no downtime

`.backup` takes a read lock, copies pages, and retries any page changed
underneath it, so the result is a consistent snapshot of a live database with
the WAL already folded in. The output is a single self-contained `.db` file
with no `-wal` beside it.

```bash
#!/bin/sh
set -eu
SRC="$HOME/.local/share/netpath-monitor"
DST="/backup/sappiwhere/$(date +%F)"
mkdir -p "$DST"
for f in app nodes alerts netpath flows snmptraps syslog ipam wireless configrx; do
    [ -f "$SRC/$f.db" ] || continue
    sqlite3 "$SRC/$f.db" ".backup '$DST/$f.db'"
done
sqlite3 "$DST/nodes.db" "PRAGMA integrity_check;"    # sanity, not a formality
```

Notes, all of which have bitten someone:

- **Run it as the account that owns the files.** From 4.38.0 the directory is
  `0700` and the databases `0600`, so a backup job running as a different user
  reads nothing and — depending on your `set -e` — may exit successfully having
  copied nothing.
- **`flows.db` and `syslog.db` are the big ones**, up to their configured size
  caps of 2 GB and 1 GB. If your window is tight, back them up less often than
  the rest; a lost day of flow records is a smaller problem than a lost
  inventory.
- **Back up `configrx.db` at the same cadence as your change-control process**,
  not the same cadence as your metrics. It is the file whose loss cannot be
  reconstructed by waiting.
- **Test a restore.** Once. On a spare host. Before you need it.

## Method 3 — from inside the application

**Settings → Maintenance** can prune and vacuum but does not take backups.
There is no in-application backup or export in this release, deliberately: a
backup written by the process that might be the thing that is broken is not a
backup. Use one of the two methods above.

---

## Restoring

Order matters, and there is one caveat that will surprise you.

1. **Stop the service.** `systemctl stop sappiwhere`, or
   `Stop-Service SappiWhere`. Confirm it is actually stopped; two processes on
   one SQLite file will fight and one of them will lose.
2. **Move the current directory aside**, do not delete it —
   `mv netpath-monitor netpath-monitor.broken`. You may want something out of
   it later, and a half-broken `configrx.db` is still better than none.
3. **Restore the files**, including any `-wal` and `-shm` if you are restoring
   a Method 1 archive. A Method 2 backup has neither, which is correct.
4. **Check the ownership and modes**: the service account must own them, `0700`
   on the directory and `0600` on the files. A restore run as root leaves
   root-owned files and the service will not start.
5. **Start the service** and watch the first thirty seconds of its log.
   Schemas migrate forward automatically on open, so restoring a 4.35 backup
   into a 4.37 installation is supported and expected — the migrations are
   idempotent and run in order.
6. **Verify** before you walk away: sign in, check the device count on the
   Nodes tab, check that the Alerts list has your rules, and open one
   ConfigRX backup.

### Restoring a partial set

The databases are independent. Restoring `configrx.db` alone, from a week ago,
while leaving everything else current, is fine and is often exactly what you
want. The only cross-file references are by id from `alerts.db` into
`nodes.db` — an alert names a device id — so restoring `nodes.db` from a
much older backup than `alerts.db` can leave alerts pointing at devices that no
longer exist. They render as an id rather than a name; nothing breaks.

### The DPAPI caveat — read this before you restore onto different hardware

**Stored credentials do not survive a move to another machine or another
Windows account.** Every encrypted credential — the DHCP credential, SNMPv3
authentication passwords, the SMTP password, the wireless controller's SNMP
credential, ConfigRX's SSH password — is protected with the Windows Data
Protection API in machine-and-account scope. That is the whole point of it: a
copy of `nodes.db` on someone else's laptop is inert.

The consequence for a restore is that the ciphertext comes back and cannot be
decrypted. Concretely:

- Restoring onto **the same machine, same service account** — everything works,
  including credentials. This is the normal case.
- Restoring onto **the same machine, a different account** (you changed which
  account the service runs as) — credentials fail to decrypt. Re-enter each
  one; there are usually only a handful.
- Restoring onto **different hardware** — the same, and this is the one that
  catches people during disaster recovery. Budget for re-entering every stored
  credential on the replacement host, and keep them somewhere a person can get
  at them. A password manager is the correct place; a text file next to the
  backup is not.
- Restoring a **Linux** backup — there are no stored credentials to lose,
  because a non-Windows host cannot store one at all
  (`CREDENTIAL-SECURITY.md` §10).

The application does not fail silently about this: a credential that will not
decrypt is reported as an error against the device or the setting that uses it,
not treated as an empty password.

Two related notes. **SSH host keys in `configrx.db` are not encrypted** and do
restore cleanly, which is what you want — a restored installation keeps
refusing a changed host key rather than trusting whatever answers. And **user
account passwords restore fine everywhere**, because they are scrypt hashes,
not encrypted secrets; DPAPI is not involved.

---

## Verifying a backup you already have

```bash
sqlite3 /backup/sappiwhere/2026-09-01/nodes.db "PRAGMA integrity_check;"
sqlite3 /backup/sappiwhere/2026-09-01/nodes.db "SELECT COUNT(*) FROM devices;"
sqlite3 /backup/sappiwhere/2026-09-01/configrx.db "SELECT COUNT(*) FROM device_config;"
```

`integrity_check` returning anything but `ok` means that backup is not one.
Counts that are zero when they should not be mean the copy was taken while the
service was writing, or as the wrong user.

---

## What is not in a backup

- **Sessions.** They live in memory and end when the service stops. Everyone
  signs in again after a restore; this is deliberate.
- **The Debug tab's event buffer.** In memory, discarded on stop. The
  persistent record of who did what is the audit log in `app.db`, which *is*
  backed up.
- **Anything the collectors did not receive.** Nothing backfills. A gap while
  the service was down stays a gap.
