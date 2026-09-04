# SappiWhere — Quick start

From an unpacked copy to a device being polled, an alert you trust, and a path
being watched. Twenty minutes, most of it waiting for a poll.

`README.md` has the full installation detail, `FEATURES.md` what each module
does, `RUNBOOK.md` what to do when one of them stops.

---

## Contents

1. [Before you start](#1-before-you-start)
2. [Start the service](#2-start-the-service)
3. [Sign in and change the password](#3-sign-in-and-change-the-password)
4. [Add a polling profile](#4-add-a-polling-profile)
5. [Add your first device](#5-add-your-first-device)
6. [Check the poll actually worked](#6-check-the-poll-actually-worked)
7. [Add a NetPath destination](#7-add-a-netpath-destination)
8. [Turn on email — or read why you cannot](#8-turn-on-email--or-read-why-you-cannot)
9. [The next hour](#9-the-next-hour)

---

## 1. Before you start

You need:

- **Python 3.10 or newer.** `python3 --version`.
- **`traceroute`** on Linux or macOS (`sudo apt install traceroute`), or the
  built-in `tracert` on Windows. NetPath shells out to it, which is why this
  application needs no raw sockets and no root.
- **One device to point at**, its IP address, and its SNMP read community —
  or a v3 username. Anything that answers SNMP will do; a switch is the most
  useful first device because it has interfaces to chart.
- **UDP 161 outbound** to that device, from this host.

You do **not** need PySide6 unless you want the desktop console window. A
headless server needs nothing but the standard library, so `requirements.txt`
is optional.

**Decide the host now, because it changes what you can do.** On Windows,
everything works out of the box. On Linux, macOS or BSD, storing a
credential needs one extra step: set `NETPATH_SECRET_PASSPHRASE_FILE` (or
the weaker `NETPATH_SECRET_PASSPHRASE`) before you start the service, and
SNMPv3 authentication, ConfigRX backups, the SSH terminal, authenticated
SMTP and the wireless controller credential all work the same as on
Windows. Skip that step and none of them can be stored — DHCP stays
Windows-only regardless of the passphrase, since it depends on
PowerShell/RSAT rather than on credential encryption. This is covered
properly in `CREDENTIAL-SECURITY.md` §10, and again in step 8. SNMP v1, v2c
and v3 noAuthNoPriv polling, NetPath, NetFlow, syslog, traps, IPAM and
alerting all work identically regardless.

## 2. Start the service

```bash
cd /opt/netpath
python3 -m netpath --web --host 127.0.0.1 --port 8443
```

`--host 127.0.0.1` binds to loopback only. Do that first, and open it up
deliberately once you have changed the admin password and, ideally, put a
certificate on it:

```bash
python3 -m netpath --web --host 0.0.0.0 --port 8443 --cert server.crt --key server.key
```

Without `--cert`/`--key` the interface is plain HTTP and session cookies travel
in the clear.

The databases are created on first start, ten of them, in
`~/.local/share/netpath-monitor/` (or `%APPDATA%\netpath-monitor\` on Windows).
From 4.39.0 that directory is created mode `0700` and each database `0600`.

Leave it running in a terminal for now. `README.md` covers running it as a
systemd unit or a Windows service, which is what you want before you rely on
it.

## 3. Sign in and change the password

Open `http://127.0.0.1:8443/`. Sign in as **`admin` / `admin`**.

The application will make you change the password before it lets you do
anything else — and from 4.39.0 it means it: the server refuses every API call
except sign-out, session state and the password change itself while
`must_change` is set on your account. In earlier releases that gate was in the
browser only, so the default password was a real hole. Pick something long; the
policy is NIST-style, so length matters and character classes do not.

Then, straight away, make yourself a second account with the `admin`
capability, on **Settings → Users**. One account is one lost password away from
a stopped service, and the recovery procedure involves deleting a table.

**What the grants mean.** Each account gets read or write per module — Nodes,
Alerts, NetPath, NetFlow, SNMP Trap, Syslog, IPAM, Wireless, ConfigRX, SSH,
Debug, Settings — where write implies read and no grant means no access. Above
those sits one capability, **`admin`**, which gates user administration,
permission changes, the update path and the destructive maintenance actions.
Give an on-call operator read on everything and write on Alerts; that is enough
to acknowledge, resolve and mute without being able to change what is polled.

## 4. Add a polling profile

**Nodes → Settings → Polling profiles → Add.** A profile is a set of
credentials and timings that devices inherit, so you set them once rather than
per device.

For a first profile:

| Field | Value | Why |
| --- | --- | --- |
| Name | `v2c-readonly` | whatever you will recognise |
| SNMP version | 2c | v1 only if the device demands it |
| Community | your read community | never a write community; this application never sends an SNMP SET, but there is no reason to hand it one |
| Poll interval | 120 s | the default, and the right starting point |
| Timeout / retries | 3.0 s / 2 | three attempts in total |
| Ping enabled | yes | this is what makes "down" mean down |
| SNMP failing alone counts as down | no | a device answering ping with a broken community is misconfigured, not down |

A profile can hold several credentials, tried in order, which is how you cope
with a fleet that has two communities in it. Add the second one later.

## 5. Add your first device

**Nodes → Add device.**

| Field | Value |
| --- | --- |
| Address | the device's IP |
| Name | leave blank — it will take `sysName` from the device |
| Polling profile | `v2c-readonly` |
| Upstream device | leave blank for now; see below |

Save. The device appears with status `unknown` and is polled within its
interval. To see it immediately, select it: a selected device drops to a
three-second cadence while you are watching it.

**A word about "Upstream device"**, because it is the single most valuable
field on this form once you have more than a rack. It names the switch or
router a device sits behind. When you have set it, an outage that takes fifty
devices with it opens **one** alert against the upstream instead of fifty, and
re-opens the others if the upstream comes back and they do not. Leave it blank
today; fill it in when you add the second site.

## 6. Check the poll actually worked

Within a couple of minutes the device row should show a green status, a vendor,
and an interface count. If it does not, in this order:

1. **Status `unknown`, no error** — it has not been polled yet. Select it to
   force the fast cadence.
2. **`auth_fail`** — wrong community, or the device restricts SNMP by source
   address. The Debug tab names which credential was tried.
3. **`down` immediately** — the device is not answering ping *or* SNMP. Check
   routing and any ACL on the device's SNMP service.
4. **Up, but no interfaces** — an SNMPv1-only device. Set the profile's version
   to 1; the poller splits the interface request differently for v1, because a
   v1 agent rejects a whole request containing one object it does not
   implement.
5. **A `mib_missing` alert** — the device's vendor is recognised and no MIB for
   it has been uploaded. It is a notice, not a fault, and from 4.39.0 it does
   not email. Ignore it or upload the vendor MIB under Nodes → MIBs.

Open the device's detail pane and look at an interface: you should see
inbound and outbound rates. The first poll shows no rate — a rate needs two
samples — which is correct, not a fault.

## 7. Add a NetPath destination

**NetPath → Add.** Give it an address you care about reaching — a site
gateway, a cloud endpoint — an interval of five minutes, and the default hop
and probe counts.

Within a few cycles the route graph draws one column per hop. This is the
module that answers "is it us or is it them" during an incident, so it is worth
having one destination per site and one per external dependency before you need
them.

## 8. Turn on email — or read why you cannot

**Alerts → Settings → Notifications.** Set the SMTP server, the port, the
security mode, and the From and To addresses. Send a test.

**On Windows**, if the relay requires authentication, enter the username and
password; the password is encrypted with DPAPI for the account the service runs
as, which is why the service should run as a dedicated account rather than as
whoever installed it.

**On Linux, macOS or BSD, storing an SMTP password needs a passphrase
configured first** — `NETPATH_SECRET_PASSPHRASE_FILE` pointed at a file
private to the account the service runs as, set before you start the
service (see step 1 and `CREDENTIAL-SECURITY.md` §10). With that done, the
field works exactly as it does on Windows. With nothing configured, which
is still the state a fresh Linux install starts in, the field refuses the
value deliberately and visibly rather than accepting it and losing it; your
options are then an internal relay that accepts unauthenticated mail from
this host by address — the normal arrangement inside a plant network — or
configuring the passphrase.

Either way, check three things before you trust the alerting:

- **The test message arrived**, and at the address on-call actually reads.
- **The hourly cap** (Alerts → Settings) is high enough for your worst hour and
  low enough that a storm cannot fill a mailbox. It is not a silent limit: mail
  past the cap is recorded against its alert as a failed notification.
- **`mib_missing` is not emailing.** It ships with notification off. If you
  turn it on for a fleet you are still onboarding, expect one message per
  device.

## 9. The next hour

In rough order of value:

- **Set `sample_retention_days` and `rollup_retention_days`** (Nodes →
  Settings) for the history you actually want. Three days of raw samples plus
  400 days of hourly rollups is the default and suits most people;
  `NETWORK-AND-STORAGE-REQUIREMENTS.md` has the arithmetic per port.
- **Point your devices' syslog and traps here** — UDP 514 and 162 — and watch
  the Syslog and SNMP Trap tabs fill. Both listeners are off until you enable
  them in their settings.
- **Add the rest of the fleet.** A discovery sweep (Nodes → Discovery) over a
  subnet is the fast way for anything reachable by ping, and it will not
  guess `public` as a community. For a fleet you already have listed
  elsewhere, **bulk import** (Nodes → Devices) takes a pasted CSV or a JSON
  array in one call, up to 2,000 rows, and reports which rows it took.
- **Fill in "Upstream device"** on everything behind a distribution switch.
- **Read `RUNBOOK.md` once**, before you need it, so you know that the
  collector status strips carry a `kernel_dropped` counter and what it means.
- **Set up backups.** `BACKUP-RESTORE.md`. Ten WAL databases do not survive
  being copied while the service is writing to them.
- **Run it as a service** rather than in a terminal, and put TLS on it.
