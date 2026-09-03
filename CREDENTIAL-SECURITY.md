# SappiWhere — Credential Security

Every place a password, username, or session token is created, stored, or
transmitted in this application, and exactly what protects it there. This is
the detailed version; `README.md` covers the same ground in brief under
Accounts and under IPAM's DHCP section.

There are three kinds of credential in the system, handled three different
ways:

| Credential | Where it lives | Recoverable by SappiWhere? |
| --- | --- | --- |
| A person's web login password | Nowhere — only a hash is stored, in `app.db` | No. Never was — a hash is a one-way function. |
| A session token, after signing in | In memory only, on the server | Not applicable — it isn't a secret derived from anything; it's random data that exists once, in memory, and is compared to itself. |
| An optional DHCP polling credential | Encrypted in `ipam.db`, if you chose to store one | No — SappiWhere can decrypt it (that's the point), but it never leaves the process as plaintext, and a copy of the file on other hardware cannot decrypt it at all. |
| An optional SNMPv3 authentication password (Nodes) | Encrypted in `nodes.db`, per device or per polling profile, if you chose to store one | No — same DPAPI machine-scoped guarantee as the DHCP credential. |
| An optional SMTP password (Alerts) | Encrypted in `alerts.db`, if you chose to store one | No — same DPAPI machine-scoped guarantee as the DHCP credential. |
| An optional SNMP credential (Wireless controller) | Encrypted in `wireless.db`, if you chose to store one | No — same DPAPI machine-scoped guarantee as the DHCP credential. |
| An optional SSH config-backup password (ConfigRX) | Encrypted in `configrx.db`, if you chose to store one | No — same DPAPI machine-scoped guarantee as the DHCP credential. |
| **The device secrets inside a stored configuration backup (ConfigRX)** | In `configrx.db`, compressed, as part of the captured config text | **Yes, and this row is the reason the table now has six entries instead of five.** A device's running configuration contains that device's own secrets — SNMP communities, enable secrets, TACACS and RADIUS keys, IPsec pre-shared keys, local user password hashes — and none of those are SappiWhere's credentials, so none of them went through DPAPI. They were stored exactly as the device printed them, behind zlib compression, which is not encryption. From 4.39.0 a redaction pass runs over every captured configuration before it is stored, and the content endpoint requires `configrx: write` rather than `configrx: read`. See §6a. |

Everything below explains why each row is true.

---

## 1. Web login passwords

### Never stored — only verified

`hash_password()` in `netpath/auth.py` runs a password through a one-way
function and keeps only the output. The input is discarded the instant the
function returns; nothing keeps the password itself, not in a variable that
outlives the request, not in a log, not anywhere. Signing in later means
hashing whatever was typed and comparing the two hashes — the stored value
is never turned back into a password, because a hash cannot be reversed.

### scrypt, at the parameters OWASP currently recommends

`N = 2^17, r = 8, p = 1` — roughly 128 MiB of memory and a fraction of a
second per hash. That memory cost is deliberate: it is the specific defense
against an attacker who has stolen the password table and is trying to crack
it offline with a GPU or a rented cracking rig. A fast hash (plain SHA-256, a
single MD5 pass) can be computed billions of times a second on cheap
hardware; scrypt's memory requirement means each attempt needs its own 128
MiB, which caps how many attempts run in parallel on any given piece of
hardware regardless of budget. This is what "memory-hard" is defending
against — it is not about slowing down a legitimate login, which still
completes in well under a second.

If the SSL library underneath is too old to support scrypt — the fallback
exists for old distributions this app might run on for years — password
hashing falls back to PBKDF2-HMAC-SHA256 at 600,000 iterations, the current
OWASP-recommended round count for that algorithm. Weaker than scrypt against
a well-funded attacker, but far from weak, and never silently used when
scrypt is available.

### A random salt, every time

16 bytes from `secrets.token_bytes()` — the operating system's
cryptographically secure random source, not `random`. Two people with the
same password get completely different stored hashes, because the salt is
mixed in before hashing. This defeats a rainbow table (a precomputed table of
hash → password) outright: precomputing a table for every possible salt is
the same amount of work as just cracking each password individually.

### Self-describing, so raising the cost later doesn't break anything

A stored hash looks like `scrypt$131072$8$1$<salt>$<hash>` — the algorithm
and its exact parameters are part of the stored string. If `SCRYPT_N` is
raised in a future version, `needs_rehash()` recognizes that an existing
account's hash used weaker parameters and transparently rehashes it at the
new cost the next time that person signs in successfully. Nobody is forced to
reset a password because the security bar moved; the upgrade happens as a
side effect of a login that already proved they know the password.

### Compared in constant time

`verify_password()` uses `hmac.compare_digest()`, not `==`. A naive string
comparison returns as soon as it finds the first differing byte, which means
comparing `"aXXXXXXX"` against the real hash takes measurably less time than
comparing `"bXXXXXXX"` if the real hash starts with `a`. Enough measurements
of that timing difference can reconstruct a secret one byte at a time.
`compare_digest()` always takes the same time regardless of where the
strings first differ, specifically to close that channel.

### No password reaches a log

The login handler (`post_login` in `netpath/web/api.py`) logs the *username*
and the *source address* on a failed attempt, for the audit trail — never
the password, on failure or success. The application's access log (which
records every request for the service console's traffic view) captures the
method, path, status code, timing, client address, and user agent — never a
request body, so a password typed into the login form never appears there
either, by construction: the logging code simply has no access to the body
at all.

### An account that doesn't exist looks identical to a wrong password

If the username in a login attempt doesn't match any account, the handler
still runs a full scrypt computation — against a fixed decoy hash — before
returning the same "Wrong username or password" message a real account with
a wrong password gets. Without this, a real account's response would take
measurably longer (because a real scrypt hash is being computed) than a
nonexistent one (which could otherwise return instantly), and that timing
difference is enough to enumerate which usernames exist on the system before
ever guessing at a password.

### Failed attempts cost time, both by account and by source

`LoginThrottle` tracks failures two ways at once — per username and per
source address — and after 5 failures in a 15-minute window, each further
attempt is delayed before the server even checks the password: `min(30s, 2^(failures - 5))`
seconds, doubling each time up to a 30-second cap. Tracking both ways
means one noisy source address cannot lock a real account for everyone else
by spraying failed logins at it, and a botnet cannot avoid throttling by
spreading a single account's guesses across many addresses.

### A weak password is refused before it's ever hashed

`check_password_quality()` requires at least 12 characters, refuses a small
blocklist of the passwords that turn up in every breach of a small internal
tool (`password`, `admin123`, the product's own name, and so on), refuses a
password identical to the username, and refuses one built from fewer than 5
distinct characters (`aaaaaaaaaaaa` is 12 characters and tells you nothing).
Deliberately *not* enforced: a mandatory digit, symbol, or capital letter.
Composition rules like that were dropped from NIST's own guidance because
they push people toward predictable substitutions (`P@ssw0rd1`) without
meaningfully raising the real difficulty of guessing, while length reliably
does.

### Changing your own password needs the current one

A walk-up at an unlocked, already-signed-in browser cannot lock out the
actual account owner: setting a new password for your own account requires
the current one, verified the same way a login is. An administrator
resetting *someone else's* password is a different, explicitly separate path
— it does not need that other person's current password, and it forces
`must_change` on the account, so the person who owns it has to set their own
new password (one only they know) on their next sign-in rather than
continuing to use whatever the administrator picked for them.

Either way, every existing session for that account is destroyed the moment
the password changes — a stolen session token stops working the instant the
real owner notices and changes their password, without needing to hunt down
and revoke the token itself.

### The default account is a known trap, deliberately

A fresh install has one account, `admin` / `admin`, with `must_change` set —
the browser is walked through setting a real password before it can do
anything else. The credential is intentionally an obvious, publicly
documented default rather than a randomly generated one written to a log or
a first-run file, because a default that has to be looked up somewhere is
itself a place for it to leak; a well-known default that the software refuses
to keep using is not.

---

## 2. Session tokens

### Random, not derived from anything

`SessionStore.create()` generates 32 bytes with `secrets.token_urlsafe(32)`
— again the OS's cryptographic random source. This is not a JWT and there is
no server secret that signs it: the token itself *is* the secret. Knowing the
username, the server's clock, or any other public fact about a session gives
no way to compute or predict its token, because nothing about the token is
computed from anything — it's 256 bits of randomness with no structure to
recover.

### Held in memory only

Sessions live in a plain Python dictionary inside the running service, never
written to any file. Restarting the service — a crash, an update, a reboot —
invalidates every session at once, which is the deliberate trade-off: no
token can be recovered from a backup, a copied database file, or a crash
dump of the disk, because it was never on the disk to begin with.

### The cookie itself is locked down

Three attributes on the session cookie, each closing a specific attack:

- **`HttpOnly`** — client-side JavaScript cannot read the cookie at all, even
  through an injected script. A cross-site-scripting bug elsewhere in the
  page cannot walk off with the session token, because there is no
  JavaScript API that can see it.
- **`SameSite=Strict`** — the browser will not attach this cookie to a
  request originating from another site, even a simple link click. This is
  what stops a forged request from a malicious page tricking your browser
  into taking an action on SappiWhere using your still-valid session.
- **`Secure`** — added automatically whenever the service is running under
  TLS (`--cert`/`--key`). A `Secure` cookie is never sent over plain HTTP,
  so if the deployment does have TLS configured, the token cannot be
  captured by anyone positioned to read unencrypted traffic.

### Idle timeout that tracks a person, not an open tab

Covered in full in `CHANGELOG.md`'s 2.3.0 entry: a background poll every open
tab makes every couple of seconds does not by itself keep a session alive.
Only a deliberate action does — a write, or a heartbeat sent solely when the
browser detects real mouse or keyboard input. Left genuinely idle, a session
signs itself out after 10 minutes by default, adjustable on the Settings tab.
An absolute session length (12 hours by default) applies on top of that
regardless of activity, so a session cannot be kept alive indefinitely just
by staying at the keyboard.

---

## 3. The optional DHCP polling credential

IPAM's DHCP module (`netpath/ipam_dhcp.py`, `netpath/ipam_worker.py`,
`netpath/dpapi.py`) is the one place besides a person's own login where
SappiWhere can be asked to hold onto a credential at all, and it exists
specifically for people moving from software that took a read-only DHCP
account directly rather than through Windows. It is opt-in per server; the
default for every DHCP server is to hold no credential whatsoever.

### The default: nothing is stored, because nothing has to be

Leave a DHCP server's username and password blank and the `DhcpServer`
PowerShell module's own `Get-*` cmdlets are called with `-ComputerName`,
which authenticates as whichever Windows account is running SappiWhere — or,
if Windows Credential Manager on this machine has an entry for that server's
name, whatever credential Windows itself resolves for that target. SappiWhere
never sees a username or password on this path; it is not "encrypted
somewhere," it simply never exists inside the application at all. This is
the preferred path, and the one that needs no explaining to a security
reviewer, because there is nothing in SappiWhere's own storage to review.

### The optional path: a stored credential, encrypted for one machine

Filling in a username and password stores that credential instead, for
servers where a separate read-only account makes more sense than the running
service's own identity. What happens to it:

1. **Encrypted before it is ever written to disk.** `dpapi.protect()` calls
   Windows' own `CryptProtectData`, the same API Windows Credential Manager
   and Chrome's own password store are built on — not a cipher this
   application invented, with a key that would have to be protected in turn.
2. **Tied to the machine, not to a Windows account.**
   `CRYPTPROTECT_LOCAL_MACHINE` means the encrypted value can be decrypted by
   any account on this specific computer, but by nothing running anywhere
   else — not a copy of `ipam.db` restored onto different hardware, not the
   file opened by another tool. The alternative, user-scoped protection,
   would tie the secret to whichever Windows account happened to be logged
   into the browser at the moment the credential was typed in — which is not
   reliably the same account the background service runs as, and would make
   the credential undecryptable by the very process that needs to use it.
   Machine-scoped is the option that actually works for an unattended
   service, at the honest cost that "protected" here means "this machine,"
   not "this person."
3. **No fallback if DPAPI isn't available.** On anything other than Windows,
   attempting to store a credential is refused outright, with a message
   pointing at Credential Manager instead. There is no code path that writes
   a plaintext password, or falls back to a weaker cipher, when DPAPI can't
   be used — the feature simply declines to exist rather than exist unsafely.

### Never returned once stored

The API that lists DHCP servers reports a username (not sensitive on its
own — it's what a network diagram or an admin's own memory already has) and
a boolean, `has_credential`. The password itself — encrypted or not — never
appears in any API response, ever. There is no "reveal password" button and
no way to ask the running service what a stored password is, by design:
the only two things you can do with a stored credential are use it (which
happens entirely on the server) or replace it.

### Reaches PowerShell as an environment variable, never as command text

When the credential is used, the username and the just-decrypted password
travel to the child PowerShell process as environment variables
(`SAPPI_DHCP_USERNAME`, `SAPPI_DHCP_PASSWORD`), not as arguments woven into
a command line. This matters because a command line is comparatively public:
it shows up in `Get-Process | Select CommandLine`, in Windows' own
process-creation audit events if command-line logging is turned on, and in
shell history if a person ever ran the equivalent command by hand. An
environment variable is visible only to something that can already inspect
this specific child process's environment block — a materially higher bar,
requiring the same or greater privilege as the account running SappiWhere.

The PowerShell script itself is a fixed constant, identical every time it
runs, and never built by concatenating anything the person typed. See the
next section for how that is verified rather than merely claimed.

### Plaintext exists only as long as one call takes

The password is decrypted by `credential_for_server()` in
`ipam_worker.py` immediately before the PowerShell call it's needed for, and
the variable holding it is set back to `None` as soon as that call returns —
in both the API's "test connection" handler and the background poller. There
is no caching of a decrypted password anywhere; every use decrypts fresh from
`ipam.db` and discards it again. This does not mean the plaintext never
exists — it necessarily does, briefly, in the Python process's memory and in
the child PowerShell process's memory and environment block, because an
automated system that authenticates without a person typing anything each
time has no way to use a secret without it existing somewhere for that one
use. What this design controls is the *window*: as short as one poll or one
connection test, never longer, and never written anywhere durable.

### Every cmdlet the script can call is read-only, and that's checkable

The fixed PowerShell script (`_SCRIPT` and `_TEST_SCRIPT` in
`ipam_dhcp.py`) calls only `Get-DhcpServerv4Scope`, `Get-DhcpServerv4Lease`,
`Get-DhcpServerv4Reservation`, and `Get-DhcpServerVersion` against the DHCP
server — every one a `Get-`, none of them capable of changing anything.
`Invoke-Command`, used only for the stored-credential path, is never handed
a string: it runs a fixed scriptblock (`$body` / `$probe`) defined earlier in
the same constant script, so there is nothing for a crafted server name or
credential to inject into even in principle. This isn't just a claim in a
docstring — it's mechanically checkable by grepping the two script constants
for every cmdlet name they contain and confirming none is a mutating verb,
which is exactly the check that was run against them before they shipped.

### A restored backup doesn't restore the credential

Because the encryption is tied to the machine, moving `ipam.db` to different
hardware — a disaster-recovery restore, a migration to a new server — brings
the *existence* of a stored credential back but not its usability: DPAPI on
the new machine cannot decrypt a blob encrypted on the old one, and the
credential has to be re-entered there. Everything else in the file restores
normally. This is called out explicitly in
`NETWORK-AND-STORAGE-REQUIREMENTS.md` so it isn't a surprise during an
actual recovery.

---

## 4. The optional SNMPv3 authentication password (Nodes)

A device polled with SNMPv3 needs a username and an authentication
password, stored per device or per polling profile (`netpath/nodesdb.py`,
`netpath/dpapi.py`) — the same opt-in shape as the DHCP credential above,
and the same underlying mechanism: DPAPI-encrypted, machine-scoped, never
returned by any API response (only `has_credential: bool`), refused
outright on any platform other than Windows rather than falling back to a
weaker cipher or a plaintext file. `POST .../credential` and `DELETE
.../credential` are the only two operations exposed — store or clear,
never reveal.

A polling profile can hold more than one SNMP credential — its own
primary one plus any number of additional alternates in
`group_credentials`, tried in order for a device that doesn't answer the
primary. Every alternate's optional v3 password follows the identical
rule: `POST .../credentials/{id}/secret` and `DELETE
.../credentials/{id}/secret`, same DPAPI-or-refuse behavior, same
`has_credential: bool`-only exposure, one row's password decrypted at a
time, immediately before that row's own signing attempt, same as the
primary credential's.

**An SNMP *community* string (v1/v2c) is not treated the same way, and
that is deliberate, not an oversight.** It is stored and shown in the
clear, in the device list, in the edit form, in the API response. A
community string is not a secret by the protocol's own design — SNMPv1
and v2c send it in cleartext inside every single packet, request and
response alike, to anyone who can see the wire. Encrypting it at rest
while it travels in the open on every poll would be theater: it protects
against reading the database file but not against the one thing that
actually exposes it, a packet capture on the path to the device. It is a
filter, the same word `CREDENTIAL-SECURITY.md`'s SNMP Trap coverage
already used for the identical fact on the receiving side. Only the
SNMPv3 authentication *password* — which is never transmitted in the
clear, only ever proved via an HMAC computed over it — gets the DPAPI
treatment this section describes.

Plaintext exists only as long as one poll takes: `nodepoll.credential_for()`
decrypts a device or profile's stored password immediately before signing
that one request and never caches it, the same "decrypt fresh every use,
discard immediately after" discipline `ipam_worker.credential_for_server()`
established for DHCP. A password typed into the **Test** button on the
add/edit device form, before the device is even saved, is used the same
way — signed into that one test request in memory — and is never written
to `nodes.db` unless the **Save** (not Test) path is used and a password
was actually entered.

**A Wireless Controller's SNMP credential uses this identical mechanism**,
stored in `wireless.db` instead of `nodes.db` (`fortipoll.credential_for()`
is a straight reuse of `nodepoll`'s own function, not a reimplementation):
DPAPI-encrypted, `has_credential`-only in every API response, decrypted
immediately before each poll and discarded after. The same community-
string exception applies for the same reason — a v1/v2c community is
shown in the clear, since the protocol itself sends it in the clear on
every packet regardless of what SappiWhere does with its own storage.

## 5. The optional SMTP password (Alerts)

Alerts' email notification (`netpath/alertmail.py`, `netpath/alertsdb.py`)
needs a password only when the configured mail server requires
authentication; a server that accepts anonymous relay from this host, or
sending disabled entirely (the default), stores nothing. One password for
the whole module — not per rule or per recipient, since there is one SMTP
identity Alerts sends as — encrypted the identical DPAPI, machine-scoped
way as the DHCP and SNMPv3 credentials, never returned by any API
response, refused on non-Windows. `POST /api/alerts/smtp/credential` and
`DELETE /api/alerts/smtp/credential` store or clear it; there is no
"reveal" path.

**Send test email** works two ways: with a password already stored, it
decrypts and uses that; with one typed into the Settings dialog but not
yet saved, it signs in with that instead, for exactly that one test
message — the same "test what's currently in the form, before it's
saved" idiom the DHCP connection test and the Nodes device test both use.
Either way the plaintext exists only for the one SMTP session it
authenticates, then is discarded.

TLS is the default, not an afterthought: `smtp_security` defaults to
`starttls`, and `smtp_verify_cert` defaults to on. Turning certificate
verification off is a real, logged configuration choice — an explicit
opt-out visible in the settings dialog — never a silent downgrade a
misconfiguration could trigger by accident.

## 6. The optional SSH config-backup password (ConfigRX)

ConfigRX (`netpath/configrx.py`, `netpath/configrxdb.py`) needs an SSH
username and password to pull a device's running configuration; a device
with backup disabled, or one that hasn't had a credential entered for it
yet, stores nothing. One credential per device — the same opt-in shape,
and the same DPAPI mechanism, as every other stored credential in this
document: encrypted before it's ever written to `configrx.db`, machine-
scoped, never returned by any API response (only `has_credential:
bool`), refused outright on any platform other than Windows. `POST
.../credential` and `DELETE .../credential` are the only two operations
exposed — store or clear, never reveal, identical to every other
credential endpoint in this app.

**Never touches a command line or a process list.** This is the specific,
stated reason ConfigRX's SSH connectivity uses paramiko — the one
deliberate exception to this application's otherwise stdlib-only
dependency rule (`requirements.txt`) — rather than shelling out to a
system `ssh` binary the way `ipam_scan.py` shells out to `ping`: an SSH
password handed to a subprocess as a command-line argument is visible to
anything that can list processes on the host (`ps`, Task Manager, an
audit log with command-line capture turned on) for as long as that
process runs. paramiko authenticates entirely in-process, so the
password exists only as a Python string in this process's own memory —
the same bar an environment-variable-based credential (the DHCP and SMTP
paths) already clears, reached here by a different mechanism because
this credential's destination is a raw SSH session, not a PowerShell
child process with an environment block to put it in.

**Plaintext exists only as long as one backup pull takes.**
`ConfigRxWorker._backup_device()` decrypts the stored password into a
local variable immediately before `paramiko.SSHClient.connect()`, and a
`finally` block reassigns that variable to `None` the instant the
connection attempt finishes — success or failure — before the function
does anything else. There is no caching of a decrypted password anywhere
in this module; every scheduled pull and every manual **Back up now**
decrypts fresh from `configrx.db` and discards it again.

**No free-form command execution exists anywhere in this module, and
that boundary is load-bearing, not incidental.** (The interactive SSH
terminal, section 7, is a separate module under a separate permission; it
shares this credential, not this code.) The only function in ConfigRX that
ever writes to a device's SSH shell channel, `configrx._pull_config()`,
sends exactly two things: a fixed, per-vendor pagination-disable command
(session-scoped and itself read-only, e.g. `terminal length 0`) and one
fixed, per-vendor "show config" command (`show running-config`, `show
full-configuration`, and so on) — both sourced from
`configrx_vendors.VENDORS`, a hardcoded dictionary, never from request
text. A device's vendor-override field is free text, but it only ever
*selects* which vendor's fixed commands to use; an unrecognized value
fails to resolve to anything and the backup is skipped with a clear
error rather than sent as literal input. There is no command parameter
anywhere in ConfigRX's API, and no free-form input field anywhere in its
UI — the credential this section protects can only ever be used to run
one of a short, fixed, read-only list of commands, never anything an
operator (or an attacker who somehow obtained write access to this
module) could supply.

## 6a. What is inside a stored configuration backup

A ConfigRX backup is the device's own running configuration, and a network
device's running configuration is full of secrets that belong to the device
rather than to SappiWhere. A representative Cisco config holds
`snmp-server community`, `enable secret`, `username … secret`,
`tacacs-server key`, `radius-server key`, `crypto isakmp key` and
`pre-shared-key` lines; a FortiOS one holds `set password` and
`set psksecret`. Until 4.39.0 all of that was stored as captured, compressed
with zlib and no more, and served in full to any account with `configrx:
read`. Compression is not encryption — `zlib.decompress` on the blob returns
the plaintext — so the backup table was the least protected place in the
product holding the most valuable material in it.

Three things changed.

**A redaction pass runs before storage.** `configrx_redact.py` rewrites the
known secret-bearing directives listed above, replacing the secret with
`<redacted>` and leaving the rest of the line intact so the configuration is
still readable and still diffable. It runs after capture and before
`add_backup`, so the unredacted text never reaches the database at all — this
is not a display filter. Every stored backup records whether it was redacted,
so a row captured before the upgrade is not mistaken for a redacted one.
Redaction is on for every device, and can be turned off for a device where the
whole point of the backup is the key material: `store_secrets` on that device's
ConfigRX configuration, per device rather than global, set through the ConfigRX
API. There is deliberately no button for it — turning it on is a decision about
one switch, taken by somebody who knows what that switch's configuration
contains.

**Be clear about what redaction is and is not.** It is a pattern list. It
covers the directives above across the vendors ConfigRX supports, and it will
not cover a directive nobody has thought of, a vendor added later, or a secret
an operator has put in a description field. A redacted backup is
*substantially* safer to hand to somebody than an unredacted one; it is not a
sanitised document you should treat as public. Read it as defence in depth
underneath the permission change, not as a replacement for it.

**Reading a backup's content now requires `configrx: write`.** Listing which
backups exist, when they were taken and whether the configuration changed
stays on `configrx: read`, because that is the useful read-only view; the
configuration text itself is behind the write grant. This is the one place in
the product where a read operation deliberately requires a write grant, and it
is because "read a config backup" is not the same kind of act as "read the
alert list".

Everything in §6 about the SSH password that *fetches* the backup is
unchanged, including the host-key store described there.

## 7. The interactive SSH terminal (Nodes → SSH)

The SSH button on a device opens a real shell in the operator's browser
(`netpath/sshterm.py`, `netpath/web/wsock.py`, `netpath/web/static/ssh.js`).
It is the one place in this application that sends what a person types to a
device, and it is built around that fact.

**Its own permission, granted to nobody by default.** ConfigRX write access
means "can store a backup credential and run the fixed show-config
command"; it has never meant "can type anything into every switch", and
the terminal does not widen it. A separate **SSH** module in the
per-account permission grid gates the button, the connection itself (the
server checks it before the socket is upgraded) and trusting a changed
host key. On upgrade only accounts already holding write access to every
other module receive it.

**The stored credential is used the way ConfigRX uses it.** The ConfigRX
credential for the device, if one exists, is decrypted immediately before
`paramiko.SSHClient.connect()` and the plaintext variable is cleared the
instant the attempt resolves; the live session holds the SSH channel, never
the password, so a reconnect decrypts fresh. The one exception is a refused
host key: the credential is held, in memory only, between the warning and
the operator's answer, so that **Trust the new key** reconnects without
asking for the password again — and it is dropped with the session if the
answer is Cancel or the window closes. When no credential is stored,
or the device refuses it, the window asks for a username and password: they
travel once over the same TLS-protected WebSocket the terminal uses, are
handed to `connect()` and cleared the same way, and are never written to
any database, log or event.

**Keystrokes are never recorded.** The device's event log gets one line
when a session opens — the account name and the client address — and one
when it closes, with the duration. Nothing typed or displayed in the
terminal is stored anywhere on this server.

**Every refused login is recorded, and there are only five.** A device
refusing a username and password writes a device event naming the SSH
username, the attempt number, the account that asked and its address —
never the password — and the fifth refusal closes the session. Without
that, an account holding SSH write could use this server as a quiet
password oracle against every device it knows about, from an address those
devices trust, with nothing in any log. Each account may hold at most four
sessions at once, so one account cannot exhaust the sixteen the server
allows and lock every other operator out.

**A session is only as alive as the sign-in behind it.** The permission
check at the socket upgrade is not the last one: once a second the session
confirms the web sign-in that opened it still exists and still holds SSH
write, and closes the terminal — with a device event — the moment it does
not. Signing out in the main window, the sign-in's idle or absolute limit,
a revoked permission or a removed account therefore all end a live shell
within seconds rather than leaving it running until its own idle timer
fires. Typing in the terminal counts as presence for the web sign-in, the
same as a click in the main window does, so a person working only in the
terminal is not signed out under them.

**The socket refuses other origins.** A WebSocket upgrade is a GET, so the
JSON content-type rule that blocks cross-site form posts does not apply to
it, and the session cookie's `SameSite=Strict` is scoped to the site, not
the origin — a page served from another port on the same host would still
carry it. The server therefore requires the browser's `Origin` header on
the upgrade and refuses (403) any that does not name this server. The
Content-Security-Policy sent with every page was tightened at the same
time: `connect-src 'self'` (4.36.0 briefly allowed any `ws:`/`wss:` host,
which would have let injected script open a socket anywhere) and
`frame-ancestors 'none'`, so the terminal window and its Trust button
cannot be framed.

**Host keys are pinned after first sight.** The first connection to a
device stores its host key (a public value: type, key bytes, SHA-256
fingerprint, first-seen time). Every later connection, terminal or backup,
loads that key into paramiko before connecting and is refused if the device
presents different key bytes — a different key type from the same device
counts as different, and an RSA key that starts signing with SHA-2 does
not. Replacing the stored key is an explicit act — **Trust the new key** in
the terminal window, under the SSH permission, or **Forget** in ConfigRX,
under ConfigRX write, the permission that already decides which port and
credential the next connection uses — and the warning always shows both
fingerprints so the decision is made on the facts. Nothing else removes a
key: deleting a device from Nodes (a Nodes write) leaves it in place, so a
lower permission cannot reset the trust anchor by removing and re-adding
the device.

## 8. What this application deliberately never does

- Never stores a password in a form that can be turned back into the
  password — not the web login, not a DHCP, SNMPv3 or SMTP credential.
- Never returns a password or an encrypted password blob through any API
  response.
- Never builds a shell or PowerShell command by inserting a credential (or
  anything else user-supplied) into command text; every value that varies
  travels as an environment variable or a script parameter, never as string
  concatenation.
- Never gives ConfigRX a way to run an arbitrary command on a device over
  SSH — only a short, fixed, per-vendor allow-list of read-only "show
  config" commands exists anywhere in that module, and there is no
  free-form command field in its UI or API. The interactive terminal
  (section 7) is the single, deliberate place a person's own input reaches
  a device, behind its own permission that no account holds by default.
- Never logs a password, on success or failure, in the event log or the
  access log.
- Never falls back to weaker or absent protection silently — a DPAPI
  failure refuses the operation rather than writing plaintext; a login
  failure for a nonexistent user still pays the same time cost as a real
  one rather than skipping it for speed.
- Never persists a session token to disk.
- **Never phones home.** There is no telemetry: nothing about this
  installation, its fleet, its operators or its configuration is transmitted
  anywhere, on any schedule, ever, and there is no third party that could be
  handed a credential even by accident. See
  `NETWORK-AND-STORAGE-REQUIREMENTS.md` for the complete, closed list of every
  outbound connection this application makes.

  **A correction, because an earlier edition of this sentence also said "no
  update check" and that was not true.** Pressing **Update** on the Settings
  tab calls `selfupdate.latest_commit()`, which makes an HTTPS request to
  `api.github.com` to ask what commit is at the tip of `main`. It is
  operator-initiated, never scheduled and never automatic; it sends no
  identifier, no fleet data and no credential — a plain GET with a
  `User-Agent` — and the reply is a commit id. But it *is* an outbound
  connection to a third party, and the previous wording denied that any
  existed. From 4.39.0 the whole update path is off unless an administrator
  turns on the `updates_enabled` setting, so on a default installation the
  button refuses before it reaches the network. In an air-gapped deployment,
  leave `updates_enabled` off and the application makes no outbound
  connection at all beyond the ones you configure — SNMP, SMTP, DNS, SSH.

  **What that button installs is not verified, and that is the largest
  outstanding risk in this document.** It follows a mutable branch: no tag,
  no published digest, no signature. Whoever can push to the repository
  chooses the code every install with the setting on will run, on the hosts
  that hold the credentials this whole document is about. 4.39.0 had shipped
  the verified alternative — newest published tag, checked against a
  `SHA256SUMS` release asset — and it was withdrawn because it left installs
  already in the field unable to reach 4.39.0 through the button at all. The
  code for it is still present and still tested (`latest_tag()`,
  `published_digest()`); the SECURITY NOTE at the top of
  `netpath/selfupdate.py` records what putting it back involves. Until then,
  an installation whose threat model includes the repository being
  compromised should keep `updates_enabled` off and install by hand.

## 8a. The audit log

Until 4.39.0 the only record of who did what was `eventlog.py`: a 3,000-entry
ring buffer in memory. It was fine as a debugging aid and useless as an audit
trail — it was lost on every restart, any account with `debug: write` could
clear it, and a single 200 KB field could evict everything else in it.

There is now an append-only `audit` table in `app.db`, written for the actions
that matter and never trimmed by any retention pass, size cap or maintenance
action:

| Action | Recorded |
| --- | --- |
| Sign-in: success, failure, and a lockout | timestamp, username as supplied, client address |
| Sign-out | timestamp, username, client |
| User created, deleted, permissions changed, password reset | actor, target account, what changed |
| Own password changed | actor |
| Settings changed | actor, scope, and the keys that changed — **not** the values, so a stored secret is never written to the audit table by the act of storing it |
| Credential stored or cleared | actor, which credential, which device or profile |
| Maintenance actions | actor, which action, how many rows it removed |
| Self-update triggered | actor, the version pinned |
| Mute, acknowledge, resolve-all | actor, scope of the action |

Six properties are worth stating because they are the ones an auditor asks
about. The table is **append-only**: no route deletes or updates a row, and
the maintenance prune does not touch it. It is **never rotated by size**,
which is a deliberate trade — an audit trail that a busy fortnight can silently
truncate is not an audit trail; it is bounded instead by capping any single
message at 512 bytes. Reading it requires the **`admin`** capability, so an
operator cannot read the record of other operators' actions. It records the
**username as supplied** on a failed sign-in, including a username that does
not exist, because a run of attempts against `administrator` is exactly the
pattern you want to see — and never the password, in any form. It survives a
restart, which the ring buffer did not. And it is separate from the Debug
tab's live event view, which still exists, is still in memory, and is now
filtered to the modules the reading account has a grant for.

## 9. What is still the administrator's job

Encryption and hashing close the gaps this application controls. A few
things remain outside its reach entirely:

- **Least privilege for a stored DHCP, SNMPv3, SMTP, Wireless SNMP or
  ConfigRX SSH credential.** Create a dedicated read-only DHCP account —
  membership in the DHCP server's local `DHCP Users` group is enough —
  rather than reusing a domain admin account because it's convenient;
  give an SNMPv3 polling user read-only access on the device side; give
  the SMTP account only send rights, not a full mailbox; give a
  ConfigRX SSH account only enough privilege to run one read-only "show
  config" command, not enable/configure access. SappiWhere enforces that
  the calls it makes with a credential are read-only (DHCP, ConfigRX) or
  exactly what the credential is for (an SNMP GET, an SMTP send); it
  cannot enforce what the account itself is authorized to do beyond
  that — a ConfigRX SSH account that happens to also have enable
  privilege on the device is a risk the device's own account
  configuration controls, not something SappiWhere can restrict from its
  side of the connection.
- **TLS in any deployment that matters.** `--cert`/`--key` turns on HTTPS and
  with it the `Secure` cookie flag; without it, session cookies (though still
  `HttpOnly` and `SameSite=Strict`) travel in the clear on the network.
- **Physical and OS-level security of the host.** DPAPI's machine-scoped
  guarantee is bounded by who can run code as *any* account on that machine
  — an attacker with that level of access could call the same decryption API
  SappiWhere does. Protecting the host itself is what makes that guarantee
  mean something.
- **Who gets an account, and what it can do.** Every account has an
  explicit read/write grant per module (see `FEATURES.md`'s Permissions
  section and `INTERNALS.md`'s Permissions section for how it's
  enforced) — deciding what a new account should actually be able to
  touch is still the administrator's call to make, not something this
  application can decide on its own. Granting Settings write access in
  particular is granting the ability to change any other account's
  permissions, including its own, so treat it the same way root or
  domain-admin access would be treated. Note that "Settings write" is no
  longer the top of the tree: from 4.39.0 user administration, permission
  changes, the update path and the destructive maintenance actions require an
  explicit **`admin`** capability, which accounts holding Settings write were
  granted on upgrade, which nobody can grant to themselves, and which the last
  account holding it cannot be stripped of.

---

## 10. Non-Windows hosts cannot store a credential

This is the largest limitation in this document and it deserves its own
section rather than a footnote in five others.

Every encrypted credential in the table at the top of this file — the DHCP
credential, the SNMPv3 authentication password, the SMTP password, the
wireless controller's SNMP credential, ConfigRX's SSH password, and the
password the interactive SSH terminal reuses — goes through
`netpath/dpapi.py`, which is a wrapper over the Windows Data Protection API.
`dpapi.available()` is `os.name == "nt"`. On Linux, macOS or BSD it returns
false, and the eight API endpoints that would store a secret refuse with a
clear error instead.

**So, concretely, on a Linux host:**

| Feature | On Windows | On Linux |
| --- | --- | --- |
| SNMP v1/v2c polling | yes | yes |
| SNMPv3 noAuthNoPriv polling | yes | yes |
| SNMPv3 authNoPriv polling | yes | **no** — the auth password cannot be stored |
| Authenticated SMTP for alert email | yes | **no** — relay must accept unauthenticated mail |
| ConfigRX configuration backups | yes | **no** — the SSH password cannot be stored |
| The interactive SSH terminal | yes | **no**, for the same reason |
| Wireless (FortiGate controller) | yes | **no** — the controller's SNMP credential cannot be stored |
| DHCP scope and lease visibility | yes | **no** — and PowerShell/RSAT is Windows-only anyway |

Everything else — SNMP polling, NetPath, NetFlow, syslog, traps, IPAM
scanning, alerting, the web interface, the whole browser application — works
identically on either.

The application tells you this **before** you type a secret, not after: the
credential fields in the Nodes, Wireless, ConfigRX and Alerts dialogs render
disabled with the text "Not available on this host (Windows DPAPI only)", and
IPAM's DHCP form is replaced by a notice off Windows rather than accepting
input it cannot use. `/api/state` reports `platform: {is_windows, powershell,
secret_store: false}` so the browser can make that decision without guessing.

### Why there is no portable secret store, yet

A portable secret store was designed for 4.39.0 and **deliberately deferred**.
The reasoning is worth writing down, because "just encrypt it with a key in a
file" is the obvious answer and it is the wrong one.

DPAPI's guarantee is specific and strong: the ciphertext can be decrypted only
by the same Windows account on the same machine, with the key material held by
the operating system and never present in this application's files. A copy of
`nodes.db` taken to another machine is inert. Any portable scheme has to be
honest about giving that up, and each of the three plausible designs gives up
something different:

- **A key file beside the database** protects against nothing that matters. An
  attacker who can read `nodes.db` can read `nodes.key` in the same directory.
  It would move the credentials from "stored in the clear" to "stored in a way
  that looks encrypted", which is worse, because it invites trust it has not
  earned.
- **A passphrase supplied at start-up**, deriving the key with scrypt and
  holding it in memory only, is genuinely equivalent to DPAPI for the
  file-theft case. Its cost is that the service cannot start unattended: every
  restart — a reboot at 03:00, a systemd `Restart=always` after a crash —
  stops until somebody types the passphrase, and a monitoring system that does
  not come back by itself after a power cut has failed at its job. Working
  around that means caching the passphrase somewhere, which is the key file
  again.
- **The platform keyring** (libsecret, gnome-keyring, KWallet) is the right
  answer for a desktop and a poor one for a headless server, where the D-Bus
  session and the unlocking agent that make it work are usually absent. It
  also means a third-party dependency, and this application ships on the
  standard library alone by policy.

None of those is obviously right, and shipping the wrong one is worse than
shipping none: a credential store that quietly protects less than operators
believe it does is a bigger problem than a refusal they can plan around. The
refusal is at least accurate, visible in the interface, and documented here.

**What to do in the meantime.** Run the service on Windows if you need any of
the credentialed features — that is the supported answer. If it must be Linux,
use SNMPv1/v2c or v3 noAuthNoPriv with communities scoped read-only on the
device, and an SMTP relay on the local network that accepts unauthenticated
mail from the monitoring host by address. From 4.39.0 the data directory is
created mode `0700` and every database file `0600`, so at least a shared Linux
host does not expose one service's communities to every account on the
machine — but note that a community string is not encrypted anywhere, on any
platform, and is returned by the API to accounts with the **write** grant on
the module that owns it. Read-only accounts now see only whether a community
is set, not its value.
