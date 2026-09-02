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
the password, so a reconnect decrypts fresh. When no credential is stored,
or the device refuses it, the window asks for a username and password: they
travel once over the same TLS-protected WebSocket the terminal uses, are
handed to `connect()` and cleared the same way, and are never written to
any database, log or event.

**Keystrokes are never recorded.** The device's event log gets one line
when a session opens — the account name and the client address — and one
when it closes, with the duration. Nothing typed or displayed in the
terminal is stored anywhere on this server.

**Host keys are pinned after first sight.** The first connection to a
device stores its host key (a public value: type, key bytes, SHA-256
fingerprint, first-seen time). Every later connection, terminal or backup,
loads that key into paramiko before connecting and is refused if the device
presents different key bytes — a different key type from the same device
counts as different, and an RSA key that starts signing with SHA-2 does
not. Replacing the stored key is an explicit act (**Trust the new key** in
the terminal window, **Forget** in ConfigRX), both under the SSH
permission, and the warning always shows both fingerprints so the decision
is made on the facts.

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
- Never phones home. There is no telemetry, no update check, and no third
  party that could be handed a credential even by accident — see
  `NETWORK-AND-STORAGE-REQUIREMENTS.md` for the complete, closed list of
  every outbound connection this application makes.

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
  domain-admin access would be treated.
