# A hostile full-codebase review of 4.50.0

Eleven reviewers were pointed at this codebase with one instruction: you hate
this implementation, now prove it. Every criticism below had to name a file
and a line, describe a concrete path from an input to a wrong outcome, and
quote the code that makes it true. Anything that could not survive that test
was dropped rather than written down, and a few things were dropped — the
findings that did not survive verification are listed at the end, because a
review that only records its hits is advertising, not a review.

What came back is not the review the framing invited. This is a careful
codebase. The counter-wrap arithmetic in `nodepoll.py` handles 32-bit wrap,
64-bit reset, engine resync and discontinuity counters. `secretstore.py` is
scrypt into an encrypt-then-MAC construction with constant-time comparison
and bounded KDF parameters. The CSRF model is Origin plus `Sec-Fetch-Site`
plus `SameSite=Strict` plus a JSON content-type requirement. LDAP DN
injection is closed with an allowlist rather than an escape. MIB uploads are
bounded against both zip bombs and path traversal. The reviewer who spent its
entire budget hunting stored XSS through 27,000 lines of hand-rolled
framework-free JavaScript — tracing LLDP neighbour names, SNMP varbind text,
syslog messages and vendor config text through every `innerHTML` write and
every cell renderer in sixteen files — came back and said, in as many words,
that it did not find one and was not going to manufacture one.

So this is not a review about carelessness. Every serious finding below has
the same shape: **this codebase already contains the correct pattern, applied
somewhere else, and simply did not apply it here.** That is a much more
uncomfortable class of bug than ignorance, because it cannot be fixed by
learning something. It is what happens when 50,872 lines of Python grow across
68 flat modules with no structural boundary forcing a fix in one place to
reach its siblings.

The evidence for that is the same sentence over and over:

- `syslogd.py`'s writer thread guards its database call. `snmptrapd.py`'s
  does. `collector.py`'s does not, and one crafted UDP packet ends flow
  storage permanently.
- Every scheduler loop in `monitor.py` is wrapped in `except Exception`,
  including one whose comment reads *"a scheduler thread must never die
  quietly"*. `Monitor._loop` — the trace scheduler this product is named
  after — is not.
- `trim_to_size()` in `nodesdb.py` deletes in chunks against a deadline, with
  a comment citing a measured 38.9-second lock stall. `prune()`, sixty lines
  above it, deletes from the same table in one unbatched statement.
- `configrx.js`'s search guards against a stale response landing last with a
  generation token. Not one of the periodic live-window `refresh()` functions
  did — including `configrx.js`'s own.
- Eleven of thirteen front-end modules alias the shared HTML escape.
  `dashboard.js` pasted its own copy of it.
- `nodepoll.py`'s SNMP walk checks that the returned OID actually advanced.
  `fortipoll.py`'s hand-rolled copy of the same loop never got that fix.

None of those is a hard problem. All of them are the same problem.

---

## Contents

- [The ten that would have stopped a deployment](#the-ten-that-would-have-stopped-a-deployment)
- [What this release fixed](#what-this-release-fixed)
- [What this release left open, and why](#what-this-release-left-open-and-why)
- [Findings rejected on verification](#findings-rejected-on-verification)
- [The architecture, without flinching](#the-architecture-without-flinching)
- [Documentation that was not true](#documentation-that-was-not-true)

---

## The ten that would have stopped a deployment

Ranked by what they cost, not by how interesting they are.

### 1. An LDAP account could be signed into with no password at all

`netpath/ldapclient.py:389` · CRITICAL · **fixed**

`simple_bind()` returned success on `resultCode == 0`. RFC 4511 §4.2 defines a
BindRequest carrying a non-empty DN and a zero-length password not as a wrong
credential but as a distinct legal operation — an *unauthenticated bind* — and
a directory following the RFC literally answers it with resultCode 0, because
as far as the protocol is concerned nothing was being checked. `post_login`
read `password = str(body.get("password", ""))` and never tested it for
emptiness; `authenticate_ldap` passed it through untouched.

`POST /api/login` with `{"username": "<any ldap-mapped account>", "password":
""}` therefore minted a full session with no credential verified. RFC 4513
§5.1.2 says a client SHOULD prohibit sending one, for precisely this reason.

The rest of the authentication layer is genuinely well built — which is what
makes this one inexcusable rather than forgivable. It sits directly in the
hot path and undoes everything else the moment a directory account exists.

### 2. One crafted UDP packet permanently stopped flow storage, and the status line kept saying everything was fine

`netpath/collector.py:334`, `netpath/nfdecode.py:227` · CRITICAL · **fixed**

Three faults compounding:

A v9/IPFIX options record could declare a sampling rate with no upper bound —
`_apply_options` checked only `if rate > 1`. A crafted record set a Python int
larger than SQLite's int64 maximum. Every subsequent flow from that exporter
carried it as `Flow.sampling`, and on the next flush the parameter bind raised
`OverflowError`.

`collector.py:334` called `self.db.insert_flows(pending)` with no `try/except`
— unlike `syslogd.py:511` and `snmptrapd.py`, which guard the identical call
in the identical writer-thread position. So the exception ended the writer
thread.

And `collector.py:79` defines `running` as `self._rx_thread.is_alive()`,
checking only the *receiver*. The receiver kept accepting packets. The status
line kept reporting "Listening on … last packet just now". Zero flows were
stored from any exporter, indefinitely.

A monitoring tool that has silently stopped monitoring while showing green is
the worst failure mode in the catalogue, and this one is reachable from an
unauthenticated UDP port with about fifty bytes.

### 3. The trace scheduler died on the first locked database and never came back

`netpath/monitor.py:167` · CRITICAL · **fixed**

`Monitor._loop` is the timer and dispatch loop for every scheduled
traceroute — the NetPath module this application is named after and started
as. Its body called `self.db.targets()` and `self.db.last_trace()` with no
exception handling whatsoever.

Every sibling scheduler in the same file has a guard. One of them
(`monitor.py:296`) carries the comment *"a scheduler thread must never die
quietly"*. This one did not have it.

A single `sqlite3.OperationalError: database is locked` — which `RUNBOOK.md`
documents as an expected condition under contention — killed the thread. The
web UI stayed up. Every other collector kept running. The dashboard stayed
green. NetPath stopped tracing anything, forever, and no Settings action could
revive it: `apply_netpath_settings` calls `set_workers()` and never `start()`.

### 4. The documented way to stop this service bypassed shutdown entirely

`netpath/__main__.py:208` · CRITICAL · **fixed**

`run_headless` caught `KeyboardInterrupt` and nothing else, and there was no
`signal.signal` call anywhere in the package. `RUNBOOK.md` instructs operators
to run `systemctl stop sappiwhere` / `systemctl restart sappiwhere` on Linux
and `nssm stop SappiWhere` on Windows. Both deliver SIGTERM, whose default
disposition kills the process outright.

So the officially documented stop procedure skipped `finally: server.stop();
service.shutdown()` every single time: ten SQLite databases killed
mid-WAL-checkpoint, open SSH sessions to live network devices simply gone, an
in-flight trace never drained. The runbook and the code disagreed about the
most basic operation there is, and the runbook was the one being followed.

### 5. A failed self-update left the process running with everything shut down

`netpath/selfupdate.py:524` · CRITICAL · **fixed**

`apply()` calls `_run_before_restart()` — which stops the listener and shuts
down every worker and closes every database — and only *then* attempts
`_swap_in()`. On `OSError` (a locked file under Windows AV real-time scanning,
`ENOSPC`) it returned `{"ok": False, …}` and nothing restarted anything.

Alive process. No listener. No monitor. No collectors. Every database closed.
Indefinitely, until a human noticed the box had gone dark.

The three `write_meta()` calls after the swap were also unguarded, in a
function whose docstring promises it "never raises" — and a failure there
skipped `schedule_restart()` too, so the newly swapped-in code never loaded
either.

### 6. Stored device configurations were served to people who may not see them

`netpath/configrx.py:952`, `netpath/web/api.py:6174` · CRITICAL · **fixed**

`_backup_device` stamps every row `redacted=not store_secrets`. That records
*"the redactor ran"*, not *"the redactor removed something"*. And every
pattern in `configrx_redact.py` was anchored on Cisco-IOS or FortiOS directive
syntax, while `configrx_vendors.py` ships backup support for Juniper,
MikroTik, HP, Aruba, Moxa, Siemens and Rockwell.

For those vendors `redact()` matched nothing and returned the config verbatim
— and the row was still stamped `redacted=True`. `get_configrx_backup` then
re-redacted only `if not backup_json["redacted"]`, so it believed the stamp
and served the file whole.

A Juniper `set system radius-server … secret "…"` line, or an IKE pre-shared
key, went out in full to a caller holding only ConfigRX **read** — the exact
boundary that branch exists to enforce. Blacklist redaction is fail-open by
construction; making a permission decision from its output made the failure
silent as well.

There was a second, quieter hole in the same file: no pattern existed for a
bare Cisco `password 7 <hash>` line inside a `line vty` block, which is one of
the most common secret-bearing lines in a real IOS config, in the vendor
family the module claimed to cover completely.

### 7. Deleting a device could hand its SSH password to a different device

`netpath/web/api.py:3343`, `netpath/nodesdb.py:84` · CRITICAL · **fixed**

`delete_nodes_device` committed the `nodes.db` delete first and called
`configrx_db.forget_device()` second. These are two databases, so it cannot be
one transaction — but the order chosen was the wrong one.

`devices.id` is `INTEGER PRIMARY KEY` with no `AUTOINCREMENT`, so SQLite
reissues the highest freed rowid to the next insert. Delete the
highest-numbered device, have the second call fail or the process die between
the two lines, and `configrx.db` still holds that `device_id`'s
`device_config` row — with its `ssh_password_enc` and `enable_secret_enc` — 
keyed to an id nothing owns. Add a device. It lands on that id and silently
inherits the previous device's stored credentials, with nothing logged.

The fix is free: reverse the two calls. Then a crash leaves a Nodes row that
outlives its ConfigRX config, which an operator can simply delete again.

### 8. Two blank boxes in the Edit Rule dialog

`netpath/web/static/alerts.js:935` · CRITICAL · **fixed**

```js
values.threshold = Number(box.querySelector('#ar-threshold').value);
values.clear_threshold = Number(box.querySelector('#ar-clear').value);
```

`Number('')` is `0`. Every other optional numeric field in the same save
handler maps blank to `null` explicitly, with a comment saying why. These two
did not, and there was no server-side validation anywhere to catch the result.

Clear the **Clear threshold** box and save: `clear_threshold = 0`. The clear
test is `value < clear_threshold`, so on any metric that is never negative it
can never be satisfied. The alert raises normally and then stays open forever
— no clear notification, no auto-resolve, until somebody notices and resolves
it by hand.

Clear the **Threshold** box and save: `threshold = 0`. The breach test is
`value >= threshold`, so on the next tick every device reporting that metric
breaches at once. That is the fleet-wide page storm the rollup and digest
machinery exists to prevent, self-inflicted by a mis-click, and entirely
legitimate as far as the engine can tell.

Both are one careless click away in the shipped UI, on the subsystem whose
entire job is to be trusted at 02:00.

### 9. A disabled rule orphans its own open alert

`netpath/alertengine.py:1115` · CRITICAL · **not fixed — see below**

Clear detection for `threshold`, `dhcp_threshold` and `netpath_threshold`
rules happens only inside the per-rule loop, and that loop is filtered to
`rule["enabled"]`. Disable a rule while one of its alerts is open — the
obvious thing to do to quiet a noisy rule during an incident — and the clear
check never runs again for it. The alert sits open forever.

### 10. An outage that starts inside a maintenance window is never alerted

`netpath/alertengine.py:300` · HIGH · **not fixed — see below**

`down`, `mib_missing` and `link_down` are one-shot transition events: the
poller writes them at the moment status changes and never again while the bad
state persists. When such an occurrence is muted, the engine drops it with
`continue` — no parking, unlike the new-device grace path, which explicitly
parks and re-checks.

Mute a switch for a two-hour firmware window. It fails to come back. The
single `down` event landed inside the window and was discarded. No alert ever
opens. The operator finds out by looking.

That inverts what a maintenance window is for: it is supposed to suppress
noise during the window, not blind the system to anything that begins inside
one.

---

## What this release fixed

Every fix carries a regression test. That sentence was not true when this
document was first written — an independent final review found that the
reboot/link-event gate had shipped with none, and that two of the API tests
would have passed with their fix reverted. It is true now because those were
fixed, not because the sentence was softened. What that reviewer found is
listed in [Findings rejected on verification](#findings-rejected-on-verification)
alongside everything else this review got wrong, because a review document
that hides its own corrections is the thing this release is about.

**Authentication and sessions**
- `ldapclient.py` refuses a zero-length password before opening a socket;
  `service.authenticate_ldap` refuses it again for defence in depth.
- `auth.py:288` `destroy_user` now casefolds both sides. It compared with `==`
  while every account lookup in the application resolves through a `COLLATE
  NOCASE` column, so resetting `Bob.Smith`'s password reported "N sessions
  ended", ended none, and left the stolen session for `bob.smith` working —
  defeating the one control that makes a password reset an incident-response
  action.
- `api.py:1310` adds `session_idle_minutes`, `session_max_hours`, `web_host`,
  `web_port`, `web_cert` and `web_key` to `ADMIN_ONLY_SETTINGS`. A plain
  `settings:write` grant — deliberately weaker than admin — could extend every
  session on the host to seven days (applied immediately, not at restart) and
  repoint the TLS listener.

**Credentials**
- `secretstore.py` keys its derived-key cache on the passphrase as well as the
  scrypt parameters. It cached on `(n, r, p)` alone, and `protect()` always
  passes the same three module constants — so the cache always hit and the
  passphrase file was never re-read. An operator who believed their passphrase
  had leaked, rewrote it, and re-entered every credential through the UI was
  silently re-encrypting all of them under the old, leaked key. The docstring
  claimed the opposite.
- `configrx_redact.py` gained patterns for Juniper, MikroTik and HP/Aruba
  secret lines and for the bare Cisco `password 7` form, and its docstring no
  longer claims to cover "the two vendor families".
- `api.py` re-redacts on read for anyone without ConfigRX write regardless of
  the stored flag, taking that flag out of the trust boundary entirely.
- `BACKUP-RESTORE.md`'s recommended automated backup script never copied
  `secret.salt`, so restoring it onto new hardware made every stored
  credential permanently undecryptable. Its claim that a Linux host has "no
  stored credentials to lose" stopped being true when the portable store
  shipped.

**Collectors**
- `collector.py` guards its writer's database calls the way its two siblings
  already did, clamps learned sampling rates, and reports writer-thread
  liveness rather than only the receiver's.
- `nfdecode.py` bounds the template cache per exporter and caps
  fields-per-template. The cache was one global 4,096-entry LRU keyed on
  `(exporter, domain, template_id)` where `domain` comes out of the packet
  body, not the source address — so one sender, with no spoofing, could evict
  every real exporter's templates with a few thousand small packets and blind
  the collector until each one happened to resend.
- `trapdecode.py` clamps oversized BER integers, and `snmptrapd.py` routes a
  failed batch insert through the event log instead of a bare stderr
  traceback. One crafted trap could otherwise discard a batch of up to 200
  legitimate ones, invisibly.
- `syslogparse.py` strips embedded control and ANSI bytes at ingest. The web
  UI escapes correctly — this is not a stored-XSS finding — but the stored
  column was a terminal-escape primitive for any CLI or export consumer.

**Poller**
- `nodepoll.py` derives `_in_octet_bits` and `_out_octet_bits` independently.
  One flag computed from `hc_in or hc_out` was applied to both counters, so a
  device answering `ifHCInOctets` but not `ifHCOutOctets` got 64-bit treatment
  on a 32-bit out-counter and its wrapped samples were silently dropped.
- Link up/down detection is now gated on `rebooted`, as the rate arithmetic
  already was. Platforms that renumber ifIndex across a reload were producing
  fabricated `link_down` events on ports that never changed — and those events
  feed the alert engine.
- Utilization is clamped to [0, 100]. A port falling back to the RFC 2863
  `ifSpeed` sentinel 4294967295 reported above 100%. The reachable ceiling is
  ~130%, not unbounded, because `counter_rate` already rejects anything above
  `speed_bps * 1.3` — the original finding overstated this and was corrected.
- `fortipoll.py`'s hand-rolled walk gained the non-increasing-OID guard
  `nodepoll.py` has had for some time, and logs when it hits its row cap.

**Lifecycle**
- `monitor.py` guards its scheduler tick, counts failures, and paces itself
  outside the guard so a persistent failure cannot become a spin loop.
- `__main__.py` installs SIGTERM, SIGINT and (on Windows) SIGBREAK handlers
  that set a stop event, so the documented stop procedure runs the documented
  shutdown.
- `selfupdate.py` can no longer return from `apply()` with the service torn
  down and nothing scheduled to bring it back, and a marker-write failure no
  longer cancels the restart.
- `ipam_worker.py` passes `cancel_futures=True` like every other pool-owning
  worker, and its inert `except (DhcpUnavailable, Exception)` is now just
  `except Exception`.

**API surface**
- `server.py:1202` catches `OverflowError` beside `ValueError`. Every `(\d+)`
  route arg becomes an int with a bare `int()`, which parses thirty digits
  happily; SQLite's parameter bind is what finds out, and it raises
  `OverflowError`, which is not a `ValueError` — so a bad request answered 500
  across dozens of routes.
- `_window()` runs through `analysis.clamp_window`, the helper this codebase
  already had and this path skipped. `_num(…, float)` parses `"inf"`, `"nan"`
  and `"1e18"` without complaint, and `flowdb.overview` sizes nine lists from
  `(t1 - t0) / bucket_s`.
- `_flow_bucket` widens the bucket to keep the count bounded. It flatlined at
  a six-hour bucket for any span past 14 days, so the count grew with the
  window instead of levelling off.
- CSV exports neutralise a leading `=`, `+`, `-` or `@`. A syslog message is
  written by anything that can reach UDP/514 — no account, no HTTP request at
  all — and lands in an export an analyst opens in Excel.
- Bulk id arrays are capped at 900 (below the lower of SQLite's two variable
  limits), and `?limit=-1` on the discovery list no longer reads as SQLite's
  "no limit".

**Front end**
- Live-window `refresh()` in `syslog.js`, `snmp.js`, `nodes.js` and
  `netpath.js` carries a generation token, matching the pattern `configrx.js`
  already used. Those views recompute `t1 = Date.now()` every tick, so every
  poll built a different URL and the global per-path abort never fired — two
  polls raced, and if the older landed last it silently painted a stale
  window.
- `master()` cannot re-enter a tab's `refresh()` while the previous one is
  still running. It stamped `lastFetch` *before* the await, so a refresh
  slower than its own interval — exactly what happens as a server degrades —
  launched a second concurrent one.
- `dashboard.js` aliases `App.escapeHtml` instead of carrying its own copy.
- Two Save buttons gained the double-submit guard every sibling control in the
  same file already had, and `beforeunload` now warns about unsaved modal
  edits.

**Documentation and CI**
- `INTERNALS.md` said the service "opens five SQLite connections" on line 74
  and "Ten SQLite files" on line 133. It opens ten.
- Both `README.md` and `INTERNALS.md` "Layout" maps listed roughly 25 of 68
  modules, omitting `nodepoll.py` and `nodesdb.py` — the two largest files in
  the application — and the entire Alerts, ConfigRX, Wireless and SNMP Trap
  subsystems, which the same documents describe elsewhere as shipped features.
- `flowdb.py` labelled its database `netflow.db` in every diagnostic. The file
  on disk is `flows.db`.
- `.github/workflows/tests.yml` installed paramiko only on Linux, so five
  suites — the ones proving host-key pinning refuses a changed key, that the
  ConfigRX command allowlist holds, and that the SSH terminal's permission and
  audit boundary holds — reported SKIP on Windows, which is this product's
  primary deployment target. The workflow's own comment claimed it was two.

---

## What this release left open, and why

These are real. They are not fixed here because each one is a behavioural
change to a subsystem that is currently correct-but-incomplete, and shipping a
rushed fix to alert clearing or retention deletion is worse than shipping a
known gap with a name.

### The alerting gaps (findings 9 and 10)

A disabled rule orphaning its open alert, and a muted outage that outlives its
window never being alerted, are both genuine and both reachable through
ordinary operator workflow. Both need a design decision rather than a patch:

- For the disabled rule, does disabling force-resolve the open alerts, or does
  clear-checking continue for disabled rules? Those are different products.
  Force-resolving silently closes something that is still wrong; continuing to
  evaluate means "disabled" no longer means disabled.
- For the muted outage, the fix is to park stateful occurrences the way
  `_hold_for_new_device` already parks new-device holds and re-check them when
  the window ends. That machinery exists. Wiring it to mute expiry touches the
  occurrence lifecycle, which is the part of the engine with the most
  invariants and the least margin for a wrong guess.

### Five `prune()` implementations that never learned their sibling's lesson

`nodesdb.py:3423`, `flowdb.py:324`, `syslogdb.py:855`, `snmptrapdb.py:421`,
`alertsdb.py:2290`.

In each of those files, `trim_to_size()` — the byte-cap path — got the full
chunked-delete-with-deadline treatment, and `nodesdb.py`'s carries a comment
citing a measured 38.9-second stall *"during which every poll worker, the
alert tick and every HTTP handler waited"*. And in each of those files,
`prune()` — the age-based path that runs on **every** maintenance pass, not
just when a cap is exceeded — is still one unbatched `DELETE … WHERE ts < ?`
under the module lock.

`nodesdb.py`'s own docstring puts `samples` at 9.1 GB/day for a 2,000-device
fleet. A retention change or a skipped maintenance window turns the next
scheduled prune into exactly the stall the chunking work was written to
eliminate.

Related: `dbmaint.reclaim()` — the function every retention path calls
*specifically to avoid* a blocking VACUUM — begins with an unbudgeted
`enable_incremental_vacuum(..., max_pages=None)`, which issues a full `VACUUM`
under the same lock for any database still on `auto_vacuum=NONE` above ~8 MB.

This is a coherent piece of work — one shared chunked-delete helper, applied
to all five — and it deserves its own change with its own retention tests.

### The self-updater follows a mutable branch tip

`selfupdate.py:24` documents this itself: step 1 follows `main`, and step 3
"verifies nothing about what it downloads beyond the size cap and 'does this
look like SappiWhere'". Anyone with push access chooses the code every install
with updates enabled will run next — on hosts holding SNMP communities and SSH
credentials for a fleet.

`published_digest()` and `latest_tag()` already exist and are tested. Nothing
calls them from the live path. The mitigation currently doing all the work is
that `updates_enabled` is off by default. Wiring the verified path in is the
single highest-value change left in this codebase, and it is deliberately not
being done in the same release as thirty other fixes.

### The package swap is two filesystem operations

`selfupdate.py:305` does `os.rename(dir, backup)` then `shutil.move(new, dir)`.
The `except` covers a failure *inside* `shutil.move`, not a process death
between the two statements — which leaves the install with no `netpath/`
package at all and a crash loop on next launch, recoverable only by a human
noticing a `netpath.bak-*` directory.

### Nothing prevents two instances against the same databases

No pid file, no lock file, nothing. The only accidental protection is the
listener's bind failure, and that only helps if both instances use the same
host and port. Two `Monitor`, `NodePoller`, `IpamWorker` and `AlertEngine`
instances against the same SQLite files would double every probe to the entire
fleet and race every write.

### Wall-clock scheduling

`monitor.py:162` and `service.py:824` compute due-times from `time.time()`
snapshots. `dbmaint.py`, in the same codebase, correctly uses
`time.monotonic()` for its budgets. An NTP correction stepping the clock
backwards silently pauses retention and trace scheduling for however far it
jumped.

### IPv6 is silently inert in IPAM

`ipam_scan.py:39-44` — all three neighbour-table parsers require a dotted
quad. IPv6 subnets are explicitly supported elsewhere (`usable_addresses` and
`subnet_size` have IPv6 branches) and the ping sweep works, but no IPv6 host
ever gets a MAC, so both conflict checks — which require a non-null MAC — 
never fire. No log line, no caveat, no UI indication.

### Untested modules with real blast radius

`ipam_dhcp.py` (444 lines, stored credentials, generated PowerShell, WinRM
execution) has **zero** test coverage. `analysis.build_topology` — which
renders every path graph in the product — has none. `ipam_worker._scan`, the
actual conflict-detection logic, is stubbed out in the only suite that touches
the module.

### SNMPv3 traps have no replay window

`trapdecode.py:598` parses `msgAuthoritativeEngineBoots` and
`msgAuthoritativeEngineTime` and discards both. RFC 3414 §3.2's freshness
check is never made, so a captured authenticated trap can be replayed
indefinitely and will re-page every time.

### The `_KEY_CACHE` cost oracle

`trapdecode.py:328` runs a ~1 MiB repeated-password hash for any trap whose
username matches a configured v3 user, keyed on an engine ID copied verbatim
off the wire — before the HMAC is compared. An attacker varying the engine ID
gets a guaranteed cache miss per packet and a fresh 1 MiB hash on the
single-threaded receive path.

---

## Findings rejected on verification

A review that reports everything its reviewers said is not a review.

**The SMTP-test endpoint returning `str(exc)` is not a defect.** It was
flagged as an SSRF port-scan oracle for an `alerts:write` holder. But that
error text is the entire diagnostic value of a "test connection" button —
distinguishing "connection refused" from "authentication failed" from
"certificate not trusted" is what the operator pressed it for — and
`alerts:write` is already a trusted grant that can configure where alert mail
is sent. Removing the text would degrade a working feature to close a gap the
grant already implies. Kept, deliberately.

**Utilization does not reach 140%.** The finding claimed a 10G port on the
`ifSpeed` sentinel would report ~140%. It cannot: `counter_rate` rejects any
rate above `speed_bps * 1.3` first, so the reachable ceiling is ~130%. The
bug is real and the clamp was added; the magnitude was wrong and is corrected
here rather than repeated.

**Requiring a clear threshold on every threshold rule was too strict.** The
first version of the fix in this release refused any threshold rule without a
`clear_threshold`, and it broke an existing suite that creates one — correctly.
A rule with no clear threshold is a coherent choice: it closes on
`auto_resolve_after_s`, on a paired CLEARS occurrence, or by hand. What was
broken was a blank box silently becoming `0`, an unsatisfiable clear test. The
validation was narrowed to require `threshold` alone, since a threshold rule
without one can never fire at all.

**The admin-only settings guard was first written too broadly, and an
existing suite caught it.** The first version refused a settings POST whenever
the body *mentioned* an admin-only key. But a per-module scope discards every
key outside its own defaults, so a `netpath`-scope write carrying `web_cert`
never sets `web_cert` — and `test_security_fixes.py` pins that contract
deliberately: the write is accepted and the global key is dropped. Turning an
ignored field into a 403 was a behaviour change of its own. The guard now
filters by the scope's own defaults, so it refuses only the write that would
actually land.

**Adding the listener keys to `ADMIN_ONLY_SETTINGS` broke a real invariant,
and the invariant was right.** `test_security_fixes.py` asserts that every
admin-only setting has a control that can set it — written after
`updates_enabled` shipped guarded by the API and reachable from nowhere, so it
could only ever hold its default. `web_host`, `web_port`, `web_cert` and
`web_key` have no Settings-page control and should not get one: the listener
is changed from the service console, which needs a session on the host itself.
The check was broadened to count `console.py` as a control surface rather than
weakened, because the guarantee it exists to make — no key is guarded by the
API and settable by nothing — is unchanged.

**Stripping control bytes from syslog by deleting them was wrong.** The first
version of that fix removed each control byte, which would have welded a
legitimate multi-line payload — a device packing a stack trace into one
datagram — into `"line oneline two"`. No existing suite covered it. Each run
of control bytes is now replaced by a single space: the ESC byte is still
destroyed, so ANSI sequences are still broken, and word boundaries survive.

**The reboot gate on link events was itself a regression, and a final review
caught it.** Suppressing link up/down comparison whenever `rebooted` was true
stopped the fabricated events on ifIndex-renumbering platforms — and also
stopped the real ones everywhere else. A port that was up before a reload and
does not come back was never compared against "up" again: no `link_down` on
that poll, and by the next poll the stored baseline already said "down". That
trades a spurious alert for a missed one, which is the wrong direction on the
most common post-maintenance failure there is. The gate is now conditional on
the interface identity at that ifIndex having actually changed, and it has the
test it shipped without.

**The bulk-id cap was a fix for a problem this build does not have, and it
broke something that worked.** Capping bulk device requests at 900 was
justified by SQLite's 999-parameter limit — which applies to builds older than
3.32, while the interpreter here carries 3.45.3 and a limit of 32766. Meanwhile
the Devices page ships a 1000-row page size with a select-all, so the cap
turned an ordinary bulk delete into a 400. The parameter limit is now handled
by chunking the statement in `nodesdb`, which is correct on every build, and
the request cap exists only to refuse an absurd payload.

**Two of the API regression tests were theatre.** One asserted that a deleted
device's ConfigRX config was gone — true under the old ordering too, since both
calls run on the success path, so it pinned nothing. The other asserted that
`?limit=-1` returned `200` and a dict, which the unclamped route also did while
returning every row. Both now pin the actual behaviour: the delete ordering is
proven by making the second call fail, and the limit is proven by row count.

**No stored XSS was found.** The front-end reviewer traced device names,
interface descriptions, LLDP neighbour names, SNMP varbind text, syslog
messages and vendor config text through every `innerHTML` write and every cell
renderer in all sixteen modules and reported, explicitly, that it would not
manufacture a finding to satisfy the brief. `App.escapeHtml` is applied
consistently in text and attribute context, and the tooltip layer uses
`textContent` rather than markup. For 27,000 lines of framework-free
JavaScript that is a genuinely good result and it belongs in the record.

**The exporter allowlists are not authentication, and that is not fixable.**
NetFlow v5/v9/IPFIX carries no cryptographic identity, so matching on a UDP
source address is the only thing available. The finding is right that it is
spoofable; the fix is a documentation change telling operators to pair it with
BCP38 ingress filtering, not a code change pretending otherwise.

---

## The architecture, without flinching

The individual functions in this codebase are written with more care than
most. The structure they sit in was never given the same attention, and the
gap between those two facts is what produced nearly every finding above.

**68 modules, flat.** No subpackages except `web/`. There is no boundary that
makes a poller importing the alert engine, or a database module reaching into
web code, a visible mistake rather than an import line.

**`web/api.py` is 7,496 lines and 340 functions.** 113 of the repository's 414
commits touch it — more than one in four commits anywhere in this codebase
collides on one file. Two engineers on unrelated tabs still edit it. And the
cross-cutting invariants it depends on — permission gate present, id
bounds-checked, SQL parameterised — have no structural enforcement beyond
someone remembering. Both API findings above are that sentence, made concrete.

**The longest function is 410 lines.** `nodepoll._poll_device` handles ping
scheduling and carry-forward, SNMP credential resolution, scalar polling,
interface polling, custom MIB polling, error classification, reboot detection
and database write assembly. Nothing in it is independently testable. The
next three are `nodesdb._migrate` (273), `configrx._backup_device` (256) and
`web/server._route` (191).

**Ten SQLite files with no cross-file consistency story.** The isolation is
defensible — it bought real relief from lock contention between a busy flow
collector and everything else — but adopting it obliges you to build the thing
that replaces a transaction across those files, and nothing here does. The
device-deletion credential-inheritance bug is what that omission costs, and it
is the only finding in this review that is specific to the multi-file choice
rather than incidental to it.

**121 `except Exception:` clauses, 34 of them bare `pass`.** Half are in
`sshterm.py` and `monitor.py`. An SSH session that silently fails to resize
its PTY leaves no trace anywhere — not the event log, not stdlib logging, not
any screen.

**Three disconnected logging mechanisms.** `EventLog` is in-memory only, capped
at 3,000 entries, and says so. Six modules call `logging.getLogger(__name__)`
and *nothing anywhere* calls `basicConfig`, `addHandler` or `setLevel` — those
records go to the last-resort handler, or nowhere at all under `pythonw.exe`.
And there are 39 bare `print()` calls, including self-test blocks inside
shipped modules. A responder at 02:00 has an in-memory ring buffer that has
probably already rotated past the incident, and no persistent record at all.

**Two dependencies, both unpinned, no lockfile.** `PySide6>=6.5` and
`paramiko>=3.4,<5`. Nothing in the repository records which version a deployed
instance is actually running.

---

## Documentation that was not true

1.5 MB of markdown for 78,000 lines of code. Most of it is unusually honest —
`selfupdate.py` flags its own supply-chain debt in its module docstring, which
is more candour than most projects manage. But the maps have stopped matching
the territory, and a map that is wrong is worse than no map.

| Claim | Where | Reality |
|---|---|---|
| "opens five SQLite connections" | `INTERNALS.md:74` | Ten. The same document says "Ten SQLite files" on line 133. |
| The `netpath/` file map | `README.md:747`, `INTERNALS.md:25` | ~25 of 68 modules. Omits the two largest files in the application and five of the twelve shipped tabs. |
| api.py handlers "grouped by NetPath, NetFlow, syslog, IPAM, auth and users" | `README.md:779` | 26 route prefixes; 20 unlisted. Written for a much smaller version of the file. |
| Redaction "covers the two vendor families ConfigRX ships support for" | `configrx_redact.py:26`, `CREDENTIAL-SECURITY.md:541` | Nine vendor keys ship. Seven were not covered at all. |
| "there are no stored credentials to lose, because a non-Windows host cannot store one" | `BACKUP-RESTORE.md:187` | Untrue since the portable secret store shipped. |
| The recommended nightly backup script | `BACKUP-RESTORE.md:96` | Copies ten `.db` files and not `secret.salt`, without which every restored credential is undecryptable. |
| "the Windows leg of this matrix runs everything else and skips those two" | `.github/workflows/tests.yml` | Five suites, and they are the SSH and ConfigRX safety-boundary ones, on the primary deployment OS. |
| `apply()` "never raises" | `selfupdate.py` | Three unguarded `write_meta` calls could. |
| `_keys_for`: "a rotated passphrase file takes effect on the next key this process has not already derived" | `secretstore.py:293` | There is never such a key. It took effect at restart and not before. |

---

## Verdict

I was asked to hate this implementation. I do not, and saying otherwise would
be the least useful thing in this document.

What I object to is structural. This is a codebase where the person writing
any given function is careful, thinks about the failure mode, and writes down
why the guard is there — and where nothing carries that care from one file to
its sibling. Every serious finding here is a pattern this codebase already got
right somewhere else. The writer thread that needed a `try/except` sat two
files away from two writer threads that had one. The scheduler that needed an
exception guard sat in the same file as four that had one, under a comment
saying scheduler threads must never die quietly. The retention path that
needed chunking sat sixty lines above a chunked one with a stall time measured
in its comment.

That is not a skill problem, and it will not be fixed by reviewing harder. It
is what 68 flat modules and a 7,496-line api.py do to a team that is otherwise
doing good work: they make "apply this fix everywhere it belongs" a thing you
have to remember rather than a thing the structure does for you.

Two things I would not deploy as they stood before this release: the LDAP
empty-password bind, and the self-updater — the latter still, because the
verified path is written, tested, and not wired in. Everything else in this
document is now either fixed with a test pinning it, or named here with enough
detail that the next person does not have to find it again.

The single highest-value change left is not on the findings list. It is
splitting `web/api.py` by module. Not because it is elegant, but because it is
the file that 27% of this project's commits touch, and it is where the two
classes of bug that nobody had in their threat model — DoS by integer, DoS by
time window — were both sitting undisturbed.
