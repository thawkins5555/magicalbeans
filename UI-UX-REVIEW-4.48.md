# UI/UX Review — SappiWhere 4.48.0

**Date:** September 4, 2026
**Build reviewed:** 4.47.0, commit `fc6b3e1` (`netpath/web/static/*`, `netpath/web/server.py`, `netpath/web/wsock.py`, `netpath/configrx.py`, `netpath/theme.py`)
**Branch:** `claude/ui-ux-review-improvements-ylkdll`
**Reviewers:** two specialist passes (graphic/UI design; UX and interaction design), plus supporting passes for accessibility, the five operator-requested changes, a disposition of the 114 findings in `UI-UX-REVIEW.md` (build 4.36.1), and the test/release conventions.

## A note on how this document was assembled

The six reviewers' own reports did not survive the machine that produced them. What survived is `FINDINGS.md` — a recovery document listing every finding the approved remediation plan scheduled for work, organized into the same eight phases the review used — and the commit history of this branch, seventeen commits at the time of writing, each of which explains in its own message what was found, what was changed, and why. This document is built from those two sources: FINDINGS.md for what was raised, `git log` and `git show` for what was actually done about it. Where a number appears below, it is a number a commit measured, not one reconstructed after the fact. Where a phase is still open or mid-flight as this is written, it says so rather than guessing how it will land.

## What was reviewed, and how

The review was driven against a live seeded instance rather than against the source alone: 30 simulated SNMP devices on a `127.0.0.2–31` range with fleet control on a separate port, seven fake SSH switches (`demo/fake_ssh.py` — a Cisco IOS device, a Cisco with a pager that never turns off, a Cisco whose capture truncates, a Fortinet, a MikroTik, a menu-driven console, and a device stuck at an unprivileged prompt), three accounts spanning admin/operator/read-only permissions, three themes (dark, light, high contrast) and three viewports (1920×1080, 1366×768, 1280×720). ConfigRX's Phase 2 work added five more SSH personas during the fix, covering NX-OS, IOS-XR, a small-business switch, an ASA and a WLC — the fleet the review was run against is smaller than the one the product now ships tests against.

The review's own screenshot collector, `demo/ui_walk.mjs`, is discussed on its own terms in the closing section: its inventory had gaps that the fix work found and closed, which is itself evidence about what the original review could and could not have seen.

---

## Three defects the review did not find

These were not on the reviewers' list. Each was found while fixing something else, and each is the kind of thing a review driven from screenshots and static reading is unlikely to catch, because the failure only shows up under a specific runtime condition — a hung device, a platform's own connection-reset behaviour, or ten minutes of an idle tab.

**A device that hangs up mid-capture crashed the ConfigRX backup instead of reporting the case its own error text exists for.** `_pull_config`'s `finally: channel.close()` (`netpath/configrx.py:511-521`) could raise out of the function and discard a result that had already been computed. Closing a channel sends a message; when the device has already hung up — precisely the `"closed"` case `_capture_problem` (`netpath/configrx.py:540`) exists to describe — paramiko's `write_all` raises `EOFError` into a socket that is gone. So the one situation the code was careful to name ("The device closed the connection before the config finished") instead crashed the whole attempt with a bare `EOFError`. Fixed in `b245e526` by making the close best-effort, matching the pattern the SSH terminal's own teardown already used. Found while chasing an intermittent failure in the new six-platform Cisco test suite that turned out not to be a flaky test at all.

**A refused WebSocket lost the sentence explaining the refusal, on Windows.** `WebSocket.close()` (`netpath/web/wsock.py`) sends its close frame — carrying the code and the sentence explaining itself, "There are already 16 SSH sessions" among them — then shuts the socket down in both directions, deliberately, because a half-closed socket is what unblocks a `recv()` parked in another thread. Windows resets a connection that is closed while data the peer sent is still unread, and a reset discards whatever was last written in the other direction. So the close frame was thrown away by the reset that followed it: the peer read a bare `ConnectionResetError` where it should have read the refusal, and an operator turned away by the session cap saw only a disconnection. Linux sends a FIN in the same circumstance, which is why every previous run of the test that depends on this passed. Fixed in `17aee347` by draining the receive buffer (bounded to eight non-blocking reads) before the shutdown, which took the Windows test run to 53 of 53 for the first time.

**The Debug tab's DOM churn was `App.wireRowKeyboard` restamping every row on every poll, not the table rebuild it was assumed to be.** The append-vs-rebuild logic in `drawEvents` had already been fixed before this branch. What remained — measured at 8,042 DOM mutations per ten idle seconds, against 6 for Dashboard and 10 for Settings — was `drawEvents` calling `App.wireRowKeyboard` on every 100 ms tick regardless of whether anything had changed, and that function walks the whole table stamping `tabindex` on every row, up to the 2,000-row cap. `b5d6e654` made the call conditional on rows actually having been added or the selection having moved (871→367 mutations per 10 s on a paused tab); `1534a60f` closed the remainder by making `wireRowKeyboard` itself skip a `tabindex` write when the value is already correct, which is the change that mattered most — measured on a live event table, 5,472 writes per 30 seconds became 0, with events still arriving.

---

## Defects found and fixed, by phase

### Phase 1 — traps, silent writes, five asks (complete)

All eleven findings landed, principally in `4c28d84c` and `291fd453`, with a reconciliation pass in `3dd0aaf7` after three workers kept refining the same files past their first commit.

- **P1-1, the Account trap.** `accountBtn.onclick = accountModal` handed the click's `MouseEvent` to `accountModal(forced)`, so every Account press opened the forced, unclosable first-sign-in dialog. `4c28d84` makes the handler call `accountModal()` with no argument, turns the forced path into an explicit option, and moves `setBackgroundInert(false)` in `closeModal` ahead of the locked-dialog early return, so a locked dialog can no longer strand the page.
- **P1-2, discovery already-added.** A sweep of an already-monitored range ticked 56 checkboxes for devices already added. `4c28d84` computes `existing_device_id`/`existing_device_name` once per listing; already-monitored rows render "Already added — `<name>`" with a link and no checkbox, are excluded from select-all, and "Add approved" reports how many were genuinely new. Covered by `tests/test_nodediscover_e2e.py`.
- **P1-3, tab renames.** WIRELESS (FORTIGATE) → FORTIWIRELESS, CONFIGRX → ConfigRX, NETPATH → ROUTES, landed in `4c28d84`; the README/FEATURES tab lists followed in `52c243a4`, with a clause in each noting Routes is the NetPath module under a clearer label.
- **P1-4, the WEB button.** Device details gained a WEB link to `http://<ip>/` (IPv6 bracketed) beside SSH, in `4c28d84`; `3dd0aaf7` found that `.linkish` only matched `button.linkish` and the new `<a>` rendered as browser-default blue, and extended the selector to cover both.
- **P1-5, dialog buttons below the fold.** `4c28d84` inverts `App.modal`'s default so the button row sits at the top unless a caller opts out.
- **P1-6, validation and error routing.** The modal error paragraph gained `id="modal-error"` with `aria-describedby` wired to invalid fields, and the sign-in page did the same, in `4c28d84`. `291fd453` added the server- and client-side pieces: ConfigRX's SSH port refused outside 1–65535 on both sides, NetPath's Add validates the host both sides instead of storing `999.999.999.999`, and Add device routes a blank address or a server refusal through `requireFields` and the modal error line.
- **P1-7, Settings.** `291fd453` added a client-side range check before POST, a server-side range guard, and a `saved` snapshot so Revert repaints from the last saved payload instead of the mutated live state; `3dd0aaf7` names the mechanism `APPLY_FIELDS` and adds the dirty-tab guard that marks unsaved edits, keeps them across a tab switch, and announces them on leaving.
- **P1-8, ConfigRX viewer 403.** `291fd453` moves the stored-backup route to ConfigRX read, redacting a verbatim-stored row for callers without write, so a reader's click toasts instead of throwing an uncaught 403. `3dd0aaf7` records that this specific change had to be recovered from the pushed commit rather than the working tree, which had lost it.
- **P1-9, the discovery ambush.** `4c28d84` replaces the every-visit 62-row approval dialog with a dismissible strip line, auto-opened only for the session that started the scan and only once.
- **P1-10, IPAM's default tab.** `291fd453` reorders IPAM to open on Subnets & hosts, with DHCP disabled and its reason stated where DHCP is unavailable; `4c28d84` sets the product-wide default landing tab to Dashboard.
- **P1-11, Cancel/Close/primary hygiene.** `291fd453` gives Maintenance windows and the Wireless controllers dialog a real primary and a Cancel; `4c28d84` wires kiosk mode so a non-`kioskSafe` dialog degrades to a toast rather than blocking a wall display, with only the forced password dialog marked safe.

### Phase 2 — ConfigRX (complete)

The backend half — six new Cisco platform personas (NX-OS, IOS-XR, a small-business switch, an ASA, a WLC), enable-mode escalation, and the encrypted enable secret's storage contract — landed in `46e47ec9`, with `tests/test_configrx_cisco_platforms.py` driving every persona through the real capture chain plus one full `ConfigRxWorker.backup_now` run.

The UI half, listed as TODO in the recovered findings, landed in `b245e526`:

- The credential route accepts `enable_secret` end to end — absent leaves a stored one alone, empty clears it, non-empty is encrypted like the password — and the credential dialog surfaces it with a hint that it is only needed where a platform lands in user EXEC. The vendor field became a list of the eleven known keys with a free-text escape.
- "Back up now" is disabled with its reason instead of hidden outright, without fighting the permission gate's own disabling; a failure toasts the device and the reason, rather than only flipping the button label to "Failed".
- A capture under a fifth of the previous stored size is stored but flagged `suspect` rather than `changed`, so the next diff does not present an entire configuration as deleted.
- Port and Credential — the two facts that decide whether a backup can work at all — are visible columns by default; the list defaults to the devices ConfigRX actually manages; the backups header wraps instead of clipping its last button.

The same commit fixed the intermittent failure in the new Cisco test suite — the `_pull_config` crash described above — and a second race in the suite itself (a worker's first due-scan landing between enabling backups and storing the credential); 35 consecutive standalone runs and two full suite runs were clean afterward.

### Phase 3 — keyboard and screen-reader semantics (mostly complete)

Landed across three commits: `e468ca8e` (the tab/subtab contract, focus handling, SVG pattern collisions, the idle banner, the denied-control note), `b9785c4c` (every chart, the route graph, the topology view and the SSH terminal reachable without a pointer), and `5c88ab88` (the terminal's keyboard-trap exit).

- The tab strip has carried `role="tablist"` for releases without implementing Arrow/Home/End or roving tabindex; `e468ca8` adds both, and extends the same shared handler to all eleven `.subtabs` groups, which had no role, no selected state and no arrow keys at all.
- Eight charts, the route graph, the timeline and the topology view were `tabIndex -1` with tooltips bound to `mousemove` alone. `b9785c4` gives every chart container `tabindex`, `role="img"` and a label built from the module's own header summary; tooltips answer focus as well as hover in netflow, ipam, netpath, nodes, snmp and syslog; keyboard movement was fitted to each chart's own idiom (NetFlow's existing pan/zoom handlers take arrow keys, NetPath's timeline walks bucket by bucket, IPAM's scope trend walks point by point). NetPath's destination list — the control that decides what the whole module is about — became a real listbox with roving tabindex keyed by destination id.
- The SSH terminal gained `role="status"`, a visually hidden `role="log"`, xterm's `screenReaderMode`, one correct tab stop instead of two, disposal of the previous terminal before a reconnect, and a socket-failure message that names the host, port and where to change it instead of `[Errno None] Unable to connect to port 2201 on 127.0.0.250` (`b9785c4`). Escape had been swallowed as the terminal's only documented way out, which is a trap: Escape is a real keystroke inside vi, less and the menu-driven consoles this window exists to reach. `5c88ab8` makes Ctrl+F6 the exit and frees Escape to reach the device.
- Six SVG pattern ids were emitted identically on every page, so `url(#sw-pat-hatch)` resolved to whichever `<defs>` came first — the one mechanism carrying status without relying on hue rested on an id collision. Fixed by suffixing ids per host SVG (`e468ca8`, completed in `b9785c4` for the two remaining `statusPatternUrl` call sites).
- Also in `e468ca8`: the discard prompt now marks the form behind it `inert` rather than leaving thirteen fields focusable; sorting a column restores focus to the header afterward instead of destroying it; Space on a focused row ticks its checkbox instead of opening it; the idle banner's `role="alert"` announces checkpoints rather than every second; the denied-control sentence is one note per denied module per page instead of one per container with no gutter; and the Alerts tab's accessible name, which read "ALERTS76", was fixed.

Three items from this phase's list have no commit addressing them and remain open: the device-detail dialog opened by double-click does not pass itself as `options.trigger`, so focus return after Escape falls back to whatever `document.activeElement` happens to be rather than a deliberate choice; the three placeholder-only inputs originally flagged in `index.html` around line 1116; and keyboard number-shortcuts, which still cover nine of the twelve tabs.

### Phase 4 — feedback, outcomes, form consistency (primitives complete; module adoption in progress, uncommitted)

`1534a60f` built the shared pieces this phase needs, generalising the one good async-job pattern already in the product — ConfigRX's "Back up now" state machine — into `App.runJob(button, labels, promise)`; adding `App.emptyRow`, wired through `drawRows`, so a table cannot ship a header row over an empty body; a `button.danger` tier, pushed away from a dialog's affirmative end (`.modal-box .row button.danger { margin-right: auto }`) rather than sitting flush against Save; a two-track label-column grid so a control's left edge stops spreading 42px within one fieldset and 82px across Settings; a 68-character prose cap in place of the old 250-character measure; `.linkish.inline` for a mid-sentence link that should not carry button padding; `.scrollbox` in place of five ad-hoc heights; and an Account dialog that names who is signed in, what access they hold and when the session ends, rather than being titled "Change your password" and saying nothing about the account.

As this document is being written, the working tree carries substantial uncommitted changes across `alerts.js`, `ipam.js`, `netflow.js`, `netpath.js`, `nodes.js`, `snmp.js`, `ssh.js`, `syslog.js`, `wireless.js` and `index.html` — visibly the per-module adoption of these primitives (`App.statusMark` calls appearing in `ipam.js`, a `plottedRange` helper in `syslog.js` for the Phase 5 histogram finding below, `setText`/`setBg` helpers for Phase 7's write-on-change work). None of this is committed, so none of it is claimed as done here; its outcome is not yet verified.

Findings with no commit or in-flight change addressing them: Alerts' Clear omits `alerts-filter-state`, the only module that does; Dashboard severity tiles land on a list still filtered by the previous State; a MAC search with no hit leaves `#nd-mac-note` hidden instead of naming the likely cause; a bulk-mute refusal leaks `device_ids and/or group_id is required` verbatim; destructive verbs (Remove, Clear credential) still share a button row with Save in the Edit device dialog rather than being moved to the object's own action row; template Preview still saves the template as a side effect; NetFlow's status line still repeats "no template yet" and Nodes' identity line still reads "error authorization error".

### Phase 5 — colour, themes, charts (theme/contrast half complete; chart half open, with in-flight work)

- **Light theme contrast.** `36a07af` found the cause was the token test's own pair list, which only ever checked a semantic tone against `--bg`; `--raised` is where those tones actually live (every alternate table row), and `--ok`/`--warn` measured 4.31:1/4.21:1 there — under AA, on a suite reporting green. `TEXT_ON` now checks every semantic tone against `--raised`, `--panel` and `--selected`; the tones themselves moved to `#146530` and `#7F520C` (7.16:1 and 6.74:1, confirmed in `tokens.css`). The light theme's inverted elevation (`--panel` at 92.0% luminance and `--raised` at 84.3%, both darker than a pure-white `--bg`) was corrected by tinting the page (`--bg: #EEF1F5`) and letting surfaces climb to white.
- **High contrast's own weak spot.** The theme whose purpose is separation had the weakest surface separation of the three — `--bg`→`--raised` measured 1.09 against 1.18 in the other two themes. Now 1.21, per the comment in `tokens.css` beside `:root[data-theme="contrast"]`.
- **The `--checked-strong` exception**, recorded rather than quietly held (see below).
- **The route canvas.** `317ed92` gives high contrast its own `--canvas-*` palette rather than leaving it the shared light one — a 1500×540 white rectangle was the single largest glare source in a near-black interface, on the one theme an operator picks because brightness and separation are the problem. The dark theme was deliberately left alone (the canvas is a light palette on purpose — it is what prints), and the light theme needed no change once its own surfaces climbed to white, which gave the canvas a boundary against the page it sits in.

Everything else in this phase's list is open at the time of writing, though several items have uncommitted work already touching the relevant files: the meter fill-vs-track contrast (1.45–2.18:1 in every theme); IPAM's use of `--blocked`/`--muted` (syslog-severity colours borrowed for up/down state) rather than `App.statusMark` — the fix is visible in the uncommitted `ipam.js` diff but not yet landed; status timelines with no time axis; histograms plotting the filter window rather than the data range — a `plottedRange` helper for exactly this is present, uncommitted, in `syslog.js`; NetPath's RTT lane reporting "peak 0 ms"; IPAM's donuts with no centre figure and a duplicated legend; a zero-link topology drawing 62 empty boxes; `fit()` clamping at 100% so a two-hop route fills 4% of its pane; and the SSH terminal's ANSI palette, which is dark-theme-only and carries the product's one literal px font size.

### Phase 6 — layout, navigation, information architecture (not started)

No commit on this branch touches the grouped tab bar, the Nodes column-width contract, dashboard tile spacing, subtab URL state, the Settings-page reorganisation into subtabs, permission presets, cross-module links on the five detail panes that currently show a bare key, global search, kiosk entry/rotation from the screen, help-topic coverage beyond Nodes, login-page copy, or the 320px breakpoint. All of Phase 6 remains as recorded in FINDINGS.md.

### Phase 7 — performance (Debug and asset caching complete; the rest open, with in-flight work)

- **Debug's churn**, described above, is fixed (`b5d6e654`, `1534a60f`).
- **Static asset caching.** `b5d6e654` adds a `versioned` path to `Handler._static` (`netpath/web/server.py`): a request carrying a `v` query parameter is served `Cache-Control: public, max-age=31536000, immutable` and skips revalidation entirely, while the unversioned path keeps `no-cache` and its ETag byte for byte — which is what `tests/test_static_headers.py` pins — and `/` and `/login` stay `no-store` regardless. The mechanism is built but not yet switched on: nothing in `index.html` requests the versioned URLs yet, because that markup change is tied to the version bump, which is part of the Phase 8 work still to do. `netpath/__init__.py` still reads `__version__ = "4.47.0"` at the time of writing.

Open, with uncommitted work visible in the working tree: `fastTick` write-on-change for the NetPath timeline and other modules' `drawStatus` functions (the `setText`/`setBg` pattern seen spreading into `syslog.js`). Open, with no commit or in-flight change: the 154ms median / 175ms p95 cost of a Nodes refresh under full teardown-rebuild; transitions under `prefers-reduced-motion`; the spacing scale, `--fs-lg`, and unstyled `<code>`.

**PERF-004, minification, was declined.** The application is stdlib-only Python with vanilla JS/CSS and no build step; gzip is already negotiated in `_send` at the server's own `GZIP_LEVEL = 6` (`netpath/web/server.py`). Measured directly against the 4.47.0 build this review was run on — the fourteen files a cold load actually pulls in (`index.html`, `boot.js`, `app.js`, the twelve module scripts, `tokens.css`, `app.css`), gzipped at that level — the cold load is about 285 KB. A build step buys marginal bytes on top of a compression scheme that is already doing the real work, for a project that otherwise ships with nothing to compile; the cache work above was judged the higher-value use of the same budget.

### Test infrastructure and Windows portability

Three commits outside the phase numbering fixed the harness itself rather than the product, all found chasing the Windows leg of the test matrix:

- `d026361` — `tests/run_all.py` decoded subprocess output using the locale encoding (cp1252 on Windows), so the first suite to print an em dash raised `UnicodeDecodeError` inside subprocess's reader thread and took the runner down with a `TypeError` before printing a single PASS or FAIL. Now decodes UTF-8 with `errors="replace"`.
- `695573c` — three suites that only passed on the machine they were written on: `test_icmp_socket.py` asserted a refused ICMP socket returns `False`, which only holds where `ping` is absent (not true on Windows or most Linux hosts) and fed Unix `ping` output to the Windows RTT parser; `test_secretstore.py` called real Windows DPAPI where it meant to test the portable `NPSS` path; `test_static_headers.py` guarded the wrong endpoint against a payload-size ceiling.
- `17aee34` — the WebSocket close-frame defect described above, found while chasing the last intermittent failure in this list, which took the Windows run to 53 of 53.

`3dd0aaf7` records the Windows suite state after Phase 1's reconciliation: 51 of 53, with `test_ssh_terminal.py` passing alone and failing only under full-suite load, and the then-new `test_configrx_cisco_platforms.py` intermittent against its in-process paramiko stub — both later resolved (`46e47ec9` — the standalone `test_ssh_terminal.py` behaviour is unchanged and not further addressed here — and `b245e526` for the ConfigRX flake).

### Phase 8 — release mechanics (not started)

The version bump in `netpath/__init__.py`, the CHANGELOG entry, a Fable code review of the branch and any findings it raises, and the merge to `main` have not happened as of this document. `tests/README.md` does carry the row for `test_configrx_cisco_platforms.py` (landed with `46e47ec9`). This document is itself part of Phase 8's "consolidated review doc" item.

---

## The `--checked-strong` exception

`36a07af` found, and `tokens.css` now records in a comment beside the token block, that `--checked-strong` — the tint for a row that is both ticked for bulk action and open in the detail pane — cannot be made to clear AA on every surface without giving something else up. It is deliberately the strongest of the three selection tints, because "ticked and open" has to be unmistakable, and contrast is a luminance relationship: solving for a value where every tone clears 4.5:1 against it lands all three tints within 0.03 of each other in the dark theme, or inverts their order in the light theme. Either result defeats the reason the tint exists. The decision recorded in `tokens.css`: `--text` (7.45:1 dark, 11.27:1 light) and `--muted` (light) hold at AA on `--checked-strong`; the quietest metadata tone, `--dim`, does not, so nothing that only appears in `--dim` is drawn on a row in that state; and the high-contrast theme, which claims AAA everywhere else, was moved (`--checked-strong: #2A3E66`, at 1.55 against `--raised` where `--checked` alone is 1.27) until it clears its own bar outright.

---

## What remains open

Compiled from FINDINGS.md against what the commit history above shows landed. "In progress" means uncommitted working-tree changes exist that appear to address the item, unverified at time of writing.

| Phase | Item | Status |
|---|---|---|
| 3 | Device-detail dialog (dblclick) does not pass `options.trigger`; focus return after close is incidental | Open |
| 3 | Three placeholder-only inputs (`index.html`, originally ~1116–1159) | Open |
| 3 | Keyboard number-shortcuts cover 9 of 12 tabs | Open |
| 4 | No outcome message at each of: Add device, Acknowledge, bulk Acknowledge, Trace now, module Settings Save, Alerts "Send test" | In progress (primitive shipped, adoption uncommitted) |
| 4 | Syslog/SNMP header row over empty tbody; NetFlow three empty-state treatments at once; Nodes interfaces table headers-over-nothing | In progress (primitive shipped, adoption uncommitted) |
| 4 | Alerts Clear omits `alerts-filter-state` | Open |
| 4 | Dashboard severity tiles land on a list still filtered by the previous State | Open |
| 4 | MAC search with no hit hides `#nd-mac-note` instead of naming the likely cause | Open |
| 4 | Bulk mute error leaks `device_ids and/or group_id is required` | Open |
| 4 | "N shown" without a denominator in Alerts/Syslog/SNMP | Open |
| 4 | Destructive verbs (Remove, Clear credential) share a button row with Save in Edit device | Open |
| 4 | Remove device buried inside Edit; template Preview silently saves | Open |
| 4 | NetFlow "no template yet" repeats; Nodes "error authorization error" copy | Open |
| 4 | 61 inline `style=` attributes; a literal `4px` radius in alerts.js | Open (partially superseded by `.scrollbox`) |
| 5 | Meter fill vs track contrast, 1.45–2.18:1 in every theme | Open |
| 5 | IPAM up/down colour borrowed from syslog severity, not `App.statusMark` | In progress, uncommitted |
| 5 | Status timelines have no time axis | Open |
| 5 | Histograms plot the filter window, not the data range | In progress, uncommitted (`plottedRange` in `syslog.js`) |
| 5 | NetPath RTT lane says "peak 0 ms" over a populated chart | Open |
| 5 | IPAM donuts: no centre figure, no slice gaps, duplicated legend | Open |
| 5 | Zero-link topology draws 62 empty boxes | Open |
| 5 | `fit()` clamps at 100% scale-up | Open |
| 5 | SSH terminal ANSI palette is dark-theme-only; `fontSize: 13` is a literal px size | Open |
| 6 | Grouped tab bar with pinned utility group; `#version` into Account dialog | Open |
| 6 | Nodes colgroup `data-grow`; Response/Vendor off by default when narrow | Open |
| 6 | Dashboard tile spacing; `.target-list` gutter; nested-subtab styling; interface-dialog gutter | Open |
| 6 | Subtabs not reflected in the URL | Open |
| 6 | Settings reorganised into subtabs with in-page navigation | Open |
| 6 | User permission presets (Viewer/Operator/Admin/Custom) | Open |
| 6 | Discovery timing fields in a self-opening second dialog; raw enums in Add rule | Open |
| 6 | Five detail panes render a key with no link (Alerts object, Syslog/SNMP source, Wireless controller, IPAM conflicts) | Open |
| 6 | No global search | Open |
| 6 | Kiosk mode cannot be entered, changed or rotated from the screen | Open |
| 6 | Help coverage: `App.helpLink` used only in `nodes.js` | Open |
| 6 | Login page: no version, no first-run guidance | Open |
| 6 | NetFlow "Resolve names" writes server-wide state from a filter-bar checkbox | Open |
| 6 | 320px breakpoint | Open |
| 7 | `fastTick` write-on-change beyond Debug (NetPath timeline, other modules' `drawStatus`) | In progress, uncommitted |
| 7 | Nodes refresh: 154ms median / 175ms p95 on full teardown-rebuild | Open |
| 7 | No `prefers-reduced-motion` handling | Open |
| 7 | Spacing scale; `--fs-lg` unused; `<code>` unstyled | Open |
| 8 | Version bump, CHANGELOG entry | Open |
| 8 | Fable code review and its findings | Open |
| 8 | Merge to `main` | Open |

Phase 2's UI TODO list and Phase 1's eleven findings are the only ones fully closed with nothing remaining against them.

---

## The review method, and what it missed

The previous review (`UI-UX-REVIEW.md`, build 4.36.1) and this one's screenshot evidence both came from `demo/ui_walk.mjs`, the collector that walks the product and captures a screenshot at each named state so a change can be diffed before and after. `ec3ded8f` found that its inventory had fallen behind what the application had grown to: the Nodes topology subtab, two of the four device-detail nested subtabs, MAC search, device groups, custom MIBs and every ConfigRX dialog were simply absent from it, so a change to any of them was invisible to a before/after comparison. More significantly, it had no theme pass and no viewport pass at all — every capture it had ever taken was the dark theme at one screen size. That is one of the two concrete reasons a light-theme contrast failure (Phase 5) and a tab bar that clips its own utility group below a certain width (Phase 6, still open) both survived a review that used it: the tool literally never looked.

The collector now walks 152 steps: the previously-missing surfaces above, a kiosk pass (which also proves a non-kiosk-safe dialog degrades to a toast rather than blocking a wall display), each of the three themes across all twelve tabs, and three viewports. 151 of 152 ran clean against the live instance on the run recorded in `ec3ded8f`, producing 140 screenshots; the one failure (`dlg:alert-rule`) needs an alert rule to already exist on the seeded instance and is recorded as failed rather than silently skipped, which is the script's own design. Selection throughout is by `data-tab`/`data-subtab` rather than by visible label, specifically so that a renaming pass like this release's tab-name changes cannot silently break the walk's own aim.

What this does not fix: the collector takes screenshots, and a screenshot is still read by a person or by a model looking at it. Extending its inventory closes the class of defect where the tool never pointed a camera at the thing that was wrong; it does not by itself catch a defect the camera saw and nobody read carefully — which is presumably closer to how the 154ms Nodes-refresh figure and the still-open Phase 5/6 chart and layout defects above remain on the list despite being, in principle, visible in a capture already taken.
