# UI/UX Review — SappiWhere Network Monitoring Platform

**Date:** September 3, 2026  
**Reviewers:** two Fable-class specialist agents (graphic/UI design; UX and information architecture), two Opus auditors (accessibility and performance; consistency and content), three explorers, one evidence agent, one benchmark agent — orchestrated by Claude Code  
**Branch:** claude/ui-ux-opus-review-sxcoai  
**Build reviewed:** 4.36.1 (`netpath/web/static/*`, `netpath/web/server.py`, `netpath/theme.py`)  
**Companion:** HTML artifact with the 63 captures, wireframes and three visual directions — https://claude.ai/code/artifact/2f796a44-d79d-447b-890a-c3f0f7d1c4f7 (private to the account that ran the review; share from the page).

---

## Executive summary

SappiWhere has a coherent visual idea — quiet dark instrument chrome, monospace for figures, colour reserved for data — and real strengths to build on: one table grammar across twelve modules, a token file with written rationale, visible splitters, hatch textures where colour is not enough, and long-form copy that names consequences honestly. It lacks the system between those parts. One grey is asked to be prose, decoration and data at once and fails contrast as prose everywhere. The accent means “click me” on one page and “traceroute event” on the next. Nothing has a URL; Back does nothing; sub-tab, sort and filter state die on reload. Outcomes are reported five different ways or not at all, and a stalled server is indistinguishable from a healthy one. Rows cannot be reached from the keyboard. The first screen after every sign-in is a placeholder sentence.

Three defects, each reproduced in the seeded instance, need fixing before anything else: any account without NetFlow read gets a dead page because the module init loop is unguarded (UX-031); Add device accepts `999.999.1.oops` and fails silently on a blank address (UX-014); the forced password change can be dismissed with Escape and no API route enforces it (UX-028).

**Totals:** 114 findings — 11 critical, 37 high, 62 medium, 4 low — grouped into 15 themes and three phases. Effort scale: S ≤ 0.5 day, M 1–3 days, L > 3 days or > 10 files.

### Scorecard (1–5)

| Axis | Score | Note |
|---|---|---|
| Visual hierarchy & typography | 2 | Pane titles are the smallest text on the page; eleven font sizes and no scale; modal darker than the page. |
| Colour system | 3 | Good hues with written rationale; one grey doing three jobs; semantic tokens overloaded; charts colour-only. |
| Components | 2 | Tables are one grammar (a real strength); panels ×4, dots ×4, modals ×3, no focus, empty, loading or toast primitives. |
| Charts | 2 | Axis hysteresis and hatch textures are right; no legends, unvalidated palette, invisible donut slices. |
| Information architecture & navigation | 2 | Twelve flat tabs, settings in three places, no URL state, three home rules, Debug a peer of Nodes. |
| Task efficiency | 2 | T4 and T6 are fine; T1, T2, T3 and T8 take 6–17 steps with retyping across tabs. |
| Feedback & safety | 2 | confirmDestructive and honest maintenance copy are excellent; silent Saves, Escape-discards, invisible hung server. |
| Forms & permissions | 2 | No validation, no Enter, three “unset” conventions; gating hides some controls and lets others 403 silently. |
| Accessibility | 1 | Rows unreachable, no focus indicator, no dialog semantics, no live regions, colour-only status. |
| Responsiveness & density | 2 | Zero media queries; the tab bar breaks at 1549 px; height density modes are a genuine plus. |
| Performance | 3 | Fast on loopback and the Nodes table is diffed; 642 KB uncompressed and parser-blocking on every reload. |
| Content & copy | 3 | Long-form copy is among the best in the category; labels leak enums, times lack zone and day, five nouns for one concept. |

### If you only do twelve things

1. **[S1] Any account without NetFlow read throws at start-up and the page init loop has no isolation** (UX-031) — A (S): Guard `App.state.dimensions || []` in netflow.js:668; wrap each `page.init()` in try/catch that logs and continues; move `restartTimer()` before the init loop. today; C with the loader work.
2. **[S1] Core interactions are mouse-only: rows are not focusable, the modal has no focus trap, there are no shortcuts** (UX-035) — A (S): `tabindex="0"` + `role="row"`/`aria-selected` on clickable rows in `drawRows`/`drawTable`; ↑↓ move selection, Enter opens, Space ticks; modal: `role="dialog"`, `aria-modal`, trap Tab, return focus on close (copy the `#help` implementation). immediately (level-A conformance), B in the same quarter.
3. **[S1] Add device: 25-field modal, silent submit failure, no IP validation, Enter never submits, Escape discards** (UX-014) — B (M): A plus a two-step form (Address & profile → Overrides, all optional), one "unset" convention (UX-020), and a dirty-form guard on Escape/backdrop (UX-024). .
4. **[S1] Forced password change is dismissible; default credentials are not surfaced; password rules appear only in the modal** (UX-028) — B (M): A plus a dedicated `/change-password` page (like `/login`) instead of a modal over a live app, and login-page copy "First run? Sign in with admin / admin — you will be asked to set a new password" shown only while the default password is still in force. .
5. **[S1] Status and severity are encoded by colour alone in the histograms, the timeline lanes and the donuts** (UI-004) — B (M): A shared `App.statusGlyph(status)` returning `● ▲ ■ ○ ✕` + word, used by Nodes/Wireless/ConfigRX/IPAM/alerts detail; histogram legend with the same glyphs; the status strip labels its current segment with the word and duration. the glyph set is cheap, reads on a wall, and survives a screenshot.
6. **[S2] `--faint` is a text colour that fails AA on every surface it sits on** (UI-001) — B (M): Split the token: `--text-3: #737E8C` for tertiary prose/axis text; keep `--faint` (#4C5561) strictly for non-text marks (dividers, grips, inactive dots, "no data" fills). Recolour `.hint`, `.conn`, `.legend`, `.took`, `.usage`, `.host`, SVG axis fills to `--text-3`. it fixes the failure and stops the same token from being reused for prose again.
7. **[S2] No visible focus indicator anywhere in the app** (UI-002) — A (S): One rule: `:where(button, [role=tab], a, input, select, textarea, [tabindex]):focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }` with `--focus: #9EC1FF` (9.6:1 on panel, 3:1+ against every surface and against `--accent` fills). Remove `outline: none` at `app.css:253`. it is a one-rule fix for a level-AA failure; B and C become the direction-2 and direction-3 backlogs.
8. **[S2] Nothing is addressable: no URL routing for tab, sub-tab, entity or filter** (UX-002) — B (M): A small router in `app.js` (`route()`/`navigate()`) with a per-module `state→URL` and `URL→state` pair: `#/nodes/devices/17/interfaces?q=core&status=down`, `#/alerts?state=open&sev=2`, `#/syslog?host=core-sw-1&win=24h&live=1`; `App.selectTab` becomes `App.navigate`; NetFlow→NetPath jump becomes a real link. hash routes need no server change and unlock UX-001, UX-011, UX-013 and the filter bar.
9. **[S2] The post-login home is an empty placeholder** (UX-001) — B (M): Build the overview in wf-dashboard.svg from existing endpoints only: open alerts by severity (`/api/alerts` + `severities`), device up/down/auth counts (`/api/nodes/devices`), collector states (`/api/state`), IPAM conflicts, recent device/config events; each tile deep-links with the filter in the URL (depends on UX-002). it is the single highest-leverage change for P1 and needs no new data sources.
10. **[S2] No notification primitive: outcomes are reported five different ways or not at all** (UX-016) — B (M): A plus a shared async-job watcher (generalise configrx.js:716-775) for Poll now / Trace now / Scan now / Back up so buttons show queued → running and a toast reports the outcome. .
11. **[S2] Most Saves have no error path: a refused write leaves the dialog open and mute** (UX-018) — A (S): Wrap the primary `onClick` in `App.modal` itself: if the handler rejects, render `error.message` into a `#modal-error` line, re-enable the button, keep the dialog — one change covers every dialog. it is the smallest change with the widest reach in this review.
12. **[S2] Cross-module links are missing where the data already carries the key** (UX-011) — A (S): Make `entity_label` a `.linkish` button when `entity_kind === 'device'` that calls `App.selectTab('nodes')` and `selectDevice(entity_id)`; add "Syslog ↗ / Traps ↗" buttons in the alert detail bar that set the target tab's Source/Host filter and refresh; ConfigRX device name → Nodes device; Debug destination → NetPath target. this sprint, B with routing.

---

## What works — preserve it

- **The dark palette and its written rationale** (`app.css:1-43`) — Every `--text`-on-surface pair is 12–14.6:1; the hues are distinct and pleasant. Re-step what the validator flags; keep the character.
- **One table grammar across twelve modules** (`app.js:692-872`) — `App.grid` + `drawRows` + `sortRows` + a real indeterminate select-all; column descriptors make hiding a column safe. Rare and valuable.
- **`confirmDestructive`** (`app.js:494-521`) — Disables against double submission, awaits, keeps the dialog open with the reason on failure, passes `confirmed` to the parent. The model for the seven hand-rolled confirms.
- **The help panel’s focus handling** (`app.js:446-476`) — `role=dialog`, `aria-modal`, focus to Close, focus returned to the “?” that opened it, Escape peels one layer. The main modal should adopt exactly this.
- **ConfigRX’s Back-up-now state machine** (`configrx.js:716-775`) — Queueing → Queued → Backing up → the real outcome, bounded by a deadline and driven by observed server state. The template for a shared job watcher.
- **Nodes status column: dot + word** (`nodes.js:132-137`) — Already the correct redundant encoding; make it the rule everywhere state is drawn.
- **NetPath hatch and bar textures** (`netpath.js:871-909`) — The one place status survives greyscale. Extend, do not replace.
- **Debug’s empty states** (`debug.js:144,168,193,218`) — “Nothing pending — every known address is already named or not due for a re-check.” Each says what nothing means.
- **The maintenance and SSH copy** (`settings.js:231-268; ssh.html:54-63`) — “This is not a prune of old rows — it empties the flow database entirely, including today’s.” Dry, precise, names what survives. Keep verbatim.
- **Height-based density modes and visible splitters** (`app.css:657-777`) — `compact` and `tiny` are why 1366×768 is usable; the divider rationale (“a handle nobody can see might as well not exist”) is right.
- **Nodes row-diffing and axis hysteresis** (`nodes.js:191-305, 726-743`) — Selection survives a refresh and live charts do not breathe. Extend the diffing to the other tables.
- **MAC-search result language** (`nodes.js:3285-3350`) — “…last seen on core-sw-1 · Gi1/0/7 (VLAN 204) at … (2 d ago)”. Fold into the global search unchanged.

---

## Nine defects, each reproduced

| Capture | Defect | Detail |
|---|---|---|
| `limited-user-tabs` | A limited account gets a dead application | With read on Nodes and Syslog only, `/api/state` omits the NetFlow `dimensions` key; `netflow.js:668` iterates it, throws, and `App.start()` never reaches `selectTab()` or the poll timer. The page paints from the first-paint CSS and never updates. (UX-031) |
| `modal-edit-invalid-before` | Add device accepts `999.999.1.oops` | There is no IP validation client- or server-side; a blank IP returns silently; Enter does not submit; Escape discards the form. (UX-014, CONS-007) |
| `login-mustchange-escaped` | The forced password change is a suggestion | The modal hides Cancel but is not locked: Escape or a backdrop click dismisses it, it re-prompts only on reload, and no API route checks `must_change`. The stated guarantee in FEATURES.md is false. (UX-028) |
| `settings-usage-meters` | Every storage meter renders empty | `.usage .bar` inherits the toolbar’s `padding: 8px 12px`; under `box-sizing: border-box` a 6 px-high element has a 0 px content box, so the fill is 0 px tall. Width is computed correctly and never seen. (UI-012) |
| `firstpaint-flash-wireless` | Wireless and ConfigRX paint a blank page on reload | The first-paint rules in `app.css:194-219` list ten tabs; the product has twelve. Until 537 KB of scripts run, no page is displayed and no tab is underlined. (UI-013) |
| `settings-maintenance-row-1366` | Nine buttons in a row that cannot wrap | At 1366 px every Maintenance label wraps to two lines; the row squashes rather than clips. (UI-014) |
| `v-tabs-overflow-1548` | Below 1549 px the tab bar loses Sign out | The bar never wraps or overflows; the connection indicator, Account and Sign out are pushed off-screen. At 200 % zoom the same happens on any laptop. (UI-003, UX-004) |
| `focus-walk` | Twelve presses of Tab, no visible focus | Inputs set `outline: none`; buttons rely on Chromium’s ring, measured at 1.01:1 against the background. No row is ever reached. (UI-002, UX-035) |
| `api-error-corner-sigstop` | A stalled server looks healthy | With the server process paused, requests hang rather than fail; nothing on screen changes. The corner indicator is empty when healthy and shows a raw `Failed to fetch` when not. (UX-017) |

---

## Findings by theme

Severity rubric: **S1** blocks a core task, destroys work or fails WCAG 2.2 A · **S2** workaround-only, real error risk or fails AA · **S3** repeated friction a daily user notices · **S4** polish. Each finding carried three costed options (S/M/L) in the reviewers’ reports; the recommended one is shown. Capture names refer to the evidence pack in the companion artifact.

### Defects to fix this week  
*Phase 0 · effort S each · 3 S1, 2 S2, 6 S3*

**Recommended move.** Ship the one-line fixes: guard each module init (and the missing `dimensions` key) so a limited account gets a working app; validate the IP field and report blank/invalid inline; lock the forced-password modal and gate the API on `must_change`; reset the `.usage .bar` padding; generate the first-paint rules for all twelve tabs; wrap the Maintenance row; give the DHCP status column room; label the five missing Debug categories.

**Why.** Each is reproducible in a capture, each is under half a day, and three of them are the difference between a working product and a dead page for the very accounts an administrator creates first.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| UX-014 | S1 | Add device: 25-field modal, silent submit failure, no IP validation, Enter never submits, Escape discards | `nodes.js:1767-1830 (deviceForm)` | B (M): A plus a two-step form (Address & profile → Overrides, all optional), one "unset" convention (UX-020), and a dirty-form guard on Escape/backdrop (UX-024). . |
| UX-028 | S1 | Forced password change is dismissible; default credentials are not surfaced; password rules appear only in the modal | `app.js:36-44 (accountModal(forced) hides Cancel only)` | B (M): A plus a dedicated `/change-password` page (like `/login`) instead of a modal over a live app, and login-page copy "First run? Sign in with admin / admin — you will be asked to set a new password" shown only while the default password is still in force. . |
| UX-031 | S1 | Any account without NetFlow read throws at start-up and the page init loop has no isolation | `netflow.js:668 (unguarded `for … of App.state.dimensions`)` | A (S): Guard `App.state.dimensions || []` in netflow.js:668; wrap each `page.init()` in try/catch that logs and continues; move `restartTimer()` before the init loop. today; C with the loader work. |
| CONS-007 | S2 | Validation failure speaks through four different channels, five of them silent | ``nodes.js:1943`` | B (M): A + shape validation on IP/CIDR/port/hostname fields, client and server, with the rule stated in the placeholder. A alone tells the user nothing is wrong with `999.999.1.oops`, because as far as the app is concerned nothing is. |
| CONS-018 | S2 | The login page hides the one thing a first-run administrator needs | ``login.js:31`` | B (M): A + surface the throttle on the second consecutive failure (`Repeated failures are slowed down deliberately. Wait a few seconds.`) with no countdown, and state the full password rule in the Account modal. A leaves the throttle invisible, which is the part that produces repeated wrong behaviour. |
| CONS-013 | S3 | The Debug page shows five of its eleven event categories as raw keys | ``debug.js:3-6`` | B (M): A + move `CATEGORY_LABEL` server-side so `/api/state` ships `{key, label, colour}` and the two lists cannot drift again. A fixes today's gap; B is the reason it will not recur, and this exact drift already happened five times. |
| UI-012 | S3 | The Settings usage meters can never show a fill | `netpath/web/static/app.css:277` | A (S): Rename to `.meter`/`.meter__fill`, `padding: 0`, track `#2A323D`, fill `--accent`, 8 px tall, `border-radius: 4px`; keep the `warn/full` colour switches. . |
| UI-013 | S3 | Wireless and ConfigRX paint an empty page on every reload | `netpath/web/static/app.css:194-219` | B (M): Replace the twelve-way list with one attribute-driven pair: `html[data-tab] .tab[data-tab]` cannot match "same value", so instead have `boot.js` set `class="active"` on the matching tab/page synchronously, and keep one generic rule. it removes the class of bug, not the instance. |
| UI-014 | S3 | The nine-button Maintenance row squashes every label into two lines at 1366 px | `netpath/web/static/index.html:938-948` | B (M): A definition-list layout: one row per data set ("Syslog · 1.5 MB · [Delete]") merging the meters from UI-012 with their delete action. the meter and the delete button describe the same object. |
| UI-031 | S3 | The IPAM DHCP server error wraps one word per line in a 60 px column | `netpath/web/static/index.html:603` | A (S): Give the status span `flex: 1 1 auto; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis` and a `title`. . |
| UX-032 | S3 | Sign-in throttle is invisible; the 12 h ceiling and the fixed 60 s idle warning are unexplained | `auth.py:263-305` | A (S): Login: "Too many attempts — try again in Ns" from the throttle's `delay_for`; state payload: include `session_expires_ts`, show the same banner 5 min before the ceiling ("Session ends at 06:12 — sign in again to continue"). . |

### Keyboard reach and visible focus  
*Phase 0 · effort S now, M in foundation · 7 S1, 3 S2*

**Recommended move.** Add `:focus-visible` rings (2 px `#9EC1FF`, offset 2) to every control; make table rows `tabindex=0` with Enter/Space to select and arrow keys to move; give the main modal `role=dialog`, `aria-modal`, a focus trap and focus return, exactly as the help panel already does; name the eight icon-only buttons; announce status changes through one `aria-live` region.

**Why.** WCAG 2.1.1 and 2.4.7 are level A/AA failures on every list tab today; the fix reuses patterns the app already ships in `App.showHelp`.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| A11Y-001 | S1 | Table rows, splitters, grips and the timeline are mouse-only | ``app.js:858-872`` | B (M): A, plus arrow-key resize on focused splitters and grips and a visible "Clear pin" button on NetPath. A alone leaves the three drag interactions unreachable, and B is still one shared change plus two localised ones. |
| A11Y-002 | S1 | Every refresh destroys keyboard focus and the user's text selection | ``app.js:794-796`` | B (M): Stop replacing the `<tbody>` — patch the live one — and make `App.grid` rebuild `<thead>` only when the column set changes (it already computes a `columnsKey` for exactly this in `nodes.js`). it removes the cause rather than papering over it, and `App.grid` is one function shared by every table. |
| A11Y-003 | S1 | 59 row checkboxes have no accessible name | ``nodes.js:130-131`` | B (M): A, plus wrap each box in a 24 × 24 px `<label>` so the name and the target size are fixed together. the size and the name are the same defect in the same markup and should be fixed once. |
| A11Y-004 | S1 | The main modal is not a dialog | ``index.html:960`` | B (M): A, plus a focus trap and `inert` on `#tabs` and the active `section.page` while the modal is open. it reaches conformance without rewriting 30 call sites, and the help panel proves the pattern works in this codebase. |
| A11Y-005 | S1 | No landmark, no heading level 1, no skip link, tabs are not a tablist | ``index.html:19-38`` | B (M): A, plus wrap the page container in `<main id="content">` and give each `section.page` an `aria-labelledby` pointing at its new `<h1>`. A without a main landmark leaves the skip link with nowhere to skip to. |
| A11Y-006 | S1 | There is no visible focus indicator | ``app.css:253`` | A (S): One rule — `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px }` — and delete the `outline: none`. a single rule clears a Level A failure across the entire product; B is worth doing but is polish on top. |
| UX-035 | S1 | Core interactions are mouse-only: rows are not focusable, the modal has no focus trap, there are no shortcuts | `nodes.js:287-294 (`tr.onclick`/`ondblclick` only)` | A (S): `tabindex="0"` + `role="row"`/`aria-selected` on clickable rows in `drawRows`/`drawTable`; ↑↓ move selection, Enter opens, Space ticks; modal: `role="dialog"`, `aria-modal`, trap Tab, return focus on close (copy the `#help` implementation). immediately (level-A conformance), B in the same quarter. |
| A11Y-013 | S2 | Labels: 63 hard-coded capitals and ten punctuation-glyph button names | ``index.html:315-316`` | B (M): A, plus move the capitals to `text-transform: uppercase` on `.section`, `.tab` and `.subtab` and write the markup in sentence case. A alone leaves the capitals, and the capitals are the part that affects every tab. |
| A11Y-014 | S2 | Chart tooltips are hover-only and unreachable | ``app.js:341-376`` | B (M): A, plus make each histogram bar a focusable element with an `aria-label` carrying the same text, so the data is available without the tooltip at all. it fixes 1.4.13 and 1.1.1 together and puts the numbers somewhere they can be read. |
| UI-002 | S2 | No visible focus indicator anywhere in the app | `netpath/web/static/app.css:253` | A (S): One rule: `:where(button, [role=tab], a, input, select, textarea, [tabindex]):focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }` with `--focus: #9EC1FF` (9.6:1 on panel, 3:1+ against every surface and against `--accent` fills). Remove `outline: none` at `app.css:253`. it is a one-rule fix for a level-AA failure; B and C become the direction-2 and direction-3 backlogs. |

### Status carried by colour alone  
*Phase 0 · effort S–M · 1 S1, 3 S2, 3 S3*

**Recommended move.** Adopt the rule the Nodes status column already follows: glyph + colour + word, everywhere a dot, band or slice encodes state. Swap the NetFlow series set for the validated eight-colour palette; give histograms a legend and collapse to four bands; draw the IPAM remainder in a visible neutral; show the severity name, not a digit; colour the badge by worst severity.

**Why.** The ok/warn/fail triad is inseparable for protan viewers (measured ΔE 3.8) and vanishes in a greyscale screenshot pasted into a ticket.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| UI-004 | S1 | Status and severity are encoded by colour alone in the histograms, the timeline lanes and the donuts | `netpath/web/static/alerts.js:4-5` | B (M): A shared `App.statusGlyph(status)` returning `● ▲ ■ ○ ✕` + word, used by Nodes/Wireless/ConfigRX/IPAM/alerts detail; histogram legend with the same glyphs; the status strip labels its current segment with the word and duration. the glyph set is cheap, reads on a wall, and survives a screenshot. |
| A11Y-008 | S2 | Selection and route state are signalled by a 1.2–1.4:1 tint alone | ``app.css:504`` | A (S): Add a 2 px `--accent` left border on the selected row (on the `<tr>`, not per cell — the comment at `app.css:505-511` explains why the earlier per-cell attempt failed) and `aria-selected="true"`. the selected row is the state operators depend on most and it is currently invisible; B follows once the UI agent has settled the chart language. |
| CONS-011 | S2 | Severity is shown three different ways in three tables | ``alerts.js:144-145`` | A (S): Alerts renders `${severity_name}` in a 90 px `Severity` column, sorting on the digit; retire the hidden duplicate column. the name is already in the payload and already rendered two lines away in the detail pane. |
| UI-005 | S2 | The NetFlow ten-colour series palette is not colour-blind safe and the legend silently drops series | `netpath/web/static/netflow.js:4-6` | A (S): Replace `SERIES` with the validated 8-slot re-step of the same hue order — `#5B8DEB, #CF7638, #2FA886, #B0881A, #D1609A, #4F9A3A, #8F76E8, #DC5A5A` (all five checks PASS on `#151A21`: CVD ΔE 10.2, normal 16.2, ≥ 3:1) — fold slots 9+ into "Other" (`OTHER` stays `--faint`), drop `fill-opacity` to 1 with a 1 px `--panel` stroke between bands. , then B — the palette swap is a six-line change with a measured result. |
| UI-010 | S3 | The IPAM donuts draw "available / never seen" in `--hairline`, which is invisible on the panel | `netpath/web/static/ipam.js:74` | A (S): Use `--data-neutral: #3A4552` (1.7:1 as a *fill* is fine — it is a shape, not text) for the remainder slice, add `stroke-dasharray` gaps of 2 px between slices, and put the headroom percentage in the donut centre in `--text` 14 px 700 mono. now; B is the direction-2 version. |
| UI-011 | S3 | The three severity histograms stack a near-white band and have no legend or axis title | `netpath/web/static/alerts.js:4-5` | A (S): Collapse to four stacked bands — *critical* (0–2, `--fail`), *error* (3, `--sev-3`), *warning* (4, `--warn`), *info* (5–7, `--data-neutral`) — with a four-item legend in the title bar, `fill-opacity` 1 and a 1 px panel gap between stacked segments. + B. |
| UI-032 | S3 | The badge is always amber, whatever the worst open severity is | `netpath/web/static/app.css:157-163` | A (S): `.badge[data-sev="1"]` → `--fail` with `--text` numerals (5.6:1), `data-sev="3"` → `--sev-3`, else neutral `--raised` border + `--text`; the API already returns per-severity counts to the histogram. . |

### Text that cannot be read at 11 px on dark  
*Phase 1 · effort M · 2 S2, 7 S3*

**Recommended move.** Split `--faint` into a text tone (`#737E8C`, 4.2:1 on panel) and a non-text tone; raise `th` to `--text-2`; floor hints at 12 px; adopt the six-step rem scale (11/12/13/14/16/20) with three weights; put a real title on every page and pane; use `--ui` for prose inside tables and `--mono` for figures only; add a wall density that scales the whole scale up.

**Why.** 39 of 135 rendered text pairs fail AA; 31 of them are one token doing three jobs.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| A11Y-007 | S2 | `--faint` is used as a text colour and fails contrast everywhere | ``app.css:264`` | A (S): Retire `--faint` as a text colour (keep it for hairlines): point `.hint` at `--muted`, and lift `--muted` from `#7C8794` to about `#8B96A4` so `th` on `--raised` clears 4.5:1. it is a two-line change that clears the great majority of the 39 failures; the UI agent owns whether the hierarchy needs rebuilding. |
| UI-001 | S2 | `--faint` is a text colour that fails AA on every surface it sits on | `netpath/web/static/app.css:12` | B (M): Split the token: `--text-3: #737E8C` for tertiary prose/axis text; keep `--faint` (#4C5561) strictly for non-text marks (dividers, grips, inactive dots, "no data" fills). Recolour `.hint`, `.conn`, `.legend`, `.took`, `.usage`, `.host`, SVG axis fills to `--text-3`. it fixes the failure and stops the same token from being reused for prose again. |
| UI-006 | S3 | Eleven font sizes, five letter-spacings and no type scale | `netpath/web/static/app.css:78` | B (M): A plus `html { font-size: 13px }` and every size in `rem`, so `body.compact`/`tiny`/a future `wall` mode scale the whole UI from one number. it is the change that makes UI-026 (wallboard mode) a one-liner later. |
| UI-015 | S3 | Everything in a table is monospace, including prose | `netpath/web/static/app.css:490` | A (S): `td { font-family: var(--ui) }` by default; `td.mono` for columns flagged `mono: true` in each module's `COLUMNS` (IP, MAC, time, counts, OIDs). + B. |
| UI-016 | S3 | Three stacked bars consume 150 px before any data, and the page has no title | `netpath/web/static/index.html:51-100` | B (M): Merge the strip and the filter bar into one 48 px header row (title · state pill · KPI chips · actions) and keep sub-tabs as a segmented control, as mock-dir2 — saves ~50 px. . |
| UI-020 | S3 | The NetPath route canvas is a white rectangle in a dark app, and its 10 px grey labels fail on white | `netpath/web/static/netpath.js:437-440` | A (S): `--canvas-faint → #5F6B79` (5.4:1 on white, 5.0:1 on canvas-panel); hop eyebrow 11 px; add `--canvas-blocked: #C2410C`. now, B as part of direction 3. |
| UI-026 | S3 | Wallboard legibility: 12 px mono and 11 px hints at three metres | `netpath/web/static/app.css:755-777` | A (S): `body.wall` class (toggle in Account menu, persisted) that sets `html { font-size: 16px }` once UI-006 B is in, 32 px rows, 12 px status dots, hides hints. + B. |
| UI-029 | S3 | Table headers, grips and carets are below contrast and below size | `netpath/web/static/app.css:491-500` | A (S): `th { color: #94A0AE }` (6.0:1 on raised), `.sort-caret { font-size: 10px }`, grip tick `#3A4552` → 1.7:1 at rest is a *decoration*, so show it at 3:1 (`#4C5561` on `--raised` is 2.1 — use `#5A6573`, 2.6) only on `th:hover`, and full `--accent` on drag. . |
| UI-034 | S3 | Pane titles are the smallest text on the page, and headings invert across pages | `netpath/web/static/app.css:259-263` | A (S): Style `h2` (page title 16 px 700) and `h3` (pane title 13 px 600 sentence case) explicitly; keep the eyebrow as a *secondary* label under the pane title where a pane has both a name and a summary. + B. |

### Feedback: outcomes, errors, a hung server  
*Phase 1 · effort M · 7 S2, 4 S3*

**Recommended move.** Add three primitives — a toast region (`aria-live=polite`, Undo where the server allows), an inline field error, and a job watcher generalised from ConfigRX’s Back-up-now state machine. Wrap every primary modal action in one try/catch inside `App.modal` so a refused Save says why. Make `#conn` a health chip that shows data age and turns amber after two missed polls. Say “300 of 2,425”, never “300 shown”. Render every empty state in one component with a why and a next step.

**Why.** Today outcomes are reported five different ways or not at all, and a stalled server is indistinguishable from a healthy one (Nielsen 1 and 9, both rated 4).

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| A11Y-011 | S2 | Nothing is announced: the whole product has no live region | ``app.js:130-134`` | A (S): One `<div role="status" aria-live="polite">` in the chrome plus an `App.announce(text)` helper; wire `connected()` and the idle banner to it. it clears the AA failure in one file and gives the UX agent's toast work a hook to plug into. |
| CONS-006 | S2 | A failed Save is indistinguishable from a successful one | ``app.js:398`` | A (S): Wrap `spec.onClick` in try/catch inside `modal()` and render `error.message` into a standard `<p class="err" role="alert">` appended to the modal body. one function in one file removes the whole class of silent failures. |
| CONS-010 | S2 | Row counts never say what they are out of | ``syslog.js:379`` | B (M): A + return the total from the six list endpoints and colour the count `--warn` when the cap is hit. the honest number is the whole point, and colouring the cap is what converts it from a fact into a warning. |
| PERF-008 | S2 | Two tabs paint blank, and nothing anywhere says "loading" | ``app.css:194-219`` | B (M): A, plus a shared skeleton/loading state applied by `App.grid` on first draw and while a refresh is in flight beyond ~400 ms. the missing selectors are trivial, but the absent stale-data signal is the part that can mislead an operator during an incident. |
| UX-016 | S2 | No notification primitive: outcomes are reported five different ways or not at all | `nodes.js:352-388 (settle() label mutation, 3 s)` | B (M): A plus a shared async-job watcher (generalise configrx.js:716-775) for Poll now / Trace now / Scan now / Back up so buttons show queued → running and a toast reports the outcome. . |
| UX-017 | S2 | Connection health: raw fetch error in the corner, and a stalled server looks healthy | `app.js:130-134 (connected() writes `error.message` verbatim)` | B (M): A plus a health dot in the chrome (green/amber/red with tooltip "last update 4 s ago"), per-module "updated N s ago" in each strip, and a stale overlay on charts older than 3× their refresh. . |
| UX-018 | S2 | Most Saves have no error path: a refused write leaves the dialog open and mute | `alerts.js:493-498 (editRule Save)` | A (S): Wrap the primary `onClick` in `App.modal` itself: if the handler rejects, render `error.message` into a `#modal-error` line, re-enable the button, keep the dialog — one change covers every dialog. it is the smallest change with the widest reach in this review. |
| CONS-012 | S3 | Empty states are rendered seven ways in four type sizes | ``netflow.js:146-148`` | B (M): A + rewrite the 25 strings to the two-part house pattern *(what is empty) + (what changes it)*, modelled on `nodes.js:1600` and `debug.js:144`. the rendering fix without the wording fix leaves five dead ends. |
| CONS-017 | S3 | Button labels change meaning by state, and one toggle never names its other half | ``nodes.js:2566-2567`` | B (M): A + one `App.buttonProgress(button, {busy, done, revertMs})` adopted by the six long actions, modelled on `configrx.js:731-767`. ConfigRX's state machine is already the right answer written once; the work is generalising it. |
| UI-023 | S3 | Errors are raw exception strings in the top-right corner; there are no empty, loading or toast primitives | `netpath/web/static/index.html:37` | A (S): One `.empty` block (icon glyph 20 px `--faint`, 13 px `--muted` title, 12 px `--text-3` hint, centred in the pane) and one `.status-pill` for `#conn` (`● Live` / `● Reconnecting…` / `● Offline 12 s`) with a fixed 110 px width so it never wraps. + B. |
| UX-019 | S3 | No loading states; "N shown" without "of M"; 2 001 rows in one table | `index.html:456-461` | A (S): Render "300 of 2,425 · next 300 →" in one place per table (the filter bar's count slot) and disable the primary while a fetch is in flight. now, B with the filter bar. |

### One dialog contract: submit, discard, confirm  
*Phase 1 · effort M · 3 S2, 4 S3*

**Recommended move.** Make `App.modal` render a `<form>` so Enter submits; track dirty state and ask “Discard changes?” on Escape or backdrop when a field changed; migrate the seven hand-rolled confirms to `confirmDestructive`; stack confirms above their parent instead of replacing it; move Remove out of Edit into the object’s action row; make Preview render without saving; lift the modal to the raised surface with a shadow so elevation reads correctly.

**Why.** Five confirms can report success on failure and a stray Escape discards a 25-field form. The good helper exists; the work is adoption.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| CONS-005 | S2 | Destructive confirmation is split between a good helper and seven hand-rolled copies | ``nodes.js:470-481`` | B (M): A + strengthen the three thinnest bodies (`alerts.js:550`, `netpath.js:307`, `settings.js:374`) to name survivors and irreversibility, per §2.6. the helper already exists and is correct; the work is adopting it and bringing three messages up to the standard of the other fifteen. |
| UX-024 | S2 | Escape, backdrop click and nested confirms discard unsaved edits without asking | `app.js:407-415 (closeModal)` | B (M): A plus a second dialog layer for confirms (like `#help` already is) so a confirm never replaces its parent and no reopen-from-server is needed. . |
| UX-025 | S2 | Five hand-rolled confirms close before the request completes, so a failed delete reports success | `nodes.js:460-482 (bulkDeleteDevices: closeModal then `await App.post`, no catch)` | A (S): Replace the five with `App.confirmDestructive` calls (same copy, same buttons). . |
| UI-018 | S3 | The modal is the darkest surface on screen, so elevation is inverted | `netpath/web/static/app.css:819-828` | A (S): `.modal-box { background: var(--raised); box-shadow: var(--shadow-3) }` and `.modal-box fieldset { background: var(--panel) }` (a darker inset inside a lighter dialog reads as a well). . |
| UX-023 | S3 | Enter never submits a dialog; first field is focused but the form has no submit semantics | `app.js:385-405 (modal builds buttons with `onclick`, no `<form>`)` | A (S): In `App.modal`, wrap the body in `<form>` and treat `submit` as the primary button's click; `type="button"` on the non-primary buttons. now, C as the bundle. |
| UX-026 | S3 | Confirm-from-dialog destroys the parent's edits (Clear credential, Remove credential, Reset template) | `alerts.js:583-590` | B (M): Second dialog layer (UX-024 B) so the confirm stacks over the form. (shared with UX-024). |
| UX-027 | S3 | Remove device hidden inside Edit; Preview saves the template silently | `nodes.js:1985 (Remove added to the Edit dialog's button row)` | B (M): Preview endpoint accepts the draft body (`POST /templates/{id}/preview {subject, body}`) so Preview stops writing. for Preview, A for Remove. |

### Forms, defaults and help  
*Phase 1 · effort M · 1 S2, 8 S3*

**Recommended move.** One “inherit from profile” convention (a select option that names the inherited value); a two-step Add device (address, then profile) with everything else under Advanced; human names and pickers instead of raw enums in Add rule; move any hint over 40 words behind a `?` using the existing help panel; expand sixteen acronyms once per surface; give Users role presets (Viewer, Operator, Admin) above the 12×3 grid.

**Why.** The Add device modal is the first task of every administrator and currently fails three ways; the help mechanism is built but used on three settings.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| A11Y-015 | S2 | Validation is silent and there is no error identification | ``nodes.js:1943`` | B (M): A, plus client-side IP/CIDR validation with a named message and focus moved to the offending field. A leaves the invalid-IP defect intact, and that one silently breaks polling. |
| A11Y-016 | S3 | Controls change context or global state on input | ``nodes.js:3464`` | B (M): A, plus move `Resolve names` out of the NetFlow filter bar into the module Settings dialog where server-wide settings live. the server-wide write disguised as a personal filter is the part that surprises people badly. |
| CONS-014 | S3 | Sixteen unexpanded acronyms, and help exists on three settings out of hundreds | ``nodes.js:2394-2492`` | B (M): A + expand in place where the label has room (`AP serial (WTP id)`, `search: scanning (no full-text index)`, `Refused (ICMP unreachable)` as the pattern), and register `?` topics for the eight that cannot be expanded inline. the app already demonstrates the right pattern twice; this is applying it fourteen more times. |
| CONS-015 | S3 | One dialog offers three different words for "not set" | ``nodes.js:1901`` | B (M): A + a small `— inherited (2s) —` form that shows the value being inherited, so the user knows what they are leaving alone. knowing *what* you inherit is the actual question behind the word, and the endpoint already returns it for devices. |
| CONS-016 | S3 | 149 hint paragraphs carry the documentation, eight of them over 70 words | ``alerts.js:730`` | B (M): A + a rule and a lint check: no `.hint` over 40 words; anything longer becomes a help topic. Applies to the 34 over-length paragraphs. the writing is an asset; the fix is where it lives, and a threshold is what stops it drifting back. |
| UX-015 | S3 | T8 grant read-only: a 12×3 radio grid inline on a page that also has a staged Apply | `settings.js:288-311 (permissionGridHtml/readPermissionGrid)` | B (M): Role presets (Viewer = read all, Operator = write on Alerts/Nodes, Admin = write all, Custom) with the grid as the Custom detail; "Copy permissions from …"; a generated initial password with copy button. . |
| UX-020 | S3 | Three "unset" conventions in one form | `nodes.js:1900-1904 (triOptions "(profile)")` | A (S): One word — `inherit` — as the first option/placeholder everywhere, always followed by the effective value: "inherit (v2c)", "inherit (3 probes)"; the profile endpoint already returns these. . |
| UX-021 | S3 | Help is a "?" on three settings; everywhere else it is 11 px prose or a tooltip | `nodes.js:2394-2492 (three help entries registered)` | A (S): Convert every `.hint` paragraph longer than one sentence in a form into a registered help entry with a "?"; keep a one-line hint. . |
| UX-022 | S3 | Add rule exposes raw enums and a free-text "source kind" | `alerts.js:504-546` | A (S): Label the options in plain language ("Device event — down/up/rebooted…"), make Source kind a `<select>` populated per kind from a server list, auto-generate Key from Name. . |

### Permissions: disable with a reason, never hide silently  
*Phase 1 · effort M · 1 S2, 1 S3*

**Recommended move.** Replace hide-only gating with a `data-requires-write` renderer that disables the control and attaches “Needs Nodes write — ask an administrator”; cover the fifteen controls that are not gated at all (NetPath Add/Edit/Remove/Trace, IPAM Add/Edit/Scan/Poll/Mark resolved, Alerts rules, Nodes profiles/MIBs/discovery/bulk); make Settings read-only for readers instead of editable with Apply hidden.

**Why.** A viewer today can open a delete confirm that closes without deleting; the SSH page already shows the right message.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| UX-029 | S2 | Permission gating hides some write controls and leaves others live, which then 403 silently | `index.html:95-98 (bulk buttons without the attribute` | B (M): Change the rule: hide *tabs* you cannot read; *disable* (never hide) write controls inside a readable tab, with a tooltip "Needs Nodes write — ask an admin" (wf-feedback callout D); gate at the `App.modal` primary button too. . |
| UX-030 | S3 | Settings is fully editable for readers, with Apply hidden and Revert visible | `index.html:952-957` | A (S): For readers, set `disabled` on every `#page-settings input, select` and show a one-line banner "You can view these settings. Changing them needs Settings write.". . |

### Addressability: URL state, one home, grouped navigation  
*Phase 2 · effort L · 4 S2, 4 S3*

**Recommended move.** Hash routes for tab, sub-tab, entity and filters (`#/nodes/devices/17/ports/7?win=1h`); sign-in always lands on Overview, reload restores the URL, login preserves `next`; group the twelve tabs as Overview · Observe · Inventory · Admin with a compact bar that fits 1180 px and an overflow menu; module gears open the same settings section a drawer under Admin lists; Debug becomes Admin › System.

**Why.** Nothing is linkable, Back does nothing, sub-tab and filter state die on reload, and the bar loses Sign out below 1549 px. Routing is the dependency for the Dashboard, cross-links and saved filters.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| UI-003 | S2 | The tab bar never wraps or overflows, so the utility items fall off the screen below 1549 px | `netpath/web/static/app.css:63-84` | A (S): `.tab { padding: 10px 14px; letter-spacing: 0.4px }`, move `#version` into the Account menu, let `#tabs` wrap (`flex-wrap: wrap`) with the utility group on its own line when needed. Fits ~1180 px unwrapped. now, B in the design-system pass; the labels do not need 22 px of padding each. |
| UX-001 | S2 | The post-login home is an empty placeholder | `index.html:41-47` | B (M): Build the overview in wf-dashboard.svg from existing endpoints only: open alerts by severity (`/api/alerts` + `severities`), device up/down/auth counts (`/api/nodes/devices`), collector states (`/api/state`), IPAM conflicts, recent device/config events; each tile deep-links with the filter in the URL (depends on UX-002). it is the single highest-leverage change for P1 and needs no new data sources. |
| UX-002 | S2 | Nothing is addressable: no URL routing for tab, sub-tab, entity or filter | `app.js:964-985 (selectTab writes localStorage only)` | B (M): A small router in `app.js` (`route()`/`navigate()`) with a per-module `state→URL` and `URL→state` pair: `#/nodes/devices/17/interfaces?q=core&status=down`, `#/alerts?state=open&sev=2`, `#/syslog?host=core-sw-1&win=24h&live=1`; `App.selectTab` becomes `App.navigate`; NetFlow→NetPath jump becomes a real link. hash routes need no server change and unlock UX-001, UX-011, UX-013 and the filter bar. |
| UX-004 | S2 | Twelve flat tabs with no grouping; utility controls fall off-screen below 1549 px | `index.html:19-38` | B (M): Group the tabs as in §E (Overview · Observe · Inventory · Admin) with the module list as a second row or a hover/click sub-strip; Debug and Settings move under Admin. the grouping is the cheapest way to make twelve modules legible; the rail is a later polish. |
| CONS-019 | S3 | The Dashboard is the landing page, and the documentation describes a different one | ``index.html:43-45`` | A (S): Correct the three documentation statements and the code comment; replace the placeholder text with three links to the tabs a new user should start from. until C exists, the honest fix is to stop claiming otherwise and give the empty page a way out; B swaps one inconsistency for another. |
| UX-003 | S3 | Three different "home" behaviours | `login.js:36-40` | A (S): One rule: `home = Dashboard`; reload restores the *URL* (UX-002), not a separate key; delete the NetPath default. now, C with UX-002. |
| UX-005 | S3 | Module settings live in three places; two refresh rates have no UI; collectors start from a checkbox | `index.html:806-811` | B (M): One settings surface with two entry points: Admin › Settings gets a left index (General · Sign-in · Storage · Users · Update · Maintenance · Modules › Nodes, Alerts, …); each module's strip gear opens the *same* module section in a drawer — one implementation, no drift. . |
| UX-007 | S3 | Debug is a first-class peer of operational modules | `index.html:30` | B (M): A plus a "Health" summary at the top of Debug (the collector table from wf-dashboard callout 4) so the page starts with the answer, not the thread dump; Clear requires Debug *write*. . |

### Cross-module links, the device page and global search  
*Phase 2 · effort L · 3 S2, 2 S3*

**Recommended move.** Alerts → device link today (the `entity_id` is already in the row); a device page whose header answers “up since 03 Sep 09:12 (5 h 20 m) · last poll 4 s ago” and whose tabs pre-filter Alerts, Syslog, Traps, Route and Config to that device; Ctrl+K search that infers IP/MAC/hostname/port and returns grouped results as routes; IPAM opens on Subnets and its search results become links.

**Why.** T1 drops from 6 steps to 3, T2 from up to 9 to 3, T5 from 6 to 2; the MAC-search language already written in Nodes moves into the palette unchanged.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| UX-009 | S2 | T1 "is it up, since when?" is not answered on the device pane | `nodes.js:526-586 (deviceSummaryHtml: IP · status · admin-chosen fields · error — no `since`)` | A (S): Add `since <stamp> (<duration>)` after the status in `deviceSummaryHtml` using the newest status-change event the pane already fetches (`view.events`), and `last poll <ago>`; render event times with `App.stamp(ts, span)` so the day appears when the window exceeds a day. immediately, then C with UX-002/UX-011. |
| UX-010 | S2 | T2 lookup is split across three boxes with three behaviours; no global search | `index.html:70-71` | B (M): A plus typed inference (IPv4/IPv6/CIDR/MAC/port/free text) shown as a chip, keyboard palette semantics (Ctrl+K, `/`, ↑↓, Enter, Esc returns focus), and "actions" rows (`>go nodes`, `>start scan`). the palette also relieves the twelve-tab IA (UX-004) and is the keyboard entry point the app lacks. |
| UX-011 | S2 | Cross-module links are missing where the data already carries the key | `alerts.js:144-147` | A (S): Make `entity_label` a `.linkish` button when `entity_kind === 'device'` that calls `App.selectTab('nodes')` and `selectDevice(entity_id)`; add "Syslog ↗ / Traps ↗" buttons in the alert detail bar that set the target tab's Source/Host filter and refresh; ConfigRX device name → Nodes device; Debug destination → NetPath target. this sprint, B with routing. |
| UI-022 | S3 | The Nodes status strip cannot answer "since when" | `netpath/web/static/nodes.js:806-830` | B (M): A plus "since hh:mm (2h 14m)" in the identity line next to `status`, and the same treatment for NetPath's STATUS lane. . |
| UX-006 | S3 | IPAM opens on the Windows-only DHCP view; search results are a dead-end modal | `index.html:548-552` | A (S): Default to Subnets & Hosts; remember the last IPAM sub-tab (UX-002); make the Source and Subnet cells in the results modal links (`selectSub('subnets')` + select subnet; DHCP lease → scope). now, C with UX-010. |

### One filter bar, one time control, one Live toggle  
*Phase 1 · effort M · 5 S3*

**Recommended move.** A shared filter component: search + Enter, facet selects that apply on change, one time-window control with ‹ − + › and a LIVE toggle that says “paused at 00:29” when a histogram click narrows it, Clear that clears everything, count as “N of M”, state mirrored to the URL. Per-user view choices (resolve names, columns) stop writing server-wide settings.

**Why.** Six bars diverge on four axes at once; the same control has three labels and five shapes.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| CONS-002 | S3 | Filter-bar grammar diverges on four axes at once | ``index.html:80`` | B (M): A + make `Clear` reset every control on its bar including window, limit and live-tail. the label fix is cosmetic; the behaviour fix is what prevents a wrong conclusion. |
| CONS-008 | S3 | Live-tail and time-window controls have three labels and five shapes | ``index.html:335`` | B (M): A + one `timeWindowBar()` component rendering label + select + (optional ‹ − + ›) + Live + Reset, adopted by all six surfaces. labels alone leave the same control in three positions with three affordance sets. |
| CONS-009 | S3 | The Alerts histogram offers a click it does not accept | ``alerts.js:120-130`` | B (M): Attach the SNMP/Syslog click handler to Alerts, narrowing `view.t0/t1` to the bucket and unticking nothing (Alerts has no Live toggle). the behaviour is 8 lines already written twice; the stale-select issue is fixed by showing the window as text beside the select, as NetFlow already does (`index.html:384`). |
| UX-008 | S3 | Per-user-looking controls write server-wide settings | `netflow.js:716-722` | B (M): Make column choice and resolve-names per-browser (`localStorage`, alongside widths) with "Set as server default" for writers. cheap and matches every benchmark product (per-user view state). |
| UX-013 | S3 | T5 filter bars diverge: Apply vs Search, Enter on some tabs, Clear that does not clear, Live that silently unticks | `syslog.js:406-413 (Clear resets text/selects but not window, Live or limit)` | B (M): One `App.filterBar(spec)` component (wf-filterbar.svg): search, facet chips, one time-window control, Live toggle, Clear, result count "N of M", URL sync (UX-002). it is the same work as A done once instead of six times. |

### Tokens and one component set  
*Phase 1 · effort L · 2 S2, 10 S3*

**Recommended move.** Adopt the token tables in this report (surfaces, text tones, semantic rules, spacing, radius, shadow, z-index, focus). One `.panel`, one `.status` glyph component, one three-tier button set with all states, a segmented control for third-level tabs, one modal used by the app, login and SSH pages. `--accent` means interactive only; categories come from `--cat-1…8`; status from ok/warn/fail plus texture.

**Why.** Four panels, four dots, three modals and two competing primaries coexist; the palette is right but is not used as a system.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| A11Y-009 | S2 | Control borders, dividers and grips fail non-text contrast; the grip is a 7 px target | ``app.css:245-247`` | A (S): Move control borders and divider/grip lines to `--muted` (measured 4.39–5.18:1, comfortably over 3:1) and widen `th .grip` to 24 px while keeping the 1 px visible line via `::after`. two rules and a width change clear both SCs. |
| A11Y-012 | S2 | Tables carry no header semantics and no sort state | ``app.js:711-746`` | A (S): In `App.grid`, add `th.scope = 'col'`, `aria-sort` reflecting `sort.key`/`sort.descending`, and wrap the sortable label in a `<button>`. it is confined to one function and fixes all ten tables at once. |
| UI-007 | S3 | Four panel implementations that differ by a few pixels each | `netpath/web/static/app.css:292-297` | B (M): Replace the four with `.panel` + modifiers (`.panel--form`, `.panel--table`, `.panel--chart`), one `.panel__title` eyebrow, and move `legend` out of `<fieldset>` into a real heading so Settings sections look like the rest of the app. . |
| UI-008 | S3 | Four status-dot implementations and a semantic clash in ConfigRX | `netpath/web/static/configrx.js:39-40` | B (M): A plus the glyph set from UI-004 so the dot is never colour-only. . |
| UI-009 | S3 | Semantic colours are overloaded: `--accent`, `--blocked` and `--faint` each mean four things | `netpath/web/static/app.css:598-603` | A (S): Add aliases so intent is at least named: `--sev-3: var(--blocked)` today, `--data-neutral: #3A4552` for "no data/never seen/available", `--cat-1..6` for Debug categories; stop using `--accent` for any static data (Debug trace/ipam → `--cat-*`, ConfigRX unchanged → `--ok`, IPAM reserved → `--cat-2`). . |
| UI-017 | S3 | Two competing "primary" buttons on every strip, and disabled primaries keep their fill | `netpath/web/static/app.css:233` | B (M): Three-tier button set (`.btn`, `.btn--primary`, `.btn--ghost`, plus `.btn--danger` for Delete/Remove confirms) with hover/active/focus/disabled states on tokens; migrate `.linkish` and `.icon`. . |
| UI-019 | S3 | Selection and zebra stripes are one lightness step apart, so the selected row is hard to find | `netpath/web/static/app.css:502-504` | A (S): `tr.selected td { background: var(--checked) }` plus `tr.selected td:first-child { box-shadow: inset 3px 0 0 var(--accent) }` (first cell only, so no stripes at column dividers); ticked+selected → `--checked-strong`. + B. |
| UI-021 | S3 | The timeline lanes have no axes, so two buckets become two giant blue slabs | `netpath/web/static/netpath.js:801-820` | A (S): Two horizontal gridlines with tick labels (0, peak) in `--text-3` 10 px, lane titles 11 px, bars `fill-opacity` 0.7 with 1 px gaps, `niceCeiling(peak)` for the axis instead of raw peak. . |
| UI-024 | S3 | Sub-tabs at three nesting depths look identical | `netpath/web/static/app.css:90-113` | A (S): Level 3 becomes a segmented control (pill group on `--raised`, active pill `--panel`, sentence case 12 px) — see mock-dir2 — distinct from the underlined levels 1–2. + B. |
| UI-030 | S3 | Login and SSH pages have their own type scale and their own modal | `netpath/web/static/app.css:800-808` | A (S): Pick the login label style as *the* form-label token (`.label-eyebrow`) and apply it to modal labels; make `.ssh-panel` an alias of `.modal-box` once UI-018 fixes the modal surface. + B. |
| UI-033 | S3 | The Alerts histogram spends a 90 px full-width strip on five bars in its right quarter | `netpath/web/static/index.html:243` | A (S): Move the histogram into the detail pane's top (it is contextual to the selection) and centre the empty state; or make `.canvas.small` collapsible with the state persisted. . |
| UX-012 | S3 | Discovery has three approval surfaces and a dialog that pops on its own | `nodes.js:2690-2745 (startDiscovery opens a second modal of timing fields before scanning)` | B (M): A plus fold the timing fields into an "Advanced ▸" disclosure on the Discovery bar so Start scans immediately with defaults. . |

### Responsive layout and wallboard density  
*Phase 2 · effort M · 1 S2, 1 S3, 1 S4*

**Recommended move.** One stacking breakpoint (splitters become stacked panes under 1100 px), fluid sidebar, `min-width: min(420px, 92vw)` on modals, pointer events on splitters and grips; a `wall` density that scales the rem base to 16 px and rows to 32 px; `?kiosk=1` strips chrome and keeps the session alive; a `[data-theme=light]` and a high-contrast dark variant priced from the mapping table.

**Why.** There are zero media queries; at 820 px the layout still assumes 1600, and a NOC wallboard is the stated use.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| A11Y-010 | S2 | Zero media queries: the app cannot reflow, and `#conn` disappears at 1366 px | ``app.css` (no `@media`)` | B (M): A, plus three breakpoints (1280 / 1024 / 768) that collapse the pane splitters to a vertical stack and let table wrappers scroll independently. A alone still leaves two-dimensional scrolling at 820 px; B reaches conformance at the widths the personas actually use. |
| UI-025 | S3 | Zero media queries: at 820 px the layout still assumes 1600 | `netpath/web/static/app.css:464-469` | A (S): One `@media (max-width: 1100px)`: `.split, [data-splitter].cols { flex-direction: column }`, `.sidebar { width: auto }`, `.modal-box { min-width: 0; width: calc(100vw - 32px) }`. . |
| UI-035 | S4 | The light-canvas palette has no equivalents for seven chrome tokens | `netpath/web/static/app.css:29-39` | A (S): Add the seven missing `--canvas-*` values (see §C mapping table) even if unused, and generate `theme.py` from `app.css` with a script so the palettes cannot drift. now; B is priced in §C. |

### Time, timezone, names and voice  
*Phase 0 · effort S–M · 1 S2, 4 S3, 2 S4*

**Recommended move.** Show the display zone once in the chrome and date every timestamp older than today; one `App.ago()` and one `App.stamp()`; one noun (“collector”) for the thing that runs a module and a Start control on every module strip; one product name in filenames, titles and storage keys; a wordmark and favicon; apply the ten-rule voice guide distilled from the app’s own best copy.

**Why.** Seven `ago()` copies disagree on “never”, the Debug export is in UTC while the screen is local, and a vendor in another zone cannot use a pasted `00:19:47`.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| CONS-004 | S2 | No timezone anywhere, and the Debug export disagrees with the Debug screen | ``debug.js:292`` | B (M): A + make the Debug export local with an explicit offset, and put the zone in the file's first line. A alone leaves the export/screen contradiction, which is the part that produces a wrong answer in a ticket. |
| CONS-001 | S3 | Five nouns for the thing that runs a module, and two modules with no way to start it | ``index.html:53`` | B (M): A + give IPAM and NetPath the same strip as the other eight (dot, status, counters, toggle, Settings). the wording fix alone leaves two modules unstartable from their own tab, which is the part that actually blocks a task. |
| CONS-003 | S3 | Seven relative-time formatters, four behaviours, and one that loses the date | ``debug.js:24-31`` | A (S): One exported `App.ago(ts, {zero})` built on `App.span()`; delete the seven copies; use `App.span()`/`App.duration()` for the five Debug durations. the whole divergence is 60 lines of duplicated code; the fix is mechanical and removes a real defect (`debug.js:30`). |
| UI-027 | S3 | No favicon, no wordmark, no visual identity beyond a row of uppercase words | `netpath/web/static/login.html:11` | A (S): An inline SVG favicon (`<link rel="icon" href="data:image/svg+xml,…">`) — a 16 px signal-trace glyph in `--accent` on `--bg` — and the same glyph + "SappiWhere" 14 px 700 at the left of `#tabs` (replacing 22 px of tab padding, see UI-003 A). + B. |
| UX-033 | S3 | No timezone anywhere; seven `ago()` copies with different "never"; day-less times in logs | `nodes.js:42-49` | A (S): One `App.ago()`/`App.when()` pair replacing the seven copies; `stamp(ts, span)` (already handles day/seconds by span) used for every table time; a zone label in the chrome ("UTC+01:00 · 14:32") with a title showing the server zone. . |
| CONS-020 | S4 | The product answers to three names | ``debug.js:301`` | B (M): A + rename the NetPath **tab** to `ROUTES` (matching its own `ROUTE` panel header, `index.html:310`), leaving the package name as an internal detail. A alone leaves the tab/package collision that makes the documentation ambiguous; C costs a great deal for a name no user sees. |
| UX-034 | S4 | Unexpanded jargon and five module nouns for "the thing that runs" | `index.html:53, 205, 353, 420, 481, 540, 643, 697 (strip nouns)` | A (S): A glossary map applied at render time (`ap_offline` → "AP offline", `trace_rtt_warn_pct` → "RTT vs warn threshold (%)"); one noun ("collector") in all strips; Sev rendered as name + digit. . |

### Frontend performance and perceived speed  
*Phase 1 · effort S–M · 4 S2, 3 S3, 1 S4*

**Recommended move.** Serve gzip and `defer` the thirteen module scripts (the `App` IIFE contract survives); cache static files immutably by content hash; trim `/api/state` to what the open tab needs and stop re-walking permissions every two seconds; extend the Nodes row-diffing to Syslog, Traps and Alerts; batch splitter and column drags through `requestAnimationFrame`; add 120 ms transitions to hover and selection.

**Why.** 642 KB over 24 uncompressed parser-blocking requests on every reload; the Nodes table is already diffed, the rest are rebuilt wholesale.

| ID | Sev | Finding | Code | Recommended |
|---|---|---|---|---|
| PERF-001 | S2 | Nothing is compressed; gzip alone saves 431 KB of the cold load and 80–85 % of the poll traffic | ``netpath/web/server.py:355-379`` | B (M): A, plus pre-compress the 16 static files once at start-up and serve the cached `.gz` bytes with the existing `ETag`, so repeated static requests do not re-compress. A is the whole win; B avoids re-gzipping 174 KB of `nodes.js` on every cold load and costs one dictionary. |
| PERF-002 | S2 | Every open tab costs 18–61 MB/hour, and the placeholder Dashboard costs 17.7 | ``netpath/web/server.py:383`` | B (M): A, plus give `/api/state` a cheap version token (a counter bumped on any settings/permission/session change) and return `304` when the client's `If-None-Match` matches. A is free and big; B removes the largest single stream and is bounded to one endpoint. |
| PERF-003 | S2 | All 13 module scripts are parser-blocking and parsed on every load regardless of tab | ``index.html:15`` | B (M): A, plus load lazily — keep `app.js`, `dashboard.js` and the module for the tab `boot.js` restored, and inject the other 11 `<script>` tags on first `selectTab`, awaiting load before calling `init()`. `App.pages[name]` is already the indirection that makes this safe. Initial JS drops from 537 KB to about **223 KB raw / 65 KB gzipped** for Nodes, 74 KB for the Dashboard. A is a one-line-per-tag change worth taking immediately, and B is where the 60 % reduction is. |
| PERF-005 | S2 | Syslog and Alerts rebuild the entire table and both histograms every cycle | ``app.js:794-796`` | B (M): A, plus make `App.grid` rebuild `<thead>`/`<colgroup>` only when the column set changes (reuse the `columnsKey` signature `nodes.js` already computes). A and B together remove the long tasks, the grip destruction and the focus loss; C is the `PERFORMANCE_REVIEW.md` item and should wait until B's numbers are in. |
| PERF-004 | S3 | No minification (worth far less than compression, and should not be done first) | ``index.html:962-974`` | A (S): Nothing — ship PERF-001 and stop; the marginal gain does not justify a build step for a stdlib-only, zero-dependency project. measure first, and the measurement says compression is the win; revisit only if the initial bundle stays above 200 KB gzipped after PERF-003. |
| PERF-006 | S3 | A warm reload spends 15 conditional round trips before any code runs | ``netpath/web/server.py:601`` | B (M): Version-stamp asset URLs from the build/commit id the Settings tab already displays (`#update-commit`), and serve those with `max-age=31536000, immutable`. it removes revalidation entirely and reuses an identifier the server already has. |
| PERF-007 | S3 | Pointer-driven work is unthrottled: 62 chart redraws per second of drag | ``app.js:623`` | A (S): Coalesce the `panes-resized` dispatch through `requestAnimationFrame` (dispatch at most once per frame, plus a final one on `mouseup`) and hoist the tooltip's `getBoundingClientRect()` so the read happens before the write. the dispatch and the layout thrash are the whole of the measured cost, and both are a handful of lines. |
| UI-028 | S4 | Wholesale redraws with no transitions make hover states flicker and the page feel jumpy | `netpath/web/static/app.css:684` | A (S): `@media (prefers-reduced-motion: no-preference) { button, .tab, .subtab, tr td { transition: background-color 120ms, border-color 120ms, color 120ms } }`; keep the hover rect alive by reusing it (`svg.querySelector('#hover') || create`). . |

---

## Proposals

### The eight tasks, before and after

| Task | Today | Proposed |
|---|---|---|
| **T1** Is device X up, and since when? | 6 — Nodes → Find → type → Apply → row → Events sub-tab, infer from the newest event (time only, no date) | 3 — Ctrl+K → name → Enter; header reads “UP · since 03 Sep 09:12 (5 h 20 m) · last poll 4 s ago” |
| **T2** Find the device/port behind a MAC or IP | MAC 4; IP 4–9 across IPAM’s dead-end modal and Nodes | 3 — Ctrl+K → paste → Enter on a grouped result; every result is a URL |
| **T3** Triage and acknowledge open alerts | 7 for one alert with device context (retype the device name in Nodes) | 4 — ↓ to row, `a` to acknowledge (toast with Undo), device name is a link |
| **T4** Who is eating bandwidth now? | 4 — NetFlow → window → group by → Apply | 0–1 — Overview “Top talkers” tile; click opens NetFlow with the window in the URL |
| **T5** Confirm a syslog / trap arrived from X | 6 across two differently shaped filter bars; Live silently drops | 2 — device page → Syslog tab (pre-filtered, “N of M”, LIVE) |
| **T6** Check a DHCP scope’s headroom | 3 — already good | 3, plus an Overview tile for scopes above 80 % and a pasteable URL |
| **T7** Add a device and get it polling | 5–6 — 25-field modal, 900 px scroll, silent on success, accepts an invalid IP | 4 — address (validated) → profile → Enter; toast “added · first poll running · Open” |
| **T8** Grant a colleague read-only access | 17 — scroll to Users, type, twelve Read radios, tell them the password out of band | 6 — Admin › Users → Add → name → preset Viewer → Create → one-time password |

### Information architecture

Keep every module; group by what the operator is doing; one settings implementation with two entry points; every view a hash route; Overview the only home. Sign-in → Overview. Reload → the current URL. A link → that URL after login. A hidden module in the URL → Overview with a toast.

```
SappiWhere
├── Overview  #/                          ← home for every sign-in (?kiosk=1 for walls)
├── Observe
│   ├── Alerts     #/alerts?state&sev&device&win   #/alerts/{id}   #/alerts/rules   #/alerts/templates
│   ├── Syslog     #/syslog?q&sev&host&src&win&live #/syslog/msg/{id}
│   ├── SNMP Trap  #/traps?…                        #/traps/{id}
│   ├── NetFlow    #/netflow?win&by&src&dst&port    #/netflow/records
│   └── NetPath    #/netpath/{target}?t0&t1
├── Inventory
│   ├── Nodes      #/nodes/devices?q&status         #/nodes/devices/{id}/{overview|ports|alerts|events|syslog|traps|route|config|metrics}
│   │              #/nodes/discovery[/{job}]        #/nodes/profiles   #/nodes/mibs
│   ├── IPAM       #/ipam/subnets[/{id}]  ← default #/ipam/conflicts   #/ipam/dhcp/{server}/scopes/{scope}
│   ├── Wireless   #/wireless/aps[/{id}]            #/wireless/controllers
│   └── ConfigRX   #/configrx/devices[/{id}/backups/{b}]
├── Admin
│   ├── Settings   #/admin/settings/{general|sign-in|storage|update|maintenance}
│   │              #/admin/settings/modules/{module}   ← same section the module gear opens
│   ├── Users      #/admin/users[/{name}]            presets Viewer · Operator · Admin · Custom
│   └── System     #/admin/system/health             #/admin/system/events   (today: Debug)
├── Account ▾      password · display zone · start page · sign out
└── Search  Ctrl+K · /   → results are the routes above
```

Wireframes (in the artifact): Overview for the NOC operator; Ctrl+K search with typed inference; the unified filter bar; the device page with a header that answers “up since when” and related tabs pre-filtered to the device; the feedback system (toast region, inline errors, dirty-form guard, disabled-with-reason, connection banner).

### Design-system proposal (summary)

Keep the character; re-step, split and add.

| Token | Hex | Role | Change |
|---|---|---|---|
| `--bg` | `#0E1116` | page ground | unchanged |
| `--panel` | `#151A21` | panels, tab bar, table body | unchanged |
| `--raised` | `#1B222B` | inputs, buttons, sticky th, zebra, modal box | becomes the modal surface |
| `--overlay` | `#222A34` | tooltips, menus, toasts | new |
| `--grid` | `#1F262F` | row rules, chart gridlines | re-stepped darker than hairline |
| `--hairline` | `#343E4B` | panel and input borders | re-stepped from #2A323D |
| `--hairline-strong` | `#3A4552` | grips, dividers, focus inner | new; 3:1 as non-text |
| `--data-neutral` | `#3A4552` | no data / never seen / available | replaces --nodata and --hairline as data |
| `--checked` | `#22304A` | ticked rows and plain selection | unchanged; now also selection |
| `--checked-strong` | `#2E4470` | ticked + selected | unchanged |

| Text tone | Hex | Role | Contrast bg / panel / raised |
|---|---|---|---|
| `--text` | `#DCE3EA` | primary content | 14.6 / 13.5 / 12.4 |
| `--text-2` | `#94A0AE` | labels, th, resting tab | 7.1 / 6.6 / 6.0 |
| `--text-3` | `#737E8C` | hints, axis text, captions | 4.6 / 4.2 / 3.9 |
| `--faint` | `#4C5561` | non-text only: dividers at rest, inactive dot | — |
| `--on-accent` | `#0E1116` | text on accent / ok / warn fills | 7.5 / 7.4 / 9.7 |
| `--focus` | `#9EC1FF` | focus ring only | 9.6 on bg |

| Semantic | Value | May mean | May not mean |
|---|---|---|---|
| `--accent` | `#7AA2F7` | interactive only: active tab, primary button, links, selection bar, brush | static data, categories, “unchanged”, traceroute |
| `--ok` | `#3FB950` | healthy / up / connected / alive | “changed” |
| `--warn` | `#E3B341` | degraded / auth failed / warning severity | a series colour |
| `--fail` | `#F85149` | down / no reply / severity 0–2 / error text | — |
| `--sev-3` | `#FF8A65` | syslog and alert severity 3 | path refusal |
| `--path-refused` | `#FF8A65 + hatch` | NetPath refused hop, always with texture | severity |
| `--path-skipped` | `#4DB6AC + bars` | overrun, always with texture | — |
| `--probe-error` | `#A371F7` | probe failed | a series colour |
| `--cat-1…8` | `#5B8DEB #CF7638 #2FA886 #B0881A #D1609A #4F9A3A #8F76E8 #DC5A5A` | categorical series in fixed order; slot 9+ → data-neutral “Other” | status |

Type scale (rem on a 13 px base): 11 / 12 / 13 / 14 / 16 / 20 with line heights 1.2–1.45; weights 400 / 600 / 700; tracking 0 except eyebrows. Spacing 4 / 6 / 8 / 12 / 16 / 24; radius 3 / 6 / 10; three shadows; a z-index ladder; focus ring `2px solid #9EC1FF` offset 2 on `:focus-visible`. The eight categorical colours pass the data-visualisation validator on `#151A21`; the ok/warn/fail triad does not pass colour-vision-deficiency checks, so status always carries a glyph and a word. A light theme is feasible by promoting the `--canvas-*` values to the light side of the same tokens plus seven new values; a high-contrast dark variant is a small addition.

### Three visual directions

| | Direction | Effort | Fixes | Would not fix |
|---|---|---|---|---|
| 1 | Conservative polish — token edits and rules, same layout | S–M, 3–4 days | every measured contrast, focus, overflow, glyph+word, legend, meter, first-paint and row-wrap failure | chrome height, four panels/dots, eleven font sizes, 820 px, wallboard, identity |
| 2 | Systematic design system — components rebuilt on tokens, same IA | L, ~3 weeks | one panel, one button set, one status glyph, segmented third-level tabs, merged header, rem scale, focusable rows, empty/toast primitives, one breakpoint, validated chart palette | wall legibility, wordmark, kiosk, white route canvas, the Overview |
| 3 | Instrument-panel rebrand — wordmark, grouped nav, high-contrast base, KPI tiles, wall density, kiosk, Ctrl+K | L, 5–6 weeks incl. 2 | everything in 2 plus identity and wallboard use | triage model, URL state, permissions, Overview content (the UX proposals it is designed to carry) |

The three boards are also side by side, at scale, on the design canvas: https://claude.ai/code/artifact/873c6aaf-2a7d-4294-a1b4-f979d70bc141

---

## Roadmap

### Phase 0 — Fix now

Each item is under half a day and reproducible in a capture. About two weeks of one engineer.

- **Defects to fix this week** — S each · 11 findings · depends on: —
- **Keyboard reach and visible focus** — S now, M in foundation · 10 findings · depends on: defects
- **Status carried by colour alone** — S–M · 7 findings · depends on: —
- **Time, timezone, names and voice** — S–M · 7 findings · depends on: —

### Phase 1 — Foundation

Tokens, type scale, component set, focus, feedback and dialog primitives, unified filter bar, permission renderer, performance. Roughly six to eight weeks; every later change gets cheaper.

- **Text that cannot be read at 11 px on dark** — M · 9 findings · depends on: components (tokens)
- **Feedback: outcomes, errors, a hung server** — M · 11 findings · depends on: —
- **One dialog contract: submit, discard, confirm** — M · 7 findings · depends on: feedback (toast)
- **Forms, defaults and help** — M · 9 findings · depends on: dialogs, feedback
- **Permissions: disable with a reason, never hide silently** — M · 2 findings · depends on: feedback (disabled-with-reason)
- **One filter bar, one time control, one Live toggle** — M · 5 findings · depends on: navigation (URL sync), components
- **Tokens and one component set** — L · 12 findings · depends on: legibility tokens
- **Frontend performance and perceived speed** — S–M · 8 findings · depends on: —

### Phase 2 — Navigation, Overview and the device page

Hash routing, grouped navigation, the Overview page, cross-links, Ctrl+K search, responsive and wall modes. Six to ten weeks; the visible payoff.

- **Addressability: URL state, one home, grouped navigation** — L · 8 findings · depends on: feedback, components
- **Cross-module links, the device page and global search** — L · 5 findings · depends on: navigation, filterbar
- **Responsive layout and wallboard density** — M · 3 findings · depends on: components

**Before any L-size item:** validate the three assumed personas (NOC operator on a wallboard; engineer mid-incident; administrator onboarding) with about five real operators. Every click count in this review is derived from the documentation and the feature set, not observed use.

---

## Voice and tone (distilled from the app’s own best copy)

1. State the consequence, not the action.
2. Say what survives.
3. Say when it is irreversible, in those words, last.
4. Name the blast radius when it exceeds this browser.
5. Admit uncertainty rather than rounding it away.
6. An empty state says why it is empty and what changes it.
7. Expand an acronym the first time it appears on a surface.
8. Sentence case; full stops on sentences, none on labels; no “Oops”, no “Please”.
9. One idea per paragraph; over 40 words, it belongs behind a “?”.
10. Never let a control’s only explanation live in a title attribute.

---

## Method and limitations

- **Evidence.** The app was run headless in a sandbox with the SQLite stores seeded directly (40 devices, traces, flows, syslog, traps, alerts at four severities, subnets, access points, backups; admin, read-only and two-module accounts). 63 named states were captured with Playwright at 1600×1000, 1366×768, 820 wide, 700/880 high and 200 % zoom. Measured: 39 of 135 rendered text pairs fail AA; the button focus ring is 1.01:1; the tab bar breaks at 1549 px; cold load is 24 requests / 642 KB with no compression; `/api/state` is 10.3 KB every 2 s; Syslog and Alerts rebuild every row per refresh while Nodes is diffed.
- **Benchmark.** LibreNMS, Zabbix 7, PRTG and Grafana on eight axes (overview, global search, device detail, alert triage, theming, density, deep links, keyboard); documentation fetches were blocked by the proxy, so cells are marked verified or from knowledge in the artifact.
- **Limits.** Personas are assumed. Collectors needing `ping`, `traceroute`, `nslookup` or `paramiko` were stopped in the sandbox; “Poller stopped” strips in captures are an artefact. Light-theme images are synthesised. The PySide6 console was reviewed from code. Nothing recorded as implemented in `PERFORMANCE_REVIEW.md` is recommended again.
- **Reproduce.** Recipe, seed script, capture script and measurements are described in the artifact’s Method section; all `file:line` references are to build 4.36.1 on this branch.

---

## Appendix A — Prior art

| Axis | LibreNMS | Zabbix 7.x | PRTG | Grafana |
|---|---|---|---|---|
| **1. Landing / overview** | Drag-drop widget dashboards, multiple named, per-user default; usable stock layout (availability, alerts, top ports). [K] | Dashboard of typed widgets (Problems, Top hosts, Graph, Map, SLA), free layout; operators mostly live in Monitoring → Problems. [K] | Welcome/Home tiles; "dashboards" are hand-drawn absolute-positioned **Maps**. The sensor tree is the real overview. [K] | No domain model; Home dashboard, fully composable panel grid, rows, template variables. The customisation reference. [K] |
| **2. Global search** | Header autocomplete for devices/ports/apps, plus *separate* IPv4/IPv6/MAC/ARP pages. No unified box, no `/` shortcut. [V] ([community](https://community.librenms.org/t/can-i-search-by-mac-address/23744)) | Persistent header box: hosts, groups, templates; grouped results with per-row action menus. Not IP/MAC aware. [K] | Header box over objects (probe/group/device/sensor) by name and address, grouped results. [K] | `Ctrl/Cmd+K` command palette (dashboards, panels, nav, actions); `?` lists all shortcuts. [V] ([docs](https://grafana.com/docs/grafana/latest/visualizations/dashboards/use-dashboards/)) |
| **3. Device detail** | Identity header (host, OS icon, uptime, status pill) + tab strip (Overview/Graphs/Health/Ports/Routing/Logs); ports = sortable table with mini graphs. [K] | No unified device page — host context popup → Graphs / Latest data / Problems / Config. Weakest of the four. [K] | Persistent left object tree; tabs Overview / 2d / 30d / 365d / Historic / Log / Settings; actions in a context menu. [K] | N/A; nearest analogue is a `$host` template variable. [K] |
| **4. Alert triage** | Table (state, device, rule, time, duration); per-row ack with note; coloured row + text; links to device; weak bulk actions. [K] | Strongest: severity as colour band **and** text (Not classified→Disaster); checkboxes drive a **bulk** "Update problem" dialog (ack, suppress, reseverity, note, close); unacknowledged filter. [K] | Status-filtered sensor list; Acknowledge Alarm / Pause per sensor or via multi-edit; red/amber + status text. [K] | Alert rules grouped by state; silences rather than acks; links via dashboard annotations. [K] |
| **5. Theming** | Per-user light/dark picker; no system-follow, no high-contrast. [K] | Per-user: **System default, Blue, Dark, High-contrast light, High-contrast dark** — only product here with explicit high-contrast themes. [V] ([docs](https://www.zabbix.com/documentation/current/en/manual/config/users_and_usergroups/user)) | Per-user dark theme / Color Mode under Setup → Account Settings → My Account; applies to exported graphs; read-only users included. [V] ([KB](https://helpdesk.paessler.com/en/support/solutions/articles/76000063984-dark-theme-for-large-screen-display)) | Per-user light/dark/system, org default, per-dashboard override, `theme` URL param. [K] |
| **6. Density** | Per-page entry-count selector only. [K] | Per-user **Rows per page**; "compact view" toggle on several monitoring views; no font-size control. [V] (same doc) | Fixed, fairly airy; item counts only. [K] | None; density is the dashboard author's problem. `&kiosk` strips chrome for wall displays. [K] |
| **7. Deep links** | Every view addressable (`/device/<id>/ports`, `/alerts`); back/forward fine. [K] | All views plus **filter state** in query params; named per-user filter tabs, shareable by URL. [K] | Object IDs in URLs (`device.htm?id=…`); some flows modal-only. [K] | Gold standard: UID+slug, variables and time range in the query string, Copy link / snapshot, absolute-time rewriting. [K] |
| **8. Keyboard / a11y** | Minimal; no documented shortcuts. [K] | Esc closes dialogs, Enter submits; high-contrast themes are the a11y story; no cheat-sheet. [K] | Minimal; no published shortcut list. [K] | Richest: `?` cheat-sheet, `Ctrl+K` palette, `d`/`t` chords, `Esc` exits panel/edit/settings. [V] ([docs](https://grafana.com/docs/grafana/latest/visualizations/dashboards/use-dashboards/)) |

## Appendix B — WCAG 2.2 AA checklist

| SC | Lvl | Result | Evidence (measured value / capture / path:line) | Fix | Effort |
|---|---|---|---|---|---|
| **1.1.1** Non-text Content | A | **FAIL** | Every visible `<svg>` chart has no `<title>`, no `<desc>`, no `role`, no `aria-label`, no `aria-hidden` — measured across Nodes/NetPath/NetFlow/SNMP/Syslog (`a11y3.json` `svgAcc`). NetPath's route SVG carries 8–13 `<text>` glyphs at 10 px and is otherwise an unlabelled graphic. `netpath.js:689`, `syslog.js:61`, `alerts.js:95` | Give each chart `role="img"` + `aria-label` summarising the current window ("Messages per hour, last 24 h, peak 412 at 14:00"), and a visually-hidden `<table>` of the same buckets as the text alternative | M |
| **1.2.x** Time-based media | A/AA | n/a | No audio or video in the product | — | — |
| **1.3.1** Info and Relationships | A | **FAIL** | (a) `nav#tabs` (`index.html:19-38`) is 12 plain `<button>`s — measured `role` on every `.tab` = none, `aria-selected` count = 0. (b) Zero `<h1>` on all 12 tabs (`a11y3.json` `headingOutline`); the only `<h1>` in the product is the login page (`login.html:11`). `h2` is 15 px in a modal and 11 px in the NetPath sidebar; `h3` (11 px) is *smaller* than body text. (c) Tables: `#nodes-table` has 8 `<th>`, **0 with `scope`**, **0 with `aria-sort`**, no `<caption>`, no `aria-label` (`a11y6.json` `tableSemantics`). (d) 41 checkboxes on Nodes carry no programmatic name (see 4.1.2) | Add `role="tablist"/"tab"` + `aria-selected` + `aria-controls`; one `<h1>` per tab (visually hidden is fine); `scope="col"` and `aria-sort` in `App.grid` (`app.js:711-746`) — one change fixes all 20+ tables | M |
| **1.3.2** Meaningful Sequence | A | **PASS** | Measured, and my brief's premise was wrong. `app.css` contains **no** `order:`, `row-reverse`, `column-reverse` or `direction` declaration. A banded reading-order comparison (group focusables by 30 px row, sort by x, count inversions against DOM order) gives **0 inversions on IPAM**, Alerts, SNMP, Syslog, Wireless and Debug (`a11y4.json`). The apparent Nodes/NetPath/Settings "inversions" are two-column pane layouts and a fixed bottom Apply bar, both of which read correctly column-first. The IPAM claim in Appendix B refers to the sub-*panel* DOM order (subnets 553 / conflicts 590 / dhcp 599 in `index.html` vs sub-tab buttons DHCP/CONFLICTS/SUBNETS at `index.html:548-552`); since `.subpage` is `display:none` when inactive (`app.css:114-115`) exactly one is ever in the accessibility tree, so it has no user-facing effect | No change; keep the constraint in mind if panes ever become simultaneously visible | — |
| **1.3.3** Sensory Characteristics | A | **FAIL** | NetPath's legend is written purely as colour names: "green healthy · amber degraded · red no reply … violet probe failed" (`index.html:298-301`). Four of the six states have no second channel; only "orange hatched" and "teal striped" carry a texture | Name the state, not the colour, and give the four flat states a shape or hatch of their own | S |
| **1.4.1** Use of Colour | A | **FAIL** | The row open in the detail pane is signalled *only* by `tr.selected td { background: var(--hairline) }` (`app.css:504`). Measured: `#2A323D` vs `--panel` = **1.35:1**, vs the `--raised` zebra stripe = **1.24:1**. No border, no glyph, no `aria-selected` (`a11y6.json` `rowKeyboard`). Same for the ticked-row tint (`--checked` vs `--raised` = **1.21:1**, `app.css:512`) and the both-states tint (`--checked-strong` vs `--checked` = **1.37:1**). NetPath route states as above. *Credit where due:* Nodes' status column pairs the dot with the literal status text (`nodes.js:132-137`), and Syslog severity pairs the colour with the severity name (`app.css:570-577`) — those pass | Add a 2 px `--accent` left border (on the row, not per-cell) plus `aria-selected="true"`; texture the four flat NetPath states | S |
| **1.4.3** Contrast (Minimum) | AA | **FAIL** | §4a: **39 of 135** distinct rendered (fg, bg, size, weight) pairs fail across four tabs. Worst and most numerous: `.hint` (`app.css:264`, `--faint #4C5561` at 11 px) at **1.71:1 / 2.12:1 / 2.31:1 / 2.50:1** depending on the surface behind it — 20 + 19 + 15 instances on Nodes/Settings alone, and that class carries every empty state, every counter and all Settings prose. `th.sortable` `--muted` on `--raised` = **4.39:1** (needs 4.5). `--canvas-faint` on white = **2.84–3.07:1** in NetPath SVG labels | Retire `--faint` as a *text* colour (keep it for hairlines); lift `.hint` to `--muted`, and lift `--muted` from `#7C8794` to ≈`#8B96A4` so `th` clears 4.5:1 on `--raised` | S |
| **1.4.4** Resize Text | AA | **PARTIAL** | Text does scale — nothing is in `px`-locked containers that clip it. But at 200 % on a 1280×720 laptop (CSS 640×360, measured `zoom.json`) only **6 of 12 tabs** are on screen, `Sign out`, `Account`, `#whoami` and `#conn` are all off screen, and **3 of 40** device rows are visible. Capture `zoom200-nodes` | Fixed by the 1.4.10 work below (wrap `#tabs`, add breakpoints) | M |
| **1.4.5** Images of Text | AA | **PASS** | No text is rendered as a raster image anywhere; charts use live `<text>` | — | — |
| **1.4.10** Reflow | AA | **FAIL** | `app.css` contains **zero `@media` rules** (grepped: only `@media`-free density classes `body.compact`/`body.tiny` driven from JS). Measured document scroll width is a constant **1543 px** at every viewport from 320 to 1366 px, i.e. horizontal *and* vertical scrolling at 4.8× overflow at 320 px (`a11y2.json` `reflow`). §4f bisects the breaking point at **1549 px** — below it `#signout` and `#conn` leave the viewport. At the ordinary laptop width of 1366 px the connection-failure indicator `#conn` — the app's only failure signal — is already off screen. Captures `v1366-nodes`, `v-tabs-overflow-1548`, `v820-nodes` | `flex-wrap: wrap` on `#tabs` plus three breakpoints (1280 / 1024 / 768) that stack the pane splitters vertically; move `#conn` into the flow so it can never be the thing that overflows | M |
| **1.4.11** Non-text Contrast | AA | **FAIL** | Computed from the tokens: input/select/textarea border `--hairline` vs `--panel` = **1.35:1** (needs 3:1), vs `--raised` = **1.24:1**, vs `--bg` = **1.46:1** (`app.css:245-247`). Splitter and column-grip visible lines are `--faint` at **2.12–2.50:1** (`app.css:558-566`, `app.css:679-687`). Chromium's UA focus ring computes to `rgb(16,16,16)` = **1.01:1** against `--bg` (§4b), 1.09:1 on `--panel`, 1.19:1 on `--raised`. Selection tints as under 1.4.1. *Passing:* the focused-input border `--accent` reaches 6.36–7.51:1 | Raise control borders to a token ≥ 3:1 against all three surfaces; make dividers/grips `--muted` | S |
| **1.4.12** Text Spacing | AA | **PASS** | Applied the SC's four overrides (line-height 1.5, letter-spacing 0.12em, word-spacing 0.16em, paragraph 2em) to the live Nodes page: document scroll width moved 1600 → 1624 px and **exactly one** element reported new overflow — `div.table-wrap`, which is an `overflow:auto` scroller by design (`a11y2.json` `textSpacing`). No text is clipped or lost | No change | — |
| **1.4.13** Content on Hover or Focus | AA | **FAIL** | `App.tooltip` (`app.js:341-376`) is wired only to `mousemove`/`mouseleave` at every call site (e.g. `syslog.js:125-126`, `alerts.js:95`) — never to `focus`/`blur` — and `.tooltip` is `pointer-events: none` (`app.css:735-738`), so the content is not hoverable, not dismissible with Escape, and unreachable by keyboard. It is the only carrier of the per-hour severity breakdown on both histograms | Add `focus`/`blur` to the same handler, drop `pointer-events:none`, and let the existing Escape handler (`app.js:1112-1119`) dismiss it | S |
| **2.1.1** Keyboard | A | **FAIL** | (a) Table rows are click-only: measured `tabindex` absent, `role` none, `onclick` present on `#nodes-table tbody tr` (`a11y6.json`); the same pattern in `syslog.js:196`, `alerts.js:192-196`. Opening a device, a syslog message or an alert is unreachable from the keyboard. (b) Pane splitters are `mousedown`-only (`app.js:599-638`) and column grips likewise (`app.js:765-786`). (c) NetPath's timeline drag/wheel/`oncontextmenu` gestures (`netpath.js:960-985`) have no keyboard route — and `svg.oncontextmenu` at `netpath.js:976` also suppresses the browser context menu. §4b: a 12-Tab walk never leaves the tab strip | Make rows `tabindex="0"` + Enter/Space in `App.drawRows` (`app.js:858-872`) — one change covers 10 tables; add arrow-key resize on splitters/grips; give the timeline explicit prev/next/zoom buttons (they already exist at `index.html:331-334` — bind the same actions) | M |
| **2.1.2** No Keyboard Trap | A | **PASS** | Nothing traps focus. The opposite problem — focus *escaping* the modal — is filed under 2.4.3 | — | — |
| **2.1.4** Character Key Shortcuts | A | **PASS** | No single-character shortcuts exist | — | — |
| **2.2.1** Timing Adjustable | A | **PARTIAL** | The idle sign-out warns and offers "Stay signed in" (`app.js:196-215`), which satisfies the extend requirement. But the countdown always starts at 60 s regardless of the configured timeout (`WARNING_MS = 60_000`, `app.js:149`; §6.4), so the warning period is not adjustable, and the banner is never announced (4.1.3). Capture `idle-banner` | Derive the warning window from the timeout (min 20 s, or 1/10 of it) and mark the banner `role="alertdialog"` | S |
| **2.2.2** Pause, Stop, Hide | A | **PASS** | Auto-updating content is genuinely pausable: Syslog/SNMP have a Live tick, NetPath/NetFlow a Follow tick, and Settings exposes every module's refresh rate (`index.html:842-858`) | — | — |
| **2.4.1** Bypass Blocks | A | **FAIL** | No skip link. Exactly **one `<main>` in the whole application** (`index.html:306`, inside NetPath only) — the other 11 tabs have no main landmark; `section.page` carries no `aria-label`. Measured landmark counts 1–5 per tab, none of them a page-level main (`a11y3.json`). Every keyboard user therefore traverses the same 14 chrome stops before reaching content on every tab (§4b, stops 1–14) | Wrap the page container in `<main id="content">`, add a skip link as the first focusable element, and label each `section.page` | S |
| **2.4.2** Page Titled | A | **PASS** | `login.html:6` sets a real title; the shell sets one too | — | — |
| **2.4.3** Focus Order | A | **FAIL** | Three separate failures. (a) **Focus is destroyed by the refresh loop.** Measured: focus a row checkbox on Nodes, wait one 10 s cycle — `document.activeElement` goes from `nd-check` to `BODY`, even though the row `<tr>` survives the diff (`a11y6.json` `nodesFocus`). The cause is the `<tbody>` swap plus `App.grid` clearing `table.innerHTML` (`app.js:794-796`) on every draw. On Syslog the whole table including `<thead>` is replaced. Keyboard use of any table is impossible for longer than one refresh interval. (b) **Escape from a modal drops focus on `BODY`** rather than returning it to the trigger (`a11y2.json` `modal.focusAfterEscape`); `closeModal` (`app.js:407-415`) has no focus-return. (c) On NetPath the first Tab stop inside the page is `#target-add` at **y = 776 px** — three-quarters down the screen — before the route header controls at y = 55 (`a11y5.json`) | (a) preserve focus across draws (record `activeElement.id`/row key before the swap, restore after) — or better, stop replacing the `<tbody>`; (b) store and restore the trigger exactly as `showHelp`/`closeHelp` already do (`app.js:431-475`); (c) reorder the NetPath sidebar so its buttons sit at the top | M |
| **2.4.4** Link Purpose | A | **PASS** | The product has almost no `<a>`; actions are buttons with text | — | — |
| **2.4.5** Multiple Ways | AA | n/a | Single-page application, one navigation mechanism — SC not applicable to a single-page process | — | — |
| **2.4.6** Headings and Labels | AA | **FAIL** | (a) **63 strings are typed in capitals directly into the markup** (counted in `index.html`; only 3 CSS `text-transform: uppercase` rules exist, at `app.css:323,342,804`), so "SNMP TRAP", "CONFIGRX", "ASN / OWNER LOOKUP" reach assistive technology as capitals, and some screen readers spell them letter by letter. (b) Icon buttons are named by a single punctuation glyph — the accessibility tree returns literally `"−"`, `"+"`, `"‹"`, `"›"` for the 6 NetPath and 4 NetFlow icon buttons (`a11y3.json` `acc_netpath`/`acc_netflow`; `index.html:315-316,331-334,379-382`). (c) No `<h1>` anywhere in the app shell (1.3.1) | Write labels in sentence case and apply `text-transform: uppercase` in CSS; give each icon button an `aria-label` ("Zoom in", "Earlier", "Later") | S |
| **2.4.7** Focus Visible | A | **FAIL** | The application's stylesheets contain exactly **two** focus rules (enumerated at runtime, §4b): `input:focus, select:focus, textarea:focus { outline: none; … }` (`app.css:253`) and `.help-link:hover, .help-link:focus` (`app.css:850`). There is no `:focus-visible` rule anywhere and no focus style for `button`, `.tab`, `.subtab`, rows or the modal. Buttons therefore fall back to Chromium's UA ring at **1.01:1** against `--bg`. Inputs show computed `outline: none 0px` — their only cue is the border moving to `--accent` | One rule: `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px }`, and delete `outline:none` | S |
| **2.4.11** Focus Not Obscured (Min) | AA | **PASS** | Measured directly: 40 consecutive Tab stops through the Nodes table, checking each focused element against the sticky `<thead>` box (`app.css:492`) and against the pane — **0 obscured, 0 pushed outside the pane, 0 hit-test failures** (`obscure.json`). The Add-device modal has no sticky button row and none of its 26 stops is obscured. Residual risk only: `.idle-banner` is `position:fixed; bottom:20px; left:50%; z-index:60` (`app.css:693-698`) and would cover the horizontal middle of the last ~40 px band while visible | No change; keep the banner out of the focus path if it ever gains focusable siblings beyond its own button | — |
| **2.5.1** Pointer Gestures | A | **FAIL** | Splitter and column-grip resizing and the NetPath timeline range-select are path-based drags with no single-pointer alternative (`app.js:599-638`, `app.js:765-786`, `netpath.js:960-975`). Clearing a NetPath pin is bound to right-click only (`netpath.js:976-980`) | Add double-click-to-reset (splitters already have it, `app.js:639-651` — extend to grips) and a visible "Clear pin" button | S |
| **2.5.2** Pointer Cancellation | A | **PASS** | Actions fire on `click`/`mouseup`, not `mousedown`; drags settle on `mouseup` | — | — |
| **2.5.3** Label in Name | A | **PARTIAL** | Only one element in the product uses `aria-label`: the help "?" button, `aria-label="Help"` with visible text "?" (`app.js:443`). "?" is not contained in "Help", so it is a technical failure, though a glyph-only label is the case the SC least cares about. Everything else derives its name from its own text and passes | Use `aria-label="Help"` on the *icon*, or add a visually-hidden "Help" span; and when 2.4.6's `aria-label`s are added to icon buttons, make sure any future visible text is a substring | S |
| **2.5.7** Dragging Movements | AA | **FAIL** | Same three drags as 2.5.1: pane splitters, column grips, timeline range-select. None has a non-drag equivalent | Arrow-key resize when the splitter/grip is focused; numeric column-width fields already exist in the column picker dialog and could take widths | M |
| **2.5.8** Target Size (Minimum) | AA | **FAIL** | Measured on the live page (`a11y2.json` `targets`): column grip **7 × 26 px** (`app.css:547-554`) — under the 24 × 24 minimum on the narrow axis, and its spacing exception does not apply because it sits flush against the sortable header it overlaps. Row checkboxes render **13 × 13 px** with ~4 px of padding around them. *Passing:* pane dividers 8 × 817 px (long axis exempts them under the "inline" reasoning only if undersized targets are spaced — they are), tabs 137 × 34, icon buttons 32 × 27 | Widen the grip hit area to 24 px (keep the 1 px visible line), and give row checkboxes a 24 px padded label wrapper — which also fixes their missing name (4.1.2) | S |
| **3.1.1** Language of Page | A | **PASS** | `<html lang="en">` on both documents | — | — |
| **3.2.1** On Focus | A | **PASS** | Nothing changes context on focus; the modal's auto-focus of its first field (`app.js:402-403`) is an initial placement, not a context change | — | — |
| **3.2.2** On Input | A | **FAIL** | Measured, five controls on Nodes fire a refetch on `change` while an explicit **Apply** button sits beside them (`a11y6.json` `onInput`; `nodes.js:3473-3476` vs `nodes.js:3464`) — the same control set is submit-on-Apply and submit-on-change at once. Worse: `#nf-resolve`, presented as a NetFlow *filter*, writes a **server-wide setting** for every user on change (`netflow.js:716-722`); and clicking a Syslog histogram bar silently unticks Live and rewrites the time window (`syslog.js:127-134`) | Pick one submission model per filter bar (auto-apply, and delete Apply, is the smaller change); move `Resolve names` out of the filter bar into the module Settings dialog; keep the Live tick ticked when a bar is clicked, or say in the bar that it was turned off | S |
| **3.2.3 / 3.2.4** Consistent Nav / Identification | AA | **PASS** | The tab strip and chrome are identical on every page (§4b: the first 14 stops are the same everywhere); `App.grid`/`App.drawRows` give every table one implementation | — | — |
| **3.2.6** Consistent Help | A | **PARTIAL** | The help mechanism exists but is present on exactly three settings (`nodes.js:2394-2492`); there is no help affordance in a consistent screen position | Put a single "?" in the chrome that opens the same panel with a per-tab entry | M |
| **3.3.1** Error Identification | A | **FAIL** | Empty required fields return silently — `if (!ip) return;` at `nodes.js:1943`, and the same shape at `nodes.js:2068,2376`, `alerts.js:529,650`. The Add button appears not to work with no message. Most Save paths have no `catch`, so a server rejection produces nothing (`alerts.js:497,540,628`; `nodes.js:1994`; `ipam.js:273`). A 500 or a 400 is silent | Add a `<p role="alert">` slot to `App.modal` and route both validation and `catch` into it — one change in `app.js:385-404` covers every dialog | S |
| **3.3.2** Labels or Instructions | AA | **PARTIAL** | Real `<label for>` is used widely and correctly — my DOM scan found **0 unlabelled inputs** on NetPath, Syslog, IPAM, NetFlow and only **2 placeholder-only** fields on Settings (`a11y1.json`). Against that: row checkboxes have no label at all (4.1.2), and three different conventions signal "unset" in the Nodes forms (blank / `(profile)` / `0`) with nothing explaining which is which | Label the checkboxes; normalise the unset convention to one and say so in the field hint | S |
| **3.3.3** Error Suggestion | AA | **FAIL** | There is **no IP validation anywhere** — §6.2 proves `999.999.1.oops` is accepted by the Add-device dialog and lands in `nodes.db`. When an error does surface, it is the raw `TypeError.message` from `fetch` rendered in the top-right corner (`api-error-corner`; `app.js:130-134`), which suggests nothing | Validate IP/CIDR client-side with a named message; replace raw `error.message` with a mapped sentence | S |
| **3.3.4** Error Prevention | AA | **PARTIAL** | `confirmDestructive` (`app.js:481-500`) is a genuinely good single confirmation shape — but six hand-rolled confirms bypass it, and a modal with unsaved edits is discarded by Escape or a backdrop click with no dirty check (`app.js:1112-1119`, `app.js:1109-1111`). The forced password-change modal is itself dismissible with Escape (§5.4, capture `login-mustchange-escaped`) because `settings.forcePasswordChange` never sets `state.modalLocked` | Dirty-check before Escape/backdrop close; set `modalLocked` on the forced-change modal | S |
| **4.1.2** Name, Role, Value | A | **FAIL** | Measured from Chromium's accessibility tree: **41 interactive elements on Nodes and 18 on Alerts have an empty accessible name** — every row checkbox plus the select-all box (`a11y1.json`, `a11y3.json`; `nodes.js:130`, `app.js:720-733`, which sets only `box.title`). The main modal has **no `role`, no `aria-modal`, no `aria-labelledby`**, its background is neither `inert` nor `aria-hidden` (70 focusable elements remain behind it), and focus leaves the box after **27 Tabs** (`a11y2.json` `modal`; `index.html:960`). Tabs have no `role`/`aria-selected`. Sort state is a caret glyph with no `aria-sort` | Name the checkboxes ("Select <device name>"); give `#modal-box` `role="dialog" aria-modal="true" aria-labelledby`, a focus trap and `inert` on the background — the help panel at `app.js:456-457,467,474` is already the correct template to copy | M |
| **4.1.3** Status Messages | AA | **FAIL** | **The entire application contains four ARIA attributes**, three of them on the help panel and one `role="alert"` on the login page. Measured `[aria-live], [role=alert], [role=status], output` count = **0** on all 12 tabs (`a11y1.json`). Silent as a result: `#conn` losing the connection (`app.js:130-134`), the idle sign-out banner (`app.js:196-215`), every settle/bulk result, the 2.5–4 s button-label mutations that stand in for toasts, and the Alerts bulk banner | One polite live region in the chrome plus `role="status"` on `#conn` and `role="alert"` on the idle banner | S |

## Appendix C — Code hygiene (S4, not ranked)

| # | path:line | Issue | Fix |
|---|---|---|---|
| H1 | `app.js:390-392` | `box.innerHTML = \`<h2>${title}</h2>…\`` — the modal title is interpolated unescaped. Every caller passing user data is therefore an injection point. | Escape `title` in `modal()`; then all call sites are safe regardless. |
| H2 | `alerts.js:414` | `App.modal(\`Edit ${r.name}\`, …)` — rule name unescaped (**verified**) | Covered by H1 |
| H3 | `alerts.js:583` | `Edit template: ${t.name}` unescaped (**verified**) | Covered by H1 |
| H4 | `configrx.js:525` | `ConfigRX settings: ${device.name}` unescaped (**verified**) | Covered by H1 |
| H5 | `nodes.js:1263` | `Browse OIDs — ${displayName(device \|\| {})}` unescaped (**verified**) | Covered by H1 |
| H6 | `nodes.js:1971` | `Edit ${displayName(d)}` unescaped (**verified**) | Covered by H1 |
| H7 | `nodes.js:2497` | `Edit ${g.name}` unescaped (**verified**) | Covered by H1 |
| H8 | `settings.js:314` | `Permissions for ${user.username}` unescaped (**verified**) | Covered by H1 |
| H9 | `wireless.js:248` | `Edit controller: ${c.name}` unescaped (**verified**) | Covered by H1 |
| H10 | `ipam.js:1021`, `nodes.js:2702` | The **only two** call sites that *do* escape their title — proving the omission elsewhere is an oversight, not a policy | After H1, remove the now-double escaping here |
| H11 | `app.css:121-125` | Comment: *"this coexists safely with the existing `.hidden` toggle in nodes.js"*. There is no `.hidden` class in `nodes.js` (or anywhere in `*.js`) — `grep -rn "classList.*hidden\|class=\"hidden\"" *.js index.html` returns only `visibility: 'hidden'` SVG attributes | Delete the last sentence of the comment |
| H12 | `app.js:1155-1158` | Comment: *"The five files are ordinary parser-blocking scripts"*. `index.html:15, 962-974` load **14** (`boot.js`, `app.js`, twelve module files) | `The fourteen files are ordinary parser-blocking scripts` |
| H13 | `app.css:450` and `:460` | `.timeline svg` declared twice (**verified** — one of only three duplicated top-level selectors in the file) | Merge into `:460` |
| H14 | `app.css:793-797` and `:798` | `.login-box h1` declared twice, the second adding only `margin-bottom: 18px` after the first set `margin: 0` (**verified**) | Merge: `margin: 0 0 18px` |
| H15 | `app.css:606` and `:655` | `#page-settings .scroll` declared twice, ~50 lines apart, the second adding the Firefox scrollbar properties (**verified**) | Move `:655` adjacent to `:647-654` where the WebKit rules live |
| H16 | `app.css:567` | `background: var(--accent, var(--muted))` — `--accent` is unconditionally defined at `:root` (`app.css:4-43`), so the fallback is unreachable | `background: var(--accent)` |
| H17 | `app.css:259-263`, `:320-324`, `:339-343`, `:615-619` | Four near-identical "small uppercase label" blocks: `.section`, `.card h3`, `.sidebar h2`, `legend`. All use `font: 600 11px/1 var(--ui)`; `.section`/`.card h3`/`.sidebar h2` use `letter-spacing: 1.4px`, `legend` uses `1.2px`; `.card h3`/`.sidebar h2` apply `text-transform: uppercase` while `.section`/`legend` rely on capitals typed into the markup. **[Corrected: Appendix B's `.section` "declared 4×" is not literally true — there is one `.section {}` rule at `:259`; the duplication is of the declaration block across four selectors.]** | One `%label-caps` block (or a `.caps` utility) applied to all four; one letter-spacing; `text-transform` everywhere |
| H18 | `index.html:20-31, 63-65, 140-141, 214-215, 549-551`, 32 `.section` spans, 64 `<legend>`s | ~110 strings typed in capitals in the markup rather than styled with `text-transform` | Sentence-case the source; let CSS uppercase it |
| H19 | `netpath/theme.py:11-44`, `ssh.js:107-124`, `app.css:4-43` | The palette exists in three places. `ssh.js` reads CSS variables *and* hard-codes a fallback for each; `theme.py` is an independent Qt copy | Generate `theme.py` from `app.css`, or move both to one JSON read at build time. `ssh.js`'s fallbacks should be one `#000`/`#fff` pair, not a second palette |
| H20 | `alerts.js:41`, `configrx.js:23`, `debug.js:24`, `ipam.js:25`, `netflow.js:35`, `nodes.js:42`, `wireless.js:28` | Seven `ago()` copies with four behaviours (convention #24). `debug.js:30` falls back to `App.clock()`, which has no date — a three-day-old event renders as `14:32:07` | One `App.ago()`; delete the seven |
| H21 | `alerts.js:874,949`, `nodes.js:3388,3529`, `nodes.js:3391,3538`, `ipam.js:143,1046` | Four sub-tab wirings, three selector strategies (`> .subtabs >`, bare descendant, `#nd-detail .subtabs >`). **[Corrected: Appendix C says three; it is four — `nodes.js` has both a page-level and a detail-level pair.]** | One `App.wireSubtabs()` |
| H22 | `nodes.js:134-137`, `wireless.js:39-40`, `configrx.js:48-49` | Three byte-identical inline 8 px dot spans that override `app.css:336`'s 10 px `.dot` with inline styles | `App.dot(color)` + a `.dot.sm` class |
| H23 | `app.css:155` | `#nd-detail { display: flex; … }` — an ID selector for a layout concern every other pane solves with `.pane`/`.subpage` | `.detail-pane` class |
| H24 | `index.html:548-551` vs `:554, :585, :599` | IPAM sub-tab **button** order is DHCP, CONFLICTS, SUBNETS & HOSTS; sub-page **DOM** order is subnets, conflicts, dhcp — exactly reversed | Reorder the `.subpage` divs to match the nav |
| H25 | `debug.js:3-6` vs `netpath/eventlog.py:22-34` | `CATEGORY_LABEL` covers 6 of the 11 categories the server emits. `eventlog.py` defines `trace, dns, netflow, snmp, nodes, alerts, ipam, wireless, configrx, system, error`; `debug.js` labels `trace, dns, netflow, ipam, system, error`. The filter row builds from `App.state.categories` (`debug.js:364`), so **`snmp`, `nodes`, `alerts`, `wireless`, `configrx` render as raw lowercase keys** beside six Title-Case labels — visible in `debug-full` | Add the five labels: `SNMP`, `Nodes`, `Alerts`, `Wireless`, `ConfigRX` |
| H26 | `app.css:598-603` | Matching gap: `.cat-trace/-dns/-netflow/-ipam/-system/-error` only. The five unlabelled categories also render uncoloured | Add `.cat-snmp/.cat-nodes/.cat-alerts/.cat-wireless/.cat-configrx` |
| H27 | `debug.js:301` | `link.download = 'sappi-netpath-debug.txt'` | `sappiwhere-debug-log.txt` |
| H28 | `debug.js:292` vs `debug.js:281` | The same events export as `toISOString()` (UTC) and display as `toLocaleString()` (local) | Both local, or both UTC with the zone in the filename/header |
| H29 | `FEATURES.md:13-15` and `FEATURES.md:1819-1822` | Both state the Dashboard aggregates per-permission summaries. `index.html:43-45` is an empty placeholder, and `CHANGELOG.md:1613-1615` correctly says so | Rewrite both FEATURES passages to match the CHANGELOG |
| H30 | `app.js:70-72` | Code comment repeats the same claim: *"'dashboard' is always shown — it aggregates whatever the user can already read"* | Amend to "is a placeholder and is never gated" |
| H31 | `FEATURES.md:46-47`, `README.md:36-37` | *"insists on a new password before anything else"*. `app.js:1019-1023` prompts once per page load, is not `modalLocked`, closes on Escape (capture `login-mustchange-escaped`), and no server route rejects the old password | Either gate it server-side, or write *"asks for a new password on first sign-in"* |
| H32 | `README.md:9` | The tab list omits **Wireless** and **ConfigRX** entirely, and lists Debug/Settings as if they follow IPAM | Add both modules in tab order |
| H33 | `boot.js:19-26`, `app.js:1144`, `app.js:1150` | `'netpath'` as the default tab is written in three places, with a comment (`boot.js:16-17`) noting they must stay in step — and `login.js:39` writes a *fourth* value, `'dashboard'` | One exported constant; one landing rule |
| H34 | `syslog.js:170`, `alerts.js:157` | A hidden-by-default `Severity name` column that, for Syslog, duplicates the visible `Severity` column | Remove from Syslog; for Alerts, make it the visible column (see 2.4) |
| H35 | `wireless.js:59-61` | `wl-last-reported` reads `never reported` with no subject; not covered by any `title` | See 2.2 |

---
