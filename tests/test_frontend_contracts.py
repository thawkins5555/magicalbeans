"""Static invariants of the frontend that no other test can see.

There is no bundler, no linter and no unit test for the browser code in
this repository, so a rule that lives only in a code comment is a rule that
comes back. These are the ones from the 4.41.0 dialog work: each was a
defect that shipped once, each is a one-line grep, and each would otherwise
be re-introduced by the next hand-rolled dialog.

Nothing here parses JavaScript or HTML properly, and it is not trying to.
It reads the shipped files as text and asserts the small number of things
that must be true of them.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "netpath", "web", "static")

failures = []


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
        return handle.read()


def check(condition, message):
    if condition:
        print("OK   %s" % message)
    else:
        print("FAIL %s" % message)
        failures.append(message)


MODULES = [f for f in sorted(os.listdir(STATIC)) if f.endswith(".js")]
INDEX = read("index.html")
APP = read("app.js")

# ---------------------------------------------------------------------------
# 1. No native alert() anywhere.
#
# It cannot name the field it is about, it cannot be styled or positioned,
# it stops the browser to say one sentence, and it is invisible to anything
# not sitting in front of the window. App.showModalError and App.toast are
# what replaced the last two.
alert_calls = []
for name in MODULES:
    for line_no, line in enumerate(read(name).splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        # `App.alert…`, `bulkAlert(` and `.alert(` are not this. Neither is
        # the prose this codebase is full of: "3 alert(s)" in a tooltip, and
        # "native alert()" in the comments explaining why it is gone.
        for match in re.finditer(r"(?<![\w.])alert\s*\(", line):
            tail = line[match.end():match.end() + 2]
            if tail.startswith(")") or tail.startswith("s)"):
                continue
            alert_calls.append("%s:%d" % (name, line_no))
check(not alert_calls, "no native alert() in the frontend (found: %s)"
      % (", ".join(alert_calls) or "none"))

# ---------------------------------------------------------------------------
# 2. Every dialog goes through App.modal, and destructive ones through
#    App.confirmDestructive.
#
# Seven dialogs hand-rolled a Cancel/Remove pair on App.modal. One of them
# closed the dialog before awaiting the delete, so a refusal reported the
# removal of up to forty devices that were all still there. The shape below
# is what those looked like.
hand_rolled = []
for name in MODULES:
    body = read(name)
    for match in re.finditer(r"App\.modal\(\s*['\"](Remove|Delete)\b", body):
        line_no = body.count("\n", 0, match.start()) + 1
        hand_rolled.append("%s:%d" % (name, line_no))
check(not hand_rolled,
      "no hand-rolled Remove/Delete dialogs; they use App.confirmDestructive"
      " (found: %s)" % (", ".join(hand_rolled) or "none"))

# ---------------------------------------------------------------------------
# 3. The modal is a form whose primary button submits it.
#
# Enter did nothing in any dialog in this product until it was: a form field
# with no form around it has nowhere to submit to.
check("<form class=\"modal-form\"" in APP,
      "App.modal wraps the dialog body in a form")
check("button.type = spec.primary ? 'submit' : 'button'" in APP,
      "the primary dialog button is the form's submit button")
check("'.modal-buttons'" in APP,
      "the button row is found by its own class, not by '.row' — three "
      "dialog bodies contain a .row of their own")

# ---------------------------------------------------------------------------
# 4. The dialog action runner exists and nothing bypasses it.
#
# `button.onclick = () => spec.onClick(...)` discarded the promise: that is
# the whole defect, and it is one line to re-introduce.
check("function runModalAction(" in APP,
      "App.modal runs button handlers through runModalAction")
check(not re.search(r"button\.onclick = \(\) => spec\.onClick", APP),
      "no dialog button discards the promise its handler returns")

# ---------------------------------------------------------------------------
# 5. Escape and the backdrop ask before discarding an edit.
check("function requestCloseModal(" in APP,
      "there is a close path that can ask before discarding an edit")
check("if (event.target.id === 'modal') requestCloseModal();" in APP,
      "the backdrop goes through requestCloseModal, not straight to close")
check("else requestCloseModal();" in APP,
      "Escape goes through requestCloseModal, not straight to close")

# ---------------------------------------------------------------------------
# 6. Permission gating disables; it does not hide.
#
# Hiding taught a read-only operator that their install did not have the
# feature, and it could never un-hide, so a permission granted mid-session
# waited for a reload.
check("function applyWriteGate(" in APP,
      "write gating goes through applyWriteGate")
check(not re.search(r"if \(!canWrite\(el\.dataset\.requiresWrite\)\) el\.hidden = true;", APP),
      "write gating no longer hides the control")
check("write-denied-why" in APP and "write-denied-why" in read("app.css"),
      "a disabled control is accompanied by a visible reason, styled")

# ---------------------------------------------------------------------------
# 7. The write controls that had no gate at all.
#
# Each of these ran a write API from a button a read-only account could
# press, and got a 403 with nothing on the page to explain it.
MUST_BE_GATED = {
    "target-add": "netpath", "target-edit": "netpath", "target-remove": "netpath",
    "target-trace": "netpath",
    "ipam-scan-now": "ipam", "ipam-edit-subnet": "ipam", "ipam-add-subnet": "ipam",
    "ipam-poll-now": "ipam", "ipam-edit-dhcp": "ipam", "ipam-add-dhcp": "ipam",
    "nd-bulk-delete": "nodes", "nd-bulk-profile": "nodes", "nd-bulk-group": "nodes",
    "nd-bulk-ungroup": "nodes", "nd-bulk-poll": "nodes", "nd-poll-now": "nodes",
    "disc-start": "nodes", "disc-promote": "nodes",
    "nd-add-profile": "nodes", "nd-edit-profile": "nodes",
    "nd-remove-profile": "nodes", "nd-default-profile": "nodes",
    "nd-upload-mib": "nodes", "nd-resolve-all": "nodes",
    "alerts-add-rule": "alerts", "alerts-edit-rule": "alerts",
    "alerts-remove-rule": "alerts", "alerts-add-template": "alerts",
    "alerts-edit-template": "alerts",
    "wl-oos": "wireless", "wl-remove-ap": "wireless",
    "add-user": "admin", "set-revert": "settings",
}
ungated = []
for element_id, module in sorted(MUST_BE_GATED.items()):
    match = re.search(r"<button id=\"%s\"([^>]*)>" % re.escape(element_id), INDEX)
    if match is None:
        ungated.append("%s (no such button)" % element_id)
    elif 'data-requires-write="%s"' % module not in match.group(1):
        ungated.append(element_id)
check(not ungated, "every write control declares the module it writes to "
      "(ungated: %s)" % (", ".join(ungated) or "none"))

# ---------------------------------------------------------------------------
# 8. The live region and its visible half both exist, exactly once.
check(INDEX.count('id="live"') == 1, "one live region")
check(INDEX.count('id="toasts"') == 1, "one toast region")
check('aria-hidden="true"' in INDEX.split('id="toasts"')[1].split(">")[0]
      or 'id="toasts" class="toasts" aria-hidden="true"' in INDEX,
      "the toast region is hidden from assistive technology — the same text "
      "has already gone through the live region")

# A <button> inside a <form> is a submit button unless told otherwise, and
# modules write buttons into dialog BODIES (vendor Save, OID Walk, MIB Install).
# modal() must type them, or each one also fires the dialog's primary action.
check("form.querySelectorAll('button:not([type])')" in read("app.js")
      and "bodyButton.type = 'button'" in read("app.js"),
      "modal() makes every body button type=button so only the primary submits")

# ---------------------------------------------------------------------------
# 9. One write-only-if-changed guard, in app.js, not one per module.
#
# `if (el && el.PROP !== value) el.PROP = value;` guards a redraw that runs
# on every fastTick — ten times a second whether or not anything changed —
# against re-queuing a DOM mutation for a value that is already there (and,
# for `.style.*`, against cancelling a transition already in flight). Seven
# modules each grew this three times over (setText/setBg/setHtml, ipam.js's
# setHidden a fourth shape of the same idiom) before app.js carried one.
# Matched on the guard's shape, not the name — a `setFoo` or `writeIfChanged`
# would still be this.
GUARD_RE = re.compile(
    r"function\s+\w+\(\s*\w+\s*,\s*\w+\s*\)\s*\{\s*"
    r"if\s*\(\s*\w+\s*&&\s*\w+(?:\.\w+)+\s*!==\s*\w+\s*\)\s*"
    r"\w+(?:\.\w+)+\s*=\s*\w+;\s*\}"
)
guarded = [name for name in MODULES if name != "app.js" and GUARD_RE.search(read(name))]
check(not guarded, "no module re-implements app.js's write-only-if-changed "
      "guard (setText/setBg/setHtml and kin) (found in: %s)"
      % (", ".join(guarded) or "none"))

# ---------------------------------------------------------------------------
# 10. One device-lookup cache, in app.js, not one per module.
#
# "Which device has this IP (or this id)" was answered five times: ipam.js,
# wireless.js and both event pages each cached the whole unpaged device
# list behind a 30-second clock (loadDeviceByIp), and alerts.js kept a
# fifth, differently shaped cache for the same cross-link the other way
# (device id -> ip). What the five share, past the naming, is the idiom: an
# early return on a cache hit — a timestamp still inside its window, or a
# Map that already has the key — standing in front of a fetch of
# /api/nodes/devices. A module fetching that endpoint without caching it
# (a one-off dialog list, say) is not this; the cache-hit idiom is what
# app.js's App.deviceIndex replaced.
TIME_CACHE_HIT = re.compile(r"Date\.now\(\)\s*-\s*\w+\s*<\s*\d+\)\s*return\s+\w+;")
MAP_CACHE_HIT = re.compile(r"\w+\.has\(\w+\)\)\s*return\s+\w+\.get\(\w+\);")
device_cached = []
for name in MODULES:
    if name == "app.js":
        continue
    body = read(name)
    if "/api/nodes/devices" not in body:
        continue
    if TIME_CACHE_HIT.search(body) or (MAP_CACHE_HIT.search(body) and ".set(" in body):
        device_cached.append(name)
check(not device_cached, "no module keeps its own device-by-ip/id cache in "
      "front of /api/nodes/devices; that cache is App.deviceIndex "
      "(found in: %s)" % (", ".join(device_cached) or "none"))

# ---------------------------------------------------------------------------
# 11. One histogram-range narrower, in app.js, not one per module.
#
# alerts.js and both event pages each carried a character-for-character
# copy of the fix for a handful of events inside a day-long window plotting
# as a sliver at the far right of an otherwise-empty chart — one copy's own
# comment admitted it was done "independently in each owned module rather
# than a shared one in app.js". The giveaway is the scan for the first and
# last non-empty bucket and the narrowed flag it returns, not the name
# plottedRange.
PLOTTED_RANGE_RE = re.compile(r"findIndex\(\(\w*\)\s*=>\s*\w+\.total\)")
plotted = []
for name in MODULES:
    if name == "app.js":
        continue
    body = read(name)
    if PLOTTED_RANGE_RE.search(body) and "narrowed: false" in body and "narrowed: true" in body:
        plotted.append(name)
check(not plotted, "no module re-implements the histogram range narrower; "
      "that is App.plottedRange (found in: %s)" % (", ".join(plotted) or "none"))


# ---------------------------------------------------------------------------
# 12. The flattened tab strip (4.49.0) is walked through two scoped helpers,
#     not a bare document-wide query.
#
# `document.querySelectorAll('.tab')` used to reach every top-level tab
# fine on its own, but each call site re-derived "and not hidden" slightly
# differently, and a document-wide query would silently start matching a
# wrapper's own class again if one ever came back. stripTabs()/visibleTabs()
# scope to `:scope > .tab` under #tabs, which is only correct because the
# four labelled wrappers are gone (index.html) — a bare selector surviving
# anywhere is the same defect back.
check("function stripTabs()" in APP and "function visibleTabs()" in APP,
      "the scoped tab-strip helpers exist")
check(":scope > .tab" in APP, "stripTabs() scopes to #tabs's direct children")
# Excludes a backtick-quoted mention of the old pattern inside the helpers'
# own explanatory comment, not a real call site.
bare_tab_query = [m for m in re.finditer(r"document\.querySelectorAll\('\.tab[^-]", APP)
                   if APP[m.start() - 1:m.start()] != "`"]
check(not bare_tab_query,
      "no bare document.querySelectorAll('.tab...') survives outside the "
      "helpers (found %d)" % len(bare_tab_query))

# ---------------------------------------------------------------------------
# 13. The kiosk bar's title promises exactly the digit range the keydown
#     handler implements.
#
# The '1'-'9' shortcut only ever reaches the first nine tabs — three of the
# twelve (SNMP Trap, Settings, Debug, by DOM order) are unreachable this
# way — so index.html's kiosk-bar title has to name the same range the
# handler actually checks, not a bigger one nobody could act on.
digit_range = re.search(r"event\.key < '(\d)' \|\| event\.key > '(\d)'", APP)
check(bool(digit_range), "the digit-shortcut range check is present")
if digit_range:
    lo, hi = digit_range.group(1), digit_range.group(2)
    check('title="Press %s-%s on a connected keyboard' % (lo, hi) in INDEX,
          "the kiosk-bar title promises the same %s-%s the handler "
          "implements (found a different range in index.html)" % (lo, hi))

# ---------------------------------------------------------------------------
# 14. Global search: one failure costs one group, not every group after it,
#     and coverage reaches the endpoints that already exist.
#
# gsearchRun used to wrap all four lookups (MAC, devices, alerts, NetPath)
# in a single try/catch carrying the comment "a failed lookup just leaves
# that group out" — which was not true: an exception partway through
# skipped every group written after it. Matched on shape (an `await get(`
# inside its own `try` block, each followed by its own `catch`), not on a
# fixed count, since a group added later must keep the same shape.
GSEARCH = APP[APP.index("async function gsearchRun("):APP.index("function gsearchRender(")]
gsearch_tries = re.findall(r"try\s*\{[^}]*await get\(", GSEARCH, re.S)
check(len(gsearch_tries) >= 8,
      "gsearchRun wraps each lookup in its own try (found %d, want >= 8)"
      % len(gsearch_tries))
check("catch (error) { /* a failed lookup just leaves that group out */ }" not in APP,
      "the old single try/catch's comment is gone (it never matched the code under it)")
check("get('/api/ipam/search'" in GSEARCH and "IPAM hosts" in GSEARCH,
      "global search reaches IPAM hosts")
check("get('/api/ipam/subnets'" in GSEARCH and "IPAM subnets" in GSEARCH,
      "global search reaches IPAM subnets")
check("/api/syslog/search" in GSEARCH and "'Syslog'" in GSEARCH,
      "global search reaches syslog messages")
check("/api/wireless/aps" in GSEARCH and "Wireless access points" in GSEARCH,
      "global search reaches wireless access points")
check("ConfigRX" in GSEARCH and "search endpoint" in GSEARCH,
      "a marked, not-yet-wired place for ConfigRX search is left in gsearchRun")

# ---------------------------------------------------------------------------
# 15. Eleven of the twelve tab modules are lazy; Dashboard is not.
#
# Thirteen unconditional <script defer> tags (this file plus all twelve
# modules) used to cost 1.17 MB uncompressed on every visit. Only app.js,
# boot.js and dashboard.js may still be unconditional script tags in
# index.html; every other module's tag must be gone, fetched instead by
# app.js's own loader the first time its tab is selected.
EAGER_SCRIPTS = {"app.js", "boot.js", "dashboard.js"}
LAZY_MODULES = [name[:-3] for name in MODULES
                if name.endswith(".js") and name not in EAGER_SCRIPTS
                and name not in ("login.js", "ssh.js")]
check(len(LAZY_MODULES) >= 10, "found the expected set of lazy tab modules (%s)"
      % ", ".join(sorted(LAZY_MODULES)))
tags = re.findall(r'<script src="/(\w[\w.-]*?)\.js\?v=__SW_VERSION__"[^>]*></script>', INDEX)
check(set(tags) == {"boot", "app", "dashboard"},
      "index.html's own <script> tags are exactly boot.js, app.js and "
      "dashboard.js (found: %s)" % (", ".join(sorted(tags)) or "none"))
for name in LAZY_MODULES:
    check('src="/%s.js' % name not in INDEX,
          "%s.js has no <script> tag of its own in index.html (loaded lazily)" % name)
check("function ensureModuleReady(" in APP, "app.js's lazy-module loader exists")
check("function isLazyModule(" in APP and "!== 'dashboard'" in APP,
      "dashboard is the one module lazy loading does not apply to")
check("function activateTab(" in APP,
      "selectTab and applyRoute hand off to a loaded module through one function")
check(APP.count("activateTab(") >= 3,
      "activateTab is used by both selectTab and applyRoute's same-tab branch")
check("moduleLoads.set(name, promise)" in APP or "moduleLoads.get(name)" in APP,
      "concurrent selections of the same not-yet-loaded module share one load")
check("brokenPages.add(name)" in APP.split("function ensureModuleReady(")[1].split("function activateTab(")[0],
      "a module that fails to load degrades through the same brokenPages contract "
      "a module that failed to init() during eager startup already uses")
check('section.setAttribute(\'aria-busy\', \'true\')' in APP,
      "a loading module shows the same in-flight signal an ordinary slow refresh already does")

# ---------------------------------------------------------------------------
# 16. The audit trail (appdb.py's audit table, served at GET /api/audit) has
#     a page that reads it: a Settings subtab, read-only throughout.
SETTINGS = read("settings.js")
check('data-subtab="audit"' in INDEX and 'id="settings-sub-audit"' in INDEX,
      "the Audit subtab and its subpage exist")
check('id="audit-table"' in INDEX and 'id="audit-range"' in INDEX
      and 'id="audit-user"' in INDEX and 'id="audit-action"' in INDEX
      and 'id="audit-target"' in INDEX and 'id="audit-q"' in INDEX
      and 'id="audit-more"' in INDEX,
      "the audit filter bar and table markup exist")
# Read-only end to end: no button in the audit subpage may write anything —
# matched on the subpage's own markup slice, not the whole file, since
# Settings elsewhere is full of legitimate data-requires-write buttons.
audit_markup = INDEX.split('id="settings-sub-audit"')[1].split('<div class="bar footer">')[0]
audit_buttons = re.findall(r'<button[^>]*\bid="([\w-]+)"', audit_markup)
check("data-requires-write" not in audit_markup,
      "the audit subpage has no data-requires-write control (nothing here writes)")
check(bool(audit_buttons) and set(audit_buttons) <= {"audit-apply", "audit-clear", "audit-more"},
      "the audit subpage has no button beyond Search/Clear/Load older (found: %s)"
      % (", ".join(audit_buttons) or "none"))
check("function auditVisible()" in SETTINGS and "App.canRead('admin')" in SETTINGS,
      "the audit subtab is gated on admin READ, matching GET /api/audit's own grant")
check("function auditFetchPage(" in SETTINGS and "'/api/audit'" in SETTINGS,
      "the audit subtab calls the existing /api/audit route rather than inventing a new one")
check("before_id" in SETTINGS and "auditGeneration" in SETTINGS,
      "keyset paging (before_id) exists and a stale in-flight page cannot be appended "
      "after the filters changed (auditGeneration)")
check("payload.rows === undefined && payload.events !== undefined" in SETTINGS,
      "the still-unwired server response is told apart from a genuinely empty result, "
      "not shown as an empty table with no explanation")
check("function auditTargetHtml(" in SETTINGS
      and "kind !== 'device' && kind !== 'configrx'" in SETTINGS,
      "target is parsed as <kind>:<value> and linked for the kinds that already have a page")
check("?target=" in SETTINGS or "opts.query.target" in SETTINGS,
      "the audit subtab reads a target= query param so another page can link back here pre-filtered")
check("function auditIsRoutine(" in SETTINGS and ".audit-row-routine" in read("app.css"),
      "routine actions are visually de-emphasised, not hidden, in the default view")

# ---------------------------------------------------------------------------
# 17. The forced password-change prompt does not depend on a lazy module.
#
# It used to run through `pages.settings.forcePasswordChange`, a one-line
# delegate to `App.accountModal({forced: true})` that both already lived
# beside — and once Settings became a lazy module (loaded on first
# selection, not before), `pages.settings` did not exist yet on the very
# first /api/state poll after login, so the `if` guarding the call was
# false and the dialog silently never opened. The sentinel meant to record
# "we asked" was set unconditionally regardless, so it never got a second
# chance. An administrator left on a fresh install's admin/admin with no
# visible sign anything was owed is as serious as this application's UI
# gets — accountModal is called directly now, and the sentinel is set only
# once that call has actually run.
check("pages.settings" not in APP.split("must_change")[1].split("return payload;")[0],
      "the forced prompt no longer reaches through pages.settings at all")
must_change_block = APP.split("if (payload.session.must_change")[1].split("\n      }")[0]
check("accountModal({ forced: true })" in must_change_block,
      "the forced prompt calls App.accountModal directly")
check("state.promptedChange = true" in must_change_block.split("accountModal({ forced: true })")[1],
      "the sentinel is set AFTER the call that must actually run, not before it")
check("function forcePasswordChange(" not in SETTINGS and "forcePasswordChange," not in SETTINGS,
      "the now-dead one-line delegate is gone from settings.js, not left orphaned")

# ---------------------------------------------------------------------------
# 18. dateShort/stamp reuse one Intl.DateTimeFormat instead of building one
#     per call.
#
# `date.toLocaleDateString(locale, options)` builds a fresh formatter
# internally on every call; dateShort is called once per row through
# timeCell()'s own tooltip title (when(), unconditionally, regardless of
# whether the row's visible text needs a date at all) — profiled live
# against the Debug page's event log (up to 2,000 rows, uncapped on its
# first render): dateShort was the single hottest JS-level function in that
# page's own 200ms-plus long task. Pinned on the constructor call (not the
# word "toLocaleDateString", which the explanatory comment above the fix
# still legitimately says) so a reviewer re-introducing the pattern in a
# fresh function is what this actually catches.
check(re.search(r"new Intl\.DateTimeFormat\(", APP), "a cached Intl.DateTimeFormat exists")
check(APP.count("new Intl.DateTimeFormat(") == 2,
      "exactly two cached formatters (with year, without) — not rebuilt per call")
formatting_block = APP[APP.index("function clock("):APP.index("function span(")]
check(".format(d)" in formatting_block, "dateShort/stamp call .format() on the cached formatter")
code_lines = [line for line in formatting_block.splitlines() if not line.strip().startswith("//")]
check(not any("toLocaleDateString" in line for line in code_lines),
      "no toLocaleDateString call remains in the formatting functions' own code "
      "(the explanatory comment above the fix still legitimately names it)")

# ---------------------------------------------------------------------------
# 19. No lazy module reaches into another lazy module's App.pages.<name>
#     object directly.
#
# Found during the lazy-loading regression hunt prompted by #17's
# forcePasswordChange defect: NetFlow's "→ Route" button called
# App.pages.netpath.activate(...) straight into an object that is undefined
# until netpath.js's own script has run — a fresh session's first click on
# it, before the NetPath tab had ever been opened, threw out of the click
# handler, and the App.selectTab call right after it (meant to load and
# switch to the tab) never ran either, so the click did nothing visible.
# The fix routes the jump through a real hash change instead (see
# netflow.js/netpath.js), the same path every other cross-tab link already
# uses, which goes through app.js's own ensureModuleReady gate before the
# target module's activate() is ever called — a lazy module's App.pages
# entry should never be read from outside app.js itself.
cross_module_pages_access = []
for _name in LAZY_MODULES:
    _text = read("%s.js" % _name)
    for _match in re.finditer(r"App\.pages\.(\w+)\.", _text):
        if _match.group(1) != _name:
            cross_module_pages_access.append(
                "%s.js reaches into App.pages.%s" % (_name, _match.group(1)))
check(not cross_module_pages_access,
      "no lazy module reaches into another module's App.pages object directly "
      "(found: %s)" % "; ".join(cross_module_pages_access))

# ---------------------------------------------------------------------------
# 20. ConfigRX's diff view tells "genuinely identical" apart from "differs
#     only in a redacted value" (O-57).
#
# GET /api/configrx/diff redacts both backups a second time unconditionally,
# so a secret that only changed VALUE (a rotated enable secret, a new SNMP
# community) maps to the identical "<redacted>" token on both sides and no
# line differs — the same empty diff a genuinely identical pair produces.
# `identical` and `redacted_only_change` are the two backups' own sha256
# (never redacted) telling those apart; a UI that renders an empty diff off
# `result.diff` alone shows "no differences" for a config that quietly
# changed. And once that distinction is drawn, it must stop there — no
# masked before/after, no hint at the old or new value, nothing that invites
# turning redaction off to go look.
CONFIGRX = read("configrx.js")
check("redacted_only_change" in CONFIGRX,
      "configrx.js reads the redacted_only_change field the diff route sends")
_diff_render = CONFIGRX[CONFIGRX.index("async function showDiff("):CONFIGRX.index("function closeDiff(")]
check("result.identical" in _diff_render and "result.redacted_only_change" in _diff_render,
      "showDiff branches on both identical and redacted_only_change, not just on an empty diff string")
check(not re.search(r"redacted[\s\S]{0,200}(old value|new value|previous value|became|now reads)",
                    _diff_render, re.I),
      "the redacted-diff message does not hint at the old or new value")

# ---------------------------------------------------------------------------
# 21. The SSH terminal's onclose prefers the server's own explanation over
#     the fixed CLOSE_WORDS table.
#
# sshterm.py closes an idle terminal with code 4408 and a message naming the
# timeout actually in force ("Closed after 10 minute(s) idle" — the lesser
# of IDLE_TIMEOUT_S and the live web-session setting), sent first as a
# status:closed control frame. It arrived, and briefly set #ssh-status
# correctly — then ws.onclose fired a moment later and overwrote it with
# CLOSE_WORDS[4408], a fixed, duration-less phrase, because event.reason
# was never read and the control frame's own message was never kept
# anywhere onclose could see it. Fixed by stashing the message on the
# socket itself (ws.__closeMessage, set only when the frame carried one) —
# not a module-level variable, so a later, unrelated close on a different
# socket cannot see a previous session's explanation, since a fresh
# WebSocket object starts with no such property at all. CLOSE_WORDS stays
# the fallback for the (majority) of closes that carry no message.
SSH = read("ssh.js")
check("__closeMessage" in SSH,
      "ssh.js stashes the server's close message somewhere onclose can read it")
_onclose = SSH[SSH.index("ws.onclose = (event)"):SSH.index("function closeSocket(")]
check("ws.__closeMessage" in _onclose,
      "onclose reads the stashed message")
check(_onclose.index("ws.__closeMessage") < _onclose.index("CLOSE_WORDS[event.code]"),
      "onclose checks the stashed message BEFORE falling back to CLOSE_WORDS, not after")
_handle_control = SSH[SSH.index("function handleControl("):SSH.index("function firstLine(")]
check("ws.__closeMessage = message.message" in _handle_control,
      "the status:closed frame's own message is what gets stashed, on the socket that received it")

# ---------------------------------------------------------------------------
# 22. Polling refresh() cannot overlap itself, and its own stale answer
#     cannot overwrite a newer one (hostile front-end review, 4.50.0).
#
# master()'s only gate used to be `now - page.lastFetch < rateFor(tab)`,
# stamped BEFORE `await page.refresh()` began — so a refresh() slower than
# its own poll interval (precisely what a degrading server produces) let the
# very next 100ms tick launch a second, fully concurrent refresh() for the
# same tab. Separately, events.js recomputes t1 = Date.now() / 1000
# on every Live tick, so two overlapping polls never share a URL and app.js's
# own per-path abort-dedupe (call()) cannot cancel either one; nodes.js's
# devices fetch has the same shape against live filter/pagination controls,
# netpath.js's against the selected target and window, and configrx.js's own
# periodic refresh() (distinct from its search, which already had this)
# against its own filter controls. If the older of two overlapping responses
# lands last, it silently paints a stale window, the wrong filter's devices,
# or a tab the operator has since left. configrx.js's own searchGen (search
# only) and app.js's gsearchRun already carried the fix — a generation
# token, bumped per attempt and checked before painting; this is that same
# pattern applied to master()'s poll gate and each page's periodic refresh(),
# configrx.js's own periodic refresh() included, since it is the file the
# pattern was copied from and so the one place leaving it unfixed would be
# most confusing to the next reader.
check("page.refreshing" in APP,
      "master()'s poll gate does not let a tab's refresh() overlap itself")
for _name in ("events.js", "nodes.js", "netpath.js", "configrx.js", "alerts.js"):
    _body = read(_name)
    check("refreshGen" in _body,
          "%s's periodic refresh() carries a generation token" % _name)
    check(bool(re.search(r"view\.refreshGen\s*!==\s*generation", _body)),
          "%s checks the generation token before painting a response" % _name)

# ---------------------------------------------------------------------------
# 23. A dialog with unsaved changes warns before the browser tab itself
#     closes, not just before Escape/backdrop/Close discard it.
#
# modalDirty already gated Escape, the backdrop and Close, all routed
# through requestCloseModal — but nothing listened for beforeunload, so
# closing the tab mid-edit discarded a half-filled dialog with no warning at
# all, even though every in-app way of leaving the same dialog was
# protected. ssh.js already registers its own beforeunload, for a session it
# has to tear down rather than a form it has to protect.
check(bool(re.search(r"addEventListener\('beforeunload'[\s\S]{0,200}modalDirty", APP)),
      "beforeunload warns when a dialog has unsaved changes (modalDirty)")

# ---------------------------------------------------------------------------
# 24. The two Save buttons that wrote straight to App.put with no
#     double-submit guard now hold themselves down for the life of the
#     request, like every sibling PUT/POST button beside them
#     (#ndd-reidentify, #ndd-install-bundle, #nd-pc-add) already did — PUT is
#     deliberately excluded from app.js's GET abort-dedupe, so a double-click
#     really did fire two concurrent writes.
NODES = read("nodes.js")
_vendor_save = NODES[NODES.index("function renderVendorSection("):
                     NODES.index("function ifaceStatsHtml(")]
check("#ndd-vendor-save" in _vendor_save
      and "save.disabled = true" in _vendor_save and "App.put(" in _vendor_save,
      "#ndd-vendor-save disables itself before its PUT")
_devgroup_save = NODES[NODES.index("function wireDeviceGroupRows("):
                       NODES.index("async function refreshDeviceGroupsList(")]
check("save.disabled = true" in _devgroup_save and "App.put(" in _devgroup_save,
      ".devgroup-save disables itself before its PUT")

# ---------------------------------------------------------------------------
# 25. Forgetting a stored SSH host key and clearing a stored enable secret
#     are both deletions of unrecoverable credential material — the same
#     category "clear SNMP credential" (nodes.js's editDevice) already put
#     behind App.confirmDestructive. Both configrx.js buttons used to act on
#     the click alone, reasoning that their own "danger" styling was warning
#     enough; nodes.js had already made, and documented, the opposite call
#     for the equivalent action, so both now ask first too, the same way
#     every other credential-destroying control in the product does.
_forget = CONFIGRX[CONFIGRX.index("async function drawHostKey("):
                   CONFIGRX.index("function wireEnableSecretClear(")]
check("App.confirmDestructive(" in _forget,
      "#cx-hostkey-forget confirms before deleting the stored host key")
_clear_secret = CONFIGRX[CONFIGRX.index("function wireEnableSecretClear("):
                         CONFIGRX.index("function deviceSettingsModal(")]
check("App.confirmDestructive(" in _clear_secret,
      "#cx-enable-secret-clear confirms before deleting the stored enable secret")

# ---------------------------------------------------------------------------
# 26. Every table sorts by clicking a header, one way or the other. App.grid
#     is the shared, ~30-caller way; the close to twenty tables a module
#     built for itself instead (a dialog's device list, Debug's worker
#     tables, Settings' permission grid) never had either, so app.js now
#     runs a second mechanism for those — App.sortableTable plus a
#     document-level click/keydown pair and the MutationObserver that keeps
#     a redrawn table's sort intact. This is the one-line-of-grep guard that
#     a later pass does not quietly delete half of that (all three, or none,
#     since a click handler with no MutationObserver behind it would lose
#     its sort on the very first live poll tick).
check("function sortableTable(table)" in APP, "app.js defines App.sortableTable")
check(bool(re.search(r"sortableTable\s*,\s*\n?\s*\};", APP))
      or bool(re.search(r"\bsortableTable,", APP[APP.index("const api = {"):])),
      "App.sortableTable is exported on the api object")
check("new MutationObserver" in APP and "reapplyPlainSort" in APP,
      "app.js re-applies a plain table's remembered sort via a MutationObserver")
check(bool(re.search(r"addEventListener\('click',[\s\S]{0,200}th\.sortable", APP))
      and bool(re.search(r"addEventListener\('keydown',[\s\S]{0,300}th\.sortable"
                          r"|addEventListener\('keydown',[\s\S]{0,300}classList\.contains\('sortable'\)", APP)),
      "app.js wires delegated click and keydown handlers for plain sortable headers")

# ---------------------------------------------------------------------------
# 27. Every <table id="..."> placeholder in index.html ends up with a header
#     row one way or another — App.grid builds its own, or the module that
#     fills it writes a <thead> (or a bare first row of <th>) into the
#     markup it hands the table. A table with neither is exactly the gap
#     this pass exists to close: with no header there is nothing for either
#     sort mechanism to attach to, by hand or by the document-level hook.
#
#     This cannot check proximity between the id and its header markup —
#     three different indirections are in play (a direct `App.grid(App.el(
#     'id'), …)`, debug.js's one `drawWorkerTable(id, columns, …)` shared by
#     five tables, events.js's one shared renderer keyed off a `tableId`
#     field in a spec object far from where it is declared) and a fourth is
#     free to appear tomorrow. What it checks instead: the file that
#     mentions the id at all also builds *some* header markup somewhere —
#     which turns "this table was wired up with no header at all" (the
#     failure this pass fixed for real, in nodes.js's CSV-import table) into
#     a fast, if coarse, static check, while two card-style tables that
#     never had column headers (sorted by their own control instead) are
#     named exemptions rather than a loophole the regex could be fooled by.
_HEADERLESS_BY_DESIGN = {"ipam-subnet-table", "ipam-dhcp-scope-table"}
_table_ids = re.findall(r'<table id="([a-zA-Z0-9_-]+)"', INDEX)
_missing_header = []
for _table_id in _table_ids:
    if _table_id in _HEADERLESS_BY_DESIGN:
        continue
    owners = [name for name in MODULES if ("'%s'" % _table_id) in read(name)]
    if not owners or not any(
            "App.grid(" in read(name) or "<thead" in read(name) or re.search(r"<th[ >]", read(name))
            for name in owners):
        _missing_header.append(_table_id)
check(not _missing_header,
      "every <table id> in index.html gets a header row from its renderer (missing: %s)"
      % (", ".join(_missing_header) or "none"))

# ---------------------------------------------------------------------------
# 28. MAPPER (4.54.0 re-review): the one Tab stop a "strands" link gets names
#     the whole link, the legend swatch and colour picker show the colour
#     that is actually drawn, and every write control in mapper.js's own
#     markup is wired into the same data-requires-write re-check every other
#     module's write control already gets.
#
# 28a. drawLink's strands branch used to give EVERY strand — the focusable
#      one (i === 0, the single Tab stop a "strands" link gets) included —
#      the identical per-VLAN aria-label/tooltip, so a keyboard user Tabbing
#      to a seven-VLAN trunk heard "VLAN 10 strand on the link." and nothing
#      about the other six, or either end. linkAriaLabel/linkTooltip (the
#      whole-link text, already used by "collapsed"/"plain" links) were
#      defined but never reached from strands mode at all.
MAPPER = read("mapper.js")
DRAW_LINK = MAPPER[MAPPER.index("function drawLink("):MAPPER.index("function drawPortLabels(")]
check("i === 0" in DRAW_LINK,
      "drawLink's strands branch still singles out the first strand as the one Tab stop")
check("ariaLabel: linkAriaLabel(link)" in DRAW_LINK
      and "tooltip: () => linkTooltip(link)" in DRAW_LINK,
      "the focusable strand (i === 0) is wired to the WHOLE-LINK label/tooltip, "
      "not a per-strand one — a keyboard user's one Tab stop must say every VLAN "
      "and both ends, the same as a collapsed link's single stop already does")
check("`VLAN ${vlanDisplay(strand.vlan)} strand on the link.`" in DRAW_LINK,
      "the non-focusable strands still carry their OWN per-VLAN role=\"img\" label, "
      "so a screen reader's browse cursor can still tell strand N from strand N+1")

# 28b. The VLAN table's swatch and the 16-swatch colour picker used to fill
#      with --vlan-N (tuned against --panel, what the swatch itself sits on)
#      while drawLink strokes the strand itself with --canvas-vlan-N (tuned
#      against --canvas, MAPPER's white drawing surface in every theme but
#      Contrast) — in Dark, Midnight, Nord and Solarized NONE of the sixteen
#      pairs match (Dark: swatch #DA6C6C, strand #862727), so picking
#      "Colour 1" showed a pastel that was never the maroon actually drawn.
#      Both now read the same --canvas-vlan-* family the strand itself uses.
VLAN_TABLE_BLOCK = MAPPER[MAPPER.index("const VLAN_COLUMNS"):MAPPER.index("let vlanSort")]
PICKER_BLOCK = MAPPER[MAPPER.index("function openVlanColorPicker("):
                       MAPPER.index("/* ----------------------------------------------------------- settings */")]
STRAND_STROKE = "stroke: `var(--canvas-vlan-" in DRAW_LINK
check(STRAND_STROKE, "drawLink strokes a strand with --canvas-vlan-N (the pairing "
      "this swatch/picker check assumes stays put)")
check("var(--canvas-vlan-" in VLAN_TABLE_BLOCK and "var(--vlan-" not in VLAN_TABLE_BLOCK,
      "the VLAN table's swatch fills with --canvas-vlan-*, the same family the "
      "strand is stroked with, not the --panel-tuned --vlan-*")
check("var(--canvas-vlan-" in PICKER_BLOCK and "var(--vlan-" not in PICKER_BLOCK,
      "the colour picker's 16 swatches fill with --canvas-vlan-*, matching the "
      "table swatch and the strand stroke")
# --canvas-vlan-* was never tuned against --panel, and the swatch sits on
# --panel (worst case, Nord: ~1.03:1 fill-on-panel, functionally invisible) —
# .mp-swatch needs a border that clears the GRAPHIC_ON 3:1 floor on --panel
# regardless of how the fill itself lands, so the swatch is always at least
# legible as a square. --hairline (a 1.3-1.6:1 surface-step divider in every
# theme) is not that border; --line (>=3.38:1 against --panel everywhere) is.
APP_CSS = read("app.css")
SWATCH_RULE = APP_CSS[APP_CSS.index(".mp-swatch {"):APP_CSS.index(".mp-swatch.selected")]
check("border: 1px solid var(--line)" in SWATCH_RULE,
      ".mp-swatch's border is --line, which clears 3:1 against --panel in every "
      "theme, not --hairline (1.3-1.6:1) which would leave the swatch's own "
      "shape unreadable wherever its --canvas-vlan-* fill sits close to --panel")

# 28c. Every write control mapper.js writes into its own markup (as opposed
#      to a Save/Create/Delete button App.modal renders from a spec object,
#      which every module already leaves ungated the same way) carries
#      data-requires-write="mapper" — the maps dialog's Rename/Delete, the
#      align dialog's eight buttons and the VLAN colour swatch/picker used a
#      one-shot `App.canWrite('mapper') ? '' : 'disabled'` ternary instead
#      and were never wired into applyPermissions()'s re-check, so a write
#      permission revoked while any of those stayed open left a control that
#      still looked enabled until the operator closed and reopened it.
MAPPER_WRITE_MARKERS = [
    "data-rename=", "data-delete=", 'data-align=', "data-vlan-swatch=", "data-color-index=",
]
mapper_ungated = []
for _marker in MAPPER_WRITE_MARKERS:
    for _match in re.finditer(r"<button[^>]*%s[^>]*>" % re.escape(_marker), MAPPER):
        if 'data-requires-write="mapper"' not in _match.group(0):
            _line_no = MAPPER.count("\n", 0, _match.start()) + 1
            mapper_ungated.append("%s:%d" % (_marker, _line_no))
check(bool(MAPPER_WRITE_MARKERS) and all(
    re.search(r"<button[^>]*%s" % re.escape(_marker), MAPPER) for _marker in MAPPER_WRITE_MARKERS),
    "every write-control marker checked below is still present in mapper.js "
    "(a marker renamed out from under this check would silently stop checking anything)")
check(not mapper_ungated,
      "every write control in mapper.js's own markup carries "
      "data-requires-write=\"mapper\" (missing: %s)" % (", ".join(mapper_ungated) or "none"))

# ---------------------------------------------------------------------------
# 29. The device dialog's RESOURCES section (CPU, memory, chassis
#     temperature) shares the packet-loss chart's one /metrics fetch and
#     range control rather than running a chart loop of its own.
check('id="ndd-resources"' in NODES and 'id="ndd-res-head"' in NODES,
      "the RESOURCES holder and heading exist")
check("async function loadCharts(" in NODES and "function loadLoss(" not in NODES,
      "loadLoss became loadCharts rather than gaining a sibling")
for _key in ("cpu_pct", "mem_pct", "temp_chassis_c"):
    check("'%s'" % _key in NODES, "RESOURCES reads the %s metric" % _key)
check(".nd-resources {" in APP_CSS, "app.css lays out the RESOURCES grid")
# 30. The update dialog reads the outcome from the job, not from the POST.
#
# The install runs for far longer than App.post's 30 s deadline -- the
# before-restart hook alone was measured at 37-63 seconds against a real
# fleet -- so a dialog that waited on the single response reported a timeout
# for an update that was quietly succeeding behind it. POST /api/update now
# answers 202 as soon as the job starts, and what actually happened is
# polled from GET /api/update/status.
check("'/api/update/status'" in SETTINGS,
      "settings.js reads the update job's progress from /api/update/status "
      "rather than from the POST that started it")
_CHECK_FOR_UPDATE = SETTINGS[SETTINGS.index("async function checkForUpdate"):
                             SETTINGS.index("async function pollUpdateStatus")]
check("pollUpdateStatus()" in _CHECK_FOR_UPDATE
      and "payload.up_to_date" not in _CHECK_FOR_UPDATE,
      "checkForUpdate hands over to pollUpdateStatus instead of reading an "
      "outcome out of a response that no longer carries one")
check("resumeUpdateIfRunning()" in SETTINGS
      and SETTINGS.count("function resumeUpdateIfRunning") == 1,
      "a browser that reloaded mid-update picks the running job back up "
      "(load() calls resumeUpdateIfRunning) rather than showing an idle "
      "button over an install in flight")
_STEPS = ["checking", "downloading", "extracting", "installing", "restarting"]
check(all(("    %s:" % _s) in SETTINGS for _s in _STEPS),
      "every step the job can report has a line of its own for the operator "
      "to read (%s)" % ", ".join(_STEPS))
# 31. MAPPER (5.0.0): reloading #/mapper/<id> loads that map once, and a
#     page's refresh() cannot be run twice concurrently.
#
# 29a. On a reload, deliverRoute awaits App.refreshNow('mapper') and only
#      then calls activate(). refresh() picked the REMEMBERED map, so the
#      routed one arrived as a second load; and because it stamped
#      view.lastAutoTs only after that first await, the poll tick landing
#      meanwhile started a third. Two of the three raced each other through
#      loadMapData's generation guard and the canvas drew whichever lost.
_REFRESH = MAPPER[MAPPER.index("  async function refresh()"):
                  MAPPER.index("  function forceRefresh()")]
check("App.currentRoute()" in MAPPER,
      "mapper.js reads the route (App.currentRoute) so a reload of "
      "#/mapper/<id> loads the map the URL names, not the remembered one")
check("view.lastAutoTs = " in _REFRESH
      and _REFRESH.index("view.lastAutoTs = ") < _REFRESH.index("selectMap(initial"),
      "refresh() stamps view.lastAutoTs BEFORE awaiting its first selectMap, so "
      "the poll tick that lands mid-load does not start a second one")
check("currentRoute" in APP[APP.index("  const api = {"):],
      "App exports currentRoute, the accessor mapper.js's refresh() reads")

# 29b. master() has refused to overlap a page's refresh() with itself since
#      4.49, but it only set the flag on the refreshes it started itself —
#      a route or tab refresh goes through refreshNow() and was invisible
#      to that guard.
_REFRESH_NOW = APP[APP.index("  function refreshNow(name)"):
                   APP.index("  async function start()")]
check("page.refreshing = true" in _REFRESH_NOW and "page.refreshing = false" in _REFRESH_NOW,
      "refreshNow() marks the page as refreshing for the whole call, so master()'s "
      "own overlap guard covers a route or tab refresh too")

# 29c. A canvas with no frame yet (an empty map, or a pointer reaching the
#      SVG before the first paint) has no scene coordinates at all; reading
#      view.frame.width there was a TypeError on every pointermove.
check("if (!view.frame) return null;" in MAPPER,
      "scenePoint() returns null rather than reading a frame that does not exist yet")

# 29d. Every gesture used to rebuild the whole scene synchronously inside
#      its own event — a pointermove fires faster than a frame, so a drag
#      on a 60-node map redrew it a few hundred times a second. Draws are
#      rAF-coalesced now, and the gestures that change only WHERE the scene
#      sits move one <g> instead of rebuilding it.
check("requestAnimationFrame" in MAPPER,
      "mapper.js coalesces its redraws through requestAnimationFrame")
check("function applyTransform()" in MAPPER and "function redrawDragged()" in MAPPER
      and "function drawRubber()" in MAPPER,
      "pan/zoom, a node drag and the rubber band each have their own partial "
      "redraw rather than going through the full draw()")
_ON_WHEEL = MAPPER[MAPPER.index("  function onSvgWheel("):MAPPER.index("  function zoomBy(")]
check("applyTransform();" in _ON_WHEEL and "draw();" not in _ON_WHEEL,
      "a wheel zoom moves the scene group and does not rebuild the scene")
_DRAW_GRID = MAPPER[MAPPER.index("  function drawGrid("):MAPPER.index("  function vlanDisplay(")]
check("patternUnits: 'userSpaceOnUse'" in _DRAW_GRID and "'line'" not in _DRAW_GRID,
      "the grid is one tiled <pattern> and one rect, not one <line> per grid step")
check(".mp-grid { pointer-events: none; }" in APP_CSS,
      "the grid rect covers the whole drawing, so it must not take pointer events "
      "from the nodes and links underneath it")
_INLINE = MAPPER[MAPPER.index("function inlineComputedColors("):
                 MAPPER.index("function exportPng(")]
check("value.startsWith('url(')" in _INLINE,
      "exportPng leaves a url(#pattern) paint reference alone — the browser reports "
      "it absolutised against this page, which resolves to nothing in the detached "
      "copy the PNG is rendered from, so inlining it would drop the grid")
_PAGES = MAPPER[MAPPER.index("    init, refresh, activate"):]
check("drawLegend" not in _PAGES,
      "the mapper page registration no longer redraws the legend on every fast tick")
_NEIGHBOUR_ROWS = MAPPER[MAPPER.index("    function redrawNeighbourRows()"):
                         MAPPER.index("    redrawNeighbourRows();")]
check("App.grid(" in _NEIGHBOUR_ROWS,
      "redrawNeighbourRows calls App.grid the way drawVlanTable does, so re-sorting "
      "the Add-neighbours dialog replaces its rows instead of appending a second copy")

# 29e. A 200-VLAN trunk listed all 200 in a tooltip that follows the
#      pointer and cannot be scrolled, and all 200 in the detail pane
#      above Last seen. Both are capped, and the pane says how to see the
#      rest.
check("VLAN_TOOLTIP_CAP" in MAPPER and "VLAN_DETAIL_CAP" in MAPPER,
      "the hover text and the detail pane each cap how many VLANs they name")
_LINK_DETAIL = MAPPER[MAPPER.index("  function linkDetailHtml("):
                      MAPPER.index("  /* -------------------------------------------------------- pointer input */")]
check("data-show-all-vlans" in _LINK_DETAIL,
      "linkDetailHtml offers the rest of a capped VLAN list behind a button")
_DRAW_DETAIL = MAPPER[MAPPER.index("  function drawDetail()"):
                      MAPPER.index("  function roleSelectHtml(")]
check("data-show-all-vlans" in _DRAW_DETAIL,
      "drawDetail wires that button — the pane owns its own innerHTML, so it is the "
      "only place that can")
_TOOLTIP_RULE = APP_CSS[APP_CSS.index(".tooltip {"):APP_CSS.index(".tooltip {") + 900]
check("overflow-wrap" in _TOOLTIP_RULE and "max-height" in _TOOLTIP_RULE
      and "white-space: pre-wrap" in _TOOLTIP_RULE,
      ".tooltip wraps a long line and caps its own height, so a wide VLAN list "
      "cannot run off the side or past the bottom of a box nothing can scroll")
# 32. One node per device (5.0.0). The ADDRESSES subtab is wired by the
#     generic nested-subtab machinery, which finds its pane by id alone
#     (App.selectSub with prefix 'nd-d-sub-'), so the button's data-subtab
#     and the pane's id have to agree or the tab opens onto nothing. The
#     Merge button is the one irreversible control in this work and is
#     rendered by App.modal from a spec object, which knows nothing about
#     permissions — the gate has to be stamped on afterwards or a read-only
#     account gets a live Merge button.
check('data-subtab="addresses"' in INDEX and 'id="nd-d-sub-addresses"' in INDEX,
      "index.html has the ADDRESSES subtab button and the pane its prefix "
      "resolves to")
check('id="nd-addr-table"' in INDEX and "drawAddressesTable" in NODES,
      "the addresses pane holds #nd-addr-table and nodes.js draws it")
check('id="nd-duplicates"' in INDEX and "duplicatesDialog" in NODES,
      "the Devices bar has the Duplicates button and nodes.js opens it")
MERGE_BLOCK = NODES[NODES.index("async function mergeDialog("):
                    NODES.index("/* ------------------------------------------------------- bridge & RF")]
check("dataset.requiresWrite = 'nodes'" in MERGE_BLOCK
      and "App.applyPermissions(" in MERGE_BLOCK,
      "mergeDialog stamps data-requires-write=\"nodes\" on its Merge button and "
      "re-runs applyPermissions, so a revoked write settles on the open dialog "
      "instead of leaving an irreversible control enabled")
check("error.status = response.status" in APP and "error.payload = payload" in APP,
      "app.js attaches the status and the body to a failed request's error, which "
      "is what lets the add-device dialog answer a 409 with \"Add anyway\" rather "
      "than only printing it")
check("duplicate_of_device_id" in NODES and "'/api/nodes/duplicates'" in NODES,
      "nodes.js reads the discovery duplicate verdict and the duplicates route")

# 33. Settings -> MODULE SETTINGS opens the module's own dialog (5.0.1).
#     The list used to selectTab() and then synchronously click the
#     module's #xx-settings button, but every module but Dashboard is lazy:
#     on a first visit that button's onclick is not wired yet, the click
#     reached nothing, and the operator was simply left on the module. The
#     entries also have to carry the same write gate as the buttons they
#     press, or a read-only account gets a live control that no-ops.
check("function whenModuleReady(" in APP
      and "selectTab, whenModuleReady," in APP,
      "app.js exports whenModuleReady, so a caller can await a lazy module's "
      "init() before pressing a button that module wires")
_MODULES_PANE = SETTINGS[SETTINGS.index("  function buildModulesPane()"):
                         SETTINGS.index("  /* --------------------------------------------------------- role presets")]
check("await App.whenModuleReady(" in _MODULES_PANE
      and _MODULES_PANE.index("await App.whenModuleReady(")
      < _MODULES_PANE.index("target.click()"),
      "buildModulesPane awaits the module before clicking its settings button, "
      "rather than clicking a handler that is not wired on a first visit")
check("App.state.tab !== tab" in _MODULES_PANE,
      "and gives up if the operator moved to another tab while the module's "
      "script was still loading")
check("App.canRead(tab)" in _MODULES_PANE,
      "the list is filtered on what the account can read, so it never offers a "
      "tab that is hidden")
check("dataset.requiresWrite = tab" in _MODULES_PANE
      and "App.applyPermissions(" in _MODULES_PANE,
      "each entry carries the module's write gate and is gated on the spot - it "
      "is built long after start-up's applyPermissions() walked the page")
_MODULE_DIALOGS = SETTINGS[SETTINGS.index("  const MODULE_DIALOGS = ["):
                           SETTINGS.index("  function buildModulesPane()")]
_pane_ids = re.findall(r"\['([a-z]+)', '[^']+', '([a-z-]+)'\]", _MODULE_DIALOGS)
check(len(_pane_ids) == 10,
      "all ten modules are still listed in MODULE_DIALOGS")
for _tab, _button_id in _pane_ids:
    check('id="%s" class="module-settings" data-requires-write="%s"'
          % (_button_id, _tab) in INDEX,
          "#%s is write-gated on '%s' in index.html, which is the gate the "
          "Settings entry mirrors" % (_button_id, _tab))


# ---------------------------------------------------------------------------
# 34. MAPPER (5.0.1): a click on a node stops moving it, and nothing redraws
#     the canvas out from under a gesture.
#
# 34a. `event.currentTarget` is null once the event that carried it has
#      finished dispatching. onNodePointerDown's `up`/`cancel` closures read
#      it on the release — a TypeError every single time — so `up` never
#      reached its removeEventListener calls: the pointermove listener stayed
#      attached to the node's own <g> and view.nodeDrag was never cleared, and
#      from then on every hover over the map dragged the node the operator had
#      only clicked. The element is captured once, at the press, and the
#      teardown runs in a `finally` so a throw in the write path cannot leave
#      the listeners or the drag state behind either.
_NODE_DRAG = MAPPER[MAPPER.index("  function onNodePointerDown("):
                    MAPPER.index("  function queuePositionWrite(")]
check("const target = event.currentTarget" in _NODE_DRAG,
      "onNodePointerDown captures the node's element once, into the closures it "
      "leaves behind, instead of reading event.currentTarget after dispatch")
check("event.currentTarget.removeEventListener" not in _NODE_DRAG
      and "event.currentTarget.addEventListener" not in _NODE_DRAG,
      "no listener is added to or removed from event.currentTarget, which is null "
      "by the time the drag's own pointermove/pointerup/pointercancel run")
check(_NODE_DRAG.count("target.removeEventListener") == 3
      and _NODE_DRAG.count("target.addEventListener") == 3,
      "all three listeners the press adds are removed again — by the release and "
      "by a cancel alike (a pointercancel that left them on is the same leak)")
check("} finally {" in _NODE_DRAG
      and _NODE_DRAG.index("} finally {") < _NODE_DRAG.index("view.nodeDrag = null"),
      "the release detaches and clears view.nodeDrag in a finally, so a failed "
      "position write cannot leave the map dragging a node nobody is holding")
check("if (!scenePoint(event)) {" in _NODE_DRAG,
      "a press with no scene to move within (no frame yet) selects and starts no "
      "drag, rather than recording a null origin it would subtract from later")

# 34b. The move threshold was 2 SCENE units: at zoom 0.2 that is under half a
#      pixel of pointer travel, so a click registered as a drag and wrote a
#      new position; at zoom 5 it took a centimetre to start one. It is
#      screen pixels now, and the scene units per pixel are read once at the
#      press so a re-fit or a resize mid-gesture cannot rescale the drag
#      under the pointer.
check("const MOVE_THRESHOLD_PX" in MAPPER,
      "the drag threshold is named in screen pixels")
check("MOVE_THRESHOLD_PX" in _NODE_DRAG and "moveEvent.clientX - startClient.x" in _NODE_DRAG,
      "the threshold is measured on the client (screen) delta, not on a delta "
      "already scaled into scene units")
check("const perPixelX" in _NODE_DRAG and "const perPixelY" in _NODE_DRAG,
      "the frame is frozen for the gesture: scene units per screen pixel are "
      "captured at the press")

# 34c. draw() re-fitted on EVERY draw until the operator happened to zoom or
#      pan (`!view.userZoom`), so an auto-refresh, a pane resize or a badge
#      appearing threw away an arrangement they had just made. A map is
#      fitted when it is opened and when Fit is pressed, and not otherwise.
_DRAW = MAPPER[MAPPER.index("  function draw()"):MAPPER.index("  function emptyCanvas(")]
check("if (!view.frame || view.needsFit) {" in _DRAW and "fitView(bounds, width, height);" in _DRAW,
      "draw() fits only a scene with no frame yet or one flagged for a fit, not "
      "every draw the operator has not yet zoomed away from")
check("view.needsFit = false;" in MAPPER[MAPPER.index("  function fitView("):
                                         MAPPER.index("  function translation(")],
      "fitView clears the flag, so one request means one fit")
check("view.needsFit = true;" in MAPPER[MAPPER.index("  async function selectMap("):
                                        MAPPER.index("  function mapForm(")],
      "opening a map (first load, or a switch from the Map dropdown) is what asks "
      "for a fit")
check("App.el('mp-fit').onclick" in MAPPER and "fitView(contentBounds()" in MAPPER,
      "the Fit button still exists and still re-fits on demand")

# 34d. draw() sized the scene from #mp-canvas while every pointer handler
#      measured #mp-svg — the canvas's own 1px border made the two boxes
#      differ in each axis, which lands a press beside the point it was
#      aimed at. One element answers the question everywhere.
check("App.el('mp-canvas').getBoundingClientRect()" not in MAPPER,
      "nothing measures the #mp-canvas wrapper; the scene and every pointer "
      "handler measure #mp-svg, the element the scene is actually drawn in")
check(_DRAW.index("showCanvas(svg, canvas);") < _DRAW.index("svg.getBoundingClientRect()"),
      "draw() measures the SVG after showing it — a canvas coming back from the "
      "empty state is display:none until showCanvas, and would measure as zero")

# 34e. FEATURES.md promises that dragging a node never triggers a refresh.
#      refresh() and the resize handlers redrew regardless, which rebuilt the
#      scene (and the very <g> the pointer was captured on) mid-gesture.
check("function gestureActive()" in MAPPER,
      "one predicate answers whether a gesture is in flight (node drag, rubber "
      "band or pan)")
_MP_REFRESH = MAPPER[MAPPER.index("  async function refresh()"):
                     MAPPER.index("  function forceRefresh()")]
check("gestureActive()" in _MP_REFRESH,
      "refresh() leaves the canvas alone while the operator is mid-gesture")
check("view.nodeDrag" in _MP_REFRESH or "gestureActive" in _MP_REFRESH,
      "refresh()'s guard names the drag state it is protecting")
_INIT = MAPPER[MAPPER.index("  function init()"):]
check("'resize', 'panes-resized'" in _INIT and "!gestureActive()" in _INIT,
      "a window resize or a pane drag redraws only when no gesture is in flight")
_LOAD_MAP_DATA = MAPPER[MAPPER.index("  async function loadMapData()"):
                        MAPPER.index("  /* ---------------------------------------------------------- candidates */")]
check("if (view.nodeDrag) view.nodeDrag = null;" in _LOAD_MAP_DATA,
      "a payload that does land mid-drag (an explicit reload) ends the drag "
      "rather than dropping nodes at coordinates from the payload it replaced")

# ---------------------------------------------------------------------------
# 35. MAPPER (5.0.1): what the browser walk of the module turned up after the
#     click-moves-node fix landed. Four separate defects, each one a control
#     that did nothing or did something else.
#
# 35a. Export PNG could only ever fail. It serialises the live <svg>, wraps
#      it in a Blob and loads that through an Image() before drawing it to a
#      canvas — and the page's own Content-Security-Policy had no img-src, so
#      `default-src 'self'` refused the blob: URL, img.onerror fired and the
#      button's whole visible effect was the toast "Could not render the map
#      to PNG". This is a Python file rather than a shipped static one, but
#      the rule is about the front end: the header is what makes an export
#      the operator can actually run.
_SERVER = os.path.join(REPO_ROOT, "netpath", "web", "server.py")
with open(_SERVER, encoding="utf-8") as _handle:
    SERVER_PY = _handle.read()
check("img-src 'self' blob:" in SERVER_PY,
      "the CSP allows the blob: image MAPPER's Export PNG loads; without an "
      "img-src of its own, default-src 'self' refused it and the button could "
      "only toast a failure")
MAPPER_JS = read("mapper.js")
check("const img = new Image();" in MAPPER_JS and "URL.createObjectURL(svgBlob)" in MAPPER_JS,
      "and Export PNG is still the blob-through-an-Image render that header is "
      "there for")

# 35b. The SELECTION pane is rebuilt from innerHTML on every draw, and the
#      module's own auto-refresh redraws it on its own clock — so a tick
#      landing while the operator was typing a new node name emptied the box
#      mid-word, and Save then wrote the markup's value instead of theirs.
_DETAIL = MAPPER_JS[MAPPER_JS.index("  function drawDetail()"):
                    MAPPER_JS.index("  function renderDetail()")]
check("document.activeElement" in _DETAIL and "detail.contains(active)" in _DETAIL,
      "drawDetail notices when the field being rebuilt is the one the operator "
      "is in")
check("again.value = editing.value" in _DETAIL
      and "again.setSelectionRange(" in _DETAIL
      and "again.focus(" in _DETAIL,
      "and puts their text, their caret and the focus back after the rebuild")
check("  function renderDetail()" in MAPPER_JS
      and "renderDetail();" in _DETAIL,
      "the rebuild itself is renderDetail, called once through that wrapper, so "
      "no caller can skip the restore")

# 35c. Every press on the map calls preventDefault (the drag, the pan and the
#      rubber band all need it), which suppresses the focus the browser would
#      have moved to the canvas. Focus therefore stayed on whatever was last
#      clicked, and the arrow-key pan and +/- zoom that #mp-canvas's own
#      aria-label advertises did nothing at all after a click on the map.
check("function focusCanvas()" in MAPPER_JS,
      "a press on the map moves focus to #mp-canvas itself")
check(MAPPER_JS.count("focusCanvas();") == 3,
      "all three presses that preventDefault — a node, a pan and a rubber band "
      "— focus the canvas, so the keyboard controls its aria-label promises are "
      "live straight after a click")
check("canvas.focus({ preventScroll: true })" in MAPPER_JS,
      "and it does not scroll the page to the canvas that is already under the "
      "pointer")

# 35d. Space is the pan modifier, but it is also how a keyboard activates a
#      focused button — and the browser fires that activation on the key UP,
#      after a whole pan gesture has been drawn. Panning with a toolbar button
#      still focused pressed it again on release: Fit threw away the pan just
#      made, Remove re-opened its destructive confirm.
check("const SPACE_ACTIVATES" in MAPPER_JS,
      "the controls Space activates are named in one place")
_SPACE = MAPPER_JS[MAPPER_JS.index("  function wireSpaceModifier()"):
                   MAPPER_JS.index("  /* --------------------------------------------------------- align tools */")]
check("closest(SPACE_ACTIVATES)" in _SPACE,
      "the pan modifier stands aside when the focus is on something Space would "
      "press, so Space either pans or presses — never both")
check("'INPUT'" in _SPACE and "'TEXTAREA'" in _SPACE and "'SELECT'" in _SPACE,
      "and it still stands aside for a text field, which is the case it already "
      "handled")


# ---------------------------------------------------------------------------
# 36. MAPPER (5.0.1): the follow-up review of the drag fixes.
_MAPPER2 = read("mapper.js")
_NODE_DRAG2 = _MAPPER2[_MAPPER2.index("  function onNodePointerDown("):
                       _MAPPER2.index("  function queuePositionWrite(")]
_DRAW2 = _MAPPER2[_MAPPER2.index("  function draw() {"):
                  _MAPPER2.index("  function draw() {") + 400]
check(_NODE_DRAG2.index("focusCanvas();") < _NODE_DRAG2.index("drawDetail();"),
      "a node press focuses the canvas BEFORE the pane is rebuilt, or the "
      "restore in drawDetail would carry one node's typed name into another's")
check("cdx * perPixelX" in _NODE_DRAG2 and "cdy * perPixelY" in _NODE_DRAG2,
      "the drag delta is the client delta times the per-pixel scale frozen at "
      "the press")
check(_DRAW2.index("view.nodeDrag = null;") < _DRAW2.index("svg.innerHTML = '';"),
      "draw() ends any drag before it replaces the <g> the drag captured, so "
      "the release that can never arrive does not strand the gesture")
check("if (!measured) view.needsFit = true;" in _MAPPER2,
      "a fit into the 200x200 fallback keeps needsFit set, so the first real "
      "layout fits again")
check("window.addEventListener('blur'" in _MAPPER2 and
      "view.panDrag = null; view.rubber = null; view.spaceHeld = false;" in _MAPPER2,
      "a window blur ends every gesture flag, or a release the page never "
      "saw skips refresh for good")
check("a[href]" not in _MAPPER2[_MAPPER2.index("const SPACE_ACTIVATES"):
                                _MAPPER2.index("const SPACE_ACTIVATES") + 120],
      "Space never activates a link, so a focused link must not block the pan")
check("userZoom" not in _MAPPER2 and "dragMoved" not in _MAPPER2,
      "the write-only view flags are gone")


# ---------------------------------------------------------------------------
# 37. Sorting a hand-built table hung the page (5.0.1). sortPlainTable wrote
#     the caret's textContent on every pass; that replaces the text node, a
#     childList mutation the plain-table observer answers by re-applying the
#     sort, which writes the caret again, forever. The glyph is written only
#     when it differs.
_APP_SORT = APP[APP.index("  function sortPlainTable("):APP.index("  function visibleHeaderText(")]
check("caret.textContent !== glyph" in _APP_SORT,
      "the sort caret is rewritten only when its glyph changes, or the "
      "MutationObserver that re-applies a plain table's sort loops on it")


# ---------------------------------------------------------------------------
# 38. NODES (5.1.0): the SFP badge. interfaces.media is the stored signal;
#     the dialog's own /dom read is live and may land second, so either paints.
check("badge badge-sfp" in NODES and "r.media === 'optic'" in NODES,
      "the SFP badge is driven by the stored media column, not by guessing "
      "from the port name")
check(".badge-sfp" in APP_CSS,
      "app.css styles the SFP badge, or it inherits the amber warning fill "
      "every other badge uses")
# 5.2.0: a cage with no DOM is still an SFP slot, so the badge says which
# of the two a port is rather than only appearing for the measurable half.
check("badge badge-dom" in NODES and "r.media === 'sfp_empty'" in NODES,
      "an optic with DOM reads DOM and a cage without it still reads SFP, "
      "empty or not")
check(".badge-dom" in APP_CSS,
      "app.css styles the DOM badge as well, or it inherits the amber "
      "warning fill")
check("No signal" in NODES and "darkOptic(s)" in NODES,
      "a dark optic's dBm reading is rendered as words in the DOM tables, "
      "not as a number that reads like a dying link")
check("sfpBadge(r) + escape(r.descr" in NODES,
      "the badge is prepended to the descr cell, so it is visible in the "
      "default column set rather than behind the column picker")
_DEV_DIALOG = NODES[NODES.index("  function deviceDialog("):
                    NODES.index("  /* ------------------------------------------- temperature alert overrides")]
check("dialogOptics = new Set(" in _DEV_DIALOG
      and _DEV_DIALOG.count("paintDialogIfaces()") >= 2,
      "the device dialog's /dom response patches the fetched interface rows "
      "and repaints, so the badge shows whichever fetch lands second")
check("view.ifaces =" not in _DEV_DIALOG,
      "and that patch stays in the dialog's own closure — view.ifaces "
      "describes the selected device, not the one this dialog opened")


# 41. STORAGE (5.1.0): "oldest record N ago" beside each data file, from
#     /api/state's {name}_oldest_ts, rendered where the byte counts already are.
_SETTINGS41 = read("settings.js")
_USAGE41 = _SETTINGS41[_SETTINGS41.index("  function showUsage(storage) {"):
                       _SETTINGS41.index("  function status(message, colour) {")]
check("`oldest record ${App.ago(ts)}`" in _USAGE41,
      "the age is rendered through App.ago, the one place that turns an epoch "
      "into a relative figure")
check("'no history'" in _USAGE41,
      "...and a store that has never been written to says so, rather than "
      "showing an epoch of 0 as 1970")
check("_oldest_ts'" in _USAGE41,
      "the keys read are the {name}_oldest_ts the storage block carries")
for _id in ("age-app", "age-trace", "age-flow", "age-snmp", "age-syslog",
            "age-ipam", "age-nodes", "age-nodes-series", "age-nodes-mibs",
            "age-alerts"):
    check('id="%s"' % _id in INDEX and "'%s'" % _id in _USAGE41,
          "the %s span exists in the page and is filled in by showUsage" % _id)


# 42. ConfigRX (5.1.0): the CHANGE DETECTION fieldset for ignore_line_patterns,
#     the operator-editable companion to configrx_volatile.VOLATILE.
_CX_SETTINGS = CONFIGRX[CONFIGRX.index("function settingsDialog()"):
                        CONFIGRX.index("  /* ------------------------------------------------------------- search")]
check("CHANGE DETECTION" in _CX_SETTINGS,
      "the settings dialog has a fieldset for the volatile-line ignore list, "
      "not just SCHEDULE/RETENTION/SSH")
check('id="cxs-ignore"' in _CX_SETTINGS,
      "the ignore-patterns textarea has the id the save handler reads")
check("s.ignore_line_patterns" in _CX_SETTINGS,
      "the textarea is seeded from the settings the dialog was opened with, "
      "not left blank on every reopen")
check("ignore_line_patterns: m.querySelector('#cxs-ignore').value," in _CX_SETTINGS,
      "Save posts the textarea's own value under the exact key "
      "configrxdb.DEFAULTS and api.post_settings expect")
check("ntp clock-period" in _CX_SETTINGS,
      "the hint names at least one built-in exclusion, so an operator can "
      "tell a site-specific line from one already handled before adding a "
      "redundant pattern")



# ---------------------------------------------------------------------------
# 39. ALERTS (5.1.0): the rule comparison direction and the email severity
#     floor — a select the save map never reads is a control that does nothing.
_ALERTS_JS = read("alerts.js")
check("id=\"ar-comparison\"" in _ALERTS_JS,
      "the rule editor offers the comparison direction, or a 'below' rule "
      "can only be made by hand in the database")
check("values.comparison = box.querySelector('#ar-comparison').value;" in _ALERTS_JS,
      "and the Save handler actually sends it")
check("id=\"as-notify-minsev\"" in _ALERTS_JS,
      "the alerts settings dialog offers the email severity floor")
check("notify_min_severity: Number(box.querySelector('#as-notify-minsev').value)"
      in _ALERTS_JS,
      "and it is saved under the key the engine reads, not beside it")
check("'alerts.settings.notifyminsev'" in _ALERTS_JS
      and "App.helpLink('alerts.settings.notifyminsev')" in _ALERTS_JS,
      "the floor's help entry is both registered and linked -- the ingest "
      "filter and the email floor are one word apart and read as each other")
_MINSEV_HELP = _ALERTS_JS[_ALERTS_JS.index("'alerts.settings.minsev'"):
                          _ALERTS_JS.index("'alerts.settings.notifyminsev'")]
check("EMAIL SERVER" in _MINSEV_HELP,
      "and the ingest filter's own help points at the floor, so nobody sets "
      "the wrong one")


# 40. The WEB relay (5.1.0): must not regress — a URL in the markup, a
#     missing permission gate, or a window.open placed after an await.
_WEB_CLICK = NODES[NODES.index("  async function webDevice()"):
                   NODES.index("  /* ------------------------------------------------------------ profiles */")]
check("dataset.url" not in NODES,
      "no device URL is stashed in the markup any more -- the destination "
      "comes from the device row, server-side, and the button carries a "
      "device selection and nothing else")
check(_WEB_CLICK.index("window.open(") < _WEB_CLICK.index("await App.post("),
      "the tunnel window is opened synchronously inside the click and its "
      "location set once the POST answers; a window.open after an await is "
      "no longer user-initiated and every popup blocker eats it")
check("w.opener = null" in _WEB_CLICK,
      "and its opener is cleared, since `noopener` in the feature string "
      "would discard the per-device window name")
check("if (w) w.close();" in _WEB_CLICK,
      "a refused tunnel closes the window it claimed rather than leaving a "
      "blank one on screen")
check('data-requires-write="web"' in INDEX,
      "the WEB button is gated on the web permission in the markup")
check("canWrite('web')" in NODES,
      "and in the handler, so a page that missed applyPermissions still "
      "cannot POST a relay open")
check("'#nd-f-webscheme'" in NODES and "'#nd-f-webport'" in NODES,
      "deviceOverrides carries the two WEB INTERFACE fields, so Add sets "
      "them as well as Edit")
check("web: 'Web'" in APP,
      "MODULE_NAMES names the web module, or a write refusal on it reads as "
      "'Your account can read web but not change it'")
check("'admin', 'ssh', 'web'" in SETTINGS,
      "the viewer role preset grants no web, which has no read tier to give")
check("set-web-relay-range" in INDEX and "web_relay_port_range" in SETTINGS,
      "the relay port range is an administrator-only Settings field, saved "
      "the way every other Apply field is")


# 43. NetFlow (5.2.0): the rollup retentions are settings like any other, so
#     the STORAGE fieldset carries them and Save posts them under the keys
#     flowdb.DEFAULTS names.
_NETFLOW = read("netflow.js")
_NF_SETTINGS = _NETFLOW[_NETFLOW.index("  function settingsDialog() {"):
                        _NETFLOW.index("  async function sendTestPacket() {")]
_NF_STORAGE = _NF_SETTINGS[_NF_SETTINGS.index("STORAGE AND DISPLAY"):
                           _NF_SETTINGS.index("columnPickerFieldset")]
for _id, _key in (("n-rollup-min", "rollup_minute_days"),
                  ("n-rollup-days", "rollup_retention_days")):
    check("'%s'" % _id in _NF_STORAGE,
          "the %s field sits in the STORAGE fieldset beside the flow "
          "retention it outlives" % _id)
    check("s.%s" % _key in _NF_STORAGE,
          "...seeded from the settings the dialog was opened with")
    check("%s: num('#%s')" % (_key, _id) in _NF_SETTINGS,
          "...and posted to /api/settings under %s" % _key)
check("summaries, not from the records" in _NF_STORAGE,
      "the hint says what a chart older than the flow retention is drawn "
      "from, which is the only reason the two fields exist")
check("scan_bounded" in _NETFLOW,
      "the record list reads the server's scan bound rather than implying "
      "it ordered every record in the window")


print()
if failures:
    print("FAILED %d contract(s):" % len(failures))
    for message in failures:
        print("  - %s" % message)
    sys.exit(1)
print("ALL FRONTEND CONTRACTS HOLD")
