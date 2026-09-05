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
# snmp.js, syslog.js and wireless.js each cached the whole unpaged device
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
# alerts.js, snmp.js and syslog.js each carried a character-for-character
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

print()
if failures:
    print("FAILED %d contract(s):" % len(failures))
    for message in failures:
        print("  - %s" % message)
    sys.exit(1)
print("ALL FRONTEND CONTRACTS HOLD")
