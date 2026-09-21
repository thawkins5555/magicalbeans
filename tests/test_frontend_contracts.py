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

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _source import js_function, js_functions, js_const, css_rule, python_text, static_text

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
GSEARCH = js_function(APP, "gsearchRun")
gsearch_tries = re.findall(r"try\s*\{[^}]*await get\(", GSEARCH, re.S)
check(len(gsearch_tries) >= 10,
      "gsearchRun wraps each lookup in its own try (found %d, want >= 10)"
      % len(gsearch_tries))
check("catch (error) { /* a failed lookup just leaves that group out */ }" not in APP,
      "the old single try/catch's comment is gone (it never matched the code under it)")
check("get('/api/ipam/search'" in GSEARCH and "IPAM hosts" in GSEARCH,
      "global search reaches IPAM hosts")
check("get('/api/ipam/subnets'" in GSEARCH and "IPAM subnets" in GSEARCH,
      "global search reaches IPAM subnets")
# The MAC group names the switch PORT in its title (the report was that
# global search should find a MAC on Node switch ports — it did, and the
# title never said so) and keeps the port route; the ARP group beside it
# routes to the device's ARP pane and never to /port/<if_index>, since an
# ARP row's ifIndex is a routed VLAN, not a physical port. The lease group
# has its own endpoint because /api/ipam/search folds leases into hosts.
check("'MAC address on a switch port'" in GSEARCH
      and "/port/${loc.if_index}" in GSEARCH,
      "the MAC group's title names the switch port and it still routes to the port")
check("get('/api/nodes/arp-search'" in GSEARCH and "'ARP cache (IP to MAC)'" in GSEARCH,
      "global search reaches the ARP caches, titled as the IP-to-MAC mapping")
ARP_GROUP = GSEARCH[GSEARCH.index("get('/api/nodes/arp-search'"):
                    GSEARCH.index("'Switch port for that IP (ARP")]
check("`#/nodes/device/${loc.device_id}/arp`" in ARP_GROUP
      and "/port/${loc.if_index}" not in ARP_GROUP,
      "an ARP hit routes to the device's ARP pane, not to a port dialog")
# The IP -> MAC -> switch port chain: an ARP-search response that carries
# ports (the needle matched as an address, not a MAC prefix) gets its own
# group, routed to the port dialog like the MAC group above.
check("'Switch port for that IP (ARP" in GSEARCH and "arp.ports" in GSEARCH
      and "/port/${p.if_index}" in GSEARCH,
      "global search follows an ARP hit's MAC on to the switch port it was "
      "learned on")
check("addressEnabledDevices" in GSEARCH and "gsearchRender(groups, notes)" in GSEARCH,
      "a hint is built from enabled_devices across the address lookups and "
      "passed to gsearchRender alongside the groups")
check("No forwarding tables or ARP caches have been collected yet" in APP,
      "the hint's wording matches what the plan promised the operator")
check("get('/api/ipam/dhcp/lease-search'" in GSEARCH and "'DHCP leases'" in GSEARCH,
      "global search reaches DHCP leases through their own endpoint")
_GSEARCH_RENDER = js_function(APP, "gsearchRender")
GSEARCH_EMPTY = _GSEARCH_RENDER[_GSEARCH_RENDER.index('class="gsearch-empty"'):
                                 _GSEARCH_RENDER.index("</p>'", _GSEARCH_RENDER.index('class="gsearch-empty"'))]
check("ARP" in GSEARCH_EMPTY and "DHCP leases" in GSEARCH_EMPTY,
      "the empty-state text names ARP and DHCP leases among what the box searches")
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
formatting_block = js_functions(APP, "clock", "stamp")
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
_diff_render = js_function(CONFIGRX, "showDiff")
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
_connect = js_function(SSH, "connect")
_onclose = _connect[_connect.index("ws.onclose = (event)"):]
check("ws.__closeMessage" in _onclose,
      "onclose reads the stashed message")
check(_onclose.index("ws.__closeMessage") < _onclose.index("CLOSE_WORDS[event.code]"),
      "onclose checks the stashed message BEFORE falling back to CLOSE_WORDS, not after")
_handle_control = js_function(SSH, "handleControl")
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
_vendor_save = js_function(NODES, "renderVendorSection")
check("#ndd-vendor-save" in _vendor_save
      and "save.disabled = true" in _vendor_save and "App.put(" in _vendor_save,
      "#ndd-vendor-save disables itself before its PUT")
_devgroup_save = js_function(NODES, "wireDeviceGroupRows")
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
_forget = js_function(CONFIGRX, "drawHostKey")
check("App.confirmDestructive(" in _forget,
      "#cx-hostkey-forget confirms before deleting the stored host key")
_clear_secret = js_function(CONFIGRX, "wireEnableSecretClear")
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
      or bool(re.search(r"\bsortableTable,", js_const(APP, "api"))),
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
DRAW_LINK = js_function(MAPPER, "drawLink")
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
VLAN_TABLE_BLOCK = js_const(MAPPER, "VLAN_COLUMNS")
PICKER_BLOCK = js_function(MAPPER, "openVlanColorPicker")
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
SWATCH_RULE = css_rule(APP_CSS, ".mp-swatch")
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

# 28d. 5.16.0 mapper legibility: port/VLAN labels live in their own layer
#      above every link and carry a canvas-coloured halo; the node box is
#      wider with a longer name cut; a Drag pans checkbox turns left-drag on
#      empty canvas into a pan and is a per-browser preference, not a write.
# 5.18.0: the label layer moved above the node layer too, so a label is
#      never painted under a node box.
INDEX_HTML = read("index.html")
check("group.append(gridLayer, frameLayer, linkLayer, nodeLayer, labelLayer, noteLayer)" in MAPPER,
      "the label layer paints above both links and node boxes; frameLayer "
      "(5.31.0) sits between the grid and the links so a frame paints under "
      "both; noteLayer sits above everything, last, so a note reads over "
      "whatever it annotates")
check("function drawLink(layer, link, labelLayer = layer)" in MAPPER
      # 3: the per-strand VLAN number, the collapsed-trunk VLAN count, and
      # (5.23.0, D2) a manual line's own label.
      and MAPPER.count("labelLayer.appendChild(App.svgNode('text'") == 3
      and "drawPortLabels(labelLayer, link" in MAPPER,
      "every link label is appended to the label layer, none to the link holder")
check("paint-order: stroke; stroke: var(--canvas)" in APP_CSS,
      "link labels carry a canvas-coloured halo")
check("'paint-order'" in MAPPER, "the PNG export inlines the halo's paint-order")
check("const NODE_W = 176" in MAPPER and "truncate(info.name, 24)" in MAPPER,
      "the node box is wider and shows more of the name")
check('id="mp-drag-pans"' in INDEX_HTML and 'data-requires-write' not in
      INDEX_HTML[INDEX_HTML.index('id="mp-drag-pans"') - 120:INDEX_HTML.index('id="mp-drag-pans"')],
      "the Drag pans checkbox exists and is not a write control")
check("if (view.dragPans) {" in MAPPER and "localStorage.getItem('mapper.dragPans')" in MAPPER,
      "left-drag pans when the box is ticked and the choice is remembered per browser")
check('id="mp-fiberview"' in INDEX_HTML and 'data-requires-write' not in
      INDEX_HTML[INDEX_HTML.index('id="mp-fiberview"') - 120:INDEX_HTML.index('id="mp-fiberview"')],
      "the FiberView checkbox exists and is not a write control")
check("localStorage.getItem('mapper.fiberView')" in MAPPER and "dataset.fiberview" in MAPPER,
      "FiberView is remembered per browser and toggles #mp-canvas's data attribute")
check("classList.add('fiber')" in MAPPER,
      "drawLink tags a link.fiber link (plain/collapsed path, strands underlay) with the .fiber class")
check("--mp-fiber-w" in MAPPER,
      "drawLink sets the fiber glow's bold width, in px, as --mp-fiber-w")
check("'mp-link fiber'" in MAPPER,
      "the strands-mode fiber underlay is one lone path (no wireOne) beneath the VLAN-coloured strands")
check("'dominant-baseline', 'filter']" in MAPPER,
      "the PNG export inlines the fiber glow's filter property")
check("function fanOffsets(" in MAPPER and "view.linkFan" in MAPPER,
      "draw() computes one fan offset per link (parallel cables between the "
      "same two nodes), and drawLink reads it from view.linkFan")
check("NAME_SOURCES" in MAPPER and "node.name_source" in MAPPER,
      "the node tooltip names the source of the displayed name")

# 28e. 5.16.0: the TEMPERATURE ALERTS block ends with the per-sensor table,
#      read from the stored /sensors route, never a live walk.
check("async function renderSensorTable(" in NODES and "/sensors`" in NODES
      and 'id="ndd-sensors"' in NODES,
      "Device Details renders the per-sensor table from /api/nodes/devices/<id>/sensors")

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
_CHECK_FOR_UPDATE = js_function(SETTINGS, "checkForUpdate")
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
_REFRESH = js_function(MAPPER, "refresh")
check("App.currentRoute()" in MAPPER,
      "mapper.js reads the route (App.currentRoute) so a reload of "
      "#/mapper/<id> loads the map the URL names, not the remembered one")
check("view.lastAutoTs = " in _REFRESH
      and _REFRESH.index("view.lastAutoTs = ") < _REFRESH.index("selectMap(initial"),
      "refresh() stamps view.lastAutoTs BEFORE awaiting its first selectMap, so "
      "the poll tick that lands mid-load does not start a second one")
check("currentRoute" in js_const(APP, "api"),
      "App exports currentRoute, the accessor mapper.js's refresh() reads")

# 29b. master() has refused to overlap a page's refresh() with itself since
#      4.49, but it only set the flag on the refreshes it started itself —
#      a route or tab refresh goes through refreshNow() and was invisible
#      to that guard. Since 5.3.0 both go through one runner, so the flag,
#      the busy line and the connected() bookkeeping cannot drift apart.
_MASTER = js_function(APP, "master")
_RUN_REFRESH = js_function(APP, "runRefresh")
_REFRESH_NOW = js_function(APP, "refreshNow")
check("page.refreshing = true" in _RUN_REFRESH and "page.refreshing = false" in _RUN_REFRESH,
      "the refresh runner marks the page as refreshing for the whole call, so "
      "master()'s own overlap guard covers a route or tab refresh too")
check("runRefresh(" in _REFRESH_NOW and "await runRefresh(" in _MASTER,
      "...and both the poll tick and a direct request go through that one "
      "runner rather than each keeping its own copy of it")
check("section.setAttribute('aria-busy', 'true')" in _RUN_REFRESH,
      "a direct refresh raises the busy line too, not only the poll tick — "
      "every NetFlow window change goes through refreshNow(), which showed "
      "nothing at all while it worked")
_SETTLED = _RUN_REFRESH[_RUN_REFRESH.index("}).then((value) => {"):]
check("section.removeAttribute('aria-busy')" in _SETTLED
      and "page.refreshing = false" in _SETTLED,
      "...and clears it where it clears `refreshing`, after the rejection "
      "handler, so a failed refresh cannot leave the page stuck busy")
check("page.trailing" in _REFRESH_NOW,
      "a request arriving while one is in flight queues a single trailing "
      "refresh, so N window changes are not N concurrent refresh() calls")

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
_ON_WHEEL = js_function(MAPPER, "onSvgWheel")
check("applyTransform();" in _ON_WHEEL and "draw();" not in _ON_WHEEL,
      "a wheel zoom moves the scene group and does not rebuild the scene")
_DRAW_GRID = js_function(MAPPER, "drawGrid")
check("patternUnits: 'userSpaceOnUse'" in _DRAW_GRID and "'line'" not in _DRAW_GRID,
      "the grid is one tiled <pattern> and one rect, not one <line> per grid step")
check(".mp-grid { pointer-events: none; }" in APP_CSS,
      "the grid rect covers the whole drawing, so it must not take pointer events "
      "from the nodes and links underneath it")
_INLINE = js_function(MAPPER, "inlineComputedColors")
check("value.startsWith('url(')" in _INLINE,
      "exportPng leaves a url(#pattern) paint reference alone — the browser reports "
      "it absolutised against this page, which resolves to nothing in the detached "
      "copy the PNG is rendered from, so inlining it would drop the grid")
_PAGES = MAPPER[MAPPER.index("    init, refresh, activate"):]
check("drawLegend" not in _PAGES,
      "the mapper page registration no longer redraws the legend on every fast tick")
_NEIGHBOUR_ROWS = js_function(MAPPER, "redrawNeighbourRows")
check("App.grid(" in _NEIGHBOUR_ROWS,
      "redrawNeighbourRows calls App.grid the way drawVlanTable does, so re-sorting "
      "the Add-neighbours dialog replaces its rows instead of appending a second copy")

# 29e. A 200-VLAN trunk listed all 200 in a tooltip that follows the
#      pointer and cannot be scrolled, and all 200 in the detail pane
#      above Last seen. Both are capped, and the pane says how to see the
#      rest.
check("VLAN_TOOLTIP_CAP" in MAPPER and "VLAN_DETAIL_CAP" in MAPPER,
      "the hover text and the detail pane each cap how many VLANs they name")
_LINK_DETAIL = js_function(MAPPER, "linkDetailHtml")
check("data-show-all-vlans" in _LINK_DETAIL,
      "linkDetailHtml offers the rest of a capped VLAN list behind a button")
_DRAW_DETAIL = js_functions(MAPPER, "drawDetail", "renderDetail")
check("data-show-all-vlans" in _DRAW_DETAIL,
      "drawDetail wires that button — the pane owns its own innerHTML, so it is the "
      "only place that can")
_TOOLTIP_RULE = css_rule(APP_CSS, ".tooltip")
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
# The ARP subtab is wired by the same machinery, so the same pairing rule.
check('data-subtab="arp"' in INDEX and 'id="nd-d-sub-arp"' in INDEX,
      "index.html has the ARP subtab button and the pane its prefix resolves to")
check('id="nd-arp-table"' in INDEX and "function drawArpTable(" in NODES
      and "arp: { path: 'arp'" in NODES,
      "the ARP pane holds #nd-arp-table, nodes.js draws it and DETAIL_SUBS fetches it")
check("view.arpEnabled === false" in NODES and "Read the ARP cache every" in NODES,
      "the ARP pane tells 'walk switched off' from 'nothing collected yet' and names the setting")
ARP_DRAW = js_function(NODES, "drawArpTable")
check("nd-arp-mac" in ARP_DRAW and "view.macSearchPending = true" in ARP_DRAW
      and "App.refreshNow('nodes')" in ARP_DRAW,
      "an ARP row's MAC cell reuses the Find box's own MAC search (the Enter path) "
      "rather than a copy of it")
check("/arp/export.csv" in ARP_DRAW and "nd-arp-export-csv" in ARP_DRAW,
      "the ARP pane has its own export, wired the way the neighbours pane's is")
check("parts[2] === 'arp'" in NODES and "selectDetailSub('arp')" in NODES,
      "#/nodes/device/<id>/arp opens the device and its ARP pane")
check('id="nd-duplicates"' in INDEX and "duplicatesDialog" in NODES,
      "the Devices bar has the Duplicates button and nodes.js opens it")
MERGE_BLOCK = js_function(NODES, "mergeDialog")
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
# Re-discover starts a subnet sweep and the row it sits on is not redrawn
# until the POST answers, so a live button is two sweeps for two clicks. The
# server refuses the second one, but a button that stays clickable while it
# works is the defect the refusal exists to survive, not a design.
_REDISCOVER = js_function(NODES, "rediscover")
check("button.disabled = true" in _REDISCOVER
      and "rediscover(job, e.target)" in NODES,
      "the Re-discover button is handed to rediscover() and disabled for the "
      "duration of its POST, the way every other button here that starts "
      "something is")

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
_MODULES_PANE = js_function(SETTINGS, "buildModulesPane")
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
_MODULE_DIALOGS = js_const(SETTINGS, "MODULE_DIALOGS")
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
_NODE_DRAG = js_function(MAPPER, "onNodePointerDown")
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
_DRAW = js_function(MAPPER, "draw")
check("if (!view.frame || view.needsFit) {" in _DRAW and "fitView(bounds, width, height);" in _DRAW,
      "draw() fits only a scene with no frame yet or one flagged for a fit, not "
      "every draw the operator has not yet zoomed away from")
check("view.needsFit = false;" in js_function(MAPPER, "fitView"),
      "fitView clears the flag, so one request means one fit")
check("view.needsFit = true;" in js_function(MAPPER, "selectMap"),
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
_MP_REFRESH = js_function(MAPPER, "refresh")
check("gestureActive()" in _MP_REFRESH,
      "refresh() leaves the canvas alone while the operator is mid-gesture")
check("view.nodeDrag" in _MP_REFRESH or "gestureActive" in _MP_REFRESH,
      "refresh()'s guard names the drag state it is protecting")
_INIT = js_function(MAPPER, "init")
check("'resize', 'panes-resized'" in _INIT and "!gestureActive()" in _INIT,
      "a window resize or a pane drag redraws only when no gesture is in flight")
_LOAD_MAP_DATA = js_function(MAPPER, "loadMapData")
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
_DETAIL = js_function(MAPPER_JS, "drawDetail")
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
check(MAPPER_JS.count("focusCanvas();") == 9,
      "the four presses that preventDefault — a node, a pan, a Drag-pans pan and "
      "a rubber band — still focus the canvas, so the keyboard controls its "
      "aria-label promises are live straight after a click; 5.31.0 adds three "
      "more (the framing drag, a frame press in onFramePointerDown, and "
      "centerOn's Find), and notes add two more of their own (the noting "
      "drag, a note press in onNotePointerDown)")
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
_SPACE = js_function(MAPPER_JS, "wireSpaceModifier")
check("closest(SPACE_ACTIVATES)" in _SPACE,
      "the pan modifier stands aside when the focus is on something Space would "
      "press, so Space either pans or presses — never both")
check("'INPUT'" in _SPACE and "'TEXTAREA'" in _SPACE and "'SELECT'" in _SPACE,
      "and it still stands aside for a text field, which is the case it already "
      "handled")


# ---------------------------------------------------------------------------
# 36. MAPPER (5.0.1): the follow-up review of the drag fixes.
_MAPPER2 = read("mapper.js")
_NODE_DRAG2 = js_function(_MAPPER2, "onNodePointerDown")
_DRAW2_FULL = js_function(_MAPPER2, "draw")
_DRAW2 = _DRAW2_FULL[:400]
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
check("a[href]" not in js_const(_MAPPER2, "SPACE_ACTIVATES"),
      "Space never activates a link, so a focused link must not block the pan")
check("userZoom" not in _MAPPER2 and "dragMoved" not in _MAPPER2,
      "the write-only view flags are gone")


# ---------------------------------------------------------------------------
# 37. Sorting a hand-built table hung the page (5.0.1). sortPlainTable wrote
#     the caret's textContent on every pass; that replaces the text node, a
#     childList mutation the plain-table observer answers by re-applying the
#     sort, which writes the caret again, forever. The glyph is written only
#     when it differs.
_APP_SORT = js_function(APP, "sortPlainTable")
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
check("s.value === 0" not in NODES,
      "0 dBm is 1 mW -- a nominal ER/ZR transmit level, and what an agent "
      "quoting 0.1 dBm units rounds -0.04 to -- so it must read as the "
      "figure it is, never as 'No signal'")
check("sfpBadge(r) + escape(r.descr" in NODES,
      "the badge is prepended to the descr cell, so it is visible in the "
      "default column set rather than behind the column picker")
_DEV_DIALOG = js_function(NODES, "deviceDialog")
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
_USAGE41 = js_function(_SETTINGS41, "showUsage")
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
_CX_SETTINGS = js_function(CONFIGRX, "settingsDialog")
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
# ANCHOR-TODO: these are two keys inside one App.registerHelp({...}) object
# literal, not a function or a top-level const — no _source.py helper
# extracts a call-expression's object literal by key, so this stays a
# same-file text slice.
_MINSEV_HELP = _ALERTS_JS[_ALERTS_JS.index("'alerts.settings.minsev'"):
                          _ALERTS_JS.index("'alerts.settings.notifyminsev'")]
check("EMAIL SERVER" in _MINSEV_HELP,
      "and the ingest filter's own help points at the floor, so nobody sets "
      "the wrong one")


# 40. The WEB relay (5.1.0): must not regress — a URL in the markup, a
#     missing permission gate, or a window.open placed after an await.
_WEB_CLICK = js_function(NODES, "webDevice")
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
_NF_SETTINGS = js_function(_NETFLOW, "settingsDialog")
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


# 44. NetFlow (5.3.0): switching windows was slow in the browser, not on the
#     server — the two queries ran one after the other for no reason, and
#     nothing cancelled the window that had just been left.
_GET = js_const(APP, "get")
check("call(path + query, options)" in _GET,
      "App.get passes a caller's own options through to call(), which is the "
      "only way to cancel a request whose URL has changed — call()'s in-flight "
      "map is keyed on the full URL and so only helps a page polling one address")
check("options.signal && options.signal.aborted" in APP,
      "a caller's own abort is flagged superseded like call()'s own, so "
      "abandoning a window is silent rather than an outage banner")
_NF_REFRESH = js_function(_NETFLOW, "refresh")
check("Promise.all" in _NF_REFRESH and "await App.get(" not in _NF_REFRESH,
      "the overview and the record list are asked for together: they are "
      "independent, and in series every window change cost the sum of both "
      "round trips rather than the slower of them")
check("new AbortController()" in _NF_REFRESH and "signal: abort.signal" in _NF_REFRESH,
      "...under one signal for the whole generation, so a superseded window "
      "stops holding the flow database instead of only being discarded once "
      "it finally answers")
check("if (token !== view.request) return;" in _NF_REFRESH,
      "...with the repaint guard still checked after both")
_NF_FETCH = js_functions(_NETFLOW, "dropInFlight", "requestFetch")
check("view.abort.abort()" in _NF_FETCH,
      "and a change of view aborts what is already in flight rather than "
      "waiting for it to answer something nobody will read")
check("setTimeout" in _NF_FETCH and "REFETCH_MS" in _NF_FETCH,
      "...and collapses the burst it arrived in into one fetch")
check("function setWindow(t0, t1, follow) {" in _NETFLOW,
      "...in the window-change path itself: the old opt-in `defer` argument "
      "was passed by the wheel handler and by none of the dozen other "
      "callers that change the window")
check("if (view.windowTimer) return;" in _NF_REFRESH,
      "...and the poll tick stands off while one is pending, rather than "
      "fetching the half-way window it can see mid-burst")
check("if (windowChanged) showLoading();" in _NF_FETCH,
      "the Loading state is for a window change, not for every refresh — the "
      "two-second poll must not blank the page it is refreshing")

_NF_LOADING = js_function(_NETFLOW, "showLoading")
for _target in ("drawChart();", "drawBars();", "drawTable("):
    check(_target in _NF_LOADING,
          "a window change says so over the chart, the top-N bars and the "
          "record table (%s), so the window just left is not left on screen "
          "looking like the answer" % _target.rstrip("(;"))
check("LOADING_TEXT = 'Loading…'" in _NETFLOW and "App.loading()" in _NETFLOW,
      "...in the house vocabulary App.loading() already uses everywhere else, "
      "not a modal over a read and not a second word for the same wait")

# ---------------------------------------------------------------------------
# 45. NetFlow (5.3.0): the state above had no way out but success. showLoading
#     writes "Loading…" into the chart, the top-N bars and the record table,
#     and only a refresh that COMPLETED ever wrote over it — so a 400 from a
#     filter the server refuses, or an outage under a window change, left all
#     three panes reading "Loading…" for as long as the operator stayed there,
#     next to a connection status already saying the fetch had failed.
check("view.loading ? LOADING_TEXT : NO_FLOWS_TEXT" not in _NETFLOW,
      "a pane with nothing to draw picks its sentence in one place instead of "
      "each re-deriving it from view.loading — a two-state ternary that had no "
      "answer at all for a fetch that failed")
check("const emptyMessage = () =>" in _NETFLOW,
      "...and that one place knows all three states a pane can be in: still "
      "loading, failed, and genuinely empty")
check("FAILED_TEXT = 'Could not load" in _NETFLOW,
      "the failure sentence is its own rather than NO_FLOWS_TEXT: a server "
      "that never answered has not said this window is quiet, and reporting a "
      "refused filter as 'no flows match' is a claim nobody made")
_FAILED_AT = "  function loadFailed(error) {"
check(_FAILED_AT in _NETFLOW,
      "the loading state has a way out other than success at all — this is "
      "the function that did not exist, and every check below reads it")
_NF_FAILED = js_function(_NETFLOW, "loadFailed") if _FAILED_AT in _NETFLOW else ""
check("error.superseded" in _NF_FAILED,
      "a superseded abort is not a failure — the newer fetch it was abandoned "
      "for is still loading, and its answer is the one worth waiting for")
check("view.loading = false;" in _NF_FAILED and "view.failed = true;" in _NF_FAILED,
      "a real failure stops the page claiming to be loading")
for _target in ("drawChart();", "drawBars();", "drawTable("):
    check(_target in _NF_FAILED,
          "...across the same three panes showLoading wrote to (%s), so none "
          "is left mid-sentence" % _target.rstrip("(;"))
check("!view.loading) return;" in _NF_FAILED,
      "...and only where a loading claim was actually made: a poll tick that "
      "failed under a window already on screen leaves that window on screen, "
      "rather than blanking a working display over one missed poll")
check("if (token === view.request) loadFailed(error);" in _NF_REFRESH,
      "refresh() routes a rejected fetch through it, behind the same stale "
      "guard as the repaint below — an older generation's failure must not "
      "paint over the newer one now in flight")
check("throw error;" in _NF_REFRESH,
      "...and RE-THROWS it: the connection status and the console report are "
      "runRefresh's to make, and swallowing the error here would trade a "
      "stuck pane for a silent failure")
check("view.failed = false;" in _NF_REFRESH and "view.failed = false;" in _NF_LOADING,
      "and the flag clears both ways — on the answer that supersedes it, and "
      "on the next window change, which is a new question either way")



# --- 58. FM-P1: a mechanical escaping check --------------------------------
#      Every `${...}` inside an HTML-bearing template literal is either a call
#      (escape(), a *Html() builder, a formatter), a literal, a ternary, a
#      nested template, or a bare name. A bare DOTTED name is a row field
#      reaching the DOM unescaped, which is the shape both injection findings
#      had; the ones below are ids, counts and numeric settings, and any
#      addition to that set has to be argued here rather than slip in.
ALLOWED_BARE_FIELDS = {
    "alerts.js": {"d.id", "g.id", "o.device_id", "r.severity", "row.count", "row.severity",
                  "t.id", "w.id"},
    # list.id: App.comboBox's own dropdown element id, built here as
    # `${input.id}-list` a few lines above the template that reads it back —
    # never a server-supplied row field.
    "app.js": {"c.key", "entry.html", "entry.title", "list.id"},
    "configrx.js": {"device.ssh_port", "g.id", "ids.length", "r.rule_set_id",
                    "s.backup_interval_hours", "s.capture_timeout_s", "s.configrx_workers",
                    "s.retention_count_per_device", "s.retention_days"},
    "dashboard.js": {"pool.busy", "pool.queued"},
    "events.js": {"r.severity"},
    "ipam.js": {"result.scope_count", "s.id"},
    "mapper.js": {"c.matched_device_id", "link.link_id", "m.id", "m.node_count", "node.id",
                  "r.id", "s.candidates.length", "s.device_id", "s.grid_size",
                  "s.link_width_max", "s.link_width_min", "s.max_strand_vlans",
                  "s.refresh_interval_s", "s.stale_link_hours", "s.vlan_collapse_threshold",
                  "v.vlan", "vlans.length"},
    "netflow.js": {"row.bytes_text", "row.rate_text"},
    "netpath.js": {"s.default_interval_s", "s.default_max_hops", "s.default_probes",
                   "s.default_timeout_s", "s.default_warn_loss", "s.default_warn_rtt_ms",
                   "s.topology_stale_hours", "s.trace_retention_days", "s.trace_workers",
                   "t.max_hops", "t.probes", "t.timeout_s", "t.warn_loss", "t.warn_rtt_ms"},
    "nodes.js": {"c.id", "d.a_id", "d.b_id", "d.learned_from.device_id", "duplicate.device_id",
                 "ev.walk.objects", "f.id", "g.id", "ids.length", "names.length", "owned.length",
                 "p.row", "r.caveats.length", "r.matched_device_id", "r.override_count",
                 "row.override_count"},
    "wireless.js": {"c.id", "s.poll_interval_s", "s.history_days", "s.history_sample_s",
                    "s.ap_web_port"},
}
# mapper_upstream.js carries the upstream-suggestions dialog cut out of mapper.js.
ALLOWED_BARE_FIELDS["mapper_upstream.js"] = ALLOWED_BARE_FIELDS["mapper.js"]
# nodes_credentials.js carries the polling-profile dialogs cut out of nodes.js.
ALLOWED_BARE_FIELDS["nodes_credentials.js"] = {"c.id"}


def _template_literals(body):
    i, n, out = 0, len(body), []
    while i < n:
        if body[i] == "`":
            j, depth = i + 1, 0
            while j < n:
                c = body[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "$" and body.startswith("${", j):
                    depth += 1
                    j += 2
                    continue
                if depth and c == "}":
                    depth -= 1
                elif not depth and c == "`":
                    break
                j += 1
            out.append((body.count("\n", 0, i) + 1, body[i + 1:j]))
            i = j + 1
        else:
            i += 1
    return out


def _interpolations(tpl):
    i, n, out = 0, len(tpl), []
    while i < n:
        if tpl.startswith("${", i):
            depth, j, quote = 1, i + 2, None
            while j < n and depth:
                c = tpl[j]
                if quote:
                    if c == "\\":
                        j += 1
                    elif c == quote:
                        quote = None
                elif c in "'\"`":
                    quote = c
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                j += 1
            out.append(tpl[i + 2:j - 1].strip())
            i = j
        else:
            i += 1
    return out


_DOTTED = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+$")
unescaped_fields = []
for _name in MODULES:
    if _name.startswith("vendor"):
        continue
    _body = read(_name)
    for _line, _tpl in _template_literals(_body):
        if "<" not in _tpl:
            continue
        for _expr in _interpolations(_tpl):
            if _DOTTED.match(_expr) and _expr not in ALLOWED_BARE_FIELDS.get(_name, set()):
                unescaped_fields.append("%s:%d ${%s}" % (_name, _line, _expr))
check(not unescaped_fields,
      "no HTML template interpolates a row field bare — wrap it in escape() or add "
      "it to ALLOWED_BARE_FIELDS with a reason (found: %s)"
      % (", ".join(unescaped_fields[:8]) or "none"))
check(sum(len(v) for v in ALLOWED_BARE_FIELDS.values()) >= 70,
      "the escaping allow-list still lists the fields it was written against "
      "(an emptied list would pass vacuously)")

print()
# ---------------------------------------------------------------------------
# 45a. NetFlow: "graphs are not showing all data from the timeline window".
#      Four of the five defects behind that report were in netflow.js, and
#      each is a fact about the text that a refactor could undo invisibly.
#      These are the cheap grep half; 45b below RUNS the chart, because a
#      slotSeconds() that returned bucket_s unconditionally, or a slotAt()
#      off by one, passes every line here.
_NF_CHART = js_functions(_NETFLOW, "drawChart", "slotTip")
_NF_AXIS = js_function(_NETFLOW, "axisOf")
_NF_BARS = js_function(_NETFLOW, "drawBars")
check("* 8 / slotSeconds(data, i)" in _NF_CHART
      and "App.rate(entry.value, seconds)" in _NF_CHART
      and "App.rate(total, seconds)" in _NF_CHART
      and "const seconds = slotSeconds(data, slot);" in _NF_CHART,
      "the chart and its tooltip both divide a slot by slotSeconds(), the "
      "duration it actually covers, so the trailing partial bucket is not "
      "drawn at a fraction of its rate and the hover cannot confirm a number "
      "the chart did not draw")
check("* 8 / bucket)" not in _NF_CHART and "App.rate(entry.value, bucket)" not in _NF_CHART,
      "...and nowhere divides by the nominal bucket width any more")
_WINDOW_END_BLOCK = (js_functions(_NETFLOW, "windowEnd", "slotCovered")
                      + js_const(_NETFLOW, "SLOT_MIN_FRACTION"))
check("Number.isFinite(data.t1)" in _NETFLOW and "view.t1" not in _WINDOW_END_BLOCK,
      "the window's end is the response's own t1, which is what the values "
      "were read over, not view.t1")
check("stepX" not in _NF_CHART and "const xOf = (ts) =>" in _NF_AXIS
      and "xOf(t1)" in _NF_CHART,
      "the x axis spans the window the server read, t0 to t1, rather than "
      "spreading the slots so the last one sits on the right edge with no "
      "width")
check("slotAt(timeAt(x))" in _NF_CHART,
      "...and the crosshair finds its slot from the time under the cursor on "
      "that same axis")
# The 5.7.0 review: the first fix for the cliff floored the final slot at
# five SECONDS, so a sliver holding the end of one long flow -- NetFlow
# credits every byte to the record's ts_end -- drew that flow's whole
# volume over five seconds: 720x over-read under an hour bucket, and a
# right-hand edge that flickered on every refresh of a live window.
check("SLOT_MIN_S" not in _NETFLOW and "const SLOT_MIN_FRACTION = 0.25;" in _NETFLOW
      and "data.bucket_s * SLOT_MIN_FRACTION" in _NETFLOW,
      "the final slot's rate floor is a fraction of the bucket, never a number "
      "of seconds, so the worst-case over-read is the same small factor "
      "whatever the bucket")
check("over-read is 4x" in _NETFLOW,
      "...and the comment on it says what that worst case is")
check("slotCovered(data, slot) / 2" in _NF_AXIS and "slotSeconds(data, slot) / 2" not in _NETFLOW,
      "a slot's vertex sits at the centre of the time it COVERS, never of the "
      "floored seconds it is rated over, which would push it past the window")
check("function slotCount(data)" in _NETFLOW and "count: drawn" in _NF_CHART
      and "slot < drawn" in _NF_CHART,
      "an exactly bucket-aligned t1 leaves a final slot that covers nothing; "
      "it is neither drawn nor ticked rather than landing past the right edge")
# 5.9.1: the drag came OUT of the signature again, the other way round. It
# made every pointermove a full chart rebuild (and a JSON.stringify of the
# whole response) to move one rectangle; the brush is now the persistent rect
# mapper.js's rubber band already was, so it appears without the miss.
check(":drag=" not in _NF_CHART,
      "a drag in progress is not part of the redraw signature: it would make "
      "every pointermove tear down and rebuild the whole chart")
check("const paintBrush = () =>" in _NF_CHART
      and _NF_CHART.count("paintBrush();") >= 3,
      "...because the brush is one persistent rect moved in place — painted "
      "once per rebuild, by the pointermove that moves it, and by the release "
      "that has to take it away")
check("Math.abs(to - from) > bucket" not in _NF_CHART
      and "Math.abs(to - from) >= DRAG_MIN_S" in _NF_CHART
      and "DRAG_MIN_PX" in _NF_CHART,
      "a drag-selection is accepted down to a few seconds and a few pixels, "
      "not discarded when narrower than the previous response's bucket")
check("legendRow += 1;" in _NF_CHART and "if (legendX + width_ > plot.x + plot.w) return;" not in _NF_CHART,
      "legend entries that no longer fit wrap on to another row rather than "
      "being dropped, so every drawn band is named")
check("SERIES[index % SERIES.length]" not in _NETFLOW
      and "index >= SERIES.length ? OTHER" in _NETFLOW,
      "no swatch wraps round the palette: past the eighth hue is OTHER, never "
      "--cat-1 again")
check("const drawn = namedBands(view.data);" in _NF_BARS
      and "folded ? OTHER : seriesColor(row.label, index)" in _NF_BARS,
      "a top-N bar past the number of bands the chart drew — read off the "
      "response, not written down as 8 — takes the neutral '— other —' is "
      "drawn in")
check("if (folded) tip.push({ text: FOLDED_TEXT });" in _NF_BARS
      and "folded ? `${valueId} ${foldId}` : valueId" in _NF_BARS
      and 'class="sr-only"' in _NF_BARS,
      "...and says so, in its tooltip and in its accessible description")


# 45b. NetFlow, run rather than read. The chart's helpers and drawChart
#      itself are sliced out of netflow.js and run by node against a DOM
#      stub, the way tests/test_alerts_ui.py runs the rule editor: the
#      response shapes flowdb actually produces are drawn, the polygon's
#      vertices are read back, and the pointer is moved over the SVG so the
#      crosshair, the tooltip and the drag brush answer for themselves.
#      Node is the one thing a machine here may not have; if it is missing
#      the checks say so and are skipped, and 45a's text checks are then
#      the only thing standing behind this code -- which is why this
#      section exists, and why that is printed rather than passed over.
NODE = shutil.which("node") or shutil.which("nodejs")

_NF_HELPERS = (js_function(APP, "niceCeiling")
               + js_functions(_NETFLOW, "rateLabel", "windowEnd", "slotCovered",
                             "slotSeconds", "slotCount", "axisOf", "showFocusTip", "drawChart",
                             "slotTip")
               + js_const(_NETFLOW, "SLOT_MIN_FRACTION"))
_NF_CONSTS = "".join(re.search(pat, _NETFLOW).group(0) for pat in (
    r"  const PAD = \{[^\n]*\n", r"  const DRAG_MIN_S = [^\n]*\n", r"  const DRAG_MIN_PX = [^\n]*\n"))


def _app_function(name):
    """One top-level helper of app.js, verbatim, so the numbers the tooltip
    prints are the numbers the browser prints."""
    start = APP.index("  function %s(" % name)
    return APP[start:APP.index("\n  }\n", start) + 5]


_NF_HARNESS = """
'use strict';
const DATA = %(data)s;
const PROBES = %(probes)s;
const DRAG_PX = 40;
%(consts)s
%(rate)s
%(span)s
const tips = [];
const windows = [];
/* The least that behaves like the chart's SVG: what was appended since the
   last innerHTML = '' and the handlers drawChart hangs on it. */
const svgEl = {
  attrs: {}, dataset: {}, children: [], clientWidth: 1000,
  set innerHTML(v) { this.children = []; }, get innerHTML() { return ''; },
  setAttribute(k, v) { this.attrs[k] = v; },
  appendChild(n) { this.children.push(n); },
  setPointerCapture() {},
};
const ELEMENTS = {
  'nf-chart': { dataset: {}, tabIndex: -1, setAttribute() {}, addEventListener() {},
    getBoundingClientRect: () => ({ width: 1000, height: 300, left: 0, top: 0 }) },
  'nf-chart-svg': svgEl,
  'nf-totals': { textContent: 'totals' },
};
const App = {
  rate, span,
  stamp: (ts) => `stamp:${ts}`,
  el: (id) => ELEMENTS[id],
  svgNode: (tag, attrs, text) => ({ tag, attrs: { ...attrs }, text,
    setAttribute(k, v) { this.attrs[k] = v; } }),
  emptyText: (svg, w, h, text) => svg.appendChild({ tag: 'empty', attrs: {}, text }),
  tooltip: (rows, event) => tips.push({ rows, x: event.clientX }),
  hideTooltip: () => tips.push(null),
};
const document = { activeElement: null };
const view = { t0: DATA.times[0], t1: Number.isFinite(DATA.t1) ? DATA.t1 : 0,
               data: DATA, loading: false, failed: false, drag: null };
const seriesColor = (name, index) => `c${index}`;
const emptyMessage = () => 'empty';
const NO_FLOWS_TEXT = 'none';
const setWindow = (a, b) => windows.push([a, b]);

%(helpers)s

drawChart();
const plot = { x: PAD.left, w: 1000 - PAD.left - PAD.right };
const axis = axisOf(DATA, plot);
const nodesOf = (tag) => svgEl.children.filter((n) => n.tag === tag);
const polygon = nodesOf('polygon')[0];
const vertices = polygon
  ? polygon.attrs.points.split(' ').map((p) => p.split(',').map(Number)) : [];
const probes = PROBES.map((x) => {
  tips.length = 0;
  svgEl.onpointermove({ offsetX: x, clientX: x, clientY: 0 });
  const crosshair = nodesOf('line').find((n) => 'stroke-dasharray' in n.attrs);
  const tip = tips[tips.length - 1];
  svgEl.onpointerdown({ button: 0, isPrimary: true, pointerId: 1, offsetX: x,
                        preventDefault() {} });
  const dragFrom = view.drag.from;
  svgEl.onpointermove({ offsetX: x + DRAG_PX, clientX: x + DRAG_PX, clientY: 0 });
  const dragTo = view.drag.to;
  const brush = nodesOf('rect').find((n) => n.attrs.stroke === 'var(--accent)');
  const before = windows.length;
  svgEl.onpointerup();
  return {
    x, crosshairX: crosshair.attrs.x1, crosshairVisible: crosshair.attrs.visibility,
    tipHeading: tip ? tip.rows[0].text : null,
    tipTotal: tip ? tip.rows[tip.rows.length - 1].text : null,
    timeAt: axis.timeAt(x), slot: axis.slotAt(axis.timeAt(x)),
    xBack: axis.xOf(axis.timeAt(x)),
    dragFrom, dragTo,
    brush: brush ? [Number(brush.attrs.x), Number(brush.attrs.width)] : null,
    window: windows.length > before ? windows[windows.length - 1] : null,
  };
});
console.log(JSON.stringify({
  plot, windowEnd: windowEnd(DATA), slotCount: slotCount(DATA),
  covered: DATA.times.map((_, i) => slotCovered(DATA, i)),
  seconds: DATA.times.map((_, i) => slotSeconds(DATA, i)),
  vertices,
  ticks: nodesOf('text').filter((n) => String(n.text).startsWith('stamp:'))
    .map((n) => Number(n.attrs.x)),
  probes,
}));
"""


def _draw(data, probes):
    """drawChart() on `data`, then the pointer at each x in `probes`: hover,
    press, drag DRAG_PX right, release. What came back, or {"error": ...}
    so a harness that threw reads as failed checks rather than a dead run."""
    script = _NF_HARNESS % {
        "data": json.dumps(data), "probes": json.dumps(probes),
        "consts": _NF_CONSTS, "rate": _app_function("rate"),
        "span": _app_function("span"), "helpers": _NF_HELPERS}
    folder = tempfile.mkdtemp(prefix="nf_chart_")
    try:
        path = os.path.join(folder, "run.mjs")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        out = subprocess.run([NODE, path], capture_output=True, text=True,
                             encoding="utf-8", timeout=60)
        if out.returncode != 0:
            return {"error": out.stderr.strip()[:600]}
        return json.loads(out.stdout)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


_T0 = 1700000000
_B = 60


def _response(last_covered, last_values, bucket=_B, slots=10, t1=True):
    """A flowdb overview: `slots` times one bucket apart, and a t1 that
    leaves the final slot covering `last_covered` seconds of the window.
    Two series rated at 8 and 4 Mbps in every whole bucket."""
    times = [_T0 + i * bucket for i in range(slots)]
    data = {"times": times, "bucket_s": bucket, "series": [
        {"name": "a", "values": [bucket * 1e6] * (slots - 1) + [last_values[0]]},
        {"name": "b", "values": [bucket * 0.5e6] * (slots - 1) + [last_values[1]]},
    ]}
    if t1:
        data["t1"] = times[-1] + last_covered
    return data


def _near(a, b, tolerance=1e-6):
    return a is not None and b is not None and abs(a - b) <= tolerance


if NODE is None:
    print("SKIP 45b: node is not on this machine, so the NetFlow chart was not "
          "run -- 45a's text checks are the only thing behind it here")
else:
    # -- a substantially covered final slot reads at its true rate ----------
    # 45 of 60 seconds, holding three quarters of a whole bucket's bytes: the
    # same 8 + 4 Mbps as every other slot, so the stack's top edge must be
    # flat all the way to the right edge. The 5.6 code drew it at 9 Mbps.
    r = _draw(_response(45, [45e6, 22.5e6]), [])
    check("error" not in r, "the sliced chart runs under node"
          + (" (%s)" % r["error"] if "error" in r else ""))
    plot_x, plot_w = (r.get("plot") or {}).get("x", 0), (r.get("plot") or {}).get("w", 0)
    probes = [plot_x + 5, plot_x + plot_w * 0.5, plot_x + plot_w * 0.95]
    r = _draw(_response(45, [45e6, 22.5e6]), probes)
    check(r.get("windowEnd") == _T0 + 9 * _B + 45 and r.get("slotCount") == 10,
          "windowEnd is the response's t1 and every slot covers some of the window")
    check((r.get("seconds") or [None])[-1] == 45 and (r.get("covered") or [None])[-1] == 45
          and all(x == _B for x in (r.get("seconds") or [])[:-1]),
          "a final slot three quarters covered is rated over exactly its 45 s, "
          "and every whole slot over the bucket")
    vertices = r.get("vertices", [])
    ys = [y for _, y in vertices[1:-1]]
    check(len(vertices) == 14 and ys and max(ys) - min(ys) < 1e-6,
          "drawn, the stack's top edge is flat through the partial slot to the "
          "right-hand edge -- no cliff (vertices=%d, y spread=%s)"
          % (len(vertices), (max(ys) - min(ys)) if ys else None))
    check(len(vertices) == 14
          and _near(vertices[-3][0], plot_x + plot_w * (9 * _B + 22.5) / (9 * _B + 45))
          and _near(vertices[-1][0], plot_x + plot_w),
          "the final slot's vertex sits at the centre of what it covers and the "
          "area runs on to the right-hand edge")
    for probe in r.get("probes", []):
        t = probe["timeAt"]
        expected_slot = min(int((t - _T0) // _B), 9)
        check(probe["slot"] == expected_slot
              and _near(probe["xBack"], probe["x"]),
              "x=%.1f: slotAt(timeAt(x)) is the slot whose time is under the "
              "cursor (%d), and xOf(timeAt(x)) comes back to x"
              % (probe["x"], expected_slot))
        check(probe["crosshairVisible"] == "visible" and _near(probe["crosshairX"], probe["x"])
              and (probe["tipHeading"] or "").startswith("stamp:%d" % (_T0 + expected_slot * _B)),
              "x=%.1f: the crosshair stands at x and the tooltip names slot %d's "
              "time (%r)" % (probe["x"], expected_slot, probe["tipHeading"]))
        check(probe["tipTotal"] == "total: 12.0 Mbps",
              "x=%.1f: the tooltip's total is the rate the chart drew, 12 Mbps, "
              "in the partial slot as in the whole ones (%r)"
              % (probe["x"], probe["tipTotal"]))
        check(_near(probe["dragFrom"], t) and probe["brush"] is not None
              and _near(probe["brush"][0], probe["x"]) and _near(probe["brush"][1], 40),
              "x=%.1f: a drag starts from the same time the tooltip resolved, and "
              "the brush is drawn from x, 40 px wide (%r)" % (probe["x"], probe["brush"]))
        check(probe["window"] is not None and _near(probe["window"][0], t)
              and _near(probe["window"][1], probe["dragTo"]),
              "x=%.1f: releasing asks for exactly the window dragged over"
              % probe["x"])
    last = (r.get("probes") or [{}])[-1]
    check(last.get("tipHeading") == "stamp:%d · 45s of 60s so far" % (_T0 + 9 * _B),
          "the partial slot's tooltip says what it covers so far and, rated over "
          "its own coverage, nothing more (%r)" % last.get("tipHeading"))

    # -- a sliver is rated over the quarter-bucket floor ---------------------
    # Three seconds of a 60 s bucket holding 100 MB (a minute-long flow that
    # ended in it). Over its own 3 s that is 267 Mbps; over the floor it is
    # 53 Mbps, 4x the 13 Mbps the flow really ran at, and never more.
    r = _draw(_response(3, [100e6, 0]), [plot_x + plot_w - 2])
    check((r.get("covered") or [None])[-1] == 3 and (r.get("seconds") or [None])[-1] == 15,
          "a 3 s final slot is rated over a quarter of its 60 s bucket, not over "
          "3 s and not over 60 (%r)" % r.get("seconds"))
    probe = (r.get("probes") or [{}])[-1]
    check(probe.get("slot") == 9 and probe.get("tipTotal") == "total: 53.3 Mbps",
          "...and the tooltip over it prints that floored rate, 53.3 Mbps -- 4x "
          "the flow's true 13.3, not the 266.7 a 5 s floor would print (%r)"
          % probe.get("tipTotal"))
    check(probe.get("tipHeading") == "stamp:%d · 3s of 60s so far, rated over 15s" % (_T0 + 9 * _B),
          "...and says it was rated over the floor (%r)" % probe.get("tipHeading"))
    vertices = r.get("vertices", [])
    check(len(vertices) == 14 and _near(vertices[-3][0], plot_x + plot_w * (9 * _B + 1.5) / (9 * _B + 3))
          and vertices[-3][0] <= plot_x + plot_w,
          "its vertex is at the centre of the 3 s it covers, inside the window, "
          "not at the centre of the 15 s it is rated over")

    # The cap holds whatever the bucket: 5 s of an hour bucket used to be a
    # 720x over-read; it is now 4x, and a slot one second past the quarter
    # mark is rated over its own coverage again.
    r = _draw(_response(5, [100e6, 0], bucket=3600, slots=2), [])
    check((r.get("seconds") or [None])[-1] == 900,
          "5 s of a 3600 s bucket is rated over 900 s (worst case 4x), not 5 s "
          "(720x) (%r)" % r.get("seconds"))
    r = _draw(_response(901, [100e6, 0], bucket=3600, slots=2), [])
    check((r.get("seconds") or [None])[-1] == 901,
          "901 s of a 3600 s bucket is rated over its own 901 s (%r)" % r.get("seconds"))

    # -- covered == 0: t1 exactly on a bucket boundary -------------------------
    # flowdb's int(span / bucket) + 1 then puts a tenth slot AT t1, covering
    # nothing. Its vertex used to land past the right edge at zero.
    r = _draw(_response(0, [0, 0]), [plot_x + plot_w])
    vertices = r.get("vertices", [])
    check((r.get("covered") or [None])[-1] == 0 and r.get("slotCount") == 9,
          "an exactly aligned t1 leaves the final slot covering nothing, and it "
          "is not counted among the drawn slots (%r)" % r.get("slotCount"))
    check(len(vertices) == 13 and all(x <= plot_x + plot_w + 1e-9 for x, _ in vertices)
          and _near(vertices[-3][0], plot_x + plot_w * (8 * _B + 30) / (9 * _B)),
          "...so nine slots are drawn, no vertex lands past the right-hand edge, "
          "and the last vertex is the ninth slot's centre (vertices=%d, max x=%s)"
          % (len(vertices), max((x for x, _ in vertices), default=None)))
    check(len(r.get("ticks", [])) == 9,
          "...and the empty slot gets no tick of its own (%r)" % len(r.get("ticks", [])))
    probe = (r.get("probes") or [{}])[-1]
    check(probe.get("slot") == 8 and (probe.get("tipHeading") or "") == "stamp:%d" % (_T0 + 8 * _B),
          "the cursor on the right-hand edge resolves to the ninth slot, a whole "
          "one, not to the empty tenth (%r)" % probe.get("tipHeading"))

    # -- data.t1 absent -------------------------------------------------------
    r = _draw(_response(0, [60e6, 30e6], t1=False), [])
    check(r.get("windowEnd") == _T0 + 9 * _B + _B and (r.get("covered") or [None])[-1] == _B
          and (r.get("seconds") or [None])[-1] == _B and r.get("slotCount") == 10,
          "without a t1 the window ends a whole bucket after the last slot's "
          "start, which is then whole and drawn (%r)" % r.get("windowEnd"))

    # -- a single-slot window -------------------------------------------------
    # bucket_s None on the server puts the whole window in one slot whose
    # bucket_s IS the span; every x must resolve to slot 0 and nothing else.
    single = {"times": [_T0], "bucket_s": 100, "t1": _T0 + 100,
              "series": [{"name": "a", "values": [50e6]}]}
    r = _draw(single, [plot_x, plot_x + plot_w * 0.5, plot_x + plot_w - 1])
    vertices = r.get("vertices", [])
    check(r.get("seconds") == [100] and r.get("slotCount") == 1 and len(vertices) == 5
          and _near(vertices[2][0], plot_x + plot_w * 0.5),
          "a one-slot window is rated over its whole span and drawn as one "
          "vertex at the centre of the plot (%r)" % vertices)
    probes = r.get("probes", [])
    check(len(probes) == 3 and all(p["slot"] == 0 for p in probes)
          and _near(probes[0]["timeAt"], _T0)
          and all(p["tipTotal"] == "total: 4.0 Mbps" for p in probes)
          and all(p["window"] is not None for p in probes[:2]),
          "every x on it resolves to slot 0, the left edge is t0, the tooltip "
          "reads the one rate, and a drag from the left or the middle still "
          "selects a window")
    # From one pixel inside the right edge a 40 px drag clamps to t1 and
    # spans a tenth of a second: under DRAG_MIN_S, so it is refused as a
    # wobble -- and the brush is still drawn, clamped to the edge at its
    # 2 px minimum, so the refusal is visible rather than silent.
    edge = probes[-1] if probes else {}
    check(edge.get("window") is None and _near(edge.get("dragTo"), _T0 + 100)
          and edge.get("brush") is not None and _near(edge["brush"][1], 2),
          "a drag that clamps at the right edge to under DRAG_MIN_S is refused, "
          "with the brush drawn to the edge at its minimum width (window=%r, "
          "brush=%r)" % (edge.get("window"), edge.get("brush")))


# 46. NODES/ALERTS (5.3.0): the optic power rules alert against the levels the
#     PORT publishes, so the only place an operator can see what a port is
#     judged by is the DOM table — and the only honest thing to say about a
#     port that publishes nothing is that its optic power alerts are off.
check(NODES.count('<th scope="col">Limits</th>') == 2
      and NODES.count("${domLimitsCell(s)}") == 2,
      "both DOM tables (the interface dialog's one-port read and the device "
      "dialog's whole-device one) carry the published Limits column")
check("domLimitsHint(" in NODES and "publishes no optical power" in NODES,
      "a DOM table with a light-level row that has no published band says so "
      "beneath itself — silence there reads as 'nothing is wrong with this port'")
check("s.limits_source" in NODES,
      "the Limits cell names the MIB that published the band, so an operator "
      "can tell a learned limit from an invented one")
check("alertedOnItsOwnBand(" in NODES
      and "Only the optical power rows are alerted on" in NODES,
      "the Limits column carries the temperature, bias and voltage bands the "
      "optic publishes too, but only the two dBm rules read them -- so the "
      "table says which rows are actually alerted on what it shows, rather "
      "than letting a published 70 / 75 beside a temperature row read as the "
      "number sfp_temp_high fires at")
check("reference only, not what this reading is alerted on" in NODES,
      "...and the cell's own title says so per row, for the reader who hovers "
      "one band rather than reading the sentence under the table")
_ALERTS46 = read("alerts.js")
check("PUBLISHED_THRESHOLD_KEYS" in _ALERTS46
      and "Threshold — from the optic" in _ALERTS46,
      "the rule editor replaces the two threshold inputs with a sentence for "
      "the eight optic power keys, rather than leaving a box the server "
      "refuses — which is the silent-ignore this release exists to remove")
check("if (!isPublished) {" in _ALERTS46,
      "and the save handler does not read inputs it did not render")

# ---------------------------------------------------------------------------
# 47. ALL TABS (5.4.0): a device name shown anywhere is a way into Nodes, and
#     exactly one function decides what that way is.
#
# Eleven columns across seven modules printed a device's name as dead text
# while the pane beside them linked the same name. The rule they now share is
# not obvious from any one of them — link to the device's own pane where an
# id is known, to the Nodes search where only a name is, and to neither for
# an account without Nodes read — so it lives in App.deviceNameLink and the
# call sites do not get to restate it.
check("function deviceNameLink(" in APP and "deviceNameLink," in APP,
      "App.deviceNameLink exists and is exported")
check("canRead('nodes')" in APP.split("function deviceNameLink(")[-1][:600],
      "...and it is the helper, not each caller, that refuses to hand a link "
      "into Nodes to an account that cannot open Nodes")
_NAME_ROUTE_BUILDERS = [name for name in MODULES
                        if re.search(r"buildRoute\('nodes', \[\], \{ name:", read(name))]
check(_NAME_ROUTE_BUILDERS == ["app.js"],
      "the #/nodes?name= route is built in app.js alone; a module that built "
      "it itself would be a second copy of the permission rule (found in: %s)"
      % (", ".join(_NAME_ROUTE_BUILDERS) or "nothing"))

# The call sites, by the cell each one is. NetFlow is deliberately absent:
# its rows name flow endpoints by address, not fleet devices by name.
NAME_LINK_SITES = {
    "alerts.js": ["{ key: 'entity_label', label: 'Object'"],
    "nodes.js": ["{ key: 'name', label: 'Device'",
                 "{ key: 'device_name', label: 'Device'"],
    "configrx.js": ["{ key: 'device', label: 'Device'"],
    "mapper_upstream.js": ["suggestionName(s)", "candidateLink"],
    "events.js": ["{ key: 'source', label: 'Source'",
                  "{ key: 'source_name', label: 'Source name'"],
    "wireless.js": ["{ key: 'name', label: 'Name'",
                    "{ key: 'controller_id', label: 'Controller'"],
    "ipam.js": ["{ key: 'hostname', label: 'Hostname', width: 220",
                "{ key: 'hostname', label: 'Hostname', width: 200"],
}
for _name, _anchors in sorted(NAME_LINK_SITES.items()):
    _body = read(_name)
    for _anchor in _anchors:
        _at = _body.find(_anchor)
        check(_at != -1 and "App.deviceNameLink(" in _body[_at:_at + 500],
              "%s builds its device name through App.deviceNameLink (%s)"
              % (_name, _anchor))
check("App.deviceNameLink(" in read("ipam.js").split("function resultsTable(")[-1][:900],
      "ipam.js's global-search results table links its hostnames too")
check("App.deviceNameLink(" not in read("netflow.js"),
      "NetFlow is deliberately left out: a flow endpoint is an address seen "
      "on the wire, not a device on the fleet")

# The two routes are not interchangeable, and the one that runs a MAC search
# must stay the one IPAM's conflicts link.
check("['nd-q', 'name']" in NODES and "#/nodes?name=<name>" in NODES,
      "nodes.js's route parser reads ?name= into the search box")
check(re.search(r"if \(key === 'q'\) view\.macSearchPending = true;", NODES)
      is not None,
      "...and arms the MAC search for ?q= only, so a device whose name is "
      "hex does not get told it typed a bad MAC address")


# ------------------------------------------- 5.4 indefinite maintenance mode
#
# Five surfaces, four of which fail silently if they regress: a tag that is
# never called renders nothing, a signature that omits the state never
# rebuilds the pane, a button without its gate is offered to an account the
# server will 403, and a CSV column dropped from one of the two lists shifts
# every value after it by one.
_NODES54 = read("nodes.js")
_ALERTS54 = read("alerts.js")

check("function maintenanceTag(" in _NODES54,
      "nodes.js defines maintenanceTag, the device list's own answer to "
      "'why is this one quiet' for maintenance mode")
check("mutedTag(" in _NODES54 and "${maintenanceTag(r)}${mutedTag(r)}" in _NODES54,
      "the name column calls BOTH tags -- mutedTag was left untouched, and a "
      "device that is muted AND in maintenance shows both")
check("nd-filter-maintenance" in _NODES54
      and "maintenance_only" in _NODES54,
      "the Only-in-maintenance checkbox sends maintenance_only by presence, "
      "the same convention offline_only already uses")
_FILTER_SIG = re.search(r"const filterSig = JSON\.stringify\(\[(.*?)\]\);",
                        _NODES54, re.S)
check(bool(_FILTER_SIG) and "maintenance_only" in _FILTER_SIG.group(1),
      "...and it is part of the filter signature, so ticking it resets the "
      "list to page one instead of holding an offset into a different set")

check("maint ? maint.started_ts : ''" in _ALERTS54,
      "alerts.js puts the maintenance state in view.detailSignature -- the "
      "pane is only rebuilt when that string changes, so a state left out "
      "of it would show the previous answer until something else moved")
check("App.get('/api/alerts/maintenance')" in _ALERTS54,
      "...and the maintenance fetch rides in the same Promise.all as the "
      "mutes, so the two can never disagree for a tick")
check("alerts-d-end-maintenance" in _ALERTS54
      and "alerts-d-unmute" in _ALERTS54,
      "the Alerts detail pane offers End maintenance, and the mute block "
      "beside it is untouched")

for element in ("nd-maintenance", "nd-bulk-maintenance", "nd-bulk-maintenance-off"):
    pattern = re.compile(r'id="%s"[^>]*data-requires-write="alerts"' % element)
    check(bool(pattern.search(INDEX)),
          f"index.html carries #{element} gated data-requires-write=\"alerts\" "
          "-- maintenance silences alerts, so it is the Alerts writer's to set, "
          "not the Nodes writer's")

_AVAIL_CSV = re.search(r"const header = \[\'device_id\'.*?\];", _NODES54, re.S)
_AVAIL_CSV = _AVAIL_CSV.group(0) if _AVAIL_CSV else ""
for column in ("maintenance_excluded_s", "maintenance_mode_excluded_s",
               "mute_excluded_s"):
    check(column in _AVAIL_CSV,
          f"the availability CSV header carries {column} -- the three "
          "suppression buckets stay separate, because the export is read to "
          "answer WHICH mechanism took a device out of service")



# 31. The restart wait never calls a slow restart a failed update.
#
# waitForRestart used to give the restart 60 seconds and then paint a red
# "Still not reachable after a minute". By the time it runs the install is
# already written to disk, so that message was reporting a failure over a
# working update -- and 60 seconds was never enough anyway: the restart is
# RESTART_GRACE_S plus the whole teardown plus schedule_restart's own delay
# plus a cold start that opens twelve SQLite files and starts every worker.
_WAIT_FOR_RESTART = SETTINGS[SETTINGS.index("async function waitForRestart"):]
_WAIT_FOR_RESTART = _WAIT_FOR_RESTART[:_WAIT_FOR_RESTART.index("\n  }\n") + 5]
check("60000" not in _WAIT_FOR_RESTART,
      "waitForRestart no longer gives the restart a one-minute deadline")
check("after a minute" not in SETTINGS,
      "...and the 'still not reachable after a minute' failure message is "
      "gone with it")
check("var(--fail)" not in _WAIT_FOR_RESTART,
      "waitForRestart never paints a failure: it cannot tell a slow restart "
      "from a dead one, and the install is on disk either way")
check(_WAIT_FOR_RESTART.count("reachable()") >= 3,
      "waitForRestart waits for the OLD listener to go away first, and "
      "requires two consecutive successes before redirecting -- one poll "
      "answered by the process that is about to exit sent the browser to "
      "/login on a service that was going down")

# ---------------------------------------------- 5.8.0 the SNMPv3 protocol lists
#
# Two lists the server and the browser must agree on, and one the two
# browser modules must agree on between themselves, none of which anything
# else can see. The privacy one is the dangerous one: a name the server
# stores that the select does not offer showed "(none)" in the form, and the
# next Save posted a blank protocol and dropped the privacy blob with it --
# that was "AES128" before the alias map. The wireless auth list is a second
# copy of nodes.js's on purpose (modules load lazily, so nothing in nodes.js
# is guaranteed to exist when the controller form opens), and a copy is only
# safe while something checks it.
sys.path.insert(0, REPO_ROOT)
from netpath import snmpcrypt as _snmpcrypt  # noqa: E402
from netpath import trapdecode as _trapdecode  # noqa: E402
from netpath.web import api as _api  # noqa: E402

_NODES58 = read("nodes.js")
_WIRELESS58 = read("wireless.js")


def _js_list(source, name):
    match = re.search(r"const %s = \[(.*?)\];" % re.escape(name), source, re.S)
    return re.findall(r"'([^']+)'", match.group(1)) if match else None


_PRIV_LIST = _js_list(_NODES58, "V3_PRIV_PROTOCOLS")
_AUTH_LIST = _js_list(_NODES58, "V3_AUTH_PROTOCOLS")
_WIRELESS_AUTH = _js_list(_WIRELESS58, "V3_AUTH_PROTOCOLS")
check(_PRIV_LIST == ["AES"],
      "nodes.js's V3_PRIV_PROTOCOLS is exactly ['AES'] -- AES-128-CFB is the "
      "one cipher offered (found: %r)" % (_PRIV_LIST,))
# Every name the server can STORE, from every spelling it accepts, is a name
# the select offers. The spellings are snmpcrypt's table plus api.py's alias
# map, each pushed through the same _clean_priv_proto the routes call.
_STORED = set()
for _spelling in list(_snmpcrypt.PRIV_PROTOCOLS) + list(getattr(_api, "_PRIV_PROTO_ALIASES", {})):
    for _variant in (_spelling, _spelling.lower(), " %s " % _spelling):
        _fields = {"v3_priv_proto": _variant}
        _api._clean_priv_proto(_fields)
        _STORED.add(_fields["v3_priv_proto"])
check(_STORED <= set(_PRIV_LIST or []),
      "every privacy protocol name _clean_priv_proto can store is an option "
      "of the form's select (stored: %s)" % sorted(_STORED))
check(_AUTH_LIST is not None and set(_AUTH_LIST) <= set(_trapdecode.AUTH_PROTOCOLS),
      "every auth protocol nodes.js offers is one trapdecode.AUTH_PROTOCOLS "
      "can sign with (%r)" % (_AUTH_LIST,))
check(_AUTH_LIST is not None and "SHA1" not in _AUTH_LIST,
      "...and 'SHA1', the table's alias of 'SHA', is not offered as a second "
      "option for the same digest")
check(_WIRELESS_AUTH == _AUTH_LIST,
      "wireless.js's V3_AUTH_PROTOCOLS is the same list as nodes.js's "
      "(%r vs %r) -- fortipoll signs through the same localized_key"
      % (_WIRELESS_AUTH, _AUTH_LIST))
check("V3_AUTH_PROTOCOLS.map(" in _WIRELESS58
      and '<option value="MD5"' not in _WIRELESS58,
      "the controller form's auth select is built from that list, not from "
      "hand-written options")

# The Wireless settings dialog has the verify-replies switch the changelog
# says it has, posts it under the key wirelessdb.DEFAULTS stores, and its
# hint says what turning it off gives up.
_WL_SETTINGS = js_function(_WIRELESS58, "settingsDialog")
check('id="wl-v3verify"' in _WL_SETTINGS
      and "v3_verify_replies: m.querySelector('#wl-v3verify').checked" in _WL_SETTINGS,
      "wireless.js's settings dialog carries the SNMPv3 verify-replies switch "
      "and posts it as v3_verify_replies")
check("s.v3_verify_replies !== false ? 'checked'" in _WL_SETTINGS,
      "...rendered checked unless the stored value is explicitly false, the "
      "same reading nodes.js gives the same key (a missing key is the default, on)")
check("Turning this off gives that up" in _WL_SETTINGS
      and "unsigned answer is accepted" in _WL_SETTINGS,
      "...and its hint says what turning it off gives up")

# credentialBody: every refusal is thrown before the '(profile)' early
# return, and the add path says a refused credential rather than eating it.
_CRED_BODY = _NODES58[_NODES58.index("function credentialBody("):]
_CRED_BODY = _CRED_BODY[:_CRED_BODY.index("\n  }\n") + 4]
_FIRST_NULL = _CRED_BODY.index("return null")
check(_CRED_BODY.count("return null") == 1
      and "throw new Error" not in _CRED_BODY[:_FIRST_NULL]
      and _CRED_BODY.count("throw new Error") == 3
      and "!fields.v3_user || !fields.v3_auth_proto" not in _CRED_BODY[:_FIRST_NULL],
      "credentialBody returns null only when nothing was typed; a typed "
      "password that cannot be stored is thrown, never dropped")
_ADD_PATH = js_function(_NODES58, "addDevice")
check("/credential`, credential)\n              .catch(() => {})" not in _ADD_PATH
      and "credentialError" in _ADD_PATH
      and "but its SNMPv3 credential was not stored" in _ADD_PATH,
      "addDevice no longer swallows a refused credential POST: the refusal is "
      "toasted after the dialog closes on the row that was added")

# ---------------------------------------------------------------------------
# _slice59 returns "" for a missing anchor, so an edited-out check fails
# here rather than crashing and hiding every check after it.
def _slice59(body, start, end=None):
    if start not in body:
        return ""
    tail = body[body.index(start):]
    if end is None:
        return tail
    return tail[:tail.index(end)] if end in tail else tail


def _before59(body, first, second):
    return first in body and second in body and body.index(first) < body.index(second)


# 48. FRONTEND MODULES (5.9.1 review): the escaping, the per-event work and
#     the house patterns the module review of alerts/mapper/debug/netflow/
#     netpath/wireless/configrx/ipam/ssh turned up. Each is one line of text
#     in a file no linter reads.
_A59 = read("alerts.js")
_M59 = read("mapper.js")
_D59 = read("debug.js")
_NP59 = read("netpath.js")
_W59 = read("wireless.js")
_CX59 = read("configrx.js")

# 48a. A custom rule's key is operator-supplied text the server stores
#      verbatim, and it was the one field in that table written into the
#      markup raw — an attribute break that every account with alerts:read
#      then parsed.
check('data-rule-key="${escape(' in _A59,
      "the alerts rule key is escaped into its data attribute like every "
      "other field in that table")

# 48b. wireless radio channel is a TEXT column fed from an SNMP varbind, not
#      a number, and #wl-detail is written with innerHTML.
check("channel      ${escape(" in _W59,
      "the radio channel is escaped into the wireless detail pane — it is a "
      "TEXT column carrying whatever the controller answered")

# 48c. A node drag redrew every link touching the selection once per
#      pointermove. draw() has been rAF-coalesced since 5.0.1; the drag path
#      is the one that skipped it, and it needs its own handle so a queued
#      full redraw and a queued drag redraw do not cancel each other.
_NODE_DRAG59 = _slice59(_M59, "  function onNodePointerDown(",
                        "  function queuePositionWrite(")
check("function requestDragDraw()" in _M59 and "let dragPending = 0;" in _M59
      and "dragPending = window.requestAnimationFrame(" in _M59,
      "the drag redraw is coalesced to one animation frame on its own "
      "pending handle, not on draw()'s")
check(_NODE_DRAG59 and "requestDragDraw();" in _NODE_DRAG59
      and "redrawDragged();" not in _NODE_DRAG59,
      "...and the pointermove handler asks for that frame rather than "
      "rebuilding the links inside the event")

# 48d. Debug's filter read the DOM once per event: a querySelectorAll over
#      the category boxes and a fresh Set for each of up to 3,000 events, on
#      every one-second poll.
check("function passes(event, filter)" in _D59,
      "debug's passes() takes the filter it is to apply")
_PASSES59 = _slice59(_D59, "  function passes(event, filter)",
                     "  const EVENT_COLUMNS")
check(_PASSES59 and "categoriesOn()" not in _PASSES59
      and "App.el(" not in _PASSES59,
      "...and reads no control of its own, per event")
check("function currentFilter()" in _D59
      and _D59.count("const filter = currentFilter();") == 2
      and "view.events.filter(passes)" not in _D59,
      "the categories, the destination and the search needle are read once "
      "per draw and once per export, and both pass them in")

# 48e. NetPath's timeline: the same brush fix as NetFlow above, and the rect
#      measured before the signature check — a forced layout ten times a
#      second for a signature that was going to match.
_TL59 = _slice59(_NP59, "  function drawTimeline() {",
                 "  /* The overrun note is a sentence")
check("svg.dataset.timelineSig = sig;" in _TL59
      and not _before59(_TL59, "view.drag", "svg.dataset.timelineSig = sig;"),
      "a drag in progress is not part of the timeline's redraw signature")
check("const paintBrush = () =>" in _TL59 and _TL59.count("paintBrush();") >= 3,
      "...the timeline brush is one persistent rect moved in place, painted "
      "by the rebuild, by the pointermove and by the release")
check("if (svg.dataset.timelineSig === sig)" in _TL59
      and not _before59(_TL59, "getBoundingClientRect",
                        "if (svg.dataset.timelineSig === sig)"),
      "drawTimeline does not measure the pane before the signature check — "
      "fastTick calls it ten times a second and getBoundingClientRect forces "
      "a synchronous layout")
_RESIZE59 = _slice59(_NP59, "for (const event of ['resize', 'panes-resized'])",
                     "\n    }\n")
check("function measureTimeline()" in _NP59
      and "timelineSize = null;" in _RESIZE59
      and "timelineSize || measureTimeline()" in _TL59,
      "...the size is measured on the first draw and dropped again by the "
      "resize/panes-resized listeners, which are the only things that change it")

# 48f. mapper's toolbar state runs on the same 10Hz fastTick and wrote five
#      .disabled properties unconditionally.
_TOOLBAR59 = _slice59(
    _M59, "  function drawToolbarState() {",
    "  /* -------------------------------------------------------------- VLANs */")
check("button.disabled !== disabled" in _TOOLBAR59
      and "App.el('mp-remove-node').disabled =" not in _TOOLBAR59,
      "the mapper toolbar compares before assigning .disabled, the same rule "
      "App.setText/setHidden carry for every other fastTick redraw")

# 48g. Alerts re-fetched four configuration endpoints every 10s. They are
#      read on the first refresh, on a local edit, and otherwise on a slow
#      clock.
_REFRESH59 = _slice59(_A59, "  async function refresh() {",
                      "  function drawAlertsPager()")
check("async function loadConfig()" in _A59 and "CONFIG_MAX_AGE_MS" in _A59,
      "the alerts rules/extras/templates/device-thresholds reads live in one "
      "place with an age on them")
for _path in ("'/api/alerts/rules'", "'/api/alerts/rules/extras'",
              "'/api/alerts/templates'", "'/api/alerts/device-thresholds'"):
    check(_REFRESH59 and _path not in _REFRESH59,
          "%s is configuration: refresh() does not re-read it six times a "
          "minute" % _path)
check("const config = loadConfig();" in _REFRESH59 and "await config;" in _REFRESH59,
      "...refresh() still starts that read in its own round trip and waits "
      "for it before painting")
check(_A59.count("view.configAt = 0;") >= 7,
      "every editor in alerts.js drops the cached configuration beside its "
      "App.refreshNow('alerts'), so a local edit is on screen at once")

# 48h. Three late-filled <select>s were rebuilt on every poll whether or not
#      the list had changed. app.js has carried the write-only-if-changed
#      helper since 4.55.0.
check("App.setHtml(select, '<option value=\"\">any rule</option>'" in _A59,
      "the alerts rule filter is filled through App.setHtml")
check("App.setHtml(filterSelect, '<option value=\"\">All controllers</option>'" in _W59,
      "the wireless controller filter is filled through App.setHtml")
check("App.setHtml(select, '<option value=\"\">All vendors</option>'" in _CX59,
      "the ConfigRX vendor filter is filled through App.setHtml")

# 48i. editTemplate takes an id. The Reset cancel passed the template object,
#      so the lookup fell through to whatever row happened to be selected.
check("editTemplate(t.id);" in _A59 and "editTemplate(t);" not in _A59,
      "cancelling a template reset reopens that template by its id, not by "
      "an object the lookup can never match")

# 48j. The house pattern: refresh() opens with the tab check, and one with
#      more than one await re-checks after the last of them. dashboard.js is
#      not in this list on purpose — it is the one module that is not lazy.
for _name in ("alerts", "configrx", "debug", "ipam", "mapper", "netflow",
              "netpath", "nodes", "wireless"):
    _body = read("%s.js" % _name)
    _opening = _slice59(_body, "async function refresh()")[:200]
    check("if (App.state.tab !== '%s') return;" % _name in _opening,
          "%s.js's refresh() opens with the tab guard" % _name)
# 48k. The SSH page's comment said Escape was the documented way out of the
#      terminal; the hint under it and attachCustomKeyEventHandler both say
#      Ctrl+F6, and ssh.js explains why Escape deliberately is not (it is a
#      real keystroke to the device). A maintainer following the comment
#      would break vi/less/menu consoles for every operator.
_SSH_HTML59 = read("ssh.html")
_SSH_JS59 = read("ssh.js")
_SSH_COMMENT59 = _slice59(_SSH_HTML59, "<!-- The terminal traps Tab", "-->")
check(_SSH_COMMENT59 and "Ctrl+F6" in _SSH_COMMENT59
      and "Escape is the documented" not in _SSH_COMMENT59,
      "ssh.html's comment names the exit the code actually implements")
check("event.key === 'F6' && event.ctrlKey" in _SSH_JS59
      and "<kbd>Ctrl</kbd>+<kbd>F6</kbd>" in _SSH_HTML59,
      "...which is still Ctrl+F6, in the handler and in the visible hint")


_WL_REFRESH59 = _slice59(_W59, "  async function refresh() {",
                         "  function exportApsCsv()")
check(_WL_REFRESH59.count("App.state.tab !== 'wireless'") == 2,
      "wireless's refresh re-checks the tab after its second await, before it "
      "paints the detail pane and the table")


# ---------------------------------------------------------------------------
# 49. NODES/APP (5.9.1 review): the frontend-core findings. The paged device
#     list, the kiosk query string, the per-tick configuration fetches, the
#     two browser-built CSVs and the three status lines nobody could hear.
# addProfile/editProfile/removeProfile/setDefaultProfile/profileStatus moved
# to nodes_credentials.js (5.45.0); joined so the checks below still find them.
_N59 = static_text("nodes.js", "nodes_credentials.js")
# refresh() and the three helpers it was split into (readDeviceFilters,
# reconcileSelection, drawDevicePage) are one contiguous region.
_NODES_REFRESH59 = _slice59(_N59, "  function readDeviceFilters() {",
                            "  // aabbccddeeff -> aa:bb:cc:dd:ee:ff")

# 49a. F1. /api/nodes/devices has been paged since 4.47.0, so view.devices is
#      one page, not the fleet: dropping a selection that is not on it sent
#      every deep link to a device past page 1 back to the first row a tick
#      after it opened, with the address bar still naming the right device.
check("const wholeResultSet = view.pageTotal <= view.devices.length;" in _NODES_REFRESH59
      and "if (view.selected && wholeResultSet" in _NODES_REFRESH59,
      "nodes' refresh() clears the selected device only when the page it "
      "fetched IS the whole result set")
check("if (!view.selected && view.devices.length) view.selected = view.devices[0].id;"
      in _NODES_REFRESH59,
      "...and still selects the first device when nothing is selected")

# 49b. F2. `?kiosk=1&rotate=a"` made an invalid attribute selector, and the
#      SyntaxError out of initKiosk aborted the rest of start(): no module
#      init, no poll timer, no connection indicator, and a reload of the same
#      URL failed the same way.
check("const TAB_NAME_RE = /^[a-z]+$/;" in APP,
      "app.js pins the tab-name shape boot.js already validates against")
_KIOSK59 = _slice59(APP, "  function initKiosk() {", "  let lastKioskDraw = 0;")
for _variable in ("name", "nextName"):
    check(_before59(_KIOSK59, "TAB_NAME_RE.test(%s)" % _variable,
                 '.tab[data-tab="${%s}"]' % _variable),
          "the kiosk rotate name is validated before it reaches "
          '.tab[data-tab="${%s}"]' % _variable)
check(_KIOSK59.count("TAB_NAME_RE.test(") == 2,
      "both places kiosk mode builds a .tab[data-tab=] selector validate the "
      "name first — initKiosk's filter and drawKioskDots")
check(_slice59(APP, "    try {\n      initKiosk();").startswith(
          "    try {\n      initKiosk();\n    } catch (error) {"),
      "start() wraps initKiosk in try/catch: a bad query string cannot take "
      "the splitters, the module inits and the poll timer with it")

# 49c. F3. Nine requests a tick on an idle Nodes tab, four of them answering
#      questions nobody asked. Profiles, device groups and MIB files are
#      configuration — the alerts.js loadConfig shape, for the same reason.
check("const CONFIG_MAX_AGE_MS = " in _N59 and "async function loadNodesConfig()" in _N59,
      "the nodes profiles/device-groups/MIBs reads live in one place with an "
      "age on them")
for _path in ("'/api/nodes/groups'", "'/api/nodes/device-groups'", "'/api/nodes/mibs'"):
    check(_NODES_REFRESH59 and _path not in _NODES_REFRESH59,
          "%s is configuration: nodes' refresh() does not re-read it every "
          "tick" % _path)
check(_N59.count("view.configAt = 0;") >= 14,
      "every profile, device-group and MIB editor in nodes.js drops that "
      "cache beside its App.refreshNow('nodes'), so a local edit is on "
      "screen at once")
check("function profilesVisible()" in _N59
      and "if (profilesVisible()) {" in _NODES_REFRESH59,
      "the Profiles and MIBs tables are drawn only while their subtab is on "
      "screen, the way discoveryVisible() already gates the discovery pane")
check("function discJobsDue()" in _N59 and "if (!discJobsDue()) return;" in _N59,
      "...and the discovery jobs list is fetched every tick only while that "
      "pane is up or a sweep is running")

# 49d. F4. One open port dialog on a 500-port switch re-read the device's
#      whole interface list every 5 s and its whole metric catalogue every
#      15 s, to paint one row and find two ids that cannot change.
_IFD59 = _slice59(_N59, "    async function refreshStats() {", "    let tick = 0;")
check("`/api/nodes/devices/${deviceId}/interfaces`, { if_index: ifIndex }" in _IFD59,
      "the port dialog's stats refresh asks for the one interface it draws, "
      "not the device's whole interface list")
check("let chartMetrics = null;" in _IFD59
      and "let found = chartMetrics;" in _IFD59
      and _IFD59.count("/metrics`)") == 1,
      "...and the two metric ids behind its chart are looked up once for the "
      "life of the dialog, not re-listed every 15 s")

# 49e. F5. drawCapabilitiesTab runs on every tick while Bridge & RF is on
#      screen; it rebuilt every RF chart from innerHTML and re-fetched every
#      RF series with it. resourceHolder() is the precedent.
_RF59 = _slice59(_N59, "    const rf = (view.metrics || []).filter(",
                 "  /* One RF metric's last hour")
check(_RF59.count("rfEl.innerHTML =") == 1,
      "the RF section assigns innerHTML only in its 'no RF metrics' branch — "
      "the charts themselves are reused, not rebuilt per tick")
check("function rfHolder(container, metric)" in _N59
      and "const holder = rfHolder(rfEl, m);" in _RF59,
      "...each RF chart has a holder found by metric id, the treatment "
      "resourceHolder() gives the RESOURCES charts")
check("RF_SERIES_MAX_AGE_MS" in _RF59,
      "...and its series is re-fetched on its own slower clock, not once per "
      "refresh tick")

# 49f. F6. The one full-fleet fetch 4.47.0's paging work left behind: 1.5 MB
#      at 812 devices, every 30 s, for two Maps of {id, ip, name}.
_INDEX59 = _slice59(APP, "  async function deviceIndex() {",
                    "  /* Upgrades a plain IP address into a link")
check("get('/api/nodes/devices', { fields: 'index' })" in _INDEX59,
      "App.deviceIndex asks for the index projection, not every column of "
      "every device")

# 49g. F7. The availability and Top-N exports are the only two CSVs built in
#      the browser, and the only two that skipped the formula guard every
#      server-side export applies.
#
# 5.23.0/F2: the constant moved from api.py into netpath/csvout.py (as
# CSV_FORMULA_LEAD, api.py's own leading underscore dropped) alongside
# csv_cell/csv_text, so reportsched.py's emailed CSV shares the exact same
# formula-safe formatting without importing the route module.
with open(os.path.join(REPO_ROOT, "netpath", "csvout.py"), encoding="utf-8") as _handle:
    _CSVOUT59 = _handle.read()
_SERVER_LEADS59 = [json.loads('"%s"' % _part.strip().strip('"'))
                   for _part in _slice59(_CSVOUT59, "CSV_FORMULA_LEAD = (", ")").split("(")[1].split(",")
                   if _part.strip()]
_CSV_FIELD59 = _slice59(_N59, "  function csvField(value) {", "  function saveReportCsv(")
check("CSV_FORMULA_LEAD.test(s)" in _CSV_FIELD59,
      "nodes' csvField applies a formula-lead guard before it quotes")
_JS_LEAD59 = _slice59(_N59, "  const CSV_FORMULA_LEAD = /", "\n")
_JS_CLASS59 = _JS_LEAD59.split("= ")[1].strip().strip(";")[1:-1] if "= " in _JS_LEAD59 else None
_missing59 = [c for c in _SERVER_LEADS59
              if not _JS_CLASS59 or not re.compile(_JS_CLASS59).match(c)]
check(_SERVER_LEADS59 and not _missing59,
      "...over exactly csvout.py's CSV_FORMULA_LEAD set (missing: %s)"
      % (", ".join(repr(c) for c in _missing59) or "none"))

# 49h. F8. App.modal escapes a plain-string title itself — the three call
#      sites that escaped first put &amp; and &lt; on screen, and the device
#      dialog's failed-fetch path left the mangled heading there for good.
def _first_argument59(body, open_paren):
    depth = 0
    for i in range(open_paren, len(body)):
        ch = body[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return body[open_paren:i]
        elif ch == "," and depth == 1:
            return body[open_paren:i]
    return body[open_paren:]


_escaped_titles59 = []
for _name in MODULES:
    _body = read(_name)
    for _match in re.finditer(r"App\.modal\(", _body):
        if "escape(" in _first_argument59(_body, _match.end() - 1):
            _escaped_titles59.append("%s:%d" % (_name, _body.count("\n", 0, _match.start()) + 1))
check(not _escaped_titles59,
      "no App.modal title is escaped by its caller — App.modal is the one "
      "owner of that (found: %s)" % (", ".join(_escaped_titles59) or "none"))
# The approval dialog builds its heading into a variable first, so the scan
# above cannot see it; it is the third of the three sites.
check("escape(" not in _slice59(_N59, "    const title = cancelled", "\n    const lead"),
      "the discovery approval dialog's heading is not escaped by its caller "
      "either")
_DEVDLG59 = _slice59(_N59, "    Promise.all([\n      App.get(`/api/nodes/devices/${deviceId}`),",
                     "    // Hardware sensors and DOM/SFP sensors are their own on-demand")
check("box.querySelector('h2').textContent = displayName(listed || {})" in _DEVDLG59,
      "...and the device dialog names the device from the row it was opened "
      "from when its detail fetch fails")

# 49i. F9. Three status lines were written to plain elements with no
#      live-region role and announced nowhere.
for _function, _what in (("  function discStatus(text, isError) {", "discovery status"),
                         ("  function profileStatus(message, isError) {",
                          "polling-profile status")):
    check("App.announce(" in _slice59(_N59, _function, "\n  }\n"),
          "the %s line is announced, not said only to whoever can see it" % _what)
check("App.announce(" in _slice59(_N59, "    const show = (html) => {", "\n    };\n"),
      "the answer to a MAC search is announced as well as drawn")

# 49j. F10. The one cell in the DOM/SFP tables that did not escape its
#      device-supplied value.
check("escape(String(s.value))" in _slice59(_N59, "  function domValueCell(s) {",
                                            "  function domRowAttrs(s) {"),
      "domValueCell escapes its value like every sibling cell in those tables")

# ---------------------------------------------------------------------------
# 50. THE DASHBOARD PAINTS ON THE FIRST FRAME (5.10.0).
#
# start() wired the tabs, then awaited /api/state -> /api/config ->
# /api/platform — each up to 30 s, and all three at their slowest in the
# seconds right after the pollers start — before the eager module's init()
# painted so much as "Loading…" and before the first /api/dashboard went
# out. The heartbeat was the last line of all. Clicking to another tab and
# back was the reported workaround: that path runs activate()+refreshNow
# and waits for none of it.
DASH = read("dashboard.js")
_START = js_function(APP, "start")
# The boot chain's own first await — not the `await post('/api/logout')`
# inside the sign-out handler start() wires further up.
_FIRST_AWAIT = _START.index("await loadState()")
check("plannedInitialTab()" in _START
      and _START.index("plannedInitialTab()") < _FIRST_AWAIT,
      "start() works out the landing tab before its first await")
check("page.init()" in _START and _START.index("page.init()") < _FIRST_AWAIT,
      "the eager module's init() runs before the boot fetches, so the "
      "Dashboard paints 'Loading…' on the first frame")
check("selectTab(landing" in _START and _START.index("selectTab(landing") < _FIRST_AWAIT,
      "...and its selectTab issues the first /api/dashboard in parallel with "
      "/api/state rather than behind it")
check("restartTimer();" in _START and _START.index("restartTimer();") < _FIRST_AWAIT,
      "the heartbeat starts before the awaits, not after them — a page that "
      "loads hidden never reached the last line of start() at all")
check(_START.count("restartTimer();") == 1,
      "...and it is started in exactly one place in start()")
check("addEventListener('visibilitychange', onVisibilityChange)" in _START
      and _START.index("addEventListener('visibilitychange'") < _FIRST_AWAIT,
      "the visibility handler comes up with the heartbeat: a page brought "
      "forward while the boot is still fetching must not miss the one event "
      "that would start its timer")
check("function plannedInitialTab()" in APP
      and APP.count("localStorage.getItem(TAB_KEY)") == 1,
      "the landing tab (hash, then the remembered tab, then Dashboard) is "
      "worked out in one function rather than twice")
_ENSURE = js_function(APP, "ensureModuleReady")
_EAGER50 = _ENSURE.split("if (!isLazyModule(name))")[1].split(
    "if (pages[name] && pages[name].__ready)")[0]
check("if (!pages[name])" in _EAGER50
      and _EAGER50.index("Promise.reject(") < _EAGER50.index("Promise.resolve("),
      "ensureModuleReady checks an eager module exists before resolving with "
      "it — activating one that never registered was a silent no-op")
check("never registered" in _EAGER50,
      "...and it rejects with the same 'never registered' error the lazy path uses")
_ACTIVATE = js_const(APP, "activationReported") + js_function(APP, "activateTab")
check("activationReported" in _ACTIVATE and "console.error(" in _ACTIVATE,
      "activateTab's catch reports the failure once instead of swallowing it")
_MASTER50 = js_function(APP, "master")
check("!first.lastFetch" in _MASTER50 and "refreshNow(state.tab)" in _MASTER50,
      "a page that has never fetched still gets one refresh while /api/state "
      "is failing — a tab switch would have fetched it")
check("!state.loadingState" in _MASTER50 and "state.loadingState = false" in _MASTER50,
      "the state poll is single-in-flight like a page's own refresh: an "
      "/api/state slower than the 2 s tick would otherwise be aborted as "
      "superseded by the next tick, for ever, and never land at all")
check("state.loadingState = true" in _START
      and _START.index("state.loadingState = true") < _FIRST_AWAIT,
      "...and the boot's own first load claims the same flag, so the "
      "heartbeat started above it cannot abort it")
_PERMS50 = js_function(APP, "applyPermissions")
check("page.permissionsChanged()" in _PERMS50,
      "applyPermissions tells the modules already on screen that permissions "
      "have landed (the Dashboard now paints before /api/config answers)")
check("function permissionsChanged()" in DASH
      and "permissionsChanged" in DASH.split("App.pages.dashboard = ")[1],
      "...and dashboard.js takes that hook, so the offenders lists appear as "
      "soon as the nodes grant arrives")
_SPLIT50 = _START[_START.index("initKiosk();"):_START.index("window.addEventListener('resize'")]
check(_SPLIT50.count("try {") >= 2,
      "initSplitters() and applyDensity() are wrapped the way initKiosk() is, "
      "so neither takes the module inits and the boot route down with it")
_DRAW50 = js_function(DASH, "draw")
check("const parts = [errorLine];" in _DRAW50,
      "dashboard.js draws a failed read as a line ABOVE the tiles rather than "
      "replacing a whole shift's view with one sentence")
_DREFRESH50 = js_function(DASH, "refresh")
check("if (error && error.superseded) { draw({ ifChanged: true }); return; }" in _DREFRESH50,
      "a superseded first fetch still draws — returning left the grid on "
      "'Loading…' whenever the boot and the first poll tick overlapped")
_OFFENDERS50 = _DREFRESH50[_DREFRESH50.index("OFFENDERS_EVERY_MS) {"):]
check(_OFFENDERS50.index("view.offendersFetchedAt = now;")
      > _OFFENDERS50.index("await App.get('/api/dashboard/offenders')"),
      "...and offendersFetchedAt is stamped on the answer, not on the attempt")


# --- 51. 5.10.0: the firmware report, the HTTPS check and the Debug column ----
# DETAIL_FIELDS moved to nodes_settings.js (5.45.0) with the rest of the
# settings dialog; joined so the checks below still find it.
NODES51 = static_text("nodes.js", "nodes_settings.js")
NETPATH51 = read("netpath.js")
DEBUG51 = read("debug.js")
ALERTS51 = read("alerts.js")
for needle in ("'/api/nodes/reports/firmware'", "'/api/nodes/reports/firmware/export.csv'",
               "['sw_version', ", "['sw_image', "):
    check(needle in NODES51, "nodes.js carries the firmware report route / detail field %s" % needle)
for needle in ("f-https-url", "f-https-insecure", "WEB PAGE", "/api/netpath/https"):
    check(needle in NETPATH51, "netpath.js carries the web-page check element %s" % needle)
check("stat-web" in read("index.html"), "the Routes pane has the fifth 'Web page' tile")
check("'Web page'" in DEBUG51 and "worker.https" in DEBUG51,
      "the Debug page shows each destination's web-page state beside its trace state")
check('value="netpath_event"' in ALERTS51,
      "a custom rule can be given the netpath_event kind the HTTPS rule uses")



# --- 52. 5.11.0: a neighbour known only by its IP gets a name ---------------
NODES52 = read("nodes.js")
_NB52 = js_function(NODES52, "drawNeighborsTable")
_NB52 = _NB52[:_NB52.index("App.wireRowKeyboard(body)")]
check("r.resolved_name" in _NB52,
      "nodes.js' neighbours table shows the name the API resolved for an "
      "IP-only neighbour rather than the address")
check("(reverse DNS)" in _NB52 and "r.resolved_source === 'dns'" in _NB52,
      "...and says when that name came from a PTR record")
check('<div class="ip-line">' in _NB52,
      "...with the address on a visible line of its own, not only in a title "
      "on a span no keyboard or touch screen can reach")
check("'(not in Nodes)'" in _NB52 or "(not in Nodes)" in _NB52,
      "...while still saying plainly that the neighbour is not a Nodes device")

# 52a. 5.17.0: a MATCHED row also carries a visible IP line (its device's
#      own IP), not just its name — the same two-line cell either way.
check("r.matched_device_ip" in _NB52,
      "a matched neighbour row's Remote device cell also shows the matched "
      "device's IP, on its own ip-line, not the name alone")

# --- 53. 5.11.0: the Debug log resyncs itself after a server restart ---------
DEBUG52 = read("debug.js")
check("payload.last_seq < view.seq" in DEBUG52,
      "debug.js notices the server's cursor has gone backwards (a restart) "
      "rather than polling a seq the new log will not reach for hours")
check("payload.log_epoch !== view.epoch" in DEBUG52,
      "...and notices a different process's log even when the seq happens to "
      "have caught up")
check("view.events.length - view.capacity" in DEBUG52,
      "the in-memory trim follows the server's capacity instead of a "
      "hardcoded 3000")
check("const EVENT_ROW_CAP = 2000;" in DEBUG52,
      "...while the DOM row bound stays its own, separate number")


# --- 54. 5.11.0: the mute cap is seven days, in both mute dropdowns --------
ALERTS52 = read("alerts.js")
check("const MUTE_HOURS = [1, 6, 12, 24, 168];" in ALERTS52,
      "alerts.js offers the 168-hour (7-day) mute alongside the shorter ones")
check("const muteLabel = (h) =>" in ALERTS52,
      "...through a muteLabel() helper, so 168 never reaches a dropdown raw")
check("7-day cap" in ALERTS52,
      "...and the bulk-mute hint names the 7-day cap, not the old 24-hour one")
_MUTE_SELECT_OWNERS = {"alerts-d-mute-hours": "showDetail", "bm-hours": "bulkMuteDialog"}
for _id, _owner in _MUTE_SELECT_OWNERS.items():
    _owner_body = js_function(ALERTS52, _owner)
    _near52 = _owner_body[_owner_body.index('id="%s"' % _id):][:400]
    check("MUTE_HOURS.map(" in _near52,
          "the %s select is built from MUTE_HOURS rather than its own list" % _id)

# --- 55. 5.11.0: muting one rule on one device -----------------------------
ALERTS53 = read("alerts.js")
NODES53 = read("nodes.js")
for needle in ("alerts-d-mute-rule", "alerts-d-unmute-rule", "alerts-d-rule-muted"):
    check(needle in ALERTS53,
          "the alert detail carries the per-rule mute control %s" % needle)
check("rule_key: ruleKey" in ALERTS53,
      "...and the mute/unmute calls send the rule key the pane muted on")
check("ruleMutedUntil || ''" in ALERTS53,
      "...and the pane's rebuild signature includes the per-rule mute, so a "
      "lifted one is not left on screen until something else moves")
check("m.entity_kind === 'device_rule'" in ALERTS53,
      "refresh() fills view.ruleMutes from the device_rule rows of one "
      "/api/alerts/mutes read rather than a second request")
check("rule_muted_count" in NODES53,
      "the Nodes device list reads rule_muted_count, so a device with one "
      "muted rule is not drawn as fully alerting")

# ---------------------------------------------------------------------------
# 54. 5.11.0 FIX LANE: defects a review found in the shipped browser code.
NODES54 = read("nodes.js")
EVENTS54 = read("events.js")
DEBUG54 = read("debug.js")
ALERTS54 = read("alerts.js")
NETPATH54 = read("netpath.js")

# 54a. A device deleted elsewhere while selected made loadDetail() 404 every
#      tick, raising runRefresh's stale-connection banner and never clearing it.
_LOAD54 = _slice59(NODES54, "  async function loadDetail() {",
                   "  /* One sub-pane fetched and redrawn on its own")
check(_LOAD54 and "catch (error)" in _LOAD54 and "isMissing(error)" in _LOAD54,
      "loadDetail() catches a not-found from its own fetch instead of "
      "rejecting into the refresh plumbing")
check("function isMissing(error)" in NODES54
      and "error.status === 404" in NODES54 and "No such " in NODES54,
      "...and 'not found' means the two shapes the API actually answers "
      "with: a 404, or the 400 server.py turns _require's ValueError into")
check("That device has been removed." in _LOAD54,
      "...the pane says so in words rather than just going blank")
check("view.selected = view.devices.length ? view.devices[0].id : null;"
      in _LOAD54,
      "...and the selection moves to the first row on the page, so the next "
      "tick is healthy")
check(_NODES_REFRESH59
      and "const wholeResultSet = view.pageTotal <= view.devices.length;"
      in _NODES_REFRESH59,
      "...while refresh() still keeps an off-page selection: one page is not "
      "the fleet, and \"not in this list\" still does not mean \"gone\"")

# 54b. api.py sent `community: ""` to accounts that can't read it, indistinguishable
#      from a trap that carried none; the sibling _community_fields omits the key instead.
check("function communityText(row)" in EVENTS54,
      "events.js decides the Community / user cell in one place")
check("if (!('community' in row) && row.has_community) return 'not shown';"
      in EVENTS54,
      "...a trap that carried one says so without naming it, off the "
      "has_community flag and the ABSENCE of the key")
check("cell: (r) => escape(communityText(r))" in EVENTS54,
      "...the trap table's column renders through it")
check(EVENTS54.count("escape(communityText(row))") == 2,
      "...and so do both detail lines, the v3 user and the v1/v2c community")

# 54c. /api/debug answered false/0 for NetPath figures an account can't see,
#      reading as a false fault report instead of "no access".
check("summary.scheduler == null" in DEBUG54,
      "debug.js renders a null scheduler as an em dash, not as 'stopped': "
      "null is 'you cannot see this module'")
check("summary.workers_total == null" in DEBUG54,
      "...and the same for the worker counts, rather than '0 of 0 busy'")

# 54d. Alerts' config lists were read on a 60s clock, wrong for a tab just opened.
_ACT54 = _slice59(ALERTS54, "  async function activate(opts) {",
                  "  /* ----------------------------------------------------------- refresh */")
check(_ACT54 and _before59(_ACT54, "view.configAt = 0;", "if (!opts) return;"),
      "entering the Alerts tab drops the cached configuration BEFORE the "
      "opts guard -- a plain tab switch calls activate() with none")

# 54e. Both histogram pages plotted the width asked for, not the server's actual (wider) bucket_s.
for _name, _body in (("alerts.js", ALERTS54), ("events.js", EVENTS54)):
    check("overview.bucket_s ?? bucket" in _body,
          "%s plots the bucket width the server used, not the one it asked "
          "for" % _name)

# 54f. Pause froze the cursor too, so a paused tab re-downloaded the whole ring every poll.
_REF54 = _slice59(DEBUG54, "  async function refresh() {", "  function init()")
check(_REF54 and "if (payload.events.length) {" in _REF54
      and "if (!view.paused && payload.events.length)" not in _REF54,
      "the debug cursor and buffer advance outside the paused guard -- Pause "
      "stops the drawing, not the subscription")
check(_REF54 and _before59(_REF54, "view.seq = payload.last_seq;",
                           "if (!view.paused) drawEvents("),
      "...the cursor advances first and only the draw is conditional")
check("if (!view.paused) drawEvents({ append: true });" in DEBUG54,
      "...and Resume paints the buffer that filled while it was held")

# 54g. The restart resync emptied the destination select but skipped the
#      restore, moving the page back to "All destinations".
check("function restoreSavedTarget(select)" in DEBUG54
      and DEBUG54.count("restoreSavedTarget(select)") >= 3,
      "the remembered Debug destination is restored by the restart resync as "
      "well as by an ordinary batch")

# 54h. One failing secondary series rejected refresh() entirely, taking the
#      topology fetch and both draws below it down too.
_HTTPS54 = _slice59(
    NETPATH54, "if (currentTarget() && currentTarget().https_url) {",
    "renderWebStat();")
check(_HTTPS54 and "try {" in _HTTPS54 and "catch (error)" in _HTTPS54,
      "netpath.js' web-page series is fetched inside a try, like the "
      "dashboard's offenders list -- it is not allowed to take the topology "
      "fetch and the two draws below it down with it")
check(_HTTPS54 and "error.superseded" in _HTTPS54,
      "...while a superseded request is still rethrown, so an overlapping "
      "refresh is not mistaken for a failure")

# 54i. "muted" beside a rule name didn't distinguish a device-wide mute from a per-rule one.
_TAG54 = _slice59(ALERTS54, "  function mutedTagFor(row) {",
                  "  const alertColumns")
check(_TAG54 and "'device muted'" in _TAG54 and "'rule muted'" in _TAG54,
      "the muted tag says WHICH kind of mute is on the row")
check(_TAG54 and "Every alert for this device is muted until" in _TAG54
      and "This rule is muted on this device until" in _TAG54,
      "...and its title says which, and until when")

# 54j. An empty view.rules (not loaded yet) read as a deleted rule for one interval.
check("'Loading rules" in ALERTS54 and "(view.rules || []).length" in ALERTS54,
      "an empty rules list reads as 'still loading', not as 'this alert's "
      "rule has been deleted'")


# --- 56. 5.11.0: a rule that could not be evaluated says so ----------------
#      Fails closed with a `reason`, instead of reading as plain non-compliance.
CONFIGRX56 = read("configrx.js")
check("f.reason" in CONFIGRX56,
      "the Failed rules cell shows why a rule could not be evaluated, not "
      "just which rule it was")


# --- 57. FE-P4/P5: dialog polls go through App.pollWhileModal --------------
#      The dialog timers each re-implemented "stop when the dialog is gone"
#      and none of them honoured document.hidden, so a backgrounded tab kept
#      four dialogs' worth of fetches running.
NODES57 = read("nodes.js")
check("function pollWhileModal(" in APP and "pollWhileModal," in APP,
      "app.js defines App.pollWhileModal and exports it")
_POLL57 = APP[APP.find("function pollWhileModal("):]
check("document.hidden" in _POLL57[:400],
      "...and it skips the tick while the tab is hidden, like the master loop")
check("modalIsCurrent(token)" in _POLL57[:400],
      "...and stops itself once its dialog is no longer the current one")
check(NODES57.count("setInterval(") == 0,
      "nodes.js hand-rolls no dialog poller of its own: all 5 of its former "
      "setInterval( calls go through App.pollWhileModal")
check(NODES57.count("clearInterval(") == 0,
      "...and every clear path routes through the stop function it returns")



# --- 58. Part F, 5.16.0: the port dialog reads the stored MAC table first --
#      before waiting on the live SNMP read, so the dialog has something to
#      show immediately rather than sitting on "Reading MAC address table…"
#      for as long as the live walk takes.
NODES58 = read("nodes.js")
_MAC_ROUTE = "/mac-table`"
_first_mac = NODES58.find(_MAC_ROUTE)
_second_mac = NODES58.find(_MAC_ROUTE, _first_mac + 1)
check(_first_mac != -1 and _second_mac != -1,
      "nodes.js fetches the mac-table route twice (stored, then live)")
_between = NODES58[_first_mac:_second_mac]
check("stored: 1" in _between or "stored:1" in _between,
      "the FIRST mac-table fetch asks for stored=1, before the live one")
_second_call_line = NODES58[_second_mac:_second_mac + 80]
check("stored" not in _second_call_line,
      "...and the SECOND (live) fetch carries no stored=1 param")

# --- 59. 5.17.0: every line chart carries a hover readout ------------------
# 5.21.0 lifted drawSeriesChart/formatMetricValue (and the private helpers
# only they used — attachChartHover among them) into app.js, so the
# Dashboard's new chart tiles share the exact renderer Nodes always had;
# nodes.js keeps `const drawSeriesChart = App.drawSeriesChart` in their old
# spot so its three charts are unaffected. This section now reads app.js.
NODES59 = read("nodes.js")
check("const drawSeriesChart = App.drawSeriesChart;" in NODES59
      and "const formatMetricValue = App.formatMetricValue;" in NODES59,
      "nodes.js aliases the shared chart renderer rather than keeping its "
      "own copy")
_hover = APP.find("function attachChartHover(")
check(_hover != -1, "app.js defines attachChartHover for drawSeriesChart")
check("if (!opts.noHover) attachChartHover(" in APP,
      "drawSeriesChart attaches the hover layer unless a caller opts out")
_hover_body = APP[_hover:_hover + 3000]
check("class: 'chart-hover'" in _hover_body,
      "the hover layer is a full-plot rect.chart-hover, the walk's hook")
check("addEventListener('mousemove'" in _hover_body
      and "tooltip([{ text: when(anchor) }" in _hover_body,
      "mousemove shows the tooltip with the sample time as its first row")
check("addEventListener('mouseleave', hide)" in _hover_body
      and "hideTooltip()" in _hover_body,
      "mouseleave hides the tooltip and the guide")
check("formatMetricValue(unit, p.min)" in _hover_body,
      "rollup points show their min-max band beside the average")

# --- 60. 5.17.0: the Find box words an uplink-learned MAC hit as such -------
NODES60 = read("nodes.js")
_RESOLVE60 = js_function(NODES60, "resolveMacSearch")
check("via uplink to" in _RESOLVE60,
      "resolveMacSearch words an uplink-learned MAC hit as 'via uplink to "
      "<neighbour>', not a plain port name indistinguishable from an "
      "access-port hit")
check("loc.uplink" in _RESOLVE60 and "loc.uplink_to" in _RESOLVE60,
      "...reading the uplink/uplink_to fields the mac-search API returns")

# --- 61. 5.18.0: the interface dialog's bandwidth chart has a range picker -
NODES61 = read("nodes.js")
_ifd_body = js_function(NODES61, "interfaceDialog")
check("id=\"ifd-range\" aria-label=\"Chart range\"" in _ifd_body,
      "interfaceDialog's BANDWIDTH bar has a #ifd-range select")
check("App.fillRanges(box.querySelector('#ifd-range')" in _ifd_body,
      "...filled by App.fillRanges, the same helper #ndd-loss-range uses")
check("t1 - chartRange" in _ifd_body,
      "refreshChart reads the window from chartRange, not a hard-coded hour")

# --- 62. 5.19.0: Twilio SMS notifications reach the rule editor and settings
NODES62 = read("alerts.js")
check('id="ar-notify-sms"' in NODES62,
      "the rule editor's edit form offers a Send-a-text checkbox")
_ar_notify_sms_count = NODES62.count('id="ar-notify-sms"')
check(_ar_notify_sms_count >= 2,
      "the checkbox is offered in both the edit and the create rule forms")
check("values.notify_sms = box.querySelector('#ar-notify-sms').checked;" in NODES62,
      "both forms' Save handlers send notify_sms")
for _id in ("as-sms-minsev", "as-twilio-token", "as-sms-to-list",
           "as-sms-to-add", "as-testsms"):
    check('id="%s"' % _id in NODES62,
          "the alerts settings dialog has the %s control for Twilio SMS" % _id)
# These ids are handed to App.form.check/text/number as the first argument
# rather than written as literal id="..." markup, so the id itself is the
# quoted string those helpers are called with.
for _id in ("as-sms", "as-twilio-sid", "as-twilio-from", "as-twilio-msid",
           "as-sms-maxhour"):
    check("'%s'" % _id in NODES62,
          "the alerts settings dialog has the %s control for Twilio SMS" % _id)
check("App.post('/api/alerts/sms/test'" in NODES62,
      "Send test text posts to the SMS test route")
check("App.post('/api/alerts/sms/credential'" in NODES62,
      "Save stores a typed Twilio auth token through the SMS credential route")
check("texts sent" in NODES62,
      "the counters line reports texts sent the same way it reports emails "
      "and webhooks")

# --- 63. 5.20.0: Twilio API key authentication -----------------------------
NODES63 = read("alerts.js")
for _id in ("as-twilio-auth", "as-twilio-apikey-secret", "as-twilio-token-fields",
           "as-twilio-apikey-fields"):
    check('id="%s"' % _id in NODES63,
          "the alerts settings dialog has the %s control for Twilio API key auth" % _id)
check("'as-twilio-apikey-sid'" in NODES63,
      "the API Key SID field is built with App.form.text('as-twilio-apikey-sid', ...)")
check("auth_mode:" in NODES63,
      "Save posts auth_mode to the SMS credential route")
check("twilio_auth_mode:" in NODES63,
      "Save sends twilio_auth_mode in the /api/settings values")
check("for the selected method before saving" in NODES63,
      "Save refuses to silently switch auth mode without a new secret")
check('id="as-sms-consent"' in NODES63, "the SMS number list carries the A2P consent notice")
check("Reply STOP to unsubscribe" in NODES63, "...with STOP/HELP wording carriers expect")

# --- 64. 5.21.0: the modular Dashboard --------------------------------------
DASH64 = read("dashboard.js")
INDEX64 = read("index.html")
for _key in ("fleet", "open_alerts", "workers", "storage",
            "top_events", "top_iface_events", "top_alerts", "top_rtt",
            "top_loss", "top_cpu", "iface_traffic", "device_metric",
            "device_status", "top_metric", "recent_alerts", "recent_events",
            "note", "syslog_rate", "trap_rate", "netflow_top",
            "wireless_summary", "configrx_summary", "ipam_subnets",
            "https_monitors"):
    check(("%s:" % _key in DASH64) or ("%s(" % _key in DASH64),
          "TILE_TYPES carries the %s catalogue entry" % _key)
for _id in ("dash-edit", "dash-add", "dash-done", "dash-cancel", "dash-reset"):
    check('id="%s"' % _id in INDEX64,
          "index.html carries the %s dashboard edit-mode control" % _id)
check('draggable="true"' in DASH64,
      "dashboard.js's tile tools carry a native HTML5 drag handle")
check("/api/dashboard/layout" in DASH64
      and "App.get('/api/dashboard/layout')" in DASH64
      and "App.put('/api/dashboard/layout'" in DASH64
      and "App.del('/api/dashboard/layout'" in DASH64,
      "dashboard.js reads, saves and resets the layout through App's get/put/del")
check("drawSeriesChart, formatMetricValue, sparkline," in APP,
      "app.js exports drawSeriesChart, formatMetricValue and sparkline")
check("const drawSeriesChart = App.drawSeriesChart;" in read("nodes.js")
      and "const formatMetricValue = App.formatMetricValue;" in read("nodes.js"),
      "nodes.js still aliases the shared chart renderer rather than keeping its own copy")
check("Not readable with your access." in DASH64,
      "a tile whose module the account cannot read says so instead of showing numbers")
DEBUG64 = read("debug.js")
_DRAW_EVENTS64 = js_function(DEBUG64, "drawEvents")
_FOLLOW_IF = _DRAW_EVENTS64[_DRAW_EVENTS64.index("App.el('dbg-follow').checked"):
                            _DRAW_EVENTS64.index("wrap.scrollTop = wrap.scrollHeight;")]
check("atBottom" in _FOLLOW_IF and len(_FOLLOW_IF) < 120,
      "the Debug event log's forced scroll-to-bottom line sits inside an if "
      "that gates it on atBottom, not a bare follow-checkbox check")
check("atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight <= 4;" in _DRAW_EVENTS64
      and _DRAW_EVENTS64.index("atBottom =") < _DRAW_EVENTS64.index("frag.appendChild"),
      "atBottom is measured before rows are appended, not after")

# --- 65. Review fixes on the modular Dashboard ------------------------------
# A picker left on its default null (a device/interface never chosen) is not
# an int the server's config validation accepts — saveDraft must drop a
# null/undefined config value before the PUT rather than send it literally.
check("function sanitizedLayout(layout)" in DASH64,
      "dashboard.js strips null/undefined config values before saving")
_SANITIZED = js_function(DASH64, "sanitizedLayout")
check("value !== null && value !== undefined" in _SANITIZED,
      "...specifically by dropping keys whose value is null or undefined")
check("sanitizedLayout(view.draft)" in DASH64,
      "...and saveDraft actually calls it rather than PUTting view.draft raw")
_DRAGSTART = js_function(DASH64, "onDragStart")
check(_DRAGSTART.strip().startswith("function onDragStart(event) {\n    if (!view.editing) return;"),
      "onDragStart bails out in view mode before it can preventDefault() a "
      "plain link or text drag")

# --- 66. TACACS+ AAA, the themed combobox, dashboard graph tiles and
#         drill-down everywhere ---------------------------------------------
# C. App.comboBox replaces the Dashboard's <input list="dash-devices">
# datalist — the datalist is gone from index.html, and dashboard.js's device
# field goes through the shared widget instead of its own datalist wiring.
check("function comboBox(input, opts = {})" in APP,
      "app.js defines App.comboBox(input, opts)")
check(", comboBox," in APP or "figures, comboBox," in APP,
      "App.comboBox is exported on the api object")
check('id="dash-devices"' not in INDEX,
      "index.html no longer carries the shared #dash-devices datalist")
check(".combo-list {" in read("app.css") and ".combo-item {" in read("app.css"),
      "app.css styles .combo-list/.combo-item off tokens.css variables")
DASH66 = read("dashboard.js")
check("App.comboBox(input" in DASH66,
      "dashboard.js's wireDeviceField wires the field through App.comboBox")
check("WINDOW_OPTIONS" not in DASH66,
      "dashboard.js's own fixed WINDOW_OPTIONS list is gone, replaced by App.RANGES")
check("App.RANGES.map(" in DASH66,
      "windowSelectHtml offers every App.RANGES entry")

# B3. Dashboard graph tiles: interface traffic batches every row through the
# new /api/nodes/series/batch route, a tile carries a name and a Y max, and a
# non-edit-mode tile gets its own time-window control.
check("'/api/nodes/series/batch'" in DASH66,
      "the iface_traffic tile fetches through /api/nodes/series/batch")
for _id in ("dc-name", "dc-ymax", "dc-iface-rows", "dc-add-iface"):
    check('#%s' % _id in DASH66 or "'%s'" % _id in DASH66 or '"%s"' % _id in DASH66,
          "dashboard.js's Configure dialogs carry the %s control" % _id)
check('class="tile-range"' in DASH66,
      "renderTile draws a select.tile-range outside edit mode for graph tiles")
check("data-tile-live" in DASH66,
      "a pinned graph tile gets a Live button to clear its custom window")
check("s.dash" in APP and "'stroke-dasharray': s.dash" in APP,
      "drawSeriesChart draws a dashed stroke for a series carrying opts.dash")

# D1/D2. The shared range dialog and chart zoom/brush, in app.js.
check("function rangeDialog(current = {})" in APP,
      "app.js defines App.rangeDialog({t0, t1}) -> Promise<{t0,t1}|null>")
check("function rangeLabel(t0, t1, follow, presetLabel)" in APP,
      "app.js defines App.rangeLabel(t0, t1, follow, presetLabel)")
check("function attachChartZoom(svg, geo, opts = {})" in APP,
      "app.js defines App.attachChartZoom(svg, geo, opts)")
check("option.textContent = 'Custom…';" in APP,
      "fillRanges(..., {custom: true}) appends a literal 'Custom…' option")

# D3. Every "Custom…" call site and, where the plan calls for it, a pinned
# zoom/brush window that follows the same control.
NODES66 = read("nodes.js")
check("{ custom: true }" in NODES66
      and NODES66.count("App.rangeDialog(") >= 3,
      "nodes.js wires Custom… through App.rangeDialog at #ifd-range, "
      "#ndd-loss-range and #nd-d-range")
check("App.attachChartZoom(svg, geo" in NODES66,
      "the interface dialog's and the device dialog's charts attach "
      "App.attachChartZoom")
check("function setTimelineWindow(t0, t1)" in NODES66
      and "App.attachChartZoom(svg, { plot:" in NODES66,
      "drawStatusTimeline attaches App.attachChartZoom over its own bar geometry")
check("timelineWindow()" in js_function(NODES66, "loadRfChart"),
      "loadRfChart follows the #nd-d-range window instead of a fixed last hour")
for _name, _needle in (
        ("netpath.js", "App.rangeDialog("),
        ("netflow.js", "App.rangeDialog("),
        ("events.js", "App.rangeDialog("),
        ("alerts.js", "App.rangeDialog(")):
    check(_needle in read(_name), "%s wires its range select's Custom… to App.rangeDialog" % _name)
check("{ custom: true }" in read("netpath.js") and "{ custom: true }" in read("netflow.js")
      and "{ custom: true }" in read("events.js") and "{ custom: true }" in read("alerts.js"),
      "each of those range selects is filled with fillRanges(..., {custom: true})")
check("(hourly ${formatMetricValue(unit, p.min)}" in APP,
      "attachChartHover's rollup min-max band says 'hourly' beside the figures")

# A5. Settings -> SIGN-IN: the AAA (TACACS+) fieldset, and USERS' third
# auth-source radio.
INDEX66 = read("index.html")
check("AAA (TACACS+)" in INDEX66, "index.html carries the AAA (TACACS+) legend")
for _id in ("set-tacacs-enabled", "set-tacacs-servers", "set-tacacs-secret",
            "set-tacacs-secret-state", "tacacs-secret-hint", "set-tacacs-timeout",
            "set-tacacs-autocreate", "set-tacacs-role", "tacacs-apply", "tacacs-status",
            "tacacs-test-username", "tacacs-test-password", "tacacs-test",
            "tacacs-test-status", "new-auth-tacacs"):
    check('id="%s"' % _id in INDEX66, "index.html carries the %s AAA control" % _id)
SETTINGS66 = read("settings.js")
check("applyTacacsSettings" in SETTINGS66 and "testTacacs" in SETTINGS66,
      "settings.js defines applyTacacsSettings()/testTacacs()")
check("/api/settings/tacacs-test" in SETTINGS66,
      "testTacacs posts to /api/settings/tacacs-test")
check("paintTacacsSecretGate" in SETTINGS66 and "App.canStoreSecrets()" in SETTINGS66,
      "the shared secret field is gated on App.canStoreSecrets() like every "
      "other credential field")
check("tacacs_secret_set" in SETTINGS66,
      "settings.js reads the read-only tacacs_secret_set flag rather than "
      "ever painting a saved secret into the field")
check("AUTH_SOURCE_LABEL" in SETTINGS66 and "scope=\"col\">Source<" in SETTINGS66,
      "the users table gets a Source column naming local/LDAP/TACACS+")
check("['viewer', 'operator'].includes(s.tacacs_default_role)\n"
      "        ? s.tacacs_default_role : 'viewer'" in SETTINGS66,
      "a stored tacacs_default_role of anything but viewer/operator (admin, "
      "withdrawn in 5.51.0, or garbage) falls back to viewer in the select, "
      "not painted in as-is")
TACACS_ROLE_SELECT = re.search(
    r'<select id="set-tacacs-role">.*?</select>', INDEX66, re.S).group(0)
check(TACACS_ROLE_SELECT.count("<option") == 2
      and 'value="viewer"' in TACACS_ROLE_SELECT
      and 'value="operator"' in TACACS_ROLE_SELECT
      and 'value="admin"' not in TACACS_ROLE_SELECT,
      "#set-tacacs-role offers only viewer and operator, not admin")
check("admin: (mods) => Object.fromEntries(mods.map((m) => [m, 'write']))"
      in js_const(SETTINGS66, "ROLE_PRESETS"),
      "ROLE_PRESETS still carries its admin entry -- a separate, local-account "
      "feature that must not be removed by accident again")

# --- 67. Dashboard zoom: rounded t0/t1, ctrl-gated wheel, debounced saves --
DASH67 = read("dashboard.js")
check("(key === 't0' || key === 't1') ? Math.round(value) : value" in DASH67,
      "sanitizedLayout rounds t0/t1 to an int -- the server's _dash_int refuses a float")
check("Math.round(new Date(b.querySelector('#rd-start').value)" in APP
      and "Math.round(new Date(b.querySelector('#rd-end').value)" in APP,
      "App.rangeDialog's Apply handler rounds the start/end it resolves")
check("Math.round(Date.now() / 1000)" in APP,
      "App.rangeDialog's Date.now() clamp is rounded too")
check("wheelRequiresCtrl: true" in DASH67,
      "dashboard.js's tile zoom requires ctrl/meta on a wheel, so a plain "
      "wheel over a tile scrolls the page instead of zooming")
check("state.opts.wheelRequiresCtrl && !event.ctrlKey && !event.metaKey" in APP,
      "App.attachChartZoom's wheel listener honours opts.wheelRequiresCtrl")
check("function queueLayoutSave(layoutTile)" in DASH67 and ", 400)" in DASH67,
      "dashboard.js debounces a tile's zoom-driven layout save by 400ms "
      "instead of PUTting once per wheel tick")
_zoom67 = APP[APP.find("function attachChartZoom("):]
check("state.geo = { ...state.geo, t0: a, t1: b };" in _zoom67
      and "state.opts.onWindow(a, b);" in _zoom67
      and _zoom67.count("emit(") >= 6,
      "attachChartZoom advances its live window before calling onWindow, so "
      "a burst of wheel ticks compounds instead of recomputing from a stale geo")
_onwin67 = DASH67[DASH67.find("onWindow: (t0, t1) => {"):DASH67.find("onReset:")]
check("drawCharts()" not in _onwin67,
      "the tile's onWindow does not redraw from cached data between ticks")

# --- 68. 5.23.0: Nodes -> Devices gets an Uptime column (off by default) --
NODES68 = read("nodes.js")
check("{ key: 'uptime', label: 'Uptime', width: 110, numeric: true, on: false,"
      in NODES68,
      "nodes.js's COLUMNS carries the Uptime column, off by default")
check("r.sys_uptime_s != null ? App.duration(r.sys_uptime_s) : '—'" in NODES68,
      "...rendered through App.duration like every other elapsed-time cell")

# --- 69. 5.23.0: Mapper PNG export carries font/opacity/dash props too, and
# renders at device pixel ratio.
MAPPER69 = read("mapper.js")
_INLINE69 = js_function(MAPPER69, "inlineComputedColors")
check("'font-family'" in _INLINE69 and "'font-size'" in _INLINE69,
      "inlineComputedColors' props list carries font-family and font-size, so "
      "a label serialised for PNG export keeps its on-screen font instead of "
      "re-flowing into the browser default and overlapping neighbours")
for _prop in ("font-weight", "text-anchor", "letter-spacing", "opacity",
             "fill-opacity", "stroke-opacity", "stroke-dasharray", "dominant-baseline"):
    check("'%s'" % _prop in _INLINE69,
          "...and %s, so a manual link's dashed stroke and any faded element "
          "survive the export too" % _prop)
_EXPORT69 = js_function(MAPPER69, "exportPng")
check("Math.min(window.devicePixelRatio || 1, 2)" in _EXPORT69,
      "exportPng renders at devicePixelRatio, capped at 2x, instead of a 1:1 "
      "canvas that looks soft on any HiDPI screen")
check("canvas.width = width * scale" in _EXPORT69 and "ctx.scale(scale, scale)" in _EXPORT69,
      "...by scaling the canvas backing store and the context, while drawImage "
      "still targets the CSS size")

# --- 70. 5.23.0: NetFlow coverage readout on the collector status strip --
NETFLOW70 = read("netflow.js")
check("function coverageLine(coverage)" in NETFLOW70,
      "netflow.js defines coverageLine(), the A5 history strip formatter")
check("`history: ${bits.join(' · ')}`" in NETFLOW70,
      "the strip line leads with the literal 'history: ' prefix the "
      "operator was told to expect")
check("`raw ${App.span(coverage.raw_newest - coverage.raw_oldest)}`" in NETFLOW70,
      "...the raw span is rendered through App.span")
check("`minute ${App.span(coverage.minute_watermark - coverage.minute_floor)}`"
      in NETFLOW70 and "(${App.span(lagS)} behind)" in NETFLOW70,
      "...the minute span carries a '(... behind)' note once the rollup "
      "watermark has fallen behind sealed time")
check("`hourly ${App.span(coverage.hourly_watermark - coverage.hourly_floor)}`"
      in NETFLOW70,
      "...and the hourly span is rendered the same way")
check("collector.coverage" in NETFLOW70,
      "drawStatus reads coverage off the /api/state collector payload")

# --- 71. 5.23.0: Mapper manual links (D2) -----------------------------------
INDEX71 = read("index.html")
check('id="mp-connect" data-requires-write="mapper"' in INDEX71,
      "index.html's Mapper bar carries the Connect button, gated on mapper write")
MAPPER71 = read("mapper.js")
check("App.el('mp-connect').onclick = openConnect;" in MAPPER71,
      "mapper.js wires Connect to openConnect()")
check("['mp-connect', !canWrite || view.selection.size !== 2]" in MAPPER71,
      "Connect is enabled only when exactly two nodes are selected")
check("function openConnect()" in MAPPER71
      and "/api/mapper/maps/${view.mapId}/links`," in MAPPER71,
      "openConnect POSTs the two selected node ids to the manual-links route")
check(".mp-link.manual { stroke: var(--canvas-muted); stroke-dasharray: 6 4; }" in APP_CSS,
      "app.css draws a manual link as a dashed neutral path")
check("wireOne(path, link.manual ? 'manual' :" in MAPPER71,
      "drawLink tags a manual link's path with the .manual class")
check("data-remove-link=\"${link.link_id}\"" in MAPPER71,
      "linkDetailHtml's manual branch offers a Remove line button")
check("await App.del(`/api/mapper/maps/${view.mapId}/links/${link.link_id}`);" in MAPPER71,
      "...wired in renderDetail() to DELETE the line and reload the map")
check("return view.nodeByPeer.get(link.a_peer_key) || null;" in MAPPER71,
      "linkNodeA falls back to a_peer_key, so a manual line to an unmanaged "
      "peer on the A side still resolves")
# server.py is not under STATIC, but the CSP check above (5.7's PNG export
# fix) already reads its current content into SERVER_PY -- reused rather
# than reopening the file a second time.
check(r'r"^/api/mapper/maps/(\d+)/links$", api.post_mapper_map_links, ("mapper", W)' in SERVER_PY,
      "server.py routes POST .../maps/<id>/links to post_mapper_map_links, mapper write")
check(r'r"^/api/mapper/maps/(\d+)/links/(\d+)$"' in SERVER_PY
      and "api.delete_mapper_map_link" in SERVER_PY,
      "...and DELETE .../maps/<id>/links/<link_id> to delete_mapper_map_link")

# --- 72. 5.23.0: Priority ports -- flag a port, alert only on it going down
NODES72 = read("nodes.js")
check('id="ifd-priority"' in NODES72,
      "the interface dialog carries the ifd-priority checkbox")
_IFD72 = js_function(NODES72, "interfaceDialog")
_IFD_PRIORITY72 = _IFD72[max(0, _IFD72.index('id="ifd-priority"') - 100):
                         _IFD72.index('id="ifd-priority"') + 100]
check('data-requires-write="nodes"' in _IFD_PRIORITY72,
      "...gated on nodes write access like every other control that changes "
      "stored state")
check("{ key: 'priority', label: '★', width: 40, on: true," in NODES72,
      "IFACE_COLUMNS carries the priority (★) column, on by default")
check(r'r"^/api/nodes/devices/(\d+)/interfaces/(\d+)/priority$"' in SERVER_PY
      and "api.put_nodes_interface_priority" in SERVER_PY,
      "server.py routes PUT .../interfaces/<if>/priority to "
      "put_nodes_interface_priority, nodes write")
ALERTS72 = read("alerts.js")
check("r.key === 'priority_interface_down'" in ALERTS72,
      "the rule editor hints that priority_interface_down only fires for "
      "flagged ports")

# --- 73. 5.23.0: Wireless AP history charts (G3) ----------------------------
INDEX73 = read("index.html")
for _id in ("wl-hist", "wl-hist-range", "wl-hist-csv", "wl-hist-clients", "wl-hist-power"):
    check('id="%s"' % _id in INDEX73, "index.html's AP detail pane carries #%s" % _id)
check('<pre id="wl-detail"' in INDEX73
      and INDEX73.index('id="wl-hist"') < INDEX73.index('id="wl-detail"'),
      "the history block sits above the text detail <pre>, not inside it -- "
      "showDetail() rewrites that pre's innerHTML on every refresh, which "
      "would otherwise tear out the chart on every poll")
WIRELESS73 = read("wireless.js")
check("App.fillRanges(App.el('wl-hist-range'), 'Last 24 hours', undefined, { custom: true });"
      in WIRELESS73,
      "wireless.js fills #wl-hist-range through App.fillRanges with a Custom… option")
check("App.rangeDialog(view.historyPinned || {})" in WIRELESS73,
      "...and Custom… opens App.rangeDialog, the same picker every other "
      "chart's range select uses")
check("function loadHistory()" in WIRELESS73
      and "/api/wireless/aps/${apId}/history`" in WIRELESS73,
      "loadHistory reads the new per-AP history route")
check("App.drawSeriesChart(clientsSvg, App.el('wl-hist-clients')" in WIRELESS73
      and "App.drawSeriesChart(powerSvg, App.el('wl-hist-power')" in WIRELESS73,
      "both charts are drawn through App.drawSeriesChart, the same "
      "renderer /api/nodes/series/batch's charts use")
check("App.attachChartZoom(clientsSvg, clientsGeo, { onWindow });" in WIRELESS73
      and "App.attachChartZoom(powerSvg, powerGeo, { onWindow });" in WIRELESS73,
      "...and both attach App.attachChartZoom so a drag/wheel re-fetches "
      "the window instead of only rescaling what's already drawn")
check("if (view.historyApId !== row.id) {" in WIRELESS73,
      "history is (re)loaded only when the selected AP actually changes, "
      "not on the page's own 5s refresh tick")
check("function exportHistoryCsv()" in WIRELESS73
      and "App.el('wl-hist-csv').onclick = exportHistoryCsv;" in WIRELESS73
      and "App.exportCsv(`/api/wireless/aps/${view.historyApId}/history/export.csv`"
      in WIRELESS73,
      "the Export CSV button calls App.exportCsv against the history CSV route")
check(r'r"^/api/wireless/aps/(\d+)/history$", api.get_wireless_ap_history, ("wireless", R)'
      in SERVER_PY,
      "server.py routes GET .../aps/<id>/history to get_wireless_ap_history, wireless read")
check(r'r"^/api/wireless/aps/(\d+)/history/export\.csv$"' in SERVER_PY
      and "api.get_wireless_ap_history_export" in SERVER_PY,
      "...and GET .../aps/<id>/history/export.csv to get_wireless_ap_history_export")

# --- 74. 5.23.0: Nodes -> HISTORY, the series query builder (E1) -----------
INDEX74 = read("index.html")
check('data-subtab="history"' in INDEX74 and 'id="nodes-sub-history"' in INDEX74,
      "index.html has the HISTORY subtab button and the pane its prefix resolves to, "
      "the same subtab/pane pairing every nested subtab in this file already uses")
check(INDEX74.index('data-subtab="history"') > INDEX74.index('data-subtab="reports"'),
      "HISTORY sits after REPORTS in the Nodes nav, as specified")
for _id in ("nd-hist-rows", "nd-hist-add", "nd-hist-range", "nd-hist-bucket",
           "nd-hist-run", "nd-hist-csv", "nd-hist-clear", "nd-hist-chart", "nd-hist-table"):
    check('id="%s"' % _id in INDEX74, "index.html's HISTORY pane carries #%s" % _id)
NODES74 = read("nodes.js")
check("App.comboBox(devInput, {" in NODES74
      and "await App.get('/api/nodes/devices', { q, limit: 20 });" in NODES74,
      "each row's device field is wired over App.comboBox against "
      "/api/nodes/devices, the same helper dashboard.js's tile forms use")
check("function histFillMetricSelect(" in NODES74
      and "await App.get(`/api/nodes/devices/${deviceId}/metrics`)" in NODES74
      and "await App.get(`/api/nodes/devices/${deviceId}/interfaces`)" in NODES74,
      "the metric select is filled from both the device's own metrics and "
      "its interfaces, offering '<port> in'/'<port> out' entries")
check("addOption(`if_in_bps.${iface.if_index}`, `${port} in`);" in NODES74
      and "addOption(`if_out_bps.${iface.if_index}`, `${port} out`);" in NODES74,
      "...using the exact if_in_bps./if_out_bps. keys the batch route's "
      "_IFACE_METRIC_KEY_RE matches")
check("const HIST_MAX_ROWS = 8;" in NODES74,
      "the query builder caps at 8 rows, the batch route's own _SERIES_BATCH_MAX")
check("App.fillRanges(App.el('nd-hist-range'), 'Last 24 hours', undefined, { custom: true });"
      in NODES74,
      "the range select offers Custom… through App.fillRanges/App.rangeDialog "
      "like every other chart range picker")
check("await App.get('/api/nodes/series/batch', { q, t0, t1, bucket_s: bucketS });" in NODES74,
      "Run queries the existing batch route with the built q= string")
_HIST_DRAW_CHART74 = js_function(NODES74, "histDrawChart")
check("App.drawSeriesChart(svg, wrap," in _HIST_DRAW_CHART74
      and "App.attachChartZoom(svg, geo, {" in _HIST_DRAW_CHART74,
      "the chart is drawn through App.drawSeriesChart and wired to "
      "App.attachChartZoom, so a drag/wheel re-runs the query over the new window")
check("dash: iface && iface[1] === 'out' ? '4 3' : undefined," in NODES74,
      "an interface's out series is dashed, the same '4 3' dashboard.js's "
      "interface-traffic tile uses to tell in/out apart without colour alone")
check("function histDrawTable(" in NODES74 and "const tsSet = new Set();" in NODES74,
      "the table builds its row set from the union of every series' "
      "buckets, not just the first series' own list")
check("App.exportCsv('/api/nodes/series/export.csv'," in NODES74,
      "Export CSV calls the new server-side history export route")
check("localStorage.setItem(HIST_LOCAL_KEY, JSON.stringify({" in NODES74
      and "try {" in js_function(NODES74, "histSaveLocal")[:200]
      and "localStorage.getItem(HIST_LOCAL_KEY)" in NODES74,
      "the last query is remembered in localStorage under 'nodes.history', "
      "guarded by try/catch for a private window or blocked storage")
check("HIST_LOCAL_KEY = 'nodes.history';" in NODES74,
      "...under the literal key the walk/spec name")

# --- 75. 5.23.0: Nodes -> Reports -> SCHEDULED, emailed report schedules (F6)
INDEX75 = read("index.html")
check('data-subtab="scheduled"' in INDEX75 and 'id="nd-rep-sub-scheduled"' in INDEX75,
      "index.html has the SCHEDULED nested subtab button and the pane its "
      "prefix (nd-rep-sub-) resolves to")
for _id in ("nd-sched-mail-hint", "nd-sched-new", "nd-sched-table"):
    check('id="%s"' % _id in INDEX75, "index.html's SCHEDULED pane carries #%s" % _id)
NODES75 = read("nodes.js")
for _id in ("nd-sched-name", "nd-sched-kind", "nd-sched-params", "nd-sched-cadence",
           "nd-sched-hour", "nd-sched-minute", "nd-sched-weekday", "nd-sched-dom",
           "nd-sched-recipients", "nd-sched-enabled"):
    check('id="%s"' % _id in NODES75, "the New/Edit dialog carries #%s" % _id)
check("api.get_nodes_report_schedules" in SERVER_PY
      and r'r"^/api/nodes/reports/schedules$", api.post_nodes_report_schedule' in SERVER_PY,
      "server.py routes GET/POST /api/nodes/reports/schedules, nodes read/write")
check(r'r"^/api/nodes/reports/schedules/(\d+)$"' in SERVER_PY
      and "api.put_nodes_report_schedule" in SERVER_PY
      and "api.delete_nodes_report_schedule" in SERVER_PY,
      "...PUT/DELETE .../schedules/<id>, nodes write")
check(r'r"^/api/nodes/reports/schedules/(\d+)/run$"' in SERVER_PY
      and "api.post_nodes_report_schedule_run" in SERVER_PY,
      "...and POST .../schedules/<id>/run to send one now, nodes write")
check("function updateSchedMailHint()" in NODES75
      and "App.state.alertsSettings" in NODES75,
      "the mail-not-configured hint reads alertsSettings off the shared "
      "/api/config poll, the same way alerts.js's own settings dialog does")
check("function scheduleDialog(existing)" in NODES75,
      "nodes.js defines the New/Edit dialog function")

# --- 76. 5.23.0: max_wireless_db_mb, the wireless history size cap --------
INDEX76 = read("index.html")
check('id="set-wireless-cap"' in INDEX76 and 'id="use-wireless"' in INDEX76,
      "index.html's Data & Retention fieldset carries the Wireless database "
      "cap input and its usage meter, the same pair every other capped "
      "store's row has")
check("Wireless caps its AP/radio history samples" in INDEX76,
      "...and the hint paragraph explaining the caps no longer lists "
      "Wireless among the uncapped stores")
check("Wireless, ConfigRX and Mapper have no cap either" not in INDEX76,
      "...the stale 'Wireless has no cap' sentence is gone, not just added "
      "alongside a contradicting one")
SETTINGS76 = read("settings.js")
check("['max_wireless_db_mb', 'set-wireless-cap', 'num']" in SETTINGS76,
      "settings.js reads/writes max_wireless_db_mb through the same "
      "APPLY_FIELDS table every other cap uses")
check("App.el('set-wireless-cap').value = s.max_wireless_db_mb;" in SETTINGS76,
      "...and paints it back on load")
check("['wireless', 'size-wireless', 'age-wireless', 'use-wireless', "
      "'set-wireless-cap', true]" in SETTINGS76,
      "...and showUsage's per-store table now gives Wireless a meter/cap "
      "pair instead of the null/null a store with no cap gets")
check('"max_wireless_db_mb": (16, None),' in python_text("web.api"),
      "api.py's settings-range check has an entry for max_wireless_db_mb, "
      "like every other db-mb cap")
_APPDB76 = open(os.path.join(REPO_ROOT, "netpath", "appdb.py"), encoding="utf-8").read()
check('"max_wireless_db_mb": 256,' in _APPDB76,
      "appdb.py's GLOBAL_DEFAULTS carries the new key's default")
_SERVICE76 = open(os.path.join(REPO_ROOT, "netpath", "web", "service.py"),
                  encoding="utf-8").read()
check('Store("wireless", "Wireless", "wireless_db", "max_wireless_db_mb"),' in _SERVICE76,
      "service.py's STORES entry for wireless now carries its cap key, so "
      "the Dashboard headroom tile and the maintenance size-alert sweep "
      "both pick it up automatically")
check('self._trim_db("max_wireless_db_mb", self.wireless_db, "Wireless database",'
      in _SERVICE76,
      "_run_maintenance_body trims wireless.db to its cap, beside its own "
      "prune_ap_events/prune_history calls")

# --- 77. Review: wireless history_days/history_sample_s are range-checked --
WIRELESS77 = read("wireless.js")
for _id in ("wl-hist-days", "wl-hist-sample-s"):
    check('id="%s"' % _id in WIRELESS77,
          "the Wireless settings dialog carries #%s" % _id)
check("history_days: Number(m.querySelector('#wl-hist-days').value)," in WIRELESS77
      and "history_sample_s: Number(m.querySelector('#wl-hist-sample-s').value)," in WIRELESS77,
      "Save posts both fields to the wireless settings scope")
_API77 = python_text("web.api")
check('"wireless": {"history_days": (1, 3650), "history_sample_s": (60, 86400),' in _API77
      and '"ap_web_port": (1, 65535)},' in _API77,
      "api.py's _SCOPE_SETTINGS_RANGES carries the wireless override, so "
      "POST /api/settings refuses history_days <= 0 and history_sample_s "
      "below 60 the same way every other range-checked setting is refused")

# --- 78. Priority-port row tint; HISTORY device combo shows a real name --
NODES78 = read("nodes.js")
check("tr.className = r.priority ? 'clickable priority' : 'clickable';" in NODES78,
      "drawIfaceTable's App.drawRows callback adds 'priority' to a "
      "priority port's row class, alongside 'clickable', so the tint and "
      "the click handler share one row exactly like every other flagged "
      "row in this codebase")
check("tr.priority td { background: color-mix(in srgb, var(--accent) 10%, var(--panel)); }"
      in read("app.css"),
      "app.css tints a priority-port row off --accent/--panel tokens, so "
      "every theme block picks it up without a per-theme override")
check("function histDeviceLabel(d) {" in NODES78,
      "nodes.js's HISTORY device combo has its own label helper rather "
      "than repeating `${d.name || d.ip} (${d.ip})`")
check("const name = displayName(d);" in NODES78,
      "...and that helper reads the module's shared display-name "
      "precedence (manual name / sysName / name / ip), the same one "
      "the device pane, the device dialog and the interface dialog use, "
      "so a device known only by its SNMP sysName still shows a name "
      "instead of just its IP")
check(".map((d) => ({ id: d.id, label: histDeviceLabel(d) }));" in NODES78
      and "devInput.value = histDeviceLabel(d);" in NODES78,
      "...used for both the dropdown items and the label painted back "
      "after a reload, so the two never drift")


# --- 79. SFP inventory report, modelled on the firmware report -------------
NODES79 = read("nodes.js")
INDEX79 = read("index.html")
check('data-subtab="sfp"' in INDEX79, "the Reports nested nav carries the SFP INVENTORY subtab")
check('id="nd-rep-sub-sfp"' in INDEX79, "the SFP report has its own subpage")
for needle in ("'/api/nodes/reports/sfp'", "'/api/nodes/reports/sfp/export.csv'",
              "function runSfpReport(", "function drawSfpReportTable(",
              "function exportSfpReportCsv("):
    check(needle in NODES79, "nodes.js carries the SFP report route / handler %s" % needle)
_SERVER79 = open(os.path.join(REPO_ROOT, "netpath", "web", "server.py"),
                 encoding="utf-8").read()
for needle in (r'r"^/api/nodes/reports/sfp$"', r'r"^/api/nodes/reports/sfp/export\.csv$"'):
    check(needle in _SERVER79, "server.py routes the SFP report literal %s" % needle)


# --- 80. Copper transceivers: the COP badge (5.25.0) ------------------------
# interfaces.media gains 'copper'; sfpBadge grows a third case and the
# device-dialog live-DOM upgrade must never flip a COP row off a bare
# temperature reading.
NODES80 = read("nodes.js")
check("badge badge-cop" in NODES80 and "r.media === 'copper'" in NODES80,
      "sfpBadge renders the copper case off the stored media column, same "
      "as DOM/SFP")
check(".badge-cop" in APP_CSS,
      "app.css styles the COP badge, or it inherits the amber warning fill "
      "every other badge uses")
_DEV_DIALOG80 = js_function(NODES80, "deviceDialog")
check("r.media !== 'copper' && dialogOptics.has(r.if_index)" in _DEV_DIALOG80,
      "a stored COP row is never upgraded to DOM by the live /dom read, "
      "whatever it carries for that port")
check("dialogOptics = new Set(rows.filter((s) => s.unit === 'dBm')" in _DEV_DIALOG80,
      "the live read only counts an optical-power (dBm) row toward DOM -- "
      "a copper port's own temperature/voltage rows must not qualify")
check("{ key: 'medium', label: 'Medium', width: 80, cell: (r) => escape(r.medium || '') }"
      in NODES80,
      "the SFP report table has a Medium column, escaped like every other "
      "server-supplied string cell")
check("${result.dom_count} DOM · ${result.sfp_count} SFP · ${result.copper_count} COP`"
      in NODES80,
      "the SFP report summary line counts copper ports alongside DOM/SFP")
check("['device_id', 'name', 'ip', 'if_index', 'port', 'alias', 'kind',\n"
      "    'medium', 'optic_mode', 'media', 'oper_status', 'admin_status', "
      "'speed_bps',\n    'last_seen_ts', 'device']" in NODES80,
      "the client SFP_CSV_HEADER mirrors the server's CSV header order -- "
      "kind, medium, optic_mode, media")
check("r.alias, r.kind, r.medium, r.optic_mode, r.media, r.oper_status" in NODES80,
      "exportSfpReportCsv's row values are built in the same order as "
      "SFP_CSV_HEADER")

# --- 81. SFP report rows are keyed per port (5.25.0) ------------------------
# App.drawRows caches <tr>s by row.id; keying the SFP report on device_id
# collapsed every device to one on-screen row.
check("row.id = `${row.device_id}:${row.if_index}`;" in NODES80,
      "runSfpReport keys each report row by device and if_index, not device alone")

# --- 81b. SINGLE PSU report, modelled on the SFP report (5.35.0) -----------
NODES_PSU = read("nodes.js")
INDEX_PSU = read("index.html")
check('data-subtab="psu"' in INDEX_PSU, "the Reports nested nav carries the SINGLE PSU subtab")
check('id="nd-rep-sub-psu"' in INDEX_PSU, "the PSU report has its own subpage")
for needle in ("'/api/nodes/reports/psu'", "'/api/nodes/reports/psu/export.csv'",
              "function runPsuReport(", "function drawPsuReportTable(",
              "function exportPsuReportCsv("):
    check(needle in NODES_PSU, "nodes.js carries the PSU report route / handler %s" % needle)
_SERVER_PSU = open(os.path.join(REPO_ROOT, "netpath", "web", "server.py"),
                   encoding="utf-8").read()
for needle in (r'r"^/api/nodes/reports/psu$"', r'r"^/api/nodes/reports/psu/export\.csv$"'):
    check(needle in _SERVER_PSU, "server.py routes the PSU report literal %s" % needle)
check("row.id = `${row.device_id}:${row.member}`;" in NODES_PSU,
      "runPsuReport keys each report row by device and member, not device alone")
check("['device_id', 'name', 'ip', 'member', 'psu_total', 'psu_present',\n"
      "    'psu_down', 'supplies', 'stack_power', 'covered', 'last_ts', 'device']"
      in NODES_PSU,
      "the client PSU_CSV_HEADER mirrors report.PSU_CSV_HEADER's order")
_REPORT_PSU = open(os.path.join(REPO_ROOT, "netpath", "report.py"), encoding="utf-8").read()
check('PSU_CSV_HEADER = ["device_id", "name", "ip", "member", "psu_total", "psu_present",\n'
      '                  "psu_down", "supplies", "stack_power", "covered", "last_ts", "device"]'
      in _REPORT_PSU,
      "report.py's own PSU_CSV_HEADER is what nodes.js's copy is pinned against")

# --- 82. Duplicate evidence is scoped to a device's own interfaces ---------
# Only addresses a device reports on its own interfaces count toward
# duplicate detection; the discovery-addresses walk and the trap/merge
# writers are gone, so device_addresses now holds nothing else.
NODES82 = read("nodes.js")
INDEX82 = read("index.html")
check("Only addresses a device reports on its own\n"
      "        interfaces count as shared." in NODES82,
      "the Duplicates dialog's hint paragraph says shared-address evidence "
      "is scoped to a device's own interfaces")
check("'<p class=\"hint\">Only addresses a device reports on its own interfaces ' +\n"
      "        'count as shared.</p>'"
      in NODES82,
      "the Duplicates dialog repeats that scope note in the empty-state "
      "branch too, so the caveat holds even when nothing looks like a "
      "duplicate today")
check("Addresses on this device's own interfaces\n"
      "                (physical, VLAN, loopback, tunnel), read from its address\n"
      "                table every hour, and the default route it reports. Its ARP\n"
      "                table is on the ARP subtab." in INDEX82,
      "the Addresses subtab (nd-d-sub-addresses) carries a static hint "
      "explaining what the table holds and where the ARP table is")
check("np-discaddr" not in NODES82,
      "the discovery-addresses checkbox (np-discaddr) is gone from the "
      "Discovery settings dialog and the settings save payload")
check("discovery_addresses" not in NODES82,
      "discovery_addresses is gone from nodes.js entirely -- the setting "
      "no longer exists server-side")
check("Folded into" not in NODES82,
      "the \"Folded into\" note is gone from nodes.js -- folding no longer "
      "exists, every discovery result is its own row")
check("folded_into_result_id" not in NODES82,
      "folded_into_result_id is gone from nodes.js -- the server JSON no "
      "longer carries it")
_API82 = python_text("web.api")
_NODEPOLL82 = python_text("nodepoll")
check("address_owners(configured=True)" in _API82,
      "api.py's duplicate-evidence paths call address_owners(configured=True), "
      "so only ipAddrTable-sourced addresses feed duplicate detection")
check("device_id_for_address(ip, configured=True)" in _API82,
      "api.py's per-address conflict check calls device_id_for_address(ip, "
      "configured=True), the same configured-only rule")
check('device_id_for_address(result["ip"], configured=True)' in _NODEPOLL82,
      "nodepoll.py's promote() fold lookup passes configured=True too, "
      "so a discovered or trap-learned address never folds a result "
      "onto a device")

# --- 83. A flagged discovery result never pre-ticks, and ticking one forces
# it in as its own device rather than the "Same as" match. Server contract:
# POST .../promote takes {result_ids, force_result_ids}. Every result is its
# own row now -- there is no folding, so the rules key on
# duplicate_of_device_id alone.
NODES83 = read("nodes.js")
INDEX83 = read("index.html")
HINT83 = ("A row marked Same as is a device already added; it starts "
          "unticked, and ticking it adds it as a separate device.")
check("if (x.snmp_ok && !x.existing_device_id && !x.duplicate_of_device_id) "
      "view.discChecked.add(x.id);" in NODES83,
      "loadDiscResults' pre-tick seeding excludes an existing or "
      "duplicate-flagged row, keyed on duplicate_of_device_id alone")
check("(x) => x.snmp_ok && !x.existing_device_id && !x.duplicate_of_device_id)"
      in NODES83,
      "openApprovalDialog's seed excludes existing_device_id and "
      "duplicate_of_device_id rows, with no folded-row exclusion")
check("function discForceSplit(ids, rows) {" in NODES83,
      "discForceSplit is the one place ticked ids are split into the two "
      "promote() keys")
check("return { result_ids, force_result_ids };" in NODES83,
      "discForceSplit returns force_result_ids for a flagged row, so "
      "ticking one adds it as a separate device")
check("const force = !!(row && row.duplicate_of_device_id);" in NODES83,
      "discForceSplit keys the force decision on duplicate_of_device_id alone")
check("discForceSplit([...checked], results)).catch(() => {});" in NODES83,
      "the approval dialog's Add approved button posts through "
      "discForceSplit, not a bare result_ids array")
check("discForceSplit([...view.discChecked], view.discResults));" in NODES83,
      "promoteSelected (the Results pane) posts through discForceSplit too")
check(HINT83 in NODES83,
      "the approval dialog carries the new Same as hint sentence")
check(HINT83 in INDEX83,
      "the Results pane (#disc-promote) carries the same hint sentence, "
      "as a <p class=\"hint\"> near the Promote button")
check("Ticking adds it as a separate device \\u2014 ${escape(r.duplicate_reason || '')}"
      in NODES83,
      "discCheckCell's title on a flagged row is "
      "\"Ticking adds it as a separate device — <duplicate_reason>\"")

check("const selectable = view.discResults.filter((r) => discSelectable(r, job)\n"
      "      && !r.duplicate_of_device_id);" in NODES83,
      "the results grid's select-all skips flagged rows, which are added "
      "separately only by their own tick")
check("${flagged ? ' data-flagged=\"1\"' : ''}" in NODES83,
      "discCheckCell marks a flagged row's box with data-flagged, so it "
      "can be told apart from a plain selectable one")
check("const boxes = [...table.querySelectorAll(`.${cls}`)]"
      ".filter((b) => !b.dataset.flagged);" in NODES83,
      "wireDiscSelectAll (the approval dialog's header box) excludes "
      "flagged boxes from its subset, the same rule the Results grid's "
      "select-all applies")
check("const foundCount = found.length;" in NODES83,
      "the discard confirm's device count is just found.length -- there "
      "are no folded rows to exclude any more")
check("`<p>Discard this scan and all <b>${foundCount}</b> device(s) it found?</p>`"
      in NODES83,
      "the discard confirm text uses foundCount")
check("const already = found.filter((x) => x.existing_device_id).length;"
      in NODES83,
      "the already-monitored count is a plain existing_device_id filter, "
      "with no folded-row exclusion")

# ---------------------------------------------------------------------------
# 84. A device-name link reveals the device in the Nodes grid (5.30.0), and
#     the Addresses subtab shows a device's own interface names and its
#     default gateway.
check("function clearFilters(tab, ids, opts = {}) {" in APP and "clearFilters," in APP,
      "App.clearFilters exists and is exported")
check("el.onclick = () => clearFilters(tab, fields, { onClear: spec.onClear, refresh: go });"
      in APP,
      "the Clear button's own handler now calls clearFilters, rather than "
      "duplicating its body")
check("async function revealDevice(deviceId) {" in NODES,
      "nodes.js's revealDevice exists")
check("await revealDevice(deviceId);" in NODES,
      "activate() calls revealDevice for a device route carrying no "
      "q/name/filter of its own")
check("} else if (view.selected !== deviceId) {" in NODES,
      "a device route that DOES carry a q/name/filter keeps the old "
      "select-only behaviour, guarded the way it always was")
REVEAL = js_function(NODES, "revealDevice")
check("App.clearFilters('nodes', ['nd-q']);" in REVEAL,
      "revealDevice clears the Find box through App.clearFilters, the same "
      "reset the Clear button runs")
check("App.clearFilters('nodes', ['nd-filter-group', 'nd-filter-devgroup',\n"
      "        'nd-filter-status', 'nd-filter-offline', 'nd-filter-maintenance',\n"
      "        'nd-filter-overrides']);" in REVEAL,
      "revealDevice falls back to clearing the rest of the filter bar when "
      "Find alone did not surface the row")
check("let pagesLeft = 10;" in REVEAL and "pagesLeft > 0" in REVEAL,
      "revealDevice is bounded to ten extra pages of paging before giving up")
check("view.pageOffset + view.pageLimit < view.pageTotal" in REVEAL,
      "revealDevice stops paging once the pager itself says there is no "
      "next page left")
check("row.scrollIntoView({ block: 'nearest' });" in REVEAL and "if (row) " in REVEAL,
      "revealDevice scrolls the revealed row into view, guarded for a row "
      "that never turned up")
check('id="nd-addr-gateway"' in INDEX,
      "index.html carries the #nd-addr-gateway hint line above the "
      "Addresses table")
check("const gateway = App.el('nd-addr-gateway');" in NODES
      and "view.detail.default_gateway" in NODES,
      "drawAddressesTable fills #nd-addr-gateway from "
      "view.detail.default_gateway")
check("!gw ? 'Default gateway: not published by this device.'" in NODES,
      "the gateway line says plainly when the device published nothing")
check("`Default gateway: ${gw} (from ConfigRX backup)`" in NODES,
      "a gateway sourced from a ConfigRX backup (SNMP left the column "
      "empty) names where it came from")
check("`Default gateway: ${gw}`" in NODES,
      "a gateway SNMP itself published is shown plain")
check("default_gateway_source" in NODES,
      "drawAddressesTable reads the source api.py's device detail tags "
      "the gateway with")
check("const iface = r.interface ? escape(r.interface)" in NODES,
      "drawAddressesTable's Interface cell prefers the device's own "
      "r.interface name")
check('`<span title="ifIndex ${escape(String(r.if_index))}">#${' in NODES,
      "...falling back to #<if_index> with an \"ifIndex <n>\" title when no "
      "interface name is known")

# ---------------------------------------------------------------------------
# 85. A reload on Devices kept resetting the remembered Find/filter bar
#     (5.30.0 review): the boot-time replay of #/nodes/device/<id> now
#     carries opts.initial, so activate() takes the plain select branch
#     instead of revealDevice, which would otherwise clear what
#     restoreControls had just put back.
check('if (options.route) { deliverRoute(options.route, { initial: !!options.initial }); return; }'
      in APP,
      "activateTab forwards options.initial into deliverRoute")
check("function deliverRoute(route, deliverOpts = {}) {" in APP
      and "initial: !!deliverOpts.initial" in APP,
      "deliverRoute accepts an initial flag and passes it on to "
      "page.activate()'s opts")
check("selectTab(route.tab, { fromRoute: true, route, initial });" in APP,
      "applyRoute threads its own initial argument into selectTab")
check("{ fromRoute: true, route: bootRoute, initial: true }" in APP,
      "the boot-time early paint marks the replayed route as initial")
check("if (!filtered && !opts.initial) {" in NODES,
      "activate() skips revealDevice (and so keeps every remembered "
      "filter) on the boot-time replay of a device route")

# ---------------------------------------------------------------------------
# 86. MAPPER (5.31.0): Find a node. A plain text box beside the Map select,
#     not a dialog — the operator is orienting themselves on a map that may
#     hold hundreds of boxes, so autocomplete and Enter answer the question
#     without one more thing to click through.
MAPPER86 = read("mapper.js")
INDEX86 = read("index.html")
_MP_BAR86 = INDEX86[INDEX86.index('<div class="bar wrap">'):INDEX86.index('id="mp-add-device"')]
check('<label>Map <select id="mp-map"></select></label>' in _MP_BAR86
      and '<label>Find <input id="mp-find"' in _MP_BAR86
      and 'autocomplete="off"' in _MP_BAR86
      and '<div id="mp-find-list" class="mp-suggest" role="listbox" hidden></div>' in _MP_BAR86,
      "the Find box and its themed suggestion dropdown sit in the Mapper "
      "action bar, right after the Map select and before Add device")
check('data-requires-write' not in _MP_BAR86[_MP_BAR86.index('id="mp-find"'):
                                             _MP_BAR86.index('id="mp-find"') + 200],
      "Find is a read control: it selects a node already on the map, it "
      "does not write one")
check("function rebuildFindList()" in MAPPER86 and "function findMatches(text)" in MAPPER86
      and "function findNode(text)" in MAPPER86 and "function centerOn(node)" in MAPPER86
      and "function showFindSuggestions(text)" in MAPPER86
      and "function pickFindSuggestion(index)" in MAPPER86,
      "rebuildFindList/findMatches/findNode/centerOn/showFindSuggestions/"
      "pickFindSuggestion all exist")
_FIND86 = js_functions(MAPPER86, "findMatches", "renderFindList", "showFindSuggestions",
                       "centerOn", "findNode")
check("for (const value of [node.label, node.name, node.resolved_name, node.ip])" in _FIND86,
      "findMatches ranks over the same four fields — label, name, "
      "resolved_name, ip — that the dropdown is built from")
check("findItems = q ? findMatches(q).slice(0, FIND_SUGGEST_CAP) : [];" in _FIND86,
      "the dropdown's own list IS a ranked findMatches() call, capped at "
      "FIND_SUGGEST_CAP — no separate, independent suggestion source to "
      "drift out of step with Enter")
check("const FIND_SUGGEST_CAP = 12;" in MAPPER86,
      "the dropdown is capped at 12 suggestions")
check('escape(node.name || node.ip || \'\')' in _FIND86 and 'escape(node.ip)' in _FIND86,
      "each suggestion's name and ip line are escaped, like every other "
      "interpolated name in this file")
check("field === q ? 0 : field.startsWith(q) ? 1 : field.includes(q) ? 2 : 4" in _FIND86,
      "a node ranks by exact match, then prefix, then plain substring, "
      "case-insensitively")
check("view.frame.cx = pos.x;" in _FIND86 and "view.frame.cy = pos.y;" in _FIND86
      and "view.pan = { x: 0, y: 0 };" in _FIND86
      and "view.zoom = Math.max(view.zoom, 1);" in _FIND86
      and "applyTransform();" in _FIND86,
      "centerOn re-centres the frame on the node and never zooms OUT to "
      "show it — a Find should not leave the operator squinting at a map "
      "that was already zoomed in further than 1x")
check("setSelection(new Set([node.id]));" in _FIND86 and "focusCanvas();" in _FIND86,
      "centerOn selects the found node and hands the canvas keyboard focus, "
      "the same as clicking it would")
check("view.findIndex = (view.findQuery.toLowerCase() === q.toLowerCase() && view.findIndex >= 0)"
      in _FIND86,
      "findNode only advances to the NEXT hit when the box still holds the "
      "same text as last time — a changed search restarts at the first hit")
check('App.toast(`No device on this map matches "${q}".`, \'fail\');' in _FIND86,
      "no match at all is reported through App.toast, not silence")
check("App.el('mp-find').addEventListener('keydown', onFindKeydown);" in MAPPER86,
      "init() wires Enter on #mp-find to findNode")
check("rebuildFindList();" in MAPPER86
      and MAPPER86.count("rebuildFindList();") == 2,
      "loadMapData rebuilds the datalist on both its branches (a real "
      "payload, and the no-map-selected reset)")

# ---------------------------------------------------------------------------
# 87. MAPPER (5.31.0): Select all in Add device and Add neighbours. Each
#     dialog keeps its own picked-id/-key Set OUTSIDE the DOM (draw2/
#     redrawNeighbourRows tear the tbody down and rebuild it on every
#     keystroke and every sort), so the header checkbox and the Add button
#     both read that Set, never the DOM's own checked state.
MAPPER87 = read("mapper.js")
_ADD_DEVICE87 = js_function(MAPPER87, "openAddDevice")
_ADD_NEIGH87 = js_function(MAPPER87, "openAddNeighbours")
for _name, _block, _picked, _field in (
    ("Add device", _ADD_DEVICE87, "devicePicked", "r.id"),
    ("Add neighbours", _ADD_NEIGH87, "neighbourPicked", "r.key"),
):
    check("selectAll: {" in _block,
          "%s passes a selectAll option to App.grid" % _name)
    check("key: 'check'," in _block, "...keyed to the 'check' column")
    check("label: 'Select all listed devices'," in _block,
          "...with the label 'Select all listed devices'" )
    check("checked: rows.length > 0 && rows.every((r) => %s.has(%s))" % (_picked, _field) in _block,
          "...checked is true only when EVERY currently filtered row (not "
          "the full candidate list) is in %s" % _picked)
    check("some: rows.some((r) => %s.has(%s))" % (_picked, _field) in _block,
          "...some (the indeterminate state) reads the same filtered rows")
    check("onToggle: (on) => {" in _block,
          "...onToggle is provided")
    check("for (const r of rows) { if (on) %s." % _picked in _block,
          "...onToggle adds or removes exactly the filtered rows, not the "
          "whole candidate list")
    check(("const %s = [...%s];" % ("ids" if _picked == "devicePicked" else "keys", _picked)) in _block,
          "the Add button reads %s directly, not a fresh "
          "querySelectorAll('.mp-pick:checked') over a tbody that may have "
          "just been rebuilt" % _picked)
    check("%s = new Set();" % _picked in _block,
          "...and the dialog starts each open with a fresh, empty Set")
    check("body.addEventListener('change', (event) => {" in _block,
          "a checkbox tick is caught by delegation on the tbody, since the "
          "tbody itself is rebuilt on every redraw")
check("cell: (r) => `<input type=\"checkbox\" class=\"mp-pick\" data-id=\"${r.id}\"` +\n"
      "        `${devicePicked.has(r.id) ? ' checked' : ''}>` }" in MAPPER87,
      "DEVICE_PICK_COLUMNS' checkbox cell renders `checked` from devicePicked, "
      "not from nothing (a checkbox that never shows a previously-ticked row "
      "as ticked again after a redraw is the same bug as never keeping the "
      "pick at all)")
check("cell: (r) => `<input type=\"checkbox\" class=\"mp-pick\" data-key=\"${escape(r.key)}\"` +\n"
      "        `${neighbourPicked.has(r.key) ? ' checked' : ''}>` }" in MAPPER87,
      "NEIGHBOUR_PICK_COLUMNS' checkbox cell renders `checked` from "
      "neighbourPicked the same way")

# ---------------------------------------------------------------------------
# 88. MAPPER (5.31.0): Frames — a labelled decoration drawn under every
#     link and node. A frame never moves what it encloses: nothing in this
#     section reads or writes view.nodes' own x/y.
MAPPER88 = read("mapper.js")
INDEX88 = read("index.html")
APP_CSS88 = read("app.css")
_MP_BAR88 = INDEX88[INDEX88.index('<div class="bar wrap">'):INDEX88.index("</div>", INDEX88.index('<div class="bar wrap">'))]
check('id="mp-add-frame" data-requires-write="mapper"' in INDEX88,
      "the Frame button exists and is gated on mapper write")
check(INDEX88.index('id="mp-connect"') < INDEX88.index('id="mp-add-frame"'),
      "Frame sits after Connect in the action bar")
check("['mp-add-frame', !canWrite || !hasMap]," in MAPPER88,
      "Frame is disabled with no map selected or no write access, in the "
      "same toolbar-state table as every other mapper write control")

# 88a. The three frame routes, and the fill/stroke pointer-events split
#      that keeps a rubber-band drag or a pan working with the pointer
#      resting over the INSIDE of a frame.
check("await App.post(`/api/mapper/maps/${view.mapId}/frames`, { x, y, width, height });" in MAPPER88,
      "createFrame POSTs the new rectangle to .../maps/<id>/frames")
check("await App.put(`/api/mapper/maps/${view.mapId}/frames/${frame.id}`, { label });" in MAPPER88
      and "await App.put(`/api/mapper/maps/${view.mapId}/frames/${frame.id}`, { color });" in MAPPER88,
      "the label save and each colour swatch PUT .../frames/<id> with just "
      "their own field")
check("() => App.del(`/api/mapper/maps/${view.mapId}/frames/${id}`)," in MAPPER88,
      "removeFrame DELETEs .../frames/<id>, through the same "
      "App.confirmDestructive action-callback shape confirmDeleteMap and "
      "removeSelected already use")
check("'pointer-events': 'none'" in MAPPER88 and "'pointer-events': 'stroke'" in MAPPER88,
      "the fill rect takes no pointer events at all, and the stroke rect "
      "only on the outline itself, so a drag started over a frame's own "
      "interior still reaches the canvas below it")

# 88b. frameLayer paints under both links and nodes (§28d's own pin, above,
#      already covers the exact append order — this just names the class
#      list a frame's <g> carries and the fixed child order within it).
_DRAW_FRAME88 = js_function(MAPPER88, "drawFrame")
check("g.append(fill, stroke, label, handle);" in _DRAW_FRAME88,
      "a frame's <g> holds its fill, stroke, label and resize handle in "
      "that fixed order")
check("class: `mp-frame ${frameColorClass(frame)}${selected ? ' selected' : ''}`" in _DRAW_FRAME88,
      "the <g> carries .selected only when it is the selected frame")
for _idx in range(6):
    check(".mp-frame-c%d {" % _idx in APP_CSS88, "app.css defines .mp-frame-c%d" % _idx)
check("--mp-frame-color: var(--canvas-vlan-1);" in APP_CSS88
      and "--mp-frame-color: var(--canvas-vlan-6);" in APP_CSS88,
      "the six frame colours share --canvas-vlan-1..6, the same "
      "canvas-tuned hues a VLAN strand already draws with in every theme")

# 88c. Drawing: Frame arms view.framing, the next empty-canvas drag reuses
#      the rubber-band gesture, and disarming is the same one function
#      whichever way the gesture ends.
check("view.rubber = { x0: p.x, y0: p.y, x1: p.x, y1: p.y, drawFrame: true };" in MAPPER88,
      "the framing drag reuses view.rubber (and so onSvgPointerMove/"
      "drawRubber) wholesale, distinguished only by the drawFrame flag")
check("if (view.rubber && view.rubber.drawFrame) {" in MAPPER88,
      "onSvgPointerUp branches on that flag before the ordinary "
      "rubber-band/multi-select handling runs")
check("if (width >= FRAME_MIN && height >= FRAME_MIN) createFrame(x, y, width, height);" in MAPPER88
      and "const FRAME_MIN = 40;" in MAPPER88,
      "a rectangle under 40x40 scene units is dropped, not POSTed")
check("function disarmFraming()" in MAPPER88
      and MAPPER88.count("disarmFraming();") >= 3,
      "disarmFraming is the one place that un-arms the tool — called after "
      "a finished drag (including a too-small one), on Escape, and when "
      "the toolbar state itself would otherwise leave a disabled button "
      "looking armed")
check("if (event.key !== 'Escape' || App.state.tab !== 'mapper' || !view.framing) return;" in MAPPER88,
      "Escape only disarms while framing is actually armed, and only on "
      "the Mapper tab")

# 88d. Selecting, editing and removing a frame.
check("function selectFrame(frame) {" in MAPPER88,
      "selectFrame is the keyboard-only path (a frame's own Enter/Space) "
      "that selects a frame and clears whatever node/link selection there "
      "was, via a full requestDraw()")
_SELECT_FRAME88 = js_function(MAPPER88, "selectFrame")[:250]
check("view.selectedFrameId = frame.id;" in _SELECT_FRAME88
      and "view.selection = new Set();" in _SELECT_FRAME88
      and "view.selectedLinkId = null;" in _SELECT_FRAME88,
      "...it sets selectedFrameId and clears both the node selection and "
      "selectedLinkId")

# 88d-bis (5.31.1 fix): a requestDraw()'d select here detaches the very <g>
# the pointer just captured, so the drag's own move/up listeners never fire
# and no PUT is ever queued. selectFrameInPlace toggles .selected in place.
check("function selectFrameInPlace(frame) {" in MAPPER88,
      "selectFrameInPlace is the frame analogue of applySelectionClasses: "
      "an in-place selection with no redraw, for onFramePointerDown's own "
      "press")
_SELECT_FRAME_IP88 = js_function(MAPPER88, "selectFrameInPlace")[:600]
check("view.selectedFrameId = frame.id;" in _SELECT_FRAME_IP88
      and "view.selection = new Set();" in _SELECT_FRAME_IP88
      and "view.selectedLinkId = null;" in _SELECT_FRAME_IP88,
      "...it sets the same three fields selectFrame does")
check("el.classList.toggle('selected', id === frame.id);" in _SELECT_FRAME_IP88,
      "...but toggles .selected on the frame <g>s already in the DOM "
      "rather than rebuilding them")
check("if (!view.frameEls.size) { requestDraw(); return; }" in _SELECT_FRAME_IP88,
      "...with a requestDraw() fallback only for a press that somehow "
      "lands before the first paint (no frame elements to toggle yet)")
check("requestDraw();\n    drawDetail();" not in _SELECT_FRAME_IP88,
      "...and the ordinary path never falls through to a requestDraw() + "
      "drawDetail() pair the way selectFrame's does")
_ON_FRAME_PD88_FULL = js_function(MAPPER88, "onFramePointerDown")
_ON_FRAME_PD88 = _ON_FRAME_PD88_FULL[:400]
check("selectFrameInPlace(frame);" in _ON_FRAME_PD88,
      "onFramePointerDown's select half calls selectFrameInPlace, not "
      "selectFrame, so the press that arms a drag never triggers a "
      "requestDraw()'d redraw underneath it")
check("selectFrame(frame);" not in _ON_FRAME_PD88,
      "...and no longer calls the requestDraw()-based selectFrame at all")
check("if (!App.canWrite('mapper')) return;" in _ON_FRAME_PD88,
      "a reader may select a frame (selectFrameInPlace above already ran) "
      "but the drag itself never arms below this guard")
check("view.selectedFrameId = null;" in js_function(MAPPER88, "setSelection")[:200]
      and "view.selectedFrameId = null;" in js_function(MAPPER88, "selectLink")[:300],
      "...and selecting a node or a link clears the frame selection back")
check("if (view.selectedFrameId) {" in js_function(MAPPER88, "renderDetail")[:400],
      "renderDetail's FRAME branch runs before the link/node branches")
check("function frameDetailHtml(frame)" in MAPPER88 and "function frameSwatchesHtml(frame, canWrite)" in MAPPER88,
      "the frame pane has its own label-input/colour-swatch/Remove markup")
check("data-requires-write=\"mapper\"${gate}" in MAPPER88,
      "the frame pane's input/swatches/Remove are gated on mapper write "
      "exactly the way the node rename field is (disabled, not hidden)")
check("if ((event.key === 'Delete' || event.key === 'Backspace') && view.selectedFrameId) {" in MAPPER88,
      "Delete/Backspace on the canvas removes the selected frame")
check("function removeFrame(id)" in MAPPER88 and "App.confirmDestructive('Remove frame'," in MAPPER88,
      "removeFrame confirms the same way removeSelected does for nodes, "
      "shared by the pane's own Remove button and the keyboard shortcut")
# 5.31.1 fix: the pane's Remove button was gated on canWrite, but the two
# keyboard paths above were not — a reader got a confirm then a 403 toast.
check("function removeFrame(id) {\n    if (!App.canWrite('mapper')) return;" in MAPPER88,
      "removeFrame checks canWrite as its very first line, closing both "
      "keyboard paths a reader could otherwise reach it through")

# 88e. Moving/resizing: a debounced, per-frame write with the same
#      debounce/retry constants flushPositionWrites already uses.
check("function queueFrameWrite(id, patch)" in MAPPER88 and "function flushFrameWrite(id)" in MAPPER88,
      "queueFrameWrite/flushFrameWrite exist")
check("view.frameWriteTimers.set(id, setTimeout(() => flushFrameWrite(id), WRITE_DEBOUNCE_MS));"
      in MAPPER88,
      "a frame write debounces on WRITE_DEBOUNCE_MS, the same constant "
      "flushPositionWrites uses for a node drag")
check("view.frameWriteRetryTimers.set(id, setTimeout(() => flushFrameWrite(id), WRITE_RETRY_MS));"
      in MAPPER88,
      "...and retries on WRITE_RETRY_MS after a failed PUT, with a toast "
      "(the same idiom, not a silently dropped edit)")
check("view.pendingFramePatches = new Map();" in MAPPER88 or "pendingFramePatches: new Map()," in MAPPER88,
      "one pending patch is tracked per frame id, not one shared patch for "
      "every frame being edited at once")
check("if (snap) { x = snapValue(x); y = snapValue(y); }" in _ON_FRAME_PD88_FULL,
      "a frame move snaps to the grid the same way a node drag does when "
      "Snap is on")
check("Math.max(FRAME_MIN, snapValue(width))" in MAPPER88 and "Math.max(FRAME_MIN, snapValue(height))" in MAPPER88,
      "a resize never snaps below the 40-unit floor")

# 88f. contentBounds (Fit / PNG export) encloses frames too.
_CONTENT_BOUNDS88 = js_function(MAPPER88, "contentBounds")
check("for (const frame of view.frames) {" in _CONTENT_BOUNDS88
      and "liveFrameRect(frame)" in _CONTENT_BOUNDS88,
      "contentBounds folds every frame's live rect into the same min/max "
      "it already computes for nodes, so Fit and the PNG export enclose "
      "a frame that sticks out past every node on the map")
# Scoped to draw() (not contentBounds, which shares this exact substring in
# its own null-bounds guard): the empty-canvas branch must check frames too
# (5.31.1 fix), or a frames-only, no-devices map draws as empty. It must
# also fall through while the Frame or Note tool is armed (5.32.0 fix,
# extended for notes), or a brand-new empty map can never draw its first
# frame or note.
_DRAW88F = js_function(MAPPER88, "draw")
check("if (!view.nodes.length && !view.frames.length) {" not in _DRAW88F
      and "if (!view.nodes.length && !view.frames.length && !view.notes.length "
          "&& !view.framing && !view.noting) {" in _DRAW88F,
      "an all-frames/all-notes, no-devices map still has content to fit, "
      "rather than reading as empty, and an armed Frame or Note tool keeps "
      "the real canvas up on a wholly empty map")
_INIT88 = js_function(MAPPER88, "init")
check("requestDraw();" in _INIT88[_INIT88.index("App.el('mp-add-frame').onclick"):
                                   _INIT88.index("App.el('mp-refresh').onclick")],
      "arming or disarming the Frame tool redraws, so the placeholder and "
      "the real canvas swap in step with it")
check("requestDraw();" in js_function(MAPPER88, "disarmFraming"),
      "Escape and a click-with-no-drag disarm through disarmFraming(), "
      "which redraws the same way the toolbar button's own disarm does")

# 88g. A frame gets the same Tab reach a node already has (5.31.0
#      follow-up): tabindex/role/aria-label set the same way a node's own
#      <g> sets them, Enter/Space selects through selectFrame (no drag),
#      Delete/Backspace removes. Nodes have no keyboard delete of their
#      own, so none was added here either — only what nodes already do.
_DRAW_FRAME88G = js_function(MAPPER88, "drawFrame")
check("g.tabIndex = 0;" in _DRAW_FRAME88G and "g.setAttribute('role', 'button');" in _DRAW_FRAME88G,
      "a frame's <g> is a Tab stop with role=button, the same two lines a "
      "node's own <g> carries")
check("g.setAttribute('aria-label', frame.label ? `Frame ${frame.label}` : 'Frame');"
      in _DRAW_FRAME88G,
      "the aria-label is set via setAttribute (never innerHTML), reading "
      "'Frame <label>' or bare 'Frame' when nothing was typed")
_FRAME_KEYDOWN88G = _DRAW_FRAME88G[_DRAW_FRAME88G.index("g.addEventListener('keydown'"):]
check("selectFrame(frame);" in _FRAME_KEYDOWN88G,
      "Enter/Space on a focused frame selects it through selectFrame — the "
      "same select-only path onFramePointerDown's own press uses, no drag "
      "started from a keydown")
check("removeFrame(frame.id);" in _FRAME_KEYDOWN88G,
      "Delete/Backspace on a focused frame removes it through removeFrame, "
      "the same confirm idiom the pane's own Remove button and the "
      "canvas-level shortcut (88d) already use")
check("ArrowLeft" not in _DRAW_FRAME88G and "ArrowRight" not in _DRAW_FRAME88G
      and "ArrowUp" not in _DRAW_FRAME88G and "ArrowDown" not in _DRAW_FRAME88G,
      "no arrow-key nudging: a node's own keydown handler does not nudge "
      "either, so a frame does not gain a capability nodes lack")

# ---------------------------------------------------------------------------
# 88h. MAPPER: Notes — a thought-bubble annotation, the frame idiom (88a-g
#      above) applied to operator commentary, with an optional node_id
#      anchor set once at creation.
check('("POST", r"^/api/mapper/maps/(\\d+)/notes$", api.post_mapper_map_notes, ("mapper", W)),'
      in SERVER_PY
      and '("PUT", r"^/api/mapper/maps/(\\d+)/notes/(\\d+)$", api.put_mapper_map_note, '
          '("mapper", W)),' in SERVER_PY
      and '("DELETE", r"^/api/mapper/maps/(\\d+)/notes/(\\d+)$",' in SERVER_PY,
      "the three note routes exist, gated on mapper write like a frame's own")
check('id="mp-add-note" data-requires-write="mapper"' in INDEX_HTML,
      "the Note button exists and is gated on mapper write")
check(INDEX_HTML.index('id="mp-add-frame"') < INDEX_HTML.index('id="mp-add-note"'),
      "Note sits right after Frame in the action bar")
check("['mp-add-note', !canWrite || !hasMap]," in MAPPER88,
      "Note is disabled with no map selected or no write access, the same "
      "gate Frame uses")
check("function drawNote(layer, note)" in MAPPER88
      and "function updateNoteElement(g, note)" in MAPPER88
      and "function noteAnchorNode(note)" in MAPPER88
      and "function noteTail(note, r)" in MAPPER88,
      "the note drawing functions exist, mirroring drawFrame/"
      "updateFrameElement/liveFrameRect")
_DRAW_NOTE88H = js_function(MAPPER88, "drawNote")
check("g.append(fill, stroke, text, tail1, tail2, handle);" in _DRAW_NOTE88H,
      "a note's children append in a fixed order -- fill, stroke, text, the "
      "two tail circles, resize handle -- the same 'one place decides the "
      "order' shape drawFrame's own comment documents")
check("g.tabIndex = 0;" in _DRAW_NOTE88H and "g.setAttribute('role', 'button');" in _DRAW_NOTE88H,
      "a note's <g> is a Tab stop with role=button, the same reach a frame's own <g> has")
_NOTE_KEYDOWN88H = _DRAW_NOTE88H[_DRAW_NOTE88H.index("g.addEventListener('keydown'"):]
check("selectNote(note);" in _NOTE_KEYDOWN88H and "removeNote(note.id);" in _NOTE_KEYDOWN88H,
      "Enter/Space selects a focused note, Delete/Backspace removes it -- "
      "the same keyboard reach a frame has")
check("function wrapNoteLines(text, innerWidth, maxLines, font)" in MAPPER88,
      "note text wraps to the bubble's own width, capped to however many "
      "lines its height fits")
check("for (const note of view.notesByNode.get(id) || []) {" in
      js_function(MAPPER88, "redrawDragged"),
      "redrawDragged also repositions any note anchored to a dragged node, "
      "so its tail follows the node it points at")
check(".mp-note-c0 { --mp-note-color: var(--canvas-vlan-1); }" in APP_CSS
      and ".mp-note-c5 { --mp-note-color: var(--canvas-vlan-6); }" in APP_CSS,
      "a note shares a frame's six-swatch --canvas-vlan-1..6 palette")
check("function noteDetailHtml(note)" in MAPPER88 and "function noteSwatchesHtml(note, canWrite)"
      in MAPPER88,
      "notes get their own detail-pane editor beside a frame's (text + colour), "
      "reusing the frame's six-swatch idiom")

# 88i. The toolbar checkbox brackets (Snap/Drag pans/FiberView): each caption
#      now reads as belonging to the box inside its own bracket rather than
#      to whichever box follows it (the caption used to sit before its box).
check(INDEX_HTML.count('<span class="mp-bracket"><label') == 3,
      "Snap, Drag pans and FiberView are each wrapped in their own bracket span")
check(".mp-bracket {" in APP_CSS, "app.css styles the bracket (hairline border, tight padding)")

# 88j. Parallel links space further apart at normal zoom (5.3x): fanOffsets'
#      own spacing floor and node-pair margin both went up.
check("const spacing = Math.max(30, widest + 16);" in MAPPER,
      "parallel cables between the same two nodes space out enough to read "
      "as two lines, not one blurred one, at normal zoom")

# 88k. Export PNG targets a higher raster (4x), backed off only by a
#      conservative canvas-size guard, never below the old dpr-capped floor.
_EXPORT88K = js_function(MAPPER, "exportPng")
check("Math.min(window.devicePixelRatio || 1, 2)" in _EXPORT88K,
      "the old dpr-capped scale is still computed, as the export's floor")
check("Math.max(dprScale, Math.min(4, guardScale))" in _EXPORT88K,
      "the export targets 4x, backed off toward the canvas guard, never "
      "below the old dpr-capped floor")
check("MAX_CANVAS_SIDE = 16384" in _EXPORT88K and "MAX_CANVAS_AREA = 268000000" in _EXPORT88K,
      "the canvas guard matches the spec: no side over 16384px, area under ~268 Mpx")

# 88l. A frame's label reads slightly larger (fs-2xs -> fs-xs), baseline
#      nudged so it still sits inside the frame.
check("font-size: var(--fs-xs);" in css_rule(APP_CSS, ".mp-frame-label"),
      "the frame label's font-size moved up a step")
check("label.setAttribute('y', r.y + TEXT_SIZES[sizeIdx].dy);" in MAPPER,
      "updateFrameElement takes the label baseline from the frame's own size")
check("{ label: 'M', dy: 17, fs: '--fs-xs' }" in MAPPER,
      "Medium still sits at the baseline the fixed one used to, so a frame "
      "drawn before there was a setting is unmoved")

# ---------------------------------------------------------------------------
# 89. The device dialog's STACK POWER section (Cisco StackPower/StackWise
#     cabling), placed after TEMPERATURE ALERTS and gated to Cisco devices
#     only -- stored data from /stack-power, never a live SNMP walk.
check('<p class="section" id="ndd-stack-power-head" hidden>STACK POWER</p>' in NODES
      and 'id="ndd-stack-power" hidden' in NODES
      and NODES.index('id="ndd-stack-power-head"') > NODES.index('id="ndd-temp-alerts"')
      and NODES.index('id="ndd-stack-power-head"') < NODES.index('DOM / SFP SENSORS'),
      "STACK POWER is a hidden-by-default section placed right after "
      "TEMPERATURE ALERTS and before DOM / SFP SENSORS")
check("device.vendor === 'cisco'" in NODES,
      "STACK POWER is revealed only for a device whose detected vendor "
      "(sysObjectID arc 9) is Cisco")
check("async function renderStackPower(" in NODES
      and "/api/nodes/devices/${deviceId}/stack-power`" in NODES,
      "the STACK POWER section reads /api/nodes/devices/<id>/stack-power")
check("s.kind === 'stack_power' ? ' <span class=\"hint\">(stack power)</span>'" in NODES,
      "the per-sensor table hints a stack_power row the same way a psu row "
      "is hinted '(power supply)'")
check("No Stack Power ports reported by this switch. Stacked Catalyst " in NODES
      and "3750-X/3850/9300 switches report them after the next poll." in NODES,
      "a Cisco device with no stack power data yet shows the not-present hint")
check("Could not read stack power: " in NODES,
      "a failed /stack-power fetch shows 'Could not read stack power: <message>'")
check("cable down \\u2014 Stack Power cable down rule" in NODES,
      "a state-2 stack power port names the rule that judges it: "
      "'cable down — Stack Power cable down rule'")
check('class="err">cable down' in NODES,
      "a cable-down port's Status cell carries the same .err 'bad' class "
      "used elsewhere in this dialog for a failed read")

# ---------------------------------------------------------------------------
# 90. Sensor Snapshot: the vendor section's write-gated bar carries a
#     dedicated button beside Re-identify, disabling itself before its own
#     POST like every sibling PUT/POST button in this dialog already does
#     (see contract 24), and the per-sensor table tags a fan row the same
#     way a psu/stack_power row is tagged.
_vendor_section = js_function(NODES, "renderVendorSection")
check('id="ndd-sensor-snapshot"' in NODES,
      "the vendor section's write-gated bar has a #ndd-sensor-snapshot button")
check("snapshotBtn.disabled = true" in _vendor_section
      and "/sensor-snapshot`, {})" in _vendor_section,
      "#ndd-sensor-snapshot disables itself before its POST")
check("s.kind === 'fan' ? ' <span class=\"hint\">(fan)</span>'" in NODES,
      "the per-sensor table hints a fan row the same way a psu/stack_power "
      "row is hinted")

# ---------------------------------------------------------------------------
# 91. --reveal (the revealDevice() row highlight, mapper.js Find/#mp-find):
#     one declaration per themed :root block, and app.css's rule reads it.
TOKENS91 = read("tokens.css")
_reveal_blocks = re.findall(r':root\[data-theme="[a-z]+"\] \{.*?\n\}', TOKENS91, re.S)
_reveal_count = sum(block.count("--reveal:") for block in _reveal_blocks)
check(len(_reveal_blocks) > 0 and len(_reveal_blocks) == _reveal_count,
      "--reveal is defined once in every :root[data-theme=] block of tokens.css "
      "(%d blocks, %d --reveal declarations)" % (len(_reveal_blocks), _reveal_count))
check("table.grid tr.revealed td" in read("app.css"),
      "app.css styles table.grid tr.revealed td off --reveal")

# ---------------------------------------------------------------------------
# 92. FiberView (mp-fiberview): --fiber defined once per themed :root block,
#     app.css keys the glow/pulse off #mp-canvas[data-fiberview] .mp-link.fiber.
_fiber_blocks = re.findall(r':root\[data-theme="[a-z]+"\] \{.*?\n\}', TOKENS91, re.S)
_fiber_count = sum(block.count("--fiber:") for block in _fiber_blocks)
check(len(_fiber_blocks) > 0 and len(_fiber_blocks) == _fiber_count,
      "--fiber is defined once in every :root[data-theme=] block of tokens.css "
      "(%d blocks, %d --fiber declarations)" % (len(_fiber_blocks), _fiber_count))
_fiber_sm_count = sum(block.count("--fiber-sm:") for block in _fiber_blocks)
check(len(_fiber_blocks) > 0 and len(_fiber_blocks) == _fiber_sm_count,
      "--fiber-sm (single-mode FiberView) is defined once in every "
      ":root[data-theme=] block of tokens.css, beside --fiber "
      "(%d blocks, %d --fiber-sm declarations)" % (len(_fiber_blocks), _fiber_sm_count))
APP_CSS92 = read("app.css")
check(".mp-link.fiber" in APP_CSS92 and "@keyframes mp-fiber-pulse" in APP_CSS92
      and "prefers-reduced-motion" in APP_CSS92,
      "app.css glows/pulses a fiber link, opt-in on no-preference like the "
      "other MAPPER/alert-row animations")
check("stroke-width: var(--mp-fiber-w, 5px);" in APP_CSS92,
      "a fiber link's bold stroke width comes from JS's own --mp-fiber-w, not a CSS calc()")
check(".mp-link.fiber.selected" in APP_CSS92,
      "a selected fiber link keeps brightness(1.35) alongside its glow")
check(".mp-link.fiber.fiber-mismatch" in APP_CSS92 and ".mp-link.fiber.fiber-sm" in APP_CSS92,
      "FiberView colours single-mode links a bright yellow and an SM/MM mismatch dotted red")
check(".mp-link.blocking { stroke-dasharray: 2 6; }" in APP_CSS92,
      "an STP-blocked link draws dotted in both normal view and FiberView")

# ---------------------------------------------------------------------------
# 93. Interface dialog RUNNING CONFIGURATION tile: an unmatched search names
#     what it searched and how large the backup's own haystack was (5.35.0).
NODES93 = read("nodes.js")
check("'This port has no stored interface row.'" in NODES93,
      "no candidate names at all (no stored ifName/ifDescr) gets its own hint")
check("interface stanzas in this backup." in NODES93,
      "a backup with headers but no matching stanza names the search and "
      "the haystack size")
check("r.searched.map(escape).join(' / ')" in NODES93,
      "every searched candidate name goes through escape() before it's "
      "rendered into the hint")

# ---------------------------------------------------------------------------
# 94. Per-VLAN STP detail (5.37.0): a Cisco port blocking in only some of
#     its VLANs names the count on Nodes and the VLAN list on the Mapper.
NODES94 = read("nodes.js")
check("blocking · " in NODES94,
      "the Nodes STP cell names a partially-blocking port's n/count of VLANs")
check("title:" in NODES94 and "Blocking in VLANs" in NODES94,
      "the span title lists which VLANs the port is blocking in")
check("r.stp_state === 'blocking' &&" in NODES94,
      "partial-VLAN STP text only renders when stp_state is actually blocking")
MAPPER94 = read("mapper.js")
check("(VLANs " in MAPPER94,
      "the Mapper's STP tooltip/aria/detail text appends the blocking end's VLAN list")

# ---------------------------------------------------------------------------
# 95. WIRELESS's own WEB tunnel (FortiAP), mirroring Nodes' WEB button.
INDEX95 = read("index.html")
_WL_WEB_BUTTON = re.search(r'<button id="wl-web-ap"([^>]*)>', INDEX95)
check(_WL_WEB_BUTTON is not None, "index.html has the wl-web-ap button")
check(_WL_WEB_BUTTON is not None
      and "data-requires-write" not in _WL_WEB_BUTTON.group(1),
      "wl-web-ap carries no data-requires-write -- like wl-oos and "
      "wl-remove-ap, drawApActions owns its .hidden per selection, not the "
      "disable-only write gate")
check(r'r"^/api/wireless/aps/(\d+)/relay$", api.post_wireless_ap_relay, ("web", W)'
      in SERVER_PY,
      "server.py routes POST .../aps/<id>/relay to post_wireless_ap_relay, "
      "gated on web write -- opening a port on this host is that module's "
      "business, not wireless's")
WIRELESS95 = read("wireless.js")
check("App.el('wl-web-ap').hidden = !(ap && ap.ip && App.canWrite('web'))"
      in WIRELESS95,
      "drawApActions shows wl-web-ap only for a selected AP with a "
      "reported ip and an operator holding web write")
APP95 = read("app.js")
check("'wireless.ap.web': {" in APP95,
      "app.js registers the wireless.ap.web help topic")

# 96. Mapper operator round (5.39.0): the legend note is gone, the STP dots
#     ride above the fiber glow, the strand bundle has one wide click target,
#     the detail pane's VLAN list carries the blocking in colour, parallel
#     cables stagger their port labels, and the toolbar Remove serves a
#     selected frame or note.
MAPPER96 = read("mapper.js")
CSS96 = read("app.css")

# 96a. The VLAN/dash/dot note is removed; the FiberView key and the
#      no-adjacency message stay.
_LEGEND96 = js_function(MAPPER96, "drawLegend")
check("draw as one thick line" not in _LEGEND96
      and "A dashed line means" not in _LEGEND96
      and "spanning-tree-blocked port" not in _LEGEND96,
      "drawLegend no longer explains the VLAN line styles")
check("FiberView: dark orange = multimode" in _LEGEND96
      and "No CDP/LLDP adjacency was found" in _LEGEND96,
      "the FiberView key and the empty-map message survive that removal")

# 96b. The blocked dots are their own unglowed path, not a dasharray on the
#      glowing one -- the glow's blur was smearing them into a solid line.
check("const overlaidBlocking = link.blocking && link.fiber === true && view.fiberView;"
      in MAPPER96,
      "drawLink knows when the glow is carrying an overlay instead of dots")
check("class: 'mp-link blocking mp-blocking-over', 'stroke-width': plan.width," in MAPPER96,
      "the overlay is a .blocking path with no .fiber, so no glow filter")
check("if (link.blocking && !overlaidBlocking) path.classList.add('blocking');" in MAPPER96,
      "the plain/collapsed link stops dashing its own glow where the overlay draws")
check(".mp-link.mp-blocking-over { stroke: var(--fail); stroke-linecap: butt; }" in CSS96,
      "red, and butt-capped -- .mp-link's round caps lengthen each 2px dash by "
      "the stroke width, which is what closed the gaps in the first place")
_DRAW_LINK96 = js_function(MAPPER96, "drawLink")
check("mp-blocking-over" not in
      _DRAW_LINK96[_DRAW_LINK96.index("if (plan.mode === 'strands'"):
                    _DRAW_LINK96.index("const neutral =")],
      "the strands ribbon gets NO overlay: its strands are thin and already "
      "dotted, and a bundle-width dashed stroke would paint a solid bar")

# 96c. One wide invisible hit target under the strands, not a fatter strand:
#      each strand must still answer for its own VLAN on hover.
check("const LINK_HIT_PAD = 14;" in MAPPER96,
      "the click target's margin past the ribbon is named once")
check("'pointer-events': 'stroke', class: 'mp-link-hit'," in MAPPER96,
      "the target is stroke-hit only, like a frame's outline")
check("hit.setAttribute('aria-hidden', 'true');" in MAPPER96,
      "it adds no second Tab stop or screen-reader name for the same link")
check(_DRAW_LINK96.index("class: 'mp-link-hit'") < _DRAW_LINK96.index("plan.strands.forEach"),
      "it is appended BEFORE the strands, so a strand still wins its own tooltip")
check("event.target.closest('.mp-link, .mp-link-hit')" in MAPPER96,
      "the canvas press handler exempts the hit path too -- without it a press "
      "there starts a rubber band and clears the selection instead of selecting")

# 96d. The one VLAN list carries the blocking as colour; the footer keeps the
#      switch and port and drops the ids it used to repeat.
check("function stpBlockedVlans(link) {" in MAPPER96,
      "the blocked map is parsed from a_stp_vlans/b_stp_vlans")
check("if (blocked === null) lines.push(row);" in MAPPER96,
      "a link with no blocking leaves its list uncoloured")
check('<span class="mp-vlan-blocked">${row}  (${where})</span>' in MAPPER96,
      "a blocked VLAN names the blocking switch beside the red, one line per VLAN")
check("stpBlockingText(link, escape(a.name), escape(b.name), escape, false)" in MAPPER96,
      "the detail pane's STP footer drops the VLAN ids the list now shows")
check("const suffix = (vlans) => (withVlans ? esc(stpVlanSuffix(vlans)) : '');" in MAPPER96,
      "the tooltip and aria-label keep naming them -- they have no list to colour")
check(".mp-vlan-pass { color: var(--ok); }" in CSS96
      and ".mp-vlan-blocked { color: var(--fail); }" in CSS96,
      "green passing, red blocked")

# 96e. Parallel cables step their port labels apart: the fan separates the
#      lines by less than a port name is wide.
check("const PORT_LABEL_STEP = 16;" in MAPPER96,
      "the per-cable label step is named once")
check("return { fan, index };" in MAPPER96,
      "fanOffsets reports each link's place in its fan, not just the offset")
check("const inset = clear + step;" in MAPPER96
      and "const aside = Math.max(8, bundleHalf + 5);" in MAPPER96,
      "drawPortLabels offsets by that place, and sits clear of the strand bundle")
check("Math.max(len / 2 - clear, 0));" in MAPPER96,
      "clamped at the midpoint, so a short link's two ends cannot swap sides")

# 96f. The toolbar Remove button serves whatever is selected. A frame never
#      joins view.selection, which is why it sat disabled.
check("&& !view.selectedFrameId && !view.selectedNoteId)]," in MAPPER96,
      "mp-remove-node enables for a selected frame or note")
check("if (view.selectedFrameId) { removeFrame(view.selectedFrameId); return; }" in MAPPER96,
      "and removeSelected dispatches to the frame's own confirm and endpoint")

# 96g. Frame label text size: three presets beside the colour swatches,
#      Medium unchanged from before the setting existed.
check("'data-frame-textsize'" in MAPPER96 and "class=\"mp-textsize" in MAPPER96,
      "the size row renders beside the swatches")
check("`Text size   ${textSizesHtml(frame, 'data-frame-textsize', canWrite)}`," in MAPPER96,
      "it sits in the frame pane next to Label and Colour")
check("{ text_size: textSize }" in MAPPER96,
      "picking one PUTs text_size on the frame")
check(".mp-frame-label.mp-frame-t0 { font-size: var(--fs-2xs); }" in CSS96
      and ".mp-frame-label.mp-frame-t2 { font-size: var(--fs-xl); }" in CSS96,
      "Small and Large are their own rules; Medium is the base font-size")

# 96h. The interface dialog's MAC table stops after five, with the rest
#      behind a count.
NODES96 = read("nodes.js")
check("MAC_TABLE_CAP = 5" in NODES96,
      "the MAC table caps at five rows")
check('nd-mac-show-all">+${hidden} more</button>' in NODES96,
      "the rest sit behind a control naming how many are hidden")

# ---------------------------------------------------------------------------
# 97. 5.40.0: notes take the frame's three text sizes; the FiberView toggle
#     redraws; port labels measure the node box instead of assuming a corner.
MAPPER97 = read("mapper.js")
CSS97 = read("app.css")

# 97a. One size table for frames and notes, each entry naming the font token
#      the note is wrapped against, so measured lines match drawn ones.
check("const TEXT_SIZES = [" in MAPPER97 and "{ label: 'L', dy: 22, fs: '--fs-xl' }" in MAPPER97,
      "the shared table carries a font token per size")
check("function textSizesHtml(item, attr, canWrite)" in MAPPER97,
      "one row builder serves both panes, told which data attribute to write")
check("`Text size   ${textSizesHtml(note, 'data-note-textsize', canWrite)}`," in MAPPER97,
      "the note pane gets the row after Colour")
check("await App.put(`/api/mapper/maps/${view.mapId}/notes/${note.id}`, { text_size: textSize });"
      in MAPPER97,
      "picking one PUTs text_size on the note")
_NOTE97 = js_function(MAPPER97, "updateNoteElement")
check("const font = noteFont(sizeIdx);" in _NOTE97,
      "the note wraps with its own size's font, not the node-label font")
check("const padTop = Math.max(NOTE_PAD_TOP, metrics.ascent + 3);" in _NOTE97,
      "the first baseline drops with the font so Large is not clipped at the top")
check("text.classList.toggle(`mp-note-t${i}`, i === sizeIdx);" in _NOTE97,
      "the size lands as a class the CSS keys off")
check("noteFontCache.clear();" in MAPPER97,
      "the per-size font cache is dropped with labelFontCache every draw")
check(".mp-note-text.mp-note-t0 { font-size: var(--fs-2xs); }" in CSS97
      and ".mp-note-text.mp-note-t2 { font-size: var(--fs-xl); }" in CSS97,
      "Small and Large are their own rules; Medium is .mp-note-text's base font-size")
check("font-size: var(--fs-xs);" in css_rule(CSS97, ".mp-note-text"),
      "...and that base is the frame's Medium")

# 97b. FiberView: drawLink decides at draw time which element carries a
#      blocked link's dots, so flipping the view must draw again.
_INIT97 = js_function(MAPPER97, "init")
_FIBER97 = _INIT97[_INIT97.index("App.el('mp-fiberview').onchange"):
                    _INIT97.index("App.el('mp-snap').onchange")]
check("applyFiberView();" in _FIBER97 and "requestDraw();" in _FIBER97
      and _FIBER97.index("applyFiberView();") < _FIBER97.index("requestDraw();"),
      "the FiberView toggle redraws after flipping the attribute")

# 97c. Port labels: the inset is measured from the node box along the link,
#      so an axis-aligned link keeps its labels near the box and a stacked
#      pair's stagger has room; steep links read away from their line.
check("const PORT_LABEL_INSET = 18;" in MAPPER97,
      "the inset is a margin, not a corner allowance")
check("function boxExit(ux, uy, ox, oy)" in MAPPER97
      and "const clear = Math.max(boxExit(ux, uy, ex, ey), boxExit(-ux, -uy, ex, ey)) + PORT_LABEL_INSET;"
      in MAPPER97,
      "drawPortLabels adds the box's own reach along the link, measured from where "
      "the label sits at whichever end reaches further")
check("const steep = Math.abs(uy) > Math.abs(ux);" in MAPPER97
      and "const anchor = fanSide > 0 ? 'start' : 'end';" in MAPPER97,
      "a steep link anchors both labels away from the fan's outward side")
check("return inset + PORT_LABEL_STEP;" in MAPPER97
      and "step = Math.min(step, Math.max(edgeLen - 2 * reserve, 0) / ((n - 1) * edgeLen));" in MAPPER97,
      "and hands the strands branch the span its labels took, so VLAN numbers stay off them")
check("const fanSide = Math.sign(fanOffset * nx) || 1;" in MAPPER97
      and "const ax = from.x + ux * inset + ox, ay = from.y + uy * inset + oy;" in MAPPER97,
      "the outward side comes from the cable's fan offset in screen x, and the "
      "label is offset from the line at its own height, not from the box edge")

# ---------------------------------------------------------------------------
# 98. 5.41.0: the link pane's blocked rows name the switch whose port blocks
#     that VLAN: STP blocks one end of a link, and PVST can block different
#     VLANs on different ends, so one word for every row hid which end.
MAPPER98 = read("mapper.js")

# 98a. Per-end map, gated on the end's own state; the row names the end.
check("const out = new Map();" in MAPPER98
      and "if (!raw || link[`${end}_stp`] !== 'blocking') continue;" in MAPPER98,
      "stpBlockedVlans keeps the end per VLAN and reads an end only while its own "
      "port blocks, the footer's gate")
check("out.set(vlan, out.has(vlan) && out.get(vlan) !== end ? 'both' : end);" in MAPPER98,
      "a VLAN both ends report maps to 'both'")
check("const where = end === 'both' ? `${escape(a.name)} and ${escape(b.name)}`" in MAPPER98
      and ": escape(end === 'a' ? a.name : b.name);" in MAPPER98,
      "the row names the blocking switch, or both, escaped")

# ---------------------------------------------------------------------------
# 99. Placeholder blocks (5.42.0): an operator-created logical box, not a
#     device, never polled, joinable to real devices with Connect.
MAPPER99 = read("mapper.js")
INDEX99 = read("index.html")
APP_CSS99 = read("app.css")
check('id="mp-add-placeholder" data-requires-write="mapper"' in INDEX99,
      "the Placeholder button exists and is gated on mapper write")
check("['mp-add-placeholder', !canWrite || !hasMap]," in MAPPER99,
      "Placeholder is disabled with no map selected or no write access, in "
      "the same toolbar-state table as every other mapper write control")
check("if (node.placeholder) {" in MAPPER99,
      "resolveNode branches on node.placeholder before the unmanaged check")
check("gone: false, placeholder: true, role: node.role || ''," in MAPPER99,
      "a placeholder resolves with placeholder: true and its own role override")
check("if (info.unmanaged || info.gone || info.placeholder) return;" in MAPPER99,
      "a placeholder's dblclick has nothing in Nodes to open, same as an "
      "unmanaged peer or a device removed from Nodes")
check(".mp-node.placeholder .mp-node-box { stroke-dasharray: 8 4; stroke: var(--canvas-muted); }"
      in APP_CSS99,
      "a placeholder draws with its own dash, distinct from .unmanaged and .gone")
check("'Placeholder — not a device. Drawn for the diagram only; select it with a ' +\n"
      "        'device and press Connect to join them.'" in MAPPER99,
      "the detail pane explains what a placeholder is and how to join it")
check("{ placeholder: true, label, x: pos.x, y: pos.y });" in MAPPER99,
      "openAddPlaceholder POSTs placeholder: true with the trimmed label")

# ---------------------------------------------------------------------------
# 100. Review fixes (5.45.0): nodes.js's three lazy dialogs -- a help key
#      nodes.js references must be registered in nodes.js itself, not left
#      for a lazy extra to supply, and each click site actually loads its
#      extra (and inits it) before calling in.
NODES100 = read("nodes.js")
_used_help_keys100 = set(re.findall(r"(?:helpLinkNamed|App\.helpLink)\('(nodes\.[\w.]+)'", NODES100))
_registered_help_keys100 = set(re.findall(r"'(nodes\.[\w.]+)':\s*\{", NODES100))
check(bool(_used_help_keys100) and _used_help_keys100 <= _registered_help_keys100,
      "every nodes.* help key nodes.js references is registered in nodes.js "
      "itself (missing: %s)"
      % (", ".join(sorted(_used_help_keys100 - _registered_help_keys100)) or "none"))

for _btn, _stem in (("nd-browse-oids", "nodes_oid_browser"), ("nd-settings", "nodes_settings"),
                   ("nd-add-profile", "nodes_credentials"), ("nd-edit-profile", "nodes_credentials"),
                   ("nd-remove-profile", "nodes_credentials"),
                   ("nd-default-profile", "nodes_credentials")):
    check(("App.el('%s').onclick = () => App.loadExtra('%s')" % (_btn, _stem)) in NODES100,
          "%s's dialog is fetched through App.loadExtra('%s')" % (_btn, _stem))

_ENTRY_CALLS100 = {
    "nd-browse-oids": "App.extras.nodesOidBrowser.open()",
    "nd-add-profile": "App.extras.nodesCredentials.addProfile()",
    "nd-edit-profile": "App.extras.nodesCredentials.editProfile()",
    "nd-remove-profile": "App.extras.nodesCredentials.removeProfile()",
    "nd-default-profile": "App.extras.nodesCredentials.setDefaultProfile()",
}
for _btn, _entry in _ENTRY_CALLS100.items():
    _click100 = _slice59(NODES100, "App.el('%s').onclick" % _btn, "'fail'));")
    check(_before59(_click100, ".init(", _entry),
          "%s's click handler inits its extra before calling %s" % (_btn, _entry))

for _name in ("download", "bulkToggle", "bulkClear", "extraCounterParts", "niceCeiling",
             "localInputValue", "confidenceBadgeHtml", "CONFIDENCE_COLOR"):
    check(_name in _slice59(APP, "const api = {", "\n  };"),
          "%s is exposed on App (the shared api object)" % _name)

# ---------------------------------------------------------------------------
# 101. Phase 4 performance (5.46.0): do-less-work-for-the-same-result changes
#      only -- these pin that the guard exists, not the DOM result, which no
#      static check here can see.
_WATCH101 = js_function(APP, "watchPlainTables")
check("node.tagName === 'TABLE' ? [node] : node.getElementsByTagName('table')" in _WATCH101,
      "the plain-table observer finds nested tables by tag name, not a CSS "
      "selector, for every added node")

for _fn in ("fillGroupFilter", "fillDevGroupFilter", "fillReportDevGroupSelects",
           "fillDiscGroups"):
    check("App.setHtml(select," in js_function(NODES100, _fn),
          "%s skips the write when its option list is unchanged" % _fn)
# A baked-in selectedId changed the string with the selection, defeating
# any skip; groupOptionsHtml() now takes none, and .value is restored below.
check("App.setHtml(select, groupOptionsHtml());" in js_function(NODES100, "fillDiscGroups"),
      "...and no longer bakes a selectedId into that string")

check("App.setHtml(App.el('nd-d-summary')" in NODES100,
      "the device detail header's summary line skips an unchanged rewrite")
_CAPS101 = js_function(NODES100, "drawCapabilitiesTab")
check("App.setHtml(stpEl," in _CAPS101 and "App.setHtml(poeEl," in _CAPS101,
      "the capabilities tab's STP/POE lines skip an unchanged rewrite")

DASHBOARD101 = read("dashboard.js")
_DRAW101 = js_function(DASHBOARD101, "draw")
_CHARTS101 = js_function(DASHBOARD101, "drawCharts")
check("let lastDrawHtml = null;" in DASHBOARD101, "dashboard.js keeps the last HTML it wrote")
check("const lastChartFetchedAt = {};" in DASHBOARD101,
      "...and the fetchedAt it last drew each tile's chart from")
check("function draw({ ifChanged } = {}) {" in DASHBOARD101,
      "draw() only skips a rewrite when its caller opts in")
check("if (ifChanged && html === lastDrawHtml) { drawCharts(false); return; }" in _DRAW101,
      "...and only when the produced HTML is unchanged too")
check(DASHBOARD101.count("draw({ ifChanged: true });") == 3,
      "only refresh()'s three draw() calls (success, supersede, error) opt "
      "into skipping -- every other caller (a new tile object, a cancelled "
      "dropdown pick) always repaints")
check("drawCharts(true);" in _DRAW101,
      "a real rewrite still forces every chart to redraw, into its fresh, "
      "empty placeholder, exactly as before")
check("if (!force && entry && lastChartFetchedAt[tileId] === entry.fetchedAt) continue;"
      in _CHARTS101,
      "an unforced drawCharts skips a tile whose own chart data has not "
      "moved since it was last drawn -- not the whole payload's volatile "
      "counters, just this tile's own fetchedAt")
check("dashResizeTimer = setTimeout(() => drawCharts(true), 150);" in DASHBOARD101,
      "a resize still forces every chart (fetchedAt does not move on a "
      "resize, so an unforced call would skip them all)")
_LOADING101 = _slice59(_DRAW101, "if (!d) {", "\n    }")
check("lastDrawHtml = null;" in _LOADING101,
      "leaving the still-loading branch clears the last-written HTML, so a "
      "later real draw is never compared against a stale 'Loading…' string")
check("JSON.stringify(view.dashboard)" not in DASHBOARD101,
      "refresh() no longer signatures the whole payload to decide whether to draw")

# A real run, not another literal pin: fillGroupFilter (and the real
# App.setHtml/lastHtml) evaluated by node, proving a second identical call
# writes innerHTML once.
_FGF_HARNESS = """
'use strict';
let writes = 0;
const selectEl = {
  value: '', selectedIndex: 0,
  get innerHTML() { return this._html || ''; },
  set innerHTML(v) { this._html = v; writes += 1; },
};
%(lastHtml)s
%(setHtml)s
const App = {
  el: () => selectEl,
  savedControl: () => '',
  setHtml,
};
const escape = (s) => String(s);
const view = { groups: [{ id: 1, name: 'a' }, { id: 2, name: 'b' }] };
function forget() {}
%(fillGroupFilter)s
fillGroupFilter();
fillGroupFilter();
console.log(JSON.stringify({ writes, value: selectEl.value }));
"""

if NODE is None:
    print("SKIP  fillGroupFilter's second-draw-is-free proof (node not on this machine)")
else:
    _script = _FGF_HARNESS % {
        "lastHtml": js_const(APP, "lastHtml"),
        "setHtml": js_function(APP, "setHtml"),
        "fillGroupFilter": js_function(NODES100, "fillGroupFilter"),
    }
    _folder = tempfile.mkdtemp(prefix="fill_group_filter_")
    try:
        _path = os.path.join(_folder, "run.js")
        with open(_path, "w", encoding="utf-8") as _handle:
            _handle.write(_script)
        _out = subprocess.run([NODE, _path], capture_output=True, text=True,
                              encoding="utf-8", timeout=30)
        _result = ({"error": _out.stderr.strip()[:400]} if _out.returncode != 0
                   else json.loads(_out.stdout))
    finally:
        shutil.rmtree(_folder, ignore_errors=True)
    check(_result.get("writes") == 1,
          "fillGroupFilter writes innerHTML once across two calls with an "
          "unchanged group list (got: %s)" % _result)

# setHtml/setText evaluated for real: an entity-bearing string still skips
# its second write, and a foreign textContent write forces the next one.
_SETHTML_HARNESS = """
'use strict';
let writes = 0;
const el = {
  get innerHTML() { return this._html || ''; },
  set innerHTML(v) { this._html = v; writes += 1; },
  get textContent() { return this._text || ''; },
  set textContent(v) { this._text = v; },
};
%(lastHtml)s
%(setHtml)s
%(setText)s
const html = "<span>O&#39;Brien &quot;Router&quot;</span>";
setHtml(el, html);
setHtml(el, html);
const afterTwo = writes;
setText(el, 'something else');
setHtml(el, html);
console.log(JSON.stringify({ afterTwo, afterForeignWrite: writes }));
"""

if NODE is None:
    print("SKIP  setHtml/setText's WeakMap proof (node not on this machine)")
else:
    _script = _SETHTML_HARNESS % {
        "lastHtml": js_const(APP, "lastHtml"),
        "setHtml": js_function(APP, "setHtml"),
        "setText": js_function(APP, "setText"),
    }
    _folder = tempfile.mkdtemp(prefix="set_html_")
    try:
        _path = os.path.join(_folder, "run.js")
        with open(_path, "w", encoding="utf-8") as _handle:
            _handle.write(_script)
        _out = subprocess.run([NODE, _path], capture_output=True, text=True,
                              encoding="utf-8", timeout=30)
        _result = ({"error": _out.stderr.strip()[:400]} if _out.returncode != 0
                   else json.loads(_out.stdout))
    finally:
        shutil.rmtree(_folder, ignore_errors=True)
    check(_result.get("afterTwo") == 1,
          "two identical setHtml calls with an entity-bearing string write "
          "once (got: %s)" % _result)
    check(_result.get("afterForeignWrite") == 2,
          "...but a foreign textContent write in between forces the next "
          "setHtml to write again, not trust a now-stale cache (got: %s)"
          % _result)

# dashboard.js's draw(): an explicit call (no options) always writes, even
# with identical HTML; only refresh()'s ifChanged call may skip.
_DRAW_HARNESS = """
'use strict';
let writes = 0;
const rootEl = {
  className: '',
  get innerHTML() { return this._html || ''; },
  set innerHTML(v) { this._html = v; writes += 1; },
};
const App = { el: () => rootEl, loading: () => 'loading' };
function syncEditButtons() {}
function activeTiles() { return []; }
function renderTile() { return ''; }
function drawCharts() {}
const escape = (s) => String(s);
const document = { activeElement: null };
const view = { editing: false, error: null, dashboard: { x: 1 } };
let lastDrawHtml = null;
%(draw)s
draw();
draw();
const afterTwoExplicit = writes;
draw({ ifChanged: true });
console.log(JSON.stringify({ afterTwoExplicit, afterIfChanged: writes }));
"""

if NODE is None:
    print("SKIP  dashboard draw()'s explicit-always-writes proof (node not on this machine)")
else:
    _script = _DRAW_HARNESS % {"draw": _DRAW101}
    _folder = tempfile.mkdtemp(prefix="dash_draw_")
    try:
        _path = os.path.join(_folder, "run.js")
        with open(_path, "w", encoding="utf-8") as _handle:
            _handle.write(_script)
        _out = subprocess.run([NODE, _path], capture_output=True, text=True,
                              encoding="utf-8", timeout=30)
        _result = ({"error": _out.stderr.strip()[:400]} if _out.returncode != 0
                   else json.loads(_out.stdout))
    finally:
        shutil.rmtree(_folder, ignore_errors=True)
    check(_result.get("afterTwoExplicit") == 2,
          "two explicit draw() calls with identical HTML both write (got: %s)" % _result)
    check(_result.get("afterIfChanged") == 2,
          "...but a draw({ ifChanged: true }) call right after, same HTML, "
          "does not (got: %s)" % _result)

# nodes.js: the re-identify and MIB-install job polls share pollVisibleSeconds
# instead of a hidden-tab-blind for loop, each keeping its original visible
# budget (90s / 120s).
_NODES_POLL = read("nodes.js")
check("async function pollVisibleSeconds(seconds, current, check) {" in _NODES_POLL,
      "nodes.js defines pollVisibleSeconds")
_POLLFN = js_function(_NODES_POLL, "pollVisibleSeconds")
check("if (document.hidden) continue;" in _POLLFN
      and _POLLFN.index("if (document.hidden) continue;") < _POLLFN.index("elapsed++;")
      and _POLLFN.index("elapsed++;") < _POLLFN.index("await check()"),
      "...a hidden tab skips both the elapsed-second count and the check() "
      "call, but still awaits its sleep so a re-shown tab is noticed promptly")
check("await pollVisibleSeconds(90, current, async () => {" in _NODES_POLL,
      "re-identify polls for up to 90 visible seconds")
check("await pollVisibleSeconds(120, current, async () => {" in _NODES_POLL,
      "MIB install polls for up to 120 visible seconds")

# A real run of pollVisibleSeconds: a fake setTimeout advances one simulated
# tick per call, and document.hidden is scripted per tick, so the test
# controls exactly which ticks are "hidden" without a real 1s wait.
_POLL_HARNESS = """
'use strict';
%(pollVisibleSeconds)s

function run(hiddenTicks, seconds, stopAfterChecks) {
  let ticks = 0;
  let checks = 0;
  global.document = { hidden: false };
  global.setTimeout = (fn) => { ticks++; document.hidden = ticks <= hiddenTicks; fn(); };
  const current = () => true;
  return pollVisibleSeconds(seconds, current, async () => {
    checks++;
    if (stopAfterChecks && checks >= stopAfterChecks) return 'stopped';
    return undefined;
  }).then((result) => ({ ticks, checks, result: result === undefined ? null : result }));
}

(async () => {
  const timedOut = await run(3, 3, 0);
  const stoppedEarly = await run(2, 5, 2);
  console.log(JSON.stringify({ timedOut, stoppedEarly }));
})();
"""

if NODE is None:
    print("SKIP  pollVisibleSeconds's hidden-tab proof (node not on this machine)")
else:
    _script = _POLL_HARNESS % {"pollVisibleSeconds": _POLLFN}
    _folder = tempfile.mkdtemp(prefix="poll_visible_")
    try:
        _path = os.path.join(_folder, "run.js")
        with open(_path, "w", encoding="utf-8") as _handle:
            _handle.write(_script)
        _out = subprocess.run([NODE, _path], capture_output=True, text=True,
                              encoding="utf-8", timeout=30)
        _result = ({"error": _out.stderr.strip()[:400]} if _out.returncode != 0
                   else json.loads(_out.stdout))
    finally:
        shutil.rmtree(_folder, ignore_errors=True)
    _timedOut = _result.get("timedOut", {})
    _stoppedEarly = _result.get("stoppedEarly", {})
    check(_timedOut.get("ticks") == 6 and _timedOut.get("checks") == 3
          and _timedOut.get("result") is None,
          "3 hidden ticks issue no check() and do not count toward a 3-second "
          "visible budget -- the poll still needs 3 more (visible) ticks and "
          "then gives up, exactly as if the tab had been visible throughout "
          "(got: %s)" % _timedOut)
    check(_stoppedEarly.get("ticks") == 4 and _stoppedEarly.get("checks") == 2
          and _stoppedEarly.get("result") == "stopped",
          "2 hidden ticks are skipped, then the poll resumes and stops the "
          "moment check() resolves, before its visible budget is spent "
          "(got: %s)" % _stoppedEarly)

# ---------------------------------------------------------------------------
# 102. Release C performance (5.49.0): the Nodes table's own list fetch asks
#      for the table's projection, not the whole 25-column row per device.
NODES102 = read("nodes.js")
_REFRESH102 = js_function(NODES102, "refresh")
check("App.get('/api/nodes/devices', { ...query, fields: 'list' })" in _REFRESH102,
      "nodes.js's device list refresh asks for the 'list' projection")

# ---------------------------------------------------------------------------
# 103. Account modal (5.52.0): the SMS opt-in fieldset carries its ids, the
#      exact consent sentence, and the number interpolation is escaped.
ACCOUNT_MODAL103 = js_function(APP, "accountModal")
for sms_id in ("am-sms-number", "am-sms-consent", "am-sms-start",
               "am-sms-code", "am-sms-confirm", "am-sms-stop"):
    check("id=\"%s\"" % sms_id in ACCOUNT_MODAL103,
          "accountModal renders #%s" % sms_id)
check("Text alerts (SMS)" in ACCOUNT_MODAL103,
      "accountModal's SMS fieldset carries its legend")
check("Reply STOP at any time to opt out, or HELP for help" in ACCOUNT_MODAL103,
      "the SMS terms sentence is intact")
check("/api/account/sms/start" in ACCOUNT_MODAL103,
      "accountModal calls the SMS start route")
check("/api/account/sms/confirm" in ACCOUNT_MODAL103,
      "accountModal calls the SMS confirm route")
check("const number = escapeHtml(" in ACCOUNT_MODAL103,
      "the SMS number is escaped before it is interpolated")
check('href="/sms-terms"' in ACCOUNT_MODAL103 and 'href="/sms-privacy"' in ACCOUNT_MODAL103,
      "accountModal's SMS paragraph links the full terms and privacy pages")
check(ACCOUNT_MODAL103.count('rel="noopener"') >= 2,
      "the SMS terms/privacy links open in a new tab without a window handle back")

# ---------------------------------------------------------------------------
# 104. SMS Terms / SMS Privacy (Twilio 10DLC campaign): the public pages
#      exist, carry the versioned asset links, and the carrier-required
#      no-sharing sentence is present verbatim.
SMS_TERMS104 = static_text("sms-terms.html")
SMS_PRIVACY104 = static_text("sms-privacy.html")
for name, text in (("sms-terms.html", SMS_TERMS104), ("sms-privacy.html", SMS_PRIVACY104)):
    for asset in ("/tokens.css?v=__SW_VERSION__", "/app.css?v=__SW_VERSION__",
                  "/boot.js?v=__SW_VERSION__"):
        check(asset in text, "%s links %s" % (name, asset))
check("No mobile information will be shared with third parties or affiliates "
      "for marketing or promotional purposes." in SMS_PRIVACY104,
      "sms-privacy.html carries the carrier-required no-sharing sentence verbatim")

if failures:
    print("FAILED %d contract(s):" % len(failures))
    for message in failures:
        print("  - %s" % message)
    sys.exit(1)
print("ALL FRONTEND CONTRACTS HOLD")
