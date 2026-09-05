"""ConfigRX search and compliance UI (4.50.0): netpath/configrx_search.py and
netpath/configrx_compliance.py shipped with a full set of routes
(test_configrx_search_routes.py) and no frontend calling any of them —
nothing in configrx.js searched a device's capture or touched a rule set,
and nothing in index.html offered a way to try.

This suite is the frontend counterpart to test_frontend_contracts.py: it
reads the shipped configrx.js and index.html as text and asserts the small
number of things that must be true of them — every one of the twelve routes
is actually called by the shipped JS, every control that writes carries the
`data-requires-write="configrx"` gate the rest of the product uses (disabled,
never hidden, for a read-only account), destructive actions go through
App.confirmDestructive rather than a hand-rolled dialog, and the new SEARCH
and COMPLIANCE subtabs exist and are wired the way Nodes' own subtabs are.

Nothing here starts a server or a browser — see test_configrx_search_routes.py
for the routes' own behaviour and tests/ui/walk.mjs for a real browser
walking the pages this file only checks the markup and script of.
"""
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "netpath", "web", "static")

FAILS = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (f"   {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
        return handle.read()


JS = read("configrx.js")
INDEX = read("index.html")
CONFIGRX_SECTION = INDEX[INDEX.index('<section id="page-configrx"'):
                         INDEX.index("</section>", INDEX.index('<section id="page-configrx"'))]


# ---------------------------------------------------------------------------
# 1. Every one of the twelve routes get_configrx_search and its compliance
#    siblings shipped with (server.py:497-514) is actually called somewhere
#    in the shipped JS — the gap this whole feature exists to close.
ROUTE_CALLS = {
    "GET /api/configrx/search": r"App\.get\(\s*['\"]/api/configrx/search['\"]",
    "GET /api/configrx/rule-sets": r"App\.get\(\s*['\"]/api/configrx/rule-sets['\"]",
    "POST /api/configrx/rule-sets": r"App\.post\(\s*['\"]/api/configrx/rule-sets['\"]",
    "GET /api/configrx/rule-sets/(id)": r"App\.get\(`/api/configrx/rule-sets/\$\{[^}]+\}`",
    "PUT /api/configrx/rule-sets/(id)": r"App\.put\(`/api/configrx/rule-sets/\$\{[^}]+\}`",
    "DELETE /api/configrx/rule-sets/(id)": r"App\.del\(`/api/configrx/rule-sets/\$\{[^}]+\}`,\s*\{\}\)",
    "GET /api/configrx/rule-sets/(id)/rules": r"App\.get\(`/api/configrx/rule-sets/\$\{[^}]+\}/rules`",
    "POST /api/configrx/rule-sets/(id)/rules": r"App\.post\(`/api/configrx/rule-sets/\$\{[^}]+\}/rules`",
    "DELETE /api/configrx/rule-sets/(id)/rules/(rid)":
        r"App\.del\(`/api/configrx/rule-sets/\$\{[^}]+\}/rules/\$\{[^}]+\}`",
    "GET /api/configrx/rule-sets/(id)/results": r"App\.get\(`/api/configrx/rule-sets/\$\{[^}]+\}/results`",
    "POST /api/configrx/rule-sets/(id)/evaluate": r"App\.post\(`/api/configrx/rule-sets/\$\{[^}]+\}/evaluate`",
    "GET /api/configrx/devices/(id)/compliance": r"App\.get\(`/api/configrx/devices/\$\{[^}]+\}/compliance`",
}
for label, pattern in ROUTE_CALLS.items():
    check(f"configrx.js calls {label}", re.search(pattern, JS) is not None)


# ---------------------------------------------------------------------------
# 1b. A 0-match search result must never read as "verified clean" — a
#     device with no stored capture at all is simply unreachable by search,
#     and (found live, 4.50.0) the index can also lag a device that HAS a
#     capture whose config has not changed since it was last indexed. The
#     empty state says so explicitly and gives the fleet's own actual
#     capture coverage alongside it, rather than a bare "no matches".
check("a 0-match result explicitly says it is not proof of a clean estate",
      "does not mean these devices are clean" in JS)
check("the empty-result state reports how many devices actually have a "
      "stored capture to search (searchCoverageNote), not just 'no matches'",
      "function searchCoverageNote()" in JS
      and "await searchCoverageNote()" in JS)
check("the match count also says whether the index or a full scan answered "
      "the query (the server's own `indexed` field), not left unsaid",
      "indexed ? ' (via the search index)'" in JS)
check("drawSearchResults guards against a newer search redrawing over an "
      "older one's still-in-flight coverage fetch (view.searchGen)",
      "view.searchGen !== generation" in JS and "view.searchGen += 1" in JS)


# ---------------------------------------------------------------------------
# 2. Search and rule-set-evaluate are read/write exactly the way server.py
#    gates them — GET search is never sent as anything requiring a write
#    grant, and the CRUD routes above are all reachable, not merely present
#    as dead code (each is invoked from a real onclick, not just defined).
for handler in ("runSearch", "clearSearch", "gotoDevice", "gotoRuleSet",
                "selectRuleSet", "loadRuleSetDetail", "refreshRuleSets",
                "ruleSetDialog", "deleteRuleSetConfirm", "addRuleDialog",
                "deleteRuleConfirm", "loadDeviceCompliance", "drawDeviceCompliance"):
    check(f"configrx.js defines {handler}()",
          re.search(r"function\s+%s\s*\(" % handler, JS) is not None)
check("the Search button is wired to runSearch",
      "App.el('cxse-run').onclick = () => runSearch();" in JS)
check("Enter in the query field runs the search too",
      "App.el('cxse-q').onkeydown" in JS and "runSearch()" in JS)
check("New rule set opens ruleSetDialog(null) (create, not edit)",
      "App.el('cxrs-new').onclick = () => ruleSetDialog(null);" in JS)
check("Evaluate now goes through App.runJob, the house pattern for a "
      "long-running action",
      re.search(r"App\.el\('cxrs-evaluate'\)\.onclick[\s\S]{0,200}App\.runJob\(", JS) is not None)


# ---------------------------------------------------------------------------
# 3. Every control that writes carries data-requires-write="configrx" — the
#    static ones in markup, the same contract test_frontend_contracts.py's
#    MUST_BE_GATED enforces for other modules' controls.
STATIC_WRITE_BUTTONS = ["cxrs-new", "cxrs-edit", "cxrs-delete", "cxrs-evaluate", "cxrs-add-rule"]
ungated = []
for element_id in STATIC_WRITE_BUTTONS:
    match = re.search(r'<button id="%s"([^>]*)>' % re.escape(element_id), INDEX)
    if match is None:
        ungated.append(f"{element_id} (no such button)")
    elif 'data-requires-write="configrx"' not in match.group(1):
        ungated.append(element_id)
check("every static compliance write control declares data-requires-write=\"configrx\"",
      not ungated, ", ".join(ungated) or "none")

# The rules table's per-row Delete button is built at render time, not
# present in index.html, so applyPermissions()'s one-shot DOM sweep cannot
# be relied on to gate it (see gateAttr's own comment in configrx.js) — it
# still carries the attribute for consistency, but is gated by hand too.
check("the per-rule Delete button still declares data-requires-write=\"configrx\"",
      'class="cxrs-rule-delete" data-requires-write="configrx"' in JS)
check("gateAttr() disables it (and says why) rather than omitting it for a "
      "read-only account — never hide a write control",
      "function gateAttr()" in JS
      and "App.canWrite('configrx')" in JS
      and "disabled title=" in JS)


# ---------------------------------------------------------------------------
# 4. Destructive actions (delete a rule set, delete a rule) go through
#    App.confirmDestructive, never a hand-rolled Cancel/Delete pair on
#    App.modal — test_frontend_contracts.py's rule #2, restated here against
#    this feature's own two deletes specifically.
check("deleteRuleSetConfirm uses App.confirmDestructive",
      re.search(r"function deleteRuleSetConfirm\([^)]*\)\s*\{\s*App\.confirmDestructive\(", JS)
      is not None)
check("deleteRuleConfirm uses App.confirmDestructive",
      re.search(r"function deleteRuleConfirm\([^)]*\)\s*\{\s*App\.confirmDestructive\(", JS)
      is not None)
check("no hand-rolled Remove/Delete dialog was introduced in configrx.js",
      re.search(r"App\.modal\(\s*['\"](Remove|Delete)\b", JS) is None)


# ---------------------------------------------------------------------------
# 5. The rule-set/rule create-and-edit dialogs are real App.modal dialogs
#    (a <form class="modal-form">, submitted by the primary button — see
#    app.js's own modal()) with their required fields checked through
#    App.requireFields rather than a native alert() or a silent no-op.
check("ruleSetDialog opens a real App.modal dialog",
      re.search(r"async function ruleSetDialog\([^)]*\)\s*\{[\s\S]{0,200}App\.modal\(", JS)
      is not None)
check("addRuleDialog opens a real App.modal dialog",
      re.search(r"function addRuleDialog\([^)]*\)\s*\{\s*App\.modal\(", JS) is not None)
check("ruleSetDialog validates its Name field through App.requireFields",
      "App.requireFields(m, [['#cxrs-f-name', 'Name']])" in JS)
check("addRuleDialog validates Pattern and Description through App.requireFields",
      "App.requireFields(m, [['#cxrs-f-pattern', 'Pattern'], ['#cxrs-f-desc', 'Description']])" in JS)


# ---------------------------------------------------------------------------
# 6. Escaping: nothing server-supplied (a device name, a rule description, a
#    config line, a group name) is interpolated into a cell's HTML unescaped
#    — configrx.js's own `escape` alias (App.escapeHtml) is what every other
#    table on this page already uses.
for label, snippet in [
    ("a search result's device name/ip", r"escape\(r\.device_name"),
    ("a search result's config line", r"escape\(r\.line\)"),
    ("a rule set's name in its own row", r"escape\(r\.name\)"),
    ("a rule's pattern", r"escape\(r\.pattern\)"),
    ("a rule's description", r"escape\(r\.description\)"),
    ("a compliance result's failed-rule descriptions", r"escape\(f\.description\)"),
    ("a device group's name", r"escape\(g\.name\)"),
]:
    check(f"{label} is escaped before it reaches innerHTML", re.search(snippet, JS) is not None)


# ---------------------------------------------------------------------------
# 6b. A "suspect" capture (configrx.py's SUSPECT_SHRINK_RATIO — stored
#     because refusing it outright is worse, but under a fifth of the
#     device's previous backup) is a real state a compliance evaluation can
#     land on: a pass or fail is genuine against what is actually stored,
#     but what is stored may not be the device's real configuration. This
#     must read as visibly distinct from an ordinary pass/fail, on both the
#     per-rule-set results table and the device's own compliance summary —
#     never silently collapsed into one of them.
check("the compliance results table flags a result computed from a "
      "suspect capture, distinctly from an ordinary pass/fail",
      "_suspect" in JS and "from a suspect" in JS)
check("the suspect flag is read from ConfigRX's own last_backup_status, "
      "not guessed from the compliance status itself",
      "last_backup_status || '').split(' ')[0] === 'suspect'" in JS)
check("the device compliance summary on the Devices subtab also calls out "
      "a suspect capture, up front, before its per-rule-set results",
      re.search(r"function drawDeviceCompliance\(\)[\s\S]{0,800}suspect", JS) is not None)


# ---------------------------------------------------------------------------
# 7. Subtabs: SEARCH and COMPLIANCE follow the exact pattern Nodes'
#    DEVICES/TOPOLOGY/DISCOVERY/PROFILES subtabs use (index.html ~143-148) —
#    a `.subtabs` nav of `.subtab` buttons with `data-subtab`, paired
#    positionally with `.subpage` siblings, wired generically by app.js's
#    wireSubtabGroups/wireSubtabRouting, with this module owning the click
#    handler that actually toggles `.active` and remembers the choice.
check("the ConfigRX page has a .subtabs nav with DEVICES/SEARCH/COMPLIANCE",
      '<nav class="subtabs">' in CONFIGRX_SECTION
      and 'data-subtab="devices"' in CONFIGRX_SECTION
      and 'data-subtab="search"' in CONFIGRX_SECTION
      and 'data-subtab="compliance"' in CONFIGRX_SECTION)
check("the three subpages exist, positionally matching the three subtabs",
      re.search(r'id="configrx-sub-devices" class="subpage active"[\s\S]*'
                r'id="configrx-sub-search" class="subpage"[\s\S]*'
                r'id="configrx-sub-compliance" class="subpage"', CONFIGRX_SECTION) is not None)
check("configrx.js owns a selectSub() that toggles .active on the right pane",
      "function selectSub(name)" in JS
      and "#page-configrx > .subtabs > .subtab" in JS
      and "#page-configrx > .subpage" in JS)
check("subtab selection is remembered with App.rememberSub and restored with "
      "App.recallSub, the same contract every other module's subtabs use",
      "App.rememberSub('configrx'," in JS and "App.recallSub('configrx'," in JS)
check("selecting a rule set writes it into the URL hash (App.setRoute), so "
      "a link to one is shareable the way a device link already is",
      "App.setRoute(['compliance', ruleSetId])" in JS)
check("activate() forces the devices subtab open for a #/configrx/device/.. "
      "link regardless of which subtab was showing",
      re.search(r"if \(opts\.parts\[0\] === 'device'\)[\s\S]{0,600}selectSub\('devices'\)", JS)
      is not None)
check("activate() also handles a direct #/configrx/compliance/<id> link",
      re.search(r"opts\.parts\[0\] === 'compliance'[\s\S]{0,300}selectRuleSet\(", JS) is not None)


# ---------------------------------------------------------------------------
# 8. A search result and a compliance result each carry a way back to the
#    device's own config/backup — the explicit ask ("a way to get from a
#    result to that device's config/backup"), not just a display of the row.
check("clicking a search result row opens that device (gotoDevice)",
      re.search(r"App\.drawRows\(body, rows, SEARCH_COLUMNS,[\s\S]{0,120}"
                r"gotoDevice\(row\.device_id\)", JS) is not None)
check("clicking a compliance result row opens that device (gotoDevice)",
      re.search(r"App\.drawRows\(body, enriched, RESULT_COLUMNS,[\s\S]{0,120}"
                r"gotoDevice\(row\.device_id\)", JS) is not None)
check("gotoDevice actually opens the device's latest backup, not just the "
      "device row — a search hit should land on a config, not an empty pane",
      re.search(r"async function gotoDevice\([\s\S]*?selectBackup\(view\.backups\[0\]\.id\)",
                JS) is not None)


# ---------------------------------------------------------------------------
# 9. The device/backup pane surfaces the selected device's own compliance
#    state (the explicit ask), read-only, and it is cleared/reloaded on
#    every device selection so it can never show a stale device's results.
check("index.html has a cx-device-compliance element on the CONFIG pane",
      'id="cx-device-compliance"' in CONFIGRX_SECTION)
check("selectDevice() resets and reloads the compliance summary for the "
      "newly selected device",
      re.search(r"async function selectDevice\(deviceId\)[\s\S]{0,400}"
                r"view\.deviceCompliance = null[\s\S]{0,400}"
                r"loadDeviceCompliance\(deviceId\)", JS) is not None)
check("a compliance summary entry jumps to its rule set (gotoRuleSet), it "
      "does not act on the result from here",
      "gotoRuleSet(Number(button.dataset.ruleSetId))" in JS)


# ---------------------------------------------------------------------------
# 10. No re-implementation of a shared app.js helper this feature had reason
#     to want its own copy of — the house rule test_frontend_contracts.py's
#     duplication contracts already enforce for the rest of the product.
check("uses the shared App.drawRows/App.wireRowKeyboard table helpers "
      "rather than hand-building rows another way",
      "App.drawRows(" in JS and "App.wireRowKeyboard(" in JS)
check("uses App.deviceIndex() for the device-by-id lookup the results table "
      "needs, rather than a new device cache",
      "await App.deviceIndex()" in JS)
check("uses App.statusMark for compliance status, the one status renderer "
      "in the app, rather than a bespoke colour/shape mapping",
      "App.statusMark(RESULT_TONE" in JS or "App.statusMark(tone" in JS)


print()
if FAILS:
    print(f"FAILED {len(FAILS)} check(s):")
    for message in FAILS:
        print(f"  - {message}")
    sys.exit(1)
print("ALL CONFIGRX SEARCH/COMPLIANCE UI CONTRACTS HOLD")
