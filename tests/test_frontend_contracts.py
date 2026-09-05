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

print()
if failures:
    print("FAILED %d contract(s):" % len(failures))
    for message in failures:
        print("  - %s" % message)
    sys.exit(1)
print("ALL FRONTEND CONTRACTS HOLD")
