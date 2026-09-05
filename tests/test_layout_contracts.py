"""The layout and input contracts 4.46.0 introduced, pinned as text.

Width breakpoints exist and the fixed widths are fluid under them; every
drag in the product is a captured pointer gesture rather than a mouse-only
one, so a finger and a pen work and a drag that leaves its element still
ends; the pane splitters are real separators the keyboard can move; kiosk
mode is a query flag the stylesheet and the script both answer to. Each of
these was a comment or a convention before, and a convention that lives only
in a comment is one that comes back.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "netpath", "web", "static")

failures = []


def check(condition, message):
    print(("OK   " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as handle:
        return handle.read()


css = read("app.css")
app = read("app.js")

# --------------------------------------------------------------------------
# 1. Breakpoints: two steps, and the fixed widths give way under them.
check("@media (max-width: 1200px)" in css, "a 1200 px breakpoint exists")
check("@media (max-width: 900px)" in css, "a 900 px breakpoint exists")
narrow = css.split("@media (max-width: 1200px)")[1]
check(".modal-box { min-width: 0;" in narrow, "dialogs lose their 420 px minimum below 1200 px")
check(".login-box { width: min(" in narrow, "the sign-in card is fluid below 1200 px")
stacked = css.split("@media (max-width: 900px)")[1]
check("[data-splitter].cols { flex-direction: column; }" in stacked,
      "side-by-side splitters stack below 900 px")
check('html[data-tab="netpath"] #page-netpath.page { flex-direction: column; }' in stacked,
      "the NetPath sidebar moves above the canvas below 900 px")
check("innerWidth < 900" in app and "'narrow'" in app,
      "applyDensity() answers the same 900 px question the stylesheet does")

# --------------------------------------------------------------------------
# 2. Pointer events, captured. No drag starts on mousedown anywhere.
DRAG_FILES = ["app.js", "netpath.js", "netflow.js"]
for name in DRAG_FILES:
    body = read(name)
    starts = [line for line in body.splitlines()
              if re.search(r"(addEventListener\('mouse(down|up)'|onmouse(down|up)\s*=)", line)
              and "ACTIVITY_EVENTS" not in line
              # a row's mousedown only moves the roving tabindex; it drags nothing
              and "other.tabIndex" not in line and "tr.addEventListener('mousedown'" not in line]
    check(not starts, "%s starts no drag on a mouse event (found %d)" % (name, len(starts)))
    doc_moves = re.findall(r"(?:document|window)\.addEventListener\('mouse(?:move|up)'", body)
    check(not doc_moves, "%s tracks no drag on document or window (found %d)" % (name, len(doc_moves)))
check(app.count("setPointerCapture") >= 2, "app.js captures the pointer for dividers and grips")
check(read("netpath.js").count("setPointerCapture") >= 2,
      "netpath.js captures the pointer for the route pan and the timeline brush")
check(read("netflow.js").count("setPointerCapture") >= 1, "netflow.js captures the pointer for its brush")
for selector in (".divider {", "th .grip {"):
    block = css.split(selector)[1].split("}")[0]
    check("touch-action: none" in block, "%s touch-action: none" % selector.strip(" {"))
check("#route-svg, .brush svg { touch-action: none; }" in css,
      "the dragged canvases are not scrolled by a finger")
index = read("index.html")
check('id="nf-chart" class="canvas chart brush"' in index and 'id="timeline" class="timeline brush"' in index,
      "the two brush charts are marked .brush")
check("'pointerdown'" in app.split("ACTIVITY_EVENTS = ")[1].split("]")[0],
      "a pointer press counts as presence for the idle timer")

# --------------------------------------------------------------------------
# 3. Splitters are separators the keyboard can move.
divider = app.split("function wireDivider(")[1].split("function resetLayout(")[0]
for needle, why in [("'separator'", "role=separator"), ("tabIndex = 0", "focusable"),
                    ("aria-orientation", "orientation"), ("aria-valuenow", "value"),
                    ("'ArrowLeft'", "arrow keys"), ("'Home'", "Home/End"),
                    ("getComputedStyle(container).flexDirection", "orientation read per gesture")]:
    check(needle in divider or needle in app.split("function isVertical(")[1].split("}")[0],
          "wireDivider: %s" % why)
check("aria-keyshortcuts', 'Alt+ArrowLeft Alt+ArrowRight'" in app,
      "column headers advertise Alt+Arrow resizing")
check(".divider:focus-visible::after { background: var(--accent); }" in css,
      "a focused divider shows it")

# --------------------------------------------------------------------------
# 4. Kiosk mode and themes are answered on both sides.
check("get('kiosk') === '1'" in app, "app.js reads ?kiosk=1")
check("html[data-kiosk] { font-size: 125%; }" in css, "kiosk grows the rem root")
# Phase 6 grouped the tab bar into .topbar (the scrolling #tabs plus the
# now-pinned .tabs-utility carrying #whoami/Account/Sign out/#conn), so
# hiding only #tabs in kiosk mode would leave that utility group on screen;
# the rule now hides the whole strip.
check("body.kiosk .topbar { display: none; }" in css, "kiosk hides the tab strip")
check('id="kiosk-bar"' in index and 'id="kiosk-session"' in index, "the kiosk bar exists")
check("{ kiosk: true }" in app and "kioskHeld" in app,
      "the kiosk heartbeat is flagged and one refusal is final")
check("THEME_KEY = 'sappiwhere.theme'" in app and "function setTheme(" in app,
      "app.js owns the theme key boot.js reads")
# Appearance (theme, and now the wall-display launcher) moved from a
# Settings fieldset — which used to lead the page ahead of every setting
# that actually lives on the server — into the Account dialog, reachable
# from every page since it is a per-browser choice rather than a server
# one. #set-theme no longer exists; the select is app.js's own #am-theme,
# and Settings leaves a plain pointer button where the fieldset was.
check('id="am-theme"' in app and "am-theme" in app,
      "Appearance moved to the Account dialog and app.js wires it")
check('id="open-account-appearance"' in index and "open-account-appearance" in read("settings.js"),
      "Settings leaves a pointer to Appearance where the fieldset used to be")
check("App.tile" in read("dashboard.js") and "function tile(" in app and "function figures(" in app,
      "tiles and figures are one shared component")
check(".dash-figure" not in css and ".dash-tile" not in css, "no dash-prefixed figure classes remain")
check("body.kiosk" in css and "App.state.kiosk" in read("nodes.js") and "App.state.kiosk" in read("alerts.js"),
      "the Nodes and Alerts strips render figures on a wall")
login = read("login.js")
check("window.location.search" in login, "login.js hands the query string (kiosk) back after sign-in")

print()
if failures:
    print("FAILED %d check(s):" % len(failures))
    for message in failures:
        print("  - " + message)
    sys.exit(1)
print("ALL LAYOUT AND INPUT CONTRACTS HOLD")
