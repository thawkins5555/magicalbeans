"""The design tokens hold what tokens.css says they hold.

tokens.css writes a contrast ratio beside every tone. This recomputes each
one from the hex values, so a token cannot be nudged for taste and quietly
fall under the AA floor the comment still claims. It also keeps the desktop
console's copy of the palette (netpath/theme.py) equal to the web's, and
asserts the two things the token file exists to make impossible: a hex
colour or a pixel font size written anywhere else, and the retired --faint
tone coming back under its old name.
"""

import itertools
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "netpath", "web", "static")
sys.path.insert(0, REPO_ROOT)

failures = []


def check(condition, message):
    print(("OK   " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as handle:
        return handle.read()


def luminance(hex_colour):
    hex_colour = hex_colour.lstrip("#")
    channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
              for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a, b):
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def lab(hex_colour):
    # sRGB -> CIE L*a*b*, for the VLAN palette's pairwise distance check
    # below: a Euclidean distance in Lab tracks perceived colour difference
    # far better than one in raw RGB, which is why CIE76 (this) or better is
    # what the MAPPER spec asks for rather than a plain hex diff.
    hex_colour = hex_colour.lstrip("#")
    r, g, b = [int(hex_colour[i:i + 2], 16) / 255 for i in (0, 2, 4)]

    def lin(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = lin(r), lin(g), lin(b)
    x = r * 0.4124 + g * 0.3576 + b * 0.1805
    y = r * 0.2126 + g * 0.7152 + b * 0.0722
    z = r * 0.0193 + g * 0.1192 + b * 0.9505
    xn, yn, zn = 0.95047, 1.0, 1.08883
    x, y, z = x / xn, y / yn, z / zn

    def f(t):
        return t ** (1 / 3) if t > 0.008856 else (7.787 * t + 16 / 116)

    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def delta_e76(hex_a, hex_b):
    # The plain Euclidean distance in Lab space. "CIE76" because later,
    # perceptually-truer formulae (CIE94, CIEDE2000) exist and are fine to
    # swap in later — this is the floor the MAPPER spec asked for ("CIE76 or
    # better"), not a ceiling on what a future edit may use.
    l1, a1, b1 = lab(hex_a)
    l2, a2, b2 = lab(hex_b)
    return ((l1 - l2) ** 2 + (a1 - a2) ** 2 + (b1 - b2) ** 2) ** 0.5


tokens_css = read(STATIC, "tokens.css")
# One dict per block: the bare :root is the dark default, and each
# :root[data-theme="…"] block is a set of overrides on top of it. The pairs
# below are then measured for every theme, each with its own overrides
# applied over the base — so a dark tone a theme forgot to redefine is
# measured against that theme's light ground and fails, instead of being
# invisible in a browser.
BLOCKS = re.findall(r':root(?:\[data-theme="([a-z]+)"\])?\s*\{(.*?)\n\}', tokens_css, re.S)
check(len(BLOCKS) == 8, "tokens.css has a base block and seven theme blocks (found %d)" % len(BLOCKS))
BASE = {}
OVERRIDES = {}
for theme_name, body_text in BLOCKS:
    values = dict(re.findall(r"^\s*(--[a-z0-9-]+):\s*([^;]+);", body_text, re.M))
    if theme_name:
        OVERRIDES[theme_name] = values
    else:
        BASE = values
TOKENS = BASE
check(len(TOKENS) > 40, "tokens.css parsed (%d tokens)" % len(TOKENS))
# The spacing scale: four steps, each a multiple of 4px and each bigger
# than the last, so a control's padding stops being a number picked by eye.
SPACE_STEPS = ["--space-xs", "--space-sm", "--space-md", "--space-lg"]
check(all(name in TOKENS for name in SPACE_STEPS),
      "tokens.css defines the spacing scale (%s)" % SPACE_STEPS)
if all(name in TOKENS for name in SPACE_STEPS):
    space_px = [int(TOKENS[name].strip().rstrip("px")) for name in SPACE_STEPS]
    check(space_px == sorted(space_px) and len(set(space_px)) == 4,
          "the spacing scale is four distinct, ascending steps (%s)" % space_px)
    check(all(value % 4 == 0 for value in space_px),
          "every spacing step is a multiple of 4px (%s)" % space_px)
THEMES = {"dark": dict(BASE)}
for theme_name, values in OVERRIDES.items():
    THEMES[theme_name] = dict(BASE, **values)
check(sorted(THEMES) == ["contrast", "dark", "light", "midnight", "neon", "nord", "slate", "solarized"],
      "the themes are dark, light, contrast, midnight, nord, solarized, slate and neon")
# Every role a light ground makes unreadable if left dark. A theme block
# must say each one explicitly.
THEMED_ROLES = ["--bg", "--panel", "--raised", "--hairline", "--grid", "--text", "--muted",
                "--dim", "--line", "--data-neutral", "--accent", "--accent-hover", "--focus",
                "--ok", "--warn", "--fail", "--blocked", "--overrun", "--error", "--nodata",
                "--selected", "--checked", "--checked-strong"]
for theme_name, values in OVERRIDES.items():
    missing = [role for role in THEMED_ROLES if role not in values]
    check(not missing, "theme %s redefines every themed role (missing %s)" % (theme_name, missing or "none"))
check("color-scheme: dark" in BLOCKS[0][1], "the base block declares color-scheme: dark")
# Every theme with a light ground needs its own color-scheme: light, so the browser draws its own
# chrome (scrollbars, the date picker, a <select>) to match — a set rather than one more
# string-split per theme, since Slate is not the only light theme any more and will not be the
# last one either.
LIGHT_SCHEME_THEMES = {"light", "slate"}
for theme_name, body_text in BLOCKS:
    if theme_name in LIGHT_SCHEME_THEMES:
        check("color-scheme: light" in body_text,
              "the %s theme declares color-scheme: light" % theme_name)


def tok(name, theme="dark"):
    return THEMES[theme][name].strip()


# --------------------------------------------------------------------------
# 1. Every contrast claim in tokens.css, recomputed. AA: 4.5 for the text
#    sizes this product uses, 3.0 for a graphical object or boundary.
TEXT_ON = [
    ("--text", "--bg", 4.5), ("--text", "--panel", 4.5), ("--text", "--raised", 4.5),
    ("--text", "--selected", 4.5), ("--text", "--checked-strong", 4.5),
    ("--muted", "--bg", 4.5), ("--muted", "--panel", 4.5), ("--muted", "--raised", 4.5),
    ("--muted", "--selected", 4.5), ("--muted", "--hairline", 4.5),
    ("--dim", "--bg", 4.5), ("--dim", "--panel", 4.5), ("--dim", "--raised", 4.5),
    ("--ok", "--bg", 4.5), ("--warn", "--bg", 4.5), ("--fail", "--bg", 4.5),
    ("--accent", "--bg", 4.5), ("--fail", "--raised", 4.5),
    # A semantic tone used to be checked against --bg only, and --fail was the
    # single one also checked against --raised. But --raised is every alternate
    # row of every table, which is where these tones actually live: "unchanged"
    # and "oper up" in --ok, the warning severity word in --warn. Both sat under
    # AA in the light theme (4.31 and 4.21) with this list reporting green.
    ("--ok", "--raised", 4.5), ("--warn", "--raised", 4.5),
    ("--accent", "--raised", 4.5), ("--blocked", "--raised", 4.5),
    ("--overrun", "--raised", 4.5), ("--error", "--raised", 4.5),
    ("--ok", "--panel", 4.5), ("--warn", "--panel", 4.5), ("--fail", "--panel", 4.5),
    # ...and on the row the operator has actually opened.
    ("--ok", "--selected", 4.5), ("--warn", "--selected", 4.5),
    ("--fail", "--selected", 4.5), ("--accent", "--selected", 4.5),
    ("--dim", "--selected", 4.5),
    # --checked-strong carries text too. Only the two tones that are allowed to
    # be drawn on it are held here; tokens.css records why the rest are not.
    ("--text", "--checked", 4.5), ("--muted", "--checked", 4.5),
    ("--text", "--checked-strong", 4.5),
    # dark text on the three badge fills
    ("--bg", "--fail", 4.5), ("--bg", "--warn", 4.5), ("--bg", "--accent", 4.5),
    ("--focus", "--bg", 4.5),
    ("--canvas-text", "--canvas", 4.5), ("--canvas-muted", "--canvas", 4.5),
    ("--canvas-accent", "--canvas", 4.5), ("--canvas-fail", "--canvas", 4.5),
    # the route canvas node box is --canvas-panel; its eyebrow and refusal
    # text must read there too
    ("--canvas-faint", "--canvas-panel", 4.5), ("--canvas-blocked", "--canvas-panel", 4.5),
    ("--canvas-fail", "--canvas-panel", 4.5), ("--canvas-warn", "--canvas-panel", 4.5),
]
GRAPHIC_ON = [
    ("--line", "--raised", 3.0), ("--line", "--panel", 3.0), ("--line", "--bg", 3.0),
    ("--data-neutral", "--panel", 3.0),
    ("--accent", "--raised", 3.0),       # the selected-row bar, the focus ring
    # The meter fill against its own track (.usage .meter, .dash-bar), which
    # is --raised, not --accent/--ok/--warn/--fail against --data-neutral —
    # the pair that was actually failing (1.66-2.82:1) while the track read
    # fine against --panel. --accent's copy of this pair already existed
    # above for an unrelated reason and is not repeated here.
    ("--ok", "--raised", 3.0), ("--warn", "--raised", 3.0), ("--fail", "--raised", 3.0),
]
# High contrast is held to AAA: 7:1 for text, 4.5:1 for a line or a ring. The four new themes are
# ordinary AA, like Dark and Light — only Contrast is asked to do more, and that floor is not
# changing here.
FLOOR_LIFT = {"dark": (0.0, 0.0), "light": (0.0, 0.0), "contrast": (2.5, 1.5),
              "midnight": (0.0, 0.0), "nord": (0.0, 0.0), "solarized": (0.0, 0.0),
              "slate": (0.0, 0.0), "neon": (0.0, 0.0)}
for theme_name in sorted(THEMES):
    text_lift, graphic_lift = FLOOR_LIFT[theme_name]
    for fg, bg, floor in TEXT_ON:
        lift = 0.0 if fg.startswith("--canvas") or bg.startswith("--canvas") else text_lift
        ratio = contrast(tok(fg, theme_name), tok(bg, theme_name))
        check(ratio >= floor + lift, "[%s] %s on %s = %.2f:1 (floor %.1f)"
              % (theme_name, fg, bg, ratio, floor + lift))
    for fg, bg, floor in GRAPHIC_ON:
        ratio = contrast(tok(fg, theme_name), tok(bg, theme_name))
        check(ratio >= floor + graphic_lift, "[%s] %s on %s = %.2f:1 (floor %.1f)"
              % (theme_name, fg, bg, ratio, floor + graphic_lift))
    # The hierarchy has to stay a hierarchy: each tone quieter than the
    # last against the page, whichever way round light and dark are.
    against_bg = [contrast(tok(role, theme_name), tok("--bg", theme_name))
                  for role in ("--text", "--muted", "--dim", "--line")]
    check(against_bg[0] > against_bg[1] > against_bg[2] > against_bg[3],
          "[%s] text > muted > dim > line against the page" % theme_name)

# --------------------------------------------------------------------------
# 1b. The alert-severity row tint, which is not a token but a colour-mix of
#     two, so section 1's token-vs-token pairs never reach it. app.css's own
#     comment states how many theme blocks --fail falls under AA in on that
#     tint, and that claim is recomputed here for the same reason every ratio
#     in tokens.css is. It earned the check: the comment read "two of the six"
#     for a figure that is five of seven statically and seven of seven at the
#     pulse peak. Both the percentages and the claim are read out of app.css
#     rather than restated, so a retuned tint or a renewed --fail moves this
#     test with it instead of leaving it asserting last year's palette.
APP_CSS = read(STATIC, "app.css")


def mix(front, back, fraction):
    # color-mix(in srgb, ...) interpolates the gamma-encoded components, and
    # the browser serializes the result to 8-bit channels — the rounding is
    # part of the colour the operator is actually looking at.
    front, back = front.lstrip("#"), back.lstrip("#")
    return "#%02X%02X%02X" % tuple(
        round(int(front[i:i + 2], 16) * fraction + int(back[i:i + 2], 16) * (1 - fraction))
        for i in (0, 2, 4))


SEVERE_CSS = APP_CSS[APP_CSS.index("tr.alert-severe td {"):APP_CSS.index("td.num {")]
TINTS = [int(pct) / 100 for pct in re.findall(
    r"color-mix\(in srgb, var\(--fail\) (\d+)%, var\(--panel\)\)", SEVERE_CSS)]
check(len(TINTS) == 3, "app.css mixes three alert-severe tints — the static one plus "
                       "the two pulse keyframe ends (found %s)" % TINTS)
CLAIM = re.search(r"under AA on this tint in (\d+)\s+of the (\d+) theme blocks\s+"
                  r"statically \(([0-9.,\s]+)\)", APP_CSS)
check(CLAIM is not None, "app.css still states the alert-severe tint's AA count")
if CLAIM and len(TINTS) == 3:
    static_tint, peak_tint = TINTS[0], max(TINTS)
    check(int(CLAIM.group(2)) == len(THEMES), "the comment counts every theme block "
          "(says %s, there are %d)" % (CLAIM.group(2), len(THEMES)))
    measured = []
    for theme_name in sorted(THEMES):
        ratio = contrast(tok("--fail", theme_name),
                         mix(tok("--fail", theme_name), tok("--panel", theme_name), static_tint))
        if ratio < 4.5:
            measured.append(round(ratio, 2))
    claimed = sorted(float(value) for value in CLAIM.group(3).split(","))
    check(int(CLAIM.group(1)) == len(measured),
          "--fail on the %d%% tint is under AA in %d of %d blocks; the comment says %s"
          % (static_tint * 100, len(measured), len(THEMES), CLAIM.group(1)))
    check(sorted(measured) == claimed, "the comment's ratios are the computed ones "
          "(comment %s, measured %s)" % (claimed, sorted(measured)))
    # The pulse peak is the worst ground a row ever shows, and the whole
    # reason .sev is pinned to --text: that fix is only sufficient if --text
    # itself clears AA there in every theme, which is what makes it the one
    # tone a cell in such a row may use.
    for theme_name in sorted(THEMES):
        peak = mix(tok("--fail", theme_name), tok("--panel", theme_name), peak_tint)
        severity_word = contrast(tok("--fail", theme_name), peak)
        check(severity_word < 4.5, "[%s] --fail on the %d%% pulse peak is %.2f:1, under AA "
              "— .sev still needs --text" % (theme_name, peak_tint * 100, severity_word))
        ratio = contrast(tok("--text", theme_name), peak)
        check(ratio >= 4.5, "[%s] --text on the %d%% pulse peak = %.2f:1 (floor 4.5)"
              % (theme_name, peak_tint * 100, ratio))

# --------------------------------------------------------------------------
# 2b. The pairing actually drawn on a MAPPER trunk is --canvas-vlan-*
#     against --canvas, not --vlan-* against --panel: mapper.js's drawLink
#     strokes a strand with --canvas-vlan-N because the strand is drawn on
#     #mp-canvas (background: var(--canvas)), not on a --panel surface. The
#     VLAN table's swatch and the colour picker read --canvas-vlan-* too, as
#     of the second review pass: they name a colour the operator is about to
#     see on the canvas, so showing them the --panel-tuned value meant the
#     legend and the line disagreed in four of the seven themes. A swatch on
#     --panel still needs its own readable border either way (.mp-swatch
#     uses var(--line), not var(--hairline), for exactly that reason). A code
#     review caught nine or ten of the sixteen --vlan-* hues failing 3:1 on
#     white before --canvas-vlan-* existed (--vlan-4 measured ~1.5:1) — this
#     is the check that catches a regression back to that bug, by checking
#     the ground the strand is actually drawn on instead of --panel.
# Not a colour-science standard: the tightest pair this file actually
# produces is the light-ground rotation ("light" and "slate" both reuse it)
# at 10.40 apart in CIE76. The floor sits just under that, so a future edit
# that lets two --canvas-vlan-* hues drift together fails here before it is
# visible on screen, without being so tight that float rounding trips it.
VLAN_DISTANCE_FLOOR = 10.0
CANVAS_VLAN_ROLES = ["--canvas-vlan-%d" % n for n in range(1, 17)]
for theme_name in sorted(THEMES):
    values = THEMES[theme_name]
    missing = [role for role in CANVAS_VLAN_ROLES if role not in values]
    check(not missing, "[%s] all sixteen --canvas-vlan-* tokens are defined (missing %s)"
          % (theme_name, missing or "none"))
    if missing:
        continue
    for role in CANVAS_VLAN_ROLES:
        ratio = contrast(tok(role, theme_name), tok("--canvas", theme_name))
        check(ratio >= 3.0, "[%s] %s on --canvas = %.2f:1 (floor 3.0)" % (theme_name, role, ratio))
    hexes = [tok(role, theme_name) for role in CANVAS_VLAN_ROLES]
    min_gap = min(delta_e76(a, b) for a, b in itertools.combinations(hexes, 2))
    check(min_gap >= VLAN_DISTANCE_FLOOR,
          "[%s] closest pair among the sixteen --canvas-vlan-* hues is %.2f apart (floor %.1f)"
          % (theme_name, min_gap, VLAN_DISTANCE_FLOOR))

# --------------------------------------------------------------------------
# 3. The desktop console carries the same values.
#
# theme.py is read as text rather than imported: it needs PySide6, which a
# headless install does not have, and the values are what matter here.
theme_src = read(REPO_ROOT, "netpath", "theme.py")
THEME = dict(re.findall(r'^([A-Z_]+) = QColor\("(#[0-9A-Fa-f]{6})"\)', theme_src, re.M))
PAIRS = {
    "--bg": "BG", "--panel": "PANEL", "--raised": "PANEL_RAISED",
    "--hairline": "HAIRLINE", "--grid": "GRID", "--text": "TEXT",
    "--muted": "TEXT_MUTED", "--dim": "TEXT_DIM", "--line": "LINE",
    "--data-neutral": "DATA_NEUTRAL", "--accent": "ACCENT", "--accent-hover": "ACCENT_HOVER",
    "--ok": "OK", "--warn": "WARN", "--fail": "FAIL", "--blocked": "BLOCKED",
    "--overrun": "OVERRUN", "--error": "ERROR", "--nodata": "NODATA",
    "--canvas": "CANVAS", "--canvas-panel": "CANVAS_PANEL",
    "--canvas-hairline": "CANVAS_HAIRLINE", "--canvas-grid": "CANVAS_GRID",
    "--canvas-text": "CANVAS_TEXT", "--canvas-muted": "CANVAS_TEXT_MUTED",
    "--canvas-faint": "CANVAS_TEXT_FAINT", "--canvas-accent": "CANVAS_ACCENT",
    "--canvas-ok": "CANVAS_OK", "--canvas-warn": "CANVAS_WARN",
    "--canvas-fail": "CANVAS_FAIL", "--canvas-blocked": "CANVAS_BLOCKED",
}
for token_name, const in PAIRS.items():
    check(THEME.get(const, "").upper() == tok(token_name).upper(),
          "theme.py %s == %s %s" % (const, token_name, tok(token_name)))
series = re.search(r"^SERIES = \[(.*?)\]", theme_src, re.M | re.S)
series_hex = re.findall(r'QColor\("(#[0-9A-Fa-f]{6})"\)', series.group(1)) if series else []
check(len(series_hex) == 8, "theme.py SERIES has the web's eight hues")
for index, colour in enumerate(series_hex, 1):
    check(colour.upper() == tok("--cat-%d" % index).upper(),
          "theme.py SERIES[%d] == --cat-%d" % (index - 1, index))
check("SERIES_OTHER = DATA_NEUTRAL" in theme_src, "theme.py SERIES_OTHER is DATA_NEUTRAL")
check(not re.search(r"^TEXT_FAINT = ", theme_src, re.M), "theme.py has no TEXT_FAINT")
stylesheet = theme_src[theme_src.index("STYLESHEET"):]
loose = re.findall(r"#[0-9A-Fa-f]{6}\b", stylesheet)
check(not loose, "theme.py stylesheet writes no hex of its own (found %s)" % (loose or "none"))

# --------------------------------------------------------------------------
# 4. Nothing else writes a value the tokens own.
SHEETS = ["app.css", "ssh.css"]
for sheet in SHEETS:
    body = read(STATIC, sheet)
    check(not re.search(r"#[0-9A-Fa-f]{3,6}\b", body),
          "%s: no hex colour (every colour is a token)" % sheet)
    sizes = re.findall(r"font(?:-size)?:[^;]*?\b\d+px", body)
    check(not sizes, "%s: no pixel font size (found %s)" % (sheet, sizes[:3] or "none"))
    check(not re.search(r"letter-spacing:\s*[\d.]+px", body),
          "%s: no pixel letter-spacing" % sheet)
    check("var(--faint)" not in body, "%s: --faint is gone" % sheet)
    # shadows and scrims are tokens too: five hand-written rgba shadows and
    # two scrims used to sit beside the token that existed for them
    check("rgba(" not in body, "%s: no literal rgba (shadows and scrims are tokens)" % sheet)
    # radii are tokens too: seven hand-tuned pixel values (2, 3, 5, 9px)
    # used to sit beside the three the contract named, one per shape,
    # before --radius-pill gave the half-height ones a single home. A
    # radius still allowed to use a token in a calc() (the nested subtab's
    # `calc(var(--radius-sm) - 1px)`) is not a literal of its own.
    radii = [value for value in re.findall(r"border-radius:\s*([^;]+);", body)
             if "px" in value and "var(" not in value]
    check(not radii, "%s: no pixel border-radius (found %s)" % (sheet, radii[:3] or "none"))
check(read(STATIC, "app.css").count(".sr-only {") == 1, "app.css defines .sr-only once")
APP_CSS = read(STATIC, "app.css")
check(APP_CSS.count("background: var(--panel);\n  border: 1px solid var(--hairline);") == 1,
      "one panel surface rule (the seven copies are gone)")
check("button.module-settings {" not in APP_CSS, "the Settings gear is an ordinary secondary button")
check(APP_CSS.count("font: 600 var(--fs-2xs)/1 var(--ui);\n  letter-spacing: var(--track-wide);") == 1,
      "one eyebrow rule")
# The flattened tab strip (4.49.0) retired the four labelled wrappers, and
# with them, the .tab-group::before entry the eyebrow selector list carried.
# The check above counts the shared declaration BLOCK, which .tab-group's
# retirement never touched (it only ever added a selector to the list this
# assertion does not count) — so it stays green whether or not the retired
# selector is still named. This one actually looks for it.
check(".tab-group::before" not in APP_CSS, "the retired .tab-group eyebrow selector is gone")
check("table { width: 100%; border-collapse: collapse; font-family: var(--ui);" in APP_CSS
      and "td.mono" in APP_CSS, "tables are proportional with mono opt-in per column")
space_uses = sum(APP_CSS.count("var(%s)" % name) for name in SPACE_STEPS)
check(space_uses > 50, "app.css actually uses the spacing scale (%d references)" % space_uses)
check("var(--radius-pill)" in APP_CSS, "app.css uses --radius-pill for the half-height shapes")
check(".row.start { justify-content: flex-start; gap: 14px; }" in APP_CSS,
      "one .row.start modifier (nodes.js/netflow.js/events.js no longer "
      "each carry this as an identical inline style)")
check(".status-fg { color: var(--ok); }" in APP_CSS
      and all(".status-fg.%s {" % tone in APP_CSS
              for tone in ("warn", "bad", "blocked", "err", "muted", "line")),
      "the .status-fg base+modifier pattern exists with the full tone vocabulary "
      "nodes.js's oper-status/STP-state text and debug.js's worker-status text need")

for name in sorted(os.listdir(STATIC)):
    if name.endswith((".js", ".html")):
        body = read(STATIC, name)
        if name == "netpath.js":
            # the route canvas is white: the dark theme's --blocked (built for
            # --bg) fails contrast there, so the canvas has its own token
            # the one legitimate use left is STATUS_COLOR, which paints the
            # timeline's status lane on the dark panel
            check(body.count("var(--blocked)") == 1,
                  "netpath.js: the dark --blocked is not painted on the white canvas")
        check("var(--faint)" not in body, "%s: --faint is gone" % name)
        if name.endswith(".js"):
            numeric = re.findall(r"'font-size':\s*\d+\b(?![\d.]*\s*[*+])", body)
            check(not numeric, "%s: SVG text sizes are tokens (found %d numeric)"
                  % (name, len(numeric)))
            # A script setting a CSS radius directly (rather than through
            # app.css) is the same drift a hard-coded hex colour would be.
            # SVG rx/ry (netpath's and netflow's node boxes and legend
            # swatches) are a diagram's own geometry, not this contract, and
            # are exempt on purpose.
            radius = re.findall(r"(?:borderRadius\s*[:=]|'border-radius':)\s*['\"]?[\d.]+px", body)
            check(not radius, "%s: no pixel border-radius set from script (found %s)"
                  % (name, radius[:3] or "none"))

# --------------------------------------------------------------------------
# 5. tokens.css is where it has to be: first on every page, and public.
# The asset URLs carry `?v=__SW_VERSION__`, substituted with the running
# version as the file is loaded (server.py's static cache) so that a
# year-long immutable cache cannot outlive the release that filled it. These
# checks are about which file is asked for and in what order, so they match
# the path and let the query alone — but the placeholder itself is asserted
# below, because markup that lost it would be served with a literal
# "?v=__SW_VERSION__" and cache the wrong bytes forever.
for page in ("index.html", "login.html", "ssh.html"):
    body = read(STATIC, page)
    check('href="/tokens.css?v=' in body and body.index("tokens.css") < body.index("app.css"),
          "%s links tokens.css before app.css" % page)
    for asset in re.findall(r'(?:src|href)="(/[\w./-]+\.(?:js|css))([^"]*)"', body):
        path, query = asset
        check(query.startswith("?v=__SW_VERSION__"),
              "%s: %s carries the version placeholder (found %r)" % (page, path, query))
server = read(REPO_ROOT, "netpath", "web", "server.py")
check('"/tokens.css"' in server.split("PUBLIC_PATHS")[1].split("}")[0],
      "server.py serves /tokens.css before sign-in")
check('"/boot.js"' in server.split("PUBLIC_PATHS")[1].split("}")[0],
      "server.py serves /boot.js before sign-in (the theme must not flash on the sign-in page)")
boot = read(STATIC, "boot.js")
check("sappiwhere.theme" in boot and "dataset.theme" in boot,
      "boot.js applies the stored theme before first paint")
for page in ("index.html", "login.html", "ssh.html"):
    body = read(STATIC, page)
    check(re.search(r'<script src="/boot\.js\?v=[^"]*"></script>', body),
          "%s loads boot.js blocking, in <head>" % page)
    check('class="brand"' in body and 'class="mark"' in body, "%s carries the wordmark" % page)
    marks = re.findall(r"<svg class=\"mark\".*?</svg>", body, re.S)
    check(marks and not any(re.search(r"#[0-9A-Fa-f]{3,6}\b", m) for m in marks),
          "%s: the inline mark is coloured by the theme, not by hex" % page)

# --------------------------------------------------------------------------
# 6. The landmark and the skip link.
index = re.sub(r"<!--.*?-->", "", read(STATIC, "index.html"), flags=re.S)
check(index.count("<main") == 1, "index.html has exactly one <main>")
check('href="#view"' in index and 'id="view"' in index,
      "the skip link targets the main landmark, not the tab strip")

print()
if failures:
    print("FAILED %d check(s):" % len(failures))
    for message in failures:
        print("  - " + message)
    sys.exit(1)
print("ALL DESIGN-TOKEN CHECKS HOLD")
