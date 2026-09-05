"""The design tokens hold what tokens.css says they hold.

tokens.css writes a contrast ratio beside every tone. This recomputes each
one from the hex values, so a token cannot be nudged for taste and quietly
fall under the AA floor the comment still claims. It also keeps the desktop
console's copy of the palette (netpath/theme.py) equal to the web's, and
asserts the two things the token file exists to make impossible: a hex
colour or a pixel font size written anywhere else, and the retired --faint
tone coming back under its old name.
"""

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


tokens_css = read(STATIC, "tokens.css")
# One dict per block: the bare :root is the dark default, and each
# :root[data-theme="…"] block is a set of overrides on top of it. The pairs
# below are then measured for every theme, each with its own overrides
# applied over the base — so a dark tone a theme forgot to redefine is
# measured against that theme's light ground and fails, instead of being
# invisible in a browser.
BLOCKS = re.findall(r':root(?:\[data-theme="([a-z]+)"\])?\s*\{(.*?)\n\}', tokens_css, re.S)
check(len(BLOCKS) == 3, "tokens.css has a base block and two theme blocks (found %d)" % len(BLOCKS))
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
check(sorted(THEMES) == ["contrast", "dark", "light"], "the themes are dark, light and contrast")
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
check("color-scheme: light" in OVERRIDES.get("light", {}).get("color-scheme", "")
      or "color-scheme: light" in tokens_css.split('[data-theme="light"]')[1],
      "the light theme declares color-scheme: light")


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
]
# High contrast is held to AAA: 7:1 for text, 4.5:1 for a line or a ring.
FLOOR_LIFT = {"dark": (0.0, 0.0), "light": (0.0, 0.0), "contrast": (2.5, 1.5)}
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
# 2. The desktop console carries the same values.
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
# 3. Nothing else writes a value the tokens own.
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
check("table { width: 100%; border-collapse: collapse; font-family: var(--ui);" in APP_CSS
      and "td.mono" in APP_CSS, "tables are proportional with mono opt-in per column")
space_uses = sum(APP_CSS.count("var(%s)" % name) for name in SPACE_STEPS)
check(space_uses > 50, "app.css actually uses the spacing scale (%d references)" % space_uses)
check("var(--radius-pill)" in APP_CSS, "app.css uses --radius-pill for the half-height shapes")

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
# 4. tokens.css is where it has to be: first on every page, and public.
for page in ("index.html", "login.html", "ssh.html"):
    body = read(STATIC, page)
    check('href="/tokens.css"' in body and body.index("tokens.css") < body.index("app.css"),
          "%s links tokens.css before app.css" % page)
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
    check('<script src="/boot.js"></script>' in body, "%s loads boot.js blocking, in <head>" % page)
    check('class="brand"' in body and 'class="mark"' in body, "%s carries the wordmark" % page)
    marks = re.findall(r"<svg class=\"mark\".*?</svg>", body, re.S)
    check(marks and not any(re.search(r"#[0-9A-Fa-f]{3,6}\b", m) for m in marks),
          "%s: the inline mark is coloured by the theme, not by hex" % page)

# --------------------------------------------------------------------------
# 5. The landmark and the skip link.
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
