"""Visual language for the app: an instrument panel, not a web dashboard.

Addresses, latencies and timestamps are set in monospace because that is the
vernacular of network tooling and because columns of figures should line up.
Chrome stays quiet so the two data views carry the colour.

Every colour here is a copy of one in netpath/web/static/tokens.css, which is
the authority; tests/test_design_tokens.py fails if the two disagree. The
names map one to one: TEXT_MUTED is --muted, LINE is --line, and so on.
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont

BG = QColor("#0E1116")
PANEL = QColor("#151A21")
PANEL_RAISED = QColor("#1B222B")
HAIRLINE = QColor("#2A323D")
GRID = QColor("#222933")

TEXT = QColor("#DCE3EA")
TEXT_MUTED = QColor("#8F9AA7")
# The dimmest tone text may be set in: 4.6:1 on PANEL_RAISED. There is no
# TEXT_FAINT any more — it was 2.5:1 and was being used for prose.
TEXT_DIM = QColor("#848F9C")
# Not text: dividers, grips, the dot of a stopped collector. 3.1:1 on RAISED.
LINE = QColor("#646E7C")
# The fill for "none of this yet" in a chart. 3.05:1 on PANEL.
DATA_NEUTRAL = QColor("#606A78")

ACCENT = QColor("#7AA2F7")
ACCENT_HOVER = QColor("#97B6FF")   # a primary button under the pointer

# The route canvas is light while the rest of the app stays dark, so it needs
# its own palette: the dark one's greys and accents have far too little
# contrast against white to be legible.
CANVAS = QColor("#FFFFFF")
CANVAS_PANEL = QColor("#F4F6F9")
CANVAS_HAIRLINE = QColor("#C9D2DD")
CANVAS_GRID = QColor("#E4E9F0")
CANVAS_TEXT = QColor("#161C24")
CANVAS_TEXT_MUTED = QColor("#55606E")
CANVAS_TEXT_FAINT = QColor("#66707E")
CANVAS_ACCENT = QColor("#2F5FC4")
CANVAS_OK = QColor("#1B7F3B")
CANVAS_WARN = QColor("#9A6510")
CANVAS_FAIL = QColor("#B3261E")
CANVAS_BLOCKED = QColor("#A63D10")

OK = QColor("#3FB950")
WARN = QColor("#E3B341")
FAIL = QColor("#F8544C")
ERROR = QColor("#A371F7")
BLOCKED = QColor("#FF8A65")
OVERRUN = QColor("#4DB6AC")
NODATA = QColor("#1E242D")

STATUS_COLORS = {
    "ok": OK,
    "warn": WARN,
    "fail": FAIL,
    "blocked": BLOCKED,
    "overrun": OVERRUN,
    "error": ERROR,
    "none": NODATA,
}

STATUS_LABELS = {
    "ok": "Healthy",
    "warn": "Degraded",
    "fail": "No reply",
    "blocked": "Refused (ICMP unreachable)",
    "overrun": "Skipped \u2014 previous trace still running",
    "error": "Probe failed",
    "none": "No data",
}

# Categorical palette for stacked flow charts: the same eight hues the web
# NetFlow chart uses (--cat-1 .. --cat-8), chosen for separation under
# protanopia simulation as well as in normal vision, and clear of the status
# green/amber/red, which carry a fixed meaning everywhere else in the app.
# The desktop console had kept its own ten-colour set after the web moved.
SERIES = [
    QColor("#5B8DEB"), QColor("#CF7638"), QColor("#2FA886"), QColor("#B0881A"),
    QColor("#D1609A"), QColor("#4F9A3A"), QColor("#8F76E8"), QColor("#DC5A5A"),
]
SERIES_OTHER = DATA_NEUTRAL


def series_color(index: int) -> QColor:
    return SERIES[index % len(SERIES)]


MONO_FAMILIES = [
    "JetBrains Mono", "SF Mono", "Menlo", "Consolas",
    "DejaVu Sans Mono", "Liberation Mono", "monospace",
]
UI_FAMILIES = [
    "Inter", "SF Pro Text", "Segoe UI", "Ubuntu", "DejaVu Sans", "sans-serif",
]


def mono(size: int = 11, bold: bool = False) -> QFont:
    font = QFont()
    font.setFamilies(MONO_FAMILIES)
    font.setPointSize(size)
    font.setBold(bold)
    return font


def ui_font(size: int = 10, bold: bool = False) -> QFont:
    font = QFont()
    font.setFamilies(UI_FAMILIES)
    font.setPointSize(size)
    font.setBold(bold)
    return font


def status_color(status: str) -> QColor:
    return STATUS_COLORS.get(status, NODATA)


STYLESHEET = f"""
QWidget {{
    background: {BG.name()};
    color: {TEXT.name()};
    font-size: 13px;
}}
/* Labels and check boxes must not paint their own background, or they show as
   dark rectangles when placed on a lighter panel such as a group box. */
QLabel, QCheckBox, QRadioButton {{ background: transparent; }}
QMainWindow::separator {{ background: {HAIRLINE.name()}; width: 1px; height: 1px; }}

QLabel#sectionTitle {{
    color: {TEXT_MUTED.name()};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.4px;
    text-transform: uppercase;
    padding: 2px 0px;
}}
QLabel#stat {{ color: {TEXT.name()}; font-family: "DejaVu Sans Mono", monospace; }}
QLabel#hint {{ color: {TEXT_MUTED.name()}; font-size: 11px; }}

QFrame#card {{
    background: {PANEL.name()};
    border: 1px solid {HAIRLINE.name()};
    border-radius: 6px;
}}

QPushButton {{
    background: {PANEL_RAISED.name()};
    border: 1px solid {HAIRLINE.name()};
    border-radius: 4px;
    padding: 5px 12px;
    color: {TEXT.name()};
}}
QPushButton:hover {{ border-color: {ACCENT.name()}; }}
QPushButton:pressed {{ background: {HAIRLINE.name()}; }}
QPushButton:disabled {{ color: {TEXT_MUTED.name()}; border-color: {GRID.name()}; }}
QPushButton#primary {{ background: {ACCENT.name()}; color: {BG.name()}; border: none; font-weight: 600; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER.name()}; }}

QListWidget {{
    background: {PANEL.name()};
    border: 1px solid {HAIRLINE.name()};
    border-radius: 6px;
    outline: none;
    padding: 4px;
}}
QListWidget::item {{ border-radius: 4px; padding: 2px; color: {TEXT.name()}; }}
QListWidget::item:hover {{ background: {GRID.name()}; }}
/* :!active covers the case where the list has lost focus — clicking the route
   graph does exactly that. Without it Qt falls back to the inactive palette
   and paints the selected row's text nearly black on a dark background. */
QListWidget::item:selected,
QListWidget::item:selected:!active {{
    background: {PANEL_RAISED.name()};
    color: {TEXT.name()};
    border: 1px solid {HAIRLINE.name()};
}}

QComboBox, QSpinBox, QDoubleSpinBox, QLineEdit, QDateTimeEdit {{
    background: {PANEL_RAISED.name()};
    border: 1px solid {HAIRLINE.name()};
    border-radius: 4px;
    padding: 4px 8px;
    selection-background-color: {ACCENT.name()};
    selection-color: {BG.name()};
}}
QComboBox:focus, QSpinBox:focus, QLineEdit:focus, QDateTimeEdit:focus {{
    border-color: {ACCENT.name()};
}}

/* Without explicit geometry Qt sizes the spin buttons from the widget's
   content rect, which the padding above shrinks. The up button ends up with a
   click target smaller than it looks while the down button keeps its area.
   Anchoring both to the border rect and giving them equal height fixes it. */
QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 18px;
    height: 13px;
    margin: 1px 1px 0px 0px;
    border-left: 1px solid {HAIRLINE.name()};
    border-top-right-radius: 3px;
    background: {PANEL_RAISED.name()};
}}
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 18px;
    height: 13px;
    margin: 0px 1px 1px 0px;
    border-left: 1px solid {HAIRLINE.name()};
    border-bottom-right-radius: 3px;
    background: {PANEL_RAISED.name()};
}}
QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background: {HAIRLINE.name()};
}}
QSpinBox::up-button:pressed, QDoubleSpinBox::up-button:pressed,
QSpinBox::down-button:pressed, QDoubleSpinBox::down-button:pressed {{
    background: {ACCENT.name()};
}}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow,
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    width: 7px;
    height: 7px;
}}

/* Module settings buttons: same look wherever they appear. */
QPushButton#moduleSettings {{
    background: {PANEL_RAISED.name()};
    border: 1px solid {ACCENT.name()};
    color: {ACCENT.name()};
    border-radius: 4px;
    padding: 5px 14px;
    font-weight: 600;
}}
QPushButton#moduleSettings:hover {{
    background: {ACCENT.name()};
    color: {BG.name()};
}}
QComboBox QAbstractItemView {{
    background: {PANEL_RAISED.name()};
    border: 1px solid {HAIRLINE.name()};
    selection-background-color: {ACCENT.name()};
    selection-color: {BG.name()};
}}
QCheckBox {{ spacing: 6px; }}

QScrollBar:vertical, QScrollBar:horizontal {{ background: transparent; width: 10px; height: 10px; }}
QScrollBar::handle {{ background: {HAIRLINE.name()}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:hover {{ background: {LINE.name()}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0px; width: 0px; }}

QToolTip {{
    background: {PANEL_RAISED.name()};
    color: {TEXT.name()};
    border: 1px solid {HAIRLINE.name()};
    padding: 6px;
}}
QMenuBar {{ background: {PANEL.name()}; border-bottom: 1px solid {HAIRLINE.name()}; }}
QMenuBar::item {{ padding: 5px 10px; background: transparent; }}
QMenuBar::item:selected {{ background: {PANEL_RAISED.name()}; }}
QMenu {{ background: {PANEL_RAISED.name()}; border: 1px solid {HAIRLINE.name()}; padding: 4px; }}
QMenu::item {{ padding: 5px 20px; border-radius: 3px; }}
QMenu::item:selected {{ background: {ACCENT.name()}; color: {BG.name()}; }}

QStatusBar {{ background: {PANEL.name()}; color: {TEXT_MUTED.name()}; }}
QSplitter::handle {{ background: {BG.name()}; }}

QTabWidget::pane {{ border: none; top: -1px; }}
QTabBar {{ background: {PANEL.name()}; }}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_MUTED.name()};
    padding: 9px 24px;
    margin-right: 2px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 600;
    letter-spacing: 0.8px;
}}
QTabBar::tab:hover {{ color: {TEXT.name()}; }}
QTabBar::tab:selected {{
    color: {TEXT.name()};
    border-bottom: 2px solid {ACCENT.name()};
}}

QTableView {{
    background: {PANEL.name()};
    alternate-background-color: {PANEL_RAISED.name()};
    color: {TEXT.name()};
    border: 1px solid {HAIRLINE.name()};
    border-radius: 6px;
    gridline-color: {GRID.name()};
}}
/* Styling ::item makes Qt paint the cell background itself, which overrides
   alternate-background-color with the default (light) palette entry and leaves
   pale text on a white row. Keeping the item transparent lets the view's own
   alternating colour show through. */
QTableView::item {{ background: transparent; color: {TEXT.name()}; padding: 2px 6px; }}
QTableView::item:selected {{ background: {HAIRLINE.name()}; color: {TEXT.name()}; }}
QHeaderView::section {{
    background: {PANEL_RAISED.name()};
    color: {TEXT_MUTED.name()};
    border: none;
    border-bottom: 1px solid {HAIRLINE.name()};
    padding: 5px 8px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {PANEL_RAISED.name()}; border: none; }}

QGroupBox {{
    background: {PANEL.name()};
    border: 1px solid {HAIRLINE.name()};
    border-radius: 6px;
    margin-top: 18px;
    padding: 12px 14px 12px 14px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 2px;
    padding: 0px 2px;
    color: {TEXT_MUTED.name()};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.2px;
}}
QScrollArea {{ border: none; background: {BG.name()}; }}
QPlainTextEdit {{
    background: {PANEL_RAISED.name()};
    border: 1px solid {HAIRLINE.name()};
    border-radius: 4px;
    padding: 4px;
}}
"""
