"""
draugr_themes.py — Theme engine for Draugr UI and reports.

Provides dark (default Draugr) and light themes for both
the Qt GUI and the HTML report output. Theme is persisted
in the Draugr config directory.
"""
import json
import os
from pathlib import Path
from typing import Dict, Any


# ── Theme definitions ────────────────────────────────────────────────
THEMES: Dict[str, Dict[str, str]] = {
    "dark": {
        "name":          "Dark (Draugr)",
        "BG":            "#170909",
        "BG_CARD":       "#1f0d0d",
        "BG_INPUT":      "#290a0a",
        "BG_HOVER":      "#3a1414",
        "BORDER":        "#551e1e",
        "FG":            "#e4ccc8",
        "FG_DIM":        "#7a5c5a",
        "FG_BRIGHT":     "#f0dbd8",
        "ACCENT":        "#cb322c",
        "ACCENT_HOVER":  "#d9645b",
        "GREEN":         "#7a9e6e",
        "BLUE":          "#7a8fa3",
        "YELLOW":        "#c4935a",
        "RED":           "#cb322c",
        "ORANGE":        "#d4722a",
        # Report-specific
        "RPT_BG":        "#170909",
        "RPT_CARD":      "#1f0d0d",
        "RPT_BORDER":    "#551e1e",
        "RPT_FG":        "#e4ccc8",
        "RPT_FG_DIM":    "#7a5c5a",
        "RPT_H1":        "#cb322c",
        "RPT_H2":        "#cb322c",
        "RPT_LINK":      "#7a8fa3",
        "RPT_TH_BG":     "#1f0d0d",
        "RPT_TH_FG":     "#7a5c5a",
        "RPT_ROW_ALT":   "#1a0505",
    },
    "light": {
        "name":          "Light",
        "BG":            "#f8f5f4",
        "BG_CARD":       "#ffffff",
        "BG_INPUT":      "#f0ecea",
        "BG_HOVER":      "#e8e0de",
        "BORDER":        "#d0c0bc",
        "FG":            "#2a1a18",
        "FG_DIM":        "#7a6560",
        "FG_BRIGHT":     "#1a0a08",
        "ACCENT":        "#b02020",
        "ACCENT_HOVER":  "#d03030",
        "GREEN":         "#3a7a2e",
        "BLUE":          "#3a5a8a",
        "YELLOW":        "#8a5a1a",
        "RED":           "#b02020",
        "ORANGE":        "#c04010",
        # Report-specific
        "RPT_BG":        "#ffffff",
        "RPT_CARD":      "#f8f5f4",
        "RPT_BORDER":    "#d0c0bc",
        "RPT_FG":        "#2a1a18",
        "RPT_FG_DIM":    "#7a6560",
        "RPT_H1":        "#b02020",
        "RPT_H2":        "#b02020",
        "RPT_LINK":      "#3a5a8a",
        "RPT_TH_BG":     "#f0ecea",
        "RPT_TH_FG":     "#7a6560",
        "RPT_ROW_ALT":   "#faf7f6",
    },
}

_ACTIVE_THEME: str = "dark"
_PREFS_PATH: Path = Path(os.environ.get(
    "APPDATA" if os.name == "nt" else "HOME", Path.home()
)) / ("Draugr" if os.name == "nt" else ".local/share/Draugr") / "prefs.json"


def _load_prefs() -> Dict[str, Any]:
    try:
        if _PREFS_PATH.exists():
            with open(_PREFS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_prefs(prefs: Dict[str, Any]) -> None:
    try:
        _PREFS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_PREFS_PATH, "w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=2)
    except Exception:
        pass


def get_theme() -> Dict[str, str]:
    """Return the currently active theme dict."""
    return THEMES.get(_ACTIVE_THEME, THEMES["dark"])


def get_theme_name() -> str:
    return _ACTIVE_THEME


def set_theme(name: str) -> bool:
    """Set active theme by name. Returns True if valid."""
    global _ACTIVE_THEME
    if name not in THEMES:
        return False
    _ACTIVE_THEME = name
    prefs = _load_prefs()
    prefs["theme"] = name
    _save_prefs(prefs)
    return True


def load_saved_theme() -> None:
    """Load theme preference from disk on startup."""
    global _ACTIVE_THEME
    prefs = _load_prefs()
    name = prefs.get("theme", "dark")
    if name in THEMES:
        _ACTIVE_THEME = name


def t(key: str, fallback: str = "#888888") -> str:
    """Shorthand: get a colour from the current theme."""
    return get_theme().get(key, fallback)


def report_css_overrides() -> str:
    """
    Return CSS variable overrides for the active theme.
    Injected into HTML reports so they respect the current theme.
    """
    theme = get_theme()
    return f"""
:root {{
    --rpt-bg:       {theme['RPT_BG']};
    --rpt-card:     {theme['RPT_CARD']};
    --rpt-border:   {theme['RPT_BORDER']};
    --rpt-fg:       {theme['RPT_FG']};
    --rpt-fg-dim:   {theme['RPT_FG_DIM']};
    --rpt-h1:       {theme['RPT_H1']};
    --rpt-h2:       {theme['RPT_H2']};
    --rpt-link:     {theme['RPT_LINK']};
    --rpt-th-bg:    {theme['RPT_TH_BG']};
    --rpt-th-fg:    {theme['RPT_TH_FG']};
    --rpt-row-alt:  {theme['RPT_ROW_ALT']};
}}
body        {{ background: var(--rpt-bg); color: var(--rpt-fg); }}
h1          {{ color: var(--rpt-h1); }}
h2          {{ color: var(--rpt-h2); border-left-color: var(--rpt-h2); }}
a           {{ color: var(--rpt-link); }}
table       {{ border-color: var(--rpt-border); }}
th          {{ background: var(--rpt-th-bg); color: var(--rpt-th-fg);
               border-bottom-color: var(--rpt-border); }}
td          {{ border-bottom-color: var(--rpt-row-alt); }}
tr:nth-child(even) td {{ background: var(--rpt-row-alt); }}
.content    {{ background: var(--rpt-bg); }}
.toc        {{ background: var(--rpt-card); border-color: var(--rpt-border); }}
"""


def qt_stylesheet(theme_name: str = "") -> str:
    """
    Return a Qt stylesheet string for the given theme (or current active theme).
    Applied at the QApplication level.
    """
    th = THEMES.get(theme_name or _ACTIVE_THEME, THEMES["dark"])
    return f"""
QWidget {{
    background: {th['BG']};
    color: {th['FG']};
    font-family: 'Segoe UI', sans-serif;
}}
QMainWindow, QDialog {{
    background: {th['BG']};
}}
QFrame {{
    border: none;
}}
QLabel {{
    background: transparent;
    border: none;
}}
QLineEdit, QTextEdit, QPlainTextEdit {{
    background: {th['BG_INPUT']};
    color: {th['FG']};
    border: 1px solid {th['BORDER']};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {th['ACCENT']};
}}
QLineEdit:focus, QTextEdit:focus {{
    border-color: {th['ACCENT']};
}}
QPushButton {{
    background: {th['BG_INPUT']};
    color: {th['FG']};
    border: 1px solid {th['BORDER']};
    border-radius: 6px;
    padding: 6px 14px;
}}
QPushButton:hover {{
    background: {th['BG_HOVER']};
}}
QPushButton:disabled {{
    background: {th['BORDER']};
    color: {th['FG_DIM']};
}}
QComboBox {{
    background: {th['BG_INPUT']};
    color: {th['FG']};
    border: 1px solid {th['BORDER']};
    border-radius: 4px;
    padding: 4px 8px;
}}
QTableWidget {{
    background: {th['BG_CARD']};
    color: {th['FG']};
    gridline-color: {th['BORDER']};
    border: 1px solid {th['BORDER']};
}}
QHeaderView::section {{
    background: {th['BG_INPUT']};
    color: {th['FG_DIM']};
    border: 1px solid {th['BORDER']};
    padding: 5px;
    font-weight: 600;
}}
QScrollBar:vertical {{
    background: {th['BG']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {th['BORDER']};
    border-radius: 4px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {th['ACCENT']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QProgressBar {{
    background: {th['BG_CARD']};
    border: none;
    border-radius: 3px;
}}
QProgressBar::chunk {{
    background: {th['GREEN']};
    border-radius: 3px;
}}
QMenuBar {{
    background: {th['BG']};
    color: {th['FG_DIM']};
    border: none;
}}
QMenuBar::item:selected {{
    background: {th['BG_HOVER']};
    color: {th['FG']};
}}
QMenu {{
    background: {th['BG_CARD']};
    color: {th['FG']};
    border: 1px solid {th['BORDER']};
    border-radius: 6px;
    padding: 4px 0;
}}
QMenu::item:selected {{
    background: {th['BG_HOVER']};
}}
QMenu::separator {{
    height: 1px;
    background: {th['BORDER']};
    margin: 4px 8px;
}}
QCheckBox {{
    color: {th['FG_DIM']};
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {th['BORDER']};
    border-radius: 3px;
    background: {th['BG_INPUT']};
}}
QCheckBox::indicator:checked {{
    background: {th['ACCENT']};
    border-color: {th['ACCENT']};
}}
QSplitter::handle {{
    background: {th['BORDER']};
}}
QTabWidget::pane {{
    border: 1px solid {th['BORDER']};
    background: {th['BG_CARD']};
}}
QTabBar::tab {{
    background: {th['BG']};
    color: {th['FG_DIM']};
    border: 1px solid {th['BORDER']};
    border-bottom: none;
    padding: 6px 16px;
    border-radius: 4px 4px 0 0;
}}
QTabBar::tab:selected {{
    background: {th['BG_CARD']};
    color: {th['FG']};
    border-bottom: 1px solid {th['BG_CARD']};
}}
QTabBar::tab:hover {{
    background: {th['BG_HOVER']};
}}
QToolTip {{
    background: {th['BG_CARD']};
    color: {th['FG']};
    border: 1px solid {th['BORDER']};
    padding: 4px 8px;
    border-radius: 4px;
}}
"""


# Initialise on import
load_saved_theme()
