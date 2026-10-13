"""Visual tokens and application stylesheet for masq."""

from __future__ import annotations

from PyQt6.QtGui import QColor, QFont, QFontDatabase

COLORS = {
    "base": "#111419",
    "surface": "#181C22",
    "raised": "#20252D",
    "hover": "#272D36",
    "line": "#2C333D",
    "line_hot": "#405064",
    "text": "#E8EDF4",
    "muted": "#8E99A8",
    "faint": "#5F6977",
    "accent": "#4CA7FF",
    "accent_hover": "#70B9FF",
    "accent_dim": "#173754",
    "success": "#58D6A8",
    "warning": "#F2BE62",
    "danger": "#FF6B7A",
    "dns": "#B58CFF",
    "tcp": "#63B3FF",
    "udp": "#5AD6C4",
    "icmp": "#F2BE62",
    "arp": "#FF8E72",
    "other": "#A5AFBC",
}


def mono_family() -> str:
    families = set(QFontDatabase.families())
    for name in ("JetBrains Mono", "IBM Plex Mono", "DejaVu Sans Mono", "Liberation Mono", "Monospace"):
        if name in families:
            return name
    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()


def ui_font(size: int = 10, weight: QFont.Weight = QFont.Weight.Normal) -> QFont:
    font = QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont)
    font.setPointSize(size)
    font.setWeight(weight)
    return font


def mono_font(size: int = 9, weight: QFont.Weight = QFont.Weight.Normal) -> QFont:
    font = QFont(mono_family(), size, weight)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFixedPitch(True)
    return font


def color(name: str) -> QColor:
    return QColor(COLORS[name])


def protocol_color(proto: str) -> QColor:
    key = proto.lower()
    if key in COLORS:
        return QColor(COLORS[key])
    return QColor(COLORS["other"])


def stylesheet() -> str:
    c = COLORS
    mono = mono_family()
    return f"""
    * {{
        selection-background-color: {c['accent_dim']};
        selection-color: {c['text']};
    }}
    QMainWindow, QWidget#Root {{
        background: {c['base']};
        color: {c['text']};
    }}
    QWidget {{
        font-size: 10pt;
    }}
    QFrame#ControlBar, QFrame#LogPanel, QFrame#MetricRail {{
        background: {c['surface']};
        border: 1px solid {c['line']};
        border-radius: 8px;
    }}
    QLabel#Product {{
        color: {c['text']};
        font-size: 15pt;
        font-weight: 700;
        letter-spacing: 1px;
    }}
    QLabel#Eyebrow {{
        color: {c['muted']};
        font-size: 8pt;
        font-weight: 600;
        letter-spacing: 1.2px;
    }}
    QLabel#MetricValue {{
        color: {c['text']};
        font-family: "{mono}";
        font-size: 15pt;
        font-weight: 600;
    }}
    QLabel#MetricLabel, QLabel#SectionMeta {{
        color: {c['muted']};
        font-size: 8pt;
        letter-spacing: .7px;
    }}
    QLabel#SectionTitle {{
        color: {c['text']};
        font-size: 11pt;
        font-weight: 600;
    }}
    QLineEdit {{
        min-height: 34px;
        padding: 0 10px;
        color: {c['text']};
        background: {c['base']};
        border: 1px solid {c['line']};
        border-radius: 6px;
        font-family: "{mono}";
        selection-background-color: {c['accent']};
        selection-color: {c['base']};
    }}
    QLineEdit:hover {{ border-color: {c['line_hot']}; }}
    QLineEdit:focus {{ border: 1px solid {c['accent']}; background: {c['surface']}; }}
    QLineEdit:disabled {{ color: {c['faint']}; background: {c['surface']}; }}
    QPushButton {{
        min-height: 34px;
        padding: 0 15px;
        color: {c['text']};
        background: {c['raised']};
        border: 1px solid {c['line']};
        border-radius: 6px;
        font-weight: 600;
    }}
    QPushButton:hover {{ background: {c['hover']}; border-color: {c['line_hot']}; }}
    QPushButton:pressed {{ background: {c['line']}; }}
    QPushButton:focus {{ border-color: {c['accent']}; }}
    QPushButton:disabled {{ color: {c['faint']}; background: {c['surface']}; border-color: {c['line']}; }}
    QPushButton#Primary {{
        color: #07121D;
        background: {c['accent']};
        border-color: {c['accent']};
    }}
    QPushButton#Primary:hover {{ background: {c['accent_hover']}; border-color: {c['accent_hover']}; }}
    QPushButton#Stop {{ color: {c['danger']}; }}
    QPushButton#Follow:checked {{ color: {c['accent']}; background: {c['accent_dim']}; border-color: {c['accent']}; }}
    QTabWidget::pane {{
        background: {c['surface']};
        border: 1px solid {c['line']};
        border-radius: 8px;
        top: -1px;
    }}
    QTabBar::tab {{
        min-width: 92px;
        min-height: 34px;
        padding: 0 10px;
        color: {c['muted']};
        background: transparent;
        border: none;
        border-bottom: 2px solid transparent;
        font-weight: 600;
    }}
    QTabBar::tab:hover {{ color: {c['text']}; background: {c['surface']}; }}
    QTabBar::tab:selected {{ color: {c['accent']}; border-bottom-color: {c['accent']}; }}
    QTableView {{
        color: {c['text']};
        background: {c['surface']};
        alternate-background-color: #1B2027;
        border: none;
        gridline-color: transparent;
        font-family: "{mono}";
        font-size: 9pt;
    }}
    QTableView::item {{ padding: 5px 7px; border-bottom: 1px solid #222831; }}
    QTableView::item:hover {{ background: {c['hover']}; }}
    QTableView::item:selected {{ background: {c['accent_dim']}; color: {c['text']}; }}
    QHeaderView::section {{
        min-height: 31px;
        padding: 0 7px;
        color: {c['muted']};
        background: {c['raised']};
        border: none;
        border-bottom: 1px solid {c['line']};
        font-size: 8pt;
        font-weight: 600;
    }}
    QTreeWidget, QPlainTextEdit, QTextEdit {{
        color: {c['text']};
        background: {c['surface']};
        border: none;
        font-family: "{mono}";
        font-size: 9pt;
    }}
    QTreeWidget::item {{ min-height: 24px; padding: 1px 5px; }}
    QTreeWidget::item:hover {{ background: {c['hover']}; }}
    QTreeWidget::item:selected {{ background: {c['accent_dim']}; }}
    QSplitter::handle {{ background: {c['line']}; }}
    QSplitter::handle:hover {{ background: {c['accent']}; }}
    QSplitter::handle:vertical {{ height: 3px; }}
    QSplitter::handle:horizontal {{ width: 3px; }}
    QScrollBar:vertical {{ width: 10px; background: {c['base']}; margin: 2px; }}
    QScrollBar:horizontal {{ height: 10px; background: {c['base']}; margin: 2px; }}
    QScrollBar::handle {{ background: {c['line_hot']}; border-radius: 4px; min-height: 30px; min-width: 30px; }}
    QScrollBar::handle:hover {{ background: {c['accent']}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QToolTip {{ color: {c['text']}; background: {c['raised']}; border: 1px solid {c['line_hot']}; padding: 5px; }}
    """
