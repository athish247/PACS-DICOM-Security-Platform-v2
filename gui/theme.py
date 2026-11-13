"""
gui/theme.py
Design System for PACS/DICOM Cybersecurity Platform.

- Architectural Obsidian & Deep Void surfaces (#05060C, #0A0C18, #0E1222)
- High-contrast editorial typography (Inter, Outfit, IBM Plex Mono)
- Razor-sharp technical borders (#1E2438, rgba(255,255,255,0.08))
- Electric Orange (#FF5500) and Cyber Cyan (#67E8F9) accents
- Minimalist technical telemetry cards & live console styling
"""

from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import Qt

# ---------------------------------------------------------------------------
# Color Palette Tokens
# ---------------------------------------------------------------------------
COLOR_VOID_BG        = "#05060C"  # Deepest canvas void
COLOR_SURFACE_PANEL  = "#0A0C18"  # Sidebar, toolbar, dock backgrounds
COLOR_SURFACE_CARD   = "#0E1222"  # Elevated cards, inspection panels
COLOR_SURFACE_INPUT  = "#070913"  # Recessed terminal & input fields
COLOR_SURFACE_HOVER  = "#141A2E"  # Card and item hover state

COLOR_BORDER_DEFAULT = "#1E2438"  # Subtle geometric dividing line
COLOR_BORDER_LIGHT   = "#2B334E"  # Focused / elevated border
COLOR_BORDER_ORANGE  = "#FF5500"  # Active accent border
COLOR_BORDER_CYAN    = "#22D3EE"  # Verified protocol border

COLOR_TEXT_PRIMARY   = "#FFFFFF"  # High-contrast title and editorial text
COLOR_TEXT_SECONDARY = "#94A3B8"  # Technical metadata and descriptions
COLOR_TEXT_MUTED     = "#64748B"  # Timestamps, minor labels
COLOR_TEXT_DIM       = "#475569"  # Disabled / inactive labels

# Signature Accents
ACCENT_ORANGE        = "#FF5500"  # Electric Orange
ACCENT_ORANGE_HOVER  = "#FF6B1A"
ACCENT_CYAN          = "#67E8F9"  # Cyber Cyan (live state, verified protocol)
ACCENT_MINT          = "#6EE7B7"  # Clean green for passed / allowed verdicts
ACCENT_CRIMSON       = "#EF4444"  # Critical vulnerability / denied verdict
ACCENT_AMBER         = "#F59E0B"  # Medium / warning status

# Backward-compatibility color constants
PRIMARY_ORANGE   = ACCENT_ORANGE
SECONDARY_ORANGE = ACCENT_ORANGE_HOVER
LIGHT_ORANGE     = "#1A1010"
PURE_WHITE       = COLOR_TEXT_PRIMARY
BG_MAIN          = COLOR_VOID_BG
BG_CARD          = COLOR_SURFACE_CARD
DARK_TEXT        = COLOR_TEXT_PRIMARY
SECONDARY_TEXT   = COLOR_TEXT_SECONDARY

# ---------------------------------------------------------------------------
# Master Dark QSS Stylesheet
# ---------------------------------------------------------------------------
DARK_STYLESHEET = """
    * {
        font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", "Roboto", "Helvetica Neue", sans-serif;
    }

    /* Tooltips */
    QToolTip {
        color: #FFFFFF;
        background-color: #0E1222;
        border: 1px solid #FF5500;
        padding: 6px 10px;
        border-radius: 4px;
        font-size: 11px;
    }

    /* Main Window & Base Widget Surfaces */
    QMainWindow {
        background-color: #05060C;
    }

    QWidget {
        background-color: transparent;
        color: #FFFFFF;
    }

    /* Tab Navigation (Top Bar) */
    QTabWidget::pane {
        border: 1px solid #1E2438;
        background-color: #05060C;
        border-radius: 6px;
        top: -1px;
    }

    QTabBar::tab {
        background-color: #0A0C18;
        color: #94A3B8;
        padding: 10px 18px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        min-width: 100px;
        font-weight: 600;
        font-size: 11px;
        letter-spacing: 0.5px;
        border: 1px solid #1E2438;
        border-bottom: none;
        margin-right: 3px;
        text-transform: uppercase;
    }

    QTabBar::tab:selected {
        background-color: #0E1222;
        color: #FFFFFF;
        font-weight: 700;
        border: 1px solid #2B334E;
        border-top: 2px solid #FF5500;
        border-bottom: 1px solid #0E1222;
    }

    QTabBar::tab:hover:!selected {
        background-color: #141A2E;
        color: #FF5500;
        border-color: #2B334E;
    }

    /* Architectural Technical Containers (GroupBoxes) */
    QGroupBox {
        background-color: #0A0C18;
        border: 1px solid #1E2438;
        border-radius: 8px;
        margin-top: 14px;
        padding-top: 18px;
        padding-left: 12px;
        padding-right: 12px;
        padding-bottom: 12px;
        color: #FFFFFF;
        font-weight: 700;
        font-size: 11px;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        left: 14px;
        padding: 0 8px;
        color: #67E8F9;
        font-weight: 700;
        font-size: 11px;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        background-color: #0A0C18;
    }

    /* Buttons */
    QPushButton {
        background-color: #0E1222;
        color: #FFFFFF;
        border: 1px solid #1E2438;
        padding: 8px 16px;
        border-radius: 5px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.4px;
    }

    QPushButton:hover {
        background-color: #141A2E;
        border: 1px solid #FF5500;
        color: #FFFFFF;
    }

    QPushButton:pressed {
        background-color: #FF5500;
        color: #FFFFFF;
        border: 1px solid #FF5500;
    }

    QPushButton:disabled {
        background-color: #070913;
        color: #475569;
        border: 1px solid #1E2438;
    }

    /* Technical Input Fields */
    QLineEdit, QSpinBox, QComboBox, QTextEdit, QPlainTextEdit {
        background-color: #070913;
        color: #FFFFFF;
        border: 1px solid #1E2438;
        padding: 7px 10px;
        border-radius: 5px;
        font-size: 12px;
    }

    QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
        border: 1px solid #FF5500;
        background-color: #090C1A;
    }

    QComboBox::drop-down {
        border: none;
        background-color: #0E1222;
        width: 24px;
        border-top-right-radius: 5px;
        border-bottom-right-radius: 5px;
    }

    QComboBox QAbstractItemView {
        background-color: #0A0C18;
        color: #FFFFFF;
        border: 1px solid #1E2438;
        selection-background-color: #141A2E;
        selection-color: #FF5500;
        padding: 4px;
        outline: none;
    }

    /* Tree Views & Technical Data Grids */
    QTreeWidget, QTreeView, QTableWidget, QTableView {
        background-color: #070913;
        color: #E2E8F0;
        border: 1px solid #1E2438;
        border-radius: 6px;
        alternate-background-color: #0A0C18;
        gridline-color: #161A2B;
        font-size: 12px;
        outline: none;
    }

    QTreeWidget::item, QTreeView::item, QTableWidget::item, QTableView::item {
        padding: 7px 8px;
        border-bottom: 1px solid #121524;
    }

    QTreeWidget::item:hover, QTreeView::item:hover, QTableWidget::item:hover, QTableView::item:hover {
        background-color: #141A2E;
        color: #FFFFFF;
    }

    QTreeWidget::item:selected, QTreeView::item:selected, QTableWidget::item:selected, QTableView::item:selected {
        background-color: #1A213B;
        color: #67E8F9;
        font-weight: 600;
    }

    QHeaderView::section {
        background-color: #0A0C18;
        color: #94A3B8;
        padding: 8px 10px;
        border: none;
        border-bottom: 1px solid #1E2438;
        border-right: 1px solid #1E2438;
        font-weight: 700;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    /* Progress Bar */
    QProgressBar {
        border: 1px solid #1E2438;
        border-radius: 5px;
        text-align: center;
        color: #FFFFFF;
        font-weight: bold;
        font-size: 10px;
        background-color: #070913;
        height: 18px;
    }

    QProgressBar::chunk {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF5500, stop:1 #FF7A1A);
        border-radius: 4px;
    }

    /* Minimalist Scrollbars */
    QScrollBar:vertical {
        background: #05060C;
        width: 8px;
        border: none;
        margin: 0;
    }

    QScrollBar::handle:vertical {
        background: #1E2438;
        min-height: 20px;
        border-radius: 4px;
    }

    QScrollBar::handle:vertical:hover {
        background: #FF5500;
    }

    QScrollBar:horizontal {
        background: #05060C;
        height: 8px;
        border: none;
        margin: 0;
    }

    QScrollBar::handle:horizontal {
        background: #1E2438;
        min-width: 20px;
        border-radius: 4px;
    }

    QScrollBar::handle:horizontal:hover {
        background: #FF5500;
    }

    /* Sidebar Dock */
    QDockWidget {
        color: #FFFFFF;
        titlebar-close-icon: none;
    }

    QDockWidget::title {
        background: #0A0C18;
        padding: 8px;
        color: #67E8F9;
        font-weight: bold;
        border-bottom: 1px solid #1E2438;
        font-size: 11px;
        letter-spacing: 0.8px;
    }

    /* Checkbox */
    QCheckBox {
        color: #CBD5E1;
        spacing: 8px;
        font-size: 12px;
        font-weight: 500;
    }

    QCheckBox::indicator {
        width: 15px;
        height: 15px;
        border: 1px solid #2B334E;
        background: #070913;
        border-radius: 3px;
    }

    QCheckBox::indicator:hover {
        border: 1px solid #FF5500;
    }

    QCheckBox::indicator:checked {
        background: #FF5500;
        border: 1px solid #FF5500;
    }

    /* Menu & Toolbar */
    QMenuBar {
        background-color: #05060C;
        color: #FFFFFF;
        border-bottom: 1px solid #1E2438;
    }

    QMenuBar::item:selected {
        background: #141A2E;
        color: #FF5500;
        border-radius: 3px;
    }

    QMenu {
        background-color: #0A0C18;
        color: #FFFFFF;
        border: 1px solid #1E2438;
        border-radius: 6px;
        padding: 6px;
    }

    QMenu::item:selected {
        background-color: #141A2E;
        color: #FF5500;
        border-radius: 3px;
    }

    QStatusBar {
        background-color: #05060C;
        color: #94A3B8;
        border-top: 1px solid #1E2438;
        font-size: 11px;
        padding: 4px 8px;
    }

    QSplitter::handle {
        background: #1E2438;
    }

    QToolBar {
        background-color: #05060C;
        border-bottom: 1px solid #1E2438;
        spacing: 8px;
        padding: 6px 12px;
    }
"""


def apply_palette(app_or_widget):
    """Apply QPalette dark colours matching architectural aesthetic."""
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor(5, 6, 12))
    palette.setColor(QPalette.WindowText,      QColor(255, 255, 255))
    palette.setColor(QPalette.Base,            QColor(7, 9, 19))
    palette.setColor(QPalette.AlternateBase,   QColor(10, 12, 24))
    palette.setColor(QPalette.ToolTipBase,     QColor(14, 18, 34))
    palette.setColor(QPalette.ToolTipText,     QColor(255, 255, 255))
    palette.setColor(QPalette.Text,            QColor(255, 255, 255))
    palette.setColor(QPalette.Button,          QColor(14, 18, 34))
    palette.setColor(QPalette.ButtonText,      QColor(255, 255, 255))
    palette.setColor(QPalette.BrightText,      QColor(239, 68, 68))
    palette.setColor(QPalette.Link,            QColor(103, 232, 249))
    palette.setColor(QPalette.Highlight,       QColor(255, 85, 0))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    palette.setColor(QPalette.Disabled, QPalette.Text,       QColor(100, 116, 139))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(100, 116, 139))
    app_or_widget.setPalette(palette)


def apply_theme(app_or_widget):
    """Applies the master dark theme."""
    apply_palette(app_or_widget)
    app_or_widget.setStyleSheet(DARK_STYLESHEET)


def apply_dark_theme(app_or_widget):
    """Backward compatibility alias."""
    apply_theme(app_or_widget)
