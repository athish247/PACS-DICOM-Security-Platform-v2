"""
gui/history_tab.py
Assessment History Workspace for PACS/DICOM Security Assessment Platform.
- Editorial typography ("RECORD THE BREACH BEFORE IT MANIFESTS.")
- Monospaced technical audit trace tables and service footprint inspection
- Deep obsidian & void surfaces (#05060C, #0E1222, razor-thin borders #1E2438)
- Architectural electric orange and cyber cyan action triggers
- 100% preservation of all signals, slots, and SQLite historical queries
"""

from __future__ import annotations

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QGroupBox,
    QMessageBox, QSplitter, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont

from db import database as db
from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class HistoryTab(QWidget):
    """
    Historical assessment audit trail and comparison workspace.
    """

    view_findings_requested = pyqtSignal(int)
    generate_report_requested = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.refresh_history()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # -------------------------------------------------------------------
        # Editorial Header
        # -------------------------------------------------------------------
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        main_title = QLabel("RECORD THE BREACH BEFORE IT MANIFESTS.")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        main_title.setFont(title_font)
        main_title.setStyleSheet("color: #FFFFFF; font-weight: 900; letter-spacing: 1.2px;")
        title_box.addWidget(main_title)

        sub_title = QLabel("HISTORICAL AUDIT REGISTRY // ARCHITECTURAL EVENT TRACE & PERSISTED RUNS")
        sub_title.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;")
        title_box.addWidget(sub_title)

        header_layout.addLayout(title_box)
        header_layout.addStretch()

        self.refresh_btn = QPushButton("↺ REFRESH AUDIT HISTORY")
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E2438;
                color: #FFFFFF;
                border: 1px solid #2B334D;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 1px;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2B334D;
                border-color: #FF5500;
            }
        """)
        self.refresh_btn.clicked.connect(self.refresh_history)
        header_layout.addWidget(self.refresh_btn)
        layout.addLayout(header_layout)

        # Splitter: Top = History List, Bottom = Selected Run Detail
        splitter = QSplitter(Qt.Vertical)

        # -------------------------------------------------------------------
        # Top: Table of Assessments
        # -------------------------------------------------------------------
        hist_group = QGroupBox("HISTORICAL ASSESSMENT AUDIT LOG")
        hist_layout = QVBoxLayout(hist_group)
        hist_layout.setContentsMargins(14, 14, 14, 14)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "ID", "TARGET HOST", "PORT", "START TIME", "COMPLETED",
            "STATUS", "CRITICAL", "HIGH", "MEDIUM", "TOTAL FINDINGS"
        ])
        self.tree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        hist_layout.addWidget(self.tree)
        splitter.addWidget(hist_group)

        # -------------------------------------------------------------------
        # Bottom: Detail & Discovered Services
        # -------------------------------------------------------------------
        detail_group = QGroupBox("SELECTED ASSESSMENT FOOTPRINT & PROTOCOL RESPONSES")
        detail_layout = QVBoxLayout(detail_group)
        detail_layout.setContentsMargins(14, 14, 14, 14)
        detail_layout.setSpacing(10)

        self.detail_label = QLabel("Select an assessment above to inspect its discovered service footprint.")
        self.detail_label.setStyleSheet("font-size: 11px; color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-weight: 600;")
        detail_layout.addWidget(self.detail_label)

        self.services_tree = QTreeWidget()
        self.services_tree.setHeaderLabels(["HOST", "PORT", "AE RESPONSE", "C-ECHO", "TLS CAPABLE", "LATENCY (MS)"])
        self.services_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        detail_layout.addWidget(self.services_tree)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.view_findings_btn = QPushButton("⚡ INSPECT FINDINGS IN WORKSPACE")
        self.view_findings_btn.setCursor(Qt.PointingHandCursor)
        self.view_findings_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF5500;
                color: #FFFFFF;
                border: none;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 800;
                font-size: 11px;
                letter-spacing: 1px;
                padding: 9px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #E04B00;
            }
        """)
        self.view_findings_btn.clicked.connect(self._on_view_findings)
        btn_layout.addWidget(self.view_findings_btn)

        self.report_btn = QPushButton("📄 LOAD INTO REPORTING CONSOLE")
        self.report_btn.setCursor(Qt.PointingHandCursor)
        self.report_btn.setStyleSheet("""
            QPushButton {
                background-color: #082F49;
                color: #67E8F9;
                border: 1px solid #0284C7;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 1px;
                padding: 9px 18px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0C4A6E;
                border-color: #38BDF8;
            }
        """)
        self.report_btn.clicked.connect(self._on_open_report)
        btn_layout.addWidget(self.report_btn)

        btn_layout.addStretch()
        detail_layout.addLayout(btn_layout)
        splitter.addWidget(detail_group)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

    def refresh_history(self):
        self.tree.clear()
        self.services_tree.clear()
        try:
            assessments = db.get_all_assessments()
            for a in assessments:
                aid = a.get("id")
                counts = db.get_finding_counts_for_assessment(aid)
                tot = sum(counts.values())

                item = QTreeWidgetItem([
                    str(aid),
                    str(a.get("target_host", "N/A")),
                    str(a.get("target_port", 104)),
                    str(a.get("start_time", ""))[:19],
                    str(a.get("end_time", "Running…"))[:19] if a.get("end_time") else "Incomplete",
                    f"[{str(a.get('status', 'unknown')).upper()}]",
                    str(counts.get("Critical", 0)),
                    str(counts.get("High", 0)),
                    str(counts.get("Medium", 0)),
                    str(tot)
                ])

                font_mono = QFont("IBM Plex Mono")
                font_mono.setPointSize(9)
                item.setFont(0, font_mono)
                item.setFont(1, font_mono)
                item.setFont(2, font_mono)
                item.setFont(5, font_mono)

                item.setForeground(1, QColor("#67E8F9"))

                if counts.get("Critical", 0) > 0:
                    item.setForeground(6, QColor("#FDA4AF"))
                    item.setBackground(6, QColor("#4C0519"))
                if counts.get("High", 0) > 0:
                    item.setForeground(7, QColor("#FDBA74"))
                    item.setBackground(7, QColor("#7C2D12"))

                item.setData(0, Qt.UserRole, a)
                self.tree.addTopLevelItem(item)
        except Exception:
            pass

    def _on_selection_changed(self):
        item = self.tree.currentItem()
        if not item:
            return

        aid = int(item.text(0))
        self.services_tree.clear()

        try:
            services = db.get_services_for_assessment(aid)
            for s in services:
                echo = "[SUCCESS]" if s.get("echo_success") else "[FAILED]"
                tls = "[ENABLED]" if s.get("tls_capable") else "[DISABLED]"
                lat = f"{s.get('response_ms', 0):.1f} ms" if s.get('response_ms') is not None else "—"
                svc_item = QTreeWidgetItem([
                    str(s.get("host", "")),
                    str(s.get("port", "")),
                    str(s.get("ae_response") or "—"),
                    echo,
                    tls,
                    lat
                ])

                font_mono = QFont("IBM Plex Mono")
                font_mono.setPointSize(9)
                for col in range(6):
                    svc_item.setFont(col, font_mono)

                if s.get("echo_success"):
                    svc_item.setForeground(3, QColor("#6EE7B7"))
                else:
                    svc_item.setForeground(3, QColor("#FDA4AF"))

                if s.get("tls_capable"):
                    svc_item.setForeground(4, QColor("#6EE7B7"))
                else:
                    svc_item.setForeground(4, QColor("#FDE68A"))

                self.services_tree.addTopLevelItem(svc_item)

            self.detail_label.setText(
                f"AUDIT RUN #{aid} // TARGET {item.text(1)}:{item.text(2)} | "
                f"DISCOVERED SERVICES: {len(services)} | STATUS: {item.text(5)}"
            )
        except Exception as e:
            self.detail_label.setText(f"ERROR LOADING SERVICES: {e}")

    def _on_view_findings(self):
        item = self.tree.currentItem()
        if item:
            aid = int(item.text(0))
            self.view_findings_requested.emit(aid)
        else:
            QMessageBox.information(self, "Selection Required", "Please select an assessment run from the table.")

    def _on_open_report(self):
        item = self.tree.currentItem()
        if item:
            aid = int(item.text(0))
            self.generate_report_requested.emit(aid)
        else:
            QMessageBox.information(self, "Selection Required", "Please select an assessment run from the table.")
