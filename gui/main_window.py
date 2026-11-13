"""
gui/main_window.py
Main Window for PACS/DICOM Security Assessment Platform.
- Deep obsidian canvas (#05060C, #0A0C18, #0E1222)
- High-contrast editorial typography and monospaced technical indicators
- Sharp architectural electric orange (#FF5500) and cyber cyan (#67E8F9) accents
"""

from __future__ import annotations

import sys
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QDockWidget, QPushButton, QLabel, QAction, QMessageBox, QApplication, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QFont

from gui.theme import apply_theme, ACCENT_ORANGE, ACCENT_CYAN, COLOR_VOID_BG, COLOR_SURFACE_PANEL
from gui.scan_worker import ScanWorker
from gui.dashboard_tab import DashboardTab
from gui.assets_tab import AssetsTab
from gui.target_tab import TargetTab
from gui.assessment_config_tab import AssessmentConfigTab
from gui.live_assessment_tab import LiveAssessmentTab
from gui.findings_tab import FindingsTab
from gui.compliance_tab import ComplianceTab
from gui.reports_tab import ReportsTab
from gui.history_tab import HistoryTab
from db import database as db


class MainWindow(QMainWindow):
    """
    Medical Imaging Cybersecurity Console.
    Preserves 100% of underlying scanning, models, signals, and database logic.
    0: Operations Centre (Dashboard)
    1: Network Discovery (Assets)
    2: Target Repository (Targets)
    3: Assessment Scope (Config)
    4: Enforcement Console (Live Run)
    5: Security Findings (Findings)
    6: Compliance Matrix (Compliance)
    7: Reports & SIEM (Reports)
    8: Audit Registry (History)
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PACS & DICOM Security Assessment Console")
        self.resize(1400, 900)
        self.setMinimumSize(1080, 720)

        # Apply dark theme
        apply_theme(self)

        self.current_worker: ScanWorker | None = None
        self._nav_buttons: list[QPushButton] = []
        self.init_ui()
        self.statusBar().showMessage("SYSTEM STATUS: ONLINE · LOCAL PAC-SEC REPOSITORY ATTACHED")

    def init_ui(self):
        main_central = QWidget()
        main_central.setStyleSheet("background-color: #05060C;")
        self.setCentralWidget(main_central)
        central_layout = QVBoxLayout(main_central)
        central_layout.setContentsMargins(8, 8, 8, 8)

        # -------------------------------------------------------------------
        # Main Tab Widget (9 Workspaces)
        # -------------------------------------------------------------------
        self.tabs = QTabWidget()
        self.dashboard_tab = DashboardTab(self)
        self.assets_tab = AssetsTab(self)
        self.target_tab = TargetTab(self)
        self.config_tab = AssessmentConfigTab(self)
        self.live_tab = LiveAssessmentTab(self)
        self.findings_tab = FindingsTab(self)
        self.compliance_tab = ComplianceTab(self)
        self.reports_tab = ReportsTab(self)
        self.history_tab = HistoryTab(self)

        self.tabs.addTab(self.dashboard_tab, "01 // Operations Centre")
        self.tabs.addTab(self.assets_tab, "02 // Network Discovery")
        self.tabs.addTab(self.target_tab, "03 // Target Repository")
        self.tabs.addTab(self.config_tab, "04 // Assessment Scope")
        self.tabs.addTab(self.live_tab, "05 // Enforcement Console")
        self.tabs.addTab(self.findings_tab, "06 // Security Findings")
        self.tabs.addTab(self.compliance_tab, "07 // Compliance Matrix")
        self.tabs.addTab(self.reports_tab, "08 // Reports & SIEM")
        self.tabs.addTab(self.history_tab, "09 // Audit Registry")

        self.tabs.currentChanged.connect(self._on_tab_changed)
        central_layout.addWidget(self.tabs)

        # -------------------------------------------------------------------
        # Architectural Navigation Dock (Left)
        # -------------------------------------------------------------------
        self.create_sidebar()

        # -------------------------------------------------------------------
        # Minimalist Top Header
        # -------------------------------------------------------------------
        self.create_toolbar()

        # -------------------------------------------------------------------
        # Inter-Tab Signal Wiring (Strictly Preserved)
        # -------------------------------------------------------------------
        self.assets_tab.assess_asset_requested.connect(self._on_asset_assess_requested)
        self.target_tab.target_selected.connect(self._on_target_selected)
        self.config_tab.start_assessment_signal.connect(self.start_assessment)
        self.live_tab.cancel_requested_signal.connect(self.cancel_assessment)
        self.history_tab.view_findings_requested.connect(self._on_view_findings_for_run)
        self.history_tab.generate_report_requested.connect(self._on_generate_report_for_run)

        # Initial active button highlight
        self._update_sidebar_selection(0)

    def create_sidebar(self):
        """Creates the architectural navigation panel."""
        self.sidebar = QDockWidget("Navigation", self)
        self.sidebar.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        self.sidebar.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)

        dock_widget = QWidget()
        dock_widget.setStyleSheet("background-color: #0A0C18; border-right: 1px solid #1E2438;")
        dock_layout = QVBoxLayout(dock_widget)
        dock_layout.setContentsMargins(12, 16, 12, 16)
        dock_layout.setSpacing(4)

        # Brand Identity Header
        brand_frame = QFrame()
        brand_frame.setStyleSheet(
            "background-color: #0E1222; border: 1px solid #1E2438; "
            "border-left: 3px solid #FF5500; border-radius: 6px; padding: 6px;"
        )
        brand_layout = QVBoxLayout(brand_frame)
        brand_layout.setContentsMargins(8, 8, 8, 8)
        brand_layout.setSpacing(2)

        logo_title = QLabel("PACS // DEFENSE")
        logo_title.setStyleSheet(
            "color: #FFFFFF; font-weight: 800; font-size: 13px; "
            "letter-spacing: 1.2px; font-family: 'Inter', sans-serif; border: none; background: transparent;"
        )
        brand_layout.addWidget(logo_title)

        logo_sub = QLabel("Clinical Cyber Defense")
        logo_sub.setStyleSheet("color: #67E8F9; font-size: 10px; font-weight: 600; letter-spacing: 0.6px; border: none; background: transparent;")
        brand_layout.addWidget(logo_sub)

        ver_pill = QLabel("SYSTEM ID: DICOM-ENFORCE-v2.0")
        ver_pill.setStyleSheet("color: #64748B; font-size: 8.5px; font-family: monospace; border: none; background: transparent;")
        brand_layout.addWidget(ver_pill)

        dock_layout.addWidget(brand_frame)
        dock_layout.addSpacing(12)

        nav_title = QLabel("SYSTEM CONSOLE")
        nav_title.setStyleSheet("color: #64748B; font-weight: 700; font-size: 9px; letter-spacing: 1.5px; padding-left: 6px;")
        dock_layout.addWidget(nav_title)

        nav_items = [
            ("01  OPERATIONS CENTRE", 0),
            ("02  NETWORK DISCOVERY", 1),
            ("03  TARGET REPOSITORY", 2),
            ("04  ASSESSMENT SCOPE", 3),
            ("05  ENFORCEMENT CONSOLE", 4),
            ("06  SECURITY FINDINGS", 5),
            ("07  COMPLIANCE MATRIX", 6),
            ("08  REPORTS & SIEM", 7),
            ("09  AUDIT REGISTRY", 8),
        ]

        self._nav_buttons = []
        for text, tab_idx in nav_items:
            btn = QPushButton(text)
            btn.setCheckable(False)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked, idx=tab_idx: self.tabs.setCurrentIndex(idx))
            dock_layout.addWidget(btn)
            self._nav_buttons.append(btn)

        dock_layout.addStretch()

        # Policy & Authorization Badge
        auth_badge = QLabel("POLICY ENFORCED · LIVE\nHIPAA § 164.312 CONFORMANCE\nZERO-PHI RETENTION BOUNDARY")
        auth_badge.setAlignment(Qt.AlignCenter)
        auth_badge.setStyleSheet(
            "color: #64748B; font-size: 8.5px; font-family: monospace; line-height: 1.5; padding: 10px; "
            "border: 1px solid #1E2438; border-radius: 6px; background-color: #070913; font-weight: 600;"
        )
        dock_layout.addWidget(auth_badge)

        self.sidebar.setWidget(dock_widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.sidebar)

    def create_toolbar(self):
        """Creates top quick-action toolbar."""
        toolbar = self.addToolBar("Standard Actions")
        toolbar.setMovable(False)
        toolbar.setStyleSheet("background-color: #05060C; border-bottom: 1px solid #1E2438; spacing: 8px; padding: 6px 14px;")

        new_scan_action = QAction("⚡ RUN ASSESSMENT", self)
        new_scan_action.triggered.connect(self.new_scan)
        toolbar.addAction(new_scan_action)

        toolbar.addSeparator()

        discover_assets_action = QAction("🌐 NETWORK SCOPE", self)
        discover_assets_action.triggered.connect(lambda: self.tabs.setCurrentIndex(1))
        toolbar.addAction(discover_assets_action)

        toolbar.addSeparator()

        refresh_all_action = QAction("🔄 SYNC TELEMETRY", self)
        refresh_all_action.triggered.connect(self.refresh_all_views)
        toolbar.addAction(refresh_all_action)

        toolbar.addSeparator()

        about_action = QAction("ℹ️ SYSTEM IDENTITY", self)
        about_action.triggered.connect(self.show_about)
        toolbar.addAction(about_action)

        spacer = QWidget()
        spacer.setSizePolicy(QWidget().sizePolicy().Expanding, QWidget().sizePolicy().Preferred)
        toolbar.addWidget(spacer)

        # Live Status Pill
        status_badge = QLabel("  ● CONSOLE LIVE: MONITORED  ")
        status_badge.setStyleSheet(
            "background-color: rgba(103, 232, 249, 0.1); color: #67E8F9; border: 1px solid #1E2438; "
            "border-radius: 12px; font-weight: 700; font-size: 9.5px; font-family: monospace; padding: 4px 10px;"
        )
        toolbar.addWidget(status_badge)

    def _on_tab_changed(self, index: int):
        self._update_sidebar_selection(index)

    def _update_sidebar_selection(self, active_index: int):
        for idx, btn in enumerate(self._nav_buttons):
            if idx == active_index:
                btn.setStyleSheet("""
                    QPushButton {
                        text-align: left;
                        padding: 9px 12px;
                        font-size: 11px;
                        font-weight: 700;
                        font-family: monospace;
                        letter-spacing: 0.5px;
                        border-radius: 4px;
                        background-color: #0E1222;
                        border: 1px solid #2B334E;
                        border-left: 3px solid #FF5500;
                        color: #FFFFFF;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        text-align: left;
                        padding: 9px 12px;
                        font-size: 11px;
                        font-weight: 500;
                        font-family: monospace;
                        letter-spacing: 0.5px;
                        border-radius: 4px;
                        background-color: transparent;
                        border: 1px solid transparent;
                        color: #94A3B8;
                    }
                    QPushButton:hover {
                        background-color: #141A2E;
                        border: 1px solid #1E2438;
                        color: #FFFFFF;
                    }
                """)

    def new_scan(self):
        """Safely navigates to Assessment Config tab."""
        self.tabs.setCurrentIndex(3)
        self.statusBar().showMessage("Configure assessment scope and parameters.")

    def refresh_all_views(self):
        """Refreshes all data-backed tabs."""
        self.dashboard_tab.refresh_metrics()
        self.assets_tab.load_inventory()
        self.target_tab.load_targets()
        self.findings_tab.refresh_findings()
        self.compliance_tab.refresh_compliance()
        self.reports_tab.refresh_assessments()
        self.history_tab.refresh_history()
        self.statusBar().showMessage("Telemetry synchronized with local security database.")

    def start_assessment(self, config: dict):
        """Instantiates background QThread ScanWorker and starts non-blocking scan."""
        if self.current_worker and self.current_worker.isRunning():
            QMessageBox.warning(self, "Assessment in Progress", "An assessment is already actively running.")
            return

        host = config.get("host")
        port = config.get("port", 104)
        called_ae = config.get("called_ae", "ANY-SCP")
        calling_ae = config.get("calling_ae", "PACSSCANNER")
        timeout = config.get("timeout", 15)

        self.current_worker = ScanWorker(
            host=host,
            port=port,
            called_ae=called_ae,
            calling_ae=calling_ae,
            timeout=timeout,
            parent=self
        )

        # Connect Worker Signals to Live Tab and Window slots
        self.current_worker.progress_signal.connect(self.live_tab.on_progress_updated)
        self.current_worker.status_signal.connect(self.live_tab.on_status_updated)
        self.current_worker.finding_signal.connect(self.live_tab.on_finding_discovered)
        self.current_worker.service_signal.connect(self.live_tab.on_service_discovered)
        self.current_worker.finished_signal.connect(self._on_scan_finished)
        self.current_worker.error_signal.connect(self._on_scan_error)

        # Notify Live tab & Switch to it
        self.live_tab.on_assessment_started(host, port)
        self.tabs.setCurrentIndex(4)  # Switch to Live tab

        self.current_worker.start()
        self.statusBar().showMessage(f"Active assessment executing against {host}:{port}…")

    def cancel_assessment(self):
        """Requests cooperative graceful cancellation from worker."""
        if self.current_worker and self.current_worker.isRunning():
            self.current_worker.request_cancel()
            self.statusBar().showMessage("Cancellation signal delivered to assessment thread…")

    def _on_scan_finished(self, normal_completion: bool):
        self.live_tab.on_assessment_finished(normal_completion)
        self.refresh_all_views()
        if normal_completion:
            self.statusBar().showMessage("Assessment completed. Audit results committed to database.")
            QMessageBox.information(
                self,
                "Assessment Complete",
                "The clinical security assessment has completed.\n"
                "Results are now available in Security Findings, Compliance Matrix, and Reports."
            )
        else:
            self.statusBar().showMessage("Assessment stopped.")

    def _on_scan_error(self, err_msg: str):
        self.statusBar().showMessage("Assessment halted due to error.")
        QMessageBox.critical(self, "Scan Engine Error", f"Assessment stopped with error:\n{err_msg}")

    def _on_asset_assess_requested(self, asset_dict: dict):
        """Loads selected asset from asset inventory into Assessment Config tab."""
        target_data = {
            "name": asset_dict.get("device_type", "PACS Asset"),
            "host": asset_dict.get("ip", "127.0.0.1"),
            "port": 104,
            "called_ae": "ANY-SCP",
            "notes": f"Discovered asset: {asset_dict.get('vendor', 'Unknown')}"
        }
        open_ports = asset_dict.get("open_ports", [])
        for p in [4242, 104, 11112, 11114, 2762]:
            if p in open_ports:
                target_data["port"] = p
                break
        self.config_tab.set_target(target_data)
        self.tabs.setCurrentIndex(3)
        self.statusBar().showMessage(f"Loaded asset {target_data['host']}:{target_data['port']} into Assessment Scope.")

    def _on_target_selected(self, target_data: dict):
        self.config_tab.set_target(target_data)
        self.tabs.setCurrentIndex(3)
        self.statusBar().showMessage(f"Loaded target {target_data.get('host')}:{target_data.get('port')} into Assessment Scope.")

    def _on_view_findings_for_run(self, aid: int):
        self.tabs.setCurrentIndex(5)
        idx = self.findings_tab.assessment_combo.findData(aid)
        if idx >= 0:
            self.findings_tab.assessment_combo.setCurrentIndex(idx)
        self.statusBar().showMessage(f"Viewing findings for Assessment Run #{aid}.")

    def _on_generate_report_for_run(self, aid: int):
        self.tabs.setCurrentIndex(7)
        idx = self.reports_tab.assessment_combo.findData(aid)
        if idx >= 0:
            self.reports_tab.assessment_combo.setCurrentIndex(idx)
        self.statusBar().showMessage(f"Prepared reporting scope for Assessment Run #{aid}.")

    def show_about(self):
        about_text = (
            "<h2>PACS DEFENSE</h2>"
            "<p><b>Design:</b> Architectural Cybersecurity Console</p>"
            "<p><b>Version:</b> 2.0 (Enterprise Suite)</p>"
            "<p>Specialized medical device cybersecurity assessment platform engineered for "
            "evaluating PACS, VNA, DICOM modalities, and DICOMweb endpoints against HIPAA Security Rule, "
            "NIST CSF 2.0, NIST SP 800-53, IEC 80001-1, and DICOM PS 3.15 standards.</p>"
            "<p><b>Engines:</b> pynetdicom 3.x, pydicom 3.x, python-nmap, ReportLab platypus, SQLite3.</p>"
            "<hr/>"
            "<p><font color='#FF5500'><b>Non-destructive:</b> Zero patient health data collection. Pure protocol inspection.</font></p>"
        )
        QMessageBox.about(self, "System Identity", about_text)
