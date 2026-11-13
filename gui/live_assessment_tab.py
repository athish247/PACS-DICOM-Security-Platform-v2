"""
gui/live_assessment_tab.py
Live Assessment Tab for PACS/DICOM Security Assessment Platform.
- Monospaced real-time protocol telemetry stream
- High-contrast verdict pills (ALLOWED / FLAGGED / DENIED)
- Minimalist electric orange progress indicator (#FF5500)
- Deep terminal execution inspection log
"""

from __future__ import annotations

from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QTreeWidget, QTreeWidgetItem, QTextEdit,
    QGroupBox, QHeaderView, QSplitter, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont

from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class LiveAssessmentTab(QWidget):
    """
    Live Enforcement Console displaying real-time DICOM DIMSE transactions,
    active presentation context negotiations, and live vulnerability verdicts.
    """

    cancel_requested_signal = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # -------------------------------------------------------------------
        # Console Header
        # -------------------------------------------------------------------
        prog_group = QGroupBox("THIS IS THE CONSOLE // REAL-TIME ENFORCEMENT STREAM")
        prog_layout = QVBoxLayout(prog_group)
        prog_layout.setSpacing(8)

        self.status_label = QLabel("STANDBY // READY TO INITIATE DICOM PROTOCOL INSPECTION")
        self.status_label.setStyleSheet("font-size: 11px; font-weight: 700; font-family: monospace; color: #67E8F9; letter-spacing: 0.5px;")
        prog_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #1E2438;
                border-radius: 4px;
                text-align: center;
                height: 18px;
                background-color: #070913;
                font-family: monospace;
                font-weight: 700;
                font-size: 10px;
                color: #FFFFFF;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF5500, stop:1 #FF7A1A);
                border-radius: 3px;
            }
        """)
        prog_layout.addWidget(self.progress_bar)

        ctrl_layout = QHBoxLayout()
        self.cancel_btn = QPushButton("🛑 HALT ENFORCEMENT")
        self.cancel_btn.setCursor(Qt.PointingHandCursor)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #EF4444;
                color: #FFFFFF;
                font-weight: 700;
                font-family: monospace;
                padding: 6px 16px;
                border-radius: 4px;
                border: none;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #DC2626;
            }
            QPushButton:disabled {
                background-color: #070913;
                color: #475569;
                border: 1px solid #1E2438;
            }
        """)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        ctrl_layout.addWidget(self.cancel_btn)

        self.clear_btn = QPushButton("CLEAR CONSOLE BUFFER")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #0E1222;
                color: #94A3B8;
                border: 1px solid #1E2438;
                font-family: monospace;
                padding: 6px 14px;
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #141A2E;
                color: #FFFFFF;
                border: 1px solid #FF5500;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_views)
        ctrl_layout.addWidget(self.clear_btn)
        ctrl_layout.addStretch()

        prog_layout.addLayout(ctrl_layout)
        layout.addWidget(prog_group)

        # -------------------------------------------------------------------
        # Splitter: Left = Findings & Services, Right = Execution Log
        # -------------------------------------------------------------------
        splitter = QSplitter(Qt.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)

        # Discovered Services Tree
        services_group = QGroupBox("DISCOVERED DICOM & WEB ENDPOINTS")
        services_layout = QVBoxLayout(services_group)
        self.services_tree = QTreeWidget()
        self.services_tree.setHeaderLabels(["HOST", "PORT", "AE RESPONSE", "C-ECHO", "TLS STATUS", "LATENCY"])
        self.services_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.services_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        services_layout.addWidget(self.services_tree)
        left_layout.addWidget(services_group, 1)

        # Discovered Findings Tree
        findings_group = QGroupBox("REAL-TIME FINDINGS CLASSIFICATION FEED")
        findings_layout = QVBoxLayout(findings_group)
        self.findings_tree = QTreeWidget()
        self.findings_tree.setHeaderLabels(["SEVERITY", "FINDING TITLE", "HOST:PORT", "SERVICE", "DETECTION METHOD"])
        self.findings_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.findings_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        findings_layout.addWidget(self.findings_tree)
        left_layout.addWidget(findings_group, 2)

        splitter.addWidget(left_widget)

        # Execution Log Text Box
        log_group = QGroupBox("LIVE ENFORCEMENT TRANSACTION STREAM")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet(
            "background-color: #070913; color: #67E8F9; "
            "font-family: 'IBM Plex Mono', Consolas, 'Courier New', monospace; font-size: 11px; "
            "border: 1px solid #1E2438; border-radius: 6px; padding: 10px; line-height: 1.4;"
        )
        log_layout.addWidget(self.log_text)

        splitter.addWidget(log_group)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter, 1)

    def on_assessment_started(self, host: str, port: int):
        self.clear_views()
        self.status_label.setText(f"INSPECTING // ENGAGED AGAINST {host}:{port}")
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.append_log(f"[SYS] Assessment stream initiated against {host}:{port}")

    def on_assessment_finished(self, normal_completion: bool):
        self.cancel_btn.setEnabled(False)
        if normal_completion:
            self.status_label.setText("ENFORCEMENT COMPLETE // ALL TRANSACTIONS RECORDED")
            self.progress_bar.setValue(100)
            self.append_log("[✓] Assessment pipeline completed. Audit results committed to database.")
        else:
            self.status_label.setText("INSPECTION HALTED // OPERATOR SIGNAL")
            self.append_log("[!] Assessment pipeline stopped by operator.")

    def on_progress_updated(self, percent: int):
        self.progress_bar.setValue(percent)

    def on_status_updated(self, message: str):
        self.status_label.setText(f"ENFORCEMENT ACTIVE // {message.upper()}")
        self.append_log(f"[*] {message}")

    def on_finding_discovered(self, finding_dict: dict):
        sev = finding_dict.get("severity", "Informational")
        title = finding_dict.get("title", "Unknown Finding")
        host = finding_dict.get("host", "")
        port = finding_dict.get("port", "")
        service = finding_dict.get("service", "")
        method = finding_dict.get("detection_method", "")

        verdict_badge = f"[{sev.upper()}]"
        item = QTreeWidgetItem([
            verdict_badge,
            title,
            f"{host}:{port}",
            service,
            method
        ])

        # Semantic Verdict Coloring
        if sev == "Critical":
            item.setForeground(0, QColor("#EF4444"))
            item.setBackground(0, QColor(239, 68, 68, 25))
        elif sev == "High":
            item.setForeground(0, QColor("#FF5500"))
            item.setBackground(0, QColor(255, 85, 0, 25))
        elif sev == "Medium":
            item.setForeground(0, QColor("#F59E0B"))
            item.setBackground(0, QColor(245, 158, 11, 25))
        elif sev == "Low":
            item.setForeground(0, QColor("#38BDF8"))
            item.setBackground(0, QColor(56, 189, 248, 25))
        else:
            item.setForeground(0, QColor("#94A3B8"))

        self.findings_tree.insertTopLevelItem(0, item)
        self.append_log(f"[{sev.upper()} · LOGGED] {title} on {host}:{port} ({method})")

    def on_service_discovered(self, service_dict: dict):
        host = service_dict.get("host", "")
        port = str(service_dict.get("port", ""))
        ae_resp = service_dict.get("ae_response") or service_dict.get("ae_title_response") or "N/A"
        echo_ok = "ALLOWED" if service_dict.get("echo_success") else "REJECTED"
        tls_ok = "ENCRYPTED" if service_dict.get("tls_capable") else "PLAINTEXT"
        latency = f"{service_dict.get('response_ms', 0):.1f} ms" if service_dict.get('response_ms') is not None else "N/A"

        item = QTreeWidgetItem([
            host,
            port,
            ae_resp,
            f"[{echo_ok}]",
            f"[{tls_ok}]",
            latency
        ])
        if echo_ok == "ALLOWED":
            item.setForeground(3, QColor("#6EE7B7"))
        else:
            item.setForeground(3, QColor("#EF4444"))

        if tls_ok == "ENCRYPTED":
            item.setForeground(4, QColor("#6EE7B7"))
        else:
            item.setForeground(4, QColor("#FF5500"))

        self.services_tree.addTopLevelItem(item)
        self.append_log(f"[ENDPOINT] Port {port} on {host}: C-ECHO={echo_ok}, TLS={tls_ok}")

    def append_log(self, text: str):
        now = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{now}] {text}")
        self.log_text.moveCursor(self.log_text.textCursor().End)

    def clear_views(self):
        self.services_tree.clear()
        self.findings_tree.clear()
        self.log_text.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("STANDBY // READY TO INITIATE DICOM PROTOCOL INSPECTION")

    def _on_cancel_clicked(self):
        self.cancel_btn.setEnabled(False)
        self.status_label.setText("SIGNAL SENT // REQUESTING CANCELLATION…")
        self.cancel_requested_signal.emit()
