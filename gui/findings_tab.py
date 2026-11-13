"""
gui/findings_tab.py
Vulnerability Findings Tab for PACS/DICOM Security Assessment Platform.
- Monospaced classification tags
- High-contrast verdict indicators (CRITICAL / HIGH / MEDIUM / LOW)
- Dark architectural modal with raw DIMSE PDU & HTTP payload evidence
- Automated configuration hardening diff inspection
"""

from __future__ import annotations

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem,
    QDialog, QTextEdit, QHeaderView, QGroupBox, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from db import database as db
from reports.csv_exporter import CSVExporter
from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class FindingDetailDialog(QDialog):
    """
    Modal Dialog displaying in-depth technical evidence,
    CVSS metrics vector, and vendor-aware configuration diffs.
    """

    def __init__(self, finding: dict, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.setWindowTitle(f"TECHNICAL FINDING: {finding.get('title', 'Security Finding')}")
        self.setMinimumSize(740, 560)
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("background-color: #05060C; color: #FFFFFF;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        # Header Title (Editorial Style)
        title_label = QLabel(self.finding.get("title", ""))
        font = QFont()
        font.setPointSize(13)
        font.setBold(True)
        title_label.setFont(font)
        title_label.setStyleSheet("color: #FFFFFF; font-weight: 800; letter-spacing: 0.5px;")
        layout.addWidget(title_label)

        # Meta pills
        meta_layout = QHBoxLayout()
        meta_layout.setSpacing(8)

        sev = self.finding.get("severity", "Informational")
        sev_label = QLabel(f"SEVERITY // {sev.upper()}")
        if sev == "Critical":
            sev_style = "background-color: rgba(239,68,68,0.15); color: #EF4444; border: 1px solid #7F1D1D;"
        elif sev == "High":
            sev_style = "background-color: rgba(255,85,0,0.15); color: #FF5500; border: 1px solid #9A3412;"
        elif sev == "Medium":
            sev_style = "background-color: rgba(245,158,11,0.15); color: #F59E0B; border: 1px solid #78350F;"
        elif sev == "Low":
            sev_style = "background-color: rgba(56,189,248,0.15); color: #38BDF8; border: 1px solid #075985;"
        else:
            sev_style = "background-color: #0E1222; color: #94A3B8; border: 1px solid #1E2438;"

        sev_label.setStyleSheet(f"{sev_style} font-weight: 700; font-family: monospace; padding: 4px 10px; border-radius: 4px; font-size: 10px;")
        meta_layout.addWidget(sev_label)

        cvss = self.finding.get("cvss_score")
        cvss_str = f"CVSS // {cvss:.1f}" if cvss is not None else "CVSS // UNASSIGNED"
        cvss_label = QLabel(cvss_str)
        cvss_label.setStyleSheet("background-color: #0E1222; color: #67E8F9; padding: 4px 10px; border-radius: 4px; border: 1px solid #1E2438; font-family: monospace; font-weight: 700; font-size: 10px;")
        meta_layout.addWidget(cvss_label)

        cve = self.finding.get("cve_id")
        cve_str = f"CVE // {cve}" if cve else "CVE // N/A"
        cve_label = QLabel(cve_str)
        cve_label.setStyleSheet("background-color: #0E1222; color: #FF5500; padding: 4px 10px; border-radius: 4px; border: 1px solid #1E2438; font-family: monospace; font-weight: 700; font-size: 10px;")
        meta_layout.addWidget(cve_label)

        fid = self.finding.get("finding_id", "FIND-UNKNOWN")
        fid_label = QLabel(f"ID // {fid}")
        fid_label.setStyleSheet("background-color: #0E1222; color: #94A3B8; padding: 4px 10px; border-radius: 4px; border: 1px solid #1E2438; font-family: monospace; font-weight: 600; font-size: 10px;")
        meta_layout.addWidget(fid_label)

        meta_layout.addStretch()
        layout.addLayout(meta_layout)

        # Target & Method Details
        info_group = QGroupBox("TARGET NODE & PROTOCOL ATTRIBUTES")
        info_layout = QVBoxLayout(info_group)
        host = self.finding.get("host", "")
        port = self.finding.get("port", "")
        svc = self.finding.get("service", "")
        method = self.finding.get("detection_method", "")
        conf = self.finding.get("confidence", "Medium")

        info_text = (
            f"<b>Target Endpoint:</b> <span style='color:#67E8F9;'>{host}:{port}</span> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Service:</b> {svc}<br/>"
            f"<b>Detection Method:</b> {method} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Confidence:</b> {conf}"
        )
        lbl = QLabel(info_text)
        lbl.setStyleSheet("font-size: 11px; font-family: monospace; line-height: 1.5; color: #CBD5E1;")
        info_layout.addWidget(lbl)
        layout.addWidget(info_group)

        # Technical Evidence Box
        ev_group = QGroupBox("OBSERVED PROTOCOL EVIDENCE // PDU STREAM CAPTURE")
        ev_layout = QVBoxLayout(ev_group)
        self.evidence_text = QTextEdit()
        self.evidence_text.setReadOnly(True)
        self.evidence_text.setPlainText(self.finding.get("evidence", "No raw evidence captured."))
        self.evidence_text.setStyleSheet(
            "background-color: #070913; color: #67E8F9; "
            "font-family: 'IBM Plex Mono', Consolas, monospace; font-size: 11px; "
            "border: 1px solid #1E2438; border-radius: 4px; padding: 8px;"
        )
        ev_layout.addWidget(self.evidence_text)
        layout.addWidget(ev_group, 2)

        # Remediation & Configuration Diff Box
        rem_group = QGroupBox("VENDOR HARDENING BLUEPRINT // CONFIGURATION DIFF")
        rem_layout = QVBoxLayout(rem_group)
        self.rem_text = QTextEdit()
        self.rem_text.setReadOnly(True)
        rem_content = self.finding.get("remediation", "")
        if self.finding.get("remediation_config"):
            rem_content += "\n\n--- RECOMMENDED CONFIGURATION DIFF ---\n" + self.finding.get("remediation_config")
        self.rem_text.setPlainText(rem_content or "No remediation specified.")
        self.rem_text.setStyleSheet(
            "background-color: #070913; font-family: 'IBM Plex Mono', Consolas, monospace; "
            "font-size: 11px; color: #FF5500; border: 1px solid #1E2438; border-radius: 4px; padding: 8px;"
        )
        rem_layout.addWidget(self.rem_text)
        layout.addWidget(rem_group, 2)

        # Analyst Investigation & Finding Lifecycle
        invest_group = QGroupBox("GOVERNANCE LIFECYCLE & ANALYST ATTESTATION")
        invest_layout = QHBoxLayout(invest_group)

        invest_layout.addWidget(QLabel("Status:"))
        self.status_combo = QComboBox()
        self.status_combo.addItems(["Open", "Confirmed", "False Positive", "Risk Accepted", "Resolved"])
        current_status = self.finding.get("status", "Open")
        idx = self.status_combo.findText(current_status)
        if idx >= 0:
            self.status_combo.setCurrentIndex(idx)
        invest_layout.addWidget(self.status_combo)

        invest_layout.addWidget(QLabel("Notes:"))
        self.notes_input = QLineEdit(self.finding.get("analyst_notes", ""))
        self.notes_input.setPlaceholderText("Add verification comments, risk acceptance rationale…")
        invest_layout.addWidget(self.notes_input, 2)

        self.save_status_btn = QPushButton("SAVE STATUS")
        self.save_status_btn.setCursor(Qt.PointingHandCursor)
        self.save_status_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF5500, stop:1 #FF7A1A);
                color: #FFFFFF;
                font-family: monospace;
                font-weight: 700;
                border: none;
                padding: 6px 14px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #E54600;
            }
        """)
        self.save_status_btn.clicked.connect(self._on_save_status)
        invest_layout.addWidget(self.save_status_btn)

        layout.addWidget(invest_group)

        # Close Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("CLOSE")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet("padding: 7px 18px; font-weight: 600; font-family: monospace;")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _on_save_status(self):
        new_status = self.status_combo.currentText()
        notes = self.notes_input.text()
        fid = self.finding.get("finding_id")
        if fid:
            db.update_finding_status(fid, new_status, notes)
            self.finding["status"] = new_status
            self.finding["analyst_notes"] = notes
            QMessageBox.information(self, "Status Saved", f"Finding {fid} marked as '{new_status}'.")


class FindingsTab(QWidget):
    """
    Searchable, filterable list of all discovered security findings.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_findings: list[dict] = []
        self.init_ui()
        self.refresh_findings()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # -------------------------------------------------------------------
        # Filter Bar
        # -------------------------------------------------------------------
        filter_group = QGroupBox("FILTER CLASSIFIED FINDINGS // MULTI-CRITERIA SCOPE")
        filter_layout = QHBoxLayout(filter_group)
        filter_layout.setSpacing(10)

        filter_layout.addWidget(QLabel("Assessment Run:"))
        self.assessment_combo = QComboBox()
        self.assessment_combo.addItem("All Recorded Assessments", None)
        self.assessment_combo.currentIndexChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.assessment_combo, 2)

        filter_layout.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Informational"])
        self.severity_combo.currentIndexChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.severity_combo, 1)

        filter_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter title, host, service, CVE…")
        self.search_input.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.search_input, 2)

        self.refresh_btn = QPushButton("🔄 SYNC")
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.clicked.connect(self.refresh_findings)
        filter_layout.addWidget(self.refresh_btn)

        layout.addWidget(filter_group)

        # -------------------------------------------------------------------
        # Findings Tree Table
        # -------------------------------------------------------------------
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["SEVERITY", "FINDING TITLE", "STATUS", "TARGET HOST", "PORT", "SERVICE", "CVSS", "CVE", "CONFIDENCE"])
        self.tree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.tree, 1)

        # Action Bar
        action_layout = QHBoxLayout()
        self.count_label = QLabel("Showing 0 findings")
        self.count_label.setStyleSheet("color: #64748B; font-size: 11px; font-family: monospace; font-weight: 600;")
        action_layout.addWidget(self.count_label)

        action_layout.addStretch()

        self.view_btn = QPushButton("🔍 INSPECT EVIDENCE")
        self.view_btn.setCursor(Qt.PointingHandCursor)
        self.view_btn.clicked.connect(self._view_selected)
        action_layout.addWidget(self.view_btn)

        self.export_csv_btn = QPushButton("📊 EXPORT FINDINGS (CSV)")
        self.export_csv_btn.setCursor(Qt.PointingHandCursor)
        self.export_csv_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF5500, stop:1 #FF7A1A);
                color: #FFFFFF;
                font-family: monospace;
                font-weight: 700;
                border: none;
                padding: 7px 18px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #E54600;
            }
        """)
        self.export_csv_btn.clicked.connect(self._export_csv)
        action_layout.addWidget(self.export_csv_btn)

        layout.addLayout(action_layout)

    def refresh_findings(self):
        """Reloads assessments dropdown and full findings list from SQLite."""
        self._populate_assessment_dropdown()
        self.apply_filter()

    def _populate_assessment_dropdown(self):
        current_data = self.assessment_combo.currentData()
        self.assessment_combo.blockSignals(True)
        self.assessment_combo.clear()
        self.assessment_combo.addItem("All Recorded Assessments", None)

        try:
            assessments = db.get_all_assessments()
            for a in assessments:
                aid = a.get("id")
                host = a.get("target_host", "unknown")
                port = a.get("target_port", 104)
                start = str(a.get("start_time", ""))[:19]
                self.assessment_combo.addItem(f"Run #{aid:04d} — {host}:{port} ({start})", aid)
        except Exception:
            pass

        if current_data is not None:
            idx = self.assessment_combo.findData(current_data)
            if idx >= 0:
                self.assessment_combo.setCurrentIndex(idx)
        self.assessment_combo.blockSignals(False)

    def apply_filter(self):
        """Applies dropdown and search filters against DB records."""
        self.tree.clear()
        selected_aid = self.assessment_combo.currentData()
        sev_filter = self.severity_combo.currentText()
        query = self.search_input.text().strip().lower()

        try:
            if selected_aid is not None:
                findings = db.get_findings_for_assessment(selected_aid)
            else:
                findings = db.get_all_findings()
        except Exception:
            findings = []

        self._current_findings = findings
        displayed = 0

        for f in findings:
            sev = f.get("severity", "Informational")
            title = f.get("title", "")
            host = f.get("host", "")
            port = str(f.get("port", ""))
            svc = f.get("service", "")
            cve = f.get("cve_id", "") or "N/A"
            cvss = f"{f.get('cvss_score', 0):.1f}" if f.get('cvss_score') is not None else "N/A"
            conf = f.get("confidence", "Medium")

            if sev_filter != "All Severities" and sev != sev_filter:
                continue

            if query:
                combined = f"{title} {host} {port} {svc} {cve}".lower()
                if query not in combined:
                    continue

            status = f.get("status", "Open")
            verdict_badge = f"[{sev.upper()}]"
            item = QTreeWidgetItem([
                verdict_badge,
                title,
                status,
                host,
                port,
                svc,
                cvss,
                cve,
                conf
            ])
            item.setData(0, Qt.UserRole, f)

            # Semantic Colors
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

            self.tree.addTopLevelItem(item)
            displayed += 1

        self.count_label.setText(f"INDEXED: {displayed} of {len(findings)} technical finding(s)")

    def _on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        finding_data = item.data(0, Qt.UserRole)
        if finding_data:
            dlg = FindingDetailDialog(finding_data, self)
            dlg.exec_()

    def _view_selected(self):
        item = self.tree.currentItem()
        if item:
            self._on_item_double_clicked(item, 0)
        else:
            QMessageBox.information(self, "Selection Required", "Please select a finding from the table to view.")

    def _export_csv(self):
        if not self._current_findings:
            QMessageBox.warning(self, "No Data", "No findings available to export.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Findings to CSV", "dicom_assessment_findings.csv", "CSV Files (*.csv)")
        if not path:
            return

        try:
            from models.findings import Finding, Severity, Confidence, FindingType
            finding_objects = []
            for d in self._current_findings:
                finding_objects.append(Finding(
                    title=d.get("title", ""),
                    severity=Severity(d.get("severity", "Informational")),
                    host=d.get("host", ""),
                    port=int(d.get("port", 0)),
                    service=d.get("service", ""),
                    evidence=d.get("evidence", ""),
                    detection_method=d.get("detection_method", ""),
                    confidence=Confidence(d.get("confidence", "Medium")),
                    finding_type=FindingType(d.get("finding_type", "VULNERABILITY")),
                    cve_id=d.get("cve_id"),
                    cvss_score=d.get("cvss_score"),
                    remediation=d.get("remediation"),
                ))

            CSVExporter.export_to_file(finding_objects, path)
            QMessageBox.information(self, "Export Complete", f"Successfully exported findings to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSV: {e}")
