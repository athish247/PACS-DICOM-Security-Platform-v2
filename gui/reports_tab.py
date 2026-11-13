"""
gui/reports_tab.py
Reporting Workspace for PACS/DICOM Security Assessment Platform.
- Editorial typography ("DOCUMENT THE GAP. DELIVER THE EVIDENCE.")
- Monospaced technical export triggers (PDF / CSV / SIEM)
- Deep obsidian & void surfaces (#05060C, #0E1222, razor-thin borders #1E2438)
- High-contrast live HTML executive terminal preview
- 100% preservation of ReportLab PDF generation, CSV, and SIEM exports
"""

from __future__ import annotations

import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QCheckBox, QPushButton, QTextEdit, QGroupBox, QFileDialog,
    QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from db import database as db
from models.findings import (
    AssessmentResult, AssessmentTarget, Finding, DicomService,
    Severity, Confidence, FindingType
)
from reports.pdf_generator import generate_pdf_report
from reports.csv_exporter import CSVExporter
from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class ReportsTab(QWidget):
    """
    Report generation and compliance document interface.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.refresh_assessments()

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

        main_title = QLabel("DOCUMENT THE GAP. DELIVER THE EVIDENCE.")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        main_title.setFont(title_font)
        main_title.setStyleSheet("color: #FFFFFF; font-weight: 900; letter-spacing: 1.2px;")
        title_box.addWidget(main_title)

        sub_title = QLabel("ENTERPRISE AUDIT & REPORT GENERATION // PDF · CSV · SIEM (CEF / LEEF / JSON)")
        sub_title.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;")
        title_box.addWidget(sub_title)

        header_layout.addLayout(title_box)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # -------------------------------------------------------------------
        # Scope & Document Options
        # -------------------------------------------------------------------
        config_group = QGroupBox("AUDIT RUN & DOCUMENT EXPORT CONFIGURATION")
        config_layout = QVBoxLayout(config_group)
        config_layout.setContentsMargins(14, 14, 14, 14)
        config_layout.setSpacing(12)

        # Assessment Run Selector
        run_layout = QHBoxLayout()
        lbl_run = QLabel("SELECT ASSESSMENT:")
        lbl_run.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        run_layout.addWidget(lbl_run)

        self.assessment_combo = QComboBox()
        self.assessment_combo.currentIndexChanged.connect(self._on_assessment_selected)
        run_layout.addWidget(self.assessment_combo, 2)

        self.refresh_btn = QPushButton("↺ REFRESH RUNS")
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
                padding: 7px 14px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2B334D;
                border-color: #FF5500;
            }
        """)
        self.refresh_btn.clicked.connect(self.refresh_assessments)
        run_layout.addWidget(self.refresh_btn)
        config_layout.addLayout(run_layout)

        # Report Type and Anonymization
        opts_layout = QHBoxLayout()
        lbl_type = QLabel("DOCUMENT TYPE:")
        lbl_type.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        opts_layout.addWidget(lbl_type)

        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems([
            "Full Assessment Report (Executive + Technical)",
            "Executive Summary Report",
            "Technical Findings Report",
            "Compliance Evidence Report (Auditors)"
        ])
        opts_layout.addWidget(self.report_type_combo, 2)

        self.anonymize_check = QCheckBox("Anonymize Hostnames / IPs (e.g. SYSTEM-01)")
        self.anonymize_check.setChecked(False)
        self.anonymize_check.setStyleSheet("""
            QCheckBox {
                color: #94A3B8;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 10px;
                font-weight: 600;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 14px;
                height: 14px;
                border: 1px solid #1E2438;
                border-radius: 3px;
                background-color: #070913;
            }
            QCheckBox::indicator:checked {
                background-color: #FF5500;
                border-color: #FF5500;
            }
        """)
        opts_layout.addWidget(self.anonymize_check, 1)

        config_layout.addLayout(opts_layout)
        layout.addWidget(config_group)

        # -------------------------------------------------------------------
        # Generation Action Buttons
        # -------------------------------------------------------------------
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.generate_pdf_btn = QPushButton("📄 GENERATE PDF AUDIT REPORT")
        self.generate_pdf_btn.setCursor(Qt.PointingHandCursor)
        self.generate_pdf_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF5500;
                color: #FFFFFF;
                border: none;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 800;
                font-size: 11px;
                letter-spacing: 1.2px;
                padding: 10px 22px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #E04B00;
            }
        """)
        self.generate_pdf_btn.clicked.connect(self.generate_pdf)
        btn_layout.addWidget(self.generate_pdf_btn)

        self.export_csv_btn = QPushButton("📊 EXPORT CSV FINDINGS")
        self.export_csv_btn.setCursor(Qt.PointingHandCursor)
        self.export_csv_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E2438;
                color: #FFFFFF;
                border: 1px solid #2B334D;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 1px;
                padding: 10px 18px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2B334D;
                border-color: #FF5500;
            }
        """)
        self.export_csv_btn.clicked.connect(self.export_csv)
        btn_layout.addWidget(self.export_csv_btn)

        self.export_siem_btn = QPushButton("🛡️ EXPORT SIEM (CEF / JSON / LEEF)")
        self.export_siem_btn.setCursor(Qt.PointingHandCursor)
        self.export_siem_btn.setStyleSheet("""
            QPushButton {
                background-color: #082F49;
                color: #67E8F9;
                border: 1px solid #0284C7;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 1px;
                padding: 10px 18px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0C4A6E;
                border-color: #38BDF8;
            }
        """)
        self.export_siem_btn.clicked.connect(self.export_siem)
        btn_layout.addWidget(self.export_siem_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # -------------------------------------------------------------------
        # Live Report Preview Pane (Dark Terminal)
        # -------------------------------------------------------------------
        preview_group = QGroupBox("DOCUMENT EXECUTIVE PREVIEW")
        preview_layout = QVBoxLayout(preview_group)
        preview_layout.setContentsMargins(14, 14, 14, 14)

        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setStyleSheet("""
            QTextEdit {
                background-color: #070913;
                color: #E2E8F0;
                border: 1px solid #1E2438;
                border-radius: 4px;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 11px;
                line-height: 1.6;
                padding: 14px;
            }
        """)
        preview_layout.addWidget(self.preview_text)
        layout.addWidget(preview_group, 1)

    def refresh_assessments(self):
        """Populates assessment selector with completed assessments from DB."""
        self.assessment_combo.blockSignals(True)
        self.assessment_combo.clear()
        try:
            assessments = db.get_all_assessments()
            for a in assessments:
                aid = a.get("id")
                host = a.get("target_host", "unknown")
                port = a.get("target_port", 104)
                start = str(a.get("start_time", ""))[:19]
                status = str(a.get("status", "")).upper()
                self.assessment_combo.addItem(f"ASSESSMENT #{aid} // {host}:{port} [{status}] ({start})", aid)
        except Exception:
            pass
        self.assessment_combo.blockSignals(False)

        if self.assessment_combo.count() > 0:
            self._on_assessment_selected(0)
        else:
            self.preview_text.setHtml("<p style='color:#64748B;'><i>No assessment records available. Run an assessment to generate audit documents.</i></p>")

    def _on_assessment_selected(self, index: int):
        aid = self.assessment_combo.currentData()
        if aid is None:
            return

        try:
            assessment = db.get_assessment(aid)
            findings = db.get_findings_for_assessment(aid)
            counts = db.get_finding_counts_for_assessment(aid)
            services = db.get_services_for_assessment(aid)

            host = assessment.get("target_host", "N/A")
            port = assessment.get("target_port", 104)
            start = assessment.get("start_time", "N/A")
            end = assessment.get("end_time", "N/A")

            preview_html = f"""
            <h3 style="color: #FFFFFF; font-family: 'IBM Plex Mono', monospace; letter-spacing: 1px; margin-bottom: 4px;">
                PACS / DICOM SECURITY ASSESSMENT REPORT — RUN #{aid}
            </h3>
            <p style="color: #67E8F9; font-size: 11px; font-family: 'IBM Plex Mono', monospace;">
                <b>TARGET NODE:</b> {host}:{port} &nbsp;&nbsp;|&nbsp;&nbsp;
                <b>AUDIT WINDOW:</b> {start} → {end}
            </p>
            <hr style="border: 0; border-top: 1px solid #1E2438; margin: 10px 0;"/>
            <h4 style="color: #FF5500; font-family: 'IBM Plex Mono', monospace; margin-bottom: 8px;">
                RISK FINDINGS BREAKDOWN // DISCOVERED PROTOCOL GAPS
            </h4>
            <p style="font-family: 'IBM Plex Mono', monospace; font-size: 11px;">
                <span style="background-color:#4C0519; color:#FDA4AF; border:1px solid #E11D48; padding:3px 8px; border-radius:3px; font-weight:bold;">CRITICAL: {counts.get('Critical', 0)}</span> &nbsp;
                <span style="background-color:#7C2D12; color:#FDBA74; border:1px solid #EA580C; padding:3px 8px; border-radius:3px; font-weight:bold;">HIGH: {counts.get('High', 0)}</span> &nbsp;
                <span style="background-color:#78350F; color:#FDE68A; border:1px solid #D97706; padding:3px 8px; border-radius:3px; font-weight:bold;">MEDIUM: {counts.get('Medium', 0)}</span> &nbsp;
                <span style="background-color:#064E3B; color:#6EE7B7; border:1px solid #059669; padding:3px 8px; border-radius:3px; font-weight:bold;">LOW: {counts.get('Low', 0)}</span> &nbsp;
                <span style="background-color:#1E1B4B; color:#A5B4FC; border:1px solid #4338CA; padding:3px 8px; border-radius:3px; font-weight:bold;">INFORMATIONAL: {counts.get('Informational', 0)}</span>
            </p>
            <h4 style="color: #67E8F9; font-family: 'IBM Plex Mono', monospace; margin-top: 14px;">
                DISCOVERED CLINICAL DICOM SERVICES: {len(services)}
            </h4>
            """

            if findings:
                preview_html += "<h4 style='color:#FFFFFF; font-family: IBM Plex Mono, monospace;'>KEY DETECTED SECURITY OBSERVATIONS:</h4><ol style='color:#E2E8F0; font-family: IBM Plex Mono, monospace; font-size: 11px;'>"
                for f in findings[:6]:
                    sev = f.get('severity', 'Info')
                    preview_html += f"<li><b>[{sev}]</b> {f.get('title')} — <span style='color:#67E8F9;'>{f.get('service')}</span></li>"
                if len(findings) > 6:
                    preview_html += f"<li><i style='color:#94A3B8;'>…and {len(findings) - 6} additional findings indexed in database.</i></li>"
                preview_html += "</ol>"
            else:
                preview_html += "<p style='color:#6EE7B7; font-family: IBM Plex Mono, monospace;'><i>No high-risk vulnerabilities identified for this assessment.</i></p>"

            self.preview_text.setHtml(preview_html)
        except Exception as e:
            self.preview_text.setPlainText(f"Error loading assessment preview: {e}")

    def _build_assessment_result_from_db(self, aid: int) -> AssessmentResult:
        """Constructs an AssessmentResult model from SQLite database tables."""
        assessment = db.get_assessment(aid)
        if not assessment:
            raise ValueError(f"Assessment ID {aid} not found in database.")

        findings_rows = db.get_findings_for_assessment(aid)
        services_rows = db.get_services_for_assessment(aid)

        target = AssessmentTarget(
            host=assessment.get("target_host", "unknown"),
            port=assessment.get("target_port", 104),
            called_ae="ANY-SCP",
            calling_ae="PACSSCANNER",
            timeout=30,
            authorized=True,
            notes="Assessment retrieved from database."
        )

        findings = []
        for r in findings_rows:
            findings.append(Finding(
                title=r.get("title", ""),
                severity=Severity(r.get("severity", "Informational")),
                host=r.get("host", ""),
                port=int(r.get("port", 0)),
                service=r.get("service", ""),
                evidence=r.get("evidence", ""),
                detection_method=r.get("detection_method", ""),
                confidence=Confidence(r.get("confidence", "Medium")),
                finding_type=FindingType(r.get("finding_type", "VULNERABILITY")),
                cve_id=r.get("cve_id"),
                cvss_score=r.get("cvss_score"),
                remediation=r.get("remediation"),
            ))

        services = []
        for s in services_rows:
            services.append(DicomService(
                host=s.get("host", ""),
                port=int(s.get("port", 104)),
                ae_response=s.get("ae_response"),
                echo_success=bool(s.get("echo_success")),
                tls_capable=bool(s.get("tls_capable")),
                response_ms=s.get("response_ms"),
            ))

        start_time = datetime.utcnow()
        if assessment.get("start_time"):
            try:
                start_time = datetime.fromisoformat(assessment["start_time"][:19])
            except Exception:
                pass

        end_time = datetime.utcnow()
        if assessment.get("end_time"):
            try:
                end_time = datetime.fromisoformat(assessment["end_time"][:19])
            except Exception:
                pass

        return AssessmentResult(
            target=target,
            start_time=start_time,
            end_time=end_time,
            findings=findings,
            services_discovered=services,
            scan_modules_run=["pynetdicom", "nmap", "tls", "cve", "auth"],
            errors=[]
        )

    def generate_pdf(self):
        aid = self.assessment_combo.currentData()
        if aid is None:
            QMessageBox.warning(self, "No Selection", "Please select an assessment to generate report.")
            return

        default_filename = f"pacs_security_report_run_{aid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path, _ = QFileDialog.getSaveFileName(self, "Save PDF Report", default_filename, "PDF Files (*.pdf)")
        if not path:
            return

        try:
            result = self._build_assessment_result_from_db(aid)
            type_idx = self.report_type_combo.currentIndex()
            report_type_str = "full" if type_idx == 0 else "executive" if type_idx == 1 else "technical"
            anonymize = self.anonymize_check.isChecked()

            out_path = generate_pdf_report(
                result=result,
                output_path=path,
                report_type=report_type_str,
                anonymize=anonymize
            )

            db.log_audit_event("PDF_REPORT_GENERATED", f"assessment_id={aid} path={out_path} anonymized={anonymize}")
            QMessageBox.information(self, "Report Created", f"Security report successfully generated at:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "PDF Generation Error", f"Failed to generate report: {e}")

    def export_csv(self):
        aid = self.assessment_combo.currentData()
        if aid is None:
            QMessageBox.warning(self, "No Selection", "Please select an assessment to export.")
            return

        default_filename = f"pacs_findings_run_{aid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV Findings", default_filename, "CSV Files (*.csv)")
        if not path:
            return

        try:
            result = self._build_assessment_result_from_db(aid)
            CSVExporter.export_to_file(result.findings, path)
            db.log_audit_event("CSV_EXPORTED", f"assessment_id={aid} path={path}")
            QMessageBox.information(self, "Export Complete", f"Findings successfully exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "CSV Export Error", f"Failed to export CSV: {e}")

    def export_siem(self):
        aid = self.assessment_combo.currentData()
        if aid is None:
            QMessageBox.warning(self, "No Selection", "Please select an assessment to export.")
            return

        default_filename = f"pacs_siem_events_run_{aid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cef"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export SIEM Events", default_filename,
            "CEF Log Format (*.cef);;JSON Format (*.json);;LEEF Format (*.leef)"
        )
        if not path:
            return

        try:
            from reports.siem_exporter import SIEMExporter
            raw_findings = db.get_findings_for_assessment(aid)
            fmt = "json" if path.endswith(".json") else "leef" if path.endswith(".leef") else "cef"
            SIEMExporter.export_to_file(raw_findings, path, format_type=fmt)
            db.log_audit_event("SIEM_EXPORTED", f"assessment_id={aid} path={path} format={fmt}")
            QMessageBox.information(self, "SIEM Export Complete", f"Enterprise SIEM events ({fmt.upper()}) successfully exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "SIEM Export Error", f"Failed to export SIEM events: {e}")
