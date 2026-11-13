"""
gui/compliance_tab.py
Healthcare Cybersecurity Compliance Centre.
- Large editorial typography ("CONTROL BELONGS IN THE ACTION.")
- Monospaced technical control status badges ([PASSED] / [FAILED] / [EVAL_PENDING])
- Deep obsidian and void card surfaces (#05060C, #0E1222, razor-thin borders #1E2438)
- High-contrast clinical compliance telemetry and interactive evidence inspector
- Strict zero modification of assessment algorithms or database structures
"""

from __future__ import annotations

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QGroupBox, QDialog, QTextEdit, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from db import database as db
from engines.compliance_engine import COMPLIANCE_DISCLAIMER
from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class ComplianceControlDetailDialog(QDialog):
    """
    Technical inspection dialog for regulatory control evaluation.
    """
    def __init__(self, control: dict, parent=None):
        super().__init__(parent)
        self.control = control
        self.setWindowTitle(f"CONTROL AUDIT: {control.get('control_id')} // {control.get('control_title')}")
        self.resize(720, 520)
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0A0C18;
                color: #FFFFFF;
                border: 1px solid #1E2438;
            }
            QLabel {
                color: #E2E8F0;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Title
        title_box = QVBoxLayout()
        title_box.setSpacing(4)
        mono_sub = QLabel(f"FRAMEWORK // {self.control.get('framework', 'CLINICAL')}")
        mono_sub.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', 'Cascadia Code', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1.2px;")
        title_box.addWidget(mono_sub)

        title_lbl = QLabel(f"{self.control.get('control_id')}: {self.control.get('control_title')}")
        f = QFont()
        f.setPointSize(13)
        f.setBold(True)
        title_lbl.setFont(f)
        title_lbl.setStyleSheet("color: #FFFFFF; font-weight: 800; letter-spacing: 0.5px;")
        title_box.addWidget(title_lbl)
        layout.addLayout(title_box)

        # Status Badge Pill
        status = self.control.get("status", "NOT_ASSESSED")
        if status == "PASSED":
            badge_style = "background-color: #064E3B; color: #6EE7B7; border: 1px solid #059669;"
            status_text = "[VERIFIED COMPLIANT]"
        elif status == "FAILED":
            badge_style = "background-color: #4C0519; color: #FDA4AF; border: 1px solid #E11D48;"
            status_text = "[NON-COMPLIANT // REGULATORY BREACH]"
        else:
            badge_style = "background-color: #1E1B4B; color: #A5B4FC; border: 1px solid #4338CA;"
            status_text = "[UNAUDITED // PENDING]"

        status_pill = QLabel(f"EVALUATION STATUS: {status_text}")
        status_pill.setStyleSheet(f"""
            {badge_style}
            font-family: 'IBM Plex Mono', 'Cascadia Code', monospace;
            font-weight: 700;
            font-size: 10px;
            letter-spacing: 1px;
            padding: 6px 14px;
            border-radius: 4px;
        """)
        layout.addWidget(status_pill)

        # Control Description
        lbl_desc = QLabel("CONTROL SPECIFICATION")
        lbl_desc.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1px;")
        layout.addWidget(lbl_desc)

        desc_box = QTextEdit()
        desc_box.setReadOnly(True)
        desc_box.setPlainText(self.control.get("description", ""))
        desc_box.setMaximumHeight(70)
        desc_box.setStyleSheet("""
            background-color: #0E1222;
            color: #E2E8F0;
            border: 1px solid #1E2438;
            border-radius: 4px;
            font-size: 11px;
            padding: 8px;
        """)
        layout.addWidget(desc_box)

        # Technical Evidence (Observed PDU / Protocol trace)
        lbl_ev = QLabel("OBSERVED PROTOCOL & TELEMETRY EVIDENCE")
        lbl_ev.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1px;")
        layout.addWidget(lbl_ev)

        ev_box = QTextEdit()
        ev_box.setReadOnly(True)
        ev_box.setPlainText(self.control.get("evidence", "No technical evidence recorded."))
        ev_box.setStyleSheet("""
            background-color: #05060C;
            color: #67E8F9;
            font-family: 'IBM Plex Mono', 'Cascadia Code', monospace;
            font-size: 11px;
            border: 1px solid #1E2438;
            border-radius: 4px;
            padding: 10px;
        """)
        layout.addWidget(ev_box)

        # Guidance / Remediation
        lbl_rem = QLabel("HARDENING & AUDIT REMEDIATION")
        lbl_rem.setStyleSheet("color: #FF5500; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1px;")
        layout.addWidget(lbl_rem)

        rem_box = QTextEdit()
        rem_box.setReadOnly(True)
        rem_box.setPlainText(self.control.get("remediation_guidance", "Maintain established security controls."))
        rem_box.setMaximumHeight(80)
        rem_box.setStyleSheet("""
            background-color: #0E1222;
            color: #E2E8F0;
            border: 1px solid #1E2438;
            border-radius: 4px;
            font-size: 11px;
            padding: 8px;
        """)
        layout.addWidget(rem_box)

        # Footer Actions
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("DISMISS")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E2438;
                color: #FFFFFF;
                border: 1px solid #2B334D;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 700;
                font-size: 11px;
                padding: 8px 24px;
                border-radius: 4px;
                letter-spacing: 1px;
            }
            QPushButton:hover {
                background-color: #2B334D;
                border-color: #FF5500;
            }
        """)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)


class ComplianceTab(QWidget):
    """
    Dedicated Healthcare Compliance & Regulatory Governance View.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_controls: list[dict] = []
        self.init_ui()
        self.refresh_compliance()

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

        main_title = QLabel("CONTROL BELONGS IN THE ACTION.")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        main_title.setFont(title_font)
        main_title.setStyleSheet("color: #FFFFFF; font-weight: 900; letter-spacing: 1.2px;")
        title_box.addWidget(main_title)

        sub_title = QLabel("HEALTHCARE REGULATORY & CLINICAL ASSURANCE // HIPAA · DICOM PS 3.15 · MDS2 · NIST CSF")
        sub_title.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;")
        title_box.addWidget(sub_title)

        header_layout.addLayout(title_box)
        header_layout.addStretch()

        self.refresh_btn = QPushButton("↺ RE-EVALUATE AUDIT")
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
        self.refresh_btn.clicked.connect(self.refresh_compliance)
        header_layout.addWidget(self.refresh_btn)
        layout.addLayout(header_layout)

        # -------------------------------------------------------------------
        # Architectural Disclaimer Card
        # -------------------------------------------------------------------
        disclaimer_frame = QFrame()
        disclaimer_frame.setStyleSheet("""
            QFrame {
                background-color: #121008;
                border: 1px solid #78350F;
                border-left: 3px solid #F59E0B;
                border-radius: 4px;
                padding: 6px;
            }
        """)
        disc_layout = QVBoxLayout(disclaimer_frame)
        disc_layout.setContentsMargins(10, 8, 10, 8)
        disc_layout.setSpacing(2)

        disc_badge = QLabel("REGULATORY DISCLAIMER // CLINICAL ASSURANCE GATEWAY")
        disc_badge.setStyleSheet("color: #F59E0B; font-family: 'IBM Plex Mono', monospace; font-size: 9px; font-weight: 800; letter-spacing: 1.2px;")
        disc_layout.addWidget(disc_badge)

        disclaimer_lbl = QLabel(COMPLIANCE_DISCLAIMER)
        disclaimer_lbl.setWordWrap(True)
        disclaimer_lbl.setStyleSheet("color: #D1D5DB; font-size: 11px; line-height: 1.4;")
        disc_layout.addWidget(disclaimer_lbl)
        layout.addWidget(disclaimer_frame)

        # -------------------------------------------------------------------
        # Scope Filter & Real-Time Telemetry Bar
        # -------------------------------------------------------------------
        scope_group = QGroupBox("REGULATORY SCOPE & AUDIT CONTROLS")
        scope_layout = QHBoxLayout(scope_group)
        scope_layout.setContentsMargins(14, 14, 14, 14)
        scope_layout.setSpacing(12)

        lbl_scope = QLabel("ASSESSMENT RUN:")
        lbl_scope.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        scope_layout.addWidget(lbl_scope)

        self.assessment_combo = QComboBox()
        self.assessment_combo.currentIndexChanged.connect(self._on_assessment_changed)
        scope_layout.addWidget(self.assessment_combo, 2)

        lbl_fw = QLabel("FRAMEWORK:")
        lbl_fw.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        scope_layout.addWidget(lbl_fw)

        self.framework_combo = QComboBox()
        self.framework_combo.addItems([
            "All Healthcare Frameworks",
            "HIPAA Security Rule",
            "DICOM PS 3.15",
            "MDS2",
            "IHE ATNA",
            "NIST CSF 2.0"
        ])
        self.framework_combo.currentIndexChanged.connect(self._apply_filter)
        scope_layout.addWidget(self.framework_combo, 1)

        # Telemetry Verdict Badges
        self.passed_badge = QLabel("PASSED: 0")
        self.passed_badge.setStyleSheet("""
            background-color: #064E3B;
            color: #6EE7B7;
            border: 1px solid #059669;
            font-family: 'IBM Plex Mono', monospace;
            font-weight: 800;
            font-size: 11px;
            letter-spacing: 1px;
            padding: 6px 14px;
            border-radius: 4px;
        """)
        scope_layout.addWidget(self.passed_badge)

        self.failed_badge = QLabel("NON-COMPLIANT: 0")
        self.failed_badge.setStyleSheet("""
            background-color: #4C0519;
            color: #FDA4AF;
            border: 1px solid #E11D48;
            font-family: 'IBM Plex Mono', monospace;
            font-weight: 800;
            font-size: 11px;
            letter-spacing: 1px;
            padding: 6px 14px;
            border-radius: 4px;
        """)
        scope_layout.addWidget(self.failed_badge)

        layout.addWidget(scope_group)

        # -------------------------------------------------------------------
        # Controls Tree Table
        # -------------------------------------------------------------------
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["VERDICT", "FRAMEWORK", "CONTROL ID", "CONTROL TITLE", "TECHNICAL EVIDENCE SUMMARY", "REMEDIATION GUIDANCE"])
        self.tree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.tree, 1)

    def refresh_compliance(self):
        self._populate_assessments()
        self._load_controls_for_selected()

    def _populate_assessments(self):
        curr = self.assessment_combo.currentData()
        self.assessment_combo.blockSignals(True)
        self.assessment_combo.clear()

        try:
            assessments = db.get_all_assessments()
            for a in assessments:
                aid = a.get("id")
                host = a.get("target_host", "127.0.0.1")
                port = a.get("target_port", 104)
                start = str(a.get("start_time", ""))[:19]
                self.assessment_combo.addItem(f"ASSESSMENT #{aid} // {host}:{port} [{start}]", aid)
        except Exception:
            pass

        if curr is not None:
            idx = self.assessment_combo.findData(curr)
            if idx >= 0:
                self.assessment_combo.setCurrentIndex(idx)
        self.assessment_combo.blockSignals(False)

    def _on_assessment_changed(self):
        self._load_controls_for_selected()

    def _load_controls_for_selected(self):
        aid = self.assessment_combo.currentData()
        if aid is None:
            self.tree.clear()
            self._current_controls = []
            return

        try:
            controls = db.get_compliance_controls_for_assessment(aid)
            self._current_controls = controls
            self._apply_filter()
        except Exception:
            self._current_controls = []
            self.tree.clear()

    def _apply_filter(self):
        self.tree.clear()
        fw_filter = self.framework_combo.currentText()

        passed = 0
        failed = 0

        for c in self._current_controls:
            fw = c.get("framework", "")
            if fw_filter != "All Healthcare Frameworks":
                if fw_filter == "HIPAA Security Rule" and fw != "HIPAA":
                    continue
                if fw_filter == "DICOM PS 3.15" and fw != "DICOM_PS_3_15":
                    continue
                if fw_filter == "MDS2" and fw != "MDS2":
                    continue
                if fw_filter == "IHE ATNA" and fw != "IHE_ATNA":
                    continue
                if fw_filter == "NIST CSF 2.0" and fw != "NIST_CSF_2_0":
                    continue

            status = c.get("status", "NOT_ASSESSED")
            if status == "PASSED":
                passed += 1
            elif status == "FAILED":
                failed += 1

            status_display = f"[{status}]"
            item = QTreeWidgetItem([
                status_display,
                fw,
                c.get("control_id", ""),
                c.get("control_title", ""),
                c.get("evidence", "")[:120],
                c.get("remediation_guidance", "")[:100]
            ])
            item.setData(0, Qt.UserRole, c)

            # High-contrast status color coding
            if status == "PASSED":
                item.setBackground(0, QColor("#064E3B"))
                item.setForeground(0, QColor("#6EE7B7"))
            elif status == "FAILED":
                item.setBackground(0, QColor("#4C0519"))
                item.setForeground(0, QColor("#FDA4AF"))
            else:
                item.setBackground(0, QColor("#1E1B4B"))
                item.setForeground(0, QColor("#A5B4FC"))

            font_mono = QFont("IBM Plex Mono")
            font_mono.setPointSize(9)
            font_mono.setBold(True)
            item.setFont(0, font_mono)
            item.setFont(2, font_mono)

            self.tree.addTopLevelItem(item)

        self.passed_badge.setText(f"PASSED: {passed}")
        self.failed_badge.setText(f"NON-COMPLIANT: {failed}")

    def _on_item_double_clicked(self, item: QTreeWidgetItem, col: int):
        data = item.data(0, Qt.UserRole)
        if data:
            dlg = ComplianceControlDetailDialog(data, self)
            dlg.exec_()
