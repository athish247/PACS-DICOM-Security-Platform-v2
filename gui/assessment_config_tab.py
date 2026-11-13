"""
gui/assessment_config_tab.py
Assessment Configuration Workspace for PACS/DICOM Security Assessment Platform.
- Editorial typography ("DEFINED PROTOCOLS. RIGOROUS BOUNDARIES.")
- Deep obsidian & void surfaces (#05060C, #0E1222, razor-thin borders #1E2438)
- Architectural electric orange launch triggers (#FF5500)
- Monospaced technical parameters (Host, Port, AE, Timeout)
- Clinical safety guardrail callout in dark amber obsidian
- Strict 100% preservation of all signals, configuration dictionary schema, and modules
"""

from __future__ import annotations

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSpinBox, QCheckBox, QGroupBox, QComboBox,
    QFileDialog, QMessageBox, QFrame
)
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor

from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class AssessmentConfigTab(QWidget):
    """
    Configures module execution, timeouts, scan intensity, and initiates assessments.
    """

    start_assessment_signal = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

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

        main_title = QLabel("DEFINED PROTOCOLS. RIGOROUS BOUNDARIES.")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        main_title.setFont(title_font)
        main_title.setStyleSheet("color: #FFFFFF; font-weight: 900; letter-spacing: 1.2px;")
        title_box.addWidget(main_title)

        sub_title = QLabel("SECURITY ASSESSMENT ORCHESTRATION // 8 ENTERPRISE DICOM & PACS ENGINES")
        sub_title.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;")
        title_box.addWidget(sub_title)

        header_layout.addLayout(title_box)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # -------------------------------------------------------------------
        # Target Scope Summary Card
        # -------------------------------------------------------------------
        scope_group = QGroupBox("ASSESSMENT TARGET SCOPE")
        scope_layout = QHBoxLayout(scope_group)
        scope_layout.setContentsMargins(14, 14, 14, 14)
        scope_layout.setSpacing(12)

        lbl_host = QLabel("TARGET HOST:")
        lbl_host.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        scope_layout.addWidget(lbl_host)

        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 12px;")
        scope_layout.addWidget(self.host_input, 2)

        lbl_port = QLabel("DICOM PORT:")
        lbl_port.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        scope_layout.addWidget(lbl_port)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(104)
        self.port_spin.setStyleSheet("font-family: 'IBM Plex Mono', monospace;")
        scope_layout.addWidget(self.port_spin, 1)

        lbl_called = QLabel("CALLED AE:")
        lbl_called.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        scope_layout.addWidget(lbl_called)

        self.called_ae_input = QLineEdit("ANY-SCP")
        self.called_ae_input.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 12px;")
        scope_layout.addWidget(self.called_ae_input, 1)

        lbl_calling = QLabel("CALLING AE:")
        lbl_calling.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        scope_layout.addWidget(lbl_calling)

        self.calling_ae_input = QLineEdit("PACSSCANNER")
        self.calling_ae_input.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 12px;")
        scope_layout.addWidget(self.calling_ae_input, 1)

        layout.addWidget(scope_group)

        # -------------------------------------------------------------------
        # Assessment Profile & Modules
        # -------------------------------------------------------------------
        profile_group = QGroupBox("ASSESSMENT PROFILE & STAGES")
        profile_layout = QVBoxLayout(profile_group)
        profile_layout.setContentsMargins(14, 14, 14, 14)
        profile_layout.setSpacing(12)

        prof_sel_layout = QHBoxLayout()
        lbl_prof = QLabel("ASSESSMENT PROFILE:")
        lbl_prof.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        prof_sel_layout.addWidget(lbl_prof)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems([
            "Comprehensive PACS Assessment (All 8 Engines)",
            "Standard Security Audit (Recommended)",
            "Quick Port & C-ECHO Verification",
            "Custom Module Selection"
        ])
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        prof_sel_layout.addWidget(self.profile_combo, 2)

        lbl_timeout = QLabel("TIMEOUT (S):")
        lbl_timeout.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        prof_sel_layout.addWidget(lbl_timeout)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(2, 60)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setStyleSheet("font-family: 'IBM Plex Mono', monospace;")
        prof_sel_layout.addWidget(self.timeout_spin, 1)
        profile_layout.addLayout(prof_sel_layout)

        # Module Checkboxes (8 Enterprise Stages)
        mod_group = QGroupBox("ACTIVE PROTOCOL & COMPLIANCE ENGINES")
        mod_layout = QVBoxLayout(mod_group)
        mod_layout.setContentsMargins(12, 12, 12, 12)
        mod_layout.setSpacing(8)

        check_style = """
            QCheckBox {
                color: #E2E8F0;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 11px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 15px;
                height: 15px;
                border: 1px solid #1E2438;
                border-radius: 3px;
                background-color: #070913;
            }
            QCheckBox::indicator:checked {
                background-color: #FF5500;
                border-color: #FF5500;
            }
        """

        self.mod_net = QCheckBox("01 // Network Port & Service Fingerprinting (Nmap / socket detection)")
        self.mod_net.setChecked(True)
        self.mod_net.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_net)

        self.mod_dicom = QCheckBox("02 // DICOM Verification SOP Class (C-ECHO Protocol Handshake)")
        self.mod_dicom.setChecked(True)
        self.mod_dicom.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_dicom)

        self.mod_assoc = QCheckBox("03 // Application Entity (AE) Title Whitelisting & Boundary Enforcement")
        self.mod_assoc.setChecked(True)
        self.mod_assoc.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_assoc)

        self.mod_adv_dicom = QCheckBox("04 // Advanced Presentation Contexts (CT/MR Storage, Worklist) & Transfer Syntaxes")
        self.mod_adv_dicom.setChecked(True)
        self.mod_adv_dicom.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_adv_dicom)

        self.mod_dicomweb = QCheckBox("05 // DICOMweb REST API Security (QIDO, WADO, STOW, CORS, Cookie Flags)")
        self.mod_dicomweb.setChecked(True)
        self.mod_dicomweb.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_dicomweb)

        self.mod_tls = QCheckBox("06 // Cryptographic Guardrails (TLS 1.2/1.3, Cipher Suites, Certificate Integrity)")
        self.mod_tls.setChecked(True)
        self.mod_tls.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_tls)

        self.mod_cve = QCheckBox("07 // Vulnerability Intelligence & Curated PACS CVE Correlation (NVD / CISA KEV)")
        self.mod_cve.setChecked(True)
        self.mod_cve.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_cve)

        self.mod_compliance = QCheckBox("08 // Healthcare Compliance Intelligence & Hardening Blueprint (HIPAA/NIST/MDS2)")
        self.mod_compliance.setChecked(True)
        self.mod_compliance.setStyleSheet(check_style)
        mod_layout.addWidget(self.mod_compliance)

        # Optional DICOM Metadata analysis
        meta_layout = QHBoxLayout()
        meta_layout.setSpacing(8)
        self.mod_meta = QCheckBox("09 // DICOM Metadata Privacy Audit (PHI Tag Identification):")
        self.mod_meta.setChecked(False)
        self.mod_meta.setStyleSheet(check_style)
        meta_layout.addWidget(self.mod_meta)

        self.dicom_file_path = QLineEdit()
        self.dicom_file_path.setPlaceholderText("Path to synthetic or authorized DICOM test file (.dcm)")
        self.dicom_file_path.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 11px;")
        meta_layout.addWidget(self.dicom_file_path, 2)

        self.browse_btn = QPushButton("BROWSE…")
        self.browse_btn.setCursor(Qt.PointingHandCursor)
        self.browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E2438;
                color: #FFFFFF;
                border: 1px solid #2B334D;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 10px;
                font-weight: 700;
                padding: 6px 14px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2B334D;
                border-color: #FF5500;
            }
        """)
        self.browse_btn.clicked.connect(self._browse_dicom_file)
        meta_layout.addWidget(self.browse_btn)

        mod_layout.addLayout(meta_layout)
        profile_layout.addWidget(mod_group)
        layout.addWidget(profile_group)

        # -------------------------------------------------------------------
        # Safety & Non-Destructive Guardrails Panel
        # -------------------------------------------------------------------
        guard_frame = QFrame()
        guard_frame.setStyleSheet("""
            QFrame {
                background-color: #121008;
                border: 1px solid #78350F;
                border-left: 3px solid #F59E0B;
                border-radius: 4px;
            }
        """)
        guard_layout = QVBoxLayout(guard_frame)
        guard_layout.setContentsMargins(12, 10, 12, 10)
        guard_layout.setSpacing(4)

        guard_title = QLabel("CLINICAL SAFETY GUARDRAILS // STRICT NON-DESTRUCTIVE ENFORCEMENT")
        guard_title.setStyleSheet("color: #F59E0B; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 800; letter-spacing: 1px;")
        guard_layout.addWidget(guard_title)

        guard_desc = QLabel(
            "• All probes are <b>strictly non-destructive</b>. No imaging datasets or study records are altered or deleted.<br/>"
            "• Read-only presentation context verification adheres strictly to zero-PHI retention protocols.<br/>"
            "• Architecture aligns with IEC 80001-1 and IHE ATNA medical network safety standards."
        )
        guard_desc.setStyleSheet("color: #D1D5DB; font-size: 11px; line-height: 1.5;")
        guard_layout.addWidget(guard_desc)
        layout.addWidget(guard_frame)

        # -------------------------------------------------------------------
        # Start Assessment Action
        # -------------------------------------------------------------------
        action_layout = QHBoxLayout()
        self.start_btn = QPushButton("⚡ INITIATE SECURITY ASSESSMENT")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF5500;
                color: #FFFFFF;
                border: none;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 800;
                font-size: 13px;
                letter-spacing: 1.5px;
                padding: 12px 32px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #E04B00;
            }
        """)
        self.start_btn.clicked.connect(self._on_start_clicked)
        action_layout.addWidget(self.start_btn)
        action_layout.addStretch()

        layout.addLayout(action_layout)
        layout.addStretch()

    def set_target(self, target_dict: dict):
        """Populates scope from selected Target management tab."""
        self.host_input.setText(target_dict.get("host", ""))
        self.port_spin.setValue(int(target_dict.get("port", 104)))
        called = target_dict.get("called_ae")
        if called:
            self.called_ae_input.setText(called)

    def _on_profile_changed(self, index: int):
        if index == 0:  # Comprehensive
            self.mod_net.setChecked(True)
            self.mod_dicom.setChecked(True)
            self.mod_assoc.setChecked(True)
            self.mod_adv_dicom.setChecked(True)
            self.mod_dicomweb.setChecked(True)
            self.mod_tls.setChecked(True)
            self.mod_cve.setChecked(True)
            self.mod_compliance.setChecked(True)
        elif index == 1:  # Standard
            self.mod_net.setChecked(True)
            self.mod_dicom.setChecked(True)
            self.mod_assoc.setChecked(True)
            self.mod_adv_dicom.setChecked(True)
            self.mod_dicomweb.setChecked(True)
            self.mod_tls.setChecked(True)
            self.mod_cve.setChecked(True)
            self.mod_compliance.setChecked(True)
        elif index == 2:  # Quick Port & C-ECHO
            self.mod_net.setChecked(True)
            self.mod_dicom.setChecked(True)
            self.mod_assoc.setChecked(False)
            self.mod_adv_dicom.setChecked(False)
            self.mod_dicomweb.setChecked(False)
            self.mod_tls.setChecked(False)
            self.mod_cve.setChecked(False)
            self.mod_compliance.setChecked(False)

    def _browse_dicom_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select DICOM Test File", "", "DICOM Files (*.dcm *.ima);;All Files (*.*)"
        )
        if file_path:
            self.dicom_file_path.setText(file_path)
            self.mod_meta.setChecked(True)

    def _on_start_clicked(self):
        host = self.host_input.text().strip()
        if not host:
            QMessageBox.warning(self, "Invalid Scope", "Please specify a target hostname or IP address.")
            return

        config = {
            "host": host,
            "port": self.port_spin.value(),
            "called_ae": self.called_ae_input.text().strip() or "ANY-SCP",
            "calling_ae": self.calling_ae_input.text().strip() or "PACSSCANNER",
            "timeout": self.timeout_spin.value(),
            "modules": {
                "network": self.mod_net.isChecked(),
                "dicom_discovery": self.mod_dicom.isChecked(),
                "association": self.mod_assoc.isChecked(),
                "dicom_advanced": self.mod_adv_dicom.isChecked(),
                "dicomweb": self.mod_dicomweb.isChecked(),
                "tls": self.mod_tls.isChecked(),
                "cve": self.mod_cve.isChecked(),
                "compliance": self.mod_compliance.isChecked(),
                "metadata": self.mod_meta.isChecked(),
                "metadata_file": self.dicom_file_path.text().strip(),
            }
        }
        self.start_assessment_signal.emit(config)
