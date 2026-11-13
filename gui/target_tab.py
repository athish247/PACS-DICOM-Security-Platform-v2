"""
gui/target_tab.py
Target Management Workspace for PACS/DICOM Security Assessment Platform.
- Editorial typography ("BOUNDARIES DEFINED BY IDENTITY.")
- Deep obsidian & void surfaces (#05060C, #0E1222, razor-thin borders #1E2438)
- Architectural electric orange action buttons (#FF5500)
- Monospaced target parameter indicators & quick port triggers
- Strict 100% preservation of legal authorization mandates and SQLite persistence
"""

from __future__ import annotations

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSpinBox, QCheckBox, QGroupBox, QTreeWidget,
    QTreeWidgetItem, QMessageBox, QHeaderView, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QColor

from db import database as db
from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class TargetTab(QWidget):
    """
    Target Registry & Clinical Boundary Management.
    """

    target_selected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.load_targets()

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

        main_title = QLabel("BOUNDARIES DEFINED BY IDENTITY.")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        main_title.setFont(title_font)
        main_title.setStyleSheet("color: #FFFFFF; font-weight: 900; letter-spacing: 1.2px;")
        title_box.addWidget(main_title)

        sub_title = QLabel("AUTHORIZED PACS TARGET REGISTRY // CLINICAL SCOPE ENFORCEMENT")
        sub_title.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;")
        title_box.addWidget(sub_title)

        header_layout.addLayout(title_box)
        header_layout.addStretch()

        self.refresh_btn = QPushButton("↺ REFRESH TARGETS")
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
        self.refresh_btn.clicked.connect(self.load_targets)
        header_layout.addWidget(self.refresh_btn)
        layout.addLayout(header_layout)

        # -------------------------------------------------------------------
        # Target Configuration Form Box
        # -------------------------------------------------------------------
        form_group = QGroupBox("TARGET NODE SPECIFICATION & AUTHORIZATION MANDATE")
        form_layout = QVBoxLayout(form_group)
        form_layout.setContentsMargins(16, 16, 16, 16)
        form_layout.setSpacing(12)

        # Host and Port
        hp_layout = QHBoxLayout()
        hp_layout.setSpacing(10)

        lbl_host = QLabel("TARGET IP / HOSTNAME:")
        lbl_host.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        hp_layout.addWidget(lbl_host)

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g. 192.168.1.100 or pacs.hospital.local")
        self.host_input.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 12px;")
        hp_layout.addWidget(self.host_input, 2)

        lbl_port = QLabel("DICOM PORT:")
        lbl_port.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        hp_layout.addWidget(lbl_port)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(104)
        self.port_spin.setStyleSheet("font-family: 'IBM Plex Mono', monospace;")
        hp_layout.addWidget(self.port_spin, 1)

        form_layout.addLayout(hp_layout)

        # Quick Port Selector Buttons
        quick_layout = QHBoxLayout()
        lbl_quick = QLabel("QUICK PORT SELECT:")
        lbl_quick.setStyleSheet("color: #64748B; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        quick_layout.addWidget(lbl_quick)

        for p in [104, 11112, 2761, 2762, 4242, 8042]:
            btn = QPushButton(str(p))
            btn.setFixedWidth(58)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #070913;
                    color: #67E8F9;
                    border: 1px solid #1E2438;
                    font-family: 'IBM Plex Mono', monospace;
                    font-size: 10px;
                    font-weight: 700;
                    padding: 5px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    border-color: #FF5500;
                    color: #FFFFFF;
                }
            """)
            btn.clicked.connect(lambda checked, port=p: self.port_spin.setValue(port))
            quick_layout.addWidget(btn)
        quick_layout.addStretch()
        form_layout.addLayout(quick_layout)

        # Application Entity (AE) Titles
        ae_layout = QHBoxLayout()
        ae_layout.setSpacing(10)

        lbl_called = QLabel("CALLED AE TITLE (SCP):")
        lbl_called.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        ae_layout.addWidget(lbl_called)

        self.called_ae_input = QLineEdit("ANY-SCP")
        self.called_ae_input.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 11px;")
        ae_layout.addWidget(self.called_ae_input)

        lbl_calling = QLabel("CALLING AE TITLE (SCU):")
        lbl_calling.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        ae_layout.addWidget(lbl_calling)

        self.calling_ae_input = QLineEdit("PACSSCANNER")
        self.calling_ae_input.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 11px;")
        ae_layout.addWidget(self.calling_ae_input)

        lbl_timeout = QLabel("TIMEOUT (S):")
        lbl_timeout.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        ae_layout.addWidget(lbl_timeout)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(2, 120)
        self.timeout_spin.setValue(15)
        self.timeout_spin.setStyleSheet("font-family: 'IBM Plex Mono', monospace;")
        ae_layout.addWidget(self.timeout_spin)

        form_layout.addLayout(ae_layout)

        # Notes / Environment
        notes_layout = QHBoxLayout()
        lbl_notes = QLabel("ASSESSMENT NOTES:")
        lbl_notes.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        notes_layout.addWidget(lbl_notes)

        self.notes_input = QLineEdit()
        self.notes_input.setPlaceholderText("e.g. Authorized staging assessment, Radiology department, Centricity PACS v5")
        self.notes_input.setStyleSheet("font-family: 'IBM Plex Mono', monospace; font-size: 11px;")
        notes_layout.addWidget(self.notes_input)
        form_layout.addLayout(notes_layout)

        # Authorization Mandate Checkbox
        self.auth_check = QCheckBox(
            "LEGAL AUTHORIZATION MANDATE: I confirm that I possess explicit written authorization "
            "to execute security assessments against this clinical PACS/DICOM target."
        )
        self.auth_check.setStyleSheet("""
            QCheckBox {
                color: #F59E0B;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 10px;
                font-weight: 700;
                spacing: 8px;
                margin-top: 4px;
            }
            QCheckBox::indicator {
                width: 15px;
                height: 15px;
                border: 1px solid #78350F;
                border-radius: 3px;
                background-color: #070913;
            }
            QCheckBox::indicator:checked {
                background-color: #FF5500;
                border-color: #FF5500;
            }
        """)
        form_layout.addWidget(self.auth_check)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.save_btn = QPushButton("💾 SAVE AUTHORIZED TARGET")
        self.save_btn.setCursor(Qt.PointingHandCursor)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF5500;
                color: #FFFFFF;
                border: none;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 800;
                font-size: 11px;
                letter-spacing: 1px;
                padding: 9px 22px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #E04B00;
            }
        """)
        self.save_btn.clicked.connect(self.save_target)
        btn_layout.addWidget(self.save_btn)

        self.clear_btn = QPushButton("CLEAR FORM")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #1E2438;
                color: #94A3B8;
                border: 1px solid #2B334D;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 10px;
                font-weight: 700;
                padding: 9px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                color: #FFFFFF;
                border-color: #FF5500;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_form)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addStretch()

        form_layout.addLayout(btn_layout)
        layout.addWidget(form_group)

        # -------------------------------------------------------------------
        # Saved Targets List
        # -------------------------------------------------------------------
        list_group = QGroupBox("PERSISTED AUTHORIZED TARGET REGISTRY")
        list_layout = QVBoxLayout(list_group)
        list_layout.setContentsMargins(14, 14, 14, 14)
        list_layout.setSpacing(10)

        self.target_tree = QTreeWidget()
        self.target_tree.setHeaderLabels(["ID", "HOST", "PORT", "CALLED AE", "CALLING AE", "TIMEOUT", "AUTH", "NOTES", "REGISTERED AT"])
        self.target_tree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.target_tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.target_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.target_tree.itemDoubleClicked.connect(self.select_target_from_tree)
        list_layout.addWidget(self.target_tree)

        # List Actions
        action_layout = QHBoxLayout()
        action_layout.setSpacing(10)

        self.use_target_btn = QPushButton("⚡ LOAD TARGET INTO ASSESSMENT CONFIG")
        self.use_target_btn.setCursor(Qt.PointingHandCursor)
        self.use_target_btn.setStyleSheet("""
            QPushButton {
                background-color: #082F49;
                color: #67E8F9;
                border: 1px solid #0284C7;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 700;
                font-size: 11px;
                letter-spacing: 1px;
                padding: 9px 20px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #0C4A6E;
                border-color: #38BDF8;
            }
        """)
        self.use_target_btn.clicked.connect(self.use_selected_target)
        action_layout.addWidget(self.use_target_btn)
        action_layout.addStretch()

        list_layout.addLayout(action_layout)
        layout.addWidget(list_group, 2)

    def save_target(self):
        host = self.host_input.text().strip()
        if not host:
            QMessageBox.warning(self, "Validation Error", "Please provide a valid IP address or hostname.")
            return

        if not self.auth_check.isChecked():
            QMessageBox.critical(
                self,
                "Authorization Required",
                "You must check the authorization confirmation before saving an assessment target.\n"
                "Testing unauthorized systems violates clinical cybersecurity mandates."
            )
            return

        port = self.port_spin.value()
        called_ae = self.called_ae_input.text().strip() or "ANY-SCP"
        calling_ae = self.calling_ae_input.text().strip() or "PACSSCANNER"
        timeout = self.timeout_spin.value()
        notes = self.notes_input.text().strip()

        try:
            target_id = db.save_target(
                host=host,
                port=port,
                called_ae=called_ae,
                calling_ae=calling_ae,
                timeout=timeout,
                notes=notes,
                authorized=True
            )
            db.log_audit_event("TARGET_SAVED", f"id={target_id} host={host}:{port} called_ae={called_ae}")
            QMessageBox.information(self, "Success", f"Target {host}:{port} saved successfully in console registry.")
            self.load_targets()
            self.clear_form()
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to save target: {e}")

    def load_targets(self):
        self.target_tree.clear()
        try:
            targets = db.get_all_targets()
            for t in targets:
                auth_str = "[AUTHORIZED]" if t.get("authorized") else "[UNAUTHORIZED]"
                item = QTreeWidgetItem([
                    str(t.get("id")),
                    str(t.get("host")),
                    str(t.get("port")),
                    str(t.get("called_ae")),
                    str(t.get("calling_ae")),
                    f"{t.get('timeout')}s",
                    auth_str,
                    str(t.get("notes", "")),
                    str(t.get("created_at", ""))[:19]
                ])

                font_mono = QFont("IBM Plex Mono")
                font_mono.setPointSize(9)
                item.setFont(0, font_mono)
                item.setFont(1, font_mono)
                item.setFont(2, font_mono)
                item.setFont(6, font_mono)

                item.setForeground(1, QColor("#67E8F9"))
                if t.get("authorized"):
                    item.setForeground(6, QColor("#6EE7B7"))
                else:
                    item.setForeground(6, QColor("#FDA4AF"))

                self.target_tree.addTopLevelItem(item)
        except Exception:
            pass

    def select_target_from_tree(self, item):
        self.host_input.setText(item.text(1))
        self.port_spin.setValue(int(item.text(2)))
        self.called_ae_input.setText(item.text(3))
        self.calling_ae_input.setText(item.text(4))
        self.auth_check.setChecked("[AUTHORIZED]" in item.text(6))
        self.notes_input.setText(item.text(7))

    def use_selected_target(self):
        selected = self.target_tree.currentItem()
        if not selected:
            QMessageBox.warning(self, "Selection", "Please select a target from the list.")
            return

        data = {
            "id": int(selected.text(0)),
            "host": selected.text(1),
            "port": int(selected.text(2)),
            "called_ae": selected.text(3),
            "calling_ae": selected.text(4),
            "authorized": "[AUTHORIZED]" in selected.text(6),
        }
        self.target_selected.emit(data)

    def clear_form(self):
        self.host_input.clear()
        self.port_spin.setValue(104)
        self.called_ae_input.setText("ANY-SCP")
        self.calling_ae_input.setText("PACSSCANNER")
        self.notes_input.clear()
        self.auth_check.setChecked(False)
