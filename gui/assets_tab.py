"""
gui/assets_tab.py
Network Asset Inventory & Subnet Discovery Workspace.
- Editorial typography ("DISCOVER THE SYSTEM AROUND THE PROBLEM.")
- Monospaced technical IP / Port telemetry and classification badges
- Deep obsidian & void surfaces (#05060C, #0E1222, razor-thin borders #1E2438)
- Architectural electric orange action buttons (#FF5500)
- Minimalist terminal progress indicator
- 100% preservation of SubnetWorker, threading, signals, and database inventory CRUD
"""

from __future__ import annotations

import json
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QGroupBox, QProgressBar, QCheckBox, QMessageBox, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QColor, QFont

from db import database as db
from engines.subnet_scanner import SubnetScanner
from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class SubnetWorker(QThread):
    progress_signal = pyqtSignal(int, str)
    asset_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(bool)

    def __init__(self, target_spec: str, authorized: bool, parent=None):
        super().__init__(parent)
        self.target_spec = target_spec
        self.authorized = authorized
        self.scanner = SubnetScanner(target_spec=target_spec, authorized=authorized)

    def run(self):
        try:
            self.scanner.run(
                progress_callback=lambda pct, msg: self.progress_signal.emit(pct, msg),
                asset_discovered_callback=lambda a: self.asset_signal.emit(a),
            )
            self.finished_signal.emit(True)
        except Exception as exc:
            self.progress_signal.emit(0, f"Error: {exc}")
            self.finished_signal.emit(False)


class AssetsTab(QWidget):
    """
    Asset discovery and clinical imaging asset inventory workspace.
    """

    assess_asset_requested = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: SubnetWorker | None = None
        self.init_ui()
        self.load_inventory()

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

        main_title = QLabel("DISCOVER THE SYSTEM AROUND THE PROBLEM.")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        main_title.setFont(title_font)
        main_title.setStyleSheet("color: #FFFFFF; font-weight: 900; letter-spacing: 1.2px;")
        title_box.addWidget(main_title)

        sub_title = QLabel("CLINICAL NETWORK DISCOVERY // ACTIVE PACS & MODALITY INVENTORY ENUMERATION")
        sub_title.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 1.5px;")
        title_box.addWidget(sub_title)

        header_layout.addLayout(title_box)
        header_layout.addStretch()

        self.refresh_btn = QPushButton("↺ REFRESH INVENTORY")
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
        self.refresh_btn.clicked.connect(self.load_inventory)
        header_layout.addWidget(self.refresh_btn)
        layout.addLayout(header_layout)

        # -------------------------------------------------------------------
        # Subnet Discovery Control Box
        # -------------------------------------------------------------------
        scan_group = QGroupBox("CLINICAL NETWORK DISCOVERY & CIDR SCOPE")
        scan_layout = QVBoxLayout(scan_group)
        scan_layout.setContentsMargins(16, 16, 16, 16)
        scan_layout.setSpacing(12)

        input_layout = QHBoxLayout()
        input_layout.setSpacing(10)

        lbl_target = QLabel("TARGET CIDR / SUBNET:")
        lbl_target.setStyleSheet("color: #94A3B8; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 700;")
        input_layout.addWidget(lbl_target)

        self.subnet_input = QLineEdit("127.0.0.1")
        self.subnet_input.setPlaceholderText("e.g. 192.168.1.0/24, 10.0.4.0/24, or 127.0.0.1")
        self.subnet_input.setStyleSheet("""
            QLineEdit {
                background-color: #070913;
                color: #FFFFFF;
                border: 1px solid #1E2438;
                border-radius: 4px;
                font-family: 'IBM Plex Mono', monospace;
                font-size: 12px;
                padding: 8px 12px;
            }
            QLineEdit:focus {
                border-color: #FF5500;
            }
        """)
        input_layout.addWidget(self.subnet_input, 2)

        self.start_btn = QPushButton("DISCOVER SUBNET ASSETS")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setStyleSheet("""
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
            QPushButton:disabled {
                background-color: #1E2438;
                color: #64748B;
            }
        """)
        self.start_btn.clicked.connect(self._start_scan)
        input_layout.addWidget(self.start_btn)
        scan_layout.addLayout(input_layout)

        # Authorization check
        self.auth_check = QCheckBox("I confirm explicit authorization to discover clinical assets on this hospital/clinic subnet.")
        self.auth_check.setChecked(True)
        self.auth_check.setStyleSheet("""
            QCheckBox {
                color: #94A3B8;
                font-size: 11px;
                font-family: 'IBM Plex Mono', monospace;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #1E2438;
                border-radius: 3px;
                background-color: #070913;
            }
            QCheckBox::indicator:checked {
                background-color: #FF5500;
                border-color: #FF5500;
            }
        """)
        scan_layout.addWidget(self.auth_check)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #070913;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #FF5500;
                border-radius: 3px;
            }
        """)
        scan_layout.addWidget(self.progress_bar)

        self.status_lbl = QLabel("READY // STANDBY FOR CLINICAL ASSET ENUMERATION")
        self.status_lbl.setStyleSheet("color: #64748B; font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 600; letter-spacing: 1px;")
        scan_layout.addWidget(self.status_lbl)

        layout.addWidget(scan_group)

        # -------------------------------------------------------------------
        # Asset Inventory Table
        # -------------------------------------------------------------------
        inv_group = QGroupBox("CLINICAL IMAGING ASSET INVENTORY")
        inv_layout = QVBoxLayout(inv_group)
        inv_layout.setContentsMargins(14, 14, 14, 14)
        inv_layout.setSpacing(12)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["IP ADDRESS", "HOSTNAME", "VENDOR / ARCHITECTURE", "CLASSIFICATION", "OPEN PORTS", "SERVICES DETECTED", "LAST AUDITED"])
        self.tree.header().setSectionResizeMode(QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        inv_layout.addWidget(self.tree)

        # Action bar
        act_layout = QHBoxLayout()
        self.count_lbl = QLabel("0 ASSETS INDEXED IN CONSOLE REGISTRY")
        self.count_lbl.setStyleSheet("color: #67E8F9; font-family: 'IBM Plex Mono', monospace; font-weight: 700; font-size: 10px; letter-spacing: 1.2px;")
        act_layout.addWidget(self.count_lbl)
        act_layout.addStretch()

        self.assess_btn = QPushButton("⚡ TARGET FOR SECURITY ASSESSMENT")
        self.assess_btn.setCursor(Qt.PointingHandCursor)
        self.assess_btn.setStyleSheet("""
            QPushButton {
                background-color: #121008;
                color: #FF5500;
                border: 1px solid #78350F;
                font-family: 'IBM Plex Mono', monospace;
                font-weight: 800;
                font-size: 10px;
                letter-spacing: 1px;
                padding: 8px 18px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #FF5500;
                color: #FFFFFF;
                border-color: #FF5500;
            }
        """)
        self.assess_btn.clicked.connect(self._on_assess_clicked)
        act_layout.addWidget(self.assess_btn)

        inv_layout.addLayout(act_layout)
        layout.addWidget(inv_group, 2)

    def load_inventory(self):
        self.tree.clear()
        try:
            assets = db.get_all_assets()
            for a in assets:
                ports_raw = a.get("open_ports", "[]")
                ports_list = json.loads(ports_raw) if isinstance(ports_raw, str) else ports_raw
                ports_str = ", ".join(str(p) for p in ports_list)

                svc_raw = a.get("detected_services", "[]")
                svc_list = json.loads(svc_raw) if isinstance(svc_raw, str) else svc_raw
                svc_str = ", ".join(svc_list)

                item = QTreeWidgetItem([
                    a.get("ip", ""),
                    a.get("hostname", ""),
                    a.get("vendor", "Unknown"),
                    a.get("device_type", "PACS Server"),
                    ports_str,
                    svc_str,
                    str(a.get("last_seen", ""))[:19]
                ])
                item.setData(0, Qt.UserRole, a)

                font_mono = QFont("IBM Plex Mono")
                font_mono.setPointSize(9)
                item.setFont(0, font_mono)
                item.setFont(4, font_mono)
                item.setForeground(0, QColor("#67E8F9"))

                self.tree.addTopLevelItem(item)

            self.count_lbl.setText(f"{len(assets)} ASSET(S) INDEXED IN CONSOLE REGISTRY")
        except Exception as exc:
            self.status_lbl.setText(f"ERROR LOADING INVENTORY: {exc}")

    def _start_scan(self):
        target = self.subnet_input.text().strip()
        auth = self.auth_check.isChecked()

        if not target:
            QMessageBox.warning(self, "Invalid Target", "Please specify a valid IP or subnet (e.g. 192.168.1.0/24).")
            return

        if not auth:
            QMessageBox.critical(self, "Authorization Required", "Clinical asset discovery requires explicit authorization confirmation.")
            return

        self.start_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_lbl.setText(f"INITIATING NETWORK DISCOVERY ACROSS {target}…")

        self.worker = SubnetWorker(target_spec=target, authorized=auth, parent=self)
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.asset_signal.connect(self._on_asset_found)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def _on_progress(self, pct: int, msg: str):
        self.progress_bar.setValue(pct)
        self.status_lbl.setText(f"[{pct}%] {msg.upper()}")

    def _on_asset_found(self, asset_dict: dict):
        self.load_inventory()

    def _on_finished(self, success: bool):
        self.start_btn.setEnabled(True)
        if success:
            self.status_lbl.setText("DISCOVERY COMPLETED // INVENTORY SYNCHRONIZED")
            self.progress_bar.setValue(100)
            self.load_inventory()
        else:
            self.status_lbl.setText("DISCOVERY HALTED OR COMPLETED WITH WARNINGS")

    def _on_item_double_clicked(self, item: QTreeWidgetItem, col: int):
        asset_data = item.data(0, Qt.UserRole)
        if asset_data:
            self.assess_asset_requested.emit(asset_data)

    def _on_assess_clicked(self):
        item = self.tree.currentItem()
        if not item:
            QMessageBox.information(self, "Selection Required", "Please select an asset from the inventory to assess.")
            return
        self._on_item_double_clicked(item, 0)
