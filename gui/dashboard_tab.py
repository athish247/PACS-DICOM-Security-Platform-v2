"""
gui/dashboard_tab.py
Dashboard Tab for PACS/DICOM Security Assessment Platform.
- Large editorial typography ("SYSTEMS, NOT FEATURE LISTS.")
- Technical telemetry cards (#0E1222, razor-thin borders #1E2438)
- Interactive DICOM Communication Flow & Architecture visualisation
- High-contrast data grids and real database metrics
"""

from __future__ import annotations

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox,
    QTreeWidget, QTreeWidgetItem, QPushButton, QHeaderView, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont

from db import database as db
from gui.theme import (
    ACCENT_ORANGE, ACCENT_CYAN, ACCENT_MINT, ACCENT_CRIMSON, ACCENT_AMBER,
    COLOR_VOID_BG, COLOR_SURFACE_CARD, COLOR_BORDER_DEFAULT
)


class DashboardTab(QWidget):
    """
    Operations Centre displaying operational security metrics,
    DICOM protocol flow architecture, and recent assessment activity.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.refresh_metrics()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # -------------------------------------------------------------------
        # Editorial Header
        # -------------------------------------------------------------------
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        main_title = QLabel("SYSTEMS, NOT FEATURE LISTS.")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        main_title.setFont(title_font)
        main_title.setStyleSheet("color: #FFFFFF; font-weight: 900; letter-spacing: 1.2px;")
        title_box.addWidget(main_title)

        sub_title = QLabel("CYBERSECURITY GOVERNANCE FOR MEDICAL IMAGING & PACS INFRASTRUCTURE")
        sub_title.setStyleSheet("color: #67E8F9; font-size: 10px; font-weight: 700; font-family: monospace; letter-spacing: 1px;")
        title_box.addWidget(sub_title)
        header_layout.addLayout(title_box)

        header_layout.addStretch()

        self.refresh_btn = QPushButton("🔄 SYNC TELEMETRY")
        self.refresh_btn.setCursor(Qt.PointingHandCursor)
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #0E1222;
                color: #67E8F9;
                border: 1px solid #1E2438;
                font-family: monospace;
                font-weight: 700;
                font-size: 11px;
                padding: 8px 16px;
                border-radius: 4px;
                letter-spacing: 0.5px;
            }
            QPushButton:hover {
                background-color: #141A2E;
                border: 1px solid #67E8F9;
                color: #FFFFFF;
            }
        """)
        self.refresh_btn.clicked.connect(self.refresh_metrics)
        header_layout.addWidget(self.refresh_btn)
        layout.addLayout(header_layout)

        # -------------------------------------------------------------------
        # Technical Telemetry Cards (6 Cards)
        # -------------------------------------------------------------------
        stats_group = QGroupBox("OPERATIONAL SECURITY TELEMETRY // REAL-TIME METRICS")
        stats_layout = QHBoxLayout(stats_group)
        stats_layout.setSpacing(10)

        self.card_total = self._create_stat_card("01 // TOTAL RUNS", "0", "#FFFFFF")
        self.card_assets = self._create_stat_card("02 // INDEXED ASSETS", "0", "#67E8F9")
        self.card_services = self._create_stat_card("03 // DICOM SERVICES", "0", "#22D3EE")
        self.card_compliance = self._create_stat_card("04 // COMPLIANCE POLICIES", "0 / 0", "#6EE7B7")
        self.card_critical = self._create_stat_card("05 // CRITICAL EXPOSURES", "0", "#EF4444")
        self.card_high = self._create_stat_card("06 // HIGH RISKS", "0", "#FF5500")

        stats_layout.addWidget(self.card_total)
        stats_layout.addWidget(self.card_assets)
        stats_layout.addWidget(self.card_services)
        stats_layout.addWidget(self.card_compliance)
        stats_layout.addWidget(self.card_critical)
        stats_layout.addWidget(self.card_high)
        layout.addWidget(stats_group)

        # -------------------------------------------------------------------
        # Technical Flow & Architecture Visualisation
        # -------------------------------------------------------------------
        flow_group = QGroupBox("PROTOCOL INSPECTION PATH // DICOM BOUNDARY ENFORCEMENT")
        flow_layout = QVBoxLayout(flow_group)
        flow_layout.setSpacing(8)

        flow_banner = QLabel(
            "<b>[ASSESSMENT SCU]</b> ──(A-ASSOCIATE-RQ)──► <b>[NETWORK GATEWAY]</b> "
            "──► <b>[PACS SCP :4242/:104]</b> ──► <b>[SOP NEGOTIATION]</b> "
            "──► <b>[POLICY DECISION: ALLOWED / FLAGGED / DENIED]</b>"
        )
        flow_banner.setStyleSheet(
            "background-color: #070913; color: #67E8F9; font-family: monospace; font-size: 11px; "
            "padding: 10px 14px; border: 1px solid #1E2438; border-radius: 5px; letter-spacing: 0.5px;"
        )
        flow_layout.addWidget(flow_banner)

        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(10)

        # Severity breakdown
        dist_box = QFrame()
        dist_box.setStyleSheet("background-color: #070913; border: 1px solid #1E2438; border-radius: 6px; padding: 10px;")
        dist_layout = QVBoxLayout(dist_box)
        dist_layout.setSpacing(4)
        dist_title = QLabel("FINDING SEVERITY CLASSIFICATION")
        dist_title.setStyleSheet("color: #64748B; font-weight: 700; font-size: 9.5px; font-family: monospace; letter-spacing: 1px;")
        dist_layout.addWidget(dist_title)

        self.dist_label = QLabel("Loading distribution metrics…")
        self.dist_label.setStyleSheet("font-size: 11px; font-family: monospace; line-height: 1.6; color: #FFFFFF;")
        dist_layout.addWidget(self.dist_label)
        mid_layout.addWidget(dist_box, 1)

        # Operational Assurance
        last_box = QFrame()
        last_box.setStyleSheet("background-color: #070913; border: 1px solid #1E2438; border-radius: 6px; padding: 10px;")
        last_layout = QVBoxLayout(last_box)
        last_layout.setSpacing(4)
        last_title = QLabel("ASSESSMENT RUNTIME ASSURANCE")
        last_title.setStyleSheet("color: #64748B; font-weight: 700; font-size: 9.5px; font-family: monospace; letter-spacing: 1px;")
        last_layout.addWidget(last_title)

        self.last_scan_label = QLabel("No assessments executed yet.")
        self.last_scan_label.setStyleSheet("font-size: 11px; font-family: monospace; color: #94A3B8; line-height: 1.5;")
        last_layout.addWidget(self.last_scan_label)
        mid_layout.addWidget(last_box, 1)

        flow_layout.addLayout(mid_layout)
        layout.addWidget(flow_group)

        # -------------------------------------------------------------------
        # Recent Assessments Audit Table
        # -------------------------------------------------------------------
        recent_group = QGroupBox("HISTORICAL AUDIT STREAM // RECENT ENFORCEMENT RUNS")
        recent_layout = QVBoxLayout(recent_group)

        self.recent_table = QTreeWidget()
        self.recent_table.setHeaderLabels(["RUN ID", "TARGET HOST", "PORT", "EXECUTION START", "VERDICT STATUS", "CRITICAL", "HIGH", "TOTAL FINDINGS"])
        self.recent_table.header().setSectionResizeMode(QHeaderView.Stretch)
        self.recent_table.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.recent_table.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        recent_layout.addWidget(self.recent_table)

        layout.addWidget(recent_group, 2)

    def _create_stat_card(self, title: str, initial_value: str, color_hex: str) -> QWidget:
        card = QFrame()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card_layout.setAlignment(Qt.AlignCenter)

        val_label = QLabel(initial_value)
        val_font = QFont()
        val_font.setPointSize(20)
        val_font.setBold(True)
        val_label.setFont(val_font)
        val_label.setAlignment(Qt.AlignCenter)
        val_label.setStyleSheet(f"color: {color_hex}; font-weight: 800; font-family: monospace; border: none; background: transparent;")

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #64748B; font-size: 9.5px; font-family: monospace; font-weight: 700; letter-spacing: 0.8px; border: none; background: transparent;")

        card_layout.addWidget(val_label)
        card_layout.addWidget(title_label)
        card.setStyleSheet("""
            QFrame {
                background-color: #0E1222;
                border-radius: 6px;
                border: 1px solid #1E2438;
            }
            QFrame:hover {
                border: 1px solid #FF5500;
                background-color: #141A2E;
            }
        """)
        return card

    def refresh_metrics(self):
        """Loads live counts and recent runs directly from SQLite database."""
        try:
            metrics = db.get_dashboard_metrics()
            dist = db.get_severity_distribution()

            # Update Stat Cards
            self._update_card_val(self.card_total, str(metrics.get("total_assessments", 0)))
            self._update_card_val(self.card_assets, str(metrics.get("total_assets", 0)))
            self._update_card_val(self.card_services, str(metrics.get("dicom_services", 0)))

            passed_c = metrics.get("compliance_passed", 0)
            failed_c = metrics.get("compliance_failed", 0)
            comp_str = f"{passed_c}P / {failed_c}F" if (passed_c + failed_c) > 0 else "0"
            self._update_card_val(self.card_compliance, comp_str)

            self._update_card_val(self.card_critical, str(metrics.get("critical_findings", 0)))
            self._update_card_val(self.card_high, str(metrics.get("high_findings", 0)))

            # Update Distribution Text
            tot_vulns = sum(dist.values())
            dist_text = (
                f"<b>TOTAL EXPOSURES DETECTED:</b> <font color='#FF5500'><b>{tot_vulns}</b></font><br/>"
                f"• <span style='color:#EF4444; font-weight:bold;'>CRITICAL: {dist.get('Critical', 0)}</span> &nbsp;&nbsp;"
                f"• <span style='color:#FF5500; font-weight:bold;'>HIGH: {dist.get('High', 0)}</span> &nbsp;&nbsp;"
                f"• <span style='color:#F59E0B; font-weight:bold;'>MEDIUM: {dist.get('Medium', 0)}</span> &nbsp;&nbsp;"
                f"• <span style='color:#38BDF8; font-weight:bold;'>LOW: {dist.get('Low', 0)}</span>"
            )
            self.dist_label.setText(dist_text)

            # Update Last Scan
            last_ts = metrics.get("last_scan_time")
            if last_ts:
                self.last_scan_label.setText(
                    f"<b>LAST INSPECTION:</b> <font color='#67E8F9'>{last_ts[:19]}</font><br/>"
                    f"<b>POLICIES EVALUATED:</b> HIPAA § 164.312, DICOM PS 3.15, MDS2<br/>"
                    f"<b>ENFORCEMENT MODE:</b> Non-destructive DIMSE probing, zero PHI retained."
                )
            else:
                self.last_scan_label.setText("No previous assessments recorded in local database.")

            # Update Recent Assessments Table
            self.recent_table.clear()
            recent_runs = db.get_recent_assessments(limit=15)
            for run in recent_runs:
                aid = run.get("id")
                counts = db.get_finding_counts_for_assessment(aid)
                total_f = sum(counts.values())
                status_raw = str(run.get("status", "unknown")).upper()
                verdict = f"[ALLOWED · {status_raw}]" if total_f == 0 else f"[FLAGGED · {status_raw}]"

                item = QTreeWidgetItem([
                    f"#{aid:04d}",
                    str(run.get("target_host", "N/A")),
                    str(run.get("target_port", 104)),
                    str(run.get("start_time", "N/A"))[:19],
                    verdict,
                    str(counts.get("Critical", 0)),
                    str(counts.get("High", 0)),
                    str(total_f)
                ])
                if counts.get("Critical", 0) > 0:
                    item.setForeground(5, QColor("#EF4444"))
                    item.setForeground(4, QColor("#EF4444"))
                elif counts.get("High", 0) > 0:
                    item.setForeground(6, QColor("#FF5500"))
                    item.setForeground(4, QColor("#FF5500"))
                else:
                    item.setForeground(4, QColor("#6EE7B7"))

                self.recent_table.addTopLevelItem(item)

        except Exception as exc:
            self.last_scan_label.setText(f"Error loading dashboard telemetry: {exc}")

    def _update_card_val(self, card_widget: QWidget, new_val: str):
        lbl = card_widget.findChild(QLabel)
        if lbl:
            lbl.setText(new_val)
