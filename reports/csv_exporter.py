"""
reports/csv_exporter.py
CSV Export Module for PACS/DICOM Security Assessment Platform.

Exports structured vulnerability and configuration findings to CSV format
suitable for SIEM ingestion, ticket creation, and compliance records.
"""

from __future__ import annotations

import csv
import io
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from models.findings import Finding, Severity, Confidence, FindingType


class CSVExporter:
    """
    Exports assessment findings to standard CSV.
    Safeguards patient privacy: strictly excludes raw imaging or PHI payloads.
    """

    HEADERS = [
        "Severity",
        "Finding Title",
        "Host",
        "Port",
        "Service",
        "Type",
        "Detection Method",
        "Confidence",
        "CVSS Score",
        "CVE ID",
        "Remediation",
        "Timestamp",
        "Evidence Summary"
    ]

    @classmethod
    def findings_to_csv_string(cls, findings: List[Finding]) -> str:
        """
        Converts a list of Finding objects into an in-memory CSV string.
        """
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(cls.HEADERS)

        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            ft = f.finding_type.value if hasattr(f.finding_type, "value") else str(f.finding_type)
            conf = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            ts = f.timestamp.isoformat() if isinstance(f.timestamp, datetime) else str(f.timestamp)
            ev = f.evidence.replace("\n", " | ") if f.evidence else ""

            writer.writerow([
                sev,
                f.title,
                f.host,
                f.port,
                f.service,
                ft,
                f.detection_method,
                conf,
                f.cvss_score if f.cvss_score is not None else "N/A",
                f.cve_id if f.cve_id else "N/A",
                f.remediation if f.remediation else "N/A",
                ts,
                ev
            ])

        return output.getvalue()

    @classmethod
    def export_to_file(cls, findings: List[Finding], filepath: str) -> str:
        """
        Writes findings to a specified CSV destination file.
        """
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        content = cls.findings_to_csv_string(findings)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            f.write(content)
        return filepath
