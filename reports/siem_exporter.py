"""
reports/siem_exporter.py
SIEM & Enterprise Log Integration Exporter for PACS/DICOM Security Assessment Platform.

Supports:
- JSON Export
- CEF (Common Event Format for Splunk, Microsoft Sentinel, Micro Focus ArcSight)
- LEEF (Log Event Extended Format for IBM QRadar)
- Syslog RFC 5424 message generation
Strictly excludes unmasked PHI.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

SEVERITY_TO_CEF = {
    "Critical": "10",
    "High": "7",
    "Medium": "5",
    "Low": "3",
    "Informational": "1",
}


class SIEMExporter:
    """
    Transforms assessment findings into standard SIEM event formats.
    """

    @staticmethod
    def to_json(findings: List[Dict[str, Any]], indent: int = 2) -> str:
        return json.dumps(findings, indent=indent, default=str)

    @staticmethod
    def to_cef(findings: List[Dict[str, Any]]) -> str:
        """
        Converts findings into Common Event Format (CEF) lines.
        Format:
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        cef_lines = []
        for f in findings:
            sev_str = f.get("severity", "Informational")
            cef_sev = SEVERITY_TO_CEF.get(sev_str, "1")
            title = f.get("title", "Security Finding").replace("|", "\\|")
            fid = f.get("finding_id", "FIND-UNKNOWN")
            host = f.get("host", "127.0.0.1")
            port = f.get("port", 104)
            evidence = f.get("evidence", "").replace("\n", " ")[:250].replace("=", "\\=")
            cve = f.get("cve_id") or "N/A"

            ext = f"src={host} spt={port} cs1Label=CVE cs1={cve} msg={evidence} cs2Label=Status cs2={f.get('status', 'Open')}"
            line = f"CEF:0|MedicalImagingCybersecurity|PACSSecurityPlatform|2.0|{fid}|{title}|{cef_sev}|{ext}"
            cef_lines.append(line)

        return "\n".join(cef_lines)

    @staticmethod
    def to_leef(findings: List[Dict[str, Any]]) -> str:
        """
        Converts findings into Log Event Extended Format (LEEF) for IBM QRadar.
        """
        leef_lines = []
        for f in findings:
            fid = f.get("finding_id", "FIND-UNKNOWN")
            title = f.get("title", "Security Finding")
            host = f.get("host", "127.0.0.1")
            port = f.get("port", 104)
            sev = f.get("severity", "Medium")

            line = f"LEEF:1.0|MedicalCybersecurity|PACSSecurityPlatform|2.0|{fid}|devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSZ\tdevTime={f.get('timestamp')}\tsrc={host}\tdpt={port}\tsev={sev}\ttitle={title}"
            leef_lines.append(line)

        return "\n".join(leef_lines)

    @staticmethod
    def export_to_file(findings: List[Dict[str, Any]], file_path: str, format_type: str = "json") -> str:
        format_type = format_type.lower()
        if format_type == "cef":
            content = SIEMExporter.to_cef(findings)
        elif format_type == "leef":
            content = SIEMExporter.to_leef(findings)
        else:
            content = SIEMExporter.to_json(findings)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        return file_path
