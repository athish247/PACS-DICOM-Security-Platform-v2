"""
models/findings.py
Enterprise-grade data models for the PACS/DICOM Security Assessment Platform.
Supports full finding lifecycle, compliance mappings, asset inventory, and CVSS v3.1/v4.0.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingType(enum.Enum):
    VULNERABILITY = "VULNERABILITY"
    MISCONFIGURATION = "MISCONFIGURATION"
    INFORMATIONAL = "INFORMATIONAL"


class Severity(enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Confidence(enum.Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class FindingStatus(enum.Enum):
    OPEN = "Open"
    CONFIRMED = "Confirmed"
    FALSE_POSITIVE = "False Positive"
    RISK_ACCEPTED = "Risk Accepted"
    RESOLVED = "Resolved"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _ts(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt is not None else None


def generate_finding_id() -> str:
    """Generates a standardized enterprise finding identifier: FIND-YYYY-XXXX."""
    year = datetime.utcnow().year
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"FIND-{year}-{short_uuid}"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CVERecord:
    """A verified CVE entry from curated intelligence or NVD API."""
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: str                         # "Critical" / "High" / "Medium" / "Low"
    affected_product: str
    remediation: str
    source_url: str
    published_date: Optional[str] = None
    cisa_kev: bool = False                # In CISA Known Exploited Vulnerabilities catalog
    cvss_vector: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "affected_product": self.affected_product,
            "remediation": self.remediation,
            "source_url": self.source_url,
            "published_date": self.published_date,
            "cisa_kev": self.cisa_kev,
            "cvss_vector": self.cvss_vector,
        }


@dataclass
class Finding:
    """
    Enterprise-grade security finding with lifecycle tracking, technical evidence,
    compliance cross-referencing, and remediation intelligence.
    """
    title: str
    severity: Severity
    host: str
    port: int
    service: str
    evidence: str                         # Technical evidence; never unmasked PHI
    detection_method: str
    confidence: Confidence
    finding_type: FindingType
    finding_id: str = field(default_factory=generate_finding_id)
    assessment_id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_version: str = "3.1"             # "3.1" or "4.0"
    cvss_vector: Optional[str] = None
    remediation: Optional[str] = None
    remediation_config: Optional[str] = None  # Exact vendor configuration snippet / diff
    affected_component: str = "DICOM Upper Layer / PACS"
    standards_mapping: Dict[str, List[str]] = field(default_factory=dict)
    status: FindingStatus = FindingStatus.OPEN
    verification_status: str = "Automated Assessment Verified"
    analyst_notes: str = ""
    assigned_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        sev_val = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        conf_val = self.confidence.value if isinstance(self.confidence, Confidence) else str(self.confidence)
        type_val = self.finding_type.value if isinstance(self.finding_type, FindingType) else str(self.finding_type)
        status_val = self.status.value if isinstance(self.status, FindingStatus) else str(self.status)

        return {
            "finding_id": self.finding_id,
            "assessment_id": self.assessment_id,
            "title": self.title,
            "severity": sev_val,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "evidence": self.evidence,
            "detection_method": self.detection_method,
            "confidence": conf_val,
            "finding_type": type_val,
            "timestamp": _ts(self.timestamp),
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "remediation": self.remediation,
            "remediation_config": self.remediation_config,
            "affected_component": self.affected_component,
            "standards_mapping": self.standards_mapping,
            "status": status_val,
            "verification_status": self.verification_status,
            "analyst_notes": self.analyst_notes,
            "assigned_to": self.assigned_to,
        }


@dataclass
class AssessmentTarget:
    """Describes a PACS/DICOM target authorised for testing."""
    host: str
    port: int
    called_ae: str
    calling_ae: str
    timeout: int                          # seconds
    authorized: bool                      # Enforced before scans
    notes: str = ""
    target_id: Optional[int] = None
    cidr_subnet: Optional[str] = None
    target_type: str = "PACS Server"      # PACS, Modality, Gateway, Workstation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "host": self.host,
            "port": self.port,
            "called_ae": self.called_ae,
            "calling_ae": self.calling_ae,
            "timeout": self.timeout,
            "authorized": self.authorized,
            "notes": self.notes,
            "cidr_subnet": self.cidr_subnet,
            "target_type": self.target_type,
        }


@dataclass
class DicomService:
    """Result of a DICOM service probe (C-ECHO / Upper Layer negotiation)."""
    host: str
    port: int
    ae_response: Optional[str]            # AE title returned in A-ASSOCIATE-AC
    echo_success: bool
    tls_capable: bool
    response_ms: Optional[float]          # Round-trip latency in ms
    timestamp: datetime = field(default_factory=datetime.utcnow)
    implementation_class_uid: Optional[str] = None
    implementation_version_name: Optional[str] = None
    accepted_sop_classes: List[str] = field(default_factory=list)
    accepted_transfer_syntaxes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ae_response": self.ae_response,
            "ae_title_response": self.ae_response,
            "echo_success": self.echo_success,
            "tls_capable": self.tls_capable,
            "response_ms": self.response_ms,
            "response_time_ms": self.response_ms,
            "timestamp": _ts(self.timestamp),
            "implementation_class_uid": self.implementation_class_uid,
            "implementation_version_name": self.implementation_version_name,
            "accepted_sop_classes": self.accepted_sop_classes,
            "accepted_transfer_syntaxes": self.accepted_transfer_syntaxes,
        }


@dataclass
class Asset:
    """Network Asset Inventory entry for clinical imaging infrastructure."""
    asset_id: str
    ip: str
    hostname: str
    mac_address: Optional[str] = None
    vendor: str = "Unknown"
    device_type: str = "Clinical Modality / PACS"
    os_fingerprint: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    detected_services: List[str] = field(default_factory=list)
    ae_titles: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "os_fingerprint": self.os_fingerprint,
            "open_ports": self.open_ports,
            "detected_services": self.detected_services,
            "ae_titles": self.ae_titles,
            "first_seen": _ts(self.first_seen),
            "last_seen": _ts(self.last_seen),
            "risk_score": self.risk_score,
        }


@dataclass
class ComplianceControl:
    """Assessment of a specific control within a cybersecurity framework."""
    framework: str                        # HIPAA, NIST_CSF_2_0, NIST_800_53, IEC_80001_1, DICOM_PS_3_15, IHE_ATNA, MDS2
    control_id: str                       # e.g., "164.312(e)(1)", "PR.DS-02"
    control_title: str
    description: str
    status: str                           # "PASSED", "FAILED", "MANUAL_VERIFY", "NOT_ASSESSED"
    evidence: str
    remediation_guidance: str
    associated_finding_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "control_title": self.control_title,
            "description": self.description,
            "status": self.status,
            "evidence": self.evidence,
            "remediation_guidance": self.remediation_guidance,
            "associated_finding_ids": self.associated_finding_ids,
        }


@dataclass
class AssessmentResult:
    """Aggregated result for one complete assessment run."""
    target: AssessmentTarget
    start_time: datetime
    end_time: Optional[datetime]
    findings: List[Finding] = field(default_factory=list)
    services_discovered: List[DicomService] = field(default_factory=list)
    scan_modules_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    compliance_controls: List[ComplianceControl] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "start_time": _ts(self.start_time),
            "end_time": _ts(self.end_time),
            "findings": [f.to_dict() for f in self.findings],
            "services_discovered": [s.to_dict() for s in self.services_discovered],
            "scan_modules_run": self.scan_modules_run,
            "errors": self.errors,
            "compliance_controls": [c.to_dict() for c in self.compliance_controls],
        }


@dataclass
class ScoredFinding:
    """Output of risk_scorer.score_finding() with explainable risk breakdown."""
    original_finding: Finding
    final_severity: Severity
    cvss_estimate: Optional[float]
    rationale: str
    confidence: Confidence
    healthcare_impact_score: float = 0.0  # 0.0 to 10.0
    clinical_risk_tier: str = "Low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_finding": self.original_finding.to_dict(),
            "final_severity": self.final_severity.value,
            "cvss_estimate": self.cvss_estimate,
            "rationale": self.rationale,
            "confidence": self.confidence.value,
            "healthcare_impact_score": self.healthcare_impact_score,
            "clinical_risk_tier": self.clinical_risk_tier,
        }
