"""
engines/compliance_engine.py
Healthcare Cybersecurity Compliance Intelligence Engine.

Maps technical security assessment findings directly to medical device and healthcare standards:
1. HIPAA Security Rule (45 CFR § 164.312)
2. NIST Cybersecurity Framework 2.0 (CSF 2.0)
3. NIST SP 800-53 Rev. 5
4. IEC 80001-1 (Risk Management for Medical IT Networks)
5. DICOM PS 3.15 (Security & System Management Profiles)
6. IHE ATNA (Audit Trail and Node Authentication Profile)
7. Manufacturer Disclosure Statement for Medical Device Security (MDS2)

Notice: Technical evidence mapping only. Does not constitute formal legal certification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from models.findings import Finding, ComplianceControl, Severity

logger = logging.getLogger(__name__)

COMPLIANCE_DISCLAIMER = (
    "DISCLAIMER: This report provides technical evidence and cybersecurity control mapping based on "
    "observed protocol behavior. It does not constitute legal counsel, formal regulatory certification, "
    "or an exhaustive compliance determination under HIPAA, IEC 80001-1, or FDA medical device guidance."
)

# Standard control definitions
CONTROL_DEFINITIONS = [
    # HIPAA Security Rule
    {
        "framework": "HIPAA",
        "control_id": "164.312(a)(1)",
        "control_title": "Access Control (ePHI Protection)",
        "description": "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.",
        "eval_triggers": ["Access", "Whitelist", "Anonymous", "QIDO-RS", "Admin", "Storage SOP"],
    },
    {
        "framework": "HIPAA",
        "control_id": "164.312(e)(1)",
        "control_title": "Transmission Security",
        "description": "Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network.",
        "eval_triggers": ["Unencrypted", "TLS", "Cipher", "SSL", "CORS"],
    },
    {
        "framework": "HIPAA",
        "control_id": "164.312(c)(1)",
        "control_title": "Integrity Controls",
        "description": "Implement policies and procedures to protect electronic protected health information from improper alteration or destruction.",
        "eval_triggers": ["Storage SOP", "Big Endian", "Integrity"],
    },
    {
        "framework": "HIPAA",
        "control_id": "164.312(d)",
        "control_title": "Person or Entity Authentication",
        "description": "Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed.",
        "eval_triggers": ["AE Title", "Authentication", "Credential", "Bearer"],
    },
    # DICOM PS 3.15
    {
        "framework": "DICOM_PS_3_15",
        "control_id": "Profile B.8",
        "control_title": "Secure DICOM Communication Profile (TLS 1.3)",
        "description": "Enforces transport layer security (TLS 1.3 / BCP 195) with secure cipher suites on port 2762 for all DICOM upper layer exchanges.",
        "eval_triggers": ["Unencrypted", "TLS", "Port 104", "Port 4242"],
    },
    {
        "framework": "DICOM_PS_3_15",
        "control_id": "Profile E.1",
        "control_title": "Basic Application Level Confidentiality Profile",
        "description": "Requires safe de-identification of patient-identifiable elements prior to secondary sharing or research export.",
        "eval_triggers": ["PHI", "Metadata", "PatientName"],
    },
    # IHE ATNA
    {
        "framework": "IHE_ATNA",
        "control_id": "ATNA-NodeAuth",
        "control_title": "Node Authentication & Mutual TLS (mTLS)",
        "description": "Requires bilateral entity authentication using X.509 digital certificates to establish trusted communication between clinical modalities and archives.",
        "eval_triggers": ["mTLS", "Client Certificate", "Whitelist", "Anonymous"],
    },
    # MDS2
    {
        "framework": "MDS2",
        "control_id": "CNCP",
        "control_title": "Transmission Confidentiality & Integrity",
        "description": "Manufacturer specification of network communication encryption capabilities for protected health data in transit.",
        "eval_triggers": ["Unencrypted", "TLS", "Transmission"],
    },
    {
        "framework": "MDS2",
        "control_id": "AUTO",
        "control_title": "Authorization & Access Controls",
        "description": "Manufacturer specification of access restriction mechanisms (AE Title filtering, IP filtering, user roles).",
        "eval_triggers": ["Access", "Whitelist", "AE Title"],
    },
    # NIST CSF 2.0
    {
        "framework": "NIST_CSF_2_0",
        "control_id": "PR.AC-03",
        "control_title": "Access Enforcement on Network Services",
        "description": "Access to services is managed through least privilege and authorized network connection controls.",
        "eval_triggers": ["Access", "Storage SOP", "Admin"],
    },
    {
        "framework": "NIST_CSF_2_0",
        "control_id": "PR.DS-02",
        "control_title": "Data-in-Transit Protection",
        "description": "Data in transit is protected using robust cryptographic mechanisms.",
        "eval_triggers": ["Unencrypted", "TLS", "CORS"],
    },
]


@dataclass
class ComplianceSummary:
    total_controls: int = 0
    passed_count: int = 0
    failed_count: int = 0
    manual_verify_count: int = 0
    not_assessed_count: int = 0
    compliance_score_pct: float = 0.0
    controls: List[ComplianceControl] = field(default_factory=list)


class ComplianceEngine:
    """
    Evaluates assessment findings against healthcare cybersecurity frameworks.
    Produces rigorous, evidence-backed control status mappings.
    """

    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def evaluate(self) -> ComplianceSummary:
        summary = ComplianceSummary()
        summary.total_controls = len(CONTROL_DEFINITIONS)

        for c_def in CONTROL_DEFINITIONS:
            framework = c_def["framework"]
            ctrl_id = c_def["control_id"]
            title = c_def["control_title"]
            desc = c_def["description"]
            triggers = c_def["eval_triggers"]

            # Match findings that relate to this control
            matched_findings = []
            for f in self.findings:
                f_title = f.title.lower()
                f_ev = f.evidence.lower()
                f_map = f.standards_mapping.get(framework, [])

                # Check explicit standards mapping first
                if any(ctrl_id in m for m in f_map):
                    matched_findings.append(f)
                    continue

                # Fallback keyword match
                for t in triggers:
                    if t.lower() in f_title or t.lower() in f_ev:
                        matched_findings.append(f)
                        break

            finding_ids = [f.finding_id for f in matched_findings]

            if matched_findings:
                # If any Critical or High finding exists, control status is FAILED
                has_high = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in matched_findings)
                status = "FAILED" if has_high else "MANUAL_VERIFY"
                evidence = "; ".join([f"{f.title} ({f.severity.value})" for f in matched_findings[:3]])
                remediation = matched_findings[0].remediation or "Review configuration against standard."

                control = ComplianceControl(
                    framework=framework,
                    control_id=ctrl_id,
                    control_title=title,
                    description=desc,
                    status=status,
                    evidence=f"Violations detected: {evidence}",
                    remediation_guidance=remediation,
                    associated_finding_ids=finding_ids,
                )
                if status == "FAILED":
                    summary.failed_count += 1
                else:
                    summary.manual_verify_count += 1

            else:
                # No related violations detected in the assessment scope
                control = ComplianceControl(
                    framework=framework,
                    control_id=ctrl_id,
                    control_title=title,
                    description=desc,
                    status="PASSED",
                    evidence="No non-conformance detected during automated protocol assessment.",
                    remediation_guidance="Maintain current security posture and monitor periodically.",
                    associated_finding_ids=[],
                )
                summary.passed_count += 1

            summary.controls.append(control)

        if summary.total_controls > 0:
            summary.compliance_score_pct = round((summary.passed_count / summary.total_controls) * 100.0, 1)

        return summary
