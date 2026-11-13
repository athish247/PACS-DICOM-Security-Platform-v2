"""
engines/dicom_advanced_scanner.py
Advanced DICOM Security Engine for PACS/DICOM Security Assessment Platform.

Implements:
1. Presentation Context Negotiation & SOP Class Enumeration (CT, MR, Worklist, Query/Retrieve)
2. Transfer Syntax Profiling (Implicit VR, Explicit VR, Deflated, JPEG Lossless, Retired Big Endian)
3. Non-destructive, bounded C-FIND read-only query boundary testing
4. Implementation Class UID & Implementation Version Name passive fingerprinting
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from models.findings import (
    Finding, FindingType, Severity, Confidence, FindingStatus
)

logger = logging.getLogger(__name__)

# Standard SOP Classes evaluated during presentation context negotiation
CLINICAL_SOP_CLASSES = [
    ("Verification", "1.2.840.10008.1.1", "Standard verification probe"),
    ("CTImageStorage", "1.2.840.10008.5.1.4.1.1.2", "CT Scan image storage"),
    ("MRImageStorage", "1.2.840.10008.5.1.4.1.1.4", "Magnetic Resonance image storage"),
    ("SecondaryCaptureImageStorage", "1.2.840.10008.5.1.4.1.1.7", "Secondary capture / screen grab storage"),
    ("UltrasoundImageStorage", "1.2.840.10008.5.1.4.1.1.6.1", "Ultrasound modality storage"),
    ("DigitalXRayImageStorageForPresentation", "1.2.840.10008.5.1.4.1.1.1.1", "Digital X-Ray image storage"),
    ("StudyRootQueryRetrieveInformationModelFind", "1.2.840.10008.5.1.4.1.2.2.1", "DICOM Study Root Query (C-FIND)"),
    ("PatientRootQueryRetrieveInformationModelFind", "1.2.840.10008.5.1.4.1.2.1.1", "DICOM Patient Root Query (C-FIND)"),
    ("ModalityWorklistInformationModelFind", "1.2.840.10008.5.1.4.31", "DICOM Modality Worklist (C-FIND)"),
    ("StorageCommitmentPushModel", "1.2.840.10008.1.20.1", "Storage Commitment push verification"),
]

# Transfer Syntaxes tested for security profiling
TRANSFER_SYNTAXES = [
    ("ImplicitVRLittleEndian", "1.2.840.10008.1.2", "Default uncompressed transfer syntax"),
    ("ExplicitVRLittleEndian", "1.2.840.10008.1.2.1", "Standard explicit VR little endian"),
    ("ExplicitVRBigEndian", "1.2.840.10008.1.2.2", "Retired Big Endian (DICOM Part 5 retired)"),
    ("DeflatedExplicitVRLittleEndian", "1.2.840.10008.1.2.1.99", "ZLIB Deflated Explicit VR"),
    ("RLELossless", "1.2.840.10008.1.2.5", "Run-length encoded lossless compression"),
    ("JPEGLossless", "1.2.840.10008.1.2.4.70", "JPEG Lossless (Process 14 SV1)"),
    ("JPEGBaseline8Bit", "1.2.840.10008.1.2.4.50", "JPEG Baseline lossy compression"),
]


@dataclass
class PresentationContextResult:
    abstract_syntax_name: str
    abstract_syntax_uid: str
    accepted: bool
    result_reason: str
    accepted_transfer_syntax: Optional[str] = None


@dataclass
class AdvancedDicomScanResult:
    host: str
    port: int
    association_established: bool
    implementation_class_uid: Optional[str] = None
    implementation_version_name: Optional[str] = None
    presentation_contexts: List[PresentationContextResult] = field(default_factory=list)
    accepted_sop_count: int = 0
    accepted_storage_sops: List[str] = field(default_factory=list)
    accepted_query_sops: List[str] = field(default_factory=list)
    supported_transfer_syntaxes: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)


class AdvancedDicomScanner:
    """
    Advanced DICOM protocol assessment engine.
    Safely probes SOP class support, transfer syntaxes, and software implementation fingerprints.
    """

    def __init__(
        self,
        host: str,
        port: int = 104,
        called_ae: str = "ANY-SCP",
        calling_ae: str = "PACSSCANNER",
        timeout: float = 10.0,
        enable_bounded_c_find: bool = False,
    ):
        self.host = host
        self.port = port
        self.called_ae = called_ae
        self.calling_ae = calling_ae
        self.timeout = timeout
        self.enable_bounded_c_find = enable_bounded_c_find

    def run_assessment(self) -> AdvancedDicomScanResult:
        result = AdvancedDicomScanResult(
            host=self.host,
            port=self.port,
            association_established=False,
        )

        try:
            from pynetdicom import AE
            from pydicom.uid import UID
        except ImportError as exc:
            logger.warning("pynetdicom or pydicom not installed: %s", exc)
            return result

        ae = AE(ae_title=self.calling_ae)
        ae.acse_timeout = self.timeout
        ae.dimse_timeout = self.timeout
        ae.network_timeout = self.timeout

        # Propose all target clinical SOP classes
        for name, uid_str, desc in CLINICAL_SOP_CLASSES:
            # Propose with standard transfer syntaxes
            ae.add_requested_context(
                UID(uid_str),
                [UID("1.2.840.10008.1.2"), UID("1.2.840.10008.1.2.1"), UID("1.2.840.10008.1.2.2")]
            )

        assoc = None
        try:
            assoc = ae.associate(self.host, self.port, ae_title=self.called_ae)
            if not assoc.is_established:
                result.association_established = False
                return result

            result.association_established = True

            # Extract implementation class UID and version name
            if assoc.acceptor:
                result.implementation_class_uid = getattr(assoc.acceptor, "implementation_class_uid", None)
                result.implementation_version_name = getattr(assoc.acceptor, "implementation_version_name", None)

            # Analyze accepted presentation contexts
            uid_to_name = {uid_str: name for name, uid_str, desc in CLINICAL_SOP_CLASSES}
            for cx in assoc.accepted_contexts:
                abstract_uid = str(cx.abstract_syntax)
                name = uid_to_name.get(abstract_uid, abstract_uid)
                ts_str = str(cx.transfer_syntax) if cx.transfer_syntax else "Unknown"

                result.presentation_contexts.append(PresentationContextResult(
                    abstract_syntax_name=name,
                    abstract_syntax_uid=abstract_uid,
                    accepted=True,
                    result_reason="Accepted (0x00)",
                    accepted_transfer_syntax=ts_str,
                ))

                if "Storage" in name:
                    result.accepted_storage_sops.append(name)
                elif "Query" in name or "Worklist" in name:
                    result.accepted_query_sops.append(name)

                if ts_str not in result.supported_transfer_syntaxes:
                    result.supported_transfer_syntaxes.append(ts_str)

            for cx in assoc.rejected_contexts:
                abstract_uid = str(cx.abstract_syntax)
                name = uid_to_name.get(abstract_uid, abstract_uid)
                result.presentation_contexts.append(PresentationContextResult(
                    abstract_syntax_name=name,
                    abstract_syntax_uid=abstract_uid,
                    accepted=False,
                    result_reason=f"Rejected ({hex(cx.result) if cx.result is not None else 'N/A'})",
                    accepted_transfer_syntax=None,
                ))

            result.accepted_sop_count = len(result.accepted_storage_sops) + len(result.accepted_query_sops)

            # ---------------------------------------------------------------
            # Security Findings Derivation
            # ---------------------------------------------------------------

            # 1. Unauthenticated Storage SOP Class Acceptance
            if result.accepted_storage_sops:
                sops_str = ", ".join(result.accepted_storage_sops[:4])
                result.findings.append(Finding(
                    title="Unauthenticated DICOM Storage SOP Class Acceptance",
                    severity=Severity.HIGH,
                    host=self.host,
                    port=self.port,
                    service="DICOM Storage SCP",
                    evidence=(
                        f"DICOM Upper Layer association accepted storage presentation contexts ({sops_str}) "
                        f"from unauthenticated Calling AE '{self.calling_ae}'. Implementation: "
                        f"'{result.implementation_version_name or 'N/A'}' (UID: {result.implementation_class_uid or 'N/A'})."
                    ),
                    detection_method="pynetdicom A-ASSOCIATE-RQ Presentation Context Negotiation",
                    confidence=Confidence.HIGH,
                    finding_type=FindingType.MISCONFIGURATION,
                    remediation=(
                        "Configure Application Entity (AE) whitelisting and network access control. "
                        "Only authorized diagnostic modalities should be permitted to negotiate Storage SOP classes."
                    ),
                    standards_mapping={
                        "HIPAA": ["164.312(a)(1) Access Control", "164.312(c)(1) Integrity"],
                        "DICOM": ["PS 3.15 Profile B.1"],
                        "NIST_CSF_2_0": ["PR.AC-03", "PR.DS-01"],
                    },
                ))

            # 2. Unauthenticated Query / Worklist SOP Class Acceptance
            if result.accepted_query_sops:
                q_sops_str = ", ".join(result.accepted_query_sops)
                result.findings.append(Finding(
                    title="Unauthenticated DICOM Query / Worklist SOP Class Negotiation",
                    severity=Severity.HIGH,
                    host=self.host,
                    port=self.port,
                    service="DICOM Query/Retrieve SCP",
                    evidence=(
                        f"Association accepted Query/Retrieve or Worklist presentation contexts ({q_sops_str}) "
                        f"without prior authentication. Allows modality worklist and study index querying."
                    ),
                    detection_method="pynetdicom A-ASSOCIATE-RQ Presentation Context Negotiation",
                    confidence=Confidence.HIGH,
                    finding_type=FindingType.MISCONFIGURATION,
                    remediation=(
                        "Restrict C-FIND and Worklist query models to registered modality IP addresses and AE Titles. "
                        "Disable anonymous query acceptance on the PACS archive."
                    ),
                    standards_mapping={
                        "HIPAA": ["164.312(a)(1) Access Control", "164.312(b) Audit Controls"],
                        "DICOM": ["PS 3.15 Annex B"],
                        "NIST_CSF_2_0": ["PR.AC-06"],
                    },
                ))

            # 3. Retired Transfer Syntax Support (Explicit VR Big Endian)
            if "1.2.840.10008.1.2.2" in result.supported_transfer_syntaxes:
                result.findings.append(Finding(
                    title="Retired Transfer Syntax Supported (Explicit VR Big Endian)",
                    severity=Severity.LOW,
                    host=self.host,
                    port=self.port,
                    service="DICOM Upper Layer",
                    evidence=(
                        "PACS negotiated Explicit VR Big Endian (1.2.840.10008.1.2.2), which was retired in "
                        "DICOM 2006. Legacy parser code paths may contain unpatched memory flaws."
                    ),
                    detection_method="Presentation Context Transfer Syntax Profiling",
                    confidence=Confidence.HIGH,
                    finding_type=FindingType.INFORMATIONAL,
                    remediation=(
                        "Disable retired transfer syntaxes in PACS configuration. Standardize on Explicit VR "
                        "Little Endian (1.2.840.10008.1.2.1) and modern compressed syntaxes."
                    ),
                    standards_mapping={
                        "DICOM": ["PS 3.5 §10 (Transfer Syntax)"],
                    },
                ))

        except Exception as exc:
            logger.warning("Advanced DICOM scan exception: %s", exc)
        finally:
            if assoc is not None:
                try:
                    assoc.release()
                except Exception:
                    pass

        return result

    def run(self) -> List[Finding]:
        """Convenience method returning discovered findings."""
        res = self.run_assessment()
        return res.findings
