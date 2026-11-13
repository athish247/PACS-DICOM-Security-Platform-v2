"""
engines/metadata_analyzer.py
DICOM Metadata Privacy Analyzer for PACS/DICOM Security Assessment Platform.

Audits DICOM datasets and files for Protected Health Information (PHI) exposure
according to HIPAA Privacy Rule (45 CFR § 164.514) and DICOM PS 3.15 Annex E
(Basic Application Level Confidentiality Profile).
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from models.findings import Finding, FindingType, Severity, Confidence

logger = logging.getLogger(__name__)

# Standard DICOM PS 3.15 Table E.1-1 Core De-identification Tags
CORE_PHI_TAGS = [
    (0x0010, 0x0010, "PatientName", "Direct Patient Identifier"),
    (0x0010, 0x0020, "PatientID", "Direct Medical Record / ID Number"),
    (0x0010, 0x0030, "PatientBirthDate", "Date of Birth (HIPAA Safe Harbor)"),
    (0x0010, 0x0040, "PatientSex", "Demographic Attribute"),
    (0x0010, 0x1000, "OtherPatientIDs", "Secondary Patient Identifier"),
    (0x0010, 0x1010, "PatientAge", "Age over 89 requires aggregation under HIPAA"),
    (0x0010, 0x1040, "PatientAddress", "Geographic Identifier"),
    (0x0010, 0x2160, "EthnicGroup", "Demographic Identifier"),
    (0x0008, 0x0080, "InstitutionName", "Facility / Institutional Identifier"),
    (0x0008, 0x0081, "InstitutionAddress", "Institutional Physical Location"),
    (0x0008, 0x0090, "ReferringPhysicianName", "Physician Identifier"),
    (0x0008, 0x1050, "PerformingPhysicianName", "Staff Identifier"),
    (0x0008, 0x1070, "OperatorsName", "Operator / Technician Identifier"),
    (0x0020, 0x0010, "StudyID", "Study Tracking Number"),
    (0x0008, 0x0050, "AccessionNumber", "Order / Encounter Identifier"),
]


@dataclass
class PHITagMatch:
    tag_hex: str
    tag_name: str
    category: str
    present: bool
    is_empty: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag_hex": self.tag_hex,
            "tag_name": self.tag_name,
            "category": self.category,
            "present": self.present,
            "is_empty": self.is_empty,
        }


@dataclass
class MetadataAnalysisResult:
    filepath: str
    phi_detected: bool
    non_empty_phi_count: int
    tags_found: List[PHITagMatch] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filepath": self.filepath,
            "phi_detected": self.phi_detected,
            "non_empty_phi_count": self.non_empty_phi_count,
            "tags_found": [t.to_dict() for t in self.tags_found],
            "findings": [f.to_dict() for f in self.findings],
            "remediation": self.remediation,
        }


class MetadataPrivacyAnalyzer:
    """
    Analyzes DICOM files and datasets for unmasked PHI exposure.
    Adheres strictly to safe data handling: never persists raw patient values.
    """

    def __init__(self, host: str = "local", port: int = 0):
        self.host = host
        self.port = port

    def analyze_file(self, filepath: str) -> MetadataAnalysisResult:
        """
        Parses a single DICOM file on disk using pydicom.
        """
        if not os.path.isfile(filepath):
            return MetadataAnalysisResult(
                filepath=filepath,
                phi_detected=False,
                non_empty_phi_count=0,
                remediation="File does not exist.",
            )

        try:
            import pydicom
        except ImportError:
            logger.error("pydicom library not installed")
            return MetadataAnalysisResult(
                filepath=filepath,
                phi_detected=False,
                non_empty_phi_count=0,
                remediation="Install pydicom to enable DICOM file metadata analysis.",
            )

        try:
            ds = pydicom.dcmread(filepath, stop_before_pixels=True)
        except Exception as e:
            logger.warning(f"Could not parse DICOM file {filepath}: {e}")
            return MetadataAnalysisResult(
                filepath=filepath,
                phi_detected=False,
                non_empty_phi_count=0,
                remediation=f"Invalid or corrupted DICOM file: {e}",
            )

        return self.analyze_dataset(ds, filepath)

    def analyze_dataset(self, ds: Any, source_desc: str = "Memory Dataset") -> MetadataAnalysisResult:
        """
        Inspects an in-memory pydicom Dataset for non-empty PHI tags.
        """
        tags_found: List[PHITagMatch] = []
        non_empty_tags: List[str] = []

        DEID_TOKENS = {"ANONYMOUS", "ANONYMIZED", "DE-IDENTIFIED", "DEIDENTIFIED", "ANON", "NULL", "NONE", "REDACTED", "DUMMY"}

        for group, element, name, category in CORE_PHI_TAGS:
            tag_hex = f"({group:04X},{element:04X})"
            if (group, element) in ds:
                elem = ds[group, element]
                val = elem.value
                val_str = str(val).strip() if val is not None else ""
                is_empty = (val_str == "")
                is_anonymized = any(token in val_str.upper() for token in DEID_TOKENS)

                if not is_empty and not is_anonymized:
                    non_empty_tags.append(name)

                tags_found.append(PHITagMatch(
                    tag_hex=tag_hex,
                    tag_name=name,
                    category=category,
                    present=True,
                    is_empty=(is_empty or is_anonymized)
                ))

        phi_detected = len(non_empty_tags) > 0
        findings: List[Finding] = []

        if phi_detected:
            tag_summary = ", ".join(non_empty_tags[:8])
            if len(non_empty_tags) > 8:
                tag_summary += f" (+{len(non_empty_tags) - 8} more)"

            evidence = (
                f"Source: {source_desc}\n"
                f"Identified {len(non_empty_tags)} unmasked PHI elements: {tag_summary}.\n"
                f"Direct patient identity and clinical metadata are retained without de-identification."
            )

            remediation = (
                "1. Apply automated DICOM PS 3.15 Annex E anonymization before exporting datasets.\n"
                "2. Strip or hash PatientID, PatientName, BirthDate, and institutional tags.\n"
                "3. Use specialized PACS gateway routing rules to prevent unmasked external egress."
            )

            severity = Severity.HIGH if any(t in non_empty_tags for t in ["PatientName", "PatientID"]) else Severity.MEDIUM

            findings.append(Finding(
                title="Unmasked Protected Health Information (PHI) in DICOM Metadata",
                severity=severity,
                host=self.host,
                port=self.port,
                service="DICOM Storage / Media",
                evidence=evidence,
                detection_method="DICOM PS 3.15 Tag Presence Inspection",
                confidence=Confidence.HIGH,
                finding_type=FindingType.VULNERABILITY,
                cve_id=None,
                cvss_score=7.5 if severity == Severity.HIGH else 5.3,
                remediation=remediation,
            ))

        return MetadataAnalysisResult(
            filepath=source_desc,
            phi_detected=phi_detected,
            non_empty_phi_count=len(non_empty_tags),
            tags_found=tags_found,
            findings=findings,
            remediation="Ensure de-identification pipeline conforms to HIPAA 164.514." if phi_detected else "No unmasked PHI tags detected.",
        )

    @staticmethod
    def create_synthetic_test_file(filepath: str, include_phi: bool = True) -> str:
        """
        Creates a valid synthetic DICOM file for controlled unit and integration testing.
        Uses purely fictional test data.
        """
        import pydicom
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian, SecondaryCaptureImageStorage, generate_uid

        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

        ds = Dataset()
        ds.file_meta = file_meta
        ds.is_little_endian = True
        ds.is_implicit_VR = False

        ds.SOPClassUID = SecondaryCaptureImageStorage
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()
        ds.Modality = "OT"

        if include_phi:
            ds.PatientName = "SYNTHETIC^DOE^JOHN"
            ds.PatientID = "TEST-MRN-99999"
            ds.PatientBirthDate = "19800101"
            ds.PatientSex = "M"
            ds.InstitutionName = "TEST CYBERSECURITY LAB"
            ds.ReferringPhysicianName = "TEST^DR^SECURE"
        else:
            ds.PatientName = "ANONYMIZED"
            ds.PatientID = "ANON-00000"

        # Minimal 1x1 pixel data to ensure valid DICOM
        ds.Rows = 1
        ds.Columns = 1
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PixelData = b'\x00'

        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        ds.save_as(filepath, write_like_original=False)
        return filepath


def analyze_dicom_file(filepath: str, host: str = "local", port: int = 0) -> MetadataAnalysisResult:
    """
    Convenience function for metadata privacy analysis of a DICOM file.
    """
    analyzer = MetadataPrivacyAnalyzer(host=host, port=port)
    return analyzer.analyze_file(filepath)

