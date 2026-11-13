"""
engines/auth_assessor.py
Authentication and Access Control Assessor for PACS/DICOM Security Assessment Platform.

Evaluates DICOM association access controls and DICOMweb API authentication boundaries.
Does NOT perform destructive attacks, brute-force dictionary attempts, or denial-of-service.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from models.findings import Finding, FindingType, Severity, Confidence

logger = logging.getLogger(__name__)


@dataclass
class AuthAssessmentResult:
    host: str
    dicom_port: int
    web_port: Optional[int]
    anonymous_dicom_allowed: bool
    unauthenticated_dicomweb_detected: bool
    endpoints_tested: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "dicom_port": self.dicom_port,
            "web_port": self.web_port,
            "anonymous_dicom_allowed": self.anonymous_dicom_allowed,
            "unauthenticated_dicomweb_detected": self.unauthenticated_dicomweb_detected,
            "endpoints_tested": self.endpoints_tested,
            "findings": [f.to_dict() for f in self.findings],
        }


class AuthAssessor:
    """
    Evaluates authentication barriers across standard DICOM DIMSE services and DICOMweb REST services.
    """

    def __init__(self, host: str, dicom_port: int = 104, called_ae: str = "ANY-SCP", timeout: int = 5):
        self.host = host
        self.dicom_port = dicom_port
        self.called_ae = called_ae
        self.timeout = timeout

    def assess_dicom_association_auth(self) -> Tuple[bool, List[Finding]]:
        """
        Attempts a DICOM association using the Calling AE 'ANONYMOUS' with Verification SOP Class.
        Tests whether the PACS enforces an Application Entity (AE) whitelist.
        """
        findings: List[Finding] = []
        anon_allowed = False

        try:
            from pynetdicom import AE
            from pynetdicom.sop_class import Verification
        except ImportError:
            logger.warning("pynetdicom not installed; skipping DICOM association auth check")
            return False, findings

        ae = AE(ae_title="ANONYMOUS")
        ae.add_requested_context(Verification)
        ae.network_timeout = self.timeout
        ae.acse_timeout = self.timeout
        ae.dimse_timeout = self.timeout

        try:
            assoc = ae.associate(self.host, self.dicom_port, ae_title=self.called_ae)
            if assoc.is_established:
                anon_allowed = True
                status = assoc.send_c_echo()
                echo_ok = status and status.Status == 0x0000
                assoc.release()

                evidence = (
                    f"Target accepted DICOM Association Request from unwhitelisted Calling AE 'ANONYMOUS'.\n"
                    f"Called AE: '{self.called_ae}'.\n"
                    f"C-ECHO verification response: {'0x0000 (Success)' if echo_ok else 'Accepted without C-ECHO'}.\n"
                    f"The DICOM Upper Layer lacks AE Title filtering, permitting arbitrary network clients to negotiate associations."
                )

                remediation = (
                    "1. Configure strict Application Entity (AE) Title whitelisting on the PACS.\n"
                    "2. Enforce IP address / subnet filtering for all modalities connecting to port {self.dicom_port}.\n"
                    "3. Mandate DICOM-TLS with mutual client certificate validation."
                )

                findings.append(Finding(
                    title="Unauthenticated DICOM Association Acceptance (Missing AE Filtering)",
                    severity=Severity.HIGH,
                    host=self.host,
                    port=self.dicom_port,
                    service="DICOM Upper Layer (DIMSE)",
                    evidence=evidence,
                    detection_method="P-ASSOCIATE-RQ with unauthenticated Calling AE 'ANONYMOUS'",
                    confidence=Confidence.HIGH,
                    finding_type=FindingType.VULNERABILITY,
                    cve_id=None,
                    cvss_score=7.5,
                    remediation=remediation,
                ))
            elif assoc.is_rejected:
                logger.info(f"DICOM association rejected by {self.host}:{self.dicom_port} — access controls active")
                # Do NOT flag rejection as a vulnerability — rejection is expected security behavior!
            assoc.close()
        except Exception as e:
            logger.debug(f"DICOM association attempt exception: {e}")

        return anon_allowed, findings

    def assess_dicomweb_auth(self, web_port: int, use_tls: bool = False) -> Tuple[bool, List[Dict[str, Any]], List[Finding]]:
        """
        Probes standard DICOMweb REST API endpoints (QIDO-RS / WADO-RS) for unauthenticated exposure.
        Validates Content-Type and structural payload before reporting findings.
        """
        findings: List[Finding] = []
        endpoints_tested: List[Dict[str, Any]] = []
        unauth_detected = False

        scheme = "https" if use_tls or web_port in [443, 8443] else "http"
        base_url = f"{scheme}://{self.host}:{web_port}"

        dicomweb_paths = [
            "/dicom-web/studies",
            "/dicomweb/studies",
            "/qido-rs/studies",
            "/pacs/dicom-web/studies",
            "/orthanc/studies",
            "/dcm4chee-arc/aets/DCM4CHEE/rs/studies",
        ]

        for path in dicomweb_paths:
            target_url = f"{base_url}{path}"
            endpoint_record: Dict[str, Any] = {
                "url": target_url,
                "status_code": None,
                "accessible_unauth": False,
            }

            try:
                resp = requests.get(
                    target_url,
                    timeout=self.timeout,
                    verify=False,
                    headers={"Accept": "application/dicom+json, application/json"}
                )
                endpoint_record["status_code"] = resp.status_code

                # Verification: MUST be HTTP 200 AND contain DICOM JSON or clinical study metadata
                if resp.status_code == 200:
                    ct = resp.headers.get("Content-Type", "").lower()
                    text = resp.text.lower()
                    is_dicom_api = (
                        "dicom+json" in ct or
                        "json" in ct and any(tag in text for tag in ["0020000d", "studyinstanceuid", "00100020", "patientid"])
                    )

                    if is_dicom_api:
                        unauth_detected = True
                        endpoint_record["accessible_unauth"] = True

                        evidence = (
                            f"DICOMweb endpoint accessible without credentials: {target_url}\n"
                            f"HTTP Response: 200 OK\n"
                            f"Content-Type: {ct}\n"
                            f"Response contains clinical study metadata or DICOM JSON elements."
                        )

                        remediation = (
                            "1. Implement OAuth2 / OpenID Connect token validation on DICOMweb endpoints.\n"
                            "2. Enforce HTTP Basic or Bearer Authentication at the reverse proxy (e.g. NGINX / Envoy).\n"
                            "3. Restrict DICOMweb REST API to authorized hospital network VLANs."
                        )

                        findings.append(Finding(
                            title="Unauthenticated DICOMweb REST API Exposure",
                            severity=Severity.CRITICAL,
                            host=self.host,
                            port=web_port,
                            service="DICOMweb (QIDO-RS / WADO-RS)",
                            evidence=evidence,
                            detection_method=f"HTTP GET {target_url} without Authorization header",
                            confidence=Confidence.HIGH,
                            finding_type=FindingType.VULNERABILITY,
                            cve_id=None,
                            cvss_score=9.1,
                            remediation=remediation,
                        ))
                        break  # Found confirmed unauthenticated endpoint, avoid duplicate alerts
            except requests.RequestException:
                pass

            endpoints_tested.append(endpoint_record)

        return unauth_detected, endpoints_tested, findings

    def run_full_assessment(self, web_ports: Optional[List[int]] = None) -> AuthAssessmentResult:
        """
        Executes all non-destructive authentication and access boundary assessments.
        """
        all_findings: List[Finding] = []

        # 1. Test DICOM Upper Layer AE Title Filtering
        anon_dicom, dicom_findings = self.assess_dicom_association_auth()
        all_findings.extend(dicom_findings)

        # 2. Test DICOMweb REST services if ports provided
        unauth_web = False
        all_endpoints: List[Dict[str, Any]] = []
        tested_web_port = None

        if web_ports:
            for wp in web_ports:
                tested_web_port = wp
                unauth, endpoints, web_findings = self.assess_dicomweb_auth(wp)
                all_endpoints.extend(endpoints)
                all_findings.extend(web_findings)
                if unauth:
                    unauth_web = True

        return AuthAssessmentResult(
            host=self.host,
            dicom_port=self.dicom_port,
            web_port=tested_web_port,
            anonymous_dicom_allowed=anon_dicom,
            unauthenticated_dicomweb_detected=unauth_web,
            endpoints_tested=all_endpoints,
            findings=all_findings,
        )


def run_auth_assessment(
    host: str,
    port: int = 104,
    called_ae: str = "ANY-SCP",
    timeout: float = 5.0,
    web_ports: Optional[List[int]] = None,
) -> AuthAssessmentResult:
    """
    Convenience function to run authentication assessment.
    """
    assessor = AuthAssessor(host=host, dicom_port=port, called_ae=called_ae, timeout=int(timeout))
    return assessor.run_full_assessment(web_ports=web_ports)

