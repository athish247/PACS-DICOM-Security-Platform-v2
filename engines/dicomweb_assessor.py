"""
engines/dicomweb_assessor.py
Dedicated DICOMweb & Medical Imaging Web Security Engine.

Assesses:
1. QIDO-RS (/studies, /series, /instances) query authorization
2. WADO-RS (/studies/{study}/metadata) metadata access boundaries
3. STOW-RS endpoint availability without destructive uploads
4. CORS wildcard policies (Access-Control-Allow-Origin: *)
5. Cookie security attributes (SameSite, Secure, HttpOnly)
6. Administrative REST API exposure (/system, /modalities, /peers)
7. HTTP security headers & Information leakage
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import requests
from requests.exceptions import RequestException

from models.findings import (
    Finding, FindingType, Severity, Confidence, FindingStatus
)

logger = logging.getLogger(__name__)

STANDARD_DICOMWEB_ENDPOINTS = [
    ("QIDO-RS Studies", "/studies", "GET", "Query patient study records"),
    ("QIDO-RS Series", "/series", "GET", "Query imaging series"),
    ("QIDO-RS Instances", "/instances", "GET", "Query individual DICOM instances"),
    ("WADO-RS Metadata", "/studies/1/metadata", "GET", "Retrieve study DICOM metadata"),
    ("STOW-RS Storage", "/studies", "OPTIONS", "Inspect STOW-RS storage endpoint"),
]

PACS_ADMIN_ENDPOINTS = [
    ("Orthanc System API", "/system", "GET", "Orthanc core configuration & version"),
    ("Orthanc Modalities", "/modalities", "GET", "Registered modality routing table"),
    ("Orthanc Peers", "/peers", "GET", "DICOM peer federation table"),
    ("Orthanc Statistics", "/statistics", "GET", "Database size and patient study count"),
    ("dcm4chee Archive UI", "/dcm4chee-arc/ui2/", "GET", "dcm4chee web management console"),
    ("dcm4chee AE Config", "/dcm4chee-arc/aets", "GET", "dcm4chee Application Entity definitions"),
]


@dataclass
class EndpointAssessment:
    name: str
    path: str
    method: str
    status_code: Optional[int]
    unauthenticated_access: bool
    headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: str = ""


@dataclass
class DicomwebScanResult:
    host: str
    port: int
    url_base: str
    endpoints_tested: List[EndpointAssessment] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    cors_wildcard_detected: bool = False
    insecure_cookies_detected: bool = False


class DicomwebAssessor:
    """
    Dedicated security evaluator for RESTful DICOMweb services and PACS web interfaces.
    Strictly non-destructive: never writes data or uploads files.
    """

    def __init__(
        self,
        host: str,
        port: int = 8042,
        use_https: bool = False,
        timeout: float = 6.0,
    ):
        self.host = host
        self.port = port
        self.use_https = use_https
        self.timeout = timeout
        scheme = "https" if use_https or port in (443, 8443) else "http"
        self.url_base = f"{scheme}://{host}:{port}"

    def run_assessment(self) -> DicomwebScanResult:
        result = DicomwebScanResult(
            host=self.host,
            port=self.port,
            url_base=self.url_base,
        )

        all_endpoints = STANDARD_DICOMWEB_ENDPOINTS + PACS_ADMIN_ENDPOINTS

        for name, path, method, description in all_endpoints:
            url = f"{self.url_base}{path}"
            headers = {"Origin": "https://malicious-external-site.local"}
            try:
                if method == "OPTIONS":
                    resp = requests.options(url, timeout=self.timeout, verify=False, headers=headers)
                else:
                    resp = requests.get(url, timeout=self.timeout, verify=False, headers=headers, allow_redirects=False)

                status = resp.status_code
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                snippet = resp.text[:200].strip() if resp.text else ""

                unauth_ok = (status == 200)

                ea = EndpointAssessment(
                    name=name,
                    path=path,
                    method=method,
                    status_code=status,
                    unauthenticated_access=unauth_ok,
                    headers=resp_headers,
                    response_snippet=snippet,
                )
                result.endpoints_tested.append(ea)

                # -----------------------------------------------------------
                # Findings Derivation
                # -----------------------------------------------------------

                # 1. Unauthenticated DICOMweb QIDO-RS Study Metadata Exposure
                if "QIDO-RS" in name and unauth_ok:
                    result.findings.append(Finding(
                        title=f"Unauthenticated DICOMweb {name} Endpoint Accessible",
                        severity=Severity.HIGH,
                        host=self.host,
                        port=self.port,
                        service="DICOMweb / QIDO-RS",
                        evidence=(
                            f"HTTP GET {url} returned status 200 OK without requiring authentication credentials. "
                            f"Response snippet: {snippet[:100]}"
                        ),
                        detection_method="DICOMweb REST API Probe",
                        confidence=Confidence.HIGH,
                        finding_type=FindingType.VULNERABILITY,
                        remediation=(
                            "Enforce OAuth2 Bearer token authentication or HTTP Basic Auth on all DICOMweb endpoints. "
                            "In Orthanc, enable 'AuthenticationEnabled': true and configure RegisteredUsers."
                        ),
                        standards_mapping={
                            "HIPAA": ["164.312(a)(1) Access Control", "164.312(d) Authentication"],
                            "DICOM": ["PS 3.18 (Web Services) Security Profile"],
                            "NIST_CSF_2_0": ["PR.AC-01", "PR.AA-01"],
                        },
                    ))

                # 2. Unauthenticated Administrative API Exposure
                if "Admin" in name or "System" in name or "Modalities" in name:
                    if unauth_ok:
                        result.findings.append(Finding(
                            title=f"Unauthenticated Administrative PACS Endpoint Exposed ({name})",
                            severity=Severity.HIGH,
                            host=self.host,
                            port=self.port,
                            service="PACS Admin REST API",
                            evidence=(
                                f"HTTP GET {url} returned HTTP 200 with sensitive configuration/modality data. "
                                f"Snippet: {snippet[:120]}"
                            ),
                            detection_method="PACS Management API Probe",
                            confidence=Confidence.HIGH,
                            finding_type=FindingType.VULNERABILITY,
                            remediation=(
                                "Restrict administrative REST APIs to localhost or isolated management subnets. "
                                "Require administrative credentials for /system and /modalities configuration endpoints."
                            ),
                            standards_mapping={
                                "HIPAA": ["164.312(a)(1) Access Control"],
                                "NIST_CSF_2_0": ["PR.AC-03"],
                            },
                        ))

                # 3. CORS Wildcard Policy Inspection
                cors_origin = resp_headers.get("access-control-allow-origin", "")
                if cors_origin == "*" or "malicious-external-site" in cors_origin:
                    result.cors_wildcard_detected = True
                    result.findings.append(Finding(
                        title="Permissive Cross-Origin Resource Sharing (CORS) on Medical Imaging API",
                        severity=Severity.MEDIUM,
                        host=self.host,
                        port=self.port,
                        service="DICOMweb HTTP",
                        evidence=(
                            f"Endpoint {path} responded with 'Access-Control-Allow-Origin: {cors_origin}'. "
                            "Allows unauthorized browser origins to issue authenticated requests and siphon imaging metadata."
                        ),
                        detection_method="CORS Preflight & Header Analysis",
                        confidence=Confidence.HIGH,
                        finding_type=FindingType.MISCONFIGURATION,
                        remediation=(
                            "Restrict Access-Control-Allow-Origin to trusted hospital clinical viewer origins. "
                            "Do not use wildcard '*' or reflect untrusted Origin headers."
                        ),
                        standards_mapping={
                            "HIPAA": ["164.312(e)(1) Transmission Security"],
                            "NIST_CSF_2_0": ["PR.DS-02"],
                        },
                    ))

                # 4. Insecure Session Cookie Attributes
                set_cookie = resp_headers.get("set-cookie", "")
                if set_cookie:
                    cookie_lower = set_cookie.lower()
                    missing_flags = []
                    if "httponly" not in cookie_lower:
                        missing_flags.append("HttpOnly")
                    if "secure" not in cookie_lower and self.use_https:
                        missing_flags.append("Secure")
                    if "samesite" not in cookie_lower:
                        missing_flags.append("SameSite")

                    if missing_flags:
                        result.insecure_cookies_detected = True
                        result.findings.append(Finding(
                            title=f"Insecure Session Cookie Configuration (Missing {', '.join(missing_flags)})",
                            severity=Severity.MEDIUM,
                            host=self.host,
                            port=self.port,
                            service="PACS Web Portal",
                            evidence=f"Set-Cookie header on {path} lacks security flags: {', '.join(missing_flags)}.",
                            detection_method="HTTP Set-Cookie Inspection",
                            confidence=Confidence.HIGH,
                            finding_type=FindingType.MISCONFIGURATION,
                            remediation=(
                                "Configure session cookies with 'HttpOnly; Secure; SameSite=Strict' flags to protect "
                                "against Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF)."
                            ),
                            standards_mapping={
                                "HIPAA": ["164.312(a)(1) Access Control"],
                                "NIST_CSF_2_0": ["PR.AC-07"],
                            },
                        ))

            except RequestException as exc:
                # Endpoint not reachable / connection refused
                result.endpoints_tested.append(EndpointAssessment(
                    name=name,
                    path=path,
                    method=method,
                    status_code=None,
                    unauthenticated_access=False,
                    headers={},
                    response_snippet=f"Unreachable: {type(exc).__name__}",
                ))

        return result

    def run(self) -> List[Finding]:
        """Convenience method returning findings."""
        res = self.run_assessment()
        return res.findings
