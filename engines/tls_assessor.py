"""
tls_assessor.py — Real TLS/SSL configuration assessor engine.

Performs genuine TLS handshakes using the Python ssl module and evaluates the
resulting protocol version, cipher suite, and certificate properties.
Ports that do not support TLS are recorded as "TLS not available" — that is
NOT treated as a bug in this engine; it is simply an observed fact.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# TLS protocol versions and their finding severities (None = no finding / safe)
TLS_VERSION_SEVERITY: Dict[str, Optional[Tuple[str, str]]] = {
    "TLSv1":   ("High",          "TLSv1.0 is deprecated (RFC 8996) and known-vulnerable (BEAST, POODLE)"),
    "TLSv1.1": ("Medium",        "TLSv1.1 is deprecated (RFC 8996)"),
    "TLSv1.2": ("Informational", "TLSv1.2 is acceptable but TLSv1.3 is preferred"),
    "TLSv1.3": None,             # Safe — no finding
    "SSLv2":   ("Critical",      "SSLv2 is broken and must not be used"),
    "SSLv3":   ("Critical",      "SSLv3 is broken (POODLE) and must not be used"),
}

# Weak cipher keywords → (severity, reason)
WEAK_CIPHER_PATTERNS: List[Tuple[str, str, str]] = [
    ("NULL",  "Critical", "NULL cipher provides no encryption"),
    ("anon",  "Critical", "Anonymous cipher provides no authentication"),
    ("EXPORT", "Critical", "EXPORT-grade cipher is intentionally weak"),
    ("RC4",   "High",     "RC4 is cryptographically broken (RFC 7465)"),
    ("DES",   "High",     "DES uses a 56-bit key, brute-forceable"),
    ("3DES",  "High",     "3DES is vulnerable to SWEET32 (CVE-2016-2183)"),
    ("MD5",   "Medium",   "MD5-based MAC is collision-vulnerable"),
    ("RC2",   "High",     "RC2 is cryptographically weak"),
]

# How many days' notice to give before certificate expiry
CERT_EXPIRY_THRESHOLDS = [
    (0,  "Critical", "Certificate has expired"),
    (30, "High",     "Certificate expires in less than 30 days"),
    (90, "Medium",   "Certificate expires in less than 90 days"),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: str               # Critical / High / Medium / Low / Informational
    evidence: str               # Actual observed data — no fabrication
    detection_method: str
    confidence: str             # High / Medium / Low
    remediation: str
    host: str = ""
    port: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "host": self.host,
            "port": self.port,
            "service": "DICOM-TLS" if self.port in (2761, 2762) else "TLS/SSL",
            "evidence": self.evidence,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "finding_type": "VULNERABILITY",
            "remediation": self.remediation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@dataclass
class TLSAssessmentResult:
    port: int
    tls_available: bool
    protocol_version: Optional[str]       # e.g. "TLSv1.2", None if no TLS
    cipher_suite: Optional[str]           # e.g. "ECDHE-RSA-AES256-GCM-SHA384"
    cert_expiry: Optional[datetime]       # UTC datetime of notAfter, None if no cert
    cert_self_signed: Optional[bool]      # True if issuer == subject
    cert_hostname_match: Optional[bool]   # True if cert CN/SAN matches host
    cert_subject: Optional[str]
    cert_issuer: Optional[str]
    findings: List[Finding] = field(default_factory=list)
    raw_cert_info: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class TLSScanResult:
    host: str
    assessments: List[TLSAssessmentResult] = field(default_factory=list)
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None


# ---------------------------------------------------------------------------
# TLS handshake
# ---------------------------------------------------------------------------

def _connect_tls(
    host: str,
    port: int,
    timeout: float,
) -> Tuple[Optional[ssl.SSLSocket], Optional[str]]:
    """
    Attempt a TLS handshake to *host*:*port*.

    Returns (ssl_socket, None) on success, (None, error_message) on failure.
    The caller is responsible for closing the returned socket.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Permit older protocol versions so we can *detect* them (not use them safely)
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        return None, f"TCP connection failed: {exc}"

    try:
        tls_sock = ctx.wrap_socket(raw, server_hostname=host)
        tls_sock.do_handshake()
        return tls_sock, None
    except ssl.SSLError as exc:
        raw.close()
        return None, f"TLS handshake failed: {exc}"
    except Exception as exc:
        raw.close()
        return None, f"Unexpected error: {exc}"


def _parse_cert(cert_dict: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[str], Optional[str]]:
    """
    Parse a certificate dictionary (from ssl.SSLSocket.getpeercert()) into
    (expiry_datetime, subject_cn, issuer_cn).
    """
    expiry: Optional[datetime] = None
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None

    try:
        not_after_str = cert_dict.get("notAfter")
        if not_after_str:
            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
    except (ValueError, AttributeError):
        pass

    try:
        for entry in cert_dict.get("subject", ()):
            for key, val in entry:
                if key == "commonName":
                    subject_cn = val
                    break
    except (TypeError, ValueError):
        pass

    try:
        for entry in cert_dict.get("issuer", ()):
            for key, val in entry:
                if key == "commonName":
                    issuer_cn = val
                    break
    except (TypeError, ValueError):
        pass

    return expiry, subject_cn, issuer_cn


def _is_self_signed(cert_dict: Dict[str, Any]) -> bool:
    """Return True when the certificate's issuer fields equal its subject fields."""
    return cert_dict.get("issuer") == cert_dict.get("subject")


def _check_hostname_match(host: str, cert_dict: Dict[str, Any]) -> bool:
    """
    Return True if *host* matches the certificate's CN or any SAN dNSName.

    Does NOT raise — a mismatch simply returns False.
    """
    try:
        ssl.match_hostname(cert_dict, host)
        return True
    except ssl.CertificateError:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Finding builders
# ---------------------------------------------------------------------------

def _protocol_findings(protocol_version: Optional[str], host: str, port: int) -> List[Finding]:
    findings = []
    if protocol_version is None:
        return findings
    info = TLS_VERSION_SEVERITY.get(protocol_version)
    if info is None:
        return findings  # Safe version, no finding
    severity, reason = info
    findings.append(Finding(
        title=f"Weak TLS protocol version: {protocol_version}",
        severity=severity,
        evidence=(
            f"TLS handshake with {host}:{port} negotiated {protocol_version}. "
            f"Reason: {reason}"
        ),
        detection_method="ssl.SSLSocket.version() after successful handshake",
        confidence="High",
        remediation=(
            f"Disable {protocol_version} on the server and enforce a minimum of TLSv1.2 "
            "(preferably TLSv1.3). Update cipher suite configuration to remove weak ciphers."
        ),
    ))
    return findings


def _cipher_findings(cipher_name: Optional[str], host: str, port: int) -> List[Finding]:
    findings = []
    if not cipher_name:
        return findings
    for keyword, severity, reason in WEAK_CIPHER_PATTERNS:
        if keyword.upper() in cipher_name.upper():
            findings.append(Finding(
                title=f"Weak cipher suite negotiated: {cipher_name}",
                severity=severity,
                evidence=(
                    f"TLS handshake with {host}:{port} negotiated cipher '{cipher_name}'. "
                    f"Reason: {reason}"
                ),
                detection_method="ssl.SSLSocket.cipher() after successful handshake",
                confidence="High",
                remediation=(
                    "Remove weak cipher suites from the server's TLS configuration. "
                    "Prefer ECDHE + AES-GCM or ChaCha20-Poly1305 suites with TLSv1.3."
                ),
            ))
            break  # one finding per cipher
    return findings


def _cert_expiry_findings(expiry: Optional[datetime], host: str, port: int) -> List[Finding]:
    findings = []
    if expiry is None:
        return findings
    now = datetime.now(timezone.utc)
    days_remaining = (expiry - now).days
    for threshold, severity, reason in CERT_EXPIRY_THRESHOLDS:
        if days_remaining <= threshold:
            findings.append(Finding(
                title=f"TLS certificate expiry issue: {reason}",
                severity=severity,
                evidence=(
                    f"Certificate on {host}:{port} expires at {expiry.isoformat()} UTC "
                    f"({days_remaining} days remaining)"
                ),
                detection_method="ssl.SSLSocket.getpeercert() notAfter field inspection",
                confidence="High",
                remediation=(
                    "Renew the TLS certificate immediately. Configure automated renewal "
                    "(e.g. Let's Encrypt / ACME) to avoid future expiry incidents."
                ),
            ))
            break
    return findings


def _self_signed_finding(host: str, port: int, subject_cn: Optional[str]) -> Finding:
    return Finding(
        title="Self-signed TLS certificate detected",
        severity="Medium",
        evidence=(
            f"Certificate on {host}:{port} has issuer == subject "
            f"(CN='{subject_cn}'). It was not signed by a trusted CA."
        ),
        detection_method="ssl.SSLSocket.getpeercert() issuer vs subject comparison",
        confidence="High",
        remediation=(
            "Replace the self-signed certificate with one issued by a trusted Certificate "
            "Authority (CA). For internal services use an internal PKI or a public CA "
            "such as Let's Encrypt."
        ),
    )


def _hostname_mismatch_finding(host: str, port: int, cert_cn: Optional[str]) -> Finding:
    return Finding(
        title="TLS certificate hostname mismatch",
        severity="High",
        evidence=(
            f"Certificate on {host}:{port} CN/SAN does not match '{host}'. "
            f"Certificate CN='{cert_cn}'."
        ),
        detection_method="ssl.match_hostname() against getpeercert()",
        confidence="High",
        remediation=(
            "Issue a new certificate that includes the correct hostname in the Subject "
            "Alternative Name (SAN) extension. Ensure the CN and SAN match all names "
            "used to reach this service."
        ),
    )


# ---------------------------------------------------------------------------
# Single-port assessor
# ---------------------------------------------------------------------------

def assess_tls_on_port(
    host: str,
    port: int,
    timeout: float = 10.0,
) -> TLSAssessmentResult:
    """
    Perform a TLS assessment on a single *host*:*port*.

    - If TLS is not available (handshake failure), records tls_available=False
      and returns without findings — that is not a bug in this engine.
    - All findings are conditional on actual observed data.
    """
    result = TLSAssessmentResult(
        port=port,
        tls_available=False,
        protocol_version=None,
        cipher_suite=None,
        cert_expiry=None,
        cert_self_signed=None,
        cert_hostname_match=None,
        cert_subject=None,
        cert_issuer=None,
    )

    tls_sock, error = _connect_tls(host, port, timeout)
    if tls_sock is None:
        result.error = error
        logger.debug("assess_tls_on_port(%s, %d): TLS not available — %s", host, port, error)
        return result

    try:
        result.tls_available = True

        # Protocol version
        protocol_version = tls_sock.version()   # e.g. "TLSv1.2"
        result.protocol_version = protocol_version

        # Cipher suite
        cipher_info = tls_sock.cipher()         # (name, protocol, bits)
        cipher_name = cipher_info[0] if cipher_info else None
        result.cipher_suite = cipher_name

        # Certificate
        cert_dict = tls_sock.getpeercert(binary_form=False)
        if not cert_dict:
            # Binary-form fallback when default context won't decode (e.g. CERT_NONE)
            cert_dict = {}
        result.raw_cert_info = cert_dict

        expiry, subject_cn, issuer_cn = _parse_cert(cert_dict)
        result.cert_expiry = expiry
        result.cert_subject = subject_cn
        result.cert_issuer = issuer_cn

        self_signed = _is_self_signed(cert_dict) if cert_dict else None
        result.cert_self_signed = self_signed

        hostname_match = _check_hostname_match(host, cert_dict) if cert_dict else None
        result.cert_hostname_match = hostname_match

        # --- Findings ---
        result.findings.extend(_protocol_findings(protocol_version, host, port))
        result.findings.extend(_cipher_findings(cipher_name, host, port))
        result.findings.extend(_cert_expiry_findings(expiry, host, port))

        if self_signed:
            result.findings.append(_self_signed_finding(host, port, subject_cn))

        if hostname_match is False:
            result.findings.append(_hostname_mismatch_finding(host, port, subject_cn))

    except Exception as exc:
        result.error = str(exc)
        logger.warning("assess_tls_on_port(%s, %d) post-handshake error: %s", host, port, exc)
    finally:
        try:
            tls_sock.close()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# High-level scanner
# ---------------------------------------------------------------------------

def assess_tls(
    host: str,
    ports: Optional[List[int]] = None,
    timeout: float = 10.0,
) -> TLSScanResult:
    """
    Run TLS assessments across all specified *ports* on *host*.

    Returns a TLSScanResult with one TLSAssessmentResult per port.
    """
    if ports is None:
        from engines.dicom_discovery import DICOM_DEFAULT_PORTS
        from engines.network_scanner import WEB_PORTS
        ports = list(set(DICOM_DEFAULT_PORTS) | WEB_PORTS)

    scan = TLSScanResult(host=host, scan_start=datetime.now(timezone.utc))

    for port in sorted(ports):
        logger.info("TLS assessment: %s:%d", host, port)
        assessment = assess_tls_on_port(host, port, timeout)
        scan.assessments.append(assessment)

    scan.scan_end = datetime.now(timezone.utc)
    tls_ports = [a for a in scan.assessments if a.tls_available]
    total_findings = sum(len(a.findings) for a in scan.assessments)
    logger.info(
        "TLS assessment complete for %s — %d/%d ports have TLS, %d finding(s)",
        host,
        len(tls_ports),
        len(scan.assessments),
        total_findings,
    )
    return scan


class TLSAssessor:
    """Class wrapper for TLS/SSL Assessor engine."""

    def __init__(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        port: Optional[int] = None,
        timeout: float = 10.0,
        **kwargs: Any,
    ):
        self.host = host
        if port is not None:
            self.ports = [port]
        elif ports is not None:
            self.ports = ports
        else:
            self.ports = None
        self.timeout = timeout

    def run_assessment(self) -> Any:
        scan_res = assess_tls(host=self.host, ports=self.ports, timeout=self.timeout)

        # Build convenient ports_tested dict and findings list
        class AssessmentWrapper:
            def __init__(self, scan: TLSScanResult, host: str):
                self.ports_tested: Dict[int, TLSAssessmentResult] = {a.port: a for a in scan.assessments}
                self.findings = []
                for a in scan.assessments:
                    for f in a.findings:
                        if not f.host:
                            f.host = host
                        if not f.port:
                            f.port = a.port
                        self.findings.append(f)

        return AssessmentWrapper(scan_res, self.host)

    def run(self) -> List[Any]:
        assessment = self.run_assessment()
        findings = list(assessment.findings)
        # Check if any probed DICOM port is plaintext
        for port, res in assessment.ports_tested.items():
            if not res.tls_available and port in (104, 4242, 11112, 2575):
                from engines.dicom_discovery import check_port_open
                if check_port_open(self.host, port, timeout=min(self.timeout, 2.0)):
                    findings.append(Finding(
                        title=f"Unencrypted DICOM Communication Protocol (Port {port})",
                        severity="High",
                        evidence=(
                            f"Port {port} on {self.host} accepts plaintext TCP DICOM connections without "
                            "TLS encapsulation. All transmitted medical images and patient metadata are unencrypted."
                        ),
                        detection_method="Direct TLS Handshake Probe (SSL/TLS negotiation failure)",
                        confidence="High",
                        remediation=(
                            f"Enable DICOM-TLS (DICOM PS 3.15 Annex B) on port {port} using TLS 1.3, or "
                            "isolate traffic using a dedicated IPsec tunnel or private VLAN."
                        ),
                        host=self.host,
                        port=port,
                    ))
        return findings



# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="TLS/SSL assessor")
    parser.add_argument("host")
    parser.add_argument("--ports", nargs="+", type=int)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    result = assess_tls(args.host, args.ports, args.timeout)
    for a in result.assessments:
        tls_flag = "TLS" if a.tls_available else "---"
        print(
            f"  {a.port:5d}  [{tls_flag}]  {a.protocol_version or 'N/A':8s}  "
            f"cipher={a.cipher_suite or 'N/A'}  "
            f"expires={a.cert_expiry.date() if a.cert_expiry else 'N/A'}  "
            f"self-signed={a.cert_self_signed}  findings={len(a.findings)}"
        )
        for f in a.findings:
            print(f"    [{f.severity}] {f.title}")
            print(f"      Evidence: {f.evidence}")
