"""
network_scanner.py — Real network security scanner engine.

Uses python-nmap for port/service enumeration and requests for HTTP security
header checks.  Only flags findings that are supported by observed evidence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Well-known DICOM ports — open is expected, NOT a finding
KNOWN_DICOM_PORTS = {104, 11112, 2761, 2762, 2575, 4242}

# Ports that typically indicate a web management interface
WEB_PORTS = {80, 443, 8042, 8080, 8443}

# HTTP security headers whose absence may be a finding (context-dependent)
SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: str               # Critical / High / Medium / Low / Informational
    evidence: str               # Actual observed data
    detection_method: str
    confidence: str             # High / Medium / Low
    remediation: str


@dataclass
class PortInfo:
    port: int
    state: str                  # open / closed / filtered
    service_name: str
    product: str
    version: str
    extrainfo: str
    is_dicom_port: bool
    is_web_interface: bool
    is_unexpected_service: bool  # open port with a service not expected for DICOM/medical imaging
    host: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "is_dicom_port": self.is_dicom_port,
            "is_web_interface": self.is_web_interface,
            "ae_response": self.service_name or "TCP-OPEN",
            "echo_success": False,
            "tls_capable": False,
            "response_ms": 0.0,
        }


@dataclass
class HttpHeaderResult:
    url: str
    status_code: Optional[int]
    headers_present: Dict[str, str]    # header name → value
    headers_missing: List[str]         # expected headers that are absent
    directory_listing_found: bool = False
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class NetworkScanResult:
    host: str
    ports_scanned: List[int]
    port_results: List[PortInfo] = field(default_factory=list)
    http_results: List[HttpHeaderResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    nmap_command_line: Optional[str] = None
    error: Optional[str] = None

    @property
    def open_ports(self) -> List[PortInfo]:
        return [p for p in self.port_results if p.state == "open"]


# ---------------------------------------------------------------------------
# nmap scanning
# ---------------------------------------------------------------------------

def _run_nmap(host: str, ports: List[int], intensity: int = 5) -> Dict[str, Any]:
    """
    Run nmap with service version detection (-sV) on *ports* and return the
    raw result dictionary from python-nmap.

    Raises ImportError if python-nmap is not installed.
    Raises nmap.PortScannerError if nmap binary is not found.
    """
    import nmap  # type: ignore

    scanner = nmap.PortScanner()
    port_str = ",".join(str(p) for p in sorted(ports))
    arguments = f"-sV --version-intensity {intensity} -Pn"
    logger.info("nmap %s %s -p %s", arguments, host, port_str)
    scanner.scan(hosts=host, ports=port_str, arguments=arguments)
    return scanner


def _parse_nmap_port(host: str, port: int, nmap_scanner) -> Optional[PortInfo]:
    """
    Extract PortInfo from a python-nmap PortScanner result for one port.

    Returns None if the host is not in the results (e.g. host down).
    """
    try:
        host_data = nmap_scanner[host]
    except KeyError:
        logger.debug("nmap: host %s not in results", host)
        return None

    for proto in ("tcp", "udp"):
        if proto in host_data and port in host_data[proto]:
            pd = host_data[proto][port]
            state        = pd.get("state", "unknown")
            service_name = pd.get("name", "")
            product      = pd.get("product", "")
            version      = pd.get("version", "")
            extrainfo    = pd.get("extrainfo", "")

            is_dicom    = port in KNOWN_DICOM_PORTS
            is_web      = port in WEB_PORTS
            # Unexpected: open, not a DICOM port we expect, not a web interface
            is_unexpected = (
                state == "open"
                and not is_dicom
                and not is_web
                and service_name not in ("", "unknown")
            )

            return PortInfo(
                port=port,
                state=state,
                service_name=service_name,
                product=product,
                version=version,
                extrainfo=extrainfo,
                is_dicom_port=is_dicom,
                is_web_interface=is_web,
                is_unexpected_service=is_unexpected,
            )

    # Port not in nmap results for any protocol → closed/filtered
    return PortInfo(
        port=port,
        state="filtered",
        service_name="",
        product="",
        version="",
        extrainfo="",
        is_dicom_port=port in KNOWN_DICOM_PORTS,
        is_web_interface=port in WEB_PORTS,
        is_unexpected_service=False,
    )


# ---------------------------------------------------------------------------
# HTTP header checking
# ---------------------------------------------------------------------------

def _check_http_headers(host: str, port: int, timeout: float = 10.0) -> HttpHeaderResult:
    """
    Issue an HTTP(S) HEAD request to the web interface on *port* and evaluate
    security headers.  Uses HTTPS for ports 443/8443, HTTP otherwise.
    """
    import requests  # type: ignore
    from requests.exceptions import RequestException

    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    result = HttpHeaderResult(url=url, status_code=None, headers_present={}, headers_missing=[])
    findings: List[Finding] = []

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,          # TLS cert errors handled separately by tls_assessor
            allow_redirects=True,
        )
        result.status_code = resp.status_code
        response_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Evaluate each expected security header
        for header in SECURITY_HEADERS:
            header_lower = header.lower()
            if header_lower in response_headers:
                result.headers_present[header] = response_headers[header_lower]
            else:
                result.headers_missing.append(header)

        # --- Finding: missing HSTS on HTTPS ---
        if scheme == "https" and "strict-transport-security" not in response_headers:
            findings.append(Finding(
                title="Missing HTTP Strict-Transport-Security (HSTS) header on HTTPS endpoint",
                severity="Medium",
                evidence=(
                    f"GET {url} returned HTTP {resp.status_code} without "
                    "Strict-Transport-Security header"
                ),
                detection_method="HTTP response header inspection",
                confidence="High",
                remediation=(
                    "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' "
                    "to all HTTPS responses. This prevents protocol downgrade attacks."
                ),
            ))

        # --- Finding: missing X-Frame-Options ---
        if "x-frame-options" not in response_headers:
            findings.append(Finding(
                title="Missing X-Frame-Options header (potential clickjacking exposure)",
                severity="Low",
                evidence=f"GET {url} returned HTTP {resp.status_code} without X-Frame-Options",
                detection_method="HTTP response header inspection",
                confidence="High",
                remediation=(
                    "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent the page "
                    "from being embedded in an iframe by third-party sites."
                ),
            ))

        # --- Finding: missing Content-Security-Policy ---
        if "content-security-policy" not in response_headers:
            findings.append(Finding(
                title="Missing Content-Security-Policy header",
                severity="Low",
                evidence=f"GET {url} returned HTTP {resp.status_code} without Content-Security-Policy",
                detection_method="HTTP response header inspection",
                confidence="High",
                remediation=(
                    "Define a Content-Security-Policy header to restrict resource loading "
                    "and mitigate cross-site scripting (XSS) attacks."
                ),
            ))

        # --- Finding: directory listing ---
        body = resp.text
        if "Index of" in body and resp.status_code == 200:
            result.directory_listing_found = True
            findings.append(Finding(
                title="Web server directory listing enabled",
                severity="Medium",
                evidence=(
                    f"GET {url} returned HTTP 200 with 'Index of' in body — "
                    "directory contents may be browsable"
                ),
                detection_method="HTTP response body keyword match ('Index of')",
                confidence="Medium",
                remediation=(
                    "Disable directory listing in the web server configuration "
                    "(e.g. 'Options -Indexes' in Apache, 'autoindex off' in Nginx)."
                ),
            ))

    except RequestException as exc:
        result.error = str(exc)
        logger.info("_check_http_headers(%s, %d): %s", host, port, exc)

    result.findings = findings
    return result


# ---------------------------------------------------------------------------
# Unexpected-service finding builder
# ---------------------------------------------------------------------------

def _unexpected_service_finding(pi: PortInfo, host: str) -> Finding:
    return Finding(
        title=f"Unexpected service '{pi.service_name}' on port {pi.port}",
        severity="Informational",
        evidence=(
            f"nmap -sV detected {pi.product} {pi.version} ({pi.service_name}) "
            f"on {host}:{pi.port} state={pi.state}"
        ),
        detection_method="nmap -sV service version detection",
        confidence="Medium",
        remediation=(
            f"Verify whether port {pi.port} should be open on a DICOM/PACS host. "
            "If the service is not required, disable or firewall it to reduce attack surface."
        ),
    )


def _socket_probe_port(host: str, port: int, timeout: float = 1.0) -> PortInfo:
    """Socket-level port reachability probe as robust fallback when nmap binary is missing."""
    import socket
    is_dicom = port in KNOWN_DICOM_PORTS
    is_web = port in WEB_PORTS
    state = "closed"
    service_name = ""
    product = ""
    version = ""

    try:
        with socket.create_connection((host, port), timeout=timeout):
            state = "open"
            if is_dicom:
                service_name = "dicom"
                if port == 4242:
                    product = "Orthanc PACS"
            elif is_web:
                service_name = "http" if port not in (443, 8443) else "https"
                if port == 8042:
                    product = "Orthanc Web / DICOMweb"
    except Exception:
        state = "closed"

    is_unexpected = (
        state == "open"
        and not is_dicom
        and not is_web
        and service_name not in ("", "unknown")
    )

    return PortInfo(
        port=port,
        state=state,
        service_name=service_name,
        product=product,
        version=version,
        extrainfo="",
        is_dicom_port=is_dicom,
        is_web_interface=is_web,
        is_unexpected_service=is_unexpected,
        host=host,
    )


# ---------------------------------------------------------------------------
# High-level scanner
# ---------------------------------------------------------------------------

def scan_network(
    host: str,
    ports: Optional[List[int]] = None,
    http_timeout: float = 10.0,
    nmap_intensity: int = 5,
) -> NetworkScanResult:
    """
    Run a full network scan against *host*.

    1. nmap -sV on all requested ports (or pure socket fallback if nmap is unavailable).
    2. HTTP header checks on any open web-interface ports.
    3. Unexpected-service informational notes.
    """
    if ports is None:
        from engines.dicom_discovery import DICOM_DEFAULT_PORTS
        ports = list(set(DICOM_DEFAULT_PORTS) | WEB_PORTS | {22, 23, 21, 25, 3306, 5432})

    result = NetworkScanResult(
        host=host,
        ports_scanned=ports,
        scan_start=datetime.now(timezone.utc),
    )

    # --- nmap ---
    nmap_succeeded = False
    try:
        import nmap  # type: ignore

        scanner = _run_nmap(host, ports, nmap_intensity)
        try:
            result.nmap_command_line = scanner.command_line()
        except Exception:
            pass

        for port in ports:
            pi = _parse_nmap_port(host, port, scanner)
            if pi is None:
                continue
            pi.host = host
            result.port_results.append(pi)

            if pi.is_unexpected_service and pi.state == "open":
                result.findings.append(_unexpected_service_finding(pi, host))
        nmap_succeeded = len(result.port_results) > 0
    except ImportError:
        result.error = "python-nmap not installed; falling back to native socket probe"
        logger.info(result.error)
    except Exception as exc:
        result.error = f"nmap unavailable ({exc}); falling back to native socket probe"
        logger.info("scan_network socket fallback engaged: %s", exc)

    # --- Pure socket fallback if nmap failed or returned no results ---
    if not nmap_succeeded or not result.port_results:
        result.port_results.clear()
        for port in ports:
            pi = _socket_probe_port(host, port, timeout=min(http_timeout, 1.5))
            result.port_results.append(pi)
            if pi.is_unexpected_service and pi.state == "open":
                result.findings.append(_unexpected_service_finding(pi, host))

    # --- HTTP header checks for open web ports ---
    open_ports = {pi.port for pi in result.port_results if pi.state == "open"}
    for port in sorted(WEB_PORTS & open_ports):
        logger.info("Checking HTTP headers on %s:%d", host, port)
        hr = _check_http_headers(host, port, timeout=http_timeout)
        result.http_results.append(hr)
        result.findings.extend(hr.findings)

    result.scan_end = datetime.now(timezone.utc)
    logger.info(
        "Network scan complete for %s — %d ports, %d open, %d findings",
        host,
        len(result.port_results),
        sum(1 for p in result.port_results if p.state == "open"),
        len(result.findings),
    )
    return result


class NetworkScanner:
    """Class wrapper for NetworkScanner."""

    def __init__(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        timeout: float = 10.0,
        **kwargs: Any,
    ) -> None:
        self.host = host
        self.ports = ports
        self.timeout = timeout

    def run(self) -> NetworkScanResult:
        return scan_network(self.host, self.ports, http_timeout=self.timeout)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Network security scanner")
    parser.add_argument("host")
    parser.add_argument("--ports", nargs="+", type=int)
    parser.add_argument("--http-timeout", type=float, default=10.0)
    args = parser.parse_args()

    scan = scan_network(args.host, args.ports, args.http_timeout)
    print(f"\nHost: {scan.host}  |  Ports scanned: {len(scan.ports_scanned)}")
    for pi in scan.port_results:
        if pi.state == "open":
            tag = "[DICOM]" if pi.is_dicom_port else ("[WEB]" if pi.is_web_interface else "[SVC]")
            print(f"  {tag}  {pi.port}/tcp  {pi.service_name}  {pi.product} {pi.version}")
    print(f"\nFindings ({len(scan.findings)}):")
    for f in scan.findings:
        print(f"  [{f.severity}] {f.title}")
        print(f"    Evidence: {f.evidence}")
