"""
dicom_discovery.py — Real DICOM service discovery engine.

Uses pynetdicom to perform genuine C-ECHO (Verification SOP Class) probes.
Never declares a service vulnerable simply because it responded.
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DICOM_DEFAULT_PORTS: List[int] = [104, 11112, 2761, 2762, 2575, 4242]

DICOM_PORT_LABELS: Dict[int, str] = {
    104: "DICOM standard (unencrypted)",
    11112: "DICOM standard (unencrypted, alternate)",
    2761: "DICOM TLS",
    2762: "DICOM TLS (alternate)",
    2575: "DICOM HL7/TCP",
    4242: "DICOM Orthanc default",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DicomService:
    """Result of probing a single host/port for DICOM service presence."""

    host: str
    port: int
    ae_title_response: Optional[str]       # AE title returned by remote (if any)
    echo_success: bool                     # True only if C-ECHO received C-ECHO-RSP with Success status
    tls_capable: bool                      # True if TLS handshake succeeded on this port
    response_time_ms: Optional[float]      # Round-trip time for the C-ECHO, None on failure
    raw_pdu_info: Dict[str, Any]           # Raw PDU metadata captured during the association
    timestamp: datetime                    # UTC time of the probe
    port_open: bool = False                # TCP-level reachability
    error: Optional[str] = None           # Human-readable error if the probe failed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ae_response": self.ae_title_response,
            "ae_title_response": self.ae_title_response,
            "echo_success": self.echo_success,
            "tls_capable": self.tls_capable,
            "response_ms": self.response_time_ms,
            "response_time_ms": self.response_time_ms,
            "raw_pdu_info": self.raw_pdu_info,
            "port_open": self.port_open,
            "error": self.error,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class DiscoveryScanResult:
    """Aggregated result for scanning all ports on a host."""

    host: str
    services: List[DicomService] = field(default_factory=list)
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None

    def __iter__(self):
        return iter(self.services)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def check_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Test raw TCP reachability of host:port within *timeout* seconds.

    Returns True only if the three-way handshake completes.
    A closed or filtered port returns False; errors are logged.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, socket.timeout):
        return False
    except OSError as exc:
        logger.debug("check_port_open(%s, %d): %s", host, port, exc)
        return False


def _probe_tls(host: str, port: int, timeout: float = 5.0) -> bool:
    """
    Attempt a bare TLS handshake to determine whether the port speaks TLS.

    Returns True only when the handshake succeeds.  A failure (including
    ssl.SSLError) is NOT reported as a vulnerability here — it is simply
    recorded as "TLS not available on this port".
    """
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                tls_sock.do_handshake()
                return True
    except Exception as exc:
        logger.debug("_probe_tls(%s, %d): %s", host, port, exc)
        return False


# ---------------------------------------------------------------------------
# Core DICOM probe
# ---------------------------------------------------------------------------

def send_dicom_echo(
    host: str,
    port: int,
    called_ae: str = "ANY-SCP",
    calling_ae: str = "PACS-ASSESS",
    timeout: float = 10.0,
) -> DicomService:
    """
    Attempt a real DICOM C-ECHO (Verification SOP Class) to *host*:*port*.

    Uses pynetdicom to establish an association, send a C-ECHO-RQ, and
    capture the response.  Every outcome is faithfully recorded; no finding
    is fabricated.

    Parameters
    ----------
    host:       Target DICOM node hostname/IP.
    port:       Target TCP port.
    called_ae:  Called AE Title sent in the A-ASSOCIATE-RQ.
    calling_ae: Calling AE Title (our identity).
    timeout:    Network timeout in seconds.

    Returns
    -------
    DicomService dataclass populated with actual observed data.
    """
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore

    timestamp = datetime.now(timezone.utc)
    raw_pdu_info: Dict[str, Any] = {}

    # --- TCP reachability first ---
    port_open = check_port_open(host, port, timeout=min(timeout, 5.0))
    if not port_open:
        return DicomService(
            host=host,
            port=port,
            ae_title_response=None,
            echo_success=False,
            tls_capable=False,
            response_time_ms=None,
            raw_pdu_info={},
            timestamp=timestamp,
            port_open=False,
            error="TCP port not reachable",
        )

    # --- TLS probe (informational only) ---
    tls_capable = _probe_tls(host, port, timeout=min(timeout, 5.0))

    # --- DICOM association + C-ECHO ---
    ae = AE(ae_title=calling_ae)
    ae.add_requested_context(Verification)
    ae.acse_timeout = timeout
    ae.dimse_timeout = timeout
    ae.network_timeout = timeout

    echo_success = False
    ae_title_response: Optional[str] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None

    t0 = time.monotonic()
    assoc = None
    try:
        assoc = ae.associate(host, port, ae_title=called_ae)

        if assoc.is_established:
            raw_pdu_info["association_accepted"] = True
            # Capture the responding AE title from the A-ASSOCIATE-AC
            try:
                ae_title_response = (
                    assoc.acceptor.ae_title.strip()
                    if assoc.acceptor and assoc.acceptor.ae_title
                    else None
                )
                raw_pdu_info["called_ae_title"] = ae_title_response
            except AttributeError:
                pass

            # Send C-ECHO-RQ
            status = assoc.send_c_echo()
            elapsed = (time.monotonic() - t0) * 1000.0
            response_time_ms = round(elapsed, 2)

            if status and hasattr(status, "Status"):
                raw_pdu_info["c_echo_status"] = hex(status.Status)
                # 0x0000 = Success
                echo_success = (status.Status == 0x0000)
            elif status:
                # send_c_echo returns (status_dataset, identifier) in some versions
                try:
                    ds, _ = status
                    raw_pdu_info["c_echo_status"] = hex(ds.Status) if ds else "None"
                    echo_success = bool(ds and ds.Status == 0x0000)
                except (TypeError, ValueError, AttributeError):
                    raw_pdu_info["c_echo_status"] = str(status)

        elif assoc.is_rejected:
            raw_pdu_info["association_accepted"] = False
            raw_pdu_info["rejection_reason"] = "A-ASSOCIATE-RJ received"
            # Rejection is not a vulnerability — it means access control is working
            error = "Association rejected by remote AE"

        elif assoc.is_aborted:
            raw_pdu_info["association_accepted"] = False
            raw_pdu_info["abort_reason"] = "A-ABORT received"
            error = "Association aborted by remote AE"

        else:
            raw_pdu_info["association_accepted"] = False
            error = "Association failed (unknown reason)"

    except Exception as exc:
        logger.warning("send_dicom_echo(%s, %d): %s", host, port, exc)
        raw_pdu_info["exception"] = str(exc)
        error = str(exc)
    finally:
        if assoc is not None:
            try:
                assoc.release()
            except Exception:
                pass

    return DicomService(
        host=host,
        port=port,
        ae_title_response=ae_title_response,
        echo_success=echo_success,
        tls_capable=tls_capable,
        response_time_ms=response_time_ms,
        raw_pdu_info=raw_pdu_info,
        timestamp=timestamp,
        port_open=port_open,
        error=error,
    )


# ---------------------------------------------------------------------------
# High-level discovery
# ---------------------------------------------------------------------------

def discover_dicom_services(
    host: str,
    ports: Optional[List[int]] = None,
    called_ae: str = "ANY-SCP",
    calling_ae: str = "PACS-ASSESS",
    timeout: float = 10.0,
) -> DiscoveryScanResult:
    """
    Scan *host* across all standard DICOM ports (or a custom *ports* list).

    Each reachable port is probed with a C-ECHO.  Results are collected into
    a DiscoveryScanResult.  Closed ports are recorded but are NOT treated as
    findings.
    """
    if ports is None:
        ports = DICOM_DEFAULT_PORTS

    scan_start = datetime.now(timezone.utc)
    result = DiscoveryScanResult(host=host, scan_start=scan_start)

    for port in ports:
        logger.info("Probing %s:%d for DICOM…", host, port)
        svc = send_dicom_echo(
            host=host,
            port=port,
            called_ae=called_ae,
            calling_ae=calling_ae,
            timeout=timeout,
        )
        result.services.append(svc)

    result.scan_end = datetime.now(timezone.utc)
    logger.info(
        "Discovery complete for %s — %d port(s) probed, %d responded to C-ECHO",
        host,
        len(result.services),
        sum(1 for s in result.services if s.echo_success),
    )
    return result


class DicomDiscovery:
    """Class wrapper for DICOM service discovery."""

    def __init__(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        port: Optional[int] = None,
        called_ae: str = "ANY-SCP",
        calling_ae: str = "PACS-ASSESS",
        timeout: float = 10.0,
        **kwargs: Any,
    ):
        self.host = host
        if port is not None:
            self.ports = [port]
        elif ports is not None:
            self.ports = ports
        else:
            self.ports = DICOM_DEFAULT_PORTS
        self.called_ae = called_ae
        self.calling_ae = calling_ae
        self.timeout = timeout

    def run(self) -> DiscoveryScanResult:
        return discover_dicom_services(
            host=self.host,
            ports=self.ports,
            called_ae=self.called_ae,
            calling_ae=self.calling_ae,
            timeout=self.timeout,
        )

    def discover_services(self) -> List[DicomService]:
        return self.run().services



# ---------------------------------------------------------------------------
# CLI entry-point (for ad-hoc testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="DICOM service discovery probe")
    parser.add_argument("host", help="Target host or IP")
    parser.add_argument("--ports", nargs="+", type=int, default=DICOM_DEFAULT_PORTS)
    parser.add_argument("--called-ae", default="ANY-SCP")
    parser.add_argument("--calling-ae", default="PACS-ASSESS")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    scan = discover_dicom_services(
        host=args.host,
        ports=args.ports,
        called_ae=args.called_ae,
        calling_ae=args.calling_ae,
        timeout=args.timeout,
    )

    for svc in scan.services:
        status = "ECHO OK" if svc.echo_success else ("OPEN" if svc.port_open else "CLOSED")
        print(
            f"  {svc.host}:{svc.port:5d}  {status:8s}  TLS={svc.tls_capable}"
            f"  AE={svc.ae_title_response!r}  {svc.response_time_ms}ms"
        )
