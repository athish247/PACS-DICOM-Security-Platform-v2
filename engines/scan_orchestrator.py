"""
engines/scan_orchestrator.py — Master scan coordinator.

Called by gui/scan_worker.py to run all assessment modules in sequence.
Collects Finding objects, scores them, persists to DB, and returns an
AssessmentResult.

Module name strings accepted in *modules*:
    "network_scan"      → engines.network_scanner
    "dicom_discovery"   → engines.dicom_discovery
    "association_test"  → engines.dicom_association_tester
    "tls_assessment"    → engines.tls_assessor
    "auth_assessment"   → engines.auth_assessor
    "metadata_analysis" → engines.metadata_analyzer
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def run_assessment(
    host: str,
    port: int,
    called_ae: str,
    calling_ae: str,
    timeout: int,
    modules: List[str],
    cancel_flag: threading.Event,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    finding_callback: Optional[Callable[[dict], None]] = None,
    service_callback: Optional[Callable[[dict], None]] = None,
) -> "AssessmentResult":  # noqa: F821  (resolved at runtime via models)
    """
    Orchestrate a full security assessment against *host*:*port*.

    Parameters
    ----------
    host, port          : Target DICOM node.
    called_ae           : Called AE Title to use in DICOM PDUs.
    calling_ae          : Our AE Title.
    timeout             : Per-module network timeout in seconds.
    modules             : Ordered list of module names to run.
    cancel_flag         : threading.Event — set to request graceful cancellation.
    progress_callback   : Optional fn(percent: int, message: str) for UI updates.
    finding_callback    : Optional fn(finding_dict: dict) emitted per finding.
    service_callback    : Optional fn(service_dict: dict) emitted per DICOM service.

    Returns
    -------
    AssessmentResult with all findings, services, and timing.
    """
    from models.findings import (
        AssessmentTarget,
        AssessmentResult,
        Finding,
        Severity,
        Confidence,
        FindingType,
    )

    target = AssessmentTarget(
        host=host,
        port=port,
        called_ae=called_ae,
        calling_ae=calling_ae,
        timeout=timeout,
        authorized=True,  # GUI enforces authorization before calling us
    )

    result = AssessmentResult(
        target=target,
        start_time=datetime.now(timezone.utc),
        end_time=None,
    )

    # Try to open/init DB; if DB not available, we still run and just skip saves.
    assessment_id: Optional[int] = None
    try:
        from db import database as db
        db.init_db()
        assessment_id = db.save_assessment(result)
        db.log_audit_event("ASSESSMENT_START", f"host={host} port={port}")
    except Exception as exc:
        logger.warning("DB unavailable — skipping persistence: %s", exc)
        db = None  # type: ignore[assignment]

    total_modules = max(len(modules), 1)
    completed = 0

    def _progress(msg: str) -> None:
        pct = int((completed / total_modules) * 100)
        if progress_callback:
            try:
                progress_callback(pct, msg)
            except Exception:
                pass

    def _emit_finding(finding: Finding) -> None:
        result.findings.append(finding)
        if finding_callback:
            try:
                finding_callback(finding.to_dict())
            except Exception:
                pass
        # Persist immediately so the UI can reload if needed
        if db and assessment_id is not None:
            try:
                db.save_finding(assessment_id, finding)
            except Exception as exc:
                logger.debug("save_finding failed: %s", exc)

    def _emit_service(svc_dict: dict) -> None:
        if service_callback:
            try:
                service_callback(svc_dict)
            except Exception:
                pass

    # -------------------------------------------------------------------
    # Module runners
    # -------------------------------------------------------------------

    def _run_network_scan() -> None:
        _progress("Running network scan…")
        try:
            from engines.network_scanner import NetworkScanner  # type: ignore
            scanner = NetworkScanner(host=host, ports=[port], timeout=timeout)
            scan_result = scanner.run()
            result.scan_modules_run.append("network_scan")
            for finding in scan_result.findings:
                _scored = _score(finding)
                _emit_finding(_scored)
        except ImportError:
            logger.warning("network_scanner not available — skipping")
            result.errors.append("network_scan: ImportError — module not installed")
        except NotImplementedError:
            logger.warning("network_scanner not yet implemented")
            result.errors.append("network_scan: NotImplementedError")
        except Exception as exc:
            logger.error("network_scan failed: %s", exc)
            result.errors.append(f"network_scan: {exc}")

    def _run_dicom_discovery() -> None:
        _progress("Running DICOM service discovery…")
        try:
            from engines.dicom_discovery import discover_dicom_services, DicomService
            discovery = discover_dicom_services(
                host=host,
                ports=[port],
                called_ae=called_ae,
                calling_ae=calling_ae,
                timeout=float(timeout),
            )
            result.scan_modules_run.append("dicom_discovery")
            for svc in discovery.services:
                # Translate local DicomService → models.DicomService for result
                from models.findings import DicomService as ModelDicomService
                model_svc = ModelDicomService(
                    host=svc.host,
                    port=svc.port,
                    ae_response=getattr(svc, "ae_title_response", None),
                    echo_success=svc.echo_success,
                    tls_capable=svc.tls_capable,
                    response_ms=getattr(svc, "response_time_ms", None),
                    timestamp=svc.timestamp,
                )
                result.services_discovered.append(model_svc)
                _emit_service(model_svc.to_dict())
        except ImportError:
            logger.warning("dicom_discovery not available — skipping")
            result.errors.append("dicom_discovery: ImportError")
        except NotImplementedError:
            result.errors.append("dicom_discovery: NotImplementedError")
        except Exception as exc:
            logger.error("dicom_discovery failed: %s", exc)
            result.errors.append(f"dicom_discovery: {exc}")

    def _run_association_test() -> None:
        _progress("Running DICOM association security tests…")
        try:
            from engines.dicom_association_tester import run_association_tests
            suite = run_association_tests(host=host, port=port, timeout=float(timeout))
            result.scan_modules_run.append("association_test")
            for test_result in suite.results:
                if test_result.is_vulnerability and test_result.finding is not None:
                    f = test_result.finding
                    # Map local Finding → models.Finding
                    finding = _make_finding(
                        title=f.title,
                        severity_str=f.severity,
                        evidence=f.evidence,
                        detection_method=f.detection_method,
                        confidence_str=f.confidence,
                        remediation=f.remediation,
                        finding_type=FindingType.VULNERABILITY,
                    )
                    _emit_finding(finding)
        except ImportError:
            result.errors.append("association_test: ImportError")
        except NotImplementedError:
            result.errors.append("association_test: NotImplementedError")
        except Exception as exc:
            logger.error("association_test failed: %s", exc)
            result.errors.append(f"association_test: {exc}")

    def _run_tls_assessment() -> None:
        _progress("Running TLS/SSL configuration assessment…")
        try:
            from engines.tls_assessor import assess_tls  # type: ignore
            tls_result = assess_tls(host=host, port=port, timeout=float(timeout))
            result.scan_modules_run.append("tls_assessment")
            for finding in getattr(tls_result, "findings", []):
                _emit_finding(_normalise_finding(finding))
        except ImportError:
            result.errors.append("tls_assessment: ImportError")
        except NotImplementedError:
            result.errors.append("tls_assessment: NotImplementedError")
        except Exception as exc:
            logger.error("tls_assessment failed: %s", exc)
            result.errors.append(f"tls_assessment: {exc}")

    def _run_auth_assessment() -> None:
        _progress("Running authentication & access control assessment…")
        try:
            from engines.auth_assessor import run_auth_assessment  # type: ignore
            auth_result = run_auth_assessment(
                host=host, port=port, timeout=float(timeout)
            )
            result.scan_modules_run.append("auth_assessment")
            for finding in getattr(auth_result, "findings", []):
                _emit_finding(_normalise_finding(finding))
        except ImportError:
            result.errors.append("auth_assessment: ImportError")
        except NotImplementedError:
            result.errors.append("auth_assessment: NotImplementedError")
        except Exception as exc:
            logger.error("auth_assessment failed: %s", exc)
            result.errors.append(f"auth_assessment: {exc}")

    def _run_metadata_analysis() -> None:
        _progress("Running DICOM metadata privacy analysis…")
        try:
            from engines.metadata_analyzer import analyze_dicom_file  # type: ignore
            # Metadata analysis needs a file path — skip if none provided at this stage.
            # The GUI may call this directly with a file picker; orchestrator records it.
            result.scan_modules_run.append("metadata_analysis")
            logger.info("metadata_analysis: skipped — no DICOM file path provided to orchestrator")
        except ImportError:
            result.errors.append("metadata_analysis: ImportError")
        except NotImplementedError:
            result.errors.append("metadata_analysis: NotImplementedError")
        except Exception as exc:
            result.errors.append(f"metadata_analysis: {exc}")

    # -------------------------------------------------------------------
    # Dispatch map
    # -------------------------------------------------------------------

    _MODULE_DISPATCH = {
        "network_scan":     _run_network_scan,
        "dicom_discovery":  _run_dicom_discovery,
        "association_test": _run_association_test,
        "tls_assessment":   _run_tls_assessment,
        "auth_assessment":  _run_auth_assessment,
        "metadata_analysis": _run_metadata_analysis,
    }

    # -------------------------------------------------------------------
    # Run each module in sequence, honouring cancel_flag
    # -------------------------------------------------------------------
    for module_name in modules:
        if cancel_flag.is_set():
            logger.info("Assessment cancelled before running %s", module_name)
            result.errors.append(f"Cancelled before {module_name}")
            break

        runner = _MODULE_DISPATCH.get(module_name)
        if runner is None:
            logger.warning("Unknown module name: %r — skipping", module_name)
            result.errors.append(f"Unknown module: {module_name}")
        else:
            runner()

        completed += 1

    # -------------------------------------------------------------------
    # Finalise
    # -------------------------------------------------------------------
    result.end_time = datetime.now(timezone.utc)

    if db and assessment_id is not None:
        try:
            db.update_assessment_end(assessment_id, result.end_time)
            db.log_audit_event(
                "ASSESSMENT_END",
                f"host={host} port={port} findings={len(result.findings)}",
            )
        except Exception as exc:
            logger.debug("DB finalise failed: %s", exc)

    if progress_callback:
        try:
            progress_callback(100, "Assessment complete.")
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _score(finding: "Finding") -> "Finding":  # noqa: F821
    """
    Pass a Finding through risk_scorer.score_finding().
    If risk_scorer is unavailable, return the finding unchanged.
    """
    try:
        from engines.risk_scorer import score_finding  # type: ignore
        scored = score_finding(finding)
        # Promote the final_severity back onto the finding
        finding.severity = scored.final_severity
    except (ImportError, NotImplementedError):
        pass
    except Exception as exc:
        logger.debug("risk_scorer failed for finding %r: %s", finding.title, exc)
    return finding


def _make_finding(
    title: str,
    severity_str: str,
    evidence: str,
    detection_method: str,
    confidence_str: str,
    remediation: str,
    finding_type: "FindingType",  # noqa: F821
    host: str = "",
    port: int = 0,
    service: str = "DICOM",
    cve_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
) -> "Finding":  # noqa: F821
    """Convert loose strings into a typed models.Finding."""
    from models.findings import Finding, Severity, Confidence, FindingType

    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFORMATIONAL,
    }
    conf_map = {
        "high": Confidence.HIGH,
        "medium": Confidence.MEDIUM,
        "low": Confidence.LOW,
    }

    return Finding(
        title=title,
        severity=sev_map.get(severity_str.lower(), Severity.INFORMATIONAL),
        host=host,
        port=port,
        service=service,
        evidence=evidence,
        detection_method=detection_method,
        confidence=conf_map.get(confidence_str.lower(), Confidence.MEDIUM),
        finding_type=finding_type,
        cve_id=cve_id,
        cvss_score=cvss_score,
        remediation=remediation,
    )


def _normalise_finding(raw) -> "Finding":  # noqa: F821
    """
    Accept either a models.Finding or a duck-typed finding from an engine that
    defined its own local Finding dataclass, and return a canonical
    models.findings.Finding.
    """
    from models.findings import Finding

    if isinstance(raw, Finding):
        return raw

    # Duck-type conversion: engine returned its own local Finding dataclass
    return _make_finding(
        title=getattr(raw, "title", "Unknown Finding"),
        severity_str=getattr(raw, "severity", "Informational"),
        evidence=getattr(raw, "evidence", ""),
        detection_method=getattr(raw, "detection_method", "unknown"),
        confidence_str=getattr(raw, "confidence", "Medium"),
        remediation=getattr(raw, "remediation", ""),
        finding_type=__import__(
            "models.findings", fromlist=["FindingType"]
        ).FindingType.VULNERABILITY,
        host=getattr(raw, "host", ""),
        port=getattr(raw, "port", 0),
        service=getattr(raw, "service", "DICOM"),
        cve_id=getattr(raw, "cve_id", None),
        cvss_score=getattr(raw, "cvss_score", None),
    )


# ---------------------------------------------------------------------------
# FindingType alias for use inside helpers above without circular import risk
# ---------------------------------------------------------------------------
try:
    from models.findings import FindingType  # noqa: F401
except ImportError:
    pass
