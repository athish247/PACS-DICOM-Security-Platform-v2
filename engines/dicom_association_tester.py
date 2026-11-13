"""
dicom_association_tester.py — Real DICOM association security testing engine.

Tests access control by attempting associations with various AE Title values.
Key design principle: a REJECTION is a sign of working access control, NOT a
vulnerability. Only unconditional ACCEPTANCE of untrusted identities is flagged.
"""

from __future__ import annotations

import logging
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class AssocResult(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    TIMEOUT  = "TIMEOUT"
    ERROR    = "ERROR"


@dataclass
class Finding:
    """A single security finding produced by one test."""

    title: str
    severity: str                 # Critical / High / Medium / Low / Informational
    evidence: str                 # Actual observed data — no fabrication
    detection_method: str
    confidence: str               # High / Medium / Low
    remediation: str


@dataclass
class AssociationTestResult:
    """Result of a single association security test."""

    test_name: str
    ae_title_tested: str
    result: AssocResult
    details: str
    is_vulnerability: bool
    severity: str                 # Severity IF is_vulnerability else "N/A"
    evidence: str
    raw_pdu_info: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finding: Optional[Finding] = None
    host: str = ""
    port: int = 0

    def to_finding(self) -> Dict[str, Any]:
        if self.finding:
            return {
                "title": self.finding.title,
                "severity": self.finding.severity,
                "host": self.host,
                "port": self.port,
                "service": "DICOM",
                "evidence": self.finding.evidence,
                "detection_method": self.finding.detection_method,
                "confidence": self.finding.confidence,
                "finding_type": "MISCONFIGURATION",
                "remediation": self.finding.remediation,
                "timestamp": self.timestamp.isoformat(),
            }
        return {
            "title": self.test_name,
            "severity": self.severity if self.severity != "N/A" else "Medium",
            "host": self.host,
            "port": self.port,
            "service": "DICOM",
            "evidence": self.details or self.evidence,
            "detection_method": "AssociationTester",
            "confidence": "Medium",
            "finding_type": "MISCONFIGURATION",
            "remediation": "Configure AE Title access control / whitelist on the DICOM modality.",
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class AssociationTestSuite:
    """Aggregated results from running the full association test suite."""

    host: str
    port: int
    results: List[AssociationTestResult] = field(default_factory=list)
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Internal helper — raw association attempt
# ---------------------------------------------------------------------------

def _attempt_association(
    host: str,
    port: int,
    called_ae: str,
    calling_ae: str,
    timeout: float,
) -> AssociationTestResult:
    """
    Perform a single pynetdicom association attempt and return a structured
    result.  The calling_ae is used as *our* AE title; called_ae is the
    target AE title field we are probing.

    Uses Verification SOP Class as the requested presentation context — if the
    SCP accepts the association we also confirm it is active before releasing.
    """
    raw_pdu_info: Dict[str, Any] = {
        "called_ae": called_ae,
        "calling_ae": calling_ae,
    }
    assoc_result = AssocResult.ERROR
    details = ""
    evidence = f"Calling AE='{calling_ae}', Called AE='{called_ae}', host={host}, port={port}"
    assoc = None

    try:
        from pynetdicom import AE
        from pynetdicom.sop_class import Verification  # type: ignore

        ae = AE(ae_title=calling_ae)
        ae.add_requested_context(Verification)
        ae.acse_timeout = timeout
        ae.dimse_timeout = timeout
        ae.network_timeout = timeout

        assoc = ae.associate(host, port, ae_title=called_ae)

        if assoc.is_established:
            assoc_result = AssocResult.ACCEPTED
            try:
                responder_ae = (
                    assoc.acceptor.ae_title.strip()
                    if assoc.acceptor and assoc.acceptor.ae_title
                    else "<unknown>"
                )
                raw_pdu_info["responder_ae_title"] = responder_ae
                evidence += f" → A-ASSOCIATE-AC received; responder AE='{responder_ae}'"
            except AttributeError:
                evidence += " → A-ASSOCIATE-AC received"
            details = "Remote AE accepted the association."

        elif assoc.is_rejected:
            assoc_result = AssocResult.REJECTED
            try:
                result_code  = assoc.acceptor.primitive.result  if assoc.acceptor else None
                reason_code  = assoc.acceptor.primitive.result_source if assoc.acceptor else None
                raw_pdu_info["rejection_result"]  = result_code
                raw_pdu_info["rejection_source"]  = reason_code
                evidence += f" → A-ASSOCIATE-RJ; result={result_code}, source={reason_code}"
            except AttributeError:
                evidence += " → A-ASSOCIATE-RJ received"
            details = "Remote AE rejected the association (access control is active)."

        elif assoc.is_aborted:
            assoc_result = AssocResult.REJECTED   # treated as rejection for scoring
            raw_pdu_info["aborted"] = True
            evidence += " → A-ABORT received"
            details = "Remote AE aborted the association."

        else:
            # Likely a timeout / network failure
            assoc_result = AssocResult.TIMEOUT
            details = "Association attempt timed out or failed before completion."
            evidence += " → no response within timeout"

    except TimeoutError:
        assoc_result = AssocResult.TIMEOUT
        details = "Network timeout."
        evidence += " → TimeoutError"
    except ConnectionRefusedError:
        assoc_result = AssocResult.ERROR
        details = "Connection refused — port may be closed."
        evidence += " → ConnectionRefusedError"
    except Exception as exc:
        assoc_result = AssocResult.ERROR
        details = f"Exception: {exc}"
        evidence += f" → {type(exc).__name__}: {exc}"
        logger.warning("_attempt_association(%s, %d, called=%r, calling=%r): %s",
                       host, port, called_ae, calling_ae, exc)
    finally:
        if assoc is not None:
            try:
                assoc.release()
            except Exception:
                pass

    return AssociationTestResult(
        test_name="",           # filled in by caller
        ae_title_tested=calling_ae,
        result=assoc_result,
        details=details,
        is_vulnerability=False,  # filled in by caller
        severity="N/A",          # filled in by caller
        evidence=evidence,
        raw_pdu_info=raw_pdu_info,
    )


# ---------------------------------------------------------------------------
# Individual security tests
# ---------------------------------------------------------------------------

def test_anonymous_association(
    host: str,
    port: int,
    timeout: float = 10.0,
) -> AssociationTestResult:
    """
    Test whether the SCP accepts a connection from a completely unknown AE.

    We use the calling AE title "ANONYMOUS" — a value that no properly
    configured PACS should whitelist.  Acceptance means the PACS does NOT
    enforce AE-title–based access control.
    """
    calling_ae = "ANONYMOUS"
    called_ae  = "ANY-SCP"

    r = _attempt_association(host, port, called_ae, calling_ae, timeout)
    r.test_name = "Anonymous AE Title"
    r.ae_title_tested = calling_ae

    if r.result == AssocResult.ACCEPTED:
        r.is_vulnerability = True
        r.severity = "High"
        r.finding = Finding(
            title="DICOM SCP accepts anonymous / unauthenticated associations",
            severity="High",
            evidence=r.evidence,
            detection_method="pynetdicom A-ASSOCIATE-RQ with calling AE='ANONYMOUS'",
            confidence="High",
            remediation=(
                "Configure the DICOM SCP with an explicit AE-title whitelist. "
                "Reject any association whose Calling AE Title is not in the approved list. "
                "Refer to the vendor's AE-title access control documentation."
            ),
        )
    else:
        # Rejection / timeout / error — not a finding
        r.is_vulnerability = False
        r.severity = "N/A"

    return r


def test_arbitrary_ae_title(
    host: str,
    port: int,
    random_ae: Optional[str] = None,
    timeout: float = 10.0,
) -> AssociationTestResult:
    """
    Test whether the SCP accepts a randomly generated, nonsense AE Title.

    A randomly generated title has an astronomically low probability of matching
    any configured whitelist entry, so acceptance strongly implies the SCP has
    no AE-title–based access control at all.
    """
    if random_ae is None:
        random_ae = "RND-" + "".join(
            random.choices(string.ascii_uppercase + string.digits, k=8)
        )
    called_ae = "ANY-SCP"

    r = _attempt_association(host, port, called_ae, random_ae, timeout)
    r.test_name = "Arbitrary/Random AE Title"
    r.ae_title_tested = random_ae

    if r.result == AssocResult.ACCEPTED:
        r.is_vulnerability = True
        r.severity = "High"
        r.finding = Finding(
            title="DICOM SCP accepts arbitrary / random AE Titles",
            severity="High",
            evidence=r.evidence,
            detection_method=(
                f"pynetdicom A-ASSOCIATE-RQ with randomly generated calling AE='{random_ae}'"
            ),
            confidence="High",
            remediation=(
                "Implement AE-title allowlist authentication on the DICOM SCP. "
                "Only pre-registered calling AE Titles should be permitted to establish associations."
            ),
        )
    else:
        r.is_vulnerability = False
        r.severity = "N/A"

    return r


def test_null_ae_title(
    host: str,
    port: int,
    timeout: float = 10.0,
) -> AssociationTestResult:
    """
    Test whether the SCP accepts an empty string as the Calling AE Title.

    Per DICOM PS 3.7, AE Titles must be 1–16 characters of a restricted
    character set.  An SCP that accepts an empty title either does not validate
    the PDU or has access control entirely disabled.
    """
    calling_ae = ""   # empty / null AE title
    called_ae  = "ANY-SCP"

    # pynetdicom may refuse to build the PDU with an empty AE title; we catch
    # that and record it as ERROR (not a finding).
    r = _attempt_association(host, port, called_ae, calling_ae, timeout)
    r.test_name = "Null/Empty AE Title"
    r.ae_title_tested = "(empty)"

    if r.result == AssocResult.ACCEPTED:
        r.is_vulnerability = True
        r.severity = "Medium"
        r.finding = Finding(
            title="DICOM SCP accepts empty/null AE Title (no AE-title validation)",
            severity="Medium",
            evidence=r.evidence,
            detection_method="pynetdicom A-ASSOCIATE-RQ with empty Calling AE Title",
            confidence="High",
            remediation=(
                "Enforce AE-title validation at the network layer. "
                "Reject PDUs with empty, whitespace-only, or malformed AE Titles before "
                "proceeding to access control checks."
            ),
        )
    elif r.result == AssocResult.ERROR and "PDU" in r.details:
        # pynetdicom itself rejected building the PDU — still worth noting
        r.is_vulnerability = False
        r.severity = "Informational"
        r.details += " (pynetdicom blocked malformed PDU at client side)"
    else:
        r.is_vulnerability = False
        r.severity = "N/A"

    return r


def test_long_ae_title(
    host: str,
    port: int,
    timeout: float = 10.0,
) -> AssociationTestResult:
    """
    Test whether a 64-character AE Title (4× the DICOM maximum of 16) causes
    an error, crash, or unexpected acceptance on the SCP.

    Acceptance is a Medium finding (validation missing); a clean rejection is
    correct behaviour and is not flagged.
    """
    # 64 chars — deliberately over the 16-char DICOM limit
    long_ae = "A" * 64
    called_ae = "ANY-SCP"

    r = _attempt_association(host, port, called_ae, long_ae, timeout)
    r.test_name = "Oversized AE Title (64 chars)"
    r.ae_title_tested = long_ae[:20] + "…"  # truncate for display

    if r.result == AssocResult.ACCEPTED:
        r.is_vulnerability = True
        r.severity = "Medium"
        r.finding = Finding(
            title="DICOM SCP accepts oversized AE Title (>16 characters)",
            severity="Medium",
            evidence=r.evidence,
            detection_method="pynetdicom A-ASSOCIATE-RQ with 64-character Calling AE Title",
            confidence="Medium",
            remediation=(
                "Validate the length and character set of Calling AE Titles per "
                "DICOM PS 3.5 §6.2 (max 16 chars, uppercase letters, digits, space, underscore). "
                "Reject non-conforming titles at the PDU parsing layer."
            ),
        )
    else:
        r.is_vulnerability = False
        r.severity = "N/A"

    return r


# ---------------------------------------------------------------------------
# High-level test-suite runner
# ---------------------------------------------------------------------------

def run_association_tests(
    host: str,
    port: int,
    timeout: float = 10.0,
    random_ae: Optional[str] = None,
) -> AssociationTestSuite:
    """
    Run the full association security test suite against *host*:*port*.

    Returns an AssociationTestSuite containing one AssociationTestResult per
    test.  The caller is responsible for aggregating findings and deciding
    report severity.
    """
    suite = AssociationTestSuite(
        host=host,
        port=port,
        scan_start=datetime.now(timezone.utc),
    )

    tests = [
        lambda: test_anonymous_association(host, port, timeout),
        lambda: test_arbitrary_ae_title(host, port, random_ae, timeout),
        lambda: test_null_ae_title(host, port, timeout),
        lambda: test_long_ae_title(host, port, timeout),
    ]

    for test_fn in tests:
        try:
            result = test_fn()
            suite.results.append(result)
            logger.info(
                "Association test '%s': %s  vuln=%s",
                result.test_name,
                result.result.value,
                result.is_vulnerability,
            )
        except Exception as exc:
            logger.error("Association test raised unhandled exception: %s", exc)

    suite.scan_end = datetime.now(timezone.utc)
    return suite


class AssociationTester:
    """Class wrapper for DICOM Association security testing."""

    def __init__(
        self,
        host: str,
        port: int = 104,
        timeout: float = 10.0,
        called_ae: str = "ANY-SCP",
        calling_ae: str = "PACS-ASSESS",
        **kwargs: Any,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.called_ae = called_ae
        self.calling_ae = calling_ae

    def run_all_tests(self) -> List[AssociationTestResult]:
        suite = run_association_tests(self.host, self.port, timeout=self.timeout)
        for r in suite.results:
            r.host = self.host
            r.port = self.port
        return suite.results

    def run(self) -> List[AssociationTestResult]:
        return self.run_all_tests()


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="DICOM association security tester")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    suite = run_association_tests(args.host, args.port, args.timeout)
    for r in suite.results:
        vuln_flag = "⚠ VULN" if r.is_vulnerability else "  OK  "
        print(f"  {vuln_flag}  [{r.result.value:8s}]  {r.test_name}")
        if r.finding:
            print(f"           Severity : {r.finding.severity}")
            print(f"           Evidence : {r.finding.evidence}")
            print(f"           Fix      : {r.finding.remediation}")
