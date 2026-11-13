"""
engines/risk_scorer.py
CVSS-aligned risk scoring engine for the PACS/DICOM Security Assessment Platform.

Design principles:
  - Severity is derived from CVSS score OR specific evidence conditions.
  - Severity is NEVER escalated just because a port is open.
  - Severity is adjusted DOWN (not up) when confidence is Low.
  - Severity is adjusted DOWN when the service is on an internal network.
  - Every scoring decision is explained in ScoredFinding.rationale.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.findings import (
    Confidence,
    Finding,
    FindingType,
    Severity,
    ScoredFinding,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering (for downgrade logic)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

_SEVERITY_INDEX: Dict[Severity, int] = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _downgrade(severity: Severity, steps: int = 1) -> Severity:
    """Move severity down by *steps* tiers, flooring at INFORMATIONAL."""
    idx = max(0, _SEVERITY_INDEX[severity] - steps)
    return _SEVERITY_ORDER[idx]


# ---------------------------------------------------------------------------
# CVSS → base severity
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float) -> Severity:
    """
    Map a CVSS v3 base score to a Severity tier.
    Thresholds follow the NVD severity ratings:
      Critical  9.0 – 10.0
      High      7.0 – 8.9
      Medium    4.0 – 6.9
      Low       0.1 – 3.9
      (0.0 is treated as Informational)
    """
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFORMATIONAL


# ---------------------------------------------------------------------------
# Public scoring function
# ---------------------------------------------------------------------------

def score_finding(finding: Dict[str, Any]) -> ScoredFinding:
    """
    Score a raw finding dict and return a ScoredFinding.

    Expected keys in *finding* (all optional unless noted):
      title             (str)   — human-readable title [required]
      severity          (str)   — initial severity hint (may be overridden)
      host              (str)
      port              (int)
      service           (str)
      evidence          (str)
      detection_method  (str)
      confidence        (str)   "High" | "Medium" | "Low"
      finding_type      (str)   "VULNERABILITY" | "MISCONFIGURATION" | "INFORMATIONAL"
      cve_id            (str|None)
      cvss_score        (float|None)
      remediation       (str|None)
      timestamp         (datetime|str|None)

      # Scoring-specific context keys:
      network_exposed   (bool)  — True if reachable from outside the local subnet
      auth_required     (bool)  — True if the service demanded credentials
      data_sensitivity  (str)   "PHI" | "config" | "none"
      tls_available     (bool)  — True if TLS/DICOM-TLS is available on this port
      internal_only     (bool)  — True if service is confirmed non-internet-routable

    Returns:
        ScoredFinding with final_severity, cvss_estimate, rationale, confidence.
    """
    rationale_parts: list[str] = []

    # -- 1. Parse inputs -------------------------------------------------

    raw_confidence = finding.get("confidence", "Medium")
    try:
        confidence = Confidence(raw_confidence)
    except ValueError:
        confidence = Confidence.MEDIUM

    raw_cvss = finding.get("cvss_score")
    cvss_estimate: Optional[float] = float(raw_cvss) if raw_cvss is not None else None

    network_exposed: bool = bool(finding.get("network_exposed", False))
    auth_required: bool = bool(finding.get("auth_required", False))
    data_sensitivity: str = str(finding.get("data_sensitivity", "none")).lower()
    tls_available: bool = bool(finding.get("tls_available", False))
    internal_only: bool = bool(finding.get("internal_only", False))

    raw_finding_type = finding.get("finding_type", "INFORMATIONAL")
    try:
        finding_type = FindingType(raw_finding_type)
    except ValueError:
        finding_type = FindingType.INFORMATIONAL

    # -- 2. Derive base severity -----------------------------------------

    if cvss_estimate is not None:
        base_severity = _cvss_to_severity(cvss_estimate)
        rationale_parts.append(
            f"Base severity {base_severity.value} derived from CVSS score {cvss_estimate:.1f}."
        )
    else:
        # No CVSS — use evidence-based heuristics.
        # Rule: unauthenticated access to patient data confirmed → Critical
        if (
            not auth_required
            and data_sensitivity == "phi"
            and network_exposed
            and finding_type == FindingType.VULNERABILITY
        ):
            base_severity = Severity.CRITICAL
            rationale_parts.append(
                "Critical: unauthenticated access to PHI confirmed on a network-exposed interface."
            )
        # Rule: unencrypted DICOM on exposed interface WITH evidence → High
        elif (
            not tls_available
            and network_exposed
            and data_sensitivity in ("phi", "config")
            and finding_type in (FindingType.VULNERABILITY, FindingType.MISCONFIGURATION)
        ):
            base_severity = Severity.HIGH
            rationale_parts.append(
                "High: unencrypted DICOM transport on a network-exposed interface "
                f"transmitting {data_sensitivity.upper()} data."
            )
        # Rule: security misconfiguration without confirmed exploitability → Medium
        elif finding_type == FindingType.MISCONFIGURATION:
            base_severity = Severity.MEDIUM
            rationale_parts.append(
                "Medium: security misconfiguration; no confirmed exploitability."
            )
        # Rule: informational or no CVSS → Low / Informational
        elif finding_type == FindingType.INFORMATIONAL:
            base_severity = Severity.INFORMATIONAL
            rationale_parts.append("Informational: observed behaviour with no security implication.")
        else:
            base_severity = Severity.LOW
            rationale_parts.append(
                "Low: no CVSS score assigned and conditions for higher severity not met."
            )

    # -- 3. Positive factors (keep or note) ------------------------------

    if auth_required:
        rationale_parts.append("Authentication is required (positive control).")
    if tls_available:
        rationale_parts.append("TLS is available on this interface (positive control).")

    # -- 4. Downgrade adjustments ----------------------------------------

    final_severity = base_severity

    # Downgrade if confidence is Low
    if confidence == Confidence.LOW and final_severity not in (
        Severity.INFORMATIONAL,
        Severity.LOW,
    ):
        final_severity = _downgrade(final_severity, steps=1)
        rationale_parts.append(
            f"Severity downgraded one tier to {final_severity.value} because confidence is Low."
        )

    # Downgrade if service is confirmed internal-only (not internet-routable)
    if internal_only and final_severity in (Severity.CRITICAL, Severity.HIGH):
        final_severity = _downgrade(final_severity, steps=1)
        rationale_parts.append(
            f"Severity downgraded one tier to {final_severity.value} because "
            "service is confirmed not routable from the internet."
        )

    # -- 5. Guard: never escalate to Critical solely because port is open --
    # (This guard fires only if something upstream wrongly set Critical on an
    #  open-port observation with no other evidence.)
    if (
        final_severity == Severity.CRITICAL
        and not (
            # Legitimate Critical conditions:
            (cvss_estimate is not None and cvss_estimate >= 9.0)
            or (not auth_required and data_sensitivity == "phi" and network_exposed)
        )
    ):
        final_severity = Severity.HIGH
        rationale_parts.append(
            "Severity capped at High: Critical requires CVSS ≥ 9.0 or confirmed "
            "unauthenticated PHI access; neither condition was met."
        )

    # -- 6. Build the original Finding object ----------------------------

    from datetime import datetime

    raw_severity_str = finding.get("severity", final_severity.value)
    try:
        hint_severity = Severity(raw_severity_str)
    except ValueError:
        hint_severity = final_severity

    raw_ts = finding.get("timestamp")
    if isinstance(raw_ts, datetime):
        ts = raw_ts
    elif isinstance(raw_ts, str):
        try:
            ts = datetime.fromisoformat(raw_ts)
        except ValueError:
            ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    original_finding = Finding(
        title=finding.get("title", "Untitled Finding"),
        severity=hint_severity,
        host=finding.get("host", ""),
        port=int(finding.get("port", 0)),
        service=finding.get("service", ""),
        evidence=finding.get("evidence", ""),
        detection_method=finding.get("detection_method", ""),
        confidence=confidence,
        finding_type=finding_type,
        timestamp=ts,
        cve_id=finding.get("cve_id"),
        cvss_score=cvss_estimate,
        remediation=finding.get("remediation"),
    )

    # Calculate separate healthcare contextual impact dimension
    hc_score = cvss_estimate if cvss_estimate is not None else 4.0
    if data_sensitivity == "phi" or "unencrypted" in finding.get("title", "").lower():
        hc_score += 2.0
    if "storage" in finding.get("title", "").lower() or "query" in finding.get("title", "").lower():
        hc_score += 1.5
    if internal_only:
        hc_score -= 1.0
    hc_score = max(0.0, min(10.0, round(hc_score, 1)))

    if hc_score >= 8.5:
        tier = "Critical Clinical Impact"
    elif hc_score >= 6.5:
        tier = "High Clinical Impact"
    elif hc_score >= 4.0:
        tier = "Moderate Clinical Impact"
    else:
        tier = "Low Clinical Impact"

    rationale_parts.append(f"[Healthcare Context: Score {hc_score:.1f} ({tier})]")

    return ScoredFinding(
        original_finding=original_finding,
        final_severity=final_severity,
        cvss_estimate=cvss_estimate,
        rationale=" ".join(rationale_parts),
        confidence=confidence,
        healthcare_impact_score=hc_score,
        clinical_risk_tier=tier,
    )


# ---------------------------------------------------------------------------
# Convenience: score a Finding object directly
# ---------------------------------------------------------------------------

def score_finding_object(
    f: Finding,
    network_exposed: bool = False,
    auth_required: bool = False,
    data_sensitivity: str = "none",
    tls_available: bool = False,
    internal_only: bool = False,
) -> ScoredFinding:
    """Thin wrapper that converts a Finding dataclass to the dict expected by score_finding()."""
    d = f.to_dict()
    d.update(
        network_exposed=network_exposed,
        auth_required=auth_required,
        data_sensitivity=data_sensitivity,
        tls_available=tls_available,
        internal_only=internal_only,
    )
    return score_finding(d)


class RiskScorer:
    """Class wrapper for Risk Scoring engine."""

    def __init__(self, findings: Optional[List[Dict[str, Any]]] = None, **kwargs: Any):
        self.findings = findings or []

    def score(self, finding: Any, **kwargs) -> ScoredFinding:
        if isinstance(finding, Finding):
            return score_finding_object(finding, **kwargs)
        elif isinstance(finding, dict):
            return score_finding(finding)
        return score_finding_object(finding, **kwargs)

    def score_finding(self, finding_dict: Dict[str, Any]) -> ScoredFinding:
        return score_finding(finding_dict)

    def run(self) -> List[Dict[str, Any]]:
        """
        Scores all findings in self.findings, updating their severity and cvss_score.
        Returns the scored findings as dicts.
        """
        scored_results: List[Dict[str, Any]] = []
        for f in self.findings:
            f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            scored = score_finding(f_dict)
            f_dict["severity"] = scored.final_severity.value
            if scored.cvss_estimate is not None:
                f_dict["cvss_score"] = scored.cvss_estimate
            f_dict["scoring_rationale"] = scored.rationale
            scored_results.append(f_dict)
        return scored_results

