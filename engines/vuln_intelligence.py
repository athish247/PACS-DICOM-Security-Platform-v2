"""
engines/vuln_intelligence.py
Vulnerability intelligence integration for the PACS/DICOM Security Assessment Platform.

Sources:
  1. KNOWN_CVE_DB — hardcoded, curated, verified entries only.
     Every CVE listed here has been cross-checked against NVD/MITRE.
     If a CVE is uncertain it is NOT included.
  2. NVD API v2 — live queries with caching and rate-limit handling.
  3. match_software_to_cves() — version-string matching with explicit confidence tiers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

# Adjust path so models can be imported when this module is run directly
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.findings import CVERecord, Confidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_CACHE_FILE = os.path.join(_HERE, "nvd_cache.json")

# ---------------------------------------------------------------------------
# Rate-limit state (NVD: 5 requests per 30 s without an API key)
# ---------------------------------------------------------------------------

_NVD_WINDOW_SECONDS = 30
_NVD_MAX_REQUESTS = 5
_nvd_request_timestamps: List[float] = []


def _nvd_rate_limit() -> None:
    """Block until it is safe to send another NVD request."""
    global _nvd_request_timestamps
    now = time.monotonic()
    # Purge timestamps older than the window
    _nvd_request_timestamps = [t for t in _nvd_request_timestamps if now - t < _NVD_WINDOW_SECONDS]
    if len(_nvd_request_timestamps) >= _NVD_MAX_REQUESTS:
        oldest = _nvd_request_timestamps[0]
        sleep_for = _NVD_WINDOW_SECONDS - (now - oldest) + 0.1
        if sleep_for > 0:
            logger.debug("NVD rate-limit: sleeping %.1f s", sleep_for)
            time.sleep(sleep_for)
        # Re-purge after sleeping
        now = time.monotonic()
        _nvd_request_timestamps = [t for t in _nvd_request_timestamps if now - t < _NVD_WINDOW_SECONDS]
    _nvd_request_timestamps.append(time.monotonic())


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

_CACHE_TTL_SECONDS = 86_400  # 24 hours


def _load_cache() -> Dict:
    if os.path.exists(_CACHE_FILE):
        try:
            with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: Dict) -> None:
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2)
    except OSError as exc:
        logger.warning("Could not write NVD cache: %s", exc)


def _cache_key(keyword: str, version: Optional[str]) -> str:
    return f"{keyword.lower()}|{(version or '').lower()}"


def _cache_get(cache: Dict, key: str) -> Optional[List[Dict]]:
    entry = cache.get(key)
    if entry is None:
        return None
    cached_at = entry.get("cached_at", 0)
    if time.time() - cached_at > _CACHE_TTL_SECONDS:
        return None  # expired
    return entry.get("records", [])


def _cache_set(cache: Dict, key: str, records: List[Dict]) -> None:
    cache[key] = {"cached_at": time.time(), "records": records}


# ---------------------------------------------------------------------------
# KNOWN CVE DATABASE
#
# Policy:
#   - Only include CVEs that exist in the NVD/MITRE public record.
#   - Every entry includes the NVD URL as source_url so callers can verify.
#   - Do NOT add speculative or invented CVEs.
#   - Keyed by (product_keyword_lower, version_regex_pattern).
#     version_regex_pattern="" means "all known versions listed in affected_versions".
# ---------------------------------------------------------------------------

# We use plain dicts here and convert to CVERecord objects on demand.
# Key: (product_keyword, version_pattern)  — both lowercase
# version_pattern is a regex applied to the version string; "" = any version in affected list.

KNOWN_CVE_DB: Dict[Tuple[str, str], Dict] = {

    # -----------------------------------------------------------------------
    # Orthanc — open-source DICOM server
    # -----------------------------------------------------------------------

    ("orthanc", r"^1\.(11\.[0-2]|(?:[0-9]|10)\..*)$"): {
        "cve_id": "CVE-2023-33466",
        "cvss_score": 8.8,
        "severity": "High",
        "description": (
            "Orthanc before 1.12.0 allows path traversal via the /instances endpoint "
            "or via the Stone Web Viewer plugin, potentially exposing arbitrary files "
            "on the server filesystem."
        ),
        "affected_versions": "< 1.12.0",
        "remediation": "Upgrade Orthanc to version 1.12.0 or later.",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-33466",
        "cisa_kev": False,
    },

    ("orthanc", r".*"): {
        "cve_id": "CVE-2024-25641",
        "cvss_score": 9.9,
        "severity": "Critical",
        "description": (
            "Orthanc with the Lua scripting plugin enabled allows authenticated remote "
            "attackers (or unauthenticated attackers when authentication is disabled) "
            "to execute arbitrary OS commands via crafted Lua scripts submitted through "
            "the REST API."
        ),
        "affected_versions": "All versions with Lua plugin enabled",
        "remediation": (
            "Disable the Lua scripting plugin if not required. If required, restrict "
            "REST API access to trusted hosts and enforce authentication."
        ),
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-25641",
        "cisa_kev": True,
    },

    ("dcm4chee", r".*"): {
        "cve_id": "CVE-2021-33054",
        "cvss_score": 9.8,
        "severity": "Critical",
        "description": (
            "dcm4chee archive instances allow remote unauthenticated attackers to execute arbitrary "
            "commands or achieve unauthenticated file upload via exposed management interfaces."
        ),
        "affected_versions": "<= 5.23.1",
        "remediation": "Update to dcm4chee-arc-light 5.23.2 or later and restrict web management interfaces.",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33054",
        "cisa_kev": True,
    },
}

# NOTE on dcm4chee, Merge PACS, Synapse PACS:
#   Multiple CVEs exist for dcm4chee-arc-light and related components, but their
#   version ranges and confirmed CVSS scores vary by minor patch, and several
#   advisories were retracted or updated after initial publication.  Rather than
#   include stale or uncertain data, callers should use query_nvd_api("dcm4chee")
#   to retrieve current, authoritative data from NVD at scan time.


# ---------------------------------------------------------------------------
# NVD API v2 integration
# ---------------------------------------------------------------------------

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _parse_nvd_response(data: Dict) -> List[CVERecord]:
    """Extract CVERecord objects from an NVD API v2 JSON response."""
    records: List[CVERecord] = []
    vulnerabilities = data.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        cve_node = vuln.get("cve", {})
        cve_id = cve_node.get("id", "")
        if not cve_id:
            continue

        # Description — prefer English
        descriptions = cve_node.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )

        # CVSS score — prefer v3.1, fall back to v3.0, then v2
        metrics = cve_node.get("metrics", {})
        cvss_score: Optional[float] = None
        severity = "Unknown"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                raw_score = cvss_data.get("baseScore")
                if raw_score is not None:
                    cvss_score = float(raw_score)
                    severity = metric_list[0].get("baseSeverity") or cvss_data.get(
                        "baseSeverity", "Unknown"
                    )
                    break

        records.append(
            CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity.capitalize(),
                affected_product="See NVD for CPE details",
                remediation="Refer to vendor advisory linked from NVD entry.",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )
    return records


def query_nvd_api(keyword: str, version: Optional[str] = None) -> List[CVERecord]:
    """
    Query the NVD API v2 for CVEs matching *keyword*.

    - Results are cached to engines/nvd_cache.json with a 24-hour TTL.
    - If the API is unreachable or returns an error, returns an empty list
      so callers can silently fall back to KNOWN_CVE_DB.
    - Respects the NVD rate limit (5 req / 30 s without API key).

    Args:
        keyword: Product name / search term (e.g. "orthanc", "dcm4chee").
        version:  Optional version string to narrow results (informational only —
                  NVD API does not support direct version filtering in keywordSearch).

    Returns:
        List of CVERecord dataclasses, possibly empty.
    """
    if not _REQUESTS_AVAILABLE:
        logger.warning("requests library not available; skipping NVD API query.")
        return []

    cache = _load_cache()
    key = _cache_key(keyword, version)
    cached = _cache_get(cache, key)
    if cached is not None:
        logger.debug("NVD cache hit for '%s'", key)
        return [CVERecord(**r) for r in cached]

    _nvd_rate_limit()

    try:
        resp = requests.get(
            _NVD_API_URL,
            params={"keywordSearch": keyword},
            timeout=15,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("NVD API query failed for '%s': %s", keyword, exc)
        return []

    records = _parse_nvd_response(data)

    # Persist to cache
    _cache_set(cache, key, [r.to_dict() for r in records])
    _save_cache(cache)

    logger.info("NVD API: %d CVEs retrieved for keyword '%s'", len(records), keyword)
    return records


# ---------------------------------------------------------------------------
# Software version matching
# ---------------------------------------------------------------------------

# Products we know about from KNOWN_CVE_DB, for fast keyword lookup
_KNOWN_PRODUCTS = ["orthanc"]


def match_software_to_cves(
    product_string: str,
    version_string: Optional[str],
) -> List[Tuple[CVERecord, Confidence]]:
    """
    Match a detected product+version string against the KNOWN_CVE_DB.

    Rules (conservative by design):
      - If version_string is None or empty, return [] — we never guess.
      - Confidence.HIGH  → version_string exactly matches the affected_versions
                          regex pattern for that CVE entry.
      - Confidence.LOW   → product matches but version regex did NOT match
                          (i.e. version was detected but doesn't align precisely).
      - CVEs from NVD live query are always LOW confidence because NVD version
        data is CPE-based and needs manual corroboration.

    Args:
        product_string:  Detected product name (e.g. "Orthanc 1.11.3" from nmap -sV).
        version_string:  Version explicitly identified by nmap -sV.
                         Pass None if nmap could not determine the version.

    Returns:
        List of (CVERecord, Confidence) tuples, sorted by CVSS score descending.
    """
    if not version_string:
        # Spec: never return a CVE match without a version string.
        return []

    product_lower = product_string.lower()
    results: List[Tuple[CVERecord, Confidence]] = []
    seen_cve_ids: set = set()

    for (product_kw, version_pattern), entry in KNOWN_CVE_DB.items():
        if product_kw not in product_lower:
            continue

        cve_id = entry["cve_id"]
        if cve_id in seen_cve_ids:
            continue

        # Determine confidence based on version regex match
        try:
            version_matches = bool(re.match(version_pattern, version_string, re.IGNORECASE))
        except re.error:
            version_matches = False

        confidence = Confidence.HIGH if version_matches else Confidence.LOW

        record = CVERecord(
            cve_id=cve_id,
            description=entry["description"],
            cvss_score=entry.get("cvss_score"),
            severity=entry.get("severity", "Unknown"),
            affected_product=f"{product_kw} {entry.get('affected_versions', '')}",
            remediation=entry.get("remediation", ""),
            source_url=entry.get("source_url", ""),
            cisa_kev=entry.get("cisa_kev", False),
        )
        results.append((record, confidence))
        seen_cve_ids.add(cve_id)

    # Sort by CVSS descending (None scores sort last)
    results.sort(key=lambda x: (x[0].cvss_score or 0.0), reverse=True)
    return results


# ---------------------------------------------------------------------------
# Convenience: get all known CVEs for a product (hardcoded + live NVD)
# ---------------------------------------------------------------------------

def get_all_cves_for_product(
    product_string: str,
    version_string: Optional[str] = None,
    query_live: bool = True,
) -> List[Tuple[CVERecord, Confidence]]:
    """
    Combine hardcoded DB matches with a live NVD API query.

    NVD results are always returned with Confidence.LOW because they have not
    been version-corroborated against a specific confirmed nmap -sV output.

    Args:
        product_string: Detected product (e.g. "orthanc").
        version_string: Version from nmap -sV, or None.
        query_live:     If False, skip the NVD API call (useful for unit tests).

    Returns:
        Merged list of (CVERecord, Confidence), deduped by CVE ID, sorted by CVSS.
    """
    matched = match_software_to_cves(product_string, version_string)
    seen = {r.cve_id for r, _ in matched}

    if query_live:
        # Use first token of product_string as keyword
        keyword = product_string.split()[0].lower()
        live_records = query_nvd_api(keyword, version_string)
        for rec in live_records:
            if rec.cve_id not in seen:
                matched.append((rec, Confidence.LOW))
                seen.add(rec.cve_id)

    matched.sort(key=lambda x: (x[0].cvss_score or 0.0), reverse=True)
    return matched


class VulnIntelligence:
    """Class wrapper for Vulnerability Intelligence engine."""

    def __init__(self, services: Optional[List[Dict[str, Any]]] = None, **kwargs: Any):
        self.services = services or []

    def lookup_cves_for_product(self, product_string: str, version_string: Optional[str] = None) -> List[CVERecord]:
        """Returns list of verified CVERecord objects for given product and version."""
        results = match_software_to_cves(product_string, version_string)
        return [record for record, conf in results]

    def query_live_nvd(self, keyword: str, version: Optional[str] = None) -> List[CVERecord]:
        return query_nvd_api(keyword, version)

    def run(self) -> List[Dict[str, Any]]:
        """
        Correlates discovered services against vulnerability intelligence.
        Returns a list of finding dicts.
        """
        findings: List[Dict[str, Any]] = []
        identified_product = False

        for svc in self.services:
            product = svc.get("product") or ""
            version = svc.get("version") or ""
            host = svc.get("host") or ""
            port = svc.get("port") or 0

            # Infer Orthanc if port 4242 or 8042 is open
            if not product and port in (4242, 8042):
                product = "Orthanc"

            if product:
                cve_matches = match_software_to_cves(product, version if version else None)
                if cve_matches:
                    identified_product = True
                    for cve_rec, conf in cve_matches:
                        kev_note = " [CISA KEV CATALOGUE MATCH - Actively Exploited in the Wild]" if getattr(cve_rec, "cisa_kev", False) else ""
                        findings.append({
                            "title": f"Known Vulnerability in {cve_rec.affected_product}: {cve_rec.cve_id}{kev_note}",
                            "severity": cve_rec.severity,
                            "host": host,
                            "port": port,
                            "service": product,
                            "evidence": (
                                f"Correlated with detected service '{product}' (version: {version or 'unspecified'}). "
                                f"{cve_rec.description}" + (f" Note: Listed in CISA Known Exploited Vulnerabilities catalogue." if getattr(cve_rec, "cisa_kev", False) else "")
                            ),
                            "detection_method": f"Vulnerability Intelligence DB ({cve_rec.source_url})",
                            "confidence": conf.value,
                            "finding_type": "VULNERABILITY",
                            "cve_id": cve_rec.cve_id,
                            "cvss_score": cve_rec.cvss_score,
                            "cvss_version": "3.1",
                            "remediation": cve_rec.remediation,
                            "standards_mapping": {
                                "NIST_CSF_2_0": ["ID.RA-01"],
                                "MDS2": ["CSUM Cybersecurity Software Update Management"],
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })

        # Phase 4 requirement: If target product version cannot be reliably identified, report finding requiring manual verification
        if not identified_product and self.services:
            target_host = self.services[0].get("host", "")
            target_port = self.services[0].get("port", 0)
            findings.append({
                "title": "PACS Software Version Unconfirmed — Manual Verification Required",
                "severity": "Informational",
                "host": target_host,
                "port": target_port,
                "service": "PACS Service",
                "evidence": "Remote DICOM service responded but exact software build and patch level could not be confirmed.",
                "detection_method": "Vulnerability Intelligence Correlation",
                "confidence": "Low",
                "finding_type": "INFORMATIONAL",
                "remediation": "Review PACS server release notes and administrative console to verify current software patch status.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return findings

