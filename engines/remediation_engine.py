"""
engines/remediation_engine.py
Vendor-Aware Automated Remediation Intelligence Engine.

Generates precise, actionable configuration diffs, locations, and rollback procedures
for medical imaging infrastructure (Orthanc, dcm4chee, and standard modalities).
Advisory only — never modifies production PACS files automatically.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from models.findings import Finding

logger = logging.getLogger(__name__)


@dataclass
class RemediationPlan:
    finding_id: str
    finding_title: str
    target_product: str
    root_cause: str
    technical_impact: str
    config_file_path: str
    config_diff: str
    prerequisites: str
    potential_service_impact: str
    rollback_procedure: str
    verification_steps: str
    vendor_doc_url: str


ORTHANC_REMEDIATION_TEMPLATES = {
    "Unencrypted DICOM": {
        "root_cause": "Orthanc is configured with DicomTlsEnabled=false or missing DICOM-TLS certificate bindings.",
        "technical_impact": "Medical image pixel data and metadata transmitted over port 4242 are readable in plaintext via network packet inspection.",
        "config_file_path": "/etc/orthanc/orthanc.json or C:\\Program Files\\Orthanc Server\\Configuration\\orthanc.json",
        "config_diff": """--- orthanc.json (before)
+++ orthanc.json (after)
@@ -45,3 +45,5 @@
-  "DicomTlsEnabled" : false,
+  "DicomTlsEnabled" : true,
+  "DicomTlsCertificateFile" : "/etc/orthanc/pacs_server.crt",
+  "DicomTlsPrivateKeyFile"  : "/etc/orthanc/pacs_server.key",
+  "DicomTlsTrustedCertificates" : "/etc/orthanc/trusted_modalities_ca.crt",
""",
        "prerequisites": "Issue X.509 certificate for the PACS hostname and deploy the private key to a root/SYSTEM-protected directory.",
        "potential_service_impact": "Requires restarting Orthanc service. Legacy modalities lacking TLS 1.3 support must be migrated or routed via an internal TLS terminator.",
        "rollback_procedure": "Set 'DicomTlsEnabled': false in orthanc.json and restart the Orthanc service.",
        "verification_steps": "Run the PACS Security Platform assessment tool against port 4242 to verify TLS negotiation succeeds.",
        "vendor_doc_url": "https://book.orthanc-server.com/faq/features.html#dicom-tls",
    },
    "AE Title": {
        "root_cause": "Orthanc is configured with DicomCheckCalledAet=false and allows anonymous Calling AE Titles.",
        "technical_impact": "Any machine on the clinical subnet can query or send medical studies without prior authorization.",
        "config_file_path": "Configuration/orthanc.json",
        "config_diff": """--- orthanc.json (before)
+++ orthanc.json (after)
@@ -60,2 +60,7 @@
-  "DicomCheckCalledAet" : false,
+  "DicomCheckCalledAet" : true,
+  "DicomAlwaysAllowEcho" : false,
+  "DicomModalities" : {
+    "AUTHORIZED_MODALITY" : [ "CT_SCANNER_01", "192.168.1.120", 104 ]
+  },
""",
        "prerequisites": "Gather all authorized modality AE Titles, IP addresses, and DICOM listening ports from clinical engineering.",
        "potential_service_impact": "Unregistered modalities will receive A-ASSOCIATE-RJ and will not be able to push studies until added to DicomModalities.",
        "rollback_procedure": "Set 'DicomCheckCalledAet': false and reload configuration.",
        "verification_steps": "Probe with an unauthorized Calling AE title to verify an association rejection (A-ASSOCIATE-RJ) is returned.",
        "vendor_doc_url": "https://book.orthanc-server.com/users/configuration.html#securing-dicom",
    },
    "QIDO-RS": {
        "root_cause": "Orthanc HTTP REST server has AuthenticationEnabled=false.",
        "technical_impact": "Unauthenticated access allows anyone on the network to query patient metadata and download imaging studies via HTTP.",
        "config_file_path": "Configuration/orthanc.json",
        "config_diff": """--- orthanc.json (before)
+++ orthanc.json (after)
@@ -20,2 +20,6 @@
-  "AuthenticationEnabled" : false,
+  "AuthenticationEnabled" : true,
+  "RegisteredUsers" : {
+    "orthanc_admin" : "CHANGEME_STRONG_PASSWORD_HERE"
+  },
""",
        "prerequisites": "Provision credentials in the hospital secrets manager or configure an OAuth2 / Keycloak proxy plugin.",
        "potential_service_impact": "Web viewers (OHIF / Weasis) must be configured with Basic Auth or Bearer tokens.",
        "rollback_procedure": "Restore previous authentication settings in orthanc.json.",
        "verification_steps": "Issue GET /studies to verify HTTP 401 Unauthorized is returned without credentials.",
        "vendor_doc_url": "https://book.orthanc-server.com/users/configuration.html#authenticating-http-users",
    },
}


class RemediationEngine:
    """
    Generates tailored, vendor-specific remediation blueprints and configuration diffs.
    """

    def __init__(self, target_product: str = "Orthanc"):
        self.target_product = target_product

    def generate_plan(self, finding: Finding) -> RemediationPlan:
        title = finding.title

        template = None
        for key in ORTHANC_REMEDIATION_TEMPLATES:
            if key.lower() in title.lower():
                template = ORTHANC_REMEDIATION_TEMPLATES[key]
                break

        if template is None:
            # Fallback generic plan
            return RemediationPlan(
                finding_id=finding.finding_id,
                finding_title=finding.title,
                target_product=self.target_product,
                root_cause=f"Security misconfiguration in service '{finding.service}'.",
                technical_impact=f"Non-conformance with healthcare security controls: {finding.evidence}",
                config_file_path="Vendor configuration console / registry",
                config_diff=finding.remediation or "Apply vendor security hardening guide.",
                prerequisites="Review system backup status and notify clinical staff.",
                potential_service_impact="Temporary service restart may be required during maintenance window.",
                rollback_procedure="Revert configuration changes and restart services.",
                verification_steps="Re-run security scan using the assessment platform.",
                vendor_doc_url="https://www.medicalimaging.org/dicom/",
            )

        return RemediationPlan(
            finding_id=finding.finding_id,
            finding_title=finding.title,
            target_product=self.target_product,
            root_cause=template["root_cause"],
            technical_impact=template["technical_impact"],
            config_file_path=template["config_file_path"],
            config_diff=template["config_diff"],
            prerequisites=template["prerequisites"],
            potential_service_impact=template["potential_service_impact"],
            rollback_procedure=template["rollback_procedure"],
            verification_steps=template["verification_steps"],
            vendor_doc_url=template["vendor_doc_url"],
        )
