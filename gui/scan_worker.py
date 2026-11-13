"""
gui/scan_worker.py
Enterprise PyQt5 background worker orchestrating all medical imaging security assessment engines:
1. NetworkScanner: Port discovery & socket probing
2. DicomDiscovery: Real C-ECHO Verification SOP class & round-trip latency
3. AssociationTester: AE Title whitelisting & boundary negotiation
4. DicomAdvancedScanner: Presentation contexts (CT, MR, Worklist) & Transfer Syntaxes
5. DicomwebAssessor: QIDO-RS, WADO-RS, STOW-RS, CORS & cookie audit
6. TLSAssessor: Cryptographic cipher inspection & X.509 certificate validation
7. VulnIntelligence: Curated PACS CVEs & CISA KEV correlation
8. Risk & Compliance: CVSS scoring, HIPAA/NIST/MDS2 mapping & vendor-aware remediation
"""

from __future__ import annotations

import sys
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional

from PyQt5.QtCore import QThread, pyqtSignal

from models.findings import (
    Finding, FindingType, Severity, Confidence, FindingStatus, generate_finding_id
)


class ScanWorker(QThread):
    """
    Orchestrates all 8 assessment engines in sequence on a background QThread.
    """

    progress_signal  = pyqtSignal(int)
    status_signal    = pyqtSignal(str)
    finding_signal   = pyqtSignal(dict)
    service_signal   = pyqtSignal(dict)
    finished_signal  = pyqtSignal(bool)
    error_signal     = pyqtSignal(str)

    _STAGES = [
        ("NetworkScanner",          10),
        ("DicomDiscovery",          15),
        ("AssociationTester",       15),
        ("DicomAdvancedScanner",    15),
        ("DicomwebAssessor",        15),
        ("TLSAssessor",             15),
        ("VulnIntelligence",        10),
        ("RiskAndCompliance",        5),
    ]

    def __init__(
        self,
        host: str,
        port: int,
        called_ae: str = "ANY-SCP",
        calling_ae: str = "PACSSCANNER",
        timeout: int = 15,
        assessment_id: Optional[int] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.host          = host
        self.port          = port
        self.called_ae     = called_ae
        self.calling_ae    = calling_ae
        self.timeout       = timeout
        self.assessment_id = assessment_id
        self._cancel       = False

        self._findings: List[Dict[str, Any]] = []
        self._services: List[Dict[str, Any]] = []
        self._modules_run: List[str] = []
        self._errors: List[str] = []
        self._compliance_summary = None

    def request_cancel(self) -> None:
        self._cancel = True
        self.status_signal.emit("Cancellation requested — halting assessment gracefully…")

    def run(self) -> None:
        try:
            self._run_pipeline()
        except Exception as exc:
            tb = traceback.format_exc()
            self.error_signal.emit(f"Unexpected error: {exc}\n{tb}")
            self.finished_signal.emit(False)

    def _run_pipeline(self) -> None:
        progress_so_far = 0

        # ----------------------------------------------------------------
        # Stage 1/8 — Network Scanner
        # ----------------------------------------------------------------
        self.status_signal.emit("Stage 1/8 — NetworkScanner: port & service discovery…")
        if self._cancel:
            self.finished_signal.emit(False)
            return

        try:
            from engines.network_scanner import NetworkScanner
            candidate_ports = list(dict.fromkeys([self.port, 104, 11112, 2761, 2762, 2575, 4242, 8042, 80, 8080]))
            scanner = NetworkScanner(host=self.host, ports=candidate_ports, timeout=self.timeout)
            scan_result = scanner.run()
            self._modules_run.append("NetworkScanner")

            for port_info in getattr(scan_result, "open_ports", []):
                svc_dict = port_info.to_dict() if hasattr(port_info, "to_dict") else (port_info if isinstance(port_info, dict) else vars(port_info))
                self._services.append(svc_dict)
                self.service_signal.emit(svc_dict)

            for f in getattr(scan_result, "findings", []):
                f_dict = f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else vars(f))
                self._add_finding(f_dict)

        except Exception as exc:
            msg = f"NetworkScanner note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[0][1]
        self.progress_signal.emit(progress_so_far)

        # ----------------------------------------------------------------
        # Stage 2/8 — DICOM Discovery (C-ECHO Verification)
        # ----------------------------------------------------------------
        if self._cancel:
            self.finished_signal.emit(False)
            return

        self.status_signal.emit("Stage 2/8 — DicomDiscovery: C-ECHO Verification SOP class…")
        try:
            from engines.dicom_discovery import DicomDiscovery
            discovery = DicomDiscovery(
                host=self.host,
                ports=[self.port],
                called_ae=self.called_ae,
                calling_ae=self.calling_ae,
                timeout=self.timeout,
            )
            discovery_result = discovery.run()
            self._modules_run.append("DicomDiscovery")

            for svc in getattr(discovery_result, "services", []):
                svc_dict = svc.to_dict() if hasattr(svc, "to_dict") else (svc if isinstance(svc, dict) else vars(svc))
                self._services.append(svc_dict)
                self.service_signal.emit(svc_dict)

        except Exception as exc:
            msg = f"DicomDiscovery note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[1][1]
        self.progress_signal.emit(progress_so_far)

        # ----------------------------------------------------------------
        # Stage 3/8 — AE Title Association Security
        # ----------------------------------------------------------------
        if self._cancel:
            self.finished_signal.emit(False)
            return

        self.status_signal.emit("Stage 3/8 — AssociationTester: AE Title access boundaries…")
        try:
            from engines.dicom_association_tester import AssociationTester
            tester = AssociationTester(
                host=self.host,
                port=self.port,
                called_ae=self.called_ae,
                calling_ae=self.calling_ae,
                timeout=self.timeout,
            )
            assoc_results = tester.run_all_tests()
            self._modules_run.append("AssociationTester")

            for result in assoc_results:
                if getattr(result, "is_vulnerability", False):
                    finding_dict = result.to_finding() if hasattr(result, "to_finding") else vars(result)
                    if hasattr(finding_dict, "to_dict"):
                        finding_dict = finding_dict.to_dict()
                    self._add_finding(finding_dict)

        except Exception as exc:
            msg = f"AssociationTester note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[2][1]
        self.progress_signal.emit(progress_so_far)

        # ----------------------------------------------------------------
        # Stage 4/8 — Advanced DICOM (SOP Classes & Transfer Syntaxes)
        # ----------------------------------------------------------------
        if self._cancel:
            self.finished_signal.emit(False)
            return

        self.status_signal.emit("Stage 4/8 — DicomAdvancedScanner: presentation contexts & transfer syntaxes…")
        try:
            from engines.dicom_advanced_scanner import AdvancedDicomScanner
            adv_scanner = AdvancedDicomScanner(
                host=self.host,
                port=self.port,
                called_ae=self.called_ae,
                calling_ae=self.calling_ae,
                timeout=self.timeout,
            )
            adv_res = adv_scanner.run_assessment()
            self._modules_run.append("DicomAdvancedScanner")

            for f in adv_res.findings:
                self._add_finding(f.to_dict())

        except Exception as exc:
            msg = f"DicomAdvancedScanner note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[3][1]
        self.progress_signal.emit(progress_so_far)

        # ----------------------------------------------------------------
        # Stage 5/8 — DICOMweb & PACS REST Security
        # ----------------------------------------------------------------
        if self._cancel:
            self.finished_signal.emit(False)
            return

        self.status_signal.emit("Stage 5/8 — DicomwebAssessor: QIDO-RS, WADO-RS & REST access…")
        try:
            from engines.dicomweb_assessor import DicomwebAssessor
            # Check web port (8042 for Orthanc, or 80/443/8080)
            web_ports = [8042, 80, 443, 8080]
            for wp in web_ports:
                from engines.dicom_discovery import check_port_open
                if check_port_open(self.host, wp, timeout=0.8):
                    web_assessor = DicomwebAssessor(host=self.host, port=wp, timeout=self.timeout)
                    web_res = web_assessor.run_assessment()
                    for f in web_res.findings:
                        self._add_finding(f.to_dict())

            self._modules_run.append("DicomwebAssessor")

        except Exception as exc:
            msg = f"DicomwebAssessor note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[4][1]
        self.progress_signal.emit(progress_so_far)

        # ----------------------------------------------------------------
        # Stage 6/8 — TLS & Cryptographic Assessor
        # ----------------------------------------------------------------
        if self._cancel:
            self.finished_signal.emit(False)
            return

        self.status_signal.emit("Stage 6/8 — TLSAssessor: TLS protocol, ciphers & certificates…")
        try:
            from engines.tls_assessor import TLSAssessor
            tls = TLSAssessor(host=self.host, port=self.port, timeout=self.timeout)
            tls_findings = tls.run()
            self._modules_run.append("TLSAssessor")

            for f in tls_findings or []:
                f_dict = f.to_dict() if hasattr(f, "to_dict") else f
                self._add_finding(f_dict)

        except Exception as exc:
            msg = f"TLSAssessor note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[5][1]
        self.progress_signal.emit(progress_so_far)

        # ----------------------------------------------------------------
        # Stage 7/8 — Vulnerability Intelligence & CISA KEV
        # ----------------------------------------------------------------
        if self._cancel:
            self.finished_signal.emit(False)
            return

        self.status_signal.emit("Stage 7/8 — VulnIntelligence: CVE correlation & CISA KEV…")
        try:
            from engines.vuln_intelligence import VulnIntelligence
            intel = VulnIntelligence(services=self._services)
            additional_findings = intel.run()
            self._modules_run.append("VulnIntelligence")

            for f in additional_findings or []:
                f_dict = f.to_dict() if hasattr(f, "to_dict") else f
                self._add_finding(f_dict)

        except Exception as exc:
            msg = f"VulnIntelligence note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[6][1]
        self.progress_signal.emit(progress_so_far)

        # ----------------------------------------------------------------
        # Stage 8/8 — Risk Scoring, Compliance Mapping & Remediation Diff
        # ----------------------------------------------------------------
        if self._cancel:
            self.finished_signal.emit(False)
            return

        self.status_signal.emit("Stage 8/8 — Scoring, Compliance mapping & Remediation generation…")
        try:
            from engines.risk_scorer import RiskScorer
            from engines.remediation_engine import RemediationEngine
            from engines.compliance_engine import ComplianceEngine

            # 1. Risk scoring
            scorer = RiskScorer(findings=self._findings)
            self._findings = scorer.run() or self._findings
            self._modules_run.append("RiskScorer")

            # 2. Vendor remediation blueprints
            rem_engine = RemediationEngine(target_product="Orthanc")
            for f in self._findings:
                plan = rem_engine.generate_plan(Finding(
                    title=f.get("title", ""),
                    severity=Severity(f.get("severity", "Informational")) if f.get("severity") in [s.value for s in Severity] else Severity.INFORMATIONAL,
                    host=self.host,
                    port=self.port,
                    service=f.get("service", "DICOM"),
                    evidence=f.get("evidence", ""),
                    detection_method=f.get("detection_method", ""),
                    confidence=Confidence.HIGH,
                    finding_type=FindingType.VULNERABILITY,
                    remediation=f.get("remediation"),
                    finding_id=f.get("finding_id", generate_finding_id()),
                ))
                f["remediation_config"] = plan.config_diff
                f["rollback_procedure"] = plan.rollback_procedure
                f["verification_steps"] = plan.verification_steps
                f["vendor_doc_url"] = plan.vendor_doc_url

            # 3. Compliance evaluation
            typed_findings = []
            for f in self._findings:
                sev_enum = Severity(f.get("severity", "Informational")) if f.get("severity") in [s.value for s in Severity] else Severity.INFORMATIONAL
                typed_findings.append(Finding(
                    title=f.get("title", ""),
                    severity=sev_enum,
                    host=self.host,
                    port=self.port,
                    service=f.get("service", "DICOM"),
                    evidence=f.get("evidence", ""),
                    detection_method=f.get("detection_method", ""),
                    confidence=Confidence.HIGH,
                    finding_type=FindingType.VULNERABILITY,
                    finding_id=f.get("finding_id", generate_finding_id()),
                    standards_mapping=f.get("standards_mapping", {}),
                ))

            comp_engine = ComplianceEngine(typed_findings)
            self._compliance_summary = comp_engine.evaluate()
            self._modules_run.append("ComplianceEngine")

        except Exception as exc:
            msg = f"Compliance/Remediation note: {exc}"
            self.status_signal.emit(msg)
            self._errors.append(msg)

        progress_so_far += self._STAGES[7][1]
        self.progress_signal.emit(100)

        # ----------------------------------------------------------------
        # Persist to DB
        # ----------------------------------------------------------------
        self.status_signal.emit("Saving results & compliance records to database…")
        self._save_to_db()

        comp_score = f"{self._compliance_summary.compliance_score_pct}%" if self._compliance_summary else "N/A"
        self.status_signal.emit(
            f"Assessment complete — {len(self._findings)} finding(s), "
            f"{len(self._services)} service(s), Compliance: {comp_score}."
        )
        self.finished_signal.emit(True)

    def _add_finding(self, finding_dict: Dict[str, Any]) -> None:
        """Deduplicates findings by title and target port before appending."""
        if not finding_dict.get("finding_id"):
            finding_dict["finding_id"] = generate_finding_id()
        if not finding_dict.get("status"):
            finding_dict["status"] = FindingStatus.OPEN.value

        title = finding_dict.get("title")
        port = finding_dict.get("port")
        # Deduplication check
        if any(f.get("title") == title and f.get("port") == port for f in self._findings):
            return

        self._findings.append(finding_dict)
        self.finding_signal.emit(finding_dict)

    def _save_to_db(self) -> None:
        try:
            from db import database as db

            assessment_id = self.assessment_id
            if assessment_id is None:
                assessment_id = db.create_assessment(
                    target_host=self.host,
                    target_port=self.port,
                )
                self.assessment_id = assessment_id

            for svc_dict in self._services:
                try:
                    db.save_service(assessment_id, svc_dict)
                except Exception as exc:
                    self._errors.append(f"Service save error: {exc}")

            for finding_dict in self._findings:
                try:
                    db.save_finding(assessment_id, finding_dict)
                except Exception as exc:
                    self._errors.append(f"Finding save error: {exc}")

            # Save compliance controls if available
            if self._compliance_summary and hasattr(db, "save_compliance_controls"):
                db.save_compliance_controls(assessment_id, self._compliance_summary.controls)

            db.finish_assessment(assessment_id, self._modules_run, self._errors)

        except Exception as exc:
            self._errors.append(f"DB persistence error: {exc}")
