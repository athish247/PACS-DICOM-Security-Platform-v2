"""
db/database.py
SQLite persistence layer for the PACS/DICOM Security Assessment Platform.
Schema: targets, assessments, services, findings.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database location
# ---------------------------------------------------------------------------

_DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "pacs_assessments.db"
)
_DEFAULT_DB = os.path.normpath(_DEFAULT_DB)

_conn: Optional[sqlite3.Connection] = None


def get_connection(db_path: str = _DEFAULT_DB) -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(db_path, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _initialize_schema(_conn)
    return _conn


def _initialize_schema(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            host        TEXT    NOT NULL,
            port        INTEGER NOT NULL DEFAULT 104,
            called_ae   TEXT    NOT NULL DEFAULT 'ANY-SCP',
            calling_ae  TEXT    NOT NULL DEFAULT 'PACSSCANNER',
            timeout     INTEGER NOT NULL DEFAULT 30,
            notes       TEXT    DEFAULT '',
            authorized  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assessments (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id       INTEGER REFERENCES targets(id),
            target_host     TEXT,
            target_port     INTEGER,
            start_time      TEXT,
            end_time        TEXT,
            status          TEXT DEFAULT 'pending',
            modules_run     TEXT DEFAULT '[]',
            error_log       TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS services (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id   INTEGER REFERENCES assessments(id),
            host            TEXT,
            port            INTEGER,
            ae_response     TEXT,
            echo_success    INTEGER DEFAULT 0,
            tls_capable     INTEGER DEFAULT 0,
            response_ms     REAL,
            timestamp       TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id      TEXT,
            assessment_id   INTEGER REFERENCES assessments(id),
            title           TEXT,
            severity        TEXT,
            host            TEXT,
            port            INTEGER,
            service         TEXT,
            evidence        TEXT,
            detection_method TEXT,
            confidence      TEXT,
            finding_type    TEXT,
            timestamp       TEXT,
            cve_id          TEXT,
            cvss_score      REAL,
            remediation     TEXT,
            remediation_config TEXT,
            standards_mapping TEXT,
            status          TEXT DEFAULT 'Open',
            verification_status TEXT,
            analyst_notes   TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS compliance_controls (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id   INTEGER REFERENCES assessments(id),
            framework       TEXT,
            control_id      TEXT,
            control_title   TEXT,
            description     TEXT,
            status          TEXT,
            evidence        TEXT,
            remediation_guidance TEXT,
            associated_finding_ids TEXT
        );

        CREATE TABLE IF NOT EXISTS assets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id        TEXT UNIQUE,
            ip              TEXT NOT NULL,
            hostname        TEXT,
            mac_address     TEXT,
            vendor          TEXT DEFAULT 'Unknown',
            device_type     TEXT DEFAULT 'PACS Server',
            os_fingerprint  TEXT,
            open_ports      TEXT DEFAULT '[]',
            detected_services TEXT DEFAULT '[]',
            ae_titles       TEXT DEFAULT '[]',
            first_seen      TEXT,
            last_seen       TEXT,
            risk_score      REAL DEFAULT 0.0
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            details     TEXT    DEFAULT '',
            user        TEXT    NOT NULL DEFAULT 'local'
        );
    """)
    conn.commit()

    # Schema migration helper for existing findings table
    try:
        col_rows = conn.execute("PRAGMA table_info(findings)").fetchall()
        existing_cols = {row[1] for row in col_rows}
        for col_name, col_type in [
            ("finding_id", "TEXT"),
            ("remediation_config", "TEXT"),
            ("standards_mapping", "TEXT"),
            ("status", "TEXT DEFAULT 'Open'"),
            ("verification_status", "TEXT"),
            ("analyst_notes", "TEXT DEFAULT ''"),
        ]:
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")
        conn.commit()
    except Exception as exc:
        logger.debug("Schema migration notice: %s", exc)


# ---------------------------------------------------------------------------
# Target CRUD
# ---------------------------------------------------------------------------

def save_target(host: str, port: int, called_ae: str, calling_ae: str,
                timeout: int, notes: str, authorized: bool) -> int:
    """Insert a new target and return its rowid."""
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO targets (host, port, called_ae, calling_ae, timeout, notes,
                                authorized, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (host, port, called_ae, calling_ae, timeout, notes,
         1 if authorized else 0, datetime.utcnow().isoformat()),
    )
    conn.commit()
    return cur.lastrowid


def get_all_targets() -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def get_target(target_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Assessment CRUD
# ---------------------------------------------------------------------------

def create_assessment(target_host: str, target_port: int,
                      target_id: Optional[int] = None) -> int:
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO assessments (target_id, target_host, target_port,
                                    start_time, status)
           VALUES (?, ?, ?, ?, 'running')""",
        (target_id, target_host, target_port, datetime.utcnow().isoformat()),
    )
    conn.commit()
    return cur.lastrowid


def finish_assessment(assessment_id: int, modules_run: List[str],
                      errors: List[str]) -> None:
    conn = get_connection()
    conn.execute(
        """UPDATE assessments SET end_time=?, status='complete',
                                  modules_run=?, error_log=?
           WHERE id=?""",
        (datetime.utcnow().isoformat(),
         json.dumps(modules_run),
         json.dumps(errors),
         assessment_id),
    )
    conn.commit()


def get_all_assessments() -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM assessments ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_recent_assessments(limit: int = 10) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM assessments ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_assessment(assessment_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM assessments WHERE id=?", (assessment_id,)
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Service persistence
# ---------------------------------------------------------------------------

def save_service(assessment_id: int, service_dict: Any) -> None:
    if hasattr(service_dict, "to_dict"):
        service_dict = service_dict.to_dict()
    elif not isinstance(service_dict, dict):
        service_dict = vars(service_dict)

    conn = get_connection()
    conn.execute(
        """INSERT INTO services (assessment_id, host, port, ae_response,
                                  echo_success, tls_capable, response_ms, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (assessment_id,
         service_dict.get("host"),
         service_dict.get("port"),
         service_dict.get("ae_response") or service_dict.get("ae_title_response"),
         1 if service_dict.get("echo_success") else 0,
         1 if service_dict.get("tls_capable") else 0,
         service_dict.get("response_ms") or service_dict.get("response_time_ms"),
         service_dict.get("timestamp", datetime.utcnow().isoformat())),
    )
    conn.commit()


def get_services_for_assessment(assessment_id: int) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM services WHERE assessment_id=?", (assessment_id,)
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Finding persistence
# ---------------------------------------------------------------------------

def save_finding(assessment_id: int, finding_dict: Any) -> None:
    if hasattr(finding_dict, "to_dict"):
        finding_dict = finding_dict.to_dict()
    elif not isinstance(finding_dict, dict):
        finding_dict = vars(finding_dict)

    standards_json = json.dumps(finding_dict.get("standards_mapping", {}))

    conn = get_connection()
    conn.execute(
        """INSERT INTO findings (assessment_id, finding_id, title, severity, host, port,
                                  service, evidence, detection_method, confidence,
                                  finding_type, timestamp, cve_id, cvss_score,
                                  remediation, remediation_config, standards_mapping,
                                  status, verification_status, analyst_notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (assessment_id,
         finding_dict.get("finding_id"),
         finding_dict.get("title"),
         finding_dict.get("severity"),
         finding_dict.get("host"),
         finding_dict.get("port"),
         finding_dict.get("service"),
         finding_dict.get("evidence"),
         finding_dict.get("detection_method"),
         finding_dict.get("confidence"),
         finding_dict.get("finding_type"),
         finding_dict.get("timestamp", datetime.utcnow().isoformat()),
         finding_dict.get("cve_id"),
         finding_dict.get("cvss_score"),
         finding_dict.get("remediation"),
         finding_dict.get("remediation_config"),
         standards_json,
         finding_dict.get("status", "Open"),
         finding_dict.get("verification_status", "Automated Detection"),
         finding_dict.get("analyst_notes", "")),
    )
    conn.commit()


def update_finding_status(finding_id: str, new_status: str, notes: str = "") -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE findings SET status=?, analyst_notes=? WHERE finding_id=?",
        (new_status, notes, finding_id),
    )
    conn.commit()
    log_audit_event("FINDING_STATUS_CHANGE", f"id={finding_id} status={new_status}")


def save_compliance_controls(assessment_id: int, controls: List[Any]) -> None:
    conn = get_connection()
    for ctrl in controls:
        ctrl_dict = ctrl.to_dict() if hasattr(ctrl, "to_dict") else ctrl
        conn.execute(
            """INSERT INTO compliance_controls (assessment_id, framework, control_id,
                                                control_title, description, status,
                                                evidence, remediation_guidance,
                                                associated_finding_ids)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (assessment_id,
             ctrl_dict.get("framework"),
             ctrl_dict.get("control_id"),
             ctrl_dict.get("control_title"),
             ctrl_dict.get("description"),
             ctrl_dict.get("status"),
             ctrl_dict.get("evidence"),
             ctrl_dict.get("remediation_guidance"),
             json.dumps(ctrl_dict.get("associated_finding_ids", []))),
        )
    conn.commit()


def get_compliance_controls_for_assessment(assessment_id: int) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM compliance_controls WHERE assessment_id=? ORDER BY id",
        (assessment_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Asset Inventory persistence
# ---------------------------------------------------------------------------

def upsert_asset(asset_dict: Dict[str, Any]) -> None:
    conn = get_connection()
    ip = asset_dict.get("ip")
    asset_id = asset_dict.get("asset_id") or f"ASSET-{ip.replace('.', '-')}"
    now_ts = datetime.utcnow().isoformat()

    conn.execute(
        """INSERT INTO assets (asset_id, ip, hostname, mac_address, vendor,
                               device_type, os_fingerprint, open_ports, detected_services,
                               ae_titles, first_seen, last_seen, risk_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(asset_id) DO UPDATE SET
               last_seen=?,
               hostname=coalesce(excluded.hostname, assets.hostname),
               open_ports=excluded.open_ports,
               detected_services=excluded.detected_services,
               ae_titles=excluded.ae_titles,
               risk_score=excluded.risk_score""",
        (asset_id,
         ip,
         asset_dict.get("hostname", ""),
         asset_dict.get("mac_address"),
         asset_dict.get("vendor", "Unknown"),
         asset_dict.get("device_type", "PACS Server"),
         asset_dict.get("os_fingerprint"),
         json.dumps(asset_dict.get("open_ports", [])),
         json.dumps(asset_dict.get("detected_services", [])),
         json.dumps(asset_dict.get("ae_titles", [])),
         asset_dict.get("first_seen", now_ts),
         now_ts,
         asset_dict.get("risk_score", 0.0),
         now_ts),
    )
    conn.commit()


def get_all_assets() -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]


def get_findings_for_assessment(assessment_id: int) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM findings WHERE assessment_id=? ORDER BY id",
        (assessment_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_findings() -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Dashboard metrics
# ---------------------------------------------------------------------------

def get_dashboard_metrics() -> Dict[str, Any]:
    """Return real counts from the DB for the dashboard stat cards."""
    conn = get_connection()

    total_assessments = conn.execute(
        "SELECT COUNT(*) FROM assessments"
    ).fetchone()[0]

    dicom_services = conn.execute(
        "SELECT COUNT(*) FROM services WHERE echo_success=1"
    ).fetchone()[0]

    critical_findings = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE severity='Critical'"
    ).fetchone()[0]

    high_findings = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE severity='High'"
    ).fetchone()[0]

    try:
        total_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    except Exception:
        total_assets = 0

    try:
        compliance_passed = conn.execute(
            "SELECT COUNT(*) FROM compliance_controls WHERE status='PASSED'"
        ).fetchone()[0]
        compliance_failed = conn.execute(
            "SELECT COUNT(*) FROM compliance_controls WHERE status='FAILED'"
        ).fetchone()[0]
    except Exception:
        compliance_passed = 0
        compliance_failed = 0

    last_scan_row = conn.execute(
        "SELECT end_time FROM assessments WHERE end_time IS NOT NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    last_scan_time = last_scan_row[0] if last_scan_row else None

    return {
        "total_assessments": total_assessments,
        "dicom_services": dicom_services,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "total_assets": total_assets,
        "compliance_passed": compliance_passed,
        "compliance_failed": compliance_failed,
        "last_scan_time": last_scan_time,
    }


def get_severity_distribution() -> Dict[str, int]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
    ).fetchall()
    result = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for row in rows:
        sev = row["severity"] or "Informational"
        if sev in result:
            result[sev] = row["cnt"]
    return result


def get_finding_counts_for_assessment(assessment_id: int) -> Dict[str, int]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM findings WHERE assessment_id=? GROUP BY severity",
        (assessment_id,),
    ).fetchall()
    result = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for row in rows:
        sev = row["severity"] or "Informational"
        if sev in result:
            result[sev] = row["cnt"]
    return result


def init_db(db_path: str = _DEFAULT_DB) -> sqlite3.Connection:
    """Initialize database and return active connection."""
    return get_connection(db_path)


def log_audit_event(action: str, details: str = "", user: str = "local") -> None:
    """Write an immutable entry to the security audit trail."""
    try:
        conn = get_connection()
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, details, user) VALUES (?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), action, details, user),
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")


def save_assessment(assessment_obj_or_target: Any) -> int:
    """
    Saves an assessment record from either an AssessmentResult instance or dict.
    Returns the created assessment ID.
    """
    if hasattr(assessment_obj_or_target, "target"):
        target = assessment_obj_or_target.target
        host = getattr(target, "host", "unknown")
        port = getattr(target, "port", 104)
        return create_assessment(target_host=host, target_port=port)
    elif isinstance(assessment_obj_or_target, dict):
        host = assessment_obj_or_target.get("target_host", "unknown")
        port = assessment_obj_or_target.get("target_port", 104)
        return create_assessment(target_host=host, target_port=port)
    return create_assessment(target_host=str(assessment_obj_or_target), target_port=104)


def update_assessment_end(assessment_id: int, end_time: Optional[datetime] = None) -> None:
    """Updates assessment completion timestamp and marks status complete."""
    conn = get_connection()
    end_str = end_time.isoformat() if end_time else datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE assessments SET end_time=?, status='complete' WHERE id=?",
        (end_str, assessment_id),
    )
    conn.commit()


def list_assessments(limit: int = 50) -> List[Dict[str, Any]]:
    """Alias for get_recent_assessments."""
    return get_recent_assessments(limit=limit)


def list_targets() -> List[Dict[str, Any]]:
    """Alias for get_all_targets."""
    return get_all_targets()


