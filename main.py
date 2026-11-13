"""
main.py
Application Entry Point for PACS/DICOM Security Assessment Platform.
Initializes SQLite database, validates dependencies, and launches the PyQt5 user interface.
"""

from __future__ import annotations

import sys
import os
import argparse
import logging

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pacs_platform")


def check_dependencies() -> bool:
    """
    Validates presence and version compatibility of all core dependencies.
    Used by --check-deps flag.
    """
    deps = [
        ("PyQt5", "PyQt5.QtWidgets"),
        ("pynetdicom", "pynetdicom"),
        ("pydicom", "pydicom"),
        ("python-nmap", "nmap"),
        ("reportlab", "reportlab"),
        ("requests", "requests"),
        ("sqlite3", "sqlite3"),
    ]

    all_ok = True
    print("=" * 60)
    print(" PACS/DICOM Security Platform — Dependency Verification")
    print("=" * 60)

    for name, module_name in deps:
        try:
            mod = __import__(module_name)
            ver = getattr(mod, "__version__", "installed")
            print(f" [+] {name:<16} : PASS (version {ver})")
        except ImportError as e:
            print(f" [!] {name:<16} : FAIL ({e})")
            all_ok = False

    print("=" * 60)
    return all_ok


def main():
    parser = argparse.ArgumentParser(
        description="PACS/DICOM Security Assessment Platform — Medical Cybersecurity Tool"
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Check and display status of all required dependencies then exit."
    )
    args = parser.parse_args()

    if args.check_deps:
        success = check_dependencies()
        sys.exit(0 if success else 1)

    print("\n" + "=" * 70)
    print("  PACS / DICOM Security Assessment Platform v2.0")
    print("  Engineered for Authorized Healthcare Cybersecurity Assessments")
    print("  Enforcing HIPAA Safe Harbor, GDPR & DICOM PS 3.15 Conformance")
    print("=" * 70 + "\n")

    # 1. Initialize SQLite database & audit trail
    try:
        from db import database as db
        db.init_db()
        db.log_audit_event("APP_START", "PACS Security Assessment Platform launched")
        logger.info("Local SQLite database initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

    # 2. Launch PyQt5 Application
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt
    from gui.main_window import MainWindow

    # Set DPI awareness for modern Windows displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("PACS/DICOM Security Assessment Platform")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Healthcare Cybersecurity")

    window = MainWindow()
    window.show()

    exit_code = app.exec_()

    try:
        from db import database as db
        db.log_audit_event("APP_EXIT", f"Platform exited with code {exit_code}")
    except Exception:
        pass

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
