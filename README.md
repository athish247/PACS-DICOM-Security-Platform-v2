# pacs-dicom-security-tool-
A security assessment tool for PACS/DICOM systems to identify vulnerabilities and ensure HIPAA/GDPR compliance
# PACS/DICOM Security Assessment Tool

## ⚡ Core Architecture & Capabilities

1. **DICOM Upper Layer Verification (C-ECHO):** Layer 7 application verification with sub-millisecond round-trip telemetry.
2. **Application Entity (AE) Boundary Testing:** Probes Calling/Called AE Title authorization and identifies allowlist bypass vulnerabilities.
3. **Advanced SOP & Transfer Syntax Negotiation:** Tests exposure of CT/MR/Worklist presentation contexts across uncompressed and compressed syntaxes.
4. **DICOMweb REST API & Security Header Audit:** Evaluates QIDO-RS, WADO-RS, and STOW-RS endpoints for unauthenticated exposure, CORS misconfigurations, and cookie flags.
5. **Cryptographic & TLS Assessor:** Audits TLS 1.2/1.3 handshakes, deprecation of weak cipher suites (RC4/3DES), and X.509 certificate integrity.
6. **Vulnerability Intelligence (Curated Medical CVEs):** Deterministic CVE mapping for clinical PACS firmware (Orthanc, dcm4chee, GE, Philips, Siemens) with CVSS v3.1 scoring.
7. **Healthcare Regulatory Compliance Engine:** Automated scoring and gap analysis across HIPAA, DICOM PS 3.15, MDS2, and NIST controls.
8. **Clinical Subnet Scope Guardrails:** Strict `/24` CIDR boundaries, private network enforcement, and non-destructive read-only safety guarantees.
9. **Multi-Format Enterprise Reporting:** Executive ReportLab PDF generation, CSV exports, and SIEM streaming (CEF, LEEF, JSON).
A GUI-based tool to assess the security of PACS/DICOM systems, identify vulnerabilities, and ensure compliance with HIPAA/GDPR regulations.

## Installation
1. Clone the repository:
   ```bash
 https://github.com/athish247/pacs-dicom-security-tool-.git

Install dependencies:
pip install -r requirements.txt

Run the tool:
python pacs_final.py
[requirement.txt](https://github.com/user-attachments/files/20679761/requirement.txt)

# PACS & DICOM Cybersecurity Assessment Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Standards: DICOM PS 3.15](https://img.shields.io/badge/Standard-DICOM%20PS%203.15-orange.svg)](https://www.dicomstandard.org/)
[![Compliance: HIPAA & MDS2](https://img.shields.io/badge/Compliance-HIPAA%20%7C%20MDS2-red.svg)](https://www.hhs.gov/hipaa/for-professionals/security/index.html)

An enterprise-grade, non-destructive cybersecurity assessment platform engineered for clinical imaging infrastructure (PACS, VNA, DICOM Modalities, and DICOMweb endpoints). 

Designed in alignment with **IEC 80001-1**, **HIPAA Security Rule (45 CFR § 164.312)**, **DICOM PS 3.15**, and **NIST CSF 2.0**.

---


---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.10 or higher
* [Optional] Nmap installed on host for deep port scanning

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/pacs-security-platform.git
cd pacs-security-platform
```

### 2. Set Up a Virtual Environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Platform

### Start the GUI Console
```bash
python main.py
```

### Run the Automated Verification Test Suite (13 Modules)
```bash
python test_harness.py
```

---

## 📂 Project Structure
