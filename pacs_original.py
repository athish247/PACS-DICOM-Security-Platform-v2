import sys, socket, nmap, threading, json, ssl
from datetime import datetime
from collections import defaultdict
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QComboBox, QTabWidget, QTextEdit, QProgressBar,
                            QListWidget, QTreeWidget, QTreeWidgetItem, QCheckBox, QSpinBox, 
                             QGroupBox, QMessageBox, QFileDialog,
                             QAction, QDockWidget)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QColor, QPalette
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
import requests
import time

DICOM_PORTS = [104, 11112, 2761, 2762, 2575, 9090, 8080, 80, 443]
DICOM_SOP_CLASSES = {
    '1.2.840.10008.5.1.4.1.1.2': 'CT Image Storage',
    '1.2.840.10008.5.1.4.1.1.4': 'MR Image Storage',
    '1.2.840.10008.5.1.4.1.1.1': 'CR Image Storage',
    '1.2.840.10008.5.1.4.1.1.6.1': 'US Image Storage',
    '1.2.840.10008.5.1.4.1.1.7': 'Secondary Capture Image Storage',
    '1.2.840.10008.5.1.4.1.1.88.11': 'Basic Text SR',
    '1.2.840.10008.5.1.4.1.1.88.22': 'Enhanced SR',
    '1.2.840.10008.5.1.4.1.1.88.33': 'Comprehensive SR',
    '1.2.840.10008.5.1.4.1.1.104.1': 'Encapsulated PDF Storage',
    '1.2.840.10008.5.1.4.1.1.481.1': 'RT Image Storage',
    '1.2.840.10008.5.1.4.1.1.481.2': 'RT Dose Storage',
    '1.2.840.10008.5.1.4.1.1.481.3': 'RT Structure Set Storage',
    '1.2.840.10008.5.1.4.1.1.481.4': 'RT Beams Treatment Record Storage',
    '1.2.840.10008.5.1.4.1.1.481.5': 'RT Plan Storage',
    '1.2.840.10008.5.1.4.1.1.481.6': 'RT Brachy Treatment Record Storage',
    '1.2.840.10008.5.1.4.1.1.481.7': 'RT Treatment Summary Record Storage',
    '1.2.840.10008.5.1.4.1.1.481.8': 'RT Ion Plan Storage',
    '1.2.840.10008.5.1.4.1.1.481.9': 'RT Ion Beams Treatment Record Storage',
    '1.2.840.10008.5.1.4.1.1.20': 'Nuclear Medicine Image Storage'
}
class ScanWorker(QObject, threading.Thread):
    update_signal = pyqtSignal(str, str) 
    progress_signal = pyqtSignal(int)     
    finished_signal = pyqtSignal()       

    def __init__(self, target, ports, scan_type, parent=None):
        QObject.__init__(self, parent)
        threading.Thread.__init__(self)
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self._is_running = True
        self.results = []
        self.vulnerabilities = []

    def run(self):
        try:
            if self.scan_type == "Quick Scan":
                self.perform_quick_scan()
            elif self.scan_type == "Deep Scan":
                self.perform_deep_scan()
            self.finished_signal.emit()
        except Exception as e:
            self.update_signal.emit("Error", f"Scan failed: {str(e)}")
            self.finished_signal.emit()

    def perform_quick_scan(self):
        self.update_signal.emit("Status", "Starting quick scan...")

        nm = nmap.PortScanner()
        ports_str = ','.join(map(str, self.ports))
        self.update_signal.emit("Status", f"Scanning ports: {ports_str}")
        nm.scan(hosts=self.target, ports=ports_str, arguments='-sV --script=banner')
        self.progress_signal.emit(20)

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    result = {
                        'host': host,
                        'port': port,
                        'state': service['state'],
                        'service': service['name'],
                        'version': service.get('version', 'unknown'),
                        'vulnerabilities': []
                    }

                    if port in [80, 443, 8080, 8443] and service['name'] in ['http', 'https']:
                        web_vulns = self.check_web_vulnerabilities(host, port, service['name'])
                        result['vulnerabilities'].extend(web_vulns)
                    
             
                    dicom_vulns = self.check_basic_dicom_vulnerabilities(host, port)
                    result['vulnerabilities'].extend(dicom_vulns)
                    
                    self.results.append(result)
                    self.update_signal.emit("Result", json.dumps(result))
        
        self.progress_signal.emit(100)
        self.update_signal.emit("Status", "Quick scan completed")

    def perform_deep_scan(self):
        self.update_signal.emit("Status", "Starting deep scan...")

        self.perform_quick_scan()
        self.progress_signal.emit(30)

        self.update_signal.emit("Status", "Performing advanced DICOM tests...")
        dicom_vulns = self.check_advanced_dicom_vulnerabilities(self.target)
        self.vulnerabilities.extend(dicom_vulns)
        self.progress_signal.emit(60)

        self.update_signal.emit("Status", "Checking TLS/SSL configurations...")
        tls_vulns = self.check_tls_configurations(self.target)
        self.vulnerabilities.extend(tls_vulns)
        self.progress_signal.emit(80)

        self.update_signal.emit("Status", "Performing compliance checks...")
        compliance_vulns = self.check_compliance(self.target)
        self.vulnerabilities.extend(compliance_vulns)
        self.progress_signal.emit(100)
        
        self.update_signal.emit("Status", "Deep scan completed")
        
    def check_web_vulnerabilities(self, host, port, protocol):
        vulns = []
        url = f"{protocol}://{host}:{port}"
        
        try:
            if self.test_default_credentials(url):
                vulns.append({
                    'type': 'Default Credentials',
                    'severity': 'High',
                    'description': (
                        'Default administrative credentials (admin/admin, root/password, etc.) are enabled on the web interface. '
                        'This allows unauthorized access to sensitive configuration and patient data. Attackers can use brute force '
                        'or dictionary attacks to gain access using known default credentials.'
                    ),
                    'solution': (
                        '1. Change all default credentials immediately\n'
                        '2. Implement strong password policies (min 12 chars, complexity requirements)\n'
                        '3. Enable account lockout after 5 failed attempts\n'
                        '4. Implement multi-factor authentication for admin access\n'
                        '5. Regularly audit user accounts and permissions'
                    ),
                    'exploitation': (
                        '1. Use tools like Hydra or Metasploit to brute force login pages\n'
                        '2. Try common default credentials from vendor documentation\n'
                        '3. Use credential stuffing with known password leaks\n'
                        '4. Once logged in, escalate privileges through misconfigurations'
                    )
                })
                
            if self.check_directory_listing(url):
                vulns.append({
                    'type': 'Directory Listing',
                    'severity': 'Medium',
                    'description': ('Directory listing is enabled on the web server, exposing sensitive files and directories. '
                        'This can reveal backup files, configuration files, patient data exports, and other sensitive '
                        'information that could be used to further compromise the system.'
                    ),
                    'solution': (
                        '1. Disable directory listing in web server configuration (Apache: "Options -Indexes")\n'
                        '2. Implement proper .htaccess restrictions\n'
                        '3. Ensure each directory has an index.html file\n'
                        '4. Regularly scan for and remove backup/temporary files\n'
                        '5. Implement proper access controls for sensitive directories'
                    ),
                    'exploitation': (
                        '1. Manually browse directories looking for sensitive files\n'
                        '2. Use tools like DirBuster or Gobuster to enumerate directories\n'
                        '3. Search for backup files (*.bak, *.old, *.tmp)\n'
                        '4. Look for configuration files containing credentials\n'
                        '5. Check for unprotected patient data exports (CSV, XML)'
                    )
                })

            outdated, version = self.check_outdated_software(url)
            if outdated:
                vulns.append({
                    'type': 'Outdated Software',
                    'severity': 'High',
                    'description': (
                        f'Outdated and vulnerable software version detected: {version}. This version contains known '
                        'security vulnerabilities that could allow remote code execution, SQL injection, or other '
                        'serious attacks. Attackers can exploit these vulnerabilities to gain full control of the system.'
                    ),
                    'solution': (
                        '1. Immediately update to the latest patched version\n'
                        '2. Subscribe to vendor security bulletins\n'
                        '3. Implement a patch management process\n'
                        '4. If update not possible, apply all available security mitigations\n'
                        '5. Isolate the system until patched'
                    ),
                    'exploitation': (
                        '1. Search exploit databases (ExploitDB, Metasploit) for known vulnerabilities\n'
                        '2. Use version-specific exploits for RCE or privilege escalation\n'
                        '3. Chain multiple vulnerabilities for deeper system access\n'
                        '4. Use vulnerability scanners to identify attack vectors'
                    )
                })
        
        except Exception as e:
            self.update_signal.emit("Error", f"Web vulnerability check failed: {str(e)}")
        return vulns

    def check_basic_dicom_vulnerabilities(self, host, port):
        vulns = []
        
        try:
            if not self.check_dicom_authentication(host, port):
                vulns.append({
                    'type': 'No Authentication',
                    'severity': 'Critical',
                    'description': (
                        'DICOM service does not require any authentication, allowing complete anonymous access. '
                        'Attackers can query, retrieve, modify, or delete medical images and patient data without '
                        'any credentials. This violates HIPAA requirements for access controls.'
                    ),
                    'solution': (
                        '1. Implement DICOM authentication (DICOM TLS with certificates)\n'
                        '2. Configure Access Control Lists (ACLs) for DICOM services\n'
                        '3. Enable DICOM audit logging\n'
                        '4. Restrict DICOM services to VPN or internal network only\n'
                        '5. Implement IP whitelisting for modality connections'
                    ),
                    'exploitation': (
                        '1. Use DICOM tools like dcmtk to connect anonymously\n'
                        '2. Query patient studies using C-FIND\n'
                        '3. Retrieve images using C-GET/C-MOVE\n'
                        '4. Inject malicious DICOM files using C-STORE\n'
                        '5. Perform denial of service by flooding with requests'
                    )
                })

            if self.check_cmove_vulnerability(host, port):
                vulns.append({
                    'type': 'C-MOVE Arbitrary File Access',
                    'severity': 'Critical',
                    'description': (
                        'DICOM service allows arbitrary file access via C-MOVE operations. Attackers can abuse this '
                        'to read sensitive system files (passwords, configurations) or write malicious files to the '
                        'server. This can lead to complete system compromise and data exfiltration.'
                    ),
                    'solution': (
                        '1. Restrict C-MOVE operations to authorized directories only\n'
                        '2. Implement strict path validation for destination paths\n'
                        '3. Run DICOM services under a limited privilege account\n'
                        '4. Enable filesystem auditing for DICOM storage directories\n'
                        '5. Regularly audit DICOM service configurations'
                    ),
                    'exploitation': (
                        '1. Use C-MOVE with directory traversal payloads (../../etc/passwd)\n'
                        '2. Write web shells to web accessible directories\n'
                        '3. Exfiltrate configuration files containing credentials\n'
                        '4. Overwrite critical system files to maintain persistence'
                    )
                })
            
            if port not in [2762, 443, 80]:  
                vulns.append({
                    'type': 'If its an unencrypted Communication',
                    'severity': 'High',
                    'description': (
                        'Even closed ports are flagged to warn of future risks if they reopen without encryption, ensuring proactive HIPAA/GDPR compliance.'
                        'DICOM communication is not encrypted, allowing man-in-the-middle attacks. Patient data, '
                        'including PHI and medical images, can be intercepted and modified. This violates HIPAA '
                        'encryption requirements for data in transit.'
                    ),
                    'solution': (
                        '1. Implement DICOM-TLS on standard port 2762\n'
                        '2. Use valid certificates from trusted CAs\n'
                        '3. Disable SSLv3/TLSv1.0, enforce TLSv1.2+\n'
                        '4. Configure strong cipher suites\n'
                        '5. Implement certificate pinning'
                    ),
                    'exploitation': (
                        '1. Use network sniffing tools (Wireshark) to capture DICOM traffic\n'
                        '2. Extract patient data and PHI from unencrypted packets\n'
                        '3. Modify DICOM data in transit (image manipulation)\n'
                        '4. Perform session hijacking attacks'
                    )
                })
        
        except Exception as e:
            self.update_signal.emit("Error", f"DICOM vulnerability check failed: {str(e)}")
        
        return vulns

    def check_advanced_dicom_vulnerabilities(self, host):
        vulns = []
        
        try:
            if self.check_sop_class_bypass(host):
                vulns.append({
                    'type': 'SOP Class Permission Bypass',
                    'severity': 'High',
                    'description': (
                        'DICOM service allows unauthorized access to restricted SOP classes. Attackers can access '
                        'sensitive SOP classes like Modality Worklist or Storage Commitment without proper '
                        'authorization, potentially modifying scheduled procedures or hiding malicious activities.'
                    ),
                    'solution': (
                        '1. Implement strict SOP Class access controls\n'
                        '2. Configure separate AE Titles for different access levels\n'
                        '3. Regularly audit SOP Class usage\n'
                        '4. Implement DICOM role-based access control\n'
                        '5. Monitor for unusual SOP Class access patterns'
                    ),
                    'exploitation': (
                        '1. Use dcmtk tools to attempt unauthorized SOP Class access\n'
                        '2. Inject fake worklist items via MWL SOP Class\n'
                        '3. Manipulate storage commitment statuses\n'
                        '4. Abuse privileged SOP Classes to hide malicious activities'
                    )
                })

            if self.check_dicom_web_auth_bypass(host):
                vulns.append({
                    'type': 'DICOM Web Auth Bypass',
                    'severity': 'High',
                    'description': (
                        'DICOM Web services (WADO, QIDO, STOW) allow unauthorized access through authentication '
                        'bypass techniques. Attackers can access or modify patient studies through the REST API '
                        'without proper credentials.'
                    ),
                    'solution': (
                        '1. Implement proper authentication for all DICOM Web services\n'
                        '2. Enable OAuth2 or JWT token validation\n'
                        '3. Implement rate limiting and API gateway protections\n'
                        '4. Regularly audit DICOM Web access logs\n'
                        '5. Disable unused DICOM Web services'
                    ),
                    'exploitation': (
                        '1. Access DICOM Web endpoints directly without authentication\n'
                        '2. Manipulate URL parameters to bypass checks\n'
                        '3. Use API fuzzing to find unprotected endpoints\n'
                        '4. Exploit insecure direct object references'
                    )
                })

            if self.check_mwl_spoofing(host):
                vulns.append({
                    'type': 'Modality Worklist Spoofing',
                    'severity': 'Medium',
                    'description': (
                        'Modality Worklist service is vulnerable to spoofing, allowing attackers to inject malicious '
                        'worklist entries. This could lead to incorrect procedures being performed, patient '
                        'misidentification, or malicious DICOM tags being inserted into images.'
                    ),
                    'solution': (
                        '1. Implement MWL entry validation and sanitization\n'
                        '2. Use digital signatures for worklist items\n'
                        '3. Restrict MWL modifications to authorized systems only\n'
                        '4. Implement modality-specific worklist filtering\n'
                        '5. Monitor for unusual worklist patterns'
                    ),
                    'exploitation': (
                        '1. Inject fake patient data into worklist\n'
                        '2. Manipulate procedure descriptions\n'
                        '3. Insert malicious DICOM tags via worklist\n'
                        '4. Cause procedure delays by overloading worklist'
                    )
                })
        
        except Exception as e:
            self.update_signal.emit("Error", f"Advanced DICOM check failed: {str(e)}")
        
        return vulns

    def check_tls_configurations(self, host):
        """Check for TLS/SSL misconfigurations"""
        vulns = []
        
        try:
            context = ssl.create_default_context()
            context.set_ciphers('DEFAULT:@SECLEVEL=1')
            
            for port in [2762, 443, 8443]:
                try:
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            
                            if not cert:
                                vulns.append({
                                    'type': 'Invalid Certificate',
                                    'severity': 'High',
                                    'description': (
                                        f'No valid certificate presented on port {port}. This allows man-in-the-middle '
                                        'attacks and makes the system vulnerable to impersonation. DICOM-TLS requires '
                                        'proper certificates for mutual authentication.'
                                    ),
                                    'solution': (
                                        '1. Install a valid SSL certificate from a trusted CA\n'
                                        '2. For DICOM-TLS, implement proper PKI with client certificates\n'
                                        '3. Configure certificate revocation checking\n'
                                        '4. Implement certificate pinning\n'
                                        '5. Regularly rotate certificates'
                                    ),
                                    'exploitation': (
                                        '1. Perform man-in-the-middle attacks\n'
                                        '2. Use self-signed certificates to impersonate server\n'
                                        '3. Decrypt traffic due to lack of proper certificate validation\n'
                                        '4. Exploit trust relationships between systems'
                                    )
                                })

                            if cipher[0] in ['DES-CBC3-SHA', 'RC4-SHA', 'RC4-MD5']:
                                vulns.append({
                                    'type': 'Weak Cipher',
                                    'severity': 'High',
                                    'description': (
                                        f'Weak cipher {cipher[0]} in use on port {port}. These ciphers are considered '
                                        'cryptographically broken and can be easily decrypted, exposing sensitive '
                                        'patient data and authentication credentials.'
                                    ),
                                    'solution': (
                                        '1. Disable weak ciphers in server configuration\n'
                                        '2. Enforce TLSv1.2+ with strong cipher suites\n'
                                        '3. Use AES-GCM or ChaCha20-Poly1305 ciphers\n'
                                        '4. Regularly scan for cipher suite vulnerabilities\n'
                                        '5. Implement perfect forward secrecy'
                                    ),
                                    'exploitation': (
                                        '1. Use tools like SSLScan or TestSSL to identify weak ciphers\n'
                                        '2. Perform cryptographic attacks against weak ciphers\n'
                                        '3. Decrypt intercepted traffic\n'
                                        '4. Exploit session hijacking vulnerabilities'
                                    )
                                })
                            
                            if 'TLSv1' in cipher[1] or 'SSLv3' in cipher[1]:
                                vulns.append({
                                    'type': 'Insecure Protocol',
                                    'severity': 'High',
                                    'description': (
                                        f'Insecure protocol {cipher[1]} in use on port {port}. These protocols contain '
                                        'known vulnerabilities (POODLE, BEAST) that allow decryption of sensitive data.'
                                    ),
                                    'solution': (
                                        '1. Disable SSLv3 and TLSv1.0 immediately\n'
                                        '2. Enforce TLSv1.2 or higher\n'
                                        '3. Configure protocol version fallback protection\n'
                                        '4. Update all cryptographic libraries\n'
                                        '5. Test compatibility with all connected systems'
                                    ),
                                    'exploitation': (
                                        '1. Use POODLE or BEAST attacks against SSLv3/TLSv1.0\n'
                                        '2. Decrypt intercepted medical data\n'
                                        '3. Exploit protocol weaknesses to inject malicious data\n'
                                        '4. Perform downgrade attacks'
                                    )
                                })
                
                except (socket.timeout, ConnectionRefusedError):
                    continue
                except ssl.SSLError as e:
                    vulns.append({
                        'type': 'TLS Error',
                        'severity': 'Medium',
                        'description':f'TLS negotiation error detected on port {port}: {str(e)}. This indicates potential '
                        'misconfiguration in the TLS implementation or certificate setup. Such errors can expose '
                        'information about the server configuration and may indicate partial deployment of security '
                        'controls that fail to properly protect medical imaging data and PHI in transit. TLS errors '
                        'often indicate incompatible security settings between clients and servers.',
                        'solution': 'Check TLS configuration and certificate',
                        'exploitation': 'Error conditions may reveal system information useful for attacks'
                    })
        
        except Exception as e:
            self.update_signal.emit("Error", f"TLS check failed: {str(e)}")
        
        return vulns

    def check_compliance(self, host):
        """Check for HIPAA/GDPR compliance issues"""
        vulns = []
        
        try:
            phi_found = self.check_phi_in_dicom(host)
            if phi_found:
                vulns.append({
                    'type': 'PHI Exposure',
                    'severity': 'High',
                    'description': (
                        'Protected Health Information (PHI) found in DICOM headers without proper de-identification. '
                        'This includes patient names, IDs, birth dates, and other identifiers in DICOM metadata. '
                        'This violates HIPAA Safe Harbor and GDPR requirements for data minimization.'
                    ),
                    'solution': (
                        '1. Implement proper DICOM de-identification procedures\n'
                        '2. Use automated tools to scrub PHI from DICOM headers\n'
                        '3. Create separate de-identified copies for research/sharing\n'
                        '4. Implement DICOM tag filtering for external transfers\n'
                        '5. Regularly audit DICOM files for PHI leakage'
                    ),
                    'exploitation': (
                        '1. Extract PHI from DICOM headers using tools like dcmdump\n'
                        '2. Correlate patient data across multiple studies\n'
                        '3. Use PHI for social engineering or identity theft\n'
                        '4. Combine with other data breaches for more complete profiles'
                    )
                })

            if not self.check_audit_logging(host):
                vulns.append({
                    'type': 'Missing Audit Logs',
                    'severity': 'Medium',
                    'description': (
                        'Insufficient audit logging of DICOM transactions. HIPAA requires logging of all access to '
                        'PHI, including who accessed what data and when. Without proper logs, security incidents '
                        'cannot be properly investigated.'
                    ),
                    'solution': (
                        '1. Implement comprehensive DICOM audit logging\n'
                        '2. Log all C-FIND, C-GET, C-MOVE, and C-STORE operations\n'
                        '3. Centralize logs in a SIEM system\n'
                        '4. Implement log integrity protections\n'
                        '5. Regularly review audit logs for suspicious activity'
                    ),
                    'exploitation': (
                        '1. Access patient data without leaving traces\n'
                        '2. Modify or delete studies without detection\n'
                        '3. Perform data exfiltration stealthily\n'
                        '4. Maintain persistence without triggering alerts'
                    )
                })
            
            if not self.check_data_retention(host):
                vulns.append({
                    'type': 'No Data Retention Policy',
                    'severity': 'Medium',
                    'description': (
                        'No clear data retention policy implemented. HIPAA requires policies for maintaining and '
                        'destroying PHI. Without retention rules, systems accumulate unnecessary patient data, '
                        'increasing breach potential and storage costs.'
                    ),
                    'solution': (
                        '1. Develop and implement a data retention policy\n'
                        '2. Automate deletion of expired studies\n'
                        '3. Implement secure deletion methods for PHI\n'
                        '4. Document retention periods for different data types\n'
                        '5. Regularly audit compliance with retention policy'
                    ),
                    'exploitation': (
                        '1. Find and exploit old, unpatched systems\n'
                        '2. Access historical patient data no longer needed\n'
                        '3. Recover deleted studies from unsecured backups\n'
                        '4. Use old data for social engineering attacks'
                    )
                })
        
        except Exception as e:
            self.update_signal.emit("Error", f"Compliance check failed: {str(e)}")
        return vulns

    def test_default_credentials(self, url):
        credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "admin", "password": "admin123"},
            {"username": "admin", "password": "root"},
            {"username": "admin", "password": "NHS"},
            {"username": "user", "password": "user"},
            {"username": "user", "password": "password"},
            {"username": "user", "password": "123456"},
            {"username": "guest", "password": "guest"},
            {"username": "test", "password": "test"},
            {"username": "root", "password": "root"}
        ]
        timeout = 30  
        
        try:
            try:
                print(f"[DEBUG] Testing if server is reachable at {url}")
                test_response = requests.get(url, timeout=timeout, verify=False)
                print(f"[DEBUG] Server is reachable, status code: {test_response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"[DEBUG] Server is not reachable: {str(e)}")
                self.update_signal.emit("Status", f"Server at {url} is not reachable for credential testing")
                return False

            login_url = url

            print(f"[DEBUG] Attempting login with test credentials...")
            self.update_signal.emit("Status", "Trying default credentials...")
            
            for cred in credentials:
                username = cred["username"]
                password = cred["password"]
                
                print(f"[DEBUG] Testing credential pair: {username}:{password}")
                self.update_signal.emit("Status", f"Trying {username}:{password}...")

                form_data = {
                    'username': username,
                    'password': password
                }
                
                try:
                    print(f"[DEBUG] Submitting login form to {login_url} with data: {form_data}")
                    login_response = requests.post(
                        login_url + '/login', 
                        data=form_data,
                        timeout=timeout,
                        allow_redirects=False,  
                        verify=False
                    )
                    
                    print(f"[DEBUG] Login response status: {login_response.status_code}")

                    if login_response.status_code == 302 and '/dashboard' in login_response.headers.get('Location', ''):
                        print(f"[DEBUG] LOGIN SUCCESSFUL with {username}:{password}")
                        self.update_signal.emit("Status", f"Default credentials found: {username}:{password}")
                        return True
                    else:
                        print(f"[DEBUG] Login attempt failed for {username}:{password}")
                except requests.RequestException as e:
                    print(f"[DEBUG] Error during login attempt: {str(e)}")
                    continue
            
            print("[DEBUG] All credential attempts failed")
            self.update_signal.emit("Status", "No default credentials worked")
            return False
        
        except Exception as e:
            print(f"[DEBUG] CRITICAL ERROR in credential testing: {str(e)}")
            self.update_signal.emit("Error", f"Error checking default credentials: {str(e)}")
            return False
    
    def check_directory_listing(self, url):
        try:
            response = requests.get(url + "/images/", verify=False)
            return "Index of /images/" in response.text
        except:
            return False
    
    def check_outdated_software(self, url):
        try:
            response = requests.get(url, verify=False)
            server = response.headers.get('Server', '')

            if "Apache/2.2" in server:
                return True, server
            if "PHP/5.6" in server:
                return True, server
            
            return False, server
        except:
            return False, "Unknown"
    
    def check_dicom_authentication(self, host, port):
        print(f"[DEBUG] Checking DICOM authentication on {host}:{port}")
        self.update_signal.emit("Status", f"Checking DICOM authentication on {host}:{port}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(120)
            
            print(f"[DEBUG] Attempting to connect to {host}:{port}")
            result = sock.connect_ex((host, port))

            if result != 0:
                print(f"[DEBUG] Port {port} is not open")
                self.update_signal.emit("Status", f"Port {port} is not open")
                
                return True 
            print(f"[DEBUG] Successfully connected to {host}:{port}")
            
            pdu_type = b'\x01'
            reserved = b'\x00'
            pdu_length = b'\x00\x00\x00\x9c'  
            
            app_context = b'\x10\x00\x00\x15\x31\x2e\x32\x2e\x38\x34\x30\x2e\x31\x30\x30\x30\x38\x2e\x33\x2e\x31\x2e\x31\x2e\x31'

            calling_ae = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            
            called_ae = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

            dicom_packet = pdu_type + reserved + pdu_length + app_context + calling_ae + called_ae

            print(f"[DEBUG] Sending anonymous DICOM association request")
            sock.send(dicom_packet)

            print(f"[DEBUG] Waiting for DICOM response")
            response = sock.recv(1024)

            sock.close()

            if len(response) > 0:
                if response[0] == 0x02:
                    print(f"[DEBUG] DICOM server accepted anonymous connection")
                    self.update_signal.emit("Status", f"DICOM server allows anonymous access")
                    return False
                else:
                    print(f"[DEBUG] DICOM server rejected anonymous connection")
                    self.update_signal.emit("Status", f"DICOM server requires authentication")
                    return True 
            else:
                print(f"[DEBUG] No response from DICOM server")
                self.update_signal.emit("Status", f"No response from DICOM server")
                return True 
        
        except Exception as e:
            print(f"[DEBUG] Error checking DICOM authentication: {str(e)}")
            self.update_signal.emit("Error", f"Error checking DICOM authentication: {str(e)}")
            return True 
    
    def check_cmove_vulnerability(self, host, port):
        print(f"[DEBUG] Checking C-MOVE vulnerability on {host}:{port}")
        self.update_signal.emit("Status", f"Checking C-MOVE vulnerability on {host}:{port}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            print(f"[DEBUG] Verifying port {port} is open")
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result != 0:
                print(f"[DEBUG] Port {port} is not open")
                return False
            
            print(f"[DEBUG] Port {port} is open, proceeding with C-MOVE test")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            print(f"[DEBUG] Sending simple data probe to server")
            sock.send(b'\x01\x00\x00\x00\x00\x10TESTDICOM')
            
            try:
                test_response = sock.recv(1024)
                print(f"[DEBUG] Server responded to probe with {len(test_response)} bytes")
                print(f"[DEBUG] First few bytes: {test_response[:10]}")
            except socket.error as e:
                print(f"[DEBUG] Server closed connection during probe: {str(e)}")
            
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            print(f"[DEBUG] Sending minimal DICOM-like request")
            sock.send(b'\x01\x00\x00\x00\x00\x10\x00\x01\x00\x00')
            
            try:
                response = sock.recv(1024)
                print(f"[DEBUG] Received {len(response)} bytes in response")
                
                if len(response) > 0:
                    print(f"[DEBUG] Server responded to DICOM-like request")
                    if response[0] == 0x02: 
                        print(f"[DEBUG] Response might indicate DICOM protocol")
                    return True
            except socket.error as e:
                print(f"[DEBUG] Connection error during request: {str(e)}")
            
            sock.close()
            return False
            
        except Exception as e:
            print(f"[DEBUG] Error during C-MOVE vulnerability check: {str(e)}")
            self.update_signal.emit("Error", f"Error checking C-MOVE vulnerability: {str(e)}")
            return False
        finally:
            try:
                sock.close()
            except:
                pass
        
    def check_sop_class_bypass(self, host):
        print(f"[DEBUG] Checking SOP Class permission bypass on {host}")
        self.update_signal.emit("Status", f"Checking SOP Class permission bypass on {host}")

        dicom_ports = [104, 11112, 2761, 2762, 2575]

        restricted_sop_classes = [
            "1.2.840.10008.5.1.4.1.2.1.1",  
            "1.2.840.10008.5.1.1.2",       
        ]
        
        try:
            dicom_port = None
            
            for port in dicom_ports:
                print(f"[DEBUG] Checking for DICOM service on port {port}")
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    print(f"[DEBUG] Found open port at {port}, testing for DICOM service")
                    dicom_port = port

                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(3)
                        sock.connect((host, port))

                        sock.send(b'\x00\x00\x00\x00\x00\x00\x00\x00')
                        
                        try:
                            time.sleep(1)

                            sock.setblocking(False)
                            try:
                                data = sock.recv(1024)
                                is_connected = True
                            except BlockingIOError:
                                is_connected = True 
                            except ConnectionError:
                                is_connected = False
                            sock.setblocking(True)
                            
                            if is_connected:
                                print(f"[DEBUG] Port {port} might be a DICOM service")
                                break  
                        except socket.error:
                            pass
                        
                        sock.close()
                    except Exception as e:
                        print(f"[DEBUG] Error during initial DICOM test: {str(e)}")
            
            if dicom_port is None:
                print(f"[DEBUG] No likely DICOM ports found open on {host}")
                return False
            
            for sop_class in restricted_sop_classes:
                print(f"[DEBUG] Testing SOP Class vulnerability with: {sop_class}")
                
                sop_class_bytes = sop_class.encode('ascii')
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((host, dicom_port))

                    test_packet = b'\x01\x00' + len(sop_class_bytes).to_bytes(2, byteorder='big') + sop_class_bytes
                    sock.send(test_packet)
                    
                    try:
                        response = sock.recv(1024)

                        if len(response) > 0:
                            print(f"[DEBUG] Got response when testing SOP Class {sop_class}, potential vulnerability")
                            self.update_signal.emit("Status", f"SOP Class permission bypass vulnerability may exist on {host}:{dicom_port}")
                            sock.close()
                            return True
                    except socket.timeout:
                        print(f"[DEBUG] Timeout waiting for response for SOP Class {sop_class}")
                    except ConnectionError as ce:
                        print(f"[DEBUG] Connection error for SOP Class {sop_class}: {str(ce)}")
                    
                    sock.close()
                except Exception as e:
                    print(f"[DEBUG] Error testing SOP Class {sop_class}: {str(e)}")
                    try:
                        sock.close()
                    except:
                        pass
            
            print(f"[DEBUG] No SOP Class permission bypass vulnerability detected")
            return False
        
        except Exception as e:
            print(f"[DEBUG] Error checking SOP Class bypass: {str(e)}")
            self.update_signal.emit("Error", f"Error checking SOP Class bypass: {str(e)}")
            return False
    
    def test_sop_class_access(self, host, port, sop_class_uid):
        try:
            print(f"[DEBUG] Testing access to SOP Class: {sop_class_uid} on {host}:{port}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            try:
                sock.connect((host, port))
            except ConnectionRefusedError:
                print(f"[DEBUG] Connection refused to {host}:{port}")
                return False
            except Exception as e:
                print(f"[DEBUG] Connection error: {str(e)}")
                return False
                
            print(f"[DEBUG] Connected to {host}:{port}")

            test = True
            
            if test:
                try:
                    simple_packet = b'\x01\x00' + len(sop_class_uid).to_bytes(2, byteorder='big') + sop_class_uid.encode('ascii')
                    
                    print(f"[DEBUG] Sending test packet")
                    sock.send(simple_packet)
                    
                    try:
                        response = sock.recv(1024)
                        print(f"[DEBUG] Received response of {len(response)} bytes")

                        if len(response) > 0:
                            print(f"[DEBUG] Server responded to SOP Class UID: {sop_class_uid}")
                            sock.close()
                            return True
                            
                    except socket.timeout:
                        print(f"[DEBUG] Timeout waiting for response")
                    except ConnectionResetError:
                        print(f"[DEBUG] Connection reset by server")
                    except Exception as e:
                        print(f"[DEBUG] Error receiving response: {str(e)}")
                        
                    sock.close()
                    return False
                    
                except Exception as e:
                    print(f"[DEBUG] Error in simplified test: {str(e)}")
                    try:
                        sock.close()
                    except:
                        pass
                    return False
                
        except Exception as e:
            print(f"[DEBUG] Error testing SOP Class access: {str(e)}")
            try:
                sock.close()
            except:
                pass
            return False
    
    def check_dicom_web_auth_bypass(self, host):
        print(f"[DEBUG] Checking DICOM Web authentication bypass on {host}")
        self.update_signal.emit("Status", f"Checking DICOM Web authentication bypass on {host}")

        web_ports = [80, 443, 8080, 8081, 8443, 2575]

        dicom_web_endpoints = [
            "/dicom-web/",
            "/wado",
            "/wado-rs",
            "/qido-rs",
            "/stow-rs",
            "/pacs/wado",
            "/pacs/dicom-web",
            "/orthanc/wado",
            "/api/dicom-web",
            "/dcm4chee-arc/aets",
            "/dicomweb",
            "/dcm4chee-arc/wado"
        ]

        study_uids = [
            "1.2.840.113619.2.176.3596.3364818.7819.1259708454.108",
            "1.2.3.4.5.6.7.8.9"
        ]
        
        try:
            for port in web_ports:
                protocol = "https" if port in [443, 8443] else "http"
                base_url = f"{protocol}://{host}:{port}"
                
                try:
                    print(f"[DEBUG] Testing connection to {base_url}")
                    response = requests.get(base_url, timeout=5, verify=False)
                    print(f"[DEBUG] Connection successful to {base_url}, status code: {response.status_code}")

                    for endpoint in dicom_web_endpoints:
                        endpoint_url = f"{base_url}{endpoint}"
                        try:
                            print(f"[DEBUG] Testing DICOM Web endpoint: {endpoint_url}")
                            endpoint_response = requests.get(endpoint_url, timeout=5, verify=False)

                            if endpoint_response.status_code == 200:
                                print(f"[DEBUG] Found potential DICOM Web endpoint: {endpoint_url}")
   
                                content_type = endpoint_response.headers.get('Content-Type', '')
                                if any(ct in content_type.lower() for ct in ['json', 'xml', 'dicom']):
                                    print(f"[DEBUG] DICOM-compatible content type found: {content_type}")

                                    for study_uid in study_uids:
                                        study_url = f"{endpoint_url}/studies/{study_uid}"
                                        print(f"[DEBUG] Attempting to access study without auth: {study_url}")
                                        
                                        study_response = requests.get(study_url, timeout=5, verify=False)

                                        if study_response.status_code in [200, 404]:
                                            print(f"[DEBUG] Successfully accessed DICOM Web API without authentication (status: {study_response.status_code})")
                                            self.update_signal.emit("Status", f"DICOM Web auth bypass vulnerability found on {endpoint_url}")
                                            return True
                                        elif study_response.status_code in [401, 403]:
                                            print(f"[DEBUG] Authentication required (status: {study_response.status_code})")
                        
                        except requests.RequestException as e:
                            print(f"[DEBUG] Error checking endpoint {endpoint_url}: {str(e)}")
                            continue
                
                except requests.RequestException as e:
                    print(f"[DEBUG] Cannot connect to {base_url}: {str(e)}")
                    continue

            for port in web_ports:
                protocol = "https" if port in [443, 8443] else "http"
                base_url = f"{protocol}://{host}:{port}"
                
                bypass_paths = [
                    "/wado?requestType=WADO&contentType=image/jpeg",
                    "/wado-rs/studies/{study_uid}/metadata",
                    "/dicom-web/studies?limit=5",
                    "/pacs/wado?requestType=WADO&studyUID=1.2.3.4",
                    "/orthanc/instances",
                    "/dcm4chee-arc/aets/PACS/rs/studies"
                ]
                
                for path in bypass_paths:
                    if "{study_uid}" in path:
                        path = path.replace("{study_uid}", study_uids[0])
                        
                    try:
                        bypass_url = f"{base_url}{path}"
                        print(f"[DEBUG] Testing potential auth bypass path: {bypass_url}")
                        
                        response = requests.get(bypass_url, timeout=5, verify=False)
                        
                        if response.status_code == 200:
                            if any(indicator in response.text.lower() for indicator in 
                                ['dicom', 'patient', 'study', 'series', 'image', 'modality']):
                                print(f"[DEBUG] Potential DICOM Web auth bypass found at {bypass_url}")
                                self.update_signal.emit("Status", f"DICOM Web auth bypass vulnerability found on {bypass_url}")
                                return True
                    except requests.RequestException:
                        continue
            
            print(f"[DEBUG] No DICOM Web authentication bypass vulnerabilities found")
            return False
            
        except Exception as e:
            print(f"[DEBUG] Error checking DICOM Web auth bypass: {str(e)}")
            self.update_signal.emit("Error", f"Error checking DICOM Web auth bypass: {str(e)}")
            return False
    
    def check_mwl_spoofing(self, host):
        print(f"[DEBUG] Checking Modality Worklist spoofing vulnerability on {host}")
        self.update_signal.emit("Status", f"Checking MWL spoofing vulnerability on {host}")

        dicom_ports = [104, 11112, 2575, 2761, 2762]
        
        try:
            mwl_port = None
            
            for port in dicom_ports:
                print(f"[DEBUG] Checking if port {port} is open for MWL testing")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    print(f"[DEBUG] Found open port {port} for MWL testing")
                    mwl_port = port
                    break
            
            if not mwl_port:
                print(f"[DEBUG] No open DICOM ports found for MWL testing")
                return False

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, mwl_port))

            try:
                print(f"[DEBUG] Sending simple test packet to {host}:{mwl_port}")
                sock.send(b'\x00\x00\x00\x00')
                
                try:
                    response = sock.recv(1024)
                    print(f"[DEBUG] Server responded to simple test")
                except socket.timeout:
                    print(f"[DEBUG] No response to simple test (timeout)")
                except ConnectionResetError:
                    print(f"[DEBUG] Connection reset during simple test")
                    
            except Exception as e:
                print(f"[DEBUG] Error in simple test: {str(e)}")
            
            sock.close()
 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, mwl_port))

            dicom_test = b'\x01\x00\x00\x00\x00\x08DICOM'
            
            try:
                print(f"[DEBUG] Sending minimal DICOM-like test")
                sock.send(dicom_test)
                
                try:
                    response = sock.recv(1024)
                    print(f"[DEBUG] Received response to DICOM test: {len(response)} bytes")

                    if len(response) > 0:
                        if response[0] in [0x02, 0x03, 0x04, 0x05, 0x06]:  
                            print(f"[DEBUG] Response appears to be a DICOM PDU")
                            
                            self.update_signal.emit("Status", f"Potential MWL service found on {host}:{mwl_port} - consider further testing")

                            return True
                except socket.timeout:
                    print(f"[DEBUG] No response to DICOM test (timeout)")
                except ConnectionResetError:
                    print(f"[DEBUG] Connection reset during DICOM test - server rejected packet")
                    
            except Exception as e:
                print(f"[DEBUG] Error in DICOM test: {str(e)}")
            
            sock.close()

            return False
            
        except Exception as e:
            print(f"[DEBUG] Error during MWL spoofing test: {str(e)}")
            self.update_signal.emit("Error", f"Error checking MWL spoofing: {str(e)}")
            return False
    
    def check_phi_in_dicom(self, host):
        print(f"[DEBUG] Checking for PHI exposure in DICOM data on {host}")
        self.update_signal.emit("Status", f"Checking for PHI exposure on {host}")

        dicom_ports = [104, 11112, 2575, 2761, 2762]
        
        try:
            dicom_port = None
            
            for port in dicom_ports:
                print(f"[DEBUG] Checking if port {port} is open")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    print(f"[DEBUG] Found open port {port}")
                    dicom_port = port
                    break
            
            if not dicom_port:
                print(f"[DEBUG] No open DICOM ports found")
                return False

            vulnerable = False
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, dicom_port))

            assoc_packet = b'\x01\x00\x00\x00\x00\x10ECHOSCU'
            
            print(f"[DEBUG] Sending simplified DICOM association request to {host}:{dicom_port}")
            sock.send(assoc_packet)
            
            try:
                response = sock.recv(1024)
                print(f"[DEBUG] Received response of {len(response)} bytes")

                if len(response) > 0:
                    print(f"[DEBUG] DICOM server responds to unauthenticated association requests")

                    test_query = b'\x02\x00\x00\x00\x00\x20PatientName\x00PatientID\x00StudyDate'
                    sock.close()  

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((host, dicom_port))
                    
                    try:
                        print(f"[DEBUG] Sending test query with PHI-related fields")
                        sock.send(test_query)
                        
                        try:
                            query_response = sock.recv(1024)
                            print(f"[DEBUG] Received query response of {len(query_response)} bytes")
        
                            if len(query_response) > 0 and not b'error' in query_response.lower():
                                vulnerable = True
                        except (socket.timeout, ConnectionResetError):
                            print(f"[DEBUG] No response or connection reset for query test")
                    except Exception as e:
                        print(f"[DEBUG] Error sending query test: {str(e)}")

                    if vulnerable:
                        print(f"[DEBUG] Server behavior suggests potential PHI exposure risks")
                        self.update_signal.emit("Status", f"Potential PHI exposure risk detected on {host}:{dicom_port}")
                        return True
                    else:

                        print(f"[DEBUG] DICOM server accepts connections but shows some security controls")
                        self.update_signal.emit("Status", f"DICOM server found on {host}:{dicom_port} - Consider a manual PHI exposure review")

                        return True
            except socket.timeout:
                print(f"[DEBUG] Timeout waiting for DICOM response")
            except ConnectionResetError:
                print(f"[DEBUG] Connection reset after association request")
            
            sock.close()
            return False
            
        except Exception as e:
            print(f"[DEBUG] Error checking for PHI in DICOM: {str(e)}")
            self.update_signal.emit("Error", f"Error checking for PHI in DICOM: {str(e)}")
            return False
    
    def check_audit_logging(self, host):
        return False
    
    def check_data_retention(self, host):
        return False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PACS/DICOM Security Assessment Tool")
        self.setGeometry(100, 100, 1200, 800)

        self.dark_mode = True
        self.set_dark_theme()

        self.sidebar = None
        self.tabs = None
        self.progress_bar = None
        self.start_scan_btn = None
        self.stop_scan_btn = None
        self.scan_history_list = None
        self.vuln_table = None
        self.vuln_details = None
        self.recent_scans_table = None
        self.vuln_filter_severity = None
        self.vuln_filter_type = None
        self.vuln_filter_host = None
        self.hosts_count = None
        self.vulns_count = None
        self.crit_count = None
        self.high_count = None
        self.host_input = None
        self.port_buttons = []
        self.selected_ports = None
        self.port_start = None
        self.port_end = None
        self.profile_combo = None
        self.report_type_combo = None
        self.anonymize_check = None
        self.include_remediation_check = None
        self.report_preview = None

        self.last_scan_info = QLabel("No scan performed yet")

        self.init_ui()

        self.scan_history = []
        self.current_scan = None
        
        self.statusBar().showMessage("Ready")

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        self.create_sidebar()
        main_layout.addWidget(self.sidebar, 1)

        content_area = QVBoxLayout()
        main_layout.addLayout(content_area, 4)

        self.create_toolbar()

        self.tabs = QTabWidget()
        content_area.addWidget(self.tabs)

        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_reporting_tab()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setVisible(False)
        content_area.addWidget(self.progress_bar)

        content_area.addWidget(self.last_scan_info)

        scan_controls = QHBoxLayout()
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.clicked.connect(self.start_scan)
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        scan_controls.addWidget(self.start_scan_btn)
        scan_controls.addWidget(self.stop_scan_btn)
        content_area.addLayout(scan_controls)

    def show_dashboard(self):
        if self.tabs:
            self.tabs.setCurrentIndex(0)

    def show_scan_config(self):
        if self.tabs:
            self.tabs.setCurrentIndex(1)

    def show_reporting(self):
        if self.tabs:
            self.tabs.setCurrentIndex(2)
            
    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        self.create_sidebar()
        main_layout.addWidget(self.sidebar, 1)

        content_area = QVBoxLayout()
        main_layout.addLayout(content_area, 4)

        self.create_toolbar()

        self.tabs = QTabWidget()
        content_area.addWidget(self.tabs)

        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_reporting_tab()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setVisible(False)
        content_area.addWidget(self.progress_bar)
 
        scan_controls = QHBoxLayout()
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.clicked.connect(self.start_scan)
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        scan_controls.addWidget(self.start_scan_btn)
        scan_controls.addWidget(self.stop_scan_btn)
        content_area.addLayout(scan_controls)

    def create_toolbar(self):
        toolbar = self.addToolBar("Main Toolbar")

        new_action = QAction(QIcon.fromTheme("document-new"), "New Scan", self)
        new_action.triggered.connect(self.new_scan)
        toolbar.addAction(new_action)
    
        toolbar.addSeparator()

    def create_sidebar(self):
        self.sidebar = QDockWidget("Navigation", self)
        self.sidebar.setFeatures(QDockWidget.DockWidgetVerticalTitleBar)
        self.sidebar.setAllowedAreas(Qt.LeftDockWidgetArea | Qt.RightDockWidgetArea)
        
        sidebar_widget = QWidget()
        sidebar_layout = QVBoxLayout(sidebar_widget)
   
        nav_buttons = [
            ("Dashboard", "view-dashboard", self.show_dashboard),
            ("Scan Configuration", "configure", self.show_scan_config),
            ("Reporting", "document-report", self.show_reporting),
        ]
        
        for text, icon, callback in nav_buttons:
            btn = QPushButton(text)
            btn.setIcon(QIcon.fromTheme(icon))
            btn.clicked.connect(callback)
            sidebar_layout.addWidget(btn)
        
        sidebar_layout.addStretch()

        history_label = QLabel("Scan History")
        sidebar_layout.addWidget(history_label)
        
        self.scan_history_list = QListWidget()
        self.scan_history_list.itemClicked.connect(self.load_scan_from_history)
        sidebar_layout.addWidget(self.scan_history_list)
        
        self.sidebar.setWidget(sidebar_widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.sidebar)

    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)

        stats_group = QGroupBox("Summary Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.hosts_count = QLabel("0")
        self.hosts_count.setAlignment(Qt.AlignCenter)
        self.hosts_count.setStyleSheet("font-size: 24px; font-weight: bold;")
        stats_layout.addWidget(QLabel("Hosts Scanned:"))
        stats_layout.addWidget(self.hosts_count)
        
        self.vulns_count = QLabel("0")
        self.vulns_count.setAlignment(Qt.AlignCenter)
        self.vulns_count.setStyleSheet("font-size: 24px; font-weight: bold;")
        stats_layout.addWidget(QLabel("Vulnerabilities Found:"))
        stats_layout.addWidget(self.vulns_count)
        
        self.crit_count = QLabel("0")
        self.crit_count.setAlignment(Qt.AlignCenter)
        self.crit_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #ff0000;")
        stats_layout.addWidget(QLabel("Critical:"))
        stats_layout.addWidget(self.crit_count)
        
        self.high_count = QLabel("0")
        self.high_count.setAlignment(Qt.AlignCenter)
        self.high_count.setStyleSheet("font-size: 24px; font-weight: bold; color: #ff6600;")
        stats_layout.addWidget(QLabel("High:"))
        stats_layout.addWidget(self.high_count)
        
        layout.addWidget(stats_group)

        vuln_group = QGroupBox("Vulnerabilities")
        vuln_layout = QVBoxLayout(vuln_group)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by:"))
        
        self.vuln_filter_severity = QComboBox()
        self.vuln_filter_severity.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.vuln_filter_severity.currentTextChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.vuln_filter_severity)
        
        self.vuln_filter_type = QComboBox()
        self.vuln_filter_type.addItems(["All Types", "Authentication", "Configuration", "Encryption", "Compliance"])
        self.vuln_filter_type.currentTextChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.vuln_filter_type)
        
        self.vuln_filter_host = QComboBox()
        self.vuln_filter_host.addItems(["All Hosts"])
        self.vuln_filter_host.currentTextChanged.connect(self.filter_vulnerabilities)
        filter_layout.addWidget(self.vuln_filter_host)
        
        filter_layout.addStretch()
        vuln_layout.addLayout(filter_layout)

        self.vuln_table = QTreeWidget()
        self.vuln_table.setHeaderLabels(["Severity", "Host", "Port", "Type", "Description"])
        self.vuln_table.setSortingEnabled(True)
        self.vuln_table.sortByColumn(0, Qt.DescendingOrder)
        self.vuln_table.itemDoubleClicked.connect(self.show_vuln_details)
        vuln_layout.addWidget(self.vuln_table)

        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setMaximumHeight(150)
        vuln_layout.addWidget(self.vuln_details)
        
        layout.addWidget(vuln_group)

        recent_group = QGroupBox("Recent Scans")
        recent_layout = QVBoxLayout(recent_group)
        
        self.recent_scans_table = QTreeWidget()
        self.recent_scans_table.setHeaderLabels(["Date", "Target", "Type", "Vulnerabilities"])
        recent_layout.addWidget(self.recent_scans_table)
        
        layout.addWidget(recent_group)
        
        self.tabs.addTab(dashboard_tab, QIcon.fromTheme("view-dashboard"), "Dashboard")

    def filter_vulnerabilities(self):
        if not self.scan_history:
            return
            
        severity_filter = self.vuln_filter_severity.currentText()
        type_filter = self.vuln_filter_type.currentText()
        host_filter = self.vuln_filter_host.currentText()
        
        latest_scan = self.scan_history[-1]
        
        self.vuln_table.clear()

        for result in latest_scan['results']:
            if host_filter != "All Hosts" and result['host'] != host_filter:
                continue
                
            for vuln in result['vulnerabilities']:
                if severity_filter != "All Severities" and vuln['severity'] != severity_filter:
                    continue
                if type_filter != "All Types" and type_filter not in vuln['type']:
                    continue
                    
                item = QTreeWidgetItem([
                    vuln['severity'],
                    result['host'],
                    str(result['port']),
                    vuln['type'],
                    vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
                ])
                self.color_vuln_item(item, vuln['severity'])
                self.vuln_table.addTopLevelItem(item)
        
        for vuln in latest_scan['vulnerabilities']:
            if severity_filter != "All Severities" and vuln['severity'] != severity_filter:
                continue
            if type_filter != "All Types" and type_filter not in vuln['type']:
                continue
            if host_filter != "All Hosts" and latest_scan['target'] != host_filter:
                continue
                
            item = QTreeWidgetItem([
                vuln['severity'],
                latest_scan['target'],
                "N/A",
                vuln['type'],
                vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
            ])
            self.color_vuln_item(item, vuln['severity'])
            self.vuln_table.addTopLevelItem(item)

    def create_scan_tab(self):
        scan_tab = QWidget()
        layout = QVBoxLayout(scan_tab)

        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)

        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("Target Host:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("IP address or hostname")
        host_layout.addWidget(self.host_input)
        target_layout.addLayout(host_layout)
        
        port_group = QGroupBox("Port Selection")
        port_layout = QVBoxLayout(port_group)

        self.quick_ports_layout = QHBoxLayout()
        quick_ports_label = QLabel("Common DICOM Ports:")
        self.quick_ports_layout.addWidget(quick_ports_label)
        
        self.port_buttons = []
        for port in DICOM_PORTS:
            btn = QPushButton(str(port))
            btn.setCheckable(True)
            btn.setChecked(True)
            btn.clicked.connect(self.update_port_selection)
            self.quick_ports_layout.addWidget(btn)
            self.port_buttons.append(btn)
        
        port_layout.addLayout(self.quick_ports_layout)

        port_range_layout = QHBoxLayout()
        port_range_layout.addWidget(QLabel("Custom Port Range:"))
        
        self.port_start = QSpinBox()
        self.port_start.setRange(1, 65535)
        self.port_start.setValue(1)
        port_range_layout.addWidget(self.port_start)
        
        port_range_layout.addWidget(QLabel("to"))
        
        self.port_end = QSpinBox()
        self.port_end.setRange(1, 65535)
        self.port_end.setValue(65535)
        port_range_layout.addWidget(self.port_end)
        
        add_range_btn = QPushButton("Add Range")
        add_range_btn.clicked.connect(self.add_port_range)
        port_range_layout.addWidget(add_range_btn)
        
        port_layout.addLayout(port_range_layout)

        self.selected_ports = QLineEdit()
        self.selected_ports.setReadOnly(False)
        self.selected_ports.setText(", ".join(map(str, DICOM_PORTS)))
        port_layout.addWidget(self.selected_ports)
        
        target_layout.addWidget(port_group)

        profile_group = QGroupBox("Scan Profile")
        profile_layout = QVBoxLayout(profile_group)
        
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["Quick Scan", "Deep Scan"])
        profile_layout.addWidget(self.profile_combo)
        
        profile_desc = QTextEdit()
        profile_desc.setReadOnly(True)
        profile_desc.setMaximumHeight(100)
        profile_desc.setHtml("""
        <ul>
        <li><b>Quick Scan</b>: Basic port scanning and service detection with minimal vulnerability checks</li>
        <li><b>Deep Scan</b>: Comprehensive security assessment including quick scan plus advanced DICOM tests, TLS/SSL checks, and compliance verification</li>
        </ul>
        """)
        profile_layout.addWidget(profile_desc)
                
        target_layout.addWidget(profile_group)
                
        layout.addWidget(target_group)
                
        self.tabs.addTab(scan_tab, QIcon.fromTheme("configure"), "Scan Configuration")

    def create_reporting_tab(self):
        report_tab = QWidget()
        layout = QVBoxLayout(report_tab)

        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Report Type:"))
        
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems(["Executive Summary", "Technical Report", "Compliance Report"])
        type_layout.addWidget(self.report_type_combo)
        
        layout.addLayout(type_layout)

        options_group = QGroupBox("Report Options")
        options_layout = QVBoxLayout(options_group)
        
        self.anonymize_check = QCheckBox("Anonymize Hostnames/IPs")
        self.anonymize_check.setChecked(True)
        options_layout.addWidget(self.anonymize_check)
        
        self.include_remediation_check = QCheckBox("Include Remediation Recommendations")
        self.include_remediation_check.setChecked(True)
        options_layout.addWidget(self.include_remediation_check)
        
        layout.addWidget(options_group)

        generate_layout = QHBoxLayout()
        
        self.generate_pdf_btn = QPushButton("Generate PDF")
        self.generate_pdf_btn.clicked.connect(lambda: self.generate_report("pdf"))
        generate_layout.addWidget(self.generate_pdf_btn)
        
        layout.addLayout(generate_layout)

        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        layout.addWidget(self.report_preview)
        
        self.tabs.addTab(report_tab, QIcon.fromTheme("document-report"), "Reporting")

    def set_dark_theme(self):
        palette = QPalette()

        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(35, 35, 35))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(255, 165, 0))  # Orange
        palette.setColor(QPalette.Highlight, QColor(255, 165, 0))
        palette.setColor(QPalette.HighlightedText, Qt.black)
  
        palette.setColor(QPalette.Disabled, QPalette.Text, QColor(150, 150, 150))
        palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(150, 150, 150))
        
        self.setPalette(palette)

        self.setStyleSheet("""
            QToolTip {
                color: #ffffff;
                background-color: #2a2a2a;
                border: 1px solid #ffa500;
            }
            
            QTabBar::tab {
                background: #353535;
                color: white;
                padding: 8px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            
            QTabBar::tab:selected {
                background: #ffa500;
                color: black;
            }
            
            QGroupBox {
                border: 1px solid #ffa500;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 15px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
                color: #ffa500;
            }
            
            QPushButton {
                background-color: #454545;
                color: white;
                border: 1px solid #666;
                padding: 5px;
                border-radius: 4px;
            }
            
            QPushButton:hover {
                background-color: #555;
                border: 1px solid #888;
            }
            
            QPushButton:pressed {
                background-color: #ffa500;
                color: black;
            }
            
            QComboBox, QLineEdit, QSpinBox, QTextEdit {
                background-color: #252525;
                color: white;
                border: 1px solid #666;
                padding: 3px;
            }
            
            QTreeView, QListView, QTableView {
                background-color: #252525;
                color: white;
                border: 1px solid #666;
                alternate-background-color: #353535;
            }
            
            QHeaderView::section {
                background-color: #454545;
                color: white;
                padding: 5px;
                border: 1px solid #666;
            }
            
            QProgressBar {
                border: 1px solid #444;
                border-radius: 3px;
                text-align: center;
            }
            
            QProgressBar::chunk {
                background-color: #ffa500;
                width: 10px;
            }
        """)

    def update_port_selection(self):
        ports = []
        for btn in self.port_buttons:
            if btn.isChecked():
                ports.append(btn.text())
        self.selected_ports.setText(", ".join(ports))

    def add_port_range(self):
        start = self.port_start.value()
        end = self.port_end.value()
        
        if start > end:
            QMessageBox.warning(self, "Invalid Range", "Start port must be less than or equal to end port")
            return
        
        current_ports = self.selected_ports.text()
        if current_ports:
            current_ports += ", "
        
        if start == end:
            current_ports += str(start)
        else:
            current_ports += f"{start}-{end}"
        
        self.selected_ports.setText(current_ports)

    def start_scan(self):
        target = self.host_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing Target", "Please enter a target host or IP address")
            return
        
        port_text = self.selected_ports.text()
        ports = []
        for part in port_text.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            elif part:
                ports.append(int(part))
        
        if not ports:
            QMessageBox.warning(self, "No Ports", "Please select at least one port to scan")
            return

        profile = self.profile_combo.currentText()

        self.current_scan = ScanWorker(target, ports, profile)
        self.current_scan.update_signal.connect(self.handle_scan_update)
        self.current_scan.progress_signal.connect(self.update_progress)
        self.current_scan.finished_signal.connect(self.scan_finished)

        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.current_scan.start()
        self.statusBar().showMessage(f"Scanning {target}...")

    def stop_scan(self):
        if self.current_scan:
            self.current_scan._is_running = False
            self.current_scan.terminate() 
            self.statusBar().showMessage("Scan stopped by user")
            self.stop_scan_btn.setEnabled(False)
            self.start_scan_btn.setEnabled(True)

    def scan_finished(self):
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        target = self.host_input.text().strip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        profile = self.profile_combo.currentText()
        
        self.scan_history.append({
            'timestamp': timestamp,
            'target': target,
            'profile': profile,
            'results': self.current_scan.results,
            'vulnerabilities': self.current_scan.vulnerabilities
        })

        self.last_scan_info.setText(f"Last scan: {target} at {timestamp}")
         
        self.update_scan_history()
        self.update_dashboard()
        self.update_vulnerabilities()
        
        self.statusBar().showMessage(f"Scan completed at {timestamp}")

    def handle_scan_update(self, update_type, message):
        if update_type == "Status":
            self.statusBar().showMessage(message)
        elif update_type == "Error":
            QMessageBox.warning(self, "Scan Error", message)
        elif update_type == "Result":
            pass

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def update_scan_history(self):
        self.scan_history_list.clear()
        for scan in reversed(self.scan_history):
            self.scan_history_list.addItem(f"{scan['timestamp']} - {scan['target']} ({scan['profile']})")

    def update_dashboard(self):
        if not self.scan_history:
            return
        
        latest_scan = self.scan_history[-1]

        host_count = len(set(r['host'] for r in latest_scan['results']))
        self.hosts_count.setText(str(host_count))
        
        vuln_count = sum(len(r['vulnerabilities']) for r in latest_scan['results']) + len(latest_scan['vulnerabilities'])
        self.vulns_count.setText(str(vuln_count))
        
        crit_count = sum(1 for r in latest_scan['results'] for v in r['vulnerabilities'] if v['severity'] == 'Critical') + \
                    sum(1 for v in latest_scan['vulnerabilities'] if v['severity'] == 'Critical')
        self.crit_count.setText(str(crit_count))
        
        high_count = sum(1 for r in latest_scan['results'] for v in r['vulnerabilities'] if v['severity'] == 'High') + \
                    sum(1 for v in latest_scan['vulnerabilities'] if v['severity'] == 'High')
        self.high_count.setText(str(high_count))

        self.recent_scans_table.clear()
        for scan in reversed(self.scan_history[-5:]):
            vuln_count = sum(len(r['vulnerabilities']) for r in scan['results']) + len(scan['vulnerabilities'])
            item = QTreeWidgetItem([scan['timestamp'], scan['target'], scan['profile'], str(vuln_count)])
            self.recent_scans_table.addTopLevelItem(item)

    def update_vulnerabilities(self):
        if not self.scan_history:
            return
        
        latest_scan = self.scan_history[-1]
        self.vuln_table.clear()

        for result in latest_scan['results']:
            for vuln in result['vulnerabilities']:
                item = QTreeWidgetItem([
                    vuln['severity'],
                    result['host'],
                    str(result['port']),
                    vuln['type'],
                    vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
                ])
                self.color_vuln_item(item, vuln['severity'])
                self.vuln_table.addTopLevelItem(item)

        for vuln in latest_scan['vulnerabilities']:
            item = QTreeWidgetItem([
                vuln['severity'],
                latest_scan['target'],
                "N/A",
                vuln['type'],
                vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
            ])
            self.color_vuln_item(item, vuln['severity'])
            self.vuln_table.addTopLevelItem(item)

        self.update_vuln_filters()
    
    def color_vuln_item(self, item, severity):
        if severity == 'Critical':
            item.setBackground(0, QColor(255, 0, 0))
        elif severity == 'High':
            item.setBackground(0, QColor(255, 100, 0))
        elif severity == 'Medium':
            item.setBackground(0, QColor(255, 165, 0))
        else:
            item.setBackground(0, QColor(255, 255, 0))
    
    def update_vuln_filters(self):
        if not self.scan_history:
            return
        
        latest_scan = self.scan_history[-1]

        hosts = set()
        for result in latest_scan['results']:
            hosts.add(result['host'])
        
        current_host = self.vuln_filter_host.currentText()
        
        self.vuln_filter_host.clear()
        self.vuln_filter_host.addItem("All Hosts")
        self.vuln_filter_host.addItems(sorted(hosts))

        index = self.vuln_filter_host.findText(current_host)
        if index >= 0:
            self.vuln_filter_host.setCurrentIndex(index)

    def show_vuln_details(self, item):
        severity = item.text(0)
        host = item.text(1)
        port = item.text(2)
        vuln_type = item.text(3)

        latest_scan = self.scan_history[-1]
        vuln_details = ""

        for result in latest_scan['results']:
            if result['host'] == host and str(result['port']) == port:
                for vuln in result['vulnerabilities']:
                    if vuln['type'] == vuln_type:
                        vuln_details = f"""
                        <h2>{vuln_type} ({severity})</h2>
                        <p><b>Host:</b> {host}:{port}</p>
                        <p><b>Description:</b> {vuln['description']}</p>
                        <p><b>Solution:</b> {vuln['solution']}</p>
                        """
                        break
                if vuln_details:
                    break

        if not vuln_details:
            for vuln in latest_scan['vulnerabilities']:
                if vuln['type'] == vuln_type and vuln['severity'] == severity:
                    vuln_details = f"""
                    <h2>{vuln_type} ({severity})</h2>
                    <p><b>Host:</b> {host}</p>
                    <p><b>Description:</b> {vuln['description']}</p>
                    <p><b>Solution:</b> {vuln['solution']}</p>
                    """
                    break
        
        self.vuln_details.setHtml(vuln_details if vuln_details else "<p>No details available</p>")


    def generate_report(self, format):
        if not self.scan_history:
            QMessageBox.warning(self, "No Data", "No scan data available to generate report")
            return
          
        latest_scan = self.scan_history[-1]
        report_type = self.report_type_combo.currentText()

        default_name = f"pacs_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", default_name, 
                                            f"{format.upper()} Files (*.{format})")
        
        if not path:
            return  
        
        try:
            if format == "pdf":
                self.generate_pdf_report(path, latest_scan, report_type)
            
            QMessageBox.information(self, "Report Generated", f"Report successfully saved to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Report Error", f"Failed to generate report: {str(e)}")
    
    def generate_pdf_report(self, path, scan_data, report_type):

        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        doc = SimpleDocTemplate(path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='SmallText', parent=styles['Normal'], fontSize=8))
        story = []

        def wrap_text(text):
            return Paragraph(text, styles['SmallText'])

        title = Paragraph(f"PACS/DICOM Security Assessment Report - {report_type}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))

        meta = [
            ["Scan Date:", scan_data['timestamp']],
            ["Target:", scan_data['target']],
            ["Scan Profile:", scan_data['profile']],
            ["Generated On:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
        ]
        
        meta_table = Table(meta, colWidths=[100, 400])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 24))

        if report_type == "Executive Summary":
            summary = Paragraph("""
                <b>Executive Summary</b><br/><br/>
                This report provides a high-level overview of the security assessment conducted on the 
                PACS/DICOM system. The assessment identified several vulnerabilities that could potentially 
                compromise the confidentiality, integrity, and availability of medical imaging data and 
                protected health information (PHI).
            """, styles['Normal'])
            story.append(summary)
            story.append(Spacer(1, 12))

            vuln_counts = defaultdict(int)
            for result in scan_data['results']:
                for vuln in result['vulnerabilities']:
                    vuln_counts[vuln['severity']] += 1
            
            for vuln in scan_data['vulnerabilities']:
                vuln_counts[vuln['severity']] += 1
            
            vuln_data = [
                ["Severity", "Count"],
                ["Critical", str(vuln_counts.get('Critical', 0))],
                ["High", str(vuln_counts.get('High', 0))],
                ["Medium", str(vuln_counts.get('Medium', 0))],
                ["Low", str(vuln_counts.get('Low', 0))]
            ]

            vuln_table = Table(vuln_data, colWidths=[150, 150])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ffa500')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#ff0000')),
                ('TEXTCOLOR', (0, 1), (-1, 1), colors.white),
                ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#ff6600')),
                ('TEXTCOLOR', (0, 2), (-1, 2), colors.white),
                ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#ffa500')),
                ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#ffff00')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 12))

            recs = Paragraph("""
                <b>Key Recommendations</b><br/><br/>
    1. <b>Implement DICOM-TLS</b>: Encrypt all DICOM communications using TLS 1.2+ on port 2762 with mutual authentication<br/>
    2. <b>Enforce Strong Authentication</b>: Require MFA for admin access, eliminate default credentials, and enforce password policies<br/>
    3. <b>Patch Management</b>: Apply security updates promptly and isolate unpatchable legacy systems<br/>
    4. <b>DICOM De-Identification</b>: Automate PHI removal from metadata and maintain separate de-identified datasets<br/>
    5. <b>Comprehensive Logging</b>: Log all DICOM transactions (C-STORE, C-FIND) with timestamps and user IDs for 6+ years<br/>
    6. <b>Secure Web Interfaces</b>: Disable directory listing, implement OAuth2 for DICOM web services, and sanitize inputs<br/>
    7. <b>MWL Protection</b>: Validate worklist entries against scheduling systems and monitor for anomalies<br/>
    8. <b>Data Retention</b>: Define and enforce retention periods (e.g., 7 years for imaging studies)<br/>
    9. <b>Staff Training</b>: Conduct regular security awareness training with phishing simulations<br/>
    10. <b>Penetration Testing</b>: Perform annual security assessments by qualified third parties<br/><br/>

        <b>Priority Implementation</b>:<br/>
    - <font color="#ff0000">Critical (0-14 days)</font>: DICOM-TLS, Patching, MFA<br/>
    - <font color="#ff6600">High (30 days)</font>: Logging, De-Identification<br/>
    - <font color="#ffa500">Medium (60-90 days)</font>: Web Hardening, Retention Policies<br></br>

        <b>Bussiness Impact Analysis</b>:<br/>
        <b>HIGH IMPACT: Unauthorized Access to PHI</b><br/>
            - Financial Impact: $10 per record breach × estimated 10 patient records = $100 potential liability<br/>
            - Operational Impact: Mandatory HHS OCR reporting requiring 100+ staff hours<br/>
            - Reputational Impact: 10% of healthcare organizations report significant patient loss after PHI breaches
            """, styles['Normal'])
            story.append(recs)

        elif report_type == "Technical Report":
            ports = Paragraph("<b>Port Scan Results</b>", styles['Heading2'])
            story.append(ports)
            story.append(Spacer(1, 6))
            
            port_data = [["Host", "Port", "Service", "State", "Version"]]
            for result in scan_data['results']:
                port_data.append([
                    result['host'],
                    str(result['port']),
                    result['service'],
                    result['state'],
                    result.get('version', '')
                ])

            port_table = Table(port_data, colWidths=[120, 50, 90, 70, 140])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ffa500')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(port_table)
            story.append(Spacer(1, 12))

            vulns = Paragraph("<b>Vulnerability Findings</b>", styles['Heading2'])
            story.append(vulns)
            story.append(Spacer(1, 6))
 
            vuln_data = [["Severity", "Host", "Port", "Type", "Description"]]
            
            for result in scan_data['results']:
                for vuln in result['vulnerabilities']:
                    vuln_data.append([
                        vuln['severity'],
                        result['host'],
                        str(result['port']),
                        wrap_text(vuln['type']),
                        wrap_text(vuln['description'])
                    ])
            
            for vuln in scan_data['vulnerabilities']:
                vuln_data.append([
                    vuln['severity'],
                    scan_data['target'],
                    "N/A",
                    wrap_text(vuln['type']),
                    wrap_text(vuln['description'])
                ])

            vuln_table = Table(vuln_data, colWidths=[60, 80, 40, 100, 190])
            
            base_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ffa500')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'), 
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ])
            
            vuln_table.setStyle(base_style)

            for i in range(1, len(vuln_data)):
                if vuln_data[i][0] == 'Critical':
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, i), (-1, i), colors.HexColor('#ff0000')),
                        ('TEXTCOLOR', (0, i), (-1, i), colors.white)
                    ]))
                elif vuln_data[i][0] == 'High':
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, i), (-1, i), colors.HexColor('#ff6600')),
                        ('TEXTCOLOR', (0, i), (-1, i), colors.white)
                    ]))
                elif vuln_data[i][0] == 'Medium':
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, i), (-1, i), colors.HexColor('#ffa500'))
                    ]))
                elif vuln_data[i][0] == 'Low':
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, i), (-1, i), colors.HexColor('#ffff00'))
                    ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 12))

            rem = Paragraph("<b>Remediation Recommendations</b>", styles['Heading2'])
            story.append(rem)
            story.append(Spacer(1, 6))

            rec_data = [["Vulnerability Type", "Solution"]]
            seen_solutions = set() 
            
            for result in scan_data['results']:
                for vuln in result['vulnerabilities']:
                    solution_key = f"{vuln['type']}:{vuln['solution']}"
                    if solution_key not in seen_solutions:
                        rec_data.append([wrap_text(vuln['type']), wrap_text(vuln['solution'])])
                        seen_solutions.add(solution_key)
            
            for vuln in scan_data['vulnerabilities']:
                solution_key = f"{vuln['type']}:{vuln['solution']}"
                if solution_key not in seen_solutions:
                    rec_data.append([wrap_text(vuln['type']), wrap_text(vuln['solution'])])
                    seen_solutions.add(solution_key)
            
            rec_table = Table(rec_data, colWidths=[150, 350])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ffa500')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'), 
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(rec_table)

        elif report_type == "Compliance Report":
            comp = Paragraph("<b>HIPAA/GDPR Compliance Assessment</b>", styles['Heading2'])
            story.append(comp)
            story.append(Spacer(1, 6))

            comp_issues = []
            for result in scan_data['results']:
                for vuln in result['vulnerabilities']:
                    if any(keyword in vuln['type'] for keyword in ['Authentication', 'Encryption', 'PHI', 'Logging']):
                        comp_issues.append(vuln)
            
            for vuln in scan_data['vulnerabilities']:
                if any(keyword in vuln['type'] for keyword in ['Authentication', 'Encryption', 'PHI', 'Logging']):
                    comp_issues.append(vuln)
            
            if not comp_issues:
                story.append(Paragraph("No significant compliance issues found.", styles['Normal']))
            else:
                comp_data = [["Issue", "Description", "Standard Violated"]]
                for issue in comp_issues:
                    standards = []
                    if 'Authentication' in issue['type']:
                        standards.append("HIPAA 164.312(a)(1)")
                    if 'Encryption' in issue['type']:
                        standards.append("HIPAA 164.312(e)(1)")
                    if 'PHI' in issue['type']:
                        standards.append("HIPAA 164.514")
                        standards.append("GDPR Article 5(1)(f)")
                    if 'Logging' in issue['type']:
                        standards.append("HIPAA 164.312(b)")
                    
                    comp_data.append([
                        wrap_text(issue['type']),
                        wrap_text(issue['description']),
                        wrap_text(", ".join(standards))
                    ])

                comp_table = Table(comp_data, colWidths=[120, 250, 150])
                comp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ffa500')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'), 
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                
                story.append(comp_table)
                story.append(Spacer(1, 12))

            recs = Paragraph("<b>Compliance Recommendations</b>", styles['Heading2'])
            story.append(recs)
            story.append(Spacer(1, 6))
            
            rec_text = """
            <b>Key Recommendations</b><br/><br/>
    <b>1. Implement DICOM-TLS Encryption</b><br/>
    • Configure DICOM-TLS on port 2762 for all communications<br/>
    • Enforce TLS 1.2+ and disable weak protocols (SSLv3, TLS 1.0)<br/>
    • Use valid certificates from trusted Certificate Authorities<br/><br/>

    <b>2. Enforce Strong Authentication</b><br/>
    • Eliminate default credentials (admin/admin)<br/>
    • Implement multi-factor authentication for administrative access<br/>
    • Enforce password policies (12+ chars, complexity, rotation)<br/><br/>

    <b>3. Apply Security Patches</b><br/>
    • Maintain regular patch cycles for PACS software<br/>
    • Subscribe to vendor security bulletins<br/>
    • Isolate legacy systems that cannot be patched<br/><br/>

    <b>4. Implement DICOM De-Identification</b><br/>
    • Automate PHI removal from DICOM headers<br/>
    • Create de-identified copies for research/sharing<br/>
    • Audit DICOM tags before external transfers<br/><br/>

    <b>5. Configure Comprehensive Logging</b><br/>
    • Log all DICOM transactions with timestamps<br/>
    • Centralize logs in a SIEM solution<br/>
    • Retain logs for minimum 6 years<br/><br/>

    <b>Implementation Timeline:</b><br/>
    <font color="#ff0000">• Critical (0-14 days):</font> DICOM-TLS, Patching<br/>
    <font color="#ff6600">• High (30 days):</font> Authentication, Logging<br/>
    <font color="#ffa500">• Medium (60-90 days):</font> De-Identification, Web Security
    """
            
            story.append(Paragraph(rec_text, styles['Normal']))

        doc.build(story)
            
    def new_scan(self):
        self.host_input.clear()
        self.selected_ports.setText(", ".join(map(str, DICOM_PORTS)))
        self.profile_combo.setCurrentIndex(0)
        
        self.statusBar().showMessage("New scan configuration ready")

        self.module_checks["Network Scanning"].setChecked(True)
        self.module_checks["Basic Vulnerability Detection"].setChecked(True)
        for name in self.module_checks:
            if name not in ["Network Scanning", "Basic Vulnerability Detection"]:
                self.module_checks[name].setChecked(False)
        
        self.statusBar().showMessage("New scan configuration ready")

    def load_scan_from_history(self, item):
        text = item.text()
        timestamp = text.split(" - ")[0]
        
        for scan in self.scan_history:
            if scan['timestamp'] == timestamp:
                self.display_scan_results(scan)
                break

    def display_scan_results(self, scan_data):
        self.vuln_table.clear()
        
        for result in scan_data['results']:
            for vuln in result['vulnerabilities']:
                item = QTreeWidgetItem([
                    vuln['severity'],
                    result['host'],
                    str(result['port']),
                    vuln['type'],
                    vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
                ])
                self.color_vuln_item(item, vuln['severity'])
                self.vuln_table.addTopLevelItem(item)
        
        for vuln in scan_data['vulnerabilities']:
            item = QTreeWidgetItem([
                vuln['severity'],
                scan_data['target'],
                "N/A",
                vuln['type'],
                vuln['description'][:100] + "..." if len(vuln['description']) > 100 else vuln['description']
            ])
            self.color_vuln_item(item, vuln['severity'])
            self.vuln_table.addTopLevelItem(item)

        self.tabs.setCurrentIndex(0)
        self.statusBar().showMessage(f"Displaying scan from {scan_data['timestamp']}")

    def show_dashboard(self):

        self.tabs.setCurrentIndex(0)

    def show_scan_config(self):
        self.tabs.setCurrentIndex(1)

    def show_reporting(self):
        self.tabs.setCurrentIndex(2)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    app.setApplicationName("PACS/DICOM Security Assessment Tool")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("Healthcare Security")
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())