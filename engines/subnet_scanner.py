"""
engines/subnet_scanner.py
Multi-Target Discovery and Network Asset Inventory Engine.

Supports:
- Single IP, Hostname, and CIDR subnet scanning (e.g. 192.168.1.0/24)
- Concurrent worker threads with bounded connection limits
- Target scope validation (prevents accidental public internet scans)
- DICOM and web service asset fingerprinting
- Automatic asset inventory population
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from models.findings import Asset
from db import database as db

logger = logging.getLogger(__name__)

STANDARD_DISCOVERY_PORTS = [104, 2761, 2762, 4242, 8042, 80, 443, 8080, 11112]


@dataclass
class SubnetScanTarget:
    ip: str
    is_up: bool = False
    open_ports: List[int] = field(default_factory=list)
    detected_services: List[str] = field(default_factory=list)
    ae_titles: List[str] = field(default_factory=list)
    vendor: str = "Unknown"
    device_type: str = "Clinical Modality / PACS"


class SubnetScanner:
    """
    Scans IP ranges and CIDR subnets concurrently to discover active DICOM & PACS assets.
    """

    def __init__(
        self,
        target_spec: str,
        ports: Optional[List[int]] = None,
        max_threads: int = 16,
        timeout: float = 1.0,
        authorized: bool = False,
    ):
        self.target_spec = target_spec.strip()
        self.ports = ports or STANDARD_DISCOVERY_PORTS
        self.max_threads = max_threads
        self.timeout = timeout
        self.authorized = authorized
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def validate_scope(self) -> Tuple[bool, str, List[str]]:
        """
        Validates target specification. Restricts unconfirmed wide-range scans.
        Returns (is_valid, message, list_of_ips).
        """
        if not self.authorized:
            return False, "Scope authorization confirmation is strictly required.", []

        ips: List[str] = []
        try:
            if "/" in self.target_spec:
                network = ipaddress.ip_network(self.target_spec, strict=False)
                # Safeguard: cap subnet at /24 (max 256 hosts) for non-destructive scanning
                if network.prefixlen < 24:
                    return False, f"Subnet /{network.prefixlen} is too large. Please restrict scope to /24 or smaller.", []
                ips = [str(ip) for ip in network.hosts()]
            elif "," in self.target_spec:
                ips = [ip.strip() for ip in self.target_spec.split(",") if ip.strip()]
            else:
                # Single host or IP
                resolved_ip = socket.gethostbyname(self.target_spec)
                ips = [resolved_ip]
        except Exception as exc:
            return False, f"Invalid target specification: {exc}", []

        # Prevent accidental scanning of public cloud ranges
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback):
                    return False, f"Target {ip} is a public internet address. Tool is restricted to private clinical networks.", []
            except ValueError:
                pass

        return True, f"Scope validated: {len(ips)} host(s) scheduled for assessment.", ips

    def scan_host(self, ip: str) -> SubnetScanTarget:
        target = SubnetScanTarget(ip=ip)
        for port in self.ports:
            if self._cancel:
                break
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    target.is_up = True
                    target.open_ports.append(port)
                    if port in (104, 2761, 2762, 4242, 11112):
                        target.detected_services.append(f"DICOM ({port})")
                        if port == 4242:
                            target.vendor = "Orthanc PACS"
                            target.device_type = "PACS Server"
                    elif port in (8042, 80, 443, 8080):
                        target.detected_services.append(f"HTTP ({port})")
                        if port == 8042:
                            target.vendor = "Orthanc PACS"
            except Exception:
                pass

        return target

    def run(
        self,
        progress_callback: Optional[Callable[[int, str], None]] = None,
        asset_discovered_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> List[Asset]:
        is_valid, msg, ips = self.validate_scope()
        if not is_valid:
            if progress_callback:
                progress_callback(0, f"Scope validation failed: {msg}")
            return []

        total_hosts = len(ips)
        completed = 0
        discovered_assets: List[Asset] = []

        if progress_callback:
            progress_callback(5, f"Initiating concurrent discovery across {total_hosts} host(s)…")

        with ThreadPoolExecutor(max_workers=min(self.max_threads, total_hosts)) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in ips}

            for future in as_completed(future_to_ip):
                if self._cancel:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                try:
                    target_res = future.result()
                    if target_res.is_up and target_res.open_ports:
                        asset_dict = {
                            "asset_id": f"ASSET-{target_res.ip.replace('.', '-')}",
                            "ip": target_res.ip,
                            "hostname": target_res.ip,
                            "vendor": target_res.vendor,
                            "device_type": target_res.device_type,
                            "open_ports": target_res.open_ports,
                            "detected_services": target_res.detected_services,
                            "ae_titles": target_res.ae_titles,
                            "first_seen": datetime.utcnow().isoformat(),
                            "last_seen": datetime.utcnow().isoformat(),
                            "risk_score": 5.0 if any(p in target_res.open_ports for p in (104, 4242)) else 1.0,
                        }
                        db.upsert_asset(asset_dict)
                        asset_obj = Asset(**asset_dict)
                        discovered_assets.append(asset_obj)

                        if asset_discovered_callback:
                            asset_discovered_callback(asset_dict)

                except Exception as exc:
                    logger.debug("Host scan error: %s", exc)

                completed += 1
                if progress_callback:
                    pct = int((completed / total_hosts) * 90) + 5
                    progress_callback(pct, f"Discovered {len(discovered_assets)} asset(s) ({completed}/{total_hosts} scanned)")

        if progress_callback:
            progress_callback(100, f"Discovery complete — {len(discovered_assets)} active asset(s) indexed.")

        return discovered_assets
