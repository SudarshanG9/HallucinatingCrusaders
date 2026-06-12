"""
Mock Microsoft Defender for Endpoint connector.

Generates realistic endpoint-security alerts covering malware detection,
suspicious process execution, lateral movement indicators, and ransomware
behaviour patterns.
"""

from __future__ import annotations

import json
import logging
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from soc_analyst.collector.connectors.base import BaseConnector
from soc_analyst.collector.models import NormalizedAlert, SeverityLevel

__all__ = ["MockDefenderConnector"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Realistic data pools
# ---------------------------------------------------------------------------

_ALERT_TYPES: List[Dict] = [
    {
        "type": "malware_detected",
        "description": "Malware binary detected and quarantined on endpoint",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Execution"],
        "techniques": ["T1204.002"],
    },
    {
        "type": "suspicious_process",
        "description": "Suspicious process spawned from unusual parent",
        "severity": SeverityLevel.MEDIUM,
        "tactics": ["Execution", "Defense Evasion"],
        "techniques": ["T1059.001", "T1036"],
    },
    {
        "type": "lateral_movement",
        "description": "Possible lateral movement via remote service execution",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Lateral Movement"],
        "techniques": ["T1021.002", "T1570"],
    },
    {
        "type": "ransomware_behavior",
        "description": "Ransomware-like file encryption behaviour detected",
        "severity": SeverityLevel.CRITICAL,
        "tactics": ["Impact"],
        "techniques": ["T1486"],
    },
    {
        "type": "credential_dumping",
        "description": "LSASS memory access detected -- possible credential dump",
        "severity": SeverityLevel.CRITICAL,
        "tactics": ["Credential Access"],
        "techniques": ["T1003.001"],
    },
    {
        "type": "persistence_registry",
        "description": "Suspicious registry run key modification for persistence",
        "severity": SeverityLevel.MEDIUM,
        "tactics": ["Persistence"],
        "techniques": ["T1547.001"],
    },
    {
        "type": "powershell_obfuscation",
        "description": "Obfuscated PowerShell command detected on endpoint",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Execution", "Defense Evasion"],
        "techniques": ["T1059.001", "T1027"],
    },
    {
        "type": "dll_sideloading",
        "description": "Potential DLL side-loading detected in application directory",
        "severity": SeverityLevel.MEDIUM,
        "tactics": ["Persistence", "Defense Evasion"],
        "techniques": ["T1574.002"],
    },
]

_HOSTNAMES = [
    "WS-NYC-0142", "WS-LON-0087", "SRV-DC01", "SRV-FS02",
    "WS-SFO-0233", "LAPTOP-DEV-03", "WS-BER-0019", "SRV-WEB01",
    "WS-TYO-0071", "LAPTOP-EXEC-07", "SRV-DB03", "WS-SYD-0155",
]

_USERNAMES = [
    "CORP\\jdoe", "CORP\\asmith", "CORP\\bwilson",
    "CORP\\mgarcia", "CORP\\admin.svc", "CORP\\ljohnson",
    "LOCAL\\administrator", "CORP\\svc.backup", "NT AUTHORITY\\SYSTEM",
]

_PROCESS_NAMES = [
    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "svchost.exe",
]

_PARENT_PROCESSES = [
    "explorer.exe", "winword.exe", "outlook.exe", "excel.exe",
    "chrome.exe", "msedge.exe", "cmd.exe", "wmiprvse.exe",
    "svchost.exe", "services.exe", "taskeng.exe",
]

_FILE_PATHS = [
    "C:\\Users\\Public\\Downloads\\update.exe",
    "C:\\Windows\\Temp\\svc_helper.dll",
    "C:\\ProgramData\\Microsoft\\crypto\\helper.ps1",
    "C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe",
    "C:\\Windows\\System32\\Tasks\\evil_task.xml",
    "C:\\Temp\\mimikatz.exe",
    "D:\\Shares\\Finance\\encrypted_readme.txt",
]


def _random_sha256() -> str:
    """Generate a plausible random SHA-256 hash string."""
    return uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars


def _random_internal_ip() -> str:
    """Generate a random RFC-1918 IP."""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


class MockDefenderConnector(BaseConnector):
    """Generates realistic mock Microsoft Defender endpoint alerts."""

    @property
    def name(self) -> str:
        return "mock_defender"

    @property
    def vendor(self) -> str:
        return "Microsoft Defender for Endpoint"

    async def connect(self) -> bool:
        """No real connection needed for mock data."""
        logger.info("[mock_defender] Connected (mock mode)")
        return True

    async def disconnect(self) -> None:
        """No-op for mock connector."""
        logger.info("[mock_defender] Disconnected (mock mode)")

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
    ) -> List[NormalizedAlert]:
        """Generate 1-4 random Defender-style endpoint alerts."""
        count = random.randint(1, min(4, limit))
        alerts: List[NormalizedAlert] = []

        for _ in range(count):
            alert_def = random.choice(_ALERT_TYPES)
            alert = self._generate_alert(alert_def)
            alerts.append(alert)

        logger.info("[mock_defender] Generated %d mock alerts", len(alerts))
        return alerts

    async def health_check(self) -> Dict[str, object]:
        """Mock connector is always healthy."""
        return {
            "status": "healthy",
            "message": "Mock Defender connector is operational",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_alert(self, alert_def: Dict) -> NormalizedAlert:
        """Build a single mock Defender alert."""
        hostname = random.choice(_HOSTNAMES)
        username = random.choice(_USERNAMES)
        process = random.choice(_PROCESS_NAMES)
        parent = random.choice(_PARENT_PROCESSES)
        file_path = random.choice(_FILE_PATHS)
        file_hash = _random_sha256()
        machine_ip = _random_internal_ip()

        ts_offset = random.randint(0, 3600)
        timestamp = datetime.now(timezone.utc) - timedelta(seconds=ts_offset)

        alert_id = str(uuid.uuid4())

        raw_alert = {
            "id": alert_id,
            "incidentId": random.randint(10000, 99999),
            "alertCreationTime": timestamp.isoformat(),
            "title": alert_def["description"],
            "category": alert_def["type"],
            "severity": alert_def["severity"],
            "status": "New",
            "classification": None,
            "determination": None,
            "machineId": str(uuid.uuid4()),
            "computerDnsName": hostname,
            "machineIp": machine_ip,
            "userPrincipalName": username,
            "evidence": [
                {
                    "entityType": "Process",
                    "processName": process,
                    "parentProcessName": parent,
                    "processCommandLine": f'{process} -ExecutionPolicy Bypass -File "{file_path}"',
                    "sha256": file_hash,
                    "filePath": file_path,
                },
            ],
            "detectionSource": "WindowsDefenderAv",
            "threatName": random.choice([
                "Trojan:Win32/Emotet", "HackTool:Win64/Mimikatz",
                "Ransom:Win32/Conti", "Backdoor:MSIL/Cobalt",
                "Behavior:Win32/SuspProcess", None,
            ]),
            "mitreTechniques": alert_def.get("techniques", []),
        }

        return NormalizedAlert(
            source=self.name,
            vendor=self.vendor,
            timestamp=timestamp,
            severity=alert_def["severity"],
            raw_content=json.dumps(raw_alert, default=str),
            rule_id=alert_def["type"],
            rule_description=alert_def["description"],
            src_ip=machine_ip,
            dst_ip=None,
            username=username,
            hostname=hostname,
            mitre_tactics=alert_def.get("tactics", []),
            mitre_techniques=alert_def.get("techniques", []),
            tags=["defender", "endpoint", alert_def["type"]],
        )
