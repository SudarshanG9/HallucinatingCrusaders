"""
Mock AWS GuardDuty connector.

Generates realistic-looking GuardDuty-style alerts covering common finding
types: UnauthorizedAccess, Recon, Trojan, and Exfiltration.  Useful for
development and demo without an actual AWS account.
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

__all__ = ["MockGuardDutyConnector"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Realistic data pools
# ---------------------------------------------------------------------------

_FINDING_TYPES: List[Dict] = [
    {
        "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "description": "API call from a known malicious IP address",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Initial Access"],
        "techniques": ["T1078"],
    },
    {
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "description": "SSH brute-force attack detected on EC2 instance",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Credential Access"],
        "techniques": ["T1110", "T1110.001"],
    },
    {
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "description": "Unprotected port on EC2 instance is being probed",
        "severity": SeverityLevel.LOW,
        "tactics": ["Discovery"],
        "techniques": ["T1046"],
    },
    {
        "type": "Recon:IAMUser/TorIPCaller",
        "description": "API call received from a Tor exit node IP",
        "severity": SeverityLevel.MEDIUM,
        "tactics": ["Discovery"],
        "techniques": ["T1590"],
    },
    {
        "type": "Trojan:EC2/BlackholeTraffic",
        "description": "EC2 instance communicating with a known blackhole IP",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Command and Control"],
        "techniques": ["T1071"],
    },
    {
        "type": "Trojan:EC2/DGADomainRequest.B",
        "description": "EC2 instance querying algorithmically generated domains",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Command and Control"],
        "techniques": ["T1568.002"],
    },
    {
        "type": "Exfiltration:S3/MaliciousIPCaller",
        "description": "S3 bucket accessed from a known malicious IP",
        "severity": SeverityLevel.CRITICAL,
        "tactics": ["Exfiltration"],
        "techniques": ["T1537"],
    },
    {
        "type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "description": "Successful console login from an unusual location",
        "severity": SeverityLevel.MEDIUM,
        "tactics": ["Initial Access"],
        "techniques": ["T1078.004"],
    },
    {
        "type": "Exfiltration:S3/ObjectRead.Unusual",
        "description": "Unusual volume of S3 object read operations detected",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Exfiltration", "Collection"],
        "techniques": ["T1530"],
    },
    {
        "type": "Recon:EC2/Portscan",
        "description": "EC2 instance performing outbound port scan",
        "severity": SeverityLevel.MEDIUM,
        "tactics": ["Discovery"],
        "techniques": ["T1046"],
    },
]

_MALICIOUS_IPS = [
    "198.51.100.23", "203.0.113.42", "192.0.2.17", "45.33.32.156",
    "185.220.101.34", "171.25.193.9", "62.102.148.68", "91.219.236.222",
]

_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "eu-central-1",
]

_IAM_USERS = [
    "deploy-bot", "ci-runner", "admin-jsmith", "svc-monitoring",
    "dev-alice", "ops-charlie", "svc-backup", "analyst-bob",
]

_EC2_IDS = [
    "i-0a1b2c3d4e5f6a7b8", "i-09f8e7d6c5b4a3210",
    "i-01234abcde56789ff", "i-0fedcba987654321a",
    "i-0112233445566aabb", "i-0aabbccddee001122",
]

_ACCOUNT_IDS = ["123456789012", "987654321098", "112233445566"]


class MockGuardDutyConnector(BaseConnector):
    """Generates realistic mock AWS GuardDuty findings for testing."""

    @property
    def name(self) -> str:
        return "mock_guardduty"

    @property
    def vendor(self) -> str:
        return "AWS GuardDuty"

    async def connect(self) -> bool:
        """No real connection needed for mock data."""
        logger.info("[mock_guardduty] Connected (mock mode)")
        return True

    async def disconnect(self) -> None:
        """No-op for mock connector."""
        logger.info("[mock_guardduty] Disconnected (mock mode)")

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
    ) -> List[NormalizedAlert]:
        """Generate 1-5 random GuardDuty-style alerts."""
        count = random.randint(1, min(5, limit))
        alerts: List[NormalizedAlert] = []

        for _ in range(count):
            finding = random.choice(_FINDING_TYPES)
            alert = self._generate_alert(finding)
            alerts.append(alert)

        logger.info("[mock_guardduty] Generated %d mock alerts", len(alerts))
        return alerts

    async def health_check(self) -> Dict[str, object]:
        """Mock connector is always healthy."""
        return {
            "status": "healthy",
            "message": "Mock GuardDuty connector is operational",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_alert(self, finding: Dict) -> NormalizedAlert:
        """Build a single mock GuardDuty alert."""
        src_ip = random.choice(_MALICIOUS_IPS)
        region = random.choice(_REGIONS)
        iam_user = random.choice(_IAM_USERS)
        ec2_id = random.choice(_EC2_IDS)
        account_id = random.choice(_ACCOUNT_IDS)

        # Simulate a timestamp within the last 60 minutes
        ts_offset = random.randint(0, 3600)
        timestamp = datetime.now(timezone.utc) - timedelta(seconds=ts_offset)

        finding_id = str(uuid.uuid4())

        raw_finding = {
            "schemaVersion": "2.0",
            "accountId": account_id,
            "region": region,
            "id": finding_id,
            "type": finding["type"],
            "severity": finding["severity"],
            "title": finding["description"],
            "description": (
                f"GuardDuty finding: {finding['type']} detected in "
                f"account {account_id}, region {region}."
            ),
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": ec2_id,
                    "networkInterfaces": [
                        {
                            "privateIpAddress": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                            "publicIp": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                        }
                    ],
                },
            },
            "service": {
                "action": {
                    "actionType": "NETWORK_CONNECTION",
                    "networkConnectionAction": {
                        "connectionDirection": "INBOUND",
                        "remoteIpDetails": {
                            "ipAddressV4": src_ip,
                            "country": {"countryName": "Unknown"},
                        },
                    },
                },
                "additionalInfo": {"iamUser": iam_user},
            },
            "createdAt": timestamp.isoformat(),
            "updatedAt": timestamp.isoformat(),
        }

        return NormalizedAlert(
            source=self.name,
            vendor=self.vendor,
            timestamp=timestamp,
            severity=finding["severity"],
            raw_content=json.dumps(raw_finding, default=str),
            rule_id=finding["type"],
            rule_description=finding["description"],
            src_ip=src_ip,
            dst_ip=None,
            username=iam_user,
            hostname=ec2_id,
            mitre_tactics=finding.get("tactics", []),
            mitre_techniques=finding.get("techniques", []),
            tags=["aws", "guardduty", region],
        )
