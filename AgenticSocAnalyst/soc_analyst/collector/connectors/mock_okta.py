"""
Mock Okta connector.

Generates realistic identity-and-access alerts that mimic Okta System Log
events: suspicious logins, MFA bypass attempts, impossible-travel detections,
and credential-stuffing campaigns.
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

__all__ = ["MockOktaConnector"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Realistic data pools
# ---------------------------------------------------------------------------

_EVENT_TYPES: List[Dict] = [
    {
        "type": "suspicious_login",
        "description": "Login from suspicious IP address not seen before",
        "severity": SeverityLevel.MEDIUM,
        "tactics": ["Initial Access"],
        "techniques": ["T1078"],
    },
    {
        "type": "mfa_bypass",
        "description": "MFA verification bypassed or failed repeatedly",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Credential Access", "Defense Evasion"],
        "techniques": ["T1556.006", "T1111"],
    },
    {
        "type": "impossible_travel",
        "description": "User authenticated from geographically impossible locations",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Initial Access"],
        "techniques": ["T1078.004"],
    },
    {
        "type": "credential_stuffing",
        "description": "Multiple failed authentications from a single source IP",
        "severity": SeverityLevel.CRITICAL,
        "tactics": ["Credential Access"],
        "techniques": ["T1110.004"],
    },
    {
        "type": "admin_privilege_escalation",
        "description": "User granted super-admin privileges outside change window",
        "severity": SeverityLevel.CRITICAL,
        "tactics": ["Privilege Escalation"],
        "techniques": ["T1078.004", "T1098"],
    },
    {
        "type": "session_hijack",
        "description": "Session token reused from a new device fingerprint",
        "severity": SeverityLevel.HIGH,
        "tactics": ["Lateral Movement"],
        "techniques": ["T1550.001"],
    },
]

_USER_EMAILS = [
    "jdoe@acme-corp.com", "asmith@acme-corp.com", "bwilson@acme-corp.com",
    "mgarcia@acme-corp.com", "ljohnson@acme-corp.com", "clee@acme-corp.com",
    "rpatil@acme-corp.com", "kwong@acme-corp.com", "tmueller@acme-corp.com",
]

_IPS = [
    "82.165.12.55", "104.28.210.33", "91.134.190.77",
    "178.62.88.201", "45.76.34.92", "185.143.223.14",
    "103.235.46.39", "23.94.168.120", "46.101.245.17",
]

_GEOLOCATIONS = [
    {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
    {"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278},
    {"city": "Moscow", "country": "RU", "lat": 55.7558, "lon": 37.6173},
    {"city": "Shanghai", "country": "CN", "lat": 31.2304, "lon": 121.4737},
    {"city": "Sao Paulo", "country": "BR", "lat": -23.5505, "lon": -46.6333},
    {"city": "Lagos", "country": "NG", "lat": 6.5244, "lon": 3.3792},
    {"city": "Berlin", "country": "DE", "lat": 52.5200, "lon": 13.4050},
    {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36",
    "python-requests/2.31.0",
    "curl/8.1.2",
]


class MockOktaConnector(BaseConnector):
    """Generates realistic mock Okta identity-security alerts for testing."""

    @property
    def name(self) -> str:
        return "mock_okta"

    @property
    def vendor(self) -> str:
        return "Okta Identity"

    async def connect(self) -> bool:
        """No real connection needed for mock data."""
        logger.info("[mock_okta] Connected (mock mode)")
        return True

    async def disconnect(self) -> None:
        """No-op for mock connector."""
        logger.info("[mock_okta] Disconnected (mock mode)")

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
    ) -> List[NormalizedAlert]:
        """Generate 1-3 random Okta-style alerts."""
        count = random.randint(1, min(3, limit))
        alerts: List[NormalizedAlert] = []

        for _ in range(count):
            event = random.choice(_EVENT_TYPES)
            alert = self._generate_alert(event)
            alerts.append(alert)

        logger.info("[mock_okta] Generated %d mock alerts", len(alerts))
        return alerts

    async def health_check(self) -> Dict[str, object]:
        """Mock connector is always healthy."""
        return {
            "status": "healthy",
            "message": "Mock Okta connector is operational",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_alert(self, event: Dict) -> NormalizedAlert:
        """Build a single mock Okta alert."""
        user_email = random.choice(_USER_EMAILS)
        src_ip = random.choice(_IPS)
        geo = random.choice(_GEOLOCATIONS)
        user_agent = random.choice(_USER_AGENTS)

        ts_offset = random.randint(0, 3600)
        timestamp = datetime.now(timezone.utc) - timedelta(seconds=ts_offset)

        event_id = str(uuid.uuid4())

        raw_event = {
            "uuid": event_id,
            "published": timestamp.isoformat(),
            "eventType": event["type"],
            "severity": event["severity"],
            "displayMessage": event["description"],
            "actor": {
                "id": str(uuid.uuid4()),
                "type": "User",
                "alternateId": user_email,
                "displayName": user_email.split("@")[0].replace(".", " ").title(),
            },
            "client": {
                "userAgent": {"rawUserAgent": user_agent},
                "ipAddress": src_ip,
                "geographicalContext": {
                    "city": geo["city"],
                    "country": geo["country"],
                    "geolocation": {"lat": geo["lat"], "lon": geo["lon"]},
                },
            },
            "outcome": {
                "result": random.choice(["FAILURE", "SUCCESS", "FAILURE"]),
                "reason": event["description"],
            },
            "target": [
                {
                    "type": "AppInstance",
                    "displayName": random.choice([
                        "Salesforce", "AWS Console", "GitHub Enterprise",
                        "Jira Cloud", "Slack", "Microsoft 365",
                    ]),
                }
            ],
            "authenticationContext": {
                "authenticationStep": 0,
                "externalSessionId": str(uuid.uuid4())[:18],
            },
        }

        # For impossible travel, add a second location
        if event["type"] == "impossible_travel":
            second_geo = random.choice(
                [g for g in _GEOLOCATIONS if g["city"] != geo["city"]]
            )
            raw_event["debugContext"] = {
                "previousLocation": {
                    "city": second_geo["city"],
                    "country": second_geo["country"],
                },
                "timeBetweenLogins": f"{random.randint(1, 15)} minutes",
            }

        return NormalizedAlert(
            source=self.name,
            vendor=self.vendor,
            timestamp=timestamp,
            severity=event["severity"],
            raw_content=json.dumps(raw_event, default=str),
            rule_id=event["type"],
            rule_description=event["description"],
            src_ip=src_ip,
            dst_ip=None,
            username=user_email,
            hostname=None,
            mitre_tactics=event.get("tactics", []),
            mitre_techniques=event.get("techniques", []),
            tags=["okta", "identity", event["type"]],
        )
