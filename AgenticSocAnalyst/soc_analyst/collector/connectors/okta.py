"""
Real Okta connector.

Fetches security events from the Okta System Log API
(``GET /api/v1/logs``) and normalizes them into ``NormalizedAlert`` objects.

Docs: https://developer.okta.com/docs/reference/api/system-log/
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from soc_analyst.collector.connectors.base import BaseConnector
from soc_analyst.collector.models import NormalizedAlert, SeverityLevel
from soc_analyst.config import settings

__all__ = ["OktaConnector"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Okta event type → MITRE ATT&CK mapping
# ---------------------------------------------------------------------------

_MITRE_MAP: Dict[str, Dict[str, Any]] = {
    "user.session.start": {
        "tactics": ["Initial Access"],
        "techniques": ["T1078"],
    },
    "user.authentication.auth_via_mfa": {
        "tactics": ["Credential Access", "Defense Evasion"],
        "techniques": ["T1556.006"],
    },
    "user.account.lock": {
        "tactics": ["Credential Access"],
        "techniques": ["T1110"],
    },
    "user.account.privilege.grant": {
        "tactics": ["Privilege Escalation"],
        "techniques": ["T1078.004", "T1098"],
    },
    "policy.evaluate_sign_on": {
        "tactics": ["Initial Access"],
        "techniques": ["T1078"],
    },
    "user.authentication.sso": {
        "tactics": ["Initial Access"],
        "techniques": ["T1078.004"],
    },
    "user.mfa.factor.deactivate": {
        "tactics": ["Defense Evasion", "Credential Access"],
        "techniques": ["T1556.006"],
    },
    "user.account.update_password": {
        "tactics": ["Persistence"],
        "techniques": ["T1098"],
    },
    "app.user_management.deactivate_user": {
        "tactics": ["Impact"],
        "techniques": ["T1531"],
    },
    "user.session.impersonation.grant": {
        "tactics": ["Lateral Movement"],
        "techniques": ["T1550.001"],
    },
}

# ---------------------------------------------------------------------------
# Okta severity string → our SeverityLevel
# ---------------------------------------------------------------------------

_SEVERITY_MAP: Dict[str, SeverityLevel] = {
    "DEBUG": SeverityLevel.INFO,
    "INFO": SeverityLevel.LOW,
    "WARN": SeverityLevel.MEDIUM,
    "ERROR": SeverityLevel.HIGH,
}

# Security-relevant event type prefixes we care about
_SECURITY_EVENT_PREFIXES = (
    "user.session",
    "user.authentication",
    "user.account",
    "user.mfa",
    "policy.evaluate_sign_on",
    "app.user_management",
    "security.threat",
    "system.agent",
)


class OktaConnector(BaseConnector):
    """Fetches real security events from the Okta System Log API."""

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._base_url: str = ""
        self._headers: Dict[str, str] = {}

    @property
    def name(self) -> str:
        return "okta"

    @property
    def vendor(self) -> str:
        return "Okta Identity"

    async def connect(self) -> bool:
        """Authenticate with Okta using the API token."""
        domain = settings.okta.domain
        token = settings.okta.api_token

        if not domain or not token:
            logger.error("[okta] OKTA_DOMAIN or OKTA_API_TOKEN not set — cannot connect")
            return False

        self._base_url = f"https://{domain}"
        self._headers = {
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            verify=settings.okta.verify_ssl,
            timeout=30.0,
        )

        # Quick connectivity test
        try:
            resp = await self._client.get("/api/v1/users?limit=1")
            resp.raise_for_status()
            logger.info("[okta] Connected successfully to %s", domain)
            return True
        except Exception as exc:
            logger.error("[okta] Connection test failed: %s", exc)
            return False

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
        logger.info("[okta] Disconnected")

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
    ) -> List[NormalizedAlert]:
        """Fetch security events from Okta System Log since the given time."""
        if not self._client:
            logger.warning("[okta] Not connected — returning empty")
            return []

        since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        params = {
            "since": since_iso,
            "limit": min(limit, 1000),  # Okta max is 1000
            "sortOrder": "DESCENDING",
        }

        try:
            resp = await self._client.get("/api/v1/logs", params=params)
            resp.raise_for_status()
            events = resp.json()
        except Exception as exc:
            logger.error("[okta] Failed to fetch logs: %s", exc)
            return []

        # Filter to security-relevant events only
        alerts: List[NormalizedAlert] = []
        for event in events:
            event_type = event.get("eventType", "")

            if not any(event_type.startswith(p) for p in _SECURITY_EVENT_PREFIXES):
                continue

            alert = self._normalize_event(event)
            if alert:
                alerts.append(alert)

        logger.info("[okta] Fetched %d security alerts (from %d total events)", len(alerts), len(events))
        return alerts

    async def health_check(self) -> Dict[str, object]:
        """Check connectivity to Okta."""
        if not self._client:
            return {
                "status": "unhealthy",
                "message": "Not connected to Okta",
                "last_check": datetime.now(timezone.utc).isoformat(),
            }

        try:
            resp = await self._client.get("/api/v1/org")
            resp.raise_for_status()
            org_info = resp.json()
            return {
                "status": "healthy",
                "message": f"Connected to {org_info.get('companyName', 'Okta')}",
                "last_check": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {
                "status": "unhealthy",
                "message": f"Health check failed: {exc}",
                "last_check": datetime.now(timezone.utc).isoformat(),
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _normalize_event(self, event: Dict[str, Any]) -> Optional[NormalizedAlert]:
        """Convert a raw Okta System Log event into a NormalizedAlert."""
        try:
            event_type = event.get("eventType", "unknown")

            # Parse timestamp
            published = event.get("published", "")
            try:
                timestamp = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            # Severity
            okta_severity = event.get("severity", "INFO").upper()
            severity = _SEVERITY_MAP.get(okta_severity, SeverityLevel.MEDIUM)

            # Bump severity for failed outcomes
            outcome = event.get("outcome", {})
            if outcome.get("result") == "FAILURE":
                if severity.value < SeverityLevel.HIGH.value:
                    severity = SeverityLevel(severity.value + 1)

            # Actor (user)
            actor = event.get("actor", {})
            username = actor.get("alternateId") or actor.get("displayName")

            # Client info (IP, user agent)
            client = event.get("client", {})
            src_ip = client.get("ipAddress")

            # Geo context
            geo = client.get("geographicalContext", {})
            geo_city = geo.get("city", "")
            geo_country = geo.get("country", "")

            # Description
            display_msg = event.get("displayMessage") or event.get("eventType", "")
            description = f"{display_msg}"
            if geo_city and geo_country:
                description += f" (from {geo_city}, {geo_country})"

            # MITRE mapping
            mitre = _MITRE_MAP.get(event_type, {})
            tactics = mitre.get("tactics", [])
            techniques = mitre.get("techniques", [])

            # Tags
            tags = ["okta", "identity", event_type]
            if outcome.get("result") == "FAILURE":
                tags.append("failed")

            return NormalizedAlert(
                source=self.name,
                vendor=self.vendor,
                timestamp=timestamp,
                severity=severity,
                raw_content=json.dumps(event, default=str),
                rule_id=event_type,
                rule_description=description,
                src_ip=src_ip,
                dst_ip=None,
                username=username,
                hostname=None,
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                tags=tags,
            )
        except Exception as exc:
            logger.warning("[okta] Failed to normalize event: %s", exc)
            return None
