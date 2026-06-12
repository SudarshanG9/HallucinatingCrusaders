"""
Wazuh connector -- pulls real alerts from the Wazuh Indexer (OpenSearch).

Authentication flow:
    1. Obtain a JWT from the Wazuh Manager REST API.
    2. (Optional) Verify the Indexer is reachable via cluster health.
    3. Query ``wazuh-alerts-4.x-*`` using OpenSearch Query DSL.

HTTP calls use ``requests`` (sync) wrapped in ``asyncio.to_thread`` so the
event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
import urllib3

from soc_analyst.collector.connectors.base import BaseConnector
from soc_analyst.collector.models import NormalizedAlert, SeverityLevel
from soc_analyst.config import settings

__all__ = ["WazuhConnector"]

# Silence self-signed-cert warnings globally for this module
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class WazuhConnector(BaseConnector):
    """Connector that ingests alerts from the Wazuh SIEM stack.

    Alerts are fetched from the Wazuh *Indexer* (an OpenSearch instance),
    which stores the full enriched documents.  A JWT token from the Wazuh
    Manager API is obtained for management calls, while the Indexer uses
    HTTP basic auth.
    """

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "wazuh"

    @property
    def vendor(self) -> str:
        return "Wazuh SIEM"

    # ------------------------------------------------------------------
    # Init
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        # Wazuh Manager API
        self._api_url: str = settings.wazuh.api_url.rstrip("/")
        self._api_user: str = settings.wazuh.api_user
        self._api_pass: str = settings.wazuh.api_pass
        self._verify_ssl: bool = settings.wazuh.verify_ssl
        self._jwt_token: Optional[str] = None

        # Indexer (OpenSearch)
        self._indexer_url: str = settings.indexer.url.rstrip("/")
        self._indexer_auth = (settings.indexer.user, settings.indexer.password)
        self._indexer_verify: bool = settings.indexer.verify_ssl
        self._alert_index: str = settings.indexer.alert_index

        # Shared requests session for the indexer
        self._session: Optional[requests.Session] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        """Authenticate to the Wazuh Manager and verify indexer health."""
        try:
            # 1. Get JWT from the Manager API
            jwt_ok = await self._authenticate()
            if not jwt_ok:
                logger.warning("[wazuh] JWT authentication failed -- "
                               "continuing with indexer-only mode")

            # 2. Prepare an indexer session
            self._session = requests.Session()
            self._session.verify = self._indexer_verify
            self._session.auth = self._indexer_auth
            self._session.headers.update({"Content-Type": "application/json"})

            # 3. Quick indexer health check
            health = await self._indexer_health()
            if health.get("status") in ("green", "yellow"):
                logger.info(
                    "[wazuh] Connected -- cluster=%s status=%s",
                    health.get("cluster_name", "?"),
                    health.get("status"),
                )
                return True

            logger.error("[wazuh] Indexer cluster status: %s", health.get("status"))
            return False

        except Exception:
            logger.exception("[wazuh] connect() failed")
            return False

    async def disconnect(self) -> None:
        """Close the requests session."""
        if self._session is not None:
            self._session.close()
            self._session = None
        self._jwt_token = None
        logger.info("[wazuh] Disconnected")

    # ------------------------------------------------------------------
    # Alert fetching
    # ------------------------------------------------------------------

    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
    ) -> List[NormalizedAlert]:
        """Query the Wazuh Indexer for alerts newer than *since*.

        Uses the same OpenSearch Query DSL pattern as
        ``tests/indexer_query.py``.
        """
        if self._session is None:
            logger.error("[wazuh] Not connected -- call connect() first")
            return []

        query = self._build_search_query(since, limit)
        raw_hits = await self._search(query)

        alerts: List[NormalizedAlert] = []
        for hit in raw_hits:
            try:
                alert = self._normalize(hit)
                alerts.append(alert)
            except Exception:
                logger.exception("[wazuh] Failed to normalize alert: %s",
                                 json.dumps(hit, default=str)[:300])
        logger.info("[wazuh] Fetched %d alerts (since %s)", len(alerts), since.isoformat())
        return alerts

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self) -> Dict[str, object]:
        """Return indexer cluster health as a status dict."""
        try:
            health = await self._indexer_health()
            status_map = {"green": "healthy", "yellow": "degraded", "red": "unhealthy"}
            cluster_status = health.get("status", "unknown")
            return {
                "status": status_map.get(cluster_status, "unhealthy"),
                "message": (
                    f"Cluster {health.get('cluster_name', '?')} is {cluster_status}, "
                    f"{health.get('active_shards', '?')} active shards"
                ),
                "last_check": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {
                "status": "unhealthy",
                "message": f"Health check failed: {exc}",
                "last_check": datetime.now(timezone.utc).isoformat(),
            }

    # ------------------------------------------------------------------
    # Private -- JWT authentication
    # ------------------------------------------------------------------

    async def _authenticate(self) -> bool:
        """Obtain a JWT token from the Wazuh Manager API."""
        def _do_auth() -> Optional[str]:
            url = f"{self._api_url}/security/user/authenticate"
            resp = requests.post(
                url,
                auth=(self._api_user, self._api_pass),
                verify=self._verify_ssl,
                timeout=15,
            )
            if resp.status_code != 200:
                logger.error("[wazuh] Auth failed: HTTP %d -- %s",
                             resp.status_code, resp.text[:200])
                return None
            data = resp.json()
            token = data.get("data", {}).get("token")
            return token

        token = await asyncio.to_thread(_do_auth)
        if token:
            self._jwt_token = token
            logger.info("[wazuh] JWT token obtained successfully")
            return True
        return False

    # ------------------------------------------------------------------
    # Private -- Indexer helpers
    # ------------------------------------------------------------------

    async def _indexer_health(self) -> Dict[str, Any]:
        """GET /_cluster/health from OpenSearch."""
        def _call() -> Dict[str, Any]:
            if self._session is None:
                return {}
            resp = self._session.get(
                f"{self._indexer_url}/_cluster/health",
                timeout=10,
            )
            if resp.status_code != 200:
                logger.error("[wazuh] Indexer health HTTP %d", resp.status_code)
                return {}
            return resp.json()

        return await asyncio.to_thread(_call)

    def _build_search_query(self, since: datetime, limit: int) -> Dict[str, Any]:
        """Build an OpenSearch Query DSL body."""
        return {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": since.isoformat(),
                                    "format": "strict_date_optional_time",
                                }
                            }
                        }
                    ]
                }
            },
        }

    async def _search(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute a search against the alert index."""
        def _call() -> List[Dict[str, Any]]:
            if self._session is None:
                return []
            resp = self._session.post(
                f"{self._indexer_url}/{self._alert_index}/_search",
                json=query,
                timeout=30,
            )
            if resp.status_code != 200:
                logger.error("[wazuh] Search HTTP %d: %s",
                             resp.status_code, resp.text[:300])
                return []
            hits = resp.json().get("hits", {}).get("hits", [])
            return [hit.get("_source", {}) for hit in hits]

        return await asyncio.to_thread(_call)

    # ------------------------------------------------------------------
    # Private -- normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _map_wazuh_severity(level: int) -> SeverityLevel:
        """Map Wazuh rule level (0-15) to the canonical SeverityLevel.

        Ranges:
            1-3   -> INFORMATIONAL
            4-6   -> LOW
            7-9   -> MEDIUM
            10-12 -> HIGH
            13-15 -> CRITICAL
        """
        if level <= 3:
            return SeverityLevel.INFO
        if level <= 6:
            return SeverityLevel.LOW
        if level <= 9:
            return SeverityLevel.MEDIUM
        if level <= 12:
            return SeverityLevel.HIGH
        return SeverityLevel.CRITICAL

    def _normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """Convert a raw Wazuh/OpenSearch document into a NormalizedAlert."""
        rule: Dict[str, Any] = raw.get("rule", {})
        agent: Dict[str, Any] = raw.get("agent", {})
        data: Dict[str, Any] = raw.get("data", {})
        mitre: Dict[str, Any] = rule.get("mitre", {})
        win_data: Dict[str, Any] = data.get("win", {}).get("eventdata", {})

        # Extract network context
        src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or win_data.get("ipAddress")
            or None
        )
        dst_ip = data.get("dstip") or data.get("dst_ip") or None

        # Extract identity context
        username = (
            win_data.get("targetUserName")
            or data.get("srcuser")
            or data.get("dstuser")
            or None
        )
        hostname = agent.get("name") or None

        # Timestamp
        ts_raw = raw.get("timestamp")
        if isinstance(ts_raw, str):
            # Handle various ISO formats Wazuh may emit
            try:
                timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        return NormalizedAlert(
            source=self.name,
            vendor=self.vendor,
            timestamp=timestamp,
            severity=self._map_wazuh_severity(int(rule.get("level", 0))),
            raw_content=json.dumps(raw, default=str),
            rule_id=str(rule.get("id", "")) or None,
            rule_description=rule.get("description", "Unknown Wazuh rule"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            username=username,
            hostname=hostname,
            mitre_tactics=mitre.get("tactic", []),
            mitre_techniques=mitre.get("id", []),
            tags=rule.get("groups", []),
        )
