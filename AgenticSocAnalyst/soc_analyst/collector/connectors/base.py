"""
Abstract base class for all alert connectors.

Every connector (real or mock) inherits from ``BaseConnector`` and implements
the ``fetch_alerts`` coroutine plus the ``name`` / ``vendor`` properties.
"""

from __future__ import annotations

import abc
import logging
from datetime import datetime, timezone
from typing import Dict, List

from soc_analyst.collector.models import NormalizedAlert, SeverityLevel

__all__ = ["BaseConnector"]

logger = logging.getLogger(__name__)


class BaseConnector(abc.ABC):
    """Base interface that every alert source must implement.

    Lifecycle::

        connector = MyConnector()
        ok = await connector.connect()
        alerts = await connector.fetch_alerts(since=..., limit=100)
        await connector.disconnect()
    """

    # ------------------------------------------------------------------
    # Abstract properties
    # ------------------------------------------------------------------

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Short machine-readable identifier, e.g. ``'wazuh'``."""
        ...

    @property
    @abc.abstractmethod
    def vendor(self) -> str:
        """Human-readable vendor name, e.g. ``'Wazuh SIEM'``."""
        ...

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        """Establish any connections / authenticate.

        Returns ``True`` on success.  The default implementation is a no-op
        that always succeeds; override in connectors that need setup.
        """
        logger.info("[%s] connect() -- default no-op", self.name)
        return True

    async def disconnect(self) -> None:
        """Release resources.  Default is a no-op."""
        logger.info("[%s] disconnect() -- default no-op", self.name)

    # ------------------------------------------------------------------
    # Alert fetching (must be implemented)
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def fetch_alerts(
        self,
        since: datetime,
        limit: int = 100,
    ) -> List[NormalizedAlert]:
        """Retrieve new alerts created after *since*, up to *limit*.

        Subclasses must return a list of ``NormalizedAlert`` instances.
        """
        ...

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def health_check(self) -> Dict[str, object]:
        """Return a health-status dictionary.

        Keys:
            status  -- ``'healthy'`` | ``'degraded'`` | ``'unhealthy'``
            message -- human-readable note
            last_check -- ISO-8601 timestamp
        """
        return {
            "status": "healthy",
            "message": f"{self.name} connector is nominally healthy",
            "last_check": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_severity(
        vendor_level: int,
        vendor_name: str = "generic",
    ) -> SeverityLevel:
        """Map a vendor-specific numeric level to the canonical 1-5 scale.

        The default mapping covers the common Wazuh 0-15 range.
        Override in subclasses for vendor-specific scales.

        Args:
            vendor_level: Raw severity / priority from the source.
            vendor_name:  Vendor identifier (for logging only).

        Returns:
            A ``SeverityLevel`` enum member.
        """
        if vendor_level <= 3:
            return SeverityLevel.INFO
        if vendor_level <= 6:
            return SeverityLevel.LOW
        if vendor_level <= 9:
            return SeverityLevel.MEDIUM
        if vendor_level <= 12:
            return SeverityLevel.HIGH
        return SeverityLevel.CRITICAL

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.__class__.__name__} name={self.name!r}>"
