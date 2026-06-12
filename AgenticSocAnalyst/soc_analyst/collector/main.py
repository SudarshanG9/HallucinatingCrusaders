"""
Async polling orchestrator for the alert collector.

``AlertCollector`` manages the lifecycle of all registered connectors, polls
them on a configurable interval, and accumulates the results in an in-memory
store with optional PostgreSQL persistence.

It also retains the query helpers used by the API layer (``ingest``,
``update_alert``, ``get_all_alerts``, etc.) so existing code paths continue
to work.

Usage (standalone)::

    python -m soc_analyst.collector.main

Usage (programmatic)::

    collector = AlertCollector()
    collector.register(WazuhConnector())
    collector.register(MockGuardDutyConnector())
    await collector.start()       # begins polling in background tasks
    ...
    await collector.stop()        # graceful shutdown
"""

from __future__ import annotations

import asyncio
import logging
import signal
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from soc_analyst.collector.connectors.base import BaseConnector
from soc_analyst.collector.models import AlertBatch, NormalizedAlert
from soc_analyst.config import settings

__all__ = ["AlertCollector", "build_default_collector"]

logger = logging.getLogger(__name__)


class AlertCollector:
    """Central orchestrator that polls multiple connectors concurrently.

    Also acts as the single in-memory alert store that the API layer
    queries.  Thread-safe via a ``threading.Lock`` for sync callers and
    an ``asyncio.Lock`` for async callers.
    """

    # Singleton support (preserves compatibility with API layer)
    _instance: Optional["AlertCollector"] = None
    _singleton_lock: threading.Lock = threading.Lock()

    def __new__(cls) -> "AlertCollector":
        """Ensure only one instance exists (singleton pattern)."""
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialised = False
            return cls._instance

    def __init__(self) -> None:
        if self._initialised:
            return

        self._poll_interval: int = settings.collector.poll_interval_seconds
        self._batch_size: int = settings.collector.batch_size

        # Connector registry
        self.connectors: Dict[str, BaseConnector] = {}

        # In-memory alert store  (dict keeps O(1) lookup by id)
        self._alerts: Dict[str, NormalizedAlert] = {}
        self._async_lock: asyncio.Lock = asyncio.Lock()

        # Load from PostgreSQL
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            alerts = pg.get_alerts(limit=500, offset=0)
            for alert in alerts:
                self._alerts[alert.id] = alert
            logger.info("AlertCollector loaded %d alerts from PostgreSQL on startup.", len(alerts))
        except Exception as exc:
            logger.warning("Could not load alerts from PostgreSQL on startup: %s", exc)

        # Background polling tasks
        self._tasks: Dict[str, asyncio.Task] = {}
        self._running: bool = False

        # Track per-connector last-fetch watermark
        self._watermarks: Dict[str, datetime] = {}

        # Background triage queue and task
        self._triage_queue: asyncio.Queue[NormalizedAlert] = asyncio.Queue()
        self._triage_task: Optional[asyncio.Task] = None
        self.pipeline: Optional[object] = None

        self._initialised = True
        logger.info("AlertCollector initialised")

    # ------------------------------------------------------------------
    # Connector registration
    # ------------------------------------------------------------------

    def register(self, connector: BaseConnector) -> None:
        """Register a connector to be managed by this collector.

        Args:
            connector: An instance of a class inheriting ``BaseConnector``.

        Raises:
            ValueError: If a connector with the same name is already registered.
        """
        if connector.name in self.connectors:
            raise ValueError(
                f"Connector '{connector.name}' is already registered"
            )
        self.connectors[connector.name] = connector
        logger.info("Registered connector: %s (%s)", connector.name, connector.vendor)

    def unregister(self, name: str) -> None:
        """Remove a connector by name.  Does not stop a running poll task."""
        if name in self.connectors:
            del self.connectors[name]
            logger.info("Unregistered connector: %s", name)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Connect all connectors and begin polling in the background."""
        if self._running:
            logger.warning("AlertCollector is already running")
            return

        self._running = True
        logger.info(
            "Starting AlertCollector -- %d connector(s), poll every %ds",
            len(self.connectors),
            self._poll_interval,
        )

        # Initialize AnalystPipeline lazily to avoid circular imports
        if self.pipeline is None:
            try:
                from soc_analyst.agents.analyst.pipeline import AnalystPipeline
                self.pipeline = AnalystPipeline()
                logger.info("AnalystPipeline initialized within AlertCollector")
            except Exception:
                logger.exception("Failed to initialize AnalystPipeline in AlertCollector")

        # Launch auto-triage loop task
        self._triage_task = asyncio.create_task(
            self._auto_triage_loop(),
            name="auto-triage"
        )

        for name, connector in self.connectors.items():
            try:
                ok = await connector.connect()
                if ok:
                    logger.info("[%s] Connection established", name)
                else:
                    logger.warning("[%s] connect() returned False", name)
            except Exception:
                logger.exception("[%s] connect() raised an exception", name)

            # Initialize watermark: start looking back 1 hour
            self._watermarks.setdefault(
                name, datetime.now(timezone.utc) - timedelta(hours=1)
            )

            # Launch a background polling task per connector
            task = asyncio.create_task(
                self._poll_loop(name, connector),
                name=f"poll-{name}",
            )
            self._tasks[name] = task

    async def stop(self) -> None:
        """Gracefully stop all polling tasks and disconnect connectors."""
        if not self._running:
            return

        self._running = False
        logger.info("Stopping AlertCollector ...")

        # Cancel triage task
        if self._triage_task is not None:
            self._triage_task.cancel()
            try:
                await self._triage_task
            except asyncio.CancelledError:
                pass
            self._triage_task = None

        # Cancel all tasks
        for name, task in self._tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                logger.debug("Poll task '%s' cancelled", name)

        self._tasks.clear()

        # Disconnect all connectors
        for name, connector in self.connectors.items():
            try:
                await connector.disconnect()
            except Exception:
                logger.exception("[%s] Error during disconnect", name)

        logger.info("AlertCollector stopped")

    @property
    def is_running(self) -> bool:
        """Return ``True`` if the collector is actively polling."""
        return self._running

    # ------------------------------------------------------------------
    # Ingest (manual / API layer)
    # ------------------------------------------------------------------

    def ingest(self, alert: NormalizedAlert) -> None:
        """Store a normalised alert directly (used by the API layer).

        Args:
            alert: The alert to persist.
        """
        # Save to Postgres
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            pg.save_alert(alert)
        except Exception as exc:
            logger.error("Failed to save ingested alert %s to Postgres: %s", alert.id, exc)

        self._alerts[alert.id] = alert
        logger.debug("Ingested alert %s from %s", alert.id, alert.source)
        # Push to triage queue for background analysis
        self._triage_queue.put_nowait(alert)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_all_alerts(
        self, 
        limit: int = 100, 
        offset: int = 0,
        source: Optional[str] = None,
        min_severity: Optional[int] = None,
        max_severity: Optional[int] = None,
        status: Optional[str] = None,
        sort_by: str = "timestamp"
    ) -> List[NormalizedAlert]:
        """Return every alert in the store from database, matching filters."""
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            return pg.get_alerts(
                limit=limit,
                offset=offset,
                source=source,
                min_severity=min_severity,
                max_severity=max_severity,
                status=status,
                sort_by=sort_by
            )
        except Exception as exc:
            logger.error("Failed to query alerts from Postgres: %s. Falling back to memory cache.", exc)
            alerts = list(self._alerts.values())
            if source:
                alerts = [a for a in alerts if a.source == source]
            if status:
                alerts = [a for a in alerts if a.investigation_status.value == status]
            if min_severity is not None:
                alerts = [a for a in alerts if a.severity.value >= min_severity]
            if max_severity is not None:
                alerts = [a for a in alerts if a.severity.value <= max_severity]

            if sort_by == "severity":
                alerts.sort(key=lambda a: a.severity.value, reverse=True)
            else:
                alerts.sort(key=lambda a: a.timestamp, reverse=True)

            return alerts[offset : offset + limit]


    def get_alerts_by_source(self, source: str, limit: int = 100, offset: int = 0) -> List[NormalizedAlert]:
        """Return alerts originating from a specific connector *source*."""
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            return pg.get_alerts(source=source, limit=limit, offset=offset)
        except Exception as exc:
            logger.error("Failed to query alerts by source from Postgres: %s. Falling back to memory cache.", exc)
            return [a for a in self._alerts.values() if a.source == source][offset : offset + limit]

    def get_alert_by_id(self, alert_id: str) -> Optional[NormalizedAlert]:
        """Look up a single alert by its UUID."""
        if alert_id in self._alerts:
            return self._alerts[alert_id]
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            alert = pg.get_alert_by_id(alert_id)
            if alert:
                self._alerts[alert_id] = alert
            return alert
        except Exception:
            return None

    def update_alert(
        self, alert_id: str, **fields: object
    ) -> Optional[NormalizedAlert]:
        """Patch mutable fields on an existing alert.

        Returns the updated alert or ``None`` if the id does not exist.
        """
        alert = self.get_alert_by_id(alert_id)
        if alert is None:
            return None
        data = alert.model_dump()
        data.update(fields)
        updated = NormalizedAlert(**data)
        self._alerts[alert_id] = updated

        # Save to Postgres
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            pg.save_alert(updated)
        except Exception as exc:
            logger.error("Failed to update alert %s in Postgres: %s", alert_id, exc)

        return updated

    def get_alert_counts(self) -> Dict[str, int]:
        """Return per-source alert counts."""
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            counts: Dict[str, int] = {}
            for source in settings.collector.enabled_connectors:
                counts[source] = pg.get_alerts_count(source=source)
            return counts
        except Exception:
            counts = {}
            for alert in self._alerts.values():
                counts[alert.source] = counts.get(alert.source, 0) + 1
            return counts

    @property
    def count(self) -> int:
        """Total number of alerts currently stored."""
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            return pg.get_alerts_count()
        except Exception:
            return len(self._alerts)

    def get_filtered_count(
        self,
        source: Optional[str] = None,
        min_severity: Optional[int] = None,
        max_severity: Optional[int] = None,
        status: Optional[str] = None
    ) -> int:
        """Return total count of alerts matching the filters."""
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            pg = PostgresStore()
            return pg.get_alerts_count(
                source=source,
                min_severity=min_severity,
                max_severity=max_severity,
                status=status
            )
        except Exception:
            # Fallback to cache filtering count
            alerts = list(self._alerts.values())
            if source:
                alerts = [a for a in alerts if a.source == source]
            if status:
                alerts = [a for a in alerts if a.investigation_status.value == status]
            if min_severity is not None:
                alerts = [a for a in alerts if a.severity.value >= min_severity]
            if max_severity is not None:
                alerts = [a for a in alerts if a.severity.value <= max_severity]
            return len(alerts)


    # ------------------------------------------------------------------
    # Private -- polling loop
    # ------------------------------------------------------------------

    async def _poll_loop(self, name: str, connector: BaseConnector) -> None:
        """Infinite polling loop for a single connector.

        Runs until ``self._running`` is set to ``False`` or the task is
        cancelled.
        """
        retry_delay = settings.collector.retry_delay_seconds
        max_retries = settings.collector.max_retries

        while self._running:
            retries = 0
            success = False

            while retries <= max_retries and not success:
                try:
                    since = self._watermarks.get(
                        name,
                        datetime.now(timezone.utc) - timedelta(hours=1),
                    )
                    new_alerts = await connector.fetch_alerts(
                        since=since,
                        limit=self._batch_size,
                    )

                    if new_alerts:
                        batch = AlertBatch(
                            alerts=new_alerts,
                            source=name,
                        )
                        await self._store_batch(batch)

                        # Advance the watermark to the newest alert timestamp
                        latest_ts = max(a.timestamp for a in new_alerts)
                        self._watermarks[name] = latest_ts

                        logger.info(
                            "[%s] Collected %d new alert(s) | total stored: %d",
                            name,
                            len(new_alerts),
                            len(self._alerts),
                        )
                    else:
                        logger.debug("[%s] No new alerts", name)

                    success = True

                except asyncio.CancelledError:
                    raise  # Let cancellation propagate
                except Exception:
                    retries += 1
                    logger.exception(
                        "[%s] Fetch failed (attempt %d/%d)",
                        name, retries, max_retries,
                    )
                    if retries <= max_retries:
                        await asyncio.sleep(retry_delay)

            # Wait for next poll cycle
            try:
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break

    async def _store_batch(self, batch: AlertBatch) -> None:
        """Persist a batch of alerts to the PostgreSQL database and memory cache.

        The async lock ensures safe writes when multiple connectors
        produce results concurrently.
        """
        async with self._async_lock:
            for alert in batch.alerts:
                # Save to Postgres
                try:
                    from soc_analyst.memory.postgres_store import PostgresStore
                    pg = PostgresStore()
                    pg.save_alert(alert)
                except Exception as exc:
                    logger.error("Failed to save batch alert %s to Postgres: %s", alert.id, exc)
                self._alerts[alert.id] = alert
                self._triage_queue.put_nowait(alert)

    async def _auto_triage_loop(self) -> None:
        """Background loop that processes new alerts from the queue through the AnalystPipeline."""
        logger.info("Auto-triage background loop started")
        while self._running:
            try:
                alert = await self._triage_queue.get()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error getting alert from triage queue")
                await asyncio.sleep(1)
                continue

            try:
                if self.pipeline is None:
                    logger.warning("Pipeline is not initialised, skipping triage for alert %s", alert.id)
                    continue

                logger.info("Auto-triaging alert %s (%s)", alert.id, alert.rule_description)

                # Update status to investigating
                from soc_analyst.collector.models import InvestigationStatus
                self.update_alert(alert.id, investigation_status=InvestigationStatus.INVESTIGATING)

                # Call pipeline to analyze alert
                verdict = await self.pipeline.analyze_alert(alert)

                # Determine new status based on verdict
                new_status = InvestigationStatus.RESOLVED
                if verdict.verdict in ("true_positive", "suspicious", "needs_investigation"):
                    new_status = InvestigationStatus.ESCALATED
                elif verdict.verdict == "false_positive":
                    new_status = InvestigationStatus.FALSE_POSITIVE

                # Check Auto-Resolution Policy
                auto_resolved = verdict.auto_resolved
                if verdict.verdict == "false_positive" or verdict.severity_assessment in ("low", "informational"):
                    auto_resolved = True
                    new_status = InvestigationStatus.RESOLVED

                tags = list(alert.tags)
                if auto_resolved:
                    tags.append("auto-resolved")

                self.update_alert(
                    alert.id,
                    analyst_verdict=verdict.verdict,
                    analyst_reasoning=verdict.reasoning,
                    investigation_status=new_status,
                    tags=tags,
                )

                logger.info(
                    "Auto-triage complete for alert %s | verdict=%s, status=%s, auto_resolved=%s",
                    alert.id, verdict.verdict, new_status.value, auto_resolved
                )

            except Exception:
                logger.exception("Error in auto-triage loop for alert %s", alert.id)
            finally:
                self._triage_queue.task_done()

    # ------------------------------------------------------------------
    # Status / introspection
    # ------------------------------------------------------------------

    async def status(self) -> Dict[str, object]:
        """Return a summary of collector state and connector health."""
        connector_health = {}
        for name, connector in self.connectors.items():
            try:
                connector_health[name] = await connector.health_check()
            except Exception as exc:
                connector_health[name] = {
                    "status": "unhealthy",
                    "message": str(exc),
                }

        return {
            "running": self._running,
            "total_alerts": len(self._alerts),
            "alert_counts_by_source": self.get_alert_counts(),
            "poll_interval_seconds": self._poll_interval,
            "connectors": connector_health,
            "watermarks": {
                k: v.isoformat() for k, v in self._watermarks.items()
            },
        }


# ---------------------------------------------------------------------------
# Convenience: build a collector with the default set of connectors
# ---------------------------------------------------------------------------

def build_default_collector() -> AlertCollector:
    """Instantiate an ``AlertCollector`` pre-loaded with all configured connectors.

    Which connectors are enabled is driven by
    ``settings.collector.enabled_connectors``.
    """
    from soc_analyst.collector.connectors.mock_defender import MockDefenderConnector
    from soc_analyst.collector.connectors.mock_guardduty import MockGuardDutyConnector
    from soc_analyst.collector.connectors.mock_okta import MockOktaConnector
    from soc_analyst.collector.connectors.okta import OktaConnector
    from soc_analyst.collector.connectors.wazuh import WazuhConnector

    _registry = {
        "wazuh": WazuhConnector,
        "mock_guardduty": MockGuardDutyConnector,
        "mock_okta": MockOktaConnector,
        "okta": OktaConnector,
        "mock_defender": MockDefenderConnector,
    }

    collector = AlertCollector()
    enabled = settings.collector.enabled_connectors

    for name in enabled:
        if name in collector.connectors:
            # Already registered (singleton may have been called before)
            continue
        cls = _registry.get(name)
        if cls is None:
            logger.warning("Unknown connector in config: %s -- skipping", name)
            continue
        collector.register(cls())

    return collector


# ---------------------------------------------------------------------------
# CLI entry point:  python -m soc_analyst.collector.main
# ---------------------------------------------------------------------------

async def _run() -> None:
    """Main async entry point for standalone operation."""
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.info("=" * 60)
    logger.info("  HallucinatingCrusaders -- Alert Collector")
    logger.info("  Poll interval: %ds", settings.collector.poll_interval_seconds)
    logger.info("=" * 60)

    collector = build_default_collector()
    await collector.start()

    # Keep running until Ctrl+C / SIGTERM
    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    # Register signal handlers (works on Unix; on Windows use KeyboardInterrupt)
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, _handle_signal)
            except NotImplementedError:
                # Windows does not support add_signal_handler
                pass

    try:
        await stop_event.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        await collector.stop()
        status = await collector.status()
        logger.info("Final status: %s", status)


def main() -> None:
    """Synchronous wrapper for the async entry point."""
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
