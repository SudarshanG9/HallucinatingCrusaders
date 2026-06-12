"""
Health / self-monitoring endpoint for HallucinatingCrusaders.

Reports the operational status of every subsystem the platform depends on:

* Wazuh Manager REST API
* Wazuh Indexer (OpenSearch)
* PostgreSQL
* ChromaDB
* Alert Collector

``GET /api/v1/health`` does **not** require authentication so that
external monitoring systems (Prometheus, UptimeRobot, etc.) can poll it
without credentials.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from soc_analyst.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/health", tags=["Health"])

# ---------------------------------------------------------------------------
# Module-level start time for uptime tracking
# ---------------------------------------------------------------------------

_start_time: datetime = datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class SubsystemStatus(BaseModel):
    """Health status of a single subsystem."""

    status: str = Field(
        ..., description="One of: healthy, degraded, down."
    )
    latency_ms: float = Field(
        0.0, description="Round-trip probe latency in milliseconds."
    )
    message: str = Field(
        "", description="Human-readable status detail."
    )


class HealthResponse(BaseModel):
    """Aggregate health report returned by ``GET /api/v1/health``."""

    status: str = Field(..., description="Overall platform status.")
    version: str
    uptime_seconds: float
    timestamp: str
    alert_count: int = 0
    subsystems: Dict[str, SubsystemStatus]


# ---------------------------------------------------------------------------
# Probe helpers (each returns a SubsystemStatus)
# ---------------------------------------------------------------------------


def _probe_wazuh_api() -> SubsystemStatus:
    """Ping the Wazuh Manager REST API."""
    url = f"{settings.wazuh.api_url}/"
    try:
        t0 = time.monotonic()
        resp = requests.get(
            url,
            auth=(settings.wazuh.api_user, settings.wazuh.api_pass),
            verify=settings.wazuh.verify_ssl,
            timeout=5,
        )
        latency = (time.monotonic() - t0) * 1000
        if resp.status_code < 400:
            return SubsystemStatus(
                status="healthy", latency_ms=round(latency, 2), message="OK"
            )
        return SubsystemStatus(
            status="degraded",
            latency_ms=round(latency, 2),
            message=f"HTTP {resp.status_code}",
        )
    except requests.ConnectionError:
        return SubsystemStatus(
            status="down", latency_ms=0.0, message="Connection refused."
        )
    except requests.Timeout:
        return SubsystemStatus(
            status="down", latency_ms=5000.0, message="Request timed out."
        )
    except Exception as exc:  # noqa: BLE001
        return SubsystemStatus(
            status="down", latency_ms=0.0, message=str(exc)
        )


def _probe_indexer() -> SubsystemStatus:
    """Ping the Wazuh Indexer (OpenSearch) cluster health endpoint."""
    url = f"{settings.indexer.url}/_cluster/health"
    try:
        t0 = time.monotonic()
        resp = requests.get(
            url,
            auth=(settings.indexer.user, settings.indexer.password),
            verify=settings.indexer.verify_ssl,
            timeout=5,
        )
        latency = (time.monotonic() - t0) * 1000
        if resp.status_code < 400:
            data = resp.json()
            cluster_status = data.get("status", "unknown")
            if cluster_status == "green":
                sstatus = "healthy"
            elif cluster_status == "yellow":
                sstatus = "degraded"
            else:
                sstatus = "down"
            return SubsystemStatus(
                status=sstatus,
                latency_ms=round(latency, 2),
                message=f"Cluster: {cluster_status}",
            )
        return SubsystemStatus(
            status="degraded",
            latency_ms=round(latency, 2),
            message=f"HTTP {resp.status_code}",
        )
    except requests.ConnectionError:
        return SubsystemStatus(
            status="down", latency_ms=0.0, message="Connection refused."
        )
    except requests.Timeout:
        return SubsystemStatus(
            status="down", latency_ms=5000.0, message="Request timed out."
        )
    except Exception as exc:  # noqa: BLE001
        return SubsystemStatus(
            status="down", latency_ms=0.0, message=str(exc)
        )


def _probe_postgresql() -> SubsystemStatus:
    """Attempt a lightweight TCP connection to PostgreSQL."""
    import socket

    host = settings.postgres.host
    port = settings.postgres.port
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=3)
        latency = (time.monotonic() - t0) * 1000
        sock.close()
        return SubsystemStatus(
            status="healthy",
            latency_ms=round(latency, 2),
            message=f"TCP connect to {host}:{port} succeeded.",
        )
    except OSError as exc:
        return SubsystemStatus(
            status="down",
            latency_ms=0.0,
            message=f"Cannot reach {host}:{port} -- {exc}",
        )


def _probe_chromadb() -> SubsystemStatus:
    """Ping the ChromaDB HTTP API heartbeat."""
    url = f"http://{settings.chroma.host}:{settings.chroma.port}/api/v1/heartbeat"
    try:
        t0 = time.monotonic()
        resp = requests.get(url, timeout=3)
        latency = (time.monotonic() - t0) * 1000
        if resp.status_code < 400:
            return SubsystemStatus(
                status="healthy", latency_ms=round(latency, 2), message="OK"
            )
        return SubsystemStatus(
            status="degraded",
            latency_ms=round(latency, 2),
            message=f"HTTP {resp.status_code}",
        )
    except requests.ConnectionError:
        return SubsystemStatus(
            status="down", latency_ms=0.0, message="Connection refused."
        )
    except requests.Timeout:
        return SubsystemStatus(
            status="down", latency_ms=3000.0, message="Request timed out."
        )
    except Exception as exc:  # noqa: BLE001
        return SubsystemStatus(
            status="down", latency_ms=0.0, message=str(exc)
        )


def _probe_collector(request: Request) -> SubsystemStatus:
    """Check the in-process AlertCollector state."""
    try:
        collector = request.app.state.collector
        if collector.is_running:
            return SubsystemStatus(
                status="healthy",
                latency_ms=0.0,
                message=f"Running. {collector.count} alerts in store.",
            )
        return SubsystemStatus(
            status="degraded",
            latency_ms=0.0,
            message="Collector initialised but not running.",
        )
    except AttributeError:
        return SubsystemStatus(
            status="down",
            latency_ms=0.0,
            message="Collector not attached to app state.",
        )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def _overall_status(subsystems: Dict[str, SubsystemStatus]) -> str:
    """Derive an overall status from individual subsystem statuses.

    * ``healthy``  -- every subsystem is healthy.
    * ``degraded`` -- at least one subsystem is degraded (none down).
    * ``down``     -- at least one *critical* subsystem (postgresql,
      collector) is down.
    """
    statuses = {name: s.status for name, s in subsystems.items()}
    critical = {"postgresql", "collector"}

    if any(statuses.get(c) == "down" for c in critical):
        return "down"
    if any(v == "down" for v in statuses.values()):
        return "degraded"
    if any(v == "degraded" for v in statuses.values()):
        return "degraded"
    return "healthy"


@router.get(
    "",
    response_model=HealthResponse,
    summary="Platform health check",
    description=(
        "Probes every subsystem and returns an aggregate health report.  "
        "No authentication required."
    ),
)
async def health_check(request: Request) -> HealthResponse:
    """Aggregate health status for all subsystems."""
    subsystems: Dict[str, SubsystemStatus] = {
        "wazuh_api": _probe_wazuh_api(),
        "wazuh_indexer": _probe_indexer(),
        "postgresql": _probe_postgresql(),
        "chromadb": _probe_chromadb(),
        "collector": _probe_collector(request),
    }

    now = datetime.now(timezone.utc)
    uptime = (now - _start_time).total_seconds()

    alert_count = 0
    try:
        alert_count = request.app.state.collector.count
    except AttributeError:
        pass

    return HealthResponse(
        status=_overall_status(subsystems),
        version=settings.version,
        uptime_seconds=round(uptime, 2),
        timestamp=now.isoformat(),
        alert_count=alert_count,
        subsystems=subsystems,
    )


__all__ = ["router"]
