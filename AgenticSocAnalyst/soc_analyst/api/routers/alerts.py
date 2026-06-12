"""
Alert API endpoints for HallucinatingCrusaders.

Provides CRUD-like access to the normalised alert store:

* ``GET  /api/v1/alerts``              -- list with filtering / pagination
* ``GET  /api/v1/alerts/stats``        -- aggregated statistics
* ``GET  /api/v1/alerts/{alert_id}``   -- single alert
* ``PATCH /api/v1/alerts/{alert_id}/verdict`` -- set analyst verdict
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from soc_analyst.api.auth import get_current_user
from soc_analyst.collector.main import AlertCollector
from soc_analyst.collector.models import (
    InvestigationStatus,
    NormalizedAlert,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])

# ---------------------------------------------------------------------------
# Response / request schemas
# ---------------------------------------------------------------------------


class AlertResponse(BaseModel):
    """Single alert in API responses (mirrors NormalizedAlert)."""

    id: str
    source: str
    vendor: str
    timestamp: str
    received_at: str
    severity: int
    raw_content: Dict[str, Any]
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    investigation_status: str
    analyst_verdict: Optional[str] = None
    analyst_reasoning: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    @classmethod
    def from_alert(cls, alert: NormalizedAlert) -> "AlertResponse":
        """Build a response model from a domain alert."""
        return cls(
            id=alert.id,
            source=alert.source,
            vendor=alert.vendor,
            timestamp=alert.timestamp.isoformat(),
            received_at=alert.received_at.isoformat(),
            severity=alert.severity.value,
            raw_content=alert.raw_content,
            rule_id=alert.rule_id,
            rule_description=alert.rule_description,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            username=alert.username,
            hostname=alert.hostname,
            mitre_tactics=alert.mitre_tactics,
            mitre_techniques=alert.mitre_techniques,
            investigation_status=alert.investigation_status.value,
            analyst_verdict=alert.analyst_verdict,
            analyst_reasoning=alert.analyst_reasoning,
            tags=alert.tags,
        )


class AlertListResponse(BaseModel):
    """Paginated list of alerts."""

    total: int
    limit: int
    offset: int
    alerts: List[AlertResponse]


class VerdictRequest(BaseModel):
    """Body for ``PATCH .../verdict``."""

    verdict: str = Field(..., min_length=1, description="Analyst verdict string.")
    reasoning: Optional[str] = Field(None, description="Free-text rationale.")


class VerdictResponse(BaseModel):
    """Confirmation after updating a verdict."""

    alert_id: str
    verdict: str
    reasoning: Optional[str] = None
    investigation_status: str


class AlertStatsResponse(BaseModel):
    """Aggregated alert statistics."""

    total: int
    by_severity: Dict[str, int]
    by_source: Dict[str, int]
    by_status: Dict[str, int]
    by_mitre_tactic: Dict[str, int]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_collector(request: Request) -> AlertCollector:
    """Retrieve the AlertCollector from application state."""
    collector: AlertCollector = request.app.state.collector
    return collector


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=AlertListResponse,
    summary="List alerts",
    description="Retrieve a filtered, paginated list of normalised alerts.",
)
async def list_alerts(
    request: Request,
    source: Optional[str] = Query(None, description="Filter by connector source."),
    min_severity: Optional[int] = Query(
        None, ge=1, le=5, description="Minimum severity (inclusive)."
    ),
    max_severity: Optional[int] = Query(
        None, ge=1, le=5, description="Maximum severity (inclusive)."
    ),
    investigation_status: Optional[str] = Query(
        None,
        alias="status",
        description="Filter by investigation status.",
    ),
    sort_by: Optional[str] = Query(
        "timestamp",
        description="Field to sort by (timestamp | severity).",
    ),
    limit: int = Query(50, ge=1, le=500, description="Page size."),
    offset: int = Query(0, ge=0, description="Number of alerts to skip."),
    _user: Dict[str, Any] = Depends(get_current_user),
) -> AlertListResponse:
    """Return alerts matching the supplied filters."""
    collector = _get_collector(request)

    # 1. Query matching alerts count
    total = collector.get_filtered_count(
        source=source,
        min_severity=min_severity,
        max_severity=max_severity,
        status=investigation_status
    )

    # 2. Query paginated list of alerts directly from database
    page = collector.get_all_alerts(
        limit=limit,
        offset=offset,
        source=source,
        min_severity=min_severity,
        max_severity=max_severity,
        status=investigation_status,
        sort_by=sort_by or "timestamp"
    )

    return AlertListResponse(
        total=total,
        limit=limit,
        offset=offset,
        alerts=[AlertResponse.from_alert(a) for a in page],
    )



@router.get(
    "/stats",
    response_model=AlertStatsResponse,
    summary="Alert statistics",
    description="Return aggregated alert counts grouped by severity, source, status, and MITRE tactic.",
)
async def alert_stats(
    request: Request,
    _user: Dict[str, Any] = Depends(get_current_user),
) -> AlertStatsResponse:
    """Return aggregated statistics over all stored alerts."""
    collector = _get_collector(request)
    alerts = collector.get_all_alerts()

    by_severity: Counter[str] = Counter()
    by_source: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    by_mitre_tactic: Counter[str] = Counter()

    for alert in alerts:
        by_severity[alert.severity.name] += 1
        by_source[alert.source] += 1
        by_status[alert.investigation_status.value] += 1
        for tactic in alert.mitre_tactics:
            by_mitre_tactic[tactic] += 1

    return AlertStatsResponse(
        total=len(alerts),
        by_severity=dict(by_severity),
        by_source=dict(by_source),
        by_status=dict(by_status),
        by_mitre_tactic=dict(by_mitre_tactic),
    )


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert by ID",
    description="Retrieve a single normalised alert by its unique identifier.",
    responses={404: {"description": "Alert not found."}},
)
async def get_alert(
    alert_id: str,
    request: Request,
    _user: Dict[str, Any] = Depends(get_current_user),
) -> AlertResponse:
    """Return one alert or 404."""
    collector = _get_collector(request)
    alert = collector.get_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    return AlertResponse.from_alert(alert)


@router.patch(
    "/{alert_id}/verdict",
    response_model=VerdictResponse,
    summary="Set analyst verdict",
    description="Update the analyst verdict and reasoning for an alert.",
    responses={404: {"description": "Alert not found."}},
)
async def update_verdict(
    alert_id: str,
    body: VerdictRequest,
    request: Request,
    _user: Dict[str, Any] = Depends(get_current_user),
) -> VerdictResponse:
    """Patch the verdict fields on a stored alert."""
    collector = _get_collector(request)
    existing = collector.get_alert_by_id(alert_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )

    updated = collector.update_alert(
        alert_id,
        analyst_verdict=body.verdict,
        analyst_reasoning=body.reasoning,
        investigation_status=InvestigationStatus.RESOLVED,
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update alert.",
        )

    logger.info(
        "Verdict set for alert %s: %s (by %s).",
        alert_id,
        body.verdict,
        _user.get("sub", "unknown"),
    )

    return VerdictResponse(
        alert_id=updated.id,
        verdict=updated.analyst_verdict or body.verdict,
        reasoning=updated.analyst_reasoning,
        investigation_status=updated.investigation_status.value,
    )


__all__ = ["router"]
