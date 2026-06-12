"""
Analysis API endpoints for HallucinatingCrusaders.

Provides manual and batch analysis triggers, pipeline metrics, and
dead-letter queue management:

* ``POST /api/v1/analysis/analyze/{alert_id}``  -- analyze single alert
* ``POST /api/v1/analysis/analyze/batch``        -- batch analyze
* ``GET  /api/v1/analysis/metrics``              -- pipeline metrics
* ``GET  /api/v1/analysis/dead-letters``         -- dead-letter queue
* ``DELETE /api/v1/analysis/dead-letters``       -- clear dead-letters
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from soc_analyst.api.auth import get_current_user
from soc_analyst.collector.main import AlertCollector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/analysis", tags=["Analysis"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class AnalyzeResponse(BaseModel):
    """Response from a single-alert analysis."""

    alert_id: str
    verdict: str
    severity_assessment: str
    reasoning: str
    recommended_actions: List[str] = Field(default_factory=list)
    mitre_mapping: List[str] = Field(default_factory=list)
    auto_resolved: bool = False


class BatchAnalyzeRequest(BaseModel):
    """Request body for batch analysis."""

    alert_ids: List[str] = Field(
        ..., min_length=1, max_length=100, description="Alert IDs to analyze."
    )
    concurrency: int = Field(
        default=5, ge=1, le=20, description="Max concurrent analyses."
    )


class BatchAnalyzeResponse(BaseModel):
    """Response from batch analysis."""

    total: int
    succeeded: int
    failed: int
    results: List[AnalyzeResponse]


class PipelineMetricsResponse(BaseModel):
    """Pipeline execution metrics."""

    analysis_count: int
    success_count: int
    failure_count: int
    injection_blocks: int
    avg_time_seconds: float
    total_time_seconds: float


class DeadLetterEntry(BaseModel):
    """Single dead-letter queue entry."""

    alert_id: str
    error: str
    timestamp: float


class DeadLetterResponse(BaseModel):
    """Dead-letter queue listing."""

    count: int
    entries: List[DeadLetterEntry]


class ClearDeadLetterResponse(BaseModel):
    """Confirmation after clearing dead-letter queue."""

    cleared: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_collector(request: Request) -> AlertCollector:
    """Retrieve the AlertCollector from application state."""
    return request.app.state.collector


def _get_pipeline(request: Request):
    """Retrieve the AnalystPipeline from application state."""
    pipeline = getattr(request.app.state, "pipeline", None)
    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analysis pipeline is not initialised.",
        )
    return pipeline


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/analyze/{alert_id}",
    response_model=AnalyzeResponse,
    summary="Analyze a single alert",
    description=(
        "Trigger the Dual-LLM analysis pipeline for a single alert. "
        "The alert must already exist in the collector store."
    ),
    responses={
        404: {"description": "Alert not found."},
        503: {"description": "Pipeline not initialised."},
    },
)
async def analyze_alert(
    alert_id: str,
    request: Request,
    _user: Dict[str, Any] = Depends(get_current_user),
) -> AnalyzeResponse:
    """Run the full Dual-LLM pipeline on a single alert."""
    collector = _get_collector(request)
    pipeline = _get_pipeline(request)

    alert = collector.get_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )

    logger.info("Manual analysis triggered for alert %s by %s",
                alert_id, _user.get("sub", "unknown"))

    verdict = await pipeline.analyze_alert(alert)

    # Update the alert in the collector store
    from soc_analyst.collector.models import InvestigationStatus

    new_status = InvestigationStatus.RESOLVED
    if verdict.verdict in ("true_positive", "suspicious", "needs_investigation"):
        new_status = InvestigationStatus.ESCALATED

    collector.update_alert(
        alert_id,
        analyst_verdict=verdict.verdict,
        analyst_reasoning=verdict.reasoning,
        investigation_status=new_status,
    )

    return AnalyzeResponse(
        alert_id=verdict.alert_id,
        verdict=verdict.verdict,
        severity_assessment=verdict.severity_assessment,
        reasoning=verdict.reasoning,
        recommended_actions=verdict.recommended_actions,
        mitre_mapping=verdict.mitre_mapping,
        auto_resolved=verdict.auto_resolved,
    )


@router.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    summary="Batch-analyze multiple alerts",
    description="Submit a list of alert IDs for parallel analysis.",
    responses={503: {"description": "Pipeline not initialised."}},
)
async def analyze_batch(
    body: BatchAnalyzeRequest,
    request: Request,
    _user: Dict[str, Any] = Depends(get_current_user),
) -> BatchAnalyzeResponse:
    """Run the pipeline on multiple alerts with bounded concurrency."""
    collector = _get_collector(request)
    pipeline = _get_pipeline(request)

    # Resolve alert IDs to NormalizedAlert objects
    alerts = []
    missing = []
    for aid in body.alert_ids:
        alert = collector.get_alert_by_id(aid)
        if alert is not None:
            alerts.append(alert)
        else:
            missing.append(aid)

    if missing:
        logger.warning("Batch analysis: %d alert(s) not found: %s",
                       len(missing), missing[:5])

    logger.info(
        "Batch analysis triggered for %d alerts (concurrency=%d) by %s",
        len(alerts), body.concurrency, _user.get("sub", "unknown"),
    )

    verdicts = await pipeline.analyze_batch(alerts, concurrency=body.concurrency)

    # Update each alert in the store
    from soc_analyst.collector.models import InvestigationStatus

    results = []
    succeeded = 0
    failed = 0
    for verdict in verdicts:
        new_status = InvestigationStatus.RESOLVED
        if verdict.verdict in ("true_positive", "suspicious", "needs_investigation"):
            new_status = InvestigationStatus.ESCALATED

        collector.update_alert(
            verdict.alert_id,
            analyst_verdict=verdict.verdict,
            analyst_reasoning=verdict.reasoning,
            investigation_status=new_status,
        )

        if verdict.verdict != "needs_investigation" or verdict.reasoning:
            succeeded += 1
        else:
            failed += 1

        results.append(AnalyzeResponse(
            alert_id=verdict.alert_id,
            verdict=verdict.verdict,
            severity_assessment=verdict.severity_assessment,
            reasoning=verdict.reasoning,
            recommended_actions=verdict.recommended_actions,
            mitre_mapping=verdict.mitre_mapping,
            auto_resolved=verdict.auto_resolved,
        ))

    return BatchAnalyzeResponse(
        total=len(body.alert_ids),
        succeeded=succeeded,
        failed=failed + len(missing),
        results=results,
    )


@router.get(
    "/metrics",
    response_model=PipelineMetricsResponse,
    summary="Pipeline metrics",
    description="Return operational counters for the analysis pipeline.",
)
async def get_metrics(
    request: Request,
) -> PipelineMetricsResponse:
    """Return pipeline metrics (no auth required -- for monitoring)."""
    pipeline = _get_pipeline(request)
    m = pipeline.get_metrics()
    return PipelineMetricsResponse(**m)


@router.get(
    "/dead-letters",
    response_model=DeadLetterResponse,
    summary="List dead-letter queue",
    description="Return all failed analysis entries awaiting manual review.",
)
async def list_dead_letters(
    request: Request,
    _user: Dict[str, Any] = Depends(get_current_user),
) -> DeadLetterResponse:
    """Return the dead-letter queue contents."""
    pipeline = _get_pipeline(request)
    entries = pipeline.get_dead_letters()
    return DeadLetterResponse(
        count=len(entries),
        entries=[DeadLetterEntry(**e) for e in entries],
    )


@router.delete(
    "/dead-letters",
    response_model=ClearDeadLetterResponse,
    summary="Clear dead-letter queue",
    description="Remove all entries from the dead-letter queue.",
)
async def clear_dead_letters(
    request: Request,
    _user: Dict[str, Any] = Depends(get_current_user),
) -> ClearDeadLetterResponse:
    """Flush the dead-letter queue."""
    pipeline = _get_pipeline(request)
    cleared = pipeline.clear_dead_letters()
    logger.info("Dead-letter queue cleared (%d entries) by %s",
                cleared, _user.get("sub", "unknown"))
    return ClearDeadLetterResponse(cleared=cleared)


__all__ = ["router"]
