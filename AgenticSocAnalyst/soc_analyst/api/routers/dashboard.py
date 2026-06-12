"""
FastAPI router for the SOC Dashboard pages and HTMX components.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from soc_analyst.api.auth import authenticate_user, create_access_token, get_current_user_cookie
from soc_analyst.collector.main import AlertCollector
from soc_analyst.collector.models import InvestigationStatus, NormalizedAlert
from soc_analyst.config import settings
from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.responder.approval_queue import (
    approve_and_trigger,
    list_pending_actions,
    reject_and_update,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Configure Jinja2 template folder absolute path
current_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
templates_dir = os.path.join(current_dir, "dashboard", "templates")
templates = Jinja2Templates(directory=templates_dir)

# Helper to retrieve collector
def _get_collector(request: Request) -> AlertCollector:
    return request.app.state.collector

# Helper to verify auth and handle redirect to login
async def get_user_or_redirect(request: Request) -> Optional[Dict[str, Any]]:
    try:
        return await get_current_user_cookie(request)
    except HTTPException:
        return None

# Add simple filters to Jinja2 context if needed
templates.env.globals.update(zip=zip)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the dashboard login page."""
    user = await get_user_or_redirect(request)
    if user:
        return RedirectResponse(url="/dashboard/alerts", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    """Authenticate credentials and set access_token cookie."""
    user = authenticate_user(username, password)
    if user is None:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid identifier or access cipher."},
        )

    # Issue token
    access_token = create_access_token(data={"sub": user})
    
    # Redirect to alerts
    redirect_response = RedirectResponse(url="/dashboard/alerts", status_code=status.HTTP_303_SEE_OTHER)
    # Set secure HttpOnly cookie
    redirect_response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # Set True in production (HTTPS)
        samesite="lax",
    )
    return redirect_response


@router.get("/logout")
async def logout(response: Response):
    """Clear access token cookie and redirect to login."""
    redirect_response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    redirect_response.delete_cookie("access_token")
    return redirect_response


@router.get("/dashboard/alerts", response_class=HTMLResponse)
async def dashboard_alerts(request: Request):
    """Render the alerts feed page."""
    user = await get_user_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    collector = _get_collector(request)
    alerts = collector.get_all_alerts(limit=50)

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "user": user,
            "alerts": alerts,
            "active_tab": "alerts",
        },
    )


@router.get("/dashboard/alerts/table", response_class=HTMLResponse)
async def dashboard_alerts_table(request: Request, source: Optional[str] = None, severity: Optional[int] = None):
    """Return the inner HTML table snippet for live HTMX polling."""
    user = await get_user_or_redirect(request)
    if not user:
        return HTMLResponse(content="Unauthorized", status_code=status.HTTP_401_UNAUTHORIZED)

    collector = _get_collector(request)
    alerts = collector.get_all_alerts(
        limit=50,
        source=source if source else None,
        min_severity=severity if severity else None,
        max_severity=severity if severity else None,
    )

    return templates.TemplateResponse(
        request=request,
        name="alerts_table.html",
        context={
            "alerts": alerts,
        },
    )


@router.get("/dashboard/investigations/{alert_id}", response_class=HTMLResponse)
async def dashboard_investigation(request: Request, alert_id: str):
    """Render details of a specific alert investigation."""
    user = await get_user_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    collector = _get_collector(request)
    alert = collector.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    pg = PostgresStore()
    investigation = pg.get_investigation_by_alert_id(alert_id)

    return templates.TemplateResponse(
        request=request,
        name="investigation.html",
        context={
            "user": user,
            "alert": alert,
            "investigation": investigation,
            "active_tab": "alerts",
        },
    )


@router.get("/dashboard/connectors", response_class=HTMLResponse)
async def dashboard_connectors(request: Request):
    """Render connectors configuration and status page."""
    user = await get_user_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    collector = _get_collector(request)
    if not hasattr(collector, "connector_modes"):
        collector.connector_modes = {
            "wazuh": "live",
            "mock_guardduty": "mock",
            "okta": "live",
            "mock_defender": "mock",
        }

    status_summary = await collector.status()
    connectors_health = status_summary.get("connectors", {})

    return templates.TemplateResponse(
        request=request,
        name="connectors.html",
        context={
            "user": user,
            "connector_modes": collector.connector_modes,
            "connectors_health": connectors_health,
            "active_tab": "connectors",
        },
    )


@router.post("/dashboard/connectors/toggle/{connector}", response_class=HTMLResponse)
async def toggle_connector(request: Request, connector: str):
    """HTMX endpoint to toggle connector mode between live and mock."""
    user = await get_user_or_redirect(request)
    if not user:
        return HTMLResponse(content="Unauthorized", status_code=status.HTTP_401_UNAUTHORIZED)

    collector = _get_collector(request)
    if not hasattr(collector, "connector_modes"):
        collector.connector_modes = {
            "wazuh": "live",
            "mock_guardduty": "mock",
            "okta": "live",
            "mock_defender": "mock",
        }

    current_mode = collector.connector_modes.get(connector, "mock")
    new_mode = "live" if current_mode == "mock" else "mock"
    collector.connector_modes[connector] = new_mode

    # Return the updated badge representing the state
    badge_class = "neon-badge-cyan" if new_mode == "live" else "neon-badge-purple"
    return HTMLResponse(
        content=f'<span class="neon-badge {badge_class}">{new_mode.upper()} MODE</span>'
    )


@router.get("/dashboard/response", response_class=HTMLResponse)
async def dashboard_response(request: Request):
    """Render the human-in-the-loop Response Center."""
    user = await get_user_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    pg = PostgresStore()
    pending = list_pending_actions()
    audit = pg.get_response_actions_audit()
    watchlist = pg.get_watchlist()

    return templates.TemplateResponse(
        request=request,
        name="response.html",
        context={
            "user": user,
            "pending_actions": pending,
            "audit_actions": audit,
            "watchlist": watchlist,
            "active_tab": "response",
        },
    )


@router.post("/dashboard/response/approve/{action_id}", response_class=HTMLResponse)
async def approve_action_htmx(request: Request, action_id: str):
    """HTMX endpoint to approve action execution."""
    user = await get_user_or_redirect(request)
    if not user:
        return HTMLResponse(content="Unauthorized", status_code=status.HTTP_401_UNAUTHORIZED)

    username = user.get("sub", "unknown")
    try:
        res = await approve_and_trigger(action_id, approved_by=username)
        # Return success label
        return HTMLResponse(
            content='<span class="text-green-glow font-bold"><i class="fas fa-check-circle mr-1"></i> Executed Successfully</span>'
        )
    except Exception as exc:
        return HTMLResponse(
            content=f'<span class="text-red-glow font-bold"><i class="fas fa-exclamation-triangle mr-1"></i> Failed: {exc}</span>'
        )


@router.post("/dashboard/response/reject/{action_id}", response_class=HTMLResponse)
async def reject_action_htmx(request: Request, action_id: str):
    """HTMX endpoint to reject a pending action."""
    user = await get_user_or_redirect(request)
    if not user:
        return HTMLResponse(content="Unauthorized", status_code=status.HTTP_401_UNAUTHORIZED)

    username = user.get("sub", "unknown")
    try:
        reject_and_update(action_id, rejected_by=username)
        return HTMLResponse(
            content='<span class="text-muted font-bold"><i class="fas fa-ban mr-1"></i> Rejected</span>'
        )
    except Exception as exc:
        return HTMLResponse(
            content=f'<span class="text-red-glow font-bold"><i class="fas fa-exclamation-triangle mr-1"></i> Error: {exc}</span>'
        )


@router.get("/dashboard/monitor", response_class=HTMLResponse)
async def dashboard_monitor(request: Request):
    """Render the system health monitor dashboard."""
    user = await get_user_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    collector = _get_collector(request)
    status_summary = await collector.status()
    connectors_health = status_summary.get("connectors", {})

    # Call health router endpoint or mock check for other databases
    pg_ok = True
    chroma_ok = True
    indexer_ok = True
    wazuh_ok = True

    try:
        pg = PostgresStore()
        with pg.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
    except Exception:
        pg_ok = False

    pipeline = getattr(request.app.state, "pipeline", None)
    dead_letter_count = 0
    if pipeline:
        dead_letter_count = len(pipeline.get_dead_letters())

    return templates.TemplateResponse(
        request=request,
        name="monitor.html",
        context={
            "user": user,
            "collector_running": status_summary.get("running", False),
            "connectors_health": connectors_health,
            "db_postgres": "healthy" if pg_ok else "unhealthy",
            "db_chromadb": "healthy" if chroma_ok else "unhealthy",
            "db_indexer": "healthy" if indexer_ok else "unhealthy",
            "dead_letter_count": dead_letter_count,
            "active_tab": "monitor",
        },
    )


@router.get("/dashboard/analytics", response_class=HTMLResponse)
async def dashboard_analytics(request: Request):
    """Render the dashboard analytics reports charts."""
    user = await get_user_or_redirect(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    collector = _get_collector(request)
    alerts = collector.get_all_alerts(limit=500)

    # Compute aggregation counts for Chart.js
    severity_counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    source_counts: Dict[str, int] = {}
    status_counts: Dict[str, int] = {}
    mitre_counts: Dict[str, int] = {}

    for alert in alerts:
        severity_name = alert.severity.name
        severity_counts[severity_name] = severity_counts.get(severity_name, 0) + 1

        source = alert.source
        source_counts[source] = source_counts.get(source, 0) + 1

        status_val = alert.investigation_status.value
        status_counts[status_val] = status_counts.get(status_val, 0) + 1

        for technique in alert.mitre_techniques:
            mitre_counts[technique] = mitre_counts.get(technique, 0) + 1

    pipeline = getattr(request.app.state, "pipeline", None)
    injection_blocks = 0
    if pipeline:
        metrics = pipeline.get_metrics()
        injection_blocks = metrics.get("injection_blocks", 0)

    return templates.TemplateResponse(
        request=request,
        name="analytics.html",
        context={
            "user": user,
            "severity_counts": severity_counts,
            "source_counts": source_counts,
            "status_counts": status_counts,
            "mitre_counts": dict(sorted(mitre_counts.items(), key=lambda item: item[1], reverse=True)[:8]),
            "injection_blocks": injection_blocks,
            "active_tab": "analytics",
        },
    )
