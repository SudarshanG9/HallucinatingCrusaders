"""
FastAPI Router for Automated Response actions, HITL approval queue, and watchlists.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from soc_analyst.api.auth import get_current_user
from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.responder.approval_queue import (
    list_pending_actions,
    approve_and_trigger,
    reject_and_update,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/response", tags=["Response"])


# Request schemas
class ApprovalRequest(BaseModel):
    notes: Optional[str] = Field(None, description="Optional notes from the analyst approving/rejecting the action")


class WatchlistAddRequest(BaseModel):
    value: str = Field(..., description="The value to watchlist (e.g., IP address, username)")
    watch_type: str = Field("ip", description="Type of indicator: 'ip', 'username', 'domain'")
    reason: str = Field(..., description="Reason for watchlisting this target")


# Endpoints
@router.get("/pending", response_model=List[dict])
async def get_pending_actions(current_user: str = Depends(get_current_user)):
    """Retrieve all pending response actions awaiting manual approval."""
    try:
        return list_pending_actions()
    except Exception as exc:
        logger.error("Failed to list pending actions: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch pending actions: {exc}"
        )


@router.post("/approve/{action_id}", response_model=dict)
async def approve_response_action(
    action_id: str,
    req: Optional[ApprovalRequest] = None,
    current_user: dict = Depends(get_current_user)
):
    """Approve a pending action and trigger its execution."""
    notes = req.notes if req else None
    username = current_user.get("sub", "unknown") if isinstance(current_user, dict) else str(current_user)
    try:
        return await approve_and_trigger(action_id, approved_by=username, notes=notes)
    except ValueError as val_err:
        logger.warning("Invalid approval request: %s", val_err)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.error("Failed to approve action %s: %s", action_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute action approval: {exc}"
        )


@router.post("/reject/{action_id}", response_model=dict)
async def reject_response_action(
    action_id: str,
    req: Optional[ApprovalRequest] = None,
    current_user: dict = Depends(get_current_user)
):
    """Reject a pending action."""
    notes = req.notes if req else None
    username = current_user.get("sub", "unknown") if isinstance(current_user, dict) else str(current_user)
    try:
        return reject_and_update(action_id, rejected_by=username, notes=notes)
    except ValueError as val_err:
        logger.warning("Invalid rejection request: %s", val_err)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.error("Failed to reject action %s: %s", action_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reject action: {exc}"
        )


@router.get("/audit", response_model=List[dict])
async def get_response_audit(current_user: str = Depends(get_current_user)):
    """Retrieve full audit log history of all response actions."""
    try:
        return PostgresStore().get_response_actions_audit()
    except Exception as exc:
        logger.error("Failed to fetch response actions audit: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve response actions audit log: {exc}"
        )


@router.get("/watchlist", response_model=List[dict])
async def get_current_watchlist(current_user: str = Depends(get_current_user)):
    """Retrieve list of all watchlisted items."""
    try:
        return PostgresStore().get_watchlist()
    except Exception as exc:
        logger.error("Failed to fetch watchlist: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve watchlist: {exc}"
        )


@router.post("/watchlist", status_code=status.HTTP_201_CREATED)
async def add_to_watchlist(
    req: WatchlistAddRequest,
    current_user: str = Depends(get_current_user)
):
    """Add a new item to the local database watchlist."""
    try:
        PostgresStore().add_to_watchlist_db(req.value, req.watch_type, req.reason)
        return {"status": "success", "message": f"Added '{req.value}' to watchlist."}
    except Exception as exc:
        logger.error("Failed to add to watchlist: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add item to watchlist: {exc}"
        )
