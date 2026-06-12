"""
Approval queue management for remediation actions.
Controls pending, approved, and rejected state flows and execution dispatch.
"""

from __future__ import annotations

import logging
import asyncio
from typing import List, Optional
from datetime import datetime, timezone

from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.responder.actions import execute_remediation_action

logger = logging.getLogger(__name__)

def queue_response_action(
    investigation_id: str,
    alert_id: str,
    action_type: str,
    target: str,
    reason: str,
    requires_approval: bool = True
) -> str:
    """Creates a new response action in the database queue."""
    pg = PostgresStore()
    
    # Check if this exact action was already queued for this alert
    # to avoid duplication.
    with pg.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id FROM response_actions
                WHERE alert_id = %s AND action_type = %s AND target = %s
                LIMIT 1;
            """, (alert_id, action_type, target))
            row = cur.fetchone()
            if row:
                logger.info("Action %s already exists for target %s on alert %s. Skipping duplicate.", action_type, target, alert_id)
                return row[0]
                
    action = {
        "investigation_id": investigation_id,
        "alert_id": alert_id,
        "action_type": action_type,
        "target": target,
        "reason": reason,
        "requires_approval": requires_approval,
        "approval_status": "pending" if requires_approval else "auto_approved",
        "executed": False
    }
    
    action_id = pg.save_response_action(action)
    logger.info("Queued response action %s (type=%s, target=%s, requires_approval=%s)", action_id, action_type, target, requires_approval)
    return action_id


def list_pending_actions() -> List[dict]:
    """List all actions awaiting analyst approval."""
    return PostgresStore().get_pending_response_actions()


async def approve_and_trigger(action_id: str, approved_by: str, notes: Optional[str] = None) -> dict:
    """Approve a pending action and immediately trigger its execution."""
    pg = PostgresStore()
    action = pg.get_response_action_by_id(action_id)
    if not action:
        raise ValueError(f"Response action with ID {action_id} not found")
        
    if action["approval_status"] != "pending":
        raise ValueError(f"Action {action_id} cannot be approved (current status: {action['approval_status']})")
        
    logger.info("Approving response action %s by %s", action_id, approved_by)
    
    # Update DB state to approved
    pg.update_response_action(
        action_id,
        approval_status="approved",
        approved_by=approved_by,
        approval_notes=notes
    )
    
    # Trigger execution synchronously (awaited)
    return await execute_action(action_id)


def reject_and_update(action_id: str, rejected_by: str, notes: Optional[str] = None) -> dict:
    """Reject a pending response action."""
    pg = PostgresStore()
    action = pg.get_response_action_by_id(action_id)
    if not action:
        raise ValueError(f"Response action with ID {action_id} not found")
        
    if action["approval_status"] != "pending":
        raise ValueError(f"Action {action_id} cannot be rejected (current status: {action['approval_status']})")
        
    logger.info("Rejecting response action %s by %s", action_id, rejected_by)
    
    updated = pg.update_response_action(
        action_id,
        approval_status="rejected",
        approved_by=rejected_by,
        approval_notes=notes
    )
    return updated


async def execute_action(action_id: str) -> dict:
    """Executes the specific response action and records execution result in DB."""
    pg = PostgresStore()
    action = pg.get_response_action_by_id(action_id)
    if not action:
        raise ValueError(f"Response action with ID {action_id} not found")
        
    logger.info("Dispatching execution for response action %s (type=%s)", action_id, action["action_type"])
    
    # Call executor
    exec_res = await execute_remediation_action(
        action_type=action["action_type"],
        target=action["target"],
        alert_id=action["alert_id"]
    )
    
    # Update DB based on executor result
    if exec_res.get("status") == "success":
        updated = pg.update_response_action(
            action_id,
            executed=True,
            executed_at=datetime.now(timezone.utc),
            execution_result=exec_res.get("result", {}),
            error_message=None
        )
    else:
        updated = pg.update_response_action(
            action_id,
            executed=False,
            execution_result={},
            error_message=exec_res.get("error", "Unknown execution error")
        )
        
    return updated
