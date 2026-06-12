"""
Verification tests for Phase 10 -- Automated Response and HITL Approval Queue.
"""

import asyncio
import os
import sys
import uuid
import json
import logging
from datetime import datetime, timezone
from fastapi.testclient import TestClient

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_analyst.collector.models import NormalizedAlert, SeverityLevel, InvestigationStatus
from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.responder.approval_queue import (
    queue_response_action,
    list_pending_actions,
    approve_and_trigger,
    reject_and_update,
)
from soc_analyst.responder.actions import execute_remediation_action
from soc_analyst.agents.workflows.investigation_graph import InvestigationWorkflow
from soc_analyst.agents.analyst.pipeline import AnalystPipeline
from soc_analyst.agents.llm_router import LLMRouter, LLMConfig
from soc_analyst.agents.analyst.schemas import AnalystVerdict
from soc_analyst.api.main import app

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("test_phase10")


def make_test_alert(severity: SeverityLevel, rule_desc: str, username: str = "test_user", src_ip: str = "192.168.10.10", timestamp: datetime = None) -> NormalizedAlert:
    alert_id = str(uuid.uuid4())
    content = json.dumps({
        "id": alert_id,
        "rule": {
            "id": "5715",
            "level": 10 if severity == SeverityLevel.HIGH else 3,
            "description": rule_desc,
        },
        "agent": {"id": "001", "name": "TEST_HOST"},
        "data": {
            "win": {
                "eventdata": {
                    "targetUserName": username,
                    "ipAddress": src_ip,
                }
            }
        }
    })
    return NormalizedAlert(
        id=alert_id,
        source="wazuh",
        vendor="Wazuh SIEM",
        timestamp=timestamp or datetime.now(timezone.utc),
        severity=severity,
        raw_content=content,
        rule_id="5715",
        rule_description=rule_desc,
        src_ip=src_ip,
        username=username,
        hostname="TEST_HOST",
    )


async def test_approval_workflow_and_actions():
    logger.info("\n=== Running Approval Queue and Action Unit Tests ===")
    pg = PostgresStore()
    
    # 1. Setup a dummy investigation and alert
    alert = make_test_alert(SeverityLevel.HIGH, "Brute force test for responder")
    pg.save_alert(alert)
    
    inv_id = str(uuid.uuid4())
    # Save a dummy investigation record
    pg.save_investigation(
        inv_id=inv_id,
        trigger_alert_id=alert.id,
        classification="suspicious",
        severity="High",
        summary="Test investigation",
        attack_type="brute_force",
        mitre_tactics=[],
        mitre_techniques=[],
        related_alert_ids=[],
        status="in_progress",
        threat_intel={},
        network_intel={},
        endpoint_intel={},
        report_markdown="# Test Report",
        report_json={}
    )
    
    # 2. Queue actions
    logger.info("Queueing pending response actions...")
    act1_id = queue_response_action(
        investigation_id=inv_id,
        alert_id=alert.id,
        action_type="block_ip",
        target="1.2.3.4",
        reason="Malicious brute force IP",
        requires_approval=True
    )
    
    act2_id = queue_response_action(
        investigation_id=inv_id,
        alert_id=alert.id,
        action_type="disable_user",
        target="malicious_user",
        reason="Suspicious activity from user",
        requires_approval=True
    )
    
    # Auto-approval action
    logger.info("Queueing auto-approved response actions...")
    act3_id = queue_response_action(
        investigation_id=inv_id,
        alert_id=alert.id,
        action_type="create_ticket",
        target=alert.id,
        reason="Auto create ticket for incident",
        requires_approval=False
    )
    
    # Check that pending actions list contains them
    pending = list_pending_actions()
    pending_ids = [p["id"] for p in pending]
    assert act1_id in pending_ids, "Action 1 not found in pending queue"
    assert act2_id in pending_ids, "Action 2 not found in pending queue"
    # Action 3 should NOT be in pending because it's auto-approved
    assert act3_id not in pending_ids, "Auto-approved Action 3 found in pending queue"
    logger.info("Pending actions list verified: found %d pending actions", len(pending))
    
    # 3. Reject Action 2
    logger.info("Rejecting Action 2 (disable_user)...")
    reject_res = reject_and_update(act2_id, rejected_by="admin_analyst", notes="User confirmed legitimate")
    assert reject_res["approval_status"] == "rejected", "Failed to reject action"
    assert reject_res["approved_by"] == "admin_analyst", "Rejected author mismatch"
    assert reject_res["approval_notes"] == "User confirmed legitimate", "Rejection notes mismatch"
    
    # Check that it's no longer pending
    pending_after_reject = list_pending_actions()
    assert act2_id not in [p["id"] for p in pending_after_reject], "Rejected action still in pending queue"
    logger.info("Rejection verified successfully.")
    
    # 4. Approve Action 1
    logger.info("Approving Action 1 (block_ip)...")
    approve_res = await approve_and_trigger(act1_id, approved_by="admin_analyst", notes="Approved IP block")
    assert approve_res["approval_status"] == "approved", "Failed to approve action"
    assert approve_res["executed"] is True, "Action not marked as executed after approval"
    assert approve_res["execution_result"] is not None, "Execution result missing"
    assert approve_res["execution_result"]["simulation"] is True, "Expected simulation execution"
    logger.info("Approval and execution triggered verified successfully. Target IP: %s", approve_res["target"])


async def test_langgraph_integration():
    logger.info("\n=== Running LangGraph Responder Integration Tests ===")
    pg = PostgresStore()
    
    # Setup mock pipeline & workflow
    config = LLMConfig(provider="mock")
    llm = LLMRouter(config)
    pipeline = AnalystPipeline(llm=llm)
    workflow = InvestigationWorkflow(pipeline)

    # We mock the decision analyst output to return custom recommended actions
    original_analyze = pipeline._decision_analyst.analyze
    
    async def mock_analyze(facts, alert, enriched_context):
        return AnalystVerdict(
            alert_id=alert.id,
            verdict="true_positive",
            severity_assessment="high",
            reasoning="Mock analysis finding",
            recommended_actions=[
                "Block IP 198.51.100.42",
                "Disable user compromised_test_user",
                "Isolate endpoint endpoint-win-102",
                "Add 198.51.100.42 to watchlist",
                "Create ticket in Jira"
            ],
            mitre_mapping=[],
            auto_resolved=False
        )
        
    pipeline._decision_analyst.analyze = mock_analyze
    
    try:
        alert = make_test_alert(SeverityLevel.HIGH, "Ransomware simulation event for integration test")
        pg.save_alert(alert)
        
        logger.info("Running LangGraph workflow for alert %s...", alert.id)
        verdict = await workflow.run(alert)
        logger.info("Workflow completed. Verdict verdict: %s", verdict.verdict)
        
        # Verify recommended actions were parsed and stored in response_actions table
        with pg.get_conn() as conn:
            with conn.cursor() as cur:
                # Retrieve response actions associated with this alert
                cur.execute("""
                    SELECT action_type, target, approval_status, executed
                    FROM response_actions
                    WHERE alert_id = %s;
                """, (alert.id,))
                rows = cur.fetchall()
                
        logger.info("Retrieved %d response actions from DB for integration alert", len(rows))
        assert len(rows) >= 5, "Expected at least 5 response actions in DB"
        
        # Build mappings
        actions_map = {r[0]: (r[1], r[2], r[3]) for r in rows}
        
        # Check specific actions
        assert "block_ip" in actions_map, "block_ip action missing"
        assert actions_map["block_ip"][0] == "198.51.100.42", "Block IP target mismatch"
        assert actions_map["block_ip"][1] == "pending", "Block IP should be pending approval"
        
        assert "disable_user" in actions_map, "disable_user action missing"
        assert actions_map["disable_user"][0] == "compromised_test_user", "Disable user target mismatch"
        
        assert "isolate_endpoint" in actions_map, "isolate_endpoint action missing"
        assert actions_map["isolate_endpoint"][0] == "endpoint-win-102", "Isolate endpoint target mismatch"
        
        # Ticket and watchlist should be auto_approved and executed
        assert "create_ticket" in actions_map, "create_ticket action missing"
        assert actions_map["create_ticket"][1] == "auto_approved", "create_ticket should be auto_approved"
        assert actions_map["create_ticket"][2] is True, "create_ticket should be executed"
        
        assert "add_to_watchlist" in actions_map, "add_to_watchlist action missing"
        assert actions_map["add_to_watchlist"][1] == "auto_approved", "add_to_watchlist should be auto_approved"
        assert actions_map["add_to_watchlist"][2] is True, "add_to_watchlist should be executed"
        
        logger.info("LangGraph recommended actions parsing and auto-execution verified successfully!")
        
    finally:
        pipeline._decision_analyst.analyze = original_analyze


def test_api_endpoints():
    logger.info("\n=== Running FastAPI Endpoint Integration Tests ===")
    pg = PostgresStore()
    
    # 1. Setup a dummy pending action
    alert = make_test_alert(SeverityLevel.HIGH, "API test alert")
    pg.save_alert(alert)
    inv_id = str(uuid.uuid4())
    pg.save_investigation(
        inv_id=inv_id,
        trigger_alert_id=alert.id,
        classification="suspicious",
        severity="High",
        summary="Test API inv",
        attack_type="recon",
        mitre_tactics=[],
        mitre_techniques=[],
        related_alert_ids=[],
        status="in_progress",
        threat_intel={},
        network_intel={},
        endpoint_intel={},
        report_markdown="# Test Report",
        report_json={}
    )
    
    act_id = queue_response_action(
        investigation_id=inv_id,
        alert_id=alert.id,
        action_type="block_ip",
        target="9.9.9.9",
        reason="API test pending action",
        requires_approval=True
    )
    
    # Initialize TestClient
    client = TestClient(app)
    
    # Login to get JWT Token
    login_resp = client.post("/auth/token", data={"username": "admin", "password": "socadmin2026"})
    assert login_resp.status_code == 200, "Login failed"
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Unauthorized Request check
    unauth_resp = client.get("/api/v1/response/pending")
    assert unauth_resp.status_code == 401, "Expected 401 for unauthenticated request"
    logger.info("API authentication check verified.")
    
    # GET pending actions
    pending_resp = client.get("/api/v1/response/pending", headers=headers)
    assert pending_resp.status_code == 200, "Failed to get pending actions"
    pending_data = pending_resp.json()
    assert len(pending_data) > 0, "No pending actions returned"
    logger.info("API pending queue list returned %d actions", len(pending_data))
    
    # POST approve action
    approve_resp = client.post(f"/api/v1/response/approve/{act_id}", json={"notes": "API approval notes"}, headers=headers)
    assert approve_resp.status_code == 200, f"Approve API endpoint failed: {approve_resp.text}"
    approve_data = approve_resp.json()
    assert approve_data["approval_status"] == "approved", "Status update check failed"
    assert approve_data["executed"] is True, "Execution check failed"
    logger.info("API approval endpoint verified successfully.")
    
    # POST watchlist add
    wl_payload = {"value": "8.8.8.8", "watch_type": "ip", "reason": "Public DNS watch list"}
    wl_add_resp = client.post("/api/v1/response/watchlist", json=wl_payload, headers=headers)
    assert wl_add_resp.status_code == 201, "Failed to add to watchlist via API"
    
    # GET watchlist
    wl_list_resp = client.get("/api/v1/response/watchlist", headers=headers)
    assert wl_list_resp.status_code == 200, "Failed to get watchlist via API"
    wl_data = wl_list_resp.json()
    wl_values = [item["value"] for item in wl_data]
    assert "8.8.8.8" in wl_values, "Watchlisted item missing from list response"
    logger.info("API watchlist endpoints verified successfully.")
    
    # GET audit logs
    audit_resp = client.get("/api/v1/response/audit", headers=headers)
    assert audit_resp.status_code == 200, "Failed to get audit log"
    audit_data = audit_resp.json()
    assert len(audit_data) > 0, "Audit logs empty"
    logger.info("API audit endpoints verified successfully. Log entries: %d", len(audit_data))


async def main():
    logger.info("Starting Phase 10 Automated Response and HITL Verification Tests...")
    try:
        await test_approval_workflow_and_actions()
        await test_langgraph_integration()
        test_api_endpoints()
        
        logger.info("\n" + "=" * 60)
        logger.info("  All Phase 10 Automated Response & HITL Tests PASSED!  ")
        logger.info("=" * 60)
    except Exception as exc:
        logger.exception("Test validation failed")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
