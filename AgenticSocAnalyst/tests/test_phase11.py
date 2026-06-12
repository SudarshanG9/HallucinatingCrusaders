"""
Verification tests for Phase 11 -- SOC Dashboard (Python-Native).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_analyst.api.main import app
from soc_analyst.collector.models import InvestigationStatus, NormalizedAlert, SeverityLevel
from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.responder.approval_queue import queue_response_action

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("test_phase11")


def make_test_alert(severity: SeverityLevel, rule_desc: str, username: str = "test_user", src_ip: str = "192.168.11.11") -> NormalizedAlert:
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
                    "sourcePort": "49152",
                    "destPort": "445"
                }
            }
        }
    })
    return NormalizedAlert(
        id=alert_id,
        source="wazuh",
        vendor="Wazuh SIEM",
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        raw_content=content,
        rule_id="5715",
        rule_description=rule_desc,
        src_ip=src_ip,
        username=username,
        hostname="TEST_HOST",
    )


async def run_dashboard_tests():
    logger.info("Starting Phase 11 Dashboard Verification Tests...")
    
    # Initialize database store
    pg = PostgresStore()
    
    # Create test alerts and actions
    alert = make_test_alert(SeverityLevel.HIGH, "Brute force test alert for Phase 11 Dashboard")
    pg.save_alert(alert)
    
    inv_id = str(uuid.uuid4())
    pg.save_investigation(
        inv_id=inv_id,
        trigger_alert_id=alert.id,
        classification="suspicious",
        severity="High",
        summary="Brute force attack simulation analysis",
        attack_type="brute_force",
        mitre_tactics=["TA0001"],
        mitre_techniques=["T1110"],
        related_alert_ids=[],
        status="in_progress",
        threat_intel={},
        network_intel={},
        endpoint_intel={},
        report_markdown="# Custom Markdown Report\nThis is a trial report.",
        report_json={}
    )
    
    action_id = queue_response_action(
        investigation_id=inv_id,
        alert_id=alert.id,
        action_type="block_ip",
        target="192.168.11.11",
        reason="Brute force source IP block required",
        requires_approval=True
    )
    
    # Instantiate client within context to run FastAPI lifespans (starts AlertCollector)
    with TestClient(app) as client:
        # Disable redirects to test exact status codes
        client.follow_redirects = False
        
        # 1. Unauthenticated Redirect Checks
        logger.info("Verifying unauthenticated routing redirects...")
        resp = client.get("/dashboard/alerts")
        assert resp.status_code == 303, f"Expected 303 Redirect to login, got {resp.status_code}"
        assert resp.headers["location"] == "/login"
        
        resp = client.get("/dashboard/connectors")
        assert resp.status_code == 303, f"Expected 303 Redirect to login, got {resp.status_code}"
        
        resp = client.get("/dashboard/response")
        assert resp.status_code == 303, f"Expected 303 Redirect to login, got {resp.status_code}"
        
        # 2. Login flow and Cookie verification
        logger.info("Testing operators authentication and cookies flow...")
        login_resp = client.post("/login", data={"username": "admin", "password": "socadmin2026"})
        assert login_resp.status_code == 303, f"Expected 303 Redirect after login, got {login_resp.status_code}"
        assert login_resp.headers["location"] == "/dashboard/alerts"
        
        # Verify access_token cookie is present in cookies jar
        assert "access_token" in login_resp.cookies, "Access token cookie missing in login response"
        
        # Enable cookie persistence for successive requests
        client.follow_redirects = True
        
        # 3. View Rendering Tests
        logger.info("Testing main dashboard views render correctly...")
        views = [
            "/dashboard/alerts",
            "/dashboard/connectors",
            "/dashboard/response",
            "/dashboard/monitor",
            "/dashboard/analytics",
            f"/dashboard/investigations/{alert.id}"
        ]
        
        for view_path in views:
            resp = client.get(view_path)
            assert resp.status_code == 200, f"Failed to render dashboard view {view_path}: {resp.status_code}"
            assert "HallucinatingCrusaders" in resp.text, f"View {view_path} missing brand wrapper signature"
            logger.info("Successfully rendered view: %s", view_path)

        # 4. HTMX table snippet dynamic loading
        logger.info("Testing HTMX dynamic table component...")
        table_resp = client.get("/dashboard/alerts/table")
        assert table_resp.status_code == 200, f"HTMX table snippet failed: {table_resp.status_code}"
        assert "<table" in table_resp.text, "Snippet missing HTML table wrapper element"
        
        # Test filters in HTMX snippet
        filtered_resp = client.get("/dashboard/alerts/table?source=wazuh&severity=4")
        assert filtered_resp.status_code == 200, "HTMX filtered table snippet failed"
        
        # 5. Connectors switch toggling
        logger.info("Testing connector mode toggle HTMX endpoint...")
        toggle_resp = client.post("/dashboard/connectors/toggle/mock_okta")
        assert toggle_resp.status_code == 200, f"Connector toggle failed: {toggle_resp.status_code}"
        assert "MODE" in toggle_resp.text, f"Unexpected HTMX toggle response payload: {toggle_resp.text}"
        
        # 6. Response approval execution via HTMX
        logger.info("Testing HITL action approvals HTMX endpoint...")
        approve_resp = client.post(f"/dashboard/response/approve/{action_id}")
        assert approve_resp.status_code == 200, f"Approval call failed: {approve_resp.status_code}"
        assert "Executed" in approve_resp.text, f"Approval payload missing execution confirmation: {approve_resp.text}"
        
        # Create a second action to test rejection
        action_id_reject = queue_response_action(
            investigation_id=inv_id,
            alert_id=alert.id,
            action_type="disable_user",
            target="compromised_test_user",
            reason="Compromised user credential cleanup",
            requires_approval=True
        )
        reject_resp = client.post(f"/dashboard/response/reject/{action_id_reject}")
        assert reject_resp.status_code == 200, f"Rejection call failed: {reject_resp.status_code}"
        assert "Rejected" in reject_resp.text, f"Rejection payload missing rejection confirmation: {reject_resp.text}"
        
        # 7. Logout and clean cookie check
        logger.info("Testing operator sign out flow...")
        client.follow_redirects = False
        logout_resp = client.get("/logout")
        assert logout_resp.status_code == 303, f"Expected 303 Redirect after logout, got {logout_resp.status_code}"
        assert logout_resp.headers["location"] == "/login"
        
        # Check that access_token cookie is deleted (set to empty or Max-Age=0)
        cookie_val = logout_resp.cookies.get("access_token")
        assert not cookie_val or cookie_val == "", "Access token cookie was not deleted after logout"
        
    logger.info("\n" + "=" * 60)
    logger.info("  All Phase 11 Python-Native SOC Dashboard Tests PASSED!  ")
    logger.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_dashboard_tests())
