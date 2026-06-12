"""
Verification tests for Phase 9 -- Incident Memory + Data Retention.

Verifies:
1. PostgresStore partitioned database migration runs successfully.
2. Saving and updating alerts in the partitioned table.
3. Thread-safe retrieval of alerts with database-level pagination.
4. Historical correlation IP/user lookups in Postgres.
5. ChromaDB report indexing and cosine similarity querying.
6. Execution of memory tools in correlation nodes.
7. Standalone retention script execution and partition/vector purging.
"""

import asyncio
import time
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_analyst.collector.models import NormalizedAlert, SeverityLevel, InvestigationStatus
from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.memory.vector_store import VectorStore
from soc_analyst.agents.tools.memory_tools import get_ip_history, get_user_history, search_past_incidents
from soc_analyst.agents.workflows.investigation_graph import InvestigationWorkflow
from soc_analyst.agents.analyst.pipeline import AnalystPipeline
from soc_analyst.agents.llm_router import LLMRouter, LLMConfig

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("test_phase9")


def make_test_alert(severity: SeverityLevel, rule_desc: str, username: str = "test_user", src_ip: str = "192.168.9.9", timestamp: datetime = None) -> NormalizedAlert:
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


async def test_postgres_store():
    logger.info("\n=== Running PostgresStore Unit Tests ===")
    pg = PostgresStore()
    
    # 1. Save alert
    alert = make_test_alert(SeverityLevel.HIGH, "Brute force test alert for PostgresStore")
    logger.info("Saving alert %s...", alert.id)
    pg.save_alert(alert)
    logger.info("Alert saved.")

    # 2. Get alert by ID
    logger.info("Retrieving alert by ID %s...", alert.id)
    fetched = pg.get_alert_by_id(alert.id)
    assert fetched is not None, "Failed to retrieve saved alert"
    assert fetched.rule_description == alert.rule_description, "Rule description mismatch"
    logger.info("Alert fetched: %s", fetched.rule_description)

    # 3. Update alert status
    logger.info("Updating alert status to ESCALATED...")
    updated = pg.update_alert(alert.id, investigation_status=InvestigationStatus.ESCALATED, analyst_verdict="true_positive")
    assert updated is not None, "Failed to update alert"
    assert updated.investigation_status == InvestigationStatus.ESCALATED, "Status update failed"
    logger.info("Alert updated successfully. Verdict: %s", updated.analyst_verdict)

    # 4. Get paginated alerts
    logger.info("Testing paginated queries...")
    alerts_list = pg.get_alerts(limit=5, offset=0)
    assert len(alerts_list) > 0, "No alerts returned by paginated query"
    logger.info("Fetched %d alerts.", len(alerts_list))

    # 5. Save investigation and incident memory
    inv_id = str(uuid.uuid4())
    logger.info("Saving investigation log %s...", inv_id)
    pg.save_investigation(
        inv_id=inv_id,
        trigger_alert_id=alert.id,
        classification="suspicious",
        severity="High",
        summary="Suspicious logon brute force",
        attack_type="credential_access",
        mitre_tactics=["TA0001"],
        mitre_techniques=["T1110"],
        related_alert_ids=[],
        status="escalated",
        threat_intel={},
        network_intel={},
        endpoint_intel={},
        report_markdown="# Test Investigation",
        report_json={"test": True}
    )
    logger.info("Investigation log saved.")

    logger.info("Saving incident memory (IOC cache)...")
    pg.save_incident_memory(
        investigation_id=inv_id,
        ioc_type="ip",
        ioc_value="192.168.9.9",
        reputation_score=75.0,
        reputation_data={"abuse_confidence": 75},
        tags=["brute-force", "test"]
    )
    logger.info("Incident memory saved.")


async def test_vector_store():
    logger.info("\n=== Running VectorStore Unit Tests ===")
    v_store = VectorStore()
    
    # Clear existing documents to ensure test independence
    try:
        existing = v_store.collection.get()
        if existing and existing.get("ids"):
            v_store.collection.delete(ids=existing["ids"])
            logger.info("Cleared %d existing vector documents.", len(existing["ids"]))
    except Exception as exc:
        logger.warning("Failed to clear vector store: %s", exc)
    
    alert_id = str(uuid.uuid4())
    report_text = """
    # Incident report
    Attack detected from IP 192.168.99.99 using brute force against Administrator user.
    Verdict: CONFIRMED_THREAT
    """
    metadata = {
        "alert_id": alert_id,
        "timestamp": int(time.time()),
        "severity": "critical",
        "verdict": "true_positive",
        "rule_description": "Brute force admin",
        "src_ip": "192.168.99.99",
        "username": "admin"
    }

    # 1. Index report
    logger.info("Indexing incident report for alert %s...", alert_id)
    v_store.add_incident_report(alert_id, report_text, metadata)

    # 2. Similarity search
    logger.info("Querying vector store for similarity search...")
    matches = v_store.search_similar_incidents("Brute force login from IP 192.168.99.99 against admin", limit=1)
    assert len(matches) > 0, "No vector store similarity matches returned"
    logger.info("Match found: ID=%s, Distance=%f, Similarity=%f", 
                matches[0]["id"], matches[0]["distance"], matches[0]["similarity"])
    assert matches[0]["id"] == alert_id, "Similarity query returned wrong ID"
    logger.info("Vector similarity query verified.")


async def test_memory_tools():
    logger.info("\n=== Running Memory Tools Tests ===")
    
    # 1. Test get_ip_history tool
    logger.info("Invoking [get_ip_history] tool for IP 192.168.9.9...")
    ip_hist = await get_ip_history("192.168.9.9")
    assert "alerts" in ip_hist, "Tool get_ip_history response missing alerts"
    logger.info("IP History tool returned %d matching alerts.", ip_hist["history_count"])
    assert ip_hist["history_count"] > 0, "Expected at least 1 match"

    # 2. Test get_user_history tool
    logger.info("Invoking [get_user_history] tool for user test_user...")
    user_hist = await get_user_history("test_user")
    assert "alerts" in user_hist, "Tool get_user_history response missing alerts"
    logger.info("User History tool returned %d matching alerts.", user_hist["history_count"])
    assert user_hist["history_count"] > 0, "Expected at least 1 match"

    # 3. Test search_past_incidents tool
    logger.info("Invoking [search_past_incidents] tool for brute force...")
    vec_results = await search_past_incidents("brute force against Administrator", limit=2)
    assert "incidents" in vec_results, "Tool search_past_incidents response missing incidents"
    logger.info("Vector search tool returned %d matching incident reports.", vec_results["match_count"])
    assert vec_results["match_count"] > 0, "Expected at least 1 match"


async def test_langgraph_e2e_persistence():
    logger.info("\n=== Running LangGraph End-to-End Persistence Tests ===")
    config = LLMConfig(provider="mock")
    llm = LLMRouter(config)
    pipeline = AnalystPipeline(llm=llm)
    workflow = InvestigationWorkflow(pipeline)

    alert = make_test_alert(SeverityLevel.HIGH, "Unauthorized database login attempt", "db_admin", "10.0.0.99")
    
    # Pre-save alert in status "new" (normally done by AlertCollector)
    pg = PostgresStore()
    pg.save_alert(alert)
    
    logger.info("Triggering LangGraph workflow for alert %s...", alert.id)
    verdict = await workflow.run(alert)
    logger.info("LangGraph verdict returned: %s", verdict.verdict)

    # Verify report_node persisted details to Postgres
    logger.info("Verifying PostgreSQL database state updates...")
    db_alert = pg.get_alert_by_id(alert.id)
    assert db_alert is not None, "Failed to retrieve alert from Postgres after workflow run"
    assert db_alert.investigation_status == InvestigationStatus.ESCALATED, "Alert status not updated to ESCALATED"
    assert db_alert.analyst_verdict == "suspicious", "Alert verdict mismatch"
    logger.info("DB state update verified: Status=%s, Verdict=%s", db_alert.investigation_status.value, db_alert.analyst_verdict)

    # Verify report_node indexed report in ChromaDB
    logger.info("Verifying ChromaDB report search...")
    v_store = VectorStore()
    matches = v_store.search_similar_incidents("Unauthorized database login by db_admin", limit=1)
    assert len(matches) > 0, "Failed to find incident report in vector store after workflow run"
    assert matches[0]["id"] == alert.id, "Vector index ID mismatch"
    logger.info("Vector index verified.")


async def test_retention_cleanup():
    logger.info("\n=== Running Standalone Retention Cleanup Test ===")
    pg = PostgresStore()
    v_store = VectorStore()

    # 1. Create a dummy alert with timestamp 200 days in the past (to trigger partition purge)
    past_date = datetime.now(timezone.utc) - timedelta(days=200)
    past_alert = make_test_alert(SeverityLevel.LOW, "Ancient alert for partition purge", timestamp=past_date)
    
    logger.info("Saving ancient alert %s from %s...", past_alert.id, past_date.date())
    pg.save_alert(past_alert)
    
    # Verify partition was created
    part_name = f"alerts_y{past_date.year}m{past_date.month:02d}"
    with pg.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = %s)", (part_name,))
            assert cur.fetchone()[0] is True, "Ancient partition table was not created"
            logger.info("Ancient partition table %s exists.", part_name)

    # 2. Add an ancient vector report (200 days old)
    past_report_id = str(uuid.uuid4())
    past_metadata = {
        "alert_id": past_report_id,
        "timestamp": int(past_date.timestamp()),
        "severity": "low",
        "verdict": "false_positive",
        "rule_description": "ancient test",
        "src_ip": "1.1.1.1",
        "username": "none"
    }
    v_store.add_incident_report(past_report_id, "Ancient report document", past_metadata)

    # 3. Execute retention cleanup script functions directly
    from scripts.retention_cleanup import run_postgres_cleanup, run_chroma_cleanup
    
    logger.info("Running PostgreSQL retention cleanup (retention window = 180 days)...")
    run_postgres_cleanup(pg, retention_days=180)
    
    # Verify partition was dropped
    with pg.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = %s)", (part_name,))
            assert cur.fetchone()[0] is False, "Ancient partition table was not dropped"
            logger.info("Ancient partition table %s was successfully dropped.", part_name)

    # Verify normal partition still exists
    now = datetime.now(timezone.utc)
    current_part = f"alerts_y{now.year}m{now.month:02d}"
    with pg.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = %s)", (current_part,))
            assert cur.fetchone()[0] is True, "Current partition table was dropped"
            logger.info("Current partition table %s remains active.", current_part)

    # 4. Run ChromaDB retention cleanup (retention window = 90 days)
    logger.info("Running ChromaDB retention cleanup (retention window = 90 days)...")
    run_chroma_cleanup(v_store, retention_days=90)
    
    # Verify ancient report was dropped
    results = v_store.collection.get(ids=[past_report_id])
    assert len(results.get("ids", [])) == 0, "Ancient vector report was not purged"
    logger.info("Ancient vector report was successfully purged.")


async def main():
    logger.info("Starting Phase 9 Incident Memory & Data Retention Verification Tests...")
    
    # Run the tests sequentially
    try:
        await test_postgres_store()
        await test_vector_store()
        await test_memory_tools()
        await test_langgraph_e2e_persistence()
        await test_retention_cleanup()
        
        logger.info("\n" + "=" * 60)
        logger.info("  All Phase 9 Incident Memory & Retention Tests PASSED!  ")
        logger.info("=" * 60)
    except Exception as exc:
        logger.exception("Test validation failed")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
