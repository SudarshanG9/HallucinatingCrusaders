"""
Verification tests for Phase 6 -- Integration, Auto-Triage & Parallel Enrichment.

Verifies:
1. Parallel enrichment (threat intel, geoip, endpoint processes, whois)
2. Background auto-triage loop in AlertCollector
3. Auto-Resolution Policy (low severity alerts automatically resolved and tagged)
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_analyst.collector.main import AlertCollector
from soc_analyst.collector.models import NormalizedAlert, SeverityLevel, InvestigationStatus
from soc_analyst.agents.analyst.pipeline import AnalystPipeline
from soc_analyst.agents.llm_router import LLMRouter, LLMConfig

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
logger = logging.getLogger("test_phase6")


def make_test_alert(severity: SeverityLevel, rule_desc: str, username: str = "john_doe", src_ip: str = "8.8.8.8") -> NormalizedAlert:
    return NormalizedAlert(
        source="wazuh",
        vendor="Wazuh SIEM",
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        raw_content=json.dumps({
            "rule": {
                "id": "5715",
                "level": 10 if severity == SeverityLevel.HIGH else 3,
                "description": rule_desc,
            },
            "agent": {"id": "001", "name": "MAXW"},
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": username,
                        "ipAddress": src_ip,
                    }
                }
            }
        }),
        rule_id="5715",
        rule_description=rule_desc,
        src_ip=src_ip,
        username=username,
        hostname="MAXW",
    )


async def main():
    logger.info("=" * 60)
    logger.info("  Phase 6 E2E Verification Tests  ")
    logger.info("=" * 60)

    # 1. Test Parallel Enrichment standalone
    logger.info("\n--- TEST 1: Parallel Enrichment Standalone ---")
    config = LLMConfig(provider="mock")
    llm = LLMRouter(config)
    pipeline = AnalystPipeline(llm=llm)

    alert = make_test_alert(SeverityLevel.HIGH, "sshd brute force attempt", "root", "8.8.8.8")
    
    # Extract facts first
    facts = await pipeline._fact_extractor.extract(alert)
    logger.info("Extracted facts: %s", facts.model_dump_json(indent=2))

    # Run enrichment
    enriched = await pipeline._enrich_context(alert, facts)
    logger.info("Enriched context categories: %s", list(enriched.keys()))
    
    # Assert on expected enriched components
    assert "ips" in enriched, "Enrichment missing 'ips' category"
    assert "8.8.8.8" in enriched["ips"], "Enrichment missing IP details for 8.8.8.8"
    assert "virustotal" in enriched["ips"]["8.8.8.8"], "Missing VirusTotal in IP enrichment"
    assert "abuseipdb" in enriched["ips"]["8.8.8.8"], "Missing AbuseIPDB in IP enrichment"
    assert "geoip" in enriched["ips"]["8.8.8.8"], "Missing GeoIP in IP enrichment"
    
    logger.info("IP Enrichment matches: %s", json.dumps(enriched["ips"]["8.8.8.8"], indent=2, default=str)[:300] + "...")
    logger.info("TEST 1 PASSED!")

    # 2. Test Background Auto-Triage Loop & Auto-Resolution
    logger.info("\n--- TEST 2: Collector Background Auto-Triage & Auto-Resolution ---")
    
    # Use default collector (or instantiate one manually)
    collector = AlertCollector()
    collector.pipeline = pipeline  # Bind our mock pipeline
    
    # Start collector polling (starts triage worker loop)
    await collector.start()
    
    try:
        # Ingest a HIGH severity alert (should be ESCALATED)
        high_alert = make_test_alert(SeverityLevel.HIGH, "Brute force attack", "admin", "192.168.1.50")
        logger.info("Ingesting HIGH severity alert %s", high_alert.id)
        collector.ingest(high_alert)
        
        # Ingest a LOW severity alert (should be auto-resolved)
        low_alert = make_test_alert(SeverityLevel.LOW, "Routine system check", "alice", "192.168.1.60")
        logger.info("Ingesting LOW severity alert %s", low_alert.id)
        collector.ingest(low_alert)

        # Wait for the background loop to pick up and process both alerts
        logger.info("Waiting for background auto-triage loop to process alerts...")
        await asyncio.sleep(3)

        # Verify HIGH alert
        triaged_high = collector.get_alert_by_id(high_alert.id)
        logger.info("High alert verdict: %s", triaged_high.analyst_verdict)
        logger.info("High alert status: %s", triaged_high.investigation_status)
        assert triaged_high.investigation_status in (InvestigationStatus.ESCALATED, InvestigationStatus.INVESTIGATING, InvestigationStatus.RESOLVED), \
            f"Expected status to be updated, got {triaged_high.investigation_status}"
        assert triaged_high.analyst_verdict is not None, "Expected verdict to be set"

        # Verify LOW alert
        triaged_low = collector.get_alert_by_id(low_alert.id)
        logger.info("Low alert verdict: %s", triaged_low.analyst_verdict)
        logger.info("Low alert status: %s", triaged_low.investigation_status)
        logger.info("Low alert tags: %s", triaged_low.tags)
        
        # Check auto-resolution policy
        assert triaged_low.investigation_status == InvestigationStatus.RESOLVED, \
            f"Expected resolved status, got {triaged_low.investigation_status}"
        assert "auto-resolved" in triaged_low.tags, "Expected 'auto-resolved' tag to be appended"

        logger.info("TEST 2 PASSED!")

    finally:
        await collector.stop()

    logger.info("\n" + "=" * 60)
    logger.info("  All Phase 6 Verification Tests PASSED!  ")
    logger.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
