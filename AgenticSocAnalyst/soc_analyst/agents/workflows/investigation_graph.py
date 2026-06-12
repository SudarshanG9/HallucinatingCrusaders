"""
Stateful multi-step security alert investigation workflows using LangGraph.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

from langgraph.graph import END, StateGraph

from soc_analyst.agents.analyst.pipeline import AnalystPipeline, DeadLetterEntry
from soc_analyst.agents.analyst.schemas import AnalystVerdict, ExtractedFacts
from soc_analyst.agents.workflows.state import InvestigationState
from soc_analyst.collector.models import NormalizedAlert, InvestigationStatus

logger = logging.getLogger(__name__)

__all__ = ["InvestigationWorkflow"]


class InvestigationWorkflow:
    """Orchestrates the multi-agent/multi-node analysis using LangGraph.

    This graph integrates the InjectionGate, FactExtractor, parallel context
    enrichment, and DecisionAnalyst into a unified state machine.
    """

    def __init__(self, pipeline: Optional[AnalystPipeline] = None) -> None:
        if pipeline is None:
            pipeline = AnalystPipeline()
        self.pipeline = pipeline
        self.graph = self._build_graph()
        logger.info("InvestigationWorkflow graph compiled")

    def _build_graph(self) -> Any:
        """Construct the Directed Acyclic Graph (DAG) for investigation."""
        workflow = StateGraph(InvestigationState)

        # 1. Define nodes
        workflow.add_node("gate", self.gate_node)
        workflow.add_node("triage", self.triage_node)
        workflow.add_node("investigation", self.investigation_node)
        workflow.add_node("threat_intel", self.threat_intel_node)
        workflow.add_node("correlation", self.correlation_node)
        workflow.add_node("report", self.report_node)

        # 2. Set entry point
        workflow.set_entry_point("gate")

        # 3. Add conditional transitions
        workflow.add_conditional_edges(
            "gate",
            self.route_after_gate,
            {
                "blocked": "report",
                "failed": "report",
                "clean": "triage",
            },
        )

        # 4. Add static transitions & Parallel Fan-out / Fan-in
        # From triage, fan-out to investigation, threat_intel, and correlation in parallel
        workflow.add_edge("triage", "investigation")
        workflow.add_edge("triage", "threat_intel")
        workflow.add_edge("triage", "correlation")

        # Fan-in back to report node
        workflow.add_edge("investigation", "report")
        workflow.add_edge("threat_intel", "report")
        workflow.add_edge("correlation", "report")

        workflow.add_edge("report", END)

        return workflow.compile()

    # ------------------------------------------------------------------
    # Node implementations
    # ------------------------------------------------------------------

    async def gate_node(self, state: InvestigationState) -> Dict[str, Any]:
        """Node for scanning potential prompt injection (Stage 3) and extracting facts (Stage 4)."""
        alert = state["alert"]
        logger.info("LangGraph [gate_node] starting for alert %s", alert.id)

        try:
            content = alert.raw_content or ""
            gate_result = await self.pipeline._gate.check(
                content, llm=self.pipeline._llm
            )

            is_blocked = gate_result.action == "block"
            facts = None
            errors = []

            if is_blocked:
                self.pipeline.metrics.injection_blocks += 1
                facts = self.pipeline._fact_extractor._blocked_facts(
                    alert, gate_result.detected_patterns
                )
                logger.warning(
                    "LangGraph [gate_node] detected prompt injection on alert %s. Blocking execution.",
                    alert.id,
                )
                return {
                    "is_blocked": is_blocked,
                    "facts": facts,
                    "errors": errors,
                }

            # If not blocked, extract facts using quarantined LLM (Stage 4)
            try:
                facts = await self.pipeline._fact_extractor.extract(alert)
            except Exception as exc:
                logger.error("Error during quarantined fact extraction: %s", exc)
                errors.append(f"Fact extraction error: {exc}")

            return {
                "is_blocked": False,
                "facts": facts,
                "errors": errors,
            }

        except Exception as exc:
            logger.error("Error in LangGraph [gate_node]: %s", exc)
            return {
                "is_blocked": False,
                "facts": None,
                "errors": [f"Gate node error: {exc}"],
            }

    async def triage_node(self, state: InvestigationState) -> Dict[str, Any]:
        """Node for classifying severity and attack type based on facts only (TriageNode)."""
        alert = state["alert"]
        facts = state["facts"]
        logger.info("LangGraph [triage_node] starting for alert %s", alert.id)

        if facts is None:
            return {
                "triage_result": {
                    "severity": "medium",
                    "attack_type": "unknown",
                }
            }

        from soc_analyst.agents.analyst.prompts import TRIAGE_SYSTEM_PROMPT

        # Serialize facts to JSON
        facts_json = facts.model_dump_json(indent=2)
        prompt = f"Analyze the following extracted facts and classify initial severity and attack type:\n\n{facts_json}"

        try:
            raw_response = await self.pipeline._llm.call(
                prompt=prompt,
                system_prompt=TRIAGE_SYSTEM_PROMPT,
            )

            # Parse LLM JSON response
            text = raw_response.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                lines = [ln for ln in lines if not ln.strip().startswith("```")]
                text = "\n".join(lines)

            data = json.loads(text)
            severity = data.get("severity", "medium").lower()
            attack_type = data.get("attack_type", "unknown").lower()

            logger.info("TriageNode classified alert %s as severity=%s, attack_type=%s", alert.id, severity, attack_type)
            return {
                "triage_result": {
                    "severity": severity,
                    "attack_type": attack_type,
                }
            }
        except Exception as exc:
            logger.error("Error in TriageNode: %s. Falling back to default triage based on facts.", exc)
            # Default fallback triage mapping using facts fields and alert severity hint
            severity = "medium"
            if alert.severity.value >= 5:
                severity = "critical"
            elif facts.requires_escalation or alert.severity.value >= 4:
                severity = "high"
            elif alert.severity.value <= 2:
                severity = "low"
            attack_type = facts.attack_stage
            return {
                "triage_result": {
                    "severity": severity,
                    "attack_type": attack_type,
                },
                "errors": state.get("errors", []) + [f"Triage node error: {exc}"],
            }

    async def investigation_node(self, state: InvestigationState) -> Dict[str, Any]:
        """Node for collecting endpoint and network evidence (InvestigationNode)."""
        alert = state["alert"]
        facts = state["facts"]
        logger.info("LangGraph [investigation_node] starting for alert %s", alert.id)

        if facts is None:
            return {"investigation_result": {}}

        try:
            indicators = self._prepare_indicators(alert, facts)
            ips = indicators["ips"]
            domains = indicators["domains"]

            tasks = []
            task_info = []

            # 1. Network lookups for IPs (GeoIP)
            for ip in ips[:3]:
                from soc_analyst.agents.tools import geoip_lookup
                tasks.append(geoip_lookup(ip))
                task_info.append(("ips", ip, "geoip"))

            # 2. Network lookups for domains (DNS, WHOIS)
            for domain in domains[:3]:
                from soc_analyst.agents.tools import dns_lookup, whois_lookup
                tasks.append(dns_lookup(domain))
                task_info.append(("domains", domain, "dns"))
                tasks.append(whois_lookup(domain))
                task_info.append(("domains", domain, "whois"))

            # 3. Endpoint lookups (Wazuh processes, FIM events, user activity)
            agent_id = None
            if alert.source == "wazuh" or alert.vendor.lower() == "wazuh":
                try:
                    import json
                    raw = json.loads(alert.raw_content)
                    agent_id = raw.get("agent", {}).get("id")
                except Exception:
                    pass

            if agent_id:
                from soc_analyst.agents.tools import get_agent_processes, get_file_integrity_events, get_user_activity
                tasks.append(get_agent_processes(agent_id))
                task_info.append(("endpoint", agent_id, "processes"))
                tasks.append(get_file_integrity_events(agent_id))
                task_info.append(("endpoint", agent_id, "fim_events"))
                if alert.username:
                    tasks.append(get_user_activity(agent_id, alert.username))
                    task_info.append(("endpoint", f"{agent_id}:{alert.username}", "user_activity"))

            if not tasks:
                return {"investigation_result": {}}

            results = await asyncio.gather(*tasks, return_exceptions=True)

            investigation_result = {
                "ips": {},
                "domains": {},
                "endpoint": {}
            }

            for (category, key, tool), res in zip(task_info, results):
                if isinstance(res, Exception):
                    logger.error("Investigation failed for %s/%s/%s: %s", category, key, tool, res)
                    res_val = {"error": str(res)}
                else:
                    res_val = res

                if category not in investigation_result:
                    investigation_result[category] = {}
                if key not in investigation_result[category]:
                    investigation_result[category][key] = {}
                investigation_result[category][key][tool] = res_val

            return {"investigation_result": investigation_result}

        except Exception as exc:
            logger.error("Error in LangGraph [investigation_node]: %s", exc)
            return {
                "investigation_result": {},
                "errors": state.get("errors", []) + [f"Investigation node error: {exc}"],
            }

    async def threat_intel_node(self, state: InvestigationState) -> Dict[str, Any]:
        """Node for enriching IOC reputation metrics (ThreatIntelNode)."""
        alert = state["alert"]
        facts = state["facts"]
        logger.info("LangGraph [threat_intel_node] starting for alert %s", alert.id)

        if facts is None:
            return {"threat_intel_result": {}}

        try:
            indicators = self._prepare_indicators(alert, facts)
            ips = indicators["ips"]
            domains = indicators["domains"]
            hashes = indicators["hashes"]

            tasks = []
            task_info = []

            from soc_analyst.agents.tools import check_abuseipdb, check_virustotal, check_otx

            # 1. IP Reputation
            for ip in ips[:3]:
                tasks.append(check_abuseipdb(ip))
                task_info.append(("ips", ip, "abuseipdb"))
                tasks.append(check_virustotal(ip, "ip"))
                task_info.append(("ips", ip, "virustotal"))
                tasks.append(check_otx(ip, "ip"))
                task_info.append(("ips", ip, "otx"))

            # 2. Domain Reputation
            for domain in domains[:3]:
                tasks.append(check_virustotal(domain, "domain"))
                task_info.append(("domains", domain, "virustotal"))
                tasks.append(check_otx(domain, "domain"))
                task_info.append(("domains", domain, "otx"))

            # 3. Hash Reputation
            for h in hashes[:3]:
                tasks.append(check_virustotal(h, "hash"))
                task_info.append(("hashes", h, "virustotal"))
                tasks.append(check_otx(h, "hash"))
                task_info.append(("hashes", h, "otx"))

            if not tasks:
                return {"threat_intel_result": {}}

            results = await asyncio.gather(*tasks, return_exceptions=True)

            threat_intel_result = {
                "ips": {},
                "domains": {},
                "hashes": {}
            }

            for (category, key, tool), res in zip(task_info, results):
                if isinstance(res, Exception):
                    logger.error("Threat Intel failed for %s/%s/%s: %s", category, key, tool, res)
                    res_val = {"error": str(res)}
                else:
                    res_val = res

                if category not in threat_intel_result:
                    threat_intel_result[category] = {}
                if key not in threat_intel_result[category]:
                    threat_intel_result[category][key] = {}
                threat_intel_result[category][key][tool] = res_val

            return {"threat_intel_result": threat_intel_result}

        except Exception as exc:
            logger.error("Error in LangGraph [threat_intel_node]: %s", exc)
            return {
                "threat_intel_result": {},
                "errors": state.get("errors", []) + [f"Threat Intel node error: {exc}"],
            }

    async def correlation_node(self, state: InvestigationState) -> Dict[str, Any]:
        """Node for cross-vendor logs and DB incident matching (CorrelationNode)."""
        alert = state["alert"]
        facts = state["facts"]
        logger.info("LangGraph [correlation_node] starting for alert %s", alert.id)

        if facts is None:
            return {"correlation_result": {}}

        try:
            indicators = self._prepare_indicators(alert, facts)
            ips = indicators["ips"]
            usernames = indicators["usernames"]
            hostnames = indicators["hostnames"]

            tasks = []
            task_info = []

            from soc_analyst.agents.tools import (
                search_all_vendors_for_ip, 
                search_okta_user, 
                search_defender_host,
                get_ip_history,
                get_user_history
            )

            # 1. IP Cross-vendor Alerts & DB History
            for ip in ips[:3]:
                tasks.append(search_all_vendors_for_ip(ip))
                task_info.append(("ips", ip, "cross_vendor_alerts"))
                tasks.append(get_ip_history(ip))
                task_info.append(("ips", ip, "db_history"))

            # 2. Okta User Activity & DB History
            for user in usernames[:3]:
                tasks.append(search_okta_user(user))
                task_info.append(("users", user, "okta_search"))
                tasks.append(get_user_history(user))
                task_info.append(("users", user, "db_history"))

            # 3. Defender Host Activity
            for host in hostnames[:3]:
                tasks.append(search_defender_host(host))
                task_info.append(("hosts", host, "defender_search"))

            if not tasks:
                return {"correlation_result": {}}

            results = await asyncio.gather(*tasks, return_exceptions=True)

            correlation_result = {
                "ips": {},
                "users": {},
                "hosts": {}
            }

            for (category, key, tool), res in zip(task_info, results):
                if isinstance(res, Exception):
                    logger.error("Correlation failed for %s/%s/%s: %s", category, key, tool, res)
                    res_val = {"error": str(res)}
                else:
                    res_val = res

                if category not in correlation_result:
                    correlation_result[category] = {}
                if key not in correlation_result[category]:
                    correlation_result[category][key] = {}
                correlation_result[category][key][tool] = res_val

            return {"correlation_result": correlation_result}


        except Exception as exc:
            logger.error("Error in LangGraph [correlation_node]: %s", exc)
            return {
                "correlation_result": {},
                "errors": state.get("errors", []) + [f"Correlation node error: {exc}"],
            }

    async def report_node(self, state: InvestigationState) -> Dict[str, Any]:
        """Node for report synthesis and database / metrics persistence."""
        alert = state["alert"]
        verdict = state["verdict"]
        is_blocked = state.get("is_blocked", False)
        errors = state.get("errors", [])
        logger.info("LangGraph [report_node] starting for alert %s", alert.id)

        # 1. Synthesize legacy enriched_context for backward compatibility
        enriched_context = self._synthesize_enriched_context(state)

        # 2. Handle failed branches
        if errors and not verdict:
            self.pipeline.metrics.failure_count += 1
            error_str = "; ".join(errors)
            self.pipeline.dead_letter_queue.append(
                DeadLetterEntry(alert_id=alert.id, error=error_str)
            )
            # Safe fallback verdict
            verdict = AnalystVerdict(
                alert_id=alert.id,
                verdict="needs_investigation",
                severity_assessment="medium",
                reasoning=f"Workflow error(s): {error_str}. Manual review required.",
                recommended_actions=[
                    "Review SIEM console",
                    "Check workflow dead-letter queue",
                ],
                auto_resolved=False,
            )
        elif is_blocked:
            # Blocked at injection gate, create blocked verdict
            facts = state["facts"]
            reasoning = (
                facts.summary if facts else "Blocked at prompt injection gate."
            )
            verdict = AnalystVerdict(
                alert_id=alert.id,
                verdict="true_positive",
                severity_assessment="critical",
                reasoning=reasoning,
                recommended_actions=[
                    "Isolate host immediately",
                    "Quarantine original alert text",
                    "Audit perimeter firewall traffic",
                ],
                mitre_mapping=[],
                auto_resolved=False,
            )
            self.pipeline.metrics.success_count += 1
        elif verdict:
            self.pipeline.metrics.success_count += 1
        else:
            # Execute Stage 5 reasoning on the merged context
            try:
                facts = state["facts"]
                verdict = await self.pipeline._decision_analyst.analyze(
                    facts, alert, enriched_context
                )
                self.pipeline.metrics.success_count += 1
            except Exception as exc:
                logger.error("Error invoking DecisionAnalyst in report_node: %s", exc)
                self.pipeline.metrics.failure_count += 1
                error_str = f"Decision analysis error: {exc}"
                self.pipeline.dead_letter_queue.append(
                    DeadLetterEntry(alert_id=alert.id, error=error_str)
                )
                verdict = self.pipeline._decision_analyst._rule_based_verdict(facts, alert)

        # 3. Persist results to PostgreSQL and ChromaDB stores
        try:
            from soc_analyst.memory.postgres_store import PostgresStore
            from soc_analyst.memory.vector_store import VectorStore
            import uuid

            pg_store = PostgresStore()
            v_store = VectorStore()

            # Determine new status based on verdict
            new_status = "resolved"
            if verdict.verdict in ("true_positive", "suspicious", "needs_investigation"):
                new_status = "escalated"
            if verdict.verdict == "false_positive":
                new_status = "false_positive"

            # If auto-resolved or low severity, status is resolved
            if verdict.auto_resolved or verdict.severity_assessment in ("low", "informational"):
                new_status = "resolved"

            # Generate synthesis report
            report_md = f"""# Incident Investigation Report: {alert.rule_description or 'Security Alert'}

## Executive Summary
- **Alert ID:** {alert.id}
- **Timestamp:** {alert.timestamp.isoformat()}
- **Severity Assessment:** {verdict.severity_assessment.upper()}
- **Verdict:** {verdict.verdict.upper()}
- **Mitre ATT&CK Mapping:** {", ".join(verdict.mitre_mapping) or "None"}

## AI Analyst Reasoning
{verdict.reasoning}

## Recommended Action Playbook
"""
            for i, action in enumerate(verdict.recommended_actions, 1):
                report_md += f"{i}. {action}\n"

            report_md += f"\n## Extracted Facts Summary\n"
            if state.get("facts"):
                facts_data = state["facts"]
                report_md += f"- **Attack Stage:** {facts_data.attack_stage}\n"
                report_md += f"- **Assets Affected:** {', '.join(facts_data.affected_assets) or 'None'}\n"
                report_md += f"- **Requires Escalation:** {facts_data.requires_escalation}\n"
                report_md += f"- **Mitre Mapping:** {', '.join(verdict.mitre_mapping) or 'None'}\n"

            # Update alert fields in state
            alert.investigation_status = InvestigationStatus(new_status)
            alert.analyst_verdict = verdict.verdict
            alert.analyst_reasoning = verdict.reasoning
            
            # Save or update the alert in PostgreSQL
            pg_store.save_alert(alert)

            # Generate and associate an investigation_id
            inv_id = str(uuid.uuid4())
            
            # Extract related alerts from correlation results
            related_alerts = []
            if state.get("correlation_result"):
                c_res = state["correlation_result"]
                for cat in c_res.values():
                    for key_res in cat.values():
                        for tool_res in key_res.values():
                            if isinstance(tool_res, dict) and "alerts" in tool_res:
                                for a in tool_res["alerts"]:
                                    if "id" in a and a["id"] != alert.id:
                                        related_alerts.append(a["id"])
            related_alerts = list(set(related_alerts))

            # Map categories for database investigation persistence
            threat_intel = state.get("threat_intel_result") or {}
            inv_res = state.get("investigation_result") or {}
            net_intel = {
                "ips": inv_res.get("ips", {}),
                "domains": inv_res.get("domains", {})
            }
            end_intel = inv_res.get("endpoint", {})

            # Save investigation log to Postgres
            pg_store.save_investigation(
                inv_id=inv_id,
                trigger_alert_id=alert.id,
                classification=verdict.verdict,
                severity=verdict.severity_assessment,
                summary=verdict.reasoning,
                attack_type=state.get("triage_result", {}).get("attack_type", "unknown") if state.get("triage_result") else "unknown",
                mitre_tactics=alert.mitre_tactics,
                mitre_techniques=verdict.mitre_mapping,
                related_alert_ids=related_alerts,
                status="closed" if new_status in ("resolved", "false_positive") else "escalated",
                threat_intel=threat_intel,
                network_intel=net_intel,
                endpoint_intel=end_intel,
                report_markdown=report_md,
                report_json=verdict.model_dump()
            )

            # Update the alert with this investigation_id
            pg_store.update_alert(alert.id, investigation_id=inv_id)

            # Save incident memories (IOCs) to Postgres
            if state.get("facts") and state["facts"].extracted_iocs:
                iocs = state["facts"].extracted_iocs
                # IPs
                for ip in (iocs.ips or []):
                    score = None
                    rep_data = {}
                    if threat_intel.get("ips", {}).get(ip):
                        ip_intel = threat_intel["ips"][ip]
                        vt = ip_intel.get("virustotal", {})
                        ab = ip_intel.get("abuseipdb", {})
                        score = vt.get("reputation_score") or ab.get("abuse_confidence_score")
                        rep_data = ip_intel
                    
                    pg_store.save_incident_memory(
                        investigation_id=inv_id,
                        ioc_type="ip",
                        ioc_value=ip,
                        reputation_score=float(score) if score is not None else None,
                        reputation_data=rep_data,
                        tags=["correlation-triage"]
                    )
                # Domains
                for d in (iocs.domains or []):
                    pg_store.save_incident_memory(investigation_id=inv_id, ioc_type="domain", ioc_value=d, tags=["correlation-triage"])
                # Hashes
                for h in (iocs.hashes or []):
                    pg_store.save_incident_memory(investigation_id=inv_id, ioc_type="hash", ioc_value=h, tags=["correlation-triage"])

            # Process recommended response actions (Phase 10)
            from soc_analyst.responder.approval_queue import queue_response_action, execute_action
            import re
            
            ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
            
            for rec in (verdict.recommended_actions or []):
                rec_lower = rec.lower()
                action_type = None
                target = None
                requires_approval = True
                
                # Check for Block IP
                if any(x in rec_lower for x in ["block ip", "block the ip", "block source ip", "firewall drop", "drop ip"]):
                    # Try to extract IP from string
                    ip_match = ip_pattern.search(rec)
                    if ip_match:
                        target = ip_match.group(0)
                    elif alert.src_ip:
                        target = alert.src_ip
                        
                    if target:
                        if "guardduty" in alert.source or "aws" in alert.source:
                            action_type = "block_ip_aws"
                        elif "cloudflare" in alert.source:
                            action_type = "block_ip_cloudflare"
                        else:
                            action_type = "block_ip"
                            
                # Check for Disable User
                elif any(x in rec_lower for x in ["disable user", "disable account", "deactivate user", "disable okta"]):
                    words = rec.split()
                    for idx, w in enumerate(words):
                        if w.lower() in ["user", "account"] and idx + 1 < len(words):
                            potential_user = words[idx+1].strip(".,()\"'")
                            if potential_user and potential_user.lower() not in ["and", "or", "to", "for", "in", "is", "a", "the"]:
                                target = potential_user
                                break
                    if not target and alert.username:
                        target = alert.username
                    if target and target.lower() != "none":
                        action_type = "disable_user"
                        
                # Check for Isolate Endpoint
                elif any(x in rec_lower for x in ["isolate endpoint", "isolate host", "isolate defender", "isolate machine"]):
                    words = rec.split()
                    for idx, w in enumerate(words):
                        if w.lower() in ["endpoint", "host", "machine"] and idx + 1 < len(words):
                            potential_host = words[idx+1].strip(".,()\"'")
                            if potential_host and potential_host.lower() not in ["and", "or", "to", "for", "in", "is", "a", "the"]:
                                target = potential_host
                                break
                    if not target and alert.hostname:
                        target = alert.hostname
                    if target and target.lower() != "none":
                        action_type = "isolate_endpoint"
                        
                # Check for Ticket
                elif any(x in rec_lower for x in ["ticket", "jira", "linear"]):
                    action_type = "create_ticket"
                    target = alert.id
                    requires_approval = False
                    
                # Check for Watchlist
                elif "watchlist" in rec_lower:
                    action_type = "add_to_watchlist"
                    ip_match = ip_pattern.search(rec)
                    if ip_match:
                        target = ip_match.group(0)
                    else:
                        target = alert.src_ip or alert.username or "watchlist_item"
                    requires_approval = False
                    
                # If we mapped a valid action, queue it!
                if action_type and target:
                    try:
                        act_id = queue_response_action(
                            investigation_id=inv_id,
                            alert_id=alert.id,
                            action_type=action_type,
                            target=target,
                            reason=f"Recommended by AI Analyst: '{rec}'",
                            requires_approval=requires_approval
                        )
                        
                        # If it is auto-approved (does not require approval), execute it immediately
                        if not requires_approval:
                            asyncio.create_task(execute_action(act_id))
                    except Exception as e:
                        logger.error("Failed to queue or execute response action: %s", e)

            # Save report to Vector Database (ChromaDB)
            metadata = {
                "alert_id": alert.id,
                "timestamp": int(alert.timestamp.timestamp()),
                "severity": verdict.severity_assessment,
                "verdict": verdict.verdict,
                "rule_description": alert.rule_description or "none",
                "src_ip": alert.src_ip or "none",
                "username": alert.username or "none"
            }
            v_store.add_incident_report(alert.id, report_md, metadata)

        except Exception as exc:
            logger.error("Failed to persist workflow results to stores in report_node: %s", exc)
            errors.append(f"Persistence error: {exc}")

        return {
            "verdict": verdict,
            "enriched_context": enriched_context,
        }


    # ------------------------------------------------------------------
    # Routing functions
    # ------------------------------------------------------------------

    def route_after_gate(self, state: InvestigationState) -> str:
        """Route to block, fail or proceed depending on gate scans and facts extraction."""
        if state.get("is_blocked", False):
            return "blocked"
        if state.get("facts") is None and state.get("errors"):
            return "failed"
        return "clean"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _prepare_indicators(self, alert: NormalizedAlert, facts: ExtractedFacts) -> Dict[str, List[str]]:
        """Clean and extract indicators from facts and alert metadata."""
        ips = list(set([ip.strip() for ip in (facts.extracted_iocs.ips or []) if ip.strip()]))
        if alert.src_ip and alert.src_ip.strip() not in ips:
            ips.append(alert.src_ip.strip())
        if alert.dst_ip and alert.dst_ip.strip() not in ips:
            ips.append(alert.dst_ip.strip())

        domains = list(set([d.strip() for d in (facts.extracted_iocs.domains or []) if d.strip()]))
        hashes = list(set([h.strip() for h in (facts.extracted_iocs.hashes or []) if h.strip()]))

        assets = [a.strip() for a in (facts.affected_assets or []) if a.strip()]

        usernames = []
        if alert.username and alert.username.strip():
            usernames.append(alert.username.strip())
        for asset in assets:
            if not asset.replace(".", "").isdigit() and not any(h in asset.lower() for h in ["server", "client", "host", "win-"]):
                if asset not in usernames:
                    usernames.append(asset)

        hostnames = []
        if alert.hostname and alert.hostname.strip():
            hostnames.append(alert.hostname.strip())
        for asset in assets:
            if any(h in asset.lower() for h in ["server", "client", "host", "win-", "-pc"]):
                if asset not in hostnames:
                    hostnames.append(asset)

        return {
            "ips": ips,
            "domains": domains,
            "hashes": hashes,
            "usernames": usernames,
            "hostnames": hostnames
        }

    def _synthesize_enriched_context(self, state: InvestigationState) -> Dict[str, Any]:
        """Merge specialized node results into legacy enriched_context format for DecisionAnalyst compatibility."""
        enriched = {
            "ips": {},
            "domains": {},
            "hashes": {},
            "users": {},
            "hosts": {},
            "endpoint": {}
        }

        # 1. Merge from investigation_result
        inv = state.get("investigation_result") or {}
        for category in ["ips", "domains", "endpoint"]:
            if category in inv:
                for key, tools in inv[category].items():
                    if key not in enriched[category]:
                        enriched[category][key] = {}
                    enriched[category][key].update(tools)

        # 2. Merge from threat_intel_result
        intel = state.get("threat_intel_result") or {}
        for category in ["ips", "domains", "hashes"]:
            if category in intel:
                for key, tools in intel[category].items():
                    if key not in enriched[category]:
                        enriched[category][key] = {}
                    enriched[category][key].update(tools)

        # 3. Merge from correlation_result
        corr = state.get("correlation_result") or {}
        for category in ["ips", "users", "hosts"]:
            if category in corr:
                for key, tools in corr[category].items():
                    if key not in enriched[category]:
                        enriched[category][key] = {}
                    enriched[category][key].update(tools)

        return enriched

    # ------------------------------------------------------------------
    # Public Execution Entry point
    # ------------------------------------------------------------------

    async def run(self, alert: NormalizedAlert) -> AnalystVerdict:
        """Execute the full compiled LangGraph workflow on the alert."""
        self.pipeline.metrics.analysis_count += 1
        t0 = time.monotonic()

        initial_state: InvestigationState = {
            "alert": alert,
            "facts": None,
            "triage_result": None,
            "investigation_result": None,
            "threat_intel_result": None,
            "correlation_result": None,
            "enriched_context": {},
            "verdict": None,
            "errors": [],
            "is_blocked": False,
        }

        try:
            final_state = await self.graph.ainvoke(initial_state)
            verdict = final_state["verdict"]
        except Exception as exc:
            logger.error("LangGraph critical execution failure: %s", exc)
            self.pipeline.metrics.failure_count += 1
            self.pipeline.dead_letter_queue.append(
                DeadLetterEntry(alert_id=alert.id, error=f"Graph crash: {exc}")
            )
            verdict = AnalystVerdict(
                alert_id=alert.id,
                verdict="needs_investigation",
                severity_assessment="medium",
                reasoning=f"Critical workflow crash: {exc}.",
                recommended_actions=["Investigate workflow errors immediately"],
                auto_resolved=False,
            )
        finally:
            elapsed = time.monotonic() - t0
            self.pipeline.metrics.total_time_seconds += elapsed

        return verdict
