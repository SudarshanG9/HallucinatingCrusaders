"""
Full Dual-LLM Analyst Pipeline orchestrator.

Wires together:

    InjectionGate --> FactExtractor (quarantined LLM)
                         |
                         v
                  DecisionAnalyst (privileged LLM)

Provides single-alert and batch-processing entry points, a dead-letter
queue for failed analyses, and operational metrics.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from soc_analyst.agents.analyst.decision_analyst import DecisionAnalyst
from soc_analyst.agents.analyst.fact_extractor import FactExtractor
from soc_analyst.agents.analyst.injection_gate import InjectionGate
from soc_analyst.agents.analyst.schemas import AnalystVerdict, ExtractedFacts
from soc_analyst.agents.llm_router import LLMRouter
from soc_analyst.collector.models import NormalizedAlert
from soc_analyst.config import settings
from soc_analyst.agents.tools import (
    check_virustotal,
    check_abuseipdb,
    check_otx,
    dns_lookup,
    whois_lookup,
    geoip_lookup,
    get_agent_processes,
    get_file_integrity_events,
    get_user_activity,
    search_okta_user,
    search_defender_host,
    search_all_vendors_for_ip,
)

logger = logging.getLogger(__name__)

__all__ = ["AnalystPipeline", "PipelineMetrics"]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class PipelineMetrics:
    """Lightweight operational counters for the pipeline."""

    analysis_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    injection_blocks: int = 0
    total_time_seconds: float = 0.0

    @property
    def avg_time(self) -> float:
        """Average analysis time in seconds."""
        if self.analysis_count == 0:
            return 0.0
        return self.total_time_seconds / self.analysis_count

    def summary(self) -> Dict[str, Any]:
        """Return metrics as a plain dict."""
        return {
            "analysis_count": self.analysis_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "injection_blocks": self.injection_blocks,
            "avg_time_seconds": round(self.avg_time, 3),
            "total_time_seconds": round(self.total_time_seconds, 3),
        }


# ---------------------------------------------------------------------------
# Dead-letter entry
# ---------------------------------------------------------------------------

@dataclass
class DeadLetterEntry:
    """Record of a failed analysis attempt."""

    alert_id: str
    error: str
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class AnalystPipeline:
    """Orchestrate the Dual-LLM alert analysis pipeline.

    Parameters
    ----------
    llm : LLMRouter, optional
        LLM router instance.  If not provided, one is created from
        ``settings.llm``.
    gate : InjectionGate, optional
        Injection gate instance.  Defaults to a new ``InjectionGate()``.
    """

    def __init__(
        self,
        llm: Optional[LLMRouter] = None,
        gate: Optional[InjectionGate] = None,
    ) -> None:
        # Build default LLM router from config if none supplied
        if llm is None:
            from soc_analyst.agents.llm_router import LLMConfig as RouterLLMConfig

            cfg = settings.llm
            router_cfg = RouterLLMConfig(
                provider=cfg.provider,
                model_name=cfg.model_name,
                api_key=cfg.api_key,
                base_url=cfg.base_url,
                temperature=cfg.temperature,
                max_tokens=cfg.max_tokens,
            )
            llm = LLMRouter(router_cfg)

        self._llm = llm
        self._gate = gate or InjectionGate()
        self._fact_extractor = FactExtractor(llm=self._llm, gate=self._gate)
        self._decision_analyst = DecisionAnalyst(llm=self._llm)

        self.metrics = PipelineMetrics()
        self.dead_letter_queue: List[DeadLetterEntry] = []

        logger.info("AnalystPipeline initialised")

    # ------------------------------------------------------------------
    # Single alert
    # ------------------------------------------------------------------

    async def analyze_alert(self, alert: NormalizedAlert) -> AnalystVerdict:
        """Run the full pipeline for a single alert.

        Delegates execution to the stateful LangGraph workflows module.

        Parameters
        ----------
        alert : NormalizedAlert

        Returns
        -------
        AnalystVerdict
        """
        workflow = getattr(self, "_workflow", None)
        if workflow is None:
            from soc_analyst.agents.workflows.investigation_graph import InvestigationWorkflow
            workflow = InvestigationWorkflow(self)
            self._workflow = workflow

        return await workflow.run(alert)

    async def _enrich_context(
        self, alert: NormalizedAlert, facts: ExtractedFacts
    ) -> Dict[str, Any]:
        """Query threat intel, network, endpoint, and cross-vendor logs in parallel."""
        # Clean and extract indicators
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

        # Build parallel tasks
        tasks = []
        task_info = []  # list of tuples (category, key, tool_name)

        # 1. IPs
        for ip in ips[:3]:
            tasks.append(check_abuseipdb(ip))
            task_info.append(("ips", ip, "abuseipdb"))
            tasks.append(check_virustotal(ip, "ip"))
            task_info.append(("ips", ip, "virustotal"))
            tasks.append(check_otx(ip, "ip"))
            task_info.append(("ips", ip, "otx"))
            tasks.append(geoip_lookup(ip))
            task_info.append(("ips", ip, "geoip"))
            tasks.append(search_all_vendors_for_ip(ip))
            task_info.append(("ips", ip, "cross_vendor_alerts"))

        # 2. Domains
        for domain in domains[:3]:
            tasks.append(dns_lookup(domain))
            task_info.append(("domains", domain, "dns"))
            tasks.append(whois_lookup(domain))
            task_info.append(("domains", domain, "whois"))
            tasks.append(check_virustotal(domain, "domain"))
            task_info.append(("domains", domain, "virustotal"))
            tasks.append(check_otx(domain, "domain"))
            task_info.append(("domains", domain, "otx"))

        # 3. Hashes
        for h in hashes[:3]:
            tasks.append(check_virustotal(h, "hash"))
            task_info.append(("hashes", h, "virustotal"))
            tasks.append(check_otx(h, "hash"))
            task_info.append(("hashes", h, "otx"))

        # 4. Users
        for user in usernames[:3]:
            tasks.append(search_okta_user(user))
            task_info.append(("users", user, "okta_search"))

        # 5. Hosts
        for host in hostnames[:3]:
            tasks.append(search_defender_host(host))
            task_info.append(("hosts", host, "defender_search"))

        # 6. Endpoint (Wazuh specific)
        agent_id = None
        if alert.source == "wazuh" or alert.vendor.lower() == "wazuh":
            try:
                import json
                raw = json.loads(alert.raw_content)
                agent_id = raw.get("agent", {}).get("id")
            except Exception:
                pass

        if agent_id:
            tasks.append(get_agent_processes(agent_id))
            task_info.append(("endpoint", agent_id, "processes"))
            tasks.append(get_file_integrity_events(agent_id))
            task_info.append(("endpoint", agent_id, "fim_events"))
            if alert.username:
                tasks.append(get_user_activity(agent_id, alert.username))
                task_info.append(("endpoint", f"{agent_id}:{alert.username}", "user_activity"))

        if not tasks:
            return {}

        logger.info("Gathering %d enrichment tasks in parallel...", len(tasks))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Compile structured enriched context
        enriched = {
            "ips": {},
            "domains": {},
            "hashes": {},
            "users": {},
            "hosts": {},
            "endpoint": {}
        }

        for (category, key, tool), res in zip(task_info, results):
            if isinstance(res, Exception):
                logger.error("Enrichment failed for %s/%s/%s: %s", category, key, tool, res)
                res_val = {"error": str(res)}
            else:
                res_val = res

            if key not in enriched[category]:
                enriched[category][key] = {}

            enriched[category][key][tool] = res_val

        return enriched


    # ------------------------------------------------------------------
    # Batch processing
    # ------------------------------------------------------------------

    async def analyze_batch(
        self,
        alerts: List[NormalizedAlert],
        concurrency: int = 5,
    ) -> List[AnalystVerdict]:
        """Analyze multiple alerts with bounded concurrency.

        Parameters
        ----------
        alerts : list[NormalizedAlert]
            Alerts to analyze.
        concurrency : int
            Maximum number of concurrent analyses (default 5).

        Returns
        -------
        list[AnalystVerdict]
            Verdicts in the same order as the input alerts.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _guarded(alert: NormalizedAlert) -> AnalystVerdict:
            async with semaphore:
                return await self.analyze_alert(alert)

        logger.info(
            "Starting batch analysis  count=%d  concurrency=%d",
            len(alerts),
            concurrency,
        )
        t0 = time.monotonic()

        verdicts = await asyncio.gather(
            *[_guarded(a) for a in alerts],
            return_exceptions=False,
        )

        elapsed = time.monotonic() - t0
        logger.info(
            "Batch analysis complete  count=%d  elapsed=%.2fs  "
            "avg=%.2fs  failures=%d",
            len(alerts),
            elapsed,
            elapsed / max(len(alerts), 1),
            self.metrics.failure_count,
        )
        return list(verdicts)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def get_metrics(self) -> Dict[str, Any]:
        """Return current pipeline metrics."""
        return self.metrics.summary()

    def get_dead_letters(self) -> List[Dict[str, Any]]:
        """Return all dead-letter queue entries."""
        return [
            {
                "alert_id": entry.alert_id,
                "error": entry.error,
                "timestamp": entry.timestamp,
            }
            for entry in self.dead_letter_queue
        ]

    def clear_dead_letters(self) -> int:
        """Clear the dead-letter queue and return the number removed."""
        count = len(self.dead_letter_queue)
        self.dead_letter_queue.clear()
        return count
