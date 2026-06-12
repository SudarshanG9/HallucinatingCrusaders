"""
Privileged Decision Analyst -- the TRUSTED-side LLM in the Dual-LLM pipeline.

This component receives ONLY the sanitized ``ExtractedFacts`` produced by
the Fact Extractor.  It NEVER sees the raw alert content, enforcing the
trust boundary.  It has conceptual access to tools (threat intel, historical
queries) though tool integration is handled at the pipeline level.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from soc_analyst.agents.analyst.prompts import DECISION_ANALYST_SYSTEM_PROMPT
from soc_analyst.agents.analyst.schemas import AnalystVerdict, ExtractedFacts
from soc_analyst.agents.llm_router import LLMRouter
from soc_analyst.collector.models import NormalizedAlert

logger = logging.getLogger(__name__)

__all__ = ["DecisionAnalyst"]


# Severity name -> assessment string mapping for rule-based fallback
_SEVERITY_MAP: Dict[int, str] = {
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


class DecisionAnalyst:
    """Analyze sanitized facts and produce an ``AnalystVerdict``.

    Parameters
    ----------
    llm : LLMRouter
        Router configured for the privileged (trusted) LLM.
    """

    def __init__(self, llm: LLMRouter) -> None:
        self._llm = llm

    async def analyze(
        self,
        facts: ExtractedFacts,
        alert: NormalizedAlert,
        enriched_context: Optional[Dict[str, Any]] = None,
    ) -> AnalystVerdict:
        """Produce a verdict from sanitized facts, alert metadata, and enriched context.

        The prompt sent to the LLM contains ONLY:
        - The ``ExtractedFacts`` JSON (already sanitised).
        - Safe non-content metadata from the alert (severity, source, MITRE IDs).
        - The structured, sanitized ``enriched_context`` JSON.

        It does NOT contain ``alert.raw_content``.

        Parameters
        ----------
        facts : ExtractedFacts
        alert : NormalizedAlert
        enriched_context : Optional[Dict[str, Any]]

        Returns
        -------
        AnalystVerdict
        """
        prompt = self._build_prompt(facts, alert, enriched_context)

        try:
            raw_response = await self._llm.call(
                prompt=prompt,
                system_prompt=DECISION_ANALYST_SYSTEM_PROMPT,
            )
            verdict = self._parse_response(raw_response, alert.id)
            logger.info(
                "DecisionAnalyst  alert=%s  verdict=%s  severity=%s  auto=%s",
                alert.id,
                verdict.verdict,
                verdict.severity_assessment,
                verdict.auto_resolved,
            )
            return verdict

        except Exception as exc:
            logger.error(
                "DecisionAnalyst LLM call failed for alert %s: %s -- "
                "falling back to rule-based verdict",
                alert.id,
                exc,
            )
            return self._rule_based_verdict(facts, alert)

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_prompt(
        facts: ExtractedFacts,
        alert: NormalizedAlert,
        enriched_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Build the analyst prompt from facts, metadata, and enriched context."""
        # Serialise facts to JSON (this is the ONLY data the LLM sees)
        facts_json = facts.model_dump_json(indent=2)

        parts = [
            "Analyze the following extracted facts and enriched context, and provide your verdict.",
            "",
            "== EXTRACTED FACTS ==",
            facts_json,
            "",
        ]

        if enriched_context:
            parts.extend([
                "== ENRICHED CONTEXT (Threat Intel, Network, Endpoint, Cross-Vendor Logs) ==",
                json.dumps(enriched_context, indent=2, default=str),
                "",
            ])

        parts.extend([
            "== ALERT METADATA (safe, non-content fields) ==",
            f"Source: {alert.source}",
            f"Vendor: {alert.vendor}",
            f"Severity: {alert.severity.name} ({alert.severity.value})",
            f"Rule ID: {alert.rule_id or 'N/A'}",
            f"Rule Description: {alert.rule_description or 'N/A'}",
        ])
        if alert.mitre_tactics:
            parts.append(f"MITRE Tactics: {', '.join(alert.mitre_tactics)}")
        if alert.mitre_techniques:
            parts.append(f"MITRE Techniques: {', '.join(alert.mitre_techniques)}")

        parts.append("")
        parts.append(
            "Based on these facts, metadata, and enriched context, provide your verdict, "
            "severity assessment, reasoning, and recommended actions."
        )
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_response(raw: str, alert_id: str) -> AnalystVerdict:
        """Parse the LLM's JSON response into an ``AnalystVerdict``."""
        text = raw.strip()
        # Strip markdown fences
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            text = "\n".join(lines)

        data: Dict[str, Any] = json.loads(text)

        return AnalystVerdict(
            alert_id=data.get("alert_id", alert_id),
            verdict=data.get("verdict", "needs_investigation"),
            severity_assessment=data.get("severity_assessment", "medium"),
            reasoning=data.get("reasoning", ""),
            recommended_actions=data.get("recommended_actions", []),
            mitre_mapping=data.get("mitre_mapping", []),
            similar_past_incidents=data.get("similar_past_incidents", []),
            auto_resolved=bool(data.get("auto_resolved", False)),
        )

    # ------------------------------------------------------------------
    # Rule-based fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_based_verdict(
        facts: ExtractedFacts, alert: NormalizedAlert
    ) -> AnalystVerdict:
        """Deterministic fallback when the LLM is unavailable."""
        sev_value = alert.severity.value
        severity_str = _SEVERITY_MAP.get(sev_value, "medium")

        # Determine verdict from severity + confidence + escalation flag
        if facts.requires_escalation or sev_value >= 5:
            verdict = "true_positive"
            actions = [
                "Isolate affected host(s) immediately",
                "Notify incident response team",
                "Preserve forensic evidence",
                "Block source IPs at perimeter",
            ]
            auto = False
        elif sev_value >= 4 or facts.confidence_score >= 0.8:
            verdict = "suspicious"
            actions = [
                "Investigate source IP reputation",
                "Review authentication logs for affected user",
                "Enable enhanced monitoring on target host",
            ]
            auto = False
        elif sev_value >= 3:
            verdict = "needs_investigation"
            actions = [
                "Review alert details during next triage cycle",
                "Check for similar recent alerts",
            ]
            auto = False
        elif sev_value == 2:
            verdict = "benign"
            actions = ["Continue standard monitoring"]
            auto = True
        else:
            verdict = "false_positive"
            actions = ["No action required"]
            auto = True

        return AnalystVerdict(
            alert_id=alert.id,
            verdict=verdict,
            severity_assessment=severity_str,
            reasoning=(
                f"Rule-based fallback verdict. Alert severity={alert.severity.name}, "
                f"confidence={facts.confidence_score:.2f}, "
                f"attack_stage={facts.attack_stage}, "
                f"escalation_required={facts.requires_escalation}."
            ),
            recommended_actions=actions,
            mitre_mapping=alert.mitre_techniques,
            similar_past_incidents=[],
            auto_resolved=auto,
        )
