"""
Pydantic v2 schemas for the Dual-LLM Analyst Pipeline.

Three core models:

* ``ExtractedFacts`` -- output of the quarantined Fact Extractor LLM.
* ``AnalystVerdict`` -- output of the privileged Decision Analyst LLM.
* ``InjectionCheckResult`` -- output of the Injection Gate layers.
"""

from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field

__all__ = [
    "ExtractedIOCs",
    "ExtractedFacts",
    "AnalystVerdict",
    "InjectionCheckResult",
]


# ---------------------------------------------------------------------------
# Fact Extractor output
# ---------------------------------------------------------------------------

class ExtractedIOCs(BaseModel):
    """Indicators of Compromise extracted from alert content."""

    ips: List[str] = Field(default_factory=list, description="IP addresses.")
    domains: List[str] = Field(default_factory=list, description="Domain names.")
    hashes: List[str] = Field(default_factory=list, description="File hashes.")
    emails: List[str] = Field(default_factory=list, description="Email addresses.")


class ExtractedFacts(BaseModel):
    """Structured facts produced by the quarantined Fact Extractor LLM.

    The Fact Extractor has NO tool access; it merely converts raw alert
    content into this deterministic schema.
    """

    alert_id: str = Field(..., description="Alert identifier from the source.")
    summary: str = Field(
        ..., description="1-2 sentence summary of the alert."
    )
    key_indicators: List[str] = Field(
        default_factory=list,
        description="IOCs and suspicious patterns observed.",
    )
    affected_assets: List[str] = Field(
        default_factory=list,
        description="IPs, hostnames, and usernames involved.",
    )
    attack_stage: str = Field(
        default="unknown",
        description=(
            "Estimated MITRE ATT&CK kill-chain stage: "
            "recon / initial_access / execution / persistence / "
            "privilege_escalation / defense_evasion / credential_access / "
            "discovery / lateral_movement / collection / exfiltration / "
            "command_and_control / impact / unknown"
        ),
    )
    confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Model confidence in the extraction (0.0 - 1.0).",
    )
    requires_escalation: bool = Field(
        default=False,
        description="True if the alert should be escalated to a human analyst.",
    )
    extracted_iocs: ExtractedIOCs = Field(
        default_factory=ExtractedIOCs,
        description="Structured IOC breakdown.",
    )

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Decision Analyst output
# ---------------------------------------------------------------------------

class AnalystVerdict(BaseModel):
    """Verdict produced by the privileged Decision Analyst LLM.

    This model receives ONLY sanitized ``ExtractedFacts``, never raw alert
    content, enforcing the dual-LLM trust boundary.
    """

    alert_id: str = Field(..., description="Alert identifier.")
    verdict: str = Field(
        ...,
        description=(
            "Classification: true_positive / false_positive / benign / "
            "suspicious / needs_investigation"
        ),
    )
    severity_assessment: str = Field(
        default="medium",
        description="Assessed severity: critical / high / medium / low / informational.",
    )
    reasoning: str = Field(
        default="",
        description="Detailed explanation supporting the verdict.",
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Ordered list of recommended response actions.",
    )
    mitre_mapping: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g. T1078).",
    )
    similar_past_incidents: List[str] = Field(
        default_factory=list,
        description="IDs of similar historical incidents.",
    )
    auto_resolved: bool = Field(
        default=False,
        description="True if the pipeline auto-resolved without human input.",
    )

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Injection Gate output
# ---------------------------------------------------------------------------

class InjectionCheckResult(BaseModel):
    """Result from the Injection Gate's multi-layer analysis."""

    is_suspicious: bool = Field(
        default=False,
        description="True if injection patterns were detected.",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregate risk score across all layers (0.0 - 1.0).",
    )
    detected_patterns: List[str] = Field(
        default_factory=list,
        description="Names / descriptions of detected injection patterns.",
    )
    sanitized_content: str = Field(
        default="",
        description="Content after sanitisation (stripped of dangerous tokens).",
    )
    action: str = Field(
        default="allow",
        description="Gate decision: allow / quarantine / block.",
    )

    model_config = {"populate_by_name": True}
