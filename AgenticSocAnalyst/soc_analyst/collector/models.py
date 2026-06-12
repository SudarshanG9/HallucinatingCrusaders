"""
Normalized alert model used across the entire SOC Analyst platform.

Every connector (Wazuh, GuardDuty, Okta, Defender, ...) transforms its
vendor-specific alert into this common schema before storage and analysis.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SeverityLevel(int, enum.Enum):
    """Alert severity on a 1-5 scale (maps roughly to Wazuh levels)."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class InvestigationStatus(str, enum.Enum):
    """Lifecycle status of an alert investigation."""

    NEW = "new"
    ENRICHED = "enriched"
    INVESTIGATING = "investigating"
    AWAITING_VERDICT = "awaiting_verdict"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"


class NormalizedAlert(BaseModel):
    """Vendor-agnostic alert representation.

    Fields
    ------
    id : str
        Unique alert identifier (UUID4 string).
    source : str
        Originating connector name, e.g. ``"wazuh"``, ``"guardduty"``.
    vendor : str
        Upstream vendor name (``"Wazuh"``, ``"AWS"``, ``"Okta"``).
    timestamp : datetime
        When the event originally occurred (UTC).
    received_at : datetime
        When the collector ingested the alert (UTC).
    severity : SeverityLevel
        Normalised severity (1-5).
    raw_content : dict
        Full original payload preserved for audit / re-analysis.
    rule_id : str | None
        Vendor rule identifier (e.g. Wazuh rule 5710).
    rule_description : str | None
        Human-readable rule description.
    src_ip : str | None
        Source IP address extracted from the event.
    dst_ip : str | None
        Destination IP address extracted from the event.
    username : str | None
        Username associated with the event.
    hostname : str | None
        Hostname where the event originated.
    mitre_tactics : list[str]
        MITRE ATT&CK tactic IDs (e.g. ``["TA0001"]``).
    mitre_techniques : list[str]
        MITRE ATT&CK technique IDs (e.g. ``["T1078"]``).
    investigation_status : InvestigationStatus
        Current lifecycle state.
    analyst_verdict : str | None
        Final verdict set by human or AI analyst.
    analyst_reasoning : str | None
        Free-text explanation supporting the verdict.
    tags : list[str]
        Arbitrary tags for filtering / grouping.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique alert identifier (UUID4).")
    source: str = Field(..., description="Originating connector name.")
    vendor: str = Field(..., description="Upstream vendor name.")
    timestamp: datetime = Field(..., description="Original event time (UTC).")
    received_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Ingestion time (UTC).",
    )
    severity: SeverityLevel = Field(..., description="Normalised severity 1-5.")
    raw_content: str = Field(
        default="",
        description="Full original payload as JSON string.",
    )
    rule_id: Optional[str] = Field(None, description="Vendor rule identifier.")
    rule_description: Optional[str] = Field(None, description="Rule description.")
    src_ip: Optional[str] = Field(None, description="Source IP address.")
    dst_ip: Optional[str] = Field(None, description="Destination IP address.")
    username: Optional[str] = Field(None, description="Associated username.")
    hostname: Optional[str] = Field(None, description="Originating hostname.")
    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE tactic IDs.")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE technique IDs.")
    investigation_status: InvestigationStatus = Field(
        default=InvestigationStatus.NEW,
        description="Current investigation state.",
    )
    analyst_verdict: Optional[str] = Field(None, description="Analyst verdict.")
    analyst_reasoning: Optional[str] = Field(None, description="Verdict reasoning.")
    tags: List[str] = Field(default_factory=list, description="Arbitrary tags.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "source": "wazuh",
                    "vendor": "Wazuh",
                    "timestamp": "2026-06-01T12:00:00Z",
                    "severity": 4,
                    "raw_content": {"rule": {"id": "5710"}},
                    "rule_id": "5710",
                    "rule_description": "sshd: Attempt to login using a denied user.",
                    "src_ip": "192.168.1.100",
                    "dst_ip": "10.0.0.5",
                    "username": "root",
                    "hostname": "web-server-01",
                    "mitre_tactics": ["TA0001"],
                    "mitre_techniques": ["T1078"],
                    "investigation_status": "new",
                    "tags": ["brute_force", "ssh"],
                }
            ]
        }
    }


class AlertBatch(BaseModel):
    """A batch of alerts returned by a connector during a single fetch cycle."""

    alerts: List[NormalizedAlert] = Field(
        default_factory=list, description="List of normalised alerts."
    )
    source: str = Field(..., description="Connector name that produced this batch.")
    fetched_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this batch was fetched (UTC).",
    )


__all__ = [
    "SeverityLevel",
    "InvestigationStatus",
    "NormalizedAlert",
    "AlertBatch",
]

