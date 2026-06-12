"""
Cross-vendor intelligence tool functions.

Queries the ``AlertCollector`` in-memory alert store to correlate alerts
across different vendor connectors (Okta, AWS GuardDuty, Microsoft Defender).
All functions are async and return plain JSON-safe dicts.

No ``@ttl_cache`` is applied because these operate on local in-memory data
and should always reflect the latest collector state.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from soc_analyst.collector.main import AlertCollector
from soc_analyst.collector.models import NormalizedAlert

__all__ = [
    "search_okta_user",
    "search_guardduty_ip",
    "search_defender_host",
    "search_all_vendors_for_ip",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert_timestamp_iso(alert: NormalizedAlert) -> str:
    """Return the alert timestamp as an ISO-8601 string."""
    return alert.timestamp.isoformat()


def _severity_value(alert: NormalizedAlert) -> int:
    """Return the integer value of the alert severity."""
    return alert.severity.value


# ---------------------------------------------------------------------------
# 1. Okta user search
# ---------------------------------------------------------------------------

async def search_okta_user(email_or_username: str) -> Dict[str, Any]:
    """Search Okta alerts for a specific user (email or username).

    Queries alerts from the ``okta`` (live) or ``mock_okta`` source and
    filters on the ``username`` field using a case-insensitive comparison.

    Args:
        email_or_username: The email address or username to search for.

    Returns:
        A dict with ``query``, ``match_count``, ``alerts`` (list of dicts),
        and ``vendor``.
    """
    logger.info("Searching Okta alerts for user: %s", email_or_username)

    collector = AlertCollector()
    # Try live connector first, fall back to mock
    okta_alerts: List[NormalizedAlert] = collector.get_alerts_by_source("okta")
    if not okta_alerts:
        okta_alerts = collector.get_alerts_by_source("mock_okta")

    query_lower = email_or_username.lower()
    matches = [
        a for a in okta_alerts
        if a.username and a.username.lower() == query_lower
    ]

    alert_dicts = [
        {
            "id": a.id,
            "timestamp": _alert_timestamp_iso(a),
            "severity": _severity_value(a),
            "rule_description": a.rule_description,
            "src_ip": a.src_ip,
            "verdict": a.analyst_verdict,
        }
        for a in matches
    ]

    logger.info(
        "Okta user search for '%s' returned %d match(es) out of %d alert(s)",
        email_or_username,
        len(matches),
        len(okta_alerts),
    )

    return {
        "query": email_or_username,
        "match_count": len(matches),
        "alerts": alert_dicts,
        "vendor": "Okta",
    }


# ---------------------------------------------------------------------------
# 2. GuardDuty IP search
# ---------------------------------------------------------------------------

async def search_guardduty_ip(ip: str) -> Dict[str, Any]:
    """Search AWS GuardDuty alerts for a specific IP address.

    Matches against both ``src_ip`` and ``dst_ip`` fields.

    Args:
        ip: The IP address to search for.

    Returns:
        A dict with ``query``, ``match_count``, ``alerts`` (list of dicts),
        and ``vendor``.
    """
    logger.info("Searching GuardDuty alerts for IP: %s", ip)

    collector = AlertCollector()
    gd_alerts: List[NormalizedAlert] = collector.get_alerts_by_source("mock_guardduty")

    matches = [
        a for a in gd_alerts
        if a.src_ip == ip or a.dst_ip == ip
    ]

    alert_dicts = [
        {
            "id": a.id,
            "timestamp": _alert_timestamp_iso(a),
            "severity": _severity_value(a),
            "rule_description": a.rule_description,
            "hostname": a.hostname,
        }
        for a in matches
    ]

    logger.info(
        "GuardDuty IP search for '%s' returned %d match(es) out of %d alert(s)",
        ip,
        len(matches),
        len(gd_alerts),
    )

    return {
        "query": ip,
        "match_count": len(matches),
        "alerts": alert_dicts,
        "vendor": "AWS GuardDuty",
    }


# ---------------------------------------------------------------------------
# 3. Defender host search
# ---------------------------------------------------------------------------

async def search_defender_host(hostname: str) -> Dict[str, Any]:
    """Search Microsoft Defender alerts for a specific hostname.

    Uses a case-insensitive comparison on the ``hostname`` field.

    Args:
        hostname: The hostname to search for.

    Returns:
        A dict with ``query``, ``match_count``, ``alerts`` (list of dicts),
        and ``vendor``.
    """
    logger.info("Searching Defender alerts for host: %s", hostname)

    collector = AlertCollector()
    defender_alerts: List[NormalizedAlert] = collector.get_alerts_by_source(
        "mock_defender"
    )

    hostname_lower = hostname.lower()
    matches = [
        a for a in defender_alerts
        if a.hostname and a.hostname.lower() == hostname_lower
    ]

    alert_dicts = [
        {
            "id": a.id,
            "timestamp": _alert_timestamp_iso(a),
            "severity": _severity_value(a),
            "rule_description": a.rule_description,
            "username": a.username,
            "src_ip": a.src_ip,
        }
        for a in matches
    ]

    logger.info(
        "Defender host search for '%s' returned %d match(es) out of %d alert(s)",
        hostname,
        len(matches),
        len(defender_alerts),
    )

    return {
        "query": hostname,
        "match_count": len(matches),
        "alerts": alert_dicts,
        "vendor": "Microsoft Defender",
    }


# ---------------------------------------------------------------------------
# 4. Cross-vendor IP search
# ---------------------------------------------------------------------------

async def search_all_vendors_for_ip(ip: str) -> Dict[str, Any]:
    """Search ALL vendor sources for alerts mentioning a given IP address.

    Matches against both ``src_ip`` and ``dst_ip`` fields across every
    alert in the collector's store.

    Args:
        ip: The IP address to search for.

    Returns:
        A dict with ``ip``, ``total_matches``, ``by_vendor`` (vendor → count),
        and ``alerts`` (list of dicts).
    """
    logger.info("Cross-vendor IP search for: %s", ip)

    collector = AlertCollector()
    all_alerts: List[NormalizedAlert] = collector.get_all_alerts()

    matches = [
        a for a in all_alerts
        if a.src_ip == ip or a.dst_ip == ip
    ]

    by_vendor: Dict[str, int] = {}
    for a in matches:
        by_vendor[a.vendor] = by_vendor.get(a.vendor, 0) + 1

    alert_dicts = [
        {
            "id": a.id,
            "source": a.source,
            "vendor": a.vendor,
            "timestamp": _alert_timestamp_iso(a),
            "severity": _severity_value(a),
            "rule_description": a.rule_description,
        }
        for a in matches
    ]

    logger.info(
        "Cross-vendor IP search for '%s' returned %d match(es) across %d vendor(s)",
        ip,
        len(matches),
        len(by_vendor),
    )

    return {
        "ip": ip,
        "total_matches": len(matches),
        "by_vendor": by_vendor,
        "alerts": alert_dicts,
    }
