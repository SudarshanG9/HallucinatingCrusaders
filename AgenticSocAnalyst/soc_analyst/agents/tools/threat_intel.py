"""
Threat intelligence lookup functions for SOC investigation.

Provides async helpers that query VirusTotal, AbuseIPDB, and AlienVault OTX.
When the corresponding API key environment variable is **not** set, each
function returns a realistic mock response so the rest of the pipeline can be
exercised without live credentials.

All functions are cached via the ``@ttl_cache`` decorator (24-hour TTL by
default) to avoid burning rate-limited API quotas.

Environment variables
---------------------
VT_API_KEY         – VirusTotal v3 API key
ABUSEIPDB_API_KEY  – AbuseIPDB v2 API key
OTX_API_KEY        – AlienVault OTX DirectConnect API key
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

import httpx

from soc_analyst.agents.tools.cache import ttl_cache

logger = logging.getLogger(__name__)

__all__ = ["check_virustotal", "check_abuseipdb", "check_otx"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HTTP_TIMEOUT = 10  # seconds


def _deterministic_int(seed: str, low: int = 0, high: int = 100) -> int:
    """Return a deterministic integer in [low, high] derived from *seed*."""
    digest = hashlib.sha256(seed.encode()).hexdigest()
    return low + int(digest[:8], 16) % (high - low + 1)


def _deterministic_pick(seed: str, options: list, count: int = 1) -> list:
    """Pick *count* items from *options* deterministically."""
    digest = hashlib.sha256(seed.encode()).hexdigest()
    idx_start = int(digest[:8], 16)
    picked: list = []
    for i in range(count):
        picked.append(options[(idx_start + i * 7) % len(options)])
    return picked


# ---------------------------------------------------------------------------
# 1.  VirusTotal
# ---------------------------------------------------------------------------

_VT_BASE = "https://www.virustotal.com/api/v3"

_VT_ENDPOINT_MAP = {
    "ip": "/ip_addresses/{indicator}",
    "domain": "/domains/{indicator}",
    "hash": "/files/{indicator}",
}


def _build_vt_mock(indicator: str, indicator_type: str) -> dict:
    """Return a realistic but synthetic VirusTotal-style result."""
    seed = f"vt:{indicator_type}:{indicator}"
    malicious = _deterministic_int(seed + ":mal", 0, 72)
    total = _deterministic_int(seed + ":total", 70, 93)
    reputation = max(0, min(100, 100 - int(malicious / total * 100))) if total else 50

    tag_pool = [
        "malware", "phishing", "botnet", "c2", "spam",
        "miner", "trojan", "ransomware", "scanner", "tor-exit",
    ]
    country_pool = ["US", "RU", "CN", "DE", "NL", "BR", "IN", "UA", "KR", "GB"]
    asn_pool = [
        "Google LLC", "Amazon.com Inc.", "DigitalOcean LLC",
        "Hetzner Online GmbH", "OVH SAS", "Cloudflare Inc.",
    ]

    return {
        "indicator": indicator,
        "type": indicator_type,
        "reputation_score": reputation,
        "malicious_count": malicious,
        "total_engines": total,
        "country": _deterministic_pick(seed + ":cc", country_pool)[0]
        if indicator_type in ("ip", "domain")
        else None,
        "as_owner": _deterministic_pick(seed + ":asn", asn_pool)[0]
        if indicator_type == "ip"
        else None,
        "tags": _deterministic_pick(seed + ":tags", tag_pool, count=_deterministic_int(seed + ":tc", 0, 4)),
        "last_analysis_date": datetime.now(timezone.utc).isoformat(),
    }


@ttl_cache(ttl_seconds=86_400)
async def check_virustotal(
    indicator: str,
    indicator_type: str = "ip",
) -> dict:
    """Look up an indicator on VirusTotal (v3 API).

    Parameters
    ----------
    indicator : str
        IP address, domain name, or file hash.
    indicator_type : str
        One of ``'ip'``, ``'domain'``, or ``'hash'``.

    Returns
    -------
    dict
        Normalised result with reputation data, or an ``error`` key on failure.
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        logger.info("VT_API_KEY not set – returning mock for %s", indicator)
        return _build_vt_mock(indicator, indicator_type)

    path_template = _VT_ENDPOINT_MAP.get(indicator_type)
    if path_template is None:
        return {"error": f"Unsupported indicator_type: {indicator_type}"}

    url = f"{_VT_BASE}{path_template.format(indicator=indicator)}"
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            reputation = max(0, min(100, 100 - int(malicious / total * 100))) if total else 50

            analysis_ts = attrs.get("last_analysis_date")
            last_analysis_iso = (
                datetime.fromtimestamp(analysis_ts, tz=timezone.utc).isoformat()
                if analysis_ts
                else None
            )

            return {
                "indicator": indicator,
                "type": indicator_type,
                "reputation_score": reputation,
                "malicious_count": malicious,
                "total_engines": total,
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "tags": attrs.get("tags", []),
                "last_analysis_date": last_analysis_iso,
            }
    except httpx.HTTPStatusError as exc:
        logger.error("VirusTotal HTTP %s for %s: %s", exc.response.status_code, indicator, exc)
        return {"error": f"VirusTotal HTTP {exc.response.status_code}", "indicator": indicator}
    except Exception as exc:  # noqa: BLE001
        logger.exception("VirusTotal request failed for %s", indicator)
        return {"error": str(exc), "indicator": indicator}


# ---------------------------------------------------------------------------
# 2.  AbuseIPDB
# ---------------------------------------------------------------------------

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def _build_abuseipdb_mock(ip: str) -> dict:
    """Return a realistic but synthetic AbuseIPDB-style result."""
    seed = f"abuseipdb:{ip}"
    confidence = _deterministic_int(seed + ":conf", 0, 100)
    total_reports = _deterministic_int(seed + ":rep", 0, 500)

    country_pool = ["US", "RU", "CN", "DE", "NL", "BR", "IN", "UA", "KR", "GB"]
    isp_pool = [
        "Comcast Cable Communications", "China Telecom", "Deutsche Telekom AG",
        "PJSC Rostelecom", "Amazon.com Inc.", "DigitalOcean LLC",
    ]
    domain_pool = [
        "comcast.net", "chinatelecom.cn", "t-online.de",
        "rostelecom.ru", "amazonaws.com", "digitalocean.com",
    ]

    return {
        "ip": ip,
        "abuse_confidence_score": confidence,
        "total_reports": total_reports,
        "country_code": _deterministic_pick(seed + ":cc", country_pool)[0],
        "isp": _deterministic_pick(seed + ":isp", isp_pool)[0],
        "domain": _deterministic_pick(seed + ":dom", domain_pool)[0],
        "is_public": True,
        "last_reported": datetime.now(timezone.utc).isoformat() if total_reports > 0 else None,
    }


@ttl_cache(ttl_seconds=86_400)
async def check_abuseipdb(ip: str) -> dict:
    """Look up an IP address on AbuseIPDB.

    Parameters
    ----------
    ip : str
        IPv4 or IPv6 address to query.

    Returns
    -------
    dict
        Abuse-confidence data, or an ``error`` key on failure.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.info("ABUSEIPDB_API_KEY not set – returning mock for %s", ip)
        return _build_abuseipdb_mock(ip)

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(_ABUSEIPDB_URL, headers=headers, params=params)
            resp.raise_for_status()
            d = resp.json().get("data", {})
            return {
                "ip": ip,
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country_code": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "domain": d.get("domain", ""),
                "is_public": d.get("isPublic", True),
                "last_reported": d.get("lastReportedAt"),
            }
    except httpx.HTTPStatusError as exc:
        logger.error("AbuseIPDB HTTP %s for %s: %s", exc.response.status_code, ip, exc)
        return {"error": f"AbuseIPDB HTTP {exc.response.status_code}", "ip": ip}
    except Exception as exc:  # noqa: BLE001
        logger.exception("AbuseIPDB request failed for %s", ip)
        return {"error": str(exc), "ip": ip}


# ---------------------------------------------------------------------------
# 3.  AlienVault OTX
# ---------------------------------------------------------------------------

_OTX_BASE = "https://otx.alienvault.com/api/v1"

_OTX_SECTION_MAP = {
    "ip": "/indicators/IPv4/{ioc}/general",
    "domain": "/indicators/domain/{ioc}/general",
    "hash": "/indicators/file/{ioc}/general",
    "url": "/indicators/url/{ioc}/general",
}


def _build_otx_mock(ioc: str, ioc_type: str) -> dict:
    """Return a realistic but synthetic OTX-style result."""
    seed = f"otx:{ioc_type}:{ioc}"
    pulse_count = _deterministic_int(seed + ":pc", 0, 50)
    reputation = _deterministic_int(seed + ":rep", 0, 100)

    tag_pool = [
        "apt", "malware", "phishing", "ransomware", "c2",
        "exploit", "botnet", "scanning", "brute-force", "spam",
    ]
    indicator_pool = [
        "198.51.100.23", "203.0.113.42", "evil-domain.example.com",
        "d41d8cd98f00b204e9800998ecf8427e", "phish.example.net",
    ]

    tag_count = _deterministic_int(seed + ":tc", 0, 4)
    rel_count = _deterministic_int(seed + ":rc", 0, 3)

    return {
        "ioc": ioc,
        "type": ioc_type,
        "pulse_count": pulse_count,
        "tags": _deterministic_pick(seed + ":tags", tag_pool, count=tag_count),
        "reputation": reputation,
        "related_indicators": _deterministic_pick(
            seed + ":rel", indicator_pool, count=rel_count
        ),
    }


@ttl_cache(ttl_seconds=86_400)
async def check_otx(ioc: str, ioc_type: str = "ip") -> dict:
    """Look up an IOC on AlienVault OTX DirectConnect.

    Parameters
    ----------
    ioc : str
        Indicator of compromise (IP, domain, hash, or URL).
    ioc_type : str
        One of ``'ip'``, ``'domain'``, ``'hash'``, or ``'url'``.

    Returns
    -------
    dict
        Pulse/reputation data, or an ``error`` key on failure.
    """
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        logger.info("OTX_API_KEY not set – returning mock for %s", ioc)
        return _build_otx_mock(ioc, ioc_type)

    path_template = _OTX_SECTION_MAP.get(ioc_type)
    if path_template is None:
        return {"error": f"Unsupported ioc_type: {ioc_type}"}

    url = f"{_OTX_BASE}{path_template.format(ioc=ioc)}"
    headers = {"X-OTX-API-KEY": api_key}

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            # Extract tags from pulses
            pulses = data.get("pulse_info", {}).get("pulses", [])
            tags: List[str] = []
            for pulse in pulses[:20]:
                tags.extend(pulse.get("tags", []))
            tags = list(dict.fromkeys(tags))[:10]  # deduplicate, cap at 10

            # Related indicators from first few pulses
            related: List[str] = []
            for pulse in pulses[:5]:
                for ind in pulse.get("indicators", [])[:3]:
                    val = ind if isinstance(ind, str) else ind.get("indicator", "")
                    if val and val != ioc:
                        related.append(val)
            related = list(dict.fromkeys(related))[:10]

            return {
                "ioc": ioc,
                "type": ioc_type,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "tags": tags,
                "reputation": data.get("reputation", 0),
                "related_indicators": related,
            }
    except httpx.HTTPStatusError as exc:
        logger.error("OTX HTTP %s for %s: %s", exc.response.status_code, ioc, exc)
        return {"error": f"OTX HTTP {exc.response.status_code}", "ioc": ioc}
    except Exception as exc:  # noqa: BLE001
        logger.exception("OTX request failed for %s", ioc)
        return {"error": str(exc), "ioc": ioc}
