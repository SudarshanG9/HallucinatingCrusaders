"""
Network intelligence lookup functions for SOC investigation.

Provides async helpers to resolve DNS records, query WHOIS data,
and geolocate IP addresses.  Every function returns a plain dict
(JSON-safe) and uses the shared ``@ttl_cache`` decorator so that
repeated lookups against the same target hit the in-memory cache
instead of the upstream service.

Usage::

    from soc_analyst.agents.tools.network_intel import (
        dns_lookup, whois_lookup, geoip_lookup,
    )

    result = await dns_lookup("example.com")
    result = await whois_lookup("example.com")
    result = await geoip_lookup("8.8.8.8")
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional

import httpx

from soc_analyst.agents.tools.cache import ttl_cache

logger = logging.getLogger(__name__)

__all__ = ["dns_lookup", "whois_lookup", "geoip_lookup"]


# ---------------------------------------------------------------------------
# 1. DNS lookup
# ---------------------------------------------------------------------------

@ttl_cache(ttl_seconds=3600)
async def dns_lookup(domain: str) -> Dict[str, Any]:
    """Resolve a domain name to its A records using the system resolver.

    Uses :func:`socket.getaddrinfo` (wrapped in ``asyncio.to_thread``
    to avoid blocking the event loop) to obtain IPv4 addresses.

    Parameters
    ----------
    domain : str
        The domain name to resolve (e.g. ``"example.com"``).

    Returns
    -------
    dict
        ``domain``  – the queried domain.
        ``a_records`` – list of resolved IPv4 address strings.
        ``error`` – error message string, or ``None`` on success.
    """
    logger.info("DNS lookup for domain: %s", domain)

    try:
        addr_infos = await asyncio.to_thread(
            socket.getaddrinfo,
            domain,
            None,
            socket.AF_INET,      # IPv4 only → A records
            socket.SOCK_STREAM,
        )

        # getaddrinfo returns tuples: (family, type, proto, canonname, sockaddr)
        # sockaddr for AF_INET is (address, port)
        a_records: List[str] = sorted(
            {info[4][0] for info in addr_infos}
        )

        logger.info(
            "DNS lookup for %s resolved to %d A record(s)", domain, len(a_records)
        )
        return {
            "domain": domain,
            "a_records": a_records,
            "error": None,
        }

    except socket.gaierror as exc:
        logger.warning("DNS lookup failed for %s: %s", domain, exc)
        return {
            "domain": domain,
            "a_records": [],
            "error": f"DNS resolution failed: {exc}",
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error during DNS lookup for %s: %s", domain, exc)
        return {
            "domain": domain,
            "a_records": [],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# 2. WHOIS lookup
# ---------------------------------------------------------------------------

def _safe_str(value: Any) -> Optional[str]:
    """Coerce a value to a JSON-safe string, handling lists and datetimes."""
    if value is None:
        return None
    if isinstance(value, list):
        # python-whois sometimes returns a list of dates
        return str(value[0]) if value else None
    return str(value)


@ttl_cache(ttl_seconds=86_400)
async def whois_lookup(target: str) -> Dict[str, Any]:
    """Query WHOIS information for a domain or IP address.

    Attempts to use the ``python-whois`` library.  If the library is
    not installed the function returns a **mock** result instead of
    raising, so callers always get a well-formed dict.

    Parameters
    ----------
    target : str
        A domain name (e.g. ``"example.com"``) or IP address.

    Returns
    -------
    dict
        ``target``          – the queried target.
        ``registrar``       – registrar name or ``None``.
        ``creation_date``   – creation date string or ``None``.
        ``expiration_date`` – expiration date string or ``None``.
        ``registrant``      – registrant org/name or ``None``.
        ``name_servers``    – list of name-server hostnames.
        ``error``           – error message string, or ``None``.
    """
    logger.info("WHOIS lookup for target: %s", target)

    try:
        import whois  # type: ignore[import-untyped]  # noqa: F811
    except ImportError:
        logger.warning(
            "python-whois is not installed – returning mock WHOIS result for %s",
            target,
        )
        return {
            "target": target,
            "registrar": "Mock Registrar (python-whois not installed)",
            "creation_date": "2020-01-01T00:00:00",
            "expiration_date": "2030-01-01T00:00:00",
            "registrant": "Mock Registrant",
            "name_servers": ["ns1.mock.example.com", "ns2.mock.example.com"],
            "error": "python-whois library is not installed; returning mock data",
        }

    try:
        w = await asyncio.to_thread(whois.whois, target)

        # Normalise name_servers to a plain list of strings
        raw_ns = w.name_servers or []
        if isinstance(raw_ns, str):
            raw_ns = [raw_ns]
        name_servers: List[str] = sorted(
            {ns.lower() for ns in raw_ns if isinstance(ns, str)}
        )

        result: Dict[str, Any] = {
            "target": target,
            "registrar": _safe_str(w.registrar),
            "creation_date": _safe_str(w.creation_date),
            "expiration_date": _safe_str(w.expiration_date),
            "registrant": _safe_str(getattr(w, "org", None)),
            "name_servers": name_servers,
            "error": None,
        }

        logger.info("WHOIS lookup for %s completed successfully", target)
        return result

    except Exception as exc:  # noqa: BLE001
        logger.error("WHOIS lookup failed for %s: %s", target, exc)
        return {
            "target": target,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "registrant": None,
            "name_servers": [],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# 3. GeoIP lookup
# ---------------------------------------------------------------------------

_GEOIP_API_URL = "http://ip-api.com/json/{ip}"
_GEOIP_TIMEOUT = 10  # seconds


@ttl_cache(ttl_seconds=86_400)
async def geoip_lookup(ip: str) -> Dict[str, Any]:
    """Geolocate an IP address using the free ip-api.com service.

    Parameters
    ----------
    ip : str
        An IPv4 or IPv6 address to geolocate.

    Returns
    -------
    dict
        ``ip``           – the queried IP address.
        ``country``      – country name.
        ``country_code`` – two-letter ISO country code.
        ``region``       – region / state name.
        ``city``         – city name.
        ``isp``          – Internet Service Provider.
        ``org``          – organisation name.
        ``as_number``    – Autonomous System number + name.
        ``lat``          – latitude.
        ``lon``          – longitude.
        ``error``        – error message string, or ``None``.
    """
    logger.info("GeoIP lookup for IP: %s", ip)

    try:
        async with httpx.AsyncClient(timeout=_GEOIP_TIMEOUT) as client:
            response = await client.get(_GEOIP_API_URL.format(ip=ip))
            response.raise_for_status()
            data = response.json()

        if data.get("status") == "fail":
            msg = data.get("message", "Unknown error from ip-api.com")
            logger.warning("GeoIP API returned failure for %s: %s", ip, msg)
            return _geoip_fallback(ip, error=msg)

        result: Dict[str, Any] = {
            "ip": ip,
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "as_number": data.get("as", ""),
            "lat": data.get("lat", 0.0),
            "lon": data.get("lon", 0.0),
            "error": None,
        }

        logger.info("GeoIP lookup for %s: %s, %s", ip, result["country"], result["city"])
        return result

    except httpx.HTTPStatusError as exc:
        logger.error("GeoIP HTTP error for %s: %s", ip, exc)
        return _geoip_fallback(ip, error=f"HTTP {exc.response.status_code}")
    except httpx.RequestError as exc:
        logger.error("GeoIP request error for %s: %s", ip, exc)
        return _geoip_fallback(ip, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error during GeoIP lookup for %s: %s", ip, exc)
        return _geoip_fallback(ip, error=str(exc))


def _geoip_fallback(ip: str, *, error: str) -> Dict[str, Any]:
    """Return a well-formed GeoIP dict populated with fallback values."""
    logger.warning("Returning GeoIP fallback/mock result for %s", ip)
    return {
        "ip": ip,
        "country": "Unknown",
        "country_code": "XX",
        "region": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "as_number": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "error": error,
    }
