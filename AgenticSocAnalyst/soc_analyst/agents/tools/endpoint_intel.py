"""
Endpoint intelligence – live queries against the Wazuh Manager REST API
and Wazuh Indexer (OpenSearch) for host-level investigation data.

Functions
---------
get_agent_processes      – running processes on a Wazuh agent
get_file_integrity_events – FIM (syscheck) events for an agent
get_user_activity        – authentication / logon events for a user on an agent

All functions are async, return plain dicts, and cache results for
300 seconds (endpoint state is volatile).

Usage::

    from soc_analyst.agents.tools.endpoint_intel import (
        get_agent_processes,
        get_file_integrity_events,
        get_user_activity,
    )

    procs = await get_agent_processes("001")
    fim   = await get_file_integrity_events("001", limit=10)
    auth  = await get_user_activity("001", "jdoe")
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from soc_analyst.agents.tools.cache import ttl_cache
from soc_analyst.config import settings

logger = logging.getLogger(__name__)

__all__ = [
    "get_agent_processes",
    "get_file_integrity_events",
    "get_user_activity",
]

# ---------------------------------------------------------------------------
# Internal: JWT authentication helper
# ---------------------------------------------------------------------------

@ttl_cache(ttl_seconds=900)
async def _get_wazuh_token() -> str:
    """Authenticate against the Wazuh Manager and return a JWT token.

    The token is cached for 900 seconds (15 min) which is well within
    the default Wazuh token lifetime of 900 s.

    Returns
    -------
    str
        Bearer token string.

    Raises
    ------
    httpx.HTTPStatusError
        If the authentication request fails.
    """
    url = f"{settings.wazuh.api_url}/security/user/authenticate"
    logger.debug("Requesting new Wazuh JWT token from %s", url)

    async with httpx.AsyncClient(verify=settings.wazuh.verify_ssl) as client:
        resp = await client.post(
            url,
            auth=(settings.wazuh.api_user, settings.wazuh.api_pass),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()

    token: str = resp.json()["data"]["token"]
    logger.info("Obtained Wazuh JWT token (length=%d)", len(token))
    return token


def _auth_headers(token: str) -> Dict[str, str]:
    """Return the Authorization header dict for Wazuh API calls."""
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Running processes on an agent
# ---------------------------------------------------------------------------

@ttl_cache(ttl_seconds=300)
async def get_agent_processes(agent_id: str) -> dict:
    """Retrieve the list of running processes on a Wazuh agent.

    Parameters
    ----------
    agent_id : str
        Wazuh agent ID (e.g. ``"001"``).

    Returns
    -------
    dict
        ``agent_id``  – the queried agent ID
        ``process_count`` – number of processes returned
        ``processes`` – list of dicts with ``name``, ``pid``, ``user``, ``state``
        ``error``     – error message string, or ``None`` on success
    """
    try:
        token = await _get_wazuh_token()

        url = f"{settings.wazuh.api_url}/syscollector/{agent_id}/processes"
        logger.debug("GET %s", url)

        async with httpx.AsyncClient(verify=settings.wazuh.verify_ssl) as client:
            resp = await client.get(url, headers=_auth_headers(token))
            resp.raise_for_status()

        data: Dict[str, Any] = resp.json()
        items: List[Dict[str, Any]] = data.get("data", {}).get("affected_items", [])

        processes = [
            {
                "name": proc.get("name", "unknown"),
                "pid": proc.get("pid"),
                "user": proc.get("euser", proc.get("ruser", "unknown")),
                "state": proc.get("state", "unknown"),
            }
            for proc in items
        ]

        logger.info(
            "Agent %s: retrieved %d processes", agent_id, len(processes)
        )
        return {
            "agent_id": agent_id,
            "process_count": len(processes),
            "processes": processes,
            "error": None,
        }

    except Exception as exc:
        logger.error(
            "Failed to get processes for agent %s: %s", agent_id, exc
        )
        return {
            "agent_id": agent_id,
            "process_count": 0,
            "processes": [],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# 2. File Integrity Monitoring (syscheck) events
# ---------------------------------------------------------------------------

@ttl_cache(ttl_seconds=300)
async def get_file_integrity_events(
    agent_id: str, limit: int = 20
) -> dict:
    """Retrieve recent File Integrity Monitoring events for an agent.

    Parameters
    ----------
    agent_id : str
        Wazuh agent ID.
    limit : int
        Maximum number of events to return (default 20).

    Returns
    -------
    dict
        ``agent_id``    – the queried agent ID
        ``event_count`` – number of FIM events returned
        ``events``      – list of dicts with ``file``, ``event``, ``date``
        ``error``       – error message string, or ``None`` on success
    """
    try:
        token = await _get_wazuh_token()

        url = f"{settings.wazuh.api_url}/syscheck/{agent_id}"
        logger.debug("GET %s (limit=%d)", url, limit)

        async with httpx.AsyncClient(verify=settings.wazuh.verify_ssl) as client:
            resp = await client.get(
                url,
                headers=_auth_headers(token),
                params={"limit": limit},
            )
            resp.raise_for_status()

        data: Dict[str, Any] = resp.json()
        items: List[Dict[str, Any]] = data.get("data", {}).get("affected_items", [])

        events = [
            {
                "file": item.get("file", "unknown"),
                "event": item.get("event", "unknown"),
                "date": item.get("date", "unknown"),
            }
            for item in items
        ]

        logger.info(
            "Agent %s: retrieved %d FIM events", agent_id, len(events)
        )
        return {
            "agent_id": agent_id,
            "event_count": len(events),
            "events": events,
            "error": None,
        }

    except Exception as exc:
        logger.error(
            "Failed to get FIM events for agent %s: %s", agent_id, exc
        )
        return {
            "agent_id": agent_id,
            "event_count": 0,
            "events": [],
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# 3. User authentication activity (via Wazuh Indexer / OpenSearch)
# ---------------------------------------------------------------------------

@ttl_cache(ttl_seconds=300)
async def get_user_activity(agent_id: str, username: str) -> dict:
    """Query the Wazuh Indexer for recent authentication events tied to a user.

    This sends an OpenSearch ``_search`` query against the alerts index,
    filtering by ``agent.id`` and ``data.win.eventdata.targetUserName``.

    Parameters
    ----------
    agent_id : str
        Wazuh agent ID.
    username : str
        Target username to search for (Windows ``targetUserName``).

    Returns
    -------
    dict
        ``agent_id``    – the queried agent ID
        ``username``    – the queried username
        ``event_count`` – number of matching events
        ``events``      – list of dicts with ``timestamp``, ``rule_description``,
                          ``src_ip``, ``event_id``
        ``error``       – error message string, or ``None`` on success
    """
    try:
        indexer_url = settings.indexer.url.rstrip("/")
        search_url = f"{indexer_url}/wazuh-alerts-4.x-*/_search"

        query_body: Dict[str, Any] = {
            "size": 20,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.id": agent_id}},
                        {
                            "match": {
                                "data.win.eventdata.targetUserName": username
                            }
                        },
                    ]
                }
            },
        }

        logger.debug("POST %s  agent=%s user=%s", search_url, agent_id, username)

        async with httpx.AsyncClient(verify=settings.indexer.verify_ssl) as client:
            resp = await client.post(
                search_url,
                json=query_body,
                auth=(settings.indexer.user, settings.indexer.password),
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()

        hits: List[Dict[str, Any]] = (
            resp.json().get("hits", {}).get("hits", [])
        )

        events = []
        for hit in hits:
            src: Dict[str, Any] = hit.get("_source", {})
            rule: Dict[str, Any] = src.get("rule", {})
            win_event: Dict[str, Any] = (
                src.get("data", {}).get("win", {}).get("eventdata", {})
            )
            events.append(
                {
                    "timestamp": src.get("timestamp", "unknown"),
                    "rule_description": rule.get("description", "unknown"),
                    "src_ip": win_event.get("ipAddress", "N/A"),
                    "event_id": str(
                        src.get("data", {})
                        .get("win", {})
                        .get("system", {})
                        .get("eventID", "unknown")
                    ),
                }
            )

        logger.info(
            "Agent %s / user %s: found %d auth events",
            agent_id,
            username,
            len(events),
        )
        return {
            "agent_id": agent_id,
            "username": username,
            "event_count": len(events),
            "events": events,
            "error": None,
        }

    except Exception as exc:
        logger.error(
            "Failed to get user activity for agent %s / user %s: %s",
            agent_id,
            username,
            exc,
        )
        return {
            "agent_id": agent_id,
            "username": username,
            "event_count": 0,
            "events": [],
            "error": str(exc),
        }
