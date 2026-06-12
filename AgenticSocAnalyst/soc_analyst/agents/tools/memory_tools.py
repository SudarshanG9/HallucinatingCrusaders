"""
Memory investigation tools for historical correlation and incident search.
"""

import asyncio
import logging
from typing import Dict, Any, List

from soc_analyst.agents.tools.cache import ttl_cache
from soc_analyst.memory.postgres_store import PostgresStore
from soc_analyst.memory.vector_store import VectorStore

logger = logging.getLogger(__name__)

__all__ = ["search_past_incidents", "get_ip_history", "get_user_history"]


@ttl_cache(ttl_seconds=1800)  # Cache for 30 minutes
async def search_past_incidents(query: str, limit: int = 5) -> Dict[str, Any]:
    """Search for past incidents similar to the current incident description.

    Args:
        query: Clear text description or indicators of the incident.
        limit: Max results to return.

    Returns:
        Dict detailing matching reports, their IDs, verdicts, and similarities.
    """
    logger.info("Running memory tool [search_past_incidents] for query: %s", query[:60])
    try:
        store = VectorStore()
        # Run in thread executor because chromadb HTTP client query is blocking
        results = await asyncio.to_thread(store.search_similar_incidents, query, limit)
        return {
            "query": query,
            "match_count": len(results),
            "incidents": results
        }
    except Exception as exc:
        logger.error("Error in [search_past_incidents] tool: %s", exc)
        return {"error": str(exc), "incidents": []}


@ttl_cache(ttl_seconds=600)  # Cache for 10 minutes
async def get_ip_history(ip: str) -> Dict[str, Any]:
    """Retrieve historical alert occurrences for a specific IP from the Postgres store.

    Args:
        ip: The IP address to search for.

    Returns:
        Dict listing matching occurrences and statuses.
    """
    logger.info("Running memory tool [get_ip_history] for IP: %s", ip)
    try:
        store = PostgresStore()
        # Fetch up to 30 days of history
        results = await asyncio.to_thread(store.get_ip_history, ip, 30)
        
        # Serialize datetime fields for JSON compatibility
        serialized = []
        for r in results:
            item = dict(r)
            if "timestamp" in item and item["timestamp"]:
                item["timestamp"] = item["timestamp"].isoformat()
            serialized.append(item)

        return {
            "ip": ip,
            "history_count": len(serialized),
            "alerts": serialized
        }
    except Exception as exc:
        logger.error("Error in [get_ip_history] tool: %s", exc)
        return {"error": str(exc), "alerts": []}


@ttl_cache(ttl_seconds=600)  # Cache for 10 minutes
async def get_user_history(username: str) -> Dict[str, Any]:
    """Retrieve historical alert occurrences for a specific username from the Postgres store.

    Args:
        username: The username to search for.

    Returns:
        Dict listing matching occurrences and statuses.
    """
    logger.info("Running memory tool [get_user_history] for user: %s", username)
    try:
        store = PostgresStore()
        results = await asyncio.to_thread(store.get_user_history, username, 30)
        
        # Serialize datetime fields for JSON compatibility
        serialized = []
        for r in results:
            item = dict(r)
            if "timestamp" in item and item["timestamp"]:
                item["timestamp"] = item["timestamp"].isoformat()
            serialized.append(item)

        return {
            "username": username,
            "history_count": len(serialized),
            "alerts": serialized
        }
    except Exception as exc:
        logger.error("Error in [get_user_history] tool: %s", exc)
        return {"error": str(exc), "alerts": []}
