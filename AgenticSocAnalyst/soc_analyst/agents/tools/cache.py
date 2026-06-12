"""
Thread-safe, in-memory TTL cache for investigation tool results.

Prevents rate-limit exhaustion on external APIs (e.g. VirusTotal
allows only 4 requests/minute on the free tier).  Cached entries
expire after a configurable TTL (default: 24 hours).

Usage::

    from soc_analyst.agents.tools.cache import ttl_cache, ToolCache

    # Decorator form -- automatically caches by function name + args
    @ttl_cache(ttl_seconds=86400)
    async def check_virustotal(ip: str) -> dict:
        ...

    # Manual form
    cache = ToolCache(ttl_seconds=86400)
    cache.set("vt:8.8.8.8", {"score": 0})
    result = cache.get("vt:8.8.8.8")  # dict | None
"""

from __future__ import annotations

import functools
import hashlib
import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

__all__ = ["ToolCache", "ttl_cache"]


class ToolCache:
    """Thread-safe in-memory cache with per-entry TTL.

    Parameters
    ----------
    ttl_seconds : int
        Time-to-live for each entry in seconds (default 86 400 = 24h).
    max_entries : int
        Maximum number of cached entries.  When exceeded the oldest
        entries are evicted regardless of TTL (simple LRU-like policy).
    """

    def __init__(
        self,
        ttl_seconds: int = 86_400,
        max_entries: int = 10_000,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._store: Dict[str, tuple[float, Any]] = {}  # key -> (expires_at, value)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[Any]:
        """Return cached value or ``None`` if missing / expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Store *value* under *key* with the given TTL."""
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl
        with self._lock:
            self._store[key] = (time.time() + ttl, value)
            # Evict oldest if over capacity
            if len(self._store) > self._max:
                self._evict()

    def invalidate(self, key: str) -> bool:
        """Remove a specific key.  Returns ``True`` if it existed."""
        with self._lock:
            return self._store.pop(key, None) is not None

    def clear(self) -> int:
        """Flush the entire cache.  Returns number of entries removed."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            return count

    @property
    def size(self) -> int:
        """Current number of entries (including possibly-expired ones)."""
        return len(self._store)

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        now = time.time()
        with self._lock:
            total = len(self._store)
            expired = sum(1 for (exp, _) in self._store.values() if now > exp)
        return {
            "total_entries": total,
            "expired_entries": expired,
            "active_entries": total - expired,
            "max_entries": self._max,
            "ttl_seconds": self._ttl,
        }

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _evict(self) -> None:
        """Remove the oldest 10% of entries (called under lock)."""
        to_remove = max(1, len(self._store) // 10)
        sorted_keys = sorted(
            self._store, key=lambda k: self._store[k][0]
        )
        for key in sorted_keys[:to_remove]:
            del self._store[key]
        logger.debug("Cache evicted %d entries", to_remove)


# ---------------------------------------------------------------------------
# Singleton global cache (shared across all tools)
# ---------------------------------------------------------------------------

_global_cache = ToolCache()


def get_global_cache() -> ToolCache:
    """Return the module-level shared cache instance."""
    return _global_cache


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------


def _make_cache_key(func_name: str, args: tuple, kwargs: dict) -> str:
    """Build a deterministic cache key from function name + arguments."""
    raw = f"{func_name}:{args}:{sorted(kwargs.items())}"
    return hashlib.md5(raw.encode()).hexdigest()


def ttl_cache(
    ttl_seconds: int = 86_400,
    cache: Optional[ToolCache] = None,
) -> Callable:
    """Decorator that caches an async function's return value.

    Parameters
    ----------
    ttl_seconds : int
        Per-entry TTL (default 24 hours).
    cache : ToolCache, optional
        Cache instance to use.  Defaults to the global singleton.
    """
    _cache = cache or _global_cache

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = _make_cache_key(func.__qualname__, args, kwargs)
            cached = _cache.get(key)
            if cached is not None:
                logger.debug("Cache HIT  %s(%s)", func.__name__, args)
                return cached
            logger.debug("Cache MISS %s(%s)", func.__name__, args)
            result = await func(*args, **kwargs)
            _cache.set(key, result, ttl_seconds)
            return result

        # Expose the underlying cache for testing / manual invalidation
        wrapper.cache = _cache  # type: ignore[attr-defined]
        return wrapper

    return decorator
