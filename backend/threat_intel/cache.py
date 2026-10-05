"""NetSentinel Threat Intelligence Cache.

Provides thread-safe in-memory caching with SQLite persistence backing, configurable TTL,
and deduplication to prevent hammering external providers during high-volume event storms.
"""

from collections import OrderedDict
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

from .models import ThreatIntelResult

logger = logging.getLogger("netsentinel.threat_intel.cache")


class ThreatIntelCache:
    """Thread-safe TTL cache for threat intelligence lookups with SQLite persistence."""

    def __init__(
        self,
        default_ttl: float = 3600.0,
        max_entries: int = 2000,
        saver: Optional[Callable[..., bool]] = None,
        loader: Optional[Callable[..., List[Dict[str, Any]]]] = None,
    ):
        self.default_ttl = float(default_ttl)
        self.max_entries = int(max_entries)
        self.saver = saver
        self.loader = loader

        self._lock = threading.RLock()
        self._cache: OrderedDict[str, ThreatIntelResult] = OrderedDict()
        self._in_flight: Set[str] = set()

        self._hits = 0
        self._misses = 0

    def _cache_key(self, indicator: str, provider: str) -> str:
        return f"{provider.lower()}:{indicator.strip()}"

    def set_persistence(
        self,
        saver: Optional[Callable[..., bool]] = None,
        loader: Optional[Callable[..., List[Dict[str, Any]]]] = None,
    ) -> None:
        """Register database persistence hooks."""
        self.saver = saver
        self.loader = loader

    def load_persisted(self) -> int:
        """Load fresh cache records from SQLite into memory."""
        if not self.loader:
            return 0
        try:
            records = self.loader()
            loaded = 0
            now = time.time()
            with self._lock:
                for r in records:
                    exp = float(r.get("expires_at", 0))
                    if exp > now:
                        res = ThreatIntelResult(
                            indicator=r["indicator"],
                            provider=r["provider"],
                            queried_at=r.get("queried_at", now),
                            expires_at=exp,
                            available=r.get("available", True),
                            reputation=r.get("result", {}).get("reputation", "UNKNOWN"),
                            abuse_confidence=r.get("result", {}).get("abuse_confidence"),
                            malicious_score=r.get("result", {}).get("malicious_score"),
                            suspicious_score=r.get("result", {}).get("suspicious_score"),
                            report_count=r.get("result", {}).get("report_count", 0),
                            last_reported_at=r.get("result", {}).get("last_reported_at"),
                            country=r.get("result", {}).get("country"),
                            asn=r.get("result", {}).get("asn"),
                            as_owner=r.get("result", {}).get("as_owner"),
                            categories=r.get("result", {}).get("categories", []),
                            tags=r.get("result", {}).get("tags", []),
                            confidence=r.get("result", {}).get("confidence", 0.0),
                            source_url=r.get("result", {}).get("source_url"),
                            error=r.get("error"),
                        )
                        key = self._cache_key(res.indicator, res.provider)
                        self._cache[key] = res
                        loaded += 1
            return loaded
        except Exception as ex:
            logger.debug("Failed to load persisted TI cache records: %s", ex)
            return 0

    def get(
        self, indicator: str, provider: str, allow_stale: bool = False
    ) -> Optional[ThreatIntelResult]:
        """Retrieve a cached result for indicator and provider."""
        key = self._cache_key(indicator, provider)
        with self._lock:
            result = self._cache.get(key)
            if not result:
                self._misses += 1
                return None

            if not allow_stale and result.is_stale:
                self._misses += 1
                return None

            # Move to end for LRU tracking
            self._cache.move_to_end(key)
            self._hits += 1
            return result

    def is_fresh(self, indicator: str, provider: str) -> bool:
        """Check if a fresh (unexpired) entry exists in the cache."""
        res = self.get(indicator, provider, allow_stale=False)
        return res is not None and not res.is_stale

    def put(self, result: ThreatIntelResult) -> None:
        """Store a threat intelligence result in memory and trigger persistence."""
        key = self._cache_key(result.indicator, result.provider)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = result

            # Bounded capacity eviction (LRU)
            if len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)

        if self.saver:
            try:
                self.saver(
                    indicator=result.indicator,
                    provider=result.provider,
                    result=result.to_dict(),
                    expires_at=result.expires_at,
                    available=result.available,
                    error=result.error,
                    queried_at=result.queried_at,
                )
            except Exception as ex:
                logger.debug("TI cache persistence hook failed: %s", ex)

    def mark_in_flight(self, indicator: str, provider: Optional[str] = None) -> bool:
        """Attempt to claim an in-flight lookup. Returns True if claimed, False if already active."""
        tag = f"{provider or '*'}:{indicator.strip()}"
        with self._lock:
            if tag in self._in_flight:
                return False
            self._in_flight.add(tag)
            return True

    def clear_in_flight(self, indicator: str, provider: Optional[str] = None) -> None:
        """Release in-flight tracking for an indicator."""
        tag = f"{provider or '*'}:{indicator.strip()}"
        with self._lock:
            self._in_flight.discard(tag)

    def prune_expired(self) -> int:
        """Remove expired entries from the in-memory cache."""
        now = time.time()
        removed = 0
        with self._lock:
            keys_to_remove = [k for k, v in self._cache.items() if v.expires_at < now]
            for k in keys_to_remove:
                del self._cache[k]
                removed += 1
        return removed

    def stats(self) -> Dict[str, Any]:
        """Return cache health metrics."""
        now = time.time()
        with self._lock:
            total = len(self._cache)
            fresh = sum(1 for v in self._cache.values() if v.expires_at >= now)
            stale = total - fresh
            return {
                "total_entries": total,
                "fresh_entries": fresh,
                "stale_entries": stale,
                "hits": self._hits,
                "misses": self._misses,
                "in_flight": len(self._in_flight),
            }
