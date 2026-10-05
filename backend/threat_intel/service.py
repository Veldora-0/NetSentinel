"""NetSentinel Threat Intelligence Service.

Coordinates IP eligibility checks, bounded async queueing, background worker execution,
multi-provider querying, TTL caching, reputation aggregation, and metric tracking.
Ensures zero blocking on packet capture / detection hot paths.
"""

from collections import deque
import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .models import (
    ThreatIntelResult,
    AggregatedThreatIntel,
    REPUTATION_UNKNOWN,
    REPUTATION_CLEAN,
    REPUTATION_SUSPICIOUS,
    REPUTATION_MALICIOUS,
    REPUTATION_CONFLICTING,
    CONSENSUS_STRONG_POSITIVE,
    CONSENSUS_MODERATE_POSITIVE,
    CONSENSUS_CLEAN,
    CONSENSUS_CONFLICTING,
    CONSENSUS_UNKNOWN,
)
from .eligibility import is_eligible_public_ip, normalize_ip
from .providers import BaseThreatIntelProvider, AbuseIPDBProvider, VirusTotalProvider
from .cache import ThreatIntelCache

logger = logging.getLogger("netsentinel.threat_intel.service")


class ThreatIntelService:
    """Central Threat Intelligence enrichment coordinator."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        on_intel_updated: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        cfg = config or {}
        self.enabled = bool(cfg.get("ti_enabled", False))
        self.queue_max = int(cfg.get("ti_queue_max", 500))
        self.workers_count = max(1, int(cfg.get("ti_workers", 1)))
        self.cache_ttl = float(cfg.get("ti_cache_ttl", 3600.0))
        self.min_request_interval = float(cfg.get("ti_min_request_interval", 15.0))
        self.request_timeout = float(cfg.get("ti_request_timeout", 8.0))

        self.on_intel_updated = on_intel_updated

        # Cache management
        self.cache = ThreatIntelCache(default_ttl=self.cache_ttl)

        # Thread synchronization and work queue
        self._lock = threading.RLock()
        self._queue: queue.Queue = queue.Queue(maxsize=self.queue_max)
        self._threads: List[threading.Thread] = []
        self._running = False

        # Provider registry
        self._providers: Dict[str, BaseThreatIntelProvider] = {}
        self._init_providers(cfg)


        # Operational metrics
        self._stats = {
            "lookups_queued": 0,
            "lookups_completed": 0,
            "lookups_failed": 0,
            "lookups_dropped_queue_full": 0,
            "rate_limited_requests": 0,
            "last_successful_lookup": None,
            "last_error": None,
        }

        if self.enabled:
            self.start()

    def _init_providers(self, cfg: Dict[str, Any]) -> None:
        """Register default threat intelligence provider adapters based on config."""
        # 1. AbuseIPDB
        abuse_enabled = cfg.get("abuseipdb_enabled", False)
        abuse_key = cfg.get("abuseipdb_api_key", "")
        abuse_max_age = cfg.get("abuseipdb_max_age_days", 90)
        self.register_provider(
            AbuseIPDBProvider(
                enabled=abuse_enabled,
                api_key=abuse_key,
                max_age_days=abuse_max_age,
                timeout=self.request_timeout,
                min_request_interval=self.min_request_interval,
            )
        )

        # 2. VirusTotal
        vt_enabled = cfg.get("vt_enabled", False)
        vt_key = cfg.get("vt_api_key", "")
        self.register_provider(
            VirusTotalProvider(
                enabled=vt_enabled,
                api_key=vt_key,
                timeout=self.request_timeout,
                min_request_interval=self.min_request_interval,
            )
        )

    def register_provider(self, provider: BaseThreatIntelProvider) -> None:
        """Register an adapter into the provider pool."""
        with self._lock:
            self._providers[provider.name] = provider

    def get_configured_providers(self) -> List[str]:
        """Return names of providers enabled and configured with credentials."""
        with self._lock:
            return [p.name for p in self._providers.values() if p.is_configured]

    def get_available_providers(self) -> List[str]:
        """Return names of configured providers not currently rate-limited."""
        with self._lock:
            return [
                p.name
                for p in self._providers.values()
                if p.is_configured and not p.is_rate_limited
            ]

    def start(self) -> None:
        """Start the background enrichment worker thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            for i in range(self.workers_count):
                t = threading.Thread(
                    target=self._worker_loop,
                    name=f"ThreatIntelWorker-{i}",
                    daemon=True,
                )
                t.start()
                self._threads.append(t)
            logger.info("ThreatIntelService started with %d worker(s).", self.workers_count)

    def stop(self) -> None:
        """Stop worker threads cleanly."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            # Unblock queue
            for _ in self._threads:
                try:
                    self._queue.put_nowait(None)
                except Exception:
                    pass
            for t in self._threads:
                t.join(timeout=2.0)
            self._threads.clear()
            logger.info("ThreatIntelService stopped.")

    def queue_ip(self, ip: Any, priority: bool = False) -> bool:
        """Non-blocking submission of a candidate IP for async threat intelligence enrichment.

        Returns:
            True if queued successfully or already cached/in-flight; False if dropped or ineligible.
        """
        if not self.enabled:
            return False

        norm_ip = normalize_ip(ip)
        if not norm_ip:
            return False

        # If zero providers are configured, skip queueing
        configured = self.get_configured_providers()
        if not configured:
            return False

        # Check if all configured providers already have fresh cached entries
        all_fresh = all(self.cache.is_fresh(norm_ip, p_name) for p_name in configured)
        if all_fresh:
            return True

        # Claim in-flight deduplication
        if not self.cache.mark_in_flight(norm_ip):
            # Already being enriched by a worker
            return True

        try:
            self._queue.put_nowait((norm_ip, priority))
            with self._lock:
                self._stats["lookups_queued"] += 1
            return True
        except queue.Full:
            self.cache.clear_in_flight(norm_ip)
            with self._lock:
                self._stats["lookups_dropped_queue_full"] += 1
            logger.warning("Threat intelligence queue full. Dropped lookup for %s", norm_ip)
            return False

    def _worker_loop(self) -> None:
        """Background worker consuming IP enrichment jobs."""
        while self._running:
            try:
                item = self._queue.get(timeout=1.0)
                if item is None:
                    break

                ip, _ = item
                try:
                    self._process_ip_enrichment(ip)
                finally:
                    self.cache.clear_in_flight(ip)
                    self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as ex:
                logger.debug("Unexpected error in TI worker: %s", ex)

    def _process_ip_enrichment(self, ip: str) -> Optional[AggregatedThreatIntel]:
        """Perform provider queries and update cache/incidents."""
        configured = self.get_configured_providers()
        if not configured:
            return None

        results = []
        any_success = False

        for p_name in configured:
            provider = self._providers.get(p_name)
            if not provider or not provider.is_configured:
                continue

            # Check cache first
            cached = self.cache.get(ip, p_name, allow_stale=False)
            if cached:
                results.append(cached)
                any_success = True
                continue

            if provider.is_rate_limited:
                with self._lock:
                    self._stats["rate_limited_requests"] += 1
                continue

            # Query provider
            res = provider.lookup_ip(ip)
            if res.available:
                any_success = True
                self.cache.put(res)
                results.append(res)
            else:
                if res.error and "429" in res.error:
                    with self._lock:
                        self._stats["rate_limited_requests"] += 1
                with self._lock:
                    self._stats["lookups_failed"] += 1
                    self._stats["last_error"] = f"{p_name}: {res.error}"

        if any_success:
            with self._lock:
                self._stats["lookups_completed"] += 1
                self._stats["last_successful_lookup"] = time.time()

        agg = self.aggregate_results(ip, results)

        # Notify listener (Socket.IO / Incident correlation)
        if self.on_intel_updated:
            try:
                self.on_intel_updated(agg.to_dict())
            except Exception as ex:
                logger.debug("on_intel_updated callback error: %s", ex)

        return agg

    def enrich_ip(self, ip: Any) -> Optional[AggregatedThreatIntel]:
        """Synchronous enrichment across configured providers (for explicit operator lookups)."""
        norm_ip = normalize_ip(ip)
        if not norm_ip:
            return None

        configured = self.get_configured_providers()
        if not configured:
            # Return unknown aggregate
            return AggregatedThreatIntel(ip=norm_ip, reputation=REPUTATION_UNKNOWN)

        results = []
        for p_name in configured:
            provider = self._providers.get(p_name)
            if not provider or not provider.is_configured:
                continue

            cached = self.cache.get(norm_ip, p_name, allow_stale=False)
            if cached:
                results.append(cached)
                continue

            res = provider.lookup_ip(norm_ip)
            if res.available:
                self.cache.put(res)
                results.append(res)

        return self.aggregate_results(norm_ip, results)

    def get_cached_summary(self, ip: Any, allow_stale: bool = True) -> Optional[AggregatedThreatIntel]:
        """Formulate an aggregated summary strictly from existing cached data without making requests."""
        norm_ip = normalize_ip(ip)
        if not norm_ip:
            return None

        configured = self.get_configured_providers()
        results = []
        for p_name in (configured or self._providers.keys()):
            cached = self.cache.get(norm_ip, p_name, allow_stale=allow_stale)
            if cached:
                results.append(cached)

        if not results:
            return None

        return self.aggregate_results(norm_ip, results)

    def aggregate_results(
        self, ip: str, results: List[ThreatIntelResult]
    ) -> AggregatedThreatIntel:
        """Combine multiple provider results into a deterministic, explainable aggregate."""
        now = time.time()
        available_results = [r for r in results if r.available]
        checked_count = len(results)
        avail_count = len(available_results)

        if not available_results:
            return AggregatedThreatIntel(
                ip=ip,
                reputation=REPUTATION_UNKNOWN,
                confidence=0.0,
                consensus=CONSENSUS_UNKNOWN,
                providers_checked=checked_count,
                providers_available=0,
                last_checked=now,
                stale=False,
            )

        malicious_results = [r for r in available_results if r.reputation == REPUTATION_MALICIOUS]
        suspicious_results = [r for r in available_results if r.reputation == REPUTATION_SUSPICIOUS]
        clean_results = [r for r in available_results if r.reputation == REPUTATION_CLEAN]

        mal_count = len(malicious_results)
        sus_count = len(suspicious_results)
        clean_count = len(clean_results)

        # Deterministic consensus rules
        if mal_count >= 2:
            reputation = REPUTATION_MALICIOUS
            consensus = CONSENSUS_STRONG_POSITIVE
        elif mal_count == 1 and sus_count >= 1:
            reputation = REPUTATION_MALICIOUS
            consensus = CONSENSUS_MODERATE_POSITIVE
        elif mal_count >= 1 and clean_count >= 1:
            reputation = REPUTATION_CONFLICTING
            consensus = CONSENSUS_CONFLICTING
        elif mal_count == 1 and clean_count == 0:
            reputation = REPUTATION_MALICIOUS
            consensus = CONSENSUS_MODERATE_POSITIVE
        elif sus_count >= 1 and mal_count == 0:
            reputation = REPUTATION_SUSPICIOUS
            consensus = CONSENSUS_MODERATE_POSITIVE
        elif clean_count >= 1 and mal_count == 0 and sus_count == 0:
            reputation = REPUTATION_CLEAN
            consensus = CONSENSUS_CLEAN
        else:
            reputation = REPUTATION_UNKNOWN
            consensus = CONSENSUS_UNKNOWN

        # Aggregated confidence
        confidences = [r.confidence for r in available_results if r.confidence > 0.0]
        avg_confidence = (sum(confidences) / len(confidences)) if confidences else 0.0

        # Extract metadata
        abuse_scores = [r.abuse_confidence for r in available_results if r.abuse_confidence is not None]
        top_abuse = max(abuse_scores) if abuse_scores else None
        total_reports = sum(r.report_count for r in available_results)
        countries = [r.country for r in available_results if r.country]
        asns = [r.asn for r in available_results if r.asn]
        owners = [r.as_owner for r in available_results if r.as_owner]

        min_expiry = min((r.expires_at for r in available_results), default=now + 3600.0)
        is_stale = any(r.is_stale for r in available_results)

        provider_map = {r.provider: r.to_dict() for r in available_results}

        return AggregatedThreatIntel(
            ip=ip,
            reputation=reputation,
            confidence=avg_confidence,
            consensus=consensus,
            providers_checked=checked_count,
            providers_available=avail_count,
            abuse_score=top_abuse,
            report_count=total_reports,
            malicious_count=mal_count,
            suspicious_count=sus_count,
            country=countries[0] if countries else None,
            asn=asns[0] if asns else None,
            as_owner=owners[0] if owners else None,
            last_checked=max((r.queried_at for r in available_results), default=now),
            expires_at=min_expiry,
            stale=is_stale,
            provider_results=provider_map,
        )

    def get_status(self) -> Dict[str, Any]:
        """Return operational status and metrics without leaking any credentials."""
        cache_stats = self.cache.stats()
        configured = self.get_configured_providers()
        available = self.get_available_providers()

        with self._lock:
            return {
                "enabled": self.enabled,
                "configured_providers": configured,
                "available_providers": available,
                "provider_count": len(self._providers),
                "queue_size": self._queue.qsize(),
                "queue_capacity": self.queue_max,
                "cache_entries": cache_stats["total_entries"],
                "fresh_cache_entries": cache_stats["fresh_entries"],
                "stale_cache_entries": cache_stats["stale_entries"],
                "successful_lookups": self._stats["lookups_completed"],
                "failed_lookups": self._stats["lookups_failed"],
                "dropped_queue_full": self._stats["lookups_dropped_queue_full"],
                "rate_limited_requests": self._stats["rate_limited_requests"],
                "last_successful_lookup": self._stats["last_successful_lookup"],
                "last_error": self._stats["last_error"],
            }
