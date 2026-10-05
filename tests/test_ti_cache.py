"""Unit tests for NetSentinel Threat Intelligence Cache (LRU, TTL, In-Flight, Persistence)."""

import time
from threat_intel.cache import ThreatIntelCache
from threat_intel.models import ThreatIntelResult, REPUTATION_MALICIOUS, REPUTATION_CLEAN


def test_cache_put_and_get():
    """Verify storing and retrieving a fresh result from cache."""
    cache = ThreatIntelCache(default_ttl=3600.0, max_entries=100)
    now = time.time()
    res = ThreatIntelResult(
        indicator="8.8.8.8",
        provider="AbuseIPDB",
        queried_at=now,
        expires_at=now + 3600.0,
        available=True,
        reputation=REPUTATION_CLEAN,
    )
    cache.put(res)

    cached = cache.get("8.8.8.8", "AbuseIPDB")
    assert cached is not None
    assert cached.indicator == "8.8.8.8"
    assert cached.reputation == REPUTATION_CLEAN

    # Miss for unqueried provider
    assert cache.get("8.8.8.8", "VirusTotal") is None


def test_cache_ttl_expiration():
    """Verify expired cache items are not returned unless allow_stale=True."""
    cache = ThreatIntelCache(default_ttl=10.0, max_entries=100)
    now = time.time()
    # Expired 5 seconds ago
    res = ThreatIntelResult(
        indicator="1.1.1.1",
        provider="VirusTotal",
        queried_at=now - 20.0,
        expires_at=now - 5.0,
        available=True,
        reputation=REPUTATION_CLEAN,
    )
    cache.put(res)

    assert cache.get("1.1.1.1", "VirusTotal") is None
    stale = cache.get("1.1.1.1", "VirusTotal", allow_stale=True)
    assert stale is not None
    assert stale.is_stale is True


def test_cache_lru_eviction():
    """Verify LRU capacity bounds and eviction."""
    cache = ThreatIntelCache(max_entries=3)
    now = time.time()

    for i in range(1, 5):
        ip = f"185.220.101.{i}"
        res = ThreatIntelResult(
            indicator=ip,
            provider="TestProvider",
            queried_at=now,
            expires_at=now + 1000.0,
            available=True,
            reputation=REPUTATION_MALICIOUS,
        )
        cache.put(res)

    # Max entries is 3, so first item (185.220.101.1) should have been evicted
    assert cache.get("185.220.101.1", "TestProvider") is None
    assert cache.get("185.220.101.2", "TestProvider") is not None
    assert cache.get("185.220.101.3", "TestProvider") is not None
    assert cache.get("185.220.101.4", "TestProvider") is not None


def test_in_flight_tracking():
    """Verify deduplication locks for in-flight lookups."""
    cache = ThreatIntelCache()

    # First attempt claims the lock
    assert cache.mark_in_flight("8.8.8.8", "AbuseIPDB") is True
    # Concurrent second attempt fails
    assert cache.mark_in_flight("8.8.8.8", "AbuseIPDB") is False

    # Clear releases lock
    cache.clear_in_flight("8.8.8.8", "AbuseIPDB")
    assert cache.mark_in_flight("8.8.8.8", "AbuseIPDB") is True


def test_persistence_callbacks():
    """Verify saver callback is triggered on put."""
    saved_items = []

    def mock_saver(**kwargs):
        saved_items.append(kwargs)
        return True

    cache = ThreatIntelCache(saver=mock_saver)
    now = time.time()
    res = ThreatIntelResult(
        indicator="93.184.216.34",
        provider="AbuseIPDB",
        queried_at=now,
        expires_at=now + 3600.0,
        available=True,
        reputation=REPUTATION_CLEAN,
    )
    cache.put(res)

    assert len(saved_items) == 1
    assert saved_items[0]["indicator"] == "93.184.216.34"
    assert saved_items[0]["provider"] == "AbuseIPDB"
