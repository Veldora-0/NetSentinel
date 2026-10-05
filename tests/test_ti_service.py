"""Unit tests for NetSentinel Threat Intelligence Service."""

import time
from threat_intel.service import ThreatIntelService
from threat_intel.models import (
    ThreatIntelResult,
    REPUTATION_MALICIOUS,
    REPUTATION_CLEAN,
    REPUTATION_CONFLICTING,
    CONSENSUS_STRONG_POSITIVE,
    CONSENSUS_CONFLICTING,
    CONSENSUS_CLEAN,
)


def test_service_queue_and_drop_on_full():
    """Verify queue accepts eligible IPs and rejects when queue reaches max capacity."""
    svc = ThreatIntelService(
        config={
            "ti_enabled": False,  # keep workers stopped for controlled testing
            "ti_queue_max": 2,
            "abuseipdb_enabled": True,
            "abuseipdb_api_key": "test_key",
        }
    )
    # Enable service logic without starting worker loop thread
    svc.enabled = True

    # 1. Enqueue valid public IP
    assert svc.queue_ip("8.8.8.8") is True
    assert svc.queue_ip("1.1.1.1") is True

    # 2. Queue is now full (maxsize=2)
    assert svc.queue_ip("93.184.216.34") is False
    assert svc.get_status()["dropped_queue_full"] == 1


def test_service_enqueue_rejects_private():
    """Verify private/local IPs are rejected before queueing."""
    svc = ThreatIntelService(
        config={
            "ti_enabled": False,
            "abuseipdb_enabled": True,
            "abuseipdb_api_key": "test_key",
        }
    )
    svc.enabled = True
    assert svc.queue_ip("192.168.1.1") is False
    assert svc.queue_ip("127.0.0.1") is False
    assert svc.queue_ip("localhost") is False
    assert svc._queue.qsize() == 0


def test_consensus_aggregation_strong_positive():
    """Verify 2 malicious results produce MALICIOUS reputation with STRONG_POSITIVE consensus."""
    svc = ThreatIntelService(config={"ti_enabled": False})
    now = time.time()

    r1 = ThreatIntelResult(
        indicator="185.220.101.5",
        provider="AbuseIPDB",
        available=True,
        reputation=REPUTATION_MALICIOUS,
        confidence=0.9,
        queried_at=now,
        expires_at=now + 3600.0,
    )
    r2 = ThreatIntelResult(
        indicator="185.220.101.5",
        provider="VirusTotal",
        available=True,
        reputation=REPUTATION_MALICIOUS,
        confidence=0.8,
        queried_at=now,
        expires_at=now + 3600.0,
    )

    agg = svc.aggregate_results("185.220.101.5", [r1, r2])
    assert agg.reputation == REPUTATION_MALICIOUS
    assert agg.consensus == CONSENSUS_STRONG_POSITIVE
    assert agg.confidence >= 0.8


def test_consensus_aggregation_conflicting():
    """Verify malicious + clean results produce CONFLICTING reputation."""
    svc = ThreatIntelService(config={"ti_enabled": False})
    now = time.time()

    r1 = ThreatIntelResult(
        indicator="185.220.101.5",
        provider="AbuseIPDB",
        available=True,
        reputation=REPUTATION_MALICIOUS,
        confidence=0.7,
        queried_at=now,
        expires_at=now + 3600.0,
    )
    r2 = ThreatIntelResult(
        indicator="185.220.101.5",
        provider="VirusTotal",
        available=True,
        reputation=REPUTATION_CLEAN,
        confidence=0.8,
        queried_at=now,
        expires_at=now + 3600.0,
    )

    agg = svc.aggregate_results("185.220.101.5", [r1, r2])
    assert agg.reputation == REPUTATION_CONFLICTING
    assert agg.consensus == CONSENSUS_CONFLICTING


def test_consensus_aggregation_clean():
    """Verify clean provider result produces CLEAN reputation."""
    svc = ThreatIntelService(config={"ti_enabled": False})
    now = time.time()

    r1 = ThreatIntelResult(
        indicator="8.8.8.8",
        provider="AbuseIPDB",
        available=True,
        reputation=REPUTATION_CLEAN,
        confidence=0.9,
        queried_at=now,
        expires_at=now + 3600.0,
    )

    agg = svc.aggregate_results("8.8.8.8", [r1])
    assert agg.reputation == REPUTATION_CLEAN
    assert agg.consensus == CONSENSUS_CLEAN


def test_status_does_not_leak_keys():
    """Verify status dictionary contains operational metrics but never API keys."""
    svc = ThreatIntelService(
        config={
            "ti_enabled": True,
            "abuseipdb_enabled": True,
            "abuseipdb_api_key": "SUPER_SECRET_KEY_12345",
            "vt_enabled": True,
            "vt_api_key": "ANOTHER_SECRET_KEY_67890",
        }
    )

    status = svc.get_status()
    status_str = str(status)
    assert "SUPER_SECRET_KEY_12345" not in status_str
    assert "ANOTHER_SECRET_KEY_67890" not in status_str
    assert "configured_providers" in status
    assert "AbuseIPDB" in status["configured_providers"]
    assert "VirusTotal" in status["configured_providers"]
    assert "queue_size" in status
    assert "cache_entries" in status
    svc.stop()
