"""REST API integration tests for Threat Intelligence Enrichment (Phase 11)."""

import pytest
import time
from app import create_app
from database import db
from threat_intel.models import ThreatIntelResult, REPUTATION_CLEAN


@pytest.fixture
def app_and_client():
    app, socketio = create_app(start_capture=False)
    app.config["TESTING"] = True

    with app.app_context():
        # Ensure TI service has clean cache
        ti_svc = getattr(app, "threat_intel_service", None)
        if ti_svc:
            ti_svc.cache.prune_expired()
        with app.test_client() as client:
            yield app, client


def test_ti_status_endpoint(app_and_client):
    """Verify GET /api/threat-intel/status returns status structure."""
    app, client = app_and_client
    resp = client.get("/api/threat-intel/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "threat_intel" in data
    ti_info = data["threat_intel"]
    assert "enabled" in ti_info
    assert "queue_size" in ti_info
    assert "cache_entries" in ti_info
    assert "configured_providers" in ti_info


def test_ti_get_ip_ineligible(app_and_client):
    """Verify GET /api/threat-intel/ip/<ip> returns eligible=False for private or invalid IPs."""
    app, client = app_and_client

    # Private RFC 1918
    r1 = client.get("/api/threat-intel/ip/192.168.1.1")
    assert r1.status_code == 200
    d1 = r1.get_json()
    assert d1["eligible"] is False
    assert d1["reason"] == "ineligible_private_or_local"

    # Loopback
    r2 = client.get("/api/threat-intel/ip/127.0.0.1")
    assert r2.status_code == 200
    d2 = r2.get_json()
    assert d2["eligible"] is False

    # Malformed
    r3 = client.get("/api/threat-intel/ip/invalid-ip")
    assert r3.status_code == 200
    d3 = r3.get_json()
    assert d3["eligible"] is False


def test_ti_get_ip_cached(app_and_client):
    """Verify GET /api/threat-intel/ip/<ip> returns cached reputation for eligible public IP."""
    app, client = app_and_client
    ti_svc = getattr(app, "threat_intel_service", None)
    assert ti_svc is not None

    # Pre-populate cache with public IP
    now = time.time()
    res = ThreatIntelResult(
        indicator="8.8.8.8",
        provider="AbuseIPDB",
        available=True,
        reputation=REPUTATION_CLEAN,
        confidence=0.9,
        queried_at=now,
        expires_at=now + 3600.0,
    )
    ti_svc.cache.put(res)

    resp = client.get("/api/threat-intel/ip/8.8.8.8")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ip"] == "8.8.8.8"
    assert data["eligible"] is True
    assert data["available"] is True
    assert data["intelligence"]["reputation"] == REPUTATION_CLEAN


def test_ti_lookup_endpoint(app_and_client):
    """Verify POST /api/threat-intel/ip/<ip>/lookup validates eligibility and configuration."""
    app, client = app_and_client
    ti_svc = getattr(app, "threat_intel_service", None)

    # 1. Ineligible returns 400
    r_bad = client.post("/api/threat-intel/ip/10.0.0.1/lookup")
    assert r_bad.status_code == 400
    assert "Ineligible" in r_bad.get_json()["message"]

    # 2. Disabled TI service returns 400
    ti_svc.enabled = False
    r_disabled = client.post("/api/threat-intel/ip/1.1.1.1/lookup")
    assert r_disabled.status_code == 400
    assert "disabled" in r_disabled.get_json()["message"]

    # 3. Enabled but unconfigured returns 400
    ti_svc.enabled = True
    r_unconf = client.post("/api/threat-intel/ip/1.1.1.1/lookup")
    assert r_unconf.status_code == 400
    assert "No threat intelligence providers configured" in r_unconf.get_json()["message"]

    # 4. Enabled with configured provider returns 200/202 (queued)
    ti_svc._providers["AbuseIPDB"].enabled = True
    ti_svc._providers["AbuseIPDB"]._api_key = "mock_key"
    r_ok = client.post("/api/threat-intel/ip/1.1.1.1/lookup")
    assert r_ok.status_code in (200, 202)
    assert r_ok.get_json()["status"] == "ok"
