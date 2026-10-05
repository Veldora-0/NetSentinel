"""Automated tests for NetSentinel Production Hardening, Operational Controls, and Service Architecture."""

import io
import json
import logging
import os
import sys
import time
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app import create_app
from config import Config
from database import check_database_health, db, init_db
from lifecycle import LifecycleManager, WorkerStatus, check_firewall_capabilities
from logging_config import RequestContextFilter, SecretSanitizingFilter, setup_logging
from security_middleware import InMemoryRateLimiter, SecurityMiddleware


@pytest.fixture
def app_and_client():
    """Create a configured test Flask app and client with in-memory database."""
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "API_RATE_LIMIT": 100,
        "SENSITIVE_RATE_LIMIT": 10,
        "LOG_LEVEL": "INFO",
        "CORS_ORIGINS": ["http://localhost:5173", "http://127.0.0.1:5173"],
    }
    app, _ = create_app(config_class=test_config, start_capture=False)
    client = app.test_client()
    return app, client


# ==============================================================================
# 1. Logging and Secret Sanitization Tests
# ==============================================================================

def test_secret_sanitizing_filter():
    """Verify that logging filters redact API keys, passwords, and bearer tokens."""
    f = SecretSanitizingFilter()
    record = logging.LogRecord(
        name="netsentinel.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Connecting with api_key=ab12cd34ef56gh78 and password=SuperSecretPassword123",
        args=(),
        exc_info=None,
    )
    f.filter(record)
    assert "SuperSecretPassword123" not in record.msg
    assert "[REDACTED]" in record.msg


def test_bearer_token_sanitization():
    """Verify that Bearer tokens in logs are safely scrubbed."""
    f = SecretSanitizingFilter()
    record = logging.LogRecord(
        name="netsentinel.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret_sig_xyz",
        args=(),
        exc_info=None,
    )
    f.filter(record)
    assert "secret_sig_xyz" not in record.msg
    assert "Bearer [REDACTED]" in record.msg


# ==============================================================================
# 2. Security Headers & Request Correlation ID Tests
# ==============================================================================

def test_security_headers_injected(app_and_client):
    """Verify that security middleware injects defensive HTTP response headers."""
    _, client = app_and_client
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in res.headers
    assert "X-Request-ID" in res.headers


def test_request_id_preserved_when_supplied(app_and_client):
    """Verify that incoming X-Request-ID headers are sanitized and preserved across responses."""
    _, client = app_and_client
    custom_id = "test-corr-id-12345"
    res = client.get("/api/health", headers={"X-Request-ID": custom_id})
    assert res.status_code == 200
    assert res.headers.get("X-Request-ID") == custom_id
    data = res.get_json()
    assert data.get("request_id") == custom_id


# ==============================================================================
# 3. Normalized Error Responses & No Traceback Leaks
# ==============================================================================

def test_normalized_404_error(app_and_client):
    """Verify that 404 Not Found returns normalized JSON without leaking backend stack traces."""
    _, client = app_and_client
    res = client.get("/api/nonexistent_route_404")
    assert res.status_code == 404
    assert res.is_json
    data = res.get_json()
    assert data.get("status") == "error"
    assert data.get("code") == 404
    assert "traceback" not in json.dumps(data).lower()


def test_normalized_405_error(app_and_client):
    """Verify that 405 Method Not Allowed returns structured JSON."""
    _, client = app_and_client
    res = client.post("/api/health")
    assert res.status_code == 405
    assert res.is_json
    data = res.get_json()
    assert data.get("status") == "error"
    assert data.get("code") == 405


# ==============================================================================
# 4. In-Memory Rate Limiting Tests
# ==============================================================================

def test_rate_limiter_allows_and_blocks():
    """Verify sliding-window rate limiter throttles client after exceeding threshold."""
    limiter = InMemoryRateLimiter(max_requests=5, window_seconds=60.0)
    ip = "198.51.100.1"

    for _ in range(5):
        allowed, remaining, _ = limiter.check_rate_limit(ip)
        assert allowed is True

    # 6th request is throttled
    allowed, remaining, retry_after = limiter.check_rate_limit(ip)
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0


def test_sensitive_endpoint_rate_limit():
    """Verify sensitive endpoints have tighter rate limits enforced."""
    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60.0)
    ip = "198.51.100.2"

    assert limiter.check_rate_limit(ip)[0] is True
    assert limiter.check_rate_limit(ip)[0] is True
    assert limiter.check_rate_limit(ip)[0] is False


def test_rate_limiter_sliding_window_cleanup():
    """Verify rate limiter cleans up expired request timestamps."""
    limiter = InMemoryRateLimiter(max_requests=2, window_seconds=0.1)
    ip = "198.51.100.3"

    assert limiter.check_rate_limit(ip)[0] is True
    assert limiter.check_rate_limit(ip)[0] is True
    assert limiter.check_rate_limit(ip)[0] is False

    time.sleep(0.15)
    # Window expired, should be allowed again
    allowed, remaining, _ = limiter.check_rate_limit(ip)
    assert allowed is True
    assert remaining == 1


# ==============================================================================
# 5. Health, Readiness, and Diagnostics Endpoints
# ==============================================================================

def test_api_health_liveness(app_and_client):
    """Verify /api/health endpoint satisfies both backward-compatibility and Phase 12 fields."""
    _, client = app_and_client
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "NetSentinel Backend"
    assert data["alive"] is True
    assert "version" in data
    assert "timestamp" in data
    assert "request_id" in data


def test_api_readiness_healthy(app_and_client):
    """Verify /api/ready returns 200 when database and workers are operational."""
    _, client = app_and_client
    res = client.get("/api/ready")
    assert res.status_code == 200
    data = res.get_json()
    assert data["ready"] is True
    assert data["checks"]["database"] == "ok"
    assert data["checks"]["configuration"] == "ok"


def test_api_system_status_diagnostics(app_and_client):
    """Verify /api/system/status returns rich operational diagnostics without secret leakage."""
    _, client = app_and_client
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "application" in data
    assert data["application"]["name"] == "NetSentinel"
    assert data["application"]["version"] == Config.VERSION
    assert "uptime_seconds" in data["application"]

    # Database health
    assert "database" in data
    assert data["database"]["healthy"] is True
    assert "latency_ms" in data["database"]

    # Firewall diagnostics
    assert "firewall" in data
    assert "capable" in data["firewall"]

    # Redacted configuration check (no sensitive keys exposed)
    config_dict = data.get("configuration", {})
    assert "secret_key" in config_dict or "SECRET_KEY" in config_dict
    raw_str = json.dumps(config_dict)
    assert "super-secret" not in raw_str
    if "secret_key" in config_dict:
        assert config_dict["secret_key"] == "[REDACTED]"


# ==============================================================================
# 6. Worker Lifecycle & Watchdog Tests
# ==============================================================================

def test_lifecycle_manager_worker_registration_and_status():
    """Verify LifecycleManager registers workers and records heartbeats."""
    mgr = LifecycleManager()
    dummy_worker = MagicMock()
    dummy_worker.is_alive.return_value = True

    mgr.register_worker("worker_a", dummy_worker, role="Test Worker", is_optional=False)
    statuses = mgr.get_all_worker_statuses()

    assert "worker_a" in statuses
    assert statuses["worker_a"]["status"] == WorkerStatus.HEALTHY
    assert statuses["worker_a"]["role"] == "Test Worker"

    # Record error transitions to degraded
    mgr.record_worker_error("worker_a", "Test exception occurred")
    statuses = mgr.get_all_worker_statuses()
    assert statuses["worker_a"]["status"] == WorkerStatus.DEGRADED
    assert statuses["worker_a"]["error_count"] == 1


def test_lifecycle_manager_readiness_assessment():
    """Verify assess_readiness fails if a non-optional worker is FAILED."""
    mgr = LifecycleManager()
    dummy_worker = MagicMock()
    dummy_worker.is_alive.return_value = False

    mgr.register_worker("critical_worker", dummy_worker, role="Critical", is_optional=False)
    mgr.set_worker_status("critical_worker", WorkerStatus.FAILED, error="Crash")

    is_ready, checks = mgr.assess_readiness()
    assert is_ready is False
    assert checks["critical_worker"].lower() == "failed"


def test_lifecycle_manager_graceful_shutdown():
    """Verify stop_all invokes stop() on all registered workers."""
    mgr = LifecycleManager()
    worker_1 = MagicMock()
    worker_2 = MagicMock()

    mgr.register_worker("w1", worker_1)
    mgr.register_worker("w2", worker_2)

    assert not mgr.shutdown_event.is_set()
    mgr.stop_all(timeout=1.0)
    assert mgr.shutdown_event.is_set()

    worker_1.stop.assert_called_once()
    worker_2.stop.assert_called_once()


# ==============================================================================
# 7. Database Health Probe & Hardening Pragmas Tests
# ==============================================================================

def test_database_health_check(app_and_client):
    """Verify check_database_health executes a quick probe and measures latency."""
    app, _ = app_and_client
    with app.app_context():
        res = check_database_health()
        assert res["healthy"] is True
        assert res["status"] == "ok"
        assert res["latency_ms"] is not None
        assert res["latency_ms"] >= 0.0


# ==============================================================================
# 8. Firewall Capability Probe Tests
# ==============================================================================

def test_firewall_capabilities_probe():
    """Verify check_firewall_capabilities correctly evaluates binary existence and permissions."""
    mock_fw = MagicMock()
    mock_fw.dry_run = True

    # Case 1: dry_run mode enabled
    res = check_firewall_capabilities(mock_fw)
    assert res["capable"] is True
    assert res["mode"] == "dry_run"

    # Case 2: active mode with mock which returning None (no iptables)
    mock_fw.dry_run = False
    with patch("shutil.which", return_value=None):
        res = check_firewall_capabilities(mock_fw)
        assert res["capable"] is False
        assert res["mode"] in ("unavailable", "missing_binary")
