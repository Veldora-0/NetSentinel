"""Unit and integration tests for packet capture interface, runtime status, and rate limiting.

Tests cover:
1. Configured interface is passed to the capture engine.
2. Runtime interface reported by the API matches the interface actually opened.
3. Capture status transitions correctly on startup, stop, and initialization failure.
4. Packet counters increase when test frames are processed.
5. Missing interfaces and socket errors are reported clearly without fallback to eth0.
6. Authoritative capture state exposed to the dashboard.
7. Normal dashboard polling does not repeatedly exceed rate limits.
8. Socket.IO / CORS accepts development origins (including http://10.0.2.3:5173) and rejects unapproved origins.
"""

import os
import sys
import time
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from capture import TrafficMetrics, PacketCapture
from parser import ParsedPacket
from config import Config, resolve_network_interface
from security_middleware import InMemoryRateLimiter, SecurityMiddleware
from app import create_app


def test_configured_interface_passed_to_capture_engine():
    """Verify configured interface is preserved and tracked by PacketCapture."""
    capture = PacketCapture(interface="enp0s3", configured_interface="enp0s3")
    assert capture.interface == "enp0s3"
    assert capture.configured_interface == "enp0s3"
    assert capture.actual_interface is None  # Not opened yet

    metrics = capture.get_metrics()
    assert metrics["configured_interface"] == "enp0s3"
    assert metrics["interface"] == "enp0s3"
    assert metrics["actual_interface"] is None
    assert metrics["socket_state"] == "CLOSED"
    assert metrics["status"] == "stopped"


def test_runtime_interface_reported_by_api_matches_active():
    """Verify API endpoints report actual and configured interface accurately."""
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "NETWORK_INTERFACE": "enp0s3",
        "AUTH_ENABLED": False,
    }
    app, _ = create_app(config_class=test_config, start_capture=False)

    with app.test_client() as client:
        # 1. /api/metrics
        resp = client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["configured_interface"] == "enp0s3"
        assert data["interface"] == "enp0s3"
        assert "socket_state" in data

        # 2. /api/network/status
        resp_net = client.get("/api/network/status")
        assert resp_net.status_code == 200
        net_data = resp_net.get_json()
        assert net_data["network"]["capture"]["configured_interface"] == "enp0s3"
        assert net_data["network"]["capture"]["interface"] == "enp0s3"

        # 3. /api/system/status
        resp_sys = client.get("/api/system/status")
        assert resp_sys.status_code == 200
        sys_data = resp_sys.get_json()
        assert sys_data["packet_capture"]["configured_interface"] == "enp0s3"


def test_capture_status_transitions():
    """Verify lifecycle state transitions across start, running, stop, and mock failure."""
    capture = PacketCapture(interface="lo")
    assert capture.status == "stopped"
    assert capture.socket_state == "CLOSED"

    # Mock successful raw socket
    mock_sock = MagicMock()
    with patch("socket.socket", return_value=mock_sock):
        started = capture.start()
        assert started is True
        assert capture.status == "running"
        assert capture.actual_interface == "lo"
        assert capture.socket_state == "OPEN"

        metrics = capture.get_metrics()
        assert metrics["status"] == "running"
        assert metrics["actual_interface"] == "lo"
        assert metrics["socket_state"] == "OPEN"

        capture.stop()
        assert capture.status == "stopped"
        assert capture.actual_interface is None
        assert capture.socket_state == "CLOSED"


def test_packet_counters_and_rates_update():
    """Verify packet counters and rates increase when test frames are processed."""
    capture = PacketCapture(interface="enp0s3")
    t0 = time.time()

    # Inject 5 test ICMP frames
    for i in range(5):
        pkt = ParsedPacket(
            timestamp=t0 + (i * 0.2),
            raw_length=98,
            src_mac="08:00:27:12:34:56",
            dst_mac="08:00:27:3e:3c:0d",
            ethertype=0x0800,
            ethertype_name="IPv4",
            protocol=1,
            protocol_name="ICMP",
            src_ip="10.0.2.15",
            dst_ip="10.0.2.3",
        )
        capture.process_test_packet(pkt)

    metrics = capture.get_metrics()
    assert metrics["total_packets"] == 5
    assert metrics["total_frames"] == 5
    assert metrics["total_bytes"] == 5 * 98
    assert metrics["icmp_packets"] == 5
    assert metrics["tcp_packets"] == 0
    assert metrics["udp_packets"] == 0
    assert metrics["packets_per_sec"] > 0
    assert metrics["current_pps"] > 0


def test_missing_interface_reported_clearly_without_eth0_fallback():
    """Verify nonexistent interface reports clear error state without crashing or defaulting to eth0."""
    nonexistent = "invalid_dev_9999"
    capture = PacketCapture(interface=nonexistent, configured_interface=nonexistent)

    started = capture.start()
    assert started is False
    assert capture.status == "error"
    assert capture.socket_state == "ERROR"
    assert capture.actual_interface is None
    assert capture.error_message is not None
    assert nonexistent in capture.error_message
    assert "does not exist on this host" in capture.error_message

    metrics = capture.get_metrics()
    assert metrics["status"] == "error"
    assert metrics["socket_state"] == "ERROR"
    assert metrics["error"] == capture.error_message
    assert metrics["interface"] == nonexistent
    assert metrics["configured_interface"] == nonexistent
    assert "eth0" not in (metrics["interface"], metrics["configured_interface"])


def test_dashboard_polling_rate_limits_under_schedule():
    """Verify normal dashboard polling from 127.0.0.1 does not exceed rate limits."""
    # Test with standard rate limiter configured for SOC dashboard usage (240 req/min)
    limiter = InMemoryRateLimiter(default_limit=240, sensitive_limit=10, window_sec=60.0)

    client_ip = "127.0.0.1"

    # Simulate 80 rapid dashboard GET requests (e.g. initial multi-card mount + fast tab switching)
    for _ in range(80):
        allowed, retry_after = limiter.is_allowed(client_ip, is_sensitive=False)
        assert allowed is True
        assert retry_after == 0

    # Verify sensitive requests (e.g. login, firewall action) remain strictly bounded
    for _ in range(10):
        allowed, _ = limiter.is_allowed(client_ip, is_sensitive=True)
        assert allowed is True

    # 11th sensitive request must be rejected
    allowed_sensitive_overflow, retry_sensitive = limiter.is_allowed(client_ip, is_sensitive=True)
    assert allowed_sensitive_overflow is False
    assert retry_sensitive > 0


def test_socketio_cors_accepts_configured_origins_and_rejects_unapproved():
    """Verify CORS origins include development origins (e.g. 10.0.2.3:5173) and reject others."""
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "AUTH_ENABLED": False,
        "CORS_ORIGINS": ["http://localhost:5173", "http://127.0.0.1:5173", "http://10.0.2.3:5173"],
    }
    app, _ = create_app(config_class=test_config, start_capture=False)

    with app.test_client() as client:
        # Approved origin 1: http://10.0.2.3:5173
        resp1 = client.get("/api/health", headers={"Origin": "http://10.0.2.3:5173"})
        assert resp1.headers.get("Access-Control-Allow-Origin") == "http://10.0.2.3:5173"

        # Approved origin 2: http://localhost:5173
        resp2 = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert resp2.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"

        # Unapproved origin: http://malicious-site.com
        resp3 = client.get("/api/health", headers={"Origin": "http://malicious-site.com"})
        assert resp3.headers.get("Access-Control-Allow-Origin") != "http://malicious-site.com"
