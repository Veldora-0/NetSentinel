"""Unit tests for NetSentinel Risk and Firewall REST API and Socket.IO Integration."""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app import create_app
from detector import SecurityEvent


@pytest.fixture
def test_app():
    """Create test Flask app and SocketIO instance."""
    app, socketio = create_app(start_capture=False)
    app.config["TESTING"] = True
    return app, socketio


def test_api_risk_recent_and_stats(test_app):
    """Test GET /api/risk/recent and GET /api/risk/stats endpoints."""
    app, _ = test_app
    with app.test_client() as client:
        # Pre-populate an assessment
        app.risk_engine.assess("198.51.100.12", rule_alerts=[{"severity": "HIGH"}])

        res_recent = client.get("/api/risk/recent")
        assert res_recent.status_code == 200
        data_recent = res_recent.get_json()
        assert data_recent["status"] == "ok"
        assert len(data_recent["assessments"]) >= 1
        assert data_recent["assessments"][0]["source_ip"] == "198.51.100.12"

        res_stats = client.get("/api/risk/stats")
        assert res_stats.status_code == 200
        data_stats = res_stats.get_json()
        assert data_stats["status"] == "ok"
        assert data_stats["stats"]["total_assessments"] >= 1


def test_api_firewall_status_and_blocked(test_app):
    """Test GET /api/firewall/status and GET /api/firewall/blocked endpoints."""
    app, _ = test_app
    with app.test_client() as client:
        res_status = client.get("/api/firewall/status")
        assert res_status.status_code == 200
        data_status = res_status.get_json()
        assert data_status["status"] == "ok"
        assert "enabled" in data_status["firewall"]
        assert "chain" in data_status["firewall"]

        res_blocked = client.get("/api/firewall/blocked")
        assert res_blocked.status_code == 200
        data_blocked = res_blocked.get_json()
        assert data_blocked["status"] == "ok"
        assert isinstance(data_blocked["blocked_ips"], list)


def test_api_firewall_manual_block_and_unblock(test_app):
    """Test POST /api/firewall/block and POST /api/firewall/unblock endpoints."""
    app, _ = test_app
    with app.test_client() as client:
        # 1. Invalid request (missing IP)
        res_bad = client.post("/api/firewall/block", json={})
        assert res_bad.status_code == 400

        # 2. Invalid IP address
        res_invalid = client.post("/api/firewall/block", json={"ip": "invalid-ip-format"})
        assert res_invalid.status_code == 400

        # 3. Protected localhost IP rejection
        res_lb = client.post("/api/firewall/block", json={"ip": "127.0.0.1"})
        assert res_lb.status_code == 400

        # 4. Valid manual block
        res_ok = client.post(
            "/api/firewall/block",
            json={"ip": "198.51.100.70", "reason": "Operator Test Block", "duration": 120},
        )
        assert res_ok.status_code == 200
        data_ok = res_ok.get_json()
        assert data_ok["status"] == "ok"
        assert app.firewall.is_blocked("198.51.100.70") is True

        # 5. Valid manual unblock
        res_unblock = client.post("/api/firewall/unblock", json={"ip": "198.51.100.70"})
        assert res_unblock.status_code == 200
        assert app.firewall.is_blocked("198.51.100.70") is False


def test_socketio_risk_and_firewall_events(test_app):
    """Test Socket.IO initial risk and firewall payloads and live event broadcast."""
    app, socketio = test_app
    socket_client = socketio.test_client(app)
    assert socket_client.is_connected()

    received = socket_client.get_received()
    event_names = [evt["name"] for evt in received]

    assert "risk_status" in event_names
    assert "firewall_status" in event_names
    assert "blocked_ips" in event_names

    # Trigger a rule-based SecurityEvent to test full pipeline to risk assessment
    sec_event = SecurityEvent(
        event_id="test-evt-001",
        timestamp=time.time(),
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="198.51.100.80",
        destination_ip="10.0.0.1",
        protocol="TCP",
        source_port=12345,
        destination_port=80,
        description="Port scan detected",
        evidence={"unique_ports": 20},
        rule_name="RULE_PORT_SCAN",
    )

    # Invoke internal callback directly to simulate rule engine detection
    for cb in app.detector._event_callbacks:
        cb(sec_event)

    new_received = socket_client.get_received()
    new_event_names = [evt["name"] for evt in new_received]

    assert "security_event" in new_event_names
    assert "risk_assessment" in new_event_names

    socket_client.disconnect()
