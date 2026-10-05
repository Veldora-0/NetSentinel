"""Integration tests for NetSentinel Historical Security Events and Host Telemetry APIs."""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app import create_app
from detector import SecurityEvent


@pytest.fixture
def app_and_client():
    """Create test application and test client fixture."""
    app, socketio = create_app(start_capture=False)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield app, client, socketio


def test_api_security_events_endpoint(app_and_client):
    """Test GET /api/events endpoint with filtering and pagination."""
    app, client, _ = app_and_client

    # Inject security events into the system callback
    event = SecurityEvent(
        event_id="api-evt-001",
        timestamp=time.time(),
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="198.51.100.99",
        destination_ip="10.0.0.1",
        protocol="TCP",
        source_port=44444,
        destination_port=80,
        description="Port scan detected across 20 ports",
        evidence={"unique_ports": 20},
        rule_name="RULE_PORT_SCAN",
    )

    for cb in app.detector._event_callbacks:
        cb(event)

    # 1. Query without filters
    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["total"] >= 1
    assert any(e["event_id"] == "api-evt-001" for e in data["events"])

    # 2. Query with matching source_ip filter
    res_ip = client.get("/api/events?source_ip=198.51.100.99")
    assert res_ip.status_code == 200
    data_ip = res_ip.get_json()
    assert data_ip["count"] >= 1
    assert data_ip["events"][0]["source_ip"] == "198.51.100.99"

    # 3. Query with non-matching filter
    res_none = client.get("/api/events?source_ip=99.99.99.99")
    assert res_none.status_code == 200
    data_none = res_none.get_json()
    assert data_none["count"] == 0


def test_api_risk_history_endpoint(app_and_client):
    """Test GET /api/risk/history endpoint returns persisted assessments."""
    app, client, _ = app_and_client

    # Trigger a risk assessment through the pipeline
    sec_event = SecurityEvent(
        event_id="risk-api-evt",
        timestamp=time.time(),
        detection_type="SYN_FLOOD",
        severity="CRITICAL",
        source_ip="198.51.100.105",
        destination_ip="10.0.0.1",
        protocol="TCP",
        source_port=54321,
        destination_port=80,
        description="SYN flood attack",
        evidence={"syn_rate": 200},
        rule_name="RULE_SYN_FLOOD",
    )
    for cb in app.detector._event_callbacks:
        cb(sec_event)

    res = client.get("/api/risk/history")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["total"] >= 1
    assert any(a["source_ip"] == "198.51.100.105" for a in data["assessments"])


def test_api_security_summary_endpoint(app_and_client):
    """Test GET /api/security/summary endpoint returns aggregate statistics."""
    app, client, _ = app_and_client

    res = client.get("/api/security/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    summary = data["summary"]
    assert "total_events" in summary
    assert "total_assessments" in summary
    assert "total_firewall_actions" in summary
    assert "detection_types" in summary
    assert "severities" in summary
    assert "top_source_ips" in summary


def test_api_telemetry_endpoints(app_and_client):
    """Test GET /api/telemetry/current and GET /api/telemetry/history endpoints."""
    app, client, _ = app_and_client

    # 1. Current telemetry snapshot
    res_cur = client.get("/api/telemetry/current")
    assert res_cur.status_code == 200
    data_cur = res_cur.get_json()
    assert data_cur["status"] == "ok"
    telem = data_cur["telemetry"]
    assert "cpu_percent" in telem
    assert "memory_percent" in telem
    assert "disk_percent" in telem
    assert "host_tx_bps" in telem

    # 2. Historical telemetry query
    res_hist = client.get("/api/telemetry/history?limit=10")
    assert res_hist.status_code == 200
    data_hist = res_hist.get_json()
    assert data_hist["status"] == "ok"
    assert isinstance(data_hist["telemetry"], list)


def test_firewall_action_persistence(app_and_client):
    """Test that manual block and unblock operations are persisted in the database."""
    app, client, _ = app_and_client

    # Block IP
    res_block = client.post(
        "/api/firewall/block",
        json={"ip": "198.51.100.222", "reason": "Test Persistence Block", "duration": 300},
    )
    assert res_block.status_code == 200

    # Unblock IP
    res_unblock = client.post(
        "/api/firewall/unblock",
        json={"ip": "198.51.100.222"},
    )
    assert res_unblock.status_code == 200

    # Verify summary reflects firewall actions
    res_sum = client.get("/api/security/summary")
    summary = res_sum.get_json()["summary"]
    assert summary["total_firewall_actions"] >= 2
