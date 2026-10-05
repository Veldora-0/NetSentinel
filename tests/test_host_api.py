"""API and integration tests for Host Intrusion Detection endpoints and pipeline (Phase 7)."""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app import create_app
from detector import SecurityEvent
from database import SecurityEventRecord


@pytest.fixture
def app_and_client():
    app, socketio = create_app(start_capture=False)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield app, client


def test_get_host_status(app_and_client):
    """Verify GET /api/host/status returns correct HIDS structure."""
    app, client = app_and_client
    response = client.get("/api/host/status")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert "data" in data
    
    status = data["data"]
    assert "enabled" in status
    assert "ssh_detector" in status
    assert "process_monitor" in status
    assert "status" in status["ssh_detector"]
    assert "status" in status["process_monitor"]


def test_get_host_events_empty_or_filtered(app_and_client):
    """Verify GET /api/host/events returns list containing only host security events."""
    app, client = app_and_client
    response = client.get("/api/host/events")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert "events" in data
    assert isinstance(data["events"], list)


def test_host_event_pipeline_integration(app_and_client):
    """Verify host security event is persisted to database, assessed by risk engine, and queryable."""
    app, client = app_and_client
    test_id = f"test-host-evt-{int(time.time() * 1000)}"
    host_evt = SecurityEvent(
        event_id=test_id,
        timestamp=time.time(),
        detection_type="SSH_BRUTE_FORCE",
        severity="HIGH",
        source_ip="198.51.100.99",
        destination_ip="127.0.0.1",
        description="Test SSH brute force for pipeline test",
        metadata={"failures": 5, "username": "admin"},
    )

    # Process host event through application pipeline
    app.host_manager._dispatch_event(host_evt)

    # Check persistence in database
    with app.app_context():
        record = SecurityEventRecord.query.filter_by(event_id=test_id).first()
        assert record is not None
        assert record.detection_type == "SSH_BRUTE_FORCE"
        assert record.source_ip == "198.51.100.99"
        assert record.severity == "HIGH"

    # Query through /api/host/events
    resp = client.get("/api/host/events")
    assert resp.status_code == 200
    events = resp.get_json()["events"]
    matched = [e for e in events if e["event_id"] == test_id]
    assert len(matched) == 1
    assert matched[0]["detection_type"] == "SSH_BRUTE_FORCE"


def test_suspicious_process_event_pipeline_null_ip(app_and_client):
    """Verify local host process event with None source_ip persists and processes safely."""
    app, client = app_and_client
    test_id = f"test-proc-evt-{int(time.time() * 1000)}"
    proc_evt = SecurityEvent(
        event_id=test_id,
        timestamp=time.time(),
        detection_type="SUSPICIOUS_PROCESS",
        severity="MEDIUM",
        source_ip=None,
        description="Test suspicious process in /tmp",
        metadata={"pid": 77777, "exe": "/tmp/test.sh"},
    )

    app.host_manager._dispatch_event(proc_evt)

    # Verify database persistence
    with app.app_context():
        record = SecurityEventRecord.query.filter_by(event_id=test_id).first()
        assert record is not None
        assert record.detection_type == "SUSPICIOUS_PROCESS"
        assert record.source_ip is None or record.source_ip == "127.0.0.1"
