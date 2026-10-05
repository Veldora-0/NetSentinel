"""Unit tests for NetSentinel Incident REST API Endpoints and Socket.IO Integration."""

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


def test_api_incidents_crud_and_query(test_app):
    """Test GET /api/incidents and GET /api/incidents/<id> endpoints."""
    app, _ = test_app
    with app.test_client() as client:
        # Generate an incident via pipeline
        ev = SecurityEvent(
            event_id="ev-api-01",
            timestamp=time.time(),
            detection_type="PORT_SCAN",
            severity="HIGH",
            source_ip="198.51.100.88",
            description="API test port scan",
        )
        with app.app_context():
            inc = app.incident_manager.correlate_security_event(ev)
            inc_id = inc.incident_id

        # Query all incidents
        res = client.get("/api/incidents")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["total"] >= 1
        assert any(i["incident_id"] == inc_id for i in data["incidents"])

        # Query with filters
        res_filter = client.get("/api/incidents?severity=HIGH&status=OPEN")
        assert res_filter.status_code == 200
        data_filter = res_filter.get_json()
        assert data_filter["total"] >= 1

        # Query single incident detail
        res_detail = client.get(f"/api/incidents/{inc_id}")
        assert res_detail.status_code == 200
        detail_data = res_detail.get_json()
        assert detail_data["status"] == "ok"
        assert detail_data["incident"]["incident_id"] == inc_id
        assert len(detail_data["incident"]["evidence"]) >= 1

        # Query nonexistent incident
        res_404 = client.get("/api/incidents/inc-nonexistent-999")
        assert res_404.status_code == 404


def test_api_incident_timeline_and_summary(test_app):
    """Test GET /api/incidents/<id>/timeline and GET /api/incidents/<id>/summary."""
    app, _ = test_app
    with app.test_client() as client:
        t0 = time.time()
        ev = SecurityEvent(
            event_id="ev-api-02",
            timestamp=t0,
            detection_type="SYN_FLOOD",
            severity="CRITICAL",
            source_ip="198.51.100.89",
        )
        with app.app_context():
            inc = app.incident_manager.correlate_security_event(ev)
            app.incident_manager.correlate_firewall_action(
                action="block",
                source_ip="198.51.100.89",
                reason="Auto block test",
                duration=300.0,
                timestamp=t0 + 1,
            )
            inc_id = inc.incident_id

        # Timeline
        res_time = client.get(f"/api/incidents/{inc_id}/timeline")
        assert res_time.status_code == 200
        data_time = res_time.get_json()
        assert data_time["status"] == "ok"
        assert data_time["count"] >= 2
        assert len(data_time["timeline"]) >= 2

        # Summary
        res_sum = client.get(f"/api/incidents/{inc_id}/summary")
        assert res_sum.status_code == 200
        data_sum = res_sum.get_json()
        assert data_sum["status"] == "ok"
        assert data_sum["summary"]["incident_id"] == inc_id
        assert data_sum["summary"]["severity"] == "CRITICAL"
        assert data_sum["summary"]["total_mitigations"] == 1


def test_api_incident_workflow_transitions(test_app):
    """Test operator action shortcuts: acknowledge, resolve, reopen, close."""
    app, _ = test_app
    with app.test_client() as client:
        ev = SecurityEvent(
            event_id="ev-api-03",
            timestamp=time.time(),
            detection_type="NULL_SCAN",
            severity="LOW",
            source_ip="198.51.100.90",
        )
        with app.app_context():
            inc = app.incident_manager.correlate_security_event(ev)
            inc_id = inc.incident_id

        # 1. Acknowledge
        res_ack = client.post(f"/api/incidents/{inc_id}/acknowledge", json={"analyst_note": "Taking ticket"})
        assert res_ack.status_code == 200
        assert res_ack.get_json()["incident"]["status"] == "ACKNOWLEDGED"

        # 2. Resolve
        res_res = client.post(
            f"/api/incidents/{inc_id}/resolve",
            json={"resolution": "Harmless scan dismissed", "analyst_note": "Closed out"},
        )
        assert res_res.status_code == 200
        assert res_res.get_json()["incident"]["status"] == "RESOLVED"

        # 3. Reopen
        res_reopen = client.post(f"/api/incidents/{inc_id}/reopen", json={"analyst_note": "Reopened by admin"})
        assert res_reopen.status_code == 200
        assert res_reopen.get_json()["incident"]["status"] == "OPEN"

        # 4. Close
        res_close = client.post(f"/api/incidents/{inc_id}/close", json={"resolution": "Finished investigation"})
        assert res_close.status_code == 200
        assert res_close.get_json()["incident"]["status"] == "CLOSED"


def test_api_incident_stats_endpoint(test_app):
    """Test GET /api/incidents/stats endpoint."""
    app, _ = test_app
    with app.test_client() as client:
        res = client.get("/api/incidents/stats")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert "total_incidents" in data["stats"]
        assert "open" in data["stats"]
        assert "resolved" in data["stats"]
        assert "severities" in data["stats"]


def test_socketio_incident_events(test_app):
    """Test Socket.IO emission of incident events."""
    app, socketio = test_app
    socket_client = socketio.test_client(app)
    assert socket_client.is_connected()

    received = socket_client.get_received()
    event_names = [e["name"] for e in received]
    assert "connection_response" in event_names
    assert "incident_stats" in event_names

    # Trigger security event pipeline to emit incident_created
    ev = SecurityEvent(
        event_id="ev-sock-01",
        timestamp=time.time(),
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="198.51.100.99",
    )
    with app.app_context():
        app.incident_manager.correlate_security_event(ev)

    received_after = socket_client.get_received()
    after_events = [e["name"] for e in received_after]
    assert "incident_created" in after_events

    socket_client.disconnect()
