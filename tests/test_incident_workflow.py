"""Unit tests for Incident Lifecycle Workflow Transitions, Timeline, and Report Summaries."""

import os
import sys
import time
import pytest
from flask import Flask

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database import db, init_db
from incident_manager import (
    IncidentManager,
    STATUS_OPEN,
    STATUS_ACKNOWLEDGED,
    STATUS_RESOLVED,
    STATUS_CLOSED,
)
from detector import SecurityEvent


@pytest.fixture
def app_ctx():
    """Create Flask application context with in-memory database."""
    app = Flask("test_incident_workflow_app")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    init_db(app)

    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


def test_status_workflow_transitions(app_ctx):
    """Test standard progression: OPEN -> ACKNOWLEDGED -> RESOLVED -> CLOSED."""
    status_events = []
    mgr = IncidentManager(
        on_incident_status_changed=lambda data: status_events.append(data)
    )

    t0 = time.time()
    ev = SecurityEvent(
        event_id="ev-wf-1",
        timestamp=t0,
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="192.168.1.90",
    )
    inc = mgr.correlate_security_event(ev)
    inc_id = inc.incident_id

    # 1. Acknowledge
    ok, msg, data = mgr.transition_status(inc_id, STATUS_ACKNOWLEDGED, analyst_note="Investigating")
    assert ok is True
    assert data["status"] == STATUS_ACKNOWLEDGED
    assert data["analyst_note"] == "Investigating"

    # 2. Resolve
    ok, msg, data = mgr.transition_status(
        inc_id, STATUS_RESOLVED, resolution="Firewall block mitigated scanning activity"
    )
    assert ok is True
    assert data["status"] == STATUS_RESOLVED
    assert data["closed_at"] is not None
    assert "mitigated" in data["resolution"]

    # 3. Close
    ok, msg, data = mgr.transition_status(inc_id, STATUS_CLOSED)
    assert ok is True
    assert data["status"] == STATUS_CLOSED

    # 4. Reopen
    ok, msg, data = mgr.transition_status(inc_id, STATUS_OPEN, analyst_note="Reopened due to recurrence")
    assert ok is True
    assert data["status"] == STATUS_OPEN
    assert data["analyst_note"] == "Reopened due to recurrence"

    assert len(status_events) == 4


def test_invalid_status_rejected(app_ctx):
    """Test that invalid target statuses and impossible transitions are safely rejected."""
    mgr = IncidentManager()

    t0 = time.time()
    ev = SecurityEvent(
        event_id="ev-bad-1",
        timestamp=t0,
        detection_type="NULL_SCAN",
        severity="LOW",
        source_ip="192.168.1.91",
    )
    inc = mgr.correlate_security_event(ev)

    ok, msg, _ = mgr.transition_status(inc.incident_id, "BOGUS_STATUS")
    assert ok is False
    assert "Invalid target status" in msg

    ok_missing, msg_missing, _ = mgr.transition_status("nonexistent-inc-id", STATUS_ACKNOWLEDGED)
    assert ok_missing is False
    assert "not found" in msg_missing


def test_timeline_construction(app_ctx):
    """Test generating a chronological timeline containing milestones, alerts, and firewall actions."""
    mgr = IncidentManager()

    t0 = time.time()
    ev = SecurityEvent(
        event_id="ev-time-1",
        timestamp=t0,
        detection_type="XMAS_SCAN",
        severity="MEDIUM",
        source_ip="192.168.1.92",
        description="XMAS scan detected",
    )
    inc = mgr.correlate_security_event(ev)

    mgr.correlate_firewall_action(
        action="block",
        source_ip="192.168.1.92",
        reason="Auto Block mitigation",
        duration=300.0,
        timestamp=t0 + 2,
    )

    mgr.transition_status(
        inc.incident_id, STATUS_RESOLVED, resolution="Attack neutralized", analyst_note="Done"
    )

    timeline = mgr.build_incident_timeline(inc.incident_id)

    assert len(timeline) >= 3
    # Check chronological ordering
    timestamps = [item["timestamp"] for item in timeline]
    assert timestamps == sorted(timestamps)

    # Check entry types
    types = [item["type"] for item in timeline]
    assert "MILESTONE" in types
    assert "SECURITY_EVENT" in types
    assert "FIREWALL_ACTION" in types


def test_incident_summary_report(app_ctx):
    """Test generating a report-ready SOC summary dictionary."""
    mgr = IncidentManager()

    t0 = time.time()
    ev = SecurityEvent(
        event_id="ev-sum-1",
        timestamp=t0,
        detection_type="SYN_FLOOD",
        severity="HIGH",
        source_ip="192.168.1.93",
    )
    inc = mgr.correlate_security_event(ev)

    summary = mgr.get_incident_summary(inc.incident_id)

    assert summary is not None
    assert summary["incident_id"] == inc.incident_id
    assert summary["primary_source_ip"] == "192.168.1.93"
    assert summary["severity"] == "HIGH"
    assert summary["total_events"] == 1
    assert "SYN_FLOOD" in summary["attack_vectors"]
    assert "network" in summary["attack_domains"]
    assert summary["first_seen_iso"] is not None
    assert summary["last_seen_iso"] is not None
