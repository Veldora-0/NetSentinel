"""Unit tests for NetSentinel Incident Correlation Engine, Risk Aggregation, and Monotonicity."""

import os
import sys
import time
import pytest
from flask import Flask

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database import db, init_db
from incident_manager import IncidentManager, STATUS_OPEN
from detector import SecurityEvent
from risk_engine import RiskAssessment


@pytest.fixture
def app_ctx():
    """Create Flask application context with in-memory database."""
    app = Flask("test_incident_correlator_app")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    init_db(app)

    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


def test_single_alert_creates_incident(app_ctx):
    """Test that a single incoming SecurityEvent initiates an open incident."""
    created_events = []
    mgr = IncidentManager(
        config={"incident_window_sec": 300.0},
        on_incident_created=lambda inc: created_events.append(inc),
    )

    t0 = time.time()
    event = SecurityEvent(
        event_id="ev-101",
        timestamp=t0,
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.1",
        description="Port Scan detected from 192.168.1.50",
    )

    incident = mgr.correlate_security_event(event)

    assert incident is not None
    assert incident.status == STATUS_OPEN
    assert incident.primary_source_ip == "192.168.1.50"
    assert incident.correlation_key == "ip:192.168.1.50"
    assert incident.event_count == 1
    assert "network" in incident.attack_domains
    assert "PORT_SCAN" in incident.detection_types
    assert incident.risk_score >= 0.40  # MEDIUM severity score baseline
    assert "Port Scan" in incident.title
    assert len(created_events) == 1


def test_multiple_alerts_within_window_group_together(app_ctx):
    """Test that subsequent alerts from the same IP within the correlation window join the same incident."""
    mgr = IncidentManager(config={"incident_window_sec": 300.0})

    t0 = time.time()
    ev1 = SecurityEvent(
        event_id="ev-1",
        timestamp=t0,
        detection_type="PORT_SCAN",
        severity="LOW",
        source_ip="192.168.1.60",
    )
    ev2 = SecurityEvent(
        event_id="ev-2",
        timestamp=t0 + 45,
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip="192.168.1.60",
    )

    inc1 = mgr.correlate_security_event(ev1)
    inc2 = mgr.correlate_security_event(ev2)

    assert inc1.incident_id == inc2.incident_id
    assert inc2.event_count == 2
    assert inc2.first_seen == t0
    assert inc2.last_seen == t0 + 45


def test_alert_after_window_expiration_creates_new_incident(app_ctx):
    """Test that alerts arriving after the correlation window expires initiate a new incident."""
    mgr = IncidentManager(config={"incident_window_sec": 10.0})

    t0 = time.time()
    ev1 = SecurityEvent(
        event_id="ev-1",
        timestamp=t0,
        detection_type="SYN_FLOOD",
        severity="HIGH",
        source_ip="10.10.10.10",
    )
    # Arrives 15 seconds later (> 10s window)
    ev2 = SecurityEvent(
        event_id="ev-2",
        timestamp=t0 + 15,
        detection_type="SYN_FLOOD",
        severity="HIGH",
        source_ip="10.10.10.10",
    )

    inc1 = mgr.correlate_security_event(ev1)
    inc2 = mgr.correlate_security_event(ev2)

    assert inc1.incident_id != inc2.incident_id
    assert inc1.event_count == 1
    assert inc2.event_count == 1


def test_cross_domain_and_multi_vector_risk_boost(app_ctx):
    """Test deterministic boosts: cross-domain (+0.10) and multi-vector (+0.05)."""
    mgr = IncidentManager(
        config={
            "incident_window_sec": 300.0,
            "cross_domain_boost": 0.10,
            "multi_vector_boost": 0.05,
            "max_incident_boost": 0.20,
        }
    )

    t0 = time.time()
    # 1. Network event: PORT_SCAN (base MEDIUM = 0.40)
    net_ev = SecurityEvent(
        event_id="ev-net",
        timestamp=t0,
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip="172.16.0.5",
    )
    inc = mgr.correlate_security_event(net_ev)
    initial_score = inc.risk_score
    assert initial_score == pytest.approx(0.40, abs=0.01)

    # 2. Host event for same source IP: SSH_BRUTE_FORCE (base HIGH = 0.70)
    host_ev = SecurityEvent(
        event_id="ev-host",
        timestamp=t0 + 10,
        detection_type="SSH_BRUTE_FORCE",
        severity="HIGH",
        source_ip="172.16.0.5",
    )
    mgr.correlate_security_event(host_ev)

    # Base becomes max(0.40, 0.70) = 0.70
    # Domains: {'network', 'host'} -> +0.10 boost
    # Vectors: {'PORT_SCAN', 'SSH_BRUTE_FORCE'} -> +0.05 boost
    # Expected final score = 0.70 + 0.10 + 0.05 = 0.85 (CRITICAL)
    assert inc.risk_score == pytest.approx(0.85, abs=0.01)
    assert inc.severity == "CRITICAL"
    assert "Cross-Domain" in inc.title


def test_risk_score_monotonicity_never_downgrades(app_ctx):
    """Verify that lower-severity alerts never downgrade an existing critical incident."""
    mgr = IncidentManager(config={"incident_window_sec": 300.0})

    t0 = time.time()
    crit_ev = SecurityEvent(
        event_id="ev-crit",
        timestamp=t0,
        detection_type="SYN_FLOOD",
        severity="CRITICAL",
        source_ip="192.168.5.5",
    )
    inc = mgr.correlate_security_event(crit_ev)
    assert inc.severity == "CRITICAL"
    crit_score = inc.risk_score

    # Subsequent LOW alert arrives
    low_ev = SecurityEvent(
        event_id="ev-low",
        timestamp=t0 + 5,
        detection_type="ICMP_SWEEP",
        severity="LOW",
        source_ip="192.168.5.5",
    )
    mgr.correlate_security_event(low_ev)

    assert inc.severity == "CRITICAL"
    assert inc.risk_score >= crit_score


def test_host_suspicious_process_correlates_to_host_identity(app_ctx):
    """Verify SUSPICIOUS_PROCESS events correlate to host:<hostname>, not 127.0.0.1."""
    mgr = IncidentManager()

    t0 = time.time()
    proc_ev = SecurityEvent(
        event_id="ev-proc-1",
        timestamp=t0,
        detection_type="SUSPICIOUS_PROCESS",
        severity="HIGH",
        source_ip=None,
        evidence={"source": "host", "pid": 9999, "cmdline": "/tmp/evil"},
        description="Suspicious binary executed from /tmp",
    )

    inc = mgr.correlate_security_event(proc_ev)

    assert inc.correlation_key.startswith("host:")
    assert inc.primary_source_ip is None
    assert "Host" in inc.title
    assert "host" in inc.attack_domains


def test_firewall_mitigation_correlation(app_ctx):
    """Verify firewall actions are properly correlated as mitigation evidence."""
    mgr = IncidentManager()

    t0 = time.time()
    ev = SecurityEvent(
        event_id="ev-fw-test",
        timestamp=t0,
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="192.168.10.99",
    )
    inc = mgr.correlate_security_event(ev)
    assert inc.firewall_action_count == 0

    # Firewall block occurs
    fw_inc = mgr.correlate_firewall_action(
        action="block",
        source_ip="192.168.10.99",
        reason="Exceeded risk threshold",
        duration=300.0,
        timestamp=t0 + 2,
    )

    assert fw_inc.incident_id == inc.incident_id
    assert fw_inc.firewall_action_count == 1
    assert any(e.evidence_type == "FIREWALL_ACTION" for e in fw_inc.evidence_list)


def test_bounded_memory_evicts_oldest_active(app_ctx):
    """Test memory limit pruning when max_active_incidents is exceeded."""
    mgr = IncidentManager(config={"max_active_incidents": 3, "incident_window_sec": 300.0})

    t0 = time.time()
    for i in range(4):
        ev = SecurityEvent(
            event_id=f"ev-mem-{i}",
            timestamp=t0 + i * 10,
            detection_type="PORT_SCAN",
            severity="LOW",
            source_ip=f"10.0.0.{i+1}",
        )
        mgr.correlate_security_event(ev)

    assert len(mgr._active_by_key) <= 3
    # First IP (10.0.0.1) should have been pruned from active tracking
    assert "ip:10.0.0.1" not in mgr._active_by_key
    assert "ip:10.0.0.4" in mgr._active_by_key
