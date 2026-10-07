"""Phase 14 End-to-End Validation: Incident Correlation & Multi-Vector Synthesis.

Verifies:
1. Multi-vector sequences from the same source IP merge into a single incident.
2. Cross-domain attack classification captures both network and host evidence.
3. Deterministic correlation boosts (+0.10 cross-domain, +0.05 multi-vector) apply.
4. Risk score and severity behave monotonically (never accidentally downgraded).
5. Incident timeline reflects chronological ordering of attack progression.
6. Incident state and attached evidence persist cleanly to SQLite.
"""

import time
import pytest

from app import create_app
from database import db, get_incident_by_id, query_incidents
from detector import SecurityEvent


@pytest.fixture
def corr_app():
    cfg = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "INCIDENT_SETTINGS": {
            "incident_window_sec": 300.0,
            "cross_domain_boost": 0.10,
            "multi_vector_boost": 0.05,
            "max_incident_boost": 0.20,
        },
    }
    app, _ = create_app(config_class=cfg, start_capture=False)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_e2e_multi_vector_incident_lifecycle(corr_app):
    """Verify that network and host events merge, boost risk, and maintain timeline ordering."""
    mgr = corr_app.incident_manager
    now = time.time()
    attacker_ip = "192.168.1.200"

    # Step 1: Initial network probe (PORT_SCAN, MEDIUM severity = 0.40)
    ev_net1 = SecurityEvent(
        event_id="ev-seq-01",
        timestamp=now,
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip=attacker_ip,
        destination_ip="192.168.1.10",
        description="Port scan reconnaissance probe",
    )
    inc1 = mgr.correlate_security_event(ev_net1)
    inc_id = inc1.incident_id
    score1 = inc1.risk_score
    assert inc1.attack_domains == {"network"}
    assert inc1.detection_types == {"PORT_SCAN"}
    assert score1 >= 0.40

    # Step 2: Host authentication failure from same source IP (SSH_AUTH_FAILURE, LOW severity = 0.20)
    ev_host = SecurityEvent(
        event_id="ev-seq-02",
        timestamp=now + 5.0,
        detection_type="SSH_AUTH_FAILURE",
        severity="LOW",
        source_ip=attacker_ip,
        destination_ip="192.168.1.10",
        description="SSH authentication failure",
    )
    inc2 = mgr.correlate_security_event(ev_host)
    score2 = inc2.risk_score

    # Assert incident was merged, not duplicated
    assert inc2.incident_id == inc_id
    assert inc2.attack_domains == {"network", "host"}
    # Cross-domain boost applied -> risk score must increase
    assert score2 >= score1 + 0.10

    # Step 3: Second network vector (SYN_FLOOD, HIGH severity = 0.70)
    ev_net2 = SecurityEvent(
        event_id="ev-seq-03",
        timestamp=now + 10.0,
        detection_type="SYN_FLOOD",
        severity="HIGH",
        source_ip=attacker_ip,
        destination_ip="192.168.1.10",
        description="SYN flood denial of service",
    )
    inc3 = mgr.correlate_security_event(ev_net2)
    score3 = inc3.risk_score

    # Multi-vector boost applied
    assert inc3.incident_id == inc_id
    assert len(inc3.detection_types) >= 2
    assert score3 >= score2
    assert inc3.severity in ("HIGH", "CRITICAL")

    # Step 4: Verify timeline chronology
    timeline = mgr.build_incident_timeline(inc_id)
    assert len(timeline) >= 4  # Milestone + 3 events
    for i in range(len(timeline) - 1):
        assert timeline[i]["timestamp"] <= timeline[i + 1]["timestamp"]

    # Step 5: Verify SQLite persistence
    db_inc = get_incident_by_id(inc_id, include_evidence=True)
    assert db_inc is not None
    assert db_inc["incident_id"] == inc_id
    assert len(db_inc["evidence"]) >= 3


def test_e2e_critical_incident_monotonicity(corr_app):
    """Verify that an incident escalated to CRITICAL cannot be downgraded by low-severity events."""
    mgr = corr_app.incident_manager
    now = time.time()
    attacker_ip = "192.168.1.205"

    # Seed with CRITICAL event
    ev_crit = SecurityEvent(
        event_id="ev-crit-01",
        timestamp=now,
        detection_type="EXPLOIT_PAYLOAD",
        severity="CRITICAL",
        source_ip=attacker_ip,
        description="Zero-day exploit attempt",
    )
    inc = mgr.correlate_security_event(ev_crit)
    assert inc.severity == "CRITICAL"
    assert inc.risk_score >= 0.80

    # Follow up with a LOW severity event
    ev_low = SecurityEvent(
        event_id="ev-low-01",
        timestamp=now + 2.0,
        detection_type="PING_PROBE",
        severity="LOW",
        source_ip=attacker_ip,
        description="Routine ping probe",
    )
    inc_after = mgr.correlate_security_event(ev_low)

    # Invariant: Must remain CRITICAL
    assert inc_after.severity == "CRITICAL"
    assert inc_after.risk_score >= 0.80
