"""Unit tests for NetSentinel Incident Database Models, Persistence, Queries, and Retention."""

import os
import sys
import time
import pytest
from flask import Flask

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database import (
    db,
    init_db,
    IncidentRecord,
    IncidentEvidenceRecord,
    save_incident_record,
    save_incident_evidence_record,
    get_incident_by_id,
    query_incidents,
    query_incident_stats,
    query_security_summary,
    cleanup_old_records,
)


@pytest.fixture
def app_ctx():
    """Create Flask application with in-memory SQLite database for testing."""
    app = Flask("test_incident_db_app")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    init_db(app)

    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


def test_save_and_get_incident_record(app_ctx):
    """Test creating and retrieving an IncidentRecord."""
    t0 = time.time()
    inc_data = {
        "incident_id": "inc-test-001",
        "created_at": t0,
        "updated_at": t0,
        "status": "OPEN",
        "severity": "HIGH",
        "risk_score": 0.75,
        "title": "Port Scan Activity from 192.168.1.100",
        "summary": "Port scanning detected.",
        "primary_source_ip": "192.168.1.100",
        "correlation_key": "ip:192.168.1.100",
        "attack_domains": ["network"],
        "detection_types": ["PORT_SCAN"],
        "event_count": 3,
        "risk_assessment_count": 3,
        "firewall_action_count": 1,
        "first_seen": t0,
        "last_seen": t0 + 10,
        "correlation_reason": "Grouped 3 port scan events.",
    }

    assert save_incident_record(inc_data) is True

    retrieved = get_incident_by_id("inc-test-001", include_evidence=True)
    assert retrieved is not None
    assert retrieved["incident_id"] == "inc-test-001"
    assert retrieved["severity"] == "HIGH"
    assert retrieved["risk_score"] == 0.75
    assert retrieved["primary_source_ip"] == "192.168.1.100"
    assert "network" in retrieved["attack_domains"]
    assert "PORT_SCAN" in retrieved["detection_types"]
    assert retrieved["event_count"] == 3
    assert retrieved["evidence"] == []


def test_update_existing_incident_record(app_ctx):
    """Test updating existing incident record fields."""
    t0 = time.time()
    inc_data = {
        "incident_id": "inc-test-update",
        "created_at": t0,
        "updated_at": t0,
        "status": "OPEN",
        "severity": "LOW",
        "risk_score": 0.20,
        "title": "Initial",
        "primary_source_ip": "10.0.0.5",
        "correlation_key": "ip:10.0.0.5",
        "attack_domains": ["network"],
        "detection_types": ["ICMP_SWEEP"],
        "event_count": 1,
    }
    save_incident_record(inc_data)

    # Update with new event and higher risk
    inc_data["updated_at"] = t0 + 50
    inc_data["status"] = "ACKNOWLEDGED"
    inc_data["severity"] = "CRITICAL"
    inc_data["risk_score"] = 0.95
    inc_data["event_count"] = 5
    inc_data["analyst_note"] = "Investigating ongoing sweep."

    assert save_incident_record(inc_data) is True

    updated = get_incident_by_id("inc-test-update", include_evidence=False)
    assert updated["status"] == "ACKNOWLEDGED"
    assert updated["severity"] == "CRITICAL"
    assert updated["risk_score"] == 0.95
    assert updated["event_count"] == 5
    assert updated["analyst_note"] == "Investigating ongoing sweep."


def test_save_incident_evidence_records_and_cascade(app_ctx):
    """Test attaching evidence records to an incident and cascading delete."""
    t0 = time.time()
    save_incident_record({
        "incident_id": "inc-evidence-test",
        "created_at": t0,
        "updated_at": t0,
        "status": "OPEN",
        "severity": "MEDIUM",
        "risk_score": 0.45,
        "title": "Evidence Test",
        "primary_source_ip": "192.168.1.55",
        "correlation_key": "ip:192.168.1.55",
    })

    ev1 = {
        "evidence_id": "ev-01",
        "incident_id": "inc-evidence-test",
        "evidence_type": "SECURITY_EVENT",
        "reference_id": "ref-sec-01",
        "timestamp": t0,
        "source_ip": "192.168.1.55",
        "detection_type": "SYN_FLOOD",
        "severity": "HIGH",
        "risk_score": 0.70,
        "summary": "SYN flood packets detected",
        "metadata": {"packet_count": 100},
    }
    ev2 = {
        "evidence_id": "ev-02",
        "incident_id": "inc-evidence-test",
        "evidence_type": "FIREWALL_ACTION",
        "reference_id": "ref-fw-01",
        "timestamp": t0 + 1,
        "source_ip": "192.168.1.55",
        "summary": "Firewall block applied",
        "metadata": {"action": "block", "duration": 300},
    }

    assert save_incident_evidence_record(ev1) is True
    assert save_incident_evidence_record(ev2) is True

    inc = get_incident_by_id("inc-evidence-test", include_evidence=True)
    assert len(inc["evidence"]) == 2
    assert inc["evidence"][0]["evidence_id"] == "ev-01"
    assert inc["evidence"][0]["metadata"]["packet_count"] == 100
    assert inc["evidence"][1]["evidence_id"] == "ev-02"
    assert inc["evidence"][1]["metadata"]["action"] == "block"

    # Delete incident and ensure evidence cascades
    rec = IncidentRecord.query.filter_by(incident_id="inc-evidence-test").first()
    db.session.delete(rec)
    db.session.commit()

    assert IncidentRecord.query.count() == 0
    assert IncidentEvidenceRecord.query.count() == 0


def test_query_incidents_with_filtering_and_pagination(app_ctx):
    """Test querying incidents with status, severity, source IP, and pagination filters."""
    t0 = time.time()
    for i in range(10):
        save_incident_record({
            "incident_id": f"inc-{i:02d}",
            "created_at": t0 + i * 10,
            "updated_at": t0 + i * 10,
            "status": "OPEN" if i < 6 else "RESOLVED",
            "severity": "CRITICAL" if i % 2 == 0 else "MEDIUM",
            "risk_score": 0.85 if i % 2 == 0 else 0.45,
            "title": f"Incident {i}",
            "primary_source_ip": f"10.0.0.{10 + (i % 3)}",
            "correlation_key": f"ip:10.0.0.{10 + (i % 3)}",
        })

    # Test limit and offset
    res = query_incidents(limit=4, offset=0)
    assert res["total"] == 10
    assert len(res["incidents"]) == 4

    res_page2 = query_incidents(limit=4, offset=4)
    assert len(res_page2["incidents"]) == 4

    # Test status filter
    open_res = query_incidents(status="OPEN")
    assert open_res["total"] == 6

    # Test severity filter
    crit_res = query_incidents(severity="CRITICAL")
    assert crit_res["total"] == 5

    # Test primary source IP filter
    ip_res = query_incidents(primary_source_ip="10.0.0.10")
    # i=0, 3, 6, 9 -> 4 incidents
    assert ip_res["total"] == 4


def test_query_incident_stats_and_summary_integration(app_ctx):
    """Test query_incident_stats and its aggregation in query_security_summary."""
    t0 = time.time()
    save_incident_record({
        "incident_id": "inc-stat-1",
        "created_at": t0,
        "updated_at": t0,
        "status": "OPEN",
        "severity": "CRITICAL",
        "risk_score": 0.90,
        "title": "Incident 1",
        "primary_source_ip": "1.2.3.4",
        "correlation_key": "ip:1.2.3.4",
    })
    save_incident_record({
        "incident_id": "inc-stat-2",
        "created_at": t0 + 1,
        "updated_at": t0 + 1,
        "status": "RESOLVED",
        "severity": "LOW",
        "risk_score": 0.20,
        "title": "Incident 2",
        "primary_source_ip": "5.6.7.8",
        "correlation_key": "ip:5.6.7.8",
    })

    stats = query_incident_stats()
    assert stats["total_incidents"] == 2
    assert stats["open"] == 1
    assert stats["resolved"] == 1
    assert stats["severities"].get("CRITICAL") == 1
    assert stats["severities"].get("LOW") == 1

    summary = query_security_summary()
    assert summary["incidents_total"] == 2
    assert summary["incidents_open"] == 1
    assert summary["incidents_critical"] == 1
    assert summary["incidents_resolved"] == 1
    assert len(summary["top_incident_sources"]) == 2


def test_cleanup_old_records_preserves_active_incidents(app_ctx):
    """Test that cleanup_old_records prunes resolved/closed incidents older than retention, but preserves active incidents."""
    now = time.time()
    cutoff_old = now - (10 * 86400)  # 10 days ago

    # Old resolved incident (should be pruned)
    save_incident_record({
        "incident_id": "inc-old-resolved",
        "created_at": cutoff_old - 100,
        "updated_at": cutoff_old - 50,
        "status": "RESOLVED",
        "severity": "HIGH",
        "risk_score": 0.70,
        "title": "Old Resolved",
        "primary_source_ip": "192.168.1.1",
        "correlation_key": "ip:192.168.1.1",
    })
    save_incident_evidence_record({
        "evidence_id": "ev-old-resolved",
        "incident_id": "inc-old-resolved",
        "evidence_type": "SECURITY_EVENT",
        "reference_id": "ref-001",
        "timestamp": cutoff_old - 90,
        "summary": "Old alert",
    })

    # Old OPEN incident (MUST BE PRESERVED)
    save_incident_record({
        "incident_id": "inc-old-open",
        "created_at": cutoff_old - 100,
        "updated_at": cutoff_old - 50,
        "status": "OPEN",
        "severity": "CRITICAL",
        "risk_score": 0.90,
        "title": "Old Open",
        "primary_source_ip": "192.168.1.2",
        "correlation_key": "ip:192.168.1.2",
    })

    # Recent resolved incident (within retention, should be preserved)
    save_incident_record({
        "incident_id": "inc-recent-resolved",
        "created_at": now - 3600,
        "updated_at": now - 1800,
        "status": "RESOLVED",
        "severity": "LOW",
        "risk_score": 0.25,
        "title": "Recent Resolved",
        "primary_source_ip": "192.168.1.3",
        "correlation_key": "ip:192.168.1.3",
    })

    cleanup_res = cleanup_old_records(retention_days=7)
    assert cleanup_res["deleted_incidents"] == 1

    remaining_ids = [r.incident_id for r in IncidentRecord.query.all()]
    assert "inc-old-resolved" not in remaining_ids
    assert "inc-old-open" in remaining_ids
    assert "inc-recent-resolved" in remaining_ids
