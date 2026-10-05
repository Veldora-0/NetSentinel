"""Unit tests for NetSentinel Database Models, Persistence, Queries, and Retention Pruning."""

import os
import sys
import time
import pytest
from flask import Flask

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database import (
    db,
    init_db,
    SecurityEventRecord,
    RiskAssessmentRecord,
    FirewallActionRecord,
    HostTelemetryRecord,
    save_security_event_record,
    save_assessment_record,
    save_firewall_action_record,
    save_host_telemetry_record,
    query_security_events,
    query_risk_history,
    query_security_summary,
    query_telemetry_history,
    cleanup_old_records,
)
from detector import SecurityEvent


@pytest.fixture
def app_ctx():
    """Create Flask application with in-memory SQLite database for testing."""
    app = Flask("test_db_app")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    init_db(app)

    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


def test_save_and_query_security_events(app_ctx):
    """Test persisting SecurityEvent and querying with filtering and pagination."""
    t0 = time.time() - 100

    # Save multiple events
    event1 = SecurityEvent(
        event_id="evt-001",
        timestamp=t0 + 10,
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        protocol="TCP",
        source_port=50000,
        destination_port=80,
        description="Port Scan detected",
        evidence={"ports": [80, 443, 22]},
        rule_name="RULE_PORT_SCAN",
    )
    assert save_security_event_record(event1) is True

    event2 = {
        "event_id": "evt-002",
        "timestamp": t0 + 20,
        "detection_type": "SYN_FLOOD",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.200",
        "destination_ip": "10.0.0.1",
        "description": "SYN Flood attack",
        "evidence": {"rate": 500},
    }
    assert save_security_event_record(event2) is True

    # 1. Query all
    res = query_security_events(limit=50)
    assert res["total"] == 2
    assert res["count"] == 2
    assert res["events"][0]["event_id"] == "evt-002"  # Newest first

    # 2. Filter by detection_type
    res_type = query_security_events(detection_type="PORT_SCAN")
    assert res_type["total"] == 1
    assert res_type["events"][0]["event_id"] == "evt-001"

    # 3. Filter by severity
    res_sev = query_security_events(severity="CRITICAL")
    assert res_sev["total"] == 1
    assert res_sev["events"][0]["event_id"] == "evt-002"

    # 4. Filter by timestamp window
    res_time = query_security_events(since=t0 + 15, until=t0 + 25)
    assert res_time["total"] == 1
    assert res_time["events"][0]["event_id"] == "evt-002"

    # 5. Pagination
    res_page = query_security_events(limit=1, offset=1)
    assert res_page["total"] == 2
    assert res_page["count"] == 1
    assert res_page["events"][0]["event_id"] == "evt-001"


def test_save_and_query_firewall_actions(app_ctx):
    """Test saving firewall action records and verifying attributes."""
    t_now = time.time()
    saved = save_firewall_action_record(
        action="block",
        source_ip="203.0.113.5",
        success=True,
        reason="Exceeded risk threshold",
        risk_score=0.92,
        assessment_id="risk-xyz",
        expires_at=t_now + 300,
        timestamp=t_now,
    )
    assert saved is True

    saved_unblock = save_firewall_action_record(
        action="unblock",
        source_ip="203.0.113.5",
        success=True,
        reason="Manual operator unblock",
        timestamp=t_now + 10,
    )
    assert saved_unblock is True

    records = FirewallActionRecord.query.order_by(FirewallActionRecord.timestamp.asc()).all()
    assert len(records) == 2
    assert records[0].action == "block"
    assert records[0].source_ip == "203.0.113.5"
    assert records[0].risk_score == 0.92
    assert records[1].action == "unblock"


def test_save_and_query_host_telemetry(app_ctx):
    """Test saving host telemetry snapshots and querying bounded history."""
    t0 = time.time() - 60
    for i in range(5):
        sample = {
            "telemetry_id": f"telem-{i}",
            "timestamp": t0 + (i * 10),
            "cpu_percent": 15.0 + i,
            "memory_percent": 45.0,
            "memory_used_bytes": 4500000000,
            "memory_available_bytes": 5500000000,
            "disk_percent": 60.0,
            "disk_used_bytes": 60000000000,
            "disk_free_bytes": 40000000000,
            "load_1": 0.5,
            "load_5": 0.4,
            "load_15": 0.3,
            "network_bytes_sent": 1000 * i,
            "network_bytes_recv": 2000 * i,
            "network_packets_sent": 10 * i,
            "network_packets_recv": 20 * i,
            "host_tx_bps": 100.0,
            "host_rx_bps": 200.0,
            "host_tx_pps": 1.0,
            "host_rx_pps": 2.0,
        }
        assert save_host_telemetry_record(sample) is True

    # Query telemetry history
    res = query_telemetry_history(limit=3)
    assert res["count"] == 3
    # Verify chronological ordering (oldest of the 3 to newest)
    assert res["telemetry"][0]["timestamp"] < res["telemetry"][-1]["timestamp"]
    assert res["telemetry"][-1]["telemetry_id"] == "telem-4"


def test_query_security_summary(app_ctx):
    """Test security summary aggregation calculation across events, risks, and firewall actions."""
    t_now = time.time()

    # 1. Create security events
    save_security_event_record({
        "event_id": "s-1",
        "timestamp": t_now,
        "detection_type": "PORT_SCAN",
        "severity": "MEDIUM",
        "source_ip": "10.0.0.99",
    })
    save_security_event_record({
        "event_id": "s-2",
        "timestamp": t_now,
        "detection_type": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": "10.0.0.99",
    })
    save_security_event_record({
        "event_id": "s-3",
        "timestamp": t_now,
        "detection_type": "SYN_FLOOD",
        "severity": "CRITICAL",
        "source_ip": "10.0.0.88",
    })

    # 2. Create risk assessments
    class DummyAssessment:
        def __init__(self, aid, src, score, level, act):
            self.assessment_id = aid
            self.timestamp = t_now
            self.source_ip = src
            self.destination_ip = None
            self.rule_score = score
            self.ml_anomaly_score = 0.0
            self.combined_score = score
            self.risk_level = level
            self.recommended_action = act
            self.blocked = (act == "block")
            self.reason = "test"
            self.detection_types = []
            self.evidence = {}

    save_assessment_record(DummyAssessment("r-1", "10.0.0.99", 0.60, "MEDIUM", "alert"))
    save_assessment_record(DummyAssessment("r-2", "10.0.0.88", 0.90, "CRITICAL", "block"))

    # 3. Create firewall action
    save_firewall_action_record(action="block", source_ip="10.0.0.88", success=True)

    summary = query_security_summary()
    assert summary["total_events"] == 3
    assert summary["total_assessments"] == 2
    assert summary["total_firewall_actions"] == 1
    assert summary["detection_types"]["PORT_SCAN"] == 2
    assert summary["detection_types"]["SYN_FLOOD"] == 1
    assert summary["severities"]["HIGH"] == 1
    assert summary["severities"]["CRITICAL"] == 1
    assert summary["highest_risk_score"] == 0.90
    assert summary["average_risk_score"] == 0.75
    assert len(summary["top_source_ips"]) >= 1
    assert summary["top_source_ips"][0]["source_ip"] == "10.0.0.99"


def test_cleanup_old_records_retention(app_ctx):
    """Test that retention pruning removes expired records and preserves fresh ones."""
    now = time.time()
    old_time = now - (10 * 86400)  # 10 days ago (older than 7 days retention)
    fresh_time = now - 3600         # 1 hour ago

    # Old records
    save_security_event_record({
        "event_id": "old-event",
        "timestamp": old_time,
        "detection_type": "PORT_SCAN",
        "source_ip": "1.1.1.1",
    })
    save_firewall_action_record(
        action="block",
        source_ip="1.1.1.1",
        timestamp=old_time,
    )
    save_host_telemetry_record({
        "telemetry_id": "old-telem",
        "timestamp": old_time,
        "cpu_percent": 10.0,
    })

    # Fresh records
    save_security_event_record({
        "event_id": "fresh-event",
        "timestamp": fresh_time,
        "detection_type": "PORT_SCAN",
        "source_ip": "2.2.2.2",
    })
    save_firewall_action_record(
        action="block",
        source_ip="2.2.2.2",
        timestamp=fresh_time,
    )
    save_host_telemetry_record({
        "telemetry_id": "fresh-telem",
        "timestamp": fresh_time,
        "cpu_percent": 20.0,
    })

    # Perform retention prune (retention_days=7)
    cleanup_res = cleanup_old_records(retention_days=7)
    assert cleanup_res["deleted_events"] == 1
    assert cleanup_res["deleted_firewall_actions"] == 1
    assert cleanup_res["deleted_telemetry"] == 1

    # Verify only fresh records remain
    events_left = SecurityEventRecord.query.all()
    assert len(events_left) == 1
    assert events_left[0].event_id == "fresh-event"

    fw_left = FirewallActionRecord.query.all()
    assert len(fw_left) == 1
    assert fw_left[0].source_ip == "2.2.2.2"

    telem_left = HostTelemetryRecord.query.all()
    assert len(telem_left) == 1
    assert telem_left[0].telemetry_id == "fresh-telem"
