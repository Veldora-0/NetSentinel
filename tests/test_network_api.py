"""Tests for Phase 8 Network Detection Endpoints and Pipeline Integration."""

import os
import tempfile
import time
import pytest
from app import create_app
from config import Config
from database import db, SecurityEventRecord, RiskAssessmentRecord
from parser import ParsedPacket, ParsedARP
from detector import SecurityEvent
from risk_engine import RiskEngine


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    METRICS_EMIT_INTERVAL = 9999.0
    DETECTOR_THRESHOLDS = {
        "port_scan_window_sec": 10.0,
        "port_scan_threshold": 5,
        "syn_flood_window_sec": 5.0,
        "syn_flood_threshold": 10,
        "null_scan_enabled": True,
        "xmas_scan_enabled": True,
        "icmp_sweep_window_sec": 10.0,
        "icmp_sweep_threshold": 3,
        "icmp_sweep_cooldown_sec": 60.0,
        "alert_cooldown_sec": 30.0,
        "max_tracked_ips": 1000,
        "state_cleanup_sec": 60.0,
        "max_alert_history": 100,
    }
    ARP_DETECTION_SETTINGS = {
        "arp_enabled": True,
        "arp_state_timeout": 300.0,
        "arp_max_tracked_ips": 1000,
        "arp_max_tracked_macs": 1000,
        "arp_cooldown_sec": 60.0,
        "arp_conflict_threshold": 3,
        "arp_trusted_mappings": {"192.168.1.1": "00:50:56:c0:00:01"},
    }


@pytest.fixture
def client_and_app():
    """Create test application and test client fixture."""
    app, socketio = create_app(config_class=TestConfig, start_capture=False)
    with app.app_context():
        db.create_all()
        client = app.test_client()
        yield client, app
        db.session.remove()
        db.drop_all()


def test_get_network_status_endpoint(client_and_app):
    """Verify GET /api/network/status returns comprehensive status and metrics."""
    client, app = client_and_app
    response = client.get("/api/network/status")
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "ok"
    assert "network" in data
    assert "arp" in data["network"]
    assert "icmp_sweep" in data["network"]
    assert "thresholds" in data["network"]

    arp_status = data["network"]["arp"]
    assert arp_status["enabled"] is True
    assert arp_status["trusted_mappings_count"] == 1
    assert arp_status["conflict_threshold"] == 3

    icmp_status = data["network"]["icmp_sweep"]
    assert icmp_status["enabled"] is True
    assert icmp_status["threshold"] == 3


def test_get_arp_mappings_endpoint(client_and_app):
    """Verify GET /api/network/arp returns tracked IP-to-MAC bindings."""
    client, app = client_and_app
    # Trusted mapping was pre-seeded
    response = client.get("/api/network/arp")
    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "ok"
    assert data["total"] >= 1
    assert len(data["mappings"]) >= 1

    trusted_entry = next((m for m in data["mappings"] if m["ip"] == "192.168.1.1"), None)
    assert trusted_entry is not None
    assert trusted_entry["mac"] == "00:50:56:c0:00:01"
    assert trusted_entry["is_trusted"] is True


def test_arp_event_full_pipeline_persistence(client_and_app):
    """Verify ARP spoofing event is persisted to database and assessed by Risk Engine."""
    client, app = client_and_app
    arp_detector = app.arp_detector

    # Send baseline ARP packet for 10.0.0.50
    arp_info1 = ParsedARP(
        hardware_type=1,
        protocol_type=0x0800,
        hardware_size=6,
        protocol_size=4,
        operation=1,
        operation_name="REQUEST",
        sender_mac="00:11:22:33:44:55",
        sender_ip="10.0.0.50",
        target_mac="00:00:00:00:00:00",
        target_ip="10.0.0.1",
        is_gratuitous=False,
    )
    pkt1 = ParsedPacket(
        timestamp=time.time(),
        raw_length=42,
        src_mac="00:11:22:33:44:55",
        dst_mac="00:00:00:00:00:00",
        ethertype=0x0806,
        ethertype_name="ARP",
        protocol=None,
        protocol_name="ARP",
        src_ip="10.0.0.50",
        dst_ip="10.0.0.1",
        arp_info=arp_info1,
    )
    arp_detector.process_packet(pkt1)

    # Send spoofed packet claiming same IP with new MAC
    arp_info2 = ParsedARP(
        hardware_type=1,
        protocol_type=0x0800,
        hardware_size=6,
        protocol_size=4,
        operation=2,
        operation_name="REPLY",
        sender_mac="aa:bb:cc:dd:ee:ff",
        sender_ip="10.0.0.50",
        target_mac="00:11:22:33:44:55",
        target_ip="10.0.0.1",
        is_gratuitous=True,
    )
    pkt2 = ParsedPacket(
        timestamp=time.time() + 1.0,
        raw_length=42,
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="00:11:22:33:44:55",
        ethertype=0x0806,
        ethertype_name="ARP",
        protocol=None,
        protocol_name="ARP",
        src_ip="10.0.0.50",
        dst_ip="10.0.0.1",
        arp_info=arp_info2,
    )
    events = arp_detector.process_packet(pkt2)
    assert len(events) == 1
    assert events[0].detection_type == "ARP_SPOOFING"

    # Query SQLite database to verify persistence
    with app.app_context():
        record = SecurityEventRecord.query.filter_by(detection_type="ARP_SPOOFING").first()
        assert record is not None
        assert record.source_ip == "10.0.0.50"
        assert record.severity == "HIGH"
        assert record.protocol == "ARP"

        assessment = RiskAssessmentRecord.query.filter_by(source_ip="10.0.0.50").first()
        assert assessment is not None
        assert assessment.rule_score > 0.0


def test_icmp_sweep_pipeline_persistence(client_and_app):
    """Verify ICMP sweep event triggers risk assessment and persists to SQLite."""
    client, app = client_and_app
    detector = app.detector

    src_ip = "172.16.0.99"
    for i in range(3):
        pkt = ParsedPacket(
            timestamp=time.time() + i,
            raw_length=60,
            src_mac="00:11:22:33:44:55",
            dst_mac="00:66:77:88:99:aa",
            ethertype=0x0800,
            ethertype_name="IPv4",
            protocol=1,
            protocol_name="ICMP",
            src_ip=src_ip,
            dst_ip=f"172.16.0.{i+10}",
            icmp_type=8,
            icmp_code=0,
        )
        detector.analyze_packet(pkt)

    with app.app_context():
        record = SecurityEventRecord.query.filter_by(detection_type="ICMP_SWEEP").first()
        assert record is not None
        assert record.source_ip == src_ip
        assert record.severity == "MEDIUM"


def test_risk_engine_classifies_network_threats():
    """Verify RiskEngine recognizes ARP and ICMP threats as network domain evidence."""
    engine = RiskEngine()

    assert engine._classify_detection_type("ARP_SPOOFING") == "network"
    assert engine._classify_detection_type("ARP_IDENTITY_CONFLICT") == "network"
    assert engine._classify_detection_type("ICMP_SWEEP") == "network"

    # Calculate risk score for ARP_SPOOFING (HIGH -> base score 0.70)
    score = engine.calculate_risk_score(
        rule_alerts=[{"severity": "HIGH", "detection_type": "ARP_SPOOFING"}],
        ml_anomaly_score=0.0,
    )
    # rule_weight=0.65 * 0.70 = 0.455
    assert score == pytest.approx(0.455, abs=0.01)
