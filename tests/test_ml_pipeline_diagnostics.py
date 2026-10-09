"""Regression tests for NetSentinel ML anomaly pipeline, baseline status, and incident correlation.

Verifies:
1. Authoritative baseline status reporting when pre-trained model is READY.
2. Primary source and destination IP extraction in TrafficWindow.
3. Accurate event attributes on MLAnomalyEvent.
4. Correct persistence of MLAnomalyEvent in SQLite without falling back to UNKNOWN.
5. Correct correlation of MLAnomalyEvent and RiskAssessment in IncidentManager.
6. End-to-end ML anomaly callback wiring into RiskEngine and IncidentManager.
"""

import json
import os
import sys
import tempfile
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database import init_db, db, SecurityEventRecord, RiskAssessmentRecord, save_security_event_record, save_assessment_record
from incident_manager import IncidentManager
from ml.detector import MLAnomalyDetector, MLAnomalyEvent
from ml.feature_extractor import TrafficWindow
from ml.model import IsolationForestModel, ModelStatus
from parser import ParsedPacket
from risk_engine import RiskEngine
from app import create_app


def make_test_packet(src_ip="10.0.2.15", dst_ip="10.0.2.3", proto=1, proto_name="ICMP", raw_len=98):
    """Generate a test ParsedPacket."""
    return ParsedPacket(
        timestamp=time.time(),
        raw_length=raw_len,
        src_mac="08:00:27:11:22:33",
        dst_mac="08:00:27:44:55:66",
        ethertype=0x0800,
        ethertype_name="IPv4",
        ip_version=4,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        protocol_name=proto_name,
        icmp_type=8,
        icmp_code=0,
    )


def test_pretrained_model_reports_established_baseline_status():
    """Verify get_status reports established baseline count and readiness, not 0/10."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "test_if.joblib")
        meta_path = os.path.join(tmpdir, "test_meta.json")

        # Train and save a 10-sample model
        if_model = IsolationForestModel(n_estimators=10, min_samples=5)
        samples = [[10.0 + (i % 2), 500.0, 50.0, 0.8, 0.2, 0.0, 0.1, 0.8, 0.0, 0.0, 2.0, 2.0, 2.0] for i in range(10)]
        assert if_model.train(samples) is True
        assert if_model.save(model_path, meta_path) is True

        cfg = {
            "enabled": True,
            "window_seconds": 5.0,
            "baseline_windows": 10,
            "model_path": model_path,
            "metadata_path": meta_path,
        }
        detector = MLAnomalyDetector(config=cfg)
        assert detector.model.status == ModelStatus.READY

        status = detector.get_status()
        assert status["model_status"] == "READY"
        assert status["model_ready"] is True
        assert status["baseline_established"] is True
        # Must report established training sample count, not 0
        assert status["baseline_samples_collected"] == 10
        assert status["baseline_target_samples"] == 10


def test_traffic_window_tracks_primary_source_and_destination_ip():
    """Verify TrafficWindow identifies the dominant source and destination IP in the window."""
    tw = TrafficWindow(window_seconds=2.0)
    for _ in range(5):
        tw.add_packet(make_test_packet(src_ip="10.0.2.15", dst_ip="10.0.2.3"))
    tw.add_packet(make_test_packet(src_ip="10.0.2.20", dst_ip="10.0.2.3"))

    vec, f_dict, count = tw.consume_window(custom_duration=2.0)
    assert count == 6
    assert tw.last_primary_source_ip == "10.0.2.15"
    assert tw.last_primary_destination_ip == "10.0.2.3"


def test_ml_anomaly_event_attributes_and_defaults():
    """Verify MLAnomalyEvent carries detection_type, source_ip, and destination_ip."""
    event = MLAnomalyEvent(
        event_id="evt12345",
        timestamp=time.time(),
        event_type="ML_ANOMALY",
        severity="MEDIUM",
        prediction="ANOMALY",
        raw_score=-0.05,
        anomaly_score=0.55,
        features={"packets_per_second": 10.0},
        model_status="READY",
        description="Test anomaly",
        source_ip="10.0.2.15",
        destination_ip="10.0.2.3",
        detection_type="ML_ANOMALY",
    )
    assert event.detection_type == "ML_ANOMALY"
    assert event.source_ip == "10.0.2.15"
    assert event.destination_ip == "10.0.2.3"

    d = event.to_dict()
    assert d["detection_type"] == "ML_ANOMALY"
    assert d["source_ip"] == "10.0.2.15"
    assert d["destination_ip"] == "10.0.2.3"


def test_save_security_event_record_persists_ml_anomaly_accurately():
    """Verify MLAnomalyEvent persists to security_events table with ML_ANOMALY detection type."""
    from flask import Flask

    test_app = Flask(__name__)
    test_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    test_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    init_db(test_app)

    event = MLAnomalyEvent(
        event_id="ml_evt_001",
        timestamp=1000.0,
        event_type="ML_ANOMALY",
        severity="MEDIUM",
        prediction="ANOMALY",
        raw_score=-0.02,
        anomaly_score=0.52,
        features={"packets_per_second": 4.0, "bytes_per_second": 392.0},
        model_status="READY",
        description="Traffic window anomaly detected",
        source_ip="10.0.2.15",
        destination_ip="10.0.2.3",
        detection_type="ML_ANOMALY",
    )

    with test_app.app_context():
        saved = save_security_event_record(event)
        assert saved is True

        rec = SecurityEventRecord.query.filter_by(event_id="ml_evt_001").first()
        assert rec is not None
        assert rec.detection_type == "ML_ANOMALY"
        assert rec.source_ip == "10.0.2.15"
        assert rec.destination_ip == "10.0.2.3"
        assert rec.severity == "MEDIUM"
        assert "packets_per_second" in rec.evidence


def test_incident_manager_correlates_ml_anomaly_with_risk_assessment():
    """Verify IncidentManager creates an ML_ANOMALY incident with attached risk assessment."""
    from flask import Flask

    test_app = Flask(__name__)
    test_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    test_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    init_db(test_app)

    risk_engine = RiskEngine()
    incident_mgr = IncidentManager()

    event = MLAnomalyEvent(
        event_id="ml_evt_002",
        timestamp=1500.0,
        event_type="ML_ANOMALY",
        severity="MEDIUM",
        prediction="ANOMALY",
        raw_score=-0.05,
        anomaly_score=0.55,
        features={"packets_per_second": 12.0},
        model_status="READY",
        description="Deviant traffic burst",
        source_ip="10.0.2.15",
        destination_ip="10.0.2.3",
        detection_type="ML_ANOMALY",
    )

    with test_app.app_context():
        assessment = risk_engine.assess(
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            rule_alerts=[],
            ml_anomaly_score=event.anomaly_score,
        )
        assert assessment.source_ip == "10.0.2.15"
        assert assessment.combined_score > 0.0

        incident = incident_mgr.correlate_security_event(event, risk_assessment=assessment)
        assert incident is not None
        assert incident.primary_source_ip == "10.0.2.15"
        assert "ML_ANOMALY" in incident.detection_types
        assert incident.risk_assessment_count == 1
        assert incident.event_count == 1
        assert len(incident.evidence_list) == 2  # SECURITY_EVENT + RISK_ASSESSMENT


def test_app_on_ml_anomaly_wiring_updates_risk_and_incidents():
    """Verify that when an ML anomaly fires, risk assessments increment and incident is persisted."""
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "AUTH_ENABLED": False,
    }
    app, socketio = create_app(config_class=test_config, start_capture=False)

    with app.app_context():
        # Baseline total risk assessments
        stats_before = app.risk_engine.get_stats()
        initial_assessments = stats_before["total_assessments"]

        # Simulate ML anomaly event
        test_event = MLAnomalyEvent(
            event_id="ml_wired_001",
            timestamp=2000.0,
            event_type="ML_ANOMALY",
            severity="MEDIUM",
            prediction="ANOMALY",
            raw_score=-0.08,
            anomaly_score=0.58,
            features={"packets_per_second": 25.0},
            model_status="READY",
            description="High deviation traffic",
            source_ip="10.0.2.15",
            destination_ip="10.0.2.3",
            detection_type="ML_ANOMALY",
        )

        # Trigger registered ML anomaly callbacks
        for cb in app.ml_detector._anomaly_callbacks:
            cb(test_event)

        # Risk assessments must increment
        stats_after = app.risk_engine.get_stats()
        assert stats_after["total_assessments"] == initial_assessments + 1

        # Check database persistence of SecurityEvent, RiskAssessment, and Incident
        sec_rec = SecurityEventRecord.query.filter_by(event_id="ml_wired_001").first()
        assert sec_rec is not None
        assert sec_rec.detection_type == "ML_ANOMALY"
        assert sec_rec.source_ip == "10.0.2.15"

        assess_rec = RiskAssessmentRecord.query.filter_by(source_ip="10.0.2.15").first()
        assert assess_rec is not None
        assert assess_rec.ml_anomaly_score == 0.58

        from database import query_incidents
        inc_res = query_incidents(primary_source_ip="10.0.2.15")
        assert inc_res["total"] >= 1
        assert "ip:10.0.2.15" in app.incident_manager._active_by_key
