"""Unit tests for Threat Intelligence integration with Risk Engine and Incident Manager."""

import time
import pytest
from flask import Flask
from database import db, init_db
from risk_engine import RiskEngine
from incident_manager import IncidentManager
from threat_intel.models import (
    AggregatedThreatIntel,
    REPUTATION_MALICIOUS,
    REPUTATION_SUSPICIOUS,
    REPUTATION_CLEAN,
    REPUTATION_CONFLICTING,
    CONSENSUS_STRONG_POSITIVE,
)


@pytest.fixture
def app_ctx():
    """Create Flask application context with in-memory database."""
    app = Flask("test_ti_risk_app")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    init_db(app)

    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


def test_ti_risk_modifiers():
    """Verify TI reputation adds bounded deterministic modifiers."""
    engine = RiskEngine()

    # Base assessment with no alerts or ML: base score is 0.0
    base_score = engine.calculate_risk_score(rule_alerts=[], ml_anomaly_score=0.0)
    assert base_score == 0.0

    # 1. Malicious adds +0.15
    ti_mal = AggregatedThreatIntel(ip="185.220.101.5", reputation=REPUTATION_MALICIOUS, confidence=0.9)
    score_mal = engine.calculate_risk_score(rule_alerts=[], ml_anomaly_score=0.0, ti_summary=ti_mal)
    assert score_mal == 0.15

    # 2. Suspicious adds +0.05
    ti_sus = AggregatedThreatIntel(ip="185.220.101.5", reputation=REPUTATION_SUSPICIOUS, confidence=0.6)
    score_sus = engine.calculate_risk_score(rule_alerts=[], ml_anomaly_score=0.0, ti_summary=ti_sus)
    assert score_sus == 0.05

    # 3. Conflicting adds +0.02
    ti_conf = AggregatedThreatIntel(ip="185.220.101.5", reputation=REPUTATION_CONFLICTING, confidence=0.5)
    score_conf = engine.calculate_risk_score(rule_alerts=[], ml_anomaly_score=0.0, ti_summary=ti_conf)
    assert score_conf == 0.02

    # 4. Clean adds +0.00
    ti_clean = AggregatedThreatIntel(ip="8.8.8.8", reputation=REPUTATION_CLEAN, confidence=0.8)
    score_clean = engine.calculate_risk_score(rule_alerts=[], ml_anomaly_score=0.0, ti_summary=ti_clean)
    assert score_clean == 0.0


def test_ti_stale_halves_modifier():
    """Verify stale cache items halve the applied TI boost."""
    engine = RiskEngine()

    ti_stale = AggregatedThreatIntel(
        ip="185.220.101.5",
        reputation=REPUTATION_MALICIOUS,
        confidence=0.9,
        stale=True,
    )
    score = engine.calculate_risk_score(rule_alerts=[], ml_anomaly_score=0.0, ti_summary=ti_stale)
    # +0.15 * 0.5 = 0.075
    assert score == 0.075


def test_ti_alone_cannot_trigger_firewall_block():
    """Verify TI modifier cannot elevate benign traffic to CRITICAL or trigger block."""
    engine = RiskEngine()

    # Highly malicious TI on routine/benign traffic
    ti_mal = AggregatedThreatIntel(
        ip="185.220.101.5",
        reputation=REPUTATION_MALICIOUS,
        confidence=1.0,
        consensus=CONSENSUS_STRONG_POSITIVE,
    )
    res = engine.assess(source_ip="185.220.101.5", rule_alerts=[], ml_anomaly_score=0.0, ti_summary=ti_mal)
    assert res.risk_level != "CRITICAL"
    assert res.recommended_action in ("log", "monitor")
    assert res.recommended_action != "block"


def test_incident_manager_correlates_ti(app_ctx):
    """Verify TI attaches evidence to existing open incident and does not create incident alone."""
    mgr = IncidentManager()

    ti_data = {
        "ip": "185.220.101.5",
        "reputation": "MALICIOUS",
        "consensus": "STRONG_POSITIVE",
        "confidence": 0.95,
        "providers_checked": 2,
    }

    # 1. Without an existing incident, correlate_threat_intel returns None (never creates incident on TI alone)
    inc_none = mgr.correlate_threat_intel("185.220.101.5", ti_data)
    assert inc_none is None

    # 2. Correlate a security event first to create an incident
    dummy_event = {
        "event_id": "ev-test-1",
        "timestamp": time.time(),
        "source_ip": "185.220.101.5",
        "detection_type": "PORT_SCAN",
        "severity": "HIGH",
        "risk_score": 0.70,
        "description": "Port scan detected",
    }
    incident = mgr.correlate_security_event(dummy_event)
    assert incident is not None

    # 3. Now correlate TI evidence to the open incident
    updated_inc = mgr.correlate_threat_intel("185.220.101.5", ti_data)
    assert updated_inc is not None
    assert updated_inc.incident_id == incident.incident_id

    # Verify evidence item added
    ti_evidence_items = [e for e in updated_inc.evidence_list if e.evidence_type == "THREAT_INTELLIGENCE"]
    assert len(ti_evidence_items) == 1
    assert ti_evidence_items[0].detection_type == "THREAT_INTELLIGENCE"
    assert ti_evidence_items[0].metadata["reputation"] == "MALICIOUS"
