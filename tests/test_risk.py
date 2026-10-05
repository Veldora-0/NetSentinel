"""Unit tests for NetSentinel Composite Risk Engine.

Tests rule severity scoring, ML contribution weighting, score clamping,
risk level classification, recommended actions, repeated source frequency boosts,
bounded state retention, and stale history pruning.
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from risk_engine import RiskEngine, RiskAssessment


def test_rule_severity_scores_baseline():
    """Verify rule score calculation across low, medium, high, and critical severities."""
    engine = RiskEngine()

    # Rule only (ml=0.0): combined = 0.65 * rule_score
    score_low = engine.calculate_risk_score([{"severity": "LOW"}], ml_anomaly_score=0.0)
    assert score_low == pytest.approx(0.65 * 0.20, abs=1e-3)

    score_med = engine.calculate_risk_score([{"severity": "MEDIUM"}], ml_anomaly_score=0.0)
    assert score_med == pytest.approx(0.65 * 0.40, abs=1e-3)

    score_high = engine.calculate_risk_score([{"severity": "HIGH"}], ml_anomaly_score=0.0)
    assert score_high == pytest.approx(0.65 * 0.70, abs=1e-3)

    score_crit = engine.calculate_risk_score([{"severity": "CRITICAL"}], ml_anomaly_score=0.0)
    assert score_crit == pytest.approx(0.65 * 0.90, abs=1e-3)


def test_ml_only_anomaly_scoring():
    """Verify ML anomaly only without rules produces 0.35 * ml_anomaly_score."""
    engine = RiskEngine()

    # ML score 0.0 -> 0.0
    assert engine.calculate_risk_score([], ml_anomaly_score=0.0) == 0.0

    # ML score 0.6 -> 0.6 * 0.35 = 0.21
    assert engine.calculate_risk_score([], ml_anomaly_score=0.6) == pytest.approx(0.21, abs=1e-3)

    # ML score 1.0 (extreme outlier) -> 0.35 (can never exceed MEDIUM risk by itself)
    score_max_ml = engine.calculate_risk_score([], ml_anomaly_score=1.0)
    assert score_max_ml == 0.35


def test_combined_rule_and_ml_scoring():
    """Verify composite formula: 0.65 * rule_score + 0.35 * ml_anomaly_score."""
    engine = RiskEngine()

    # HIGH rule (0.70) + ML anomaly (0.80)
    # expected = (0.65 * 0.70) + (0.35 * 0.80) = 0.455 + 0.280 = 0.735
    score = engine.calculate_risk_score([{"severity": "HIGH"}], ml_anomaly_score=0.8)
    assert score == pytest.approx(0.735, abs=1e-3)


def test_score_clamping_to_unit_interval():
    """Verify score clamping guarantees results remain strictly within [0.0, 1.0]."""
    engine = RiskEngine()

    # Negative inputs clamped to 0.0
    assert engine.calculate_risk_score([], ml_anomaly_score=-0.5) == 0.0

    # Excessive scores clamped to 1.0
    assessment = engine.assess(
        source_ip="198.51.100.1",
        rule_alerts=[{"severity": "CRITICAL", "detection_type": "SYN_FLOOD"}],
        ml_anomaly_score=1.0,
    )
    assert 0.0 <= assessment.combined_score <= 1.0


def test_risk_level_boundaries_and_actions():
    """Verify mapping of scores to risk levels and recommended actions."""
    engine = RiskEngine()

    # 1. LOW: 0.00 - 0.29 -> monitor
    lvl, act = engine._determine_risk_level_and_action(0.15)
    assert lvl == "LOW"
    assert act == "monitor"

    # 2. MEDIUM: 0.30 - 0.59 -> log
    lvl, act = engine._determine_risk_level_and_action(0.45)
    assert lvl == "MEDIUM"
    assert act == "log"

    # 3. HIGH: 0.60 - 0.79 -> alert
    lvl, act = engine._determine_risk_level_and_action(0.65)
    assert lvl == "HIGH"
    assert act == "alert"

    # 4. CRITICAL: 0.80 - 1.00 -> block
    lvl, act = engine._determine_risk_level_and_action(0.85)
    assert lvl == "CRITICAL"
    assert act == "block"


def test_repeated_source_frequency_boost():
    """Verify repeated detections from same source IP increment risk score up to max boost."""
    engine = RiskEngine(config={
        "rule_weight": 0.65,
        "ml_weight": 0.35,
        "repeat_increment": 0.05,
        "max_repeat_boost": 0.20,
        "history_window_seconds": 60.0,
        "severity_scores": {"LOW": 0.20, "MEDIUM": 0.40, "HIGH": 0.70, "CRITICAL": 0.90},
    })

    ip = "203.0.113.50"
    alert = {"severity": "MEDIUM", "detection_type": "PORT_SCAN"}

    # 1st detection: no repeat boost
    a1 = engine.assess(source_ip=ip, rule_alerts=[alert])
    assert a1.evidence["repeat_boost"] == 0.0

    # 2nd detection: +0.05 boost
    a2 = engine.assess(source_ip=ip, rule_alerts=[alert])
    assert a2.evidence["repeat_boost"] == 0.05
    assert a2.combined_score > a1.combined_score

    # Feed multiple repeated events to reach max repeat boost (0.20)
    for _ in range(10):
        a_last = engine.assess(source_ip=ip, rule_alerts=[alert])

    assert a_last.evidence["repeat_boost"] == 0.20


def test_bounded_state_and_history_pruning():
    """Verify risk engine enforces max_history on assessments and cleans stale IP history."""
    engine = RiskEngine(config={
        "max_assessment_history": 5,
        "history_window_seconds": 1.0,
    })

    for i in range(10):
        engine.assess(source_ip=f"192.0.2.{i}", rule_alerts=[{"severity": "LOW"}])

    recent = engine.get_recent_assessments(limit=10)
    assert len(recent) <= 5

    # Simulate passage of time past history window
    future_time = time.time() + 10.0
    pruned = engine.cleanup_stale_state(now=future_time)
    assert pruned > 0


def test_risk_stats_aggregation():
    """Verify get_stats accurately tracks totals, level breakdowns, and averages."""
    engine = RiskEngine()

    engine.assess("192.0.2.1", rule_alerts=[{"severity": "LOW"}])       # LOW
    engine.assess("192.0.2.2", rule_alerts=[{"severity": "MEDIUM"}])    # LOW/MEDIUM
    engine.assess("192.0.2.3", rule_alerts=[{"severity": "CRITICAL"}], ml_anomaly_score=0.9) # CRITICAL

    stats = engine.get_stats()
    assert stats["total_assessments"] == 3
    assert stats["average_risk_score"] > 0.0
    assert stats["highest_risk_score"] >= 0.80
    assert stats["critical_count"] >= 1
