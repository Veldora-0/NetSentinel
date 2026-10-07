"""Phase 14 End-to-End Validation: Composite Risk Engine Boundaries & Formulas.

Verifies:
1. Deterministic base severity scoring across LOW, MEDIUM, HIGH, CRITICAL.
2. Source IP repeat boost increments (+0.05 per repeat within history window).
3. Repeat boost hard ceiling (+0.20 cap regardless of total repetitions).
4. Deterministic mapping to risk levels and recommended actions.
5. Escalation to CRITICAL (0.90) triggering recommended_action='block'.
"""

import time
import pytest

from risk_engine import RiskEngine


def test_e2e_risk_severity_base_scores():
    """Verify base scores map according to configured weights without repeat boost."""
    engine = RiskEngine()

    test_cases = [
        ("LOW", 0.20, round(0.65 * 0.20, 4), "LOW", "monitor"),
        ("MEDIUM", 0.40, round(0.65 * 0.40, 4), "LOW", "monitor"),
        ("HIGH", 0.70, round(0.65 * 0.70, 4), "MEDIUM", "log"),
        ("CRITICAL", 0.90, round(0.65 * 0.90, 4), "MEDIUM", "log"),
    ]

    for sev, base_sev, expected_combined, expected_level, expected_action in test_cases:
        ip = f"192.168.10.{sev}"
        assessment = engine.assess(source_ip=ip, rule_alerts=[{"severity": sev, "detection_type": "TEST"}])
        assert abs(assessment.combined_score - expected_combined) < 0.001
        assert assessment.risk_level == expected_level
        assert assessment.recommended_action == expected_action


def test_e2e_repeat_boost_increment_and_cap():
    """Verify repeat boost increments by +0.05 per occurrence and caps at +0.20."""
    engine = RiskEngine()
    test_ip = "192.168.1.250"

    # Initial LOW event: base = 0.20, repeat = 0.0 -> effective = 0.20 -> 0.20 * 0.65 = 0.1300
    a0 = engine.assess(source_ip=test_ip, rule_alerts=[{"severity": "LOW", "detection_type": "TEST"}])
    assert a0.combined_score == 0.13

    # Repeat 1: repeat = 0.05 -> effective = 0.25 -> 0.25 * 0.65 = 0.1625
    a1 = engine.assess(source_ip=test_ip, rule_alerts=[{"severity": "LOW", "detection_type": "TEST"}])
    assert a1.combined_score == 0.1625

    # Repeat 2: repeat = 0.10 -> effective = 0.30 -> 0.30 * 0.65 = 0.1950
    a2 = engine.assess(source_ip=test_ip, rule_alerts=[{"severity": "LOW", "detection_type": "TEST"}])
    assert a2.combined_score == 0.195

    # Repeat 3: repeat = 0.15 -> effective = 0.35 -> 0.35 * 0.65 = 0.2275
    a3 = engine.assess(source_ip=test_ip, rule_alerts=[{"severity": "LOW", "detection_type": "TEST"}])
    assert a3.combined_score == 0.2275

    # Repeat 4: repeat = 0.20 (cap reached) -> effective = 0.40 -> 0.40 * 0.65 = 0.2600
    a4 = engine.assess(source_ip=test_ip, rule_alerts=[{"severity": "LOW", "detection_type": "TEST"}])
    assert a4.combined_score == 0.26

    # Repeat 10 more times: must remain capped at 0.2600
    for _ in range(10):
        engine.assess(source_ip=test_ip, rule_alerts=[{"severity": "LOW", "detection_type": "TEST"}])

    a_capped = engine.assess(source_ip=test_ip, rule_alerts=[{"severity": "LOW", "detection_type": "TEST"}])
    assert a_capped.combined_score == 0.26


def test_e2e_critical_escalation_and_action():
    """Verify rule + ML anomaly score escalates risk to CRITICAL and recommends 'block'."""
    engine = RiskEngine()
    test_ip = "192.168.1.251"

    # Rule CRITICAL (0.90) + ML anomaly (0.90):
    # (0.65 * 0.90) + (0.35 * 0.90) = 0.585 + 0.315 = 0.9000
    assessment = engine.assess(
        source_ip=test_ip,
        rule_alerts=[{"severity": "CRITICAL", "detection_type": "EXPLOIT"}],
        ml_anomaly_score=0.90,
    )

    assert assessment.combined_score >= 0.80
    assert assessment.risk_level == "CRITICAL"
    assert assessment.recommended_action == "block"
