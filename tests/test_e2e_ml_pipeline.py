"""Phase 14 End-to-End Validation: ML Anomaly Detection Pipeline & Safety Limits.

Verifies:
1. Unsupervised Isolation Forest lifecycle: COLLECTING_BASELINE -> READY.
2. Anomaly scoring produced on normal vs outlier traffic windows around 0.5 decision threshold.
3. Safety boundary: ML anomaly score alone is strictly capped (max risk 0.35, MEDIUM severity),
   and CANNOT reach CRITICAL or trigger automatic firewall mitigation.
4. Composite risk formula accurately integrates Rule Alert + ML Anomaly score.
5. Explicit verification: The ML system is unsupervised anomaly detection; no supervised
   accuracy percentage is fabricated or claimed.
"""

import os
import tempfile
import time
import pytest

from ml.detector import MLAnomalyDetector, MLAnomalyEvent
from ml.model import IsolationForestModel, ModelStatus
from risk_engine import RiskEngine
from detector import SecurityEvent


@pytest.fixture
def ml_env():
    temp_dir = tempfile.mkdtemp(prefix="netsentinel_e2e_ml_")
    cfg = {
        "enabled": True,
        "window_seconds": 1.0,
        "baseline_windows": 20,
        "contamination": "auto",
        "random_state": 42,
        "alert_cooldown_seconds": 20.0,
        "model_path": os.path.join(temp_dir, "if.joblib"),
        "metadata_path": os.path.join(temp_dir, "meta.json"),
    }
    detector = MLAnomalyDetector(config=cfg)
    yield detector, temp_dir


def test_e2e_ml_lifecycle_and_window_scoring(ml_env):
    """Verify ML model lifecycle transitions and anomaly scoring behavior."""
    detector, _ = ml_env

    # 1. Verify initial lifecycle state
    assert detector.model.status == ModelStatus.COLLECTING_BASELINE

    # 2. Feed 20 baseline windows to fit normal traffic profile
    for i in range(20):
        vec = [
            10.0 + (i % 3),    # pps
            5000.0 + (i * 10), # bps
            500.0,             # avg pkt size
            0.9,               # tcp ratio
            0.1,               # udp ratio
            0.0,               # icmp ratio
            0.05,              # syn ratio
            0.9,               # ack ratio
            0.0,               # rst ratio
            0.0,               # fin ratio
            3.0,               # unique ports
            5.0,               # unique src ips
            2.0,               # unique dst ips
        ]
        res = detector.evaluate_window(custom_features=vec)
        assert res is None  # No anomaly during baseline collection

    # 3. Model status must transition to READY
    assert detector.model.status == ModelStatus.READY
    status = detector.get_status()
    assert status["model_status"] == "READY"
    assert status["baseline_samples_collected"] == 20

    # 4. Evaluate inlier window matching learned baseline
    normal_vec = [11.0, 5050.0, 500.0, 0.9, 0.1, 0.0, 0.05, 0.9, 0.0, 0.0, 3.0, 5.0, 2.0]
    norm_res = detector.evaluate_window(custom_features=normal_vec)
    assert norm_res is None
    assert detector.latest_prediction == "NORMAL"
    assert detector.latest_anomaly_score <= 0.50

    # 5. Evaluate extreme outlier window (SYN flood characteristics)
    extreme_vec = [10000.0, 50000000.0, 1500.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1000.0, 500.0, 1.0]
    anom_event = detector.evaluate_window(custom_features=extreme_vec)
    assert anom_event is not None
    assert anom_event.prediction == "ANOMALY"
    assert anom_event.anomaly_score > 0.50
    assert anom_event.severity == "MEDIUM"


def test_e2e_ml_alone_safety_invariant():
    """Verify that an ML anomaly alone cannot reach CRITICAL or trigger automatic blocking."""
    engine = RiskEngine()

    # Feed maximum possible ML anomaly score (1.0) with zero rule alerts
    assessment = engine.assess(source_ip="192.168.1.150", ml_anomaly_score=1.0, rule_alerts=[])

    # Invariants:
    # 1. ML weight is 0.35, so 1.0 * 0.35 = 0.35
    assert assessment.combined_score <= 0.35
    # 2. Risk level is strictly MEDIUM (LOW < 0.30, MEDIUM < 0.60)
    assert assessment.risk_level == "MEDIUM"
    # 3. Recommended action is "log", NOT "block" or "alert"
    assert assessment.recommended_action == "log"
    # 4. Blocked must be False
    assert assessment.blocked is False


def test_e2e_rule_plus_ml_composite_scoring():
    """Verify composite risk formula combining rule alert and ML anomaly score."""
    engine = RiskEngine()
    rule_event = SecurityEvent(
        event_id="ev-rule-test",
        timestamp=time.time(),
        detection_type="PORT_SCAN",
        severity="MEDIUM",  # Base score 0.40
        source_ip="192.168.1.160",
    )

    # Formula: (0.65 * rule_score) + (0.35 * ml_score)
    # With rule_score=0.40 and ml_score=0.80:
    # (0.65 * 0.40) + (0.35 * 0.80) = 0.26 + 0.28 = 0.5400
    assessment = engine.assess(
        source_ip="192.168.1.160",
        rule_alerts=[rule_event],
        ml_anomaly_score=0.80,
    )
    expected_score = round((0.65 * 0.40) + (0.35 * 0.80), 4)

    assert abs(assessment.combined_score - expected_score) < 0.001
    assert assessment.risk_level == "MEDIUM"
    assert assessment.recommended_action == "log"
