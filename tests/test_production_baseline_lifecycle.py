"""Verification test suite for NetSentinel Production Baseline Redesign.

Covers all 15 required verification items:
1. Fewer than 512 windows cannot train.
2. Exactly 512 windows initiate training.
3. Invalid/incomplete windows excluded.
4. Duplicate windows not counted twice.
5. Concurrent collection cannot trigger duplicate training.
6. Training failure does not mark ready.
7. Persistence failure does not mark ready.
8. Safe restart handling.
9. Model compatibility & 13-feature order validation.
10. API reports correct warmup progress.
11. Frontend warmup visibility fields.
12. Suricata and HIDS continue operating during warmup.
13. Firewall and auto-block remain disabled.
14. Two-Stage Trim disabled by default.
15. End-to-end production pipeline integrity.
"""

import json
import os
import sys
import tempfile
import threading
import time
from typing import List
from unittest.mock import patch, MagicMock

import numpy as np
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from config import Config
from ml.feature_extractor import FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus
from ml.detector import (
    MLAnomalyDetector,
    MLAnomalyEvent,
    two_stage_trim_filter,
    filter_baseline_outliers,
)
from app import create_app


def generate_valid_feature_vector(seed: int = 0) -> List[float]:
    """Generate a valid canonical 13-feature synthetic network traffic vector."""
    return [
        float(15.0 + (seed % 5)),           # packets_per_second
        float(7500.0 + (seed * 10)),        # bytes_per_second
        500.0,                              # average_packet_size
        0.85,                               # tcp_ratio
        0.15,                               # udp_ratio
        0.0,                                # icmp_ratio
        0.05,                               # syn_ratio
        0.80,                               # ack_ratio
        0.0,                                # rst_ratio
        0.0,                                # fin_ratio
        4.0,                                # unique_destination_ports
        6.0,                                # unique_source_ips
        3.0,                                # unique_destination_ips
    ]


# ---------------------------------------------------------------------------
# Item 1: Fewer than 512 windows cannot train
# ---------------------------------------------------------------------------
def test_1_fewer_than_512_windows_cannot_train():
    """Verify that the detector remains in warmup and cannot train with < 512 windows."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "window_seconds": 5.0,
            "baseline_windows": 512,
            "min_samples": 512,
            "baseline_filter": "none",
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)
        assert detector.baseline_windows == 512
        assert detector.min_samples == 512
        assert detector.model.status == ModelStatus.COLLECTING_BASELINE

        # Feed 511 valid windows
        for i in range(511):
            res = detector.evaluate_window(custom_features=generate_valid_feature_vector(i))
            assert res is None

        # Still not ready
        assert len(detector.baseline_samples) == 511
        assert detector.model.status == ModelStatus.COLLECTING_BASELINE
        assert detector.model.model is None

        status = detector.get_status()
        assert status["model_ready"] is False
        assert status["warmup_status"] == "WARMUP"
        assert status["baseline_windows_collected"] == 511
        assert status["baseline_windows_required"] == 512
        assert status["warmup_progress_percent"] == 99.8
        assert status["training_in_progress"] is False


# ---------------------------------------------------------------------------
# Item 2: Exactly 512 windows initiate training
# ---------------------------------------------------------------------------
def test_2_exactly_512_windows_initiates_training():
    """Verify that receiving the 512th valid window transitions the model to READY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "model.joblib")
        meta_path = os.path.join(tmpdir, "meta.json")
        cfg = {
            "enabled": True,
            "window_seconds": 5.0,
            "baseline_windows": 512,
            "min_samples": 512,
            "baseline_filter": "none",
            "model_path": model_path,
            "metadata_path": meta_path,
        }
        detector = MLAnomalyDetector(config=cfg)

        for i in range(512):
            detector.evaluate_window(custom_features=generate_valid_feature_vector(i))

        assert detector.model.status == ModelStatus.READY
        assert detector.model.model is not None
        assert detector.model.training_sample_count == 512
        assert os.path.exists(model_path)
        assert os.path.exists(meta_path)

        status = detector.get_status()
        assert status["model_ready"] is True
        assert status["warmup_status"] == "READY"
        assert status["warmup_progress_percent"] == 100.0
        assert status["training_in_progress"] is False


# ---------------------------------------------------------------------------
# Item 3: Invalid/incomplete windows excluded
# ---------------------------------------------------------------------------
def test_3_invalid_incomplete_windows_excluded():
    """Verify that malformed, non-finite, or negative feature windows are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 512,
            "min_samples": 512,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        # 1. Under-dimensioned (12 features)
        res = detector.evaluate_window(custom_features=[1.0] * 12)
        assert res is None
        assert len(detector.baseline_samples) == 0

        # 2. Over-dimensioned (14 features)
        res = detector.evaluate_window(custom_features=[1.0] * 14)
        assert res is None
        assert len(detector.baseline_samples) == 0

        # 3. Vector with NaN
        nan_vec = generate_valid_feature_vector(1)
        nan_vec[1] = float("nan")
        res = detector.evaluate_window(custom_features=nan_vec)
        assert res is None
        assert len(detector.baseline_samples) == 0

        # 4. Vector with positive Inf
        inf_vec = generate_valid_feature_vector(2)
        inf_vec[2] = float("inf")
        res = detector.evaluate_window(custom_features=inf_vec)
        assert res is None
        assert len(detector.baseline_samples) == 0

        # 5. Vector with negative Inf
        neg_inf_vec = generate_valid_feature_vector(3)
        neg_inf_vec[0] = float("-inf")
        res = detector.evaluate_window(custom_features=neg_inf_vec)
        assert res is None
        assert len(detector.baseline_samples) == 0

        # 6. Negative rate / packet count
        neg_rate_vec = generate_valid_feature_vector(4)
        neg_rate_vec[0] = -10.0
        res = detector.evaluate_window(custom_features=neg_rate_vec)
        assert res is None
        assert len(detector.baseline_samples) == 0

        # Feed 1 valid window and assert count is strictly 1
        detector.evaluate_window(custom_features=generate_valid_feature_vector(5))
        assert len(detector.baseline_samples) == 1


# ---------------------------------------------------------------------------
# Item 4: Duplicate windows not counted twice
# ---------------------------------------------------------------------------
def test_4_duplicate_windows_not_counted_twice():
    """Verify that duplicate window submissions (by window_id or timestamp) are deduplicated."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 512,
            "min_samples": 512,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        vec = generate_valid_feature_vector(1)

        # Feed with window_id
        detector.evaluate_window(custom_features=vec, window_id="win-uuid-101")
        assert len(detector.baseline_samples) == 1

        # Re-feed duplicate window_id
        detector.evaluate_window(custom_features=vec, window_id="win-uuid-101")
        assert len(detector.baseline_samples) == 1

        # Feed with timestamp
        detector.evaluate_window(custom_features=vec, timestamp=1700000000.0)
        assert len(detector.baseline_samples) == 2

        # Re-feed duplicate timestamp
        detector.evaluate_window(custom_features=vec, timestamp=1700000000.0)
        assert len(detector.baseline_samples) == 2


# ---------------------------------------------------------------------------
# Item 5: Concurrent collection cannot trigger duplicate training
# ---------------------------------------------------------------------------
def test_5_concurrent_collection_prevents_duplicate_training():
    """Verify that multi-threaded window collection does not trigger concurrent training."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 512,
            "min_samples": 512,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        def worker(start_idx: int, count: int):
            for i in range(start_idx, start_idx + count):
                detector.evaluate_window(custom_features=generate_valid_feature_vector(i))

        # Spawn 8 threads providing 64 windows each = 512 total
        threads = []
        for t in range(8):
            th = threading.Thread(target=worker, args=(t * 64, 64))
            threads.append(th)
            th.start()

        for th in threads:
            th.join(timeout=10.0)

        assert detector.model.status == ModelStatus.READY
        assert detector.model.training_sample_count == 512
        assert detector.get_status()["model_ready"] is True


# ---------------------------------------------------------------------------
# Item 6: Training failure does not mark ready
# ---------------------------------------------------------------------------
def test_6_training_failure_does_not_mark_ready():
    """Verify that model fitting failure transitions to ERROR and does not mark READY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 512,
            "min_samples": 512,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        # Mock IsolationForest.fit to raise RuntimeError
        with patch("sklearn.ensemble.IsolationForest.fit", side_effect=RuntimeError("Simulated fit failure")):
            for i in range(512):
                detector.evaluate_window(custom_features=generate_valid_feature_vector(i))

        assert detector.model.status == ModelStatus.ERROR
        assert detector.model.model is None
        status = detector.get_status()
        assert status["model_ready"] is False
        assert status["warmup_status"] == "ERROR"
        assert "Simulated fit failure" in (status["error_message"] or "")


# ---------------------------------------------------------------------------
# Item 7: Persistence failure does not mark ready
# ---------------------------------------------------------------------------
def test_7_persistence_failure_does_not_mark_ready():
    """Verify that failure to atomically save the model transitions to ERROR without marking READY."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 512,
            "min_samples": 512,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        # Mock model.save to return False
        with patch.object(detector.model, "save", return_value=False):
            for i in range(512):
                detector.evaluate_window(custom_features=generate_valid_feature_vector(i))

        assert detector.model.status == ModelStatus.ERROR
        status = detector.get_status()
        assert status["model_ready"] is False
        assert status["warmup_status"] == "ERROR"


# ---------------------------------------------------------------------------
# Item 8: Safe restart handling (verify model compatibility)
# ---------------------------------------------------------------------------
def test_8_safe_restart_handling():
    """Verify that safe restart loads a valid 512-window model, but rejects an obsolete <512 model."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "model.joblib")
        meta_path = os.path.join(tmpdir, "meta.json")

        # 1. Train and persist valid 512-window model
        m1 = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [generate_valid_feature_vector(i) for i in range(512)]
        assert m1.train(samples) is True
        assert m1.save(model_path, meta_path) is True

        # Fresh detector instance loads successfully
        cfg = {
            "enabled": True,
            "baseline_windows": 512,
            "min_samples": 512,
            "model_path": model_path,
            "metadata_path": meta_path,
        }
        detector_valid = MLAnomalyDetector(config=cfg)
        assert detector_valid.model.status == ModelStatus.READY
        assert detector_valid.get_status()["model_ready"] is True

        # 2. Tamper metadata to reflect obsolete baseline size (< 512, e.g. 27 windows)
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        meta["training_sample_count"] = 27
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)

        # Fresh detector must reject the obsolete 27-window model and restart baseline collection
        detector_obsolete = MLAnomalyDetector(config=cfg)
        assert detector_obsolete.model.status == ModelStatus.COLLECTING_BASELINE
        assert detector_obsolete.get_status()["model_ready"] is False
        assert detector_obsolete.get_status()["baseline_windows_collected"] == 0


# ---------------------------------------------------------------------------
# Item 9: Model compatibility & 13-feature order validation
# ---------------------------------------------------------------------------
def test_9_model_compatibility_and_13_feature_order_validation():
    """Verify that corrupted feature ordering or count in persisted model is rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "model.joblib")
        meta_path = os.path.join(tmpdir, "meta.json")

        m = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [generate_valid_feature_vector(i) for i in range(512)]
        m.train(samples)
        m.save(model_path, meta_path)

        # Swap two features in metadata to simulate incompatible schema
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        meta["feature_names"][0], meta["feature_names"][1] = meta["feature_names"][1], meta["feature_names"][0]
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)

        m_fresh = IsolationForestModel(min_samples=512)
        assert m_fresh.load(model_path, meta_path) is False
        assert m_fresh.status == ModelStatus.ERROR
        assert "feature ordering mismatch" in m_fresh.last_error.lower()


# ---------------------------------------------------------------------------
# Item 10: API reports correct warmup progress
# ---------------------------------------------------------------------------
def test_10_api_reports_correct_warmup_progress():
    """Verify that Flask /api/ml/status endpoint exposes accurate warmup telemetry."""
    app, _ = create_app(start_capture=False)
    app.config["TESTING"] = True

    with app.test_client() as client:
        # Configure app ml_detector in warmup
        detector = app.ml_detector
        detector.baseline_windows = 512
        detector.min_samples = 512
        detector.model.status = ModelStatus.COLLECTING_BASELINE
        detector.baseline_samples = [generate_valid_feature_vector(i) for i in range(256)]

        # Read status
        res = client.get("/api/ml/status")
        assert res.status_code == 200
        data = res.get_json()

        assert data["model_ready"] is False
        assert data["warmup_status"] == "WARMUP"
        assert data["baseline_windows_collected"] == 256
        assert data["baseline_windows_required"] == 512
        assert data["warmup_progress_percent"] == 50.0
        assert data["training_in_progress"] is False
        assert data["baseline_filter"] == "none"
        assert data["sensors_active"]["rule_nids"] is True
        assert data["sensors_active"]["suricata"] is True
        assert data["sensors_active"]["hids"] is True


# ---------------------------------------------------------------------------
# Item 11: Frontend warmup visibility fields
# ---------------------------------------------------------------------------
def test_11_frontend_warmup_visibility_fields():
    """Verify all telemetry attributes expected by Overview.jsx and Detection.jsx are present."""
    detector = MLAnomalyDetector()
    status = detector.get_status()

    required_keys = [
        "enabled",
        "model_status",
        "model_ready",
        "warmup_status",
        "baseline_established",
        "baseline_windows_collected",
        "baseline_windows_required",
        "baseline_samples_collected",
        "baseline_target_samples",
        "warmup_progress_percent",
        "training_in_progress",
        "baseline_filter",
        "anomaly_threshold",
        "window_seconds",
        "sensors_active",
    ]
    for key in required_keys:
        assert key in status, f"Missing required telemetry key for frontend: {key}"


# ---------------------------------------------------------------------------
# Item 12: Suricata and HIDS continue operating during warmup
# ---------------------------------------------------------------------------
def test_12_suricata_and_hids_continue_operating_during_warmup():
    """Verify hybrid rule-based NIDS and HIDS monitoring continue operating while ML is warming up."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 512,
            "min_samples": 512,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)
        status = detector.get_status()

        # ML is warming up
        assert status["model_ready"] is False
        assert status["warmup_status"] == "WARMUP"

        # Suricata NIDS & auditd HIDS remain active
        assert status["sensors_active"]["rule_nids"] is True
        assert status["sensors_active"]["suricata"] is True
        assert status["sensors_active"]["hids"] is True


# ---------------------------------------------------------------------------
# Item 13: Firewall and auto-block remain disabled
# ---------------------------------------------------------------------------
def test_13_firewall_and_auto_block_remain_disabled():
    """Verify strict safety boundaries: firewall disabled, auto-block disabled, dry-run enabled."""
    assert Config.FIREWALL_SETTINGS["enabled"] is False
    assert Config.FIREWALL_SETTINGS["auto_block"] is False
    assert Config.FIREWALL_SETTINGS["dry_run"] is True


# ---------------------------------------------------------------------------
# Item 14: Two-Stage Trim disabled by default
# ---------------------------------------------------------------------------
def test_14_two_stage_trim_disabled_by_default():
    """Verify production baseline filtering defaults to 'none' and Two-Stage Trim is standalone."""
    assert Config.ML_SETTINGS["baseline_filter"] == "none"
    detector = MLAnomalyDetector()
    assert detector.baseline_filter == "none"

    # Verify two_stage_trim_filter is an importable function with documented limitations
    samples = [generate_valid_feature_vector(i) for i in range(100)]
    trimmed = two_stage_trim_filter(samples, trim_percent=0.05, min_samples=50)
    assert len(trimmed) <= len(samples)


# ---------------------------------------------------------------------------
# Item 15: End-to-end production pipeline integrity
# ---------------------------------------------------------------------------
def test_15_production_pipeline_integrity():
    """Verify end-to-end production pipeline: 512 windows -> fit 100 trees -> inlier/outlier scoring."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "window_seconds": 5.0,
            "baseline_windows": 512,
            "min_samples": 512,
            "baseline_filter": "none",
            "n_estimators": 100,
            "anomaly_threshold": 0.50,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        # Feed 512 baseline windows
        for i in range(512):
            detector.evaluate_window(custom_features=generate_valid_feature_vector(i))

        assert detector.model.status == ModelStatus.READY

        # Test normal inlier at median of distribution
        normal_vec = generate_valid_feature_vector(256)
        norm_event = detector.evaluate_window(custom_features=normal_vec)
        assert norm_event is None
        assert detector.latest_prediction == "NORMAL"
        assert detector.latest_anomaly_score <= 0.50

        # Test extreme outlier
        extreme_vec = [15000.0, 50000000.0, 1500.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 5000.0, 2000.0, 1.0]
        anom_event = detector.evaluate_window(custom_features=extreme_vec)
        assert anom_event is not None
        assert anom_event.prediction == "ANOMALY"
        assert anom_event.anomaly_score > 0.50
        assert detector.latest_prediction == "ANOMALY"
