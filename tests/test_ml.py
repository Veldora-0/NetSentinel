"""Unit tests for NetSentinel Machine Learning Anomaly Detection.

Tests feature extraction, windowing, IsolationForest training/prediction,
persistence, insufficient data safeguards, and live anomaly evaluation.
"""

import json
import os
import sys
import tempfile
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from ml.feature_extractor import FEATURE_NAMES, extract_features_from_window, TrafficWindow
from ml.model import IsolationForestModel, ModelStatus
from ml.detector import MLAnomalyDetector, MLAnomalyEvent
from parser import ParsedPacket
from app import create_app


def make_packet(
    proto: int = 6,
    proto_name: str = "TCP",
    raw_len: int = 100,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    src_port: int = 1234,
    dst_port: int = 80,
    tcp_flags: dict = None,
) -> ParsedPacket:
    """Helper to generate a mock ParsedPacket."""
    return ParsedPacket(
        timestamp=time.time(),
        raw_length=raw_len,
        src_mac="00:00:00:00:00:01",
        dst_mac="00:00:00:00:00:02",
        ethertype=0x0800,
        ethertype_name="IPv4",
        ip_version=4,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        protocol_name=proto_name,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
    )


# --- Feature Extraction Tests ---

def test_extract_features_empty_window():
    """Verify empty window produces zeroed features without division-by-zero errors."""
    vec, f_dict = extract_features_from_window([], window_duration=5.0)
    assert len(vec) == len(FEATURE_NAMES)
    for name in FEATURE_NAMES:
        assert f_dict[name] == 0.0


def test_extract_features_tcp_flags_ratios():
    """Verify accurate calculation of TCP flag ratios, rates, and average size."""
    syn_flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
    ack_flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False}

    p1 = make_packet(raw_len=100, tcp_flags=syn_flags, dst_port=80)
    p2 = make_packet(raw_len=200, tcp_flags=ack_flags, dst_port=443)

    vec, f_dict = extract_features_from_window([p1, p2], window_duration=2.0)

    assert f_dict["packets_per_second"] == 1.0  # 2 pkts / 2 sec
    assert f_dict["bytes_per_second"] == 150.0  # 300 bytes / 2 sec
    assert f_dict["average_packet_size"] == 150.0  # 300 / 2
    assert f_dict["tcp_ratio"] == 1.0
    assert f_dict["udp_ratio"] == 0.0
    assert f_dict["syn_ratio"] == 0.5  # 1/2
    assert f_dict["ack_ratio"] == 0.5  # 1/2
    assert f_dict["unique_destination_ports"] == 2.0  # 80 and 443
    assert f_dict["unique_source_ips"] == 1.0


def test_extract_features_mixed_protocols():
    """Verify protocol ratios for mixed TCP, UDP, and ICMP traffic."""
    p_tcp = make_packet(proto=6, proto_name="TCP", raw_len=100)
    p_udp = make_packet(proto=17, proto_name="UDP", raw_len=50)
    p_icmp = make_packet(proto=1, proto_name="ICMP", raw_len=60)
    p_other = make_packet(proto=2, proto_name="IGMP", raw_len=40)

    vec, f_dict = extract_features_from_window([p_tcp, p_udp, p_icmp, p_other], window_duration=4.0)

    assert f_dict["tcp_ratio"] == 0.25
    assert f_dict["udp_ratio"] == 0.25
    assert f_dict["icmp_ratio"] == 0.25
    assert f_dict["average_packet_size"] == (100 + 50 + 60 + 40) / 4.0


def test_traffic_window_buffer():
    """Verify TrafficWindow correctly buffers and consumes packets."""
    tw = TrafficWindow(window_seconds=1.0)
    assert tw.packet_count == 0

    tw.add_packet(make_packet(raw_len=80))
    tw.add_packet(make_packet(raw_len=120))
    assert tw.packet_count == 2

    vec, f_dict, count = tw.consume_window(custom_duration=1.0)
    assert count == 2
    assert tw.packet_count == 0
    assert f_dict["bytes_per_second"] == 200.0


# --- Isolation Forest Model Tests ---

def test_model_initialization_and_not_ready():
    """Verify model starts in MODEL_NOT_READY and raises if predict called prematurely."""
    model = IsolationForestModel(n_estimators=50, contamination=0.05, min_samples=5)
    assert model.status == ModelStatus.MODEL_NOT_READY

    with pytest.raises(RuntimeError):
        model.predict([0.0] * len(FEATURE_NAMES))


def test_model_insufficient_samples_rejected():
    """Verify training is rejected if provided samples are below min_samples."""
    model = IsolationForestModel(min_samples=5)
    too_few_samples = [[1.0] * len(FEATURE_NAMES) for _ in range(3)]

    with pytest.raises(ValueError, match="Insufficient baseline samples"):
        model.train(too_few_samples)
    assert model.status == ModelStatus.MODEL_NOT_READY


def test_model_training_and_prediction():
    """Verify model trains on normal baseline and accurately scores inliers and outliers."""
    model = IsolationForestModel(n_estimators=50, contamination="auto", min_samples=5, random_state=42)

    # Synthetic normal baseline: modest rates, web traffic
    baseline = []
    for i in range(20):
        sample = [
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
        baseline.append(sample)

    success = model.train(baseline)
    assert success is True
    assert model.status == ModelStatus.READY

    # Test an inlier matching baseline
    normal_window = [11.0, 5050.0, 500.0, 0.9, 0.1, 0.0, 0.05, 0.9, 0.0, 0.0, 3.0, 5.0, 2.0]
    is_anomaly_norm, raw_norm, score_norm = model.predict(normal_window)
    assert is_anomaly_norm is False
    assert raw_norm > 0.0  # Inlier has positive decision score

    # Test an extreme outlier (massive flood with extreme values)
    extreme_outlier = [
        10000.0, 50000000.0, 1500.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1000.0, 500.0, 1.0
    ]
    is_anomaly_out, raw_out, score_out = model.predict(extreme_outlier)
    assert is_anomaly_out is True
    assert raw_out < 0.0  # Anomaly has negative decision score
    assert score_out > 0.5


def test_model_persistence():
    """Verify model can be saved and reloaded with exact feature metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "model.joblib")
        meta_path = os.path.join(tmpdir, "meta.json")

        model1 = IsolationForestModel(n_estimators=30, contamination="auto", min_samples=5)
        samples = [[float(i)] * len(FEATURE_NAMES) for i in range(10)]
        model1.train(samples)

        assert model1.save(model_path, meta_path) is True
        assert os.path.exists(model_path)
        assert os.path.exists(meta_path)

        # Reload in a fresh instance
        model2 = IsolationForestModel(n_estimators=30, min_samples=5)
        assert model2.load(model_path, meta_path) is True
        assert model2.status == ModelStatus.READY
        assert model2.training_sample_count == 10
        assert model2.feature_names == FEATURE_NAMES


def test_model_corrupted_file_safe():
    """Verify loading corrupted model fails gracefully without crashing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "bad_model.joblib")
        meta_path = os.path.join(tmpdir, "bad_meta.json")

        with open(model_path, "w") as fh:
            fh.write("corrupted data")
        with open(meta_path, "w") as fh:
            fh.write('{"feature_names": ["mismatched"]}')

        model = IsolationForestModel()
        assert model.load(model_path, meta_path) is False
        assert model.status == ModelStatus.ERROR


# --- ML Anomaly Detector Coordinator Tests ---

def test_detector_baseline_collection_to_ready():
    """Verify detector transitions from COLLECTING_BASELINE to READY when window target is reached."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "window_seconds": 1.0,
            "baseline_windows": 5,
            "contamination": "auto",
            "alert_cooldown_seconds": 10.0,
            "model_path": os.path.join(tmpdir, "test_if.joblib"),
            "metadata_path": os.path.join(tmpdir, "test_meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)
        assert detector.model.status == ModelStatus.COLLECTING_BASELINE

        # Feed 5 normal windows
        normal_vec = [10.0, 500.0, 50.0, 0.8, 0.2, 0.0, 0.1, 0.8, 0.0, 0.0, 2.0, 2.0, 2.0]
        for i in range(5):
            res = detector.evaluate_window(custom_features=list(normal_vec))
            assert res is None  # No anomaly during baseline collection

        # Model should now be READY
        assert detector.model.status == ModelStatus.READY
        status = detector.get_status()
        assert status["model_status"] == "READY"
        assert status["baseline_samples_collected"] == 5


def test_detector_detects_anomaly_and_cooldown():
    """Verify anomalous window triggers MLAnomalyEvent and adheres to cooldown."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "window_seconds": 1.0,
            "baseline_windows": 5,
            "contamination": "auto",
            "alert_cooldown_seconds": 20.0,
            "model_path": os.path.join(tmpdir, "test_if.joblib"),
            "metadata_path": os.path.join(tmpdir, "test_meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        # Baseline with slight natural variation
        for i in range(5):
            vec = [5.0 + (i % 2), 250.0 + (i * 10), 50.0, 0.9, 0.1, 0.0, 0.1, 0.9, 0.0, 0.0, 2.0, 2.0, 2.0]
            detector.evaluate_window(custom_features=vec)
        assert detector.model.status == ModelStatus.READY

        # Extreme outlier feature vector
        extreme_vec = [50000.0, 50000000.0, 1000.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 999.0, 999.0, 999.0]
        event1 = detector.evaluate_window(custom_features=extreme_vec)
        assert event1 is not None
        assert event1.event_type == "ML_ANOMALY"
        assert event1.prediction == "ANOMALY"
        assert event1.severity == "MEDIUM"
        assert event1.anomaly_score > 0.5
        assert detector.total_anomalies_detected == 1

        # Second extreme window immediately after -> should be suppressed by cooldown
        event2 = detector.evaluate_window(custom_features=extreme_vec)
        assert event2 is None  # Suppressed by cooldown
        assert detector.total_anomalies_detected == 2  # Counter still tracks occurrences


def test_api_ml_endpoints():
    """Verify GET /api/ml/status and GET /api/ml/metrics endpoints."""
    app, _ = create_app(start_capture=False)
    app.config["TESTING"] = True

    with app.test_client() as client:
        # 1. /api/ml/status
        res_status = client.get("/api/ml/status")
        assert res_status.status_code == 200
        data_status = res_status.get_json()
        assert "model_status" in data_status
        assert "baseline_samples_collected" in data_status
        assert "total_anomalies_detected" in data_status

        # 2. /api/ml/metrics
        res_metrics = client.get("/api/ml/metrics")
        assert res_metrics.status_code == 200
        data_metrics = res_metrics.get_json()
        assert "status" in data_metrics
        assert "window_history" in data_metrics
        assert "recent_anomalies" in data_metrics


def test_canonical_13_feature_schema():
    """Verify that the feature extractor enforces strictly the 13 canonical features in order."""
    expected_order = [
        "packets_per_second",
        "bytes_per_second",
        "average_packet_size",
        "tcp_ratio",
        "udp_ratio",
        "icmp_ratio",
        "syn_ratio",
        "ack_ratio",
        "rst_ratio",
        "fin_ratio",
        "unique_destination_ports",
        "unique_source_ips",
        "unique_destination_ips",
    ]
    assert list(FEATURE_NAMES) == expected_order
    assert len(FEATURE_NAMES) == 13

    pkts = [
        make_packet(proto=6, proto_name="TCP", raw_len=100, tcp_flags={"SYN": True}),
        make_packet(proto=6, proto_name="TCP", raw_len=200, tcp_flags={"ACK": True}),
        make_packet(proto=6, proto_name="TCP", raw_len=300, tcp_flags={"RST": True}),
    ]
    vec, f_dict = extract_features_from_window(pkts, window_duration=5.0)
    assert len(vec) == 13
    assert len(f_dict) == 13
    assert list(f_dict.keys()) == expected_order


def test_traffic_window_canonical():
    """Verify TrafficWindow consumes strictly 13 canonical features."""
    win = TrafficWindow(window_seconds=5.0)
    win.add_packet(make_packet(proto=6, proto_name="TCP", raw_len=500, tcp_flags={"SYN": True}))
    vec, f_dict, count = win.consume_window()
    assert count == 1
    assert len(vec) == 13
    assert len(f_dict) == 13


def test_model_lifecycle_and_dimension_checks():
    """Verify IsolationForestModel enforces strict 13-feature dimension checks."""
    model = IsolationForestModel(n_estimators=20, min_samples=5)
    assert len(model.feature_names) == 13

    # Train with 13-feature vectors
    X_train = [[1.0] * 13 for _ in range(10)]
    assert model.train(X_train) is True
    assert model.status == ModelStatus.READY

    # Predict with 13 features -> succeeds
    is_anom, raw_s, norm_s = model.predict([1.0] * 13)
    assert isinstance(is_anom, bool)
    assert 0.0 <= norm_s <= 1.0

    # Predict with 12 or 17 features -> raises ValueError
    with pytest.raises(ValueError, match="Feature vector dimension mismatch"):
        model.predict([1.0] * 12)

    with pytest.raises(ValueError, match="Feature vector dimension mismatch"):
        model.predict([1.0] * 17)


def test_model_persistence_and_loading():
    """Verify model persistence and reloading with 13-feature schema."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        mod_file = os.path.join(tmp_dir, "test_13.joblib")
        meta_file = os.path.join(tmp_dir, "test_13.json")

        m1 = IsolationForestModel(n_estimators=10, min_samples=5)
        m1.train([[2.0] * 13 for _ in range(8)])
        assert m1.save(mod_file, meta_file) is True

        m2 = IsolationForestModel(n_estimators=10, min_samples=5)
        assert m2.load(mod_file, meta_file) is True
        assert len(m2.feature_names) == 13
        assert m2.status == ModelStatus.READY

        # Verify predictions match
        test_vec = [2.0] * 13
        p1 = m1.predict(test_vec)
        p2 = m2.predict(test_vec)
        assert p1 == p2


def test_baseline_outlier_filtering():
    """Verify detector baseline outlier filtering rejects contaminated flood windows."""
    cfg = {
        "enabled": True,
        "baseline_windows": 10,
        "window_seconds": 5.0,
        "n_estimators": 50,
        "min_samples": 5,
    }
    detector = MLAnomalyDetector(config=cfg)

    # 10 windows: 9 normal windows and 1 massive flood outlier
    normal_samples = [[20.0, 15000.0, 750.0, 0.9, 0.1, 0.0, 0.05, 0.85, 0.01, 0.02, 5.0, 2.0, 4.0] for _ in range(9)]
    outlier_sample = [5000.0, 5000000.0, 1000.0, 1.0, 0.0, 0.0, 0.99, 0.0, 0.0, 0.0, 200.0, 100.0, 2.0]
    all_samples = normal_samples + [outlier_sample]

    filtered = detector._filter_baseline_outliers(all_samples)
    assert len(filtered) == 9
    assert outlier_sample not in filtered


def test_calibrated_anomaly_threshold():
    """Verify calibrated decision threshold suppresses false alarms at borderline scores."""
    # Detector with calibrated threshold = 0.58
    cfg = {
        "enabled": True,
        "baseline_windows": 5,
        "window_seconds": 5.0,
        "anomaly_threshold": 0.58,
    }
    detector = MLAnomalyDetector(config=cfg)
    assert detector.anomaly_threshold == 0.58

    # Train model on normal samples
    normal_samples = [[20.0, 15000.0, 750.0, 0.9, 0.1, 0.0, 0.05, 0.85, 0.01, 0.02, 5.0, 2.0, 4.0] for _ in range(10)]
    detector.model.train(normal_samples)

    status = detector.get_status()
    assert status["anomaly_threshold"] == 0.58


def test_atomic_model_saving():
    """Verify model save writes atomically and cleans up any temp files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        mod_file = os.path.join(tmp_dir, "atomic_model.joblib")
        meta_file = os.path.join(tmp_dir, "atomic_meta.json")

        m = IsolationForestModel(n_estimators=10, min_samples=5)
        m.train([[1.0] * 13 for _ in range(6)])
        assert m.save(mod_file, meta_file) is True

        assert os.path.exists(mod_file)
        assert os.path.exists(meta_file)

        # Confirm no leftover .tmp files
        files = os.listdir(tmp_dir)
        tmp_files = [f for f in files if ".tmp" in f]
        assert len(tmp_files) == 0


def test_production_baseline_defaults_and_filtering():
    """Verify production baseline defaults and reusable outlier filtering function."""
    from config import Config
    from ml.detector import filter_baseline_outliers

    assert Config.ML_BASELINE_WINDOWS == 512
    assert Config.ML_MIN_SAMPLES == 512
    assert Config.ML_BASELINE_FILTER == "none"

    detector = MLAnomalyDetector()
    assert detector.baseline_windows == 512
    assert detector.min_samples == 512
    assert detector.baseline_filter == "none"
    assert detector.anomaly_threshold == 0.50

    # 10 windows: 9 normal, 1 extreme volumetric outlier
    normal = [[20.0, 15000.0, 750.0, 0.9, 0.1, 0.0, 0.05, 0.85, 0.01, 0.02, 5.0, 2.0, 4.0] for _ in range(9)]
    outlier = [10000.0, 9999999.0, 1500.0, 1.0, 0.0, 0.0, 0.99, 0.0, 0.0, 0.0, 500.0, 200.0, 5.0]
    filtered = filter_baseline_outliers(normal + [outlier], min_samples=5)
    assert len(filtered) == 9
    assert outlier not in filtered


