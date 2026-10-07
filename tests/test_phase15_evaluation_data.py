"""Unit tests for Phase 15 Synthetic Data Generation & ML Dataset Integrity."""

import pytest
from evaluation.data_generator import (
    SyntheticDataGenerator,
    generate_synthetic_raw_frame,
    generate_synthetic_parsed_packet,
)
from ml.feature_extractor import FEATURE_NAMES
from parser import parse_packet


def test_raw_frame_construction_and_parsing():
    """Verify that synthetic raw frames conform to Ethernet+IPv4+TCP protocol structure."""
    raw = generate_synthetic_raw_frame(
        src_ip="192.168.1.55",
        dst_ip="192.168.1.1",
        src_port=52000,
        dst_port=80,
        flags=0x02,  # SYN
        payload_len=32,
    )
    assert len(raw) >= 14 + 20 + 20 + 32  # 86 bytes minimum

    parsed = parse_packet(raw)
    assert parsed.error is None
    assert parsed.ethertype_name == "IPv4"
    assert parsed.protocol_name == "TCP"
    assert parsed.src_ip == "192.168.1.55"
    assert parsed.dst_ip == "192.168.1.1"
    assert parsed.dst_port == 80
    assert parsed.tcp_flags["SYN"] is True
    assert parsed.tcp_flags["ACK"] is False


def test_parsed_packet_construction():
    """Verify synthetic ParsedPacket generator."""
    pkt = generate_synthetic_parsed_packet(
        src_ip="10.0.0.99",
        dst_port=443,
        tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False},
    )
    assert pkt.src_ip == "10.0.0.99"
    assert pkt.dst_port == 443
    assert pkt.protocol_name == "TCP"
    assert pkt.tcp_flags["ACK"] is True


def test_ml_baseline_dataset_shape_and_features():
    """Verify ML baseline dataset format and feature vector properties."""
    gen = SyntheticDataGenerator(seed=42)
    baseline = gen.generate_ml_baseline_dataset(window_count=30, seed=42)

    assert len(baseline) == 30
    for vec in baseline:
        assert len(vec) == len(FEATURE_NAMES)
        assert len(vec) == 13
        # Invariants: pps > 0, tcp_ratio in [0, 1], syn_ratio in [0, 1]
        assert vec[0] > 0.0  # pps
        assert 0.0 <= vec[3] <= 1.0  # tcp_ratio
        assert 0.0 <= vec[6] <= 1.0  # syn_ratio


def test_ml_dataset_train_test_separation():
    """Verify strict separation between training baseline and evaluation test samples."""
    gen = SyntheticDataGenerator(seed=42)
    X_train = gen.generate_ml_baseline_dataset(window_count=20, seed=42)
    X_test, y_test, meta = gen.generate_ml_evaluation_dataset(
        normal_count=20, anomaly_count=20, seed=1337
    )

    # Check non-overlap
    train_tuples = {tuple(v) for v in X_train}
    test_tuples = {tuple(v) for v in X_test}

    # Strict separation: No training sample may appear in test set
    intersection = train_tuples.intersection(test_tuples)
    assert len(intersection) == 0, f"Found {len(intersection)} overlapping samples between train and test sets!"


def test_ml_evaluation_dataset_labels_and_archetypes():
    """Verify ground truth binary labels and distinct anomaly archetypes."""
    gen = SyntheticDataGenerator(seed=42)
    X_test, y_test, meta = gen.generate_ml_evaluation_dataset(
        normal_count=25, anomaly_count=25, seed=999
    )

    assert len(X_test) == 50
    assert len(y_test) == 50
    assert len(meta) == 50

    normal_labels = [y for y in y_test if y == 0]
    anomaly_labels = [y for y in y_test if y == 1]
    assert len(normal_labels) == 25
    assert len(anomaly_labels) == 25

    # Check that anomalies exhibit distinct feature characteristics
    # For instance, SYN flood archetype has syn_ratio > 0.90
    syn_floods = [m for m in meta if "SYN Flood" in m["label_name"]]
    assert len(syn_floods) > 0
    idx = syn_floods[0]["sample_index"]
    assert X_test[idx][6] >= 0.90  # syn_ratio
