"""Unit tests for Phase 15.5 Real-World Dataset ML Evaluation Engine.

Tests Zeek log parsing, streaming PCAP reading, 5-second windowing, deterministic
ground-truth labelling, data leakage protection, metrics aggregation, reproducibility,
and security invariants without requiring the external CTU-IDSEVAL-6 dataset.
"""

import os
import pytest
from typing import List, Tuple

from config import Config
from evaluation.metrics import (
    calculate_confusion_matrix,
    calculate_classification_metrics,
)
from evaluation.pcap_reader import (
    PcapReader,
    PcapPacketRecord,
    write_synthetic_pcap,
)
from evaluation.zeek_parser import (
    ZeekLogParser,
    ZeekFlowRecord,
    normalize_zeek_label,
    write_synthetic_zeek_log,
)
from evaluation.window_builder import (
    TrafficWindowBuilder,
    WindowEvaluationRecord,
    WindowGroundTruth,
    determine_window_ground_truth,
)
from evaluation.real_dataset import (
    RealDatasetEvaluator,
    DataLeakageError,
    run_smoke_test,
)
from evaluation.data_generator import generate_synthetic_raw_frame
from parser import parse_packet


# =========================================================================
# A. ZEEK LOG PARSER TESTS
# =========================================================================

def test_zeek_parser_dynamic_fields_and_labels(tmp_path):
    """Verify Zeek parser dynamically resolves fields and extracts labels."""
    log_file = str(tmp_path / "test.conn-labeled.log")
    flows_input = [
        {"ts": 100.5, "duration": 2.0, "label": "Benign", "detailedlabel": "NormalHTTP"},
        {"ts": 95.0, "duration": "-", "label": "Malicious", "detailedlabel": "SYNScan"},
        {"ts": 105.0, "duration": 0.0, "label": "Background", "detailedlabel": "-"},
    ]
    write_synthetic_zeek_log(log_file, flows_input)

    parser = ZeekLogParser(log_file)
    flows = parser.parse_flows()

    # Must sort by ts ascending: 95.0, 100.5, 105.0
    assert len(flows) == 3
    assert flows[0].ts == 95.0
    assert flows[0].label == "Malicious"
    assert flows[0].detailed_label == "SYNScan"
    assert flows[0].duration == 0.0  # "-" converted to 0.0
    assert flows[0].end_time == 95.0

    assert flows[1].ts == 100.5
    assert flows[1].label == "Benign"
    assert flows[1].duration == 2.0
    assert flows[1].end_time == 102.5

    assert flows[2].ts == 105.0
    assert flows[2].label == "Background"


def test_zeek_label_normalization():
    """Verify label string normalization for varying casings and keywords."""
    assert normalize_zeek_label("Malicious") == "Malicious"
    assert normalize_zeek_label("malicious-activity") == "Malicious"
    assert normalize_zeek_label("Benign") == "Benign"
    assert normalize_zeek_label("benign_user") == "Benign"
    assert normalize_zeek_label("Background") == "Background"
    assert normalize_zeek_label("background_flow") == "Background"


# =========================================================================
# B. WINDOWING TESTS
# =========================================================================

def test_windowing_exact_boundaries_and_ordering(tmp_path):
    """Verify exact 5-second boundaries and packet placement."""
    pcap_file = str(tmp_path / "win.pcap")
    pkts = [
        (generate_synthetic_raw_frame(dst_port=80), 100.0),  # Window 0: [100.0, 105.0)
        (generate_synthetic_raw_frame(dst_port=80), 104.99), # Window 0: [100.0, 105.0)
        (generate_synthetic_raw_frame(dst_port=80), 105.0),  # Window 1: [105.0, 110.0)
        (generate_synthetic_raw_frame(dst_port=80), 109.9),  # Window 1: [105.0, 110.0)
    ]
    write_synthetic_pcap(pcap_file, pkts)

    reader = PcapReader(pcap_file).iter_packets()
    builder = TrafficWindowBuilder(window_duration=5.0)
    windows, summary = builder.process_capture("test", reader, [])

    assert len(windows) == 2
    assert windows[0].start_time == 100.0
    assert windows[0].end_time == 105.0
    assert windows[0].packet_count == 2

    assert windows[1].start_time == 105.0
    assert windows[1].end_time == 110.0
    assert windows[1].packet_count == 2


def test_windowing_duration_crossing_and_empty_windows(tmp_path):
    """Verify flow crossing multiple windows and empty window generation."""
    pcap_file = str(tmp_path / "cross.pcap")
    # Packets at 100.0 and 115.0 (gap of 15 seconds)
    pkts = [
        (generate_synthetic_raw_frame(dst_port=80), 100.0),
        (generate_synthetic_raw_frame(dst_port=80), 115.0),
    ]
    write_synthetic_pcap(pcap_file, pkts)

    # 1. include_empty_windows = True
    reader = PcapReader(pcap_file).iter_packets()
    builder = TrafficWindowBuilder(window_duration=5.0, include_empty_windows=True)
    # Long flow spanning 100.0 to 120.0
    long_flow = [ZeekFlowRecord(
        flow_index=0, ts=100.0, duration=20.0, start_time=100.0, end_time=120.0,
        label="Benign", raw_label="Benign", detailed_label="LongFlow"
    )]
    windows, _ = builder.process_capture("test", reader, long_flow)

    # Expected windows: [100, 105), [105, 110), [110, 115), [115, 120) -> 4 windows
    assert len(windows) == 4
    assert windows[1].packet_count == 0  # Empty window generated
    assert windows[1].ground_truth == WindowGroundTruth.BENIGN  # Overlapped by long_flow
    assert windows[2].packet_count == 0  # Empty window generated
    assert windows[2].ground_truth == WindowGroundTruth.BENIGN


# =========================================================================
# C. GROUND TRUTH ASSIGNMENT TESTS
# =========================================================================

def test_ground_truth_deterministic_rules():
    """Verify ground truth resolution rules A, B, C, D and mixed flag."""
    flow_mal = ZeekFlowRecord(0, 10.0, 1.0, 10.0, 11.0, "Malicious", "Malicious", "Scan")
    flow_ben = ZeekFlowRecord(1, 10.0, 1.0, 10.0, 11.0, "Benign", "Benign", "-")
    flow_bg = ZeekFlowRecord(2, 10.0, 1.0, 10.0, 11.0, "Background", "Background", "-")

    # A. Malicious only
    gt, mixed, _, _ = determine_window_ground_truth([flow_mal])
    assert gt == WindowGroundTruth.MALICIOUS
    assert mixed is False

    # B. Benign only
    gt, mixed, _, _ = determine_window_ground_truth([flow_ben])
    assert gt == WindowGroundTruth.BENIGN
    assert mixed is False

    # C. Background only
    gt, mixed, _, _ = determine_window_ground_truth([flow_bg])
    assert gt == WindowGroundTruth.BACKGROUND_ONLY
    assert mixed is False

    # D. Unlabeled (no flows)
    gt, mixed, _, _ = determine_window_ground_truth([])
    assert gt == WindowGroundTruth.UNLABELED
    assert mixed is False

    # Mixed Malicious + Benign => MALICIOUS with is_mixed=True
    gt, mixed, _, _ = determine_window_ground_truth([flow_mal, flow_ben])
    assert gt == WindowGroundTruth.MALICIOUS
    assert mixed is True


# =========================================================================
# D. PCAP PROCESSING & PARSER ROBUSTNESS
# =========================================================================

def test_pcap_reader_and_truncated_packet_handling(tmp_path):
    """Verify PCAP reader parses valid frames and cleanly counts truncated records."""
    pcap_file = str(tmp_path / "truncated.pcap")
    pkts = [
        (generate_synthetic_raw_frame(dst_port=80), 100.0),
        (b"\x00\x01\x02\x03", 101.0),  # 4-byte truncated record (fails < 14 bytes)
        (generate_synthetic_raw_frame(dst_port=443), 102.0),
    ]
    write_synthetic_pcap(pcap_file, pkts)

    reader = PcapReader(pcap_file).iter_packets()
    builder = TrafficWindowBuilder()
    windows, summary = builder.process_capture("trunc_test", reader, [])

    assert summary.total_capture_records == 3
    assert summary.parsed_successfully == 2
    assert summary.parse_failures == 1
    assert summary.parse_success_rate == round(2 / 3, 4)
    assert len(windows) == 1
    assert windows[0].packet_count == 2  # Only 2 successfully parsed packets in window


# =========================================================================
# E. DATA LEAKAGE PREVENTION TESTS
# =========================================================================

def test_data_leakage_safeguard_triggers_on_malicious_training(tmp_path):
    """Verify evaluator raises DataLeakageError if training capture contains attack window."""
    pcap_dir = str(tmp_path / "pcap")
    zeek_dir = str(tmp_path / "zeek")
    os.makedirs(pcap_dir)
    os.makedirs(zeek_dir)

    train_pcap = os.path.join(pcap_dir, "ctu-idseval-6-benign-user-traffic-1.pcap")
    train_zeek = os.path.join(zeek_dir, "ctu-idseval-6-benign-user-traffic-1.conn-labeled.log")

    # Contaminate training capture with a Malicious flow
    pkts = [(generate_synthetic_raw_frame(), 100.0)]
    flows = [{"ts": 100.0, "duration": 2.0, "label": "Malicious", "detailedlabel": "AttackInTrain"}]
    write_synthetic_pcap(train_pcap, pkts)
    write_synthetic_zeek_log(train_zeek, flows)

    evaluator = RealDatasetEvaluator(
        dataset_root=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        pcap_dir=pcap_dir,
        zeek_dir=zeek_dir,
    )

    with pytest.raises(DataLeakageError):
        evaluator.run_evaluation(
            captures_override={
                "ctu-idseval-6-benign-user-traffic-1": {"pcap": train_pcap, "zeek": train_zeek},
                "ctu-idseval-6-malicious-malware-1": {"pcap": train_pcap, "zeek": train_zeek},
            }
        )


def test_data_leakage_safeguard_training_test_disjointness():
    """Verify training capture cannot appear in test capture list."""
    evaluator = RealDatasetEvaluator(output_dir="/tmp")
    with pytest.raises(DataLeakageError):
        # Force training capture into test list
        evaluator.run_evaluation(
            captures_override={
                "ctu-idseval-6-benign-user-traffic-1": {"pcap": "/tmp/a.pcap", "zeek": "/tmp/a.log"},
            },
            selected_captures=["ctu-idseval-6-benign-user-traffic-1"],
        )


# =========================================================================
# F. METRICS CALCULATION TESTS
# =========================================================================

def test_metrics_calculation_known_fixture():
    """Verify precision, recall, F1, FPR, FNR, and accuracy on known confusion matrix."""
    y_true = [1, 1, 1, 1, 0, 0, 0, 0]
    y_pred = [1, 1, 1, 0, 0, 0, 1, 0]  # TP=3, FN=1, TN=3, FP=1
    cm = calculate_confusion_matrix(y_true, y_pred)

    assert cm["true_positives"] == 3
    assert cm["false_negatives"] == 1
    assert cm["true_negatives"] == 3
    assert cm["false_positives"] == 1

    metrics = calculate_classification_metrics(cm)
    assert metrics["precision"] == 0.75
    assert metrics["recall"] == 0.75
    assert metrics["f1_score"] == 0.75
    assert metrics["false_positive_rate"] == 0.25
    assert metrics["false_negative_rate"] == 0.25
    assert metrics["accuracy"] == 0.75


# =========================================================================
# G. END-TO-END SMOKE TEST & REPRODUCIBILITY
# =========================================================================

def test_smoke_test_end_to_end_reproducibility(tmp_path):
    """Verify end-to-end smoke test executes and produces deterministic results."""
    out1 = str(tmp_path / "out1")
    out2 = str(tmp_path / "out2")

    rep1 = run_smoke_test(output_dir=out1)
    rep2 = run_smoke_test(output_dir=out2)

    # Check identical metrics across deterministic runs
    m1 = rep1["test_summary"]["overall_metrics"]
    m2 = rep2["test_summary"]["overall_metrics"]

    assert m1["total_windows"] == m2["total_windows"]
    assert m1["malicious_windows"] == m2["malicious_windows"]
    assert m1["benign_windows"] == m2["benign_windows"]
    assert m1["true_positives"] == m2["true_positives"]
    assert m1["false_positives"] == m2["false_positives"]


# =========================================================================
# H. SECURITY INVARIANTS
# =========================================================================

def test_security_invariants_preserved():
    """Verify firewall and auto-block remain strictly disabled during evaluation."""
    assert Config.FIREWALL_SETTINGS["enabled"] is False
    assert Config.FIREWALL_SETTINGS["auto_block"] is False
    assert os.environ.get("NETSENTINEL_FIREWALL_ENABLED", "false").lower() in ("false", "0", "")
    assert os.environ.get("NETSENTINEL_AUTO_BLOCK", "false").lower() in ("false", "0", "")


# =========================================================================
# I. IMPORT ISOLATION & SIDE-EFFECT FREEDOM REGRESSION TESTS
# =========================================================================

def test_offline_evaluation_import_isolation_subprocess():
    """Verify importing evaluation submodules does NOT import app or start live workers.

    Uses an isolated Python subprocess so pytest collection state cannot mask
    leaked imports.
    """
    import subprocess
    import sys

    script = (
        "import sys\n"
        "sys.path.insert(0, 'backend')\n"
        "from evaluation import pcap_reader, zeek_parser, window_builder, real_dataset\n"
        "from evaluation import RealDatasetEvaluator, TrafficWindowBuilder\n"
        "assert 'app' not in sys.modules, f'app leaked into sys.modules: {sys.modules.get(\"app\")}'\n"
        "assert 'evaluation.benchmarks' not in sys.modules, 'benchmarks leaked into sys.modules'\n"
        "assert 'evaluation.runner' not in sys.modules, 'runner leaked into sys.modules'\n"
        "print('ISOLATION_CONFIRMED')\n"
    )

    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, f"Subprocess failed with stderr: {proc.stderr}"
    assert "ISOLATION_CONFIRMED" in proc.stdout

    # Verify no ambient workers or live log messages were emitted
    combined_output = proc.stdout + proc.stderr
    assert "AF_PACKET" not in combined_output
    assert "ML Anomaly Detector worker started" not in combined_output
    assert "FirewallManager initialized" not in combined_output
    assert "HostDetectionManager background worker started" not in combined_output
    assert "Host process baseline established" not in combined_output
    assert "FIM: Restored" not in combined_output


def test_real_dataset_cli_help_subprocess():
    """Verify executing real_dataset.py --help does NOT initialize live backend components."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "backend/evaluation/real_dataset.py", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    assert "NetSentinel Phase 15.5: Real-World Dataset ML Evaluation" in proc.stdout

    combined_output = proc.stdout + proc.stderr
    assert "AF_PACKET" not in combined_output
    assert "ML Anomaly Detector worker started" not in combined_output
    assert "FirewallManager initialized" not in combined_output
    assert "HostDetectionManager" not in combined_output
    assert "Host process baseline established" not in combined_output


def test_public_evaluation_api_exports_accessible():
    """Verify that all public package exports from evaluation/__init__.py remain accessible."""
    import evaluation
    from evaluation import (
        BenchmarkSuite,
        BenchmarkResult,
        EvaluationRunner,
        RealDatasetEvaluator,
        TrafficWindowBuilder,
        MLEvaluator,
    )

    assert BenchmarkSuite is not None
    assert BenchmarkResult is not None
    assert EvaluationRunner is not None
    assert RealDatasetEvaluator is not None
    assert TrafficWindowBuilder is not None
    assert MLEvaluator is not None
