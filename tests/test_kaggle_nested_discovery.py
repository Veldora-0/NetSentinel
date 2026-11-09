"""Deterministic tests for nested Kaggle dataset directory discovery.

Tests support for Kaggle mounted directory structure:
  - pcap/pcap/*.pcap
  - zeek/zeek/*.conn-labeled.log
  - labels/labels/*.labels.config
And verifies strict pairing, counterpart validation, duplicate rejection, and end-to-end evaluation.
"""

import json
import os
import shutil
import tempfile
from typing import List

import pytest

from evaluation.pcap_reader import write_synthetic_pcap
from evaluation.zeek_parser import write_synthetic_zeek_log
from evaluation.data_generator import generate_synthetic_raw_frame
from kaggle_evaluation.evaluate_ctu_idseval6 import (
    discover_ctu_captures,
    run_kaggle_evaluation,
    _extract_capture_id,
)

ALL_SIX_CAPTURES = [
    "ctu-idseval-6-benign-user-traffic-1",
    "ctu-idseval-6-malicious-portscan-1",
    "ctu-idseval-6-malicious-portscan-2",
    "ctu-idseval-6-malicious-portscan-3",
    "ctu-idseval-6-malicious-malware-1",
    "ctu-idseval-6-malicious-malware-2",
]


def _create_nested_kaggle_layout(root_dir: str, capture_names: List[str], use_gzip: bool = False):
    """Create exact nested Kaggle CTU-IDSEVAL-6 filesystem fixture."""
    pcap_dir = os.path.join(root_dir, "pcap", "pcap")
    zeek_dir = os.path.join(root_dir, "zeek", "zeek")
    labels_dir = os.path.join(root_dir, "labels", "labels")

    os.makedirs(pcap_dir, exist_ok=True)
    os.makedirs(zeek_dir, exist_ok=True)
    os.makedirs(labels_dir, exist_ok=True)

    pcap_ext = ".pcap.gz" if use_gzip else ".pcap"
    zeek_ext = ".conn-labeled.log.gz" if use_gzip else ".conn-labeled.log"

    for cap in capture_names:
        p_path = os.path.join(pcap_dir, f"{cap}{pcap_ext}")
        z_path = os.path.join(zeek_dir, f"{cap}{zeek_ext}")
        l_path = os.path.join(labels_dir, f"{cap}.labels.config")

        with open(p_path, "wb") as f:
            f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
        with open(z_path, "w", encoding="utf-8") as f:
            f.write("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tlabel\tdetailed-label\n")
        with open(l_path, "w", encoding="utf-8") as f:
            f.write(f"capture = {cap}\nlabel = normal\n")

    # Add unrelated files to verify they are ignored
    with open(os.path.join(root_dir, "dataset_overview.txt"), "w") as f:
        f.write("Dataset description text")
    with open(os.path.join(labels_dir, "metadata.json"), "w") as f:
        f.write('{"dataset": "ctu-idseval-6"}')


def test_extract_capture_id_normalized():
    """Verify capture ID extraction strips known extensions and rejects invalid names."""
    assert _extract_capture_id("ctu-idseval-6-benign-user-traffic-1.pcap") == "ctu-idseval-6-benign-user-traffic-1"
    assert _extract_capture_id("ctu-idseval-6-benign-user-traffic-1.pcap.gz") == "ctu-idseval-6-benign-user-traffic-1"
    assert _extract_capture_id("ctu-idseval-6-benign-user-traffic-1.conn-labeled.log") == "ctu-idseval-6-benign-user-traffic-1"
    assert _extract_capture_id("ctu-idseval-6-benign-user-traffic-1.conn-labeled.log.gz") == "ctu-idseval-6-benign-user-traffic-1"
    assert _extract_capture_id("ctu-idseval-6-benign-user-traffic-1.conn.log") == "ctu-idseval-6-benign-user-traffic-1"
    assert _extract_capture_id("ctu-idseval-6-benign-user-traffic-1.conn.log.gz") == "ctu-idseval-6-benign-user-traffic-1"

    # Reject non-capture files and hidden files
    assert _extract_capture_id("capture.labels.config") is None
    assert _extract_capture_id("readme.txt") is None
    assert _extract_capture_id(".hidden.pcap") is None
    assert _extract_capture_id("._capture.conn-labeled.log") is None


def test_nested_kaggle_directory_layout_all_six_captures_paired():
    """Verify all six CTU-IDSEVAL-6 captures in nested Kaggle structure are discovered and paired."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_nested_kaggle_layout(tmpdir, ALL_SIX_CAPTURES, use_gzip=False)

        captures = discover_ctu_captures(tmpdir)
        assert len(captures) == 6
        assert sorted(captures.keys()) == sorted(ALL_SIX_CAPTURES)

        for cap in ALL_SIX_CAPTURES:
            pcap_path = captures[cap]["pcap"]
            zeek_path = captures[cap]["zeek"]

            assert os.path.exists(pcap_path)
            assert os.path.exists(zeek_path)
            assert pcap_path.endswith(f"{cap}.pcap")
            assert zeek_path.endswith(f"{cap}.conn-labeled.log")
            # Verify paths are inside nested subdirectories
            assert os.path.join("pcap", "pcap") in pcap_path
            assert os.path.join("zeek", "zeek") in zeek_path


def test_nested_kaggle_gzip_captures_paired():
    """Verify nested .pcap.gz and .conn-labeled.log.gz files are properly paired."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_nested_kaggle_layout(tmpdir, ALL_SIX_CAPTURES, use_gzip=True)

        captures = discover_ctu_captures(tmpdir)
        assert len(captures) == 6
        for cap in ALL_SIX_CAPTURES:
            assert captures[cap]["pcap"].endswith(f"{cap}.pcap.gz")
            assert captures[cap]["zeek"].endswith(f"{cap}.conn-labeled.log.gz")


def test_nested_kaggle_missing_pcap_rejected():
    """Verify missing PCAP counterpart for a Zeek log raises descriptive ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_nested_kaggle_layout(tmpdir, ALL_SIX_CAPTURES)

        # Delete one PCAP file
        missing_cap = "ctu-idseval-6-malicious-portscan-2"
        pcap_file = os.path.join(tmpdir, "pcap", "pcap", f"{missing_cap}.pcap")
        os.remove(pcap_file)

        with pytest.raises(ValueError) as excinfo:
            discover_ctu_captures(tmpdir)

        msg = str(excinfo.value)
        assert "without matching PCAP capture" in msg
        assert missing_cap in msg


def test_nested_kaggle_missing_zeek_rejected():
    """Verify missing Zeek counterpart for a PCAP file raises descriptive ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_nested_kaggle_layout(tmpdir, ALL_SIX_CAPTURES)

        # Delete one Zeek file
        missing_cap = "ctu-idseval-6-benign-user-traffic-1"
        zeek_file = os.path.join(tmpdir, "zeek", "zeek", f"{missing_cap}.conn-labeled.log")
        os.remove(zeek_file)

        with pytest.raises(ValueError) as excinfo:
            discover_ctu_captures(tmpdir)

        msg = str(excinfo.value)
        assert "without matching Zeek log" in msg
        assert missing_cap in msg


def test_nested_kaggle_duplicate_ambiguous_pcap_rejected():
    """Verify duplicate ambiguous PCAP files mapping to same capture ID are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_nested_kaggle_layout(tmpdir, ALL_SIX_CAPTURES)

        # Create duplicate PCAP in a parallel nested directory
        dup_dir = os.path.join(tmpdir, "pcap", "backup")
        os.makedirs(dup_dir, exist_ok=True)
        dup_pcap = os.path.join(dup_dir, "ctu-idseval-6-benign-user-traffic-1.pcap")
        shutil.copy2(os.path.join(tmpdir, "pcap", "pcap", "ctu-idseval-6-benign-user-traffic-1.pcap"), dup_pcap)

        with pytest.raises(ValueError) as excinfo:
            discover_ctu_captures(tmpdir)

        msg = str(excinfo.value)
        assert "Ambiguous dataset matches found" in msg
        assert "Multiple PCAP files map to capture ID 'ctu-idseval-6-benign-user-traffic-1'" in msg


def test_nested_kaggle_duplicate_ambiguous_zeek_rejected():
    """Verify duplicate ambiguous Zeek log files mapping to same capture ID are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _create_nested_kaggle_layout(tmpdir, ALL_SIX_CAPTURES)

        # Create duplicate Zeek log in an archive directory
        archive_dir = os.path.join(tmpdir, "zeek", "archive")
        os.makedirs(archive_dir, exist_ok=True)
        dup_zeek = os.path.join(archive_dir, "ctu-idseval-6-malicious-malware-1.conn-labeled.log")
        shutil.copy2(os.path.join(tmpdir, "zeek", "zeek", "ctu-idseval-6-malicious-malware-1.conn-labeled.log"), dup_zeek)

        with pytest.raises(ValueError) as excinfo:
            discover_ctu_captures(tmpdir)

        msg = str(excinfo.value)
        assert "Ambiguous dataset matches found" in msg
        assert "Multiple Zeek log files map to capture ID 'ctu-idseval-6-malicious-malware-1'" in msg


def test_nested_kaggle_empty_or_nonexistent_directory():
    """Verify empty or nonexistent directory raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        discover_ctu_captures("/nonexistent/dataset/directory/path")

    with tempfile.TemporaryDirectory() as empty_dir:
        with pytest.raises(FileNotFoundError, match="No valid PCAP or Zeek captures discovered"):
            discover_ctu_captures(empty_dir)


def test_nested_kaggle_unrelated_files_ignored():
    """Verify that unrelated files like labels, readme, and configs do not match as captures."""
    with tempfile.TemporaryDirectory() as tmpdir:
        labels_dir = os.path.join(tmpdir, "labels", "labels")
        os.makedirs(labels_dir, exist_ok=True)
        with open(os.path.join(labels_dir, "malware-1.labels.config"), "w") as f:
            f.write("config=true")
        with open(os.path.join(tmpdir, "notes.txt"), "w") as f:
            f.write("notes")

        with pytest.raises(FileNotFoundError, match="No valid PCAP or Zeek captures discovered"):
            discover_ctu_captures(tmpdir)


def test_end_to_end_kaggle_evaluation_on_nested_structure():
    """Verify run_kaggle_evaluation executes cleanly on exact nested Kaggle directory structure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_dir = os.path.join(tmpdir, "pcap", "pcap")
        zeek_dir = os.path.join(tmpdir, "zeek", "zeek")
        labels_dir = os.path.join(tmpdir, "labels", "labels")
        out_dir = os.path.join(tmpdir, "output")
        os.makedirs(pcap_dir, exist_ok=True)
        os.makedirs(zeek_dir, exist_ok=True)
        os.makedirs(labels_dir, exist_ok=True)

        base_t = 1523450000.0

        # 1. Training capture: ctu-idseval-6-benign-user-traffic-1
        train_pcap = os.path.join(pcap_dir, "ctu-idseval-6-benign-user-traffic-1.pcap")
        train_zeek = os.path.join(zeek_dir, "ctu-idseval-6-benign-user-traffic-1.conn-labeled.log")
        train_pkts = []
        train_flows = []
        for w in range(8):
            w_start = base_t + (w * 5.0)
            train_flows.append({"ts": w_start, "duration": 4.5, "label": "Benign", "detailedlabel": "NormalBrowsing"})
            for p in range(10):
                train_pkts.append((generate_synthetic_raw_frame(dst_port=80), w_start + (p * 0.45)))
        write_synthetic_pcap(train_pcap, train_pkts)
        write_synthetic_zeek_log(train_zeek, train_flows)

        # 2. Test capture: ctu-idseval-6-malicious-malware-1
        mal_pcap = os.path.join(pcap_dir, "ctu-idseval-6-malicious-malware-1.pcap")
        mal_zeek = os.path.join(zeek_dir, "ctu-idseval-6-malicious-malware-1.conn-labeled.log")
        mal_pkts = []
        mal_flows = []
        m_base_t = 1523460000.0
        for w in range(4):
            w_start = m_base_t + (w * 5.0)
            mal_flows.append({"ts": w_start, "duration": 4.0, "label": "Benign", "detailedlabel": "-"})
            for p in range(8):
                mal_pkts.append((generate_synthetic_raw_frame(dst_port=443), w_start + (p * 0.5)))
        for w in range(4, 8):
            w_start = m_base_t + (w * 5.0)
            mal_flows.append({"ts": w_start, "duration": 4.0, "label": "Malicious", "detailedlabel": "C2Beacon"})
            for p in range(50):
                mal_pkts.append((generate_synthetic_raw_frame(dst_port=6667), w_start + (p * 0.08)))
        write_synthetic_pcap(mal_pcap, mal_pkts)
        write_synthetic_zeek_log(mal_zeek, mal_flows)

        # Add dummy label files in labels/labels
        with open(os.path.join(labels_dir, "ctu-idseval-6-benign-user-traffic-1.labels.config"), "w") as f:
            f.write("label=benign\n")
        with open(os.path.join(labels_dir, "ctu-idseval-6-malicious-malware-1.labels.config"), "w") as f:
            f.write("label=malware\n")

        # Run Kaggle evaluation on nested dataset root
        report = run_kaggle_evaluation(
            dataset_root=tmpdir,
            output_dir=out_dir,
            threshold=0.50,
            n_estimators=100,
            contamination="auto",
            baseline_windows=8,
            baseline_filter="none",
            captures_filter=["malware-1"],
        )

        assert report is not None
        assert "overall_metrics" in report
        assert report["overall_metrics"]["eligible_windows"] == 8
        assert "ctu-idseval-6-malicious-malware-1" in report["per_capture_metrics"]

        # Confirm artifacts written
        json_report = os.path.join(out_dir, "kaggle_isolation_forest_evaluation.json")
        csv_report = os.path.join(out_dir, "kaggle_isolation_forest_evaluation.csv")
        assert os.path.exists(json_report)
        assert os.path.exists(csv_report)

        with open(json_report, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["feature_count"] == 13
            assert data["model_parameters"]["baseline_filter"] == "none"
