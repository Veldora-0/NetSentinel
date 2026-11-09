"""Self-contained verification test for the Kaggle Evaluation Package.

Simulates a local CTU-IDSEVAL-6 structure, runs evaluate_ctu_idseval6.py,
and verifies comparative artifact generation.
"""

import json
import os
import shutil
import sys
import tempfile

# Ensure paths
CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from evaluation.pcap_reader import write_synthetic_pcap
from evaluation.zeek_parser import write_synthetic_zeek_log
from evaluation.data_generator import generate_synthetic_raw_frame
from kaggle_evaluation.evaluate_ctu_idseval6 import run_kaggle_comparative_evaluation


def run_kaggle_smoke_test():
    """Create synthetic CTU fixture, execute Kaggle comparative evaluation, and check outputs."""
    temp_dir = tempfile.mkdtemp(prefix="test_kaggle_pkg_")
    out_dir = os.path.join(temp_dir, "output")

    try:
        pcap_dir = os.path.join(temp_dir, "pcap")
        zeek_dir = os.path.join(temp_dir, "zeek")
        os.makedirs(pcap_dir, exist_ok=True)
        os.makedirs(zeek_dir, exist_ok=True)

        # 1. Training Capture: ctu-idseval-6-benign-user-traffic-1
        train_pcap = os.path.join(pcap_dir, "ctu-idseval-6-benign-user-traffic-1.pcap")
        train_zeek = os.path.join(zeek_dir, "ctu-idseval-6-benign-user-traffic-1.conn-labeled.log")
        train_pkts = []
        train_flows = []
        base_t = 1523450000.0

        for w in range(12):
            w_start = base_t + (w * 5.0)
            train_flows.append({"ts": w_start, "duration": 4.5, "label": "Benign", "detailedlabel": "NormalBrowsing"})
            for p in range(10):
                train_pkts.append((generate_synthetic_raw_frame(dst_port=80), w_start + (p * 0.45)))

        write_synthetic_pcap(train_pcap, train_pkts)
        write_synthetic_zeek_log(train_zeek, train_flows)

        # 2. Test Capture: ctu-idseval-6-malicious-malware-1
        mal1_pcap = os.path.join(pcap_dir, "ctu-idseval-6-malicious-malware-1.pcap")
        mal1_zeek = os.path.join(zeek_dir, "ctu-idseval-6-malicious-malware-1.conn-labeled.log")
        mal1_pkts = []
        mal1_flows = []
        m_base_t = 1523460000.0

        # 4 benign windows, 4 malicious windows
        for w in range(4):
            w_start = m_base_t + (w * 5.0)
            mal1_flows.append({"ts": w_start, "duration": 4.0, "label": "Benign", "detailedlabel": "-"})
            for p in range(8):
                mal1_pkts.append((generate_synthetic_raw_frame(dst_port=443), w_start + (p * 0.5)))

        for w in range(4, 8):
            w_start = m_base_t + (w * 5.0)
            mal1_flows.append({"ts": w_start, "duration": 4.0, "label": "Malicious", "detailedlabel": "C2Beacon"})
            for p in range(50):
                mal1_pkts.append((generate_synthetic_raw_frame(dst_port=6667), w_start + (p * 0.08)))

        write_synthetic_pcap(mal1_pcap, mal1_pkts)
        write_synthetic_zeek_log(mal1_zeek, mal1_flows)

        # Run Kaggle comparative evaluation
        report = run_kaggle_comparative_evaluation(
            dataset_root=temp_dir,
            output_dir=out_dir,
            improved_threshold=0.52,
        )

        assert "comparison" in report
        assert "overall_baseline" in report["comparison"]
        assert "overall_optimized" in report["comparison"]

        json_out = os.path.join(out_dir, "kaggle_isolation_forest_comparison.json")
        csv_out = os.path.join(out_dir, "kaggle_isolation_forest_comparison.csv")
        assert os.path.exists(json_out), f"Missing JSON report at {json_out}"
        assert os.path.exists(csv_out), f"Missing CSV report at {csv_out}"

        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["comparison"]["overall_baseline"]["eligible_windows"] > 0
            assert data["comparison"]["overall_optimized"]["eligible_windows"] > 0

        print("\n[SUCCESS] Kaggle evaluation package smoke test passed completely.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_kaggle_smoke_test()
