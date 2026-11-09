"""Standalone Kaggle Evaluation Script for NetSentinel Isolation Forest (CTU-IDSEVAL-6).

Designed to be executed directly in Kaggle Notebooks or offline Linux environments.
Evaluates and compares:
1. Baseline Production Isolation Forest (100 trees, auto contamination, T=0.50)
2. Optimized Isolation Forest (150 trees, max_samples 512, contamination 0.05, calibrated T=0.52)

Enforces strict data leakage safeguards:
- Training only on clean BENIGN windows from 'benign-user-traffic-1'.
- Evaluates on held-out malware and portscan captures.
- Excludes background-only and unlabeled intervals from binary metrics.
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Automatically detect and add NetSentinel backend root to path
CURRENT_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np

try:
    from ml.feature_extractor import FEATURE_NAMES, FEATURE_NAMES_V1, FEATURE_NAMES_V2, get_feature_names
    from ml.model import IsolationForestModel, ModelStatus
    from evaluation.pcap_reader import PcapReader
    from evaluation.zeek_parser import ZeekLogParser
    from evaluation.window_builder import (
        TrafficWindowBuilder,
        WindowGroundTruth,
        WindowEvaluationRecord,
    )
except ImportError as err:
    sys.stderr.write(
        f"Error importing NetSentinel modules: {err}\n"
        "Ensure the script is executed within the NetSentinel repository or that PYTHONPATH includes 'backend/'.\n"
    )
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel.kaggle")

TRAINING_CAPTURE_PATTERN = "benign-user-traffic-1"
DEFAULT_TEST_PATTERNS = [
    "malware-1",
    "malware-2",
    "portscan-1",
    "portscan-2",
    "portscan-3",
]


def discover_ctu_captures(dataset_root: str, pcap_dir: Optional[str] = None, zeek_dir: Optional[str] = None) -> Dict[str, Dict[str, str]]:
    """Locate matching PCAP and Zeek files in the provided dataset directory structure."""
    p_dir = pcap_dir or os.path.join(dataset_root, "pcap")
    z_dir = zeek_dir or os.path.join(dataset_root, "zeek")

    if not os.path.exists(p_dir):
        # Check if files reside directly in dataset_root
        if any(f.endswith(".pcap") or f.endswith(".pcap.gz") for f in os.listdir(dataset_root)):
            p_dir = dataset_root
            z_dir = dataset_root
        else:
            raise FileNotFoundError(f"PCAP directory not found at {p_dir} or {dataset_root}")

    pcap_files = [f for f in os.listdir(p_dir) if f.endswith(".pcap") or f.endswith(".pcap.gz")]
    zeek_files = [f for f in os.listdir(z_dir) if ".conn-labeled.log" in f or "conn.log" in f]

    captures: Dict[str, Dict[str, str]] = {}
    for pfile in pcap_files:
        base = pfile.replace(".pcap.gz", "").replace(".pcap", "")
        matched_zeek = None
        for zfile in zeek_files:
            if base in zfile:
                matched_zeek = os.path.join(z_dir, zfile)
                break
        if matched_zeek:
            captures[base] = {
                "pcap": os.path.join(p_dir, pfile),
                "zeek": matched_zeek,
            }

    return captures


def evaluate_model_on_windows(
    model: IsolationForestModel,
    windows: List[WindowEvaluationRecord],
    threshold: float,
) -> Dict[str, Any]:
    """Score windows using trained model and compute performance metrics."""
    eligible = [w for w in windows if w.is_eligible_for_metrics]
    if not eligible:
        return {
            "eligible_windows": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "tp": 0, "tn": 0, "fp": 0, "fn": 0,
            "score_separation_margin": 0.0,
        }

    b_scores: List[float] = []
    m_scores: List[float] = []
    tp = tn = fp = fn = 0

    for w in eligible:
        is_anom, raw_s, norm_s = model.predict(w.feature_vector)
        pred_label = 1 if norm_s > threshold else 0

        if w.ground_truth == WindowGroundTruth.MALICIOUS:
            m_scores.append(norm_s)
            if pred_label == 1:
                tp += 1
            else:
                fn += 1
        elif w.ground_truth == WindowGroundTruth.BENIGN:
            b_scores.append(norm_s)
            if pred_label == 1:
                fp += 1
            else:
                tn += 1

    total = len(eligible)
    acc = round(float((tp + tn) / total), 4) if total > 0 else 0.0
    prec = round(float(tp / (tp + fp)), 4) if (tp + fp) > 0 else 0.0
    rec = round(float(tp / (tp + fn)), 4) if (tp + fn) > 0 else 0.0
    f1 = round(float(2 * prec * rec / (prec + rec)), 4) if (prec + rec) > 0 else 0.0
    fpr = round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0
    fnr = round(float(fn / (fn + tp)), 4) if (fn + tp) > 0 else 0.0

    b_mean = float(np.mean(b_scores)) if b_scores else 0.0
    m_mean = float(np.mean(m_scores)) if m_scores else 0.0
    sep = round(m_mean - b_mean, 4)

    return {
        "eligible_windows": total,
        "malicious_windows": len(m_scores),
        "benign_windows": len(b_scores),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "benign_mean_score": round(b_mean, 4),
        "malicious_mean_score": round(m_mean, 4),
        "score_separation_margin": sep,
    }


def run_kaggle_comparative_evaluation(
    dataset_root: str,
    output_dir: str,
    max_windows: Optional[int] = None,
    captures_filter: Optional[List[str]] = None,
    improved_threshold: float = 0.52,
) -> Dict[str, Any]:
    """Execute side-by-side comparison between Baseline and Optimized Isolation Forest."""
    t_start = time.time()
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 80)
    print("NetSentinel CTU-IDSEVAL-6 Kaggle Evaluation: Original vs. Optimized Isolation Forest")
    print("=" * 80)
    print(f"Dataset Root       : {dataset_root}")
    print(f"Output Directory   : {output_dir}")
    print(f"Improved Threshold : {improved_threshold}")
    print("=" * 80)

    # 1. Discover Captures
    captures = discover_ctu_captures(dataset_root)
    training_tag = next((tag for tag in captures if TRAINING_CAPTURE_PATTERN in tag), None)
    if not training_tag:
        raise ValueError(f"Training capture matching '{TRAINING_CAPTURE_PATTERN}' not found in {dataset_root}.")

    test_tags = [tag for tag in captures if tag != training_tag]
    if captures_filter:
        test_tags = [tag for tag in test_tags if any(f in tag for f in captures_filter)]

    print(f"Training Baseline Capture : {training_tag}")
    print(f"Held-Out Test Captures    : {', '.join(test_tags)}")

    # 2. Extract 5-second windows for Training Baseline
    print(f"\n[1/3] Processing Baseline Training Capture: {training_tag}...")
    builder_v1 = TrafficWindowBuilder(window_duration=5.0, schema_version="v1")
    train_pkts = PcapReader(captures[training_tag]["pcap"]).iter_packets()
    train_flows = ZeekLogParser(captures[training_tag]["zeek"]).parse_flows()
    train_windows_v1, train_sum = builder_v1.process_capture(
        capture_name=training_tag,
        packet_records=train_pkts,
        zeek_flows=train_flows,
        max_windows=max_windows,
    )

    clean_train_v1 = [w for w in train_windows_v1 if w.ground_truth == WindowGroundTruth.BENIGN]
    print(f"  - Clean BENIGN baseline windows: {len(clean_train_v1)}")
    X_train_v1 = [w.feature_vector for w in clean_train_v1]

    # 3. Train Both Models on the exact same clean baseline
    print("\n[2/3] Training Models on Baseline Normal Traffic...")

    # Model A: Baseline Production (Original)
    print("  Fitting Model A: Baseline Production Isolation Forest (100 trees, auto contamination)...")
    model_baseline = IsolationForestModel(n_estimators=100, contamination="auto", random_state=42, schema_version="v1")
    model_baseline.train(X_train_v1)

    # Model B: Optimized Production Isolation Forest
    print(f"  Fitting Model B: Optimized Isolation Forest (150 trees, max_samples 512, contamination 0.05, threshold={improved_threshold})...")
    from sklearn.ensemble import IsolationForest
    raw_opt = IsolationForest(
        n_estimators=150,
        max_samples=min(512, len(X_train_v1)),
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    raw_opt.fit(np.asarray(X_train_v1, dtype=np.float64))

    # Wrap in model container for inference
    model_optimized = IsolationForestModel(n_estimators=150, contamination=0.05, random_state=42, schema_version="v1")
    model_optimized.model = raw_opt
    model_optimized.status = ModelStatus.READY

    # 4. Process Test Captures and Run Comparative Inference
    print("\n[3/3] Evaluating Held-Out Test Captures...")
    all_test_windows_v1: List[WindowEvaluationRecord] = []
    per_capture_comparison: Dict[str, Dict[str, Any]] = {}

    for t_tag in test_tags:
        print(f"\n  Evaluating {t_tag}...")
        t_pkts = PcapReader(captures[t_tag]["pcap"]).iter_packets()
        t_flows = ZeekLogParser(captures[t_tag]["zeek"]).parse_flows()
        windows_v1, _ = builder_v1.process_capture(
            capture_name=t_tag,
            packet_records=t_pkts,
            zeek_flows=t_flows,
            max_windows=max_windows,
        )
        all_test_windows_v1.extend(windows_v1)

        res_base = evaluate_model_on_windows(model_baseline, windows_v1, threshold=0.50)
        res_opt = evaluate_model_on_windows(model_optimized, windows_v1, threshold=improved_threshold)

        per_capture_comparison[t_tag] = {
            "baseline": res_base,
            "optimized": res_opt,
        }
        print(f"    Baseline (T=0.50) : Acc={res_base['accuracy']:.4f} | F1={res_base['f1_score']:.4f} | FPR={res_base['false_positive_rate']:.4f} | Rec={res_base['recall']:.4f}")
        print(f"    Optimized(T={improved_threshold:.2f}): Acc={res_opt['accuracy']:.4f} | F1={res_opt['f1_score']:.4f} | FPR={res_opt['false_positive_rate']:.4f} | Rec={res_opt['recall']:.4f}")

    # Overall Aggregation
    overall_base = evaluate_model_on_windows(model_baseline, all_test_windows_v1, threshold=0.50)
    overall_opt = evaluate_model_on_windows(model_optimized, all_test_windows_v1, threshold=improved_threshold)

    # Print Final Summary Comparison
    print("\n" + "=" * 80)
    print("FINAL COMPARATIVE EVALUATION RESULTS (CTU-IDSEVAL-6)")
    print("=" * 80)
    print(f"{'Metric':<25} | {'Original Baseline (T=0.50)':<25} | {'Optimized IF (T=' + str(improved_threshold) + ')':<25} | {'Delta':<10}")
    print("-" * 88)

    metrics_to_show = [
        ("Accuracy", "accuracy", "%"),
        ("Precision", "precision", "%"),
        ("Recall", "recall", "%"),
        ("F1-Score", "f1_score", "%"),
        ("False Positive Rate", "false_positive_rate", "%"),
        ("False Negative Rate", "false_negative_rate", "%"),
        ("Score Separation", "score_separation_margin", ""),
    ]

    for label, key, unit in metrics_to_show:
        v_base = overall_base[key]
        v_opt = overall_opt[key]
        diff = v_opt - v_base
        if unit == "%":
            str_base = f"{v_base * 100:.2f}%"
            str_opt = f"{v_opt * 100:.2f}%"
            str_diff = f"{diff * 100:+.2f}%"
        else:
            str_base = f"{v_base:.4f}"
            str_opt = f"{v_opt:.4f}"
            str_diff = f"{diff:+.4f}"
        print(f"{label:<25} | {str_base:<25} | {str_opt:<25} | {str_diff:<10}")

    print("=" * 88)
    print(f"Confusion Matrix Baseline : TP={overall_base['tp']} | TN={overall_base['tn']} | FP={overall_base['fp']} | FN={overall_base['fn']}")
    print(f"Confusion Matrix Optimized: TP={overall_opt['tp']} | TN={overall_opt['tn']} | FP={overall_opt['fp']} | FN={overall_opt['fn']}")
    print("=" * 88)

    # Export Artifacts
    report = {
        "evaluation_timestamp": time.time(),
        "evaluation_timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_root": dataset_root,
        "training_capture": training_tag,
        "test_captures": test_tags,
        "comparison": {
            "overall_baseline": overall_base,
            "overall_optimized": overall_opt,
            "per_capture": per_capture_comparison,
        },
    }

    json_path = os.path.join(output_dir, "kaggle_isolation_forest_comparison.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[Artifact] JSON Report saved to : {json_path}")

    csv_path = os.path.join(output_dir, "kaggle_isolation_forest_comparison.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Model", "Capture", "Accuracy", "Precision", "Recall", "F1_Score", "FPR", "FNR", "TP", "TN", "FP", "FN"])
        w.writerow(["Baseline", "OVERALL", overall_base["accuracy"], overall_base["precision"], overall_base["recall"], overall_base["f1_score"], overall_base["false_positive_rate"], overall_base["false_negative_rate"], overall_base["tp"], overall_base["tn"], overall_base["fp"], overall_base["fn"]])
        w.writerow(["Optimized", "OVERALL", overall_opt["accuracy"], overall_opt["precision"], overall_opt["recall"], overall_opt["f1_score"], overall_opt["false_positive_rate"], overall_opt["false_negative_rate"], overall_opt["tp"], overall_opt["tn"], overall_opt["fp"], overall_opt["fn"]])
        for cap, data in per_capture_comparison.items():
            cb = data["baseline"]
            co = data["optimized"]
            w.writerow(["Baseline", cap, cb["accuracy"], cb["precision"], cb["recall"], cb["f1_score"], cb["false_positive_rate"], cb["false_negative_rate"], cb["tp"], cb["tn"], cb["fp"], cb["fn"]])
            w.writerow(["Optimized", cap, co["accuracy"], co["precision"], co["recall"], co["f1_score"], co["false_positive_rate"], co["false_negative_rate"], co["tp"], co["tn"], co["fp"], co["fn"]])
    print(f"[Artifact] CSV Comparison saved to : {csv_path}")

    return report


def main():
    parser = argparse.ArgumentParser(description="NetSentinel CTU-IDSEVAL-6 Kaggle Evaluation Runner")
    parser.add_argument(
        "--dataset-root",
        type=str,
        default="/kaggle/input/ctu-idseval-6",
        help="Path to CTU-IDSEVAL-6 dataset (default: /kaggle/input/ctu-idseval-6)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./kaggle_output",
        help="Directory to save comparison reports (default: ./kaggle_output)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.52,
        help="Decision threshold for optimized Isolation Forest (default: 0.52)",
    )
    parser.add_argument(
        "--max-windows",
        type=int,
        default=None,
        help="Optional limit on windows per capture for fast evaluation",
    )
    parser.add_argument(
        "--captures",
        type=str,
        default=None,
        help="Optional comma-separated list of test captures (e.g. malware-1,malware-2)",
    )

    args = parser.parse_args()
    caps = [c.strip() for c in args.captures.split(",")] if args.captures else None

    run_kaggle_comparative_evaluation(
        dataset_root=args.dataset_root,
        output_dir=args.output_dir,
        max_windows=args.max_windows,
        captures_filter=caps,
        improved_threshold=args.threshold,
    )


if __name__ == "__main__":
    main()
