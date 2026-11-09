"""Standalone Kaggle Evaluation Script for NetSentinel Isolation Forest (CTU-IDSEVAL-6).

Designed to be executed directly in Kaggle Notebooks or offline Linux environments.
Evaluates NetSentinel's single final Isolation Forest model using the canonical 13 network traffic features.

Enforces strict data leakage safeguards:
- Baseline training only on clean BENIGN windows from 'benign-user-traffic-1'.
- Evaluates on held-out malware and portscan captures.
- Excludes background-only and unlabeled intervals from binary classification metrics.
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
from sklearn.metrics import average_precision_score, roc_auc_score

try:
    from ml.feature_extractor import FEATURE_NAMES
    from ml.model import IsolationForestModel, ModelStatus
    from ml.detector import filter_baseline_outliers
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


def evaluate_windows(
    model: IsolationForestModel,
    windows: List[WindowEvaluationRecord],
    threshold: float,
) -> Dict[str, Any]:
    """Score windows using trained model and compute performance metrics."""
    eligible = [w for w in windows if w.is_eligible_for_metrics]
    if not eligible:
        return {
            "total_windows": len(windows),
            "eligible_windows": 0,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "tp": 0, "tn": 0, "fp": 0, "fn": 0,
            "roc_auc": 0.0,
            "pr_auc": 0.0,
            "benign_mean_score": 0.0,
            "malicious_mean_score": 0.0,
            "score_separation_margin": 0.0,
            "inference_time_ms_per_window": 0.0,
            "attack_categories": {},
        }

    b_scores: List[float] = []
    m_scores: List[float] = []
    y_true: List[int] = []
    y_scores: List[float] = []
    tp = tn = fp = fn = 0

    category_stats: Dict[str, Dict[str, Any]] = {}

    t_infer_start = time.perf_counter()
    for w in eligible:
        is_anom, raw_s, norm_s = model.predict(w.feature_vector)
        pred_label = 1 if norm_s > threshold else 0

        y_scores.append(norm_s)
        if w.ground_truth == WindowGroundTruth.MALICIOUS:
            y_true.append(1)
            m_scores.append(norm_s)
            if pred_label == 1:
                tp += 1
            else:
                fn += 1

            # Track attack categories
            cat = w.detailed_labels[0] if w.detailed_labels else "UnknownMalicious"
            if cat not in category_stats:
                category_stats[cat] = {"total": 0, "detected": 0, "scores": []}
            category_stats[cat]["total"] += 1
            if pred_label == 1:
                category_stats[cat]["detected"] += 1
            category_stats[cat]["scores"].append(norm_s)

        elif w.ground_truth == WindowGroundTruth.BENIGN:
            y_true.append(0)
            b_scores.append(norm_s)
            if pred_label == 1:
                fp += 1
            else:
                tn += 1

    t_infer_end = time.perf_counter()
    infer_ms_per_window = round(((t_infer_end - t_infer_start) / len(eligible)) * 1000.0, 4) if eligible else 0.0

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

    # AUC metrics
    pr_auc = 0.0
    roc_auc = 0.0
    if len(set(y_true)) > 1:
        try:
            pr_auc = round(float(average_precision_score(y_true, y_scores)), 4)
            roc_auc = round(float(roc_auc_score(y_true, y_scores)), 4)
        except Exception:
            pass

    # Summarize attack categories
    attack_cat_summary: Dict[str, Dict[str, Any]] = {}
    for cat, data in category_stats.items():
        tot = data["total"]
        det = data["detected"]
        rate = round(det / tot, 4) if tot > 0 else 0.0
        avg_score = round(float(np.mean(data["scores"])), 4) if data["scores"] else 0.0
        attack_cat_summary[cat] = {
            "total_windows": tot,
            "detected_windows": det,
            "detection_rate": rate,
            "mean_score": avg_score,
        }

    return {
        "total_windows": len(windows),
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
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "benign_mean_score": round(b_mean, 4),
        "malicious_mean_score": round(m_mean, 4),
        "score_separation_margin": sep,
        "inference_time_ms_per_window": infer_ms_per_window,
        "attack_categories": attack_cat_summary,
    }


def run_kaggle_evaluation(
    dataset_root: str,
    output_dir: str,
    threshold: float = 0.50,
    n_estimators: int = 100,
    contamination: Any = "auto",
    max_samples: Any = "auto",
    baseline_windows: int = 512,
    baseline_filter: str = "none",
    max_windows: Optional[int] = None,
    captures_filter: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Execute evaluation of the single production Isolation Forest on CTU-IDSEVAL-6."""
    t_start = time.time()
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 80)
    print("NetSentinel CTU-IDSEVAL-6 Evaluation: Canonical 13-Feature Isolation Forest")
    print("=" * 80)
    print(f"Dataset Root       : {dataset_root}")
    print(f"Output Directory   : {output_dir}")
    print(f"Feature Schema     : Canonical 13 Features ({len(FEATURE_NAMES)} features)")
    print(f"Baseline Size      : {baseline_windows} windows ({baseline_windows * 5.0:.1f}s collection)")
    print(f"Baseline Filter    : {baseline_filter}")
    print(f"Hyperparameters    : n_estimators={n_estimators}, max_samples={max_samples}, contamination={contamination}")
    print(f"Anomaly Threshold  : {threshold:.2f}")
    print("=" * 80)

    # 1. Discover Captures
    captures = discover_ctu_captures(dataset_root)
    training_tag = next((tag for tag in captures if TRAINING_CAPTURE_PATTERN in tag), None)
    if not training_tag:
        raise ValueError(f"Training capture matching '{TRAINING_CAPTURE_PATTERN}' not found in {dataset_root}.")

    # 2. Explicit Held-Out Test Capture Selection & Validation
    target_patterns = captures_filter if captures_filter else DEFAULT_TEST_PATTERNS
    test_tags: List[str] = []
    missing_patterns: List[str] = []

    for pattern in target_patterns:
        matched = [tag for tag in captures if pattern in tag and tag != training_tag]
        if matched:
            test_tags.extend(matched)
        else:
            missing_patterns.append(pattern)

    # De-duplicate while preserving discovery order
    seen: set = set()
    test_tags = [t for t in test_tags if not (t in seen or seen.add(t))]

    # Exclude unexpected captures discovered in dataset directory
    unexpected_tags = [
        tag for tag in captures
        if tag != training_tag and not any(pat in tag for pat in target_patterns)
    ]
    if unexpected_tags:
        print(f"[Notice] Excluding unexpected/non-target capture(s) from evaluation: {', '.join(unexpected_tags)}")

    if missing_patterns:
        print(f"[Warning] Expected test capture pattern(s) not found in dataset directory: {', '.join(missing_patterns)}")

    if not test_tags:
        raise ValueError(
            f"No valid held-out test captures found matching patterns {target_patterns} in {dataset_root}."
        )

    print(f"Training Baseline Capture : {training_tag}")
    print(f"Held-Out Test Captures    : {', '.join(test_tags)}")

    # 3. Extract 5-second windows for Training Baseline (Production Consistency)
    print(f"\n[1/3] Processing Baseline Training Capture: {training_tag}...")
    builder = TrafficWindowBuilder(window_duration=5.0)
    train_pkts = PcapReader(captures[training_tag]["pcap"]).iter_packets()
    train_flows = ZeekLogParser(captures[training_tag]["zeek"]).parse_flows()
    train_windows, train_sum = builder.process_capture(
        capture_name=training_tag,
        packet_records=train_pkts,
        zeek_flows=train_flows,
        max_windows=max_windows,
    )

    clean_train_windows = [w for w in train_windows if w.ground_truth == WindowGroundTruth.BENIGN]
    if not clean_train_windows:
        raise ValueError(f"No clean BENIGN windows found in training capture '{training_tag}'.")

    # Sample exactly matching the production baseline collection procedure
    selected_train_windows = clean_train_windows[:baseline_windows]
    print(f"  - Available clean BENIGN windows : {len(clean_train_windows)}")
    print(f"  - Production baseline sample size : {len(selected_train_windows)} windows (target: {baseline_windows})")

    raw_X_train = [w.feature_vector for w in selected_train_windows]

    # Apply baseline filtering strategy ('none' by default matching approved production configuration)
    if baseline_filter == "iqr":
        X_train = filter_baseline_outliers(raw_X_train, min_samples=min(5, len(raw_X_train) // 2))
        print(f"  - Clean baseline samples for IF  : {len(X_train)} windows (after IQR outlier filtering)")
    else:
        X_train = raw_X_train
        print(f"  - Clean baseline samples for IF  : {len(X_train)} windows (no outlier filtering, production default)")

    # 4. Fit Single Isolation Forest Model
    print(f"\n[2/3] Fitting Unsupervised Isolation Forest Model ({n_estimators} trees)...")
    t_train_start = time.perf_counter()
    model = IsolationForestModel(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination=contamination,
        random_state=42,
        min_samples=min(512, len(X_train)),
    )
    model.train(X_train)
    t_train_end = time.perf_counter()
    training_time_sec = round(t_train_end - t_train_start, 4)

    if model.status != ModelStatus.READY:
        raise RuntimeError(f"Isolation Forest model training failed: {model.last_error}")
    print(f"  - Isolation Forest READY on {len(X_train)} baseline windows (train time: {training_time_sec:.3f}s).")

    # 5. Process Held-Out Test Captures and Run Inference
    print("\n[3/3] Evaluating Held-Out Test Captures...")
    all_test_windows: List[WindowEvaluationRecord] = []
    per_capture_results: Dict[str, Dict[str, Any]] = {}

    for t_tag in test_tags:
        print(f"\n  Evaluating {t_tag}...")
        t_pkts = PcapReader(captures[t_tag]["pcap"]).iter_packets()
        t_flows = ZeekLogParser(captures[t_tag]["zeek"]).parse_flows()
        windows, _ = builder.process_capture(
            capture_name=t_tag,
            packet_records=t_pkts,
            zeek_flows=t_flows,
            max_windows=max_windows,
        )
        all_test_windows.extend(windows)

        res = evaluate_windows(model, windows, threshold=threshold)
        per_capture_results[t_tag] = res
        print(f"    Eligible Windows: {res['eligible_windows']} | Malicious: {res['malicious_windows']} | Benign: {res['benign_windows']}")
        print(f"    Confusion Matrix: TP={res['tp']} | TN={res['tn']} | FP={res['fp']} | FN={res['fn']}")
        print(f"    Metrics         : Acc={res['accuracy']:.4f} | Prec={res['precision']:.4f} | Rec={res['recall']:.4f} | F1={res['f1_score']:.4f} | FPR={res['false_positive_rate']:.4f}")

    # Overall Aggregation across all test windows
    overall_results = evaluate_windows(model, all_test_windows, threshold=threshold)

    # Print Final Summary Table
    print("\n" + "=" * 80)
    print("FINAL EVALUATION RESULTS (CTU-IDSEVAL-6)")
    print("=" * 80)
    print(f"Model Architecture         : Single Isolation Forest (Unsupervised)")
    print(f"Feature Count              : 13 Canonical Features")
    print(f"Baseline Training Windows  : {len(X_train)} (target: {baseline_windows})")
    print(f"Training Time              : {training_time_sec:.3f} seconds")
    print(f"Prediction Latency         : {overall_results['inference_time_ms_per_window']:.4f} ms / window")
    print(f"Threshold                  : {threshold:.2f}")
    print("-" * 80)
    print(f"Accuracy                   : {overall_results['accuracy'] * 100:.2f}%")
    print(f"Precision                  : {overall_results['precision'] * 100:.2f}%")
    print(f"Recall                     : {overall_results['recall'] * 100:.2f}%")
    print(f"F1-Score                   : {overall_results['f1_score'] * 100:.2f}%")
    print(f"False Positive Rate (FPR)  : {overall_results['false_positive_rate'] * 100:.2f}%")
    print(f"False Negative Rate (FNR)  : {overall_results['false_negative_rate'] * 100:.2f}%")
    print(f"PR-AUC (Average Precision) : {overall_results['pr_auc']:.4f}")
    print(f"ROC-AUC                    : {overall_results['roc_auc']:.4f}")
    print(f"Score Separation Margin    : {overall_results['score_separation_margin']:+.4f} (Malicious - Benign)")
    print(f"Confusion Matrix           : TP={overall_results['tp']} | TN={overall_results['tn']} | FP={overall_results['fp']} | FN={overall_results['fn']}")
    print("=" * 80)

    if overall_results["attack_categories"]:
        print("\nAttack Category Breakdown:")
        for cat, c_data in overall_results["attack_categories"].items():
            print(f"  - {cat:<25}: Detection Rate = {c_data['detection_rate'] * 100:5.1f}% ({c_data['detected_windows']}/{c_data['total_windows']}) | Mean Score = {c_data['mean_score']:.4f}")

    elapsed_total = round(time.time() - t_start, 2)

    # Export Artifacts
    report = {
        "evaluation_timestamp": time.time(),
        "evaluation_timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "execution_time_seconds": elapsed_total,
        "dataset_root": dataset_root,
        "feature_count": len(FEATURE_NAMES),
        "features": list(FEATURE_NAMES),
        "model_parameters": {
            "n_estimators": n_estimators,
            "max_samples": max_samples,
            "contamination": contamination,
            "threshold": threshold,
            "baseline_windows_target": baseline_windows,
            "baseline_windows_used": len(X_train),
            "baseline_filter": baseline_filter,
        },
        "training_time_seconds": training_time_sec,
        "training_baseline_capture": training_tag,
        "test_captures": test_tags,
        "missing_expected_captures": missing_patterns,
        "overall_metrics": overall_results,
        "per_capture_metrics": per_capture_results,
    }

    json_path = os.path.join(output_dir, "kaggle_isolation_forest_evaluation.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[Artifact] JSON Report saved to : {json_path}")

    csv_path = os.path.join(output_dir, "kaggle_isolation_forest_evaluation.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "Capture", "TotalWindows", "EligibleWindows", "Accuracy", "Precision",
            "Recall", "F1_Score", "FPR", "FNR", "PR_AUC", "ROC_AUC",
            "ScoreSeparation", "TP", "TN", "FP", "FN", "InfLatencyMs"
        ])
        w.writerow([
            "OVERALL",
            overall_results["total_windows"],
            overall_results["eligible_windows"],
            overall_results["accuracy"],
            overall_results["precision"],
            overall_results["recall"],
            overall_results["f1_score"],
            overall_results["false_positive_rate"],
            overall_results["false_negative_rate"],
            overall_results["pr_auc"],
            overall_results["roc_auc"],
            overall_results["score_separation_margin"],
            overall_results["tp"],
            overall_results["tn"],
            overall_results["fp"],
            overall_results["fn"],
            overall_results["inference_time_ms_per_window"],
        ])
        for cap, c_res in per_capture_results.items():
            w.writerow([
                cap,
                c_res["total_windows"],
                c_res["eligible_windows"],
                c_res["accuracy"],
                c_res["precision"],
                c_res["recall"],
                c_res["f1_score"],
                c_res["false_positive_rate"],
                c_res["false_negative_rate"],
                c_res["pr_auc"],
                c_res["roc_auc"],
                c_res["score_separation_margin"],
                c_res["tp"],
                c_res["tn"],
                c_res["fp"],
                c_res["fn"],
                c_res["inference_time_ms_per_window"],
            ])
    print(f"[Artifact] CSV Results saved to : {csv_path}")

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
        default="./kaggle_output_production_512",
        help="Directory to save evaluation reports (default: ./kaggle_output_production_512)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.50,
        help="Anomaly score threshold (default: 0.50)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of Isolation Forest trees (default: 100)",
    )
    parser.add_argument(
        "--contamination",
        type=str,
        default="auto",
        help="Contamination parameter ('auto' or float, default: 'auto')",
    )
    parser.add_argument(
        "--max-samples",
        type=str,
        default="auto",
        help="Max samples per tree ('auto' or int, default: 'auto')",
    )
    parser.add_argument(
        "--max-windows",
        type=int,
        default=None,
        help="Optional limit on windows per capture for fast evaluation",
    )
    parser.add_argument(
        "--baseline-windows",
        type=int,
        default=512,
        help="Number of normal traffic windows used for baseline training (default: 512, matching approved production configuration)",
    )
    parser.add_argument(
        "--baseline-filter",
        type=str,
        default="none",
        choices=["none", "iqr"],
        help="Baseline outlier filter (default: 'none', matching approved production configuration)",
    )
    parser.add_argument(
        "--captures",
        type=str,
        default=None,
        help="Optional comma-separated list of test captures (e.g. malware-1,malware-2)",
    )

    args = parser.parse_args()
    caps = [c.strip() for c in args.captures.split(",")] if args.captures else None

    contam_val: Any = "auto"
    if args.contamination != "auto":
        try:
            contam_val = float(args.contamination)
        except ValueError:
            contam_val = "auto"

    max_samp_val: Any = "auto"
    if args.max_samples != "auto":
        try:
            max_samp_val = int(args.max_samples)
        except ValueError:
            max_samp_val = "auto"

    run_kaggle_evaluation(
        dataset_root=args.dataset_root,
        output_dir=args.output_dir,
        threshold=args.threshold,
        n_estimators=args.n_estimators,
        contamination=contam_val,
        max_samples=max_samp_val,
        baseline_windows=args.baseline_windows,
        baseline_filter=args.baseline_filter,
        max_windows=args.max_windows,
        captures_filter=caps,
    )


if __name__ == "__main__":
    main()
