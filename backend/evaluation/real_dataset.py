"""NetSentinel Real-World Dataset ML Evaluation Engine (Phase 15.5).

Evaluates NetSentinel's existing unsupervised Isolation Forest anomaly detection pipeline
against real-world labelled network captures (CTU-IDSEVAL-6).
Maintains strict data leakage safeguards, uses production 5-second windows and 13 canonical features,
and produces comprehensive per-capture and aggregate metrics.
"""

import argparse
import csv
from dataclasses import dataclass, asdict
import json
import logging
import math
import os
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure backend root is in python path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np

from ml.feature_extractor import FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus

try:
    from .pcap_reader import PcapReader, write_synthetic_pcap
    from .zeek_parser import ZeekLogParser, ZeekFlowRecord, write_synthetic_zeek_log
    from .window_builder import (
        TrafficWindowBuilder,
        WindowEvaluationRecord,
        WindowGroundTruth,
        CaptureProcessingSummary,
    )
    from .metrics import calculate_confusion_matrix, calculate_classification_metrics
except ImportError:
    from evaluation.pcap_reader import PcapReader, write_synthetic_pcap
    from evaluation.zeek_parser import ZeekLogParser, ZeekFlowRecord, write_synthetic_zeek_log
    from evaluation.window_builder import (
        TrafficWindowBuilder,
        WindowEvaluationRecord,
        WindowGroundTruth,
        CaptureProcessingSummary,
    )
    from evaluation.metrics import calculate_confusion_matrix, calculate_classification_metrics

logger = logging.getLogger("netsentinel.evaluation.real_dataset")

# Canonical CTU-IDSEVAL-6 Capture Identifiers
TRAINING_CAPTURE_PATTERN = "benign-user-traffic-1"
TEST_CAPTURE_PATTERNS = [
    "malware-1",
    "malware-2",
    "portscan-1",
    "portscan-2",
    "portscan-3",
]


class DataLeakageError(RuntimeError):
    """Raised when data leakage between training and testing partitions is detected."""
    pass


@dataclass
class WindowPredictionRecord:
    """Detailed prediction record for a single evaluated window."""
    capture_name: str
    window_id: int
    start_time: float
    end_time: float
    packet_count: int
    ground_truth: str
    is_mixed: bool
    raw_decision_score: float
    normalized_anomaly_score: float
    predicted_anomaly_at_0_50: int
    is_correct_at_0_50: Optional[bool]
    is_eligible: bool
    detailed_labels: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CaptureEvaluationMetrics:
    """Evaluation metrics for a specific network traffic capture."""
    capture_name: str
    total_windows: int
    benign_windows: int
    malicious_windows: int
    background_only_windows: int
    unlabeled_windows: int
    mixed_windows: int
    eligible_windows: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    classification_accuracy: float
    score_distribution_benign: Dict[str, Any]
    score_distribution_malicious: Dict[str, Any]
    score_separation_margin: Optional[float]
    processing_summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RealDatasetEvaluator:
    """Evaluates the existing NetSentinel ML pipeline on external PCAP and Zeek datasets."""

    def __init__(
        self,
        dataset_root: Optional[str] = None,
        output_dir: Optional[str] = None,
        pcap_dir: Optional[str] = None,
        zeek_dir: Optional[str] = None,
        window_duration: float = 5.0,
        include_empty_windows: bool = False,
    ):
        self.dataset_root = dataset_root or ""
        self.output_dir = output_dir or os.path.join(PROJECT_ROOT, "reports")
        self.pcap_dir = pcap_dir or (os.path.join(self.dataset_root, "pcap") if self.dataset_root else "")
        self.zeek_dir = zeek_dir or (os.path.join(self.dataset_root, "zeek") if self.dataset_root else "")
        self.window_duration = float(window_duration)
        self.include_empty_windows = bool(include_empty_windows)

        os.makedirs(self.output_dir, exist_ok=True)
        self.window_builder = TrafficWindowBuilder(
            window_duration=self.window_duration,
            include_empty_windows=self.include_empty_windows,
        )

    def discover_captures(self) -> Dict[str, Dict[str, str]]:
        """Discover available PCAP and Zeek log files.

        Returns:
            Dict mapping capture tag (e.g. 'benign-user-traffic-1', 'malware-1')
            to {'pcap': filepath, 'zeek': filepath}.
        """
        captures: Dict[str, Dict[str, str]] = {}
        if not os.path.exists(self.pcap_dir) or not os.path.exists(self.zeek_dir):
            return captures

        pcap_files = [f for f in os.listdir(self.pcap_dir) if f.endswith(".pcap") or f.endswith(".pcap.gz")]
        zeek_files = [f for f in os.listdir(self.zeek_dir) if ".conn-labeled.log" in f or "conn.log" in f]

        for pfile in pcap_files:
            p_path = os.path.join(self.pcap_dir, pfile)
            base_name = pfile.replace(".pcap.gz", "").replace(".pcap", "")

            # Match corresponding Zeek file
            matched_zeek: Optional[str] = None
            for zfile in zeek_files:
                if base_name in zfile:
                    matched_zeek = os.path.join(self.zeek_dir, zfile)
                    break

            if matched_zeek:
                captures[base_name] = {"pcap": p_path, "zeek": matched_zeek}

        return captures

    def run_evaluation(
        self,
        captures_override: Optional[Dict[str, Dict[str, str]]] = None,
        max_windows_per_capture: Optional[int] = None,
        selected_captures: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute the real-world dataset evaluation protocol.

        1. Discover / validate training capture and test captures.
        2. Process training capture and verify zero data leakage.
        3. Train production Isolation Forest model on clean BENIGN windows.
        4. Process held-out test captures and run inference at T=0.50.
        5. Compute per-capture and overall aggregate metrics.
        6. Export JSON and CSV evaluation artifacts.
        """
        all_captures = captures_override if captures_override is not None else self.discover_captures()
        if not all_captures:
            raise FileNotFoundError(
                f"No matching PCAP and Zeek captures discovered under {self.dataset_root}. "
                "Ensure dataset contains pcap/ and zeek/ directories."
            )

        # 1. Identify Training Capture
        training_tag: Optional[str] = None
        for tag in all_captures:
            if TRAINING_CAPTURE_PATTERN in tag:
                training_tag = tag
                break

        if not training_tag:
            raise ValueError(
                f"Required training capture '{TRAINING_CAPTURE_PATTERN}' not found in dataset. "
                f"Available captures: {list(all_captures.keys())}"
            )

        # 2. Identify Test Captures (strictly disjoint from training)
        if selected_captures and any(TRAINING_CAPTURE_PATTERN in sel or (training_tag and training_tag in sel) for sel in selected_captures):
            raise DataLeakageError(
                f"Critical Data Leakage: Training capture matching '{TRAINING_CAPTURE_PATTERN}' "
                "cannot be selected as a test capture."
            )

        test_tags: List[str] = []
        for tag in all_captures:
            if tag == training_tag:
                continue
            if selected_captures:
                if any(sel in tag for sel in selected_captures):
                    test_tags.append(tag)
            else:
                test_tags.append(tag)

        if not test_tags:
            raise ValueError("No held-out test captures available for evaluation.")

        # Data Leakage Invariant: Training and test sets must be completely disjoint
        if training_tag in test_tags:
            raise DataLeakageError(f"Critical Data Leakage: Training capture '{training_tag}' present in test captures!")

        print("=" * 70)
        print("NetSentinel Phase 15.5: Real-World Dataset ML Evaluation")
        print("=" * 70)
        print(f"Training Baseline Capture : {training_tag}")
        print(f"Held-Out Test Captures    : {', '.join(test_tags)}")
        print(f"Window Duration           : {self.window_duration}s")
        print(f"Production Threshold      : 0.50 (normalized score)")
        print(f"Feature Vector Order      : {len(FEATURE_NAMES)} canonical features")
        print("=" * 70)

        # 3. Process Training Capture
        print(f"\n[1/3] Processing Training Capture: {training_tag}...")
        train_pcap = all_captures[training_tag]["pcap"]
        train_zeek = all_captures[training_tag]["zeek"]

        train_flows = ZeekLogParser(train_zeek).parse_flows()
        train_reader = PcapReader(train_pcap).iter_packets()
        train_windows, train_summary = self.window_builder.process_capture(
            capture_name=training_tag,
            packet_records=train_reader,
            zeek_flows=train_flows,
            max_windows=max_windows_per_capture,
        )

        # Data Leakage Invariant: Training capture must not contain Malicious windows
        malicious_in_train = [w for w in train_windows if w.ground_truth == WindowGroundTruth.MALICIOUS]
        if malicious_in_train:
            raise DataLeakageError(
                f"Critical Data Leakage: Found {len(malicious_in_train)} MALICIOUS windows "
                f"in training capture '{training_tag}'! Baseline training aborted."
            )

        # Filter strictly BENIGN windows for baseline training
        clean_train_windows = [w for w in train_windows if w.ground_truth == WindowGroundTruth.BENIGN]
        if len(clean_train_windows) < 5:
            raise ValueError(
                f"Insufficient clean BENIGN training windows in {training_tag} "
                f"(found {len(clean_train_windows)}, required >= 5 for Isolation Forest)."
            )

        X_train = [w.feature_vector for w in clean_train_windows]
        print(f"  - Parsed records: {train_summary.parsed_successfully}/{train_summary.total_capture_records}")
        print(f"  - Generated windows: {len(train_windows)} total ({len(clean_train_windows)} clean BENIGN used for training)")

        # 4. Fit Isolation Forest with exact production parameters
        print("\n[2/3] Fitting Unsupervised Isolation Forest Model...")
        model = IsolationForestModel(
            n_estimators=100,
            contamination="auto",
            random_state=42,
            min_samples=max(5, len(X_train) // 2),
        )
        trained_ok = model.train(X_train)
        if not trained_ok or model.status != ModelStatus.READY:
            raise RuntimeError(f"Isolation Forest model training failed: {model.last_error}")
        print(f"  - Isolation Forest READY on {len(X_train)} normal traffic windows.")

        # 5. Process Held-Out Test Captures and Run Inference
        print("\n[3/3] Evaluating Held-Out Test Captures...")
        per_capture_results: Dict[str, CaptureEvaluationMetrics] = {}
        all_test_predictions: List[WindowPredictionRecord] = []

        for t_tag in test_tags:
            print(f"\n  Evaluating Capture: {t_tag}...")
            t_pcap = all_captures[t_tag]["pcap"]
            t_zeek = all_captures[t_tag]["zeek"]

            t_flows = ZeekLogParser(t_zeek).parse_flows()
            t_reader = PcapReader(t_pcap).iter_packets()
            t_windows, t_summary = self.window_builder.process_capture(
                capture_name=t_tag,
                packet_records=t_reader,
                zeek_flows=t_flows,
                max_windows=max_windows_per_capture,
            )

            # Evaluate each window
            cap_preds: List[WindowPredictionRecord] = []
            for w in t_windows:
                is_anom, raw_s, norm_s = model.predict(w.feature_vector)
                pred_binary = 1 if norm_s > 0.50 else 0

                is_correct: Optional[bool] = None
                if w.is_eligible_for_metrics:
                    if w.ground_truth == WindowGroundTruth.MALICIOUS:
                        is_correct = bool(pred_binary == 1)
                    elif w.ground_truth == WindowGroundTruth.BENIGN:
                        is_correct = bool(pred_binary == 0)

                rec = WindowPredictionRecord(
                    capture_name=t_tag,
                    window_id=w.window_id,
                    start_time=w.start_time,
                    end_time=w.end_time,
                    packet_count=w.packet_count,
                    ground_truth=w.ground_truth.value,
                    is_mixed=w.is_mixed,
                    raw_decision_score=raw_s,
                    normalized_anomaly_score=norm_s,
                    predicted_anomaly_at_0_50=pred_binary,
                    is_correct_at_0_50=is_correct,
                    is_eligible=w.is_eligible_for_metrics,
                    detailed_labels=w.detailed_labels,
                )
                cap_preds.append(rec)
                all_test_predictions.append(rec)

            # Compute capture metrics
            metrics = self._compute_capture_metrics(t_tag, cap_preds, t_summary)
            per_capture_results[t_tag] = metrics

            print(f"    Windows: {metrics.total_windows} total | {metrics.malicious_windows} Malicious | {metrics.benign_windows} Benign | {metrics.background_only_windows} Background | {metrics.unlabeled_windows} Unlabeled")
            if metrics.eligible_windows > 0:
                print(f"    Confusion Matrix : TP={metrics.true_positives} | TN={metrics.true_negatives} | FP={metrics.false_positives} | FN={metrics.false_negatives}")
                print(f"    Classification   : Prec={metrics.precision:.4f} | Rec={metrics.recall:.4f} | F1={metrics.f1_score:.4f} | FPR={metrics.false_positive_rate:.4f} | FNR={metrics.false_negative_rate:.4f}")
            else:
                print("    Notice: No eligible BENIGN or MALICIOUS windows in this capture partition.")

        # 6. Compute Overall Aggregate Metrics
        overall_metrics = self._compute_overall_metrics(all_test_predictions)

        print("\n" + "=" * 70)
        print("OVERALL REAL-WORLD DATASET EVALUATION RESULTS (Aggregated Test Captures)")
        print("=" * 70)
        print(f"Total Evaluated Test Windows: {overall_metrics['total_windows']}")
        print(f"Eligible Windows (Benign + Malicious) : {overall_metrics['eligible_windows']}")
        print(f"  - Malicious Windows : {overall_metrics['malicious_windows']}")
        print(f"  - Benign Windows    : {overall_metrics['benign_windows']}")
        print(f"Excluded Windows:")
        print(f"  - Background-Only   : {overall_metrics['background_only_windows']}")
        print(f"  - Unlabeled         : {overall_metrics['unlabeled_windows']}")
        print(f"Mixed Windows (Benign + Malicious)    : {overall_metrics['mixed_windows']}")
        print(f"\nConfusion Matrix at Threshold 0.50:")
        print(f"  TP={overall_metrics['true_positives']} | TN={overall_metrics['true_negatives']} | FP={overall_metrics['false_positives']} | FN={overall_metrics['false_negatives']}")
        print(f"\nMetrics:")
        print(f"  Precision : {overall_metrics['precision']:.4f}")
        print(f"  Recall    : {overall_metrics['recall']:.4f}")
        print(f"  F1-Score  : {overall_metrics['f1_score']:.4f}")
        print(f"  FPR       : {overall_metrics['false_positive_rate']:.4f}")
        print(f"  FNR       : {overall_metrics['false_negative_rate']:.4f}")
        print(f"  Accuracy  : {overall_metrics['classification_accuracy']:.4f} (on labelled subset)")
        if overall_metrics["score_separation_margin"] is not None:
            print(f"  Score Separation Margin: +{overall_metrics['score_separation_margin']:.4f} (Malicious Mean - Benign Mean)")

        # 7. Compile Final Report Data Structure
        report_data = {
            "evaluation_phase": "Phase 15.5",
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": {
                "os": "Linux",
                "python_version": sys.version.split()[0],
                "platform": sys.platform,
            },
            "model_configuration": {
                "algorithm": "Isolation Forest (Unsupervised)",
                "n_estimators": 100,
                "contamination": "auto",
                "random_state": 42,
                "feature_count": len(FEATURE_NAMES),
                "feature_names": FEATURE_NAMES,
                "window_duration_seconds": self.window_duration,
                "production_anomaly_threshold": 0.50,
            },
            "training_summary": {
                "capture_name": training_tag,
                "total_windows_generated": train_summary.total_windows_generated,
                "clean_benign_windows_used": len(clean_train_windows),
                "data_leakage_safeguard_verified": True,
                "processing_summary": asdict(train_summary),
            },
            "test_summary": {
                "test_captures": test_tags,
                "overall_metrics": overall_metrics,
                "per_capture_metrics": {k: v.to_dict() for k, v in per_capture_results.items()},
            },
            "exclusions_and_quality": {
                "background_only_excluded": overall_metrics["background_only_windows"],
                "unlabeled_excluded": overall_metrics["unlabeled_windows"],
                "mixed_benign_malicious_recorded": overall_metrics["mixed_windows"],
            },
            "safety_invariants": {
                "firewall_enabled": False,
                "auto_block": False,
                "ambient_capabilities_invoked": False,
                "external_network_traffic": False,
            },
        }

        # 8. Serialize Output Artifacts
        self._export_artifacts(report_data, all_test_predictions)

        print("\n" + "=" * 70)
        print("Phase 15.5 Real-World Dataset Evaluation Complete.")
        print("=" * 70)

        return report_data

    def _compute_capture_metrics(
        self,
        capture_name: str,
        predictions: List[WindowPredictionRecord],
        summary: CaptureProcessingSummary,
    ) -> CaptureEvaluationMetrics:
        """Compute metrics for an individual capture."""
        total_w = len(predictions)
        benign_w = sum(1 for p in predictions if p.ground_truth == WindowGroundTruth.BENIGN.value)
        mal_w = sum(1 for p in predictions if p.ground_truth == WindowGroundTruth.MALICIOUS.value)
        bg_w = sum(1 for p in predictions if p.ground_truth == WindowGroundTruth.BACKGROUND_ONLY.value)
        unlab_w = sum(1 for p in predictions if p.ground_truth == WindowGroundTruth.UNLABELED.value)
        mixed_w = sum(1 for p in predictions if p.is_mixed)

        eligible = [p for p in predictions if p.is_eligible]
        tp = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.MALICIOUS.value and p.predicted_anomaly_at_0_50 == 1)
        fn = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.MALICIOUS.value and p.predicted_anomaly_at_0_50 == 0)
        fp = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.BENIGN.value and p.predicted_anomaly_at_0_50 == 1)
        tn = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.BENIGN.value and p.predicted_anomaly_at_0_50 == 0)

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        acc = float((tp + tn) / len(eligible)) if eligible else 0.0

        # Score distributions
        b_scores = [p.normalized_anomaly_score for p in eligible if p.ground_truth == WindowGroundTruth.BENIGN.value]
        m_scores = [p.normalized_anomaly_score for p in eligible if p.ground_truth == WindowGroundTruth.MALICIOUS.value]

        dist_b = self._compute_score_distribution(b_scores)
        dist_m = self._compute_score_distribution(m_scores)

        sep_margin: Optional[float] = None
        if dist_b.get("mean") is not None and dist_m.get("mean") is not None:
            sep_margin = round(dist_m["mean"] - dist_b["mean"], 4)

        return CaptureEvaluationMetrics(
            capture_name=capture_name,
            total_windows=total_w,
            benign_windows=benign_w,
            malicious_windows=mal_w,
            background_only_windows=bg_w,
            unlabeled_windows=unlab_w,
            mixed_windows=mixed_w,
            eligible_windows=len(eligible),
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            classification_accuracy=round(acc, 4),
            score_distribution_benign=dist_b,
            score_distribution_malicious=dist_m,
            score_separation_margin=sep_margin,
            processing_summary=asdict(summary),
        )

    def _compute_overall_metrics(self, all_predictions: List[WindowPredictionRecord]) -> Dict[str, Any]:
        """Compute aggregate metrics across all test captures."""
        total_w = len(all_predictions)
        benign_w = sum(1 for p in all_predictions if p.ground_truth == WindowGroundTruth.BENIGN.value)
        mal_w = sum(1 for p in all_predictions if p.ground_truth == WindowGroundTruth.MALICIOUS.value)
        bg_w = sum(1 for p in all_predictions if p.ground_truth == WindowGroundTruth.BACKGROUND_ONLY.value)
        unlab_w = sum(1 for p in all_predictions if p.ground_truth == WindowGroundTruth.UNLABELED.value)
        mixed_w = sum(1 for p in all_predictions if p.is_mixed)

        eligible = [p for p in all_predictions if p.is_eligible]
        tp = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.MALICIOUS.value and p.predicted_anomaly_at_0_50 == 1)
        fn = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.MALICIOUS.value and p.predicted_anomaly_at_0_50 == 0)
        fp = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.BENIGN.value and p.predicted_anomaly_at_0_50 == 1)
        tn = sum(1 for p in eligible if p.ground_truth == WindowGroundTruth.BENIGN.value and p.predicted_anomaly_at_0_50 == 0)

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        acc = float((tp + tn) / len(eligible)) if eligible else 0.0

        b_scores = [p.normalized_anomaly_score for p in eligible if p.ground_truth == WindowGroundTruth.BENIGN.value]
        m_scores = [p.normalized_anomaly_score for p in eligible if p.ground_truth == WindowGroundTruth.MALICIOUS.value]

        dist_b = self._compute_score_distribution(b_scores)
        dist_m = self._compute_score_distribution(m_scores)

        sep_margin: Optional[float] = None
        if dist_b.get("mean") is not None and dist_m.get("mean") is not None:
            sep_margin = round(dist_m["mean"] - dist_b["mean"], 4)

        return {
            "total_windows": total_w,
            "benign_windows": benign_w,
            "malicious_windows": mal_w,
            "background_only_windows": bg_w,
            "unlabeled_windows": unlab_w,
            "mixed_windows": mixed_w,
            "eligible_windows": len(eligible),
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "classification_accuracy": round(acc, 4),
            "score_distribution_benign": dist_b,
            "score_distribution_malicious": dist_m,
            "score_separation_margin": sep_margin,
        }

    def _compute_score_distribution(self, scores: List[float]) -> Dict[str, Any]:
        """Compute statistical summary for score array."""
        if not scores:
            return {
                "count": 0,
                "mean": None,
                "median": None,
                "std": None,
                "min": None,
                "max": None,
            }
        arr = np.asarray(scores, dtype=np.float64)
        return {
            "count": len(arr),
            "mean": round(float(np.mean(arr)), 4),
            "median": round(float(np.median(arr)), 4),
            "std": round(float(np.std(arr)), 4),
            "min": round(float(np.min(arr)), 4),
            "max": round(float(np.max(arr)), 4),
        }

    def _export_artifacts(
        self,
        report_data: Dict[str, Any],
        predictions: List[WindowPredictionRecord],
    ) -> None:
        """Export JSON report and CSV prediction samples."""
        json_path = os.path.join(self.output_dir, "phase15_5_real_dataset_evaluation.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[Artifact] JSON Report saved to : {json_path}")

        csv_path = os.path.join(self.output_dir, "phase15_5_real_dataset_windows.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow([
                "CaptureName", "WindowId", "StartTime", "EndTime", "PacketCount",
                "GroundTruth", "IsMixed", "RawDecisionScore", "NormalizedAnomalyScore",
                "PredictedAnomalyAt0_50", "IsCorrect", "IsEligible", "DetailedLabels"
            ])
            for p in predictions:
                writer.writerow([
                    p.capture_name, p.window_id, p.start_time, p.end_time, p.packet_count,
                    p.ground_truth, p.is_mixed, p.raw_decision_score, p.normalized_anomaly_score,
                    p.predicted_anomaly_at_0_50, p.is_correct_at_0_50, p.is_eligible,
                    ";".join(p.detailed_labels),
                ])
        print(f"[Artifact] CSV Windows saved to : {csv_path}")


def run_smoke_test(output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Execute a self-contained synthetic smoke test simulating CTU-IDSEVAL-6 structure.

    Generates tiny temporary PCAP and Zeek files in a temporary directory, runs the full
    evaluation pipeline, and confirms that training, inference, and serialization succeed.
    """
    import tempfile
    import shutil
    try:
        from .data_generator import generate_synthetic_raw_frame
    except ImportError:
        from evaluation.data_generator import generate_synthetic_raw_frame

    temp_root = tempfile.mkdtemp(prefix="netsentinel_phase15_5_smoke_")
    out_dir = output_dir or os.path.join(temp_root, "output")

    try:
        pcap_dir = os.path.join(temp_root, "pcap")
        zeek_dir = os.path.join(temp_root, "zeek")
        os.makedirs(pcap_dir, exist_ok=True)
        os.makedirs(zeek_dir, exist_ok=True)

        # 1. Create Training Capture: ctu-idseval-6-benign-user-traffic-1
        train_pcap = os.path.join(pcap_dir, "ctu-idseval-6-benign-user-traffic-1.pcap")
        train_zeek = os.path.join(zeek_dir, "ctu-idseval-6-benign-user-traffic-1.conn-labeled.log")

        train_pkts = []
        train_flows = []
        base_t = 1523450000.0
        # 10 windows of benign traffic (each window has 10 packets)
        for w in range(10):
            w_start = base_t + (w * 5.0)
            train_flows.append({
                "ts": w_start + 0.1,
                "duration": 4.5,
                "label": "Benign",
                "detailedlabel": "NormalBrowsing",
            })
            for p in range(10):
                pkt_t = w_start + (p * 0.45)
                raw = generate_synthetic_raw_frame(src_port=50000 + p, dst_port=80)
                train_pkts.append((raw, pkt_t))

        write_synthetic_pcap(train_pcap, train_pkts)
        write_synthetic_zeek_log(train_zeek, train_flows)

        # 2. Create Test Capture 1: ctu-idseval-6-malicious-malware-1
        mal1_pcap = os.path.join(pcap_dir, "ctu-idseval-6-malicious-malware-1.pcap")
        mal1_zeek = os.path.join(zeek_dir, "ctu-idseval-6-malicious-malware-1.conn-labeled.log")

        mal1_pkts = []
        mal1_flows = []
        m_base_t = 1523460000.0
        # 4 Benign windows, 4 Malicious windows, 1 Background-only window
        for w in range(4):
            w_start = m_base_t + (w * 5.0)
            mal1_flows.append({"ts": w_start, "duration": 4.0, "label": "Benign", "detailedlabel": "-"})
            for p in range(8):
                mal1_pkts.append((generate_synthetic_raw_frame(dst_port=443), w_start + (p * 0.5)))

        for w in range(4, 8):
            w_start = m_base_t + (w * 5.0)
            mal1_flows.append({"ts": w_start, "duration": 4.0, "label": "Malicious", "detailedlabel": "MalwareC2"})
            for p in range(50):  # high packet count
                mal1_pkts.append((generate_synthetic_raw_frame(dst_port=6667), w_start + (p * 0.08)))

        # 1 Background window
        w_start = m_base_t + (8 * 5.0)
        mal1_flows.append({"ts": w_start, "duration": 4.0, "label": "Background", "detailedlabel": "-"})
        for p in range(5):
            mal1_pkts.append((generate_synthetic_raw_frame(dst_port=53), w_start + (p * 0.5)))

        # Add one truncated record to test parser robustness
        mal1_pkts.append((b"\x00\x01\x02\x03", m_base_t + 100.0))

        write_synthetic_pcap(mal1_pcap, mal1_pkts)
        write_synthetic_zeek_log(mal1_zeek, mal1_flows)

        # 3. Create Test Capture 2: ctu-idseval-6-malicious-portscan-1
        ps1_pcap = os.path.join(pcap_dir, "ctu-idseval-6-malicious-portscan-1.pcap")
        ps1_zeek = os.path.join(zeek_dir, "ctu-idseval-6-malicious-portscan-1.conn-labeled.log")

        ps1_pkts = []
        ps1_flows = []
        ps_base_t = 1523470000.0
        # 2 Malicious port scan windows
        for w in range(2):
            w_start = ps_base_t + (w * 5.0)
            ps1_flows.append({"ts": w_start, "duration": 4.0, "label": "Malicious", "detailedlabel": "PortScan"})
            for p in range(60):
                ps1_pkts.append((generate_synthetic_raw_frame(dst_port=1000 + p), w_start + (p * 0.06)))

        write_synthetic_pcap(ps1_pcap, ps1_pkts)
        write_synthetic_zeek_log(ps1_zeek, ps1_flows)

        # Run RealDatasetEvaluator
        evaluator = RealDatasetEvaluator(
            dataset_root=temp_root,
            output_dir=out_dir,
            pcap_dir=pcap_dir,
            zeek_dir=zeek_dir,
        )
        report = evaluator.run_evaluation()

        assert "test_summary" in report
        assert "overall_metrics" in report["test_summary"]
        assert report["test_summary"]["overall_metrics"]["malicious_windows"] > 0
        assert report["test_summary"]["overall_metrics"]["benign_windows"] > 0
        assert report["test_summary"]["overall_metrics"]["background_only_windows"] >= 1

        print("\n[Smoke Test PASSED] Synthetic CTU fixture evaluated successfully.")
        return report

    finally:
        # Clean up temporary test files
        shutil.rmtree(temp_root, ignore_errors=True)


def main():
    """CLI entrypoint for Phase 15.5 Real-World Dataset Evaluator."""
    parser = argparse.ArgumentParser(
        description="NetSentinel Phase 15.5: Real-World Dataset ML Evaluation (CTU-IDSEVAL-6)"
    )
    parser.add_argument(
        "--dataset-root",
        type=str,
        default=None,
        help="Path to root dataset directory containing pcap/ and zeek/ subdirectories",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to write output JSON and CSV artifacts (default: reports/ for dataset evaluations, temporary directory for --smoke-test)",
    )
    parser.add_argument(
        "--pcap-dir",
        type=str,
        default=None,
        help="Explicit path to directory containing .pcap files (overrides dataset-root/pcap)",
    )
    parser.add_argument(
        "--zeek-dir",
        type=str,
        default=None,
        help="Explicit path to directory containing .conn-labeled.log files (overrides dataset-root/zeek)",
    )
    parser.add_argument(
        "--captures",
        type=str,
        default=None,
        help="Optional comma-separated list of capture tags to evaluate (e.g. malware-1,portscan-1)",
    )
    parser.add_argument(
        "--max-windows",
        type=int,
        default=None,
        help="Optional limit on maximum windows per capture for quick smoke testing",
    )
    parser.add_argument(
        "--include-empty-windows",
        action="store_true",
        help="Generate empty windows for silent 5-second intervals (default: False)",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run self-contained synthetic fixture smoke test without requiring external dataset",
    )

    args = parser.parse_args()

    if args.smoke_test or not args.dataset_root:
        if args.smoke_test:
            print("Executing self-contained synthetic smoke test...")
            run_smoke_test(output_dir=args.output_dir)
            return
        else:
            print("No --dataset-root provided. Run with --smoke-test or specify --dataset-root <path>.")
            parser.print_help()
            sys.exit(1)

    selected = [c.strip() for c in args.captures.split(",")] if args.captures else None

    evaluator = RealDatasetEvaluator(
        dataset_root=args.dataset_root,
        output_dir=args.output_dir,
        pcap_dir=args.pcap_dir,
        zeek_dir=args.zeek_dir,
        include_empty_windows=args.include_empty_windows,
    )

    evaluator.run_evaluation(
        max_windows_per_capture=args.max_windows,
        selected_captures=selected,
    )


if __name__ == "__main__":
    main()
