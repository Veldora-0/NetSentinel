"""NetSentinel ML Baseline Scaling and Outlier Filtering Controlled Experiment.

Investigates the impact of baseline sample size (30, 128, 256, 512, 1000, 2250)
and outlier filtering (Existing 3.0x IQR vs No Filtering) on Isolation Forest
anomaly detection performance under strict architectural constraints:
- Exactly ONE Isolation Forest
- Original canonical 13 features in identical order
- Fixed: n_estimators=100, max_samples="auto", contamination="auto", random_state=42
- Fixed threshold: 0.50 (normalized score)
- 5.0-second aggregation windows

Outputs:
- JSON report: reports/baseline_experiments/baseline_experiment_results.json
- CSV table:   reports/baseline_experiments/baseline_comparison_table.csv
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Ensure backend directory is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.detector import filter_baseline_outliers
from ml.feature_extractor import FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus
from ml_experiments.data_loader import SyntheticTrafficGenerator, ValidationDataset

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel.baseline_experiment")

BASELINE_SIZES = [30, 128, 256, 512, 1000, 2250]


@dataclass
class TrialResult:
    baseline_target_size: int
    filtering_condition: str  # "With_IQR" or "No_Filtering"
    raw_samples_count: int
    used_samples_count: int
    dropped_samples_count: int
    dropped_ratio_pct: float
    effective_max_samples: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: float
    pr_auc: float
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    training_time_sec: float
    prediction_latency_ms: float
    benign_score_mean: float
    benign_score_std: float
    malicious_score_mean: float
    malicious_score_std: float


class BaselineScalingExperiment:
    """Executes controlled grid experiments across baseline sizes and filtering strategies."""

    def __init__(
        self,
        output_dir: Optional[str] = None,
        seed: int = 42,
        dataset_root: Optional[str] = None,
    ):
        self.output_dir = output_dir or os.path.join(PROJECT_ROOT, "reports", "baseline_experiments")
        self.seed = seed
        self.dataset_root = dataset_root
        self.generator = SyntheticTrafficGenerator(seed=seed)
        os.makedirs(self.output_dir, exist_ok=True)

    def load_dataset(self) -> Tuple[List[List[float]], np.ndarray, np.ndarray, List[str]]:
        """Load evaluation dataset.

        Uses real CTU-IDSEVAL-6 PCAP/Zeek if dataset_root provided and present,
        otherwise uses the verified multi-modal validation generator.
        """
        if self.dataset_root and os.path.isdir(self.dataset_root):
            logger.info("Ingesting real CTU-IDSEVAL-6 dataset from %s", self.dataset_root)
            return self._load_real_ctu_dataset(self.dataset_root)

        logger.info(
            "Generating independent multi-modal benchmark validation dataset (seed=%d)...",
            self.seed,
        )
        # Generate 2,250 baseline normal windows and 2,000 independent validation windows
        ds: ValidationDataset = self.generator.build_benchmark_dataset(
            train_samples=2250,
            val_normal_samples=1000,
            val_attack_samples=1000,
        )
        return ds.X_train_normal.tolist(), ds.X_val, ds.y_val, ds.val_labels

    def _load_real_ctu_dataset(
        self, dataset_root: str
    ) -> Tuple[List[List[float]], np.ndarray, np.ndarray, List[str]]:
        """Load and window real CTU-IDSEVAL-6 capture files."""
        from evaluation.pcap_reader import PcapReader
        from evaluation.window_builder import TrafficWindowBuilder, WindowGroundTruth
        from evaluation.zeek_parser import ZeekLogParser

        training_pattern = "benign-user-traffic-1"
        test_patterns = ["malware-1", "malware-2", "portscan-1", "portscan-2", "portscan-3"]

        # Discover captures
        captures: Dict[str, Dict[str, str]] = {}
        for root, _, files in os.walk(dataset_root):
            for f in files:
                tag = None
                for pat in [training_pattern] + test_patterns:
                    if pat in f:
                        tag = pat
                        break
                if not tag:
                    continue
                captures.setdefault(tag, {})
                full_path = os.path.join(root, f)
                if f.endswith((".pcap", ".pcapng", ".cap")):
                    captures[tag]["pcap"] = full_path
                elif "conn-labeled" in f or f.endswith((".log", ".tsv")):
                    captures[tag]["zeek"] = full_path

        if training_pattern not in captures or "pcap" not in captures[training_pattern]:
            raise ValueError(f"Could not locate training capture '{training_pattern}' in {dataset_root}")

        builder = TrafficWindowBuilder(window_duration=5.0)
        # Train baseline
        train_pcap = captures[training_pattern]["pcap"]
        train_zeek = captures[training_pattern].get("zeek")
        train_pkts = PcapReader(train_pcap).iter_packets()
        train_flows = ZeekLogParser(train_zeek).parse_flows() if train_zeek else []
        train_windows, _ = builder.process_capture(training_pattern, train_pkts, train_flows)
        clean_train = [w.feature_vector for w in train_windows if w.ground_truth == WindowGroundTruth.BENIGN]

        # Test windows
        test_vectors: List[List[float]] = []
        test_labels: List[int] = []
        test_desc: List[str] = []

        for t_pat in test_patterns:
            if t_pat not in captures or "pcap" not in captures[t_pat]:
                continue
            pkts = PcapReader(captures[t_pat]["pcap"]).iter_packets()
            flows = ZeekLogParser(captures[t_pat]["zeek"]).parse_flows() if "zeek" in captures[t_pat] else []
            wins, _ = builder.process_capture(t_pat, pkts, flows)
            for w in wins:
                if not w.is_eligible_for_metrics:
                    continue
                test_vectors.append(w.feature_vector)
                y = 1 if w.ground_truth == WindowGroundTruth.MALICIOUS else 0
                test_labels.append(y)
                test_desc.append(f"{t_pat}_{w.ground_truth.value}")

        return clean_train, np.asarray(test_vectors), np.asarray(test_labels), test_desc

    def run(self) -> List[TrialResult]:
        """Execute the full factorial baseline experiment."""
        clean_train_pool, X_val, y_val, val_labels = self.load_dataset()
        avail_train = len(clean_train_pool)
        logger.info(
            "Dataset ready: %d baseline normal windows available, %d validation windows (%d benign, %d attack)",
            avail_train,
            len(X_val),
            int(np.sum(y_val == 0)),
            int(np.sum(y_val == 1)),
        )

        # Filter target sizes based on availability
        sizes_to_test = [s for s in BASELINE_SIZES if s <= avail_train]
        if avail_train not in sizes_to_test:
            sizes_to_test.append(avail_train)
        sizes_to_test.sort()

        results: List[TrialResult] = []

        print("\n" + "=" * 90)
        print("NETSENTINEL ISOLATION FOREST: CONTROLLED BASELINE SCALING & FILTERING EXPERIMENT")
        print("Architecture: Single 13-Feature Isolation Forest | n_estimators=100 | threshold=0.50")
        print("=" * 90)

        for target_size in sizes_to_test:
            for use_filter in [True, False]:
                cond_name = "With_IQR" if use_filter else "No_Filtering"
                raw_subset = clean_train_pool[:target_size]

                # Outlier filtering condition
                if use_filter:
                    filtered_subset = filter_baseline_outliers(
                        raw_subset, min_samples=min(5, len(raw_subset) // 2)
                    )
                else:
                    filtered_subset = list(raw_subset)

                used_count = len(filtered_subset)
                dropped_count = len(raw_subset) - used_count
                dropped_ratio = (dropped_count / len(raw_subset)) * 100.0

                # Fit single production Isolation Forest model
                t0_train = time.perf_counter()
                model = IsolationForestModel(
                    n_estimators=100,
                    max_samples="auto",
                    contamination="auto",
                    random_state=self.seed,
                    min_samples=min(5, used_count // 2),
                )
                model.train(filtered_subset)
                train_time_sec = time.perf_counter() - t0_train

                if model.status != ModelStatus.READY:
                    logger.error("Model training failed for size %d (%s)", target_size, cond_name)
                    continue

                # Measure single-sample prediction latency
                latency_trials = min(100, len(X_val))
                t0_lat = time.perf_counter()
                for i in range(latency_trials):
                    _ = model.predict(X_val[i].tolist())
                single_latency_ms = ((time.perf_counter() - t0_lat) / latency_trials) * 1000.0

                # Vectorized batch evaluation across all validation windows
                raw_scores = model.model.decision_function(X_val)
                norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
                y_pred = (norm_scores > 0.50).astype(int)

                # Metrics calculation
                tn, fp, fn, tp = confusion_matrix(y_val, y_pred, labels=[0, 1]).ravel()
                acc = float(accuracy_score(y_val, y_pred))
                prec = float(precision_score(y_val, y_pred, zero_division=0))
                rec = float(recall_score(y_val, y_pred, zero_division=0))
                f1 = float(f1_score(y_val, y_pred, zero_division=0))
                fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
                fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

                roc_auc = float(roc_auc_score(y_val, norm_scores))
                p_curve, r_curve, _ = precision_recall_curve(y_val, norm_scores)
                pr_auc = float(auc(r_curve, p_curve))

                benign_scores = norm_scores[y_val == 0]
                mal_scores = norm_scores[y_val == 1]
                effective_max_samples = min(256, used_count)

                trial = TrialResult(
                    baseline_target_size=target_size,
                    filtering_condition=cond_name,
                    raw_samples_count=len(raw_subset),
                    used_samples_count=used_count,
                    dropped_samples_count=dropped_count,
                    dropped_ratio_pct=round(dropped_ratio, 2),
                    effective_max_samples=effective_max_samples,
                    accuracy=round(acc, 4),
                    precision=round(prec, 4),
                    recall=round(rec, 4),
                    f1_score=round(f1, 4),
                    false_positive_rate=round(fpr, 4),
                    false_negative_rate=round(fnr, 4),
                    roc_auc=round(roc_auc, 4),
                    pr_auc=round(pr_auc, 4),
                    true_positives=int(tp),
                    true_negatives=int(tn),
                    false_positives=int(fp),
                    false_negatives=int(fn),
                    training_time_sec=round(train_time_sec, 4),
                    prediction_latency_ms=round(single_latency_ms, 4),
                    benign_score_mean=round(float(np.mean(benign_scores)), 4),
                    benign_score_std=round(float(np.std(benign_scores)), 4),
                    malicious_score_mean=round(float(np.mean(mal_scores)), 4),
                    malicious_score_std=round(float(np.std(mal_scores)), 4),
                )
                results.append(trial)

                print(
                    f"Size: {target_size:>4} | {cond_name:<12} | Samples: {len(raw_subset):>4} -> {used_count:>4} "
                    f"(-{dropped_count:>3}, {dropped_ratio:4.1f}%) | "
                    f"Acc: {acc*100:5.2f}% | Prec: {prec*100:5.2f}% | Rec: {rec*100:5.2f}% | F1: {f1:0.4f} | "
                    f"FPR: {fpr*100:5.2f}% | ROC-AUC: {roc_auc:0.4f} | PR-AUC: {pr_auc:0.4f} | "
                    f"BenignScoreMean: {trial.benign_score_mean:.4f} | TrainT: {train_time_sec:0.3f}s"
                )

        print("=" * 90 + "\n")
        self.save_artifacts(results)
        return results

    def save_artifacts(self, results: List[TrialResult]) -> Tuple[str, str]:
        """Save results to JSON and CSV formats."""
        json_path = os.path.join(self.output_dir, "baseline_experiment_results.json")
        csv_path = os.path.join(self.output_dir, "baseline_comparison_table.csv")

        # 1. Save JSON
        json_data = {
            "metadata": {
                "algorithm": "Isolation Forest (Unsupervised)",
                "n_estimators": 100,
                "max_samples": "auto",
                "contamination": "auto",
                "random_state": self.seed,
                "threshold": 0.50,
                "feature_count": 13,
                "feature_names": FEATURE_NAMES,
                "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "trials": [asdict(r) for r in results],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        # 2. Save CSV
        if results:
            fieldnames = list(asdict(results[0]).keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    writer.writerow(asdict(r))

        logger.info("Saved JSON results to %s", json_path)
        logger.info("Saved CSV comparison table to %s", csv_path)
        return json_path, csv_path


def main():
    parser = argparse.ArgumentParser(description="NetSentinel ML Baseline Scaling Experiment Runner")
    parser.add_argument(
        "--dataset-root",
        type=str,
        default=None,
        help="Optional path to CTU-IDSEVAL-6 dataset root directory",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to save experimental results (default: reports/baseline_experiments)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    runner = BaselineScalingExperiment(
        output_dir=args.output_dir,
        seed=args.seed,
        dataset_root=args.dataset_root,
    )
    runner.run()


if __name__ == "__main__":
    main()
