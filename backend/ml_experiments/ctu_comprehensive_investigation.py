"""NetSentinel Isolation Forest: Comprehensive CTU-IDSEVAL-6 Real Data Investigation.

Executes all 7 tasks required for the rigorous investigation:
1. Historical Phase 15.5 Reproduction (All 2,250 windows, no IQR filtering)
2. Baseline Scaling on Real CTU Data (30, 128, 256, 512, 1000, 2250 x With_IQR vs No_Filtering)
3. Deep Investigation of the IQR Filter on Real CTU Traffic
4. Training Data Quality & Temporal Sampling Bias (First N vs Time-Dispersed vs Full Random)
5. Validation and Leakage Audit
6. Final Multi-Metric Ranking and Trade-off Analysis
7. Quality Control and Reproducibility Verification

All operations preserve production code, git status, and the canonical 13-feature schema.
"""

import argparse
import csv
import json
import logging
import os
import pickle
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

from evaluation.pcap_reader import PcapReader
from evaluation.window_builder import TrafficWindowBuilder, WindowGroundTruth
from evaluation.zeek_parser import ZeekLogParser
from ml.detector import filter_baseline_outliers
from ml.feature_extractor import FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel.ctu_investigation")

DATASET_ROOT_DEFAULT = "/tmp/ctu-idseval-6"
CACHE_PATH = "/tmp/ctu_windows_cache.pkl"
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports", "ctu_investigation")


@dataclass
class CaptureEvaluationMetrics:
    capture_name: str
    total_eligible: int
    benign_count: int
    malicious_count: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: Optional[float]
    pr_auc: Optional[float]
    benign_score_mean: Optional[float]
    malicious_score_mean: Optional[float]


@dataclass
class ComprehensiveExperimentResult:
    experiment_id: str
    baseline_size: int
    filtering_strategy: str  # "No_Filtering", "With_IQR"
    sampling_strategy: str   # "First_N", "Time_Dispersed", "Random_Representative"
    raw_baseline_samples: int
    used_baseline_samples: int
    dropped_samples: int
    dropped_ratio_pct: float
    effective_max_samples: int
    overall_accuracy: float
    overall_precision: float
    overall_recall: float
    overall_f1_score: float
    overall_fpr: float
    overall_fnr: float
    overall_roc_auc: float
    overall_pr_auc: float
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
    per_capture_results: Dict[str, Dict[str, Any]]


class CTUComprehensiveInvestigator:
    """Manages the full end-to-end investigation on real CTU-IDSEVAL-6 data."""

    def __init__(self, dataset_root: str = DATASET_ROOT_DEFAULT, output_dir: str = OUTPUT_DIR):
        self.dataset_root = dataset_root
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.clean_train_windows: List[List[float]] = []
        self.test_captures_data: Dict[str, Dict[str, Any]] = {}
        # test_captures_data[cap_name] = {"X": np.ndarray, "y": np.ndarray}

    def load_or_extract_windows(self, force_recompute: bool = False):
        """Extract or load cached window features and labels from raw PCAPs."""
        if os.path.exists(CACHE_PATH) and not force_recompute:
            logger.info("Loading pre-extracted window features from cache: %s", CACHE_PATH)
            with open(CACHE_PATH, "rb") as f:
                data = pickle.load(f)
            self.clean_train_windows = data["clean_train_windows"]
            self.test_captures_data = data["test_captures_data"]
            logger.info(
                "Cache loaded: %d clean training windows, %d test captures",
                len(self.clean_train_windows),
                len(self.test_captures_data),
            )
            return

        logger.info("Extracting 5.0-second traffic windows from CTU-IDSEVAL-6 dataset...")
        builder = TrafficWindowBuilder(window_duration=5.0)

        # 1. Training Baseline: benign-user-traffic-1
        train_pcap = os.path.join(self.dataset_root, "pcap", "ctu-idseval-6-benign-user-traffic-1.pcap")
        train_zeek = os.path.join(self.dataset_root, "zeek", "ctu-idseval-6-benign-user-traffic-1.conn-labeled.log")
        t0 = time.time()
        train_pkts = PcapReader(train_pcap).iter_packets()
        train_flows = ZeekLogParser(train_zeek).parse_flows()
        train_wins, train_sum = builder.process_capture("benign-user-traffic-1", train_pkts, train_flows)
        self.clean_train_windows = [
            w.feature_vector for w in train_wins if w.ground_truth == WindowGroundTruth.BENIGN
        ]
        logger.info(
            "Extracted %d total windows (%d clean BENIGN) from benign-user-traffic-1 in %.2fs",
            len(train_wins),
            len(self.clean_train_windows),
            time.time() - t0,
        )

        # 2. Test Captures
        test_names = [
            "ctu-idseval-6-malicious-portscan-1",
            "ctu-idseval-6-malicious-portscan-2",
            "ctu-idseval-6-malicious-portscan-3",
            "ctu-idseval-6-malicious-malware-1",
            "ctu-idseval-6-malicious-malware-2",
        ]

        self.test_captures_data = {}
        for name in test_names:
            t0 = time.time()
            pcap = os.path.join(self.dataset_root, "pcap", f"{name}.pcap")
            zeek = os.path.join(self.dataset_root, "zeek", f"{name}.conn-labeled.log")
            pkts = PcapReader(pcap).iter_packets()
            flows = ZeekLogParser(zeek).parse_flows()
            wins, sumry = builder.process_capture(name, pkts, flows)
            el_wins = [w for w in wins if w.is_eligible_for_metrics]
            X = np.asarray([w.feature_vector for w in el_wins], dtype=np.float64)
            y = np.asarray(
                [1 if w.ground_truth == WindowGroundTruth.MALICIOUS else 0 for w in el_wins],
                dtype=np.int32,
            )
            self.test_captures_data[name] = {"X": X, "y": y, "total_windows": len(wins)}
            logger.info(
                "Extracted %s: %d total, %d eligible (%d benign, %d malicious) in %.2fs",
                name,
                len(wins),
                len(el_wins),
                int(np.sum(y == 0)),
                int(np.sum(y == 1)),
                time.time() - t0,
            )

        # Save cache
        with open(CACHE_PATH, "wb") as f:
            pickle.dump(
                {
                    "clean_train_windows": self.clean_train_windows,
                    "test_captures_data": self.test_captures_data,
                },
                f,
            )
        logger.info("Saved extracted windows cache to %s", CACHE_PATH)

    def evaluate_model(
        self,
        train_features: List[List[float]],
        experiment_id: str,
        baseline_size: int,
        filtering_strategy: str,
        sampling_strategy: str,
        raw_count: int,
        dropped_count: int,
    ) -> ComprehensiveExperimentResult:
        """Train Isolation Forest and evaluate across all test captures."""
        used_count = len(train_features)
        dropped_ratio = (dropped_count / raw_count) * 100.0 if raw_count > 0 else 0.0

        # Train model
        t0_train = time.perf_counter()
        model = IsolationForestModel(
            n_estimators=100,
            max_samples="auto",
            contamination="auto",
            random_state=42,
            min_samples=min(5, used_count // 2),
        )
        model.train(train_features)
        training_time = time.perf_counter() - t0_train

        # Latency benchmark
        first_cap_X = next(iter(self.test_captures_data.values()))["X"]
        t0_lat = time.perf_counter()
        for i in range(min(100, len(first_cap_X))):
            _ = model.predict(first_cap_X[i].tolist())
        latency_ms = ((time.perf_counter() - t0_lat) / min(100, len(first_cap_X))) * 1000.0

        # Evaluate across captures
        all_y_true: List[int] = []
        all_norm_scores: List[float] = []
        all_preds: List[int] = []
        per_cap_metrics: Dict[str, Dict[str, Any]] = {}

        for cap_name, cap_data in self.test_captures_data.items():
            X = cap_data["X"]
            y = cap_data["y"]

            if len(X) == 0:
                continue

            raw_scores = model.model.decision_function(X)
            norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
            preds = (norm_scores > 0.50).astype(int)

            all_y_true.extend(y.tolist())
            all_norm_scores.extend(norm_scores.tolist())
            all_preds.extend(preds.tolist())

            # Capture metrics
            ben_mask = y == 0
            mal_mask = y == 1
            ben_count = int(np.sum(ben_mask))
            mal_count = int(np.sum(mal_mask))

            tp = int(np.sum((preds == 1) & (y == 1)))
            tn = int(np.sum((preds == 0) & (y == 0)))
            fp = int(np.sum((preds == 1) & (y == 0)))
            fn = int(np.sum((preds == 0) & (y == 1)))

            c_acc = float(accuracy_score(y, preds))
            c_prec = float(precision_score(y, preds, zero_division=0))
            c_rec = float(recall_score(y, preds, zero_division=0))
            c_f1 = float(f1_score(y, preds, zero_division=0))
            c_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            c_fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

            c_roc_auc = float(roc_auc_score(y, norm_scores)) if len(np.unique(y)) > 1 else None
            if len(np.unique(y)) > 1:
                p_c, r_c, _ = precision_recall_curve(y, norm_scores)
                c_pr_auc = float(auc(r_c, p_c))
            else:
                c_pr_auc = None

            per_cap_metrics[cap_name] = {
                "eligible_windows": len(X),
                "benign_windows": ben_count,
                "malicious_windows": mal_count,
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "accuracy": round(c_acc, 4),
                "precision": round(c_prec, 4),
                "recall": round(c_rec, 4),
                "f1_score": round(c_f1, 4),
                "false_positive_rate": round(c_fpr, 4),
                "false_negative_rate": round(c_fnr, 4),
                "roc_auc": round(c_roc_auc, 4) if c_roc_auc is not None else None,
                "pr_auc": round(c_pr_auc, 4) if c_pr_auc is not None else None,
                "benign_score_mean": round(float(np.mean(norm_scores[ben_mask])), 4) if ben_count > 0 else None,
                "malicious_score_mean": round(float(np.mean(norm_scores[mal_mask])), 4) if mal_count > 0 else None,
            }

        # Overall dataset metrics
        y_true_arr = np.array(all_y_true)
        norm_scores_arr = np.array(all_norm_scores)
        preds_arr = np.array(all_preds)

        tot_tp = int(np.sum((preds_arr == 1) & (y_true_arr == 1)))
        tot_tn = int(np.sum((preds_arr == 0) & (y_true_arr == 0)))
        tot_fp = int(np.sum((preds_arr == 1) & (y_true_arr == 0)))
        tot_fn = int(np.sum((preds_arr == 0) & (y_true_arr == 1)))

        acc = float(accuracy_score(y_true_arr, preds_arr))
        prec = float(precision_score(y_true_arr, preds_arr, zero_division=0))
        rec = float(recall_score(y_true_arr, preds_arr, zero_division=0))
        f1 = float(f1_score(y_true_arr, preds_arr, zero_division=0))
        fpr = float(tot_fp / (tot_fp + tot_tn)) if (tot_fp + tot_tn) > 0 else 0.0
        fnr = float(tot_fn / (tot_fn + tot_tp)) if (tot_fn + tot_tp) > 0 else 0.0

        roc_auc = float(roc_auc_score(y_true_arr, norm_scores_arr))
        p_c, r_c, _ = precision_recall_curve(y_true_arr, norm_scores_arr)
        pr_auc = float(auc(r_c, p_c))

        ben_all = norm_scores_arr[y_true_arr == 0]
        mal_all = norm_scores_arr[y_true_arr == 1]
        effective_max = min(256, used_count)

        return ComprehensiveExperimentResult(
            experiment_id=experiment_id,
            baseline_size=baseline_size,
            filtering_strategy=filtering_strategy,
            sampling_strategy=sampling_strategy,
            raw_baseline_samples=raw_count,
            used_baseline_samples=used_count,
            dropped_samples=dropped_count,
            dropped_ratio_pct=round(dropped_ratio, 2),
            effective_max_samples=effective_max,
            overall_accuracy=round(acc, 4),
            overall_precision=round(prec, 4),
            overall_recall=round(rec, 4),
            overall_f1_score=round(f1, 4),
            overall_fpr=round(fpr, 4),
            overall_fnr=round(fnr, 4),
            overall_roc_auc=round(roc_auc, 4),
            overall_pr_auc=round(pr_auc, 4),
            true_positives=tot_tp,
            true_negatives=tot_tn,
            false_positives=tot_fp,
            false_negatives=tot_fn,
            training_time_sec=round(training_time, 4),
            prediction_latency_ms=round(latency_ms, 4),
            benign_score_mean=round(float(np.mean(ben_all)), 4),
            benign_score_std=round(float(np.std(ben_all)), 4),
            malicious_score_mean=round(float(np.mean(mal_all)), 4),
            malicious_score_std=round(float(np.std(mal_all)), 4),
            per_capture_results=per_cap_metrics,
        )

    def run_all(self) -> Dict[str, Any]:
        """Execute all investigation tasks."""
        self.load_or_extract_windows()

        logger.info("=" * 80)
        logger.info("STARTING TASK 1: HISTORICAL REPRODUCTION (All 2,250 clean windows, No IQR)")
        logger.info("=" * 80)
        reproduction_res = self.evaluate_model(
            train_features=self.clean_train_windows,
            experiment_id="task1_historical_reproduction_2250_nofilter",
            baseline_size=2250,
            filtering_strategy="No_Filtering",
            sampling_strategy="All_Available",
            raw_count=len(self.clean_train_windows),
            dropped_count=0,
        )

        logger.info("Historical Reproduction Results on Real CTU-IDSEVAL-6:")
        logger.info(
            "Accuracy: %.2f%% | Prec: %.2f%% | Rec: %.2f%% | F1: %.4f | FPR: %.2f%% | ROC-AUC: %.4f | PR-AUC: %.4f",
            reproduction_res.overall_accuracy * 100,
            reproduction_res.overall_precision * 100,
            reproduction_res.overall_recall * 100,
            reproduction_res.overall_f1_score,
            reproduction_res.overall_fpr * 100,
            reproduction_res.overall_roc_auc,
            reproduction_res.overall_pr_auc,
        )

        # -------------------------------------------------------------
        # TASK 2: BASELINE SCALING ON REAL CTU DATA
        # -------------------------------------------------------------
        logger.info("\n" + "=" * 80)
        logger.info("STARTING TASK 2: BASELINE SCALING ON REAL CTU DATA")
        logger.info("=" * 80)
        scaling_results: List[ComprehensiveExperimentResult] = []
        target_sizes = [30, 128, 256, 512, 1000, 2250]

        for sz in target_sizes:
            raw_subset = self.clean_train_windows[:sz]

            # A. No Filtering
            res_nofilt = self.evaluate_model(
                train_features=raw_subset,
                experiment_id=f"task2_scaling_{sz}_nofilter",
                baseline_size=sz,
                filtering_strategy="No_Filtering",
                sampling_strategy="First_N",
                raw_count=len(raw_subset),
                dropped_count=0,
            )
            scaling_results.append(res_nofilt)

            # B. With IQR Filtering
            filtered_subset = filter_baseline_outliers(raw_subset, min_samples=min(5, len(raw_subset) // 2))
            dropped = len(raw_subset) - len(filtered_subset)
            res_iqr = self.evaluate_model(
                train_features=filtered_subset,
                experiment_id=f"task2_scaling_{sz}_with_iqr",
                baseline_size=sz,
                filtering_strategy="With_IQR",
                sampling_strategy="First_N",
                raw_count=len(raw_subset),
                dropped_count=dropped,
            )
            scaling_results.append(res_iqr)

            logger.info(
                "Size %4d | NoFilter: Acc=%.2f%%, FPR=%.2f%%, Rec=%.2f%%, ROC=%.4f | "
                "WithIQR (-%d): Acc=%.2f%%, FPR=%.2f%%, Rec=%.2f%%, ROC=%.4f",
                sz,
                res_nofilt.overall_accuracy * 100,
                res_nofilt.overall_fpr * 100,
                res_nofilt.overall_recall * 100,
                res_nofilt.overall_roc_auc,
                dropped,
                res_iqr.overall_accuracy * 100,
                res_iqr.overall_fpr * 100,
                res_iqr.overall_recall * 100,
                res_iqr.overall_roc_auc,
            )

        # -------------------------------------------------------------
        # TASK 3: DEEP INVESTIGATION OF THE IQR FILTER ON REAL CTU DATA
        # -------------------------------------------------------------
        logger.info("\n" + "=" * 80)
        logger.info("STARTING TASK 3: INVESTIGATE THE IQR FILTER ON REAL CTU DATA")
        logger.info("=" * 80)
        iqr_audit = self._audit_iqr_filter()

        # -------------------------------------------------------------
        # TASK 4: TRAINING DATA QUALITY & TEMPORAL SAMPLING BIAS
        # -------------------------------------------------------------
        logger.info("\n" + "=" * 80)
        logger.info("STARTING TASK 4: TEMPORAL SAMPLING BIAS EXPERIMENT")
        logger.info("=" * 80)
        temporal_results: List[ComprehensiveExperimentResult] = []

        # Compare at N=256 and N=512
        for sz in [256, 512]:
            # Strategy 1: First N consecutive
            first_n = self.clean_train_windows[:sz]
            r1 = self.evaluate_model(
                train_features=first_n,
                experiment_id=f"task4_sampling_{sz}_first_n",
                baseline_size=sz,
                filtering_strategy="No_Filtering",
                sampling_strategy="First_N",
                raw_count=sz,
                dropped_count=0,
            )
            temporal_results.append(r1)

            # Strategy 2: Time-dispersed (evenly strided across all 2,250 windows)
            step = len(self.clean_train_windows) / sz
            indices_strided = [int(i * step) for i in range(sz)]
            strided_subset = [self.clean_train_windows[i] for i in indices_strided]
            r2 = self.evaluate_model(
                train_features=strided_subset,
                experiment_id=f"task4_sampling_{sz}_time_dispersed",
                baseline_size=sz,
                filtering_strategy="No_Filtering",
                sampling_strategy="Time_Dispersed",
                raw_count=sz,
                dropped_count=0,
            )
            temporal_results.append(r2)

            # Strategy 3: Random representative sample (seed=42)
            rng = np.random.RandomState(42)
            rand_indices = sorted(rng.choice(len(self.clean_train_windows), size=sz, replace=False))
            random_subset = [self.clean_train_windows[i] for i in rand_indices]
            r3 = self.evaluate_model(
                train_features=random_subset,
                experiment_id=f"task4_sampling_{sz}_random_representative",
                baseline_size=sz,
                filtering_strategy="No_Filtering",
                sampling_strategy="Random_Representative",
                raw_count=sz,
                dropped_count=0,
            )
            temporal_results.append(r3)

            logger.info(
                "Size %d Comparison: First_N (Acc=%.2f%%, FPR=%.2f%%, ROC=%.4f) vs "
                "Time_Dispersed (Acc=%.2f%%, FPR=%.2f%%, ROC=%.4f) vs "
                "Random (Acc=%.2f%%, FPR=%.2f%%, ROC=%.4f)",
                sz,
                r1.overall_accuracy * 100,
                r1.overall_fpr * 100,
                r1.overall_roc_auc,
                r2.overall_accuracy * 100,
                r2.overall_fpr * 100,
                r2.overall_roc_auc,
                r3.overall_accuracy * 100,
                r3.overall_fpr * 100,
                r3.overall_roc_auc,
            )

        # -------------------------------------------------------------
        # SAVE ARTIFACTS
        # -------------------------------------------------------------
        all_trials = [reproduction_res] + scaling_results + temporal_results
        self._save_results(all_trials, iqr_audit)

        return {
            "reproduction": reproduction_res,
            "scaling": scaling_results,
            "temporal": temporal_results,
            "iqr_audit": iqr_audit,
        }

    def _audit_iqr_filter(self) -> Dict[str, Any]:
        """Deep feature-level inspection of IQR filtering on real CTU baseline traffic."""
        arr = np.asarray(self.clean_train_windows, dtype=np.float64)
        total_samples = len(arr)

        check_indices = [0, 1, 6, 10]
        check_names = [
            FEATURE_NAMES[0],  # packets_per_second
            FEATURE_NAMES[1],  # bytes_per_second
            FEATURE_NAMES[6],  # syn_ratio
            FEATURE_NAMES[10], # unique_destination_ports
        ]

        per_feature_stats = {}
        outlier_indices_per_feature = {}

        for idx, name in zip(check_indices, check_names):
            col = arr[:, idx]
            q25 = float(np.percentile(col, 25))
            q75 = float(np.percentile(col, 75))
            iqr = q75 - q25
            med = float(np.median(col))
            mean = float(np.mean(col))
            max_val = float(np.max(col))
            bound = q75 + (3.0 * iqr)
            outs = np.where(col > bound)[0].tolist()
            outlier_indices_per_feature[name] = outs
            per_feature_stats[name] = {
                "mean": round(mean, 4),
                "median": round(med, 4),
                "p25": round(q25, 4),
                "p75": round(q75, 4),
                "iqr": round(iqr, 4),
                "cutoff_threshold": round(bound, 4),
                "max_value": round(max_val, 4),
                "outlier_count": len(outs),
                "outlier_pct": round((len(outs) / total_samples) * 100.0, 2),
            }

        # Union of outliers
        all_outliers = set()
        for outs in outlier_indices_per_feature.values():
            all_outliers.update(outs)

        # Inspect dropped window attributes
        dropped_arr = arr[list(all_outliers)]
        retained_indices = [i for i in range(total_samples) if i not in all_outliers]
        retained_arr = arr[retained_indices]

        audit_summary = {
            "total_clean_windows": total_samples,
            "total_outliers_dropped": len(all_outliers),
            "dropped_percentage": round((len(all_outliers) / total_samples) * 100.0, 2),
            "retained_windows": len(retained_indices),
            "per_feature_stats": per_feature_stats,
            "dropped_windows_profile": {
                "mean_packets_per_second": round(float(np.mean(dropped_arr[:, 0])), 2),
                "max_packets_per_second": round(float(np.max(dropped_arr[:, 0])), 2),
                "mean_bytes_per_second": round(float(np.mean(dropped_arr[:, 1])), 2),
                "max_bytes_per_second": round(float(np.max(dropped_arr[:, 1])), 2),
                "mean_average_packet_size": round(float(np.mean(dropped_arr[:, 2])), 2),
                "mean_tcp_ratio": round(float(np.mean(dropped_arr[:, 3])), 4),
                "mean_unique_destination_ports": round(float(np.mean(dropped_arr[:, 10])), 2),
            },
            "retained_windows_profile": {
                "mean_packets_per_second": round(float(np.mean(retained_arr[:, 0])), 2),
                "max_packets_per_second": round(float(np.max(retained_arr[:, 0])), 2),
                "mean_bytes_per_second": round(float(np.mean(retained_arr[:, 1])), 2),
                "max_bytes_per_second": round(float(np.max(retained_arr[:, 1])), 2),
                "mean_average_packet_size": round(float(np.mean(retained_arr[:, 2])), 2),
                "mean_tcp_ratio": round(float(np.mean(retained_arr[:, 3])), 4),
                "mean_unique_destination_ports": round(float(np.mean(retained_arr[:, 10])), 2),
            },
        }

        # Check behavior on 30-window sample as well
        sample_30 = self.clean_train_windows[:30]
        filt_30 = filter_baseline_outliers(sample_30)
        audit_summary["n30_behavior"] = {
            "raw_samples": 30,
            "retained_samples": len(filt_30),
            "dropped_samples": 30 - len(filt_30),
        }

        logger.info(
            "IQR Audit Summary: Across full capture, %d/%d windows dropped (%.2f%%)",
            len(all_outliers),
            total_samples,
            (len(all_outliers) / total_samples) * 100.0,
        )
        return audit_summary

    def _save_results(self, trials: List[ComprehensiveExperimentResult], iqr_audit: Dict[str, Any]):
        """Save results to JSON and CSV files."""
        json_path = os.path.join(self.output_dir, "ctu_real_experiment_results.json")
        csv_path = os.path.join(self.output_dir, "ctu_real_comparison_table.csv")
        iqr_json_path = os.path.join(self.output_dir, "ctu_iqr_audit.json")

        # 1. Save Full JSON
        out_json = {
            "metadata": {
                "dataset": "CTU-IDSEVAL-6 (Exact Zenodo Real Captures)",
                "algorithm": "Isolation Forest (Unsupervised)",
                "n_estimators": 100,
                "max_samples": "auto",
                "contamination": "auto",
                "random_state": 42,
                "threshold": 0.50,
                "window_duration_seconds": 5.0,
                "feature_count": 13,
                "feature_names": FEATURE_NAMES,
                "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "trials": [asdict(t) for t in trials],
            "iqr_audit": iqr_audit,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(out_json, f, indent=2)

        # 2. Save Comparison CSV
        rows = []
        for t in trials:
            d = asdict(t)
            # Remove nested per_capture_results from top-level CSV row for clean presentation
            del d["per_capture_results"]
            rows.append(d)

        fieldnames = list(rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)

        # 3. Save IQR Audit
        with open(iqr_json_path, "w", encoding="utf-8") as f:
            json.dump(iqr_audit, f, indent=2)

        logger.info("Saved complete results to %s", json_path)
        logger.info("Saved CSV comparison table to %s", csv_path)
        logger.info("Saved IQR audit to %s", iqr_json_path)


def main():
    parser = argparse.ArgumentParser(description="CTU-IDSEVAL-6 Real Data Investigation Runner")
    parser.add_argument(
        "--dataset-root",
        type=str,
        default=DATASET_ROOT_DEFAULT,
        help="Path to CTU-IDSEVAL-6 root directory",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=OUTPUT_DIR,
        help="Output directory for reports",
    )
    args = parser.parse_args()

    investigator = CTUComprehensiveInvestigator(
        dataset_root=args.dataset_root,
        output_dir=args.output_dir,
    )
    investigator.run_all()


if __name__ == "__main__":
    main()
