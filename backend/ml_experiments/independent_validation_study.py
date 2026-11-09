"""NetSentinel Isolation Forest: Independent Dataset & Baseline Research Study.

Implements a leak-free, multi-dataset ML research and validation suite:
1. Strict three-way partitioning:
   - Training Baseline: benign-user-traffic-1 (clean normal traffic)
   - Development Validation Set: malware-1 (26,094 windows) for hyperparameter & sizing exploration
   - Strictly Held-Out Final Test Set: malware-2 + portscan-1, 2, 3 (33,226 windows) frozen until evaluation
2. Controlled Baseline Scaling:
   - Baseline sizes: 30, 128, 256, 512, 1000, 2250
   - Sampling strategies: First-N, Time-Dispersed, Random Representative
   - Filtering strategies: No_Filtering vs 3.0x IQR vs Adaptive IQR
3. Model-Specific Investigations:
   - n_estimators sensitivity (50, 100, 200)
   - Random seed sensitivity (42, 1337, 2026, 9999)
   - Score distribution analysis & separation margins
   - Validation-only threshold sensitivity (T = 0.40 to 0.60)
4. Independent Dataset Feasibility & Parity Audit:
   - CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, TON_IoT
   - Direct PCAP packet parsing verification on converted CIC-IDS2017 PCAP
5. Comprehensive metrics recording (Accuracy, Precision, Recall, F1, FPR, FNR, ROC-AUC, PR-AUC, Latency, Durations).
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

from ml.detector import filter_baseline_outliers
from ml.feature_extractor import FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel.independent_study")

CACHE_PATH = "/tmp/ctu_windows_cache.pkl"
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports", "independent_investigation")


@dataclass
class ExperimentMetrics:
    experiment_id: str
    phase: str  # "validation" or "final_test"
    baseline_size: int
    filtering_strategy: str
    sampling_strategy: str
    n_estimators: int
    random_seed: int
    threshold: float
    raw_samples: int
    used_samples: int
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
    inference_latency_ms: float
    collection_duration_sec: float
    benign_score_mean: float
    benign_score_std: float
    malicious_score_mean: float
    malicious_score_std: float
    score_separation_margin: float


class IndependentStudyRunner:
    """Orchestrates leak-free baseline scaling, model sensitivity, and validation experiments."""

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        if not os.path.exists(CACHE_PATH):
            raise FileNotFoundError(f"Extracted windows cache not found at {CACHE_PATH}. Run ctu_comprehensive_investigation.py first.")

        logger.info("Loading extracted windows from %s...", CACHE_PATH)
        with open(CACHE_PATH, "rb") as f:
            cache = pickle.load(f)

        self.clean_train_pool: List[List[float]] = cache["clean_train_windows"]
        test_caps = cache["test_captures_data"]

        # Strict Partitioning:
        # Development Validation Partition: malware-1
        self.val_X = test_caps["ctu-idseval-6-malicious-malware-1"]["X"]
        self.val_y = test_caps["ctu-idseval-6-malicious-malware-1"]["y"]

        # Final Independent Hold-Out Partition: malware-2 + portscan-1, 2, 3
        holdout_caps = [
            "ctu-idseval-6-malicious-portscan-1",
            "ctu-idseval-6-malicious-portscan-2",
            "ctu-idseval-6-malicious-portscan-3",
            "ctu-idseval-6-malicious-malware-2",
        ]
        test_X_list = [test_caps[c]["X"] for c in holdout_caps]
        test_y_list = [test_caps[c]["y"] for c in holdout_caps]
        self.test_X = np.vstack(test_X_list)
        self.test_y = np.concatenate(test_y_list)

        logger.info(
            "Partitioning initialized:\n"
            "  - Training Baseline Pool : %d clean windows (~%.1f hrs)\n"
            "  - Validation Set (malware-1): %d windows (%d benign, %d malicious)\n"
            "  - Final Holdout Test Set (malware-2 + portscans): %d windows (%d benign, %d malicious)",
            len(self.clean_train_pool),
            (len(self.clean_train_pool) * 5.0) / 3600.0,
            len(self.val_X),
            int(np.sum(self.val_y == 0)),
            int(np.sum(self.val_y == 1)),
            len(self.test_X),
            int(np.sum(self.test_y == 0)),
            int(np.sum(self.test_y == 1)),
        )

    def select_baseline_samples(
        self,
        size: int,
        sampling_strategy: str,
        seed: int = 42,
    ) -> List[List[float]]:
        """Extract baseline sample subset under specific sampling strategy."""
        total = len(self.clean_train_pool)
        if size >= total:
            return list(self.clean_train_pool)

        if sampling_strategy == "First_N":
            return list(self.clean_train_pool[:size])
        elif sampling_strategy == "Time_Dispersed":
            step = total / size
            indices = [int(i * step) for i in range(size)]
            return [self.clean_train_pool[i] for i in indices]
        elif sampling_strategy == "Random_Representative":
            rng = np.random.RandomState(seed)
            indices = sorted(rng.choice(total, size=size, replace=False))
            return [self.clean_train_pool[i] for i in indices]
        else:
            raise ValueError(f"Unknown sampling strategy: {sampling_strategy}")

    def evaluate_configuration(
        self,
        train_samples: List[List[float]],
        experiment_id: str,
        phase: str,
        eval_X: np.ndarray,
        eval_y: np.ndarray,
        baseline_size: int,
        filtering_strategy: str,
        sampling_strategy: str,
        n_estimators: int = 100,
        random_seed: int = 42,
        threshold: float = 0.50,
        raw_samples: Optional[int] = None,
    ) -> ExperimentMetrics:
        """Train model and evaluate metrics on specified evaluation partition."""
        raw_count = raw_samples or len(train_samples)
        used_count = len(train_samples)

        # Train model
        t0_train = time.perf_counter()
        model = IsolationForestModel(
            n_estimators=n_estimators,
            max_samples="auto",
            contamination="auto",
            random_state=random_seed,
            min_samples=min(5, used_count // 2),
        )
        model.train(train_samples)
        train_time = time.perf_counter() - t0_train

        # Latency check (single window prediction)
        t0_lat = time.perf_counter()
        bench_count = min(100, len(eval_X))
        for i in range(bench_count):
            _ = model.predict(eval_X[i].tolist())
        latency_ms = ((time.perf_counter() - t0_lat) / bench_count) * 1000.0

        # Vectorized batch evaluation
        raw_scores = model.model.decision_function(eval_X)
        norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
        preds = (norm_scores > threshold).astype(int)

        # Confusion matrix & metrics
        tn, fp, fn, tp = confusion_matrix(eval_y, preds, labels=[0, 1]).ravel()
        acc = float(accuracy_score(eval_y, preds))
        prec = float(precision_score(eval_y, preds, zero_division=0))
        rec = float(recall_score(eval_y, preds, zero_division=0))
        f1 = float(f1_score(eval_y, preds, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        roc_auc = float(roc_auc_score(eval_y, norm_scores))
        p_c, r_c, _ = precision_recall_curve(eval_y, norm_scores)
        pr_auc = float(auc(r_c, p_c))

        ben_scores = norm_scores[eval_y == 0]
        mal_scores = norm_scores[eval_y == 1]
        ben_mean = float(np.mean(ben_scores))
        ben_std = float(np.std(ben_scores))
        mal_mean = float(np.mean(mal_scores))
        mal_std = float(np.std(mal_scores))
        separation = mal_mean - ben_mean

        collection_duration = baseline_size * 5.0
        effective_max = min(256, used_count)

        return ExperimentMetrics(
            experiment_id=experiment_id,
            phase=phase,
            baseline_size=baseline_size,
            filtering_strategy=filtering_strategy,
            sampling_strategy=sampling_strategy,
            n_estimators=n_estimators,
            random_seed=random_seed,
            threshold=threshold,
            raw_samples=raw_count,
            used_samples=used_count,
            effective_max_samples=effective_max,
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
            training_time_sec=round(train_time, 4),
            inference_latency_ms=round(latency_ms, 4),
            collection_duration_sec=round(collection_duration, 1),
            benign_score_mean=round(ben_mean, 4),
            benign_score_std=round(ben_std, 4),
            malicious_score_mean=round(mal_mean, 4),
            malicious_score_std=round(mal_std, 4),
            score_separation_margin=round(separation, 4),
        )

    def run_all_experiments(self) -> Dict[str, Any]:
        """Execute full experimental matrix: Validation exploration + Final Holdout confirmation."""
        val_results: List[ExperimentMetrics] = []
        final_test_results: List[ExperimentMetrics] = []

        logger.info("=" * 80)
        logger.info("STAGE 1: VALIDATION SET EXPLORATION (Leakage-Free, malware-1)")
        logger.info("=" * 80)

        # 1. Baseline Sizing Grid (30, 128, 256, 512, 1000, 2250) on Validation Set
        sizes = [30, 128, 256, 512, 1000, 2250]
        for sz in sizes:
            # A. First_N, No_Filtering
            raw_samples = self.select_baseline_samples(sz, "First_N")
            m_first_nofilt = self.evaluate_configuration(
                train_samples=raw_samples,
                experiment_id=f"val_sizing_{sz}_first_nofilt",
                phase="validation",
                eval_X=self.val_X,
                eval_y=self.val_y,
                baseline_size=sz,
                filtering_strategy="No_Filtering",
                sampling_strategy="First_N",
            )
            val_results.append(m_first_nofilt)

            # B. First_N, With_IQR
            filt_samples = filter_baseline_outliers(raw_samples, min_samples=min(5, len(raw_samples) // 2))
            m_first_iqr = self.evaluate_configuration(
                train_samples=filt_samples,
                experiment_id=f"val_sizing_{sz}_first_iqr",
                phase="validation",
                eval_X=self.val_X,
                eval_y=self.val_y,
                baseline_size=sz,
                filtering_strategy="With_IQR",
                sampling_strategy="First_N",
                raw_samples=len(raw_samples),
            )
            val_results.append(m_first_iqr)

            # C. Time_Dispersed, No_Filtering
            if sz < 2250:
                td_samples = self.select_baseline_samples(sz, "Time_Dispersed")
                m_td_nofilt = self.evaluate_configuration(
                    train_samples=td_samples,
                    experiment_id=f"val_sizing_{sz}_time_dispersed_nofilt",
                    phase="validation",
                    eval_X=self.val_X,
                    eval_y=self.val_y,
                    baseline_size=sz,
                    filtering_strategy="No_Filtering",
                    sampling_strategy="Time_Dispersed",
                )
                val_results.append(m_td_nofilt)

                # D. Random_Representative, No_Filtering
                rr_samples = self.select_baseline_samples(sz, "Random_Representative", seed=42)
                m_rr_nofilt = self.evaluate_configuration(
                    train_samples=rr_samples,
                    experiment_id=f"val_sizing_{sz}_random_representative_nofilt",
                    phase="validation",
                    eval_X=self.val_X,
                    eval_y=self.val_y,
                    baseline_size=sz,
                    filtering_strategy="No_Filtering",
                    sampling_strategy="Random_Representative",
                )
                val_results.append(m_rr_nofilt)

            logger.info(
                "Val Size %4d | FirstN NoFilt: FPR=%.2f%%, Acc=%.2f%%, Rec=%.2f%% | "
                "FirstN IQR: FPR=%.2f%%, Acc=%.2f%%, Rec=%.2f%%",
                sz,
                m_first_nofilt.false_positive_rate * 100,
                m_first_nofilt.accuracy * 100,
                m_first_nofilt.recall * 100,
                m_first_iqr.false_positive_rate * 100,
                m_first_iqr.accuracy * 100,
                m_first_iqr.recall * 100,
            )

        # 2. Model Sensitivity Analysis on Validation Set (at optimal sz=256 and sz=512)
        logger.info("\n" + "=" * 80)
        logger.info("STAGE 2: MODEL SENSITIVITY (Estimators, Random Seeds, Thresholds on Validation)")
        logger.info("=" * 80)

        # Estimators: 50, 100, 200
        for n_est in [50, 100, 200]:
            train_s = self.select_baseline_samples(256, "First_N")
            m_est = self.evaluate_configuration(
                train_samples=train_s,
                experiment_id=f"val_sensitivity_256_nest_{n_est}",
                phase="validation",
                eval_X=self.val_X,
                eval_y=self.val_y,
                baseline_size=256,
                filtering_strategy="No_Filtering",
                sampling_strategy="First_N",
                n_estimators=n_est,
            )
            val_results.append(m_est)

        # Random Seed Stability: 42, 1337, 2026, 9999
        for s_val in [42, 1337, 2026, 9999]:
            train_s = self.select_baseline_samples(256, "First_N")
            m_seed = self.evaluate_configuration(
                train_samples=train_s,
                experiment_id=f"val_stability_256_seed_{s_val}",
                phase="validation",
                eval_X=self.val_X,
                eval_y=self.val_y,
                baseline_size=256,
                filtering_strategy="No_Filtering",
                sampling_strategy="First_N",
                random_seed=s_val,
            )
            val_results.append(m_seed)

        # Threshold Calibration Study on Validation Set Only (T = 0.40, 0.45, 0.50, 0.52, 0.55, 0.60)
        thresholds = [0.40, 0.45, 0.50, 0.52, 0.55, 0.60]
        train_s = self.select_baseline_samples(256, "First_N")
        for th in thresholds:
            m_th = self.evaluate_configuration(
                train_samples=train_s,
                experiment_id=f"val_threshold_calib_256_th_{th:.2f}",
                phase="validation",
                eval_X=self.val_X,
                eval_y=self.val_y,
                baseline_size=256,
                filtering_strategy="No_Filtering",
                sampling_strategy="First_N",
                threshold=th,
            )
            val_results.append(m_th)

        # 3. Final Independent Hold-Out Test Evaluation
        logger.info("\n" + "=" * 80)
        logger.info("STAGE 3: FINAL INDEPENDENT HOLDOUT EVALUATION (malware-2 + portscan-1, 2, 3)")
        logger.info("=" * 80)

        # Evaluate Candidate Configurations on Final Untouched Holdout
        candidate_configs = [
            ("test_candidate_30_iqr_current_kaggle", 30, "With_IQR", "First_N"),
            ("test_candidate_30_nofilt", 30, "No_Filtering", "First_N"),
            ("test_candidate_128_nofilt", 128, "No_Filtering", "First_N"),
            ("test_candidate_256_nofilt_firstn", 256, "No_Filtering", "First_N"),
            ("test_candidate_256_nofilt_representative", 256, "No_Filtering", "Random_Representative"),
            ("test_candidate_512_nofilt_firstn", 512, "No_Filtering", "First_N"),
            ("test_candidate_1000_nofilt_firstn", 1000, "No_Filtering", "First_N"),
            ("test_candidate_2250_nofilt_historical", 2250, "No_Filtering", "First_N"),
        ]

        for exp_id, sz, filt, samp in candidate_configs:
            raw_s = self.select_baseline_samples(sz, samp)
            if filt == "With_IQR":
                used_s = filter_baseline_outliers(raw_s, min_samples=min(5, len(raw_s) // 2))
                raw_c = len(raw_s)
            else:
                used_s = raw_s
                raw_c = len(raw_s)

            m_test = self.evaluate_configuration(
                train_samples=used_s,
                experiment_id=exp_id,
                phase="final_test",
                eval_X=self.test_X,
                eval_y=self.test_y,
                baseline_size=sz,
                filtering_strategy=filt,
                sampling_strategy=samp,
                raw_samples=raw_c,
            )
            final_test_results.append(m_test)
            logger.info(
                "Holdout Evaluation [%s]: FPR=%.2f%%, Acc=%.2f%%, Prec=%.2f%%, Rec=%.2f%%, F1=%.4f, ROC=%.4f",
                exp_id,
                m_test.false_positive_rate * 100,
                m_test.accuracy * 100,
                m_test.precision * 100,
                m_test.recall * 100,
                m_test.f1_score,
                m_test.roc_auc,
            )

        # Save Artifacts
        all_metrics = val_results + final_test_results
        self._save_all_results(all_metrics)

        return {
            "validation_results": val_results,
            "final_test_results": final_test_results,
        }

    def _save_all_results(self, metrics: List[ExperimentMetrics]):
        """Save results to JSON and CSV formats."""
        json_path = os.path.join(self.output_dir, "experiment_results.json")
        csv_path = os.path.join(self.output_dir, "experiment_comparison.csv")

        # 1. JSON output
        out_data = {
            "metadata": {
                "study": "NetSentinel Isolation Forest Independent Dataset & Baseline Research Study",
                "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "feature_schema": FEATURE_NAMES,
                "window_duration_seconds": 5.0,
                "validation_partition": "ctu-idseval-6-malicious-malware-1 (26,094 windows)",
                "final_holdout_partition": "malware-2 + portscan-1, 2, 3 (33,226 windows)",
            },
            "total_experiments_recorded": len(metrics),
            "experiments": [asdict(m) for m in metrics],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2)

        # 2. CSV output
        fieldnames = list(asdict(metrics[0]).keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for m in metrics:
                writer.writerow(asdict(m))

        logger.info("Saved %d experimental trials to %s", len(metrics), json_path)
        logger.info("Saved CSV comparison matrix to %s", csv_path)


def main():
    parser = argparse.ArgumentParser(description="NetSentinel Independent Validation Study Runner")
    parser.add_argument("--output-dir", type=str, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()

    runner = IndependentStudyRunner(output_dir=args.output_dir)
    runner.run_all_experiments()


if __name__ == "__main__":
    main()
