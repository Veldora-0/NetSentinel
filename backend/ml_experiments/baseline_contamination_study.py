"""NetSentinel Isolation Forest: Production Baseline Contamination Study.

Investigates the resilience of unsupervised Isolation Forest anomaly detection
when cold-start baseline traffic is contaminated with unlabeled attack windows.

Simulation Scope:
- Baseline sizes: 30 (current production), 128, 256, 512 windows
- Contamination levels: 0.0% (clean), 1.0%, 5.0%, 10.0%, 20.0%
- Attack contaminant types:
  1. Malware C2 / beaconing traffic (from CTU-IDSEVAL-6 malware captures)
  2. Reconnaissance / port scanning traffic (from CTU-IDSEVAL-6 portscan captures)
  3. Mixed malicious traffic
- Defenses evaluated:
  1. No_Defense (Standard Isolation Forest with contamination="auto")
  2. Contamination_Tuned (Isolation Forest with contamination=0.05)
  3. Production_IQR (Current 3.0x IQR volumetric filter)
  4. Two_Stage_Trimmed (Iterative Isolation Forest baseline self-filtering)
- Metrics tracked:
  Accuracy, Precision, Recall, F1, FPR, FNR, ROC-AUC, PR-AUC,
  Score Distributions (benign/malicious mean & std), Separation Margin.
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
from ml.model import IsolationForestModel

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netsentinel.contamination_study")

CACHE_PATH = "/tmp/ctu_windows_cache.pkl"
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports", "contamination_investigation")


@dataclass
class ContaminationMetrics:
    experiment_id: str
    baseline_size: int
    contamination_rate: float
    contaminant_type: str
    defense_strategy: str
    n_clean_injected: int
    n_attack_injected: int
    actual_used_samples: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: float
    pr_auc: float
    benign_score_mean: float
    benign_score_std: float
    malicious_score_mean: float
    malicious_score_std: float
    separation_margin: float
    training_time_sec: float


def two_stage_trim_defense(raw_baseline: List[List[float]], trim_percentile: float = 95.0) -> List[List[float]]:
    """Defensive baseline filter: train initial iForest, trim windows with anomaly score above percentile."""
    if len(raw_baseline) < 20:
        return raw_baseline
    
    init_model = IsolationForestModel(n_estimators=50, random_state=42)
    init_model.train(raw_baseline)
    
    X = np.array(raw_baseline)
    raw_scores = init_model.model.decision_function(X)
    norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
    
    cutoff = np.percentile(norm_scores, trim_percentile)
    retained = [raw_baseline[i] for i in range(len(raw_baseline)) if norm_scores[i] <= cutoff]
    
    # Ensure minimum sample count preserved
    if len(retained) < 10:
        return raw_baseline
    return retained


class BaselineContaminationRunner:
    """Simulates real-world baseline contamination during cold-start collection."""

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        if not os.path.exists(CACHE_PATH):
            raise FileNotFoundError(f"Extracted windows cache not found at {CACHE_PATH}.")

        logger.info("Loading extracted windows from %s...", CACHE_PATH)
        with open(CACHE_PATH, "rb") as f:
            cache = pickle.load(f)

        self.clean_train_pool: List[List[float]] = cache["clean_train_windows"]
        test_caps = cache["test_captures_data"]

        # Evaluation partitions
        self.val_X = test_caps["ctu-idseval-6-malicious-malware-1"]["X"]
        self.val_y = test_caps["ctu-idseval-6-malicious-malware-1"]["y"]

        # Malicious pools for injection
        malware_idx = np.where(test_caps["ctu-idseval-6-malicious-malware-2"]["y"] == 1)[0]
        self.malware_attack_pool = test_caps["ctu-idseval-6-malicious-malware-2"]["X"][malware_idx].tolist()

        ps_idx = np.where(test_caps["ctu-idseval-6-malicious-portscan-3"]["y"] == 1)[0]
        self.portscan_attack_pool = test_caps["ctu-idseval-6-malicious-portscan-3"]["X"][ps_idx].tolist()

        logger.info(
            "Loaded data pools:\n"
            "  - Clean Baseline Pool: %d windows\n"
            "  - Malware Attack Pool: %d windows\n"
            "  - Portscan Attack Pool: %d windows\n"
            "  - Validation Test Set: %d windows (%d benign, %d malicious)",
            len(self.clean_train_pool),
            len(self.malware_attack_pool),
            len(self.portscan_attack_pool),
            len(self.val_X),
            int(np.sum(self.val_y == 0)),
            int(np.sum(self.val_y == 1)),
        )

    def generate_contaminated_baseline(
        self,
        baseline_size: int,
        contamination_rate: float,
        contaminant_type: str,
        seed: int = 42,
    ) -> Tuple[List[List[float]], int, int]:
        """Constructs a baseline of given size with exact contamination proportion."""
        n_attack = int(round(baseline_size * contamination_rate))
        n_clean = baseline_size - n_attack

        # Draw clean windows
        clean_subset = self.clean_train_pool[:n_clean]

        if n_attack == 0:
            return clean_subset, n_clean, 0

        rng = np.random.RandomState(seed)
        if contaminant_type == "malware":
            idx = rng.choice(len(self.malware_attack_pool), size=n_attack, replace=(len(self.malware_attack_pool) < n_attack))
            attack_subset = [self.malware_attack_pool[i] for i in idx]
        elif contaminant_type == "portscan":
            idx = rng.choice(len(self.portscan_attack_pool), size=n_attack, replace=(len(self.portscan_attack_pool) < n_attack))
            attack_subset = [self.portscan_attack_pool[i] for i in idx]
        elif contaminant_type == "mixed":
            n_m = n_attack // 2
            n_p = n_attack - n_m
            idx_m = rng.choice(len(self.malware_attack_pool), size=n_m, replace=(len(self.malware_attack_pool) < n_m))
            idx_p = rng.choice(len(self.portscan_attack_pool), size=n_p, replace=(len(self.portscan_attack_pool) < n_p))
            attack_subset = [self.malware_attack_pool[i] for i in idx_m] + [self.portscan_attack_pool[i] for i in idx_p]
        else:
            raise ValueError(f"Unknown contaminant type: {contaminant_type}")

        contaminated = clean_subset + attack_subset
        # Shuffle contaminated baseline
        rng.shuffle(contaminated)
        return contaminated, n_clean, n_attack

    def evaluate_model(
        self,
        train_samples: List[List[float]],
        experiment_id: str,
        baseline_size: int,
        contamination_rate: float,
        contaminant_type: str,
        defense_strategy: str,
        n_clean: int,
        n_attack: int,
        contamination_param: Any = "auto",
        threshold: float = 0.50,
    ) -> ContaminationMetrics:
        """Trains Isolation Forest on baseline and computes comprehensive metrics on validation set."""
        t0 = time.perf_counter()
        model = IsolationForestModel(
            n_estimators=100,
            max_samples="auto",
            contamination=contamination_param,
            random_state=42,
            min_samples=min(5, len(train_samples) // 2),
        )
        model.train(train_samples)
        train_time = time.perf_counter() - t0

        raw_scores = model.model.decision_function(self.val_X)
        norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
        preds = (norm_scores > threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(self.val_y, preds, labels=[0, 1]).ravel()
        acc = float(accuracy_score(self.val_y, preds))
        prec = float(precision_score(self.val_y, preds, zero_division=0))
        rec = float(recall_score(self.val_y, preds, zero_division=0))
        f1 = float(f1_score(self.val_y, preds, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        roc_auc = float(roc_auc_score(self.val_y, norm_scores))
        p_c, r_c, _ = precision_recall_curve(self.val_y, norm_scores)
        pr_auc = float(auc(r_c, p_c))

        ben_scores = norm_scores[self.val_y == 0]
        mal_scores = norm_scores[self.val_y == 1]
        ben_mean = float(np.mean(ben_scores))
        ben_std = float(np.std(ben_scores))
        mal_mean = float(np.mean(mal_scores))
        mal_std = float(np.std(mal_scores))
        separation = mal_mean - ben_mean

        return ContaminationMetrics(
            experiment_id=experiment_id,
            baseline_size=baseline_size,
            contamination_rate=contamination_rate,
            contaminant_type=contaminant_type,
            defense_strategy=defense_strategy,
            n_clean_injected=n_clean,
            n_attack_injected=n_attack,
            actual_used_samples=len(train_samples),
            accuracy=round(acc, 4),
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            roc_auc=round(roc_auc, 4),
            pr_auc=round(pr_auc, 4),
            benign_score_mean=round(ben_mean, 4),
            benign_score_std=round(ben_std, 4),
            malicious_score_mean=round(mal_mean, 4),
            malicious_score_std=round(mal_std, 4),
            separation_margin=round(separation, 4),
            training_time_sec=round(train_time, 4),
        )

    def run_all(self) -> List[ContaminationMetrics]:
        """Runs full matrix of baseline sizes, contamination rates, and defense mechanisms."""
        results: List[ContaminationMetrics] = []

        baseline_sizes = [30, 128, 256, 512]
        contamination_rates = [0.00, 0.01, 0.05, 0.10, 0.20]
        contaminant_types = ["malware", "portscan", "mixed"]

        logger.info("=" * 80)
        logger.info("STARTING BASELINE CONTAMINATION EXPERIMENTAL SUITE")
        logger.info("=" * 80)

        # 1. Contamination Sweeps without Defense
        for sz in baseline_sizes:
            for rate in contamination_rates:
                for c_type in contaminant_types:
                    # Skip duplicate 0.0 rate runs for other types
                    if rate == 0.0 and c_type != "malware":
                        continue

                    raw_baseline, n_clean, n_attack = self.generate_contaminated_baseline(
                        baseline_size=sz,
                        contamination_rate=rate,
                        contaminant_type=c_type,
                    )

                    # A. No Defense (vanilla)
                    exp_id = f"contam_sz_{sz}_rate_{int(rate*100):02d}_{c_type}_nodefense"
                    m_no = self.evaluate_model(
                        train_samples=raw_baseline,
                        experiment_id=exp_id,
                        baseline_size=sz,
                        contamination_rate=rate,
                        contaminant_type=c_type,
                        defense_strategy="No_Defense",
                        n_clean=n_clean,
                        n_attack=n_attack,
                        contamination_param="auto",
                    )
                    results.append(m_no)

                    # B. Current Production IQR Filter Defense
                    filt_iqr = filter_baseline_outliers(raw_baseline, min_samples=min(5, len(raw_baseline) // 2))
                    exp_id_iqr = f"contam_sz_{sz}_rate_{int(rate*100):02d}_{c_type}_iqr"
                    m_iqr = self.evaluate_model(
                        train_samples=filt_iqr,
                        experiment_id=exp_id_iqr,
                        baseline_size=sz,
                        contamination_rate=rate,
                        contaminant_type=c_type,
                        defense_strategy="Production_IQR",
                        n_clean=n_clean,
                        n_attack=n_attack,
                        contamination_param="auto",
                    )
                    results.append(m_iqr)

                    # C. Two-Stage Score-Trimmed Defense (for sz >= 128 and rate > 0)
                    if sz >= 128 and rate > 0.0:
                        trim_pct = 100.0 * (1.0 - max(0.05, rate))
                        filt_trimmed = two_stage_trim_defense(raw_baseline, trim_percentile=trim_pct)
                        exp_id_trim = f"contam_sz_{sz}_rate_{int(rate*100):02d}_{c_type}_trimmed"
                        m_trim = self.evaluate_model(
                            train_samples=filt_trimmed,
                            experiment_id=exp_id_trim,
                            baseline_size=sz,
                            contamination_rate=rate,
                            contaminant_type=c_type,
                            defense_strategy="Two_Stage_Trimmed",
                            n_clean=n_clean,
                            n_attack=n_attack,
                            contamination_param="auto",
                        )
                        results.append(m_trim)

                    # D. Contamination Parameter Tuning (e.g. contamination=0.05)
                    if rate > 0.0 and sz >= 128:
                        exp_id_tuned = f"contam_sz_{sz}_rate_{int(rate*100):02d}_{c_type}_param05"
                        m_tuned = self.evaluate_model(
                            train_samples=raw_baseline,
                            experiment_id=exp_id_tuned,
                            baseline_size=sz,
                            contamination_rate=rate,
                            contaminant_type=c_type,
                            defense_strategy="Contamination_Param_0.05",
                            n_clean=n_clean,
                            n_attack=n_attack,
                            contamination_param=0.05,
                        )
                        results.append(m_tuned)

                    logger.info(
                        "Sz=%3d | Rate=%2d%% | Type=%-8s | NoDef: FPR=%.2f%%, Rec=%.2f%%, Sep=%.3f | IQR: FPR=%.2f%%, Rec=%.2f%%",
                        sz,
                        int(rate * 100),
                        c_type,
                        m_no.false_positive_rate * 100,
                        m_no.recall * 100,
                        m_no.separation_margin,
                        m_iqr.false_positive_rate * 100,
                        m_iqr.recall * 100,
                    )

        self._save_results(results)
        return results

    def _save_results(self, results: List[ContaminationMetrics]):
        """Persists contamination metrics to JSON and CSV."""
        json_path = os.path.join(self.output_dir, "contamination_results.json")
        csv_path = os.path.join(self.output_dir, "contamination_comparison.csv")

        payload = {
            "metadata": {
                "study": "NetSentinel Baseline Contamination & Defense Study",
                "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_trials": len(results),
            },
            "trials": [asdict(r) for r in results],
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        if results:
            fieldnames = list(asdict(results[0]).keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    writer.writerow(asdict(r))

        logger.info("Saved %d contamination trials to %s and %s", len(results), json_path, csv_path)


def main():
    parser = argparse.ArgumentParser(description="Baseline Contamination Study Runner")
    parser.add_argument("--output-dir", type=str, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()

    runner = BaselineContaminationRunner(output_dir=args.output_dir)
    runner.run_all()


if __name__ == "__main__":
    main()
