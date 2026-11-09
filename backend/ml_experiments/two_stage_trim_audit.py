"""NetSentinel Isolation Forest: Comprehensive Two-Stage Trim Audit & Pipeline Verification.

Rigorous audit of the Two-Stage Trimmed baseline defense:
1. Investigates whether Two-Stage Trim genuinely purges attack contamination
   or simply discards legitimate unusual/high-throughput benign traffic.
2. Evaluates across contamination levels: 0% (clean), 1%, 5%, 10%, 20%.
3. Evaluates across attack types: Malware C2, Port Scanning, Mixed.
4. Compares:
   - A. No Filtering
   - B. Production 3.0x IQR Filtering
   - C. Two-Stage Trim 2% (98th percentile cutoff)
   - D. Two-Stage Trim 5% (95th percentile cutoff)
   - E. Two-Stage Trim 10% (90th percentile cutoff)
5. Measures ground-truth filter behavior:
   - Attack removal rate (True Trimming Rate)
   - Benign removal rate (False Trimming Rate)
   - Retained baseline purity
   - Feature distribution comparison of trimmed vs retained benign samples.
6. Evaluates the complete candidate production pipeline (512 windows + Two-Stage Trim + iForest)
   on the full development protocol with exact confusion matrices and downstream metrics.
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
logger = logging.getLogger("netsentinel.two_stage_trim_audit")

CACHE_PATH = "/tmp/ctu_windows_cache.pkl"
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "reports", "two_stage_trim_investigation")


@dataclass
class FilterAuditRecord:
    experiment_id: str
    baseline_size: int
    contamination_rate: float
    contaminant_type: str
    filter_strategy: str
    trim_percentage: float
    n_initial_total: int
    n_initial_clean: int
    n_initial_attack: int
    n_removed_total: int
    n_removed_clean: int
    n_removed_attack: int
    n_retained_total: int
    n_retained_clean: int
    n_retained_attack: int
    attack_removal_rate: float  # True Trimming Rate: attack_removed / initial_attack
    benign_removal_rate: float  # False Trimming Rate: clean_removed / initial_clean
    retained_baseline_purity: float  # retained_clean / retained_total
    filter_execution_time_sec: float
    # Downstream metrics on validation set (malware-1)
    val_accuracy: float
    val_precision: float
    val_recall: float
    val_f1: float
    val_fpr: float
    val_fnr: float
    val_roc_auc: float
    val_pr_auc: float
    val_tp: int
    val_tn: int
    val_fp: int
    val_fn: int
    # Downstream metrics on holdout set (malware-2 + portscans)
    holdout_accuracy: float
    holdout_precision: float
    holdout_recall: float
    holdout_f1: float
    holdout_fpr: float
    holdout_fnr: float
    holdout_roc_auc: float
    holdout_pr_auc: float
    holdout_tp: int
    holdout_tn: int
    holdout_fp: int
    holdout_fn: int
    # Latencies & scores
    training_time_sec: float
    inference_latency_ms: float
    holdout_separation_margin: float


def execute_two_stage_trim(
    labeled_samples: List[Tuple[List[float], int]],
    trim_percentage: float,
) -> Tuple[List[Tuple[List[float], int]], List[Tuple[List[float], int]], float]:
    """Applies two-stage trim on labeled baseline samples, returning retained and removed sets."""
    t0 = time.perf_counter()
    if len(labeled_samples) < 20 or trim_percentage <= 0.0:
        return list(labeled_samples), [], time.perf_counter() - t0

    features = [s[0] for s in labeled_samples]
    init_model = IsolationForestModel(n_estimators=50, random_state=42)
    init_model.train(features)

    X = np.array(features)
    raw_scores = init_model.model.decision_function(X)
    norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)

    cutoff_percentile = 100.0 - trim_percentage
    cutoff_score = np.percentile(norm_scores, cutoff_percentile)

    retained = []
    removed = []
    for i, item in enumerate(labeled_samples):
        if norm_scores[i] <= cutoff_score:
            retained.append(item)
        else:
            removed.append(item)

    filt_time = time.perf_counter() - t0
    # Safeguard minimum samples
    if len(retained) < 10:
        return list(labeled_samples), [], filt_time

    return retained, removed, filt_time


def execute_iqr_filter(
    labeled_samples: List[Tuple[List[float], int]],
) -> Tuple[List[Tuple[List[float], int]], List[Tuple[List[float], int]], float]:
    """Applies existing production filter_baseline_outliers on labeled baseline samples."""
    t0 = time.perf_counter()
    features = [s[0] for s in labeled_samples]
    # We apply the exact logic of filter_baseline_outliers but preserve ground truth tracking
    retained_features = filter_baseline_outliers(features, min_samples=min(5, len(features) // 2))
    
    # Identify retained vs removed by matching vectors
    retained_set = set(tuple(f) for f in retained_features)
    retained = []
    removed = []
    for item in labeled_samples:
        if tuple(item[0]) in retained_set:
            retained.append(item)
        else:
            removed.append(item)

    filt_time = time.perf_counter() - t0
    return retained, removed, filt_time


class TwoStageTrimAuditor:
    """Orchestrates comprehensive audit of baseline filtering defenses."""

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        if not os.path.exists(CACHE_PATH):
            raise FileNotFoundError(f"CTU cache not found at {CACHE_PATH}.")

        logger.info("Loading extracted windows from cache...")
        with open(CACHE_PATH, "rb") as f:
            cache = pickle.load(f)

        self.clean_train_pool: List[List[float]] = cache["clean_train_windows"]
        test_caps = cache["test_captures_data"]

        # Development Validation Partition: malware-1
        self.val_X = test_caps["ctu-idseval-6-malicious-malware-1"]["X"]
        self.val_y = test_caps["ctu-idseval-6-malicious-malware-1"]["y"]

        # Development Holdout Partition: malware-2 + portscan-1, 2, 3
        holdout_caps = [
            "ctu-idseval-6-malicious-portscan-1",
            "ctu-idseval-6-malicious-portscan-2",
            "ctu-idseval-6-malicious-portscan-3",
            "ctu-idseval-6-malicious-malware-2",
        ]
        self.holdout_X = np.vstack([test_caps[c]["X"] for c in holdout_caps])
        self.holdout_y = np.concatenate([test_caps[c]["y"] for c in holdout_caps])

        # Malicious pools for injection
        mal_idx = np.where(test_caps["ctu-idseval-6-malicious-malware-2"]["y"] == 1)[0]
        self.malware_attack_pool = test_caps["ctu-idseval-6-malicious-malware-2"]["X"][mal_idx].tolist()

        ps_idx = np.where(test_caps["ctu-idseval-6-malicious-portscan-3"]["y"] == 1)[0]
        self.portscan_attack_pool = test_caps["ctu-idseval-6-malicious-portscan-3"]["X"][ps_idx].tolist()

        logger.info(
            "Auditor initialized:\n"
            "  - Clean Baseline Pool: %d windows\n"
            "  - Validation Set (malware-1): %d windows (%d benign, %d mal)\n"
            "  - Holdout Set (malware-2 + ps): %d windows (%d benign, %d mal)",
            len(self.clean_train_pool),
            len(self.val_X),
            int(np.sum(self.val_y == 0)),
            int(np.sum(self.val_y == 1)),
            len(self.holdout_X),
            int(np.sum(self.holdout_y == 0)),
            int(np.sum(self.holdout_y == 1)),
        )

    def generate_labeled_baseline(
        self,
        baseline_size: int,
        contamination_rate: float,
        contaminant_type: str,
        seed: int = 42,
    ) -> List[Tuple[List[float], int]]:
        """Constructs labeled baseline where label 0 = benign, label 1 = attack contaminant."""
        n_attack = int(round(baseline_size * contamination_rate))
        n_clean = baseline_size - n_attack

        clean_subset = [(self.clean_train_pool[i], 0) for i in range(n_clean)]

        if n_attack == 0:
            return clean_subset

        rng = np.random.RandomState(seed)
        if contaminant_type == "malware":
            idx = rng.choice(len(self.malware_attack_pool), size=n_attack, replace=(len(self.malware_attack_pool) < n_attack))
            attack_subset = [(self.malware_attack_pool[i], 1) for i in idx]
        elif contaminant_type == "portscan":
            idx = rng.choice(len(self.portscan_attack_pool), size=n_attack, replace=(len(self.portscan_attack_pool) < n_attack))
            attack_subset = [(self.portscan_attack_pool[i], 1) for i in idx]
        elif contaminant_type == "mixed":
            n_m = n_attack // 2
            n_p = n_attack - n_m
            idx_m = rng.choice(len(self.malware_attack_pool), size=n_m, replace=(len(self.malware_attack_pool) < n_m))
            idx_p = rng.choice(len(self.portscan_attack_pool), size=n_p, replace=(len(self.portscan_attack_pool) < n_p))
            attack_subset = [(self.malware_attack_pool[i], 1) for i in idx_m] + [(self.portscan_attack_pool[i], 1) for i in idx_p]
        else:
            raise ValueError(f"Unknown contaminant type: {contaminant_type}")

        combined = clean_subset + attack_subset
        rng.shuffle(combined)
        return combined

    def evaluate_filter_strategy(
        self,
        labeled_baseline: List[Tuple[List[float], int]],
        experiment_id: str,
        baseline_size: int,
        contamination_rate: float,
        contaminant_type: str,
        filter_strategy: str,
        trim_percentage: float = 0.0,
    ) -> FilterAuditRecord:
        """Applies filter, tracks ground-truth removal, trains model, and evaluates on validation and holdout."""
        n_init_tot = len(labeled_baseline)
        n_init_clean = sum(1 for _, label in labeled_baseline if label == 0)
        n_init_att = sum(1 for _, label in labeled_baseline if label == 1)

        # Apply specific filtering strategy
        if filter_strategy == "No_Filtering":
            retained = list(labeled_baseline)
            removed = []
            filt_time = 0.0
        elif filter_strategy == "Production_IQR":
            retained, removed, filt_time = execute_iqr_filter(labeled_baseline)
        elif filter_strategy.startswith("Two_Stage_Trim"):
            retained, removed, filt_time = execute_two_stage_trim(labeled_baseline, trim_percentage=trim_percentage)
        else:
            raise ValueError(f"Unknown filter strategy: {filter_strategy}")

        # Compute ground-truth filter effectiveness
        n_rem_clean = sum(1 for _, label in removed if label == 0)
        n_rem_att = sum(1 for _, label in removed if label == 1)
        n_ret_clean = sum(1 for _, label in retained if label == 0)
        n_ret_att = sum(1 for _, label in retained if label == 1)

        att_rem_rate = float(n_rem_att / n_init_att) if n_init_att > 0 else 0.0
        ben_rem_rate = float(n_rem_clean / n_init_clean) if n_init_clean > 0 else 0.0
        purity = float(n_ret_clean / len(retained)) if len(retained) > 0 else 0.0

        # Train final model on retained baseline (features only)
        train_features = [s[0] for s in retained]
        t0_train = time.perf_counter()
        model = IsolationForestModel(
            n_estimators=100,
            max_samples="auto",
            contamination="auto",
            random_state=42,
            min_samples=min(5, len(train_features) // 2),
        )
        model.train(train_features)
        train_time = time.perf_counter() - t0_train

        # Latency check (single window inference)
        t0_lat = time.perf_counter()
        bench_count = min(100, len(self.val_X))
        for i in range(bench_count):
            _ = model.predict(self.val_X[i].tolist())
        lat_ms = ((time.perf_counter() - t0_lat) / bench_count) * 1000.0

        # 1. Validation evaluation (malware-1)
        raw_val = model.model.decision_function(self.val_X)
        norm_val = np.clip(0.5 - raw_val, 0.0, 1.0)
        preds_val = (norm_val > 0.50).astype(int)
        tn_v, fp_v, fn_v, tp_v = confusion_matrix(self.val_y, preds_val, labels=[0, 1]).ravel()
        acc_v = float(accuracy_score(self.val_y, preds_val))
        prec_v = float(precision_score(self.val_y, preds_val, zero_division=0))
        rec_v = float(recall_score(self.val_y, preds_val, zero_division=0))
        f1_v = float(f1_score(self.val_y, preds_val, zero_division=0))
        fpr_v = float(fp_v / (fp_v + tn_v)) if (fp_v + tn_v) > 0 else 0.0
        fnr_v = float(fn_v / (fn_v + tp_v)) if (fn_v + tp_v) > 0 else 0.0
        roc_v = float(roc_auc_score(self.val_y, norm_val))
        p_c_v, r_c_v, _ = precision_recall_curve(self.val_y, norm_val)
        pr_v = float(auc(r_c_v, p_c_v))

        # 2. Holdout evaluation (malware-2 + portscans)
        raw_hold = model.model.decision_function(self.holdout_X)
        norm_hold = np.clip(0.5 - raw_hold, 0.0, 1.0)
        preds_hold = (norm_hold > 0.50).astype(int)
        tn_h, fp_h, fn_h, tp_h = confusion_matrix(self.holdout_y, preds_hold, labels=[0, 1]).ravel()
        acc_h = float(accuracy_score(self.holdout_y, preds_hold))
        prec_h = float(precision_score(self.holdout_y, preds_hold, zero_division=0))
        rec_h = float(recall_score(self.holdout_y, preds_hold, zero_division=0))
        f1_h = float(f1_score(self.holdout_y, preds_hold, zero_division=0))
        fpr_h = float(fp_h / (fp_h + tn_h)) if (fp_h + tn_h) > 0 else 0.0
        fnr_h = float(fn_h / (fn_h + tp_h)) if (fn_h + tp_h) > 0 else 0.0
        roc_h = float(roc_auc_score(self.holdout_y, norm_hold))
        p_c_h, r_c_h, _ = precision_recall_curve(self.holdout_y, norm_hold)
        pr_h = float(auc(r_c_h, p_c_h))

        ben_scores_h = norm_hold[self.holdout_y == 0]
        mal_scores_h = norm_hold[self.holdout_y == 1]
        sep_h = float(np.mean(mal_scores_h) - np.mean(ben_scores_h))

        return FilterAuditRecord(
            experiment_id=experiment_id,
            baseline_size=baseline_size,
            contamination_rate=contamination_rate,
            contaminant_type=contaminant_type,
            filter_strategy=filter_strategy,
            trim_percentage=trim_percentage,
            n_initial_total=n_init_tot,
            n_initial_clean=n_init_clean,
            n_initial_attack=n_init_att,
            n_removed_total=len(removed),
            n_removed_clean=n_rem_clean,
            n_removed_attack=n_rem_att,
            n_retained_total=len(retained),
            n_retained_clean=n_ret_clean,
            n_retained_attack=n_ret_att,
            attack_removal_rate=round(att_rem_rate, 4),
            benign_removal_rate=round(ben_rem_rate, 4),
            retained_baseline_purity=round(purity, 4),
            filter_execution_time_sec=round(filt_time, 4),
            val_accuracy=round(acc_v, 4),
            val_precision=round(prec_v, 4),
            val_recall=round(rec_v, 4),
            val_f1=round(f1_v, 4),
            val_fpr=round(fpr_v, 4),
            val_fnr=round(fnr_v, 4),
            val_roc_auc=round(roc_v, 4),
            val_pr_auc=round(pr_v, 4),
            val_tp=int(tp_v),
            val_tn=int(tn_v),
            val_fp=int(fp_v),
            val_fn=int(fn_v),
            holdout_accuracy=round(acc_h, 4),
            holdout_precision=round(prec_h, 4),
            holdout_recall=round(rec_h, 4),
            holdout_f1=round(f1_h, 4),
            holdout_fpr=round(fpr_h, 4),
            holdout_fnr=round(fnr_h, 4),
            holdout_roc_auc=round(roc_h, 4),
            holdout_pr_auc=round(pr_h, 4),
            holdout_tp=int(tp_h),
            holdout_tn=int(tn_h),
            holdout_fp=int(fp_h),
            holdout_fn=int(fn_h),
            training_time_sec=round(train_time, 4),
            inference_latency_ms=round(lat_ms, 4),
            holdout_separation_margin=round(sep_h, 4),
        )

    def run_clean_baseline_trim_profile(self) -> Dict[str, Any]:
        """Analyzes what kinds of benign windows get pruned on a 100% clean baseline."""
        logger.info("Profiling feature characteristics of trimmed benign windows on clean baseline (N=512)...")
        clean_512 = [(self.clean_train_pool[i], 0) for i in range(512)]

        # Two-stage trim at 5%
        ret_5, rem_5, _ = execute_two_stage_trim(clean_512, trim_percentage=5.0)
        # IQR filter
        ret_iqr, rem_iqr, _ = execute_iqr_filter(clean_512)

        ret_5_arr = np.array([s[0] for s in ret_5])
        rem_5_arr = np.array([s[0] for s in rem_5])
        ret_iqr_arr = np.array([s[0] for s in ret_iqr])
        rem_iqr_arr = np.array([s[0] for s in rem_iqr])

        profile = {
            "n_initial_clean": 512,
            "two_stage_trim_5pct": {
                "n_retained": len(ret_5),
                "n_removed": len(rem_5),
                "feature_comparison": {},
            },
            "iqr_filter": {
                "n_retained": len(ret_iqr),
                "n_removed": len(rem_iqr),
                "feature_comparison": {},
            },
        }

        for i, name in enumerate(FEATURE_NAMES):
            profile["two_stage_trim_5pct"]["feature_comparison"][name] = {
                "retained_mean": round(float(np.mean(ret_5_arr[:, i])), 3),
                "removed_mean": round(float(np.mean(rem_5_arr[:, i])), 3) if len(rem_5) > 0 else 0.0,
            }
            profile["iqr_filter"]["feature_comparison"][name] = {
                "retained_mean": round(float(np.mean(ret_iqr_arr[:, i])), 3),
                "removed_mean": round(float(np.mean(rem_iqr_arr[:, i])), 3) if len(rem_iqr) > 0 else 0.0,
            }

        return profile

    def run_all_audits(self) -> List[FilterAuditRecord]:
        """Executes full comparative audit of baseline filters across contamination levels."""
        records: List[FilterAuditRecord] = []
        contamination_rates = [0.00, 0.01, 0.05, 0.10, 0.20]
        contaminant_types = ["malware", "portscan", "mixed"]
        baseline_sz = 512

        logger.info("=" * 80)
        logger.info("STARTING TWO-STAGE TRIM AUDIT EXPERIMENTS (N=512)")
        logger.info("=" * 80)

        for rate in contamination_rates:
            for c_type in contaminant_types:
                if rate == 0.0 and c_type != "malware":
                    continue

                labeled_base = self.generate_labeled_baseline(
                    baseline_size=baseline_sz,
                    contamination_rate=rate,
                    contaminant_type=c_type,
                )

                strategies = [
                    ("No_Filtering", 0.0),
                    ("Production_IQR", 0.0),
                    ("Two_Stage_Trim_2%", 2.0),
                    ("Two_Stage_Trim_5%", 5.0),
                    ("Two_Stage_Trim_10%", 10.0),
                ]

                for strat_name, trim_p in strategies:
                    exp_id = f"audit_sz512_rate{int(rate*100):02d}_{c_type}_{strat_name}"
                    rec = self.evaluate_filter_strategy(
                        labeled_baseline=labeled_base,
                        experiment_id=exp_id,
                        baseline_size=baseline_sz,
                        contamination_rate=rate,
                        contaminant_type=c_type,
                        filter_strategy=strat_name,
                        trim_percentage=trim_p,
                    )
                    records.append(rec)
                    logger.info(
                        "Rate=%2d%% | Type=%-8s | Strat=%-18s | AttRem=%5.1f%%, BenRem=%5.1f%%, Pur=%5.1f%% | HoldRec=%.2f%%, HoldFPR=%.2f%%, Sep=%.3f",
                        int(rate * 100),
                        c_type,
                        strat_name,
                        rec.attack_removal_rate * 100,
                        rec.benign_removal_rate * 100,
                        rec.retained_baseline_purity * 100,
                        rec.holdout_recall * 100,
                        rec.holdout_fpr * 100,
                        rec.holdout_separation_margin,
                    )

        clean_profile = self.run_clean_baseline_trim_profile()
        self._save_results(records, clean_profile)
        return records

    def _save_results(self, records: List[FilterAuditRecord], clean_profile: Dict[str, Any]):
        """Persists records to JSON and CSV formats."""
        json_path = os.path.join(self.output_dir, "two_stage_trim_audit_results.json")
        csv_path = os.path.join(self.output_dir, "two_stage_trim_audit_comparison.csv")
        profile_path = os.path.join(self.output_dir, "clean_baseline_trim_profile.json")

        payload = {
            "metadata": {
                "study": "NetSentinel Isolation Forest Two-Stage Trim & Baseline Filter Audit",
                "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "total_trials": len(records),
                "baseline_size": 512,
            },
            "records": [asdict(r) for r in records],
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(clean_profile, f, indent=2)

        if records:
            fieldnames = list(asdict(records[0]).keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in records:
                    writer.writerow(asdict(r))

        logger.info("Saved audit records to %s and %s", json_path, csv_path)


def main():
    parser = argparse.ArgumentParser(description="Two-Stage Trim Audit Runner")
    parser.add_argument("--output-dir", type=str, default=OUTPUT_DIR, help="Output directory")
    args = parser.parse_args()

    auditor = TwoStageTrimAuditor(output_dir=args.output_dir)
    auditor.run_all_audits()


if __name__ == "__main__":
    main()
