"""NetSentinel ML Experiment Runner.

Orchestrates Isolation Forest optimization experiments:
- Baseline generation & validation
- Feature expansion analysis (v1 vs candidate v2)
- Hyperparameter grid sweep
- Anomaly decision threshold calibration
- Detailed report generation in reports/ml_optimization/
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure backend directory is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np

from ml.feature_extractor import FEATURE_NAMES
from ml_experiments.data_loader import SyntheticTrafficGenerator, ValidationDataset
from ml_experiments.feature_experiments import (
    FeatureAnalyzer,
    CANONICAL_V1_FEATURES,
    CANDIDATE_V2_FEATURES,
)
from ml_experiments.hyperparameter_search import (
    IsolationForestOptimizer,
    HyperparameterTrial,
)
from ml_experiments.threshold_analysis import ThresholdAnalyzer

logger = logging.getLogger("netsentinel.ml_experiments.runner")


class MLOptimizationRunner:
    """Orchestrates Isolation Forest model optimization experiments."""

    def __init__(self, output_dir: Optional[str] = None, seed: int = 42):
        self.output_dir = output_dir or os.path.join(PROJECT_ROOT, "reports", "ml_optimization")
        self.seed = seed
        self.generator = SyntheticTrafficGenerator(seed=seed)
        os.makedirs(self.output_dir, exist_ok=True)

    def run_all_experiments(
        self,
        train_samples: int = 500,
        val_samples: int = 300,
        quick: bool = False,
    ) -> Dict[str, Any]:
        """Run complete ML optimization pipeline and return structured results."""
        t_start = time.time()
        print("=" * 70)
        print("NetSentinel ML Optimization Experiment Suite")
        print("=" * 70)
        print(f"Output Directory : {self.output_dir}")
        print(f"Random Seed      : {self.seed}")
        print(f"Execution Mode   : {'Quick' if quick else 'Exhaustive'}")
        print("=" * 70)

        # -------------------------------------------------------------
        # Experiment 1: Feature Expansion & Separation Analysis
        # -------------------------------------------------------------
        print("\n[1/4] Running Feature Separation & Correlation Analysis...")
        dataset_v1 = self.generator.build_benchmark_dataset(
            train_samples=train_samples,
            val_normal_samples=val_samples // 2,
            val_attack_samples=val_samples // 2,
            schema_version="v1",
            feature_names=CANONICAL_V1_FEATURES,
        )
        dataset_v2 = self.generator.build_benchmark_dataset(
            train_samples=train_samples,
            val_normal_samples=val_samples // 2,
            val_attack_samples=val_samples // 2,
            schema_version="v2",
            feature_names=CANDIDATE_V2_FEATURES,
        )

        analyzer_v1 = FeatureAnalyzer(CANONICAL_V1_FEATURES)
        analyzer_v2 = FeatureAnalyzer(CANDIDATE_V2_FEATURES)

        val_norm_v2 = dataset_v2.X_val[dataset_v2.y_val == 0]
        val_att_v2 = dataset_v2.X_val[dataset_v2.y_val == 1]
        v2_separation = analyzer_v2.compute_separation_scores(val_norm_v2, val_att_v2)
        v2_redundant = analyzer_v2.evaluate_redundant_features(dataset_v2.X_train_normal, threshold=0.92)

        print(f"  - Evaluated {len(CANONICAL_V1_FEATURES)} v1 features vs {len(CANDIDATE_V2_FEATURES)} v2 features.")
        print(f"  - Top discriminative features: {list(v2_separation.keys())[:5]}")
        print(f"  - Highly correlated feature pairs: {len(v2_redundant)}")

        # -------------------------------------------------------------
        # Experiment 2: Hyperparameter Grid Search (v1 vs v2)
        # -------------------------------------------------------------
        print("\n[2/4] Running Isolation Forest Hyperparameter Grid Search...")
        if quick:
            grid = {
                "n_estimators": [100, 200],
                "max_samples": [256, "auto"],
                "contamination": ["auto", 0.02],
                "max_features": [1.0],
                "bootstrap": [False],
                "random_state": [self.seed],
            }
        else:
            grid = {
                "n_estimators": [100, 150, 200, 250],
                "max_samples": [256, 512, "auto"],
                "contamination": ["auto", 0.01, 0.02, 0.05],
                "max_features": [0.85, 1.0],
                "bootstrap": [False],
                "random_state": [self.seed],
            }

        optimizer_v1 = IsolationForestOptimizer(dataset_v1)
        trials_v1 = optimizer_v1.run_grid_search(grid, default_threshold=0.50)
        best_v1 = optimizer_v1.get_best_trial()

        optimizer_v2 = IsolationForestOptimizer(dataset_v2)
        trials_v2 = optimizer_v2.run_grid_search(grid, default_threshold=0.50)
        best_v2 = optimizer_v2.get_best_trial()

        print(f"  - Completed {len(trials_v1)} configurations for v1 schema.")
        print(f"    Best v1: Acc={best_v1.accuracy:.4f}, F1={best_v1.f1_score:.4f}, Prec={best_v1.precision:.4f}, Rec={best_v1.recall:.4f}, FPR={best_v1.false_positive_rate:.4f}")
        print(f"  - Completed {len(trials_v2)} configurations for v2 schema.")
        print(f"    Best v2: Acc={best_v2.accuracy:.4f}, F1={best_v2.f1_score:.4f}, Prec={best_v2.precision:.4f}, Rec={best_v2.recall:.4f}, FPR={best_v2.false_positive_rate:.4f}")

        # -------------------------------------------------------------
        # Experiment 3: Calibrated Decision Threshold Sweep
        # -------------------------------------------------------------
        print("\n[3/4] Performing Decision Threshold Calibration Sweep...")
        # Fit model with best_v1 hyperparameters and sweep threshold
        from sklearn.ensemble import IsolationForest
        best_model_v1 = IsolationForest(
            n_estimators=best_v1.n_estimators,
            max_samples=best_v1.max_samples,
            contamination=best_v1.contamination,
            max_features=best_v1.max_features,
            bootstrap=best_v1.bootstrap,
            random_state=best_v1.random_state,
            n_jobs=-1,
        )
        best_model_v1.fit(dataset_v1.X_train_normal)
        raw_v1 = best_model_v1.decision_function(dataset_v1.X_val)
        norm_v1 = np.clip(0.5 - raw_v1, 0.0, 1.0)

        threshold_analyzer = ThresholdAnalyzer(dataset_v1.y_val, norm_v1)
        sweep_v1 = threshold_analyzer.sweep_thresholds(
            min_thresh=0.35, max_thresh=0.75, step=0.01, target_max_fpr=0.02
        )

        print(f"  - Best F1 Threshold : T={sweep_v1.best_f1_point.threshold:.2f} (F1={sweep_v1.best_f1_point.f1_score:.4f}, FPR={sweep_v1.best_f1_point.false_positive_rate:.4f})")
        print(f"  - Low-FPR Threshold : T={sweep_v1.best_low_fpr_point.threshold:.2f} (F1={sweep_v1.best_low_fpr_point.f1_score:.4f}, FPR={sweep_v1.best_low_fpr_point.false_positive_rate:.4f}, Rec={sweep_v1.best_low_fpr_point.recall:.4f})")
        print(f"  - Balanced Threshold: T={sweep_v1.best_balanced_point.threshold:.2f} (Youden's J={sweep_v1.best_balanced_point.youden_j:.4f})")

        # -------------------------------------------------------------
        # Experiment 4: Baseline Sample Sizing & Contamination Robustness
        # -------------------------------------------------------------
        print("\n[4/4] Evaluating Baseline Window Sample Sizes & Stability...")
        sample_sizes = [20, 50, 100, 250, 500] if not quick else [20, 100, 300]
        sizing_results: List[Dict[str, Any]] = []

        for sz in sample_sizes:
            sub_X_train = dataset_v1.X_train_normal[:sz]
            m_sz = IsolationForest(
                n_estimators=best_v1.n_estimators,
                max_samples=min(256, sz) if best_v1.max_samples != "auto" else "auto",
                contamination=best_v1.contamination,
                random_state=best_v1.random_state,
                n_jobs=-1,
            )
            m_sz.fit(sub_X_train)
            raw = m_sz.decision_function(dataset_v1.X_val)
            norm = np.clip(0.5 - raw, 0.0, 1.0)
            preds = (norm > sweep_v1.best_f1_point.threshold).astype(int)

            tp = int(np.sum((preds == 1) & (dataset_v1.y_val == 1)))
            tn = int(np.sum((preds == 0) & (dataset_v1.y_val == 0)))
            fp = int(np.sum((preds == 1) & (dataset_v1.y_val == 0)))
            fn = int(np.sum((preds == 0) & (dataset_v1.y_val == 1)))
            acc = round(float((tp + tn) / len(dataset_v1.y_val)), 4)
            prec = round(float(tp / (tp + fp)), 4) if (tp + fp) > 0 else 0.0
            rec = round(float(tp / (tp + fn)), 4) if (tp + fn) > 0 else 0.0
            f1 = round(float(2 * prec * rec / (prec + rec)), 4) if (prec + rec) > 0 else 0.0
            fpr = round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0

            sizing_results.append({
                "baseline_samples": sz,
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "false_positive_rate": fpr,
            })
            print(f"  - Baseline Size {sz:3d}: Acc={acc:.4f}, F1={f1:.4f}, Prec={prec:.4f}, Rec={rec:.4f}, FPR={fpr:.4f}")

        elapsed_total = round(time.time() - t_start, 2)

        # -------------------------------------------------------------
        # Export Artifacts
        # -------------------------------------------------------------
        report_data = {
            "experiment_timestamp": time.time(),
            "experiment_timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "execution_time_seconds": elapsed_total,
            "seed": self.seed,
            "feature_analysis": {
                "canonical_v1_count": len(CANONICAL_V1_FEATURES),
                "candidate_v2_count": len(CANDIDATE_V2_FEATURES),
                "v2_separation_scores": v2_separation,
                "v2_redundant_pairs": [{"feature_1": f1, "feature_2": f2, "correlation": c} for f1, f2, c in v2_redundant],
            },
            "hyperparameter_search": {
                "total_trials_v1": len(trials_v1),
                "best_v1_trial": best_v1.to_dict(),
                "total_trials_v2": len(trials_v2),
                "best_v2_trial": best_v2.to_dict(),
            },
            "threshold_calibration": {
                "best_f1_threshold": sweep_v1.best_f1_point.to_dict(),
                "best_low_fpr_threshold": sweep_v1.best_low_fpr_point.to_dict(),
                "best_balanced_threshold": sweep_v1.best_balanced_point.to_dict(),
            },
            "baseline_sizing": sizing_results,
        }

        self._export_reports(report_data, trials_v1, trials_v2, sweep_v1)
        print("\n" + "=" * 70)
        print(f"Experiments Complete ({elapsed_total}s). Reports saved to {self.output_dir}.")
        print("=" * 70)
        return report_data

    def _export_reports(
        self,
        report_data: Dict[str, Any],
        trials_v1: List[HyperparameterTrial],
        trials_v2: List[HyperparameterTrial],
        sweep_v1: Any,
    ) -> None:
        """Serialize JSON, CSV and Markdown summary reports."""
        # 1. JSON Report
        json_path = os.path.join(self.output_dir, "experiment_results.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # 2. CSV Comparison
        csv_path = os.path.join(self.output_dir, "experiment_comparison.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Schema", "TrialId", "n_estimators", "max_samples", "contamination",
                "max_features", "Accuracy", "Precision", "Recall", "F1_Score", "FPR",
                "ROC_AUC", "PR_AUC", "TrainTimeMs", "InfTimeMs"
            ])
            for t in trials_v1:
                writer.writerow([
                    "v1", t.trial_id, t.n_estimators, t.max_samples, t.contamination,
                    t.max_features, t.accuracy, t.precision, t.recall, t.f1_score,
                    t.false_positive_rate, t.roc_auc, t.pr_auc, t.training_time_ms, t.inference_time_ms
                ])
            for t in trials_v2:
                writer.writerow([
                    "v2", t.trial_id, t.n_estimators, t.max_samples, t.contamination,
                    t.max_features, t.accuracy, t.precision, t.recall, t.f1_score,
                    t.false_positive_rate, t.roc_auc, t.pr_auc, t.training_time_ms, t.inference_time_ms
                ])

        # 3. Threshold Analysis JSON
        thresh_path = os.path.join(self.output_dir, "threshold_analysis.json")
        with open(thresh_path, "w", encoding="utf-8") as f:
            json.dump(sweep_v1.to_dict(), f, indent=2)

        # 4. Markdown Summary
        best_v1 = report_data["hyperparameter_search"]["best_v1_trial"]
        best_thresh = report_data["threshold_calibration"]["best_f1_threshold"]
        low_fpr_thresh = report_data["threshold_calibration"]["best_low_fpr_threshold"]

        md_path = os.path.join(self.output_dir, "optimization_summary.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# NetSentinel Isolation Forest Optimization Summary\n\n")
            f.write(f"- **Execution Timestamp**: {report_data['experiment_timestamp_iso']}\n")
            f.write(f"- **Seed**: {report_data['seed']}\n\n")
            f.write("## 1. Optimal Hyperparameters\n\n")
            f.write(f"- `n_estimators`: {best_v1['n_estimators']}\n")
            f.write(f"- `max_samples`: `{best_v1['max_samples']}`\n")
            f.write(f"- `contamination`: `{best_v1['contamination']}`\n")
            f.write(f"- `max_features`: {best_v1['max_features']}\n")
            f.write(f"- `accuracy`: **{best_v1['accuracy'] * 100:.2f}%**\n")
            f.write(f"- `precision`: **{best_v1['precision'] * 100:.2f}%**\n")
            f.write(f"- `recall`: **{best_v1['recall'] * 100:.2f}%**\n")
            f.write(f"- `f1_score`: **{best_v1['f1_score'] * 100:.2f}%**\n")
            f.write(f"- `false_positive_rate`: **{best_v1['false_positive_rate'] * 100:.2f}%**\n\n")
            f.write("## 2. Decision Threshold Calibration\n\n")
            f.write(f"- **Best F1 Threshold**: `T = {best_thresh['threshold']:.2f}` (F1: {best_thresh['f1_score']:.4f}, FPR: {best_thresh['false_positive_rate']:.4f})\n")
            f.write(f"- **Low-FPR Threshold**: `T = {low_fpr_thresh['threshold']:.2f}` (Recall: {low_fpr_thresh['recall']:.4f}, FPR: {low_fpr_thresh['false_positive_rate']:.4f})\n\n")
            f.write("## 3. Baseline Window Sample Size Recommendations\n\n")
            f.write("| Baseline Samples | Accuracy | Precision | Recall | F1 Score | FPR |\n")
            f.write("|------------------|----------|-----------|--------|----------|-----|\n")
            for b in report_data["baseline_sizing"]:
                f.write(f"| {b['baseline_samples']} | {b['accuracy']:.4f} | {b['precision']:.4f} | {b['recall']:.4f} | {b['f1_score']:.4f} | {b['false_positive_rate']:.4f} |\n")


def main():
    parser = argparse.ArgumentParser(description="NetSentinel ML Optimization Experiment Runner")
    parser.add_argument("--quick", action="store_true", help="Run fast reduced parameter grid")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory to save optimization reports")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--train-samples", type=int, default=500, help="Training baseline sample count")
    parser.add_argument("--val-samples", type=int, default=300, help="Validation sample count")

    args = parser.parse_args()
    runner = MLOptimizationRunner(output_dir=args.output_dir, seed=args.seed)
    runner.run_all_experiments(
        train_samples=args.train_samples,
        val_samples=args.val_samples,
        quick=args.quick,
    )


if __name__ == "__main__":
    main()
