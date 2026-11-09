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
    CANONICAL_FEATURES,
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
        print(f"Features         : Canonical 13 features")
        print("=" * 70)

        # -------------------------------------------------------------
        # Experiment 1: Feature Separation & Correlation Analysis
        # -------------------------------------------------------------
        print("\n[1/4] Running Feature Separation & Correlation Analysis...")
        dataset = self.generator.build_benchmark_dataset(
            train_samples=train_samples,
            val_normal_samples=val_samples // 2,
            val_attack_samples=val_samples // 2,
            feature_names=CANONICAL_FEATURES,
        )

        analyzer = FeatureAnalyzer(CANONICAL_FEATURES)
        val_norm = dataset.X_val[dataset.y_val == 0]
        val_att = dataset.X_val[dataset.y_val == 1]
        separation_scores = analyzer.compute_separation_scores(val_norm, val_att)
        redundant_pairs = analyzer.evaluate_redundant_features(dataset.X_train_normal, threshold=0.92)

        print(f"  - Evaluated {len(CANONICAL_FEATURES)} canonical features.")
        print(f"  - Top discriminative features: {list(separation_scores.keys())[:5]}")
        print(f"  - Highly correlated feature pairs: {len(redundant_pairs)}")

        # -------------------------------------------------------------
        # Experiment 2: Hyperparameter Grid Search
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

        optimizer = IsolationForestOptimizer(dataset)
        trials = optimizer.run_grid_search(grid, default_threshold=0.50)
        best_trial = optimizer.get_best_trial()

        print(f"  - Completed {len(trials)} configurations for canonical 13-feature schema.")
        print(f"    Best: Acc={best_trial.accuracy:.4f}, F1={best_trial.f1_score:.4f}, Prec={best_trial.precision:.4f}, Rec={best_trial.recall:.4f}, FPR={best_trial.false_positive_rate:.4f}")

        # -------------------------------------------------------------
        # Experiment 3: Calibrated Decision Threshold Sweep
        # -------------------------------------------------------------
        print("\n[3/4] Performing Decision Threshold Calibration Sweep...")
        from sklearn.ensemble import IsolationForest
        best_model = IsolationForest(
            n_estimators=best_trial.n_estimators,
            max_samples=best_trial.max_samples,
            contamination=best_trial.contamination,
            max_features=best_trial.max_features,
            bootstrap=best_trial.bootstrap,
            random_state=best_trial.random_state,
            n_jobs=-1,
        )
        best_model.fit(dataset.X_train_normal)
        raw_scores = best_model.decision_function(dataset.X_val)
        norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)

        threshold_analyzer = ThresholdAnalyzer(dataset.y_val, norm_scores)
        sweep = threshold_analyzer.sweep_thresholds(
            min_thresh=0.35, max_thresh=0.75, step=0.01, target_max_fpr=0.02
        )

        print(f"  - Best F1 Threshold : T={sweep.best_f1_point.threshold:.2f} (F1={sweep.best_f1_point.f1_score:.4f}, FPR={sweep.best_f1_point.false_positive_rate:.4f})")
        print(f"  - Low-FPR Threshold : T={sweep.best_low_fpr_point.threshold:.2f} (F1={sweep.best_low_fpr_point.f1_score:.4f}, FPR={sweep.best_low_fpr_point.false_positive_rate:.4f}, Rec={sweep.best_low_fpr_point.recall:.4f})")
        print(f"  - Balanced Threshold: T={sweep.best_balanced_point.threshold:.2f} (Youden's J={sweep.best_balanced_point.youden_j:.4f})")

        # -------------------------------------------------------------
        # Experiment 4: Baseline Sample Sizing & Contamination Robustness
        # -------------------------------------------------------------
        print("\n[4/4] Evaluating Baseline Window Sample Sizes & Stability...")
        sample_sizes = [20, 50, 100, 250, 500] if not quick else [20, 100, 300]
        sizing_results: List[Dict[str, Any]] = []

        for sz in sample_sizes:
            sub_X_train = dataset.X_train_normal[:sz]
            m_sz = IsolationForest(
                n_estimators=best_trial.n_estimators,
                max_samples=min(256, sz) if best_trial.max_samples != "auto" else "auto",
                contamination=best_trial.contamination,
                random_state=best_trial.random_state,
                n_jobs=-1,
            )
            m_sz.fit(sub_X_train)
            raw = m_sz.decision_function(dataset.X_val)
            norm = np.clip(0.5 - raw, 0.0, 1.0)
            preds = (norm > sweep.best_f1_point.threshold).astype(int)

            tp = int(np.sum((preds == 1) & (dataset.y_val == 1)))
            tn = int(np.sum((preds == 0) & (dataset.y_val == 0)))
            fp = int(np.sum((preds == 1) & (dataset.y_val == 0)))
            fn = int(np.sum((preds == 0) & (dataset.y_val == 1)))
            acc = round(float((tp + tn) / len(dataset.y_val)), 4)
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
                "canonical_count": len(CANONICAL_FEATURES),
                "separation_scores": separation_scores,
                "redundant_pairs": [{"feature_1": f1, "feature_2": f2, "correlation": c} for f1, f2, c in redundant_pairs],
            },
            "hyperparameter_search": {
                "total_trials": len(trials),
                "best_trial": best_trial.to_dict(),
            },
            "threshold_calibration": {
                "best_f1_threshold": sweep.best_f1_point.to_dict(),
                "best_low_fpr_threshold": sweep.best_low_fpr_point.to_dict(),
                "best_balanced_threshold": sweep.best_balanced_point.to_dict(),
            },
            "baseline_sizing": sizing_results,
        }

        self._export_reports(report_data, trials, sweep)
        print("\n" + "=" * 70)
        print(f"Experiments Complete ({elapsed_total}s). Reports saved to {self.output_dir}.")
        print("=" * 70)
        return report_data

    def _export_reports(
        self,
        report_data: Dict[str, Any],
        trials: List[HyperparameterTrial],
        sweep: Any,
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
                "TrialId", "n_estimators", "max_samples", "contamination",
                "max_features", "Accuracy", "Precision", "Recall", "F1_Score", "FPR",
                "ROC_AUC", "PR_AUC", "TrainTimeMs", "InfTimeMs"
            ])
            for t in trials:
                writer.writerow([
                    t.trial_id, t.n_estimators, t.max_samples, t.contamination,
                    t.max_features, t.accuracy, t.precision, t.recall, t.f1_score,
                    t.false_positive_rate, t.roc_auc, t.pr_auc, t.training_time_ms, t.inference_time_ms
                ])

        # 3. Threshold Analysis JSON
        thresh_path = os.path.join(self.output_dir, "threshold_analysis.json")
        with open(thresh_path, "w", encoding="utf-8") as f:
            json.dump(sweep.to_dict(), f, indent=2)

        # 4. Markdown Summary
        best_trial = report_data["hyperparameter_search"]["best_trial"]
        best_thresh = report_data["threshold_calibration"]["best_f1_threshold"]
        low_fpr_thresh = report_data["threshold_calibration"]["best_low_fpr_threshold"]

        md_path = os.path.join(self.output_dir, "optimization_summary.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# NetSentinel Isolation Forest Optimization Summary\n\n")
            f.write(f"- **Execution Timestamp**: {report_data['experiment_timestamp_iso']}\n")
            f.write(f"- **Seed**: {report_data['seed']}\n")
            f.write(f"- **Feature Schema**: Canonical 13 Features\n\n")
            f.write("## 1. Optimal Hyperparameters\n\n")
            f.write(f"- `n_estimators`: {best_trial['n_estimators']}\n")
            f.write(f"- `max_samples`: `{best_trial['max_samples']}`\n")
            f.write(f"- `contamination`: `{best_trial['contamination']}`\n")
            f.write(f"- `max_features`: {best_trial['max_features']}\n")
            f.write(f"- `accuracy`: **{best_trial['accuracy'] * 100:.2f}%**\n")
            f.write(f"- `precision`: **{best_trial['precision'] * 100:.2f}%**\n")
            f.write(f"- `recall`: **{best_trial['recall'] * 100:.2f}%**\n")
            f.write(f"- `f1_score`: **{best_trial['f1_score'] * 100:.2f}%**\n")
            f.write(f"- `false_positive_rate`: **{best_trial['false_positive_rate'] * 100:.2f}%**\n\n")
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
