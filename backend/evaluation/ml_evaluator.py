"""NetSentinel Machine Learning Evaluator Module (Phase 15).

Performs controlled, supervised evaluation of the unsupervised Isolation Forest
anomaly detection model against labelled ground-truth evaluation datasets.
Computes confusion matrices, precision, recall, F1-score, false-positive/negative rates,
and threshold sensitivity analysis without altering production code or thresholds.
"""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from ml.model import IsolationForestModel, ModelStatus
from ml.feature_extractor import FEATURE_NAMES

from .data_generator import SyntheticDataGenerator
from .metrics import (
    calculate_confusion_matrix,
    calculate_classification_metrics,
    evaluate_thresholds,
)


@dataclass
class MLEvaluationResult:
    """Comprehensive evaluation results container for machine learning analysis."""
    model_parameters: Dict[str, Any]
    dataset_summary: Dict[str, Any]
    production_threshold: float
    confusion_matrix: Dict[str, int]
    classification_metrics: Dict[str, float]
    threshold_analysis: List[Dict[str, Any]]
    score_distribution: Dict[str, Any]
    sample_predictions: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MLEvaluator:
    """Evaluates the unsupervised Isolation Forest anomaly detection pipeline."""

    def __init__(self, data_generator: Optional[SyntheticDataGenerator] = None):
        self.gen = data_generator or SyntheticDataGenerator(seed=42)

    def run_evaluation(
        self,
        baseline_windows: int = 50,
        normal_test_count: int = 100,
        anomaly_test_count: int = 100,
        thresholds: Optional[List[float]] = None,
    ) -> MLEvaluationResult:
        """Run supervised evaluation on separate synthetic training and test partitions.

        Args:
            baseline_windows: Number of normal traffic windows to fit the baseline.
            normal_test_count: Number of held-out normal evaluation windows.
            anomaly_test_count: Number of diverse anomalous evaluation windows.
            thresholds: List of candidate decision thresholds to evaluate offline.

        Returns:
            MLEvaluationResult dataclass with complete metrics and threshold sweep.
        """
        eval_thresholds = thresholds or [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]

        # 1. Generate separate baseline training data and evaluation data
        X_train = self.gen.generate_ml_baseline_dataset(window_count=baseline_windows, seed=42)
        X_test, y_true, meta = self.gen.generate_ml_evaluation_dataset(
            normal_count=normal_test_count, anomaly_count=anomaly_test_count, seed=1337
        )

        # 2. Initialize and train IsolationForest with exact production hyperparameters
        model = IsolationForestModel(
            n_estimators=100,
            contamination="auto",
            random_state=42,
            min_samples=max(5, baseline_windows // 2),
        )
        model.train(X_train)
        assert model.status == ModelStatus.READY

        # 3. Perform inference across all evaluation samples
        raw_scores: List[float] = []
        norm_scores: List[float] = []
        sample_results: List[Dict[str, Any]] = []

        for i, (vec, label, m) in enumerate(zip(X_test, y_true, meta)):
            is_anomaly, raw_s, norm_s = model.predict(vec)
            raw_scores.append(raw_s)
            norm_scores.append(norm_s)

            # Decision at production threshold (0.50):
            # normalized_score > 0.50 indicates anomalous tendency
            pred_binary = 1 if norm_s > 0.50 else 0

            sample_results.append({
                "sample_index": i,
                "ground_truth": label,
                "label_name": m["label_name"],
                "category": m["category"],
                "raw_decision_score": raw_s,
                "normalized_anomaly_score": norm_s,
                "predicted_anomaly_at_0_50": pred_binary,
                "is_correct_at_0_50": bool(pred_binary == label),
            })

        # 4. Compute primary metrics at production threshold (0.50)
        y_pred_prod = [1 if s > 0.50 else 0 for s in norm_scores]
        cm_prod = calculate_confusion_matrix(y_true, y_pred_prod)
        metrics_prod = calculate_classification_metrics(cm_prod)

        # 5. Compute threshold sensitivity sweep around 0.50
        sweep_results = evaluate_thresholds(y_true, norm_scores, eval_thresholds)

        # 6. Compute score distributions
        norm_arr = np.asarray([s for s, y in zip(norm_scores, y_true) if y == 0], dtype=np.float64)
        anom_arr = np.asarray([s for s, y in zip(norm_scores, y_true) if y == 1], dtype=np.float64)

        score_dist = {
            "normal_windows": {
                "count": len(norm_arr),
                "mean": round(float(np.mean(norm_arr)), 4),
                "std": round(float(np.std(norm_arr)), 4),
                "min": round(float(np.min(norm_arr)), 4),
                "max": round(float(np.max(norm_arr)), 4),
            },
            "anomalous_windows": {
                "count": len(anom_arr),
                "mean": round(float(np.mean(anom_arr)), 4),
                "std": round(float(np.std(anom_arr)), 4),
                "min": round(float(np.min(anom_arr)), 4),
                "max": round(float(np.max(anom_arr)), 4),
            },
            "separation_margin": round(float(np.mean(anom_arr) - np.mean(norm_arr)), 4),
        }

        dataset_summary = {
            "baseline_training_samples": len(X_train),
            "test_normal_samples": normal_test_count,
            "test_anomaly_samples": anomaly_test_count,
            "total_eval_samples": len(X_test),
            "feature_count": len(FEATURE_NAMES),
            "training_test_separation": "Strictly independent seeds (seed 42 for train, seed 1337 for test)",
        }

        model_params = {
            "algorithm": "Isolation Forest (Unsupervised)",
            "n_estimators": model.n_estimators,
            "contamination": str(model.contamination),
            "random_state": model.random_state,
            "feature_names": FEATURE_NAMES,
        }

        return MLEvaluationResult(
            model_parameters=model_params,
            dataset_summary=dataset_summary,
            production_threshold=0.50,
            confusion_matrix=cm_prod,
            classification_metrics=metrics_prod,
            threshold_analysis=sweep_results,
            score_distribution=score_dist,
            sample_predictions=sample_results,
        )
