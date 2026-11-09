"""NetSentinel ML Hyperparameter Search Module.

Systematically searches Isolation Forest hyperparameter space to optimize
anomaly detection accuracy, recall, and false positive reduction.
"""

from dataclasses import dataclass, asdict
import itertools
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, average_precision_score

from .data_loader import ValidationDataset


@dataclass
class HyperparameterTrial:
    """Evaluation result for a single hyperparameter configuration."""
    trial_id: int
    n_estimators: int
    max_samples: Any
    contamination: Any
    max_features: float
    bootstrap: bool
    random_state: int
    threshold: float
    training_time_ms: float
    inference_time_ms: float
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
    roc_auc: float
    pr_auc: float
    benign_mean_score: float
    malicious_mean_score: float
    score_separation_margin: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IsolationForestOptimizer:
    """Grid search and evaluation harness for unsupervised Isolation Forest tuning."""

    def __init__(self, dataset: ValidationDataset):
        self.dataset = dataset
        self.trials: List[HyperparameterTrial] = []

    def evaluate_configuration(
        self,
        trial_id: int,
        n_estimators: int = 100,
        max_samples: Any = "auto",
        contamination: Any = "auto",
        max_features: float = 1.0,
        bootstrap: bool = False,
        random_state: int = 42,
        threshold: float = 0.50,
    ) -> HyperparameterTrial:
        """Train and evaluate a specific Isolation Forest configuration."""
        X_train = self.dataset.X_train_normal
        X_val = self.dataset.X_val
        y_val = self.dataset.y_val

        # 1. Fit Isolation Forest
        t0 = time.perf_counter()
        model = IsolationForest(
            n_estimators=int(n_estimators),
            max_samples=max_samples,
            contamination=contamination,
            max_features=float(max_features),
            bootstrap=bool(bootstrap),
            random_state=int(random_state),
            n_jobs=-1,
        )
        model.fit(X_train)
        train_time_ms = round((time.perf_counter() - t0) * 1000, 2)

        # 2. Predict on validation set
        t1 = time.perf_counter()
        raw_scores = model.decision_function(X_val)
        inf_time_ms = round((time.perf_counter() - t1) * 1000, 2)

        # Convert to NetSentinel normalized anomaly score: clip(0.5 - raw_score, 0.0, 1.0)
        norm_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)

        # Binary classification at decision threshold
        y_pred = (norm_scores > threshold).astype(int)

        tp = int(np.sum((y_pred == 1) & (y_val == 1)))
        tn = int(np.sum((y_pred == 0) & (y_val == 0)))
        fp = int(np.sum((y_pred == 1) & (y_val == 0)))
        fn = int(np.sum((y_pred == 0) & (y_val == 1)))

        total = len(y_val)
        acc = round(float((tp + tn) / total), 4) if total > 0 else 0.0
        prec = round(float(tp / (tp + fp)), 4) if (tp + fp) > 0 else 0.0
        rec = round(float(tp / (tp + fn)), 4) if (tp + fn) > 0 else 0.0
        f1 = round(float(2 * prec * rec / (prec + rec)), 4) if (prec + rec) > 0 else 0.0
        fpr = round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0
        fnr = round(float(fn / (fn + tp)), 4) if (fn + tp) > 0 else 0.0

        try:
            roc_auc = round(float(roc_auc_score(y_val, norm_scores)), 4)
        except Exception:
            roc_auc = 0.5

        try:
            pr_auc = round(float(average_precision_score(y_val, norm_scores)), 4)
        except Exception:
            pr_auc = 0.5

        benign_mask = (y_val == 0)
        mal_mask = (y_val == 1)
        b_mean = round(float(np.mean(norm_scores[benign_mask])), 4) if np.any(benign_mask) else 0.0
        m_mean = round(float(np.mean(norm_scores[mal_mask])), 4) if np.any(mal_mask) else 0.0
        sep_margin = round(m_mean - b_mean, 4)

        trial = HyperparameterTrial(
            trial_id=trial_id,
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination=contamination,
            max_features=max_features,
            bootstrap=bootstrap,
            random_state=random_state,
            threshold=threshold,
            training_time_ms=train_time_ms,
            inference_time_ms=inf_time_ms,
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            accuracy=acc,
            precision=prec,
            recall=rec,
            f1_score=f1,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            roc_auc=roc_auc,
            pr_auc=pr_auc,
            benign_mean_score=b_mean,
            malicious_mean_score=m_mean,
            score_separation_margin=sep_margin,
        )
        return trial

    def run_grid_search(
        self,
        param_grid: Optional[Dict[str, List[Any]]] = None,
        default_threshold: float = 0.50,
    ) -> List[HyperparameterTrial]:
        """Execute exhaustive or custom grid search over hyperparameter combinations."""
        grid = param_grid or {
            "n_estimators": [100, 200, 300],
            "max_samples": [256, 512, "auto"],
            "contamination": ["auto", 0.01, 0.03],
            "max_features": [0.85, 1.0],
            "bootstrap": [False],
            "random_state": [42],
        }

        keys = list(grid.keys())
        combos = list(itertools.product(*(grid[k] for k in keys)))
        results: List[HyperparameterTrial] = []

        for idx, combo in enumerate(combos, 1):
            kwargs = dict(zip(keys, combo))
            kwargs["threshold"] = default_threshold
            trial = self.evaluate_configuration(trial_id=idx, **kwargs)
            results.append(trial)

        # Sort by F1 score descending, then by FPR ascending
        results.sort(key=lambda t: (t.f1_score, -t.false_positive_rate), reverse=True)
        self.trials = results
        return results

    def get_best_trial(self) -> Optional[HyperparameterTrial]:
        """Return trial with highest F1 score and lowest FPR."""
        if not self.trials:
            return None
        return self.trials[0]
