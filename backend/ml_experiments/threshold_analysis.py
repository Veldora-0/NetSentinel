"""NetSentinel ML Threshold Analysis Module.

Evaluates decision threshold sweeps across normalized Isolation Forest anomaly scores
to identify optimal operating points balancing Recall and False Positive Rate.
"""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class ThresholdSweepPoint:
    """Performance metrics at a single threshold cut."""
    threshold: float
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
    youden_j: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThresholdSweepResult:
    """Summary of threshold sweep analysis."""
    best_f1_point: ThresholdSweepPoint
    best_low_fpr_point: ThresholdSweepPoint       # Best Recall where FPR <= target_max_fpr
    best_balanced_point: ThresholdSweepPoint      # Best Youden's J statistic
    sweep_curve: List[ThresholdSweepPoint]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "best_f1_point": self.best_f1_point.to_dict(),
            "best_low_fpr_point": self.best_low_fpr_point.to_dict(),
            "best_balanced_point": self.best_balanced_point.to_dict(),
            "sweep_curve": [p.to_dict() for p in self.sweep_curve],
        }


class ThresholdAnalyzer:
    """Analyzes sensitivity and specificity across anomaly score thresholds."""

    def __init__(self, y_true: np.ndarray, norm_scores: np.ndarray):
        self.y_true = np.asarray(y_true, dtype=np.int32)
        self.norm_scores = np.asarray(norm_scores, dtype=np.float64)

    def sweep_thresholds(
        self,
        min_thresh: float = 0.35,
        max_thresh: float = 0.75,
        step: float = 0.01,
        target_max_fpr: float = 0.02,
    ) -> ThresholdSweepResult:
        """Evaluate performance across range [min_thresh, max_thresh]."""
        thresholds = np.arange(min_thresh, max_thresh + (step / 2.0), step)
        points: List[ThresholdSweepPoint] = []

        total_pos = int(np.sum(self.y_true == 1))
        total_neg = int(np.sum(self.y_true == 0))
        total = len(self.y_true)

        for th in thresholds:
            t = round(float(th), 4)
            preds = (self.norm_scores > t).astype(int)

            tp = int(np.sum((preds == 1) & (self.y_true == 1)))
            tn = int(np.sum((preds == 0) & (self.y_true == 0)))
            fp = int(np.sum((preds == 1) & (self.y_true == 0)))
            fn = int(np.sum((preds == 0) & (self.y_true == 1)))

            acc = round(float((tp + tn) / total), 4) if total > 0 else 0.0
            prec = round(float(tp / (tp + fp)), 4) if (tp + fp) > 0 else 0.0
            rec = round(float(tp / total_pos), 4) if total_pos > 0 else 0.0
            f1 = round(float(2 * prec * rec / (prec + rec)), 4) if (prec + rec) > 0 else 0.0
            fpr = round(float(fp / total_neg), 4) if total_neg > 0 else 0.0
            fnr = round(float(fn / total_pos), 4) if total_pos > 0 else 0.0
            # Youden's J = Sensitivity + Specificity - 1 = Recall - FPR
            youden_j = round(float(rec - fpr), 4)

            points.append(
                ThresholdSweepPoint(
                    threshold=t,
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
                    youden_j=youden_j,
                )
            )

        # 1. Best F1
        best_f1 = max(points, key=lambda p: (p.f1_score, -p.false_positive_rate))

        # 2. Best Low FPR (Recall maximized subject to FPR <= target_max_fpr)
        low_fpr_candidates = [p for p in points if p.false_positive_rate <= target_max_fpr]
        if low_fpr_candidates:
            best_low_fpr = max(low_fpr_candidates, key=lambda p: (p.recall, p.f1_score))
        else:
            best_low_fpr = min(points, key=lambda p: p.false_positive_rate)

        # 3. Best Balanced (Max Youden's J)
        best_balanced = max(points, key=lambda p: p.youden_j)

        return ThresholdSweepResult(
            best_f1_point=best_f1,
            best_low_fpr_point=best_low_fpr,
            best_balanced_point=best_balanced,
            sweep_curve=points,
        )
