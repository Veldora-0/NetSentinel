"""NetSentinel Evaluation Metrics Module (Phase 15).

Provides reproducible statistical latency/throughput calculations,
confusion matrix extraction, and supervised classification metrics for
evaluating unsupervised anomaly detectors.
"""

from typing import Any, Dict, List, Optional
import numpy as np


def calculate_statistics(
    latencies_sec: List[float], total_duration_sec: Optional[float] = None
) -> Dict[str, float]:
    """Calculate latency percentiles and throughput from sample durations.

    Args:
        latencies_sec: List of individual operation latencies in seconds.
        total_duration_sec: Optional overall wall-clock elapsed time in seconds.
            If omitted or zero, sum of latencies is used.

    Returns:
        Dictionary containing sample count, throughput, mean, median,
        p95, p99, min, and max latencies formatted in milliseconds.
    """
    n = len(latencies_sec)
    if n == 0:
        return {
            "samples": 0,
            "total_duration_sec": 0.0,
            "throughput_ops_per_sec": 0.0,
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
        }

    arr_ms = np.asarray(latencies_sec, dtype=np.float64) * 1000.0
    elapsed = float(total_duration_sec) if (total_duration_sec and total_duration_sec > 0) else float(np.sum(latencies_sec))
    throughput = (n / elapsed) if elapsed > 0 else 0.0

    return {
        "samples": n,
        "total_duration_sec": round(elapsed, 4),
        "throughput_ops_per_sec": round(throughput, 2),
        "mean_ms": round(float(np.mean(arr_ms)), 4),
        "median_ms": round(float(np.percentile(arr_ms, 50)), 4),
        "p95_ms": round(float(np.percentile(arr_ms, 95)), 4),
        "p99_ms": round(float(np.percentile(arr_ms, 99)), 4),
        "min_ms": round(float(np.min(arr_ms)), 4),
        "max_ms": round(float(np.max(arr_ms)), 4),
    }


def calculate_confusion_matrix(y_true: List[int], y_pred: List[int]) -> Dict[str, int]:
    """Compute standard binary confusion matrix.

    Convention:
        1: Positive (Anomalous)
        0: Negative (Normal / Inlier)

    Args:
        y_true: Ground-truth binary labels (0 or 1).
        y_pred: Predicted binary labels (0 or 1).

    Returns:
        Dictionary with keys: true_positives, true_negatives,
        false_positives, false_negatives, total_samples.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"Length mismatch: y_true has {len(y_true)}, y_pred has {len(y_pred)}"
        )

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "total_samples": len(y_true),
    }


def calculate_classification_metrics(cm: Dict[str, int]) -> Dict[str, float]:
    """Derive standard classification metrics from a confusion matrix.

    Args:
        cm: Confusion matrix dictionary from calculate_confusion_matrix.

    Returns:
        Dictionary of precision, recall, f1_score, false_positive_rate,
        false_negative_rate, and accuracy.
    """
    tp = cm["true_positives"]
    tn = cm["true_negatives"]
    fp = cm["false_positives"]
    fn = cm["false_negatives"]
    total = cm.get("total_samples", tp + tn + fp + fn)

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = (fn / (tp + fn)) if (tp + fn) > 0 else 0.0
    accuracy = ((tp + tn) / total) if total > 0 else 0.0

    return {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "accuracy": round(float(accuracy), 4),
    }


def evaluate_thresholds(
    y_true: List[int], scores: List[float], thresholds: List[float]
) -> List[Dict[str, Any]]:
    """Perform threshold sensitivity analysis across multiple decision cutoffs.

    Args:
        y_true: Ground truth binary labels.
        scores: Continuous anomaly scores (typically in [0.0, 1.0]).
        thresholds: List of decision thresholds to evaluate.

    Returns:
        List of dictionaries with threshold evaluation results including
        confusion matrix entries and derived metrics.
    """
    results: List[Dict[str, Any]] = []

    for thresh in thresholds:
        # Decision rule: score > thresh indicates positive (anomaly)
        y_pred = [1 if s > thresh else 0 for s in scores]
        cm = calculate_confusion_matrix(y_true, y_pred)
        metrics = calculate_classification_metrics(cm)

        entry = {
            "threshold": round(float(thresh), 4),
            "confusion_matrix": cm,
            "metrics": metrics,
        }
        results.append(entry)

    return results
