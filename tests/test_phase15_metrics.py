"""Unit tests for Phase 15 Evaluation Metrics & Statistics calculations."""

import pytest
from evaluation.metrics import (
    calculate_statistics,
    calculate_confusion_matrix,
    calculate_classification_metrics,
    evaluate_thresholds,
)


def test_calculate_statistics_known_values():
    """Verify statistical latency percentiles and throughput on known data."""
    # 5 operations: 10ms, 20ms, 30ms, 40ms, 50ms (in seconds)
    latencies = [0.010, 0.020, 0.030, 0.040, 0.050]
    total_duration = 0.150  # 150 ms total

    stats = calculate_statistics(latencies, total_duration)

    assert stats["samples"] == 5
    assert stats["total_duration_sec"] == 0.15
    assert stats["throughput_ops_per_sec"] == round(5 / 0.15, 2)
    assert stats["mean_ms"] == 30.0
    assert stats["median_ms"] == 30.0
    assert stats["min_ms"] == 10.0
    assert stats["max_ms"] == 50.0
    assert stats["p95_ms"] >= 45.0
    assert stats["p99_ms"] >= 48.0


def test_calculate_statistics_empty_list():
    """Verify graceful zero-handling on empty latency list."""
    stats = calculate_statistics([])
    assert stats["samples"] == 0
    assert stats["throughput_ops_per_sec"] == 0.0
    assert stats["mean_ms"] == 0.0


def test_confusion_matrix_perfect():
    """Verify confusion matrix with perfect classification."""
    y_true = [0, 0, 0, 1, 1]
    y_pred = [0, 0, 0, 1, 1]

    cm = calculate_confusion_matrix(y_true, y_pred)
    assert cm["true_positives"] == 2
    assert cm["true_negatives"] == 3
    assert cm["false_positives"] == 0
    assert cm["false_negatives"] == 0
    assert cm["total_samples"] == 5


def test_confusion_matrix_mixed():
    """Verify confusion matrix with known false positives and negatives."""
    y_true = [1, 1, 0, 0, 1, 0]
    y_pred = [1, 0, 0, 1, 1, 0]

    cm = calculate_confusion_matrix(y_true, y_pred)
    assert cm["true_positives"] == 2  # indices 0, 4
    assert cm["true_negatives"] == 2  # indices 2, 5
    assert cm["false_positives"] == 1  # index 3
    assert cm["false_negatives"] == 1  # index 1


def test_confusion_matrix_length_mismatch():
    """Verify ValueError is raised if true and predicted labels differ in length."""
    with pytest.raises(ValueError):
        calculate_confusion_matrix([1, 0], [1])


def test_classification_metrics_values():
    """Verify mathematical correctness of derived classification metrics."""
    # TP=80, TN=70, FP=30, FN=20 (Total=200)
    cm = {
        "true_positives": 80,
        "true_negatives": 70,
        "false_positives": 30,
        "false_negatives": 20,
        "total_samples": 200,
    }

    metrics = calculate_classification_metrics(cm)

    # Precision = TP / (TP + FP) = 80 / 110 = 0.72727...
    assert metrics["precision"] == 0.7273
    # Recall = TP / (TP + FN) = 80 / 100 = 0.8000
    assert metrics["recall"] == 0.8000
    # F1 = 2 * (0.72727 * 0.8) / (0.72727 + 0.8) = 0.7619
    assert metrics["f1_score"] == 0.7619
    # FPR = FP / (FP + TN) = 30 / 100 = 0.3000
    assert metrics["false_positive_rate"] == 0.3000
    # FNR = FN / (TP + FN) = 20 / 100 = 0.2000
    assert metrics["false_negative_rate"] == 0.2000
    # Accuracy = (80 + 70) / 200 = 0.7500
    assert metrics["accuracy"] == 0.7500


def test_classification_metrics_zero_division():
    """Verify zero division safety when all predictions are negative."""
    cm = {
        "true_positives": 0,
        "true_negatives": 10,
        "false_positives": 0,
        "false_negatives": 10,
        "total_samples": 20,
    }
    metrics = calculate_classification_metrics(cm)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 1.0


def test_evaluate_thresholds_sweep():
    """Verify sensitivity analysis across multiple decision cutoffs."""
    y_true = [0, 0, 1, 1]
    scores = [0.20, 0.45, 0.60, 0.80]
    thresholds = [0.30, 0.50, 0.70]

    sweep = evaluate_thresholds(y_true, scores, thresholds)
    assert len(sweep) == 3

    # At T=0.50:
    # Preds: 0.20 <= 0.50 -> 0; 0.45 <= 0.50 -> 0; 0.60 > 0.50 -> 1; 0.80 > 0.50 -> 1
    # Perfect match: TP=2, TN=2, FP=0, FN=0
    entry_50 = sweep[1]
    assert entry_50["threshold"] == 0.50
    assert entry_50["confusion_matrix"]["true_positives"] == 2
    assert entry_50["confusion_matrix"]["true_negatives"] == 2
    assert entry_50["metrics"]["f1_score"] == 1.0
