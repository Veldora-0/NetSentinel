"""NetSentinel Performance and Machine Learning Evaluation Package (Phase 15).

Provides deterministic benchmarks, resource monitoring, and supervised evaluation
of the unsupervised Isolation Forest anomaly detection pipeline.
"""

from .metrics import (
    calculate_statistics,
    calculate_confusion_matrix,
    calculate_classification_metrics,
    evaluate_thresholds,
)
from .data_generator import (
    SyntheticDataGenerator,
    generate_synthetic_raw_frame,
    generate_synthetic_parsed_packet,
)
from .resource_monitor import ResourceMonitor, ResourceSnapshot
from .benchmarks import (
    BenchmarkSuite,
    BenchmarkResult,
)
from .ml_evaluator import MLEvaluator, MLEvaluationResult
from .runner import EvaluationRunner

__all__ = [
    "calculate_statistics",
    "calculate_confusion_matrix",
    "calculate_classification_metrics",
    "evaluate_thresholds",
    "SyntheticDataGenerator",
    "generate_synthetic_raw_frame",
    "generate_synthetic_parsed_packet",
    "ResourceMonitor",
    "ResourceSnapshot",
    "BenchmarkSuite",
    "BenchmarkResult",
    "MLEvaluator",
    "MLEvaluationResult",
    "EvaluationRunner",
]
