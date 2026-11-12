"""NetSentinel Performance and Machine Learning Evaluation Package.

Provides deterministic benchmarks, resource monitoring, and evaluation
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
from .ml_evaluator import MLEvaluator, MLEvaluationResult

# Lazy exports for modules with heavier dependencies
_LAZY_EXPORTS = {
    "BenchmarkSuite": (".benchmarks", "BenchmarkSuite"),
    "BenchmarkResult": (".benchmarks", "BenchmarkResult"),
    "EvaluationRunner": (".runner", "EvaluationRunner"),
}


def __getattr__(name: str):
    if name in _LAZY_EXPORTS:
        module_path, attr_name = _LAZY_EXPORTS[name]
        import importlib

        mod = importlib.import_module(module_path, __package__)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(list(globals().keys()) + list(_LAZY_EXPORTS.keys()))


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
