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
from .pcap_reader import (
    PcapPacketRecord,
    PcapReader,
    write_synthetic_pcap,
)
from .zeek_parser import (
    ZeekFlowRecord,
    ZeekLogParser,
    normalize_zeek_label,
    write_synthetic_zeek_log,
)
from .window_builder import (
    TrafficWindowBuilder,
    WindowEvaluationRecord,
    WindowGroundTruth,
    CaptureProcessingSummary,
    determine_window_ground_truth,
)
from .real_dataset import (
    RealDatasetEvaluator,
    DataLeakageError,
    WindowPredictionRecord,
    CaptureEvaluationMetrics,
    run_smoke_test,
)

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
    "PcapPacketRecord",
    "PcapReader",
    "write_synthetic_pcap",
    "ZeekFlowRecord",
    "ZeekLogParser",
    "normalize_zeek_label",
    "write_synthetic_zeek_log",
    "TrafficWindowBuilder",
    "WindowEvaluationRecord",
    "WindowGroundTruth",
    "CaptureProcessingSummary",
    "determine_window_ground_truth",
    "RealDatasetEvaluator",
    "DataLeakageError",
    "WindowPredictionRecord",
    "CaptureEvaluationMetrics",
    "run_smoke_test",
]
