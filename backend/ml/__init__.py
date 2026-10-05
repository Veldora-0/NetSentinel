"""NetSentinel Machine Learning Package.

Unsupervised network anomaly detection using Scikit-learn's Isolation Forest.
Provides windowed feature extraction, baseline profiling, model persistence,
and real-time anomaly detection independent of rule-based detectors.
"""

from ml.feature_extractor import FEATURE_NAMES, extract_features_from_window, TrafficWindow
from ml.model import IsolationForestModel, ModelStatus
from ml.detector import MLAnomalyDetector, MLAnomalyEvent

__all__ = [
    "FEATURE_NAMES",
    "extract_features_from_window",
    "TrafficWindow",
    "IsolationForestModel",
    "ModelStatus",
    "MLAnomalyDetector",
    "MLAnomalyEvent",
]
