"""NetSentinel Machine Learning Package.

Unsupervised network anomaly detection using Scikit-learn's Isolation Forest.
Provides windowed feature extraction, baseline profiling, model persistence,
and real-time anomaly detection independent of rule-based detectors.
"""

from ml.feature_extractor import (
    FEATURE_NAMES,
    FEATURE_NAMES_V1,
    FEATURE_NAMES_V2,
    FEATURE_SCHEMAS,
    get_feature_names,
    extract_features_from_window,
    TrafficWindow,
)
from ml.model import IsolationForestModel, ModelStatus
from ml.detector import MLAnomalyDetector, MLAnomalyEvent

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_NAMES_V1",
    "FEATURE_NAMES_V2",
    "FEATURE_SCHEMAS",
    "get_feature_names",
    "extract_features_from_window",
    "TrafficWindow",
    "IsolationForestModel",
    "ModelStatus",
    "MLAnomalyDetector",
    "MLAnomalyEvent",
]
