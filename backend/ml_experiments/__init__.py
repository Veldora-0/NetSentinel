"""NetSentinel ML Experiments Package.

Provides isolated experimental frameworks for unsupervised Isolation Forest optimization:
- Synthetic validation data loaders
- Feature expansion & correlation experiments
- Hyperparameter grid searching & stability analysis
- Calibrated anomaly threshold analysis
- Reproducible optimization report generation
"""

from .data_loader import SyntheticTrafficGenerator, ValidationDataset
from .feature_experiments import FeatureAnalyzer, CANDIDATE_V2_FEATURES
from .hyperparameter_search import IsolationForestOptimizer, HyperparameterTrial
from .threshold_analysis import ThresholdAnalyzer, ThresholdSweepResult

__all__ = [
    "SyntheticTrafficGenerator",
    "ValidationDataset",
    "FeatureAnalyzer",
    "CANDIDATE_V2_FEATURES",
    "IsolationForestOptimizer",
    "HyperparameterTrial",
    "ThresholdAnalyzer",
    "ThresholdSweepResult",
]
