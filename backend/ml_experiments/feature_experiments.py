"""NetSentinel ML Feature Experiments Module.

Analyzes feature distributions, correlation matrices, and discriminative power
between canonical v1 features and candidate extended features (v2).
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from ml.feature_extractor import FEATURE_NAMES

# Canonical 13 features
CANONICAL_FEATURES: List[str] = list(FEATURE_NAMES)
CANONICAL_V1_FEATURES: List[str] = CANONICAL_FEATURES  # Backward-compatible alias


class FeatureAnalyzer:
    """Evaluates discriminative power, variance, and collinearity of feature sets."""

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feature_names = feature_names or CANONICAL_FEATURES

    def compute_feature_statistics(self, X: np.ndarray) -> Dict[str, Dict[str, float]]:
        """Compute basic statistical summary for each feature."""
        stats: Dict[str, Dict[str, float]] = {}
        for idx, name in enumerate(self.feature_names):
            col = X[:, idx]
            stats[name] = {
                "mean": round(float(np.mean(col)), 4),
                "std": round(float(np.std(col)), 4),
                "min": round(float(np.min(col)), 4),
                "max": round(float(np.max(col)), 4),
                "variance": round(float(np.var(col)), 6),
            }
        return stats

    def compute_correlation_matrix(self, X: np.ndarray) -> Dict[str, Dict[str, float]]:
        """Compute Pearson correlation matrix across all features."""
        # Add tiny epsilon to prevent division by zero in constant columns
        std = np.std(X, axis=0)
        valid_cols = std > 1e-6
        corr = np.eye(X.shape[1], dtype=np.float64)

        if np.any(valid_cols):
            sub_corr = np.corrcoef(X[:, valid_cols], rowvar=False)
            valid_indices = np.where(valid_cols)[0]
            for i_sub, i_full in enumerate(valid_indices):
                for j_sub, j_full in enumerate(valid_indices):
                    corr[i_full, j_full] = sub_corr[i_sub, j_sub]

        matrix: Dict[str, Dict[str, float]] = {}
        for i, name_i in enumerate(self.feature_names):
            matrix[name_i] = {}
            for j, name_j in enumerate(self.feature_names):
                val = corr[i, j]
                matrix[name_i][name_j] = round(float(0.0 if np.isnan(val) else val), 4)

        return matrix

    def compute_separation_scores(
        self, X_normal: np.ndarray, X_attack: np.ndarray
    ) -> Dict[str, float]:
        """Compute Fisher separation criterion for each feature: |mu_norm - mu_att|^2 / (var_norm + var_att)."""
        scores: Dict[str, float] = {}
        for idx, name in enumerate(self.feature_names):
            norm_col = X_normal[:, idx]
            att_col = X_attack[:, idx]

            mu_norm = float(np.mean(norm_col))
            mu_att = float(np.mean(att_col))
            var_norm = float(np.var(norm_col))
            var_att = float(np.var(att_col))

            denom = var_norm + var_att + 1e-6
            fisher = ((mu_norm - mu_att) ** 2) / denom
            scores[name] = round(float(fisher), 4)

        return dict(sorted(scores.items(), key=lambda item: item[1], reverse=True))

    def evaluate_redundant_features(self, X: np.ndarray, threshold: float = 0.95) -> List[Tuple[str, str, float]]:
        """Identify feature pairs with absolute correlation exceeding threshold."""
        corr_matrix = self.compute_correlation_matrix(X)
        redundant: List[Tuple[str, str, float]] = []
        n = len(self.feature_names)

        for i in range(n):
            for j in range(i + 1, n):
                f1 = self.feature_names[i]
                f2 = self.feature_names[j]
                val = abs(corr_matrix[f1][f2])
                if val >= threshold:
                    redundant.append((f1, f2, val))

        return sorted(redundant, key=lambda x: x[2], reverse=True)
