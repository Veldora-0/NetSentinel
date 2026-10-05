"""NetSentinel Isolation Forest Model Module.

Wraps Scikit-learn's IsolationForest for unsupervised network traffic anomaly detection.
Provides model lifecycle management, training validation, anomaly scoring, and model persistence.
"""

from enum import Enum
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ml.feature_extractor import FEATURE_NAMES

logger = logging.getLogger("netsentinel.ml.model")


class ModelStatus(str, Enum):
    """Lifecycle state of the Isolation Forest model."""
    MODEL_NOT_READY = "MODEL_NOT_READY"
    COLLECTING_BASELINE = "COLLECTING_BASELINE"
    READY = "READY"
    ERROR = "ERROR"


class IsolationForestModel:
    """Unsupervised network traffic anomaly detector powered by Isolation Forest."""

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: Any = "auto",
        random_state: int = 42,
        min_samples: int = 5,
    ):
        self.n_estimators = int(n_estimators)
        if isinstance(contamination, str) and contamination.strip().lower() == "auto":
            self.contamination: Any = "auto"
        else:
            self.contamination = float(contamination)
        self.random_state = int(random_state)
        self.min_samples = int(min_samples)

        self.status = ModelStatus.MODEL_NOT_READY
        self.model: Optional[IsolationForest] = None
        self.trained_at: Optional[float] = None
        self.training_sample_count: int = 0
        self.feature_names: List[str] = list(FEATURE_NAMES)
        self.last_error: Optional[str] = None

    def train(self, feature_matrix: List[List[float]]) -> bool:
        """Train the Isolation Forest model on a normal traffic baseline feature matrix.

        Args:
            feature_matrix: List of feature vectors extracted from normal traffic windows.

        Returns:
            True if training succeeded, False if training criteria was not met.

        Raises:
            ValueError: If sample count is below min_samples.
        """
        sample_count = len(feature_matrix)
        if sample_count < self.min_samples:
            self.status = ModelStatus.MODEL_NOT_READY
            err_msg = (
                f"Insufficient baseline samples: provided {sample_count}, "
                f"minimum required is {self.min_samples}."
            )
            self.last_error = err_msg
            logger.warning(err_msg)
            raise ValueError(err_msg)

        try:
            X = np.asarray(feature_matrix, dtype=np.float64)
            if X.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"Feature dimension mismatch: expected {len(self.feature_names)}, got {X.shape[1]}."
                )

            # Fit unsupervised Isolation Forest
            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1,
            )
            model.fit(X)

            self.model = model
            self.training_sample_count = sample_count
            self.trained_at = time.time()
            self.status = ModelStatus.READY
            self.last_error = None
            logger.info("Isolation Forest successfully trained on %d baseline windows.", sample_count)
            return True

        except Exception as ex:
            self.status = ModelStatus.ERROR
            self.last_error = f"Model training failed: {str(ex)}"
            logger.error(self.last_error)
            return False

    def predict(self, feature_vector: List[float]) -> Tuple[bool, float, float]:
        """Perform anomaly prediction and scoring on a single traffic window feature vector.

        Args:
            feature_vector: Numerical feature vector matching FEATURE_NAMES ordering.

        Returns:
            Tuple of (is_anomaly, raw_decision_score, normalized_anomaly_score).
            - is_anomaly: True if the model considers the window an anomaly (outlier).
            - raw_decision_score: Scikit-learn decision_function output (< 0 means anomaly).
            - normalized_anomaly_score: Score normalized between 0.0 (normal) and 1.0 (anomalous).

        Raises:
            RuntimeError: If model is not in READY state.
        """
        if self.status != ModelStatus.READY or self.model is None:
            raise RuntimeError(f"Cannot perform prediction while model is in {self.status.value} state.")

        X = np.asarray([feature_vector], dtype=np.float64)
        pred = self.model.predict(X)[0]  # +1 = inlier/normal, -1 = outlier/anomaly
        raw_score = float(self.model.decision_function(X)[0])

        is_anomaly = bool(pred == -1)

        # Normalization: raw_score < 0 is anomaly, raw_score > 0 is inlier
        # Map raw decision score around 0.0 decision threshold:
        # normalized_score > 0.5 indicates anomalous tendency
        normalized_score = round(float(np.clip(0.5 - raw_score, 0.0, 1.0)), 4)

        return is_anomaly, round(raw_score, 4), normalized_score

    def save(self, model_path: str, metadata_path: str) -> bool:
        """Persist trained model binary and feature metadata to disk.

        Args:
            model_path: Filepath for the joblib model artifact.
            metadata_path: Filepath for the JSON model metadata file.

        Returns:
            True if saved successfully, False otherwise.
        """
        if self.status != ModelStatus.READY or self.model is None:
            logger.warning("Attempted to save model that is not in READY state.")
            return False

        try:
            os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
            joblib.dump(self.model, model_path)

            meta = {
                "trained_at": self.trained_at,
                "training_sample_count": self.training_sample_count,
                "feature_names": self.feature_names,
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
                "random_state": self.random_state,
            }
            with open(metadata_path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2)

            logger.info("Isolation Forest model saved to %s", model_path)
            return True
        except Exception as ex:
            logger.error("Failed to save model: %s", ex)
            return False

    def load(self, model_path: str, metadata_path: str) -> bool:
        """Load trained model artifact and verify feature consistency.

        Args:
            model_path: Filepath for the joblib model artifact.
            metadata_path: Filepath for the JSON metadata file.

        Returns:
            True if loaded successfully, False if missing, corrupted, or incompatible.
        """
        if not os.path.exists(model_path) or not os.path.exists(metadata_path):
            self.status = ModelStatus.MODEL_NOT_READY
            return False

        try:
            with open(metadata_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)

            saved_features = meta.get("feature_names", [])
            if saved_features != self.feature_names:
                raise ValueError("Loaded model feature ordering does not match current feature definitions.")

            loaded_model = joblib.load(model_path)

            self.model = loaded_model
            self.trained_at = meta.get("trained_at")
            self.training_sample_count = meta.get("training_sample_count", 0)
            self.n_estimators = meta.get("n_estimators", self.n_estimators)
            self.contamination = meta.get("contamination", self.contamination)
            self.random_state = meta.get("random_state", self.random_state)
            self.status = ModelStatus.READY
            self.last_error = None
            logger.info("Isolation Forest model loaded successfully from %s", model_path)
            return True

        except Exception as ex:
            self.status = ModelStatus.ERROR
            self.last_error = f"Failed to load model: {str(ex)}"
            logger.error(self.last_error)
            return False
