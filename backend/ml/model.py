"""NetSentinel Isolation Forest Model Module.

Wraps Scikit-learn's IsolationForest for unsupervised network traffic anomaly detection
using exactly the original 13 network traffic features.
Provides model lifecycle management, training validation, anomaly scoring, and atomic persistence.
"""

from enum import Enum
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ml.feature_extractor import FEATURE_NAMES

logger = logging.getLogger("netsentinel.ml.model")


class ModelStatus(str, Enum):
    """Lifecycle state of the Isolation Forest model."""
    MODEL_NOT_READY = "MODEL_NOT_READY"
    COLLECTING_BASELINE = "COLLECTING_BASELINE"
    TRAINING = "TRAINING"
    READY = "READY"
    ERROR = "ERROR"


class IsolationForestModel:
    """Unsupervised network traffic anomaly detector powered by Isolation Forest."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: Any = "auto",
        contamination: Any = "auto",
        max_features: float = 1.0,
        random_state: int = 42,
        min_samples: int = 512,
    ):
        self.n_estimators = int(n_estimators)
        if isinstance(max_samples, str) and max_samples.strip().lower() == "auto":
            self.max_samples: Any = "auto"
        elif max_samples is not None and not isinstance(max_samples, str):
            self.max_samples = int(max_samples) if max_samples > 1 else float(max_samples)
        else:
            self.max_samples = "auto"

        if isinstance(contamination, str) and contamination.strip().lower() == "auto":
            self.contamination: Any = "auto"
        else:
            self.contamination = float(contamination)

        self.max_features = float(max_features)
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
            ValueError: If sample count is below min_samples or dimensions mismatch.
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

        self.status = ModelStatus.TRAINING
        try:
            X = np.asarray(feature_matrix, dtype=np.float64)
            if X.shape[1] != len(self.feature_names):
                raise ValueError(
                    f"Feature dimension mismatch: expected {len(self.feature_names)} features, got {X.shape[1]}."
                )

            if not np.all(np.isfinite(X)):
                raise ValueError("Feature matrix contains non-finite values (NaN or Inf).")

            # Fit unsupervised Isolation Forest
            model = IsolationForest(
                n_estimators=self.n_estimators,
                max_samples=self.max_samples,
                contamination=self.contamination,
                max_features=self.max_features,
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
            self.model = None
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
            ValueError: If feature vector length does not match FEATURE_NAMES (13).
        """
        if self.status != ModelStatus.READY or self.model is None:
            raise RuntimeError(f"Cannot perform prediction while model is in {self.status.value} state.")

        if len(feature_vector) != len(self.feature_names):
            raise ValueError(
                f"Feature vector dimension mismatch: expected {len(self.feature_names)} features, got {len(feature_vector)}."
            )

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
        """Persist trained model binary, feature metadata, and manifest atomically as a crash-consistent generation.

        Args:
            model_path: Filepath for the joblib model artifact.
            metadata_path: Filepath for the JSON model metadata file.

        Returns:
            True if saved successfully, False otherwise.
        """
        if self.status != ModelStatus.READY or self.model is None:
            logger.warning("Attempted to save model that is not in READY state.")
            return False

        tmp_model = None
        tmp_meta = None
        tmp_manifest = None
        try:
            model_dir = os.path.dirname(os.path.abspath(model_path))
            os.makedirs(model_dir, exist_ok=True)
            suffix = f"{os.getpid()}.{time.time_ns()}"
            tmp_model = f"{model_path}.tmp.{suffix}"
            tmp_meta = f"{metadata_path}.tmp.{suffix}"
            manifest_path = os.path.join(model_dir, "model_manifest.json")
            tmp_manifest = f"{manifest_path}.tmp.{suffix}"

            # 1. Dump model binary to temporary file
            joblib.dump(self.model, tmp_model)

            # 2. Compute binary SHA-256 and generation ID
            with open(tmp_model, "rb") as fh:
                model_sha256 = hashlib.sha256(fh.read()).hexdigest()

            generation_id = getattr(self, "generation_id", None) or uuid.uuid4().hex[:16]
            self.generation_id = generation_id
            self.model_sha256 = model_sha256

            # 3. Create metadata bound to generation and binary SHA-256
            meta = {
                "generation_id": generation_id,
                "model_sha256": model_sha256,
                "trained_at": self.trained_at,
                "training_sample_count": self.training_sample_count,
                "min_samples": self.min_samples,
                "feature_names": self.feature_names,
                "feature_count": len(self.feature_names),
                "n_estimators": self.n_estimators,
                "max_samples": self.max_samples,
                "contamination": self.contamination,
                "max_features": self.max_features,
                "random_state": self.random_state,
            }
            with open(tmp_meta, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2)

            with open(tmp_meta, "rb") as fh:
                meta_sha256 = hashlib.sha256(fh.read()).hexdigest()

            # 4. Create generation manifest
            manifest = {
                "generation_id": generation_id,
                "model_file": os.path.basename(model_path),
                "model_sha256": model_sha256,
                "metadata_file": os.path.basename(metadata_path),
                "metadata_sha256": meta_sha256,
                "committed_at": time.time(),
            }
            with open(tmp_manifest, "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=2)

            # 5. Atomic replacement sequence: model, then metadata, then manifest commit
            os.replace(tmp_model, model_path)
            os.replace(tmp_meta, metadata_path)
            os.replace(tmp_manifest, manifest_path)

            logger.info("Isolation Forest model generation %s saved atomically to %s", generation_id, model_path)
            return True
        except Exception as ex:
            for tmp_f in (tmp_model, tmp_meta, tmp_manifest):
                if tmp_f and os.path.exists(tmp_f):
                    try:
                        os.remove(tmp_f)
                    except OSError:
                        pass
            logger.error("Failed to save model: %s", ex)
            return False

    def load(
        self,
        model_path: str,
        metadata_path: str,
        enforce_approved_params: Optional[bool] = None,
    ) -> bool:
        """Load trained model artifact and verify generation integrity and parameters.

        Args:
            model_path: Filepath for the joblib model artifact.
            metadata_path: Filepath for the JSON metadata file.
            enforce_approved_params: Whether to enforce approved production hyperparameters
                (n_estimators=100, max_samples='auto', contamination='auto', max_features=1.0,
                random_state=42, 13 features, min_samples>=512). If None, defaults to True
                when min_samples >= 512 and n_estimators == 100.

        Returns:
            True if loaded successfully, False if missing, corrupted, interrupted, or incompatible.
        """
        if not os.path.exists(model_path) or not os.path.exists(metadata_path):
            self.status = ModelStatus.MODEL_NOT_READY
            return False

        if enforce_approved_params is None:
            enforce_approved_params = (self.min_samples >= 512 and self.n_estimators == 100)

        try:
            with open(metadata_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)

            # 1. Feature schema & ordering verification
            saved_features = meta.get("feature_names", [])
            if saved_features != self.feature_names:
                raise ValueError(
                    f"Loaded model feature ordering mismatch: expected {len(self.feature_names)} features, got {len(saved_features)}."
                )

            feature_count = meta.get("feature_count", len(saved_features))
            if feature_count != len(self.feature_names):
                raise ValueError(
                    f"Feature count mismatch: expected {len(self.feature_names)}, got {feature_count}."
                )

            # 2. Check minimum sample count
            training_sample_count = int(meta.get("training_sample_count", 0))
            if training_sample_count < self.min_samples:
                raise ValueError(
                    f"Insufficient baseline samples in persisted model: found {training_sample_count}, "
                    f"minimum required is {self.min_samples}."
                )

            # 3. Model binary SHA-256 checksum and crash-consistency check
            with open(model_path, "rb") as fh:
                actual_model_sha256 = hashlib.sha256(fh.read()).hexdigest()

            expected_sha256 = meta.get("model_sha256")
            if expected_sha256 is not None and actual_model_sha256 != expected_sha256:
                raise ValueError(
                    f"Model binary SHA-256 mismatch (crash-inconsistent generation): "
                    f"metadata expected {expected_sha256}, actual binary is {actual_model_sha256}."
                )

            # 4. Generation manifest validation (if manifest exists)
            manifest_path = os.path.join(os.path.dirname(os.path.abspath(model_path)), "model_manifest.json")
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as mfh:
                        manifest = json.load(mfh)
                    if manifest.get("generation_id") and meta.get("generation_id"):
                        if manifest["generation_id"] != meta["generation_id"]:
                            raise ValueError(
                                f"Generation manifest mismatch: manifest generation {manifest.get('generation_id')} "
                                f"differs from metadata generation {meta.get('generation_id')}."
                            )
                    if manifest.get("model_sha256") and manifest["model_sha256"] != actual_model_sha256:
                        raise ValueError(
                            f"Manifest model SHA-256 mismatch: manifest {manifest.get('model_sha256')}, "
                            f"actual {actual_model_sha256}."
                        )
                except json.JSONDecodeError:
                    raise ValueError(f"Corrupted generation manifest file at {manifest_path}")

            # 5. Load model binary
            loaded_model = joblib.load(model_path)
            if not isinstance(loaded_model, IsolationForest):
                raise TypeError(f"Loaded artifact is not an IsolationForest instance: {type(loaded_model)}")

            if getattr(loaded_model, "n_features_in_", None) != len(self.feature_names):
                raise ValueError(
                    f"Loaded model features dimension mismatch: expected {len(self.feature_names)}, "
                    f"got {getattr(loaded_model, 'n_features_in_', None)}."
                )

            saved_n_estimators = meta.get("n_estimators")
            if saved_n_estimators is not None and getattr(loaded_model, "n_estimators", None) != saved_n_estimators:
                raise ValueError(
                    f"Loaded model binary n_estimators ({getattr(loaded_model, 'n_estimators', None)}) "
                    f"differs from metadata ({saved_n_estimators})."
                )

            # 6. Strict approved production parameters check
            if enforce_approved_params:
                if expected_sha256 is None:
                    raise ValueError("Model metadata lacks required model_sha256 checksum for production model.")
                if saved_n_estimators != 100 or getattr(loaded_model, "n_estimators", None) != 100:
                    raise ValueError(f"Invalid n_estimators for production Isolation Forest: expected 100, got {saved_n_estimators}")
                if meta.get("max_samples") != "auto" or getattr(loaded_model, "max_samples", None) != "auto":
                    raise ValueError(f"Invalid max_samples for production Isolation Forest: expected 'auto', got {meta.get('max_samples')}")
                if meta.get("contamination") != "auto" or getattr(loaded_model, "contamination", None) != "auto":
                    raise ValueError(f"Invalid contamination for production Isolation Forest: expected 'auto', got {meta.get('contamination')}")
                if meta.get("max_features") != 1.0 or getattr(loaded_model, "max_features", None) != 1.0:
                    raise ValueError(f"Invalid max_features for production Isolation Forest: expected 1.0, got {meta.get('max_features')}")
                if meta.get("random_state") != 42 or getattr(loaded_model, "random_state", None) != 42:
                    raise ValueError(f"Invalid random_state for production Isolation Forest: expected 42, got {meta.get('random_state')}")
                if training_sample_count < 512:
                    raise ValueError(f"Production model baseline samples must be >= 512, found {training_sample_count}")

            self.model = loaded_model
            self.trained_at = meta.get("trained_at")
            self.training_sample_count = training_sample_count
            self.generation_id = meta.get("generation_id")
            self.model_sha256 = actual_model_sha256
            self.n_estimators = saved_n_estimators or self.n_estimators
            self.max_samples = meta.get("max_samples", getattr(self, "max_samples", "auto"))
            self.contamination = meta.get("contamination", self.contamination)
            self.max_features = meta.get("max_features", getattr(self, "max_features", 1.0))
            self.random_state = meta.get("random_state", self.random_state)
            self.status = ModelStatus.READY
            self.last_error = None
            logger.info("Isolation Forest model (generation=%s) loaded successfully from %s", self.generation_id, model_path)
            return True

        except Exception as ex:
            self.model = None
            self.status = ModelStatus.ERROR
            self.last_error = f"Failed to load model: {str(ex)}"
            logger.error(self.last_error)
            return False
