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


_HEX_LOWER_CHARS = set("0123456789abcdef")
_GEN_ID_CHARS = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-")


def _is_valid_sha256(val: Any) -> bool:
    """Validate that val is strictly a 64-character lowercase hexadecimal SHA-256 string.

    Rejects non-string values, uppercase characters, whitespace (leading, trailing, or embedded),
    and non-hexadecimal characters. Does not perform normalization.
    """
    if not isinstance(val, str) or len(val) != 64:
        return False
    return all(c in _HEX_LOWER_CHARS for c in val)


def _is_valid_generation_id(val: Any) -> bool:
    """Validate that val is a valid non-empty generation ID string.

    Must be a string of length 8 to 64 alphanumeric characters (including _ and -) with no whitespace.
    """
    if not isinstance(val, str) or not val:
        return False
    if len(val) < 8 or len(val) > 64:
        return False
    return all(c in _GEN_ID_CHARS for c in val)


def _is_safe_filename(fname: Any, expected_name: str) -> bool:
    """Validate filename is safe, matches expected basename, and contains no path traversal."""
    if not isinstance(fname, str) or not fname:
        return False
    if "/" in fname or "\\" in fname or ".." in fname or "\x00" in fname:
        return False
    if os.path.basename(fname) != fname:
        return False
    return fname == expected_name


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

            # Clean up any stale temporary files from previous interrupted runs
            try:
                for entry in os.listdir(model_dir):
                    if ".tmp." in entry:
                        stale_path = os.path.join(model_dir, entry)
                        try:
                            os.remove(stale_path)
                        except OSError:
                            pass
            except OSError:
                pass

            suffix = f"{os.getpid()}.{time.time_ns()}"
            tmp_model = f"{model_path}.tmp.{suffix}"
            tmp_meta = f"{metadata_path}.tmp.{suffix}"
            manifest_path = os.path.join(model_dir, "model_manifest.json")
            tmp_manifest = f"{manifest_path}.tmp.{suffix}"

            # 1. Dump model binary to temporary file
            joblib.dump(self.model, tmp_model)

            # 2. Compute binary SHA-256 and fresh generation ID
            with open(tmp_model, "rb") as fh:
                model_sha256 = hashlib.sha256(fh.read()).hexdigest().lower()

            generation_id = uuid.uuid4().hex[:16]
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
                meta_sha256 = hashlib.sha256(fh.read()).hexdigest().lower()

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
            logger.error("Failed to save model: %s", ex)
            return False
        finally:
            # Guarantee temporary file cleanup on any failure
            for tmp_f in (tmp_model, tmp_meta, tmp_manifest):
                if tmp_f and os.path.exists(tmp_f):
                    try:
                        os.remove(tmp_f)
                    except OSError:
                        pass

    def load(
        self,
        model_path: str,
        metadata_path: str,
        enforce_approved_params: Optional[bool] = None,
    ) -> bool:
        """Load trained model artifact and verify generation integrity and parameters.

        Requires model binary, metadata JSON, and model_manifest.json to exist
        and belong to the same verified generation. Fails closed on any inconsistency.

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
        model_exists = os.path.exists(model_path)
        meta_exists = os.path.exists(metadata_path)
        model_dir = os.path.dirname(os.path.abspath(model_path))
        manifest_path = os.path.join(model_dir, "model_manifest.json")
        manifest_exists = os.path.exists(manifest_path)

        # Ordinary case: no model artifact has ever existed
        if not model_exists and not meta_exists and not manifest_exists:
            self.model = None
            self.status = ModelStatus.MODEL_NOT_READY
            self.last_error = None
            return False

        if enforce_approved_params is None:
            enforce_approved_params = (self.min_samples >= 512 and self.n_estimators == 100)

        try:
            # 1. Require all three generation artifacts; fail closed if any is missing
            if not model_exists:
                raise ValueError(f"Missing required model binary artifact at {model_path}")
            if not meta_exists:
                raise ValueError(f"Missing required model metadata at {metadata_path}")
            if not manifest_exists:
                raise ValueError(f"Missing required model manifest at {manifest_path}")

            # 2. Read and validate manifest structure
            try:
                with open(manifest_path, "r", encoding="utf-8") as mfh:
                    manifest = json.load(mfh)
            except Exception as m_err:
                raise ValueError(f"Malformed generation manifest JSON at {manifest_path}: {m_err}")

            if not isinstance(manifest, dict):
                raise ValueError(f"Malformed generation manifest at {manifest_path}: root must be a JSON object")

            # Validate required manifest fields
            required_manifest_fields = {
                "generation_id": str,
                "model_file": str,
                "model_sha256": str,
                "metadata_file": str,
                "metadata_sha256": str,
                "committed_at": (int, float),
            }
            for field, expected_type in required_manifest_fields.items():
                if field not in manifest or manifest[field] is None:
                    raise ValueError(f"Manifest missing required field: '{field}'")
                val = manifest[field]
                if not isinstance(val, expected_type):
                    raise ValueError(f"Manifest field '{field}' has invalid type: expected {expected_type}, got {type(val)}")

            # 3. Validate generation ID format (strictly 8-64 alphanumeric chars, no whitespace or normalization)
            manifest_generation_id = manifest["generation_id"]
            if not _is_valid_generation_id(manifest_generation_id):
                raise ValueError(f"Invalid manifest generation_id format: {repr(manifest_generation_id)}")

            # 4. Validate manifest checksum formats (strictly 64 lowercase hex chars, no normalization)
            manifest_model_sha256 = manifest["model_sha256"]
            if not _is_valid_sha256(manifest_model_sha256):
                raise ValueError(f"Invalid manifest model_sha256 checksum format: {repr(manifest_model_sha256)}")

            manifest_meta_sha256 = manifest["metadata_sha256"]
            if not _is_valid_sha256(manifest_meta_sha256):
                raise ValueError(f"Invalid manifest metadata_sha256 checksum format: {repr(manifest_meta_sha256)}")

            # 5. Validate filenames and reject path traversal or references outside expected model directory
            expected_model_file = os.path.basename(model_path)
            expected_meta_file = os.path.basename(metadata_path)

            manifest_model_file = manifest["model_file"]
            manifest_meta_file = manifest["metadata_file"]

            if not _is_safe_filename(manifest_model_file, expected_model_file):
                raise ValueError(f"Manifest model filename mismatch or path traversal: {repr(manifest_model_file)}")

            if not _is_safe_filename(manifest_meta_file, expected_meta_file):
                raise ValueError(f"Manifest metadata filename mismatch or path traversal: {repr(manifest_meta_file)}")

            resolved_model_path = os.path.abspath(os.path.join(model_dir, manifest_model_file))
            resolved_meta_path = os.path.abspath(os.path.join(model_dir, manifest_meta_file))
            if os.path.dirname(resolved_model_path) != model_dir or resolved_model_path != os.path.abspath(model_path):
                raise ValueError(f"Manifest model file resolves outside expected model directory: '{resolved_model_path}'")
            if os.path.dirname(resolved_meta_path) != model_dir or resolved_meta_path != os.path.abspath(metadata_path):
                raise ValueError(f"Manifest metadata file resolves outside expected model directory: '{resolved_meta_path}'")

            # 6. Read metadata file bytes, compute byte SHA-256, parse JSON, and verify feature schema
            with open(metadata_path, "rb") as fh:
                raw_meta_bytes = fh.read()
            actual_meta_sha256 = hashlib.sha256(raw_meta_bytes).hexdigest()

            try:
                meta = json.loads(raw_meta_bytes.decode("utf-8"))
            except Exception as j_err:
                raise ValueError(f"Corrupted metadata JSON file at {metadata_path}: {j_err}")
            if not isinstance(meta, dict):
                raise ValueError(f"Metadata root must be a JSON object: {metadata_path}")

            # Feature schema & ordering verification
            saved_features = meta.get("feature_names")
            if not isinstance(saved_features, list) or saved_features != self.feature_names:
                raise ValueError(
                    f"Loaded model feature ordering mismatch: expected {len(self.feature_names)} features, got {len(saved_features) if isinstance(saved_features, list) else type(saved_features)}."
                )

            feature_count = meta.get("feature_count")
            if not isinstance(feature_count, int) or feature_count != len(self.feature_names):
                raise ValueError(
                    f"Feature count mismatch: expected {len(self.feature_names)}, got {feature_count}."
                )

            # 7. Verify actual metadata file SHA-256 matches manifest metadata_sha256
            if actual_meta_sha256 != manifest_meta_sha256:
                raise ValueError(
                    f"Metadata SHA-256 mismatch: manifest expected {manifest_meta_sha256}, "
                    f"actual metadata file is {actual_meta_sha256}."
                )

            # 8. Verify generation IDs match across manifest and metadata (strictly no normalization)
            meta_generation_id = meta.get("generation_id")
            if not _is_valid_generation_id(meta_generation_id):
                raise ValueError(f"Invalid metadata generation_id format: {repr(meta_generation_id)}")

            if manifest_generation_id != meta_generation_id:
                raise ValueError(
                    f"Generation manifest mismatch: manifest generation '{manifest_generation_id}' "
                    f"differs from metadata generation '{meta_generation_id}'."
                )

            # 9. Validate metadata model_sha256 format (strictly 64 lowercase hex)
            expected_model_sha256 = meta.get("model_sha256")
            if not _is_valid_sha256(expected_model_sha256):
                raise ValueError(f"Invalid metadata model_sha256 checksum format: {repr(expected_model_sha256)}")

            # 10. Read actual model binary bytes and compute SHA-256
            with open(model_path, "rb") as fh:
                actual_model_sha256 = hashlib.sha256(fh.read()).hexdigest()

            if actual_model_sha256 != manifest_model_sha256:
                raise ValueError(
                    f"Manifest model SHA-256 mismatch: manifest {manifest_model_sha256}, "
                    f"actual {actual_model_sha256}."
                )

            if actual_model_sha256 != expected_model_sha256:
                raise ValueError(
                    f"Model binary SHA-256 mismatch (crash-inconsistent generation): "
                    f"metadata expected {expected_model_sha256}, actual binary is {actual_model_sha256}."
                )

            # 11. Check minimum sample count
            training_sample_count = meta.get("training_sample_count")
            if not isinstance(training_sample_count, int) or training_sample_count < self.min_samples:
                raise ValueError(
                    f"Insufficient baseline samples in persisted model: found {training_sample_count}, "
                    f"minimum required is {self.min_samples}."
                )

            # 12. Load model binary with joblib
            try:
                loaded_model = joblib.load(model_path)
            except Exception as j_err:
                raise ValueError(f"Corrupted or unreadable model binary at {model_path}: {j_err}")

            if not isinstance(loaded_model, IsolationForest):
                raise TypeError(f"Loaded artifact is not an IsolationForest instance: {type(loaded_model)}")

            # 13. Verify actual deserialized estimator attributes against metadata claims
            est_n_estimators = getattr(loaded_model, "n_estimators", None)
            if est_n_estimators != meta.get("n_estimators"):
                raise ValueError(
                    f"Estimator n_estimators ({est_n_estimators}) differs from metadata ({meta.get('n_estimators')})."
                )

            est_max_samples = getattr(loaded_model, "max_samples", None)
            if est_max_samples != meta.get("max_samples"):
                raise ValueError(
                    f"Estimator max_samples ({est_max_samples}) differs from metadata ({meta.get('max_samples')})."
                )

            est_contamination = getattr(loaded_model, "contamination", None)
            if est_contamination != meta.get("contamination"):
                raise ValueError(
                    f"Estimator contamination ({est_contamination}) differs from metadata ({meta.get('contamination')})."
                )

            est_max_features = getattr(loaded_model, "max_features", None)
            if est_max_features != meta.get("max_features"):
                raise ValueError(
                    f"Estimator max_features ({est_max_features}) differs from metadata ({meta.get('max_features')})."
                )

            est_random_state = getattr(loaded_model, "random_state", None)
            if est_random_state != meta.get("random_state"):
                raise ValueError(
                    f"Estimator random_state ({est_random_state}) differs from metadata ({meta.get('random_state')})."
                )

            est_features_in = getattr(loaded_model, "n_features_in_", None)
            if est_features_in != len(self.feature_names):
                raise ValueError(
                    f"Loaded model feature dimension mismatch: expected {len(self.feature_names)}, got {est_features_in}."
                )

            fitted_trees = getattr(loaded_model, "estimators_", None)
            if fitted_trees is not None and len(fitted_trees) != est_n_estimators:
                raise ValueError(
                    f"Fitted tree count mismatch: ensemble has {len(fitted_trees)} trees, expected {est_n_estimators}."
                )

            # 14. Strict approved production parameters check on BOTH metadata and estimator
            if enforce_approved_params:
                if meta.get("n_estimators") != 100 or est_n_estimators != 100 or (fitted_trees is not None and len(fitted_trees) != 100):
                    raise ValueError(f"Invalid n_estimators for production Isolation Forest: expected 100")
                if meta.get("max_samples") != "auto" or est_max_samples != "auto":
                    raise ValueError(f"Invalid max_samples for production Isolation Forest: expected 'auto'")
                if meta.get("contamination") != "auto" or est_contamination != "auto":
                    raise ValueError(f"Invalid contamination for production Isolation Forest: expected 'auto'")
                if meta.get("max_features") != 1.0 or est_max_features != 1.0:
                    raise ValueError(f"Invalid max_features for production Isolation Forest: expected 1.0")
                if meta.get("random_state") != 42 or est_random_state != 42:
                    raise ValueError(f"Invalid random_state for production Isolation Forest: expected 42")
                if training_sample_count < 512:
                    raise ValueError(f"Production model baseline samples must be >= 512, found {training_sample_count}")

            # Every integrity and compatibility check succeeded. Model transitions to READY.
            self.model = loaded_model
            self.trained_at = meta.get("trained_at")
            self.training_sample_count = training_sample_count
            self.generation_id = manifest_generation_id
            self.model_sha256 = actual_model_sha256
            self.n_estimators = est_n_estimators
            self.max_samples = est_max_samples
            self.contamination = est_contamination
            self.max_features = est_max_features
            self.random_state = est_random_state
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
