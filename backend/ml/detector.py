"""NetSentinel ML Anomaly Detector Module.

Orchestrates live traffic windowing, unsupervised baseline profile collection,
Isolation Forest inference, and real-time anomaly event dispatching.
"""

from collections import deque, OrderedDict
from dataclasses import dataclass, asdict
import logging
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

import numpy as np

from config import Config
from ml.feature_extractor import TrafficWindow, FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus
from parser import ParsedPacket

logger = logging.getLogger("netsentinel.ml.detector")


@dataclass
class MLAnomalyEvent:
    """Structured machine learning anomaly event."""
    event_id: str
    timestamp: float
    event_type: str
    severity: str
    prediction: str
    raw_score: float
    anomaly_score: float
    features: Dict[str, float]
    model_status: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    detection_type: str = "ML_ANOMALY"

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to JSON-serializable dictionary."""
        return asdict(self)


def two_stage_trim_filter(
    samples: List[List[float]],
    trim_percent: float = 0.05,
    min_samples: int = 512,
) -> List[List[float]]:
    """Experimental defense: score baseline windows with a 50-tree Isolation Forest and trim top anomaly scores.

    LIMITATIONS (Empirical Research Findings):
    1. Trims legitimate high-throughput traffic: On 100% clean baselines, removes ~5.1% of authentic
       valid network windows (such as active HTTP/FTP transfers).
    2. Vulnerable under heavy contamination: Under >=20% attack contamination, the preliminary
       Isolation Forest internalizes the attack pattern and trims legitimate benign windows instead.
    3. Disabled by default in production (baseline_filter='none') to protect authentic benign traffic.
    """
    if len(samples) < 50:
        return list(samples)

    try:
        from sklearn.ensemble import IsolationForest

        arr = np.asarray(samples, dtype=np.float64)
        if not np.all(np.isfinite(arr)):
            return list(samples)

        init_forest = IsolationForest(
            n_estimators=50,
            max_samples="auto",
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        init_forest.fit(arr)
        # raw decision score: lower (more negative) is more anomalous
        scores = init_forest.decision_function(arr)

        trim_count = int(np.floor(len(samples) * trim_percent))
        if trim_count <= 0:
            return list(samples)

        # Retain indices with highest decision scores (most inlier-like)
        ranked_indices = np.argsort(scores)  # lowest (most anomalous) first
        retained_indices = set(ranked_indices[trim_count:])

        if len(retained_indices) >= min_samples:
            logger.info(
                "Experimental Two-Stage Trim: trimmed %d suspicious windows, retained %d clean windows.",
                trim_count,
                len(retained_indices),
            )
            return [samples[i] for i in range(len(samples)) if i in retained_indices]

        return list(samples)
    except Exception as ex:
        logger.warning("Two-Stage Trim filtering failed: %s. Using untrimmed baseline.", ex)
        return list(samples)


def filter_baseline_outliers(
    samples: List[List[float]], min_samples: int = 5
) -> List[List[float]]:
    """Filter extreme outlier windows from baseline samples before model fitting.

    HISTORICAL NOTE & CAUTION:
    In baseline scaling evaluations, 3.0x IQR volumetric filtering stripped 100% of authentic
    TCP sessions during idle collection periods (imposing an artificial 1.13 KB/s upper bound),
    causing false positive rate to spike to 54.77%.
    This function is preserved for diagnostic analysis, but is strictly EXCLUDED from the
    default production baseline path.
    """
    if len(samples) < 8:
        return list(samples)

    try:
        arr = np.asarray(samples, dtype=np.float64)
        # Inspect key volumetric and attack features:
        # 0: packets_per_second, 1: bytes_per_second, 6: syn_ratio, 10: unique_destination_ports
        check_indices = [0, 1, 6, 10]
        outlier_set = set()

        for idx in check_indices:
            if idx >= arr.shape[1]:
                continue
            col = arr[:, idx]
            q25 = float(np.percentile(col, 25))
            q75 = float(np.percentile(col, 75))
            iqr = q75 - q25
            med = float(np.median(col))
            std = float(np.std(col))

            if iqr > 1e-4:
                upper_bound = q75 + (3.0 * iqr)
            elif std > 1e-4:
                upper_bound = med + (3.0 * std)
            else:
                upper_bound = max(1.0, med * 3.0)

            outliers = np.where(col > upper_bound)[0]
            for out_idx in outliers:
                outlier_set.add(int(out_idx))

        if outlier_set:
            clean_indices = [i for i in range(len(samples)) if i not in outlier_set]
            if len(clean_indices) >= min_samples:
                logger.warning(
                    "Baseline contamination defense: filtered %d outlier windows from baseline (retained %d clean windows).",
                    len(outlier_set),
                    len(clean_indices),
                )
                return [samples[i] for i in clean_indices]

        return list(samples)
    except Exception as ex:
        logger.debug("Baseline outlier filtering skipped due to error: %s", ex)
        return list(samples)


class MLAnomalyDetector:
    """Traffic windowing and Isolation Forest anomaly detection coordinator."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or Config.ML_SETTINGS

        self.enabled = bool(cfg.get("enabled", True))
        self.window_seconds = float(cfg.get("window_seconds", 5.0))
        # Approved production baseline: 512 valid windows (~42m 40s at 5.0s/window)
        self.baseline_windows = max(1, int(cfg.get("baseline_windows", 512)))
        self.min_samples = max(1, int(cfg.get("min_samples", self.baseline_windows)))
        if self.min_samples > self.baseline_windows:
            logger.warning(
                "min_samples (%d) cannot exceed baseline_windows (%d); clamping min_samples to %d.",
                self.min_samples,
                self.baseline_windows,
                self.baseline_windows,
            )
            self.min_samples = self.baseline_windows

        # Initial production baseline filtering: strictly 'none' unless explicitly configured
        raw_filter = str(cfg.get("baseline_filter", "none")).strip().lower()
        if raw_filter not in ("none", "two_stage_trim", "iqr"):
            logger.warning("Unrecognized baseline_filter '%s'; falling back to production default 'none'.", raw_filter)
            raw_filter = "none"
        self.baseline_filter = raw_filter
        if self.baseline_filter == "two_stage_trim":
            logger.warning(
                "EXPERIMENTAL DEFENSE ACTIVE: Two-Stage Trim baseline filter enabled. "
                "Note: this filter removes ~5.1%% of authentic traffic on clean baselines and breaks under >=20%% contamination."
            )

        self.alert_cooldown_seconds = float(cfg.get("alert_cooldown_seconds", 15.0))
        self.anomaly_threshold = float(cfg.get("anomaly_threshold", 0.50))
        self.model_path = str(cfg.get("model_path", Config.ML_MODEL_PATH))
        self.metadata_path = str(cfg.get("metadata_path", Config.ML_METADATA_PATH))

        # Model wrapper
        contamination_val = cfg.get("contamination", "auto")
        self.model = IsolationForestModel(
            n_estimators=int(cfg.get("n_estimators", 100)),
            max_samples=cfg.get("max_samples", "auto"),
            contamination=contamination_val,
            max_features=float(cfg.get("max_features", 1.0)),
            random_state=int(cfg.get("random_state", 42)),
            min_samples=self.min_samples,
        )

        # Traffic window buffer
        self.window = TrafficWindow(window_seconds=self.window_seconds)

        # State & metrics tracking
        self._lock = threading.RLock()
        self._training_lock = threading.Lock()
        self.baseline_samples: List[List[float]] = []

        # Bounded deduplication tracking (FIFO bounded to max 2048 entries to prevent unbounded memory growth)
        self._max_dedup_entries: int = 2048
        self._seen_window_ids: OrderedDict = OrderedDict()
        self._seen_window_timestamps: OrderedDict = OrderedDict()

        self.training_in_progress: bool = False
        self.total_anomalies_detected: int = 0
        self.latest_prediction: str = "PENDING"
        self.latest_anomaly_score: float = 0.0
        self.latest_raw_score: float = 0.0
        self.last_alert_time: float = 0.0

        # Sensor status provider hook
        self._sensor_status_provider: Optional[Callable[[], Dict[str, Any]]] = None

        # Recent window history: deque of dicts for time-series dashboard visualization
        self.window_history: deque = deque(maxlen=30)
        # Event history of triggered anomalies
        self.anomaly_history: deque = deque(maxlen=100)

        # Event listeners (e.g. Socket.IO)
        self._anomaly_callbacks: List[Callable[[MLAnomalyEvent], None]] = []
        self._heartbeat_callback: Optional[Callable[[], None]] = None
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Attempt to load existing model artifact if available and valid
        model_loaded = False
        if os.path.exists(self.model_path) and os.path.exists(self.metadata_path):
            model_loaded = self.model.load(self.model_path, self.metadata_path)
            if not model_loaded:
                logger.warning(
                    "Persisted model artifact at %s rejected or incompatible. Starting fresh baseline collection (%d windows).",
                    self.model_path,
                    self.baseline_windows,
                )

        if not model_loaded:
            self.model.status = ModelStatus.COLLECTING_BASELINE

    def set_sensor_status_provider(self, provider: Callable[[], Dict[str, Any]]) -> None:
        """Register a provider callable returning real-time sensor operational health."""
        with self._lock:
            self._sensor_status_provider = provider

    def get_sensor_statuses(self) -> Dict[str, str]:
        """Retrieve actual operational health for hybrid intrusion sensors.

        Returns:
            Dict mapping sensor names ('rule_nids', 'suricata', 'hids') to
            'active', 'stopped', 'failed', or 'unknown'.
        """
        with self._lock:
            provider = self._sensor_status_provider

        if provider is not None:
            try:
                raw = provider()
                if isinstance(raw, dict):
                    return {
                        k: str(raw.get(k, "unknown")).lower()
                        for k in ("rule_nids", "suricata", "hids")
                    }
            except Exception as ex:
                logger.warning("Error querying sensor status provider: %s", ex)

        return {
            "rule_nids": "unknown",
            "suricata": "unknown",
            "hids": "unknown",
        }

    def retry_training(self) -> bool:
        """Operator recovery action: retry fitting the model on existing baseline samples."""
        with self._lock:
            if len(self.baseline_samples) < self.min_samples:
                self.model.last_error = (
                    f"Cannot retry training: only {len(self.baseline_samples)} samples collected "
                    f"(minimum {self.min_samples} required)."
                )
                logger.warning(self.model.last_error)
                return False
            if self.training_in_progress:
                return False
            self.training_in_progress = True
            self.model.status = ModelStatus.TRAINING
            self.model.last_error = None
            training_batch = list(self.baseline_samples[:self.baseline_windows])

        return self._execute_training(training_batch)

    def reset_baseline(self, clear_samples: bool = False) -> None:
        """Operator recovery action: reset detector out of ERROR state back to COLLECTING_BASELINE."""
        with self._lock:
            if clear_samples:
                self.baseline_samples.clear()
                self._seen_window_ids.clear()
                self._seen_window_timestamps.clear()
            self.model.status = ModelStatus.COLLECTING_BASELINE
            self.model.last_error = None
            self.training_in_progress = False
            logger.info(
                "Operator reset baseline: state set to COLLECTING_BASELINE (retained %d samples, clear_samples=%s).",
                len(self.baseline_samples),
                clear_samples,
            )

    def set_heartbeat_callback(self, callback: Callable[[], None]) -> None:
        """Register a heartbeat callback invoked on completed window processing."""
        self._heartbeat_callback = callback

    def add_anomaly_callback(self, callback: Callable[[MLAnomalyEvent], None]) -> None:
        """Register a callback for generated ML anomaly events."""
        self._anomaly_callbacks.append(callback)

    def _filter_baseline(self, samples: List[List[float]]) -> List[List[float]]:
        """Filter baseline samples according to configured strategy.

        Approved production configuration uses 'none' (preserving 100% authentic normal windows).
        """
        if self.baseline_filter == "two_stage_trim":
            return two_stage_trim_filter(samples, trim_percent=0.05, min_samples=self.min_samples)
        elif self.baseline_filter == "iqr":
            return filter_baseline_outliers(samples, min_samples=self.min_samples)
        return list(samples)

    def _filter_baseline_outliers(self, samples: List[List[float]]) -> List[List[float]]:
        """Filter extreme outlier windows using the IQR filter function (for diagnostic evaluation)."""
        return filter_baseline_outliers(samples, min_samples=self.min_samples)

    def _execute_training(self, training_batch: List[List[float]]) -> bool:
        """Execute baseline filtering, model training, and atomic persistence.

        Uses self._training_lock to serialize fitting operations without holding
        the main reader lock (self._lock) across the entire training duration.
        """
        with self._training_lock:
            try:
                clean_samples = self._filter_baseline(training_batch)
                if len(clean_samples) < self.min_samples:
                    with self._lock:
                        self.model.status = ModelStatus.COLLECTING_BASELINE
                        self.training_in_progress = False
                    logger.warning(
                        "Baseline contained too many filtered windows (%d retained < %d required). Continuing collection.",
                        len(clean_samples),
                        self.min_samples,
                    )
                    return False

                train_ok = self.model.train(clean_samples)
                if not train_ok:
                    with self._lock:
                        self.model.status = ModelStatus.ERROR
                        self.training_in_progress = False
                    logger.error("Model fitting failed: %s", self.model.last_error)
                    return False

                save_ok = self.model.save(self.model_path, self.metadata_path)
                if not save_ok:
                    with self._lock:
                        self.model.status = ModelStatus.ERROR
                        self.model.last_error = f"Atomic persistence failed for {self.model_path}"
                        self.training_in_progress = False
                    logger.error(self.model.last_error)
                    return False

                with self._lock:
                    self.model.status = ModelStatus.READY
                    self.training_in_progress = False
                logger.info(
                    "Model training and persistence successfully completed with %d baseline windows.",
                    len(clean_samples),
                )
                return True
            except Exception as err:
                with self._lock:
                    self.model.status = ModelStatus.ERROR
                    self.model.last_error = f"Baseline training exception: {str(err)}"
                    self.training_in_progress = False
                logger.error(self.model.last_error)
                return False

    def process_packet(self, packet: ParsedPacket) -> None:
        """Callback invoked by PacketCapture for each captured frame."""
        if not self.enabled:
            return
        self.window.add_packet(packet)

    def evaluate_window(
        self,
        custom_features: Optional[List[float]] = None,
        custom_dict: Optional[Dict[str, float]] = None,
        window_id: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> Optional[MLAnomalyEvent]:
        """Process one traffic window, handle baseline collection or live inference.

        Args:
            custom_features: Optional feature vector override (useful for testing).
            custom_dict: Optional feature dictionary override.
            window_id: Optional unique window identifier for deduplication.
            timestamp: Optional window epoch timestamp.

        Returns:
            MLAnomalyEvent if an anomaly was detected and cooldown passed, else None.
        """
        now = float(timestamp) if timestamp is not None else time.time()

        if custom_features is not None:
            vec = custom_features
            f_dict = custom_dict or {name: val for name, val in zip(self.model.feature_names, vec)}
            try:
                pkt_count = int(vec[0] * self.window_seconds) if (len(vec) > 0 and np.isfinite(vec[0])) else 0
            except (OverflowError, ValueError, TypeError):
                pkt_count = 0
        else:
            vec, f_dict, pkt_count = self.window.consume_window()

        # Strict window validation:
        # 1. Feature length check (must be exactly 13)
        if not isinstance(vec, (list, tuple, np.ndarray)) or len(vec) != len(self.model.feature_names):
            logger.warning(
                "Rejected invalid traffic window: expected %d features, got %s",
                len(self.model.feature_names),
                len(vec) if hasattr(vec, "__len__") else "non-iterable",
            )
            return None

        # 2. Finite numeric values check (no NaN or Inf)
        try:
            vec_floats = [float(x) for x in vec]
        except (ValueError, TypeError):
            logger.warning("Rejected invalid traffic window: non-numeric feature encountered.")
            return None

        if not all(np.isfinite(x) for x in vec_floats):
            logger.warning("Rejected invalid traffic window: non-finite (NaN or Inf) feature encountered.")
            return None

        # 3. Non-negative checks
        if pkt_count < 0 or vec_floats[0] < 0.0 or vec_floats[1] < 0.0:
            logger.warning("Rejected invalid traffic window: negative count or rate encountered.")
            return None

        should_train = False
        training_batch: List[List[float]] = []

        with self._lock:
            # 4. Bounded deduplication checks
            if window_id is not None:
                if window_id in self._seen_window_ids:
                    logger.debug("Duplicate window ID '%s' ignored.", window_id)
                    return None
                self._seen_window_ids[window_id] = True
                if len(self._seen_window_ids) > self._max_dedup_entries:
                    self._seen_window_ids.popitem(last=False)

            if timestamp is not None:
                ts_key = round(float(timestamp), 4)
                if ts_key in self._seen_window_timestamps:
                    logger.debug("Duplicate window timestamp %s ignored.", ts_key)
                    return None
                self._seen_window_timestamps[ts_key] = True
                if len(self._seen_window_timestamps) > self._max_dedup_entries:
                    self._seen_window_timestamps.popitem(last=False)

            # 1. Baseline Collection Mode
            if self.model.status in (ModelStatus.COLLECTING_BASELINE, ModelStatus.MODEL_NOT_READY, ModelStatus.TRAINING):
                if self.model.status != ModelStatus.TRAINING:
                    self.baseline_samples.append(vec_floats)
                    # Memory cap: baseline collection buffer never grows unbounded
                    if len(self.baseline_samples) > (self.baseline_windows + 100):
                        self.baseline_samples.pop(0)

                    collected_count = len(self.baseline_samples)
                    logger.info(
                        "Collected baseline traffic window %d/%d (packets=%d)",
                        collected_count,
                        self.baseline_windows,
                        pkt_count,
                    )

                    # Trigger model fitting strictly when target baseline sample count is reached
                    if collected_count >= self.baseline_windows and not self.training_in_progress:
                        self.training_in_progress = True
                        self.model.status = ModelStatus.TRAINING
                        should_train = True
                        training_batch = list(self.baseline_samples[:self.baseline_windows])

                self.window_history.append({
                    "timestamp": now,
                    "packets_per_sec": f_dict.get("packets_per_second", 0.0),
                    "bytes_per_sec": f_dict.get("bytes_per_second", 0.0),
                    "anomaly_score": 0.0,
                    "raw_score": 0.0,
                    "prediction": "TRAINING" if self.model.status == ModelStatus.TRAINING else "COLLECTING",
                    "is_anomaly": False,
                })

        # Execute training outside global self._lock to prevent blocking API status reads
        if should_train:
            self._execute_training(training_batch)
            return None

        with self._lock:
            # 2. Live Inference Mode
            if self.model.status != ModelStatus.READY:
                return None

            try:
                is_raw_anom, raw_score, norm_score = self.model.predict(vec_floats)
                # Use calibrated decision threshold
                is_anomaly = bool(norm_score > self.anomaly_threshold)
                self.latest_raw_score = raw_score
                self.latest_anomaly_score = norm_score
                self.latest_prediction = "ANOMALY" if is_anomaly else "NORMAL"

                self.window_history.append({
                    "timestamp": now,
                    "packets_per_sec": f_dict.get("packets_per_second", 0.0),
                    "bytes_per_sec": f_dict.get("bytes_per_second", 0.0),
                    "anomaly_score": norm_score,
                    "raw_score": raw_score,
                    "prediction": self.latest_prediction,
                    "is_anomaly": is_anomaly,
                })

                if is_anomaly:
                    self.total_anomalies_detected += 1

                    # Cooldown check to avoid alert fatigue
                    if (now - self.last_alert_time) >= self.alert_cooldown_seconds:
                        self.last_alert_time = now
                        top_src = getattr(self.window, "last_primary_source_ip", None)
                        top_dst = getattr(self.window, "last_primary_destination_ip", None)
                        event = MLAnomalyEvent(
                            event_id=uuid.uuid4().hex[:12],
                            timestamp=now,
                            event_type="ML_ANOMALY",
                            severity="MEDIUM",
                            prediction="ANOMALY",
                            raw_score=raw_score,
                            anomaly_score=norm_score,
                            features=f_dict,
                            model_status="READY",
                            description=(
                                f"Anomalous traffic pattern detected: window score {norm_score:.4f} "
                                f"(raw: {raw_score:+.4f}) deviates significantly from the learned baseline."
                            ),
                            source_ip=top_src,
                            destination_ip=top_dst,
                            detection_type="ML_ANOMALY",
                        )
                        self.anomaly_history.append(event)

                        # Dispatch to observers
                        for cb in self._anomaly_callbacks:
                            try:
                                cb(event)
                            except Exception as cb_err:
                                logger.debug("Error in ML anomaly callback: %s", cb_err)

                        return event

            except Exception as pred_err:
                logger.error("Error during ML window prediction: %s", pred_err)

        return None

    def _worker_loop(self) -> None:
        """Background thread executing periodic window aggregation and evaluation."""
        while not self._stop_event.is_set():
            time.sleep(self.window_seconds)
            if self._stop_event.is_set():
                break
            try:
                self.evaluate_window()
                if self._heartbeat_callback:
                    try:
                        self._heartbeat_callback()
                    except Exception:
                        pass
            except Exception as err:
                logger.error("Unexpected error in ML worker loop: %s", err)

    def start(self) -> None:
        """Start the background window processor thread."""
        if not self.enabled or (self._worker_thread and self._worker_thread.is_alive()):
            return

        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="NetSentinel-MLDetector", daemon=True
        )
        self._worker_thread.start()
        logger.info("ML Anomaly Detector worker started (window=%0.1fs).", self.window_seconds)

    def stop(self) -> None:
        """Stop the background window processor thread."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.5)
        logger.info("ML Anomaly Detector worker stopped.")

    def get_status(self) -> Dict[str, Any]:
        """Return read-only current state summary for API and dashboard."""
        with self._lock:
            status_val = self.model.status.value
            is_ready = (self.model.status == ModelStatus.READY)
            is_training = self.training_in_progress or (self.model.status == ModelStatus.TRAINING)
            is_collecting = (self.model.status == ModelStatus.COLLECTING_BASELINE)
            is_error = (self.model.status == ModelStatus.ERROR)

            training_count = getattr(self.model, "training_sample_count", 0)
            collected_count = len(self.baseline_samples)
            if is_ready and collected_count == 0:
                collected_count = training_count or self.baseline_windows

            req_windows = self.baseline_windows
            progress_pct = 100.0 if is_ready else round(min(100.0, (collected_count / max(1, req_windows)) * 100.0), 1)

            if is_ready:
                warmup_status = "READY"
            elif is_training:
                warmup_status = "TRAINING"
            elif is_error:
                warmup_status = "ERROR"
            else:
                warmup_status = "WARMUP"

            return {
                "enabled": self.enabled,
                "model_status": status_val,
                "model_ready": is_ready,
                "is_ready": is_ready,
                "warmup_status": warmup_status,
                "baseline_established": is_ready,
                "baseline_windows_collected": collected_count,
                "baseline_windows_required": req_windows,
                "baseline_samples_collected": collected_count,
                "baseline_target_samples": req_windows,
                "warmup_progress_percent": progress_pct,
                "training_in_progress": is_training,
                "training_sample_count": training_count,
                "baseline_filter": self.baseline_filter,
                "error_message": self.model.last_error,
                "total_anomalies_detected": self.total_anomalies_detected,
                "latest_prediction": self.latest_prediction,
                "latest_anomaly_score": self.latest_anomaly_score,
                "latest_raw_score": self.latest_raw_score,
                "anomaly_threshold": self.anomaly_threshold,
                "window_seconds": self.window_seconds,
                "n_estimators": self.model.n_estimators,
                "last_alert_time": self.last_alert_time,
                "model_trained_at": self.model.trained_at,
                "sensors_active": self.get_sensor_statuses(),
                "recovery_action": "retry_or_reset" if is_error else None,
                "can_retry": bool(is_error and len(self.baseline_samples) >= self.min_samples),
            }

    def get_metrics(self) -> Dict[str, Any]:
        """Return history of evaluated traffic windows for dashboard visualization."""
        with self._lock:
            return {
                "status": self.get_status(),
                "window_history": list(self.window_history),
                "recent_anomalies": [evt.to_dict() for evt in list(self.anomaly_history)[-20:]],
            }
