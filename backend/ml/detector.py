"""NetSentinel ML Anomaly Detector Module.

Orchestrates live traffic windowing, unsupervised baseline profile collection,
Isolation Forest inference, and real-time anomaly event dispatching.
"""

from collections import deque
from dataclasses import dataclass, asdict
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional
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


class MLAnomalyDetector:
    """Traffic windowing and Isolation Forest anomaly detection coordinator."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or Config.ML_SETTINGS

        self.enabled = bool(cfg.get("enabled", True))
        self.window_seconds = float(cfg.get("window_seconds", 5.0))
        self.baseline_windows = int(cfg.get("baseline_windows", 10))
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
            min_samples=max(5, self.baseline_windows // 2),
        )

        # Traffic window buffer
        self.window = TrafficWindow(window_seconds=self.window_seconds)

        # State & metrics tracking
        self._lock = threading.RLock()
        self.baseline_samples: List[List[float]] = []
        self.total_anomalies_detected: int = 0
        self.latest_prediction: str = "PENDING"
        self.latest_anomaly_score: float = 0.0
        self.latest_raw_score: float = 0.0
        self.last_alert_time: float = 0.0

        # Recent window history: deque of dicts for time-series dashboard visualization
        self.window_history: deque = deque(maxlen=30)
        # Event history of triggered anomalies
        self.anomaly_history: deque = deque(maxlen=100)

        # Event listeners (e.g. Socket.IO)
        self._anomaly_callbacks: List[Callable[[MLAnomalyEvent], None]] = []
        self._heartbeat_callback: Optional[Callable[[], None]] = None
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Attempt to load existing model artifact if available
        if os.path.exists(self.model_path) and os.path.exists(self.metadata_path):
            self.model.load(self.model_path, self.metadata_path)

        if self.model.status != ModelStatus.READY:
            self.model.status = ModelStatus.COLLECTING_BASELINE

    def set_heartbeat_callback(self, callback: Callable[[], None]) -> None:
        """Register a heartbeat callback invoked on completed window processing."""
        self._heartbeat_callback = callback

    def add_anomaly_callback(self, callback: Callable[[MLAnomalyEvent], None]) -> None:
        """Register a callback for generated ML anomaly events."""
        self._anomaly_callbacks.append(callback)

    def _filter_baseline_outliers(self, samples: List[List[float]]) -> List[List[float]]:
        """Filter extreme outlier windows from baseline samples before model fitting.

        Protects baseline training against adversarial pollution or flood traffic occurring
        during the initial baseline collection period.
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
                if len(clean_indices) >= self.model.min_samples:
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

    def process_packet(self, packet: ParsedPacket) -> None:
        """Callback invoked by PacketCapture for each captured frame."""
        if not self.enabled:
            return
        self.window.add_packet(packet)

    def evaluate_window(
        self, custom_features: Optional[List[float]] = None, custom_dict: Optional[Dict[str, float]] = None
    ) -> Optional[MLAnomalyEvent]:
        """Process one traffic window, handle baseline collection or live inference.

        Args:
            custom_features: Optional feature vector override (useful for testing).
            custom_dict: Optional feature dictionary override.

        Returns:
            MLAnomalyEvent if an anomaly was detected and cooldown passed, else None.
        """
        now = time.time()

        if custom_features is not None:
            vec = custom_features
            f_dict = custom_dict or {name: val for name, val in zip(self.model.feature_names, vec)}
            pkt_count = int(vec[0] * self.window_seconds)
        else:
            vec, f_dict, pkt_count = self.window.consume_window()

        with self._lock:
            # 1. Baseline Collection Mode
            if self.model.status == ModelStatus.COLLECTING_BASELINE:
                self.baseline_samples.append(vec)
                logger.info(
                    "Collected baseline traffic window %d/%d (packets=%d)",
                    len(self.baseline_samples),
                    self.baseline_windows,
                    pkt_count,
                )

                if len(self.baseline_samples) >= self.baseline_windows:
                    try:
                        clean_samples = self._filter_baseline_outliers(self.baseline_samples)
                        if len(clean_samples) >= self.model.min_samples:
                            self.model.train(clean_samples)
                            self.model.save(self.model_path, self.metadata_path)
                        else:
                            logger.warning(
                                "Baseline contained too many contaminated windows (%d clean < %d required). Continuing collection.",
                                len(clean_samples),
                                self.model.min_samples,
                            )
                    except Exception as err:
                        logger.error("Failed to train model from baseline: %s", err)

                self.window_history.append({
                    "timestamp": now,
                    "packets_per_sec": f_dict.get("packets_per_second", 0.0),
                    "bytes_per_sec": f_dict.get("bytes_per_second", 0.0),
                    "anomaly_score": 0.0,
                    "raw_score": 0.0,
                    "prediction": "COLLECTING",
                    "is_anomaly": False,
                })
                return None

            # 2. Live Inference Mode
            if self.model.status == ModelStatus.READY:
                try:
                    is_raw_anom, raw_score, norm_score = self.model.predict(vec)
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
            training_count = getattr(self.model, "training_sample_count", 0)
            collected_count = len(self.baseline_samples)
            if is_ready and collected_count == 0:
                collected_count = training_count or self.baseline_windows

            return {
                "enabled": self.enabled,
                "model_status": status_val,
                "model_ready": is_ready,
                "baseline_established": is_ready,
                "baseline_samples_collected": collected_count,
                "baseline_target_samples": self.baseline_windows,
                "training_sample_count": training_count,
                "total_anomalies_detected": self.total_anomalies_detected,
                "latest_prediction": self.latest_prediction,
                "latest_anomaly_score": self.latest_anomaly_score,
                "latest_raw_score": self.latest_raw_score,
                "anomaly_threshold": self.anomaly_threshold,
                "window_seconds": self.window_seconds,
                "last_alert_time": self.last_alert_time,
                "model_trained_at": self.model.trained_at,
            }

    def get_metrics(self) -> Dict[str, Any]:
        """Return history of evaluated traffic windows for dashboard visualization."""
        with self._lock:
            return {
                "status": self.get_status(),
                "window_history": list(self.window_history),
                "recent_anomalies": [evt.to_dict() for evt in list(self.anomaly_history)[-20:]],
            }
