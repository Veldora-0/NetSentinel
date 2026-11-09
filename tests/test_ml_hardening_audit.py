"""NetSentinel ML Hardening & Post-Implementation Audit Test Suite.

Verifies post-implementation hardening of the single 13-feature Isolation Forest:
1. Clean typing and imports (no NameError on Set or annotations).
2. Memory-bounded deduplication caches (max 2048 entries FIFO).
3. Crash-consistent single generation persistence and checksum verification.
4. Strict approved hyperparameter validation on model loading.
5. Operational sensor status reporting (active, stopped, failed, unknown).
6. Operator error recovery actions (retry_training, reset_baseline, REST endpoints).
7. Configuration invariant enforcement and production boundary protection.
"""

import hashlib
import json
import os
import tempfile
import time
from typing import Dict, List
import uuid

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from app import create_app
from config import Config
from config_validator import ConfigValidator, ConfigurationError
from ml.detector import MLAnomalyDetector
from ml.feature_extractor import FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus


def _create_valid_window(offset: int = 0) -> List[float]:
    """Generate canonical 13-feature synthetic normal window."""
    return [
        float(10.0 + (offset % 5)),    # packets_per_second
        float(5000.0 + (offset * 10)), # bytes_per_second
        500.0,                         # average_packet_size
        0.85,                          # tcp_ratio
        0.15,                          # udp_ratio
        0.0,                           # icmp_ratio
        0.05,                          # syn_ratio
        0.80,                          # ack_ratio
        0.0,                           # rst_ratio
        0.0,                           # fin_ratio
        4.0,                           # unique_destination_ports
        8.0,                           # unique_source_ips
        3.0,                           # unique_destination_ips
    ]


# ===========================================================================
# 1. Detector Import and Construction Sanity
# ===========================================================================
def test_detector_construction_no_name_error():
    """Verify MLAnomalyDetector constructs cleanly without Set or typing NameErrors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "window_seconds": 5.0,
            "baseline_windows": 512,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)
        assert detector is not None
        assert detector.baseline_windows == 512
        assert detector.min_samples == 512
        assert detector.baseline_filter == "none"
        assert detector.model.status == ModelStatus.COLLECTING_BASELINE


# ===========================================================================
# 2. Bounded Deduplication
# ===========================================================================
def test_bounded_deduplication_caps_memory_growth():
    """Verify deduplication tracking caches are strictly bounded to 2048 entries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 3000,
            "min_samples": 3000,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)

        # Feed 2500 distinct windows
        for i in range(2500):
            w_id = f"win-{i}"
            ts = 1000.0 + float(i) * 5.0
            vec = _create_valid_window(i)
            detector.evaluate_window(custom_features=vec, window_id=w_id, timestamp=ts)

        # Check bounded cache size
        assert len(detector._seen_window_ids) == 2048
        assert len(detector._seen_window_timestamps) == 2048

        # Evicted entry (e.g. win-0) is no longer in deduplication set
        assert "win-0" not in detector._seen_window_ids

        # Recent entry (e.g. win-2499) is in deduplication set
        assert "win-2499" in detector._seen_window_ids

        # Re-feeding an active entry is deduplicated (rejected)
        pre_count = len(detector.baseline_samples)
        detector.evaluate_window(
            custom_features=_create_valid_window(9999),
            window_id="win-2499",
            timestamp=25000.0,
        )
        assert len(detector.baseline_samples) == pre_count


# ===========================================================================
# 3. Crash-Consistent Persistence & Manifest Validation
# ===========================================================================
def test_persistence_atomic_generation_manifest():
    """Verify model save creates consistent binary, metadata, and manifest generation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        assert model.train(samples) is True
        assert model.save(model_path, meta_path) is True

        assert os.path.exists(model_path)
        assert os.path.exists(meta_path)
        assert os.path.exists(manifest_path)

        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)

        # Check generation binding
        assert "generation_id" in meta
        assert meta["generation_id"] == manifest["generation_id"]
        assert "model_sha256" in meta
        assert meta["model_sha256"] == manifest["model_sha256"]

        # Compute actual binary SHA256
        with open(model_path, "rb") as fh:
            actual_sha = hashlib.sha256(fh.read()).hexdigest()
        assert meta["model_sha256"] == actual_sha

        # Verify load succeeds
        loader_model = IsolationForestModel(n_estimators=100, min_samples=512)
        assert loader_model.load(model_path, meta_path) is True
        assert loader_model.status == ModelStatus.READY


def test_crash_interruption_checksum_mismatch_rejected():
    """Verify that a corrupted model binary or mismatched metadata generation is rejected on load."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        assert model.train(samples) is True
        assert model.save(model_path, meta_path) is True

        # Simulate crash-interrupted binary replacement (tampered/corrupted binary)
        with open(model_path, "ab") as fh:
            fh.write(b"interrupted_corrupted_trailing_bytes")

        loader_model = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader_model.load(model_path, meta_path)
        assert loaded is False
        assert loader_model.status == ModelStatus.ERROR
        assert "SHA-256 mismatch" in loader_model.last_error


def test_crash_interruption_manifest_mismatch_rejected():
    """Verify that mismatched manifest generation ID prevents loading out-of-sync generation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        assert model.train(samples) is True
        assert model.save(model_path, meta_path) is True

        # Tamper manifest to point to different generation
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["generation_id"] = "different_older_generation"
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

        loader_model = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader_model.load(model_path, meta_path)
        assert loaded is False
        assert loader_model.status == ModelStatus.ERROR
        assert "Generation manifest mismatch" in loader_model.last_error


def test_manifest_missing_rejected():
    """Verify loading fails closed when model_manifest.json is missing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        assert model.train(samples) is True
        assert model.save(model_path, meta_path) is True
        assert os.path.exists(manifest_path)

        # Remove manifest
        os.remove(manifest_path)

        loader_model = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader_model.load(model_path, meta_path)
        assert loaded is False
        assert loader_model.status == ModelStatus.ERROR
        assert loader_model.model is None
        assert "Missing required model manifest" in loader_model.last_error


@pytest.mark.parametrize("corrupt_content", [
    "not-json-content{[[",
    "[]",  # not a dict
    '{"generation_id": "123"}',  # missing required fields
    '{"generation_id": "", "model_file": "isolation_forest.joblib", "model_sha256": "abc", "metadata_file": "model_metadata.json", "metadata_sha256": "def", "committed_at": 12345}', # empty generation_id
])
def test_manifest_malformed_rejected(corrupt_content):
    """Verify loading fails closed when model_manifest.json is malformed or missing required fields."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        model.train(samples)
        model.save(model_path, meta_path)

        # Write corrupt manifest
        with open(manifest_path, "w", encoding="utf-8") as fh:
            fh.write(corrupt_content)

        loader_model = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader_model.load(model_path, meta_path)
        assert loaded is False
        assert loader_model.status == ModelStatus.ERROR
        assert loader_model.model is None
        assert "manifest" in loader_model.last_error.lower()


def test_metadata_tampering_rejected():
    """Verify loading fails closed when metadata file bytes are tampered."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        model.train(samples)
        model.save(model_path, meta_path)

        # Tamper metadata content (e.g. change trained_at timestamp)
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        meta["trained_at"] = 123456789.0
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

        loader_model = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader_model.load(model_path, meta_path)
        assert loaded is False
        assert loader_model.status == ModelStatus.ERROR
        assert loader_model.model is None
        assert "Metadata SHA-256 mismatch" in loader_model.last_error


def test_metadata_generation_id_mismatch_rejected():
    """Verify loading fails closed when metadata generation ID differs from manifest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        model.train(samples)
        model.save(model_path, meta_path)

        # Update metadata generation ID and recompute metadata_sha256 in manifest
        # to test purely generation ID mismatch detection
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        meta["generation_id"] = "different_metadata_gen"
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

        # Re-hash metadata into manifest so metadata hash passes, isolating generation mismatch
        with open(meta_path, "rb") as fh:
            new_meta_hash = hashlib.sha256(fh.read()).hexdigest()
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["metadata_sha256"] = new_meta_hash
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        loader_model = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader_model.load(model_path, meta_path)
        assert loaded is False
        assert loader_model.status == ModelStatus.ERROR
        assert loader_model.model is None
        assert "Generation manifest mismatch" in loader_model.last_error


def test_manifest_filename_mismatches_rejected():
    """Verify manifest model_file and metadata_file mismatches are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        model.train(samples)
        model.save(model_path, meta_path)

        # 1. Model file mismatch in manifest
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        orig_model_file = manifest["model_file"]
        manifest["model_file"] = "mismatched_model.joblib"
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        loader = IsolationForestModel(n_estimators=100, min_samples=512)
        assert loader.load(model_path, meta_path) is False
        assert loader.status == ModelStatus.ERROR
        assert loader.model is None
        assert "model filename mismatch" in loader.last_error.lower()

        # 2. Metadata file mismatch in manifest
        manifest["model_file"] = orig_model_file
        manifest["metadata_file"] = "mismatched_metadata.json"
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        loader2 = IsolationForestModel(n_estimators=100, min_samples=512)
        assert loader2.load(model_path, meta_path) is False
        assert loader2.status == ModelStatus.ERROR
        assert loader2.model is None
        assert "metadata filename mismatch" in loader2.last_error.lower()


@pytest.mark.parametrize("traversal_str", [
    "../escaped_model.joblib",
    "/tmp/escaped_model.joblib",
    "subdir/model.joblib",
    "..\\windows_traversal.joblib",
    "model.joblib\x00extra",
])
def test_manifest_path_traversal_rejected(traversal_str):
    """Verify paths containing traversal or references outside expected directory are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        model.train(samples)
        model.save(model_path, meta_path)

        # Inject path traversal in model_file
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["model_file"] = traversal_str
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        loader = IsolationForestModel(n_estimators=100, min_samples=512)
        assert loader.load(model_path, meta_path) is False
        assert loader.status == ModelStatus.ERROR
        assert loader.model is None
        assert ("traversal" in loader.last_error.lower() or "mismatch" in loader.last_error.lower() or "resolves outside" in loader.last_error.lower())


@pytest.mark.parametrize("invalid_checksum", [
    "tooshort12345",
    "toolong" + "a" * 64,
    "g" * 64, # non-hex character 'g'
    "z" * 64, # non-hex character 'z'
    "   ",
])
def test_manifest_invalid_checksum_formats_rejected(invalid_checksum):
    """Verify malformed checksum values (invalid length or non-hex characters) are rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")
        manifest_path = os.path.join(tmpdir, "model_manifest.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        model.train(samples)
        model.save(model_path, meta_path)

        # 1. Invalid model_sha256 in manifest
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        orig_model_sha = manifest["model_sha256"]
        manifest["model_sha256"] = invalid_checksum
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        loader = IsolationForestModel(n_estimators=100, min_samples=512)
        assert loader.load(model_path, meta_path) is False
        assert loader.status == ModelStatus.ERROR
        assert loader.model is None

        # 2. Invalid metadata_sha256 in manifest
        manifest["model_sha256"] = orig_model_sha
        manifest["metadata_sha256"] = invalid_checksum
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        loader2 = IsolationForestModel(n_estimators=100, min_samples=512)
        assert loader2.load(model_path, meta_path) is False
        assert loader2.status == ModelStatus.ERROR
        assert loader2.model is None


def test_mixed_generation_artifacts_rejected():
    """Verify incomplete or mixed-generation artifacts (binary from gen1, metadata/manifest from gen2) fail closed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dir1 = os.path.join(tmpdir, "gen1")
        dir2 = os.path.join(tmpdir, "gen2")
        os.makedirs(dir1, exist_ok=True)
        os.makedirs(dir2, exist_ok=True)

        m1_path = os.path.join(dir1, "isolation_forest.joblib")
        meta1_path = os.path.join(dir1, "model_metadata.json")

        m2_path = os.path.join(dir2, "isolation_forest.joblib")
        meta2_path = os.path.join(dir2, "model_metadata.json")

        # Train and save Gen 1
        model1 = IsolationForestModel(n_estimators=100, min_samples=512)
        samples1 = [_create_valid_window(i) for i in range(512)]
        model1.train(samples1)
        model1.save(m1_path, meta1_path)

        # Train and save Gen 2 (different samples to ensure distinct binary and checksum)
        model2 = IsolationForestModel(n_estimators=100, min_samples=512)
        samples2 = [_create_valid_window(i + 100) for i in range(512)]
        model2.train(samples2)
        model2.save(m2_path, meta2_path)

        # Create mixed generation directory: binary from gen1, metadata & manifest from gen2
        mixed_dir = os.path.join(tmpdir, "mixed")
        os.makedirs(mixed_dir, exist_ok=True)
        import shutil
        shutil.copy2(m1_path, os.path.join(mixed_dir, "isolation_forest.joblib"))
        shutil.copy2(meta2_path, os.path.join(mixed_dir, "model_metadata.json"))
        shutil.copy2(os.path.join(dir2, "model_manifest.json"), os.path.join(mixed_dir, "model_manifest.json"))

        mixed_model_path = os.path.join(mixed_dir, "isolation_forest.joblib")
        mixed_meta_path = os.path.join(mixed_dir, "model_metadata.json")

        loader = IsolationForestModel(n_estimators=100, min_samples=512)
        assert loader.load(mixed_model_path, mixed_meta_path) is False
        assert loader.status == ModelStatus.ERROR
        assert loader.model is None
        assert ("SHA-256 mismatch" in loader.last_error or "mismatch" in loader.last_error.lower())


# ===========================================================================
# 4. Strict Approved Hyperparameter Verification on Model Loading
# ===========================================================================
@pytest.mark.parametrize("param_key,invalid_value", [
    ("n_estimators", 50),
    ("n_estimators", 200),
    ("max_samples", 256),
    ("contamination", 0.05),
    ("max_features", 0.8),
    ("random_state", 99),
    ("feature_names", list(reversed(FEATURE_NAMES))),
])
def test_strict_parameter_checks_reject_unapproved_models(param_key, invalid_value):
    """Verify production model loading strictly enforces all approved hyperparameters."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")

        model = IsolationForestModel(n_estimators=100, min_samples=512)
        samples = [_create_valid_window(i) for i in range(512)]
        model.train(samples)
        model.save(model_path, meta_path)

        # Tamper metadata parameter
        with open(meta_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
        meta[param_key] = invalid_value
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)

        loader = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader.load(model_path, meta_path, enforce_approved_params=True)
        assert loaded is False
        assert loader.status == ModelStatus.ERROR


def test_strict_parameter_checks_reject_sub_512_production_model():
    """Verify production model loading rejects artifacts trained with fewer than 512 samples."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "isolation_forest.joblib")
        meta_path = os.path.join(tmpdir, "model_metadata.json")

        model = IsolationForestModel(n_estimators=100, min_samples=100)
        samples = [_create_valid_window(i) for i in range(256)]
        model.train(samples)
        model.save(model_path, meta_path)

        loader = IsolationForestModel(n_estimators=100, min_samples=512)
        loaded = loader.load(model_path, meta_path, enforce_approved_params=True)
        assert loaded is False
        assert loader.status == ModelStatus.ERROR
        assert "baseline samples" in loader.last_error.lower()


# ===========================================================================
# 5. Operational Sensor Status Reporting
# ===========================================================================
def test_sensors_active_defaults_to_unknown_without_provider():
    """Verify standalone detector reports 'unknown' for all sensors when no provider is registered."""
    detector = MLAnomalyDetector()
    status = detector.get_status()
    assert status["sensors_active"] == {
        "rule_nids": "unknown",
        "suricata": "unknown",
        "hids": "unknown",
    }


def test_sensors_active_reflects_actual_provider_health():
    """Verify detector reports dynamic operational health delivered by provider hook."""
    detector = MLAnomalyDetector()

    # Register stopped sensor state
    detector.set_sensor_status_provider(lambda: {
        "rule_nids": "stopped",
        "suricata": "failed",
        "hids": "active",
    })
    status = detector.get_status()
    assert status["sensors_active"] == {
        "rule_nids": "stopped",
        "suricata": "failed",
        "hids": "active",
    }


# ===========================================================================
# 6. Operator Error Recovery Actions
# ===========================================================================
def test_error_state_recovery_retry_training():
    """Verify operator can trigger retry_training to successfully recover detector from ERROR state."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = {
            "enabled": True,
            "baseline_windows": 10,
            "min_samples": 10,
            "model_path": os.path.join(tmpdir, "model.joblib"),
            "metadata_path": os.path.join(tmpdir, "meta.json"),
        }
        detector = MLAnomalyDetector(config=cfg)
        for i in range(10):
            detector.baseline_samples.append(_create_valid_window(i))

        # Manually induce ERROR state (e.g. simulating transient persistence failure)
        detector.model.status = ModelStatus.ERROR
        detector.model.last_error = "Simulated I/O disk error during initial fitting"
        status = detector.get_status()
        assert status["model_status"] == "ERROR"
        assert status["warmup_status"] == "ERROR"
        assert status["recovery_action"] == "retry_or_reset"
        assert status["can_retry"] is True

        # Retry training
        ok = detector.retry_training()
        assert ok is True
        assert detector.model.status == ModelStatus.READY
        assert detector.model.last_error is None
        assert detector.get_status()["warmup_status"] == "READY"


def test_error_state_recovery_reset_baseline():
    """Verify operator can reset detector from ERROR state back to baseline collection."""
    detector = MLAnomalyDetector()
    detector.model.status = ModelStatus.ERROR
    detector.model.last_error = "Baseline corruption encountered"

    detector.reset_baseline(clear_samples=True)
    assert detector.model.status == ModelStatus.COLLECTING_BASELINE
    assert detector.model.last_error is None
    assert len(detector.baseline_samples) == 0
    assert detector.get_status()["warmup_status"] == "WARMUP"


def test_api_retry_and_reset_endpoints():
    """Verify /api/ml/retry and /api/ml/reset REST endpoints function under Flask."""
    cfg = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "AUTH_ENFORCE_IN_TESTS": True,
    }
    app, _ = create_app(config_class=cfg, start_capture=False)

    with app.test_client() as client:
        # Create and authenticate admin user
        with app.app_context():
            from database import db
            from auth.roles import Role
            from auth.service import AuthService
            db.create_all()
            AuthService.create_user("audit_admin", "AdminPass123!", Role.ADMIN)
            _, token, _, _ = AuthService.authenticate("audit_admin", "AdminPass123!")
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Put detector in ERROR state
        detector = app.ml_detector
        detector.baseline_windows = 10
        detector.min_samples = 10
        detector.model.min_samples = 10
        detector.baseline_samples = [_create_valid_window(i) for i in range(10)]
        detector.model.status = ModelStatus.ERROR
        detector.model.last_error = "Test transient error"

        # 2. Call /api/ml/retry
        res_retry = client.post("/api/ml/retry", headers=headers)
        assert res_retry.status_code == 200
        data = res_retry.get_json()
        assert data["status"] == "ok"
        assert data["ml_status"]["model_status"] == "READY"

        # 3. Call /api/ml/reset
        res_reset = client.post("/api/ml/reset", headers=headers, json={"clear_samples": True})
        assert res_reset.status_code == 200
        data_reset = res_reset.get_json()
        assert data_reset["status"] == "ok"
        assert data_reset["ml_status"]["model_status"] == "COLLECTING_BASELINE"


# ===========================================================================
# 7. Configuration Safety and Invariant Enforcement
# ===========================================================================
def test_config_validator_enforces_min_samples_le_baseline_windows():
    """Verify ConfigValidator catches min_samples > baseline_windows violation."""
    bad_cfg = {
        "ML_SETTINGS": {
            "baseline_windows": 100,
            "min_samples": 200,
        }
    }
    with pytest.raises(ConfigurationError) as exc_info:
        ConfigValidator.validate_or_raise(bad_cfg)
    assert "cannot exceed ML_SETTINGS.baseline_windows" in str(exc_info.value)


def test_config_validator_enforces_production_baseline_size():
    """Verify ConfigValidator rejects sub-512 baseline sizes when operating in production."""
    prod_cfg = {
        "ENV": "production",
        "ML_SETTINGS": {
            "baseline_windows": 256,
            "min_samples": 256,
        }
    }
    # Clear test marker to simulate true production validation
    current_test = os.environ.pop("PYTEST_CURRENT_TEST", None)
    try:
        with pytest.raises(ConfigurationError) as exc_info:
            ConfigValidator.validate_or_raise(prod_cfg)
        assert "Production environment requires ML_SETTINGS.baseline_windows >= 512" in str(exc_info.value)
    finally:
        if current_test:
            os.environ["PYTEST_CURRENT_TEST"] = current_test
