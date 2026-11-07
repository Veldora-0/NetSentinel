"""Unit tests for Phase 1 Supervised Random Forest Training Pipeline.

Tests dataset validation, feature schema consistency, missing-value handling,
training reproducibility, model serialization, prediction output, data leakage safeguards,
and invalid input handling.
"""

import os
import pytest
import numpy as np

from ml.feature_extractor import FEATURE_NAMES
from ml.train_supervised import (
    DatasetPartition,
    DatasetValidationError,
    DataLeakageError,
    SupervisedPipeline,
    calculate_metrics_from_predictions,
    run_pipeline_experiment,
    load_partitions_from_synthetic_fixture,
)


# =========================================================================
# 1. Dataset Partition & Schema Validation Tests
# =========================================================================

def test_dataset_partition_initialization_and_validation():
    """Verify partition validates dimension and lengths correctly."""
    features = [[1.0] * 13 for _ in range(10)]
    labels = [0] * 5 + [1] * 5
    captures = ["cap-1"] * 10

    partition = DatasetPartition(
        name="test-part",
        features=features,
        labels=labels,
        capture_ids=captures,
    )

    assert partition.sample_count == 10
    assert partition.benign_count == 5
    assert partition.malicious_count == 5
    assert partition.unique_captures == ["cap-1"]

    pipeline = SupervisedPipeline()
    diag = pipeline.validate_partition(partition)
    assert diag["sample_count"] == 10
    assert diag["nan_count"] == 0
    assert diag["feature_dim"] == 13


def test_dataset_partition_dimension_mismatch_raises():
    """Verify partition with wrong feature dimension is rejected."""
    features = [[1.0] * 10 for _ in range(5)]  # 10 features instead of 13
    labels = [0] * 5
    captures = ["cap-1"] * 5

    partition = DatasetPartition(
        name="bad-dim",
        features=features,
        labels=labels,
        capture_ids=captures,
    )

    pipeline = SupervisedPipeline()
    with pytest.raises(DatasetValidationError, match="Feature dimension mismatch"):
        pipeline.validate_partition(partition)


def test_dataset_partition_missing_nan_inf_values_rejected():
    """Verify that NaNs or Infs in feature vectors trigger validation error."""
    features = [[1.0] * 13 for _ in range(5)]
    features[2][3] = float("nan")
    labels = [0] * 5
    captures = ["cap-1"] * 5

    partition = DatasetPartition(
        name="nan-part",
        features=features,
        labels=labels,
        capture_ids=captures,
    )

    pipeline = SupervisedPipeline()
    with pytest.raises(DatasetValidationError, match="Invalid numerical values"):
        pipeline.validate_partition(partition)


def test_dataset_partition_unknown_labels_rejected():
    """Verify that labels outside {0, 1} are rejected."""
    features = [[1.0] * 13 for _ in range(4)]
    labels = [0, 1, 2, 0]  # Label '2' is invalid
    captures = ["cap-1"] * 4

    partition = DatasetPartition(
        name="bad-label-part",
        features=features,
        labels=labels,
        capture_ids=captures,
    )

    pipeline = SupervisedPipeline()
    with pytest.raises(DatasetValidationError, match="Unknown labels"):
        pipeline.validate_partition(partition)


# =========================================================================
# 2. Data Leakage Safeguards
# =========================================================================

def test_data_leakage_safeguard_triggers_on_shared_capture():
    """Verify DataLeakageError is raised if any capture is shared across train and test."""
    p_train = DatasetPartition(
        name="train",
        features=[[1.0] * 13 for _ in range(10)],
        labels=[0] * 5 + [1] * 5,
        capture_ids=["cap-A"] * 5 + ["cap-B"] * 5,
    )

    p_test = DatasetPartition(
        name="test",
        features=[[1.0] * 13 for _ in range(4)],
        labels=[0] * 2 + [1] * 2,
        capture_ids=["cap-B"] * 2 + ["cap-C"] * 2,  # cap-B leaks!
    )

    pipeline = SupervisedPipeline()
    with pytest.raises(DataLeakageError, match="Critical Data Leakage"):
        pipeline.verify_no_data_leakage(p_train, [p_test])


def test_data_leakage_safeguard_passes_on_disjoint_captures():
    """Verify safeguard allows cleanly partitioned captures."""
    p_train = DatasetPartition(
        name="train",
        features=[[1.0] * 13 for _ in range(10)],
        labels=[0] * 5 + [1] * 5,
        capture_ids=["cap-A"] * 10,
    )

    p_val = DatasetPartition(
        name="val",
        features=[[1.0] * 13 for _ in range(6)],
        labels=[0] * 3 + [1] * 3,
        capture_ids=["cap-B"] * 6,
    )

    pipeline = SupervisedPipeline()
    pipeline.verify_no_data_leakage(p_train, [p_val])  # Must not raise


# =========================================================================
# 3. Model Training, Reproducibility & Output Format
# =========================================================================

def test_training_reproducibility():
    """Verify identical random_state produces identical tree models."""
    rng = np.random.default_rng(42)
    X = rng.normal(size=(40, 13)).tolist()
    y = ([0] * 20) + ([1] * 20)
    caps = ["cap-1"] * 40

    part = DatasetPartition(name="rep-train", features=X, labels=y, capture_ids=caps)

    p1 = SupervisedPipeline(model_config={"random_state": 42, "n_estimators": 20})
    p2 = SupervisedPipeline(model_config={"random_state": 42, "n_estimators": 20})

    p1.train(part)
    p2.train(part)

    preds1 = p1.model.predict(X)
    preds2 = p2.model.predict(X)
    np.testing.assert_array_equal(preds1, preds2)


def test_metrics_calculation_known_confusion_matrix():
    """Verify precision, recall, F1, FPR, and FNR calculations."""
    y_true = [1, 1, 1, 1, 0, 0, 0, 0]
    y_pred = [1, 1, 1, 0, 0, 0, 1, 0]
    # TP=3, FN=1, TN=3, FP=1

    m = calculate_metrics_from_predictions(y_true, y_pred)
    assert m.true_positives == 3
    assert m.false_negatives == 1
    assert m.true_negatives == 3
    assert m.false_positives == 1
    assert m.accuracy == 0.75
    assert m.precision == 0.75
    assert m.recall == 0.75
    assert m.f1_score == 0.75
    assert m.false_positive_rate == 0.25
    assert m.false_negative_rate == 0.25


# =========================================================================
# 4. Model Serialization & Production Safety Invariant
# =========================================================================

def test_experimental_model_serialization_and_safety_invariant(tmp_path):
    """Verify experimental model saves and loads without overwriting production."""
    features = [[0.5] * 13 for _ in range(20)]
    labels = [0] * 10 + [1] * 10
    part = DatasetPartition(name="train", features=features, labels=labels, capture_ids=["c1"] * 20)

    pipe = SupervisedPipeline(model_config={"n_estimators": 10})
    pipe.train(part)

    exp_model = str(tmp_path / "rf.joblib")
    exp_meta = str(tmp_path / "rf_meta.json")

    saved = pipe.save_experimental(exp_model, exp_meta)
    assert saved is True
    assert os.path.exists(exp_model)
    assert os.path.exists(exp_meta)

    # Test loading
    loader_pipe = SupervisedPipeline()
    loaded = loader_pipe.load_experimental(exp_model, exp_meta)
    assert loaded is True
    assert loader_pipe.model is not None


def test_saving_to_production_path_strictly_prohibited():
    """Verify that attempting to overwrite production isolation_forest.joblib raises PermissionError."""
    from config import Config
    features = [[0.5] * 13 for _ in range(20)]
    labels = [0] * 10 + [1] * 10
    part = DatasetPartition(name="train", features=features, labels=labels, capture_ids=["c1"] * 20)

    pipe = SupervisedPipeline(model_config={"n_estimators": 10})
    pipe.train(part)

    with pytest.raises(PermissionError, match="Safety Violation: Cannot overwrite production"):
        pipe.save_experimental(Config.ML_MODEL_PATH, "/tmp/meta.json")


# =========================================================================
# 5. End-to-End Pipeline Fixture Test
# =========================================================================

def test_synthetic_fixture_end_to_end_experiment(tmp_path):
    """Verify end-to-end experiment execution on synthetic multi-capture partitions."""
    train_p, val_p, test_p = load_partitions_from_synthetic_fixture()
    assert train_p.sample_count > 0
    assert val_p.sample_count > 0
    assert test_p.sample_count > 0

    out_dir = str(tmp_path / "reports")
    m_dir = str(tmp_path / "models")

    res = run_pipeline_experiment(
        train_partition=train_p,
        val_partition=val_p,
        test_partition=test_p,
        output_dir=out_dir,
        model_dir=m_dir,
    )

    assert os.path.exists(os.path.join(out_dir, "random_forest_baseline.json"))
    assert os.path.exists(os.path.join(out_dir, "random_forest_baseline.md"))
    assert os.path.exists(os.path.join(m_dir, "random_forest.joblib"))
    assert os.path.exists(os.path.join(m_dir, "random_forest_metadata.json"))

    assert res["validation_evaluation"]["overall_metrics"]["f1_score"] >= 0.90
    assert res["test_evaluation"]["overall_metrics"]["f1_score"] >= 0.90
