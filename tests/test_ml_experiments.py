"""Tests for NetSentinel ML Experiments Package.

Verifies synthetic traffic generation, feature analysis, hyperparameter search,
threshold calibration, and experiment report generation.
"""

import json
import os
import shutil
import sys
import tempfile
import pytest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from ml.feature_extractor import FEATURE_NAMES
from ml_experiments.data_loader import SyntheticTrafficGenerator, ValidationDataset
from ml_experiments.feature_experiments import (
    FeatureAnalyzer,
    CANONICAL_FEATURES,
)
from ml_experiments.hyperparameter_search import (
    IsolationForestOptimizer,
    HyperparameterTrial,
)
from ml_experiments.threshold_analysis import ThresholdAnalyzer, ThresholdSweepResult
from ml_experiments.experiment_runner import MLOptimizationRunner


def test_synthetic_traffic_generator_shapes():
    """Verify data generator produces valid 13-feature vectors for all normal and attack modes."""
    gen = SyntheticTrafficGenerator(seed=123)

    for mode in ["web", "stream", "dns", "ssh", "idle"]:
        norm_vec = gen.generate_normal_window(mode=mode)
        assert len(norm_vec) == 13
        assert len(norm_vec) == len(FEATURE_NAMES)
        assert all(np.isfinite(norm_vec))

    for atype in ["syn_flood", "udp_flood", "portscan", "slowloris", "c2_beacon"]:
        att_vec = gen.generate_attack_window(attack_type=atype)
        assert len(att_vec) == 13
        assert len(att_vec) == len(FEATURE_NAMES)
        assert all(np.isfinite(att_vec))


def test_build_benchmark_dataset():
    """Verify partitioned benchmark dataset generation."""
    gen = SyntheticTrafficGenerator(seed=42)
    ds = gen.build_benchmark_dataset(
        train_samples=50,
        val_normal_samples=20,
        val_attack_samples=20,
    )
    assert ds.X_train_normal.shape == (50, 13)
    assert ds.X_val.shape == (40, 13)
    assert ds.y_val.shape == (40,)
    assert np.sum(ds.y_val == 0) == 20
    assert np.sum(ds.y_val == 1) == 20
    assert len(ds.val_labels) == 40


def test_feature_analyzer_metrics():
    """Verify statistical analysis and Fisher separation scores."""
    gen = SyntheticTrafficGenerator(seed=42)
    ds = gen.build_benchmark_dataset(train_samples=40, val_normal_samples=20, val_attack_samples=20)
    analyzer = FeatureAnalyzer(CANONICAL_FEATURES)

    stats = analyzer.compute_feature_statistics(ds.X_train_normal)
    assert len(stats) == 13
    assert "packets_per_second" in stats
    assert stats["packets_per_second"]["mean"] > 0

    corr = analyzer.compute_correlation_matrix(ds.X_train_normal)
    assert len(corr) == 13
    assert corr["packets_per_second"]["packets_per_second"] == pytest.approx(1.0)

    val_norm = ds.X_val[ds.y_val == 0]
    val_att = ds.X_val[ds.y_val == 1]
    sep = analyzer.compute_separation_scores(val_norm, val_att)
    assert len(sep) == 13
    assert all(isinstance(v, float) for v in sep.values())


def test_hyperparameter_search_trial():
    """Verify single trial evaluation and grid search execution."""
    gen = SyntheticTrafficGenerator(seed=42)
    ds = gen.build_benchmark_dataset(train_samples=60, val_normal_samples=30, val_attack_samples=30)
    optimizer = IsolationForestOptimizer(ds)

    trial = optimizer.evaluate_configuration(
        trial_id=1,
        n_estimators=50,
        max_samples=64,
        contamination="auto",
        random_state=42,
    )
    assert isinstance(trial, HyperparameterTrial)
    assert trial.trial_id == 1
    assert 0.0 <= trial.accuracy <= 1.0
    assert 0.0 <= trial.f1_score <= 1.0
    assert 0.0 <= trial.roc_auc <= 1.0

    # Small grid search
    small_grid = {
        "n_estimators": [30, 50],
        "max_samples": [64],
        "contamination": ["auto"],
        "max_features": [1.0],
        "bootstrap": [False],
        "random_state": [42],
    }
    results = optimizer.run_grid_search(small_grid)
    assert len(results) == 2
    best = optimizer.get_best_trial()
    assert best is not None
    assert best == results[0]


def test_threshold_analyzer():
    """Verify decision threshold sweep identifies best F1 and low FPR points."""
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    norm_scores = np.array([0.2, 0.3, 0.35, 0.45, 0.55, 0.65, 0.70, 0.85])

    analyzer = ThresholdAnalyzer(y_true, norm_scores)
    res = analyzer.sweep_thresholds(min_thresh=0.30, max_thresh=0.70, step=0.05, target_max_fpr=0.05)

    assert isinstance(res, ThresholdSweepResult)
    assert res.best_f1_point.f1_score >= 0.8
    assert res.best_low_fpr_point.false_positive_rate <= 0.05
    assert len(res.sweep_curve) > 0


def test_ml_optimization_runner_execution():
    """Verify end-to-end experiment runner generates all expected artifacts."""
    temp_dir = tempfile.mkdtemp(prefix="test_ml_opt_")
    try:
        runner = MLOptimizationRunner(output_dir=temp_dir, seed=42)
        report = runner.run_all_experiments(
            train_samples=40,
            val_samples=30,
            quick=True,
        )

        assert "hyperparameter_search" in report
        assert "threshold_calibration" in report
        assert os.path.exists(os.path.join(temp_dir, "experiment_results.json"))
        assert os.path.exists(os.path.join(temp_dir, "experiment_comparison.csv"))
        assert os.path.exists(os.path.join(temp_dir, "threshold_analysis.json"))
        assert os.path.exists(os.path.join(temp_dir, "optimization_summary.md"))

        with open(os.path.join(temp_dir, "experiment_results.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "hyperparameter_search" in data
            assert data["hyperparameter_search"]["total_trials"] > 0
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_kaggle_evaluation_package_smoke():
    """Verify kaggle evaluation smoke test runs and produces valid comparison artifacts."""
    from kaggle_evaluation.smoke_test_kaggle_package import run_kaggle_smoke_test
    # Should execute and pass without throwing any exception
    run_kaggle_smoke_test()

