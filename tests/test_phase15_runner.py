"""Unit tests for Phase 15 EvaluationRunner and ResourceMonitor."""

import os
import shutil
import tempfile
import pytest

from evaluation.runner import EvaluationRunner
from evaluation.resource_monitor import ResourceMonitor
from evaluation.ml_evaluator import MLEvaluator


def test_resource_monitor_lifecycle():
    """Verify ResourceMonitor captures initial baseline and final delta."""
    monitor = ResourceMonitor()
    snap = monitor.start()
    assert snap.process_rss_mb > 0.0

    inter_snap = monitor.sample()
    assert inter_snap.process_rss_mb > 0.0

    summary = monitor.stop()
    assert summary["elapsed_wall_clock_sec"] >= 0.0
    assert summary["baseline_rss_mb"] > 0.0
    assert summary["peak_rss_mb"] >= summary["baseline_rss_mb"]
    assert "platform" in summary
    assert summary["platform"]["os"] == "Linux"


def test_ml_evaluator_standalone():
    """Verify supervised evaluation of unsupervised Isolation Forest pipeline."""
    evaluator = MLEvaluator()
    res = evaluator.run_evaluation(
        baseline_windows=20,
        normal_test_count=20,
        anomaly_test_count=20,
        thresholds=[0.40, 0.50, 0.60],
    )

    assert res.production_threshold == 0.50
    assert res.dataset_summary["total_eval_samples"] == 40
    assert len(res.sample_predictions) == 40
    assert len(res.threshold_analysis) == 3

    # Anomaly scores must be separated: anomaly mean > normal mean
    norm_mean = res.score_distribution["normal_windows"]["mean"]
    anom_mean = res.score_distribution["anomalous_windows"]["mean"]
    assert anom_mean > norm_mean
    assert res.score_distribution["separation_margin"] > 0.0


def test_evaluation_runner_quick_execution():
    """Verify EvaluationRunner executes end-to-end and serializes artifacts."""
    temp_dir = tempfile.mkdtemp(prefix="netsentinel_test_runner_")

    try:
        runner = EvaluationRunner(output_dir=temp_dir)
        report = runner.run(quick=True)

        assert "environment" in report
        assert "resource_usage" in report
        assert len(report["benchmarks"]) > 0
        assert "ml_evaluation" in report

        # Verify files on disk
        json_file = os.path.join(temp_dir, "evaluation_report.json")
        bench_csv = os.path.join(temp_dir, "benchmark_summary.csv")
        ml_csv = os.path.join(temp_dir, "ml_evaluation_samples.csv")

        assert os.path.exists(json_file)
        assert os.path.exists(bench_csv)
        assert os.path.exists(ml_csv)
        assert os.path.getsize(json_file) > 100
        assert os.path.getsize(bench_csv) > 100
        assert os.path.getsize(ml_csv) > 100

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
