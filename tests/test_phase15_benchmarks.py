"""Unit and integration tests for Phase 15 Benchmark Suites and Safety Invariants."""

import pytest
from evaluation.benchmarks import BenchmarkSuite, BenchmarkResult
from evaluation.data_generator import SyntheticDataGenerator
from config import Config


@pytest.fixture
def bench_suite():
    return BenchmarkSuite(data_generator=SyntheticDataGenerator(seed=123))


def test_benchmark_parser_execution(bench_suite):
    """Verify packet parser benchmark runs and returns valid statistics."""
    results = bench_suite.benchmark_parser(load_levels=[50])
    assert len(results) == 1
    res = results[0]
    assert res.category == "Parser"
    assert res.load_level == 50
    assert res.statistics["samples"] == 50
    assert res.statistics["throughput_ops_per_sec"] > 0.0
    assert res.statistics["mean_ms"] > 0.0


def test_benchmark_rule_detector_execution(bench_suite):
    """Verify rule detector benchmark runs and captures alert occurrences."""
    results = bench_suite.benchmark_rule_detector(load_levels=[50])
    assert len(results) == 1
    res = results[0]
    assert res.category == "Detection Rules"
    assert res.load_level == 50
    assert res.statistics["throughput_ops_per_sec"] > 0.0


def test_benchmark_ml_pipeline_execution(bench_suite):
    """Verify ML feature extraction and inference micro-benchmarks."""
    results = bench_suite.benchmark_ml_pipeline(load_levels=[25])
    assert len(results) >= 2  # Feature extraction + inference
    names = [r.name for r in results]
    assert "ML Feature Extraction" in names
    assert "Isolation Forest Inference" in names


def test_benchmark_risk_engine_execution(bench_suite):
    """Verify composite risk calculation benchmark."""
    results = bench_suite.benchmark_risk_engine(load_levels=[30])
    assert len(results) == 1
    res = results[0]
    assert res.category == "Risk Engine"
    assert res.statistics["samples"] == 30


def test_benchmark_incident_manager_execution(bench_suite):
    """Verify incident correlator and timeline benchmark."""
    results = bench_suite.benchmark_incident_manager(load_levels=[20])
    assert len(results) == 1
    res = results[0]
    assert res.category == "Incident Management"
    assert res.statistics["samples"] == 20


def test_benchmark_persistence_execution(bench_suite):
    """Verify SQLite persistence benchmark in isolated database."""
    results = bench_suite.benchmark_persistence(load_levels=[25])
    assert len(results) == 1
    res = results[0]
    assert res.category == "Persistence"
    assert res.statistics["samples"] >= 25


def test_benchmark_end_to_end_pipeline_execution(bench_suite):
    """Verify integrated synthetic pipeline benchmark."""
    results = bench_suite.benchmark_end_to_end_pipeline(load_levels=[25])
    assert len(results) == 1
    res = results[0]
    assert res.category == "Integrated Pipeline"
    assert res.statistics["samples"] == 25


def test_benchmark_safety_invariants(bench_suite):
    """Verify strict safety invariants: firewall disabled, auto-block disabled, dry run."""
    assert Config.FIREWALL_SETTINGS["enabled"] is False
    assert Config.FIREWALL_SETTINGS["auto_block"] is False
    assert Config.FIREWALL_SETTINGS["dry_run"] is True
