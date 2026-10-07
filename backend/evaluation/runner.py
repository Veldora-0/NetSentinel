"""NetSentinel Performance & ML Evaluation Runner (Phase 15).

CLI and programmatic entrypoint for executing comprehensive performance benchmarks,
resource utilization profiling, and ML anomaly detection evaluations.

Usage:
    .venv/bin/python backend/evaluation/runner.py [--quick] [--output-dir reports/]
"""

import argparse
import csv
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure backend directory and project root are in python path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from evaluation.benchmarks import BenchmarkSuite, BenchmarkResult
from evaluation.ml_evaluator import MLEvaluator, MLEvaluationResult
from evaluation.resource_monitor import ResourceMonitor


class EvaluationRunner:
    """Orchestrates Phase 15 evaluation runs and serializes results."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or os.path.join(PROJECT_ROOT, "reports")
        os.makedirs(self.output_dir, exist_ok=True)
        self.resource_monitor = ResourceMonitor()
        self.benchmark_suite = BenchmarkSuite()
        self.ml_evaluator = MLEvaluator()

    def run(self, quick: bool = False) -> Dict[str, Any]:
        """Execute all benchmarks and ML evaluations."""
        print("=" * 70)
        print("NetSentinel Phase 15: Performance & Machine Learning Evaluation")
        print("=" * 70)

        # 1. Start Resource Monitoring
        self.resource_monitor.start()

        # Configure load levels
        if quick:
            parser_levels = [100, 500]
            detector_levels = [100, 500]
            ml_levels = [50, 100]
            risk_levels = [100, 500]
            inc_levels = [50, 100]
            db_levels = [50, 100]
            e2e_levels = [50, 100]
            ml_eval_normal = 50
            ml_eval_anomaly = 50
        else:
            parser_levels = [100, 1000, 5000]
            detector_levels = [100, 500, 1000]
            ml_levels = [50, 200, 500]
            risk_levels = [100, 500, 1000]
            inc_levels = [50, 200, 500]
            db_levels = [50, 200, 500]
            e2e_levels = [100, 500, 1000]
            ml_eval_normal = 100
            ml_eval_anomaly = 100

        all_benchmark_results: List[BenchmarkResult] = []

        # 2. Execute Benchmark Suites
        print("\n[1/7] Running Packet Parser benchmarks...")
        res_parser = self.benchmark_suite.benchmark_parser(load_levels=parser_levels)
        all_benchmark_results.extend(res_parser)
        for r in res_parser:
            print(f"  - Load: {r.load_level:<5} | Throughput: {r.statistics['throughput_ops_per_sec']:>10.2f} pkts/s | Mean: {r.statistics['mean_ms']:>7.4f} ms | p95: {r.statistics['p95_ms']:>7.4f} ms")

        print("\n[2/7] Running Rule Detector benchmarks...")
        res_detector = self.benchmark_suite.benchmark_rule_detector(load_levels=detector_levels)
        all_benchmark_results.extend(res_detector)
        for r in res_detector:
            print(f"  - Load: {r.load_level:<5} | Throughput: {r.statistics['throughput_ops_per_sec']:>10.2f} pkts/s | Mean: {r.statistics['mean_ms']:>7.4f} ms | p95: {r.statistics['p95_ms']:>7.4f} ms")

        print("\n[3/7] Running Machine Learning Pipeline benchmarks...")
        res_ml = self.benchmark_suite.benchmark_ml_pipeline(load_levels=ml_levels)
        all_benchmark_results.extend(res_ml)
        for r in res_ml:
            print(f"  - {r.name:<30} | Load: {r.load_level:<5} | Throughput: {r.statistics['throughput_ops_per_sec']:>10.2f} ops/s | Mean: {r.statistics['mean_ms']:>7.4f} ms")

        print("\n[4/7] Running Composite Risk Engine benchmarks...")
        res_risk = self.benchmark_suite.benchmark_risk_engine(load_levels=risk_levels)
        all_benchmark_results.extend(res_risk)
        for r in res_risk:
            print(f"  - Load: {r.load_level:<5} | Throughput: {r.statistics['throughput_ops_per_sec']:>10.2f} ops/s | Mean: {r.statistics['mean_ms']:>7.4f} ms | p95: {r.statistics['p95_ms']:>7.4f} ms")

        print("\n[5/7] Running Incident Correlator benchmarks...")
        res_inc = self.benchmark_suite.benchmark_incident_manager(load_levels=inc_levels)
        all_benchmark_results.extend(res_inc)
        for r in res_inc:
            print(f"  - Load: {r.load_level:<5} | Throughput: {r.statistics['throughput_ops_per_sec']:>10.2f} ops/s | Mean: {r.statistics['mean_ms']:>7.4f} ms | p95: {r.statistics['p95_ms']:>7.4f} ms")

        print("\n[6/7] Running SQLite Persistence benchmarks...")
        res_db = self.benchmark_suite.benchmark_persistence(load_levels=db_levels)
        all_benchmark_results.extend(res_db)
        for r in res_db:
            print(f"  - Load: {r.load_level:<5} | Throughput: {r.statistics['throughput_ops_per_sec']:>10.2f} ops/s | Mean: {r.statistics['mean_ms']:>7.4f} ms | p95: {r.statistics['p95_ms']:>7.4f} ms")

        print("\n[7/7] Running End-to-End Pipeline benchmarks...")
        res_e2e = self.benchmark_suite.benchmark_end_to_end_pipeline(load_levels=e2e_levels)
        all_benchmark_results.extend(res_e2e)
        for r in res_e2e:
            print(f"  - Load: {r.load_level:<5} | Throughput: {r.statistics['throughput_ops_per_sec']:>10.2f} pkts/s | Mean: {r.statistics['mean_ms']:>7.4f} ms | p95: {r.statistics['p95_ms']:>7.4f} ms")

        # 3. Supervised Machine Learning Evaluation
        print("\n[ML] Running Supervised ML Evaluation (Isolation Forest)...")
        ml_eval = self.ml_evaluator.run_evaluation(
            baseline_windows=50 if not quick else 20,
            normal_test_count=ml_eval_normal,
            anomaly_test_count=ml_eval_anomaly,
        )

        cm = ml_eval.confusion_matrix
        m = ml_eval.classification_metrics
        print(f"  - Confusion Matrix (at threshold 0.50): TP={cm['true_positives']} | TN={cm['true_negatives']} | FP={cm['false_positives']} | FN={cm['false_negatives']}")
        print(f"  - Precision: {m['precision']:.4f} | Recall: {m['recall']:.4f} | F1-Score: {m['f1_score']:.4f}")
        print(f"  - False Positive Rate: {m['false_positive_rate']:.4f} | False Negative Rate: {m['false_negative_rate']:.4f}")
        print(f"  - Score Distribution: Normal Mean={ml_eval.score_distribution['normal_windows']['mean']:.4f} vs Anomaly Mean={ml_eval.score_distribution['anomalous_windows']['mean']:.4f} (Margin: +{ml_eval.score_distribution['separation_margin']:.4f})")

        # 4. Finalize Resource Monitoring
        resource_summary = self.resource_monitor.stop()
        print(f"\n[Resource Usage] RSS Peak: {resource_summary['peak_rss_mb']} MB (Growth: +{resource_summary['process_memory_growth_mb']} MB) | Elapsed: {resource_summary['elapsed_wall_clock_sec']:.2f}s")

        # 5. Compile Master Report Dictionary
        report_data = {
            "timestamp": time.time(),
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "environment": resource_summary["platform"],
            "resource_usage": resource_summary,
            "benchmarks": [b.to_dict() for b in all_benchmark_results],
            "ml_evaluation": ml_eval.to_dict(),
        }

        # 6. Save Artifacts
        json_path = os.path.join(self.output_dir, "evaluation_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print(f"\n[Output] JSON Report saved to: {json_path}")

        # Benchmark Summary CSV
        csv_bench_path = os.path.join(self.output_dir, "benchmark_summary.csv")
        with open(csv_bench_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow([
                "Name", "Category", "LoadLevel", "ThroughputOpsPerSec",
                "MeanMs", "MedianMs", "P95Ms", "P99Ms", "MinMs", "MaxMs", "TotalDurationSec"
            ])
            for b in all_benchmark_results:
                st = b.statistics
                writer.writerow([
                    b.name, b.category, b.load_level, st["throughput_ops_per_sec"],
                    st["mean_ms"], st["median_ms"], st["p95_ms"], st["p99_ms"],
                    st["min_ms"], st["max_ms"], st["total_duration_sec"]
                ])
        print(f"[Output] Benchmark Summary CSV saved to: {csv_bench_path}")

        # ML Evaluation Samples CSV
        csv_ml_path = os.path.join(self.output_dir, "ml_evaluation_samples.csv")
        with open(csv_ml_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow([
                "SampleIndex", "GroundTruth", "LabelName", "Category",
                "RawScore", "NormalizedScore", "PredictedAnomalyAt0_50", "IsCorrect"
            ])
            for sp in ml_eval.sample_predictions:
                writer.writerow([
                    sp["sample_index"], sp["ground_truth"], sp["label_name"], sp["category"],
                    sp["raw_decision_score"], sp["normalized_anomaly_score"],
                    sp["predicted_anomaly_at_0_50"], sp["is_correct_at_0_50"]
                ])
        print(f"[Output] ML Samples CSV saved to: {csv_ml_path}")

        print("=" * 70)
        print("NetSentinel Phase 15 Evaluation Complete.")
        print("=" * 70)

        return report_data


def main():
    parser = argparse.ArgumentParser(description="NetSentinel Phase 15 Performance and ML Evaluation Runner")
    parser.add_argument("--quick", action="store_true", help="Run with reduced load levels for rapid validation")
    parser.add_argument("--output-dir", type=str, default=None, help="Directory to save generated evaluation artifacts")
    args = parser.parse_args()

    runner = EvaluationRunner(output_dir=args.output_dir)
    runner.run(quick=args.quick)


if __name__ == "__main__":
    main()
