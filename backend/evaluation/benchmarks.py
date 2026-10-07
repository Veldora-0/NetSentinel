"""NetSentinel Performance Benchmark Suite (Phase 15).

Evaluates latency, throughput, and scaling for existing components:
1. Packet parser
2. Rule-based detector
3. Machine learning pipeline (extraction, inference, windowing)
4. Composite risk engine
5. Incident manager and correlator
6. Durable SQLite persistence
7. End-to-end synthetic pipeline
"""

from dataclasses import dataclass, asdict
import os
import shutil
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from app import create_app
from database import (
    db,
    save_security_event_record,
    save_assessment_record,
    save_incident_record,
    save_incident_evidence_record,
    query_security_events,
    query_incidents,
    query_risk_history,
)
from detector import SecurityEvent, TrafficDetector
from incident_manager import IncidentManager
from ml.detector import MLAnomalyDetector
from ml.feature_extractor import extract_features_from_window, FEATURE_NAMES
from ml.model import IsolationForestModel, ModelStatus
from parser import parse_packet, ParsedPacket
from risk_engine import RiskEngine, RiskAssessment

from .data_generator import (
    generate_synthetic_raw_frame,
    generate_synthetic_parsed_packet,
    SyntheticDataGenerator,
)
from .metrics import calculate_statistics


@dataclass
class BenchmarkResult:
    """Standardized result envelope for benchmark executions."""
    name: str
    category: str
    load_level: int
    statistics: Dict[str, Any]
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BenchmarkSuite:
    """Deterministic performance evaluation engine for NetSentinel subsystems."""

    def __init__(self, data_generator: Optional[SyntheticDataGenerator] = None):
        self.gen = data_generator or SyntheticDataGenerator(seed=42)

    # =========================================================================
    # A. PACKET PARSER BENCHMARK
    # =========================================================================

    def benchmark_parser(
        self, load_levels: Optional[List[int]] = None
    ) -> List[BenchmarkResult]:
        """Benchmark binary Ethernet + IPv4 + TCP/UDP frame parser."""
        levels = load_levels or [100, 1000, 5000]
        results: List[BenchmarkResult] = []

        # Generate representative raw frame bytes
        raw_frames = [
            generate_synthetic_raw_frame(src_port=50000 + (i % 100), dst_port=80 if i % 2 == 0 else 443)
            for i in range(100)
        ]

        # Warm-up parser
        for f in raw_frames[:20]:
            parse_packet(f)

        for count in levels:
            latencies: List[float] = []
            start_wall = time.perf_counter()

            for i in range(count):
                frame = raw_frames[i % len(raw_frames)]
                t0 = time.perf_counter()
                pkt = parse_packet(frame)
                t1 = time.perf_counter()
                latencies.append(t1 - t0)

            total_wall = time.perf_counter() - start_wall
            stats = calculate_statistics(latencies, total_wall)

            results.append(
                BenchmarkResult(
                    name="Packet Parser",
                    category="Parser",
                    load_level=count,
                    statistics=stats,
                    details={"frame_size_bytes": len(raw_frames[0])},
                )
            )

        return results

    # =========================================================================
    # B. RULE DETECTOR BENCHMARK
    # =========================================================================

    def benchmark_rule_detector(
        self, load_levels: Optional[List[int]] = None
    ) -> List[BenchmarkResult]:
        """Benchmark rule detector processing across diverse packet sequences."""
        levels = load_levels or [100, 500, 1000]
        results: List[BenchmarkResult] = []

        # Create fresh detector with safe test configuration
        detector = TrafficDetector()

        # Pre-build packet mix: 70% normal, 15% port scan, 15% SYN flood
        packets_mix: List[ParsedPacket] = []
        now = time.time()
        for i in range(1000):
            if i % 10 < 7:
                p = self.gen.generate_normal_packets(count=1)[0]
                p.timestamp = now + (i * 0.01)
            elif i % 10 < 9:
                p = self.gen.generate_port_scan_packets(ports_count=1)[0]
                p.timestamp = now + (i * 0.01)
                p.dst_port = 1000 + (i % 50)
            else:
                p = self.gen.generate_syn_flood_packets(packet_count=1)[0]
                p.timestamp = now + (i * 0.01)
            packets_mix.append(p)

        # Warm-up
        for p in packets_mix[:20]:
            detector.analyze_packet(p)

        for count in levels:
            latencies: List[float] = []
            alerts_generated = 0
            start_wall = time.perf_counter()

            for i in range(count):
                pkt = packets_mix[i % len(packets_mix)]
                t0 = time.perf_counter()
                alerts = detector.analyze_packet(pkt)
                t1 = time.perf_counter()
                latencies.append(t1 - t0)
                if alerts:
                    alerts_generated += len(alerts)

            total_wall = time.perf_counter() - start_wall
            stats = calculate_statistics(latencies, total_wall)

            results.append(
                BenchmarkResult(
                    name="Rule Detector",
                    category="Detection Rules",
                    load_level=count,
                    statistics=stats,
                    details={"alerts_generated": alerts_generated},
                )
            )

        return results

    # =========================================================================
    # C. ML PIPELINE BENCHMARK
    # =========================================================================

    def benchmark_ml_pipeline(
        self, load_levels: Optional[List[int]] = None
    ) -> List[BenchmarkResult]:
        """Benchmark window feature extraction and Isolation Forest inference."""
        levels = load_levels or [50, 200, 500]
        results: List[BenchmarkResult] = []

        temp_dir = tempfile.mkdtemp(prefix="netsentinel_bench_ml_")

        try:
            # 1. Feature Extraction Micro-Benchmark
            sample_packet_window = self.gen.generate_normal_packets(count=25)
            # Warm-up
            extract_features_from_window(sample_packet_window, window_duration=5.0)

            ext_latencies: List[float] = []
            start_wall = time.perf_counter()
            for _ in range(levels[-1]):
                t0 = time.perf_counter()
                feat_vec, _ = extract_features_from_window(sample_packet_window, window_duration=5.0)
                t1 = time.perf_counter()
                ext_latencies.append(t1 - t0)
            total_wall = time.perf_counter() - start_wall
            ext_stats = calculate_statistics(ext_latencies, total_wall)

            results.append(
                BenchmarkResult(
                    name="ML Feature Extraction",
                    category="Machine Learning",
                    load_level=levels[-1],
                    statistics=ext_stats,
                    details={"window_packet_count": len(sample_packet_window), "feature_count": len(FEATURE_NAMES)},
                )
            )

            # 2. Isolation Forest Inference Micro-Benchmark (READY model)
            model = IsolationForestModel(n_estimators=100, contamination="auto", random_state=42)
            baseline = self.gen.generate_ml_baseline_dataset(window_count=30)
            model.train(baseline)
            assert model.status == ModelStatus.READY

            # Pre-sample feature vectors
            eval_vectors, _, _ = self.gen.generate_ml_evaluation_dataset(normal_count=250, anomaly_count=250)

            # Warm-up
            for v in eval_vectors[:10]:
                model.predict(v)

            for count in levels:
                inf_latencies: List[float] = []
                start_wall = time.perf_counter()

                for i in range(count):
                    vec = eval_vectors[i % len(eval_vectors)]
                    t0 = time.perf_counter()
                    model.predict(vec)
                    t1 = time.perf_counter()
                    inf_latencies.append(t1 - t0)

                total_wall = time.perf_counter() - start_wall
                inf_stats = calculate_statistics(inf_latencies, total_wall)

                results.append(
                    BenchmarkResult(
                        name="Isolation Forest Inference",
                        category="Machine Learning",
                        load_level=count,
                        statistics=inf_stats,
                        details={"model_status": "READY", "n_estimators": 100},
                    )
                )

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        return results

    # =========================================================================
    # D. COMPOSITE RISK ENGINE BENCHMARK
    # =========================================================================

    def benchmark_risk_engine(
        self, load_levels: Optional[List[int]] = None
    ) -> List[BenchmarkResult]:
        """Benchmark deterministic risk calculation across operational paths."""
        levels = load_levels or [100, 500, 1000]
        results: List[BenchmarkResult] = []

        risk_eng = RiskEngine()

        sample_event = SecurityEvent(
            event_id="ev-bench-risk",
            timestamp=time.time(),
            detection_type="PORT_SCAN",
            severity="MEDIUM",
            source_ip="192.168.1.180",
        )

        # Warm-up
        for _ in range(20):
            risk_eng.assess(source_ip="192.168.1.180", rule_alerts=[sample_event], ml_anomaly_score=0.45)

        for count in levels:
            latencies: List[float] = []
            start_wall = time.perf_counter()

            for i in range(count):
                # Cycle between rule-only, rule+ML, ML-only, and repeat activity
                mod = i % 4
                if mod == 0:
                    # Rule-only
                    t0 = time.perf_counter()
                    risk_eng.assess(source_ip="192.168.1.181", rule_alerts=[sample_event], ml_anomaly_score=0.0)
                    t1 = time.perf_counter()
                elif mod == 1:
                    # Rule + ML
                    t0 = time.perf_counter()
                    risk_eng.assess(source_ip="192.168.1.182", rule_alerts=[sample_event], ml_anomaly_score=0.65)
                    t1 = time.perf_counter()
                elif mod == 2:
                    # ML-only safety path
                    t0 = time.perf_counter()
                    risk_eng.assess(source_ip="192.168.1.183", rule_alerts=[], ml_anomaly_score=0.90)
                    t1 = time.perf_counter()
                else:
                    # Repeated source IP activity (exercising repeat boost tracking)
                    t0 = time.perf_counter()
                    risk_eng.assess(source_ip="192.168.1.180", rule_alerts=[sample_event], ml_anomaly_score=0.50)
                    t1 = time.perf_counter()

                latencies.append(t1 - t0)

            total_wall = time.perf_counter() - start_wall
            stats = calculate_statistics(latencies, total_wall)

            results.append(
                BenchmarkResult(
                    name="Composite Risk Engine",
                    category="Risk Engine",
                    load_level=count,
                    statistics=stats,
                    details={"rule_weight": 0.65, "ml_weight": 0.35},
                )
            )

        return results

    # =========================================================================
    # E. INCIDENT CORRELATION BENCHMARK
    # =========================================================================

    def benchmark_incident_manager(
        self, load_levels: Optional[List[int]] = None
    ) -> List[BenchmarkResult]:
        """Benchmark incident creation, evidence linking, and timeline construction."""
        levels = load_levels or [50, 200, 500]
        results: List[BenchmarkResult] = []

        temp_db_fd, temp_db_path = tempfile.mkstemp(prefix="netsentinel_bench_inc_", suffix=".db")
        os.close(temp_db_fd)

        app_cfg = {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{temp_db_path}",
            "NETSENTINEL_FIREWALL_ENABLED": "False",
            "NETSENTINEL_AUTO_BLOCK": "False",
        }
        app, _ = create_app(config_class=app_cfg, start_capture=False)

        try:
            with app.app_context():
                db.create_all()
                mgr = app.incident_manager
                now = time.time()

                sample_events = [
                    SecurityEvent(
                        event_id=f"ev-inc-{i}",
                        timestamp=now + i,
                        detection_type="PORT_SCAN" if i % 2 == 0 else "SSH_AUTH_FAILURE",
                        severity="MEDIUM" if i % 2 == 0 else "LOW",
                        source_ip=f"192.168.1.{100 + (i % 20)}",
                    )
                    for i in range(100)
                ]

                # Warm-up
                for ev in sample_events[:10]:
                    mgr.correlate_security_event(ev)

                for count in levels:
                    latencies: List[float] = []
                    start_wall = time.perf_counter()
                    last_inc_id = None

                    for i in range(count):
                        ev = sample_events[i % len(sample_events)]
                        t0 = time.perf_counter()
                        inc = mgr.correlate_security_event(ev)
                        t1 = time.perf_counter()
                        latencies.append(t1 - t0)
                        last_inc_id = inc.incident_id

                    # Timeline benchmark
                    if last_inc_id:
                        mgr.build_incident_timeline(last_inc_id)

                    total_wall = time.perf_counter() - start_wall
                    stats = calculate_statistics(latencies, total_wall)

                    results.append(
                        BenchmarkResult(
                            name="Incident Correlator",
                            category="Incident Management",
                            load_level=count,
                            statistics=stats,
                            details={"active_incidents": len(mgr._active_by_key)},
                        )
                    )

        finally:
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)

        return results

    # =========================================================================
    # F. DATABASE PERSISTENCE BENCHMARK
    # =========================================================================

    def benchmark_persistence(
        self, load_levels: Optional[List[int]] = None
    ) -> List[BenchmarkResult]:
        """Benchmark representative SQLite persistence operations."""
        levels = load_levels or [50, 200, 500]
        results: List[BenchmarkResult] = []

        temp_db_fd, temp_db_path = tempfile.mkstemp(prefix="netsentinel_bench_db_", suffix=".db")
        os.close(temp_db_fd)

        app_cfg = {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{temp_db_path}",
            "NETSENTINEL_FIREWALL_ENABLED": "False",
            "NETSENTINEL_AUTO_BLOCK": "False",
        }
        app, _ = create_app(config_class=app_cfg, start_capture=False)

        try:
            with app.app_context():
                db.create_all()

                for count in levels:
                    latencies: List[float] = []
                    start_wall = time.perf_counter()

                    for i in range(count):
                        ev = SecurityEvent(
                            event_id=f"ev-db-{uuid.uuid4().hex[:8]}",
                            timestamp=time.time(),
                            detection_type="PORT_SCAN",
                            severity="MEDIUM",
                            source_ip=f"192.168.1.{(i % 200) + 1}",
                        )
                        t0 = time.perf_counter()
                        save_security_event_record(ev)
                        t1 = time.perf_counter()
                        latencies.append(t1 - t0)

                    # Query latency test
                    t_q0 = time.perf_counter()
                    query_security_events(limit=50)
                    t_q1 = time.perf_counter()
                    latencies.append(t_q1 - t_q0)

                    total_wall = time.perf_counter() - start_wall
                    stats = calculate_statistics(latencies, total_wall)

                    results.append(
                        BenchmarkResult(
                            name="SQLite Persistence & Query",
                            category="Persistence",
                            load_level=count,
                            statistics=stats,
                            details={"db_type": "SQLite"},
                        )
                    )

        finally:
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)

        return results

    # =========================================================================
    # G. END-TO-END PIPELINE BENCHMARK
    # =========================================================================

    def benchmark_end_to_end_pipeline(
        self, load_levels: Optional[List[int]] = None
    ) -> List[BenchmarkResult]:
        """Benchmark the complete integrated flow: Packet -> Parser -> Detector -> ML -> Risk -> Incident -> DB."""
        levels = load_levels or [100, 500, 1000]
        results: List[BenchmarkResult] = []

        temp_db_fd, temp_db_path = tempfile.mkstemp(prefix="netsentinel_e2e_bench_", suffix=".db")
        os.close(temp_db_fd)

        app_cfg = {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{temp_db_path}",
            "NETSENTINEL_FIREWALL_ENABLED": "False",
            "NETSENTINEL_AUTO_BLOCK": "False",
            "ML_SETTINGS": {
                "enabled": True,
                "window_seconds": 1.0,
                "baseline_windows": 10,
                "n_estimators": 100,
                "contamination": "auto",
                "random_state": 42,
            },
        }
        app, _ = create_app(config_class=app_cfg, start_capture=False)

        # Pre-generate raw frame stream
        raw_frames = [
            generate_synthetic_raw_frame(
                src_ip=f"192.168.1.{(i % 20) + 100}",
                src_port=40000 + (i % 100),
                dst_port=80 if (i % 2 == 0) else 443,
            )
            for i in range(100)
        ]

        try:
            with app.app_context():
                db.create_all()

                # Train ML model to READY state
                baseline_data = self.gen.generate_ml_baseline_dataset(window_count=20)
                app.ml_detector.model.train(baseline_data)
                app.ml_detector.model.status = ModelStatus.READY

                for count in levels:
                    latencies: List[float] = []
                    start_wall = time.perf_counter()

                    for i in range(count):
                        frame = raw_frames[i % len(raw_frames)]
                        t0 = time.perf_counter()

                        # 1. Parse raw frame
                        parsed = parse_packet(frame)

                        # 2. Rule Detection
                        alerts = app.detector.analyze_packet(parsed)

                        # 3. ML Feature Window ingest
                        app.ml_detector.process_packet(parsed)

                        # 4. Risk Assessment
                        ml_score = app.ml_detector.latest_anomaly_score or 0.0
                        assessment = app.risk_engine.assess(
                            source_ip=parsed.src_ip,
                            destination_ip=parsed.dst_ip,
                            rule_alerts=alerts,
                            ml_anomaly_score=ml_score,
                        )

                        # 5. Incident Correlation & Database Persistence (if alerts occurred)
                        if alerts:
                            for alert in alerts:
                                save_security_event_record(alert)
                                app.incident_manager.correlate_security_event(alert, risk_assessment=assessment)

                        t1 = time.perf_counter()
                        latencies.append(t1 - t0)

                    total_wall = time.perf_counter() - start_wall
                    stats = calculate_statistics(latencies, total_wall)

                    results.append(
                        BenchmarkResult(
                            name="End-to-End Pipeline",
                            category="Integrated Pipeline",
                            load_level=count,
                            statistics=stats,
                            details={"subsystems_evaluated": ["Parser", "Detector", "ML", "RiskEngine", "IncidentManager", "SQLite"]},
                        )
                    )

        finally:
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)

        return results
