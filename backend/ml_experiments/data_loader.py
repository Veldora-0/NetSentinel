"""NetSentinel ML Experiments Data Loader.

Generates reproducible synthetic normal and attack traffic feature sets for offline
hyperparameter search, feature sensitivity analysis, and threshold calibration.
Maintains strict independence from external evaluation sets (zero data leakage).
"""

from dataclasses import dataclass
import random
from typing import Dict, List, Optional, Tuple
import numpy as np

from ml.feature_extractor import FEATURE_NAMES


@dataclass
class ValidationDataset:
    """Encapsulates training baselines and labeled validation sets."""
    X_train_normal: np.ndarray          # Baseline normal windows for training
    X_val: np.ndarray                   # Validation feature matrix
    y_val: np.ndarray                   # Ground truth binary labels (0 = normal, 1 = attack)
    val_labels: List[str]               # Human-readable labels (e.g., 'NormalBrowsing', 'PortScan')
    feature_names: List[str]            # Feature ordering


class SyntheticTrafficGenerator:
    """Generates synthetic network traffic window feature vectors for ML optimization."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = np.random.RandomState(seed)

    def generate_normal_window(self, mode: str = "web", schema_version: str = "v1") -> List[float]:
        """Generate a realistic normal traffic feature vector.

        Modes:
        - 'web': Standard HTTP/HTTPS browsing, moderate packet rate, balanced TCP flags.
        - 'dns': Lightweight UDP querying, small packet sizes, low byte rate.
        - 'stream': High throughput video/media streaming, large packet sizes.
        - 'ssh': Interactive terminal session, low steady packet count, small packets.
        - 'idle': Low background traffic (ARP, broadcast, keepalives).
        """
        r = self.rng
        if mode == "web":
            pps = float(r.uniform(10.0, 60.0))
            avg_size = float(r.uniform(400.0, 950.0))
            bps = pps * avg_size
            tcp_r = float(r.uniform(0.85, 0.98))
            udp_r = float(r.uniform(0.01, 1.0 - tcp_r))
            icmp_r = max(0.0, 1.0 - tcp_r - udp_r)
            syn_r = float(r.uniform(0.02, 0.08))
            ack_r = float(r.uniform(0.70, 0.92))
            rst_r = float(r.uniform(0.00, 0.02))
            fin_r = float(r.uniform(0.01, 0.05))
            dst_ports = float(r.randint(1, 12))
            src_ips = float(r.randint(1, 4))
            dst_ips = float(r.randint(1, 8))
        elif mode == "stream":
            pps = float(r.uniform(80.0, 250.0))
            avg_size = float(r.uniform(1100.0, 1480.0))
            bps = pps * avg_size
            tcp_r = float(r.uniform(0.60, 0.99))
            udp_r = max(0.0, 1.0 - tcp_r)
            icmp_r = 0.0
            syn_r = float(r.uniform(0.005, 0.02))
            ack_r = float(r.uniform(0.85, 0.99))
            rst_r = float(r.uniform(0.00, 0.005))
            fin_r = float(r.uniform(0.001, 0.01))
            dst_ports = float(r.randint(1, 4))
            src_ips = float(r.randint(1, 2))
            dst_ips = float(r.randint(1, 3))
        elif mode == "dns":
            pps = float(r.uniform(2.0, 15.0))
            avg_size = float(r.uniform(80.0, 160.0))
            bps = pps * avg_size
            tcp_r = float(r.uniform(0.0, 0.05))
            udp_r = float(r.uniform(0.90, 1.0 - tcp_r))
            icmp_r = max(0.0, 1.0 - tcp_r - udp_r)
            syn_r = 0.0
            ack_r = float(r.uniform(0.0, 0.05))
            rst_r = 0.0
            fin_r = 0.0
            dst_ports = float(r.randint(1, 3))
            src_ips = float(r.randint(1, 2))
            dst_ips = float(r.randint(1, 3))
        elif mode == "ssh":
            pps = float(r.uniform(2.0, 10.0))
            avg_size = float(r.uniform(90.0, 220.0))
            bps = pps * avg_size
            tcp_r = 1.0
            udp_r = 0.0
            icmp_r = 0.0
            syn_r = 0.0
            ack_r = float(r.uniform(0.90, 1.0))
            rst_r = 0.0
            fin_r = 0.0
            dst_ports = 1.0
            src_ips = 1.0
            dst_ips = 1.0
        else:  # idle
            pps = float(r.uniform(0.2, 3.0))
            avg_size = float(r.uniform(60.0, 200.0))
            bps = pps * avg_size
            tcp_r = float(r.uniform(0.2, 0.5))
            udp_r = float(r.uniform(0.2, 0.5))
            icmp_r = max(0.0, 1.0 - tcp_r - udp_r)
            syn_r = float(r.uniform(0.0, 0.05))
            ack_r = float(r.uniform(0.2, 0.6))
            rst_r = 0.0
            fin_r = 0.0
            dst_ports = float(r.randint(1, 3))
            src_ips = float(r.randint(1, 2))
            dst_ips = float(r.randint(1, 2))

        v1 = [
            round(pps, 4),
            round(bps, 4),
            round(avg_size, 4),
            round(tcp_r, 4),
            round(udp_r, 4),
            round(icmp_r, 4),
            round(syn_r, 4),
            round(ack_r, 4),
            round(rst_r, 4),
            round(fin_r, 4),
            dst_ports,
            src_ips,
            dst_ips,
        ]

        if schema_version == "v2":
            # Extended behavioral features
            syn_to_ack = round(syn_r / (ack_r + 1e-4), 4)
            rst_to_ack = round(rst_r / (ack_r + 1e-4), 4)
            time_variance = round(float(r.uniform(0.01, 0.15)), 4)
            payload_ratio = round(min(1.0, avg_size / 1500.0), 4)
            return v1 + [syn_to_ack, rst_to_ack, time_variance, payload_ratio]

        return v1

    def generate_attack_window(self, attack_type: str = "syn_flood", schema_version: str = "v1") -> List[float]:
        """Generate a realistic attack traffic feature vector.

        Attack types:
        - 'syn_flood': Massive SYN packet rate, near-zero ACKs, many destination/source variations.
        - 'udp_flood': Overwhelming UDP volume, small to medium packets, high bps.
        - 'portscan': High unique destination ports, elevated SYN ratio, low byte per packet.
        - 'slowloris': Low packets/sec, low bytes, but high TCP ratio, open SYN keepalives, low payload.
        - 'c2_beacon': Highly regular inter-arrival, fixed packet size, periodic bursts.
        """
        r = self.rng
        if attack_type == "syn_flood":
            pps = float(r.uniform(500.0, 2500.0))
            avg_size = float(r.uniform(54.0, 74.0))
            bps = pps * avg_size
            tcp_r = 1.0
            udp_r = 0.0
            icmp_r = 0.0
            syn_r = float(r.uniform(0.92, 1.0))
            ack_r = float(r.uniform(0.0, 0.05))
            rst_r = float(r.uniform(0.0, 0.02))
            fin_r = 0.0
            dst_ports = float(r.randint(1, 10))
            src_ips = float(r.randint(50, 500))
            dst_ips = float(r.randint(1, 3))
        elif attack_type == "udp_flood":
            pps = float(r.uniform(800.0, 3000.0))
            avg_size = float(r.uniform(300.0, 1200.0))
            bps = pps * avg_size
            tcp_r = 0.0
            udp_r = 1.0
            icmp_r = 0.0
            syn_r = 0.0
            ack_r = 0.0
            rst_r = 0.0
            fin_r = 0.0
            dst_ports = float(r.randint(1, 20))
            src_ips = float(r.randint(20, 200))
            dst_ips = float(r.randint(1, 2))
        elif attack_type == "portscan":
            pps = float(r.uniform(100.0, 800.0))
            avg_size = float(r.uniform(54.0, 68.0))
            bps = pps * avg_size
            tcp_r = float(r.uniform(0.90, 1.0))
            udp_r = max(0.0, 1.0 - tcp_r)
            icmp_r = 0.0
            syn_r = float(r.uniform(0.80, 0.98))
            ack_r = float(r.uniform(0.0, 0.08))
            rst_r = float(r.uniform(0.02, 0.15))
            fin_r = 0.0
            dst_ports = float(r.randint(50, 600))
            src_ips = 1.0
            dst_ips = float(r.randint(1, 5))
        elif attack_type == "slowloris":
            pps = float(r.uniform(1.0, 8.0))
            avg_size = float(r.uniform(50.0, 110.0))
            bps = pps * avg_size
            tcp_r = 1.0
            udp_r = 0.0
            icmp_r = 0.0
            syn_r = float(r.uniform(0.15, 0.40))
            ack_r = float(r.uniform(0.60, 0.85))
            rst_r = float(r.uniform(0.0, 0.05))
            fin_r = 0.0
            dst_ports = 1.0
            src_ips = float(r.randint(1, 4))
            dst_ips = 1.0
        else:  # c2_beacon
            pps = float(r.uniform(0.5, 4.0))
            avg_size = float(r.uniform(250.0, 350.0))
            bps = pps * avg_size
            tcp_r = 0.9
            udp_r = 0.1
            icmp_r = 0.0
            syn_r = float(r.uniform(0.05, 0.15))
            ack_r = float(r.uniform(0.80, 0.95))
            rst_r = 0.0
            fin_r = float(r.uniform(0.05, 0.10))
            dst_ports = 1.0
            src_ips = 1.0
            dst_ips = 1.0

        v1 = [
            round(pps, 4),
            round(bps, 4),
            round(avg_size, 4),
            round(tcp_r, 4),
            round(udp_r, 4),
            round(icmp_r, 4),
            round(syn_r, 4),
            round(ack_r, 4),
            round(rst_r, 4),
            round(fin_r, 4),
            dst_ports,
            src_ips,
            dst_ips,
        ]

        if schema_version == "v2":
            syn_to_ack = round(syn_r / (ack_r + 1e-4), 4)
            rst_to_ack = round(rst_r / (ack_r + 1e-4), 4)
            time_variance = round(float(r.uniform(0.0001, 0.005)) if attack_type == "c2_beacon" else float(r.uniform(0.20, 0.80)), 4)
            payload_ratio = round(min(1.0, avg_size / 1500.0), 4)
            return v1 + [syn_to_ack, rst_to_ack, time_variance, payload_ratio]

        return v1

    def build_benchmark_dataset(
        self,
        train_samples: int = 500,
        val_normal_samples: int = 250,
        val_attack_samples: int = 250,
        schema_version: str = "v1",
        feature_names: Optional[List[str]] = None,
    ) -> ValidationDataset:
        """Create a complete partitioned benchmark dataset for model training and evaluation."""
        normal_modes = ["web", "stream", "dns", "ssh", "idle"]
        attack_types = ["syn_flood", "udp_flood", "portscan", "slowloris", "c2_beacon"]

        # 1. Training Baseline Normal Traffic
        X_train_list = []
        for i in range(train_samples):
            mode = normal_modes[i % len(normal_modes)]
            X_train_list.append(self.generate_normal_window(mode=mode, schema_version=schema_version))

        # 2. Validation Normal Traffic
        X_val_list = []
        y_val_list = []
        val_labels = []

        for i in range(val_normal_samples):
            mode = normal_modes[i % len(normal_modes)]
            X_val_list.append(self.generate_normal_window(mode=mode, schema_version=schema_version))
            y_val_list.append(0)
            val_labels.append(f"Normal_{mode.capitalize()}")

        # 3. Validation Attack Traffic
        for i in range(val_attack_samples):
            atype = attack_types[i % len(attack_types)]
            X_val_list.append(self.generate_attack_window(attack_type=atype, schema_version=schema_version))
            y_val_list.append(1)
            val_labels.append(f"Attack_{atype.capitalize()}")

        names = feature_names or FEATURE_NAMES
        return ValidationDataset(
            X_train_normal=np.asarray(X_train_list, dtype=np.float64),
            X_val=np.asarray(X_val_list, dtype=np.float64),
            y_val=np.asarray(y_val_list, dtype=np.int32),
            val_labels=val_labels,
            feature_names=names,
        )
