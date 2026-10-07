"""NetSentinel Synthetic Data Generator Module (Phase 15).

Provides deterministic, reproducible synthetic packet byte streams,
ParsedPacket structures, attack sequences, and labelled feature vectors
for performance profiling and ML anomaly evaluation.
"""

import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from parser import ParsedPacket, ParsedARP
from ml.feature_extractor import FEATURE_NAMES


def build_raw_ethernet_frame(
    dst_mac: bytes = b"\xaa\xbb\xcc\xdd\xee\xff",
    src_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    ethertype: int = 0x0800,
    payload: bytes = b"",
) -> bytes:
    """Pack an Ethernet header with payload."""
    return struct.pack("!6s6sH", dst_mac, src_mac, ethertype) + payload


def build_raw_ipv4_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.10",
    protocol: int = 6,  # TCP
    payload: bytes = b"",
    ttl: int = 64,
) -> bytes:
    """Pack an IPv4 header with payload."""
    version_ihl = (4 << 4) | 5
    total_len = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_len,
        54321,
        0,
        ttl,
        protocol,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return hdr + payload


def build_raw_tcp_segment(
    src_port: int = 50000,
    dst_port: int = 80,
    seq: int = 1000,
    ack: int = 0,
    flags: int = 0x02,  # SYN
    payload: bytes = b"",
) -> bytes:
    """Pack a standard 20-byte TCP header with payload."""
    offset_reserved = (5 << 4)
    hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flags,
        8192,
        0,
        0,
    )
    return hdr + payload


def generate_synthetic_raw_frame(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.10",
    src_port: int = 50000,
    dst_port: int = 80,
    flags: int = 0x02,
    payload_len: int = 32,
) -> bytes:
    """Generate a complete synthetic raw Ethernet + IPv4 + TCP packet frame."""
    payload = b"X" * payload_len
    tcp_seg = build_raw_tcp_segment(src_port=src_port, dst_port=dst_port, flags=flags, payload=payload)
    ip_pkt = build_raw_ipv4_packet(src_ip=src_ip, dst_ip=dst_ip, protocol=6, payload=tcp_seg)
    return build_raw_ethernet_frame(payload=ip_pkt)


def generate_synthetic_parsed_packet(
    timestamp: Optional[float] = None,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.10",
    protocol: int = 6,
    proto_name: str = "TCP",
    src_port: int = 50000,
    dst_port: int = 80,
    tcp_flags: Optional[Dict[str, bool]] = None,
    raw_tcp_flags: Optional[int] = None,
    raw_length: int = 64,
) -> ParsedPacket:
    """Create a structured ParsedPacket for detector benchmarking."""
    ts = timestamp if timestamp is not None else time.time()
    flags = tcp_flags or {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
    return ParsedPacket(
        timestamp=ts,
        raw_length=raw_length,
        src_mac="00:11:22:33:44:55",
        dst_mac="aa:bb:cc:dd:ee:ff",
        ethertype=0x0800,
        ethertype_name="IPv4",
        ip_version=4,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        protocol_name=proto_name,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        raw_tcp_flags=raw_tcp_flags if raw_tcp_flags is not None else 0x02,
    )


class SyntheticDataGenerator:
    """Deterministic generator for synthetic attack sequences and ML evaluation datasets."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = np.random.default_rng(seed)

    def generate_normal_packets(
        self, count: int = 100, src_ip: str = "10.0.0.50", dst_ip: str = "10.0.0.1"
    ) -> List[ParsedPacket]:
        """Generate benign TCP ACK / application stream packets."""
        now = time.time()
        packets = []
        for i in range(count):
            p = generate_synthetic_parsed_packet(
                timestamp=now + (i * 0.01),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=40000 + (i % 50),
                dst_port=443 if (i % 2 == 0) else 80,
                tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False},
                raw_tcp_flags=0x10,
                raw_length=64 + (i % 128),
            )
            packets.append(p)
        return packets

    def generate_port_scan_packets(
        self, ports_count: int = 20, src_ip: str = "192.168.1.120", dst_ip: str = "192.168.1.10"
    ) -> List[ParsedPacket]:
        """Generate a sequential TCP SYN port scan probe."""
        now = time.time()
        packets = []
        for port in range(1, ports_count + 1):
            p = generate_synthetic_parsed_packet(
                timestamp=now + (port * 0.05),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=55000,
                dst_port=port,
                tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
                raw_tcp_flags=0x02,
                raw_length=60,
            )
            packets.append(p)
        return packets

    def generate_syn_flood_packets(
        self, packet_count: int = 60, src_ip: str = "192.168.1.130", dst_ip: str = "192.168.1.10", dst_port: int = 80
    ) -> List[ParsedPacket]:
        """Generate a high-rate single-port SYN flood."""
        now = time.time()
        packets = []
        for i in range(packet_count):
            p = generate_synthetic_parsed_packet(
                timestamp=now + (i * 0.005),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=30000 + i,
                dst_port=dst_port,
                tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
                raw_tcp_flags=0x02,
                raw_length=60,
            )
            packets.append(p)
        return packets

    def generate_stealth_null_packet(
        self, src_ip: str = "192.168.1.140", dst_ip: str = "192.168.1.10", dst_port: int = 80
    ) -> ParsedPacket:
        """Generate a single stealth NULL scan packet (no flags)."""
        return generate_synthetic_parsed_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            tcp_flags={"SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
            raw_tcp_flags=0,
            raw_length=60,
        )

    def generate_stealth_xmas_packet(
        self, src_ip: str = "192.168.1.141", dst_ip: str = "192.168.1.10", dst_port: int = 443
    ) -> ParsedPacket:
        """Generate a single stealth XMAS scan packet (FIN, PSH, URG)."""
        return generate_synthetic_parsed_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            tcp_flags={"SYN": False, "ACK": False, "FIN": True, "RST": False, "PSH": True, "URG": True},
            raw_tcp_flags=0x29,
            raw_length=60,
        )

    # =========================================================================
    # ML FEATURE DATASET GENERATION
    # =========================================================================

    def _sample_normal_window(self, rng: np.random.Generator) -> List[float]:
        """Synthesize a single 13-feature vector representing normal traffic baseline."""
        pps = float(np.clip(rng.normal(20.0, 3.0), 10.0, 35.0))
        bps = float(np.clip(rng.normal(10000.0, 1500.0), 4000.0, 20000.0))
        avg_pkt = float(np.clip(bps / max(1.0, pps), 300.0, 800.0))
        tcp_ratio = float(np.clip(rng.normal(0.90, 0.03), 0.80, 0.98))
        udp_ratio = float(np.clip(1.0 - tcp_ratio, 0.02, 0.20))
        icmp_ratio = 0.0
        syn_ratio = float(np.clip(rng.normal(0.05, 0.015), 0.01, 0.10))
        ack_ratio = float(np.clip(rng.normal(0.90, 0.03), 0.80, 0.98))
        rst_ratio = 0.0
        fin_ratio = 0.0
        uniq_ports = float(np.clip(rng.normal(3.5, 0.8), 2.0, 6.0))
        uniq_src = float(np.clip(rng.normal(5.0, 1.0), 3.0, 9.0))
        uniq_dst = float(np.clip(rng.normal(2.0, 0.5), 1.0, 4.0))

        return [
            round(pps, 4),
            round(bps, 4),
            round(avg_pkt, 4),
            round(tcp_ratio, 4),
            round(udp_ratio, 4),
            round(icmp_ratio, 4),
            round(syn_ratio, 4),
            round(ack_ratio, 4),
            round(rst_ratio, 4),
            round(fin_ratio, 4),
            round(uniq_ports, 4),
            round(uniq_src, 4),
            round(uniq_dst, 4),
        ]

    def _sample_anomalous_window(self, rng: np.random.Generator, archetype: int) -> Tuple[List[float], str]:
        """Synthesize a single 13-feature vector representing an anomalous attack pattern."""
        if archetype == 0:
            # SYN Flood Anomaly: high pps, syn_ratio near 1.0, zero acks
            label_desc = "SYN Flood Outlier"
            pps = float(rng.uniform(3000.0, 8000.0))
            bps = float(pps * rng.uniform(60.0, 120.0))
            avg_pkt = 70.0
            tcp_ratio = 1.0
            udp_ratio = 0.0
            icmp_ratio = 0.0
            syn_ratio = float(rng.uniform(0.92, 1.0))
            ack_ratio = 0.0
            rst_ratio = 0.0
            fin_ratio = 0.0
            uniq_ports = 1.0
            uniq_src = float(rng.uniform(1.0, 10.0))
            uniq_dst = 1.0

        elif archetype == 1:
            # Port Scan Reconnaissance: high port cardinality, elevated SYN ratio
            label_desc = "Port Scan Outlier"
            pps = float(rng.uniform(400.0, 1200.0))
            bps = float(pps * 64.0)
            avg_pkt = 64.0
            tcp_ratio = 1.0
            udp_ratio = 0.0
            icmp_ratio = 0.0
            syn_ratio = float(rng.uniform(0.85, 0.98))
            ack_ratio = float(rng.uniform(0.0, 0.10))
            rst_ratio = 0.0
            fin_ratio = 0.0
            uniq_ports = float(rng.uniform(100.0, 500.0))
            uniq_src = 1.0
            uniq_dst = 1.0

        elif archetype == 2:
            # High-Volume UDP Flood: pure UDP ratio, elevated pps and bps
            label_desc = "UDP Flood Outlier"
            pps = float(rng.uniform(2500.0, 6000.0))
            bps = float(pps * rng.uniform(800.0, 1400.0))
            avg_pkt = float(bps / pps)
            tcp_ratio = 0.0
            udp_ratio = 1.0
            icmp_ratio = 0.0
            syn_ratio = 0.0
            ack_ratio = 0.0
            rst_ratio = 0.0
            fin_ratio = 0.0
            uniq_ports = float(rng.uniform(20.0, 100.0))
            uniq_src = float(rng.uniform(5.0, 30.0))
            uniq_dst = 1.0

        elif archetype == 3:
            # Stealth Flag Anomaly: abnormal FIN or RST ratio without standard handshake
            label_desc = "Stealth Scan Flag Anomaly"
            pps = float(rng.uniform(15.0, 50.0))
            bps = float(pps * 60.0)
            avg_pkt = 60.0
            tcp_ratio = 1.0
            udp_ratio = 0.0
            icmp_ratio = 0.0
            syn_ratio = 0.0
            ack_ratio = 0.0
            rst_ratio = float(rng.uniform(0.40, 0.85))
            fin_ratio = float(rng.uniform(0.40, 0.85))
            uniq_ports = float(rng.uniform(10.0, 40.0))
            uniq_src = 1.0
            uniq_dst = 1.0

        else:
            # Distributed Reconnaissance / Host Sweep: high destination cardinality
            label_desc = "Host Sweep Cardinality Anomaly"
            pps = float(rng.uniform(200.0, 800.0))
            bps = float(pps * 80.0)
            avg_pkt = 80.0
            tcp_ratio = 0.5
            udp_ratio = 0.5
            icmp_ratio = 0.0
            syn_ratio = 0.5
            ack_ratio = 0.0
            rst_ratio = 0.0
            fin_ratio = 0.0
            uniq_ports = 5.0
            uniq_src = 1.0
            uniq_dst = float(rng.uniform(50.0, 150.0))

        vec = [
            round(pps, 4),
            round(bps, 4),
            round(avg_pkt, 4),
            round(tcp_ratio, 4),
            round(udp_ratio, 4),
            round(icmp_ratio, 4),
            round(syn_ratio, 4),
            round(ack_ratio, 4),
            round(rst_ratio, 4),
            round(fin_ratio, 4),
            round(uniq_ports, 4),
            round(uniq_src, 4),
            round(uniq_dst, 4),
        ]
        return vec, label_desc

    def generate_ml_baseline_dataset(
        self, window_count: int = 50, seed: int = 42
    ) -> List[List[float]]:
        """Generate baseline normal training dataset to fit Isolation Forest."""
        rng = np.random.default_rng(seed)
        return [self._sample_normal_window(rng) for _ in range(window_count)]

    def generate_ml_evaluation_dataset(
        self, normal_count: int = 100, anomaly_count: int = 100, seed: int = 1337
    ) -> Tuple[List[List[float]], List[int], List[Dict[str, Any]]]:
        """Generate separate held-out evaluation dataset with known ground-truth labels.

        Args:
            normal_count: Number of normal test windows.
            anomaly_count: Number of anomalous test windows.
            seed: Deterministic seed (independent of training seed).

        Returns:
            Tuple of (X_eval, y_true, sample_metadata).
            - X_eval: List of 13-feature vectors.
            - y_true: Ground truth binary labels (0 = normal, 1 = anomalous).
            - sample_metadata: List of dicts describing each sample.
        """
        rng = np.random.default_rng(seed)

        X_eval: List[List[float]] = []
        y_true: List[int] = []
        meta: List[Dict[str, Any]] = []

        # 1. Normal held-out samples (Label = 0)
        for i in range(normal_count):
            vec = self._sample_normal_window(rng)
            X_eval.append(vec)
            y_true.append(0)
            meta.append({
                "sample_index": len(X_eval) - 1,
                "ground_truth": 0,
                "label_name": "Normal Traffic",
                "category": "normal",
            })

        # 2. Anomalous samples across 5 distinct archetypes (Label = 1)
        for i in range(anomaly_count):
            archetype = i % 5
            vec, desc = self._sample_anomalous_window(rng, archetype)
            X_eval.append(vec)
            y_true.append(1)
            meta.append({
                "sample_index": len(X_eval) - 1,
                "ground_truth": 1,
                "label_name": desc,
                "category": "anomaly",
            })

        return X_eval, y_true, meta
