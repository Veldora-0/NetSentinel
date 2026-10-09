"""NetSentinel Feature Extractor Module.

Converts structured ParsedPacket streams into fixed-length numerical feature vectors
aggregated over discrete time windows for unsupervised machine learning anomaly detection.
"""

import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from parser import ParsedPacket

# Canonical feature ordering used across training and live inference
FEATURE_NAMES: List[str] = [
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "unique_destination_ports",
    "unique_source_ips",
    "unique_destination_ips",
]


def extract_features_from_window(
    packets: List[ParsedPacket], window_duration: float
) -> Tuple[List[float], Dict[str, float]]:
    """Extract a numerical feature vector from a list of packets observed in a time window.

    Guaranteed to be safe against division-by-zero for empty windows or quiet periods.

    Args:
        packets: List of ParsedPacket objects observed in the window.
        window_duration: Effective window duration in seconds (must be > 0).

    Returns:
        Tuple of (feature_list in FEATURE_NAMES order, feature_dict mapping names to floats).
    """
    duration = max(0.1, float(window_duration))
    total_packets = len(packets)

    if total_packets == 0:
        # Graceful empty window handling
        empty_dict = {name: 0.0 for name in FEATURE_NAMES}
        return [0.0] * len(FEATURE_NAMES), empty_dict

    total_bytes = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    syn_count = 0
    ack_count = 0
    rst_count = 0
    fin_count = 0

    unique_dst_ports: Set[int] = set()
    unique_src_ips: Set[str] = set()
    unique_dst_ips: Set[str] = set()

    for pkt in packets:
        total_bytes += pkt.raw_length

        if pkt.src_ip:
            unique_src_ips.add(pkt.src_ip)
        if pkt.dst_ip:
            unique_dst_ips.add(pkt.dst_ip)
        if pkt.dst_port is not None:
            unique_dst_ports.add(pkt.dst_port)

        proto = pkt.protocol_name
        if proto == "TCP":
            tcp_count += 1
            if pkt.tcp_flags:
                if pkt.tcp_flags.get("SYN"):
                    syn_count += 1
                if pkt.tcp_flags.get("ACK"):
                    ack_count += 1
                if pkt.tcp_flags.get("RST"):
                    rst_count += 1
                if pkt.tcp_flags.get("FIN"):
                    fin_count += 1
        elif proto == "UDP":
            udp_count += 1
        elif proto in ("ICMP", "ICMPv6"):
            icmp_count += 1

    feature_dict: Dict[str, float] = {
        "packets_per_second": round(total_packets / duration, 4),
        "bytes_per_second": round(total_bytes / duration, 4),
        "average_packet_size": round(total_bytes / total_packets, 4),
        "tcp_ratio": round(tcp_count / total_packets, 4),
        "udp_ratio": round(udp_count / total_packets, 4),
        "icmp_ratio": round(icmp_count / total_packets, 4),
        "syn_ratio": round(syn_count / total_packets, 4),
        "ack_ratio": round(ack_count / total_packets, 4),
        "rst_ratio": round(rst_count / total_packets, 4),
        "fin_ratio": round(fin_count / total_packets, 4),
        "unique_destination_ports": float(len(unique_dst_ports)),
        "unique_source_ips": float(len(unique_src_ips)),
        "unique_destination_ips": float(len(unique_dst_ips)),
    }

    feature_vector = [feature_dict[name] for name in FEATURE_NAMES]
    return feature_vector, feature_dict


class TrafficWindow:
    """Thread-safe packet window buffer that aggregates packets over discrete time slices."""

    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = float(window_seconds)
        self._lock = threading.Lock()
        self._packets: List[ParsedPacket] = []
        self._window_start = time.time()
        self.last_primary_source_ip: Optional[str] = None
        self.last_primary_destination_ip: Optional[str] = None

    def add_packet(self, packet: ParsedPacket) -> None:
        """Add a parsed packet to the current window buffer."""
        if not packet or packet.error:
            return
        with self._lock:
            self._packets.append(packet)

    @property
    def packet_count(self) -> int:
        """Return count of packets currently accumulated in the window."""
        with self._lock:
            return len(self._packets)

    def consume_window(
        self, custom_duration: Optional[float] = None
    ) -> Tuple[List[float], Dict[str, float], int]:
        """Atomically consume accumulated packets, reset buffer, and compute features.

        Args:
            custom_duration: Optional override for window duration (defaults to elapsed or configured).

        Returns:
            Tuple of (feature_vector, feature_dict, packet_count_in_window).
        """
        now = time.time()
        with self._lock:
            pkts = self._packets
            self._packets = []
            elapsed = now - self._window_start
            self._window_start = now

        top_src: Optional[str] = None
        top_dst: Optional[str] = None
        if pkts:
            src_counts: Dict[str, int] = {}
            dst_counts: Dict[str, int] = {}
            for p in pkts:
                if p.src_ip:
                    src_counts[p.src_ip] = src_counts.get(p.src_ip, 0) + 1
                if p.dst_ip:
                    dst_counts[p.dst_ip] = dst_counts.get(p.dst_ip, 0) + 1
            if src_counts:
                top_src = max(src_counts, key=src_counts.get)
            if dst_counts:
                top_dst = max(dst_counts, key=dst_counts.get)
        self.last_primary_source_ip = top_src
        self.last_primary_destination_ip = top_dst

        duration = custom_duration if custom_duration is not None else max(self.window_seconds, elapsed)
        vec, f_dict = extract_features_from_window(pkts, duration)
        return vec, f_dict, len(pkts)

    def reset(self) -> None:
        """Clear buffer and reset window start timestamp."""
        with self._lock:
            self._packets = []
            self._window_start = time.time()
