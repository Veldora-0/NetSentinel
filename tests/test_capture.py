"""Unit tests for NetSentinel Packet Capture and Traffic Metrics."""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from capture import TrafficMetrics, PacketCapture
from parser import ParsedPacket
from app import create_app


def test_traffic_metrics_counters():
    """Verify that TrafficMetrics accurately updates protocol counts and bytes."""
    metrics = TrafficMetrics(window_seconds=2.0)

    # 1. TCP Packet
    tcp_pkt = ParsedPacket(
        timestamp=time.time(),
        raw_length=100,
        src_mac="00:00:00:00:00:01",
        dst_mac="00:00:00:00:00:02",
        ethertype=0x0800,
        ethertype_name="IPv4",
        protocol=6,
        protocol_name="TCP",
    )
    metrics.update(tcp_pkt)

    # 2. UDP Packet
    udp_pkt = ParsedPacket(
        timestamp=time.time(),
        raw_length=60,
        src_mac="00:00:00:00:00:01",
        dst_mac="00:00:00:00:00:02",
        ethertype=0x0800,
        ethertype_name="IPv4",
        protocol=17,
        protocol_name="UDP",
    )
    metrics.update(udp_pkt)

    # 3. ICMP Packet
    icmp_pkt = ParsedPacket(
        timestamp=time.time(),
        raw_length=80,
        src_mac="00:00:00:00:00:01",
        dst_mac="00:00:00:00:00:02",
        ethertype=0x0800,
        ethertype_name="IPv4",
        protocol=1,
        protocol_name="ICMP",
    )
    metrics.update(icmp_pkt)

    # 4. Other (e.g. ARP) Packet
    arp_pkt = ParsedPacket(
        timestamp=time.time(),
        raw_length=42,
        src_mac="00:00:00:00:00:01",
        dst_mac="00:00:00:00:00:02",
        ethertype=0x0806,
        ethertype_name="ARP",
    )
    metrics.update(arp_pkt)

    snapshot = metrics.get_snapshot(interface="test0", status="running")
    assert snapshot["total_packets"] == 4
    assert snapshot["total_bytes"] == 282
    assert snapshot["tcp_packets"] == 1
    assert snapshot["udp_packets"] == 1
    assert snapshot["icmp_packets"] == 1
    assert snapshot["other_packets"] == 1
    assert snapshot["interface"] == "test0"
    assert snapshot["status"] == "running"


def test_packet_capture_lifecycle_unprivileged():
    """Verify PacketCapture handles unprivileged socket open safely without crashing."""
    capture = PacketCapture(interface="lo")
    assert capture.status == "stopped"

    # In unprivileged test environment, start() returns False and sets status safely
    capture.start()
    assert capture.status in ("running", "permission_denied")

    metrics = capture.get_metrics()
    assert "total_packets" in metrics
    assert "packets_per_sec" in metrics

    capture.stop()
    assert capture.status == "stopped"


def test_api_metrics_endpoint():
    """Verify GET /api/metrics endpoint returns status 200 and metrics payload."""
    app, _ = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        resp = client.get("/api/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_packets" in data
        assert "packets_per_sec" in data
        assert "bytes_per_sec" in data
        assert "tcp_packets" in data
        assert "udp_packets" in data
        assert "icmp_packets" in data
        assert "other_packets" in data
