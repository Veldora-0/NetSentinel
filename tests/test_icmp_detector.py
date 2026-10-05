"""Tests for ICMP Sweep Detection in TrafficDetector (detector.py)."""

import time
import pytest
from detector import TrafficDetector, SecurityEvent
from parser import ParsedPacket


def make_icmp_packet(
    src_ip: str,
    dst_ip: str,
    icmp_type: int = 8,  # Echo Request
    icmp_code: int = 0,
    timestamp: float = None,
) -> ParsedPacket:
    """Helper to construct synthetic ParsedPacket for ICMP."""
    return ParsedPacket(
        timestamp=timestamp or time.time(),
        raw_length=60,
        src_mac="00:11:22:33:44:55",
        dst_mac="00:66:77:88:99:aa",
        ethertype=0x0800,
        ethertype_name="IPv4",
        protocol=1,
        protocol_name="ICMP",
        src_ip=src_ip,
        dst_ip=dst_ip,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
    )


def test_icmp_sweep_below_threshold():
    """Verify ICMP echo requests below threshold do not trigger an alert."""
    detector = TrafficDetector({
        "icmp_sweep_window_sec": 10.0,
        "icmp_sweep_threshold": 5,
    })

    src_ip = "192.168.1.100"
    for i in range(4):
        events = detector.analyze_packet(
            make_icmp_packet(src_ip, f"192.168.1.{i+1}", timestamp=100.0 + i)
        )
        assert len(events) == 0


def test_icmp_sweep_threshold_exceeded():
    """Verify reaching unique destination threshold generates an ICMP_SWEEP alert."""
    detector = TrafficDetector({
        "icmp_sweep_window_sec": 10.0,
        "icmp_sweep_threshold": 5,
        "icmp_sweep_cooldown_sec": 60.0,
    })

    src_ip = "192.168.1.100"
    events = []
    for i in range(5):
        evs = detector.analyze_packet(
            make_icmp_packet(src_ip, f"192.168.1.{i+10}", timestamp=100.0 + i)
        )
        events.extend(evs)

    assert len(events) == 1
    evt = events[0]
    assert evt.detection_type == "ICMP_SWEEP"
    assert evt.severity == "MEDIUM"
    assert evt.source_ip == src_ip
    assert evt.evidence["unique_hosts_count"] == 5
    assert evt.evidence["threshold"] == 5
    assert len(evt.evidence["sample_destinations"]) == 5


def test_icmp_sweep_duplicate_targets_not_counted():
    """Verify repeated echo requests to the same target IP do not inflate destination count."""
    detector = TrafficDetector({
        "icmp_sweep_window_sec": 10.0,
        "icmp_sweep_threshold": 5,
    })

    src_ip = "10.0.0.99"
    # Send 10 packets, but only to 2 distinct hosts
    events = []
    for i in range(10):
        target = "10.0.0.1" if (i % 2 == 0) else "10.0.0.2"
        evs = detector.analyze_packet(
            make_icmp_packet(src_ip, target, timestamp=100.0 + (i * 0.1))
        )
        events.extend(evs)

    assert len(events) == 0


def test_icmp_sweep_time_window_expiration():
    """Verify probes outside sliding window expire and do not trigger alert."""
    detector = TrafficDetector({
        "icmp_sweep_window_sec": 5.0,
        "icmp_sweep_threshold": 4,
    })

    src_ip = "192.168.1.55"
    # 3 probes at t=100.0
    for i in range(3):
        detector.analyze_packet(
            make_icmp_packet(src_ip, f"192.168.1.{i+1}", timestamp=100.0)
        )

    # 4th probe at t=106.0 (6 seconds later > 5s window) -> earlier probes expired
    events = detector.analyze_packet(
        make_icmp_packet(src_ip, "192.168.1.4", timestamp=106.0)
    )
    assert len(events) == 0


def test_icmp_sweep_cooldown_suppression():
    """Verify alert cooldown suppresses duplicate sweep alerts for same source IP."""
    detector = TrafficDetector({
        "icmp_sweep_window_sec": 10.0,
        "icmp_sweep_threshold": 3,
        "icmp_sweep_cooldown_sec": 30.0,
    })

    src_ip = "192.168.1.77"
    # Sweep 1: 3 hosts -> alert
    ev1 = []
    for i in range(3):
        ev1.extend(detector.analyze_packet(
            make_icmp_packet(src_ip, f"192.168.1.{i+1}", timestamp=100.0 + i)
        ))
    assert len(ev1) == 1

    # Sweep 2: additional hosts at t=110 (10s < 30s cooldown) -> suppressed
    ev2 = []
    for i in range(3):
        ev2.extend(detector.analyze_packet(
            make_icmp_packet(src_ip, f"192.168.1.{i+10}", timestamp=110.0 + i)
        ))
    assert len(ev2) == 0

    # Sweep 3: additional hosts at t=140 (40s > 30s cooldown) -> alerted
    ev3 = []
    for i in range(3):
        ev3.extend(detector.analyze_packet(
            make_icmp_packet(src_ip, f"192.168.1.{i+20}", timestamp=140.0 + i)
        ))
    assert len(ev3) == 1
    assert ev3[0].detection_type == "ICMP_SWEEP"


def test_icmp_sweep_filtered_edge_cases():
    """Verify broadcast, multicast, loopback, and unspecified destinations are filtered."""
    detector = TrafficDetector({
        "icmp_sweep_window_sec": 10.0,
        "icmp_sweep_threshold": 3,
    })

    src_ip = "192.168.1.88"
    ignored_targets = [
        "255.255.255.255",  # Broadcast
        "127.0.0.1",        # Loopback
        "224.0.0.1",        # Multicast
        "0.0.0.0",          # Unspecified
        "169.254.1.1",      # Link-local
    ]

    events = []
    for target in ignored_targets:
        evs = detector.analyze_packet(make_icmp_packet(src_ip, target, timestamp=100.0))
        events.extend(evs)

    assert len(events) == 0
    # No targets should have been tracked
    assert len(detector._icmp_sweep_state.get(src_ip, [])) == 0


def test_icmp_non_echo_request_ignored():
    """Verify non-echo-request ICMP messages (type 0 reply, type 3 unreachable) are ignored."""
    detector = TrafficDetector({
        "icmp_sweep_threshold": 3,
    })

    src_ip = "192.168.1.99"
    # Echo Reply (type 0)
    evs1 = detector.analyze_packet(make_icmp_packet(src_ip, "192.168.1.1", icmp_type=0))
    assert len(evs1) == 0

    # Destination Unreachable (type 3)
    evs2 = detector.analyze_packet(make_icmp_packet(src_ip, "192.168.1.2", icmp_type=3))
    assert len(evs2) == 0

    assert src_ip not in detector._icmp_sweep_state
