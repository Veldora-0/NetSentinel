"""Unit tests for NetSentinel Rule-Based Intrusion Detector.

Tests Port Scan, SYN Flood, NULL Scan, and XMAS Scan rules,
alert suppression/cooldown, state pruning, and security event serialization.
"""

import json
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from detector import TrafficDetector, SecurityEvent
from parser import ParsedPacket
from app import create_app


def make_tcp_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    tcp_flags: dict = None,
    raw_flags: int = 0,
    timestamp: float = None,
) -> ParsedPacket:
    """Helper to generate a mock TCP ParsedPacket."""
    flags = tcp_flags if tcp_flags is not None else {
        "SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False
    }
    return ParsedPacket(
        timestamp=timestamp or time.time(),
        raw_length=60,
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        ethertype=0x0800,
        ethertype_name="IPv4",
        ip_version=4,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=6,
        protocol_name="TCP",
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        raw_tcp_flags=raw_flags,
    )


# --- Port Scan Tests ---

def test_port_scan_below_threshold():
    """Verify no alert is emitted if probed ports are below threshold."""
    detector = TrafficDetector({
        "port_scan_window_sec": 5.0,
        "port_scan_threshold": 5,
        "alert_cooldown_sec": 10.0,
    })

    events = []
    # Probe 4 ports (threshold is 5)
    for port in range(1, 5):
        pkt = make_tcp_packet(src_ip="192.168.1.50", dst_port=port)
        evts = detector.analyze_packet(pkt)
        events.extend(evts)

    assert len(events) == 0


def test_port_scan_threshold_exceeded():
    """Verify alert is emitted when distinct destination ports reach threshold."""
    detector = TrafficDetector({
        "port_scan_window_sec": 5.0,
        "port_scan_threshold": 5,
        "alert_cooldown_sec": 10.0,
    })

    events = []
    # Probe 5 distinct ports
    for port in range(1, 6):
        pkt = make_tcp_packet(src_ip="192.168.1.50", dst_port=port)
        evts = detector.analyze_packet(pkt)
        events.extend(evts)

    assert len(events) == 1
    evt = events[0]
    assert evt.detection_type == "PORT_SCAN"
    assert evt.severity == "MEDIUM"
    assert evt.source_ip == "192.168.1.50"
    assert evt.evidence["unique_ports_count"] == 5
    assert evt.rule_name == "RULE_PORT_SCAN"


def test_port_scan_time_window_expiration():
    """Verify ports probed outside the detection window do not accumulate."""
    detector = TrafficDetector({
        "port_scan_window_sec": 2.0,
        "port_scan_threshold": 3,
        "alert_cooldown_sec": 10.0,
    })

    t0 = 1000.0
    # 2 probes at t0
    detector.analyze_packet(make_tcp_packet(src_ip="1.2.3.4", dst_port=80, timestamp=t0))
    detector.analyze_packet(make_tcp_packet(src_ip="1.2.3.4", dst_port=81, timestamp=t0 + 0.1))

    # Next probe 3 seconds later (exceeds 2.0s window, earlier 2 probes expired)
    evts = detector.analyze_packet(make_tcp_packet(src_ip="1.2.3.4", dst_port=82, timestamp=t0 + 3.0))
    assert len(evts) == 0


def test_port_scan_independent_sources():
    """Verify distinct source IPs are tracked independently."""
    detector = TrafficDetector({
        "port_scan_window_sec": 5.0,
        "port_scan_threshold": 4,
        "alert_cooldown_sec": 10.0,
    })

    # Host A probes 3 ports
    for p in [80, 443, 22]:
        assert len(detector.analyze_packet(make_tcp_packet(src_ip="10.0.0.1", dst_port=p))) == 0

    # Host B probes 3 ports
    for p in [80, 443, 21]:
        assert len(detector.analyze_packet(make_tcp_packet(src_ip="10.0.0.2", dst_port=p))) == 0

    # Neither has hit 4, so 0 alerts
    assert len(detector.event_history) == 0


def test_port_scan_cooldown_suppression():
    """Verify duplicate port scan alerts are suppressed during cooldown."""
    detector = TrafficDetector({
        "port_scan_window_sec": 5.0,
        "port_scan_threshold": 3,
        "alert_cooldown_sec": 15.0,
    })

    t = 100.0
    # Probe 3 ports -> triggers alert
    detector.analyze_packet(make_tcp_packet(src_ip="192.168.1.99", dst_port=1, timestamp=t))
    detector.analyze_packet(make_tcp_packet(src_ip="192.168.1.99", dst_port=2, timestamp=t))
    evts1 = detector.analyze_packet(make_tcp_packet(src_ip="192.168.1.99", dst_port=3, timestamp=t))
    assert len(evts1) == 1

    # Probe 4th port 2 seconds later -> suppressed by 15s cooldown
    evts2 = detector.analyze_packet(make_tcp_packet(src_ip="192.168.1.99", dst_port=4, timestamp=t + 2.0))
    assert len(evts2) == 0

    # Probe after cooldown expires (16s later) -> new alert triggers
    detector.analyze_packet(make_tcp_packet(src_ip="192.168.1.99", dst_port=5, timestamp=t + 17.0))
    detector.analyze_packet(make_tcp_packet(src_ip="192.168.1.99", dst_port=6, timestamp=t + 17.0))
    evts3 = detector.analyze_packet(make_tcp_packet(src_ip="192.168.1.99", dst_port=7, timestamp=t + 17.0))
    assert len(evts3) == 1


# --- SYN Flood Tests ---

def test_syn_flood_normal_traffic_no_alert():
    """Verify ordinary SYN traffic below threshold triggers no alert."""
    detector = TrafficDetector({
        "syn_flood_window_sec": 5.0,
        "syn_flood_threshold": 10,
        "alert_cooldown_sec": 20.0,
    })

    syn_flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
    for i in range(5):
        evts = detector.analyze_packet(make_tcp_packet(src_ip="10.10.10.10", tcp_flags=syn_flags))
        assert len(evts) == 0


def test_syn_flood_threshold_exceeded():
    """Verify alert is triggered when SYN count hits threshold."""
    detector = TrafficDetector({
        "syn_flood_window_sec": 5.0,
        "syn_flood_threshold": 5,
        "alert_cooldown_sec": 20.0,
    })

    syn_flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
    events = []
    for i in range(5):
        evts = detector.analyze_packet(make_tcp_packet(src_ip="10.10.10.10", tcp_flags=syn_flags))
        events.extend(evts)

    assert len(events) == 1
    evt = events[0]
    assert evt.detection_type == "SYN_FLOOD"
    assert evt.severity == "HIGH"
    assert evt.source_ip == "10.10.10.10"
    assert evt.evidence["syn_count"] == 5


def test_syn_flood_window_expiration():
    """Verify SYNs outside the window are discarded."""
    detector = TrafficDetector({
        "syn_flood_window_sec": 2.0,
        "syn_flood_threshold": 3,
        "alert_cooldown_sec": 10.0,
    })

    syn_flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
    t0 = 2000.0
    detector.analyze_packet(make_tcp_packet(src_ip="5.5.5.5", tcp_flags=syn_flags, timestamp=t0))
    detector.analyze_packet(make_tcp_packet(src_ip="5.5.5.5", tcp_flags=syn_flags, timestamp=t0 + 0.5))

    # Send third SYN after window expired (at t0 + 3.0s)
    evts = detector.analyze_packet(make_tcp_packet(src_ip="5.5.5.5", tcp_flags=syn_flags, timestamp=t0 + 3.0))
    assert len(evts) == 0


# --- NULL Scan Tests ---

def test_null_scan_detection():
    """Verify NULL scan (all TCP flags 0) is accurately detected."""
    detector = TrafficDetector()
    null_flags = {"SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
    pkt = make_tcp_packet(src_ip="172.16.5.5", tcp_flags=null_flags, raw_flags=0)

    events = detector.analyze_packet(pkt)
    assert len(events) == 1
    assert events[0].detection_type == "NULL_SCAN"
    assert events[0].severity == "HIGH"
    assert events[0].source_ip == "172.16.5.5"


def test_null_scan_normal_packet_ignored():
    """Verify standard TCP packet (ACK or SYN+ACK) does not trigger NULL scan."""
    detector = TrafficDetector()
    normal_flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False}
    pkt = make_tcp_packet(src_ip="172.16.5.5", tcp_flags=normal_flags, raw_flags=0x10)

    events = detector.analyze_packet(pkt)
    assert len(events) == 0


# --- XMAS Scan Tests ---

def test_xmas_scan_detection():
    """Verify XMAS scan (FIN, PSH, URG set) is accurately detected."""
    detector = TrafficDetector()
    xmas_flags = {"SYN": False, "ACK": False, "FIN": True, "RST": False, "PSH": True, "URG": True}
    pkt = make_tcp_packet(src_ip="172.16.8.8", tcp_flags=xmas_flags, raw_flags=0x29)

    events = detector.analyze_packet(pkt)
    assert len(events) == 1
    assert events[0].detection_type == "XMAS_SCAN"
    assert events[0].severity == "HIGH"
    assert events[0].source_ip == "172.16.8.8"


def test_xmas_scan_normal_packet_ignored():
    """Verify regular packet does not trigger XMAS scan."""
    detector = TrafficDetector()
    syn_ack_flags = {"SYN": True, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False}
    pkt = make_tcp_packet(src_ip="172.16.8.8", tcp_flags=syn_ack_flags, raw_flags=0x12)

    events = detector.analyze_packet(pkt)
    assert len(events) == 0


# --- Robustness, State Cleanup, & Serialization ---

def test_malformed_and_empty_packets_safe():
    """Verify detector handles None, error-flagged, or invalid packets without crashing."""
    detector = TrafficDetector()

    # None packet
    assert detector.analyze_packet(None) == []

    # Error-flagged packet
    err_pkt = ParsedPacket(
        timestamp=time.time(),
        raw_length=5,
        src_mac="00:00:00:00:00:00",
        dst_mac="00:00:00:00:00:00",
        ethertype=0,
        ethertype_name="UNKNOWN",
        error="Truncated frame",
    )
    assert detector.analyze_packet(err_pkt) == []

    # Missing IP
    no_ip = make_tcp_packet(src_ip=None)
    assert detector.analyze_packet(no_ip) == []


def test_state_cleanup_and_bounded_memory():
    """Verify periodic state cleanup purges stale records and bounds memory."""
    detector = TrafficDetector({
        "port_scan_window_sec": 1.0,
        "syn_flood_window_sec": 1.0,
        "alert_cooldown_sec": 2.0,
        "state_cleanup_sec": 0.5,
        "max_tracked_ips": 5,
    })

    t = 1000.0
    # Add records for 6 different IPs
    for i in range(6):
        ip = f"10.0.0.{i}"
        detector.analyze_packet(make_tcp_packet(src_ip=ip, dst_port=80, timestamp=t))

    # Tracked IPs must not exceed max_tracked_ips (5)
    assert len(detector._port_scan_state) <= 5

    # Run cleanup at t + 10.0s (all earlier entries are stale)
    detector._prune_state_if_needed(now=t + 10.0)
    assert len(detector._port_scan_state) == 0


def test_security_event_json_serialization():
    """Verify SecurityEvent converts to valid JSON with required fields."""
    event = SecurityEvent(
        event_id="evt123",
        timestamp=1700000000.0,
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        protocol="TCP",
        source_port=54321,
        destination_port=80,
        description="Port scan detected",
        evidence={"unique_ports": 15},
        rule_name="RULE_PORT_SCAN",
    )

    d = event.to_dict()
    assert d["event_id"] == "evt123"
    assert d["severity"] == "MEDIUM"

    json_str = json.dumps(d)
    assert "PORT_SCAN" in json_str


def test_api_alerts_endpoint():
    """Verify GET /api/alerts returns recent alerts in newest-first order."""
    app, _ = create_app()
    app.config["TESTING"] = True

    # Inject two test alerts
    null_flags = {"SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False}
    app.detector.analyze_packet(make_tcp_packet(src_ip="1.1.1.1", tcp_flags=null_flags, timestamp=100.0))
    app.detector.analyze_packet(make_tcp_packet(src_ip="2.2.2.2", tcp_flags=null_flags, timestamp=200.0))

    with app.test_client() as client:
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["count"] >= 2
        # Check newest first
        alerts = data["alerts"]
        assert alerts[0]["source_ip"] == "2.2.2.2"
        assert alerts[1]["source_ip"] == "1.1.1.1"
