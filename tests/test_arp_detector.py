"""Tests for ARP Threat Detector Module (arp_detector.py)."""

import time
import pytest
from arp_detector import ARPDetector
from parser import ParsedPacket, ParsedARP


def make_arp_packet(
    sender_ip: str,
    sender_mac: str,
    target_ip: str = "192.168.1.1",
    target_mac: str = "00:00:00:00:00:00",
    operation: int = 1,
    operation_name: str = "REQUEST",
    is_gratuitous: bool = False,
    timestamp: float = None,
) -> ParsedPacket:
    """Helper to construct synthetic ParsedPacket containing ParsedARP."""
    arp_info = ParsedARP(
        hardware_type=1,
        protocol_type=0x0800,
        hardware_size=6,
        protocol_size=4,
        operation=operation,
        operation_name=operation_name,
        sender_mac=sender_mac,
        sender_ip=sender_ip,
        target_mac=target_mac,
        target_ip=target_ip,
        is_gratuitous=is_gratuitous,
    )
    return ParsedPacket(
        timestamp=timestamp or time.time(),
        raw_length=42,
        src_mac=sender_mac,
        dst_mac=target_mac,
        ethertype=0x0806,
        ethertype_name="ARP",
        protocol=None,
        protocol_name="ARP",
        src_ip=sender_ip,
        dst_ip=target_ip,
        arp_info=arp_info,
    )


def test_arp_baseline_no_alert():
    """Verify first observation of an IP establishes baseline without triggering alert."""
    detector = ARPDetector({"arp_enabled": True})
    pkt = make_arp_packet("192.168.1.50", "00:11:22:33:44:55")

    events = detector.process_packet(pkt)
    assert len(events) == 0

    mappings = detector.get_mappings()
    assert len(mappings) == 1
    assert mappings[0]["ip"] == "192.168.1.50"
    assert mappings[0]["mac"] == "00:11:22:33:44:55"
    assert mappings[0]["claims_count"] == 1


def test_arp_repeated_same_mac_updates_state():
    """Verify repeated packets from same MAC increment claims without alerting."""
    detector = ARPDetector({"arp_enabled": True})
    pkt1 = make_arp_packet("192.168.1.50", "00:11:22:33:44:55", timestamp=100.0)
    pkt2 = make_arp_packet("192.168.1.50", "00:11:22:33:44:55", timestamp=105.0)

    detector.process_packet(pkt1)
    events = detector.process_packet(pkt2)

    assert len(events) == 0
    mappings = detector.get_mappings()
    assert len(mappings) == 1
    assert mappings[0]["claims_count"] == 2
    assert mappings[0]["last_seen"] == 105.0


def test_arp_spoofing_new_mac_triggers_alert():
    """Verify active IP claimed by a different MAC triggers ARP_SPOOFING alert."""
    detector = ARPDetector({"arp_enabled": True, "arp_cooldown_sec": 60.0})
    # Legitimate host claims IP
    detector.process_packet(make_arp_packet("192.168.1.50", "00:11:22:33:44:55", timestamp=100.0))

    # Attacker MAC claims same IP within state timeout
    events = detector.process_packet(
        make_arp_packet("192.168.1.50", "aa:bb:cc:dd:ee:ff", timestamp=110.0, is_gratuitous=True)
    )

    assert len(events) == 1
    evt = events[0]
    assert evt.detection_type == "ARP_SPOOFING"
    assert evt.severity == "HIGH"
    assert evt.source_ip == "192.168.1.50"
    assert evt.evidence["original_mac"] == "00:11:22:33:44:55"
    assert evt.evidence["claimed_mac"] == "aa:bb:cc:dd:ee:ff"
    assert evt.evidence["is_gratuitous"] is True


def test_arp_spoofing_alert_cooldown():
    """Verify duplicate ARP spoofing alerts for same IP are suppressed during cooldown."""
    detector = ARPDetector({"arp_enabled": True, "arp_cooldown_sec": 60.0})
    detector.process_packet(make_arp_packet("192.168.1.50", "00:11:22:33:44:55", timestamp=100.0))

    # First spoof attempt -> alert
    ev1 = detector.process_packet(make_arp_packet("192.168.1.50", "aa:bb:cc:dd:ee:ff", timestamp=110.0))
    assert len(ev1) == 1

    # Second spoof attempt at timestamp 130 (20s < 60s cooldown) -> suppressed
    ev2 = detector.process_packet(make_arp_packet("192.168.1.50", "11:22:33:44:55:66", timestamp=130.0))
    assert len(ev2) == 0

    # Third spoof attempt at timestamp 180 (70s > 60s cooldown) -> alerted
    ev3 = detector.process_packet(make_arp_packet("192.168.1.50", "77:88:99:aa:bb:cc", timestamp=180.0))
    assert len(ev3) == 1
    assert ev3[0].detection_type == "ARP_SPOOFING"


def test_arp_spoofing_trusted_mapping_enforcement():
    """Verify static trusted binding generates alert immediately and preserves authoritative MAC."""
    trusted = {"192.168.1.1": "00:50:56:00:00:01"}
    detector = ARPDetector({
        "arp_enabled": True,
        "arp_trusted_mappings": trusted,
    })

    # Rogue device claims trusted gateway IP with different MAC
    events = detector.process_packet(
        make_arp_packet("192.168.1.1", "de:ad:be:ef:00:99", timestamp=200.0)
    )

    assert len(events) == 1
    evt = events[0]
    assert evt.detection_type == "ARP_SPOOFING"
    assert evt.severity == "HIGH"
    assert evt.evidence["is_trusted_target"] is True
    assert evt.evidence["original_mac"] == "00:50:56:00:00:01"

    # Authoritative mapping remains preserved
    mappings = {m["ip"]: m for m in detector.get_mappings()}
    assert mappings["192.168.1.1"]["mac"] == "00:50:56:00:00:01"
    assert mappings["192.168.1.1"]["is_trusted"] is True


def test_arp_state_timeout_expiration():
    """Verify expired mapping allows new MAC reassignment without false positive alert."""
    detector = ARPDetector({
        "arp_enabled": True,
        "arp_state_timeout": 50.0,
    })

    # Host A claims IP at t=100
    detector.process_packet(make_arp_packet("192.168.1.200", "00:11:11:11:11:11", timestamp=100.0))

    # Host B claims IP at t=200 (delta 100s > 50s timeout) -> normal DHCP reassignment, no alert
    events = detector.process_packet(
        make_arp_packet("192.168.1.200", "00:22:22:22:22:22", timestamp=200.0)
    )
    assert len(events) == 0

    mappings = {m["ip"]: m for m in detector.get_mappings()}
    assert mappings["192.168.1.200"]["mac"] == "00:22:22:22:22:22"


def test_arp_identity_conflict_threshold():
    """Verify single MAC claiming >= conflict_threshold distinct IPs emits ARP_IDENTITY_CONFLICT."""
    detector = ARPDetector({
        "arp_enabled": True,
        "arp_conflict_threshold": 3,
        "arp_cooldown_sec": 60.0,
    })

    mac = "ee:ff:11:22:33:44"
    # Claim IP 1
    ev1 = detector.process_packet(make_arp_packet("10.0.0.1", mac, timestamp=100.0))
    assert len(ev1) == 0

    # Claim IP 2
    ev2 = detector.process_packet(make_arp_packet("10.0.0.2", mac, timestamp=101.0))
    assert len(ev2) == 0

    # Claim IP 3 -> reaches threshold of 3!
    ev3 = detector.process_packet(make_arp_packet("10.0.0.3", mac, timestamp=102.0))
    assert len(ev3) == 1
    evt = ev3[0]
    assert evt.detection_type == "ARP_IDENTITY_CONFLICT"
    assert evt.severity == "MEDIUM"
    assert evt.evidence["mac"] == mac
    assert evt.evidence["claimed_ips_count"] == 3


def test_arp_memory_bounds_and_pruning():
    """Verify maximum tracked IP and MAC bounds prevent memory leaks."""
    detector = ARPDetector({
        "arp_enabled": True,
        "arp_max_tracked_ips": 5,
        "arp_max_tracked_macs": 5,
    })

    # Add 10 distinct IPs from 10 distinct MACs
    for i in range(10):
        detector.process_packet(
            make_arp_packet(f"192.168.1.{i+1}", f"00:00:00:00:00:0{i}", timestamp=100.0 + i)
        )

    assert len(detector._ip_to_mac) <= 5
    assert len(detector._mac_to_ips) <= 5


def test_arp_get_status():
    """Verify operational status report structure."""
    detector = ARPDetector({
        "arp_enabled": True,
        "arp_conflict_threshold": 4,
        "arp_state_timeout": 120.0,
    })
    detector.process_packet(make_arp_packet("192.168.1.10", "aa:bb:cc:11:22:33"))

    status = detector.get_status()
    assert status["enabled"] is True
    assert status["tracked_ips_count"] == 1
    assert status["conflict_threshold"] == 4
    assert status["state_timeout_sec"] == 120.0
    assert status["stats"]["total_arp_packets"] == 1
