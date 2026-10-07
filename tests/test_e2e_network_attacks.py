"""Phase 14 End-to-End Validation: Network Attack Scenarios.

Verifies detection rules, SecurityEvent generation, risk assessment,
incident correlation, and persistence for:
1. Port Scan (satisfying current configured detector threshold)
2. SYN Flood (satisfying current configured rate threshold)
3. Stealth NULL Scan (TCP segment with all flags cleared)
4. Stealth XMAS Scan (TCP segment with FIN, PSH, URG active)
5. ICMP Sweep (satisfying unique-destination threshold, and negative control)
6. ARP Spoofing, Identity Conflict, and Trusted Mapping Enforcement
"""

import time
import pytest

from app import create_app
from database import db, query_incidents, query_security_events
from parser import ParsedPacket, ParsedARP


def make_pkt(
    proto: int = 6,
    proto_name: str = "TCP",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.10",
    src_port: int = 50000,
    dst_port: int = 80,
    tcp_flags: dict = None,
    raw_tcp_flags: int = None,
    icmp_type: int = None,
    icmp_code: int = None,
    arp_info: ParsedARP = None,
    timestamp: float = None,
) -> ParsedPacket:
    return ParsedPacket(
        timestamp=timestamp or time.time(),
        raw_length=64,
        src_mac="00:11:22:33:44:55",
        dst_mac="aa:bb:cc:dd:ee:ff",
        ethertype=0x0806 if proto_name == "ARP" else 0x0800,
        ethertype_name="ARP" if proto_name == "ARP" else "IPv4",
        ip_version=4 if proto_name != "ARP" else None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=proto,
        protocol_name=proto_name,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        raw_tcp_flags=raw_tcp_flags,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        arp_info=arp_info,
    )


@pytest.fixture
def e2e_app():
    cfg = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "NETSENTINEL_FIREWALL_ENABLED": "False",
        "NETSENTINEL_AUTO_BLOCK": "False",
        "ARP_DETECTION_SETTINGS": {
            "arp_enabled": True,
            "arp_conflict_threshold": 3,
            "arp_cooldown_sec": 60.0,
            "arp_trusted_mappings": {
                "192.168.1.1": "00:00:5e:00:53:01",
            },
        },
    }
    app, _ = create_app(config_class=cfg, start_capture=False)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_e2e_port_scan_pipeline(e2e_app):
    """Verify port scan meeting configured threshold triggers event, risk, incident, and cooldown."""
    now = time.time()
    src_ip = "192.168.1.101"
    threshold = e2e_app.detector.port_scan_threshold  # Default 15

    alerts = []
    for port in range(1, threshold + 1):
        pkt = make_pkt(
            src_ip=src_ip,
            dst_port=port,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
            timestamp=now + (port * 0.1),
        )
        alerts.extend(e2e_app.detector.analyze_packet(pkt))

    assert len(alerts) >= 1
    event = alerts[0]
    assert event.detection_type == "PORT_SCAN"
    assert event.severity == "MEDIUM"
    assert event.source_ip == src_ip
    assert event.evidence["unique_ports_count"] >= threshold

    # Verify cooldown: next probe within cooldown window must not generate duplicate event
    extra_pkt = make_pkt(
        src_ip=src_ip,
        dst_port=9999,
        tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
        timestamp=now + 5.0,
    )
    extra_alerts = e2e_app.detector.analyze_packet(extra_pkt)
    assert len(extra_alerts) == 0

    # Verify database persistence & incident correlation
    sec_events = query_security_events(detection_type="PORT_SCAN", source_ip=src_ip)
    assert sec_events["total"] >= 1

    incidents = query_incidents(primary_source_ip=src_ip)
    assert incidents["total"] == 1
    inc = incidents["incidents"][0]
    assert "PORT_SCAN" in inc["detection_types"]
    assert inc["severity"] in ("MEDIUM", "HIGH")
    assert inc["risk_score"] > 0.0


def test_e2e_syn_flood_pipeline(e2e_app):
    """Verify SYN flood meeting configured threshold triggers HIGH severity event and correlation."""
    now = time.time()
    src_ip = "192.168.1.102"
    threshold = e2e_app.detector.syn_flood_threshold  # Default 50

    alerts = []
    for i in range(threshold):
        pkt = make_pkt(
            src_ip=src_ip,
            dst_port=80,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
            timestamp=now + (i * 0.05),
        )
        alerts.extend(e2e_app.detector.analyze_packet(pkt))

    assert len(alerts) >= 1
    event = alerts[0]
    assert event.detection_type == "SYN_FLOOD"
    assert event.severity == "HIGH"
    assert event.evidence["syn_count"] >= threshold

    # Verify persistence & incident
    incidents = query_incidents(primary_source_ip=src_ip)
    assert incidents["total"] == 1
    assert "SYN_FLOOD" in incidents["incidents"][0]["detection_types"]


def test_e2e_null_scan_pipeline(e2e_app):
    """Verify stealth NULL scan triggers HIGH severity security event."""
    now = time.time()
    src_ip = "192.168.1.103"
    null_pkt = make_pkt(
        src_ip=src_ip,
        dst_port=80,
        tcp_flags={"SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False, "URG": False},
        raw_tcp_flags=0,
        timestamp=now,
    )
    alerts = e2e_app.detector.analyze_packet(null_pkt)
    assert len(alerts) == 1
    assert alerts[0].detection_type == "NULL_SCAN"
    assert alerts[0].severity == "HIGH"

    incidents = query_incidents(primary_source_ip=src_ip)
    assert incidents["total"] == 1
    assert "NULL_SCAN" in incidents["incidents"][0]["detection_types"]


def test_e2e_xmas_scan_pipeline(e2e_app):
    """Verify stealth XMAS scan triggers HIGH severity security event."""
    now = time.time()
    src_ip = "192.168.1.104"
    xmas_pkt = make_pkt(
        src_ip=src_ip,
        dst_port=443,
        tcp_flags={"SYN": False, "ACK": False, "FIN": True, "RST": False, "PSH": True, "URG": True},
        raw_tcp_flags=0x29,
        timestamp=now,
    )
    alerts = e2e_app.detector.analyze_packet(xmas_pkt)
    assert len(alerts) == 1
    assert alerts[0].detection_type == "XMAS_SCAN"
    assert alerts[0].severity == "HIGH"

    incidents = query_incidents(primary_source_ip=src_ip)
    assert incidents["total"] == 1
    assert "XMAS_SCAN" in incidents["incidents"][0]["detection_types"]


def test_e2e_icmp_sweep_and_negative_control(e2e_app):
    """Verify ICMP sweep triggers at threshold, and does NOT trigger below threshold."""
    now = time.time()
    threshold = e2e_app.detector.icmp_sweep_threshold  # Default 10

    # 1. Negative control: 5 destination probes (below threshold)
    quiet_src = "192.168.1.105"
    quiet_alerts = []
    for i in range(5):
        pkt = make_pkt(
            proto=1,
            proto_name="ICMP",
            src_ip=quiet_src,
            dst_ip=f"10.0.0.{i + 1}",
            icmp_type=8,
            icmp_code=0,
            timestamp=now + (i * 0.1),
        )
        quiet_alerts.extend(e2e_app.detector.analyze_packet(pkt))
    assert len(quiet_alerts) == 0, "Probes below threshold must not trigger alert"
    assert query_incidents(primary_source_ip=quiet_src)["total"] == 0

    # 2. Positive test: threshold destination probes (at threshold)
    sweep_src = "192.168.1.106"
    sweep_alerts = []
    for i in range(threshold):
        pkt = make_pkt(
            proto=1,
            proto_name="ICMP",
            src_ip=sweep_src,
            dst_ip=f"10.0.0.{i + 10}",
            icmp_type=8,
            icmp_code=0,
            timestamp=now + (i * 0.1),
        )
        sweep_alerts.extend(e2e_app.detector.analyze_packet(pkt))

    assert len(sweep_alerts) >= 1
    assert sweep_alerts[0].detection_type == "ICMP_SWEEP"
    assert sweep_alerts[0].severity == "MEDIUM"

    incidents = query_incidents(primary_source_ip=sweep_src)
    assert incidents["total"] == 1
    assert "ICMP_SWEEP" in incidents["incidents"][0]["detection_types"]


def test_e2e_arp_spoofing_and_identity_conflict(e2e_app):
    """Verify ARP spoofing, identity conflict, and trusted static binding enforcement."""
    now = time.time()
    arp_det = e2e_app.arp_detector

    # 1. Normal learning baseline
    arp1 = ParsedARP(
        hardware_type=1, protocol_type=0x0800, hardware_size=6, protocol_size=4,
        operation=2, operation_name="reply",
        sender_mac="00:11:22:33:44:01", sender_ip="192.168.1.50",
        target_mac="ff:ff:ff:ff:ff:ff", target_ip="192.168.1.1",
    )
    p1 = make_pkt(proto=0, proto_name="ARP", src_ip="192.168.1.50", dst_ip="192.168.1.1", arp_info=arp1, timestamp=now)
    assert len(arp_det.process_packet(p1)) == 0

    # 2. Conflicting MAC claiming same IP -> ARP Spoofing
    arp2 = ParsedARP(
        hardware_type=1, protocol_type=0x0800, hardware_size=6, protocol_size=4,
        operation=2, operation_name="reply",
        sender_mac="aa:bb:cc:dd:ee:01", sender_ip="192.168.1.50",
        target_mac="ff:ff:ff:ff:ff:ff", target_ip="192.168.1.1",
    )
    p2 = make_pkt(proto=0, proto_name="ARP", src_ip="192.168.1.50", dst_ip="192.168.1.1", arp_info=arp2, timestamp=now + 1.0)
    spoof_alerts = arp_det.process_packet(p2)
    assert len(spoof_alerts) == 1
    assert spoof_alerts[0].detection_type == "ARP_SPOOFING"
    assert spoof_alerts[0].severity == "HIGH"
    assert spoof_alerts[0].evidence["original_mac"] == "00:11:22:33:44:01"
    assert spoof_alerts[0].evidence["claimed_mac"] == "aa:bb:cc:dd:ee:01"

    # 3. Trusted static gateway mapping conflict
    arp_trusted = ParsedARP(
        hardware_type=1, protocol_type=0x0800, hardware_size=6, protocol_size=4,
        operation=2, operation_name="reply",
        sender_mac="99:99:99:99:99:99", sender_ip="192.168.1.1",
        target_mac="ff:ff:ff:ff:ff:ff", target_ip="192.168.1.50",
    )
    p_trusted = make_pkt(proto=0, proto_name="ARP", src_ip="192.168.1.1", dst_ip="192.168.1.50", arp_info=arp_trusted, timestamp=now + 2.0)
    trusted_alerts = arp_det.process_packet(p_trusted)
    assert len(trusted_alerts) == 1
    assert trusted_alerts[0].detection_type == "ARP_SPOOFING"
    assert trusted_alerts[0].evidence["is_trusted_target"] is True

    # 4. Identity conflict: 1 MAC claiming 3 distinct IPs
    conflict_mac = "aa:bb:cc:dd:ee:99"
    conflict_alerts = []
    for i, ip_suf in enumerate([81, 82, 83]):
        arp_c = ParsedARP(
            hardware_type=1, protocol_type=0x0800, hardware_size=6, protocol_size=4,
            operation=2, operation_name="reply",
            sender_mac=conflict_mac, sender_ip=f"192.168.1.{ip_suf}",
            target_mac="ff:ff:ff:ff:ff:ff", target_ip="192.168.1.1",
        )
        p_c = make_pkt(proto=0, proto_name="ARP", src_ip=f"192.168.1.{ip_suf}", dst_ip="192.168.1.1", arp_info=arp_c, timestamp=now + 3.0 + i)
        conflict_alerts.extend(arp_det.process_packet(p_c))

    assert any(e.detection_type == "ARP_IDENTITY_CONFLICT" for e in conflict_alerts)
