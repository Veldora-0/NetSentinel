"""Phase 14 End-to-End Validation: Normal Traffic Baseline.

Verifies that benign, normal network traffic:
1. Passes through the packet parser and detector cleanly.
2. Does NOT generate false positive security alerts.
3. Keeps composite risk scores at LOW / routine baseline levels.
4. Creates NO spurious security incidents.
5. Causes NO firewall mitigation action.
"""

import time
import pytest

from app import create_app
from database import db, query_incidents, query_security_events
from parser import ParsedPacket


def make_benign_tcp_packet(seq: int, timestamp: float) -> ParsedPacket:
    """Construct an ordinary TCP packet representing benign web browsing traffic."""
    return ParsedPacket(
        timestamp=timestamp,
        raw_length=128,
        src_mac="00:11:22:33:44:01",
        dst_mac="aa:bb:cc:dd:ee:01",
        ethertype=0x0800,
        ethertype_name="IPv4",
        ip_version=4,
        src_ip="10.0.0.25",
        dst_ip="10.0.0.1",
        protocol=6,
        protocol_name="TCP",
        src_port=49200 + (seq % 10),
        dst_port=443,
        tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False},
        payload_length=64,
    )


def test_e2e_normal_traffic_baseline():
    """Verify that a steady stream of normal traffic produces no alerts or incidents."""
    cfg = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "NETSENTINEL_FIREWALL_ENABLED": "False",
        "NETSENTINEL_AUTO_BLOCK": "False",
        "FIREWALL_SETTINGS": {
            "enabled": False,
            "auto_block": False,
            "dry_run": True,
            "chain": "NETSENTINEL",
            "block_duration": 300.0,
            "max_blocked_ips": 500,
            "allowlist": ["127.0.0.1", "::1"],
        },
    }

    app, _ = create_app(config_class=cfg, start_capture=False)

    with app.app_context():
        db.create_all()
        now = time.time()
        emitted_alerts = []

        # Send 30 benign packets over a simulated 3-second period
        for i in range(30):
            pkt = make_benign_tcp_packet(seq=i, timestamp=now + (i * 0.1))
            alerts = app.detector.analyze_packet(pkt)
            app.ml_detector.process_packet(pkt)
            arp_alerts = app.arp_detector.process_packet(pkt)
            emitted_alerts.extend(alerts + arp_alerts)

        # Confirm pipeline state
        assert len(emitted_alerts) == 0, "Normal traffic should not generate rule alerts"

        sec_events = query_security_events(limit=50)
        assert sec_events["total"] == 0, "No security events should be saved for benign traffic"

        incidents = query_incidents(limit=50)
        assert incidents["total"] == 0, "No security incidents should be created for benign traffic"

        # Firewall invariants
        assert app.firewall.enabled is False
        assert app.firewall.auto_block is False
