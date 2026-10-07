"""Phase 14 End-to-End Validation: Firewall Safety & Invariant Containment.

Verifies:
1. Automated mitigation remains completely disabled (`NETSENTINEL_FIREWALL_ENABLED=false`, `NETSENTINEL_AUTO_BLOCK=false`).
2. Even when a CRITICAL risk assessment recommends action="block", no iptables command executes.
3. Direct `block_ip()` calls return simulated responses in disabled mode.
4. Allowlist addresses (127.0.0.1, ::1) are strictly rejected from blocking.
"""

import pytest

from app import create_app
from database import db


@pytest.fixture
def fw_app():
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
        yield app
        db.session.remove()
        db.drop_all()


def test_e2e_firewall_invariants_and_auto_block_prevention(fw_app):
    """Verify that auto-blocking is prevented and firewall configuration remains disabled."""
    fw = fw_app.firewall

    # Initial safety invariants
    assert fw.enabled is False
    assert fw.auto_block is False
    assert fw.dry_run is True

    # Assess CRITICAL event recommending block
    assessment = fw_app.risk_engine.assess(
        source_ip="192.168.1.240",
        rule_alerts=[{"severity": "CRITICAL", "detection_type": "SYN_FLOOD"}],
        ml_anomaly_score=1.0,
    )
    assert assessment.recommended_action == "block"
    assert assessment.risk_level == "CRITICAL"

    # Invariant: Pipeline must not have marked assessment as blocked
    assert assessment.blocked is False


def test_e2e_firewall_direct_block_simulated(fw_app):
    """Verify direct block call operates safely in simulated mode without modifying kernel chains."""
    fw = fw_app.firewall
    target_ip = "192.168.1.245"

    res = fw.block_ip(ip_address=target_ip, reason="Manual block simulation test")
    assert res["success"] is True
    assert res["status"] == "simulated"
    assert res["mode"] == "disabled"
    assert "simulated" in res["message"].lower()

    # Block list inspection
    status = fw.get_status()
    assert status["enabled"] is False
    assert status["blocked_count"] == 1


def test_e2e_firewall_allowlist_protection(fw_app):
    """Verify loopback and allowlisted addresses are strictly rejected from blocking."""
    fw = fw_app.firewall

    # Loopback addresses
    for loopback in ["127.0.0.1", "::1"]:
        res = fw.block_ip(ip_address=loopback, reason="Attempted loopback block")
        assert res["success"] is False
        assert res["status"] == "rejected"
        assert "loopback" in res["message"].lower()

    # Configured custom allowlist address
    fw.allowlist_configured.append("192.168.1.5")
    res_allow = fw.block_ip(ip_address="192.168.1.5", reason="Attempted allowlisted IP block")
    assert res_allow["success"] is False
    assert res_allow["status"] == "rejected"
    assert "allowlist" in res_allow["message"].lower()
