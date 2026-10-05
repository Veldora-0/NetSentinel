"""Unit tests for Network + Host security event correlation in RiskEngine (Phase 7)."""

import time
import pytest
from backend.risk_engine import RiskEngine
from backend.detector import SecurityEvent


def test_cross_domain_correlation_network_then_host():
    """Verify network event followed by host event from same IP triggers correlation."""
    engine = RiskEngine()
    attacker_ip = "203.0.113.50"

    # Step 1: Network event (Port Scan)
    net_event = SecurityEvent(
        event_id="net-evt-1",
        timestamp=time.time(),
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip=attacker_ip,
        destination_ip="192.168.1.10",
        description="Port scan detected from 203.0.113.50",
    )
    assessment1 = engine.assess_rule_event(net_event)
    assert assessment1.evidence["correlated"] is False
    assert assessment1.evidence["correlation_boost"] == 0.0

    # Step 2: Host event (SSH Brute Force) from same IP within window
    host_event = SecurityEvent(
        event_id="host-evt-1",
        timestamp=time.time(),
        detection_type="SSH_BRUTE_FORCE",
        severity="HIGH",
        source_ip=attacker_ip,
        destination_ip="192.168.1.10",
        description="SSH brute-force attack from 203.0.113.50",
    )
    assessment2 = engine.assess_rule_event(host_event)
    
    assert assessment2.evidence["correlated"] is True
    assert assessment2.evidence["correlation_boost"] == 0.10
    assert "Correlated hybrid attack" in assessment2.evidence["correlation_reason"]
    assert "network" in assessment2.evidence["correlation_reason"]
    assert "host" in assessment2.evidence["correlation_reason"]


def test_cross_domain_correlation_host_then_network():
    """Verify host event followed by network event from same IP triggers correlation."""
    engine = RiskEngine()
    attacker_ip = "203.0.113.60"

    # Step 1: Host event (SSH Auth Failure)
    host_event = SecurityEvent(
        event_id="host-evt-2",
        timestamp=time.time(),
        detection_type="SSH_AUTH_FAILURE",
        severity="LOW",
        source_ip=attacker_ip,
        description="Failed SSH login from 203.0.113.60",
    )
    assessment1 = engine.assess_rule_event(host_event)
    assert assessment1.evidence["correlated"] is False

    # Step 2: Network event (SYN Flood) from same IP
    net_event = SecurityEvent(
        event_id="net-evt-2",
        timestamp=time.time(),
        detection_type="SYN_FLOOD",
        severity="HIGH",
        source_ip=attacker_ip,
        destination_ip="192.168.1.10",
        description="SYN flood attack from 203.0.113.60",
    )
    assessment2 = engine.assess_rule_event(net_event)
    assert assessment2.evidence["correlated"] is True
    assert assessment2.evidence["correlation_boost"] == 0.10


def test_same_domain_events_do_not_trigger_cross_domain_correlation():
    """Verify two events from the same domain (e.g. two network scans) do not trigger cross-domain correlation."""
    engine = RiskEngine()
    attacker_ip = "203.0.113.70"

    ev1 = SecurityEvent(
        event_id="net-1",
        timestamp=time.time(),
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip=attacker_ip,
        description="Port scan 1",
    )
    ev2 = SecurityEvent(
        event_id="net-2",
        timestamp=time.time(),
        detection_type="NULL_SCAN",
        severity="MEDIUM",
        source_ip=attacker_ip,
        description="NULL scan 2",
    )

    engine.assess_rule_event(ev1)
    assessment2 = engine.assess_rule_event(ev2)
    assert assessment2.evidence["correlated"] is False
    assert assessment2.evidence["correlation_boost"] == 0.0


def test_correlation_window_expiration():
    """Verify expired events outside correlation window do not trigger correlation."""
    engine = RiskEngine()
    attacker_ip = "203.0.113.80"

    # Event 1 in the past (> 300s)
    old_time = time.time() - 350
    net_event = SecurityEvent(
        event_id="net-old",
        timestamp=old_time,
        detection_type="PORT_SCAN",
        severity="MEDIUM",
        source_ip=attacker_ip,
        description="Old port scan",
    )
    engine.assess_rule_event(net_event)

    # Event 2 now (host event)
    host_event = SecurityEvent(
        event_id="host-new",
        timestamp=time.time(),
        detection_type="SSH_AUTH_FAILURE",
        severity="LOW",
        source_ip=attacker_ip,
        description="New SSH failure",
    )
    assessment = engine.assess_rule_event(host_event)
    assert assessment.evidence["correlated"] is False
    assert assessment.evidence["correlation_boost"] == 0.0
