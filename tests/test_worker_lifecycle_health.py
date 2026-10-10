"""Automated tests for NetSentinel Worker Lifecycle, Health Probes, and Degraded Prevention.

Verifies:
- Test A: Fresh worker heartbeat -> HEALTHY
- Test B: Stale heartbeat (exceeding 2x stale_threshold_sec) -> DEGRADED
- Test C: Recorded operational error -> DEGRADED
- Test D: Genuine error recovery vs invalid recovery attempt on dead/failing worker
- Test E: Unexpected thread death / is_alive() returning False -> FAILED
- Test F: Intentionally disabled components (firewall, threat_intel) -> remain DISABLED
- Test G: Repeated frontend polling of /api/ready and /api/system/status does not degrade workers
- Test H: Readiness probe returns 200 when ready, 503 when required worker fails
- Test I: End-to-end security pipeline functioning without lifecycle regressions
"""

import threading
import time
from unittest.mock import MagicMock

import pytest

from app import create_app
from config import Config
from detector import SecurityEvent
from lifecycle import (
    LifecycleManager,
    STATUS_HEALTHY,
    STATUS_DEGRADED,
    STATUS_DISABLED,
    STATUS_FAILED,
    STATUS_STOPPED,
    WorkerStatus,
)


@pytest.fixture
def test_app_and_client():
    test_config = {
        "TESTING": True,
        "SECRET_KEY": "test-key-lifecycle-health",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "DETECTOR_THRESHOLDS": {
            "port_scan_window_sec": 5.0,
            "port_scan_threshold": 5,
            "syn_flood_window_sec": 3.0,
            "syn_flood_threshold": 10,
        },
        "ML_SETTINGS": {
            "window_size_seconds": 2.0,
            "baseline_window_count": 2,
            "contamination": 0.05,
            "anomaly_threshold": -0.15,
        },
        "RISK_SETTINGS": {
            "rule_weight": 0.65,
            "ml_weight": 0.35,
            "auto_block_threshold": 0.85,
        },
        "FIREWALL_SETTINGS": {
            "firewall_enabled": False,
            "dry_run": True,
        },
        "TI_SETTINGS": {
            "ti_enabled": False,
        },
    }
    app, _ = create_app(config_class=test_config, start_capture=False)
    client = app.test_client()
    return app, client


# ==============================================================================
# Test A: Fresh worker heartbeat -> HEALTHY
# ==============================================================================
def test_fresh_worker_heartbeat_healthy():
    mgr = LifecycleManager()
    mock_instance = MagicMock()
    mock_instance.is_alive.return_value = True

    mgr.register_worker("worker_a", mock_instance, stale_threshold_sec=2.0)
    assert mgr.get_worker_status("worker_a")["status"] == STATUS_HEALTHY

    # Update heartbeat
    mgr.record_heartbeat("worker_a")
    assert mgr.get_worker_status("worker_a")["status"] == STATUS_HEALTHY


# ==============================================================================
# Test B: Stale heartbeat (exceeding 2x threshold) -> DEGRADED
# ==============================================================================
def test_stale_heartbeat_degraded():
    mgr = LifecycleManager()
    mock_instance = MagicMock()
    mock_instance.is_alive.return_value = True

    # 1.0s threshold => stale at > 2.0s
    mgr.register_worker("worker_stale", mock_instance, stale_threshold_sec=1.0)
    assert mgr.get_worker_status("worker_stale")["status"] == STATUS_HEALTHY

    # Artificially age the heartbeat
    with mgr._lock:
        mgr._workers["worker_stale"].last_heartbeat = time.time() - 3.0

    assert mgr.get_worker_status("worker_stale")["status"] == STATUS_DEGRADED

    # Heartbeat refresh restores HEALTHY
    mgr.record_heartbeat("worker_stale")
    assert mgr.get_worker_status("worker_stale")["status"] == STATUS_HEALTHY


# ==============================================================================
# Test C: Recorded operational error -> DEGRADED
# ==============================================================================
def test_operational_error_degraded():
    mgr = LifecycleManager()
    mock_instance = MagicMock()
    mock_instance.is_alive.return_value = True

    mgr.register_worker("worker_err", mock_instance)
    assert mgr.get_worker_status("worker_err")["status"] == STATUS_HEALTHY

    mgr.record_error("worker_err", "Transient network timeout")
    status = mgr.get_worker_status("worker_err")
    assert status["status"] == STATUS_DEGRADED
    assert status["last_error"] == "Transient network timeout"
    assert status["error_count"] == 1


# ==============================================================================
# Test D: Genuine error recovery vs invalid recovery attempt on dead thread
# ==============================================================================
def test_genuine_recovery_vs_invalid_recovery():
    mgr = LifecycleManager()
    mock_instance = MagicMock()
    mock_instance.is_alive.return_value = True

    mgr.register_worker("worker_rec", mock_instance)
    mgr.record_error("worker_rec", "Database lock contention")
    assert mgr.get_worker_status("worker_rec")["status"] == STATUS_DEGRADED

    # Genuine recovery check succeeds while instance is alive
    recovered = mgr.record_recovery("worker_rec")
    assert recovered is True
    assert mgr.get_worker_status("worker_rec")["status"] == STATUS_HEALTHY
    assert mgr.get_worker_status("worker_rec")["last_error"] is None

    # Now simulate dead instance and error
    mgr.record_error("worker_rec", "Fatal crash")
    mock_instance.is_alive.return_value = False

    recovered_again = mgr.record_recovery("worker_rec")
    assert recovered_again is False
    assert mgr.get_worker_status("worker_rec")["status"] == STATUS_FAILED


# ==============================================================================
# Test E: Unexpected thread death -> FAILED
# ==============================================================================
def test_unexpected_thread_death_failed():
    mgr = LifecycleManager()

    # Real thread terminated unexpectedly
    def worker_work():
        return

    dead_thread = threading.Thread(target=worker_work, name="DeadThread")
    dead_thread.start()
    dead_thread.join()

    # Worker record wrapping dead thread
    class Subsystem:
        def __init__(self, thread):
            self._worker_thread = thread

    subsystem = Subsystem(dead_thread)
    mgr.register_worker("worker_crashed", subsystem, is_optional=False)

    status = mgr.get_worker_status("worker_crashed")
    assert status["status"] == STATUS_FAILED

    # For optional worker, unexpected crash reflects DEGRADED
    mgr.register_worker("optional_crashed", subsystem, is_optional=True)
    assert mgr.get_worker_status("optional_crashed")["status"] == STATUS_DEGRADED


# ==============================================================================
# Test F: Intentionally disabled components -> remain DISABLED
# ==============================================================================
def test_disabled_components_remain_disabled():
    mgr = LifecycleManager()

    class DisabledService:
        enabled = False

    disabled_svc = DisabledService()
    mgr.register_worker("firewall", disabled_svc, is_optional=True)
    mgr.register_worker("threat_intel", disabled_svc, is_optional=True)

    # Health checks across all workers
    results = mgr.check_all_workers_health()
    assert results["firewall"][0] is True
    assert results["threat_intel"][0] is True

    assert mgr.get_worker_status("firewall")["status"] == STATUS_DISABLED
    assert mgr.get_worker_status("threat_intel")["status"] == STATUS_DISABLED


# ==============================================================================
# Test G: Repeated frontend polling of /api/ready and /api/system/status
# ==============================================================================
def test_repeated_frontend_polling_no_degraded_workers(test_app_and_client):
    app, client = test_app_and_client

    # Poll /api/ready multiple times (simulating frontend polling every 2s)
    for _ in range(5):
        res = client.get("/api/ready")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ready"] is True
        workers = data["checks"]["workers"]
        # Required workers should NOT be DEGRADED
        for w_name, st in workers.items():
            if w_name in ("firewall", "threat_intel"):
                assert st == STATUS_DISABLED
            elif w_name == "packet_capture":
                assert st in (STATUS_HEALTHY, STATUS_STOPPED)
            else:
                assert st == STATUS_HEALTHY, f"Worker {w_name} degraded to {st}"

    # Also authenticate and poll /api/system/status
    with app.app_context():
        from auth.service import AuthService
        user, _ = AuthService.create_user("testadmin", "AdminPass123!", "ADMIN")
        _, token, _, _ = AuthService.authenticate("testadmin", "AdminPass123!")

    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(5):
        res = client.get("/api/system/status", headers=headers)
        assert res.status_code == 200
        data = res.get_json()
        workers = data["workers"]
        for w_name, w_info in workers.items():
            if w_name in ("firewall", "threat_intel"):
                assert w_info["status"] == STATUS_DISABLED
            elif w_name == "packet_capture":
                assert w_info["status"] in (STATUS_HEALTHY, STATUS_STOPPED)
            else:
                assert w_info["status"] == STATUS_HEALTHY, f"Worker {w_name} degraded to {w_info['status']}"


# ==============================================================================
# Test H: Readiness returns 200 when ready, 503 when required worker fails
# ==============================================================================
def test_readiness_probe_status_codes(test_app_and_client):
    app, client = test_app_and_client
    mgr = app.lifecycle_manager

    # Baseline: ready
    res = client.get("/api/ready")
    assert res.status_code == 200
    assert res.get_json()["ready"] is True

    # Simulate failure on required worker (e.g. ml_detector)
    mgr.set_worker_status("ml_detector", STATUS_FAILED, error="Model corruption")
    res_fail = client.get("/api/ready")
    assert res_fail.status_code == 503
    assert res_fail.get_json()["ready"] is False
    assert res_fail.get_json()["checks"]["workers"]["ml_detector"] == STATUS_FAILED

    # Recover worker
    mgr.set_worker_status("ml_detector", STATUS_HEALTHY)
    res_rec = client.get("/api/ready")
    assert res_rec.status_code == 200
    assert res_rec.get_json()["ready"] is True


# ==============================================================================
# Test I: Pipeline functionality remains intact with heartbeat updates
# ==============================================================================
def test_pipeline_security_event_heartbeats(test_app_and_client):
    app, _ = test_app_and_client
    mgr = app.lifecycle_manager

    # Before event, detector and risk_engine are registered
    initial_hb_det = mgr._workers["detector"].last_heartbeat
    time.sleep(0.05)

    # Dispatch security event through app.detector
    evt = SecurityEvent(
        event_id="test-evt-lifecycle-1",
        timestamp=time.time(),
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        description="Test port scan alert",
    )

    with app.app_context():
        app.detector._event_callbacks[0](evt)

    # Detector and risk engine heartbeats should have refreshed
    assert mgr._workers["detector"].last_heartbeat >= initial_hb_det
    assert mgr.get_worker_status("detector")["status"] == STATUS_HEALTHY
    assert mgr.get_worker_status("risk_engine")["status"] == STATUS_HEALTHY
    assert mgr.get_worker_status("incident_manager")["status"] == STATUS_HEALTHY
