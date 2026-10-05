"""REST API and lifecycle integration tests for File Integrity Monitoring (FIM) (Phase 10)."""

import os
import sys
import tempfile
import time
import pytest

from app import create_app
from database import db, save_fim_baseline_record, SecurityEventRecord
from host.file_integrity import FileIntegrityMonitor


@pytest.fixture
def app_and_client(tmp_path):
    f1 = tmp_path / "passwd_test"
    f1.write_text("root:x:0:0::/root:/bin/bash")
    f2 = tmp_path / "shadow_test"
    f2.write_text("root:*:19000:0:99999:7:::")

    app, socketio = create_app(start_capture=False)
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["FIM_SETTINGS"] = {
        "fim_enabled": True,
        "fim_interval_sec": 10.0,
        "fim_paths": [str(f1), str(f2)],
        "fim_max_files": 100,
        "fim_max_file_size": 1048576,
    }

    with app.app_context():
        db.create_all()
        # Initialize FIM monitor with test paths
        if hasattr(app, "host_manager") and hasattr(app.host_manager, "file_integrity"):
            app.host_manager.file_integrity.configured_paths = [str(f1), str(f2)]
            app.host_manager.file_integrity.build_baseline()

        with app.test_client() as client:
            yield app, client, (f1, f2)
            db.session.remove()
            db.drop_all()


def test_get_fim_status(app_and_client):
    """Verify GET /api/fim/status returns operational FIM state."""
    app, client, (f1, f2) = app_and_client
    response = client.get("/api/fim/status")
    assert response.status_code == 200

    data = response.get_json()
    assert "enabled" in data
    assert "baseline_ready" in data
    assert data["baseline_ready"] is True
    assert "baseline_file_count" in data
    assert data["baseline_file_count"] >= 2
    assert "changed_count" in data
    assert "missing_count" in data
    assert "unreadable_count" in data
    assert "interval_seconds" in data


def test_get_fim_baseline(app_and_client):
    """Verify GET /api/fim/baseline returns paginated baseline records with path filtering."""
    app, client, (f1, f2) = app_and_client

    response = client.get("/api/fim/baseline")
    assert response.status_code == 200
    data = response.get_json()
    assert "total" in data
    assert "baseline" in data
    assert isinstance(data["baseline"], list)

    # Filter by path substring
    filtered_res = client.get(f"/api/fim/baseline?path={f1.name}")
    assert filtered_res.status_code == 200
    filtered_data = filtered_res.get_json()
    assert filtered_data["total"] >= 1
    assert any(b["path"] == str(f1) for b in filtered_data["baseline"])


def test_get_fim_events_empty_and_populated(app_and_client):
    """Verify GET /api/fim/events retrieves and filters historical FIM alerts."""
    app, client, (f1, f2) = app_and_client

    # Empty initially
    resp1 = client.get("/api/fim/events")
    assert resp1.status_code == 200
    data1 = resp1.get_json()
    assert data1["total"] == 0

    # Populate a record
    with app.app_context():
        sec_rec = SecurityEventRecord(
            event_id="fim-api-evt-1",
            timestamp=time.time(),
            detection_type="FILE_MODIFIED",
            severity="MEDIUM",
            source_ip=None,
            description=f"Integrity fingerprint changed for {f1}",
            evidence=f'{{"path": "{f1}", "change_type": "FILE_MODIFIED"}}',
        )
        db.session.add(sec_rec)
        db.session.commit()

    resp2 = client.get("/api/fim/events")
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2["total"] == 1
    assert data2["events"][0]["detection_type"] == "FILE_MODIFIED"

    # Filter by change_type
    resp_mod = client.get("/api/fim/events?change_type=FILE_MODIFIED")
    assert resp_mod.status_code == 200
    assert resp_mod.get_json()["total"] == 1

    resp_del = client.get("/api/fim/events?change_type=FILE_DELETED")
    assert resp_del.status_code == 200
    assert resp_del.get_json()["total"] == 0


def test_post_fim_rebaseline_success_and_validation(app_and_client):
    """Verify POST /api/fim/rebaseline triggers baseline recalculation safely."""
    app, client, (f1, f2) = app_and_client

    # 1. Invalid payload format
    inv_resp = client.post("/api/fim/rebaseline", json={"paths": "not-a-list"})
    assert inv_resp.status_code == 400
    inv_data = inv_resp.get_json()
    assert inv_data["success"] is False

    # 2. Modify file content
    f1.write_text("altered root content for rebaseline test")

    # 3. Valid rebaseline call
    resp = client.post("/api/fim/rebaseline", json={"paths": [str(f1)]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "summary" in data
    assert data["summary"]["updated_count"] == 1

    # Verify status reflects 0 changes after rebaseline
    status_resp = client.get("/api/fim/status")
    status_data = status_resp.get_json()
    assert status_data["changed_count"] == 0


def test_fim_standalone_worker_lifecycle(tmp_path):
    """Verify FileIntegrityMonitor standalone thread start, verify, and stop lifecycle."""
    f1 = tmp_path / "worker_test.txt"
    f1.write_text("worker baseline")

    monitor = FileIntegrityMonitor(config={
        "fim_paths": [str(f1)],
        "fim_interval_sec": 0.5,
        "fim_enabled": True,
    })
    monitor.build_baseline()

    # Start background thread
    started = monitor.start()
    assert started is True
    assert monitor._worker_thread.is_alive()

    # Calling start again should not spawn duplicate thread
    started_again = monitor.start()
    assert started_again is True

    time.sleep(0.1)

    # Stop gracefully
    monitor.stop()
    assert monitor._worker_thread is None
