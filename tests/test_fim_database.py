"""Database and persistence tests for File Integrity Monitoring (FIM) (Phase 10)."""

import os
import sys
import time
import pytest

from app import create_app
from database import (
    db,
    FileIntegrityBaselineRecord,
    SecurityEventRecord,
    save_fim_baseline_record,
    get_fim_baseline_record,
    get_all_fim_baseline_records,
    delete_fim_baseline_record,
    query_fim_baseline,
    query_fim_stats,
    query_fim_events,
    cleanup_old_records,
)
from detector import SecurityEvent


@pytest.fixture
def test_app():
    app, socketio = create_app(start_capture=False)
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    with app.app_context():
        db.create_all()
        FileIntegrityBaselineRecord.query.delete()
        SecurityEventRecord.query.delete()
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()



def test_fim_baseline_crud(test_app):
    """Verify insert, get, update, and delete for FIM baseline records."""
    path = "/etc/test_config.conf"
    record_data = {
        "path": path,
        "file_type": "regular",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "size": 1024,
        "mode": "0644",
        "uid": 0,
        "gid": 0,
        "inode": 12345678,
        "mtime": 1700000000.0,
        "status": "BASELINE",
    }

    # 1. Insert
    success = save_fim_baseline_record(record_data)
    assert success is True

    # 2. Get
    retrieved = get_fim_baseline_record(path)
    assert retrieved is not None
    assert retrieved["path"] == path
    assert retrieved["size"] == 1024
    assert retrieved["status"] == "BASELINE"

    # 3. Update
    record_data["sha256"] = "1111111111111111111111111111111111111111111111111111111111111111"
    record_data["status"] = "CHANGED"
    update_success = save_fim_baseline_record(record_data)
    assert update_success is True

    updated = get_fim_baseline_record(path)
    assert updated["sha256"] == record_data["sha256"]
    assert updated["status"] == "CHANGED"

    # 4. Get all
    all_records = get_all_fim_baseline_records()
    assert path in all_records
    assert all_records[path]["status"] == "CHANGED"

    # 5. Delete
    del_res = delete_fim_baseline_record(path)
    assert del_res is True
    assert get_fim_baseline_record(path) is None


def test_query_fim_baseline_filtering(test_app):
    """Verify query_fim_baseline supports pagination, path filtering, and status filtering."""
    paths = [
        ("/etc/passwd", "BASELINE"),
        ("/etc/shadow", "BASELINE"),
        ("/etc/sudoers", "CHANGED"),
        ("/etc/deleted.conf", "MISSING"),
        ("/etc/secret.key", "UNREADABLE"),
    ]

    for p, st in paths:
        save_fim_baseline_record({
            "path": p,
            "file_type": "regular",
            "sha256": "dummyhash",
            "status": st,
        })

    # All records
    res_all = query_fim_baseline()
    assert res_all["total"] == 5
    assert len(res_all["baseline"]) == 5

    # Filter by status
    res_changed = query_fim_baseline(status="CHANGED")
    assert res_changed["total"] == 1
    assert res_changed["baseline"][0]["path"] == "/etc/sudoers"

    # Filter by path substring
    res_shadow = query_fim_baseline(path="shadow")
    assert res_shadow["total"] == 1
    assert res_shadow["baseline"][0]["path"] == "/etc/shadow"

    # Pagination
    res_page = query_fim_baseline(limit=2, offset=0)
    assert len(res_page["baseline"]) == 2
    assert res_page["total"] == 5


def test_query_fim_stats(test_app):
    """Verify query_fim_stats aggregates status counts accurately."""
    save_fim_baseline_record({"path": "/file1", "status": "BASELINE"})
    save_fim_baseline_record({"path": "/file2", "status": "BASELINE"})
    save_fim_baseline_record({"path": "/file3", "status": "CHANGED"})
    save_fim_baseline_record({"path": "/file4", "status": "MISSING"})
    save_fim_baseline_record({"path": "/file5", "status": "UNREADABLE"})

    stats = query_fim_stats()
    assert stats["total_files"] == 5
    assert stats["baseline_count"] == 2
    assert stats["changed_count"] == 1
    assert stats["missing_count"] == 1
    assert stats["unreadable_count"] == 1


def test_query_fim_events(test_app):
    """Verify query_fim_events retrieves only FIM security events with filters."""
    now = time.time()

    # Add 2 FIM events and 1 network event
    fim_evt1 = SecurityEventRecord(
        event_id="fim-evt-1",
        timestamp=now - 50,
        detection_type="FILE_MODIFIED",
        severity="MEDIUM",
        source_ip=None,
        description="Integrity fingerprint changed for /etc/passwd",
        evidence='{"path": "/etc/passwd", "change_type": "FILE_MODIFIED"}',
    )
    fim_evt2 = SecurityEventRecord(
        event_id="fim-evt-2",
        timestamp=now - 20,
        detection_type="FILE_DELETED",
        severity="MEDIUM",
        source_ip=None,
        description="Monitored file deleted from /etc/deleted.conf",
        evidence='{"path": "/etc/deleted.conf", "change_type": "FILE_DELETED"}',
    )
    net_evt = SecurityEventRecord(
        event_id="net-evt-1",
        timestamp=now - 10,
        detection_type="PORT_SCAN",
        severity="HIGH",
        source_ip="192.168.1.100",
        description="Port scan detected",
    )

    db.session.add_all([fim_evt1, fim_evt2, net_evt])
    db.session.commit()

    # Query all FIM events
    all_fim = query_fim_events()
    assert all_fim["total"] == 2
    assert all(e["detection_type"] in ("FILE_MODIFIED", "FILE_DELETED") for e in all_fim["events"])

    # Query by change_type
    mod_only = query_fim_events(change_type="FILE_MODIFIED")
    assert mod_only["total"] == 1
    assert mod_only["events"][0]["event_id"] == "fim-evt-1"

    # Query by path filter
    deleted_path = query_fim_events(path="deleted.conf")
    assert deleted_path["total"] == 1
    assert deleted_path["events"][0]["event_id"] == "fim-evt-2"


def test_fim_baseline_survives_retention_cleanup(test_app):
    """Verify baseline records are NEVER pruned during historical data retention cleanup."""
    # Add old baseline records with timestamps from 30 days ago
    old_ts = time.time() - (30 * 86400)
    save_fim_baseline_record({
        "path": "/etc/long_standing_config.conf",
        "file_type": "regular",
        "sha256": "persistent_hash_123",
        "status": "BASELINE",
        "first_seen": old_ts,
        "last_verified": old_ts,
    })

    # Run retention cleanup for 7 days
    res = cleanup_old_records(retention_days=7)

    # Baseline record must STILL exist
    record = get_fim_baseline_record("/etc/long_standing_config.conf")
    assert record is not None
    assert record["path"] == "/etc/long_standing_config.conf"
    assert record["sha256"] == "persistent_hash_123"
