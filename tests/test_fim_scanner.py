"""Tests for File Integrity Monitoring (FIM) core engine and scanner (Phase 10)."""

import hashlib
import os
import stat
import sys
import tempfile
import time
import pytest

from host.file_integrity import (
    FileIntegrityMonitor,
    hash_file,
    FILE_CREATED,
    FILE_DELETED,
    FILE_MODIFIED,
    FILE_REPLACED,
    FILE_METADATA_CHANGED,
    STATUS_BASELINE,
    STATUS_MISSING,
    STATUS_CHANGED,
    STATUS_UNREADABLE,
)


def test_hash_file_sha256_correctness(tmp_path):
    """Verify SHA-256 computation matches hashlib digest."""
    test_file = tmp_path / "sample.txt"
    content = b"NetSentinel File Integrity Verification Payload 12345"
    test_file.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()
    computed_hash, reason = hash_file(str(test_file))

    assert reason is None
    assert computed_hash == expected_hash


def test_hash_file_chunked_reading(tmp_path):
    """Verify chunked reading properly hashes multi-chunk content."""
    test_file = tmp_path / "large_chunk.bin"
    # Write 130 KiB to exceed a 64 KiB chunk size
    content = b"A" * (130 * 1024)
    test_file.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()
    computed_hash, reason = hash_file(str(test_file), chunk_size=65536)

    assert reason is None
    assert computed_hash == expected_hash


def test_hash_file_size_limit_safety(tmp_path):
    """Verify files larger than max_size are skipped safely without crashing."""
    test_file = tmp_path / "oversized.bin"
    test_file.write_bytes(b"X" * 1000)

    # Set max_size to 500 bytes
    computed_hash, reason = hash_file(str(test_file), max_size=500)
    assert computed_hash is None
    assert reason == "SKIPPED_OVERSIZED"


def test_hash_file_missing_and_error(tmp_path):
    """Verify hash_file gracefully handles missing files."""
    missing_file = tmp_path / "does_not_exist.txt"
    digest, reason = hash_file(str(missing_file))
    assert digest is None
    assert reason == "FILE_NOT_FOUND"


def test_hash_file_symlink_safety(tmp_path):
    """Verify symlinks are not followed for hashing."""
    target_file = tmp_path / "target.txt"
    target_file.write_text("Sensitive target content")

    link_file = tmp_path / "symlink_test"
    try:
        os.symlink(str(target_file), str(link_file))
    except (OSError, NotImplementedError):
        pytest.skip("Symlink not supported in test environment")

    digest, reason = hash_file(str(link_file))
    assert digest is None
    assert reason == "SYMLINK"


def test_fim_baseline_creation(tmp_path):
    """Verify baseline establishment records metadata and hashes for target files."""
    f1 = tmp_path / "config.conf"
    f2 = tmp_path / "users.txt"
    f1.write_text("key=value")
    f2.write_text("admin:1000")

    monitor = FileIntegrityMonitor(config={
        "fim_paths": [str(f1), str(f2)],
        "fim_enabled": True,
    })

    res = monitor.build_baseline()
    assert res["established"] is True
    assert res["total_files"] == 2
    assert res["missing"] == 0
    assert monitor.baseline_ready is True

    status = monitor.get_status()
    assert status["baseline_file_count"] == 2
    assert status["changed_count"] == 0


def test_fim_baseline_missing_file_during_init(tmp_path):
    """Verify baseline handles non-existent configured paths without crashing."""
    f1 = tmp_path / "exists.txt"
    f1.write_text("hello")
    f2 = tmp_path / "missing_at_start.txt"

    monitor = FileIntegrityMonitor(config={
        "fim_paths": [str(f1), str(f2)],
        "fim_enabled": True,
    })

    res = monitor.build_baseline()
    assert res["established"] is True
    assert res["total_files"] == 2
    assert res["missing"] == 1

    status = monitor.get_status()
    assert status["missing_count"] == 1


def test_fim_detect_content_modification(tmp_path):
    """Verify FILE_MODIFIED is detected when file content changes."""
    f1 = tmp_path / "monitored.txt"
    f1.write_text("original content")

    monitor = FileIntegrityMonitor(config={
        "fim_paths": [str(f1)],
        "fim_enabled": True,
    })
    monitor.build_baseline()

    # Modify content
    time.sleep(0.01)
    f1.write_text("altered content")

    events = monitor.verify_integrity()
    assert len(events) == 1
    ev = events[0]
    assert ev.detection_type == FILE_MODIFIED
    assert ev.source_ip is None
    assert ev.severity == "MEDIUM"
    assert ev.evidence["path"] == str(f1)
    assert ev.evidence["change_type"] == FILE_MODIFIED
    assert ev.evidence["previous_sha256"] != ev.evidence["current_sha256"]


def test_fim_detect_critical_path_modification(tmp_path):
    """Verify FILE_MODIFIED for a critical path has HIGH severity."""
    f1 = tmp_path / "passwd_mock"
    f1.write_text("root:x:0:0:root:/root:/bin/bash")

    monitor = FileIntegrityMonitor(config={
        "fim_paths": [str(f1)],
        "fim_critical_paths": [str(f1)],
        "fim_enabled": True,
    })
    monitor.build_baseline()

    f1.write_text("root:x:0:0:root:/root:/bin/sh\nbackdoor:x:0:0::/root:/bin/bash")

    events = monitor.verify_integrity()
    assert len(events) == 1
    assert events[0].detection_type == FILE_MODIFIED
    assert events[0].severity == "HIGH"


def test_fim_detect_file_deletion(tmp_path):
    """Verify FILE_DELETED is emitted when a baseline file is removed."""
    f1 = tmp_path / "delete_me.txt"
    f1.write_text("temporary")

    monitor = FileIntegrityMonitor(config={"fim_paths": [str(f1)]})
    monitor.build_baseline()

    # Delete the file
    os.remove(str(f1))

    events = monitor.verify_integrity()
    assert len(events) == 1
    assert events[0].detection_type == FILE_DELETED
    assert events[0].severity == "MEDIUM"
    assert events[0].evidence["path"] == str(f1)


def test_fim_detect_file_creation(tmp_path):
    """Verify FILE_CREATED is emitted when a previously missing target appears."""
    f1 = tmp_path / "future_file.txt"

    monitor = FileIntegrityMonitor(config={"fim_paths": [str(f1)]})
    monitor.build_baseline()
    assert monitor.get_status()["missing_count"] == 1

    # Create the file
    f1.write_text("created now")

    events = monitor.verify_integrity()
    assert len(events) == 1
    assert events[0].detection_type == FILE_CREATED
    assert events[0].severity == "MEDIUM"


def test_fim_detect_file_replaced_inode(tmp_path):
    """Verify FILE_REPLACED is emitted when file identity (inode) changes while path remains."""
    f1 = tmp_path / "replaced.txt"
    f1.write_text("file version 1")

    monitor = FileIntegrityMonitor(config={"fim_paths": [str(f1)]})
    monitor.build_baseline()

    # Simulate atomic file replacement (write to temp then rename over target)
    temp_new = tmp_path / "replaced.tmp"
    temp_new.write_text("file version 2 atomically swapped")
    os.replace(str(temp_new), str(f1))

    events = monitor.verify_integrity()
    assert len(events) == 1
    assert events[0].detection_type == FILE_REPLACED
    assert events[0].severity == "HIGH"
    assert events[0].evidence["previous_inode"] != events[0].evidence["current_inode"]


def test_fim_detect_metadata_change(tmp_path):
    """Verify FILE_METADATA_CHANGED is emitted when mode changes without content hash change."""
    f1 = tmp_path / "perm_test.txt"
    f1.write_text("stable content")
    os.chmod(str(f1), 0o644)

    monitor = FileIntegrityMonitor(config={"fim_paths": [str(f1)]})
    monitor.build_baseline()

    # Change permission mode only
    os.chmod(str(f1), 0o777)

    events = monitor.verify_integrity()
    assert len(events) == 1
    assert events[0].detection_type == FILE_METADATA_CHANGED
    assert events[0].severity == "LOW"
    assert events[0].evidence["previous_mode"] != events[0].evidence["current_mode"]


def test_fim_repeated_unchanged_scan_no_duplicate_alert(tmp_path):
    """Verify repeated scans with no further changes do NOT produce duplicate alerts."""
    f1 = tmp_path / "change_once.txt"
    f1.write_text("initial")

    monitor = FileIntegrityMonitor(config={"fim_paths": [str(f1)]})
    monitor.build_baseline()

    # Change once
    f1.write_text("altered")
    events1 = monitor.verify_integrity()
    assert len(events1) == 1

    # Second scan with same altered state: must NOT produce duplicate alert
    events2 = monitor.verify_integrity()
    assert len(events2) == 0

    # Third scan: still 0
    events3 = monitor.verify_integrity()
    assert len(events3) == 0


def test_fim_change_followed_by_restoration(tmp_path):
    """Verify file change followed by restoration clears change latch and alerts on new change."""
    f1 = tmp_path / "restore_test.txt"
    original_content = "original state"
    f1.write_text(original_content)

    monitor = FileIntegrityMonitor(config={"fim_paths": [str(f1)]})
    monitor.build_baseline()

    # 1. Modify
    f1.write_text("tampered state")
    ev1 = monitor.verify_integrity()
    assert len(ev1) == 1
    assert ev1[0].detection_type == FILE_MODIFIED

    # 2. Restore to original
    f1.write_text(original_content)
    ev2 = monitor.verify_integrity()
    assert len(ev2) == 0  # No alert on restoration

    # 3. Modify again: must emit fresh alert
    f1.write_text("tampered second time")
    ev3 = monitor.verify_integrity()
    assert len(ev3) == 1
    assert ev3[0].detection_type == FILE_MODIFIED


def test_fim_directory_monitoring_and_bounding(tmp_path):
    """Verify recursive directory monitoring respects file count bounds and skips special files."""
    mon_dir = tmp_path / "monitored_dir"
    mon_dir.mkdir()

    for i in range(15):
        (mon_dir / f"file_{i}.txt").write_text(f"content {i}")

    # Set max_files to 10
    monitor = FileIntegrityMonitor(config={
        "fim_paths": [str(mon_dir)],
        "fim_max_files": 10,
    })

    targets = monitor.get_monitored_files()
    assert len(targets) == 10  # Bounded to 10


def test_fim_persistence_callbacks_and_restart(tmp_path):
    """Verify baseline survives restart using persistence loader/saver hooks without overwriting."""
    f1 = tmp_path / "saved.txt"
    f1.write_text("initial saved content")

    fake_db: dict = {}

    def fake_saver(path, record):
        fake_db[path] = dict(record)

    def fake_loader():
        return dict(fake_db)

    # 1. First run creates baseline and saves to fake_db
    monitor1 = FileIntegrityMonitor(
        config={"fim_paths": [str(f1)]},
        baseline_loader=fake_loader,
        baseline_saver=fake_saver,
    )
    monitor1.initialize()
    assert str(f1) in fake_db
    orig_hash = fake_db[str(f1)]["sha256"]

    # File is modified while NetSentinel is "stopped"
    f1.write_text("tampered while offline")

    # 2. Restart NetSentinel with existing persisted baseline
    monitor2 = FileIntegrityMonitor(
        config={"fim_paths": [str(f1)]},
        baseline_loader=fake_loader,
        baseline_saver=fake_saver,
    )
    monitor2.initialize()

    # The baseline should NOT be overwritten; it must verify against the saved baseline
    assert monitor2._baseline[str(f1)]["sha256"] == orig_hash

    # Verification must detect the tampering that occurred while offline
    events = monitor2.verify_integrity()
    assert len(events) == 1
    assert events[0].detection_type == FILE_MODIFIED
    assert events[0].evidence["previous_sha256"] == orig_hash


def test_fim_rebuild_baseline(tmp_path):
    """Verify operator rebaseline updates expected hash to current state."""
    f1 = tmp_path / "rebaseline_test.txt"
    f1.write_text("version 1")

    monitor = FileIntegrityMonitor(config={"fim_paths": [str(f1)]})
    monitor.build_baseline()

    # Modify
    f1.write_text("version 2 (legitimate update)")
    ev = monitor.verify_integrity()
    assert len(ev) == 1

    # Operator explicitly rebuilds baseline
    rebuild_res = monitor.rebuild_baseline()
    assert rebuild_res["success"] is True
    assert rebuild_res["updated_count"] == 1

    # Subsequent verification should find no deviation
    ev_after = monitor.verify_integrity()
    assert len(ev_after) == 0
    assert monitor.get_status()["changed_count"] == 0
