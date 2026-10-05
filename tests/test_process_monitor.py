"""Unit tests for ProcessMonitor (Phase 7 HIDS)."""

import os
import psutil
import pytest
from unittest.mock import MagicMock, patch
from backend.host.process_monitor import ProcessMonitor
from backend.detector import SecurityEvent


def test_process_monitor_initial_baseline():
    """Verify ProcessMonitor establishes baseline of existing PIDs on initialization."""
    monitor = ProcessMonitor(scan_interval=60)
    assert len(monitor.baseline_pids) > 0
    assert os.getpid() in monitor.baseline_pids
    assert monitor.status in ("INITIALIZED", "RUNNING")


def test_process_monitor_normal_process_no_alert():
    """Verify normal running processes do not produce suspicious alerts."""
    events = []
    monitor = ProcessMonitor(scan_interval=60, on_event=lambda e: events.append(e))
    # Reset baseline to empty to force checking current process
    monitor.baseline_pids = set()

    # Scan processes
    detected = monitor.scan_once()
    # The running python / pytest process should NOT be considered suspicious
    # (unless running out of /tmp, which is not the case here)
    curr_events = [e for e in detected if e.metadata.get("pid") == os.getpid()]
    assert len(curr_events) == 0


def test_process_monitor_detects_suspicious_path():
    """Verify ProcessMonitor alerts when a process binary resides in /tmp or /dev/shm."""
    events = []
    monitor = ProcessMonitor(scan_interval=60, on_event=lambda e: events.append(e))
    monitor.baseline_pids = set()

    # Mock a mock process running from /tmp
    mock_proc = MagicMock()
    mock_proc.pid = 99999
    mock_proc.info = {
        "pid": 99999,
        "name": "malicious_script.sh",
        "exe": "/tmp/malicious_script.sh",
        "cmdline": ["/tmp/malicious_script.sh", "--run"],
        "username": "debian",
        "create_time": 1700000000.0,
    }

    with patch("psutil.process_iter", return_value=[mock_proc]):
        detected = monitor.scan_once()

    assert len(detected) == 1
    ev = detected[0]
    assert ev.detection_type == "SUSPICIOUS_PROCESS"
    assert ev.severity == "MEDIUM"
    assert ev.metadata["pid"] == 99999
    assert "Suspicious execution path" in ev.description
    assert ev.metadata["reason"] == "suspicious_path"
    assert ev.source_ip is None or ev.source_ip == "127.0.0.1"


def test_process_monitor_detects_deleted_binary():
    """Verify ProcessMonitor alerts when an executable binary was unlinked/deleted from disk."""
    monitor = ProcessMonitor(scan_interval=60)
    monitor.baseline_pids = set()

    mock_proc = MagicMock()
    mock_proc.pid = 88888
    mock_proc.info = {
        "pid": 88888,
        "name": "hidden_daemon",
        "exe": "/usr/local/bin/hidden_daemon (deleted)",
        "cmdline": ["hidden_daemon"],
        "username": "root",
        "create_time": 1700000000.0,
    }

    with patch("psutil.process_iter", return_value=[mock_proc]):
        detected = monitor.scan_once()

    assert len(detected) == 1
    ev = detected[0]
    assert ev.detection_type == "SUSPICIOUS_PROCESS"
    assert "deleted/unlinked binary" in ev.description
    assert ev.metadata["reason"] == "deleted_binary"


def test_process_monitor_handles_process_exceptions():
    """Verify NoSuchProcess, AccessDenied, and ZombieProcess exceptions are handled cleanly."""
    monitor = ProcessMonitor(scan_interval=60)
    monitor.baseline_pids = set()

    # Create generator that raises psutil exceptions
    def error_gen(*args, **kwargs):
        yield MagicMock(info={"pid": 11111, "name": "normal", "exe": "/bin/bash", "cmdline": []})
        raise psutil.NoSuchProcess(pid=22222)

    with patch("psutil.process_iter", side_effect=error_gen):
        detected = monitor.scan_once()
        # Should not crash
        assert isinstance(detected, list)


def test_process_monitor_status():
    """Verify get_status() returns required health and monitoring metrics."""
    monitor = ProcessMonitor(scan_interval=60)
    status = monitor.get_status()
    assert "status" in status
    assert "baseline_pids_count" in status
    assert "total_scans" in status
    assert "suspicious_processes_detected" in status
