"""Unit tests for SSHLogReader and SSHDetector (Phase 7 HIDS)."""

import os
import tempfile
import time
import pytest
from backend.host.log_reader import SSHLogReader
from backend.host.ssh_detector import SSHDetector
from backend.detector import SecurityEvent


def test_ssh_log_reader_not_found():
    """Verify SSHLogReader gracefully handles non-existent paths."""
    reader = SSHLogReader(configured_path="/non/existent/path/auth.log")
    lines = reader.read_new_lines()
    assert lines == []
    assert reader.status == "NOT_FOUND"


def test_ssh_log_reader_reads_new_lines_incrementally():
    """Verify SSHLogReader reads newly appended lines without re-reading old lines."""
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write("line 1: initial line\nline 2: initial line\n")
        tf.flush()
        temp_path = tf.name

    try:
        reader = SSHLogReader(configured_path=temp_path)
        # First read starts at end of file (or beginning if from_start=True)
        # By default start_at_end=True, so existing lines are skipped
        initial_lines = reader.read_new_lines()
        assert initial_lines == []
        assert reader.status == "RUNNING"

        # Append new lines
        with open(temp_path, "a") as f:
            f.write("line 3: Failed password for root from 192.168.1.50 port 22 ssh2\n")
            f.write("line 4: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2\n")

        new_lines = reader.read_new_lines()
        assert len(new_lines) == 2
        assert "192.168.1.50" in new_lines[0]
        assert "admin" in new_lines[1]

        # No more lines
        empty_lines = reader.read_new_lines()
        assert empty_lines == []
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_ssh_log_reader_handles_truncation():
    """Verify SSHLogReader detects truncation (file size shrinking) and resets offset."""
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write("A" * 500 + "\n")
        tf.flush()
        temp_path = tf.name

    try:
        reader = SSHLogReader(configured_path=temp_path)
        reader.read_new_lines()
        assert reader.offset > 0

        # Truncate file to smaller size
        with open(temp_path, "w") as f:
            f.write("new line after truncation\n")

        lines = reader.read_new_lines()
        assert len(lines) == 1
        assert "new line after truncation" in lines[0]
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_ssh_detector_parses_failed_password():
    """Verify SSHDetector parses standard OpenSSH failed password lines."""
    detector = SSHDetector(threshold=5, window_seconds=60, alert_cooldown=60)
    
    line = "Oct 05 12:00:00 debian sshd[12345]: Failed password for root from 192.168.1.100 port 54321 ssh2"
    event = detector.parse_line(line)
    
    assert event is not None
    assert event["source_ip"] == "192.168.1.100"
    assert event["username"] == "root"
    assert event["port"] == 54321
    assert event["is_invalid_user"] is False


def test_ssh_detector_parses_invalid_user():
    """Verify SSHDetector parses failed password for invalid/non-existent user."""
    detector = SSHDetector()
    line = "Oct 05 12:00:01 debian sshd[12346]: Failed password for invalid user oracle from 10.0.0.5 port 43210 ssh2"
    event = detector.parse_line(line)
    
    assert event is not None
    assert event["source_ip"] == "10.0.0.5"
    assert event["username"] == "oracle"
    assert event["is_invalid_user"] is True


def test_ssh_detector_rejects_bogus_ip():
    """Verify SSHDetector validates IPs and ignores invalid strings."""
    detector = SSHDetector()
    line = "Oct 05 12:00:02 debian sshd[12347]: Failed password for root from 999.999.999.999 port 22 ssh2"
    event = detector.parse_line(line)
    assert event is None


def test_ssh_detector_emits_auth_failure_and_brute_force():
    """Verify single failure produces SSH_AUTH_FAILURE, and threshold breaches trigger SSH_BRUTE_FORCE."""
    captured_events = []

    def on_event(ev):
        captured_events.append(ev)

    detector = SSHDetector(
        threshold=3,
        window_seconds=10,
        alert_cooldown=30,
        on_event=on_event,
    )

    # 1st failure
    line1 = "Oct 05 12:00:01 debian sshd[100]: Failed password for user1 from 192.168.1.200 port 1000 ssh2"
    events1 = detector.process_line(line1)
    assert len(events1) == 1
    assert events1[0].detection_type == "SSH_AUTH_FAILURE"
    assert events1[0].severity == "LOW"
    assert events1[0].source_ip == "192.168.1.200"

    # 2nd failure
    line2 = "Oct 05 12:00:02 debian sshd[101]: Failed password for user2 from 192.168.1.200 port 1001 ssh2"
    events2 = detector.process_line(line2)
    assert len(events2) == 1
    assert events2[0].detection_type == "SSH_AUTH_FAILURE"

    # 3rd failure -> reaches threshold 3 -> emits SSH_AUTH_FAILURE AND SSH_BRUTE_FORCE
    line3 = "Oct 05 12:00:03 debian sshd[102]: Failed password for user3 from 192.168.1.200 port 1002 ssh2"
    events3 = detector.process_line(line3)
    assert len(events3) == 2
    types = [e.detection_type for e in events3]
    assert "SSH_AUTH_FAILURE" in types
    assert "SSH_BRUTE_FORCE" in types

    bf_event = next(e for e in events3 if e.detection_type == "SSH_BRUTE_FORCE")
    assert bf_event.severity == "HIGH"
    assert bf_event.source_ip == "192.168.1.200"
    assert "3 failures" in bf_event.description

    # 4th failure within cooldown -> only SSH_AUTH_FAILURE, no duplicate SSH_BRUTE_FORCE
    line4 = "Oct 05 12:00:04 debian sshd[103]: Failed password for user4 from 192.168.1.200 port 1003 ssh2"
    events4 = detector.process_line(line4)
    assert len(events4) == 1
    assert events4[0].detection_type == "SSH_AUTH_FAILURE"


def test_ssh_detector_window_expiration():
    """Verify failures outside the sliding window are pruned and do not trigger brute-force."""
    detector = SSHDetector(threshold=3, window_seconds=1, alert_cooldown=30)

    # 2 failures at t=0
    detector.process_line("Failed password for u1 from 192.168.1.201 port 1000 ssh2")
    detector.process_line("Failed password for u2 from 192.168.1.201 port 1001 ssh2")
    assert len(detector._failed_attempts["192.168.1.201"]) == 2

    # Wait for window to expire
    time.sleep(1.2)

    # 1 failure at t=1.2 -> previous 2 expired, so count becomes 1, not 3
    evs = detector.process_line("Failed password for u3 from 192.168.1.201 port 1002 ssh2")
    assert len(evs) == 1
    assert evs[0].detection_type == "SSH_AUTH_FAILURE"
    assert len(detector._failed_attempts["192.168.1.201"]) == 1
