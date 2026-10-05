"""Unit tests for NetSentinel Host Telemetry Sampling, Delta Rates, and Worker Lifecycle."""

import os
import sys
import time
from unittest.mock import MagicMock, patch
from collections import namedtuple
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from telemetry import TelemetryWorker, get_system_metrics


def test_telemetry_worker_initialization():
    """Test TelemetryWorker correctly primes baseline and creates initial snapshot."""
    worker = TelemetryWorker(config={"interval": 2.0, "persist_interval": 5.0})
    snapshot = worker.get_current_telemetry()

    assert snapshot is not None
    assert "cpu_percent" in snapshot
    assert "memory_percent" in snapshot
    assert "disk_percent" in snapshot
    assert "load_1" in snapshot
    assert "host_tx_bps" in snapshot
    assert "host_rx_bps" in snapshot
    assert "host_tx_pps" in snapshot
    assert "host_rx_pps" in snapshot

    # Values must be within plausible physical bounds
    assert 0.0 <= snapshot["cpu_percent"] <= 100.0
    assert 0.0 <= snapshot["memory_percent"] <= 100.0
    assert 0.0 <= snapshot["disk_percent"] <= 100.0


def test_telemetry_rate_delta_calculation():
    """Test host network rate calculations using delta differences over time."""
    worker = TelemetryWorker()

    NetCounters = namedtuple("NetCounters", ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv"])

    # Simulate prev state
    worker._prev_net_io = NetCounters(bytes_sent=1000, bytes_recv=2000, packets_sent=10, packets_recv=20)
    worker._last_time = time.monotonic() - 2.0  # 2 seconds elapsed

    curr_net = NetCounters(bytes_sent=3000, bytes_recv=6000, packets_sent=30, packets_recv=60)

    with patch("psutil.net_io_counters", return_value=curr_net):
        sample = worker.sample_now()

        # Delta: sent 2000 bytes over 2s -> 1000 B/s
        # Delta: recv 4000 bytes over 2s -> 2000 B/s
        # Delta: sent 20 pkts over 2s -> 10 pps
        # Delta: recv 40 pkts over 2s -> 20 pps
        assert abs(sample["host_tx_bps"] - 1000.0) < 50.0
        assert abs(sample["host_rx_bps"] - 2000.0) < 50.0
        assert abs(sample["host_tx_pps"] - 10.0) < 1.0
        assert abs(sample["host_rx_pps"] - 20.0) < 1.0


def test_telemetry_counter_wrap_handling():
    """Test that counter wraps or interface resets (curr < prev) don't produce negative rates."""
    worker = TelemetryWorker()
    NetCounters = namedtuple("NetCounters", ["bytes_sent", "bytes_recv", "packets_sent", "packets_recv"])

    worker._prev_net_io = NetCounters(bytes_sent=100000, bytes_recv=100000, packets_sent=1000, packets_recv=1000)
    worker._last_time = time.monotonic() - 1.0

    # Current has smaller values (interface reset or wrap)
    curr_net = NetCounters(bytes_sent=50, bytes_recv=50, packets_sent=5, packets_recv=5)

    with patch("psutil.net_io_counters", return_value=curr_net):
        sample = worker.sample_now()
        assert sample["host_tx_bps"] >= 0.0
        assert sample["host_rx_bps"] >= 0.0
        assert sample["host_tx_pps"] >= 0.0
        assert sample["host_rx_pps"] >= 0.0


def test_telemetry_worker_thread_lifecycle():
    """Test starting and stopping the background sampling thread."""
    mock_socketio = MagicMock()
    worker = TelemetryWorker(
        socketio=mock_socketio,
        config={"interval": 0.1, "persist_interval": 10.0},
    )

    started = worker.start()
    assert started is True
    assert worker._thread is not None
    assert worker._thread.is_alive()

    # Wait brief moment for at least one sample iteration
    time.sleep(0.25)
    worker.stop()
    assert worker._thread is None


def test_get_system_metrics_backward_compatibility():
    """Test legacy get_system_metrics function returns required keys."""
    res = get_system_metrics()
    assert isinstance(res, dict)
    assert "cpu_percent" in res
    assert "memory_percent" in res
    assert "bytes_sent" in res
    assert "bytes_recv" in res
