"""NetSentinel System Telemetry Module.

Collects real host system resource statistics (CPU utilization, RAM memory,
disk usage, OS load averages, and host-level network I/O rates) via psutil.
Provides background sampling, rate computation, Socket.IO streaming,
periodic database persistence, and automated retention pruning.
"""

import logging
import os
import threading
import time
from typing import Any, Dict, Optional
import uuid

import psutil

from database import cleanup_old_records, save_host_telemetry_record

logger = logging.getLogger("netsentinel.telemetry")


class TelemetryWorker:
    """Background sampling worker for host resource metrics."""

    def __init__(
        self,
        app=None,
        socketio=None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.app = app
        self.socketio = socketio
        cfg = config or {}

        self.interval = float(cfg.get("interval", 5.0))
        self.persist_interval = float(cfg.get("persist_interval", 15.0))
        self.retention_days = int(cfg.get("retention_days", 7))
        self.prune_interval = float(cfg.get("prune_interval", 3600.0))

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Prime psutil CPU utilization baseline so first sample is not 0.0
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

        # Prime initial network counters and monotonic time for accurate deltas
        self._last_time = time.monotonic()
        try:
            self._prev_net_io = psutil.net_io_counters()
        except Exception:
            self._prev_net_io = None

        self._last_persist_time = 0.0
        self._last_prune_time = time.time()

        # Initial sample snapshot
        self._current_telemetry: Dict[str, Any] = self._sample_metrics()

    def _sample_metrics(self) -> Dict[str, Any]:
        """Perform a single host metrics collection and compute delta rates."""
        now_mono = time.monotonic()
        now_wall = time.time()
        dt = now_mono - self._last_time
        if dt <= 0:
            dt = 1e-6

        # 1. CPU Utilization (%)
        try:
            cpu_pct = float(psutil.cpu_percent(interval=None))
        except Exception as ex:
            logger.debug("CPU percent reading failed: %s", ex)
            cpu_pct = 0.0

        # 2. Virtual Memory
        try:
            mem = psutil.virtual_memory()
            mem_pct = float(mem.percent)
            mem_used = int(mem.used)
            mem_avail = int(mem.available)
        except Exception as ex:
            logger.debug("Memory reading failed: %s", ex)
            mem_pct, mem_used, mem_avail = 0.0, 0, 0

        # 3. Disk Usage
        try:
            # Measure root filesystem mount point
            disk = psutil.disk_usage(os.path.abspath(os.sep))
            disk_pct = float(disk.percent)
            disk_used = int(disk.used)
            disk_free = int(disk.free)
        except Exception as ex:
            logger.debug("Disk reading failed: %s", ex)
            disk_pct, disk_used, disk_free = 0.0, 0, 0

        # 4. OS System Load Averages (1, 5, 15 min)
        load_1, load_5, load_15 = 0.0, 0.0, 0.0
        try:
            if hasattr(os, "getloadavg"):
                l1, l5, l15 = os.getloadavg()
                load_1, load_5, load_15 = float(l1), float(l5), float(l15)
        except Exception as ex:
            logger.debug("Load average reading failed: %s", ex)

        # 5. Host Network I/O Counters & Rate Derivation
        tx_bps, rx_bps, tx_pps, rx_pps = 0.0, 0.0, 0.0, 0.0
        net_bytes_sent, net_bytes_recv = 0, 0
        net_pkts_sent, net_pkts_recv = 0, 0

        try:
            curr_net = psutil.net_io_counters()
            if curr_net:
                net_bytes_sent = int(curr_net.bytes_sent)
                net_bytes_recv = int(curr_net.bytes_recv)
                net_pkts_sent = int(curr_net.packets_sent)
                net_pkts_recv = int(curr_net.packets_recv)

                if self._prev_net_io is not None and dt > 0.05:
                    delta_tx_bytes = max(0, curr_net.bytes_sent - self._prev_net_io.bytes_sent)
                    delta_rx_bytes = max(0, curr_net.bytes_recv - self._prev_net_io.bytes_recv)
                    delta_tx_pkts = max(0, curr_net.packets_sent - self._prev_net_io.packets_sent)
                    delta_rx_pkts = max(0, curr_net.packets_recv - self._prev_net_io.packets_recv)

                    tx_bps = round(delta_tx_bytes / dt, 2)
                    rx_bps = round(delta_rx_bytes / dt, 2)
                    tx_pps = round(delta_tx_pkts / dt, 2)
                    rx_pps = round(delta_rx_pkts / dt, 2)

                self._prev_net_io = curr_net
        except Exception as ex:
            logger.debug("Network counters reading failed: %s", ex)

        self._last_time = now_mono

        return {
            "telemetry_id": str(uuid.uuid4()),
            "timestamp": now_wall,
            "cpu_percent": round(cpu_pct, 2),
            "memory_percent": round(mem_pct, 2),
            "memory_used_bytes": mem_used,
            "memory_available_bytes": mem_avail,
            "disk_percent": round(disk_pct, 2),
            "disk_used_bytes": disk_used,
            "disk_free_bytes": disk_free,
            "load_1": round(load_1, 2),
            "load_5": round(load_5, 2),
            "load_15": round(load_15, 2),
            "network_bytes_sent": net_bytes_sent,
            "network_bytes_recv": net_bytes_recv,
            "network_packets_sent": net_pkts_sent,
            "network_packets_recv": net_pkts_recv,
            "host_tx_bps": tx_bps,
            "host_rx_bps": rx_bps,
            "host_tx_pps": tx_pps,
            "host_rx_pps": rx_pps,
        }

    def sample_now(self) -> Dict[str, Any]:
        """Trigger an immediate sample and return the updated snapshot."""
        sample = self._sample_metrics()
        with self._lock:
            self._current_telemetry = sample
        return sample

    def get_current_telemetry(self) -> Dict[str, Any]:
        """Return the most recently collected host telemetry snapshot."""
        with self._lock:
            return dict(self._current_telemetry)

    def start(self) -> bool:
        """Start the background sampling thread."""
        if self._thread and self._thread.is_alive():
            return True

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="NetSentinel-HostTelemetry", daemon=True
        )
        self._thread.start()
        logger.info("Host telemetry worker thread started (interval=%.1fs, persist=%.1fs)", self.interval, self.persist_interval)
        return True

    def stop(self) -> None:
        """Stop the background sampling thread gracefully."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        logger.info("Host telemetry worker thread stopped.")

    def _run_loop(self) -> None:
        """Main loop: periodically sample, emit over Socket.IO, persist, and prune."""
        while not self._stop_event.is_set():
            # Wait for interval or stop event
            if self._stop_event.wait(self.interval):
                break

            try:
                sample = self._sample_metrics()
                with self._lock:
                    self._current_telemetry = sample

                # Emit real-time telemetry over Socket.IO
                if self.socketio:
                    try:
                        self.socketio.emit("host_telemetry", sample)
                    except Exception as emit_err:
                        logger.debug("Socket.IO host telemetry emit failed: %s", emit_err)

                # Periodic Persistence
                now_wall = time.time()
                if (now_wall - self._last_persist_time) >= self.persist_interval:
                    self._last_persist_time = now_wall
                    if self.app:
                        try:
                            with self.app.app_context():
                                save_host_telemetry_record(sample)
                        except Exception as persist_err:
                            logger.debug("Telemetry persistence error: %s", persist_err)

                # Periodic Retention Pruning
                if (now_wall - self._last_prune_time) >= self.prune_interval:
                    self._last_prune_time = now_wall
                    if self.app:
                        try:
                            with self.app.app_context():
                                cleanup_old_records(self.retention_days)
                        except Exception as prune_err:
                            logger.debug("Retention cleanup error: %s", prune_err)

            except Exception as ex:
                logger.error("Error in telemetry worker loop: %s", ex)


def get_system_metrics() -> Dict[str, Any]:
    """Retrieve instantaneous host system resource statistics.

    Maintained for backward compatibility.
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        net_io = psutil.net_io_counters()

        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "bytes_sent": net_io.bytes_sent if net_io else 0,
            "bytes_recv": net_io.bytes_recv if net_io else 0,
        }
    except Exception as err:
        return {
            "error": f"Telemetry collection failed: {str(err)}",
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "bytes_sent": 0,
            "bytes_recv": 0,
        }
