"""NetSentinel Host Detection Manager Module.

Coordinates the SSH authentication failure detector and process observer,
runs an asynchronous polling worker, and dispatches structured SecurityEvents
to the central NetSentinel application pipeline.
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from detector import SecurityEvent
from host.ssh_detector import SSHDetector
from host.process_monitor import ProcessMonitor
from host.file_integrity import FileIntegrityMonitor

logger = logging.getLogger("netsentinel.host.manager")


class HostDetectionManager:
    """Coordinator and lifecycle manager for all host-based intrusion detectors."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = bool(self.config.get("host_enabled", True))
        self.ssh_detector = SSHDetector(config=self.config)
        self.process_monitor = ProcessMonitor(config=self.config)
        self.file_integrity = FileIntegrityMonitor(config=self.config)

        self._callbacks: List[Callable[[SecurityEvent], None]] = []
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_process_scan: float = 0.0
        self._last_fim_scan: float = 0.0


    def add_event_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for host-generated SecurityEvents."""
        self._callbacks.append(callback)

    def _dispatch_event(self, event: SecurityEvent) -> None:
        """Dispatch a generated SecurityEvent to all registered callbacks."""
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as ex:
                logger.debug("Error in host event callback: %s", ex)

    def start(self) -> bool:
        """Start the background host detection worker thread."""
        if self._thread and self._thread.is_alive():
            return True

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="NetSentinel-HostDetector", daemon=True
        )
        self._thread.start()
        logger.info("HostDetectionManager background worker started")
        return True

    def stop(self) -> None:
        """Stop the background host detection worker thread gracefully."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        logger.info("HostDetectionManager background worker stopped")

    def _run_loop(self) -> None:
        """Main periodic loop for checking SSH logs and scanning processes."""
        while not self._stop_event.is_set():
            now = time.time()

            # 1. Check SSH authentication logs
            try:
                ssh_events = self.ssh_detector.check_new_logs(now=now)
                for ev in ssh_events:
                    self._dispatch_event(ev)
            except Exception as ex:
                logger.debug("Error checking SSH logs: %s", ex)

            # 2. Check process monitor at configured interval
            if (now - self._last_process_scan) >= self.process_monitor.interval_seconds:
                self._last_process_scan = now
                try:
                    proc_events = self.process_monitor.scan_processes(now=now)
                    for ev in proc_events:
                        self._dispatch_event(ev)
                except Exception as ex:
                    logger.debug("Error checking processes: %s", ex)

            # 3. Check file integrity at configured interval
            if (now - self._last_fim_scan) >= self.file_integrity.interval_seconds:
                self._last_fim_scan = now
                try:
                    fim_events = self.file_integrity.verify_integrity(now=now)
                    for ev in fim_events:
                        self._dispatch_event(ev)
                except Exception as ex:
                    logger.debug("Error checking file integrity: %s", ex)

            # Sleep briefly or exit if signaled
            if self._stop_event.wait(1.5):
                break

    def get_status(self) -> Dict[str, Any]:
        """Return combined status of all host detection components."""
        return {
            "enabled": self.enabled,
            "ssh_detector": self.ssh_detector.get_status(),
            "process_monitor": self.process_monitor.get_status(),
            "file_integrity": self.file_integrity.get_status(),
        }

