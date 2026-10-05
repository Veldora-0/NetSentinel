"""NetSentinel Host Process Activity Monitor Module.

Implements lightweight, non-invasive process monitoring using psutil.
Establishes a running-process baseline on startup and checks for conservative
suspicious signals (e.g. execution from temporary directories or unlinked binaries).
Never terminates or modifies processes.
"""

import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

import psutil

from detector import SecurityEvent

logger = logging.getLogger("netsentinel.host.process_monitor")

# Conservative directories where binary execution is commonly irregular
SUSPICIOUS_EXEC_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


class ProcessMonitor:
    """Lightweight host process behavioral observer."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        scan_interval: Optional[float] = None,
        alert_cooldown: Optional[float] = None,
        on_event: Optional[Callable[[SecurityEvent], None]] = None,
    ):
        cfg = config or {}
        self.enabled = bool(cfg.get("process_monitor_enabled", True))
        self.interval_seconds = float(scan_interval if scan_interval is not None else cfg.get("process_interval_sec", 10.0))
        self.alert_cooldown_sec = float(alert_cooldown if alert_cooldown is not None else cfg.get("process_alert_cooldown_sec", 60.0))
        self._on_event = on_event

        self.baseline_ready: bool = False
        # Known processes: pid -> create_time
        self._known_processes: Dict[int, float] = {}
        # Alert cooldown tracking: (pid, exe) -> last_alert_time
        self._alert_cooldowns: Dict[str, float] = {}

        self.total_scans_performed: int = 0
        self.total_suspicious_events: int = 0
        self.last_scan_time: float = 0.0

        if self.enabled:
            self._init_baseline()

    @property
    def baseline_pids(self) -> Set[int]:
        """Set of process IDs in the baseline snapshot."""
        return set(self._known_processes.keys())

    @baseline_pids.setter
    def baseline_pids(self, pids: Set[int]) -> None:
        self._known_processes = {pid: 0.0 for pid in pids}

    @property
    def baseline_pids_count(self) -> int:
        """Count of process IDs in the baseline snapshot."""
        return len(self._known_processes)

    @property
    def total_scans(self) -> int:
        """Total process scans executed."""
        return self.total_scans_performed

    @property
    def total_suspicious_detected(self) -> int:
        """Total suspicious processes detected."""
        return self.total_suspicious_events

    @property
    def status(self) -> str:
        """Status string of the process monitor."""
        if not self.enabled:
            return "DISABLED"
        if not self.baseline_ready:
            return "INITIALIZED"
        return "RUNNING"

    def scan_once(self, now: Optional[float] = None) -> List[SecurityEvent]:
        """Perform a single scan pass, dispatch events, and return detected events."""
        events = self.scan_processes(now=now)
        if self._on_event:
            for ev in events:
                try:
                    self._on_event(ev)
                except Exception as ex:
                    logger.debug("Error in ProcessMonitor on_event callback: %s", ex)
        return events

    def _init_baseline(self) -> None:
        """Establish baseline snapshot of currently running processes."""
        try:
            count = 0
            for proc in psutil.process_iter(["pid", "create_time"]):
                try:
                    pid = proc.info["pid"]
                    ctime = proc.info["create_time"] or 0.0
                    self._known_processes[pid] = ctime
                    count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            self.baseline_ready = True
            logger.info("Host process baseline established with %d existing processes", count)
        except Exception as ex:
            logger.debug("Failed to establish complete process baseline: %s", ex)
            self.baseline_ready = True

    def scan_processes(self, now: Optional[float] = None) -> List[SecurityEvent]:
        """Enumerate active processes, identify newly launched ones, and evaluate suspicious signals.

        Returns:
            List of generated SecurityEvent instances.
        """
        if not self.enabled:
            return []

        curr_time = now if now is not None else time.time()
        self.last_scan_time = curr_time
        self.total_scans_performed += 1

        events: List[SecurityEvent] = []
        current_pids: Set[int] = set()

        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time", "cpu_percent", "memory_percent"]):
                try:
                    info = proc.info
                    pid = info.get("pid")
                    if not pid or pid == 0:
                        continue

                    current_pids.add(pid)
                    create_time = info.get("create_time") or 0.0

                    # Check if this process was already seen in baseline or previous scan
                    if pid in self._known_processes and abs(self._known_processes[pid] - create_time) < 1.0:
                        continue

                    # Process is newly observed
                    self._known_processes[pid] = create_time

                    # Check conservative suspicious execution indicators
                    suspicious_reason = self._evaluate_suspicious(proc, info)
                    if suspicious_reason:
                        event = self._generate_event(proc, info, suspicious_reason, curr_time)
                        if event:
                            events.append(event)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as ex:
                    logger.debug("Unexpected error evaluating process %s: %s", getattr(proc, "pid", "unknown"), ex)
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        # Prune terminated PIDs from tracking dictionary
        terminated = [p for p in self._known_processes if p not in current_pids]
        for p in terminated:
            del self._known_processes[p]

        # Prune old alert cooldowns
        cooldown_cutoff = curr_time - (self.alert_cooldown_sec * 3)
        stale_keys = [k for k, t in self._alert_cooldowns.items() if t < cooldown_cutoff]
        for k in stale_keys:
            del self._alert_cooldowns[k]

        return events

    def _evaluate_suspicious(self, proc: psutil.Process, info: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        """Check process attributes against explainable suspicious signals."""
        exe = info.get("exe") or ""
        name = info.get("name") or ""

        # Signal 1: Executable running from temporary writable directories
        if exe:
            for prefix in SUSPICIOUS_EXEC_PREFIXES:
                if exe.startswith(prefix):
                    return ("suspicious_path", f"Suspicious execution path in temporary directory: {prefix}")

        # Signal 2: Executable path marked deleted/unlinked while process runs
        if exe and (" (deleted)" in exe or "(deleted)" in exe):
            return ("deleted_binary", "Process running from deleted/unlinked binary")

        # Signal 3: Executable path exists as string but unlinked from filesystem
        if exe and not exe.startswith("/proc") and not os.path.exists(exe):
            return ("missing_binary", f"Process executable path '{exe}' does not exist on disk")

        return None

    def _generate_event(
        self, proc: psutil.Process, info: Dict[str, Any], reason_info: Any, now: float
    ) -> Optional[SecurityEvent]:
        """Generate structured SUSPICIOUS_PROCESS SecurityEvent respecting alert cooldown."""
        if isinstance(reason_info, tuple):
            reason_code, reason_desc = reason_info
        else:
            reason_code = "suspicious_path" if "temporary" in str(reason_info) else "deleted_binary"
            reason_desc = str(reason_info)

        pid = info.get("pid")
        name = info.get("name") or "unknown"
        exe = info.get("exe") or ""
        user = info.get("username") or "unknown"

        # Cooldown key per executable & process name
        cooldown_key = f"{name}:{exe}"
        last_alert = self._alert_cooldowns.get(cooldown_key, 0.0)
        if (now - last_alert) < self.alert_cooldown_sec:
            return None

        self._alert_cooldowns[cooldown_key] = now
        self.total_suspicious_events += 1

        cpu_pct = 0.0
        mem_pct = 0.0
        try:
            cpu_pct = round(float(info.get("cpu_percent") or 0.0), 1)
            mem_pct = round(float(info.get("memory_percent") or 0.0), 1)
        except Exception:
            pass

        return SecurityEvent(
            event_id=uuid.uuid4().hex[:12],
            timestamp=now,
            detection_type="SUSPICIOUS_PROCESS",
            severity="MEDIUM",
            source_ip=None,
            destination_ip=None,
            protocol=None,
            source_port=None,
            destination_port=None,
            description=f"Suspicious host process detected: {name} (PID {pid}) - {reason_desc}",
            evidence={
                "pid": pid,
                "process_name": name,
                "executable_path": exe,
                "username": user,
                "reason": reason_code,
                "reason_description": reason_desc,
                "cpu_percent": cpu_pct,
                "memory_percent": mem_pct,
            },
            rule_name="RULE_SUSPICIOUS_PROCESS",
        )

    def get_status(self) -> Dict[str, Any]:
        """Return operational status summary of process monitor."""
        return {
            "status": self.status,
            "enabled": self.enabled,
            "interval_seconds": self.interval_seconds,
            "baseline_ready": self.baseline_ready,
            "baseline_pids_count": len(self._known_processes),
            "tracked_processes": len(self._known_processes),
            "total_scans": self.total_scans_performed,
            "total_scans_performed": self.total_scans_performed,
            "suspicious_processes_detected": self.total_suspicious_events,
            "total_suspicious_events": self.total_suspicious_events,
            "last_scan_time": self.last_scan_time,
        }
