"""NetSentinel Resource Monitor Module (Phase 15).

Captures process memory (RSS), CPU utilization, and system metrics during
synthetic benchmark execution using psutil.
"""

from dataclasses import dataclass, asdict
import os
import platform
import time
from typing import Any, Dict, List, Optional
import psutil


@dataclass
class ResourceSnapshot:
    """Point-in-time resource snapshot."""
    timestamp: float
    process_rss_mb: float
    process_vms_mb: float
    process_cpu_percent: float
    system_memory_used_mb: float
    system_memory_percent: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResourceMonitor:
    """Non-invasive resource observer for benchmarking workloads."""

    def __init__(self):
        self.proc = psutil.Process(os.getpid())
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._initial_snapshot: Optional[ResourceSnapshot] = None
        self._final_snapshot: Optional[ResourceSnapshot] = None
        self._peak_rss_mb: float = 0.0

    def start(self) -> ResourceSnapshot:
        """Initialize observation baseline."""
        # Prime CPU calculation
        self.proc.cpu_percent(interval=None)
        self._start_time = time.perf_counter()
        mem = self.proc.memory_info()
        sys_mem = psutil.virtual_memory()

        snap = ResourceSnapshot(
            timestamp=self._start_time,
            process_rss_mb=round(mem.rss / (1024 * 1024), 2),
            process_vms_mb=round(mem.vms / (1024 * 1024), 2),
            process_cpu_percent=0.0,
            system_memory_used_mb=round(sys_mem.used / (1024 * 1024), 2),
            system_memory_percent=round(sys_mem.percent, 2),
        )
        self._initial_snapshot = snap
        self._peak_rss_mb = snap.process_rss_mb
        return snap

    def sample(self) -> ResourceSnapshot:
        """Take an intermediate observation and update peak metrics."""
        now = time.perf_counter()
        mem = self.proc.memory_info()
        sys_mem = psutil.virtual_memory()
        cpu = self.proc.cpu_percent(interval=None)

        rss_mb = round(mem.rss / (1024 * 1024), 2)
        if rss_mb > self._peak_rss_mb:
            self._peak_rss_mb = rss_mb

        return ResourceSnapshot(
            timestamp=now,
            process_rss_mb=rss_mb,
            process_vms_mb=round(mem.vms / (1024 * 1024), 2),
            process_cpu_percent=round(cpu, 2),
            system_memory_used_mb=round(sys_mem.used / (1024 * 1024), 2),
            system_memory_percent=round(sys_mem.percent, 2),
        )

    def stop(self) -> Dict[str, Any]:
        """Finalize benchmark observation and return summary."""
        self._end_time = time.perf_counter()
        final_snap = self.sample()
        self._final_snapshot = final_snap

        elapsed = (self._end_time - (self._start_time or self._end_time))
        initial_rss = self._initial_snapshot.process_rss_mb if self._initial_snapshot else final_snap.process_rss_mb
        peak_rss = max(self._peak_rss_mb, final_snap.process_rss_mb)
        delta_rss = round(peak_rss - initial_rss, 2)

        return {
            "elapsed_wall_clock_sec": round(elapsed, 4),
            "baseline_rss_mb": initial_rss,
            "peak_rss_mb": peak_rss,
            "process_memory_growth_mb": delta_rss,
            "final_cpu_percent": final_snap.process_cpu_percent,
            "platform": {
                "os": platform.system(),
                "release": platform.release(),
                "python_version": platform.python_version(),
                "cpu_cores": psutil.cpu_count(logical=True),
                "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            },
            "disclaimer": "Synthetic benchmark measurements in the evaluation environment.",
        }
