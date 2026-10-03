"""NetSentinel System Telemetry Module.

Reserved for collecting host system resource statistics (CPU utilization, memory usage,
and network interface throughput statistics) via psutil.

Note: Full telemetry streaming will be implemented in a future phase.
"""

from typing import Any, Dict
import psutil


def get_system_metrics() -> Dict[str, Any]:
    """Retrieve host system resource statistics.

    Returns:
        Dictionary containing current CPU percentage, RAM memory percentage,
        and basic network I/O counters.
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
