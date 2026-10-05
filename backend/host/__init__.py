"""NetSentinel Host-Based Intrusion Detection System (HIDS) Package.

Provides SSH authentication failure and brute-force detection, process execution
monitoring, and coordinator management.
"""

from host.log_reader import SSHLogReader
from host.ssh_detector import SSHDetector
from host.process_monitor import ProcessMonitor
from host.file_integrity import FileIntegrityMonitor
from host.manager import HostDetectionManager

__all__ = [
    "SSHLogReader",
    "SSHDetector",
    "ProcessMonitor",
    "FileIntegrityMonitor",
    "HostDetectionManager",
]

