"""NetSentinel Configuration Module.

Centralizes backend settings, environment configurations, SQLite database URLs,
network interface configuration, and reserved placeholders for detection and ML.
"""

import os
from typing import Optional
import psutil

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")


def resolve_network_interface(configured_iface: Optional[str] = None) -> str:
    """Resolve configured or auto-detected active Linux network interface.

    Args:
        configured_iface: Explicit interface name or None for automatic discovery.

    Returns:
        Interface name to listen on.
    """
    if configured_iface and configured_iface.strip():
        return configured_iface.strip()

    # Automatic discovery: 1. Check default gateway route from /proc/net/route
    try:
        with open("/proc/net/route", "r") as fh:
            for line in fh:
                fields = line.strip().split()
                if len(fields) >= 2 and fields[1] == "00000000":
                    return fields[0]
    except Exception:
        pass

    # Automatic discovery: 2. Fallback to first non-loopback UP interface
    try:
        stats = psutil.net_if_stats()
        for name, stat in stats.items():
            if stat.isup and name != "lo":
                return name
    except Exception:
        pass

    # Fallback to loopback
    return "lo"


class Config:
    """Base Configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "netsentinel-dev-secret-key-change-in-production")
    DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "t")
    
    # Server Binding
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))

    # Network Packet Capture & Metrics Configuration
    # Set to specific interface (e.g. "enp0s3", "eth0", "lo") or None for auto-detection
    NETWORK_INTERFACE = os.environ.get("NETSENTINEL_INTERFACE", None)
    METRICS_EMIT_INTERVAL = float(os.environ.get("METRICS_EMIT_INTERVAL", "1.0"))

    # Database Configuration (SQLite)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'netsentinel.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Reserved Configuration: Rule-Based Detection Thresholds (Future Phase)
    DETECTOR_THRESHOLDS = {
        "port_scan_window_sec": 10,
        "port_scan_threshold": 100,
        "syn_flood_window_sec": 5,
        "syn_flood_threshold": 500,
        "null_scan_enabled": True,
        "xmas_scan_enabled": True,
    }

    # Reserved Configuration: Machine Learning & Risk Engine (Future Phase)
    RISK_ENGINE_SETTINGS = {
        "isolation_forest_contamination": 0.01,
        "high_risk_threshold": 0.75,
        "auto_block_enabled": False,
    }

    # Reserved Configuration: Firewall Settings (Future Phase)
    FIREWALL_SETTINGS = {
        "iptables_chain": "NETSENTINEL_INPUT",
        "dry_run": True,
    }
