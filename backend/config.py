"""NetSentinel Configuration Module.

Centralizes backend settings, environment configurations, SQLite database URLs,
and reserved configuration placeholders for future intrusion detection rules and ML models.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

class Config:
    """Base Configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "netsentinel-dev-secret-key-change-in-production")
    DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "t")
    
    # Server Binding
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))

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
