"""NetSentinel Configuration Module.

Centralizes backend settings, environment configurations, SQLite database URLs,
network interface configuration, rule-based detection thresholds, and
unsupervised machine learning anomaly detection settings.
"""

import os
from typing import Optional
import psutil

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODELS_DIR = os.path.join(DATA_DIR, "models")


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
    NETWORK_INTERFACE = os.environ.get("NETSENTINEL_INTERFACE", None)
    METRICS_EMIT_INTERVAL = float(os.environ.get("METRICS_EMIT_INTERVAL", "1.0"))

    # Database Configuration (SQLite)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(DATA_DIR, 'netsentinel.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Rule-Based Intrusion Detection Thresholds (Phase 3)
    DETECTOR_THRESHOLDS = {
        # Port scan: min unique destination ports probed within time window
        "port_scan_window_sec": float(os.environ.get("PORT_SCAN_WINDOW_SEC", "10.0")),
        "port_scan_threshold": int(os.environ.get("PORT_SCAN_THRESHOLD", "15")),
        # SYN flood: min SYN packets from a source within time window
        "syn_flood_window_sec": float(os.environ.get("SYN_FLOOD_WINDOW_SEC", "5.0")),
        "syn_flood_threshold": int(os.environ.get("SYN_FLOOD_THRESHOLD", "50")),
        # Stealth flag scans
        "null_scan_enabled": True,
        "xmas_scan_enabled": True,
        # ICMP sweep thresholds
        "icmp_sweep_window_sec": float(os.environ.get("ICMP_SWEEP_WINDOW_SEC", "10.0")),
        "icmp_sweep_threshold": int(os.environ.get("ICMP_SWEEP_THRESHOLD", "10")),
        "icmp_sweep_cooldown_sec": float(os.environ.get("ICMP_SWEEP_COOLDOWN_SEC", "60.0")),
        # Alert de-duplication cooldown per (source_ip, rule) pair
        "alert_cooldown_sec": float(os.environ.get("ALERT_COOLDOWN_SEC", "30.0")),
        # Memory bounds
        "max_tracked_ips": int(os.environ.get("MAX_TRACKED_IPS", "1000")),
        "state_cleanup_sec": float(os.environ.get("STATE_CLEANUP_SEC", "60.0")),
        "max_alert_history": int(os.environ.get("MAX_ALERT_HISTORY", "100")),
    }

    PORT_SCAN_WINDOW_SECONDS = DETECTOR_THRESHOLDS["port_scan_window_sec"]
    PORT_SCAN_UNIQUE_PORT_THRESHOLD = DETECTOR_THRESHOLDS["port_scan_threshold"]
    SYN_FLOOD_WINDOW_SECONDS = DETECTOR_THRESHOLDS["syn_flood_window_sec"]
    SYN_FLOOD_PACKET_THRESHOLD = DETECTOR_THRESHOLDS["syn_flood_threshold"]
    ICMP_SWEEP_WINDOW_SECONDS = DETECTOR_THRESHOLDS["icmp_sweep_window_sec"]
    ICMP_SWEEP_THRESHOLD = DETECTOR_THRESHOLDS["icmp_sweep_threshold"]
    ALERT_COOLDOWN_SECONDS = DETECTOR_THRESHOLDS["alert_cooldown_sec"]
    MAX_ALERT_HISTORY = DETECTOR_THRESHOLDS["max_alert_history"]

    # Unsupervised Anomaly Detection Settings (Phase 4 - Isolation Forest)
    ML_SETTINGS = {
        "enabled": os.environ.get("ML_ENABLED", "True").lower() in ("true", "1", "t"),
        # Duration of each traffic aggregation window in seconds
        "window_seconds": float(os.environ.get("ML_WINDOW_SECONDS", "5.0")),
        # Target number of normal traffic windows required to fit the baseline model
        "baseline_windows": int(os.environ.get("ML_BASELINE_WINDOWS", "10")),
        # Isolation Forest hyperparameters
        "n_estimators": int(os.environ.get("ML_N_ESTIMATORS", "100")),
        "contamination": os.environ.get("ML_CONTAMINATION", "auto"),
        "random_state": int(os.environ.get("ML_RANDOM_STATE", "42")),
        # Anomaly alert suppression cooldown in seconds
        "alert_cooldown_seconds": float(os.environ.get("ML_ALERT_COOLDOWN_SEC", "15.0")),
        # Model persistence filesystem paths
        "model_path": os.path.join(MODELS_DIR, "isolation_forest.joblib"),
        "metadata_path": os.path.join(MODELS_DIR, "model_metadata.json"),
    }

    ML_WINDOW_SECONDS = ML_SETTINGS["window_seconds"]
    ML_BASELINE_WINDOWS = ML_SETTINGS["baseline_windows"]
    ML_N_ESTIMATORS = ML_SETTINGS["n_estimators"]
    ML_CONTAMINATION = ML_SETTINGS["contamination"]
    ML_RANDOM_STATE = ML_SETTINGS["random_state"]
    ML_ALERT_COOLDOWN_SECONDS = ML_SETTINGS["alert_cooldown_seconds"]
    ML_MODEL_PATH = ML_SETTINGS["model_path"]
    ML_METADATA_PATH = ML_SETTINGS["metadata_path"]

    # Composite Risk Engine Settings (Phase 5)
    RISK_SETTINGS = {
        "rule_weight": float(os.environ.get("RISK_RULE_WEIGHT", "0.65")),
        "ml_weight": float(os.environ.get("RISK_ML_WEIGHT", "0.35")),
        "severity_scores": {
            "LOW": 0.20,
            "MEDIUM": 0.40,
            "HIGH": 0.70,
            "CRITICAL": 0.90,
        },
        "repeat_increment": float(os.environ.get("RISK_REPEAT_INCREMENT", "0.05")),
        "max_repeat_boost": float(os.environ.get("RISK_MAX_REPEAT_BOOST", "0.20")),
        "history_window_seconds": float(os.environ.get("RISK_HISTORY_WINDOW_SEC", "60.0")),
        "auto_block_threshold": float(os.environ.get("RISK_AUTO_BLOCK_THRESHOLD", "0.80")),
        "max_tracked_ips": int(os.environ.get("RISK_MAX_TRACKED_IPS", "1000")),
        "max_assessment_history": int(os.environ.get("RISK_MAX_HISTORY", "100")),
    }

    RISK_ENGINE_SETTINGS = RISK_SETTINGS

    # Linux iptables Firewall Settings (Phase 5)
    _raw_allowlist = os.environ.get("NETSENTINEL_FIREWALL_ALLOWLIST", "127.0.0.1,::1")
    _allowlist_items = [x.strip() for x in _raw_allowlist.split(",") if x.strip()]
    if "127.0.0.1" not in _allowlist_items:
        _allowlist_items.append("127.0.0.1")
    if "::1" not in _allowlist_items:
        _allowlist_items.append("::1")

    FIREWALL_SETTINGS = {
        "enabled": os.environ.get("NETSENTINEL_FIREWALL_ENABLED", "False").lower() in ("true", "1", "t"),
        "auto_block": os.environ.get("NETSENTINEL_AUTO_BLOCK", "False").lower() in ("true", "1", "t"),
        "dry_run": os.environ.get("NETSENTINEL_FIREWALL_DRY_RUN", "True").lower() in ("true", "1", "t"),
        "chain": os.environ.get("NETSENTINEL_IPTABLES_CHAIN", "NETSENTINEL"),
        "block_duration": float(os.environ.get("NETSENTINEL_BLOCK_DURATION", "300.0")),
        "max_blocked_ips": int(os.environ.get("NETSENTINEL_MAX_BLOCKED_IPS", "500")),
        "allowlist": _allowlist_items,
    }

    # Host Telemetry & History Retention Settings (Phase 6)
    TELEMETRY_SETTINGS = {
        "interval": float(os.environ.get("NETSENTINEL_TELEMETRY_INTERVAL", "5.0")),
        "persist_interval": float(os.environ.get("NETSENTINEL_TELEMETRY_PERSIST_INTERVAL", "15.0")),
        "retention_days": int(os.environ.get("NETSENTINEL_RETENTION_DAYS", "7")),
        "prune_interval": float(os.environ.get("NETSENTINEL_PRUNE_INTERVAL", "3600.0")),
    }

    TELEMETRY_INTERVAL = TELEMETRY_SETTINGS["interval"]
    TELEMETRY_PERSIST_INTERVAL = TELEMETRY_SETTINGS["persist_interval"]
    RETENTION_DAYS = TELEMETRY_SETTINGS["retention_days"]

    # Host Intrusion Detection & Process Monitor Settings (Phase 7)
    HOST_DETECTION_SETTINGS = {
        "ssh_enabled": os.environ.get("NETSENTINEL_SSH_ENABLED", "True").lower() in ("true", "1", "t"),
        "ssh_log_path": os.environ.get("NETSENTINEL_SSH_LOG_PATH", None),
        "ssh_window_sec": float(os.environ.get("NETSENTINEL_SSH_WINDOW", "60.0")),
        "ssh_failure_threshold": int(os.environ.get("NETSENTINEL_SSH_FAILURE_THRESHOLD", "5")),
        "ssh_alert_cooldown_sec": float(os.environ.get("NETSENTINEL_SSH_ALERT_COOLDOWN", "60.0")),
        "ssh_max_tracked_ips": int(os.environ.get("NETSENTINEL_SSH_MAX_TRACKED_IPS", "1000")),
        "process_monitor_enabled": os.environ.get("NETSENTINEL_PROCESS_MONITOR_ENABLED", "True").lower() in ("true", "1", "t"),
        "process_interval_sec": float(os.environ.get("NETSENTINEL_PROCESS_INTERVAL", "10.0")),
        "process_alert_cooldown_sec": float(os.environ.get("NETSENTINEL_PROCESS_ALERT_COOLDOWN", "60.0")),
        "correlation_window_sec": float(os.environ.get("NETSENTINEL_CORRELATION_WINDOW", "300.0")),
        "correlation_boost": float(os.environ.get("NETSENTINEL_CORRELATION_BOOST", "0.10")),
        "max_correlation_boost": float(os.environ.get("NETSENTINEL_MAX_CORRELATION_BOOST", "0.20")),
    }

    SSH_DETECTOR_ENABLED = HOST_DETECTION_SETTINGS["ssh_enabled"]
    SSH_WINDOW_SECONDS = HOST_DETECTION_SETTINGS["ssh_window_sec"]
    SSH_FAILURE_THRESHOLD = HOST_DETECTION_SETTINGS["ssh_failure_threshold"]
    PROCESS_MONITOR_ENABLED = HOST_DETECTION_SETTINGS["process_monitor_enabled"]
    PROCESS_INTERVAL_SECONDS = HOST_DETECTION_SETTINGS["process_interval_sec"]
    CORRELATION_WINDOW_SECONDS = HOST_DETECTION_SETTINGS["correlation_window_sec"]
    CORRELATION_BOOST = HOST_DETECTION_SETTINGS["correlation_boost"]

    # Advanced Network Threat Detection: ARP Settings (Phase 8)
    ARP_DETECTION_SETTINGS = {
        "arp_enabled": os.environ.get("NETSENTINEL_ARP_ENABLED", "True").lower() in ("true", "1", "t"),
        "arp_state_timeout": float(os.environ.get("NETSENTINEL_ARP_STATE_TIMEOUT", "300.0")),
        "arp_max_tracked_ips": int(os.environ.get("NETSENTINEL_ARP_MAX_IPS", "1000")),
        "arp_max_tracked_macs": int(os.environ.get("NETSENTINEL_ARP_MAX_MACS", "1000")),
        "arp_cooldown_sec": float(os.environ.get("NETSENTINEL_ARP_COOLDOWN_SEC", "60.0")),
        "arp_conflict_threshold": int(os.environ.get("NETSENTINEL_ARP_CONFLICT_THRESHOLD", "3")),
        "arp_trusted_mappings": {},
    }

    ARP_ENABLED = ARP_DETECTION_SETTINGS["arp_enabled"]
    ARP_STATE_TIMEOUT = ARP_DETECTION_SETTINGS["arp_state_timeout"]
    ARP_CONFLICT_THRESHOLD = ARP_DETECTION_SETTINGS["arp_conflict_threshold"]

    # Incident Correlation & Investigation Settings (Phase 9)
    INCIDENT_SETTINGS = {
        "incident_window_sec": float(os.environ.get("NETSENTINEL_INCIDENT_WINDOW", "300.0")),
        "max_active_incidents": int(os.environ.get("NETSENTINEL_MAX_ACTIVE_INCIDENTS", "1000")),
        "cross_domain_boost": float(os.environ.get("NETSENTINEL_INCIDENT_CROSS_DOMAIN_BOOST", "0.10")),
        "multi_vector_boost": float(os.environ.get("NETSENTINEL_INCIDENT_MULTI_VECTOR_BOOST", "0.05")),
        "max_incident_boost": float(os.environ.get("NETSENTINEL_MAX_INCIDENT_BOOST", "0.20")),
        "auto_resolve_sec": float(os.environ.get("NETSENTINEL_INCIDENT_AUTO_RESOLVE_SEC", "86400.0")),
    }

    INCIDENT_WINDOW_SECONDS = INCIDENT_SETTINGS["incident_window_sec"]
    MAX_ACTIVE_INCIDENTS = INCIDENT_SETTINGS["max_active_incidents"]

    # File Integrity Monitoring (FIM) Settings (Phase 10)
    FIM_SETTINGS = {
        "fim_enabled": os.environ.get("NETSENTINEL_FIM_ENABLED", "True").lower() in ("true", "1", "t"),
        "fim_interval_sec": float(os.environ.get("NETSENTINEL_FIM_INTERVAL", "30.0")),
        "fim_paths": [
            p.strip()
            for p in os.environ.get(
                "NETSENTINEL_FIM_PATHS",
                "/etc/passwd,/etc/group,/etc/ssh/sshd_config"
            ).split(",")
            if p.strip()
        ],
        "fim_max_files": int(os.environ.get("NETSENTINEL_FIM_MAX_FILES", "1000")),
        "fim_max_file_size": int(os.environ.get("NETSENTINEL_FIM_MAX_FILE_SIZE", "10485760")),  # 10 MB
        "fim_critical_paths": [
            p.strip()
            for p in os.environ.get(
                "NETSENTINEL_FIM_CRITICAL_PATHS",
                "/etc/passwd,/etc/shadow,/etc/ssh/sshd_config,/etc/sudoers"
            ).split(",")
            if p.strip()
        ],
        "fim_chunk_size": int(os.environ.get("NETSENTINEL_FIM_CHUNK_SIZE", "65536")),  # 64 KiB
    }

    FIM_ENABLED = FIM_SETTINGS["fim_enabled"]
    FIM_INTERVAL_SECONDS = FIM_SETTINGS["fim_interval_sec"]
    FIM_PATHS = FIM_SETTINGS["fim_paths"]
    FIM_MAX_FILES = FIM_SETTINGS["fim_max_files"]
    FIM_MAX_FILE_SIZE = FIM_SETTINGS["fim_max_file_size"]
    FIM_CRITICAL_PATHS = FIM_SETTINGS["fim_critical_paths"]

    # Threat Intelligence (TI) Enrichment Settings (Phase 11)
    TI_SETTINGS = {
        "ti_enabled": os.environ.get("NETSENTINEL_TI_ENABLED", "False").lower() in ("true", "1", "t"),
        "ti_queue_max": int(os.environ.get("NETSENTINEL_TI_QUEUE_MAX", "500")),
        "ti_workers": int(os.environ.get("NETSENTINEL_TI_WORKERS", "1")),
        "ti_cache_ttl": float(os.environ.get("NETSENTINEL_TI_CACHE_TTL", "3600.0")),  # 1 hour
        "ti_min_request_interval": float(os.environ.get("NETSENTINEL_TI_MIN_REQUEST_INTERVAL", "15.0")),
        "ti_request_timeout": float(os.environ.get("NETSENTINEL_TI_REQUEST_TIMEOUT", "8.0")),
        # Provider 1: AbuseIPDB
        "abuseipdb_enabled": os.environ.get("NETSENTINEL_TI_ABUSEIPDB_ENABLED", "False").lower() in ("true", "1", "t"),
        "abuseipdb_api_key": os.environ.get("NETSENTINEL_TI_ABUSEIPDB_API_KEY", "").strip(),
        "abuseipdb_max_age_days": int(os.environ.get("NETSENTINEL_TI_ABUSEIPDB_MAX_AGE_DAYS", "90")),
        # Provider 2: VirusTotal
        "vt_enabled": os.environ.get("NETSENTINEL_TI_VT_ENABLED", "False").lower() in ("true", "1", "t"),
        "vt_api_key": os.environ.get("NETSENTINEL_TI_VT_API_KEY", "").strip(),
    }

    TI_ENABLED = TI_SETTINGS["ti_enabled"]
    TI_QUEUE_MAX = TI_SETTINGS["ti_queue_max"]
    TI_WORKERS = TI_SETTINGS["ti_workers"]
    TI_CACHE_TTL = TI_SETTINGS["ti_cache_ttl"]
    TI_MIN_REQUEST_INTERVAL = TI_SETTINGS["ti_min_request_interval"]
    TI_REQUEST_TIMEOUT = TI_SETTINGS["ti_request_timeout"]
    TI_ABUSEIPDB_ENABLED = TI_SETTINGS["abuseipdb_enabled"]
    TI_ABUSEIPDB_API_KEY = TI_SETTINGS["abuseipdb_api_key"]
    TI_ABUSEIPDB_MAX_AGE_DAYS = TI_SETTINGS["abuseipdb_max_age_days"]
    TI_VT_ENABLED = TI_SETTINGS["vt_enabled"]
    TI_VT_API_KEY = TI_SETTINGS["vt_api_key"]



