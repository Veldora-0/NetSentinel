"""Unit and integration tests for NetSentinel Central Configuration Validator and Safe Defaults."""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from config import Config
from config_validator import ConfigValidator, ConfigurationError, NETSENTINEL_VERSION


def test_default_config_validates():
    """Verify that the default application configuration passes all validation checks."""
    cfg = Config()
    validated = ConfigValidator.validate_or_raise(cfg)
    assert validated is not None
    assert getattr(validated, "VERSION", "1.0.0") == "1.0.0"


def test_invalid_host_and_port():
    """Verify that invalid HOST or PORT settings raise ConfigurationError."""
    with pytest.raises(ConfigurationError, match="PORT must be an integer"):
        ConfigValidator.validate_or_raise({"PORT": "invalid_port"})

    with pytest.raises(ConfigurationError, match="PORT must be between 1 and 65535"):
        ConfigValidator.validate_or_raise({"PORT": 70000})

    with pytest.raises(ConfigurationError, match="PORT must be between 1 and 65535"):
        ConfigValidator.validate_or_raise({"PORT": -1})

    with pytest.raises(ConfigurationError, match="HOST must be a non-empty string"):
        ConfigValidator.validate_or_raise({"HOST": ""})


def test_invalid_intervals_and_windows():
    """Verify that negative or non-positive operational intervals are rejected."""
    with pytest.raises(ConfigurationError, match="METRICS_EMIT_INTERVAL must be a positive number"):
        ConfigValidator.validate_or_raise({"METRICS_EMIT_INTERVAL": 0})

    with pytest.raises(ConfigurationError, match="TELEMETRY_INTERVAL must be a positive number"):
        ConfigValidator.validate_or_raise({"TELEMETRY_INTERVAL": -5})

    with pytest.raises(ConfigurationError, match="FIM_SCAN_INTERVAL must be a positive number"):
        ConfigValidator.validate_or_raise({"FIM_SCAN_INTERVAL": -10})

    with pytest.raises(ConfigurationError, match="INCIDENT_WINDOW_SEC must be a positive number"):
        ConfigValidator.validate_or_raise({"INCIDENT_WINDOW_SEC": -1})


def test_invalid_risk_thresholds():
    """Verify that risk engine score thresholds must be valid probabilities [0.0, 1.0]."""
    with pytest.raises(ConfigurationError, match="RISK_HIGH_THRESHOLD must be between 0.0 and 1.0"):
        ConfigValidator.validate_or_raise({"RISK_HIGH_THRESHOLD": 1.5})

    with pytest.raises(ConfigurationError, match="RISK_CRITICAL_THRESHOLD must be between 0.0 and 1.0"):
        ConfigValidator.validate_or_raise({"RISK_CRITICAL_THRESHOLD": -0.1})

    with pytest.raises(ConfigurationError, match="RISK_HIGH_THRESHOLD cannot be greater than RISK_CRITICAL_THRESHOLD"):
        ConfigValidator.validate_or_raise({
            "RISK_HIGH_THRESHOLD": 0.90,
            "RISK_CRITICAL_THRESHOLD": 0.80,
        })


def test_firewall_allowlist_validation():
    """Verify that FIREWALL_ALLOWLIST enforces valid IPv4/IPv6 and CIDR network notations."""
    # Valid allowlist
    valid_cfg = {
        "FIREWALL_ALLOWLIST": ["127.0.0.1", "10.0.0.0/8", "192.168.1.1", "::1"]
    }
    validated = ConfigValidator.validate_or_raise(valid_cfg)
    assert len(validated["FIREWALL_ALLOWLIST"]) == 4

    # Invalid string instead of list
    with pytest.raises(ConfigurationError, match="FIREWALL_ALLOWLIST must be a list"):
        ConfigValidator.validate_or_raise({"FIREWALL_ALLOWLIST": "127.0.0.1"})

    # Invalid IP address syntax
    with pytest.raises(ConfigurationError, match="Invalid IP or CIDR in FIREWALL_ALLOWLIST"):
        ConfigValidator.validate_or_raise({"FIREWALL_ALLOWLIST": ["999.999.999.999"]})

    with pytest.raises(ConfigurationError, match="Invalid IP or CIDR in FIREWALL_ALLOWLIST"):
        ConfigValidator.validate_or_raise({"FIREWALL_ALLOWLIST": ["not-an-ip-address"]})


def test_cors_origins_validation():
    """Verify that CORS_ORIGINS accepts lists or comma-delimited strings."""
    # Valid list
    res1 = ConfigValidator.validate_or_raise({"CORS_ORIGINS": ["http://localhost:5173", "http://127.0.0.1:5173"]})
    assert len(res1["CORS_ORIGINS"]) == 2

    # Valid comma-delimited string
    res2 = ConfigValidator.validate_or_raise({"CORS_ORIGINS": "http://localhost:5173, http://10.0.0.5:3000"})
    assert "http://10.0.0.5:3000" in res2["CORS_ORIGINS"]

    # Invalid type
    with pytest.raises(ConfigurationError, match="CORS origins must be a list or comma-separated string"):
        ConfigValidator.validate_or_raise({"CORS_ORIGINS": 12345})


def test_rate_limit_validation():
    """Verify that rate limits must be positive integers."""
    with pytest.raises(ConfigurationError, match="API_RATE_LIMIT must be a positive integer"):
        ConfigValidator.validate_or_raise({"API_RATE_LIMIT": 0})

    with pytest.raises(ConfigurationError, match="SENSITIVE_RATE_LIMIT must be a positive integer"):
        ConfigValidator.validate_or_raise({"SENSITIVE_RATE_LIMIT": -5})


def test_secret_redaction():
    """Verify that ConfigValidator.redact_secrets scrubs all sensitive credentials and tokens."""
    sensitive_dict = {
        "SECRET_KEY": "super-secret-key-12345",
        "ABUSEIPDB_API_KEY": "abuseipdb_secret_key_abc",
        "VIRUSTOTAL_API_KEY": "virustotal_secret_key_xyz",
        "DATABASE_PASSWORD": "db_password_top_secret",
        "AUTH_TOKEN": "jwt-token-string-999",
        "HOST": "0.0.0.0",
        "PORT": 5000,
        "DEBUG": False,
        "VERSION": "1.0.0",
    }

    redacted = ConfigValidator.redact_secrets(sensitive_dict)
    assert redacted["SECRET_KEY"] == "[REDACTED]"
    assert redacted["ABUSEIPDB_API_KEY"] == "[REDACTED]"
    assert redacted["VIRUSTOTAL_API_KEY"] == "[REDACTED]"
    assert redacted["DATABASE_PASSWORD"] == "[REDACTED]"
    assert redacted["AUTH_TOKEN"] == "[REDACTED]"

    # Non-sensitive keys remain visible
    assert redacted["HOST"] == "0.0.0.0"
    assert redacted["PORT"] == 5000
    assert redacted["DEBUG"] is False
    assert redacted["VERSION"] == "1.0.0"


def test_config_class_redacted_dict():
    """Verify that Config.get_redacted_dict() masks sensitive keys."""
    redacted = Config.get_redacted_dict()
    assert isinstance(redacted, dict)
    assert redacted.get("SECRET_KEY") == "[REDACTED]"
    if "ABUSEIPDB_API_KEY" in redacted:
        assert redacted["ABUSEIPDB_API_KEY"] in ("[REDACTED]", None, "")
    assert redacted.get("version") == "1.0.0"
