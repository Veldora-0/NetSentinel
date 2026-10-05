"""NetSentinel Central Configuration Validator.

Provides strict, deterministic startup configuration validation and secret redaction.
Guarantees that invalid, dangerous, or malformed parameters are caught immediately
with clear, actionable diagnostic messages, preventing silent degradation or security bypass.
"""

from dataclasses import dataclass
import ipaddress
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("netsentinel.config_validator")

NETSENTINEL_VERSION = "1.0.0"


class ConfigurationError(ValueError):
    """Raised when application configuration contains invalid, contradictory, or unsafe parameters."""
    pass


@dataclass
class ValidationResult:
    """Detailed result of configuration validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]


class ConfigValidator:
    """Validates NetSentinel system configuration against strict operational boundaries."""

    SENSITIVE_KEYS = {
        "secret_key",
        "api_key",
        "abuseipdb_api_key",
        "vt_api_key",
        "password",
        "token",
        "private_key",
        "credentials",
    }

    @classmethod
    def redact_secrets(cls, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Produce a safe, redacted clone of configuration suitable for APIs and logs.

        Replaces secret values with '[REDACTED]' while indicating presence.
        """
        redacted = {}
        for key, value in config_dict.items():
            lower_key = str(key).lower()
            if any(s in lower_key for s in cls.SENSITIVE_KEYS):
                if value and str(value).strip():
                    redacted[key] = "[REDACTED]"
                else:
                    redacted[key] = ""
            elif isinstance(value, dict):
                redacted[key] = cls.redact_secrets(value)
            elif isinstance(value, list):
                redacted[key] = [
                    cls.redact_secrets(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        return redacted

    @classmethod
    def validate_ip_or_cidr(cls, candidate: str, field_name: str) -> None:
        """Validate string as a single IPv4/IPv6 address or valid CIDR network."""
        if not candidate or not isinstance(candidate, str):
            raise ConfigurationError(f"{field_name}: empty or non-string IP address provided")
        clean = candidate.strip()
        try:
            if "/" in clean:
                ipaddress.ip_network(clean, strict=False)
            else:
                ipaddress.ip_address(clean)
        except ValueError as err:
            raise ConfigurationError(
                f"{field_name}: invalid IP address or CIDR range '{clean}': {err}"
            )

    @classmethod
    def validate_positive_number(
        cls, value: Any, field_name: str, allow_zero: bool = False, min_val: Optional[float] = None
    ) -> float:
        """Ensure a configuration value is a positive numeric float."""
        try:
            num = float(value)
        except (ValueError, TypeError):
            raise ConfigurationError(f"{field_name}: expected numeric value, got '{value}'")

        if not allow_zero and num <= 0:
            raise ConfigurationError(f"{field_name}: must be strictly positive (> 0), got {num}")
        if allow_zero and num < 0:
            raise ConfigurationError(f"{field_name}: cannot be negative, got {num}")
        if min_val is not None and num < min_val:
            raise ConfigurationError(f"{field_name}: must be >= {min_val}, got {num}")
        return num

    @classmethod
    def validate_positive_int(
        cls, value: Any, field_name: str, allow_zero: bool = False, min_val: Optional[int] = None
    ) -> int:
        """Ensure a configuration value is a positive integer."""
        try:
            num = int(value)
        except (ValueError, TypeError):
            raise ConfigurationError(f"{field_name}: expected integer value, got '{value}'")

        if not allow_zero and num <= 0:
            raise ConfigurationError(f"{field_name}: must be strictly positive (> 0), got {num}")
        if allow_zero and num < 0:
            raise ConfigurationError(f"{field_name}: cannot be negative, got {num}")
        if min_val is not None and num < min_val:
            raise ConfigurationError(f"{field_name}: must be >= {min_val}, got {num}")
        return num

    @classmethod
    def validate_cors_origins(cls, origins: Any) -> List[str]:
        """Validate and normalize CORS origin configurations."""
        if isinstance(origins, str):
            items = [x.strip() for x in origins.split(",") if x.strip()]
        elif isinstance(origins, (list, tuple, set)):
            items = [str(x).strip() for x in origins if str(x).strip()]
        else:
            raise ConfigurationError(f"CORS origins must be a list or comma-separated string, got {type(origins)}")

        if not items:
            raise ConfigurationError("CORS origins cannot be empty")

        for item in items:
            if item == "*":
                continue
            parsed = urlparse(item)
            if not parsed.scheme or not parsed.netloc:
                raise ConfigurationError(
                    f"CORS origin '{item}' is malformed. Must include scheme and host (e.g. 'http://localhost:5173')"
                )
            if parsed.scheme not in ("http", "https"):
                raise ConfigurationError(
                    f"CORS origin '{item}' has invalid scheme '{parsed.scheme}'. Must be 'http' or 'https'"
                )
        return items

    @classmethod
    def validate_config(cls, cfg: Any) -> ValidationResult:
        """Perform comprehensive validation across all NetSentinel subsystems.

        Args:
            cfg: Config class or dictionary of settings.

        Returns:
            ValidationResult containing valid status, error messages, and warnings.
        """
        errors: List[str] = []
        warnings: List[str] = []

        def get_val(key: str, default: Any = None) -> Any:
            if isinstance(cfg, dict):
                return cfg.get(key, default)
            return getattr(cfg, key, default)

        # 1. Server Bindings
        host = get_val("HOST", "0.0.0.0")
        if not host or not isinstance(host, str):
            errors.append("HOST must be a non-empty string")
        port = get_val("PORT", 5000)
        try:
            p_num = int(port)
            if p_num < 1 or p_num > 65535:
                errors.append(f"PORT must be between 1 and 65535, got {p_num}")
        except Exception:
            errors.append(f"PORT must be an integer, got '{port}'")

        # 2. Rule Detector Settings
        det = get_val("DETECTOR_THRESHOLDS", {})
        if det:
            for k in ("port_scan_window_sec", "syn_flood_window_sec", "icmp_sweep_window_sec", "alert_cooldown_sec"):
                if k in det:
                    try:
                        cls.validate_positive_number(det[k], f"DETECTOR_THRESHOLDS.{k}")
                    except ConfigurationError as e:
                        errors.append(str(e))
            for k in ("port_scan_threshold", "syn_flood_threshold", "icmp_sweep_threshold", "max_tracked_ips"):
                if k in det:
                    try:
                        cls.validate_positive_int(det[k], f"DETECTOR_THRESHOLDS.{k}", min_val=1)
                    except ConfigurationError as e:
                        errors.append(str(e))

        # 3. Machine Learning Settings
        ml = get_val("ML_SETTINGS", {})
        if ml:
            if "window_seconds" in ml:
                try:
                    cls.validate_positive_number(ml["window_seconds"], "ML_SETTINGS.window_seconds", min_val=0.5)
                except ConfigurationError as e:
                    errors.append(str(e))
            if "baseline_windows" in ml:
                try:
                    cls.validate_positive_int(ml["baseline_windows"], "ML_SETTINGS.baseline_windows", min_val=1)
                except ConfigurationError as e:
                    errors.append(str(e))
            if "n_estimators" in ml:
                try:
                    cls.validate_positive_int(ml["n_estimators"], "ML_SETTINGS.n_estimators", min_val=10)
                except ConfigurationError as e:
                    errors.append(str(e))
            if "contamination" in ml and ml["contamination"] != "auto":
                try:
                    c = float(ml["contamination"])
                    if c <= 0.0 or c > 0.5:
                        errors.append(f"ML_SETTINGS.contamination must be 'auto' or in range (0.0, 0.5], got {c}")
                except (ValueError, TypeError):
                    errors.append(f"ML_SETTINGS.contamination invalid value '{ml['contamination']}'")

        # 4. Composite Risk Engine Settings
        risk = get_val("RISK_SETTINGS", {})
        if risk:
            for w in ("rule_weight", "ml_weight"):
                if w in risk:
                    try:
                        val = cls.validate_positive_number(risk[w], f"RISK_SETTINGS.{w}", allow_zero=True)
                        if val > 1.0:
                            errors.append(f"RISK_SETTINGS.{w} must be <= 1.0, got {val}")
                    except ConfigurationError as e:
                        errors.append(str(e))

        # 5. Linux iptables Firewall Settings
        fw = get_val("FIREWALL_SETTINGS", {})
        if fw:
            if "block_duration" in fw:
                try:
                    cls.validate_positive_number(fw["block_duration"], "FIREWALL_SETTINGS.block_duration", min_val=1.0)
                except ConfigurationError as e:
                    errors.append(str(e))
            if "max_blocked_ips" in fw:
                try:
                    cls.validate_positive_int(fw["max_blocked_ips"], "FIREWALL_SETTINGS.max_blocked_ips", min_val=1)
                except ConfigurationError as e:
                    errors.append(str(e))
            allowlist = fw.get("allowlist", [])
            for item in allowlist:
                try:
                    cls.validate_ip_or_cidr(item, "FIREWALL_SETTINGS.allowlist")
                except ConfigurationError as e:
                    errors.append(str(e))

            # Guard safe defaults
            if fw.get("enabled") and not fw.get("dry_run"):
                warnings.append("Firewall is configured in LIVE ACTIVE mode (dry_run=False). Ensure iptables permissions exist.")

        # 6. Telemetry Settings
        telemetry = get_val("TELEMETRY_SETTINGS", {})
        if telemetry:
            for k in ("interval", "persist_interval", "prune_interval"):
                if k in telemetry:
                    try:
                        cls.validate_positive_number(telemetry[k], f"TELEMETRY_SETTINGS.{k}", min_val=0.5)
                    except ConfigurationError as e:
                        errors.append(str(e))
            if "retention_days" in telemetry:
                try:
                    cls.validate_positive_int(telemetry["retention_days"], "TELEMETRY_SETTINGS.retention_days", allow_zero=True)
                except ConfigurationError as e:
                    errors.append(str(e))

        # 7. Host Detection Settings
        host_cfg = get_val("HOST_DETECTION_SETTINGS", {})
        if host_cfg:
            for k in ("ssh_window_sec", "ssh_alert_cooldown_sec", "process_interval_sec", "correlation_window_sec"):
                if k in host_cfg:
                    try:
                        cls.validate_positive_number(host_cfg[k], f"HOST_DETECTION_SETTINGS.{k}", min_val=1.0)
                    except ConfigurationError as e:
                        errors.append(str(e))
            if "ssh_failure_threshold" in host_cfg:
                try:
                    cls.validate_positive_int(host_cfg["ssh_failure_threshold"], "HOST_DETECTION_SETTINGS.ssh_failure_threshold", min_val=1)
                except ConfigurationError as e:
                    errors.append(str(e))

        # 8. File Integrity Monitoring (FIM) Settings
        fim = get_val("FIM_SETTINGS", {})
        if fim:
            if "fim_interval_sec" in fim:
                try:
                    cls.validate_positive_number(fim["fim_interval_sec"], "FIM_SETTINGS.fim_interval_sec", min_val=1.0)
                except ConfigurationError as e:
                    errors.append(str(e))
            for k in ("fim_max_files", "fim_max_file_size", "fim_chunk_size"):
                if k in fim:
                    try:
                        cls.validate_positive_int(fim[k], f"FIM_SETTINGS.{k}", min_val=1)
                    except ConfigurationError as e:
                        errors.append(str(e))
            paths = fim.get("fim_paths", [])
            if not isinstance(paths, list):
                errors.append("FIM_SETTINGS.fim_paths must be a list of file/directory paths")

        # 9. Threat Intelligence Settings
        ti = get_val("TI_SETTINGS", {})
        if ti:
            for k in ("ti_queue_max", "ti_workers"):
                if k in ti:
                    try:
                        cls.validate_positive_int(ti[k], f"TI_SETTINGS.{k}", min_val=1)
                    except ConfigurationError as e:
                        errors.append(str(e))
            for k in ("ti_cache_ttl", "ti_request_timeout"):
                if k in ti:
                    try:
                        cls.validate_positive_number(ti[k], f"TI_SETTINGS.{k}", min_val=0.5)
                    except ConfigurationError as e:
                        errors.append(str(e))
            if "ti_min_request_interval" in ti:
                try:
                    cls.validate_positive_number(ti["ti_min_request_interval"], "TI_SETTINGS.ti_min_request_interval", allow_zero=True)
                except ConfigurationError as e:
                    errors.append(str(e))

        # 10. CORS & API Security Settings
        cors = get_val("CORS_ORIGINS", None)
        if cors is not None:
            try:
                cls.validate_cors_origins(cors)
            except ConfigurationError as e:
                errors.append(str(e))

        # Check flat interval / window keys if provided
        for k in ("METRICS_EMIT_INTERVAL", "TELEMETRY_INTERVAL", "FIM_SCAN_INTERVAL", "INCIDENT_WINDOW_SEC"):
            val = get_val(k, None)
            if val is not None:
                try:
                    cls.validate_positive_number(val, k, min_val=0.01)
                except ConfigurationError as e:
                    errors.append(f"{k} must be a positive number: {e}")

        # Check flat risk thresholds
        r_high = get_val("RISK_HIGH_THRESHOLD", None)
        r_crit = get_val("RISK_CRITICAL_THRESHOLD", None)
        if r_high is not None:
            try:
                num = float(r_high)
                if num < 0.0 or num > 1.0:
                    errors.append(f"RISK_HIGH_THRESHOLD must be between 0.0 and 1.0, got {num}")
            except Exception:
                errors.append(f"RISK_HIGH_THRESHOLD must be numeric, got '{r_high}'")
        if r_crit is not None:
            try:
                num = float(r_crit)
                if num < 0.0 or num > 1.0:
                    errors.append(f"RISK_CRITICAL_THRESHOLD must be between 0.0 and 1.0, got {num}")
            except Exception:
                errors.append(f"RISK_CRITICAL_THRESHOLD must be numeric, got '{r_crit}'")
        if r_high is not None and r_crit is not None:
            try:
                if float(r_high) > float(r_crit):
                    errors.append("RISK_HIGH_THRESHOLD cannot be greater than RISK_CRITICAL_THRESHOLD")
            except Exception:
                pass

        # Check flat firewall allowlist
        fw_allowlist = get_val("FIREWALL_ALLOWLIST", None)
        if fw_allowlist is not None:
            if not isinstance(fw_allowlist, (list, tuple, set)):
                errors.append("FIREWALL_ALLOWLIST must be a list of IP addresses or CIDR notations")
            else:
                for item in fw_allowlist:
                    try:
                        cls.validate_ip_or_cidr(item, "FIREWALL_ALLOWLIST")
                    except ConfigurationError as e:
                        errors.append(f"Invalid IP or CIDR in FIREWALL_ALLOWLIST: {e}")

        # Rate limits (flat or namespaced)
        rate_limit = get_val("API_RATE_LIMIT", get_val("NETSENTINEL_API_RATE_LIMIT", 60))
        try:
            cls.validate_positive_int(rate_limit, "API_RATE_LIMIT", min_val=1)
        except ConfigurationError as e:
            errors.append(f"API_RATE_LIMIT must be a positive integer: {e}")

        sensitive_rate = get_val("SENSITIVE_RATE_LIMIT", get_val("NETSENTINEL_SENSITIVE_RATE_LIMIT", 10))
        try:
            cls.validate_positive_int(sensitive_rate, "SENSITIVE_RATE_LIMIT", min_val=1)
        except ConfigurationError as e:
            errors.append(f"SENSITIVE_RATE_LIMIT must be a positive integer: {e}")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)

    @classmethod
    def validate_or_raise(cls, cfg: Any) -> Any:
        """Validate configuration and raise ConfigurationError if any errors are discovered."""
        result = cls.validate_config(cfg)
        if not result.is_valid:
            summary = "\n  - " + "\n  - ".join(result.errors)
            raise ConfigurationError(f"NetSentinel Configuration Validation Failed:{summary}")
        return cfg
