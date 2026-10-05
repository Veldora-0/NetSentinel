"""NetSentinel SSH Authentication Failure and Brute-Force Detector Module.

Parses authentication failure signals from Linux authentication logs, validates source IPs,
maintains sliding failure windows, and generates structured SecurityEvents for
SSH_AUTH_FAILURE and SSH_BRUTE_FORCE attacks.
"""

from collections import deque
from datetime import datetime
import ipaddress
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from detector import SecurityEvent
from host.log_reader import SSHLogReader

logger = logging.getLogger("netsentinel.host.ssh_detector")

# Regular expressions for standard OpenSSH failure messages
SSH_FAILURE_PATTERNS = [
    # 1. Failed password / publickey for user
    re.compile(
        r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>[a-zA-Z0-9_.@-]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
        re.IGNORECASE,
    ),
    # 2. Invalid user
    re.compile(
        r"Invalid user (?P<user>[a-zA-Z0-9_.@-]+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
        re.IGNORECASE,
    ),
    # 3. PAM authentication failure
    re.compile(
        r"authentication failure; .* rhost=(?P<ip>[0-9a-fA-F:.]+)(?: +user=(?P<user>[a-zA-Z0-9_.@-]+))?",
        re.IGNORECASE,
    ),
    # 4. Connection closed during preauth
    re.compile(
        r"Connection closed by authenticating user (?P<user>[a-zA-Z0-9_.@-]+) (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+) \[preauth\]",
        re.IGNORECASE,
    ),
]


class SSHDetector:
    """Stateful SSH authentication failure and brute-force detection engine."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        log_reader: Optional[SSHLogReader] = None,
        threshold: Optional[int] = None,
        window_seconds: Optional[float] = None,
        alert_cooldown: Optional[float] = None,
        on_event: Optional[Callable[[SecurityEvent], None]] = None,
    ):
        cfg = config or {}
        self.enabled = bool(cfg.get("ssh_enabled", True))
        self.window_seconds = float(window_seconds if window_seconds is not None else cfg.get("ssh_window_sec", 60.0))
        self.failure_threshold = int(threshold if threshold is not None else cfg.get("ssh_failure_threshold", 5))
        self.alert_cooldown_sec = float(alert_cooldown if alert_cooldown is not None else cfg.get("ssh_alert_cooldown_sec", 60.0))
        self.max_tracked_ips = int(cfg.get("ssh_max_tracked_ips", 1000))
        self._on_event = on_event

        # Log reader instance
        if log_reader is not None:
            self.log_reader = log_reader
        else:
            log_path = cfg.get("ssh_log_path")
            self.log_reader = SSHLogReader(custom_path=log_path) if self.enabled else None

        # Stateful failure tracking: source_ip -> deque of timestamps
        self._failures: Dict[str, deque] = {}
        # Alert cooldown tracking: source_ip -> last_bruteforce_alert_time
        self._alert_history: Dict[str, float] = {}

        # Telemetry counters
        self.total_failures_observed: int = 0
        self.total_brute_force_detected: int = 0
        self.last_check_time: float = 0.0

    @property
    def status(self) -> str:
        """Operating status of the SSH detector."""
        if not self.enabled:
            return "DISABLED"
        if not self.log_reader:
            return "NOT_INITIALIZED"
        return self.log_reader.status.upper()

    @property
    def log_path(self) -> Optional[str]:
        """Path of the active log file being monitored."""
        return self.log_reader.current_path if self.log_reader else None

    @property
    def total_failures(self) -> int:
        """Total authentication failures observed."""
        return self.total_failures_observed

    @property
    def _failed_attempts(self) -> Dict[str, deque]:
        """Map of tracked source IPs to recent failure timestamps."""
        return self._failures

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse log line without state side-effects (for inspection and unit testing)."""
        if not line:
            return None
        for pattern in SSH_FAILURE_PATTERNS:
            m = pattern.search(line)
            if m:
                extracted_ip = m.groupdict().get("ip")
                valid_ip = self._validate_ip(extracted_ip)
                if not valid_ip:
                    continue
                username = self._sanitize_username(m.groupdict().get("user"))
                port_str = m.groupdict().get("port")
                port = int(port_str) if port_str and port_str.isdigit() else 22
                is_invalid = "invalid" in line.lower()
                return {
                    "source_ip": valid_ip,
                    "username": username,
                    "port": port,
                    "is_invalid_user": is_invalid,
                    "method": m.groupdict().get("method") or "password",
                }
        return None

    def _sanitize_username(self, user: Optional[str]) -> str:
        """Sanitize extracted username to prevent secret leakage or log poisoning."""
        if not user:
            return "unknown"
        clean = user.strip()
        # Cap length and eliminate non-alphanumeric characters
        if len(clean) > 32 or any(c in clean for c in " \t\n\r\"'\\;"):
            return "[filtered]"
        return clean

    def _validate_ip(self, ip_str: Optional[str]) -> Optional[str]:
        """Validate and normalize IPv4/IPv6 address string."""
        if not ip_str:
            return None
        clean = ip_str.strip()
        try:
            addr = ipaddress.ip_address(clean)
            return str(addr)
        except ValueError:
            return None

    def _parse_timestamp(self, line: str, fallback_time: float) -> float:
        """Extract timestamp from standard syslog or ISO format line."""
        # Try ISO 8601 (e.g. 2026-10-05T10:15:30)
        iso_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
        if iso_match:
            try:
                dt_str = iso_match.group(1).replace(" ", "T")
                dt = datetime.fromisoformat(dt_str)
                return dt.timestamp()
            except Exception:
                pass

        # Try standard BSD syslog (e.g. Oct  5 10:15:30)
        syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
        if syslog_match:
            try:
                current_year = datetime.now().year
                dt = datetime.strptime(f"{current_year} {syslog_match.group(1)}", "%Y %b %d %H:%M:%S")
                return dt.timestamp()
            except Exception:
                pass

        return fallback_time

    def process_line(self, line: str, now: Optional[float] = None) -> List[SecurityEvent]:
        """Analyze a single log line and return any resulting SecurityEvents.

        Args:
            line: Raw log line string.
            now: Optional timestamp override for deterministic testing.

        Returns:
            List of generated SecurityEvent instances (can contain failure and/or brute-force event).
        """
        if not self.enabled or not line:
            return []

        curr_time = now if now is not None else time.time()
        events: List[SecurityEvent] = []

        # Attempt to match against known failure patterns
        matched = False
        source_ip: Optional[str] = None
        username: str = "unknown"
        method: str = "password"

        for pattern in SSH_FAILURE_PATTERNS:
            m = pattern.search(line)
            if m:
                extracted_ip = m.groupdict().get("ip")
                valid_ip = self._validate_ip(extracted_ip)
                if not valid_ip:
                    continue

                source_ip = valid_ip
                username = self._sanitize_username(m.groupdict().get("user"))
                method = m.groupdict().get("method") or "password"
                matched = True
                break

        if not matched or not source_ip:
            return []

        event_time = self._parse_timestamp(line, fallback_time=curr_time)
        self.total_failures_observed += 1

        # 1. Generate SSH_AUTH_FAILURE event (LOW severity signal)
        auth_failure_event = SecurityEvent(
            event_id=uuid.uuid4().hex[:12],
            timestamp=event_time,
            detection_type="SSH_AUTH_FAILURE",
            severity="LOW",
            source_ip=source_ip,
            destination_ip=None,
            protocol="TCP",
            source_port=None,
            destination_port=22,
            description=f"SSH authentication failure for user '{username}' from {source_ip}",
            evidence={
                "username": username,
                "authentication_method": method,
                "failure_type": "authentication_failure",
            },
            rule_name="RULE_SSH_AUTH_FAILURE",
        )
        events.append(auth_failure_event)

        # 2. Check for SSH_BRUTE_FORCE condition (sliding window)
        self._record_failure(source_ip, event_time)
        failures_in_window = len(self._failures[source_ip])

        if failures_in_window >= self.failure_threshold:
            last_alert = self._alert_history.get(source_ip, 0.0)
            if (curr_time - last_alert) >= self.alert_cooldown_sec:
                self._alert_history[source_ip] = curr_time
                self.total_brute_force_detected += 1

                brute_force_event = SecurityEvent(
                    event_id=uuid.uuid4().hex[:12],
                    timestamp=event_time,
                    detection_type="SSH_BRUTE_FORCE",
                    severity="HIGH",
                    source_ip=source_ip,
                    destination_ip=None,
                    protocol="TCP",
                    source_port=None,
                    destination_port=22,
                    description=(
                        f"SSH brute-force attack detected from {source_ip} "
                        f"({failures_in_window} failures in {int(self.window_seconds)}s)"
                    ),
                    evidence={
                        "username": username,
                        "failure_count": failures_in_window,
                        "window_seconds": self.window_seconds,
                        "threshold": self.failure_threshold,
                        "authentication_method": method,
                        "failure_type": "ssh_bruteforce",
                    },
                    rule_name="RULE_SSH_BRUTEFORCE",
                )
                events.append(brute_force_event)

        if self._on_event:
            for ev in events:
                try:
                    self._on_event(ev)
                except Exception as ex:
                    logger.debug("Error in SSHDetector on_event callback: %s", ex)

        return events

    def _record_failure(self, source_ip: str, timestamp: float) -> None:
        """Record failure timestamp for source IP and prune expired entries."""
        if source_ip not in self._failures:
            # Memory state bounding
            if len(self._failures) >= self.max_tracked_ips:
                self._prune_stale_ips(timestamp)
            if len(self._failures) >= self.max_tracked_ips:
                oldest = next(iter(self._failures))
                del self._failures[oldest]
            self._failures[source_ip] = deque()

        history = self._failures[source_ip]
        history.append(timestamp)

        # Prune entries outside sliding time window
        cutoff = timestamp - self.window_seconds
        while history and history[0] < cutoff:
            history.popleft()

    def _prune_stale_ips(self, now: float) -> None:
        """Remove IPs that have no failures within current window."""
        cutoff = now - self.window_seconds
        stale = []
        for ip, history in self._failures.items():
            while history and history[0] < cutoff:
                history.popleft()
            if not history:
                stale.append(ip)

        for ip in stale:
            del self._failures[ip]

        # Prune alert history
        alert_cutoff = now - (self.alert_cooldown_sec * 3)
        stale_alerts = [ip for ip, t in self._alert_history.items() if t < alert_cutoff]
        for ip in stale_alerts:
            del self._alert_history[ip]

    def check_new_logs(self, now: Optional[float] = None) -> List[SecurityEvent]:
        """Tail log reader for newly appended lines and process them."""
        if not self.enabled or not self.log_reader:
            return []

        self.last_check_time = now if now is not None else time.time()
        lines = self.log_reader.read_new_lines()
        events: List[SecurityEvent] = []

        for line in lines:
            line_events = self.process_line(line, now=now)
            events.extend(line_events)

        return events

    def get_status(self) -> Dict[str, Any]:
        """Return operational status of SSH detector."""
        return {
            "status": self.status,
            "enabled": self.enabled,
            "log_path": self.log_path,
            "log_source": self.log_reader.current_path if self.log_reader else None,
            "reader_status": self.log_reader.status if self.log_reader else "disabled",
            "window_seconds": self.window_seconds,
            "threshold": self.failure_threshold,
            "alert_cooldown_seconds": self.alert_cooldown_sec,
            "tracked_sources": len(self._failures),
            "tracked_sources_count": len(self._failures),
            "total_failures": self.total_failures_observed,
            "total_failures_observed": self.total_failures_observed,
            "total_brute_force_detected": self.total_brute_force_detected,
            "last_check_time": self.last_check_time,
        }
