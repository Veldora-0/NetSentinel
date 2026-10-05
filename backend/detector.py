"""NetSentinel Intrusion Detector Module.

Implements stateful and signature rule-based network intrusion detection
for Port Scans, SYN Floods, NULL Scans, and XMAS Scans.
Generates structured SecurityEvents with automated duplicate alert cooldowns
and bounded memory state management.
"""

from collections import deque
from dataclasses import dataclass, asdict
import ipaddress
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from config import Config
from parser import ParsedPacket

logger = logging.getLogger("netsentinel.detector")


@dataclass
class SecurityEvent:
    """Structured security detection event."""
    event_id: str
    timestamp: float
    detection_type: str
    severity: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    description: str = ""
    evidence: Optional[Dict[str, Any]] = None
    rule_name: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = self.metadata if self.metadata is not None else {}
        if self.metadata is None:
            self.metadata = self.evidence

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to JSON-serializable dictionary."""
        d = asdict(self)
        if d.get("evidence") is None:
            d["evidence"] = {}
        if d.get("metadata") is None:
            d["metadata"] = d["evidence"]
        return d


class TrafficDetector:
    """Stateful rule-based network intrusion detection engine."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or Config.DETECTOR_THRESHOLDS

        # Detection Thresholds
        self.port_scan_window_sec = float(cfg.get("port_scan_window_sec", 10.0))
        self.port_scan_threshold = int(cfg.get("port_scan_threshold", 15))

        self.syn_flood_window_sec = float(cfg.get("syn_flood_window_sec", 5.0))
        self.syn_flood_threshold = int(cfg.get("syn_flood_threshold", 50))

        self.null_scan_enabled = bool(cfg.get("null_scan_enabled", True))
        self.xmas_scan_enabled = bool(cfg.get("xmas_scan_enabled", True))

        # ICMP Sweep Thresholds
        self.icmp_sweep_window_sec = float(cfg.get("icmp_sweep_window_sec", 10.0))
        self.icmp_sweep_threshold = int(cfg.get("icmp_sweep_threshold", 10))
        self.icmp_sweep_cooldown_sec = float(cfg.get("icmp_sweep_cooldown_sec", 60.0))

        # Alert Cooldown & Memory Limits
        self.alert_cooldown_sec = float(cfg.get("alert_cooldown_sec", 30.0))
        self.max_tracked_ips = int(cfg.get("max_tracked_ips", 1000))
        self.state_cleanup_sec = float(cfg.get("state_cleanup_sec", 60.0))
        max_alert_history = int(cfg.get("max_alert_history", 100))

        # Stateful Tracking Structures
        self._lock = threading.Lock()
        # source_ip -> deque of (timestamp, dst_port)
        self._port_scan_state: Dict[str, deque] = {}
        # source_ip -> deque of timestamps
        self._syn_flood_state: Dict[str, deque] = {}
        # source_ip -> deque of (timestamp, dst_ip)
        self._icmp_sweep_state: Dict[str, deque] = {}

        # Alert Suppression: (source_ip, rule_name) -> last_alert_time
        self._alert_cooldowns: Dict[Tuple[str, str], float] = {}

        # Bounded in-memory event store
        self.event_history: deque = deque(maxlen=max_alert_history)
        self._event_callbacks: List[Callable[[SecurityEvent], None]] = []
        self._last_cleanup = 0.0

    def add_event_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for generated security events (e.g. Socket.IO emission)."""
        self._event_callbacks.append(callback)

    def _is_in_cooldown(self, source_ip: str, rule_name: str, now: float) -> bool:
        """Check if an alert for (source_ip, rule_name) should be suppressed."""
        last_time = self._alert_cooldowns.get((source_ip, rule_name))
        if last_time is not None:
            cooldown = self.icmp_sweep_cooldown_sec if rule_name == "ICMP_SWEEP" else self.alert_cooldown_sec
            if (now - last_time) < cooldown:
                return True
        return False

    def _mark_alerted(self, source_ip: str, rule_name: str, now: float) -> None:
        """Record the timestamp of a newly emitted alert for cooldown tracking."""
        self._alert_cooldowns[(source_ip, rule_name)] = now

    def _prune_state_if_needed(self, now: float, force: bool = False) -> None:
        """Periodically clean up inactive tracking state to prevent unbounded memory growth."""
        if not force and abs(now - self._last_cleanup) < self.state_cleanup_sec:
            return

        self._last_cleanup = now

        # Prune inactive port scan tracking
        cutoff_port = now - self.port_scan_window_sec
        stale_port_ips = []
        for ip, probes in self._port_scan_state.items():
            while probes and probes[0][0] < cutoff_port:
                probes.popleft()
            if not probes:
                stale_port_ips.append(ip)
        for ip in stale_port_ips:
            del self._port_scan_state[ip]

        # Prune inactive SYN flood tracking
        cutoff_syn = now - self.syn_flood_window_sec
        stale_syn_ips = []
        for ip, timestamps in self._syn_flood_state.items():
            while timestamps and timestamps[0] < cutoff_syn:
                timestamps.popleft()
            if not timestamps:
                stale_syn_ips.append(ip)
        for ip in stale_syn_ips:
            del self._syn_flood_state[ip]

        # Prune inactive ICMP sweep tracking
        cutoff_icmp = now - self.icmp_sweep_window_sec
        stale_icmp_ips = []
        for ip, probes in self._icmp_sweep_state.items():
            while probes and probes[0][0] < cutoff_icmp:
                probes.popleft()
            if not probes:
                stale_icmp_ips.append(ip)
        for ip in stale_icmp_ips:
            del self._icmp_sweep_state[ip]

        # Prune expired alert cooldowns
        cutoff_cooldown = now - (max(self.alert_cooldown_sec, self.icmp_sweep_cooldown_sec) * 2)
        stale_cooldowns = [
            key for key, ts in self._alert_cooldowns.items() if ts < cutoff_cooldown
        ]
        for key in stale_cooldowns:
            del self._alert_cooldowns[key]

    def _enforce_max_ips(self) -> None:
        """Enforce maximum tracked IP limit by discarding oldest records if overloaded."""
        while len(self._port_scan_state) >= self.max_tracked_ips:
            oldest_ip = next(iter(self._port_scan_state))
            del self._port_scan_state[oldest_ip]

        while len(self._syn_flood_state) >= self.max_tracked_ips:
            oldest_ip = next(iter(self._syn_flood_state))
            del self._syn_flood_state[oldest_ip]

        while len(self._icmp_sweep_state) >= self.max_tracked_ips:
            oldest_ip = next(iter(self._icmp_sweep_state))
            del self._icmp_sweep_state[oldest_ip]

    def detect_port_scan(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """Detect Port Scan activity based on unique destination ports probed within window."""
        if not packet.src_ip or packet.dst_port is None:
            return None

        # Port scan detection applies to transport traffic (TCP/UDP)
        if packet.protocol not in (6, 17):
            return None

        now = packet.timestamp or time.time()
        src_ip = packet.src_ip
        dst_port = packet.dst_port

        if src_ip not in self._port_scan_state:
            self._enforce_max_ips()
            self._port_scan_state[src_ip] = deque()

        probes = self._port_scan_state[src_ip]
        probes.append((now, dst_port))

        # Evict probes outside the active time window
        cutoff = now - self.port_scan_window_sec
        while probes and probes[0][0] < cutoff:
            probes.popleft()

        unique_ports: Set[int] = {port for _, port in probes}

        if len(unique_ports) >= self.port_scan_threshold:
            if not self._is_in_cooldown(src_ip, "PORT_SCAN", now):
                self._mark_alerted(src_ip, "PORT_SCAN", now)
                sample_ports = sorted(list(unique_ports))[:10]
                event = SecurityEvent(
                    event_id=uuid.uuid4().hex[:12],
                    timestamp=now,
                    detection_type="PORT_SCAN",
                    severity="MEDIUM",
                    source_ip=src_ip,
                    destination_ip=packet.dst_ip,
                    protocol=packet.protocol_name or "TCP",
                    source_port=packet.src_port,
                    destination_port=dst_port,
                    description=(
                        f"Port scan detected: {len(unique_ports)} distinct destination ports "
                        f"probed within {self.port_scan_window_sec:.1f}s window."
                    ),
                    evidence={
                        "unique_ports_count": len(unique_ports),
                        "window_seconds": self.port_scan_window_sec,
                        "threshold": self.port_scan_threshold,
                        "sample_ports": sample_ports,
                    },
                    rule_name="RULE_PORT_SCAN",
                )
                return event

        return None

    def detect_syn_flood(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """Detect SYN Flood activity based on excessive TCP SYN rates within window."""
        if not packet.src_ip or packet.protocol != 6 or not packet.tcp_flags:
            return None

        # Match isolated SYN packet (connection request without ACK)
        if not (packet.tcp_flags.get("SYN") and not packet.tcp_flags.get("ACK")):
            return None

        now = packet.timestamp or time.time()
        src_ip = packet.src_ip

        if src_ip not in self._syn_flood_state:
            self._enforce_max_ips()
            self._syn_flood_state[src_ip] = deque()

        syn_times = self._syn_flood_state[src_ip]
        syn_times.append(now)

        # Evict timestamps outside the active time window
        cutoff = now - self.syn_flood_window_sec
        while syn_times and syn_times[0] < cutoff:
            syn_times.popleft()

        syn_count = len(syn_times)
        if syn_count >= self.syn_flood_threshold:
            if not self._is_in_cooldown(src_ip, "SYN_FLOOD", now):
                self._mark_alerted(src_ip, "SYN_FLOOD", now)
                rate = round(syn_count / self.syn_flood_window_sec, 2)
                event = SecurityEvent(
                    event_id=uuid.uuid4().hex[:12],
                    timestamp=now,
                    detection_type="SYN_FLOOD",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=packet.dst_ip,
                    protocol="TCP",
                    source_port=packet.src_port,
                    destination_port=packet.dst_port,
                    description=(
                        f"SYN flood detected: {syn_count} SYN packets observed "
                        f"within {self.syn_flood_window_sec:.1f}s window ({rate} pps)."
                    ),
                    evidence={
                        "syn_count": syn_count,
                        "window_seconds": self.syn_flood_window_sec,
                        "threshold": self.syn_flood_threshold,
                        "syn_rate_pps": rate,
                    },
                    rule_name="RULE_SYN_FLOOD",
                )
                return event

        return None

    def detect_null_scan(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """Detect NULL Scan stealth probe (TCP segment with all control flags cleared)."""
        if not self.null_scan_enabled:
            return None

        if not packet.src_ip or packet.protocol != 6 or packet.tcp_flags is None:
            return None

        # Check if all 6 standard flags are False
        flags = packet.tcp_flags
        if not (flags.get("SYN") or flags.get("ACK") or flags.get("FIN") or 
                flags.get("RST") or flags.get("PSH") or flags.get("URG")):
            now = packet.timestamp or time.time()
            src_ip = packet.src_ip

            if not self._is_in_cooldown(src_ip, "NULL_SCAN", now):
                self._mark_alerted(src_ip, "NULL_SCAN", now)
                event = SecurityEvent(
                    event_id=uuid.uuid4().hex[:12],
                    timestamp=now,
                    detection_type="NULL_SCAN",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=packet.dst_ip,
                    protocol="TCP",
                    source_port=packet.src_port,
                    destination_port=packet.dst_port,
                    description="Stealth NULL scan detected: TCP packet with all flags set to 0.",
                    evidence={
                        "raw_tcp_flags": packet.raw_tcp_flags or 0,
                        "probed_port": packet.dst_port,
                    },
                    rule_name="RULE_NULL_SCAN",
                )
                return event

        return None

    def detect_xmas_scan(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """Detect XMAS Scan stealth probe (TCP segment with FIN, PSH, and URG flags set)."""
        if not self.xmas_scan_enabled:
            return None

        if not packet.src_ip or packet.protocol != 6 or packet.tcp_flags is None:
            return None

        flags = packet.tcp_flags
        # Classic XMAS: FIN, PSH, URG active (without SYN, ACK, RST)
        if (flags.get("FIN") and flags.get("PSH") and flags.get("URG") and
                not flags.get("SYN") and not flags.get("ACK") and not flags.get("RST")):
            now = packet.timestamp or time.time()
            src_ip = packet.src_ip

            if not self._is_in_cooldown(src_ip, "XMAS_SCAN", now):
                self._mark_alerted(src_ip, "XMAS_SCAN", now)
                event = SecurityEvent(
                    event_id=uuid.uuid4().hex[:12],
                    timestamp=now,
                    detection_type="XMAS_SCAN",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=packet.dst_ip,
                    protocol="TCP",
                    source_port=packet.src_port,
                    destination_port=packet.dst_port,
                    description="Stealth XMAS scan detected: TCP packet with FIN, PSH, and URG flags active.",
                    evidence={
                        "raw_tcp_flags": packet.raw_tcp_flags or 0,
                        "probed_port": packet.dst_port,
                    },
                    rule_name="RULE_XMAS_SCAN",
                )
                return event

        return None

    def detect_icmp_sweep(self, packet: ParsedPacket) -> Optional[SecurityEvent]:
        """Detect ICMP Sweep / ping scan probing multiple target hosts within window."""
        # Must be ICMP Echo Request (packet.protocol == 1 and icmp_type == 8)
        if not packet.src_ip or packet.protocol != 1 or packet.icmp_type != 8 or not packet.dst_ip:
            return None

        # Filter out multicast, loopback, broadcast, and invalid addresses
        try:
            target = ipaddress.ip_address(packet.dst_ip)
            if target.is_multicast or target.is_loopback or target.is_unspecified or target.is_link_local:
                return None
            if str(target) == "255.255.255.255":
                return None
        except ValueError:
            return None

        now = packet.timestamp or time.time()
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip

        if src_ip not in self._icmp_sweep_state:
            self._enforce_max_ips()
            self._icmp_sweep_state[src_ip] = deque()

        probes = self._icmp_sweep_state[src_ip]
        probes.append((now, dst_ip))

        # Evict probes outside the active time window
        cutoff = now - self.icmp_sweep_window_sec
        while probes and probes[0][0] < cutoff:
            probes.popleft()

        unique_dsts: Set[str] = {dst for _, dst in probes}

        if len(unique_dsts) >= self.icmp_sweep_threshold:
            if not self._is_in_cooldown(src_ip, "ICMP_SWEEP", now):
                self._mark_alerted(src_ip, "ICMP_SWEEP", now)
                sample_dsts = sorted(list(unique_dsts))[:10]
                event = SecurityEvent(
                    event_id=uuid.uuid4().hex[:12],
                    timestamp=now,
                    detection_type="ICMP_SWEEP",
                    severity="MEDIUM",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="ICMP",
                    description=(
                        f"ICMP sweep detected: {len(unique_dsts)} distinct destination hosts "
                        f"probed with ICMP Echo Requests within {self.icmp_sweep_window_sec:.1f}s window."
                    ),
                    evidence={
                        "unique_hosts_count": len(unique_dsts),
                        "window_seconds": self.icmp_sweep_window_sec,
                        "threshold": self.icmp_sweep_threshold,
                        "sample_destinations": sample_dsts,
                    },
                    rule_name="RULE_ICMP_SWEEP",
                )
                return event

        return None

    def analyze_packet(self, packet: ParsedPacket) -> List[SecurityEvent]:
        """Process a structured ParsedPacket through all active detection rules.

        Thread-safe entry point for packet capture callbacks.

        Args:
            packet: ParsedPacket dataclass from parser.py.

        Returns:
            List of generated SecurityEvent instances (if any triggered).
        """
        if not packet or packet.error or not packet.src_ip:
            return []

        now = packet.timestamp or time.time()
        new_events: List[SecurityEvent] = []

        with self._lock:
            self._prune_state_if_needed(now)

            # 1. Evaluate Port Scan rule
            ps_event = self.detect_port_scan(packet)
            if ps_event:
                new_events.append(ps_event)

            # 2. Evaluate SYN Flood rule
            sf_event = self.detect_syn_flood(packet)
            if sf_event:
                new_events.append(sf_event)

            # 3. Evaluate NULL Scan rule
            null_event = self.detect_null_scan(packet)
            if null_event:
                new_events.append(null_event)

            # 4. Evaluate XMAS Scan rule
            xmas_event = self.detect_xmas_scan(packet)
            if xmas_event:
                new_events.append(xmas_event)

            # 5. Evaluate ICMP Sweep rule
            icmp_event = self.detect_icmp_sweep(packet)
            if icmp_event:
                new_events.append(icmp_event)

            # Store and dispatch generated events
            for evt in new_events:
                self.event_history.append(evt)
                for cb in self._event_callbacks:
                    try:
                        cb(evt)
                    except Exception as err:
                        logger.debug("Error in event callback: %s", err)

        return new_events

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent security alerts in newest-first order.

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of JSON-serializable alert dictionaries.
        """
        with self._lock:
            events = list(self.event_history)
            events.reverse()
            return [evt.to_dict() for evt in events[:limit]]
