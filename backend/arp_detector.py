"""NetSentinel ARP Threat Detector Module.

Implements stateful ARP traffic inspection to detect:
1. ARP Spoofing / Poisoning (rapid or conflicting MAC address claiming an active IP)
2. ARP Identity Conflict (single MAC claiming an excessive number of distinct IPs)

Maintains bounded in-memory IP-to-MAC state tables with automatic expiration,
trusted static bindings, alert cooldowns, and zero external ARP commands.
"""

from collections import deque
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from config import Config
from detector import SecurityEvent
from parser import ParsedPacket

logger = logging.getLogger("netsentinel.arp_detector")


class ARPDetector:
    """Stateful ARP threat detection engine."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}

        self.enabled = bool(cfg.get("arp_enabled", True))
        self.state_timeout = float(cfg.get("arp_state_timeout", 300.0))
        self.max_tracked_ips = int(cfg.get("arp_max_tracked_ips", 1000))
        self.max_tracked_macs = int(cfg.get("arp_max_tracked_macs", 1000))
        self.cooldown_sec = float(cfg.get("arp_cooldown_sec", 60.0))
        self.conflict_threshold = int(cfg.get("arp_conflict_threshold", 3))

        # Normalize trusted mappings to lower-case MACs
        raw_trusted = cfg.get("arp_trusted_mappings", {})
        self.trusted_mappings: Dict[str, str] = {
            ip.strip(): mac.strip().lower()
            for ip, mac in raw_trusted.items()
            if ip and mac
        }

        self._lock = threading.Lock()

        # State tracking:
        # IP -> {"ip": ip, "mac": mac, "first_seen": ts, "last_seen": ts, "claims_count": int, "is_trusted": bool}
        self._ip_to_mac: Dict[str, Dict[str, Any]] = {}

        # MAC -> {ip: last_seen_ts}
        self._mac_to_ips: Dict[str, Dict[str, float]] = {}

        # Alert cooldown tracking: (key, rule_name) -> timestamp
        self._alert_cooldowns: Dict[Tuple[str, str], float] = {}

        # Event history and callbacks
        max_history = int(cfg.get("max_alert_history", 100))
        self.event_history: deque = deque(maxlen=max_history)
        self._event_callbacks: List[Callable[[SecurityEvent], None]] = []

        # Lifetime counters
        self._stats: Dict[str, int] = {
            "total_arp_packets": 0,
            "arp_requests": 0,
            "arp_replies": 0,
            "gratuitous_arp": 0,
            "spoofing_alerts": 0,
            "conflict_alerts": 0,
        }
        self._last_cleanup = 0.0

        # Pre-seed trusted mappings into the state table
        now = time.time()
        for tip, tmac in self.trusted_mappings.items():
            self._ip_to_mac[tip] = {
                "ip": tip,
                "mac": tmac,
                "first_seen": now,
                "last_seen": now,
                "claims_count": 0,
                "is_trusted": True,
            }
            if tmac not in self._mac_to_ips:
                self._mac_to_ips[tmac] = {}
            self._mac_to_ips[tmac][tip] = now

    def add_event_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for generated ARP security events."""
        self._event_callbacks.append(callback)

    def _is_in_cooldown(self, identifier: str, rule_name: str, now: float) -> bool:
        """Check if an alert for (identifier, rule_name) should be suppressed."""
        last_time = self._alert_cooldowns.get((identifier, rule_name))
        if last_time is not None and (now - last_time) < self.cooldown_sec:
            return True
        return False

    def _mark_alerted(self, identifier: str, rule_name: str, now: float) -> None:
        """Record the timestamp of an emitted alert for suppression."""
        self._alert_cooldowns[(identifier, rule_name)] = now

    def _cleanup_stale_state(self, now: float, force: bool = False) -> None:
        """Prune inactive IP and MAC mappings to avoid unbounded memory."""
        if not force and abs(now - self._last_cleanup) < 30.0:
            return

        self._last_cleanup = now
        cutoff = now - self.state_timeout

        # Prune IP-to-MAC mappings (preserve static trusted entries)
        stale_ips = [
            ip for ip, entry in self._ip_to_mac.items()
            if not entry.get("is_trusted", False) and entry.get("last_seen", 0.0) < cutoff
        ]
        for ip in stale_ips:
            del self._ip_to_mac[ip]

        # Prune MAC-to-IP mappings
        stale_macs = []
        for mac, ip_dict in self._mac_to_ips.items():
            expired_ips = [ip for ip, ts in ip_dict.items() if ts < cutoff]
            for eip in expired_ips:
                # Do not delete trusted mapping from MAC list if trusted
                if eip not in self.trusted_mappings:
                    del ip_dict[eip]
            if not ip_dict:
                stale_macs.append(mac)

        for mac in stale_macs:
            del self._mac_to_ips[mac]

        # Prune alert cooldowns
        cooldown_cutoff = now - (self.cooldown_sec * 2)
        stale_cooldowns = [
            key for key, ts in self._alert_cooldowns.items()
            if ts < cooldown_cutoff
        ]
        for key in stale_cooldowns:
            del self._alert_cooldowns[key]

    def _enforce_max_limits(self) -> None:
        """Enforce maximum tracked IP and MAC bounds via FIFO/LRU eviction."""
        while len(self._ip_to_mac) >= self.max_tracked_ips:
            # Find oldest non-trusted IP
            oldest_ip = None
            oldest_ts = float("inf")
            for ip, entry in self._ip_to_mac.items():
                if not entry.get("is_trusted", False) and entry.get("last_seen", 0.0) < oldest_ts:
                    oldest_ts = entry["last_seen"]
                    oldest_ip = ip

            if oldest_ip:
                del self._ip_to_mac[oldest_ip]
            else:
                # All entries are trusted; break to prevent infinite loop
                break

        while len(self._mac_to_ips) >= self.max_tracked_macs:
            oldest_mac = next(iter(self._mac_to_ips))
            del self._mac_to_ips[oldest_mac]

    def process_packet(self, packet: ParsedPacket) -> List[SecurityEvent]:
        """Inspect a parsed packet for ARP-related anomalies and spoofing.

        Thread-safe entry point for packet capture callbacks.
        """
        if not self.enabled or not packet or not packet.arp_info:
            return []

        arp = packet.arp_info
        sender_ip = (arp.sender_ip or "").strip()
        sender_mac = (arp.sender_mac or "").strip().lower()

        # Ignore invalid/reserved addresses (e.g. 0.0.0.0 probe in RFC 5227 ACD)
        if not sender_ip or sender_ip == "0.0.0.0" or not sender_mac:
            return []
        if sender_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return []

        now = packet.timestamp or time.time()
        new_events: List[SecurityEvent] = []

        with self._lock:
            # 1. Update general ARP statistics
            self._stats["total_arp_packets"] += 1
            if arp.operation == 1:
                self._stats["arp_requests"] += 1
            elif arp.operation == 2:
                self._stats["arp_replies"] += 1

            if arp.is_gratuitous:
                self._stats["gratuitous_arp"] += 1

            self._cleanup_stale_state(now)

            # 2. Evaluate ARP Spoofing / Poisoning
            if sender_ip in self._ip_to_mac:
                entry = self._ip_to_mac[sender_ip]
                is_trusted = entry.get("is_trusted", False) or (sender_ip in self.trusted_mappings)
                last_seen = entry.get("last_seen", 0.0)

                # Check if prior mapping expired (and is not a static trusted mapping)
                if not is_trusted and (now - last_seen) > self.state_timeout:
                    # Previous lease expired; reassign without alert
                    entry["mac"] = sender_mac
                    entry["first_seen"] = now
                    entry["last_seen"] = now
                    entry["claims_count"] = 1
                elif entry.get("mac") != sender_mac:
                    # Active mapping conflict detected!
                    old_mac = entry.get("mac")
                    if not self._is_in_cooldown(sender_ip, "ARP_SPOOFING", now):
                        self._mark_alerted(sender_ip, "ARP_SPOOFING", now)
                        self._stats["spoofing_alerts"] += 1

                        desc = (
                            f"ARP spoofing / poisoning detected: IP {sender_ip} previously mapped to "
                            f"{old_mac} is now claimed by {sender_mac}."
                        )
                        if is_trusted:
                            desc = (
                                f"ARP spoofing detected: Claimed MAC {sender_mac} conflicts with "
                                f"authoritative trusted mapping {old_mac} for IP {sender_ip}."
                            )

                        event = SecurityEvent(
                            event_id=uuid.uuid4().hex[:12],
                            timestamp=now,
                            detection_type="ARP_SPOOFING",
                            severity="HIGH",
                            source_ip=sender_ip,
                            destination_ip=arp.target_ip,
                            protocol="ARP",
                            description=desc,
                            evidence={
                                "ip": sender_ip,
                                "original_mac": old_mac,
                                "claimed_mac": sender_mac,
                                "operation": arp.operation_name,
                                "is_gratuitous": arp.is_gratuitous,
                                "is_trusted_target": is_trusted,
                                "target_ip": arp.target_ip,
                                "target_mac": arp.target_mac,
                            },
                            rule_name="RULE_ARP_SPOOFING",
                        )
                        new_events.append(event)

                    if not is_trusted:
                        entry["mac"] = sender_mac
                    entry["last_seen"] = now
                    entry["claims_count"] = entry.get("claims_count", 0) + 1
                else:
                    # Normal update: same MAC confirming assignment
                    entry["last_seen"] = now
                    entry["claims_count"] = entry.get("claims_count", 0) + 1
            else:
                # First time seeing this IP
                # Check conflict with static trusted mappings
                is_trusted = sender_ip in self.trusted_mappings
                trusted_mac = self.trusted_mappings.get(sender_ip)
                if trusted_mac and trusted_mac != sender_mac:
                    if not self._is_in_cooldown(sender_ip, "ARP_SPOOFING", now):
                        self._mark_alerted(sender_ip, "ARP_SPOOFING", now)
                        self._stats["spoofing_alerts"] += 1
                        event = SecurityEvent(
                            event_id=uuid.uuid4().hex[:12],
                            timestamp=now,
                            detection_type="ARP_SPOOFING",
                            severity="HIGH",
                            source_ip=sender_ip,
                            destination_ip=arp.target_ip,
                            protocol="ARP",
                            description=(
                                f"ARP spoofing detected: Claimed MAC {sender_mac} conflicts with "
                                f"static trusted binding {trusted_mac} for IP {sender_ip}."
                            ),
                            evidence={
                                "ip": sender_ip,
                                "original_mac": trusted_mac,
                                "claimed_mac": sender_mac,
                                "operation": arp.operation_name,
                                "is_gratuitous": arp.is_gratuitous,
                                "is_trusted_target": True,
                                "target_ip": arp.target_ip,
                                "target_mac": arp.target_mac,
                            },
                            rule_name="RULE_ARP_SPOOFING",
                        )
                        new_events.append(event)

                self._enforce_max_limits()
                self._ip_to_mac[sender_ip] = {
                    "ip": sender_ip,
                    "mac": trusted_mac if is_trusted else sender_mac,
                    "first_seen": now,
                    "last_seen": now,
                    "claims_count": 1,
                    "is_trusted": is_trusted,
                }

            # 3. Evaluate ARP Identity Conflict (one MAC claiming >= N distinct IPs)
            if sender_mac not in self._mac_to_ips:
                self._enforce_max_limits()
                self._mac_to_ips[sender_mac] = {}

            self._mac_to_ips[sender_mac][sender_ip] = now
            active_ips = [
                ip for ip, ts in self._mac_to_ips[sender_mac].items()
                if (now - ts) <= self.state_timeout
            ]

            if len(active_ips) >= self.conflict_threshold:
                if not self._is_in_cooldown(sender_mac, "ARP_IDENTITY_CONFLICT", now):
                    self._mark_alerted(sender_mac, "ARP_IDENTITY_CONFLICT", now)
                    self._stats["conflict_alerts"] += 1

                    sample_ips = sorted(active_ips)[:10]
                    event = SecurityEvent(
                        event_id=uuid.uuid4().hex[:12],
                        timestamp=now,
                        detection_type="ARP_IDENTITY_CONFLICT",
                        severity="MEDIUM",
                        source_ip=sender_ip,
                        destination_ip=arp.target_ip,
                        protocol="ARP",
                        description=(
                            f"ARP identity conflict: MAC {sender_mac} is actively claiming "
                            f"{len(active_ips)} distinct IP addresses."
                        ),
                        evidence={
                            "mac": sender_mac,
                            "claimed_ips_count": len(active_ips),
                            "threshold": self.conflict_threshold,
                            "sample_claimed_ips": sample_ips,
                            "operation": arp.operation_name,
                            "is_gratuitous": arp.is_gratuitous,
                        },
                        rule_name="RULE_ARP_IDENTITY_CONFLICT",
                    )
                    new_events.append(event)

            # 4. Dispatch events to history and registered callbacks
            for evt in new_events:
                self.event_history.append(evt)
                for cb in self._event_callbacks:
                    try:
                        cb(evt)
                    except Exception as err:
                        logger.debug("Error in ARP event callback: %s", err)

        return new_events

    def get_status(self) -> Dict[str, Any]:
        """Return operational status and metrics for the ARP detector."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "tracked_ips_count": len(self._ip_to_mac),
                "tracked_macs_count": len(self._mac_to_ips),
                "trusted_mappings_count": len(self.trusted_mappings),
                "state_timeout_sec": self.state_timeout,
                "cooldown_sec": self.cooldown_sec,
                "conflict_threshold": self.conflict_threshold,
                "stats": dict(self._stats),
            }

    def get_mappings(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return active ARP IP-to-MAC mappings newest last_seen first."""
        with self._lock:
            items = list(self._ip_to_mac.values())
            items.sort(key=lambda x: x.get("last_seen", 0.0), reverse=True)
            return items[:max(1, min(limit, 1000))]

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent ARP security alerts newest first."""
        with self._lock:
            events = list(self.event_history)
            events.reverse()
            return [evt.to_dict() for evt in events[:limit]]
