"""NetSentinel Linux iptables Firewall Management Module.

Provides safe, reversible Linux iptables mitigation for malicious source IP addresses.
Operates exclusively on a dedicated managed chain (NETSENTINEL) without touching global rules.
Implements strict safety safeguards against blocking loopback, broadcast, multicast,
local machine addresses, or operator-allowlisted IP ranges.
"""

from dataclasses import dataclass, asdict
import ipaddress
import logging
import os
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set
import psutil

from config import Config

logger = logging.getLogger("netsentinel.firewall")


@dataclass
class BlockRecord:
    """Metadata for an actively blocked IP address."""
    ip: str
    blocked_at: float
    expires_at: Optional[float]
    reason: str
    risk_score: float
    assessment_id: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert block record dataclass to JSON-serializable dictionary."""
        return asdict(self)


class FirewallManager:
    """Safe Linux iptables manager operating on an isolated NetSentinel chain."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or Config.FIREWALL_SETTINGS

        self.enabled = bool(cfg.get("enabled", False))
        self.auto_block = bool(cfg.get("auto_block", False))
        self.dry_run = bool(cfg.get("dry_run", True))
        self.chain = str(cfg.get("chain", "NETSENTINEL")).strip()
        self.block_duration = float(cfg.get("block_duration", 300.0))
        self.max_blocked_ips = int(cfg.get("max_blocked_ips", 500))
        self.allowlist_configured: List[str] = list(cfg.get("allowlist", ["127.0.0.1", "::1"]))

        self._lock = threading.RLock()
        self._blocked_ips: Dict[str, BlockRecord] = {}
        self._chain_initialized = False

        # Gather local host addresses
        self._local_addresses: Set[str] = self._discover_local_addresses()

        logger.info(
            "FirewallManager initialized (enabled=%s, auto_block=%s, dry_run=%s, chain=%s)",
            self.enabled,
            self.auto_block,
            self.dry_run,
            self.chain,
        )

    def _discover_local_addresses(self) -> Set[str]:
        """Discover all active network interface IP addresses for host self-protection."""
        local_ips: Set[str] = {"127.0.0.1", "::1"}
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.address:
                        # Strip IPv6 scope ID if present (e.g. %eth0)
                        ip_clean = addr.address.split("%")[0].strip()
                        try:
                            ipaddress.ip_address(ip_clean)
                            local_ips.add(ip_clean)
                        except ValueError:
                            pass
        except Exception as ex:
            logger.debug("Failed discovering local interfaces: %s", ex)
        return local_ips

    def is_safe_to_block(self, ip_str: str) -> tuple[bool, str]:
        """Verify whether an IP address is safe to block.

        Guards against blocking loopback, broadcast, multicast, local interface addresses,
        or operator-configured allowlisted IPs.
        """
        if not ip_str or not isinstance(ip_str, str):
            return False, "Invalid or empty IP address"

        clean_ip = ip_str.strip()

        # 1. Parse and validate IP syntax
        try:
            parsed = ipaddress.ip_address(clean_ip)
        except ValueError:
            return False, f"Malformed IP address: '{clean_ip}'"

        # 2. Check special and reserved addresses
        if parsed.is_loopback:
            return False, "Loopback addresses cannot be blocked"
        if parsed.is_multicast:
            return False, "Multicast addresses cannot be blocked"
        if parsed.is_unspecified:
            return False, "Unspecified addresses (0.0.0.0 / ::) cannot be blocked"
        if parsed.is_reserved:
            return False, "Reserved network addresses cannot be blocked"

        # Broadcast check for IPv4
        if parsed.version == 4 and clean_ip == "255.255.255.255":
            return False, "Global broadcast address cannot be blocked"

        # 3. Check local machine addresses
        if clean_ip in self._local_addresses:
            return False, f"Host local machine address '{clean_ip}' cannot be blocked"

        # 4. Check operator allowlist
        for allowed in self.allowlist_configured:
            try:
                if "/" in allowed:
                    network = ipaddress.ip_network(allowed.strip(), strict=False)
                    if parsed in network:
                        return False, f"IP belongs to allowlisted network '{allowed}'"
                else:
                    if parsed == ipaddress.ip_address(allowed.strip()):
                        return False, f"IP matches allowlisted address '{allowed}'"
            except ValueError:
                pass

        return True, "Safe to block"

    def _run_iptables_command(self, args: List[str]) -> tuple[bool, str]:
        """Execute iptables command safely via argument array without shell expansion."""
        cmd = ["iptables"] + args
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if proc.returncode == 0:
                return True, proc.stdout.strip()
            err = proc.stderr.strip() or f"iptables exited with code {proc.returncode}"
            return False, err
        except FileNotFoundError:
            return False, "iptables command not found on host system"
        except subprocess.TimeoutExpired:
            return False, "iptables command timed out"
        except PermissionError:
            return False, "Permission denied executing iptables (requires root or CAP_NET_ADMIN)"
        except Exception as ex:
            return False, f"Unexpected error executing iptables: {str(ex)}"

    def _ensure_chain_exists(self) -> bool:
        """Create dedicated NetSentinel chain and attach it to INPUT if not yet present."""
        if not self.enabled or self.dry_run:
            return True

        if self._chain_initialized:
            return True

        # Check if chain exists or create it
        success, _ = self._run_iptables_command(["-N", self.chain])
        # Even if -N returned error because chain already exists, proceed to link check

        # Verify whether INPUT chain jumps to NETSENTINEL
        check_jump, _ = self._run_iptables_command(["-C", "INPUT", "-j", self.chain])
        if not check_jump:
            # Insert jump at position 1 of INPUT chain
            link_success, link_err = self._run_iptables_command(["-I", "INPUT", "1", "-j", self.chain])
            if not link_success:
                logger.warning("Failed linking %s chain to INPUT: %s", self.chain, link_err)
                return False

        self._chain_initialized = True
        logger.info("Dedicated iptables chain '%s' initialized and linked to INPUT.", self.chain)
        return True

    def block_ip(
        self,
        ip_address: str,
        reason: str = "Automated Security Mitigation",
        duration: Optional[float] = None,
        risk_score: float = 0.0,
        assessment_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Block a source IP address on the dedicated managed chain."""
        clean_ip = str(ip_address).strip()
        safe, msg = self.is_safe_to_block(clean_ip)
        if not safe:
            return {
                "success": False,
                "action": "block",
                "ip": clean_ip,
                "status": "rejected",
                "message": msg,
            }

        now = time.time()
        block_len = duration if duration is not None else self.block_duration
        expires_at = (now + block_len) if block_len > 0 else None

        with self._lock:
            # Prune any expired blocks before checking capacity
            self.cleanup_expired_blocks(now)

            if clean_ip in self._blocked_ips:
                # Update existing record
                rec = self._blocked_ips[clean_ip]
                rec.expires_at = expires_at
                rec.reason = reason
                rec.risk_score = risk_score
                return {
                    "success": True,
                    "action": "block",
                    "ip": clean_ip,
                    "status": "already_blocked",
                    "expires_at": expires_at,
                    "message": f"IP {clean_ip} is already blocked; updated expiration.",
                }

            if len(self._blocked_ips) >= self.max_blocked_ips:
                return {
                    "success": False,
                    "action": "block",
                    "ip": clean_ip,
                    "status": "limit_reached",
                    "message": f"Maximum managed block capacity ({self.max_blocked_ips}) reached.",
                }

            # If firewall is disabled or dry run, simulate
            if not self.enabled or self.dry_run:
                self._blocked_ips[clean_ip] = BlockRecord(
                    ip=clean_ip,
                    blocked_at=now,
                    expires_at=expires_at,
                    reason=reason,
                    risk_score=risk_score,
                    assessment_id=assessment_id,
                )
                mode_str = "disabled" if not self.enabled else "dry_run"
                return {
                    "success": True,
                    "action": "block",
                    "ip": clean_ip,
                    "status": "simulated",
                    "mode": mode_str,
                    "expires_at": expires_at,
                    "message": f"Simulated block for {clean_ip} ({mode_str} mode).",
                }

            # Real iptables execution
            self._ensure_chain_exists()
            ok, err = self._run_iptables_command(["-I", self.chain, "1", "-s", clean_ip, "-j", "DROP"])
            if not ok:
                return {
                    "success": False,
                    "action": "block",
                    "ip": clean_ip,
                    "status": "error",
                    "message": f"Failed inserting iptables rule: {err}",
                }

            self._blocked_ips[clean_ip] = BlockRecord(
                ip=clean_ip,
                blocked_at=now,
                expires_at=expires_at,
                reason=reason,
                risk_score=risk_score,
                assessment_id=assessment_id,
            )
            logger.info("IP %s blocked in iptables chain %s (reason: %s).", clean_ip, self.chain, reason)
            return {
                "success": True,
                "action": "block",
                "ip": clean_ip,
                "status": "active",
                "expires_at": expires_at,
                "message": f"Successfully blocked {clean_ip} in {self.chain}.",
            }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove an IP address from the managed blocked list and iptables chain."""
        clean_ip = str(ip_address).strip()

        with self._lock:
            if clean_ip not in self._blocked_ips:
                return {
                    "success": False,
                    "action": "unblock",
                    "ip": clean_ip,
                    "status": "not_found",
                    "message": f"IP {clean_ip} is not currently in managed block list.",
                }

            del self._blocked_ips[clean_ip]

            if not self.enabled or self.dry_run:
                return {
                    "success": True,
                    "action": "unblock",
                    "ip": clean_ip,
                    "status": "simulated",
                    "message": f"Simulated unblock for {clean_ip}.",
                }

            # Real iptables rule deletion
            ok, err = self._run_iptables_command(["-D", self.chain, "-s", clean_ip, "-j", "DROP"])
            if not ok:
                logger.warning("iptables delete rule error for %s: %s", clean_ip, err)
                return {
                    "success": True,
                    "action": "unblock",
                    "ip": clean_ip,
                    "status": "warning",
                    "message": f"Removed from internal state, but iptables returned: {err}",
                }

            logger.info("IP %s unblocked from iptables chain %s.", clean_ip, self.chain)
            return {
                "success": True,
                "action": "unblock",
                "ip": clean_ip,
                "status": "active",
                "message": f"Successfully unblocked {clean_ip} from {self.chain}.",
            }

    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP address is currently blocked and unexpired."""
        clean_ip = str(ip_address).strip()
        now = time.time()
        with self._lock:
            rec = self._blocked_ips.get(clean_ip)
            if not rec:
                return False
            if rec.expires_at is not None and now >= rec.expires_at:
                self.unblock_ip(clean_ip)
                return False
            return True

    def list_blocked_ips(self) -> List[Dict[str, Any]]:
        """Retrieve list of all active managed blocked IPs."""
        now = time.time()
        with self._lock:
            self.cleanup_expired_blocks(now)
            records = [rec.to_dict() for rec in self._blocked_ips.values()]
            # Newest blocks first
            records.sort(key=lambda r: r["blocked_at"], reverse=True)
            return records

    def clear_managed_rules(self) -> Dict[str, Any]:
        """Flush ONLY the managed NetSentinel chain without touching global iptables rules."""
        with self._lock:
            cleared_count = len(self._blocked_ips)
            self._blocked_ips.clear()

            if not self.enabled or self.dry_run:
                return {
                    "success": True,
                    "cleared_count": cleared_count,
                    "status": "simulated",
                    "message": f"Simulated flush of managed {self.chain} chain ({cleared_count} IPs cleared).",
                }

            # Flush ONLY the dedicated chain! NEVER global chains!
            ok, err = self._run_iptables_command(["-F", self.chain])
            if not ok:
                return {
                    "success": False,
                    "cleared_count": cleared_count,
                    "status": "error",
                    "message": f"Failed flushing {self.chain}: {err}",
                }

            logger.info("Flushed managed chain %s (%d rules cleared).", self.chain, cleared_count)
            return {
                "success": True,
                "cleared_count": cleared_count,
                "status": "active",
                "message": f"Flushed managed chain {self.chain}.",
            }

    def cleanup_expired_blocks(self, now: Optional[float] = None) -> int:
        """Clean up all temporary blocks that have exceeded their expiration duration."""
        current_time = now or time.time()
        expired_ips: List[str] = []

        with self._lock:
            for ip, rec in self._blocked_ips.items():
                if rec.expires_at is not None and current_time >= rec.expires_at:
                    expired_ips.append(ip)

            for ip in expired_ips:
                self.unblock_ip(ip)

        if expired_ips:
            logger.info("Cleaned up %d expired IP blocks: %s", len(expired_ips), expired_ips)
        return len(expired_ips)

    def get_status(self) -> Dict[str, Any]:
        """Return read-only status dictionary for REST APIs and dashboard."""
        now = time.time()
        with self._lock:
            self.cleanup_expired_blocks(now)
            return {
                "enabled": self.enabled,
                "auto_block": self.auto_block,
                "dry_run": self.dry_run,
                "chain": self.chain,
                "block_duration": self.block_duration,
                "blocked_count": len(self._blocked_ips),
                "max_blocked_ips": self.max_blocked_ips,
                "allowlist": self.allowlist_configured,
            }
