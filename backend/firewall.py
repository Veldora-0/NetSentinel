"""NetSentinel Firewall Management Module.

Reserved for automated IP blocking, unblocking, and Linux iptables chain rule management.

Note: Real iptables execution is reserved for future phases.
"""

from typing import Any, Dict, List, Optional


class FirewallManager:
    """Interface for Linux iptables firewall rule management."""

    def __init__(self, dry_run: bool = True):
        """Initialize FirewallManager.

        Args:
            dry_run: When True, firewall actions are logged without invoking iptables.
        """
        self.dry_run = dry_run

    def block_ip(self, ip_address: str, reason: str = "Manual Block") -> Dict[str, Any]:
        """Add an IP address to the iptables drop rule.

        Note: Real iptables shell execution is disabled in this initial foundation phase.
        """
        return {
            "status": "simulated",
            "action": "block",
            "ip": ip_address,
            "reason": reason,
            "message": "Firewall command execution will be enabled in a future phase.",
        }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Remove an IP address from the iptables block rule.

        Note: Real iptables shell execution is disabled in this initial foundation phase.
        """
        return {
            "status": "simulated",
            "action": "unblock",
            "ip": ip_address,
            "message": "Firewall command execution will be enabled in a future phase.",
        }

    def list_blocked_ips(self) -> List[Dict[str, Any]]:
        """Retrieve list of currently blocked IP addresses.

        Returns:
            List of blocked IP metadata records.
        """
        # Reserved for future iptables state parsing implementation
        return []
