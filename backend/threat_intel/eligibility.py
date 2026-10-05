"""NetSentinel Public IP Eligibility Validator.

Enforces strict privacy and operational boundaries by ensuring that only valid,
globally-routable public IP addresses can be queried against external threat intelligence
providers. Rejects private, loopback, multicast, link-local, broadcast, unspecified,
and local system identifiers.
"""

import ipaddress
import logging
from typing import Any, Optional

logger = logging.getLogger("netsentinel.threat_intel.eligibility")


def is_eligible_public_ip(ip_val: Any) -> bool:
    """Validate whether an IP address is an externally observed, globally-routable public IP.

    Args:
        ip_val: String or object representing an IP address.

    Returns:
        True if the IP is a valid public IPv4/IPv6 address eligible for TI lookup; False otherwise.
    """
    if not ip_val or not isinstance(ip_val, (str, bytes)):
        return False

    raw_str = ip_val.decode("utf-8", errors="ignore") if isinstance(ip_val, bytes) else str(ip_val)
    candidate = raw_str.strip()
    if not candidate:
        return False

    # Quick rejection of host-local identifiers and non-IP formatting
    if candidate.startswith("host:") or candidate in ("localhost", "None", "none"):
        return False

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except (ValueError, TypeError):
        return False

    # 1. Reject loopback (127.0.0.0/8, ::1)
    if ip_obj.is_loopback:
        return False

    # 2. Reject RFC1918 / Unique Local private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    if ip_obj.is_private:
        return False

    # 3. Reject link-local addresses (169.254.0.0/16, fe80::/10)
    if ip_obj.is_link_local:
        return False

    # 4. Reject multicast ranges (224.0.0.0/4, ff00::/8)
    if ip_obj.is_multicast:
        return False

    # 5. Reject unspecified addresses (0.0.0.0, ::)
    if ip_obj.is_unspecified:
        return False

    # 6. Reject reserved addresses (e.g. 240.0.0.0/4, IETF assignments)
    if ip_obj.is_reserved:
        return False

    # 7. Explicit check for IPv4 broadcast
    if ip_obj.version == 4 and candidate == "255.255.255.255":
        return False

    # 8. Must be globally routable
    if not ip_obj.is_global:
        return False

    return True


def normalize_ip(ip_val: Any) -> Optional[str]:
    """Parse and return a canonical string representation of an eligible public IP.

    Returns:
        Canonical IP string if eligible, or None if invalid/ineligible.
    """
    if not is_eligible_public_ip(ip_val):
        return None
    try:
        return str(ipaddress.ip_address(str(ip_val).strip()))
    except Exception:
        return None
