"""Tests for NetSentinel Threat Intelligence IP Eligibility."""

import pytest
from threat_intel.eligibility import is_eligible_public_ip, normalize_ip


def test_public_ips_are_eligible():
    """Verify common globally-routable public IPv4 and IPv6 addresses are accepted."""
    public_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "104.244.42.1",
        "142.250.190.46",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ]
    for ip in public_ips:
        assert is_eligible_public_ip(ip) is True
        assert normalize_ip(ip) is not None


def test_private_rfc1918_ips_are_rejected():
    """Verify RFC 1918 private subnets are strictly rejected."""
    private_ips = [
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.0.100",
        "192.168.254.254",
    ]
    for ip in private_ips:
        assert is_eligible_public_ip(ip) is False
        assert normalize_ip(ip) is None


def test_loopback_and_local_rejected():
    """Verify loopback, localhost, and unspecified addresses are rejected."""
    local_identifiers = [
        "127.0.0.1",
        "127.0.0.53",
        "::1",
        "localhost",
        "host:debian",
        "0.0.0.0",
        "::",
    ]
    for ip in local_identifiers:
        assert is_eligible_public_ip(ip) is False
        assert normalize_ip(ip) is None


def test_link_local_and_multicast_rejected():
    """Verify link-local and multicast addresses are rejected."""
    ineligible_ips = [
        "169.254.1.1",
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "239.255.255.250",
        "ff02::1",
        "255.255.255.255",
    ]
    for ip in ineligible_ips:
        assert is_eligible_public_ip(ip) is False
        assert normalize_ip(ip) is None


def test_malformed_and_none_values():
    """Verify null, empty, non-string, or malformed values are handled gracefully."""
    invalid_inputs = [
        None,
        "",
        "   ",
        "not-an-ip",
        "999.999.999.999",
        12345,
        [],
        {},
    ]
    for inp in invalid_inputs:
        assert is_eligible_public_ip(inp) is False
        assert normalize_ip(inp) is None
