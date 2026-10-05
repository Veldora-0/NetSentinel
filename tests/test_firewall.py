"""Unit tests for NetSentinel Linux iptables Firewall Manager.

Tests IP validation, safety safeguards (loopback, multicast, broadcast, local interfaces,
allowlist), managed chain isolation, command execution security (no shell=True),
duplicate blocks, unblocks, temporary block expiration, and dry-run/disabled modes.
"""

from unittest.mock import patch, MagicMock
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from firewall import FirewallManager, BlockRecord


def test_ip_validation_valid_addresses():
    """Verify valid IPv4 and IPv6 public addresses pass safety checks."""
    fm = FirewallManager(config={"dry_run": True, "enabled": False})

    safe_v4, _ = fm.is_safe_to_block("198.51.100.25")
    assert safe_v4 is True

    safe_v6, _ = fm.is_safe_to_block("2001:db8::1234")
    assert safe_v6 is True


def test_ip_validation_invalid_and_malformed():
    """Verify malformed strings and invalid formats are rejected safely."""
    fm = FirewallManager()

    invalid_inputs = [
        "",
        "   ",
        "999.999.999.999",
        "192.168.1.1.1",
        "example.com",
        "192.168.1.1; rm -rf /",
        "192.168.1.1\nDROP",
        None,
    ]

    for bad_ip in invalid_inputs:
        safe, msg = fm.is_safe_to_block(bad_ip)
        assert safe is False
        res = fm.block_ip(bad_ip)
        assert res["success"] is False
        assert res["status"] == "rejected"


def test_localhost_and_loopback_safeguards():
    """Verify 127.0.0.0/8 and ::1 loopback addresses can never be blocked."""
    fm = FirewallManager()

    loopbacks = ["127.0.0.1", "127.0.0.2", "127.10.20.30", "::1"]
    for lb in loopbacks:
        safe, msg = fm.is_safe_to_block(lb)
        assert safe is False
        assert "Loopback" in msg or "cannot be blocked" in msg

        res = fm.block_ip(lb)
        assert res["success"] is False
        assert res["status"] == "rejected"


def test_multicast_broadcast_unspecified_safeguards():
    """Verify multicast, broadcast, and unspecified addresses are never blocked."""
    fm = FirewallManager()

    protected = [
        ("0.0.0.0", "Unspecified"),
        ("::", "Unspecified"),
        ("224.0.0.1", "Multicast"),
        ("239.255.255.250", "Multicast"),
        ("ff02::1", "Multicast"),
        ("255.255.255.255", "broadcast"),
    ]

    for ip, label in protected:
        safe, msg = fm.is_safe_to_block(ip)
        assert safe is False
        res = fm.block_ip(ip)
        assert res["success"] is False
        assert res["status"] == "rejected"


def test_allowlist_protection():
    """Verify operator-configured allowlisted IPs and CIDR subnets are protected."""
    fm = FirewallManager(config={
        "allowlist": ["192.0.2.10", "10.0.0.0/24"],
        "dry_run": True,
        "enabled": False,
    })

    # Exact match allowlist
    safe_exact, msg_exact = fm.is_safe_to_block("192.0.2.10")
    assert safe_exact is False
    assert "allowlisted" in msg_exact

    # Subnet match allowlist
    safe_sub, msg_sub = fm.is_safe_to_block("10.0.0.55")
    assert safe_sub is False
    assert "allowlisted" in msg_sub

    # Non-allowlisted IP should pass
    safe_other, _ = fm.is_safe_to_block("10.0.1.55")
    assert safe_other is True


def test_disabled_firewall_and_dry_run_simulation():
    """Verify disabled or dry_run mode performs simulation without calling iptables."""
    fm = FirewallManager(config={"enabled": False, "dry_run": True})

    with patch("subprocess.run") as mock_sub:
        res = fm.block_ip("198.51.100.42", reason="Test Simulation")
        assert res["success"] is True
        assert res["status"] == "simulated"
        assert fm.is_blocked("198.51.100.42") is True
        # subprocess must NOT be called in dry run / disabled mode
        mock_sub.assert_not_called()

        res_unblock = fm.unblock_ip("198.51.100.42")
        assert res_unblock["success"] is True
        assert res_unblock["status"] == "simulated"
        assert fm.is_blocked("198.51.100.42") is False


def test_duplicate_block_updates_expiration():
    """Verify blocking an already blocked IP updates expiration rather than duplicating."""
    fm = FirewallManager(config={"enabled": False, "dry_run": True, "block_duration": 100.0})

    ip = "198.51.100.99"
    r1 = fm.block_ip(ip, duration=50.0)
    assert r1["status"] == "simulated"
    exp1 = r1["expires_at"]

    time.sleep(0.01)
    r2 = fm.block_ip(ip, duration=200.0)
    assert r2["status"] == "already_blocked"
    assert r2["expires_at"] > exp1

    blocked_list = fm.list_blocked_ips()
    # Should only have 1 entry for this IP
    assert len([b for b in blocked_list if b["ip"] == ip]) == 1


def test_block_expiration_and_cleanup():
    """Verify temporary block expires automatically and is cleaned up."""
    fm = FirewallManager(config={"enabled": False, "dry_run": True, "block_duration": 0.05})

    ip = "198.51.100.77"
    fm.block_ip(ip, duration=0.05)
    assert fm.is_blocked(ip) is True

    # Wait for expiration
    time.sleep(0.08)
    assert fm.is_blocked(ip) is False
    assert len(fm.list_blocked_ips()) == 0


def test_clear_managed_rules_only_targets_dedicated_chain():
    """Verify clear_managed_rules flushes ONLY the dedicated chain, never global chains."""
    fm = FirewallManager(config={
        "enabled": True,
        "dry_run": False,
        "chain": "NETSENTINEL",
    })

    with patch("subprocess.run") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_sub.return_value = mock_proc

        res = fm.clear_managed_rules()
        assert res["success"] is True

        # Check call arguments
        mock_sub.assert_called_once()
        args, kwargs = mock_sub.call_args
        cmd = args[0]
        assert cmd == ["iptables", "-F", "NETSENTINEL"]
        # Ensure shell=True was NEVER passed
        assert kwargs.get("shell") is not True


def test_real_iptables_command_arguments_security():
    """Verify real iptables execution uses argument arrays and never shell=True."""
    fm = FirewallManager(config={
        "enabled": True,
        "dry_run": False,
        "chain": "NETSENTINEL",
    })

    with patch("subprocess.run") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_sub.return_value = mock_proc

        res = fm.block_ip("203.0.113.111")
        assert res["success"] is True

        # Check subprocess calls
        for call in mock_sub.call_args_list:
            call_args, call_kwargs = call
            cmd = call_args[0]
            assert isinstance(cmd, list)
            assert cmd[0] == "iptables"
            assert call_kwargs.get("shell") is not True


def test_iptables_missing_or_permission_denied_handled_safely():
    """Verify missing iptables binary or permission errors fail gracefully without crashing."""
    fm = FirewallManager(config={"enabled": True, "dry_run": False})

    with patch("subprocess.run", side_effect=FileNotFoundError):
        res = fm.block_ip("198.51.100.88")
        assert res["success"] is False
        assert "not found" in res["message"]

    with patch("subprocess.run", side_effect=PermissionError):
        res2 = fm.block_ip("198.51.100.89")
        assert res2["success"] is False
        assert "Permission denied" in res2["message"]
