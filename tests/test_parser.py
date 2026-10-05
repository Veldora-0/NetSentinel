"""Unit tests for NetSentinel Packet Parser.

Tests parsing of Ethernet, IPv4, IPv6, TCP, UDP, and ICMP frames
using deterministic raw byte fixtures.
"""

import socket
import struct
import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from parser import (
    parse_packet,
    parse_ethernet_frame,
    parse_ip_header,
    parse_tcp_header,
    parse_udp_header,
    parse_icmp_header,
    format_mac,
)


def build_ethernet_frame(dst_mac: bytes, src_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    """Helper to craft an Ethernet frame."""
    return struct.pack("!6s6sH", dst_mac, src_mac, ethertype) + payload


def build_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    """Helper to craft an IPv4 packet."""
    ihl = 5
    version = 4
    version_ihl = (version << 4) | ihl
    total_len = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,  # DSCP/ECN
        total_len,
        1001,  # ID
        0,  # Flags / Frag offset
        ttl,
        proto,
        0,  # Checksum
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return hdr + payload


def build_ipv6_packet(src_ip: str, dst_ip: str, next_hdr: int, payload: bytes, hop_limit: int = 64) -> bytes:
    """Helper to craft an IPv6 packet."""
    first_word = (6 << 28)
    hdr = struct.pack(
        "!IHBB16s16s",
        first_word,
        len(payload),
        next_hdr,
        hop_limit,
        socket.inet_pton(socket.AF_INET6, src_ip),
        socket.inet_pton(socket.AF_INET6, dst_ip),
    )
    return hdr + payload


def build_tcp_segment(src_port: int, dst_port: int, flags: int, seq: int = 100, ack: int = 200, payload: bytes = b"") -> bytes:
    """Helper to craft a TCP segment."""
    data_offset = 5  # 5 * 4 = 20 bytes
    offset_reserved = (data_offset << 4)
    hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flags,
        64240,  # Window
        0,      # Checksum
        0,      # Urgent ptr
    )
    return hdr + payload


def build_udp_datagram(src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    """Helper to craft a UDP datagram."""
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return hdr + payload


def build_icmp_message(icmp_type: int, icmp_code: int, payload: bytes = b"") -> bytes:
    """Helper to craft an ICMP message."""
    hdr = struct.pack("!BBH", icmp_type, icmp_code, 0) + struct.pack("!HH", 1234, 1)
    return hdr + payload


# --- Unit Tests ---

def test_format_mac():
    """Verify MAC formatting function."""
    raw = b"\x00\x1a\x2b\x3c\x4d\x5e"
    assert format_mac(raw) == "00:1a:2b:3c:4d:5e"


def test_ethernet_ipv4_packet():
    """1. Test Ethernet + basic IPv4 packet."""
    src_mac = b"\x11\x22\x33\x44\x55\x66"
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    ip_payload = b"SamplePayload"
    ip_bytes = build_ipv4_packet("192.168.1.50", "10.0.0.1", proto=2, payload=ip_payload, ttl=128)
    frame = build_ethernet_frame(dst_mac, src_mac, 0x0800, ip_bytes)

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.src_mac == "11:22:33:44:55:66"
    assert pkt.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert pkt.ethertype == 0x0800
    assert pkt.ethertype_name == "IPv4"
    assert pkt.ip_version == 4
    assert pkt.src_ip == "192.168.1.50"
    assert pkt.dst_ip == "10.0.0.1"
    assert pkt.protocol == 2
    assert pkt.protocol_name == "IGMP"
    assert pkt.ttl == 128
    assert pkt.ip_length == 20 + len(ip_payload)
    assert pkt.payload_length == len(ip_payload)


def test_ipv4_tcp_packet():
    """2. Test IPv4 + TCP packet."""
    tcp_payload = b"HTTP GET /index.html"
    # SYN + ACK flags: 0x02 | 0x10 = 0x12
    tcp_bytes = build_tcp_segment(src_port=443, dst_port=52341, flags=0x12, seq=55555, ack=66666, payload=tcp_payload)
    ip_bytes = build_ipv4_packet("172.16.0.2", "192.168.1.1", proto=6, payload=tcp_bytes)
    frame = build_ethernet_frame(b"\x00"*6, b"\x01"*6, 0x0800, ip_bytes)

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.ip_version == 4
    assert pkt.protocol == 6
    assert pkt.protocol_name == "TCP"
    assert pkt.src_port == 443
    assert pkt.dst_port == 52341
    assert pkt.seq_num == 55555
    assert pkt.ack_num == 66666
    assert pkt.tcp_flags is not None
    assert pkt.tcp_flags["SYN"] is True
    assert pkt.tcp_flags["ACK"] is True
    assert pkt.tcp_flags["FIN"] is False
    assert pkt.tcp_flags["RST"] is False
    assert pkt.payload_length == len(tcp_payload)


def test_ipv4_udp_packet():
    """3. Test IPv4 + UDP packet."""
    udp_payload = b"DNSQueryData123"
    udp_bytes = build_udp_datagram(src_port=53, dst_port=48912, payload=udp_payload)
    ip_bytes = build_ipv4_packet("8.8.8.8", "192.168.1.10", proto=17, payload=udp_bytes)
    frame = build_ethernet_frame(b"\x00"*6, b"\x02"*6, 0x0800, ip_bytes)

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.ip_version == 4
    assert pkt.protocol == 17
    assert pkt.protocol_name == "UDP"
    assert pkt.src_port == 53
    assert pkt.dst_port == 48912
    assert pkt.udp_length == 8 + len(udp_payload)
    assert pkt.payload_length == len(udp_payload)


def test_icmp_packet():
    """4. Test ICMP packet (Echo Request)."""
    icmp_payload = b"PingPayload12345"
    icmp_bytes = build_icmp_message(icmp_type=8, icmp_code=0, payload=icmp_payload)
    ip_bytes = build_ipv4_packet("192.168.1.20", "192.168.1.1", proto=1, payload=icmp_bytes)
    frame = build_ethernet_frame(b"\x00"*6, b"\x03"*6, 0x0800, ip_bytes)

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.protocol == 1
    assert pkt.protocol_name == "ICMP"
    assert pkt.icmp_type == 8
    assert pkt.icmp_code == 0
    assert pkt.src_ip == "192.168.1.20"
    assert pkt.dst_ip == "192.168.1.1"


def test_ipv6_packet():
    """5. Test IPv6 packet with UDP."""
    udp_bytes = build_udp_datagram(src_port=5353, dst_port=5353, payload=b"mDNS")
    ip6_bytes = build_ipv6_packet("fe80::1", "ff02::fb", next_hdr=17, payload=udp_bytes, hop_limit=255)
    frame = build_ethernet_frame(b"\x00"*6, b"\x04"*6, 0x86DD, ip6_bytes)

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.ethertype == 0x86DD
    assert pkt.ethertype_name == "IPv6"
    assert pkt.ip_version == 6
    assert pkt.src_ip == "fe80::1"
    assert pkt.dst_ip == "ff02::fb"
    assert pkt.protocol == 17
    assert pkt.protocol_name == "UDP"
    assert pkt.src_port == 5353
    assert pkt.dst_port == 5353
    assert pkt.ttl == 255


def test_malformed_truncated_packets():
    """6. Test malformed and truncated frames do not crash parser."""
    # Sub-test A: Shorter than 14 bytes Ethernet frame
    pkt_short = parse_packet(b"\x00\x11\x22\x33\x44")
    assert pkt_short.error is not None
    assert "Truncated Ethernet frame" in pkt_short.error

    # Sub-test B: Ethernet OK but truncated IPv4 header (< 20 bytes)
    truncated_ip = b"\x45\x00\x00\x20\x00\x01\x00\x00"  # only 8 bytes
    frame_trunc_ip = build_ethernet_frame(b"\x00"*6, b"\x00"*6, 0x0800, truncated_ip)
    pkt_trunc_ip = parse_packet(frame_trunc_ip)
    assert pkt_trunc_ip.error is not None
    assert "Malformed IPv4 header" in pkt_trunc_ip.error

    # Sub-test C: IPv4 OK but truncated TCP header (< 20 bytes)
    truncated_tcp = b"\x00\x50\x00\x50\x00\x00"  # only 6 bytes
    ip_trunc_tcp = build_ipv4_packet("10.0.0.1", "10.0.0.2", proto=6, payload=truncated_tcp)
    frame_trunc_tcp = build_ethernet_frame(b"\x00"*6, b"\x00"*6, 0x0800, ip_trunc_tcp)
    pkt_trunc_tcp = parse_packet(frame_trunc_tcp)
    assert pkt_trunc_tcp.error is not None
    assert "Malformed TCP segment" in pkt_trunc_tcp.error


def test_tcp_flags_extraction():
    """7. Test TCP flag combinations (SYN, FIN, RST, PSH, ACK, URG)."""
    # Test A: SYN flag alone (0x02)
    tcp_syn = build_tcp_segment(src_port=1000, dst_port=80, flags=0x02)
    pkt_syn = parse_packet(build_ethernet_frame(b"\x00"*6, b"\x00"*6, 0x0800, build_ipv4_packet("1.1.1.1", "2.2.2.2", 6, tcp_syn)))
    assert pkt_syn.tcp_flags["SYN"] is True
    assert pkt_syn.tcp_flags["ACK"] is False
    assert pkt_syn.tcp_flags["FIN"] is False
    assert pkt_syn.tcp_flags["RST"] is False

    # Test B: RST flag alone (0x04)
    tcp_rst = build_tcp_segment(src_port=80, dst_port=1000, flags=0x04)
    pkt_rst = parse_packet(build_ethernet_frame(b"\x00"*6, b"\x00"*6, 0x0800, build_ipv4_packet("2.2.2.2", "1.1.1.1", 6, tcp_rst)))
    assert pkt_rst.tcp_flags["RST"] is True
    assert pkt_rst.tcp_flags["SYN"] is False

    # Test C: XMAS scan flags (FIN=0x01 + PSH=0x08 + URG=0x20 = 0x29)
    tcp_xmas = build_tcp_segment(src_port=1234, dst_port=80, flags=0x29)
    pkt_xmas = parse_packet(build_ethernet_frame(b"\x00"*6, b"\x00"*6, 0x0800, build_ipv4_packet("1.1.1.1", "2.2.2.2", 6, tcp_xmas)))
    assert pkt_xmas.tcp_flags["FIN"] is True
    assert pkt_xmas.tcp_flags["PSH"] is True
    assert pkt_xmas.tcp_flags["URG"] is True
    assert pkt_xmas.tcp_flags["SYN"] is False
    assert pkt_xmas.tcp_flags["ACK"] is False

    # Test D: NULL scan (flags = 0x00)
    tcp_null = build_tcp_segment(src_port=1234, dst_port=80, flags=0x00)
    pkt_null = parse_packet(build_ethernet_frame(b"\x00"*6, b"\x00"*6, 0x0800, build_ipv4_packet("1.1.1.1", "2.2.2.2", 6, tcp_null)))
    for flag_name, is_set in pkt_null.tcp_flags.items():
        assert is_set is False, f"Flag {flag_name} was unexpectedly set in NULL scan"
