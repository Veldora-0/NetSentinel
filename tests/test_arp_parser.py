"""Tests for ARP Packet Parsing in parser.py."""

import struct
import pytest
from parser import parse_packet, parse_arp_packet, ParsedPacket, ParsedARP


def build_raw_arp_frame(
    hw_type=1,
    proto_type=0x0800,
    hw_size=6,
    proto_size=4,
    operation=1,
    sender_mac=b"\x00\x11\x22\x33\x44\x55",
    sender_ip=b"\xc0\xa8\x01\x32",  # 192.168.1.50
    target_mac=b"\x00\x00\x00\x00\x00\x00",
    target_ip=b"\xc0\xa8\x01\x01",  # 192.168.1.1
    eth_dst=b"\xff\xff\xff\xff\xff\xff",
    eth_src=b"\x00\x11\x22\x33\x44\x55",
) -> bytes:
    """Build synthetic raw Ethernet frame carrying an ARP packet."""
    eth_header = eth_dst + eth_src + struct.pack("!H", 0x0806)
    arp_payload = struct.pack(
        "!HHBBH",
        hw_type,
        proto_type,
        hw_size,
        proto_size,
        operation,
    ) + sender_mac + sender_ip + target_mac + target_ip
    return eth_header + arp_payload


def test_parse_arp_request():
    """Verify parsing of standard RFC 826 ARP Request frame."""
    frame = build_raw_arp_frame(
        operation=1,
        sender_mac=b"\x00\x0c\x29\xab\xcd\xef",
        sender_ip=struct.pack("!BBBB", 192, 168, 1, 100),
        target_mac=b"\x00\x00\x00\x00\x00\x00",
        target_ip=struct.pack("!BBBB", 192, 168, 1, 1),
    )

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.ethertype == 0x0806
    assert pkt.protocol_name == "ARP"
    assert pkt.src_ip == "192.168.1.100"
    assert pkt.dst_ip == "192.168.1.1"

    arp = pkt.arp_info
    assert arp is not None
    assert arp.operation == 1
    assert arp.operation_name == "REQUEST"
    assert arp.sender_mac == "00:0c:29:ab:cd:ef"
    assert arp.sender_ip == "192.168.1.100"
    assert arp.target_mac == "00:00:00:00:00:00"
    assert arp.target_ip == "192.168.1.1"
    assert arp.is_gratuitous is False


def test_parse_arp_reply():
    """Verify parsing of standard RFC 826 ARP Reply frame."""
    frame = build_raw_arp_frame(
        operation=2,
        sender_mac=b"\x00\x50\x56\xc0\x00\x08",
        sender_ip=struct.pack("!BBBB", 192, 168, 1, 1),
        target_mac=b"\x00\x0c\x29\xab\xcd\xef",
        target_ip=struct.pack("!BBBB", 192, 168, 1, 100),
    )

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.protocol_name == "ARP"
    assert pkt.arp_info is not None
    assert pkt.arp_info.operation == 2
    assert pkt.arp_info.operation_name == "REPLY"
    assert pkt.arp_info.sender_mac == "00:50:56:c0:00:08"
    assert pkt.arp_info.sender_ip == "192.168.1.1"
    assert pkt.arp_info.target_mac == "00:0c:29:ab:cd:ef"
    assert pkt.arp_info.target_ip == "192.168.1.100"
    assert pkt.arp_info.is_gratuitous is False


def test_parse_gratuitous_arp():
    """Verify detection of Gratuitous ARP announcements (sender_ip == target_ip)."""
    frame = build_raw_arp_frame(
        operation=2,
        sender_mac=b"\x00\x11\x22\x33\x44\x55",
        sender_ip=struct.pack("!BBBB", 10, 0, 0, 5),
        target_mac=b"\xff\xff\xff\xff\xff\xff",
        target_ip=struct.pack("!BBBB", 10, 0, 0, 5),
    )

    pkt = parse_packet(frame)
    assert pkt.error is None
    assert pkt.arp_info is not None
    assert pkt.arp_info.is_gratuitous is True
    assert pkt.arp_info.sender_ip == "10.0.0.5"
    assert pkt.arp_info.target_ip == "10.0.0.5"


def test_parse_truncated_arp_payload():
    """Verify truncated ARP payload handled safely without exceptions."""
    eth_header = b"\xff" * 6 + b"\x00" * 6 + struct.pack("!H", 0x0806)
    truncated_payload = b"\x00\x01\x08\x00\x06\x04\x00\x01"  # only 8 bytes instead of 28

    pkt = parse_packet(eth_header + truncated_payload)
    assert pkt.protocol_name == "ARP"
    assert pkt.arp_info is None
    assert "Malformed ARP frame" in (pkt.error or "")


def test_parse_non_ethernet_ipv4_arp():
    """Verify non-Ethernet or non-IPv4 ARP structures rejected gracefully."""
    # hlen != 6 (e.g. hlen = 8)
    frame = build_raw_arp_frame(hw_size=8)
    pkt = parse_packet(frame)
    assert pkt.arp_info is None
    assert "Malformed ARP frame" in (pkt.error or "")

    # plen != 4 (e.g. plen = 16 for IPv6)
    frame2 = build_raw_arp_frame(proto_size=16)
    pkt2 = parse_packet(frame2)
    assert pkt2.arp_info is None
    assert "Malformed ARP frame" in (pkt2.error or "")
