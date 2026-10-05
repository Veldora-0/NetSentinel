"""NetSentinel Packet Parser Module.

Parses raw Ethernet frames captured via Linux AF_PACKET raw sockets
into structured Python representations covering Ethernet, IPv4, IPv6,
TCP, UDP, and ICMP protocols.
"""

from dataclasses import dataclass, asdict, field
import socket
import struct
import time
from typing import Any, Dict, Optional


@dataclass
class ParsedPacket:
    """Structured representation of a parsed network packet."""
    timestamp: float
    raw_length: int
    src_mac: str
    dst_mac: str
    ethertype: int
    ethertype_name: str
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[int] = None
    protocol_name: Optional[str] = None
    ttl: Optional[int] = None
    ip_length: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    seq_num: Optional[int] = None
    ack_num: Optional[int] = None
    tcp_flags: Optional[Dict[str, bool]] = None
    raw_tcp_flags: Optional[int] = None
    udp_length: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    payload_length: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to dictionary representation."""
        return asdict(self)


# Protocol number to name mappings
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-Route",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

ETHERTYPES = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
    0x0806: "ARP",
    0x8100: "802.1Q",
}


def format_mac(raw_bytes: bytes) -> str:
    """Format 6 bytes into colon-separated hexadecimal MAC address."""
    return ":".join(f"{b:02x}" for b in raw_bytes)


def parse_ethernet_frame(raw_data: bytes) -> Optional[Dict[str, Any]]:
    """Parse raw byte stream into an Ethernet frame structure.

    Args:
        raw_data: Raw byte array from raw socket capture (min 14 bytes).

    Returns:
        Structured dictionary containing source MAC, destination MAC, ethertype,
        payload slice, or None if packet is malformed.
    """
    if len(raw_data) < 14:
        return None

    try:
        dst_mac_raw, src_mac_raw, ethertype = struct.unpack("!6s6sH", raw_data[:14])
        return {
            "dst_mac": format_mac(dst_mac_raw),
            "src_mac": format_mac(src_mac_raw),
            "ethertype": ethertype,
            "ethertype_name": ETHERTYPES.get(ethertype, f"0x{ethertype:04x}"),
            "payload": raw_data[14:],
        }
    except Exception as e:
        return None


def parse_ip_header(packet_data: bytes, ethertype: int = 0x0800) -> Optional[Dict[str, Any]]:
    """Parse IPv4 or IPv6 header from packet data following the Ethernet frame.

    Args:
        packet_data: Packet byte slice following Ethernet header.
        ethertype: EtherType from Ethernet header (0x0800 for IPv4, 0x86DD for IPv6).

    Returns:
        Structured dictionary containing IP header fields and remaining payload.
    """
    if ethertype == 0x0800:  # IPv4
        if len(packet_data) < 20:
            return None

        try:
            version_ihl, dscp_ecn, total_length, identification, flags_offset, ttl, protocol, checksum, src_ip_raw, dst_ip_raw = struct.unpack(
                "!BBHHHBBH4s4s", packet_data[:20]
            )
            version = (version_ihl >> 4) & 0x0F
            ihl = (version_ihl & 0x0F) * 4

            if ihl < 20 or len(packet_data) < ihl:
                return None

            src_ip = socket.inet_ntoa(src_ip_raw)
            dst_ip = socket.inet_ntoa(dst_ip_raw)

            return {
                "ip_version": 4,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "protocol_name": IP_PROTOCOLS.get(protocol, f"PROTO_{protocol}"),
                "ttl": ttl,
                "total_length": total_length,
                "header_length": ihl,
                "payload": packet_data[ihl:],
            }
        except Exception:
            return None

    elif ethertype == 0x86DD:  # IPv6
        if len(packet_data) < 40:
            return None

        try:
            first_word, payload_length, next_header, hop_limit, src_ip_raw, dst_ip_raw = struct.unpack(
                "!IHBB16s16s", packet_data[:40]
            )
            version = (first_word >> 28) & 0x0F
            src_ip = socket.inet_ntop(socket.AF_INET6, src_ip_raw)
            dst_ip = socket.inet_ntop(socket.AF_INET6, dst_ip_raw)

            return {
                "ip_version": 6,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": next_header,
                "protocol_name": IP_PROTOCOLS.get(next_header, f"PROTO_{next_header}"),
                "ttl": hop_limit,
                "total_length": 40 + payload_length,
                "header_length": 40,
                "payload": packet_data[40:],
            }
        except Exception:
            return None

    return None


def parse_tcp_header(segment_data: bytes) -> Optional[Dict[str, Any]]:
    """Parse TCP segment header from transport layer data.

    Args:
        segment_data: Bytes starting from the TCP header (min 20 bytes).

    Returns:
        Structured dictionary containing ports, flags (SYN, ACK, FIN, RST, PSH, URG),
        sequence and ACK numbers, and payload.
    """
    if len(segment_data) < 20:
        return None

    try:
        src_port, dst_port, seq_num, ack_num, offset_reserved, flags, window, checksum, urg_ptr = struct.unpack(
            "!HHIIBBHHH", segment_data[:20]
        )
        data_offset = ((offset_reserved >> 4) & 0x0F) * 4

        if data_offset < 20 or len(segment_data) < data_offset:
            return None

        tcp_flags = {
            "FIN": bool(flags & 0x01),
            "SYN": bool(flags & 0x02),
            "RST": bool(flags & 0x04),
            "PSH": bool(flags & 0x08),
            "ACK": bool(flags & 0x10),
            "URG": bool(flags & 0x20),
        }

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq_num": seq_num,
            "ack_num": ack_num,
            "tcp_flags": tcp_flags,
            "raw_tcp_flags": flags,
            "header_length": data_offset,
            "payload": segment_data[data_offset:],
        }
    except Exception:
        return None


def parse_udp_header(segment_data: bytes) -> Optional[Dict[str, Any]]:
    """Parse UDP header from transport layer data.

    Args:
        segment_data: Bytes starting from the UDP header (min 8 bytes).

    Returns:
        Structured dictionary containing source port, destination port, length, and payload.
    """
    if len(segment_data) < 8:
        return None

    try:
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", segment_data[:8])
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "header_length": 8,
            "payload": segment_data[8:],
        }
    except Exception:
        return None


def parse_icmp_header(icmp_data: bytes) -> Optional[Dict[str, Any]]:
    """Parse ICMP / ICMPv6 header from network layer payload.

    Args:
        icmp_data: Bytes starting from the ICMP header (min 4 bytes).

    Returns:
        Structured dictionary containing type, code, and payload.
    """
    if len(icmp_data) < 4:
        return None

    try:
        icmp_type, icmp_code, checksum = struct.unpack("!BBH", icmp_data[:4])
        return {
            "type": icmp_type,
            "code": icmp_code,
            "header_length": 4,
            "payload": icmp_data[4:],
        }
    except Exception:
        return None


def parse_packet(raw_frame: bytes, timestamp: Optional[float] = None) -> ParsedPacket:
    """Parse a full raw Ethernet frame into a structured ParsedPacket object.

    Gracefully handles unknown protocols and malformed packets without crashing.

    Args:
        raw_frame: Raw frame bytes from AF_PACKET socket.
        timestamp: Optional capture timestamp (defaults to current time).

    Returns:
        ParsedPacket dataclass populated with parsed protocol details.
    """
    pkt_time = timestamp if timestamp is not None else time.time()
    raw_len = len(raw_frame)

    if raw_len < 14:
        return ParsedPacket(
            timestamp=pkt_time,
            raw_length=raw_len,
            src_mac="00:00:00:00:00:00",
            dst_mac="00:00:00:00:00:00",
            ethertype=0,
            ethertype_name="UNKNOWN",
            error="Truncated Ethernet frame (< 14 bytes)",
        )

    eth = parse_ethernet_frame(raw_frame)
    if not eth:
        return ParsedPacket(
            timestamp=pkt_time,
            raw_length=raw_len,
            src_mac="00:00:00:00:00:00",
            dst_mac="00:00:00:00:00:00",
            ethertype=0,
            ethertype_name="UNKNOWN",
            error="Failed to parse Ethernet header",
        )

    ethertype = eth["ethertype"]
    payload = eth["payload"]

    packet = ParsedPacket(
        timestamp=pkt_time,
        raw_length=raw_len,
        src_mac=eth["src_mac"],
        dst_mac=eth["dst_mac"],
        ethertype=ethertype,
        ethertype_name=eth["ethertype_name"],
        payload_length=len(payload),
    )

    # Process IP layer if IPv4 or IPv6
    if ethertype in (0x0800, 0x86DD):
        ip_info = parse_ip_header(payload, ethertype=ethertype)
        if not ip_info:
            packet.error = f"Malformed {eth['ethertype_name']} header"
            return packet

        packet.ip_version = ip_info["ip_version"]
        packet.src_ip = ip_info["src_ip"]
        packet.dst_ip = ip_info["dst_ip"]
        packet.protocol = ip_info["protocol"]
        packet.protocol_name = ip_info["protocol_name"]
        packet.ttl = ip_info["ttl"]
        packet.ip_length = ip_info["total_length"]
        transport_payload = ip_info["payload"]
        packet.payload_length = len(transport_payload)

        # Transport layer parsing
        if packet.protocol == 6:  # TCP
            tcp_info = parse_tcp_header(transport_payload)
            if tcp_info:
                packet.src_port = tcp_info["src_port"]
                packet.dst_port = tcp_info["dst_port"]
                packet.seq_num = tcp_info["seq_num"]
                packet.ack_num = tcp_info["ack_num"]
                packet.tcp_flags = tcp_info["tcp_flags"]
                packet.raw_tcp_flags = tcp_info["raw_tcp_flags"]
                packet.payload_length = len(tcp_info["payload"])
            else:
                packet.error = "Malformed TCP segment"

        elif packet.protocol == 17:  # UDP
            udp_info = parse_udp_header(transport_payload)
            if udp_info:
                packet.src_port = udp_info["src_port"]
                packet.dst_port = udp_info["dst_port"]
                packet.udp_length = udp_info["length"]
                packet.payload_length = len(udp_info["payload"])
            else:
                packet.error = "Malformed UDP datagram"

        elif packet.protocol in (1, 58):  # ICMP (IPv4) or ICMPv6
            icmp_info = parse_icmp_header(transport_payload)
            if icmp_info:
                packet.icmp_type = icmp_info["type"]
                packet.icmp_code = icmp_info["code"]
                packet.payload_length = len(icmp_info["payload"])
            else:
                packet.error = "Malformed ICMP message"

    return packet
