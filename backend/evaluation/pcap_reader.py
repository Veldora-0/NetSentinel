"""NetSentinel Streaming PCAP Reader (Phase 15.5).

Provides a lightweight, pure-Python streaming reader for standard Libpcap binary packet
captures (.pcap and .pcap.gz) without requiring external C libraries or heavy dependencies.
Preserves microsecond/nanosecond capture timestamps and yields raw frame bytes.
"""

from dataclasses import dataclass
import gzip
import os
import struct
from typing import Generator, Iterator, List, Optional, Tuple


# Standard Libpcap magic numbers
TCPDUMP_MAGIC_MICRO_BE = 0xA1B2C3D4  # Big-endian, microseconds
TCPDUMP_MAGIC_MICRO_LE = 0xD4C3B2A1  # Little-endian, microseconds
TCPDUMP_MAGIC_NANO_BE = 0xA1B23C4D   # Big-endian, nanoseconds
TCPDUMP_MAGIC_NANO_LE = 0x4D3CB2A1   # Little-endian, nanoseconds

# Data link types
LINKTYPE_ETHERNET = 1


@dataclass
class PcapPacketRecord:
    """Represents a single raw packet record read from a PCAP stream."""
    record_index: int
    timestamp: float          # Unix epoch seconds with fractional seconds
    incl_len: int             # Number of bytes saved in PCAP
    orig_len: int             # Original packet length on wire
    raw_bytes: bytes          # Captured frame octets


class PcapReader:
    """Streaming binary PCAP file reader."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.endianness: str = "<"
        self.time_scale: float = 1e6
        self.version_major: int = 2
        self.version_minor: int = 4
        self.snaplen: int = 65535
        self.network: int = LINKTYPE_ETHERNET

    def iter_packets(self) -> Generator[PcapPacketRecord, None, None]:
        """Stream packet records from the PCAP file one by one.

        Yields:
            PcapPacketRecord with exact capture timestamp and raw octets.
        """
        is_gz = self.filepath.endswith(".gz")
        open_func = gzip.open if is_gz else open

        with open_func(self.filepath, "rb") as f:
            # 1. Read Global Header (24 bytes)
            global_header = f.read(24)
            if len(global_header) < 24:
                raise ValueError(f"Truncated PCAP header in {self.filepath} (only {len(global_header)} bytes)")

            magic_bytes = global_header[:4]
            if magic_bytes == b"\xa1\xb2\xc3\xd4":
                self.endianness = ">"
                self.time_scale = 1e6
            elif magic_bytes == b"\xd4\xc3\xb2\xa1":
                self.endianness = "<"
                self.time_scale = 1e6
            elif magic_bytes == b"\xa1\xb2\x3c\x4d":
                self.endianness = ">"
                self.time_scale = 1e9
            elif magic_bytes == b"\x4d\x3c\xb2\xa1":
                self.endianness = "<"
                self.time_scale = 1e9
            else:
                raise ValueError(f"Unsupported PCAP magic bytes {magic_bytes.hex()} in {self.filepath}")

            fmt = f"{self.endianness}IHHiIII"
            _, major, minor, _, _, snaplen, network = struct.unpack(fmt, global_header)
            self.version_major = major
            self.version_minor = minor
            self.snaplen = snaplen
            self.network = network

            # 2. Stream Packet Records (16-byte header + incl_len payload)
            pkt_hdr_fmt = f"{self.endianness}IIII"
            pkt_index = 0

            while True:
                hdr_bytes = f.read(16)
                if not hdr_bytes:
                    break
                if len(hdr_bytes) < 16:
                    # Incomplete trailing header; terminate gracefully
                    break

                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(pkt_hdr_fmt, hdr_bytes)
                timestamp = float(ts_sec) + (float(ts_frac) / self.time_scale)

                payload = f.read(incl_len)
                if len(payload) < incl_len:
                    # Premature EOF; record truncated packet
                    pass

                yield PcapPacketRecord(
                    record_index=pkt_index,
                    timestamp=timestamp,
                    incl_len=incl_len,
                    orig_len=orig_len,
                    raw_bytes=payload,
                )
                pkt_index += 1


def write_synthetic_pcap(filepath: str, packets: List[Tuple[bytes, float]]) -> None:
    """Helper utility to write a valid synthetic Libpcap file for testing.

    Args:
        filepath: Target output file path.
        packets: List of (raw_bytes, timestamp) tuples.
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "wb") as f:
        # Standard little-endian microsecond header (24 bytes)
        # magic=b"\xd4\xc3\xb2\xa1", v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
        hdr = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
        f.write(hdr)

        for raw_bytes, ts in packets:
            ts_sec = int(ts)
            ts_usec = int(round((ts - ts_sec) * 1e6))
            incl_len = len(raw_bytes)
            orig_len = len(raw_bytes)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
            f.write(pkt_hdr)
            f.write(raw_bytes)
