"""NetSentinel Packet Capture and Traffic Metrics Module.

Captures raw Ethernet frames using Linux AF_PACKET raw sockets,
invokes the packet parser, maintains real-time traffic statistics,
and exposes thread-safe lifecycle control for the capture engine.
"""

from collections import deque
import logging
import os
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from parser import ParsedPacket, parse_packet

logger = logging.getLogger("netsentinel.capture")


class TrafficMetrics:
    """Thread-safe real-time network traffic metrics aggregator."""

    def __init__(self, window_seconds: float = 3.0):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()

        # Cumulative counters
        self.total_packets = 0
        self.total_bytes = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.arp_packets = 0
        self.other_packets = 0

        # Rolling window history: deque of (timestamp, packet_count, byte_count)
        self._history = deque()

    def update(self, packet: ParsedPacket) -> None:
        """Update metrics with a freshly parsed packet."""
        with self._lock:
            now = packet.timestamp
            raw_len = packet.raw_length

            self.total_packets += 1
            self.total_bytes += raw_len

            proto = packet.protocol_name
            if proto == "TCP":
                self.tcp_packets += 1
            elif proto == "UDP":
                self.udp_packets += 1
            elif proto in ("ICMP", "ICMPv6"):
                self.icmp_packets += 1
            elif proto == "ARP":
                self.arp_packets += 1
            else:
                self.other_packets += 1

            self._history.append((now, 1, raw_len))
            self._prune_history(now)

    def _prune_history(self, current_time: float) -> None:
        """Remove entries outside the sliding time window."""
        cutoff = current_time - self.window_seconds
        while self._history and self._history[0][0] < cutoff:
            self._history.popleft()

    def get_snapshot(
        self,
        interface: str,
        status: str,
        error: Optional[str] = None,
        configured_interface: Optional[str] = None,
        actual_interface: Optional[str] = None,
        socket_state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a point-in-time metrics snapshot including rolling rates."""
        with self._lock:
            now = time.time()
            self._prune_history(now)

            if len(self._history) >= 2:
                time_span = self._history[-1][0] - self._history[0][0]
                if time_span > 0.05:
                    window_pkts = sum(item[1] for item in self._history)
                    window_bytes = sum(item[2] for item in self._history)
                    pps = round(window_pkts / time_span, 2)
                    bps = round(window_bytes / time_span, 2)
                else:
                    pps = 0.0
                    bps = 0.0
            elif len(self._history) == 1:
                pps = round(1.0 / self.window_seconds, 2)
                bps = round(self._history[0][2] / self.window_seconds, 2)
            else:
                pps = 0.0
                bps = 0.0

            active_iface = actual_interface or interface

            return {
                "timestamp": now,
                "interface": active_iface,
                "configured_interface": configured_interface or interface,
                "actual_interface": actual_interface,
                "status": status,
                "socket_state": socket_state or ("OPEN" if status == "running" else "CLOSED"),
                "error": error,
                "last_error": error,
                "total_packets": self.total_packets,
                "total_frames": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_volume": self.total_bytes,
                "packets_per_sec": pps,
                "current_pps": pps,
                "bytes_per_sec": bps,
                "current_bps": bps,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "icmp_packets": self.icmp_packets,
                "arp_packets": self.arp_packets,
                "other_packets": self.other_packets,
            }


class PacketCapture:
    """Linux AF_PACKET raw frame capture manager."""

    def __init__(
        self,
        interface: Optional[str] = None,
        configured_interface: Optional[str] = None,
    ):
        self.interface = interface
        self.configured_interface = configured_interface or interface
        self.actual_interface: Optional[str] = None
        self.metrics = TrafficMetrics()
        self.status = "stopped"  # "stopped", "starting", "running", "permission_denied", "error"
        self.error_message: Optional[str] = None

        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None
        self._packet_callbacks: List[Callable[[ParsedPacket], None]] = []

    def add_packet_callback(self, callback: Callable[[ParsedPacket], None]) -> None:
        """Register a callback for downstream packet analysis."""
        self._packet_callbacks.append(callback)

    @property
    def runtime_status(self) -> str:
        """Reflect real worker lifecycle state."""
        if self.status == "running":
            if self._capture_thread and not self._capture_thread.is_alive():
                return "error" if self.error_message else "stopped"
        return self.status

    @property
    def socket_state(self) -> str:
        """Report actual low-level raw socket state."""
        if self._socket is not None:
            return "OPEN"
        if self.status == "permission_denied":
            return "PERMISSION_DENIED"
        if self.status == "error":
            return "ERROR"
        return "CLOSED"

    def start(self) -> bool:
        """Initialize AF_PACKET raw socket and launch capture thread.

        Returns:
            True if capture started, False if permission or socket error occurred.
        """
        if self.status == "running" and self._capture_thread and self._capture_thread.is_alive():
            return True

        self._stop_event.clear()
        self.status = "starting"

        # Validate interface existence if a specific non-any/non-lo interface is specified (on Linux)
        if self.interface and self.interface not in ("any", "lo"):
            sys_net_path = f"/sys/class/net/{self.interface}"
            if os.path.exists("/sys/class/net") and not os.path.exists(sys_net_path):
                self.status = "error"
                self.actual_interface = None
                available = []
                try:
                    available = [x for x in os.listdir("/sys/class/net") if x != "lo"]
                except Exception:
                    pass
                avail_str = ", ".join(available) if available else "none"
                self.error_message = (
                    f"Configured capture interface '{self.interface}' does not exist on this host. "
                    f"Available interfaces: {avail_str}."
                )
                logger.error(self.error_message)
                return False

        # Attempt to open Linux AF_PACKET raw socket (ETH_P_ALL = 0x0003)
        try:
            ETH_P_ALL = 0x0003
            self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
            self._socket.settimeout(0.5)

            # Bind to specific interface if requested
            if self.interface and self.interface != "any":
                self._socket.bind((self.interface, 0))

            self.actual_interface = self.interface
            self.status = "running"
            self.error_message = None
            logger.info("AF_PACKET raw socket opened on interface '%s'", self.interface)

        except PermissionError:
            self.actual_interface = None
            self.status = "permission_denied"
            self.error_message = (
                "AF_PACKET raw socket requires CAP_NET_RAW capability or elevated privileges "
                "(e.g. sudo setcap cap_net_raw,cap_net_admin+eip <python>)."
            )
            logger.warning(self.error_message)
            return False

        except Exception as e:
            self.actual_interface = None
            self.status = "error"
            self.error_message = f"Failed to initialize packet capture on '{self.interface}': {str(e)}"
            logger.error(self.error_message)
            return False

        # Launch capture worker thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop, name="NetSentinel-PacketCapture", daemon=True
        )
        self._capture_thread.start()
        return True

    def _capture_loop(self) -> None:
        """Worker loop receiving raw frames and dispatching to parser and metrics."""
        while not self._stop_event.is_set():
            if not self._socket:
                break

            try:
                raw_frame, _ = self._socket.recvfrom(65535)
                capture_time = time.time()
                parsed = parse_packet(raw_frame, timestamp=capture_time)

                # Update live traffic metrics
                self.metrics.update(parsed)

                # Dispatch to registered observers (e.g. detection engine, ML, ARP)
                for cb in self._packet_callbacks:
                    try:
                        cb(parsed)
                    except Exception as cb_err:
                        logger.debug("Error in packet callback: %s", cb_err)

            except socket.timeout:
                continue
            except OSError as os_err:
                if self._stop_event.is_set():
                    break
                logger.debug("Socket read error on '%s': %s", self.interface, os_err)
            except Exception as ex:
                logger.error("Unexpected error in capture loop on '%s': %s", self.interface, ex)

        self._cleanup_socket()
        if not self._stop_event.is_set():
            self.status = "error"
            if not self.error_message:
                self.error_message = f"Capture loop on '{self.interface}' terminated unexpectedly."
            self.actual_interface = None
        else:
            self.status = "stopped"
            self.actual_interface = None

    def process_test_packet(self, packet: ParsedPacket) -> None:
        """Process a test packet directly without requiring raw socket reception (for testing)."""
        self.metrics.update(packet)
        for cb in self._packet_callbacks:
            try:
                cb(packet)
            except Exception as cb_err:
                logger.debug("Error in packet callback: %s", cb_err)

    def _cleanup_socket(self) -> None:
        """Safely close raw socket."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def stop(self) -> None:
        """Signal capture loop to terminate and release socket resources."""
        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=1.5)
        self._cleanup_socket()
        self.actual_interface = None
        self.status = "stopped"
        logger.info("Packet capture stopped.")

    def get_metrics(self) -> Dict[str, Any]:
        """Retrieve current metrics snapshot."""
        return self.metrics.get_snapshot(
            interface=self.actual_interface or self.interface or "auto",
            status=self.runtime_status,
            error=self.error_message,
            configured_interface=self.configured_interface,
            actual_interface=self.actual_interface,
            socket_state=self.socket_state,
        )
