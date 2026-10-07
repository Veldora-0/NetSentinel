"""NetSentinel Window Builder & Ground-Truth Labeller (Phase 15.5).

Constructs discrete 5.0-second traffic windows from streaming PCAP packet records,
extracts canonical 13-feature vectors using the production feature extractor,
and deterministically assigns ground-truth labels using overlapping Zeek flows.
"""

from dataclasses import dataclass, field
from enum import Enum
import math
import sys
import os
from typing import Any, Dict, Generator, Iterator, List, Optional, Set, Tuple

# Ensure backend root is accessible
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from parser import parse_packet, ParsedPacket
from ml.feature_extractor import extract_features_from_window, FEATURE_NAMES

try:
    from .pcap_reader import PcapPacketRecord, PcapReader
    from .zeek_parser import ZeekFlowRecord
except ImportError:
    from evaluation.pcap_reader import PcapPacketRecord, PcapReader
    from evaluation.zeek_parser import ZeekFlowRecord


class WindowGroundTruth(str, Enum):
    """Ground-truth classification of an evaluated 5-second traffic window."""
    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"
    BACKGROUND_ONLY = "BACKGROUND_ONLY"
    UNLABELED = "UNLABELED"


@dataclass
class WindowEvaluationRecord:
    """Complete evaluation data envelope for a single 5.0-second traffic window."""
    window_id: int
    capture_name: str
    start_time: float
    end_time: float
    packet_count: int
    feature_vector: List[float]
    feature_dict: Dict[str, float]
    ground_truth: WindowGroundTruth
    is_mixed: bool                    # True if window overlaps both Benign and Malicious flows
    overlapping_flow_count: int
    overlapping_labels: List[str]
    detailed_labels: List[str]
    raw_packets: List[ParsedPacket] = field(default_factory=list, repr=False)

    @property
    def is_eligible_for_metrics(self) -> bool:
        """Only BENIGN and MALICIOUS windows participate in classification metrics."""
        return self.ground_truth in (WindowGroundTruth.BENIGN, WindowGroundTruth.MALICIOUS)


@dataclass
class CaptureProcessingSummary:
    """Summary statistics for PCAP parsing and window generation."""
    capture_name: str
    total_capture_records: int
    parsed_successfully: int
    parse_failures: int
    parse_success_rate: float
    first_timestamp: Optional[float]
    last_timestamp: Optional[float]
    capture_duration_sec: float
    total_windows_generated: int
    benign_windows_count: int
    malicious_windows_count: int
    background_only_count: int
    unlabeled_count: int
    mixed_windows_count: int


def determine_window_ground_truth(
    overlapping_flows: List[ZeekFlowRecord]
) -> Tuple[WindowGroundTruth, bool, List[str], List[str]]:
    """Assign deterministic ground truth to a 5-second window from overlapping flows.

    Deterministic Rule:
    A. If at least one overlapping flow is labelled 'Malicious' => MALICIOUS
    B. Else if at least one overlapping flow is labelled 'Benign' => BENIGN
    C. Else if overlapping flows exist and all are 'Background' => BACKGROUND_ONLY
    D. If no labelled flow overlaps the window => UNLABELED

    Mixed Window Flag:
    If a window contains both Benign and Malicious flows, it is classified as MALICIOUS
    and flagged with is_mixed=True.

    Returns:
        Tuple of (ground_truth, is_mixed, overlapping_labels, detailed_labels).
    """
    if not overlapping_flows:
        return WindowGroundTruth.UNLABELED, False, [], []

    labels = [f.label for f in overlapping_flows]
    detailed = list(set(f.detailed_label for f in overlapping_flows if f.detailed_label and f.detailed_label != "-"))

    has_malicious = any(lbl == "Malicious" for lbl in labels)
    has_benign = any(lbl == "Benign" for lbl in labels)

    if has_malicious:
        # Rule A: Any Malicious flow => window is MALICIOUS
        is_mixed = has_benign
        return WindowGroundTruth.MALICIOUS, is_mixed, list(set(labels)), detailed
    elif has_benign:
        # Rule B: No Malicious, at least one Benign flow => BENIGN
        return WindowGroundTruth.BENIGN, False, list(set(labels)), detailed
    else:
        # Rule C: All overlapping flows are Background => BACKGROUND_ONLY
        return WindowGroundTruth.BACKGROUND_ONLY, False, list(set(labels)), detailed


class TrafficWindowBuilder:
    """Constructs discrete 5-second traffic windows and resolves ground truth."""

    def __init__(
        self,
        window_duration: float = 5.0,
        include_empty_windows: bool = False,
    ):
        self.window_duration = float(window_duration)
        self.include_empty_windows = bool(include_empty_windows)

    def process_capture(
        self,
        capture_name: str,
        packet_records: Iterator[PcapPacketRecord],
        zeek_flows: List[ZeekFlowRecord],
        max_windows: Optional[int] = None,
    ) -> Tuple[List[WindowEvaluationRecord], CaptureProcessingSummary]:
        """Process packet records and align with sorted Zeek flows into 5-second windows.

        Args:
            capture_name: Identifier for the capture file.
            packet_records: Generator/iterator of PcapPacketRecord.
            zeek_flows: Pre-parsed ZeekFlowRecord list, sorted by start_time.
            max_windows: Optional maximum number of windows to generate.

        Returns:
            Tuple of (list of WindowEvaluationRecord, CaptureProcessingSummary).
        """
        # Ensure flows are sorted
        flows_sorted = sorted(zeek_flows, key=lambda f: f.start_time)

        total_records = 0
        parsed_ok = 0
        parse_fails = 0
        first_ts: Optional[float] = None
        last_ts: Optional[float] = None

        windows: List[WindowEvaluationRecord] = []
        current_window_packets: List[ParsedPacket] = []
        current_window_start: Optional[float] = None

        flow_cursor = 0
        total_flows = len(flows_sorted)

        def finalize_window(w_start: float, pkts: List[ParsedPacket]) -> WindowEvaluationRecord:
            nonlocal flow_cursor
            w_end = w_start + self.window_duration

            # Advance flow cursor to skip flows that ended before this window
            while flow_cursor < total_flows and flows_sorted[flow_cursor].end_time < w_start:
                flow_cursor += 1

            # Collect all flows overlapping [w_start, w_end)
            overlapping: List[ZeekFlowRecord] = []
            scan_idx = flow_cursor
            while scan_idx < total_flows:
                flow = flows_sorted[scan_idx]
                if flow.start_time >= w_end:
                    # Flows sorted by start_time: subsequent flows start after this window
                    break
                # Overlap condition: flow starts before window ends, and ends at/after window start
                if flow.start_time < w_end and flow.end_time >= w_start:
                    overlapping.append(flow)
                scan_idx += 1

            # Extract 13 features using production extractor
            feature_vec, feature_dict = extract_features_from_window(
                pkts, window_duration=self.window_duration
            )

            # Determine ground truth
            gt, is_mixed, ov_labels, det_labels = determine_window_ground_truth(overlapping)

            return WindowEvaluationRecord(
                window_id=len(windows),
                capture_name=capture_name,
                start_time=w_start,
                end_time=w_end,
                packet_count=len(pkts),
                feature_vector=feature_vec,
                feature_dict=feature_dict,
                ground_truth=gt,
                is_mixed=is_mixed,
                overlapping_flow_count=len(overlapping),
                overlapping_labels=ov_labels,
                detailed_labels=det_labels,
                raw_packets=pkts,
            )

        # Stream and parse packets
        for rec in packet_records:
            total_records += 1
            ts = rec.timestamp
            if first_ts is None:
                first_ts = ts
            last_ts = ts

            # Parse frame using existing NetSentinel parser without modifications
            parsed_pkt = parse_packet(rec.raw_bytes, timestamp=ts)

            if parsed_pkt.error:
                # Capture record fails Ethernet or protocol parsing
                parse_fails += 1
                continue

            parsed_ok += 1

            # Initialize initial window boundary
            if current_window_start is None:
                current_window_start = ts

            # Check if packet belongs to current window or subsequent window
            while ts >= current_window_start + self.window_duration:
                # Finalize current window
                win_rec = finalize_window(current_window_start, current_window_packets)
                windows.append(win_rec)
                current_window_packets = []
                current_window_start += self.window_duration

                if max_windows and len(windows) >= max_windows:
                    break

                # If empty windows not requested, fast-forward to window containing ts
                if not self.include_empty_windows and ts >= current_window_start + self.window_duration:
                    steps = int((ts - current_window_start) // self.window_duration)
                    current_window_start += steps * self.window_duration

            if max_windows and len(windows) >= max_windows:
                break

            current_window_packets.append(parsed_pkt)

        # Finalize trailing active window if packets remain
        if (
            (max_windows is None or len(windows) < max_windows)
            and current_window_start is not None
            and (len(current_window_packets) > 0 or self.include_empty_windows)
        ):
            win_rec = finalize_window(current_window_start, current_window_packets)
            windows.append(win_rec)

        # Compute summary
        duration = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0.0
        success_rate = (parsed_ok / total_records) if total_records > 0 else 0.0

        benign_count = sum(1 for w in windows if w.ground_truth == WindowGroundTruth.BENIGN)
        mal_count = sum(1 for w in windows if w.ground_truth == WindowGroundTruth.MALICIOUS)
        bg_count = sum(1 for w in windows if w.ground_truth == WindowGroundTruth.BACKGROUND_ONLY)
        unlab_count = sum(1 for w in windows if w.ground_truth == WindowGroundTruth.UNLABELED)
        mixed_count = sum(1 for w in windows if w.is_mixed)

        summary = CaptureProcessingSummary(
            capture_name=capture_name,
            total_capture_records=total_records,
            parsed_successfully=parsed_ok,
            parse_failures=parse_fails,
            parse_success_rate=round(success_rate, 4),
            first_timestamp=first_ts,
            last_timestamp=last_ts,
            capture_duration_sec=round(duration, 4),
            total_windows_generated=len(windows),
            benign_windows_count=benign_count,
            malicious_windows_count=mal_count,
            background_only_count=bg_count,
            unlabeled_count=unlab_count,
            mixed_windows_count=mixed_count,
        )

        return windows, summary
