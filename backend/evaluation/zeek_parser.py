"""NetSentinel Zeek Labelled Connection Log Parser (Phase 15.5).

Dynamically parses Zeek (.conn-labeled.log and .conn-labeled.log.gz) tab-separated connection
logs. Reads field headers dynamically to extract flow timestamps, durations, and labels without
assuming fixed column positions.
"""

from dataclasses import dataclass
import gzip
import os
from typing import Any, Dict, Generator, List, Optional


@dataclass
class ZeekFlowRecord:
    """Represents a single parsed connection flow record from Zeek logs."""
    flow_index: int
    ts: float                     # Flow start timestamp (Unix epoch seconds)
    duration: float               # Flow duration in seconds (>= 0.0)
    start_time: float             # Equivalent to ts
    end_time: float               # ts + duration
    label: str                    # Standardized label ("Benign", "Malicious", "Background")
    raw_label: str                # Exact raw label string from log
    detailed_label: str           # Detailed label (e.g. "PortScan", "Attack", "-")
    proto: Optional[str] = None   # Protocol name ("tcp", "udp", "icmp")
    orig_h: Optional[str] = None  # Source IP
    orig_p: Optional[int] = None  # Source Port
    resp_h: Optional[str] = None  # Destination IP
    resp_p: Optional[int] = None  # Destination Port


def normalize_zeek_label(raw: str) -> str:
    """Normalize raw Zeek label string into canonical class name.

    Returns:
        "Malicious", "Benign", or "Background".
    """
    cleaned = raw.strip().lower()
    if "malicious" in cleaned:
        return "Malicious"
    elif "benign" in cleaned:
        return "Benign"
    elif "background" in cleaned:
        return "Background"
    return raw.strip()


class ZeekLogParser:
    """Parser for Zeek connection logs with dynamic header resolution."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse_flows(self) -> List[ZeekFlowRecord]:
        """Parse all connection flows from the log file, sorted by ts ascending.

        Returns:
            List of ZeekFlowRecord objects sorted by start_time.
        """
        flows: List[ZeekFlowRecord] = []
        is_gz = self.filepath.endswith(".gz")
        open_func = gzip.open if is_gz else open

        separator = "\t"
        fields: Optional[List[str]] = None
        field_indices: Dict[str, int] = {}
        flow_idx = 0

        with open_func(self.filepath, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue

                # Header inspection
                if line.startswith("#separator"):
                    parts = line.split()
                    if len(parts) >= 2:
                        raw_sep = parts[1]
                        if raw_sep == "\\x09":
                            separator = "\t"
                        elif raw_sep == "\\x20":
                            separator = " "
                        else:
                            separator = raw_sep
                    continue

                if line.startswith("#fields"):
                    parts = line.split(separator)
                    fields = [p.strip() for p in parts[1:]]
                    field_indices = {name: i for i, name in enumerate(fields)}
                    continue

                # Ignore comments or directives
                if line.startswith("#"):
                    continue

                # Data line
                if not fields:
                    continue

                tokens = line.split(separator)
                if len(tokens) < len(fields):
                    # Malformed or truncated row
                    continue

                # Extract ts
                if "ts" not in field_indices:
                    continue
                try:
                    ts = float(tokens[field_indices["ts"]])
                except (ValueError, TypeError):
                    continue

                # Extract duration
                duration = 0.0
                if "duration" in field_indices:
                    dur_val = tokens[field_indices["duration"]].strip()
                    if dur_val not in ("-", "(empty)", ""):
                        try:
                            duration = max(0.0, float(dur_val))
                        except (ValueError, TypeError):
                            duration = 0.0

                # Extract label
                raw_label = "-"
                if "label" in field_indices:
                    raw_label = tokens[field_indices["label"]].strip()
                elif "tunnel_parents.label" in field_indices:
                    raw_label = tokens[field_indices["tunnel_parents.label"]].strip()

                norm_label = normalize_zeek_label(raw_label)

                # Extract detailedlabel
                detailed = "-"
                if "detailedlabel" in field_indices:
                    detailed = tokens[field_indices["detailedlabel"]].strip()
                elif "detailed_label" in field_indices:
                    detailed = tokens[field_indices["detailed_label"]].strip()

                # Optional connection identifiers
                proto = tokens[field_indices["proto"]].strip() if "proto" in field_indices else None
                orig_h = tokens[field_indices["id.orig_h"]].strip() if "id.orig_h" in field_indices else None
                resp_h = tokens[field_indices["id.resp_h"]].strip() if "id.resp_h" in field_indices else None

                orig_p = None
                if "id.orig_p" in field_indices:
                    try:
                        orig_p = int(tokens[field_indices["id.orig_p"]].strip())
                    except ValueError:
                        pass

                resp_p = None
                if "id.resp_p" in field_indices:
                    try:
                        resp_p = int(tokens[field_indices["id.resp_p"]].strip())
                    except ValueError:
                        pass

                flows.append(ZeekFlowRecord(
                    flow_index=flow_idx,
                    ts=ts,
                    duration=duration,
                    start_time=ts,
                    end_time=ts + duration,
                    label=norm_label,
                    raw_label=raw_label,
                    detailed_label=detailed,
                    proto=proto,
                    orig_h=orig_h,
                    orig_p=orig_p,
                    resp_h=resp_h,
                    resp_p=resp_p,
                ))
                flow_idx += 1

        # Sort flows by timestamp ascending
        flows.sort(key=lambda x: x.ts)
        return flows


def write_synthetic_zeek_log(
    filepath: str,
    flows: List[Dict[str, Any]],
) -> None:
    """Helper utility to write a valid synthetic Zeek .conn-labeled.log for tests.

    Args:
        filepath: Target output file path.
        flows: List of flow dictionaries with keys:
               ts, duration, label, detailedlabel, (optional: proto, orig_h, orig_p, resp_h, resp_p).
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n")
        f.write("#empty_field\t(empty)\n")
        f.write("#unset_field\t-\n")
        f.write("#path\tconn\n")
        f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tlabel\tdetailedlabel\n")
        f.write("#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\tstring\tstring\n")

        for i, flow in enumerate(flows):
            ts = flow["ts"]
            dur = str(flow.get("duration", "-"))
            lbl = flow.get("label", "Benign")
            det = flow.get("detailedlabel", "-")
            proto = flow.get("proto", "tcp")
            src_ip = flow.get("orig_h", "192.168.1.10")
            src_p = str(flow.get("orig_p", 50000 + (i % 1000)))
            dst_ip = flow.get("resp_h", "10.0.0.1")
            dst_p = str(flow.get("resp_p", 80))

            f.write(f"{ts}\tC{i:05d}\t{src_ip}\t{src_p}\t{dst_ip}\t{dst_p}\t{proto}\thttp\t{dur}\t100\t200\tSF\t-\t-\t0\tShADadFf\t5\t300\t5\t400\t-\t{lbl}\t{det}\n")

        f.write("#close\n")
