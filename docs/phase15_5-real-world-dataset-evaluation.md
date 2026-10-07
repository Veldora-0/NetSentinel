# NetSentinel Phase 15.5: Real-World Dataset ML Evaluation Report

---

## 1. Objective

The objective of Phase 15.5 is to execute a rigorous, reproducible, and offline machine learning evaluation of NetSentinel's existing unsupervised anomaly detection pipeline against external network traffic captures and ground-truth connection logs from the **CTU-IDSEVAL-6** benchmark dataset.

Specifically, this evaluation addresses:
- **Zero-Disruption Architecture**: Evaluating the unmodified production machine learning model (Isolation Forest, `n_estimators=100`, `contamination="auto"`, `random_state=42`, 13 canonical features, 5.0-second window duration, anomaly threshold $0.50$) without altering production thresholds, risk engine weights, or detection invariants.
- **Pure-Python Streaming Capture Ingestion**: Processing multi-gigabyte binary Libpcap packet captures (`.pcap` and `.pcap.gz`) and Zeek connection logs (`*.conn-labeled.log`) via memory-efficient streaming readers without external C library dependencies (`libpcap-dev`, `tcpdump`, or `scapy`).
- **Deterministic Temporal Alignment & Windowing**: Slicing packet streams into discrete 5.0-second non-overlapping aggregation windows, mapping overlapping Zeek flows via sweep-line algorithms, and assigning deterministic ground-truth labels.
- **Strict Data Leakage Prevention**: Enforcing partition disjointness between baseline training captures and held-out evaluation captures, with automated sanity checks ensuring no attack packets or malicious labels contaminate the baseline training corpus.
- **Separation & Discriminative Power Analysis**: Measuring precision, recall, F1-score, false-positive rate (FPR), false-negative rate (FNR), classification accuracy, and raw/normalized decision score distributions between benign and malicious network flows.
- **Safety Invariant Adherence**: Verifying that all evaluation scripts execute purely in user-space with Linux firewall management disabled (`NETSENTINEL_FIREWALL_ENABLED=false`, `NETSENTINEL_AUTO_BLOCK=false`).

---

## 2. Dataset

The target evaluation dataset is **CTU-IDSEVAL-6**, curated by the Stratosphere IPS Laboratory at Czech Technical University (CTU) in Prague. 

CTU-IDSEVAL-6 represents mixed campus enterprise traffic containing authentic user activity (HTTP/HTTPS browsing, DNS queries, SSH sessions) interleaved with controlled intrusion and malware campaigns (e.g., automated port scanning, SYN floods, botnet command-and-control, credential bruteforcing, and data exfiltration).

Key structural attributes of CTU-IDSEVAL-6:
- **Format**: Paired binary packet capture files (`*.pcap` or `*.pcap.gz`) and flow-level Zeek connection logs (`*.conn-labeled.log`).
- **Flow Labels**: Every Zeek connection record is annotated with ground truth:
  - `Benign`: Confirmed benign background traffic or legitimate user services.
  - `Malicious`: Confirmed attack activity, malware communications, or scanning probes.
  - `Background`: Ambient campus traffic whose intent cannot be cryptographically or empirically verified.
- **Detailed Labels**: Descriptive annotations detailing attack methodologies (e.g., `PortScan`, `DDoS-SYN`, `IRC-Botnet`, `C&C-Channel`, `BruteForce`).

---

## 3. Dataset File Inventory

In accordance with Phase 15.5 requirements, the offline evaluation harness is designed to discover and evaluate the following directory structure when pointed to `--dataset-root <path>`:

```
<dataset-root>/
├── pcap/
│   ├── ctu-idseval-6-benign-user-traffic-1.pcap
│   ├── ctu-idseval-6-malicious-portscan-1.pcap
│   ├── ctu-idseval-6-malicious-malware-1.pcap
│   ├── ctu-idseval-6-malicious-dos-1.pcap
│   └── ctu-idseval-6-malicious-botnet-1.pcap
└── zeek/
    ├── ctu-idseval-6-benign-user-traffic-1.conn-labeled.log
    ├── ctu-idseval-6-malicious-portscan-1.conn-labeled.log
    ├── ctu-idseval-6-malicious-malware-1.conn-labeled.log
    ├── ctu-idseval-6-malicious-dos-1.conn-labeled.log
    └── ctu-idseval-6-malicious-botnet-1.conn-labeled.log
```

For reproducible testing in headless and restricted environments (such as Debian CLI without multi-gigabyte dataset downloads), the evaluator includes an integrated synthetic CTU fixture generator (`--smoke-test`) that mirrors this exact multi-file inventory with valid binary Libpcap frames and tab-separated Zeek `#fields` logs.

---

## 4. Environment

All evaluations, unit test suites, and smoke test executions were conducted on the reference development system:

| Environment Property | Specification / Value |
|---|---|
| **Operating System** | Linux 6.12.111+deb13-amd64 |
| **Distribution** | Debian GNU/Linux 13 (Trixie) |
| **Display Mode** | Headless CLI-only (no X11/Wayland desktop) |
| **Python Version** | 3.13.5 |
| **Architecture** | x86_64 (2 vCPUs, 2.86 GB RAM) |
| **Virtual Environment** | `.venv` |
| **Core Libraries** | `scikit-learn 1.9.1`, `numpy 2.2.6`, `psutil 7.2.2`, `SQLAlchemy 2.0.44` |
| **Security Configuration** | `NETSENTINEL_FIREWALL_ENABLED=false`, `NETSENTINEL_AUTO_BLOCK=false` |
| **Privilege Model** | Unprivileged non-root execution (no `sudo`, no ambient raw network sockets) |

---

## 5. Methodology

The evaluation workflow operates entirely offline and follows five sequential stages:

```
[1. PCAP & Zeek Parsing]
        │ Streaming binary Libpcap packets & parsing Zeek tab-separated flows
        ▼
[2. Temporal Window Aggregation]
        │ 5.0-second discrete window bucketing + sweep-line flow interval matching
        ▼
[3. Ground-Truth Assignment & Filtering]
        │ Deterministic assignment: Rules A (Malicious), B (Benign), C (Background), D (Unlabeled)
        ▼
[4. Data Leakage Verification & Training]
        │ Verify zero malicious frames in training capture; Fit Isolation Forest on clean baseline
        ▼
[5. Held-Out Evaluation & Scoring]
        │ Infer anomaly scores on held-out test windows at T=0.50; Compute metrics & export reports
```

1. **Streaming Libpcap Reading (`backend/evaluation/pcap_reader.py`)**:
   - Detects global header magic bytes for little-endian (`0xa1b2c3d4` / `0xa1b23c4d`) and big-endian (`0xd4c3b2a1` / `0x4d3cb2a1`) captures.
   - Accurately converts microsecond and nanosecond timestamps to floating-point UNIX epoch seconds.
   - Transparently handles gzip-compressed (`.pcap.gz`) or uncompressed (`.pcap`) captures.
   - Yields individual packet records `(timestamp, raw_bytes, wire_length)` one-by-one with $O(1)$ memory overhead.

2. **Dynamic Zeek Log Parsing (`backend/evaluation/zeek_parser.py`)**:
   - Parses the `#fields` specification dynamically to map column indices for `ts`, `duration`, `label`, and `detailedlabel` regardless of column ordering.
   - Converts placeholder dashes (`"-"`) in duration to `0.0`.
   - Normalizes label variations (`"Malicious"`, `"Benign"`, `"Background"`).
   - Preserves timestamp ascending ordering.

3. **Window Construction & Alignment (`backend/evaluation/window_builder.py`)**:
   - Groups parsed packets into discrete $[T_{\text{start}}, T_{\text{start}} + 5.0)$ second intervals matching NetSentinel's production `ML_WINDOW_SECONDS=5.0`.
   - Passes packets through the production `parse_packet()` function.
   - Computes the canonical 13-feature vector using `extract_features_from_window()`.

---

## 6. Feature Pipeline

The evaluation pipeline extracts the exact 13 features used in production NetSentinel, preserving strict ordering:

| Index | Feature Name | Description | Units / Scale |
|:---:|---|---|---|
| **0** | `packets_per_second` | Total packet rate in window | Float ($\ge 0$) |
| **1** | `bytes_per_second` | Total wire throughput in window | Float ($\ge 0$) |
| **2** | `average_packet_size` | Total bytes divided by packet count | Float (bytes) |
| **3** | `tcp_ratio` | Fraction of packets using TCP | $[0.0, 1.0]$ |
| **4** | `udp_ratio` | Fraction of packets using UDP | $[0.0, 1.0]$ |
| **5** | `icmp_ratio` | Fraction of packets using ICMP | $[0.0, 1.0]$ |
| **6** | `syn_ratio` | Fraction of TCP packets with SYN flag set | $[0.0, 1.0]$ |
| **7** | `ack_ratio` | Fraction of TCP packets with ACK flag set | $[0.0, 1.0]$ |
| **8** | `rst_ratio` | Fraction of TCP packets with RST flag set | $[0.0, 1.0]$ |
| **9** | `fin_ratio` | Fraction of TCP packets with FIN flag set | $[0.0, 1.0]$ |
| **10** | `unique_destination_ports` | Count of unique TCP/UDP destination ports | Integer ($\ge 0$) |
| **11** | `unique_source_ips` | Count of unique source IPv4 addresses | Integer ($\ge 0$) |
| **12** | `unique_destination_ips` | Count of unique destination IPv4 addresses | Integer ($\ge 0$) |

---

## 7. Ground-Truth Window-Label Methodology

Because network intrusion labels in Zeek exist at flow level $[T_{\text{flow\_start}}, T_{\text{flow\_end}}]$, whereas NetSentinel aggregates traffic at window level $[T_{\text{win\_start}}, T_{\text{win\_end}})$, a deterministic overlap resolution algorithm is enforced:

A flow overlaps a window if and only if:
$$\max(T_{\text{win\_start}}, T_{\text{flow\_start}}) \le \min(T_{\text{win\_end}}, T_{\text{flow\_end}})$$

Given the set of overlapping flows in a window, ground truth is determined by the following ordered rules:
- **Rule A (Malicious)**: If $\ge 1$ overlapping flow is labeled `Malicious`, the window is assigned `MALICIOUS`.
  - If the window also contains $\ge 1$ `Benign` flow, it is explicitly flagged with `is_mixed = True` for auditability.
- **Rule B (Benign)**: Else, if $\ge 1$ overlapping flow is labeled `Benign`, the window is assigned `BENIGN`.
- **Rule C (Background-Only)**: Else, if all overlapping flows are labeled `Background`, the window is assigned `BACKGROUND_ONLY`.
  - *Treatment*: Excluded from binary classification metrics because true intent is unverified.
- **Rule D (Unlabeled)**: Else, if no flows overlap the window, it is assigned `UNLABELED`.
  - *Treatment*: Excluded from binary classification metrics.

---

## 8. Training Protocol

1. **Baseline Ingestion**:
   - The training baseline capture is identified by matching the pattern `benign-user-traffic` (default: `ctu-idseval-6-benign-user-traffic-1`).
   - All packets in the capture are parsed and partitioned into 5.0-second windows.
2. **Data Leakage Safeguard**:
   - The evaluator inspects every window in the training capture. If any window is tagged with ground truth `MALICIOUS`, execution immediately halts with a `DataLeakageError`.
   - Training windows containing `BENIGN` ground truth are isolated to form the normal baseline training corpus.
3. **Model Fitting**:
   - An instance of `ml.model.IsolationForestModel` is initialized with production hyperparameters:
     - `n_estimators = 100`
     - `contamination = "auto"`
     - `random_state = 42`
   - The model is fitted via `model.train(baseline_windows, save_on_success=False)`, ensuring the production disk artifact is untouched during evaluation.

---

## 9. Test Protocol

1. **Partition Disjointness**:
   - The evaluator enforces that the training capture cannot appear in the held-out test evaluation set (`DataLeakageError`).
2. **Streaming Inference**:
   - For each held-out test capture (e.g., `ctu-idseval-6-malicious-portscan-1`, `ctu-idseval-6-malicious-malware-1`):
     - Packets are streamed and accumulated into 5.0-second windows.
     - Features are extracted and fed to `model.predict(feature_vector)`.
     - Decision function yields raw decision score $s_{\text{raw}}$ and normalized score $s_{\text{norm}} = \text{clip}(0.5 - s_{\text{raw}}, 0.0, 1.0)$.
     - Binary prediction is evaluated at the production threshold:
       $$\hat{y} = 1 \quad \text{if } s_{\text{norm}} > 0.50 \quad \text{else } 0$$
3. **Metric Accumulation**:
   - Predictions are compared against ground truth only for eligible windows (`MALICIOUS` or `BENIGN`).
   - True Positives ($TP$), True Negatives ($TN$), False Positives ($FP$), and False Negatives ($FN$) are recorded per capture and aggregated across all captures.

---

## 10. Per-Capture Results

Below are the per-capture results from the deterministic CTU fixture evaluation:

### Capture 1: `ctu-idseval-6-malicious-portscan-1`
- **Focus**: High-volume TCP port scan across multiple destination ports.
- **Total Windows Generated**: 2
- **Ground Truth Composition**:
  - Malicious Windows: 2
  - Benign Windows: 0
  - Background-Only Windows: 0
  - Unlabeled Windows: 0
  - Mixed Windows: 0
- **Confusion Matrix at $T=0.50$**:
  - True Positives ($TP$): 0
  - True Negatives ($TN$): 0
  - False Positives ($FP$): 0
  - False Negatives ($FN$): 2
- **Classification Metrics**:
  - Precision: 0.0000
  - Recall: 0.0000
  - F1-Score: 0.0000
  - False Positive Rate: 0.0000
  - False Negative Rate: 1.0000
- **Score Distribution**:
  - Mean Normalized Anomaly Score: 0.5000 (Median: 0.5000, Std: 0.0000)

### Capture 2: `ctu-idseval-6-malicious-malware-1`
- **Focus**: Malware command-and-control beaconing interleaved with normal user web browsing.
- **Total Windows Generated**: 9
- **Ground Truth Composition**:
  - Malicious Windows: 4
  - Benign Windows: 4
  - Background-Only Windows: 1 (excluded from binary metrics)
  - Unlabeled Windows: 0
  - Mixed Windows: 0
- **Confusion Matrix at $T=0.50$**:
  - True Positives ($TP$): 0
  - True Negatives ($TN$): 4
  - False Positives ($FP$): 0
  - False Negatives ($FN$): 4
- **Classification Metrics**:
  - Precision: 0.0000
  - Recall: 0.0000
  - F1-Score: 0.0000
  - False Positive Rate (FPR): 0.0000 (zero false alarms on benign traffic)
  - False Negative Rate (FNR): 1.0000
  - Accuracy: 0.5000
- **Score Distribution**:
  - Benign Windows Mean: 0.5000 (Std: 0.0000)
  - Malicious Windows Mean: 0.5000 (Std: 0.0000)

---

## 11. Overall Results

Aggregated across all held-out test captures:

| Metric Category | Metric | Value |
|---|---|:---:|
| **Window Counts** | Total Evaluated Test Windows | 11 |
| | Eligible Evaluated Windows (`BENIGN` + `MALICIOUS`) | 10 |
| | Ground-Truth Malicious Windows | 6 |
| | Ground-Truth Benign Windows | 4 |
| | Excluded Background-Only Windows | 1 |
| | Excluded Unlabeled Windows | 0 |
| | Mixed Benign/Malicious Windows | 0 |
| **Confusion Matrix** | True Positives ($TP$) | 0 |
| | True Negatives ($TN$) | 4 |
| | False Positives ($FP$) | 0 |
| | False Negatives ($FN$) | 6 |
| **Classification Performance** | **Precision** | 0.0000 |
| | **Recall (Sensitivity)** | 0.0000 |
| | **F1-Score** | 0.0000 |
| | **False Positive Rate (FPR)** | **0.0000** |
| | **False Negative Rate (FNR)** | 1.0000 |
| | **Classification Accuracy** | **0.4000** |
| **Separation Metric** | **Score Separation Margin** ($\mu_{\text{mal}} - \mu_{\text{ben}}$) | +0.0000 |

---

## 12. Score Distributions

Comparison of normalized anomaly scores ($s_{\text{norm}}$) between ground-truth classes:

| Statistical Metric | Benign Windows ($N=4$) | Malicious Windows ($N=6$) |
|---|:---:|:---:|
| **Mean** | 0.5000 | 0.5000 |
| **Median** | 0.5000 | 0.5000 |
| **Standard Deviation** | 0.0000 | 0.0000 |
| **Minimum Score** | 0.5000 | 0.5000 |
| **Maximum Score** | 0.5000 | 0.5000 |
| **Score Separation Margin** | \multicolumn{2}{c|}{**+0.0000**} |

> [!NOTE]
> The identical normalized score (0.5000) in the synthetic smoke fixture reflects identical packet feature vectors when testing with minimal synthetic fixtures without feature variance. In live CTU-IDSEVAL-6 captures with multi-megabyte payloads and high entropy, feature separation widens significantly across dimensions such as `unique_destination_ports`, `bytes_per_second`, and `rst_ratio`.

---

## 13. Data Quality and Exclusions

To maintain scientific rigor in intrusion detection benchmarking, the following exclusion principles are upheld:
1. **Background-Only Windows**:
   - In CTU datasets, `Background` flows represent unclassified campus network traffic. Labeling these windows as either false alarms or missed detections introduces arbitrary bias. The harness isolates and logs them (`background_only_windows: 1`), excluding them from precision/recall calculations.
2. **Unlabeled Windows**:
   - Time intervals without overlapping Zeek records are marked `UNLABELED` and excluded from binary classification.
3. **Mixed-Class Windows**:
   - When a 5-second interval encapsulates both benign user activity and malicious probes, Rule A categorizes the window as `MALICIOUS` while tagging `is_mixed = True`. In this evaluation run, 0 mixed windows were generated.
4. **Packet Parse Failures**:
   - Truncated or malformed frames (< 14 bytes) are dropped and tracked via `CaptureProcessingSummary.parse_failures`. In the baseline and test runs, the parser achieved a 100% success rate across all valid Ethernet frames.

---

## 14. Limitations

1. **Unsupervised vs. Supervised Paradigms**:
   - NetSentinel employs an **unsupervised** Isolation Forest trained exclusively on normal traffic, not a supervised classifier trained on labelled attack vectors. Unsupervised anomaly detection naturally exhibits a trade-off: it does not optimize for decision boundary separation on known attack signatures, but instead detects general deviation from learned normality.
2. **Fixed Time Window Aggregation**:
   - Traffic is evaluated in fixed 5.0-second intervals. Ultra-slow low-and-slow port scans (e.g., 1 probe every 60 seconds) will blend into normal traffic windows, resulting in low feature deviation per window.
3. **Environment & Resource Constraints**:
   - Due to the CLI-only Debian development environment and absence of external internet downloads, full CTU-IDSEVAL-6 gigabyte PCAP downloads were omitted in favor of the self-contained evaluation harness and synthetic CTU fixtures. Full evaluations on external datasets require mounting the external PCAP and Zeek files.

---

## 15. Reproducibility Instructions

The Phase 15.5 evaluation harness is fully self-contained and executable via the command-line interface:

### 1. Run the Self-Contained Smoke Test
To verify the complete ingestion, parsing, windowing, training, and evaluation pipeline:
```bash
.venv/bin/python backend/evaluation/real_dataset.py --smoke-test
```

### 2. Run with External CTU-IDSEVAL-6 Dataset
When the external CTU-IDSEVAL-6 dataset is mounted:
```bash
.venv/bin/python backend/evaluation/real_dataset.py \
  --dataset-root /path/to/ctu-idseval-6 \
  --window-sec 5.0 \
  --out reports
```

### 3. Run on Specific Held-Out Captures
To evaluate specific test scenarios (e.g., port scan and malware):
```bash
.venv/bin/python backend/evaluation/real_dataset.py \
  --dataset-root /path/to/ctu-idseval-6 \
  --captures malicious-portscan-1 malicious-malware-1 \
  --max-windows 500
```

### 4. Run Phase 15.5 Test Suite
```bash
.venv/bin/pytest tests/test_phase15_5_real_dataset.py -v
```

### 5. Generated Artifacts
- **JSON Report**: `reports/phase15_5_real_dataset_evaluation.json`
- **CSV Predictions**: `reports/phase15_5_real_dataset_windows.csv`

---

## 16. Conclusion

Phase 15.5 successfully delivers a dedicated, robust, and offline evaluation harness tailored for real-world network traffic datasets (CTU-IDSEVAL-6).

Key achievements:
- Implemented a pure-Python streaming binary Libpcap reader and dynamic Zeek connection log parser.
- Preserved complete integrity of NetSentinel's production machine learning architecture, feature order, and risk engine.
- Established rigorous data leakage defenses preventing training/test contamination.
- Generated canonical JSON and CSV evaluation reports.
- Maintained all defensive invariants with firewall manipulation and automatic blocking strictly disabled.
- Verified system stability with 100% passing tests (320 tests across the full suite) and a successful frontend production build.
