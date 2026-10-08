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
- **Offline Runtime Isolation**: Ensuring that offline evaluation modules and entrypoints do not import the live application runtime (`app.py`), preventing ambient socket instantiation (`AF_PACKET`), background worker startup, or firewall manager initialization during offline processing.
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

The CTU-IDSEVAL-6 evaluation utilizes six distinct network traffic captures partitioned into an isolated baseline training set and held-out test scenarios:

```
<dataset-root>/
├── pcap/
│   ├── ctu-idseval-6-benign-user-traffic-1.pcap
│   ├── ctu-idseval-6-malicious-portscan-1.pcap
│   ├── ctu-idseval-6-malicious-portscan-2.pcap
│   ├── ctu-idseval-6-malicious-portscan-3.pcap
│   ├── ctu-idseval-6-malicious-malware-1.pcap
│   └── ctu-idseval-6-malicious-malware-2.pcap
└── zeek/
    ├── ctu-idseval-6-benign-user-traffic-1.conn-labeled.log
    ├── ctu-idseval-6-malicious-portscan-1.conn-labeled.log
    ├── ctu-idseval-6-malicious-portscan-2.conn-labeled.log
    ├── ctu-idseval-6-malicious-portscan-3.conn-labeled.log
    ├── ctu-idseval-6-malicious-malware-1.conn-labeled.log
    └── ctu-idseval-6-malicious-malware-2.conn-labeled.log
```

### Partition Roles
- **Baseline Training Capture**: `ctu-idseval-6-benign-user-traffic-1` (used exclusively to fit the offline evaluation model on clean benign network behavior).
- **Held-Out Test Captures**:
  - `ctu-idseval-6-malicious-portscan-1`: Network reconnaissance and port probing.
  - `ctu-idseval-6-malicious-portscan-2`: Targeted port sweep activity.
  - `ctu-idseval-6-malicious-portscan-3`: Horizontal port scanning across services.
  - `ctu-idseval-6-malicious-malware-1`: Malware execution and command-and-control communication mixed with regular user traffic.
  - `ctu-idseval-6-malicious-malware-2`: Large-scale sustained malware exfiltration and beaconing campaign.

For local regression testing without downloading full multi-gigabyte PCAP files, the evaluator includes an integrated synthetic CTU fixture generator (`--smoke-test`) that mirrors this directory structure with valid binary Libpcap frames and tab-separated Zeek `#fields` logs.

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
   - The training baseline capture is identified by matching the pattern `benign-user-traffic` (`ctu-idseval-6-benign-user-traffic-1`).
   - Packets in the capture are parsed and partitioned into 5.0-second aggregation windows, yielding **2,250 clean BENIGN windows**.
2. **Data Leakage Safeguard**:
   - The evaluator inspects every window in the training capture. Zero malicious windows were found (0 malicious windows). If any window were tagged `MALICIOUS`, execution would immediately halt with a `DataLeakageError`.
   - Training/test partition disjointness was verified across all capture sets.
3. **Model Fitting**:
   - An offline instance of `ml.model.IsolationForestModel` is initialized with production hyperparameters:
     - `n_estimators = 100`
     - `contamination = "auto"`
     - `random_state = 42`
   - The model is fitted via `model.train(baseline_windows, save_on_success=False)` on the 2,250 clean BENIGN windows, ensuring the production disk artifact is untouched during evaluation.
   - *Important Interpretation*: The offline evaluation model is fitted on 2,250 clean benign windows from the external dataset while preserving the production algorithm, hyperparameters, features, 5.0-second window duration, and operating threshold ($0.50$). This evaluation model is separate from the production detector's normal 10-window live baseline, and the live production runtime was neither replaced nor retrained.

---

## 9. Test Protocol

1. **Partition Disjointness**:
   - The evaluator enforces that the training capture cannot appear in the held-out test evaluation set (`DataLeakageError`).
2. **Streaming Inference**:
   - Across the five held-out test captures (`portscan-1`, `portscan-2`, `portscan-3`, `malware-1`, `malware-2`):
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

Below are the per-capture results from the canonical CTU-IDSEVAL-6 Kaggle evaluation across all five held-out attack scenarios:

### Capture 1: `ctu-idseval-6-malicious-portscan-1`
- **Focus**: Targeted TCP port scan against isolated network services.
- **Total Windows Generated**: 1
- **Ground Truth Composition**:
  - Malicious Windows: 1
  - Benign Windows: 0
  - Background-Only Windows: 0
  - Unlabeled Windows: 0
  - Mixed Windows: 0
- **Confusion Matrix at $T=0.50$**:
  - True Positives ($TP$): 1
  - True Negatives ($TN$): 0
  - False Positives ($FP$): 0
  - False Negatives ($FN$): 0
- **Classification Metrics**:
  - Precision: 1.0000 | Recall: 1.0000 | F1-Score: 1.0000 | FPR: 0.0000 | FNR: 0.0000 | Accuracy: 1.0000
- **Score Distribution**:
  - Malicious Mean Score: **0.7303**

### Capture 2: `ctu-idseval-6-malicious-portscan-2`
- **Focus**: Fast port sweep across specific destination ports.
- **Total Windows Generated**: 1
- **Ground Truth Composition**:
  - Malicious Windows: 1
  - Benign Windows: 0
  - Background-Only Windows: 0
  - Unlabeled Windows: 0
  - Mixed Windows: 0
- **Confusion Matrix at $T=0.50$**:
  - True Positives ($TP$): 1
  - True Negatives ($TN$): 0
  - False Positives ($FP$): 0
  - False Negatives ($FN$): 0
- **Classification Metrics**:
  - Precision: 1.0000 | Recall: 1.0000 | F1-Score: 1.0000 | FPR: 0.0000 | FNR: 0.0000 | Accuracy: 1.0000
- **Score Distribution**:
  - Malicious Mean Score: **0.6997**

### Capture 3: `ctu-idseval-6-malicious-portscan-3`
- **Focus**: Multi-host horizontal port scan activity.
- **Total Windows Generated**: 21
- **Ground Truth Composition**:
  - Malicious Windows: 21
  - Benign Windows: 0
  - Background-Only Windows: 0
  - Unlabeled Windows: 0
  - Mixed Windows: 0
- **Confusion Matrix at $T=0.50$**:
  - True Positives ($TP$): 21
  - True Negatives ($TN$): 0
  - False Positives ($FP$): 0
  - False Negatives ($FN$): 0
- **Classification Metrics**:
  - Precision: 1.0000 | Recall: 1.0000 | F1-Score: 1.0000 | FPR: 0.0000 | FNR: 0.0000 | Accuracy: 1.0000
- **Score Distribution**:
  - Malicious Mean Score: **0.7353**

> [!WARNING]
> **Sample Size Notice**: The three portscan scenarios (`portscan-1`, `portscan-2`, and `portscan-3`) contain compact durations yielding 1, 1, and 21 windows respectively. While all 23 attack windows were detected correctly at $T=0.50$ without false negatives, these small window counts reflect brief bursts rather than large statistical samples.

### Capture 4: `ctu-idseval-6-malicious-malware-1`
- **Focus**: Malware command-and-control beaconing interleaved with authentic campus browsing.
- **Total Windows Generated**: 34,680
- **Packet Ingestion**: 146,425 / 146,426 packets parsed successfully (1 parse failure).
- **Ground Truth Composition**:
  - Eligible Windows: 26,094
  - Malicious Windows: 9,595
  - Benign Windows: 16,499
  - Background-Only Windows: 47 (isolated from binary metrics)
  - Unlabeled Windows: 8,539 (isolated from binary metrics)
  - Mixed Windows: 9,548
- **Confusion Matrix at $T=0.50$**:
  - True Positives ($TP$): 8,993
  - True Negatives ($TN$): 12,750
  - False Positives ($FP$): 3,749
  - False Negatives ($FN$): 602
- **Classification Metrics**:
  - Precision: **0.7058** (70.58%)
  - Recall: **0.9373** (93.73%)
  - F1-Score: **0.8052**
  - False Positive Rate (FPR): **0.2272** (22.72%)
  - False Negative Rate (FNR): **0.0627** (6.27%)
  - Classification Accuracy: **0.8333** (83.33% on eligible windows)
- **Score Distribution**:
  - Benign Mean Score: 0.4219 | Malicious Mean Score: 0.5731 | Score Separation Margin: **+0.1512**

### Capture 5: `ctu-idseval-6-malicious-malware-2`
- **Focus**: Long-duration sustained malware command-and-control and exfiltration.
- **Total Windows Generated**: 229,502
- **Packet Ingestion**: 750,882 / 750,882 packets parsed successfully (0 parse failures).
- **Ground Truth Composition**:
  - Eligible Windows: 33,203
  - Malicious Windows: 26,575
  - Benign Windows: 6,628
  - Background-Only Windows: 0
  - Unlabeled Windows: 196,299 (idle transmission intervals without overlapping flows)
  - Mixed Windows: 24,780
- **Confusion Matrix at $T=0.50$**:
  - True Positives ($TP$): 25,339
  - True Negatives ($TN$): 6,569
  - False Positives ($FP$): 59
  - False Negatives ($FN$): 1,236
- **Classification Metrics**:
  - Precision: **0.9977** (99.77%)
  - Recall: **0.9535** (95.35%)
  - F1-Score: **0.9751**
  - False Positive Rate (FPR): **0.0089** (0.89%)
  - False Negative Rate (FNR): **0.0465** (4.65%)
  - Classification Accuracy: **0.9610** (96.10% on eligible windows)
- **Score Distribution**:
  - Benign Mean Score: 0.4115 | Malicious Mean Score: 0.5703 | Score Separation Margin: **+0.1588**

---

## 11. Overall Results

Aggregated across all five held-out test captures from the canonical CTU-IDSEVAL-6 Kaggle evaluation:

| Metric Category | Metric | Value |
|---|---|:---:|
| **Window Counts** | Total Generated Test Windows | 264,205 |
| | Eligible Evaluated Windows (`BENIGN` + `MALICIOUS`) | 59,320 |
| | Ground-Truth Malicious Windows | 36,193 |
| | Ground-Truth Benign Windows | 23,127 |
| | Excluded Background-Only Windows | 47 |
| | Excluded Unlabeled Windows | 204,838 |
| | Mixed Benign/Malicious Windows | 34,328 |
| **Confusion Matrix** | True Positives ($TP$) | **34,355** |
| | True Negatives ($TN$) | **19,319** |
| | False Positives ($FP$) | **3,808** |
| | False Negatives ($FN$) | **1,838** |
| **Classification Performance** | **Precision** | **0.9002** (90.02%) |
| | **Recall (Sensitivity)** | **0.9492** (94.92%) |
| | **F1-Score** | **0.9241** |
| | **False Positive Rate (FPR)** | **0.1647** (16.47%) |
| | **False Negative Rate (FNR)** | **0.0508** (5.08%) |
| | **Classification Accuracy** | **0.9048** (90.48%) |
| **Separation Metric** | **Score Separation Margin** ($\mu_{\text{mal}} - \mu_{\text{ben}}$) | **+0.1523** |

> [!IMPORTANT]
> The **90.48% classification accuracy** applies specifically to the **59,320 labelled BENIGN and MALICIOUS windows** eligible for binary classification. It does not apply to the 204,838 unlabeled or 47 background-only intervals, which are excluded from binary metrics to avoid unverified classification bias.

---

## 12. Score Distributions

Comparison of normalized anomaly scores ($s_{\text{norm}}$) between ground-truth classes across the 59,320 eligible windows:

| Statistical Metric | Benign Windows ($N=23,127$) | Malicious Windows ($N=36,193$) |
|---|:---:|:---:|
| **Mean** | **0.4189** | **0.5712** |
| **Median** | **0.4087** | **0.5749** |
| **Standard Deviation** | 0.0651 | 0.0400 |
| **Minimum Score** | 0.3305 | 0.3542 |
| **Maximum Score** | 0.7355 | 0.7624 |
| **Score Separation Margin** | \multicolumn{2}{c|}{**+0.1523**} |

The empirical score separation margin of **+0.1523** confirms that the unsupervised Isolation Forest naturally shifts malicious traffic patterns past the production anomaly threshold ($0.50$), with the median malicious window scoring **0.5749** compared to **0.4087** for benign user activity.

---

## 13. Data Quality and Exclusions

To maintain scientific rigor in intrusion detection benchmarking, the following exclusion principles are upheld:
1. **Background-Only Windows (47 windows)**:
   - In CTU datasets, `Background` flows represent unclassified campus network traffic whose benign or malicious nature cannot be verified. Labeling these windows as either false alarms or missed detections introduces arbitrary bias. The harness isolates them and excludes them from binary classification.
2. **Unlabeled Windows (204,838 windows)**:
   - In long continuous captures (notably `malware-2`), quiet network intervals exist where no active Zeek flow records overlap the 5.0-second window. These are categorized as `UNLABELED` and excluded from binary metrics.
3. **Mixed-Class Windows (34,328 windows)**:
   - When a 5-second interval encapsulates both authentic user traffic and malicious malware/probe activity, Rule A categorizes the window as `MALICIOUS` while tagging `is_mixed = True`. In total, 34,328 mixed windows were recorded.
4. **Packet Parse Failures (1 frame)**:
   - Across 897,308 total binary packets evaluated across the test captures, only 1 truncated frame failed parsing in `malware-1` (146,425 / 146,426 frames parsed; 100% in `malware-2` with 750,882 / 750,882 frames). The overall parser success rate was **99.9999%**.

---

## 14. Limitations

1. **Unsupervised vs. Supervised Paradigms**:
   - NetSentinel employs an **unsupervised** Isolation Forest trained exclusively on normal traffic, not a supervised classifier trained on labelled attack vectors. Unsupervised anomaly detection naturally exhibits a trade-off: it does not optimize for decision boundary separation on known attack signatures, but instead detects general deviation from learned normality.
2. **Fixed Time Window Aggregation**:
   - Traffic is evaluated in fixed 5.0-second intervals. Ultra-slow low-and-slow port scans (e.g., 1 probe every 60 seconds) will blend into normal traffic windows, resulting in low feature deviation per window.
3. **Portscan Sample Size**:
   - The three portscan scenarios contain brief burst durations (1, 1, and 21 windows). While detection was 100% at $T=0.50$, these counts are compact and must be evaluated alongside the large-scale malware captures.
4. **Mixed Window Assignment**:
   - In accordance with Rule A, mixed windows containing both benign and malicious flows are assigned `MALICIOUS`. In high-traffic enterprise environments, benign packets within mixed windows contribute to aggregate window features.

---

## 15. Reproducibility Instructions

The Phase 15.5 evaluation harness is fully self-contained and executable via the command-line interface:

### 1. Run the Self-Contained Smoke Test
To verify the complete ingestion, parsing, windowing, training, and evaluation pipeline without external data:
```bash
.venv/bin/python backend/evaluation/real_dataset.py --smoke-test
```
*(The smoke test writes to an isolated temporary directory and does not overwrite canonical report artifacts).*

### 2. Run with External CTU-IDSEVAL-6 Dataset
When the external CTU-IDSEVAL-6 dataset is mounted:
```bash
.venv/bin/python backend/evaluation/real_dataset.py \
  --dataset-root /path/to/ctu-idseval-6 \
  --window-sec 5.0 \
  --output-dir reports
```

### 3. Run on Specific Held-Out Captures
To evaluate specific test scenarios (e.g., port scan and malware):
```bash
.venv/bin/python backend/evaluation/real_dataset.py \
  --dataset-root /path/to/ctu-idseval-6 \
  --captures malicious-portscan-1,malicious-malware-1 \
  --max-windows 500
```

### 4. Run Phase 15.5 Test Suite
```bash
.venv/bin/pytest tests/test_phase15_5_real_dataset.py -v
```

### 5. Repository Evaluation Artifacts
- **JSON Report**: [`reports/phase15_5_real_dataset_evaluation.json`](file:///home/debian/Desktop/NetSentinel/reports/phase15_5_real_dataset_evaluation.json) contains the complete machine-readable metrics, per-capture confusion matrices, score distributions, and quality counters from the canonical CTU-IDSEVAL-6 Kaggle evaluation.
- **Window-Level CSV Notice**: The complete 264,205-row window-level prediction CSV was generated during the external Kaggle evaluation run. A synthetic subset is not committed to the repository to avoid misleading representations.

---

## 16. Conclusion

Phase 15.5 successfully delivers a dedicated, robust, and offline evaluation harness tailored for real-world network traffic datasets (CTU-IDSEVAL-6).

Key achievements:
- Validated NetSentinel's unsupervised Isolation Forest anomaly detection engine against 264,205 generated traffic windows (59,320 labelled windows) from CTU-IDSEVAL-6.
- Achieved **90.48% classification accuracy**, **94.92% recall**, **90.02% precision**, and an $F_1$-score of **0.9241** on labelled real-world traffic.
- Preserved complete integrity of NetSentinel's production machine learning architecture, feature order, and risk engine.
- Established rigorous data leakage defenses preventing training/test contamination.
- Maintained all defensive invariants with firewall manipulation and automatic blocking strictly disabled.
- Verified system stability with 100% passing tests (323 tests across the full suite) and a successful frontend production build.
