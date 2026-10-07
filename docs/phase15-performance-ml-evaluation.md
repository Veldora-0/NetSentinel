# NetSentinel Phase 15: Performance and Machine Learning Evaluation Report

---

## 1. Objective

The objective of Phase 15 is to execute a rigorous, reproducible, and scientifically grounded performance benchmarking and machine learning evaluation of the existing NetSentinel defensive system.

This evaluation specifically addresses:
- Subsystem micro-benchmarks (raw frame parsing, rule-based intrusion detection, feature extraction, Isolation Forest inference, composite risk scoring, incident correlation, and durable SQLite persistence).
- End-to-end synthetic pipeline throughput and latency scaling.
- Resource utilization profiling (CPU utilization, process RSS memory, and memory growth) during synthetic workloads.
- Supervised evaluation of the unsupervised Isolation Forest anomaly detection engine against a controlled, ground-truth labelled evaluation dataset.
- Confusion matrix extraction, precision, recall, F1-score, and false-positive/negative trade-off analysis across decision thresholds.
- Concrete verification that safety invariants remain active throughout all evaluations (`NETSENTINEL_FIREWALL_ENABLED=false`, `NETSENTINEL_AUTO_BLOCK=false`).

---

## 2. Environment

All benchmark runs and evaluation workloads were executed on the local development environment:

| Property | Value |
|---|---|
| **Canonical Run Timestamp** | `2026-10-07T14:43:22Z` (Unix: `1791384202.434`) |
| **Operating System** | Linux 6.12.111+deb13-amd64 |
| **Distribution** | Debian GNU/Linux 13 (Trixie) |
| **Display Mode** | Headless / CLI-only |
| **Python Version** | 3.13.5 |
| **CPU Architecture** | x86_64 (2 logical cores) |
| **Physical Memory (RAM)** | 2.86 GB total |
| **Virtual Environment** | Python 3.13 `.venv` |
| **Key Runtime Dependencies** | `scikit-learn 1.9.1`, `numpy 2.2.6`, `psutil 7.2.2`, `SQLAlchemy 2.0.44`, `Flask 3.1.2` |
| **Network Security Privileges** | Unprivileged non-root execution (no `sudo`, no ambient `CAP_NET_RAW` / `CAP_NET_ADMIN` invoked) |
| **Firewall State** | `enabled=False`, `auto_block=False`, `dry_run=True` (no kernel `iptables` rules manipulated) |

> [!NOTE]
> All throughput and latency numbers in this document represent **synthetic benchmark measurements in the development Debian environment**. They do not constitute claims of line-rate production hardware throughput under live physical network traffic.

---

## 3. Methodology

1. **Deterministic Synthetic Workloads**:
   All benchmarked network inputs consist of deterministically crafted binary Ethernet/IPv4/TCP frames and `ParsedPacket` structures. Public IP addresses and external target networks were strictly excluded; all source and destination addresses use loopback (`127.0.0.1`) and RFC 1918 private subnets (`10.0.0.0/8`, `192.168.1.0/24`).

2. **Latency Timing**:
   Individual operation latencies were measured using high-resolution monotonic timers via Python's `time.perf_counter()`. Percentiles ($p_{50}$, $p_{95}$, $p_{99}$), arithmetic means, minima, and maxima were computed using standard NumPy numerical routines.

3. **Steady-State Isolation**:
   Where applicable, benchmarks execute warm-up iterations. Warm-up iterations reduce first-run initialization and cache effects so reported measurements better represent steady-state execution.

4. **Strict Safety Boundary**:
   The automated harness continuously verifies that `firewall.enabled` and `firewall.auto_block` evaluate to `False`. Mitigation actions in risk engine and incident manager benchmarks operated exclusively in simulated/dry-run mode.

---

## 4. Performance Benchmark Methodology

The benchmark suite (`backend/evaluation/benchmarks.py`) directly exercises existing components:

1. **Packet Parser**:
   Evaluates `parser.parse_packet()` on 86-byte binary frames comprising Ethernet, IPv4, and TCP headers with synthetic payload. Evaluated across load tiers of 100, 1,000, and 5,000 frames.

2. **Rule-Based Intrusion Detector**:
   Evaluates `detector.TrafficDetector.analyze_packet()` across a realistic sequence comprising 70% benign TCP traffic, 15% TCP port scan probes, and 15% TCP SYN flood packets. Evaluated across load tiers of 100, 500, and 1,000 packets.

3. **Machine Learning Pipeline**:
   - *Feature Extractor*: Evaluates `ml.feature_extractor.extract_features_from_window()` across sliding 25-packet windows over 500 iterations.
   - *Model Inference*: Evaluates `ml.model.IsolationForestModel.predict()` on a fitted, `READY` model (`n_estimators=100`, `contamination="auto"`, `random_state=42`) across load tiers of 50, 200, and 500 window vectors.

4. **Composite Risk Engine**:
   Evaluates `risk_engine.RiskEngine.assess()` across an alternating workload: rule-only detections, composite rule + ML evaluations, ML-only evaluations, and repeated source IP events exercising sliding-window repeat boosts (+0.05). Evaluated across load tiers of 100, 500, and 1,000 assessments.

5. **Incident Correlator**:
   Evaluates `incident_manager.IncidentManager.correlate_security_event()` and `build_incident_timeline()` within an isolated SQLite application context. Evaluated across load tiers of 50, 200, and 500 correlated events.

6. **SQLite Persistence**:
   Evaluates database operations (`database.save_security_event_record()` and `database.query_security_events()`) on an isolated temporary SQLite database. Evaluated across load tiers of 50, 200, and 500 operations.

7. **End-to-End Pipeline**:
   Executes the complete integrated pipeline:
   $$\text{Raw Frame Bytes} \longrightarrow \text{Parser} \longrightarrow \text{Detector} \longrightarrow \text{ML Buffer} \longrightarrow \text{Risk Engine} \longrightarrow \text{Incident Correlator} \longrightarrow \text{SQLite Database}$$
   Evaluated across load tiers of 100, 500, and 1,000 integrated packet cycles.

---

## 5. Performance Results

The following measurements were recorded during the canonical benchmark run:

### Subsystem Benchmark Summary

| Subsystem | Load Tier (Ops) | Throughput (ops/sec) | Mean Latency (ms) | Median / p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Packet Parser** | 100 | 6,475.53 | 0.0557 | 0.0099 | 0.1624 | 1.5632 | 0.0067 | 1.6615 |
| **Packet Parser** | 1,000 | 79,263.42 | 0.0124 | 0.0103 | 0.0209 | 0.0699 | 0.0067 | 0.2407 |
| **Packet Parser** | 5,000 | 93,963.79 | 0.0104 | 0.0071 | 0.0141 | 0.0645 | 0.0067 | 1.5207 |
| **Rule Detector** | 100 | 228,565.16 | 0.0041 | 0.0029 | 0.0050 | 0.0539 | 0.0018 | 0.0547 |
| **Rule Detector** | 500 | 24,625.05 | 0.0400 | 0.0089 | 0.0169 | 0.0855 | 0.0027 | 11.9185 |
| **Rule Detector** | 1,000 | 41,715.98 | 0.0235 | 0.0207 | 0.0408 | 0.0877 | 0.0037 | 0.2999 |
| **ML Feature Extraction** | 500 | 64,446.26 | 0.0153 | 0.0127 | 0.0223 | 0.0405 | 0.0120 | 0.6896 |
| **Isolation Forest Inference** | 50 | 50.38 | 19.8463 | 15.8205 | 32.6599 | 89.3887 | 12.3405 | 132.9387 |
| **Isolation Forest Inference** | 200 | 68.16 | 14.6690 | 13.4982 | 21.3580 | 24.8056 | 11.2784 | 44.9923 |
| **Isolation Forest Inference** | 500 | 69.01 | 14.4893 | 13.4533 | 19.5162 | 23.9949 | 11.3782 | 94.1706 |
| **Composite Risk Engine** | 100 | 7,538.83 | 0.1323 | 0.0115 | 0.0619 | 4.9298 | 0.0084 | 5.6750 |
| **Composite Risk Engine** | 500 | 20,655.41 | 0.0480 | 0.0178 | 0.0400 | 0.1998 | 0.0093 | 11.1635 |
| **Composite Risk Engine** | 1,000 | 6,254.90 | 0.1586 | 0.0355 | 0.2281 | 2.0837 | 0.0092 | 31.8180 |
| **Incident Correlator** | 50 | 361.97 | 2.7605 | 2.6070 | 3.4426 | 5.0297 | 2.1160 | 5.3055 |
| **Incident Correlator** | 200 | 386.39 | 2.5867 | 2.4402 | 3.4798 | 4.6291 | 2.0134 | 5.2277 |
| **Incident Correlator** | 500 | 414.21 | 2.4129 | 2.2423 | 3.3282 | 4.6860 | 1.8507 | 15.9909 |
| **SQLite Persistence & Query** | 50 | 1,940.07 | 0.5026 | 0.3859 | 0.7190 | 2.7693 | 0.3269 | 3.5230 |
| **SQLite Persistence & Query** | 200 | 2,404.10 | 0.4034 | 0.3681 | 0.5879 | 0.6753 | 0.3208 | 1.2392 |
| **SQLite Persistence & Query** | 500 | 2,098.61 | 0.4623 | 0.3958 | 0.7672 | 1.0906 | 0.3238 | 3.1111 |
| **End-to-End Pipeline** | 100 | 14,418.08 | 0.0688 | 0.0437 | 0.1327 | 0.6448 | 0.0256 | 0.7800 |
| **End-to-End Pipeline** | 500 | 21,208.65 | 0.0467 | 0.0302 | 0.0818 | 0.1784 | 0.0252 | 1.3903 |
| **End-to-End Pipeline** | 1,000 | 4,182.70 | 0.2386 | 0.0320 | 0.0906 | 8.7282 | 0.0258 | 18.3425 |

---

## 6. Resource Usage Results

System and process resource utilization metrics were monitored via `psutil` throughout the execution of the full benchmark and evaluation suite:

| Resource Metric | Measured Value | Operational Notes |
|---|:---:|---|
| **Elapsed Wall-Clock Time** | `17.92 s` | Complete execution of 7 benchmark suites + full ML evaluation |
| **Initial Process RSS Memory** | `164.81 MB` | Baseline memory following Python, Flask, and Scikit-learn imports |
| **Peak Process RSS Memory** | `175.76 MB` | Maximum resident memory observed across all benchmark runs |
| **Process Memory Growth ($\Delta$)** | `+10.95 MB` | Residual memory delta following garbage collection |
| **Final CPU Utilization** | `99.3%` | Measured instantaneous CPU percentage at the end of the evaluation run |
| **System Memory Utilization** | `26.8%` | Relative to total system memory (2.86 GB) |

> [!NOTE]
> Resource measurements reflect the synthetic benchmark execution environment. No sustained unbounded RSS growth was observed during the bounded evaluation workload. The benchmark evaluation loop runs sequentially in a single Python thread, while internal Scikit-learn/NumPy linear algebra and decision tree routines utilize multi-core CPU capabilities when available.

---

## 7. Machine Learning Evaluation Methodology

NetSentinel's machine learning engine utilizes **unsupervised Isolation Forest anomaly detection** operating over sliding 13-feature statistical traffic window vectors.

### Supervised Evaluation Protocol for Unsupervised Models
In production operation, Isolation Forest learns an unsupervised baseline without human labels. To evaluate its detection capability scientifically:
1. **Ground-Truth Labelled Dataset**: A controlled synthetic dataset of 200 windows was generated with verified ground-truth labels ($y \in \{0, 1\}$).
2. **Train/Test Independence**:
   - Baseline fitting used **50 normal windows** generated with deterministic seed `42`.
   - Test evaluation used **200 held-out windows** generated with independent seed `1337`.
   - No training window appears in the evaluation test set (0% sample overlap verified).
3. **Production Operating Threshold**:
   - Production decision rule: $\text{normalized\_score} > 0.50 \implies \text{ANOMALY} \ (1)$, else $\text{NORMAL} \ (0)$.
   - $\text{normalized\_score} = \text{clip}(0.5 - \text{raw\_decision\_score}, 0.0, 1.0)$.
4. **Metric Terminology**:
   - The continuous anomaly score $[0.0, 1.0]$ is strictly distinguished from binary classification decisions.
   - Classification accuracy, precision, and recall are reported solely in reference to this labelled evaluation test set, not as intrinsic properties of the unsupervised score itself.

---

## 8. Machine Learning Dataset Composition

The evaluation dataset was constructed with strict ground-truth labeling:

| Partition | Window Count | Class Label | Description & Feature Composition |
|---|:---:|:---:|---|
| **Training Baseline** | 50 | Normal ($0$) | Inlier baseline: pps $\approx 15\text{--}30$, tcp\_ratio $\approx 0.85\text{--}0.95$, syn\_ratio $\approx 0.02\text{--}0.08$, ack\_ratio $\approx 0.85\text{--}0.95$. Used exclusively to fit Isolation Forest trees. |
| **Held-Out Normal Test** | 100 | Normal ($0$) | Unseen normal operational traffic drawn from the baseline distribution with independent stochastic variance. |
| **Anomalous Test: SYN Flood** | 20 | Anomaly ($1$) | High pps ($3000\text{--}8000$), syn\_ratio $> 0.92$, zero ACK packets, targeting single port. |
| **Anomalous Test: Port Scan** | 20 | Anomaly ($1$) | Elevated pps ($400\text{--}1200$), high destination port cardinality ($100\text{--}500$ distinct ports), syn\_ratio $> 0.85$. |
| **Anomalous Test: UDP Flood** | 20 | Anomaly ($1$) | Elevated pps ($2500\text{--}6000$), high bps, udp\_ratio $= 1.0$, tcp\_ratio $= 0.0$. |
| **Anomalous Test: Stealth Flags** | 20 | Anomaly ($1$) | Abnormal RST/FIN ratios ($0.40\text{--}0.85$) without standard TCP handshake sequence. |
| **Anomalous Test: IP Sweep** | 20 | Anomaly ($1$) | High destination IP cardinality ($50\text{--}150$ targets), balanced protocol distribution. |
| **Total Evaluation Test Set** | **200** | **100 Normal / 100 Anomaly** | Perfectly balanced (50.0% normal, 50.0% anomalous) test set. |

---

## 9. Confusion Matrix (At Production Threshold = 0.50)

Evaluated on the 200-sample held-out evaluation test set:

```
                      PREDICTED NORMAL (<= 0.50)    PREDICTED ANOMALY (> 0.50)
ACTUAL NORMAL (0)                65 (TN)                       35 (FP)
ACTUAL ANOMALY (1)                0 (FN)                      100 (TP)
```

- **True Positives (TP)**: `100` (All 100 synthetic attack windows correctly flagged).
- **True Negatives (TN)**: `65` (65 of 100 normal windows correctly categorized below threshold).
- **False Positives (FP)**: `35` (35 normal windows exceeded the 0.50 threshold due to natural variance).
- **False Negatives (FN)**: `0` (Zero attack windows evaded anomaly detection).
- **Total Test Samples**: `200`.

---

## 10. Precision, Recall, and F1-Score

Derived from the confusion matrix at the production operating threshold ($T = 0.50$):

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{100}{100 + 35} = \mathbf{0.7407} \ (74.07\%)$$

$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{100}{100 + 0} = \mathbf{1.0000} \ (100.00\%)$$

$$F_1\text{-Score} = \frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2 \times 0.7407 \times 1.0000}{0.7407 + 1.0000} = \mathbf{0.8511}$$

$$\text{Test Set Accuracy} = \frac{\text{TP} + \text{TN}}{\text{Total}} = \frac{100 + 65}{200} = \mathbf{0.8250} \ (82.50\%)$$

---

## 11. False-Positive and False-Negative Rate Analysis

- **False Positive Rate (FPR / Fall-out)**:
  $$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{35}{35 + 65} = \mathbf{0.3500} \ (35.00\%)$$
- **False Negative Rate (FNR / Miss Rate)**:
  $$\text{FNR} = \frac{\text{FN}}{\text{TP} + \text{FN}} = \frac{0}{100 + 0} = \mathbf{0.0000} \ (0.00\%)$$

### Anomaly Score Distribution Analysis

| Sample Cohort | Sample Count | Mean Score | Std Dev | Min Score | Max Score |
|---|:---:|:---:|:---:|:---:|:---:|
| **Normal Traffic Windows** | 100 | `0.4773` | `0.0467` | `0.3868` | `0.5909` |
| **Anomalous Traffic Windows** | 100 | `0.6899` | `0.0140` | `0.6491` | `0.7177` |
| **Separation Margin** | — | **`+0.2126`** | — | — | — |

The mean anomaly score for synthetic attacks ($0.6899$) is separated by $+0.2126$ from the normal traffic mean ($0.4773$).

---

## 12. Threshold Sensitivity Analysis

To investigate the detection trade-off without altering production code, an offline threshold sweep was evaluated across candidate cutoffs from $0.30$ to $0.70$:

| Threshold ($T$) | TP | TN | FP | FN | Precision | Recall | F1-Score | FPR | FNR | Operational Characterization |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **0.30** | 100 | 0 | 100 | 0 | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 0.0000 | Degenerate (all windows flagged as anomaly) |
| **0.35** | 100 | 0 | 100 | 0 | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 0.0000 | Degenerate (all windows flagged as anomaly) |
| **0.40** | 100 | 3 | 97 | 0 | 0.5076 | 1.0000 | 0.6734 | 0.9700 | 0.0000 | Excessive false alarms |
| **0.45** | 100 | 34 | 66 | 0 | 0.6024 | 1.0000 | 0.7519 | 0.6600 | 0.0000 | Elevated false alarms |
| **0.50** | **100** | **65** | **35** | **0** | **0.7407** | **1.0000** | **0.8511** | **0.3500** | **0.0000** | **Production Operating Point (100% attack recall)** |
| **0.55** | 100 | 94 | 6 | 0 | 0.9434 | 1.0000 | 0.9709 | 0.0600 | 0.0000 | High specificity cutoff |
| **0.60** | 100 | 100 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | Zero false alarm boundary for this test set |
| **0.65** | 98 | 100 | 0 | 2 | 1.0000 | 0.9800 | 0.9899 | 0.0000 | 0.0200 | Initial false negatives appear (stealth scans missed) |
| **0.70** | 14 | 100 | 0 | 86 | 1.0000 | 0.1400 | 0.2456 | 0.0000 | 0.8600 | Severe under-detection (only extreme floods detected) |

---

## 13. Architectural Interpretation

The empirical results directly validate NetSentinel's defensive design decisions:

1. **Why the ML-Alone Safety Invariant is Essential**:
   At the production threshold ($T = 0.50$), the Isolation Forest model achieves **100% recall** on attacks but exhibits a **35% false positive rate** on normal traffic variations. If the ML system were granted autonomous blocking authority, these benign fluctuations would result in denial-of-service for legitimate users.
   
   NetSentinel solves this through the **Composite Risk Engine formula**:
   $$\text{combined\_score} = 0.65 \times \text{rule\_score} + 0.35 \times \text{ml\_anomaly\_score}$$
   When an ML anomaly occurs without corroborating signature evidence, the score is capped at:
   $$0.35 \times 1.00 = \mathbf{0.3500} \ (\text{MEDIUM risk, recommended action: "log"})$$
   Because automated firewall blocking requires a risk score $\ge 0.80$, an ML anomaly alone **can never trigger an automated IP block**.

2. **Subsystem Throughput Profile**:
   - The **packet parser** operates at up to **93,963.79 packets/sec** (mean latency 0.0104 ms at 5,000 load, and 79,263.42 pkts/s at 1,000 load), demonstrating that frame decoding does not form a processing bottleneck in Python.
   - The **rule detector** processes up to **228,565.16 packets/sec** for benign traffic (100 load), settling to **24,625.05–41,715.98 packets/sec** when actively tracking stateful port scan probe state and SYN flood queues.
   - **Isolation Forest inference** requires $\approx 14.5\text{--}19.8 \text{ ms}$ per window evaluation (mean 14.49 ms at 500 load, 14.67 ms at 200 load). Because inference occurs periodically per sliding time window (every 1.0–5.0 seconds) rather than per packet, this computational cost is completely decoupled from line-rate packet capture.

---

## 14. Limitations

1. **Synthetic Nature of Evaluated Traffic**:
   All benchmarked network streams were generated synthetically using software packet structures. Physical NIC interrupt handling, kernel packet ring drops, and cable propagation delays were not present in this test environment.
2. **Coarse Timing Resolution on Micro-Benchmarks**:
   In sub-microsecond parser evaluations, timing jitter from Python interpreter overhead and virtual machine CPU scheduling can introduce variance in maximum latency measurements.
3. **Synthetic Ground-Truth Boundaries**:
   The ML evaluation dataset models distinct attack archetypes (SYN flood, port scan, UDP flood, stealth flags, IP sweeps). Real-world Advanced Persistent Threat (APT) traffic or sophisticated low-and-slow exfiltration may exhibit subtler feature differences not captured in synthetic models.
4. **Single-Node SQLite Persistence**:
   SQLite persistence throughput ($\approx 1,500\text{--}2,000 \text{ ops/sec}$) is optimized for edge/host deployments; distributed multi-gigabit enterprise deployments would require off-node time-series database clustering.

---

## 15. Reproducibility Instructions

The entire Phase 15 evaluation suite can be reproduced deterministically with a single CLI command:

### 1. Execute Full Benchmark and ML Evaluation
```bash
cd /home/debian/Desktop/NetSentinel
source .venv/bin/activate
.venv/bin/python backend/evaluation/runner.py
```

### 2. Execute Rapid Validation Run
```bash
.venv/bin/python backend/evaluation/runner.py --quick
```

### 3. Run Automated Evaluation Test Suite
```bash
.venv/bin/pytest tests/test_phase15_*.py -v
```

### 4. Generated Artifact Files
Execution generates the following files in `reports/`:
- `reports/evaluation_report.json`: Machine-readable results with complete benchmark percentiles, resource snapshots, and ML metrics.
- `reports/benchmark_summary.csv`: Tabular benchmark summary with load levels, throughput, and latency percentiles.
- `reports/ml_evaluation_samples.csv`: Per-sample prediction log recording ground truth, anomaly scores, and classification correctness.

---

## 16. Final Conclusion

Phase 15 confirms that NetSentinel's defensive architecture exhibits robust, measurable performance characteristics. The packet parsing and rule detection subsystems provide high-throughput observation, while the unsupervised Isolation Forest engine provides sensitive anomaly detection ($100\%$ recall on evaluated attack patterns) without compromising defensive stability. The composite risk formula safely bounds unsupervised anomaly scores, mathematically eliminating false-positive automated blocks while maintaining comprehensive threat visibility.
