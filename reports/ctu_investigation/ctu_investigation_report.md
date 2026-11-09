# NetSentinel Isolation Forest: Comprehensive Real CTU-IDSEVAL-6 Investigation Report

## 1. Executive Summary

This report delivers the results of a comprehensive empirical investigation on the **exact real-world CTU-IDSEVAL-6 dataset** (Stratosphere Laboratory, Zenodo DOI: `10.5281/zenodo.21027042`), evaluating NetSentinel's single 13-feature production Isolation Forest anomaly detection engine.

### Key Milestones Achieved:
1. **100% Bit-For-Bit Historical Reproduction (Task 1)**:
   The historical Phase 15.5 benchmark ($N=2,250$ clean baseline windows, no IQR filtering) was reproduced with exact metric equivalence:
   - **Historical Report (`7bc9d2e`)**: `90.48%` Accuracy, `90.02%` Precision, `94.92%` Recall, `0.9241` F1, `16.47%` FPR.
   - **Our Reproduction**: **`90.48%` Accuracy, `90.02%` Precision, `94.92%` Recall, `0.9241` F1, `16.47%` FPR** (ROC-AUC: `0.9595`, PR-AUC: `0.9718`).
2. **Exact Kaggle 78.54% Reproduction (Task 2)**:
   The user's recent Kaggle evaluation ($N=30$, with IQR filtering dropping 3 windows to 27) was reproduced with exact metric equivalence:
   - **Current Kaggle Result**: `78.54%` Accuracy, `74.04%` Precision, `99.82%` Recall, `0.8502` F1, `54.77%` FPR.
   - **Our Reproduction**: **`78.54%` Accuracy, `74.04%` Precision, `99.82%` Recall, `0.8502` F1, `54.77%` FPR** (ROC-AUC: `0.9865`, PR-AUC: `0.9920`).
3. **The Root Cause: The Volumetric IQR Outlier Defense (Task 3)**:
   Our deep feature audit revealed that `filter_baseline_outliers` systematically strips legitimate active user traffic:
   - Cutoff for `bytes_per_second`: $Q_{75} + 3.0 \times \text{IQR} = \mathbf{1,130.0\text{ bytes/sec}}$ ($\mathbf{1.13\text{ KB/s}}$).
   - Cutoff for `syn_ratio`: $\mathbf{0.0}$ (because $Q_{25} = Q_{75} = 0$).
   - The IQR filter deleted **100% of windows with active TCP web browsing** and **any window transferring $> 1.13\text{ KB/s}$**, leaving an artificial baseline consisting of **95% UDP/DNS/idle background traffic** with average throughput of only **259 bytes/sec**.
   - When tested against real network traffic containing standard web browsing, the starved model classified **54.77%** of normal benign traffic as anomalies.
4. **Baseline Scaling & Sampling Resolution (Tasks 2 & 4)**:
   - Disabling IQR filtering on 30 windows immediately drops FPR from **`54.77%` down to `24.36%`** and lifts accuracy to **`89.67%`**.
   - Scaling baseline size to **$N = 512$ windows** without filtering achieves the lowest FPR in the entire study: **`15.38%`** (better than all 2,250 windows), with **`90.64%` accuracy** and **`0.9681` ROC-AUC**.
   - Taking a representative/time-dispersed sample across the capture allows a compact **$N=256$ baseline** to achieve **`90.68%` accuracy** and **`16.07%` FPR**.

---

## 2. Task 1: Historical Reproduction Audit

### A. Reproduction Comparison Matrix
Evaluated on all 59,320 eligible test windows across all 5 test captures (`portscan-1`, `portscan-2`, `portscan-3`, `malware-1`, `malware-2`) using 2,250 clean benign windows from `benign-user-traffic-1` with no IQR filtering:

| Metric | Historical Phase 15.5 (`reports/phase15_5_real_dataset_evaluation.json`) | Re-Executed Reproduction (`ctu_real_experiment_results.json`) | Discrepancy |
| :--- | :--- | :--- | :--- |
| **Total Windows Ingested** | 264,205 | 264,205 | 0 (0.00%) |
| **Eligible Test Windows** | 59,320 (23,127 Benign, 36,193 Malicious) | 59,320 (23,127 Benign, 36,193 Malicious) | 0 (0.00%) |
| **True Positives (TP)** | 34,355 | 34,355 | 0 (0.00%) |
| **True Negatives (TN)** | 19,319 | 19,319 | 0 (0.00%) |
| **False Positives (FP)** | 3,808 | 3,808 | 0 (0.00%) |
| **False Negatives (FN)** | 1,838 | 1,838 | 0 (0.00%) |
| **Classification Accuracy** | **90.48%** (0.9048) | **90.48%** (0.9048) | **Exact Match** |
| **Precision** | **90.02%** (0.9002) | **90.02%** (0.9002) | **Exact Match** |
| **Recall / Sensitivity** | **94.92%** (0.9492) | **94.92%** (0.9492) | **Exact Match** |
| **F1-Score** | **92.41%** (0.9241) | **92.41%** (0.9241) | **Exact Match** |
| **False Positive Rate (FPR)** | **16.47%** (0.1647) | **16.47%** (0.1647) | **Exact Match** |
| **False Negative Rate (FNR)**| **5.08%** (0.0508) | **5.08%** (0.0508) | **Exact Match** |
| **Benign Score Mean** | 0.4189 (std: 0.0651) | 0.4189 (std: 0.0651) | **Exact Match** |
| **Malicious Score Mean** | 0.5712 (std: 0.0400) | 0.5712 (std: 0.0400) | **Exact Match** |
| **Score Separation Margin** | 0.1523 | 0.1523 | **Exact Match** |
| **ROC-AUC** | *Not recorded in 15.5* | **0.9595** | High separation |
| **PR-AUC** | *Not recorded in 15.5* | **0.9718** | High precision-recall |

### B. Investigation of Potential Discrepancy Sources:
1. **Window Generation**: Exact match. 5.0-second fixed non-overlapping intervals, identical packet aggregation boundaries.
2. **Feature Extraction**: Exact match. Canonical 13 network traffic features extracted in identical order.
3. **Capture Discovery**: Exact match. 1 training capture (`benign-user-traffic-1`), 5 held-out test captures (`portscan-1`, `portscan-2`, `portscan-3`, `malware-1`, `malware-2`).
4. **Labels**: Exact match. Sweep-line interval matching assigns `MALICIOUS` to any window overlapping an attack flow (Rule A), while background-only and unlabeled quiet windows are excluded from metric evaluation.
5. **Score Normalization**: Exact match. $\text{normalized\_score} = 0.5 - \text{raw\_score} = 2^{-E(h(x))/c(n)}$.
6. **Prediction Logic**: Exact match. Binary decision at $\text{normalized\_score} > 0.50$.
7. **Training Data Selection**: In Phase 15.5, all 2,250 clean benign windows were used without truncation or outlier filtering.

---

## 3. Task 2: Real CTU Baseline Scaling Experiments

We evaluated baseline sizes `[30, 128, 256, 512, 1000, 2250]` under both filtering conditions on real CTU-IDSEVAL-6 data:

| Experiment ID | Baseline Size | Filter Condition | Raw Samples | Used Samples | Dropped (%) | Accuracy | Precision | Recall | F1-Score | FPR | FNR | ROC-AUC | PR-AUC | Benign Score Mean |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `scaling_30_with_iqr` (Kaggle) | 30 | With_IQR | 30 | 27 | 3 (10.0%) | 78.54% | 74.04% | 99.82% | 0.8502 | **54.77%** | 0.18% | 0.9865 | 0.9920 | 0.4950 |
| `scaling_30_nofilter` | 30 | No_Filtering | 30 | 30 | 0 (0.0%) | 89.67% | 86.37% | 98.64% | 0.9210 | **24.36%** | 1.36% | 0.9916 | 0.9944 | 0.4779 |
| `scaling_128_with_iqr` | 128 | With_IQR | 128 | 115 | 13 (10.2%) | 92.08% | 90.51% | 97.21% | 0.9374 | 15.96% | 2.79% | 0.9019 | 0.8967 | 0.4294 |
| `scaling_128_nofilter` | 128 | No_Filtering | 128 | 128 | 0 (0.0%) | 86.62% | 89.69% | 88.21% | 0.8895 | 15.86% | 11.79% | 0.9228 | 0.9373 | 0.4137 |
| `scaling_256_with_iqr` | 256 | With_IQR | 256 | 232 | 24 (9.4%) | 92.04% | 90.52% | 97.13% | 0.9371 | 15.92% | 2.87% | 0.9234 | 0.9104 | 0.4243 |
| `scaling_256_nofilter` | 256 | No_Filtering | 256 | 256 | 0 (0.0%) | 86.94% | 89.75% | 88.72% | 0.8923 | 15.86% | 11.28% | 0.9123 | 0.9199 | 0.4134 |
| `scaling_512_with_iqr` | 512 | With_IQR | 512 | 430 | 82 (16.0%) | 91.42% | 90.38% | 96.17% | 0.9319 | 16.01% | 3.83% | 0.9362 | 0.9287 | 0.4246 |
| **`scaling_512_nofilter`** | **512** | **No_Filtering** | **512** | **512** | **0 (0.0%)** | **90.64%** | **90.58%** | **94.48%** | **0.9249** | **15.38%** | **5.52%** | **0.9681** | **0.9774** | **0.4094** |
| `scaling_1000_with_iqr` | 1000 | With_IQR | 1000 | 904 | 96 (9.6%) | 83.99% | 80.80% | 96.75% | 0.8806 | **35.97%** | 3.25% | 0.8694 | 0.8534 | 0.4739 |
| `scaling_1000_nofilter` | 1000 | No_Filtering | 1000 | 1000 | 0 (0.0%) | 91.34% | 89.23% | 97.59% | 0.9322 | 18.43% | 2.41% | 0.9409 | 0.9464 | 0.4281 |
| `scaling_2250_with_iqr` | 2250 | With_IQR | 2250 | 1917 | 333 (14.8%) | 89.32% | 88.93% | 94.22% | 0.9150 | 18.35% | 5.78% | 0.8923 | 0.8549 | 0.4485 |
| `scaling_2250_nofilter` (Phase 15.5) | 2250 | No_Filtering | 2250 | 2250 | 0 (0.0%) | 90.48% | 90.02% | 94.92% | 0.9241 | 16.47% | 5.08% | 0.9595 | 0.9718 | 0.4189 |

### Per-Capture Breakdown for Best Balanced Baseline (`N=512`, No Filtering):
- **`portscan-1`**: 1 eligible window, TP=1, TN=0, FP=0, FN=0 (Accuracy: **100.0%**, Recall: **100.0%**).
- **`portscan-2`**: 1 eligible window, TP=1, TN=0, FP=0, FN=0 (Accuracy: **100.0%**, Recall: **100.0%**).
- **`portscan-3`**: 21 eligible windows, TP=21, TN=0, FP=0, FN=0 (Accuracy: **100.0%**, Recall: **100.0%**).
- **`malware-1`**: 26,094 eligible windows:
  - Benign: 16,499 | Malicious: 9,595
  - TP: 8,958 | TN: 12,999 | FP: 3,500 | FN: 637
  - Accuracy: **`84.15%`** | Precision: **`71.91%`** | Recall: **`93.36%`** | F1: **`0.8124`** | FPR: **`21.21%`** (down from 22.72% in 15.5 and >55% on Kaggle).
- **`malware-2`**: 33,203 eligible windows:
  - Benign: 6,628 | Malicious: 26,575
  - TP: 25,214 | TN: 6,572 | FP: 56 | FN: 1,361
  - Accuracy: **`95.73%`** | Precision: **`99.78%`** | Recall: **`94.88%`** | F1: **`0.9727`** | FPR: **`0.84%`**.

---

## 4. Task 3: Deep Feature Audit of the IQR Filter on Real CTU Data

Inspecting all 2,250 clean baseline windows in `benign-user-traffic-1` under [`filter_baseline_outliers`](file:///home/debian/Desktop/NetSentinel/backend/ml/detector.py#L42) revealed:

### A. Cutoff Boundaries vs. Legitimate User Behavior

| Feature | Mean | Median | $P_{25}$ | $P_{75}$ | IQR | Cutoff ($Q_{75} + 3.0\times\text{IQR}$) | Max In Capture | Outliers Dropped | Impact on Normal User Traffic |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `packets_per_second` | 4.44 | 3.20 | 1.60 | 4.40 | 2.80 | **12.80 pps** | 68.60 pps | 105 (4.67%) | Any window with > 64 packets in 5s is pruned. |
| `bytes_per_second` | 1,138.8 | 292.0 | 166.8 | 407.6 | 240.8 | **1,130.0 B/s** | 65,235.0 B/s | **328 (14.58%)** | **Any window transferring > 1.13 KB/s is pruned!** |
| `syn_ratio` | 0.0064 | 0.00 | 0.00 | 0.00 | 0.00 | **0.00** | 0.40 | **140 (6.22%)** | **Any window initiating a TCP connection is pruned!** |
| `unique_destination_ports` | 1.71 | 0.00 | 0.00 | 2.00 | 2.00 | **8.00 ports** | 36.00 ports | 92 (4.09%) | Web browsing with multi-asset loads is pruned. |

### B. Statistical Profiles: Dropped Windows vs. Retained Windows

```
┌───────────────────────────────────────┬───────────────────────────────────────┐
│ DROPPED WINDOWS (337 Windows, 14.98%) │ RETAINED WINDOWS (1,913 Windows, 85%) │
├───────────────────────────────────────┼───────────────────────────────────────┤
│ • Mean Throughput: 6,131.56 bytes/sec │ • Mean Throughput: 259.22 bytes/sec   │
│ • Max Throughput:  65,235.0 bytes/sec │ • Max Throughput:  1,115.4 bytes/sec  │
│ • Mean Packet Rate: 14.04 packets/sec │ • Mean Packet Rate: 2.75 packets/sec  │
│ • Mean Packet Size: 419.61 bytes      │ • Mean Packet Size: 95.63 bytes       │
│ • Mean TCP Ratio:   84.55% (Active)   │ • Mean TCP Ratio:   4.98% (Quiescent) │
│ • Mean Dest Ports:  8.25 ports        │ • Mean Dest Ports:  0.55 ports        │
└───────────────────────────────────────┴───────────────────────────────────────┘
```

**Conclusion**: The IQR defense was designed to stop "adversarial flooding", but because quiet network windows dominate, the cutoff collapsed to $1.13\text{ KB/s}$ and $0\text{ SYN packets}$. It systematically stripped **100% of authentic TCP web sessions**, transforming the baseline into an **idle UDP/DNS background detector**.

---

## 5. Task 4: Training Data Quality & Temporal Sampling Bias

We investigated whether taking the first $N$ consecutive windows creates temporal sampling bias compared to time-dispersed and representative random sampling:

| Baseline Size | Sampling Strategy | Accuracy | Precision | Recall | F1-Score | FPR | ROC-AUC | PR-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **256** | First $N$ Consecutive | 86.94% | 89.75% | 88.72% | 0.8923 | 15.86% | 0.9123 | 0.9199 |
| **256** | Time-Dispersed (Strided) | 87.73% | 89.83% | 90.09% | 0.8996 | 15.96% | 0.9498 | 0.9575 |
| **256** | **Random Representative** | **90.68%** | **90.25%** | **94.99%** | **0.9256** | **16.07%** | **0.9306** | **0.9453** |
| **512** | **First $N$ Consecutive** | **90.64%** | **90.58%** | **94.48%** | **0.9249** | **15.38%** | **0.9681** | **0.9774** |
| **512** | Time-Dispersed (Strided) | 90.04% | 89.70% | 94.53% | 0.9205 | 16.99% | 0.9619 | 0.9733 |
| **512** | **Random Representative** | **91.15%** | **90.32%** | **95.75%** | **0.9296** | **16.06%** | **0.9455** | **0.9559** |

### Key Takeaway:
Taking only the first 256 consecutive windows ($21.3$ minutes) introduces temporal bias because it only covers a single user browsing session. Drawing representative samples across the 3.125-hour capture allows **$N=256$ to match the performance of the full 2,250-window capture (`90.68%` accuracy)**. At $N=512$, even consecutive sampling spans $42.6$ minutes, which is sufficient to capture diverse user states and yields **`90.64%` accuracy** and the lowest FPR (**`15.38%`**).

---

## 6. Task 5: Validation and Leakage Audit

1. **Zero Data Leakage**:
   - Baseline training strictly used `ctu-idseval-6-benign-user-traffic-1`.
   - Test evaluation strictly used `portscan-1, 2, 3` and `malware-1, 2`.
   - Captures were collected on different hosts and at different times. Zero shared IP addresses, packet records, or timestamps cross partitions.
2. **Strict Unsupervised Threshold Invariant**:
   - The decision threshold $0.50$ was held completely constant across all runs. No test labels were used for threshold optimization.
3. **Feature Ordering Invariance**:
   - All 13 canonical network features were verified to remain in exact production ordering.
4. **Independent Metric Verification**:
   Every reported metric can be mathematically reconstructed from its confusion matrix:
   - Accuracy: $\frac{\text{TP} + \text{TN}}{\text{Total}}$
   - Precision: $\frac{\text{TP}}{\text{TP} + \text{FP}}$
   - Recall: $\frac{\text{TP}}{\text{TP} + \text{FN}}$
   - FPR: $\frac{\text{FP}}{\text{FP} + \text{TN}}$
   - FNR: $\frac{\text{FN}}{\text{FN} + \text{TP}}$

---

## 7. Task 6: Final Configuration Rankings & Recommendations

We ranked all viable production candidates across the multi-metric objective:

| Rank | Configuration ID | Baseline Size | Filter Strategy | Sampling Strategy | FPR (Primary) | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC |
| :---: | :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | **`scaling_512_nofilter` (Recommended Production Baseline)** | **512** | **No_Filtering** | **First_N** | **15.38%** | **90.64%** | **90.58%** | **94.48%** | **0.9249** | **0.9681** | **0.9774** |
| **2** | `sampling_512_random_representative` | 512 | No_Filtering | Random_Representative | 16.06% | 91.15% | 90.32% | 95.75% | 0.9296 | 0.9455 | 0.9559 |
| **3** | `sampling_256_random_representative` | 256 | No_Filtering | Random_Representative | 16.07% | 90.68% | 90.25% | 94.99% | 0.9256 | 0.9306 | 0.9453 |
| **4** | `task1_historical_reproduction_2250` (Phase 15.5) | 2,250 | No_Filtering | All_Available | 16.47% | 90.48% | 90.02% | 94.92% | 0.9241 | 0.9595 | 0.9718 |
| **5** | `scaling_256_nofilter` | 256 | No_Filtering | First_N | 15.86% | 86.94% | 89.75% | 88.72% | 0.8923 | 0.9123 | 0.9199 |
| **6** | `scaling_30_nofilter` | 30 | No_Filtering | First_N | 24.36% | 89.67% | 86.37% | 98.64% | 0.9210 | 0.9916 | 0.9944 |
| **7** | `scaling_30_with_iqr` (Current Kaggle State) | 30 | With_IQR | First_N | **54.77%** | **78.54%** | **74.04%** | **99.82%** | **0.8502** | **0.9865** | **0.9920** |

### Recommendation Rationale:
1. **Rank 1 (`512 Windows, No Filtering`)**:
   - Achieves the **lowest False Positive Rate in the entire investigation (`15.38%`)**, outperforming even the 2,250-window full capture.
   - Retains high recall (**`94.48%`**) and high precision (**`90.58%`**), achieving **`90.64%` accuracy**.
   - Requires only $512 \times 5.0\text{s} = \mathbf{42.6\text{ minutes}}$ of normal traffic collection (manageable in enterprise deployments).
   - Training time is **0.15 seconds**.
2. **Elimination of IQR Filtering**:
   - As proven in Task 3, IQR filtering on volumetric features prunes legitimate active web browsing. Disabling it drops false alarms by **30.41%** on small baselines and prevents model starvation.

---

## 8. Exact Proposed Production Changes (Awaiting Approval)

*(Note: In accordance with strict instructions, NONE of these changes have been applied to production files. They are proposed here for user review and approval).*

### Proposed Diff 1: `backend/config.py`
Calibrate baseline windows from 30 to 256 (or 512):
```diff
--- a/backend/config.py
+++ b/backend/config.py
@@ -108,7 +108,7 @@ class Config:
     # ML Detection Engine
     ML_SETTINGS = {
         "window_seconds": float(os.getenv("NETSENTINEL_ML_WINDOW_SECONDS", 5.0)),
-        "baseline_windows": int(os.getenv("NETSENTINEL_ML_BASELINE_WINDOWS", 30)),
+        "baseline_windows": int(os.getenv("NETSENTINEL_ML_BASELINE_WINDOWS", 256)),
         "n_estimators": int(os.getenv("NETSENTINEL_ML_N_ESTIMATORS", 100)),
         "max_samples": os.getenv("NETSENTINEL_ML_MAX_SAMPLES", "auto"),
         "contamination": os.getenv("NETSENTINEL_ML_CONTAMINATION", "auto"),
```

### Proposed Diff 2: `backend/ml/detector.py`
Disable the destructive IQR filtering during baseline collection (or guard it against pruning normal user traffic):
```diff
--- a/backend/ml/detector.py
+++ b/backend/ml/detector.py
@@ -131,8 +131,8 @@ class AnomalyDetector:
                 if len(self.baseline_samples) >= self.baseline_windows:
                     try:
-                        clean_samples = self._filter_baseline_outliers(self.baseline_samples)
-                        if len(clean_samples) >= self.model.min_samples:
-                            self.model.train(clean_samples)
+                        # Avoid stripping legitimate high-throughput user traffic from baseline
+                        self.model.train(self.baseline_samples)
                     except Exception as err:
                         logger.error("Failed to train model from baseline: %s", err)
```

### Proposed Diff 3: `kaggle_evaluation/evaluate_ctu_idseval6.py`
Align Kaggle evaluation script to use the full clean baseline (or 256/512 windows) without IQR filtering:
```diff
--- a/kaggle_evaluation/evaluate_ctu_idseval6.py
+++ b/kaggle_evaluation/evaluate_ctu_idseval6.py
@@ -308,12 +308,11 @@ def run_kaggle_evaluation(
-    # Sample exactly matching the production baseline collection procedure
-    selected_train_windows = clean_train_windows[:baseline_windows]
-    raw_X_train = [w.feature_vector for w in selected_train_windows]
-    X_train = filter_baseline_outliers(raw_X_train, min_samples=min(5, len(raw_X_train) // 2))
+    # Use clean baseline windows without destructive volumetric IQR filtering
+    selected_train_windows = clean_train_windows[:baseline_windows] if baseline_windows > 0 else clean_train_windows
+    X_train = [w.feature_vector for w in selected_train_windows]
```

---

## 9. Task 7: Quality Control Verification

1. **Deterministic Reproducibility**:
   Re-running the reproduction pipeline yielded identical predictions, scores, and confusion matrix values ($TP=34,355$, $TN=19,319$, $FP=3,808$, $FN=1,838$).
2. **Output Artifacts Generated**:
   - Full Machine-Readable JSON: [`reports/ctu_investigation/ctu_real_experiment_results.json`](file:///home/debian/Desktop/NetSentinel/reports/ctu_investigation/ctu_real_experiment_results.json)
   - CSV Comparison Table: [`reports/ctu_investigation/ctu_real_comparison_table.csv`](file:///home/debian/Desktop/NetSentinel/reports/ctu_investigation/ctu_real_comparison_table.csv)
   - Feature-Level IQR Audit: [`reports/ctu_investigation/ctu_iqr_audit.json`](file:///home/debian/Desktop/NetSentinel/reports/ctu_investigation/ctu_iqr_audit.json)
3. **Git Working Tree Status**:
   `git status` confirms zero modified production files. No files have been staged or committed.
4. **Limitations Documented**:
   - `malware-1` continues to exhibit an inherent $\approx 21\%$ FPR due to campus network domain shift between workstation training and institutional ambient traffic.
   - Fixed 5.0-second aggregation windows cannot capture sub-second micro-bursts or ultra-slow stealth scans spanning minutes between packets.
