# NetSentinel Phase 2: Real-World Dataset Evaluation & Feasibility Audit Report

**Timestamp:** `2026-11-07T13:40:00Z`  
**Status:** `AWAITING_DATASET_MOUNT` (Authentic Dataset Verified Absent Locally)  
**Safety Protocol:** Strict Scientific Integrity Enforced (Zero Data Fabrication / Zero Synthetic Substitution)

---

## 1. Executive Summary

In Phase 1, an offline supervised pipeline (`backend/ml/train_supervised.py`) and a baseline `RandomForestClassifier` were developed, tested, and validated using multi-capture synthetic fixtures.

Phase 2 mandates evaluating this experimental Random Forest classifier against **authentic real-world network traffic** from the benchmark **CTU-IDSEVAL-6** dataset, specifically examining whether it improves upon the existing unsupervised Isolation Forest's difficult case in `malware-1` (where Isolation Forest achieved $83.33\%$ accuracy, $70.58\%$ precision, and $22.72\%$ false positive rate).

Following strict project safety rules:
> **"If authentic datasets are unavailable, stop before claiming real-world results and provide precise instructions for obtaining and mounting them. Scientific validity takes priority over achieving a target metric."**

A complete filesystem audit was conducted across `/home/debian/`, `/tmp/`, `/var/`, `/mnt/`, and `/media/`. **The multi-gigabyte raw binary `.pcap` and `.conn-labeled.log` files of CTU-IDSEVAL-6 are not present on the local disk.** (The local Debian disk has 29 GB available on `/dev/sda1`, and the historical 264,205-window CTU evaluation recorded in `reports/phase15_5_real_dataset_evaluation.json` was conducted on an external Kaggle runtime).

Consequently, in accordance with scientific ethics:
1. **No synthetic fixtures were substituted as real-world results.**
2. **No metrics or numbers were fabricated.**
3. **The exact capture partitions, ground-truth methodologies, comparative baseline metrics, and mounting instructions have been documented and implemented in `backend/ml/train_supervised.py`.**

---

## 2. Real-World Dataset Availability & Missing Files

### Filesystem Audit Results:
- Searched: `/home/debian`, `/mnt`, `/media`, `/tmp`, `/var`
- Result: **0 authentic CTU-IDSEVAL-6 PCAP or Zeek files found**.
- The existing evaluation code in `backend/evaluation/real_dataset.py` is fully functional and ready to ingest authentic captures via pure-Python streaming readers (`PcapReader`, `ZeekLogParser`, `TrafficWindowBuilder`).

### Required Capture Inventory:
To execute Phase 2 training and evaluation on authentic data, the following directory structure must be mounted:

```
<dataset-root>/
├── pcap/
│   ├── ctu-idseval-6-benign-user-traffic-1.pcap (or .pcap.gz)
│   ├── ctu-idseval-6-malicious-portscan-1.pcap (or .pcap.gz)
│   ├── ctu-idseval-6-malicious-portscan-2.pcap (or .pcap.gz)
│   ├── ctu-idseval-6-malicious-portscan-3.pcap (or .pcap.gz)
│   ├── ctu-idseval-6-malicious-malware-1.pcap (or .pcap.gz)
│   └── ctu-idseval-6-malicious-malware-2.pcap (or .pcap.gz)
└── zeek/
    ├── ctu-idseval-6-benign-user-traffic-1.conn-labeled.log
    ├── ctu-idseval-6-malicious-portscan-1.conn-labeled.log
    ├── ctu-idseval-6-malicious-portscan-2.conn-labeled.log
    ├── ctu-idseval-6-malicious-portscan-3.conn-labeled.log
    ├── ctu-idseval-6-malicious-malware-1.conn-labeled.log
    └── ctu-idseval-6-malicious-malware-2.conn-labeled.log
```

---

## 3. Strict Real-World Capture Partition Design

To prevent all forms of data leakage across captures, the following disjoint partition design is pre-configured in `backend/ml/train_supervised.py`:

| Partition Role | Capture Identifiers | Traffic Description & Target Attack Archetypes |
|---|---|---|
| **Training Partition** | `ctu-idseval-6-benign-user-traffic-1`<br>`ctu-idseval-6-malicious-portscan-1`<br>`ctu-idseval-6-malicious-portscan-2` | 2,250 clean benign windows + 2 malicious portscan captures. Provides normal background baseline and reconnaissance attack signatures. |
| **Validation Partition** | `ctu-idseval-6-malicious-portscan-3`<br>(Subset of Benign Windows) | Held-out horizontal port scan capture. Used strictly for hyperparameter tuning and probability threshold calibration. |
| **Independent Test Partition** | `ctu-idseval-6-malicious-malware-1`<br>`ctu-idseval-6-malicious-malware-2` | 59,297 authentic enterprise windows (HTTP, DNS, IRC botnet, C2 exfiltration). Never exposed during training or threshold tuning. |

### Data Leakage Invariants:
1. **Capture-Level Disjointness:** No capture ID in training may appear in validation or testing.
2. **Zero Temporal Overlap:** Windows are sliced into discrete non-overlapping 5.0-second boundaries.
3. **No Feature Transformer Leakage:** Feature scalers are fit strictly within training folds.
4. **Independent Thresholding:** Decision thresholds are tuned on validation data only.

---

## 4. Ground-Truth Labelling Methodology & Mixed Window Handling

In `backend/evaluation/window_builder.py` and `backend/ml/train_supervised.py`:
1. **Rule A (Malicious):** If at least one overlapping Zeek flow is annotated `Malicious` $\implies$ `MALICIOUS` ($y=1$).
2. **Rule B (Benign):** If no malicious flows overlap and at least one flow is `Benign` $\implies$ `BENIGN` ($y=0$).
3. **Rule C (Background Only):** If all overlapping flows are `Background` $\implies$ `BACKGROUND_ONLY` (Excluded from binary classification metrics).
4. **Rule D (Unlabeled):** If no flow overlaps the 5-second interval $\implies$ `UNLABELED` (Excluded from binary classification metrics).
5. **Mixed Window Guardrail:** In authentic traffic, attack packets often share a 5-second slice with ambient benign browsing (e.g. 34,328 mixed windows occurred in CTU-IDSEVAL-6).
   - In unsupervised evaluation, mixed windows are flagged `is_mixed=True`.
   - **For Supervised Training:** Mixed windows must **not** be used as clean benign training examples. In `train_supervised.py`, training requires pure benign windows to prevent label pollution.

---

## 5. Comparative Reference Metrics: Isolation Forest vs. Target

From the canonical verified run in `reports/phase15_5_real_dataset_evaluation.json` ($N=59,320$ eligible windows):

| Metric | Historical Isolation Forest Baseline | Phase 2 Random Forest Target |
|---|:---:|:---:|
| **Overall Accuracy** | **90.48%** | **$\ge 97.00\%$** |
| **Overall Precision** | **90.02%** | **$\ge 95.00\%$** |
| **Overall Recall** | **94.92%** | **$\ge 97.00\%$** |
| **Overall F1-Score** | **0.9241** | **$\ge 0.9600$** |
| **Overall False Positive Rate (FPR)** | **16.47%** | **$\le 2.00\%$** |
| **Overall False Negative Rate (FNR)** | **5.08%** | **$\le 3.00\%$** |

### Malware-1 Critical Case (The Primary Improvement Target):
In CTU-IDSEVAL-6 `malware-1` ($26,094$ eligible windows):
- **Isolation Forest Accuracy:** **83.33%**
- **Isolation Forest Precision:** **70.58%**
- **Isolation Forest Recall:** **93.73%**
- **Isolation Forest FPR:** **22.72%** (3,749 benign windows falsely alerted as attacks)
- **Isolation Forest FNR:** **6.27%** (602 attack windows missed)

*Why Random Forest is Expected to Improve Malware-1:*
Isolation Forest penalizes natural variance in benign traffic bursts (causing high FPR). A supervised Random Forest learns non-linear split boundaries between legitimate multi-port web traffic and true malicious C2 beaconing/scanning.

---

## 6. Precise Instructions for Mounting the Real-World Dataset

To execute the real-world evaluation immediately upon obtaining the dataset:

### Step 1: Download or Mount the Files
Mount the directory containing `pcap/` and `zeek/` to `/home/debian/Desktop/NetSentinel/data/ctu-idseval-6/` or `/mnt/ctu-idseval-6/`:
```bash
sudo mkdir -p /mnt/ctu-idseval-6
# Mount external drive, NFS share, or VirtualBox shared folder:
sudo mount -t vboxsf ctu_dataset /mnt/ctu-idseval-6
```

### Step 2: Execute Supervised Training & Real-World Evaluation
Run the pipeline pointing to the mounted dataset:
```bash
PYTHONPATH=backend .venv/bin/python -c "
from ml.train_supervised import load_partitions_from_ctu_dataset, run_pipeline_experiment

train_p, val_p, test_p = load_partitions_from_ctu_dataset(
    dataset_root='/mnt/ctu-idseval-6',
    training_capture_names=['ctu-idseval-6-benign-user-traffic-1', 'ctu-idseval-6-malicious-portscan-1', 'ctu-idseval-6-malicious-portscan-2'],
    validation_capture_names=['ctu-idseval-6-malicious-portscan-3'],
    test_capture_names=['ctu-idseval-6-malicious-malware-1', 'ctu-idseval-6-malicious-malware-2'],
    window_duration=5.0
)

run_pipeline_experiment(
    train_partition=train_p,
    val_partition=val_p,
    test_partition=test_p,
    output_dir='reports/ml'
)
"
```

---

## 7. Safety & Regression Verification

- **Production Isolation:** `data/models/isolation_forest.joblib` remains untouched.
- **Firewall Defaults:** `NETSENTINEL_FIREWALL_ENABLED=false` and `NETSENTINEL_AUTO_BLOCK=false` verified intact.
- **Regression Suite:** 395/395 tests passing (`.venv/bin/pytest -q`).
- **Validation Harness:** 13/13 scenarios passing (`backend/validation_harness.py`).
