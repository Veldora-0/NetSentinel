# NetSentinel Kaggle Evaluation Guide: CTU-IDSEVAL-6 Isolation Forest Comparison

This standalone package allows you to evaluate and compare NetSentinel's **Original Production Isolation Forest** against the **Optimized Isolation Forest** on the real-world **CTU-IDSEVAL-6** benchmark dataset inside Kaggle.

---

## 1. Evaluation Architecture & Configurations Compared

The evaluation runs both models side-by-side on the **exact same 5-second traffic windows** extracted from the official CTU-IDSEVAL-6 capture partitions:

| Parameter | Original Baseline Model | Optimized Model |
| :--- | :--- | :--- |
| **Algorithm** | Unsupervised Isolation Forest | Unsupervised Isolation Forest |
| **Estimators (`n_estimators`)** | `100` | `150` |
| **Subsampling (`max_samples`)** | `"auto"` (`256`) | `512` (captures multi-modal baseline) |
| **Contamination** | `"auto"` | `0.05` |
| **Feature Dimension** | 13 Canonical Features | 13 Canonical Features (or 17 v2) |
| **Decision Threshold** | `0.50` (raw 0.0 offset) | `0.52` (calibrated decision boundary) |
| **Outlier Baseline Filter** | Disabled | Enabled (3.0x IQR outlier defense) |

### Strict Data Leakage Safeguards
- **Training Baseline**: Fitted strictly on clean `BENIGN` windows from `benign-user-traffic-1`.
- **Test Set**: Held-out malware captures (`malware-1`, `malware-2`) and portscan captures (`portscan-1`, `portscan-2`, `portscan-3`).
- **Exclusion Rules**: Windows containing background-only or unlabeled traffic are excluded from binary classification metrics to prevent ground-truth contamination.

---

## 2. Step-by-Step Kaggle Execution Instructions

### Step 1: Create a Kaggle Notebook and Attach CTU-IDSEVAL-6
1. Go to [Kaggle](https://www.kaggle.com/) and create a new Python Notebook.
2. Under the **Data** pane (right sidebar), click **Add Data** and select your CTU-IDSEVAL-6 dataset.
   - Typical path: `/kaggle/input/ctu-idseval-6`
   - Ensure the dataset contains the `pcap/` and `zeek/` directories (or `.pcap` and `.conn-labeled.log` files).

---

### Step 2: Clone NetSentinel & Install Dependencies
In the first notebook cell, clone the repository directly from GitHub:

```bash
!git clone https://github.com/Veldora-0/NetSentinel.git
%cd NetSentinel
!pip install -r kaggle_evaluation/requirements.txt
```

---

### Step 3: Run Fast Package Verification (Smoke Test)
In the second cell, run the self-contained smoke test to confirm that packet parsing, window aggregation, and model scoring work smoothly in the Kaggle environment:

```bash
!python kaggle_evaluation/smoke_test_kaggle_package.py
```
*(Should output: `[SUCCESS] Kaggle evaluation package smoke test passed completely.`)*

---

### Step 4: Run the Comparative CTU-IDSEVAL-6 Evaluation
In the third cell, execute the comparative evaluation script pointing to your Kaggle dataset path:

```bash
!python kaggle_evaluation/evaluate_ctu_idseval6.py \
    --dataset-root /kaggle/input/ctu-idseval-6 \
    --output-dir /kaggle/working/kaggle_output \
    --threshold 0.52
```

#### Optional: Quick Subset Run
If you want to perform a fast preliminary sanity check before processing the full 260,000+ windows:
```bash
!python kaggle_evaluation/evaluate_ctu_idseval6.py \
    --dataset-root /kaggle/input/ctu-idseval-6 \
    --output-dir /kaggle/working/kaggle_output \
    --max-windows 500 \
    --threshold 0.52
```

---

## 3. Generated Evaluation Artifacts

Upon completion, the script outputs a comparative terminal table and exports two permanent artifacts:

1. **`kaggle_isolation_forest_comparison.json`**:
   - Machine-readable summary of aggregate and per-capture metrics.
   - Contains score separation margins (`Malicious Mean Score - Benign Mean Score`).
   - Detailed window-level counts.

2. **`kaggle_isolation_forest_comparison.csv`**:
   - Tabular comparison table containing:
     - Accuracy
     - Precision
     - Recall
     - F1-Score
     - False Positive Rate (FPR)
     - False Negative Rate (FNR)
     - Full Confusion Matrix (`TP`, `TN`, `FP`, `FN`) for each capture and overall aggregate.

---

## 4. Expected Output Format

```text
================================================================================
FINAL COMPARATIVE EVALUATION RESULTS (CTU-IDSEVAL-6)
================================================================================
Metric                    | Original Baseline (T=0.50) | Optimized IF (T=0.52)     | Delta     
----------------------------------------------------------------------------------------
Accuracy                  | 90.48%                    | [Your Kaggle Result]      | ...       
Precision                 | 90.02%                    | [Your Kaggle Result]      | ...       
Recall                    | 94.92%                    | [Your Kaggle Result]      | ...       
F1-Score                  | 92.41%                    | [Your Kaggle Result]      | ...       
False Positive Rate       | 16.47%                    | [Your Kaggle Result]      | ...       
False Negative Rate       | 5.08%                     | [Your Kaggle Result]      | ...       
Score Separation          | 0.1523                    | [Your Kaggle Result]      | ...       
========================================================================================
```

---

## 5. Security Invariants
- `NETSENTINEL_FIREWALL_ENABLED=false`
- `NETSENTINEL_AUTO_BLOCK=false`
- Unsupervised Isolation Forest only (no supervised Random Forest models).
- No external network packets dispatched.
