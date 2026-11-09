# NetSentinel Kaggle Evaluation Guide: CTU-IDSEVAL-6 Isolation Forest Evaluation

This standalone package allows you to evaluate NetSentinel's **single final production Isolation Forest model using the canonical 13 network traffic features** on the real-world **CTU-IDSEVAL-6** benchmark dataset inside Kaggle.

---

## 1. Evaluation Architecture

The evaluation runs NetSentinel's single unsupervised Isolation Forest model on **5-second traffic windows** extracted from the official CTU-IDSEVAL-6 capture partitions using the canonical 13 features:

| Parameter | Specification |
| :--- | :--- |
| **Algorithm** | Unsupervised Isolation Forest (Scikit-Learn) |
| **Estimators (`n_estimators`)** | `100` (configurable via `--n-estimators`) |
| **Subsampling (`max_samples`)** | `"auto"` (`256`) (configurable via `--max-samples`) |
| **Contamination** | `"auto"` (configurable via `--contamination`) |
| **Features** | Canonical 13 Features in strict order |
| **Decision Threshold** | `0.50` (configurable via `--threshold`) |
| **Window Duration** | `5.0` seconds |

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
*(Expected output: `[SUCCESS] Kaggle evaluation package smoke test passed completely.`)*

---

### Step 4: Run the CTU-IDSEVAL-6 Evaluation
In the third cell, execute the evaluation script pointing to your Kaggle dataset path:

```bash
!python kaggle_evaluation/evaluate_ctu_idseval6.py \
    --dataset-root /kaggle/input/ctu-idseval-6 \
    --output-dir /kaggle/working/kaggle_output \
    --threshold 0.50
```

#### Optional: Quick Subset Run
If you want to perform a fast preliminary sanity check before processing the full dataset:
```bash
!python kaggle_evaluation/evaluate_ctu_idseval6.py \
    --dataset-root /kaggle/input/ctu-idseval-6 \
    --output-dir /kaggle/working/kaggle_output \
    --max-windows 500 \
    --threshold 0.50
```

---

## 3. Generated Evaluation Artifacts

Upon completion, the script displays summary metrics in the console and exports two structured artifacts to the output directory:

1. **`kaggle_isolation_forest_evaluation.json`**:
   - Machine-readable summary of aggregate and per-capture metrics.
   - Training time (seconds) and per-window prediction latency (ms).
   - PR-AUC (Average Precision) and ROC-AUC.
   - Score separation margin (`Malicious Mean Score - Benign Mean Score`).
   - Per-attack-category detection rates and mean anomaly scores.

2. **`kaggle_isolation_forest_evaluation.csv`**:
   - Tabular evaluation table containing:
     - Accuracy
     - Precision
     - Recall
     - F1-Score
     - False Positive Rate (FPR)
     - False Negative Rate (FNR)
     - PR-AUC and ROC-AUC
     - Score Separation Margin
     - Full Confusion Matrix (`TP`, `TN`, `FP`, `FN`) for each capture and overall aggregate.
     - Inference Latency per window (ms).

---

## 4. Expected Output Format

```text
================================================================================
FINAL EVALUATION RESULTS (CTU-IDSEVAL-6)
================================================================================
Model Architecture         : Single Isolation Forest (Unsupervised)
Feature Count              : 13 Canonical Features
Training Time              : [Measured train time] seconds
Prediction Latency         : [Measured inference time] ms / window
Threshold                  : 0.50
--------------------------------------------------------------------------------
Accuracy                   : [Your Kaggle Result]%
Precision                  : [Your Kaggle Result]%
Recall                     : [Your Kaggle Result]%
F1-Score                   : [Your Kaggle Result]%
False Positive Rate (FPR)  : [Your Kaggle Result]%
False Negative Rate (FNR)  : [Your Kaggle Result]%
PR-AUC (Average Precision) : [Your Kaggle Result]
ROC-AUC                    : [Your Kaggle Result]
Score Separation Margin    : [Your Kaggle Result] (Malicious - Benign)
Confusion Matrix           : TP=[...] | TN=[...] | FP=[...] | FN=[...]
================================================================================
```

---

## 5. Security Invariants
- `NETSENTINEL_FIREWALL_ENABLED=false`
- `NETSENTINEL_AUTO_BLOCK=false`
- Exactly ONE Unsupervised Isolation Forest model using the 13 canonical network traffic features.
- No supervised Random Forest models, no schema versions, no multi-model switching.
- No external network packets dispatched.
