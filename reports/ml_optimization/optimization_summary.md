# NetSentinel Isolation Forest Optimization Summary

- **Execution Timestamp**: 2026-11-09T11:26:53Z
- **Seed**: 42

## 1. Optimal Hyperparameters

- `n_estimators`: 250
- `max_samples`: `512`
- `contamination`: `0.05`
- `max_features`: 0.85
- `accuracy`: **90.67%**
- `precision`: **93.57%**
- `recall`: **87.33%**
- `f1_score`: **90.34%**
- `false_positive_rate`: **6.00%**

## 2. Decision Threshold Calibration

- **Best F1 Threshold**: `T = 0.49` (F1: 0.9136, FPR: 0.0900)
- **Low-FPR Threshold**: `T = 0.52` (Recall: 0.6867, FPR: 0.0200)

## 3. Baseline Window Sample Size Recommendations

| Baseline Samples | Accuracy | Precision | Recall | F1 Score | FPR |
|------------------|----------|-----------|--------|----------|-----|
| 20 | 0.7267 | 0.8063 | 0.5967 | 0.6858 | 0.1433 |
| 50 | 0.7417 | 0.8372 | 0.6000 | 0.6990 | 0.1167 |
| 100 | 0.7700 | 0.8522 | 0.6533 | 0.7396 | 0.1133 |
| 250 | 0.8083 | 0.8776 | 0.7167 | 0.7890 | 0.1000 |
| 500 | 0.8133 | 0.9052 | 0.7000 | 0.7895 | 0.0733 |
