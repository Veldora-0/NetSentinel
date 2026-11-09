# NetSentinel Isolation Forest Optimization Summary

- **Execution Timestamp**: 2026-11-09T11:58:38Z
- **Seed**: 42
- **Feature Schema**: Canonical 13 Features

## 1. Optimal Hyperparameters

- `n_estimators`: 250
- `max_samples`: `512`
- `contamination`: `0.05`
- `max_features`: 0.85
- `accuracy`: **92.67%**
- `precision`: **93.24%**
- `recall`: **92.00%**
- `f1_score`: **92.62%**
- `false_positive_rate`: **6.67%**

## 2. Decision Threshold Calibration

- **Best F1 Threshold**: `T = 0.48` (F1: 0.9313, FPR: 0.1400)
- **Low-FPR Threshold**: `T = 0.54` (Recall: 0.6667, FPR: 0.0133)

## 3. Baseline Window Sample Size Recommendations

| Baseline Samples | Accuracy | Precision | Recall | F1 Score | FPR |
|------------------|----------|-----------|--------|----------|-----|
| 20 | 0.7233 | 0.7965 | 0.6000 | 0.6844 | 0.1533 |
| 50 | 0.7300 | 0.8000 | 0.6133 | 0.6943 | 0.1533 |
| 100 | 0.7800 | 0.8281 | 0.7067 | 0.7626 | 0.1467 |
| 250 | 0.8767 | 0.8599 | 0.9000 | 0.8795 | 0.1467 |
| 500 | 0.8800 | 0.8851 | 0.8733 | 0.8792 | 0.1133 |
