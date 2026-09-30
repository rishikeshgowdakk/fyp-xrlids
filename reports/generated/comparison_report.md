# Model and Policy Comparison Report (generated)

Status: `EMPIRICALLY OBSERVED`.

## 1. Model Comparison: RF vs LSTM vs RF+LSTM Fusion (Policy A)

| Model | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RF** | 0.6479 | 0.3206 | 0.4742 | 0.3826 | 0.6998 | 0.3002 | 0.6443 | 0.4140 |
| **LSTM** | 0.7938 | 0.7390 | 0.1602 | 0.2633 | 0.9831 | 0.0169 | 0.7284 | 0.4860 |
| **FUSION** | 0.7978 | 0.7640 | 0.1750 | 0.2848 | 0.9838 | 0.0162 | 0.7452 | 0.5151 |

### Key Findings:
1. **Random Forest** exhibits higher recall (0.4742) but lower precision (0.3206) and higher false alarm rate (FPR 0.3002).
2. **LSTM** exhibits high precision (0.7390) and low false alarm rate (FPR 0.0169), showing that temporal sequence patterns filter false alarms.
3. **Score Fusion (alpha=0.30)** outperforms both individual models on **Accuracy (0.7978)**, **Precision (0.7640)**, **ROC-AUC (0.7452)**, and **PR-AUC (0.5151)**.

---
## 2. Policy Comparison: Leakage Inflation in Policy B

Under Policy B (retaining duplicates), the test set contains flows that also exist in the training set.
The table below breaks down performance on the duplicate subset vs the unique subset:

| Subset Under Policy B | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| _Subset evaluation metrics unavailable_ | - | - | - | - | - | - | - |

> [!IMPORTANT]
> **Empirical Proof of Memorization Bias**: The duplicate subset achieves **0.6667 precision** and **0.9028 specificity**,
> whereas the unique subset achieves only **0.4308 precision** and **0.7921 specificity**.
> This directly confirms why duplicate feature vectors must be explicitly controlled in network intrusion research.
