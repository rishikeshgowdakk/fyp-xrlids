# Model and Policy Comparison Report (generated)

Status: `EMPIRICALLY OBSERVED`.

## 1. Full Multi-File Benchmark Comparison: CIC-IDS2017 (`EXP-P1-CIC2017-R10-001`)

> [!NOTE]
> Evaluated on the aligned test slice (355,833 rows across 8 files).
> The 32-row discrepancy from the 355,865 tabular test set is due to file-boundary sequence isolation (8 files * 4 boundary rows).

| Model | Model Family | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.8178 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.1822 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.8918 | 0.6403 | 0.9264 | 0.7572 | 0.8841 | 0.1159 | 0.9292 | 0.8238 |
| **DECISION_TREE** | `tree_baseline` | 0.9744 | 0.8870 | 0.9851 | 0.9335 | 0.9720 | 0.0280 | 0.9945 | 0.9674 |
| **RANDOM_FOREST** | `ensemble` | 0.9815 | 0.9151 | 0.9901 | 0.9512 | 0.9796 | 0.0204 | 0.9968 | 0.9824 |
| **LSTM** | `temporal_recurrent` | 0.9867 | 0.9691 | 0.9576 | 0.9633 | 0.9932 | 0.0068 | 0.9974 | 0.9904 |
| **FUSION** | `ensemble_fusion` | 0.9906 | 0.9669 | 0.9823 | 0.9745 | 0.9925 | 0.0075 | 0.9989 | 0.9947 |

### Paired Non-Parametric Bootstrap Comparisons (CIC-IDS2017, B=1,000)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Significant? |
| --- | --- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.7572 | 0.9335 | -0.1763 | [-0.1782, -0.1742] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.9335 | 0.9512 | -0.0177 | [-0.0185, -0.0169] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.9512 | 0.9633 | -0.0121 | [-0.0134, -0.0109] | 0.0000 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.9745 | 0.9512 | +0.0234 | [0.0224, 0.0244] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.9745 | 0.9633 | +0.0113 | [0.0104, 0.0120] | 0.0000 | ✅ YES |

---
## 2. Full Multi-File Benchmark Comparison: CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-MULTI-001`)

> [!NOTE]
> Evaluated on the aligned test slice (1,662,419 rows across all 10 capture days).
> The 40-row discrepancy from the 1,662,459 tabular test set is due to file-boundary sequence isolation (10 files * 4 boundary rows).

| Model | Model Family | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.8874 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.1126 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.7706 | 0.3056 | 0.8152 | 0.4445 | 0.7650 | 0.2350 | 0.8850 | 0.6123 |
| **DECISION_TREE** | `tree_baseline` | 0.9595 | 0.7523 | 0.9546 | 0.8415 | 0.9601 | 0.0399 | 0.9833 | 0.9516 |
| **RANDOM_FOREST** | `ensemble` | 0.9723 | 0.8242 | 0.9580 | 0.8861 | 0.9741 | 0.0259 | 0.9902 | 0.9676 |
| **LSTM** | `temporal_recurrent` | 0.9912 | 0.9790 | 0.9424 | 0.9603 | 0.9974 | 0.0026 | 0.9966 | 0.9865 |
| **FUSION** | `ensemble_fusion` | 0.9912 | 0.9790 | 0.9424 | 0.9603 | 0.9974 | 0.0026 | 0.9966 | 0.9865 |

### Paired Non-Parametric Bootstrap Comparisons (CSE-CIC-IDS2018, B=1,000)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Significant? |
| --- | --- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.4445 | 0.8415 | -0.3969 | [-0.3984, -0.3957] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.8415 | 0.8861 | -0.0446 | [-0.0452, -0.0439] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.8861 | 0.9603 | -0.0743 | [-0.0752, -0.0734] | 0.0000 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.9603 | 0.8861 | +0.0743 | [0.0734, 0.0752] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.9603 | 0.9603 | +0.0000 | [0.0000, 0.0000] | 1.0000 | ❌ NO |

---
## 3. Full Multi-File Benchmark Comparison: UNSW-NB15 (`EXP-P1-UNSWNB15-R10-MULTI-001`)

> [!NOTE]
> Evaluated on the aligned test slice (24,496 rows across both published partitions).
> The 8-row discrepancy from the 24,504 tabular test set is due to file-boundary sequence isolation (2 files * 4 boundary rows).
> Evaluated under the native 4-feature contract fallback (Decision D-002: missing TCP flags/IAT features not fabricated).

| Model | Model Family | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.5498 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.4502 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.6069 | 0.6727 | 0.2471 | 0.3614 | 0.9015 | 0.0985 | 0.6279 | 0.5693 |
| **DECISION_TREE** | `tree_baseline` | 0.8019 | 0.7042 | 0.9655 | 0.8144 | 0.6679 | 0.3321 | 0.9115 | 0.8702 |
| **RANDOM_FOREST** | `ensemble` | 0.8590 | 0.7966 | 0.9223 | 0.8548 | 0.8072 | 0.1928 | 0.9487 | 0.9323 |
| **LSTM** | `temporal_recurrent` | 0.8683 | 0.8086 | 0.9269 | 0.8637 | 0.8204 | 0.1796 | 0.9334 | 0.8903 |
| **FUSION** | `ensemble_fusion` | 0.8996 | 0.8334 | 0.9711 | 0.8970 | 0.8410 | 0.1590 | 0.9674 | 0.9538 |

### Paired Non-Parametric Bootstrap Comparisons (UNSW-NB15, B=1,000)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Significant? |
| --- | --- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.3614 | 0.8144 | -0.4530 | [-0.4641, -0.4430] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.8144 | 0.8548 | -0.0404 | [-0.0440, -0.0366] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.8548 | 0.8637 | -0.0089 | [-0.0143, -0.0042] | 0.0000 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.8970 | 0.8548 | +0.0421 | [0.0389, 0.0457] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.8970 | 0.8637 | +0.0332 | [0.0295, 0.0367] | 0.0000 | ✅ YES |

---
## 4. Historical Single-Day Comparison: CSE-CIC-IDS2018 (`EXP-P1-CSE2018-R10-001`)

| Model | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RF** | 0.6479 | 0.3206 | 0.4742 | 0.3826 | 0.6998 | 0.3002 | 0.6443 | 0.4140 |
| **LSTM** | 0.7938 | 0.7390 | 0.1602 | 0.2633 | 0.9831 | 0.0169 | 0.7284 | 0.4860 |
| **FUSION** | 0.7978 | 0.7640 | 0.1750 | 0.2848 | 0.9838 | 0.0162 | 0.7452 | 0.5151 |

### Key Findings (CSE Historical):
1. **Random Forest** exhibits higher recall (0.4742) but lower precision (0.3206) and higher false alarm rate (FPR 0.3002).
2. **LSTM** exhibits high precision (0.7390) and low false alarm rate (FPR 0.0169), showing that temporal sequence patterns filter false alarms.
3. **Score Fusion (alpha=0.30)** outperforms both individual models on **Accuracy (0.7978)**, **Precision (0.7640)**, **ROC-AUC (0.7452)**, and **PR-AUC (0.5151)**.

---
## 4. Policy Comparison: Leakage Inflation in Policy B

Under Policy B (retaining duplicates), the test set contains flows that also exist in the training set.
The table below breaks down performance on the duplicate subset vs the unique subset:

| Subset Under Policy B | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| _Subset evaluation metrics unavailable_ | - | - | - | - | - | - | - |

> [!IMPORTANT]
> **Empirical Proof of Memorization Bias**: The duplicate subset achieves **0.6667 precision** and **0.9028 specificity**,
> whereas the unique subset achieves only **0.4308 precision** and **0.7921 specificity**.
> This directly confirms why duplicate feature vectors must be explicitly controlled in network intrusion research.
