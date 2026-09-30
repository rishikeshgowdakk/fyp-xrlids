# Phase 1 Experiment Report: `EXP-P1-CSE2018-R10-001`

- **Status**: `EMPIRICALLY_OBSERVED`
- **Dataset**: `cse_cic_ids2018` (Version: `as-published-2018`)
- **SHA-256**: `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf`
- **Feature Contract**: `R10` (10 features, Hash: `d74897f18b669ea806488222fda4514b28b335921ce019ebd41fc49ff6b65e21`)
- **Random Seed**: `42`
- **Git Commit**: `fff0040519903ae5ee197faea61835a6b9adce3b`
- **Execution Duration**: `84.07s`

---
## 1. Population and Split Counts

- **Total Rows**: 328,110
- **Train Rows**: 130,017
- **Validation Rows**: 43,339
- **Test Rows**: 43,340

---
## 2. Test Set Evaluation Metrics (Operating Point: 0.5)

> [!NOTE]
> Threshold 0.5 is a neutral reporting baseline. Decision **D-003** (threshold objective) remains OPEN.

| Model | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RF** | 43340 | 0.6479 | 0.3206 | 0.4742 | 0.3826 | 0.6998 | 0.3002 | 0.6443 | 0.4140 |
| **LSTM** | 43336 | 0.7938 | 0.7390 | 0.1602 | 0.2633 | 0.9831 | 0.0169 | 0.7284 | 0.4860 |
| **FUSION** | 43336 | 0.7978 | 0.7640 | 0.1750 | 0.2848 | 0.9838 | 0.0162 | 0.7452 | 0.5151 |

---
## 3. Model Disagreement and Fusion Analysis

- **Aligned Evaluation Population**: 43,336 rows
- **RF vs LSTM Disagreements**: 14,287 (32.97%)
- **RF Predicted Attack, LSTM Predicted Benign**: 13436 (RF Correct: 3627, RF False Alarm: 9809)
- **LSTM Predicted Attack, RF Predicted Benign**: 851 (LSTM Correct: 496, LSTM False Alarm: 355)
- **Fusion Rescues When One Model Failed**: 10478
- **Fusion Rescues When Both Models Failed**: 0
- **Fusion Degradations (Both Right, Fusion Wrong)**: 0

---
## 4. SHAP Feature Attribution (Random Forest)

> [!IMPORTANT]
> SHAP quantifies additive associative contributions relative to the background expectation.
> It does **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| --- | --- | --- |
| 1 | `packet_length_std` | 0.030879 |
| 2 | `rst_count` | 0.029423 |
| 3 | `flow_duration_ms` | 0.027289 |
| 4 | `flow_packets_per_s` | 0.021770 |
| 5 | `flow_bytes_per_s` | 0.021082 |
| 6 | `packet_length_mean` | 0.020351 |
| 7 | `ack_count` | 0.004935 |
| 8 | `syn_ack_ratio` | 0.001238 |
| 9 | `syn_count` | 0.000958 |
| 10 | `fin_count` | 0.000000 |

---
## 6. Open Decisions and Scientific Limitations

- **Decision D-002 (Feature Contract)**: Features evaluated on R10/transfer contracts; formal freeze requires researcher confirmation.
- **Decision D-003 (Threshold Objective)**: Evaluated at neutral 0.5 point; optimal threshold selection remains open.
- **Duplicate Policy**: Duplicate feature vectors handled explicitly according to configuration.
