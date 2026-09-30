# Phase 1 Experiment Report: `EXP-P1-CSE2018-R10-001`

- **Status**: `PRELIMINARY_SUBSAMPLE`
- **Dataset**: `cse_cic_ids2018` (Version: `as-published-2018`)
- **SHA-256**: `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf`
- **Feature Contract**: `R10` (10 features, Hash: `d74897f18b669ea806488222fda4514b28b335921ce019ebd41fc49ff6b65e21`)
- **Random Seed**: `42`
- **Git Commit**: `2372e36791561dcb84f943dedc65a0c5b1be1e78`
- **Execution Duration**: `10.73s`

---
## 1. Population and Split Counts

- **Total Rows**: 2,972
- **Train Rows**: 1,532
- **Validation Rows**: 511
- **Test Rows**: 511

---
## 2. Test Set Evaluation Metrics (Operating Point: 0.5)

> [!NOTE]
> Threshold 0.5 is a neutral reporting baseline. Decision **D-003** (threshold objective) remains OPEN.

| Model | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RF** | 511 | 0.7299 | 0.4706 | 0.3636 | 0.4103 | 0.8575 | 0.1425 | 0.6048 | 0.4645 |
| **LSTM** | 507 | 0.7396 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5071 | 0.3648 |
| **FUSION** | 507 | 0.7633 | 1.0000 | 0.0909 | 0.1667 | 1.0000 | 0.0000 | 0.5762 | 0.4682 |

---
## 3. Model Disagreement and Fusion Analysis

- **Aligned Evaluation Population**: 507 rows
- **RF vs LSTM Disagreements**: 102 (20.12%)
- **RF Predicted Attack, LSTM Predicted Benign**: 102 (RF Correct: 48, RF False Alarm: 54)
- **LSTM Predicted Attack, RF Predicted Benign**: 0 (LSTM Correct: 0, LSTM False Alarm: 0)
- **Fusion Rescues When One Model Failed**: 66
- **Fusion Rescues When Both Models Failed**: 0
- **Fusion Degradations (Both Right, Fusion Wrong)**: 0

---
## 4. SHAP Feature Attribution (Random Forest)

> [!IMPORTANT]
> SHAP quantifies additive associative contributions relative to the background expectation.
> It does **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| --- | --- | --- |
| 1 | `flow_duration_ms` | 0.044560 |
| 2 | `flow_bytes_per_s` | 0.044340 |
| 3 | `flow_packets_per_s` | 0.043378 |
| 4 | `packet_length_mean` | 0.038025 |
| 5 | `packet_length_std` | 0.025729 |
| 6 | `rst_count` | 0.017008 |
| 7 | `ack_count` | 0.010991 |
| 8 | `syn_ack_ratio` | 0.001433 |
| 9 | `syn_count` | 0.001332 |
| 10 | `fin_count` | 0.000168 |

---
## 6. Open Decisions and Scientific Limitations

- **Decision D-002 (Feature Contract)**: Features evaluated on R10/transfer contracts; formal freeze requires researcher confirmation.
- **Decision D-003 (Threshold Objective)**: Evaluated at neutral 0.5 point; optimal threshold selection remains open.
- **Duplicate Policy**: Duplicate feature vectors handled explicitly according to configuration.
