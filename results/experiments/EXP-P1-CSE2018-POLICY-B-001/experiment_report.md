# Phase 1 Experiment Report: `EXP-P1-CSE2018-POLICY-B-001`

- **Status**: `PRELIMINARY_SUBSAMPLE`
- **Dataset**: `cse_cic_ids2018` (Version: `as-published-2018`)
- **SHA-256**: `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf`
- **Feature Contract**: `R10` (10 features, Hash: `d74897f18b669ea806488222fda4514b28b335921ce019ebd41fc49ff6b65e21`)
- **Random Seed**: `42`
- **Git Commit**: `63f44770aae32237d08c82e36724b316f159c6f0`
- **Execution Duration**: `10.66s`

---
## 1. Population and Split Counts

- **Total Rows**: 2,972
- **Train Rows**: 1,783
- **Validation Rows**: 594
- **Test Rows**: 595

---
## 2. Test Set Evaluation Metrics (Operating Point: 0.5)

> [!NOTE]
> Threshold 0.5 is a neutral reporting baseline. Decision **D-003** (threshold objective) remains OPEN.

| Model | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RF** | 595 | 0.7008 | 0.4636 | 0.4192 | 0.4403 | 0.8107 | 0.1893 | 0.6338 | 0.5066 |
| **LSTM** | 591 | 0.7174 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.6208 | 0.3791 |
| **FUSION** | 591 | 0.7208 | 0.5250 | 0.1257 | 0.2029 | 0.9552 | 0.0448 | 0.6582 | 0.4927 |

---
## 3. Model Disagreement and Fusion Analysis

- **Aligned Evaluation Population**: 591 rows
- **RF vs LSTM Disagreements**: 151 (25.55%)
- **RF Predicted Attack, LSTM Predicted Benign**: 151 (RF Correct: 70, RF False Alarm: 81)
- **LSTM Predicted Attack, RF Predicted Benign**: 0 (LSTM Correct: 0, LSTM False Alarm: 0)
- **Fusion Rescues When One Model Failed**: 83
- **Fusion Rescues When Both Models Failed**: 0
- **Fusion Degradations (Both Right, Fusion Wrong)**: 0

---
## 4. SHAP Feature Attribution (Random Forest)

> [!IMPORTANT]
> SHAP quantifies additive associative contributions relative to the background expectation.
> It does **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| --- | --- | --- |
| 1 | `flow_packets_per_s` | 0.054743 |
| 2 | `flow_duration_ms` | 0.048475 |
| 3 | `flow_bytes_per_s` | 0.047728 |
| 4 | `packet_length_mean` | 0.039860 |
| 5 | `packet_length_std` | 0.024765 |
| 6 | `ack_count` | 0.009080 |
| 7 | `rst_count` | 0.007011 |
| 8 | `syn_ack_ratio` | 0.003712 |
| 9 | `syn_count` | 0.002551 |
| 10 | `fin_count` | 0.000225 |

---
## 6. Open Decisions and Scientific Limitations

- **Decision D-002 (Feature Contract)**: Features evaluated on R10/transfer contracts; formal freeze requires researcher confirmation.
- **Decision D-003 (Threshold Objective)**: Evaluated at neutral 0.5 point; optimal threshold selection remains open.
- **Duplicate Policy**: Duplicate feature vectors handled explicitly according to configuration.
