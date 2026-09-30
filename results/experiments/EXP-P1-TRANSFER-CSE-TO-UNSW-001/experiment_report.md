# Phase 1 Experiment Report: `EXP-P1-TRANSFER-CSE-TO-UNSW-001`

- **Status**: `PRELIMINARY_SUBSAMPLE`
- **Dataset**: `cse_cic_ids2018` (Version: `as-published-2018`)
- **SHA-256**: `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf`
- **Feature Contract**: `transfer_common_4` (4 features, Hash: `7b2e3edf447d34b7d00c8f2a877c51599af42fd42e5ff63e6811c6b22eda12a4`)
- **Random Seed**: `42`
- **Git Commit**: `daf02be5376b58d7f0b87fe1c4584c1f61937e1b`
- **Execution Duration**: `10.23s`

---
## 1. Population and Split Counts

- **Total Rows**: 2,972
- **Train Rows**: 1,518
- **Validation Rows**: 506
- **Test Rows**: 507

---
## 2. Test Set Evaluation Metrics (Operating Point: 0.5)

> [!NOTE]
> Threshold 0.5 is a neutral reporting baseline. Decision **D-003** (threshold objective) remains OPEN.

| Model | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RF** | 507 | 0.6884 | 0.3673 | 0.2727 | 0.3130 | 0.8347 | 0.1653 | 0.5828 | 0.4181 |
| **LSTM** | 503 | 0.7376 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.6296 | 0.4781 |
| **FUSION** | 503 | 0.6859 | 0.3673 | 0.2727 | 0.3130 | 0.8329 | 0.1671 | 0.5818 | 0.4191 |

---
## 3. Model Disagreement and Fusion Analysis

- **Aligned Evaluation Population**: 503 rows
- **RF vs LSTM Disagreements**: 98 (19.48%)
- **RF Predicted Attack, LSTM Predicted Benign**: 98 (RF Correct: 36, RF False Alarm: 62)
- **LSTM Predicted Attack, RF Predicted Benign**: 0 (LSTM Correct: 0, LSTM False Alarm: 0)
- **Fusion Rescues When One Model Failed**: 36
- **Fusion Rescues When Both Models Failed**: 0
- **Fusion Degradations (Both Right, Fusion Wrong)**: 0

---
## 4. SHAP Feature Attribution (Random Forest)

> [!IMPORTANT]
> SHAP quantifies additive associative contributions relative to the background expectation.
> It does **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| --- | --- | --- |
| 1 | `flow_packets_per_s` | 0.061253 |
| 2 | `flow_bytes_per_s` | 0.060504 |
| 3 | `flow_duration_ms` | 0.054033 |
| 4 | `packet_length_mean` | 0.048903 |

---
## 5. Cross-Dataset Transfer Analysis

- **Target Dataset**: `unsw_nb15`
- **Common Transfer Features (4)**: `flow_duration_ms, flow_packets_per_s, flow_bytes_per_s, packet_length_mean`
- **Excluded Features Lacked by Target**: `packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio`
- **Scientific Note**: For cross-dataset/transfer evaluation, models must ONLY be trained and tested on common_transfer_features. Excluded features must NEVER be fabricated or proxied.
- **Target Availability**: `DATA_NOT_AVAILABLE`

---
## 6. Open Decisions and Scientific Limitations

- **Decision D-002 (Feature Contract)**: Features evaluated on R10/transfer contracts; formal freeze requires researcher confirmation.
- **Decision D-003 (Threshold Objective)**: Evaluated at neutral 0.5 point; optimal threshold selection remains open.
- **Duplicate Policy**: Duplicate feature vectors handled explicitly according to configuration.
