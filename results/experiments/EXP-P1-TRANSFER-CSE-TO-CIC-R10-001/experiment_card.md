# EXPERIMENT CARD: `EXP-P1-TRANSFER-CSE-TO-CIC-R10-001`

> [!IMPORTANT]
> This experiment card documents cross-dataset transfer evaluation under strict scientific isolation.
> Preprocessing and source models were fitted exclusively on source training data.
> Target domain data was evaluated strictly out-of-domain with zero target parameter tuning.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-TRANSFER-CSE-TO-CIC-R10-001`
- **Research Question**: `RQ5_CROSS_DATASET_TRANSFER`
- **Source Dataset**: `cse_cic_ids2018`
- **Target Dataset**: `cicids2017`
- **Feature Contract**: `R10` (10 features)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `07138caac5398765d66d60987d8170f05d34e766`
- **Random Seed**: `42`
- **Frozen Source Fusion Alpha**: `0.50`
- **Peak RSS**: `6115.89 MiB` (CPU Count: `12`)
- **Wall-Clock Duration**: `17.80s`

---
## 2. Feature Contract & Strict Isolation Protocol

Active features evaluated (10):
1. `flow_duration_ms`
2. `flow_packets_per_s`
3. `flow_bytes_per_s`
4. `packet_length_mean`
5. `packet_length_std`
6. `syn_count`
7. `ack_count`
8. `rst_count`
9. `fin_count`
10. `syn_ack_ratio`

### Isolation Guarantees
1. **Zero Preprocessor Leakage**: Preprocessor parameters (means, scales, medians) were learned exclusively from the source training population. The target dataset never fitted the preprocessor.
2. **Frozen Model Weights**: Detectors (Majority, LR, DT, RF, LSTM) were trained exclusively on source data. No fine-tuning or adaptation was performed on target data.
3. **Decision Parameters & Isolation**: Fusion weight $\alpha$ was selected using source validation data. Decision threshold 0.50 was fixed as the neutral baseline (threshold optimization remains OPEN under D-003). Target data was never used to tune either parameter.
4. **Sequence Safety**: LSTM sequence windows ($T=5$, stride=1, label_rule='last') were strictly isolated by target source capture file, with no synthetic sequences crossing capture boundaries.

---
## 3. Transfer Degradation Matrix (Fair Aligned Target Population)

> Aligned target evaluation population: **355,833** rows.

| Model | Contract | Source Reference F1 | Target Transfer F1 | ΔF1 (Degradation) | Source FPR | Target FPR | ΔFPR | Target ROC-AUC | Target PR-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `R10` | 0.0000 | 0.0000 | **+0.0000** | 0.0000 | 0.0000 | +0.0000 | 0.5000 | 0.1822 |
| **LOGISTIC_REGRESSION** | `R10` | 0.4445 | 0.3349 | **-0.1096** | 0.2350 | 0.1811 | -0.0540 | 0.4646 | 0.3263 |
| **DECISION_TREE** | `R10` | 0.8415 | 0.2805 | **-0.5610** | 0.0399 | 0.0892 | +0.0493 | 0.3083 | 0.2345 |
| **RF** | `R10` | 0.8861 | 0.0301 | **-0.8560** | 0.0259 | 0.0248 | -0.0011 | 0.7127 | 0.3154 |
| **LSTM** | `R10` | 0.9603 | 0.2601 | **-0.7003** | 0.0026 | 0.0141 | +0.0115 | 0.8052 | 0.5333 |
| **FUSION** | `R10` | 0.9603 | 0.1191 | **-0.8412** | 0.0026 | 0.0107 | +0.0081 | 0.8099 | 0.4544 |

---
## 4. Covariate & Label Distribution Shift Analysis

- **Source Train Class Balance**: Benign = 4,425,894 (88.7%), Attack = 561,483 (11.3%)
- **Target Test Class Balance**: Benign = 291,045 (81.8%), Attack = 64,820 (18.2%)
- **Class Prevalence Shift**: +0.0696

| Feature | Source Mean ± Std | Target Mean ± Std | Median Shift | KS Statistic ($D$) | Wasserstein Distance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `flow_duration_ms` | 20353.62 ± 37534.64 | 23417.46 ± 39912.11 | -1912.46 | 0.1924 | 4909.08 |
| `flow_packets_per_s` | 317.92 ± 11776.85 | 2282.99 ± 31708.14 | +15.10 | 0.1898 | 1962.25 |
| `flow_bytes_per_s` | 32115.85 ± 2059683.63 | 182680.89 ± 4731226.59 | +1040.69 | 0.2035 | 139181.09 |
| `packet_length_mean` | 118.96 ± 123.33 | 259.40 ± 353.64 | -21.06 | 0.2147 | 148.33 |
| `packet_length_std` | 199.71 ± 179.14 | 461.33 ± 746.24 | -125.23 | 0.2246 | 316.84 |
| `syn_count` | 0.02 ± 0.15 | 0.04 ± 0.18 | +0.00 | 0.0149 | 0.01 |
| `ack_count` | 0.19 ± 0.39 | 0.22 ± 0.41 | +0.00 | 0.0255 | 0.03 |
| `rst_count` | 0.29 ± 0.45 | 0.00 ± 0.02 | +0.00 | 0.2900 | 0.29 |
| `fin_count` | 0.00 ± 0.04 | 0.04 ± 0.19 | +0.00 | 0.0379 | 0.04 |
| `syn_ack_ratio` | 0.02 ± 0.15 | 0.04 ± 0.18 | +0.00 | 0.0131 | 0.01 |

---
## 5. Model Disagreements & Error Analysis on Target Domain

- **Aligned Evaluation Size**: 355,833 rows
- **RF vs LSTM Disagreements**: 21,502 (6.04%)
- **RF Positive, LSTM Negative**: 7,712 (RF Correct: 0, RF False Alarm: 0)
- **LSTM Positive, RF Negative**: 13,790 (LSTM Correct: 0, LSTM False Alarm: 0)

---
## 6. Target Domain Per-Attack-Family Detection Breakdown

| Attack Family | Class | Target Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 291,013 | 283,791 | 7,222 | 0 | 97.52% | 2.48% |
| `DOS HULK` | ATTACK | 33,074 | 5 | 0 | 33,069 | 0.02% | 99.98% |
| `DDOS` | ATTACK | 25,347 | 0 | 0 | 25,347 | 0.00% | 100.00% |
| `DOS GOLDENEYE` | ATTACK | 2,037 | 484 | 0 | 1,553 | 23.76% | 76.24% |
| `DOS SLOWHTTPTEST` | ATTACK | 1,020 | 66 | 0 | 954 | 6.47% | 93.53% |
| `DOS SLOWLORIS` | ATTACK | 901 | 539 | 0 | 362 | 59.82% | 40.18% |
| `FTP-PATATOR` | ATTACK | 897 | 2 | 0 | 895 | 0.22% | 99.78% |
| `SSH-PATATOR` | ATTACK | 648 | 3 | 0 | 645 | 0.46% | 99.54% |
| `PORTSCAN` | ATTACK | 320 | 0 | 0 | 320 | 0.00% | 100.00% |
| `WEB ATTACK - BRUTE FORCE` | ATTACK | 258 | 0 | 0 | 258 | 0.00% | 100.00% |
| `BOT` | ATTACK | 196 | 1 | 0 | 195 | 0.51% | 99.49% |
| `WEB ATTACK - XSS` | ATTACK | 108 | 0 | 0 | 108 | 0.00% | 100.00% |
| `INFILTRATION` | ATTACK | 8 | 0 | 0 | 8 | 0.00% | 100.00% |
| `HEARTBLEED` | ATTACK | 3 | 0 | 0 | 3 | 0.00% | 100.00% |
| `WEB ATTACK - SQL INJECTION` | ATTACK | 3 | 0 | 0 | 3 | 0.00% | 100.00% |

---
## 7. Artifact Traceability

All cross-dataset transfer artifacts are recorded deterministically in the experiment directory:
- `experiment_record.json`: Complete experiment metadata and provenance sidecar
- `test_metrics.json`: Full metric dictionary across all detectors on target test set
- `transfer_comparison.json`: Detailed degradation accounting against source-domain baseline
- `distribution_shift.json`: Covariate moments, KS-test statistics, and Wasserstein distances
- `error_analysis.json`: Model disagreements, false alarms, and attack misses
- `per_family_metrics.csv`: Per-attack-family detection rates on target domain
- `resource_profile.json`: Peak RSS, duration, CPU count, and memory footprint