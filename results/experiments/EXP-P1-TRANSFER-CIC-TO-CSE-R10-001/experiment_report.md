# EXPERIMENT CARD: `EXP-P1-TRANSFER-CIC-TO-CSE-R10-001`

> [!IMPORTANT]
> This experiment card documents cross-dataset transfer evaluation under strict scientific isolation.
> Preprocessing and source models were fitted exclusively on source training data.
> Target domain data was evaluated strictly out-of-domain with zero target parameter tuning.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-TRANSFER-CIC-TO-CSE-R10-001`
- **Research Question**: `RQ5_CROSS_DATASET_TRANSFER`
- **Source Dataset**: `cicids2017`
- **Target Dataset**: `cse_cic_ids2018`
- **Feature Contract**: `R10` (10 features)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `07138caac5398765d66d60987d8170f05d34e766`
- **Random Seed**: `42`
- **Frozen Source Fusion Alpha**: `0.50`
- **Peak RSS**: `6115.89 MiB` (CPU Count: `12`)
- **Wall-Clock Duration**: `622.26s`

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

> Aligned target evaluation population: **1,662,419** rows.

| Model | Contract | Source Reference F1 | Target Transfer F1 | ΔF1 (Degradation) | Source FPR | Target FPR | ΔFPR | Target ROC-AUC | Target PR-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `R10` | 0.0000 | 0.0000 | **+0.0000** | 0.0000 | 0.0000 | +0.0000 | 0.5000 | 0.1126 |
| **LOGISTIC_REGRESSION** | `R10` | 0.7572 | 0.3270 | **-0.4302** | 0.1159 | 0.1370 | +0.0210 | 0.5704 | 0.1636 |
| **DECISION_TREE** | `R10` | 0.9335 | 0.3073 | **-0.6262** | 0.0280 | 0.0577 | +0.0298 | 0.7358 | 0.2551 |
| **RF** | `R10` | 0.9512 | 0.3286 | **-0.6225** | 0.0204 | 0.0486 | +0.0281 | 0.7008 | 0.2509 |
| **LSTM** | `R10` | 0.9633 | 0.0983 | **-0.8650** | 0.0068 | 0.0635 | +0.0567 | 0.4787 | 0.1226 |
| **FUSION** | `R10` | 0.9745 | 0.1139 | **-0.8606** | 0.0075 | 0.0159 | +0.0084 | 0.6604 | 0.2184 |

---
## 4. Covariate & Label Distribution Shift Analysis

- **Source Train Class Balance**: Benign = 873,134 (81.8%), Attack = 194,459 (18.2%)
- **Target Test Class Balance**: Benign = 1,475,298 (88.7%), Attack = 187,161 (11.3%)
- **Class Prevalence Shift**: -0.0696

| Feature | Source Mean ± Std | Target Mean ± Std | Median Shift | KS Statistic ($D$) | Wasserstein Distance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `flow_duration_ms` | 23410.77 ± 39921.45 | 20313.33 ± 37496.99 | +1911.46 | 0.1959 | 4668.23 |
| `flow_packets_per_s` | 2222.82 ± 28736.56 | 318.94 ± 11440.03 | -14.99 | 0.1848 | 1813.27 |
| `flow_bytes_per_s` | 186470.99 ± 4813151.35 | 33650.35 ± 2400898.23 | -1032.91 | 0.1988 | 174704.90 |
| `packet_length_mean` | 259.66 ± 354.54 | 119.12 ± 123.10 | +21.53 | 0.2118 | 149.26 |
| `packet_length_std` | 461.44 ± 747.04 | 200.05 ± 179.21 | +125.97 | 0.2246 | 320.64 |
| `syn_count` | 0.04 ± 0.18 | 0.02 ± 0.15 | +0.00 | 0.0144 | 0.01 |
| `ack_count` | 0.21 ± 0.41 | 0.19 ± 0.39 | +0.00 | 0.0248 | 0.02 |
| `rst_count` | 0.00 ± 0.02 | 0.29 ± 0.45 | +0.00 | 0.2914 | 0.29 |
| `fin_count` | 0.04 ± 0.19 | 0.00 ± 0.04 | +0.00 | 0.0386 | 0.04 |
| `syn_ack_ratio` | 0.04 ± 0.18 | 0.02 ± 0.15 | +0.00 | 0.0141 | 0.01 |

---
## 5. Model Disagreements & Error Analysis on Target Domain

- **Aligned Evaluation Size**: 1,662,419 rows
- **RF vs LSTM Disagreements**: 210,485 (12.66%)
- **RF Positive, LSTM Negative**: 112,368 (RF Correct: 0, RF False Alarm: 0)
- **LSTM Positive, RF Negative**: 98,117 (LSTM Correct: 0, LSTM False Alarm: 0)

---
## 6. Target Domain Per-Attack-Family Detection Breakdown

| Attack Family | Class | Target Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 1,475,258 | 1,403,624 | 71,634 | 0 | 95.14% | 4.86% |
| `DDOS ATTACKS-LOIC-HTTP` | ATTACK | 106,973 | 48,028 | 0 | 58,945 | 44.90% | 55.10% |
| `DDOS ATTACK-HOIC` | ATTACK | 22,483 | 0 | 0 | 22,483 | 0.00% | 100.00% |
| `DOS ATTACKS-HULK` | ATTACK | 19,374 | 0 | 0 | 19,374 | 0.00% | 100.00% |
| `SSH-BRUTEFORCE` | ATTACK | 18,043 | 0 | 0 | 18,043 | 0.00% | 100.00% |
| `DOS ATTACKS-GOLDENEYE` | ATTACK | 8,109 | 1,546 | 0 | 6,563 | 19.07% | 80.93% |
| `INFILTERATION` | ATTACK | 7,027 | 48 | 0 | 6,979 | 0.68% | 99.32% |
| `BOT` | ATTACK | 2,999 | 27 | 0 | 2,972 | 0.90% | 99.10% |
| `DOS ATTACKS-SLOWLORIS` | ATTACK | 1,709 | 1,233 | 0 | 476 | 72.15% | 27.85% |
| `DDOS ATTACK-LOIC-UDP` | ATTACK | 358 | 0 | 0 | 358 | 0.00% | 100.00% |
| `BRUTE FORCE -WEB` | ATTACK | 49 | 0 | 0 | 49 | 0.00% | 100.00% |
| `BRUTE FORCE -XSS` | ATTACK | 22 | 0 | 0 | 22 | 0.00% | 100.00% |
| `SQL INJECTION` | ATTACK | 15 | 0 | 0 | 15 | 0.00% | 100.00% |

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