# EXPERIMENT CARD: `EXP-P1-TRANSFER-UNSW-TO-CSE-R4-001`

> [!IMPORTANT]
> This experiment card documents cross-dataset transfer evaluation under strict scientific isolation.
> Preprocessing and source models were fitted exclusively on source training data.
> Target domain data was evaluated strictly out-of-domain with zero target parameter tuning.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-TRANSFER-UNSW-TO-CSE-R4-001`
- **Research Question**: `RQ5_CROSS_DATASET_TRANSFER`
- **Source Dataset**: `unsw_nb15`
- **Target Dataset**: `cse_cic_ids2018`
- **Feature Contract**: `transfer_common_4` (4 features)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `07138caac5398765d66d60987d8170f05d34e766`
- **Random Seed**: `42`
- **Frozen Source Fusion Alpha**: `0.60`
- **Peak RSS**: `6115.89 MiB` (CPU Count: `12`)
- **Wall-Clock Duration**: `57.45s`

---
## 2. Feature Contract & Strict Isolation Protocol

Active features evaluated (4):
1. `flow_duration_ms`
2. `flow_packets_per_s`
3. `flow_bytes_per_s`
4. `packet_length_mean`

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
| **MAJORITY** | `transfer_common_4` | 0.0000 | 0.0000 | **+0.0000** | 0.0000 | 0.0000 | +0.0000 | 0.5000 | 0.1126 |
| **LOGISTIC_REGRESSION** | `transfer_common_4` | 0.3614 | 0.1300 | **-0.2315** | 0.0985 | 0.5285 | +0.4301 | 0.4651 | 0.0981 |
| **DECISION_TREE** | `transfer_common_4` | 0.8144 | 0.1062 | **-0.7082** | 0.3321 | 0.6863 | +0.3542 | 0.2655 | 0.0826 |
| **RF** | `transfer_common_4` | 0.8548 | 0.0217 | **-0.8331** | 0.1928 | 0.6473 | +0.4544 | 0.1793 | 0.0664 |
| **LSTM** | `transfer_common_4` | 0.8637 | 0.0380 | **-0.8258** | 0.1796 | 0.5074 | +0.3278 | 0.2251 | 0.0679 |
| **FUSION** | `transfer_common_4` | 0.8970 | 0.0268 | **-0.8702** | 0.1590 | 0.5513 | +0.3924 | 0.1423 | 0.0630 |

---
## 4. Covariate & Label Distribution Shift Analysis

- **Source Train Class Balance**: Benign = 40,427 (55.0%), Attack = 33,085 (45.0%)
- **Target Test Class Balance**: Benign = 1,475,298 (88.7%), Attack = 187,161 (11.3%)
- **Class Prevalence Shift**: -0.3375

| Feature | Source Mean ± Std | Target Mean ± Std | Median Shift | KS Statistic ($D$) | Wasserstein Distance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `flow_duration_ms` | 1416.62 ± 4872.76 | 20313.33 ± 37496.99 | +1564.68 | 0.4148 | 18952.44 |
| `flow_packets_per_s` | 11357.16 ± 81446.86 | 318.94 ± 11440.03 | -36.61 | 0.5706 | 11006.43 |
| `flow_bytes_per_s` | 5300566.45 ± 42407072.09 | 33650.35 ± 2400898.23 | -7499.88 | 0.4831 | 5202016.80 |
| `packet_length_mean` | 255.18 ± 264.35 | 119.12 ± 123.10 | -19.22 | 0.2679 | 134.80 |

---
## 5. Model Disagreements & Error Analysis on Target Domain

- **Aligned Evaluation Size**: 1,662,419 rows
- **RF vs LSTM Disagreements**: 713,290 (42.91%)
- **RF Positive, LSTM Negative**: 457,040 (RF Correct: 0, RF False Alarm: 0)
- **LSTM Positive, RF Negative**: 256,250 (LSTM Correct: 0, LSTM False Alarm: 0)

---
## 6. Target Domain Per-Attack-Family Detection Breakdown

| Attack Family | Class | Target Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 1,475,258 | 520,378 | 954,880 | 0 | 35.27% | 64.73% |
| `DDOS ATTACKS-LOIC-HTTP` | ATTACK | 106,973 | 65 | 0 | 106,908 | 0.06% | 99.94% |
| `DDOS ATTACK-HOIC` | ATTACK | 22,483 | 0 | 0 | 22,483 | 0.00% | 100.00% |
| `DOS ATTACKS-HULK` | ATTACK | 19,374 | 2,206 | 0 | 17,168 | 11.39% | 88.61% |
| `SSH-BRUTEFORCE` | ATTACK | 18,043 | 5 | 0 | 18,038 | 0.03% | 99.97% |
| `DOS ATTACKS-GOLDENEYE` | ATTACK | 8,109 | 4,173 | 0 | 3,936 | 51.46% | 48.54% |
| `INFILTERATION` | ATTACK | 7,027 | 4,370 | 0 | 2,657 | 62.19% | 37.81% |
| `BOT` | ATTACK | 2,999 | 686 | 0 | 2,313 | 22.87% | 77.13% |
| `DOS ATTACKS-SLOWLORIS` | ATTACK | 1,709 | 948 | 0 | 761 | 55.47% | 44.53% |
| `DDOS ATTACK-LOIC-UDP` | ATTACK | 358 | 0 | 0 | 358 | 0.00% | 100.00% |
| `BRUTE FORCE -WEB` | ATTACK | 49 | 48 | 0 | 1 | 97.96% | 2.04% |
| `BRUTE FORCE -XSS` | ATTACK | 22 | 22 | 0 | 0 | 100.00% | 0.00% |
| `SQL INJECTION` | ATTACK | 15 | 13 | 0 | 2 | 86.67% | 13.33% |

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