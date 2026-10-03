# EXPERIMENT CARD: `EXP-P1-TRANSFER-UNSW-TO-CIC-R4-001`

> [!IMPORTANT]
> This experiment card documents cross-dataset transfer evaluation under strict scientific isolation.
> Preprocessing and source models were fitted exclusively on source training data.
> Target domain data was evaluated strictly out-of-domain with zero target parameter tuning.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-TRANSFER-UNSW-TO-CIC-R4-001`
- **Research Question**: `RQ5_CROSS_DATASET_TRANSFER`
- **Source Dataset**: `unsw_nb15`
- **Target Dataset**: `cicids2017`
- **Feature Contract**: `transfer_common_4` (4 features)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `07138caac5398765d66d60987d8170f05d34e766`
- **Random Seed**: `42`
- **Frozen Source Fusion Alpha**: `0.60`
- **Peak RSS**: `6115.89 MiB` (CPU Count: `12`)
- **Wall-Clock Duration**: `20.80s`

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

> Aligned target evaluation population: **355,833** rows.

| Model | Contract | Source Reference F1 | Target Transfer F1 | ΔF1 (Degradation) | Source FPR | Target FPR | ΔFPR | Target ROC-AUC | Target PR-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `transfer_common_4` | 0.0000 | 0.0000 | **+0.0000** | 0.0000 | 0.0000 | +0.0000 | 0.5000 | 0.1822 |
| **LOGISTIC_REGRESSION** | `transfer_common_4` | 0.3614 | 0.5161 | **+0.1547** | 0.0985 | 0.3476 | +0.2491 | 0.7833 | 0.3434 |
| **DECISION_TREE** | `transfer_common_4` | 0.8144 | 0.3292 | **-0.4852** | 0.3321 | 0.6656 | +0.3335 | 0.4716 | 0.2011 |
| **RF** | `transfer_common_4` | 0.8548 | 0.3276 | **-0.5273** | 0.1928 | 0.6858 | +0.4930 | 0.6057 | 0.2306 |
| **LSTM** | `transfer_common_4` | 0.8637 | 0.3389 | **-0.5248** | 0.1796 | 0.3178 | +0.1382 | 0.6690 | 0.2444 |
| **FUSION** | `transfer_common_4` | 0.8970 | 0.3664 | **-0.5306** | 0.1590 | 0.5394 | +0.3804 | 0.6804 | 0.3020 |

---
## 4. Covariate & Label Distribution Shift Analysis

- **Source Train Class Balance**: Benign = 40,427 (55.0%), Attack = 33,085 (45.0%)
- **Target Test Class Balance**: Benign = 291,045 (81.8%), Attack = 64,820 (18.2%)
- **Class Prevalence Shift**: -0.2679

| Feature | Source Mean ± Std | Target Mean ± Std | Median Shift | KS Statistic ($D$) | Wasserstein Distance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `flow_duration_ms` | 1416.62 ± 4872.76 | 23417.46 ± 39912.11 | -346.07 | 0.3402 | 21917.72 |
| `flow_packets_per_s` | 11357.16 ± 81446.86 | 2282.99 ± 31708.14 | -21.52 | 0.4052 | 9536.79 |
| `flow_bytes_per_s` | 5300566.45 ± 42407072.09 | 182680.89 ± 4731226.59 | -6459.02 | 0.3750 | 5100993.26 |
| `packet_length_mean` | 255.18 ± 264.35 | 259.40 ± 353.64 | -40.60 | 0.2194 | 79.69 |

---
## 5. Model Disagreements & Error Analysis on Target Domain

- **Aligned Evaluation Size**: 355,833 rows
- **RF vs LSTM Disagreements**: 189,066 (53.13%)
- **RF Positive, LSTM Negative**: 157,928 (RF Correct: 0, RF False Alarm: 0)
- **LSTM Positive, RF Negative**: 31,138 (LSTM Correct: 0, LSTM False Alarm: 0)

---
## 6. Target Domain Per-Attack-Family Detection Breakdown

| Attack Family | Class | Target Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 291,013 | 91,440 | 199,573 | 0 | 31.42% | 68.58% |
| `DOS HULK` | ATTACK | 33,074 | 32,657 | 0 | 417 | 98.74% | 1.26% |
| `DDOS` | ATTACK | 25,347 | 16,134 | 0 | 9,213 | 63.65% | 36.35% |
| `DOS GOLDENEYE` | ATTACK | 2,037 | 1,457 | 0 | 580 | 71.53% | 28.47% |
| `DOS SLOWHTTPTEST` | ATTACK | 1,020 | 268 | 0 | 752 | 26.27% | 73.73% |
| `DOS SLOWLORIS` | ATTACK | 901 | 384 | 0 | 517 | 42.62% | 57.38% |
| `FTP-PATATOR` | ATTACK | 897 | 2 | 0 | 895 | 0.22% | 99.78% |
| `SSH-PATATOR` | ATTACK | 648 | 641 | 0 | 7 | 98.92% | 1.08% |
| `PORTSCAN` | ATTACK | 320 | 171 | 0 | 149 | 53.44% | 46.56% |
| `WEB ATTACK - BRUTE FORCE` | ATTACK | 258 | 38 | 0 | 220 | 14.73% | 85.27% |
| `BOT` | ATTACK | 196 | 18 | 0 | 178 | 9.18% | 90.82% |
| `WEB ATTACK - XSS` | ATTACK | 108 | 3 | 0 | 105 | 2.78% | 97.22% |
| `INFILTRATION` | ATTACK | 8 | 6 | 0 | 2 | 75.00% | 25.00% |
| `HEARTBLEED` | ATTACK | 3 | 3 | 0 | 0 | 100.00% | 0.00% |
| `WEB ATTACK - SQL INJECTION` | ATTACK | 3 | 2 | 0 | 1 | 66.67% | 33.33% |

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