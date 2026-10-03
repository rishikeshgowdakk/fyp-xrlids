# EXPERIMENT CARD: `EXP-P1-TRANSFER-CIC-TO-UNSW-R4-001`

> [!IMPORTANT]
> This experiment card documents cross-dataset transfer evaluation under strict scientific isolation.
> Preprocessing and source models were fitted exclusively on source training data.
> Target domain data was evaluated strictly out-of-domain with zero target parameter tuning.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-TRANSFER-CIC-TO-UNSW-R4-001`
- **Research Question**: `RQ5_CROSS_DATASET_TRANSFER`
- **Source Dataset**: `cicids2017`
- **Target Dataset**: `unsw_nb15`
- **Feature Contract**: `transfer_common_4` (4 features)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `07138caac5398765d66d60987d8170f05d34e766`
- **Random Seed**: `42`
- **Frozen Source Fusion Alpha**: `0.90`
- **Peak RSS**: `6115.89 MiB` (CPU Count: `12`)
- **Wall-Clock Duration**: `287.38s`

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
3. **Frozen Decision Parameters**: Fusion weight $\alpha$ and calibration mappings were tuned exclusively on source validation data; target test ground truth was never inspected during tuning.
4. **Sequence Safety**: LSTM sequence windows ($T=5$, stride=1, label_rule='last') were strictly isolated by target source capture file, with no synthetic sequences crossing capture boundaries.

---
## 3. Transfer Degradation Matrix (Fair Aligned Target Population)

> Aligned target evaluation population: **24,496** rows.

| Model | Contract | Source Reference F1 | Target Transfer F1 | ΔF1 (Degradation) | Source FPR | Target FPR | ΔFPR | Target ROC-AUC | Target PR-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `transfer_common_4` | 0.0000 | 0.0000 | **+0.0000** | 0.0000 | 0.0000 | +0.0000 | 0.5000 | 0.4502 |
| **LOGISTIC_REGRESSION** | `transfer_common_4` | 0.6872 | 0.2942 | **-0.3930** | 0.0939 | 0.0692 | -0.0247 | 0.4970 | 0.5023 |
| **DECISION_TREE** | `transfer_common_4` | 0.9284 | 0.0305 | **-0.8979** | 0.0290 | 0.0356 | +0.0066 | 0.4720 | 0.4363 |
| **RF** | `transfer_common_4` | 0.9525 | 0.0016 | **-0.9509** | 0.0194 | 0.0016 | -0.0179 | 0.4172 | 0.4103 |
| **LSTM** | `transfer_common_4` | 0.9054 | 0.0051 | **-0.9004** | 0.0122 | 0.0019 | -0.0103 | 0.5355 | 0.5237 |
| **FUSION** | `transfer_common_4` | 0.9533 | 0.0004 | **-0.9529** | 0.0190 | 0.0015 | -0.0175 | 0.4751 | 0.4673 |

---
## 4. Covariate & Label Distribution Shift Analysis

- **Source Train Class Balance**: Benign = 873,134 (81.8%), Attack = 194,459 (18.2%)
- **Target Test Class Balance**: Benign = 13,476 (55.0%), Attack = 11,028 (45.0%)
- **Class Prevalence Shift**: +0.2679

| Feature | Source Mean ± Std | Target Mean ± Std | Median Shift | KS Statistic ($D$) | Wasserstein Distance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `flow_duration_ms` | 23410.77 ± 39921.45 | 1363.32 ± 4540.41 | +347.37 | 0.3446 | 22174.77 |
| `flow_packets_per_s` | 2222.82 ± 28736.56 | 10877.96 ± 76666.19 | +20.51 | 0.4017 | 9108.24 |
| `flow_bytes_per_s` | 186470.99 ± 4813151.35 | 5097406.27 ± 38902109.18 | +6078.12 | 0.3777 | 4916572.39 |
| `packet_length_mean` | 259.66 ± 354.54 | 253.31 ± 263.82 | +39.20 | 0.2128 | 78.94 |

---
## 5. Model Disagreements & Error Analysis on Target Domain

- **Aligned Evaluation Size**: 24,496 rows
- **RF vs LSTM Disagreements**: 84 (0.34%)
- **RF Positive, LSTM Negative**: 30 (RF Correct: 0, RF False Alarm: 0)
- **LSTM Positive, RF Negative**: 54 (LSTM Correct: 0, LSTM False Alarm: 0)

---
## 6. Target Domain Per-Attack-Family Detection Breakdown

| Attack Family | Class | Target Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Normal` | BENIGN | 13,468 | 13,447 | 21 | 0 | 99.84% | 0.16% |
| `Exploits` | ATTACK | 5,071 | 1 | 0 | 5,070 | 0.02% | 99.98% |
| `Fuzzers` | ATTACK | 3,187 | 5 | 0 | 3,182 | 0.16% | 99.84% |
| `Reconnaissance` | ATTACK | 1,373 | 0 | 0 | 1,373 | 0.00% | 100.00% |
| `DoS` | ATTACK | 723 | 2 | 0 | 721 | 0.28% | 99.72% |
| `Generic` | ATTACK | 242 | 0 | 0 | 242 | 0.00% | 100.00% |
| `Shellcode` | ATTACK | 201 | 1 | 0 | 200 | 0.50% | 99.50% |
| `Analysis` | ATTACK | 103 | 0 | 0 | 103 | 0.00% | 100.00% |
| `Backdoor` | ATTACK | 83 | 0 | 0 | 83 | 0.00% | 100.00% |
| `Worms` | ATTACK | 45 | 0 | 0 | 45 | 0.00% | 100.00% |

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