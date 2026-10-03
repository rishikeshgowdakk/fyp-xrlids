# EXPERIMENT CARD: `EXP-P1-TRANSFER-CSE-TO-UNSW-R4-001`

> [!IMPORTANT]
> This experiment card documents cross-dataset transfer evaluation under strict scientific isolation.
> Preprocessing and source models were fitted exclusively on source training data.
> Target domain data was evaluated strictly out-of-domain with zero target parameter tuning.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-TRANSFER-CSE-TO-UNSW-R4-001`
- **Research Question**: `RQ5_CROSS_DATASET_TRANSFER`
- **Source Dataset**: `cse_cic_ids2018`
- **Target Dataset**: `unsw_nb15`
- **Feature Contract**: `transfer_common_4` (4 features)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `07138caac5398765d66d60987d8170f05d34e766`
- **Random Seed**: `42`
- **Frozen Source Fusion Alpha**: `0.50`
- **Peak RSS**: `6174.69 MiB` (CPU Count: `12`)
- **Wall-Clock Duration**: `1282.02s`

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
| **LOGISTIC_REGRESSION** | `transfer_common_4` | 0.3247 | 0.5860 | **+0.2613** | 0.3916 | 0.3303 | -0.0612 | 0.5968 | 0.5428 |
| **DECISION_TREE** | `transfer_common_4` | 0.8419 | 0.0902 | **-0.7517** | 0.0368 | 0.0741 | +0.0373 | 0.5317 | 0.4562 |
| **RF** | `transfer_common_4` | 0.8672 | 0.0026 | **-0.8646** | 0.0313 | 0.0923 | +0.0610 | 0.3506 | 0.3476 |
| **LSTM** | `transfer_common_4` | 0.8920 | 0.0048 | **-0.8872** | 0.0083 | 0.0489 | +0.0406 | 0.3477 | 0.3594 |
| **FUSION** | `transfer_common_4` | 0.9302 | 0.0019 | **-0.9283** | 0.0093 | 0.0398 | +0.0305 | 0.3312 | 0.3404 |

---
## 4. Covariate & Label Distribution Shift Analysis

- **Source Train Class Balance**: Benign = 4,425,894 (88.7%), Attack = 561,483 (11.3%)
- **Target Test Class Balance**: Benign = 13,476 (55.0%), Attack = 11,028 (45.0%)
- **Class Prevalence Shift**: +0.3375

| Feature | Source Mean ± Std | Target Mean ± Std | Median Shift | KS Statistic ($D$) | Wasserstein Distance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `flow_duration_ms` | 20353.62 ± 37534.64 | 1363.32 ± 4540.41 | -1565.81 | 0.4166 | 18936.56 |
| `flow_packets_per_s` | 317.92 ± 11776.85 | 10877.96 ± 76666.19 | +35.50 | 0.5679 | 10619.37 |
| `flow_bytes_per_s` | 32115.85 ± 2059683.63 | 5097406.27 ± 38902109.18 | +7110.86 | 0.4830 | 5073122.51 |
| `packet_length_mean` | 118.96 ± 123.33 | 253.31 ± 263.82 | +17.99 | 0.2639 | 133.71 |

---
## 5. Model Disagreements & Error Analysis on Target Domain

- **Aligned Evaluation Size**: 24,496 rows
- **RF vs LSTM Disagreements**: 1,574 (6.43%)
- **RF Positive, LSTM Negative**: 1,073 (RF Correct: 0, RF False Alarm: 0)
- **LSTM Positive, RF Negative**: 501 (LSTM Correct: 0, LSTM False Alarm: 0)

---
## 6. Target Domain Per-Attack-Family Detection Breakdown

| Attack Family | Class | Target Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Normal` | BENIGN | 13,468 | 12,225 | 1,243 | 0 | 90.77% | 9.23% |
| `Exploits` | ATTACK | 5,071 | 6 | 0 | 5,065 | 0.12% | 99.88% |
| `Fuzzers` | ATTACK | 3,187 | 3 | 0 | 3,184 | 0.09% | 99.91% |
| `Reconnaissance` | ATTACK | 1,373 | 0 | 0 | 1,373 | 0.00% | 100.00% |
| `DoS` | ATTACK | 723 | 3 | 0 | 720 | 0.41% | 99.59% |
| `Generic` | ATTACK | 242 | 1 | 0 | 241 | 0.41% | 99.59% |
| `Shellcode` | ATTACK | 201 | 3 | 0 | 198 | 1.49% | 98.51% |
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