# EXPERIMENT CARD: `EXP-P1-CIC2017-R10-001`

> [!IMPORTANT]
> This experiment card is automatically generated from machine-readable evaluation artifacts.
> It documents the complete auditable pipeline from raw verified files to final test metrics.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-CIC2017-R10-001`
- **Research Question**: `RQ1_RQ2_RQ3`
- **Hypothesis**: Flow-level behavioral features separate benign and malicious traffic on CIC-IDS2017; supervised LSTM and RF+LSTM fusion provide complementary signals without test leakage.
- **Dataset Key**: `cicids2017` (Version: `1.0.0`)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `40a0c58d3f3fef5301ea808750cf56afb3c80f4c`
- **Random Seed(s)**: `42`
- **Wall-Clock Time**: `613.32s`
- **Peak RSS**: `1692.64 MiB` (CPU Count: `12`)

---
## 2. Input Files and Integrity Verification

| Source File | SHA-256 (first 16 chars) | Byte Size | Raw Rows | Provenance Class | Integrity Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | `6ff1580f5f81c0ae...` | 77,123,859 | 225,745 | `third_party_mirror` | `verified` |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | `ca1824c51bfbb7b3...` | 76,906,168 | 286,467 | `third_party_mirror` | `verified` |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | `53a41c24d570ea83...` | 58,316,725 | 191,033 | `third_party_mirror` | `verified` |
| `Monday-WorkingHours.pcap_ISCX.csv` | `852c4beb34eda186...` | 176,927,918 | 529,918 | `third_party_mirror` | `verified` |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | `6bcda3857c250467...` | 83,102,436 | 288,602 | `third_party_mirror` | `verified` |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | `d67066211fb1689c...` | 52,023,263 | 170,366 | `third_party_mirror` | `verified` |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | `52b8692ae8c7d2ed...` | 135,078,995 | 445,909 | `third_party_mirror` | `verified` |
| `Wednesday-workingHours.pcap_ISCX.csv` | `893c27dc968bf7a8...` | 225,166,395 | 692,703 | `third_party_mirror` | `verified` |

---
## 3. Multi-Stage Row Accounting and Mathematical Reconciliation

```text
Raw Rows Loaded:                      2,830,743
  - Unknown / Rejected Labels:                0
  - Malformed / Invalid Rows:               113
  - Exact Duplicate Rows:               194,073
  - Non-Finite Feature Rows:              1,686
  - Duplicate-Label Conflicts:          319,537
  - Feature-Space Duplicates (Pol A):   536,012
  -------------------------------------------------
Final Modelling Population:           1,779,322
```

- **Reconciliation Check**: `PASSED (Identity verified)`
- **Reconciliation Formula**: `raw_rows - (removed_unknown_label + removed_invalid + removed_exact_duplicates + removed_non_finite + removed_feature_duplicates + removed_label_conflicts) == final_modeling_rows`

### Duplicate-Label Conflict Analysis
- **Unique Duplicate Vectors**: 93,655
- **Conflicting Vectors Detected**: 1,743 (319,537 rows involved)
- **Benign ↔ Attack Conflicts**: 10
- **Conflict Policy Applied**: `reject_conflicts` (Rows dropped: 319,537)

---
## 4. Split Methodology and Ordering Justification

- **Methodology**: `deduplicate_features` with stratified partition
- **Duplicate Policy**: `deduplicate_features`
- **Ordering Basis**: Capture/arrival order from source collection. Microsecond timestamps are absent (CIC-IDS2017/UNSW-NB15) or non-monotonic with second-level ties (CSE-CIC-IDS2018).
- **Sequence Safety**: LSTM sequences are strictly bounded within individual source files; no cross-file sequence generation.
- **Split Counts**: Train=1,067,593, Val=355,864, Test=355,865

---
## 5. Baseline Ladder Comparison (Fair Aligned Population)

> [!NOTE]
> To ensure direct mathematical fairness, all baseline ladder models and headline fusion
> comparisons are evaluated on the exact same aligned test slice (355,865 rows).

| Model | Model Family | Test Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.8179 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.1821 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.8918 | 0.6403 | 0.9264 | 0.7572 | 0.8841 | 0.1159 | 0.9292 | 0.8238 |
| **DECISION_TREE** | `tree_baseline` | 0.9744 | 0.8870 | 0.9851 | 0.9335 | 0.9721 | 0.0279 | 0.9945 | 0.9674 |
| **RANDOM_FOREST** | `ensemble` | 0.9815 | 0.9151 | 0.9901 | 0.9512 | 0.9796 | 0.0204 | 0.9968 | 0.9824 |

### Statistical Model Comparisons (Paired Non-Parametric Bootstrap)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Statistically Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.7572 | 0.9335 | -0.1763 | [-0.1782, -0.1741] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.9335 | 0.9512 | -0.0177 | [-0.0185, -0.0169] | 0.0000 | ✅ YES |

---
## 6. Per-Attack-Family Evaluation

| Attack Family | Class | Test Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 291,045 | 285,094 | 5,951 | 0 | 97.96% | 2.04% |
| `DoS Hulk` | ATTACK | 33,074 | 32,996 | 0 | 78 | 99.76% | 0.24% |
| `DDoS` | ATTACK | 25,347 | 25,271 | 0 | 76 | 99.70% | 0.30% |
| `DoS GoldenEye` | ATTACK | 2,037 | 1,959 | 0 | 78 | 96.17% | 3.83% |
| `DoS Slowhttptest` | ATTACK | 1,020 | 1,004 | 0 | 16 | 98.43% | 1.57% |
| `DoS slowloris` | ATTACK | 901 | 867 | 0 | 34 | 96.23% | 3.77% |
| `FTP-Patator` | ATTACK | 897 | 894 | 0 | 3 | 99.67% | 0.33% |
| `SSH-Patator` | ATTACK | 648 | 638 | 0 | 10 | 98.46% | 1.54% |
| `PortScan` | ATTACK | 320 | 317 | 0 | 3 | 99.06% | 0.94% |
| `Web Attack � Brute Force` | ATTACK | 258 | 41 | 0 | 217 | 15.89% | 84.11% |
| `Bot` | ATTACK | 196 | 188 | 0 | 8 | 95.92% | 4.08% |
| `Web Attack � XSS` | ATTACK | 108 | 3 | 0 | 105 | 2.78% | 97.22% |
| `Infiltration` | ATTACK | 8 | 0 | 0 | 8 | 0.00% | 100.00% |
| `Heartbleed` | ATTACK | 3 | 2 | 0 | 1 | 66.67% | 33.33% |
| `Web Attack � Sql Injection` | ATTACK | 3 | 0 | 0 | 3 | 0.00% | 100.00% |

---
## 7. Explainability (TreeSHAP Feature Attributions)

> [!NOTE]
> SHAP attributions quantify additive contributions relative to the background expectation.
> They do **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| :---: | :--- | :---: |
| 1 | `packet_length_std` | 0.094327 |
| 2 | `packet_length_mean` | 0.087260 |
| 3 | `flow_packets_per_s` | 0.047941 |
| 4 | `flow_bytes_per_s` | 0.036564 |
| 5 | `flow_duration_ms` | 0.031858 |
| 6 | `ack_count` | 0.020760 |
| 7 | `fin_count` | 0.011039 |
| 8 | `syn_count` | 0.003289 |
| 9 | `syn_ack_ratio` | 0.002803 |
| 10 | `rst_count` | 0.000000 |

---
## 9. Calibration & Threshold Analysis

- **Validation Platt Calibration Brier Score (RF)**: 0.015734909912174275
- **Validation Platt Calibration ECE (RF)**: N/A
- **Decision D-003 Status**: OPEN. Operational operating point requires application-specific cost trade-offs.

---
## 10. Open Decisions & Limitations

1. **D-002 (Feature Contract)**: CIC-IDS2017 & CSE-CIC-IDS2018 satisfy R10/R15/R20. UNSW-NB15 lacks TCP flag counts, subflow fields, and IAT statistics; evaluated via 4-feature common transfer contract.
2. **D-003 (Operational Threshold)**: Neutral 0.5 threshold reported; candidate operational points provided in `threshold_candidates.json`.
3. **Temporal Modeling Limitation**: Network flow capture CSVs do not provide verified microsecond packet ordering; sequence models reflect capture chunk sequence rather than continuous temporal flow.

---
## 11. Artifact Traceability

All experiment artifacts are deterministically recorded in the experiment directory:
- `experiment_population.json`: Complete file manifest, accounting, and conflict report
- `split_manifest.json`: Split assignments, leakage audit, and ordering basis
- `test_metrics.json`: Full metric dictionary across native and aligned populations
- `model_comparisons.json`: Paired bootstrap hypothesis tests and confidence intervals
- `per_family_metrics.csv`: Per-attack-family support, detection rate, and error rate
- `calibration_report.json`: Pre- and post-calibration Brier scores and ECE
- `threshold_candidates.json`: Validation threshold operating points
- `shap_summary.json`: Global, class-specific, and per-family SHAP attributions
- `resource_profile.json`: Peak RSS, duration, CPU count, and disk usage
- `experiment_record.json`: Complete experiment metadata with reproducibility sidecar