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
- **Git Commit**: `4798758c58044eee89ff6b8f39851bbb7ec439e9`
- **Random Seed(s)**: `123`
- **Wall-Clock Time**: `1091.73s`
- **Peak RSS**: `2785.68 MiB` (CPU Count: `12`)

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
> comparisons are evaluated on the exact same aligned test slice (355,833 rows).
>
> **Aligned Population Accounting (32-Row Boundary Explanation)**:
> The 32-row discrepancy between the full tabular test set (355,865 rows) and the aligned test set (355,833 rows) occurs because sequence construction requires $T=5$ consecutive records within the same source capture file (`stride=1`, `label_rule='last'`). To prevent synthetic temporal cross-contamination across disjoint capture days, sequence windows are strictly forbidden from crossing source file boundaries. Across the 8 source capture files in the test split, the first $T - 1 = 4$ flow records of each file lack sufficient preceding intra-file context to form a valid 5-step sequence ending at those records (8 files $\times$ 4 boundary records = 32 dropped rows). Direct baseline ladder comparisons and paired statistical hypothesis tests are evaluated exclusively on this identical aligned test slice.

| Model | Model Family | Test Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.8178 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.1822 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.8924 | 0.6417 | 0.9269 | 0.7584 | 0.8847 | 0.1153 | 0.9286 | 0.8242 |
| **DECISION_TREE** | `tree_baseline` | 0.9767 | 0.9000 | 0.9809 | 0.9387 | 0.9757 | 0.0243 | 0.9941 | 0.9676 |
| **RANDOM_FOREST** | `ensemble` | 0.9816 | 0.9162 | 0.9893 | 0.9513 | 0.9798 | 0.0202 | 0.9967 | 0.9820 |
| **LSTM** | `temporal_recurrent` | 0.9858 | 0.9630 | 0.9592 | 0.9611 | 0.9918 | 0.0082 | 0.9974 | 0.9886 |
| **FUSION** | `ensemble_fusion` | 0.9895 | 0.9683 | 0.9742 | 0.9712 | 0.9929 | 0.0071 | 0.9985 | 0.9920 |

### Statistical Model Comparisons (Paired Non-Parametric Bootstrap)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Statistically Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.7584 | 0.9387 | -0.1803 | [-0.1824, -0.1783] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.9387 | 0.9513 | -0.0126 | [-0.0133, -0.0119] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.9513 | 0.9611 | -0.0097 | [-0.0110, -0.0085] | 0.0000 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.9712 | 0.9513 | +0.0199 | [0.0189, 0.0210] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.9712 | 0.9611 | +0.0102 | [0.0095, 0.0108] | 0.0000 | ✅ YES |

---
## 6. Per-Attack-Family Evaluation

| Attack Family | Class | Test Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 291,045 | 285,178 | 5,867 | 0 | 97.98% | 2.02% |
| `DOS HULK` | ATTACK | 33,126 | 33,045 | 0 | 81 | 99.76% | 0.24% |
| `DDOS` | ATTACK | 25,402 | 25,329 | 0 | 73 | 99.71% | 0.29% |
| `DOS GOLDENEYE` | ATTACK | 1,986 | 1,917 | 0 | 69 | 96.53% | 3.47% |
| `DOS SLOWHTTPTEST` | ATTACK | 1,004 | 980 | 0 | 24 | 97.61% | 2.39% |
| `DOS SLOWLORIS` | ATTACK | 915 | 891 | 0 | 24 | 97.38% | 2.62% |
| `FTP-PATATOR` | ATTACK | 871 | 870 | 0 | 1 | 99.89% | 0.11% |
| `SSH-PATATOR` | ATTACK | 581 | 572 | 0 | 9 | 98.45% | 1.55% |
| `PORTSCAN` | ATTACK | 280 | 274 | 0 | 6 | 97.86% | 2.14% |
| `WEB ATTACK - BRUTE FORCE` | ATTACK | 280 | 31 | 0 | 249 | 11.07% | 88.93% |
| `BOT` | ATTACK | 225 | 214 | 0 | 11 | 95.11% | 4.89% |
| `WEB ATTACK - XSS` | ATTACK | 143 | 2 | 0 | 141 | 1.40% | 98.60% |
| `INFILTRATION` | ATTACK | 5 | 0 | 0 | 5 | 0.00% | 100.00% |
| `HEARTBLEED` | ATTACK | 1 | 1 | 0 | 0 | 100.00% | 0.00% |
| `WEB ATTACK - SQL INJECTION` | ATTACK | 1 | 0 | 0 | 1 | 0.00% | 100.00% |

---
## 7. Explainability (TreeSHAP Feature Attributions)

> [!NOTE]
> SHAP attributions quantify additive contributions relative to the background expectation.
> They do **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| :---: | :--- | :---: |
| 1 | `packet_length_std` | 0.085167 |
| 2 | `packet_length_mean` | 0.079044 |
| 3 | `flow_packets_per_s` | 0.041050 |
| 4 | `flow_duration_ms` | 0.030387 |
| 5 | `flow_bytes_per_s` | 0.025015 |
| 6 | `ack_count` | 0.018522 |
| 7 | `fin_count` | 0.009396 |
| 8 | `syn_ack_ratio` | 0.001557 |
| 9 | `syn_count` | 0.001496 |
| 10 | `rst_count` | 0.000000 |

---
## 8. Failure Analysis & Model Disagreements

- **Aligned Evaluation Size**: 355,833 rows
- **RF vs LSTM Disagreements**: 7,425 (2.09%)
- **RF Positive, LSTM Negative**: 6427 (RF Correct: 2136, RF False Alarm: 4291)
- **LSTM Positive, RF Negative**: 998 (LSTM Correct: 183, LSTM False Alarm: 815)

---
## 9. Calibration & Threshold Analysis

- **Validation Platt Calibration Brier Score (RF)**: 0.016028739088065687
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