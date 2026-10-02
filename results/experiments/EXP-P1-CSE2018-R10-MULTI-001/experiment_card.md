# EXPERIMENT CARD: `EXP-P1-CSE2018-R10-MULTI-001`

> [!IMPORTANT]
> This experiment card is automatically generated from machine-readable evaluation artifacts.
> It documents the complete auditable pipeline from raw verified files to final test metrics.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-CSE2018-R10-MULTI-001`
- **Research Question**: `RQ1_RQ2_RQ3`
- **Hypothesis**: Multi-day capture data in CSE-CIC-IDS2018 provides comprehensive attack coverage across 10 capture days; features evaluated under Policy A with duplicate conflict resolution prevent cross-day vector leakage.
- **Dataset Key**: `cse_cic_ids2018` (Version: `1.0.0`)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `9e78dd5bc336db5061a5a38faead849a9161ce11`
- **Random Seed(s)**: `42`
- **Wall-Clock Time**: `8045.54s`
- **Peak RSS**: `5754.54 MiB` (CPU Count: `12`)

---
## 2. Input Files and Integrity Verification

| Source File | SHA-256 (first 16 chars) | Byte Size | Raw Rows | Provenance Class | Integrity Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | `d96f38e7496aba83...` | 352,368,373 | 1,048,575 | `recognized_mirror` | `verified` |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | `1a4919faa0c49c7a...` | 333,723,605 | 1,048,575 | `recognized_mirror` | `verified` |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | `d0a7f5059d9823b6...` | 382,840,456 | 1,048,575 | `recognized_mirror` | `verified` |
| `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | `7287a4d7740a1ddd...` | 4,054,925,350 | 7,948,748 | `recognized_mirror` | `verified` |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | `b0534c5d7d8b41e0...` | 107,842,858 | 331,125 | `recognized_mirror` | `verified` |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | `fa2947a8256d81ee...` | 375,945,899 | 1,048,575 | `recognized_mirror` | `verified` |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | `da33c927018274f9...` | 382,636,202 | 1,048,575 | `recognized_mirror` | `verified` |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | `acff8bc61376ee03...` | 358,223,333 | 1,048,575 | `recognized_mirror` | `verified` |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | `a5f4a1c2689e0aa6...` | 328,893,673 | 1,048,575 | `recognized_mirror` | `verified` |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | `f15e2a1230444605...` | 209,249,758 | 613,104 | `recognized_mirror` | `verified` |

---
## 3. Multi-Stage Row Accounting and Mathematical Reconciliation

```text
Raw Rows Loaded:                     16,233,002
  - Unknown / Rejected Labels:               10
  - Malformed / Invalid Rows:                14
  - Exact Duplicate Rows:               383,622
  - Non-Finite Feature Rows:             95,671
  - Duplicate-Label Conflicts:        4,496,789
  - Feature-Space Duplicates (Pol A): 2,944,601
  -------------------------------------------------
Final Modelling Population:           8,312,295
```

- **Reconciliation Check**: `PASSED (Identity verified)`
- **Reconciliation Formula**: `raw_rows - (removed_unknown_label + removed_invalid + removed_exact_duplicates + removed_non_finite + removed_feature_duplicates + removed_label_conflicts) == final_modeling_rows`

### Duplicate-Label Conflict Analysis
- **Unique Duplicate Vectors**: 919,077
- **Conflicting Vectors Detected**: 122,481 (4,496,789 rows involved)
- **Benign ↔ Attack Conflicts**: 10
- **Conflict Policy Applied**: `reject_conflicts` (Rows dropped: 4,496,789)

---
## 4. Split Methodology and Ordering Justification

- **Methodology**: `deduplicate_features` with stratified partition
- **Duplicate Policy**: `deduplicate_features`
- **Ordering Basis**: Capture/arrival order from source collection. Microsecond timestamps are absent (CIC-IDS2017/UNSW-NB15) or non-monotonic with second-level ties (CSE-CIC-IDS2018).
- **Sequence Safety**: LSTM sequences are strictly bounded within individual source files; no cross-file sequence generation.
- **Split Counts**: Train=4,987,377, Val=1,662,459, Test=1,662,459

---
## 5. Baseline Ladder Comparison (Fair Aligned Population)

> [!NOTE]
> To ensure direct mathematical fairness, all baseline ladder models and headline fusion
> comparisons are evaluated on the exact same aligned test slice (1,662,419 rows).
>
> **Aligned Population Accounting (40-Row Boundary Explanation)**:
> The 40-row discrepancy between the full tabular test set (1,662,459 rows) and the aligned test set (1,662,419 rows) occurs because sequence construction requires $T=5$ consecutive records within the same source capture file (`stride=1`, `label_rule='last'`). To prevent synthetic temporal cross-contamination across disjoint capture days, sequence windows are strictly forbidden from crossing source file boundaries. Across the 10 source capture files in the test split, the first $T - 1 = 4$ flow records of each file lack sufficient preceding intra-file context to form a valid 5-step sequence ending at those records (10 files $\times$ 4 boundary records = 40 dropped rows). Direct baseline ladder comparisons and paired statistical hypothesis tests are evaluated exclusively on this identical aligned test slice.

| Model | Model Family | Test Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.8874 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.1126 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.7706 | 0.3056 | 0.8152 | 0.4445 | 0.7650 | 0.2350 | 0.8850 | 0.6123 |
| **DECISION_TREE** | `tree_baseline` | 0.9595 | 0.7523 | 0.9546 | 0.8415 | 0.9601 | 0.0399 | 0.9833 | 0.9516 |
| **RANDOM_FOREST** | `ensemble` | 0.9723 | 0.8242 | 0.9580 | 0.8861 | 0.9741 | 0.0259 | 0.9902 | 0.9676 |
| **LSTM** | `temporal_recurrent` | 0.9912 | 0.9790 | 0.9424 | 0.9603 | 0.9974 | 0.0026 | 0.9966 | 0.9865 |
| **FUSION** | `ensemble_fusion` | 0.9912 | 0.9790 | 0.9424 | 0.9603 | 0.9974 | 0.0026 | 0.9966 | 0.9865 |

### Statistical Model Comparisons (Paired Non-Parametric Bootstrap)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Statistically Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.4445 | 0.8415 | -0.3969 | [-0.3984, -0.3957] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.8415 | 0.8861 | -0.0446 | [-0.0452, -0.0439] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.8861 | 0.9603 | -0.0743 | [-0.0752, -0.0734] | 0.0000 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.9603 | 0.8861 | +0.0743 | [0.0734, 0.0752] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.9603 | 0.9603 | +0.0000 | [0.0000, 0.0000] | 1.0000 | ❌ NO |

---
## 6. Per-Attack-Family Evaluation

| Attack Family | Class | Test Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 1,475,298 | 1,437,059 | 38,239 | 0 | 97.41% | 2.59% |
| `DDOS ATTACKS-LOIC-HTTP` | ATTACK | 106,973 | 106,059 | 0 | 914 | 99.15% | 0.85% |
| `DDOS ATTACK-HOIC` | ATTACK | 22,483 | 22,275 | 0 | 208 | 99.07% | 0.93% |
| `DOS ATTACKS-HULK` | ATTACK | 19,374 | 19,059 | 0 | 315 | 98.37% | 1.63% |
| `SSH-BRUTEFORCE` | ATTACK | 18,043 | 18,043 | 0 | 0 | 100.00% | 0.00% |
| `DOS ATTACKS-GOLDENEYE` | ATTACK | 8,109 | 8,008 | 0 | 101 | 98.75% | 1.25% |
| `INFILTERATION` | ATTACK | 7,027 | 752 | 0 | 6,275 | 10.70% | 89.30% |
| `BOT` | ATTACK | 2,999 | 2,974 | 0 | 25 | 99.17% | 0.83% |
| `DOS ATTACKS-SLOWLORIS` | ATTACK | 1,709 | 1,692 | 0 | 17 | 99.01% | 0.99% |
| `DDOS ATTACK-LOIC-UDP` | ATTACK | 358 | 358 | 0 | 0 | 100.00% | 0.00% |
| `BRUTE FORCE -WEB` | ATTACK | 49 | 45 | 0 | 4 | 91.84% | 8.16% |
| `BRUTE FORCE -XSS` | ATTACK | 22 | 21 | 0 | 1 | 95.45% | 4.55% |
| `SQL INJECTION` | ATTACK | 15 | 11 | 0 | 4 | 73.33% | 26.67% |

---
## 7. Explainability (TreeSHAP Feature Attributions)

> [!NOTE]
> SHAP attributions quantify additive contributions relative to the background expectation.
> They do **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| :---: | :--- | :---: |
| 1 | `flow_duration_ms` | 0.048827 |
| 2 | `packet_length_std` | 0.047968 |
| 3 | `packet_length_mean` | 0.041746 |
| 4 | `flow_packets_per_s` | 0.038704 |
| 5 | `ack_count` | 0.028670 |
| 6 | `rst_count` | 0.025091 |
| 7 | `flow_bytes_per_s` | 0.024931 |
| 8 | `syn_ack_ratio` | 0.000617 |
| 9 | `syn_count` | 0.000612 |
| 10 | `fin_count` | 0.000000 |

---
## 8. Failure Analysis & Model Disagreements

- **Aligned Evaluation Size**: 1,662,419 rows
- **RF vs LSTM Disagreements**: 42,059 (2.53%)
- **RF Positive, LSTM Negative**: 39709 (RF Correct: 4421, RF False Alarm: 35288)
- **LSTM Positive, RF Negative**: 2350 (LSTM Correct: 1508, LSTM False Alarm: 842)

---
## 9. Calibration & Threshold Analysis

- **Validation Platt Calibration Brier Score (RF)**: 0.02118915044236191
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