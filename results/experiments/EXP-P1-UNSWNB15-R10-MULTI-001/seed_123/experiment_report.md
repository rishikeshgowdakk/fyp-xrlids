# EXPERIMENT CARD: `EXP-P1-UNSWNB15-R10-MULTI-001`

> [!IMPORTANT]
> This experiment card is automatically generated from machine-readable evaluation artifacts.
> It documents the complete auditable pipeline from raw verified files to final test metrics.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-UNSWNB15-R10-MULTI-001`
- **Research Question**: `RQ1_IN_DOMAIN_UNSW`
- **Hypothesis**: Evaluates the full UNSW-NB15 multi-file population under the frozen R10 contract using the 4 verified derivable flow features (flow_duration_ms, flow_packets_per_s, flow_bytes_per_s, packet_length_mean). The 6 missing TCP flag, subflow, and IAT features are intentionally omitted under Decision D-002 rather than fabricated.
- **Dataset Key**: `unsw_nb15` (Version: `1.0.0`)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `4798758c58044eee89ff6b8f39851bbb7ec439e9`
- **Random Seed(s)**: `123`
- **Wall-Clock Time**: `184.27s`
- **Peak RSS**: `916.98 MiB` (CPU Count: `12`)

---
## 2. Input Files and Integrity Verification

| Source File | SHA-256 (first 16 chars) | Byte Size | Raw Rows | Provenance Class | Integrity Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `UNSW_NB15_testing-set.csv` | `734fe6642edf758f...` | 15,380,800 | 82,332 | `recognized_mirror` | `verified` |
| `UNSW_NB15_training-set.csv` | `bec7dd5ec88dc2a0...` | 32,293,018 | 175,341 | `recognized_mirror` | `verified` |

---
## 3. Multi-Stage Row Accounting and Mathematical Reconciliation

```text
Raw Rows Loaded:                        257,673
  - Unknown / Rejected Labels:                0
  - Malformed / Invalid Rows:                 0
  - Exact Duplicate Rows:                     0
  - Non-Finite Feature Rows:              3,607
  - Duplicate-Label Conflicts:           29,410
  - Feature-Space Duplicates (Pol A):   102,136
  -------------------------------------------------
Final Modelling Population:             122,520
```

- **Reconciliation Check**: `PASSED (Identity verified)`
- **Reconciliation Formula**: `raw_rows - (removed_unknown_label + removed_invalid + removed_exact_duplicates + removed_non_finite + removed_feature_duplicates + removed_label_conflicts) == final_modeling_rows`

### Duplicate-Label Conflict Analysis
- **Unique Duplicate Vectors**: 10,625
- **Conflicting Vectors Detected**: 558 (29,410 rows involved)
- **Benign ↔ Attack Conflicts**: 10
- **Conflict Policy Applied**: `reject_conflicts` (Rows dropped: 29,410)

---
## 4. Split Methodology and Ordering Justification

- **Methodology**: `deduplicate_features` with stratified partition
- **Duplicate Policy**: `deduplicate_features`
- **Ordering Basis**: Capture/arrival order from source collection. Microsecond timestamps are absent (CIC-IDS2017/UNSW-NB15) or non-monotonic with second-level ties (CSE-CIC-IDS2018).
- **Sequence Safety**: LSTM sequences are strictly bounded within individual source files; no cross-file sequence generation.
- **Split Counts**: Train=73,512, Val=24,504, Test=24,504

---
## 5. Baseline Ladder Comparison (Fair Aligned Population)

> [!NOTE]
> To ensure direct mathematical fairness, all baseline ladder models and headline fusion
> comparisons are evaluated on the exact same aligned test slice (24,496 rows).
>
> **Aligned Population Accounting (8-Row Boundary Explanation)**:
> The 8-row discrepancy between the full tabular test set (24,504 rows) and the aligned test set (24,496 rows) occurs because sequence construction requires $T=5$ consecutive records within the same source capture file (`stride=1`, `label_rule='last'`). To prevent synthetic temporal cross-contamination across disjoint capture days, sequence windows are strictly forbidden from crossing source file boundaries. Across the 2 source capture files in the test split, the first $T - 1 = 4$ flow records of each file lack sufficient preceding intra-file context to form a valid 5-step sequence ending at those records (2 files $\times$ 4 boundary records = 8 dropped rows). Direct baseline ladder comparisons and paired statistical hypothesis tests are evaluated exclusively on this identical aligned test slice.

| Model | Model Family | Test Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.5498 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.4502 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.6030 | 0.6713 | 0.2313 | 0.3441 | 0.9073 | 0.0927 | 0.6445 | 0.5784 |
| **DECISION_TREE** | `tree_baseline` | 0.8095 | 0.7122 | 0.9681 | 0.8207 | 0.6797 | 0.3203 | 0.9152 | 0.8763 |
| **RANDOM_FOREST** | `ensemble` | 0.8640 | 0.8126 | 0.9071 | 0.8573 | 0.8287 | 0.1713 | 0.9499 | 0.9342 |
| **LSTM** | `temporal_recurrent` | 0.8688 | 0.8036 | 0.9378 | 0.8655 | 0.8124 | 0.1876 | 0.9324 | 0.8908 |
| **FUSION** | `ensemble_fusion` | 0.8977 | 0.8289 | 0.9736 | 0.8955 | 0.8355 | 0.1645 | 0.9669 | 0.9539 |

### Statistical Model Comparisons (Paired Non-Parametric Bootstrap)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Statistically Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.3441 | 0.8207 | -0.4766 | [-0.4875, -0.4656] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.8207 | 0.8573 | -0.0366 | [-0.0407, -0.0326] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.8573 | 0.8655 | -0.0083 | [-0.0131, -0.0028] | 0.0020 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.8955 | 0.8573 | +0.0382 | [0.0345, 0.0419] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.8955 | 0.8655 | +0.0299 | [0.0268, 0.0334] | 0.0000 | ✅ YES |

---
## 6. Per-Attack-Family Evaluation

| Attack Family | Class | Test Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Normal` | BENIGN | 13,476 | 11,165 | 2,311 | 0 | 82.85% | 17.15% |
| `Exploits` | ATTACK | 5,070 | 4,921 | 0 | 149 | 97.06% | 2.94% |
| `Fuzzers` | ATTACK | 3,226 | 2,495 | 0 | 731 | 77.34% | 22.66% |
| `Reconnaissance` | ATTACK | 1,332 | 1,327 | 0 | 5 | 99.62% | 0.38% |
| `DoS` | ATTACK | 740 | 689 | 0 | 51 | 93.11% | 6.89% |
| `Generic` | ATTACK | 234 | 228 | 0 | 6 | 97.44% | 2.56% |
| `Shellcode` | ATTACK | 218 | 179 | 0 | 39 | 82.11% | 17.89% |
| `Analysis` | ATTACK | 96 | 63 | 0 | 33 | 65.62% | 34.38% |
| `Backdoor` | ATTACK | 72 | 62 | 0 | 10 | 86.11% | 13.89% |
| `Worms` | ATTACK | 40 | 40 | 0 | 0 | 100.00% | 0.00% |

---
## 7. Explainability (TreeSHAP Feature Attributions)

> [!NOTE]
> SHAP attributions quantify additive contributions relative to the background expectation.
> They do **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| :---: | :--- | :---: |
| 1 | `flow_packets_per_s` | 0.216913 |
| 2 | `packet_length_mean` | 0.090962 |
| 3 | `flow_bytes_per_s` | 0.088485 |
| 4 | `flow_duration_ms` | 0.080989 |

---
## 8. Failure Analysis & Model Disagreements

- **Aligned Evaluation Size**: 24,496 rows
- **RF vs LSTM Disagreements**: 3,766 (15.37%)
- **RF Positive, LSTM Negative**: 1604 (RF Correct: 606, RF False Alarm: 998)
- **LSTM Positive, RF Negative**: 2162 (LSTM Correct: 944, LSTM False Alarm: 1218)

---
## 9. Calibration & Threshold Analysis

- **Validation Platt Calibration Brier Score (RF)**: 0.090149483573526
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