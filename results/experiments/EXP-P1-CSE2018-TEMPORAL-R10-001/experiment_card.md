# EXPERIMENT CARD: `EXP-P1-CSE2018-TEMPORAL-R10-001`

> [!IMPORTANT]
> This experiment card is automatically generated from machine-readable evaluation artifacts.
> It documents the complete auditable pipeline from raw verified files to final test metrics.

## 1. Overview & Provenance

- **Experiment ID**: `EXP-P1-CSE2018-TEMPORAL-R10-001`
- **Research Question**: `RQ1_RQ2_RQ3_TEMPORAL_VALIDATION`
- **Hypothesis**: A strictly time-ordered held-out test period measures future-day generalisation and quantifies how much of the row-level random-split performance is attributable to near-duplicate temporal leakage.
- **Dataset Key**: `cse_cic_ids2018` (Version: `1.0.0`)
- **Execution Status**: `EMPIRICALLY_OBSERVED`
- **Git Commit**: `a775da1aa100aecc300e35a4d46e2ac8df635d31`
- **Random Seed(s)**: `42`
- **Wall-Clock Time**: `2784.30s`
- **Peak RSS**: `6413.32 MiB` (CPU Count: `12`)

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

- **Methodology**: `temporal` (strict future-day holdout; no class stratification)
- **Duplicate Policy**: `deduplicate_features`
- **Ordering Basis**: Real capture `Timestamp`, sorted ascending. The temporal holdout is cut at hour boundaries; test rows are strictly later than validation rows, and validation rows are strictly later than training rows.
- **Sequence Safety**: LSTM sequences are strictly bounded within individual source files; no cross-file sequence generation.
- **Split Counts**: Train=5,053,051, Val=1,627,614, Test=1,631,630
- **Temporal Cut Strategy**: `nearest_hour_boundary` (hour-aligned: `True`; repaired timestamps: `0`)
- **Temporal Ranges**: train 2018-02-14 01:00:00 → 2018-02-20 10:59:59; validation 2018-02-20 11:00:00 → 2018-02-22 10:59:59; test 2018-02-22 11:00:00 → 2018-03-02 12:59:59

---
## 5. Baseline Ladder Comparison (Fair Aligned Population)

> [!NOTE]
> To ensure direct mathematical fairness, all baseline ladder models and headline fusion
> comparisons are evaluated on the exact same aligned test slice (1,631,630 rows).

| Model | Model Family | Test Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **MAJORITY** | `prior_baseline` | 0.9692 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 0.5000 | 0.0308 |
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.8126 | 0.0285 | 0.1533 | 0.0480 | 0.8335 | 0.1665 | 0.5757 | 0.0401 |
| **DECISION_TREE** | `tree_baseline` | 0.9597 | 0.0427 | 0.0143 | 0.0214 | 0.9898 | 0.0102 | 0.5244 | 0.0359 |
| **RANDOM_FOREST** | `ensemble` | 0.9633 | 0.0332 | 0.0068 | 0.0113 | 0.9937 | 0.0063 | 0.3905 | 0.0256 |

### Statistical Model Comparisons (Paired Non-Parametric Bootstrap)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Statistically Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.0480 | 0.0214 | +0.0266 | [0.0250, 0.0282] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.0214 | 0.0113 | +0.0102 | [0.0089, 0.0114] | 0.0000 | ✅ YES |

---
## 6. Per-Attack-Family Evaluation

| Attack Family | Class | Test Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 1,581,324 | 1,571,379 | 9,945 | 0 | 99.37% | 0.63% |
| `INFILTERATION` | ATTACK | 34,807 | 328 | 0 | 34,479 | 0.94% | 99.06% |
| `BOT` | ATTACK | 15,214 | 13 | 0 | 15,201 | 0.09% | 99.91% |
| `BRUTE FORCE -WEB` | ATTACK | 179 | 0 | 0 | 179 | 0.00% | 100.00% |
| `BRUTE FORCE -XSS` | ATTACK | 75 | 0 | 0 | 75 | 0.00% | 100.00% |
| `SQL INJECTION` | ATTACK | 31 | 0 | 0 | 31 | 0.00% | 100.00% |

---
## 9. Calibration & Threshold Analysis

- **Validation Platt Calibration Brier Score (RF)**: 0.044121917235664686
- **Validation Platt Calibration ECE (RF)**: N/A
- **Decision D-003 Status**: OPEN. Operational operating point requires application-specific cost trade-offs.

---
## 10. Open Decisions & Limitations

1. **D-002 (Feature Contract)**: CIC-IDS2017 & CSE-CIC-IDS2018 satisfy R10/R15/R20. UNSW-NB15 lacks TCP flag counts, subflow fields, and IAT statistics; evaluated via 4-feature common transfer contract.
2. **D-003 (Operational Threshold)**: Neutral 0.5 threshold reported; candidate operational points provided in `threshold_candidates.json`.
3. **Future-Day Generalization Limitation**: The strict temporal holdout produced RF F1 0.0113 (recall 0.0068, ROC-AUC 0.3905) on 50,306 surviving future attacks. The random-split F1 0.8861 is an in-domain upper bound, not a future-day estimate. The temporal test attack prevalence is 3.08% after Policy A conflict/duplicate removal; the run is single-seed and does not include LSTM/fusion.
4. **Temporal Modeling Limitation**: Network flow capture CSVs do not provide verified microsecond packet ordering; sequence models reflect capture chunk sequence rather than continuous temporal flow.

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