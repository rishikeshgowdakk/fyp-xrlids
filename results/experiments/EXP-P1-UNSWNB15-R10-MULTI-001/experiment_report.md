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
- **Git Commit**: `416fa89c1c8162fe1c05d1e152b13ee550930a85`
- **Random Seed(s)**: `42`
- **Wall-Clock Time**: `172.00s`
- **Peak RSS**: `1049.45 MiB` (CPU Count: `12`)

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
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.6069 | 0.6727 | 0.2471 | 0.3614 | 0.9015 | 0.0985 | 0.6279 | 0.5693 |
| **DECISION_TREE** | `tree_baseline` | 0.8019 | 0.7042 | 0.9655 | 0.8144 | 0.6679 | 0.3321 | 0.9115 | 0.8702 |
| **RANDOM_FOREST** | `ensemble` | 0.8590 | 0.7966 | 0.9223 | 0.8548 | 0.8072 | 0.1928 | 0.9487 | 0.9323 |
| **LSTM** | `temporal_recurrent` | 0.8683 | 0.8086 | 0.9269 | 0.8637 | 0.8204 | 0.1796 | 0.9334 | 0.8903 |
| **FUSION** | `ensemble_fusion` | 0.8996 | 0.8334 | 0.9711 | 0.8970 | 0.8410 | 0.1590 | 0.9674 | 0.9538 |

### Statistical Model Comparisons (Paired Non-Parametric Bootstrap)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Statistically Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.3614 | 0.8144 | -0.4530 | [-0.4641, -0.4430] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.8144 | 0.8548 | -0.0404 | [-0.0440, -0.0366] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.8548 | 0.8637 | -0.0089 | [-0.0143, -0.0042] | 0.0000 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.8970 | 0.8548 | +0.0421 | [0.0389, 0.0457] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.8970 | 0.8637 | +0.0332 | [0.0295, 0.0367] | 0.0000 | ✅ YES |

> [!NOTE]
> **Delta Direction Clarification**: Row 3 evaluates $\Delta(A - B)$ where $A=\text{RF}$ and $B=\text{LSTM}$, giving $\text{RF} - \text{LSTM} = -0.0089$ (95% CI [-0.0143, -0.0042], $p = 0.0000$). Equivalently, $\text{LSTM} - \text{RF} = +0.0089$, demonstrating that Supervised LSTM statistically significantly outperforms Random Forest on UNSW-NB15.

---
## 6. Per-Attack-Family Evaluation

| Attack Family | Class | Test Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Normal` | BENIGN | 13,476 | 10,873 | 2,603 | 0 | 80.68% | 19.32% |
| `Exploits` | ATTACK | 5,071 | 4,976 | 0 | 95 | 98.13% | 1.87% |
| `Fuzzers` | ATTACK | 3,187 | 2,517 | 0 | 670 | 78.98% | 21.02% |
| `Reconnaissance` | ATTACK | 1,373 | 1,372 | 0 | 1 | 99.93% | 0.07% |
| `DoS` | ATTACK | 723 | 697 | 0 | 26 | 96.40% | 3.60% |
| `Generic` | ATTACK | 242 | 232 | 0 | 10 | 95.87% | 4.13% |
| `Shellcode` | ATTACK | 201 | 183 | 0 | 18 | 91.04% | 8.96% |
| `Analysis` | ATTACK | 103 | 80 | 0 | 23 | 77.67% | 22.33% |
| `Backdoor` | ATTACK | 83 | 70 | 0 | 13 | 84.34% | 15.66% |
| `Worms` | ATTACK | 45 | 44 | 0 | 1 | 97.78% | 2.22% |

---
## 7. Explainability (TreeSHAP Feature Attributions)

> [!NOTE]
> SHAP attributions quantify additive contributions relative to the background expectation.
> They do **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| :---: | :--- | :---: |
| 1 | `flow_packets_per_s` | 0.221586 |
| 2 | `packet_length_mean` | 0.102222 |
| 3 | `flow_bytes_per_s` | 0.079184 |
| 4 | `flow_duration_ms` | 0.073908 |

---
## 8. Failure Analysis & Model Disagreements

- **Aligned Evaluation Size**: 24,496 rows
- **RF vs LSTM Disagreements**: 3,901 (15.93%)
- **RF Positive, LSTM Negative**: 2014 (RF Correct: 717, RF False Alarm: 1297)
- **LSTM Positive, RF Negative**: 1887 (LSTM Correct: 768, LSTM False Alarm: 1119)

---
## 9. Calibration & Threshold Analysis

- **Validation Platt Calibration Brier Score (RF)**: 0.08924923957187168
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