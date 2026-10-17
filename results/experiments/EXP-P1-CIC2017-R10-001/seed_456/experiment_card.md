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
- **Random Seed(s)**: `456`
- **Wall-Clock Time**: `1022.58s`
- **Peak RSS**: `2845.12 MiB` (CPU Count: `12`)

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
| **LOGISTIC_REGRESSION** | `linear_baseline` | 0.8927 | 0.6420 | 0.9287 | 0.7592 | 0.8846 | 0.1154 | 0.9298 | 0.8238 |
| **DECISION_TREE** | `tree_baseline` | 0.9768 | 0.8990 | 0.9830 | 0.9391 | 0.9754 | 0.0246 | 0.9945 | 0.9677 |
| **RANDOM_FOREST** | `ensemble` | 0.9819 | 0.9171 | 0.9899 | 0.9522 | 0.9801 | 0.0199 | 0.9968 | 0.9825 |
| **LSTM** | `temporal_recurrent` | 0.9849 | 0.9582 | 0.9590 | 0.9586 | 0.9907 | 0.0093 | 0.9969 | 0.9875 |
| **FUSION** | `ensemble_fusion` | 0.9906 | 0.9650 | 0.9843 | 0.9746 | 0.9920 | 0.0080 | 0.9984 | 0.9919 |

### Statistical Model Comparisons (Paired Non-Parametric Bootstrap)

| Comparison (A vs B) | Metric | Estimate A | Estimate B | Δ (A - B) | 95% Bootstrap CI | p-value | Statistically Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LR** vs **DT** | `f1` | 0.7592 | 0.9391 | -0.1799 | [-0.1819, -0.1779] | 0.0000 | ✅ YES |
| **DT** vs **RF** | `f1` | 0.9391 | 0.9522 | -0.0131 | [-0.0138, -0.0123] | 0.0000 | ✅ YES |
| **RF** vs **LSTM** | `f1` | 0.9522 | 0.9586 | -0.0065 | [-0.0077, -0.0052] | 0.0000 | ✅ YES |
| **Fusion** vs **RF** | `f1` | 0.9746 | 0.9522 | +0.0224 | [0.0215, 0.0233] | 0.0000 | ✅ YES |
| **Fusion** vs **LSTM** | `f1` | 0.9746 | 0.9586 | +0.0159 | [0.0150, 0.0168] | 0.0000 | ✅ YES |

---
## 6. Per-Attack-Family Evaluation

| Attack Family | Class | Test Support | Correct | False Positives | False Negatives | Detection Rate (Recall) | Error Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | BENIGN | 291,045 | 285,248 | 5,797 | 0 | 98.01% | 1.99% |
| `DOS HULK` | ATTACK | 32,880 | 32,801 | 0 | 79 | 99.76% | 0.24% |
| `DDOS` | ATTACK | 25,635 | 25,563 | 0 | 72 | 99.72% | 0.28% |
| `DOS GOLDENEYE` | ATTACK | 2,042 | 1,965 | 0 | 77 | 96.23% | 3.77% |
| `DOS SLOWHTTPTEST` | ATTACK | 1,019 | 992 | 0 | 27 | 97.35% | 2.65% |
| `DOS SLOWLORIS` | ATTACK | 903 | 887 | 0 | 16 | 98.23% | 1.77% |
| `FTP-PATATOR` | ATTACK | 834 | 833 | 0 | 1 | 99.88% | 0.12% |
| `SSH-PATATOR` | ATTACK | 579 | 567 | 0 | 12 | 97.93% | 2.07% |
| `PORTSCAN` | ATTACK | 290 | 286 | 0 | 4 | 98.62% | 1.38% |
| `BOT` | ATTACK | 258 | 247 | 0 | 11 | 95.74% | 4.26% |
| `WEB ATTACK - BRUTE FORCE` | ATTACK | 255 | 22 | 0 | 233 | 8.63% | 91.37% |
| `WEB ATTACK - XSS` | ATTACK | 110 | 1 | 0 | 109 | 0.91% | 99.09% |
| `INFILTRATION` | ATTACK | 10 | 1 | 0 | 9 | 10.00% | 90.00% |
| `HEARTBLEED` | ATTACK | 4 | 3 | 0 | 1 | 75.00% | 25.00% |
| `WEB ATTACK - SQL INJECTION` | ATTACK | 1 | 0 | 0 | 1 | 0.00% | 100.00% |

---
## 7. Explainability (TreeSHAP Feature Attributions)

> [!NOTE]
> SHAP attributions quantify additive contributions relative to the background expectation.
> They do **NOT** prove causality in underlying network traffic.

| Rank | Feature Name | Mean Absolute SHAP Value |
| :---: | :--- | :---: |
| 1 | `packet_length_std` | 0.082255 |
| 2 | `packet_length_mean` | 0.072361 |
| 3 | `flow_packets_per_s` | 0.047601 |
| 4 | `flow_duration_ms` | 0.030396 |
| 5 | `flow_bytes_per_s` | 0.029694 |
| 6 | `ack_count` | 0.021818 |
| 7 | `fin_count` | 0.008594 |
| 8 | `syn_count` | 0.003620 |
| 9 | `syn_ack_ratio` | 0.002871 |
| 10 | `rst_count` | 0.000000 |

---
## 8. Failure Analysis & Model Disagreements

- **Aligned Evaluation Size**: 355,833 rows
- **RF vs LSTM Disagreements**: 7,717 (2.17%)
- **RF Positive, LSTM Negative**: 6404 (RF Correct: 2208, RF False Alarm: 4196)
- **LSTM Positive, RF Negative**: 1313 (LSTM Correct: 204, LSTM False Alarm: 1109)

---
## 9. Calibration & Threshold Analysis

- **Validation Platt Calibration Brier Score (RF)**: 0.016130861558673087
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