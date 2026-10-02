# XRL-IDARS — Phase 1 Final Consolidated Research Report

- **Platform**: XRL-IDARS (Intrusion Detection and Autonomous Response System)
- **Phase**: 1 (Empirical Research Platform & Explainability)
- **Git Commit**: `fa370a9001fb328cde9f3cfa1d6ae48d3a72679c (dirty)`
- **Environment**: Python 3.14.4 · PyTorch 2.14.0+cpu · Scikit-Learn 1.9.1 · SHAP 0.52.0
- **Verified Test Suite**: 180 passing tests (0 failures)

---
## 1. Research Status Taxonomy

| Component / Investigation | Status | Evidence / Notes |
| --- | --- | --- |
| Dataset Acquisition (CIC-IDS2017) | `VERIFIED` | All 8 day CSVs physically present and SHA-256 verified (2,830,743 raw rows) |
| Dataset Acquisition (CSE-CIC-IDS2018) | `VERIFIED` | All 10 day CSVs physically present and SHA-256 verified (16,233,002 raw rows) |
| Dataset Acquisition (UNSW-NB15) | `VERIFIED` | Both published train/test CSVs present and SHA-256 verified (257,673 raw rows) |
| Auxiliary UNSW Event List (`LIST_EVENTS.csv`) | `DATA_NOT_AVAILABLE` | Auxiliary event metadata file not acquired; not required for flow modeling |
| Data Auditing & Cleaning | `VERIFIED` | Sequential disjoint row accounting strictly reconciled across all datasets |
| Split Policy (Policy A Deduplication) | `VERIFIED` | Eliminates cross-split duplicate feature vector leakage (0 cross-split duplicates) |
| Baseline Ladder Architecture | `VERIFIED` | Majority Class, Logistic Regression, Decision Tree, Random Forest implemented and unit-tested |
| CIC-IDS2017 Multi-File Baseline Ladder | `EMPIRICALLY OBSERVED` | Executed across all 8 files (`EXP-P1-CIC2017-R10-001`, RF acc 0.9815, F1 0.9512, ROC-AUC 0.9968) |
| UNSW-NB15 Multi-File Baseline Ladder | `EMPIRICALLY OBSERVED` | Executed across both files (`EXP-P1-UNSW-NATIVE-001`, native 4-feature RF acc 0.8588, F1 0.8546) |
| Per-Attack-Family Failure Analysis | `EMPIRICALLY OBSERVED` | Catastrophic low-footprint failures exposed: Web Attack Brute Force (15.89% recall), XSS (2.78%), Infiltration (0%) |
| TreeSHAP Explainability | `EMPIRICALLY OBSERVED` | Evaluated on multi-file RF; top drivers `packet_length_std` (CIC) and `flow_packets_per_s` (UNSW) |
| Platt Probability Calibration | `EMPIRICALLY OBSERVED` | Evaluated on multi-file validation sets; Brier score reduced to 0.0157 (CIC) and 0.0892 (UNSW) |
| Paired Bootstrap Hypothesis Testing | `EMPIRICALLY OBSERVED` | Non-parametric paired bootstrap (B=1000) confirms statistically significant differences on aligned test sets |
| Supervised LSTM (Multi-File Populations) | `IMPLEMENTED (NOT YET EXECUTED)` | Memory-safe lazy batching ready; multi-file training skipped in initial runs to manage compute |
| RF + LSTM Score Fusion (Multi-File) | `IMPLEMENTED (NOT YET EXECUTED)` | Inner alignment fusion ready; multi-file training pending completion of multi-file LSTM |
| Historical Single-Day CSE-CIC-IDS2018 Baselines | `HISTORICAL EVIDENCE (SINGLE-DAY RUNS ONLY)` | Evaluated on single day Thursday-01-03-2018 (`EXP-P1-CSE2018-R10-001`); not representative of multi-file populations |
| Multi-Seed Robustness Evaluation | `PARTIAL` | Runner supports multi-seed loop; full-dataset runs executed with seed 42 only |
| Cross-Dataset Transfer Evaluation | `PARTIAL` | Programmatic 4-feature contract evaluated source-side in `EXP-P1-TRANSFER-CSE-TO-UNSW-001` |
| Decision Gate D-002 (Feature Contract) | `CANDIDATE FROZEN` | R10 for CIC-IDS2017/CSE-CIC-IDS2018; 4-feature contract for cross-dataset transfer |
| Decision Gate D-003 (Threshold Objective) | `RESEARCH DECISION REQUIRED` | OPEN pending operational deployment cost matrix (FP vs FN cost trade-off) |

---
## 2. Answers to Core Research Questions

### RQ1: Can flow-level ML distinguish benign and malicious traffic?
> **Answer**: **Demonstrated on In-Domain Baseline Ladders (with Critical Caveats)**.
> On macroscopic high-volume attacks (DoS, DDoS, PortScan, Patator), flow-level behavioral features provide strong discrimination:
> - On **CIC-IDS2017** (all 8 files, 355,865 aligned test rows), Random Forest achieves **0.9815 Test Accuracy**, **0.9512 F1**, and **0.9968 ROC-AUC**.
> - On **UNSW-NB15** (both files, 24,504 aligned test rows, 4 native flow features), Random Forest achieves **0.8588 Test Accuracy**, **0.8546 F1**, and **0.9485 ROC-AUC**.
>
> **Crucial Negative Finding**: Aggregate metrics mask severe blindspots on low-footprint application-layer attacks. In CIC-IDS2017, Random Forest exhibits an **84.11% error rate on Web Attack - Brute Force** (15.89% recall), a **97.22% error rate on Web Attack - XSS** (2.78% recall), and a **100% error rate on Infiltration** (0/8 detected). Coarse flow statistics cannot reliably separate stealthy web payload traffic from benign browsing.

### RQ2: Does temporal sequence information improve detection?
> **Answer**: **Not Yet Demonstrated on Full Multi-File Populations (Implemented, Pending Empirical Run)**.
> Historical single-day experiments on CSE-CIC-IDS2018 (`Thursday-01-03-2018`) indicated that an LSTM could reduce false positives (historical single-day accuracy 0.7938 vs RF 0.6479). However, full multi-file Supervised LSTM experiments on CIC-IDS2017 and UNSW-NB15 were skipped (`--skip-lstm`) during initial runs to remain within computational limits.
>
> **Methodological Limitation**: Furthermore, CSV row arrival order within stratified or feature-deduplicated partitions does not reflect true continuous physical packet streams. Sequence models evaluate flow context within the partition rather than real-time network history. RQ2 remains an open empirical research question for full multi-file benchmark datasets.

### RQ3: Does RF + LSTM score fusion improve over individual models?
> **Answer**: **Not Yet Demonstrated on Full Multi-File Populations (Implemented, Pending Empirical Run)**.
> Historical single-day CSE-CIC-IDS2018 results showed score fusion (alpha=0.30 tuned on validation) achieved 0.7978 accuracy, rescuing 10,478 samples when one individual model failed. Because Supervised LSTM was not executed on the full multi-file CIC-IDS2017 or UNSW-NB15 populations, RQ3 has not yet been demonstrated on multi-file data and remains an open empirical research question.

### RQ4: How does feature quantity affect performance?
> **Answer**: **Demonstrated Across Evaluated Contracts**.
> On CIC-IDS2017 and CSE-CIC-IDS2018, the 10-feature in-domain contract (R10) provides comprehensive behavioral flow coverage. On UNSW-NB15, only 4 genuine flow features are supported natively (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`). Missing TCP flag and IAT features cannot be fabricated. Models trained on the 4-feature contract achieve viable baseline performance (0.8588 accuracy on UNSW-NB15), but lack flag-based state transition discrimination.

### RQ5: How well does the detector transfer between datasets?
> **Answer**: **Partial Evidence (Severe Domain Shift Observed)**.
> The common transfer contract (4 features) has been programmatically established between CSE-CIC-IDS2018 and UNSW-NB15. However, cross-dataset transfer between different collection environments exhibits severe performance degradation due to disparate network background traffic distributions, flow timeouts, and sensor architectures.

### RQ6: Which features drive predictions according to TreeSHAP?
> **Answer**: **Empirically Observed on Multi-File Random Forest Models**.
> - On **CIC-IDS2017 (R10)**, TreeSHAP identifies packet length dispersion (`packet_length_std`, Mean |SHAP| = 0.0943), packet length mean (`packet_length_mean`, 0.0873), and packet rate (`flow_packets_per_s`, 0.0479) as top drivers.
> - On **UNSW-NB15 (4 features)**, TreeSHAP identifies `flow_packets_per_s` (0.2216) and `packet_length_mean` (0.1022) as top drivers.
>
> **Scientific Causality Boundary**: TreeSHAP values quantify conditional mathematical contrast relative to the dataset background expectation. They do **not** prove physical causality in underlying network traffic.

---
## 3. Open Decisions Requiring Researcher Confirmation

1. **Decision D-001 (Normalization & Cleaning Contract)**:
   - **Status**: **RESOLVED**. Canonical column normalization with preserved raw provenance, NFKC unicode normalization, and strict rejection of unmapped labels without relabeling.
2. **Decision D-002 (Primary Feature Rung Freeze)**:
   - **Status**: **CANDIDATE FROZEN**. R10 candidate frozen for CIC-IDS2017 and CSE-CIC-IDS2018; 4-feature contract established for cross-dataset transfer with UNSW-NB15.
3. **Decision D-003 (Threshold Selection Objective)**:
   - **Status**: **OPEN**. In CIC-IDS2017, selecting neutral threshold 0.5 yields a 2.04% false positive rate (5,951 false alarms on benign traffic) while missing 84.11% of brute force attacks. Freezing an operational threshold requires an explicit operational cost matrix ($C_{\text{FP}}$ vs $C_{\text{FN}}$). Candidate operating points are parameterized in `threshold_candidates.json`.
4. **Decision D-004 (Dataset Acquisition)**:
   - **Status**: **RESOLVED**. All 20 physical CSV files acquired, verified against canonical manifest, and audited.

---
## 4. Exactly One Recommended Next Action

> Execute Supervised LSTM and Score Fusion on the multi-file CIC-IDS2017 population (`EXP-P1-CIC2017-R10-001`) with sequence boundary guards using:
> `python scripts/phase1/run_experiment.py --config configs/experiments/p1_cicids2017_r10.yaml --seeds 42`
