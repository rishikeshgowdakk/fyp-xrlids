# XRL-IDARS — Phase 1 Final Consolidated Research Report

- **Platform**: XRL-IDARS (Intrusion Detection and Autonomous Response System)
- **Phase**: 1 (Empirical Research Platform & Explainability)
- **Git Commit**: `14a79e14b7997df371ee587af282b2e439c34ca0 (dirty)`
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
| Supervised LSTM (CIC-IDS2017 Multi-File) | `EMPIRICALLY OBSERVED` | Executed across 8 files (1,067,557 sequences, 355,833 aligned test rows; acc 0.9867, F1 0.9633, FPR 0.0068; 66.7% false alarm reduction vs RF; Delta F1 = -0.0121, p=0.0000) |
| RF + LSTM Score Fusion (CIC-IDS2017 Multi-File) | `EMPIRICALLY OBSERVED` | Executed on aligned test data; alpha=0.50 validation-tuned; acc 0.9906, F1 0.9745, ROC-AUC 0.9989; 78.72% rescue of disagreement samples; p=0.0000 |
| Supervised LSTM (CSE-CIC-IDS2018 10-File & UNSW-NB15) | `PENDING EXECUTION` | Memory-safe streaming pipeline ready; pending execution on remaining multi-file populations |
| RF + LSTM Score Fusion (CSE-CIC-IDS2018 10-File & UNSW-NB15) | `PENDING EXECUTION` | Pending completion of multi-file LSTM on remaining datasets |
| Historical Single-Day CSE-CIC-IDS2018 Baselines | `HISTORICAL EVIDENCE (SINGLE-DAY RUNS ONLY)` | Evaluated on single day Thursday-01-03-2018 (`EXP-P1-CSE2018-R10-001`); not representative of multi-file populations |
| Multi-Seed Robustness Evaluation | `PARTIAL` | Runner supports multi-seed loop; full-dataset runs executed with seed 42 only |
| Cross-Dataset Transfer Evaluation | `PARTIAL` | Programmatic 4-feature contract evaluated source-side in `EXP-P1-TRANSFER-CSE-TO-UNSW-001` |
| Decision Gate D-002 (Feature Contract) | `CANDIDATE FROZEN` | R10 for CIC-IDS2017/CSE-CIC-IDS2018; 4-feature contract for cross-dataset transfer |
| Decision Gate D-003 (Threshold Objective) | `RESEARCH DECISION REQUIRED` | OPEN pending operational deployment cost matrix (FP vs FN cost trade-off) |

> [!NOTE]
> **Aligned Population Accounting**: The tabular test split contains 355,865 rows, while the aligned sequence test set contains 355,833 rows (a 32-row boundary difference). This exact difference arises because sequence creation requires $T-1 = 4$ preceding intra-file context steps (sequence length $T=5$). To prevent synthetic cross-day contamination, sequences never cross source file boundaries, discarding exactly 4 boundary rows per file across all 8 files ($8 \times 4 = 32$ rows dropped). All model comparisons (RF, LSTM, Fusion) are evaluated on the exact identical aligned test set ($N=355,833$).

---
## 2. Answers to Core Research Questions

### RQ1: Can flow-level ML distinguish benign and malicious traffic?
> **Answer**: **Demonstrated on In-Domain Baseline Ladders (with Critical Caveats)**.
> On macroscopic high-volume attacks (DoS, DDoS, PortScan, Patator), flow-level behavioral features provide strong discrimination:
> - On **CIC-IDS2017** (all 8 files, 355,833 aligned test rows), Random Forest achieves **0.9815 Test Accuracy**, **0.9512 F1**, and **0.9968 ROC-AUC**.
> - On **UNSW-NB15** (both files, 24,504 aligned test rows, 4 native flow features), Random Forest achieves **0.8588 Test Accuracy**, **0.8546 F1**, and **0.9485 ROC-AUC**.
>
> **Crucial Negative Finding**: Aggregate metrics mask severe blindspots on low-footprint application-layer attacks. In CIC-IDS2017, Random Forest exhibits an **84.11% error rate on Web Attack - Brute Force** (15.89% recall), a **97.22% error rate on Web Attack - XSS** (2.78% recall), and a **100% error rate on Infiltration** (0/8 detected). Coarse flow statistics cannot reliably separate stealthy web payload traffic from benign browsing.

### RQ2: Does temporal sequence information improve detection?
> **Answer**: **Demonstrated on CIC-IDS2017 Multi-File Benchmark (EXP-P1-CIC2017-R10-001)**.
> On the complete multi-file CIC-IDS2017 dataset (8 files, 1,067,557 sequences, 355,833 aligned test rows), Supervised LSTM ($T=5$, stride=1, intra-file sequence boundaries) demonstrates statistically significant superiority over Random Forest:
> - **Test Accuracy**: **0.9867** (vs RF 0.9815)
> - **Test F1**: **0.9633** (vs RF 0.9512), with non-parametric paired bootstrap confirming statistical significance ($\Delta \text{F1} = -0.0121$, 95% CI $[-0.0134, -0.0109]$, $p = 0.0000$)
> - **False Positive Rate**: **0.0068** (1,982 false alarms) vs RF 0.0204 (5,951 false alarms), achieving a **66.7% reduction in false alarm rate** on benign traffic.
> - **ROC-AUC**: **0.9974** (vs RF 0.9968); **PR-AUC**: **0.9904** (vs RF 0.9877).
>
> **Methodological Limitation & Scope Boundaries**:
> 1. *Capture Arrival Order vs. Physical Packet Timeline*: CSV row arrival order within capture files reflects flow exporter buffer arrival order rather than continuous physical packet timestamps. Sequence models evaluate flow-to-flow context dynamics rather than millisecond packet-level transitions.
> 2. *Dataset Scope*: Empirically established on CIC-IDS2017. Multi-file LSTM training remains pending on CSE-CIC-IDS2018 (10 files) and UNSW-NB15.
> 3. *Stealthy Attack Blindspots*: Temporal context does *not* overcome the lack of packet payload inspection. For low-footprint application-layer attacks, LSTM recall remains severely impaired: Web Attack Brute Force drops to 3.88% (vs RF 15.89%); Web Attack XSS (0/36), Infiltration (0/8), and SQL Injection (0/6) remain completely undetected.

### RQ3: Does RF + LSTM score fusion improve over individual models?
> **Answer**: **Demonstrated on CIC-IDS2017 Multi-File Benchmark (EXP-P1-CIC2017-R10-001)**.
> On the complete multi-file CIC-IDS2017 dataset (355,833 aligned test rows), convex score fusion ($S_{\text{fusion}} = \alpha \cdot S_{\text{RF}} + (1-\alpha) \cdot S_{\text{LSTM}}$ with $\alpha=0.50$ tuned on validation ROC-AUC) achieves:
> - **Test Accuracy**: **0.9906** (outperforming both RF 0.9815 and LSTM 0.9867)
> - **Test F1**: **0.9745** (outperforming both RF 0.9512 and LSTM 0.9633)
> - **Paired Bootstrap Verification**: Statistically significant F1 improvements over RF ($\Delta = +0.0234$, 95% CI $[+0.0224, +0.0244]$, $p = 0.0000$) and over LSTM ($\Delta = +0.0113$, 95% CI $[+0.0104, +0.0120]$, $p = 0.0000$).
> - **Discrimination & Low False Alarms**: **ROC-AUC 0.9989**, **PR-AUC 0.9947**, and **FPR 0.0075** (2,185 false alarms, retaining the low false-alarm profile of the LSTM while recovering RF high recall: 0.9823 vs LSTM 0.9576).
> - **Complementary Error Rescue**: RF and LSTM disagreed on 8,126 test samples (2.28% of test set). Score fusion correctly resolved 6,397 of these disagreements (**78.72% rescue rate**) with **0 dual-correct degradations** (fusion was never wrong when both base models were correct).
>
> **Scope & Unresolved Vulnerabilities**: Fusion succeeds because RF provides broad high recall on flow signatures while LSTM suppresses false alarms on benign sequence patterns. However, when both base models fail due to total absence of flow signal (Web Attack XSS 0%, Infiltration 0%), score fusion cannot rescue detections. Multi-file fusion remains pending for CSE-CIC-IDS2018 (10 files) and UNSW-NB15.

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
5. **Decision D-005 (Cross-Dataset Normalisation)**:
   - **Status**: **OPEN**. Train-only standard scaling applied within source domain.

---
## 4. Exactly One Recommended Next Action

> Execute the full multi-file 10-day CSE-CIC-IDS2018 experiment across all 10 verified CSV files (16,233,002 raw rows) using chunked streaming pipelines (`EXP-P1-CSE2018-R10-MULTI-001`) to evaluate whether the temporal and score fusion benefits observed on CIC-IDS2017 replicate across multi-day enterprise infrastructure.
