# XRL-IDARS — Phase 1 Final Consolidated Research Report

- **Platform**: XRL-IDARS (Intrusion Detection and Autonomous Response System)
- **Phase**: 1 (Empirical Research Platform & Explainability)
- **Git Commit**: `933a142a26b16c6e41421ace7dc07573786194eb`
- **Environment**: Python 3.14.4 · PyTorch 2.14.0+cpu · Scikit-Learn 1.9.1 · SHAP 0.52.0
- **Verified Test Suite**: 209 passing tests (0 failures)

---
## 1. Research Status Taxonomy

All claims and findings adhere strictly to four evidentiary tiers: `VERIFIED`, `EMPIRICALLY OBSERVED`, `DATA_NOT_AVAILABLE`, and `RESEARCH DECISION REQUIRED`.

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
| CSE-CIC-IDS2018 Multi-File Baseline Ladder | `EMPIRICALLY OBSERVED` | Executed across all 10 files (`EXP-P1-CSE2018-R10-MULTI-001`, RF acc 0.9723, F1 0.8861, ROC-AUC 0.9902) |
| UNSW-NB15 Multi-File Baseline Ladder | `EMPIRICALLY OBSERVED` | Executed across both files (`EXP-P1-UNSW-NATIVE-001`, native 4-feature RF acc 0.8588, F1 0.8546) |
| Per-Attack-Family Failure Analysis | `EMPIRICALLY OBSERVED` | Low-footprint failures exposed: Infiltration (10.70% recall on CSE-2018, 0% on CIC), Web Brute Force (15.89%), XSS (2.78%) |
| TreeSHAP Explainability | `EMPIRICALLY OBSERVED` | Evaluated on multi-file RF; top drivers `flow_duration_ms` / `packet_length_std` (CSE), `packet_length_std` (CIC) |
| Platt Probability Calibration | `EMPIRICALLY OBSERVED` | Evaluated on multi-file validation sets; Brier score reduced across all benchmark models |
| Paired Bootstrap Hypothesis Testing | `EMPIRICALLY OBSERVED` | Non-parametric paired bootstrap (B=1000) confirms statistically significant differences on aligned test sets |
| Supervised LSTM (All 3 Domains) | `EMPIRICALLY OBSERVED` | Validated on all multi-file populations: CIC-IDS2017 (acc 0.9867, F1 0.9633), CSE-CIC-IDS2018 (acc 0.9912, F1 0.9603), and UNSW-NB15 (acc 0.8683, F1 0.8637, p=0.0000) |
| RF + LSTM Score Fusion (All 3 Domains) | `EMPIRICALLY OBSERVED` | Validated across all benchmarks: CIC-IDS2017 (alpha=0.50, F1 0.9745), CSE-CIC-IDS2018 (alpha=0.00, F1 0.9603), and UNSW-NB15 (alpha=0.60, acc 0.8996, F1 0.8970, p=0.0000) |
| Multi-File UNSW-NB15 Benchmark | `EMPIRICALLY OBSERVED` | Full 2-file benchmark under 4-feature contract fallback (`EXP-P1-UNSWNB15-R10-MULTI-001`, Fusion acc 0.8996, F1 0.8970, ROC-AUC 0.9674) |
| Historical Single-Day CSE-CIC-IDS2018 Baselines | `HISTORICAL EVIDENCE (SINGLE-DAY RUNS ONLY)` | Evaluated on single day Thursday-01-03-2018 (`EXP-P1-CSE2018-R10-001`); superseded by full 10-file multi-day run |
| Multi-Seed Robustness Evaluation | `PARTIAL` | Runner supports multi-seed loop; full-dataset runs executed with seed 42 only |
| Cross-Dataset Transfer Evaluation | `EMPIRICALLY OBSERVED` | Evaluated across 6 transfer directions: Primary R10 (`CIC ↔ CSE`), Auxiliary R4 (`UNSW ↔ CIC`, `UNSW ↔ CSE`); severe domain collapse observed |
| Decision Gate D-002 (Feature Contract) | `FROZEN` | R10 frozen for CIC-IDS2017/CSE-CIC-IDS2018; 4-feature contract for cross-dataset transfer |
| Decision Gate D-003 (Threshold Objective) | `RESOLVED` | Two-tier contract: Research baseline tau=0.50, Operational policy tau_ops=0.40 / calibrated risk scoring |
| Decision Gate D-004 (Dataset Acquisition) | `RESOLVED` | All 20 canonical CSV files verified and audited |
| Decision Gate D-005 (Cross-Dataset Normalization) | `RESOLVED` | Strict source-only preprocessing fit (zero target data leakage) under frozen semantic contracts |
| Decision Gate D-006 (Flow Completion Policy) | `RESOLVED` | Option D: Hybrid flow completion policy (TCP FIN/RST completion, 120.0s idle timeout fallback) |
| Live Demonstration Foundation | `VERIFIED` | Pure-Python streaming PCAP replay, FlowBuilder, R10 feature parity (atol <= 1e-4), and safe observational monitor |

> [!NOTE]
> **Aligned Population Accounting**: Direct baseline ladder comparisons and paired statistical hypothesis tests are evaluated exclusively on identical aligned test sets. The boundary discrepancy between tabular and sequence test sets (32 rows dropped in CIC-IDS2017, 40 rows dropped in CSE-CIC-IDS2018, 8 rows dropped in UNSW-NB15) is mathematically proven by file-boundary isolation: $T - 1 = 4$ context steps cannot cross disjoint capture file boundaries ($N_{files} \times 4$ dropped rows).

---
## 2. Answers to Core Research Questions

### RQ1: Can flow-level ML distinguish benign and malicious traffic?
> **Answer**: **Demonstrated on In-Domain Baseline Ladders across CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 (with Critical Caveats)**.
> On macroscopic high-volume attacks (DoS, DDoS, PortScan, Brute Force), flow-level behavioral features provide strong discrimination:
> - On **CIC-IDS2017** (all 8 files, 355,833 aligned test rows), Random Forest achieves **0.9815 Test Accuracy**, **0.9512 F1**, and **0.9968 ROC-AUC**.
> - On **CSE-CIC-IDS2018** (all 10 files, 1,662,419 aligned test rows), Random Forest achieves **0.9723 Test Accuracy**, **0.8861 F1**, and **0.9902 ROC-AUC**.
> - On **UNSW-NB15** (both files, 24,496 aligned test rows, 4 native flow features), Random Forest achieves **0.8590 Test Accuracy**, **0.8548 F1**, and **0.9487 ROC-AUC**.
>
> **Crucial Negative Finding**: Aggregate metrics mask severe blindspots on stealthy low-footprint attacks. In CSE-CIC-IDS2018, Random Forest exhibits an **89.30% error rate on Infiltration** (10.70% recall, 6,275 missed attacks out of 7,027). In CIC-IDS2017, Random Forest exhibits an **84.11% error rate on Web Attack - Brute Force** (15.89% recall) and a **97.22% error rate on Web Attack - XSS** (2.78% recall). In UNSW-NB15, Random Forest exhibits a **22.33% error rate on Analysis** (77.67% recall), a **21.02% error rate on Fuzzers** (78.98% recall), and a **15.66% error rate on Backdoor** (84.34% recall). Coarse flow statistics cannot reliably separate stealthy payload attacks from benign browsing.

### RQ2: Does temporal sequence information improve detection?
> **Answer**: **Demonstrated Across All Three Multi-File Benchmarks**.
> On all three full multi-file datasets, Supervised Sequence LSTM ($T=5$, stride=1, file-bounded sequence isolation) demonstrates statistically significant superiority over Random Forest:
> - On **CSE-CIC-IDS2018** (all 10 files, 1,662,419 aligned test rows):
>   - **Test Accuracy**: **0.9912** (vs RF 0.9723)
>   - **Test F1**: **0.9603** (vs RF 0.8861), with paired bootstrap confirming statistical significance ($\text{LSTM} - \text{RF} = +0.0743$, $\text{RF} - \text{LSTM} = -0.0743$, 95% CI $[-0.0752, -0.0734]$, $p = 0.0000$)
>   - **False Positive Rate**: **0.0026** (3,792 false alarms) vs RF 0.0259 (38,238 false alarms), achieving a **10x reduction in false alarm rate** on benign traffic.
>   - **ROC-AUC**: **0.9966** (vs RF 0.9902); **PR-AUC**: **0.9865** (vs RF 0.9676).
> - On **CIC-IDS2017** (all 8 files, 355,833 aligned test rows):
>   - **Test Accuracy**: **0.9867** (vs RF 0.9815)
>   - **Test F1**: **0.9633** (vs RF 0.9512), with paired bootstrap confirming statistical significance ($\text{LSTM} - \text{RF} = +0.0121$, $\text{RF} - \text{LSTM} = -0.0121$, 95% CI $[-0.0134, -0.0109]$, $p = 0.0000$)
>   - **False Positive Rate**: **0.0068** (1,982 false alarms) vs RF 0.0204 (5,951 false alarms), achieving a **66.7% reduction in false alarm rate**.
> - On **UNSW-NB15** (both files, 24,496 aligned test rows, 4 native flow features):
>   - **Test Accuracy**: **0.8683** (vs RF 0.8590)
>   - **Test F1**: **0.8637** (vs RF 0.8548), with paired bootstrap confirming statistical significance ($\text{LSTM} - \text{RF} = +0.0089$, $\text{RF} - \text{LSTM} = -0.0089$, 95% CI $[-0.0143, -0.0042]$, $p = 0.0000$)
>   - **False Positive Rate**: **0.1796** (2,419 false alarms) vs RF 0.1928 (2,597 false alarms).
>   - **ROC-AUC**: **0.9334**; **PR-AUC**: **0.8903**.
>
> **Methodological Limitation & Scope Boundaries**:
> 1. *Capture Arrival Order vs. Physical Packet Timeline*: CSV row arrival order within capture files reflects flow exporter buffer arrival order rather than continuous physical packet timestamps. Sequence models evaluate flow-to-flow context dynamics rather than millisecond packet-level transitions.
> 2. *Stealthy Attack Blindspots*: Temporal context does *not* overcome the lack of packet payload inspection. For low-footprint application-layer attacks, stealthy single-flow attacks remain undetectable without payload visibility.

### RQ3: Does RF + LSTM score fusion improve over individual models?
> **Answer**: **Demonstrated on Multi-File Benchmarks Across All Three Domains**.
> - On **CIC-IDS2017** (355,833 aligned test rows), score fusion ($S_{\text{fusion}} = 0.50 S_{\text{RF}} + 0.50 S_{\text{LSTM}}$) delivers statistically significant F1 improvements over RF ($\Delta = +0.0234$, $p=0.0000$) and LSTM ($\Delta = +0.0113$, $p=0.0000$), achieving **0.9906 Accuracy**, **0.9745 F1**, **0.9989 ROC-AUC**, and rescuing 78.72% of model disagreement samples with 0 dual-correct degradations.
> - On **CSE-CIC-IDS2018** (1,662,419 aligned test rows), validation tuning yields $\alpha=0.00$, where Fusion directly adopts the superior sequence decision boundary of the LSTM (which achieved 0.9603 F1 and 0.0026 FPR compared to RF's 0.8861 F1 and 0.0259 FPR).
> - On **UNSW-NB15** (24,496 aligned test rows), validation tuning yields $\alpha=0.60$, where Score Fusion ($S_{\text{fusion}} = 0.60 S_{\text{RF}} + 0.40 S_{\text{LSTM}}$) delivers statistically significant F1 improvements over both Random Forest ($\Delta = +0.0421$, 95% CI $[+0.0389, +0.0457]$, $p = 0.0000$) and LSTM ($\Delta = +0.0332$, 95% CI $[+0.0295, +0.0367]$, $p = 0.0000$), achieving **0.8996 Accuracy**, **0.8970 F1**, **0.9674 ROC-AUC**, and rescuing 538 false negatives ($857 \to 319$).
>
> **Scope & Unresolved Vulnerabilities**: Fusion succeeds where complementary trade-offs exist (RF high recall + LSTM false-positive suppression). When one model dominates across all operating points or both fail on payload-hidden attacks, fusion cannot fabricate unobserved signals.

### RQ4: How does feature quantity affect performance?
> **Answer**: **Demonstrated Across Evaluated Contracts**.
> On CIC-IDS2017 and CSE-CIC-IDS2018, the 10-feature in-domain contract (R10) provides comprehensive behavioral flow coverage with identical semantic mappings and units. On UNSW-NB15, only 4 genuine flow features are supported natively (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`). Missing TCP flag and IAT features cannot be fabricated. Models trained on the 4-feature contract achieve viable baseline performance (0.8590 accuracy on UNSW-NB15), but lack flag-based state transition discrimination.

### RQ5: How well does the detector transfer between datasets?
> **Answer**: **Empirically Observed Across All 6 Transfer Directions (Severe Domain Degradation Demonstrated)**.
> Cross-dataset transfer was rigorously evaluated under strict scientific isolation:
> - Scalers were fitted strictly on source training partitions; models were frozen without target fine-tuning.
> - Fusion weight $\alpha$ was selected using source validation data; decision threshold 0.50 was FIXED as the neutral baseline; target data was never used to tune either parameter.
>
> 1. **Primary 10-Feature Contract (`CIC-IDS2017 ↔ CSE-CIC-IDS2018`)**:
>    - `CIC → CSE`: Random Forest F1 degrades from 0.9512 to **0.3286** ($\Delta = -0.6225$, ROC-AUC 0.7008), while Supervised LSTM collapses from 0.9633 to **0.0983** ($\Delta = -0.8650$, ROC-AUC 0.4787), and Fusion yields **0.1139** ($\Delta = -0.8606$, ROC-AUC 0.6604). Tabular Random Forest exhibits significantly higher out-of-domain ranking discriminability than sequence LSTM. A plausible explanation is that axis-aligned decision tree splits may tolerate monotonic scale shifts better than recurrent hidden states conditioned on fine-grained packet inter-arrival dynamics; however, this interpretation is not directly established by the transfer experiment itself.
>    - `CSE → CIC`: Random Forest F1 degrades from 0.8861 to **0.0301** ($\Delta = -0.8560$, ROC-AUC 0.7127), while Supervised LSTM yields **0.2601** ($\Delta = -0.7003$, ROC-AUC 0.8052), and Fusion yields **0.1191** ($\Delta = -0.8412$, ROC-AUC 0.8099). Directional transfer asymmetry confirms that source dataset traffic diversity and sample distributions govern cross-domain discrimination.
> 2. **Auxiliary 4-Feature Transfers Involving UNSW-NB15**:
>    - *Provenance*: For transfers to UNSW (`CIC → UNSW` and `CSE → UNSW`), source reference models were trained and evaluated strictly under the 4-feature (R4) contract rather than reusing R10 models.
>    - `UNSW → CIC`: RF F1 = 0.3276 (FPR 68.58%), LSTM F1 = 0.3389 (FPR 31.78%), Fusion F1 = 0.3664 (FPR 53.94%). Elevated false alarm rates on benign traffic may be consistent with flow exporter discrepancies (e.g., Bro/Zeek vs CICFlowMeter flow timeouts), though exporter effects were not independently isolated.
>    - `UNSW → CSE`: RF F1 = 0.0217 (FPR 64.73%), LSTM F1 = 0.0380 (FPR 50.74%), Fusion F1 = 0.0268.
>    - `CIC → UNSW` & `CSE → UNSW`: Both models collapse (F1 < 0.005). Plausible contributing factors include extreme class prevalence differences (UNSW ~45% attack vs CIC/CSE ~11–18%) and synthetic attack generation characteristics.
> 3. **Covariate Shift**: Two-sample Kolmogorov-Smirnov tests confirm statistically significant distribution shift ($p = 0.0000$). The largest KS statistics occur in UNSW-involving transfers (reaching $D \approx 0.57$), whereas CIC ↔ CSE primary R10 transfers exhibit maximum $D \approx 0.29$.
>
> **Core Scientific Conclusion**: High in-domain benchmark performance (>0.96–0.99 F1) does **not** transfer across network domains without domain adaptation. Autonomous response systems (Phase 2/3) must incorporate uncertainty quantification and continuous adaptation rather than assuming universal detector transferability.

### RQ6: Which features drive predictions according to TreeSHAP?
> **Answer**: **Empirically Observed on Multi-File Random Forest Models**.
> - On **CSE-CIC-IDS2018 (R10)**, TreeSHAP identifies `flow_duration_ms` (mean |SHAP| = 0.0488), `packet_length_std` (0.0480), and `packet_length_mean` (0.0417) as top associative drivers.
> - On **CIC-IDS2017 (R10)**, TreeSHAP identifies `packet_length_std` (0.0943), `packet_length_mean` (0.0873), and `flow_packets_per_s` (0.0479) as top drivers.
> - On **UNSW-NB15 (4 features)**, TreeSHAP identifies `flow_packets_per_s` (0.2216) and `packet_length_mean` (0.1022) as top drivers.
>
> **Scientific Causality Boundary**: TreeSHAP values quantify conditional mathematical contrast relative to the dataset background expectation. They do **not** prove physical causality in underlying network traffic.

---
## 3. Formal Research Decisions Status

1. **Decision D-001 (Normalization & Cleaning Contract)**:
   - **Status**: **RESOLVED**. Canonical column normalization with preserved raw provenance, NFKC unicode normalization, and strict rejection of unmapped labels without relabeling.
2. **Decision D-002 (Primary Feature Rung Freeze)**:
   - **Status**: **FROZEN**. R10 frozen as Main Cross-Dataset 10-Feature Contract for CIC-IDS2017 and CSE-CIC-IDS2018; 4-feature contract established for cross-dataset transfer with UNSW-NB15.
3. **Decision D-003 (Threshold Selection Objective)**:
   - **Status**: **RESOLVED (TWO-TIER THRESHOLD CONTRACT)**. Preserves neutral threshold $\tau=0.50$ for academic literature comparison. Establishes cost-sensitive operational policy $\tau_{\text{ops}}=0.40$ or continuous calibrated risk scoring $P(\text{attack} \mid x, s)$ for Phase 2 autonomous response under asymmetric operational loss ($C_{\text{FN}} \ge 5 \cdot C_{\text{FP}}$).
4. **Decision D-004 (Dataset Acquisition)**:
   - **Status**: **RESOLVED**. All 20 physical CSV files acquired, verified against canonical manifest, and audited.
5. **Decision D-005 (Cross-Dataset Normalisation)**:
   - **Status**: **RESOLVED**. Strict source-only preprocessing fit (zero target data leakage) under frozen semantic contracts (R10 for CIC ↔ CSE, R4 for UNSW).
6. **Decision D-006 (Flow Completion Policy)**:
   - **Status**: **RESOLVED**. Option D (Hybrid flow completion policy: TCP FIN/RST completion, 120.0s idle timeout fallback).

---
## 4. Phase 1 Freeze & Transition to Phase 2

> Phase 1 research programme is formally **FROZEN**. The reproducible live demonstration foundation, pure-Python streaming packet capture replay, bidirectional flow construction, and strict numerical feature parity ($\text{atol} \le 10^{-4}$) are implemented and verified.
> Next execution: Phase 2 — Explainable Autonomous Response with Reinforcement Learning (DQN, continuous state spaces, action execution safety contracts, and operational cost policies).
