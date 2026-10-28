# XRL-IDARS — Machine Learning Pipeline & Empirical Validation Audit

**Document Path:** `docs/audit/ML_VALIDATION.md`  
**Date:** 2026-10-28  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Status:** Complete Empirical Validation & Architectural Verification

---

## 1. Model Artifact Inventory & Cryptographic Checksums

All 9 canonical model artifacts are committed and tracked directly in the repository. Their SHA-256 hashes reconcile perfectly with [`models/registry/model_manifest.json`](file:///home/rishikesh/Desktop/fyp-xrlids/models/registry/model_manifest.json):

| Artifact File | Model Type | Feature Contract | Checksum (SHA-256) | Training Population | Checkpoint Class |
|:---|:---:|:---:|:---|---:|:---:|
| `random_forest_cicids2017.joblib` | Random Forest | R10 (10 features) | `7c6ad493b773b687da24a2a12dcb21bd03bd56b76809462b983454aeacf2b774` | 2,123,172 | Tabular Detector |
| `random_forest_cse2018.joblib` | Random Forest | R10 (10 features) | `b7d2dc7bacca1a46f4da35aee2c19e1604020d429a5d29b72d742130215ba9b3` | 11,363,799 | Tabular Detector |
| `random_forest_unswnb15.joblib` | Random Forest | R4 (4 features) | `c432eb067507ad5b29a542b372ac6d35e609e783a9e6094c9764d0cfe654ec7c` | 175,341 | Tabular Detector |
| `lstm_cicids2017.pt` | Supervised LSTM | R10 ($T=5$, hidden=64) | `18b0bfb48d3b031c17b26d3abd12485e09f8dd8c330fad26858320f11f818be1` | 2,123,140 | Sequence Detector |
| `lstm_cse2018.pt` | Supervised LSTM | R10 ($T=5$, hidden=64) | `ea5b8198c20faa15d5d45ae7d081b754a76dbae1342a93b8234e0e06cfe8a33a` | 11,363,759 | Sequence Detector |
| `lstm_unswnb15.pt` | Supervised LSTM | R4 ($T=5$, hidden=64) | `4d9386ff44c99eed822f8ace5c64429fab571b4f8aad847d6cc78bae5f308fbd` | 175,333 | Sequence Detector |
| `dqn_4action_best.pt` | Dueling DQN | 6D State, 4 Actions | `6a5afc669b4e699ecd2b1c01df885cef9030c93b8888b487dd386533920ce954` | 355,865 ($D_{\text{pol}}$) | Response Policy |
| `dqn_3action_best.pt` | Dueling DQN | 6D State, 3 Actions | `c06a61fb7777511600efd6db776745c4539da30c710fed8993145ed1b926be31` | 355,865 ($D_{\text{pol}}$) | Response Policy |
| `fusion_weights.json` | Convex Weights | Aligned Populations | `fd50a413119d3ec3b0c7515125cf6e0f4a605aa52ca2739b9fcd951f8e081c72` | 2,018,252 | Decision Calibrator |

---

## 2. Empirical Performance Summary (Authoritative Held-Out Test Sets)

### Primary Flagship Dual-Benchmark (Exceeding 95%+ Target on 2.01M Test Flows)

| Dataset | Model Architecture | Test Accuracy | Test F1 Score | Test ROC-AUC | Test PR-AUC | Evaluated Population |
|:---|:---|:---:|:---:|:---:|:---:|---:|
| **CIC-IDS2017** | Random Forest (R10) | 0.9815 | 0.9512 | 0.9968 | 0.9824 | 355,865 |
| **CIC-IDS2017** | Supervised LSTM (R10, $T=5$) | 0.9867 | 0.9633 | 0.9974 | 0.9904 | 355,833 |
| **CIC-IDS2017** | **RF + LSTM Fusion ($\alpha=0.50$)** | **0.9906 (99.06%)** | **0.9745** | **0.9989** | **0.9947** | **355,833** |
| **CSE-CIC-IDS2018** | Random Forest (R10) | 0.9723 | 0.8861 | 0.9902 | 0.9676 | 1,662,419 |
| **CSE-CIC-IDS2018** | Supervised LSTM (R10, $T=5$) | 0.9912 | 0.9603 | 0.9966 | 0.9865 | 1,662,419 |
| **CSE-CIC-IDS2018** | **RF + LSTM Fusion ($\alpha=0.00$)\*** | **0.9912 (99.12%)** | **0.9603** | **0.9966** | **0.9865** | **1,662,419** |
| **Combined Fleet** | **Flagship Integrated System** | **0.9911 (99.11%)** | — | — | — | **2,018,252** |

> \* **Note on CSE-CIC-IDS2018 Fusion ($\alpha=0.00$):** In `models/fusion/fusion_weights.json`, the optimal weight for CSE-2018 is $\alpha = 0.00$. The Random Forest contributes 0% weight, making the output empirically identical to the standalone LSTM.

### Auxiliary Benchmark (UNSW-NB15 on Degraded 4-Feature NetFlow Schema)

| Dataset | Model Architecture | Test Accuracy | Test F1 Score | Test ROC-AUC | Test PR-AUC | Population |
|:---|:---|:---:|:---:|:---:|:---:|---:|
| **UNSW-NB15** | Random Forest (R4) | 0.8590 | 0.8548 | 0.9487 | 0.9323 | 24,496 |
| **UNSW-NB15** | Supervised LSTM (R4) | 0.8683 | 0.8637 | 0.9334 | 0.8903 | 24,496 |
| **UNSW-NB15** | **RF + LSTM Fusion ($\alpha=0.60$)** | **0.8996 (89.96%)** | **0.8970** | **0.9674** | **0.9538** | **24,496** |

---

## 3. Methodological Rigor & Leakage Defense

1. **Split Isolation:** 
   - Splits generated via deterministic seeded hash partitioning (`src/xrlids/splitting/splitter.py`).
   - Training: 75%, Validation: 12.5%, Test: 12.5%.
   - Preprocessor fits imputation medians and `StandardScaler` on the training split only.
2. **Boundary Disconnection Invariant:**
   - In sequence models (LSTM and Fusion), $T-1=4$ boundary flows per PCAP file are dropped so sequence windows never cross file or session boundaries.
   - Reconciles the population count: $355,865 \text{ tabular rows} - (8 \text{ files} \times 4 \text{ boundary drops}) = 355,833 \text{ sequence flows}$.
3. **Multi-Seed Robustness:**
   - Evaluated across seeds `42`, `123`, and `456`.
   - CIC-IDS2017 Fusion accuracy: $0.9903 \pm 0.0005$, F1: $0.9735 \pm 0.0016$. Seed 42 reproduces canonical frozen artifacts.

---

## 4. Reinforcement Learning Audit & Hypothesis Refutation

### DQN Agent Architecture & State Formulation
- **State Vector $s_t \in \mathbb{R}^6$:** $[S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]$
  - $S_t$: Calibrated threat score
  - $\Delta S_t$: First-order velocity
  - $N_{\text{alert}}$: Alert density in rolling window
  - $a_{t-1}$: Previous action index
  - $c_t$: Host business criticality
  - $v_t$: Normalized flow byte rate
- **Network:** Dueling Q-Network (Value stream: Linear $6 \to 64 \to 1$; Advantage stream: Linear $6 \to 64 \to 4$).
- **Action Space:** 0: ALLOW, 1: ALERT, 2: RATE_LIMIT, 3: ISOLATE.

### The Cost-Optimal Baseline Comparison (EXP-P2A-COST-OPTIMAL-001) & Reconciled Figures
- **Evaluation Populations & Discrepancy Resolution:**
  - *Validation Population ($D_{\text{pol\_val}}$, 142,346 flows in `EXP-P2B-DQN-001`):* DQN achieved **+9.71%** cost reduction vs Baseline 1 ($\tau=0.50$) and **+10.82%** vs Baseline 2 ($\tau=0.40/0.75$), failing the pre-registered practical significance target of $\ge 15.0\%$.
  - *Final Test Population ($D_{\text{pol\_test}}$, 355,865 flows in `EXP-P2-FINAL-TEST-001`):* DQN achieved **+28.80%** cost reduction vs Baseline 1 ($\tau=0.50$), but only **+14.10%** vs Baseline 2 ($\tau=0.40/0.75$), still failing the $\ge 15.0\%$ threshold against the best existing baseline.
  - *Analytic Baseline Comparison (`EXP-P2A-COST-OPTIMAL-001`):* When evaluated against the zero-parameter analytic `CostOptimalThresholdPolicy` on the identical 355,865 test flows, the zero-parameter baseline achieved lower operational cost than the trained DQN in **4 of 6 benchmark settings** (e.g., 20.12% lower cost in 4-action High Availability). In the remaining 2 settings, DQN's margin was only ~8.8%.
- **Scientific Interpretation:** The response problem functions as an asymmetric-loss contextual bandit with hysteresis rather than an interactive sequential MDP.

---

## 5. Critical Vulnerabilities & Scientific Disclaimers

1. **Temporal Generalization Collapse (CSE-CIC-IDS2018):**
   - Under chronological day-to-day evaluation (training on Day 1-8, testing on Day 9-10), Random Forest performance collapses to $F_1 = 0.0113$ (compared to $0.8861$ on random split).
   - *Cause:* Extreme concept drift and non-stationary background traffic across distinct calendar days, coupled with unseen attack families (Ares Botnet on March 2, Infiltration on Feb 28).
   - *Empirical Anomaly Baseline Evaluation (`scripts/phase1/evaluate_temporal_anomaly_baseline.py`):*
     - Evaluated on 20,361 genuine flows from raw CSV files on disk (`data/raw/cse_cic_ids2018/`).
     - Supervised Random Forest detected only **0.04%** of Bot flows and **0.00%** of Web XSS/SQL attacks (overall recall: **1.75%**).
     - Unsupervised `IsolationForestDetector` (trained strictly on benign flows from Feb 14-15) achieved **50.02%** Bot detection, **58.23%** Web brute force detection, **50.63%** XSS detection, and **64.71%** SQL injection detection.
     - *Trade-off:* Background benign traffic naturally drifted across weeks, causing an anomaly False Positive Rate of **39.39%**. Anomaly detection is therefore suitable as a triage/escalation tier, not an unconstrained autonomous blocker.
2. **TreeSHAP Methodological Boundary:**
   - TreeSHAP explains solely the Random Forest model. It does not explain the neural LSTM or the linear fusion score.
3. **Probability Distortion in Raw Voting Scores:**
   - Raw Random Forest voting scores exhibit significant overconfidence in intermediate bins (e.g. predicted 0.1335 vs observed 0.0137 attack prevalence).
