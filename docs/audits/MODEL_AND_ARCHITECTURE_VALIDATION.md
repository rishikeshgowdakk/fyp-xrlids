# XRL-IDARS — Forensic Model Validation and Research Architecture Review

**Document Identifier**: `AUDIT-XRLIDS-ARCH-001`  
**Audit Date**: `2026-10-28`  
**Auditor**: Senior ML Engineer, Deep Learning Engineer, Reinforcement Learning Researcher, Network Security Auditor  
**Baseline Git Commit**: `5989bf4b4cbd82418140f2b0c4389397a170c55c`  
**Git Branch**: `main`  
**Working-Tree Status**: Clean (0 uncommitted changes at audit start)  

---

## 1. Executive Summary & Verification Taxonomy

This forensic audit independently evaluates the scientific validity, empirical evidence, artifact integrity, and production readiness of the **Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)**.

The audit protocol enforces strict evidence-based auditing: claims are classified as **Verified and Reproducible**, **Implemented but Not Empirically Validated**, **Partially Implemented**, **Incorrect or Misleading**, or **Blocked by Missing Data**. Model loading is never equated with correctness, high random-split metrics are never equated with out-of-distribution robustness, and reinforcement learning is not assumed superior without a controlled benchmark.

### Component-by-Component Validation Summary

| Component | Architecture / Mechanism | Scope / Dataset | Formal Validation Status | Primary Finding / Empirical Reality |
|:---|:---|:---|:---:|:---|
| **Random Forest Detector** | `RandomForestClassifier` (200 trees, depth 16) | CIC-IDS2017 (`R10`), CSE-2018 (`R10`), UNSW (`R4`) | **`VERIFIED_FOR_DEFINED_SCOPE`** | Highly accurate on random splits (F1 0.9512 / 0.8861 / 0.8548), but exhibits significant calibration gap in [0.1, 0.8] range and collapses to F1 0.0113 under temporal holdout. |
| **Supervised LSTM** | 2-layer LSTM (hidden 64, dropout 0.2, $T=5$) | CIC-IDS2017 (`R10`), CSE-2018 (`R10`), UNSW (`R4`) | **`PARTIALLY_VERIFIED`** | F1 0.9633 verified on aligned slice; however, shuffled-window ablation shows zero order gain ($\Delta \text{F1} = -0.0038$), proving the model performs local window smoothing rather than temporal reasoning. |
| **RF–LSTM Fusion** | Linear score weighting: $\alpha P_{\text{rf}} + (1-\alpha) P_{\text{lstm}}$ | CIC-IDS2017 ($\alpha=0.5$), CSE-2018 ($\alpha=0.0$), UNSW ($\alpha=0.6$) | **`PARTIALLY_VERIFIED`** | CIC-IDS2017 fusion achieves F1 0.9745 (+0.0112 over LSTM). On CSE-CIC-IDS2018, $\alpha = 0.00$, making fusion mathematically identical to standalone LSTM (degenerate configuration). |
| **Feature Contracts** | Semantic mapping: `R10` (10 features) vs `R4` (4 features) | Cross-dataset feature registry | **`VERIFIED_FOR_DEFINED_SCOPE`** | Rigid schemas enforced in `src/xrlids/features/definitions.py`. UNSW-NB15 correctly isolated to R4 because Argus flow exporter omitted TCP flags. |
| **Flow Semantics & Parity** | `FlowBuilder` (D-006 completion, 120s timeout) | Streaming packets vs canonical offline mapping | **`PARTIALLY_VERIFIED`** | Live extractor matches offline feature specification ($\text{atol} \le 10^{-4}$). However, original CICFlowMeter/Argus batch quirks differ from live streaming heuristics. |
| **Response Simulation (MDP)** | Offline flow replay with simulated consequence engine | Held-out CIC-IDS2017 ($355,865$ flows) | **`DEFECT_CONFIRMED`** | Traffic arrivals are strictly exogenous replay. Policy actions cannot alter future packet arrivals, inter-arrival times, or attack progression. Not a genuine sequential MDP. |
| **Deep Q-Network (DQN)** | Dueling DQN (state 6, $\gamma=0.95$, target net) | 3-action & 4-action policies | **`REQUIRES_REFORMULATION`** | Analytic `CostOptimalThresholdPolicy` beats DQN in 4 of 6 settings (up to 20.12% lower cost). DQN fails the 15% improvement target in all settings and is 53x slower. |
| **Deterministic Safety Gate** | Multi-tier rules (quarantine cap, cooldown, rate-limit fallback) | Pre-execution action validation | **`VERIFIED_FOR_DEFINED_SCOPE`** | 100% authoritative override on invalid actions. Tested across 6 adversarial invariant suites. Autonomous production enforcement remains `NO-GO`. |

---

## 2. Phase 0 — Baseline Protection and Repository Provenance

### 2.1 Git and Environment Baseline
- **Audit Commit**: `5989bf4b4cbd82418140f2b0c4389397a170c55c`
- **Current Branch**: `main`
- **Python Runtime**: `3.14.4`
- **PyTorch Version**: `2.14.0+cpu`
- **Scikit-Learn Version**: `1.9.1`
- **Joblib Version**: `1.6.0`
- **SHAP Version**: `0.52.0`

### 2.2 Canonical Model Artifacts Inventory
All 9 canonical models registered in `models/registry/model_manifest.json` are committed directly in Git (no Git-LFS required):

| Model Artifact File | Type | Feature Contract | Checksum (SHA-256) | File Size | Registry Status |
|:---|:---:|:---:|:---|---:|:---:|
| `models/rf/random_forest_cicids2017.joblib` | RF | `R10` | `7c6ad493b773b687da24a2a12dcb21bd03bd56b76809462b983454aeacf2b774` | 26.4 MB | REGISTERED |
| `models/rf/random_forest_cse2018.joblib` | RF | `R10` | `b7d2dc7bacca1a46f4da35aee2c19e1604020d429a5d29b72d742130215ba9b3` | 68.2 MB | REGISTERED |
| `models/rf/random_forest_unswnb15.joblib` | RF | `R4` | `c432eb067507ad5b29a542b372ac6d35e609e783a9e6094c9764d0cfe654ec7c` | 22.6 MB | REGISTERED |
| `models/lstm/lstm_cicids2017.pt` | LSTM | `R10` | `18b0bfb48d3b031c17b26d3abd12485e09f8dd8c330fad26858320f11f818be1` | 60.4 KB | REGISTERED |
| `models/lstm/lstm_cse2018.pt` | LSTM | `R10` | `ea5b8198c20faa15d5d45ae7d081b754a76dbae1342a93b8234e0e06cfe8a33a` | 60.9 KB | REGISTERED |
| `models/lstm/lstm_unswnb15.pt` | LSTM | `R4` | `4d9386ff44c99eed822f8ace5c64429fab571b4f8aad847d6cc78bae5f308fbd` | 57.8 KB | REGISTERED |
| `models/dqn/dqn_3action_best.pt` | DQN | `response_state_v1` | `c06a61fb7777511600efd6db776745c4539da30c710fed8993145ed1b926be31` | 43.0 KB | REGISTERED |
| `models/dqn/dqn_4action_best.pt` | DQN | `response_state_v1` | `6a5afc669b4e699ecd2b1c01df885cef9030c93b8888b487dd386533920ce954` | 43.2 KB | REGISTERED |
| `models/fusion/fusion_weights.json` | Fusion | Multi | `fd50a413119d3ec3b0c7515125cf6e0f4a605aa52ca2739b9fcd951f8e081c72` | 1.0 KB | REGISTERED |

### 2.3 Historical Git Provenance Trace
- **Phase 1 Baseline (`EXP-P1-CIC2017-R10-001`)**: Trained and frozen at commit `fa370a9001fb328cde9f3cfa1d6ae48d3a72679c`.
- **Phase 2 Held-Out Response Test (`EXP-P2-FINAL-TEST-001`)**: Evaluated at commit `c2097fa548ed96f519c4f2886c6c01653349e649`.
- **Phase 2A Cost-Optimal Benchmark (`EXP-P2A-COST-OPTIMAL-001`)**: Executed at commit `18da4acbc3a1df8acb6d4ed17658fb287ddf6e76` (committed in `70c17d21fa64d3379028165c8e9ed0e04f106f20`).
- **Phase 2B Readiness Audit (`EXP-P2B-READINESS-AUDIT-001`)**: Verified and remediated at commit `f4c881559868ba869a8385bbd867c427ff15b49d` and `5989bf4b4cbd82418140f2b0c4389397a170c55c`.

---

## 3. Phase 1 — Validation of ML, DL, and Fusion Components

### 3.1 Random Forest Detector
1. **Feature Schema & Order Enforcement**:
   - `RandomForestDetector.predict_proba()` strictly compares `list(X.columns) == self.feature_names`. Any permutation or missing column raises a immediate `RandomForestError`.
   - Feature scaling is not applied to tree decisions; however, numeric infinities and NaNs are clamped/rejected by preprocessing metadata.
2. **Positive-Class Indexing**:
   - Verified that `predict_proba(X)[:, 1]` corresponds to the attack class (`1`), while class `0` is benign.
3. **Probability Calibration Defect**:
   - As documented in `results/experiments/EXP-P1-CIC2017-R10-001/calibration_report.json`, tree vote fractions in the intermediate range deviate substantially from true empirical frequencies:
     - Predicted Bin $[0.4, 0.5]$: Mean predicted score $= 0.4497$, observed attack frequency $= 0.1450$ (Calibration Gap $= 0.3047$).
     - Predicted Bin $[0.5, 0.6]$: Mean predicted score $= 0.5484$, observed attack frequency $= 0.2857$ (Calibration Gap $= 0.2627$).
     - Predicted Bin $[0.7, 0.8]$: Mean predicted score $= 0.7424$, observed attack frequency $= 0.4226$ (Calibration Gap $= 0.3197$).
   - **Conclusion**: The raw RF score must be treated as a tree-vote confidence score, not a calibrated posterior probability $P(\text{Attack} \mid x)$.
4. **Out-of-Distribution Temporal Collapse (CSE-CIC-IDS2018)**:
   - On CSE-CIC-IDS2018, when tested on genuine chronological future days (`EXP-P1-CSE2018-TEMPORAL-R10-001`), RF F1 collapses from **0.8861** to **0.0113** (Bot recall drops from 99.17% to 0.09%, ROC-AUC collapses to 0.3905). High random-split scores do not indicate future-day robustness.

### 3.2 Supervised LSTM Sequence Classifier
1. **Architecture & Memory Representation**:
   - Checkpoint dimensions match `src/xrlids/models/lstm.py`: 2-layer LSTM, input size 10 (or 4 for R4), hidden size 64, dropout 0.2, linear head to single logit with Sigmoid.
   - 3D sequence tensors $(N, T, F)$ are never fully materialized in RAM; `SequenceArray` creates mini-batch slices dynamically from a contiguous 2D float32 array.
2. **Sequence Boundary Enforcement**:
   - Sequences are constructed strictly within individual capture files. Crossing capture boundaries is prohibited by `assert_no_boundary_crossing()`.
3. **Temporal Reasoning Ablation (The Shuffled-Window Test)**:
   - In `results/ablations/lstm_temporal_ablation.json`, when flow sequence order was permuted within each length-5 window:
     - Chronological condition: $\text{F1} = 0.9314$, $\text{PR-AUC} = 0.9466$
     - Shuffled condition: $\text{F1} = 0.9353$, $\text{PR-AUC} = 0.9411$
     - Order Gain $\Delta \text{F1} = -0.0038$
   - **Conclusion**: The LSTM does not learn recurrent time-series dynamics; it acts as a non-linear spatial/contextual smoothing filter across 5 consecutive flows.

### 3.3 RF–LSTM Fusion & Degenerate Weights
1. **Fusion Formula**:
   $$P_{\text{fusion}} = \alpha \cdot P_{\text{rf}} + (1 - \alpha) \cdot P_{\text{lstm}}$$
2. **Empirical Results**:
   - **CIC-IDS2017** ($\alpha = 0.50$): RF F1 0.9512, LSTM F1 0.9633, Fusion F1 **0.9745** (+0.0112 gain).
   - **UNSW-NB15** ($\alpha = 0.60$, R4): RF F1 0.8548, LSTM F1 0.8637, Fusion F1 **0.8970** (+0.0333 gain).
   - **CSE-CIC-IDS2018** ($\alpha = 0.00$): Optimal validation grid search yielded $\alpha = 0.00$.
3. **Degeneracy Warning**:
   - At $\alpha = 0.00$, $P_{\text{fusion}} = 0 \cdot P_{\text{rf}} + 1 \cdot P_{\text{lstm}} \equiv P_{\text{lstm}}$.
   - Presenting fusion on CSE-CIC-IDS2018 as an ensemble innovation is misleading; the model is mathematically 100% equivalent to the standalone LSTM detector.

---

## 4. Phase 2 — Population Reconciliation and Split Integrity

### 4.1 The 32-Flow Population Difference
The repository contains two evaluation numbers for CIC-IDS2017:
- **355,865 tabular flows** (evaluated by RF and Phase 2 offline replay).
- **355,833 sequence-aligned flows** (evaluated by LSTM and Fusion).

Direct forensic recomputation of `data/processed/phase2_cache/d_pol_test_flows.joblib` and `results/experiments/EXP-P1-CIC2017-R10-001/predictions_test.csv` proves:
- Causal sequences of length $T=5$ require dropping the first $(T - 1) = 4$ flows of each capture file so sequences never span across disjoint network sessions.
- Across all 8 CIC-IDS2017 capture files, exactly $8 \times 4 = 32$ flows are dropped.
- **Every single dropped boundary flow was benign (32 benign dropped, 0 attack flows dropped)**.
- Across all surviving 355,833 rows, test labels match with **100.000% parity**.

| Capture File Name | Tabular Flows (Tot / Ben / Atk) | Aligned Sequence Flows (Tot / Ben / Atk) | Dropped Boundary Flows |
|:---|---:|---:|---:|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 41,768 / 16,421 / 25,347 | 41,764 / 16,417 / 25,347 | 4 Benign / 0 Attack |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 18,892 / 18,572 / 320 | 18,888 / 18,568 / 320 | 4 Benign / 0 Attack |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 26,961 / 26,765 / 196 | 26,957 / 26,761 / 196 | 4 Benign / 0 Attack |
| `Monday-WorkingHours.pcap_ISCX.csv` | 69,273 / 69,273 / 0 | 69,269 / 69,269 / 0 | 4 Benign / 0 Attack |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 28,715 / 28,707 / 8 | 28,711 / 28,703 / 8 | 4 Benign / 0 Attack |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 21,683 / 21,314 / 369 | 21,679 / 21,310 / 369 | 4 Benign / 0 Attack |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 56,624 / 55,079 / 1,545 | 56,620 / 55,075 / 1,545 | 4 Benign / 0 Attack |
| `Wednesday-workingHours.pcap_ISCX.csv` | 91,949 / 54,914 / 37,035 | 91,945 / 54,910 / 37,035 | 4 Benign / 0 Attack |
| **TOTAL** | **355,865 / 291,045 / 64,820** | **355,833 / 291,013 / 64,820** | **32 Benign / 0 Attack** |

---

## 5. Phase 3 — Reinforcement Learning Response Architecture Review

### 5.1 Environment Causal Reality: Contextual Decision vs Sequential MDP
Inspection of `src/xrlids/response/environment.py` reveals that the simulator advances by reading the next pre-recorded flow from an offline dataset:
```python
flow = self.flows[self._current_step]
# ... evaluates action cost ...
self._current_step += 1
next_flow = self.flows[self._current_step]
```
- **Finding**: Future flow arrivals, IP addresses, packet volumes, and attack progressions are strictly exogenous.
- Taking action `ISOLATE` on flow $t$ does not alter whether an attack arrives at flow $t+1$.
- The only sequential state variables carried over are internal policy variables: `cooldown_remaining`, `last_action` (used for chattering cost), and `_consecutive_alerts` (used for fatigue cost).
- **Scientific Implication**: Discount factor $\gamma = 0.95$ optimizes spurious correlations across 20 steps of exogenous traffic. The problem is properly formulated as an **Asymmetric-Loss Contextual Decision Policy with Hysteresis Constraints**, not an unconstrained MDP.

### 5.2 Controlled Benchmark: Cost-Optimal Baseline vs DQN
In Phase 2A (`EXP-P2A-COST-OPTIMAL-001`), the trained DQN was evaluated alongside an analytically derived threshold baseline (`CostOptimalThresholdPolicy`) on the identical 355,865 held-out flows across all 6 standardized operational settings:

| Operational Setting | Policy | Total Operational Cost | Mean Cost / Flow | Availability (BAS) | Action Chattering | Winner | Relative Difference |
|:---|:---|---:|---:|---:|---:|:---:|---:|
| **Standard Enterprise (3-Action)** | Cost-Optimal Baseline | 554,496.5 | 1.5582 | 85.81% | 0.0245 | DQN | -8.82% |
| | Trained DQN | 505,610.5 | 1.4208 | 96.51% | 0.0019 | | |
| **High Availability (3-Action)** | Cost-Optimal Baseline | 590,116.0 | 1.6583 | 91.16% | 0.0232 | DQN | -8.80% |
| | Trained DQN | 538,160.5 | 1.5123 | 96.51% | 0.0019 | | |
| **High Security Enclave (3-Action)** | Cost-Optimal Baseline | **856,841.0** | 2.4078 | 63.90% | 0.0274 | **Baseline** | **-3.94%** |
| | Trained DQN | 891,946.5 | 2.5064 | 96.51% | 0.0019 | | |
| **Standard Enterprise (4-Action)** | Cost-Optimal Baseline | **1,837,079.0** | 5.1623 | 85.81% | 0.0228 | **Baseline** | **-3.07%** |
| | Trained DQN | 1,895,196.5 | 5.3256 | 96.52% | 0.0214 | | |
| **High Availability (4-Action)** | Cost-Optimal Baseline | **1,547,511.0** | 4.3486 | 91.16% | 0.0208 | **Baseline** | **-20.12%** |
| | Trained DQN | 1,937,476.5 | 5.4444 | 96.52% | 0.0214 | | |
| **High Security Enclave (4-Action)** | Cost-Optimal Baseline | **2,356,339.0** | 6.6214 | 63.90% | 0.0333 | **Baseline** | **-3.65%** |
| | Trained DQN | 2,445,511.5 | 6.8720 | 96.52% | 0.0214 | | |

### 5.3 Key Takeaways for Viva & Review
1. **Cost-Optimal Baseline Beats DQN in 4 of 6 Settings**: In the 4-action High Availability regime, the analytic baseline achieves a **20.12% cost reduction** over DQN ($1,547,511$ vs $1,937,476$).
2. **DQN Fails Practical 15% Improvement Threshold**: In the 2 settings where DQN has lower cost, its advantage is only $8.82\%$ and $8.80\%$, failing the pre-registered 15% target.
3. **Execution Latency**: The analytic baseline evaluates in **0.40 µs** (2.5 million decisions/s) vs **21.28 µs** (47,000 decisions/s) for DQN neural inference—a **53x latency advantage**.
4. **Final DQN Verdict**: **`REQUIRES_REFORMULATION`**. The reinforcement learning agent cannot be recommended for autonomous production enforcement over analytic cost-sensitive decision rules.
