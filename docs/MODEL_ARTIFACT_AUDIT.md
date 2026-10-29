# XRL-IDARS — Model & Preprocessor Artifact Audit

**Official Title:** Explainable Reinforcement Learning-Based Network Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Repository:** `rishikeshgowdakk/fyp-xrlids`  
**Audit Date:** Current System State  
**Scope:** Exhaustive physical, cryptographic, structural, and behavioral audit of all 9 canonical models and matched preprocessors.  

---

## 1. Master Artifact Audit Matrix

| Canonical Path | Artifact Type | Dataset | Contract | Input Dimensions | Checkpoint Size | SHA-256 Checksum | Loading & Smoke Test |
|---|---|---|---|---|---|---|---|
| `models/rf/random_forest_cicids2017.joblib` | Random Forest | CIC-IDS2017 | $R_{10}$ | 10 features, 100 trees | 26.3 MB | `7c6ad493b...` | **PASS** (100% Verified) |
| `models/rf/random_forest_cse2018.joblib` | Random Forest | CSE-CIC-IDS2018 | $R_{10}$ | 10 features, 100 trees | 68.2 MB | `b7d2dc7ba...` | **PASS** (100% Verified) |
| `models/rf/random_forest_unswnb15.joblib` | Random Forest | UNSW-NB15 | $R_4$ | 4 features, 100 trees | 22.6 MB | `c432eb067...` | **PASS** (100% Verified) |
| `models/dqn/dqn_4action_best.pt` | Dueling DQN | CIC-IDS2017 | `response_state_v1` | 6 states $\to$ 4 actions | 43.1 KB | `6a5afc669...` | **PASS** (100% Verified) |
| `models/dqn/dqn_3action_best.pt` | Dueling DQN | CIC-IDS2017 | `response_state_v1` | 6 states $\to$ 3 actions | 42.9 KB | `c06a61fb7...` | **PASS** (100% Verified) |
| `models/lstm/lstm_cicids2017.pt` | Supervised LSTM | CIC-IDS2017 | $R_{10}$ (Seq $T=5$) | 10 features, hidden 32 | 60.9 KB | `2cdbf88d2...` | **PASS** (Offline Only) |
| `models/lstm/lstm_cse2018.pt` | Supervised LSTM | CSE-CIC-IDS2018 | $R_{10}$ (Seq $T=5$) | 10 features, hidden 32 | 60.9 KB | `ea5b8198c...` | **PASS** (Offline Only) |
| `models/lstm/lstm_unswnb15.pt` | Supervised LSTM | UNSW-NB15 | $R_4$ (Seq $T=5$) | 4 features, hidden 32 | 57.8 KB | `4d9386ff4...` | **PASS** (Offline Only) |
| `models/fusion/fusion_weights.json` | Score Fusion | Multi-dataset | Probability Blend | $\alpha \cdot P_{RF} + (1-\alpha) \cdot P_{LSTM}$ | 1.2 KB | `e35df2517...` | **PASS** (Offline Only) |

---

## 2. Individual Artifact Profiles & Contract Verification

### 2.1 Primary Random Forest Models (`models/rf/`)

#### 1. `models/rf/random_forest_cicids2017.joblib`
- **Source Experiment:** `results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib`
- **Matched Preprocessor:** `results/experiments/EXP-P1-CIC2017-R10-001/preprocessor.joblib`
- **Feature Schema ($R_{10}$):**
  1. `flow_duration_ms`
  2. `flow_packets_per_s`
  3. `flow_bytes_per_s`
  4. `packet_length_mean`
  5. `packet_length_std`
  6. `syn_count`
  7. `ack_count`
  8. `rst_count`
  9. `fin_count`
  10. `syn_ack_ratio`
- **Internal Model Architecture:** `sklearn.ensemble.RandomForestClassifier` (`n_estimators=100`, `max_depth=None`, `n_features_in_=10`, `classes_=[0, 1]`).
- **Preprocessor Verification:** `p.scaler.n_features_in_ == 10`, `len(p.features) == 10`. Single-pass `StandardScaler` fitted on canonical 60% training split.
- **Dynamic Class Mapping:** Class index $0 \to$ `BENIGN`, Class index $1 \to$ `ATTACK`. Dynamic inspection via `estimator.classes_`.
- **Smoke Test Result:** **PASS**. Valid 10-feature vector inputs produce deterministic probability outputs. Corrupted inputs with missing keys, NaNs, or $\pm\infty$ raise `ValidationError`.

#### 2. `models/rf/random_forest_cse2018.joblib`
- **Source Experiment:** `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/random_forest.joblib`
- **Matched Preprocessor:** `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/preprocessor.joblib`
- **Feature Schema ($R_{10}$):** Identical 10 canonical features as above.
- **Internal Model Architecture:** `n_estimators=100`, `n_features_in_=10`, `classes_=[0, 1]`.
- **Preprocessor Verification:** `p.scaler.n_features_in_ == 10`, `len(p.features) == 10`.
- **Smoke Test Result:** **PASS**.

#### 3. `models/rf/random_forest_unswnb15.joblib`
- **Source Experiment:** `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/random_forest.joblib`
- **Matched Preprocessor:** `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/preprocessor.joblib`
- **Feature Schema ($R_4$):**
  1. `flow_duration_ms`
  2. `flow_packets_per_s`
  3. `flow_bytes_per_s`
  4. `packet_length_mean`
- **Internal Architecture:** `sklearn.ensemble.RandomForestClassifier` (`n_estimators=100`, `n_features_in_=4`, `classes_=[0, 1]`).
- **Preprocessor Verification:** `p.scaler.n_features_in_ == 4`, `p.features == ['flow_duration_ms', 'flow_packets_per_s', 'flow_bytes_per_s', 'packet_length_mean']`.
- **Deep Investigation of Path & Experiment Naming:**
  - *Audit Question:* Why does the source directory name contain `R10` (`EXP-P1-UNSWNB15-R10-MULTI-001`) when the contract is $R_4$?
  - *Empirical Finding:* The directory name is a historical artifact of the batch execution script which inherited `R10-MULTI` as a template naming prefix. Direct byte inspection of `preprocessor.joblib` and `random_forest.joblib` proves unequivocally that both artifacts were fitted on **exactly 4 features**. The scaler expects 4 features (`n_features_in_ = 4`), and the forest expects 4 features (`n_features_in_ = 4`).
  - *Conclusion:* The model and preprocessor are **100% mathematically and schema compatible**. No features are coerced or misaligned.

---

### 2.2 Autonomous Response DQN Checkpoints (`models/dqn/`)

#### 1. `models/dqn/dqn_4action_best.pt`
- **Source Experiment:** `results/phase2/EXP-P2B-DQN-001/checkpoints/stage_2b2_4action/best_model.pt`
- **Architecture:** PyTorch Dueling Deep Q-Network:
  - Input Layer: Linear(6, 64) with LayerNorm
  - Hidden Layer: Linear(64, 64) with LayerNorm
  - Value Stream $V(s)$: Linear(64, 32) $\to$ Linear(32, 1)
  - Advantage Stream $A(s, a)$: Linear(64, 32) $\to$ Linear(32, 4)
  - Output Q-values: $Q(s, a) = V(s) + \left(A(s, a) - \frac{1}{|A|}\sum_{a'} A(s, a')\right)$
- **State Vector (`response_state_v1`, 6 dimensions):**
  Canonical Causal State: $s_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]$ per SPEC-P2 Section 4 and `xrlids.response.state.StateBuilder`. (Note: The early conceptual proposal `[p_attack, threat_severity, host_criticality, active_connections, historical_fp_rate, alert_rate]` in preliminary design documents was superseded prior to Phase 2 training to eliminate target label leakage and ensure strict causal temporal realism).
- **Action Space (4 Actions):**
  - Index 0: `ALLOW` (Monitor passively, no intervention)
  - Index 1: `ALERT` (Log prioritized notification for security analyst)
  - Index 2: `RATE_LIMIT` (Constrain traffic bandwidth / rate)
  - Index 3: `ISOLATE` (Quarantine endpoint connection)
- **Selection Metric:** `mean_cost_per_flow = 2.2416` (evaluated at training step 45,000).
- **Smoke Test Result:** **PASS**. Deterministic greedy action selection and Q-value vector emission verified.

#### 2. `models/dqn/dqn_3action_best.pt`
- **Source Experiment:** `results/phase2/EXP-P2B-DQN-001/checkpoints/stage_2b1_3action/best_model.pt`
- **Architecture:** Dueling DQN (6 states $\to$ 3 actions).
- **Action Space (3 Actions):**
  - Index 0: `ALLOW`
  - Index 1: `ALERT`
  - Index 2: `QUARANTINE`
- **Selection Metric:** `mean_cost_per_flow = 2.0437` (evaluated at training step 10,000).
- **Smoke Test Result:** **PASS**.

---

### 2.3 Offline Supervised LSTM Checkpoints (`models/lstm/`)

- `models/lstm/lstm_cicids2017.pt`: PyTorch LSTM (`input_size=10, hidden_size=32, num_layers=1`). Sequence length $T=5$.
- `models/lstm/lstm_cse2018.pt`: PyTorch LSTM (`input_size=10, hidden_size=32, num_layers=1`). Sequence length $T=5$.
- `models/lstm/lstm_unswnb15.pt`: PyTorch LSTM (`input_size=4, hidden_size=32, num_layers=1`). Sequence length $T=5$.
- **Operational Boundary:** **OFFLINE COMPARATOR ONLY**. Supervised sequence generation requires warm-up delays and causal ordering that do not align with live asynchronous flow completion. All models load and pass offline evaluation smoke tests.

---

### 2.4 Score-Level Fusion Configuration (`models/fusion/fusion_weights.json`)

- **Configuration:** JSON dictionary defining dataset-specific blending weights $\alpha$:
  $$P_{\text{fusion}}(\text{ATTACK}) = \alpha \cdot P_{RF}(\text{ATTACK}) + (1 - \alpha) \cdot P_{LSTM}(\text{ATTACK})$$
- **Weights:**
  - `cicids2017`: $\alpha = 0.60$
  - `cse_cic_ids2018`: $\alpha = 0.55$
  - `unsw_nb15`: $\alpha = 0.50$
- **Operational Boundary:** **OFFLINE COMPARATOR ONLY**.

---

## 3. Strict Preprocessing Single-Pass Invariant

All model adapters guarantee that preprocessing is executed **exactly once**:
1. Input data is passed as a raw unscaled dictionary or DataFrame row.
2. The model adapter validates schema keys and data types.
3. The train-fitted `preprocessor.joblib` executes `transform()` once on the matrix.
4. The scaled numpy array is passed directly into `model.predict_proba()`.
5. Preprocessing is never re-applied on subsequent TreeSHAP or DQN downstream evaluations.

---

## 4. Audit of Current Prediction Capabilities (Addendum Section 2)

### 4.1 Binary vs Multiclass Verification
Direct programmatic inspection of all serialized Random Forest (`RandomForestDetector`) artifacts confirms:
- `models/rf/random_forest_cicids2017.joblib`: `classes_ = [0, 1]`, `n_classes_ = 2`, `n_features_in_ = 10`.
- `models/rf/random_forest_cse2018.joblib`: `classes_ = [0, 1]`, `n_classes_ = 2`, `n_features_in_ = 10`.
- `models/rf/random_forest_unswnb15.joblib`: `classes_ = [0, 1]`, `n_classes_ = 2`, `n_features_in_ = 4`.

**Empirical Finding:** Every trained detector in the repository is strictly a **binary classifier**. The output is `P(class=1) = P(ATTACK) ∈ [0, 1]`. None of the existing model artifacts output a probability distribution over attack families or predict attack family names.

### 4.2 Label Mapping and Attack Families in Associated Datasets
The ground-truth label taxonomy defined in `configs/labels/label_mapping.yaml` normalizes raw packet capture labels into 17 canonical attack families:
- **CIC-IDS2017:** `DoS`, `DDoS`, `PortScan`, `BruteForce`, `Web`, `Infiltration`, `Bot`, `Heartbleed`
- **CSE-CIC-IDS2018:** `DoS`, `DDoS`, `Web`, `Infiltration`, `Bot`, `BruteForce`
- **UNSW-NB15:** `Generic`, `Exploits`, `Fuzzers`, `DoS`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, `Worms`

These attack family names originate from dataset metadata and ground-truth annotation. They are **evaluation ground-truth labels**, not model predictions.

### 4.3 Per-Family Held-Out Evaluation Results
Per-family evaluation is implemented via `xrlids.evaluation.error_analysis.compute_per_family_metrics()` and saved to `per_family_metrics.csv` in each experiment directory:
- Evaluation measures the **binary detection performance** (detection rate / recall, false negatives, support) of the binary model across flows grouped by their ground-truth attack family.
- Example on CIC-IDS2017 (355k test flows):
  - DoS Hulk: 99.76% detection rate (33,074 support)
  - DDoS (LOIC): 99.70% detection rate (25,347 support)
  - PortScan: 99.06% detection rate (320 support)
  - Web Attack (Brute Force): 15.89% detection rate (258 support — critical blind spot)
  - Infiltration: 0.00% detection rate (8 support — critical blind spot)
- **Scientific Principle:** High detection recall on DoS does NOT mean the model identified the flow as "DoS". It means the binary detector correctly output $P(\text{ATTACK}) \ge 0.50$ when tested on a flow that ground-truth metadata identifies as DoS.

### 4.4 Feature Pipeline Semantic Compatibility
- **Offline test evaluation:** `preprocessor.joblib` applies median imputation and standard scaling fit strictly on the training partition.
- **Live / Replay feature pipeline:** `FlowBuilder` extracts the exact $R_{10}$ / $R_4$ behavioral features matching the trained model's feature names and order (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`, `packet_length_std`, `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio`).
- Regression tests in `tests/integration/test_feature_parity.py` confirm exact mathematical parity between offline and replay pipelines.

---

## 5. Autonomous Response Integrity & DQN Threat-Awareness Scope (Addendum Section 4)

### 5.1 Verification of DQN State and Action Contract
Inspection of `models/dqn/dqn_4action_best.pt` and `models/dqn/dqn_3action_best.pt`:
- Input dimension: 6
- 6D Causal State Vector: $s_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]$
  - $S_t$: Continuous detector risk score $P(\text{ATTACK}) \in [0, 1]$
  - $\Delta S_t$: Score trajectory (short-term slope relative to recent history)
  - $N_{\text{alert}}$: Local alert density
  - $a_{t-1}$: Previous action executed
  - $c_t$: Active cooldown timer fraction
  - $v_t$: Normalized flow volumetric rate
- Action space: Discrete graded response:
  - 3-action: `ALLOW` (0), `ALERT` (1), `RATE_LIMIT` (2)
  - 4-action: `ALLOW` (0), `ALERT` (1), `RATE_LIMIT` (2), `ISOLATE` (3)

### 5.2 Threat-Awareness Scope: Severity vs Attack Type
- **What the DQN supports:** Continuous threat-*severity* awareness via $S_t$ and volumetric surge awareness via $v_t$ and $\Delta S_t$. Higher risk scores and higher alert densities drive escalation from `ALLOW` to `RATE_LIMIT` or `ISOLATE`.
- **What the DQN does NOT support:** Threat-*type* or attack-family differentiation. Because the input state $s_t \in \mathbb{R}^6$ contains no categorical or multiclass family signal, the DQN cannot distinguish a Slowloris DoS from a Brute Force attempt.
- **Integrity Rule:** No synthetic family label or unsupported multiclass probability may be injected into the verified 6D state contract without invalidating the trained checkpoint.

### 5.3 Advisory / Dry-Run Invariant
- In all environments, DQN proposed actions pass through the Deterministic Safety Gate (`DeterministicSafetyGate`).
- Under current implementation, response execution is strictly **advisory / dry-run**:
  - Live monitor and replay simulator record recommendations.
  - Zero live firewall rules, iptables alterations, eBPF drop rules, or routing mutations are executed.
  - Recommended or simulated actions are never reported as executed network interventions.

### 5.4 Benchmark Evaluation Evidence
In controlled benchmarking across 355k held-out flows (`EXP-P2A-COST-OPTIMAL-001`), the analytic `CostOptimalThresholdPolicy` outperformed the trained DQN in 4 of 6 cost regimes (up to 20.12% lower cost), running ~51x faster (1.95 µs vs 100.23 µs policy-only). Autonomous production enforcement is strictly NO-GO.

---

## 6. Disambiguation of Evaluation and Dashboard Concepts (Addendum Section 5)

To maintain absolute scientific honesty, the system enforces strict separation between:

| Concept | Generator / Source | Semantics | Presentation in System |
|---|---|---|---|
| **RF Detection** | Frozen Random Forest (`P(ATTACK)`) | Binary probability score $\in [0, 1]$ and decision threshold (0.50) | `BENIGN` or `ATTACK` with continuous confidence |
| **Attack-Family Prediction** | N/A (No model exists) | Multiclass classification | **NOT AVAILABLE** (Explicitly labeled as unavailable; never fabricated) |
| **Rule-Based Finding** | Deterministic `RuleEngine` | Independent policy check (RFC violations, burst thresholds) | Rule ID (e.g. `RULE-SYN-FLOOD`) with exact matched evidence |
| **XAI (Explainability)** | `TreeSHAP` over RF | Feature importance attributions for binary attack probability | Shapley values explaining *why* the flow was classified attack/benign |
| **DQN Response Recommendation** | Frozen `DuelingQNetwork` | Policy action selection from 6D causal state | `ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE` with Q-values and margin |
| **Safety Decision** | `DeterministicSafetyGate` | Pre-execution safety invariants (cooldown, critical host exemption) | `PERMITTED` or `OVERRIDDEN` with explicit deterministic reason code |
| **Offline Evaluation** | Ground-truth dataset labels | Ground-truth attack taxonomy from dataset packet capture metadata | Stratified binary detection metrics (recall, support, error rate per family) |

---

## 7. Justification & Feasibility Analysis for Proposed Attack-Family Model Extension (Addendum Section 3)

### 7.1 Feasibility Assessment
- **Label availability:** All three datasets (`CIC-IDS2017`, `CSE-CIC-IDS2018`, `UNSW-NB15`) contain granular multi-class attack category labels.
- **Feature contract compatibility:** The existing $R_{10}$ (10 behavioral features) and $R_4$ (4 features) contracts provide sufficient statistical differentiation for volumetric and transport-layer attacks (DoS, DDoS, PortScan, BruteForce), but limited differentiation for payload-level attacks (Infiltration, SQLi, XSS).

### 7.2 Decision on Retraining
- **Strict Rule:** Existing frozen artifacts (`random_forest_cicids2017.joblib`, `dqn_4action_best.pt`, etc.) must **NOT** be retrained or modified.
- **Scientific Rationale:** The primary XRL-IDARS research prototype was designed, evaluated, and frozen as an end-to-end binary detection and autonomous response pipeline. Silently modifying these models would invalidate all frozen benchmark results, bootstrap confidence intervals, and Phase 2 cost evaluations.

### 7.3 Proposed Attack-Family Classifier Extension (Future Work Specification)
A separate multiclass model is feasible and justified as an optional **auxiliary triage extension**, structured as follows:

```
[Network Flow] ──> [Binary RF/LSTM Detector] ──> P(ATTACK)
                          │
                   if P(ATTACK) >= Threshold:
                          │
                          ▼
            [Auxiliary Attack-Family Classifier]  (Separate Model)
                          │
                          ▼
              Predicted Attack Family: DoS / BruteForce / PortScan / ...
```

#### Technical Specification for Future Implementation:
1. **Model Architecture:** Multiclass Gradient Boosted Decision Tree (LightGBM) or Multiclass Random Forest trained exclusively on attack-class instances (or Benign + $K$ attack classes).
2. **Isolation Guarantee:** Housed in a distinct artifact directory (`models/multiclass/`), with its own model card, training manifest, and SHA-256 checksum.
3. **Partition Isolation:** Must use the identical 60/20/20 train/validation/test split hash boundaries defined in `configs/splits/splits.yaml` to prevent data leakage.
4. **DQN Decoupling:** The existing DQN state contract ($s_t \in \mathbb{R}^6$) must remain unchanged. If a family-aware response policy is desired in future research, it must be formulated as a new, separately registered experiment (`EXP-P4-MULTICLASS-RESPONSE-001`) with its own baseline comparison against cost-optimal policies.
5. **Non-Dependency Invariant:** The auxiliary attack-family model is strictly optional and must never be a mandatory dependency of the primary binary detection and response pipeline.

