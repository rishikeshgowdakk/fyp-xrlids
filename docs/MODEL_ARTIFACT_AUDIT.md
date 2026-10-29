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
  `[p_attack, threat_severity, host_criticality, active_connections, historical_fp_rate, alert_rate]`
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
