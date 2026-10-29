# XRL-IDARS — Research Evaluation Protocol

**Official Title:** Explainable Reinforcement Learning-Based Network Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Repository:** `rishikeshgowdakk/fyp-xrlids`  
**Execution Context:** Linux x86_64, Python 3.14  
**Scope:** Authoritative evaluation protocols, metric equations, benchmark splits, leakage controls, RL baselines, latency measurement, and exact reproduction commands.  

---

## 1. Benchmark Data Splits & Leakage Prevention Protocol

### 1.1 Policy A Stratified Split Architecture
All supervised models (Random Forest, LSTM) and reinforcement learning response policies (Dueling DQN) are evaluated on strict **held-out test splits** constructed under Policy A:

| Benchmark Dataset | Total Processed Flows | Train Split (60%) | Validation Split (20%) | Held-Out Test Split (20%) | Contract Schema |
|---|---|---|---|---|---|
| **CIC-IDS2017** | 1,779,165 | 1,067,499 | 355,833 | **355,833** | $R_{10}$ (10 features) |
| **CSE-CIC-IDS2018** | 8,312,095 | 4,987,257 | 1,662,419 | **1,662,419** | $R_{10}$ (10 features) |
| **UNSW-NB15** | 122,480 | 73,488 | 24,496 | **24,496** | $R_4$ (4 features) |

### 1.2 Target Leakage & Information Isolation Controls
To ensure scientific validity and prevent optimistic bias:
1. **Feature-Target Isolation:** Ground-truth label columns (`Label`, `label`, `attack_cat`) are extracted and stripped before the feature matrix $X$ is formed.
2. **Metadata Separation:** Identifiers, IP addresses (`src_ip`, `dst_ip`), port numbers (`src_port`, `dst_port`), protocol IDs, and flow timestamps are stored in an unindexed metadata sidecar and never passed to the ML scaler or estimator.
3. **Strict Train-Fitted Preprocessing:** `preprocessor.joblib` was fitted solely on the 60% training partition. Scaling parameters (mean $\mu$, standard deviation $\sigma$, medians) are frozen. The validation and test sets are transformed without updating parameters.
4. **Row Accounting:** Every evaluated CSV row is verified. Non-finite values ($NaN$, $\pm\infty$) are counted in an audit tally and rejected, not silently zero-filled.

---

## 2. Detection Metric Definitions & Mathematical Formulas

For all binary classification tasks, `BENIGN` is defined as Class $0$ (Negative) and `ATTACK` is defined as Class $1$ (Positive).

1. **Confusion Matrix:**
   - **True Positive ($TP$):** Attack correctly classified as Attack.
   - **False Positive ($FP$):** Benign traffic misclassified as Attack (False Alarm).
   - **True Negative ($TN$):** Benign traffic correctly classified as Benign.
   - **False Negative ($FN$):** Attack traffic misclassified as Benign (Missed Attack).

2. **Classification Metrics:**
   - **Accuracy:**
     $$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$
   - **Precision (Positive Predictive Value):**
     $$\text{Precision} = \frac{TP}{TP + FP}$$
   - **Recall (Sensitivity / Detection Rate):**
     $$\text{Recall} = \frac{TP}{TP + FN}$$
   - **F1-Score (Harmonic Mean):**
     $$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2 \cdot TP}{2 \cdot TP + FP + FN}$$
   - **False Positive Rate ($FPR$):**
     $$FPR = \frac{FP}{FP + TN}$$
   - **Area Under the ROC Curve (ROC-AUC):** Integral of True Positive Rate against False Positive Rate across all decision thresholds $\tau \in [0, 1]$.
   - **Precision-Recall AUC (PR-AUC):** Integral of Precision against Recall across all thresholds $\tau \in [0, 1]$.

---

## 3. Autonomous Response Policy Evaluation Protocol

The Deep Q-Network response policy is evaluated on **held-out test episodes** (355,865 test flows) against 4 clearly defined heuristic baselines:

### 3.1 Baseline Policy Definitions
- **Baseline 0 — No Response (`ALLOW`):** Passive monitoring only. Never mitigates attacks.
  - Action rule: $a = \text{ALLOW}$ for all states.
  - Failure mode: Severe penalty from uncontained attack flows ($N_{\text{miss}} \cdot C_{\text{miss}}$).
- **Baseline 1 — Always Block (`ISOLATE` / `QUARANTINE`):** Aggressive isolation.
  - Action rule: $a = \text{ISOLATE}$ for all alerts.
  - Failure mode: Catastrophic disruption to benign business operations ($N_{\text{false}} \cdot C_{\text{false}}$).
- **Baseline 2 — Fixed Threshold Gate:**
  - Action rule: If $P(\text{ATTACK}) \ge 0.50$, action $a = \text{ISOLATE}$; else $a = \text{ALLOW}$.
  - Failure mode: Ignores host criticality, active connections, and blast-radius constraints.
- **Baseline 3 — Confidence-Tiered Heuristic:**
  - Action rule:
    - If $P(\text{ATTACK}) < 0.50 \to \text{ALLOW}$
    - If $0.50 \le P(\text{ATTACK}) < 0.80 \to \text{ALERT}$
    - If $0.80 \le P(\text{ATTACK}) < 0.95 \to \text{RATE\_LIMIT}$
    - If $P(\text{ATTACK}) \ge 0.95 \to \text{ISOLATE}$
- **Trained DQN Policy:**
  - Action rule: $a^* = \arg\max_a Q(s, a; \theta)$, where state $s$ encodes model confidence, threat severity, host criticality, connection density, historical false-positive rate, and alert rate.

### 3.2 Enterprise Cost Matrix & Reward Interpretation
Response performance is evaluated via an enterprise risk cost function:
$$\text{Cost} = N_{\text{miss}} \cdot C_{\text{miss}} + N_{\text{false}} \cdot C_{\text{false}} + N_{\text{latency}} \cdot C_{\text{latency}} + N_{\text{loss}} \cdot C_{\text{loss}}$$
where:
- $C_{\text{miss}} = 100.0$ (Critical cost of allowing a malicious intrusion)
- $C_{\text{false}} = 50.0$ (Cost of false isolation disrupting legitimate users)
- $C_{\text{latency}} = 10.0$ (Cost incurred per step of delayed mitigation)
- $C_{\text{loss}} = 5.0$ (Collateral business impact on shared network links)

**Interpretation:** **Lower total cost indicates a superior policy**. An agent that achieves low cost successfully balances high attack mitigation rate with near-zero false isolation.

---

## 4. Latency Profiling Protocol

Latency is benchmarked using the standard Python high-resolution monotonic timer:
`t_start = time.perf_counter_ns()` ... `t_elapsed = (time.perf_counter_ns() - t_start) / 1e6`

### 4.1 Measurement Boundaries
1. **Flow Feature Extraction:** Time to update flow state, calculate mean, std, rates, and produce canonical feature dictionary.
2. **Rule Engine Check:** Time to evaluate 5 deterministic security rules over the flow state.
3. **Random Forest Inference:** Time to validate dictionary, apply single-pass scaling, and run `predict_proba()` (100 trees).
4. **TreeSHAP Explanation:** Time to execute `shap.TreeExplainer.shap_values()` on the single-flow feature array.
5. **DQN Response Policy:** Time to construct 6-dimensional state vector and execute PyTorch forward pass to compute Q-values.
6. **End-to-End Decision:** Total wall-clock time from flow completion to emitted advisory recommendation.

### 4.2 Benchmark Execution Standards
- **Warm-Up:** 50 warm-up runs executed before measurement to eliminate JIT and caching variance.
- **Trial Count:** Minimum 1,000 repeated trials per stage.
- **Reporting Metrics:** Median ($p_{50}$), 95th percentile ($p_{95}$), and 99th percentile ($p_{99}$) reported in milliseconds (ms).

---

## 5. Explanation Faithfulness & Additivity Protocol

Every TreeSHAP explanation generated by `explain_flow_prediction()` is validated against the fundamental **Efficiency / Additivity Axiom**:
$$\sum_{i=1}^{M} \phi_i = f(x) - \mathbb{E}[f(x)]$$
where:
- $M$ is the number of features ($10$ or $4$).
- $\phi_i$ is the local Shapley attribution for feature $i$.
- $f(x)$ is the model output score for the predicted class.
- $\mathbb{E}[f(x)]$ is the base value (expected model output over training background).

**Tolerance Gate:** An explanation is accepted as mathematically valid if and only if:
$$\left| \sum_{i=1}^{M} \phi_i - (f(x) - \mathbb{E}[f(x)]) \right| < 10^{-5}$$
If this check fails, the explanation is marked invalid and rejected.

---

## 6. Conditions Under Which Metrics Must NOT Be Reported

To maintain scientific integrity:
1. **Never Report Training Metrics as Test Results:** Accuracy or F1 measured on training data must never be presented as test performance.
2. **Never Conflate Synthetic Demos with Real Attack Data:** Synthetic in-browser traffic generators test user interface functionality and must never be cited as benchmark accuracy.
3. **Never Report Explanations Without Real Attribution Values:** If TreeSHAP computation fails, an explicit `UNAVAILABLE` status must be reported; fallback heuristic rankings must never be passed off as Shapley values.
4. **Never Report Unverified Live Traffic Detection:** Metrics cannot be reported for live raw socket capture without ground-truth verification.
5. **Never Report Execution When Dry-Run is Active:** Recommended mitigation actions must be labelled `RECOMMENDED (DRY-RUN)` and never reported as real network mutations.

---

## 7. Exact Reproduction Commands

All evaluation metrics reported in this project can be reproduced from scratch using these exact CLI commands:

```bash
# Activate virtual environment
source .venv/bin/activate

# 1. Run Complete Automated Test Suite (550 tests)
pytest tests/

# 2. Run Focused Rule Engine Unit Tests
pytest tests/unit/test_rules_engine.py

# 3. Run Central Model Registry & Inference Tests
pytest tests/unit/test_model_registry_inference.py

# 4. Run TreeSHAP Local Explanation Tests
pytest tests/unit/test_flow_treeshap.py

# 5. Run Working Tree Cleanliness Invariant Tests
pytest tests/unit/test_working_tree_clean.py

# 6. Run Mode B Exhibition Benchmark Evaluation (200 flows per dataset)
python scripts/demo/run_replay_demo.py

# 7. Start Interactive Dashboard Server
python dashboard/server.py --port 8000
# Open browser at: http://localhost:8000
```
