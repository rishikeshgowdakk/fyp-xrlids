# Multiclass Attack Family Attribution & UNKNOWN Fallback Specification
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `SPEC-MULTICLASS-CLASSIFICATION-001`  
**Classification:** Core System Architecture Specification  
**Status:** IMPLEMENTED & EMPIRICALLY VERIFIED  

---

## 1. Architectural Role & Decoupling

In XRL-IDARS, threat detection and attack family attribution are structured as a **two-tier perception hierarchy**:

1. **Tier 1 (Binary Threat Perception):** Champion detector (XGBoost or Random Forest) computes continuous risk posterior $P(\text{ATTACK} \mid \mathbf{x}) \in [0.0, 1.0]$ in $<0.25\ \text{ms}$.
2. **Tier 2 (Multiclass Attribution):** When Tier 1 flags a significant anomaly or attack ($P(\text{ATTACK}) \ge 0.50$ or Hybrid trigger), `MulticlassAttackClassifier` estimates the probability distribution across canonical attack families:
   $$\mathbf{p} = [p_{\text{BENIGN}}, p_{\text{DoS}}, p_{\text{DDoS}}, p_{\text{PortScan}}, p_{\text{BruteForce}}, p_{\text{Bot}}, p_{\text{Infiltration}}, p_{\text{Web}}]$$
3. **Calibrated Confidence & UNKNOWN Fallback:**
   Let $p^* = \max_{k} p_k$ be the top class probability.
   $$\hat{y} = \begin{cases} \arg\max_k p_k & \text{if } p^* \ge \tau_{\text{confidence}} \ (0.40) \\ \text{UNKNOWN} & \text{if } p^* < \tau_{\text{confidence}} \end{cases}$$
   This guarantees that ambiguous, novel, or zero-day anomalous flows are never forced into an incorrect attack bucket, enabling SOC analysts to flag novel attack variants.

4. **Rule Engine Independence:** Protocol invariant violations (RFC 793 / RFC 1122 illegal flags, zero-window attacks) operate on an independent deterministic path. A rule hit triggers immediate hybrid escalation regardless of the multiclass model posterior.

---

## 2. Empirical Holdout Performance

Trained on balanced cross-capture samples from CICIDS2017 under canonical contract $R_{10}$ and evaluated on a holdout test set of 9,596 flows:

| Attack Family | Precision | Recall | F1 Score | Test Support |
|:---|:---:|:---:|:---:|:---:|
| **BENIGN** | 98.93% | 90.80% | 0.9469 | 4,500 |
| **BruteForce** | 99.47% | 99.87% | 0.9967 | 1,500 |
| **DDoS** | 94.79% | 99.53% | 0.9711 | 1,500 |
| **DoS** | 95.14% | 97.80% | 0.9645 | 1,500 |
| **PortScan** | 94.74% | 96.77% | 0.9574 | 93 |
| **Web Attacks** | 78.73% | 97.45% | 0.8710 | 471 |
| **Bot** | 13.84% | 68.75% | 0.2304 | 32 |
| **UNKNOWN (Fallback)** | N/A | N/A | N/A | 0 (Held-in test set) |
| **Weighted Average** | **96.46%** | **94.99%** | **0.9552** | **9,596** |

**Artifact Location:** `models/multiclass/multiclass_rf_champion.joblib` (2.4 MB).

---

## 3. Integration Points

1. `src/xrlids/models/multiclass_detector.py`: Implements `MulticlassAttackClassifier`, `predict_family()`, `predict_batch()`, and UNKNOWN fallback.
2. `src/xrlids/models/manager.py`: Integrates multiclass inference into `FlowInferenceResult`.
3. `src/xrlids/pipeline/active_pipeline.py`: Surfaces attack family and confidence inside `SecurityEvent.detection`.
4. `src/xrlids/flagship.py`: Exposes `attack_family_prediction` in unified `FlagshipDecision`.
5. `dashboard/pages/03_Model_Evaluation.py`: Visualizes multiclass metrics and fallback policies.
