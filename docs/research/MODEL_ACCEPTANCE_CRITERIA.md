# XRL-IDARS — Model Acceptance Criteria & Evaluation Policy

**Document ID:** `POLICY-2026-MAC-001`  
**Version:** 1.0.0  
**Phase:** Phase 1C — Model Acceptance Policy Finalization  
**Date:** October 30, 2026  
**Author:** Principal Network Security Architect & ML Systems Engineer  
**Status:** APPROVED PROJECT POLICY  
**Repository:** `/home/rishikesh/Desktop/fyp-xrlids`  

---

## 1. Executive Summary & Plain-Language Policy Guide

### 1.1 The Plain-Language Principle
In many academic AI projects, researchers force multiple complex neural networks together into a single "frankenstein" model to make their thesis sound more impressive—even when the simpler model is faster, more accurate, and more reliable.

Under the **Master Engineering Directive**, XRL-IDARS rejects this practice:
- **Random Forest is our certified primary detector**. It is fast ($< 1.0\,\text{ms}$), highly accurate ($99.01\%$ recall), explainable via TreeSHAP, and independently operational.
- **The Temporal LSTM is strictly an optional, experimental detector**. It must prove its own scientific worth on real held-out data. If the LSTM does not provide meaningful value over Random Forest, we will **honestly document the result and leave the LSTM disabled**.
- **Score Fusion is explicitly removed**. We will not blend probabilities with arbitrary weights ($\alpha$). The models produce independent outputs.
- **The system must remain 100% operational with Random Forest alone**.

---

## 2. Formal Acceptance Criteria by Subsystem

### 2.1 Subsystem 1: Random Forest (Primary Operational Detector)
The Random Forest model ([`models/rf/random_forest_cicids2017.joblib`](file:///home/rishikesh/Desktop/fyp-xrlids/models/rf/random_forest_cicids2017.joblib)) is the foundational detection engine.

#### Operational Invariants:
1. **Total Independence**: The Random Forest must execute without waiting for or depending upon any neural network, sequence buffer, or background thread.
2. **Deterministic Preprocessing**: Uses the verified, frozen `StandardScaler` loaded from `preprocessor.joblib`. Zero retraining or runtime re-fitting.
3. **Execution Latency Budget**: Per-flow classification latency must remain **$< 1.0\,\text{millisecond}$** under continuous traffic.
4. **Explainability Contract**: Must support exact local feature attributions via TreeSHAP without breaking or delaying detection events.

#### Quantitative Acceptance Thresholds:
- **Attack Recall**: $\ge 98.0\%$ on held-out test splits.
- **Precision**: $\ge 90.0\%$ on held-out test splits.
- **F1 Score**: $\ge 0.940$.
- **PR-AUC**: $\ge 0.970$.
- **Inference Latency ($p95$)**: $< 1.0\,\text{ms}$ per flow.

---

### 2.2 Subsystem 2: Temporal LSTM (Independent Experimental Detector)
The newly proposed R10-FlowSeq LSTM evaluates sequences of 5 completed flows from a source host.

#### Evaluation Protocol & Acceptance Policy:
1. **Separation of Metrics & Compatible Task Scope**:
   - The Random Forest operates on isolated single-flow feature vectors ($N=1$).
   - The LSTM operates on causal host sequence histories ($K=5$ consecutive flows).
   - The LSTM is evaluated on its native semantic target: **Host-Sequence Detection** (classifying whether a host's sequence trajectory represents malicious behavior).
   - **No Sole-Outperformance Requirement**: Statistically significant superiority over Random Forest on single-flow metrics is **NOT** a prerequisite for LSTM acceptance. Flow-level and sequence-level models evaluate fundamentally different granularities of network state. If the LSTM performs well on sequence trajectory classification but does not outperform RF on individual flows, this is documented honestly as a scientific finding rather than treated as a model defect.
2. **Multi-Dimensional Evaluation Dimensions**:
   The LSTM model is characterized across seven core dimensions on held-out test data:
   - **Core Classification Metrics**: Accuracy, Precision, Recall, and Macro-F1.
   - **Threshold-Independent Discriminative Power**: Precision-Recall AUC (PR-AUC) and ROC-AUC.
   - **Operational False Alarm Rate**: False Positive Rate (FPR) on benign host traffic streams ($\le 1.0\%$).
   - **Per-Class Detection Performance**: Breakdown of true positive rates on attack sequences vs benign sequences.
   - **Generalization to Unseen Hosts**: Evaluated on strictly held-out attacker IPs (Hosts 8, 9, 10) never observed during training.
   - **Inference Latency Budget**: Per-sequence batch-1 inference latency must be **$< 20.0\,\text{ms}$** (tested target $\le 10.0\,\text{ms}$).
   - **Resource Footprint**: Minimal CPU and resident memory consumption in the background worker thread without starving the RF fast path.
3. **Acceptance Conditions for Operational Inclusion**:
   The LSTM is certified as an active independent detector if all of the following conditions are met:
   - **Sequence Classification Fidelity**: Held-out sequence Test $F1 \ge 0.90$, Test $\text{PR-AUC} \ge 0.92$, and $\text{FPR} \le 1.0\%$.
   - **Unseen Host Generalization**: Demonstrates stable detection ($F1 \ge 0.85$) on unseen attacker IP streams.
   - **Sequence Value-Add**: Demonstrates genuine diagnostic utility on temporal patterns (e.g. multi-flow volumetric bursts, sustained scanning rates) where single-flow classifiers lack historical context.
   - **Execution Latency**: Inference latency $p95 < 20.0\,\text{ms}$ per 5-flow sequence on standard CPU.
4. **Transparent Research Disposition**:
   - If the LSTM satisfies these multi-dimensional criteria, it is integrated as an independent, asynchronous context generator providing host risk scores to the dashboard and advisory DQN.
   - If the LSTM fails to achieve acceptable sequence discriminative power or exceeds the latency budget, the checkpoint and comprehensive benchmark results will be fully documented in `docs/research/LSTM_EVALUATION_REPORT.md` for scientific transparency, and the operational engine will run solely on Random Forest.

---

### 2.3 Subsystem 3: Multi-Model Score Fusion (REMOVED)
- **Status**: **EXPLICITLY REMOVED FROM APPROVED ARCHITECTURE**.
- **Architectural Policy**:
  - No blended probabilities ($S = \alpha P_{\text{RF}} + (1-\alpha) P_{\text{LSTM}}$).
  - No fusion configuration files in operational code paths.
  - Random Forest and LSTM produce **independent, un-blended detection events**.
  - Downstream components (Dueling DQN response agent and Dashboard) receive the independent scores as separate signals.

---

### 2.4 Subsystem 4: Dueling DQN Response Policy (Advisory Only)
The Dueling DQN model ([`models/dqn/dqn_4action_best.pt`](file:///home/rishikesh/Desktop/fyp-xrlids/models/dqn/dqn_4action_best.pt)) recommends incident response actions.

#### Operational Invariants:
1. **Strictly Advisory**: All recommended actions (`ALLOW`, `ALERT`, `RATE_LIMIT`, `CONTAIN`) are advisory recommendations displayed on the dashboard and logged to audit trails.
2. **Zero Host Mutations**: The system modifies zero live firewall rules (`iptables`, `nftables`) and drops zero network connections during normal operation.
3. **RF-Only Fallback**: The DQN causal state vector must function completely using Random Forest flow attributes and alert counts when the LSTM is disabled or unavailable.

---

### 2.5 Subsystem 5: Deterministic Safety Gate
The safety gate ([`src/xrlids/response/safety.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/safety.py)) governs all policy recommendations.

#### Invariants Enforced:
1. **Independent Governance**: The DQN cannot bypass the safety gate under any circumstances.
2. **Blast-Radius & Cooldown Enforcement**: Rate limits repeated actions on the same host and enforces cooldown intervals.
3. **Critical Host Protection**: Critical infrastructure hosts (DNS, Gateway, Monitoring) are protected by an un-bypassable allowlist.
4. **Fails Closed**: Any malformed or unauthorized action is rejected and logged.

---

## 3. Quantitative Acceptance & Stop Decision Matrix

| Subsystem | Evaluation Condition | Acceptance Bound | Stop / Rejection Action |
| :--- | :--- | :---: | :--- |
| **Random Forest** | Held-Out Test Evaluation | $F1 \ge 0.940$, Recall $\ge 98.0\%$ | If broken, stop and fix feature contract before any temporal work. |
| **Random Forest** | Flow Latency Benchmark | $p95 < 1.0\,\text{ms}$, $p99 < 2.0\,\text{ms}$ | Optimize vectorized preprocessor; profile feature extraction. |
| **Temporal LSTM** | Held-Out Test Evaluation | Multi-dimensional: $F1 \ge 0.90$, $\text{PR-AUC} \ge 0.92$, $\text{FPR} \le 1\%$, Unseen Host $F1 \ge 0.85$ | If below bounds, document transparently in research report; disable operationally. |
| **Temporal LSTM** | Sequence Latency | Latency $< 20.0\,\text{ms}$ per sequence | If too slow, disable background worker; retain RF fast path. |
| **Score Fusion** | Operational Codebase | **0% Fusion Dependencies** | Formally removed; do not implement or deploy. |
| **Dueling DQN** | Simulated Environment | Expected return > random / heuristic | If invalid, retain deterministic rule advisory and document DQN scope. |
| **Safety Gate** | Live & Simulated Stress | **0 Unintended Network Mutations** | Absolute zero-tolerance invariant. |
