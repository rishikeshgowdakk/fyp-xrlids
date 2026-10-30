# XRL-IDARS — System Architecture & Component Interface Specification

**Official Title:** Explainable Reinforcement Learning-Based Network Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Repository:** `rishikeshgowdakk/fyp-xrlids`  
**Architecture Version:** 2.1.0 (Implemented, Tested & Reconciled)  
**Primary Reference:** [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)  

---

## 1. End-to-End Architectural Pipeline

```text
Raw Network Packets (Live AF_PACKET / Scapy Sniff / PCAP Replay)
      ↓
Scapy Packet Ingestion & Parser (src/xrlids/capture/scapy_service.py)
      ↓
Bidirectional Flow Builder under D-006 (src/xrlids/live/flow_builder.py, demo/flow.py)
[TCP FIN/RST Teardown + 120.0s Idle Timeout Expiration]
      ↓
Canonical Feature Extraction & Schema Validation (src/xrlids/features/, registry.py)
[R10 Contract: 10 Features (CIC-IDS2017 / CSE-2018) | R4 Contract: 4 Features (UNSW-NB15)]
      ↓
Single-Pass Preprocessing & Scaling (StandardScaler fit on 60% Train Split Only)
      ↓
┌───────────────────────────────────────┐
│                                       │
▼                                       ▼
Random Forest Detector (100 Trees)   Sliding Sequence Buffer (T=5 Flows per Session)
[models/rf/random_forest_*.joblib]       │
│                                       ▼
│                                    Supervised LSTM Detector (models/lstm/lstm_*.pt)
└───────────────────┬───────────────────┘
                    ▼
         Convex Score-Level Fusion (models/fusion/fusion_weights.json)
         [S_fusion = alpha * S_rf + (1 - alpha) * S_lstm (when both valid)]
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
   TreeSHAP Explainer      Causal State Builder (src/xrlids/response/state.py)
   (shap.TreeExplainer)    [s_t = (S_t, ΔS_t, N_alert, a_{t-1}, c_t, v_t) in R^6]
   [Local attribution on RF]   │
                               ▼
                           Dueling DQN Policy Agent (models/dqn/dqn_*action_best.pt)
                           [Output: Q(s, a) -> a_proposed in {ALLOW, ALERT, RATE_LIMIT, ISOLATE}]
                               │
                               ▼
                           Deterministic Safety Gate (src/xrlids/response/safety.py)
                           [1. Critical Host Allowlist (Gateway, DNS, DC Exemption)]
                           [2. Mandatory Action Cooldown (T_cool = 30 steps = 30.0s)]
                           [3. Blast Radius Circuit Breaker (max 5.0% active isolation)]
                               │
                               ▼
                           Response Authorization & Enforcement Boundary
                           ├── Standard Operations: Strictly ADVISORY / DRY_RUN (0 Host Mutations)
                           └── Isolated Lab Only: NetnsActuatorBackend in LAB-ISOLATED-NETNS-01
                                (HostNetworkBaseline Verification & Atomic Rollback)
                               │
                               ▼
                           Security Operations Center & Dashboard (dashboard/server.py)
                           [Live Stream, Workbench Explorer, 10K Replay Lab, Audit Logs]
```

---

## 2. Component Implementation & Interface Matrix

| Subsystem | Implemented Module Path | Primary Class / Functions | Key Invariants & Contracts |
|---|---|---|---|
| **Packet Capture** | [`src/xrlids/capture/scapy_service.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/capture/scapy_service.py) | `ScapyCaptureService`, `scapy_packet_to_packet_info` | Non-blocking bounded queue, BPF filtering, graceful termination, packet drop accounting. |
| **Flow Construction** | [`src/xrlids/live/flow_builder.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/live/flow_builder.py), [`demo/flow.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/demo/flow.py) | `LiveFlowBuilder`, `Flow`, `FlowKey` | D-006 hybrid completion policy: immediate FIN/RST teardown, 120s idle timeout fallback. |
| **Feature Extraction** | [`src/xrlids/features/definitions.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/features/definitions.py) | `Flow.to_features()`, `R10_FEATURES`, `R4_FEATURES` | Zero formula duplication; numerical parity verified within $\text{atol} \le 10^{-4}$ in `test_feature_parity.py`. |
| **Deterministic Rules** | [`src/xrlids/rules/engine.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/rules/engine.py) | `RuleEngine`, `SecurityRule`, `RuleMatch` | 5 deterministic RFC/attack rules; executes in $<0.01$ ms; clearly decoupled from ML detector scores. |
| **Unified Inference** | [`src/xrlids/models/inference_service.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/inference_service.py) | `UnifiedInferenceService`, `SequenceBufferManager` | Per-session $T=5$ history buffering; RF fallback during 4-flow warm-up; score-level fusion upon 5th flow. |
| **Random Forest** | [`src/xrlids/models/random_forest.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/random_forest.py) | `RandomForestDetector` | 100 trees, strictly binary classification ($P(\text{ATTACK})$), memory-bounded parallelism (`n_jobs <= 4`). |
| **Supervised LSTM** | [`src/xrlids/models/lstm.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/lstm.py) | `LSTMDetector`, `SequenceArray`, `SequenceSet` | Supervised sequence classifier over $T=5$ consecutive flows; on-the-fly mini-batching without 3D RAM materialization. |
| **Score Fusion** | [`src/xrlids/models/fusion.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/models/fusion.py) | `ScoreFusionDetector`, `models/fusion/fusion_weights.json` | $S_{\text{fusion}} = \alpha \cdot S_{\text{rf}} + (1-\alpha) \cdot S_{\text{lstm}}$; only evaluated when both scores available. |
| **Explainability** | [`src/xrlids/explainability/shap_analysis.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/explainability/shap_analysis.py) | `explain_flow_prediction`, `TreeExplainer` | Local Shapley values on Random Forest only; validates additivity axiom $\sum \phi_i = f(x) - E[f(x)]$. |
| **Causal State** | [`src/xrlids/response/state.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/state.py) | `StateBuilder` | Strictly 6D causal vector $\mathbf{s}_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t] \in \mathbb{R}^6$; no label leakage. |
| **DQN Policy** | [`src/xrlids/response/dqn/network.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/dqn/network.py) | `DuelingQNetwork`, `DQNAgent` | Dueling architecture (Value stream $V(s) \in \mathbb{R}^1$, Advantage stream $A(s, a) \in \mathbb{R}^4$). |
| **Deterministic Safety** | [`src/xrlids/response/safety.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/safety.py) | `DeterministicSafetyGate` | Non-bypassable: Critical host allowlist, 30-step cooldown window, 5% blast-radius circuit breaker. |
| **Response Transactions** | [`src/xrlids/response/transaction.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/transaction.py) | `ControlledResponseTransactionManager` | Atomic lifecycle: IDLE → SNAPSHOT → VALIDATE → PREPARE → APPLY → VERIFY → COMMITTED with compensation rollback. |
| **Isolated Lab Actuator** | [`src/xrlids/enforcement/lab.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/enforcement/lab.py) | `IsolatedLabEnvironment`, `NetnsActuatorBackend` | Operates strictly in network namespace `LAB-ISOLATED-NETNS-01`; verifies zero host network interface mutations. |
| **Replay Lab (10k)** | [`src/xrlids/demo/replay_lab.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/demo/replay_lab.py) | `ReplayLabEngine` | High-throughput streaming replay (6,716 flows/s) of authentic labelled dataset records with full CSV export. |
| **Dashboard & API** | [`dashboard/server.py`](file:///home/rishikesh/Desktop/fyp-xrlids/dashboard/server.py), [`app.js`](file:///home/rishikesh/Desktop/fyp-xrlids/dashboard/app.js) | Python HTTP server + frontend client | Endpoints for benchmarks, dataset explorer, live capture, replay lab, and on-demand TreeSHAP explanation. |

---

## 3. Inviolable Architectural Invariants

1. **Path Separation Invariant**:
   - The CSV evaluation path and 10K Replay Lab are strictly offline research and verification tools. They never feed predictions back into live detection and do not mutate model weights.
   - Live monitoring is strictly observational by default (`response_mode="advisory"`).

2. **Zero Host Network Mutation Guarantee**:
   - Production host firewall modifications (`iptables`, `nftables`, `tc`, routing tables) are strictly prohibited.
   - Any disruptive enforcement is confined exclusively to the isolated lab namespace (`LAB-ISOLATED-NETNS-01`), protected by `HostNetworkBaseline` cryptographic verification before and after transactions.

3. **Detection vs. Response Policy Decoupling**:
   - Classifiers (Random Forest, LSTM, Fusion) output continuous threat risk probabilities ($P(\text{ATTACK})$).
   - The Dueling DQN policy and Deterministic Safety Gate decide what operational action to take. Classifiers never issue network remediation commands directly.

4. **Honest Reporting of Negative Empirical Findings**:
   - While the DQN policy achieved statistically significant cost reductions ($p < 0.001$), it failed the pre-registered practical significance criterion ($\ge 15.0\%$).
   - The zero-parameter analytic `CostOptimalThresholdPolicy` outperformed DQN in 4 of 6 benchmark regimes, confirming the environment acts as an asymmetric-loss contextual bandit with hysteresis.
