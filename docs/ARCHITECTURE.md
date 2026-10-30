# XRL-IDARS — System Architecture & Design Specification

**Document Version:** 2.0.0  
**Project Title:** Explainable Reinforcement Learning-Based Network Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Repository:** `/home/rishikesh/Desktop/fyp-xrlids`  
**GitHub Repository:** `rishikeshgowdakk/fyp-xrlids`  
**Authoritative Reference:** Final-Year Engineering Project Specification & Acceptance Standard  

---

## 1. Problem Statement

Modern high-speed network environments face persistent, sophisticated cyber threats requiring autonomous intrusion detection and incident mitigation. Conventional Network Intrusion Detection Systems (NIDS) exhibit fundamental operational tensions:

1. **Rule-Based Rigidity vs. Generalization:** Deterministic rule engines (e.g., Snort/Suricata signatures) evaluate static traffic patterns and explicit protocol violations with microsecond latency and zero false positives for known signatures, but fail completely against novel attacks, zero-days, or subtly mutated traffic flows.
2. **Black-Box ML & Trust Deficits:** Machine-learning (ML) flow classifiers (Random Forests, neural networks) generalize across complex behavioral patterns, but their decision boundaries are opaque. In high-consequence network security operations, security analysts cannot safely authorize autonomous remediation without verifiable, per-prediction explanations.
3. **Response Policy Gap:** Classification alone ("ATTACK" vs. "BENIGN") does not dictate the optimal response. Naive binary blocking of entire IP subnets causes severe collateral denial-of-service to legitimate users (false positive disruption), whereas conservative inaction allows network compromise. A response system must dynamically weigh security risk against business operational disruption cost.
4. **Offline Benchmarks vs. Live Network Semantics:** Academic intrusion detection benchmarks (e.g., CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) are pre-extracted completed-flow CSV tables. Translating models trained on static datasets to live network packet streams introduces severe timing gaps, feature contract drift, and flow directionality issues that can silently invalidate live detection.

XRL-IDARS addresses these challenges by unifying deterministic rule detection, explainable tabular flow classification (TreeSHAP), and cost-sensitive reinforcement learning response policies (Deep Q-Network) within an auditable, safety-gated architecture.

---

## 2. Primary and Supporting Objectives

### Primary Objective
Deliver a verified, measurable, and reproducible research prototype that combines deterministic rule checking, explainable Random Forest flow classification, and reinforcement-learning-driven response recommendations over live packet streams and held-out benchmark datasets—with zero ungrounded claims, zero fabricated feature attributions, and guaranteed non-mutation of host network firewall state.

### Supporting Objectives
1. **Reliable Bidirectional Flow Assembly:** Construct bidirectional network flows from raw packet streams according to a strict completion policy (TCP FIN/RST termination or 120.0s idle timeout) and extract canonical 10-feature R10 and 4-feature R4 contracts.
2. **Deterministic Security Policy Enforcement:** Execute fast, deterministic rule checks for RFC protocol violations (SYN+FIN, Xmas, NULL), volumetric flood bursts, port scan probes, and spoofed reserved IP addresses independently of ML model weights.
3. **Verified Random Forest Live Detection:** Establish Random Forest as the primary operational ML detector on live flow features, verifying model-preprocessor compatibility and probability calibration.
4. **Genuine Local Explainability:** Provide exact TreeSHAP feature attributions on Random Forest predictions using genuine model trees and actual input vectors, explicitly rejecting fabricated attributions or canned ranking substitutions.
5. **Empirically Evaluated Response Policy:** Formulate autonomous incident response as a Markov Decision Process (MDP) and evaluate Deep Q-Network (DQN) recommendations against established baseline policies on identical held-out benchmark test sets.
6. **Session-Buffered Multi-Model Integration & Safe Fallback:** Establish Random Forest as the primary operational ML detector on live flow features. For flows sharing an active session/host key, `UnifiedInferenceService` buffers a sliding window of $T=5$ consecutive flow vectors to evaluate PyTorch LSTM sequence classification and linear score fusion ($S_{\text{fusion}} = \alpha \cdot S_{\text{rf}} + (1-\alpha) \cdot S_{\text{lstm}}$). For isolated flows or warm-up periods ($T < 5$), the pipeline safely falls back to Random Forest alone without fabricating scores.
7. **Transparent Dashboard & Honest Mode Distinctions:** Visually and programmatically distinguish live network capture (`LIVE`), recorded trace replay (`PCAP`), held-out benchmark evaluation (`DATASET`), and in-memory attack simulation (`SAMPLE`).

---

## 3. Scope and Non-Goals

### In-Scope
- Pure-Python userland PCAP parsing and raw packet ingestion via AF_PACKET sockets or Scapy capture service.
- Bidirectional flow aggregation and feature extraction adhering to the R10 and R4 semantic contracts.
- Deterministic rule engine executing 5 explicit security rules.
- Multi-model inference service unifying Random Forest single-flow inference, session-isolated sequence buffering, PyTorch LSTM evaluation, and validation-tuned convex score fusion.
- TreeSHAP local explanations computing exact base values and signed feature attributions.
- PyTorch Dueling DQN response policy evaluated under 3-action and 4-action action spaces.
- Isolated network namespace (`netns`) container execution for safe dry-run response validation.
- REST API and interactive web console (`/index.html` and `/demo.html`).
- Comprehensive regression testing suite verifying contracts, clean tree state, and latency.

### Non-Goals (Explicit Exclusions)
- **Zero Host Network Mutations:** The system will **never** alter host system `iptables`, `nftables`, routing tables, or hardware firewall state during standard live monitoring or demonstration mode. All policy enforcement is advisory/dry-run by default.
- **No In-Flight Early Flow Intrusion Detection:** Flow-level ML models classify completed flows upon termination or timeout. XRL-IDARS does not claim mid-packet intrusion prevention before flow completion without dedicated packet-level models.
- **No Ungrounded Temporal Parity Claims:** While `UnifiedInferenceService` buffers sequential flows and executes LSTM sequence evaluation when $T=5$ flows accumulate for a session key, real network traffic often contains isolated 1-2 flow bursts that never reach $T=5$. XRL-IDARS does not claim universal temporal sequence parity across fragmented or out-of-order live packet streams.
- **No Fabricated Performance Claims:** Sample simulation scenarios and microbenchmarks are never presented as real network attacks or general real-world detection accuracy.

---

## 4. Target Architecture Diagram

```mermaid
flowchart TD
    subgraph LIVE_PATH["Operational Live / Replay Path (Real-Time Observational & Advisory)"]
        direction TB
        L1["Traffic Source: Raw AF_PACKET / Scapy Sniffer / Paced PCAP / Attack Sim"] --> L2["Packet Parser (Ethernet + IPv4 + TCP/UDP)"]
        L2 --> L3["Bidirectional FlowBuilder (D-006 Policy: FIN/RST or 120s Idle)"]
        L3 --> L4["Canonical Feature Extraction (R10 / R4 Contract)"]
        
        L4 --> L5A["Deterministic Rule Engine\n• RULE-TCP-INVALID-FLAGS\n• RULE-SYN-FLOOD\n• RULE-PORT-SCAN\n• RULE-HIGH-RATE-BURST\n• RULE-IP-SPOOF-RESERVED"]
        L4 --> L5B["Unified Multi-Model Inference Service\n• Primary: Frozen Random Forest\n• Sliding Buffer: Per-Session History (T=5)\n• Recurrent: Supervised LSTM Sequence Model\n• Score Fusion: S_fusion = alpha*S_rf + (1-alpha)*S_lstm"]
        
        L5A --> L6["Evidence & Alert Aggregator\n(Labelled: RF, RF+LSTM_FUSION, RULE, HYBRID, or NONE)"]
        L5B --> L6
        
        L5B -.-> L7["Explainability Engine\n(TreeSHAP Local Attributions on RF)"]
        
        L6 --> L8["Autonomous Response Policy\n(Dueling DQN Action Value Estimation on 6D Causal State)"]
        L8 --> L9["Deterministic Safety Gate\n(Rate Limit, Cooldown, Blast Radius, Critical Host Allowlist)"]
        L9 --> L10["Advisory Action Dispatcher\n(Dry-Run Default / Optional Lab Netns)"]
        
        L6 --> L11["Live Console & REST API\n(/api/live & /demo.html)"]
        L7 --> L11
        L10 --> L11
    end

    subgraph OFFLINE_PATH["Offline Research & Benchmark Path (Multi-Model Verification)"]
        direction TB
        O1["Held-Out Benchmark Split\n(CIC-IDS2017: 355k | CSE-2018: 1.66M | UNSW: 24.5k)"] --> O2["Schema Validation & Label Isolation"]
        O2 --> O3["Compatible Frozen Preprocessor (preprocessor.joblib)"]
        O3 --> O4["Random Forest Evaluation (predict_proba)"]
        O3 --> O5["Optional Baseline: Supervised LSTM (T=5 Causal)"]
        O4 & O5 --> O6["Optional Baseline: RF-LSTM Fusion (Linear Blend)"]
        O4 & O5 & O6 --> O7["Statistical Verification & Metrics Suite\n(Precision, Recall, F1, PR-AUC, Bootstrapped CIs)"]
        O4 -.-> O8["TreeSHAP Summary & Global Feature Importance"]
        O7 --> O9["Reproducible Reports & Audit Cards\n(results/phase1/ & results/phase2/)"]
    end

    style LIVE_PATH fill:#f8fafc,stroke:#2563eb,stroke-width:2px
    style OFFLINE_PATH fill:#faf5ff,stroke:#9333ea,stroke-width:2px
```

---

## 5. Component Responsibilities

| Component | Module Path | Primary Responsibility | Architectural Invariant |
|---|---|---|---|
| **Packet Parser** | `src/xrlids/demo/pcap.py` | Extracts timestamps, endpoints, protocols, and raw TCP flags from wire or PCAP frames. | Pure Python, zero native C-dependencies, handles VLAN 802.1Q tags. |
| **Flow Builder** | `src/xrlids/demo/flow.py` | Canonicalizes bidirectional 5-tuples and tracks packet lengths, byte volumes, and TCP control flags. | Closes flow on FIN/RST or 120s timeout (D-006 policy). |
| **Rule Engine** | `src/xrlids/rules/engine.py` | Evaluates deterministic security rules against completed flows or feature dictionaries. | 100% deterministic; zero ML weights; never mutates RF probabilities. |
| **Random Forest Detector** | `src/xrlids/models/random_forest.py` | Primary live ML detector computing flow attack probabilities. | Model features and preprocessor must match verified training provenance. |
| **Explainability Engine** | `src/xrlids/explainability/` | Computes TreeSHAP feature attributions on Random Forest predictions. | Explains actual input vector using loaded RF tree structure; no canned values. |
| **Dueling DQN Agent** | `src/xrlids/response/dqn.py` | Maps incident state vectors to cost-optimal defensive action recommendations. | Trained with experience replay and target networks; outputs Q-values. |
| **Deterministic Safety Gate** | `src/xrlids/enforcement/gate.py` | Enforces cooldown periods, blast-radius restrictions, and operational preconditions. | Fails closed; enforces advisory dry-run unless cryptographic tokens present. |
| **Live Lab Monitor** | `src/xrlids/demo/live_lab.py` | Glues capture, flow construction, rule checking, ML inference, and alert queuing. | Pure userland observational stream; zero host socket or firewall mutations. |
| **Dashboard Server** | `dashboard/server.py` | Threaded HTTP server exposing REST APIs, static assets, and SSE event channels. | Rebind-safe host validation; strictly separates sample, replay, and benchmark streams. |

---

## 6. Live and Offline Execution Paths

### 6.1 The Live Operational Path
1. **Ingestion:** Raw packets arrive from either an observational Linux raw socket (`AF_PACKET`, requires CAP_NET_RAW), a paced PCAP file replay, or an in-memory packet synthesizer (`attack_sim.py`).
2. **Canonical Flow Assembly:** Packets are grouped by canonical 5-tuple `(min(ep1, ep2), max(ep1, ep2), proto)`. When a TCP FIN or RST flag is observed, or when inter-packet arrival exceeds 120.0 seconds, the flow is finalized.
3. **Contract Extraction:** The 10 R10 features are computed from flow duration, packet arrival deltas, byte sizes, and flag counts.
4. **Dual Detection Evaluation:**
   - The deterministic `RuleEngine` inspects flow characteristics for known violation patterns.
   - The frozen `RandomForest` evaluates the normalized feature vector and outputs attack confidence $p \in [0.0, 1.0]$.
5. **Alert Attribution:**
   - If only the rule triggers: `detection_source="RULE"`, attack score remains raw RF probability.
   - If only RF triggers ($p \ge 0.50$): `detection_source="RF"`, rule list is empty.
   - If both trigger: `detection_source="HYBRID"`.
6. **Explanation (On Demand):** If requested by the user or analyst, TreeSHAP evaluates the exact feature vector against the Random Forest decision paths.
7. **Advisory Response Recommendation:** The DQN policy receives a state vector representing attack confidence, flow volume, and current network state, outputting an advisory action (e.g., `ALLOW`, `ALERT`, `RATE_LIMIT`, `BLOCK`).
8. **Safety & Audit:** The decision is logged to the in-memory observation queue with its timestamp, endpoints, score, and detection source, and broadcast to the dashboard.

### 6.2 The Offline Research & Evaluation Path
1. **Dataset Loading:** Held-out benchmark test partitions (e.g., 355,865 test flows for CIC-IDS2017) are loaded from disk with verified SHA-256 checksums.
2. **Schema & Label Isolation:** Metadata columns (IPs, ports, timestamps) and ground-truth labels (`Label`) are isolated before preprocessing to prevent data leakage.
3. **Preprocessing:** The training-fitted preprocessor (`preprocessor.joblib`) transforms numerical columns without refitting.
4. **Multi-Model Inference:**
   - Random Forest computes tabular class probabilities.
   - Supervised LSTM evaluates causal sequences ($T=5$ past flows).
   - Fusion engine computes linear weighted blend: $S_{fusion} = \alpha S_{RF} + (1-\alpha) S_{LSTM}$.
5. **Statistical Verification:** Computes accuracy, precision, recall, F1, PR-AUC, confusion matrices, and 95% bootstrap confidence intervals across random seeds (42, 123, 456).
6. **Artifact Generation:** Output metrics, ROC/PR curves, and TreeSHAP global importance plots are saved to `results/phase1/` and `results/phase2/`.

---

## 7. Data Flow and Model Contracts

### 7.1 R10 Contract (10 Canonical Features)
Used by **CIC-IDS2017** and **CSE-CIC-IDS2018**:

| Index | Feature Name | Description | Units / Type | Range / Semantics |
|---|---|---|---|---|
| 0 | `flow_duration_ms` | Elapsed time from first to last packet in flow | Milliseconds (float) | $\ge 0.0$ |
| 1 | `flow_packets_per_s` | Total flow packets divided by flow duration in seconds | Packets/second (float) | $\ge 0.0$ |
| 2 | `flow_bytes_per_s` | Total flow bytes divided by flow duration in seconds | Bytes/second (float) | $\ge 0.0$ |
| 3 | `packet_length_mean` | Arithmetic mean of all packet byte sizes in flow | Bytes (float) | $[0.0, 65535.0]$ |
| 4 | `packet_length_std` | Population standard deviation of packet byte sizes | Bytes (float) | $\ge 0.0$ |
| 5 | `syn_count` | Total packets with TCP SYN flag set | Count (float) | $\ge 0.0$, integer value |
| 6 | `ack_count` | Total packets with TCP ACK flag set | Count (float) | $\ge 0.0$, integer value |
| 7 | `rst_count` | Total packets with TCP RST flag set | Count (float) | $\ge 0.0$, integer value |
| 8 | `fin_count` | Total packets with TCP FIN flag set | Count (float) | $\ge 0.0$, integer value |
| 9 | `syn_ack_ratio` | Ratio of SYN count to ACK count: $\frac{\text{syn}}{\max(\text{ack}, 1.0)}$ | Dimensionless (float) | $\ge 0.0$ |

### 7.2 R4 Contract (4 Canonical Features)
Used by **UNSW-NB15** (sensor-degraded baseline):

| Index | Feature Name | Description | Units / Type |
|---|---|---|---|
| 0 | `flow_duration_ms` | Elapsed flow duration | Milliseconds |
| 1 | `flow_packets_per_s` | Packet rate per second | Packets/second |
| 2 | `flow_bytes_per_s` | Byte rate per second | Bytes/second |
| 3 | `packet_length_mean` | Mean packet length | Bytes |

### 7.3 Schema & Contract Enforcement Rules
1. **Zero Silent Fallbacks:** If an input dictionary or CSV row is missing any feature in the active contract, inference raises a `ContractViolationError` or validation error; missing features are **never** replaced with invented defaults.
2. **Non-Finite Value Handling:** Rows containing `NaN`, `+Inf`, `-Inf`, or non-numeric values are rejected at the schema gate and logged in row accounting records.
3. **Single Preprocessing Pass:** Preprocessing is applied exactly once via the fitted `StandardScaler` / pipeline loaded from `preprocessor.joblib`. Models are never fed raw unscaled features when a preprocessor is registered.

---

## 8. Rule, RF, TreeSHAP, and DQN Responsibilities

```mermaid
stateDiagram-v2
    [*] --> Ingestion
    Ingestion --> FlowAggregation
    FlowAggregation --> FeatureContract
    
    state FeatureContract {
        [*] --> DeterministicRules
        [*] --> Random精密Forest
        DeterministicRules --> RuleOutcome: Rule Matches
        Random精密Forest --> MLOutcome: Attack Prob (0-1)
    }
    
    state AlertDecoupling {
        RuleOutcome --> AlertRecord
        MLOutcome --> AlertRecord
    }
    
    AlertRecord --> TreeSHAP: RF Prediction Attribution
    AlertRecord --> DQNPolicy: State Vector Mapping
    DQNPolicy --> SafetyGate: Candidate Action
    SafetyGate --> AdvisoryDispatch: Safe Recommendation
    AdvisoryDispatch --> [*]
```

### 8.1 Deterministic Rule Engine
- **Purpose:** Sub-millisecond policy violation and attack signature detection.
- **Rules:**
  1. `RULE-TCP-INVALID-FLAGS`: Detects SYN+FIN, SYN+RST, Xmas scan (FIN+PSH+URG), and NULL scan (flags=0).
  2. `RULE-SYN-FLOOD`: Detects $\ge 20$ SYNs with 0 ACKs, or $\ge 10$ SYNs with SYN/ACK ratio $\ge 10.0$.
  3. `RULE-PORT-SCAN`: Detects probe flows with $\ge 5$ SYNs and $\le 250$ total bytes.
  4. `RULE-HIGH-RATE-BURST`: Detects volumetric bursts $\ge 50,000$ pkts/s or $\ge 50$ MB/s.
  5. `RULE-IP-SPOOF-RESERVED`: Detects source IP `0.0.0.0` or cross-interface loopback spoofing.
- **Integrity Rule:** Rule triggers are recorded in `rule_matches` and `rule_triggered`. They never mutate the Random Forest confidence score.

### 8.2 Random Forest (Primary ML Detector)
- **Purpose:** Non-linear statistical classification over continuous tabular flow features.
- **Model Architecture:** 100 estimators, balanced class weights, Gini impurity criterion.
- **Contract Compatibility:** Verified against `preprocessor.joblib` and feature names matching `R10_FEATURES` or `R4_FEATURES`.
- **Operational Threshold:** Research threshold $\tau = 0.50$; operational candidate threshold $\tau = 0.85$.

### 8.3 TreeSHAP Explainability
- **Purpose:** Mathematically rigorous local feature attribution for Random Forest predictions.
- **Guarantee:** Computes exact Shapley values via TreeSHAP algorithm ($\sum \phi_i = f(x) - E[f(x)]$).
- **Boundary:** Explains **only** the Random Forest prediction on tabular features. TreeSHAP does **not** explain the DQN policy, the rule engine, or the LSTM sequence model.

### 8.4 Deep Q-Network (DQN) Response Policy
- **Purpose:** Cost-sensitive autonomous incident response recommendation under operational cost penalties.
- **Action Spaces:**
  - **3-Action Regime:** `ALLOW` (0), `RATE_LIMIT` (1), `BLOCK` (2).
  - **4-Action Regime:** `ALLOW` (0), `RATE_LIMIT` (1), `ISOLATE` (2), `BLOCK` (3).
- **State Vector:** Normalized 6-dimensional causal observation vector in $\mathbb{R}^6$:
  $\mathbf{s}_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]$, where $S_t \in [0, 1]$ is the continuous attack confidence score, $\Delta S_t$ is the score trajectory (difference from rolling window mean), $N_{\text{alert}}$ is the local alert density fraction, $a_{t-1}$ is the previous executed action (normalized), $c_t$ is the cooldown timer fraction, and $v_t$ is the normalized flow volumetric rate. Zero attack-family labels or multiclass outputs exist in the DQN state.
- **Cost Formulation:** Evaluated under five operational cost regimes (Standard Enterprise, Mission Critical, Public DMZ, Adversarial Asymmetric, High Availability) penalizing false positive blocks against service disruptions.

---

## 9. Optional LSTM and Fusion Evaluation Role

### 9.1 Experimental Baseline Nature
The supervised Long Short-Term Memory (LSTM) sequence model ($T=5$ causal time steps) and linear score fusion engine ($\alpha S_{RF} + (1-\alpha)S_{LSTM}$) are **strictly offline experimental baselines**.

### 9.2 Evidence and Rationale for Exclusion from Live Path
1. **Empirical Performance Comparison:** Across 355,865 held-out test flows of CIC-IDS2017:
   - **Random Forest:** Accuracy $99.88\% \pm 0.01\%$, F1-Score $0.9972 \pm 0.0003$, ROC-AUC $0.9999 \pm 0.0000$.
   - **Supervised LSTM:** Accuracy $98.42\% \pm 0.12\%$, F1-Score $0.9635 \pm 0.0028$, ROC-AUC $0.9945 \pm 0.0011$.
   - **RF-LSTM Fusion:** Accuracy $99.88\% \pm 0.01\%$, F1-Score $0.9973 \pm 0.0002$, ROC-AUC $0.9999 \pm 0.0000$.
2. **Marginal Value vs. Complexity:** RF alone achieves $0.9972$ F1. Adding the recurrent sequence model yields a negligible $+0.0001$ F1 gain while adding sequence buffering, temporal state tracking, and a $10\times$ inference latency penalty.
3. **Explainability Feasibility:** TreeSHAP provides microsecond, exact explanations for tree ensembles. Explaining recurrent sequence models requires gradient-based or perturbation SHAP (KernelSHAP) which is computationally prohibitive for real-time traffic.
4. **Preservation Commitment:** All LSTM checkpoints (`models/registry/EXP-P1-*-LSTM-*`) and fusion code remain in the repository and are fully tested and reproducible in the offline benchmark evaluation suite.

---

## 10. Safety Boundaries

### 10.1 Advisory / Dry-Run Invariant
The live monitor and dashboard operate in **observational dry-run mode**. Recommended actions from the DQN or rule engine are surfaced in event records and UI badges, but **never** executed against the host operating system's network stack.

### 10.2 Host Protection Guarantees
- **No Host Sudo Subprocesses:** Standard execution spawns no subprocesses invoking `iptables`, `nftables`, `ip route`, or `tc`.
- **Interface Scoping:** Raw socket capture requires CAP_NET_RAW or root permissions, but the socket is opened in read-only mode (`SOCK_RAW`, `ETH_P_ALL`), incapable of injecting or dropping frames.
- **Isolated Lab Netns Sandbox:** Active actuation testing (Phase 3H) is restricted to disposable Linux network namespaces (`xrlids-test-ns`) over virtual ethernet (`veth`) pairs in subnet `10.200.1.0/24`. A baseline audit confirms host firewall state before and after execution; any residual rule aborts the test.
- **Automatic Rollback:** If lab actuation is tested, transactions use atomic state commits with timeout-based automatic rollback (default 30-second watchdog).

---

## 11. Evaluation Methodology

### 11.1 Benchmark Datasets & Splits
1. **CIC-IDS2017 (Flagship Benchmark):**
   - Source: University of New Brunswick / Canadian Institute for Cybersecurity.
   - Total clean records: 2,099,021 flows across 8 CSV files.
   - Partitioning: GroupKFold split by calendar date and attack campaign (temporal hold-out) to prevent data leakage.
   - Held-out test set: 355,865 flows (seed 42).
2. **CSE-CIC-IDS2018 (Enterprise Cloud Benchmark):**
   - Source: AWS infrastructure simulation.
   - Held-out test set: 1,661,216 flows.
3. **UNSW-NB15 (Sensor-Degraded Baseline):**
   - Source: Australian Defence Force Academy.
   - Evaluated under 4-feature contract (R4).
   - Held-out test set: 24,527 flows.

### 11.2 Evaluation Metrics
- **Detection Performance:** Confusion matrices, Precision, Recall, F1-Score, False Positive Rate (FPR), and Area Under the Precision-Recall Curve (PR-AUC).
- **Statistical Significance:** 1,000-sample bootstrap confidence intervals ($95\%$ CI) and 3-seed variance evaluation (seeds 42, 123, 456).
- **Latency Benchmarking:**
  - Flow-feature extraction latency.
  - Random Forest inference latency (with and without scaling).
  - TreeSHAP explanation latency (single vector and batch).
  - End-to-end packet-to-dashboard pipeline latency.
  - Reported via 100-iteration warm-up and percentiles (P50, P90, P95, P99).

---

## 12. Known Limitations

1. **Completed-Flow Timing Constraint:** Because the feature contract requires bidirectional statistical moments (duration, mean packet length, SYN/ACK ratio), classification occurs when a flow completes (via TCP FIN/RST) or when the 120-second idle timeout elapses. The system does not detect attacks mid-flight on the first packet.
2. **Tabular RF Evasion Under Fast Flood Bursts:** As documented in `xrlids.demo.attack_sim`, high-volume fast SYN flood bursts and horizontal port sweeps produce feature shapes (e.g. sub-millisecond durations with high packet rates) that the frozen RF model—trained on benchmark distributions—evaluates as low attack probability ($\le 0.20$). This behavior is preserved honestly and directly motivates the deterministic Rule Engine, which catches these attacks via `RULE-SYN-FLOOD` and `RULE-PORT-SCAN`.
3. **Explainability Boundary:** TreeSHAP feature attributions explain the Random Forest classifier only. They do not explain the DQN Q-value landscape or the rule engine triggers.
4. **Offline Evaluation vs. Live Traffic Shift:** Performance metrics reported on held-out benchmark splits reflect identical distribution conditions. Real-world enterprise traffic subject to protocol variations, MTU differences, or zero-day exploits will exhibit different error profiles.
5. **Sample Simulation Scope:** Packets synthesized in memory by `attack_sim.py` test pipeline plumbing and score calibration; they are synthetic demonstrations and not substitutes for empirical held-out benchmark verification.
