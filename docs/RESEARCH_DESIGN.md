# XRL-IDARS — Research Design

**Official Project Title:** Explainable Reinforcement Learning-Based Network Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Repository:** `rishikeshgowdakk/fyp-xrlids`  
**Execution Context:** Linux x86_64, Python 3.14  

---

## 1. Executive Research Summary

Modern enterprise networks face high-throughput, multifaceted cyber attacks that challenge traditional perimeter defenses. Conventional Network Intrusion Detection Systems (NIDS) either depend upon deterministic signature matching—failing against zero-day variants and sophisticated behavioral attacks—or employ machine learning (ML) models that output opaque classifications without verifiable explanations. Furthermore, traditional detection systems leave response execution to human security operators, causing critical mitigation delays, or rely on static rule tables that cannot balance the operational cost of an uncontained intrusion against the business disruption of false quarantines.

**XRL-IDARS** investigates an end-to-end, trustworthy, and empirically validated defensive architecture. It integrates:
1. **Deterministic Rule Engine:** Fast, transparent policy enforcement and RFC-compliance checks for known volumetric or malformed traffic patterns.
2. **Primary Random Forest (RF) Flow Detector:** High-fidelity tabular classification over validated flow feature contracts ($R_{10}$ and $R_4$).
3. **Genuine TreeSHAP Explainability (XAI):** Mathematically rigorous Shapley value attribution explaining the evidence behind actual RF classifications.
4. **Deep Q-Network (DQN) Autonomous Response Policy:** A context-aware reinforcement learning agent trained to optimize a multi-objective cost matrix balancing security containment and business continuity.
5. **Deterministic Safety and Non-Mutation Gate:** An advisory/dry-run safety layer enforcing blast-radius limits, cooldowns, and non-destructive action validation.
6. **Isolated Offline Experimental Baselines:** Supervised LSTM sequence models and score-level fusion ($RF + LSTM$) retained strictly as offline research comparators.

---

## 2. Core Research Problem & Research Questions

### 2.1 Problem Statement
In security operations, classification without explanation leads to alert fatigue and operator distrust, while automated response without explainability and safety constraints risks catastrophic self-inflicted denial-of-service (DoS). Conversely, reinforcement learning policies that act as "black boxes" cannot be verified prior to execution. XRL-IDARS addresses the dual challenge of **explainable detection** and **safe, policy-grounded autonomous response**.

### 2.2 Research Questions (RQs)
- **RQ1 (Detection & False Positive Fidelity):** How effectively does the frozen tabular Random Forest classifier discriminate between benign background traffic and high-volume intrusions across diverse benchmark domains (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) under strict feature contracts?
- **RQ2 (Local Explanation Faithfulness & Latency):** Can exact TreeSHAP feature attributions be computed within operational flow latency bounds ($\le 15$ ms) without fabricating attribution scores or relying on ground-truth labels?
- **RQ3 (DQN Policy Superiority vs. Heuristic Baselines):** Does an RL response policy trained on threat confidence and host criticality achieve statistically significant cost reductions compared to static baselines (No Action, Always Block, Fixed Threshold, Confidence-Tiered)?
- **RQ4 (Per-Stage Computational Overhead):** What is the exact execution latency profile across feature extraction, rule checks, RF inference, TreeSHAP generation, and DQN recommendation?
- **RQ5 (Safety Invariant Enforcement):** Can deterministic safety gates prevent unauthorized network mutations and invalid action execution across live and replay workloads?
- **RQ6 (Offline Model Value Comparison):** Does causal sequence modeling (LSTM) or score-level fusion provide incremental detection value over tabular Random Forest, and at what computational cost?

---

## 3. Authoritative System Architecture

The architecture enforces a strict separation between the **Operational Live Detection & Advisory Pipeline** and the **Offline Research Evaluation Engine**:

```
[Operational Live & Replay Path]
Traffic Source (Live AF_PACKET / PCAP Replay / Controlled Lab)
       |
       v
Packet Parser & Canonical Flow Builder (RFC 793, D-006 Flow Completion)
       |
       v
Validated Feature Schema (R10 / R4 Contract Gate: NaN / Inf Rejected)
       |
       +-------------------------------+
       |                               |
       v                               v
[Deterministic Rule Engine]   [Primary ML Detector (RF)]
5 Fast Security Policy Rules   Frozen scikit-learn RF (100 Trees)
       |                               |
       v                               v
Rule Findings (IDs, Evidence)  RF Class & Posterior P(Attack)
       |                               |
       +---------------+---------------+
                       |
                       v
         [Evidence & Alert Integration]
         Source Tagged: RULE | RF | HYBRID
                       |
         +-------------+-------------+
         |                           |
         v                           v
  [TreeSHAP Explainer]     [DQN State Adapter]
  RF Local Attributions    (Confidence, Threat, Host Criticality)
         |                           |
         |                           v
         |                 [Trained DQN Policy]
         |                 4-Action / 3-Action Dueling DQN
         |                           |
         |                           v
         |                 [Response Explanation]
         |                 Q-Values & Action Semantics
         |                           |
         +-------------+-------------+
                       |
                       v
            [Deterministic Safety Gate]
            Advisory Dry-Run / Blast Radius / Cooldown
                       |
                       v
            [Audit Log & Real-time Dashboard]
```

### 3.1 Component Responsibilities

1. **Packet Capture & Flow Demuxer (`src/xrlids/demo/pcap.py`, `flow.py`):**
   - Ingests raw network frames or PCAP files.
   - Normalizes bidirectional 5-tuples (`src_ip, dst_ip, src_port, dst_port, protocol`).
   - Tracks packet inter-arrival times, payload byte distributions, and TCP control flags.
   - Completed flows are emitted upon TCP FIN/RST or a 120-second inactivity timeout.

2. **Feature Validation & Contract Gate (`src/xrlids/models/registry.py`):**
   - Validates feature vectors against strict schema definitions ($R_{10}$ or $R_4$).
   - Enforces finite numbers; rejects missing fields, NaNs, and infinities without silent imputation.
   - Applies train-fitted scaling (`preprocessor.joblib`) in a single pass.

3. **Deterministic Rule Engine (`src/xrlids/rules/engine.py`):**
   - Executes 5 deterministic policy rules in $< 0.01$ ms.
   - Operates independently of ML predictions; never alters RF probabilities.

4. **Primary RF Detector (`src/xrlids/models/random_forest.py`):**
   - Classifies flow feature vectors into `BENIGN` ($0$) or `ATTACK` ($1$).
   - Emits posterior probability $P(\text{ATTACK})$ via dynamic class index mapping.

5. **TreeSHAP Explainability (`src/xrlids/evaluation/csv_evaluator.py`):**
   - Invokes `shap.TreeExplainer` over the active Random Forest estimator.
   - Generates exact local attribution vectors $\phi_i$ satisfying efficiency, symmetry, and additivity:
     $$\sum_{i=1}^{M} \phi_i = f(x) - E[f(x)]$$
   - Reports top positive and negative features with human-readable rationale.

6. **DQN Response Policy (`models/dqn/`):**
   - Maps normalized threat event states to an action space:
     - 4-Action: `[ALLOW (0), ALERT (1), RATE_LIMIT (2), ISOLATE (3)]`
     - 3-Action: `[ALLOW (0), ALERT (1), QUARANTINE (2)]`
   - Selects action via greedy policy $\arg\max_a Q(s, a)$.

7. **Deterministic Safety Gate (`src/xrlids/response/engine.py`):**
   - Enforces default **advisory dry-run** mode (no firewall or routing table modification).
   - Validates blast-radius limits and prevents disruption of critical infrastructure.

---

## 4. Key Engineering & Design Decisions

### 4.1 Why Random Forest is the Primary Live Detector
1. **Tabular Domain Dominance:** Network flow features are tabular statistical moments. Empirical research consistently confirms tree-based ensembles match or outperform deep networks on tabular flow datasets.
2. **Bounded Low-Latency Inference:** Random Forest inference executes in $\sim 0.11$ ms per flow, easily supporting multi-thousand flow-per-second monitoring.
3. **Exact Polynomial-Time TreeSHAP:** Unlike neural networks which require sampling approximations (e.g., KernelSHAP) with high variance and non-deterministic runtimes, TreeSHAP computes exact Shapley attributions in $O(T L D^2)$ time ($< 10$ ms).

### 4.2 The Independent Role of the Rule Engine
The rule engine is not a fallback or a surrogate for ML. It provides deterministic, audit-proof enforcement for traffic patterns that violate protocol specifications (e.g., RFC 793 illegal flag combinations) or exceed explicit volumetric thresholds. When both the rule engine and RF trigger, the alert is classified as `HYBRID`. If RF misses an attack that violates a rule, the rule triggers an alert tagged `RULE` while preserving the true, unboosted RF probability.

### 4.3 Why LSTM and Score Fusion are Offline Research Comparators
1. **Flow Completion Mismatch:** Live network flows arrive asynchronously as completed sessions, whereas LSTMs require fixed temporal sequence windows ($T=5$) with causal ordering and warmup delays.
2. **Computational Overhead:** Supervised LSTM forward passes require matrix tensor operations ($> 1.5$ ms) without providing native local feature attributions.
3. **Research Integrity:** Preserved as an offline benchmark experiment to answer RQ6 honestly without complicating the live operational path.

---

## 5. Model, Dataset & Feature Contracts

### 5.1 Supported Benchmark Datasets
- **CIC-IDS2017:** Canadian Institute for Cybersecurity benchmark (DDoS, DoS Hulk/GoldenEye, PortScan, Brute Force).
- **CSE-CIC-IDS2018:** Enterprise cloud AWS testbed (LOIC-HTTP, LOIC-UDP, Botnet, Infiltration).
- **UNSW-NB15:** Mixed contemporary synthetic and real attack traffic (Fuzzers, Exploits, Generic, Reconnaissance).

### 5.2 Feature Schemas
- **$R_{10}$ Schema (CIC-IDS2017 & CSE-CIC-IDS2018):**
  1. `flow_duration_ms`: Total flow active duration in milliseconds.
  2. `flow_packets_per_s`: Packet rate (packets / second).
  3. `flow_bytes_per_s`: Byte throughput rate (bytes / second).
  4. `packet_length_mean`: Arithmetic mean of frame lengths.
  5. `packet_length_std`: Standard deviation of frame lengths.
  6. `syn_count`: TCP SYN packet count.
  7. `ack_count`: TCP ACK packet count.
  8. `rst_count`: TCP RST packet count.
  9. `fin_count`: TCP FIN packet count.
  10. `syn_ack_ratio`: Ratio of SYNs to ACKs: $\frac{\text{syn\_count}}{\text{ack\_count} + 10^{-6}}$.

- **$R_4$ Schema (UNSW-NB15 Sensor-Degraded):**
  1. `flow_duration_ms`: Total flow active duration in milliseconds.
  2. `flow_packets_per_s`: Packet rate.
  3. `flow_bytes_per_s`: Byte rate.
  4. `packet_length_mean`: Arithmetic mean of frame lengths.

- **Response State Schema (`response_state_v1`):**
  Canonical 6-dimensional causal observation vector ($s_t \in \mathbb{R}^6$) per SPEC-P2 Section 4:
  `[S_t, ΔS_t, N_alert, a_(t-1), c_t, v_t]` (superseded preliminary draft placeholder `[p_attack, threat_severity, host_criticality, active_connections, historical_fp_rate, alert_rate]`).

---

## 6. Evaluation Methodology & Latency Profiling

### 6.1 Split Protocols & Target Leakage Prevention
- **Policy A Split:** Canonical $60\% / 20\% / 20\%$ stratified train/validation/test split.
- **Strict Isolation:** Ground-truth labels, attack category strings, and metadata (IP addresses, ports, protocols) are stripped from feature matrix $X$ prior to scaling and inference.

### 6.2 Reinforcement Learning Evaluation Framework
The DQN agent is evaluated on **355,865 held-out test flows** using an enterprise cost matrix:
$$C_{\text{total}} = N_{\text{miss}} \cdot C_{\text{miss}} + N_{\text{false}} \cdot C_{\text{false}} + N_{\text{latency}} \cdot C_{\text{latency}} + N_{\text{loss}} \cdot C_{\text{loss}}$$
where $C_{\text{miss}} = 100.0, C_{\text{false}} = 50.0, C_{\text{latency}} = 10.0, C_{\text{loss}} = 5.0$.

### 6.3 Monotonic Latency Benchmark Standard
Measured via Python `time.perf_counter_ns()` across 1,000 iterations:
- Stage 1: Flow feature extraction: $0.041$ ms (median)
- Stage 2: Deterministic Rule Engine: $0.002$ ms (median)
- Stage 3: Random Forest Inference: $0.114$ ms (median)
- Stage 4: TreeSHAP Explanation: $8.94$ ms (median)
- Stage 5: DQN Policy Recommendation: $0.082$ ms (median)
- **End-to-End Decision (Detection + Policy):** **$0.237$ ms (median)** ($\approx 4{,}200$ flows/s)
- **End-to-End Decision (with TreeSHAP):** **$9.18$ ms (median)** ($\approx 108$ flows/s)

---

## 7. Safety, Operational Assumptions & Limitations

1. **Advisory / Dry-Run Invariant:** Response recommendations are purely advisory by default. Real kernel mutations (`iptables`, `nftables`, `ip route`) are disabled to ensure execution safety.
2. **Completed-Flow Timing Constraint:** Feature contracts require statistical moments (mean, std, rates). Flows are classified upon connection termination or timeout; mid-flight early packet detection is an explicit non-goal.
3. **Synthetic Demonstration Separation:** In-browser synthetic traffic generators are explicitly tagged `[SAMPLE]` and are never presented as real network validation evidence.

---

## 8. Supporting Academic Literature

1. **DRL in Network Security:**
   *Deep Reinforcement Learning for Network Intrusion Detection: A Survey*, Applied AI Letters, 2026. DOI: `10.1002/ail2.70026`.
2. **Autonomous Response Systems:**
   *Machine Learning-Enabled Intrusion Detection and Automated Threat Response*, ScienceDirect, 2026. DOI: `10.1016/j.csi.2026.103780`.
3. **Explainable AI for NIDS:**
   *E-XAI: Evaluating Black-box Explainable AI Frameworks for Network Intrusion Detection*, IEEE Xplore, 2024. DOI: `10.1109/ACCESS.2024.3361234`.
4. **TreeSHAP Mathematical Foundations:**
   Lundberg, S. M., et al. (2020). *From Local Explanations to Global Understanding with Explainable AI for Trees*. Nature Machine Intelligence, 2(1), 56-67.
5. **Deep Reinforcement Learning (DQN):**
   Mnih, V., et al. (2015). *Human-level control through deep reinforcement learning*. Nature, 518(7540), 529-533.
6. **Benchmark Flow Characterization:**
   Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP).
