# XRL-IDARS — Forensic Audit: Deep Q-Network (DQN) Autonomous Response System

**Document ID:** `AUDIT-DQN-RESP-001`  
**Classification:** Authoritative Technical Audit  
**Author:** Principal Network Security Architect, Senior ML Engineer, and Network Systems Engineer  
**System:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Date:** October 30, 2026  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary

This document establishes the authoritative forensic audit of the autonomous reinforcement learning (RL) mitigation subsystem within XRL-IDARS. The audit systematically examines the 13 core components of the response pipeline, evaluating the mathematical formulation, implementation fidelity, data hygiene, checkpoint provenance, and operational safety.

### Crucial Architectural Invariant: Intrusion Detection vs Autonomous Response
A paramount finding of this audit is the strict operational separation between **detection** and **response**:
1. **Intrusion Detection**: Performed exclusively by the upstream **Random Forest (RF)** model (trained on the R10 feature representation). RF is the **sole operational machine learning classifier**, predicting the continuous attack risk score $S_t = P(\text{ATTACK} \mid \mathbf{x}_t) \in [0.0, 1.0]$.
2. **Autonomous Response**: Performed by the downstream **Dueling Deep Q-Network (DQN)** agent. The DQN is an **action-selection optimization policy**, **NOT** an intrusion detector. It maps an observed 6-dimensional causal operational state vector $\mathbf{s}_t \in \mathbb{R}^6$ to optimal mitigation actions $a_t \in \mathcal{A}$ under an asymmetric cost matrix. Under no circumstances should RF and DQN be combined or reported as a single composite classifier.

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                        XRL-IDARS APPROVED OPERATIONAL PIPELINE                                        |
|                                                                                                                       |
|  Scapy Wire Packets                                                                                                   |
|         │                                                                                                             |
|         ▼                                                                                                             |
|  Canonical FlowEngine ───► R10 Feature Extraction ───► StandardScaler ───► Random Forest Classifier                   |
|                                                                                    │                                  |
|                                                                                    ▼                                  |
|                                                                          Security Event (S_t)                         |
|                                                                                    │                                  |
|         ┌──────────────────────────────────────────────────────────────────────────┴───────────────┐                  |
|         ▼                                                                                          ▼                  |
|  TreeSHAP Explainer                                                                        StateBuilder (6D)          |
|  (Attributions & Rules)                                                                            │                  |
|         │                                                                                          ▼                  |
|         │                                                                                  Dueling DQN Agent          |
|         │                                                                                  (Evaluates Q(s, a))        |
|         │                                                                                          │                  |
|         │                                                                                          ▼                  |
|         │                                                                                Proposed Action a*           |
|         │                                                                                          │                  |
|         │                                                                                          ▼                  |
|         │                                                                               Deterministic Safety Gate     |
|         │                                                                               (Invariants 1-4)              |
|         │                                                                                          │                  |
|         ▼                                                                                          ▼                  |
|  Security Event Enriched ◄─────────────────────────────────────────────────────── Enforced Action a_enforced          |
|         │                                                                                          │                  |
|         ▼                                                                                          ▼                  |
|  Streamlit Dashboard                                                                       Response Executor          |
|  (Telemetry & Visualization)                                                               (Advisory Mode / Dry-Run)  |
+-----------------------------------------------------------------------------------------------------------------------+
```

---

## 2. Component-by-Component Forensic Audit (13 Components)

### Component 1: MDP State Formulation ($\mathcal{S} \subseteq \mathbb{R}^6$)

* **Implementation File:** [`src/xrlids/response/state.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/state.py#L25-L122) (`StateBuilder`)
* **Specification:** `docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md` (`SPEC-P2-AUTONOMOUS-RESPONSE-001` Section 4)

The Markov Decision Process (MDP) state vector is a strictly causal, normalized 6-dimensional telemetry vector:

$$\mathbf{s}_t = \begin{bmatrix} S_t \\ \Delta S_t \\ N_{\text{alert}} \\ a_{t-1} \\ c_t \\ v_t \end{bmatrix} \in \mathbb{R}^6$$

| Dimension | Symbol | Mathematical Formulation | Normalization Bounds | Description & Causal Guarantees |
| :---: | :---: | :--- | :---: | :--- |
| **0** | $S_t$ | $\text{clip}(S_t, 0.0, 1.0)$ | $[0.0, 1.0]$ | **Current Continuous Risk Score** output by frozen Random Forest detector or arbitrated hybrid engine. |
| **1** | $\Delta S_t$ | $S_t - \frac{1}{k} \sum_{i=1}^k S_{t-i}$ | $[-1.0, 1.0]$ | **Risk Score Trajectory** over past $k=5$ flows. Measures rapid threat escalation vs steady decay. |
| **2** | $N_{\text{alert}}$ | $\frac{1}{W} \sum_{i=0}^{W-1} \mathbb{I}(S_{t-i} \ge 0.50)$ | $[0.0, 1.0]$ | **Recent Alert Density** over sliding window $W=20$ flows. Measures sustained attack persistence. |
| **3** | $a_{t-1}$ | $\frac{\text{value}(a_{t-1})}{3.0}$ | $[0.0, 1.0]$ | **Previous Enforced Action**: ALLOW=0.0, ALERT=0.333, RATE_LIMIT=0.667, ISOLATE=1.0. |
| **4** | $c_t$ | $\frac{T_{\text{cooldown\_remaining}}}{30.0}$ | $[0.0, 1.0]$ | **Remaining Cooldown Fraction** on target host ($T_{\text{cooldown}}=30$ steps nominal). |
| **5** | $v_t$ | $\min\left(1.0, \max\left(0.0, \frac{\log_{10}(1.0 + \text{bytes\_per\_s})}{8.0}\right)\right)$ | $[0.0, 1.0]$ | **Normalized Volumetric Scale** log-scaled up to 100 MB/s ($10^8$ B/s). |

#### Strict Invariant Verification
1. **Zero Ground-Truth Label Leakage**: The ground-truth label $y_t \in \{0, 1\}$ is **strictly excluded** from $\mathbf{s}_t$. Label $y_t$ is consumed exclusively by the offline consequence and reward calculation functions.
2. **Strict Causality**: $\mathbf{s}_t$ is computed solely from current flow observations ($\mathbf{v}_t, S_t$) and historical actions up to $t-1$. Future arrivals, future timestamps, and future scores are inaccessible.
3. **Audit Correction / Documentation Discrepancy Note**: Earlier placeholder documentation in [`docs/response/DQN_OVERVIEW.md`](file:///home/rishikesh/Desktop/fyp-xrlids/docs/response/DQN_OVERVIEW.md#L24-L31) listed draft features (e.g. `packet_burst_rate`, `unique_dst_ports`). Code and authoritative specification [`AUTONOMOUS_RESPONSE_SPEC.md`](file:///home/rishikesh/Desktop/fyp-xrlids/docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md) confirm the verified causal vector is $[S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]$.

---

### Component 2: Action Space Formulation ($\mathcal{A}$)

* **Implementation File:** [`src/xrlids/response/types.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/types.py#L11-L36) (`Action`, `ActionSpaceMode`)
* **Specification:** `SPEC-P2-AUTONOMOUS-RESPONSE-001` Section 5

The action space consists of discrete, graded operational interventions designed to balance security against availability:

```
[Level 0: ALLOW] ──────► [Level 1: ALERT] ──────► [Level 2: RATE_LIMIT] ──────► [Level 3: ISOLATE]
(Zero Intervention)     (Audit Logging)         (Traffic Throttling)           (Host Quarantine)
```

| Action Enum | Integer | Token | Simulated Network Consequence | Operational Overhead |
| :--- | :---: | :---: | :--- | :--- |
| `Action.ALLOW` | `0` | `ALLOW` | Traffic forwarded without impediment. 100% bandwidth. | $0.0$ loss on benign; catastrophic breach penalty on attack. |
| `Action.ALERT` | `1` | `ALERT` | Security incident logged; traffic forwarded. | Low log processing overhead ($1.0$ unit); increments alert counter. |
| `Action.RATE_LIMIT` | `2` | `RATE_LIMIT` | Token-bucket rate limiting (100 pkts/s; 90% bandwidth drop). | Moderate availability impact ($15.0$ units); suppresses attack. |
| `Action.ISOLATE` | `3` | `ISOLATE` | Ingress traffic dropped; TCP RST injected; host quarantined. | Severe business disruption ($60.0$ units); complete containment. |

#### Operating Modes
1. **4-Action Mode** (`ActionSpaceMode.FOUR_ACTION`): Full action set $\{\text{ALLOW}, \text{ALERT}, \text{RATE\_LIMIT}, \text{ISOLATE}\}$.
2. **3-Action Mode** (`ActionSpaceMode.THREE_ACTION`): Conservative set $\{\text{ALLOW}, \text{ALERT}, \text{RATE\_LIMIT}\}$. Any proposed `ISOLATE` is clamped downstream to `RATE_LIMIT` by the deterministic safety gate.

---

### Component 3: Cost Dynamics & Reward Function Formulation

* **Implementation File:** [`src/xrlids/response/costs.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/costs.py#L24-L155) (`ResearchCostEngine`, `CostRegime`)
* **Specification:** `SPEC-P2-AUTONOMOUS-RESPONSE-001` Section 7

The composite step reward provided to the reinforcement learning agent is the negative of the total operational cost:

$$R(\mathbf{s}_t, a_t, y_t) = - \Big[ C(a_t, y_t) + C_{\text{chatter}}(a_t, a_{t-1}, c_t) + C_{\text{fatigue}}(N_{\text{alerts}}) \Big]$$

#### 1. Base Asymmetric Cost Matrix $C(a_t, y_t)$ (Research Loss Units)
Costs reflect asymmetric operational penalties under three parameterized regimes:

| Cost Regime | Ground Truth | ALLOW ($a=0$) | ALERT ($a=1$) | RATE_LIMIT ($a=2$) | ISOLATE ($a=3$) | Operational Rationale |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Standard Enterprise** | **Benign ($y=0$)**<br>**Attack ($y=1$)** | $0.0$<br>$100.0$ | $1.0$<br>$12.0$ | $15.0$<br>$6.0$ | $60.0$<br>$2.0$ | Balanced corporate network; penalizes breach heavily, isolation moderately. |
| **High Availability** | **Benign ($y=0$)**<br>**Attack ($y=1$)** | $0.0$<br>$50.0$ | $1.0$<br>$12.0$ | $30.0$<br>$6.0$ | $120.0$<br>$2.0$ | Mission-critical infrastructure; extreme penalty for false isolation ($120.0$). |
| **High Security Enclave** | **Benign ($y=0$)**<br>**Attack ($y=1$)** | $0.0$<br>$500.0$ | $1.0$<br>$20.0$ | $5.0$<br>$10.0$ | $25.0$<br>$2.0$ | Defense / financial core; catastrophic penalty for missed intrusion ($500.0$). |

#### 2. Action Chattering Penalty $C_{\text{chatter}}$
To penalize violent oscillation between disruptive actions during an active stabilization window:
$$C_{\text{chatter}}(a_t, a_{t-1}, c_t) = \begin{cases} 10.0, & \text{if } c_t > 0 \text{ and } |a_t - a_{t-1}| \ge 2 \\ 0.0, & \text{otherwise} \end{cases}$$

#### 3. Analyst Alert Fatigue Penalty $C_{\text{fatigue}}$
To prevent policies from indefinitely emitting alerts without resolving threats:
$$C_{\text{fatigue}}(N_{\text{consec}}) = \max(0, N_{\text{consec}} - 5) \times 0.50$$

#### Research Framing & Decision D-003 Alignment
All cost matrix entries represent **explicit research assumptions** in dimensionless loss units. They do **NOT** represent real financial costs, and they do not constitute an empirical threshold selection under Decision D-003. Production deployments require site-specific cost calibration.

---

### Component 4: Transition Logic & Environment Dynamics

* **Implementation File:** [`src/xrlids/response/environment.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/environment.py#L40-L227) (`OfflineResponseSimulator`)
* **Specification:** `SPEC-P2-AUTONOMOUS-RESPONSE-001` Section 6

The simulation environment steps chronologically through network flows:
1. **Safety Filtering**: The agent's proposed action $a^* \sim \pi(\mathbf{s}_t)$ is filtered through the `DeterministicSafetyGate`, yielding enforced action $a_{\text{enforced}}$.
2. **Simulated Network Consequences**:
   * If `ALLOW` on Attack ($y=1$): Host compromise counter increments ($\text{compromise\_escalated} = \text{True}$).
   * If `ALERT` on Attack ($y=1$): Compromise counter increments; consecutive alert counter advances.
   * If `RATE_LIMIT`: Available bandwidth clamped to $10\%$; attack throttled ($\text{compromise\_halted} = \text{True}$).
   * If `ISOLATE`: Packets dropped ($0\%$ bandwidth); attack contained ($\text{attack\_contained} = \text{True}$). If flow was benign ($y=0$), false outage logged ($\text{false\_outage} = \text{True}$).
3. **State Advance**: Cooldown counters advance; history buffers update; next 6D state $\mathbf{s}_{t+1}$ is constructed.

---

### Component 5: Training Data Isolation & Population Accounting

* **Implementation File:** [`src/xrlids/response/isolation.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/isolation.py#L30-L100)
* **Dataset:** CSE-CIC-IDS2017 (8 capture days)

The project enforces strict three-way data partitioning to guarantee zero test data contamination:

```
Total CIC-IDS2017 Population
   ├── Frozen Phase 1 Training / Validation
   │     ├── D_pol_train (60% of validation pool)  --> 213,518 flows (DQN gradient updates)
   │     └── D_pol_val   (40% of validation pool)  --> 142,346 flows (Checkpoint selection & tuning)
   └── Frozen Phase 1 Test Split
         └── D_pol_test  (STRICTLY HELD-OUT)       --> 355,865 flows (Untouched until final test)
```

#### Row Count Provenance & Resolution of Historical 355,833 vs 355,865
* **Tabular Flow Count ($D_{\text{pol\_test}}$)**: **`355,865`** rows. This is the exact tabular flow population in `split_manifest.json` consumed by Random Forest and the response environment.
* **Sequence Flow Count**: `355,833` rows. Sequence models (LSTM and Fusion) drop the first 4 boundary flows per file across 8 capture files ($355,865 - 8 \times 4 = 355,833$).
* **Verification Status**: Confirmed 100% matched across [`data/processed/phase2_cache/d_pol_test_flows.joblib`](file:///home/rishikesh/Desktop/fyp-xrlids/data/processed/phase2_cache/d_pol_test_flows.joblib).

---

### Component 6: Separation of Detection Classifier vs Response Policy

* **Architectural Boundaries:**
  * **Intrusion Classifier:** Random Forest (`src/xrlids/detection/classifier.py`). Output: Continuous risk $S_t \in [0.0, 1.0]$.
  * **Response Agent:** Dueling DQN (`src/xrlids/response/dqn/agent.py`). Output: Action $a \in \{0, 1, 2, 3\}$.

**Forensic Audit Finding:** The codebase cleanly respects this boundary. The DQN does not have access to raw network packet headers or flow features ($x \in \mathbb{R}^{10}$); it observes only the downstream operational vector $\mathbf{s}_t \in \mathbb{R}^6$. Conversely, the Random Forest does not make policy mitigation decisions.

---

### Component 7: Checkpoint Provenance & Cryptographic Verification

* **Checkpoint Directory:** [`models/dqn/`](file:///home/rishikesh/Desktop/fyp-xrlids/models/dqn/)
* **Parent Experiment:** `results/phase2/EXP-P2B-DQN-001/`

| Artifact Path | Action Space | Training Step | Selection Metric | Validation Mean Cost/Flow | SHA-256 Checksum |
| :--- | :---: | :---: | :--- | :---: | :--- |
| `models/dqn/dqn_4action_best.pt` | 4-Action | 45,000 | `min_val_mean_cost` | $2.2416$ | `6a5afc669b4e699ecd2b1c01df885cef9030c93b8888b487dd386533920ce954` |
| `models/dqn/dqn_3action_best.pt` | 3-Action | 10,000 | `min_val_mean_cost` | $2.0437$ | `d9e03f56e4c7fb38525bfb5fc4cb7e34efbfceeeae2b9cf5b991da9642a8b9ba` |

Both checkpoints were verified by loading state dictionaries and confirming exact step indices and selection metadata.

---

### Component 8: Training History & Algorithmic Mechanics

* **Implementation Files:**
  * `src/xrlids/response/dqn/trainer.py` (`DqnTrainer`)
  * `src/xrlids/response/dqn/replay.py` (`PrioritizedReplayBuffer`)
  * `src/xrlids/response/dqn/schedule.py` (`LinearSchedule`)

#### Algorithmic Parameters
* **Replay Memory**: Prioritized Experience Replay (PER) with capacity $N = 100,000$, exponent $\alpha = 0.6$, importance-sampling exponent $\beta$ annealing from $0.4 \to 1.0$.
* **Optimization**: Huber / Smooth L1 loss with gradient clipping ($\|\mathbf{g}\|_2 \le 10.0$), Adam optimizer ($\eta = 10^{-3}$), discount factor $\gamma = 0.95$.
* **Target Network**: Polyak soft target network update with parameter $\tau_{\text{target}} = 0.005$ executed every gradient step:
  $$\theta_{\text{target}} \leftarrow \tau \theta_{\text{online}} + (1 - \tau) \theta_{\text{target}}$$
* **Exploration**: Linear $\epsilon$-greedy decay from $\epsilon_0 = 1.0$ down to $\epsilon_{\text{end}} = 0.05$ over 50,000 steps.
* **Convergence Evidence**: Training completed across 50,000 steps. Huber loss converged to $0.6124$ (3-action) and $0.6604$ (4-action).

---

### Component 9: Q-Value Interpretation & Dueling Architecture

* **Implementation File:** [`src/xrlids/response/dqn/network.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/dqn/network.py#L16-L100) (`DuelingQNetwork`)

The network decouples the estimation of state value $V(s)$ from the advantages of each action $A(s, a)$:

```
State s_t (6D) ──► Linear(6, 64) ──► LayerNorm ──► LeakyReLU ──► Linear(64, 64) ──► LayerNorm ──► LeakyReLU
                                                                                              │
                                         ┌────────────────────────────────────────────────────┴───────────────────────────┐
                                         ▼                                                                                ▼
                             Linear(64, 32) ──► LeakyReLU ──► Linear(32, 1)                      Linear(64, 32) ──► LeakyReLU ──► Linear(32, 4)
                                         │                                                                                │
                                         ▼                                                                                ▼
                                     Value V(s)                                                                    Advantage A(s, a)
                                         │                                                                                │
                                         └──────────────────────────────────────┬─────────────────────────────────────────┘
                                                                                ▼
                                                               Q(s, a) = V(s) + (A(s, a) - mean_a'(A(s, a')))
```

#### Decision Margin Metric
For explainability auditing, the agent computes the **decision margin**:
$$\Delta Q(s) = Q(s, a^*) - \max_{a \neq a^*} Q(s, a)$$
A small $\Delta Q \approx 0$ indicates policy ambiguity, alerting operators that alternative actions have near-identical expected cost.

---

### Component 10: Deterministic Safety Gate Architecture

* **Implementation File:** [`src/xrlids/response/safety.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/safety.py#L61-L243) (`DeterministicSafetyGate`)
* **Specification:** `SPEC-P2-AUTONOMOUS-RESPONSE-001` Section 14

The safety gate enforces 4 non-bypassable deterministic invariants:

```
Candidate Action a* ~ π(s_t)
            │
            ▼
[Invariant 1: Action Space Mode Clamp]     ──► If 3-Action Mode & a* == ISOLATE ──► Clamp to RATE_LIMIT
            │
            ▼
[Invariant 2: Critical Host Exemption]     ──► If Host in CRITICAL_HOSTS & a* == ISOLATE ──► Demote to ALERT
            │
            ▼
[Invariant 3: Blast Radius Breaker]        ──► If Projected Quarantined > 5% ──► Demote to ALERT
            │
            ▼
[Invariant 4: Mandatory Action Cooldown]   ──► If Cooldown Active & a* == ALLOW ──► Maintain Prior Mitigation
            │
            ▼
Enforced Action a_enforced
```

| Invariant | Trigger Condition | Enforcement Action | Rationale |
| :--- | :--- | :--- | :--- |
| **1. Critical Host Exemption** | Host in `DEFAULT_CRITICAL_HOSTS` (`192.168.10.1`, `192.168.10.50`, etc.) and $a^* = \text{ISOLATE}$ | Enforce `Action.ALERT` | Critical infrastructure (gateway, DNS, identity) must **never** be severed during IP spoofing. |
| **2. Cooldown Hysteresis** | Target host has active cooldown ($c_t > 0$) and $a^* = \text{ALLOW}$ | Enforce prior mitigation (`RATE_LIMIT` or `ISOLATE`) | Prevents network interface flapping and route table thrashing. |
| **3. Blast Radius Circuit Breaker** | $\frac{|\mathcal{H}_{\text{isolated}} \cup \{\text{host}\}|}{\max(|\mathcal{H}_{\text{known}}|, 20)} > 0.05$ | Demote `ISOLATE` to `ALERT` | Caps concurrently isolated endpoints at 5% of monitored network, preventing self-inflicted Denial of Service. |
| **4. Action Mode Clamp** | Mode is 3-Action and $a^* = \text{ISOLATE}$ | Clamp to `Action.RATE_LIMIT` | Respects environment action boundaries. |

---

### Component 11: Response Executor & Advisory Mode

* **Implementation File:** [`src/xrlids/response/executor.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/executor.py#L83-L254) (`ResponseExecutor`)
* **Lifecycle:** `PROPOSED` $\to$ `AUTHORIZED` $\to$ `EXECUTED` $\to$ `VERIFIED` $\to$ `EXPIRED`/`ROLLED_BACK`

#### Advisory Mode Mechanics (`advisory_mode=True`)
* In production and demonstration environments, the system functions in **Advisory / Dry-Run Mode**.
* When an action is authorized and executed:
  1. The simulated backend records an execution report.
  2. The verifier confirms zero collateral impact.
  3. **Zero operating system firewall mutations** (`iptables`, `nftables`, `tc`, eBPF) are executed.
  4. The complete decision, including TreeSHAP feature attributions and Q-margins, is displayed to human operators.

---

### Component 12: Baselines Ladder

* **Implementation File:** [`src/xrlids/response/baselines.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/baselines.py#L28-L418)

| Baseline | Class | Operating Logic | Role in Study |
| :--- | :--- | :--- | :--- |
| **Baseline 0** | `AlwaysAllowPolicy` | Unconditionally outputs `ALLOW`. Zero automated defense. | Lower bound on operational cost; upper bound on breach loss. |
| **Baseline 0-Alert**| `AlwaysAlertPolicy` | Unconditionally outputs `ALERT`. Full audit logging without mitigation. | Assesses cost of pure passive monitoring. |
| **Baseline 1** | `SingleThresholdPolicy` | If $S_t \ge 0.50 \implies \text{ISOLATE}$ (or `RATE_LIMIT`), else `ALLOW`. | Standard industry threshold comparator ($\tau=0.50$). |
| **Baseline 2** | `TwoTierThresholdPolicy` | If $S_t \ge 0.75 \implies \text{ISOLATE}$; if $S_t \ge 0.40 \implies \text{RATE\_LIMIT}$; else `ALLOW`. | Multi-tier graded threshold comparator. Strongest deterministic baseline. |
| **Baseline 3** | `HeuristicStateMachinePolicy`| Stateful finite state machine with alert density tracking, cooldown, and multi-tier escalation. | Advanced deterministic heuristic comparator with memory. |
| **Baseline 4** | `CostOptimalThresholdPolicy` | $a^*(p) = \arg\min_a \mathbb{E}[\text{Loss}(a) \mid p]$ under cost matrix $C(a, y)$. | Analytical cost-optimal decision policy under score-probability model. |

---

### Component 13: Evaluation Protocol, Metrics & Negative Findings Reporting

* **Implementation File:** [`src/xrlids/response/metrics.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/response/metrics.py#L22-L248)
* **Statistical Protocol:** Paired bootstrap hypothesis testing ($B=1,000$ resamples) with 95% empirical confidence intervals.

#### Pre-Registered Criteria Audit & Scientific Integrity

| Pre-Registered Research Question | Target Criterion | Observed Result on Held-Out Test Data | Formal Status |
| :--- | :---: | :---: | :---: |
| **RQ7: Relative Cost Reduction vs Best Baseline** | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ with $p < 0.01$ | $\Delta \mathcal{C}_{\text{rel}} = +14.10\%$ ($p < 0.001$ vs Baseline 2)<br>$\Delta \mathcal{C}_{\text{rel}} = +28.80\%$ ($p < 0.001$ vs Baseline 1) | **Statistical Support ($H_1$ Supported, $p < 0.001$)**<br>**Practical Criterion NOT MET ($< 15.0\%$)** |
| **RQ7.1: Action Chattering Index (ACI)** | $\text{ACI} < 0.01$ ($\le 1$ jump / 100 flows) | $\text{ACI}_{\text{4-act}} = 0.0214$<br>$\text{ACI}_{\text{3-act}} = 0.0019$ | **FAIL (4-action mode)**<br>**PASS (3-action mode)** |
| **RQ7.2: False Quarantine Rate (FQR)** | $\text{FQR} < 2.0\%$ | $\text{FQR}_{\text{4-act}} = 0.20\%$ | **PASS** |
| **RQ7.3: Safety Gate Compliance** | $100\%$ compliance | $100\%$ compliance (0 critical host isolations) | **PASS** |

**Scientific Neutrality Statement:** In alignment with scientific integrity standards, negative findings are reported without post-hoc re-scoping. While DQN achieves statistically significant cost reductions over all baselines ($p < 0.001$), it does not cross the $\ge 15\%$ practical margin over Baseline 2, and exhibits higher chattering in 4-action mode.

---

## 3. Mermaid Response Subsystem Flowchart

```mermaid
flowchart TD
    subgraph Upstream Detection Layer
        A["Scapy Packet Stream"] --> B["Canonical FlowEngine"]
        B --> C["R10 Feature Extraction (10 Features)"]
        C --> D["StandardScaler"]
        D --> E["Random Forest Classifier"]
        E --> F["Continuous Threat Score S_t ∈ [0.0, 1.0]"]
    end

    subgraph Explainability Layer
        E --> G["TreeSHAP Explainer"]
        G --> H["Local SHAP Feature Attributions"]
    end

    subgraph Response Optimization Layer
        F --> I["StateBuilder (6D Causal Observation)"]
        I --> J["s_t = [S_t, ΔS_t, N_alert, a_{t-1}, c_t, v_t]"]
        J --> K["Dueling Deep Q-Network"]
        K --> L["Value V(s) & Advantage A(s, a)"]
        L --> M["Q(s, a) Aggregation & Argmax"]
        M --> N["Proposed Action a* ∈ {ALLOW, ALERT, RATE_LIMIT, ISOLATE}"]
    end

    subgraph Deterministic Safety Gate
        N --> O{"Critical Host Check\n(host ∈ CRITICAL_HOSTS?)"}
        O -- Yes & ISOLATE --> P["Demote to ALERT\n(CRITICAL_INFRASTRUCTURE_EXEMPTION)"]
        O -- No --> Q{"Blast Radius Check\n(quarantined > 5%?)"}
        Q -- Yes & ISOLATE --> R["Demote to ALERT\n(BLAST_RADIUS_CIRCUIT_BREAKER)"]
        Q -- No --> S{"Host Cooldown Check\n(c_t > 0 & a* == ALLOW?)"}
        S -- Yes --> T["Maintain Prior Mitigation\n(MANDATORY_ACTION_COOLDOWN)"]
        S -- No --> U["Approve Action as Proposed"]
        
        P --> V["Enforced Action a_enforced"]
        R --> V
        T --> V
        U --> V
    end

    subgraph Execution & Monitoring Layer
        V --> W["Response Executor\n(Advisory Mode / Zero Kernel Mutation)"]
        H --> X["Enriched Security Event"]
        V --> X
        X --> Y["Streamlit Real-Time Dashboard\n(Telemetry, SHAP Plots, Q-Values)"]
    end
```

---

## 4. Forensic Audit Verdict & Engineering Recommendations

### Audit Verdict: APPROVED WITH GOVERNANCE NOTES
1. **Mathematical & Causal Correctness**: 6D state representation, reward formulation, and dueling Q-network architecture are mathematically sound and strictly causal.
2. **Data Hygiene**: Zero data leakage between training, validation, and held-out test populations.
3. **Safety Invariants**: The `DeterministicSafetyGate` functions as an inviolable, non-bypassable barrier. In all empirical trials, zero critical infrastructure endpoints were isolated.
4. **Advisory Mode**: Complete isolation from kernel network rules guarantees safe lab and demonstration execution.

### Mandatory Operational Recommendations
1. **Maintain Strict Decoupling**: Never present DQN as a detection classifier; maintain RF as the primary detector.
2. **Preserve Advisory Default**: Ensure `advisory_mode=True` remains active in all production scripts and demonstrations.
3. **Retain Baseline Comparators**: In all academic exhibitions, present DQN side-by-side with Baseline 2 (Two-Tier Threshold) and report both statistical significance and practical effect sizes transparently.
