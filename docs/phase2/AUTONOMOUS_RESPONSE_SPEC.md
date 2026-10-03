# Phase 2 Research & Design Specification: Explainable Autonomous Response Layer (XRL-IDARS)

- **Document Identifier**: `SPEC-P2-AUTONOMOUS-RESPONSE-001`
- **Current Status**: `PROPOSED RESEARCH SPECIFICATION (PRE-IMPLEMENTATION)`
- **Target Research Question**: `RQ7` (Autonomous Response Intelligence)
- **Author**: Lead Implementation / Research Engineering Agent
- **Date**: `2026-10-03`
- **Parent Governance**: Decision `D-003` (Threshold Governance: $\tau_{\text{research}} = 0.50$ frozen; $\tau_{\text{ops}} = 0.40$ proposed candidate only; operational threshold selection open), Decision `D-006` (Flow Completion Policy)
- **Phase 1 Reference**: Frozen Phase 1 Multi-File Empirical Programme (`EXP-P1-CIC2017-R10-001`, `EXP-P1-CSE2018-R10-MULTI-001`, `EXP-P1-UNSWNB15-R10-MULTI-001`)

---

## 1. Executive Summary & Scientific Purpose

Phase 1 of XRL-IDARS established a scientifically frozen, multi-file intrusion detection foundation across three benchmark suites (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15), proving the predictive discriminability of flow-level Random Forests, sequence-level LSTMs, and score fusion, while rigorously exposing severe covariate degradation under cross-domain transfer (RQ5) and blindspots on stealthy low-footprint attacks (Infiltration recall 10.70%, Web attacks 2.78%).

The objective of **Phase 2** is to address **Research Question 7 (RQ7)**:
> *Can an explainable autonomous response policy, conditioned on continuous detector risk scores and temporal interaction context, select safer and more cost-effective response actions than fixed-threshold or rule-based deterministic policies under explicit asymmetric operational loss?*

This specification establishes the complete theoretical, mathematical, architectural, and experimental blueprint for the Phase 2 autonomous response layer. **In accordance with research governance, zero reinforcement learning (RL) algorithms, firewall mutations, or network blocking implementations are executed within this document.** This specification serves as the pre-registered design protocol against which subsequent Phase 2 implementations must be evaluated.

---

## 2. Problem Definition (RQ7)

### 2.1 The Core Operational Dilemma
Traditional intrusion detection systems rely on static scalar decision thresholds ($\tau \in [0, 1]$) applied to detector scores:
$$\text{Action}_t = \begin{cases} \text{BLOCK/ALERT}, & \text{if } S_t \ge \tau \\ \text{ALLOW}, & \text{if } S_t < \tau \end{cases}$$
Under asymmetric operational realities, static thresholding suffers from fundamental failure modes:
1. **The Stealth Dilemma**: Setting $\tau$ high (e.g., $\tau = 0.75$) minimizes false alarms on benign enterprise traffic but allows low-footprint attacks (whose continuous risk scores frequently fall in $S_t \in [0.40, 0.60]$) to penetrate unimpeded.
2. **The Denial-of-Service Dilemma**: Lowering $\tau$ (e.g., to proposed candidate $\tau_{\text{ops}} = 0.40$) improves stealth recall but risks automated disruption cascades on benign operational bursts, quarantining critical servers or disrupting legitimate business transactions.
3. **Stateless Disconnection**: Static thresholds evaluate each flow in isolation, disregarding attack history, target criticality, past actions, and mitigation efficacy over time.

### 2.2 Formal Research Problem
Given a frozen intrusion detector generating a continuous attack risk score $S_t \in [0, 1]$ for network flows arriving sequentially, determine whether a sequential decision policy $\pi(a_t \mid s_t)$ can optimize cumulative operational utility:
$$\max_{\pi} \mathbb{E} \left[ \sum_{t=0}^T \gamma^t R(s_t, a_t, y_t) \right]$$
where $R(s_t, a_t, y_t)$ reflects explicit asymmetric operational costs for false alarms, missed compromises, service disruptions, and action oscillations.

### 2.3 Explicit Null Hypothesis
- **Null Hypothesis ($H_0$)**: A reinforcement learning response policy does not achieve a statistically significant reduction in cumulative operational cost or mitigation latency compared to an optimal cost-sensitive static threshold policy ($S_t \ge \tau^*$) or heuristic multi-tier rule engines.
- **Alternative Hypothesis ($H_1$)**: Conditioned on dynamic sequence state (score trajectory, alert density, cooldown timer, previous action), a learned response policy achieves lower cumulative cost by selectively applying intermediate throttling and targeted quarantines without triggering false-quarantine cascades.

> [!IMPORTANT]
> **No Assumption of RL Superiority & Neutral Acceptance of $H_0$**: Reinforcement learning is treated strictly as an empirical hypothesis, not an assumed solution. RL introduces training instability, sample inefficiency, action chattering, and policy opacity. If simple deterministic policies achieve equivalent or superior cost profiles, the Null Hypothesis will be formally accepted, and the project will recommend the deterministic baseline.

---

## 3. Frozen Detector Interface

The response layer operates strictly downstream of the frozen Phase 1 detection pipeline. The detector interface is formally frozen to prevent leakage and circular feedback:

```
[Network Traffic Stream]
          │
          ▼
[Flow Constructor (D-006 Hybrid Policy: 120s Idle / FIN-RST)]
          │
          ▼
[Feature Extractor (R10 10-Feature Contract, Schema Hash 9d6c3826...)]
          │
          ▼
[Frozen Feature Scaler (Fitted strictly on Phase 1 Source Train Data)]
          │
          ▼
[Frozen Detector Pipeline (Random Forest / Supervised LSTM / Fusion)]
          │
          ▼
[Continuous Attack Risk Score S_t ∈ [0, 1]]
          │
          ▼
[Phase 2 Autonomous Response Simulation Environment]
```

### Invariants of the Detector Interface:
1. **Read-Only Model Weights**: The Phase 1 tabular Random Forest, sequence LSTM, and score fusion weights are immutable. The response policy cannot backpropagate gradients into, retrain, or modify Phase 1 models.
2. **Continuous Output Contract**: The detector emits a continuous attack risk score $S_t \in [0, 1]$ (such as tree-vote fraction from Random Forest or sigmoid-activated sequence output from LSTM; calibrated probability is reported only where an explicit Platt calibration artifact is applied). The detector does NOT emit hard binary decisions; binary thresholding is replaced by policy action selection.
3. **Zero Target Data Leakage**: In cross-dataset evaluations, detectors remain frozen on source data; the response policy must operate directly on unadapted out-of-domain detector scores.

---

## 4. Minimum Justified State Representation

To avoid the curse of dimensionality and prevent the RL policy from redundantly relearning network flow classification, the state vector $\mathbf{s}_t$ must adhere to strict **Occam's razor**. It must capture only the information necessary for sequential decision-making.

### 4.1 State Vector Components ($d = 6$)

$$\mathbf{s}_t = \Big[ S_t,\; \Delta S_t,\; N_{\text{alert}},\; a_{t-1},\; c_t,\; v_t \Big] \in \mathbb{R}^6$$

| Dimension | Variable | Domain | Physical Meaning & Justification | Source | Possible Leakage / Isolation |
|:---:|:---:|:---:|:---|:---:|:---|
| $s^{(0)}$ | $S_t$ | $[0.0, 1.0]$ | **Current Attack Risk Score**: Primary detector perception indicating immediate flow malignancy. | Frozen Detector Output | Strictly flow $t$; zero future label information. |
| $s^{(1)}$ | $\Delta S_t$ | $[-1.0, 1.0]$ | **Risk Score Trajectory**: $S_t - \bar{S}_{t-k:t-1}$. Captures whether risk is accelerating (burst/campaign) or transient noise. | Buffer of past $k=5$ detector scores | Historical observations up to $t-1$; no leakage. |
| $s^{(2)}$ | $N_{\text{alert}}$ | $[0.0, 1.0]$ | **Recent Alert Density**: Normalized fraction of flows exceeding baseline warning threshold ($\tau=0.50$) in window $W=20$. | Buffer of past $W$ flows | Historical count; reflects sustained hostile intent. |
| $s^{(3)}$ | $a_{t-1}$ | $\{0, 1, 2, 3\}$ | **Previous Action State**: Encodes the action applied at step $t-1$ to prevent rapid policy oscillation / chattering. | Action History | Prior agent decision; strictly causal. |
| $s^{(4)}$ | $c_t$ | $[0.0, 1.0]$ | **Cooldown Timer Fraction**: Remaining fraction of mandatory cooldown period ($c_t = \text{remaining\_steps} / W_{\text{cooldown}}$, where $W_{\text{cooldown}} = 30 \text{ steps} \equiv 30.0\,\text{s}$ at $\Delta t_{\text{step}} = 1.0\,\text{s}$) before disruptive actions can be de-escalated. | Safety Gate State | Operational control variable; prevents flapping. |
| $s^{(5)}$ | $v_t$ | $[0.0, 1.0]$ | **Coarse Volumetric Scale**: $\min(1.0, \log_{10}(1 + \text{bytes/s}) / 8.0)$. Provides context on attack scale (DoS vs stealth payload). | R10 Feature (`flow_bytes_per_s`) | Direct flow measurement; normalized logarithmic rate. |

### 4.2 Explicit Rejection of State Candidates
1. **Rejection of Raw 10 R10 Features**: Duplicating `syn_count`, `packet_length_std`, etc., inside the RL state forces the policy to act as a secondary classifier. The frozen detector already compresses these features into $S_t$.
2. **Rejection of Ground Truth Labels**: Under no circumstances does true label $y_t$ enter $\mathbf{s}_t$.
3. **Rejection of Unbounded Timestamps**: Absolute timestamps violate stationary Markov assumptions; relative cooldowns and windowed counts are used exclusively.

---

## 5. Candidate Action Space & Simulation Boundary

### 5.1 Action Space Definition ($\mathcal{A}$)

The action space consists of discrete, graded response actions:

$$\mathcal{A} = \Big\{ \text{ALLOW (0)},\; \text{ALERT (1)},\; \text{RATE\_LIMIT (2)},\; \text{ISOLATE (3)} \Big\}$$

| Action ID | Action Token | Operational Semantics | System Disruption Level | Intended Security Target |
|:---:|:---|:---|:---:|:---|
| **0** | `ALLOW` | Permit packet transit without intervention or logging overhead. | Zero disruption | Normal benign operational traffic. |
| **1** | `ALERT` | Forward flow telemetry to SIEM/SOC; no packet disruption. | Negligible (analyst triage cost) | Ambiguous / borderline risk flows ($S_t \approx 0.45$). |
| **2** | `RATE_LIMIT` | Simulated bandwidth throttling (token-bucket drop to 10% rate). | Moderate (latency / throughput penalty) | Volumetric floods, brute-force scans, DoS. |
| **3** | `ISOLATE` | Simulated endpoint quarantine (drop flow + TCP RST injection). | Severe (total communication disruption) | Critical compromised hosts, confirmed exploits. |

### 5.2 Scoping for Initial Phase 2 Studies
To ensure stable policy learning and avoid premature convergence to trivial extremes:
- **Phase 2A / 2B Initial Evaluation**: Will benchmark a **3-action space** (`ALLOW`, `ALERT`, `RATE_LIMIT`) vs the **full 4-action space** (`ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`).
- Evaluating the 3-action space first prevents the policy from relying on irreversible total isolation before proving its ability to manage graded rate-limiting.

### 5.3 Strict Simulation Boundary
All action execution in Phase 2 is **strictly simulated within the offline replay environment**:
- No Linux kernel modifications (`iptables`, `nftables`, `tc`, `ebtables`).
- No socket packet dropping or interface disconnection.
- No network infrastructure configuration changes.
The simulator models the state transitions and cost consequences of actions mathematically.

---

## 6. Offline Response Simulator Design

To enable reproducible, zero-risk RL training and evaluation, an **Offline Response Simulator** will execute against ordered flow streams from designated policy partitions.

The dataset isolation protocol strictly follows:
```text
Phase 1 detector:
    frozen

Policy-development population:
    designated policy-training portion (D_pol_train)
    designated policy-validation portion (D_pol_val)

Final policy test population:
    completely untouched until final evaluation (D_pol_test)
```

The simulator engine supports replaying any configured flow split, but the experimental protocol strictly confines RL policy exploration, training, and hyperparameter tuning to the designated policy-development partitions (`D_pol_train` and `D_pol_val`). The final policy test population remains completely untouched until final benchmark evaluation. Under no circumstances may future flows or ground-truth labels enter the current policy state.

```
┌──────────────────────────────────────────────────────────────────┐
│                   Offline Replay Simulator                       │
│                                                                  │
│  [Ordered Flow Stream (Designated Policy Split: D_pol_train/val)]│
│                            │                                     │
│                            ▼                                     │
│  Flow Extractor ──► Frozen Detector ──► Attack Risk Score S_t    │
│                                                   │              │
│                                                   ▼              │
│  State Builder ◄── Action / Cooldown State ── State s_t          │
│        │                                          │              │
│        ▼                                          ▼              │
│  Response Policy (Baseline / DQN) ───────► Proposed Action a_t   │
│                                                   │              │
│                                                   ▼              │
│  Deterministic Safety Gate ──────────────► Enforced Action a_t'  │
│                                                   │              │
│                                                   ▼              │
│  Consequence Engine ◄── Ground Truth Label y_t ── Operational    │
│                                                   Cost C(a_t', y)│
│                                                   │              │
│                                                   ▼              │
│  Environment Step ─────────────────────────► Next State s_{t+1}  │
│                                              Reward R_t = -C     │
└──────────────────────────────────────────────────────────────────┘
```

### 6.1 Simulation Execution Rules
1. **Time-Series Ordering**: Flows are ingested strictly in chronological capture order within each source capture session.
2. **Session / Host Grouping**: Flows are partitioned by endpoint identifier (`src_ip` or session ID), modeling response impact on specific hosts.
3. **Temporal Causality**: The state builder observes only flows up to step $t$; future flows and future labels are strictly inaccessible.
4. **Offline Evaluation Guarantee**: The simulation operates entirely in memory on pre-recorded dataset artifacts.

### 6.2 Simulated Transition Assumptions & Modeling Boundaries
All state progression, endpoint compromise, and action consequences inside the simulator are explicit **simulated transition assumptions**:
1. **Delayed Compromise Accumulation**: The model assumption that an unmitigated attack flow ($a_t=\text{ALLOW}, y_t=1$) compounds compromise state or elevates subsequent risk within that session is a **simulated transition assumption**, NOT an empirical property directly observed or recorded in the Phase 1 static CSV records.
2. **Simulated Action Consequences**: Actions such as `RATE_LIMIT` (assumed to throttle flow throughput by 90%) and `ISOLATE` (assumed to terminate session communication) are idealized **simulated transition assumptions**. They require sensitivity analysis across transition parameters.
3. **No Empirical Claim of Physical Dynamics**: The Phase 1 datasets provide ground-truth labeled flows; the downstream consequence engine, host compromise progression, and mitigation feedback loops are synthetic modeling constructs. They do not constitute empirical proof that physical enterprise networks exhibit these exact state dynamics.

---

## 7. Cost & Reward Model: Illustrative Research Cost Framework

Under Decision `D-003`, research reporting threshold $\tau_{\text{research}} = 0.50$ is frozen for benchmark reporting, $\tau_{\text{ops}} = 0.40$ is strictly a proposed Phase 2 operational candidate, and operational threshold selection remains explicitly OPEN pending deployment-specific cost/loss evidence.

Therefore, the Phase 2 cost model is formulated NOT as a selection or resolution of a real-world deployment threshold, but as **an illustrative research cost framework used to evaluate response policies under controlled asymmetric-loss regimes**. It does NOT select or resolve the real deployment threshold.

### 7.1 Illustrative Baseline Research Cost Matrix ($C_{\text{base}}$)

> [!IMPORTANT]
> **Research Assumptions Only**: The specific numerical loss values below (e.g., missed attack = 100.0, benign isolation = 60.0, rate-limit degradation = 15.0, alert triage = 1.0) are explicit **research assumptions** established to create controlled asymmetric loss gradients. They do **NOT** represent real, empirically calibrated enterprise financial costs. Any physical production deployment would require site-specific risk assessments and empirical cost calibration before deployment.

Costs are expressed in dimensionless research loss units:

| Ground Truth ($y_t$) | `ALLOW` ($a=0$) | `ALERT` ($a=1$) | `RATE_LIMIT` ($a=2$) | `ISOLATE` ($a=3$) |
|:---|:---:|:---:|:---:|:---:|
| **Benign ($y=0$)** | **0.0** (Ideal baseline) | **1.0** (Research assumption: triage overhead) | **15.0** (Research assumption: degraded service) | **60.0** (Research assumption: false outage / DoS) |
| **Attack ($y=1$)** | **100.0** (Research assumption: uncontained breach) | **12.0** (Research assumption: logged, but uncontained) | **6.0** (Research assumption: attack throttled) | **2.0** (Research assumption: attack contained) |

### 7.2 Dynamic Penalties for Policy Stability
In addition to static state-action costs, the reward function penalizes unstable operational behavior:
1. **Action Chattering Penalty ($C_{\text{chatter}}$)**:
   $$C_{\text{chatter}} = \begin{cases} 10.0, & \text{if } |a_t - a_{t-1}| \ge 2 \text{ and endpoint under active cooldown } (c_t > 0, \text{ i.e., } \Delta t_{\text{steps}} < W_{\text{cooldown}}) \\ 0.0, & \text{otherwise} \end{cases}$$
   Penalizes rapid jumping between `ISOLATE` and `ALLOW` during the 30-step ($30.0\,\text{s}$ nominal) cooldown window, preventing destructive oscillation.
2. **Alert Fatigue Penalty ($C_{\text{fatigue}}$)**:
   $$C_{\text{fatigue}} = 0.5 \times \max(0, N_{\text{consecutive\_alerts}} - 5)$$
   Penalizes generating continuous uncontained alerts without taking mitigating action.

### 7.3 Composite Step Reward
$$R(s_t, a_t, y_t) = -\Big[ C(a_t, y_t) + C_{\text{chatter}}(a_t, a_{t-1}) + C_{\text{fatigue}} \Big]$$

### 7.4 Multi-Regime Sensitivity Analysis

Because numerical loss parameters are research assumptions rather than universal physical constants, Phase 2 evaluations must conduct sensitivity analysis across three distinct asymmetric loss regimes rather than overfitting to a single arbitrary matrix:

| Cost Regime | $C(\text{ALLOW}, \text{Atk})$ | $C(\text{ISO}, \text{Ben})$ | $C(\text{RL}, \text{Ben})$ | Parameterized Research Model |
|:---|:---:|:---:|:---:|:---|
| **Regime A: High Availability** | 50.0 | 120.0 | 30.0 | Parameterized model prioritizing uptime; high penalty for false outages. |
| **Regime B: Standard Enterprise (Default)** | 100.0 | 60.0 | 15.0 | Balanced parameterized model between mitigation and availability. |
| **Regime C: High Security Enclave** | 500.0 | 25.0 | 5.0 | Parameterized model prioritizing containment; high penalty for uncontained breaches. |

These regimes are parameterized research assumptions. They demonstrate that optimal policy behavior depends fundamentally on external operational loss parameters rather than intrinsic model properties, reaffirming that operational threshold selection remains an open, deployment-specific decision.

---

## 8. Deterministic Baseline Policies

Before evaluating any reinforcement learning agent, Phase 2 establishes **four deterministic baselines**. The learned policy must demonstrate statistically significant improvement over these simpler, transparent rules:

```
Baseline Ladder for Autonomous Response:
┌────────────────────────────────────────────────────────────────────────┐
│ Level 0: Always-ALLOW Policy (Zero Automated Defense)                  │
├────────────────────────────────────────────────────────────────────────┤
│ Level 1: Deterministic Single-Threshold Policy (τ = 0.50 Research)     │
├────────────────────────────────────────────────────────────────────────┤
│ Level 2: Exploratory Two-Tier Static Threshold Policy (0.40 / 0.75)    │
├────────────────────────────────────────────────────────────────────────┤
│ Level 3: Deterministic Rule-Based State Machine                        │
├────────────────────────────────────────────────────────────────────────┤
│ Level 4: Candidate RL Agent (DQN)                                      │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Baseline 0 (Always-ALLOW)**:
   $$a_t = \text{ALLOW} \quad \forall t$$
   Measures raw unmitigated breach damage across the evaluation dataset.
2. **Baseline 1 (Deterministic Single-Threshold Policy, $\tau = 0.50$)**:
   $$a_t = \begin{cases} \text{ISOLATE}, & \text{if } S_t \ge 0.50 \\ \text{ALLOW}, & \text{if } S_t < 0.50 \end{cases}$$
   Evaluates response actions under the frozen academic research reporting boundary ($\tau = 0.50$). This serves as a standard experimental baseline comparator, not an operational deployment recommendation.
3. **Baseline 2 (Exploratory Two-Tier Static Threshold Policy, $\tau_1 = 0.40, \tau_2 = 0.75$)**:
   Evaluates an exploratory two-tier tiered response baseline using proposed candidate operating points:
   $$a_t = \begin{cases} \text{ISOLATE}, & \text{if } S_t \ge 0.75 \text{ (High confidence attack; min-FPR candidate)} \\ \text{RATE\_LIMIT}, & \text{if } 0.40 \le S_t < 0.75 \text{ (Suspect flow; proposed Phase 2 candidate)} \\ \text{ALLOW}, & \text{if } S_t < 0.40 \text{ (Low risk / baseline benign)} \end{cases}$$
   > [!NOTE]
   > Neither Baseline 1 ($\tau = 0.50$) nor Baseline 2 ($\tau = 0.40 / 0.75$) constitutes a Decision `D-003` deployment-threshold decision. These baselines are experimental comparators for evaluating multi-tier graded actions against single thresholds; operational threshold selection remains open.
4. **Baseline 3 (Heuristic State Machine / Rule Engine)**:
   Deterministic rule engine with memory:
   - Escalates from `ALLOW` $\to$ `ALERT` on first suspect flow ($S_t \ge 0.40$).
   - Escalates to `RATE_LIMIT` if $\ge 3$ alerts occur within 10 flows.
   - Escalates to `ISOLATE` if $S_t \ge 0.85$ or if attack persists under rate-limiting.
   - Enforces a 30-step ($30.0\,\text{s}$ nominal) cooldown before de-escalation.

---

## 9. Reinforcement Learning Formulation (DQN Candidate)

Deep Q-Learning (DQN) is formulated as the initial RL candidate architecture:

### 9.1 Network Architecture
- **Input**: State vector $\mathbf{s}_t \in \mathbb{R}^6$.
- **Hidden Layers**: Fully connected MLP with 2 hidden layers (64 units, 64 units), LayerNorm, and LeakyReLU activations.
- **Output**: Action-value vector $Q(\mathbf{s}_t, a) \in \mathbb{R}^4$.
- **Dueling Architecture**: Decomposes state value $V(\mathbf{s})$ and action advantage $A(\mathbf{s}, a)$ to stabilize training in environments where action choices rarely change step-to-step:
  $$Q(\mathbf{s}, a) = V(\mathbf{s}) + \left( A(\mathbf{s}, a) - \frac{1}{|\mathcal{A}|} \sum_{a'} A(\mathbf{s}, a') \right)$$

### 9.2 Training Hyperparameters & Stabilization
- **Loss Function**: Smooth L1 (Huber) loss on Bellman error.
- **Discount Factor ($\gamma$)**: $\gamma = 0.95$ (balances immediate mitigation with session-long impact).
- **Target Network**: Polyak soft parameter updates ($\tau_{\text{target}} = 0.005$) per step.
- **Exploration**: $\epsilon$-greedy schedule decaying from $\epsilon_0 = 1.0$ to $\epsilon_{\text{min}} = 0.05$ over 50,000 steps.
- **Replay Buffer**: Prioritized Experience Replay (PER, capacity 100,000 transitions, $\alpha_{\text{per}} = 0.6, \beta_{\text{per}} = 0.4 \to 1.0$).

### 9.3 Episode Construction & Boundary Enforcement
- Episodes are constructed from continuous capture sessions of length $T_{\text{ep}} = 100$ flows.
- Episodes terminate either when $T_{\text{ep}}$ is reached or when a terminal isolation action occurs on a confirmed attack session.

---

## 10. Evaluation Protocol & Multi-Dimensional Metrics

Autonomous response evaluation cannot rely on classification accuracy or ROC-AUC. Performance must be measured via operational efficiency, safety, and stability metrics:

1. **Cumulative Operational Cost ($\mathcal{C}_{\text{total}}$)**:
   $$\mathcal{C}_{\text{total}} = \sum_{t=1}^T C(a_t, y_t)$$
   Primary optimization target.
2. **Mitigation Delay ($\bar{\Delta}_{\text{contain}}$)**:
   Mean number of flow steps elapsed from the first attack flow in an intrusion campaign to the first mitigating action (`RATE_LIMIT` or `ISOLATE`).
3. **False Quarantine Rate ($\text{FQR}$)**:
   Fraction of benign flows erroneously subjected to `ISOLATE`:
   $$\text{FQR} = \frac{\sum_{t} \mathbb{I}(a_t = \text{ISOLATE} \land y_t = 0)}{\sum_t \mathbb{I}(y_t = 0)}$$
4. **Action Chattering Index ($\text{ACI}$)**:
   $$\text{ACI} = \frac{1}{T-1} \sum_{t=2}^T \mathbb{I}(|a_t - a_{t-1}| \ge 2)$$
   Measures violent policy oscillation between severe containment and total passivity.
5. **Business Availability Score ($\text{BAS}$)**:
   Percentage of benign flows that pass completely uninterrupted (`ALLOW`):
   $$\text{BAS} = \frac{\sum_{t} \mathbb{I}(a_t = \text{ALLOW} \land y_t = 0)}{\sum_t \mathbb{I}(y_t = 0)} \times 100\%$$
6. **Cost Reduction vs. Baselines ($\Delta \mathcal{C}$)**:
   $$\Delta \mathcal{C}_{\text{rel}} = \frac{\mathcal{C}_{\text{baseline}} - \mathcal{C}_{\text{DQN}}}{\mathcal{C}_{\text{baseline}}} \times 100\%$$
   Evaluated with paired bootstrap confidence intervals (95% CI, $B=1000$).

---

## 11. Experimental Isolation & Anti-Leakage Protocol

To ensure rigorous scientific validity, the evaluation protocol establishes an unambiguous three-tier population hierarchy:

```text
Phase 1 detector:
    frozen

Policy-development population:
    designated policy-training portion (D_pol_train)
    designated policy-validation portion (D_pol_val)

Final policy test population:
    completely untouched until final evaluation (D_pol_test)
```

```
Dataset Partitioning Strategy for Phase 2:
┌─────────────────────────────────────────────────────────────┐
│ Phase 1 Source Training Data (Frozen)                        │
│ ──► Used exclusively for Phase 1 Detector Training          │
├─────────────────────────────────────────────────────────────┤
│ Phase 1 Validation Data (Partitioned)                       │
│ ├── Sub-Partition 1 (60%): RL Policy Training (D_pol_train) │
│ └── Sub-Partition 2 (40%): RL Policy Validation (D_pol_val) │
├─────────────────────────────────────────────────────────────┤
│ Phase 1 Test Data (Completely Held-Out)                     │
│ ──► Final Benchmark Comparison (D_pol_test)                 │
└─────────────────────────────────────────────────────────────┘
```

1. **Zero Detector Retraining**: Detectors produce frozen feature representations with fixed parameters.
2. **Strict Final Test Isolation**: The final policy test population (355,833 CIC flows; 1,662,419 CSE flows; 24,496 UNSW flows) remains **completely untouched and unseen** during RL exploration, policy training, baseline tuning, or hyperparameter selection. It is evaluated strictly once during the final comparative study.
3. **Temporal Causality & Information Isolation**: State vectors and replay buffers are constructed sequentially from historical observations only; no future flows, future timestamps, or ground-truth labels are accessible to the agent during policy execution.

---

## 12. Robustness Experiments Against Phase 1 Findings

Phase 1 empirical findings proved that detectors suffer from severe out-of-domain degradation (RQ5) and stealth attack blindspots (RQ1). Phase 2 must evaluate whether autonomous response intelligence remains safe under these real-world failure modes:

| Robustness Stress Test | Empirical Phenomenon Simulated | Failure Mode to Monitor | Pass / Safe Operating Criteria |
|:---|:---|:---|:---|
| **1. Out-of-Domain Covariate Shift** | Ingesting transfer data (`CIC → CSE` transfer where detector F1 collapsed to 0.3286). | Policy triggering massive false isolation cascades due to elevated baseline scores. | Policy must gracefully de-escalate to `ALERT` or `ALLOW`; FQR must not exceed 2.0%. |
| **2. Stealth Attack Campaigns** | Evaluating on Infiltration and Web Attack sequences where detector scores hover at $S_t \in [0.40, 0.55]$. | Complete containment failure (all flows allowed). | Temporal escalation: Policy must escalate to `RATE_LIMIT` upon observing persistent borderline scores. |
| **3. Benign Traffic Spikes** | Injecting 10x packet rate bursts into benign flows. | False rate-limiting on legitimate heavy transfers. | Policy must recognize benign flag signatures and avoid disruptive action. |
| **4. Adversarial Score Jitter** | Adding Gaussian noise $\mathcal{N}(0, \sigma^2)$ to detector output $S_t$. | Policy chattering and state thrashing. | Action Chattering Index (ACI) must remain $< 0.05$. |

---

## 13. Dual-Layer Explainability Architecture

A critical tenet of XRL-IDARS is that autonomous action must never be an uninterpretable black box. Phase 2 introduces a **Dual-Layer Explainability Framework**:

```
Flow Arrival ──► [Layer 1: Perception Explainability]
                       │
                       ├─► Attributed Flow Features (TreeSHAP)
                       │   "Why did the detector flag this flow as risky?"
                       │   (e.g., packet_length_std, rst_count)
                       ▼
                 [Layer 2: Response Policy Explainability]
                       │
                       ├─► Action Advantage Decomposition (Q-Values)
                       │   "Why did the policy choose ISOLATE over RATE_LIMIT?"
                       ├─► State Feature Attribution (Integrated Gradients)
                       │   (e.g., recent alert density was 0.85, cooldown expired)
                       ▼
                 [Action Decision Audit Card (Generated per intervention)]
```

### Action Decision Audit Card Format (JSON & Markdown):
```json
{
  "timestamp": "2026-10-04T12:00:00Z",
  "flow_id": "flow-10293",
  "enforced_action": "RATE_LIMIT",
  "perception_layer": {
    "detector_score": 0.5421,
    "top_contributing_features": [
      {"feature": "packet_length_std", "shap_value": 0.0841},
      {"feature": "flow_packets_per_s", "shap_value": 0.0520}
    ]
  },
  "policy_layer": {
    "q_values": {
      "ALLOW": -45.2,
      "ALERT": -18.1,
      "RATE_LIMIT": -6.4,
      "ISOLATE": -24.8
    },
    "decision_margin": 11.7,
    "driving_state_factors": [
      "Alert density accelerated (+0.35 over window)",
      "Target service is non-critical infrastructure"
    ]
  },
  "safety_gate": {
    "invariants_checked": ["NOT_GATEWAY_DNS", "COOLDOWN_ACTIVE"],
    "action_overruled": false
  }
}
```

---

## 14. Deterministic Safety Architecture & Non-Bypassable Invariants

The reinforcement learning agent is **not allowed to directly manipulate simulated network execution**. All policy recommendations pass through a hard deterministic **Safety Gate**:

$$\text{Action}_{\text{proposed}} \sim \pi(s_t) \;\xrightarrow{\quad}\; \boxed{\text{Deterministic Safety Gate}} \;\xrightarrow{\quad}\; \text{Action}_{\text{enforced}}$$

### Inviolable Safety Invariants:
1. **Critical Infrastructure Exemption**:
   - Flows targeting designated infrastructure endpoints (Default Gateway, Core DNS, Identity Provider, Health Monitors) **can never be isolated**:
     $$\text{If } \text{dst\_ip} \in \text{CRITICAL\_HOSTS} \land a_{\text{proposed}} = \text{ISOLATE} \implies a_{\text{enforced}} = \text{ALERT}$$
2. **Mandatory Action Cooldown**:
   - Once a disruptive action (`RATE_LIMIT` or `ISOLATE`) is executed on an endpoint, the action cannot be toggled back to `ALLOW` within cooldown window $W_{\text{cooldown}} = 30$ discrete flow-arrival steps. Because source network flows (e.g. CIC-IDS2017) lack sub-second physical timestamp monotonicity (with timestamps absent or non-monotonic across files, as audited in Phase 1 split manifests), the offline simulation environment models decision epochs as discrete arrival steps with nominal step duration $\Delta t_{\text{step}} = 1.0\,\text{s}$, establishing the exact mathematical relation:
     $$T_{\text{cool}} = W_{\text{cooldown}} \times \Delta t_{\text{step}} = 30 \text{ steps} \times 1.0\,\text{s/step} = 30.0\,\text{seconds}$$
   - If an action change back to `ALLOW` is requested within this cooldown window, the safety gate maintains the previous disruptive action without extending the cooldown timer.
3. **Blast Radius Circuit Breaker**:
   - The safety gate monitors the global fraction of currently isolated endpoints. If total isolated hosts exceed 5.0% of the active network inventory, all subsequent `ISOLATE` actions are automatically downgraded to `ALERT` and a high-priority operator alarm is raised.

---

## 15. Formally Defined Phase 2 Research Questions

> [!IMPORTANT]
> **Pre-Registered Proposed Research Study Criteria**: The quantitative targets below ($\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$, $p < 0.01$, $\text{ACI} < 0.01$, $\text{FQR} < 2.0\%$) are **pre-registered proposed research study criteria**, NOT empirically established facts or guaranteed performance promises. They serve as objective benchmarks to test whether reinforcement learning justifies its operational complexity.
>
> **Neutral Null Hypothesis Acceptance**: The experimental framework is designed with strict scientific neutrality. If empirical evaluation demonstrates that deterministic baseline policies (such as the heuristic state machine or exploratory two-tier threshold) achieve equivalent or superior cost profiles compared to the learned policy, the Null Hypothesis ($H_0$) will be formally accepted, and the project will recommend the simpler deterministic solution.

| Question ID | Formulation | Pre-Registered Proposed Research Study Criteria |
|:---|:---|:---|
| **RQ7** (Primary) | Can an autonomous reinforcement learning policy achieve lower cumulative operational cost than fixed-threshold and rule-based baselines under asymmetric cost matrices? | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ cost reduction over best deterministic baseline with $p < 0.01$ (paired bootstrap). |
| **RQ7.1** | Can stateful action representations and cooldown invariants eliminate action chattering? | Action Chattering Index (ACI) $< 0.01$ (less than 1 chattering transition per 100 flows). |
| **RQ7.2** | Does the response policy maintain safe bounds under cross-dataset domain shift (RQ5 transfer degradation)? | False Quarantine Rate (FQR) $< 2.0\%$ on out-of-domain transfer datasets without retraining. |
| **RQ7.3** | Does the dual-layer explainability architecture reliably expose the perception vs. policy drivers of every automated response? | 100% of non-ALLOW actions accompanied by valid TreeSHAP + Q-margin audit records. |

---

## 16. Phased Implementation Roadmap

Phase 2 implementation will proceed in five strictly sequenced, auditable stages:

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 2A: Environment & Deterministic Baselines             │
│ - Gym-compatible offline flow replay simulator              │
│ - Cost matrix engine & dynamic reward evaluator             │
│ - 4 Deterministic baseline policies (ALLOW, Threshold, Rule)│
├─────────────────────────────────────────────────────────────┤
│ Phase 2B: Reinforcement Learning Candidate (DQN)            │
│ - Dueling DQN architecture with Prioritized Experience      │
│ - Offline training pipeline on D_pol_train                  │
├─────────────────────────────────────────────────────────────┤
│ Phase 2C: Validation, Ablation & Sensitivity Study          │
│ - Cost matrix sensitivity sweep (Regimes A, B, C)           │
│ - State vector component ablation                           │
├─────────────────────────────────────────────────────────────┤
│ Phase 2D: Cross-Dataset Robustness & Failure Injection      │
│ - Evaluation on out-of-domain transfer traffic (RQ5)        │
│ - Stealth attack campaign containment evaluation            │
├─────────────────────────────────────────────────────────────┤
│ Phase 2E: Explainability Engine & Safety Invariant Harness  │
│ - Dual-layer audit card generator                           │
│ - Deterministic safety gate & blast radius circuit breaker  │
└─────────────────────────────────────────────────────────────┘
```

> [!CAUTION]
> **Safety Invariant for Phase 2 Development**: All Phase 2 stages remain **simulation-only**. No actual packet dropping, firewall mutations, or network isolation commands are to be executed.
