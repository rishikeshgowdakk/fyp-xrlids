# XRL-IDARS — DQN Autonomous Response Policy Specification

**Module:** `src/xrlids/response/service.py` (`DQNResponseService`)  
**Architecture:** Dueling Deep Q-Network (Wang et al., 2016) with LayerNorm and LeakyReLU activations  
**Checkpoints:** `models/dqn/dqn_4action_best.pt` (4 actions), `models/dqn/dqn_3action_best.pt` (3 actions)

---

## 1. Response Problem Formulation & Trade-offs

Autonomous intrusion response requires trading off **security risk reduction** against **operational disruption cost**:
- **Under-response (e.g. allowing an active intrusion):** Leads to data exfiltration, service compromise, and persistence.
- **Over-response (e.g. aggressively isolating benign production servers):** Causes self-inflicted Denial of Service, violating availability requirements.

Heuristic rule-based thresholding (e.g. "always block if $P \ge 0.50$") suffers from severe collateral disruption under false alarms. The XRL-IDARS **Dueling DQN Policy** learns an optimal mapping from a 6-dimensional operational threat state $\mathbf{s}_t$ to response actions by optimizing long-term cumulative negative cost.

---

## 2. 6-Dimensional Causal State Representation ($\mathbf{s}_t$)

At each flow decision step $t$, the state vector is constructed strictly causally without future information:

$$\mathbf{s}_t = \begin{bmatrix} S_t \\ \Delta S_t \\ N_{\text{alert}} \\ a_{t-1} \\ c_t \\ v_t \end{bmatrix} \in \mathbb{R}^6$$

| Dimension | Symbol | Range | Description & Formulation |
|---|---|---|---|
| **0** | $S_t$ | $[0.0, 1.0]$ | Continuous attack posterior probability $P(\text{ATTACK})$ from the champion ML detector. |
| **1** | $\Delta S_t$ | $[-1.0, 1.0]$ | First-order score trajectory: $S_t - \frac{1}{k}\sum_{i=1}^k S_{t-i}$ ($k=5$). Identifies rapid escalation vs. steady-state noise. |
| **2** | $N_{\text{alert}}$ | $[0.0, 1.0]$ | Fraction of recent flows ($W=20$) crossing the alert threshold ($0.50$). |
| **3** | $a_{t-1}$ | $[0.0, 1.0]$ | Normalized previous action: $\text{ALLOW} = 0.0$, $\text{ALERT} = 0.33$, $\text{RATE\_LIMIT} = 0.67$, $\text{ISOLATE} = 1.0$. |
| **4** | $c_t$ | $[0.0, 1.0]$ | Remaining cooldown timer fraction ($\frac{\text{steps\_remaining}}{30}$). Enforces dampening. |
| **5** | $v_t$ | $[0.0, 1.0]$ | Logarithmic coarse volumetric scale: $\min\left(1.0, \frac{\log_{10}(1.0 + \text{bytes/s})}{8.0}\right)$. Distinguishes volumetric bursts. |

---

## 3. Action Space

| Action Index | Action Enum | Real-World Operational Semantics | Disruption Cost |
|---|---|---|---|
| **0** | `ALLOW` | Permit packet transmission without modification. | $0.0$ |
| **1** | `ALERT` | Forward flow, emit high-priority alert to SIEM / audit log. | Low ($0.05$) |
| **2** | `RATE_LIMIT` | Enforce bandwidth throttling / QoS queuing on source IP. | Moderate ($0.30$) |
| **3** | `ISOLATE` | Drop packets / quarantine host at edge boundary. | High ($1.00$) |

---

## 4. Policy Explanation & Q-Value Transparency

The DQN agent outputs the full action-value vector:

$$\mathbf{Q}(\mathbf{s}_t) = \left[Q(\mathbf{s}_t, \text{ALLOW}), Q(\mathbf{s}_t, \text{ALERT}), Q(\mathbf{s}_t, \text{RATE\_LIMIT}), Q(\mathbf{s}_t, \text{ISOLATE})\right]$$

The chosen action is the greedy action $a_t^* = \arg\max_a Q(\mathbf{s}_t, a)$.

Every response recommendation exposes:
- Exact Q-values across all 4 candidate actions.
- The relative Q-value advantage $\Delta Q = Q(s, a^*) - \max_{a \ne a^*} Q(s, a)$.
- State component breakdown explaining which environmental factors (e.g. high alert density or extreme volume) guided the decision.
