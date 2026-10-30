# DQN Policy State/Action Contract & Compatibility Audit
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `AUDIT-DQN-CONTRACT-COMPATIBILITY-001`  
**Classification:** Deep RL Contract & Integrity Verification  
**Status:** COMPLETE & FROZEN  

---

## 1. Frozen Checkpoint Provenance

The production mitigation policy operates on a frozen Deep Q-Network checkpoint:
- **Checkpoint File:** `models/dqn/dqn_4action_best.pt` (SHA256 verified)
- **Model Architecture:** Dueling Deep Q-Network (`DuelingQNetwork`)
  - Input Layer: 6-dimensional continuous causal state vector $\mathbf{s}_t \in \mathbb{R}^6$
  - Shared Representation: Linear(6 $\to$ 64, ReLU) $\to$ Linear(64 $\to$ 64, ReLU)
  - Value Stream $V(s)$: Linear(64 $\to$ 32, ReLU) $\to$ Linear(32 $\to$ 1)
  - Advantage Stream $A(s, a)$: Linear(64 $\to$ 32, ReLU) $\to$ Linear(32 $\to$ 4)
  - Q-Aggregation: $Q(s, a) = V(s) + \left(A(s, a) - \frac{1}{|\mathcal{A}|} \sum_{a'} A(s, a')\right)$
- **Inference Mode:** Strictly deterministic evaluation (`torch.no_grad()`, `eval()`). Zero online backpropagation during live packet capture.

---

## 2. Six-Dimensional Causal State Contract

The DQN policy relies on a strictly causal 6D state representation constructed at each flow arrival step $t$:

$$\mathbf{s}_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]^T \in \mathbb{R}^6$$

| State Dimension | Symbol | Domain | Description | Normalization / Formula |
|:---:|:---:|:---:|:---|:---|
| **$s_0$** | $S_t$ | $[0.0, 1.0]$ | Current Threat Posterior | Continuous posterior $P(\text{ATTACK} \mid \mathbf{x}_t)$ from Stage 1 ML champion. |
| **$s_1$** | $\Delta S_t$ | $[-1.0, 1.0]$ | Threat Score Trajectory | Velocity of threat progression: $\Delta S_t = S_t - \frac{1}{k} \sum_{i=1}^k S_{t-i}$ ($k=5$). |
| **$s_2$** | $N_{\text{alert}}$ | $[0.0, 1.0]$ | Recent Alert Density | Fraction of past $W=20$ flows from this host with $S_i \ge 0.50$. |
| **$s_3$** | $a_{t-1}$ | $[0.0, 1.0]$ | Previous Action | Normalized prior action index ($0.0 = \text{ALLOW}, 0.33 = \text{ALERT}, 0.67 = \text{RATE\_LIMIT}, 1.0 = \text{ISOLATE}$). |
| **$s_4$** | $c_t$ | $[0.0, 1.0]$ | Cooldown Remaining | Active cooldown timer: $T_{\text{remaining}} / T_{\text{cool\_max}}$ ($T_{\text{cool\_max}} = 30$ steps). |
| **$s_5$** | $v_t$ | $[0.0, 1.0]$ | Volumetric Feature | Log-scaled throughput: $\min\left(1.0, \frac{\log_{10}(1 + \text{flow\_bytes\_per\_s})}{8.0}\right)$. |

### Invariant Checks
1. **Strict Causality:** Dimensions rely strictly on historical observations up to step $t-1$ and current flow measurement $v_t$. Future flow arrivals and labels $y_t$ are mathematically forbidden.
2. **Dynamic Range Safety:** All inputs are clipped to $[0.0, 1.0]$ (or $[-1.0, 1.0]$ for $\Delta S_t$) ensuring the neural network never receives out-of-distribution floating-point extremes.

---

## 3. Discrete Action Space

The policy maps state $\mathbf{s}_t$ to one of four discrete actions:

| Action Code | Name | Semantic Operational Meaning | Safety Gate Constraint |
|:---:|:---|:---|:---|
| **0** | `ALLOW` | Permit bidirectional traffic without restriction. | Cannot immediately restore if cooldown $c_t > 0$. |
| **1** | `ALERT` | Log high-priority security event; do not shape traffic. | Non-disruptive fallback for critical host violations. |
| **2** | `RATE_LIMIT` | Apply token-bucket traffic shaping (e.g. 100 Kbps clamp). | Critical hosts exempt. Triggers 30s cooldown. |
| **3** | `ISOLATE` | Drop all ingress/egress packets to/from target IP. | Critical hosts exempt. Clamped if blast radius $>5\%$. |

---

## 4. Upstream Score Compatibility Contract

When swapping or upgrading the upstream detection model (e.g., from Random Forest to XGBoost or Multiclass attribution):
- The detector **MUST** output a calibrated posterior $P(\text{ATTACK}) \in [0.0, 1.0]$.
- Arbitrary uncalibrated margins (e.g., raw SVM distances or unnormalized log-odds) must **NEVER** be piped directly into dimension $s_0$, as this distorts the Q-value landscape.
- In XRL-IDARS, both Random Forest (`predict_proba`) and XGBoost (`predict_proba` with logistic loss) satisfy this contract exactly, ensuring seamless drop-in compatibility with the frozen DQN policy.
