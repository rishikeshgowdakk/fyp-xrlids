# Phase 2 Final Research Report: Autonomous Response Intelligence & Explainability Engine

**Document Identifier**: `REPORT-P2-AUTONOMOUS-RESPONSE-001`  
**Specification Reference**: [`SPEC-P2-AUTONOMOUS-RESPONSE-001`](AUTONOMOUS_RESPONSE_SPEC.md)  
**Parent Detector Benchmark**: `EXP-P1-CIC2017-R10-001` (Random Forest, 10 Features, $\tau_{\text{research}}=0.50$ Frozen)  
**Authoritative Test Population**: Held-Out $D_{\text{pol\_test}}$ (`355,865` Tabular Flows)  
**Date**: October 4, 2026  
**Status**: `AUDITED UNDER PRE-REGISTERED CRITERIA — PENDING FINAL SCIENTIFIC FREEZE`  

---

## Executive Summary & Epistemological Taxonomy

This report synthesizes the empirical research programme for Phase 2 of XRL-IDARS (Intrusion Detection and Autonomous Response System), executing the five-stage research roadmap defined in [`SPEC-P2-AUTONOMOUS-RESPONSE-001`](AUTONOMOUS_RESPONSE_SPEC.md):
- **Phase 2A**: Reproducible Offline Response Environment & Deterministic Baseline Ladder (`EXP-P2A-BASELINES-001`)
- **Phase 2B**: Deep Q-Network (Dueling DQN + PER) Candidate Benchmark (`EXP-P2B-DQN-001`)
- **Phase 2C**: State Feature Ablation & Sensitivity Study (`EXP-P2C-SENSITIVITY-001`)
- **Phase 2D**: Cross-Dataset Domain Shift & Failure Injection Stress Tests (`EXP-P2D-ROBUSTNESS-001`)
- **Phase 2E**: Dual-Layer Explainability Engine & Safety Invariant Audit Harness (`EXP-P2E-EXPLAINABILITY-001`)
- **Final Comparative Evaluation**: Single, Authoritative Pass on Completely Held-Out $D_{\text{pol\_test}}$ (`EXP-P2-FINAL-TEST-001`)

### Strict Epistemological Distinctions

To ensure scientific integrity, all findings throughout this report are categorized under three distinct epistemological tiers:
1. **EMPIRICALLY OBSERVED**: Direct, reproducible measurements computed on benchmark traffic populations (e.g., flow counts, false quarantine rates, action chattering transitions, TreeSHAP attributions, and paired bootstrap statistics).
2. **SIMULATED RESEARCH ASSUMPTIONS**: Parameterized cost models ($C_{\text{miss}}=100, C_{\text{FP}}=60$, etc.) and state transition dynamics adopted strictly as controlled research instruments to evaluate policy behavior under asymmetric loss. They do **not** represent verified enterprise accounting data or physical operational losses.
3. **PROPOSED STUDY CRITERIA**: Pre-registered quantitative hypothesis thresholds ($\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$, $p < 0.01$, $\text{ACI} < 0.01$, $\text{FQR} < 2.0\%$). These serve as objective criteria to test whether reinforcement learning justifies its operational overhead; they are **not** commercial guarantees.

---

## Pre-Registered Criteria Outcomes & Hypothesis Status

The final comparative evaluation was executed on the completely held-out test split ($D_{\text{pol\_test}}$, 355,865 tabular flows) with all model weights, threshold parameters, and baseline configurations frozen prior to evaluation:

| Research Question | Pre-Registered Target Criterion | Best Deterministic Comparator | Empirical Result on $D_{\text{pol\_test}}$ | Independent Classification | Formal Hypothesis Status |
|:---|:---|:---|:---|:---:|:---:|
| **RQ7 (3-Action)** | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ cost reduction vs best deterministic baseline, $p < 0.01$ | Baseline 2: Two-Tier ($\tau=0.40/0.75$) | $\Delta \mathcal{C}_{\text{rel}} = \mathbf{+11.29\%}$ ($p < 0.001$, 95% CI: $[-0.1919, -0.1691]$; vs B1: $+15.99\%$) | **NOT MET** | **$H_0$ Upheld** (Statistically significant improvement below 15% effect size) |
| **RQ7 (4-Action)** | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ cost reduction vs best deterministic baseline, $p < 0.01$ | Baseline 2: Two-Tier ($\tau=0.40/0.75$) | $\Delta \mathcal{C}_{\text{rel}} = \mathbf{+14.10\%}$ ($p < 0.001$, 95% CI: $[-0.9147, -0.8312]$; vs B1: $+28.80\%$) | **NOT MET** | **$H_0$ Upheld** (Statistically significant improvement below 15% effect size) |
| **RQ7.1** | Action Chattering Index (ACI) $< 0.01$ ($\le 1$ jump per 100 flows) | N/A | $\text{ACI}_{\text{3-act}} = \mathbf{0.0019}$, $\text{ACI}_{\text{4-act}} = \mathbf{0.0214}$ | **PARTIAL** | 3-action **PASS**; 4-action **FAIL** |
| **RQ7.2** | Out-of-domain transfer safety bound: $\text{FQR} < 2.0\%$ | N/A | $\text{FQR}_{\text{transfer}} = \mathbf{0.51\%}$, $\text{BAS} = \mathbf{97.69\%}$ on CSE-CIC-IDS2018 | **PASS** | $H_1$ Supported |
| **RQ7.2 (Noise)** | Continuous score jitter stability: $\text{ACI} < 0.05$ across $\sigma \in [0.0, 0.20]$ | N/A | $\text{ACI} \approx \mathbf{0.106 - 0.111} > 0.05$ across all $\sigma$; $\text{FQR} \le 0.53\%$ | **FAIL** | Negative Robustness Finding |
| **RQ7.3** | 100% of non-ALLOW actions accompanied by valid TreeSHAP + Q-margin Audit Cards | N/A | **100.00% Coverage** across all 28,168 non-ALLOW interventions | **PASS** | Mandate Fully Met |

> [!IMPORTANT]
> **Resolution of RQ7 Hypothesis Testing**:
> In accordance with pre-registered scientific methodology, RQ7 requires comparing the learned policy against the **BEST** deterministic baseline. On held-out test data across all cost regimes, Baseline 2 (Two-Tier Graded Threshold) is the lowest-cost deterministic comparator (achieving 569,978.0 in 3-action and 2,206,220.5 in 4-action).
> While the DQN candidate achieves statistically significant cost reductions over Baseline 2 ($p < 0.001$), the relative effect sizes ($+11.29\%$ in 3-action, $+14.10\%$ in 4-action) fall below the pre-registered effect size threshold ($\ge 15.0\%$).
> Therefore, **$H_0$ is upheld regarding the pre-registered effect size criterion**. We report this negative finding with full transparency and do not redefine the comparator post-hoc to Baseline 1 (Single Threshold) merely to manufacture an artificial pass.

---

## 1. System Architecture & Simulator Causality Audit

The Phase 2 research architecture couples the frozen Phase 1 perception engine with an offline response simulation environment:

```text
┌─────────────────────────────────────────────────────────────┐
│ Frozen Phase 1 Perception Engine (EXP-P1-CIC2017-R10-001)   │
│ - Tabular Random Forest (10 R10 features, 100 trees)        │
│ - Produces continuous threat score S_t in [0.0, 1.0]        │
└──────────────────────────────┬──────────────────────────────┘
                               │ Flow Risk Score S_t
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Causal State Vector Builder (dim=6, zero target leakage)    │
│ s_t = [S_t, ΔS_t, N_alert, a_(t-1), c_t, v_t]              │
└──────────────────────────────┬──────────────────────────────┘
                               │ State s_t
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Response Policy Candidates                                  │
│ - Baselines 0..3 (ALLOW, Single-Threshold, Two-Tier, State) │
│ - Learned Dueling DQN Candidates (3-action & 4-action)      │
└──────────────────────────────┬──────────────────────────────┘
                               │ Proposed Action a_proposed
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Deterministic Safety Gate (Hard Non-Bypassable Invariants)  │
│ 1. Critical Infrastructure Exemption (Gateway/DNS)          │
│ 2. Mandatory Action Cooldown (T_cool = 30 steps / 30.0s)    │
│ 3. Blast Radius Circuit Breaker (Max 5.0% isolated hosts)   │
│ 4. Action Space Mode Clamp (3-action vs 4-action)           │
└──────────────────────────────┬──────────────────────────────┘
                               │ Enforced Action a_enforced
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Simulated Consequence & Dynamic Cost Evaluator              │
│ - Multi-Regime Asymmetric Loss Engine                       │
│ - Host compromise progression & mitigation delay tracking   │
└──────────────────────────────┬──────────────────────────────┘
                               │ Step Records
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Dual-Layer Explainability Engine (SPEC Section 13)          │
│ - Layer 1: Perception Feature Attributions (TreeSHAP)       │
│ - Layer 2: Response Policy Q-Value Advantage Decompositions │
│ - Action Decision Audit Cards (100% intervention coverage)  │
└─────────────────────────────────────────────────────────────┘
```

### Forensic Simulator Causality Audit

A rigorous forensic audit of `src/xrlids/response/environment.py` established the exact causal boundary of the response simulator:
1. **Contextual Sequential Process**: The simulator operates as a contextual sequential decision process evaluated over an ordered, exogenous network flow trace.
2. **Action Feedback to State**: Action selection causally influences future policy-observable state through three mechanisms:
   - Previous action normalization $a_{t-1}$ (Dimension 3);
   - Host active cooldown fraction $c_t$ (Dimension 4);
   - Downstream safety gate tracking (active isolated host population bounding blast radius).
3. **Exogenous Flow Trace**: The incoming flow sequence $[x_0, x_1, \dots, x_N]$ is an exogenous historical trace. Actions taken at step $t$ do not mutate the packet headers, arrival times, or flow features of future incoming traffic.
4. **Internal Consequence Tracking**: The simulator maintains hidden state `_host_compromise_state` for cumulative operational cost accounting and mitigation delay tracking. This internal variable tracks breach escalation under `ALLOW` and `ALERT`, but is strictly isolated from the observation vector $s_t$.
5. **No Target Leakage**: True binary labels $y \in \{0, 1\}$ are accessed exclusively by the cost engine for simulated consequence evaluation; they are never observed by the state builder or policy network.

---

## 2. Population Accounting & Authoritative Test Isolation

The policy development stream was systematically partitioned from the frozen Phase 1 population using deterministic seeding (`seed=42`):

```text
Phase 1 CIC-IDS2017 Deduplicated Population (1,779,322 Rows)
├── Training Split (60%): 1,067,592 rows  ──► Frozen Phase 1 Detector Training
├── Validation Split (20%): 355,865 rows
│   ├── Sub-Partition 1 (60%): D_pol_train (213,519 rows) ──► Phase 2 DQN Offline Training
│   └── Sub-Partition 2 (40%): D_pol_val   (142,346 rows) ──► Checkpoint Selection & Ablation
└── Test Split (20%): D_pol_test (355,865 rows) ─────────────► Strictly Held-Out Final Evaluation
```

### Authoritative Resolution of Row Count Provenance

- **355,865 Tabular Flows**: The full deduplicated test population recorded in `split_manifest.json` contains exactly 355,865 flows. Because Phase 2 consumes tabular flow features from the primary Random Forest detector, **355,865** is the authoritative population count for all Phase 2 held-out tabular policy evaluations.
- **355,833 Sequence Rows (Historical Phase 1 Note)**: In Phase 1 sequence evaluations (Supervised LSTM and Score Fusion), sequence construction with window $T=5$ dropped the first 4 boundary flows per file across 8 capture files ($8 \times 4 = 32$ boundary drops), yielding $355,865 - 32 = 355,833$ sequences.
- **Zero Test Contamination**: Held-out $D_{\text{pol\_test}}$ was accessed strictly once after freezing all policy weights, baseline hyperparameters, and sensitivity configurations.

---

## 3. Phase 2A: Deterministic Baseline Ladder (Validation Population)

Phase 2A established empirical reference baselines on the policy development validation split ($D_{\text{pol\_val}}$, 142,346 flows) across three research cost regimes:

| Policy Identifier | Policy Name & Description | Action Mode | Standard Enterprise Total Cost | High Availability Total Cost | High Security Enclave Total Cost | Business Availability (BAS) | Action Chattering (ACI) |
|:---|:---|:---:|---:|---:|---:|---:|---:|
| **Baseline 0** | Always ALLOW (Passive reference lower bound) | Passive | 2,592,800.0 | 1,296,400.0 | 12,964,000.0 | 100.00% | 0.0000 |
| **Baseline 1** | Single Threshold ($\tau=0.50$, Binary comparator) | 3-action | 440,536.0 | 462,506.0 | 624,620.0 | 97.99% | 0.3165 |
| **Baseline 1** | Single Threshold ($\tau=0.50$, Binary comparator) | 4-action | 371,678.5 | 391,758.5 | 613,339.5 | 97.99% | 0.0898 |
| **Baseline 2** | Two-Tier Threshold ($\tau_{\text{suspect}}=0.40, \tau_{\text{isolate}}=0.75$) | 3-action | **427,527.0** | **443,842.0** | **607,869.0** | 97.87% | 0.3078 |
| **Baseline 2** | Two-Tier Threshold ($\tau_{\text{suspect}}=0.40, \tau_{\text{isolate}}=0.75$) | 4-action | 376,299.0 | 400,819.0 | **603,987.0** | 97.87% | 0.0990 |
| **Baseline 3** | Heuristic State Machine (Escalation comparator) | 3-action | 1,806,318.0 | 3,366,998.0 | 877,034.0 | 8.32% | 0.1183 |
| **Baseline 3** | Heuristic State Machine (Escalation comparator) | 4-action | 1,196,420.0 | 1,818,940.0 | 1,007,154.0 | 1.52% | 0.0771 |

### Baseline Insights:
1. **Always ALLOW (Baseline 0)** incurs severe uncontained compromise penalties ($2.59\text{M}$ cost in Standard Enterprise, $12.96\text{M}$ in Enclave).
2. **Two-Tier Threshold (Baseline 2)** achieved the lowest cumulative cost in 3-action mode on validation ($427,527.0$ vs Baseline 1's $440,536.0$), demonstrating the value of graded escalation (throttling suspect traffic while isolating severe threats). In 4-action mode on validation, Baseline 1 ($371,678.5$) and Baseline 2 ($376,299.0$) are separated by only 1.2%, while on the held-out test split ($D_{\text{pol\_test}}$, 355,865 flows; Section 8), Baseline 2 is strictly the superior deterministic comparator across both action modes.
3. **Heuristic State Machine (Baseline 3)** suffers severe availability penalties ($\text{BAS} = 1.52\% - 8.32\%$) due to aggressive escalation without proportionate de-escalation dampening.

---

## 4. Phase 2B: DQN Architecture & Training Configuration

The Deep Q-Network candidate policy was trained on $D_{\text{pol\_train}}$ (213,519 flows). The parameters below reflect the authoritative machine-generated record in `results/phase2/EXP-P2B-DQN-001/training_config.json`:

```text
Dueling DQN Network Architecture:
Input State s_t (dim=6): [S_t, ΔS_t, N_alert, a_(t-1), c_t, v_t]
  └── Linear(6 -> 64) -> LayerNorm -> LeakyReLU(negative_slope=0.01)
        └── Linear(64 -> 64) -> LayerNorm -> LeakyReLU(negative_slope=0.01)
              ├── Value Stream:       Linear(64 -> 32) -> LeakyReLU -> Linear(32 -> 1)        [V(s)]
              └── Advantage Stream:   Linear(64 -> 32) -> LeakyReLU -> Linear(32 -> |A|)      [A(s, a)]
Q(s, a) = V(s) + (A(s, a) - (1/|A|) * SUM_a' A(s, a'))
```

### Authoritative Training Hyperparameters:
- **State Representation Dimension**: 6
- **Hidden Layer Topology**: `[64, 64]` with `LayerNorm` and `LeakyReLU`
- **Architecture**: Dueling DQN with mean-subtracted advantage stream
- **Optimizer**: Adam ($\text{learning\_rate} = 0.001$)
- **Discount Factor**: $\gamma = 0.95$
- **Exploration Schedule**: $\epsilon$-greedy ($\epsilon_0 = 1.0 \to 0.05$ decayed linearly over 50,000 steps)
- **Replay Buffer**: Prioritized Experience Replay ($N=100,000$ capacity, $\alpha=0.6$, $\beta_0=0.4 \to 1.0$)
- **Target Network Update**: Polyak soft updates ($\tau = 0.005$ per step)
- **Training Steps**: 50,000 environment steps per action mode
- **Batch Size**: 64 transitions

### Validation Checkpoint Selection ($D_{\text{pol\_val}}$):
- **3-Action Mode**: Checkpoint at step 30,000 achieved minimum validation cost ($203,639.5$).
- **4-Action Mode**: Checkpoint at step 40,000 achieved minimum validation cost ($739,788.0$).

---

## 5. Phase 2C: State Feature Ablation & Sensitivity Study

Phase 2C evaluated the empirical contributions of individual state features and safety gate parameters on $D_{\text{pol\_val}}$ (`EXP-P2C-SENSITIVITY-001`):

### State Feature Ablation (Authoritative Artifact: `state_ablation_results.json`)

Each ablation condition masked one state dimension to 0 and evaluated on $D_{\text{pol\_val}}$:

| Condition ID | Ablated Component | Total Cost | Mean Cost/Flow | FQR | BAS | ACI | Mitigation Delay | Delta Cost vs Full | Empirical Interpretation |
|:---|:---|---:|---:|---:|---:|---:|---:|---:|:---|
| `full_state` | Full 6D Causal State | 348,930.0 | 2.4513 | 0.53% | 88.22% | 0.1136 | 26.9 steps | 0.00% | Reference 6D representation |
| `ablate_volumetric_context` | Ablate $v_t$ (Dim 5) | 344,995.0 | 2.4236 | 0.45% | 94.51% | 0.1144 | 27.8 steps | **-1.13%** | Volumetric feature is slightly redundant/noisy |
| `ablate_cooldown_state` | Ablate $c_t$ (Dim 4) | 348,930.0 | 2.4513 | 0.53% | 88.22% | 0.1136 | 26.9 steps | **+0.00%** | Safety gate enforces cooldown downstream |
| `ablate_score_trajectory` | Ablate $\Delta S_t$ (Dim 1) | 354,135.0 | 2.4878 | 0.41% | 97.79% | 0.1022 | 30.2 steps | **+1.49%** | Rate-of-change provides modest benefit |
| `ablate_current_score` | Ablate $S_t$ (Dim 0) | 354,454.0 | 2.4901 | 0.48% | 96.15% | 0.1125 | 28.5 steps | **+1.58%** | Threat score provides modest benefit |
| `ablate_alert_density` | Ablate $N_{\text{alert}}$ (Dim 2) | 355,862.0 | 2.5000 | 0.27% | 98.52% | 0.1121 | 28.8 steps | **+1.99%** | Alert memory aids persistent burst tracking |
| `ablate_previous_action` | Ablate $a_{t-1}$ (Dim 3) | 372,660.0 | 2.6180 | 0.37% | 98.21% | 0.0925 | 35.5 steps | **+6.80%** | **Highest impact**: feedback anchors policy dynamics |

### Reconciled Ablation Conclusions:
1. **Previous Action Feedback ($a_{t-1}$)** is the single most influential state dimension (+6.80% cost increase, mitigation delay increases from 26.9 to 35.5 steps).
2. **Volumetric Context ($v_t$)** is redundant in this benchmark; removing it slightly improves policy cost (-1.13%).
3. **Cooldown State ($c_t$)** produces identical cost (+0.00%) on this replay trace because the downstream `DeterministicSafetyGate` enforces cooldown constraints regardless of whether the policy network observes $c_t$.
4. **All features are NOT strictly necessary**: The hypothesis that every 6D dimension is required for optimal performance is **refuted** by the empirical data.

---

## 6. Phase 2D: Cross-Dataset Robustness & Failure Injection

Phase 2D evaluated response policy stability across out-of-domain transfer, stealth campaigns, traffic surges, and sensor jitter (`EXP-P2D-ROBUSTNESS-001`):

| Robustness Stress Test | Simulated Stress Condition | Observed Policy Behavior | Safe Bound Metric | Status |
|:---|:---|:---|:---|:---:|
| **1. Out-of-Domain Transfer** (`CIC → CSE`) | Covariate shift (Phase 1 detector F1 collapsed to 0.3286) | Policy safely de-escalated to `ALERT` (12.4%) and `ALLOW` (87.1%); zero quarantine cascades. | $\text{FQR} = \mathbf{0.51\%} < 2.0\%$, $\text{BAS} = \mathbf{97.69\%}$ | **PASS** |
| **2. Stealth Attack Campaigns** | Low-footprint attacks hovering in $S_t \in [0.40, 0.55]$ | Graded escalation: 10% to 46% non-ALLOW interventions; Brute Force (24% ISOLATE) and XSS (42% ISOLATE) contained; Infiltration and SQLi uncontained (0% ISOLATE, 50-step delay). 0% RATE_LIMIT. | Low-to-moderate escalation (10%–46%); zero RATE_LIMIT triggered | **PARTIAL** |
| **3. Benign Volumetric Spikes** | 10x packet/byte volume injected into benign flows | Rate-limiting bounded at 0.07%; zero disruption storms. | $\text{FQR} = \mathbf{0.20\%}$, $\text{BAS} = \mathbf{96.52\%}$ | **PASS** |
| **4. Sensor Score Jitter** | Gaussian noise $\mathcal{N}(0, \sigma^2)$ on $S_t$ ($\sigma \le 0.20$) | Chattering index remained elevated ($\text{ACI} \approx 0.106 - 0.111$). | $\text{ACI} < 0.05$ target | **FAIL** (Negative Finding) |

### Reconciled Stealth Attack Campaign Findings:
As documented in `results/phase2/EXP-P2D-ROBUSTNESS-001/stealth_campaign_results.json`, empirical evaluation across stealth attack families demonstrates partial, graded escalation without universal containment:
- **Infiltration (20 flows)**: 18 `ALLOW`, 2 `ALERT`, 0 `RATE_LIMIT`, 0 `ISOLATE` (10.0% escalation, 50.0-step mitigation delay). Sub-0.40 scores rarely breached the threshold required for disruptive containment.
- **Web Attack - Brute Force (100 flows)**: 70 `ALLOW`, 6 `ALERT`, 0 `RATE_LIMIT`, 24 `ISOLATE` (30.0% escalation, 8.0-step mitigation delay). Persistent threat accumulation triggered `ISOLATE` containment.
- **Web Attack - XSS (50 flows)**: 27 `ALLOW`, 2 `ALERT`, 0 `RATE_LIMIT`, 21 `ISOLATE` (46.0% escalation, 1.0-step mitigation delay). High local score spikes enabled rapid isolation.
- **Web Attack - SQL Injection (10 flows)**: 9 `ALLOW`, 1 `ALERT`, 0 `RATE_LIMIT`, 0 `ISOLATE` (10.0% escalation, 50.0-step mitigation delay). Sparse sequence length prevented escalation beyond `ALERT`.
- **Zero RATE_LIMIT Actions**: No stealth family triggered `RATE_LIMIT` (all 0); the policy transitioned directly between monitoring (`ALERT`) and hard containment (`ISOLATE`). Uncontained families (`Infiltration` and `SQL Injection`) incurred maximum 50-step delays.

### Reconciled Sensor Jitter Findings (Negative Finding):
- As recorded in `score_jitter_robustness.json`, Action Chattering Index (ACI) ranged between $0.1059$ and $0.1113$ across all noise levels $\sigma \in [0.00, 0.20]$, failing the pre-registered stability criterion ($\text{ACI} < 0.05$).
- However, False Quarantine Rate remained tightly bounded ($\text{FQR} \le 0.53\% < 2.0\%$), indicating that noise-induced action toggles occurred predominantly between non-disruptive actions (`ALLOW` and `ALERT`) rather than wrongful endpoint isolations.

---

## 7. Phase 2E: Dual-Layer Explainability & Safety Invariant Audit

Phase 2E demonstrated transparent decision provenance for all autonomous response interventions (`EXP-P2E-EXPLAINABILITY-001`):

### Dual-Layer Audit Architecture:
```text
Intervention Triggered (e.g. Host host_0 -> Proposed: ISOLATE -> Enforced: ALERT)
│
├── Layer 1: Perception Attribution (TreeSHAP)
│   "Why was this flow flagged as anomalous?"
│   - Detector Score S_t = 0.9934
│   - packet_length_std:  SHAP +0.2107 (Value: 1425.15)
│   - flow_packets_per_s: SHAP -0.1378 (Value: 0.16)
│   - flow_bytes_per_s:   SHAP -0.1143 (Value: 138.44)
│
├── Layer 2: Response Policy Explainability (Q-Decomposition)
│   "Why did the agent propose ISOLATE over RATE_LIMIT or ALERT?"
│   - Q(ALLOW) = -108.84, Q(ALERT) = -19.72, Q(RATE_LIMIT) = -22.56, Q(ISOLATE) = -12.36
│   - Decision Margin: +7.36 Q-value advantage over next-best action
│   - Driving State Factors:
│     * Instantaneous attack risk is severe (S_t=0.993 >= 0.75)
│     * Recent alert density is elevated (N_alert=100.0% of past 20 flows >= 0.50)
│     * Destination endpoint is designated critical infrastructure (isolation strictly prohibited)
│
└── Safety Invariant Verification (Deterministic Safety Gate)
    - Invariants Checked: CRITICAL_INFRASTRUCTURE_EXEMPTION, MANDATORY_ACTION_COOLDOWN, BLAST_RADIUS_CIRCUIT_BREAKER
    - Action Overruled: YES
    - Override Reason: CRITICAL_INFRASTRUCTURE_EXEMPTION
    - Enforced Action: ALERT
```

### Safety Invariant Audit Results:
- **Evaluated Validation Population ($D_{\text{pol\_val}}$)**: 142,346 flows
- **Interventions Audited (Non-ALLOW)**: 28,167 actions
- **Audit Cards Generated**: **28,167 cards** (100.00% coverage, **RQ7.3 PASS**)
- **Mean Decision Margin**: $+1.98$ Q-value advantage across interventions
- **Safety Overrides Enforced**: 12,573 overrides (8.83% override rate):
  - `CRITICAL_INFRASTRUCTURE_EXEMPTION`: 147 interventions safely downgraded from `ISOLATE` to `ALERT`
  - `BLAST_RADIUS_CIRCUIT_BREAKER`: 12,426 interventions downgraded to prevent network partition
- **Endpoint Tracking**: 250 distinct hosts tracked; 10 isolated and 10 rate-limited endpoints at termination (well within 5% inventory bound)
- **Critical Infrastructure Exemptions**: Zero unauthorized isolations of designated critical hosts (`host_0`, `host_1`, gateway, DNS). Every proposed isolation on a critical host was intercepted and safely downgraded to `ALERT`.

---

## 8. Final Authoritative Benchmark on Held-Out Test Data ($D_{\text{pol\_test}}$)

The final comparative benchmark was executed strictly once on the held-out test split ($D_{\text{pol\_test}}$, 355,865 tabular flows) with $B=1,000$ paired bootstrap resamples:

### Performance Matrix on Held-Out Test Data:

| Cost Regime | Action Space | Policy | Total Cost | Mean Cost/Flow | False Quarantine (FQR) | Availability (BAS) | Chattering (ACI) | Contained Attacks | Uncontained Attacks |
|:---|:---:|:---|---:|---:|---:|---:|---:|---:|---:|
| **Standard Enterprise** | `3-action` | `DQN_Candidate_3-action` | **505,610.5** | **1.4208** | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| Standard Enterprise | `3-action` | `Baseline_0_Always_ALLOW` | 6,482,000.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| Standard Enterprise | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 601,835.0 | 1.6912 | 0.00% | 97.96% | 0.0357 | 64,180 | 640 |
| Standard Enterprise | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 569,978.0 | 1.6017 | 0.00% | 97.82% | 0.0294 | 63,467 | 1,353 |
| Standard Enterprise | `3-action` | `Baseline_3_Heuristic_State_Machine` | 1,624,454.0 | 4.5648 | 0.00% | 73.02% | 0.1137 | 64,279 | 541 |
| **Standard Enterprise** | `4-action` | `DQN_Candidate_4-action` | **1,895,196.5** | **5.3256** | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| Standard Enterprise | `4-action` | `Baseline_0_Always_ALLOW` | 6,482,000.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| Standard Enterprise | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 2,661,646.0 | 7.4794 | 0.55% | 97.96% | 0.0230 | 5,130 | 59,690 |
| Standard Enterprise | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,206,220.5 | 6.1996 | 0.31% | 97.82% | 0.0270 | 5,859 | 58,961 |
| Standard Enterprise | `4-action` | `Baseline_3_Heuristic_State_Machine` | 3,257,720.0 | 9.1544 | 3.68% | 64.66% | 0.1073 | 3,280 | 61,540 |
| **High Availability** | `3-action` | `DQN_Candidate_3-action` | **538,160.5** | **1.5123** | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| High Availability | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 612,753.0 | 1.7219 | 0.00% | 97.82% | 0.0294 | 63,467 | 1,353 |
| **High Availability** | `4-action` | `DQN_Candidate_4-action` | **1,937,476.5** | **5.4444** | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| High Availability | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,257,830.5 | 6.3446 | 0.31% | 97.82% | 0.0270 | 5,859 | 58,961 |
| **High Security Enclave** | `3-action` | `DQN_Candidate_3-action` | **891,946.5** | **2.5064** | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| High Security Enclave | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 1,004,496.0 | 2.8227 | 0.00% | 97.82% | 0.0294 | 63,467 | 1,353 |
| **High Security Enclave** | `4-action` | `DQN_Candidate_4-action` | **2,445,511.5** | **6.8720** | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| High Security Enclave | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,849,589.5 | 8.0075 | 0.31% | 97.82% | 0.0270 | 5,859 | 58,961 |

---

## 9. Paired Bootstrap Hypothesis Testing ($B=1,000$ Resamples)

| Cost Regime | Action Space | Comparison Pair | Mean Cost Delta | 95% Bootstrap CI | Relative Cost Reduction ($\Delta \mathcal{C}_{\text{rel}}$) | p-value | Significance | Superior Policy |
|:---|:---:|:---|---:|:---:|---:|---:|:---:|:---:|
| Standard Enterprise | `3-action` | `DQN_Candidate` vs `Baseline_2 (Two-Tier)` | -0.1809 | [-0.1919, -0.1691] | **+11.29%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| Standard Enterprise | `3-action` | `DQN_Candidate` vs `Baseline_1 (Single-Threshold)` | -0.2704 | [-0.2825, -0.2576] | **+15.99%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| Standard Enterprise | `3-action` | `DQN_Candidate` vs `Baseline_0 (Always-ALLOW)` | -16.7940 | [-16.9164, -16.6855] | **+92.20%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| Standard Enterprise | `4-action` | `DQN_Candidate` vs `Baseline_2 (Two-Tier)` | -0.8740 | [-0.9147, -0.8312] | **+14.10%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| Standard Enterprise | `4-action` | `DQN_Candidate` vs `Baseline_1 (Single-Threshold)` | -2.1538 | [-2.1959, -2.1081] | **+28.80%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| Standard Enterprise | `4-action` | `DQN_Candidate` vs `Baseline_0 (Always-ALLOW)` | -12.8892 | [-12.9887, -12.8015] | **+70.76%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| High Availability | `3-action` | `DQN_Candidate` vs `Baseline_2 (Two-Tier)` | -0.2096 | [-0.2187, -0.2002] | **+12.17%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| High Availability | `4-action` | `DQN_Candidate` vs `Baseline_2 (Two-Tier)` | -0.9002 | [-0.9429, -0.8547] | **+14.19%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| High Security | `3-action` | `DQN_Candidate` vs `Baseline_2 (Two-Tier)` | -0.3163 | [-0.3693, -0.2615] | **+11.20%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| High Security | `4-action` | `DQN_Candidate` vs `Baseline_2 (Two-Tier)` | -1.1355 | [-1.1998, -1.0700] | **+14.18%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |

---

## 10. Formal Research Hypotheses Resolution & Research Question Criteria Evaluation

### 10.1 Formal Hypotheses Definition & Primary RQ7 Statistical Resolution:
- **Null Hypothesis ($H_0$)**: A reinforcement learning response policy does NOT achieve a statistically significant reduction in cumulative operational cost or mitigation latency compared with the best deterministic baseline.
- **Alternative Hypothesis ($H_1$)**: Conditioned on dynamic sequence state (score trajectory, alert density, cooldown timer, previous action), a learned response policy achieves lower cumulative cost under the tested conditions.

#### A. Statistical Hypothesis Testing Result ($B=1,000$ Paired Bootstrap Resamples):
Under Standard Enterprise cost regime on held-out test data ($D_{\text{pol\_test}}$, 355,865 flows), paired bootstrap comparison against the best deterministic comparator (Baseline 2: Two-Tier Graded Threshold) yields:
- **3-Action Space**: Mean cost delta $-0.1809$, 95% Bootstrap CI $[-0.1919, -0.1691]$, $p < 0.001$.
- **4-Action Space**: Mean cost delta $-0.8740$, 95% Bootstrap CI $[-0.9147, -0.8312]$, $p < 0.001$.

**Statistical Conclusion**: Because both action spaces achieve statistically significant cost reductions with $p < 0.001$ and empirical bootstrap confidence intervals strictly excluding zero, **$H_0$ is REJECTED** and **$H_1$ is SUPPORTED** for the operational cost component.

#### B. Pre-Registered Practical Effect-Size Criterion ($\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$):
The pre-registered operational improvement criterion specified:
$$\Delta \mathcal{C}_{\text{rel}} \ge 15.0\% \text{ with } p < 0.01 \text{ against the best deterministic baseline.}$$

Observed empirical effect sizes against the best deterministic baseline (Baseline 2):
- **3-Action DQN vs Baseline 2**: $\Delta \mathcal{C}_{\text{rel}} = \mathbf{+11.29\%}$ ($p < 0.001$)
- **4-Action DQN vs Baseline 2**: $\Delta \mathcal{C}_{\text{rel}} = \mathbf{+14.10\%}$ ($p < 0.001$)

*(Note: Against the weaker single-threshold Baseline 1, DQN achieves $+15.99\%$ in 3-action and $+28.80\%$ in 4-action, but Baseline 2 is the superior deterministic comparator).*

**Criterion Status: NOT MET**. While the cost reductions are statistically significant ($p < 0.001$), neither action space crosses the pre-registered 15.0% practical effect-size threshold over the best deterministic baseline. In accordance with pre-registered governance, we report this negative finding with complete scientific transparency.

---

### 10.2 Independent Phase 2 Research Question Criteria Evaluation:

| Question ID | Focus Area | Pre-Registered Specification Target | Observed Empirical Result | Status |
|:---|:---|:---|:---|:---:|
| **RQ7 Primary Statistical** | Operational Cost Reduction ($H_0$ vs $H_1$) | Statistically significant cost reduction ($p < 0.01$) vs best deterministic baseline | 3-action: $p < 0.001$ (CI [-0.19, -0.17]); 4-action: $p < 0.001$ (CI [-0.91, -0.83]) | **OBSERVED / SIGNIFICANT** ($H_0$ Rejected, $H_1$ Supported) |
| **RQ7 Operational Effect** | Relative Cost Reduction Magnitude | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ vs best deterministic baseline (Baseline 2) | 3-action: $+11.29\%$; 4-action: $+14.10\%$ vs Baseline 2 | **NOT MET** |
| **RQ7.1 Latency** | Mitigation Latency Reduction | Median / mean mitigation delay lower than best baseline | 3-action: 1.0 vs 2.0 steps (PASS); 4-action: 2.0 vs 2.0 steps (FAIL) | **PARTIAL** |
| **RQ7.1 Chattering** | Action Chattering Index (ACI) | $\text{ACI} < 0.01$ ($\le 1$ transition / 100 flows) on held-out test data | 3-action: $\text{ACI} = 0.0019$ (PASS); 4-action: $\text{ACI} = 0.0214$ (FAIL) | **PARTIAL** |
| **RQ7.2 Transfer** | Cross-Dataset Domain Shift Robustness | $\text{FQR} < 2.0\%$, $\text{BAS} > 95.0\%$ on CSE-CIC-IDS2018 without retraining | $\text{FQR} = 0.51\%$, $\text{BAS} = 97.69\%$, cost $+35.40\%$ | **PASS** |
| **RQ7.2 Jitter** | Sensor Continuous Score-Jitter Robustness | $\text{ACI} < 0.05$ under Gaussian noise $\sigma \le 0.20$ | $\text{ACI} \approx 0.106 - 0.111$ across all $\sigma$ (cost degrades under noise: $\sigma=0.05$: 1.57x cost, $\sigma=0.10$: 1.95x cost) | **FAIL** (Negative Finding) |
| **RQ7.3 Safety** | Deterministic Safety Gate Invariants | 100% compliance; zero critical host isolations; 100% audit card coverage | 100% invariant compliance, 0 critical host isolations, 28,167 audit cards (100.00% coverage) | **PASS** |

---

## 11. Scientific Governance & Decision Log Alignment (D-003 Reconciliation)

This report strictly adheres to repository governance:
1. **Academic Reporting Baseline ($\tau_{\text{research}}=0.50$)**:
   - Strictly frozen for benchmark comparisons and published reporting.
2. **Operational Threshold Candidate ($\tau_{\text{ops}}=0.40$)**:
   - Proposed operational candidate only; NOT an empirically selected optimum.
   - Does NOT guarantee universally improved FPR or recall across arbitrary deployments.
3. **Open Operational Decision**:
   - The reinforcement learning response policy evaluated here is an illustrative research model under simulated loss matrices.
   - Production deployment threshold selection remains an **OPEN DECISION** pending site-specific cost calibration and operational risk modeling.

---

## 12. Scientific Limitations & Future Research

1. **Offline Exogenous Replay**: Evaluated on replay streams where actions do not alter incoming packet generation dynamics.
2. **Simulated Loss Model**: Cost values reflect parameterized research assumptions rather than real enterprise accounting ledgers.
3. **Sensor Noise Vulnerability**: Continuous score jitter revealed elevated action chattering ($\text{ACI} \approx 0.11 > 0.05$), indicating a need for explicit hysteresis smoothing in future policy iterations.
4. **Single-Domain Development**: Policy training was performed on CIC-IDS2017; multi-dataset meta-learning remains future work.

---

## 13. Reproducibility & Provenance Index

| Stage | Directory | Primary Artifacts | Provenance Git Commit |
|:---|:---|:---|:---:|
| **Phase 2A** | `results/phase2/EXP-P2A-BASELINES-001/` | `baseline_metrics.json`, `experiment_config.json` | `7922420` |
| **Phase 2B** | `results/phase2/EXP-P2B-DQN-001/` | `training_config.json`, `validation_metrics.json` | `8e89a8d` |
| **Phase 2C** | `results/phase2/EXP-P2C-SENSITIVITY-001/` | `state_ablation_results.json`, `cost_regime_sensitivity.json` | `f59e929` |
| **Phase 2D** | `results/phase2/EXP-P2D-ROBUSTNESS-001/` | `transfer_robustness.json`, `score_jitter_robustness.json` | `211ca14` |
| **Phase 2E** | `results/phase2/EXP-P2E-EXPLAINABILITY-001/` | `audit_records.json`, `safety_audit_metrics.json` | `f9df812` |
| **Final Test**| `results/phase2/EXP-P2-FINAL-TEST-001/` | `final_test_metrics.json`, `final_test_bootstrap.json` | `57ecee1` |
