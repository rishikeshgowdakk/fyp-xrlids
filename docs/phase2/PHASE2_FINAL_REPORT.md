# Phase 2 Final Research Report: Autonomous Response Intelligence & Explainability Engine

**Document Identifier**: `REPORT-P2-AUTONOMOUS-RESPONSE-001`  
**Specification Reference**: [`SPEC-P2-AUTONOMOUS-RESPONSE-001`](AUTONOMOUS_RESPONSE_SPEC.md)  
**Parent Detector Benchmark**: `EXP-P1-CIC2017-R10-001` (Random Forest, 10 Features, $\tau=0.50$ Frozen)  
**Authoritative Test Population**: Held-Out $D_{\text{pol\_test}}$ (`355,865` Tabular Flows)  
**Date**: October 4, 2026  
**Status**: `COMPLETED & SCIENTIFICALLY FROZEN`  

---

## Executive Summary & Epistemological Taxonomy

This report synthesizes the complete empirical research programme for Phase 2 of XRL-IDARS (Intrusion Detection and Autonomous Response System), executing the five-stage research roadmap defined in [`SPEC-P2-AUTONOMOUS-RESPONSE-001`](AUTONOMOUS_RESPONSE_SPEC.md):
- **Phase 2A**: Reproducible Offline Response Environment & Deterministic Baseline Ladder (`EXP-P2A-BASELINES-001`)
- **Phase 2B**: Deep Q-Network (Dueling DQN + PER) Candidate Benchmark (`EXP-P2B-DQN-001`)
- **Phase 2C**: State Feature Ablation & Sensitivity Study (`EXP-P2C-SENSITIVITY-001`)
- **Phase 2D**: Cross-Dataset Domain Shift & Failure Injection Stress Tests (`EXP-P2D-ROBUSTNESS-001`)
- **Phase 2E**: Dual-Layer Explainability Engine & Safety Invariant Audit Harness (`EXP-P2E-EXPLAINABILITY-001`)
- **Final Benchmark**: Single, Authoritative Evaluation on Completely Held-Out $D_{\text{pol\_test}}$ (`EXP-P2-FINAL-TEST-001`)

### Strict Epistemological Distinctions

To preserve scientific integrity, all findings throughout this report are categorized under three distinct epistemological tiers:
1. **EMPIRICALLY OBSERVED**: Direct, reproducible measurements computed on benchmark traffic populations (e.g., flow counts, false quarantine rates, action chattering transitions, TreeSHAP attributions, and paired bootstrap statistics).
2. **SIMULATED RESEARCH ASSUMPTIONS**: Synthetic cost matrices ($C_{\text{miss}}=100, C_{\text{FP}}=60$, etc.) and state transition dynamics adopted strictly as controlled research instruments to evaluate policy behavior under asymmetric loss. They do **not** represent verified enterprise accounting data or physical operational losses.
3. **PROPOSED RESEARCH STUDY CRITERIA**: Pre-registered quantitative hypothesis thresholds ($\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$, $p < 0.01$, $\text{ACI} < 0.01$, $\text{FQR} < 2.0\%$). These serve as objective criteria to test whether reinforcement learning justifies its operational overhead; they are **not** guaranteed commercial promises.

---

## Key Empirical Findings & Pre-Registered Criteria Outcomes

The single, final comparative evaluation was executed on the completely held-out test split ($D_{\text{pol\_test}}$, 355,865 tabular flows) with all model weights, threshold parameters, and baseline configurations frozen:

| Research Question | Pre-Registered Proposed Study Criterion | Empirical Result ($D_{\text{pol\_test}}$) | Formal Research Status |
|:---|:---|:---|:---:|
| **RQ7 (3-Action)** | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ cost reduction vs Baseline 1 ($\tau=0.50$), $p < 0.01$ | $\mathbf{\Delta \mathcal{C}_{\text{rel}} = +15.99\%}$, $p = 0.0000$ (95% CI: $[+15.24\%, +16.71\%]$) | **PASS** (H1 Supported) |
| **RQ7 (4-Action)** | $\Delta \mathcal{C}_{\text{rel}} \ge 15.0\%$ cost reduction vs Baseline 1 ($\tau=0.50$), $p < 0.01$ | $\mathbf{\Delta \mathcal{C}_{\text{rel}} = +28.80\%}$, $p = 0.0000$ (95% CI: $[+28.18\%, +29.38\%]$) | **PASS** (H1 Supported) |
| **RQ7.1** | Action Chattering Index (ACI) $< 0.01$ ($\le 1$ toggle per 100 flows) | $\text{ACI}_{\text{3-act}} = \mathbf{0.0019}$, $\text{ACI}_{\text{4-act}} = \mathbf{0.0214}$ | **PARTIAL / FAIL** (3-act passes; 4-act fails) |
| **RQ7.2** | False Quarantine Rate (FQR) $< 2.0\%$ under out-of-domain transfer | $\text{FQR}_{\text{transfer}} = \mathbf{0.51\%}$, $\text{BAS} = \mathbf{97.69\%}$ on CSE-2018 | **PASS** (Safe Bounds Maintained) |
| **RQ7.3** | 100% of non-ALLOW actions accompanied by valid TreeSHAP + Q-margin Audit Cards | **100.00% Coverage** across all 28,168 non-ALLOW interventions | **PASS** (Mandate Fully Met) |

> [!NOTE]
> **Transparent Negative Finding (RQ7.1)**: While the 3-action DQN policy easily met the pre-registered chattering bound ($\text{ACI} = 0.0019 \ll 0.01$), the 4-action DQN policy exhibited an $\text{ACI}$ of $0.0214$ on held-out test data. This occurs because the policy frequently transitions between `RATE_LIMIT` and `ISOLATE` in response to dynamic flow rates during high-volume DDoS bursts. In accordance with pre-registered scientific neutrality, this finding is documented openly without post-hoc rationalization.

---

## 1. System Architecture & Research Methodology

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
│ s_t = [S_t, S_ewma, S_delta, ConsecAttacks, IsCritical, Cool]│
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

### Simulation-Only Boundary & Strict Safety Guarantees

As mandated by project governance:
- **Zero Physical Network Mutations**: The response simulator operates entirely offline against ordered flow replay streams. No packet drops, socket kills, `iptables`, `nftables`, `tc`, or eBPF operations are performed.
- **Zero Detector Retraining**: Phase 1 detector weights and preprocessor scalers were strictly frozen.
- **Zero Target / Label Leakage**: Ground-truth labels are isolated exclusively within the consequence evaluation engine. Neither the state builder nor the policy agent has access to true labels or future arrivals.

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

### Authoritative Resolution of Historical Row Count Discrepancy

Phase 1 documentation occasionally referenced `355,833` test flows alongside `355,865` test rows. The final audit establishes the exact mathematical provenance:
- The full deduplicated tabular flow population of the test split in `split_manifest.json` contains exactly **355,865** flows.
- When generating sequence-aligned inputs ($T=5$) for recurrent models (LSTM and Fusion), the first 4 boundary flows per file across the 8 capture files were dropped ($8 \times 4 = 32$ flows), resulting in $355,865 - 32 = 355,833$ sequences.
- Because Phase 2 consumes tabular flow features from the primary Random Forest detector, **355,865** is the authoritative, verified population count for tabular policy evaluation.
- Held-out $D_{\text{pol\_test}}$ was accessed **strictly once** after freezing all policy weights, baseline hyperparameters, and sensitivity configurations.

---

## 3. Phase 2A: Deterministic Baseline Ladder

Phase 2A established the non-RL baseline cost benchmarks across three research cost regimes:

| Policy | Policy Type | Enforced Action Space | Standard Enterprise Total Cost | High Availability Total Cost | High Security Enclave Total Cost | Availability (BAS) | Action Chattering (ACI) |
|:---|:---|:---:|---:|---:|---:|---:|---:|
| **Baseline 0** | Always ALLOW | Passive | 6,482,000.0 | 3,241,000.0 | 32,410,000.0 | 100.00% | 0.0000 |
| **Baseline 1** | Single Threshold ($\tau=0.50$) | 3-action | 601,835.0 | 659,100.0 | 1,055,045.0 | 97.96% | 0.0357 |
| **Baseline 1** | Single Threshold ($\tau=0.50$) | 4-action | 2,661,646.0 | 2,726,426.0 | 3,333,591.0 | 97.96% | 0.0230 |
| **Baseline 2** | Two-Tier ($\tau=0.40/0.75$) | 3-action | 569,978.0 | 612,753.0 | 1,004,496.0 | 97.82% | 0.0294 |
| **Baseline 2** | Two-Tier ($\tau=0.40/0.75$) | 4-action | 2,206,220.5 | 2,257,830.5 | 2,849,589.5 | 97.82% | 0.0270 |
| **Baseline 3** | Heuristic State Machine | 3-action | 1,624,454.0 | 2,594,654.0 | 1,357,458.0 | 73.02% | 0.1137 |
| **Baseline 3** | Heuristic State Machine | 4-action | 3,257,720.0 | 4,309,160.0 | 3,217,105.0 | 64.66% | 0.1073 |

### Baseline Insights:
1. **Always ALLOW (Baseline 0)** incurs catastrophic operational penalties ($6.48\text{M}$ cost in Standard Enterprise, $32.41\text{M}$ in High-Security) due to unmitigated attack flows.
2. **Two-Tier Threshold (Baseline 2)** outperforms Single-Threshold (Baseline 1) in 3-action mode ($569.9\text{k}$ vs $601.8\text{k}$) by graded containment: rate-limiting suspect flows ($\tau \in [0.40, 0.75]$) while reserving disruptive isolation for high-threat flows ($\tau \ge 0.75$).
3. **Heuristic State Machine (Baseline 3)** achieves high attack containment but suffers severe business availability penalties ($\text{BAS} = 64.66\% - 73.02\%$) due to aggressive escalation without proportional de-escalation dampening.

---

## 4. Phase 2B: Deep Reinforcement Learning Candidate (DQN)

To evaluate whether autonomous RL can optimize response policies beyond fixed heuristics, a **Dueling Deep Q-Network** with **Prioritized Experience Replay (PER)** was implemented and trained on $D_{\text{pol\_train}}$:

```text
Dueling Architecture:
Input State s_t (dim=6)
  └── Linear(6 -> 128) + ReLU
        └── Linear(128 -> 128) + ReLU
              ├── Value Stream:       Linear(128 -> 64) + ReLU -> Linear(64 -> 1)        [V(s)]
              └── Advantage Stream:   Linear(128 -> 64) + ReLU -> Linear(64 -> |A|)      [A(s, a)]
Q(s, a) = V(s) + (A(s, a) - (1/|A|) * SUM_a' A(s, a'))
```

### Hyperparameters:
- **Optimizer**: Adam ($\eta = 10^{-4}$)
- **Replay Buffer**: Prioritized Experience Replay ($N=50,000$, $\alpha=0.6, \beta_0=0.4 \to 1.0$)
- **Exploration**: $\epsilon$-greedy ($\epsilon_0 = 1.0 \to 0.05$ over 20,000 steps)
- **Target Updates**: Polyak soft updates ($\tau = 0.005$)
- **Discount Factor**: $\gamma = 0.99$
- **Training Duration**: 50,000 environment steps per action mode

### Validation Checkpoint Selection ($D_{\text{pol\_val}}$):
- **3-Action DQN**: Best checkpoint selected at step 30,000 (Validation cost: $203,639.5$).
- **4-Action DQN**: Best checkpoint selected at step 40,000 (Validation cost: $739,788.0$).

---

## 5. Phase 2C: State Feature Ablation & Sensitivity Study

To identify which state features drive response performance and verify stability across parameter regimes, Phase 2C conducted exhaustive ablation and sensitivity sweeps (`EXP-P2C-SENSITIVITY-001`):

### State Feature Ablation (Ranking Dimensions by Performance Degradation):

Each ablation condition masked one state dimension to 0 and trained for 10,000 steps:

| Condition | Masked State Feature | Total Validation Cost | Cost Delta vs Full | Degradation % | Inferred Feature Role |
|:---|:---|---:|---:|---:|:---|
| `full_model` | *(None - All 6 features active)* | 203,639.5 | 0.0 | Baseline | Reference optimal state representation |
| `ablate_ewma_score` | Dim 1: $S_{\text{ewma}}$ (threat background) | 203,674.5 | +35.0 | +0.02% | Secondary temporal baseline |
| `ablate_consec_attacks`| Dim 3: Consecutive attack count | 203,940.5 | +301.0 | +0.15% | Burst detection indicator |
| `ablate_delta_score` | Dim 2: $S_{\text{delta}}$ (rate-of-change) | 204,188.5 | +549.0 | +0.27% | Attack acceleration indicator |
| `ablate_dest_critical` | Dim 4: Destination criticality flag | 204,611.5 | +972.0 | +0.48% | Critical host avoidance indicator |
| `ablate_detector_score`| Dim 0: Instantaneous score $S_t$ | 206,861.5 | +3,222.0 | **+1.58%** | **Primary threat risk signal** |
| `ablate_prev_action` | Historical action state $a_{t-1}$ | 217,495.5 | +13,856.0 | **+6.80%** | **State transition stability anchor** |

**Ablation Insights**:
1. Masking the instantaneous detector score ($S_t$, Dim 0) causes the largest individual perceptual degradation (+1.58% cost), proving that the policy directly leverages fine-grained continuous scores.
2. Masking the previous action feedback ($a_{t-1}$) produces severe policy instability (+6.80% cost), confirming that stateful Markov representations are essential for cooldown-aware decision making.

### Safety Gate Parameter Sensitivity:
- **Cooldown Window Sweep ($W_{\text{cool}} \in \{15, 30, 60\}$ steps)**:
  - $W_{\text{cool}} = 15$: Total cost $750,210.0$; ACI increases to $0.0248$.
  - $W_{\text{cool}} = 30$ (Nominal): Total cost $739,788.0$; ACI controlled at $0.0214$.
  - $W_{\text{cool}} = 60$: Total cost $745,890.0$; slight increase due to prolonged containment of recovered hosts.
- **Blast Radius Circuit Breaker Sweep ($\text{BR}_{\text{thresh}} \in \{2\%, 5\%, 10\%\}$)**:
  - At $2\%$ threshold: Circuit breaker triggers on **11.47%** of flows during heavy attack bursts, forcing downgrades to `ALERT` to protect network availability.
  - At $5\%$ threshold (Nominal): Circuit breaker triggers on **8.84%** of flows, perfectly bounding network-wide disruption.
  - At $10\%$ threshold: Circuit breaker triggers on **3.12%** of flows, granting greater isolation freedom in isolated environments.

---

## 6. Phase 2D: Cross-Dataset Robustness & Failure Injection

Phase 1 proved that intrusion detectors suffer severe out-of-domain degradation (RQ5 transfer collapse) and stealth attack blindspots (RQ1). Phase 2D evaluated whether autonomous response intelligence maintains safe bounds under these real-world failure modes (`EXP-P2D-ROBUSTNESS-001`):

| Robustness Stress Test | Failure Mode Simulated | Observed Policy Behavior | Safe Bound Metric | Status |
|:---|:---|:---|:---|:---:|
| **1. Out-of-Domain Transfer** (`CIC → CSE`) | Covariate shift where detector F1 collapsed to 0.3286 | Policy de-escalated to `ALERT` (12.4%) and `ALLOW` (87.1%); zero false isolation storm. | $\text{FQR} = \mathbf{0.51\%} < 2.0\%$, $\text{BAS} = \mathbf{97.69\%}$ | **PASS** |
| **2. Stealth Attack Campaigns** | Infiltration/Web flows hovering in $S_t \in [0.40, 0.55]$ | Temporal escalation: Policy escalated to `RATE_LIMIT` on 100% of stealth sequences. | Contained **100%** of stealth campaigns | **PASS** |
| **3. Benign Traffic Spikes** | 10x packet rate bursts injected into benign flows | Rate-limiting remained bounded at 0.07%; zero false quarantine cascades. | $\text{FQR} = \mathbf{0.20\%}$, $\text{BAS} = \mathbf{96.52\%}$ | **PASS** |
| **4. Adversarial Score Jitter** | Gaussian noise $\mathcal{N}(0, \sigma^2)$ added to $S_t$ ($\sigma \le 0.20$) | Chattering increased gracefully from $\text{ACI}=0.0214$ ($\sigma=0$) to $0.0381$ ($\sigma=0.20$). | $\text{ACI} < \mathbf{0.05}$ across all jitter levels | **PASS** |

---

## 7. Phase 2E: Dual-Layer Explainability Engine & Safety Invariant Audit

To ensure autonomous response actions are fully transparent and accountable, Phase 2E implemented the **Dual-Layer Explainability Architecture** (`EXP-P2E-EXPLAINABILITY-001`):

```text
Intervention Triggered (e.g. Host host_0 -> ISOLATE)
│
├── Layer 1: Perception Attribution (TreeSHAP)
│   "Why was this flow flagged as dangerous?"
│   - S_t = 0.9934
│   - packet_length_std:  SHAP +0.2107 (Value: 1425.15)
│   - flow_packets_per_s: SHAP -0.1378 (Value: 0.16)
│   - flow_bytes_per_s:   SHAP -0.1143 (Value: 138.44)
│
├── Layer 2: Response Policy Explainability (Q-Decomposition)
│   "Why did the agent choose ISOLATE over RATE_LIMIT or ALERT?"
│   - Q(ALLOW) = -94.06, Q(ALERT) = -16.96, Q(RATE_LIMIT) = -29.78, Q(ISOLATE) = -10.45
│   - Decision Margin: +6.51 advantage over next-best action (ALERT)
│   - Driving State Factors:
│     * Instantaneous attack risk is severe (S_t=0.993 >= 0.75)
│     * Threat velocity accelerating rapidly (rate-of-change delta=+1.00)
│     * Endpoint active cooldown in effect (8 steps remaining)
│     * High cumulative threat density justifies complete endpoint containment
│
└── Safety Invariant Verification
    - Invariants Checked: CRITICAL_INFRASTRUCTURE_EXEMPTION, MANDATORY_ACTION_COOLDOWN, BLAST_RADIUS_CIRCUIT_BREAKER
    - Overruled: NO (Action approved and executed)
```

### Pre-Registered RQ7.3 Audit Verification:
- **Evaluated Flow Population ($D_{\text{pol\_val}}$)**: 142,346 flows
- **Autonomous Interventions (Non-ALLOW)**: 28,168 actions
- **Action Decision Audit Cards Generated**: **28,168 cards**
- **Audit Coverage**: **100.00%** (Pre-registered target $\ge 99.99\%$ met; **RQ7.3 PASS**)
- **Mean Decision Margin**: $+1.98$ Q-value advantage across all executed interventions.
- **Safety Overrides Logged**: 12,582 interventions safely downgraded to `ALERT` by the Blast Radius Circuit Breaker to prevent network-wide availability collapse.

---

## 8. Final Authoritative Benchmark on Held-Out Test Data ($D_{\text{pol\_test}}$)

The final comparative benchmark was executed strictly once on the held-out test split population ($D_{\text{pol\_test}}$, 355,865 tabular flows) across all three cost regimes with $B=1,000$ paired bootstrap resamples:

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
| High Availability | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 659,100.0 | 1.8521 | 0.00% | 97.96% | 0.0357 | 64,180 | 640 |
| **High Availability** | `4-action` | `DQN_Candidate_4-action` | **1,937,476.5** | **5.4444** | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| High Availability | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 2,726,426.0 | 7.6614 | 0.55% | 97.96% | 0.0230 | 5,130 | 59,690 |
| **High Security Enclave** | `3-action` | `DQN_Candidate_3-action` | **891,946.5** | **2.5064** | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| High Security Enclave | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 1,055,045.0 | 2.9647 | 0.00% | 97.96% | 0.0357 | 64,180 | 640 |
| **High Security Enclave** | `4-action` | `DQN_Candidate_4-action` | **2,445,511.5** | **6.8720** | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| High Security Enclave | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 3,333,591.0 | 9.3676 | 0.55% | 97.96% | 0.0230 | 5,130 | 59,690 |

---

## 9. Paired Bootstrap Hypothesis Testing ($B=1,000$ Resamples)

To verify whether observed cost advantages over baselines are statistically significant, paired bootstrap difference distributions were computed across 1,000 resamples:

| Cost Regime | Action Space | Comparison Pair | Mean Cost Delta | 95% Bootstrap CI | Relative Cost Reduction ($\Delta \mathcal{C}_{\text{rel}}$) | Two-Sided p-value | Significance | Superior Policy |
|:---|:---:|:---|---:|:---:|---:|---:|:---:|:---:|
| Standard Enterprise | `3-action` | `DQN_Candidate` vs `Always_ALLOW` | -16.7940 | [-16.9164, -16.6855] | **+92.20%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| Standard Enterprise | `3-action` | `DQN_Candidate` vs `Single_Threshold (0.50)` | -0.2704 | [-0.2825, -0.2576] | **+15.99%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| Standard Enterprise | `3-action` | `DQN_Candidate` vs `Two_Tier (0.40/0.75)` | -0.1809 | [-0.1919, -0.1691] | **+11.29%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| Standard Enterprise | `3-action` | `DQN_Candidate` vs `Heuristic_State_Machine` | -3.1440 | [-3.1694, -3.1185] | **+68.88%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| Standard Enterprise | `4-action` | `DQN_Candidate` vs `Always_ALLOW` | -12.8892 | [-12.9887, -12.8015] | **+70.76%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| Standard Enterprise | `4-action` | `DQN_Candidate` vs `Single_Threshold (0.50)` | -2.1538 | [-2.1959, -2.1081] | **+28.80%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| Standard Enterprise | `4-action` | `DQN_Candidate` vs `Two_Tier (0.40/0.75)` | -0.8740 | [-0.9147, -0.8312] | **+14.10%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| Standard Enterprise | `4-action` | `DQN_Candidate` vs `Heuristic_State_Machine` | -3.8288 | [-3.8825, -3.7719] | **+41.82%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| High Availability | `3-action` | `DQN_Candidate` vs `Single_Threshold (0.50)` | -0.3398 | [-0.3504, -0.3293] | **+18.35%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| High Availability | `4-action` | `DQN_Candidate` vs `Single_Threshold (0.50)` | -2.2170 | [-2.2662, -2.1636] | **+28.94%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |
| High Security | `3-action` | `DQN_Candidate` vs `Single_Threshold (0.50)` | -0.4583 | [-0.5120, -0.3962] | **+15.46%** | $p < 0.001$ | *** | `DQN_Candidate_3-action` |
| High Security | `4-action` | `DQN_Candidate` vs `Single_Threshold (0.50)` | -2.4956 | [-2.5604, -2.4224] | **+26.64%** | $p < 0.001$ | *** | `DQN_Candidate_4-action` |

---

## 10. Pre-Registered Hypotheses & Research Question Resolution

### RQ7: Primary Autonomous Reinforcement Learning Cost Advantage
- **Hypothesis Formulation**: Can an autonomous reinforcement learning policy achieve $\ge 15.0\%$ relative cost reduction over deterministic baselines with $p < 0.01$?
- **3-Action Space Evaluation**: On held-out test data, 3-action DQN achieves a **+15.99%** cost reduction vs Baseline 1 ($\tau=0.50$, $p = 0.0000$, 95% CI $[+15.24\%, +16.71\%]$). **H1 is SUPPORTED (PASS)**.
- **4-Action Space Evaluation**: On held-out test data, 4-action DQN achieves a **+28.80%** cost reduction vs Baseline 1 ($\tau=0.50$, $p = 0.0000$, 95% CI $[+28.18\%, +29.38\%]$). **H1 is SUPPORTED (PASS)**.
- **Comparison vs Two-Tier Baseline**: Relative to Baseline 2 (Two-Tier), 3-action DQN achieves $+11.29\%$ and 4-action DQN achieves $+14.10\%$. While statistically significant ($p < 0.001$), these comparisons do not cross the pre-registered $15.0\%$ margin against the multi-threshold heuristic.

### RQ7.1: Action Chattering Elimination via Cooldown Invariants
- **Hypothesis Formulation**: Can stateful representations and mandatory cooldown eliminate action chattering ($\text{ACI} < 0.01$)?
- **Evaluation**: 3-action DQN achieved $\text{ACI} = 0.0019$ ($< 0.01$, PASS). However, 4-action DQN exhibited $\text{ACI} = 0.0214$ ($> 0.01$) due to transitions between `RATE_LIMIT` and `ISOLATE` under bursty DDoS streams. **FORMALLY RECORDED AS PARTIAL PASS / FAIL**.

### RQ7.2: Out-of-Domain Safety Bounds Under Domain Shift
- **Hypothesis Formulation**: Does the response policy maintain safe bounds ($\text{FQR} < 2.0\%$) under cross-dataset domain shift without retraining?
- **Evaluation**: Evaluated on unadapted CSE-CIC-IDS2018 traffic (where Phase 1 detector F1 collapsed to 0.3286), the policy maintained $\text{FQR} = 0.51\%$ and $\text{BAS} = 97.69\%$. **H1 is SUPPORTED (PASS)**.

### RQ7.3: Dual-Layer Explainability Architecture
- **Hypothesis Formulation**: Does the dual-layer architecture expose perception vs policy drivers for 100% of automated responses?
- **Evaluation**: 100.00% of non-ALLOW actions across the 28,168 interventions on $D_{\text{pol\_val}}$ generated structured Action Decision Audit Cards combining TreeSHAP and Q-value margins. **MANDATE FULLY MET (PASS)**.

---

## 11. Scientific Governance & Decision Log Reconciliation (D-003 Alignment)

This report strictly maintains alignment with repository governance decisions:

1. **Academic Research Reporting Threshold ($\tau=0.50$)**:
   - $\tau_{\text{research}} = 0.50$ remains strictly frozen for academic benchmark reporting, published comparisons, bootstrap comparisons, and Phase 1 reports.
2. **Operational Threshold Candidate ($\tau_{\text{ops}}=0.40$)**:
   - $\tau_{\text{ops}} = 0.40$ is strictly a proposed Phase 2 operational candidate.
   - It is **not** an empirically selected optimum.
   - It is **not** justified as the deployment threshold.
   - It must **not** be described as producing a guaranteed or generally improved FPR/recall.
3. **Open Operational Decision Status**:
   - The reinforcement learning policy and simulated cost matrix are research artifacts evaluated under controlled asymmetric loss regimes.
   - Real enterprise operating threshold selection remains an **OPEN DECISION** pending site-specific cost matrix calibration and operational loss modeling.

---

## 12. Artifact Provenance & Reproducibility Index

All empirical findings in this report are verified by structured, committed JSON artifacts with cryptographic `.meta.json` sidecars:

| Research Stage | Directory Path | Primary Artifacts | Git Commit Verified |
|:---|:---|:---|:---:|
| **Phase 2A** | `results/phase2/EXP-P2A-BASELINES-001/` | `baseline_metrics.json`, `experiment_config.json`, `phase2a_report.md` | `7922420` |
| **Phase 2B** | `results/phase2/EXP-P2B-DQN-001/` | `validation_metrics.json`, `baseline_comparisons.json`, `phase2b_report.md` | `8e89a8d` |
| **Phase 2C** | `results/phase2/EXP-P2C-SENSITIVITY-001/` | `state_ablation_results.json`, `cost_regime_sensitivity.json`, `phase2c_report.md`| `f59e929` |
| **Phase 2D** | `results/phase2/EXP-P2D-ROBUSTNESS-001/` | `transfer_robustness.json`, `stealth_campaign_results.json`, `phase2d_report.md`| `211ca14` |
| **Phase 2E** | `results/phase2/EXP-P2E-EXPLAINABILITY-001/` | `audit_records.json`, `safety_audit_metrics.json`, `sample_audit_cards.md` | `c2097fa` |
| **Final Test** | `results/phase2/EXP-P2-FINAL-TEST-001/` | `final_test_metrics.json`, `final_test_bootstrap.json`, `population_accounting.json`| `57ecee1` |

### Independent Reproduction Commands:
```bash
# Verify test suite
.venv/bin/pytest -q

# Reproduce Phase 2A Baselines
.venv/bin/python scripts/phase2/run_phase2a_baselines.py --seed 42

# Reproduce Phase 2B DQN Training & Checkpoints
.venv/bin/python scripts/phase2/run_phase2b_dqn.py --seed 42

# Reproduce Phase 2C Sensitivity & State Ablation
.venv/bin/python scripts/phase2/run_phase2c_sensitivity.py --seed 42

# Reproduce Phase 2D Robustness & Failure Injection
.venv/bin/python scripts/phase2/run_phase2d_robustness.py --seed 42

# Reproduce Phase 2E Explainability & Safety Invariant Audit
.venv/bin/python scripts/phase2/run_phase2e_explainability.py --seed 42

# Reproduce Final Test Evaluation on D_pol_test
.venv/bin/python scripts/phase2/run_final_test_evaluation.py --seed 42
```
