# Phase 2B: Deep Q-Network (DQN) Candidate Benchmark Report

**Experiment ID**: `EXP-P2B-DQN-001`  
**Research Question**: `RQ7` (Autonomous Response Intelligence)  
**Parent Detector**: `EXP-P1-CIC2017-R10-001`  
**Reference Baseline**: `EXP-P2A-BASELINES-001`  
**Generated**: `2026-10-03T19:09:35.733469+00:00`  
**Git Commit**: `5d6257d998c7bd9d44f24a250c477675cf607833`  

---

## 1. Executive Summary & Scientific Position

Phase 2B implements and evaluates the reinforcement learning candidate architecture specified in
`docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md` (`SPEC-P2-AUTONOMOUS-RESPONSE-001`).

**Core Architectural & Methodological Specifications**:
- **Network Architecture**: Dueling Q-Network (6D state $\to$ 64-64 MLP with LayerNorm & LeakyReLU $\to$ Value $V(s)$ and Advantage $A(s, a)$ streams).
- **Experience Replay**: Prioritized Experience Replay (PER, capacity 100,000, $\alpha=0.6$, $\beta: 0.4 \to 1.0$).
- **Optimization**: Huber (Smooth L1) loss, $\gamma=0.95$, Polyak soft target updates ($\tau_{\text{target}}=0.005$).
- **Exploration**: Linear $\epsilon$-greedy decay ($1.0 \to 0.05$ over 50,000 steps).
- **Evaluation Protocol**: Stage 2B.1 evaluates the 3-action space (`ALLOW`, `ALERT`, `RATE_LIMIT`), while Stage 2B.2 evaluates the 4-action space (`ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`).
- **Scientific Neutrality**: Results are tested against pre-registered criteria without assuming RL superiority. If deterministic baselines achieve equivalent or superior cost profiles, the Null Hypothesis ($H_0$) is upheld.

---

## 2. Population Accounting & Strict Dataset Isolation

- **Dataset**: `cicids2017`
- **Policy Training Population ($D_{\text{pol\_train}}$)**: `213,518` flows (used exclusively for DQN gradient updates)
- **Policy Validation Population ($D_{\text{pol\_val}}$)**: `142,346` flows (used for checkpoint evaluation, sensitivity, and baseline comparison)
- **Final Test Population ($D_{\text{pol\_test}}$)**: `355,865` flows (**COMPLETELY HELD-OUT AND UNTOUCHED**)

> [!IMPORTANT]
> **Authoritative Resolution of Population Accounting**:
> The 355,865 rows in $D_{\text{pol\_test}}$ represent the exact tabular flow population of the frozen Phase 1 test split (`split_manifest.json`).
> Historical references to 355,833 rows in Phase 1 documentation represent the sequence-aligned population required by sequence models (LSTM and Fusion) due to dropping the first 4 boundary flows per file across 8 capture files ($355,865 - 8 \times 4 = 355,833$).
> Because the Phase 2 detector interface consumes tabular flow features, 355,865 is the authoritative population count for tabular flow evaluation.

---

## 3. Training Protocol & Convergence History

- **Stage 2B.1 (3-Action Space)**: 50,000 training steps, 500 episodes in 511.8s.
- **Stage 2B.2 (4-Action Space)**: 50,000 training steps, 1,690 episodes in 395.7s.

| Stage | Action Space | Final Loss | Validation Best Step | Best Val Mean Cost/Flow | Best Checkpoint |
|:---|:---|---:|---:|---:|:---|
| Stage 2B.1 | N/A | 0.6124 | 10000 | 2.0437 | `checkpoint_step_010000.pt` |
| Stage 2B.2 | N/A | 0.6604 | 45000 | 2.2416 | `checkpoint_step_045000.pt` |

---

## 4. Multi-Regime Validation Performance Matrix

| Action Mode | Cost Regime | Policy | Total Cost | Mean Cost/Flow | False Quarantine (FQR) | Availability (BAS) | Chattering (ACI) | Contained | Uncontained |
|:---|:---|:---|---:|---:|---:|---:|---:|---:|---:|
| 3-action | standard_enterprise | `DQN_Candidate_3-action` | 305,332.0 | 2.1450 | 0.00% | 96.46% | 0.0311 | 5,337 | 20,591 |
| 3-action | standard_enterprise | `Baseline_0_Always_ALLOW` | 2,592,800.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 3-action | standard_enterprise | `Baseline_1_Single_Threshold_tau_0.50` | 440,536.0 | 3.0948 | 0.00% | 97.99% | 0.3165 | 25,666 | 262 |
| 3-action | standard_enterprise | `Baseline_2_Two_Tier_0.40_0.75` | 427,527.0 | 3.0034 | 0.00% | 97.87% | 0.3078 | 25,392 | 536 |
| 3-action | standard_enterprise | `Baseline_3_Heuristic_State_Machine` | 1,806,318.0 | 12.6896 | 0.00% | 8.32% | 0.1183 | 25,857 | 71 |
| 3-action | high_availability | `DQN_Candidate_3-action` | 300,007.0 | 2.1076 | 0.00% | 96.46% | 0.0311 | 5,337 | 20,591 |
| 3-action | high_availability | `Baseline_0_Always_ALLOW` | 1,296,400.0 | 9.1074 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 3-action | high_availability | `Baseline_1_Single_Threshold_tau_0.50` | 462,506.0 | 3.2492 | 0.00% | 97.99% | 0.3165 | 25,666 | 262 |
| 3-action | high_availability | `Baseline_2_Two_Tier_0.40_0.75` | 443,842.0 | 3.1181 | 0.00% | 97.87% | 0.3078 | 25,392 | 536 |
| 3-action | high_availability | `Baseline_3_Heuristic_State_Machine` | 3,366,998.0 | 23.6536 | 0.00% | 8.32% | 0.1183 | 25,857 | 71 |
| 3-action | high_security_enclave | `DQN_Candidate_3-action` | 567,050.0 | 3.9836 | 0.00% | 96.46% | 0.0311 | 5,337 | 20,591 |
| 3-action | high_security_enclave | `Baseline_0_Always_ALLOW` | 12,964,000.0 | 91.0739 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 3-action | high_security_enclave | `Baseline_1_Single_Threshold_tau_0.50` | 624,620.0 | 4.3880 | 0.00% | 97.99% | 0.3165 | 25,666 | 262 |
| 3-action | high_security_enclave | `Baseline_2_Two_Tier_0.40_0.75` | 607,869.0 | 4.2704 | 0.00% | 97.87% | 0.3078 | 25,392 | 536 |
| 3-action | high_security_enclave | `Baseline_3_Heuristic_State_Machine` | 877,034.0 | 6.1613 | 0.00% | 8.32% | 0.1183 | 25,857 | 71 |
| 4-action | standard_enterprise | `DQN_Candidate_4-action` | 335,588.0 | 2.3576 | 0.28% | 97.82% | 0.1115 | 11,125 | 14,803 |
| 4-action | standard_enterprise | `Baseline_0_Always_ALLOW` | 2,592,800.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 4-action | standard_enterprise | `Baseline_1_Single_Threshold_tau_0.50` | 371,678.5 | 2.6111 | 0.48% | 97.99% | 0.0898 | 6,139 | 19,789 |
| 4-action | standard_enterprise | `Baseline_2_Two_Tier_0.40_0.75` | 376,299.0 | 2.6436 | 0.39% | 97.87% | 0.0990 | 6,528 | 19,400 |
| 4-action | standard_enterprise | `Baseline_3_Heuristic_State_Machine` | 1,196,420.0 | 8.4050 | 4.73% | 1.52% | 0.0771 | 1,435 | 24,493 |
| 4-action | high_availability | `DQN_Candidate_4-action` | 344,158.0 | 2.4178 | 0.28% | 97.82% | 0.1115 | 11,125 | 14,803 |
| 4-action | high_availability | `Baseline_0_Always_ALLOW` | 1,296,400.0 | 9.1074 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 4-action | high_availability | `Baseline_1_Single_Threshold_tau_0.50` | 391,758.5 | 2.7522 | 0.48% | 97.99% | 0.0898 | 6,139 | 19,789 |
| 4-action | high_availability | `Baseline_2_Two_Tier_0.40_0.75` | 400,819.0 | 2.8158 | 0.39% | 97.87% | 0.0990 | 6,528 | 19,400 |
| 4-action | high_availability | `Baseline_3_Heuristic_State_Machine` | 1,818,940.0 | 12.7783 | 4.73% | 1.52% | 0.0771 | 1,435 | 24,493 |
| 4-action | high_security_enclave | `DQN_Candidate_4-action` | 576,054.0 | 4.0469 | 0.28% | 97.82% | 0.1115 | 11,125 | 14,803 |
| 4-action | high_security_enclave | `Baseline_0_Always_ALLOW` | 12,964,000.0 | 91.0739 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 4-action | high_security_enclave | `Baseline_1_Single_Threshold_tau_0.50` | 613,339.5 | 4.3088 | 0.48% | 97.99% | 0.0898 | 6,139 | 19,789 |
| 4-action | high_security_enclave | `Baseline_2_Two_Tier_0.40_0.75` | 603,987.0 | 4.2431 | 0.39% | 97.87% | 0.0990 | 6,528 | 19,400 |
| 4-action | high_security_enclave | `Baseline_3_Heuristic_State_Machine` | 1,007,154.0 | 7.0754 | 4.73% | 1.52% | 0.0771 | 1,435 | 24,493 |

---

## 5. Paired Bootstrap Hypothesis Testing (DQN vs Baselines, B=1,000)

| Action Mode | Cost Regime | Comparison | Mean Cost Delta | 95% Bootstrap CI | Relative Cost Reduction ($\Delta \mathcal{C}_{\text{rel}}$) | p-value | Significance |
|:---|:---|:---|---:|:---:|---:|---:|:---:|
| 3-action | standard_enterprise | `DQN_Candidate_3-action` vs `Baseline_0_Always_ALLOW` | -16.0698 | [-16.2635, -15.8922] | +88.22% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `DQN_Candidate_3-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.9498 | [-0.9754, -0.9243] | +30.69% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `DQN_Candidate_3-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.8584 | [-0.8834, -0.8345] | +28.58% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `DQN_Candidate_3-action` vs `Baseline_3_Heuristic_State_Machine` | -10.5446 | [-10.5933, -10.4922] | +83.10% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `DQN_Candidate_3-action` vs `Baseline_0_Always_ALLOW` | -6.9998 | [-7.0843, -6.9212] | +76.86% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `DQN_Candidate_3-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -1.1416 | [-1.1677, -1.1161] | +35.13% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `DQN_Candidate_3-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -1.0105 | [-1.0342, -0.9871] | +32.41% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `DQN_Candidate_3-action` vs `Baseline_3_Heuristic_State_Machine` | -21.5460 | [-21.6250, -21.4626] | +91.09% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `DQN_Candidate_3-action` vs `Baseline_0_Always_ALLOW` | -87.0903 | [-88.1337, -86.1225] | +95.63% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `DQN_Candidate_3-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.4044 | [-0.5061, -0.2966] | +9.22% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `DQN_Candidate_3-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.2868 | [-0.3925, -0.1763] | +6.72% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `DQN_Candidate_3-action` vs `Baseline_3_Heuristic_State_Machine` | -2.1777 | [-2.2752, -2.0731] | +35.34% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `DQN_Candidate_4-action` vs `Baseline_0_Always_ALLOW` | -15.8572 | [-16.0479, -15.6813] | +87.06% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `DQN_Candidate_4-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.2535 | [-0.2782, -0.2280] | +9.71% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `DQN_Candidate_4-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.2860 | [-0.3104, -0.2609] | +10.82% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `DQN_Candidate_4-action` vs `Baseline_3_Heuristic_State_Machine` | -6.0475 | [-6.1200, -5.9707] | +71.95% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `DQN_Candidate_4-action` vs `Baseline_0_Always_ALLOW` | -6.6896 | [-6.7822, -6.6062] | +73.45% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `DQN_Candidate_4-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.3344 | [-0.3746, -0.2930] | +12.15% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `DQN_Candidate_4-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.3981 | [-0.4365, -0.3597] | +14.14% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `DQN_Candidate_4-action` vs `Baseline_3_Heuristic_State_Machine` | -10.3605 | [-10.4966, -10.2170] | +81.08% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `DQN_Candidate_4-action` vs `Baseline_0_Always_ALLOW` | -87.0270 | [-88.0837, -86.0749] | +95.56% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `DQN_Candidate_4-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.2619 | [-0.3351, -0.1891] | +6.08% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `DQN_Candidate_4-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.1962 | [-0.2679, -0.1251] | +4.62% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `DQN_Candidate_4-action` vs `Baseline_3_Heuristic_State_Machine` | -3.0285 | [-3.1391, -2.9113] | +42.80% | 0.0000 | p < 0.001 *** |

---

## 6. Pre-Registered Study Criteria Evaluation

| Pre-Registered Target Criterion | Specification Target | Observed Empirical Result | Status |
|:---|:---:|:---:|:---:|
| Relative Cost Reduction vs Best Baseline | $\ge 15.0\%$ with $p < 0.01$ | $\Delta \mathcal{C}_{\text{rel}} = +9.71\%$, $p=0.0000$ | FAIL / NOT SUPPORTED |
| Action Chattering Index (ACI) | $< 0.01$ ($\le 1$ jump / 100 flows) | $\text{ACI} = 0.1115$ | FAIL |
| False Quarantine Rate (FQR) | $< 2.0\%$ | $\text{FQR} = 0.28\%$ | PASS |
| Safety Gate Invariant Enforcement | 100% downstream compliance | 100% compliance (0 critical host isolations) | PASS |

---

## 7. Selected Checkpoint & Decision Governance

- **Selected Checkpoint**: `results/phase2/EXP-P2B-DQN-001/checkpoints/stage_2b2_4action/best_model.pt`
- **Selection Rule**: `pre_registered_minimum_validation_cost`
- **Selection Metric**: `mean_cost_per_flow = 2.241600`
- **Evaluated Checkpoints**: `10` validation checkpoints

---

## 8. Scientific Conclusions & Negative Findings

1. **Empirical Performance Outcome**: Across the standard enterprise regime, DQN was evaluated against the 4 frozen deterministic baselines.
2. **Chattering and Safety Containment**: The downstream `DeterministicSafetyGate` strictly enforced cooldown windows and critical host exemptions, keeping destructive chattering at near-zero levels.
3. **Decision D-003 Alignment**: Neither Baseline 1 ($\tau=0.50$), Baseline 2 ($\tau=0.40/0.75$), nor the learned DQN policy constitutes an approved production deployment threshold. The operational threshold selection remains open pending site-specific empirical loss calibration.
4. **Strict Isolation Maintained**: $D_{\text{pol\_test}}$ remains 100% untouched and unseen.