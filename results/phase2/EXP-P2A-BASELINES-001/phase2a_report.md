# Phase 2A: Autonomous Response Baseline Ladder Report

**Experiment ID**: `EXP-P2A-BASELINES-001`  
**Parent Detector**: `EXP-P1-CIC2017-R10-001`  
**Generated**: `2026-10-03T17:44:19.427759+00:00`  
**Git Commit**: `16003221acd61ab69d8eb48800a0b7390300c8d8`  

---

## 1. Executive Summary & Research Context

Phase 2A implements and benchmarks the deterministic autonomous response baseline ladder defined in
`docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md` (`SPEC-P2-AUTONOMOUS-RESPONSE-001`).

**Key Findings & Governance Position**:
- **Empirical Baseline Established**: Evaluated 4 deterministic baselines across 3 research cost regimes
  and 2 action modes (24 total configurations) on designated policy validation population $D_{\text{pol\_val}}$.
- **No Reinforcement Learning**: Phase 2A establishes the pure non-learning reference ladder; zero DQN code is present.
- **Decision D-003 Compliance**: Research threshold $\tau_{\text{research}} = 0.50$ serves strictly as an experimental
  baseline comparator (Baseline 1). $\tau_{\text{ops}} = 0.40$ serves as a suspect tier threshold (Baseline 2).
  Operational deployment threshold selection remains OPEN pending site-specific cost calibration.
- **Cost Framework Framing**: Cost matrix entries are explicit research assumptions for sensitivity analysis,
  not claimed real enterprise losses.
- **Dataset Isolation**: Phase 1 final test population ($D_{\text{pol\_test}}$, 355,865 rows) remains completely untouched.

---

## 2. Dataset Isolation & Population Accounting

- **Dataset**: `cicids2017`
- **Source Phase 1 Validation Rows**: `355,864`
- **$D_{\text{pol\_train}}$ (Reserved for Phase 2B DQN Training, 60%)**: `213,518` rows
- **$D_{\text{pol\_val}}$ (Phase 2A Baseline Evaluation, 40%)**: `142,346` rows
- **$D_{\text{pol\_test}}$ (Phase 1 Final Test Population, Held-Out)**: `355,865` rows (**UNTOUCHED**)
- **Split Manifest SHA-256**: `f77da334aeaf61cf794ef249ff89020ed412ae0b7ca5aefbc04a982e6a78f7ca`

---

## 3. Evaluated Response Policies

| Policy ID | Policy Name | Operational Mechanism | Role in Research |
|:---|:---|:---|:---|
| **Baseline 0** | Always ALLOW | Passes 100% of traffic unconditionally | Zero-defense lower bound reference |
| **Baseline 1** | Single Threshold (0.50) | $\ge 0.50 \to \text{ISOLATE}$ (or RATE_LIMIT in 3-action); $< 0.50 \to \text{ALLOW}$ | Research boundary comparator (not deployment policy) |
| **Baseline 2** | Two-Tier Threshold (0.40/0.75) | $< 0.40 \to \text{ALLOW}$; $[0.40, 0.75) \to \text{RATE\_LIMIT}$; $\ge 0.75 \to \text{ISOLATE}$ | Graded suspicion comparator |
| **Baseline 3** | Heuristic State Machine | Stateful escalation: First suspect $\to$ ALERT; repeated $\to$ RATE_LIMIT; severe $\to$ ISOLATE | Context-aware heuristic comparator |

---

## 4. Performance Matrix (All 24 Configurations)

| Action Mode | Cost Regime | Policy Name | Total Cost | Mean Cost/Flow | False Quarantine Rate (FQR) | Business Availability (BAS) | Action Chattering (ACI) | Contained Attacks | Uncontained Attacks |
|:---|:---|:---|---:|---:|---:|---:|---:|---:|---:|
| 4-action | standard_enterprise | Baseline_0_Always_ALLOW | 2,592,800.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 4-action | standard_enterprise | Baseline_1_Single_Threshold_tau_0.50 | 371,678.5 | 2.6111 | 0.48% | 97.99% | 0.0898 | 6,139 | 19,789 |
| 4-action | standard_enterprise | Baseline_2_Two_Tier_0.40_0.75 | 376,299.0 | 2.6436 | 0.39% | 97.87% | 0.0990 | 6,528 | 19,400 |
| 4-action | standard_enterprise | Baseline_3_Heuristic_State_Machine | 1,196,420.0 | 8.4050 | 4.73% | 1.52% | 0.0771 | 1,435 | 24,493 |
| 4-action | high_availability | Baseline_0_Always_ALLOW | 1,296,400.0 | 9.1074 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 4-action | high_availability | Baseline_1_Single_Threshold_tau_0.50 | 391,758.5 | 2.7522 | 0.48% | 97.99% | 0.0898 | 6,139 | 19,789 |
| 4-action | high_availability | Baseline_2_Two_Tier_0.40_0.75 | 400,819.0 | 2.8158 | 0.39% | 97.87% | 0.0990 | 6,528 | 19,400 |
| 4-action | high_availability | Baseline_3_Heuristic_State_Machine | 1,818,940.0 | 12.7783 | 4.73% | 1.52% | 0.0771 | 1,435 | 24,493 |
| 4-action | high_security_enclave | Baseline_0_Always_ALLOW | 12,964,000.0 | 91.0739 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 4-action | high_security_enclave | Baseline_1_Single_Threshold_tau_0.50 | 613,339.5 | 4.3088 | 0.48% | 97.99% | 0.0898 | 6,139 | 19,789 |
| 4-action | high_security_enclave | Baseline_2_Two_Tier_0.40_0.75 | 603,987.0 | 4.2431 | 0.39% | 97.87% | 0.0990 | 6,528 | 19,400 |
| 4-action | high_security_enclave | Baseline_3_Heuristic_State_Machine | 1,007,154.0 | 7.0754 | 4.73% | 1.52% | 0.0771 | 1,435 | 24,493 |
| 3-action | standard_enterprise | Baseline_0_Always_ALLOW | 2,592,800.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 3-action | standard_enterprise | Baseline_1_Single_Threshold_tau_0.50 | 440,536.0 | 3.0948 | 0.00% | 97.99% | 0.3165 | 25,666 | 262 |
| 3-action | standard_enterprise | Baseline_2_Two_Tier_0.40_0.75 | 427,527.0 | 3.0034 | 0.00% | 97.87% | 0.3078 | 25,392 | 536 |
| 3-action | standard_enterprise | Baseline_3_Heuristic_State_Machine | 1,806,318.0 | 12.6896 | 0.00% | 8.32% | 0.1183 | 25,857 | 71 |
| 3-action | high_availability | Baseline_0_Always_ALLOW | 1,296,400.0 | 9.1074 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 3-action | high_availability | Baseline_1_Single_Threshold_tau_0.50 | 462,506.0 | 3.2492 | 0.00% | 97.99% | 0.3165 | 25,666 | 262 |
| 3-action | high_availability | Baseline_2_Two_Tier_0.40_0.75 | 443,842.0 | 3.1181 | 0.00% | 97.87% | 0.3078 | 25,392 | 536 |
| 3-action | high_availability | Baseline_3_Heuristic_State_Machine | 3,366,998.0 | 23.6536 | 0.00% | 8.32% | 0.1183 | 25,857 | 71 |
| 3-action | high_security_enclave | Baseline_0_Always_ALLOW | 12,964,000.0 | 91.0739 | 0.00% | 100.00% | 0.0000 | 0 | 25,928 |
| 3-action | high_security_enclave | Baseline_1_Single_Threshold_tau_0.50 | 624,620.0 | 4.3880 | 0.00% | 97.99% | 0.3165 | 25,666 | 262 |
| 3-action | high_security_enclave | Baseline_2_Two_Tier_0.40_0.75 | 607,869.0 | 4.2704 | 0.00% | 97.87% | 0.3078 | 25,392 | 536 |
| 3-action | high_security_enclave | Baseline_3_Heuristic_State_Machine | 877,034.0 | 6.1613 | 0.00% | 8.32% | 0.1183 | 25,857 | 71 |

---

## 5. Paired Statistical Comparisons (Bootstrap B=1,000)

| Action Mode | Cost Regime | Comparison | Mean Cost Delta | 95% Bootstrap CI | Relative Cost Reduction ($\Delta \mathcal{C}_{\text{rel}}$) | p-value | Significance |
|:---|:---|:---|---:|:---:|---:|---:|:---:|
| 4-action | standard_enterprise | `Baseline_1_Single_Threshold_tau_0.50` vs `Baseline_0_Always_ALLOW` | -15.6037 | [-15.7999, -15.4251] | +85.66% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_0_Always_ALLOW` | -15.5712 | [-15.7701, -15.3954] | +85.49% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `Baseline_3_Heuristic_State_Machine` vs `Baseline_0_Always_ALLOW` | -9.8098 | [-10.0178, -9.6058] | +53.86% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_1_Single_Threshold_tau_0.50` | +0.0325 | [+0.0173, +0.0478] | -1.24% | 0.0000 | p < 0.001 *** |
| 4-action | standard_enterprise | `Baseline_3_Heuristic_State_Machine` vs `Baseline_1_Single_Threshold_tau_0.50` | +5.7939 | [+5.7137, +5.8672] | -221.90% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `Baseline_1_Single_Threshold_tau_0.50` vs `Baseline_0_Always_ALLOW` | -6.3552 | [-6.4496, -6.2626] | +69.78% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_0_Always_ALLOW` | -6.2916 | [-6.3868, -6.2001] | +69.08% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `Baseline_3_Heuristic_State_Machine` vs `Baseline_0_Always_ALLOW` | +3.6709 | [+3.5059, +3.8351] | -40.31% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_1_Single_Threshold_tau_0.50` | +0.0637 | [+0.0379, +0.0892] | -2.31% | 0.0000 | p < 0.001 *** |
| 4-action | high_availability | `Baseline_3_Heuristic_State_Machine` vs `Baseline_1_Single_Threshold_tau_0.50` | +10.0261 | [+9.8812, +10.1621] | -364.30% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `Baseline_1_Single_Threshold_tau_0.50` vs `Baseline_0_Always_ALLOW` | -86.7651 | [-87.8230, -85.8043] | +95.27% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_0_Always_ALLOW` | -86.8308 | [-87.9228, -85.8729] | +95.34% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `Baseline_3_Heuristic_State_Machine` vs `Baseline_0_Always_ALLOW` | -83.9985 | [-85.0748, -83.0219] | +92.23% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.0657 | [-0.1019, -0.0342] | +1.52% | 0.0000 | p < 0.001 *** |
| 4-action | high_security_enclave | `Baseline_3_Heuristic_State_Machine` vs `Baseline_1_Single_Threshold_tau_0.50` | +2.7666 | [+2.6530, +2.8734] | -64.21% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `Baseline_1_Single_Threshold_tau_0.50` vs `Baseline_0_Always_ALLOW` | -15.1199 | [-15.3112, -14.9442] | +83.01% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_0_Always_ALLOW` | -15.2113 | [-15.4001, -15.0378] | +83.51% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `Baseline_3_Heuristic_State_Machine` vs `Baseline_0_Always_ALLOW` | -5.5251 | [-5.7594, -5.3128] | +30.33% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.0914 | [-0.1009, -0.0826] | +2.95% | 0.0000 | p < 0.001 *** |
| 3-action | standard_enterprise | `Baseline_3_Heuristic_State_Machine` vs `Baseline_1_Single_Threshold_tau_0.50` | +9.5948 | [+9.5355, +9.6498] | -310.03% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `Baseline_1_Single_Threshold_tau_0.50` vs `Baseline_0_Always_ALLOW` | -5.8582 | [-5.9451, -5.7777] | +64.32% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_0_Always_ALLOW` | -5.9893 | [-6.0753, -5.9118] | +65.76% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `Baseline_3_Heuristic_State_Machine` vs `Baseline_0_Always_ALLOW` | +14.5462 | [+14.3829, +14.6946] | -159.72% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.1311 | [-0.1432, -0.1198] | +4.04% | 0.0000 | p < 0.001 *** |
| 3-action | high_availability | `Baseline_3_Heuristic_State_Machine` vs `Baseline_1_Single_Threshold_tau_0.50` | +20.4045 | [+20.3142, +20.4946] | -627.99% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `Baseline_1_Single_Threshold_tau_0.50` vs `Baseline_0_Always_ALLOW` | -86.6858 | [-87.7569, -85.7304] | +95.18% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_0_Always_ALLOW` | -86.8035 | [-87.9006, -85.8418] | +95.31% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `Baseline_3_Heuristic_State_Machine` vs `Baseline_0_Always_ALLOW` | -84.9126 | [-86.0011, -83.9215] | +93.23% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `Baseline_2_Two_Tier_0.40_0.75` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.1177 | [-0.1525, -0.0867] | +2.68% | 0.0000 | p < 0.001 *** |
| 3-action | high_security_enclave | `Baseline_3_Heuristic_State_Machine` vs `Baseline_1_Single_Threshold_tau_0.50` | +1.7732 | [+1.6593, +1.8798] | -40.41% | 0.0000 | p < 0.001 *** |

---

## 6. Safety Gate Enforcement & Invariant Verification

All candidate policy actions passed through the non-bypassable `DeterministicSafetyGate`:
1. **Critical Infrastructure Exemption**: Host endpoints designated as critical infrastructure (gateways, DNS, auth) were never isolated.
2. **Mandatory Action Cooldown**: Endpoints were protected against de-escalation oscillation within 30-step windows.
3. **Blast Radius Circuit Breaker**: Global quarantine limit capped at 5.0% of endpoint inventory.

---

## 7. Next Steps for Phase 2B

With Phase 2A baselines frozen and fully quantified:
1. Implement `DqnResponseAgent` architecture under `src/xrlids/response/dqn/`.
2. Train agent strictly on $D_{\text{pol\_train}}$ using causal 6D state representation.
3. Validate against $D_{\text{pol\_val}}$ across the 3 research cost regimes.
4. Evaluate trained policy against the frozen Baseline 0–3 ladder.