# Phase 2: Final Comparative Benchmark Report (Held-Out Test Population)

**Experiment ID**: `EXP-P2-FINAL-TEST-001`  
**Research Questions**: `RQ7, RQ7.1, RQ7.2, RQ7.3`  
**Parent Detector**: `EXP-P1-CIC2017-R10-001`  
**Parent DQN Experiment**: `EXP-P2B-DQN-001`  
**Generated**: `2026-10-03T21:38:58.549930+00:00`  
**Git Commit**: `c2097fa548ed96f519c4f2886c6c01653349e649`  

---

## 1. Executive Summary & Authoritative Test Isolation

This report records the single, final comparative benchmark evaluation executed on the completely
held-out test split population ($D_{\text{pol\_test}}$), strictly preserved and untouched throughout all prior
RL exploration, policy training, baseline tuning, and hyperparameter selection stages.

**Population Accounting & Verification**:
- **Dataset**: `cicids2017`  
- **Evaluated Test Population**: `355,865` flows  
- **Expected Tabular Test Population**: `355,865` flows  
- **Integrity Status**: 100% matched tabular split manifest; zero leakage into state or policy representations.

> [!IMPORTANT]
> **Authoritative Resolution of Historical Row Count Discrepancy**:
> The 355,865 rows in $D_{\text{pol\_test}}$ represent the exact tabular flow population of the frozen Phase 1 test split (`split_manifest.json`).
> Historical references to 355,833 rows in Phase 1 documentation represent the sequence-aligned population required by sequence models (LSTM and Fusion) due to dropping the first 4 boundary flows per file across 8 capture files ($355,865 - 8 \times 4 = 355,833$).
> Because the Phase 2 detector interface consumes tabular flow features, 355,865 is the authoritative population count for tabular flow evaluation.

---

## 2. Final Multi-Regime Performance Matrix on Held-Out Test Data

| Cost Regime | Action Space | Policy | Total Cost | Mean Cost/Flow | False Quarantine (FQR) | Availability (BAS) | Chattering (ACI) | Contained | Uncontained |
|:---|:---:|:---|---:|---:|---:|---:|---:|---:|---:|
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` | 505,610.5 | 1.4208 | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| standard_enterprise | `3-action` | `Baseline_0_Always_ALLOW` | 6,482,000.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| standard_enterprise | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 601,835.0 | 1.6912 | 0.00% | 97.96% | 0.0357 | 64,180 | 640 |
| standard_enterprise | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 569,978.0 | 1.6017 | 0.00% | 97.82% | 0.0294 | 63,467 | 1,353 |
| standard_enterprise | `3-action` | `Baseline_3_Heuristic_State_Machine` | 1,624,454.0 | 4.5648 | 0.00% | 73.02% | 0.1137 | 64,279 | 541 |
| high_availability | `3-action` | `DQN_Candidate_3-action` | 538,160.5 | 1.5123 | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| high_availability | `3-action` | `Baseline_0_Always_ALLOW` | 3,241,000.0 | 9.1074 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| high_availability | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 659,100.0 | 1.8521 | 0.00% | 97.96% | 0.0357 | 64,180 | 640 |
| high_availability | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 612,753.0 | 1.7219 | 0.00% | 97.82% | 0.0294 | 63,467 | 1,353 |
| high_availability | `3-action` | `Baseline_3_Heuristic_State_Machine` | 2,594,654.0 | 7.2911 | 0.00% | 73.02% | 0.1137 | 64,279 | 541 |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` | 891,946.5 | 2.5064 | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| high_security_enclave | `3-action` | `Baseline_0_Always_ALLOW` | 32,410,000.0 | 91.0739 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| high_security_enclave | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 1,055,045.0 | 2.9647 | 0.00% | 97.96% | 0.0357 | 64,180 | 640 |
| high_security_enclave | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 1,004,496.0 | 2.8227 | 0.00% | 97.82% | 0.0294 | 63,467 | 1,353 |
| high_security_enclave | `3-action` | `Baseline_3_Heuristic_State_Machine` | 1,357,458.0 | 3.8145 | 0.00% | 73.02% | 0.1137 | 64,279 | 541 |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` | 1,895,196.5 | 5.3256 | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| standard_enterprise | `4-action` | `Baseline_0_Always_ALLOW` | 6,482,000.0 | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| standard_enterprise | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 2,661,646.0 | 7.4794 | 0.55% | 97.96% | 0.0230 | 5,130 | 59,690 |
| standard_enterprise | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,206,220.5 | 6.1996 | 0.31% | 97.82% | 0.0270 | 5,859 | 58,961 |
| standard_enterprise | `4-action` | `Baseline_3_Heuristic_State_Machine` | 3,257,720.0 | 9.1544 | 3.68% | 64.66% | 0.1073 | 3,280 | 61,540 |
| high_availability | `4-action` | `DQN_Candidate_4-action` | 1,937,476.5 | 5.4444 | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| high_availability | `4-action` | `Baseline_0_Always_ALLOW` | 3,241,000.0 | 9.1074 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| high_availability | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 2,726,426.0 | 7.6614 | 0.55% | 97.96% | 0.0230 | 5,130 | 59,690 |
| high_availability | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,257,830.5 | 6.3446 | 0.31% | 97.82% | 0.0270 | 5,859 | 58,961 |
| high_availability | `4-action` | `Baseline_3_Heuristic_State_Machine` | 4,309,160.0 | 12.1090 | 3.68% | 64.66% | 0.1073 | 3,280 | 61,540 |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` | 2,445,511.5 | 6.8720 | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| high_security_enclave | `4-action` | `Baseline_0_Always_ALLOW` | 32,410,000.0 | 91.0739 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| high_security_enclave | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 3,333,591.0 | 9.3676 | 0.55% | 97.96% | 0.0230 | 5,130 | 59,690 |
| high_security_enclave | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,849,589.5 | 8.0075 | 0.31% | 97.82% | 0.0270 | 5,859 | 58,961 |
| high_security_enclave | `4-action` | `Baseline_3_Heuristic_State_Machine` | 3,217,105.0 | 9.0402 | 3.68% | 64.66% | 0.1073 | 3,280 | 61,540 |

---

## 3. Paired Bootstrap Hypothesis Testing on Held-Out Test Data (B=1,000)

| Cost Regime | Action Space | Comparison | Mean Cost Delta | 95% Bootstrap CI | Relative Cost Reduction ($\Delta \mathcal{C}_{\text{rel}}$) | p-value | Significance | Superior Policy |
|:---|:---:|:---|---:|:---:|---:|---:|:---:|:---:|
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` vs `Baseline_0_Always_ALLOW` | -16.7940 | [-16.9164, -16.6855] | +92.20% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.2704 | [-0.2825, -0.2576] | +15.99% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.1809 | [-0.1919, -0.1691] | +11.29% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` vs `Baseline_3_Heuristic_State_Machine` | -3.1440 | [-3.1694, -3.1185] | +68.88% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_availability | `3-action` | `DQN_Candidate_3-action` vs `Baseline_0_Always_ALLOW` | -7.5951 | [-7.6542, -7.5444] | +83.40% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_availability | `3-action` | `DQN_Candidate_3-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.3398 | [-0.3504, -0.3293] | +18.35% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_availability | `3-action` | `DQN_Candidate_3-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.2096 | [-0.2187, -0.2002] | +12.17% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_availability | `3-action` | `DQN_Candidate_3-action` vs `Baseline_3_Heuristic_State_Machine` | -5.7789 | [-5.8228, -5.7349] | +79.26% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` vs `Baseline_0_Always_ALLOW` | -88.5674 | [-89.2001, -87.9975] | +97.25% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -0.4583 | [-0.5120, -0.3962] | +15.46% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.3163 | [-0.3693, -0.2615] | +11.20% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` vs `Baseline_3_Heuristic_State_Machine` | -1.3081 | [-1.3570, -1.2567] | +34.29% | 0.0000 | p < 0.001 *** | `DQN_Candidate_3-action` |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` vs `Baseline_0_Always_ALLOW` | -12.8892 | [-12.9887, -12.8015] | +70.76% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -2.1538 | [-2.1959, -2.1081] | +28.80% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.8740 | [-0.9147, -0.8312] | +14.10% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` vs `Baseline_3_Heuristic_State_Machine` | -3.8288 | [-3.8825, -3.7719] | +41.82% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_availability | `4-action` | `DQN_Candidate_4-action` vs `Baseline_0_Always_ALLOW` | -3.6630 | [-3.7099, -3.6192] | +40.22% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_availability | `4-action` | `DQN_Candidate_4-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -2.2170 | [-2.2662, -2.1636] | +28.94% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_availability | `4-action` | `DQN_Candidate_4-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -0.9002 | [-0.9429, -0.8547] | +14.19% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_availability | `4-action` | `DQN_Candidate_4-action` vs `Baseline_3_Heuristic_State_Machine` | -6.6646 | [-6.7480, -6.5812] | +55.04% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` vs `Baseline_0_Always_ALLOW` | -84.2018 | [-84.8023, -83.6554] | +92.45% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` vs `Baseline_1_Single_Threshold_tau_0.50` | -2.4956 | [-2.5604, -2.4224] | +26.64% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` vs `Baseline_2_Two_Tier_0.40_0.75` | -1.1355 | [-1.1998, -1.0700] | +14.18% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` vs `Baseline_3_Heuristic_State_Machine` | -2.1682 | [-2.2296, -2.1010] | +23.98% | 0.0000 | p < 0.001 *** | `DQN_Candidate_4-action` |

---

## 4. Pre-Registered Criteria Final Evaluation

| Research Question | Pre-Registered Target Criterion | Specification Target | Observed Empirical Result | Status |
|:---|:---|:---:|:---:|:---:|
| **RQ7 (3-Action)** | Relative Cost Reduction vs Baseline 1 (Standard) | $\ge 15.0\%$ with $p < 0.01$ | $\Delta \mathcal{C}_{\text{rel}} = +15.99\%$, $p=0.0000$ | PASS (H1 Supported) |
| **RQ7 (4-Action)** | Relative Cost Reduction vs Baseline 1 (Standard) | $\ge 15.0\%$ with $p < 0.01$ | $\Delta \mathcal{C}_{\text{rel}} = +28.80\%$, $p=0.0000$ | PASS (H1 Supported) |
| **RQ7.1** | Action Chattering Index (ACI) | $< 0.01$ ($\le 1$ jump / 100 flows) | $\text{ACI}_{\text{3-act}} = 0.0019$, $\text{ACI}_{\text{4-act}} = 0.0214$ | FAIL |
| **RQ7.2** | False Quarantine Rate (FQR) | $< 2.0\%$ | $\text{FQR}_{\text{3-act}} = 0.00\%$, $\text{FQR}_{\text{4-act}} = 0.20\%$ | PASS |
| **RQ7.3** | Safety Gate Invariant Enforcement | 100% compliance | 100% compliance (0 critical host isolations) | PASS |

---

## 5. Scientific Governance & Decision Governance

1. **Primary Research Question Outcome (RQ7)**:
   - **3-Action Space**: Under the Standard Enterprise research cost regime on held-out test data, 3-action DQN achieves a relative cost reduction of **+15.99%** ($p=0.0000$) compared to Baseline 1 (Single Threshold $\tau=0.50$). Pre-registered $\ge 15.0\%$ target status: **PASS**.
   - **4-Action Space**: Under the Standard Enterprise regime, 4-action DQN achieves a relative cost reduction of **+28.80%** ($p=0.0000$) compared to Baseline 1. Pre-registered $\ge 15.0\%$ target status: **PASS**.
   - In accordance with pre-registered scientific neutrality, all positive and negative findings are documented transparently without post-hoc rationalization.
2. **Operational Threshold Status (Decision D-003 Alignment)**:
   - Research threshold $\tau_{\text{research}} = 0.50$ remains strictly frozen for academic benchmarks.
   - Proposed threshold $\tau_{\text{ops}} = 0.40$ remains an exploratory candidate and is NOT an empirically selected optimum.
   - The learned DQN policy is an illustrative research artifact evaluated under simulated cost models; it does NOT constitute an approved production threshold.
   - Real-world deployment threshold selection remains an OPEN decision pending enterprise site-specific loss matrix calibration.
3. **Zero Test Contamination Guarantee**:
   - All model weights, baseline parameters, and ablation configurations were frozen prior to this single held-out test pass.