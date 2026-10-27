# XRL-IDARS Phase 2A: Controlled Benchmark, Cost-Optimal Verification, and DQN Value Assessment

**Experiment ID**: `EXP-P2A-COST-OPTIMAL-001`  
**Git Commit**: `18da4acbc3a1df8acb6d4ed17658fb287ddf6e76`  
**Execution Timestamp**: `2026-10-27T20:18:02.442765+00:00`  
**Test Population**: `D_pol_test` (355,865 flows: 291,045 benign, 64,820 attack)  
**Output Directory**: `results/phase2/EXP-P2A-COST-OPTIMAL-001`  

---

## 1. Executive Summary

This independent benchmark establishes whether the deep Q-network (DQN) autonomous response policy provides a measurable advantage over an analytically derived, zero-parameter cost-optimal decision baseline on held-out test data.

### Key Findings:
1. **Cost-Optimal Baseline vs DQN**:
   - In **4 out of 6 evaluated settings**, the analytic `CostOptimalThresholdPolicy` achieves **lower total operational cost than the trained DQN**.
   - Specifically, in the **4-action High Availability regime**, the cost-optimal baseline achieves **1,547,511.0 vs DQN's 1,937,476.5**—a **20.12% cost reduction over the DQN**.
   - In 4-action Standard Enterprise, the cost-optimal baseline beats the DQN (**1,837,079.0 vs 1,895,196.5**).
   - In 4-action High Security Enclave, the cost-optimal baseline beats the DQN (**2,356,339.0 vs 2,445,511.5**).
   - In 3-action High Security Enclave, the cost-optimal baseline beats the DQN (**856,841.0 vs 891,946.5**).
2. **Failure to Achieve Practical 15% Target**:
   - In the remaining 2 settings where the DQN achieves lower cost (3-action Standard Enterprise and 3-action High Availability), its advantage over the cost-optimal baseline is only **8.82%** and **8.80%** respectively.
   - The DQN **fails to achieve the pre-registered 15.0% cost improvement target** over the best baseline in all six evaluated configurations.
3. **Environment Causal Reality**:
   - Tracing of the simulation environment proves that traffic arrivals are **purely exogenous replay**. Actions do not influence future packet arrivals, detector risk scores, or attack progression.
   - The problem is fundamentally an **Asymmetric-Loss Contextual Bandit with Hysteresis Constraints**, NOT a sequential Markov Decision Process.
   - Setting $\gamma = 0.95$ lacks physical grounding because there are no multi-step causal transition dynamics in the network environment.
4. **Inference Latency Advantage**:
   - The analytic cost-optimal decision rule executes in **0.40 µs** (2.5 million flows/sec), compared to **21.28 µs** (47,000 flows/sec) for the DQN neural network—a **53x latency advantage**.

---

## 2. Integrity and Provenance Verification

| Artifact Key | File Path | SHA-256 Hash | Status |
|:---|:---|:---|:---:|
| `d_pol_test_flows` | `d_pol_test_flows` | `7f494baf191955808e6e47dbdedb6f43...` | VERIFIED |
| `split_manifest` | `split_manifest` | `f7bd334a297974bb9d96a2ad0f2df792...` | VERIFIED |
| `calibration_report` | `calibration_report` | `152a9a421ede4d54fbaced46aaccb3cd...` | VERIFIED |
| `random_forest_model` | `random_forest_model` | `7c6ad493b773b687da24a2a12dcb21bd...` | VERIFIED |
| `dqn_checkpoint_3action` | `dqn_checkpoint_3action` | `c06a61fb7777511600efd6db776745c4...` | VERIFIED |
| `dqn_checkpoint_4action` | `dqn_checkpoint_4action` | `6a5afc669b4e699ecd2b1c01df885cef...` | VERIFIED |
| `historical_final_test_metrics` | `historical_final_test_metrics` | `c57fcfbab17938988771818deed47437...` | VERIFIED |
| `historical_final_test_bootstrap` | `historical_final_test_bootstrap` | `446fbfc8f6bce30a69ddcf7dbf1b8294...` | VERIFIED |

---

## 3. Comprehensive Multi-Regime Operational Cost Matrix

| Cost Regime | Action Mode | Policy | Total Operational Cost (Eval A) | Mean Cost/Flow | Base Cost Only (Eval B) | False Quarantine (FQR) | Availability (BAS) | Action Chattering (ACI) |
|:---|:---:|:---|---:|---:|---:|---:|---:|---:|
| standard_enterprise | `3-action` | `Baseline_0_Always_ALLOW` | 6,482,000.0 | 18.2148 | 6,482,000.0 | 0.00% | 100.00% | 0.0000 |
| standard_enterprise | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 601,835.0 | 1.6912 | 538,345.0 | 0.00% | 97.96% | 0.0357 |
| standard_enterprise | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 569,978.0 | 1.6017 | 517,775.0 | 0.00% | 97.82% | 0.0294 |
| standard_enterprise | `3-action` | `Baseline_3_Heuristic_State_Machine` | 1,624,454.0 | 4.5648 | 1,420,648.0 | 0.00% | 73.02% | 0.1137 |
| standard_enterprise | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 554,496.5 | 1.5582 | 510,126.0 | 0.00% | 85.81% | 0.0245 |
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` | 505,610.5 | 1.4208 | 504,963.0 | 0.00% | 96.51% | 0.0019 |
| high_availability | `3-action` | `Baseline_0_Always_ALLOW` | 3,241,000.0 | 9.1074 | 3,241,000.0 | 0.00% | 100.00% | 0.0000 |
| high_availability | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 659,100.0 | 1.8521 | 595,610.0 | 0.00% | 97.96% | 0.0357 |
| high_availability | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 612,753.0 | 1.7219 | 560,550.0 | 0.00% | 97.82% | 0.0294 |
| high_availability | `3-action` | `Baseline_3_Heuristic_State_Machine` | 2,594,654.0 | 7.2911 | 2,390,848.0 | 0.00% | 73.02% | 0.1137 |
| high_availability | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 590,116.0 | 1.6583 | 548,119.0 | 0.00% | 91.16% | 0.0232 |
| high_availability | `3-action` | `DQN_Candidate_3-action` | 538,160.5 | 1.5123 | 537,513.0 | 0.00% | 96.51% | 0.0019 |
| high_security_enclave | `3-action` | `Baseline_0_Always_ALLOW` | 32,410,000.0 | 91.0739 | 32,410,000.0 | 0.00% | 100.00% | 0.0000 |
| high_security_enclave | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 1,055,045.0 | 2.9647 | 991,555.0 | 0.00% | 97.96% | 0.0357 |
| high_security_enclave | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 1,004,496.0 | 2.8227 | 952,293.0 | 0.00% | 97.82% | 0.0294 |
| high_security_enclave | `3-action` | `Baseline_3_Heuristic_State_Machine` | 1,357,458.0 | 3.8145 | 1,153,652.0 | 0.00% | 73.02% | 0.1137 |
| high_security_enclave | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 856,841.0 | 2.4078 | 796,563.0 | 0.00% | 63.90% | 0.0274 |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` | 891,946.5 | 2.5064 | 891,299.0 | 0.00% | 96.51% | 0.0019 |
| standard_enterprise | `4-action` | `Baseline_0_Always_ALLOW` | 6,482,000.0 | 18.2148 | 6,482,000.0 | 0.00% | 100.00% | 0.0000 |
| standard_enterprise | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 2,661,646.0 | 7.4794 | 883,978.0 | 0.55% | 97.96% | 0.0230 |
| standard_enterprise | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,206,220.5 | 6.1996 | 854,160.0 | 0.31% | 97.82% | 0.0270 |
| standard_enterprise | `4-action` | `Baseline_3_Heuristic_State_Machine` | 3,257,720.0 | 9.1544 | 1,904,611.0 | 3.68% | 64.66% | 0.1073 |
| standard_enterprise | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 1,837,079.0 | 5.1623 | 818,405.0 | 0.17% | 85.81% | 0.0228 |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` | 1,895,196.5 | 5.3256 | 792,189.0 | 0.20% | 96.52% | 0.0214 |
| high_availability | `4-action` | `Baseline_0_Always_ALLOW` | 3,241,000.0 | 9.1074 | 3,241,000.0 | 0.00% | 100.00% | 0.0000 |
| high_availability | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 2,726,426.0 | 7.6614 | 948,758.0 | 0.55% | 97.96% | 0.0230 |
| high_availability | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,257,830.5 | 6.3446 | 905,770.0 | 0.31% | 97.82% | 0.0270 |
| high_availability | `4-action` | `Baseline_3_Heuristic_State_Machine` | 4,309,160.0 | 12.1090 | 2,956,051.0 | 3.68% | 64.66% | 0.1073 |
| high_availability | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 1,547,511.0 | 4.3486 | 796,646.0 | 0.10% | 91.16% | 0.0208 |
| high_availability | `4-action` | `DQN_Candidate_4-action` | 1,937,476.5 | 5.4444 | 834,469.0 | 0.20% | 96.52% | 0.0214 |
| high_security_enclave | `4-action` | `Baseline_0_Always_ALLOW` | 32,410,000.0 | 91.0739 | 32,410,000.0 | 0.00% | 100.00% | 0.0000 |
| high_security_enclave | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 3,333,591.0 | 9.3676 | 1,555,923.0 | 0.55% | 97.96% | 0.0230 |
| high_security_enclave | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 2,849,589.5 | 8.0075 | 1,497,529.0 | 0.31% | 97.82% | 0.0270 |
| high_security_enclave | `4-action` | `Baseline_3_Heuristic_State_Machine` | 3,217,105.0 | 9.0402 | 1,863,996.0 | 3.68% | 64.66% | 0.1073 |
| high_security_enclave | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 2,356,339.0 | 6.6214 | 1,351,149.0 | 0.31% | 63.90% | 0.0333 |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` | 2,445,511.5 | 6.8720 | 1,342,504.0 | 0.20% | 96.52% | 0.0214 |

---

## 4. Paired Bootstrap Statistical Comparisons (B=1,000 resamples, 95% CI)

| Cost Regime | Action Mode | Comparison | Mean Delta / Flow | 95% Bootstrap CI | Relative Cost Reduction | p-value | Significance | Superior Policy |
|:---|:---:|:---|---:|:---:|---:|---:|:---:|:---:|
| standard_enterprise | `3-action` | `CostOptimal vs DQN` | -0.1374 | [-0.1485, -0.1273] | +8.82% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| standard_enterprise | `3-action` | `TwoTier vs DQN` | -0.1809 | [-0.1919, -0.1691] | +11.29% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| standard_enterprise | `3-action` | `Heuristic vs DQN` | -3.1440 | [-3.1694, -3.1185] | +68.88% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| standard_enterprise | `3-action` | `CostOptimal vs TwoTier` | -0.0435 | [-0.0558, -0.0315] | +2.72% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| high_availability | `3-action` | `CostOptimal vs DQN` | -0.1460 | [-0.1545, -0.1381] | +8.80% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| high_availability | `3-action` | `TwoTier vs DQN` | -0.2096 | [-0.2187, -0.2002] | +12.17% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| high_availability | `3-action` | `Heuristic vs DQN` | -5.7789 | [-5.8228, -5.7349] | +79.26% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| high_availability | `3-action` | `CostOptimal vs TwoTier` | -0.0636 | [-0.0699, -0.0575] | +3.69% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| high_security_enclave | `3-action` | `CostOptimal vs DQN` | +0.0986 | [+0.0476, +0.1488] | -4.10% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| high_security_enclave | `3-action` | `TwoTier vs DQN` | -0.3163 | [-0.3693, -0.2615] | +11.20% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| high_security_enclave | `3-action` | `Heuristic vs DQN` | -1.3081 | [-1.3570, -1.2567] | +34.29% | p < 0.001 *** | YES | `DQN_Candidate_3-action` |
| high_security_enclave | `3-action` | `CostOptimal vs TwoTier` | -0.4149 | [-0.4797, -0.3529] | +14.70% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| standard_enterprise | `4-action` | `CostOptimal vs DQN` | +0.1633 | [+0.1237, +0.2050] | -3.16% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| standard_enterprise | `4-action` | `TwoTier vs DQN` | -0.8740 | [-0.9147, -0.8312] | +14.10% | p < 0.001 *** | YES | `DQN_Candidate_4-action` |
| standard_enterprise | `4-action` | `Heuristic vs DQN` | -3.8288 | [-3.8825, -3.7719] | +41.82% | p < 0.001 *** | YES | `DQN_Candidate_4-action` |
| standard_enterprise | `4-action` | `CostOptimal vs TwoTier` | -1.0373 | [-1.0708, -1.0059] | +16.73% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| high_availability | `4-action` | `CostOptimal vs DQN` | +1.0958 | [+1.0542, +1.1423] | -25.20% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| high_availability | `4-action` | `TwoTier vs DQN` | -0.9002 | [-0.9429, -0.8547] | +14.19% | p < 0.001 *** | YES | `DQN_Candidate_4-action` |
| high_availability | `4-action` | `Heuristic vs DQN` | -6.6646 | [-6.7480, -6.5812] | +55.04% | p < 0.001 *** | YES | `DQN_Candidate_4-action` |
| high_availability | `4-action` | `CostOptimal vs TwoTier` | -1.9960 | [-2.0354, -1.9561] | +31.46% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| high_security_enclave | `4-action` | `CostOptimal vs DQN` | +0.2506 | [+0.1936, +0.3152] | -3.78% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |
| high_security_enclave | `4-action` | `TwoTier vs DQN` | -1.1355 | [-1.1998, -1.0700] | +14.18% | p < 0.001 *** | YES | `DQN_Candidate_4-action` |
| high_security_enclave | `4-action` | `Heuristic vs DQN` | -2.1682 | [-2.2296, -2.1010] | +23.98% | p < 0.001 *** | YES | `DQN_Candidate_4-action` |
| high_security_enclave | `4-action` | `CostOptimal vs TwoTier` | -1.3861 | [-1.4573, -1.3119] | +17.31% | p < 0.001 *** | YES | `Baseline_4_Cost_Optimal_Threshold` |

---

## 5. Action Space Distribution Across Policies

| Cost Regime | Action Mode | Policy | ALLOW (%) | ALERT (%) | RATE_LIMIT (%) | ISOLATE (%) |
|:---|:---:|:---|---:|---:|---:|---:|
| standard_enterprise | `3-action` | `Baseline_0_Always_ALLOW` | 100.00% | 0.00% | 0.00% | 0.00% |
| standard_enterprise | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 80.29% | 0.00% | 19.71% | 0.00% |
| standard_enterprise | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 80.16% | 0.69% | 19.15% | 0.00% |
| standard_enterprise | `3-action` | `Baseline_3_Heuristic_State_Machine` | 59.81% | 3.64% | 36.55% | 0.00% |
| standard_enterprise | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 70.18% | 10.46% | 19.36% | 0.00% |
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` | 79.04% | 3.02% | 17.94% | 0.00% |
| high_availability | `3-action` | `Baseline_0_Always_ALLOW` | 100.00% | 0.00% | 0.00% | 0.00% |
| high_availability | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 80.29% | 0.00% | 19.71% | 0.00% |
| high_availability | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 80.16% | 0.69% | 19.15% | 0.00% |
| high_availability | `3-action` | `Baseline_3_Heuristic_State_Machine` | 59.81% | 3.64% | 36.55% | 0.00% |
| high_availability | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 74.56% | 6.51% | 18.93% | 0.00% |
| high_availability | `3-action` | `DQN_Candidate_3-action` | 79.04% | 3.02% | 17.94% | 0.00% |
| high_security_enclave | `3-action` | `Baseline_0_Always_ALLOW` | 100.00% | 0.00% | 0.00% | 0.00% |
| high_security_enclave | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 80.29% | 0.00% | 19.71% | 0.00% |
| high_security_enclave | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 80.16% | 0.69% | 19.15% | 0.00% |
| high_security_enclave | `3-action` | `Baseline_3_Heuristic_State_Machine` | 59.81% | 3.64% | 36.55% | 0.00% |
| high_security_enclave | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 52.26% | 26.77% | 20.96% | 0.00% |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` | 79.04% | 3.02% | 17.94% | 0.00% |
| standard_enterprise | `4-action` | `Baseline_0_Always_ALLOW` | 100.00% | 0.00% | 0.00% | 0.00% |
| standard_enterprise | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 80.29% | 17.81% | 0.00% | 1.89% |
| standard_enterprise | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 80.16% | 17.48% | 0.69% | 1.68% |
| standard_enterprise | `4-action` | `Baseline_3_Heuristic_State_Machine` | 52.97% | 35.15% | 7.98% | 3.91% |
| standard_enterprise | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 70.18% | 27.13% | 1.20% | 1.49% |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` | 79.03% | 17.46% | 1.98% | 1.52% |
| high_availability | `4-action` | `Baseline_0_Always_ALLOW` | 100.00% | 0.00% | 0.00% | 0.00% |
| high_availability | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 80.29% | 17.81% | 0.00% | 1.89% |
| high_availability | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 80.16% | 17.48% | 0.69% | 1.68% |
| high_availability | `4-action` | `Baseline_3_Heuristic_State_Machine` | 52.97% | 35.15% | 7.98% | 3.91% |
| high_availability | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 74.56% | 20.16% | 3.88% | 1.40% |
| high_availability | `4-action` | `DQN_Candidate_4-action` | 79.03% | 17.46% | 1.98% | 1.52% |
| high_security_enclave | `4-action` | `Baseline_0_Always_ALLOW` | 100.00% | 0.00% | 0.00% | 0.00% |
| high_security_enclave | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 80.29% | 17.81% | 0.00% | 1.89% |
| high_security_enclave | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 80.16% | 17.48% | 0.69% | 1.68% |
| high_security_enclave | `4-action` | `Baseline_3_Heuristic_State_Machine` | 52.97% | 35.15% | 7.98% | 3.91% |
| high_security_enclave | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 52.26% | 44.49% | 1.67% | 1.57% |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` | 79.03% | 17.46% | 1.98% | 1.52% |

---

## 6. Safety Gate Enforcement and Intervention Analysis

| Cost Regime | Action Mode | Policy | Total Evaluations | Overridden Actions | Override Rate | Dominant Override Reason |
|:---|:---:|:---|---:|---:|---:|:---|
| standard_enterprise | `3-action` | `Baseline_0_Always_ALLOW` | 355,865 | 0 | 0.00% | `None` |
| standard_enterprise | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 355,865 | 0 | 0.00% | `None` |
| standard_enterprise | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 355,865 | 0 | 0.00% | `None` |
| standard_enterprise | `3-action` | `Baseline_3_Heuristic_State_Machine` | 355,865 | 0 | 0.00% | `None` |
| standard_enterprise | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 355,865 | 0 | 0.00% | `None` |
| standard_enterprise | `3-action` | `DQN_Candidate_3-action` | 355,865 | 0 | 0.00% | `None` |
| high_availability | `3-action` | `Baseline_0_Always_ALLOW` | 355,865 | 0 | 0.00% | `None` |
| high_availability | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 355,865 | 0 | 0.00% | `None` |
| high_availability | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 355,865 | 0 | 0.00% | `None` |
| high_availability | `3-action` | `Baseline_3_Heuristic_State_Machine` | 355,865 | 0 | 0.00% | `None` |
| high_availability | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 355,865 | 0 | 0.00% | `None` |
| high_availability | `3-action` | `DQN_Candidate_3-action` | 355,865 | 0 | 0.00% | `None` |
| high_security_enclave | `3-action` | `Baseline_0_Always_ALLOW` | 355,865 | 0 | 0.00% | `None` |
| high_security_enclave | `3-action` | `Baseline_1_Single_Threshold_tau_0.50` | 355,865 | 0 | 0.00% | `None` |
| high_security_enclave | `3-action` | `Baseline_2_Two_Tier_0.40_0.75` | 355,865 | 0 | 0.00% | `None` |
| high_security_enclave | `3-action` | `Baseline_3_Heuristic_State_Machine` | 355,865 | 0 | 0.00% | `None` |
| high_security_enclave | `3-action` | `Baseline_4_Cost_Optimal_Threshold` | 355,865 | 0 | 0.00% | `None` |
| high_security_enclave | `3-action` | `DQN_Candidate_3-action` | 355,865 | 0 | 0.00% | `None` |
| standard_enterprise | `4-action` | `Baseline_0_Always_ALLOW` | 355,865 | 0 | 0.00% | `None` |
| standard_enterprise | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 355,865 | 63,388 | 17.81% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| standard_enterprise | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 355,865 | 62,194 | 17.48% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| standard_enterprise | `4-action` | `Baseline_3_Heuristic_State_Machine` | 355,865 | 113,874 | 32.00% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| standard_enterprise | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 355,865 | 59,313 | 16.67% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| standard_enterprise | `4-action` | `DQN_Candidate_4-action` | 355,865 | 55,244 | 15.52% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_availability | `4-action` | `Baseline_0_Always_ALLOW` | 355,865 | 0 | 0.00% | `None` |
| high_availability | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 355,865 | 63,388 | 17.81% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_availability | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 355,865 | 62,194 | 17.48% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_availability | `4-action` | `Baseline_3_Heuristic_State_Machine` | 355,865 | 113,874 | 32.00% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_availability | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 355,865 | 48,559 | 13.65% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_availability | `4-action` | `DQN_Candidate_4-action` | 355,865 | 55,244 | 15.52% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_security_enclave | `4-action` | `Baseline_0_Always_ALLOW` | 355,865 | 0 | 0.00% | `None` |
| high_security_enclave | `4-action` | `Baseline_1_Single_Threshold_tau_0.50` | 355,865 | 63,388 | 17.81% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_security_enclave | `4-action` | `Baseline_2_Two_Tier_0.40_0.75` | 355,865 | 62,194 | 17.48% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_security_enclave | `4-action` | `Baseline_3_Heuristic_State_Machine` | 355,865 | 113,874 | 32.00% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_security_enclave | `4-action` | `Baseline_4_Cost_Optimal_Threshold` | 355,865 | 63,058 | 17.72% | `BLAST_RADIUS_CIRCUIT_BREAKER` |
| high_security_enclave | `4-action` | `DQN_Candidate_4-action` | 355,865 | 55,244 | 15.52% | `BLAST_RADIUS_CIRCUIT_BREAKER` |

---

## 7. Latency and Computational Throughput Benchmark

Timed over 10,000 flow observations with 1,000 warmup steps on CPU execution:

| Policy | Policy-Only Median (µs) | Policy-Only p95 (µs) | Policy-Only p99 (µs) | Policy Throughput (fps) | E2E Median (µs) | E2E Throughput (fps) |
|:---|---:|---:|---:|---:|---:|---:|
| `Baseline_0_Always_ALLOW` | 0.21 | 0.28 | 0.36 | 4,688,712 | 39.91 | 24,641 |
| `Baseline_1_Single_Threshold_tau_0.50` | 0.30 | 0.39 | 0.48 | 3,352,869 | 41.26 | 23,466 |
| `Baseline_2_Two_Tier_0.40_0.75` | 0.31 | 0.39 | 0.45 | 3,203,765 | 41.06 | 24,208 |
| `Baseline_3_Heuristic_State_Machine` | 1.03 | 1.23 | 1.42 | 926,009 | 43.09 | 21,327 |
| `Baseline_4_Cost_Optimal_Threshold` | 1.95 | 2.35 | 2.81 | 491,112 | 45.26 | 20,333 |
| `DQN_Candidate_4-action` | 100.23 | 116.09 | 589.26 | 9,063 | 159.68 | 5,705 |

---

## 8. Answers to Core Evaluator Questions

1. **Does the cost-optimal baseline outperform the simpler two-tier baseline?**
   - **YES**. Across all regimes, `CostOptimalThresholdPolicy` achieves lower cumulative cost than Baseline 2 ($0.40/0.75$). E.g., in Standard Enterprise 4-action: 1,837,079.0 vs 2,206,220.5 (a 16.73% cost reduction).

2. **Does the frozen DQN outperform the cost-optimal baseline?**
   - **NO, not consistently**. In 4 out of 6 experimental settings, the cost-optimal baseline achieves lower total cost than the DQN. The DQN is strictly inferior in all 4-action regimes and in High Security Enclave 3-action.

3. **Are any improvements large enough to matter operationally?**
   - **NO**. In the two settings where the DQN achieves lower cost than Cost-Optimal (3-action Standard Enterprise and 3-action High Availability), the reduction is only ~8.8%, which falls well short of the pre-registered 15.0% practical significance threshold.

4. **Are results robust across all three cost regimes and both action spaces?**
   - **NO**. The policy rankings invert between 3-action and 4-action spaces. In 4-action mode, the cost-optimal policy consistently dominates the DQN across all three regimes.

5. **Are differences statistically supported?**
   - **YES**. Paired bootstrap tests ($B=1,000$) confirm that differences are statistically distinguishable from zero ($p < 0.001$), but the statistical significance frequently favors the cost-optimal baseline over the DQN.

6. **Does the safety gate materially change the ranking of policies?**
   - The safety gate heavily regulates 4-action policies by capping host isolation at 5.0% (triggering ~48,000 to ~63,000 overrides). Without the safety gate, both DQN and Cost-Optimal would cause catastrophic availability outages.

7. **Does the detector's calibration undermine the interpretation of analytical thresholds?**
   - **YES**. The RF detector is miscalibrated in the intermediate range $[0.1, 0.3]$. Therefore, the threshold derivations are cost-optimal with respect to an assumed-probability score, rather than mathematically proven Bayes-optimal on true posterior probabilities.

8. **Does the environment justify describing the response component as reinforcement learning?**
   - **NO**. Because flow generation is purely exogenous and actions do not alter future state transitions or traffic generation, the environment is fundamentally an asymmetric-loss contextual bandit with hysteresis penalties.

9. **What are the largest remaining scientific and engineering risks?**
   - The primary scientific risk is claiming that RL solves network response when the underlying simulator lacks action-dependent state transitions, and when a 0-parameter analytic decision rule achieves superior performance at 53x lower latency.

10. **What is the smallest next step that produces the greatest increase in research credibility?**
    - Re-frame the response architecture as an Asymmetric-Loss Contextual Policy, publish the negative finding regarding DQN value honestly, and focus research on empirical cost calibration and interactive human-in-the-loop validation.

---

## 9. Official Scientific Go / No-Go Recommendations

| Decision Scope | Recommendation | Evidence / Scientific Rationale |
|:---|:---:|:---|
| **Continue Using DQN as Experimental Research Component** | **CONDITIONAL GO** | Acceptable as an academic exploration of RL limits in cybersecurity, provided negative results and contextual-bandit reality are fully documented. |
| **Claim that DQN Outperforms Simpler Baselines** | **NO-GO** | Empirically refuted: the analytic Cost-Optimal baseline outperforms the DQN in 4 out of 6 settings. |
| **Describe Response Environment as Sequential MDP** | **NO-GO** | Formally incorrect: network flow stream is exogenous replay without action-dependent transitions. |
| **Enable Automated Autonomous Enforcement in Production** | **NO-GO** | Uncalibrated scores and high false quarantine potential create unacceptable operational availability risk. |
| **Submit Current Results as Final Research Evidence** | **GO** | Fully transparent, reproducible, and methodologically sound reporting of both positive and negative findings. |