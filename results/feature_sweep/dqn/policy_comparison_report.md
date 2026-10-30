# XRL-IDARS Autonomous Response Policy Benchmark Report

**Generated**: `2026-10-30T06:27:11.115065+00:00`  
**Test Population**: `50,000 held-out flows`  
**Bootstrap Resamples**: `1000`  

## 1. Direct Comparative Policy Benchmark

| Policy | Mean Cost/Flow | Containment Rate | False Quarantine | Availability | Chattering Index | Mitigation Delay |
|---|---:|---:|---:|---:|---:|---:|
| **Baseline_0_Always_Allow** | 50.7560 | 0.00% | 0.000% | 100.00% | 0.0000 | 50.00 |
| **Baseline_2_Two_Tier_Threshold** | 16.5693 | 6.49% | 1.657% | 83.12% | 0.0480 | 23.71 |
| **Baseline_3_Heuristic_Rule_Engine** | 24.7825 | 4.87% | 3.931% | 33.61% | 0.0781 | 35.49 |
| **Track_B1_Binary_DQN** | 4.7071 | 98.13% | 1.430% | 79.45% | 0.0364 | 0.00 |
| **Track_B2_Attack_Aware_DQN** | 4.1415 | 99.85% | 2.315% | 83.22% | 0.0199 | 0.00 |

## 2. Paired Bootstrap Hypothesis Testing (Candidate vs Baseline)

| Comparison | Mean Cost Delta | 95% Confidence Interval | p-value | Statistically Significant? |
|---|---:|:---:|---:|:---:|
| `Track_B1_Binary_DQN_vs_Baseline_3_Heuristic_Rule_Engine` | -20.0754 | [-20.2841, -19.8632] | 0.0000 | **YES (p < 0.05)** |
| `Track_B2_Attack_Aware_DQN_vs_Baseline_3_Heuristic_Rule_Engine` | -20.6410 | [-20.8565, -20.4306] | 0.0000 | **YES (p < 0.05)** |
| `Track_B2_Attack_Aware_DQN_vs_Track_B1_Binary_DQN` | -0.5656 | [-0.6372, -0.4997] | 0.0000 | **YES (p < 0.05)** |
| `Track_B1_Binary_DQN_vs_Baseline_0_Always_Allow` | -46.0489 | [-46.4786, -45.5941] | 0.0000 | **YES (p < 0.05)** |
| `Track_B2_Attack_Aware_DQN_vs_Baseline_0_Always_Allow` | -46.6145 | [-47.0375, -46.1617] | 0.0000 | **YES (p < 0.05)** |
